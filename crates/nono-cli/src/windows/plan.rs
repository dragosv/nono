//! Turning `nono run` arguments into a capability set and launch options.
//!
//! Policy that belongs to the CLI lives here: program resolution, enumerate
//! grants on ancestors, environment filtering and the session proxy. There is no nono temp directory: PSEC sets TEMP/TMP to the
//! container's own temp folder, which is private to the run and removed
//! with it.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nono::{AccessMode, CapabilitySet, LaunchOptions, LaunchStdio, NonoError, Result, Sandbox};

use super::RunArgs;
use super::env_sanitization::is_dangerous_env_var;

/// Variables that carry nono's own state and never reach the workload.
const NONO_INTERNAL_ENV: &[&str] = &["NONO_CAP_FILE", "NONO_ALLOW"];

/// Everything one run needs. Dropping it stops the proxy, so it must
/// outlive the child.
pub(crate) struct Plan {
    pub(crate) caps: CapabilitySet,
    pub(crate) options: LaunchOptions,
    pub(crate) win32k_allowed: bool,
    program: PathBuf,
    env_names: Vec<String>,
    proxy: Option<Proxy>,
}

struct Proxy {
    handle: nono_proxy::ProxyHandle,
    _runtime: tokio::runtime::Runtime,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

impl Plan {
    pub(crate) fn build(args: &RunArgs, stdio: LaunchStdio) -> Result<Self> {
        if !args.write.is_empty() || !args.write_file.is_empty() {
            return Err(NonoError::SandboxInit(
                "--write/--write-file are not available on Windows: PSEC has no write-only grant. Use --allow/--allow-file for read+write".to_string(),
            ));
        }
        let Some((program_arg, program_args)) = args.command.split_first() else {
            return Err(NonoError::NoCommand);
        };
        let cwd = plain(&std::env::current_dir().map_err(NonoError::Io)?);
        let program = resolve_program(program_arg)?;

        let mut caps = CapabilitySet::new();
        for dir in &args.allow {
            caps = caps.allow_path(dir, AccessMode::ReadWrite)?;
        }
        for dir in &args.read {
            caps = caps.allow_path(dir, AccessMode::Read)?;
        }
        for file in &args.allow_file {
            caps = caps.allow_file(file, AccessMode::ReadWrite)?;
        }
        for file in &args.read_file {
            caps = caps.allow_file(file, AccessMode::Read)?;
        }
        if args.allow_cwd {
            caps = caps.allow_path(&cwd, AccessMode::Read)?;
        }
        // The program image itself must be readable. Only the file is
        // granted, not its directory.
        if !covered(&caps, &program) {
            caps = caps.allow_file(&program, AccessMode::Read)?;
        }

        let mut proxy = None;
        if args.block_net {
            caps = caps.block_network();
        } else if !args.allow_domain.is_empty() || !args.deny_domain.is_empty() {
            if !args.allow_private_inbound {
                return Err(NonoError::SandboxInit(
                    "--allow-domain/--deny-domain route traffic through nono's proxy, which on Windows also lets hosts on a private network connect to listeners in the workload. Add --allow-private-inbound to accept this, or use --block-net".to_string(),
                ));
            }
            let started = start_proxy(&args.allow_domain, &args.deny_domain)?;
            caps = caps.proxy_only(started.handle.port);
            proxy = Some(started);
        }

        let mut env = workload_env(std::env::vars_os());
        if let Some(proxy) = &proxy {
            for (key, value) in proxy.handle.env_vars() {
                env.retain(|(k, _)| !k.eq_ignore_ascii_case(&key));
                env.push((key.into(), value.into()));
            }
        }
        let env_names = env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();

        let mut options = LaunchOptions::new(&program, &cwd)
            .args(program_args.iter().cloned())
            .allow_win32k(args.allow_win32k)
            .allow_private_network_inbound(args.allow_private_inbound)
            .stdio(stdio);
        for (key, value) in env {
            options = options.env(key, value);
        }
        for path in &args.deny {
            options = options.deny_path(path);
        }
        // Opt-in only: the set includes the volume root, and a volume-root
        // enumerate grant exposes every file name on the volume (observed on
        // build 26300). The library refuses enumerate grants on hosts without
        // PSEC 1.1 enumeration.
        if args.enumerate_ancestors {
            for path in enumerate_ancestors(&caps, &program, &cwd) {
                options = options.enumerate_path(path);
            }
        }

        Ok(Self {
            caps,
            options,
            win32k_allowed: args.allow_win32k,
            program,
            env_names,
            proxy,
        })
    }

    /// Human-readable policy for `--dry-run`. Environment values are omitted.
    pub(crate) fn describe(&self) -> Result<String> {
        let policy = Sandbox::render_launch_policy(&self.caps, &self.options)?;
        let mut out = String::new();
        let _ = writeln!(out, "program:   {}", self.program.display());
        let _ = writeln!(out, "{policy}");
        if let Some(proxy) = &self.proxy {
            let _ = writeln!(
                out,
                "proxy:     nono-proxy on 127.0.0.1:{} (session token in HTTP(S)_PROXY)",
                proxy.handle.port
            );
        }
        let _ = write!(out, "env:       {}", self.env_names.join(", "));
        Ok(out)
    }
}

/// Run with pipes (non-interactive): relay stdio, propagate the exit code,
/// end the tree on Ctrl-C.
pub(crate) fn run_piped(args: &RunArgs) -> Result<u32> {
    let plan = Plan::build(args, LaunchStdio::Piped)?;
    let mut child = Sandbox::launch(&plan.caps, &plan.options)?;
    install_interrupt_handler();

    let stdin_pipe = child.take_stdin();
    let stdout_pipe = child.take_stdout();
    let stderr_pipe = child.take_stderr();
    if let Some(mut pipe) = stdin_pipe {
        // Detached: a blocking read on our stdin must not delay exit.
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut std::io::stdin().lock(), &mut pipe);
        });
    }
    let out = stdout_pipe.map(|p| std::thread::spawn(move || relay(p, std::io::stdout())));
    let err = stderr_pipe.map(|p| std::thread::spawn(move || relay(p, std::io::stderr())));

    let code = loop {
        if INTERRUPTED.load(Ordering::SeqCst) {
            child.terminate()?;
        }
        if let Some(code) = child.wait_timeout(Duration::from_millis(100))? {
            break code;
        }
    };
    // Descendants may still hold the pipes open; end the tree so the relays
    // see EOF.
    drop(child);
    for handle in [out, err].into_iter().flatten() {
        let _ = handle.join();
    }
    super::explain_exit(code, plan.win32k_allowed);
    Ok(code)
}

fn relay(mut from: std::fs::File, mut to: impl Write) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = to.flush();
            }
        }
    }
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn install_interrupt_handler() {
    unsafe extern "system" fn handler(_ctrl_type: u32) -> windows_sys::core::BOOL {
        INTERRUPTED.store(true, Ordering::SeqCst);
        1
    }
    // SAFETY: registers a handler with the correct signature; it only stores
    // to an atomic.
    unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(handler), 1) };
}

fn start_proxy(allow: &[String], deny: &[String]) -> Result<Proxy> {
    let config = nono_proxy::ProxyConfig {
        allowed_hosts: allow.to_vec(),
        denied_hosts: deny.to_vec(),
        // An allowlist means "only these"; a denylist alone filters the rest.
        strict_filter: !allow.is_empty(),
        ..nono_proxy::ProxyConfig::default()
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .map_err(NonoError::Io)?;
    let handle = runtime
        .block_on(nono_proxy::start(config))
        .map_err(|e| NonoError::SandboxInit(format!("failed to start nono-proxy: {e}")))?;
    Ok(Proxy {
        handle,
        _runtime: runtime,
    })
}

/// Host environment minus loader/interpreter injection variables, nono's own
/// state and the host's TEMP/TMP (PSEC supplies the container's own).
///
/// A variable whose name is not valid Unicode cannot be checked against the
/// filters, so it is dropped. Values pass through unchanged.
fn workload_env(host: impl Iterator<Item = (OsString, OsString)>) -> Vec<(OsString, OsString)> {
    let mut skipped = 0usize;
    let env: Vec<(OsString, OsString)> = host
        .filter(|(key, _)| {
            let Some(key) = key.to_str() else {
                skipped = skipped.saturating_add(1);
                return false;
            };
            // Windows names are case-insensitive; the shared filter is not.
            let upper = key.to_ascii_uppercase();
            !key.starts_with('=')
                && !is_dangerous_env_var(&upper)
                && !is_dangerous_windows_env_var(&upper)
                && !NONO_INTERNAL_ENV.contains(&upper.as_str())
                && upper != "TEMP"
                && upper != "TMP"
        })
        .collect();
    if skipped > 0 {
        eprintln!(
            "nono: {skipped} environment variable(s) with a non-Unicode name were not passed to the workload"
        );
    }
    env
}

/// Windows loader, profiler and compatibility-shim variables that make every
/// matching process load code chosen by whoever set them. `key` is uppercase.
fn is_dangerous_windows_env_var(key: &str) -> bool {
    // .NET Framework and .NET (Core) profilers: COR_ENABLE_PROFILING,
    // COR_PROFILER, COR_PROFILER_PATH{,_32,_64} and the CORECLR_ forms.
    key == "COR_ENABLE_PROFILING"
        || key.starts_with("COR_PROFILER")
        || key == "CORECLR_ENABLE_PROFILING"
        || key.starts_with("CORECLR_PROFILER")
        // .NET host: extra dependency manifests and shared stores.
        || key == "DOTNET_ADDITIONAL_DEPS"
        || key == "DOTNET_SHARED_STORE"
        // Application compatibility shims.
        || key == "__COMPAT_LAYER"
}

/// Resolve the program without consulting the current directory: an explicit
/// path is used as given; a bare name is searched on PATH with PATHEXT.
fn resolve_program(arg: &OsStr) -> Result<PathBuf> {
    let candidate = Path::new(arg);
    if candidate.components().count() > 1 || candidate.is_absolute() {
        let absolute = std::path::absolute(candidate).map_err(NonoError::Io)?;
        return with_extension(&absolute).ok_or(NonoError::PathNotFound(absolute));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        if !dir.is_absolute() {
            continue;
        }
        if let Some(found) = with_extension(&dir.join(candidate)) {
            return Ok(found);
        }
    }
    Err(NonoError::SandboxInit(format!(
        "command not found on PATH: {}",
        candidate.display()
    )))
}

fn with_extension(base: &Path) -> Option<PathBuf> {
    if base.extension().is_some() && base.is_file() {
        return Some(plain(base));
    }
    let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    for ext in pathext.split(';').filter(|e| !e.is_empty()) {
        let mut name = OsString::from(base.as_os_str());
        name.push(ext);
        let path = PathBuf::from(name);
        if path.is_file() {
            return Some(plain(&path));
        }
    }
    None
}

fn covered(caps: &CapabilitySet, path: &Path) -> bool {
    let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    caps.fs_capabilities()
        .iter()
        .any(|cap| target == cap.resolved || (!cap.is_file && target.starts_with(&cap.resolved)))
}

/// Ancestors of every grant, the program and the working directory.
/// cmd.exe needs to enumerate all of them, volume root included, to start a
/// program by absolute path. Enumeration grants no content reads, but it is
/// recursive.
fn enumerate_ancestors(caps: &CapabilitySet, program: &Path, cwd: &Path) -> BTreeSet<PathBuf> {
    let mut roots: Vec<PathBuf> = caps
        .fs_capabilities()
        .iter()
        .map(|cap| plain(&cap.resolved))
        .collect();
    roots.push(program.to_path_buf());
    roots.push(cwd.to_path_buf());
    let mut out = BTreeSet::new();
    for root in roots {
        for ancestor in root.ancestors().skip(1) {
            out.insert(ancestor.to_path_buf());
        }
    }
    out
}

/// `\\?\X:\...` → `X:\...`; other forms unchanged. Works on path components,
/// so non-Unicode names survive.
pub(crate) fn plain(path: &Path) -> PathBuf {
    use std::path::{Component, Prefix};
    let mut components = path.components();
    match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::VerbatimDisk(drive) => {
                let mut plain = PathBuf::from(format!("{}:\\", char::from(drive)));
                plain.extend(components.filter(|c| !matches!(c, Component::RootDir)));
                plain
            }
            _ => path.to_path_buf(),
        },
        _ => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_strips_only_verbatim_drive_prefix() {
        assert_eq!(plain(Path::new(r"\\?\C:\a")), PathBuf::from(r"C:\a"));
        assert_eq!(
            plain(Path::new(r"\\?\UNC\s\x")),
            PathBuf::from(r"\\?\UNC\s\x")
        );
        assert_eq!(plain(Path::new(r"D:\b")), PathBuf::from(r"D:\b"));
    }

    fn kept(host: &[(OsString, OsString)]) -> Vec<String> {
        workload_env(host.iter().cloned())
            .into_iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect()
    }

    fn pairs(names: &[&str]) -> Vec<(OsString, OsString)> {
        names.iter().map(|n| (n.into(), "x".into())).collect()
    }

    #[test]
    fn workload_env_filters_injection_variables_case_insensitively() {
        let names = kept(&pairs(&[
            "node_options",
            "PATH",
            "Cor_Enable_Profiling",
            "COR_PROFILER",
            "COR_PROFILER_PATH_64",
            "CORECLR_ENABLE_PROFILING",
            "CORECLR_PROFILER_PATH",
            "DOTNET_ADDITIONAL_DEPS",
            "dotnet_startup_hooks",
            "__COMPAT_LAYER",
            "NONO_CAP_FILE",
            "TEMP",
        ]));
        assert_eq!(names, ["PATH"]);
    }

    #[test]
    fn workload_env_drops_non_unicode_names_without_panicking() {
        use std::os::windows::ffi::OsStringExt;
        let lone_surrogate = OsString::from_wide(&[0xD800, u16::from(b'X')]);
        let mut host = pairs(&["PATH"]);
        host.push((lone_surrogate.clone(), "x".into()));
        host.push(("KEEP".into(), lone_surrogate));
        assert_eq!(kept(&host), ["PATH", "KEEP"]);
    }

    #[test]
    fn plain_keeps_non_unicode_components() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let mut wide: Vec<u16> = r"\\?\C:\a\".encode_utf16().collect();
        wide.push(0xD800);
        let path = PathBuf::from(OsString::from_wide(&wide));
        let out: Vec<u16> = plain(&path).as_os_str().encode_wide().collect();
        let mut expected: Vec<u16> = r"C:\a\".encode_utf16().collect();
        expected.push(0xD800);
        assert_eq!(out, expected);
    }

    #[test]
    fn enumerate_ancestors_excludes_the_paths_themselves() {
        let caps = CapabilitySet::new();
        let set = enumerate_ancestors(
            &caps,
            Path::new(r"C:\tools\bin\x.exe"),
            Path::new(r"C:\work"),
        );
        assert!(set.contains(Path::new(r"C:\tools\bin")));
        assert!(set.contains(Path::new(r"C:\")));
        assert!(!set.contains(Path::new(r"C:\work")));
    }
}
