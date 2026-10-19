//! Turning `nono run` arguments into a capability set and launch options.
//!
//! Policy that belongs to the CLI lives here: program resolution, the
//! per-run temp directory, enumerate grants on ancestors, environment
//! filtering and the session proxy.

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

/// Everything one run needs. Dropping it stops the proxy and removes the
/// temp directory, so it must outlive the child.
pub(crate) struct Plan {
    pub(crate) caps: CapabilitySet,
    pub(crate) options: LaunchOptions,
    pub(crate) win32k_allowed: bool,
    program: PathBuf,
    env_names: Vec<String>,
    _temp: tempfile::TempDir,
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

        // Per-run temp directory, read+write, exported as TEMP/TMP.
        let temp = tempfile::Builder::new()
            .prefix("nono-")
            .tempdir()
            .map_err(NonoError::Io)?;
        let temp_path = plain(&temp.path().canonicalize().map_err(NonoError::Io)?);
        caps = caps.allow_path(&temp_path, AccessMode::ReadWrite)?;

        let mut proxy = None;
        if args.block_net {
            caps = caps.block_network();
        } else if !args.allow_domain.is_empty() || !args.deny_domain.is_empty() {
            let started = start_proxy(&args.allow_domain, &args.deny_domain)?;
            caps = caps.proxy_only(started.handle.port);
            proxy = Some(started);
        }

        let mut env = workload_env(&temp_path);
        if let Some(proxy) = &proxy {
            for (key, value) in proxy.handle.env_vars() {
                env.retain(|(k, _)| !k.eq_ignore_ascii_case(&key));
                env.push((key, value));
            }
        }
        let env_names = env.iter().map(|(k, _)| k.clone()).collect();

        let mut options = LaunchOptions::new(&program, &cwd)
            .args(program_args.iter().cloned())
            .allow_win32k(args.allow_win32k)
            .stdio(stdio);
        for (key, value) in env {
            options = options.env(key, value);
        }
        for path in &args.deny {
            options = options.deny_path(path);
        }
        // Opt-in only: the set includes the volume root, and a volume-root
        // enumerate grant exposes every file name on the volume (observed on
        // build 26300).
        if args.enumerate_ancestors {
            if !Sandbox::windows_support().fs_enumerate {
                return Err(NonoError::SandboxInit(
                    "--enumerate-ancestors needs PSEC 1.1 enumeration, which this host lacks"
                        .to_string(),
                ));
            }
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
            _temp: temp,
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

/// Host environment minus loader/interpreter injection variables and nono's
/// own state, with TEMP/TMP pointing at the per-run temp directory.
fn workload_env(temp: &Path) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(key, _)| {
            let upper = key.to_ascii_uppercase();
            // Windows names are case-insensitive; the shared filter is not.
            !key.starts_with('=')
                && !is_dangerous_env_var(&upper)
                && !NONO_INTERNAL_ENV.contains(&upper.as_str())
                && upper != "TEMP"
                && upper != "TMP"
        })
        .collect();
    let temp = temp.display().to_string();
    env.push(("TEMP".to_string(), temp.clone()));
    env.push(("TMP".to_string(), temp));
    env
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

/// `\\?\X:\...` → `X:\...`; other forms unchanged.
pub(crate) fn plain(path: &Path) -> PathBuf {
    let s = path.as_os_str().to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
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

    #[test]
    fn workload_env_filters_injection_variables_case_insensitively() {
        let env = [("node_options", "--require x"), ("PATH", "C:\\bin")];
        let kept: Vec<_> = env
            .iter()
            .filter(|(k, _)| !is_dangerous_env_var(&k.to_ascii_uppercase()))
            .collect();
        assert_eq!(kept.len(), 1);
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
