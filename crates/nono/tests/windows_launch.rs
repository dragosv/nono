//! End-to-end tests for the Windows PSEC launch backend.
//!
//! These launch real processes inside a Windows ProcessContainer. On a host
//! without PSEC they are skipped, unless `NONO_REQUIRE_ENFORCEMENT=1` is set,
//! in which case a skip is a failure (CI on qualified hosts sets it).

#![cfg(target_os = "windows")]
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nono::{AccessMode, CapabilitySet, LaunchOptions, LaunchStdio, Sandbox};

fn psec_or_skip() -> bool {
    let support = Sandbox::windows_support();
    if support.psec_available {
        return true;
    }
    assert!(
        std::env::var_os("NONO_REQUIRE_ENFORCEMENT").is_none(),
        "PSEC required but unavailable: {:?}",
        support.unavailable_reason
    );
    eprintln!(
        "skipping: PSEC unavailable: {:?}",
        support.unavailable_reason
    );
    false
}

fn plain(path: &Path) -> PathBuf {
    let s = path.display().to_string();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

fn system32(exe: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    Path::new(&root).join("System32").join(exe)
}

/// A fixture with `ro`, `rw`, `rw\deny` and `un` (ungranted) directories.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        // Plain `C:...` form: scripts below embed these paths for cmd.exe.
        let root = plain(&dir.path().canonicalize().unwrap());
        for sub in ["ro", "rw", r"rw\deny", "un"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        fs::write(root.join(r"ro\in.txt"), "readable").unwrap();
        fs::write(root.join(r"un\secret.txt"), "secret").unwrap();
        fs::write(root.join(r"rw\deny\hidden.txt"), "hidden").unwrap();
        Self { _dir: dir, root }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn caps(&self) -> CapabilitySet {
        CapabilitySet::new()
            .allow_path(self.path("ro"), AccessMode::Read)
            .unwrap()
            .allow_path(self.path("rw"), AccessMode::ReadWrite)
            .unwrap()
            .block_network()
    }

    /// `cmd.exe /d /c <script>` with the minimum environment and win32k on.
    fn cmd(&self, script: &str) -> LaunchOptions {
        let mut opts = LaunchOptions::new(system32("cmd.exe"), self.path("rw"))
            .args(["/d", "/c", script])
            .allow_win32k(true)
            .stdio(LaunchStdio::Piped);
        for (key, value) in base_env() {
            opts = opts.env(key, value);
        }
        opts
    }
}

fn base_env() -> Vec<(String, String)> {
    let get = |k: &str| std::env::var(k).unwrap_or_default();
    vec![
        ("SystemRoot".into(), get("SystemRoot")),
        ("LOCALAPPDATA".into(), get("LOCALAPPDATA")),
        ("PATH".into(), system32("").display().to_string()),
        ("ComSpec".into(), system32("cmd.exe").display().to_string()),
        ("PATHEXT".into(), ".COM;.EXE;.BAT;.CMD".into()),
    ]
}

struct Output {
    code: u32,
    stdout: String,
    stderr: String,
}

fn run(caps: &CapabilitySet, opts: &LaunchOptions) -> Output {
    let mut child = Sandbox::launch(caps, opts).unwrap();
    drop(child.take_stdin());
    let mut out_pipe = child.take_stdout().unwrap();
    let mut err_pipe = child.take_stderr().unwrap();
    let err_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = err_pipe.read_to_string(&mut s);
        s
    });
    let mut stdout = String::new();
    let _ = out_pipe.read_to_string(&mut stdout);
    let stderr = err_reader.join().unwrap_or_default();
    let code = child
        .wait_timeout(Duration::from_secs(30))
        .unwrap()
        .expect("child did not exit");
    Output {
        code,
        stdout,
        stderr,
    }
}

#[test]
fn reads_granted_and_writes_granted() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    let script = format!(
        r#"type {} && echo written> {}"#,
        fx.path(r"ro\in.txt").display(),
        fx.path(r"rw\out.txt").display()
    );
    let out = run(&fx.caps(), &fx.cmd(&script));
    assert_eq!(out.code, 0, "stdout={} stderr={}", out.stdout, out.stderr);
    assert!(out.stdout.contains("readable"));
    assert_eq!(
        fs::read_to_string(fx.path(r"rw\out.txt")).unwrap().trim(),
        "written"
    );
}

#[test]
fn write_to_read_only_grant_is_denied() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    // The first write is a positive control: the script ran and its paths
    // are valid, so the second failure is the policy.
    let script = format!(
        r#"echo x> {} && echo x> {}"#,
        fx.path(r"rw\control.txt").display(),
        fx.path(r"ro\new.txt").display()
    );
    let out = run(&fx.caps(), &fx.cmd(&script));
    assert!(fx.path(r"rw\control.txt").exists(), "{}", out.stderr);
    assert_ne!(out.code, 0);
    assert!(!fx.path(r"ro\new.txt").exists());
}

#[test]
fn ungranted_read_is_denied() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    let script = format!(
        r#"type {} && type {}"#,
        fx.path(r"ro\in.txt").display(),
        fx.path(r"un\secret.txt").display()
    );
    let out = run(&fx.caps(), &fx.cmd(&script));
    assert!(out.stdout.contains("readable"), "{}", out.stderr);
    assert_ne!(out.code, 0);
    assert!(!out.stdout.contains("secret"));
}

#[test]
fn deny_inside_read_write_grant() {
    if !psec_or_skip() || !Sandbox::windows_support().fs_deny {
        return;
    }
    let fx = Fixture::new();
    fs::write(fx.path(r"rw\visible.txt"), "visible").unwrap();
    let script = format!(
        r#"type {} && type {}"#,
        fx.path(r"rw\visible.txt").display(),
        fx.path(r"rw\deny\hidden.txt").display()
    );
    let opts = fx.cmd(&script).deny_path(fx.path(r"rw\deny"));
    let out = run(&fx.caps(), &opts);
    assert!(out.stdout.contains("visible"), "{}", out.stderr);
    assert_ne!(out.code, 0);
    assert!(!out.stdout.contains("hidden"));
}

/// Enumerate grants as observed on build 26300: on an ordinary directory they
/// do not even allow listing it, but on a volume root they cascade and allow
/// listing every file name on the volume. They never allow reading content.
/// The CLI makes ancestor enumeration (which needs the volume root) opt-in
/// for that reason. If this test starts failing, the platform changed.
#[test]
fn enumerate_grants_list_only_via_volume_root_and_never_read() {
    if !psec_or_skip() || !Sandbox::windows_support().fs_enumerate {
        return;
    }
    let fx = Fixture::new();
    let list = format!("dir /b {}", fx.path("un").display());
    let read = format!("type {}", fx.path(r"un\secret.txt").display());
    let volume_root = fx.root.ancestors().last().unwrap().to_path_buf();
    let listed = |paths: &[PathBuf]| {
        let mut opts = fx.cmd(&list);
        for p in paths {
            opts = opts.enumerate_path(p);
        }
        run(&fx.caps(), &opts).stdout.contains("secret.txt")
    };

    assert!(!listed(&[]), "listed without any enumerate grant");
    assert!(
        !listed(&[fx.root.clone(), fx.path("un")]),
        "ordinary enumerate grants allowed listing"
    );
    assert!(
        listed(std::slice::from_ref(&volume_root)),
        "volume-root enumerate no longer cascades"
    );

    let opts = fx.cmd(&read).enumerate_path(&volume_root);
    let out = run(&fx.caps(), &opts);
    assert_ne!(out.code, 0);
    assert!(
        !out.stdout.contains("secret"),
        "enumerate must not grant reads"
    );
}

#[test]
fn environment_is_exactly_what_was_passed() {
    if !psec_or_skip() {
        return;
    }
    // USERNAME is set in the test process and must not reach the child.
    let fx = Fixture::new();
    let out = run(&fx.caps(), &fx.cmd("set").env("NONO_MARKER", "present"));
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("NONO_MARKER=present"));
    assert!(!out.stdout.contains("USERNAME="), "{}", out.stdout);
}

fn curl(fx: &Fixture, port: u16) -> LaunchOptions {
    let mut opts = LaunchOptions::new(system32("curl.exe"), fx.path("rw"))
        .args([
            "-s".to_string(),
            "-o".to_string(),
            "NUL".to_string(),
            "-m".to_string(),
            "5".to_string(),
            format!("http://127.0.0.1:{port}/"),
        ])
        .allow_win32k(true)
        .stdio(LaunchStdio::Piped);
    for (key, value) in base_env() {
        opts = opts.env(key, value);
    }
    opts
}

/// Accept one connection and answer with a minimal HTTP response.
fn serve_once(listener: TcpListener) -> std::thread::JoinHandle<bool> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::Write;
                let mut buf = [0u8; 1024];
                let _ = stream.set_nonblocking(false);
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    })
}

#[test]
fn blocked_network_refuses_loopback() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = serve_once(listener);
    let out = run(&fx.caps(), &curl(&fx, port));
    assert_ne!(
        out.code, 0,
        "curl reached a loopback port under a blocked policy"
    );
    drop(server);
}

#[test]
fn proxy_only_reaches_only_the_proxy_port() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = other.local_addr().unwrap().port();
    let caps = CapabilitySet::new()
        .allow_path(fx.path("rw"), AccessMode::ReadWrite)
        .unwrap()
        .proxy_only(proxy_port);

    let curl = |port| curl(&fx, port).allow_private_network_inbound(true);

    let served = serve_once(proxy);
    let out = run(&caps, &curl(proxy_port));
    assert_eq!(out.code, 0, "proxy port unreachable: {}", out.stderr);
    assert!(served.join().unwrap());

    let _other_server = serve_once(other);
    let out = run(&caps, &curl(other_port));
    assert_ne!(out.code, 0, "a non-proxy loopback port was reachable");
}

/// A verbatim path may name `safe.`, a directory distinct from `safe`.
/// Emitted without the prefix, a grant on it also opened `safe` (observed on
/// build 26300), so such paths are refused.
#[test]
fn verbatim_name_with_trailing_dot_is_refused() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    let dotted = format!(r"\\?\{}.", fx.path("un").display());
    fs::create_dir_all(&dotted).unwrap();
    let caps = CapabilitySet::new()
        .allow_path(fx.path("rw"), AccessMode::ReadWrite)
        .unwrap()
        .allow_path(&dotted, AccessMode::Read)
        .unwrap();
    let err = Sandbox::launch(&caps, &fx.cmd("exit 0")).err();
    assert!(
        err.as_ref()
            .is_some_and(|e| e.to_string().contains("dot or space")),
        "{err:?}"
    );
}

/// Inside the sandbox, a read-only file grant that sits in a read-write
/// tree can be neither deleted nor shadowed by a junction to an ungranted
/// directory.
#[test]
fn file_grant_cannot_be_replaced_from_inside() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    fs::create_dir_all(fx.path(r"rw\sub")).unwrap();
    fs::write(fx.path(r"rw\sub\f.txt"), "file-grant").unwrap();
    let caps = CapabilitySet::new()
        .allow_path(fx.path("rw"), AccessMode::ReadWrite)
        .unwrap()
        .allow_file(fx.path(r"rw\sub\f.txt"), AccessMode::Read)
        .unwrap();

    let out = run(&caps, &fx.cmd(r"type sub\f.txt"));
    assert!(
        out.stdout.contains("file-grant"),
        "positive control: {}",
        out.stderr
    );

    let script = format!(
        r"del sub\f.txt & mklink /J sub\j {} & type sub\j\secret.txt",
        fx.path("un").display()
    );
    let out = run(&caps, &fx.cmd(&script));
    assert!(
        fx.path(r"rw\sub\f.txt").exists(),
        "the file grant was deleted"
    );
    assert!(!out.stdout.contains("secret"), "{}", out.stdout);
    assert!(!fx.path(r"rw\sub\j").exists(), "a junction was created");
}

#[test]
fn terminate_ends_the_process_tree() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    // The child starts a busy-looping grandchild and then loops itself.
    // (ping would exit at once: ICMP is refused under a blocked policy.)
    let opts =
        fx.cmd("start /b cmd /d /c for /l %j in (0,0,1) do @rem & for /l %i in (0,0,1) do @rem");
    let mut child = Sandbox::launch(&fx.caps(), &opts).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(child.try_wait().unwrap(), None);
    child.terminate().unwrap();
    assert!(
        child
            .wait_timeout(Duration::from_secs(5))
            .unwrap()
            .is_some(),
        "child survived terminate"
    );
}

#[test]
fn drop_ends_background_descendants_after_main_exit() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    let beacon = fx.path(r"rw\beacon.txt");
    // The main process exits at once; the grandchild keeps appending.
    let script = format!(
        "start /b cmd /d /c for /l %j in (0,0,1) do @echo x>> {} & exit 0",
        beacon.display()
    );
    let mut child = Sandbox::launch(&fx.caps(), &fx.cmd(&script)).unwrap();
    assert_eq!(
        child.wait_timeout(Duration::from_secs(10)).unwrap(),
        Some(0)
    );
    std::thread::sleep(Duration::from_millis(300));
    let growing = fs::metadata(&beacon).map(|m| m.len()).unwrap_or(0);
    assert!(growing > 0, "grandchild never ran");
    drop(child);
    std::thread::sleep(Duration::from_millis(300));
    let after_drop = fs::metadata(&beacon).unwrap().len();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        fs::metadata(&beacon).unwrap().len(),
        after_drop,
        "grandchild still running after drop"
    );
}

/// whoami.exe loads user32: it must fail to initialise with win32k blocked
/// (the default) and run with it allowed.
#[test]
fn win32k_is_blocked_by_default_and_allowed_on_request() {
    if !psec_or_skip() {
        return;
    }
    const STATUS_DLL_INIT_FAILED: u32 = 0xC000_0142;
    let fx = Fixture::new();
    let whoami = |allow: bool| {
        let mut opts = LaunchOptions::new(system32("whoami.exe"), fx.path("rw"))
            .allow_win32k(allow)
            .stdio(LaunchStdio::Piped);
        for (key, value) in base_env() {
            opts = opts.env(key, value);
        }
        run(&fx.caps(), &opts)
    };
    assert_eq!(whoami(false).code, STATUS_DLL_INIT_FAILED);
    let allowed = whoami(true);
    assert_eq!(allowed.code, 0, "{}", allowed.stderr);
    assert!(!allowed.stdout.trim().is_empty());
}

#[test]
fn missing_psec_environment_variables_fail_before_launch() {
    let fx = Fixture::new();
    let opts = LaunchOptions::new(system32("cmd.exe"), fx.path("rw")).env("PATH", "x");
    let err = Sandbox::launch(&fx.caps(), &opts)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("SYSTEMROOT") || err.contains("PSEC"), "{err}");
}

#[test]
fn relative_program_is_rejected() {
    if !psec_or_skip() {
        return;
    }
    let fx = Fixture::new();
    let mut opts = LaunchOptions::new("cmd.exe", fx.path("rw"));
    for (key, value) in base_env() {
        opts = opts.env(key, value);
    }
    assert!(Sandbox::launch(&fx.caps(), &opts).is_err());
}

#[test]
fn rendered_policy_lists_grants_and_network() {
    let fx = Fixture::new();
    let policy = Sandbox::render_launch_policy(&fx.caps(), &fx.cmd("exit 0")).unwrap();
    let text = policy.to_string();
    assert!(text.contains("read-write"), "{text}");
    assert!(text.contains("network:   blocked"), "{text}");
    assert!(policy.win32k_allowed);
}
