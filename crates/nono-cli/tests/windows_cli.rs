//! End-to-end tests for the native Windows front end (`src/windows/`).
//!
//! Each test drives the real `nono` binary through the shared hermetic
//! harness. Tests that need enforcement are skipped on hosts without Windows
//! ProcessContainer (PSEC), unless `NONO_REQUIRE_ENFORCEMENT=1` is set, in
//! which case a skip is a failure. Every denial has a positive control with
//! the same command shape, so a denial cannot pass because the command was
//! broken.

#![cfg(windows)]

use std::fs;
use std::io::ErrorKind;
use std::net::TcpListener;
use std::path::{Component, PathBuf};

use nono_test_support::{Argv, NonoTest, nono_test};

/// `0xC0000142` (STATUS_DLL_INIT_FAILED) as `ExitStatus::code` reports it.
const STATUS_DLL_INIT_FAILED: i32 = i32::from_ne_bytes(0xC000_0142_u32.to_ne_bytes());

/// True when PSEC is usable. Without it the test is skipped, or fails when
/// `NONO_REQUIRE_ENFORCEMENT` is set.
fn psec(t: &NonoTest) -> bool {
    let out = t.raw(&["setup", "--check-only"]);
    if out
        .stdout()
        .contains("mechanism:       Windows ProcessContainer (PSEC) 1.")
    {
        return true;
    }
    assert!(
        std::env::var_os("NONO_REQUIRE_ENFORCEMENT").is_none(),
        "PSEC required but unavailable:\n{}",
        out.stdout()
    );
    eprintln!("skipping: PSEC unavailable");
    false
}

/// A directory under the workspace holding the given files.
fn dir(t: &NonoTest, name: &str, files: &[(&str, &str)]) -> PathBuf {
    let path = t.workspace().join(name);
    fs::create_dir_all(&path).expect("workspace is a fresh dir this test owns");
    for (file, contents) in files {
        let file = path.join(file);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent).expect("workspace is a fresh dir this test owns");
        }
        fs::write(file, contents).expect("workspace is a fresh dir this test owns");
    }
    path
}

/// `cmd /d /c <script>`. The script must not contain `"`: cmd does not
/// honour `CommandLineToArgvW` escapes.
fn cmd(script: &str) -> Argv {
    Argv::new("cmd").arg("/d").arg("/c").arg(script)
}

fn curl(args: &[&str]) -> Argv {
    args.iter()
        .fold(Argv::new("curl"), |argv, arg| argv.arg(arg))
}

/// A loopback listener that records whether anything connected.
fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback is available");
    listener
        .set_nonblocking(true)
        .expect("loopback listener accepts nonblocking mode");
    let port = listener
        .local_addr()
        .expect("bound listener has an address")
        .port();
    (listener, port)
}

fn was_connected(listener: &TcpListener) -> bool {
    match listener.accept() {
        Ok(_) => true,
        Err(e) if e.kind() == ErrorKind::WouldBlock => false,
        Err(e) => panic!("accept failed: {e}"),
    }
}

#[test]
fn setup_reports_the_mechanism_and_what_is_not_ported() {
    let t = nono_test!("win-setup");
    t.raw(&["setup", "--check-only"])
        .assert_success("setup --check-only only reports")
        .assert_stdout_contains("platform:        windows")
        .assert_stdout_contains("mechanism:")
        .assert_stdout_contains("not ported:");
}

#[test]
fn read_write_grant_allows_writes_in_the_granted_dir() {
    let t = nono_test!("win-rw");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    t.run()
        .allow(&rw)
        .launch_dir(&rw)
        .exec(cmd("echo written>out.txt"))
        .assert_success("rw grant permits writes");
    let written = fs::read_to_string(rw.join("out.txt")).expect("the child wrote out.txt");
    assert_eq!(written.trim(), "written");
}

#[test]
fn read_grant_reads_but_refuses_writes() {
    let t = nono_test!("win-ro");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    let ro = dir(&t, "ro", &[("ro.txt", "ro-content")]);

    t.run()
        .allow(&rw)
        .read(&ro)
        .launch_dir(&rw)
        .exec(cmd(&format!("type {}", ro.join("ro.txt").display())))
        .assert_success("read grant permits reads")
        .assert_stdout_contains("ro-content");

    t.run()
        .allow(&rw)
        .read(&ro)
        .launch_dir(&rw)
        .exec(cmd(&format!("echo x>{}", ro.join("new.txt").display())))
        .assert_failure("read grant must refuse writes");
    assert!(!ro.join("new.txt").exists(), "write escaped a read grant");
}

#[test]
fn ungranted_path_is_unreadable() {
    let t = nono_test!("win-ungranted");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    let secret = dir(&t, "secret", &[("s.txt", "top-secret")]);
    let read_secret = cmd(&format!("type {}", secret.join("s.txt").display()));

    t.run()
        .allow(&rw)
        .launch_dir(&rw)
        .exec(read_secret.clone())
        .assert_failure("an ungranted file must be unreadable")
        .assert_stdout_lacks("top-secret");

    t.run()
        .allow(&rw)
        .read(&secret)
        .launch_dir(&rw)
        .exec(read_secret)
        .assert_success("positive control: the same read with a grant")
        .assert_stdout_contains("top-secret");
}

#[test]
fn deny_inside_a_grant_wins() {
    let t = nono_test!("win-deny");
    if !psec(&t) {
        return;
    }
    let rw = dir(
        &t,
        "rw",
        &[("ok.txt", "ok-content"), ("deny/d.txt", "denied-content")],
    );

    t.run()
        .allow(&rw)
        .deny(rw.join("deny"))
        .launch_dir(&rw)
        .exec(cmd(r"type deny\d.txt"))
        .assert_failure("a denied path inside a grant must be unreadable")
        .assert_stdout_lacks("denied-content");

    t.run()
        .allow(&rw)
        .deny(rw.join("deny"))
        .launch_dir(&rw)
        .exec(cmd("type ok.txt"))
        .assert_success("positive control: the rest of the grant stays readable")
        .assert_stdout_contains("ok-content");
}

#[test]
fn write_only_access_is_refused_not_widened() {
    let t = nono_test!("win-write-only");
    let rw = dir(&t, "rw", &[]);
    t.run()
        .write(&rw)
        .exec(cmd("echo x>out.txt"))
        .assert_failure("PSEC has no write-only grant")
        .assert_stderr_contains("not available on Windows");
    assert!(!rw.join("out.txt").exists());
}

#[test]
fn exit_code_is_propagated() {
    let t = nono_test!("win-exit");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    t.run()
        .allow(&rw)
        .launch_dir(&rw)
        .exec(cmd("exit 7"))
        .assert_exit_code(7, "the workload's exit code reaches the caller");
}

/// PSEC points TEMP at the container's own temp folder: writable, distinct
/// per run, and removed when the run ends.
#[test]
fn temp_is_private_to_each_run_and_removed_afterwards() {
    let t = nono_test!("win-temp");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    let temp_of_one_run = || {
        let out = t
            .run()
            .allow(&rw)
            .launch_dir(&rw)
            .exec(cmd(
                r"echo %TEMP%&&echo temp-ok>%TEMP%\t.txt&&type %TEMP%\t.txt",
            ))
            .assert_success("TEMP is writable")
            .assert_stdout_contains("temp-ok");
        PathBuf::from(out.stdout().lines().next().unwrap_or_default().trim())
    };

    let first = temp_of_one_run();
    let second = temp_of_one_run();
    assert!(
        first.ends_with(r"AC\Temp"),
        "TEMP is not the container's temp folder: {}",
        first.display()
    );
    assert_ne!(first, second, "two runs shared a TEMP folder");
    assert!(
        !first.exists(),
        "the container's temp folder outlived the run: {}",
        first.display()
    );
}

#[test]
fn block_net_refuses_loopback() {
    let t = nono_test!("win-block-net");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    let (listener, port) = listener();

    t.run()
        .allow(&rw)
        .block_net()
        .allow_win32k()
        .launch_dir(&rw)
        .exec(curl(&["--version"]))
        .assert_success("positive control: curl itself runs under --block-net");

    let url = format!("http://127.0.0.1:{port}/");
    t.run()
        .allow(&rw)
        .block_net()
        .allow_win32k()
        .launch_dir(&rw)
        .exec(curl(&["-s", "-o", "NUL", "-m", "5", &url]))
        .assert_failure("--block-net must refuse loopback connections");
    assert!(!was_connected(&listener), "a connection got through");
}

#[test]
fn allow_domain_filters_through_the_proxy() {
    let t = nono_test!("win-proxy");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    let status = |url: &str| {
        t.run()
            .allow(&rw)
            .allow_domain("allowed.invalid")
            .allow_private_inbound()
            .allow_win32k()
            .launch_dir(&rw)
            .exec(curl(&[
                "-s",
                "-o",
                "NUL",
                "-w",
                "%{http_code}",
                "-m",
                "15",
                url,
            ]))
            .stdout()
            .trim()
            .to_string()
    };

    assert_eq!(
        status("http://denied.invalid/"),
        "403",
        "the proxy must refuse a host outside the allowlist"
    );
    // Positive control: an allowed host passes the filter. The proxy then
    // fails to resolve it, which is an upstream error, not a refusal. "000"
    // would mean curl never reached the proxy.
    let allowed = status("http://allowed.invalid/");
    assert!(
        allowed != "403" && allowed != "000",
        "allowed host was refused or the proxy was unreachable: {allowed}"
    );
}

#[test]
fn direct_connection_bypassing_the_proxy_is_refused() {
    let t = nono_test!("win-proxy-bypass");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    let (listener, port) = listener();
    let url = format!("http://127.0.0.1:{port}/");
    t.run()
        .allow(&rw)
        .allow_domain("allowed.invalid")
        .allow_private_inbound()
        .allow_win32k()
        .launch_dir(&rw)
        .exec(curl(&[
            "--noproxy",
            "*",
            "-s",
            "-o",
            "NUL",
            "-m",
            "5",
            &url,
        ]))
        .assert_failure("only the proxy port is reachable in proxy-only mode");
    assert!(!was_connected(&listener), "a direct connection got through");
}

#[test]
fn dry_run_shows_the_policy_but_not_environment_values() {
    let t = nono_test!("win-dry-run");
    let rw = dir(&t, "rw", &[]);
    t.run()
        .allow(&rw)
        .dry_run()
        .env("API_TOKEN_FOR_TEST", "hunter2-value")
        .exec(cmd("echo never-runs"))
        .assert_success("dry-run only prints the policy")
        .assert_stdout_contains("read-write")
        .assert_stdout_contains(&rw.display().to_string())
        .assert_stdout_contains("win32k:    blocked")
        .assert_stdout_contains("internet only (host loopback and private networks blocked)")
        .assert_stdout_contains("implicit:  read: files and directories whose ACL grants")
        .assert_stdout_contains("API_TOKEN_FOR_TEST")
        .assert_stdout_lacks("hunter2-value")
        .assert_stdout_lacks("enumerate")
        .assert_stdout_lacks("never-runs");
}

#[test]
fn proxy_mode_requires_accepting_private_inbound() {
    let t = nono_test!("win-proxy-ack");
    let rw = dir(&t, "rw", &[]);
    t.run()
        .allow(&rw)
        .allow_domain("allowed.invalid")
        .dry_run()
        .exec(cmd("echo never-runs"))
        .assert_failure("proxy mode admits private-network inbound; it must be accepted")
        .assert_stderr_contains("--allow-private-inbound");

    t.run()
        .allow(&rw)
        .allow_domain("allowed.invalid")
        .allow_private_inbound()
        .dry_run()
        .exec(cmd("echo never-runs"))
        .assert_success("positive control: accepted explicitly")
        .assert_stdout_contains("inbound from private networks admitted");
}

/// `\\?\...\safe.` names a directory distinct from `safe`, and a grant on it
/// emitted without the prefix also opened `safe` (build 26300).
#[test]
fn verbatim_name_with_trailing_dot_is_refused() {
    let t = nono_test!("win-dotted");
    let rw = dir(&t, "rw", &[]);
    let safe = dir(&t, "safe", &[("secret.txt", "SAFE-SECRET")]);
    let dotted = format!(r"\\?\{}.", safe.display());
    fs::create_dir_all(&dotted).expect("verbatim paths can name a dotted directory");
    t.run()
        .allow(&rw)
        .read(&dotted)
        .launch_dir(&rw)
        .exec(cmd(&format!("type {}", safe.join("secret.txt").display())))
        .assert_failure("a name Windows would rewrite must not be granted")
        .assert_stderr_contains("dot or space")
        .assert_stdout_lacks("SAFE-SECRET");
}

/// The interactive path: a new console makes nono host a pseudo console and
/// run the workload through the console shim. The shim sits in nono's
/// kill-on-close job, so the workload is assigned to its own UI-limited job
/// from inside another job.
#[test]
fn interactive_run_works_inside_the_shim_job() {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_CONSOLE, CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION,
        STARTF_USESHOWWINDOW, STARTUPINFOW, WaitForSingleObject,
    };

    let t = nono_test!("win-interactive");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    let nono = env!("CARGO_BIN_EXE_nono");
    // No argument needs quoting except the paths, which hold no quotes.
    let line = format!(
        "\"{nono}\" run --allow \"{}\" -- cmd /d /c echo ran>marker.txt&&exit 7",
        rw.display()
    );
    let mut line: Vec<u16> = line.encode_utf16().chain(Some(0)).collect();
    let cwd: Vec<u16> = rw.as_os_str().encode_wide().chain(Some(0)).collect();

    // SAFETY: plain data; all-zero is a valid value.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(u32::MAX);
    // A hidden window; no STARTF_USESTDHANDLES, so the console is nono's
    // standard input and output.
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = 0;
    // SAFETY: plain data; all-zero is a valid value.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated mutable command line and working directory that
    // outlive the call; no handles are inherited.
    let created = unsafe {
        CreateProcessW(
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_NEW_CONSOLE,
            std::ptr::null(),
            cwd.as_ptr(),
            &startup,
            &mut info,
        )
    };
    assert_ne!(created, 0, "could not start nono in a new console");
    // SAFETY: live process handle from CreateProcessW.
    let waited = unsafe { WaitForSingleObject(info.hProcess, 60_000) };
    let mut code = u32::MAX;
    // SAFETY: live process handle and out-pointer.
    unsafe { GetExitCodeProcess(info.hProcess, &mut code) };
    // SAFETY: both handles came from CreateProcessW and are closed once.
    unsafe {
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
    }
    assert_eq!(waited, WAIT_OBJECT_0, "interactive nono did not exit");
    assert_eq!(code, 7, "the workload's exit code did not reach the caller");
    let marker = fs::read_to_string(rw.join("marker.txt")).unwrap_or_default();
    assert_eq!(marker.trim(), "ran", "the workload did not run");
}

#[test]
fn enumerate_ancestors_is_opt_in_and_flagged() {
    let t = nono_test!("win-enumerate");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    let root: PathBuf = rw
        .components()
        .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        .collect();
    t.run()
        .allow(&rw)
        .enumerate_ancestors()
        .dry_run()
        .exec(cmd("echo"))
        .assert_success("dry-run only prints the policy")
        .assert_stdout_contains(&format!("enumerate  {}", root.display()))
        .assert_stdout_contains("exposes every file name");
}

#[test]
fn injection_variables_do_not_reach_the_workload() {
    let t = nono_test!("win-env");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    t.run()
        .allow(&rw)
        .launch_dir(&rw)
        .env("KEEP_ME_VAR", "kept")
        .env("COR_ENABLE_PROFILING", "1")
        .env("COR_PROFILER", "{00000000-0000-0000-0000-000000000000}")
        .env("CORECLR_PROFILER_PATH", r"C:\evil.dll")
        .env("NODE_OPTIONS", "--require evil")
        .env("__COMPAT_LAYER", "RunAsInvoker")
        .exec(cmd("set"))
        .assert_success("set lists the environment")
        .assert_stdout_contains("KEEP_ME_VAR=kept")
        .assert_stdout_lacks("COR_ENABLE_PROFILING")
        .assert_stdout_lacks("COR_PROFILER")
        .assert_stdout_lacks("CORECLR_PROFILER_PATH")
        .assert_stdout_lacks("NODE_OPTIONS")
        .assert_stdout_lacks("__COMPAT_LAYER");
}

#[test]
fn win32k_is_blocked_by_default_with_a_hint() {
    let t = nono_test!("win-win32k");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[]);
    // whoami.exe loads user32.
    t.run()
        .allow(&rw)
        .launch_dir(&rw)
        .exec(Argv::new("whoami"))
        .assert_exit_code(STATUS_DLL_INIT_FAILED, "user32 cannot initialise")
        .assert_stderr_contains("--allow-win32k");

    t.run()
        .allow(&rw)
        .allow_win32k()
        .launch_dir(&rw)
        .exec(Argv::new("whoami"))
        .assert_success("positive control: the same program with win32k");
}

#[test]
fn unknown_command_fails_closed() {
    let t = nono_test!("win-not-found");
    t.run()
        .exec(Argv::new("nono-no-such-command-for-tests"))
        .assert_failure("an unresolvable program must not run")
        .assert_stderr_contains("command not found on PATH");
}

#[test]
fn unported_flags_are_rejected_not_ignored() {
    let t = nono_test!("win-unported");
    t.run()
        .profile_name("default")
        .exec(cmd("echo never-runs"))
        .assert_failure("--profile is not implemented on Windows")
        .assert_stdout_lacks("never-runs");
}

/// A batch file named with a trailing dot still gets the batch argument
/// filter, and the refusal happens before anything is launched.
///
/// Starting a batch file directly fails under PSEC on build 26300 ("Access
/// is denied."); `cmd /c call` works, which is the positive control that the
/// file itself is runnable.
#[test]
fn batch_arguments_are_filtered_even_with_a_trailing_dot() {
    let t = nono_test!("win-batch");
    if !psec(&t) {
        return;
    }
    let rw = dir(&t, "rw", &[("run.bat", "@echo batch ran %*\r\n")]);

    t.run()
        .allow(&rw)
        .launch_dir(&rw)
        .exec(cmd(r"call .\run.bat safe-arg"))
        .assert_success("positive control: the batch file runs")
        .assert_stdout_contains("batch ran safe-arg");

    let mut trailing_dot = rw.join("run.bat").into_os_string();
    trailing_dot.push(".");
    t.run()
        .allow(&rw)
        .launch_dir(&rw)
        .exec(Argv::new(&trailing_dot).arg("x&echo INJECTED"))
        .assert_failure("cmd metacharacters must not reach a batch file")
        .assert_stderr_contains("cannot be passed safely to a batch file")
        .assert_stdout_lacks("INJECTED");
}
