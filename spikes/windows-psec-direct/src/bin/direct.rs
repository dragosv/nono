//! Direct-FFI PSEC spike driver (no mxc-sdk).
//! Usage: `direct <fixture-root> [host|fs|net|cleanup|pty|all]`
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;
use windows_psec_direct::{Api, Child, Net, Policy, Stdio, launch};

struct Ctx {
    api: Api,
    minor: u16,
    root: PathBuf,
    probe: String,
    probe_dir: String,
    env: Vec<(String, String)>,
}

impl Ctx {
    fn p(&self, rel: &str) -> String {
        self.root.join(rel).display().to_string()
    }
    fn policy(&self, rw: &[String], ro: &[String], deny: &[String], net: Net) -> Policy {
        let mut read_only = ro.to_vec();
        read_only.push(self.probe_dir.clone());
        let mut read_write = rw.to_vec();
        read_write.push(self.p("tmp"));
        Policy { read_write, read_only, deny: deny.to_vec(), enumerate: Vec::new(), net, allow_win32k: false, unconfined_control: false }
    }
    fn run(&self, title: &str, policy: &Policy, ops: &str) {
        println!("\n=== {title}");
        let args: Vec<String> = ops.split_whitespace().map(str::to_string).collect();
        match launch(&self.api, policy, self.minor, &self.probe, &args, &self.probe_dir, &self.env, Stdio::Piped) {
            Ok(mut c) => {
                let mut out = String::new();
                if let Some(s) = c.stdout.as_mut() {
                    let _ = s.read_to_string(&mut out);
                }
                println!("exit: {:?}", c.wait_ms(60_000));
                print!("{out}");
            }
            Err(e) => println!("LAUNCH ERROR: {}", e.0),
        }
    }
}

fn listener(tag: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut buf = [0u8; 256];
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.read(&mut buf);
            let _ = s.write_all(format!("HTTP/1.0 200 {tag}\r\n\r\n").as_bytes());
        }
    });
    port
}

fn pid_alive(pid: &str) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(pid))
        .unwrap_or(false)
}

fn main() {
    // Clear an inherited "ignore Ctrl-C" console flag (set by some shells) so
    // children we start get default Ctrl-C handling.
    // SAFETY: a null handler with FALSE restores default Ctrl-C processing.
    unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 0) };
    let args: Vec<String> = std::env::args().collect();
    let root = PathBuf::from(args.get(1).expect("usage: direct <fixture-root> [scenario]"));
    let which = args.get(2).cloned().unwrap_or_else(|| "all".into());
    let all = which == "all";
    std::fs::create_dir_all(root.join("tmp")).expect("tmp");

    let api = match Api::load() {
        Ok(a) => a,
        Err(e) => {
            println!("PSEC API unavailable: {}", e.0);
            std::process::exit(2);
        }
    };
    let minor = api.version_supported(1).ok().flatten().unwrap_or(0) as u16;
    if all || which == "host" {
        println!("=== host");
        println!("PSEC v1 supported minor: {:?}", api.version_supported(1).map_err(|e| e.0));
        println!("PSEC v2 supported: {:?}", api.version_supported(2).map_err(|e| e.0));
        println!("support flags: {:?}", api.support_flags().map(|f| format!("0x{f:x}")).map_err(|e| e.0));
    }

    let exe = std::env::current_exe().expect("exe");
    let probe_dir = exe.parent().expect("dir").display().to_string();
    let tmp = root.join("tmp").display().to_string();
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    // Explicit environment: nothing from the launcher leaks in by construction.
    let env = vec![
        ("SystemRoot".into(), sysroot.clone()),
        ("windir".into(), sysroot.clone()),
        ("PATH".into(), format!("{sysroot}\\System32;{sysroot}")),
        ("PATHEXT".into(), ".COM;.EXE;.BAT;.CMD".into()),
        ("ComSpec".into(), format!("{sysroot}\\System32\\cmd.exe")),
        // PSEC requires SYSTEMROOT and LOCALAPPDATA to be present (else Win32 error 203).
        ("LOCALAPPDATA".into(), std::env::var("LOCALAPPDATA").unwrap_or_default()),
        ("TEMP".into(), tmp.clone()),
        ("TMP".into(), tmp),
    ];
    let ctx = Ctx {
        api,
        minor,
        probe: format!("{probe_dir}\\probe.exe"),
        probe_dir,
        root,
        env,
    };

    if all || which == "fs" {
        fs(&ctx);
    }
    if all || which == "net" {
        net(&ctx);
    }
    if all || which == "cleanup" {
        cleanup(&ctx);
    }
    if all || which == "pty" {
        pty(&ctx);
    }
    if all || which == "ptyshim" {
        pty_shim(&ctx);
    }
    if all || which == "cmdchild" {
        cmd_child(&ctx);
    }
    if which == "shim" {
        shim(&ctx, &args[3..]);
    }
}

/// `direct <root> shim <win32k 0|1> <program> [args...]`: runs unconfined,
/// attached to whatever console it was given (e.g. a ConPTY), and launches
/// `program` under PSEC inheriting that console. Exits with the child's code.
fn shim(ctx: &Ctx, rest: &[String]) {
    let mut pol = ctx.policy(&[], &[], &[], Net::Blocked);
    pol.allow_win32k = rest.first().map(String::as_str) == Some("1");
    pol.enumerate = std::path::Path::new(&ctx.probe_dir)
        .ancestors()
        .skip(1)
        .map(|p| p.display().to_string())
        .collect();
    let program = rest.get(1).expect("shim program");
    match launch(&ctx.api, &pol, ctx.minor, program, &rest[2..], &ctx.probe_dir, &ctx.env, Stdio::InheritConsole) {
        Ok(c) => {
            let code = c.wait_ms(u32::MAX).ok().flatten().unwrap_or(1);
            std::process::exit(code as i32);
        }
        Err(e) => {
            eprintln!("shim launch error: {}", e.0);
            std::process::exit(99);
        }
    }
}

fn pty_shim(ctx: &Ctx) {
    let exe = std::env::current_exe().expect("exe").display().to_string();
    let root = ctx.root.display().to_string();
    let cmd = format!(r"{}\System32\cmd.exe", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
    let host = |title: &str, inner: &[&str], resize_after_ms: Option<u64>, ctrl_c: bool| {
        println!("\n=== ConPTY -> unconfined shim -> PSEC child: {title}");
        let mut pol = ctx.policy(&[], &[], &[], Net::Blocked);
        pol.unconfined_control = true;
        let mut args = vec![root.clone(), "shim".to_string()];
        args.extend(inner.iter().map(|s| s.to_string()));
        match launch(&ctx.api, &pol, ctx.minor, &exe, &args, &ctx.probe_dir, &ctx.env, Stdio::Pty { cols: 80, rows: 25 }) {
            Ok(mut c) => {
                let mut out = c.stdout.take().expect("out");
                let reader = std::thread::spawn(move || {
                    let mut s = Vec::new();
                    let _ = out.read_to_end(&mut s);
                    s
                });
                if let Some(ms) = resize_after_ms {
                    std::thread::sleep(Duration::from_millis(ms));
                    println!("resize -> 120x40: {:?}", c.resize(120, 40).map_err(|e| e.0));
                }
                if ctrl_c {
                    std::thread::sleep(Duration::from_millis(1500));
                    let mut input = c.pty_in.take().expect("pty in");
                    println!("send ^C: {:?}", input.write_all(b"\x03").and_then(|_| input.flush()));
                    let t = std::time::Instant::now();
                    println!("exit after ^C: {:?} in {} ms", c.wait_ms(5000).map(|o| o.map(|v| format!("0x{v:x}"))).map_err(|e| e.0), t.elapsed().as_millis());
                } else {
                    println!("exit: {:?}", c.wait_ms(15_000).map(|o| o.map(|v| format!("0x{v:x}"))).map_err(|e| e.0));
                }
                c.close_pty();
                drop(c);
                let raw = reader.join().unwrap_or_default();
                println!("  (raw {} bytes, contains \"120\": {})", raw.len(), String::from_utf8_lossy(&raw).contains("120"));
                let clean = strip_ansi(&String::from_utf8_lossy(&raw));
                for l in clean.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("Keyboard") && !l.starts_with("Code page") && !l.starts_with("---")) {
                    println!("  | {l}");
                }
            }
            Err(e) => println!("LAUNCH ERROR: {}", e.0),
        }
    };
    let probe = ctx.probe.clone();
    let un = format!("{}\\un.txt", ctx.p("un"));
    host("cmd echo + mode con (win32k)", &["1", &cmd, "/c", "echo", "PTY_OK", "&", "mode", "con"], None, false);
    host("confinement still applies (read ungranted)", &["0", &probe, "read", &un, ";", "tcp", "1.1.1.1:443"], None, false);
    host("resize while running", &["1", &cmd, "/c", "(for /l %i in (1,1,20000) do @cd .) & mode con"], Some(300), false);
    let via_cmd = format!("{probe} env TEMP");
    host("cmd.exe starting probe.exe (Access denied check)", &["1", &cmd, "/c", &via_cmd], None, false);
    host("cmd.exe starting probe.exe, win32k off", &["0", &cmd, "/c", &via_cmd], None, false);
    host("Ctrl-C to sleeping PSEC child", &["0", &probe, "sleep", "30"], None, true);
}

fn fs(ctx: &Ctx) {
    let pol = ctx.policy(&[ctx.p("rw")], &[ctx.p("ro"), ctx.p("files\\a.txt")], &[ctx.p("rw\\deny")], Net::Blocked);
    let ops = format!(
        "write {rw}\\direct.txt ; read {ro}\\ro.txt ; write {ro}\\x.txt ; read {un}\\un.txt ; read {fa} ; read {fb} ; \
         read {rw}\\deny\\s.txt ; write {rw}\\deny\\y.txt ; read {rw}\\junc\\un.txt ; read {un}\\un.txt:s ; \
         env SPIKE_LAUNCHER_SECRET ; env TEMP ; write {tmp}\\t.txt ; \
         child read {un}\\un.txt ; write {ro}\\c1.txt ; child read {rw}\\deny\\s.txt",
        rw = ctx.p("rw"),
        ro = ctx.p("ro"),
        un = ctx.p("un"),
        fa = ctx.p("files\\a.txt"),
        fb = ctx.p("files\\b.txt"),
        tmp = ctx.p("tmp"),
    );
    ctx.run("fs: rw/ro/single-file/deny/junction/ADS/env/descendants", &pol, &ops);
}

fn net(ctx: &Ctx) {
    let pa = listener("proxyA");
    let pb = listener("other");
    let probes = format!(
        "tcp 1.1.1.1:443 ; tcp [2606:4700:4700::1111]:443 ; udpdns 1.1.1.1:53 ; resolve rust-lang.org ; \
         httpget 127.0.0.1:{pa} ; tcp 127.0.0.1:{pb} ; tcp [::1]:{pb} ; child tcp 1.1.1.1:443 ; httpget 127.0.0.1:{pa} ; tcp 127.0.0.1:{pb}"
    );
    ctx.run("net: allow-all control", &ctx.policy(&[], &[], &[], Net::AllowAll), &probes);
    ctx.run("net: blocked", &ctx.policy(&[], &[], &[], Net::Blocked), &probes);
    ctx.run("net: proxy mode -> 127.0.0.1:pa", &ctx.policy(&[], &[], &[], Net::Proxy(format!("http://127.0.0.1:{pa}"))), &probes);
    println!("host control: tcp 1.1.1.1:443 => {:?}", TcpStream::connect_timeout(&"1.1.1.1:443".parse().expect("addr"), Duration::from_secs(3)).map(|_| "OK"));
}

fn bg_pid(c: &mut Child) -> Option<String> {
    let mut buf = [0u8; 128];
    let n = c.stdout.as_mut()?.read(&mut buf).ok()?;
    let line = String::from_utf8_lossy(&buf[..n]).to_string();
    println!("container: {}", line.trim());
    line.split("pid ").nth(1).map(|s| s.trim().to_string())
}

fn cleanup(ctx: &Ctx) {
    let pol = ctx.policy(&[], &[], &[], Net::Blocked);
    let args: Vec<String> = "spawnbg 120 ; sleep 120".split_whitespace().map(str::to_string).collect();
    for mode in ["terminate", "drop"] {
        println!("\n=== cleanup: {mode} with background grandchild");
        match launch(&ctx.api, &pol, ctx.minor, &ctx.probe, &args, &ctx.probe_dir, &ctx.env, Stdio::Piped) {
            Ok(mut c) => {
                let pid = bg_pid(&mut c);
                if let Some(p) = &pid {
                    println!("bg {p} alive before: {}", pid_alive(p));
                }
                if mode == "terminate" {
                    println!("terminate: {:?}", c.terminate().map_err(|e| e.0));
                    println!("wait: {:?}", c.wait_ms(5000).map_err(|e| e.0));
                }
                drop(c);
                std::thread::sleep(Duration::from_millis(500));
                if let Some(p) = &pid {
                    println!("bg {p} alive after: {}", pid_alive(p));
                }
            }
            Err(e) => println!("LAUNCH ERROR: {}", e.0),
        }
    }
    println!("\n=== launch failure: missing program");
    match launch(&ctx.api, &pol, ctx.minor, "C:\\does\\not\\exist.exe", &[], &ctx.probe_dir, &ctx.env, Stdio::Piped) {
        Ok(_) => println!("unexpected success"),
        Err(e) => println!("error (expected): {}", e.0),
    }
}

fn pty_case(ctx: &Ctx, title: &str, program: &str, args: &[&str], win32k: bool, stdio_pty: bool, ctrl_c: bool) {
    println!("\n=== pty matrix: {title} (win32k={win32k}, {})", if stdio_pty { "ConPTY" } else { "pipe" });
    let mut pol = ctx.policy(&[], &[], &[], Net::Blocked);
    pol.allow_win32k = win32k;
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let stdio = if stdio_pty { Stdio::Pty { cols: 80, rows: 25 } } else { Stdio::Piped };
    match launch(&ctx.api, &pol, ctx.minor, program, &args, &ctx.probe_dir, &ctx.env, stdio) {
        Ok(mut c) => {
            let mut out = c.stdout.take().expect("out");
            let reader = std::thread::spawn(move || {
                let mut s = Vec::new();
                let _ = out.read_to_end(&mut s);
                s
            });
            if ctrl_c {
                std::thread::sleep(Duration::from_millis(1000));
                println!("resize: {:?}", c.resize(120, 40).map_err(|e| e.0));
                let mut input = c.pty_in.take().expect("pty in");
                println!("send ^C: {:?}", input.write_all(b"\x03").and_then(|_| input.flush()));
                let t = std::time::Instant::now();
                println!("exit after ^C: {:?} in {} ms (None = still running)", c.wait_ms(5000).map_err(|e| e.0), t.elapsed().as_millis());
                let _ = c.terminate();
            } else {
                println!("exit: {:?}", c.wait_ms(10_000).map(|o| o.map(|v| format!("0x{v:x}"))).map_err(|e| e.0));
            }
            c.close_pty();
            drop(c);
            let raw = reader.join().unwrap_or_default();
            let clean = strip_ansi(&String::from_utf8_lossy(&raw));
            for l in clean.lines().map(str::trim).filter(|l| !l.is_empty()).take(8) {
                println!("  | {l}");
            }
        }
        Err(e) => println!("LAUNCH ERROR: {}", e.0),
    }
}

fn pty(ctx: &Ctx) {
    let cmd = format!(r"{}\System32\cmd.exe", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
    let cmd_args = ["/c", "echo", "PTY_OK", "&", "mode", "con"];
    pty_case(ctx, "cmd.exe", &cmd, &cmd_args, false, false, false);
    pty_case(ctx, "cmd.exe", &cmd, &cmd_args, true, false, false);
    pty_case(ctx, "cmd.exe", &cmd, &cmd_args, false, true, false);
    pty_case(ctx, "cmd.exe", &cmd, &cmd_args, true, true, false);
    pty_case(ctx, "probe env", &ctx.probe, &["env", "TEMP"], false, true, false);
    pty_case(ctx, "probe sleep + ^C", &ctx.probe, &["sleep", "30"], false, true, true);
    pty_case(ctx, "probe sleep + ^C", &ctx.probe, &["sleep", "30"], true, true, true);
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            if it.peek() == Some(&'[') {
                it.next();
                while let Some(&n) = it.peek() {
                    it.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else if it.peek() == Some(&']') {
                while let Some(n) = it.next() {
                    if n == '\u{7}' {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// cmd.exe launching probe.exe inside PSEC: with and without enumerate grants
/// on the probe directory's ancestors, and with the probe dir as read-write.
fn cmd_child(ctx: &Ctx) {
    let cmd = format!(r"{}\System32\cmd.exe", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
    let via = format!("{} env TEMP", ctx.probe);
    let ancestors: Vec<String> = std::path::Path::new(&ctx.probe_dir)
        .ancestors()
        .skip(1)
        .map(|p| p.display().to_string())
        .collect();
    for (title, enumerate, win32k) in [
        ("no enumerate", Vec::new(), true),
        ("enumerate ancestors", ancestors.clone(), true),
    ] {
        println!("\n=== cmd.exe -> probe.exe: {title}");
        let mut pol = ctx.policy(&[], &[], &[], Net::Blocked);
        pol.enumerate = enumerate;
        pol.allow_win32k = win32k;
        let args: Vec<String> = vec!["/c".into(), via.clone()];
        match launch(&ctx.api, &pol, ctx.minor, &cmd, &args, &ctx.probe_dir, &ctx.env, Stdio::Piped) {
            Ok(mut c) => {
                let mut out = String::new();
                if let Some(s) = c.stdout.as_mut() {
                    let _ = s.read_to_string(&mut out);
                }
                println!("exit: {:?}", c.wait_ms(10_000).map_err(|e| e.0));
                print!("{out}");
            }
            Err(e) => println!("LAUNCH ERROR: {}", e.0),
        }
    }
    // Same, but probe launching itself through CreateProcessW for comparison.
    let pol = ctx.policy(&[], &[], &[], Net::Blocked);
    ctx.run("probe.exe -> probe.exe (Rust CreateProcessW)", &pol, "child env TEMP");
}
