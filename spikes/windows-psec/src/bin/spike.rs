//! Spike driver for openspec change `add-windows-processcontainer-backend`.
//!
//! Every request is sent through the exact-version JSON API with
//! `fallback.allowDaclMutation = false`, because the typed v1
//! `ContainerRequest` does not expose that switch and defaults to allowing
//! Tier 3 (AppContainer + host DACL mutation).
//!
//! Usage: `spike <fixture-root> [scenario]`
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

struct Ctx {
    root: PathBuf,
    probe: PathBuf,
    probe_dir: PathBuf,
}

impl Ctx {
    fn p(&self, rel: &str) -> String {
        self.root.join(rel).display().to_string()
    }
}

fn request(ctx: &Ctx, ops: &[String], fs: Value, network: Value, extra: Value) -> String {
    let mut cmd = format!("\"{}\"", ctx.probe.display());
    for o in ops {
        cmd.push(' ');
        cmd.push_str(o);
    }
    let mut fs = fs;
    // The probe binary's directory must be readable to execute it.
    let ro = fs["readonlyPaths"].as_array_mut().expect("readonlyPaths array");
    ro.push(json!(ctx.probe_dir.display().to_string()));
    let mut req = json!({
        "version": "1.0.0",
        "containment": "processcontainer",
        "process": { "commandLine": cmd, "timeout": 60000 },
        "filesystem": fs,
        "fallback": { "allowDaclMutation": false },
        "network": network,
    });
    if let (Some(r), Some(e)) = (req.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            r.insert(k.clone(), v.clone());
        }
    }
    req.to_string()
}

fn ops(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

fn run(title: &str, req: &str) {
    println!("\n=== {title}");
    let t = Instant::now();
    match mxc_sdk::__ffi::run_json(req, false) {
        Ok(r) => {
            println!("outcome: {:?} ({} ms)", r.outcome, t.elapsed().as_millis());
            for w in &r.warnings {
                println!("warning: {w}");
            }
            print!("{}", String::from_utf8_lossy(&r.stdout));
            let err = String::from_utf8_lossy(&r.stderr);
            if !err.trim().is_empty() {
                println!("stderr: {}", err.trim());
            }
        }
        Err(e) => println!("LAUNCH ERROR: {e:?}"),
    }
}

/// Minimal HTTP responder on 127.0.0.1:0 standing in for nono-proxy.
fn listener(tag: &'static str) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = l.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 256];
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.read(&mut buf);
            let _ = s.write_all(format!("HTTP/1.0 200 {tag}\r\n\r\n").as_bytes());
        }
    });
    port
}

fn host_tcp(addr: &str) -> String {
    match TcpStream::connect_timeout(&addr.parse().expect("addr"), Duration::from_secs(3)) {
        Ok(_) => "OK".into(),
        Err(e) => format!("ERR {e}"),
    }
}

fn pid_alive(pid: &str) -> bool {
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(pid))
        .unwrap_or(false)
}

fn icacls(path: &str) -> String {
    Command::new("icacls")
        .arg(path)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

fn setup(root: &Path) {
    let mk = |rel: &str| std::fs::create_dir_all(root.join(rel)).expect("mkdir");
    let wr = |rel: &str| std::fs::write(root.join(rel), b"data").expect("write");
    for d in ["rw/deny", "ro", "un", "files", "proj"] {
        mk(d);
    }
    for f in ["rw/deny/s.txt", "ro/ro.txt", "un/un.txt", "files/a.txt", "files/b.txt"] {
        wr(f);
    }
    // Alternate data streams on a granted and an ungranted file.
    let _ = std::fs::write(root.join("ro/ro.txt:s"), b"ads");
    let _ = std::fs::write(root.join("un/un.txt:s"), b"ads");
    let junc = root.join("rw/junc");
    if !junc.exists() {
        let st = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junc)
            .arg(root.join("un"))
            .output()
            .expect("mklink");
        println!("mklink /J: {}", String::from_utf8_lossy(&st.stdout).trim());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let root = PathBuf::from(args.get(1).expect("usage: spike <fixture-root> [scenario]"));
    let which = args.get(2).cloned().unwrap_or_else(|| "all".into());
    let exe = std::env::current_exe().expect("current_exe");
    let probe_dir = exe.parent().expect("exe dir").to_path_buf();
    let ctx = Ctx {
        probe: probe_dir.join("probe.exe"),
        probe_dir,
        root,
    };
    setup(&ctx.root);
    let all = which == "all";

    if all || which == "fs" {
        fs_scenarios(&ctx);
    }
    if all || which == "fs2" {
        fs2(&ctx);
    }
    if all || which == "net" {
        net_scenarios(&ctx);
    }
    if all || which == "conc" {
        concurrency(&ctx);
    }
    if all || which == "cleanup" {
        cleanup(&ctx);
    }
    if all || which == "pty" {
        pty(&ctx);
    }
    if all || which == "env" {
        env_check(&ctx);
    }
    if which == "orphan" {
        orphan(&ctx);
    }
}

fn deny_all_net() -> Value {
    json!({ "egress": { "default": "deny" } })
}

fn fs_scenarios(ctx: &Ctx) {
    let before = icacls(&ctx.p("rw"));
    let fs = json!({
        "readwritePaths": [ctx.p("rw")],
        "readonlyPaths": [ctx.p("ro"), ctx.p("files/a.txt")],
        "deniedPaths": [ctx.p("rw/deny")],
    });
    let o = ops(&format!(
        "write {rw}\\new.txt ; read {ro}\\ro.txt ; write {ro}\\x.txt ; read {un}\\un.txt ; \
         list {un} ; read {fa} ; read {fb} ; read {rw}\\deny\\s.txt ; write {rw}\\deny\\y.txt ; \
         read {rw}\\junc\\un.txt ; write {rw}\\junc\\z.txt ; read {ro}\\ro.txt:s ; read {un}\\un.txt:s ; \
         read C:\\Windows\\win.ini ; list C:\\Windows\\System32 ; list C:\\Users ; \
         read {home}\\.gitconfig ; list {home} ; \
         child read {un}\\un.txt ; write {ro}\\c1.txt ; child write {un}\\c2.txt ; read {rw}\\deny\\s.txt",
        rw = ctx.p("rw"),
        ro = ctx.p("ro"),
        un = ctx.p("un"),
        fa = ctx.p("files/a.txt"),
        fb = ctx.p("files/b.txt"),
        home = std::env::var("USERPROFILE").unwrap_or_default(),
    ));
    run("1.3/1.4 filesystem grants, denies, junction, ADS, descendants", &request(ctx, &o, fs, deny_all_net(), json!({})));
    let after = icacls(&ctx.p("rw"));
    println!("host DACL on rw unchanged after run: {}", before == after);

    // Short (8.3) name of the ro directory, if the volume generates them.
    let short = Command::new("cmd")
        .args(["/c", "for %I in (\"", &ctx.p("ro"), "\") do @echo %~sI"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    println!("8.3 form of ro: {short}");

    // Volume root grant: does C:\ read cascade to C:\...\un?
    let fs = json!({ "readwritePaths": [], "readonlyPaths": ["C:\\"], "deniedPaths": [] });
    let o = ops(&format!("read {}\\un.txt ; list C:\\", ctx.p("un")));
    run("1.3 volume-root grant", &request(ctx, &o, fs, deny_all_net(), json!({})));

    // Drive-relative and UNC grants: how does the SDK react?
    for (title, path) in [
        ("1.3 drive-relative grant", "C:relative".to_string()),
        ("1.3 UNC grant", "\\\\localhost\\C$\\Windows".to_string()),
    ] {
        let fs = json!({ "readwritePaths": [], "readonlyPaths": [path], "deniedPaths": [] });
        run(title, &request(ctx, &ops("read C:\\Windows\\win.ini"), fs, deny_all_net(), json!({})));
    }
}

/// Junctions and 8.3 names. Expects (created by hand before the run):
/// rw\junc -> un, rw\junc2 -> ro, outjunc -> un; and env SHORT_UN / SHORT_RO
/// holding the 8.3 forms of `un` and `ro`.
fn fs2(ctx: &Ctx) {
    let short_un = std::env::var("SHORT_UN").unwrap_or_default();
    let short_ro = std::env::var("SHORT_RO").unwrap_or_default();
    let fs = json!({ "readwritePaths": [ctx.p("rw")], "readonlyPaths": [], "deniedPaths": [] });
    let o = ops(&format!(
        "read {rw}\\junc\\un.txt ; write {rw}\\junc\\z.txt ; read {rw}\\junc2\\ro.txt ; write {rw}\\junc2\\z.txt",
        rw = ctx.p("rw")
    ));
    run("1.3 junctions inside rw grant: junc->un (ungranted), junc2->ro (ungranted here)", &request(ctx, &o, fs, deny_all_net(), json!({})));

    let fs = json!({ "readwritePaths": [], "readonlyPaths": [ctx.p("ro"), ctx.p("outjunc")], "deniedPaths": [] });
    let o = ops(&format!("read {}\\un.txt ; read {}\\un.txt", ctx.p("outjunc"), ctx.p("un")));
    run("1.3 grant names a junction (outjunc->un): is the target granted?", &request(ctx, &o, fs, deny_all_net(), json!({})));

    let fs = json!({ "readwritePaths": [], "readonlyPaths": [short_un.clone()], "deniedPaths": [] });
    let o = ops(&format!("read {}\\un.txt ; read {short_un}\\un.txt", ctx.p("un")));
    run("1.3 grant via 8.3 name of un; read via long and short", &request(ctx, &o, fs, deny_all_net(), json!({})));

    let fs = json!({ "readwritePaths": [], "readonlyPaths": [ctx.p("ro")], "deniedPaths": [] });
    let o = ops(&format!("read {short_ro}\\ro.txt ; read {}\\RO\\RO.TXT", ctx.p("")));
    run("1.3 grant long name of ro; read via 8.3 and different case", &request(ctx, &o, fs, deny_all_net(), json!({})));

    let fs = json!({ "readwritePaths": [ctx.p("rw")], "readonlyPaths": [], "deniedPaths": [format!("{short_ro}\\..\\rw\\deny")] });
    let o = ops(&format!("read {}\\deny\\s.txt", ctx.p("rw")));
    run("1.3 deny given as non-canonical path (8.3 + ..)", &request(ctx, &o, fs, deny_all_net(), json!({})));
}

fn net_scenarios(ctx: &Ctx) {
    let pa = listener("proxyA");
    let pb = listener("other");
    let empty_fs = || json!({ "readwritePaths": [], "readonlyPaths": [], "deniedPaths": [] });
    let probes = format!(
        "tcp 1.1.1.1:443 ; tcp [2606:4700:4700::1111]:443 ; udpdns 1.1.1.1:53 ; \
         udpdns [2606:4700:4700::1111]:53 ; resolve example.com ; resolve rust-lang.org ; httpget 127.0.0.1:{pa} ; \
         tcp 127.0.0.1:{pb} ; tcp [::1]:{pb} ; child tcp 1.1.1.1:443 ; httpget 127.0.0.1:{pa} ; tcp 127.0.0.1:{pb}"
    );

    run("control: egress default allow", &request(ctx, &ops(&probes), empty_fs(), json!({ "egress": { "default": "allow" } }), json!({})));
    println!("host control during runs: tcp 1.1.1.1:443 => {}", host_tcp("1.1.1.1:443"));

    run("1.5 blocked (egress deny, no ingress section)", &request(ctx, &ops(&probes), empty_fs(), deny_all_net(), json!({})));

    // The SDK's proxy mode demands: egress.default=deny with no rules, and
    // ingress.default=allow (+ hostLoopback=allow on PSEC 1.0).
    let proxy_shape = json!({ "egress": { "default": "deny" }, "ingress": { "default": "allow", "hostLoopback": "allow" } });
    let rc = json!({ "runtimeConfig": { "networkProxy": format!("http://127.0.0.1:{pa}") } });
    run("1.6 proxy-only A: SDK proxy shape + networkProxy=pa", &request(ctx, &ops(&probes), empty_fs(), proxy_shape.clone(), rc.clone()));
    run("1.6 proxy-only B: SDK proxy shape, no networkProxy", &request(ctx, &ops(&probes), empty_fs(), proxy_shape.clone(), json!({})));

    let allow_pa = json!([ { "to": [ { "cidr": "127.0.0.1/32" } ], "ports": [ { "protocol": "tcp", "port": pa } ] } ]);
    let net_c = json!({ "egress": { "default": "deny", "allow": allow_pa.clone() }, "ingress": { "default": "allow", "hostLoopback": "allow" } });
    run("1.6 proxy-only C: egress allow 127.0.0.1:pa + ingress allow + hostLoopback allow", &request(ctx, &ops(&probes), empty_fs(), net_c, json!({})));
    let net_d = json!({ "egress": { "default": "deny", "allow": allow_pa.clone() }, "ingress": { "default": "deny", "hostLoopback": "allow" } });
    run("1.6 proxy-only D: egress allow 127.0.0.1:pa + ingress deny + hostLoopback allow", &request(ctx, &ops(&probes), empty_fs(), net_d, json!({})));
    let net_e = json!({ "egress": { "default": "deny", "allow": allow_pa } });
    run("1.6 E: egress allow 127.0.0.1:pa only (DNS leak check)", &request(ctx, &ops(&probes), empty_fs(), net_e, json!({})));

    // Ingress: can the host reach a listener inside a proxy-mode container?
    let lport = 47123;
    let req = request(ctx, &ops(&format!("listen {lport}")), empty_fs(), proxy_shape, rc);
    println!("\n=== 1.6 ingress: host -> container listener (proxy-only A)");
    match mxc_sdk::__ffi::spawn_container_json(&req, false) {
        Ok(mut p) => {
            let out = p.take_stdout().expect("stdout");
            let mut lines = BufReader::new(out).lines();
            if let Some(Ok(first)) = lines.next() {
                println!("container: {first}");
            }
            println!("host connect to 127.0.0.1:{lport} => {}", host_tcp(&format!("127.0.0.1:{lport}")));
            for l in lines.map_while(Result::ok) {
                println!("container: {l}");
            }
            println!("outcome: {:?}", p.wait());
        }
        Err(e) => println!("LAUNCH ERROR: {e:?}"),
    }
}

fn concurrency(ctx: &Ctx) {
    let pa = listener("A");
    let pb = listener("B");
    let empty_fs = || json!({ "readwritePaths": [], "readonlyPaths": [], "deniedPaths": [] });
    // SDK proxy mode (the only shape that scopes loopback to one endpoint).
    let net = || json!({ "egress": { "default": "deny" }, "ingress": { "default": "allow", "hostLoopback": "allow" } });
    let rc = |p: u16| json!({ "runtimeConfig": { "networkProxy": format!("http://127.0.0.1:{p}") } });
    let a = request(ctx, &ops(&format!("sleep 2 ; httpget 127.0.0.1:{pa} ; tcp 127.0.0.1:{pb}")), empty_fs(), net(), rc(pa));
    let b = request(ctx, &ops(&format!("sleep 2 ; httpget 127.0.0.1:{pb} ; tcp 127.0.0.1:{pa}")), empty_fs(), net(), rc(pb));
    println!("\n=== 1.7 concurrent containers A(pa={pa}) B(pb={pb})");
    let ta = std::thread::spawn(move || mxc_sdk::__ffi::run_json(&a, false));
    let tb = std::thread::spawn(move || mxc_sdk::__ffi::run_json(&b, false));
    std::thread::sleep(Duration::from_secs(1));
    println!("host control while both run: tcp 1.1.1.1:443 => {}", host_tcp("1.1.1.1:443"));
    for (name, t) in [("A", ta), ("B", tb)] {
        match t.join().expect("join") {
            Ok(r) => print!("{name}: {:?}\n{}", r.outcome, String::from_utf8_lossy(&r.stdout)),
            Err(e) => println!("{name}: LAUNCH ERROR {e:?}"),
        }
    }
}

fn first_pid(p: &mut mxc_sdk::v1::MxcProcess) -> Option<String> {
    let out = p.take_stdout()?;
    let mut line = String::new();
    BufReader::new(out).read_line(&mut line).ok()?;
    println!("container: {}", line.trim());
    line.split("pid ").nth(1).map(|s| s.trim().to_string())
}

fn cleanup(ctx: &Ctx) {
    let empty_fs = || json!({ "readwritePaths": [], "readonlyPaths": [], "deniedPaths": [] });
    println!("\n=== 1.8 cleanup: kill() with background grandchild");
    let req = request(ctx, &ops("spawnbg 120 ; sleep 120"), empty_fs(), deny_all_net(), json!({}));
    match mxc_sdk::__ffi::spawn_container_json(&req, false) {
        Ok(mut p) => {
            let pid = first_pid(&mut p);
            if let Some(pid) = &pid {
                println!("bg pid {pid} alive before kill: {}", pid_alive(pid));
            }
            println!("kill: {:?}", p.kill());
            println!("wait: {:?}", p.wait());
            std::thread::sleep(Duration::from_millis(500));
            if let Some(pid) = &pid {
                println!("bg pid {pid} alive after kill: {}", pid_alive(pid));
            }
        }
        Err(e) => println!("LAUNCH ERROR: {e:?}"),
    }

    println!("\n=== 1.8 cleanup: drop without kill");
    match mxc_sdk::__ffi::spawn_container_json(&req, false) {
        Ok(mut p) => {
            let pid = first_pid(&mut p);
            drop(p);
            std::thread::sleep(Duration::from_millis(500));
            if let Some(pid) = &pid {
                println!("bg pid {pid} alive after drop: {}", pid_alive(pid));
            }
        }
        Err(e) => println!("LAUNCH ERROR: {e:?}"),
    }

    println!("\n=== 1.8 cleanup: timeout");
    let mut v: Value = serde_json::from_str(&req).expect("json");
    v["process"]["timeout"] = json!(3000);
    match mxc_sdk::__ffi::spawn_container_json(&v.to_string(), false) {
        Ok(mut p) => {
            let pid = first_pid(&mut p);
            println!("wait: {:?}", p.wait());
            std::thread::sleep(Duration::from_millis(500));
            if let Some(pid) = &pid {
                println!("bg pid {pid} alive after timeout: {}", pid_alive(pid));
            }
        }
        Err(e) => println!("LAUNCH ERROR: {e:?}"),
    }

    println!("\n=== 1.8 cleanup: launch failure (missing program)");
    let mut v: Value = serde_json::from_str(&req).expect("json");
    v["process"]["commandLine"] = json!("C:\\does\\not\\exist.exe");
    match mxc_sdk::__ffi::run_json(&v.to_string(), false) {
        Ok(r) => println!("outcome: {:?} stderr: {}", r.outcome, String::from_utf8_lossy(&r.stderr).trim()),
        Err(e) => println!("LAUNCH ERROR (expected): {e:?}"),
    }

    println!("\n=== 1.8 cleanup: launching process aborts");
    let out = Command::new(std::env::current_exe().expect("exe"))
        .arg(ctx.root.display().to_string())
        .arg("orphan")
        .output()
        .expect("orphan run");
    let text = String::from_utf8_lossy(&out.stdout);
    let pid = text.lines().find_map(|l| l.split("pid ").nth(1)).map(|s| s.trim().to_string());
    std::thread::sleep(Duration::from_secs(1));
    if let Some(pid) = pid {
        println!("bg pid {pid} alive after launcher abort: {}", pid_alive(&pid));
    } else {
        println!("orphan output: {text}");
    }
}

fn orphan(ctx: &Ctx) {
    let empty_fs = json!({ "readwritePaths": [], "readonlyPaths": [], "deniedPaths": [] });
    let req = request(ctx, &ops("spawnbg 120 ; sleep 120"), empty_fs, deny_all_net(), json!({}));
    if let Ok(mut p) = mxc_sdk::__ffi::spawn_container_json(&req, false) {
        let _ = first_pid(&mut p);
        let _ = std::io::stdout().flush();
        std::process::abort();
    }
}

fn pty(ctx: &Ctx) {
    println!("\n=== 1.9 PTY spawn for processcontainer");
    let req = request(
        ctx,
        &ops("read C:\\Windows\\win.ini"),
        json!({ "readwritePaths": [], "readonlyPaths": [], "deniedPaths": [] }),
        deny_all_net(),
        json!({}),
    );
    let size = mxc_sdk::v1::MxcPtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 };
    match mxc_sdk::__ffi::spawn_with_pty_json(&req, false, size) {
        Ok(_) => println!("PTY spawn: OK"),
        Err(e) => println!("PTY spawn: ERROR {e:?}"),
    }
}

/// Does the backend-default environment include the launcher's variables?
fn env_check(ctx: &Ctx) {
    // SAFETY: the spike is single-threaded here; no other thread reads the environment.
    unsafe { std::env::set_var("SPIKE_LAUNCHER_SECRET", "s3cr3t") };
    let fs = json!({ "readwritePaths": [], "readonlyPaths": [], "deniedPaths": [] });
    run("env: default environment vs launcher env", &request(ctx, &ops("env SPIKE_LAUNCHER_SECRET ; env PATH ; env USERPROFILE ; env TEMP"), fs, deny_all_net(), json!({})));
}
