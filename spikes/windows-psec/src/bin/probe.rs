//! Workload helper run *inside* the container by `spike`.
//!
//! Usage: `probe <op> [arg] [; <op> [arg] ...]`
//! Each op prints one line: `<op> <arg> => OK <detail>` or `=> ERR <detail>`.
//!
//! Ops:
//!   read <path>          read a file
//!   write <path>         create/overwrite a file
//!   list <dir>           enumerate a directory
//!   tcp <addr:port>      TCP connect (3 s timeout)
//!   httpget <addr:port>  TCP connect + send "GET / HTTP/1.0" and read a reply
//!   udpdns <addr:port>   send a DNS query over UDP and wait for a reply
//!   resolve <host>       system resolver lookup
//!   child <ops...>       run the remaining ops in a child probe (repeatable)
//!   sleep <secs>         sleep (cleanup tests)
//!   spawnbg <secs>       start a detached child probe that sleeps, print its pid
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::time::Duration;

fn op(name: &str, arg: &str) -> Result<String, String> {
    match name {
        "read" => std::fs::read(arg)
            .map(|b| format!("{} bytes", b.len()))
            .map_err(|e| e.to_string()),
        "write" => std::fs::write(arg, b"spike")
            .map(|_| "written".into())
            .map_err(|e| e.to_string()),
        "list" => std::fs::read_dir(arg)
            .map(|d| format!("{} entries", d.count()))
            .map_err(|e| e.to_string()),
        "tcp" => {
            let addr: SocketAddr = arg.parse().map_err(|e| format!("{e}"))?;
            TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                .map(|_| "connected".into())
                .map_err(|e| e.to_string())
        }
        "httpget" => {
            let addr: SocketAddr = arg.parse().map_err(|e| format!("{e}"))?;
            let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| e.to_string())?;
            s.set_read_timeout(Some(Duration::from_secs(3))).ok();
            s.write_all(b"GET / HTTP/1.0\r\n\r\n")
                .map_err(|e| e.to_string())?;
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).map_err(|e| e.to_string())?;
            Ok(String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string())
        }
        "udpdns" => {
            let addr: SocketAddr = arg.parse().map_err(|e| format!("{e}"))?;
            let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
            let s = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
            s.set_read_timeout(Some(Duration::from_secs(3))).ok();
            // Minimal DNS query for example.com A.
            let q: [u8; 29] = [
                0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
                b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
            ];
            s.send_to(&q, addr).map_err(|e| format!("send: {e}"))?;
            let mut buf = [0u8; 512];
            s.recv_from(&mut buf)
                .map(|(n, _)| format!("reply {n} bytes"))
                .map_err(|e| format!("recv: {e}"))
        }
        "resolve" => (arg, 443)
            .to_socket_addrs()
            .map(|a| format!("{} addrs", a.count()))
            .map_err(|e| e.to_string()),
        "listen" => {
            // listen <port>: accept one connection within 8 s on 127.0.0.1.
            let l = std::net::TcpListener::bind(("127.0.0.1", arg.parse::<u16>().map_err(|e| format!("{e}"))?))
                .map_err(|e| format!("bind: {e}"))?;
            println!("listening {arg}");
            l.set_nonblocking(true).ok();
            for _ in 0..80 {
                if let Ok((_, peer)) = l.accept() {
                    return Ok(format!("accepted from {peer}"));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err("no connection".into())
        }
        "env" => std::env::var(arg).map(|v| format!("set ({} chars)", v.len())).map_err(|e| e.to_string()),
        "sleep" => {
            let secs: u64 = arg.parse().map_err(|e| format!("{e}"))?;
            std::thread::sleep(Duration::from_secs(secs));
            Ok("slept".into())
        }
        "spawnbg" => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let child = Command::new(exe)
                .args(["sleep", arg])
                .spawn()
                .map_err(|e| e.to_string())?;
            Ok(format!("pid {}", child.id()))
        }
        other => Err(format!("unknown op {other}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run(&args, 0);
}

fn run(args: &[String], depth: usize) {
    let mut i = 0;
    while i < args.len() {
        let name = args[i].as_str();
        if name == ";" {
            i += 1;
            continue;
        }
        if name == "child" {
            let rest = &args[i + 1..];
            let exe = match std::env::current_exe() {
                Ok(e) => e,
                Err(e) => {
                    println!("{}child => ERR current_exe: {e}", "  ".repeat(depth));
                    return;
                }
            };
            match Command::new(exe).args(rest).output() {
                Ok(out) => {
                    for line in String::from_utf8_lossy(&out.stdout).lines() {
                        println!("{}[child] {line}", "  ".repeat(depth));
                    }
                }
                Err(e) => println!("{}child => ERR spawn: {e}", "  ".repeat(depth)),
            }
            return;
        }
        let arg = args.get(i + 1).map(String::as_str).unwrap_or("");
        match op(name, arg) {
            Ok(d) => println!("{name} {arg} => OK {d}"),
            Err(d) => println!("{name} {arg} => ERR {d}"),
        }
        i += 2;
    }
}
