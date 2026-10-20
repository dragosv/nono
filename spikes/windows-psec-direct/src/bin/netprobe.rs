//! Review experiment: which network shapes keep proxy-only and allow-all
//! faithful (egress reach, host-loopback reach, inbound from the host's
//! LAN address)?
//!
//! Usage: `netprobe <fixture-root>`. A connection from the host's own LAN
//! address is not traffic from a second machine; it is the closest check one
//! host can make.
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;
use windows_psec_direct::{Api, CustomNet, Net, Policy, Stdio, launch};

fn host_listener(ip: IpAddr) -> u16 {
    let l = TcpListener::bind((ip, 0)).expect("bind");
    let port = l.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let mut buf = [0u8; 256];
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.0 200 OK\r\n\r\n");
        }
    });
    port
}

fn lan_ip() -> IpAddr {
    let s = UdpSocket::bind("0.0.0.0:0").expect("udp");
    s.connect("8.8.8.8:53").expect("route");
    s.local_addr().expect("addr").ip()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("bind").local_addr().expect("addr").port()
}

fn main() {
    let root = PathBuf::from(std::env::args().nth(1).expect("usage: netprobe <fixture-root>"));
    std::fs::create_dir_all(&root).expect("root");
    let api = Api::load().expect("PSEC");
    let minor = api.version_supported(1).ok().flatten().unwrap_or(0) as u16;
    println!("support flags: {:?}", api.support_flags().map(|f| format!("0x{f:x}")).map_err(|e| e.0));
    let exe = std::env::current_exe().expect("exe");
    let probe_dir = exe.parent().expect("dir").display().to_string();
    let probe = format!("{probe_dir}\\probe.exe");
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let env: Vec<(String, String)> = vec![
        ("SystemRoot".into(), sysroot.clone()),
        ("PATH".into(), format!("{sysroot}\\System32")),
        ("LOCALAPPDATA".into(), std::env::var("LOCALAPPDATA").unwrap_or_default()),
    ];

    let lan = lan_ip();
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
    let proxy_port = host_listener(loopback);
    let other_port = host_listener(loopback);
    let lan_port = host_listener(lan);
    println!("lan ip {lan}; proxy 127.0.0.1:{proxy_port}; other 127.0.0.1:{other_port}; lan {lan}:{lan_port}");

    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let proxy_url = Some(format!("http://127.0.0.1:{proxy_port}"));
    let peer = Some("MXC-Loopback".to_string());
    let variants: Vec<(&str, CustomNet)> = vec![
        ("P0 proxy as shipped (pncs+loopback, no ingress table)", CustomNet {
            capabilities: s(&["privateNetworkClientServer", "networkLoopback"]),
            proxy: proxy_url.clone(), peer: peer.clone(), ..Default::default()
        }),
        ("P1 proxy + ingress deny/deny", CustomNet {
            capabilities: s(&["privateNetworkClientServer", "networkLoopback"]),
            ingress: Some((false, false)),
            proxy: proxy_url.clone(), peer: peer.clone(), ..Default::default()
        }),
        ("P2 proxy without pncs (networkLoopback only)", CustomNet {
            capabilities: s(&["networkLoopback"]),
            proxy: proxy_url.clone(), peer: peer.clone(), ..Default::default()
        }),
        ("P3 proxy without pncs + ingress deny/deny", CustomNet {
            capabilities: s(&["networkLoopback"]),
            ingress: Some((false, false)),
            proxy: proxy_url.clone(), peer: peer.clone(), ..Default::default()
        }),
        ("A0 allow-all as shipped (internetClient, egress allow)", CustomNet {
            capabilities: s(&["internetClient"]), egress_allow: Some(true), ..Default::default()
        }),
        ("A1 allow-all + pncs + ingress allow/deny", CustomNet {
            capabilities: s(&["internetClient", "privateNetworkClientServer"]),
            egress_allow: Some(true), ingress: Some((true, false)), ..Default::default()
        }),
        ("A2 allow-all + pncs + networkLoopback + ingress allow/allow", CustomNet {
            capabilities: s(&["internetClient", "privateNetworkClientServer", "networkLoopback"]),
            egress_allow: Some(true), ingress: Some((true, true)), ..Default::default()
        }),
    ];

    for (title, net) in variants {
        println!("\n=== {title}");
        let policy = Policy {
            read_only: vec![probe_dir.clone()],
            net: Net::Custom(net),
            ..Default::default()
        };
        let ops = format!(
            "tcp 127.0.0.1:{proxy_port} tcp 127.0.0.1:{other_port} tcp {lan}:{lan_port} tcp 1.1.1.1:443"
        );
        let args: Vec<String> = ops.split_whitespace().map(str::to_string).collect();
        match launch(&api, &policy, minor, &probe, &args, &probe_dir, &env, Stdio::Piped) {
            Ok(mut c) => {
                let mut out = String::new();
                if let Some(o) = c.stdout.as_mut() {
                    let _ = o.read_to_string(&mut out);
                }
                let _ = c.wait_ms(30_000);
                for line in out.lines() {
                    println!("  egress  {line}");
                }
            }
            Err(e) => {
                println!("  LAUNCH ERROR: {}", e.0);
                continue;
            }
        }

        let port = free_port();
        let args = vec!["listenall".to_string(), port.to_string()];
        match launch(&api, &policy, minor, &probe, &args, &probe_dir, &env, Stdio::Piped) {
            Ok(mut c) => {
                std::thread::sleep(Duration::from_millis(1500));
                for ip in [loopback, lan] {
                    let r = TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(2));
                    println!("  ingress host -> {ip}:{port}: {}", if r.is_ok() { "CONNECTED" } else { "refused/timeout" });
                }
                let _ = c.terminate();
                let mut out = String::new();
                if let Some(o) = c.stdout.as_mut() {
                    let _ = o.read_to_string(&mut out);
                }
                for line in out.lines() {
                    println!("  inside  {line}");
                }
            }
            Err(e) => println!("  LAUNCH ERROR (listener): {}", e.0),
        }
    }
}
