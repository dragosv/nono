//! Mapping from [`CapabilitySet`] and [`LaunchOptions`] to a PSEC policy.
//!
//! Every capability field is either enforced faithfully or rejected with an
//! error naming it. Nothing is dropped silently and no grant is widened.

use std::fmt;
use std::path::{Component, Path, PathBuf, Prefix};

use crate::capability::{
    AccessMode, CapabilitySet, IpcMode, NetworkMode, ProcessInfoMode, SignalMode,
};
use crate::error::{NonoError, Result};

use super::launch::LaunchOptions;
use super::psec::{SUPPORT_FS_DENY, SUPPORT_FS_ENUMERATE};

/// Network policy expressible on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Network {
    Blocked,
    AllowAll,
    /// Only `http://127.0.0.1:<port>` is reachable (PSEC proxy form).
    Proxy {
        port: u16,
    },
}

/// A validated policy, ready to encode. Paths are in `X:\...` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsPolicy {
    pub(crate) read_write: Vec<String>,
    pub(crate) read_only: Vec<String>,
    pub(crate) deny: Vec<String>,
    pub(crate) enumerate: Vec<String>,
    pub(crate) network: Network,
    pub(crate) allow_win32k: bool,
    /// Job-wide committed-memory cap. Enforced by the Job Object, not PSEC.
    pub(crate) memory_bytes: Option<u64>,
}

impl WindowsPolicy {
    /// The most restrictive policy: no grants, no network, no win32k.
    pub(crate) fn probe() -> Self {
        Self {
            read_write: Vec::new(),
            read_only: Vec::new(),
            deny: Vec::new(),
            enumerate: Vec::new(),
            network: Network::Blocked,
            allow_win32k: false,
            memory_bytes: None,
        }
    }

    /// Build the policy for a launch.
    ///
    /// `host` is `(schema_minor, feature_flags)` from the live PSEC binding.
    /// When it is `None` (rendering without a host), optional features are
    /// assumed present and are re-checked at launch.
    pub(crate) fn from_launch(
        caps: &CapabilitySet,
        opts: &LaunchOptions,
        host: Option<(u32, u64)>,
    ) -> Result<Self> {
        reject_inexpressible(caps)?;

        let mut read_write = Vec::new();
        let mut read_only = Vec::new();
        for cap in caps.fs_capabilities() {
            let path = policy_path(&cap.resolved, PathUse::Grant)?;
            match cap.access {
                AccessMode::Read => push_unique(&mut read_only, path),
                AccessMode::ReadWrite => push_unique(&mut read_write, path),
                AccessMode::Write => {
                    return Err(unsupported(format!(
                        "write-only access to {} cannot be expressed: PSEC has no write-only grant, and nono does not widen it to read-write",
                        cap.original.display()
                    )));
                }
            }
        }

        let mut deny = Vec::new();
        for path in opts.deny_paths() {
            push_unique(&mut deny, policy_path(&canonical(path)?, PathUse::Deny)?);
        }
        if !deny.is_empty()
            && let Some((_, flags)) = host
            && flags & SUPPORT_FS_DENY == 0
        {
            return Err(unsupported(
                "deny paths are requested but this Windows host does not enforce PSEC deny paths"
                    .to_string(),
            ));
        }

        let mut enumerate = Vec::new();
        for path in opts.enumerate_paths() {
            push_unique(
                &mut enumerate,
                policy_path(&canonical(path)?, PathUse::Enumerate)?,
            );
        }
        if !enumerate.is_empty()
            && let Some((minor, flags)) = host
            && (minor < 1 || flags & SUPPORT_FS_ENUMERATE == 0)
        {
            return Err(unsupported(
                "enumerate-only paths are requested but this Windows host does not support PSEC 1.1 enumeration"
                    .to_string(),
            ));
        }

        let network = match caps.network_mode() {
            NetworkMode::Blocked => Network::Blocked,
            NetworkMode::AllowAll => {
                if !caps.dns_enabled() {
                    return Err(unsupported(
                        "DNS blocking with unrestricted network cannot be enforced on Windows"
                            .to_string(),
                    ));
                }
                Network::AllowAll
            }
            NetworkMode::ProxyOnly { port, bind_ports } => {
                if !bind_ports.is_empty() {
                    return Err(unsupported(
                        "proxy-only bind ports cannot be expressed on Windows".to_string(),
                    ));
                }
                if !caps.dns_enabled() {
                    return Err(unsupported(
                        "DNS blocking cannot be enforced in proxy-only mode on Windows: the system resolver stays reachable"
                            .to_string(),
                    ));
                }
                if *port == 0 {
                    return Err(unsupported("proxy port 0 is not valid".to_string()));
                }
                // PSEC's proxy form needs privateNetworkClientServer, a
                // bidirectional capability, and refuses an ingress table
                // next to it (E_INVALIDARG on build 26300). Inbound traffic
                // from private networks therefore cannot be ruled out.
                if !opts.private_inbound_allowed() {
                    return Err(unsupported(
                        "proxy-only networking on Windows also admits inbound connections from private networks (privateNetworkClientServer is bidirectional and cannot be narrowed); the caller must accept this explicitly"
                            .to_string(),
                    ));
                }
                Network::Proxy { port: *port }
            }
        };

        Ok(Self {
            read_write,
            read_only,
            deny,
            enumerate,
            network,
            allow_win32k: opts.win32k_allowed(),
            memory_bytes: caps.resource_limits().and_then(|l| l.memory_bytes),
        })
    }

    pub(crate) fn render(&self, schema_minor: Option<u32>) -> RenderedPolicy {
        let paths = |v: &[String]| v.iter().map(PathBuf::from).collect();
        RenderedPolicy {
            schema_major: super::psec::SCHEMA_MAJOR,
            schema_minor,
            read_write: paths(&self.read_write),
            read_only: paths(&self.read_only),
            deny: paths(&self.deny),
            enumerate: paths(&self.enumerate),
            network: match self.network {
                Network::Blocked => RenderedNetwork::Blocked,
                Network::AllowAll => RenderedNetwork::AllowAll,
                Network::Proxy { port } => RenderedNetwork::ProxyOnly { port },
            },
            win32k_allowed: self.allow_win32k,
            memory_bytes: self.memory_bytes,
            implicit: IMPLICIT_ACCESS.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

/// Access every PSEC workload has without a grant (spike §1.2: reading
/// `C:\Windows\win.ini` and listing `System32` succeed; listing `C:\Users`
/// does not). Exact coverage depends on the host's ACLs.
const IMPLICIT_ACCESS: [&str; 3] = [
    "read: files and directories whose ACL grants ALL APPLICATION PACKAGES (by default most of %SystemRoot% and %ProgramFiles%; host-dependent)",
    "read: registry keys readable by ALL APPLICATION PACKAGES",
    "read-write: the container's own TEMP folder (per run, removed when the run ends)",
];

fn unsupported(reason: String) -> NonoError {
    NonoError::SandboxInit(reason)
}

fn reject_inexpressible(caps: &CapabilitySet) -> Result<()> {
    let mut rejected = Vec::new();
    if !caps.unix_socket_capabilities().is_empty() {
        rejected.push("unix socket grants");
    }
    if caps.signal_mode() != SignalMode::default() {
        rejected.push("signal_mode");
    }
    if caps.process_info_mode() != ProcessInfoMode::default() {
        rejected.push("process_info_mode");
    }
    if caps.ipc_mode() != IpcMode::default() {
        rejected.push("ipc_mode");
    }
    if !caps.platform_rules().is_empty() {
        rejected.push("platform_rules");
    }
    if caps.extensions_enabled() {
        rejected.push("extensions_enabled");
    }
    if !caps.tcp_connect_ports().is_empty() {
        rejected.push("tcp_connect_ports");
    }
    if !caps.tcp_bind_ports().is_empty() {
        rejected.push("tcp_bind_ports");
    }
    if !caps.localhost_ports().is_empty() {
        rejected.push("localhost_ports");
    }
    if !caps.localhost_port_ranges().is_empty() {
        rejected.push("localhost_port_ranges");
    }
    if caps
        .resource_limits()
        .is_some_and(|l| l.max_processes.is_some())
    {
        // A Job Object counts processes only; the limit also covers threads.
        rejected.push("resource_limits.max_processes (Windows cannot limit threads)");
    }
    if rejected.is_empty() {
        Ok(())
    } else {
        Err(unsupported(format!(
            "capabilities not enforceable on Windows: {}",
            rejected.join(", ")
        )))
    }
}

fn push_unique(list: &mut Vec<String>, path: String) {
    if !list.iter().any(|p| p.eq_ignore_ascii_case(&path)) {
        list.push(path);
    }
}

fn canonical(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .map_err(|e| NonoError::PathCanonicalization {
            path: path.to_path_buf(),
            source: e,
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathUse {
    Grant,
    Deny,
    Enumerate,
}

/// Validate a canonical path and convert it to the `X:\...` form PSEC takes.
///
/// `std::fs::canonicalize` on Windows returns the `GetFinalPathNameByHandleW`
/// form (`\\?\X:\...`), with reparse points, 8.3 names and case resolved.
/// Accepted: a verbatim or plain drive-letter path. Rejected: UNC and device
/// paths, drive-relative paths, alternate data streams, and volume roots for
/// grants and denies (a volume-root grant cascades on some builds and is too
/// broad to emit).
pub(crate) fn policy_path(path: &Path, usage: PathUse) -> Result<String> {
    let reject = |why: &str| {
        Err(unsupported(format!(
            "path {} cannot be used in a Windows policy: {why}",
            path.display()
        )))
    };
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::VerbatimDisk(d) | Prefix::Disk(d) => d,
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) => {
                return reject("network (UNC) paths are not supported");
            }
            Prefix::DeviceNS(_) | Prefix::Verbatim(_) => {
                return reject("device paths are not supported");
            }
        },
        _ => return reject("not an absolute drive path"),
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return reject("drive-relative paths are not supported");
    }
    let mut out = format!("{}:\\", char::from(drive).to_ascii_uppercase());
    let mut depth = 0usize;
    for component in components {
        match component {
            Component::Normal(name) => {
                let Some(name) = name.to_str() else {
                    return reject("path is not valid Unicode");
                };
                if name.contains(':') {
                    return reject("alternate data streams are not supported");
                }
                if let Some(why) = win32_name_problem(name) {
                    return reject(why);
                }
                if depth > 0 {
                    out.push('\\');
                }
                out.push_str(name);
                depth = depth.saturating_add(1);
            }
            Component::CurDir | Component::ParentDir => {
                return reject("path is not canonical");
            }
            Component::Prefix(_) | Component::RootDir => return reject("malformed path"),
        }
    }
    if depth == 0 && usage != PathUse::Enumerate {
        return reject("volume roots cannot be granted or denied");
    }
    Ok(out)
}

/// Why a path component would name a different object once the `\\?\`
/// prefix is removed, or `None` if it is safe.
///
/// PSEC and Win32 normalise plain paths: trailing dots and spaces are
/// dropped and DOS device names refer to devices. A verbatim path can name a
/// directory `safe.` that is distinct from `safe`; stripping the prefix
/// would silently retarget a grant, a deny or the working directory.
pub(crate) fn win32_name_problem(name: &str) -> Option<&'static str> {
    if name.ends_with('.') || name.ends_with(' ') {
        return Some("a name ending in a dot or space is rewritten by Windows");
    }
    if name
        .chars()
        .any(|c| c < ' ' || matches!(c, '<' | '>' | '"' | '|' | '?' | '*' | '/'))
    {
        return Some("the name contains characters Windows treats specially");
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    let device = |prefix: &str| {
        stem.chars().count() == prefix.len() + 1
            && stem.is_char_boundary(prefix.len())
            && stem[..prefix.len()].eq_ignore_ascii_case(prefix)
            && stem[prefix.len()..]
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '¹' | '²' | '³'))
    };
    let reserved = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|d| stem.eq_ignore_ascii_case(d))
        || device("COM")
        || device("LPT");
    if reserved {
        return Some("the name is a DOS device name");
    }
    None
}

/// The policy a launch will apply, in display form.
///
/// Returned by `Sandbox::render_launch_policy` so callers can show users what
/// is enforced before anything runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPolicy {
    /// PSEC schema major version.
    pub schema_major: u32,
    /// PSEC schema minor version, when rendered against a live host.
    pub schema_minor: Option<u32>,
    /// Read-write grants (files or recursive directories).
    pub read_write: Vec<PathBuf>,
    /// Read-only grants (files or recursive directories).
    pub read_only: Vec<PathBuf>,
    /// Denied paths, enforced inside granted trees.
    pub deny: Vec<PathBuf>,
    /// Paths that may be listed and queried but not read.
    pub enumerate: Vec<PathBuf>,
    /// Network policy.
    pub network: RenderedNetwork,
    /// Whether win32k (user32/gdi32) system calls are permitted. When they
    /// are, the job still denies clipboard, global atoms, other processes'
    /// windows and desktop or system settings.
    pub win32k_allowed: bool,
    /// Committed-memory cap for the whole process tree, in bytes. Allocations
    /// beyond it fail; the tree is not killed.
    pub memory_bytes: Option<u64>,
    /// Access Windows gives every PSEC workload without a grant.
    pub implicit: Vec<String>,
}

/// Network policy in display form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderedNetwork {
    /// All network access is refused, including system resolver lookups.
    Blocked,
    /// Outbound internet access. Host loopback and private networks stay
    /// blocked: opening them needs bidirectional capabilities that would
    /// also admit inbound connections.
    AllowAll,
    /// Only the local proxy is reachable. System resolver lookups remain
    /// available, and Windows admits inbound connections from private
    /// networks (the proxy form requires `privateNetworkClientServer`).
    ProxyOnly {
        /// Proxy port on 127.0.0.1.
        port: u16,
    },
}

impl fmt::Display for RenderedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.schema_minor {
            Some(minor) => writeln!(f, "mechanism: Windows PSEC {}.{minor}", self.schema_major)?,
            None => writeln!(f, "mechanism: Windows PSEC {}.x", self.schema_major)?,
        }
        let mut list = |label: &str, paths: &[PathBuf]| -> fmt::Result {
            for p in paths {
                writeln!(f, "{label:<10} {}", p.display())?;
            }
            Ok(())
        };
        list("read-write", &self.read_write)?;
        list("read", &self.read_only)?;
        list("deny", &self.deny)?;
        list("enumerate", &self.enumerate)?;
        if self.enumerate.iter().any(|p| p.parent().is_none()) {
            writeln!(
                f,
                "           (enumerate on a volume root exposes every file name on that volume; contents stay unreadable)"
            )?;
        }
        match self.network {
            RenderedNetwork::Blocked => {
                writeln!(f, "network:   blocked (system resolver blocked)")?
            }
            RenderedNetwork::AllowAll => writeln!(
                f,
                "network:   internet only (host loopback and private networks blocked)"
            )?,
            RenderedNetwork::ProxyOnly { port } => writeln!(
                f,
                "network:   proxy-only via http://127.0.0.1:{port} (system resolver reachable; inbound from private networks admitted)"
            )?,
        }
        for line in &self.implicit {
            writeln!(f, "implicit:  {line}")?;
        }
        if let Some(bytes) = self.memory_bytes {
            writeln!(
                f,
                "memory:    {bytes} bytes committed (allocations beyond it fail)"
            )?;
        }
        write!(
            f,
            "win32k:    {}",
            if self.win32k_allowed {
                "allowed (no clipboard, global atoms, foreign windows or desktop settings)"
            } else {
                "blocked"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_path_accepts_verbatim_and_plain_drive_paths() {
        assert_eq!(
            policy_path(Path::new(r"\\?\c:\Users\me\proj"), PathUse::Grant).ok(),
            Some(r"C:\Users\me\proj".to_string())
        );
        assert_eq!(
            policy_path(Path::new(r"D:\data"), PathUse::Grant).ok(),
            Some(r"D:\data".to_string())
        );
    }

    #[test]
    fn policy_path_rejects_unsafe_forms() {
        for bad in [
            r"\\server\share\x",
            r"\\?\UNC\server\share\x",
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\X",
            r"C:relative",
            r"C:\proj\file.txt:stream",
            r"C:\proj\..\other",
            r"relative\path",
        ] {
            assert!(
                policy_path(Path::new(bad), PathUse::Grant).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn names_windows_would_rewrite_are_rejected() {
        // Observed on build 26300: a grant on \\?\...\safe. emitted as
        // ...\safe. also opened the sibling ...\safe.
        for bad in [
            r"\\?\C:\proj\safe.",
            r"\\?\C:\proj\safe ",
            r"\\?\C:\proj\safe. .",
            r"\\?\C:\proj\NUL",
            r"\\?\C:\proj\nul.txt",
            r"\\?\C:\proj\COM1",
            r"\\?\C:\proj\lpt9.log",
            r"\\?\C:\proj\COM¹",
            r"\\?\C:\proj\CONOUT$",
            r"\\?\C:\proj\a*b",
            r"\\?\C:\proj\a?b",
        ] {
            for usage in [PathUse::Grant, PathUse::Deny, PathUse::Enumerate] {
                assert!(
                    policy_path(Path::new(bad), usage).is_err(),
                    "{bad} must be rejected for {usage:?}"
                );
            }
        }
        for good in [
            r"\\?\C:\proj\.git",
            r"\\?\C:\proj\v1.2",
            r"\\?\C:\proj\console",
            r"\\?\C:\proj\COM10",
            r"\\?\C:\proj\nullable",
        ] {
            assert!(
                policy_path(Path::new(good), PathUse::Grant).is_ok(),
                "{good} must be accepted"
            );
        }
    }

    #[test]
    fn volume_root_only_allowed_for_enumerate() {
        assert!(policy_path(Path::new(r"\\?\C:\"), PathUse::Grant).is_err());
        assert!(policy_path(Path::new(r"\\?\C:\"), PathUse::Deny).is_err());
        assert_eq!(
            policy_path(Path::new(r"\\?\C:\"), PathUse::Enumerate).ok(),
            Some(r"C:\".to_string())
        );
    }

    #[test]
    fn write_only_grant_is_rejected_not_widened() -> Result<()> {
        let dir = tempfile::tempdir().map_err(NonoError::Io)?;
        let caps = CapabilitySet::new().allow_path(dir.path(), AccessMode::Write)?;
        let opts = LaunchOptions::new(r"C:\Windows\System32\whoami.exe", dir.path());
        assert!(WindowsPolicy::from_launch(&caps, &opts, None).is_err());
        Ok(())
    }

    #[test]
    fn inexpressible_fields_are_named() -> Result<()> {
        let caps = CapabilitySet::new()
            .block_network()
            .allow_localhost_port(8080);
        let opts = LaunchOptions::new(r"C:\Windows\System32\whoami.exe", r"C:\");
        let err = WindowsPolicy::from_launch(&caps, &opts, None)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("localhost_ports"), "{err}");
        Ok(())
    }

    #[test]
    fn process_limit_is_refused_not_weakened() -> Result<()> {
        let opts = LaunchOptions::new(r"C:\Windows\System32\whoami.exe", r"C:\");
        let limited = |limits| {
            let caps = CapabilitySet::new()
                .block_network()
                .with_resource_limits(limits);
            WindowsPolicy::from_launch(&caps, &opts, None)
        };
        let err = limited(crate::ResourceLimits {
            memory_bytes: None,
            max_processes: Some(64),
        })
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
        assert!(err.contains("max_processes"), "{err}");

        let policy = limited(crate::ResourceLimits {
            memory_bytes: Some(1 << 30),
            max_processes: None,
        })?;
        assert_eq!(policy.memory_bytes, Some(1 << 30));
        Ok(())
    }

    #[test]
    fn dns_block_refused_in_proxy_mode() {
        let caps = CapabilitySet::new().proxy_only(3128).block_dns();
        let opts = LaunchOptions::new(r"C:\Windows\System32\whoami.exe", r"C:\");
        assert!(WindowsPolicy::from_launch(&caps, &opts, None).is_err());
    }

    #[test]
    fn dns_block_accepted_when_network_blocked() -> Result<()> {
        let caps = CapabilitySet::new().block_network().block_dns();
        let opts = LaunchOptions::new(r"C:\Windows\System32\whoami.exe", r"C:\");
        let policy = WindowsPolicy::from_launch(&caps, &opts, None)?;
        assert_eq!(policy.network, Network::Blocked);
        Ok(())
    }

    #[test]
    fn proxy_only_requires_accepting_private_inbound() -> Result<()> {
        let caps = CapabilitySet::new().proxy_only(3128);
        let opts = LaunchOptions::new(r"C:\Windows\System32\whoami.exe", r"C:\");
        let err = WindowsPolicy::from_launch(&caps, &opts, None)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("private networks"), "{err}");

        let opts = opts.allow_private_network_inbound(true);
        let policy = WindowsPolicy::from_launch(&caps, &opts, None)?;
        assert_eq!(policy.network, Network::Proxy { port: 3128 });
        let shown = policy.render(None).to_string();
        assert!(
            shown.contains("inbound from private networks admitted"),
            "{shown}"
        );
        Ok(())
    }

    #[test]
    fn rendering_is_honest_about_allow_all_and_implicit_access() -> Result<()> {
        let opts = LaunchOptions::new(r"C:\Windows\System32\whoami.exe", r"C:\");
        let shown = WindowsPolicy::from_launch(&CapabilitySet::new(), &opts, None)?
            .render(None)
            .to_string();
        assert!(
            shown.contains("internet only (host loopback and private networks blocked)"),
            "{shown}"
        );
        assert!(
            shown.contains(
                "implicit:  read: files and directories whose ACL grants ALL APPLICATION PACKAGES"
            ),
            "{shown}"
        );
        Ok(())
    }

    #[test]
    fn proxy_bind_ports_rejected() {
        let caps = CapabilitySet::new().proxy_only_with_bind(3128, vec![9000]);
        let opts = LaunchOptions::new(r"C:\Windows\System32\whoami.exe", r"C:\");
        assert!(WindowsPolicy::from_launch(&caps, &opts, None).is_err());
    }

    #[test]
    fn deny_requires_host_support() -> Result<()> {
        let dir = tempfile::tempdir().map_err(NonoError::Io)?;
        let caps = CapabilitySet::new().allow_path(dir.path(), AccessMode::ReadWrite)?;
        let opts =
            LaunchOptions::new(r"C:\Windows\System32\whoami.exe", dir.path()).deny_path(dir.path());
        assert!(WindowsPolicy::from_launch(&caps, &opts, Some((1, 0))).is_err());
        assert!(WindowsPolicy::from_launch(&caps, &opts, Some((1, SUPPORT_FS_DENY))).is_ok());
        Ok(())
    }
}
