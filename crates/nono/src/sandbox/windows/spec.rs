//! Encoding of a [`WindowsPolicy`] as a PSEC v1 FlatBuffer.
//!
//! The network shapes are the ones validated on a live host (spike §1.6 and
//! §1.11). In particular, proxy-only uses the PSEC proxy form: it is the only
//! form that scopes loopback egress to a single endpoint. A host-loopback
//! allow without a proxy URL opens every loopback port and is never emitted.

use super::policy::{Network, WindowsPolicy};
use super::psec::SCHEMA_MAJOR;
use super::psec_spec::process_security_environment_layout as layout;

/// Identity-less loopback peer used by the PSEC proxy form.
const LOOPBACK_PEER: &str = "MXC-Loopback";

pub(crate) fn build(policy: &WindowsPolicy, minor: u32) -> Vec<u8> {
    let nonempty = |v: &[String]| (!v.is_empty()).then(|| v.to_vec());
    let mut capabilities: Vec<&str> = Vec::new();
    let mut network = layout::NetworkPolicyT::default();
    match policy.network {
        Network::Blocked => {
            network.egress = Some(Box::new(layout::EndpointPolicyT {
                default_action: layout::FilterAction::deny,
                ..Default::default()
            }));
        }
        Network::AllowAll => {
            capabilities.push("internetClient");
            network.egress = Some(Box::new(layout::EndpointPolicyT {
                default_action: layout::FilterAction::allow,
                ..Default::default()
            }));
        }
        Network::Proxy { port } => {
            capabilities.push("privateNetworkClientServer");
            capabilities.push("networkLoopback");
            network.proxy = Some(Box::new(layout::ProxyInfoT {
                url: Some(format!("http://127.0.0.1:{port}")),
            }));
            network.allowed_appcontainer_peer = Some(LOOPBACK_PEER.to_string());
        }
    }
    // Enumerate grants are a 1.1 field; never emit them to a 1.0 host.
    let enumerate = if minor >= 1 {
        nonempty(&policy.enumerate)
    } else {
        None
    };
    let spec = layout::ProcessSecurityEnvironmentT {
        version: layout::SchemaVersionT {
            major: u16::try_from(SCHEMA_MAJOR).unwrap_or(u16::MAX),
            minor: u16::try_from(minor.min(1)).unwrap_or(1),
        },
        capabilities: (!capabilities.is_empty()).then(|| capabilities.join(",")),
        disallow_win32k_system_calls: !policy.allow_win32k,
        // UI limits are applied on the Job Object (documented semantics);
        // this field's meaning is not documented for PSEC.
        ui_restrictions: 0,
        fs_read_write: nonempty(&policy.read_write),
        fs_read_only: nonempty(&policy.read_only),
        fs_deny: nonempty(&policy.deny),
        fs_enumerate: enumerate,
        network_policy: Some(Box::new(network)),
    };
    let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let root = spec.pack(&mut builder);
    layout::finish_process_security_environment_buffer(&mut builder, root);
    builder.finished_data().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(buf: &[u8]) -> layout::ProcessSecurityEnvironmentT {
        match layout::root_as_process_security_environment(buf) {
            Ok(root) => root.unpack(),
            Err(e) => panic!("encoded spec does not verify: {e}"),
        }
    }

    fn base() -> WindowsPolicy {
        WindowsPolicy {
            read_write: vec![r"C:\proj".into()],
            read_only: vec![r"C:\Windows".into()],
            deny: vec![r"C:\proj\.env".into()],
            enumerate: vec![r"C:\".into()],
            network: Network::Blocked,
            allow_win32k: false,
            memory_bytes: None,
        }
    }

    #[test]
    fn round_trips_filesystem_and_blocked_network() {
        let spec = decode(&build(&base(), 1));
        assert_eq!(spec.version.major, 1);
        assert_eq!(spec.version.minor, 1);
        assert_eq!(spec.fs_read_write, Some(vec![r"C:\proj".to_string()]));
        assert_eq!(spec.fs_read_only, Some(vec![r"C:\Windows".to_string()]));
        assert_eq!(spec.fs_deny, Some(vec![r"C:\proj\.env".to_string()]));
        assert_eq!(spec.fs_enumerate, Some(vec![r"C:\".to_string()]));
        assert!(spec.disallow_win32k_system_calls);
        assert_eq!(spec.capabilities, None);
        let net = spec.network_policy.unwrap_or_default();
        assert_eq!(
            net.egress.map(|e| e.default_action),
            Some(layout::FilterAction::deny)
        );
        assert!(net.proxy.is_none());
    }

    #[test]
    fn proxy_form_has_no_egress_table() {
        let mut policy = base();
        policy.network = Network::Proxy { port: 3128 };
        let spec = decode(&build(&policy, 1));
        assert_eq!(
            spec.capabilities.as_deref(),
            Some("privateNetworkClientServer,networkLoopback")
        );
        let net = spec.network_policy.unwrap_or_default();
        assert!(net.egress.is_none());
        assert!(net.ingress.is_none());
        assert_eq!(
            net.proxy.and_then(|p| p.url).as_deref(),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(
            net.allowed_appcontainer_peer.as_deref(),
            Some(LOOPBACK_PEER)
        );
    }

    #[test]
    fn enumerate_omitted_for_minor_zero() {
        let spec = decode(&build(&base(), 0));
        assert_eq!(spec.version.minor, 0);
        assert_eq!(spec.fs_enumerate, None);
    }
}
