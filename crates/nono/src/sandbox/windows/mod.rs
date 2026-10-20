//! Windows backend: Windows ProcessContainer through a process security
//! environment (PSEC).
//!
//! Windows has no self-restriction primitive comparable to Landlock or
//! Seatbelt, so this backend does not implement `apply_auto`. The caller
//! launches the workload already confined with [`Sandbox::launch`] and owns
//! its lifetime through [`SandboxedChild`].
//!
//! PSEC is called directly: `processmodel.dll` exports resolved from System32
//! and a PSEC FlatBuffer encoded with vendored bindings (see
//! `psec_spec/NOTICE.md`). There is no AppContainer or DACL fallback; a host
//! without PSEC gets an error.
//!
//! [`Sandbox::launch`]: crate::Sandbox::launch

#[allow(
    dead_code,
    unused_imports,
    non_snake_case,
    non_camel_case_types,
    clippy::all,
    clippy::unwrap_used,
    mismatched_lifetime_syntaxes,
    unsafe_op_in_unsafe_fn
)]
mod psec_spec;

mod launch;
mod pin;
mod policy;
mod psec;
mod spec;

pub use launch::{LaunchOptions, LaunchStdio, SandboxedChild};
pub use policy::{RenderedNetwork, RenderedPolicy};
pub use psec::WindowsSupport;

use crate::capability::CapabilitySet;
use crate::error::Result;

use super::SupportInfo;

pub(crate) fn launch(caps: &CapabilitySet, opts: &LaunchOptions) -> Result<SandboxedChild> {
    launch::launch(caps, opts)
}

pub(crate) fn render(caps: &CapabilitySet, opts: &LaunchOptions) -> Result<RenderedPolicy> {
    launch::render(caps, opts)
}

pub(crate) fn is_supported() -> bool {
    WindowsSupport::probe().psec_available
}

pub(crate) fn support_info() -> SupportInfo {
    let support = WindowsSupport::probe();
    let details = match (&support.unavailable_reason, support.schema_minor) {
        (Some(reason), _) => reason.clone(),
        (None, minor) => {
            let yes_no = |b: bool| if b { "yes" } else { "no" };
            format!(
                "Windows ProcessContainer (PSEC) {}.{}; deny paths: {}; enumerate-only: {}; inbound policy: {}",
                psec::SCHEMA_MAJOR,
                minor.unwrap_or(0),
                yes_no(support.fs_deny),
                yes_no(support.fs_enumerate),
                yes_no(support.network_ingress),
            )
        }
    };
    SupportInfo {
        is_supported: support.psec_available,
        platform: "windows",
        details,
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error() -> u32 {
    // SAFETY: reads the calling thread's last-error value; no preconditions.
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}
