//! Runtime binding to the process security environment (PSEC) exports of
//! `processmodel.dll`.
//!
//! The exports are not in the public Windows SDK import libraries, so they are
//! resolved at runtime from System32 only:
//!
//! ```text
//! HRESULT CreateProcessSecurityEnvironment(LPCVOID spec, DWORD size, DWORD flags, HANDLE* env)
//! HRESULT QueryProcessSecurityEnvironmentSupport(UINT64* flags)
//! HRESULT IsProcessSecurityEnvironmentVersionSupported(DWORD major, BOOLEAN* ok, DWORD* minor)
//! void    CloseProcessSecurityEnvironment(HANDLE env)
//! ```
//!
//! A missing DLL or export is an error. There is no fallback mechanism.

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

use crate::error::{NonoError, Result};

use super::{last_error, wide};

/// PSEC schema major version this backend emits.
pub(crate) const SCHEMA_MAJOR: u32 = 1;

/// `QueryProcessSecurityEnvironmentSupport` flag: deny paths are enforced.
pub(crate) const SUPPORT_FS_DENY: u64 = 0x1;
/// `QueryProcessSecurityEnvironmentSupport` flag: enumerate-only grants.
pub(crate) const SUPPORT_FS_ENUMERATE: u64 = 0x4;
/// `QueryProcessSecurityEnvironmentSupport` flag: inbound network policy.
pub(crate) const SUPPORT_NETWORK_INGRESS: u64 = 0x8;

type PfnCreate = unsafe extern "system" fn(*const c_void, u32, u32, *mut HANDLE) -> i32;
type PfnQuery = unsafe extern "system" fn(*mut u64) -> i32;
type PfnVersion = unsafe extern "system" fn(u32, *mut u8, *mut u32) -> i32;
type PfnClose = unsafe extern "system" fn(HANDLE);

/// Resolved PSEC exports. `processmodel.dll` stays loaded for the life of the
/// process.
#[derive(Clone, Copy)]
pub(crate) struct Api {
    create: PfnCreate,
    query: PfnQuery,
    version: PfnVersion,
    close: PfnClose,
}

static API: OnceLock<std::result::Result<Api, String>> = OnceLock::new();

/// The process-wide PSEC binding, loaded on first use.
pub(crate) fn api() -> Result<&'static Api> {
    API.get_or_init(Api::load)
        .as_ref()
        .map_err(|reason| NonoError::UnsupportedPlatform(reason.clone()))
}

impl Api {
    fn load() -> std::result::Result<Self, String> {
        let dll = wide("processmodel.dll");
        // SAFETY: `dll` is a NUL-terminated UTF-16 string that outlives the
        // call, and the search is restricted to System32 so a planted DLL in
        // the application or current directory is never loaded.
        let module =
            unsafe { LoadLibraryExW(dll.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(format!(
                "Windows ProcessContainer (PSEC) is not available: processmodel.dll could not be loaded (Win32 error {})",
                last_error()
            ));
        }
        let get = |name: &[u8]| {
            // SAFETY: `module` is a loaded module handle and `name` is a
            // NUL-terminated ASCII export name.
            unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or_else(|| {
                format!(
                    "Windows ProcessContainer (PSEC) is not available: processmodel.dll has no export {}",
                    String::from_utf8_lossy(name.strip_suffix(b"\0").unwrap_or(name))
                )
            })
        };
        let create = get(b"CreateProcessSecurityEnvironment\0")?;
        let query = get(b"QueryProcessSecurityEnvironmentSupport\0")?;
        let version = get(b"IsProcessSecurityEnvironmentVersionSupported\0")?;
        let close = get(b"CloseProcessSecurityEnvironment\0")?;
        // SAFETY: each export is reinterpreted as the signature documented in
        // the module header. The signatures match the declarations the MXC
        // SDK uses for the same exports and were exercised on build 26300.
        unsafe {
            Ok(Self {
                create: std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnCreate>(
                    create,
                ),
                query: std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnQuery>(query),
                version: std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnVersion>(
                    version,
                ),
                close: std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnClose>(close),
            })
        }
    }

    /// Highest supported minor version for `major`, or `None` when the major
    /// version is not supported.
    pub(crate) fn version_supported(&self, major: u32) -> Result<Option<u32>> {
        let (mut ok, mut minor) = (0u8, 0u32);
        // SAFETY: both out-pointers reference live locals.
        let hr = unsafe { (self.version)(major, &mut ok, &mut minor) };
        if hr < 0 {
            return Err(NonoError::SandboxInit(format!(
                "IsProcessSecurityEnvironmentVersionSupported failed: HRESULT 0x{hr:08x}"
            )));
        }
        Ok((ok != 0).then_some(minor))
    }

    /// Optional feature flags (`SUPPORT_*`).
    pub(crate) fn support_flags(&self) -> Result<u64> {
        let mut flags = 0u64;
        // SAFETY: the out-pointer references a live local.
        let hr = unsafe { (self.query)(&mut flags) };
        if hr < 0 {
            return Err(NonoError::SandboxInit(format!(
                "QueryProcessSecurityEnvironmentSupport failed: HRESULT 0x{hr:08x}"
            )));
        }
        Ok(flags)
    }

    /// Create an environment from an encoded PSEC FlatBuffer.
    pub(crate) fn create(&self, spec: &[u8]) -> Result<Environment> {
        let len = u32::try_from(spec.len())
            .map_err(|_| NonoError::SandboxInit("PSEC spec exceeds 4 GiB".to_string()))?;
        let mut handle: HANDLE = null_mut();
        // SAFETY: `spec` is valid for `len` bytes for the duration of the
        // call and `handle` is a live out-pointer.
        let hr = unsafe { (self.create)(spec.as_ptr().cast(), len, 0, &mut handle) };
        if hr < 0 || handle.is_null() {
            return Err(NonoError::SandboxInit(format!(
                "CreateProcessSecurityEnvironment rejected the policy: HRESULT 0x{hr:08x}"
            )));
        }
        Ok(Environment {
            handle,
            close: self.close,
        })
    }
}

/// An owned PSEC environment, closed on drop.
pub(crate) struct Environment {
    handle: HANDLE,
    close: PfnClose,
}

// SAFETY: the environment handle is a kernel object handle with no thread
// affinity; it is only passed by value to Win32 calls and closed once in Drop.
unsafe impl Send for Environment {}
// SAFETY: shared references only read the handle value.
unsafe impl Sync for Environment {}

impl std::fmt::Debug for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Environment")
    }
}

impl Environment {
    pub(crate) fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for Environment {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateProcessSecurityEnvironment and
        // this is the only place it is closed.
        unsafe { (self.close)(self.handle) };
    }
}

/// Windows PSEC support as observed on this host.
///
/// This is informational. A launch never relies on a cached probe result: it
/// creates its own environment and fails if any step fails.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsSupport {
    /// `processmodel.dll` loaded, schema major 1 is supported, and a probe
    /// environment was created.
    pub psec_available: bool,
    /// Highest supported minor version of schema major 1.
    pub schema_minor: Option<u32>,
    /// Raw `QueryProcessSecurityEnvironmentSupport` flags.
    pub feature_flags: u64,
    /// Deny paths inside granted trees are enforced.
    pub fs_deny: bool,
    /// Enumerate-only grants (no content reads) are available.
    pub fs_enumerate: bool,
    /// Inbound network policy is available.
    pub network_ingress: bool,
    /// Why PSEC is unavailable, when it is.
    pub unavailable_reason: Option<String>,
}

impl WindowsSupport {
    /// Probe this host.
    #[must_use]
    pub fn probe() -> Self {
        match Self::try_probe() {
            Ok(support) => support,
            Err(e) => Self {
                unavailable_reason: Some(e.to_string()),
                ..Self::default()
            },
        }
    }

    fn try_probe() -> Result<Self> {
        let api = api()?;
        let Some(minor) = api.version_supported(SCHEMA_MAJOR)? else {
            return Err(NonoError::UnsupportedPlatform(format!(
                "Windows ProcessContainer (PSEC) does not support schema version {SCHEMA_MAJOR}.x"
            )));
        };
        let flags = api.support_flags()?;
        // Creating an environment from the most restrictive policy proves the
        // mechanism accepts our encoding on this host.
        let probe = super::spec::build(&super::policy::WindowsPolicy::probe(), minor);
        drop(api.create(&probe)?);
        Ok(Self {
            psec_available: true,
            schema_minor: Some(minor),
            feature_flags: flags,
            fs_deny: flags & SUPPORT_FS_DENY != 0,
            fs_enumerate: minor >= 1 && flags & SUPPORT_FS_ENUMERATE != 0,
            network_ingress: flags & SUPPORT_NETWORK_INGRESS != 0,
            unavailable_reason: None,
        })
    }
}
