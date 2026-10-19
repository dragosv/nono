//! Minimal direct binding to the Windows process security environment (PSEC).
//!
//! `processmodel.dll` exports (resolved at runtime):
//!   HRESULT CreateProcessSecurityEnvironment(LPCVOID spec, DWORD size, DWORD flags, HANDLE* env)
//!   HRESULT QueryProcessSecurityEnvironmentSupport(UINT64* flags)
//!   HRESULT IsProcessSecurityEnvironmentVersionSupported(DWORD major, BOOLEAN* ok, DWORD* minor)
//!   void    CloseProcessSecurityEnvironment(HANDLE env)
//! The environment handle is attached to an ordinary `CreateProcessW` through
//! `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` (35 | PROC_THREAD_ATTRIBUTE_INPUT).
#![allow(clippy::missing_safety_doc)]

#[allow(dead_code, unused_imports, non_snake_case, non_camel_case_types, clippy::all, mismatched_lifetime_syntaxes)]
#[path = "psec_spec/mod.rs"]
mod psec_spec;

use psec_spec::process_security_environment_layout as layout;
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
};

const PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT: usize = 35 | 0x0002_0000;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;

pub const SUPPORT_FS_DENY: u64 = 0x1;
pub const SUPPORT_FS_ENUMERATE: u64 = 0x4;
pub const SUPPORT_NETWORK_INGRESS: u64 = 0x8;

type PfnCreate = unsafe extern "system" fn(*const c_void, u32, u32, *mut HANDLE) -> i32;
type PfnQuery = unsafe extern "system" fn(*mut u64) -> i32;
type PfnVersion = unsafe extern "system" fn(u32, *mut u8, *mut u32) -> i32;
type PfnClose = unsafe extern "system" fn(HANDLE);

#[derive(Debug)]
pub struct Error(pub String);
pub type Result<T> = std::result::Result<T, Error>;

fn win32(what: &str) -> Error {
    // SAFETY: reads the calling thread's last-error value.
    Error(format!("{what} failed: Win32 error {}", unsafe { GetLastError() }))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Resolved PSEC exports.
#[derive(Clone, Copy)]
pub struct Api {
    create: PfnCreate,
    query: PfnQuery,
    version: PfnVersion,
    close: PfnClose,
}

impl Api {
    pub fn load() -> Result<Self> {
        let dll = wide("processmodel.dll");
        // SAFETY: valid NUL-terminated wide string; search restricted to System32.
        let module = unsafe { LoadLibraryExW(dll.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(win32("LoadLibraryExW(processmodel.dll)"));
        }
        let get = |name: &[u8]| {
            // SAFETY: `module` is a loaded module and `name` is NUL-terminated.
            unsafe { GetProcAddress(module, name.as_ptr()) }
                .ok_or_else(|| Error(format!("export {} missing", String::from_utf8_lossy(&name[..name.len() - 1]))))
        };
        // SAFETY: each export is transmuted to the signature documented above
        // (taken from the MXC SDK's declarations of the same exports).
        unsafe {
            Ok(Self {
                create: std::mem::transmute::<_, PfnCreate>(get(b"CreateProcessSecurityEnvironment\0")?),
                query: std::mem::transmute::<_, PfnQuery>(get(b"QueryProcessSecurityEnvironmentSupport\0")?),
                version: std::mem::transmute::<_, PfnVersion>(get(b"IsProcessSecurityEnvironmentVersionSupported\0")?),
                close: std::mem::transmute::<_, PfnClose>(get(b"CloseProcessSecurityEnvironment\0")?),
            })
        }
    }

    /// Highest supported minor version for `major`, if `major` is supported.
    pub fn version_supported(&self, major: u32) -> Result<Option<u32>> {
        let (mut ok, mut minor) = (0u8, 0u32);
        // SAFETY: valid out-pointers.
        let hr = unsafe { (self.version)(major, &mut ok, &mut minor) };
        if hr < 0 {
            return Err(Error(format!("IsProcessSecurityEnvironmentVersionSupported hr=0x{hr:08x}")));
        }
        Ok((ok != 0).then_some(minor))
    }

    pub fn support_flags(&self) -> Result<u64> {
        let mut flags = 0u64;
        // SAFETY: valid out-pointer.
        let hr = unsafe { (self.query)(&mut flags) };
        if hr < 0 {
            return Err(Error(format!("QueryProcessSecurityEnvironmentSupport hr=0x{hr:08x}")));
        }
        Ok(flags)
    }

    pub fn create(&self, spec: &[u8]) -> Result<Environment> {
        let mut env: HANDLE = null_mut();
        let len = u32::try_from(spec.len()).map_err(|_| Error("spec too large".into()))?;
        // SAFETY: `spec` is a valid buffer of `len` bytes; `env` is a valid out-pointer.
        let hr = unsafe { (self.create)(spec.as_ptr().cast(), len, 0, &mut env) };
        if hr < 0 || env.is_null() {
            return Err(Error(format!("CreateProcessSecurityEnvironment hr=0x{hr:08x}")));
        }
        Ok(Environment { handle: env, close: self.close })
    }
}

/// Owned PSEC environment; closed on drop.
pub struct Environment {
    handle: HANDLE,
    close: PfnClose,
}

impl Drop for Environment {
    fn drop(&mut self) {
        // SAFETY: handle came from CreateProcessSecurityEnvironment and is closed once.
        unsafe { (self.close)(self.handle) };
    }
}

#[derive(Default, Clone)]
pub enum Net {
    /// Deny all egress.
    #[default]
    Blocked,
    /// Allow all egress.
    AllowAll,
    /// PSEC proxy mode: only the given loopback proxy URL is reachable.
    Proxy(String),
}

#[derive(Default, Clone)]
pub struct Policy {
    pub read_write: Vec<String>,
    pub read_only: Vec<String>,
    pub deny: Vec<String>,
    /// Paths that may be queried/enumerated without reading content (PSEC 1.1).
    pub enumerate: Vec<String>,
    pub net: Net,
    /// Permit win32k (user32/gdi32) system calls; console apps like cmd.exe need it.
    pub allow_win32k: bool,
    /// Spike-only: launch WITHOUT the security environment (control runs, shim host).
    pub unconfined_control: bool,
}

/// Encode a PSEC v1.x FlatBuffer for `policy`, mirroring what mxc-sdk 1.0.1
/// emits for the equivalent request.
pub fn build_spec(policy: &Policy, minor: u16) -> Vec<u8> {
    let nonempty = |v: &Vec<String>| (!v.is_empty()).then(|| v.clone());
    let mut caps: Vec<&str> = Vec::new();
    let mut network = layout::NetworkPolicyT::default();
    match &policy.net {
        Net::Blocked => {
            network.egress = Some(Box::new(layout::EndpointPolicyT {
                default_action: layout::FilterAction::deny,
                ..Default::default()
            }));
        }
        Net::AllowAll => {
            caps.push("internetClient");
            network.egress = Some(Box::new(layout::EndpointPolicyT {
                default_action: layout::FilterAction::allow,
                ..Default::default()
            }));
        }
        Net::Proxy(url) => {
            // SDK proxy shape: ingress default allow -> privateNetworkClientServer,
            // hostLoopback allow -> networkLoopback + identity-less loopback peer.
            caps.push("privateNetworkClientServer");
            caps.push("networkLoopback");
            network.proxy = Some(Box::new(layout::ProxyInfoT { url: Some(url.clone()) }));
            network.allowed_appcontainer_peer = Some("MXC-Loopback".to_string());
        }
    }
    let spec = layout::ProcessSecurityEnvironmentT {
        version: layout::SchemaVersionT { major: 1, minor },
        capabilities: (!caps.is_empty()).then(|| caps.join(",")),
        disallow_win32k_system_calls: !policy.allow_win32k,
        ui_restrictions: 0,
        fs_read_write: nonempty(&policy.read_write),
        fs_read_only: nonempty(&policy.read_only),
        fs_deny: nonempty(&policy.deny),
        fs_enumerate: nonempty(&policy.enumerate),
        network_policy: Some(Box::new(network)),
    };
    let mut b = flatbuffers::FlatBufferBuilder::with_capacity(1024);
    let root = spec.pack(&mut b);
    layout::finish_process_security_environment_buffer(&mut b, root);
    b.finished_data().to_vec()
}

/// Windows command-line quoting compatible with `CommandLineToArgvW`.
pub fn quote_arg(arg: &str, out: &mut String) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
}

pub fn command_line(program: &str, args: &[String]) -> String {
    let mut s = String::new();
    quote_arg(program, &mut s);
    for a in args {
        s.push(' ');
        quote_arg(a, &mut s);
    }
    s
}

fn env_block(env: &[(String, String)]) -> Vec<u16> {
    let mut sorted: Vec<_> = env.to_vec();
    sorted.sort_by_key(|(k, _)| k.to_uppercase());
    let mut block = Vec::new();
    for (k, v) in sorted {
        block.extend(format!("{k}={v}").encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// Owned handle that is closed on drop.
pub struct Owned(pub HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: owned, valid handle closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn pipe(inherit_read: bool, inherit_write: bool) -> Result<(Owned, Owned)> {
    let (mut r, mut w): (HANDLE, HANDLE) = (null_mut(), null_mut());
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: valid out-pointers and attributes.
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
        return Err(win32("CreatePipe"));
    }
    let (r, w) = (Owned(r), Owned(w));
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    // SAFETY: valid handles owned above.
    unsafe {
        if !inherit_read {
            SetHandleInformation(r.0, HANDLE_FLAG_INHERIT, 0);
        }
        if !inherit_write {
            SetHandleInformation(w.0, HANDLE_FLAG_INHERIT, 0);
        }
    }
    Ok((r, w))
}

pub enum Stdio {
    /// Child stdout+stderr go to a pipe returned in `Child::stdout`.
    Piped,
    /// Child is attached to a new pseudo console of this size.
    Pty { cols: i16, rows: i16 },
    /// Child inherits the parent's console (no std handle redirection).
    InheritConsole,
}

/// A process launched inside a PSEC environment and a kill-on-close job.
/// Drop order: job (kills the tree) -> environment.
pub struct Child {
    pub process: Owned,
    pub pid: u32,
    pub stdout: Option<std::fs::File>,
    pub pty_in: Option<std::fs::File>,
    pub pty: Option<HPCON>,
    job: Owned,
    _env: Environment,
}

impl Child {
    /// Wait up to `ms` milliseconds; returns the exit code if it exited.
    pub fn wait_ms(&self, ms: u32) -> Result<Option<u32>> {
        // SAFETY: valid process handle.
        match unsafe { WaitForSingleObject(self.process.0, ms) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: valid process handle and out-pointer.
                if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
                    return Err(win32("GetExitCodeProcess"));
                }
                Ok(Some(code))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(win32("WaitForSingleObject")),
        }
    }

    pub fn terminate(&self) -> Result<()> {
        // SAFETY: valid job handle.
        if unsafe { TerminateJobObject(self.job.0, 1) } == 0 {
            return Err(win32("TerminateJobObject"));
        }
        Ok(())
    }

    pub fn resize(&self, cols: i16, rows: i16) -> Result<()> {
        let pty = self.pty.ok_or_else(|| Error("no pty".into()))?;
        // SAFETY: valid pseudo console handle.
        let hr = unsafe { ResizePseudoConsole(pty, COORD { X: cols, Y: rows }) };
        if hr < 0 {
            return Err(Error(format!("ResizePseudoConsole hr=0x{hr:08x}")));
        }
        Ok(())
    }

    /// Close the pseudo console (flushes and ends its output stream).
    pub fn close_pty(&mut self) {
        if let Some(p) = self.pty.take() {
            // SAFETY: valid pseudo console handle closed once.
            unsafe { ClosePseudoConsole(p) };
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        self.close_pty();
        // Job handle drops first (KILL_ON_JOB_CLOSE), then `_env`.
    }
}

pub fn launch(
    api: &Api,
    policy: &Policy,
    minor: u16,
    program: &str,
    args: &[String],
    cwd: &str,
    env: &[(String, String)],
    stdio: Stdio,
) -> Result<Child> {
    use std::os::windows::io::FromRawHandle;

    let spec = build_spec(policy, minor);
    let environment = api.create(&spec)?;

    // SAFETY: anonymous job, default security.
    let job = Owned(unsafe { CreateJobObjectW(null(), null()) });
    if job.0.is_null() {
        return Err(win32("CreateJobObjectW"));
    }
    // SAFETY: zero-initialised POD struct.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: valid job handle and correctly sized struct.
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(win32("SetInformationJobObject"));
    }

    // Stdio plumbing.
    let mut stdout_read = None;
    let mut child_stdout_write = None;
    let mut pty_handle: Option<HPCON> = None;
    let mut pty_in_write = None;
    let mut pty_out_read = None;
    let mut inherit: Vec<HANDLE> = Vec::new();
    match stdio {
        Stdio::Piped => {
            let (r, w) = pipe(false, true)?;
            inherit.push(w.0);
            stdout_read = Some(r);
            child_stdout_write = Some(w);
        }
        Stdio::InheritConsole => {}
        Stdio::Pty { cols, rows } => {
            let (in_r, in_w) = pipe(false, false)?;
            let (out_r, out_w) = pipe(false, false)?;
            let mut hpc: HPCON = 0 as HPCON;
            // SAFETY: valid pipe handles; out-pointer valid.
            let hr = unsafe { CreatePseudoConsole(COORD { X: cols, Y: rows }, in_r.0, out_w.0, 0, &mut hpc) };
            if hr < 0 {
                return Err(Error(format!("CreatePseudoConsole hr=0x{hr:08x}")));
            }
            // The pseudo console duplicated these ends.
            drop(in_r);
            drop(out_w);
            pty_handle = Some(hpc);
            pty_in_write = Some(in_w);
            pty_out_read = Some(out_r);
        }
    }

    // Attribute list: security environment (+ handle list | pseudo console).
    let attr_count = 2u32;
    let mut size = 0usize;
    // SAFETY: documented sizing call.
    unsafe { InitializeProcThreadAttributeList(null_mut(), attr_count, 0, &mut size) };
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = storage.as_mut_ptr().cast();
    // SAFETY: `storage` has at least `size` bytes, pointer-aligned.
    if unsafe { InitializeProcThreadAttributeList(list, attr_count, 0, &mut size) } == 0 {
        return Err(win32("InitializeProcThreadAttributeList"));
    }
    struct ListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for ListGuard {
        fn drop(&mut self) {
            // SAFETY: list was initialised.
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _guard = ListGuard(list);
    let env_value: HANDLE = environment.handle;
    // Spike-only control: SPIKE_NO_PSEC=1 launches WITHOUT the security
    // environment, to validate the ConPTY/stdio plumbing in isolation.
    let control = policy.unconfined_control || std::env::var_os("SPIKE_NO_PSEC").is_some();
    // SAFETY: list initialised; value pointer outlives CreateProcessW.
    if !control && unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT,
            (&raw const env_value).cast(),
            std::mem::size_of::<HANDLE>(),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(win32("UpdateProcThreadAttribute(SECURITY_ENVIRONMENT)"));
    }
    if let Some(hpc) = pty_handle {
        // SAFETY: as above; HPCON passed by value per ConPTY docs.
        if unsafe {
            UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpc as *const c_void, std::mem::size_of::<HPCON>(), null_mut(), null())
        } == 0
        {
            return Err(win32("UpdateProcThreadAttribute(PSEUDOCONSOLE)"));
        }
    } else if !inherit.is_empty() {
        // SAFETY: as above; `inherit` outlives CreateProcessW.
        if unsafe {
            UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit.as_ptr().cast(), std::mem::size_of_val(inherit.as_slice()), null_mut(), null())
        } == 0
        {
            return Err(win32("UpdateProcThreadAttribute(HANDLE_LIST)"));
        }
    }

    // SAFETY: zero-initialised POD struct.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = list;
    if let Some(w) = &child_stdout_write {
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdOutput = w.0;
        si.StartupInfo.hStdError = w.0;
        si.StartupInfo.hStdInput = null_mut();
    } else if pty_handle.is_some() {
        // Without this, a console child picks up the parent's (pipe) std
        // handles instead of the pseudo console's.
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    }

    let mut cmd = wide(&command_line(program, args));
    let cwd_w = wide(cwd);
    let block = env_block(env);
    // SAFETY: zero-initialised POD struct.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let inherit_handles = i32::from(child_stdout_write.is_some());
    // SAFETY: all pointers valid for the duration of the call; `cmd` is mutable as required.
    let ok = unsafe {
        CreateProcessW(
            null(),
            cmd.as_mut_ptr(),
            null(),
            null(),
            inherit_handles,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            block.as_ptr().cast(),
            cwd_w.as_ptr(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    if ok == 0 {
        if let Some(h) = pty_handle {
            // SAFETY: created above, closed once on this error path.
            unsafe { ClosePseudoConsole(h) };
        }
        return Err(win32("CreateProcessW(SECURITY_ENVIRONMENT)"));
    }
    let process = Owned(pi.hProcess);
    let thread = Owned(pi.hThread);
    // SAFETY: valid job and process handles.
    if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
        let e = win32("AssignProcessToJobObject");
        // SAFETY: process created suspended; terminate before it runs.
        unsafe { windows_sys::Win32::System::Threading::TerminateProcess(process.0, 1) };
        return Err(e);
    }
    // SAFETY: valid suspended thread handle.
    if unsafe { ResumeThread(thread.0) } == u32::MAX {
        return Err(win32("ResumeThread"));
    }
    drop(child_stdout_write); // parent keeps only the read end

    // SAFETY: ownership of the raw handles moves into `File`.
    let to_file = |o: Owned| {
        let h = o.0;
        std::mem::forget(o);
        unsafe { std::fs::File::from_raw_handle(h) }
    };
    Ok(Child {
        process,
        pid: pi.dwProcessId,
        stdout: stdout_read.map(to_file).or(pty_out_read.map(to_file)),
        pty_in: pty_in_write.map(to_file),
        pty: pty_handle,
        job,
        _env: environment,
    })
}
