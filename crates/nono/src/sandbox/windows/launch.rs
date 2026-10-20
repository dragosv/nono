//! Launching a process inside a PSEC environment.
//!
//! Sequence (D4/D8): encode the policy, create the PSEC environment, create a
//! kill-on-close Job Object, create the process suspended with the
//! environment attached, assign it to the job, then resume it. No workload
//! instruction runs before confinement and tree ownership are both in place,
//! and any failing step returns an error.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::capability::CapabilitySet;
use crate::error::{NonoError, Result};
use crate::resource::ResourceLimits;

use super::policy::WindowsPolicy;
use super::psec::{self, Environment, SCHEMA_MAJOR};
use super::{last_error, spec};

/// `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`: attribute 35 with
/// `PROC_THREAD_ATTRIBUTE_INPUT`. Not yet in the public SDK headers.
const PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT: usize = 35 | 0x0002_0000;
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

/// Environment variables PSEC requires to be present (Win32 error 203
/// otherwise). Only presence is checked.
const REQUIRED_ENV: [&str; 2] = ["SYSTEMROOT", "LOCALAPPDATA"];

/// Standard I/O for a launched process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LaunchStdio {
    /// stdin, stdout and stderr are the `NUL` device. The process gets its own
    /// hidden console, never the caller's.
    #[default]
    Null,
    /// stdin, stdout and stderr are pipes available from
    /// [`SandboxedChild::take_stdin`] and friends. The process gets its own
    /// hidden console, never the caller's.
    Piped,
    /// The process inherits the caller's console and standard handles.
    ///
    /// The process shares the console input buffer, so it can inject input
    /// that the console's other readers receive. Use this only when the
    /// caller's console is a pseudo console the caller owns, never the user's
    /// terminal.
    InheritConsole,
}

/// What to launch and how. The environment is exactly [`LaunchOptions::env`];
/// nothing is inherited from the caller.
///
/// `Debug` omits argument and environment values, which may carry secrets.
#[derive(Clone)]
pub struct LaunchOptions {
    program: PathBuf,
    args: Vec<OsString>,
    cwd: PathBuf,
    env: Vec<(OsString, OsString)>,
    deny_paths: Vec<PathBuf>,
    enumerate_paths: Vec<PathBuf>,
    allow_win32k: bool,
    stdio: LaunchStdio,
}

impl std::fmt::Debug for LaunchOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let env_names: Vec<_> = self.env.iter().map(|(k, _)| k).collect();
        f.debug_struct("LaunchOptions")
            .field("program", &self.program)
            .field("args", &format_args!("[{} redacted]", self.args.len()))
            .field("cwd", &self.cwd)
            .field("env_names", &env_names)
            .field("deny_paths", &self.deny_paths)
            .field("enumerate_paths", &self.enumerate_paths)
            .field("allow_win32k", &self.allow_win32k)
            .field("stdio", &self.stdio)
            .finish()
    }
}

impl LaunchOptions {
    /// Launch `program` (an absolute path) with working directory `cwd`.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>, cwd: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: cwd.into(),
            env: Vec::new(),
            deny_paths: Vec::new(),
            enumerate_paths: Vec::new(),
            allow_win32k: false,
            stdio: LaunchStdio::Null,
        }
    }

    /// Append an argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Append arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Add an environment variable. `SYSTEMROOT` and `LOCALAPPDATA` must be
    /// present for a launch to succeed.
    #[must_use]
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Deny a path inside a granted tree. Requires host support.
    #[must_use]
    pub fn deny_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_paths.push(path.into());
        self
    }

    /// Allow querying a path without reading file contents. Requires PSEC 1.1.
    ///
    /// On a volume root the grant cascades (build 26300): the workload can
    /// list the name of every file on the volume. `cmd.exe` needs it on every
    /// ancestor of a program it starts by absolute path, volume root
    /// included.
    #[must_use]
    pub fn enumerate_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.enumerate_paths.push(path.into());
        self
    }

    /// Permit win32k (user32/gdi32) system calls. Off by default. Programs
    /// that load user32, including `cmd.exe`, fail with `0xC0000142` without
    /// it.
    #[must_use]
    pub fn allow_win32k(mut self, allow: bool) -> Self {
        self.allow_win32k = allow;
        self
    }

    /// Standard I/O mode.
    #[must_use]
    pub fn stdio(mut self, stdio: LaunchStdio) -> Self {
        self.stdio = stdio;
        self
    }

    pub(crate) fn deny_paths(&self) -> &[PathBuf] {
        &self.deny_paths
    }

    pub(crate) fn enumerate_paths(&self) -> &[PathBuf] {
        &self.enumerate_paths
    }

    pub(crate) fn win32k_allowed(&self) -> bool {
        self.allow_win32k
    }
}

/// A process running inside a PSEC environment and a kill-on-close Job
/// Object.
///
/// Dropping it ends the whole process tree and then releases the environment.
#[derive(Debug)]
pub struct SandboxedChild {
    pid: u32,
    process: OwnedHandle,
    job: Option<OwnedHandle>,
    environment: Option<Environment>,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    status: Option<u32>,
}

impl SandboxedChild {
    /// Process ID of the launched process.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.pid
    }

    /// Writable end of the process's stdin, for [`LaunchStdio::Piped`].
    pub fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }

    /// Readable end of the process's stdout, for [`LaunchStdio::Piped`].
    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    /// Readable end of the process's stderr, for [`LaunchStdio::Piped`].
    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }

    /// Exit code if the process has exited.
    pub fn try_wait(&mut self) -> Result<Option<u32>> {
        self.wait_ms(0)
    }

    /// Wait for the process to exit and return its exit code.
    pub fn wait(&mut self) -> Result<u32> {
        loop {
            if let Some(code) = self.wait_ms(INFINITE)? {
                return Ok(code);
            }
        }
    }

    /// Wait up to `timeout`; `None` if the process is still running.
    pub fn wait_timeout(&mut self, timeout: Duration) -> Result<Option<u32>> {
        let ms = u32::try_from(timeout.as_millis()).unwrap_or(INFINITE - 1);
        self.wait_ms(ms.min(INFINITE - 1))
    }

    /// End the process and every descendant.
    pub fn terminate(&mut self) -> Result<()> {
        if let Some(job) = &self.job {
            // SAFETY: `job` is a live job handle owned by self.
            if unsafe { TerminateJobObject(job.as_raw_handle(), 1) } == 0 {
                return Err(win32_error("TerminateJobObject"));
            }
        }
        Ok(())
    }

    fn wait_ms(&mut self, ms: u32) -> Result<Option<u32>> {
        if let Some(code) = self.status {
            return Ok(Some(code));
        }
        // SAFETY: `process` is a live process handle owned by self.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), ms) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: live process handle and out-pointer.
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                    return Err(win32_error("GetExitCodeProcess"));
                }
                self.status = Some(code);
                Ok(Some(code))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(win32_error("WaitForSingleObject")),
        }
    }
}

impl Drop for SandboxedChild {
    fn drop(&mut self) {
        // Closing the job would kill the tree too (KILL_ON_JOB_CLOSE); the
        // explicit terminate makes the order certain: tree first, then the
        // environment.
        let _ = self.terminate();
        drop(self.job.take());
        drop(self.environment.take());
    }
}

pub(crate) fn render(caps: &CapabilitySet, opts: &LaunchOptions) -> Result<super::RenderedPolicy> {
    let host = host_info().ok();
    let policy = WindowsPolicy::from_launch(caps, opts, host)?;
    Ok(policy.render(host.map(|(minor, _)| minor)))
}

fn host_info() -> Result<(u32, u64)> {
    host_info_from(psec::api()?)
}

fn host_info_from(api: &psec::Api) -> Result<(u32, u64)> {
    let minor = api.version_supported(SCHEMA_MAJOR)?.ok_or_else(|| {
        NonoError::UnsupportedPlatform(format!(
            "Windows ProcessContainer (PSEC) does not support schema version {SCHEMA_MAJOR}.x"
        ))
    })?;
    Ok((minor, api.support_flags()?))
}

pub(crate) fn launch(caps: &CapabilitySet, opts: &LaunchOptions) -> Result<SandboxedChild> {
    let api = psec::api()?;
    let (minor, flags) = host_info_from(api)?;
    let policy = WindowsPolicy::from_launch(caps, opts, Some((minor, flags)))?;

    if !opts.program.is_absolute() {
        return Err(NonoError::SandboxInit(format!(
            "program must be an absolute path: {}",
            opts.program.display()
        )));
    }
    let program = strip_verbatim(&opts.program);
    let application = wide_path(&program, "program")?;
    let mut command_line = command_line(&program, &opts.args)?;
    let cwd = wide_path(&strip_verbatim(&opts.cwd), "working directory")?;
    let env_block = env_block(&opts.env)?;

    let environment = api.create(&spec::build(&policy, minor))?;
    let job = create_job(caps.resource_limits())?;
    let mut stdio = Stdio::new(opts.stdio)?;

    // Attribute list: security environment, plus the handle list when the
    // child gets explicit standard handles.
    let attribute_count = if stdio.inherit.is_empty() { 1 } else { 2 };
    let attributes = AttributeList::new(attribute_count)?;
    let environment_handle: HANDLE = environment.handle();
    // SAFETY: the list is initialised; the value pointer references a local
    // that outlives CreateProcessW below.
    if unsafe {
        UpdateProcThreadAttribute(
            attributes.as_ptr(),
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT,
            (&raw const environment_handle).cast(),
            std::mem::size_of::<HANDLE>(),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(win32_error(
            "UpdateProcThreadAttribute(SECURITY_ENVIRONMENT)",
        ));
    }
    if !stdio.inherit.is_empty() {
        // SAFETY: as above; `stdio.inherit` outlives CreateProcessW and holds
        // only inheritable handles owned by `stdio`.
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                stdio.inherit.as_ptr().cast(),
                std::mem::size_of_val(stdio.inherit.as_slice()),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(win32_error("UpdateProcThreadAttribute(HANDLE_LIST)"));
        }
    }

    // SAFETY: STARTUPINFOEXW is plain data; all-zero is a valid empty value.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb =
        u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(u32::MAX);
    startup.lpAttributeList = attributes.as_ptr();
    let mut creation_flags =
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    if let Some([input, output, error]) = stdio.child {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = input;
        startup.StartupInfo.hStdOutput = output;
        startup.StartupInfo.hStdError = error;
        // A private hidden console: the workload never attaches to the
        // caller's console, so it cannot inject input into it.
        creation_flags |= CREATE_NO_WINDOW;
    }

    // SAFETY: PROCESS_INFORMATION is plain data; all-zero is a valid value.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // The child ends are inheritable only around this call, so a concurrent
    // CreateProcess elsewhere in the caller has the shortest possible window
    // to inherit them.
    stdio.set_child_ends_inheritable(true)?;
    // SAFETY: every pointer references a live, NUL-terminated buffer for the
    // duration of the call; `command_line` is mutable as CreateProcessW
    // requires; handle inheritance is restricted by the handle list.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            i32::from(!stdio.inherit.is_empty()),
            creation_flags,
            env_block.as_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    let create_error =
        (created == 0).then(|| win32_error("CreateProcessW with the security environment"));
    // The child holds its own duplicates; the parent keeps only its pipe ends.
    stdio.close_child_ends();
    if let Some(error) = create_error {
        return Err(error);
    }
    // SAFETY: CreateProcessW succeeded, so both handles are valid and owned
    // by this function.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };
    // SAFETY: live job and process handles.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        let error = win32_error("AssignProcessToJobObject");
        // SAFETY: the process is still suspended; end it before it runs.
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        return Err(error);
    }
    // SAFETY: live handle to the suspended primary thread.
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        let error = win32_error("ResumeThread");
        // SAFETY: live job handle; ends the suspended process.
        unsafe { TerminateJobObject(job.as_raw_handle(), 1) };
        return Err(error);
    }
    drop(thread);

    Ok(SandboxedChild {
        pid: info.dwProcessId,
        process,
        job: Some(job),
        environment: Some(environment),
        stdin: stdio.parent_stdin.take(),
        stdout: stdio.parent_stdout.take(),
        stderr: stdio.parent_stderr.take(),
        status: None,
    })
}

fn win32_error(what: &str) -> NonoError {
    NonoError::SandboxInit(format!("{what} failed: Win32 error {}", last_error()))
}

fn owned(handle: HANDLE, what: &str) -> Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(win32_error(what));
    }
    // SAFETY: the handle was just returned to us by a successful Win32 call
    // and is not owned elsewhere.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn create_job(limits: Option<&ResourceLimits>) -> Result<OwnedHandle> {
    // SAFETY: anonymous job object with default security.
    let job = owned(
        unsafe { CreateJobObjectW(null(), null()) },
        "CreateJobObjectW",
    )?;
    // SAFETY: plain data; all-zero is a valid empty value.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    // Breakaway is not permitted (no JOB_OBJECT_LIMIT_BREAKAWAY_OK).
    let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // `max_processes` is refused by the policy mapping: a job cannot limit
    // threads. The memory cap is on committed memory, which bounds private
    // resident memory; allocations beyond it fail instead of the tree being
    // killed.
    if let Some(bytes) = limits.and_then(|l| l.memory_bytes) {
        info.JobMemoryLimit = usize::try_from(bytes).map_err(|_| {
            NonoError::SandboxInit(format!("memory limit {bytes} exceeds the address space"))
        })?;
        flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    }
    info.BasicLimitInformation.LimitFlags = flags;
    // SAFETY: live job handle; the pointer and size describe `info`.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .unwrap_or(u32::MAX),
        )
    } == 0
    {
        return Err(win32_error("SetInformationJobObject"));
    }
    // PSEC confines win32k only by turning it off. When it is allowed, these
    // keep the workload away from the clipboard, global atoms, other
    // processes' windows and desktop or system settings.
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: UI_RESTRICTIONS,
    };
    // SAFETY: live job handle; the pointer and size describe `ui`.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectBasicUIRestrictions,
            (&raw const ui).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>())
                .unwrap_or(u32::MAX),
        )
    } == 0
    {
        return Err(win32_error("SetInformationJobObject(UI restrictions)"));
    }
    Ok(job)
}

/// Every job UI limit.
const UI_RESTRICTIONS: u32 = JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

/// An initialised `PROC_THREAD_ATTRIBUTE_LIST`, deleted on drop.
struct AttributeList {
    // Backing memory for `list`; never resized after initialisation.
    _storage: Vec<usize>,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttributeList {
    fn new(count: u32) -> Result<Self> {
        let mut size = 0usize;
        // SAFETY: documented sizing call with a null list; it fails with
        // ERROR_INSUFFICIENT_BUFFER and writes the required size.
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        if size == 0 {
            return Err(win32_error("InitializeProcThreadAttributeList(size)"));
        }
        let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: `storage` is pointer-aligned and at least `size` bytes.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), count, 0, &mut size)
        } == 0
        {
            return Err(win32_error("InitializeProcThreadAttributeList"));
        }
        let list = storage.as_mut_ptr().cast();
        Ok(Self {
            _storage: storage,
            list,
        })
    }

    fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.list
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialised in `new` and is deleted once.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

/// Standard handle plumbing for one launch.
struct Stdio {
    /// Child-side handles (stdin, stdout, stderr), when redirected.
    child: Option<[HANDLE; 3]>,
    /// Distinct inheritable handles for the handle list.
    inherit: Vec<HANDLE>,
    /// Owners of the child-side handles, closed after launch.
    child_owned: Vec<OwnedHandle>,
    parent_stdin: Option<File>,
    parent_stdout: Option<File>,
    parent_stderr: Option<File>,
}

impl Stdio {
    fn new(mode: LaunchStdio) -> Result<Self> {
        let mut stdio = Self {
            child: None,
            inherit: Vec::new(),
            child_owned: Vec::new(),
            parent_stdin: None,
            parent_stdout: None,
            parent_stderr: None,
        };
        match mode {
            LaunchStdio::InheritConsole => {}
            LaunchStdio::Null => {
                let null = open_null()?;
                let raw = null.as_raw_handle();
                stdio.child = Some([raw, raw, raw]);
                stdio.inherit.push(raw);
                stdio.child_owned.push(null);
            }
            LaunchStdio::Piped => {
                let (child_in, parent_in) = pipe()?;
                let (parent_out, child_out) = pipe()?;
                let (parent_err, child_err) = pipe()?;
                stdio.child = Some([
                    child_in.as_raw_handle(),
                    child_out.as_raw_handle(),
                    child_err.as_raw_handle(),
                ]);
                stdio.inherit.extend([
                    child_in.as_raw_handle(),
                    child_out.as_raw_handle(),
                    child_err.as_raw_handle(),
                ]);
                stdio.child_owned.extend([child_in, child_out, child_err]);
                stdio.parent_stdin = Some(File::from(parent_in));
                stdio.parent_stdout = Some(File::from(parent_out));
                stdio.parent_stderr = Some(File::from(parent_err));
            }
        }
        Ok(stdio)
    }

    /// Toggle inheritance on the child-side handles. They are created
    /// non-inheritable and made inheritable only for `CreateProcessW`.
    fn set_child_ends_inheritable(&self, inheritable: bool) -> Result<()> {
        let value = if inheritable { HANDLE_FLAG_INHERIT } else { 0 };
        for handle in &self.child_owned {
            // SAFETY: live handle owned by `self`.
            if unsafe { SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, value) }
                == 0
            {
                return Err(win32_error("SetHandleInformation"));
            }
        }
        Ok(())
    }

    fn close_child_ends(&mut self) {
        self.child = None;
        self.inherit.clear();
        self.child_owned.clear();
    }
}

/// Create a pipe. Neither end is inheritable; see
/// [`Stdio::set_child_ends_inheritable`].
fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let (mut read, mut write): (HANDLE, HANDLE) = (null_mut(), null_mut());
    // SAFETY: live out-pointers; null attributes make both ends
    // non-inheritable.
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        return Err(win32_error("CreatePipe"));
    }
    Ok((owned(read, "CreatePipe")?, owned(write, "CreatePipe")?))
}

fn open_null() -> Result<OwnedHandle> {
    let name = super::wide("NUL");
    // SAFETY: NUL-terminated name; null attributes make the handle
    // non-inheritable.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    owned(handle, "CreateFileW(NUL)")
}

/// `\\?\X:\rest` → `X:\rest`. Canonical paths come back in verbatim form,
/// which `cmd.exe` and other programs treat as UNC when used as the working
/// directory or argv[0]. Other forms are returned unchanged.
fn strip_verbatim(path: &Path) -> PathBuf {
    use std::path::{Component, Prefix};
    let mut components = path.components();
    match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::VerbatimDisk(drive) => {
                let mut plain = PathBuf::from(format!("{}:\\", char::from(drive)));
                plain.extend(components.filter(|c| !matches!(c, Component::RootDir)));
                plain
            }
            _ => path.to_path_buf(),
        },
        _ => path.to_path_buf(),
    }
}

fn wide_path(path: &Path, what: &str) -> Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(NonoError::SandboxInit(format!("{what} contains NUL")));
    }
    wide.push(0);
    Ok(wide)
}

const BACKSLASH: u16 = b'\\' as u16;
const QUOTE: u16 = b'"' as u16;

/// Build a `CommandLineToArgvW`-compatible command line.
///
/// `cmd.exe` parses the command line of `.bat`/`.cmd` targets with its own
/// rules, so arguments for them are limited to characters it treats literally
/// (the BatBadBut class of injection).
pub(crate) fn command_line(program: &Path, args: &[OsString]) -> Result<Vec<u16>> {
    let program_wide: Vec<u16> = program.as_os_str().encode_wide().collect();
    if program_wide.contains(&0) || program_wide.contains(&QUOTE) {
        return Err(NonoError::SandboxInit(format!(
            "program path cannot be quoted: {}",
            program.display()
        )));
    }
    // Windows drops trailing dots and spaces from the file name and resolves
    // `name:stream` to a data stream, so `run.bat.`, `run.bat ` and
    // `run.bat::$DATA` would run as batch files while `extension()` sees no
    // `bat`. Such names are refused rather than reinterpreted.
    let file_name: Vec<u16> = program
        .file_name()
        .map(|n| n.encode_wide().collect())
        .unwrap_or_default();
    if file_name.is_empty()
        || file_name.ends_with(&[u16::from(b'.')])
        || file_name.ends_with(&[u16::from(b' ')])
        || file_name.contains(&u16::from(b':'))
    {
        return Err(NonoError::SandboxInit(format!(
            "program file name is ambiguous on Windows (trailing dot or space, or a data stream): {}",
            program.display()
        )));
    }
    let is_batch = program
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|e| e.eq_ignore_ascii_case("bat") || e.eq_ignore_ascii_case("cmd"));

    // argv[0] is parsed without escape processing: quote it verbatim.
    let mut line = Vec::with_capacity(program_wide.len().saturating_add(2));
    line.push(QUOTE);
    line.extend_from_slice(&program_wide);
    line.push(QUOTE);
    // Errors name the argument position only; values may carry secrets.
    for (index, arg) in args.iter().enumerate() {
        let position = index.saturating_add(1);
        let arg_wide: Vec<u16> = arg.encode_wide().collect();
        if arg_wide.contains(&0) {
            return Err(NonoError::SandboxInit(format!(
                "argument {position} contains NUL"
            )));
        }
        if is_batch && !batch_safe(arg) {
            return Err(NonoError::SandboxInit(format!(
                "argument {position} contains characters that cannot be passed safely to a batch file"
            )));
        }
        line.push(u16::from(b' '));
        quote_arg(&arg_wide, &mut line);
    }
    line.push(0);
    Ok(line)
}

fn batch_safe(arg: &OsStr) -> bool {
    arg.to_str().is_some_and(|s| {
        s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '-' | '_' | '.' | ',' | '/' | '\\' | ':' | '=' | '+' | '@' | '~' | '#'
                )
        })
    })
}

fn quote_arg(arg: &[u16], out: &mut Vec<u16>) {
    let needs_quotes = arg.is_empty()
        || arg
            .iter()
            .any(|&c| matches!(c, 0x20 | 0x09 | 0x0a | 0x0b) || c == QUOTE);
    if !needs_quotes {
        out.extend_from_slice(arg);
        return;
    }
    out.push(QUOTE);
    let mut backslashes = 0usize;
    for &c in arg {
        if c == BACKSLASH {
            backslashes = backslashes.saturating_add(1);
            continue;
        }
        if c == QUOTE {
            // Escape the run of backslashes and the quote itself.
            out.extend(std::iter::repeat_n(
                BACKSLASH,
                backslashes.saturating_mul(2).saturating_add(1),
            ));
        } else {
            out.extend(std::iter::repeat_n(BACKSLASH, backslashes));
        }
        out.push(c);
        backslashes = 0;
    }
    // Backslashes before the closing quote must be doubled.
    out.extend(std::iter::repeat_n(
        BACKSLASH,
        backslashes.saturating_mul(2),
    ));
    out.push(QUOTE);
}

/// Build a sorted, double-NUL-terminated environment block.
pub(crate) fn env_block(env: &[(OsString, OsString)]) -> Result<Vec<u16>> {
    let invalid = |var: &OsStr, reason: &str| NonoError::EnvVarValidation {
        var: var.to_string_lossy().into_owned(),
        reason: reason.to_string(),
    };
    let mut entries: Vec<(String, Vec<u16>)> = Vec::with_capacity(env.len());
    for (key, value) in env {
        let key_wide: Vec<u16> = key.encode_wide().collect();
        if key_wide.is_empty() || key_wide.contains(&0) || key_wide.contains(&u16::from(b'=')) {
            return Err(invalid(key, "invalid variable name"));
        }
        let value_wide: Vec<u16> = value.encode_wide().collect();
        if value_wide.contains(&0) {
            return Err(invalid(key, "value contains NUL"));
        }
        let folded = key.to_string_lossy().to_uppercase();
        if entries.iter().any(|(k, _)| *k == folded) {
            return Err(invalid(
                key,
                "variable is set more than once (names are case-insensitive)",
            ));
        }
        let mut entry = key_wide;
        entry.push(u16::from(b'='));
        entry.extend(value_wide);
        entries.push((folded, entry));
    }
    let missing: Vec<&str> = REQUIRED_ENV
        .iter()
        .copied()
        .filter(|name| !entries.iter().any(|(k, _)| k == name))
        .collect();
    if !missing.is_empty() {
        return Err(NonoError::EnvVarValidation {
            var: missing.join(", "),
            reason: "required by Windows PSEC for process creation".to_string(),
        });
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut block = Vec::new();
    for (_, entry) in entries {
        block.extend(entry);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(program: &str, args: &[&str]) -> Result<String> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let wide = command_line(Path::new(program), &args)?;
        Ok(String::from_utf16_lossy(
            &wide[..wide.len().saturating_sub(1)],
        ))
    }

    #[test]
    fn quoting_matches_command_line_to_argv() -> Result<()> {
        assert_eq!(line(r"C:\a b\p.exe", &["x"])?, r#""C:\a b\p.exe" x"#);
        assert_eq!(line(r"C:\p.exe", &[""])?, r#""C:\p.exe" """#);
        assert_eq!(line(r"C:\p.exe", &["a b"])?, r#""C:\p.exe" "a b""#);
        assert_eq!(
            line(r"C:\p.exe", &[r#"say "hi""#])?,
            r#""C:\p.exe" "say \"hi\"""#
        );
        assert_eq!(
            line(r"C:\p.exe", &[r"C:\dir\ x\"])?,
            r#""C:\p.exe" "C:\dir\ x\\""#
        );
        assert_eq!(line(r"C:\p.exe", &[r"a\\b"])?, r#""C:\p.exe" a\\b"#);
        Ok(())
    }

    #[test]
    fn batch_targets_refuse_metacharacters() {
        assert!(line(r"C:\x\run.cmd", &["ok-arg", r"C:\path"]).is_ok());
        for bad in ["a&b", "%PATH%", "a|b", "\"q\"", "a^b", "x>y", "(x)", "!x!"] {
            assert!(line(r"C:\x\run.BAT", &[bad]).is_err(), "{bad}");
        }
    }

    #[test]
    fn strip_verbatim_only_touches_drive_paths() {
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\C:\a\b")),
            PathBuf::from(r"C:\a\b")
        );
        assert_eq!(strip_verbatim(Path::new(r"\\?\C:\")), PathBuf::from(r"C:\"));
        assert_eq!(strip_verbatim(Path::new(r"D:\x")), PathBuf::from(r"D:\x"));
        assert_eq!(
            strip_verbatim(Path::new(r"\\?\UNC\s\share")),
            PathBuf::from(r"\\?\UNC\s\share")
        );
    }

    #[test]
    fn secrets_stay_out_of_debug_and_errors() {
        let opts = LaunchOptions::new(r"C:\x\run.cmd", r"C:\")
            .arg("--token=hunter2-arg")
            .env("API_KEY", "hunter2-env");
        let debug = format!("{opts:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("API_KEY"), "{debug}");

        let err = line(r"C:\x\run.cmd", &["hunter2&calc"])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(!err.is_empty() && !err.contains("hunter2"), "{err}");
    }

    #[test]
    fn program_with_quote_is_rejected() {
        assert!(line(r#"C:\a"b.exe"#, &[]).is_err());
    }

    #[test]
    fn ambiguous_program_names_are_rejected() {
        // Each of these runs C:\x\run.bat through cmd.exe while
        // `extension()` reports something other than `bat` (CVE-2024-43402).
        for program in [
            r"C:\x\run.bat.",
            r"C:\x\run.bat ",
            r"C:\x\run.bat. .",
            r"C:\x\run.bat::$DATA",
            r"C:\x\run.exe.",
        ] {
            assert!(line(program, &[]).is_err(), "{program:?}");
            assert!(line(program, &["a&calc"]).is_err(), "{program:?}");
        }
        assert!(line(r"C:\x.y\run.exe", &["a&b"]).is_ok());
    }

    #[test]
    fn ui_restrictions_cover_every_limit() {
        assert_eq!(UI_RESTRICTIONS, 0xff);
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    #[test]
    fn env_block_requires_psec_variables() {
        let err = env_block(&env(&[("PATH", "x")]))
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            err.contains("SYSTEMROOT") && err.contains("LOCALAPPDATA"),
            "{err}"
        );
    }

    #[test]
    fn env_block_rejects_case_insensitive_duplicates() {
        let e = env(&[
            ("SystemRoot", "C:\\Windows"),
            ("SYSTEMROOT", "x"),
            ("LOCALAPPDATA", "y"),
        ]);
        assert!(env_block(&e).is_err());
    }

    #[test]
    fn env_block_rejects_bad_names() {
        let e = env(&[("SystemRoot", "a"), ("LOCALAPPDATA", "b"), ("A=B", "c")]);
        assert!(env_block(&e).is_err());
    }

    #[test]
    fn env_block_is_sorted_and_double_nul_terminated() -> Result<()> {
        let e = env(&[
            ("b", "2"),
            ("SystemRoot", "C:\\Windows"),
            ("LocalAppData", "L"),
            ("A", "1"),
        ]);
        let block = env_block(&e)?;
        let text = String::from_utf16_lossy(&block);
        assert_eq!(text, "A=1\0b=2\0LocalAppData=L\0SystemRoot=C:\\Windows\0\0");
        Ok(())
    }
}
