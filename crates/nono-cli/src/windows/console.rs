//! Interactive runs: a nono-owned pseudo console and an unconfined shim.
//!
//! A PSEC child does not attach to a pseudo console passed next to the
//! security environment, but it does inherit its parent's console. So:
//!
//! ```text
//! nono (user console) ──ConPTY──▶ nono __console-shim run … (unconfined)
//!                                   └──PSEC, console inherited──▶ workload
//! ```
//!
//! The workload is never attached to the user's console, so it cannot inject
//! input that the user's shell reads after nono exits. The shim and the
//! workload live in a kill-on-close job owned by this process, so they die
//! with it.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::time::Duration;

use nono::{LaunchStdio, NonoError, Result, Sandbox};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, COORD, ClosePseudoConsole, CreatePseudoConsole,
    DISABLE_NEWLINE_AUTO_RETURN, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle,
    HPCON, ResizePseudoConsole, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
    SetConsoleMode,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::RunArgs;
use super::plan::Plan;

const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: usize = 0x0002_0016;

fn win32_error(what: &str) -> NonoError {
    NonoError::SandboxInit(format!(
        "{what} failed: Win32 error {}",
        // SAFETY: reads the calling thread's last-error value.
        unsafe { windows_sys::Win32::Foundation::GetLastError() }
    ))
}

fn owned(handle: HANDLE, what: &str) -> Result<OwnedHandle> {
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(win32_error(what));
    }
    // SAFETY: freshly returned by a successful Win32 call and not owned
    // elsewhere.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn std_handle(which: u32) -> HANDLE {
    // SAFETY: GetStdHandle has no preconditions.
    unsafe { GetStdHandle(which) }
}

fn console_mode(handle: HANDLE) -> Option<CONSOLE_MODE> {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: live out-pointer; fails harmlessly for non-console handles.
    (unsafe { GetConsoleMode(handle, &mut mode) } != 0).then_some(mode)
}

/// Both stdin and stdout are attached to a console.
pub(crate) fn is_interactive() -> bool {
    console_mode(std_handle(STD_INPUT_HANDLE)).is_some()
        && console_mode(std_handle(STD_OUTPUT_HANDLE)).is_some()
}

fn console_size() -> COORD {
    // SAFETY: plain data; all-zero is valid.
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: live handle and out-pointer.
    if unsafe { GetConsoleScreenBufferInfo(std_handle(STD_OUTPUT_HANDLE), &mut info) } == 0 {
        return COORD { X: 80, Y: 25 };
    }
    COORD {
        X: info
            .srWindow
            .Right
            .saturating_sub(info.srWindow.Left)
            .saturating_add(1),
        Y: info
            .srWindow
            .Bottom
            .saturating_sub(info.srWindow.Top)
            .saturating_add(1),
    }
}

/// Restores the user's console modes on drop.
struct ConsoleModes {
    input: (HANDLE, CONSOLE_MODE),
    output: (HANDLE, CONSOLE_MODE),
}

impl ConsoleModes {
    /// Raw VT input (Ctrl-C arrives as a byte for the pseudo console to turn
    /// into an interrupt) and VT output.
    fn enter_raw() -> Result<Self> {
        let input = std_handle(STD_INPUT_HANDLE);
        let output = std_handle(STD_OUTPUT_HANDLE);
        let saved = Self {
            input: (
                input,
                console_mode(input).ok_or_else(|| win32_error("GetConsoleMode(stdin)"))?,
            ),
            output: (
                output,
                console_mode(output).ok_or_else(|| win32_error("GetConsoleMode(stdout)"))?,
            ),
        };
        // SAFETY: live console handles.
        unsafe {
            SetConsoleMode(input, ENABLE_VIRTUAL_TERMINAL_INPUT);
            SetConsoleMode(
                output,
                saved.output.1
                    | ENABLE_PROCESSED_OUTPUT
                    | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                    | DISABLE_NEWLINE_AUTO_RETURN,
            );
        }
        Ok(saved)
    }
}

impl Drop for ConsoleModes {
    fn drop(&mut self) {
        // SAFETY: live console handles; restores the saved modes.
        unsafe {
            SetConsoleMode(self.input.0, self.input.1);
            SetConsoleMode(self.output.0, self.output.1);
        }
    }
}

/// Owned pseudo console, closed on drop.
struct PseudoConsole(HPCON);

// SAFETY: an HPCON is an opaque handle usable from any thread.
unsafe impl Send for PseudoConsole {}
// SAFETY: resize is the only shared operation and is thread-safe.
unsafe impl Sync for PseudoConsole {}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        // SAFETY: created by CreatePseudoConsole and closed once.
        unsafe { ClosePseudoConsole(self.0) };
    }
}

fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let (mut read, mut write): (HANDLE, HANDLE) = (null_mut(), null_mut());
    // SAFETY: live out-pointers; null attributes make both ends
    // non-inheritable.
    if unsafe { CreatePipe(&mut read, &mut write, null(), 0) } == 0 {
        return Err(win32_error("CreatePipe"));
    }
    Ok((owned(read, "CreatePipe")?, owned(write, "CreatePipe")?))
}

fn kill_on_close_job() -> Result<OwnedHandle> {
    // SAFETY: anonymous job with default security.
    let job = owned(
        unsafe { CreateJobObjectW(null(), null()) },
        "CreateJobObjectW",
    )?;
    // SAFETY: plain data; all-zero is valid.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: live job handle; pointer and size describe `info`.
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
    Ok(job)
}

/// The command line that re-runs this nono invocation in shim mode.
fn shim_command_line() -> Result<(Vec<u16>, Vec<u16>)> {
    let exe = std::env::current_exe().map_err(NonoError::Io)?;
    let exe = super::plan::plain(&exe);
    let mut line = String::new();
    let mut push = |arg: &str| {
        if !line.is_empty() {
            line.push(' ');
        }
        quote_into(arg, &mut line);
    };
    let exe_str = exe.to_string_lossy().into_owned();
    push(&exe_str);
    push(super::CONSOLE_SHIM_ARG);
    for arg in std::env::args_os().skip(1) {
        let arg = arg.into_string().map_err(|_| {
            NonoError::SandboxInit(
                "arguments must be valid Unicode for interactive runs".to_string(),
            )
        })?;
        push(&arg);
    }
    let wide = |s: &str| {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    Ok((
        exe.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect(),
        wide(&line),
    ))
}

/// `CommandLineToArgvW`-compatible quoting.
fn quote_into(arg: &str, out: &mut String) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        if c == '\\' {
            backslashes = backslashes.saturating_add(1);
            continue;
        }
        let count = if c == '"' {
            backslashes.saturating_mul(2).saturating_add(1)
        } else {
            backslashes
        };
        out.extend(std::iter::repeat_n('\\', count));
        out.push(c);
        backslashes = 0;
    }
    out.extend(std::iter::repeat_n('\\', backslashes.saturating_mul(2)));
    out.push('"');
}

/// Copy between raw handles until either side fails.
fn pump(from: usize, to: usize) {
    let (from, to) = (from as HANDLE, to as HANDLE);
    let mut buf = [0u8; 4096];
    loop {
        let mut read = 0u32;
        // SAFETY: live handles owned by the caller for the life of the
        // thread; the buffer and counts are valid.
        let ok = unsafe {
            ReadFile(
                from,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            break;
        }
        let mut offset = 0usize;
        while offset < read as usize {
            let mut written = 0u32;
            let chunk = &buf[offset..read as usize];
            // SAFETY: as above.
            let ok = unsafe {
                WriteFile(
                    to,
                    chunk.as_ptr(),
                    chunk.len() as u32,
                    &mut written,
                    null_mut(),
                )
            };
            if ok == 0 || written == 0 {
                return;
            }
            offset = offset.saturating_add(written as usize);
        }
    }
}

/// Interactive run: host a pseudo console and relay the user's console to it.
pub(crate) fn run_interactive() -> Result<u32> {
    let (input_read, input_write) = pipe()?;
    let (output_read, output_write) = pipe()?;
    let size = console_size();
    let mut hpc: HPCON = 0;
    // SAFETY: live pipe handles and out-pointer.
    let hr = unsafe {
        CreatePseudoConsole(
            size,
            input_read.as_raw_handle(),
            output_write.as_raw_handle(),
            0,
            &mut hpc,
        )
    };
    if hr < 0 {
        return Err(NonoError::SandboxInit(format!(
            "CreatePseudoConsole failed: HRESULT 0x{hr:08x}"
        )));
    }
    let console = std::sync::Arc::new(PseudoConsole(hpc));
    // The pseudo console holds its own duplicates.
    drop(input_read);
    drop(output_write);

    let job = kill_on_close_job()?;
    let shim = spawn_shim(&console, &job)?;

    // Relays: user console → pseudo console, pseudo console → user console.
    let modes = ConsoleModes::enter_raw()?;
    let input_raw = input_write.as_raw_handle() as usize;
    let stdin_raw = std_handle(STD_INPUT_HANDLE) as usize;
    // Detached: blocks in ReadFile on the user's console until exit.
    std::thread::spawn(move || pump(stdin_raw, input_raw));
    let output_raw = output_read.as_raw_handle() as usize;
    let stdout_raw = std_handle(STD_OUTPUT_HANDLE) as usize;
    let output = std::thread::spawn(move || pump(output_raw, stdout_raw));

    // Resize: follow the user's window size.
    let resize_console = std::sync::Arc::clone(&console);
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let resize_done = std::sync::Arc::clone(&done);
    std::thread::spawn(move || {
        let mut last = size;
        while !resize_done.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
            let now = console_size();
            if now.X != last.X || now.Y != last.Y {
                // SAFETY: the pseudo console outlives this thread via Arc.
                unsafe { ResizePseudoConsole(resize_console.0, now) };
                last = now;
            }
        }
    });

    // SAFETY: live process handle.
    let waited = unsafe { WaitForSingleObject(shim.as_raw_handle(), INFINITE) };
    let mut code = 1u32;
    if waited == WAIT_OBJECT_0 {
        // SAFETY: live process handle and out-pointer.
        unsafe { GetExitCodeProcess(shim.as_raw_handle(), &mut code) };
    }
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    // Closing the pseudo console flushes and ends its output stream.
    drop(console);
    drop(input_write);
    let _ = output.join();
    drop(modes);
    drop(job);
    Ok(code)
}

fn spawn_shim(console: &PseudoConsole, job: &OwnedHandle) -> Result<OwnedHandle> {
    let (application, mut command_line) = shim_command_line()?;

    let mut size = 0usize;
    // SAFETY: documented sizing call.
    unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
    let mut storage = vec![0usize; size.div_ceil(std::mem::size_of::<usize>()).max(1)];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = storage.as_mut_ptr().cast();
    // SAFETY: `storage` is pointer-aligned and at least `size` bytes.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        return Err(win32_error("InitializeProcThreadAttributeList"));
    }
    struct ListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for ListGuard {
        fn drop(&mut self) {
            // SAFETY: initialised above, deleted once.
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _guard = ListGuard(list);
    // SAFETY: the HPCON is passed by value as ConPTY documents.
    if unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            console.0 as *const c_void,
            std::mem::size_of::<HPCON>(),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(win32_error("UpdateProcThreadAttribute(PSEUDOCONSOLE)"));
    }

    // SAFETY: plain data; all-zero is valid.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb =
        u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(u32::MAX);
    startup.lpAttributeList = list;
    // Null standard handles: otherwise the shim inherits ours instead of the
    // pseudo console's.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;

    // SAFETY: plain data; all-zero is valid.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated buffers live for the call; no handles are
    // inherited; the environment and working directory are this process's.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
            null(),
            null(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(win32_error("CreateProcessW(console shim)"));
    }
    // SAFETY: CreateProcessW succeeded; both handles are ours.
    let (process, thread) = unsafe {
        (
            OwnedHandle::from_raw_handle(info.hProcess),
            OwnedHandle::from_raw_handle(info.hThread),
        )
    };
    // SAFETY: live job and process handles.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        let error = win32_error("AssignProcessToJobObject(console shim)");
        // SAFETY: the shim is still suspended.
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        return Err(error);
    }
    // SAFETY: live suspended thread.
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        return Err(win32_error("ResumeThread(console shim)"));
    }
    Ok(process)
}

/// Shim mode: attached to nono's pseudo console, launch the workload with
/// the console inherited and return its exit code.
pub(crate) fn run_shim(args: &RunArgs) -> Result<u32> {
    unsafe extern "system" fn survive(_ctrl_type: u32) -> windows_sys::core::BOOL {
        // Ctrl-C and Ctrl-Break are for the workload; the shim keeps waiting.
        1
    }
    // SAFETY: clears any inherited "ignore Ctrl-C" flag so the workload gets
    // default handling, then installs a handler (handlers are not inherited)
    // that keeps the shim alive.
    unsafe {
        SetConsoleCtrlHandler(None, 0);
        SetConsoleCtrlHandler(Some(survive), 1);
    }
    let plan = Plan::build(args, LaunchStdio::InheritConsole)?;
    let mut child = Sandbox::launch(&plan.caps, &plan.options)?;
    let code = child.wait()?;
    drop(child);
    super::explain_exit(code, plan.win32k_allowed);
    Ok(code)
}
