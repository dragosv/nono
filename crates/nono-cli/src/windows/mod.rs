//! `nono` on native Windows.
//!
//! A deliberately small front end over the library's PSEC launch backend
//! (`nono::Sandbox::launch`). Flags keep the Unix CLI's names where the
//! meaning is the same. Features that are not ported (profiles, supervisor
//! approvals, sessions, rollback, tool sandboxing) are not accepted: clap
//! rejects their flags instead of ignoring them.
//!
//! Interactive runs use a nono-owned pseudo console and an unconfined console
//! shim (`console.rs`); the workload never shares the user's console.

#[path = "../exec_strategy/env_sanitization.rs"]
#[allow(dead_code)]
mod env_sanitization;

mod console;
mod plan;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Hidden first argument that selects console-shim mode (see `console.rs`).
pub(crate) const CONSOLE_SHIM_ARG: &str = "__console-shim";

#[derive(Parser, Debug)]
#[command(
    name = "nono",
    version,
    about = "Capability-based sandbox for AI agents (native Windows, Windows ProcessContainer)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a command inside the sandbox
    Run(Box<RunArgs>),
    /// Check host support
    Setup(SetupArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub(crate) struct RunArgs {
    /// Allow read+write access to a directory (recursive)
    #[arg(long, short = 'a', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub(crate) allow: Vec<PathBuf>,
    /// Allow read-only access to a directory (recursive)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub(crate) read: Vec<PathBuf>,
    /// Write-only access is not available on Windows
    #[arg(
        long,
        short = 'w',
        value_name = "DIR",
        help_heading = "FILESYSTEM",
        hide = true
    )]
    pub(crate) write: Vec<PathBuf>,
    /// Allow read+write access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub(crate) allow_file: Vec<PathBuf>,
    /// Allow read-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub(crate) read_file: Vec<PathBuf>,
    /// Write-only access is not available on Windows
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM", hide = true)]
    pub(crate) write_file: Vec<PathBuf>,
    /// Deny a path inside a granted directory (Windows)
    #[arg(long, value_name = "PATH", help_heading = "FILESYSTEM")]
    pub(crate) deny: Vec<PathBuf>,
    /// Allow read-only access to the current directory
    #[arg(long, help_heading = "FILESYSTEM")]
    pub(crate) allow_cwd: bool,
    /// Block all network access, including system DNS lookups
    #[arg(long = "block-net", conflicts_with_all = ["allow_net", "allow_domain", "deny_domain"], help_heading = "NETWORK")]
    pub(crate) block_net: bool,
    /// Deprecated compatibility flag. Network is unrestricted by default.
    #[arg(long = "allow-net", hide = true, help_heading = "NETWORK")]
    pub(crate) allow_net: bool,
    /// Route traffic through nono's filtering proxy and allow this domain
    /// (repeatable)
    #[arg(long = "allow-domain", value_name = "DOMAIN", help_heading = "NETWORK")]
    pub(crate) allow_domain: Vec<String>,
    /// Route traffic through nono's filtering proxy and block this domain
    /// (repeatable)
    #[arg(
        long = "deny-domain",
        value_name = "DOMAIN",
        conflicts_with = "allow_net",
        help_heading = "NETWORK"
    )]
    pub(crate) deny_domain: Vec<String>,
    /// Permit win32k (user32/gdi32) system calls. Needed by programs that
    /// load user32 (Windows)
    #[arg(long, help_heading = "WINDOWS")]
    pub(crate) allow_win32k: bool,
    /// Grant enumerate on every ancestor of the program, the working
    /// directory and each grant, volume root included. A volume-root grant
    /// exposes the names (not contents) of every file on that volume. cmd.exe
    /// needs it to start a program by absolute path (Windows)
    #[arg(long, help_heading = "WINDOWS")]
    pub(crate) enumerate_ancestors: bool,
    /// Show the policy that would be applied, then exit
    #[arg(long, help_heading = "OPTIONS")]
    pub(crate) dry_run: bool,
    /// Command to run, with its arguments
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    pub(crate) command: Vec<std::ffi::OsString>,
}

#[derive(Args, Debug)]
struct SetupArgs {
    /// Only report host support; change nothing
    #[arg(long)]
    check_only: bool,
}

pub(crate) fn main() {
    let mut raw: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let shim = raw.get(1).is_some_and(|a| a == CONSOLE_SHIM_ARG);
    if shim {
        raw.remove(1);
    }
    let cli = Cli::parse_from(raw);
    let code = match cli.command {
        Command::Run(args) if shim => console::run_shim(&args),
        Command::Run(args) => run(&args),
        Command::Setup(args) => {
            setup(&args);
            Ok(0)
        }
    };
    match code {
        Ok(code) => std::process::exit(exit_code(code)),
        Err(e) => {
            eprintln!("nono: {e}");
            std::process::exit(1);
        }
    }
}

fn run(args: &RunArgs) -> nono::Result<u32> {
    if args.dry_run {
        let plan = plan::Plan::build(args, nono::LaunchStdio::Null)?;
        println!("{}", plan.describe()?);
        return Ok(0);
    }
    if console::is_interactive() {
        console::run_interactive()
    } else {
        plan::run_piped(args)
    }
}

fn setup(args: &SetupArgs) {
    let _ = args.check_only;
    let support = nono::Sandbox::windows_support();
    let yes_no = |b: bool| if b { "available" } else { "unavailable" };
    println!("platform:        windows");
    match &support.unavailable_reason {
        Some(reason) => {
            println!("mechanism:       Windows ProcessContainer (PSEC): unavailable");
            println!("reason:          {reason}");
        }
        None => {
            println!(
                "mechanism:       Windows ProcessContainer (PSEC) 1.{}",
                support.schema_minor.unwrap_or(0)
            );
            println!("deny paths:      {}", yes_no(support.fs_deny));
            println!("enumerate-only:  {}", yes_no(support.fs_enumerate));
            println!("inbound policy:  {}", yes_no(support.network_ingress));
            println!("feature flags:   0x{:x}", support.feature_flags);
        }
    }
    println!(
        "not ported:      profiles, supervisor approvals, sessions, rollback, tool sandboxing"
    );
}

/// Windows exit codes are 32-bit; `std::process::exit` takes the same bits.
fn exit_code(code: u32) -> i32 {
    i32::from_ne_bytes(code.to_ne_bytes())
}

/// Hint for the most common failure under the default win32k restriction.
pub(crate) fn explain_exit(code: u32, win32k_allowed: bool) {
    const STATUS_DLL_INIT_FAILED: u32 = 0xC000_0142;
    if code == STATUS_DLL_INIT_FAILED && !win32k_allowed {
        eprintln!(
            "nono: the program failed to initialise (0xC0000142). It probably loads user32; rerun with --allow-win32k."
        );
    }
}
