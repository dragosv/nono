# Design

## Context

See `proposal.md` (Why) for motivation, and the specs for required
behavior. This section covers only the current state that shapes the
approach.

- **Self-restriction API.** `Sandbox::apply_auto(&caps)` restricts the
  calling process. Descendants inherit through Landlock or Seatbelt.
  Windows has no equivalent for restricting the current process with a path
  ruleset. PSEC instead *creates* a process inside a container. The
  Windows backend is therefore launch-shaped, not apply-shaped.
- **Windows build is blocked.** `lib.rs` exports `supervisor`
  unconditionally. `supervisor/socket.rs` imports `std::os::unix::{io,
  net}` and uses `SCM_RIGHTS`, `SO_PEERCRED`/`getpeereid` and
  `PermissionsExt`. Other library modules also use `std::os::unix`/`libc`:
  `audit`, `broker_path`, `capability`, `keystore`, `path`, `query`,
  `state`, `trust/policy`, `undo/{merkle,object_store,snapshot}`.
  `libc` is an unconditional dependency.
- **The CLI is fork-based.** `exec_strategy.rs` (~6.5k lines) uses `nix`
  `fork`, `waitpid` and signals unconditionally. `pty_proxy.rs` is
  `openpty`-based. `main.rs` already gates `connect_client`,
  `hook_runtime` and `remote_run` with `#[cfg(unix)]`. Some
  `not(linux|macos)` fallbacks exist in `execution_runtime.rs` and
  `capability_ext.rs`.
- **No explicit deny paths in `CapabilitySet`.** It holds grants only
  (`fs: Vec<FsCapability>`). Denies are expressed on macOS via Seatbelt
  `platform_rules` and on Linux by not granting. Windows deny paths must
  therefore be an explicit launch input supplied by the CLI.
- **The proxy already authenticates sessions.** `nono-proxy` binds
  `127.0.0.1:0` and issues `http://nono:<token>@127.0.0.1:<port>`.
- **CI has no Windows.** The matrix is `ubuntu-latest` and `macos-latest`.
  The analysis host is Windows 11 build 26300 on arm64. Microsoft lists
  Process Isolation support from 24H2 26100.9278 and 25H2 26200.9278. These
  are reference points, not a substitute for probing.
- **Governance.** NEP-0005 is `draft` and describes the SRT model. Under
  the NEP process, implementation waits for an accepted NEP.

## Goals / Non-Goals

**Goals:**
- A single mechanism (PSEC) with fail-secure gating, so that "nono
  sandboxed this process" means the same set of guarantees on every
  supported Windows host.
- A library API usable by downstream consumers (devcroft) before the
  CLI reaches parity.
- Keep the library/CLI boundary: the library translates and enforces; the
  CLI owns defaults, deny lists, proxy lifecycle and UX.

**Non-Goals:**
- Implementing the launch API on Linux or macOS in this change. Its shape
  stays platform-neutral so it can be added later.
- C FFI for the launch API.
- Supervisor IPC on Windows (named pipes, handle duplication), runtime
  approvals, tool sandboxing, detached sessions, rollback.
- Per-port ingress, `bind_ports`, `localhost_ports`/ranges, and
  `tcp_connect_ports` on Windows. All of these are refused.
- Network shares (UNC) as grant targets.

## Decisions

### D1. PSEC/BaseContainer is the only v1 mechanism
Use the native PSEC path (`CreateProcessSecurityEnvironment`-backed
BaseContainer) for both filesystem and network.

Alternatives considered:
- **AppContainer/LPAC fallback.** It has a different grant model (ACLs on
  host objects, capability SIDs) and its own registry and COM breakage.
  Supporting it would double the enforcement surface and the guarantees.
  A fallback would need its own design and probes.
- **SRT model (account + restricted token + ACLs + persistent WFP).**
  Requires an elevated install, stored credentials and machine state, and
  breaks nono's per-invocation, no-persistent-state model.
- **Restricted token + Job Objects alone.** They express no
  filesystem/network path policy.
- **Windows Sandbox/Hyper-V.** These run a guest, not host processes.

### D2. Direct FFI to `processmodel.dll` with a vendored PSEC schema (no `mxc-sdk` dependency)
`sandbox/windows.rs` calls the OS directly through `windows-sys`:
1. Load `processmodel.dll` with `LOAD_LIBRARY_SEARCH_SYSTEM32` and resolve
   these exports:
   - `CreateProcessSecurityEnvironment`
   - `QueryProcessSecurityEnvironmentSupport`
   - `IsProcessSecurityEnvironmentVersionSupported`
   - `CloseProcessSecurityEnvironment`
2. Encode the policy as a "PSEC" FlatBuffer.
3. Attach the environment to `CreateProcessW` through
   `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` (`35 | 0x20000`).

The generated FlatBuffer bindings (flatc 25.12.19) are vendored from MXC
v1.0.1 under MIT, with a provenance file. The schema sha256 and the flatc
version are pinned, and a CI drift check compares them against MXC
releases. The only new dependency is `flatbuffers`; `windows-sys` 0.61.2 is
already in the lockfile. Spike §1.11 showed that this path behaves the
same as the SDK path for filesystem, network, cleanup and environment.

Alternatives considered:
- **`mxc-sdk` crate** (spike §1.2, §1.10). It pulls in about 100 transitive
  crates and includes telemetry. Its typed API cannot forbid the
  AppContainer + host-DACL fallback, so PSEC-only needs a
  `#[doc(hidden)]` JSON entry point. It also does not support PTY for
  processcontainer.
- **Hand-written FlatBuffer encoder.** Possible, but the vendored
  generated code is reviewable and drift-checkable.

Trade-off: nono owns tracking the OS contract (schema minor versions,
support flags). The schema is not yet in the public Windows SDK. Task 2.0
asks Microsoft to publish it. Codex's MXC integration is a reference
implementation only.

### D3. Additive launch API; `apply_auto` is not compiled on Windows
Add a public, platform-neutral type family, with names to be finalized in
review:

```text
Sandbox::launch(&CapabilitySet, &LaunchOptions, Command) -> Result<SandboxedChild>
LaunchOptions { deny_paths, stdio, inherit_handles, env (exact, no implicit inheritance), cwd }
SandboxedChild { stdin/stdout/stderr, wait(), try_wait(), terminate(), Drop = terminate + release }
Sandbox::render_launch_policy(&CapabilitySet, &LaunchOptions) -> Result<RenderedPolicy>
```

In this change, `launch` and `render_launch_policy` are compiled only for
`target_os = "windows"`. `Sandbox::apply_auto` and the other
self-restriction functions are not compiled for Windows. Callers get a
compile error, not a misleading success.
`is_supported()`/`support_info()` gain a Windows branch backed by D5.
`SupportInfo` gains an optional per-feature map. The map is additive, and
the existing fields keep their meaning.

Alternatives considered:
- **`apply_auto` returns `Ok` on Windows and the confinement happens at
  the next spawn.** Rejected: it violates the meaning of "the caller is
  sandboxed" (spec: Self-restriction is not emulated).
- **Return the launch result from `apply_auto`.** Rejected: it gives one
  name two meanings across platforms.

### D4. PSEC-only by construction
The direct path (D2) has no AppContainer or DACL fallback code at all. A
launch either creates a PSEC environment and attaches it to `CreateProcessW`,
or it returns an error. Any of these makes it fail:
- a missing `processmodel.dll`
- a missing export
- no support for schema major version 1
- a failing `CreateProcessSecurityEnvironment` HRESULT
- a failing `CreateProcessW` with the attribute

The process is created suspended. It is assigned to the job and then
resumed, so no workload instruction runs before both are in place. The
support probe (D5) is informational and is never consulted as proof at
launch.

### D5. Affirmative probing
The probe creates a throwaway PSEC container running a no-op process and
confirms the mechanism. It then queries each optional feature that
`SupportInfo` lists: deny paths, enumerate-without-read, egress filtering
and the proxy path. Results are cached per process for reporting only.
A host build number is reported as context and is never used as the gate.
The probe also records whether a volume-root grant cascades. The MXC docs
say it does not, but on build 26300 it did. Volume-root grants are refused
unless the probe confirms that they cascade. The probe uses
`IsProcessSecurityEnvironmentVersionSupported(1)` (minor version) and
`QueryProcessSecurityEnvironmentSupport` (flags: `0x1` deny, `0x4`
enumerate, `0x8` ingress).

### D6. Capability mapping
| `CapabilitySet` / options | Windows v1 |
|---|---|
| `FsCapability{access: Read}` | read-only path (file or recursive dir per `is_file`) |
| `FsCapability{access: ReadWrite}` | read-write path |
| `FsCapability{access: Write}` | launch error. The PSEC schema has no write-only mode (spike §1.9), and the grant is never widened to read-write |
| `LaunchOptions.deny_paths` | native deny path; launch error if the host lacks it |
| `NetworkMode::Blocked` | deny all egress (v4/v6, TCP/UDP) |
| `NetworkMode::ProxyOnly{port, bind_ports: []}` | egress only to `127.0.0.1:port` / `[::1]:port` |
| `ProxyOnly{bind_ports: non-empty}`, `tcp_*_ports`, `localhost_port(s/ranges)` | launch error |
| `NetworkMode::AllowAll` | no network restriction |
| `unix_sockets`, non-default `signal_mode` / `process_info_mode` / `ipc_mode`, `platform_rules`, `extensions_enabled` | launch error naming the field |
| `allowed_commands` / `blocked_commands` | CLI-level as today, not backend-enforced |

The rule is that every field must be either faithfully enforced or
rejected. Grants are rejected too, not silently dropped, so that profile
divergence is visible.

### D7. Windows path normalization lives in the library
A new `path::windows` module opens each grant with
`FILE_FLAG_BACKUP_SEMANTICS` and takes `GetFinalPathNameByHandleW`
(normalized, DOS form). This resolves reparse points, 8.3 names and case.
The path is then reduced to `\\?\X:\...` for the native policy and `X:\...`
for display. It rejects drive-relative paths, UNC, `\\.\` device paths,
and any component containing `:` after the drive (ADS). Comparison uses
`Path` components with case-insensitive matching on volumes reported as
case-insensitive. Directories flagged case-sensitive are compared exactly.
Paths that do not exist are rejected at the boundary. The CLI keeps its
existing "skip missing optional path" behavior above this layer.

### D8. Process tree ownership: container plus a kill-on-close Job Object
The process is created suspended and assigned to a Job Object with
`KILL_ON_JOB_CLOSE`, with breakaway disallowed, before it is resumed.
`SandboxedChild` owns the job handle, the container context and the stdio
handles. `terminate()` and `Drop` close the job first (tree kill) and then
release the container. If the spike shows the container already gives
equivalent tree semantics, the job stays as defense in depth unless it
conflicts with the container.

The command line is built with the same quoting rules as Rust `std`
(`CommandLineToArgvW`-compatible). It refuses arguments that cannot be
safely escaped for `.bat`/`.cmd` targets (the BatBadBut class). A program
file name that Windows would reinterpret (trailing dot or space, or a
`name:stream` data stream) is refused, because `run.bat.` runs as a batch
file while its extension reads as empty (CVE-2024-43402). NUL in an
argument is an error. The environment block is exactly
`LaunchOptions.env`.

Child-side standard handles are created non-inheritable and made
inheritable only around `CreateProcessW`, then closed at once. This keeps a
concurrent `CreateProcess` in a multithreaded caller from inheriting them,
apart from that short window.

The job also carries every `JOB_OBJECT_UILIMIT_*` flag. PSEC confines win32k
only by switching it off, so with win32k allowed the job denies the
clipboard, global atoms, other processes' windows and desktop or system
settings. `ResourceLimits.memory_bytes` maps to the job's committed-memory
limit; allocations beyond it fail and the tree is not killed. The rendered
policy shows this. `ResourceLimits.max_processes` is refused: a job counts
processes, not threads, so it cannot enforce the documented limit.

### D9. Proxy on Windows: host `nono-proxy` via the PSEC proxy form
`nono-proxy` runs unconfined on the host, as it does today. The spec uses
the PSEC proxy form only:
- `network_policy.proxy.url = http://127.0.0.1:<port>`
- no egress table
- capabilities `privateNetworkClientServer,networkLoopback`
- `allowed_appcontainer_peer = "MXC-Loopback"` (identity-less loopback proxy)

Spike §1.6 and §1.11 showed that this is the only form that scopes loopback
egress to a single endpoint. Host-loopback allow without a proxy URL opens
every host loopback port, and egress allow rules do not narrow it. That
form is never emitted.

System resolver lookups stay available in proxy mode. They are rendered in
the policy, and a DNS-block request is refused (spec: System resolver
exposure is explicit).

Session authentication reuses the existing proxy token. Each run gets its
own proxy port and its own environment. The spike showed that concurrent
runs stay separated.

### D10. Terminal: nono-owned ConPTY plus an unconfined console shim
Spike §1.11 found that putting `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` next
to the security environment does not attach the child. A PSEC child does,
however, inherit its parent's console normally. Interactive runs therefore
use this chain:

```text
nono (user terminal) ──ConPTY──▶ nono --console-shim (unconfined, attached to the ConPTY)
                                   └──CreateProcessW+PSEC, console inherited──▶ workload
```

The spike verified output, resize (80x25 → 120x40 seen by the child) and
Ctrl-C (`0xC000013A` within about 5 ms) through this chain. The shim:
- clears the inherited "ignore Ctrl-C" flag
- propagates the exit code
- dies with the job

The workload is **never** attached to the user's own console. A shared
console input buffer would let it inject keystrokes (`WriteConsoleInput`)
into the user's shell after exit, the Windows TIOCSTI analogue. Piped
(non-interactive) runs use pipes and a handle list, with no console
inheritance.

### D10a. Environment, temp directory and win32k
- **Environment.** The library passes an explicit environment block (D3),
  so nothing from the launcher leaks. `CreateProcessW` under PSEC fails
  with Win32 error 203 unless `SYSTEMROOT` and `LOCALAPPDATA` are present.
  Only their presence is checked. The CLI always supplies both. The library
  validates this and returns an error naming the missing variables.
- **Temp directory.** The CLI creates a per-run temp directory, grants it
  read-write, and sets `TEMP`/`TMP`.
- **win32k.** `disallow_win32k_system_calls = true` makes every
  user32-loading binary fail with `0xC0000142`, including `cmd.exe` under a
  console and `mode.com`. The library exposes this as an explicit launch
  option, off by default for least privilege. CLI profiles turn win32k on
  for shells and toolchains that need it. The rendered policy shows the
  setting.
- **Ancestor enumeration.** `cmd.exe` can start an exe by absolute path
  only if every ancestor, volume root included, has an `fs_enumerate` grant
  (PSEC 1.1). Starting it by name from the working directory needs none.
  Enumerate never grants content reads. On an ordinary directory it does
  not even allow listing that directory. On a volume root, however, it
  cascades (build 26300, integration §1.12): the workload can list the name
  of every file on the volume. The CLI therefore does **not** add ancestor
  enumeration by default. It is opt-in (`--enumerate-ancestors`), and the
  rendered policy warns when a volume root is enumerated. A regression test
  pins the observed behavior. On a PSEC 1.0 host the flag is refused.
- **Piped runs get a private hidden console.** Piped and null-stdio launches
  pass `CREATE_NO_WINDOW`, so the workload has its own console and never
  the caller's. `cmd.exe` then runs without win32k. Only `InheritConsole`
  (used by the console shim) shares a console.
- **Verbatim paths.** Canonical paths come back as `\\?\X:\...`. `cmd.exe`
  treats such a working directory as UNC and falls back to `C:\Windows`.
  The library converts the program path and working directory to `X:\...`
  before `CreateProcessW`.

### D11. Unix-only library code is gated, not ported
`supervisor::socket` and its re-exports (`SupervisorListener`,
`SupervisorSocket`) become `#[cfg(unix)]`. `supervisor::types` and the
`ApprovalBackend` trait stay cross-platform. In the other modules,
permission-bit code is gated. On Windows, nono state files live under
`%LOCALAPPDATA%`, which carries a per-user ACL. This is documented as the
owner-only equivalent. `libc` moves to `[target.'cfg(unix)'.dependencies]`.
`keyring` gets a `windows-native` target feature.

### D12. CI: build everywhere, enforce only on qualified hosts
- `windows-latest` (x86_64-pc-windows-msvc): build, clippy, and unit tests
  for the library and proxy, then the CLI once it compiles. This job also
  build-checks `aarch64-pc-windows-msvc`.
- A qualified host job (Windows 11 24H2+ with PSEC) runs the enforcement
  suite. That suite sets `NONO_REQUIRE_ENFORCEMENT=1`, which turns every
  "capability unavailable" skip into a failure. A run where every
  enforcement test is skipped therefore fails.

## Risks / Trade-offs

- **[NEP not accepted or redirected]** → Phases 0–1 are designed to be
  useful either way (evidence plus NEP text). No library code merges
  before acceptance.
- **[The vendored PSEC schema drifts from the OS contract]** → The schema
  sha256 and flatc version are pinned, a CI drift check runs against MXC
  releases, and the schema minor version is negotiated through
  `IsProcessSecurityEnvironmentVersionSupported`. A spec the OS rejects
  fails the launch. It never degrades.
- **[Console input injection through a shared console]** → The workload
  never gets the user's console. Interactive runs go through a nono-owned
  ConPTY and the console shim (D10). A dedicated probe for
  `WriteConsoleInput` into the parent console is added to the enforcement
  suite.
- **[The host-loopback compatibility path permits more than one endpoint,
  or bidirectional loopback]** → The spike tests other-port and ingress
  cases. Otherwise proxy-only is refused (D9). Users still get blocked
  mode.
- **[Implicit system grants are broader than on Linux/macOS]** → They are
  enumerated, rendered in `RenderedPolicy` and documented in `windows.mdx`.
  Any grant beyond the backend's documented minimum is a CLI default, not
  a library default.
- **[Junction swapped between canonicalization and access (TOCTOU)]** →
  Enforcement happens in the OS at access time, keyed on the canonical
  target. Grants pointing into agent-writable trees are not resolved
  further. The spike tests a swap scenario.
- **[Parent-directory marker searches (git, node) get ACCESS_DENIED
  outside grants]** → Read-only enumerate-without-read grants are used on
  ancestors where the host supports them. Otherwise the CLI documents the
  limitation and the profile must grant explicitly.
- **[Volume-root cascade differs by build]** → The MXC docs say a
  volume-root grant does not cascade, but on build 26300 it did (spike
  §1.3). It is refused unless the probe confirms cascading. The error
  suggests granting subdirectories. The CLI never grants a volume root by
  default.
- **[The DNS exfiltration channel in proxy-only mode]** → System resolver
  lookups stay available (spike §1.6), just as macOS proxy-only does by
  default. They are rendered explicitly. A DNS-block request is refused
  instead of silently ignored.
- **[SeLs lowbox leak per environment (microsoft/mxc#1486)]** → One-shot
  `nono run` is unaffected in practice. Long-lived consumers (devcroft) must
  track the upstream fix.
- **[No qualified CI host is available upstream]** → Build-only CI lands
  first. Enforcement merges stay blocked until a qualified runner exists.
  A green build-only run is not presented as validation.
- **[Tooling breakage from DLL, registry or temp directory access]** →
  Phase 4 qualifies PowerShell, Git for Windows, Node and Python against
  the default profile before CLI support is announced.
- **[State files on Windows use inherited ACLs instead of 0600]** → They
  are limited to `%LOCALAPPDATA%\nono`. The CLI verifies at startup that
  the directory's ACL grants no access beyond the user, SYSTEM and
  Administrators, and errors otherwise.

## Migration Plan

Windows support did not exist before, so no user migration is needed and
Linux/macOS are unchanged. Delivery follows `tasks.md` phases and PR
boundaries:
1. Spike and NEP revision. No product code merges.
2. PR 1: Windows build plus probing plus CI (library only).
3. PR 2: library launch API and enforcement, released as an experimental
   platform.
4. PR 3: CLI and proxy.

Rollback means reverting the Windows `cfg` modules. Because the API is
additive, no consumer on other platforms is affected. The C header is
untouched.

## Open Questions

- Who provides and operates the qualified Windows CI host: a self-hosted
  runner, or a hosted image once one ships a PSEC-capable build? D12
  defines the gate either way.
- Final public names for `launch`, `LaunchOptions`, `SandboxedChild` and
  `RenderedPolicy`. To be settled in API review. The shape is fixed by D3.
- Whether `nono-cli` also exposes a lower-level `nono wrap`-style entry
  point on Windows. This does not change the library work.
