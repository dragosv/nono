# Proposal

## Why

nono has no enforcement on native Windows: `Sandbox::is_supported()` is
`false`, the library does not compile there (unconditional Unix IPC in
`supervisor/socket.rs`), and WSL2 does not cover projects on NTFS (issue
#2000, #1203). NEP-0005 (draft) proposes a persistent WFP SID-fence plus a
dedicated account and an elevated install. Windows 11 24H2+/25H2 now ships
ProcessContainer with a native PSEC/BaseContainer path that gives
per-container filesystem and network policy for host processes, with an
OS-managed lifetime and no nono-owned installer. In the issue #2000
discussion (2026-10-15), contributors proposed MXC/ProcessContainer as a
better direction and said NEP-0005 needs updating. No maintainer has
accepted it yet.

## What Changes

This change is phased. Phases 2–4 are **gated on maintainer acceptance of a
revised NEP-0005**: the NEP process requires acceptance before
implementation planning becomes implementation.

- **Phase 0 — validation spike (pre-NEP).** Prove on a compatible host
  that PSEC launch, filesystem grants and refusals, network block,
  proxy-only via `nono-proxy`, descendant inheritance, run separation and
  cleanup behave as required. Record the evidence and pin the schema version
  and reference commits.
- **Phase 1 — NEP-0005 revision.** Propose ProcessContainer/PSEC as the
  primary Windows mechanism. Distinguish legacy Windows, AppContainer and
  PSEC filesystem capabilities. Treat the elevated install as a property
  of the SRT mechanism, not of every Windows backend. Make launch and
  resource ownership an explicit library contract. Narrow the "no
  containers" non-goal so that it excludes VM/guest isolation but not
  ProcessContainer.
- **Phase 2 — Windows build and probing.** Make the `nono` library compile
  on Windows by gating Unix-only code (supervisor socket transport,
  `SCM_RIGHTS`, peer credentials and other `std::os::unix` users). Report
  Windows host capabilities affirmatively. Add Windows CI.
- **Phase 3 — library enforcement backend.** Add an **additive** library
  API that launches a process inside a PSEC container from a
  `CapabilitySet` and returns an owning handle (stdio, wait, terminate,
  cleanup). Map filesystem grants and network modes to native container
  policy. Fail secure whenever the PSEC path or a required capability is
  unavailable. The existing self-restriction API (`Sandbox::apply_auto`)
  is not given a Windows meaning.
- **Phase 4 — CLI and proxy.** Make `nono run` usable on Windows: Windows
  profile defaults, proxy-only through `nono-proxy` with per-session
  authentication, stdio and then ConPTY terminal support, cleanup,
  diagnostics, and an explicit "unavailable on Windows" error for features
  not ported (approvals/supervisor, tool sandboxing, detached sessions).

No change to Linux or macOS enforcement, capability semantics, or the
profile format on those platforms. Nothing in this change is **BREAKING**:
the launch API is additive.

**Out of scope:** the devcroft runtime port and the Windows environment
provider (Pixi), which consume this backend downstream and are planned in
devcroft. Also out of scope: an AppContainer/LPAC fallback, the SRT model
(dedicated account, restricted token, ACLs, persistent WFP), Windows
Sandbox/Hyper-V, and the advanced CLI features beyond a clear refusal.

## Capabilities

### New Capabilities

- `sandboxed-process-launch`: library contract for launching a process
  already confined by a `CapabilitySet` and owning its lifetime (handles,
  stdio, wait, terminate, cleanup), distinct from in-process
  self-restriction.
- `windows-host-support`: Windows support detection, required-mechanism
  gating (PSEC only, no silent fallback), refusal before the workload
  runs, and reporting of library features unavailable on Windows.
- `windows-filesystem-enforcement`: mapping of read, read-write and deny
  policy to native container policy, Windows path normalization, and
  confinement of descendants.
- `windows-network-enforcement`: blocked and proxy-only network modes for
  Windows workloads, isolation between concurrent runs, and no impact on
  ordinary host processes.
- `windows-cli-run`: `nono run` on Windows, covering profile defaults,
  proxy startup and authentication, stdio/terminal, cleanup, diagnostics
  and explicit refusal of unported features.

### Modified Capabilities

None. `openspec/specs/` holds no existing capabilities. Linux/macOS
behavior is unchanged.

## Impact

- **Library (`crates/nono`)**: new `sandbox/windows.rs` module. The
  launch API is new public surface. `cfg` gating in `lib.rs`,
  `supervisor/`, and the other modules that use `std::os::unix`/`libc`
  (`audit`, `broker_path`, `capability`, `keystore`, `path`, `query`,
  `state`, `trust/policy`, `undo/*`). PSEC is called directly through
  `windows-sys` (`processmodel.dll` exports) with vendored, MIT-licensed
  PSEC FlatBuffer bindings. The only new dependency is `flatbuffers`. No
  `mxc-sdk` dependency (spike §1.11).
- **CLI (`crates/nono-cli`)**: the execution path is fork-based
  (`exec_strategy.rs` uses `nix` unconditionally) and needs a Windows
  launch strategy. `pty_proxy.rs` needs a ConPTY counterpart. Profiles and
  protected paths need Windows defaults.
- **Proxy (`crates/nono-proxy`)**: works as-is at the application layer.
  The Unix-only bits (`route.rs`, `oauth_capture/persist.rs`,
  `tls_intercept/bundle.rs`) need gating. The existing per-session
  `nono:<token>@127.0.0.1` authentication is reused.
- **C bindings (`bindings/c`)**: exposing the launch API through FFI is
  deferred. `nono.h` changes only if the bindings change.
- **CI**: new Windows jobs. Enforcement tests must run on a host qualified
  for PSEC and must not count as passing when skipped.
- **Docs/governance**: NEP-0005 revision, a new
  `docs/cli/internals/windows.mdx`, and Windows notes in
  `security-model.mdx`.
- **Downstream**: devcroft (pinned to nono 0.77.0) can consume the library
  backend once Phase 3 lands, without waiting for full CLI parity.
