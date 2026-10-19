# Tasks

> Gate: groups 1–2 may proceed now. Groups 3 and later must not merge
> upstream until NEP-0005 (revised) has `status: accepted` (task 2.4).
> Enforcement tests in groups 5–8 and 13 count only when run on a qualified
> PSEC host with `NONO_REQUIRE_ENFORCEMENT=1` (design D12).
>
> Local implementation status (2026-10-19, branch `spike/windows-psec`,
> pre-NEP, not for merge; see spike-report §1.12). Checked boxes are fully
> verified on build 26300 arm64. Partially done, still unchecked:
> 3.2 (library builds on Windows; `libc` not yet moved to `cfg(unix)`; Linux
> and macOS `make ci` not run), 3.4 (vendored with NOTICE and license; no
> drift check), 3.5 (loader and probe; no internal trait or mock), 3.6
> (`apply_auto` absent on Windows; no `compile_fail` doctest), 5.1 (API
> exists and `cargo doc` builds; no doctest), 5.3 (suspended, job, resume;
> no non-PSEC host test), 5.4 (no unlisted-handle test), 6.1–6.3 and
> 7.1–7.2 (mapping, rejection and rendering implemented and tested), 8.1
> (`crates/nono/tests/windows_launch.rs`, 14 tests), 9.1 (`nono-proxy`
> builds on Windows; its tests not run), 10.1–10.4 (a separate Windows front
> end instead of gating each Unix module; proxy, exit status, interrupt and
> cleanup work), 11.2a (win32k is a flag; ancestor enumeration is opt-in
> because a volume-root grant exposes every file name), 12.1 (ConPTY plus
> shim works; no automated resize or Ctrl-C test), 13.1 (no build number).

## 1. Phase 0 — validation spike (throwaway branch, not merged)

- [x] 1.1 Record the spike host (Windows edition, build, arch, PSEC availability) and pin the MXC Rust SDK version and the reference commits (MXC, Codex integration) in `openspec/changes/add-windows-processcontainer-backend/spike-report.md`; verify the report lists exact versions and hashes
- [ ] 1.2 Launch a process via the SDK requesting PSEC and confirm the selected mechanism is PSEC (design D4); verify by also running on a host without PSEC and showing that launch fails rather than falling back, with the outcome recorded in the report
  - Partial (spike-report §1.2): PSEC-only is guaranteed structurally (JSON contract + `allowDaclMutation: false` + default features); still open: run the refusal case on a host without PSEC.
  - Direct FFI (§1.11): no fallback code path exists. A missing DLL, export or schema version, or a failing HRESULT, is an error. Still open: observe this on a host without PSEC.
- [x] 1.3 Prove filesystem semantics: a read-write grant allows writes, a read grant refuses writes, an ungranted path refuses reads, a single-file grant excludes its sibling, a deny path inside a read-write grant is denied, whether a volume-root grant cascades is recorded, and a junction to an ungranted target is denied; verify each case with a probe binary and record the result
- [x] 1.4 Prove that a child and a grandchild keep the filesystem and network restrictions; verify with a probe that spawns two levels deep
- [x] 1.5 Prove blocked mode: TCP and UDP over IPv4 and IPv6, plus DNS, refused; verify with probe output for each protocol and address family
- [x] 1.6 Prove proxy-only with a host `nono-proxy` through the host-loopback compatibility path: the proxy port is reachable, other loopback ports and direct egress are refused, an allowed domain passes, a disallowed domain is refused, and the host can still reach other listeners; record whether egress can be scoped to a single endpoint and whether ingress is opened (design D9)
  - §1.6: endpoint scoping in PSEC proxy form; other ports and direct egress refused; no ingress; system-resolver DNS leak found.
  - Closed in §1.12: with the real `nono-proxy`, an allowed domain passes, a disallowed one gets 403 from the proxy, and a direct connection bypassing the proxy is refused by PSEC.
- [x] 1.7 Prove two concurrent containers with different proxy endpoints cannot reach each other's proxy, and that an unconfined host process keeps full network access during a run; verify by recorded probe output
- [ ] 1.8 Prove cleanup: on exit, timeout, interrupt and launch failure, no container, process or network rule remains, including when the launching process is killed; verify by enumerating processes and network policy after each case
  - Partial (§1.8): processes gone in every case; still open: WFP filter enumeration after abnormal exit (needs elevation).
- [x] 1.9 Test ConPTY attachment to a PSEC-created process (resize, Ctrl-C) and write-only (`AccessMode::Write`) expressibility; record feasible or infeasible for each
- [x] 1.10 Decide SDK versus direct FFI against the design D2 triggers (backend reporting, public surface, dependency cost measured as crate count, build time and binary size); verify the decision and its evidence are in the report
  - Revised (§1.11, user direction): direct FFI. A working spike in `spikes/windows-psec-direct/` matches the SDK results with 4 crates.

## 2. Phase 1 — NEP-0005 revision

- [ ] 2.0 Ask Microsoft (Windows SDK feedback or a microsoft/mxc issue) to publish `ProcessSecurityEnvironment.fbs` and the `processmodel.dll` PSEC exports in the public Windows SDK, and to document `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` with a security environment; verify the links are recorded in spike-report.md
- [ ] 2.1 Comment on issue #2000 with the spike summary and intent to revise NEP-0005, disclosing agent assistance; verify the comment links the spike report
- [ ] 2.2 Draft the NEP-0005 revision: PSEC as the primary mechanism; the legacy Windows, AppContainer and PSEC filesystem capabilities distinguished; elevated install described as a consequence of the SRT mechanism; the launch and ownership library contract; the "no containers" non-goal narrowed to VM/guest isolation; Security Considerations updated; pinned schema hash, flatc version and MXC commit; verify it renders and follows `neps/NEP-template.md`
- [ ] 2.3 Open the NEP PR (DCO sign-off, PR template, agent disclosure, link to #2000); verify CI and PR lint pass
- [ ] 2.4 Obtain maintainer acceptance (`status: accepted`) and fold any review changes back into `proposal.md`, `design.md` and the specs; verify `openspec validate add-windows-processcontainer-backend --strict` passes after the update

## 3. PR 1 — Windows library build and probing

- [x] 3.1 Gate `supervisor::socket` and the `SupervisorListener`/`SupervisorSocket` re-exports with `#[cfg(unix)]`, keeping `supervisor::types` and `ApprovalBackend` cross-platform; verify `cargo check -p nono --target x86_64-pc-windows-msvc` gets past `supervisor`
- [ ] 3.2 Gate the `std::os::unix`/`libc` uses in `audit`, `broker_path`, `capability`, `keystore`, `path`, `query`, `state`, `trust/policy` and `undo/{merkle,object_store,snapshot}`, and move `libc` to `cfg(unix)` dependencies; verify `cargo check -p nono` succeeds on Windows and `make ci` stays green on Linux and macOS
- [ ] 3.3 Add the `keyring` `windows-native` target feature; verify the keystore unit tests pass on Windows
- [ ] 3.4 Vendor the generated PSEC FlatBuffer bindings with a provenance/NOTICE file and pinned schema sha256 and flatc version, and add a CI drift check against MXC releases (design D2); verify the drift check fails on a modified schema
- [ ] 3.5 Add `sandbox/windows.rs` with the `processmodel.dll` loader (System32-only search, four exports, an error on any missing export) behind an internal trait, and the affirmative probe (version 1 minor plus support flags, design D5), and give `is_supported()`/`support_info()` a Windows branch plus the additive per-feature map; verify unit tests cover supported, unsupported and partial-feature reports via a mock adaptor
- [ ] 3.6 Make self-restriction functions uncompiled on Windows (design D3); verify with a `compile_fail` doctest gated to Windows
- [ ] 3.7 Add a `windows-latest` CI job (build, clippy, `nono` unit tests) and an `aarch64-pc-windows-msvc` build check; verify the jobs run green on the PR
- [ ] 3.8 Document Windows build prerequisites and the support-probe semantics in `docs/cli/internals/windows.mdx`; verify the docs lint (`tests/lint_docs.rs`) passes

## 4. PR 2 — Windows path normalization

- [ ] 4.1 Implement `path::windows` canonicalization (design D7): final-path resolution, `\\?\` and display forms, case handling per volume and directory; verify unit tests for 8.3 names, case variants, and junction and symlink resolution
- [ ] 4.2 Reject drive-relative, UNC, `\\.\` device, ADS-bearing and nonexistent paths with distinct `NonoError` variants; verify a unit test per rejection
- [ ] 4.3 Ensure all comparisons use `Path` components; verify a test that `C:\proj` does not cover `C:\project2`

## 5. PR 2 — Launch API and ownership

- [ ] 5.1 Add `LaunchOptions`, `Sandbox::launch` and `SandboxedChild` (design D3), Windows-only, with rustdoc stating the launch-not-apply semantics; verify `cargo doc` builds and the doctest compiles on Windows
- [x] 5.2 Build the command line with `std`-equivalent quoting, refuse unsafe `.bat`/`.cmd` arguments and NUL, and pass the exact environment block (design D8); verify unit tests covering quoting edge cases, batch refusal and the absence of inherited environment
- [ ] 5.3 Create the process suspended, assign it to a kill-on-close job with breakaway disallowed, verify the mechanism is PSEC (design D4), then resume; verify an enforcement test that a non-PSEC selection fails with no process created
- [ ] 5.4 Implement stdio piping, explicit handle inheritance, `wait`/`try_wait`, `terminate` and `Drop` cleanup with release errors surfaced; verify tests for exit status propagation, tree termination of a child and grandchild, drop-while-running, and the non-inheritance of an unlisted handle
- [x] 5.5 Redact environment values and scrub arguments in launch errors and `Debug`; verify a test that a credential in the environment never appears in error or `Debug` output
- [x] 5.6 Validate that the explicit environment contains `SYSTEMROOT` and `LOCALAPPDATA`, returning an error naming any that are missing (design D10a); verify a unit test plus an enforcement test showing that Win32 error 203 is never surfaced raw
- [x] 5.7 Expose win32k as an explicit launch option, disallowed by default, and render it in the policy (design D10a); verify an enforcement test that a user32-loading binary fails with win32k off and runs with it on

## 6. PR 2 — Filesystem enforcement mapping

- [ ] 6.1 Map `FsCapability` Read/ReadWrite (and Write per the spike result) and `LaunchOptions.deny_paths` to native policy, rejecting volume roots and unsupported denies (design D6); verify enforcement tests for every scenario in `specs/windows-filesystem-enforcement`
- [ ] 6.2 Reject `CapabilitySet` fields without a Windows expression (unix sockets, non-default signal/process-info/IPC modes, platform rules, extensions) with an error naming the field; verify a unit test per field
- [ ] 6.3 Implement `render_launch_policy` listing the normalized grants, denies and the backend's required system grants; verify a test that the rendered entries equal the entries passed to the adaptor
- [ ] 6.4 Document the filesystem mapping, required system grants and known limitations (volume roots, parent-marker searches, enumerate-without-read) in `windows.mdx`; verify the docs lint passes

## 7. PR 2 — Network enforcement mapping

- [ ] 7.1 Map `NetworkMode::Blocked`, `AllowAll` and `ProxyOnly{bind_ports: []}` to container egress policy for IPv4 and IPv6 (design D6, D9); verify enforcement tests for every blocked and proxy-only scenario in `specs/windows-network-enforcement`
- [ ] 7.2 Reject `bind_ports`, `tcp_connect_ports`, `tcp_bind_ports`, `localhost_ports` and port ranges, and refuse proxy-only when the probe reports the endpoint-scoped proxy path unavailable; verify unit tests per rejection
- [ ] 7.3 Verify concurrent separation and host isolation with an enforcement test running two launches with different proxy ports while a host process connects out
- [ ] 7.4 Document the network modes, the proxy path and what is refused in `windows.mdx`; verify the docs lint passes

## 8. PR 2 — Qualified-host enforcement suite

- [ ] 8.1 Add a Windows integration test crate or target that runs the probe binaries from group 1 against `Sandbox::launch` and treats any skip as failure under `NONO_REQUIRE_ENFORCEMENT=1`; verify that a run on a non-PSEC host with the variable set fails
- [ ] 8.2 Add the qualified-host CI job (self-hosted or hosted PSEC image, per design open question) running the suite; verify a green run with a non-zero count of executed enforcement tests
- [ ] 8.3 Run the security review for enforcement, paths and processes on Windows separately from Linux and macOS (`AGENTS.md`); verify the findings are resolved or tracked

## 9. PR 3 — nono-proxy on Windows

- [ ] 9.1 Gate the Unix-only code in `route.rs`, `oauth_capture/persist.rs` and `tls_intercept/bundle.rs`; verify `cargo check -p nono-proxy` and the proxy unit tests pass on Windows
- [ ] 9.2 Verify that the per-session token authentication rejects unauthenticated local clients on Windows, with an integration test
- [ ] 9.3 Add `nono-proxy` to the `windows-latest` CI job; verify it runs green

## 10. PR 3 — CLI Windows launch path

- [ ] 10.1 Gate the fork, `nix` and `openpty` paths in `exec_strategy.rs`, `pty_proxy.rs` and related modules, and move `nix` to `cfg(unix)`; verify `cargo check -p nono-cli` succeeds on Windows and `make ci` stays green on Linux and macOS
- [ ] 10.2 Add a Windows execution strategy that resolves the profile into `CapabilitySet` and `LaunchOptions` (including Windows deny paths) and calls `Sandbox::launch`; verify an integration test where `nono run` exits with the child's status
- [ ] 10.3 Start `nono-proxy` for proxy-only runs, pass the proxy environment and confine the child to its endpoint; verify an integration test where an allowed domain succeeds and a disallowed one is refused
- [ ] 10.4 Implement cleanup on exit, timeout, interrupt and launch failure (process tree, proxy, context); verify an integration test for interrupt with a background child
- [ ] 10.5 Refuse runs when the probe or the required features are missing, with a diagnostic and a non-zero exit; verify an integration test with a forced-unsupported adaptor

## 11. PR 3 — Windows profiles and refusals

- [ ] 11.1 Add Windows default system grants and protected paths (for example `%USERPROFILE%\.ssh`, credential stores) to the CLI policy; verify tests that the default profile starts `pwsh -NoProfile` and denies reading `.ssh`
- [ ] 11.2 Error on profile entries without a Windows expression, naming the entry; verify an integration test with a Unix socket grant
- [ ] 11.2a Add `fs_enumerate` grants for the ancestors of executable directories, and turn win32k on for shell and toolchain profiles, rendering both (design D10a); verify an integration test where `cmd.exe /c <granted exe>` succeeds and the ancestors stay unreadable
- [ ] 11.3 Make approval/supervisor, tool sandboxing, detached/attached sessions and rollback flags fail with "unavailable on Windows"; verify a CLI test per feature flag
- [ ] 11.4 Document the Windows profile defaults and unsupported features in the CLI docs; verify the docs lint passes

## 12. PR 3 — Terminal

- [ ] 12.1 Implement the nono-owned ConPTY plus the unconfined `--console-shim` re-exec that launches the PSEC workload with console inheritance (design D10; spike §1.11 proved output, resize and Ctrl-C); verify an automated ConPTY test for output, resize (child sees the new size) and Ctrl-C exit status
- [ ] 12.2 Ensure the workload never inherits the user's own console: interactive runs always go through the shim, and piped runs use a handle list with no console; verify an enforcement probe that `WriteConsoleInput` from the workload cannot reach the user's console
- [ ] 12.3 Document terminal behavior on Windows; verify the docs lint passes

## 13. PR 3 — Diagnostics and integration qualification

- [ ] 13.1 Extend `nono setup --check-only` to report the host build, the mechanism and per-feature availability on Windows; verify a CLI test of the output on qualified and unsupported hosts
- [ ] 13.2 Qualify PowerShell, Git for Windows (clone, commit), Node (`npm ci`, build) and Python (venv, `pip install` through the proxy) under the default profile on a qualified host; verify by recording the command transcripts and adding regression tests where automatable
- [ ] 13.3 Run `make ci` on Linux and macOS, plus the Windows and qualified-host jobs; verify all are green with enforcement tests actually executed

## Workflow follow-up

- Open the upstream PRs in the order PR 1, PR 2, PR 3, each with DCO sign-off, the PR template, agent disclosure and links to NEP-0005 and #2000.
- After the PRs merge, ask a maintainer to set NEP-0005 to `implemented`.
- Archive this change with `/opsx:archive` after review requirements are satisfied.
- Downstream, outside this repo: the devcroft runtime port and the Pixi provider qualification consume `Sandbox::launch`.
