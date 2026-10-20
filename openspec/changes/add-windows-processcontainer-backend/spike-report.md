# Spike report — Windows ProcessContainer/PSEC (tasks 1.1–1.10)

Date: 2026-10-18. Branch: `spike/windows-psec`. The spike code is in
`spikes/windows-psec/`. It is not a workspace member and is not meant to
merge.

Every result below was observed on the single host described in 1.1. None of
it has been reproduced on another build, on x64, or on a host without PSEC.

## 1.1 Host, SDK and pins

| Item | Value |
|---|---|
| OS | Windows 11 Pro, DisplayVersion 26H2, build 26300.9711, arm64 |
| Toolchain | rustc 1.99.1 (`aarch64-pc-windows-msvc`), VS Build Tools 2026 (VC ARM64 + x64) |
| SDK | `mxc-sdk` **=1.0.1** (crates.io), `.crate` sha256 `7c9e2d05b3953fdb34c44e4de8d8f2b447f4444534cb95294b72fb297a468f61` |
| MXC source tag | `v1.0.1` → `fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2` |
| Codex reference | Not consulted in this spike. Pin it if it is used later. |

What the SDK detected (`v1::available_backends()` and `v1::probe(None)`):
- tier `base-container`
- `baseContainerApiPresent: true`
- `baseContainerSupportsDenyPaths: true`
- `baseContainerSupportsEnumeratePaths: true`
- `baseContainerSupportsIngressHostLoopbackAllow: true`
- `baseContainerSupportsIdentitylessLoopbackProxy: true`
- `bfsCompiledIn: false`
- `nativeCaptureAvailable: true`

**PSEC is available on this host.**

Note: SDK v1.0.1 was published on 2026-10-17, one day before this spike. It
was chosen for its PSEC 1.0 host-loopback fix. Before upstream use,
re-evaluate the pin against the project's dependency-age policy.

## 1.2 PSEC-only selection

Findings from reading the source (`fallback_detector.rs`, `dispatcher.rs`):
- The SDK picks a tier automatically:
  - T1 BaseContainer (PSEC)
  - T2 AppContainer + BFS (only with the `tier2_bfs` feature, which is off by default)
  - T3 AppContainer + **host DACL mutation**
- T3 is gated only by `fallback.allowDaclMutation`, and it **defaults to `true`**.
- The typed v1 `ContainerRequest` **does not expose** `fallback`. A typed
  request can therefore silently degrade to T3 on a host without PSEC.
- The exact-version JSON contract (`"version": "1.0.0"`) accepts
  `"fallback": {"allowDaclMutation": false}`. It is reachable only through
  `mxc_sdk::__ffi::{run_json, spawn_container_json}`, which is
  `#[doc(hidden)]` and documented as "not SDK authoring APIs".
- With default features (T2 not compiled in) and `allowDaclMutation: false`,
  the outcome is structurally either **T1 or an error**. Every request in
  this spike used that shape. `icacls` on a granted directory was identical
  before and after a run, so no DACL mutation occurred.

**Not verified:** the refusal path on a host without PSEC. No such host was
available. This part of the task is still open.

## 1.3 / 1.4 Filesystem

| Case | Result |
|---|---|
| write inside read-write grant | allowed |
| read inside read grant | allowed |
| write inside read grant | denied (os error 5) |
| read/list of ungranted dir | denied |
| single-file grant `a.txt`, read sibling `b.txt` | `a.txt` allowed, `b.txt` denied |
| deny path inside read-write grant (read and write) | denied |
| ADS of granted file / ungranted file | allowed / denied |
| junction inside read-write grant → ungranted target | denied (target decides) |
| grant names a junction → target | target **granted** (PSEC resolves at grant time) |
| grant via 8.3 name, access via long name (and reverse) | equivalent |
| access with different case | equivalent |
| deny given as non-canonical path (8.3 + `..`) | enforced |
| child and grandchild: read ungranted, write read-only, write ungranted, read denied | all denied |
| implicit access: `C:\Windows\win.ini`, list `System32` | allowed |
| implicit access: list `C:\Users`, list `%USERPROFILE%` | denied |
| **volume-root grant `C:\` read** | **cascades**: an ungranted file under `C:\` became readable |
| drive-relative `C:relative`, UNC `\\localhost\C$\Windows` as grant | **accepted silently** by the SDK |

Consequences:
- The MXC documentation says a volume-root grant does not cascade. On this
  build it does. Behavior may differ by build, so it must be probed or
  refused. It must never be assumed.
- The SDK does not validate path forms. nono must validate them itself
  (design D7).
- A grant that names a junction grants its target. nono must canonicalize so
  the rendered policy shows the target.

## 1.5 Blocked network

Policy: `egress.default = deny`, no ingress section. All of the following
were refused, in the workload and in a child process:
- TCP to `1.1.1.1:443` and to `[2606:4700:4700::1111]:443` (WSAEACCES 10013)
- UDP DNS to `1.1.1.1:53` and to the IPv6 resolver (no reply)
- system resolver lookups (11001)
- loopback to host listeners over IPv4 and IPv6

In the control run (`egress.default = allow`), all external traffic
succeeded, but host loopback stayed refused. Containers are isolated from
host loopback by default.

## 1.6 Proxy-only

The SDK rejects `runtimeConfig.networkProxy` unless all of these hold:
- `egress.default = deny` **with no allow or deny rules**
- `ingress.default = allow`
- `hostLoopback = allow`

| Variant | proxy port | other loopback port | direct egress | system DNS |
|---|---|---|---|---|
| **A: SDK proxy mode** (`networkProxy = 127.0.0.1:pa`) | reachable | **refused** (v4 and v6) | refused | **resolves** |
| B: proxy shape without `networkProxy` | reachable | **reachable** | refused | resolves |
| C/D: egress allow rule for `127.0.0.1:pa` + `hostLoopback` allow | reachable | **reachable** | refused | resolves |
| E: egress allow rule only | refused | refused | refused | resolves |

Ingress in variant A: the host could not connect to a listener inside the
container (timed out).

Conclusions:
- **Only variant A (SDK proxy mode) scopes egress to a single endpoint.**
  `hostLoopback = allow` without `networkProxy` opens every host loopback
  port, and egress allow rules do not narrow it. Design D9 must use
  variant A only.
- **DNS leak:** whenever the policy is not fully blocked, the workload can
  resolve names through the system resolver (the Dnscache service). That is
  an exfiltration channel through DNS queries. Direct UDP/53 stays refused.
  This matches nono's default macOS proxy-only behavior (resolver grants)
  but not the spec as written. `dns_blocked` cannot be enforced in proxy
  mode on Windows, so the spec and design need updating.
- Domain filtering by `nono-proxy` was not exercised. The stand-in proxy
  was a plain HTTP responder. That work belongs to group 9.

## 1.7 Concurrency and host isolation

- Two containers ran at the same time, A in proxy mode to `pa` and B in
  proxy mode to `pb`. Each reached only its own proxy. A→`pb` and B→`pa`
  were refused.
- An unconfined host process connected to `1.1.1.1:443` successfully while
  both containers were running.

## 1.8 Cleanup

| Case | Background grandchild afterwards |
|---|---|
| `kill()` | gone (`wait` = `Exited(-1)`) |
| drop handle without kill | gone |
| request timeout (3 s) | gone (`wait` = `TimedOut`) |
| launching process `abort()`s | gone |
| missing program | launch error before any workload (`CreateProcessW(PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT)` failed, code 2) |

**Not verified:** whether WFP filters persist after an abnormal exit.
Enumerating filters requires elevation.

Known upstream issue: microsoft/mxc#1486 reports that each environment
leaks one SeLs lowbox entry, and that `CreateProcessSecurityEnvironment`
fails after about 64K of them until reboot. This matters for long-lived
hosts such as the devcroft keeper, less so for one-shot `nono run`.

## 1.9 PTY and write-only

- **PTY:** `spawn_with_pty` on `processcontainer` fails with
  `UnsupportedContainment` ("does not yet support PTY spawning"). PSEC is
  attached through `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` on an
  ordinary `CreateProcessW`. A pseudo console attribute could in principle
  share that attribute list, but only through a direct adaptor (D2), not
  the SDK. **Not feasible through the SDK. Unproven through direct FFI.**
- **Write-only (`AccessMode::Write`):** the policy schema has only read-write,
  read-only and denied paths. **Not expressible**, so the launch must fail.

## 1.10 SDK versus direct FFI (design D2)

| Trigger | Result |
|---|---|
| 1. Can the SDK force the backend or report it? | **Partially hit.** No typed control and no post-spawn tier report. Only the hidden JSON entry point disables T3. |
| 2. Required operations only in non-public surfaces | **Hit.** `allowDaclMutation` is reachable only via `__ffi` (`#[doc(hidden)]`). |
| 3. Dependency cost | About 100 crates: tokio, chrono, flatbuffers, nix, url, uuid, tracelogging telemetry, winreg, windows 0.62 and others. Release driver binary is 3.3 MB. A clean release build of the spike took about 1.5 min. |

Direct FFI cost: `CreateProcessSecurityEnvironment` takes a "PSEC"
**FlatBuffer** specification. Its schema ships in the MIT-licensed SDK
source but is not documented as a public OS contract. A direct adaptor
would have to vendor that schema and track OS contract versions.

**Decision (recommendation for the NEP):**
- Keep the SDK behind the internal adaptor (D2), but call it through the
  exact-version JSON contract (`"version": "1.0.0"`) with
  `fallback.allowDaclMutation = false`.
- Build with default features only, so `tier2_bfs` is off. Add a CI check on
  the feature set so that **T1-or-error** holds by construction.
- Explicitly disable SDK telemetry.
- Ask MXC upstream to expose `fallback` and a tier pin (or a
  `require_tier`) in the typed v1 API, and to report the selected tier on
  `MxcProcess`.
- Revisit direct FFI if upstream declines, or if ConPTY (1.9) proves to
  need it.

## Impact on the plan

| Artifact | Change needed |
|---|---|
| `specs/windows-network-enforcement` | Proxy-only: direct DNS is refused, but system-resolver lookups remain (same as macOS default). A requested DNS block must fail the launch on Windows. |
| `design.md` D4 | Make PSEC-only structural: JSON contract, `allowDaclMutation: false`, default features, feature-set CI check. |
| `design.md` D5 | Probe volume-root cascade behavior. Disable SDK telemetry. |
| `design.md` D9 | Use SDK proxy mode only. Never `hostLoopback` without `networkProxy`. |
| `design.md` D10 | PTY needs a direct adaptor. Interactive mode is refused until that is proven. |
| `design.md` CLI | Grant a per-run temp directory and set `TEMP`/`TMP`. The default `TEMP` points to an ungranted user temp directory. The default environment does not inherit the launcher's variables (verified with a marker variable). |
| Still open | Refusal on a host without PSEC. WFP persistence after abort. x64 and other builds. Domain filtering with the real `nono-proxy`. |

## 1.11 Direct FFI without mxc-sdk (follow-up, 2026-10-18)

The decision changed after user direction: invoke PSEC directly, with no
`mxc-sdk` dependency. The spike lives in `spikes/windows-psec-direct/`.
`src/lib.rs` is about 570 lines of `windows-sys` calls plus the vendored
FlatBuffer bindings.

**Mechanism (confirmed working):**
1. Load `processmodel.dll` with `LOAD_LIBRARY_SEARCH_SYSTEM32` and resolve
   four exports:
   - `CreateProcessSecurityEnvironment`
   - `QueryProcessSecurityEnvironmentSupport`
   - `IsProcessSecurityEnvironmentVersionSupported`
   - `CloseProcessSecurityEnvironment`
2. Encode the policy as a "PSEC" FlatBuffer. The schema is vendored from
   MXC v1.0.1 (MIT). It originates in the Windows OS repository and is
   **not** in the public Windows SDK 10.0.26100.
3. Call `CreateProcessW` with these flags:
   `EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT`.
   The attribute list carries `PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT`
   (`35 | 0x20000`) and `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, which limits
   inheritance to exactly the stdio pipe.
4. Assign the process to a kill-on-close Job Object, then resume it.

Drop order: job (kills the tree), then the environment is closed.

**Host:** PSEC v1 supports minor version 1. v2 is not supported. Support
flags are `0xf` (deny, enumerate, ingress, plus one undocumented bit,
`0x2`).

**Results:** the same as the SDK runs for every case retested.

| Area | Result |
|---|---|
| filesystem | Read-write, read-only, single file, deny inside read-write, junction to ungranted, ADS and grandchild all behave as in §1.3–1.4 |
| network | Allow-all control works. Blocked refuses everything, including resolver lookups. Proxy mode (`ProxyInfo.url` + `privateNetworkClientServer,networkLoopback` + peer `MXC-Loopback`) reaches only the proxy port; other loopback ports and direct egress are refused, and the system resolver still answers (same DNS leak as §1.6). A host process is unaffected. |
| cleanup | `TerminateJobObject` and plain drop both kill the background grandchild. A missing program fails at `CreateProcessW` (error 2). |
| environment | An explicit block is passed and nothing from the launcher leaks. **`SYSTEMROOT` and `LOCALAPPDATA` must be present**, otherwise `CreateProcessW` fails with Win32 error 203. Only their presence is checked, not their values. |
| PSEC-only | There is no fallback code path at all. If `processmodel.dll`, an export or the version is missing, the call returns an error. A host without PSEC was not available to observe this. |

**New findings:**
- **win32k:** with `disallow_win32k_system_calls = true` (the SDK default
  for `ui.disable`), any binary that loads user32 fails at start with
  `0xC0000142` (`STATUS_DLL_INIT_FAILED`). Examples: `mode.com` in pipe
  mode, `cmd.exe` under ConPTY. Rust and console-only binaries run.
  Allowing win32k is a policy choice that trades UI-subsystem attack
  surface for tool compatibility.
- **Ancestor enumeration:** `cmd.exe` gets "Access is denied" when it starts
  an exe from a granted directory, unless the directory's **ancestors are
  granted `fs_enumerate`** (PSEC 1.1). Rust `CreateProcessW` works without
  that grant. This is the "parent-directory marker search" risk from the
  design, and enumerate grants (which do not grant content reads) solve it.
- **ConPTY attached directly fails:** putting
  `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` in the same attribute list as the
  security environment does not attach the child. It runs and exits 0, but
  no output reaches the pseudo console. A control run without PSEC
  confirmed that the ConPTY code itself is correct.
- **ConPTY through a shim works:** the chain is ConPTY → unconfined shim
  (nono itself) → PSEC child that inherits the shim's console. Verified:
  - output arrives through the ConPTY
  - the child sees the ConPTY size (80x25), and after `ResizePseudoConsole`
    it sees 120x40
  - confinement still applies (ungranted read and TCP refused)
  - **Ctrl-C** written as `0x03` ends the child in about 5 ms with
    `0xC000013A`

  (Ctrl-C also requires that the launcher's inherited "ignore Ctrl-C" flag
  is cleared with `SetConsoleCtrlHandler(NULL, FALSE)`.)
- **Console sharing risk (not tested):** a PSEC child attached to the
  *user's* console shares its input buffer. It could inject input with
  `WriteConsoleInput`, and the user's shell would read that input after nono
  exits. This is the Windows analogue of TIOCSTI. Interactive runs should
  therefore always interpose a nono-owned ConPTY (the shim) and never hand
  over the user's console. This still needs a dedicated probe.

**Dependency cost:** `flatbuffers 25.12.19`, `windows-sys 0.61.2`,
`windows-link` and `bitflags`. That is 4 crates. `windows-sys 0.61.2` is
already in nono's `Cargo.lock`.

**Revised decision for 1.10:** go with **direct FFI**:
- Vendor the generated PSEC bindings: about 2.6k lines, MIT, with
  provenance in `psec_spec/NOTICE.md`.
- Pin the schema hash and the flatc version, and add a drift check against
  MXC releases.

Costs to accept:
- nono now owns tracking of the OS contract (schema minor versions,
  support flags).
- The schema is not a documented public Windows SDK contract yet.

Ask Microsoft (task 2.0) to publish `ProcessSecurityEnvironment.fbs` and the
exports in the Windows SDK.

## 1.12 Integration in the workspace (local, pre-NEP, 2026-10-19)

The direct-FFI backend now lives in `crates/nono/src/sandbox/windows/`, and
`nono-cli` has a separate Windows front end in `src/windows/`. This work is
local on `spike/windows-psec`. It is **not** for merge until NEP-0005 is
accepted (groups 3+).

**Library** (`Sandbox::launch`, `render_launch_policy`, `windows_support`;
`LaunchOptions`, `LaunchStdio`, `SandboxedChild`):
- 24 unit tests: path validation, spec round-trip, quoting, batch refusal,
  environment block, field rejection, redaction.
- 14 end-to-end tests under PSEC (`crates/nono/tests/windows_launch.rs`,
  `NONO_REQUIRE_ENFORCEMENT=1`) with positive controls in every denial
  test: read/write grants, read-only refusal, ungranted read, deny inside a
  grant, exact environment, blocked loopback, proxy-only scoping, terminate,
  drop with a background grandchild, win32k on/off, PSEC variables, relative
  program, rendered policy, enumerate behavior.

**CLI** (`nono run`, `nono setup --check-only`):
- Unix modules are untouched and compiled only under `cfg(unix)`.
- Verified: grants and denials (cmd, PowerShell), exit-code propagation,
  `--write` refusal, `--block-net`, and proxy-only through the real
  `nono-proxy` (`--allow-domain example.com`: example.com 200, github.com
  `403 Forbidden: host github.com:443 is not in the allowlist`, a direct
  connection with `--noproxy '*'` refused by PSEC with "Bad access";
  `--deny-domain`). This closes task 1.6.
- Git for Windows (`init`, `add`, `commit`, `log`) runs confined with
  `--allow-win32k`. Without it, git fails with `0xC0000142` and the CLI
  prints the hint.
- Interactive path, run in a fresh console: ConPTY → shim → workload. The
  workload sees the nono-owned console (120x30), its exit code 7 reaches the
  caller, a write outside the grants is refused, and no nono process
  remains afterwards.

**New findings:**
- **Enumerate on a volume root cascades.** It lists every file name on the
  volume; contents stay unreadable. Enumerate on an ordinary directory does
  not even list that directory. `cmd.exe` needs enumerate on all ancestors,
  volume root included, to start a program by absolute path. Ancestor
  enumeration is therefore opt-in in the CLI (design D10a).
- **Piped launches use `CREATE_NO_WINDOW`.** `cmd.exe` then runs without
  win32k. Only `InheritConsole` shares a console.
- **Verbatim working directory.** `cmd.exe` rejects a `\?\X:\` working
  directory, so the library strips the verbatim prefix.
- **`cmd /c` quoting.** `cmd /c` does not honour `CommandLineToArgvW`
  escapes, so scripts embedding quoted paths need care. This is the caller's
  concern, as with `std::process::Command`.
- **Build prerequisite.** `aws-lc-sys` needs clang-cl on Windows ARM64 (LLVM
  23.1.3 installed). Without it, nothing in the workspace builds there.

**Review fixes (2026-10-20):**
- Program names Windows would reinterpret (`run.bat.`, `run.bat `,
  `run.bat::$DATA`) are refused, so they cannot get past the batch argument
  filter. The CLI already normalized them through `std::path::absolute`.
- Job UI limits are always set. With `--allow-win32k`, a confined
  `Get-Clipboard` fails ("Requested Clipboard operation did not succeed"),
  while git still works.
- `max_processes` is refused; `memory_bytes` is shown as a committed-memory
  cap.
- The CLI environment is read with `vars_os`, so a non-Unicode variable no
  longer panics: a non-Unicode name is dropped. It also filters the Windows
  profiler, loader and shim variables (`COR_*PROFIL*`,
  `CORECLR_*PROFIL*`, `DOTNET_ADDITIONAL_DEPS`, `DOTNET_SHARED_STORE`,
  `__COMPAT_LAYER`).
- Child stdio handles are inheritable only around `CreateProcessW`.
- In the interactive path, Ctrl-Break ends the sandbox and the console modes
  are restored. The stdin relay thread owns its pipe handle, so it never
  writes to a closed handle.

**CLI integration tests on Windows (2026-10-20):**
- `crates/nono-cli/tests/windows_cli.rs` holds 18 end-to-end tests of the
  Windows front end, run through the shared hermetic harness. Each denial
  has a positive control. They cover rw, read-only, ungranted and deny
  grants, `--write` refusal, exit codes, TEMP, `--block-net`,
  `--allow-domain` filtering (403 for an unlisted host; a direct
  `--noproxy` connection is refused), dry-run redaction, opt-in
  enumeration, injection variables, win32k, command resolution, refusal of
  unported flags, and the batch filter with a trailing dot.
- The 12 test files that drive unported Unix CLI features (profiles, trust,
  audit, rollback, `wrap`, `--config`, `NONO_*`, globs, AF_UNIX, the
  supervisor socket) are `#![cfg(unix)]` and give the reason in a comment.
  The lint tests find Git for Windows' bash
  (`nono_test_support::bash`). `cargo test -p nono-cli --tests` passes on
  Windows.
- **PSEC sets TEMP/TMP** to the container's own temp folder
  (`%LOCALAPPDATA%\Packages\sandbox.{guid}\AC\Temp`). It is distinct per
  run and deleted when the run ends. The CLI therefore no longer creates or
  grants a temp directory of its own; that grant had no effect.
- **A batch file started directly fails** under PSEC with "Access is
  denied." `cmd /c call x.bat` works.
- **`cmd`'s `dir` needs ancestor enumeration** even inside a read-write
  grant. PowerShell's `Get-ChildItem` lists the same directory without it.

**Second review (2026-10-20), checked on build 26300:**
- **Verbatim names Windows rewrites: confirmed and fixed.** Granting
  `\\?\...\safe.` emitted `...\safe.` and opened the sibling `safe` (its
  secret was readable). Policy paths, the program and the working directory
  now refuse components ending in a dot or space, DOS device names (`NUL`,
  `COM1`, `nul.txt`, `COM¹`) and wildcard characters. Covered by unit,
  enforcement and CLI tests.
- **File grant turned into a directory or junction: fixed.** PSEC resolves
  paths when the environment is created. Every grant, deny and enumerate
  path is now opened before that, checked (final path; file or directory
  kind for grants) and held without `FILE_SHARE_DELETE`. Once the process
  exists, still suspended, each path is resolved again and must name the
  same file ID. Inside the sandbox, a read-only file grant in a read-write
  tree cannot be deleted, and `mklink /J` is refused.
- **UI limits and nested jobs.** The interactive path worked with the limits
  set before assignment: exit 7 reached the caller, the marker file was
  written, and the clipboard was denied. The documented contract forbids
  assigning a process that is already in a job to a job with UI limits, so
  the limits are now applied after assignment, while the process is still
  suspended. Clipboard denial was re-verified in both modes, and an automated
  interactive test (`CREATE_NEW_CONSOLE`) covers the shim path.
- **Proxy-only and private-network inbound.** PSEC refuses the proxy form
  with an ingress table, and without `privateNetworkClientServer`
  (`E_INVALIDARG`), so inbound traffic from private networks cannot be ruled
  out. On this host, inbound to a listener in the container was refused
  from loopback and from the host's own LAN address. That address counts as
  loopback, though, and the network profile is Public, so this says
  nothing about a second machine on a private network. Proxy-only is
  therefore refused unless the caller accepts it
  (`LaunchOptions::allow_private_network_inbound`, CLI
  `--allow-private-inbound`), and the rendered policy states it. A test from
  a second machine on a Private network is still open.
- **Allow-all is internet only.** Host loopback and private networks are
  refused under `internetClient` alone. Opening them takes
  `privateNetworkClientServer` plus `networkLoopback` with ingress allowed,
  which also admits inbound traffic (verified: host → container connected).
  nono keeps the narrower mapping and now says so in the rendered policy and
  the help.
- **Implicit access** (files and registry readable by ALL APPLICATION
  PACKAGES, and the container's TEMP) is listed in `RenderedPolicy::implicit`
  and in `--dry-run`.
- **Batch script paths** containing characters cmd.exe expands (`%`, `!`,
  `^`, `&`) are refused. Arguments were already filtered.
- Experiment driver: `spikes/windows-psec-direct/src/bin/netprobe.rs`.

**Open:**
- 13 pre-existing `nono` unit tests fail on Windows. They assume Unix PATH
  separators, file permissions or Unix sockets, and none touch the backend.
- The Unix CLI integration tests run only on Unix until the matching
  features are ported (profiles, trust, audit, rollback, supervisor).
- Profiles, default protected paths, the `WriteConsoleInput` probe, an
  automated resize and Ctrl-C test, the non-PSEC refusal (1.2) and the WFP
  check after abort (1.8) are not done.
