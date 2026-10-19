# Spec Delta

## Purpose

Defines the behavior of `nono run` on native Windows: how profiles, the
proxy, stdio and terminals, cleanup and diagnostics work, and how features
not yet available on Windows are refused.

## ADDED Requirements

### Requirement: Run a Windows program confined
`nono run` on a compatible Windows host SHALL launch the given Windows
program, such as PowerShell, `git.exe`, `node.exe` or `python.exe`, against
a project on NTFS. The program SHALL run under the filesystem and network
policy resolved from the profile and flags, and `nono run` SHALL exit with
the program's exit status.

#### Scenario: Confined build in project
- **WHEN** a user runs `nono run` with read-write access to a project directory and invokes a toolchain that writes build output there
- **THEN** the build output is written and nono exits with the toolchain's exit status

#### Scenario: Write outside project
- **WHEN** the confined program attempts to write to the user's profile directory outside the grants
- **THEN** the write is denied

### Requirement: Refuse when enforcement unavailable
`nono run` on Windows SHALL refuse to start the program when the host lacks
the PSEC path or any enforcement feature the resolved policy requires. It
SHALL exit non-zero with a diagnostic naming what is missing. It SHALL NOT
run the program unconfined.

#### Scenario: Unsupported Windows build
- **WHEN** `nono run` is invoked on a Windows build without the PSEC path
- **THEN** nono exits non-zero, explains the requirement, and the program is not started

### Requirement: Windows profile defaults
The CLI SHALL provide Windows-specific default system grants and protected
paths so that common Windows toolchains start under the default profile.
These grants SHALL be read-only unless a write is required, and they SHALL
be documented.

#### Scenario: Default profile starts a shell
- **WHEN** a user runs `nono run -- pwsh -NoProfile -Command "exit 0"` with the default profile
- **THEN** the shell starts and exits 0

#### Scenario: Protected credential directory
- **WHEN** a confined program reads a default-protected credential location such as the user's SSH key directory
- **THEN** the read is denied

### Requirement: Cross-platform profile entries that cannot be expressed
When a profile resolves to a capability that Windows enforcement cannot
express, `nono run` SHALL fail with an error naming the entry. This covers
Unix socket grants, signal or process-info isolation modes and raw platform
rules. The CLI SHALL NOT drop the entry silently.

#### Scenario: Unix socket grant on Windows
- **WHEN** the resolved profile contains a Unix socket grant
- **THEN** nono exits non-zero naming the unsupported entry and the program is not started

### Requirement: Proxy-only through nono-proxy
When the resolved network policy uses the proxy, the CLI SHALL start
`nono-proxy` outside the confinement with a per-session credential. It SHALL
pass the proxy configuration to the program, and SHALL confine the program to
that proxy endpoint.

#### Scenario: Allowed and blocked domains
- **WHEN** a proxy-only run fetches an allowed domain and then a disallowed domain
- **THEN** the allowed fetch succeeds and the disallowed fetch is refused

### Requirement: Stdio and interactive terminal
`nono run` SHALL forward stdin, stdout and stderr between the user and the
confined program. When attached to an interactive console, it SHALL provide
a pseudo console that supports input, output, resize and Ctrl-C delivery. If
the host cannot provide one for a confined process, it SHALL fail with an
error rather than run without confinement.

#### Scenario: Piped output
- **WHEN** `nono run` runs a program whose output is redirected to a file
- **THEN** the program's stdout is written to the file

#### Scenario: Ctrl-C in interactive session
- **WHEN** a user presses Ctrl-C during an interactive confined session
- **THEN** the confined program receives the interrupt and nono exits after it terminates

#### Scenario: Terminal resize
- **WHEN** the user resizes the console window during an interactive session
- **THEN** the confined program observes the new console dimensions

### Requirement: Workload never shares the user's console
The confined program SHALL NOT be attached to the console of the terminal
that invoked `nono run`. Interactive runs SHALL give it a pseudo console
owned by nono, and non-interactive runs SHALL give it pipes only, so it
cannot inject input that the user's shell reads after nono exits.

#### Scenario: Console input injection attempt
- **WHEN** the confined program writes console input records intended for the invoking terminal
- **THEN** the invoking terminal's input buffer does not receive them

### Requirement: Cleanup on every exit path
On program exit, timeout, user interrupt, launch failure or failure of nono
itself, the CLI SHALL end the confined process tree. It SHALL stop the
session's proxy and release the isolation context.

#### Scenario: Interrupt with background child
- **WHEN** the confined program has started a background child and the user interrupts nono
- **THEN** the program, the background child and the session proxy are all ended

### Requirement: Unported features refused explicitly
On Windows, CLI features that depend on facilities not yet ported SHALL fail
with an error stating they are unavailable on Windows. This covers runtime
capability approval through the supervisor, tool sandboxing, detached or
attached sessions, and rollback snapshots. Their flags SHALL NOT be accepted
and then ignored.

#### Scenario: Supervisor approval requested
- **WHEN** a user requests interactive capability approval on Windows
- **THEN** nono exits non-zero stating the feature is unavailable on Windows

### Requirement: Windows diagnostics
`nono setup --check-only` and equivalent diagnostics on Windows SHALL report
the detected host build and mechanism and the availability of each optional
enforcement feature. They SHALL also report the rendered policy for a run,
with paths in normalized Windows form.

#### Scenario: Check-only on compatible host
- **WHEN** a user runs the setup check on a compatible Windows host
- **THEN** the output reports PSEC as available and lists each optional feature with its availability
