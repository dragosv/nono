# Spec Delta

## Purpose

Defines the library contract for starting a new process that is already
confined by a `CapabilitySet` and for owning that process's lifetime, as
distinct from restricting the calling process in place.

## ADDED Requirements

### Requirement: Confined launch from a capability set
On Windows, the library SHALL provide an operation that takes a
`CapabilitySet`, launch options, a program, its arguments, an environment and
a working directory. It SHALL start that program already confined by the
policy derived from them. The program SHALL NOT execute any instruction
before the confinement is in effect.

#### Scenario: Program starts confined
- **WHEN** a caller launches a program with a capability set that grants read-write access to one directory only
- **THEN** the program's first file access outside that directory is denied

#### Scenario: Caller remains unconfined
- **WHEN** a caller launches a confined program
- **THEN** the calling process's own filesystem and network access is unchanged

### Requirement: Launch fails closed
If any part of the derived policy cannot be applied, the launch operation
SHALL return an error and SHALL NOT start the program. It SHALL NOT return a
running process that has only part of the policy applied.

#### Scenario: Unapplicable policy element
- **WHEN** the capability set contains an element the backend cannot enforce
- **THEN** the operation returns an error naming that element and no process is created

#### Scenario: Launch failure after resource allocation
- **WHEN** the OS rejects process creation after the isolation context was allocated
- **THEN** the operation returns an error and releases the isolation context

### Requirement: Owning process handle
A successful launch SHALL return a handle that owns the confined process,
its descendants and the isolation context. Through the handle the caller
SHALL be able to wait for exit with the exit status, terminate the process
tree, and take the child's standard input, output and error streams.

#### Scenario: Wait reports exit status
- **WHEN** the confined program exits with status 3
- **THEN** waiting on the handle returns exit status 3

#### Scenario: Terminate stops descendants
- **WHEN** the caller terminates through the handle while the program has a running child and grandchild
- **THEN** all three processes are ended

#### Scenario: Stdio is piped
- **WHEN** the caller requests piped stdio and the program writes to stdout
- **THEN** the caller reads that output from the handle's stdout stream

### Requirement: Cleanup on release
Releasing the handle, whether explicitly or by drop, SHALL end any remaining
processes in the confined tree and release the isolation context and every
OS resource the launch allocated. A release that cannot be completed SHALL be
reported as an error, not ignored.

#### Scenario: Handle dropped while running
- **WHEN** the handle is dropped while the program is still running
- **THEN** the program and its descendants are ended and the isolation context is released

#### Scenario: Normal exit releases resources
- **WHEN** the program exits normally and the handle is released
- **THEN** no isolation context or process created by the launch remains

### Requirement: Inherited handles are explicit
The launched program SHALL inherit only the handles or file descriptors the
caller passes explicitly to the launch operation, plus the requested stdio.
No other handle of the calling process SHALL be inherited.

#### Scenario: Unlisted handle not inherited
- **WHEN** the caller holds an open file handle it does not pass to the launch
- **THEN** the confined program cannot use that handle

### Requirement: Secrets kept out of launch diagnostics
Errors, `Debug` output and logs produced by the launch operation SHALL NOT
include environment variable values, and SHALL pass program arguments
through the library's existing scrubbing before they appear.

#### Scenario: Launch error with secret environment
- **WHEN** a launch fails and the environment contains a credential value
- **THEN** the returned error and any log output do not contain that value

#### Scenario: Argument containing a token
- **WHEN** a launch fails and an argument matches the scrubbing policy
- **THEN** the argument appears only in scrubbed form

### Requirement: Self-restriction is not emulated by launch
On a platform where confinement is available only through confined launch,
in-process self-restriction SHALL NOT report success. The operation SHALL
either be unavailable at compile time or return an error stating that only
confined launch is supported.

#### Scenario: Self-restriction requested on Windows
- **WHEN** a caller on Windows requests in-process self-restriction
- **THEN** the call is unavailable or returns an error, and the caller is not reported as sandboxed
