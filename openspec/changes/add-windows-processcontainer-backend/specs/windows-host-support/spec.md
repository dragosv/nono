# Spec Delta

## Purpose

Defines how nono detects, reports and gates Windows enforcement support, so
that a Windows workload runs only when the required native isolation path is
actually in effect.

## ADDED Requirements

### Requirement: Library builds on Windows
The `nono` library SHALL compile and pass its platform-independent tests on
Windows targets. Functionality that depends on Unix-only facilities SHALL be
excluded from Windows builds, or SHALL be present and return an explicit
unsupported-platform error.

#### Scenario: Windows build
- **WHEN** the library is built for a Windows target
- **THEN** the build succeeds without Unix-only modules

#### Scenario: Unix-only feature called on Windows
- **WHEN** a Windows caller uses a library feature that has no Windows implementation, such as supervisor descriptor passing
- **THEN** the call is unavailable at compile time or returns an unsupported-platform error

### Requirement: Affirmative support detection
Support reporting on Windows SHALL report the platform as supported only
after affirmatively confirming that the native PSEC process-isolation path is
available on the host. Absence of an error from an API lookup SHALL NOT count
as confirmation.

#### Scenario: Compatible host
- **WHEN** support is queried on a host where the PSEC path is available
- **THEN** support is reported as supported, with the detected host build and mechanism in the details

#### Scenario: Incompatible host
- **WHEN** support is queried on a Windows build without the PSEC path
- **THEN** support is reported as unsupported, with the reason in the details

### Requirement: Per-capability support reporting
Support reporting SHALL list, separately, whether each optional enforcement
feature the backend uses is available on the host: filesystem deny paths,
directory enumeration without read, network egress filtering, and the proxy
path used for proxy-only mode.

#### Scenario: Host lacks deny-path support
- **WHEN** support is queried on a host that offers PSEC but not native deny paths
- **THEN** the report marks deny paths as unavailable while still reporting PSEC as available

### Requirement: PSEC path required at launch
A confined launch on Windows SHALL take effect only through the native PSEC
path. If the isolation machinery would select any other backend, such as an
AppContainer fallback, the launch SHALL fail. An earlier support probe SHALL
NOT stand in for this check at launch time.

#### Scenario: Fallback would be selected
- **WHEN** a launch is requested and the host would satisfy it only through a non-PSEC fallback
- **THEN** the launch fails with an error identifying the missing PSEC path and no process is created

#### Scenario: Host changes after probe
- **WHEN** the support probe succeeded but the PSEC path is unavailable when the launch happens
- **THEN** the launch fails and no process is created

### Requirement: Required capability missing refuses before workload
If the policy requires an optional enforcement feature the host does not
offer, the launch SHALL fail before any workload code runs. The error SHALL
name the missing feature.

#### Scenario: Deny path required but unsupported
- **WHEN** the policy includes a deny path on a host without deny-path support
- **THEN** the launch fails naming deny-path support and the workload does not run

### Requirement: No persistent host state
Windows enforcement SHALL NOT need an elevated install step, create local
user accounts, store credentials, change ACLs on host paths, or leave network
filters in place after the isolation context is released.

#### Scenario: Unprivileged run on compatible host
- **WHEN** a non-elevated user launches a confined process on a compatible host
- **THEN** the launch succeeds without an elevation prompt or prior install step

#### Scenario: State after run
- **WHEN** a confined run has ended and its handle was released
- **THEN** no nono-created account, ACL change or network filter remains on the host
