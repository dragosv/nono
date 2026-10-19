# Spec Delta

## Purpose

Defines the filesystem confinement a Windows workload receives from a
`CapabilitySet` and the rules for interpreting Windows paths, so that the
policy shown to users matches the policy the OS enforces.

## ADDED Requirements

### Requirement: Read grants
A path granted read access SHALL be readable by the workload. The workload
SHALL NOT be able to create, modify, rename or delete anything at or under
that path.

#### Scenario: Read in read-only directory
- **WHEN** the workload reads a file inside a directory granted read access
- **THEN** the read succeeds

#### Scenario: Write in read-only directory
- **WHEN** the workload attempts to create or modify a file inside a directory granted read access
- **THEN** the operation is denied

### Requirement: Read-write grants
A path granted read-write access SHALL be readable and writable by the
workload, including creating and deleting entries beneath a granted
directory.

#### Scenario: Create in writable directory
- **WHEN** the workload creates, writes and deletes a file inside a directory granted read-write access
- **THEN** each operation succeeds

### Requirement: Ungranted paths denied
Paths not covered by a grant, or by a host-required system grant documented
for the backend, SHALL be inaccessible to the workload for both reading and
writing.

#### Scenario: Read outside grants
- **WHEN** the workload reads a file in a user directory that no grant covers
- **THEN** the read is denied

### Requirement: Grant granularity is preserved
A grant on a single file SHALL cover only that file. A grant on a directory
SHALL cover the directory and its descendants. Where a host limitation stops
a grant from covering what it would cover on Linux or macOS, such as a grant
on a volume root, the launch SHALL fail. It SHALL NOT silently narrow or
widen the grant.

#### Scenario: Single-file grant
- **WHEN** a single file is granted read access and the workload reads a sibling file in the same directory
- **THEN** reading the granted file succeeds and reading the sibling is denied

#### Scenario: Volume root grant not expressible
- **WHEN** the capability set grants a volume root on a host where such grants do not cascade
- **THEN** the launch fails with an error explaining the limitation

### Requirement: Explicit deny paths
A deny path supplied by the caller SHALL be inaccessible to the workload even
when it lies inside a broader grant. If the host cannot enforce the deny
natively, the launch SHALL fail. The deny SHALL NOT be dropped.

#### Scenario: Deny inside writable grant
- **WHEN** a directory is granted read-write access and a subdirectory of it is a deny path
- **THEN** accessing the subdirectory is denied and the rest of the directory stays writable

### Requirement: Descendants inherit confinement
Every process started by the workload, directly or indirectly, SHALL be
subject to the same filesystem policy as the workload.

#### Scenario: Grandchild write outside grants
- **WHEN** the workload starts a child, the child starts a grandchild, and the grandchild writes outside the grants
- **THEN** the write is denied

### Requirement: Windows path normalization
Before mapping a grant to native policy, the backend SHALL convert each path
to one absolute canonical form, resolving drive letters, `\\?\` prefixes,
8.3 short names, case and reparse points. It SHALL reject any path it cannot
canonicalize reliably, such as drive-relative, UNC or device paths.
Comparison SHALL work on path components, never on string prefixes.

#### Scenario: Short name and long name agree
- **WHEN** a grant is given using an 8.3 short name for a directory
- **THEN** the enforced and displayed policy refers to the same directory as its long name

#### Scenario: Junction target outside grants
- **WHEN** a granted directory contains a junction pointing to an ungranted directory and the workload accesses it
- **THEN** access through the junction is decided by the junction target's own grant status, and here it is denied

#### Scenario: Drive-relative path rejected
- **WHEN** a grant is given as a drive-relative path such as `C:project`
- **THEN** the grant is rejected with an error and no process is created

#### Scenario: UNC share rejected
- **WHEN** a grant names a network share such as `\\server\share\repo`
- **THEN** the grant is rejected with an error stating that network paths are unsupported

### Requirement: Alternate data streams follow their file
Access to an alternate data stream SHALL be allowed or denied exactly as
access to the file that holds it. A grant SHALL NOT be expressible on a
stream name alone.

#### Scenario: Stream of ungranted file
- **WHEN** the workload opens `secret.txt:stream` where `secret.txt` is not granted
- **THEN** the open is denied

#### Scenario: Grant naming a stream
- **WHEN** a capability set contains a grant whose path names an alternate data stream
- **THEN** the grant is rejected with an error

### Requirement: Displayed policy matches enforced policy
The rendered policy that the library reports for a Windows launch SHALL list
the same normalized paths and access modes that were passed to the native
isolation policy. It SHALL also list the host-required system grants the
backend added.

#### Scenario: Rendered grants
- **WHEN** a caller renders the policy for a capability set before launch
- **THEN** every path and access mode in the rendering corresponds to a native policy entry and vice versa

### Requirement: Enumerate-only grants are explicit
Enumerate-only grants SHALL never permit reading file contents. Because an
enumerate grant on a volume root exposes the name of every file on that
volume, the CLI SHALL NOT add such grants unless the user asks for them. The
rendered policy SHALL warn whenever a volume root is enumerated.

#### Scenario: Default run adds no enumerate grants
- **WHEN** a user runs `nono run` without requesting ancestor enumeration
- **THEN** the rendered policy contains no enumerate entries

#### Scenario: Volume-root enumeration is rendered with a warning
- **WHEN** a user requests ancestor enumeration
- **THEN** the rendered policy lists the volume root and states that every file name on the volume becomes visible

#### Scenario: Enumerate never reads content
- **WHEN** a workload with a volume-root enumerate grant reads an ungranted file
- **THEN** the read is denied
