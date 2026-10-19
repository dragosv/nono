# Spec Delta

## Purpose

Defines network confinement for Windows workloads, covering blocked and
proxy-only modes enforced by the OS on the workload and its descendants
without affecting other processes on the host.

## ADDED Requirements

### Requirement: Blocked network mode
When the network mode is blocked, the workload and its descendants SHALL be
unable to send or receive network traffic over IPv4 or IPv6, by TCP or UDP,
including DNS queries to any resolver. The only exception is the loopback
traffic the backend documents as required for the process to run.

#### Scenario: Direct TCP egress
- **WHEN** a workload in blocked mode opens a TCP connection to a public IPv4 or IPv6 address
- **THEN** the connection is refused or fails

#### Scenario: UDP and DNS
- **WHEN** a workload in blocked mode sends a UDP datagram or a DNS query to an external resolver
- **THEN** the traffic does not leave the host

### Requirement: Proxy-only network mode
When the network mode is proxy-only, the workload and its descendants SHALL
be able to connect to the authorized proxy endpoint only. Every other
destination SHALL be refused, on IPv4 and IPv6, by TCP and UDP. That includes
other loopback ports and DNS sent directly to any resolver. This SHALL hold
even if the workload ignores proxy environment variables.

#### Scenario: Authorized proxy reachable
- **WHEN** a workload in proxy-only mode connects to the authorized proxy endpoint
- **THEN** the connection succeeds

#### Scenario: Direct bypass refused
- **WHEN** a workload in proxy-only mode ignores the proxy variables and connects directly to a public address
- **THEN** the connection is refused or fails

#### Scenario: Other loopback listener refused
- **WHEN** a workload in proxy-only mode connects to a loopback port other than the authorized proxy endpoint
- **THEN** the connection is refused or fails

### Requirement: System resolver exposure is explicit
In proxy-only mode, the rendered policy SHALL state whether name lookups
through the host's system resolver remain available to the workload. On
current PSEC hosts they do, as with nono's default macOS resolver grants.
When the capability set asks for DNS to be blocked and the backend cannot
block the system resolver, the launch SHALL fail.

#### Scenario: DNS block requested in proxy-only mode
- **WHEN** a proxy-only capability set requests DNS blocking on a host where system resolver lookups cannot be blocked
- **THEN** the launch fails with an error naming DNS blocking

#### Scenario: Resolver exposure rendered
- **WHEN** a caller renders the policy for a proxy-only launch
- **THEN** the rendering states that system resolver lookups remain available

#### Scenario: Blocked mode resolves nothing
- **WHEN** a workload in blocked mode looks up a name through the system resolver
- **THEN** the lookup fails

### Requirement: Proxy applies domain policy
In proxy-only mode, destination host filtering and credential injection
SHALL be performed by `nono-proxy` outside the workload's confinement, using
the same policy semantics as on Linux and macOS.

#### Scenario: Allowed domain
- **WHEN** a proxy-only workload requests an allowed domain through the proxy
- **THEN** the proxy forwards the request upstream

#### Scenario: Disallowed domain
- **WHEN** a proxy-only workload requests a domain the proxy policy does not allow
- **THEN** the proxy refuses the request

### Requirement: Proxy listener requires session authentication
The proxy endpoint reachable from a workload SHALL accept only requests that
present that session's proxy credential. The credential SHALL NOT appear in
logs, errors or diagnostics.

#### Scenario: Unauthenticated local client
- **WHEN** a process without the session credential sends a request to the proxy listener
- **THEN** the proxy rejects the request

### Requirement: Inbound port grants not silently dropped
If the capability set requests inbound bind or listen ports, or localhost
IPC ports, that the backend cannot enforce with per-port fidelity, the launch
SHALL fail with an error. It SHALL NOT allow broader access, and it SHALL NOT
ignore the request.

#### Scenario: Proxy-only with bind ports
- **WHEN** a proxy-only capability set includes bind ports and the backend has no per-port ingress enforcement
- **THEN** the launch fails with an error naming the unsupported bind ports

### Requirement: Descendants inherit network policy
Every process the workload starts, directly or indirectly, SHALL be subject
to the same network policy as the workload.

#### Scenario: Grandchild direct egress
- **WHEN** a grandchild of a proxy-only workload connects directly to a public address
- **THEN** the connection is refused or fails

### Requirement: Host processes unaffected
Network policy applied to a confined workload SHALL NOT restrict network
access of processes outside that workload's isolation context.

#### Scenario: Host process during confined run
- **WHEN** a blocked-mode workload is running and an unconfined host process opens an outbound connection
- **THEN** the host process's connection succeeds as it would without nono

### Requirement: Concurrent runs are separated
Two confined workloads running at the same time SHALL each be subject only
to their own network policy and proxy endpoint.

#### Scenario: Two proxies, two policies
- **WHEN** workload A is proxy-only to proxy A and workload B is proxy-only to proxy B
- **THEN** A cannot connect to proxy B and B cannot connect to proxy A

### Requirement: Network policy released with the context
Network policy created for a workload SHALL be removed when its isolation
context is released, including after abnormal termination of the caller.

#### Scenario: Caller crash
- **WHEN** the process that launched the workload terminates abnormally
- **THEN** the network policy for that workload does not persist after the isolation context ends
