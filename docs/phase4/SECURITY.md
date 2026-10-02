# RiftRoute Phase 4 — Security & Threat Model

## 1. Core Security Invariants

The security model of the RiftRoute Relay architecture is governed by three strict principles:

1. **Passive Diagnostic Role Only**:
   The relay daemon operates exclusively as an out-of-band diagnostic probe server. It has zero capability to alter host routing tables, intercept UDP gaming sockets, or proxy user payload traffic.
2. **Zero Shell Execution**:
   Under no circumstances is a system shell (`/bin/sh`, `/bin/bash`, `cmd.exe`, or `powershell.exe`) spawned. All external diagnostic utilities (`ping`) are invoked via explicit executable paths and structured parameter arrays (`Command::new("ping")`), rendering shell injection impossible.
3. **Mutual Cryptographic Authentication**:
   All control sessions require mutual Ed25519 identity verification prior to executing any diagnostic action.

---

## 2. Threat Analysis & Mitigations

### 2.1 Unauthorized Relay Utilization & Resource Theft
- **Threat**: An arbitrary third party discovers the relay control port and utilizes it to perform distributed network scanning or denial of service attacks.
- **Mitigation**:
  - The relay maintains an explicit whitelist of authorized clients in [config.json](file:///d:/network%20optimiser/data/relay/config.json).
  - Unauthenticated connections are dropped immediately.
  - Rate limiting (sliding window per-IP) enforces strict request thresholds (e.g. max 120 req/min).
  - Concurrency is capped by `max_concurrent_jobs` (default: 5).

### 2.2 Replay Attacks & Man-in-the-Middle (MITM)
- **Threat**: An eavesdropper captures an authentication handshake and replays the signed response to open an unauthorized session.
- **Mitigation**:
  - The relay generates a 256-bit cryptographically secure pseudorandom nonce (`challenge_nonce`).
  - The client signs a canonical string binding the nonce, relay ID, and client ID:
    `riftroute_auth:<challenge_nonce>:<relay_id>:<client_id>`
  - Nonces have a strict time-to-live (TTL: 30 seconds) and are permanently destroyed upon first verification attempt.
  - The client verifies the relay's public key fingerprint against its pinned registry before signing.

### 2.3 SSRF & Internal Network Probing
- **Threat**: A client requests the relay to probe `127.0.0.1`, cloud metadata services (`169.254.169.254`), or private internal subnets (`10.0.0.0/8`, `192.168.0.0/16`).
- **Mitigation**:
  - Target destination validation checks for private, loopback, link-local, and broadcast IP ranges.
  - Any request targeting an internal or private address is rejected with `RelayFailureMode::InvalidMeasurementRequest` unless explicit test mode (`allow_private_targets: true`) is enabled on a development node.

### 2.4 Metacharacter & Flag Injection
- **Threat**: An attacker supplies input such as `8.8.8.8; rm -rf /` or `-n 1000 8.8.8.8` to exploit parser vulnerabilities.
- **Mitigation**:
  - `RelayMeasurementEngine::validate_destination` strips leading hyphens to prevent command-line flag injection.
  - It checks all input characters against a strict rejection list of shell metacharacters: `;`, `&`, `|`, `` ` ``, `$`, `\`, `>`, `<`, `"`, `'`, `*`, `?`, `~`, `!`, `\n`, `\r`, `\t`.

---

## 3. Explicit Failure Modes (Step 23)

Ten explicit failure modes are defined in [`RelayFailureMode`](file:///d:/network%20optimiser/core/rust/rift-relay/src/models.rs#L115-L126):

| Failure Mode | Description | Trigger Condition |
| :--- | :--- | :--- |
| `RelayOffline` | Target relay unreachable | Connection refused or TCP timeout |
| `ControlChannelTimeout` | Protocol framing timeout | Socket read/write exceeds deadline |
| `AuthenticationFailure` | Handshake rejected | Unknown client ID or bad Ed25519 signature |
| `InvalidMeasurementRequest` | Unsafe target specified | Metacharacters, flags, or private IP |
| `DestinationUnreachable` | Probe target dead | 100% packet loss reported by ping |
| `RelayMeasurementTimeout` | Measurement hung | Probe execution exceeded timeout limit |
| `MalformedResponse` | Protocol violation | Invalid length header or unparsable JSON |
| `ProtocolVersionMismatch` | Protocol version conflict | Client requested incompatible protocol version |
| `IdentityMismatch` | MITM or key mismatch | Server public key does not match pinned fingerprint |
| `RateLimitExceeded` | Too many requests | Client exceeded rate limits or max active jobs |
