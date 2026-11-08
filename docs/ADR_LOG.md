## Architectural Decision Records (ADRs)

This log captures foundational design choices, evaluated alternatives, and accepted trade-offs governing the system.

| ID | Decision Title | Status | Date | Superseded By |
|:---|:---|:---:|:---:|:---|
| **ADR-001** | Adopt Rust and Envoy for Gateway Data Plane over Java/Node.js | `ACCEPTED` | 2026-01-14 | - |
| **ADR-002** | Adopt Append-Only Kafka Streaming for Regulatory Audit Telemetry | `ACCEPTED` | 2026-02-02 | - |
| **ADR-003** | Two-Tier Policy Caching (Local LRU + Redis Cluster) for Sub-Millisecond Auth | `ACCEPTED` | 2026-03-10 | - |
| **ADR-004** | Migrate from RSA-2048 to Ed25519 Elliptic Curve Signatures for Microservice Tokens | `ACCEPTED` | 2026-04-18 | - |


### ADR-001: Adopt Rust and Envoy for Gateway Data Plane over Java/Node.js

- **Status:** `ACCEPTED`
- **Decision Date:** `2026-01-14`

#### 1. Context & Problem Statement
Our previous ingress proxy was implemented in Java/Netty. Under 150k RPS peak traffic, garbage collection (GC) stop-the-world pauses caused p99 tail latency spikes to exceed 320ms, triggering client-side timeouts. We needed a runtime with zero GC overhead, predictable memory usage, and memory-safe semantics.

#### 2. Architectural Decision
Re-architect the core edge ingress router in Rust using Envoy's C++ data plane and custom Rust WebAssembly / native filters. Rust provides zero-cost abstractions, deterministic memory deallocation (RAII), and compile-time concurrency safety.

#### 3. Consequences & Trade-offs
**Positive Impacts (Benefits):**
- [x] Eliminated all GC pauses, cutting p99 tail latency from 320ms to 4.2ms.
- [x] Reduced memory footprint from 4.8 GiB to 420 MiB per container pod replica.
- [x] Zero vulnerability to memory corruption CVEs (buffer overflows, use-after-free).

**Negative Impacts (Accepted Costs & Operational Overhead):**
- [!] Increased developer ramp-up time for engineers unfamiliar with the Rust borrow checker.
- [!] CI build and compilation times increased by ~3.5 minutes.

**Neutral / Structural Impacts:**
- [i] Enforced automated Cargo Clippy and ASAN (AddressSanitizer) checks in PR gates.


---

### ADR-002: Adopt Append-Only Kafka Streaming for Regulatory Audit Telemetry

- **Status:** `ACCEPTED`
- **Decision Date:** `2026-02-02`

#### 1. Context & Problem Statement
Direct synchronous logging of security decisions to relational databases (PostgreSQL) created severe write contention, leading to database connection pool exhaustion and gateway request throttling during traffic bursts.

#### 2. Architectural Decision
Decouple audit trail generation from synchronous request serving. Security events are pushed asynchronously to an append-only Apache Kafka cluster with tenant-keyed partitioning and HMAC-SHA256 tamper-evident digital signatures.

#### 3. Consequences & Trade-offs
**Positive Impacts (Benefits):**
- [x] Complete write isolation: Zero impact on ingress request latency.
- [x] Guaranteed linearizable event ordering per tenant ID partition.
- [x] Replayability: Downstream security analytics and fraud detection systems can rewind and replay logs.

**Negative Impacts (Accepted Costs & Operational Overhead):**
- [!] Audit logs are eventually consistent (typical propagation lag of 120ms to warehouse).
- [!] Requires operational monitoring of Kafka consumer group lag and disk capacity.

**Neutral / Structural Impacts:**
- [i] Configured 14-day retention window on NVMe broker storage.


---

### ADR-003: Two-Tier Policy Caching (Local LRU + Redis Cluster) for Sub-Millisecond Auth

- **Status:** `ACCEPTED`
- **Decision Date:** `2026-03-10`

#### 1. Context & Problem Statement
Evaluating complex OPA Rego policies against remote Redis instances over the network added an unacceptable 1.8ms network round-trip time per request, exhausting internal VPC connection pools.

#### 2. Architectural Decision
Implement a 2-tier caching architecture: Tier 1 is an in-memory lock-free LRU cache located directly inside each proxy worker thread (TTL 10s, 95% hit rate). Tier 2 is a centralized Redis cluster for cross-pod synchronization with Redis Pub/Sub for active cache invalidation upon policy updates.

#### 3. Consequences & Trade-offs
**Positive Impacts (Benefits):**
- [x] 95% of authorization evaluations resolve in local memory in under 80 microseconds.
- [x] Reduced Redis cluster query load by 20x, saving $45,000/yr in cloud caching costs.

**Negative Impacts (Accepted Costs & Operational Overhead):**
- [!] Potential 10-second cache inconsistency window if a Redis invalidation Pub/Sub packet is lost.
- [!] Increased per-pod memory consumption for the L1 cache ring buffer (capped at 64 MiB).

**Neutral / Structural Impacts:**
- [i] Emergency revocation API bypasses L1 cache via an explicit cache-busting header.


---

### ADR-004: Migrate from RSA-2048 to Ed25519 Elliptic Curve Signatures for Microservice Tokens

- **Status:** `ACCEPTED`
- **Decision Date:** `2026-04-18`

#### 1. Context & Problem Statement
RSA-2048 cryptographic signature validation consumed 38% of gateway CPU cycles during peak traffic, requiring aggressive pod autoscaling solely for cryptographic verification.

#### 2. Architectural Decision
Transition all internal service-to-service identity tokens to Ed25519 (EdDSA) elliptic curve signatures. Ed25519 provides equivalent 128-bit cryptographic security with 32-byte public keys and 64-byte signatures, executing signature verification 4.5x faster than RSA-2048.

#### 3. Consequences & Trade-offs
**Positive Impacts (Benefits):**
- [x] 4.5x faster cryptographic signature verification, reducing gateway CPU utilization by 26%.
- [x] Significantly smaller HTTP Authorization header payload size (saves ~1.2 KiB per request).

**Negative Impacts (Accepted Costs & Operational Overhead):**
- [!] Legacy client SDKs required upgrading to libraries supporting Edwards-curve Digital Signature Algorithm (RFC 8032).

**Neutral / Structural Impacts:**
- [i] Dual-verification window maintained for 60 days to allow gradual client SDK migration.

---
<!-- DOCFORGE-SHA256: bf5e92c9bd6e04e54c76318475b7233ba0700eccccad2283efe585cd76c2f421 -->
**DocForge Cryptographic Audit Stamp:** `SHA256:bf5e92c9bd6e04e54c76318475b7233ba0700eccccad2283efe585cd76c2f421`  
_Generated deterministically by DocForge. Any manual modification invalidates CI/CD verification._
