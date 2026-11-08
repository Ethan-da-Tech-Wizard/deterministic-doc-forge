## Security Architecture & STRIDE Threat Model

Formal threat analysis for **AegisGate API Security Gateway** conducted under the Microsoft STRIDE security assessment methodology.

### 1. Identified Trust Boundaries
Data crossing these logical and physical perimeter boundaries requires explicit validation:
- [x] **Boundary:** Untrusted Public Internet <-> Edge Ingress Router (TLS 1.3 Termination)
- [x] **Boundary:** Edge Ingress Router <-> Internal Zero-Trust VPC Network
- [x] **Boundary:** Policy Decision Engine <-> Shared Redis Cache / OPA Policy Store
- [x] **Boundary:** Audit Stream Publisher <-> Kafka Broker Cluster

### 2. Foundational Security Assumptions
- [i] Cluster nodes possess hardware-backed TPM 2.0 or SPIRE-issued X.509 SVID certificates.
- [i] Internal Kubernetes control plane and API server communications are isolated over dedicated VPC subnets.
- [i] Network Time Protocol (NTP) daemons maintain cluster clock synchronization within +/- 15ms.

### 3. STRIDE Threat & Mitigation Matrix
| ID | Category | Target Component | Threat Scenario | Risk Level | Mitigation Status |
|:---|:---|:---|:---|:---:|:---:|
| **THREAT-E-01** | _Elevation of Privilege_ | `PolicyDecisionEngine` | RBAC Role Injection via Manipulated Header Propagation | `CRITICAL` | **IMPLEMENTED** |
| **THREAT-I-01** | _Information Disclosure_ | `PolicyDecisionEngine` | Tenant Attribute Leakage via Shared Cache Key Collisions | `CRITICAL` | **IMPLEMENTED** |
| **THREAT-S-01** | _Spoofing_ | `TokenValidatorService` | Cryptographic Token Forgery via Algorithm Switching or Key Confusion | `CRITICAL` | **IMPLEMENTED** |
| **THREAT-D-01** | _Denial of Service_ | `EdgeIngressRouter` | Algorithmic Complexity / Slowloris Connection Exhaustion Attack | `HIGH` | **IMPLEMENTED** |
| **THREAT-T-01** | _Tampering_ | `AuditStreamPublisher` | Audit Telemetry Modification or Record Deletion in Transit | `HIGH` | **IMPLEMENTED** |
| **THREAT-R-01** | _Repudiation_ | `AuditStreamPublisher` | Denial of High-Privilege Administrative Actions | `MEDIUM` | **IMPLEMENTED** |


### 4. Deep-Dive Threat Vector Analysis
### Threat THREAT-E-01: RBAC Role Injection via Manipulated Header Propagation

- **STRIDE Category:** `Elevation of Privilege`
- **Impacted Component:** `PolicyDecisionEngine`
- **Assessed Severity:** `CRITICAL`
- **Implementation Status:** `IMPLEMENTED`

**Attack Narrative & Exploitation Mechanism:**
An external user injects an internal header (e.g. `X-Admin-Role: superuser`) that passes through the edge proxy unfiltered to upstream services.

**Business & System Impact:** Unprivileged external user gains administrative access to internal microservices.

**Engineering Mitigation & Defense Controls:**
> EdgeIngressRouter sanitizes and strips all `X-*` and internal routing headers from incoming external requests. Internal headers are only populated and forwarded downstream after cryptographic policy verification.


---

### Threat THREAT-I-01: Tenant Attribute Leakage via Shared Cache Key Collisions

- **STRIDE Category:** `Information Disclosure`
- **Impacted Component:** `PolicyDecisionEngine`
- **Assessed Severity:** `CRITICAL`
- **Implementation Status:** `IMPLEMENTED`

**Attack Narrative & Exploitation Mechanism:**
Multi-tenant authorization attributes stored in shared Redis memory are accessed by another tenant due to missing or predictable tenant namespace key prefixes.

**Business & System Impact:** Cross-tenant data breach violating GDPR and HIPAA regulations.

**Engineering Mitigation & Defense Controls:**
> Redis keys are strictly namespaced using cryptographic tenant hash prefixes (e.g., `tenant:<sha256(tenant_id)>:user:<uid>`), with OPA policies enforcing tenant boundary verification at the bytecode level.


---

### Threat THREAT-S-01: Cryptographic Token Forgery via Algorithm Switching or Key Confusion

- **STRIDE Category:** `Spoofing`
- **Impacted Component:** `TokenValidatorService`
- **Assessed Severity:** `CRITICAL`
- **Implementation Status:** `IMPLEMENTED`

**Attack Narrative & Exploitation Mechanism:**
An adversary crafts an authorization token with 'alg': 'none' or substitutes an RSA public key into an HMAC verification routine (CVE-2015-9235 style key confusion) to impersonate service accounts.

**Business & System Impact:** Full privilege escalation, unauthorized API access, and cross-tenant data exfiltration.

**Engineering Mitigation & Defense Controls:**
> TokenValidatorService enforces an explicit algorithm allowlist (Ed25519/ES256 only), strictly prohibits 'none', and isolates public verification keys from symmetric HMAC secret paths.


---

### Threat THREAT-D-01: Algorithmic Complexity / Slowloris Connection Exhaustion Attack

- **STRIDE Category:** `Denial of Service`
- **Impacted Component:** `EdgeIngressRouter`
- **Assessed Severity:** `HIGH`
- **Implementation Status:** `IMPLEMENTED`

**Attack Narrative & Exploitation Mechanism:**
An attacker establishes thousands of slow-writing HTTP/2 streams, holding file descriptors open and exhausting proxy thread pools.

**Business & System Impact:** Edge gateway becomes unresponsive to legitimate customer requests; SLA breach.

**Engineering Mitigation & Defense Controls:**
> Strict connection timeouts (idle timeout: 4s, header read timeout: 2s), per-IP connection limits (max 50 concurrent streams), and automatic eBPF/XDP packet dropping for abusive source IPs.


---

### Threat THREAT-T-01: Audit Telemetry Modification or Record Deletion in Transit

- **STRIDE Category:** `Tampering`
- **Impacted Component:** `AuditStreamPublisher`
- **Assessed Severity:** `HIGH`
- **Implementation Status:** `IMPLEMENTED`

**Attack Narrative & Exploitation Mechanism:**
A rogue process inside the VPC intercepts unencrypted gRPC audit records and modifies transaction IDs or amounts before compliance log aggregation.

**Business & System Impact:** Falsification of regulatory compliance records resulting in SOC2 and PCI-DSS audit failure.

**Engineering Mitigation & Defense Controls:**
> All audit events are cryptographically hashed using HMAC-SHA256 at the point of origin. Kafka brokers require mutual TLS and enforce strict SASL/SCRAM write-only ACLs on audit topics.


---

### Threat THREAT-R-01: Denial of High-Privilege Administrative Actions

- **STRIDE Category:** `Repudiation`
- **Impacted Component:** `AuditStreamPublisher`
- **Assessed Severity:** `MEDIUM`
- **Implementation Status:** `IMPLEMENTED`

**Attack Narrative & Exploitation Mechanism:**
An authorized administrator performs destructive configuration modifications and claims the action was executed by an automated script or third party.

**Business & System Impact:** Inability to assign legal and security accountability during post-incident forensics.

**Engineering Mitigation & Defense Controls:**
> Every mutating request requires a signed client certificate containing an immutable SPIFFE ID, tied to non-repudiable audit logs backed by Amazon S3 Object Lock (WORM storage).

---
<!-- DOCFORGE-SHA256: 98004740f37d38b57fbd67dec4f4a5fd1359dee4553098e35ebc4f886bc2a2f8 -->
**DocForge Cryptographic Audit Stamp:** `SHA256:98004740f37d38b57fbd67dec4f4a5fd1359dee4553098e35ebc4f886bc2a2f8`  
_Generated deterministically by DocForge. Any manual modification invalidates CI/CD verification._
