# DocForge 🛠️

> **Zero-Dependency Deterministic Technical Documentation & Architecture Defense Engine**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-3776ab.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-success.svg?style=flat)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-22%20passed%20%7C%20100%25-brightgreen.svg?style=flat)](#)
[![Security: STRIDE](https://img.shields.io/badge/security-STRIDE%20threat%20modeled-blueviolet.svg?style=flat)](#)
[![CI/CD: SHA--256 Verified](https://img.shields.io/badge/CI%2FCD-SHA--256%20gated-orange.svg?style=flat)](#)

---

## ⚡ The Problem: Architecture Documentation Rot & Interview Amnesia

In software engineering, documentation suffers from three fatal problems:
1. **Architectural Archeology:** Teams reverse good architectural decisions because the historical context, constraints, and evaluated alternatives were never formally recorded in Architectural Decision Records (ADRs).
2. **Security Compliance Theater:** Threat models are created as stale slide decks during initial audits, completely detached from codebase realities and CI/CD pipelines.
3. **The "Staff-Plus Interview Wall":** Senior and Lead engineers who design and ship complex distributed systems often struggle to defend their systems during high-stakes technical interviews (L5/L6/L7 panels, Architecture Review Boards, CISO reviews) because their accomplishments aren't structured into quantified STAR narratives and rapid-fire trade-off defenses.

**DocForge solves this with code.**

DocForge takes a structured JSON specification of your system and **deterministically compiles** it into:
- 📄 **Formal Architectural Whitepapers** with Document IDs, component inventories, and verification gates.
- 📐 **Directed Acyclic Graph (DAG) Topologies** rendered in both **pure ASCII box art** and **Mermaid flowcharts**.
- 🛡️ **Formal STRIDE Threat Models** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) with automated risk weights and mitigation matrices.
- 📋 **Michael Nygard ADR Logs** with lifecycle validation and circular supersede detection.
- 🎯 **Amazon STAR Interview Guides & Technical Defense Q&A** with quantified metrics (throughput, p99 latency, cost) and traps to avoid.
- 🔒 **Cryptographic SHA-256 Fingerprinting** so any manual tampering fails CI/CD verification gates.

**Best of all? Zero external dependencies. Pure Python 3 standard library.** Anyone with Python 3.9+ can clone and run it instantly.

---

## 🚀 Quick Start (Under 30 Seconds)

No `pip install`, no virtualenv required:

```bash
# 1. Clone the repository
git clone https://github.com/Ethan-da-Tech-Wizard/deterministic-doc-forge.git
cd deterministic-doc-forge

# 2. Run the test suite (100% standard library unittest)
python3 -m unittest discover -s tests -v

# 3. Compile the enterprise sample project
python3 -m docforge build -i examples/sample_project.json -o docs/
```

This compiles:
- `docs/WHITEPAPER.md` (Authoritative system architecture whitepaper)
- `docs/ADR_LOG.md` (Michael Nygard decision log)
- `docs/THREAT_MODEL.md` (Full STRIDE risk matrix and mitigation catalog)
- `docs/STAR_INTERVIEW_GUIDE.md` (L5/L6 behavioral and system defense guide)

---

## 📦 What DocForge Generates

### 1. Pure ASCII Component Topologies (DAG)
DocForge uses **Kahn's Algorithm** to compute topological execution layers, detecting circular dependency deadlocks and rendering terminal-safe diagrams:

```text
+----------------------------------------------------------------+
|                SYSTEM COMPONENT TOPOLOGY (DAG)                 |
+----------------------------------------------------------------+
|  Layer 0 (Topological Tier)                                     |
|  +-- [ EdgeIngressRouter ] [INGRESS] (Rust, Envoy Data Plane)  |
|        |                                                       |
|        v  [ downstream dependencies / async events ]           |
|        |                                                       |
|  Layer 1 (Topological Tier)                                     |
|  +-- [ TokenValidatorService ] [AUTHENTICATION] (Go, Ed25519)  |
|        |                                                       |
|        v  [ downstream dependencies / async events ]           |
|        |                                                       |
|  Layer 2 (Topological Tier)                                     |
|  +-- [ PolicyDecisionEngine ] [AUTHORIZATION] (OPA, Redis)     |
|        |                                                       |
|        v  [ downstream dependencies / async events ]           |
|        |                                                       |
|  Layer 3 (Topological Tier)                                     |
|  +-- [ AuditStreamPublisher ] [OBSERVABILITY] (Apache Kafka)   |
|  +-- [ UpstreamWorkloadProxy ] [EGRESS] (gRPC, HTTP/2)         |
+----------------------------------------------------------------+
```

### 2. STRIDE Threat & Mitigation Matrices
Categorizes threats across all six STRIDE vectors with qualitative risk scoring:

| ID | Category | Target Component | Threat Scenario | Risk Level | Mitigation Status |
|:---|:---|:---|:---|:---:|:---:|
| **THREAT-S-01** | _Spoofing_ | `TokenValidatorService` | Cryptographic Token Forgery via Key Confusion | `CRITICAL` | **IMPLEMENTED** |
| **THREAT-I-01** | _Information Disclosure_ | `PolicyDecisionEngine` | Tenant Attribute Leakage via Shared Cache Key Collisions | `CRITICAL` | **IMPLEMENTED** |
| **THREAT-E-01** | _Elevation of Privilege_ | `PolicyDecisionEngine` | RBAC Role Injection via Manipulated Header Propagation | `CRITICAL` | **IMPLEMENTED** |
| **THREAT-D-01** | _Denial of Service_ | `EdgeIngressRouter` | Algorithmic Complexity / Slowloris Connection Exhaustion | `HIGH` | **IMPLEMENTED** |
| **THREAT-T-01** | _Tampering_ | `AuditStreamPublisher` | Audit Telemetry Modification in Message Pipeline | `HIGH` | **IMPLEMENTED** |
| **THREAT-R-01** | _Repudiation_ | `AuditStreamPublisher` | Denial of High-Privilege Administrative Actions | `MEDIUM` | **IMPLEMENTED** |

### 3. Amazon STAR Interview Guides
Synthesizes your real system metrics into structured L5/L6 behavioral narratives:

> #### Story [STAR-01]: Scaling AegisGate Ingress to 250,000 QPS with Sub-5ms p99 Latency
> **Target Competency:** `Distributed Systems Architecture & Performance Engineering`
>
> **Quantified Impact (The 'R' Metrics):**
> - **Peak Throughput:** `260,000 RPS`
> - **p99 Latency:** `4.2 ms (down from 450 ms)`
> - **Memory Footprint:** `Reduced by 85% per pod`
> - **Annual Cost Savings:** `$180,000 / year`
> - **Availability:** `99.999% across 4 global regions`
>
> **Situation:** Legacy API gateway suffered from severe tail latency amplification during peak e-commerce sales. p99 latencies exceeded 450ms, memory leaks caused 12 OOM crashes weekly...  
> **Task:** Lead architect mandated to redesign ingress data plane to sustain 250k QPS with p99 < 5ms and 99.999% availability...  
> **Action:** Engineered high-performance Rust/Envoy core, 2-tier local L1 LRU + Redis cluster cache resolving 95% of auth checks in <80µs, migrated to Ed25519 elliptic curve tokens...  
> **Result:** Scaled peak throughput to 260k QPS, p99 dropped 99% to 4.2ms, infrastructure costs cut by $180k/yr...

### 4. Technical Defense Q&A
Equips you to survive adversarial probes during system design reviews:

> **Q: "What happens if the PolicyDecisionEngine cluster crashes or partitions?"**  
> **Senior Defense:** We enforce a fail-secure architecture with local sidecar caching. Each edge proxy retains a read-only local L1 LRU cache of authorization decisions (TTL 10s). If the centralized decision engine is unreachable, cached valid sessions continue to serve. For un-cached or mutating requests (POST/PUT/DELETE), the gateway immediately returns HTTP 503.  
> ⚠️ **Trap to Avoid:** Do not answer "we fail-open to preserve user experience". In financial, healthcare, or security systems, failing open is a catastrophic architectural flaw that allows attackers to DoS policy engines to bypass all access controls.

### 5. Cryptographic SHA-256 Audit Stamp
Every generated document embeds an immutable signature block:

```markdown
---
<!-- DOCFORGE-SHA256: 0de46d66a02962813a4ccf4c38896eb5f2f054bc2d049b0645745b6c030b388a -->
**DocForge Cryptographic Audit Stamp:** `SHA256:0de46d66a02962813a4ccf4c38896eb5f2f054bc2d049b0645745b6c030b388a`  
_Generated deterministically by DocForge. Any manual modification invalidates CI/CD verification._
```

---

## 💻 CLI Reference

### 1. `docforge build`
Compiles an architecture specification into Markdown documentation:

```bash
# Build all documents into the docs/ directory
python3 -m docforge build -i spec.json -o docs/

# Build only the STRIDE threat model
python3 -m docforge build -i spec.json -o docs/ --format stride

# Output whitepaper directly to stdout for piping
python3 -m docforge build -i spec.json --stdout | pandoc -o whitepaper.pdf
```

### 2. `docforge init`
Scaffolds a comprehensive, production-grade starter specification:

```bash
# Scaffold microservice architecture spec
python3 -m docforge init -o my_architecture.json

# Force overwrite existing spec
python3 -m docforge init -o my_architecture.json --force
```

### 3. `docforge validate`
Performs static analysis on architecture specifications:
- Identifies circular dependencies in component graphs (cycles).
- Detects CRITICAL or HIGH threats lacking concrete mitigations.
- Catches broken or circular ADR supersede references.

```bash
python3 -m docforge validate -i my_architecture.json
```

### 4. `docforge verify-hash`
Validates cryptographic document integrity in CI/CD pipelines. Returns exit code `0` on match, `1` on mismatch or tampering:

```bash
python3 -m docforge verify-hash -f docs/WHITEPAPER.md
```

---

## 🛡️ CI/CD Integration (GitHub Actions)

Add this workflow to `.github/workflows/architecture-gate.yml` to prevent undocumented architecture changes:

```yaml
name: Architecture Verification Gate

on:
  pull_request:
    branches: [main]

jobs:
  verify-architecture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Run Test Suite
        run: python3 -m unittest discover -s tests -v

      - name: Validate Architecture Specification
        run: python3 -m docforge validate -i examples/sample_project.json

      - name: Check Documentation Cryptographic Integrity
        run: |
          python3 -m docforge verify-hash -f docs/WHITEPAPER.md
          python3 -m docforge verify-hash -f docs/THREAT_MODEL.md
          python3 -m docforge verify-hash -f docs/ADR_LOG.md
```

---

## 🏛️ Code Architecture & Design Walkthrough

Every single file in DocForge is heavily commented with line-by-line educational breakdowns:

```
docforge/
├── __init__.py      # Package metadata, SemVer, and clean public symbol exports
├── models.py        # Strongly-typed dataclasses for ArchSpec, ADR, ThreatModel, STAR
├── engine.py        # Kahn's DAG topological sort, ASCII/Mermaid renderer, SHA-256 hasher
├── adr.py           # Michael Nygard ADR lifecycle manager & supersede chain validator
├── stride.py        # Microsoft STRIDE threat analyzer, risk weight scoring, matrix compiler
├── star.py          # Amazon STAR interview synthesizer & technical defense Q&A formatter
├── cli.py           # POSIX CLI argument parser, standard streams, exit code dispatching
└── __main__.py      # Module entrypoint enabling direct `python3 -m docforge` execution
```

### Key Engineering Patterns Demonstrated:
1. **Topological Ordering ($O(V + E)$):** Kahn's in-degree decrementing algorithm cleanly separates ingress from deep backend tiers and flags cycles before compilation.
2. **Canonical Text Normalization:** Multi-platform determinism via unified newline translation (`\r\n` -> `\n`), trailing whitespace trimming, and sorted key hashing.
3. **Zero Third-Party Attack Surface:** Eliminates `pip` transitive CVEs and supply-chain vulnerabilities in high-security build pipelines.

---

## 🧪 Running Tests

DocForge comes with an exhaustive unit test suite covering 100% of modules:

```bash
python3 -m unittest discover -s tests -v
```

Output:
```text
test_adr_lifecycle_validation_and_cycles ... ok
test_circular_supersede_detection ... ok
test_duplicate_adr_id_rejected ... ok
test_render_summary_table ... ok
test_cli_build_and_verify_hash ... ok
test_cli_init_and_validate ... ok
test_cli_sample_project_json ... ok
test_canonicalize_and_hash ... ok
test_embed_and_verify ... ok
test_tamper_detection ... ok
test_ascii_and_mermaid_rendering ... ok
test_cycle_detection ... ok
test_topological_sort_linear ... ok
test_adr_instantiation_and_validation ... ok
test_adr_status_lifecycle ... ok
test_archspec_full_serialization ... ok
test_component_validation ... ok
test_threat_models_and_risk_scoring ... ok
test_render_defense_qa ... ok
test_render_star_story ... ok
test_statistics_and_table_rendering ... ok
test_unmitigated_critical_threat_flagged ... ok

----------------------------------------------------------------------
Ran 22 tests in 0.009s

OK
```

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for full details.

Built by **Ethan Kilmer** ([ethan@twu.software](mailto:ethan@twu.software)).
