# DocForge 🛠️

> **Zero-Dependency Deterministic Technical Documentation & Architecture Defense Engine**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-3776ab.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-success.svg?style=flat)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE)

[![Security: STRIDE](https://img.shields.io/badge/security-STRIDE%20threat%20modeled-blueviolet.svg?style=flat)](#)
[![CI/CD: SHA--256 Verified](https://img.shields.io/badge/CI%2FCD-SHA--256%20gated-orange.svg?style=flat)](#)

---

## ⚡ The Problem: Architecture Documentation Rot & Interview Amnesia

In software engineering and distributed infrastructure systems, documentation suffers from three fatal problems:
1. **Architectural Archeology & Decision Drift:** Engineering teams reverse sound architectural decisions because the historical context, forces, constraints, and evaluated alternatives were never formally recorded in Architectural Decision Records (ADRs).
2. **Security Compliance Theater:** Threat models are created as stale slide decks during initial security reviews, completely detached from codebase realities, container definitions, and CI/CD pipelines.
3. **The "Staff-Plus Interview Wall":** Senior, Staff, and Principal engineers who design and ship complex distributed systems often struggle to defend their systems during high-stakes technical interviews (L5/L6/L7 panels, Architecture Review Boards, CISO audits) because their accomplishments aren't structured into quantified STAR narratives (Situation, Task, Action, Result) and rapid-fire trade-off defenses.
4. **AI Non-Determinism & Hallucinations:** Relying on probabilistic Large Language Models (LLMs) to generate compliance documentation introduces fatal vulnerabilities: hallucinations of non-existent APIs, variable output across builds, external SaaS subscription costs, rate limits, and intellectual property exposure.

DocForge uses code to generate structured documentation. Generated statements and threat models require human review against the actual system; deterministic output does not establish accuracy or security.

DocForge operates in two complementary modes:
1. **Static AST & Repository Inspection (`scripts/twu_docgen.py`):** Automatically scans Dockerfiles, GitHub Actions CI workflows, and Python AST trees without model calls or third-party dependencies, generating draft whitepapers, STRIDE matrices, and STAR talking points.
2. **Specification-Driven Architecture Compiler (`docforge` package):** Takes a structured JSON specification of your system and deterministically compiles it into formal whitepapers, ASCII & Mermaid DAG diagrams, Michael Nygard ADR logs, STRIDE threat matrices, and Amazon STAR defense guides with SHA-256 cryptographic verification stamps.

**100% Zero External Dependencies. Pure Python 3 Standard Library.**

---

## 🚀 Quick Start (Under 30 Seconds)

No `pip install`, no virtualenv required:

```bash
# 1. Clone the repository
git clone https://github.com/Ethan-da-Tech-Wizard/deterministic-doc-forge.git
cd deterministic-doc-forge

# 2. Run the unit tests
python3 -m unittest discover -s tests -v
python3 -m unittest scripts/test_twu_docgen.py -v

# 3. Analyze local repository components statically (Zero Model Calls)
python3 scripts/twu_docgen.py analyze --path .

# 4. Synthesize a whitepaper from your local codebase
python3 scripts/twu_docgen.py whitepaper --path . --output docs/LOCAL_WHITEPAPER.md

# 5. Compile the enterprise microservice sample project
python3 -m docforge build -i examples/sample_project.json -o docs/
```

This compiles:
- `docs/WHITEPAPER.md` (Generated architecture whitepaper with Document ID; review against the actual system)
- `docs/ADR_LOG.md` (Michael Nygard decision log with lifecycle validation)
- `docs/THREAT_MODEL.md` (Full STRIDE risk matrix and mitigation catalog)
- `docs/STAR_INTERVIEW_GUIDE.md` (L5/L6/L7 behavioral and system defense guide)

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
|  +-- [ UpstreamServiceDispatcher ] [BACKEND_GATEWAY]           |
+----------------------------------------------------------------+
```

### 2. Static AST & Container Inspection (`scripts/twu_docgen.py`)
Extracts deep architectural signals from codebases without executing them:
- **Dockerfile Inspection:** Multi-stage build separation (`FROM ... AS builder`), non-root execution (`USER appuser`), container health checks (`HEALTHCHECK`), and exec-form array syntax (`ENTRYPOINT ["bin"]`) preserving POSIX PID 1 signal propagation.
- **CI/CD Workflow Inspection:** Evaluates GitHub Actions `.github/workflows/*.yml` for shift-left DevSecOps security tools (ShellCheck, Bandit AST SAST, Aqua Security Trivy, YARA rule validation, SPDX-JSON SBOM generation) and Python test matrices.
- **Python AST Inspection:** Utilizes Python's `ast.parse()` module to safely extract module docstrings, detect socket listener bindings, identify Linux cgroup/namespace sandboxing, and flag signature scanning engines without executing untrusted code.

### 3. Microsoft STRIDE Threat Modeling
Every component and boundary is evaluated against the 6 STRIDE categories:
- **S (Spoofing):** Untrusted container ingress, forged tokens, credential theft.
- **T (Tampering):** Unverified upstream dependencies, modified build artifacts, in-transit payload corruption.
- **R (Repudiation):** Unaudited administrative actions, missing tamper-proof audit trails.
- **I (Information Disclosure):** Secret leakage in container layers, verbose stack traces, unencrypted network transit.
- **D (Denial of Service):** Unbounded resource consumption, CPU starvation, connection exhaustion.
- **E (Elevation of Privilege):** Container root breakout, host kernel exploitation, insecure sudoers configurations.

### 4. Michael Nygard Architectural Decision Records (ADRs)
Generates records of the engineering decisions supplied in the input:
- Tracks status transitions: `PROPOSED` -> `ACCEPTED` -> `DEPRECATED` or `SUPERSEDED`.
- Detects circular supersede references and dangling target IDs during static validation.
- Records context, decision rationale, and quantified positive/negative trade-offs.

### 5. Amazon STAR Technical Defense Interview Guides
Prepares senior and lead engineers for Staff/Principal (L5/L6/L7) panels, Architecture Review Boards (ARBs), and CISO reviews:
- **Situation:** Quantified engineering challenges, scale requirements, and business constraints.
- **Task:** Explicit ownership and architectural goals.
- **Action:** Deep technical trade-offs, algorithms chosen (e.g. Kahn's DAG sort vs DFS), container hardening, and shift-left gates.
- **Result:** Quantified metrics (throughput, p99 latency reduction, zero cloud spend, 100% automated test pass rate).
- **Technical Defense Q&A:** Generates possible interview questions and answers that must be checked against the actual work.

---

## 🛠️ Command-Line Interface Reference

### `scripts/twu_docgen.py` (Static AST Inspector)
```bash
# Analyze project structure and print JSON metadata
python3 scripts/twu_docgen.py analyze --path /path/to/project

# Generate formal technical architecture whitepaper
python3 scripts/twu_docgen.py whitepaper --path /path/to/project --output docs/WHITEPAPER.md

# Generate quickstart runbook with verification commands
python3 scripts/twu_docgen.py quickstart --path /path/to/project --output docs/QUICKSTART.md

# Generate Architectural Decision Records (ADR log)
python3 scripts/twu_docgen.py adr --path /path/to/project --output docs/ADR_LOG.md

# Generate Microsoft STRIDE Threat Model
python3 scripts/twu_docgen.py threat-model --path /path/to/project --output docs/THREAT_MODEL.md

# Generate STAR Method Interview Guide
python3 scripts/twu_docgen.py star --path /path/to/project --output docs/STAR_GUIDE.md
```

### `docforge` CLI (Specification-Driven Compiler)
```bash
# Scaffold a new architecture specification
python3 -m docforge init -o my_architecture.json

# Validate architecture DAG, ADR chains, and STRIDE mitigations
python3 -m docforge validate -i my_architecture.json

# Compile all documents into a directory
python3 -m docforge build -i my_architecture.json -o docs/

# Verify cryptographic SHA-256 fingerprint in CI/CD
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

      - name: Run Test Suites
        run: |
          python3 -m unittest discover -s tests -v
          python3 -m unittest scripts/test_twu_docgen.py -v

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

Every single file in DocForge is exhaustively commented with line-by-line educational breakdowns:

```
deterministic-doc-forge/
├── scripts/
│   ├── twu_docgen.py         # Static AST analyzer, Dockerfile/CI inspector, Whitepaper generator
│   └── test_twu_docgen.py    # Unit tests for static analysis and doc generation (6/6 passing)
├── docforge/
│   ├── __init__.py           # Package metadata, SemVer, and clean public symbol exports
│   ├── models.py             # Strongly-typed dataclasses for ArchSpec, ADR, ThreatModel, STAR
│   ├── engine.py             # Kahn's DAG topological sort, ASCII/Mermaid renderer, SHA-256 hasher
│   ├── adr.py                # Michael Nygard ADR lifecycle manager & supersede chain validator
│   ├── stride.py             # Microsoft STRIDE threat analyzer, risk weight scoring, matrix compiler
│   ├── star.py               # Amazon STAR interview synthesizer & technical defense Q&A formatter
│   ├── cli.py                # POSIX CLI argument parser, standard streams, exit code dispatching
│   └── __main__.py           # Module entrypoint enabling direct `python3 -m docforge` execution
├── tests/
│   └── test_docforge.py      # Comprehensive test suite covering all modules (22/22 passing)
├── examples/
│   └── sample_project.json   # Example microservice security gateway specification
├── docs/                     # Compiled documentation artifacts with SHA-256 audit stamps
├── pyproject.toml            # PEP 517/621 package specification
└── LICENSE                   # MIT License (c) 2026 Ethan Kilmer <ethan@twu.software>, TWU LLC
```

---

## 🧪 Running Tests

DocForge includes unit tests; run them in your environment to see the current results. Coverage and passing tests do not verify every generated claim.

```bash
# Run docforge engine tests (22 tests)
python3 -m unittest discover -s tests -v

# Run static AST inspector tests (6 tests)
python3 -m unittest scripts/test_twu_docgen.py -v
```

Test counts and results may change; use the commands above to check the current version.

---

## 📜 License & Ownership

Distributed under the MIT License. See [LICENSE](LICENSE) for full details.

- **Author:** Ethan Kilmer ([ethan@twu.software](mailto:ethan@twu.software))
- **Organization:** TWU LLC
- **Copyright:** (c) 2026 Ethan Kilmer <ethan@twu.software>, TWU LLC

