"""
DocForge: Zero-Dependency Deterministic Technical Documentation Engine
======================================================================

DocForge transforms structured system architecture specifications into:
  1. Complete Architectural Whitepapers with formal Document IDs and ADRs.
  2. Directed Acyclic Graph (DAG) component execution topologies in pure ASCII and Mermaid.
  3. Formal STRIDE Threat Models with automated risk scoring and mitigation matrices.
  4. STAR Interview Guides (Situation, Task, Action, Result) with rapid-fire technical defense Q&A.
  5. Deterministic SHA-256 document fingerprinting for CI/CD tamper detection and audit gates.

Architecture Philosophy:
------------------------
1. Zero Runtime Dependencies:
   DocForge runs entirely on the standard Python 3.9+ library (`sys`, `os`, `json`, `dataclasses`,
   `hashlib`, `re`, `argparse`, `typing`). No pip installs, no virtualenv requirements, and zero
   supply-chain attack surface. In enterprise and high-security defense environments, minimizing
   third-party dependencies eliminates transitive vulnerabilities (CVEs) and build flakes.

2. Determinism as a First-Class Invariant:
   Given identical inputs, DocForge produces byte-for-byte identical output across Linux, macOS,
   and Windows platforms. Standardized line endings (POSIX \\n), sorted dictionary keys, and fixed
   table column formatting guarantee reproducible documentation that integrates cleanly with
   Git commit histories and cryptographic CI verification gates.

3. Dual-Purpose Engineering Artifacts:
   Systems documentation should not merely serve as static compliance paperwork; it must serve
   as an active career weapon and engineering design review asset. DocForge automatically compiles
   real system metrics into Amazon/Google-style STAR stories and Staff-plus technical defense
   interview questions.

Package Hierarchy:
------------------
  docforge/
    ├── __init__.py      -> Package exports and version metadata
    ├── models.py        -> Strongly-typed dataclass domain model and JSON schema parsing
    ├── engine.py        -> Core deterministic synthesis engine, DAG layout, and SHA-256 hasher
    ├── adr.py           -> Architectural Decision Record (ADR) lifecycle manager
    ├── stride.py        -> STRIDE threat matrix generator and mitigation validator
    ├── star.py          -> STAR behavioral and technical defense interview synthesis
    └── cli.py           -> Command-line interface with subcommands (build, init, validate, verify)
"""

# ---------------------------------------------------------------------------
# Metadata Definitions
# ---------------------------------------------------------------------------
# Semantic Versioning (SemVer 2.0.0): MAJOR.MINOR.PATCH
# MAJOR: Incompatible API or CLI flag changes.
# MINOR: Backwards-compatible feature additions (new output formats, diagram renderers).
# PATCH: Backwards-compatible bug fixes, doc updates, and performance tuning.
__version__: str = "1.0.0"
__author__: str = "Ethan Kilmer"
__email__: str = "ethan@twu.software"
__license__: str = "MIT"
__all__: list[str] = [
    # Top-Level Engine
    "DocForgeEngine",
    # Domain Models
    "ArchSpec",
    "Component",
    "ADR",
    "ADRStatus",
    "ThreatModel",
    "ThreatItem",
    "ThreatCategory",
    "RiskLevel",
    "STARStory",
    "STARDefenseQA",
    "VerificationGate",
    # Managers & Analyzers
    "ADRManager",
    "STRIDEAnalyzer",
    "STARGuideGenerator",
    # Cryptographic & DAG Utilities
    "calculate_fingerprint",
    "verify_fingerprint",
    "render_ascii_dag",
    "render_mermaid_dag",
]

# ---------------------------------------------------------------------------
# Public Module Imports
# ---------------------------------------------------------------------------
# We import key classes directly into the root `docforge` namespace so client
# code can cleanly execute `from docforge import DocForgeEngine, ArchSpec`.
from docforge.models import (
    ArchSpec,
    Component,
    ADR,
    ADRStatus,
    ThreatModel,
    ThreatItem,
    ThreatCategory,
    RiskLevel,
    STARStory,
    STARDefenseQA,
    VerificationGate,
)

from docforge.adr import ADRManager
from docforge.stride import STRIDEAnalyzer
from docforge.star import STARGuideGenerator

from docforge.engine import (
    DocForgeEngine,
    calculate_fingerprint,
    verify_fingerprint,
    render_ascii_dag,
    render_mermaid_dag,
)
