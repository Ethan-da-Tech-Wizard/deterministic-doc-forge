"""
DocForge Core Synthesis Engine & Deterministic Pipeline
======================================================

This module is the core orchestrator of DocForge. It is responsible for:
  1. Parsing and validating component dependency graphs (DAGs).
  2. Generating pure ASCII and Mermaid component execution topologies.
  3. Deterministically synthesizing Architectural Whitepapers, STRIDE Threat Models,
     ADRs, and STAR Interview Guides into standardized GitHub-Flavored Markdown.
  4. Cryptographically fingerprinting (SHA-256) all generated documents for CI/CD gating.

Design Principles & Interview Deep-Dive:
----------------------------------------
- "Topological Sorting (Kahn's Algorithm)":
  In system design, understanding service dependency chains is critical. A system
  must boot, deploy, and recover in topological order. DocForge uses Kahn's algorithm
  (an $O(V + E)$ algorithm based on in-degree tracking) to layer components from ingress
  to leaf nodes and detect illegal circular dependencies before documentation is built.

- "Hermetic & Deterministic Builds":
  Modern DevOps practices (e.g. Bazel, Nix) prioritize determinism: the exact same
  inputs must yield the exact same bitwise output on any machine. DocForge guarantees
  this by:
    a) Normalizing line endings across Windows (`\\r\\n`) and UNIX (`\\n`).
    b) Sorting dictionary keys and collections with fixed comparators.
    c) Stripping erratic trailing whitespace.
    d) Computing cryptographic SHA-256 hashes of the canonical content.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple

from docforge.adr import ADRManager
from docforge.models import ArchSpec, Component, VerificationGate
from docforge.star import STARGuideGenerator
from docforge.stride import STRIDEAnalyzer


# ===========================================================================
# Cryptographic Fingerprinting & Hashing Utilities
# ===========================================================================

FINGERPRINT_TAG_PATTERN = re.compile(
    r"<!--\s*DOCFORGE-SHA256:\s*([0-9a-fA-F]{64})\s*-->"
)

# Specifically matches only the DocForge audit footer block
AUDIT_FOOTER_PATTERN = re.compile(
    r"\n*---\s*\n"
    r"<!--\s*DOCFORGE-SHA256:\s*[0-9a-fA-F]{64}\s*-->\s*\n"
    r"\*\*DocForge Cryptographic Audit Stamp:\*\*\s*`SHA256:[0-9a-fA-F]{64}`\s*\n"
    r"_Generated deterministically by DocForge\. Any manual modification invalidates CI/CD verification\._\s*$",
    re.MULTILINE
)


def canonicalize_markdown(content: str) -> str:
    """
    Transforms a Markdown string into its canonical representation:
      1. Normalizes line endings to POSIX standard LF (\\n).
      2. Strips any previously embedded DOCFORGE-SHA256 footer or comment tags.
      3. Strips trailing whitespace from each individual line.
      4. Strips leading and trailing blank lines to avoid newline variances.
    """
    # 1. Normalize carriage returns
    text = content.replace("\r\n", "\n").replace("\r", "\n")

    # 2. Remove any pre-existing SHA-256 audit footer or comment tags
    text = AUDIT_FOOTER_PATTERN.sub("", text)
    text = FINGERPRINT_TAG_PATTERN.sub("", text)

    # 3. Strip trailing whitespace per line
    lines = [line.rstrip() for line in text.split("\n")]

    # 4. Recombine and strip outer margins
    canonical = "\n".join(lines).strip()
    return canonical


def calculate_fingerprint(content: str) -> str:
    """
    Computes a deterministic SHA-256 hexadecimal digest of canonicalized Markdown text.
    """
    canonical = canonicalize_markdown(content)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest


def embed_fingerprint(content: str) -> str:
    """
    Computes the SHA-256 fingerprint of the canonical content and appends a standardized,
    machine-readable HTML comment stamp and visual verification badge at the end of the document.
    """
    canonical = canonicalize_markdown(content)
    digest = calculate_fingerprint(canonical)

    footer = (
        f"\n\n---\n"
        f"<!-- DOCFORGE-SHA256: {digest} -->\n"
        f"**DocForge Cryptographic Audit Stamp:** `SHA256:{digest}`  \n"
        f"_Generated deterministically by DocForge. Any manual modification invalidates CI/CD verification._\n"
    )
    return canonical + footer


def verify_fingerprint(content: str) -> Tuple[bool, str, str]:
    """
    Verifies if a Markdown document's content matches its embedded SHA-256 fingerprint.

    Returns:
        A 3-tuple: (is_valid: bool, embedded_hash: str, computed_hash: str)
    """
    match = FINGERPRINT_TAG_PATTERN.search(content)
    if not match:
        computed = calculate_fingerprint(content)
        return False, "", computed

    embedded_hash = match.group(1).lower()
    computed_hash = calculate_fingerprint(content).lower()
    is_valid = (embedded_hash == computed_hash)
    return is_valid, embedded_hash, computed_hash


# ===========================================================================
# DAG Analysis & Topological Rendering (ASCII & Mermaid)
# ===========================================================================

def topological_sort_components(components: List[Component]) -> Tuple[List[List[str]], List[str]]:
    """
    Executes Kahn's algorithm on the component graph to determine execution layers
    and detect any cyclic dependency deadlocks.

    Algorithm Explanation (Interview Point):
    ----------------------------------------
    Kahn's algorithm initializes by calculating the 'in-degree' (number of incoming dependencies)
    for every node. Nodes with in-degree 0 are root components (e.g., ingress gateways).
    We peel them off into Layer 0, decrement the in-degrees of downstream dependent nodes,
    and repeat layer by layer. If nodes remain unprocessed after all layers, a directed cycle exists.

    Returns:
        (layers: List[List[component_names]], cycles: List[str])
    """
    # Map component names to object
    comp_map = {c.name: c for c in components}
    in_degree: Dict[str, int] = {c.name: 0 for c in components}
    adj_list: Dict[str, List[str]] = defaultdict(list)

    # Build adjacency and in-degree counts
    # If Component A depends on Component B, data/control flows B -> A
    for comp in components:
        for dep in comp.dependencies:
            if dep in comp_map:
                adj_list[dep].append(comp.name)
                in_degree[comp.name] += 1

    # Queue of nodes with zero in-degree (root ingress layer)
    queue: deque[str] = deque([name for name, deg in in_degree.items() if deg == 0])

    layers: List[List[str]] = []
    processed_count = 0

    while queue:
        layer_size = len(queue)
        current_layer: List[str] = []
        for _ in range(layer_size):
            node = queue.popleft()
            current_layer.append(node)
            processed_count += 1

            for neighbor in adj_list[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # Sort names in layer alphabetically for build determinism
        layers.append(sorted(current_layer))

    # Detect cycles if not all nodes were processed
    cycles: List[str] = []
    if processed_count < len(components):
        unresolved = [name for name, deg in in_degree.items() if deg > 0]
        cycles.append(
            f"Cyclic dependency detected involving components: {', '.join(sorted(unresolved))}"
        )

    return layers, cycles


def render_ascii_dag(components: List[Component]) -> str:
    """
    Renders a clean, deterministic pure ASCII box-and-arrow topology diagram.
    Guaranteed to render cleanly in terminals, GitHub previews, and text editors.
    """
    if not components:
        return "[ Empty Component Graph ]"

    layers, cycles = topological_sort_components(components)
    comp_map = {c.name: c for c in components}

    lines: List[str] = []
    lines.append("```text")
    lines.append("+----------------------------------------------------------------+")
    lines.append("|                SYSTEM COMPONENT TOPOLOGY (DAG)                 |")
    lines.append("+----------------------------------------------------------------+")

    if cycles:
        lines.append("|  [!] WARNING: CYCLIC DEPENDENCY DETECTED                      |")
        for c in cycles:
            lines.append(f"|  {c[:60]:<60}  |")
        lines.append("+----------------------------------------------------------------+")

    for layer_idx, layer in enumerate(layers):
        lines.append(f"|  Layer {layer_idx} (Topological Tier)                                     |")
        for comp_name in layer:
            comp = comp_map[comp_name]
            tier_badge = f"[{comp.tier.upper()}]"
            techs = f"({', '.join(comp.technologies[:3])})" if comp.technologies else ""
            comp_box = f"+-- [ {comp.name} ] {tier_badge} {techs}"
            lines.append(f"|  {comp_box[:60]:<60}  |")

            if comp.dependencies:
                dep_str = f"     Depends on: {', '.join(comp.dependencies)}"
                lines.append(f"|  {dep_str[:60]:<60}  |")

        if layer_idx < len(layers) - 1:
            lines.append("|        |                                                       |")
            lines.append("|        v  [ downstream dependencies / async events ]           |")
            lines.append("|        |                                                       |")

    lines.append("+----------------------------------------------------------------+")
    lines.append("```")
    return "\n".join(lines)


def render_mermaid_dag(components: List[Component]) -> str:
    """
    Renders a standard GitHub-supported Mermaid flowchart (flowchart TD).
    """
    if not components:
        return "```mermaid\nflowchart TD\n  Empty[No Components]\n```"

    lines: List[str] = []
    lines.append("```mermaid")
    lines.append("flowchart TD")

    # Define nodes with styling based on tier
    comp_map = {c.name: c for c in components}
    for comp in sorted(components, key=lambda c: c.name):
        tier_label = f"<small>[{comp.tier}]</small>"
        label = f"<b>{comp.name}</b><br/>{tier_label}"
        lines.append(f"    {comp.name}[\"{label}\"]")

    lines.append("")

    # Define dependency edges
    has_edges = False
    for comp in sorted(components, key=lambda c: c.name):
        for dep in sorted(comp.dependencies):
            if dep in comp_map:
                lines.append(f"    {dep} -->|consumes / calls| {comp.name}")
                has_edges = True

    if not has_edges:
        lines.append("    %% Standalone components (no explicit dependency edges)")

    lines.append("```")
    return "\n".join(lines)


# ===========================================================================
# Top-Level Engine Orchestration
# ===========================================================================

class DocForgeEngine:
    """
    Top-level documentation compiler that ingests an ArchSpec model and produces
    complete whitepapers, threat models, interview guides, and ADR logs.
    """

    def __init__(self, spec: ArchSpec) -> None:
        """
        Initializes the engine with an ingested architecture specification.
        """
        self.spec = spec
        self.adr_manager = ADRManager(spec.adrs)
        self.stride_analyzer = STRIDEAnalyzer(spec.threat_model)
        self.star_generator = STARGuideGenerator(spec.star_stories, spec.defense_qa)

    def render_component_table(self) -> str:
        """
        Renders a comprehensive Markdown specification table describing all components.
        """
        if not self.spec.components:
            return "_No components cataloged in specification._\n"

        lines: List[str] = []
        lines.append("| Component Name | Tier / Layer | Technologies | Primary Responsibilities | Dependencies |")
        lines.append("|:---|:---:|:---|:---|:---|")

        for c in sorted(self.spec.components, key=lambda x: x.name):
            techs = ", ".join(c.technologies) if c.technologies else "None"
            deps = ", ".join(c.dependencies) if c.dependencies else "_None (Ingress / Root)_"
            lines.append(
                f"| **{c.name}** | `{c.tier}` | {techs} | {c.description} | {deps} |"
            )

        return "\n".join(lines) + "\n"

    def render_verification_gates_section(self) -> str:
        """
        Renders the CI/CD Verification Gates and Automated Governance Table.
        """
        if not self.spec.verification_gates:
            return "_No automated verification gates defined._\n"

        lines: List[str] = []
        lines.append("### Automated Verification Gates & CI/CD Governance")
        lines.append("")
        lines.append(
            "The following compliance checks are enforced in the continuous integration pipeline "
            "to guarantee codebase alignment with this architectural specification:"
        )
        lines.append("")
        lines.append("| Gate Name | Command / Inspection Rule | Acceptance Criteria | Failure Action |")
        lines.append("|:---|:---|:---|:---:|")

        for g in sorted(self.spec.verification_gates, key=lambda x: x.name):
            lines.append(
                f"| **{g.name}** | `{g.command_or_rule}` | {g.acceptance_criteria} | **{g.failure_action}** |"
            )

        return "\n".join(lines) + "\n"

    def synthesize_whitepaper(self) -> str:
        """
        Synthesizes the complete, authoritative Architectural Whitepaper.
        Includes title, document ID, executive summary, component topologies (ASCII & Mermaid),
        ADRs, STRIDE threat model, STAR interview defense prep, verification gates,
        and cryptographic SHA-256 fingerprint.
        """
        parts: List[str] = []

        # 1. Document Header & Metadata Block
        parts.append(f"# Architectural Whitepaper: {self.spec.system_name}")
        parts.append("")
        parts.append("| Metadata Attribute | Specification Value |")
        parts.append("|:---|:---|")
        parts.append(f"| **Formal Document ID** | `{self.spec.document_id}` |")
        parts.append(f"| **System Architecture Version** | `v{self.spec.version}` |")
        parts.append(f"| **Principal Author** | {self.spec.author} |")
        parts.append(f"| **Publication Date** | {self.spec.date} |")
        if self.spec.metadata:
            for k, v in sorted(self.spec.metadata.items()):
                parts.append(f"| **{k.title()}** | {v} |")
        parts.append("")

        # 2. Executive Summary
        parts.append("## 1. Executive Summary")
        parts.append(self.spec.executive_summary)
        parts.append("")

        # 3. System Architecture & Topology
        parts.append("## 2. System Architecture & Component Topology")
        parts.append(self.spec.architecture_overview)
        parts.append("")

        parts.append("### 2.1 ASCII Directed Acyclic Graph (DAG)")
        parts.append(render_ascii_dag(self.spec.components))
        parts.append("")

        parts.append("### 2.2 Mermaid Visual Flowchart")
        parts.append(render_mermaid_dag(self.spec.components))
        parts.append("")

        parts.append("### 2.3 Component Inventory & Specification")
        parts.append(self.render_component_table())
        parts.append("")

        # 4. Architectural Decision Records (ADRs)
        parts.append("## 3. Architectural Decision Records (ADRs)")
        parts.append(self.adr_manager.render_summary_table())
        parts.append("")
        parts.append(self.adr_manager.render_detailed_records())
        parts.append("")

        # 5. STRIDE Threat Model
        parts.append("## 4. STRIDE Threat Model & Security Controls")
        parts.append(self.stride_analyzer.render_matrix_table())
        parts.append("")
        parts.append(self.stride_analyzer.render_detailed_threats())
        parts.append("")

        # 6. STAR Interview Guide & Technical Defense
        parts.append("## 5. STAR Behavioral Guides & Architecture Defense")
        parts.append(self.star_generator.render_stories_markdown())
        parts.append("")
        parts.append(self.star_generator.render_defense_qa_markdown())
        parts.append("")

        # 7. Verification Gates
        parts.append("## 6. Verification Gates & Release Criteria")
        parts.append(self.render_verification_gates_section())

        # Compile and embed cryptographic fingerprint
        raw_markdown = "\n".join(parts)
        return embed_fingerprint(raw_markdown)

    def synthesize_adr_log(self) -> str:
        """
        Synthesizes a standalone ADR log document (ADR_LOG.md).
        """
        raw = self.adr_manager.render_full_markdown()
        return embed_fingerprint(raw)

    def synthesize_threat_model(self) -> str:
        """
        Synthesizes a standalone STRIDE Threat Model document (THREAT_MODEL.md).
        """
        raw = self.stride_analyzer.render_full_markdown()
        return embed_fingerprint(raw)

    def synthesize_star_guide(self) -> str:
        """
        Synthesizes a standalone STAR Interview Guide document (STAR_INTERVIEW_GUIDE.md).
        """
        raw = self.star_generator.render_full_markdown()
        return embed_fingerprint(raw)

    def build_all(self, output_dir: str) -> Dict[str, str]:
        """
        Generates and writes all documentation artifacts to disk:
          - WHITEPAPER.md
          - ADR_LOG.md
          - THREAT_MODEL.md
          - STAR_INTERVIEW_GUIDE.md

        Returns a dictionary mapping generated filenames to their SHA-256 fingerprints.
        """
        os.makedirs(output_dir, exist_ok=True)
        manifest: Dict[str, str] = {}

        artifacts = {
            "WHITEPAPER.md": self.synthesize_whitepaper(),
            "ADR_LOG.md": self.synthesize_adr_log(),
            "THREAT_MODEL.md": self.synthesize_threat_model(),
            "STAR_INTERVIEW_GUIDE.md": self.synthesize_star_guide(),
        }

        for filename, content in artifacts.items():
            filepath = os.path.join(output_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(content)
            manifest[filename] = calculate_fingerprint(content)

        return manifest
