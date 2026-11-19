# ==============================================================================
# Program: adr.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Architectural Decision Record (ADR) lifecycle manager and Markdown synthesizer.
#          Validates ADR relationships, prevents circular supersession chains, and renders logs.
# ==============================================================================
"""
DocForge Architectural Decision Record (ADR) Manager
===================================================

This module provides lifecycle management and deterministic Markdown generation
for Architectural Decision Records (ADRs).

What is an ADR and Why Does It Matter?
--------------------------------------
An Architectural Decision Record (ADR) captures an important architectural decision
made along with its context and consequences. First formalized by Michael Nygard in 2011,
ADRs solve the classic enterprise problem of "architectural archeology": new engineers
joining a project often ask, "Why the hell did they choose asynchronous message queues instead
of synchronous gRPC calls here?" Without an ADR, teams often reverse good decisions
because the historical constraints and trade-offs have been forgotten.

Staff-Plus Architecture Review Defense:
---------------------------------------
In senior and principal systems engineering interviews, you are expected to articulate
not just what you chose, but what alternatives you rejected and why. Good ADRs articulate
the "Forces" (business deadlines, team skills, cost ceilings, SLA targets) and the accepted
"Negative Consequences" (e.g., eventual consistency complexity, operational overhead).
A design that claims "zero negative trade-offs" is an immediate red flag in any serious
systems design panel.
"""

from __future__ import annotations

# Tuple is imported but not used in this module (harmless).
from typing import Dict, List, Optional, Tuple
from docforge.models import ADR, ADRStatus


class ADRManager:
    """
    Manages collection, lifecycle transitions, consistency checks, and Markdown rendering
    for an architecture's decision log.
    """

    def __init__(self, adrs: Optional[List[ADR]] = None) -> None:
        """
        Initializes the manager with an optional list of pre-existing ADRs.
        Internal storage uses an ordered dictionary mapping ID -> ADR to guarantee
        fast lookups while preserving insertion and chronological ordering.
        """
        # Dict preserves insertion order (Python 3.7+) and gives O(1) lookup by ID.
        self._records: Dict[str, ADR] = {}
        if adrs:
            # Route through add_adr so duplicate IDs in the constructor input are rejected too.
            for adr in adrs:
                self.add_adr(adr)

    def add_adr(self, adr: ADR) -> None:
        """
        Registers a new ADR record.
        Raises ValueError if a collision occurs on the ADR ID.
        """
        # IDs are the primary key; silently overwriting would hide a bad spec, so fail loudly.
        if adr.id in self._records:
            raise ValueError(f"Duplicate ADR ID detected: '{adr.id}' is already registered.")
        self._records[adr.id] = adr

    def get_adr(self, adr_id: str) -> Optional[ADR]:
        """
        Retrieves an ADR record by its unique identifier.
        """
        return self._records.get(adr_id)

    def list_adrs(self) -> List[ADR]:
        """
        Returns all registered ADRs sorted deterministically by their identifier.
        Deterministic sorting ensures reproducible Markdown output across builds.
        """
        # Sorting by ID (not insertion order) makes output independent of JSON array order.
        return sorted(self._records.values(), key=lambda r: r.id)

    def active_adrs(self) -> List[ADR]:
        """
        Returns all records currently marked as ACCEPTED or PROPOSED.
        """
        return [r for r in self.list_adrs() if r.status.is_active()]

    def validate_lifecycle(self) -> List[str]:
        """
        Validates the integrity of the ADR collection:
          1. Every SUPERSEDED ADR must reference a valid, existing successor ADR ID.
          2. No circular supersede chains (e.g. ADR-01 -> ADR-02 -> ADR-01).
          3. Warns if any ADR is missing context, decision, or consequences.

        Returns a list of warning/error messages. An empty list signifies complete validity.
        """
        # Collect all problems instead of raising on the first, so users can fix them in one pass.
        issues: List[str] = []

        for adr in self._records.values():
            # Check superseded reference validity
            # Only SUPERSEDED records need a successor pointer; other statuses ignore superseded_by.
            if adr.status == ADRStatus.SUPERSEDED:
                if not adr.superseded_by:
                    issues.append(f"ADR {adr.id} is SUPERSEDED but 'superseded_by' is not specified.")
                elif adr.superseded_by not in self._records:
                    issues.append(
                        f"ADR {adr.id} points to non-existent successor '{adr.superseded_by}'."
                    )
                elif adr.superseded_by == adr.id:
                    issues.append(f"ADR {adr.id} cannot supersede itself (self-reference).")

            # Check decision depth
            # 10 characters is an arbitrary floor that catches empty or placeholder text (e.g. 'TBD').
            if not adr.context or len(adr.context.strip()) < 10:
                issues.append(f"ADR {adr.id} has insufficient or missing 'context' description.")
            if not adr.decision or len(adr.decision.strip()) < 10:
                issues.append(f"ADR {adr.id} has insufficient or missing 'decision' statement.")

            # Validate trade-off transparency
            # consequences is an optional dict with keys positive/negative/neutral; tolerate None.
            consequences = adr.consequences or {}
            positives = consequences.get("positive", [])
            negatives = consequences.get("negative", [])
            if not positives and not negatives:
                issues.append(f"ADR {adr.id} does not record any positive or negative consequences.")

        # Check for circular dependency loops in superseded links
        # Cycle detection: walk each superseded_by chain from every node. `visited_global` avoids
        # re-walking chains already proven acyclic, keeping the whole pass linear in the number of ADRs.
        visited_global = set()
        for adr_id in self._records:
            if adr_id in visited_global:
                continue
            # `chain` keeps visit order for the human-readable cycle message; `seen_in_chain` is the O(1) membership test.
            curr: Optional[str] = adr_id
            chain = []
            seen_in_chain = set()
            while curr:
                # Revisiting a node within a single walk means the chain loops back on itself.
                if curr in seen_in_chain:
                    issues.append(f"Circular supersede cycle detected: {' -> '.join(chain)} -> {curr}")
                    break
                seen_in_chain.add(curr)
                chain.append(curr)
                rec = self._records.get(curr)
                # Follow the link only while the record is superseded; otherwise the chain ends here.
                if rec and rec.status == ADRStatus.SUPERSEDED and rec.superseded_by:
                    curr = rec.superseded_by
                else:
                    break
            visited_global.update(seen_in_chain)

        return issues

    def render_summary_table(self) -> str:
        """
        Renders a clean, deterministic Markdown summary table indexing all ADRs.
        Standardizes column widths and status badges.
        """
        adrs = self.list_adrs()
        if not adrs:
            return "_No Architectural Decision Records logged for this system._\n"

        lines: List[str] = []
        lines.append("| ID | Decision Title | Status | Date | Superseded By |")
        # Markdown alignment row: left for text columns, centered for Status and Date.
        lines.append("|:---|:---|:---:|:---:|:---|")

        for adr in adrs:
            # Backticks render the status as inline code, a cheap 'badge' that works in any Markdown viewer.
            status_badge = f"`{adr.status.value}`"
            successor = f"[`{adr.superseded_by}`](#{adr.superseded_by.lower()})" if adr.superseded_by else "-"
            # Format title with an anchor link to the detailed section below
            # NOTE: title_link is computed but the row below uses the plain title, so the anchor is
            # currently unused. Left as-is (comments-only pass).
            title_link = f"[{adr.title}](#{adr.id.lower()}-{adr.title.lower().replace(' ', '-')})"
            lines.append(f"| **{adr.id}** | {adr.title} | {status_badge} | {adr.date} | {successor} |")

        return "\n".join(lines) + "\n"

    def render_detailed_records(self) -> str:
        """
        Renders complete, formatted Michael Nygard style ADR sections.
        Includes Context, Decision, and explicit Trade-off / Consequences matrices.
        """
        adrs = self.list_adrs()
        if not adrs:
            return ""

        sections: List[str] = []

        for adr in adrs:
            sec_lines: List[str] = []
            sec_lines.append(f"### {adr.id}: {adr.title}")
            sec_lines.append("")
            sec_lines.append(f"- **Status:** `{adr.status.value}`")
            sec_lines.append(f"- **Decision Date:** `{adr.date}`")
            if adr.superseded_by:
                sec_lines.append(f"- **Superseded By:** [`{adr.superseded_by}`](#{adr.superseded_by.lower()})")
            sec_lines.append("")

            # 1. Context & Problem Statement
            # Sections follow Michael Nygard's ADR template: Context, Decision, Consequences.
            sec_lines.append("#### 1. Context & Problem Statement")
            sec_lines.append(adr.context)
            sec_lines.append("")

            # 2. Architectural Decision
            sec_lines.append("#### 2. Architectural Decision")
            sec_lines.append(adr.decision)
            sec_lines.append("")

            # 3. Consequences & Trade-offs
            sec_lines.append("#### 3. Consequences & Trade-offs")
            consequences = adr.consequences or {}
            positives = consequences.get("positive", [])
            negatives = consequences.get("negative", [])
            neutrals = consequences.get("neutral", [])

            if positives:
                sec_lines.append("**Positive Impacts (Benefits):**")
                for p in positives:
                    # Checkbox-style markers ([x] benefit, [!] cost, [i] neutral) are plain text so they stay stable under hashing.
                    sec_lines.append(f"- [x] {p}")
                sec_lines.append("")

            if negatives:
                sec_lines.append("**Negative Impacts (Accepted Costs & Operational Overhead):**")
                for n in negatives:
                    sec_lines.append(f"- [!] {n}")
                sec_lines.append("")

            if neutrals:
                sec_lines.append("**Neutral / Structural Impacts:**")
                for neu in neutrals:
                    sec_lines.append(f"- [i] {neu}")
                sec_lines.append("")

            sections.append("\n".join(sec_lines))

        # Horizontal rule between records; trailing newline keeps files POSIX-compliant.
        return "\n\n---\n\n".join(sections) + "\n"

    def render_full_markdown(self) -> str:
        """
        Renders both the summary index table and the detailed records.
        """
        parts: List[str] = []
        parts.append("## Architectural Decision Records (ADRs)")
        parts.append("")
        parts.append(
            "This log captures foundational design choices, evaluated alternatives, "
            "and accepted trade-offs governing the system."
        )
        parts.append("")
        parts.append(self.render_summary_table())
        parts.append("")
        parts.append(self.render_detailed_records())
        return "\n".join(parts)
