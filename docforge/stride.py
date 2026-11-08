"""
DocForge STRIDE Threat Modeling Engine
======================================

This module implements automated STRIDE threat analysis, risk scoring,
and deterministic Markdown matrix generation.

What is STRIDE?
---------------
Developed by Loren Kohnfelder and Praerit Garg at Microsoft in 1999, STRIDE is the
gold-standard threat classification model used in enterprise security architecture:
  - S (Spoofing): Violates Authentication. (e.g. Attacker impersonates an edge client or service).
  - T (Tampering): Violates Integrity. (e.g. Modifying packets in transit or altering database records).
  - R (Repudiation): Violates Non-repudiation. (e.g. Attacker performs malicious action without audit trails).
  - I (Information Disclosure): Violates Confidentiality. (e.g. Leaking tokens, PII, or internal IPs).
  - D (Denial of Service): Violates Availability. (e.g. SYN floods, algorithmic complexity attacks, memory exhaustion).
  - E (Elevation of Privilege): Violates Authorization. (e.g. Standard user escalates to cluster administrator).

Interview Talking Points & Defense Strategy:
--------------------------------------------
- "How do you approach system security during design?"
  Staff engineers do not merely say "We use HTTPS and OAuth." They articulate a formal threat model.
  They identify trust boundaries (e.g. between the Public Internet and the Edge Gateway, or between
  multi-tenant pods and shared Redis clusters), enumerate threats using STRIDE, and assign explicit
  cryptographic or architectural mitigations to every boundary.
- "Shift-Left Security":
  Threat modeling in documentation *before* coding catches fundamental architectural flaws
  that static analysis tools (SAST/DAST) cannot see (e.g. missing signature verification or
  insecure multi-tenant isolation).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple
from docforge.models import RiskLevel, ThreatCategory, ThreatItem, ThreatModel


class STRIDEAnalyzer:
    """
    Analyzes, validates, and renders STRIDE threat models into deterministic Markdown reports.
    """

    def __init__(self, threat_model: Optional[ThreatModel] = None) -> None:
        """
        Initializes the STRIDE analyzer with an optional ThreatModel domain entity.
        """
        self.threat_model = threat_model

    def validate_threats(self) -> List[str]:
        """
        Conducts sanity and security checks on the threat model:
          1. Every HIGH or CRITICAL threat must have a defined mitigation.
          2. No threat may have 'ACCEPTED_RISK' for CRITICAL severity without explicit justification.
          3. Every threat must specify a valid component and attack description.

        Returns a list of validation warnings or errors.
        """
        if not self.threat_model:
            return ["No threat model provided for validation."]

        issues: List[str] = []

        for threat in self.threat_model.threats:
            # Check high-severity mitigation presence
            if threat.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                if not threat.mitigation or len(threat.mitigation.strip()) < 10:
                    issues.append(
                        f"Threat [{threat.id}] ({threat.category.value}) is rated {threat.risk_level.value} "
                        "but lacks an actionable mitigation specification."
                    )
                if threat.mitigation_status == "ACCEPTED_RISK" and threat.risk_level == RiskLevel.CRITICAL:
                    issues.append(
                        f"CRITICAL Threat [{threat.id}] marked as ACCEPTED_RISK. "
                        "Critical security risks cannot be accepted without CISO-level waiver."
                    )

            # Check description sufficiency
            if not threat.description or len(threat.description.strip()) < 10:
                issues.append(f"Threat [{threat.id}] has an insufficient description narrative.")

            if not threat.component or not threat.component.strip():
                issues.append(f"Threat [{threat.id}] is not tied to any architectural component.")

        return issues

    def get_summary_statistics(self) -> Dict[str, Any]:
        """
        Calculates aggregate statistics across categories and risk levels.
        Useful for executive dashboards and compliance scorecards.
        """
        if not self.threat_model:
            return {"total": 0, "by_category": {}, "by_risk": {}}

        by_category: Dict[str, int] = {cat.value: 0 for cat in ThreatCategory}
        by_risk: Dict[str, int] = {rl.value: 0 for rl in RiskLevel}

        for threat in self.threat_model.threats:
            by_category[threat.category.value] = by_category.get(threat.category.value, 0) + 1
            by_risk[threat.risk_level.value] = by_risk.get(threat.risk_level.value, 0) + 1

        return {
            "total": len(self.threat_model.threats),
            "by_category": by_category,
            "by_risk": by_risk,
        }

    def render_matrix_table(self) -> str:
        """
        Renders the STRIDE Risk and Mitigation Summary Table in deterministic Markdown.
        Sorted by severity (highest severity first), then by Threat ID.
        """
        if not self.threat_model or not self.threat_model.threats:
            return "_No threats cataloged in threat model._\n"

        # Deterministic sorting: by numeric risk weight descending, then threat ID ascending
        sorted_threats = sorted(
            self.threat_model.threats,
            key=lambda t: (-t.risk_level.numeric_weight(), t.id)
        )

        lines: List[str] = []
        lines.append("| ID | Category | Target Component | Threat Scenario | Risk Level | Mitigation Status |")
        lines.append("|:---|:---|:---|:---|:---:|:---:|")

        for t in sorted_threats:
            risk_badge = f"`{t.risk_level.value}`"
            status_badge = f"**{t.mitigation_status}**"
            category_badge = f"_{t.category.value}_"
            lines.append(
                f"| **{t.id}** | {category_badge} | `{t.component}` | {t.title} | {risk_badge} | {status_badge} |"
            )

        return "\n".join(lines) + "\n"

    def render_detailed_threats(self) -> str:
        """
        Renders complete threat breakdown including attack mechanics, impact assessment,
        and precise mitigation controls.
        """
        if not self.threat_model or not self.threat_model.threats:
            return ""

        sorted_threats = sorted(
            self.threat_model.threats,
            key=lambda t: (-t.risk_level.numeric_weight(), t.id)
        )

        sections: List[str] = []
        for t in sorted_threats:
            sec: List[str] = []
            sec.append(f"### Threat {t.id}: {t.title}")
            sec.append("")
            sec.append(f"- **STRIDE Category:** `{t.category.value}`")
            sec.append(f"- **Impacted Component:** `{t.component}`")
            sec.append(f"- **Assessed Severity:** `{t.risk_level.value}`")
            sec.append(f"- **Implementation Status:** `{t.mitigation_status}`")
            sec.append("")
            sec.append("**Attack Narrative & Exploitation Mechanism:**")
            sec.append(t.description)
            sec.append("")
            sec.append(f"**Business & System Impact:** {t.impact}")
            sec.append("")
            sec.append("**Engineering Mitigation & Defense Controls:**")
            sec.append(f"> {t.mitigation}")
            sec.append("")
            sections.append("\n".join(sec))

        return "\n\n---\n\n".join(sections) + "\n"

    def render_full_markdown(self) -> str:
        """
        Renders the complete STRIDE Threat Model document section.
        """
        if not self.threat_model:
            return "## Security Architecture & STRIDE Threat Model\n\n_No threat model registered._\n"

        parts: List[str] = []
        parts.append("## Security Architecture & STRIDE Threat Model")
        parts.append("")
        parts.append(
            f"Formal threat analysis for **{self.threat_model.system_name}** conducted under the "
            "Microsoft STRIDE security assessment methodology."
        )
        parts.append("")

        # Trust Boundaries
        if self.threat_model.trust_boundaries:
            parts.append("### 1. Identified Trust Boundaries")
            parts.append("Data crossing these logical and physical perimeter boundaries requires explicit validation:")
            for b in self.threat_model.trust_boundaries:
                parts.append(f"- [x] **Boundary:** {b}")
            parts.append("")

        # Security Assumptions
        if self.threat_model.security_assumptions:
            parts.append("### 2. Foundational Security Assumptions")
            for a in self.threat_model.security_assumptions:
                parts.append(f"- [i] {a}")
            parts.append("")

        # Summary Matrix
        parts.append("### 3. STRIDE Threat & Mitigation Matrix")
        parts.append(self.render_matrix_table())
        parts.append("")

        # Detailed Breakdown
        parts.append("### 4. Deep-Dive Threat Vector Analysis")
        parts.append(self.render_detailed_threats())

        return "\n".join(parts)
