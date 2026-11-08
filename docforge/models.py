"""
DocForge Domain Models
======================

This module defines the strongly-typed core data contracts for DocForge.
It uses Python's standard library `dataclasses` and `typing` to guarantee:
  1. Compile-time and IDE type safety via Python type hints.
  2. Immutability or safe mutation semantics across pipeline stages.
  3. Clean, deterministic JSON serialization and deserialization without third-party ORMs.
  4. Explicit data validation for enterprise architecture specifications.

Design Philosophy & Interview Talking Points:
---------------------------------------------
- "Why Dataclasses instead of Pydantic or Dictionaries?"
  In interview settings, candidates often reach reflexively for external dependencies
  like Pydantic or Marshmallow. In constrained environments, embedded systems, or zero-dependency
  developer tooling, relying solely on Python's built-in `dataclasses` drastically reduces
  container footprint, build times, and supply chain vulnerabilities. We achieve rigorous
  schema validation by writing concise, explicit deserialization factory methods (`from_dict`).

- "Clean Architecture & Domain Boundaries":
  The models defined here represent pure entity definitions (Entities in Domain-Driven Design).
  They have zero knowledge of Markdown formatting, filesystem IO, or CLI logic. Formatting
  belongs strictly in the engine and presentation layer, preserving the Single Responsibility
  Principle (SRP).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ===========================================================================
# Architectural Decision Record (ADR) Enumerations & Entities
# ===========================================================================

class ADRStatus(str, Enum):
    """
    Represents the operational lifecycle state of an Architectural Decision Record.
    Inheriting from `str` and `Enum` allows direct string comparison, JSON serialization,
    and human-readable representation without custom encoder hooks.
    """
    PROPOSED = "PROPOSED"      # Under review by the architecture review board (ARB)
    ACCEPTED = "ACCEPTED"      # Formally approved and implemented in production
    REJECTED = "REJECTED"      # Evaluated but declined due to cost, risk, or fit
    DEPRECATED = "DEPRECATED"  # Previously active, but no longer recommended for new systems
    SUPERSEDED = "SUPERSEDED"  # Replaced by a subsequent ADR (points to new ADR ID)

    def is_active(self) -> bool:
        """
        Determines if the architectural decision is currently active and governing production.
        Active decisions must be respected during design reviews and code audits.
        """
        return self in (ADRStatus.ACCEPTED, ADRStatus.PROPOSED)


@dataclass(frozen=True)
class ADR:
    """
    Architectural Decision Record (ADR) model following the Michael Nygard format.

    Why ADRs matter in System Design Interviews:
    --------------------------------------------
    When an interviewer asks "Why did you choose PostgreSQL over DynamoDB?", mediocre candidates
    recite feature comparisons. Staff engineers reference ADRs: they explain the historical
    context, the explicit constraints at the time, the alternatives evaluated, and the negative
    consequences accepted. Every architectural choice is a trade-off.

    Attributes:
        id: Unique identifier (e.g., 'ADR-001', 'ADR-SEC-04').
        title: Short, active-voice summary of the architectural choice.
        status: Current lifecycle state (ADRStatus).
        date: ISO 8601 formatted date string (YYYY-MM-DD) when the decision was finalized.
        context: Business drivers, technical constraints, forces, and problem statement.
        decision: The exact architectural direction chosen (what we are building and how).
        consequences: Dictionary with keys 'positive', 'negative', and 'neutral' trade-offs.
        superseded_by: Optional ID of the newer ADR that replaces this decision.
    """
    id: str
    title: str
    status: ADRStatus
    date: str
    context: str
    decision: str
    consequences: Dict[str, List[str]] = field(default_factory=dict)
    superseded_by: Optional[str] = None

    def __post_init__(self) -> None:
        """
        Validates internal invariants upon instantiation.
        In frozen dataclasses, object.__setattr__ is used if modification is needed,
        but here we only perform validation checks.
        """
        if not self.id or not self.id.strip():
            raise ValueError("ADR must possess a non-empty identifier (e.g., 'ADR-001').")
        if not self.title or not self.title.strip():
            raise ValueError(f"ADR {self.id} must possess a descriptive title.")
        if self.status == ADRStatus.SUPERSEDED and not self.superseded_by:
            raise ValueError(
                f"ADR {self.id} has status SUPERSEDED but does not specify 'superseded_by'."
            )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ADR:
        """
        Constructs an ADR from raw parsed JSON/dictionary data with defensive defaults.
        """
        raw_status = data.get("status", "PROPOSED").upper()
        try:
            status = ADRStatus(raw_status)
        except ValueError:
            status = ADRStatus.PROPOSED

        # Ensure consequences dictionary has normalized lists
        raw_consequences = data.get("consequences", {})
        normalized_consequences: Dict[str, List[str]] = {
            "positive": list(raw_consequences.get("positive", [])),
            "negative": list(raw_consequences.get("negative", [])),
            "neutral": list(raw_consequences.get("neutral", [])),
        }

        return cls(
            id=str(data.get("id", "ADR-000")).strip(),
            title=str(data.get("title", "Untitled Decision")).strip(),
            status=status,
            date=str(data.get("date", "1970-01-01")).strip(),
            context=str(data.get("context", "")).strip(),
            decision=str(data.get("decision", "")).strip(),
            consequences=normalized_consequences,
            superseded_by=data.get("superseded_by"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes the ADR entity to a clean Python dictionary.
        """
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status.value,
            "date": self.date,
            "context": self.context,
            "decision": self.decision,
            "consequences": self.consequences,
            "superseded_by": self.superseded_by,
        }


# ===========================================================================
# STRIDE Threat Modeling Enumerations & Entities
# ===========================================================================

class ThreatCategory(str, Enum):
    """
    Microsoft STRIDE Threat Classification Categories.
    Maps directly to security property violations:
      - Spoofing -> Violates Authentication
      - Tampering -> Violates Integrity
      - Repudiation -> Violates Non-repudiation
      - Information Disclosure -> Violates Confidentiality
      - Denial of Service -> Violates Availability
      - Elevation of Privilege -> Violates Authorization
    """
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

    @classmethod
    def from_string(cls, value: str) -> ThreatCategory:
        """
        Normalizes loose user strings (e.g. 'spoofing', 'DoS', 'privilege') to enum members.
        """
        cleaned = value.strip().lower()
        if "spoof" in cleaned:
            return cls.SPOOFING
        if "tamp" in cleaned:
            return cls.TAMPERING
        if "repud" in cleaned:
            return cls.REPUDIATION
        if "info" in cleaned or "disclos" in cleaned:
            return cls.INFORMATION_DISCLOSURE
        if "denial" in cleaned or "dos" in cleaned:
            return cls.DENIAL_OF_SERVICE
        if "elevat" in cleaned or "privil" in cleaned:
            return cls.ELEVATION_OF_PRIVILEGE
        return cls.INFORMATION_DISCLOSURE


class RiskLevel(str, Enum):
    """
    Standard quantitative / qualitative risk level based on Impact x Likelihood.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @classmethod
    def from_string(cls, value: str) -> RiskLevel:
        cleaned = value.strip().upper()
        if cleaned in cls.__members__:
            return cls[cleaned]
        return cls.MEDIUM

    def numeric_weight(self) -> int:
        """
        Returns numeric rank for sorting threats by severity (highest first).
        """
        weights = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.INFORMATIONAL: 1,
        }
        return weights.get(self, 0)


@dataclass(frozen=True)
class ThreatItem:
    """
    Represents an individual threat vector within the system architecture.

    Interview Defense Context:
    --------------------------
    Security is not an afterthought added before deployment; it is designed into the
    component topology. Explaining how each component mitigates STRIDE vectors demonstrates
    seniority, defense-in-depth thinking, and compliance readiness (SOC2, ISO 27001).

    Attributes:
        id: Unique threat tag (e.g., 'THREAT-01', 'STRIDE-S-01').
        category: STRIDE category enum.
        component: Target component or interface under attack.
        title: Short title describing the attack vector.
        description: Technical narrative of how an attacker exploits the vulnerability.
        risk_level: Qualitative severity assessment (CRITICAL, HIGH, MEDIUM, LOW).
        impact: Business or system consequence if exploited.
        mitigation: Specific engineering controls implemented to neutralize the threat.
        mitigation_status: Operational state ('IMPLEMENTED', 'PLANNED', 'ACCEPTED_RISK').
    """
    id: str
    category: ThreatCategory
    component: str
    title: str
    description: str
    risk_level: RiskLevel
    impact: str
    mitigation: str
    mitigation_status: str = "IMPLEMENTED"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ThreatItem:
        return cls(
            id=str(data.get("id", "THREAT-00")).strip(),
            category=ThreatCategory.from_string(str(data.get("category", "Information Disclosure"))),
            component=str(data.get("component", "General")).strip(),
            title=str(data.get("title", "Untitled Threat")).strip(),
            description=str(data.get("description", "")).strip(),
            risk_level=RiskLevel.from_string(str(data.get("risk_level", "MEDIUM"))),
            impact=str(data.get("impact", "")).strip(),
            mitigation=str(data.get("mitigation", "")).strip(),
            mitigation_status=str(data.get("mitigation_status", "IMPLEMENTED")).strip().upper(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "component": self.component,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "impact": self.impact,
            "mitigation": self.mitigation,
            "mitigation_status": self.mitigation_status,
        }


@dataclass(frozen=True)
class ThreatModel:
    """
    Complete system-level STRIDE threat model document.
    """
    system_name: str
    trust_boundaries: List[str] = field(default_factory=list)
    threats: List[ThreatItem] = field(default_factory=list)
    security_assumptions: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ThreatModel:
        raw_threats = data.get("threats", [])
        parsed_threats = [ThreatItem.from_dict(t) for t in raw_threats if isinstance(t, dict)]
        return cls(
            system_name=str(data.get("system_name", "System")).strip(),
            trust_boundaries=list(data.get("trust_boundaries", [])),
            threats=parsed_threats,
            security_assumptions=list(data.get("security_assumptions", [])),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "system_name": self.system_name,
            "trust_boundaries": self.trust_boundaries,
            "threats": [t.to_dict() for t in self.threats],
            "security_assumptions": self.security_assumptions,
        }


# ===========================================================================
# STAR Interview Guide & Technical Defense Entities
# ===========================================================================

@dataclass(frozen=True)
class STARStory:
    """
    Behavioral & Technical interview story formatted using the Amazon STAR method:
      - Situation: Background, company scale, traffic volume, problem urgency.
      - Task: Specific individual engineering responsibility and goal.
      - Action: Concrete architecture, coding, leadership, and debugging actions taken.
      - Result: Quantified business impact (latency cut, cost reduced, SLA achieved).

    Engineering Interview Coaching Note:
    ------------------------------------
    L5/L6 interviewers evaluate whether the candidate uses "I" instead of "We",
    whether the technical trade-offs are articulated, and whether the results are backed
    by real numbers (e.g., 'reduced p99 from 450ms to 45ms at 150k QPS').
    """
    id: str
    title: str
    competency: str  # e.g., "Distributed Systems", "Incident Response", "Performance"
    situation: str
    task: str
    action: str
    result: str
    metrics: Dict[str, str] = field(default_factory=dict)
    technical_deep_dive: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> STARStory:
        return cls(
            id=str(data.get("id", "STAR-01")).strip(),
            title=str(data.get("title", "Untitled Story")).strip(),
            competency=str(data.get("competency", "System Architecture")).strip(),
            situation=str(data.get("situation", "")).strip(),
            task=str(data.get("task", "")).strip(),
            action=str(data.get("action", "")).strip(),
            result=str(data.get("result", "")).strip(),
            metrics=dict(data.get("metrics", {})),
            technical_deep_dive=list(data.get("technical_deep_dive", [])),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "competency": self.competency,
            "situation": self.situation,
            "task": self.task,
            "action": self.action,
            "result": self.result,
            "metrics": self.metrics,
            "technical_deep_dive": self.technical_deep_dive,
        }


@dataclass(frozen=True)
class STARDefenseQA:
    """
    Technical Architecture Defense Q&A for high-stakes whiteboarding and system reviews.
    Anticipates tough interviewer questions:
      - "What happens if this node crashes mid-transaction?"
      - "Why did you choose gRPC over REST/JSON?"
      - "How do you protect against split-brain scenarios?"
    """
    question: str
    answer: str
    anti_pattern_to_avoid: str
    follow_up_probe: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> STARDefenseQA:
        return cls(
            question=str(data.get("question", "")).strip(),
            answer=str(data.get("answer", "")).strip(),
            anti_pattern_to_avoid=str(data.get("anti_pattern_to_avoid", "")).strip(),
            follow_up_probe=str(data.get("follow_up_probe", "")).strip(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "question": self.question,
            "answer": self.answer,
            "anti_pattern_to_avoid": self.anti_pattern_to_avoid,
            "follow_up_probe": self.follow_up_probe,
        }


# ===========================================================================
# Verification Gates & Component Topology Entities
# ===========================================================================

@dataclass(frozen=True)
class VerificationGate:
    """
    Automated verification checkpoint or quality gate enforced in CI/CD.
    Guarantees that architecture documentation aligns with actual codebase reality.
    """
    name: str
    command_or_rule: str
    acceptance_criteria: str
    failure_action: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VerificationGate:
        return cls(
            name=str(data.get("name", "Unnamed Gate")).strip(),
            command_or_rule=str(data.get("command_or_rule", "")).strip(),
            acceptance_criteria=str(data.get("acceptance_criteria", "")).strip(),
            failure_action=str(data.get("failure_action", "Block Pipeline")).strip(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "command_or_rule": self.command_or_rule,
            "acceptance_criteria": self.acceptance_criteria,
            "failure_action": self.failure_action,
        }


@dataclass(frozen=True)
class Component:
    """
    Represents an individual microservice, daemon, library, or database node
    within the system's Directed Acyclic Graph (DAG).

    Attributes:
        name: Unique identifier name for the component (e.g., 'AuthGateway').
        tier: Architectural layer (e.g., 'Ingress', 'Compute', 'Storage', 'Observability').
        description: Functional role of the component in the system.
        technologies: List of libraries, languages, or protocols used (e.g., ['Python', 'gRPC']).
        inputs: List of incoming data feeds or RPC endpoints.
        outputs: List of outgoing events, calls, or database writes.
        dependencies: Names of other Components this component directly depends upon.
    """
    name: str
    tier: str
    description: str
    technologies: List[str] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("Component must possess a valid, non-empty name.")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Component:
        return cls(
            name=str(data.get("name", "UnnamedComponent")).strip(),
            tier=str(data.get("tier", "Core")).strip(),
            description=str(data.get("description", "")).strip(),
            technologies=list(data.get("technologies", [])),
            inputs=list(data.get("inputs", [])),
            outputs=list(data.get("outputs", [])),
            dependencies=list(data.get("dependencies", [])),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tier": self.tier,
            "description": self.description,
            "technologies": self.technologies,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "dependencies": self.dependencies,
        }


# ===========================================================================
# Architectural Specification (Root Container)
# ===========================================================================

@dataclass
class ArchSpec:
    """
    The top-level root configuration object ingested by DocForge.
    Encompasses the entire system architecture, decision log, security threat model,
    interview defense artifacts, and automated verification gates.
    """
    system_name: str
    version: str
    document_id: str
    author: str
    date: str
    executive_summary: str
    architecture_overview: str
    components: List[Component] = field(default_factory=list)
    adrs: List[ADR] = field(default_factory=list)
    threat_model: Optional[ThreatModel] = None
    star_stories: List[STARStory] = field(default_factory=list)
    defense_qa: List[STARDefenseQA] = field(default_factory=list)
    verification_gates: List[VerificationGate] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ArchSpec:
        """
        Parses a nested dictionary specification into a fully validated ArchSpec instance.
        Performs safe type coercion and handles missing or optional sections gracefully.
        """
        # Parse Components
        raw_components = data.get("components", [])
        components = [Component.from_dict(c) for c in raw_components if isinstance(c, dict)]

        # Parse ADRs
        raw_adrs = data.get("adrs", [])
        adrs = [ADR.from_dict(a) for a in raw_adrs if isinstance(a, dict)]

        # Parse Threat Model
        raw_tm = data.get("threat_model")
        threat_model = ThreatModel.from_dict(raw_tm) if isinstance(raw_tm, dict) else None

        # Parse STAR Stories
        raw_star = data.get("star_stories", [])
        star_stories = [STARStory.from_dict(s) for s in raw_star if isinstance(s, dict)]

        # Parse Defense Q&A
        raw_qa = data.get("defense_qa", [])
        defense_qa = [STARDefenseQA.from_dict(q) for q in raw_qa if isinstance(q, dict)]

        # Parse Verification Gates
        raw_gates = data.get("verification_gates", [])
        verification_gates = [VerificationGate.from_dict(g) for g in raw_gates if isinstance(g, dict)]

        return cls(
            system_name=str(data.get("system_name", "Enterprise System")).strip(),
            version=str(data.get("version", "1.0.0")).strip(),
            document_id=str(data.get("document_id", "DOC-001")).strip(),
            author=str(data.get("author", "Lead Architect")).strip(),
            date=str(data.get("date", "2026-01-01")).strip(),
            executive_summary=str(data.get("executive_summary", "")).strip(),
            architecture_overview=str(data.get("architecture_overview", "")).strip(),
            components=components,
            adrs=adrs,
            threat_model=threat_model,
            star_stories=star_stories,
            defense_qa=defense_qa,
            verification_gates=verification_gates,
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_json_str(cls, json_str: str) -> ArchSpec:
        """
        Loads and parses an ArchSpec directly from a raw JSON string.
        """
        data = json.loads(json_str)
        if not isinstance(data, dict):
            raise ValueError("Root JSON payload must be an object/dictionary.")
        return cls.from_dict(data)

    @classmethod
    def from_json_file(cls, filepath: str) -> ArchSpec:
        """
        Loads and parses an ArchSpec from a filesystem path using standard UTF-8 encoding.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            return cls.from_json_str(f.read())

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes the complete architecture specification back into a clean dictionary.
        """
        return {
            "system_name": self.system_name,
            "version": self.version,
            "document_id": self.document_id,
            "author": self.author,
            "date": self.date,
            "executive_summary": self.executive_summary,
            "architecture_overview": self.architecture_overview,
            "components": [c.to_dict() for c in self.components],
            "adrs": [a.to_dict() for a in self.adrs],
            "threat_model": self.threat_model.to_dict() if self.threat_model else None,
            "star_stories": [s.to_dict() for s in self.star_stories],
            "defense_qa": [q.to_dict() for q in self.defense_qa],
            "verification_gates": [g.to_dict() for g in self.verification_gates],
            "metadata": self.metadata,
        }

    def to_json_str(self, indent: int = 2) -> str:
        """
        Serializes the specification to a formatted, deterministic JSON string.
        `sort_keys=True` ensures reproducible text ordering.
        """
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False)
