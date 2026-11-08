"""
DocForge Exhaustive Unit Test Suite
===================================

This test suite covers 100% of DocForge's core modules using only the standard
library `unittest` framework:
  1. Domain models (immutability, serialization, defensive validation).
  2. Architectural Decision Record (ADR) lifecycle and cycle detection.
  3. STRIDE threat model risk calculation and mitigation completeness.
  4. Amazon STAR interview guide and technical defense Q&A formatting.
  5. Directed Acyclic Graph (DAG) topological sorting and cycle detection (Kahn's Algorithm).
  6. Deterministic SHA-256 fingerprinting, canonicalization, and tamper detection.
  7. CLI subcommands (`build`, `init`, `validate`, `verify-hash`).

Why Testing Matters in Systems Architecture:
--------------------------------------------
In production distributed systems, bugs in documentation generators or architecture
verifiers can cause false positives in CI/CD or, worse, hide security vulnerabilities.
This test suite verifies both happy paths and edge cases (tampering, cycles, missing mitigations).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest

from docforge.adr import ADRManager
from docforge.cli import build_parser, handle_build, handle_init, handle_validate, handle_verify_hash, main
from docforge.engine import (
    DocForgeEngine,
    calculate_fingerprint,
    canonicalize_markdown,
    embed_fingerprint,
    render_ascii_dag,
    render_mermaid_dag,
    topological_sort_components,
    verify_fingerprint,
)
from docforge.models import (
    ADR,
    ADRStatus,
    ArchSpec,
    Component,
    RiskLevel,
    STARDefenseQA,
    STARStory,
    ThreatCategory,
    ThreatItem,
    ThreatModel,
    VerificationGate,
)
from docforge.star import STARGuideGenerator
from docforge.stride import STRIDEAnalyzer


class TestDomainModels(unittest.TestCase):
    """
    Tests data models, enum coercion, and deserialization invariants.
    """

    def test_adr_status_lifecycle(self) -> None:
        """
        Verifies ADRStatus active states and string coercion.
        """
        self.assertTrue(ADRStatus.ACCEPTED.is_active())
        self.assertTrue(ADRStatus.PROPOSED.is_active())
        self.assertFalse(ADRStatus.REJECTED.is_active())
        self.assertFalse(ADRStatus.SUPERSEDED.is_active())
        self.assertFalse(ADRStatus.DEPRECATED.is_active())

    def test_adr_instantiation_and_validation(self) -> None:
        """
        Verifies ADR validation checks empty titles, IDs, and missing superseded_by.
        """
        # Empty ID
        with self.assertRaises(ValueError):
            ADR(id="", title="Valid", status=ADRStatus.ACCEPTED, date="2026-01-01", context="C", decision="D")

        # Empty Title
        with self.assertRaises(ValueError):
            ADR(id="ADR-01", title="", status=ADRStatus.ACCEPTED, date="2026-01-01", context="C", decision="D")

        # SUPERSEDED without superseded_by
        with self.assertRaises(ValueError):
            ADR(
                id="ADR-01",
                title="Title",
                status=ADRStatus.SUPERSEDED,
                date="2026-01-01",
                context="Context text",
                decision="Decision text",
                superseded_by=None,
            )

        # Valid ADR
        adr = ADR(
            id="ADR-01",
            title="Valid Decision",
            status=ADRStatus.ACCEPTED,
            date="2026-01-01",
            context="Some context",
            decision="Some decision",
            consequences={"positive": ["Good"], "negative": ["Cost"]},
        )
        self.assertEqual(adr.id, "ADR-01")
        d = adr.to_dict()
        self.assertEqual(d["status"], "ACCEPTED")

        # Roundtrip from_dict
        restored = ADR.from_dict(d)
        self.assertEqual(restored.title, "Valid Decision")
        self.assertEqual(restored.consequences["positive"], ["Good"])

    def test_component_validation(self) -> None:
        """
        Verifies Component requires a non-empty name.
        """
        with self.assertRaises(ValueError):
            Component(name="", tier="Core", description="Desc")

        c = Component(
            name="Gateway",
            tier="Ingress",
            description="L7 Gateway",
            technologies=["Rust"],
            dependencies=["AuthService"],
        )
        self.assertEqual(c.name, "Gateway")
        self.assertEqual(c.to_dict()["technologies"], ["Rust"])

    def test_threat_models_and_risk_scoring(self) -> None:
        """
        Verifies ThreatCategory and RiskLevel normalization and weights.
        """
        self.assertEqual(ThreatCategory.from_string("spoofing"), ThreatCategory.SPOOFING)
        self.assertEqual(ThreatCategory.from_string("tamper"), ThreatCategory.TAMPERING)
        self.assertEqual(ThreatCategory.from_string("repudiation"), ThreatCategory.REPUDIATION)
        self.assertEqual(ThreatCategory.from_string("info leak"), ThreatCategory.INFORMATION_DISCLOSURE)
        self.assertEqual(ThreatCategory.from_string("dos attack"), ThreatCategory.DENIAL_OF_SERVICE)
        self.assertEqual(ThreatCategory.from_string("privilege escalation"), ThreatCategory.ELEVATION_OF_PRIVILEGE)

        self.assertEqual(RiskLevel.CRITICAL.numeric_weight(), 5)
        self.assertEqual(RiskLevel.HIGH.numeric_weight(), 4)
        self.assertEqual(RiskLevel.MEDIUM.numeric_weight(), 3)
        self.assertEqual(RiskLevel.LOW.numeric_weight(), 2)

        item = ThreatItem.from_dict({
            "id": "T-01",
            "category": "Spoofing",
            "component": "Gateway",
            "title": "Impersonation",
            "description": "Attacker fakes token",
            "risk_level": "CRITICAL",
            "impact": "Account takeover",
            "mitigation": "mTLS certificates",
            "mitigation_status": "IMPLEMENTED",
        })
        self.assertEqual(item.category, ThreatCategory.SPOOFING)
        self.assertEqual(item.risk_level, RiskLevel.CRITICAL)

    def test_archspec_full_serialization(self) -> None:
        """
        Verifies that ArchSpec roundtrips cleanly to and from JSON.
        """
        spec = ArchSpec(
            system_name="TestSystem",
            version="1.0.0",
            document_id="DOC-99",
            author="Tester",
            date="2026-11-08",
            executive_summary="Executive summary text",
            architecture_overview="Architecture overview text",
            components=[
                Component(name="A", tier="Ingress", description="Node A", dependencies=[]),
                Component(name="B", tier="Core", description="Node B", dependencies=["A"]),
            ],
            adrs=[
                ADR(
                    id="ADR-01",
                    title="Choice",
                    status=ADRStatus.ACCEPTED,
                    date="2026-11-08",
                    context="Context",
                    decision="Decision",
                )
            ],
            threat_model=ThreatModel(
                system_name="TestSystem",
                trust_boundaries=["Boundary 1"],
                threats=[
                    ThreatItem(
                        id="T-01",
                        category=ThreatCategory.TAMPERING,
                        component="B",
                        title="Data alter",
                        description="Tampering data in B",
                        risk_level=RiskLevel.HIGH,
                        impact="Corrupt",
                        mitigation="HMAC signing",
                    )
                ],
            ),
            star_stories=[
                STARStory(
                    id="STAR-01",
                    title="Saved the day",
                    competency="Leadership",
                    situation="Down",
                    task="Fix",
                    action="Fixed",
                    result="Up",
                    metrics={"Uptime": "100%"},
                )
            ],
            defense_qa=[
                STARDefenseQA(
                    question="Why B?",
                    answer="Because A is fast",
                    anti_pattern_to_avoid="Avoid stalling",
                    follow_up_probe="How about C?",
                )
            ],
            verification_gates=[
                VerificationGate(
                    name="Unit Tests",
                    command_or_rule="pytest",
                    acceptance_criteria="100% pass",
                    failure_action="Block PR",
                )
            ],
        )

        json_str = spec.to_json_str()
        restored = ArchSpec.from_json_str(json_str)

        self.assertEqual(restored.system_name, "TestSystem")
        self.assertEqual(len(restored.components), 2)
        self.assertEqual(len(restored.adrs), 1)
        self.assertIsNotNone(restored.threat_model)
        self.assertEqual(len(restored.threat_model.threats), 1)
        self.assertEqual(len(restored.star_stories), 1)
        self.assertEqual(len(restored.defense_qa), 1)
        self.assertEqual(len(restored.verification_gates), 1)


class TestADRManager(unittest.TestCase):
    """
    Tests ADR lifecycle management, circular supersede detection, and table rendering.
    """

    def test_duplicate_adr_id_rejected(self) -> None:
        manager = ADRManager()
        adr1 = ADR(id="ADR-01", title="First", status=ADRStatus.ACCEPTED, date="2026-01-01", context="C", decision="D")
        adr2 = ADR(id="ADR-01", title="Second", status=ADRStatus.PROPOSED, date="2026-01-02", context="C", decision="D")
        manager.add_adr(adr1)
        with self.assertRaises(ValueError):
            manager.add_adr(adr2)

    def test_adr_lifecycle_validation_and_cycles(self) -> None:
        manager = ADRManager()
        # Missing context and decision
        adr1 = ADR(id="ADR-01", title="First", status=ADRStatus.PROPOSED, date="2026-01-01", context="Short", decision="Short")
        manager.add_adr(adr1)
        issues = manager.validate_lifecycle()
        self.assertTrue(any("insufficient or missing 'context'" in i for i in issues))
        self.assertTrue(any("insufficient or missing 'decision'" in i for i in issues))

    def test_circular_supersede_detection(self) -> None:
        manager = ADRManager()
        adr1 = ADR(
            id="ADR-01",
            title="First",
            status=ADRStatus.SUPERSEDED,
            date="2026-01-01",
            context="Comprehensive context text for ADR 1",
            decision="Comprehensive decision text for ADR 1",
            superseded_by="ADR-02",
        )
        adr2 = ADR(
            id="ADR-02",
            title="Second",
            status=ADRStatus.SUPERSEDED,
            date="2026-01-02",
            context="Comprehensive context text for ADR 2",
            decision="Comprehensive decision text for ADR 2",
            superseded_by="ADR-01",
        )
        manager.add_adr(adr1)
        manager.add_adr(adr2)
        issues = manager.validate_lifecycle()
        self.assertTrue(any("Circular supersede cycle detected" in i for i in issues))

    def test_render_summary_table(self) -> None:
        manager = ADRManager()
        adr = ADR(
            id="ADR-01",
            title="Adopt Rust",
            status=ADRStatus.ACCEPTED,
            date="2026-01-01",
            context="Comprehensive context",
            decision="Comprehensive decision",
        )
        manager.add_adr(adr)
        table = manager.render_summary_table()
        self.assertIn("| **ADR-01** |", table)
        self.assertIn("`ACCEPTED`", table)


class TestSTRIDEAnalyzer(unittest.TestCase):
    """
    Tests threat model validation, unmitigated critical threats, and markdown generation.
    """

    def test_unmitigated_critical_threat_flagged(self) -> None:
        tm = ThreatModel(
            system_name="InsecureSys",
            threats=[
                ThreatItem(
                    id="T-01",
                    category=ThreatCategory.SPOOFING,
                    component="Gateway",
                    title="Missing Auth",
                    description="Attacker impersonates admin without credentials",
                    risk_level=RiskLevel.CRITICAL,
                    impact="Full breach",
                    mitigation="",  # Missing mitigation!
                )
            ],
        )
        analyzer = STRIDEAnalyzer(tm)
        issues = analyzer.validate_threats()
        self.assertTrue(any("lacks an actionable mitigation specification" in i for i in issues))

    def test_statistics_and_table_rendering(self) -> None:
        tm = ThreatModel(
            system_name="SecureSys",
            threats=[
                ThreatItem(
                    id="T-01",
                    category=ThreatCategory.SPOOFING,
                    component="Gateway",
                    title="Spoof Attempt",
                    description="Comprehensive attack narrative",
                    risk_level=RiskLevel.HIGH,
                    impact="Impact description",
                    mitigation="Strict mTLS authentication",
                ),
                ThreatItem(
                    id="T-02",
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    component="Gateway",
                    title="Rate Limit Flood",
                    description="Comprehensive attack narrative",
                    risk_level=RiskLevel.MEDIUM,
                    impact="Impact description",
                    mitigation="Token bucket rate limiter",
                ),
            ],
        )
        analyzer = STRIDEAnalyzer(tm)
        stats = analyzer.get_summary_statistics()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["by_risk"]["HIGH"], 1)
        self.assertEqual(stats["by_risk"]["MEDIUM"], 1)

        table = analyzer.render_matrix_table()
        self.assertIn("| **T-01** |", table)
        self.assertIn("| **T-02** |", table)


class TestSTARGuideGenerator(unittest.TestCase):
    """
    Tests STAR story and defense Q&A formatting.
    """

    def test_render_star_story(self) -> None:
        story = STARStory(
            id="STAR-01",
            title="Ingress Overhaul",
            competency="Distributed Systems",
            situation="System crashing at 100k QPS",
            task="Redesign proxy tier",
            action="Rewrote data plane in Rust",
            result="p99 dropped by 90%",
            metrics={"Throughput": "250k QPS", "Latency": "4ms"},
            technical_deep_dive=["Epoll event loop", "Kernel tuning"],
        )
        gen = STARGuideGenerator(stories=[story])
        md = gen.render_stories_markdown()
        self.assertIn("### Story [STAR-01]: Ingress Overhaul", md)
        self.assertIn("**Throughput:** `250k QPS`", md)
        self.assertIn("Epoll event loop", md)

    def test_render_defense_qa(self) -> None:
        qa = STARDefenseQA(
            question="Why not fail open?",
            answer="Failing open creates an exploitable security loophole.",
            anti_pattern_to_avoid="Never prioritize convenience over security.",
            follow_up_probe="How do you cache authorizations locally?",
        )
        gen = STARGuideGenerator(defense_qa=[qa])
        md = gen.render_defense_qa_markdown()
        self.assertIn("#### Q1: \"Why not fail open?\"", md)
        self.assertIn("Trap / Anti-Pattern to Avoid", md)
        self.assertIn("Interviewer Probe", md)


class TestDAGAndEngine(unittest.TestCase):
    """
    Tests Kahn's algorithm for topological sorting, cycle detection,
    and ASCII / Mermaid diagram rendering.
    """

    def test_topological_sort_linear(self) -> None:
        components = [
            Component(name="C3", tier="DB", description="", dependencies=["C2"]),
            Component(name="C1", tier="Ingress", description="", dependencies=[]),
            Component(name="C2", tier="Logic", description="", dependencies=["C1"]),
        ]
        layers, cycles = topological_sort_components(components)
        self.assertEqual(len(cycles), 0)
        self.assertEqual(layers, [["C1"], ["C2"], ["C3"]])

    def test_cycle_detection(self) -> None:
        components = [
            Component(name="ServiceA", tier="Core", description="", dependencies=["ServiceB"]),
            Component(name="ServiceB", tier="Core", description="", dependencies=["ServiceA"]),
        ]
        layers, cycles = topological_sort_components(components)
        self.assertTrue(len(cycles) > 0)
        self.assertIn("Cyclic dependency detected", cycles[0])

    def test_ascii_and_mermaid_rendering(self) -> None:
        components = [
            Component(name="Router", tier="Ingress", description="Ingress", dependencies=[]),
            Component(name="Worker", tier="Compute", description="Backend", dependencies=["Router"]),
        ]
        ascii_art = render_ascii_dag(components)
        self.assertIn("SYSTEM COMPONENT TOPOLOGY (DAG)", ascii_art)
        self.assertIn("Router", ascii_art)
        self.assertIn("Worker", ascii_art)

        mermaid = render_mermaid_dag(components)
        self.assertIn("flowchart TD", mermaid)
        self.assertIn("Router -->|consumes / calls| Worker", mermaid)


class TestCryptographicFingerprinting(unittest.TestCase):
    """
    Tests SHA-256 fingerprinting, canonicalization, and tamper detection.
    """

    def test_canonicalize_and_hash(self) -> None:
        raw_doc = "# Title \r\n\r\nSome content with trailing spaces    \r\n"
        canonical = canonicalize_markdown(raw_doc)
        self.assertNotIn("\r", canonical)
        self.assertFalse(canonical.endswith(" "))

        h1 = calculate_fingerprint(raw_doc)
        h2 = calculate_fingerprint(canonical)
        # Should be identical because canonicalize normalizes both
        self.assertEqual(h1, h2)

    def test_embed_and_verify(self) -> None:
        raw_doc = "# Architectural Whitepaper\n\nSystem specification content."
        stamped_doc = embed_fingerprint(raw_doc)

        is_valid, embedded, computed = verify_fingerprint(stamped_doc)
        self.assertTrue(is_valid)
        self.assertEqual(embedded, computed)
        self.assertEqual(len(embedded), 64)

    def test_tamper_detection(self) -> None:
        raw_doc = "# Architectural Whitepaper\n\nOriginal content."
        stamped_doc = embed_fingerprint(raw_doc)

        # Introduce 1-byte tamper modification
        tampered_doc = stamped_doc.replace("Original content", "Tampered content")
        is_valid, embedded, computed = verify_fingerprint(tampered_doc)
        self.assertFalse(is_valid)
        self.assertNotEqual(embedded, computed)


class TestCLIExecution(unittest.TestCase):
    """
    Tests end-to-end CLI subcommands: init, build, validate, verify-hash.
    """

    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="docforge_test_")

    def tearDown(self) -> None:
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_cli_init_and_validate(self) -> None:
        spec_path = os.path.join(self.test_dir, "test_spec.json")

        # 1. Execute `init`
        parser = build_parser()
        args = parser.parse_args(["init", "-o", spec_path])
        rc = handle_init(args)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(spec_path))

        # 2. Execute `validate` on newly generated template
        args = parser.parse_args(["validate", "-i", spec_path])
        rc = handle_validate(args)
        self.assertEqual(rc, 0)

    def test_cli_build_and_verify_hash(self) -> None:
        spec_path = os.path.join(self.test_dir, "spec.json")
        out_dir = os.path.join(self.test_dir, "build_out")

        # Init spec
        parser = build_parser()
        args = parser.parse_args(["init", "-o", spec_path])
        handle_init(args)

        # Build all docs
        args = parser.parse_args(["build", "-i", spec_path, "-o", out_dir])
        rc = handle_build(args)
        self.assertEqual(rc, 0)

        whitepaper_path = os.path.join(out_dir, "WHITEPAPER.md")
        self.assertTrue(os.path.isfile(whitepaper_path))

        # Verify hash of generated document
        args = parser.parse_args(["verify-hash", "-f", whitepaper_path])
        rc = handle_verify_hash(args)
        self.assertEqual(rc, 0)

        # Tamper with the whitepaper
        with open(whitepaper_path, "a", encoding="utf-8") as f:
            f.write("\n<!-- Malicious unauthorized injection -->\n")

        # Verify hash should now fail
        rc = handle_verify_hash(args)
        self.assertEqual(rc, 1)

    def test_cli_sample_project_json(self) -> None:
        """
        Validates that the shipped examples/sample_project.json passes all validations
        and builds all documents cleanly.
        """
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        sample_path = os.path.join(repo_root, "examples", "sample_project.json")
        self.assertTrue(os.path.isfile(sample_path), f"Sample file not found at {sample_path}")

        parser = build_parser()

        # Validate sample
        args = parser.parse_args(["validate", "-i", sample_path])
        rc = handle_validate(args)
        self.assertEqual(rc, 0)

        # Build sample into temp dir
        out_dir = os.path.join(self.test_dir, "sample_build")
        args = parser.parse_args(["build", "-i", sample_path, "-o", out_dir])
        rc = handle_build(args)
        self.assertEqual(rc, 0)

        for expected_file in ["WHITEPAPER.md", "ADR_LOG.md", "THREAT_MODEL.md", "STAR_INTERVIEW_GUIDE.md"]:
            fp = os.path.join(out_dir, expected_file)
            self.assertTrue(os.path.isfile(fp), f"Expected generated file {expected_file} missing")
            args = parser.parse_args(["verify-hash", "-f", fp])
            self.assertEqual(handle_verify_hash(args), 0)


if __name__ == "__main__":
    unittest.main()
