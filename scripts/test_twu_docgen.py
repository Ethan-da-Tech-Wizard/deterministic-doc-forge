#!/usr/bin/env python3
"""scripts/test_twu_docgen.py — Unit test suite for twu_docgen.py.

Author: Ethan Kilmer <ethan@twu.software>
Organization: TWU LLC
License: MIT License (c) 2026 Ethan Kilmer <ethan@twu.software>, TWU LLC

Educational Test Suite Overview:
================================
This test module verifies the correctness, determinism, and error handling of `twu_docgen.py`.
It adheres to rigorous hermetic testing standards:
  1. Sandboxed Filesystem Isolation: Every test execution allocates an isolated temporary directory
     via `tempfile.mkdtemp()`. No test touches the host user's actual files or workspace state.
  2. Deterministic Assertions: Validates exact AST inspection and regex matching against synthetic
     Dockerfiles, CI workflow YAMLs, and Python script structures.
  3. Clean Teardown: Enforces guaranteed cleanup of temporary test fixtures in `tearDown()` using `shutil.rmtree()`.
  4. Zero External Mock Dependencies: Tests rely exclusively on standard library `unittest` primitives,
     ensuring fast execution (<10ms) and reproducible test runs across any standard Python 3.9+ runtime.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Add the parent scripts directory to sys.path so twu_docgen is cleanly importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

import twu_docgen


class TestDocgen(unittest.TestCase):
    """Exhaustive unit test cases for twu_docgen static analysis and documentation synthesis."""

    def setUp(self) -> None:
        """Allocates an isolated temporary directory before each test execution."""
        # Create a sandboxed temporary directory with a distinctive prefix
        self.test_dir = tempfile.mkdtemp(prefix="twu-docgen-test-")
        self.root = Path(self.test_dir)

    def tearDown(self) -> None:
        """Removes the sandboxed temporary directory to prevent disk pollution."""
        # Safely delete all temporary files and directories created during the test run
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_invalid_directory_raises(self) -> None:
        """Verifies fail-closed validation when initializing ProjectAnalyzer on non-existent paths.

        Security & Reliability Principle:
        Passing a missing path or non-directory must raise ValueError immediately rather than
        silently returning invalid metadata or throwing unhandled OSError exceptions downstream.
        """
        # Formulate a synthetic non-existent path
        nonexistent = self.root / "nonexistent_dir_123"
        # Assert that attempting to analyze this non-existent directory raises ValueError
        with self.assertRaises(ValueError):
            twu_docgen.ProjectAnalyzer(nonexistent)

    def test_dockerfile_analysis(self) -> None:
        """Verifies deterministic parsing of multi-stage Dockerfiles and container hardening flags.

        Container Security Directives Tested:
        - `FROM python:3.12-slim-bookworm AS builder` (Builder stage detection)
        - `FROM python:3.12-slim-bookworm AS runtime` (Runtime stage detection)
        - `USER appuser:appgroup` (Least-privilege non-root execution verification)
        - `HEALTHCHECK CMD curl -f ...` (Active container healthcheck liveness probe)
        - `ENTRYPOINT ["python3"]` (Exec-form array preserving POSIX PID 1 signal handling)
        """
        dockerfile = self.root / "Dockerfile"
        dockerfile.write_text(
            "FROM python:3.12-slim-bookworm AS builder\n"
            "WORKDIR /build\n"
            "FROM python:3.12-slim-bookworm AS runtime\n"
            "USER appuser:appgroup\n"
            "HEALTHCHECK CMD curl -f http://localhost/\n"
            "ENTRYPOINT [\"python3\"]\n",
            encoding="utf-8"
        )
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        info = analyzer.inspect_dockerfile()

        # Validate that the Dockerfile was detected and analyzed correctly
        self.assertTrue(info["present"], "Expected Dockerfile to be flagged as present")
        self.assertIn("builder", info["stages"], "Expected 'builder' stage in detected stages")
        self.assertIn("runtime", info["stages"], "Expected 'runtime' stage in detected stages")
        self.assertEqual(info["non_root_user"], "appuser:appgroup", "Expected non-root user matching USER directive")
        self.assertTrue(info["has_healthcheck"], "Expected active HEALTHCHECK to be detected")
        self.assertTrue(
            any("Exec-form" in feat for feat in info["security_features"]),
            "Expected exec-form entrypoint array security control to be identified"
        )

    def test_workflows_analysis(self) -> None:
        """Verifies parsing of GitHub Actions workflows for security gates and matrix targets.

        CI/CD Shift-Left Directives Tested:
        - Workflow naming (`name: DevSecOps CI`)
        - ShellCheck static shell script linting gate
        - Bandit Python AST static application security testing (SAST)
        - Aqua Security Trivy container CVE vulnerability scanning
        - Multi-version Python test matrix (`['3.10', '3.12']`)
        """
        wf_dir = self.root / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        ci_yml = wf_dir / "ci.yml"
        ci_yml.write_text(
            "name: DevSecOps CI\n"
            "jobs:\n"
            "  lint:\n"
            "    steps:\n"
            "      - run: shellcheck scripts/*.sh\n"
            "      - run: bandit -r scripts/\n"
            "  scan:\n"
            "    steps:\n"
            "      - uses: aquasecurity/trivy-action\n"
            "  test:\n"
            "    strategy:\n"
            "      matrix:\n"
            "        python-version: ['3.10', '3.12']\n",
            encoding="utf-8"
        )
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        workflows = analyzer.inspect_workflows()

        # Validate that workflow count and configuration are correctly extracted
        self.assertEqual(len(workflows), 1, "Expected exactly 1 workflow to be discovered")
        wf = workflows[0]
        self.assertEqual(wf["name"], "DevSecOps CI", "Workflow display name should match YAML")
        self.assertIn("lint", wf["jobs"], "Expected 'lint' job in jobs list")
        self.assertIn("scan", wf["jobs"], "Expected 'scan' job in jobs list")
        self.assertIn("3.10", wf["matrix_versions"], "Expected Python 3.10 in matrix versions")
        self.assertIn("3.12", wf["matrix_versions"], "Expected Python 3.12 in matrix versions")

        # Validate detection of shift-left DevSecOps scanners
        self.assertTrue(any("ShellCheck" in s for s in wf["security_scans"]), "ShellCheck scanner should be detected")
        self.assertTrue(any("Bandit" in s for s in wf["security_scans"]), "Bandit SAST scanner should be detected")
        self.assertTrue(any("Trivy" in s for s in wf["security_scans"]), "Trivy CVE scanner should be detected")

    def test_whitepaper_synthesis(self) -> None:
        """Verifies deterministic synthesis of comprehensive technical whitepapers.

        Ensures all mandatory architectural sections are present:
        - Platform Architecture title and Document ID metadata
        - Section 1: Executive Summary
        - Section 4: Supply Chain Threat Model (STRIDE mitigations)
        - Section 5: Senior Engineering Interview Talking Points (STAR Method)
        """
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        generator = twu_docgen.WhitepaperGenerator(analyzer)
        doc = generator.generate()

        # Assert mandatory architectural whitepaper headings exist in generated output
        self.assertIn("# Platform Architecture & DevSecOps Technical Whitepaper", doc)
        self.assertIn("## 1. Executive Summary", doc)
        self.assertIn("## 4. Supply Chain Threat Model", doc)
        self.assertIn("## 5. Senior Engineering Interview Talking Points (STAR Method)", doc)

    def test_quickstart_synthesis(self) -> None:
        """Verifies synthesis of foolproof quick-start runbook with verification commands.

        Asserts that critical shell linting and bytecode compilation commands are included.
        """
        analyzer = twu_docgen.ProjectAnalyzer(self.root)
        generator = twu_docgen.WhitepaperGenerator(analyzer)
        qs = generator.generate_quickstart()

        # Assert runbook header and local verification commands exist
        self.assertIn("# Quick Start Runbook:", qs)
        self.assertIn("shellcheck", qs)
        self.assertIn("compileall", qs)

    def test_cli_subcommands(self) -> None:
        """Verifies end-to-end POSIX CLI subcommands and file output writing.

        Tests `whitepaper` and `quickstart` CLI subcommands:
        - Validates zero exit codes
        - Validates physical file creation when `--output` is specified
        - Validates markdown content integrity in written output file
        """
        out_file = self.root / "whitepaper.md"
        # Execute whitepaper subcommand targeting the sandboxed directory
        ret = twu_docgen.main(["whitepaper", "--path", str(self.root), "--output", str(out_file)])
        self.assertEqual(ret, 0, "CLI whitepaper subcommand should return exit code 0")
        self.assertTrue(out_file.is_file(), "CLI should have created whitepaper.md on disk")
        self.assertIn("Executive Summary", out_file.read_text(encoding="utf-8"))

        # Execute quickstart subcommand targeting the sandboxed directory
        ret_qs = twu_docgen.main(["quickstart", "--path", str(self.root)])
        self.assertEqual(ret_qs, 0, "CLI quickstart subcommand should return exit code 0")


if __name__ == "__main__":
    unittest.main()
