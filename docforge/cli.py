"""
DocForge Command-Line Interface (CLI)
=====================================

This module provides the terminal interface and subcommands for DocForge:
  1. `build`: Compiles specifications into whitepapers, threat models, ADRs, and STAR guides.
  2. `init`: Generates a fully populated, production-grade starter specification template.
  3. `validate`: Performs static analysis on architecture specs (cycle detection, unmitigated threats).
  4. `verify-hash`: Validates document SHA-256 integrity for CI/CD gates.

Design Philosophy & Interview Talking Points:
---------------------------------------------
- "UNIX Philosophy & Standard Streams":
  Tools must do one thing well and compose with standard UNIX pipelines (`stdout`, `stderr`, exit codes).
  DocForge supports emitting raw Markdown directly to `stdout` for piping into formatters or pandoc,
  while keeping informational logs on `stderr`.
- "Automated CI/CD Verification (GitOps)":
  The `verify-hash` subcommand provides a drop-in GitHub Actions / GitLab CI step. If an engineer
  manually tampers with an architecture whitepaper without updating the underlying specification,
  the CI pipeline fails immediately with exit code 1.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from docforge import __version__
from docforge.engine import (
    DocForgeEngine,
    calculate_fingerprint,
    topological_sort_components,
    verify_fingerprint,
)
from docforge.models import ArchSpec


# ===========================================================================
# Starter Templates for `docforge init`
# ===========================================================================

def generate_starter_template(template_name: str = "microservice") -> dict:
    """
    Returns a comprehensive, ready-to-customize architectural specification dictionary.
    """
    return {
        "system_name": "AegisCore Service Mesh",
        "version": "1.0.0",
        "document_id": "RFC-2026-AEGIS",
        "author": "Ethan Kilmer (Lead Systems Architect)",
        "date": "2026-11-08",
        "executive_summary": (
            "AegisCore is a zero-trust distributed service mesh providing sub-millisecond "
            "mutual TLS (mTLS), fine-grained attribute-based access control (ABAC), and "
            "deterministic cryptographic audit streaming across multi-region Kubernetes clusters."
        ),
        "architecture_overview": (
            "The system is organized into three decoupled tiers: Edge Ingress, Policy Decision, "
            "and Upstream Workloads. All traffic is intercepted at Layer 7 by lightweight sidecar proxies, "
            "validated against cryptographic identity tokens, and logged to append-only event ledgers."
        ),
        "components": [
            {
                "name": "EdgeIngressProxy",
                "tier": "Ingress",
                "description": "Terminates public TLS 1.3 connections, applies global rate limiting, and extracts client credentials.",
                "technologies": ["Rust", "Envoy", "OpenSSL"],
                "inputs": ["HTTPS Traffic (Port 443)"],
                "outputs": ["Internal gRPC Stream"],
                "dependencies": [],
            },
            {
                "name": "IdentityVerificationEngine",
                "tier": "Security",
                "description": "Validates cryptographic JWT signatures, parses SPIFFE IDs, and verifies tenant claim boundaries.",
                "technologies": ["Go", "SPIRE", "Ed25519"],
                "inputs": ["gRPC Verification Requests"],
                "outputs": ["Validated Identity Claims"],
                "dependencies": ["EdgeIngressProxy"],
            },
            {
                "name": "PolicyDecisionEngine",
                "tier": "Authorization",
                "description": "Evaluates OPA Rego policies against cached tenant ACLs with sub-millisecond evaluation latency.",
                "technologies": ["Open Policy Agent (OPA)", "Redis L1 Cache"],
                "inputs": ["Identity Claims + Requested Action"],
                "outputs": ["Allow / Deny Decision"],
                "dependencies": ["IdentityVerificationEngine"],
            },
            {
                "name": "AuditLedgerPublisher",
                "tier": "Observability",
                "description": "Publishes cryptographically signed, immutable audit records to partitioned streaming logs.",
                "technologies": ["Apache Kafka", "SHA-256"],
                "inputs": ["Policy Decisions"],
                "outputs": ["Audit Topic Events"],
                "dependencies": ["PolicyDecisionEngine"],
            },
            {
                "name": "InternalWorkloadProxy",
                "tier": "Upstream",
                "description": "Dispatches authorized, identity-annotated requests to target backend application microservices.",
                "technologies": ["gRPC", "HTTP/2"],
                "inputs": ["Authorized Workload Payloads"],
                "outputs": ["Application Responses"],
                "dependencies": ["PolicyDecisionEngine"],
            },
        ],
        "adrs": [
            {
                "id": "ADR-001",
                "title": "Adopt Rust for Ingress Gateway Data Plane",
                "status": "ACCEPTED",
                "date": "2026-02-15",
                "context": (
                    "The legacy Node.js ingress gateway experienced GC pauses resulting in p99 latency "
                    "spikes exceeding 280ms under 90k RPS load. We evaluated Go, C++, and Rust."
                ),
                "decision": (
                    "Implement the edge ingress reverse proxy in Rust using Tokio and Hyper, "
                    "leveraging zero-cost abstractions and deterministic memory management without garbage collection."
                ),
                "consequences": {
                    "positive": [
                        "Eliminated all GC pauses, cutting p99 tail latency from 280ms to 4.2ms.",
                        "Reduced memory footprint by 78% across 40 container replicas.",
                        "Guaranteed memory safety without risk of buffer overflows."
                    ],
                    "negative": [
                        "Steeper developer learning curve compared to Go.",
                        "Longer compilation times in CI/CD pipeline."
                    ],
                    "neutral": [
                        "Requires strict automated clippy lints in pull request gates."
                    ],
                },
                "superseded_by": None,
            },
            {
                "id": "ADR-002",
                "title": "Use Partitioned Kafka Topics for Compliance Audit Streaming",
                "status": "ACCEPTED",
                "date": "2026-03-01",
                "context": (
                    "Direct relational database logging created write contention on the PostgreSQL primary "
                    "during peak traffic events, causing cascading database connection pool exhaustion."
                ),
                "decision": (
                    "Decouple audit trail recording into an append-only Apache Kafka topic with tenant-keyed "
                    "partitioning and asynchronous downstream archival into Amazon S3 / Snowflake."
                ),
                "consequences": {
                    "positive": [
                        "100% write isolation: Ingress throughput is unaffected by downstream reporting queries.",
                        "Guarantees linearizability and strict ordering per tenant key."
                    ],
                    "negative": [
                        "Audit records are eventually consistent (typically 200ms lag before analytics visibility).",
                        "Requires monitoring Kafka consumer group lag in PagerDuty."
                    ],
                    "neutral": [
                        "Requires 7-day retention policy on broker SSD disks."
                    ],
                },
                "superseded_by": None,
            },
        ],
        "threat_model": {
            "system_name": "AegisCore Service Mesh",
            "trust_boundaries": [
                "Public Internet <-> Ingress TLS Termination",
                "Ingress Proxy <-> Internal Service Mesh Network",
                "Policy Decision Engine <-> Shared Redis Cache",
            ],
            "security_assumptions": [
                "All internal nodes possess valid hardware-backed TPM or SPIFFE mTLS certificates.",
                "Clock drift across cluster nodes is synchronized via NTP to within 10ms.",
            ],
            "threats": [
                {
                    "id": "THREAT-S-01",
                    "category": "Spoofing",
                    "component": "EdgeIngressProxy",
                    "title": "Client Identity Impersonation via Forged JWT Header",
                    "description": (
                        "An attacker sends an HTTP request with an unverified Alg: None or forged RSA signature "
                        "in an attempt to impersonate tenant administrators."
                    ),
                    "risk_level": "CRITICAL",
                    "impact": "Complete unauthorized tenant account takeover and data breach.",
                    "mitigation": (
                        "Edge gateway enforces strict RS256/ES256 signature verification using public keys fetched "
                        "over pinned mTLS from the JWKS provider. Alg: None is explicitly rejected at parser level."
                    ),
                    "mitigation_status": "IMPLEMENTED",
                },
                {
                    "id": "THREAT-T-01",
                    "category": "Tampering",
                    "component": "AuditLedgerPublisher",
                    "title": "Audit Event Modification in Message Pipeline",
                    "description": (
                        "A compromised internal node attempts to alter transaction IDs or amounts in the audit stream "
                        "before compliance reports are compiled."
                    ),
                    "risk_level": "HIGH",
                    "impact": "Falsification of financial/audit records resulting in regulatory fines.",
                    "mitigation": (
                        "Every audit payload is signed with an HMAC-SHA256 digest at generation time and verified "
                        "by downstream consumers. Kafka topics use ACLs restricting write access strictly to the publisher service account."
                    ),
                    "mitigation_status": "IMPLEMENTED",
                },
                {
                    "id": "THREAT-D-01",
                    "category": "Denial of Service",
                    "component": "EdgeIngressProxy",
                    "title": "Distributed SYN / HTTP Flood Resource Starvation",
                    "description": (
                        "Botnet transmits 500k RPS of slow-read HTTP requests to exhaust gateway socket connections and worker threads."
                    ),
                    "risk_level": "HIGH",
                    "impact": "Legitimate customer traffic dropped; SLA breach.",
                    "mitigation": (
                        "Multi-tiered defense: Cloudflare Edge DDoS mitigation upstream, followed by local Envoy token-bucket "
                        "rate limiting (10,000 req/min per IP) and strict connection timeouts (5s idle timeout)."
                    ),
                    "mitigation_status": "IMPLEMENTED",
                },
            ],
        },
        "star_stories": [
            {
                "id": "STAR-01",
                "title": "Redesigning Ingress Gateway for 150k QPS Peak",
                "competency": "Distributed Systems & Performance Optimization",
                "situation": (
                    "During peak Black Friday events, the core ingress layer experienced catastrophic latency degradation, "
                    "with p99 surging to 1,200ms and 504 gateway timeouts impacting $2M in revenue."
                ),
                "task": (
                    "As Lead Systems Architect, I was tasked with redesigning the ingress tier to support 200k sustained QPS "
                    "with a strict p99 budget under 10ms, while maintaining zero downtime during migration."
                ),
                "action": (
                    "I designed and deployed AegisCore using a Rust-based data plane. I implemented zero-copy network buffers, "
                    "migrated TLS termination to hardware-accelerated AES-NI/AVX-512 instructions, and introduced a 2-tier "
                    "local LRU cache to eliminate remote policy lookups for 94% of hot requests. I orchestrated a 1% -> 10% -> 100% "
                    "canary deployment over 14 days."
                ),
                "result": (
                    "Achieved 180k QPS sustained throughput with p99 latency dropping to 4.2ms. Infrastructure compute costs fell "
                    "by 42% ($85,000/yr savings), and the system maintained 99.999% uptime with zero customer-facing incidents."
                ),
                "metrics": {
                    "Throughput": "180,000 RPS",
                    "p99 Latency": "4.2 ms (down from 1,200 ms)",
                    "Infrastructure Savings": "$85,000 / year",
                    "Availability SLA": "99.999%",
                },
                "technical_deep_dive": [
                    "Tokio multi-threaded asynchronous runtime configured with core pinning to prevent CPU cache thrashing.",
                    "Custom Epoll event loop tuning on Linux kernel (`sysctl -w net.core.somaxconn=65535`).",
                    "Graceful connection draining using Envoy active health checks during rolling updates.",
                ],
            }
        ],
        "defense_qa": [
            {
                "question": "What happens when the PolicyDecisionEngine cluster crashes or partitions?",
                "answer": (
                    "We implement a fail-secure fallback posture with local L1 sidecar caching. Each edge proxy retains a local "
                    "read-only snapshot of policies with a 5-minute TTL. If the centralized decision engine is unreachable, "
                    "cached authorization decisions continue to serve valid sessions, while non-cached or high-risk administrative "
                    "mutations are rejected with HTTP 503 until quorum is restored."
                ),
                "anti_pattern_to_avoid": (
                    "Do NOT say 'we fail-open to preserve availability'. In security and financial gateways, failing open allows "
                    "attackers to intentionally DOS the policy engine to bypass all authorization checks."
                ),
                "follow_up_probe": "How do you invalidate the local L1 cache when a user role is revoked immediately?",
            },
            {
                "question": "Why did you choose gRPC over REST/JSON for inter-service communication?",
                "answer": (
                    "gRPC over HTTP/2 provides three decisive advantages for our data plane: First, Protocol Buffers binary serialization "
                    "is 6x faster and 4x smaller on the wire than JSON, directly reducing CPU serialization overhead. Second, HTTP/2 multiplexing "
                    "allows thousands of concurrent requests over a single TCP connection, eliminating head-of-line blocking and TLS handshake latency. "
                    "Third, strongly-typed Protobuf contracts eliminate schema drift across microservices."
                ),
                "anti_pattern_to_avoid": (
                    "Claiming gRPC is always superior without acknowledging debugging trade-offs (e.g. inability to easily curl endpoints without reflection)."
                ),
                "follow_up_probe": "How do you handle load balancing with long-lived HTTP/2 streams across backend replicas?",
            },
        ],
        "verification_gates": [
            {
                "name": "Deterministic Whitepaper Fingerprint Gate",
                "command_or_rule": "python3 -m docforge verify-hash -f docs/WHITEPAPER.md",
                "acceptance_criteria": "SHA-256 fingerprint matches computed document content exactly.",
                "failure_action": "Block Merge & Pull Request",
            },
            {
                "name": "Component DAG Cycle Detection",
                "command_or_rule": "python3 -m docforge validate -i spec.json",
                "acceptance_criteria": "Zero cyclic dependencies detected across microservice graph.",
                "failure_action": "Fail CI Build",
            },
            {
                "name": "STRIDE Critical Threat Mitigation Gate",
                "command_or_rule": "python3 -m docforge validate -i spec.json",
                "acceptance_criteria": "100% of CRITICAL and HIGH severity threats possess verified mitigations.",
                "failure_action": "Reject Security Release",
            },
        ],
        "metadata": {
            "environment": "Production Multi-Region Cloud",
            "compliance_standards": "SOC2 Type II, ISO 27001, PCI-DSS Level 1",
            "repository": "https://github.com/Ethan-da-Tech-Wizard/deterministic-doc-forge",
        },
    }


# ===========================================================================
# Subcommand Handlers
# ===========================================================================

def handle_build(args: argparse.Namespace) -> int:
    """
    Executes the `build` subcommand: loads specification, compiles Markdown,
    embeds cryptographic fingerprints, and writes artifacts to disk.
    """
    input_path = args.input
    if not os.path.isfile(input_path):
        sys.stderr.write(f"Error: Input specification file '{input_path}' not found.\n")
        return 1

    try:
        spec = ArchSpec.from_json_file(input_path)
    except Exception as exc:
        sys.stderr.write(f"Error parsing specification '{input_path}': {exc}\n")
        return 1

    engine = DocForgeEngine(spec)

    # If stdout flag is passed, emit whitepaper directly to terminal
    if getattr(args, "stdout", False):
        sys.stdout.write(engine.synthesize_whitepaper())
        return 0

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    formats = [f.strip().lower() for f in args.format.split(",")]
    generate_all = "all" in formats

    manifest = {}

    if generate_all or "whitepaper" in formats:
        content = engine.synthesize_whitepaper()
        path = os.path.join(output_dir, "WHITEPAPER.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        manifest["WHITEPAPER.md"] = calculate_fingerprint(content)

    if generate_all or "adr" in formats:
        content = engine.synthesize_adr_log()
        path = os.path.join(output_dir, "ADR_LOG.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        manifest["ADR_LOG.md"] = calculate_fingerprint(content)

    if generate_all or "stride" in formats:
        content = engine.synthesize_threat_model()
        path = os.path.join(output_dir, "THREAT_MODEL.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        manifest["THREAT_MODEL.md"] = calculate_fingerprint(content)

    if generate_all or "star" in formats:
        content = engine.synthesize_star_guide()
        path = os.path.join(output_dir, "STAR_INTERVIEW_GUIDE.md")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        manifest["STAR_INTERVIEW_GUIDE.md"] = calculate_fingerprint(content)

    # Print summary output
    sys.stdout.write("\n=== DocForge Deterministic Build Complete ===\n")
    sys.stdout.write(f"Target Directory: {os.path.abspath(output_dir)}\n\n")
    sys.stdout.write(f"{'Artifact File':<28} | {'SHA-256 Digest'}\n")
    sys.stdout.write(f"{'-' * 28}-+-{'-' * 64}\n")
    for filename, digest in sorted(manifest.items()):
        sys.stdout.write(f"{filename:<28} | {digest}\n")
    sys.stdout.write("\nAll documents cryptographically stamped and verified.\n")
    return 0


def handle_init(args: argparse.Namespace) -> int:
    """
    Executes the `init` subcommand: scaffolds a new starter specification JSON file.
    """
    output_path = args.output
    if os.path.exists(output_path) and not getattr(args, "force", False):
        sys.stderr.write(
            f"Error: Target file '{output_path}' already exists. Use --force to overwrite.\n"
        )
        return 1

    template_data = generate_starter_template(getattr(args, "template", "microservice"))

    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(template_data, f, indent=2, ensure_ascii=False)

    sys.stdout.write(f"Scaffolded new DocForge architecture specification: {os.path.abspath(output_path)}\n")
    sys.stdout.write("Run 'docforge build -i " + output_path + "' to compile into Markdown whitepapers.\n")
    return 0


def handle_validate(args: argparse.Namespace) -> int:
    """
    Executes the `validate` subcommand: runs static checks on DAG cycles,
    unmitigated security threats, and ADR consistency.
    """
    input_path = args.input
    if not os.path.isfile(input_path):
        sys.stderr.write(f"Error: Specification file '{input_path}' not found.\n")
        return 1

    try:
        spec = ArchSpec.from_json_file(input_path)
    except Exception as exc:
        sys.stderr.write(f"Validation FAILED: Invalid JSON or schema mismatch: {exc}\n")
        return 1

    issues: List[str] = []

    # 1. Check DAG topology and cycles
    layers, cycles = topological_sort_components(spec.components)
    if cycles:
        issues.extend([f"DAG Architecture: {c}" for c in cycles])

    # 2. Check ADR lifecycle
    engine = DocForgeEngine(spec)
    adr_issues = engine.adr_manager.validate_lifecycle()
    issues.extend([f"ADR Governance: {i}" for i in adr_issues])

    # 3. Check STRIDE threat mitigations
    stride_issues = engine.stride_analyzer.validate_threats()
    issues.extend([f"STRIDE Threat Model: {i}" for i in stride_issues])

    # Output results
    sys.stdout.write(f"\nValidating Architecture Specification: {input_path}\n")
    sys.stdout.write(f"System: {spec.system_name} (v{spec.version}) | Document ID: {spec.document_id}\n")
    sys.stdout.write(f"Components: {len(spec.components)} | ADRs: {len(spec.adrs)} | Threats: {len(spec.threat_model.threats if spec.threat_model else [])}\n")
    sys.stdout.write("-" * 70 + "\n")

    if issues:
        sys.stderr.write(f"Validation FAILED: Found {len(issues)} critical issue(s):\n")
        for idx, issue in enumerate(issues, 1):
            sys.stderr.write(f"  [{idx}] {issue}\n")
        return 1

    sys.stdout.write("Validation PASSED: All DAG topologies, ADR lifecycles, and STRIDE mitigations verified.\n")
    return 0


def handle_verify_hash(args: argparse.Namespace) -> int:
    """
    Executes the `verify-hash` subcommand: checks if document content matches embedded SHA-256.
    """
    file_path = args.file
    if not os.path.isfile(file_path):
        sys.stderr.write(f"Error: Target document '{file_path}' does not exist.\n")
        return 1

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    is_valid, embedded_hash, computed_hash = verify_fingerprint(content)

    sys.stdout.write(f"\nVerifying Document Integrity: {file_path}\n")
    sys.stdout.write(f"Embedded Digest: {embedded_hash or '<MISSING>'}\n")
    sys.stdout.write(f"Computed Digest: {computed_hash}\n")

    if not is_valid:
        sys.stderr.write("\nVerification FAILED: Cryptographic hash mismatch!\n")
        sys.stderr.write("The document was manually edited or corrupted after compilation.\n")
        return 1

    sys.stdout.write("\nVerification PASSED: Document matches cryptographic audit stamp.\n")
    return 0


# ===========================================================================
# Argument Parser Construction
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
    """
    Constructs the standard library ArgumentParser with intuitive CLI subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="docforge",
        description="DocForge: Zero-Dependency Deterministic Technical Documentation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"DocForge {__version__}",
        help="Print DocForge version and exit.",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. 'build' subcommand
    build_parser = subparsers.add_parser("build", help="Compile specification into Markdown documents.")
    build_parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the JSON architecture specification file.",
    )
    build_parser.add_argument(
        "-o", "--output-dir",
        default="docs",
        help="Destination directory for output documents (default: 'docs').",
    )
    build_parser.add_argument(
        "--format",
        default="all",
        help="Comma-separated formats to build: 'all', 'whitepaper', 'adr', 'stride', 'star' (default: 'all').",
    )
    build_parser.add_argument(
        "--stdout",
        action="store_true",
        help="Emit primary whitepaper directly to standard output.",
    )

    # 2. 'init' subcommand
    init_parser = subparsers.add_parser("init", help="Scaffold a new starter architecture specification.")
    init_parser.add_argument(
        "-o", "--output",
        default="architecture_spec.json",
        help="Target output filepath (default: 'architecture_spec.json').",
    )
    init_parser.add_argument(
        "--template",
        choices=["microservice", "security-gateway", "data-pipeline"],
        default="microservice",
        help="Architecture template pattern to scaffold.",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing destination file if present.",
    )

    # 3. 'validate' subcommand
    validate_parser = subparsers.add_parser("validate", help="Validate specification for cycles and missing mitigations.")
    validate_parser.add_argument(
        "-i", "--input",
        required=True,
        help="Path to the JSON architecture specification file to inspect.",
    )

    # 4. 'verify-hash' subcommand
    verify_parser = subparsers.add_parser("verify-hash", help="Verify cryptographic SHA-256 fingerprint in CI/CD.")
    verify_parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the Markdown file containing an embedded DocForge SHA-256 comment.",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for command-line execution.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help(sys.stderr)
        return 1

    if args.subcommand == "build":
        return handle_build(args)
    elif args.subcommand == "init":
        return handle_init(args)
    elif args.subcommand == "validate":
        return handle_validate(args)
    elif args.subcommand == "verify-hash":
        return handle_verify_hash(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
