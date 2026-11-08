"""
DocForge STAR Interview Guide & Technical Defense Engine
========================================================

This module transforms architectural specifications into structured engineering
interview preparation guides based on the Amazon STAR method (Situation, Task, Action, Result)
and rapid-fire technical defense Q&A.

Why Architecture Documentation Must Include Interview Prep:
------------------------------------------------------------
Great software engineers don't just build systems; they must successfully defend their designs
in front of:
  1. Internal Architecture Review Boards (ARBs) seeking to kill unnecessary projects.
  2. Security and Compliance auditors probing for regulatory gaps (SOC2/FedRAMP).
  3. Executive leadership demanding justification for compute/cloud expenditure.
  4. FAANG / Top-Tier Staff+ Technical Interviews during career advancement.

The STAR Methodology:
---------------------
- Situation: Set the context, scale, and pain point (e.g. "Legacy monolith falling over at 80k QPS").
- Task: State your specific mandate as the technical lead ("I was tasked with redesigning the ingress tier").
- Action: Deep-dive into specific engineering mechanisms chosen ("Implemented token-bucket rate limiting in Rust,
  integrated Envoy mTLS, and migrated to event-driven audit queues").
- Result: Quantitative, indisputable business metrics ("Reduced p99 latency by 68%, eliminated $140k/yr in idle
  compute, achieved 99.999% availability over 18 months").

Rapid-Fire Technical Defense Q&A:
---------------------------------
Interviewers probe system boundaries with adversarial questions:
- "Why didn't you just use Kafka?"
- "What happens if the cache cluster undergoes a network partition?"
- "How do you prevent thundering herd when an edge node recovers?"
This module automatically formats your architecture's core trade-offs into sharp,
defensible answers with explicit notes on anti-patterns to avoid.
"""

from __future__ import annotations

from typing import Dict, List, Optional
from docforge.models import STARDefenseQA, STARStory


class STARGuideGenerator:
    """
    Synthesizes STAR behavioral/technical stories and architecture defense Q&A into
    a comprehensive interview prep guide.
    """

    def __init__(
        self,
        stories: Optional[List[STARStory]] = None,
        defense_qa: Optional[List[STARDefenseQA]] = None,
    ) -> None:
        """
        Initializes the generator with optional collections of stories and defense Q&A.
        """
        self.stories: List[STARStory] = stories or []
        self.defense_qa: List[STARDefenseQA] = defense_qa or []

    def render_stories_markdown(self) -> str:
        """
        Renders STAR behavioral and technical execution narratives in markdown format.
        Emphasizes quantified metrics and technical deep-dive bullet points.
        """
        if not self.stories:
            return "_No STAR stories compiled for this architecture._\n"

        sections: List[str] = []

        for story in sorted(self.stories, key=lambda s: s.id):
            sec: List[str] = []
            sec.append(f"### Story [{story.id}]: {story.title}")
            sec.append(f"**Target Competency:** `{story.competency}`")
            sec.append("")

            # Quantified Impact Highlights
            if story.metrics:
                sec.append("#### Quantified Business & System Impact (The 'R' Metrics):")
                for metric_name, metric_val in story.metrics.items():
                    sec.append(f"- **{metric_name}:** `{metric_val}`")
                sec.append("")

            # STAR Framework Breakdown
            sec.append("#### STAR Narrative Structure:")
            sec.append(f"**Situation (Context & Scale):**\n{story.situation}\n")
            sec.append(f"**Task (Ownership & Objective):**\n{story.task}\n")
            sec.append(f"**Action (Technical Implementation & Architecture):**\n{story.action}\n")
            sec.append(f"**Result (Impact & Long-Term Health):**\n{story.result}\n")

            # Technical Deep Dive Talking Points
            if story.technical_deep_dive:
                sec.append("#### Follow-Up Probes / Technical Deep Dive Hooks:")
                sec.append("Use these details when the interviewer asks for lower-level specifics:")
                for point in story.technical_deep_dive:
                    sec.append(f"- [x] {point}")
                sec.append("")

            sections.append("\n".join(sec))

        return "\n\n---\n\n".join(sections) + "\n"

    def render_defense_qa_markdown(self) -> str:
        """
        Renders rapid-fire technical defense questions, optimal answers, and trap warnings.
        """
        if not self.defense_qa:
            return "_No Technical Defense Q&A registered._\n"

        sections: List[str] = []

        for idx, qa in enumerate(self.defense_qa, 1):
            sec: List[str] = []
            sec.append(f"#### Q{idx}: \"{qa.question}\"")
            sec.append("")
            sec.append("**Strong Senior / Staff Engineering Defense:**")
            sec.append(f"> {qa.answer}")
            sec.append("")

            if qa.anti_pattern_to_avoid:
                sec.append("**Trap / Anti-Pattern to Avoid:**")
                sec.append(f"⚠️ _{qa.anti_pattern_to_avoid}_")
                sec.append("")

            if qa.follow_up_probe:
                sec.append("**Interviewer Probe / Next Expected Question:**")
                sec.append(f"🔍 `{qa.follow_up_probe}`")
                sec.append("")

            sections.append("\n".join(sec))

        return "\n\n".join(sections) + "\n"

    def render_full_markdown(self) -> str:
        """
        Generates the complete STAR Interview Guide & Technical Defense document.
        """
        parts: List[str] = []
        parts.append("## STAR Interview Guide & Architecture Defense")
        parts.append("")
        parts.append(
            "This guide prepares engineers to defend this system's architecture in high-stakes "
            "technical interviews (Staff/L6+), Architecture Review Boards, and executive briefings."
        )
        parts.append("")

        parts.append("### 1. High-Impact STAR Stories")
        parts.append(self.render_stories_markdown())
        parts.append("")

        parts.append("### 2. Rapid-Fire Technical Defense Q&A")
        parts.append(self.render_defense_qa_markdown())

        return "\n".join(parts)
