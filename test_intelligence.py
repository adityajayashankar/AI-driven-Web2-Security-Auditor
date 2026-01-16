"""
End-to-end Intelligence Test
============================

Validates:
- Orchestrator -> Findings
- Findings -> Entities
- Deduplication
- SYSTEM handling
- Scoring & lifecycle
- AI Remediation (New)
"""

import os
from dotenv import load_dotenv

# 1. Load Environment Variables
load_dotenv()

from sast.orchestrator import run_security_checks
from sast.intelligence import build_intelligence
# [FIX 1] This import was missing or misplaced, causing "ScopePolicy not defined"
from sast.scope import ScopePolicy

# 2. Import Agents
from agents.llm_clients.openrouter_client import OpenRouterClient
from agents.remediation.remediator import RemediationAgent
from agents.contracts import AgentContext

# -------------------------
# Setup Remediation Agent
# -------------------------
remediator = None
if os.environ.get("OPENROUTER_API_KEY"):
    try:
        client = OpenRouterClient(api_key=os.environ["OPENROUTER_API_KEY"])
        remediator = RemediationAgent(client)
        print("✅ Remediation Agent initialized.")
    except Exception as e:
        print(f"⚠️ Failed to init Remediation Agent: {e}")
else:
    print("⚠️ No OPENROUTER_API_KEY found. Remediation will be skipped.")


def run_test_case(title: str, payload: dict, scope: ScopePolicy):
    print("\n" + "=" * 80)
    print(f"TEST CASE: {title}")
    print("=" * 80)

    # 1. Run Execution Plane
    res = run_security_checks(payload, scope)

    print("\n========== EXECUTION OUTPUT ==========")
    print("STATUS:", res["status"])
    print("TOOLS RUN:", res["tools"])
    print("RAW FINDINGS:", len(res["findings"]))

    # 2. Run Intelligence Plane
    # [FIX 2] This defines 'entities' so it can be used below
    entities = build_intelligence(res["findings"])

    print("\n========== INTELLIGENCE OUTPUT ==========")
    print("TOTAL ENTITIES:", len(entities))
    print("=" * 70)

    for i, e in enumerate(entities, start=1):
        print(f"\nENTITY #{i}")
        print("-" * 70)
        print("ENTITY ID:", e.entity_id)
        print("TITLE:", e.title)
        print("CATEGORY:", e.category)
        print("SEVERITY:", e.severity)
        print("CONFIDENCE:", e.confidence)
        print("RISK SCORE:", e.risk_score)
        print("SIGNALS:", len(e.signals))

    # 3. Run Agentic Remediation (New)
    if remediator and entities:
        print("\n========== AI REMEDIATION SAMPLES ==========")
        
        # Create a minimal context for the remediator based on input
        ctx = AgentContext(
            repo=payload.get("repo_path", ""),
            languages=payload.get("languages", []),
            frameworks=payload.get("frameworks", []),
            dependencies=payload.get("dependencies", []),
            is_pr=False,
            changed_files=[],
            has_public_endpoint=False
        )

        for e in entities:
            # Save money/time: only fix HIGH or CRITICAL issues in this test
            if e.severity in ("HIGH", "CRITICAL"):
                print(f"\n[AI Fix] Generating fix for: {e.title}")
                print(f"       (Rule: {e.weakness})")
                
                # Use the first signal as the evidence source
                if e.signals:
                    primary_signal = e.signals[0]
                    
                    finding_data = {
                        "title": e.title,
                        "tool": primary_signal.tool,
                        "rule_id": primary_signal.rule_id,
                        "file": primary_signal.file,
                        "evidence": primary_signal.evidence
                    }
                    
                    try:
                        fix = remediator.generate_fix(finding_data, ctx)
                        print("-" * 60)
                        print(fix)
                        print("-" * 60)
                    except Exception as err:
                        print(f"❌ AI Generation Failed: {err}")

    print("\n========== TEST COMPLETE ==========")


# ---------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------
if __name__ == "__main__":

    # Scope for tests
    scope = ScopePolicy(
        allowed_repo_prefixes=[""],
        allowed_domains=["localhost", "127.0.0.1"],
        safe_mode=True,
    )

    # Test 1: SAST + SCA (with Remediation)
    run_test_case(
        title="SAST + SCA (Remediation Test)",
        payload={
            "run_id": "remediation-test",
            "repo_path": ".",
            "languages": ["python"],
            "enable_sca": True,
            "dast": {},
        },
        scope=scope,
    )