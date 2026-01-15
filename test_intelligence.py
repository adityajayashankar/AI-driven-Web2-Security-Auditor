"""
End-to-end Intelligence Test
============================

Validates:
- Orchestrator → Findings
- Findings → Entities
- Deduplication
- SYSTEM handling
- Scoring & lifecycle
"""

from sast.orchestrator import run_security_checks
from sast.intelligence import build_intelligence
from sast.scope import ScopePolicy


def run_test_case(title: str, payload: dict, scope: ScopePolicy):
    print("\n" + "=" * 80)
    print(f"TEST CASE: {title}")
    print("=" * 80)

    res = run_security_checks(payload, scope)

    print("\n========== EXECUTION OUTPUT ==========")
    print("STATUS:", res["status"])
    print("TOOLS RUN:", res["tools"])
    print("RAW FINDINGS:", len(res["findings"]))

    if res["findings"]:
        print("FINDING TYPE:", type(res["findings"][0]))

    entities = build_intelligence(res["findings"])

    print("\n========== INTELLIGENCE OUTPUT ==========")
    print("TOTAL ENTITIES:", len(entities))
    print("=" * 70)

    for i, e in enumerate(entities, start=1):
        print(f"\nENTITY #{i}")
        print("-" * 70)
        print("ENTITY ID:", e.entity_id)
        print("TITLE:", e.title)

        # ✅ FIX: Entity has NO rule_id — derive from signals
        print("WEAKNESSES:", {s.rule_id for s in e.signals})

        print("CATEGORY:", e.category)
        print("SEVERITY:", e.severity)
        print("CONFIDENCE:", e.confidence)
        print("EXPLOITABILITY:", e.exploitability)
        print("RISK SCORE:", e.risk_score)
        print("SLA (days):", e.sla_days)
        print("FIRST SEEN:", e.first_seen)
        print("LAST SEEN:", e.last_seen)
        print("TIMES SEEN:", e.times_seen)
        print("RESURFACED:", e.resurfaced)

        print("\nSIGNALS:", len(e.signals))
        for s in e.signals:
            print(
                f"  - TOOL: {s.tool} | "
                f"CATEGORY: {s.category} | "
                f"RULE: {s.rule_id} | "
                f"SEVERITY: {s.severity}"
            )

    print("\n========== TEST COMPLETE ==========")


# ---------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------
if __name__ == "__main__":

    # -------------------------
    # Scope for tests
    # -------------------------
    scope = ScopePolicy(
        allowed_repo_prefixes=[""],
        allowed_domains=["localhost", "127.0.0.1"],
        safe_mode=True,
    )

    # -------------------------
    # Test 1: SAST + SCA only
    # -------------------------
    run_test_case(
        title="SAST + SCA (no DAST)",
        payload={
            "run_id": "test-sast-sca",
            "repo_path": ".",
            "languages": ["python"],
            "enable_sca": True,
            "dast": {},
        },
        scope=scope,
    )

    # -------------------------
    # Test 2: DAST blocked by scope
    # -------------------------
    run_test_case(
        title="DAST blocked by scope",
        payload={
            "run_id": "test-dast-blocked",
            "repo_path": ".",
            "languages": ["python"],
            "enable_sca": False,
            "dast": {
                "target_url": "https://example.com",
            },
        },
        scope=scope,
    )

    # -------------------------
    # Test 3: DAST + Config/Auth (localhost)
    # -------------------------
    run_test_case(
        title="DAST + Config/Auth (allowed target)",
        payload={
            "run_id": "test-dast-allowed",
            "repo_path": ".",
            "languages": ["python"],
            "enable_sca": False,
            "dast": {
                "target_url": "http://localhost:8000",
            },
        },
        scope=scope,
    )
