from agents.contracts import AgentContext
from agents.planner.planner_llm import LLMPlanner
from agents.gatekeeper import enforce_plan
from sast.orchestrator import run_security_checks
from sast.scope import ScopePolicy


def run_with_planner(
    input: dict,
    planner: LLMPlanner,
    scope: ScopePolicy,
) -> dict:
    """
    Authoritative execution entrypoint.
    AI decides WHAT to run.
    Orchestrator decides HOW to run.
    """

    # 1️⃣ Build AgentContext (SAFE METADATA ONLY)
    ctx = AgentContext(
        repo=input["repo_path"],
        languages=input.get("languages", []),
        frameworks=input.get("frameworks", []),
        dependencies=input.get("dependencies", []),
        is_pr=input.get("is_pr", False),
        changed_files=input.get("changed_files", []),
        has_public_endpoint=bool(input.get("dast", {}).get("target_url")),
    )

    # 2️⃣ AI planning
    plan = planner.plan(ctx)

    # 3️⃣ Hard policy enforcement
    final_plan = enforce_plan(plan, scope)

    # 4️⃣ Execute
    return run_security_checks(
        input=input,
        plan=final_plan,
        scope=scope,
    )
