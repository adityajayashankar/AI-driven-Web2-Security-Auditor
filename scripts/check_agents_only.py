from agents.llm_clients.openrouter_client import OpenRouterClient
from agents.planner.planner_llm import LLMPlanner
from agents.contracts import AgentContext
from agents.gatekeeper import enforce_plan
from sast.scope import ScopePolicy
import os


# -------------------------
# FREE LOCAL LLM (OpenRouter)
# -------------------------
client = OpenRouterClient(
    api_key=os.environ["OPENROUTER_API_KEY"],
    model="deepseek/deepseek-r1-0528:free",
)
planner = LLMPlanner(client)


# -------------------------
# Agent context (SAFE METADATA)
# -------------------------
ctx = AgentContext(
    repo="https://github.com/pallets/flask",
    languages=["python"],
    frameworks=["flask"],
    dependencies=["flask"],
    is_pr=False,
    changed_files=[],
    has_public_endpoint=True,
)


# -------------------------
# Scope policy
# -------------------------
scope = ScopePolicy(
    allowed_repo_prefixes=["https://github.com/"],
    allowed_domains=["localhost", "example.com"],
    safe_mode=True,
    max_requests=1000,
)


# -------------------------
# Run planner + gatekeeper
# -------------------------
plan = planner.plan(ctx)
final_plan = enforce_plan(plan, scope)


# -------------------------
# Output
# -------------------------
print("\n===== AI OUTPUT (ExecutionPlan) =====")
print(final_plan)

