import os
from dotenv import load_dotenv

from agents.planner.planner_llm import LLMPlanner
from agents.contracts import AgentContext
from agents.llm_clients.openrouter_client import OpenRouterClient

# Load env
load_dotenv()

client = OpenRouterClient(
    api_key=os.environ["OPENROUTER_API_KEY"],
    model="deepseek/deepseek-r1-0528:free",
)

planner = LLMPlanner(client)

ctx = AgentContext(
    repo="https://github.com/pallets/flask",
    languages=["python"],
    frameworks=["flask"],
    dependencies=["flask"],
    is_pr=False,
    changed_files=[],
    has_public_endpoint=True,
)

plan = planner.plan(ctx)

print("\n===== PLANNER OUTPUT =====")
print(plan)
