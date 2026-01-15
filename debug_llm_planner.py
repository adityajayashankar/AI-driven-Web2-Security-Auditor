from agents.planner.planner_llm import LLMPlanner
from agents.contracts import AgentContext

# Mock / real client depending on environment
from openai import OpenAI
client = OpenAI()

ctx = AgentContext(
    repo="example/repo",
    languages=["python"],
    frameworks=["fastapi"],
    dependencies=["requests", "sqlalchemy"],
    is_pr=True,
    changed_files=["auth.py"],
    has_public_endpoint=True,
)

planner = LLMPlanner(client)
plan = planner.plan(ctx)

print(plan)
