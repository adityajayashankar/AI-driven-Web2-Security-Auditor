import os
from dotenv import load_dotenv

from agents.llm_clients.openrouter_client import OpenRouterClient
from agents.planner.planner_llm import LLMPlanner
from agents.entrypoint import run_with_planner
from sast.scope import ScopePolicy

load_dotenv()

planner = LLMPlanner(
    OpenRouterClient(
        api_key=os.environ["OPENROUTER_API_KEY"],
        model="google/gemma-3n-e2b-it:free",
    )
)

scope = ScopePolicy(
    allowed_repo_prefixes=["https://github.com/"],
    allowed_domains=["localhost"],
    safe_mode=True,
    max_requests=1000,
)

result = run_with_planner(
    input={
        "run_id": "full-test-1",
        "repo_path": "https://github.com/pallets/flask",
        "languages": ["python"],
        "frameworks": ["flask"],
        "dependencies": ["flask"],
        "dast": {},  # no target_url → DAST disabled by planner
    },
    planner=planner,
    scope=scope,
)

print("TOOLS RUN:", result["tools"])
print("FINDINGS:", len(result["findings"]))
