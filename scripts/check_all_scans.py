import os
from dotenv import load_dotenv

from agents.llm_clients.openrouter_client import OpenRouterClient
from agents.planner.planner_llm import LLMPlanner
from agents.entrypoint import run_with_planner
from sast.scope import ScopePolicy

load_dotenv()

# -------------------------
# Planner (LLM)
# -------------------------
planner = LLMPlanner(
    OpenRouterClient(
        api_key=os.environ["OPENROUTER_API_KEY"],
        model="google/gemma-3n-e2b-it:free",
    )
)

# -------------------------
# Scope (ALLOW EVERYTHING FOR TEST)
# -------------------------
scope = ScopePolicy(
    allowed_repo_prefixes=["https://github.com/"],
    allowed_domains=["localhost", "127.0.0.1"],
    safe_mode=False,          # IMPORTANT for DAST testing
    max_requests=1000,
)

# -------------------------
# Full input (SAST + SCA + DAST)
# -------------------------
result = run_with_planner(
    input={
        "run_id": "all-scans-test",
        "repo_path": "C:\\Academic\\MED_CHATBOT",
        "languages": ["python"],
        "frameworks": ["flask"],
        "dependencies": ["flask"],
        "is_pr": False,
        "changed_files": [],
        "dast": {
            "target_url": "http://localhost:5000"
        },
    },
    planner=planner,
    scope=scope,
)

print("\n=== FINAL RESULT ===")
print("TOOLS RUN:", result["tools"])
print("TOTAL FINDINGS:", len(result["findings"]))
