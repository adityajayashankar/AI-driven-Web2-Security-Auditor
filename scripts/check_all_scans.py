import os
import json
import dataclasses
import requests
from collections import Counter
from dotenv import load_dotenv

from agents.llm_clients.openrouter_client import OpenRouterClient
from agents.planner.planner_llm import LLMPlanner
from agents.entrypoint import run_with_planner
from sast.scope import ScopePolicy

load_dotenv()

# ---------------------------------------------------------
# Helper: JSON Encoder
# ---------------------------------------------------------
class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)

# -------------------------
# 1. Initialize AI Planner
# -------------------------
client = OpenRouterClient(
    api_key=os.environ.get("OPENROUTER_API_KEY", "invalid-key-placeholder"),
    model="google/gemma-3n-e2b-it:free",
)
planner = LLMPlanner(client)

# -------------------------
# 2. Define Scope Policy
# -------------------------
scope = ScopePolicy(
    allowed_repo_prefixes=["https://github.com/", "http"],
    allowed_domains=["localhost", "127.0.0.1", "example.com", "notion.site", "host.docker.internal"],
    safe_mode=False, 
    max_requests=1000,
)

# -------------------------
# 3. Load Configuration
# -------------------------
input_env = os.environ.get("SCAN_INPUT_JSON")

if input_env:
    print("📥 Loading configuration from API...")
    try:
        scan_input = json.loads(input_env)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse SCAN_INPUT_JSON: {e}")
        exit(1)
else:
    print("⚠️ No API input found. Using default test targets (Manual Run).")
    scan_input = {
        "run_id": "manual-test",
        "repo_path": "https://github.com/pallets/flask",
        "languages": ["python"],
        "dast": {"target_url": "http://example.com"},
    }

# Identify the target for logging
target = scan_input.get('repo_path') or scan_input.get('dast', {}).get('target_url') or "unknown-target"
print(f"🚀 Starting Security Scan for: {target}")

# -------------------------
# 4. Run the Security Pipeline
# -------------------------
try:
    result = run_with_planner(
        input=scan_input,
        planner=planner,
        scope=scope,
    )
except Exception as e:
    print(f"❌ Critical Pipeline Error: {e}")
    result = {
        "run_id": scan_input.get("run_id"),
        "status": "failed",
        "error": str(e),
        "tools": [],
        "findings": []
    }

# -------------------------
# 5. Post-Processing (Enrichment)
# -------------------------
# Ensure every finding has the 'repo' field filled and matches your strict schema
clean_findings = []

if "findings" in result:
    for f in result["findings"]:
        # If it's already a dict (rare edge case), just update it
        if isinstance(f, dict):
             f["repo"] = target
             clean_findings.append(f)
        # If it's a Finding object (Standard), convert using your schema method
        elif hasattr(f, "to_dict"):
             f.repo = target
             clean_findings.append(f.to_dict())
        # Fallback for standard dataclasses without to_dict
        else:
            as_dict = dataclasses.asdict(f)
            as_dict["repo"] = target
            clean_findings.append(as_dict)

# Update the result object with the clean, schema-compliant list
result["findings"] = clean_findings

# -------------------------
# 6. Output Summary (Console)
# -------------------------
print("\n=== FINAL RESULT ===")
print("TOOLS RUN:", result.get("tools", []))
print("TOTAL FINDINGS:", len(clean_findings))

if clean_findings:
    # Safely count categories from dicts
    categories = Counter(f.get("category", "UNKNOWN") for f in clean_findings)
    print("FINDINGS BY CATEGORY:", dict(categories))

# -------------------------
# 7. Persistence: Save to File
# -------------------------
output_path = "scan_results.json"
try:
    with open(output_path, "w", encoding="utf-8") as f:
        # We use standard json.dump because clean_findings are now pure dicts
        json.dump(result, f, indent=2) 
    print(f"\n✅ Scan artifacts saved to: {output_path}")
except Exception as e:
    print(f"\n❌ Failed to save artifacts locally: {e}")

# -------------------------
# 8. Persistence: Callback to API
# -------------------------
callback_url = scan_input.get("callback_url")

if callback_url:
    print(f"\n📡 Sending results to Control Plane: {callback_url}")
    try:
        response = requests.post(callback_url, json=result, timeout=10)
        response.raise_for_status()
        print("✅ Results successfully stored in Database!")
    except Exception as e:
        print(f"❌ Failed to send results to API: {e}")
else:
    print("ℹ️ No callback_url provided. Skipping DB upload.")