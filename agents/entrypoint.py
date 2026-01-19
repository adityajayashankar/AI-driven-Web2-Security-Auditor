import os
import logging
from typing import Dict, Any

from agents.contracts import AgentContext
from agents.planner.planner_llm import LLMPlanner
from agents.gatekeeper import enforce_plan
from sast.orchestrator import run_security_checks
from sast.scope import ScopePolicy

# --- AGENTIC MODULES ---
from agents.triage.triage import triage_findings
from agents.remediation.remediator import RemediationAgent
from agents.llm_clients.openrouter_client import OpenRouterClient

logger = logging.getLogger(__name__)

def run_with_planner(
    input: dict,
    planner: LLMPlanner,
    scope: ScopePolicy,
) -> dict:
    """
    Authoritative execution entrypoint.
    1. AI decides WHAT to run (Planning).
    2. Orchestrator runs it (Execution).
    3. AI analyzes results (Triage & Remediation).
    """

    # 1️⃣ Build AgentContext (SAFE METADATA ONLY)
    ctx = AgentContext(
        repo=input.get("repo_path", ""),
        languages=input.get("languages", []),
        frameworks=input.get("frameworks", []),
        dependencies=input.get("dependencies", []),
        is_pr=input.get("is_pr", False),
        changed_files=input.get("changed_files", []),
        has_public_endpoint=bool(input.get("dast", {}).get("target_url")),
    )

    # 2️⃣ AI Planning
    print("🤖 AI Planner: Analyzing context...")
    plan = planner.plan(ctx)

    # 3️⃣ Hard Policy Enforcement
    final_plan = enforce_plan(plan, scope)
    print(f"📋 Execution Plan: {final_plan}")

    # 4️⃣ Execution (The "Hands")
    result = run_security_checks(
        input=input,
        plan=final_plan,
        scope=scope,
    )

    if result.get("status") == "failed":
        return result

    findings = result.get("findings", [])
    
    # 5️⃣ Agentic Triage (The "Eyes")
    if findings:
        print("🕵️ AI Triage: Analyzing findings...")
        findings = triage_findings(findings, ctx)

    # 6️⃣ Agentic Remediation (The "Hands" - Fixer)
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if api_key and findings:
        print("🔧 AI Remediation: Generating fixes for critical issues...")
        try:
            client = OpenRouterClient(api_key=api_key)
            remediator = RemediationAgent(client)

            for f in findings:
                # Cost saving: Only fix HIGH or CRITICAL issues
                if f.severity in ["HIGH", "CRITICAL"]:
                    print(f"   -> Fixing: {f.title}")
                    fix = remediator.generate_fix(f, ctx)
                    
                    if f.evidence is None: 
                        f.evidence = {}
                    f.evidence["ai_remediation"] = fix
                    
        except Exception as e:
            logger.error(f"Remediation failed: {e}")

    result["findings"] = findings
    return result