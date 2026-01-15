# agents/planner/planner_llm.py

import json
import logging
import re

from agents.contracts import ExecutionPlan, ScanLimits, AgentContext
from agents.planner.planner_fallback import FallbackPlanner

logger = logging.getLogger(__name__)


class PlannerError(Exception):
    pass


class LLMPlanner:
    """
    Production LLM-backed scan planner.

    Hard guarantees:
    - Always returns a valid ExecutionPlan
    - Never raises LLM errors upstream
    - Never expands privileges beyond fallback
    - Never violates platform invariants
    """

    def __init__(
        self,
        llm_client,
        timeout_seconds: int = 20,
        max_retries: int = 1,
    ):
        self.llm = llm_client
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.fallback = FallbackPlanner()

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------
    def plan(self, ctx: AgentContext) -> ExecutionPlan:
        base_plan = self.fallback.plan(ctx)

        for _ in range(self.max_retries + 1):
            try:
                raw = self._invoke_llm(ctx)
                llm_plan = self._parse_and_validate(raw)
                return self._merge_with_fallback(base_plan, llm_plan, ctx)
            except Exception:
                logger.exception("LLM planner attempt failed")

        return base_plan

    # ------------------------------------------------------------------
    # LLM interaction (provider-agnostic)
    # ------------------------------------------------------------------
    def _invoke_llm(self, ctx: AgentContext) -> str:
        prompt = self._build_prompt(ctx)
        return self.llm.complete(prompt)

    # ------------------------------------------------------------------
    # Parsing + validation (STRICT, DeepSeek-safe)
    # ------------------------------------------------------------------
    def _parse_and_validate(self, raw: str) -> ExecutionPlan:
        """
        Extract JSON from:
        - ```json fenced blocks
        - or first {...} object

        Required for DeepSeek / reasoning models.
        """

        # 1️⃣ Prefer fenced JSON blocks
        fenced = re.search(r"```json\s*([\s\S]*?)```", raw)
        if fenced:
            json_text = fenced.group(1).strip()
        else:
            # 2️⃣ Fallback to first JSON object
            match = re.search(r"\{[\s\S]*\}", raw)
            if not match:
                raise PlannerError("LLM did not return JSON")
            json_text = match.group(0)

        try:
            data = json.loads(json_text)
        except json.JSONDecodeError:
            raise PlannerError("Invalid JSON from LLM")

        required = {"run_sast", "run_sca", "run_dast", "reason", "limits"}
        if not required.issubset(data):
            raise PlannerError("Missing required fields")

        limits = data.get("limits")
        if not isinstance(limits, dict):
            raise PlannerError("Invalid limits object")

        if "max_runtime_seconds" not in limits or "max_requests" not in limits:
            raise PlannerError("Incomplete limits")

        return ExecutionPlan(
            run_sast=bool(data["run_sast"]),
            run_sca=bool(data["run_sca"]),
            run_dast=bool(data["run_dast"]),
            reason=str(data["reason"]),
            limits=ScanLimits(
                max_runtime_seconds=int(limits["max_runtime_seconds"]),
                max_requests=int(limits["max_requests"]),
            ),
        )

    # ------------------------------------------------------------------
    # Merge + clamp logic (authoritative)
    # ------------------------------------------------------------------
    def _merge_with_fallback(
        self,
        base: ExecutionPlan,
        llm: ExecutionPlan,
        ctx: AgentContext,
    ) -> ExecutionPlan:

        run_sast = base.run_sast and llm.run_sast
        run_sca = base.run_sca and llm.run_sca
        run_dast = base.run_dast and llm.run_dast

        if ctx.is_pr or not ctx.has_public_endpoint:
            run_dast = False

        limits = ScanLimits(
            max_runtime_seconds=min(
                base.limits.max_runtime_seconds,
                llm.limits.max_runtime_seconds,
            ),
            max_requests=min(
                base.limits.max_requests,
                llm.limits.max_requests,
            ),
        )

        return ExecutionPlan(
            run_sast=run_sast,
            run_sca=run_sca,
            run_dast=run_dast,
            reason=llm.reason or base.reason,
            limits=limits,
        )

    # ------------------------------------------------------------------
    # Prompt (DeepSeek-compatible)
    # ------------------------------------------------------------------
    def _build_prompt(self, ctx: AgentContext) -> str:
        return f"""
IMPORTANT:
- Output ONLY JSON
- NO explanations
- NO markdown
- NO text before or after JSON
- If unsure, return conservative JSON

Context:
{ctx}

Rules:
- If is_pr = true → run_dast MUST be false
- If has_public_endpoint = false → run_dast MUST be false
- If no dependencies → run_sca SHOULD be false
- Prefer fewer scans unless risk is clear

Return EXACTLY this JSON shape:

{{
  "run_sast": true,
  "run_sca": false,
  "run_dast": false,
  "reason": "short explanation",
  "limits": {{
    "max_runtime_seconds": 300,
    "max_requests": 200
  }}
}}
""".strip()



