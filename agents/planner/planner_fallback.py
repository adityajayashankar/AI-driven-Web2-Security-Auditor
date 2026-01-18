# agents/planner/planner_fallback.py

from agents.contracts import ExecutionPlan, ScanLimits, AgentContext

class FallbackPlanner:
    """
    Deterministic, policy-safe baseline planner.
    """

    def plan(self, ctx: AgentContext) -> ExecutionPlan:
        run_sast = False
        run_sca = False
        run_dast = False

        # -------------------------
        # Static analysis (SAST)
        # -------------------------
        if ctx.languages:
            run_sast = True

        # -------------------------
        # Dependency analysis (SCA)
        # -------------------------
        # [FIX] Trigger SCA if dependencies exist OR if languages imply them
        if ctx.dependencies or (ctx.languages and "python" in ctx.languages):
            run_sca = True

        # -------------------------
        # Dynamic analysis (DAST)
        # -------------------------
        if ctx.has_public_endpoint and not ctx.is_pr:
            run_dast = True

        # -------------------------
        # Conservative baseline limits
        # -------------------------
        if ctx.is_pr:
            limits = ScanLimits(
                max_runtime_seconds=300,
                max_requests=200,
            )
        else:
            limits = ScanLimits(
                max_runtime_seconds=900,
                max_requests=1_000,
            )

        return ExecutionPlan(
            run_sast=run_sast,
            run_sca=run_sca,
            run_dast=run_dast,
            reason="fallback_planner_baseline",
            limits=limits,
        )
