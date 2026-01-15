# agents/planner/planner_fallback.py

from agents.contracts import ExecutionPlan, ScanLimits, AgentContext


class FallbackPlanner:
    """
    Deterministic, policy-safe baseline planner.

    Guarantees:
    - Never enables scans without hard signals
    - Never violates invariants (PRs, exposure)
    - Provides upper-bound permissions for LLM (LLM can only reduce)
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
        if ctx.dependencies:
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
