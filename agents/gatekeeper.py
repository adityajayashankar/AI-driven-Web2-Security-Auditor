# agents/gatekeeper.py
from agents.contracts import ExecutionPlan
from sast.scope import ScopePolicy


class PlanRejected(Exception):
    pass


def enforce_plan(plan: ExecutionPlan, scope: ScopePolicy) -> ExecutionPlan:
    if plan.run_dast and not scope.allowed_domains:
        raise PlanRejected("DAST requested but no domains allowed")

    limits = plan.limits
    if limits.max_requests > scope.max_requests:
        limits = limits.__class__(
            max_runtime_seconds=limits.max_runtime_seconds,
            max_requests=scope.max_requests,
        )

    return ExecutionPlan(
        run_sast=plan.run_sast,
        run_sca=plan.run_sca,
        run_dast=plan.run_dast,
        reason=plan.reason,
        limits=limits,
    )

