import pytest

from agents.contracts import AgentContext
from agents.planner.planner_fallback import FallbackPlanner
from agents.planner.planner_llm import LLMPlanner
from agents.gatekeeper import enforce_plan
from sast.scope import ScopePolicy


# -----------------------------
# Fake LLM for testing
# -----------------------------
class FakeLLM:
    def chat_completions(self):
        return self

    def create(self, **kwargs):
        class Resp:
            choices = [
                type(
                    "Choice",
                    (),
                    {
                        "message": type(
                            "Msg",
                            (),
                            {
                                "content": """{
                                  "run_sast": true,
                                  "run_sca": false,
                                  "run_dast": true,
                                  "reason": "Test LLM output",
                                  "limits": {
                                    "max_runtime_seconds": 1000,
                                    "max_requests": 5000
                                  }
                                }"""
                            },
                        )
                    },
                )
            ]

        return Resp()


# -----------------------------
# Fixtures
# -----------------------------
@pytest.fixture
def ctx_pr():
    return AgentContext(
        repo="repo",
        languages=["python"],
        frameworks=["fastapi"],
        dependencies=["fastapi"],
        is_pr=True,
        changed_files=["app/main.py"],
        has_public_endpoint=True,
    )


@pytest.fixture
def scope():
    return ScopePolicy(
        allowed_repo_prefixes=[""],
        allowed_domains=["example.com"],
        safe_mode=True,
        max_requests=1000,
    )


# -----------------------------
# Tests
# -----------------------------
def test_fallback_planner_pr_disables_dast(ctx_pr):
    plan = FallbackPlanner().plan(ctx_pr)
    assert plan.run_dast is False


def test_llm_cannot_enable_dast_on_pr(ctx_pr, scope):
    planner = LLMPlanner(FakeLLM())
    plan = planner.plan(ctx_pr)

    # LLM tries to enable DAST
    assert plan.run_dast is False

    # Gatekeeper still enforces limits
    final_plan = enforce_plan(plan, scope)
    assert final_plan.limits.max_requests <= scope.max_requests


def test_llm_failure_falls_back(ctx_pr, scope):
    class BrokenLLM:
        def chat_completions(self):
            return self

        def create(self, **kwargs):
            raise RuntimeError("boom")

    planner = LLMPlanner(BrokenLLM())
    plan = planner.plan(ctx_pr)

    assert plan.reason == "fallback_planner_baseline"
