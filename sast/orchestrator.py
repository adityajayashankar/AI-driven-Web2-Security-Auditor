from typing import Dict, Any, List, Optional
import tempfile
import subprocess
import shutil
import os

from agents.contracts import ExecutionPlan, AgentContext
from agents.planner.planner_fallback import FallbackPlanner

from sast.runner import run_semgrep
from sast.normalize import normalize_semgrep

from sast.dast_runner import run_nuclei
from sast.normalize_dast import normalize_nuclei

from sast.sbom_runner import generate_sbom
from sast.sca_runner import run_osv_scan
from sast.normalize_sca import normalize_osv

from sast.config_runner import run_config_checks

from sast.schema import Finding
from sast.scope import (
    ScopePolicy,
    validate_repo_scope,
    validate_target_url,
    ScopeViolation,
)

# ============================================================
# Workspace resolution (TEMP local execution adapter)
# ============================================================
def resolve_repo(repo_input: str) -> tuple[str, bool]:
    """
    TEMP: Local execution adapter.
    In prod, code will already be checked out by CI.
    """
    if repo_input.startswith("http"):
        temp_dir = tempfile.mkdtemp(prefix="deplai-repo-")

        subprocess.run(
            ["git", "clone", "--depth=1", repo_input, temp_dir],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        return temp_dir, True

    return repo_input, False


# ============================================================
# Dependency detection (Python-only for now)
# ============================================================
def has_python_dependencies(repo_path: str) -> bool:
    for f in ("requirements.txt", "pyproject.toml", "poetry.lock"):
        path = os.path.join(repo_path, f)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return True
    return False


# ============================================================
# MAIN ENTRYPOINT — PLAN-DRIVEN EXECUTION
# ============================================================
def run_security_checks(
    input: Dict[str, Any],
    plan: Optional[ExecutionPlan] = None,
    scope: Optional[ScopePolicy] = None,
) -> Dict[str, Any]:

    # --------------------------------------------------------
    # 🛡️ DEFENSIVE ARG NORMALIZATION (BACKWARD COMPAT)
    # --------------------------------------------------------
    if isinstance(plan, ScopePolicy) and scope is None:
        scope = plan
        plan = None

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------
    if "run_id" not in input:
        raise ValueError("run_id is required")

    if "repo_path" not in input and "dast" not in input:
        raise ValueError("Either repo_path or dast.target_url is required")

    run_id: str = input["run_id"]
    repo_input: Optional[str] = input.get("repo_path")
    dast_cfg: Dict[str, Any] = input.get("dast", {})

    # --------------------------------------------------------
    # BACKWARD COMPATIBILITY (legacy / tests)
    # --------------------------------------------------------
    if plan is None:
        ctx = AgentContext(
            repo=repo_input or "",
            languages=input.get("languages", []),
            frameworks=input.get("frameworks", []),
            dependencies=input.get("dependencies", []),
            is_pr=input.get("is_pr", False),
            changed_files=input.get("changed_files", []),
            has_public_endpoint=bool(dast_cfg.get("target_url")),
        )
        plan = FallbackPlanner().plan(ctx)

    # --------------------------------------------------------
    # DEFAULT SCOPE (local / tests)
    # --------------------------------------------------------
    if scope is None:
        scope = ScopePolicy(
            allowed_repo_prefixes=[""],
            allowed_domains=["localhost", "127.0.0.1"],
            safe_mode=True,
        )

    # --------------------------------------------------------
    # SCOPE VALIDATION (REPO)
    # --------------------------------------------------------
    if repo_input:
        try:
            validate_repo_scope(repo_input, scope)
        except ScopeViolation as e:
            return {
                "run_id": run_id,
                "status": "blocked",
                "tools": [],
                "findings": [
                    Finding(
                        category="SYSTEM",
                        tool="scope",
                        rule_id="repo-scope-violation",
                        title="Repository blocked by scope policy",
                        severity="LOW",
                        confidence="HIGH",
                        file="scope",
                        line_start=0,
                        line_end=None,
                        fingerprint=f"scope:repo:{hash(str(e))}",
                        occurrences=1,
                        evidence={"error": str(e)},
                    )
                ],
            }

    # --------------------------------------------------------
    # WORKSPACE RESOLUTION
    # --------------------------------------------------------
    repo_path: Optional[str] = None
    is_temp_clone = False

    if repo_input:
        repo_path, is_temp_clone = resolve_repo(repo_input)

    signals: List[Finding] = []
    tools_run: List[str] = []

    try:
        # ====================================================
        # SAST
        # ====================================================
        if repo_path and plan.run_sast:
            raw = run_semgrep(repo_path)
            signals.extend(normalize_semgrep(raw))
            tools_run.append("semgrep")

        # ====================================================
        # SCA (Python-only for now)
        # ====================================================
        if repo_path and plan.run_sca:
            if not has_python_dependencies(repo_path):
                tools_run.append("sca-skipped")
            else:
                try:
                    sbom_path = generate_sbom(repo_path)
                    osv_raw = run_osv_scan(sbom_path)
                    signals.extend(normalize_osv(osv_raw, run_id))
                    tools_run.append("sca-osv")
                except Exception as e:
                    tools_run.append("sca-error")
                    signals.append(
                        Finding(
                            category="SYSTEM",
                            tool="sca",
                            rule_id="osv-execution-error",
                            title="SCA execution failed",
                            severity="LOW",
                            confidence="HIGH",
                            file="dependency-resolution",
                            line_start=0,
                            line_end=None,
                            fingerprint=f"sca-osv-error:{type(e).__name__}",
                            occurrences=1,
                            evidence={"error": str(e)},
                        )
                    )

        # ====================================================
        # DAST + CONFIG
        # ====================================================
        if plan.run_dast:
            target_url = dast_cfg.get("target_url")
            if not target_url:
                raise ValueError(
                    "Planner enabled DAST but input.dast.target_url is missing"
                )

            try:
                validate_target_url(target_url, scope)
            except ScopeViolation as e:
                return {
                    "run_id": run_id,
                    "status": "blocked",
                    "tools": tools_run,
                    "findings": [
                        Finding(
                            category="SYSTEM",
                            tool="scope",
                            rule_id="dast-scope-violation",
                            title="DAST target blocked by scope policy",
                            severity="LOW",
                            confidence="HIGH",
                            file="scope",
                            line_start=0,
                            line_end=None,
                            fingerprint=f"scope:dast:{hash(str(e))}",
                            occurrences=1,
                            evidence={"error": str(e)},
                        )
                    ],
                }

            raw = run_nuclei(target_url)
            signals.extend(normalize_nuclei(raw))
            tools_run.append("nuclei")

            signals.extend(run_config_checks(target_url))
            tools_run.append("config")

        return {
            "run_id": run_id,
            "status": "completed",
            "tools": tools_run,
            "findings": signals,
        }

    finally:
        if is_temp_clone and repo_path and os.path.exists(repo_path):
            shutil.rmtree(repo_path, ignore_errors=True)
