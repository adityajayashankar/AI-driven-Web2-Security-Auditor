from typing import Dict, Any, List
import tempfile
import subprocess
import shutil
import os

from sast.runner import run_semgrep
from sast.normalize import normalize_semgrep

from sast.dast_runner import run_nuclei
from sast.normalize_dast import normalize_nuclei

from sast.sca_runner import run_pip_audit              # fallback
from sast.sbom_runner import generate_sbom
from sast.sca_sbom_matcher import match_vulns_from_sbom
from sast.normalize_sca import normalize_pip_audit

from sast.schema import Finding


# -------------------------
# Repo resolution
# -------------------------
def resolve_repo(repo_input: str) -> tuple[str, bool]:
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


# -------------------------
# Dependency detection
# -------------------------
def has_python_dependencies(repo_path: str) -> bool:
    for f in ("requirements.txt", "pyproject.toml", "poetry.lock"):
        path = os.path.join(repo_path, f)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return True
    return False


# -------------------------
# Main entry point
# -------------------------
def run_security_checks(input: Dict[str, Any]) -> Dict[str, Any]:
    """
    EXECUTION PLANE ONLY.
    Returns raw Finding signals.
    """

    # ---- REQUIRED INPUTS ----
    if "run_id" not in input:
        raise ValueError("run_id is required")
    if "repo_path" not in input:
        raise ValueError("repo_path is required")

    run_id: str = input["run_id"]
    repo_input: str = input["repo_path"]
    languages: List[str] = input.get("languages", [])
    dast_cfg: Dict[str, Any] = input.get("dast", {})

    enable_sca: bool = input.get("enable_sca", False)

    repo_path, is_temp_clone = resolve_repo(repo_input)
    signals: List[Finding] = []
    tools_run: List[str] = []

    try:
        # ---- SAST ----
        if "python" in languages:
            raw = run_semgrep(repo_path)
            signals.extend(normalize_semgrep(raw))
            tools_run.append("semgrep")

        # ---- SCA ----
        if enable_sca and "python" in languages and has_python_dependencies(repo_path):
            try:
                sbom = generate_sbom(repo_path)
                raw = match_vulns_from_sbom(sbom, timeout=60)
                signals.extend(normalize_pip_audit(raw))
                tools_run.append("sca")

            except Exception:
                try:
                    raw = run_pip_audit(repo_path, timeout=60)
                    signals.extend(normalize_pip_audit(raw))
                    tools_run.append("sca-fallback")

                except Exception as e:
                    tools_run.append("sca-error")
                    signals.append(
                        Finding(
                            category="SYSTEM",
                            tool="sca",
                            rule_id="execution-error",
                            title="SCA execution failed",
                            severity="LOW",
                            confidence="HIGH",
                            file="requirements.txt",
                            line_start=0,
                            line_end=0,
                            fingerprint=f"sca-error:{type(e).__name__}",
                            occurrences=1,
                            evidence={"error": str(e)},
                        )
                    )

        # ---- DAST ----
        if dast_cfg.get("target_url"):
            raw = run_nuclei(dast_cfg["target_url"])
            signals.extend(normalize_nuclei(raw))
            tools_run.append("nuclei")

        return {
            "run_id": run_id,
            "status": "completed",
            "tools": tools_run,
            "findings": signals,   # ✅ List[Finding]
        }

    finally:
        if is_temp_clone and os.path.exists(repo_path):
            shutil.rmtree(repo_path, ignore_errors=True)


