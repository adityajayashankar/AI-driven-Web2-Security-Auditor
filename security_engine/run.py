from typing import Dict, Any, List

from sast.runner import run_semgrep
from sast.normalize import normalize_semgrep
from sast.dedup import dedup_findings
from sast.schema import Finding


def run_security_checks(input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pure execution-plane function (Semgrep-only).

    Guarantees:
    - deterministic output
    - canonical Finding schema
    - deduplicated issues
    - no side effects
    """

    # ---- Required inputs ----
    repo_path = input["repo_path"]
    languages: List[str] = input.get("languages", [])
    run_id = input["run_id"]

    findings: List[Finding] = []
    tools_run: List[str] = []

    # ---- SAST only ----
    if "python" in languages:
        raw = run_semgrep(repo_path)
        findings.extend(normalize_semgrep(raw))
        tools_run.append("semgrep")

    # ---- Dedup (even for single tool) ----
    findings = dedup_findings(findings)

    return {
        "run_id": run_id,
        "status": "completed",
        "tools": tools_run,
        "findings": findings,
    }
