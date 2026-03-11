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
# Imports kept as 'osv' for compatibility, but they now point to Grype logic
from sast.sca_runner import run_osv_scan
from sast.normalize_sca import normalize_osv

from sast.config_runner import run_config_checks
from sast.dedup import dedup_findings 

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
        try:
            # [FIX] Removed DEVNULL, added capture_output=True to see errors
            subprocess.run(
                ["git", "clone", "--depth=1", repo_input, temp_dir],
                check=True,
                capture_output=True, # Captures stdout/stderr
                text=True            # Decodes to string
            )
        except subprocess.CalledProcessError as e:
            # Clean up if clone fails
            shutil.rmtree(temp_dir, ignore_errors=True)
            # [FIX] Return the actual error message from Git
            raise RuntimeError(f"Failed to clone repository: {repo_input}\nGit Error: {e.stderr}")

        return temp_dir, True

    return repo_input, False
