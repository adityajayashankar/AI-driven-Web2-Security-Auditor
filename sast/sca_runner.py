import subprocess
import json
import tempfile
import os
import sys
from typing import Dict, Any


def run_pip_audit(repo_path: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Run pip-audit in a production-safe, time-bounded way.
    """

    req_path = os.path.join(repo_path, "requirements.txt")
    if not os.path.exists(req_path):
        return {"dependencies": []}

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = tmp.name

    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        "requirements.txt",
        "--format",
        "json",
        "--output",
        output_path,
    ]

    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

        # exit code 0 = no vulns
        # exit code 1 = vulns found
        # >=2 = execution error
        if proc.returncode >= 2:
            raise RuntimeError(proc.stderr.strip())

        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            return {"dependencies": []}

        with open(output_path, "r", encoding="utf-8") as f:
            return json.load(f)

    finally:
        try:
            os.remove(output_path)
        except OSError:
            pass





