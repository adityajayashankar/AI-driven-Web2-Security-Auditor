import subprocess
import json
import tempfile
import os
from typing import Dict, Any


def run_semgrep(repo_path: str) -> Dict[str, Any]:
    """
    Run Semgrep in JSON mode.

    Production semantics:
    - exit code 0 → no findings
    - exit code 1 → findings exist (NOT an error)
    - exit code >=2 → execution / config error
    - empty / invalid JSON → treat as no findings
    """

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = tmp.name

    cmd = [
        "semgrep",
        "scan",
        "--config=p/python",
        "--json",
        "--output",
        output_path,
    ]

    proc = subprocess.run(
        cmd,
        cwd=repo_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
    )

    # Real Semgrep failure
    if proc.returncode >= 2:
        raise RuntimeError(
            f"Semgrep failed with exit code {proc.returncode}\n"
            f"STDERR:\n{proc.stderr}"
        )

    # Defensive JSON handling
    try:
        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            return {"results": []}

        with open(output_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {"results": []}
            return json.loads(content)

    except json.JSONDecodeError:
        # Treat malformed output as no findings (safe default)
        return {"results": []}

    finally:
        try:
            os.remove(output_path)
        except OSError:
            pass






