import subprocess
import json
import tempfile
import os
from typing import Dict, Any, List

def run_semgrep(repo_path: str, languages: List[str] = None) -> Dict[str, Any]:
    """
    Run Semgrep in JSON mode with dynamic language support.
    """
    # [FIX] Handle dynamic languages
    if not languages:
        languages = ["python"] # Default fallback

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = tmp.name

    # [FIX] Build dynamic config flags
    config_flags = []
    for lang in languages:
        # Map common names to semgrep rulesets if needed, or use direct naming
        config_flags.append(f"--config=p/{lang}")

    cmd = [
        "semgrep",
        "scan",
    ] + config_flags + [
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
        return {"results": []}

    finally:
        try:
            os.remove(output_path)
        except OSError:
            pass





