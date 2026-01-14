import subprocess
import tempfile
import json
import os
from typing import Dict, Any


def match_vulns_from_sbom(sbom: Dict[str, Any], timeout: int = 60) -> Dict[str, Any]:
    """
    Match vulnerabilities using an SBOM as input.

    Uses pip-audit in SBOM mode.
    """

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        sbom_path = tmp.name

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        output_path = tmp.name

    try:
        with open(sbom_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f)

        cmd = [
            "pip-audit",
            "--sbom", sbom_path,
            "--format", "json",
            "--output", output_path,
        ]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

        if proc.returncode >= 2:
            raise RuntimeError(proc.stderr.strip())

        if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            return {"dependencies": []}

        with open(output_path, "r", encoding="utf-8") as f:
            return json.load(f)

    finally:
        for p in (sbom_path, output_path):
            try:
                os.remove(p)
            except OSError:
                pass
