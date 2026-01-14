import subprocess
import tempfile
import os
import json
from typing import Dict, Any


def generate_sbom(repo_path: str) -> Dict[str, Any]:
    """
    Generate a CycloneDX SBOM for a Python project.

    Returns parsed SBOM JSON.
    """

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        sbom_path = tmp.name

    cmd = [
        "cyclonedx-py",
        "--format", "json",
        "--output", sbom_path,
    ]

    try:
        subprocess.run(
            cmd,
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        with open(sbom_path, "r", encoding="utf-8") as f:
            return json.load(f)

    finally:
        try:
            os.remove(sbom_path)
        except OSError:
            pass