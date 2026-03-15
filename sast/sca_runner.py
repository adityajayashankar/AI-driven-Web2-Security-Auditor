from pathlib import Path
import subprocess
import json
import os

class SCARunnerError(RuntimeError):
    pass


def _validate_sbom(sbom_path: Path) -> Path:
    path = sbom_path.resolve()
    # Ensure path is within allowed base directories and has correct extension
    if not str(path).startswith(('/tmp', '/workspace')) or not path.suffix == '.json':
        raise ValueError("Invalid SBOM path")
    return path


def run_osv_scan(sbom_path: Path) -> dict:
    """
    Execute Grype against a CycloneDX SBOM.
    (Function name kept as 'run_osv_scan' to maintain compatibility with Orchestrator)
    """
    sbom_path = _validate_sbom(sbom_path)
    if not sbom_path.exists():
        raise SCARunnerError(f"SBOM not found at {sbom_path}")

    # Grype command: Scan the SBOM file and output JSON
    cmd = [
        "grype",
        f"sbom:{sbom_path}",
        "-o", "json"
    ]

    try:
        print(f"🔍 Scanning SBOM with Grype: {sbom_path}")
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    except subprocess.CalledProcessError as e:
        raise SCARunnerError(f"Grype failed: {e.stderr.strip()}")
    except json.JSONDecodeError as e:
        raise SCARunnerError(f"Invalid JSON returned by Grype: {str(e)}")
