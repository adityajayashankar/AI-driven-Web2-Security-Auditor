from pathlib import Path
import subprocess
import json


class SCARunnerError(RuntimeError):
    pass


def run_osv_scan(sbom_path: Path) -> dict:
    """
    Execute osv-scanner against a CycloneDX SBOM.

    Args:
        sbom_path: Path to sbom.json

    Returns:
        Parsed JSON output from osv-scanner

    Raises:
        SCARunnerError on execution or parsing failure
    """
    if not sbom_path.exists():
        raise SCARunnerError(f"SBOM not found at {sbom_path}")

    cmd = [
        "osv-scanner",
        "--sbom", str(sbom_path),
        "--format", "json",
    ]

    try:
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise SCARunnerError(
            "osv-scanner binary not found in PATH"
        )
    except subprocess.CalledProcessError as e:
        raise SCARunnerError(
            f"osv-scanner failed: {e.stderr.strip()}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise SCARunnerError(
            f"Invalid JSON returned by osv-scanner: {str(e)}"
        )





