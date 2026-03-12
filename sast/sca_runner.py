from pathlib import Path
import subprocess
import json
import shlex

class SCARunnerError(RuntimeError):
    pass


def run_osv_scan(sbom_path: Path) -> dict:
    """
    Execute Grype against a CycloneDX SBOM.
    (Function name kept as 'run_osv_scan' to maintain compatibility with Orchestrator)
    """
    if not sbom_path.exists():
        raise SCARunnerError(f"SBOM not found at {sbom_path}")

    # Grype command: Scan the SBOM file and output JSON
    cmd = [
        "grype",
        f"sbom:{shlex.quote(str(sbom_path))}",
        "-o", "json"
    ]

    try:
        print(f"\u1f50d Scanning SBOM with Grype: {sbom_path}")
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
