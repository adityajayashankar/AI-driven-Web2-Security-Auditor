from pathlib import Path
import subprocess
import os

class SBOMGenerationError(RuntimeError):
    pass

def generate_sbom(project_root: str) -> Path:
    """
    Generate a CycloneDX SBOM using cdxgen (Universal Support).
    """
    sbom_path = Path(project_root) / "sbom.json"
    
    cmd = [
        "cdxgen",
        "-o", str(sbom_path),
        "--format", "json",
        ".",
    ]

    try:
        subprocess.run(
            cmd,
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=300 # [FIX] Increased timeout to 5 mins for large repos
        )
    except FileNotFoundError:
        raise SBOMGenerationError("cdxgen not found. Check Dockerfile.")
    except subprocess.TimeoutExpired:
        raise SBOMGenerationError("SBOM generation timed out (limit: 300s).")
    except subprocess.CalledProcessError as e:
        if not sbom_path.exists():
             raise SBOMGenerationError(f"cdxgen failed: {e.stderr.strip()}")

    if not sbom_path.exists() or sbom_path.stat().st_size == 0:
        raise SBOMGenerationError("SBOM file is empty or not created.")

    return sbom_path