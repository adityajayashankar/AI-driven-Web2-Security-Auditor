from pathlib import Path
import subprocess
import os

class SBOMGenerationError(RuntimeError):
    pass


def _validate_path(project_root: str) -> Path:
    path = Path(project_root).resolve()
    # Ensure path is within allowed base directories (e.g., /tmp or /workspace)
    if not str(path).startswith(('/tmp', '/workspace')):
        raise ValueError("Invalid project root path")
    return path


def generate_sbom(project_root: str) -> Path:
    """
    Generate a CycloneDX SBOM using Syft.
    Syft is universal (Python, JS, Go, Rust, Java, etc.).
    """
    project_path = _validate_path(project_root)
    sbom_path = project_path / "sbom.json"
    
    # Syft command: Scan directory (.) and output CycloneDX JSON
    cmd = [
        "syft",
        f"dir:{project_path}",
        "-o", f"cyclonedx-json={sbom_path}"
    ]

    try:
        print(f"📦 Generating SBOM with Syft for: {project_path}")
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if sbom_path.exists() and sbom_path.stat().st_size > 0:
            return sbom_path
            
    except subprocess.CalledProcessError as e:
        raise SBOMGenerationError(f"Syft failed: {e.stderr}")
    except subprocess.TimeoutExpired:
        raise SBOMGenerationError("Syft timed out (limit: 120s)")
    except Exception as e:
        raise SBOMGenerationError(f"SBOM generation failed: {str(e)}")

    raise SBOMGenerationError("Syft produced an empty SBOM.")
