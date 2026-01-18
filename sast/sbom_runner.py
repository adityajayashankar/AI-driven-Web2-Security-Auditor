from pathlib import Path
import subprocess
import os

class SBOMGenerationError(RuntimeError):
    pass

def generate_sbom(project_root: str) -> Path:
    """
    Generate a CycloneDX SBOM using cdxgen (Universal Support).
    Optimized for speed.
    """
    sbom_path = Path(project_root) / "sbom.json"
    
    # Optimization Flags to prevent timeouts
    cmd = [
        "cdxgen",
        "-o", str(sbom_path),
        "--format", "json",
        "--no-recurse",       # Don't walk deep directory trees
        "--babel", "false",   # Disable babel parsing (slow)
        ".",
    ]

    # Special handling: If Node.js, try to use lockfile only for speed
    if (Path(project_root) / "package-lock.json").exists():
        env = os.environ.copy()
        env["FETCH_LICENSE"] = "false"
        env["CDXGEN_DEBUG_MODE"] = "false"
    else:
        env = os.environ.copy()

    try:
        subprocess.run(
            cmd,
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
            env=env,
            timeout=120 # [FIX] Reduced to 2 minutes (120s)
        )
    except FileNotFoundError:
        raise SBOMGenerationError("cdxgen not found. Check Dockerfile.")
    except subprocess.TimeoutExpired:
        raise SBOMGenerationError("SBOM generation timed out (limit: 120s).")
    except subprocess.CalledProcessError as e:
        if not sbom_path.exists():
             raise SBOMGenerationError(f"cdxgen failed: {e.stderr.strip()}")

    if not sbom_path.exists() or sbom_path.stat().st_size == 0:
        raise SBOMGenerationError("SBOM file is empty or not created.")

    return sbom_path