from pathlib import Path
import subprocess


class SBOMGenerationError(RuntimeError):
    pass


def generate_sbom(project_root: str) -> Path:
    """
    Generate a CycloneDX SBOM for the Python project.
    """
    sbom_path = Path(project_root) / "sbom.json"

    cmd = [
        "cyclonedx-py",
        "--format", "json",
        "--schema-version", "1.5",
        "--outfile", str(sbom_path),
    ]

    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        raise SBOMGenerationError(
            "cyclonedx-py not found. Install with: pip install cyclonedx-bom"
        )
    except subprocess.CalledProcessError as e:
        raise SBOMGenerationError(
            f"SBOM generation failed: {e.stderr.strip()}"
        )

    if not sbom_path.exists():
        raise SBOMGenerationError("SBOM file was not created")

    return sbom_path
