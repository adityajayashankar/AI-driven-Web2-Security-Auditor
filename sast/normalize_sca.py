from typing import List, Dict, Any
import hashlib
from sast.schema import Finding

def sca_fingerprint(package: str, version: str, vuln_id: str) -> str:
    """
    Unique identity for a vulnerability instance.
    """
    raw = f"grype|{package}|{version}|{vuln_id}"
    return hashlib.sha256(raw.encode()).hexdigest()

def normalize_osv(grype_json: Dict[str, Any], run_id: str) -> List[Finding]:
    """
    Normalize Grype output into canonical Findings.
    (Function name kept as 'normalize_osv' to maintain compatibility with Orchestrator)
    """
    findings: List[Finding] = []
    
    # Grype stores matches in "matches" list
    matches = grype_json.get("matches", [])

    for match in matches:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vuln_id = vuln.get("id", "UNKNOWN")
        severity = vuln.get("severity", "MEDIUM").upper()
        
        pkg_name = artifact.get("name", "unknown")
        pkg_version = artifact.get("version", "unknown")
        pkg_type = artifact.get("type", "unknown")
        
        # Grype often returns specific file locations
        locations = artifact.get("locations", [])
        file_path = locations[0].get("path") if locations else "unknown"

        findings.append(
            Finding(
                category="SCA",
                tool="grype",
                rule_id=vuln_id,
                title=f"{pkg_name} ({pkg_version}) has {vuln_id}",
                severity=severity,
                confidence="HIGH",
                file=file_path,
                line_start=0,
                line_end=0,
                fingerprint=sca_fingerprint(pkg_name, pkg_version, vuln_id),
                occurrences=1,
                evidence={
                    "package": pkg_name,
                    "version": pkg_version,
                    "type": pkg_type,
                    "fix_versions": vuln.get("fix", {}).get("versions", []),
                    "links": vuln.get("dataSource", "")
                },
            )
        )

    return findings