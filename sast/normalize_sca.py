from typing import List, Dict, Any
import hashlib

from sast.schema import Finding


# -------------------------
# Severity derivation
# -------------------------
def derive_osv_severity(vuln: Dict[str, Any]) -> str:
    """
    Conservative, deterministic base severity for OSV findings.
    """
    summary = (vuln.get("summary") or "").lower()

    if any(term in summary for term in (
        "remote code execution",
        "rce",
        "authentication bypass",
        "privilege escalation",
    )):
        return "CRITICAL"

    if any(term in summary for term in (
        "denial of service",
        "dos",
        "memory corruption",
        "sql injection",
        "command injection",
    )):
        return "HIGH"

    return "MEDIUM"


# -------------------------
# Fingerprint
# -------------------------
def sca_fingerprint(
    package: str,
    purl: str,
    vuln_id: str,
) -> str:
    """
    Stable fingerprint for SCA findings.
    Same vuln + same dependency = same finding.
    """
    raw = f"sca|{package}|{purl}|{vuln_id}"
    return hashlib.sha256(raw.encode()).hexdigest()


# -------------------------
# Normalization
# -------------------------
def normalize_osv(osv_json: Dict[str, Any], run_id: str) -> List[Finding]:
    """
    Normalize OSV scanner output into canonical Finding objects.
    """
    findings: List[Finding] = []

    for result in osv_json.get("results", []):
        package = result.get("package", {})
        vulnerabilities = result.get("vulnerabilities", [])

        pkg_name = package.get("name", "unknown")
        ecosystem = package.get("ecosystem", "unknown")
        purl = package.get("purl", "unknown")

        for vuln in vulnerabilities:
            vuln_id = vuln.get("id", "UNKNOWN-OSV-ID")

            findings.append(
                Finding(
                    category="SCA",
                    tool="osv",
                    rule_id=vuln_id,
                    title=vuln.get("summary")
                          or f"{pkg_name} has a known vulnerability",

                    severity=derive_osv_severity(vuln),
                    confidence="HIGH",

                    # Dependency-level location
                    file=purl,
                    line_start=0,
                    line_end=None,

                    fingerprint=sca_fingerprint(
                        package=pkg_name,
                        purl=purl,
                        vuln_id=vuln_id,
                    ),

                    occurrences=1,
                    evidence={
                        "package": {
                            "name": pkg_name,
                            "ecosystem": ecosystem,
                            "purl": purl,
                        },
                        "affected": vuln.get("affected", []),
                        "aliases": vuln.get("aliases", []),
                        "references": vuln.get("references", []),
                    },
                )
            )

    return findings