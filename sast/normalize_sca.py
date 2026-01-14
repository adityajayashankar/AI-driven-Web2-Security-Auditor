from typing import List
from sast.schema import Finding
from sast.fingerprint import sca_fingerprint


def normalize_pip_audit(raw: dict) -> List[Finding]:
    findings: List[Finding] = []

    for dep in raw.get("dependencies", []):
        package = dep.get("name", "")
        version = dep.get("version", "")

        for vuln in dep.get("vulnerabilities", []):
            cve_id = vuln.get("id", "")
            description = vuln.get("description", "")

            raw_severity = vuln.get("severity")
            severity = raw_severity.upper() if raw_severity else "UNKNOWN"

            fingerprint = sca_fingerprint(
                tool="pip-audit",
                ecosystem="python",
                cve_id=cve_id,
                package=package,
                installed_version=version,
            )

            findings.append(
                Finding(
                    category="SCA",
                    tool="pip-audit",
                    rule_id=cve_id,
                    title=f"{package} vulnerable to {cve_id}",
                    severity=severity,
                    confidence="MEDIUM",

                    file=f"dependency:{package}@{version}",
                    line_start=0,
                    line_end=None,

                    fingerprint=fingerprint,
                    occurrences=len(vuln.get("dependency_paths", [])) or 1,

                    evidence={
                        "package": package,
                        "installed_version": version,
                        "affected_versions": vuln.get("affected_versions"),
                        "fix_versions": vuln.get("fix_versions", []),
                        "description": description,
                        "references": vuln.get("links", []),
                        "source": "pip-audit",
                    },
                )
            )

    return findings

