from typing import List
from sast.schema import Finding
from .fingerprint import dast_fingerprint


def normalize_nuclei(raw: dict) -> List[Finding]:
    findings: List[Finding] = []

    for r in raw.get("results", []):
        info = r.get("info", {})

        template_id = r.get("template-id", "")
        host = r.get("host", "")
        matched = r.get("matched-at", "")

        # Split URL into host + path safely
        try:
            path = "/" + matched.split("/", 3)[3]
        except IndexError:
            path = "/"

        severity = info.get("severity", "medium").upper()

        fingerprint = dast_fingerprint(
            tool="nuclei",
            template_id=template_id,
            host=host,
            path=path,
            parameter=None,
        )

        findings.append(
            Finding(
                category="DAST",
                tool="nuclei",
                rule_id=template_id,
                title=info.get("name", template_id),
                severity=severity,
                confidence="MEDIUM",

                file=matched,        # endpoint
                line_start=0,
                line_end=0,

                fingerprint=fingerprint,
                occurrences=1,

                evidence={
                    "url": matched,
                    "host": host,
                    "description": info.get("description", ""),
                    "references": info.get("reference", []),
                    "matched_at": matched,
                },
            )
        )

    return findings

