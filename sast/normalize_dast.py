from typing import List
from urllib.parse import urlparse

from sast.schema import Finding
from .fingerprint import dast_fingerprint


def normalize_nuclei(raw: dict) -> List[Finding]:
    findings: List[Finding] = []

    for r in raw.get("results", []):
        info = r.get("info", {})

        template_id = r.get("template-id", "unknown-template")
        matched_at = r.get("matched-at", "")
        host = r.get("host", "")

        # -----------------------------
        # Parse URL safely
        # -----------------------------
        parsed = urlparse(matched_at)
        path = parsed.path or "/"

        severity = info.get("severity", "medium").upper()

        fingerprint = dast_fingerprint(
            tool="nuclei",
            template_id=template_id,
            host=parsed.hostname or host,
            path=path,
            parameter=None,
        )

        # -----------------------------
        # Minimal, SIGNAL-ONLY evidence
        # -----------------------------
        evidence = {
            "url": matched_at,
            "method": r.get("type", "http"),
            "path": path,
            "status_code": r.get("response", {}).get("status"),
            "content_type": r.get("response", {}).get("headers", {}).get("Content-Type"),
            "confidence": "HIGH",
        }

        findings.append(
            Finding(
                category="DAST",
                tool="nuclei",
                rule_id=template_id,
                title=info.get("name", template_id),
                severity=severity,
                confidence="HIGH",
                file=path,        # Endpoint, not source code
                line_start=0,
                line_end=0,
                fingerprint=fingerprint,
                occurrences=1,
                evidence=evidence,
            )
        )

    return findings
