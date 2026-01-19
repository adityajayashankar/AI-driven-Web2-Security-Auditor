# sast/normalize_dast.py

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
        
        # [FIX] Extract Deep Evidence
        # Nuclei usually provides these fields if -jsonl is used
        request = r.get("request", "")
        response = r.get("response", "")
        curl_cmd = r.get("curl-command", "")

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
                confidence="HIGH" if request else "MEDIUM", # Higher confidence if we have a request trace
                file=matched,
                fingerprint=fingerprint,
                occurrences=1,
                evidence={
                    "url": matched,
                    "host": host,
                    "description": info.get("description", ""),
                    "references": info.get("reference", []),
                    "request": request,   # <--- Critical for Reproducibility
                    "response": response, # <--- Critical for Proof
                    "curl_command": curl_cmd
                },
            )
        )

    return findings
