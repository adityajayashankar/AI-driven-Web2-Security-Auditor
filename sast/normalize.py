import hashlib
import re
from typing import List

from .schema import Finding


def normalize_code(code: str) -> str:
    if not code:
        return ""
    return re.sub(r"\s+", " ", code.strip())


def compute_fingerprint(
    tool: str,
    rule_id: str,
    file_path: str,
    code_snippet: str,
) -> str:
    raw = "|".join([
        tool,
        rule_id,
        file_path,
        normalize_code(code_snippet),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_semgrep(raw: dict) -> List[Finding]:
    """
    Convert raw Semgrep JSON output into canonical Finding objects.
    """
    findings: List[Finding] = []

    for r in raw.get("results", []):
        path = r.get("path", "")
        start_line = r.get("start", {}).get("line", 0)
        end_line = r.get("end", {}).get("line", start_line)

        code_snippet = r.get("extra", {}).get("lines", "")
        message = r.get("extra", {}).get("message", "")
        severity = r.get("extra", {}).get("severity", "MEDIUM")

        fingerprint = compute_fingerprint(
        tool="semgrep",
        rule_id=r.get("check_id", ""),
        file_path=f"{path}:{start_line}",  # 👈 required
        code_snippet=code_snippet,
        )

        finding = Finding(
            category="SAST",
            tool="semgrep",
            rule_id=r.get("check_id", ""),
            title=message,
            severity=severity,
            confidence="MEDIUM",

            file=path,
            line_start=start_line,
            line_end=end_line,

            fingerprint=fingerprint,
            occurrences=1,

            evidence={
                "code": code_snippet,
                "message": message,
            },
        )

        findings.append(finding)

    return findings
