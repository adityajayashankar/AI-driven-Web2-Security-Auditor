import hashlib
import re
from typing import List, Dict, Any
from sast.schema import Finding

# Regex for common secrets (Generic, AWS, Bearer, etc.)
SECRET_PATTERNS = [
    r"(?i)(api_?key|auth_?token|access_?token|secret|password)[\s]*[:=][\s]*['\"][a-zA-Z0-9_\-]{8,}['\"]",
    r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
]

def redact_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact potential secrets from evidence objects.
    """
    clean = evidence.copy()
    
    def clean_text(text: str) -> str:
        for pattern in SECRET_PATTERNS:
            text = re.sub(pattern, "[REDACTED_SECRET]", text)
        return text

    if "code" in clean and isinstance(clean["code"], str):
        clean["code"] = clean_text(clean["code"])
    
    if "message" in clean and isinstance(clean["message"], str):
        clean["message"] = clean_text(clean["message"])

    return clean

def compute_fingerprint(
    tool: str,
    rule_id: str,
    file_path: str,
    code_snippet: str,
) -> str:
    # Normalize code to prevent whitespace changes from breaking dedup
    normalized_code = re.sub(r"\s+", " ", code_snippet.strip()) if code_snippet else ""
    raw = "|".join([tool, rule_id, file_path, normalized_code])
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
        rule_id = r.get("check_id", "unknown-rule")

        # 1. Generate Fingerprint
        fingerprint = compute_fingerprint(
            tool="semgrep",
            rule_id=rule_id,
            file_path=f"{path}:{start_line}",
            code_snippet=code_snippet,
        )

        # 2. Redact Evidence
        raw_evidence = {
            "code": code_snippet,
            "message": message,
        }
        safe_evidence = redact_evidence(raw_evidence)

        # 3. Create Finding (Fully Populated)
        finding = Finding(
            category="SAST",
            tool="semgrep",
            rule_id=rule_id,
            title=message[:200] if message else "SAST Finding", # Truncate long titles
            severity=severity,
            confidence="MEDIUM",
            file=path,
            line=start_line,
            fingerprint=fingerprint,
            occurrences=1,
            evidence=safe_evidence, # Use the safe version
        )
        findings.append(finding)

    return findings