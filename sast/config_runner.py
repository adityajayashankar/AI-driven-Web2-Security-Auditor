"""
Config & Auth Checks (Safe, Non-Intrusive)
=========================================

Purpose:
- Detect common web security misconfigurations
- No fuzzing, no auth bypass, no state mutation
- Pure HTTP inspection

Owned by: Security
Obeys: ScopePolicy (DAST scope)
"""

from typing import List, Dict, Any
import requests
from urllib.parse import urlparse

from sast.schema import Finding


# -------------------------
# Constants
# -------------------------
SECURITY_HEADERS = {
    "Content-Security-Policy": "Missing CSP header",
    "Strict-Transport-Security": "Missing HSTS header",
    "X-Frame-Options": "Missing X-Frame-Options header",
    "X-Content-Type-Options": "Missing X-Content-Type-Options header",
    "Referrer-Policy": "Missing Referrer-Policy header",
}


# -------------------------
# Runner
# -------------------------
def run_config_checks(target_url: str, timeout: int = 10) -> List[Finding]:
    """
    Perform safe config & auth checks against target URL.
    """
    findings: List[Finding] = []

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        resp = requests.get(
            base,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "deplai-security-check"},
        )
    except Exception as e:
        findings.append(
            Finding(
                category="SYSTEM",
                tool="config",
                rule_id="config-request-failed",
                title="Config check failed to reach target",
                severity="LOW",
                confidence="HIGH",
                file=base,
                line_start=0,
                line_end=None,
                fingerprint=f"config:error:{hash(str(e))}",
                occurrences=1,
                evidence={"error": str(e)},
            )
        )
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # -------------------------
    # Security headers
    # -------------------------
    for header, message in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append(
                Finding(
                    category="CONFIG",
                    tool="config",
                    rule_id=f"missing-{header.lower()}",
                    title=message,
                    severity="MEDIUM",
                    confidence="HIGH",
                    file=base,
                    line_start=0,
                    line_end=None,
                    fingerprint=f"config:header:{header.lower()}:{base}",
                    occurrences=1,
                    evidence={"header": header},
                )
            )

    # -------------------------
    # Cookie flags (auth safety)
    # -------------------------
    cookies = resp.headers.get("Set-Cookie", "")
    if cookies:
        if "secure" not in cookies.lower():
            findings.append(
                Finding(
                    category="AUTH",
                    tool="config",
                    rule_id="cookie-missing-secure",
                    title="Session cookie missing Secure flag",
                    severity="MEDIUM",
                    confidence="HIGH",
                    file=base,
                    line_start=0,
                    line_end=None,
                    fingerprint=f"config:cookie:secure:{base}",
                    occurrences=1,
                    evidence={"set-cookie": cookies},
                )
            )

        if "httponly" not in cookies.lower():
            findings.append(
                Finding(
                    category="AUTH",
                    tool="config",
                    rule_id="cookie-missing-httponly",
                    title="Session cookie missing HttpOnly flag",
                    severity="MEDIUM",
                    confidence="HIGH",
                    file=base,
                    line_start=0,
                    line_end=None,
                    fingerprint=f"config:cookie:httponly:{base}",
                    occurrences=1,
                    evidence={"set-cookie": cookies},
                )
            )

    return findings
