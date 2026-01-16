from typing import List, Dict, Tuple
import os
from urllib.parse import urlparse

# This was the missing import causing your error
from sast.schema import Finding


def issue_key(f: Finding) -> Tuple[str, str, str]:
    """
    Canonical issue identity across tools.
    """
    return (f.category, f.tool, f.rule_id)


def normalize_path(path_or_url: str) -> str:
    """
    Extracts the 'stem' of a path/URL for fuzzy matching.
    http://localhost/api/login -> login
    src/auth/login_route.py -> login
    """
    # Handle URLs
    if path_or_url.startswith(("http:", "https:")):
        parsed = urlparse(path_or_url)
        # return the last segment of the path without extension
        path = parsed.path.strip("/")
        return os.path.splitext(os.path.basename(path))[0].lower()
    
    # Handle File Paths
    filename = os.path.basename(path_or_url)
    return os.path.splitext(filename)[0].lower()


def same_vuln_family(a: Finding, b: Finding) -> bool:
    """
    Conservative vuln family match for cross-tool correlation.
    """
    if a.rule_id == b.rule_id:
        return True

    a_id = a.rule_id.lower()
    b_id = b.rule_id.lower()

    families = [
        "sql", "xss", "auth", "csrf", "ssrf", "rce", 
        "command", "deserialization", "tls", "cipher", "crypto"
    ]

    return any(f in a_id and f in b_id for f in families)


def same_surface(a: Finding, b: Finding) -> bool:
    """
    Fuzzy correlation between code files (SAST) and endpoints (DAST).
    """
    # If same category (e.g. SAST vs SAST), use strict equality
    if a.category == b.category:
        return a.file == b.file

    # Cross-category: Fuzzy match on "stem"
    stem_a = normalize_path(a.file)
    stem_b = normalize_path(b.file)

    # If stems match and are not empty/generic (like "index" or "")
    if stem_a == stem_b and len(stem_a) > 2 and stem_a != "index":
        return True
    
    return False


def merge_findings(primary: Finding, secondary: Finding) -> Finding:
    """
    Merge two findings into one canonical issue.
    """
    primary.occurrences += secondary.occurrences

    # Preserve evidence trail
    if isinstance(primary.evidence, dict) and isinstance(secondary.evidence, dict):
        primary.evidence = {
            "signals": primary.evidence.get("signals", [primary.evidence])
            + [secondary.evidence]
        }

    # Escalate confidence if multiple signals exist
    if primary.category != secondary.category:
        primary.confidence = "HIGH"

    return primary


def dedup_findings(findings: List[Finding]) -> List[Finding]:
    """
    Unified dedup engine across SAST, DAST, SCA.
    """

    # ---------- Tier 0: exact fingerprint ----------
    by_fingerprint: Dict[str, Finding] = {}
    for f in findings:
        if f.fingerprint in by_fingerprint:
            merge_findings(by_fingerprint[f.fingerprint], f)
        else:
            by_fingerprint[f.fingerprint] = f

    unique = list(by_fingerprint.values())

    # ---------- Tier 1: issue-level grouping ----------
    by_issue: Dict[Tuple[str, str, str], Finding] = {}

    for f in unique:
        key = issue_key(f)
        if key in by_issue:
            merge_findings(by_issue[key], f)
        else:
            by_issue[key] = f

    issues = list(by_issue.values())

    # ---------- Tier 2: cross-tool correlation ----------
    final: List[Finding] = []

    for f in issues:
        merged = False
        for existing in final:
            if (
                {f.category, existing.category} == {"SAST", "DAST"}
                and same_vuln_family(f, existing)
                and same_surface(f, existing)
            ):
                merge_findings(existing, f)
                merged = True
                break

        if not merged:
            final.append(f)

    return final