from typing import List, Dict, Tuple
from sast.schema import Finding


def issue_key(f: Finding) -> Tuple[str, str, str]:
    """
    Canonical issue identity across tools.

    Groups:
    - SAST: same rule across files
    - SCA: same CVE across deps
    - DAST: same vuln class across endpoints
    """
    return (f.category, f.tool, f.rule_id)


def same_vuln_family(a: Finding, b: Finding) -> bool:
    """
    Conservative vuln family match for cross-tool correlation.
    """

    if a.rule_id == b.rule_id:
        return True

    a_id = a.rule_id.lower()
    b_id = b.rule_id.lower()

    families = [
        "sql",
        "xss",
        "auth",
        "csrf",
        "ssrf",
        "rce",
        "command",
        "deserialization",
        "tls",
        "cipher",
        "crypto",
    ]

    return any(f in a_id and f in b_id for f in families)


def same_surface(a: Finding, b: Finding) -> bool:
    """
    Best-effort surface correlation.

    SAST ↔ DAST only.
    """

    if a.category == "DAST" and b.category == "SAST":
        return b.file in a.file

    if a.category == "SAST" and b.category == "DAST":
        return a.file in b.file

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

    Order:
    1. Exact fingerprint
    2. Issue-level (same tool + rule)
    3. Cross-tool correlation
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

