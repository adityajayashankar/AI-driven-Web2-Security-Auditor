import hashlib
import re


def normalize_code(code: str) -> str:
    if not code:
        return ""
    return re.sub(r"\s+", " ", code.strip())


# -------------------------
# SAST fingerprint (existing)
# -------------------------
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


# -------------------------
# DAST fingerprint 
# -------------------------
def dast_fingerprint(
    tool: str,
    template_id: str,
    host: str,
    path: str,
    parameter: str | None = None,
) -> str:
    """
    Canonical DAST fingerprint.

    Identity = vulnerability + attack surface.
    """
    raw = "|".join([
        tool,
        template_id,
        host,
        path,
        parameter or "",
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


#-------------------------
# SCA
#-------------------------
def sca_fingerprint(
    tool: str,
    cve_id: str,
    package: str,
    installed_version: str,
) -> str:
    """
    Canonical SCA fingerprint.

    Identity = CVE + dependency + installed version
    """
    raw = "|".join([
        tool,
        cve_id,
        package,
        installed_version,
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

