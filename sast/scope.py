"""
Scope & Safety Guardrails
========================

This module is the single source of truth for:
- What can be scanned
- What must be blocked
- Why a scan was blocked (auditable)

Owned by: Platform / SCM
Consumed by: Orchestrator (execution plane)

NO tool logic belongs here.
"""

from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import urlparse


# -------------------------
# Scope Policy Definition
# -------------------------
@dataclass(frozen=True)
class ScopePolicy:
    """
    Immutable scope policy.

    If it is not explicitly allowed here, it is denied.
    """

    # SCM scope
    allowed_repo_prefixes: List[str]

    # DAST scope
    allowed_domains: List[str]
    allowed_schemes: Tuple[str, ...] = ("http", "https")

    # Safety toggles
    safe_mode: bool = True

    # Hard limits (future use, enforced by runners)
    max_requests: int = 1000
    max_runtime_seconds: int = 300


# -------------------------
# Exceptions
# -------------------------
class ScopeViolation(Exception):
    """Raised when execution violates scope policy."""
    pass


# -------------------------
# Validators
# -------------------------
def validate_repo_scope(repo_input: str, policy: ScopePolicy) -> None:
    """
    Validate that the repo URL/path is allowed by SCM policy.
    """
    if repo_input.startswith("http"):
        for prefix in policy.allowed_repo_prefixes:
            if repo_input.startswith(prefix):
                return
        raise ScopeViolation(
            f"Repository not allowed by scope: {repo_input}"
        )


def validate_target_url(target_url: str, policy: ScopePolicy) -> None:
    """
    Validate DAST target URL against allowlist.
    """
    parsed = urlparse(target_url)

    if parsed.scheme not in policy.allowed_schemes:
        raise ScopeViolation(
            f"Scheme not allowed: {parsed.scheme}"
        )

    hostname = parsed.hostname
    if not hostname:
        raise ScopeViolation("Invalid target URL")

    for domain in policy.allowed_domains:
        if hostname == domain or hostname.endswith(f".{domain}"):
            return

    raise ScopeViolation(
        f"Target domain not allowed: {hostname}"
    )
