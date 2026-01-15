from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass(frozen=True)
class ScanLimits:
    max_runtime_seconds: int
    max_requests: int


@dataclass(frozen=True)
class ExecutionPlan:
    """
    Output of the Agent Planner.
    This is the ONLY thing that can trigger scans.
    """
    run_sast: bool
    run_sca: bool
    run_dast: bool

    reason: str
    limits: ScanLimits


@dataclass(frozen=True)
class AgentContext:
    """
    SAFE context only.
    NO source code.
    NO secrets.
    """
    repo: str
    languages: List[str]
    frameworks: List[str]
    dependencies: List[str]

    is_pr: bool
    changed_files: List[str]

    has_public_endpoint: bool
