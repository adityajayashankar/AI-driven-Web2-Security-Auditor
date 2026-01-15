from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class PlannerContext:
    language: str
    files: Sequence[str]
    frameworks: Sequence[str]
    intent: str  # baseline | pr | release
