from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

from sast.schema import Finding


@dataclass
class FindingEntity:
    entity_id: str
    title: str
    weakness: str
    category: str
    severity: str
    confidence: str
    exploitability: float

    signals: List[Finding]

    # ---- LIFECYCLE ----
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    times_seen: int = 0
    resurfaced: bool = False
