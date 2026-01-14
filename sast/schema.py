from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class Finding:
    category: str
    tool: str
    rule_id: str
    title: str
    severity: str
    confidence: str

    file: str
    line_start: int
    line_end: Optional[int]

    fingerprint: str
    occurrences: int = 1        

    evidence: Dict[str, Any] = None
