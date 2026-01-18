from dataclasses import dataclass, field
from typing import Dict, Any
from datetime import datetime

@dataclass
class Finding:
    """
    Standardized Security Finding Schema.
    """
    fingerprint: str = "unknown-hash"
    title: str = "Unknown Finding"
    severity: str = "LOW"
    status: str = "open"
    repo: str = ""
    category: str = ""
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    file: str = ""
    file_path: str = ""
    line: int = 0
    url: str = ""
    confidence: str = "UNKNOWN"
    description: str = ""
    code_snippet: str = ""
    tool: str = ""
    rule_id: str = ""
    occurrences: int = 1
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __init__(self, **kwargs):
        # Manually map widely used fields to ensure safety
        self.fingerprint = kwargs.get('fingerprint', "unknown-hash")
        self.title = kwargs.get('title', "Unknown Finding")
        self.severity = kwargs.get('severity', "LOW")
        self.status = kwargs.get('status', "open")
        self.repo = kwargs.get('repo', "")
        self.category = kwargs.get('category', "")
        
        self.tool = kwargs.get('tool', "")
        self.rule_id = kwargs.get('rule_id', "")
        self.occurrences = kwargs.get('occurrences', 1)
        self.evidence = kwargs.get('evidence', {})
        
        # Location mapping
        self.file = kwargs.get('file', "")
        self.file_path = kwargs.get('file_path', self.file)
        self.line = kwargs.get('line', 0)
        self.url = kwargs.get('url', "")
        
        self.first_seen = kwargs.get('first_seen', datetime.utcnow().isoformat())
        self.last_seen = kwargs.get('last_seen', datetime.utcnow().isoformat())

    @property
    def location(self) -> str:
        if self.url: return self.url
        path = self.file_path or self.file
        return f"{path}:{self.line}" if self.line else path or "unknown"

    def to_dict(self):
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "repo": self.repo,
            "location": self.location,
            "category": self.category,
            "tool": self.tool,
            "rule_id": self.rule_id,
            "occurrences": self.occurrences,
            "evidence": self.evidence
        }