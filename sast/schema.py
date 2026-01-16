from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional
from datetime import datetime

@dataclass
class Finding:
    """
    Standardized Security Finding Schema.
    Robust version: Accepts any arguments from parsers to prevent crashes.
    """
    # --- REQUIRED FIELDS (Your Schema) ---
    fingerprint: str
    title: str
    severity: str
    status: str = "open"

    # --- OPTIONAL FIELDS (Your Schema) ---
    repo: str = ""
    category: str = ""
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # --- INTERNAL FIELDS (Used by Parsers) ---
    # We define these so we can store the data if provided
    file: str = ""           # Parsers send 'file', we map it to location
    file_path: str = ""
    line: int = 0
    url: str = ""
    confidence: str = "UNKNOWN"
    description: str = ""
    code_snippet: str = ""
    tool: str = ""
    rule_id: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __init__(self, **kwargs):
        """
        Custom Init: Catches ALL arguments. 
        If a parser sends 'file' or 'confidence', we catch it here so we don't crash.
        """
        names = set([f.name for f in dataclasses.fields(self)])
        for k, v in kwargs.items():
            if k in names:
                setattr(self, k, v)
            # Special handling: Map 'file' (from parser) to 'file_path' (our schema)
            if k == 'file':
                self.file_path = v
                self.file = v
        
        # Ensure required fields have defaults if missing (safety net)
        if not hasattr(self, 'fingerprint'): self.fingerprint = "unknown-hash"
        if not hasattr(self, 'title'): self.title = "Unknown Finding"
        if not hasattr(self, 'severity'): self.severity = "LOW"
        if not hasattr(self, 'status'): self.status = "open"
        if not hasattr(self, 'first_seen'): self.first_seen = datetime.utcnow().isoformat()
        if not hasattr(self, 'last_seen'): self.last_seen = datetime.utcnow().isoformat()
        if not hasattr(self, 'evidence'): self.evidence = {}

    @property
    def location(self) -> str:
        """
        Smart location formatter: handles URLs or File Paths
        """
        if self.url:
            return self.url
        # Use file_path if set, otherwise fallback to 'file'
        path = self.file_path or self.file
        if path:
            return f"{path}:{self.line}" if self.line else path
        return "unknown"

    def to_dict(self):
        """
        Export ONLY the clean fields you requested.
        """
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "repo": self.repo,
            "location": self.location,  # Uses the property above
            "category": self.category,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            # We keep 'tool' and 'rule_id' as they are useful for debugging,
            # but you can remove them if you want it even cleaner.
            "tool": self.tool,
            "rule_id": self.rule_id,
            "evidence": self.evidence
        }

import dataclasses