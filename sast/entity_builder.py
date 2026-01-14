import hashlib
from typing import List, Dict
from sast.schema import Finding
from sast.entity import FindingEntity


def entity_signature(f: Finding) -> str:
    """
    Deterministic identity signature.
    """
    key = "|".join([
        f.category,
        f.tool,
        f.rule_id,
        f.file,
    ])
    return hashlib.sha256(key.encode()).hexdigest()


def build_entities(findings: List[Finding]) -> List[FindingEntity]:
    """
    Layer 1: Signature-based grouping.
    """
    buckets: Dict[str, FindingEntity] = {}

    for f in findings:
        sig = entity_signature(f)

        if sig not in buckets:
            buckets[sig] = FindingEntity(
                entity_id=sig,
                title=f.title,
                weakness=f.rule_id,
                category=f.category,
                severity=f.severity,
                confidence=f.confidence,
                exploitability=0.0,
                signals=[f],
            )
        else:
            buckets[sig].signals.append(f)
            buckets[sig].last_seen = f  # updated later properly

    return list(buckets.values())
