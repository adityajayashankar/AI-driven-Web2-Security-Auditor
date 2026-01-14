from typing import List, Set
from sast.entity import FindingEntity


# ---- Normalized weakness families ----
TLS_FAMILY: Set[str] = {
    "tls",
    "ssl",
    "cipher",
    "protocol",
    "weak-ssl",
    "weak-cipher",
}

OTHER_FAMILIES = {
    "xss",
    "sql",
    "auth",
    "csrf",
    "ssrf",
    "rce",
    "deserialization",
    "crypto",
}


def extract_tokens(entity: FindingEntity) -> Set[str]:
    """
    Extract normalized weakness tokens from rule_id + title.
    """
    text = f"{entity.weakness} {entity.title}".lower()

    tokens = set()

    for t in TLS_FAMILY:
        if t in text:
            tokens.add("tls")  # collapse all TLS variants

    for t in OTHER_FAMILIES:
        if t in text:
            tokens.add(t)

    return tokens


def same_family(a: FindingEntity, b: FindingEntity) -> bool:
    """
    True if two entities belong to the same normalized weakness family.
    """
    return bool(extract_tokens(a) & extract_tokens(b))


def semantic_merge(entities: List[FindingEntity]) -> List[FindingEntity]:
    """
    Layer 2: Bounded semantic correlation.
    - Only cross-category merges
    - Only same weakness family
    - Deterministic and auditable
    """
    merged: List[FindingEntity] = []

    for ent in entities:
        matched = False

        for existing in merged:
            if (
                same_family(ent, existing)
                and ent.category != existing.category
            ):
                # Merge signals
                existing.signals.extend(ent.signals)

                # Promote category + confidence
                existing.category = "MULTI"
                existing.confidence = "HIGH"

                matched = True
                break

        if not matched:
            merged.append(ent)

    return merged


