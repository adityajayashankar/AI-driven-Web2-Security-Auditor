from typing import List, Dict
from collections import defaultdict
from sast.entity import FindingEntity


def is_sca_entity(entity: FindingEntity) -> bool:
    return any(s.category == "SCA" for s in entity.signals)


def collapse_sca_entities(
    entities: List[FindingEntity]
) -> List[FindingEntity]:
    """
    Collapse multiple SCA CVE entities into
    one entity per dependency.
    """

    sca_groups: Dict[str, List[FindingEntity]] = defaultdict(list)
    non_sca: List[FindingEntity] = []

    # ---- Group by dependency ----
    for e in entities:
        if not is_sca_entity(e):
            non_sca.append(e)
            continue

        # Use dependency name from evidence
        dep = None
        for s in e.signals:
            dep = s.evidence.get("package") or s.file
            if dep:
                break

        if not dep:
            non_sca.append(e)
            continue

        sca_groups[dep].append(e)

    collapsed: List[FindingEntity] = []

    # ---- Collapse each dependency ----
    for dep, group in sca_groups.items():
        if len(group) == 1:
            collapsed.append(group[0])
            continue

        # Choose highest severity entity as base
        base = max(
            group,
            key=lambda e: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(e.severity)
        )

        base.title = f"Outdated dependency: {dep}"
        base.category = "SCA"

        # Merge all signals
        for e in group:
            if e is not base:
                base.signals.extend(e.signals)

        # Confidence stays MEDIUM unless runtime proof exists later
        base.confidence = "MEDIUM"

        collapsed.append(base)

    return non_sca + collapsed
