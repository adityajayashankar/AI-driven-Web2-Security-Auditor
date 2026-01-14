from typing import List

from sast.schema import Finding
from sast.entity import FindingEntity
from sast.entity_builder import build_entities
from sast.semantic_merge import semantic_merge
from sast.sca_collapse import collapse_sca_entities
from sast.context import enrich_context
from sast.scoring import score_entity
from sast.lifecycle import apply_lifecycle


def build_finding_entities(findings: List[Finding]) -> List[FindingEntity]:
    if not findings:
        return []

    entities = build_entities(findings)
    entities = semantic_merge(entities)
    entities = collapse_sca_entities(entities)

    # 🔒 LIFECYCLE UPDATE
    apply_lifecycle(entities)

    for e in entities:
        enrich_context(e)
        score_entity(e)

    return entities


