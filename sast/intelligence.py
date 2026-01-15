from typing import List, Dict, Any, Optional

from sast.schema import Finding
from sast.entity import FindingEntity
from sast.entity_builder import build_entities
from sast.semantic_merge import semantic_merge
from sast.sca_collapse import collapse_sca_entities
from sast.context import enrich_context
from sast.scoring import score_entity
from sast.lifecycle import apply_lifecycle


# -------------------------
# Core entity pipeline
# -------------------------
def build_finding_entities(findings: List[Finding]) -> List[FindingEntity]:
    if not findings:
        return []

    entities = build_entities(findings)
    entities = semantic_merge(entities)
    entities = collapse_sca_entities(entities)

    # Lifecycle tracking
    apply_lifecycle(entities)

    for entity in entities:
        enrich_context(entity)
        score_entity(entity)

    return entities


# -------------------------
# Public intelligence API
# -------------------------
def build_intelligence(
    findings: List[Finding],
    *,
    run_id: Optional[str] = None,
    include_summary: bool = False,
) -> Any:
    """
    INTELLIGENCE PLANE ENTRYPOINT

    Default behavior (backward-compatible):
        build_intelligence(findings) -> List[FindingEntity]

    Structured behavior (API/UI):
        build_intelligence(findings, run_id=..., include_summary=True) -> Dict
    """

    entities = build_finding_entities(findings)

    # 🔒 DEFAULT: return entities only (matches test expectations)
    if not include_summary:
        return entities

    summary = {
        "total_findings": len(findings),
        "total_entities": len(entities),
        "by_category": {},
    }

    for entity in entities:
        summary["by_category"].setdefault(entity.category, 0)
        summary["by_category"][entity.category] += 1

    payload: Dict[str, Any] = {
        "summary": summary,
        "entities": entities,
    }

    if run_id is not None:
        payload["run_id"] = run_id

    return payload





