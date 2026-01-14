from sast.entity import FindingEntity


SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

CONFIDENCE_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def score_entity(entity: FindingEntity) -> None:
    severity = SEVERITY_WEIGHT.get(entity.severity, 1)
    confidence = CONFIDENCE_WEIGHT.get(entity.confidence, 1)

    risk = severity * confidence * (1 + entity.exploitability)
    entity.risk_score = int(risk * 10)

    if entity.risk_score >= 80:
        entity.sla_days = 7
    elif entity.risk_score >= 60:
        entity.sla_days = 14
    elif entity.risk_score >= 40:
        entity.sla_days = 30
    else:
        entity.sla_days = 90
