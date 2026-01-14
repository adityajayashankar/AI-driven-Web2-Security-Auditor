from sast.entity import FindingEntity


def enrich_context(entity: FindingEntity) -> None:
    """
    Adds exploitability proxy based on signals.
    """

    runtime = any(s.category == "DAST" for s in entity.signals)
    internet = any("http" in (s.file or "") for s in entity.signals)

    exploitability = 0.0
    exploitability += 0.4 if runtime else 0.0
    exploitability += 0.3 if internet else 0.0
    exploitability += 0.3 if entity.severity in ("HIGH", "CRITICAL") else 0.0

    entity.exploitability = min(exploitability, 1.0)
