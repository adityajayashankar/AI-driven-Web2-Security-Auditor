def triage(entity):
    if entity.resurfaced:
        return "ESCALATE"
    if entity.risk_score > 70:
        return "FIX_NOW"
    return "BACKLOG"
