# agents/triage/triage.py
from typing import Iterable, Dict
from agents.contracts import AgentContext


def triage(findings: Iterable[Dict], ctx: AgentContext) -> Iterable[Dict]:
    changed = set(ctx.changed_files)
    for f in findings:
        yield {
            **f,
            "triage": {
                "recently_changed": f.get("file") in changed,
                "confidence": 0.8,
            },
        }
