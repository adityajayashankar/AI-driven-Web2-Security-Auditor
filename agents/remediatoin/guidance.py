# agents/remediation/guidance.py
from typing import Dict


def generate_guidance(finding: Dict) -> str:
    return (
        f"Issue: {finding.get('title')}\n\n"
        f"Guidance:\n"
        f"- Address pattern related to {finding.get('rule_id')}\n"
        f"- Use framework-safe APIs\n"
        f"- Apply least-privilege and validation\n"
    )

