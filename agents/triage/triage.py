from typing import List
from agents.contracts import AgentContext
from sast.schema import Finding

def triage_findings(findings: List[Finding], ctx: AgentContext) -> List[Finding]:
    """
    Enrich findings with triage metadata:
    1. recently_changed: Did this finding occur in a file changed in the PR?
    2. ownership: (Placeholder) Who owns this code?
    """
    
    changed_set = set(ctx.changed_files) if ctx.changed_files else set()

    for finding in findings:
        # 1. Check for recent changes
        is_recent = False
        if finding.file and finding.file in changed_set:
            is_recent = True
        
        if finding.evidence is None:
            finding.evidence = {}
            
        finding.evidence["triage"] = {
            "recently_changed": is_recent,
            "priority_boost": "HIGH" if is_recent else "NONE"
        }

        # 2. Logic for Ownership
        finding.evidence["triage"]["suggested_team"] = "Security"
        if "frontend" in str(finding.file):
             finding.evidence["triage"]["suggested_team"] = "Frontend"
        elif "api" in str(finding.file) or ".py" in str(finding.file):
             finding.evidence["triage"]["suggested_team"] = "Backend"

    return findings