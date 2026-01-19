from typing import Dict, Union
from agents.contracts import AgentContext
from agents.llm_clients.openrouter_client import OpenRouterClient
from sast.schema import Finding

class RemediationAgent:
    def __init__(self, llm_client: OpenRouterClient):
        self.llm = llm_client

    def generate_fix(self, finding: Union[Finding, Dict], ctx: AgentContext) -> str:
        """
        Asks the LLM to generate a specific code fix for a finding.
        """
        if isinstance(finding, Finding):
            title = finding.title
            tool = finding.tool
            rule_id = finding.rule_id
            file_path = finding.file
            evidence = finding.evidence or {}
        else:
            title = finding.get('title')
            tool = finding.get('tool')
            rule_id = finding.get('rule_id')
            file_path = finding.get('file')
            evidence = finding.get('evidence') or {}

        code_snippet = evidence.get('code') or evidence.get('message') or "No snippet provided"

        prompt = f"""
You are an expert AppSec engineer.
Context:
- Language: {ctx.languages}
- Frameworks: {ctx.frameworks}

Vulnerability:
- Title: {title}
- Tool: {tool}
- Rule ID: {rule_id}
- File: {file_path}

Code Snippet (Evidence):
{code_snippet}


Task:
1. Explain WHY this is vulnerable in 1 sentence.
2. Provide a SECURE code rewrite for the snippet above.
3. If no snippet is provided, provide a generic pattern fix for this framework.

Output format: Markdown.
"""
        try:
            return self.llm.complete(prompt)
        except Exception as e:
            return f"Error generating fix: {str(e)}"