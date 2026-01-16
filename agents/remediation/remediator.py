from typing import Dict
from agents.contracts import AgentContext
from agents.llm_clients.openrouter_client import OpenRouterClient

class RemediationAgent:
    def __init__(self, llm_client: OpenRouterClient):
        self.llm = llm_client

    def generate_fix(self, finding: Dict, ctx: AgentContext) -> str:
        """
        Asks the LLM to generate a specific code fix for a finding.
        """
        # Safe fallback if evidence is missing
        evidence = finding.get('evidence', {})
        code_snippet = evidence.get('code') or evidence.get('message') or "No snippet provided"

        prompt = f"""
You are an expert AppSec engineer.
Context:
- Language: {ctx.languages}
- Frameworks: {ctx.frameworks}

Vulnerability:
- Title: {finding.get('title')}
- Tool: {finding.get('tool')}
- Rule ID: {finding.get('rule_id')}
- File: {finding.get('file')}

Code Snippet (Evidence):
{code_snippet}

Task:
1. Explain WHY this is vulnerable in 1 sentence.
2. Provide a SECURE code rewrite for the snippet above.
3. If no snippet is provided, provide a generic pattern fix for this framework.

Output format: Markdown.
"""
        # Call the LLM
        return self.llm.complete(prompt)