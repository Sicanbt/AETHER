from dataclasses import dataclass
from aether.core.config import AetherConfig
from aether.core.llm import call_llm
from aether.agents.hunter import Finding


@dataclass
class Patch:
    finding: Finding
    original_code: str
    patched_code: str
    explanation: str
    file: str
    line: int


class DefenderAgent:
    """
    Generates code patches for verified vulnerabilities.
    Reads file context, produces a minimal-diff fix.
    """

    def __init__(self, config: AetherConfig):
        self.config = config

    async def fix(self, finding: Finding) -> Patch:
        # Read file context for better patch quality
        try:
            with open(finding.file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            start = max(0, finding.line - 10)
            end = min(len(lines), finding.line + 10)
            context = ''.join(lines[start:end])
        except Exception:
            context = finding.code_snippet

        prompt = f"""You are a security engineer. Patch this vulnerability.

Vulnerability: {finding.cwe}
File: {finding.file}:{finding.line}
PoC: {finding.poc}

Code context (lines {start+1}-{end}):
```
{context}
```

Vulnerable line: {finding.code_snippet}

Tasks:
1. Write the minimal patch (diff-friendly, change as few lines as possible)
2. Use safe APIs (parameterized queries, escaping, allowlists, etc.)
3. Don't break existing functionality

Respond in JSON only:
{{
  "patched_code": "the corrected line(s)",
  "explanation": "what was changed and why"
}}"""

        resp = await call_llm(
            self.config, prompt,
            system="You are an experienced security engineer. Write production-ready, minimal patches."
        )

        import json, re
        try:
            match = re.search(r'\{.*\}', resp, re.DOTALL)
            data = json.loads(match.group())
            return Patch(
                finding=finding,
                original_code=finding.code_snippet,
                patched_code=data.get("patched_code", ""),
                explanation=data.get("explanation", ""),
                file=finding.file,
                line=finding.line,
            )
        except Exception:
            return Patch(
                finding=finding,
                original_code=finding.code_snippet,
                patched_code="",
                explanation="Failed to generate patch",
                file=finding.file,
                line=finding.line,
            )

    async def revise(self, finding: Finding, patch: Patch, review) -> Patch:
        """Revise patch based on reviewer feedback."""
        prompt = f"""Your patch was rejected. Revise it.

Vulnerability: {finding.cwe}
Original code: {patch.original_code}
Your previous patch: {patch.patched_code}

Reviewer rejection reason: {review.reason}
Specific issues: {review.issues}

Write an improved patch that addresses the critique.

Respond in JSON only:
{{
  "patched_code": "the improved patch",
  "explanation": "what changed in this revision"
}}"""

        resp = await call_llm(self.config, prompt)
        import json, re
        try:
            match = re.search(r'\{.*\}', resp, re.DOTALL)
            data = json.loads(match.group())
            patch.patched_code = data.get("patched_code", patch.patched_code)
            patch.explanation = data.get("explanation", patch.explanation)
        except Exception:
            pass
        return patch
