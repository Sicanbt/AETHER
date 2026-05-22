from dataclasses import dataclass, field
from typing import List
from aether.core.config import AetherConfig
from aether.core.llm import call_llm
from aether.agents.hunter import Finding
from aether.agents.defender import Patch


@dataclass
class ReviewResult:
    approved: bool
    reason: str = ""
    issues: List[str] = field(default_factory=list)


class ReviewerAgent:
    """
    Adversarial code reviewer. Challenges every patch.
    Looks for: incomplete fixes, bypasses, regressions, side effects.
    """

    def __init__(self, config: AetherConfig):
        self.config = config

    async def review(self, finding: Finding, patch: Patch) -> ReviewResult:
        prompt = f"""You are a senior security reviewer. Your job is to REJECT bad patches.

Vulnerability: {finding.cwe}
PoC that exploits the original: {finding.poc}

Original vulnerable code:
{patch.original_code}

Proposed patch:
{patch.patched_code}

Patch author's explanation:
{patch.explanation}

Critical questions:
1. Does this patch fully prevent the PoC from working?
2. Could the fix be bypassed (encoding tricks, edge cases, alternative payloads)?
3. Does it break legitimate functionality?
4. Are there any side effects or regressions?
5. Is the fix at the right layer (root cause vs symptom)?

Respond in JSON only:
{{
  "approved": true/false,
  "reason": "one-sentence summary",
  "issues": ["specific issue 1", "specific issue 2"]
}}

Be strict. If you have any doubt, reject."""

        resp = await call_llm(
            self.config, prompt,
            system="You are a rigorous security reviewer. Reject patches that are incomplete or risky."
        )

        import json, re
        try:
            match = re.search(r'\{.*\}', resp, re.DOTALL)
            data = json.loads(match.group())
            return ReviewResult(
                approved=data.get("approved", False),
                reason=data.get("reason", ""),
                issues=data.get("issues", []),
            )
        except Exception:
            return ReviewResult(approved=False, reason="Review parse error")
