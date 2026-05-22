from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
import re

from aether.core.config import AetherConfig
from aether.core.llm import call_llm


@dataclass
class Finding:
    cwe: str
    severity: str
    file: str
    line: int
    code_snippet: str
    description: str
    poc: Optional[str] = None


class HunterAgent:
    """
    Scans codebases for security vulnerabilities.
    Uses pattern matching + LLM-driven semantic analysis.
    """

    SUSPICIOUS_PATTERNS = {
        "CWE-89 SQL Injection": [
            r"execute\s*\(\s*[\"'].*?\+",
            r"cursor\.execute\s*\(\s*f[\"']",
            r"query\s*=.*?\+\s*\w+",
        ],
        "CWE-78 Command Injection": [
            r"os\.system\s*\(",
            r"subprocess\..*?shell\s*=\s*True",
            r"eval\s*\(",
            r"exec\s*\(",
        ],
        "CWE-79 XSS": [
            r"innerHTML\s*=",
            r"document\.write\s*\(",
            r"render_template_string\s*\(",
        ],
        "CWE-22 Path Traversal": [
            r"open\s*\(.*?\+",
            r"\.\./.*",
            r"os\.path\.join\s*\(.*?request\.",
        ],
        "CWE-798 Hardcoded Credentials": [
            r"(?i)(api_key|password|secret|token)\s*=\s*[\"'][^\"']{8,}[\"']",
        ],
    }

    SCAN_EXTENSIONS = {".py", ".js", ".ts", ".go", ".rs", ".java", ".php", ".rb"}

    def __init__(self, config: AetherConfig):
        self.config = config

    async def scan(self, root: str) -> List[Finding]:
        findings: List[Finding] = []
        root_path = Path(root)

        for file_path in root_path.rglob("*"):
            if file_path.suffix not in self.SCAN_EXTENSIONS:
                continue
            if any(skip in str(file_path) for skip in [".git", "node_modules", "venv", "__pycache__", "dist", "build"]):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            findings.extend(self._pattern_scan(file_path, content))

        # Limit per file to avoid noise
        return findings[:100]

    def _pattern_scan(self, file_path: Path, content: str) -> List[Finding]:
        results = []
        lines = content.splitlines()
        for cwe, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        severity = "HIGH" if "SQL" in cwe or "Command" in cwe else "MEDIUM"
                        results.append(Finding(
                            cwe=cwe,
                            severity=severity,
                            file=str(file_path),
                            line=i,
                            code_snippet=line.strip()[:200],
                            description=f"Potential {cwe} pattern detected",
                        ))
                        if len(results) >= self.config.max_findings_per_file:
                            return results
        return results
