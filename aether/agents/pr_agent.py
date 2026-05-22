from typing import List, Tuple, Optional
import subprocess
import os
from pathlib import Path
from aether.core.config import AetherConfig
from aether.agents.hunter import Finding
from aether.agents.defender import Patch


class PRAgent:
    """
    Applies approved patches to a git repo and opens a pull request via GitHub API.
    """

    def __init__(self, config: AetherConfig):
        self.config = config

    async def open_pr(self, repo_path: str, patches: List[Tuple[Finding, Patch]]) -> Optional[str]:
        repo_path = Path(repo_path).resolve()

        if not (repo_path / ".git").exists():
            return None  # not a git repo

        # Apply patches in-memory and write
        applied = self._apply_patches(repo_path, patches)
        if not applied:
            return None

        # Get repo info from git remote
        try:
            remote_url = subprocess.run(
                ["git", "-C", str(repo_path), "config", "--get", "remote.origin.url"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
            owner_repo = self._parse_github_url(remote_url)
            if not owner_repo:
                return None
        except Exception:
            return None

        # Create branch + commit + push
        branch = f"aether/security-fixes-{os.urandom(4).hex()}"
        try:
            subprocess.run(["git", "-C", str(repo_path), "checkout", "-b", branch], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(repo_path), "add", "-A"], check=True, capture_output=True)
            commit_msg = self._build_commit_message(applied)
            subprocess.run(["git", "-C", str(repo_path), "commit", "-m", commit_msg], check=True, capture_output=True)

            # Push (requires credentials available via git credential helper or token in URL)
            push_url = self._auth_url(remote_url)
            subprocess.run(["git", "-C", str(repo_path), "push", "-u", push_url, branch], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            return f"Git error: {e.stderr.decode() if e.stderr else 'unknown'}"

        # Open PR via API
        return self._create_pr(owner_repo, branch, applied)

    def _apply_patches(self, repo_path: Path, patches: List[Tuple[Finding, Patch]]) -> List[Tuple[Finding, Patch]]:
        applied = []
        for finding, patch in patches:
            if not patch.patched_code:
                continue
            file_path = Path(patch.file)
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                if patch.original_code in content:
                    new_content = content.replace(patch.original_code, patch.patched_code, 1)
                    file_path.write_text(new_content, encoding='utf-8')
                    applied.append((finding, patch))
            except Exception:
                continue
        return applied

    def _build_commit_message(self, patches: List[Tuple[Finding, Patch]]) -> str:
        cwes = sorted(set(f.cwe.split()[0] for f, _ in patches))
        title = f"Security: fix {len(patches)} verified vulnerabilities ({', '.join(cwes)})"
        body_lines = ["", "Fixes detected by AETHER (multi-agent security auditor):", ""]
        for f, p in patches:
            body_lines.append(f"- {f.cwe} in {f.file}:{f.line}")
            body_lines.append(f"  {p.explanation}")
        return title + "\n" + "\n".join(body_lines)

    def _create_pr(self, owner_repo: str, branch: str, patches: List[Tuple[Finding, Patch]]) -> Optional[str]:
        if not self.config.github_token:
            return None
        import urllib.request, json, urllib.error

        body = {
            "title": f"Security: fix {len(patches)} verified vulnerabilities",
            "head": branch,
            "base": "main",
            "body": self._build_commit_message(patches).split("\n", 1)[1],
        }

        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner_repo}/pulls",
            data=json.dumps(body).encode(),
            method="POST",
        )
        req.add_header("Authorization", f"token {self.config.github_token}")
        req.add_header("User-Agent", "aether-security-auditor")
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req) as r:
                data = json.loads(r.read().decode())
                return data.get("html_url")
        except urllib.error.HTTPError as e:
            return f"PR error: {e.read().decode()[:200]}"

    def _parse_github_url(self, url: str) -> Optional[str]:
        # Handle git@github.com:owner/repo.git and https://github.com/owner/repo.git
        import re
        m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", url)
        return m.group(1) if m else None

    def _auth_url(self, remote_url: str) -> str:
        if self.config.github_token and remote_url.startswith("https://github.com"):
            return remote_url.replace("https://", f"https://x-access-token:{self.config.github_token}@")
        return remote_url
