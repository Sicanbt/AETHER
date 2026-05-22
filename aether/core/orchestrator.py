import asyncio
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aether.core.config import AetherConfig
from aether.agents.hunter import HunterAgent
from aether.agents.exploiter import ExploiterAgent
from aether.agents.defender import DefenderAgent
from aether.agents.reviewer import ReviewerAgent
from aether.agents.pr_agent import PRAgent

console = Console()


class SecurityOrchestrator:
    """
    Coordinates the multi-agent security pipeline.
    Pipeline: Hunter -> Exploiter (PoC gate) -> Defender -> Reviewer (debate loop) -> PR Agent
    """

    def __init__(self, config: AetherConfig):
        self.config = config
        self.hunter = HunterAgent(config)
        self.exploiter = ExploiterAgent(config)
        self.defender = DefenderAgent(config)
        self.reviewer = ReviewerAgent(config)
        self.pr_agent = PRAgent(config)

    async def scan_local(self, path: str):
        console.print(Panel(f"[bold cyan]AETHER[/bold cyan] — Scanning {path}", border_style="cyan"))

        # 1. Hunt for vulnerabilities
        console.print("[bold yellow][HUNTER][/bold yellow] Scanning codebase...")
        findings = await self.hunter.scan(path)
        console.print(f"  Found {len(findings)} candidate vulnerabilities")

        # 2. PoC verification gate (eliminates false positives)
        verified = []
        if self.config.enable_poc:
            console.print(f"\n[bold red][EXPLOITER][/bold red] Verifying with PoC...")
            for f in findings:
                poc_result = await self.exploiter.verify(f)
                if poc_result.success:
                    f.poc = poc_result.poc_code
                    verified.append(f)
                    console.print(f"  [green]✓[/green] {f.cwe} in {f.file}:{f.line}")
                else:
                    console.print(f"  [dim red]✗[/dim red] {f.cwe} in {f.file}:{f.line} (no PoC)")
        else:
            verified = findings

        if not verified:
            console.print("\n[green]No verified vulnerabilities. Codebase is clean.[/green]")
            return

        console.print(f"\n[bold]Verified: {len(verified)}/{len(findings)} ({(1 - len(verified)/len(findings))*100:.0f}% false positive elimination)[/bold]")

        # 3. Generate patches with debate loop
        console.print(f"\n[bold green][DEFENDER][/bold green] Generating patches...")
        approved_patches = []
        for f in verified:
            patch = await self.defender.fix(f)

            if self.config.enable_reviewer:
                # Debate loop: reviewer challenges patch, defender revises
                for attempt in range(3):
                    review = await self.reviewer.review(f, patch)
                    if review.approved:
                        approved_patches.append((f, patch))
                        console.print(f"  [green]✓ Patch approved[/green] for {f.cwe}")
                        break
                    console.print(f"  [yellow]⚠ Patch rejected[/yellow]: {review.reason}")
                    patch = await self.defender.revise(f, patch, review)
                else:
                    console.print(f"  [red]✗ Patch failed review after 3 attempts[/red]")
            else:
                approved_patches.append((f, patch))

        # 4. Render report
        self._render_report(verified, approved_patches)

        # 5. Open PR if configured
        if self.config.auto_open_pr and approved_patches:
            console.print(f"\n[bold magenta][PR AGENT][/bold magenta] Opening pull request...")
            pr_url = await self.pr_agent.open_pr(path, approved_patches)
            if pr_url:
                console.print(f"  [bold]PR opened:[/bold] {pr_url}")

    async def scan_remote(self, repo_url: str, branch: str = "main"):
        import tempfile, subprocess
        with tempfile.TemporaryDirectory() as tmp:
            console.print(f"[dim]Cloning {repo_url} to {tmp}...[/dim]")
            subprocess.run(["git", "clone", "--depth", "1", "-b", branch, repo_url, tmp], check=True)
            await self.scan_local(tmp)

    def _render_report(self, findings, patches):
        table = Table(title="Security Findings", show_lines=True)
        table.add_column("CWE", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("File", style="yellow")
        table.add_column("Line")
        table.add_column("Patch", style="green")

        approved_files = {f.file: True for f, _ in patches}
        for f in findings:
            patch_status = "✓ ready" if f.file in approved_files else "✗ no patch"
            table.add_row(f.cwe, f.severity, f.file, str(f.line), patch_status)

        console.print(table)
