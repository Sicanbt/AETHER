import asyncio
import typer
from pathlib import Path
from rich.console import Console
from aether.core.orchestrator import SecurityOrchestrator
from aether.core.config import AetherConfig

app = typer.Typer(help="AETHER — Autonomous Multi-Agent Code Security Auditor")
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to the local repository or directory to scan"),
    auto_pr: bool = typer.Option(False, help="Open a PR automatically if path is a git repo"),
    no_poc: bool = typer.Option(False, help="Skip PoC verification (faster, higher false positives)"),
    no_reviewer: bool = typer.Option(False, help="Skip reviewer agent"),
    model: str = typer.Option("openai/gpt-4o", help="LLM backend"),
):
    """Scan a local codebase for vulnerabilities."""
    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Path not found: {target}[/red]")
        raise typer.Exit(1)

    config = AetherConfig(
        model=model,
        enable_poc=not no_poc,
        enable_reviewer=not no_reviewer,
        auto_open_pr=auto_pr,
    )
    orch = SecurityOrchestrator(config)
    asyncio.run(orch.scan_local(str(target)))


@app.command("scan-remote")
def scan_remote(
    repo_url: str = typer.Argument(..., help="GitHub repo URL"),
    branch: str = typer.Option("main", help="Branch to scan"),
    open_pr: bool = typer.Option(True, help="Open PR with verified fixes"),
):
    """Clone a GitHub repo, scan it, and open a PR with fixes."""
    config = AetherConfig(auto_open_pr=open_pr)
    orch = SecurityOrchestrator(config)
    asyncio.run(orch.scan_remote(repo_url, branch))


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0"),
    port: int = typer.Option(8001),
):
    """Start the AETHER API server."""
    import uvicorn
    from api.server import app as api_app
    uvicorn.run(api_app, host=host, port=port)


if __name__ == "__main__":
    app()
