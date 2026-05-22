"""
AETHER — Example usage scripts
"""

import asyncio
from aether.core.orchestrator import SecurityOrchestrator
from aether.core.config import AetherConfig


async def example_scan_local():
    """Scan a local repo."""
    config = AetherConfig(enable_poc=True, enable_reviewer=True, auto_open_pr=False)
    orch = SecurityOrchestrator(config)
    await orch.scan_local("./my-project")


async def example_scan_github():
    """Scan a remote GitHub repo and auto-open PR."""
    config = AetherConfig(auto_open_pr=True)
    orch = SecurityOrchestrator(config)
    await orch.scan_remote("https://github.com/owner/repo")


async def example_fast_mode():
    """Fast scan: skip PoC and reviewer (more false positives, much faster)."""
    config = AetherConfig(enable_poc=False, enable_reviewer=False)
    orch = SecurityOrchestrator(config)
    await orch.scan_local("./my-project")


if __name__ == "__main__":
    asyncio.run(example_scan_local())
