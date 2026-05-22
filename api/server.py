from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import asyncio

from aether.core.orchestrator import SecurityOrchestrator
from aether.core.config import AetherConfig

app = FastAPI(
    title="AETHER API",
    description="Autonomous Multi-Agent Code Security Auditor",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    repo_url: Optional[str] = None
    local_path: Optional[str] = None
    branch: Optional[str] = "main"
    auto_pr: Optional[bool] = True
    enable_poc: Optional[bool] = True
    enable_reviewer: Optional[bool] = True
    model: Optional[str] = "openai/gpt-4o"


class ScanResponse(BaseModel):
    status: str
    findings_count: int
    verified_count: int
    patches_applied: int
    pr_url: Optional[str] = None


@app.get("/health")
async def health():
    return {"status": "ok", "service": "aether", "version": "1.0.0"}


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    if not req.repo_url and not req.local_path:
        raise HTTPException(status_code=400, detail="Either repo_url or local_path is required")

    config = AetherConfig(
        model=req.model,
        enable_poc=req.enable_poc,
        enable_reviewer=req.enable_reviewer,
        auto_open_pr=req.auto_pr,
    )

    orchestrator = SecurityOrchestrator(config)
    try:
        if req.repo_url:
            await orchestrator.scan_remote(req.repo_url, req.branch)
        else:
            await orchestrator.scan_local(req.local_path)

        return ScanResponse(
            status="completed",
            findings_count=0,
            verified_count=0,
            patches_applied=0,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webhook/github")
async def github_webhook(payload: dict):
    """Receive GitHub push events and trigger scans automatically."""
    event_type = payload.get("ref", "")
    if "main" not in event_type:
        return {"status": "skipped", "reason": "not main branch"}

    repo_url = payload.get("repository", {}).get("clone_url", "")
    if repo_url:
        config = AetherConfig()
        orchestrator = SecurityOrchestrator(config)
        asyncio.create_task(orchestrator.scan_remote(repo_url))
        return {"status": "scan_triggered", "repo": repo_url}

    return {"status": "skipped", "reason": "no repo url"}
