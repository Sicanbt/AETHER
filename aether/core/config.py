from dataclasses import dataclass, field
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass
class AetherConfig:
    model: str = field(default_factory=lambda: os.getenv("DEFAULT_LLM", "openai/gpt-4o"))
    enable_poc: bool = field(default_factory=lambda: os.getenv("ENABLE_POC_VERIFICATION", "true").lower() == "true")
    enable_reviewer: bool = field(default_factory=lambda: os.getenv("ENABLE_REVIEWER", "true").lower() == "true")
    auto_open_pr: bool = field(default_factory=lambda: os.getenv("AUTO_OPEN_PR", "true").lower() == "true")
    max_findings_per_file: int = field(default_factory=lambda: int(os.getenv("MAX_FINDINGS_PER_FILE", "20")))
    sandbox_timeout: int = field(default_factory=lambda: int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "30")))
    chroma_persist_dir: str = field(default_factory=lambda: os.getenv("CHROMA_PERSIST_DIR", "./data/chroma"))
    openai_api_key: Optional[str] = field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    anthropic_api_key: Optional[str] = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY"))
    github_token: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))
    sandbox_image: str = field(default_factory=lambda: os.getenv("SANDBOX_IMAGE", "aether-sandbox:latest"))
