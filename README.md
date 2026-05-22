# AETHER ⚡
### Autonomous Multi-Agent Code Security Auditor

> **"Your code's adversarial twin. It hunts bugs while you sleep."**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Active](https://img.shields.io/badge/status-active-green.svg)]()

---

## The Problem

Security audits are slow, expensive, and reactive.

- A senior security engineer costs **$200K+/year** and reviews maybe 20% of your codebase
- SAST tools like Snyk and SonarQube spit out **thousands of false positives** — devs ignore them
- Vulnerabilities live in production for **an average of 277 days** before detection (IBM 2024)
- AI code review tools today are **single-pass** — they don't reason, debate, or verify their own findings

**AETHER solves this.** It deploys a swarm of specialized AI agents that:
1. **Hunter Agent** scans code for vulnerabilities
2. **Exploiter Agent** tries to construct a working PoC for each finding
3. **Defender Agent** proposes a patch
4. **Reviewer Agent** challenges the patch (could it break things? is the fix complete?)
5. **PR Agent** opens a pull request with verified fixes

If Exploiter can't build a PoC, the finding is dropped. **Zero false positives by design.**

---

## Architecture

```
                    ┌─────────────────────────┐
                    │     ORCHESTRATOR        │
                    │  (CI hook / scheduled)  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │      HUNTER AGENT       │
                    │   (Static + LLM scan)   │
                    └────────────┬────────────┘
                                 │ findings
                    ┌────────────▼────────────┐
                    │     EXPLOITER AGENT     │
                    │  (Builds PoC. No PoC =  │
                    │   no finding. Dropped.) │
                    └────────────┬────────────┘
                                 │ verified vulns
                    ┌────────────▼────────────┐
                    │     DEFENDER AGENT      │
                    │   (Generates patch)     │
                    └────────────┬────────────┘
                                 │ proposed patch
                    ┌────────────▼────────────┐
                    │     REVIEWER AGENT      │
                    │ (Adversarial: breaks?   │
                    │  incomplete? bypassed?) │
                    └────────┬───────┬────────┘
                             │       │
                    accepted │       │ rejected → loop back to Defender
                             │
                    ┌────────▼────────────┐
                    │      PR AGENT       │
                    │  (Opens GitHub PR)  │
                    └─────────────────────┘
```

---

## Why This Wins

| Tool | False Positives | Auto-Fix | Multi-Agent Verify | Open PR |
|------|----------------|----------|---------------------|---------|
| Snyk | High | Limited | No | No |
| SonarQube | Very High | No | No | No |
| GitHub CodeQL | Medium | No | No | No |
| Cursor / Copilot | Low | Manual | No | No |
| **AETHER** | **Zero (PoC-gated)** | **Yes** | **Yes** | **Yes** |

---

## Quickstart

```bash
git clone https://github.com/Sicanbt/AETHER.git
cd AETHER
pip install -r requirements.txt
cp .env.example .env  # add API keys

# Scan a local repo
python -m aether scan ./my-project

# Scan a GitHub repo (auto-opens PRs)
python -m aether scan-remote https://github.com/owner/repo
```

---

## Example Run

```
[ORCHESTRATOR] Scanning ./my-app (847 files, 124K LOC)
[HUNTER]       Found 23 candidate vulnerabilities
[EXPLOITER]    Building PoCs...
               ✓ SQL injection in user_search.py:42 — PoC successful
               ✗ XSS in template.html:88 — false positive (sanitized upstream)
               ✓ Command injection in admin.py:103 — PoC successful
               ✗ ... 18 more dropped (no PoC)
[EXPLOITER]    Verified: 5/23 (78% false positive elimination)
[DEFENDER]     Generating patches...
[REVIEWER]     Patch 1 (SQL injection): ✓ approved
               Patch 2 (Command injection): ✗ incomplete — bypass possible via shell metacharacters
[DEFENDER]     Revising patch 2...
[REVIEWER]     Patch 2 (revised): ✓ approved
[PR AGENT]     Opening PR #42: "Security: fix 5 verified vulnerabilities"
               https://github.com/owner/repo/pull/42
```

---

## Features

- **Zero false positives** — PoC verification gate eliminates noise
- **Multi-agent debate** — Reviewer challenges every patch before PR
- **CI/CD ready** — GitHub Action, GitLab CI, Jenkins integrations
- **Language agnostic** — Python, JavaScript, Go, Rust, Java, PHP, Ruby
- **CWE mapped** — every finding tagged with CWE ID and CVSS score
- **Audit trail** — full reasoning chain stored for every fix

---

## Tech Stack

- **LLM Backend**: GPT-4o / Claude 3.5 Sonnet / local Llama via Ollama
- **Static Analysis**: Semgrep (rules) + Tree-sitter (AST)
- **Sandbox**: Docker for PoC execution (isolated, ephemeral)
- **Memory**: ChromaDB for cross-scan vulnerability tracking
- **API**: FastAPI + GitHub App webhook
- **Frontend**: Next.js dashboard for findings and approvals

---

## Roadmap

- [x] Core multi-agent pipeline
- [x] Python + JavaScript scanners
- [x] PoC verification sandbox
- [x] GitHub PR auto-creation
- [ ] GitLab + Bitbucket support
- [ ] SAST/DAST hybrid (runtime fuzzing)
- [ ] Compliance reports (SOC2, PCI-DSS, HIPAA)
- [ ] On-premise enterprise edition

---

## Pricing Model (for the curious)

- **Open source core**: free forever
- **Cloud SaaS**: per-repo monthly, scales by LOC
- **Enterprise**: on-premise + custom rules + SLA

---

## License

MIT — fork it, ship it, charge for it.
