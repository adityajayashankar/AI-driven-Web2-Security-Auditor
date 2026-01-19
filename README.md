# DeplAI — AI-Driven Web2 Security Auditor
<!-- Stack -->
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-blue" />
  <img src="https://img.shields.io/badge/FastAPI-backend-green" />
  <img src="https://img.shields.io/badge/PostgreSQL-db-blue" />
  <img src="https://img.shields.io/badge/Docker-required-blue" />
</p>

<!-- LLM -->
<p align="center">
  <img src="https://img.shields.io/badge/LLM-gemma--3n--e2b--it_(google)-lightgrey" />
</p>

<!-- Security Tools -->
<p align="center">
  <img src="https://img.shields.io/badge/SAST-Semgrep-purple" />
  <img src="https://img.shields.io/badge/SBOM-Syft-blue" />
  <img src="https://img.shields.io/badge/SCA-Grype-red" />
  <img src="https://img.shields.io/badge/DAST-Nuclei-orange" />
</p>




DeplAI is an internal **AI-native DevSecOps security auditor** that plans, runs, and normalizes security scans across the SDLC using agentic logic.

---

## What it does

- Uses an **LLM planner** to decide which scans to run (SAST / SCA / DAST) based on context  
  (PR vs main, languages, files changed)
- Enforces **scope & safety policies** before execution
- Runs open-source scanners in Docker
- Normalizes + deduplicates results into a single finding model
- Optionally generates AI-assisted fixes for high/critical issues

---

## Scanners used

- **SAST**: Semgrep  
- **SCA**: Syft (SBOM) + Grype (CVEs)  
- **DAST**: Nuclei (safe templates only)  
- **Config**: Custom HTTP header & cookie checks  

---

## High-level flow

1. API receives scan request  
2. LLM produces an `ExecutionPlan`  
3. Gatekeeper validates plan against scope policy  
4. Orchestrator runs scanners in Docker  
5. Intelligence layer normalizes & dedups findings  
6. Remediator generates fixes  

---

## Setup

### Prerequisites
- Docker + Docker Compose
- Python 3.12+
- LLM API key (OpenRouter)
- Model : google/gemma-3n-e2b-it:free

### Run
```bash
git clone https://github.com/adityajayashankar/AI-driven-Web2-Security-Auditor.git
cd AI-driven-Web2-Security-Auditor

docker build -t deplai-worker .
$env:OPENROUTER_API_KEY ="<your key>"
docker-compose up --build

If you want to check for logs
docker ps -a -> chose the latest docker container ID
docker logs <container_ID>

API: http://localhost:8000
Docs: http://localhost:8000/docs

Local test (no API) - not recommened 
python scripts/check_all_scans.py


Outputs results to scan_results.json.
```
### 📂 Project Structure
.
├── agents/                 # AI agent logic <br>
│   ├── planner/            # LLM & fallback planners (decide what to scan)<br>
│   ├── remediation/        # AI fix generation<br>
│   ├── gatekeeper.py       # Scope & policy enforcement<br>
│   └── contracts.py        # Core data models (ExecutionPlan, Context)<br>
├── api/                    # FastAPI backend<br>
│   ├── main.py             # API routes<br>
│   └── models.py           # SQLModel DB schemas<br>
├── sast/                   # Security tool wrappers<br>
│   ├── runner.py           # Semgrep (SAST)<br>
│   ├── sbom_runner.py      # Syft (SBOM)<br>
│   ├── sca_runner.py       # Grype (SCA)<br>
│   ├── dast_runner.py      # Nuclei (DAST)<br>
│   ├── config_runner.py    # Header & cookie checks<br>
│   └── normalize*.py       # Tool output normalizers<br>
├── scripts/                # Local testing / harness scripts<br>
├── docker-compose.yml      # Docker orchestration<br>
├── dockerfile<br>
└── requirements.txt        <br>
## GAPS 
- AI Enhancemaent 
- Frontend is yet to be integrated
