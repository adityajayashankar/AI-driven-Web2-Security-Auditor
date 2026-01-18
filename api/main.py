import os
import json
import docker
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from sqlmodel import SQLModel, Session, create_engine, select
from pydantic import BaseModel
from typing import List, Optional, Dict
from api.models import Scan

# 1. Database Setup
DATABASE_URL = os.environ.get("DATABASE_URL")
engine = create_engine(DATABASE_URL)

def get_session():
    with Session(engine) as session:
        yield session

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables on startup
    SQLModel.metadata.create_all(engine)
    yield

app = FastAPI(title="DeplAI Control Plane", lifespan=lifespan)
client = docker.from_env()

# 2. API Models
class ScanRequest(BaseModel):
    repo_url: Optional[str] = None
    dast_target: Optional[str] = None
    languages: List[str] = ["python"]
    # [FIX] Added dependencies field so Planner knows to trigger SCA
    dependencies: List[str] = []

class ScanResponse(BaseModel):
    scan_id: str
    status: str

# 3. Endpoints
@app.post("/scans", response_model=ScanResponse)
def trigger_scan(req: ScanRequest, session: Session = Depends(get_session)):
    scan_id = str(uuid.uuid4())
    
    # Save "Pending" scan to DB
    scan = Scan(
        id=scan_id,
        repo_url=req.repo_url,
        dast_target=req.dast_target,
        status="running"
    )
    session.add(scan)
    session.commit()

    # Pass configuration to Worker
    host_url = os.environ.get("HOST_URL", "http://host.docker.internal:8000")
    
    # [FIX] Heuristic: If no dependencies provided, assume languages imply dependencies
    # This ensures the Planner sees 'dependencies' and enables SCA.
    final_dependencies = req.dependencies if req.dependencies else req.languages

    worker_input = {
        "run_id": scan_id,
        "repo_path": req.repo_url or "",
        "languages": req.languages,
        "dependencies": final_dependencies, # [FIX] Passed to worker
        "dast": {"target_url": req.dast_target} if req.dast_target else {},
        "callback_url": f"{host_url}/scans/{scan_id}/results"
    }

    try:
        client.containers.run(
            image="deplai-worker",
            detach=True,
            environment={
                "OPENROUTER_API_KEY": os.environ.get("OPENROUTER_API_KEY"),
                "SCAN_INPUT_JSON": json.dumps(worker_input)
            }
        )
        return {"scan_id": scan_id, "status": "started"}
    except Exception as e:
        scan.status = "failed"
        session.add(scan)
        session.commit()
        raise HTTPException(status_code=500, detail=str(e))

# Webhook: Worker calls this when done!
@app.post("/scans/{scan_id}/results")
def receive_results(scan_id: str, results: Dict, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    
    scan.status = "completed"
    scan.raw_results = results
    scan.findings_count = len(results.get("findings", []))
    
    session.add(scan)
    session.commit()
    return {"status": "ok"}

@app.get("/scans/{scan_id}")
def get_scan(scan_id: str, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan