from typing import Optional, Dict
from datetime import datetime
from sqlmodel import SQLModel, Field
from sqlalchemy import Column, JSON

class Scan(SQLModel, table=True):
    id: str = Field(primary_key=True)
    repo_url: Optional[str] = None
    dast_target: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Simple stats
    findings_count: int = 0
    
    # Store the full JSON result in the DB
    raw_results: Dict = Field(default={}, sa_column=Column(JSON))