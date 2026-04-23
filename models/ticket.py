from dataclasses import dataclass
from typing import Optional


@dataclass
class JiraTicket:
    key: str
    summary: str
    status: str
    snyk_project_id: Optional[str] = None
    snyk_critical_count: Optional[int] = None
    snyk_high_count: Optional[int] = None
