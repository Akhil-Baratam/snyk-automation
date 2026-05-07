from dataclasses import dataclass
from typing import Optional


@dataclass
class JiraTicket:
    key: str
    summary: str
    status: str = ""
    description: Optional[dict] = None
