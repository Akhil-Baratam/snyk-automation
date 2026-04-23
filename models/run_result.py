from dataclasses import dataclass, field


@dataclass
class CreatedTicket:
    target_name: str
    ticket_key: str
    ticket_url: str
    snyk_url: str
    critical: int
    high: int


@dataclass
class UpdatedTicket:
    target_name: str
    ticket_key: str
    ticket_url: str
    old_critical: int
    old_high: int
    new_critical: int
    new_high: int
    snyk_url: str


@dataclass
class FlaggedTicket:
    target_name: str
    ticket_key: str
    ticket_url: str
    reason: str  # "project_deleted" | "vulns_resolved"


@dataclass
class RunResult:
    created: list[CreatedTicket] = field(default_factory=list)
    updated: list[UpdatedTicket] = field(default_factory=list)
    flagged: list[FlaggedTicket] = field(default_factory=list)
    processed_count: int = 0
    error_count: int = 0
