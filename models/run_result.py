from dataclasses import dataclass, field


@dataclass
class CreatedTicket:
    target_name: str
    ticket_key: str
    ticket_url: str
    critical: int
    high: int


@dataclass
class ChangedTicket:
    target_name: str
    ticket_key: str
    ticket_url: str
    old_critical: int
    old_high: int
    new_critical: int
    new_high: int


@dataclass
class FlaggedTicket:
    target_name: str
    ticket_key: str
    ticket_url: str
    reason: str   # "Targets with 0 vulns" | "Target removed from Snyk"


@dataclass
class RunResult:
    created: list[CreatedTicket] = field(default_factory=list)
    changed: list[ChangedTicket] = field(default_factory=list)
    flagged: list[FlaggedTicket] = field(default_factory=list)
    processed_count: int = 0
    error_count: int = 0
