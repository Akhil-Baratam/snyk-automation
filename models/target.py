from dataclasses import dataclass, field


@dataclass
class SnykTarget:
    id: str
    display_name: str
    critical: int
    high: int
    projects: list[str] = field(default_factory=list)

    @property
    def has_vulns(self) -> bool:
        return self.critical > 0 or self.high > 0
