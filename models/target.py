from dataclasses import dataclass, field


@dataclass
class ProjectDetail:
    name: str           # file path within repo, e.g. "package.json"
    project_id: str     # Snyk project UUID
    critical: int
    high: int
    medium: int = 0
    low: int = 0


@dataclass
class SnykTarget:
    id: str
    display_name: str
    critical: int
    high: int
    medium: int = 0
    low: int = 0
    remote_url: str = ""
    projects: list[ProjectDetail] = field(default_factory=list)

    @property
    def has_vulns(self) -> bool:
        return self.critical > 0 or self.high > 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low
