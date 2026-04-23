"""
Snyk REST API client.

Responsibilities:
  - Org reachability check (Phase 0)
  - Paginated fetch of all org projects (groups by target in memory)
  - Paginated fetch of all org targets (display names + remote URLs)
  - Aggregation of critical/high counts per target, with per-file detail
  - Filtering to only targets with C/H > 0

The client never fetches per-target individually to stay well within
Snyk's rate limit (~1,620 req/min).
"""
import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import config
from models.target import ProjectDetail, SnykTarget
from utils.retry import with_retry

logger = logging.getLogger(__name__)

_API_VERSION = "2024-10-15"


class SnykClient:
    def __init__(self) -> None:
        self._base = config.SNYK_API_BASE_URL.rstrip("/")
        self._org_id = config.SNYK_ORG_ID
        self._session = self._build_session()

    # ── Session ───────────────────────────────────────────────────────────────

    @staticmethod
    def _build_session() -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "Authorization": f"token {config.SNYK_API_TOKEN}",
            "Content-Type": "application/json",
        })
        # urllib3-level retries disabled; all retries handled by with_retry
        adapter = HTTPAdapter(max_retries=Retry(total=0))
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        return session

    # ── Low-level HTTP ────────────────────────────────────────────────────────

    def _get(self, url: str, params: dict[str, Any] | None = None) -> dict:
        def _call() -> dict:
            resp = self._session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        return with_retry(_call)

    # ── Phase 0 check ─────────────────────────────────────────────────────────

    def check_org_reachability(self) -> None:
        """
        GET /rest/orgs/{org_id} — validates token and org ID.
        Raises on 401 (bad token), 404 (wrong org), or network error.
        """
        url = f"{self._base}/rest/orgs/{self._org_id}"
        self._get(url, params={"version": _API_VERSION})

    # ── Pagination ────────────────────────────────────────────────────────────

    def _paginate(self, url: str, params: dict[str, Any], resource_label: str) -> list[dict]:
        """
        Follow links.next cursors until exhausted.

        Snyk may return next as a full URL or a relative path; both are
        handled.  Query params embedded in next URLs take precedence.
        """
        items: list[dict] = []
        page = 1
        current_url: str = url
        current_params: dict[str, Any] | None = dict(params)

        while True:
            logger.debug("Fetching %s page %d from %s", resource_label, page, current_url)
            data = self._get(current_url, current_params)

            batch: list[dict] = data.get("data", [])
            items.extend(batch)
            logger.debug(
                "%s page %d: %d items (running total: %d)",
                resource_label, page, len(batch), len(items),
            )

            next_link: str | None = data.get("links", {}).get("next")
            if not next_link:
                break

            if next_link.startswith("http"):
                current_url = next_link
                current_params = None  # params embedded in the absolute URL
            else:
                current_url = f"{self._base}{next_link}"
                current_params = None

            page += 1

        logger.info("Fetched %d %s across %d page(s)", len(items), resource_label, page)
        return items

    # ── Public fetch methods ──────────────────────────────────────────────────

    def fetch_all_projects(self) -> list[dict]:
        url = f"{self._base}/rest/orgs/{self._org_id}/projects"
        params: dict[str, Any] = {
            "version": _API_VERSION,
            "limit": config.SNYK_PAGE_SIZE,
            "exclude_empty": "true",
        }
        return self._paginate(url, params, "projects")

    def fetch_all_targets(self) -> list[dict]:
        url = f"{self._base}/rest/orgs/{self._org_id}/targets"
        params: dict[str, Any] = {
            "version": _API_VERSION,
            "limit": config.SNYK_PAGE_SIZE,
        }
        return self._paginate(url, params, "targets")

    # ── In-memory aggregation ─────────────────────────────────────────────────

    def build_target_map(self, projects: list[dict]) -> dict[str, dict]:
        """
        Group active projects by target ID, summing critical + high counts.
        Stores per-file ProjectDetail only for files that have C or H > 0
        (description table only shows actionable files).

        Returns:
            {
                target_id: {
                    "critical": int,
                    "high": int,
                    "projects": [ProjectDetail, ...]   # only C/H > 0 files
                }
            }

        all_target_ids is NOT built here — it comes from the authoritative
        targets API response in get_aggregated_targets() (Fix 2).
        """
        target_map: dict[str, dict] = {}

        for project in projects:
            attrs: dict = project.get("attributes", {})

            if attrs.get("status") != "active":
                continue

            tid: str | None = (
                project
                .get("relationships", {})
                .get("target", {})
                .get("data", {})
                .get("id")
            )
            if not tid:
                logger.debug(
                    "Project %s has no target relationship — skipping", project.get("id")
                )
                continue

            # Snyk may use either field name depending on API version
            issue_counts: dict = (
                attrs.get("issueCounts")
                or attrs.get("issueCountsBySeverity")
                or {}
            )
            critical = int(issue_counts.get("critical") or 0)
            high     = int(issue_counts.get("high")     or 0)
            medium   = int(issue_counts.get("medium")   or 0)
            low      = int(issue_counts.get("low")      or 0)
            project_name: str = attrs.get("name", "")
            project_id: str   = project.get("id", "")

            if tid not in target_map:
                target_map[tid] = {"critical": 0, "high": 0, "projects": []}

            target_map[tid]["critical"] += critical
            target_map[tid]["high"]     += high

            # Only include in description table if file has C or H vulns
            if (critical > 0 or high > 0) and project_name:
                target_map[tid]["projects"].append(
                    ProjectDetail(
                        name=project_name,
                        project_id=project_id,
                        critical=critical,
                        high=high,
                        medium=medium,
                        low=low,
                    )
                )

        return target_map

    def build_target_lookup(self, targets: list[dict]) -> dict[str, dict]:
        """
        Returns { target_id: {"display_name": str, "remote_url": str} }
        from the raw targets list.
        remote_url is the GitLab repo URL stored on the Snyk target.
        """
        result: dict[str, dict] = {}
        for t in targets:
            tid = t.get("id")
            if not tid:
                continue
            attrs = t.get("attributes", {})
            result[tid] = {
                "display_name": attrs.get("displayName", ""),
                "remote_url": attrs.get("url", "") or attrs.get("remoteUrl", ""),
            }
        return result

    # ── Top-level pipeline ────────────────────────────────────────────────────

    def get_aggregated_targets(self) -> tuple[list[SnykTarget], set[str]]:
        """
        Full Phase 1 data-collection pipeline:

          1. Fetch all projects (paginated).
          2. Group by target, sum critical + high, store ProjectDetail per file.
          3. Fetch all targets for display names and remote URLs.
          4. Build all_target_ids from the targets API response — authoritative
             full set regardless of project active/inactive status (Fix 2).
          5. Filter to only targets with C > 0 or H > 0.

        Returns:
            (targets_with_vulns, all_target_ids)

            all_target_ids contains every target UUID from the targets API —
            so Phase 2's reverse check can correctly distinguish "clean repo"
            from "repo deleted from Snyk entirely".
        """
        logger.info("Fetching all projects for org %s", self._org_id)
        projects = self.fetch_all_projects()
        logger.info("Fetched %d projects total", len(projects))

        target_map = self.build_target_map(projects)

        vuln_count = sum(
            1 for v in target_map.values() if v["critical"] > 0 or v["high"] > 0
        )

        logger.info("Fetching all targets for display names and remote URLs")
        raw_targets = self.fetch_all_targets()

        # Build all_target_ids from the authoritative targets API response
        all_target_ids: set[str] = {t["id"] for t in raw_targets if t.get("id")}
        logger.info(
            "Targets API returned %d targets; %d active targets have C/H vulns",
            len(all_target_ids),
            vuln_count,
        )

        target_lookup = self.build_target_lookup(raw_targets)

        results: list[SnykTarget] = []
        for tid, data in target_map.items():
            if data["critical"] == 0 and data["high"] == 0:
                continue
            lookup = target_lookup.get(tid, {})
            results.append(
                SnykTarget(
                    id=tid,
                    display_name=lookup.get("display_name") or f"target-{tid[:8]}",
                    critical=data["critical"],
                    high=data["high"],
                    remote_url=lookup.get("remote_url", ""),
                    projects=data["projects"],
                )
            )

        logger.info("Phase 1 complete — %d targets with C/H vulnerabilities", len(results))
        return results, all_target_ids
