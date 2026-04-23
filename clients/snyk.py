"""
Snyk REST API client.

Responsibilities:
  - Org reachability check (Phase 0)
  - Paginated fetch of all org projects (groups by target in memory)
  - Paginated fetch of all org targets (display names)
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

    def build_target_map(
        self,
        projects: list[dict],
        all_target_ids: set[str] | None = None,
    ) -> dict[str, dict]:
        """
        Group active projects by target ID, summing critical + high counts
        and storing per-file ProjectDetail objects.

        Returns:
            {
                target_id: {
                    "critical": int,
                    "high": int,
                    "projects": [ProjectDetail, ...]
                }
            }

        If all_target_ids is provided it is populated in-place with every
        target UUID seen, including those with zero vulns.  Phase 2's reverse
        check needs this to distinguish "clean repo" from "deleted target".
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

            if all_target_ids is not None:
                all_target_ids.add(tid)

            # Snyk may use either field name depending on API version
            issue_counts: dict = (
                attrs.get("issueCounts")
                or attrs.get("issueCountsBySeverity")
                or {}
            )
            critical = int(issue_counts.get("critical") or 0)
            high = int(issue_counts.get("high") or 0)
            project_name: str = attrs.get("name", "")

            if tid not in target_map:
                target_map[tid] = {"critical": 0, "high": 0, "projects": []}

            target_map[tid]["critical"] += critical
            target_map[tid]["high"] += high
            if project_name:
                target_map[tid]["projects"].append(
                    ProjectDetail(name=project_name, critical=critical, high=high)
                )

        return target_map

    def build_display_name_lookup(self, targets: list[dict]) -> dict[str, str]:
        """Returns { target_id: display_name } from the raw targets list."""
        return {
            t["id"]: t.get("attributes", {}).get("displayName", "")
            for t in targets
            if t.get("id")
        }

    # ── Top-level pipeline ────────────────────────────────────────────────────

    def get_aggregated_targets(self) -> tuple[list[SnykTarget], set[str]]:
        """
        Full Phase 1 data-collection pipeline:

          1. Fetch all projects (paginated).
          2. Group by target, sum critical + high, store ProjectDetail per file.
          3. Fetch all targets for display names.
          4. Filter to only targets with C > 0 or H > 0.

        Returns:
            (targets_with_vulns, all_target_ids)

            all_target_ids contains every target UUID seen — including those
            with zero vulns — so Phase 2's reverse check can tell "clean repo"
            apart from "repo deleted from Snyk".
        """
        logger.info("Fetching all projects for org %s", self._org_id)
        projects = self.fetch_all_projects()
        logger.info("Fetched %d projects total", len(projects))

        all_target_ids: set[str] = set()
        target_map = self.build_target_map(projects, all_target_ids=all_target_ids)

        vuln_count = sum(
            1 for v in target_map.values() if v["critical"] > 0 or v["high"] > 0
        )
        logger.info(
            "Grouped into %d unique targets; %d have Critical/High vulns",
            len(all_target_ids),
            vuln_count,
        )

        logger.info("Fetching target display names")
        raw_targets = self.fetch_all_targets()
        display_names = self.build_display_name_lookup(raw_targets)

        results: list[SnykTarget] = []
        for tid, data in target_map.items():
            if data["critical"] == 0 and data["high"] == 0:
                continue
            results.append(
                SnykTarget(
                    id=tid,
                    display_name=display_names.get(tid) or f"target-{tid[:8]}",
                    critical=data["critical"],
                    high=data["high"],
                    projects=data["projects"],
                )
            )

        logger.info("Phase 1 complete — %d targets with C/H vulnerabilities", len(results))
        return results, all_target_ids
