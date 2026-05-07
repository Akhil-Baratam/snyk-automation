"""
Snyk API client.

Strategy (mirrors demo flow):
  1. REST API — fetch all targets (display names + remote URLs, paginated)
  2. REST API — GET /rest/orgs/{org}/projects?target_id={tid} per target
               → per-target project list (target→project mapping)
  3. V1  API  — GET /v1/org/{org}/project/{id} per project
               → reads issueCountsBySeverity.critical / .high directly

Rate limit: ~1,620 req/min. Well within limits.
"""
import logging
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import config
from models.target import ProjectDetail, SnykTarget
from utils.retry import with_retry

logger = logging.getLogger(__name__)

_REST_VERSION = "2024-10-15"
_V1_BASE      = "https://api.snyk.io/v1"


class SnykClient:

    def __init__(self) -> None:
        self._base   = config.SNYK_API_BASE_URL.rstrip("/")
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
        adapter = HTTPAdapter(max_retries=Retry(total=0))
        session.mount("https://", adapter)
        session.mount("http://",  adapter)
        return session

    # ── Low-level HTTP ────────────────────────────────────────────────────────

    def _get(self, url: str, params: dict[str, Any] | None = None) -> dict:
        def _call() -> dict:
            resp = self._session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            return resp.json()
        return with_retry(_call)

    # ── Phase 0 ───────────────────────────────────────────────────────────────

    def check_org_reachability(self) -> None:
        """Validates token + org ID. Raises on 401/404/timeout."""
        url = f"{self._base}/rest/orgs/{self._org_id}"
        self._get(url, params={"version": _REST_VERSION})

    # ── REST pagination ───────────────────────────────────────────────────────

    def _paginate(self, url: str, params: dict[str, Any], label: str) -> list[dict]:
        """Follow links.next cursors until exhausted."""
        items: list[dict] = []
        page = 1
        current_url: str = url
        current_params: dict[str, Any] | None = dict(params)

        while True:
            data  = self._get(current_url, current_params)
            batch = data.get("data", [])
            items.extend(batch)

            next_link: str | None = data.get("links", {}).get("next")
            if not next_link:
                break

            current_url    = next_link if next_link.startswith("http") else f"{self._base}{next_link}"
            current_params = None
            page += 1

        logger.info("Fetched %d %s across %d page(s)", len(items), label, page)
        return items

    # ── REST fetch methods ────────────────────────────────────────────────────

    def fetch_all_targets(self) -> list[dict]:
        """
        GET /rest/orgs/{org}/targets
        Returns target display names and remote URLs.
        """
        url    = f"{self._base}/rest/orgs/{self._org_id}/targets"
        params = {"version": _REST_VERSION, "limit": config.SNYK_PAGE_SIZE}
        return self._paginate(url, params, "targets")

    def fetch_projects_for_target(self, target_id: str) -> list[dict]:
        """
        GET /rest/orgs/{org}/projects?target_id={target_id}
        Returns only projects belonging to a specific target.
        """
        url    = f"{self._base}/rest/orgs/{self._org_id}/projects"
        params = {
            "version":   _REST_VERSION,
            "limit":     config.SNYK_PAGE_SIZE,
            "target_id": target_id,
        }
        return self._paginate(url, params, f"projects[{target_id[:8]}]")

    # ── V1 issue counts ───────────────────────────────────────────────────────

    def fetch_project_issue_counts(self, project_id: str) -> dict[str, int]:
        """
        GET /v1/org/{org}/project/{project_id}

        Returns issueCountsBySeverity directly:
        {
            "critical": int,
            "high":     int,
            "medium":   int,
            "low":      int,
        }
        """
        url  = f"{_V1_BASE}/org/{self._org_id}/project/{project_id}"
        data = self._get(url)
        counts = data.get("issueCountsBySeverity", {})
        return {
            "critical": int(counts.get("critical") or 0),
            "high":     int(counts.get("high")     or 0),
            "medium":   int(counts.get("medium")   or 0),
            "low":      int(counts.get("low")      or 0),
        }

    # ── In-memory aggregation ─────────────────────────────────────────────────

    def build_target_map(self, projects: list[dict]) -> dict[str, dict]:
        """
        For every active project:
          1. GET V1 project → read issueCountsBySeverity
          2. Accumulate counts by target_id
          3. Store ProjectDetail only for files with C/H > 0

        Returns:
            {
                target_id: {
                    "critical": int,
                    "high":     int,
                    "projects": [ProjectDetail, ...]
                }
            }
        """
        active = [p for p in projects if p.get("attributes", {}).get("status") == "active"]
        total  = len(active)
        target_map: dict[str, dict] = {}

        logger.info("Fetching issue counts for %d active projects via V1 API...", total)

        for idx, project in enumerate(active, start=1):
            proj_id   = project.get("id", "")
            proj_name = project.get("attributes", {}).get("name", "")
            target_id = (
                project
                .get("relationships", {})
                .get("target", {})
                .get("data", {})
                .get("id")
            )

            if not proj_id or not target_id:
                continue

            if idx % 50 == 0 or idx == total:
                logger.info("  Progress: %d/%d projects processed", idx, total)

            try:
                counts = self.fetch_project_issue_counts(proj_id)
            except Exception as exc:
                logger.warning(
                    "  Could not fetch counts for project %s (%s): %s",
                    proj_id, proj_name, exc
                )
                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

            if target_id not in target_map:
                target_map[target_id] = {
                    "critical": 0, "high": 0, "medium": 0, "low": 0, "projects": [],
                }

            target_map[target_id]["critical"] += counts["critical"]
            target_map[target_id]["high"]     += counts["high"]
            target_map[target_id]["medium"]   += counts["medium"]
            target_map[target_id]["low"]      += counts["low"]

            # Only include in description table if this file has C or H vulns
            if (counts["critical"] > 0 or counts["high"] > 0) and proj_name:
                target_map[target_id]["projects"].append(
                    ProjectDetail(
                        name       = proj_name,
                        project_id = proj_id,
                        critical   = counts["critical"],
                        high       = counts["high"],
                        medium     = counts["medium"],
                        low        = counts["low"],
                    )
                )

            time.sleep(0.03)  # ~33 req/s — well within 1,620/min limit

        return target_map

    def build_target_lookup(self, targets: list[dict]) -> dict[str, dict]:
        """Returns { target_id: {"display_name": str, "remote_url": str} }"""
        result: dict[str, dict] = {}
        for t in targets:
            tid = t.get("id")
            if not tid:
                continue
            attrs = t.get("attributes", {})
            result[tid] = {
                "display_name": attrs.get("display_name", ""),
                "remote_url":   attrs.get("url", "") or attrs.get("remoteUrl", ""),
            }
        return result

    # ── Top-level pipeline ────────────────────────────────────────────────────

    def get_aggregated_targets(self) -> tuple[list[SnykTarget], set[str]]:
        """
        Full Phase 1 pipeline (mirrors demo flow):

          Step 1 — GET /rest/orgs/{org}/targets                       → display names, all_target_ids
          Step 2 — GET /rest/orgs/{org}/projects?target_id={tid} × N  → per-target projects
          Step 3 — GET /v1/org/{org}/project/{id}                × M  → issueCountsBySeverity
          Step 4 — Group by target, filter to C/H > 0

        Returns:
            (targets_with_vulns, all_target_ids)

            all_target_ids = every target UUID in the org — used by Phase 2
            reverse check to distinguish "clean repo" vs "repo deleted from Snyk".
        """
        logger.info("Step 1/3 — Fetching all targets")
        raw_targets    = self.fetch_all_targets()
        all_target_ids = {t["id"] for t in raw_targets if t.get("id")}
        target_lookup  = self.build_target_lookup(raw_targets)
        logger.info("Fetched %d targets total", len(all_target_ids))

        logger.info("Step 2/3 — Fetching projects per target (%d targets)", len(all_target_ids))
        all_projects: list[dict] = []
        for tid in all_target_ids:
            projects = self.fetch_projects_for_target(tid)
            all_projects.extend(projects)
        logger.info(
            "Fetched %d projects total across %d target(s)",
            len(all_projects),
            len(all_target_ids),
        )

        logger.info("Step 3/3 — Fetching issue counts per project")
        target_map = self.build_target_map(all_projects)

        vuln_count = sum(1 for v in target_map.values() if v["critical"] > 0 or v["high"] > 0)
        logger.info("%d targets have C/H vulnerabilities", vuln_count)

        results: list[SnykTarget] = []
        for tid, data in target_map.items():
            if data["critical"] == 0 and data["high"] == 0:
                continue
            lookup = target_lookup.get(tid, {})
            results.append(
                SnykTarget(
                    id           = tid,
                    display_name = lookup.get("display_name") or f"target-{tid[:8]}",
                    critical     = data["critical"],
                    high         = data["high"],
                    medium       = data["medium"],
                    low          = data["low"],
                    remote_url   = lookup.get("remote_url", ""),
                    projects     = data["projects"],
                )
            )

        logger.info("Phase 1 complete — %d targets with C/H vulnerabilities", len(results))
        return results, all_target_ids