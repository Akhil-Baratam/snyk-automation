"""
GitLab API client — minimal.

Used only by Phase 2 to fetch the last-commit date for the ticket description.
Fails soft: if the token is unset or the call fails, returns None and the
description shows "-" for Last Commit Date / Active in Production.
"""
import logging
from datetime import datetime
from urllib.parse import quote, urlparse

import requests

import config
from utils.retry import with_retry

logger = logging.getLogger(__name__)


class GitLabClient:
    def __init__(self) -> None:
        self._base = config.GITLAB_BASE_URL.rstrip("/")
        self._token = config.GITLAB_API_TOKEN
        self._session = requests.Session()
        if self._token:
            self._session.headers["PRIVATE-TOKEN"] = self._token

    def get_last_commit_date(self, remote_url: str) -> datetime | None:
        """
        Return the most-recent commit date on the default branch of the project,
        or None if anything goes wrong / token is unset.
        """
        if not self._token:
            return None
        path = self._project_path(remote_url)
        if not path:
            return None
        encoded = quote(path, safe="")
        url = f"{self._base}/api/v4/projects/{encoded}/repository/commits"
        try:
            def _call() -> list:
                resp = self._session.get(url, params={"per_page": 1}, timeout=15)
                resp.raise_for_status()
                return resp.json() or []
            commits = with_retry(_call)
            if not commits:
                return None
            raw = commits[0].get("committed_date") or commits[0].get("authored_date")
            if not raw:
                return None
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except Exception as exc:
            logger.warning("GitLab last-commit lookup failed for '%s': %s", path, exc)
            return None

    def _project_path(self, remote_url: str) -> str | None:
        """Extract 'namespace/project' from a remote URL like https://gitlab.com/group/repo[.git]."""
        if not remote_url:
            return None
        try:
            path = urlparse(remote_url).path.strip("/")
        except Exception:
            return None
        if path.endswith(".git"):
            path = path[:-4]
        return path or None
