"""
Phase 3 -- Reverse check (Jira -> Snyk).

For every open ticket bearing the snyk label, map it back to a Snyk target via
the [snyk:<token>] embedded in the summary and bucket it:

  - token maps to a target that has C/H > 0   -> forward check handled it, skip
  - token maps to a target with C+H == 0      -> flag "Targets with 0 vulns"
  - token maps to no known target             -> flag "Target removed from Snyk"
  - summary has no token (pre-migration)      -> log WARN, skip

Read-only: no Jira writes. Safe to run in dry-run mode.
"""
import logging
import re

from clients.jira import JiraClient
from models.run_result import FlaggedTicket, RunResult
from models.target import SnykTarget

logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"\[snyk:([0-9a-f]{12})\]", re.IGNORECASE)
_NAME_RE  = re.compile(r"Repo\s*Name:\s*([^\s\[,]+)", re.IGNORECASE)

_REASON_RESOLVED = "Targets with 0 vulns"
_REASON_DELETED  = "Target removed from Snyk"


def _uuid_token(target_id: str) -> str:
    return target_id.replace("-", "")[:12]


def _extract_name(summary: str) -> str:
    m = _NAME_RE.search(summary)
    return m.group(1) if m else "(unknown)"


def run_reverse_check(
    targets: list[SnykTarget],
    all_target_ids: set[str],
    result: RunResult,
    dry_run: bool = False,
) -> None:
    jira = JiraClient()
    logger.info("Phase 3 -- Reverse check%s", " [DRY RUN]" if dry_run else "")

    token_to_id = {_uuid_token(tid): tid for tid in all_target_ids}
    vuln_ids    = {t.id for t in targets}

    if len(token_to_id) != len(all_target_ids):
        logger.warning(
            "Token collision detected -- %d unique tokens for %d target IDs",
            len(token_to_id), len(all_target_ids),
        )

    open_tickets = jira.list_open_snyk_tickets()
    missing_token: list[str] = []

    for key, summary in open_tickets:
        m = _TOKEN_RE.search(summary)
        if not m:
            missing_token.append(key)
            continue

        token = m.group(1).lower()
        tid = token_to_id.get(token)
        name = _extract_name(summary)

        if tid is None:
            reason = _REASON_DELETED
        elif tid not in vuln_ids:
            reason = _REASON_RESOLVED
        else:
            continue   # forward check handled it

        result.flagged.append(FlaggedTicket(
            target_name=name,
            ticket_key=key,
            ticket_url=jira.ticket_url(key),
            reason=reason,
        ))
        logger.info("[%s] %s -- FLAGGED: %s", name, key, reason)

    if missing_token:
        logger.warning(
            "%d open ticket(s) missing [snyk:<token>] -- skipped: %s",
            len(missing_token),
            ", ".join(missing_token[:10]) + (" ..." if len(missing_token) > 10 else ""),
        )

    resolved = sum(1 for f in result.flagged if f.reason == _REASON_RESOLVED)
    deleted  = sum(1 for f in result.flagged if f.reason == _REASON_DELETED)
    logger.info(
        "Phase 3 done -- flagged=%d (resolved=%d, deleted=%d), skipped_no_token=%d",
        len(result.flagged), resolved, deleted, len(missing_token),
    )
