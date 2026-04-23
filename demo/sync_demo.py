"""
DEMO VERSION: Phase 2 — Jira Sync (simplified).

Creates/updates tickets for demo targets.
Description format:
  - Table 1: Snyk project links | GitLab file links (per file with C/H vulns)
  - Table 2: Repository metadata (only Name, URL, Severity filled; rest = "-")
"""
import logging
from datetime import date

import config

logger = logging.getLogger(__name__)


# ── ADF Helpers ───────────────────────────────────────────────────────────────

def _text(t: str, bold: bool = False) -> dict:
    node: dict = {"type": "text", "text": t}
    if bold:
        node["marks"] = [{"type": "strong"}]
    return node


def _link_text(url: str, label: str) -> dict:
    """Clickable hyperlink text node."""
    return {
        "type": "text",
        "text": label,
        "marks": [{"type": "link", "attrs": {"href": url}}],
    }


def _inline_card(url: str) -> dict:
    """Jira inlineCard — renders as a clickable smart link."""
    return {"type": "inlineCard", "attrs": {"url": url}}


def _cell(nodes: list) -> dict:
    return {
        "type": "tableCell",
        "attrs": {},
        "content": [{"type": "paragraph", "content": nodes}],
    }


def _row(cells: list) -> dict:
    return {"type": "tableRow", "content": cells}


def _table(rows: list) -> dict:
    return {
        "type": "table",
        "attrs": {"isNumberColumnEnabled": False, "layout": "center"},
        "content": rows,
    }


# ── Content Builders ──────────────────────────────────────────────────────────

def _build_summary(display_name: str, critical: int, high: int, today: str) -> str:
    """
    Snyk Vulnerabilities Check Repo Name: smartsense4/clam, Severity[ C0,H5 as on 04/24/26]
    """
    parts = today.split("-")
    mm_dd_yy = f"{parts[1]}/{parts[2]}/{parts[0][2:]}"
    return (
        f"Snyk Vulnerabilities Check Repo Name: {display_name}, "
        f"Severity[ C{critical},H{high} as on {mm_dd_yy}]"
    )


def _snyk_project_url(project_id: str) -> str:
    slug = getattr(config, "SNYK_ORG_SLUG", "") or config.SNYK_ORG_ID
    return f"https://app.snyk.io/org/{slug}/project/{project_id}"


def _gitlab_file_url(remote_url: str, file_name: str) -> str:
    branch = getattr(config, "GITLAB_DEFAULT_BRANCH", "master")
    base = remote_url.rstrip("/")
    last_segment = file_name.split("/")[-1]
    verb = "tree" if "." not in last_segment else "blob"
    return f"{base}/{verb}/{branch}/{file_name}"


def _build_adf_description(
    display_name: str,
    critical: int,
    high: int,
    projects: list,
    remote_url: str,
) -> dict:
    """
    Two-table ADF description:
      Table 1 — one row per file with C/H vulns: Snyk link | GitLab link
      Table 2 — metadata: only Name, Repo URL, Severity filled; rest = "-"
    """
    body = []

    # ── Title ─────────────────────────────────────────────────────────────────
    body.append({
        "type": "paragraph",
        "content": [_text("Snyk Vulnerability:", bold=True)],
    })

    # ── Table 1: Per-file links ───────────────────────────────────────────────
    t1_rows = [
        _row([
            _cell([_text("Snyk vulnerability")]),
            _cell([_text("Gitlab link")]),
        ])
    ]

    for p in projects:
        pid  = getattr(p, "project_id", "") or (p.get("project_id", "") if isinstance(p, dict) else "")
        name = getattr(p, "name", "")        or (p.get("name", "")       if isinstance(p, dict) else "")

        snyk_url   = _snyk_project_url(pid) if pid else ""
        gitlab_url = _gitlab_file_url(remote_url, name) if (remote_url and name) else ""

        # Snyk link: clickable hyperlink showing the full URL
        col1 = [_link_text(snyk_url, snyk_url)] if snyk_url else [_text("-")]
        # GitLab link: inlineCard (renders as smart link badge)
        col2 = [_inline_card(gitlab_url), _text(" ")] if gitlab_url else [_text("-")]

        t1_rows.append(_row([_cell(col1), _cell(col2)]))

    if not projects:
        t1_rows.append(_row([_cell([_text("-")]), _cell([_text("-")])]))

    body.append(_table(t1_rows))

    # ── Table 2: Metadata (only 3 fields filled, rest = "-") ─────────────────
    dash = [_text("-")]

    def meta(label: str, nodes: list) -> dict:
        return _row([_cell([_text(label)]), _cell(nodes)])

    t2_rows = [
        _row([_cell([_text("Field")]), _cell([_text("Description / Example")])]),
        meta("Repository Name",   [_text(display_name)]),
        _row([
            _cell([_text("Repo URL")]),
            _cell([_inline_card(remote_url), _text(" ")] if remote_url else dash),
        ]),
        meta("Last Commit Date",                                    dash),
        meta("Active in Production",                                dash),
        meta("Critical for Enterprise",                             dash),
        meta("Facing Type",                                         dash),
        meta("Service Name",                                        dash),
        meta("Owner / Maintainer",                                  dash),
        meta("Snyk Vulnerabilities (Count) (For all severities)",   dash),
        meta("Severity Breakdown",  [_text(f"Critical: {critical}, High: {high}")]),
        meta("Mitigation Status",                                   dash),
        meta("Notes / Comments",                                    dash),
    ]
    body.append(_table(t2_rows))

    return {"version": 1, "type": "doc", "content": body}


# ── Main sync function ────────────────────────────────────────────────────────

def sync_demo(jira, snyk, state: dict, targets_with_vulns: dict) -> dict:
    """
    Simplified demo sync — forward check only.
    """
    temp_created    = []
    temp_updated    = []
    temp_flagged    = []
    processed_count = 0
    error_count     = 0
    today_str = date.today().isoformat()

    logger.info("=" * 80)
    logger.info("PHASE 2 — Jira Sync (Demo)")
    logger.info("=" * 80)
    logger.info("Forward check: processing %d targets", len(targets_with_vulns))

    for target_id, target_data in targets_with_vulns.items():
        display_name = target_data["display_name"]
        try:
            critical   = target_data["critical"]
            high       = target_data["high"]
            projects   = target_data.get("projects", [])
            remote_url = target_data.get("remote_url", "")
            snyk_url   = target_data.get("snyk_url", "")

            # Idempotency
            if state.get("targets", {}).get(target_id, {}).get("created_today"):
                logger.info("  [%s] Skipping — already created today", display_name[:35])
                processed_count += 1
                continue

            # Search (non-fatal)
            existing = None
            try:
                existing = jira.find_open_ticket_by_name(display_name)
            except Exception as e:
                logger.warning("  [%s] Search failed (%s) — creating new", display_name[:35], type(e).__name__)

            summary     = _build_summary(display_name, critical, high, today_str)
            description = _build_adf_description(display_name, critical, high, projects, remote_url)

            if existing is None:
                # ── CREATE ────────────────────────────────────────────────────
                logger.info("  [%s] No ticket → creating", display_name[:35])
                ticket_key = jira.create_ticket(summary, description)

                state.setdefault("targets", {})[target_id] = {
                    "display_name": display_name,
                    "critical": critical, "high": high,
                    "jira_ticket": ticket_key,
                    "created_today": True,
                    "last_changed": today_str,
                    "last_synced":  today_str,
                }
                temp_created.append({
                    "target_name": display_name,
                    "ticket_key":  ticket_key,
                    "ticket_url":  jira.ticket_url(ticket_key),
                    "snyk_url":    snyk_url,
                    "critical":    critical,
                    "high":        high,
                })

            else:
                # ── UPDATE or NO-CHANGE ───────────────────────────────────────
                ticket_key = existing["key"]
                old_c = state.get("targets", {}).get(target_id, {}).get("critical", 0)
                old_h = state.get("targets", {}).get(target_id, {}).get("high", 0)

                if critical != old_c or high != old_h:
                    logger.info("  [%s] %s — CHANGED C%dH%d→C%dH%d",
                                display_name[:35], ticket_key, old_c, old_h, critical, high)
                    state.setdefault("targets", {})[target_id] = {
                        "display_name": display_name,
                        "critical": critical, "high": high,
                        "jira_ticket": ticket_key,
                        "created_today": False,
                        "last_changed": today_str,
                        "last_synced":  today_str,
                    }
                    temp_updated.append({
                        "target_name":  display_name,
                        "ticket_key":   ticket_key,
                        "ticket_url":   jira.ticket_url(ticket_key),
                        "old_critical": old_c, "old_high": old_h,
                        "new_critical": critical, "new_high": high,
                        "snyk_url":     snyk_url,
                    })
                else:
                    logger.info("  [%s] %s — unchanged C%d H%d",
                                display_name[:35], ticket_key, critical, high)
                    entry = state.setdefault("targets", {}).setdefault(target_id, {})
                    entry.update({
                        "display_name": display_name,
                        "critical": critical, "high": high,
                        "jira_ticket": ticket_key,
                        "created_today": False,
                        "last_synced": today_str,
                    })
                    entry.setdefault("last_changed", today_str)

            processed_count += 1

        except Exception as exc:
            logger.error("  Error processing %s: %s", display_name, exc, exc_info=True)
            error_count += 1

    logger.info("Forward check complete: created=%d updated=%d skipped=%d",
                len(temp_created), len(temp_updated),
                processed_count - len(temp_created) - len(temp_updated))
    logger.info("(Demo: reverse check skipped)")

    return {
        "temp_created":    temp_created,
        "temp_updated":    temp_updated,
        "temp_flagged":    temp_flagged,
        "processed_count": processed_count,
        "error_count":     error_count,
    }