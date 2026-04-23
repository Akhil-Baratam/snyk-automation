"""
Demo script — Snyk → Jira → Teams workflow for specified repos only.

Features:
  - Fetches ONLY the target repos specified in DEMO_TARGET_NAMES
  - State saved locally as demo/demo_state.json (not S3)
  - Can run phases separately: --phase 0, --phase 0-1, --phase 0-2, or all
  - Creates new tickets OR updates existing ones (summary + description only)
  - NO custom fields (demo version)
  - Simple Jira search by repo name in summary
  - Prints Teams card JSON before sending
  - Single Adaptive Card (no splitting)

Usage:
  python demo/demo.py                    # Run all phases
  python demo/demo.py --phase 0          # Only Phase 0 (validation)
  python demo/demo.py --phase 0-1        # Phases 0-1 (validation + collect)
  python demo/demo.py --phase 0-2        # Phases 0-2 (+ sync)
  python demo/demo.py --phase 0-3        # All phases
  python demo/demo.py --phase 2 --load   # Phase 2 only (load state from file)
  python demo/demo.py --phase 3 --load   # Phase 3 only (load state from file)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import date, datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# ── Bootstrap ─────────────────────────────────────────────────────────────────
_DEMO_DIR = Path(__file__).parent
_ROOT = _DEMO_DIR.parent
sys.path.insert(0, str(_ROOT))

from dotenv import load_dotenv  # noqa: E402
load_dotenv(dotenv_path=_DEMO_DIR / ".env.demo", override=True)

# Project imports
import config  # noqa: E402
from clients.snyk import SnykClient  # noqa: E402
from clients.teams import TeamsClient, wrap_adaptive_card  # noqa: E402
from models.target import SnykTarget  # noqa: E402

# Demo-specific imports (no custom fields)
from jira_demo import JiraClientDemo as JiraClient  # noqa: E402
from sync_demo import sync_demo  # noqa: E402
from notify_demo import notify_demo  # noqa: E402

# ── Constants ─────────────────────────────────────────────────────────────────
_DEMO_DIR = Path(__file__).parent
_STATE_FILE = _DEMO_DIR / "demo_state.json"

IST = timezone(timedelta(hours=5, minutes=30))
_LOG_FMT = "%(asctime)s IST [%(levelname)-5s] %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


class _ISTFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=IST)
        return dt.strftime(datefmt or _DATE_FMT)


def _setup_logger(debug: bool = False) -> None:
    log_file = _DEMO_DIR / "demo.log"
    level = logging.DEBUG if debug else logging.INFO
    fmt = _ISTFormatter(_LOG_FMT)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(fmt)
    console_handler.setLevel(level)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(file_handler)
    root.addHandler(console_handler)


logger = logging.getLogger(__name__)

# ── Demo config ───────────────────────────────────────────────────────────────
_DEMO_TARGET_NAMES: list[str] = [
    n.strip()
    for n in os.environ.get("DEMO_TARGET_NAMES", "").split(",")
    if n.strip()
]


# ── State File Management ─────────────────────────────────────────────────────

class DemoState:
    """Local state file management (JSON)."""
    
    def __init__(self, path: Path = _STATE_FILE):
        self.path = path
        self.data: dict = self._load()
    
    def _load(self) -> dict:
        """Load state from file, or return empty structure."""
        if self.path.exists():
            try:
                with open(self.path, "r") as f:
                    data = json.load(f)
                logger.info("Loaded state from %s", self.path.name)
                return data
            except Exception as e:
                logger.warning("Failed to load state: %s. Starting fresh.", e)
                return self._empty_state()
        else:
            logger.info("No state file found. Starting fresh.")
            return self._empty_state()
    
    def _empty_state(self) -> dict:
        """Return empty state structure."""
        return {
            "last_run": None,
            "targets": {},
            "new_tickets": [],
            "updated_tickets": [],
        }
    
    def save(self) -> None:
        """Save state to file."""
        self.data["last_run"] = datetime.now(tz=IST).isoformat()
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=2)
        logger.info("State saved to %s", self.path.name)
    
    def get_targets(self) -> dict:
        """Get targets dict from state."""
        return self.data.get("targets", {})
    
    def set_targets(self, targets: dict) -> None:
        """Set targets dict in state."""
        self.data["targets"] = targets
    
    def add_new_ticket(self, name: str, key: str, url: str) -> None:
        """Add ticket to new_tickets list."""
        if "new_tickets" not in self.data:
            self.data["new_tickets"] = []
        self.data["new_tickets"].append({
            "display_name": name,
            "ticket_key": key,
            "ticket_url": url,
        })
    
    def add_updated_ticket(self, name: str, key: str, url: str) -> None:
        """Add ticket to updated_tickets list."""
        if "updated_tickets" not in self.data:
            self.data["updated_tickets"] = []
        self.data["updated_tickets"].append({
            "display_name": name,
            "ticket_key": key,
            "ticket_url": url,
        })
    
    def get_new_tickets(self) -> list[tuple[str, str, str]]:
        """Return new_tickets as list of tuples."""
        return [
            (t["display_name"], t["ticket_key"], t["ticket_url"])
            for t in self.data.get("new_tickets", [])
        ]
    
    def get_updated_tickets(self) -> list[tuple[str, str, str]]:
        """Return updated_tickets as list of tuples."""
        return [
            (t["display_name"], t["ticket_key"], t["ticket_url"])
            for t in self.data.get("updated_tickets", [])
        ]
    
    def clear_ticket_lists(self) -> None:
        """Clear new_tickets and updated_tickets for fresh run."""
        self.data["new_tickets"] = []
        self.data["updated_tickets"] = []


# ── URL helpers ───────────────────────────────────────────────────────────────

def _snyk_project_url(project_id: str) -> str:
    slug = config.SNYK_ORG_SLUG
    if slug:
        return f"https://app.snyk.io/org/{slug}/project/{project_id}"
    return f"https://app.snyk.io/org/{config.SNYK_ORG_ID}/project/{project_id}"


def _gitlab_file_url(remote_url: str, file_path: str) -> str:
    base = remote_url.rstrip("/")
    branch = config.GITLAB_DEFAULT_BRANCH
    return f"{base}/blob/{branch}/{file_path}"


# ── Jira ticket content builders ──────────────────────────────────────────────

def _build_summary(display_name: str, critical: int, high: int, today: str) -> str:
    parts = today.split("-")
    mm_dd_yy = f"{parts[1]}/{parts[2]}/{parts[0][2:]}"
    return (
        f"Snyk Vulnerabilities Check Repo Name:{display_name}"
        f" [ C{critical} H{high} as on {mm_dd_yy}]"
    )


def _text(t: str, bold: bool = False) -> dict:
    node: dict = {"type": "text", "text": t}
    if bold:
        node["marks"] = [{"type": "strong"}]
    return node


def _link_node(label: str, url: str) -> dict:
    return {
        "type": "text",
        "text": label,
        "marks": [{"type": "link", "attrs": {"href": url}}],
    }


def _cell(nodes: list[dict], is_header: bool = False) -> dict:
    cell_type = "tableHeader" if is_header else "tableCell"
    return {
        "type": cell_type,
        "attrs": {},
        "content": [{"type": "paragraph", "content": nodes}],
    }


def _row(cells: list[dict]) -> dict:
    return {"type": "tableRow", "content": cells}


def _table(rows: list[dict]) -> dict:
    return {
        "type": "table",
        "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
        "content": rows,
    }


def _build_adf_description(target: SnykTarget) -> dict:
    content: list[dict] = []

    header_row_1 = _row([
        _cell([_text("Snyk vulnerability", bold=True)], is_header=True),
        _cell([_text("Gitlab link",        bold=True)], is_header=True),
        _cell([_text("Severity Breakdown", bold=True)], is_header=True),
    ])

    file_rows: list[dict] = []
    for p in target.projects:
        snyk_url   = _snyk_project_url(p.project_id)
        gitlab_url = _gitlab_file_url(target.remote_url, p.name) if target.remote_url else ""
        severity   = f"C{p.critical} H{p.high} M{p.medium} L{p.low}"

        file_rows.append(_row([
            _cell([_link_node(snyk_url, snyk_url)] if snyk_url else [_text("—")]),
            _cell([_link_node(gitlab_url, gitlab_url)] if gitlab_url else [_text("—")]),
            _cell([_text(severity)]),
        ]))

    if not file_rows:
        file_rows = [_row([
            _cell([_text("No C/H vulnerability data available")]),
            _cell([_text("—")]),
            _cell([_text("—")]),
        ])]

    content.append({
        "type": "paragraph",
        "content": [_text("Snyk Vulnerability:", bold=True)],
    })
    content.append(_table([header_row_1, *file_rows]))

    repo_url_nodes = (
        [_link_node(target.remote_url, target.remote_url)]
        if target.remote_url else [_text("—")]
    )
    total_projects = len(target.projects)

    kv_rows: list[tuple[str, list[dict]]] = [
        ("Repository Name",   [_text(target.display_name)]),
        ("Repo URL",          repo_url_nodes),
        ("Last Commit Date",  [_text("-")]),
        ("Active in Production", [_text("")]),
        ("Critical for Enterprise", [_text("-")]),
        ("Facing Type",       [_text("")]),
        ("Service Name",      [_text("")]),
        ("Owner / Maintainer", [_text("")]),
        ("Snyk Vulnerabilities (Count) (For all severities)", [_text(str(total_projects))]),
        ("Severity Breakdown", [_text(f"Critical:{target.critical}, High:{target.high}")]),
        ("Mitigation Status", [_text("-")]),
        ("Notes / Comments",  [_text("")]),
    ]

    kv_table_rows = [
        _row([
            _cell([_text("Field",                bold=True)], is_header=True),
            _cell([_text("Description / Example", bold=True)], is_header=True),
        ])
    ] + [
        _row([
            _cell([_text(field, bold=True)]),
            _cell(value_nodes),
        ])
        for field, value_nodes in kv_rows
    ]

    content.append(_table(kv_table_rows))

    return {"type": "doc", "version": 1, "content": content}


# ── Teams card builders ───────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now(tz=IST).strftime("%Y-%m-%d %H:%M:%S IST")


def _build_demo_card(
    new_tickets: list[tuple[str, str, str]],
    updated_tickets: list[tuple[str, str, str]],
    repo_count: int,
) -> dict:
    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": f"Demo Run - {repo_count} Repos Checked",
            "weight": "Bolder",
            "size": "Large",
        },
        {
            "type": "TextBlock",
            "text": _ts(),
            "isSubtle": True,
            "spacing": "None",
        },
    ]

    # New tickets table
    if new_tickets:
        body.append({
            "type": "TextBlock",
            "text": f"Tickets Created ({len(new_tickets)})",
            "weight": "Bolder",
            "spacing": "Medium",
        })
        rows = [{"type": "TableRow", "cells": [
            {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Repository", "weight": "Bolder"}]},
            {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Ticket", "weight": "Bolder"}]},
        ]}]
        for name, key, url in new_tickets:
            rows.append({"type": "TableRow", "cells": [
                {"type": "TableCell", "items": [{"type": "TextBlock", "text": name, "wrap": True}]},
                {"type": "TableCell", "items": [{"type": "TextBlock", "text": f"[{key}]({url})", "wrap": True}]},
            ]})
        body.append({
            "type": "Table",
            "columns": [{"width": 2}, {"width": 1}],
            "rows": rows,
            "spacing": "Small",
        })

    # Updated tickets table
    if updated_tickets:
        body.append({
            "type": "TextBlock",
            "text": f"Tickets Updated ({len(updated_tickets)})",
            "weight": "Bolder",
            "spacing": "Medium",
        })
        rows = [{"type": "TableRow", "cells": [
            {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Repository", "weight": "Bolder"}]},
            {"type": "TableCell", "items": [{"type": "TextBlock", "text": "Ticket", "weight": "Bolder"}]},
        ]}]
        for name, key, url in updated_tickets:
            rows.append({"type": "TableRow", "cells": [
                {"type": "TableCell", "items": [{"type": "TextBlock", "text": name, "wrap": True}]},
                {"type": "TableCell", "items": [{"type": "TextBlock", "text": f"[{key}]({url})", "wrap": True}]},
            ]})
        body.append({
            "type": "Table",
            "columns": [{"width": 2}, {"width": 1}],
            "rows": rows,
            "spacing": "Small",
        })

    if not new_tickets and not updated_tickets:
        body.append({
            "type": "TextBlock",
            "text": "No tickets created or updated.",
            "isSubtle": True,
            "spacing": "Medium",
        })

    # Footer
    body.append({
        "type": "TextBlock",
        "text": "— Snyk Automation Demo",
        "isSubtle": True,
        "spacing": "Medium",
        "horizontalAlignment": "Right",
    })

    return wrap_adaptive_card(body)


# ── Phases ────────────────────────────────────────────────────────────────────

def _phase0_validate(snyk: SnykClient, jira: JiraClient, teams: TeamsClient) -> None:
    logger.info("=" * 80)
    logger.info("PHASE 0 — Validation")
    logger.info("=" * 80)

    checks = [
        ("Snyk token + org",    snyk.check_org_reachability),
        ("Jira reachability",   jira.check_reachability),
        # ("Teams webhook",       teams.check_reachability),
    ]

    for label, fn in checks:
        try:
            fn()
            logger.info("  ✓ %s: OK", label)
        except Exception as exc:
            msg = f"{label} check failed: {exc}"
            logger.error("  ✗ %s", msg)
            raise RuntimeError(msg) from exc

    logger.info("Phase 0 — all checks passed\n")


def _phase1_collect(snyk: SnykClient, state: DemoState) -> list[SnykTarget]:
    logger.info("=" * 80)
    logger.info("PHASE 1 — Collecting Snyk Data")
    logger.info("=" * 80)

    if not _DEMO_TARGET_NAMES:
        logger.warning("No demo targets specified. Set DEMO_TARGET_NAMES in .env.demo")
        return []

    # ── Step 1: Fetch all targets to find demo target IDs by name ────────────
    logger.info("Fetching all targets to find demo repos...")
    raw_targets = snyk.fetch_all_targets()
    target_lookup = snyk.build_target_lookup(raw_targets)  # { target_id: {display_name, remote_url} }

    logger.info("Target lookup built: %d entries", len(target_lookup))
    for tid, info in list(target_lookup.items())[:5]:  # first 5 only
        logger.info("  %s → '%s'", tid[:8], info["display_name"])

    # Build name → target_id map (case-insensitive)
    name_to_id: dict[str, str] = {
        info["display_name"].lower(): tid
        for tid, info in target_lookup.items()
        if info.get("display_name")
    }

    # Match demo names to target IDs
    demo_targets: dict[str, str] = {}  # { target_id: display_name }
    for name in _DEMO_TARGET_NAMES:
        tid = name_to_id.get(name.lower())
        if tid:
            display = target_lookup[tid]["display_name"]
            demo_targets[tid] = display
            logger.info("  ✓ Matched: '%s' → target %s", display, tid)
        else:
            logger.warning("  ⚠ Not found in Snyk targets: '%s'", name)
            # Show similar names to help debug
            similar = [n for n in name_to_id if name.split("/")[-1].lower() in n]
            if similar:
                logger.warning("    Similar names found: %s", similar[:5])

    if not demo_targets:
        logger.error("None of the demo targets were found in Snyk. Check DEMO_TARGET_NAMES.")
        return []

    # ── Step 2: Fetch projects only for demo target IDs ──────────────────────
    logger.info("Fetching projects for %d demo target(s)...", len(demo_targets))
    all_projects: list[dict] = []
    for tid in demo_targets:
        projects = snyk.fetch_projects_for_target(tid)
        logger.info("  Target %s: %d projects", tid[:8], len(projects))
        all_projects.extend(projects)
    logger.info("Total: %d projects across %d demo targets", len(all_projects), len(demo_targets))

    # ── Step 3: Fetch issue counts only for demo projects ────────────────────
    logger.info("Fetching issue counts for demo projects...")
    target_map = snyk.build_target_map(all_projects)
    logger.info("target_map keys: %s", list(target_map.keys()))
    for tid, data in target_map.items():
        logger.info("  %s → C%d H%d (%d projects)", tid[:8], data["critical"], data["high"], len(data["projects"]))

    # ── Step 4: Build SnykTarget objects ─────────────────────────────────────
    targets: list[SnykTarget] = []
    for tid, display_name in demo_targets.items():
        data = target_map.get(tid, {"critical": 0, "high": 0, "projects": []})
        remote_url = target_lookup.get(tid, {}).get("remote_url", "")
        t = SnykTarget(
            id           = tid,
            display_name = display_name,
            critical     = data["critical"],
            high         = data["high"],
            remote_url   = remote_url,
            projects     = data["projects"],
        )
        targets.append(t)
        logger.info("  ✓ %s — C%d H%d", display_name, t.critical, t.high)

    logger.info("Phase 1 — collected %d target(s)\n", len(targets))

    # Save targets to state
    state.set_targets({
        t.id: {
            "display_name": t.display_name,
            "critical":     t.critical,
            "high":         t.high,
        }
        for t in targets
    })

    return targets


def _phase2_sync(
    targets: list[SnykTarget],
    jira: JiraClient,
    snyk,
    state: DemoState,
    today: str,
) -> dict:
    """
    Simplified Phase 2 — uses sync_demo module.
    
    Returns sync result dict with temp_created, temp_updated, temp_flagged.
    """
    # Convert targets list to the format expected by sync_demo
    targets_dict = {
        target.id: {
            "display_name": target.display_name,
            "critical":     target.critical,
            "high":         target.high,
            "projects":     target.projects,   # list of ProjectDetail (only C/H > 0 files)
            "remote_url":   target.remote_url, # GitLab repo URL
            "snyk_url":     f"https://app.snyk.io/org/{config.SNYK_ORG_ID}/target/{target.id}",
        }
        for target in targets
    }
    
    # Call demo sync function
    result = sync_demo(jira, snyk, state.data, targets_dict)
    
    # Save state back
    state.save()
    
    return result


def _phase3_notify(teams: TeamsClient, sync_result: dict) -> None:
    """
    Simplified Phase 3 — uses notify_demo module.
    
    sync_result is the dict returned from _phase2_sync.
    """
    notify_demo(teams, sync_result)


# ── CLI Argument Parser ───────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demo script with phase-by-phase execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo.py                    # Run all phases (0-3)
  python demo.py --phase 0          # Only Phase 0 (validation)
  python demo.py --phase 0-1        # Phases 0-1 (validation + collect)
  python demo.py --phase 0-2        # Phases 0-2 (+ sync)
  python demo.py --phase 2 --load   # Phase 2 only (load state from file)
  python demo.py --phase 3 --load   # Phase 3 only (load state from file)
        """
    )
    parser.add_argument(
        "--phase",
        type=str,
        default="0-3",
        help="Phase range to execute (e.g., '0', '0-1', '0-2', '0-3'). Default: 0-3"
    )
    parser.add_argument(
        "--load",
        action="store_true",
        help="Load state from file (for running Phase 2 or 3 independently)"
    )
    return parser.parse_args()


def _parse_phase_range(phase_str: str) -> tuple[int, int]:
    """Parse phase range like '0', '0-1', '0-3' into (start, end)."""
    try:
        if "-" in phase_str:
            parts = phase_str.split("-")
            start, end = int(parts[0]), int(parts[1])
        else:
            start = end = int(phase_str)
        
        if not (0 <= start <= end <= 3):
            raise ValueError("Phases must be 0-3")
        
        return start, end
    except Exception as e:
        raise ValueError(f"Invalid phase range '{phase_str}': {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = _parse_args()
    
    try:
        start_phase, end_phase = _parse_phase_range(args.phase)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    _setup_logger(debug=config.DEBUG_LOGGING)
    today = date.today().strftime("%Y-%m-%d")

    logger.info("")
    logger.info("╔" + "=" * 78 + "╗")
    logger.info("║ Snyk Automation — DEMO (Phase %d-%d) — %s", start_phase, end_phase, today)
    logger.info("║ Demo targets: %s", _DEMO_TARGET_NAMES or "(none configured)")
    logger.info("╚" + "=" * 78 + "╝")
    logger.info("")

    snyk = SnykClient()
    jira = JiraClient()
    teams = TeamsClient()
    state = DemoState()

    try:
        # Phase 0: Validation
        if start_phase <= 0 <= end_phase:
            _phase0_validate(snyk, jira, teams)

        # Phase 1: Collect data
        targets: list[SnykTarget] = []
        if start_phase <= 1 <= end_phase:
            targets = _phase1_collect(snyk, state)
        elif args.load:
            # Load targets from state file
            logger.info("Loading targets from state file...")
            state_targets = state.get_targets()
            if not state_targets:
                logger.error("No targets in state file. Run Phase 1 first.")
                return 1
            # Reconstruct target objects (limited info from state)
            logger.info("  Loaded %d target(s) from state", len(state_targets))

        # Phase 2: Sync with Jira
        if start_phase <= 2 <= end_phase:
            if not targets and not args.load:
                logger.error("No targets available. Run Phase 1 first or use --load")
                return 1
            sync_result = _phase2_sync(targets, jira, snyk, state, today)
            state.save()

        # Phase 3: Send Teams notification
        if start_phase <= 3 <= end_phase:
            if 'sync_result' not in locals():
                logger.error("No sync result. Run Phase 2 first or load state")
                return 1
            _phase3_notify(teams, sync_result)
            state.save()

        logger.info("╔" + "=" * 78 + "╗")
        logger.info("║ Demo run complete (Phases %d-%d)", start_phase, end_phase)
        logger.info("╚" + "=" * 78 + "╝")
        logger.info("")

        return 0

    except RuntimeError as exc:
        logger.critical("Fatal error: %s", exc)
        return 1
    except Exception as exc:
        logger.critical("Unexpected error: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())