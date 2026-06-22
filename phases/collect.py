"""
Phase 1 -- Snyk data collection.

Fresh-fetch by default. Always writes the result to logs/phase1_cache.json so
later invocations can opt into reuse via `--use-cache`.

Pass `use_cache=True` to:
  - Load the previous fresh fetch from disk (no Snyk calls, no TTL check)
  - Fall back to a fresh fetch if the cache is missing or unreadable
"""
import json
import logging
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from clients.snyk import SnykClient
from models.target import ProjectDetail, SnykTarget

logger = logging.getLogger(__name__)

_LOGS_DIR     = Path(__file__).parent.parent / "logs"
_SUMMARY_FILE = _LOGS_DIR / "phase1_summary.txt"
_CACHE_FILE   = _LOGS_DIR / "phase1_cache.json"

_CACHE_SCHEMA_VERSION = 1
IST = timezone(timedelta(hours=5, minutes=30))


def run_collect(use_cache: bool = False) -> tuple[list[SnykTarget], set[str]]:
    """
    Fetch all targets, aggregate per-target C/H counts, log a summary,
    and write the summary to logs/phase1_summary.txt.

    Behaviour:
      use_cache=False (default) -- fresh Snyk fetch, write cache
      use_cache=True            -- load logs/phase1_cache.json if usable;
                                   on miss/corruption, fall back to fresh fetch

    Returns:
        (targets_with_vulns, all_target_ids)
        all_target_ids is the unfiltered full set -- needed by Phase 3's
        reverse check to distinguish "clean repo" from "deleted target".
    """
    if use_cache:
        cached = _load_cache()
        if cached is not None:
            targets, all_target_ids = cached
            _emit_summary(targets, all_target_ids)
            return targets, all_target_ids
        logger.info("Phase 1 -- cache unusable, falling back to fresh fetch")

    logger.info("Phase 1 -- Snyk data collection")
    targets, all_target_ids = SnykClient().get_aggregated_targets()
    _save_cache(targets, all_target_ids)
    _emit_summary(targets, all_target_ids)
    return targets, all_target_ids


# ── Cache I/O ────────────────────────────────────────────────────────────────

def _save_cache(targets: list[SnykTarget], all_target_ids: set[str]) -> None:
    """Always called after a fresh fetch. Overwrites any prior cache."""
    payload = {
        "schema_version": _CACHE_SCHEMA_VERSION,
        "timestamp_ist":  datetime.now(tz=IST).isoformat(),
        "all_target_ids": sorted(all_target_ids),
        "targets":        [asdict(t) for t in targets],
    }
    _LOGS_DIR.mkdir(exist_ok=True)
    _CACHE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("Phase 1 cache written to %s (%d target(s))",
                _CACHE_FILE, len(targets))


def _load_cache() -> tuple[list[SnykTarget], set[str]] | None:
    """Return (targets, all_target_ids) or None on any failure."""
    if not _CACHE_FILE.exists():
        logger.info("Phase 1 -- no cache at %s", _CACHE_FILE)
        return None
    try:
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Phase 1 cache unreadable: %s", exc)
        return None

    if data.get("schema_version") != _CACHE_SCHEMA_VERSION:
        logger.warning("Phase 1 cache schema mismatch (got %r, want %d)",
                       data.get("schema_version"), _CACHE_SCHEMA_VERSION)
        return None

    try:
        targets = [_target_from_dict(t) for t in data.get("targets", [])]
        all_target_ids = set(data.get("all_target_ids", []))
    except (KeyError, TypeError) as exc:
        logger.warning("Phase 1 cache structure invalid: %s", exc)
        return None

    if not all_target_ids:
        logger.warning("Phase 1 cache has empty all_target_ids -- ignoring")
        return None

    ts_raw = data.get("timestamp_ist", "")
    age_label = _age_label(ts_raw)
    logger.info(
        "Phase 1 cache HIT -- %d target(s) with vulns, %d total target IDs (%s) -- skipping Snyk fetch",
        len(targets), len(all_target_ids), age_label,
    )
    return targets, all_target_ids


def _target_from_dict(d: dict) -> SnykTarget:
    return SnykTarget(
        id           = d["id"],
        display_name = d["display_name"],
        critical     = int(d.get("critical", 0)),
        high         = int(d.get("high", 0)),
        medium       = int(d.get("medium", 0)),
        low          = int(d.get("low", 0)),
        remote_url   = d.get("remote_url", "") or "",
        projects     = [_project_from_dict(p) for p in d.get("projects", []) or []],
    )


def _project_from_dict(d: dict) -> ProjectDetail:
    return ProjectDetail(
        name       = d["name"],
        project_id = d["project_id"],
        critical   = int(d.get("critical", 0)),
        high       = int(d.get("high", 0)),
        medium     = int(d.get("medium", 0)),
        low        = int(d.get("low", 0)),
    )


def _age_label(ts_raw: str) -> str:
    try:
        ts = datetime.fromisoformat(ts_raw)
    except ValueError:
        return "age unknown"
    age = datetime.now(tz=IST) - ts
    mins = int(age.total_seconds() // 60)
    if mins < 60:
        return f"{mins}m old"
    return f"{mins // 60}h{mins % 60:02d}m old"


# ── Summary ──────────────────────────────────────────────────────────────────

def _emit_summary(targets: list[SnykTarget], all_target_ids: set[str]) -> None:
    ranked = sorted(
        targets,
        key=lambda t: (-t.critical, -t.high, t.display_name.lower()),
    )
    lines = [f"{t.display_name} - C{t.critical}H{t.high}" for t in ranked]

    logger.info("=" * 78)
    logger.info("Phase 1 Summary -- Targets with C/H vulnerabilities")
    logger.info("=" * 78)
    if lines:
        for line in lines:
            logger.info("  %s", line)
    else:
        logger.info("(no targets with critical or high vulnerabilities)")
    logger.info("=" * 78)
    logger.info(
        "Total: %d/%d target(s) have C/H vulnerabilities",
        len(targets), len(all_target_ids),
    )

    _SUMMARY_FILE.parent.mkdir(exist_ok=True)
    _SUMMARY_FILE.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    logger.info("Phase 1 summary written to %s", _SUMMARY_FILE)
