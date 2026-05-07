"""
Migrate existing Jira ticket summaries to the new format with UUID token.

For each ticket:
  1. GET the ticket -> read current summary
  2. Parse repo name + C/H counts + date out of the existing summary
  3. Look up the UUID token in logs/targets_mapping.tsv
  4. PUT the new summary (description untouched)

The new format:
  Snyk Vulnerabilities Check Repo Name:{name} [snyk:{token}] [ C{c} H{h} as on {date}]

Tickets already containing `[snyk:<token>]` are skipped.

Run `python dump_targets.py` first to generate the mapping file.

Usage:
  python migrate_summaries.py PSUP-5489 PSUP-5490 PSUP-5491
  python migrate_summaries.py PSUP-5489 --dry-run
  python migrate_summaries.py --from-file keys.txt --dry-run
"""
import argparse
import re
import sys
from datetime import date
from pathlib import Path

import config  # noqa: F401  -- triggers env-var validation
from clients.jira import JiraClient
from utils.logger import setup_logger

_MAPPING_FILE = Path(__file__).parent / "logs" / "targets_mapping.tsv"

# Tolerant of older formats:
#   Repo Name: foo, Severity[ C0,H5 as on 04/24/26]
#   Repo Name:foo [ C0 H5 as on 04/24/26]
_NAME_RE   = re.compile(r"Repo\s*Name:\s*([^\s\[,]+)", re.IGNORECASE)
_COUNTS_RE = re.compile(r"C(\d+)[\s,]*H(\d+)",          re.IGNORECASE)
_DATE_RE   = re.compile(r"as\s*(?:on|of)\s*(\d{1,2}/\d{1,2}/\d{2,4})", re.IGNORECASE)


def _load_mapping() -> dict[str, tuple[str, str]]:
    """Return {repo_name_lower: (uuid, token)}."""
    if not _MAPPING_FILE.exists():
        sys.exit(f"Mapping not found at {_MAPPING_FILE}. "
                 f"Run 'python dump_targets.py' first.")
    out: dict[str, tuple[str, str]] = {}
    with _MAPPING_FILE.open(encoding="utf-8") as f:
        next(f, None)  # header
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 3:
                continue
            name, uuid, token = parts
            out[name.lower()] = (uuid, token)
    return out


def _parse_summary(summary: str):
    n = _NAME_RE.search(summary)
    c = _COUNTS_RE.search(summary)
    d = _DATE_RE.search(summary)
    return (
        n.group(1) if n else None,
        int(c.group(1)) if c else None,
        int(c.group(2)) if c else None,
        d.group(1) if d else None,
    )


def _build_new(name: str, token: str, c: int, h: int, date_str: str) -> str:
    return (
        f"Snyk Vulnerabilities Check Repo Name:{name} "
        f"[snyk:{token}] "
        f"[ C{c} H{h} as on {date_str}]"
    )


def _process(key: str, jira: JiraClient, mapping: dict, dry_run: bool) -> bool:
    """Return True on a successful update."""
    try:
        data = jira._get(f"/rest/api/3/issue/{key}?fields=summary")
    except Exception as exc:
        print(f"[FAIL] {key}: GET failed ({exc})")
        return False

    summary = (data.get("fields") or {}).get("summary") or ""
    if not summary:
        print(f"[FAIL] {key}: empty summary")
        return False

    name, c, h, date_str = _parse_summary(summary)
    if not name:
        print(f"[FAIL] {key}: could not extract repo name -- '{summary}'")
        return False

    entry = mapping.get(name.lower())
    if not entry:
        print(f"[FAIL] {key}: repo '{name}' not in mapping")
        return False

    _uuid, token = entry

    if f"snyk:{token}" in summary:
        print(f"[SKIP] {key}: already migrated (token present)")
        return False

    c = c if c is not None else 0
    h = h if h is not None else 0
    if not date_str:
        date_str = date.today().strftime("%m/%d/%y")

    new_summary = _build_new(name, token, c, h, date_str)

    print(f"\n{key}")
    print(f"  Repo:   {name}  (token: {token})")
    print(f"  Before: {summary}")
    print(f"  After:  {new_summary}")

    if dry_run:
        print(f"  -> dry-run, not updated")
        return False

    try:
        jira._put(f"/rest/api/3/issue/{key}", {"fields": {"summary": new_summary}})
        print(f"  -> updated")
        return True
    except Exception as exc:
        print(f"  [FAIL] update failed: {exc}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migrate ticket summaries to the new format with UUID token.",
    )
    parser.add_argument("keys", nargs="*", help="Ticket keys, e.g. PSUP-5489 PSUP-5490")
    parser.add_argument("--from-file", help="File of ticket keys, one per line")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show planned changes without writing to Jira")
    args = parser.parse_args()

    keys = list(args.keys)
    if args.from_file:
        keys += [
            line.strip()
            for line in Path(args.from_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
    if not keys:
        parser.print_help()
        return 1

    setup_logger(debug=config.DEBUG_LOGGING)
    mapping = _load_mapping()
    jira    = JiraClient()

    print(f"Loaded {len(mapping)} repo mappings")
    print(f"Processing {len(keys)} ticket(s){' -- DRY RUN' if args.dry_run else ''}")

    updated = 0
    for key in keys:
        if _process(key.strip(), jira, mapping, args.dry_run):
            updated += 1

    print(f"\nDone. Updated {updated}/{len(keys)} ticket(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
