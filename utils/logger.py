"""
Logger setup — file handler (logs/YYYY-MM-DD.log) + console handler, timestamps in IST.
"""
import logging
import sys
from datetime import date, datetime, timezone, timedelta
from pathlib import Path

IST = timezone(timedelta(hours=5, minutes=30))

_LOG_DIR = Path(__file__).parent.parent / "logs"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"
_LOG_FMT = "%(asctime)s IST [%(levelname)-5s] %(message)s"


class _ISTFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        dt = datetime.fromtimestamp(record.created, tz=IST)
        return dt.strftime(datefmt or _DATE_FMT)


def setup_logger(debug: bool = False) -> logging.Logger:
    _LOG_DIR.mkdir(exist_ok=True)
    log_file = _LOG_DIR / f"{date.today().strftime('%Y-%m-%d')}.log"

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
    if not root.handlers:
        root.addHandler(file_handler)
        root.addHandler(console_handler)

    return logging.getLogger("snyk_automation")
