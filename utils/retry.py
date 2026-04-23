"""
Exponential backoff retry logic for all external API calls.

Two usage patterns:
  1. Direct call:   with_retry(lambda: session.get(url))
  2. Decorator:     @retry()  or  @retry(max_attempts=5)
"""
import functools
import logging
import time
from typing import Any, Callable, TypeVar

import requests

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def with_retry(
    func: Callable,
    *args: Any,
    max_attempts: int | None = None,
    base_delay: int | None = None,
    **kwargs: Any,
) -> Any:
    """
    Call func(*args, **kwargs) with exponential backoff on transient errors.

    Retried errors:
      - HTTP 429 (rate limit) — honours Retry-After header
      - HTTP 5xx (server error)
      - requests.ConnectionError / Timeout

    Not retried:
      - HTTP 4xx (except 429) — caller must handle these
    """
    import config  # late import avoids circular-import at module load

    _max = max_attempts if max_attempts is not None else config.MAX_RETRY_ATTEMPTS
    _base = base_delay if base_delay is not None else config.RETRY_BASE_DELAY_SECONDS

    last_exc: Exception | None = None
    for attempt in range(_max):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.HTTPError as exc:
            last_exc = exc
            status = exc.response.status_code if exc.response is not None else None
            if status == 429:
                wait = int(exc.response.headers.get("Retry-After", _base * (2 ** attempt)))
                logger.warning(
                    "Rate limited (429). Waiting %ds before retry %d/%d.", wait, attempt + 1, _max
                )
                time.sleep(wait)
            elif status is not None and status >= 500:
                wait = _base * (2 ** attempt)
                logger.warning(
                    "Server error %d. Waiting %ds before retry %d/%d.", status, wait, attempt + 1, _max
                )
                time.sleep(wait)
            else:
                raise
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            last_exc = exc
            wait = _base * (2 ** attempt)
            logger.warning(
                "Connection error (%s). Waiting %ds before retry %d/%d.", exc, wait, attempt + 1, _max
            )
            time.sleep(wait)

    func_name = getattr(func, "__name__", repr(func))
    raise RuntimeError(
        f"All {_max} retry attempts exhausted for '{func_name}'"
    ) from last_exc


def retry(max_attempts: int | None = None, base_delay: int | None = None) -> Callable[[F], F]:
    """Decorator form of with_retry."""
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return with_retry(func, *args, max_attempts=max_attempts, base_delay=base_delay, **kwargs)
        return wrapper  # type: ignore[return-value]
    return decorator
