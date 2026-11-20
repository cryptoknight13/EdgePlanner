"""Root logging config — writes everything to Logs/log.txt with stdout mirror.

Attaches handlers to the root logger so application code, uvicorn, fastapi,
and any third-party libraries (openai, watchfiles, ...) all funnel into the
same log file. The frontend "Logs" drawer reads that file via /api/logs.
"""
from __future__ import annotations

import logging
import sys

from api.core.config import LOG_FILE, LOGS_DIR, SERVICE_NAME

# Loggers whose records should reach our file handler. Setting `propagate=True`
# on them lets the message bubble up to the root logger we configure below.
_UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi")


def setup_logging() -> logging.Logger:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    # Wipe any pre-existing handlers uvicorn installed so we don't double-print.
    root.handlers.clear()
    root.setLevel(logging.INFO)

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(fh)
    root.addHandler(sh)

    # Force uvicorn / fastapi loggers to propagate to root (they ship with
    # their own handlers + propagate=False by default, which is why nothing
    # was hitting Logs/log.txt).
    for name in _UVICORN_LOGGERS:
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True
        lg.setLevel(logging.INFO)

    # Quiet noisy third-party loggers.
    logging.getLogger("watchfiles").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Named service logger inherits root handlers via propagation.
    service = logging.getLogger(SERVICE_NAME)
    service.setLevel(logging.INFO)
    service.propagate = True
    return service
