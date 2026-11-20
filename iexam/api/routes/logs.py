"""Log viewer endpoint.

Exposes the tail of `Logs/log.txt` so the frontend "Logs" button can show
live backend output without giving the browser raw file-system access.
"""
from __future__ import annotations

from fastapi import APIRouter, Query
from pydantic import BaseModel

from api.core.config import LOG_FILE

router = APIRouter(prefix="/api", tags=["logs"])

DEFAULT_TAIL_LINES = 500
MAX_TAIL_LINES = 5000


class LogPayload(BaseModel):
    path: str
    exists: bool
    bytes: int
    lines_returned: int
    text: str


@router.get("/logs", response_model=LogPayload)
def get_logs(
    tail: int = Query(DEFAULT_TAIL_LINES, ge=1, le=MAX_TAIL_LINES),
) -> LogPayload:
    """Return the last `tail` lines of the backend log file."""
    if not LOG_FILE.exists():
        return LogPayload(
            path=str(LOG_FILE),
            exists=False,
            bytes=0,
            lines_returned=0,
            text="",
        )
    raw = LOG_FILE.read_text(encoding="utf-8", errors="replace")
    lines = raw.splitlines()
    tail_lines = lines[-tail:] if len(lines) > tail else lines
    return LogPayload(
        path=str(LOG_FILE),
        exists=True,
        bytes=len(raw.encode("utf-8")),
        lines_returned=len(tail_lines),
        text="\n".join(tail_lines),
    )
