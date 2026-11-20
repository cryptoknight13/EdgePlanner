"""Typed exceptions and global FastAPI exception handlers.

All error responses share the shape: {"error": {"code", "message", "details"}}
and use non-2xx HTTP statuses (closes Phase 0 BUG-API-004).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api.core.config import SERVICE_NAME


class ApiException(Exception):
    """Base class for application errors. Subclass to specialize."""

    status_code: int = 500
    code: str = "internal_error"

    def __init__(self, message: str, details: Any | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class InputValidationError(ApiException):
    """Request payload failed validation. Renamed from `ValidationError` to avoid
    a name collision with `pydantic.ValidationError`.
    """

    status_code = 422
    code = "validation_error"


class NotFoundError(ApiException):
    status_code = 404
    code = "not_found"


class Metric1PrereqError(ApiException):
    """Metric 1 needs a saved goal and an optimal plan first."""

    status_code = 409
    code = "metric1_prereq_missing"


class Metric1ScriptError(ApiException):
    """A Metric 1 subprocess returned a nonzero exit code or timed out."""

    status_code = 500
    code = "metric1_script_failed"


class Metric1NoOptionsError(ApiException):
    """The options-generation script produced an empty pddl_options.txt."""

    status_code = 404
    code = "metric1_no_options"


def _error_body(code: str, message: str, details: Any | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}


def install_exception_handlers(app: FastAPI) -> None:
    """Register handlers so every error response uses one shape.

    Two handlers are registered:
      * `ApiException` — for explicitly raised, typed errors.
      * `Exception` — catch-all for anything that escapes a route handler, so
        the frontend's `ApiError` parser never sees FastAPI's default
        `{"detail": "..."}` shape.
    """
    logger = logging.getLogger(SERVICE_NAME)

    @app.exception_handler(ApiException)
    async def handle_api_exc(_: Request, exc: ApiException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc.code, exc.message, exc.details),
        )

    @app.exception_handler(Exception)
    async def handle_unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "Unhandled exception on %s %s", request.method, request.url.path,
            exc_info=exc,
        )
        return JSONResponse(
            status_code=500,
            content=_error_body(
                "internal_error",
                "An unexpected error occurred.",
                None,
            ),
        )
