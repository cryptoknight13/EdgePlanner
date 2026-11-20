"""Error-handler shape tests.

Verifies that both handler paths (typed `ApiException` and catch-all `Exception`)
produce the contract `{"error": {"code", "message", "details"}}`.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.core.errors import (
    ApiException,
    InputValidationError,
    NotFoundError,
    install_exception_handlers,
)


@pytest.fixture()
def app_with_test_routes() -> FastAPI:
    app = FastAPI()
    install_exception_handlers(app)

    @app.get("/raises-not-found")
    def raises_not_found() -> None:
        raise NotFoundError("missing", details={"id": "abc"})

    @app.get("/raises-validation")
    def raises_validation() -> None:
        raise InputValidationError("bad input")

    @app.get("/raises-base-api")
    def raises_base_api() -> None:
        raise ApiException("base error")

    @app.get("/raises-uncaught")
    def raises_uncaught() -> None:
        raise RuntimeError("oops, this leaked out of the route")

    return app


@pytest.fixture()
def test_client(app_with_test_routes: FastAPI) -> TestClient:
    # raise_server_exceptions=False lets TestClient surface 500 responses
    # rather than re-raising the exception in pytest.
    return TestClient(app_with_test_routes, raise_server_exceptions=False)


def test_not_found_error_uses_contract_shape(test_client: TestClient) -> None:
    response = test_client.get("/raises-not-found")
    assert response.status_code == 404
    body = response.json()
    assert body == {
        "error": {"code": "not_found", "message": "missing", "details": {"id": "abc"}}
    }


def test_input_validation_error_uses_contract_shape(test_client: TestClient) -> None:
    response = test_client.get("/raises-validation")
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error"
    assert body["error"]["message"] == "bad input"


def test_base_api_exception_defaults_to_500_internal(test_client: TestClient) -> None:
    response = test_client.get("/raises-base-api")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"


def test_uncaught_exception_falls_through_to_catch_all_handler(
    test_client: TestClient,
) -> None:
    """A bare `RuntimeError` from a route must produce the contract shape,
    not FastAPI's default `{"detail": "..."}`."""
    response = test_client.get("/raises-uncaught")
    assert response.status_code == 500
    body = response.json()
    assert "error" in body, f"expected wrapper 'error' key, got: {body}"
    assert body["error"]["code"] == "internal_error"
    assert "detail" not in body
