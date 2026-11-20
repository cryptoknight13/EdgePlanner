"""Shared pytest fixtures for the api/ test suite."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import create_app


@pytest.fixture()
def client() -> TestClient:
    """Fresh app + TestClient per test (isolation by default)."""
    return TestClient(create_app())
