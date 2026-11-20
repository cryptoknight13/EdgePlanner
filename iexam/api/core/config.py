"""Centralized configuration for the api/ application.

Paths are resolved relative to the repository root (parent of api/).
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
LOGS_DIR: Path = REPO_ROOT / "Logs"
LOG_FILE: Path = LOGS_DIR / "log.txt"
DATA_DIR: Path = REPO_ROOT / "Backend" / "pages" / "data"
PDDL_DIR: Path = REPO_ROOT / "Backend" / "pddl"
INPUT_DATA_DIR: Path = REPO_ROOT / "input_data"
DOWNWARD_DIR: Path = REPO_ROOT / "Backend" / "downward"
PLAN_RESULTS_DIR: Path = REPO_ROOT / "Backend" / "pages" / "_build_plan" / "results"
METRIC1_DIR: Path = REPO_ROOT / "Backend" / "pages" / "_metric1"
HANDLER_DIR: Path = REPO_ROOT / "Backend" / "pages" / "handler"

API_HOST: str = "127.0.0.1"
API_PORT: int = 8000
SERVICE_NAME: str = "iexam-api"
