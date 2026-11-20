"""Pydantic models for the /api/acg/metric1 routes."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PrepareResponse(BaseModel):
    ready: bool


class SetHeuristicRequest(BaseModel):
    choice: Literal["with", "without"]


class SavedResponse(BaseModel):
    saved: bool


class Option(BaseModel):
    label: str
    raw: str


class OptionsResponse(BaseModel):
    options: list[Option]


class SetOptionRequest(BaseModel):
    raw: str = Field(min_length=1)


class ValidationFailure(BaseModel):
    action: str
    predicate: str


class ResultsResponse(BaseModel):
    explanation: str
    cves: list[str]
    failures: list[ValidationFailure] = Field(default_factory=list)
