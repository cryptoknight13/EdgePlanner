"""ACG PDDL routes: generate, fetch, download domain/problem files."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from api.schemas.acg.start import PddlFile, PddlGenerateResponse
from api.services.acg import dataset_service, pddl_service

router = APIRouter(prefix="/api/acg/pddl", tags=["acg-pddl"])


@router.post("/generate", response_model=PddlGenerateResponse)
def generate() -> PddlGenerateResponse:
    domain, problem = pddl_service.generate_pddl()
    return PddlGenerateResponse(
        ok=True,
        domain_chars=len(domain),
        problem_chars=len(problem),
        dataset=dataset_service.dataset_status(consistency=None),
    )


@router.get("/{kind}", response_model=PddlFile)
def get_pddl(kind: Literal["domain", "problem"]) -> PddlFile:
    content = pddl_service.read_pddl(kind)
    filename = (
        pddl_service.DOMAIN_FILENAME if kind == "domain" else pddl_service.PROBLEM_FILENAME
    )
    return PddlFile(kind=kind, filename=filename, content=content)


@router.get("/{kind}/download", response_class=PlainTextResponse)
def download_pddl(kind: Literal["domain", "problem"]) -> PlainTextResponse:
    content = pddl_service.read_pddl(kind)
    filename = (
        pddl_service.DOMAIN_FILENAME if kind == "domain" else pddl_service.PROBLEM_FILENAME
    )
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
