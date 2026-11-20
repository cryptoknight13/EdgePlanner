"""Dataset I/O for ACG: validate uploaded JSON, save under canonical names,
read back the current dataset state.

All files live in `Backend/pages/data/` (existing convention). Atomic writes
go through `<canonical>.tmp` then `os.replace` so partial writes never appear.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from api.core.config import DATA_DIR
from api.core.errors import InputValidationError, NotFoundError
from api.schemas.acg.start import (
    CANONICAL_FILENAMES,
    SLOT_NAMES,
    CveInNodeFile,
    CvesFile,
    DatasetStatus,
    EdgesFile,
    NodesFile,
    SlotName,
    SlotState,
    SlotStats,
)

SLOT_VALIDATORS: dict[SlotName, type] = {
    "nodes": NodesFile,
    "edges": EdgesFile,
    "cves": CvesFile,
    "cve_in_node": CveInNodeFile,
}


def _slot_path(slot: SlotName) -> Path:
    return DATA_DIR / CANONICAL_FILENAMES[slot]


def _ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def parse_and_validate(slot: SlotName, raw_text: str) -> dict[str, Any]:
    """Parse raw upload bytes as JSON and validate the slot's schema.

    Returns the validated payload as a plain dict (Pydantic-coerced). Raises
    InputValidationError with a structured `details` payload on failure.
    """
    if slot not in SLOT_VALIDATORS:
        raise InputValidationError(
            f"Unknown slot '{slot}'", details={"valid_slots": list(SLOT_NAMES)}
        )

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise InputValidationError(
            "File is not valid JSON",
            details={"line": exc.lineno, "column": exc.colno, "msg": exc.msg},
        ) from exc

    Validator = SLOT_VALIDATORS[slot]
    try:
        model = Validator.model_validate(payload)
    except PydanticValidationError as exc:
        raise InputValidationError(
            f"Schema validation failed for slot '{slot}'",
            details={"errors": exc.errors(include_url=False)},
        ) from exc

    return model.model_dump(by_alias=True, mode="json")


def save_slot(slot: SlotName, validated: dict[str, Any]) -> SlotStats:
    """Atomically write the validated payload under its canonical name.

    Any cached PDDL is cleared because the dataset has changed.
    """
    _ensure_data_dir()
    target = _slot_path(slot)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(validated, indent=2), encoding="utf-8")
    os.replace(tmp, target)
    from api.services.acg import pddl_service

    pddl_service.clear_pddl()
    return SlotStats(count=len(validated), saved_as=target.name)


def read_slot(slot: SlotName) -> dict[str, Any] | None:
    """Read the current canonical file for `slot`, or return None if absent."""
    path = _slot_path(slot)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputValidationError(
            f"Stored {path.name} is not valid JSON — file may be corrupted",
            details={"path": str(path), "msg": exc.msg},
        ) from exc


def slot_state(slot: SlotName) -> SlotState:
    """Build a SlotState for the current on-disk file."""
    path = _slot_path(slot)
    if not path.exists():
        return SlotState(filled=False)
    payload = read_slot(slot) or {}
    return SlotState(
        filled=True,
        stats=SlotStats(count=len(payload), saved_as=path.name),
    )


def reset_dataset() -> None:
    """Delete all 4 canonical files plus any cached PDDL. Idempotent."""
    for slot in SLOT_NAMES:
        path = _slot_path(slot)
        if path.exists():
            path.unlink()
    from api.services.acg import pddl_service

    pddl_service.clear_pddl()


def pddl_files_present() -> bool:
    from api.services.acg import pddl_service

    return pddl_service.pddl_exists()


def dataset_status(consistency: Any | None = None) -> DatasetStatus:
    """Assemble the full DatasetStatus envelope."""
    return DatasetStatus(
        slots={slot: slot_state(slot) for slot in SLOT_NAMES},
        consistency=consistency,
        pddl_ready=pddl_files_present(),
    )


def all_slots_filled() -> bool:
    return all(slot_state(slot).filled for slot in SLOT_NAMES)


def require_slot(slot: SlotName) -> dict[str, Any]:
    """Like `read_slot` but raises NotFoundError if missing."""
    payload = read_slot(slot)
    if payload is None:
        raise NotFoundError(
            f"Slot '{slot}' has no data uploaded yet",
            details={"slot": slot, "expected_path": str(_slot_path(slot))},
        )
    return payload
