"""Bundled-example discovery and loading.

Each example lives in a subdirectory of `input_data/` containing a
`manifest.json` plus the four canonical JSON files. Example names are the
directory names (URL-safe).
"""
from __future__ import annotations

import json
from pathlib import Path

from api.core.config import INPUT_DATA_DIR
from api.core.errors import NotFoundError
from api.schemas.acg.start import (
    CANONICAL_FILENAMES,
    SLOT_NAMES,
    ExampleManifest,
    ExamplesList,
)
from api.services.acg import dataset_service


def list_examples() -> ExamplesList:
    """Discover bundled examples by scanning `input_data/` for manifest files."""
    items: list[ExampleManifest] = []
    if not INPUT_DATA_DIR.exists():
        return ExamplesList(items=items)
    for entry in sorted(INPUT_DATA_DIR.iterdir()):
        manifest_path = entry / "manifest.json"
        if not (entry.is_dir() and manifest_path.exists()):
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            items.append(ExampleManifest(
                name=manifest["name"],
                label=manifest["label"],
                description=manifest["description"],
            ))
        except (json.JSONDecodeError, KeyError):
            continue
    return ExamplesList(items=items)


def load_example(name: str) -> None:
    """Copy the example's 4 canonical files into the active dataset.

    Validates each file via dataset_service before copying. Raises
    NotFoundError if the example doesn't exist.
    """
    example_dir = INPUT_DATA_DIR / name
    manifest_path = example_dir / "manifest.json"
    if not manifest_path.exists():
        raise NotFoundError(
            f"Example '{name}' not found",
            details={"expected_path": str(example_dir)},
        )

    dataset_service.reset_dataset()

    for slot in SLOT_NAMES:
        src: Path = example_dir / CANONICAL_FILENAMES[slot]
        if not src.exists():
            raise NotFoundError(
                f"Example '{name}' is missing file '{src.name}'",
                details={"expected_path": str(src)},
            )
        text = src.read_text(encoding="utf-8")
        validated = dataset_service.parse_and_validate(slot, text)
        dataset_service.save_slot(slot, validated)
