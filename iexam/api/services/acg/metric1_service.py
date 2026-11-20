"""Metric 1 pipeline: prepare files, pick heuristic, generate options,
pick option, stream analyze, read results.

Wraps the existing scripts under Backend/pages/_metric1 and Backend/pages/handler
via subprocess. No FastAPI imports.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterator, Literal

log = logging.getLogger("acg.metric1")

from api.core.config import (
    DATA_DIR,
    HANDLER_DIR,
    METRIC1_DIR,
    PLAN_RESULTS_DIR,
    REPO_ROOT,
)
from api.core.errors import (
    InputValidationError,
    Metric1NoOptionsError,
    Metric1PrereqError,
    Metric1ScriptError,
    NotFoundError,
)


GOAL_FILE = DATA_DIR / "goal.txt"
PLAN_JSON = PLAN_RESULTS_DIR / "optimal_plan.json"

M1_DATA_DIR = METRIC1_DIR / "data"
HEURISTIC_FILE = M1_DATA_DIR / "heuristic_option.txt"
PDDL_OPTIONS = M1_DATA_DIR / "pddl_options.txt"
PDDL_OPTIONS_NORMALIZED = M1_DATA_DIR / "pddl_options_normalized.txt"
USER_OPTION = M1_DATA_DIR / "user_selected_option.txt"
EXPLANATIONS = METRIC1_DIR / "metric1_output" / "results" / "explanations" / "all_explanations.txt"
CVES_FILE = M1_DATA_DIR / "cves.txt"
VALIDATIONS_DIR = METRIC1_DIR / "metric1_output" / "results" / "validations"

STEP_SCRIPTS = [
    ("solutions", METRIC1_DIR / "build_solutions_domain.py", METRIC1_DIR),
    ("validation", METRIC1_DIR / "build_validation_file.py", METRIC1_DIR),
    ("explanations", METRIC1_DIR / "build_llm_for_explanations.py", METRIC1_DIR),
    ("cves", METRIC1_DIR / "extract_cves.py", METRIC1_DIR),
]

SUBPROCESS_TIMEOUT = 1800
STDERR_TAIL_BYTES = 4096


def check_prereqs() -> None:
    if not GOAL_FILE.exists() or not GOAL_FILE.read_text(encoding="utf-8").strip():
        raise Metric1PrereqError(
            "Pick a goal on the Plan page first",
            details={"missing": "goal"},
        )
    plan_json = PLAN_RESULTS_DIR / "optimal_plan.json"
    if not plan_json.exists():
        raise Metric1PrereqError(
            "Generate an optimal plan first",
            details={"missing": "optimal_plan"},
        )


def _stderr_tail(stderr: str) -> str:
    if not stderr:
        return ""
    encoded = stderr.encode("utf-8", "replace")
    return encoded[-STDERR_TAIL_BYTES:].decode("utf-8", "replace")


def _run_step(step: str, script: Path, cwd: Path | None = None,
              extra_pythonpath: bool = False) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if extra_pythonpath:
        existing = env.get("PYTHONPATH", "")
        backend = str(REPO_ROOT / "Backend")
        env["PYTHONPATH"] = f"{backend}{os.pathsep}{existing}" if existing else backend
    log.info("metric1 step %r: launching %s (cwd=%s, timeout=%ss)",
             step, script, cwd, SUBPROCESS_TIMEOUT)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        partial_out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        partial_err = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        log.error("metric1 step %r TIMEOUT after %.1fs (limit %ss)\n"
                  "--- partial stdout tail ---\n%s\n"
                  "--- partial stderr tail ---\n%s",
                  step, elapsed, SUBPROCESS_TIMEOUT,
                  partial_out[-4000:], partial_err[-4000:])
        raise Metric1ScriptError(
            f"Metric 1 step '{step}' timed out after {SUBPROCESS_TIMEOUT}s",
            details={"step": step, "error": "timeout"},
        ) from exc
    elapsed = time.monotonic() - started
    log.info("metric1 step %r finished rc=%d in %.2fs", step, proc.returncode, elapsed)
    if proc.stdout:
        log.info("metric1 step %r stdout (last 4KB):\n%s", step, proc.stdout[-4000:])
    if proc.stderr:
        log.info("metric1 step %r stderr (last 4KB):\n%s", step, proc.stderr[-4000:])
    if proc.returncode != 0:
        raise Metric1ScriptError(
            f"Metric 1 step '{step}' exited {proc.returncode}",
            details={
                "step": step,
                "returncode": proc.returncode,
                "stderr_tail": _stderr_tail(proc.stderr),
            },
        )
    return proc


def prepare() -> None:
    check_prereqs()
    _run_step("prepare", HANDLER_DIR / "build_metric1_files.py")


def set_heuristic(choice: Literal["with", "without"]) -> None:
    if choice not in ("with", "without"):
        raise InputValidationError(
            f"Unknown heuristic choice: {choice!r}",
            details={"choice": choice},
        )
    HEURISTIC_FILE.parent.mkdir(parents=True, exist_ok=True)
    HEURISTIC_FILE.write_text("2" if choice == "with" else "1")


def generate_options() -> list[dict[str, str]]:
    check_prereqs()
    _run_step(
        "options_main",
        METRIC1_DIR / "build_metric1_main.py",
        cwd=METRIC1_DIR,
        extra_pythonpath=True,
    )
    _run_step("options_normalize", HANDLER_DIR / "pddl_option_m1.py")

    raw_lines = [
        line.strip()
        for line in PDDL_OPTIONS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if PDDL_OPTIONS.exists() else []
    norm_lines = [
        line.strip()
        for line in PDDL_OPTIONS_NORMALIZED.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if PDDL_OPTIONS_NORMALIZED.exists() else []

    if not raw_lines:
        raise Metric1NoOptionsError(
            "Options generation produced no options",
            details={"raw_count": 0, "normalized_count": len(norm_lines)},
        )

    pairs: list[dict[str, str]] = []
    for idx, raw in enumerate(raw_lines):
        label = norm_lines[idx] if idx < len(norm_lines) else f"Option {idx + 1}"
        pairs.append({"label": label, "raw": raw})
    return pairs


def set_option(raw: str) -> None:
    raw = raw.strip()
    if not raw:
        raise InputValidationError("raw option is empty")
    if not PDDL_OPTIONS.exists():
        raise InputValidationError(
            "No options have been generated yet",
            details={"hint": "Call generate_options first"},
        )
    valid = {
        line.strip()
        for line in PDDL_OPTIONS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    if raw not in valid:
        raise InputValidationError(
            "Selected option is not one of the generated options",
            details={"raw": raw},
        )
    USER_OPTION.parent.mkdir(parents=True, exist_ok=True)
    USER_OPTION.write_text(raw, encoding="utf-8")


def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def analyze_stream() -> Iterator[str]:
    check_prereqs()
    for step, script, cwd in STEP_SCRIPTS:
        yield _sse("step", {"step": step, "status": "started"})
        try:
            _run_step(step, script, cwd=cwd, extra_pythonpath=True)
        except Metric1ScriptError as exc:
            details = exc.details or {}
            yield _sse("step", {
                "step": step,
                "status": "error",
                "returncode": details.get("returncode"),
                "stderr_tail": details.get("stderr_tail", ""),
                "error": details.get("error"),
            })
            return
        yield _sse("step", {"step": step, "status": "completed"})
    yield _sse("done", {"done": True})


def _parse_validation_failures(text: str) -> list[dict[str, str]]:
    """Pull (failing_action, unsatisfied_predicate) pairs from VAL output."""
    failures: list[dict[str, str]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.endswith("has an unsatisfied precondition at time"):
            i += 1
            continue
        if "has an unsatisfied precondition at time" in line:
            action_end = line.find(") has an unsatisfied precondition at time")
            action = line[: action_end + 1].strip() if action_end != -1 else line
            predicate = ""
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                predicate = lines[j].strip()
            failures.append({"action": action, "predicate": predicate})
            i = j + 1
            continue
        i += 1
    return failures


def read_results() -> dict[str, Any]:
    if not EXPLANATIONS.exists():
        raise NotFoundError("No Metric 1 results yet")
    explanation = EXPLANATIONS.read_text(encoding="utf-8").strip()
    cves: list[str] = []
    if CVES_FILE.exists():
        cves = [
            line.strip()
            for line in CVES_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    failures: list[dict[str, str]] = []
    if VALIDATIONS_DIR.exists():
        for vfile in sorted(VALIDATIONS_DIR.glob("*.txt")):
            try:
                failures.extend(
                    _parse_validation_failures(vfile.read_text(encoding="utf-8"))
                )
            except OSError:
                continue
    return {"explanation": explanation, "cves": cves, "failures": failures}
