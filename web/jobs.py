"""Pipeline runner for the web page: one page stage per request, one job at a time.

The operator steps through five page stages. Each runs one or more `run.py <step> --run <id>` subprocesses,
exactly as from the shell (Scan Your Network = scan + cveinfo; Start Planning = export + plan --prepare, so
iEXAM's input files are always rebuilt from the latest scan). Attack plans are then found per goal on request:
the `optimal` and `topk` actions. Output is streamed to runs/<id>/pipeline.log, never held in memory.
"""
import json
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
# (page stage, run.py steps in order (argv), file that marks the stage done)
STAGES = (("discover", (("discover",),), "discover.json"),
          ("gather", (("gather",),), "gather.json"),
          ("scan", (("scan",), ("cveinfo",)), "cveinfo.json"),
          ("plan", (("export",), ("plan", "--prepare")), "plans/plans.json"),
          ("mitigate", (("mitigate",),), "mitigation/mitigation.json"))
ACTIONS = ("optimal", "topk", "guide")  # per goal: planning once Start Planning ran; fix guides once Mitigate ran
K_MAX = 10
NAMES = [s for s, _, _ in STAGES]
STEPS = {s: steps for s, steps, _ in STAGES}
LOG = "pipeline.log"
TAIL_BYTES = 4000


class Busy(Exception):
    pass


def done_stages(run_dir: Path) -> list[str]:
    return [s for s, _, marker in STAGES if (run_dir / marker).exists()]


def steps_for(run_dir: Path, stage: str, goal: str | None = None, k: int | None = None) -> list[list[str]]:
    """The run.py steps (argv) a stage or action runs now."""
    if stage == "optimal":
        return [["plan", "--target", goal, "--optimal"]]
    if stage == "topk":
        return [["plan", "--target", goal, "--topk", str(k)]]
    if stage == "guide":
        return [["guide", "--target", goal]]
    # A half-finished Scan Your Network (network scan done, CVE lookup missing) resumes with the lookup.
    if stage == "scan" and (run_dir / "scan.json").exists() and not (run_dir / "cveinfo.json").exists():
        return [["cveinfo"]]
    return [list(step) for step in STEPS[stage]]


def run_goals(run_dir: Path) -> list[str]:
    try:
        return [t["goal"] for t in json.loads((run_dir / "plans" / "plans.json").read_text())["targets"]]
    except (OSError, ValueError, KeyError):
        return []


def mitigated_goals(run_dir: Path) -> list[str]:
    """Goals Mitigate found options for: the ones a fix guide can be written for."""
    try:
        targets = json.loads((run_dir / "mitigation" / "mitigation.json").read_text())["targets"]
    except (OSError, ValueError, KeyError):
        return []
    return [t["goal"] for t in targets if not t.get("unreachable") and t.get("options")]


def stage_command(step: list[str], run_id: str) -> list[str]:
    return [sys.executable, str(ROOT / "run.py"), *step, "--run", run_id]


class Pipeline:
    def __init__(self, runs_dir: Path, command: Callable[[str, str], list[str]] = stage_command):
        self.runs_dir = runs_dir
        self.command = command
        self.lock = threading.Lock()
        self.state: dict | None = None

    def start(self, run_id: str | None, stage: str, goal: str | None = None, k: int | None = None) -> dict:
        """Run one stage, or one planning action for a goal.

        Discover starts a new run (run_id None); any other stage needs the one before it done; the optimal and
        topk actions need Start Planning done and a goal from that run's attack model.
        """
        if stage not in NAMES and stage not in ACTIONS:
            raise ValueError(f"unknown stage {stage!r}")
        if (run_id is None) != (stage == "discover"):
            raise ValueError("discover starts a new run; later stages need an existing run")
        with self.lock:
            if self.state and self.state["state"] == "running":
                raise Busy(f"{self.state['current']} is running on {self.state['run']}")
            if run_id is None:
                run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                if (self.runs_dir / run_id).exists():
                    raise Busy("a run started this second; try again")
            elif not (self.runs_dir / run_id).is_dir():
                raise ValueError(f"no run {run_id}")
            elif stage == "guide":
                if goal not in mitigated_goals(self.runs_dir / run_id):
                    raise ValueError("run Mitigate for this goal first")
            elif stage in ACTIONS:
                if goal not in run_goals(self.runs_dir / run_id):
                    raise ValueError("pick a goal from this scan's attack model (run Start Planning first)")
                if stage == "topk" and not (isinstance(k, int) and 1 <= k <= K_MAX):
                    raise ValueError(f"k must be between 1 and {K_MAX}")
            else:
                before = NAMES[NAMES.index(stage) - 1]
                if before not in done_stages(self.runs_dir / run_id):
                    raise ValueError(f"run {before} first")
            (self.runs_dir / run_id).mkdir(parents=True, exist_ok=True)
            steps = steps_for(self.runs_dir / run_id, stage, goal, k)
            self.state = {"run": run_id, "stages": [stage], "steps": [s[0] for s in steps], "step": steps[0][0],
                          "goal": goal, "done": [], "current": stage, "state": "running", "returncode": None,
                          "started": datetime.now(timezone.utc).isoformat(timespec="seconds")}
            threading.Thread(target=self._run, args=(run_id, stage, steps), daemon=True).start()
        return self.snapshot()

    def _run(self, run_id: str, stage: str, steps: list[str]) -> None:
        with open(self.runs_dir / run_id / LOG, "a") as log:
            for step in steps:
                with self.lock:
                    self.state["step"] = step[0]
                log.write(f"\n=== {stage}: {' '.join(step)} ({datetime.now(timezone.utc).isoformat(timespec='seconds')}) ===\n")
                log.flush()
                try:
                    rc = subprocess.run(self.command(step, run_id), stdout=log, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, cwd=ROOT).returncode
                except OSError as exc:
                    log.write(f"could not start {step}: {exc}\n")
                    rc = -1
                if rc != 0:
                    with self.lock:
                        self.state.update(state="failed", returncode=rc)
                    return
        with self.lock:
            self.state["done"].append(stage)
            self.state.update(state="done", current=None, step=None, returncode=0)

    def snapshot(self) -> dict:
        with self.lock:
            if not self.state:
                return {"state": "idle"}
            out = {**self.state, "done": list(self.state["done"])}
        path = self.runs_dir / out["run"] / LOG
        try:
            with open(path, "rb") as f:
                f.seek(max(0, path.stat().st_size - TAIL_BYTES))
                out["log_tail"] = f.read().decode("utf-8", "replace")
        except OSError:
            out["log_tail"] = ""
        return out
