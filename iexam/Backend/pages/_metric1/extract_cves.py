"""Extract failing-action CVE(s) from Metric 1 VAL validation files.

A Metric 1 run produces one VAL validation report per (plan, problem) pair in
`metric1_output/results/validations/`. When a plan fails, VAL writes:

    Plan failed because of unsatisfied precondition in:
    (attacker-exploit-cve-YYYY-NNNN-... <args>)

The action on the line immediately after the marker is the precise step the
planner could not execute given the user-chosen option. The CVE in that
action name is the *only* CVE actually responsible for the failure — earlier
attacker-exploit actions in the plan succeeded.

Earlier versions of this script scanned whole plan files (every grounded
exploit) or the LLM explanation prose, which produced over-broad CVE lists
that polluted the graph highlight. We now extract only the failing-action
CVE so the UI highlights exactly the vulnerability blocking the chosen
mitigation.
"""
from __future__ import annotations

import re
from pathlib import Path

CVE_RE = re.compile(r"(?:CVE|cve)-\d{4}-\d{4,7}", re.IGNORECASE)
FAIL_MARKER = "Plan failed because of unsatisfied precondition in:"


def _failing_actions(validation_text: str) -> list[str]:
    """Return action lines that appear directly after a fail marker."""
    out: list[str] = []
    lines = validation_text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == FAIL_MARKER:
            for j in range(i + 1, min(i + 4, len(lines))):
                candidate = lines[j].strip()
                if candidate.startswith("(") and candidate:
                    out.append(candidate)
                    break
    return out


def _scan_validations(validations_dir: Path) -> set[str]:
    if not validations_dir.is_dir():
        return set()
    cves: set[str] = set()
    for vfile in sorted(validations_dir.glob("*.txt")):
        try:
            text = vfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for action in _failing_actions(text):
            cves.update(m.upper() for m in CVE_RE.findall(action))
    return cves


def extract_cves(validations_dir: Path, output_path: Path) -> None:
    cves = _scan_validations(validations_dir)
    print(f"Extracted {len(cves)} failing-action CVE(s): {sorted(cves)}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(sorted(cves)), encoding="utf-8")


if __name__ == "__main__":
    base_dir = Path(__file__).parent
    extract_cves(
        validations_dir=base_dir / "metric1_output" / "results" / "validations",
        output_path=base_dir / "data" / "cves.txt",
    )
