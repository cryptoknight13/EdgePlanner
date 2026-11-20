#!/usr/bin/env python3
import os
import re
from pathlib import Path

# --- Paths (as you specified) ---
CURR_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
problem_path = (CURR_DIR / "../../pddl/NetProblem.pddl").resolve()
goal_file_path = (CURR_DIR / "../data/goal.txt").resolve()
new_problem_path = (CURR_DIR / "../../pddl/newNetProblem.pddl").resolve()

def normalize_obj_name(name: str) -> str:
    s = name.strip().lower()
    s = re.sub(r"[\s_]+", "-", s)          # spaces/underscores -> hyphens
    s = re.sub(r"[^a-z0-9\-\.]", "", s)    # keep alnum, hyphen, dot
    return s

def find_goal_block_span(text: str):
    start = text.find("(:goal")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return (start, i + 1)
    return None

def extract_exploited_atoms(goal_block: str):
    """
    Returns list of tuples: (full_atom_text, object_token)
    Matches atoms like: (exploited-n1 web-server-a)
    """
    atoms = []
    for m in re.finditer(r"\(\s*exploited-[^)]+\)", goal_block):
        full = m.group(0)
        inner = full.strip()[1:-1].strip()
        parts = re.split(r"\s+", inner)
        obj = parts[-1]
        atoms.append((full, obj))
    return atoms

def replace_goal(problem_text: str, target_name: str) -> str:
    span = find_goal_block_span(problem_text)
    if not span:
        raise ValueError("No (:goal ...) block found.")
    start, end = span
    goal_block = problem_text[start:end]

    atoms = extract_exploited_atoms(goal_block)
    if not atoms:
        raise ValueError("No '(exploited-... <obj>)' atoms found in :goal block.")

    target_norm = normalize_obj_name(target_name)

    # Exact object match first
    matches = [full for (full, obj) in atoms if normalize_obj_name(obj) == target_norm]

    if not matches:
        # Fallback: substring match (e.g., "web-server" matches "web-server-a")
        cand = [full for (full, obj) in atoms if target_norm in normalize_obj_name(obj)]
        if len(cand) == 1:
            matches = cand
        elif len(cand) > 1:
            raise ValueError(f"Ambiguous goal '{target_name}'. Multiple matches: {cand}")
        else:
            available = [obj for _, obj in atoms]
            raise ValueError(f"Goal '{target_name}' not found. Available: {available}")

    chosen = matches[0]
    new_goal_block = f"(:goal\n    {chosen}\n)\n"

    return problem_text[:start] + new_goal_block + problem_text[end:]

def main():
    if not problem_path.is_file():
        raise FileNotFoundError(f"Problem file not found: {problem_path}")
    if not goal_file_path.is_file():
        raise FileNotFoundError(f"Goal file not found: {goal_file_path}")

    target_name = goal_file_path.read_text(encoding="utf-8").strip()
    problem_text = problem_path.read_text(encoding="utf-8")

    new_text = replace_goal(problem_text, target_name)
    new_problem_path.parent.mkdir(parents=True, exist_ok=True)
    new_problem_path.write_text(new_text, encoding="utf-8")

    print(f"Wrote single-goal problem to: {new_problem_path}")

if __name__ == "__main__":
    main()
