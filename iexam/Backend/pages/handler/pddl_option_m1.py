import ast
import os

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
METRIC1_DIR = os.path.abspath(os.path.join(CURR_DIR, "../_metric1/"))

def parse_option_set(option_set_str):
    # Parse the set literal safely
    try:
        items = ast.literal_eval(option_set_str)
        if not isinstance(items, set):
            return []
        return list(items)
    except Exception:
        return []

def extract_change_targets(items):
    # Extract the last word from each item (after last space)
    targets = []
    for item in items:
        # If item is like 'has-initial-state-has-n6-driver-1-dot-1 request-handling'
        # get 'request-handling'
        if isinstance(item, str):
            parts = item.strip().split()
            if parts:
                targets.append(parts[-1].replace("-", " ").replace("_", " "))
    return targets

def make_explanation(targets):
    if not targets:
        return ""
    if len(targets) == 1:
        return f"Make a change in {targets[0]}"
    else:
        # Oxford comma style
        return "Make a change in " + ", ".join(targets[:-1]) + ", and " + targets[-1]

def main():
    input_path = os.path.abspath(os.path.join(METRIC1_DIR, "data", "pddl_options.txt")) 
    output_path = os.path.abspath(os.path.join(METRIC1_DIR, "data", "pddl_options_normalized.txt")) 

    with open(input_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    explanations = []
    for idx, line in enumerate(lines):
        items = parse_option_set(line)
        targets = extract_change_targets(items)
        explanation = make_explanation(targets)
        explanations.append(f"Option {idx+1}: {explanation}")

    with open(output_path, "w", encoding="utf-8") as f:
        for exp in explanations:
            f.write(exp + "\n")

if __name__ == "__main__":
    main()
