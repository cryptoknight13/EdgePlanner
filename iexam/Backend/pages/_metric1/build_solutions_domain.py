import os
import shutil
import utils

def implement_solution(input_file, output_file, keywords, goal_ignored=None):
    """
    Simple match-and-remove:
    - Convert each 'has-initial-state-<pred> <args>' to '(<pred> <args>)'
    - Remove those exact lines from the (:init ...) block
    - Do NOT touch the goal section or anything else
    """
    # 1) Build the exact PDDL atoms to remove
    to_remove = []
    for kw in keywords:
        s = kw.strip()
        if s.startswith('has-initial-state-'):
            s = s[len('has-initial-state-'):].strip()
        parts = s.split(maxsplit=1)
        if len(parts) == 2:
            pred, args = parts[0].strip(), parts[1].strip()
            to_remove.append(f"({pred} {args})")
        elif len(parts) == 1:
            to_remove.append(f"({parts[0]})")

    # 2) Read file and locate (:init ...) block (simple balanced scan)
    with open(input_file, 'r', encoding='utf-8') as f:
        text = f.read()

    init_pos = text.find('(:init')
    if init_pos == -1:
        # No init → just copy
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text)
        return

    # find the '(' that starts the init block and its balanced ')'
    block_start = text.rfind('(', 0, init_pos + 1)
    if block_start == -1:
        block_start = init_pos
    depth = 0
    end = None
    for i in range(block_start, len(text)):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        # Unbalanced; safest is to leave file unchanged
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(text)
        return

    # 3) Filter lines inside the init block
    init_block = text[block_start:end+1]
    before = text[:block_start]
    after = text[end+1:]

    # Keep '(:init' and closing ')', only filter predicate lines
    lines = init_block.splitlines()
    kept_lines = []
    for ln in lines:
        ln_stripped = ln.strip()
        # if this line contains any exact PDDL atom we want to remove, skip it
        if any(rem in ln_stripped for rem in to_remove) and ln_stripped.startswith('(') and not ln_stripped.startswith('(:init'):
            continue
        kept_lines.append(ln)

    new_init_block = '\n'.join(kept_lines)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(before + new_init_block + after)

def read_options(path):
    with open(path, 'r', encoding='utf-8') as f:
        s = f.read().strip()
    if s.startswith('{') and s.endswith('}'):
        s = s[1:-1]
    return [p.strip().strip("'").strip('"') for p in s.split(',') if p.strip()]

def generate_one_removed_variants(input_problem_path, options_path, output_dir):
    """
    For each initial condition in options.txt, create a file that removes ONLY that one:
    solProblem_1.pddl, solProblem_2.pddl, ...
    """
    os.makedirs(output_dir, exist_ok=True)
    opts = read_options(options_path)
    for idx, opt in enumerate(opts, start=1):
        print(f"Generating variant removing option: {idx}")
        out_path = os.path.join(output_dir, f"solProblem_{idx}.pddl")
        implement_solution(input_problem_path, out_path, [opt])

def clear_folder(folder_path):
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)

def main():
    # Clear all previous outputs before starting
    folders_to_clear = [
        os.path.join(utils.get_project_root(), 'metric1_output', 'solutions', 'solDomain'),
        os.path.join(utils.get_project_root(), 'metric1_output', 'plans'),
        os.path.join(utils.get_project_root(), 'metric1_output', 'results', 'validations'),
        os.path.join(utils.get_project_root(), 'metric1_output', 'results', 'explanations'),
    ]
    for folder in folders_to_clear:
        if os.path.exists(folder):
            clear_folder(folder)

    problem_in = os.path.join(utils.get_project_root(), 'metric1_output','solutions', 'original_problem_file.pddl')
    options_in  = os.path.join(utils.get_project_root(), 'data', 'user_selected_option.txt')
    problem_out = os.path.join(utils.get_project_root(), 'metric1_output','solutions', 'solProblem.pddl')
    
    opts = read_options(options_in)
    implement_solution(problem_in, problem_out, opts, goal_ignored=None)
    
    print(f"Processed {problem_in} with options from {options_in}, output saved to {problem_out}")
    prob_out = os.path.join(utils.get_project_root(), 'metric1_output','solutions', 'solDomain')
    generate_one_removed_variants(problem_in, options_in, prob_out)

if __name__ == "__main__":
    main()