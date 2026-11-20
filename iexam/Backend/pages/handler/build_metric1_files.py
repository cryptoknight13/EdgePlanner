import re
import os

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
PDDL_DIR = os.path.abspath(os.path.join(CURR_DIR, "../../pddl"))
METRIC1_DIR = os.path.abspath(os.path.join(CURR_DIR, "../_metric1/metric1_domain"))


def process_pddl(input_file, output_file):
    with open(input_file, 'r') as file:
        lines = file.readlines()

    # Remove initial conditions for system, struct, driver, cause, and function
    init_start = next(i for i, line in enumerate(lines) if "(:init" in line)
    init_end = next(i for i, line in enumerate(lines) if "(:goal" in line)
    init_lines = lines[init_start:init_end]
    filtered_init = [
        line for line in init_lines
        if not re.search(r'\(has-n\d+-(system|struct|driver|cause|function)', line)
    ]

    # Combine the updated content (do not touch the goal section)
    output_lines = (
        lines[:init_start] +
        filtered_init +
        lines[init_end:]
    )

    # Write to the output file
    with open(output_file, 'w') as file:
        file.writelines(output_lines)

def parse_domain(input_file, output_file):
    with open(input_file, 'r') as file:
        lines = file.readlines()

    # Extract the predicates section
    predicates_start = next(i for i, line in enumerate(lines) if "(:predicates" in line)
    predicates_end = next(i for i, line in enumerate(lines[predicates_start:], start=predicates_start) if line.strip() == ")")
    predicates = lines[predicates_start:predicates_end + 1]

    # Retain all predicates and add the %OPERATORS% placeholder
    output_lines = (
        lines[:predicates_end + 1] +
        ["\n%OPERATORS%\n\n )"]
    )

    # Write to the output file
    with open(output_file, 'w') as file:
        file.writelines(output_lines)

def parse_problem(input_file, output_file):
    with open(input_file, 'r') as file:
        lines = file.readlines()

    # Extract the init section
    init_start = next(i for i, line in enumerate(lines) if "(:init" in line)
    init_end = next(i for i, line in enumerate(lines) if "(:goal" in line)
    init_lines = lines[init_start:init_end]

    # Extract the goal section
    goal_start = next(i for i, line in enumerate(lines) if "(:goal" in line)
    goal_end = goal_start
    open_parens = 0
    for i in range(goal_start, len(lines)):
        open_parens += lines[i].count("(")
        open_parens -= lines[i].count(")")
        if open_parens == 0:
            goal_end = i
            break
    goal_lines = lines[goal_start:goal_end + 1]

    # Replace init and goal with placeholders
    output_lines = (
        lines[:init_start] +
        ["\n  (:init\n\n    %INIT%\n\n  )\n"] +
        ["  (:goal (and\n\n    %GOAL%\n\n  ))\n", ")\n"]
    )

    # Write to the output file
    with open(output_file, 'w') as file:
        file.writelines(output_lines)

def copy_problem(input_file, output_file):
    with open(input_file, 'r') as src, open(output_file, 'w') as dst:
        dst.writelines(src.readlines())

# Example usage
input_problem = os.path.join(PDDL_DIR, 'newNetProblem.pddl')
output_problem  = os.path.join(METRIC1_DIR, 'unsolvable_domain', 'unsolvable.pddl')
process_pddl(input_problem, output_problem)

input_domain = os.path.join(PDDL_DIR, 'NetDomain.pddl')

output_domain_template = os.path.join(METRIC1_DIR, 'domain_template', 'NetDomain_template.pddl')
output_problem_template = os.path.join(METRIC1_DIR, 'domain_template', 'NetProblem_template.pddl') 
original_problem = os.path.join(METRIC1_DIR, 'domain_template', 'NetProblem.pddl')
original_domain = os.path.join(METRIC1_DIR, 'domain_template', 'NetDomain.pddl')
# Generate the parsed domain and problem files
parse_domain(input_domain, output_domain_template)
parse_problem(input_problem, output_problem_template)

output_problem_solv  = os.path.join(METRIC1_DIR, 'solvable_domain', 'solvable.pddl')



# Copy netproblem.pddl to solvable.pddl as is
copy_problem(input_problem,output_problem_solv)
copy_problem(input_problem,original_problem)
copy_problem(input_domain,original_domain)
