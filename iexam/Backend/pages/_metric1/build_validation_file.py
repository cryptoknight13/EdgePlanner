import os
import subprocess
import utils
from pathlib import Path
from build_helpers import create_plan

def validate_plan(domain_path, problem_path, plan_path, results_folder):
    """
    Validates the plan and saves the validation results in the results folder.
    """
    print(f"Validating with domain: {domain_path}, problem: {problem_path}, plan: {plan_path}")
    val_path = utils.get_validate_binary()
    print(f"Using Validate binary at: {val_path}")

    # Ensure files exist
    for file in [domain_path, problem_path, plan_path]:
        if not os.path.exists(file):
            raise FileNotFoundError(f"File not found: {file}")

    val_plan_cmd = [val_path, '-vv', domain_path, problem_path, plan_path]
    result = subprocess.run(val_plan_cmd, stdout=subprocess.PIPE, text=True)

    # Save the validation result
    validation_file_name = f"validation_{Path(plan_path).stem}_with_{Path(problem_path).stem}.txt"
    validation_file_path = os.path.join(results_folder, validation_file_name)
    os.makedirs(results_folder, exist_ok=True)  # Ensure the results folder exists
    with open(validation_file_path, 'w') as validation_file:
        validation_file.write(result.stdout.strip())

    print(f"Validation result saved to: {validation_file_path}")
    return result.stdout.strip()

def clear_folder(folder_path):
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)

def main():
    # Fixed domain file path
    domain_file = os.path.join(utils.get_project_root(), 'metric1_output', 'solutions', 'original_domain_file.pddl')
    original_problem_file = os.path.join(utils.get_project_root(), 'metric1_output', 'solutions', 'original_problem_file.pddl')
    
    # Folder containing problem files
    soldomain_folder = os.path.join(utils.get_project_root(), 'metric1_output', 'solutions', 'solDomain')
    
    # Folder to store generated plans
    plans_output_folder = os.path.join(utils.get_project_root(), 'metric1_output', 'plans')
    
    # Folder to store validation results
    results_folder = os.path.join(utils.get_project_root(), 'metric1_output','results', 'validations')

    # Clear previous outputs
    if os.path.exists(plans_output_folder):
        clear_folder(plans_output_folder)
    if os.path.exists(results_folder):
        clear_folder(results_folder)

    os.makedirs(plans_output_folder, exist_ok=True)
    os.makedirs(results_folder, exist_ok=True)

    solproblems = list(Path(soldomain_folder).glob("*.pddl"))
    if len(solproblems) == 1:
        # Only one solProblem file: use original_problem_file for plan generation
        problem_file = str(solproblems[0])
        plan_file_name = f"plan_{Path(problem_file).stem}.txt"
        output_plan_file = os.path.join(plans_output_folder, plan_file_name)
        print(f"Creating plan for original problem file: {original_problem_file}")
        create_plan(domain_file, original_problem_file, output_plan_file)
        # Validate plan with the single solProblem file
        print(f"Validating plan {output_plan_file} with problem file: {problem_file}")
        validate_plan(domain_file, problem_file, output_plan_file, results_folder)
    else:
        # Multiple solProblem files: standard logic
        for problem_file in solproblems:
            problem_file = str(problem_file)
            plan_file_name = f"plan_{Path(problem_file).stem}.txt"
            output_plan_file = os.path.join(plans_output_folder, plan_file_name)
            print(f"Creating plan for problem file: {problem_file}")
            create_plan(domain_file, problem_file, output_plan_file)
            for other_problem_file in solproblems:
                other_problem_file = str(other_problem_file)
                if other_problem_file != problem_file:
                    print(f"Validating plan {output_plan_file} with problem file: {other_problem_file}")
                    validate_plan(domain_file, other_problem_file, output_plan_file, results_folder)

if __name__ == "__main__":
    main()
