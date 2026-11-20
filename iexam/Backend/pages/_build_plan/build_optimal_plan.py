import os
import json
import logging
import subprocess

CURR_DIR = os.path.dirname(os.path.abspath(__file__))

# Configure logging
logging.basicConfig(
    filename=os.path.join(CURR_DIR, '../../../Logs/log.txt'),  # Log file name
    level=logging.INFO,            # Log level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    filemode='a' 
)

# Check for the existence of the plan file
def _plan_exists(plan_path):
    return os.path.isfile(plan_path) and os.path.getsize(plan_path) > 0

def generate_plan(domain_path, problem_path, plan_path):
    """
    Generate a plan using the planner.
    """
    downward_file_path = os.path.join(CURR_DIR, '../../downward/fast-downward.py')
    downward_command = [
        downward_file_path,
        '--plan-file', plan_path,
        domain_path, problem_path,
        '--search', 'astar(lmcut())'
    ]
    subprocess.run(downward_command, check=True)
    if not _plan_exists(plan_path):
        raise FileNotFoundError(f"Plan file not generated at {plan_path}")
    logging.info(f"Plan generated at {plan_path}")

def extract_plan_cost(plan_path):
    """
    Extract the cost of the plan from the generated plan file.
    """
    cost = None
    with open(plan_path, 'r') as file:
        for line in file:
            if "; cost =" in line:
                cost = int(line.split('=')[-1].strip().split()[0])
                break
    if cost is None:
        raise ValueError("Cost not found in the plan file.")
    logging.info(f"Plan cost: {cost}")
    return cost

def save_plan_to_json(plan_path, domain_path, problem_path, cost, output_json_path):
    """
    Save the plan details into a JSON file.
    """
    with open(plan_path, 'r') as file:
        plan_steps = [line.strip() for line in file if not line.startswith(";")]

    json_data = {
        "domain": domain_path,
        "problem": problem_path,
        "plan": plan_steps,
        "cost": cost
    }

    with open(output_json_path, 'w') as json_file:
        json.dump(json_data, json_file, indent=4)
    logging.info(f"Plan details saved to {output_json_path}")

def main():
    domain_path = os.path.join(CURR_DIR, "../../pddl/NetDomain.pddl")
    problem_path = os.path.join(CURR_DIR, "../../pddl/newNetProblem.pddl")
    plan_path = os.path.join(CURR_DIR, "results/optimal_plan.txt")
    output_json_path = os.path.join(CURR_DIR, "results/optimal_plan.json")

    try:
        # Step 1: Generate the plan
        logging.info("Starting plan generation.")
        generate_plan(domain_path, problem_path, plan_path)
        logging.info(f"Plan generated and saved to {plan_path}.")

        # Step 2: Extract the cost of the plan
        logging.info("Extracting plan cost.")
        cost = extract_plan_cost(plan_path)
        logging.info(f"Plan cost extracted: {cost}.")

        # Step 3: Save the plan details to JSON
        logging.info("Saving plan details to JSON.")
        save_plan_to_json(plan_path, domain_path, problem_path, cost, output_json_path)
        logging.info("Plan details successfully saved to JSON.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        raise

if __name__ == "__main__":
    main()