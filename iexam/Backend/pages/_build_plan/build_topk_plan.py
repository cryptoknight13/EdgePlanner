import logging
import os
import sys
import json
from pathlib import Path
# Add forbiditerative package path if not globally installed

CURR_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.join(CURR_DIR, '../../forbiditerative'))
print(sys.path)
from forbiditerative import planners # Assuming planners module is available

# Configure logging
#logging.basicConfig(
#    filename='log_results/topk_plan_log.txt',  # Log file name
#    level=logging.INFO,            # Log level
#    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
#    filemode='w'  # Overwrite log file on each run
#)
 
def save_plan_to_results(plan_data, plan_name):
    """
    Save the plan data to the results directory.
    """
    results_dir = os.path.join(CURR_DIR, "results")
    os.makedirs(results_dir, exist_ok=True)  # Create the directory if it doesn't exist
    output_path = os.path.join(results_dir, plan_name)
 
    with open(output_path, 'w') as file:
        file.write(plan_data)
 
    #logging.info(f"Plan saved to {output_path}")
    return output_path


def main():
    try:
        #logging.info("Starting top-k plan generation.")
 
        # Define the number of plans to generate
        #number_of_plans = 2  # You can change this value as needed
        k_env = os.environ.get("TOPK_K")
        number_of_plans = int(k_env) if k_env and k_env.isdigit() else 2    
 
        # Generate top-k plans
        domain_file = Path(os.path.join(CURR_DIR, "../../pddl/Netdomain.pddl"))  # Replace with actual domain file path
        problem_file = Path(os.path.join(CURR_DIR, "../../pddl/newNetproblem.pddl"))  # Replace with actual problem file path
        plans = planners.plan_topk(domain_file=domain_file, problem_file=problem_file, number_of_plans_bound=number_of_plans)
        
        if plans:
             output_file = Path(os.path.join(CURR_DIR, "results/topk_plans.json"))
             with open(output_file, 'w') as f:
                json.dump(plans, f, indent=2)
             print(f"Saved {number_of_plans} plans to {output_file.resolve()}")
        #else:
            #logging.warning("No plans found. Please check domain and problem definitions.")
 
        #logging.info("Top-k plan generation completed successfully.")
 
    except Exception as e:
        #logging.error(f"An error occurred: {e}")
        raise
 
if __name__ == "__main__":
    main()