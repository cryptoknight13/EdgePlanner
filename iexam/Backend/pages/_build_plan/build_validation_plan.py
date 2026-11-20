import os
import platform
import subprocess
import logging
from pathlib import Path

CURR_DIR = os.path.dirname(os.path.abspath(__file__))


def _val_binary():
    """Resolve VAL Validate binary path for the current platform."""
    override = os.environ.get("VAL_BIN_PATH")
    if override:
        return override
    arch_dir = 'linux64' if platform.system() == 'Linux' else 'macos64'
    return os.path.join(CURR_DIR, '..', '..', 'VAL', 'build', arch_dir,
                        'Release', 'bin', 'Validate')

# Configure logging
logging.basicConfig(
    filename=os.path.join(CURR_DIR, '../../../Logs/log.txt'),  # Log file name
    level=logging.INFO,            # Log level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    filemode='a' 
)
def validate_plan(domain_file, problem_file, plan_file):
    """
    Validate a plan using the VAL tool.
    """
    try:
        logging.info("Starting plan validation.")
        logging.info(f"Domain file: {domain_file}")
        logging.info(f"Problem file: {problem_file}")
        logging.info(f"Plan file: {plan_file}")

        # Command to run VAL
        VAL_file_path = _val_binary()
        command = [VAL_file_path, domain_file, problem_file, plan_file]
        logging.info(f"Running command: {' '.join(command)}")

        # Run the VAL tool
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Log the output and errors
        if result.returncode == 0:
            logging.info("Plan validation successful.")
            logging.info(f"VAL Output:\n{result.stdout}")
            print("Plan validation successful.")
            print(result.stdout)
        else:
            logging.error("Plan validation failed.")
            logging.error(f"VAL Error:\n{result.stderr}")
            print("Plan validation failed.")
            print(result.stderr)

    except Exception as e:
        logging.error(f"An error occurred during plan validation: {e}")
        print(f"An error occurred: {e}")
        raise

def main():
    # Replace these paths with the actual paths to your files
    domain_file = os.path.join(CURR_DIR, "../../pddl/NetDomain.pddl")
    problem_file = os.path.join(CURR_DIR, "../../pddl/NetProblem.pddl")
    plan_file = os.path.join(CURR_DIR, "results/optimal_plan.txt")

    # Validate the plan
    validate_plan(domain_file, problem_file, plan_file)

if __name__ == "__main__":
    main()