import os
import logging
import sys

CURR_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.join(CURR_DIR, '../handler'))
from build_explanation import extract_plan
from build_api import process_explanation_file

# Configure logging
logging.basicConfig(
    filename=os.path.join(CURR_DIR, '../../../Logs/log.txt'),  # Log file name
    level=logging.INFO,            # Log level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    filemode='a' 
)

def generate_plan_explanation(input_plan_path, output_explanation_path):
    """
    Generate an explanation for the given plan.
    """
    try:
        logging.info("Starting the process to generate a plan explanation.")
        logging.info(f"Input plan file: {input_plan_path}")
        logging.info(f"Output explanation file: {output_explanation_path}")

        # Step 1: Extract the plan and write it to the output file with an explanation prompt
        logging.info("Extracting the plan and adding explanation prompt...")
        prompt_file = os.path.join(CURR_DIR, "inputs/prompt.txt")  # Specify the path to the prompt file
        extract_plan(input_plan_path, prompt_file, output_explanation_path)
        logging.info("Plan extracted and explanation prompt added.")

        # Step 2: Process the explanation file to get the explanation
        logging.info("Generating explanation for the plan...")
        explanation = process_explanation_file(output_explanation_path)

        if explanation:
            logging.info("Explanation generated successfully.")
            logging.info("Writing explanation to the output file.")

            # Overwrite the output file with only the explanation
            with open(output_explanation_path, 'w') as output_file:
                output_file.write(explanation)

            logging.info("Explanation written to the output file.")
        else:
            logging.warning("Failed to generate an explanation for the plan.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")

def main():
    # Input and output file paths
    input_plan_path = os.path.join(CURR_DIR, "results/optimal_plan.txt")  # Replace with the path to your plan file
    output_explanation_path = os.path.join(CURR_DIR, "results/explanation_for_plan.txt")  # Output file for explanation

    # Ensure the results directory exists
    os.makedirs(os.path.dirname(output_explanation_path), exist_ok=True)

    # Generate the plan explanation
    generate_plan_explanation(input_plan_path, output_explanation_path)

if __name__ == "__main__":
    main()