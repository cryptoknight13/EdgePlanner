import os
import utils
import subprocess
import csv
import ast

def setup_output_dirs():
	project_root = utils.get_project_root()
	make_or_clear_dir(os.path.join(project_root, 'metric1_output', 'results'))
	make_or_clear_dir(os.path.join(project_root, 'metric1_output','plans'))
	make_or_clear_dir(os.path.join(project_root, 'metric1_output', 'solutions'))
	make_or_clear_dir(os.path.join(project_root, 'metric1_output', 'parsed'))


def make_or_clear_dir(dir):
	if not os.path.exists(dir):
		os.makedirs(dir)
	else:
		clear_dir(dir)

def clear_dir(dir):
	for item in os.listdir(dir):
		item_path = os.path.join(dir, item)
		if os.path.isfile(item_path):
			os.remove(item_path)
		else:
			print(f'Ignoring subdirectory: {item_path}')

def create_plan(domain_path, problem_path, plan_path):
	original_dir = os.getcwd()
	os.chdir(utils.get_project_root())
	downward_command = ['../../downward/fast-downward.py','--plan-file', plan_path, domain_path, problem_path, 
		'--search', 'astar(lmcut())' ]
	subprocess.run(downward_command)
	os.chdir(original_dir)

### New functions for processing CSV and and extract all the options ###
def process_and_save_options_from_file(filename):
    """
    Process solutions from a CSV file and save them to pddl_options.txt in the data directory.
    """
    # Ensure the data directory exists

    # Path to the output file
    output_file = os.path.join(utils.get_project_root(), 'data', "pddl_options.txt")

    # Read and process solutions from the CSV file
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Read the 'All Solutions' field and convert it to a Python list
            solutions_str = row['All Solutions']
            solutions = ast.literal_eval(solutions_str)

            # Save the solutions to the output file
            with open(output_file, 'w') as output:
                for solution in solutions:
                    output.write(f"{solution}\n")
    print(f"All options saved to {output_file}")

    # llm_for_options = os.path.join(utils.get_project_root(), "build_llm_for_options.py")
    # subprocess.run(["python", llm_for_options])

    return solutions

### New function to fetch options from pddl_options.txt and prompt user to select one ###
def fetch_and_save_user_selected_solution():
    """
    Fetch solutions from pddl_options.txt, prompt the user to select one, and save the selected solution to user_selected_option.txt.
    """
    # Path to the pddl_options.txt file
    options_file = os.path.join(utils.get_project_root(), 'data', "pddl_options.txt")
    selected_option_file = os.path.join(utils.get_project_root(), 'data', "user_selected_option.txt")

    # Check if the file exists
    if not os.path.isfile(options_file):
        print(f"Error: {options_file} does not exist.")
        return None

    # Read solutions from the file
    with open(options_file, 'r') as file:
        solutions = [line.strip() for line in file.readlines()]

    # Check if there are any solutions
    if not solutions:
        print("No solutions found in pddl_options.txt.")
        return None

    # Display solutions to the user
    print("Available Solutions:")
    for idx, solution in enumerate(solutions, start=1):
        print(f"{idx}: {solution}")

    # Prompt the user to select a solution
    while True:
        try:
            choice = int(input(f"Select a solution (1-{len(solutions)}): ").strip())
            if 1 <= choice <= len(solutions):
                selected_solution = solutions[choice - 1]
                print(f"Selected Solution: {selected_solution}")

                # Save the selected solution to user_selected_option.txt
                os.makedirs(os.path.dirname(selected_option_file), exist_ok=True)
                with open(selected_option_file, 'w') as file:
                    file.write(selected_solution)

                print(f"Selected solution saved to {selected_option_file}")
                return selected_solution
            else:
                print(f"Invalid choice. Please select a number between 1 and {len(solutions)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")