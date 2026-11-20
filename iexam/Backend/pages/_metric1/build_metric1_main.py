import os
import sys
import csv
import ast
import subprocess
import shutil
import re
import json
from datetime import datetime

CURR_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(os.path.join(CURR_DIR, '../handler'))
# from build_api import process_explanation_file
# from build_explanation import extract_plan
from Metric1.no_heuristic.src import Metric1_Network_No_Heuristic
from Metric1.with_heuristic.src import Metric1_Network_With_Heuristic
import utils
from build_helpers import *
from build_llm_for_options import convert_options_to_natural_language
from build_solutions_domain import *	

import logging
logging.basicConfig(
    filename=os.path.join(CURR_DIR, '../../../Logs/log.txt'),  # Log file name
    level=logging.INFO,            # Log level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    filemode='a' 
)

# def _plan_exists(plan_path):
#     return os.path.isfile(plan_path) and os.path.getsize(plan_path) > 0

# def _build_problem_with_changes(original_problem_file, out_path, changes, goal_atom):
#     """
#     Build a problem variant that applies ONLY `changes`.
#     Reuses your implement_solution (which removes given keywords and writes goal).
#     """
#     implement_solution(original_problem_file, out_path, changes, goal_atom)

# def _repair_via_validator(domain_path, problem_path, plan_path):
#     """
#     Run VAL and parse into (plan_repair_info, explanation).
#     """
#     result = validate_plan(domain_path, problem_path, plan_path)
#     plan_repair_info, explanation = parse(result)
#     return plan_repair_info, explanation

# def dual_failure_probe_two_changes(solution_domain_file,
#                                    original_problem_file,
# 								   chosen_solution,
#                                    changeA, changeB,
#                                    goal_atom,
#                                    baseline_plan_path):
#     """
#     Return a dict with repair info for A and B using your described flow.
#     """
#     root = utils.get_project_root()
#     # Problems with single changes
#     prob_only_B = os.path.join(root, 'metric1_output','solutions', 'SolProblem_only_B.pddl')
#     prob_only_A = os.path.join(root, 'metric1_output', 'solutions', 'SolProblem_only_A.pddl')
#     _build_problem_with_changes(original_problem_file, prob_only_B, [changeB], goal_atom)
#     _build_problem_with_changes(original_problem_file, prob_only_A, [changeA], goal_atom)
	

#     # Try planning with only-B
#     plan_only_B = os.path.join(root, 'plans', 'plan_only_B.sas')
#     create_plan(solution_domain_file, prob_only_B, plan_only_B)

# 	 # Now do the symmetric path for A (we still want its failure):
#     plan_only_A = os.path.join(root, 'plans', 'plan_only_A.sas')
#     create_plan(solution_domain_file, prob_only_A, plan_only_A)

#     repairs = {"A": None, "B": None, "meta": {}}

#     if _plan_exists(plan_only_B):
#         # We have a plan that survives change-B. Attribute A by breaking that plan on P_A.
#         rep_A, exp_A = _repair_via_validator(solution_domain_file, prob_only_A, plan_only_B)
#         # Attribute B by breaking the baseline plan on P_B (shows earliest B-caused failure).
#         rep_B, exp_B = _repair_via_validator(solution_domain_file, prob_only_B, plan_only_A)

#         repairs["A"] = {
#             "change": changeA,
#             "plan_used": "plan_only_B",
#             "plan_path": plan_only_B,
#             "plan_repair_info": rep_A,
#             "explanation": exp_A
#         }
#         repairs["B"] = {
#             "change": changeB,
#             "plan_used": "baseline",
#             "plan_path": plan_only_A,
#             "plan_repair_info": rep_B,
#             "explanation": exp_B
#         }
#     else:
        
# 		# No plan with only-B → B blocks planning alone. Get B’s repair via baseline plan on P_B.
#         rep_B, exp_B = _repair_via_validator(solution_domain_file, prob_only_B, plan_only_A)

#         # The simplest & most faithful way to attribute A is to validate the baseline plan on P_A.
#         rep_A, exp_A = _repair_via_validator(solution_domain_file, prob_only_A, plan_only_B)

#         repairs["B"] = {
#             "change": changeB,
#             "plan_used": "baseline",
#             "plan_path": plan_only_A,
#             "plan_repair_info": rep_B,
#             "explanation": exp_B
#         }
#         repairs["A"] = {
#             "change": changeA,
#             "plan_used": "baseline",
#             "plan_path": plan_only_B,
#             "plan_repair_info": rep_A,
#             "explanation": exp_A
#         }

#     # Optional: include which problems/plans were used for traceability
#     repairs["meta"] = {
#         "prob_only_A": prob_only_A,
#         "prob_only_B": prob_only_B
#     }
#     return repairs
# def normalize_changes(changes, original_problem_file=None):
#     """
#     Return a stable list of change atoms from a list/tuple/set/str.
#     If a set is given, sort it for deterministic order.
#     Optionally, stabilize by their first occurrence order in the original problem file.
#     """
#     if isinstance(changes, str):
#         seq = [changes]
#     elif isinstance(changes, (list, tuple)):
#         seq = list(changes)
#     elif isinstance(changes, (set, frozenset)):
#         seq = sorted(list(changes))  # lexicographic fallback
#         if original_problem_file:
#             try:
#                 with open(original_problem_file, 'r') as f:
#                     text = f.read()
#                 pos = {kw: text.find(kw.replace('has-initial-state-', '', 1)) for kw in seq}
#                 seq.sort(key=lambda k: (pos.get(k, 10**9), k))
#             except Exception:
#                 pass
#     else:
#         raise TypeError(f"Unsupported type for changes: {type(changes)}")
#     return seq








# def implement_solution(input_file, output_file, keywords, goal):
# 	with open(input_file, 'r') as file:
# 		lines = file.readlines()
	
# 	# Prepare the keywords we need to remove (after 'has-initial-state-')
# 	keywords_to_remove = {kw.replace('has-initial-state-', '', 1) for kw in keywords}
# 	goalSection = False
# 	with open(output_file, 'w') as file:
# 		for line in lines:
# 			if not any(keyword in line for keyword in keywords_to_remove):
# 				if '(:goal' in line:
# 					goalSection = True
# 					file.write(line)
# 					continue
# 				if not goalSection:
# 					file.write(line)
# 				if goalSection:
# 					file.write(f"               ({goal})\n  ))\n)")
# 					break




def parse(result):
	raw_file = os.path.join(utils.get_project_root(), 'parsed', get_unique_filename("raw"))
	with open(raw_file, 'w') as file:
		# Write the explanation string to the file
		raw_output = result
		file.write(raw_output + '\n')

	print('Parsing output ...')
	explanation_file = os.path.join(utils.get_project_root(), 'parsed', get_unique_filename("explanation"))
	# parse_output(raw_file, explanation_file)
	# plan_repair_info = extract_plan_repair_info(raw_file, explanation_file)
	# explanation = process_explanation_file(explanation_file)

	# return plan_repair_info, explanation

def get_unique_filename(base_filename):
	timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
	return f"{base_filename}_{timestamp}.txt"

def extract_cost(filename):
	cost = None
	flip = False
	flip_count = 0
	with open(filename, 'r') as file:
		for line in file:
			if "(flip )" in line:
				flip = True
				flip_count += 1
			if not flip:
				flip_count += 1
			if "; cost =" in line:
				cost_part = line.split('; cost =')[1].strip()
				cost = float(cost_part.split()[0])
	return cost if not flip else cost - flip_count


def pick_plan(plan_path_1, plan_path_2):
	cost_1 = extract_cost(plan_path_1)
	cost_2 = extract_cost(plan_path_2)
	print("Menu:")
	print(f"1. Cost from file 1: {cost_1}")
	print(f"2. Cost from file 2: {cost_2}")
	
	while True:
		choice = input("Choose a cost (1 or 2): ")
		if choice == '1':
			print(f'Cost changes from {cost_2} to {cost_1}')
			return plan_path_1, cost_1
		elif choice == '2':
			print(f'Cost changes from {cost_1} to {cost_2}')
			return plan_path_2, cost_2
		else:
			print("Invalid choice, please enter 1 or 2.")	


def generate_json_m1(results_path, plan_path, json_file_path, goal, chosen_solution, plan_repair_info, explanation):
	with open(results_path, 'r') as file:
		reader = csv.DictReader(file)
		results_data = list(reader)
	
		if results_data and 'All Solutions' in results_data[0]:
			try:
				solutions = ast.literal_eval(results_data[0]['All Solutions'])

				readable_changes = all_solution_changes_toString(solutions)

				results_data[0]['All Solutions'] = readable_changes
			except Exception as e:
				print(f"Error parsing 'All Solutions': {e}")

	with open(plan_path, 'r') as file:
		lines = file.readlines()
		plan = []
		for line in lines:
			if "; cost =" in line:
				continue
			else:
				plan.append(line.strip())

	chosen_solution = chosen_solution_toString(chosen_solution)
	metric = 'Metric1'

	with open(json_file_path, 'w') as json_file:
		json_data = {
			'goal': goal,
			'metric': metric,
			'results': results_data,
			'plan': plan,
			'chosen_solution': list(chosen_solution),
			'plan_repair_info': plan_repair_info,
			'explanation': explanation

		}
		json.dump(json_data, json_file, indent=4)

def all_solution_changes_toString(solutions):
	all_changes = []
	for i, solution in enumerate(solutions, start=1):
		changes = []
		for entry in solution:
			entry = entry.replace('dot', '.')
			changes.append('a change in ' + entry.split(' ')[-1])
			changes[-1] = changes[-1].replace('-', ' ')
		changes_str = ' and '.join(changes)
		all_changes.append(changes_str)
	return all_changes

def chosen_solution_toString(chosen_solution):
	changes = []
	for entry in chosen_solution:
		entry = entry.replace('dot', '.')
		changed_str = 'a change in ' + entry.split(' ')[-1]
		changed_str = changed_str.replace('-', ' ')
		changes.append(changed_str)
	return changes

# base_dir =  os.path.dirname(os.path.abspath(__file__))
# goal_file = os.path.join(base_dir, "data", "goal.txt")  # Updated path to use a local 'data' directory

# # Ensure the file exists or prompt the user for input
# if not os.path.isfile(goal_file):
#     print("Goal file not found. Please enter the goal manually:")
#     goal = input("Enter the goal (1-6): ").strip()

#     # Save the goal to the file for future use
#     os.makedirs(os.path.dirname(goal_file), exist_ok=True)
#     with open(goal_file, 'w') as f:
#         f.write(goal)
#     print(f"Goal saved to {goal_file}")
# else:
#     # Read the goal from the file
#     with open(goal_file) as f:
#         goal = f.read().strip()

# print(f"Goal: {goal}")


import subprocess
base_dir =  os.path.dirname(os.path.abspath(__file__))
clean_up_path = os.path.join(base_dir, 'clean-result.py')
subprocess.run(['python3', clean_up_path], capture_output=True, text=True)

def goal_selection_mapping_M1():
    """
    Prompt the user to select a goal node and return the corresponding PDDL file.
    """
    goals = {
        1: 'web.pddl',
        2: 'admin.pddl',
        3: 'dns.pddl',
        4: 'ftp.pddl',
        5: 'mail.pddl',
        6: 'sql.pddl'
    }

    # Display the goal options to the user
    print("Select a goal node:")
    for key, value in goals.items():
        print(f"{key}: {value}")

    # Prompt the user for input
    while True:
        try:
            goal = int(input("Enter the number corresponding to your goal node (1-6): ").strip())
            if goal in goals:
                return goals[goal]
            else:
                print("Invalid choice. Please select a number between 1 and 6.")
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 6.")

def _dec_cost(m):
        prefix, num, suffix = m.groups()
        new_val = max(0, int(num) - 1)  # clamp at 0 just in case
        return f"{prefix}{new_val}{suffix}"

#def get_inputs():
 #   """
 ##  """

    # print("Select Metric Analysis:")
    # print("1. Metric1")
    # print("2. Metric2")
    # metric_choice = int(input("Enter your choice (1 or 2): ").strip())

    #print("\nSelect Heuristic Option:")
    #print("1. No Heuristic")
    #print("2. With Heuristic")
    #heuristic_choice = int(input("Enter your choice (1 or 2): ").strip())

    #return heuristic_choice

def analysis_prompt(choice):
    """
    Map metric choice to the corresponding analysis type.
    """
    if choice == 1:
        selected_analysis = 'Metric1'
    elif choice == 2:
        selected_analysis = 'Metric2'
    else:
        raise ValueError("Invalid metric choice. Please select 1 or 2.")
    return selected_analysis

def heuristic_prompt(choice):
    """
    Map heuristic choice to the corresponding heuristic type.
    """
    if choice == 1:
        selected_heuristic = 'no_heuristic'
    elif choice == 2:
        selected_heuristic = 'with_heuristic'
    else:
        raise ValueError("Invalid heuristic choice. Please select 1 or 2.")
    return selected_heuristic


def main():

	setup_output_dirs()

	heuristic_file_path = os.path.join(CURR_DIR, "data", "heuristic_option.txt")
	with open(heuristic_file_path, 'r') as f:
		heuristic_input = int(f.readline().strip())

	selected_heuristic = heuristic_prompt(heuristic_input)

	file_names = []
	result_file_base_name = ''

	chosen_func = None
	# selected_goal = 'admin.pddl'
	# file_names = [selected_goal]
		
	original_domain_file = os.path.join(utils.get_domain_path(), 'domain_template', 'NetDomain.pddl')
	original_problem_file = os.path.join(utils.get_domain_path(), 'solvable_domain', 'solvable.pddl')
	original_unsolv_problem_file = os.path.join(utils.get_domain_path(), 'unsolvable_domain', 'unsolvable.pddl')
	plan_path_1 = os.path.join(utils.get_project_root(), 'metric1_output', 'plans', f'initial_plan.txt')
	create_plan(original_domain_file, original_problem_file, plan_path_1)
	solution_domain_file = os.path.join(utils.get_project_root(), 'metric1_output','solutions', 'original_domain_file.pddl')
	shutil.copy(original_domain_file, solution_domain_file)
	solution_problem_file = os.path.join(utils.get_project_root(), 'metric1_output','solutions', 'original_problem_file.pddl')
	shutil.copy(original_problem_file, solution_problem_file)
	solution_unsolv_problem_file = os.path.join(utils.get_project_root(), 'metric1_output','solutions', 'original_unsolv_problem_file.pddl')
		

	if selected_heuristic == 'no_heuristic':
		result_file_base_name = 'results_m1_network_no_heuristic'
		chosen_func = Metric1_Network_No_Heuristic.run
	elif selected_heuristic == 'with_heuristic':
		result_file_base_name = 'results_m1_network_with_heuristic'
		chosen_func = Metric1_Network_With_Heuristic.run
	else:
		print('Error: invalid selection')
		sys.exit()
	
	
	chosen_func()
	result_file_path = os.path.join(utils.get_project_root(), 'metric1_output', 'results', f'{result_file_base_name}.csv')

	process_and_save_options_from_file(result_file_path)
		#fetch the solutions from pddl_options.txt and give user to select one

		# solutions_save(solutions)

		#fetch_and_save_user_selected_solution()
		#read the user selected solution from user_selected_solution.txt and get it as chosen_solution
		#user_selected_solution_file = os.path.join(utils.get_project_root(),'data','user_selected_option.txt')
		# chosen_solution = get_chosen_solution(user_selected_solution_file)
		# implement_solution(original_problem_file, solution_unsolv_problem_file, chosen_solution, goal)


		
	


		# chosen_solution = solutions[selected_solution - 1]
		# original_problem_file = os.path.join(utils.get_domain_path(), 'solv', file)
		# print(f'Original problem file: {original_problem_file}')
		# print(f'Original domain file: {original_domain_file}')
		# print(f'Chosen solution: {chosen_solution}')
		# # Copy domain file
		# solution_domain_file = os.path.join(utils.get_project_root(), 'solutions', 'SolDomain.pddl')
		# shutil.copy(original_domain_file, solution_domain_file)

		# # Create solution file - Original problem minus selected option
		# solution_problem_file = os.path.join(utils.get_project_root(), 'solutions', 'SolProblem.pddl')
		# implement_solution(original_problem_file, solution_problem_file, chosen_solution, goal)

		# chosen_plan = ''
		# if selected_analysis == 'Metric1':
		# 	plan_path_1 = os.path.join(utils.get_project_root(), 'plans', f'sas_plan.txt')
		# 	json_file_path = os.path.join(utils.get_project_root(), 'results_json', f'results.json')
		# 	create_plan(original_domain_file, original_problem_file, plan_path_1)
			
		# 	# chosen_plan = plan_path_1
		# 	# result = validate_plan(solution_domain_file, solution_problem_file, chosen_plan)
		# 	# plan_repair_info, explanation =  parse(result)
		# 	# generate_json_m1(result_file_path, plan_path_1, json_file_path, goal, chosen_solution, plan_repair_info, explanation)

		# 	result = validate_plan(solution_domain_file, solution_problem_file, plan_path_1)
		# 	combined_plan_repair_info, combined_explanation = parse(result)
		# 	chosen_solution_norm = normalize_changes(chosen_solution, original_problem_file)
		# 	if len(chosen_solution) == 2:
		# 		changeA, changeB = chosen_solution_norm[0], chosen_solution_norm[1]
		# 		dual_repairs = dual_failure_probe_two_changes(
		# 			solution_domain_file=solution_domain_file,
		# 			original_problem_file=original_problem_file,
		# 			chosen_solution=chosen_solution,
		# 			changeA=changeA,
		# 			changeB=changeB,
		# 			goal_atom=goal,
		# 			baseline_plan_path=plan_path_1
		# 		)
		# 		plan_repair_info = {
		# 			"combined": combined_plan_repair_info,
		# 			"per_change": dual_repairs
		# 		}
		# 		explanation = combined_explanation  # keep as-is; per-change explanations are inside dual_repairs
		# 	else:
		# 		plan_repair_info = combined_plan_repair_info
		# 		explanation = combined_explanation
		# 	generate_json_m1(result_file_path, plan_path_1, json_file_path, goal, chosen_solution, plan_repair_info, explanation)


if __name__=='__main__':
	main()

