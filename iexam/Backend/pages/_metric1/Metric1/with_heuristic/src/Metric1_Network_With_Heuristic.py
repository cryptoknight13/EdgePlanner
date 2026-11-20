import os
import time
import pandas as pd
from .Problem import Problem

from utils import get_domain_path
	
def solve_this(domain_path, problem_path):
	base_dir = os.path.dirname(os.path.abspath(__file__))
	script_path = os.path.abspath(os.path.join(base_dir, '../../../../../downward/fast-downward.py'))
	cmd = f'python3 {script_path} {domain_path} {problem_path} --search "astar(lmcut())" > /dev/null'
	os.system(cmd)
	plan =[]
	try:
		with open('sas_plan') as f:
			plan_len = 0
			for line in f:
				if line.strip().startswith(';'):
					break
				plan_len += 1
				plan.append(line.strip())
				
			#os.remove('sas_plan')
			#os.remove('output.sas')
			return plan, True, plan_len
	except FileNotFoundError:
		return plan,False, 0

def run():
	base_dir = os.path.dirname(os.path.abspath(__file__))
	os.chdir(base_dir)

	working_dir = get_domain_path()

	full_path = os.path.join(working_dir)

	df = pd.DataFrame({
		'Problem': pd.Series(dtype='object'),
		'Total Time': pd.Series(dtype='float'),
		'Solutions Length': pd.Series(dtype='int'),
		'Final Node Number': pd.Series(dtype='int'),
		'All Solutions': pd.Series(dtype='object'),
		'Solution Times': pd.Series(dtype='object'),
		'Solution Nodes': pd.Series(dtype='object')
	})
	model_robot = os.path.join(working_dir, 'domain_template', 'NetDomain.pddl')
	model_human = model_robot

	domain_template = os.path.join(working_dir, 'domain_template', 'NetDomain_template.pddl')

	problem_robot = os.path.join(working_dir, 'unsolvable_domain', 'unsolvable.pddl')
	hproblem = os.path.join(working_dir, 'solvable_domain', 'solvable.pddl')

	problem_template = os.path.join(working_dir, 'domain_template', 'NetProblem_template.pddl')


	ground = False
	approx =None
	heuristic = None
	# hproblem = None
	plan_file = None

	pr_obj = Problem(model_robot, model_human, problem_robot, domain_template,
			ground, approx, heuristic,
			problem_template, hproblem, plan_file)

	start_time = time.time()

	plan = pr_obj.MeSearch()

	end_time = time.time()

	total_time = end_time - start_time

	print("Execution time:", total_time)

	# print(model_robot)
	print(total_time, len(pr_obj.solutions), pr_obj.final_node_number)

	pr_obj.previous_difference

	new_row = pd.DataFrame({
		'Total Time': [total_time],
		'Solutions Length': [len(pr_obj.solutions)],
		'Final Node Number': [pr_obj.final_node_number],
		'All Solutions': [pr_obj.previous_difference],
		'Solution Times':[pr_obj.solution_time_list],
		'Solution Nodes':[pr_obj.solution_node_list]
	})

	df = pd.concat([df, new_row], ignore_index=True)

	# Write the DataFrame to a CSV file
	results_filename = f'results_m1_network_with_heuristic.csv'
	results_path = os.path.join('../../../metric1_output/results', results_filename)
	df.to_csv(results_path, index=False, header=True)

