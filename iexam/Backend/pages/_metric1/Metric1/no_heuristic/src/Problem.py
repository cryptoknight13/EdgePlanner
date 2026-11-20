#!/usr/bin/env python

'''
Topic   :: Environment definition
Project :: Explanations for Multi-Model Planning
Author  :: Tathagata Chakraborti
Date    :: 09/29/2016
'''

from .PDDLhelp import *
from .Search   import *
import copy
import time

from utils import get_domain_path

'''
Class :: Environment Definition
'''

def is_superset_of_any_solution(new_state, solution_list):
    # print(new_state)
    for sol in solution_list:
        if new_state >= sol:
            return True
    return False

class Problem:

    def __init__(self, robotModelFile, humanModelFile, robotProblemFile, domainTemplate,
                 ground_flag, approx_flag, heuristic_flag,
                 problemTemplate, humanProblemFile, robotPlanFile=None):

        print ("Setting up MMP...")

        if humanProblemFile == None:
            humanProblemFile = robotProblemFile

        #new list
        self.solutions = []
        self.previous_difference = []

        self.domainTemplate = domainTemplate
        self.problemTemplate = problemTemplate
        self.approx_flag = approx_flag
        self.heuristic_flag = heuristic_flag
        self.ground_flag = ground_flag
        self.k_plan_list = []
        self.solution_time_list =[]
        self.solution_node_list =[]
        self.final_node_number = 0
        self.start_time = time.time()

        if not robotPlanFile:
            self.robotPlanFile   = os.path.join(get_domain_path(), 'cache_plan.dat')
            self.plan, self.cost = get_plan(robotModelFile, robotProblemFile)

            with open(self.robotPlanFile, 'w') as plan_file:
                if self.ground_flag:
                    plan_file.write('\n'.join(['({})'.format(item.replace(' ', '_')) for item in self.plan]) + '\n; cost = {} (unit cost)'
                                    .format(self.cost))
                else:
                    plan_file.write('\n'.join(['({})'.format(item) for item in self.plan]) + '\n; cost = {} (unit cost)'
                                    .format(self.cost))
        else:
            self.robotPlanFile   = robotPlanFile
            with open(robotPlanFile, 'r') as plan_file:
                temp      = plan_file.read().strip().split('\n')
                self.plan = temp[:-1]
                self.cost = int(temp[-1].split(' ')[3].strip())


        self.groundedRobotPlanFile   = os.path.join(get_domain_path(), 'cache_grounded_plan.dat')

        with open(self.groundedRobotPlanFile, 'w') as plan_file:
            plan_file.write('\n'.join(['({})'.format(item) for item in self.plan]) + '\n; cost = {} (unit cost)'
                            .format(self.cost))

        #if self.ground_flag:
        #    ground(robotModelFile, robotProblemFile)
        #    self.robot_state = read_state_from_domain_file('tr-domain.pddl','tr-problem.pddl')
        #    ground(humanModelFile, humanProblemFile)
        #    self.human_state = read_state_from_domain_file('tr-domain.pddl','tr-problem.pddl')
        #else:
        self.robot_state = read_state_from_domain_file(robotModelFile, robotProblemFile)
        self.human_state = read_state_from_domain_file(humanModelFile, humanProblemFile)
        #temp_plan, temp_cost = get_plan(humanModelFile, humanProblemFile)

        #if self.approx_flag:
        #    if self.ground_flag:
        #        ground(humanModelFile, humanProblemFile)
        #    else:
        create_temp_files(humanModelFile, humanProblemFile)
        self.groundedHumanPlanFile = os.path.join(get_domain_path(), 'cache_human_grounded_plan.dat')
        grounded_human_plan, self.human_grounded_plan_cost = get_plan('tr-domain.pddl', 'tr-problem.pddl')
        self.grounded_human_plan =  set([i for i in grounded_human_plan])
    
    def add_solution(self, new_solution):
        self.solutions.append(new_solution)
    
    def get_solution(self):
        return self.solutions
    
    
    def MeSearch(self):
        self.initialState = copy.copy(self.human_state)
        self.goalState = copy.copy(self.robot_state)
        plan = astarSearch(self)
        #print(self.initialState)
        return plan

    def MCESearch(self):

        self.initialState = copy.copy(self.robot_state)
        self.goalState = copy.copy(self.human_state)
        k_plan = BFSearch(self)
        #(set(k_plan))
        return list(((set(self.initialState) - set(self.human_state))| (set(self.human_state) - set(self.initialState)))
                    - set(k_plan))

    def getStartState(self):
        return self.initialState

    def isGoal(self, state):
        if self.approx_flag:
            return self.approx_isGoal(state)
        return self.orig_isGoal(state)

    def orig_isGoal(self, state):
        if is_superset_of_any_solution(set(self.human_state) - set(state), self.previous_difference):
            return (False, [])
        temp_domain, temp_problem = write_domain_file_from_state(state, self.domainTemplate, self.problemTemplate)
        #feasibility_flag = validate_plan(temp_domain, temp_problem, self.groundedRobotPlanFile)
        #print(feasibility_flag)

        plan_list_for_this_node = self.get_k_plan_list(temp_domain,temp_problem, 1 )
        # input()
        self.k_plan_list = plan_list_for_this_node
        # plan, cost       = get_plan(temp_domain, temp_problem)
        # optimality_flag  = cost == self.cost
        # TODO: Check plan is empty or not
        # if not add them to the set of solution
        #DOn't check the optimality:
        optimality_flag = False

        # solution_list = self.solutions

        if len(plan_list_for_this_node) == 0:
            optimality_flag = True

            self.add_solution(set(state))
            self.previous_difference.append(set(self.human_state) - set(state))
            #print(set(self.human_state) - set(state))
        if len(self.solutions) == 5:
            return (True, self.solutions)
        return (optimality_flag, plan_list_for_this_node)

    def approx_isGoal(self, state):
        temp_domain, temp_problem = write_domain_file_from_state(state,  self.domainTemplate, self.problemTemplate)

        if not validate_plan(temp_domain, temp_problem, self.groundedRobotPlanFile):
            #fail_pos = find_fail_point(temp_domain, temp_problem, self.groundedRobotPlanFile)
            return (False, list(self.plan)) #[ : min(fail_pos + 1 ,len(self.grounded_robot_plan) ) ])

        if self.human_grounded_plan_cost > 0 and self.human_grounded_plan_cost <= self.cost and \
                validate_plan(temp_domain, temp_problem, self.groundedHumanPlanFile):
            return (False, self.plan)

        graph_test_result = plan_graph_test(temp_domain, temp_problem, self.groundedRobotPlanFile)
        return (graph_test_result, self.plan)
    
    def heuristic(self, state):
        return 0.0

    
    def getSuccessors(self, node, old_plan = None):
        if self.heuristic_flag:
            return self.heuristic_successors(node, old_plan)
        return self.ordinary_successors(node)
    
    

    def ordinary_successors(self, node):


        #helper function

        optplanlength = 0
        listOfSuccessors = []

        state            = set(node[0])
        ground_state     = set(copy.copy(self.goalState))

        add_set          = ground_state.difference(state)
        del_set          = state.difference(ground_state)

       # difference = set(self.human_state) - set(state)
       # print("Difference between the human model and the current state:", difference)


    #690 -38 
        for item in add_set:
            new_state    = copy.deepcopy(state)
            new_state.add(item)
            current_difference = set(self.human_state) - set(new_state)
            #print(current_difference)

            
            if is_superset_of_any_solution(current_difference, self.previous_difference):
                listOfSuccessors.append([list(new_state), item])
            


               # optplanlength = len(new_state)
    

            # print("New State:", new_state)
            # listOfSuccessors.append([list(new_state), item])
            # if not any(set(new_state).issuperset(s) for s in solution_list):
            #     listOfSuccessors.append([list(new_state), item])
            #     # print("NNoooooooooooooooot SUPERSET")
        for item in del_set:
            new_state    = copy.deepcopy(state)
            new_state.remove(item)

            current_difference = set(self.human_state) - set(new_state)

            
            if not is_superset_of_any_solution(current_difference, self.previous_difference):
                listOfSuccessors.append([list(new_state), item])
            



            #if not is_subset_of_any_solution(new_state, self.solutions):
           # if len(new_state) <= optplanlength:
            #listOfSuccessors.append([list(new_state), item])
                #optplanlength = len(new_state)
 
            # # listOfSuccessors.append([list(new_state), item])
            # if not any(set(new_state).issuperset(s) for s in solution_list):
            #     listOfSuccessors.append([list(new_state), item])
        #print(self.previous_difference)
        return listOfSuccessors


    def heuristic_successors(self, node, old_plan):
        listOfSuccessors = []

        state = set(node[0])
        ground_state = set(self.robot_state)

        all_relevent_actions = set([i.lower().split()[0] for i in old_plan]) | set(
        [j.lower().split()[0] for j in self.plan])

        add_set = ground_state.difference(state)
        del_set = state.difference(ground_state)

        for item in add_set:
            if item.split('-has-')[0].lower() in all_relevent_actions:
                new_state = copy.deepcopy(state)
                new_state.add(item)
                listOfSuccessors.append([list(new_state), item])

        for item in del_set:
            if item.split('-has-')[0] in all_relevent_actions:
                new_state = copy.deepcopy(state)
                new_state.remove(item)
                listOfSuccessors.append([list(new_state), item])

        return listOfSuccessors
    def get_k_plan_list(self, domain_path, problem_path, top_k):
        # Save the current working directory
        original_directory = os.path.dirname(os.path.abspath(__file__)) 

        # print("domain_path", domain_path)

        domain_full_path = original_directory + "/" + domain_path
        problem_full_path = original_directory + "/" + problem_path

        # Define the script name and working directory
        script_name = "plan_topk.sh"
        working_directory = os.path.abspath(os.path.join(original_directory, '../../../../../forbiditerative'))
        plans_directory = os.path.join(working_directory, "found_plans", "done")

        # print("domain_full_path",domain_full_path)
        # Combine the command and arguments into a single string
        command = f"./{script_name} {domain_full_path} {problem_full_path} {top_k}"

        # Change the current working directory to where the script is located
        os.chdir(working_directory)

        # Run the command
        status = os.system(command)

        # Check if the command was executed successfully
        if status == 0:
            # print("Script executed successfully!")
            a=1
        else:
            # print("Error in script execution")
            # Return to the original working directory before exiting
            os.chdir(original_directory)
            return []

        # List all files starting with "sas_" in the specified directory and create full paths
        plan_files = [os.path.join(plans_directory, file) for file in os.listdir(plans_directory) if file.startswith("sas_")]



        # Return to the original working directory
        os.chdir(original_directory)

        # Return the sorted list of full paths to the plan files
        return plan_files


