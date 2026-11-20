#!/usr/bin/env python

'''
Topic   :: Help with PDDL stuff
Project :: Explanations for Multi-Model Planning
Author  :: Tathagata Chakraborti
Date    :: 09/29/2016
'''

import re, os
import subprocess

'''
Method :: write domain file from given state
'''

def write_domain_file_from_state(state, domain_source, problem_source):

    predicateList = set()
    actionList    = {}
    init_state_list = []
    goal_state_list =[]

    for item in state:
        if "state" not in item:
            regex_probe   = re.compile("(.*)-has-(parameters|negprecondition|precondition|add-effect|delete-effect)-(.*)$").search(item)
            actionName    = regex_probe.group(1)
            _condition    = regex_probe.group(2)
            predicateName = regex_probe.group(3)

            predicateList.add(predicateName)

            if actionName not in actionList: actionList[actionName] = {'parameters':"", 'precondition' : [], 'negprecondition' : [], 'add-effect' : [], 'delete-effect' : []}
            if _condition == 'parameters':
                actionList[actionName][_condition] = predicateName
            else:
                actionList[actionName][_condition].append(predicateName) 
        else:
            regex_probe   = re.compile("has-(initial|goal)-state-(.*)$").search(item)
            state_type = regex_probe.group(1)
            pred = regex_probe.group(2)
            if state_type == 'initial':
                init_state_list.append('({})'.format(' '.join(pred.split('@'))))
            else:
                goal_state_list.append('({})'.format(' '.join(pred.split('@'))))

    temp_domainFileName = 'temp.pddl'
    temp_problemFileName = 'temp_prob.pddl'

    with open(domain_source, 'r') as template_domain_file:
        template_domain = template_domain_file.read()

    with open(problem_source, 'r') as template_prob_file:
        template_problem = template_prob_file.read()



    with open(temp_domainFileName, 'w') as temp_domain_file:

        predicateString = '\n'.join(['( {} )'.format(item) if item != '' else '' for item in predicateList])
        actionString    = '\n'.join(['(:action {}\n:parameters ({})\n:precondition\n(and\n{}\n)\n:effect\n(and\n{}\n)\n)\n'\
                                     .format(key, actionList[key]['parameters'],'\n'.join(['( {} )'.format(p) for p in actionList[key]['precondition']]) + '\n'+
                                             '\n'.join(['(not ( {} ) )'.format(p) for p in actionList[key]['negprecondition']]), \
                                             '{}\n{}'.format('\n'.join(['( {} )'.format(p) for p in actionList[key]['add-effect']]), \
                                                             '\n'.join(['(not ( {} ))'.format(p) for p in actionList[key]['delete-effect']]))) for key in actionList.keys()])

        template_domain = template_domain.replace('%PREDICATES%',predicateString)
        temp_domain_file.write(template_domain.replace('%OPERATORS%',actionString))

    with open(temp_problemFileName, 'w') as temp_problem_file:
        template_problem = template_problem.replace('%INIT%','\n'.join(init_state_list))
        template_problem = template_problem.replace('%GOAL%','\n'.join(goal_state_list))
        temp_problem_file.write(template_problem) 
    return (temp_domainFileName, temp_problemFileName)
        

'''
Method :: read state from given domain file
'''

def read_state_from_domain_file(domainFileName, problemFileName):

    def PDDLaction(description):
        action_name            = re.search(r'\(:action(.*?)[\s+]*:', description).group(1).strip()

        try:    parameters     = re.search(r':parameters[\s+]*\((.*?)\)[\s+]*:', description).group(1)
        except: parameters     = ""
        try:    preconditions  = {re.search(r'\(((?!not).*?)\)', item).group(1).strip() : not 'not ' in item \
                                  for item in re.findall('(\(not[\s+]*\(.*?\)[\s+]*\)|\(.*?\))',
                                                         re.search(r':precondition[\s+]*\(and(.*?)\)[\s+]*:',
                                                                   description).group(1))}

        except: preconditions  = {}
        try:
            #all_effects = [item for item in
            #               re.findall('(\(not[\s+]*\(.*?\)[\s+]*\)|\(increase[\s+]*\(.*?\)[\s+]*\(.*?\)[\s+]*\)|\(.*?\))',
            #                                           re.search(r':effect[\s+]*\(and(.*?)\)$', description).group(1))]

            #effects = {}
            #for eff in all_effects:
            #    if 'increase' in eff:
            #        effects[re.search(r'\((increase.*)\)',eff).group(1)] = True
            #    else:
            #        effects[re.search(r'\(((?!not\s).*?)\)', eff).group(1).strip()] = bool(not 'not ' in eff)
            #effects = {re.search(r'\(((?!not).*?)\)', item).group(1).strip(): not 'not ' in item \
            #          for item in re.findall('(\(not[\s+]*\(.*?\)[\s+]*\)|\(.*?\))',
            #                                  re.search(r':effect[\s+]*\(and(.*?)\)[\s+]*(\(:action|\)[\s+]*$)',
            #                                            description).group(1))}

            effects = {re.search(r'\(((?!not).*?)\)', item).group(1).strip(): not 'not ' in item \
                       for item in re.findall('(\(not[\s+]*\(.*?\)[\s+]*\)|\(.*?\))',
                                              re.search(r':effect[\s+]*\(and(.*?)\)[\s+]*(\(:action|\)[\s+]*$)',
                                                        description).group(1))}

        except Exception as exc:
            print ("exception",exc)
            #print description
            effects        = {}
            
        return [action_name, parameters, preconditions, effects]

    
    ''''''

    with open(domainFileName, 'r') as domain_file:
        action_dict = {item.split(' ')[1] : PDDLaction(item)
                       for item in re.findall('\(:action.*?:effect.*?[not.*?\)]*[\s+]*\)[\s+]*\)[\s+]*\)', re.sub('[\s+]', ' ', domain_file.read()))}

        #print action_dict
    #with open(problemFileName) as problem_file:
    #    problem_lines = problem_file.readlines()
    init_state = parse_problem(domainFileName, problemFileName, "init")
    #print ("init state",init_state)
    goal_state = parse_problem(domainFileName, problemFileName, "goal")
        #print init_state
        #print goal_state
    ''''''

    state = []
    for key in action_dict.keys():
        actionName        = action_dict[key][0]
        state.append('{}-has-parameters-{}'.format(actionName, action_dict[key][1]))
        for precondition in action_dict[key][2].items():
            if precondition[1]:
                state.append('{}-has-precondition-{}'.format(actionName, precondition[0]))
            else:
                state.append('{}-has-negprecondition-{}'.format(actionName, precondition[0]))
           
        for effect in action_dict[key][3].items():
            if effect[1]: state.append('{}-has-add-effect-{}'.format(actionName, effect[0]))
            else:         state.append('{}-has-delete-effect-{}'.format(actionName, effect[0]))
    for pred in init_state:
        state.append('has-initial-state-{}'.format(pred))
    for pred in goal_state:
        state.append('has-goal-state-{}'.format(pred))
    return state


def parse_problem(domainFileName, problemFileName, section_prefix):
    parser_cmd = ['./parser.sh', domainFileName, problemFileName, section_prefix]
    result = subprocess.run(parser_cmd, stdout=subprocess.PIPE, text=True, check=True)
    state = [item.strip() for item in result.stdout.strip().split('\n')] if result.stdout.strip() else []
    return state


'''
Method :: compute plan from domain and problem files
'''

def get_plan(domainFileName, problemFileName):
    fd_plan_cmd = ['./fdplan.sh', domainFileName, problemFileName]
    result = subprocess.run(fd_plan_cmd, stdout=subprocess.PIPE, text=True, check=True)

    plan = [item.strip() for item in result.stdout.strip().split('\n')] if result.stdout.strip() else []
    if plan:
        result_cost = subprocess.run(['./get_plan_cost.sh'], stdout=subprocess.PIPE, text=True, check=True)
        cost = int(result_cost.stdout.strip())
    else:
        cost = 0
    return [plan, cost]



''' 
Method :: ground PDDL domain and problem files
'''

def ground(domainFileName, problemFileName):
    subprocess.run(['clean.sh'], check=True)
    ground_cmd = ['ground.sh', domainFileName, problemFileName]
    with open('stdout.txt', 'w') as outfile:
        subprocess.run(ground_cmd, stdout=outfile, check=True)

def create_temp_files(domainFileName, problemFileName):
    subprocess.run(['./clean.sh'], check=True)
    create_tmp_cmd = ['./create_tmp.sh', domainFileName, problemFileName]
    with open('stdout.txt', 'w') as outfile:
        subprocess.run(create_tmp_cmd, stdout=outfile, check=True)

''' 
Method :: validate plan given PDDL domain and problem files
'''

def validate_plan(domainFileName, problemFileName, planFileName):
    val_plan_cmd = ['./valplan.sh', domainFileName, problemFileName, planFileName]
    result = subprocess.run(val_plan_cmd, stdout=subprocess.PIPE, text=True, check=True)
    return eval(result.stdout.strip())

def plan_graph_test(domainFileName, problemFileName, planFileName):
    graph_test_cmd = ['./graph_test.sh', domainFileName, problemFileName, planFileName]
    result = subprocess.run(graph_test_cmd, stdout=subprocess.PIPE, text=True, check=True)
    return eval(result.stdout.strip())


def find_fail_point(domainFileName, problemFileName, planFileName):
    fail_point_cmd = ['./fail_point.sh', domainFileName, problemFileName, planFileName]
    result = subprocess.run(fail_point_cmd, stdout=subprocess.PIPE, text=True, check=True)
    output = result.stdout.strip()
    if output:
        return int(output)
    else:
        return 0


if __name__ == '__main__':
    pass

    ''' debug list '''
    #print validate_plan('../domain/fetchworld-base-m.pddl', '../domain/problem1.pddl', 'sas_plan')
    #state = read_state_from_domain_file('../domain/fetchworld-base-m.pddl')
    #write_domain_file_from_state(state)
