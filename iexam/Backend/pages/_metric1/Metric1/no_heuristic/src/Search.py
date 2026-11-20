#!/usr/bin/env python

'''
Topic   :: Search methods
Project :: Explanations for Multi-Model Planning
Author  :: Tathagata Chakraborti
Date    :: 09/29/2016
'''

from queue import PriorityQueue, Queue
import copy
import time

'''
Method :: Astar Search
'''

def astarSearch(problem):
    
    startState            = problem.getStartState()
    fringe                = PriorityQueue()
    closed                = set()
    numberOfNodesExpanded = 0
    successor_list = None

    fringe.put((problem.heuristic(startState), [startState, []]))

    print ("Runnning aStar Search...")
    start_time = time.time()
    # plan_list = []
    while not fringe.empty():
        
        node = fringe.get()[1]
        numberOfNodesExpanded += 1
        
        new_node_time=time.time()

        if not numberOfNodesExpanded % 500:
            print ("Number of Nodes Expanded =", numberOfNodesExpanded)
            print("Time elapsed: ", new_node_time-start_time )

        goal_check, old_plan = problem.isGoal(node[0])
        if goal_check:
            print ("Goal Found! Number of Nodes Expanded =", numberOfNodesExpanded, node[1])
            #problem.add_solution(node[1])
            print("Len of solution list: ",len(problem.get_solution()))
            problem.final_node_number = numberOfNodesExpanded
            problem.solution_time_list.append(time.time() - problem.start_time)
            problem.solution_node_list.append(numberOfNodesExpanded)

        if len(problem.get_solution()) == 2:
             break


        if frozenset(node[0]) not in closed:

            closed.add(frozenset(node[0]))

            successor_list         = problem.getSuccessors(node, old_plan)
            # print("Len of successor list: ",len(successor_list))


            
            while successor_list:
                
                candidate_node     = successor_list.pop()
                new_node           = [candidate_node[0], node[1] + [candidate_node[1]]]
                
                fringe.put((problem.heuristic(candidate_node[0]) + len(new_node[1]), new_node))
        if numberOfNodesExpanded == 500000:
             break
    #return the plan list
    # return plan_list
    print("Number of Nodes Expanded =", numberOfNodesExpanded)
    return None

def BFSearch(problem):

    startState            = problem.getStartState()
    fringe                = Queue()
    closed                = set()
    numberOfNodesExpanded = 0
    conflict_list = []
    current_sol = []

    fringe.put((problem.heuristic(startState), [startState, []]))

    print ("Runnning BFS...")
    while not fringe.empty():
        node = fringe.get()[1]
        goal_check, old_plan = problem.isGoal(node[0])
        if not goal_check:
            #print "Goal not Found! Number of Nodes Expanded =", numberOfNodesExpanded
            #print "Failed for path",node[1]
            conflict_list.append(set(node[1]))
        else:
            #print "It was fine"
            if frozenset(node[0]) not in closed:
                conflict_flag = False
                for item in conflict_list:
                    if item <= set(node[1]) and len(item) > 0:
                        conflict_flag = True
                if not conflict_flag:
                    current_sol = node[1]
                    closed.add(frozenset(node[0]))

                    successor_list         = problem.getSuccessors(node, old_plan)
                    numberOfNodesExpanded += 1
                    #print successor_list, node[1]
                    if not numberOfNodesExpanded % 100:
                        print ("Number of Nodes Expanded =", numberOfNodesExpanded)

                    while successor_list:

                        candidate_node     = successor_list.pop()
                        new_node           = [candidate_node[0], node[1] + [candidate_node[1]]]

                        fringe.put((problem.heuristic(candidate_node[0]) + len(new_node[1]), new_node))
    #print "curr", current_sol
    return current_sol
