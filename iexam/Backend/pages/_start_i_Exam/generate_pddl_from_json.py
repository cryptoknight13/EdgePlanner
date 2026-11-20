import json
import os
import shutil
import sys

# Load JSON files
curr_dir = os.path.dirname(os.path.abspath(__file__))
data_dir = os.path.join(curr_dir, "..", "data")

import logging
# Configure logging
logging.basicConfig(
    filename=os.path.join(curr_dir, '../../../Logs/log.txt'),  # Log file name
    level=logging.INFO,            # Log level
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
    filemode='a' 
)

with open(os.path.join(data_dir, "node-data.json")) as f:
    node_data = json.load(f)

with open(os.path.join(data_dir, "connectivity-edge.json")) as f:
    connectivity_edge = json.load(f)

with open(os.path.join(data_dir, "cve-in-node.json")) as f:
    cve_in_node = json.load(f)

with open(os.path.join(data_dir, "cve-data.json")) as f:
    cve_data = json.load(f)

# Token formatting, the CVE-field subset and node naming are shared with the
# API generator via handler/curate.py so both emit identical PDDL.
sys.path.insert(0, os.path.join(curr_dir, "..", "handler"))
import curate  # noqa: E402

format_for_pddl = curate.pddl_token
group_keys = curate.pddl_cve_fields
node_tok = curate.node_tokens(node_data)

# Helper function to determine if a node is directly connected to the attacker
def get_nodes_directly_connected_to_attacker():
    directly_connected_nodes = set()
    for edge_id, (source, target) in connectivity_edge.items():
        if source == "n0":  # Check if the source is the attacker node
            directly_connected_nodes.add(target)
    return directly_connected_nodes

# Helper function to get all source nodes for a given target node
def get_source_nodes(target_node):
    sources = []
    for edge_id, (source, target) in connectivity_edge.items():
        if target == target_node:
            sources.append(source)
    return sources

# Generate domain PDDL
def generate_domain_pddl():
    directly_connected_nodes = get_nodes_directly_connected_to_attacker()

    domain_content = """(define (domain netdomain)
    (:requirements :strips :typing)
    (:types node function struct driver system cause adversary)
    
    (:predicates
"""
    # Add predicates for service-up and connectivity
    for node_id in node_data:
        domain_content += f"      (has-service-up-{node_id} ?Node - node)\n"
    domain_content += "      (has-attacker ?atk - adversary)\n"
    domain_content += "      (can-ping ?Node1 - node ?Node2 - node)\n"
    domain_content += "      (has-connection-to ?Node - node)\n"

    # Add predicates for direct access to nodes directly connected to n0
    for node_id in directly_connected_nodes:
        domain_content += f"      (has-access-to-{node_tok[node_id]}-node ?node - node ?atk - adversary)\n"

    # Add predicates for CVEs with unique suffixes
    for node_id, cves in cve_in_node.items():
        domain_content += f"        (exploited-{node_id} ?Node - node)\n"
        for cve_index, cve_id in enumerate(cves, start=1):
            cve = cve_data[cve_id]
            grouped_keys = group_keys(cve)
            for base_key, items in grouped_keys.items():
                if base_key in ["function", "struct", "driver", "system", "cause"]:  # Exclude capability
                    for key_index, (_, value) in enumerate(items, start=1):
                        predicate_name = f"has-{node_id}-{base_key}-{cve_index}-dot-{key_index}"
                        domain_content += f"        ({predicate_name} ?{base_key}{key_index} - {base_key})\n"

    domain_content += "    )\n"

    # Add connectivity actions (excluding attacker-related edges)
    for edge_id, (source, target) in connectivity_edge.items():
        if source == "n0":  # Skip edges originating from the attacker
            continue
        source_name = node_tok[source]
        target_name = node_tok[target]
        domain_content += f"""
(:action connectivity-edge-between-{source_name}-and-{target_name}
    :parameters (?node1 - node ?node2 - node)
    :precondition (and (has-service-up-{source} ?node1) (has-service-up-{target} ?node2) (can-ping ?node1 ?node2)"""
        # Add (has-connection-to ?node1) if the source node is not directly connected to the attacker
        if source not in directly_connected_nodes:
            domain_content += f" (has-connection-to ?node1)"
        domain_content += f""")
    :effect (and
        (has-connection-to ?node2)
    )
)
"""

    # Add attacker access actions for nodes directly connected to n0
    for node_id in directly_connected_nodes:
        node_name = node_tok[node_id]
        domain_content += f"""
(:action attacker-has-access-to-{node_name}
    :parameters (?node - node ?atk - adversary)
    :precondition (and (has-attacker ?atk) (has-service-up-{node_id} ?node))
    :effect (and (has-access-to-{node_name}-node ?node ?atk))
)
"""

    # Add CVE exploitation actions for all nodes
    for node_id, cves in cve_in_node.items():
        target_name = node_tok[node_id]
        source_nodes = get_source_nodes(node_id)  # Get all source nodes for the current node
        for source_node in source_nodes:
            source_name = node_tok[source_node]
            for cve_index, cve_id in enumerate(cves, start=1):
                cve = cve_data[cve_id]
                grouped_keys = group_keys(cve)

                # Logic for nodes directly connected to the attacker
                if source_node == "n0":
                    domain_content += f"""
(:action attacker-exploit-{format_for_pddl(cve_id)}-to-compromise-{target_name}
    :parameters (?node - node ?atk - adversary"""
                    for base_key, items in grouped_keys.items():
                        if base_key in ["function", "struct", "driver", "system", "cause"]:  # Exclude capability
                            for key_index, (_, value) in enumerate(items, start=1):
                                domain_content += f" ?{base_key}{key_index} - {base_key}"
                    domain_content += ")\n    :precondition (and\n"
                    domain_content += f"        (has-access-to-{target_name}-node ?node ?atk)\n"
                    domain_content += f"        (has-service-up-{node_id} ?node)\n"  # moved from effect to precondition
                    for base_key, items in grouped_keys.items():
                        if base_key in ["function", "struct", "driver", "system", "cause"]:  # Exclude capability
                            for key_index, (_, value) in enumerate(items, start=1):
                                predicate_name = f"has-{node_id}-{base_key}-{cve_index}-dot-{key_index}"
                                domain_content += f"        ({predicate_name} ?{base_key}{key_index})\n"
                    domain_content += "    )\n    :effect (and\n"
                    domain_content += f"        (exploited-{node_id} ?node)\n"
                    domain_content += "    )\n)\n"

                # Logic for nodes not directly connected to the attacker
                else:
                    domain_content += f"""
(:action attacker-exploit-{format_for_pddl(cve_id)}-to-compromise-{target_name}-via-{source_name}
    :parameters (?node2 - node ?node1 - node"""
                    for base_key, items in grouped_keys.items():
                        if base_key in ["function", "struct", "driver", "system", "cause"]:  # Exclude capability
                            for key_index, (_, value) in enumerate(items, start=1):
                                domain_content += f" ?{base_key}{key_index} - {base_key}"
                    domain_content += ")\n    :precondition (and\n"
                    domain_content += f"        (can-ping ?node1 ?node2)\n"
                    domain_content += f"        (has-service-up-{source_node} ?node1)\n"  # moved from effect to precondition
                    domain_content += f"        (exploited-{source_node} ?node1)\n"
                    domain_content += f"        (has-service-up-{node_id} ?node2)\n"  # moved from effect to precondition
                    for base_key, items in grouped_keys.items():
                        if base_key in ["function", "struct", "driver", "system", "cause"]:  # Exclude capability
                            for key_index, (_, value) in enumerate(items, start=1):
                                predicate_name = f"has-{node_id}-{base_key}-{cve_index}-dot-{key_index}"
                                domain_content += f"        ({predicate_name} ?{base_key}{key_index})\n"
                    domain_content += "    )\n    :effect (and\n"
                    domain_content += f"        (exploited-{node_id} ?node2)\n"
                    domain_content += "    )\n)\n"

    domain_content += ")"
    return domain_content

# Generate problem PDDL
def generate_problem_pddl():
    problem_content = """(define (problem netproblem)
    (:domain netdomain)
    (:objects 
"""
    # Add nodes and CVE-related objects (excluding attacker node)
    for node_id, attributes in node_data.items():
        if node_id != "n0":  # Exclude attacker node
            problem_content += f"        {node_tok[node_id]} - node\n"
    seen_objects: set[tuple[str, str]] = set()
    for node_id, cves in cve_in_node.items():
        for cve_index, cve_id in enumerate(cves, start=1):
            cve = cve_data[cve_id]
            grouped_keys = group_keys(cve)
            for base_key, items in grouped_keys.items():
                if base_key in ["function", "struct", "driver", "system", "cause"]:  # Exclude capability
                    for key_index, (_, value) in enumerate(items, start=1):
                        formatted = format_for_pddl(value)
                        key = (base_key, formatted)
                        if key in seen_objects:
                            continue
                        seen_objects.add(key)
                        problem_content += f"        {formatted} - {base_key}\n"
    problem_content += "        attacker1 - adversary\n    )\n\n    (:init\n"

    # Add initial conditions (excluding attacker-related `has-service-up-n0`)
    for node_id in node_data:
        if node_id != "n0":  # Exclude (has-service-up-n0 attacker)
            problem_content += f"        (has-service-up-{node_id} {node_tok[node_id]})\n"
    problem_content += "        (has-attacker attacker1)\n"
    for edge_id, (source, target) in connectivity_edge.items():
        if source != "n0" and target != "n0":  # Exclude attacker-related edges
            problem_content += f"        (can-ping {node_tok[source]} {node_tok[target]})\n"
    for node_id, cves in cve_in_node.items():
        for cve_index, cve_id in enumerate(cves, start=1):
            cve = cve_data[cve_id]
            grouped_keys = group_keys(cve)
            for base_key, items in grouped_keys.items():
                if base_key in ["function", "struct", "driver", "system", "cause"]:  # Exclude capability
                    for key_index, (_, value) in enumerate(items, start=1):
                        predicate_name = f"has-{node_id}-{base_key}-{cve_index}-dot-{key_index}"
                        problem_content += f"        ({predicate_name} {format_for_pddl(value)})\n"

    problem_content += "    )\n\n    (:goal\n        (and\n"
    for node_id in node_data:
        if node_data[node_id]["name"] != "Attacker":
            problem_content += f"            (exploited-{node_id} {node_tok[node_id]})\n"
    problem_content += "        )\n    )\n)"
    return problem_content

# Write the PDDL files
logging.info("Starting generation of Domain file.")
domain_pddl = generate_domain_pddl()
logging.info("Domain file generated successfully.")
logging.info("Starting generation of Problem file.")
problem_pddl = generate_problem_pddl()
logging.info("Problem file generated successfully.")
pddl_dir = os.path.join(curr_dir, "..", "..", "pddl")  

# Clear the pddl_dir before writing files
if os.path.exists(pddl_dir):
    shutil.rmtree(pddl_dir)
os.makedirs(pddl_dir, exist_ok=True)

with open(os.path.join(pddl_dir, "NetDomain.pddl"), "w") as f:
    f.write(domain_pddl)

with open(os.path.join(pddl_dir, "NetProblem.pddl"), "w") as f:
    f.write(problem_pddl)
