#!/usr/bin/env python3
"""
Chained-plan generator — attacker included in plan-node-data.json ONLY if it appears in edges.

Usage:
  Place this script in the same dir as node-data.json, cve-data.json, connectivity-edge.json, plan.txt
  or run with --cwd to point to another directory.

Produces:
 - plan-node-data.json
 - plan-cve-in-node.json
 - plan-cve-data.json
 - plan-connectivity-edge.json
"""
import os, json, re, argparse
import shutil
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "handler"))
import curate  # noqa: E402  # shared node-token / CVE-field curation

def load_json(path):
    with open(path,'r',encoding='utf-8') as fh:
        return json.load(fh)

def save_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)  # <-- ensure directory exists
    with open(path,'w',encoding='utf-8') as fh:
        json.dump(obj, fh, indent=2)

def norm(s: str) -> str:
    return s.strip().lower().replace("_", "-").replace(" ", "-")

def extract_atoms(plan_text: str):
    return re.findall(r'\([^)]+\)', plan_text, flags=re.DOTALL)

def find_cves(text: str):
    return [m.group(1).upper() for m in re.finditer(r'(cve-\d{4}-\d+)', text, flags=re.IGNORECASE)]

def parse_to_via(action: str):
    m_t = re.search(r'-to-([a-z0-9\-]+)', action, flags=re.IGNORECASE)
    m_v = re.search(r'-via-([a-z0-9\-]+)', action, flags=re.IGNORECASE)
    return (m_t.group(1) if m_t else None, m_v.group(1) if m_v else None)

def main(plan_file="plan.txt", plan_text=None, cwd="."):
    CURR_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = os.path.abspath(os.path.join(CURR_DIR, "../_build_plan/graphData"))

    # Clear OUTPUT_DIR before saving
    if os.path.exists(OUTPUT_DIR):
        for fname in os.listdir(OUTPUT_DIR):
            fpath = os.path.join(OUTPUT_DIR, fname)
            if os.path.isfile(fpath):
                os.remove(fpath)
            elif os.path.isdir(fpath):
                shutil.rmtree(fpath)
    else:
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Use absolute path for plan_file if not already absolute
    if not os.path.isabs(plan_file):
        plan_file = os.path.abspath(os.path.join(CURR_DIR, plan_file))

    # base files
    node_file = os.path.join(CURR_DIR, "../data/node-data.json")
    cve_data_file = os.path.join(CURR_DIR, "../data/cve-data.json")
    conn_file = os.path.join(CURR_DIR, "../data/connectivity-edge.json")

    for f in (node_file, cve_data_file, conn_file):
        if not os.path.exists(f):
            raise FileNotFoundError(f"Required base file missing: {f}")

    base_nodes = load_json(node_file)
    base_cve_data = load_json(cve_data_file)

    # read plan text
    if plan_text is None:
        plan_path = plan_file
        if not os.path.exists(plan_path):
            raise FileNotFoundError(f"Plan file not found: {plan_path}")
        plan_text = open(plan_path,'r',encoding='utf-8').read()

    # name -> nid map (normalized names and direct nX tokens)
    name_to_nid = {}
    for nid, info in base_nodes.items():
        nm = norm(info.get("name",""))
        if nm:
            name_to_nid[nm] = nid
        name_to_nid[nid] = nid
    # PDDL tokens (disambiguated "name-nid" when hostnames repeat).
    for nid, tok in curate.node_tokens(base_nodes).items():
        name_to_nid[tok] = nid

    # detect attacker id but DO NOT add it automatically
    attacker_nid = name_to_nid.get("attacker") or ("n0" if "n0" in base_nodes else None)
    if attacker_nid is None:
        for nid, info in base_nodes.items():
            if "attacker" in info.get("name","").lower():
                attacker_nid = nid
                break
    if attacker_nid is None:
        attacker_nid = next(iter(base_nodes.keys()))

    # outputs accumulators
    plan_nodes = {}            # will fill only for nodes that appear in edges or have CVEs
    plan_cve_in_node = {}
    plan_cve_data = {}
    edges = []                 # ordered list of (src, dst)

    def add_edge(a,b):
        if a is None or b is None or a == b:
            return
        t = (a,b)
        if t not in edges:
            edges.append(t)

    current_pivot = None

    for atom in extract_atoms(plan_text):
        content = atom.strip("()").strip()
        if not content or content.startswith(";"):
            continue
        parts = content.split()
        if not parts:
            continue

        action = parts[0]
        tokens_after = parts[1:]

        # map tokens to nodes in order
        referenced_nodes = []
        for tok in tokens_after:
            tnorm = norm(tok)
            if tnorm in name_to_nid:
                referenced_nodes.append(name_to_nid[tnorm])
            elif tok in name_to_nid:
                referenced_nodes.append(name_to_nid[tok])

        explicit_target_name, explicit_via_name = parse_to_via(action)

        # resolve target with fallback to first referenced mapped node
        target_nid = None
        if explicit_target_name:
            target_nid = name_to_nid.get(explicit_target_name)
        if target_nid is None:
            target_nid = referenced_nodes[0] if referenced_nodes else None

        # resolve via if present & mappable
        via_nid = None
        if explicit_via_name:
            via_nid = name_to_nid.get(explicit_via_name)

        if target_nid is None:
            # nothing to do for this atom
            continue

        # register target node info now or later (we will also ensure all edge nodes are present before saving)
        # chain semantics with via-first handling:
        if current_pivot is None:
            if via_nid and via_nid in base_nodes and via_nid != target_nid:
                # start from via -> target (no attacker->target)
                add_edge(via_nid, target_nid)
                current_pivot = target_nid
            else:
                # attacker -> target (first link)
                add_edge(attacker_nid, target_nid)
                current_pivot = target_nid
        else:
            # chain: current_pivot -> target
            if target_nid != current_pivot:
                add_edge(current_pivot, target_nid)
                current_pivot = target_nid

        # CVE mapping for this atom: assign CVEs to the target only
        for cve in find_cves(content):
            plan_cve_in_node.setdefault(target_nid, [])
            if cve not in plan_cve_in_node[target_nid]:
                plan_cve_in_node[target_nid].append(cve)
            if cve in base_cve_data:
                plan_cve_data[cve] = base_cve_data[cve]
            else:
                plan_cve_data[cve] = {"cve-id": cve, "note": "not found in base cve-data.json"}

    # Now ensure plan_nodes contains all nodes that actually appear in edges (and also nodes that have CVEs)
    for a,b in edges:
        if a in base_nodes:
            plan_nodes[a] = base_nodes[a]
        if b in base_nodes:
            plan_nodes[b] = base_nodes[b]
    for nid in plan_cve_in_node.keys():
        if nid in base_nodes:
            plan_nodes[nid] = base_nodes[nid]

    # Save connectivity as ce0.. preserving order
    plan_connectivity = {f"ce{i}":[a,b] for i,(a,b) in enumerate(edges)}

    # Save outputs (use OUTPUT_DIR)
    save_json(plan_nodes, os.path.join(OUTPUT_DIR, "node-data.json"))
    save_json(plan_cve_in_node, os.path.join(OUTPUT_DIR, "cve-in-node.json"))
    save_json(plan_cve_data, os.path.join(OUTPUT_DIR, "cve-data.json"))
    save_json(plan_connectivity, os.path.join(OUTPUT_DIR, "connectivity-edge.json"))

    print("Wrote plan-* files into", OUTPUT_DIR)
    print("Edges:", plan_connectivity)
    print("Nodes included:", list(plan_nodes.keys()))

if __name__ == "__main__":
    # Directly call main with hardcoded paths
    main(
        plan_file="../_build_plan/results/optimal_plan.txt",
        plan_text=None,
        cwd="."
    )
