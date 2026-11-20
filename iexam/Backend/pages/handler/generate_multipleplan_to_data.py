#!/usr/bin/env python3
"""
generate_plan_jsons_aggregate.py

Aggregate multiple plan files into one set of plan-*.json files (deduped).

Reads base JSONs from --base-dir (default current dir):
  - node-data.json
  - cve-data.json
  - connectivity-edge.json   (only for parity; not required)

Finds plan files via --pattern (default "plan*.txt") or list via --plans.

Outputs in --outdir (default current dir):
  - node-data.json
  - cve-in-node.json
  - cve-data.json
  - connectivity-edge.json

Duplicates are removed across all plans.
"""
import os
import json
import re
import glob
import shutil
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "handler"))
import curate  # noqa: E402  # shared node-token / CVE-field curation
from typing import List, Tuple, Dict, Optional

# --- Absolute paths ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
PAGES_DIR = os.path.join(BASE_DIR, "Backend", "pages")
DATA_DIR = os.path.join(PAGES_DIR, "data")
RESULTS_DIR = os.path.join(PAGES_DIR, "_build_plan", "found_plans", "done") 

# --- Input/output files ---
NODE_FILE = os.path.join(DATA_DIR, "node-data.json")
CVE_DATA_FILE = os.path.join(DATA_DIR, "cve-data.json")
CONN_FILE = os.path.join(DATA_DIR, "connectivity-edge.json")

OUTDIR = os.path.join(PAGES_DIR, "_build_plan", "graphData")

# -------------------------
# Utilities
# -------------------------
def load_json(path: str):
    with open(path, 'r', encoding='utf-8') as fh:
        return json.load(fh)

def save_json(obj, path: str):
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, indent=2)

def norm(s: str) -> str:
    return s.strip().lower().replace("_", "-").replace(" ", "-")

def extract_atoms(plan_text: str) -> List[str]:
    return re.findall(r'\([^)]+\)', plan_text, flags=re.DOTALL)

def find_cves(text: str) -> List[str]:
    return [m.group(1).upper() for m in re.finditer(r'(cve-\d{4}-\d+)', text, flags=re.IGNORECASE)]

def parse_to_via(action: str) -> Tuple[Optional[str], Optional[str]]:
    m_t = re.search(r'-to-([a-z0-9\-]+)', action, flags=re.IGNORECASE)
    m_v = re.search(r'-via-([a-z0-9\-]+)', action, flags=re.IGNORECASE)
    return (m_t.group(1) if m_t else None, m_v.group(1) if m_v else None)

# -------------------------
# Single-plan parsing (chain semantics)
# -------------------------
def parse_plan_chain(plan_text: str, name_to_nid: Dict[str,str], base_nodes: Dict, base_cve_data: Dict,
                     attacker_nid: str) -> Tuple[List[Tuple[str,str]], Dict[str,List[str]], Dict[str,Dict]]:
    """
    Parse a single plan text into:
      - edges (attacker_nid -> target_nid for each atom, unless explicit -via-)
      - cve-in-node mapping for this plan
      - cve-data mapping for this plan
    """
    edges = []
    edge_set = set()
    plan_cve_in_node = {}
    plan_cve_data = {}

    def add_edge(a,b):
        if a is None or b is None or a == b: return
        t = (a,b)
        if t not in edge_set:
            edge_set.add(t)
            edges.append(t)

    for atom in extract_atoms(plan_text):
        content = atom.strip("()").strip()
        if not content or content.startswith(";"):
            continue
        parts = content.split()
        if not parts:
            continue

        action = parts[0]
        tokens_after = parts[1:]

        # map tokens to nodes in token order
        referenced_nodes = []
        for tok in tokens_after:
            tnorm = norm(tok)
            if tnorm in name_to_nid:
                referenced_nodes.append(name_to_nid[tnorm])
            elif tok in name_to_nid:
                referenced_nodes.append(name_to_nid[tok])

        explicit_target_name, explicit_via_name = parse_to_via(action)

        # resolve target (explicit -to- may not map; fallback to first referenced node)
        target_nid = None
        if explicit_target_name:
            target_nid = name_to_nid.get(explicit_target_name)
        if target_nid is None:
            target_nid = referenced_nodes[0] if referenced_nodes else None

        # resolve via if present
        via_nid = None
        if explicit_via_name:
            via_nid = name_to_nid.get(explicit_via_name)

        if target_nid is None:
            continue

        # Always add edge from attacker to target, unless explicit via is present
        if via_nid and via_nid in base_nodes and via_nid != target_nid:
            add_edge(via_nid, target_nid)
        else:
            add_edge(attacker_nid, target_nid)

        # CVE assignment to target only
        for cve in find_cves(content):
            plan_cve_in_node.setdefault(target_nid, [])
            if cve not in plan_cve_in_node[target_nid]:
                plan_cve_in_node[target_nid].append(cve)
            if cve in base_cve_data:
                plan_cve_data[cve] = base_cve_data[cve]
            else:
                plan_cve_data[cve] = {"cve-id": cve, "note": "not found in base cve-data.json"}

    return edges, plan_cve_in_node, plan_cve_data

# -------------------------
# Aggregation driver
# -------------------------
def aggregate_plans(plan_files: List[str], base_dir: str, out_dir: str, include_attacker_always: bool):
    # Use absolute paths
    node_file = os.path.abspath(NODE_FILE)
    cve_data_file = os.path.abspath(CVE_DATA_FILE)
    conn_file = os.path.abspath(CONN_FILE)
    out_dir = os.path.abspath(out_dir)
    plan_files = [os.path.abspath(p) for p in plan_files]

    for f in (node_file, cve_data_file, conn_file):
        if not os.path.exists(f):
            raise FileNotFoundError(f"Base file missing: {f}")

    base_nodes = load_json(node_file)
    base_cve_data = load_json(cve_data_file)

    # name -> nid map
    name_to_nid = {}
    for nid, info in base_nodes.items():
        nm = norm(info.get("name",""))
        if nm:
            name_to_nid[nm] = nid
        name_to_nid[nid] = nid
    # PDDL tokens (disambiguated "name-nid" when hostnames repeat).
    for nid, tok in curate.node_tokens(base_nodes).items():
        name_to_nid[tok] = nid

    # attacker id
    attacker_nid = name_to_nid.get("attacker") or ("n0" if "n0" in base_nodes else None)
    if attacker_nid is None:
        for nid, info in base_nodes.items():
            if "attacker" in info.get("name","").lower():
                attacker_nid = nid
                break
    if attacker_nid is None:
        attacker_nid = next(iter(base_nodes.keys()))

    # global aggregates
    global_edges = []
    global_edge_set = set()
    global_cve_in_node: Dict[str, List[str]] = {}
    global_cve_data: Dict[str, Dict] = {}
    global_nodes: Dict[str, Dict] = {}

    # process each plan and merge
    for plan_path in plan_files:
        if not os.path.exists(plan_path):
            print(f"[warn] plan file not found, skipping: {plan_path}")
            continue
        with open(plan_path, 'r', encoding='utf-8') as fh:
            plan_text = fh.read()

        edges, plan_cve_map, plan_cve_data = parse_plan_chain(plan_text, name_to_nid, base_nodes, base_cve_data, attacker_nid)

        # merge edges preserving first-discovered order (per plan file order and within-plan order)
        for e in edges:
            if e not in global_edge_set:
                global_edge_set.add(e)
                global_edges.append(e)

        # merge cve-in-node
        for nid, cves in plan_cve_map.items():
            lst = global_cve_in_node.setdefault(nid, [])
            for c in cves:
                if c not in lst:
                    lst.append(c)

        # merge cve data
        for cve, meta in plan_cve_data.items():
            if cve not in global_cve_data:
                global_cve_data[cve] = meta

    # Build node list from edges and CVE nodes (include attacker only if requested or present in edges)
    nodes_to_include = set()
    for a,b in global_edges:
        nodes_to_include.add(a); nodes_to_include.add(b)
    for nid in global_cve_in_node.keys():
        nodes_to_include.add(nid)

    if include_attacker_always:
        nodes_to_include.add(attacker_nid)

    for nid in nodes_to_include:
        if nid in base_nodes:
            global_nodes[nid] = base_nodes[nid]

    # build connectivity dict ce0.. preserving detected order
    plan_connectivity = {f"ce{i}": [a,b] for i, (a,b) in enumerate(global_edges)}

    # --- Clear OUTDIR before saving ---
    if os.path.exists(out_dir):
        for fname in os.listdir(out_dir):
            fpath = os.path.join(out_dir, fname)
            if os.path.isfile(fpath):
                os.remove(fpath)
            elif os.path.isdir(fpath):
                shutil.rmtree(fpath)

    # Save aggregated outputs (use same filenames as generate_plan_to_data.py)
    os.makedirs(out_dir, exist_ok=True)
    save_json(global_nodes, os.path.join(out_dir, "node-data.json"))
    save_json(global_cve_in_node, os.path.join(out_dir, "cve-in-node.json"))
    save_json(global_cve_data, os.path.join(out_dir, "cve-data.json"))
    save_json(plan_connectivity, os.path.join(out_dir, "connectivity-edge.json"))

    print(f"[ok] Aggregated {len(plan_files)} plans -> {out_dir}/*.json")
    print(f"Nodes: {len(global_nodes)}, Edges: {len(global_edges)}, CVEs: {len(global_cve_data)}")

# --- Entrypoint: no argparse, just run with fixed paths ---
def main():
    # Find all plan*.txt in RESULTS_DIR
    if not os.path.exists(RESULTS_DIR):
        print(f"[info] RESULTS_DIR does not exist: {RESULTS_DIR}")
        return

    plan_files = sorted(
        [os.path.join(RESULTS_DIR, f) for f in os.listdir(RESULTS_DIR) if f.startswith("sas_plan")]
    )
    if not plan_files:
        print("[info] no plan files found. nothing to do.")
        return

    aggregate_plans(
        plan_files=plan_files,
        base_dir=DATA_DIR,
        out_dir=OUTDIR,
        include_attacker_always=True
    )

if __name__ == "__main__":
    main()
