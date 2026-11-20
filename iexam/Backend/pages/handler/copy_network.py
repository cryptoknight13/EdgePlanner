import os
import shutil

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.path.join(CURR_DIR, "../data"))
GRAPH_DATA_DIR = os.path.abspath(os.path.join(CURR_DIR, "../_build_plan/graphData"))

# Remove all files from graphData
if os.path.exists(GRAPH_DATA_DIR):
    for fname in os.listdir(GRAPH_DATA_DIR):
        fpath = os.path.join(GRAPH_DATA_DIR, fname)
        if os.path.isfile(fpath):
            os.remove(fpath)
        elif os.path.isdir(fpath):
            shutil.rmtree(fpath)
else:
    os.makedirs(GRAPH_DATA_DIR, exist_ok=True)

# Copy all .json files from data to graphData
for fname in os.listdir(DATA_DIR):
    if fname.endswith(".json"):
        src = os.path.join(DATA_DIR, fname)
        dst = os.path.join(GRAPH_DATA_DIR, fname)
        shutil.copy2(src, dst)

print(f"Copied all .json files from {DATA_DIR} to {GRAPH_DATA_DIR}")
