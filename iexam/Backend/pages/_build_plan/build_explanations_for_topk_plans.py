import os
import sys
import json

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
FOUND_PLANS_DIR = os.path.join(CURR_DIR, "found_plans", "done")
RESULTS_DIR = os.path.join(CURR_DIR, "results")
PROMPT_FILE = os.path.join(CURR_DIR, "inputs", "prompt.txt")
OUTPUT_JSON = os.path.join(RESULTS_DIR, "Top_k_plan_explanations.json")

sys.path.append(os.path.join(CURR_DIR, '../handler'))
from build_explanation import extract_plan
from build_api import process_explanation_file

def generate_explanations_for_topk_plans():
    plan_files = sorted([
        f for f in os.listdir(FOUND_PLANS_DIR)
        if f.startswith("sas_plan.") and os.path.isfile(os.path.join(FOUND_PLANS_DIR, f))
    ])
    explanations = []
    for plan_file in plan_files:
        plan_path = os.path.join(FOUND_PLANS_DIR, plan_file)
        temp_explanation_path = os.path.join(RESULTS_DIR, f"explanation_{plan_file}.txt")
        # Read prompt and plan actions
        with open(PROMPT_FILE, "r", encoding="utf-8") as pf:
            prompt_text = pf.read().strip()
        with open(plan_path, "r", encoding="utf-8") as planf:
            plan_text = planf.read().strip()
        # Write required marker, prompt, then plan actions
        with open(temp_explanation_path, "w", encoding="utf-8") as outf:
            outf.write("explanation:\n")  # <-- prepend marker
            outf.write(prompt_text + "\n\n" + plan_text)
        explanation = process_explanation_file(temp_explanation_path)
        explanations.append({
            "plan_file": plan_file,
            "explanation": explanation
        })
        # Remove temp file
        try:
            os.remove(temp_explanation_path)
        except Exception:
            pass

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(explanations, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    generate_explanations_for_topk_plans()
