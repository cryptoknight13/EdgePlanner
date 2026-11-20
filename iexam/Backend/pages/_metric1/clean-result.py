import json
import os
import re

def restore_cve_format(text):
    # Match: CVE <year> <id>, case-insensitive
    pattern = r'\bcve (\d{4}) (\d+)\b'
    return re.sub(pattern, r'CVE-\1-\2', text, flags=re.IGNORECASE)

def clean_text(text):
    text = text.replace("-dot-", ".")
    text = text.replace("-", " ")
    text = restore_cve_format(text)
    return text

def strip_expl_prefix(text: str) -> str:
    if not isinstance(text, str):
        return ""
    prefix = "Here's a plain English explanation of why the plan fails:\n\n"
    return text[len(prefix):].lstrip() if text.startswith(prefix) else text

def save_json_to_text(json_file, output_file):
    # Open and load the JSON data
    with open(json_file, 'r') as f:
        data = json.load(f)

    # Check the metric type    
    metric = data.get("metric", "")

    with open(output_file, 'w') as f:
        if metric == "Metric1":
            # Write the top-level name

            #f.write(f"Goal: {data.get('goal', '')}\n\n")

            # Write each result
            result = data.get('results', [])[0]
            # f.write(f"Result :\n")
            # f.write(f"  Problem: {result.get('Problem', '')}\n")
            # f.write(f"  Total Time: {result.get('Total Time', '')}\n")
            # f.write(f"  Solutions Length: {result.get('Solutions Length', '')}\n")
            # f.write(f"  Final Node Number: {result.get('Final Node Number', '')}\n")
            
            # Write All Solutions
            # f.write("  All Solutions:\n")
            # for sol in result.get('All Solutions', []):
            #     f.write(f"    - {sol}\n")

            # Write ST list
            #f.write(f"  Solution Times:  {result.get('Solution Times', '')}\n")

            # Write SN list
            #f.write(f"  Solution Nodes: {result.get('Solution Nodes', '')}\n\n")

            # Write the other top-level fields except 'plan'
            #f.write(f"Chosen Solution: {data.get('chosen_solution', '')}\n\n")
            f.write("Chosen Solution:\n")
            for sol in data.get('chosen_solution', []):
                f.write(f"    - {sol}\n")
            f.write("\n")

            # f.write(f"Plan Repair Info: \n{clean_text(data.get('plan_repair_info', ''))}\n\n")
            
            # # Remove "Here is the explanation" if present
            # explanation = data.get('explanation', '')
            # prefix = "Here's a plain English explanation of why the plan fails:\n\n"
            # if explanation.startswith(prefix):
            #     explanation = explanation[len(prefix):].lstrip()

            # f.write(f"Explanation:\n{explanation}\n")
            # Chosen solution (list)
            # f.write("Chosen Solution:\n")
            # for sol in data.get('chosen_solution', []):
            #     f.write(f"    - {sol}\n")
            # f.write("\n")

            # Plan repair info (combined string or dict)
            pri = data.get('plan_repair_info', '')
            # combined_text = ""
            # if isinstance(pri, str):
            #     combined_text = pri
            # elif isinstance(pri, dict):
            #     combined_text = pri.get('combined', '')
            # If you have clean_text, keep using it; else just write combined_text
            # try:
            #     f.write(f"Plan Repair Info (combined): \n{clean_text(combined_text)}\n\n")
            # except NameError:
            #     f.write(f"Plan Repair Info (combined): \n{combined_text}\n\n")
            # Top-level explanation (existing behavior)
            explanation = data.get('explanation', '')
            explanation = strip_expl_prefix(explanation)
            # f.write(f"Explanation (combined):\n{explanation}\n\n")

            # >>> NEW: per-change explanations A and B <<<
            if isinstance(pri, dict):
                per_change = pri.get('per_change', {})
                A = per_change.get('A', {}) if isinstance(per_change, dict) else {}
                B = per_change.get('B', {}) if isinstance(per_change, dict) else {}

                expA = strip_expl_prefix(A.get('explanation', ''))
                expB = strip_expl_prefix(B.get('explanation', ''))
                chgA = A.get('change', '')
                chgB = B.get('change', '')

                if expA or chgA:
                    f.write("Explanation \n")
                    f.write(f" [{chgA}]" if chgA else "")
                    f.write(":\n")
                    f.write(f"{expA}\n\n")

                if expB or chgB:
                    # f.write("Explanation 2")
                    f.write(f" [{chgB}]" if chgB else "")
                    f.write(":\n")
                    f.write(f"{expB}\n")


        elif metric == "Metric2":
            # Conversion logic for Metric2
            #f.write(f"Goal: {data['goal']}\n")
            #f.write(f"Metric: {data['metric']}\n")
            f.write("Chosen Solution:\n")
            for solution in data['chosen_solution']:
                f.write(f"  - {solution}\n")
            f.write("Initial Plan:\n")
            if 'init_plan' in data:
                plan = data['init_plan']
                # Find the index of "(flip )" and get everything after it
                if "(flip )" in plan:
                    flip_index = plan.index("(flip )")
                    plan = plan[flip_index + 1:]  # Get all elements after "(flip )"

            # Update the 'init_plan' key with the modified plan
            data['init_plan'] = plan
            for step in data['init_plan']:
                f.write(f"  {step}\n")
            f.write("Final Plan:\n")
            if 'final_plan' in data:
                plan = data['final_plan']
                # Find the index of "(flip )" and get everything after it
                if "(flip )" in plan:
                    flip_index = plan.index("(flip )")
                    plan = plan[flip_index + 1:]  # Get all elements after "(flip )"

            # Update the 'final_plan' key with the modified plan
            data['final_plan'] = plan
            for step in data['final_plan']:
                f.write(f"  {step}\n")
            f.write(f"Initial Cost of Plan: {data['initial_cost']}\n")  # Add initial cost
            f.write(f"Final Cost of Plan: {data['final_cost']}\n")      # Add final cost

            # Remove "Here is the explanation" if present
            explanation = data.get('explanation', '')
            prefix = "Here's a plain English explanation of why the plan fails:\n\n"
            if explanation.startswith(prefix):
                explanation = explanation[len(prefix):].lstrip()

            f.write(f"Explanation:\n{explanation}\n")
            
        else:
            f.write("Unknown metric type. No conversion performed.\n")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))

    input_json_path = os.path.join(base_dir, 'results_json', 'results.json')
    output_txt_path = os.path.join(base_dir, 'results_json', 'results.txt')

    save_json_to_text(input_json_path, output_txt_path)

