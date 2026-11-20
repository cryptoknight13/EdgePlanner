import os
import sys
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from handler.build_api import process_explanation_file
import utils

def clear_folder(folder_path):
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)
        elif os.path.isdir(file_path):
            import shutil
            shutil.rmtree(file_path)

def generate_explanations(validation_file, prompt_file, temp_combined_file):
    """
    Convert a single option from a specific validation file into natural language using build_explanation.py and build_api,
    and return the result.
    """
    
    # Check if the validation file exists
    if not os.path.isfile(validation_file):
        print(f"Error: {validation_file} does not exist.")
        return None

    # Check if the prompt file exists
    if not os.path.isfile(prompt_file):
        print(f"Error: {prompt_file} does not exist.")
        return None

    # Read all explanations from the validation file
    with open(validation_file, 'r') as file:
        explanations = [line.strip() for line in file.readlines()]

    if not explanations:
        print("No explanations found in the validation file.")
        return None

    # Combine all explanations into a single string
    combined_explanations = "\n".join(explanations)
    print(f"Processing combined explanations:\n{combined_explanations}")

    # Read the prompt template
    try:
        with open(prompt_file, 'r') as file:
            prompt_template = file.read().strip()
        print(f"Loaded prompt template from {prompt_file}")
    except Exception as e:
        print(f"An error occurred while reading the prompt file: {e}")
        return None

    # Combine the first explanation with the prompt
    try:
        with open(temp_combined_file, 'w') as temp_file:
            temp_file.write(combined_explanations + "\n")
            temp_file.write(prompt_template)
        print(f"Combined input written to {temp_combined_file}")
    except Exception as e:
        print(f"An error occurred while writing to the temporary file: {e}")
        return None

    # Generate the explanation. Do NOT swallow exceptions — propagate so the
    # caller's subprocess exits non-zero and the SSE stream surfaces the
    # actual upstream error (missing API key, 401, network drop) instead of
    # silently writing an empty all_explanations.txt.
    explanation = process_explanation_file(temp_combined_file)
    if explanation is None:
        raise RuntimeError(
            "process_explanation_file returned None — LLM call produced no "
            "content."
        )
    print(f"Generated explanation: {explanation}")
    return explanation

def save_results_to_single_file(result, result_file):
    """
    Save the combined results to a single output file.
    """
    try:
        with open(result_file, 'w') as file:
            file.write(result)
        print(f"All explanations saved to {result_file}")
    except Exception as e:
        print(f"An error occurred while saving the results: {e}")

def main():
    """
    Main function to execute the conversion process for all validation files.
    """
    project_root = utils.get_project_root()
    validation_folder = os.path.join(project_root, 'metric1_output', 'results', 'validations')
    prompt_file = os.path.join(project_root, 'inputs', 'explanation_Prompts.txt')
    temp_combined_file = os.path.join(project_root, 'inputs', 'explanation_input_to_llm.txt')
    output_folder = os.path.join(project_root, 'metric1_output', 'results', 'explanations')
    result_file = os.path.join(output_folder, 'all_explanations.txt')

    # Clear previous outputs
    if os.path.exists(output_folder):
        clear_folder(output_folder)
    if os.path.exists(result_file):
        os.remove(result_file)

    os.makedirs(output_folder, exist_ok=True)

    combined_result = ""

    # Iterate over all validation files in the folder
    for validation_file in Path(validation_folder).glob("*.txt"):
        validation_file = str(validation_file)  # Convert Path object to string
        print(f"Processing validation file: {validation_file}")

        # Only generate explanation and append to combined_result
        generated_explanation = generate_explanations(validation_file, prompt_file, temp_combined_file)
        if generated_explanation:
            combined_result += generated_explanation + "\n\n"

    print("All validation files have been processed.")
    save_results_to_single_file(combined_result.strip(), result_file)


if __name__ == "__main__":
    main()