# import os
# import sys
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# from handler.build_api import process_options_file
# import utils

# def convert_options_to_natural_language():
#     """
#     Convert each option from pddl_options.txt into natural language using build_explanation.py and build_api,
#     and save the results in llm_generated_options.txt.
#     """
#     # File paths
#     options_file = os.path.join(utils.get_project_root(), 'data', 'pddl_options.txt')
#     prompt_file = os.path.join(utils.get_project_root(), 'inputs', 'option_prompt.txt')
#     temp_combined_file = os.path.join(utils.get_project_root(), 'inputs', 'options_input.txt')
#     output_file = os.path.join(utils.get_project_root(), 'data', 'llm_generated_options.txt')

#     # Check if the options file exists
#     if not os.path.isfile(options_file):
#         print(f"Error: {options_file} does not exist.")
#         return

#     # Check if the prompt file exists
#     if not os.path.isfile(prompt_file):
#         print(f"Error: {prompt_file} does not exist.")
#         return

#     # Read options from pddl_options.txt
#     with open(options_file, 'r') as file:
#         options = [line.strip() for line in file.readlines()]

#     # Check if there are any options
#     if not options:
#         print("No options found in pddl_options.txt.")
#         return

#     # Ensure the output directory exists
#     os.makedirs(os.path.dirname(output_file), exist_ok=True)

#     # Open the output file for writing
#     with open(output_file, 'w') as output:
#         for idx, option in enumerate(options, start=1):
#             print(f"Processing option {idx}/{len(options)}: {option}")
#             try:
#                 # Write the current option to a temporary file
#                 with open(temp_combined_file, 'w') as temp_file:
#                     temp_file.write(option + "\n")
#                     with open(prompt_file, 'r') as prompt:
#                         temp_file.write(prompt.read())

#                 # Use the build_api to process the combined input
#                 natural_language_option = process_options_file(temp_combined_file)

#                 # Write the result to llm_generated_options.txt
#                 output.write(f"Option {idx}: {natural_language_option}\n")
#             except Exception as e:
#                 print(f"Error processing option {idx}: {e}")
#                 output.write(f"Option {idx}: Error processing this option.\n")

#     print(f"All options have been converted and saved to {output_file}")

# def main():
#     """
#     Main function to execute the conversion process.
#     """
#     print("Starting the conversion of options to natural language...")
#     convert_options_to_natural_language()
#     print("Conversion process completed.")

# if __name__ == "__main__":
#     main()

import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from handler.build_api import process_options_file
import utils

def convert_options_to_natural_language():
    """
    Convert each option from pddl_options.txt into natural language using build_explanation.py and build_api,
    and save the results in llm_generated_options.txt.
    """
    # File paths
    options_file = os.path.join(utils.get_project_root(), 'data', 'pddl_options.txt')
    prompt_file = os.path.join(utils.get_project_root(), 'data', 'prompt.txt')
    temp_combined_file = os.path.join(utils.get_project_root(), 'data', 'options_input.txt')
    output_file = os.path.join(utils.get_project_root(), 'data', 'llm_generated_options.txt')

    # Check if the options file exists
    if not os.path.isfile(options_file):
        print(f"Error: {options_file} does not exist.")
        return

    # Check if the prompt file exists
    if not os.path.isfile(prompt_file):
        print(f"Error: {prompt_file} does not exist.")
        return

    # Read options from pddl_options.txt
    with open(options_file, 'r') as file:
        options = [line.strip() for line in file.readlines()]

    # Check if there are any options
    if not options:
        print("No options found in pddl_options.txt.")
        return

    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Open the output file for writing
    with open(output_file, 'w') as output:
        for idx, option in enumerate(options, start=1):
            print(f"Processing option {idx}/{len(options)}: {option}")
            try:
                # Write the current option to a temporary file
                with open(temp_combined_file, 'w') as temp_file:
                    temp_file.write(option + "\n")
                    with open(prompt_file, 'r') as prompt:
                        temp_file.write(prompt.read())

                # Use the build_api to process the combined input
                natural_language_option = process_options_file(temp_combined_file)

                # Write the result to llm_generated_options.txt
                output.write(f"Option {idx}: {natural_language_option}\n")
            except Exception as e:
                print(f"Error processing option {idx}: {e}")
                output.write(f"Option {idx}: Error processing this option.\n")

    print(f"All options have been converted and saved to {output_file}")

def main():
    """
    Main function to execute the conversion process.
    """
    print("Starting the conversion of options to natural language...")
    convert_options_to_natural_language()
    print("Conversion process completed.")

if __name__ == "__main__":
    main()