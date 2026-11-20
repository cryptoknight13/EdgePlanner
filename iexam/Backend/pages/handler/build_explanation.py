import sys

def extract_plan(input_file, prompt_file, output_file):
    """
    Extract the plan from the input file, append the prompt from the prompt file, and write to the output file.
    """
    try:
        # Read the plan from the input file
        with open(input_file, 'r') as file:
            plan = file.read()

        # Read the prompt from the prompt file
        with open(prompt_file, 'r') as file:
            prompt = file.read()

        # Write the plan and prompt to the output file
        with open(output_file, 'w') as output:
            output.write(plan + "\n\n")
            output.write(prompt)

        print("Plan and prompt are extracted and written to the output file.")
        return plan
    except Exception as e:
        print(f"An error occurred: {e}")
        raise

def extract_options(input_file, prompt_file, output_file):
    """
    Extract the options from the input file, append the prompt from the prompt file, and write to the output file.
    """
    try:
        # Read the options from the input file
        with open(input_file, 'r') as file:
            options = file.read()

        # Read the prompt from the prompt file
        with open(prompt_file, 'r') as file:
            prompt = file.read()

        # Write the options and prompt to the output file
        with open(output_file, 'w') as output:
            output.write(options + "\n\n")
            output.write(prompt)

        print("Plan and prompt are extracted and written to the output file.")
        return options
    except Exception as e:
        print(f"An error occurred: {e}")
        raise

# def extract_plan(input_file, prompt_file, output_file):
#     """
#     Extract the plan from the input file, append the prompt from the prompt file, and write to the output file.
#     """
#     try:
#         # Read the plan from the input file
#         with open(input_file, 'r') as file:
#             plan = file.read()

#         # Read the prompt from the prompt file
#         with open(prompt_file, 'r') as file:
#             prompt = file.read()

#         # Write the plan and prompt to the output file
#         with open(output_file, 'w') as output:
#             output.write(plan + "\n\n")
#             output.write(prompt)

#         print("Plan and prompt are extracted and written to the output file.")
#         return plan
#     except Exception as e:
#         print(f"An error occurred: {e}")