import os
import argparse
from dotenv import load_dotenv
from langchain_openai import OpenAI
from langchain_core.prompts import PromptTemplate

# Load environment variables
load_dotenv()

# Parse command line arguments
parser = argparse.ArgumentParser(description='Process a description for the application.')
parser.add_argument('description', type=str, help='The description of the application')
args = parser.parse_args()

# Initialize the OpenAI API
llm = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
    temperature=0.7
)

# Define the prompt template for finding the common vulnerability
template_vulnerability = """What is the most common vulnerability for {app_description}?
"""

# The input_variables parameter is used to define placeholders in a prompt template, allowing dynamic input to be substituted into the template at runtime.
prompt_template_vulnerability = PromptTemplate(
    input_variables=["app_description"],
    template=template_vulnerability,
)

# Create the chain for finding the vulnerability
chain_vulnerability = prompt_template_vulnerability | llm

# Use the description from the command line argument
description = args.description

# Invoke the chain to find the vulnerability
vulnerability_response = chain_vulnerability.invoke({"app_description": description})
vulnerability = vulnerability_response.strip()
print(f"Common Vulnerability: {vulnerability}")

# Define the prompt template for finding the exploit
template_exploit = """How do exploit this -  {vulnerability}?
"""
# The input_variables parameter is used to define placeholders in a prompt template, allowing dynamic input to be substituted into the template at runtime.
prompt_template_exploit = PromptTemplate(
    input_variables=["vulnerability"],
    template=template_exploit,
)

# Create the chain for finding the exploit
chain_exploit = prompt_template_exploit | llm

# Invoke the chain to find the exploit
exploit_response = chain_exploit.invoke({"vulnerability": vulnerability})
exploit = exploit_response.strip()
print(f"Exploit for {vulnerability}: {exploit}")