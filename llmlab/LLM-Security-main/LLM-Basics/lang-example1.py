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

# Define the prompt template
template = """What is the most common vulnerability for {app_description}?
"""

prompt_template = PromptTemplate(
    input_variables=["app_description"],
    template=template,
)

# Create the chain
chain = prompt_template | llm

# Use the description from the command line argument
description = args.description

# Invoke the chain
response = chain.invoke({"app_description": description})

# Print the response
print(response)
