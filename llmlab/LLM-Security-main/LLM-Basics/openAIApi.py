import os
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Initialize the OpenAI client with the API key from the environment variable
client = OpenAI(
    # This is the default and can be omitted
    api_key=os.environ.get("OPENAI_API_KEY"),
)

# Function to get a response from the OpenAI API based on a given prompt
def get_openai_response(prompt):
    # Create a chat completion using the GPT-3.5-turbo model
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a Product security Expert"},
            {"role": "user", "content": prompt},
        ]
    )
    
    # Extract the response content from the API response
    data = completion.choices[0].message.content
    return data

# Main function to handle the primary logic of the script
def main():
    # Define the prompt to be sent to the OpenAI API
    prompt = "What do I use for password hashing?"
    
    # Get the response from the OpenAI API using the defined prompt
    response = get_openai_response(prompt)
    
    # Print the response to the console
    print(response)

# Call the main function directly to execute the script
main()