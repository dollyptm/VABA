import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    # This is the default and can be omitted
    api_key=os.environ.get("OPENAI_API_KEY"),
)

# Create a function to get embeddings and return the response
def get_embedding(text, model="text-embedding-ada-002"):
    response = client.embeddings.create(
        model=model,
        input=text
    )
    return response

# Sample text to embed
text = "burger"

# Get the embedding response for the sample text
response = get_embedding(text)

# Print the response
print(response)
