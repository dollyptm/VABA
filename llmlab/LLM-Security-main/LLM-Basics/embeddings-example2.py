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


# Descriptions for animals
animals = {
    "cat": "A small, domestic carnivorous mammal with soft fur.",
    "dog": "A medium-sized, domestic carnivorous mammal, known as man's best friend.",
    "lion": "A large, wild carnivorous mammal, known as the king of the jungle.",
    "fish": "An aquatic animal that lives in water and typically has gills, fins, and scales."
}

# Get and print embeddings for each animal description
for animal, description in animals.items():
    embedding = get_embedding(description)
    print("animal - ")
    print(animal)
    print(embedding)  # Print first 5 dimensions for brevity
    print("---------")
