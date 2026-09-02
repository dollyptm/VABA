from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import CharacterTextSplitter
import configparser
import os
import faiss
from openai import OpenAI

from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

# Initialize the OpenAI client with the API key from environment variables
client = OpenAI(
    # This is the default and can be omitted
    api_key=os.environ.get("OPENAI_API_KEY"),
)

def process_documents_and_create_vector_store(file_path, chunk_size=300, chunk_overlap=0, save_path="faiss_index"):
    """Load documents, process them, create embeddings, and save the vector store."""
    # Load documents
    loader = TextLoader(file_path)
    documents = loader.load()

    # Split documents
    text_splitter = CharacterTextSplitter(
        chunk_size=chunk_size, 
        chunk_overlap=chunk_overlap
    )
    docs = text_splitter.split_documents(documents)

    # Create embeddings and vector store
    embeddings = OpenAIEmbeddings()
    db = FAISS.from_documents(docs, embeddings)

    # Save vector store
    db.save_local(save_path)
    print("Vector DB Successfully Created!")

def main():
    """Main function to execute the setup and processing."""
    file_path = "best-practices.txt"

    process_documents_and_create_vector_store(file_path)

if __name__ == "__main__":
    main()