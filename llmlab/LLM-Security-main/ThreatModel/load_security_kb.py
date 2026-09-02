# Uncomment the following line if you need to initialize FAISS with no AVX2 optimization
# os.environ['FAISS_NO_AVX2'] = '1'

from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import CharacterTextSplitter
import os

# Specify the directory containing the text files
directory_path = "internal_documents"

# Load all text files from the directory
documents = []
for filename in os.listdir(directory_path):
    if filename.endswith(".txt"):  # You can modify this to include other file types if needed
        file_path = os.path.join(directory_path, filename)
        loader = TextLoader(file_path)
        documents.extend(loader.load())

text_splitter = CharacterTextSplitter(
    chunk_size=300, 
    chunk_overlap=0)

docs = text_splitter.split_documents(documents)

embeddings = OpenAIEmbeddings()

db = FAISS.from_documents(docs, embeddings)

print("Vector DB Successfully Created!")

db.save_local("faiss_index")
