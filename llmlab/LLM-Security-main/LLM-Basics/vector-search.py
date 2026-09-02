# Uncomment the following line if you need to initialize FAISS with no AVX2 optimization
# os.environ['FAISS_NO_AVX2'] = '1'

from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import CharacterTextSplitter
import configparser
import os
import faiss
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(
    # This is the default and can be omitted
    api_key=os.environ.get("OPENAI_API_KEY"),
)

def load_vectordb(input_query):
    embeddings = OpenAIEmbeddings()

    #we need to be careful what we load here - to review. This can cause Pickle exploitation
    new_db = FAISS.load_local("faiss_index", embeddings,allow_dangerous_deserialization=True)

    query = input_query

    #docs = new_db.similarity_search(query)

    docs = new_db.similarity_search_with_score(query)

    print(docs[0])

load_vectordb('how to backup data')

