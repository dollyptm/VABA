import os
from langchain_openai import OpenAI
from langchain_community.utilities import SQLDatabase
from langchain_community.agent_toolkits import create_sql_agent
from langchain_openai import ChatOpenAI


# Initialize the OpenAI API
llm = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
    temperature=0.7
)

# Connect to the SQLite database
db = SQLDatabase.from_uri("sqlite:///company.db")

# Initialize the language model
llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)

# Create the SQL agent
agent_executor = create_sql_agent(
    llm=llm,
    db=db,
    agent_type="zero-shot-react-description",
    verbose=False
)

# Example usage
response = agent_executor.invoke("Who is the highest paid employee and what is their position?")
print(response)

# You can ask more complex questions like:
# response = agent_executor.invoke("Who is the highest paid employee and what is their position?")
# response = agent_executor.invoke("How many employees are there for each position?")