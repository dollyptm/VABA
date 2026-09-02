from openai import OpenAI
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
import os
from langchain.chains import RetrievalQA
from langchain.chains import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import json

def get_openai_response(prompt):
    try:
        client = OpenAI()
        completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        response_format={ "type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a Product security Expert"},
            {"role": "user", "content": prompt},
          ]
        )

        #print(completion.choices[0].message.content)

        data = completion.choices[0].message.content

        try:
            data = json.loads(data)

        except json.JSONDecodeError as e:
            print("JSON decoding error:", e)

        # Access the 'risks' key to get the list of risks
        risks_list = data['risks']

        #print("\nBefore")

        # Output the updated risks_list
        #for risks in risks_list:
            #print(risks)

        for risks in risks_list:
            risks['mitigation'] = retriever(risks['mitigation'])

        print("\nAfter")

        # Output the updated risks_list
        for risks in risks_list:
            print(risks)

    except Exception as e:
        return str(e)

def generate_data_flow_diagram(document):
    try:
        # Define prompt for generating the data flow diagram
        prompt = """
        Generate a data flow diagram (DFD) based on the design document provided below, show the code in mermaid code/sequenceDiagram:

        Design Document:
        """ + document

        # Request response from OpenAI
        response = get_openai_response(prompt)

        print(response)

    except Exception as e:
        return str(e)


def load_vectordb(input_query):
    embeddings = OpenAIEmbeddings()

    #we need to be careful what we load here - to review. This can cause Pickle exploitation
    new_db = FAISS.load_local("faiss_index", embeddings,allow_dangerous_deserialization=True)

    query = input_query

    #docs = new_db.similarity_search(query)

    docs = new_db.similarity_search_with_score(query)

    print(docs[0])


def retriever(query):
    # Caution: Review carefully to avoid Pickle exploitation risk
    embeddings = OpenAIEmbeddings()
    new_db = FAISS.load_local("faiss_index", embeddings, allow_dangerous_deserialization=True)
    retriever = new_db.as_retriever()
    llm = ChatOpenAI()

    system_prompt = (
        "Treat the query as a risk and get mitigtion from the given context"
        "If you don't know the answer, say you don't know. "
        "Use five sentence maximum and keep the answer concise. "
        "Do not repeat the query, just show mitigtion"
        "Use the text provided in the context"
        "Context: {context}"
    )
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", "{input}"),
        ]
    )
    question_answer_chain = create_stuff_documents_chain(llm, prompt)
    chain = create_retrieval_chain(retriever, question_answer_chain)

    result = chain.invoke({"input": query})
    if result:
        return result['answer']  # Assuming "text" is the key for the matched answer
    else:
        return 0

def analyze_security(document):
    try:
        # Define prompts for different severity levels
        prompt = """
            Identify Low, Medium, High severity Secuity issues in the document. Based on the issue found, also give mitigation option.
            Return the output as a JSON string
            risks = [
                    (severity, "risk_details", "mitigation"),
                    (severity, "risk_details", "mitigation"),
                    # Add more elements as needed
                    ]
        """

    
        response = get_openai_response(document + "\n" + prompt)
        
    except Exception as e:
        print("Error:", str(e))


if __name__ == "__main__":
    # Read document from document.txt
    with open('file_sharing_platform.md', 'r') as file:
        document = file.read()
    
    # Analyze security problems in the document
    analyze_security(document)

    query = """
    Storing password in the database using AES 256 Encryption may pose a security risk if the encryption keys are compromised
    """

    #retriever(query)