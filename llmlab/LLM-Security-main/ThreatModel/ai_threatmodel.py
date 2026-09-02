import json
import sys
from openai import OpenAI
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_community.vectorstores import FAISS
from langchain.chains import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate
from colorama import Fore, Style, init

class SecurityAnalyzer:
    def __init__(self):
        """
        Initializes the SecurityAnalyzer class by setting up the OpenAI client and embeddings.
        """
        self.openai_client = OpenAI()  # Initialize OpenAI client directly
        self.embeddings = OpenAIEmbeddings()  # Initialize the embeddings for vector store
        self.llm = ChatOpenAI(model_name="gpt-3.5-turbo", temperature=0)  # Initialize the ChatOpenAI model for generating responses

        init(autoreset=True)  # Initialize colorama

    def get_openai_response(self, prompt):
        """
        Sends a prompt to the OpenAI client and retrieves the response.
        
        Args:
            prompt (str): The prompt to be sent to the OpenAI model.

        Returns:
            dict or None: Parsed JSON response from OpenAI or None if an error occurs.
        """
        try:
            completion = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": "You are a Product Security Expert"},
                    {"role": "user", "content": prompt},
                ]
            )
            data = completion.choices[0].message.content  # Extract the content from the response
            return json.loads(data)  # Parse the JSON content
        except json.JSONDecodeError as e:
            print("JSON decoding error:", e)  # Handle JSON parsing errors
            return None
        except Exception as e:
            print("Error:", e)  # Handle other errors
            return None

    def retriever(self, mitigation_from_llm):
        """
        Retrieves mitigation strategies from the vector store based on the input query.

        Args:
            query (str): The security risk query.

        Returns:
            str: Mitigation text or an error message if not found.
        """
        new_db = FAISS.load_local("faiss_index", self.embeddings, allow_dangerous_deserialization=True)
        # Load the FAISS vector store
        retriever = new_db.as_retriever()  # Set up the retriever from the vector store

        # Prompt
        template = """You are a Product Security Expert. 
        Analyze the following context which is retrived from internal best practices
        {context}
        Update the below Mitigation, if there is any relevant content from above. Don't add irrelvant content to mitigation. Try to be specific
        Mitigation: {mitigation}
        """

        prompt = ChatPromptTemplate.from_template(template)

        chain = prompt | self.llm

        relevant_mitigation = new_db.similarity_search_with_score(mitigation_from_llm)

        result = chain.invoke({"context":relevant_mitigation,"mitigation":mitigation_from_llm})

        # Return the result (output from the chain invocation)
        return result.content if result else "No output generated"

    def analyze_security(self, document):
        """
        Analyzes a document to identify security risks and provides mitigations.

        Args:
            document (str): The document content to analyze.

        Returns:
            None
        """
        prompt = """
            Identify Low, Medium, High severity Security issues in the document. Based on the issue found, also give mitigation options.
            Return the output as a JSON string in the following format:
            risks = [
                {"severity": "Low", "risk_details": "details", "mitigation": "mitigation"},
                {"severity": "Medium", "risk_details": "details", "mitigation": "mitigation"},
                # Add more elements as needed
            ]
        """

        response = self.get_openai_response(document + "\n" + prompt)  # Get the response from OpenAI
        if response:
            risks_list = response.get('risks', [])  # Extract the risks list from the response
            for risk in risks_list:
                risk['mitigation'] = self.retriever(risk['mitigation'])  # Update mitigation with retrieval result
            
            # Beautify and print the updated risks with colors
            print("\nMitigation Updated Risks:")
            for risk in risks_list:
                severity_color = self.get_severity_color(risk['severity'])
                print(f"{severity_color}Severity: {risk['severity']}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Details: {risk['risk_details']}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Mitgation: {risk['mitigation']}{Style.RESET_ALL}")
                print("-" * 50)

    def get_severity_color(self, severity):
        """
        Returns the appropriate color based on severity level.
        
        Args:
            severity (str): The severity level ("Low", "Medium", "High").

        Returns:
            str: The colorama color code.
        """
        if severity == "High":
            return Fore.RED + Style.BRIGHT
        elif severity == "Medium":
            return Fore.YELLOW + Style.BRIGHT
        elif severity == "Low":
            return Fore.GREEN + Style.BRIGHT
        else:
            return Fore.WHITE + Style.BRIGHT

if __name__ == "__main__":
    # Check if the document path is provided
    import getpass
    import os

    if len(sys.argv) != 2:
        print("Usage: python3 threat_analyzer.py <document_path>")
        sys.exit(1)

    document_path = sys.argv[1]

    # Read the document from the provided path
    try:
        with open(document_path, 'r') as file:
            document = file.read()
    except FileNotFoundError:
        print(f"Error: The file at path {document_path} was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred - {e}")
        sys.exit(1)

    # Create an instance of SecurityAnalyzer
    analyzer = SecurityAnalyzer()

    # Analyze security problems in the document
    analyzer.analyze_security(document)
