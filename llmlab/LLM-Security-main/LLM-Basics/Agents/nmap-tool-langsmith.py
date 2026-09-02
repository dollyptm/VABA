import subprocess
import json
import os
from langsmith import Client
from langsmith.run_helpers import traceable
from openai import OpenAI

# Set LangSmith environment variables if not already set
# This MUST be done before initializing the Client or using @traceable
if not os.getenv("LANGCHAIN_API_KEY"):
    os.environ["LANGCHAIN_API_KEY"] = "your-api-key-here"  # Replace with your actual API key
if not os.getenv("LANGCHAIN_PROJECT"):
    os.environ["LANGCHAIN_PROJECT"] = "nmap-tool"
if not os.getenv("LANGCHAIN_TRACING_V2"):
    os.environ["LANGCHAIN_TRACING_V2"] = "true"

# Initialize LangSmith client
client = Client()

# Initialize OpenAI client
openai_client = OpenAI()

@traceable(run_type="tool", name="run_nmap")
def run_nmap(target, ports=None, scan_type="-sV"):
    """
    Safely run nmap with specified parameters
    """
    try:
        cmd = ["nmap", scan_type]
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running nmap: {str(e)}"

@traceable(run_type="llm", name="openai_chat_completion")
def _call_openai_traced(messages, tools):
    """Helper function to trace OpenAI API calls"""
    return openai_client.chat.completions.create(
        model="gpt-4",
        messages=messages,
        tools=tools
    )

tools = [{
    "type": "function",
    "function": {
        "name": "run_nmap",
        "description": "Run an nmap scan on a specified target with optional port range and scan type",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The target IP address or hostname to scan"
                },
                "ports": {
                    "type": "string",
                    "description": "Optional port range (e.g., '80,443' or '1-1000')"
                }
            },
            "required": ["target"]
        }
    }
}]

@traceable(run_type="chain", name="process_user_request")
def process_user_request(user_input):
    # Create the initial message
    messages = [{"role": "user", "content": user_input}]
    
    # Call OpenAI - this will be traced as part of the parent traceable function
    response = _call_openai_traced(messages, tools)
    
    message = response.choices[0].message
    print(message)
    
    if message.tool_calls:
        tool_call = message.tool_calls[0]
        function_args = json.loads(tool_call.function.arguments)
        
        print("\nExecuting nmap scan with parameters:")
        print(json.dumps(function_args, indent=2))
        
        result = run_nmap(**function_args)
        print("\nScan results:")
        print(result)
        return result
    else:
        print("No nmap command was generated from your request.")
        return None

def main():
    # Verify LangSmith is configured
    api_key = os.getenv("LANGCHAIN_API_KEY")
    if not api_key or api_key == "your-api-key-here":
        print("Warning: LANGCHAIN_API_KEY is not set or is using placeholder value.")
        print("Please set your LangSmith API key:")
        print("  export LANGCHAIN_API_KEY='your-actual-api-key'")
        print("  Or set it in the code at the top of the file.")
        print("\nContinuing anyway, but tracing may not work...\n")
    
    # Example usage
    user_input = input("What would you like to scan? (e.g., 'scan localhost for open ports'): ")
    process_user_request(user_input)

if __name__ == "__main__":
    main()