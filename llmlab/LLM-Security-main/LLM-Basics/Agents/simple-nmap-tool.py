from openai import OpenAI
import subprocess
import json

# Initialize OpenAI client
client = OpenAI()

def run_nmap(target, ports=None, scan_type="-sV"):
    """
    Safely run nmap with specified parameters
    """
    try:
        cmd = ["nmap", scan_type]
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)
        
        print(f"\nExecuting command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running nmap: {str(e)}"

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

def main():
    # Get user input
    user_input = input("What would you like to scan? (e.g., 'scan localhost for open ports'): ")

    
    # Get response from OpenAI
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}],
        tools=tools
    )
    
    message = response.choices[0].message
    
    if message.tool_calls:
        tool_call = message.tool_calls[0]
        function_args = json.loads(tool_call.function.arguments)
        
        print("\nTool call details:")
        print(f"Function called: {tool_call.function.name}")
        print(f"Arguments: {json.dumps(function_args, indent=2)}")
        
        result = run_nmap(**function_args)
        print("\nScan results:")
        print(result)
    else:
        print("No nmap command was generated from your request.")

if __name__ == "__main__":
    main() 