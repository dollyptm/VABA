from openai import OpenAI
import subprocess
import json
import requests
import ssl
import socket
from typing import Dict, List, Optional
from datetime import datetime, timedelta

# Initialize OpenAI client
client = OpenAI()

def check_api_key():
    """Check if OpenAI API key is set"""
    try:
        client = OpenAI()
        client.models.list()
    except Exception as e:
        print("Error: OpenAI API key not configured or invalid")
        print("Please set your OpenAI API key using:")
        print("export OPENAI_API_KEY='your-api-key'")
        exit(1)

def run_nmap(target: str) -> str:
    """Run basic nmap scan on target"""
    try:
        cmd = ["nmap", "-sV", target]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running nmap: {str(e)}"

def check_ssl(target: str, port: int = 443) -> dict:
    """Check SSL/TLS configuration"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "subject": dict(x[0] for x in cert['subject']),
                    "not_before": cert['notBefore'],
                    "not_after": cert['notAfter']
                }
    except Exception as e:
        return {"valid": False, "error": str(e)}

def check_web_security(target: str) -> dict:
    """Check basic web security headers"""
    try:
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        response = requests.get(target, verify=False, timeout=10)
        headers = dict(response.headers)
        
        security_headers = {
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing")
        }
        
        return {
            "status_code": response.status_code,
            "security_headers": security_headers
        }
    except Exception as e:
        return {"error": str(e)}

def analyze_results(results: dict, context: str) -> dict:
    """Analyze the results and determine next steps"""
    analysis_prompt = f"""
    Based on the following security scan results and the user's goal: "{context}"
    
    Results:
    {json.dumps(results, indent=2)}
    
    Analyze these results and determine:
    1. What security issues were found?
    2. What additional checks should be performed?
    3. What recommendations can be made?
    
    Format your response as a JSON object with:
    - "issues": List of found security issues
    - "next_steps": List of recommended next steps
    - "recommendations": List of security recommendations
    """
    
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": analysis_prompt}]
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {
            "issues": ["Error during analysis"],
            "next_steps": ["Retry the analysis"],
            "recommendations": ["Check the error message above"]
        }

def main():
    # Check API key before starting
    check_api_key()
    
    # Define available tools
    tools = [{
        "type": "function",
        "function": {
            "name": "run_nmap",
            "description": "Run an nmap scan on a specified target",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target IP address or hostname to scan"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_ssl",
            "description": "Check SSL/TLS configuration of a target",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target hostname to analyze"
                    },
                    "port": {
                        "type": "integer",
                        "description": "The SSL/TLS port to analyze (default: 443)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_web_security",
            "description": "Check web application security headers",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target URL to scan"
                    }
                },
                "required": ["target"]
            }
        }
    }]

    try:
        # Get user input
        user_input = input("What security assessment would you like to perform? (e.g., 'check the security of example.com'): ")
        
        # Initialize results storage
        all_results = {}
        max_iterations = 3  # Prevent infinite loops
        iteration = 0
        
        while iteration < max_iterations:
            try:
                # Get next action from GPT
                response = client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": "You are a security assessment agent. Based on the user's goal and previous results, determine what security checks to perform next."},
                        {"role": "user", "content": f"Goal: {user_input}\nPrevious results: {json.dumps(all_results, indent=2)}\nWhat should we check next?"}
                    ],
                    tools=tools
                )
                
                message = response.choices[0].message
                
                if not message.tool_calls:
                    # No more tools to run, analyze final results
                    final_analysis = analyze_results(all_results, user_input)
                    print("\nFinal Security Assessment:")
                    print(json.dumps(final_analysis, indent=2))
                    break
                    
                # Execute the recommended tool
                tool_call = message.tool_calls[0]
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                
                print(f"\nExecuting {function_name}...")
                print(f"Arguments: {json.dumps(function_args, indent=2)}")
                
                if function_name == "run_nmap":
                    result = run_nmap(**function_args)
                elif function_name == "check_ssl":
                    result = check_ssl(**function_args)
                elif function_name == "check_web_security":
                    result = check_web_security(**function_args)
                else:
                    result = {"error": f"Unknown tool: {function_name}"}
                
                all_results[function_name] = result
                iteration += 1
                
            except Exception as e:
                print(f"\nError during iteration {iteration + 1}: {str(e)}")
                iteration += 1
                continue
                
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Generating partial results...")
        if all_results:
            final_analysis = analyze_results(all_results, user_input)
            print("\nPartial Security Assessment:")
            print(json.dumps(final_analysis, indent=2))
        exit(0)
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main() 