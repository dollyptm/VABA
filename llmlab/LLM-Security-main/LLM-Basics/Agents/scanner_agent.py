from openai import OpenAI
import subprocess
import json
import requests
import ssl
import socket
import re
import logging
import sys
import os
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from langsmith import Client
from langsmith.run_helpers import traceable
from bs4 import BeautifulSoup
import urllib3

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_scanner.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize OpenAI client
client = OpenAI()

# Initialize LangSmith client
langsmith_client = Client()

@traceable(run_type="tool", name="check_api_key")
def check_api_key():
    """Check if OpenAI API key is set"""
    try:
        logger.info("Checking OpenAI API key...")
        client = OpenAI()
        client.models.list()
        logger.info("OpenAI API key is valid")
    except Exception as e:
        logger.error(f"OpenAI API key error: {str(e)}")
        print("Error: OpenAI API key not configured or invalid")
        print("Please set your OpenAI API key using:")
        print("export OPENAI_API_KEY='your-api-key'")
        exit(1)

@traceable(run_type="tool", name="parse_nmap_services")
def parse_nmap_services(nmap_output: str) -> List[Dict[str, str]]:
    """Parse NMAP output to extract service information"""
    logger.info("Parsing NMAP output for services...")
    services = []
    service_pattern = r"(\d+)/tcp\s+open\s+(\w+)\s+(.*?)(?:\n|$)"
    matches = re.finditer(service_pattern, nmap_output)
    
    for match in matches:
        port, service, version = match.groups()
        service_info = {
            "port": port,
            "service": service,
            "version": version.strip()
        }
        services.append(service_info)
        logger.debug(f"Found service: {service_info}")
    
    logger.info(f"Found {len(services)} services")
    return services

def check_nvd_vulnerabilities(service: str, version: str = None) -> Dict:
    """Check NVD for vulnerabilities related to detected services using OpenAI to generate API request"""
    logger.info(f"Checking NVD for vulnerabilities: {service} {version}")
    try:
        # Clean and format the service name
        service = service.lower().strip()
        
        # Use OpenAI to generate the API request
        prompt = f"""Based on the NVD API documentation at https://nvd.nist.gov/developers/vulnerabilities, 
        generate a Python requests code to query vulnerabilities for:
        Service: {service}
        Version: {version if version else 'any version'}
        
        The response should be a Python dictionary with the following keys:
        - url: The NVD API endpoint URL
        - headers: Dictionary of headers
        - params: Dictionary of query parameters
        
        Only return the Python dictionary, no explanations."""
        
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a security API expert. Generate only the Python dictionary for the API request."},
                {"role": "user", "content": prompt}
            ]
        )
        
        # Parse the API request configuration from OpenAI response
        try:
            api_config = json.loads(response.choices[0].message.content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OpenAI response: {str(e)}")
            return {
                "service": service,
                "version": version,
                "error": "Failed to generate API request configuration",
                "status": "error"
            }
        
        # Make the API request using the generated configuration
        logger.debug(f"NVD API request config: {api_config}")
        response = requests.get(
            api_config["url"],
            headers=api_config["headers"],
            params=api_config["params"],
            timeout=10
        )
        response.raise_for_status()
        
        # Parse the response
        vulnerabilities = []
        try:
            data = response.json()
            if isinstance(data, dict) and "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    if isinstance(vuln, dict) and "cve" in vuln:
                        cve = vuln["cve"]
                        vuln_info = {
                            "id": cve.get("id", "Unknown"),
                            "description": cve.get("descriptions", [{}])[0].get("value", "No description available"),
                            "severity": "Unknown",
                            "cvss_score": None,
                            "published": cve.get("published", "Unknown"),
                            "last_modified": cve.get("lastModified", "Unknown")
                        }
                        
                        # Extract CVSS scores if available
                        if "metrics" in cve:
                            metrics = cve["metrics"]
                            if "cvssMetricV31" in metrics:
                                cvss = metrics["cvssMetricV31"][0]
                                vuln_info["severity"] = cvss.get("cvssData", {}).get("baseSeverity", "Unknown")
                                vuln_info["cvss_score"] = cvss.get("cvssData", {}).get("baseScore")
                            elif "cvssMetricV2" in metrics:
                                cvss = metrics["cvssMetricV2"][0]
                                vuln_info["severity"] = cvss.get("baseSeverity", "Unknown")
                                vuln_info["cvss_score"] = cvss.get("cvssData", {}).get("baseScore")
                        
                        vulnerabilities.append(vuln_info)
                        logger.debug(f"Found vulnerability: {vuln_info['id']} - {vuln_info['severity']}")
            else:
                logger.warning("Unexpected JSON structure in NVD response")
                logger.debug(f"Response content: {data}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {str(e)}")
            logger.debug(f"Raw response content: {response.text[:500]}...")
        
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {service}")
        return {
            "service": service,
            "version": version,
            "vulnerabilities": vulnerabilities,
            "status": "success"
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"NVD API request failed: {str(e)}")
        return {
            "service": service,
            "version": version,
            "error": f"NVD API request failed: {str(e)}",
            "status": "error"
        }
    except Exception as e:
        logger.error(f"Error checking NVD: {str(e)}")
        return {
            "service": service,
            "version": version,
            "error": f"Error checking NVD: {str(e)}",
            "status": "error"
        }

@traceable(run_type="tool", name="run_nmap")
def run_nmap(target: str, ports: str = "80, 443, 8080") -> dict:
    """Run nmap scan on target with specified port range"""
    logger.info(f"Running NMAP scan on target: {target} for ports: {ports}")
    try:
        # Ensure target is properly formatted
        if not target.startswith(('http://', 'https://')):
            target = target.strip()
        
        # Remove protocol if present
        target = target.replace('http://', '').replace('https://', '')
        
        cmd = ["nmap", "-sV", "-p", ports, target]
        logger.debug(f"Executing command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"NMAP scan failed with return code {result.returncode}")
            logger.error(f"Error output: {result.stderr}")
            return {
                "error": f"NMAP scan failed: {result.stderr}",
                "nmap_output": "",
                "services": [],
                "vulnerability_checks": []
            }
        
        nmap_output = result.stdout
        logger.debug("NMAP scan completed successfully")
        
        # Parse services from NMAP output
        services = parse_nmap_services(nmap_output)
        
        # Check NVD for each detected service
        vulnerability_results = []
        for service in services:
            logger.info(f"Checking vulnerabilities for service: {service['service']} {service['version']}")
            vuln_check = check_nvd_vulnerabilities(service["service"], service["version"])
            vulnerability_results.append(vuln_check)
        
        return {
            "nmap_output": nmap_output,
            "services": services,
            "vulnerability_checks": vulnerability_results
        }
    except Exception as e:
        logger.error(f"Error running nmap: {str(e)}")
        return {
            "error": f"Error running nmap: {str(e)}",
            "nmap_output": "",
            "services": [],
            "vulnerability_checks": []
        }

@traceable(run_type="tool", name="check_web_security")
def check_web_security(target: str) -> dict:
    """Check basic web security headers"""
    logger.info(f"Checking web security headers for {target}")
    try:
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
            
        logger.debug(f"Making request to {target}")
        response = requests.get(target, verify=False, timeout=10)
        headers = dict(response.headers)
        
        security_headers = {
            "X-Frame-Options": headers.get("X-Frame-Options", "Missing"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Missing"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Missing"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Missing")
        }
        
        logger.debug(f"Security headers found: {security_headers}")
        return {
            "status_code": response.status_code,
            "security_headers": security_headers
        }
    except Exception as e:
        logger.error(f"Web security check failed: {str(e)}")
        return {"error": str(e)}

@traceable(run_type="chain", name="analyze_results")
def analyze_results(results: dict, context: str) -> dict:
    """Analyze the results and determine next steps based on user's context"""
    logger.info("Starting analysis of scan results")
    try:
        # Determine what the user is interested in
        context_lower = context.lower()
        focus_areas = {
            "ports": any(word in context_lower for word in ["port", "open port", "scan port"]),
            "vulnerabilities": any(word in context_lower for word in ["vulnerability", "vuln", "security issue"]),
            "web": any(word in context_lower for word in ["web", "http", "header", "security header"])
        }
        
        # Extract relevant information based on focus areas
        analysis_data = {}
        
        if "run_nmap" in results:
            nmap_results = results["run_nmap"]
            if isinstance(nmap_results, dict):
                # Always include basic port information
                if "services" in nmap_results:
                    analysis_data["ports"] = nmap_results["services"]
                
                # Include vulnerability information if relevant
                if focus_areas["vulnerabilities"] and "vulnerability_checks" in nmap_results:
                    vulnerability_info = []
                    for check in nmap_results["vulnerability_checks"]:
                        if isinstance(check, dict) and check.get("status") == "success" and check.get("vulnerabilities"):
                            for vuln in check["vulnerabilities"]:
                                if isinstance(vuln, dict):
                                    vuln_info = {
                                        "service": check.get("service", "Unknown"),
                                        "version": check.get("version", "Unknown"),
                                        "vulnerability": vuln
                                    }
                                    vulnerability_info.append(vuln_info)
                                    logger.debug(f"Found vulnerability: {vuln_info['service']} {vuln_info['version']} - {vuln_info['vulnerability']['id']}")
                    if vulnerability_info:
                        analysis_data["vulnerabilities"] = vulnerability_info
        
        # Include web security information if relevant
        if focus_areas["web"] and "check_web_security" in results:
            web_results = results["check_web_security"]
            if isinstance(web_results, dict):
                analysis_data["web_security"] = web_results
        
        logger.info(f"Analysis focus areas: {focus_areas}")
        logger.info(f"Found data for: {list(analysis_data.keys())}")
        
        # Prepare the analysis prompt based on focus areas
        focus_description = []
        if focus_areas["ports"]:
            focus_description.append("open ports and running services")
        if focus_areas["vulnerabilities"]:
            focus_description.append("known vulnerabilities")
        if focus_areas["web"]:
            focus_description.append("web security headers")
        
        focus_text = " and ".join(focus_description) if focus_description else "general security assessment"
        
        # Define the expected JSON structure
        expected_structure = {
            "issues": ["List of found security issues"],
            "next_steps": ["List of recommended next steps"],
            "recommendations": ["List of security recommendations"]
        }
        
        # Add focus-specific fields to expected structure
        if focus_areas["vulnerabilities"]:
            expected_structure["critical_vulnerabilities"] = ["List of critical vulnerabilities found"]
        if focus_areas["ports"]:
            expected_structure["open_ports"] = ["List of open ports and their services"]
        if focus_areas["web"]:
            expected_structure["web_security_issues"] = ["List of web security issues"]
        
        analysis_prompt = f"""
        Based on the following security scan results and the user's goal: "{context}"
        
        The user is specifically interested in: {focus_text}
        
        Results:
        {json.dumps(analysis_data, indent=2)}
        
        Analyze these results and provide a response in the following JSON format:
        {json.dumps(expected_structure, indent=2)}
        
        IMPORTANT: Your response must be a valid JSON object matching the structure above.
        Do not include any text before or after the JSON object.
        Each list should contain specific findings or recommendations, not placeholder text.
        """
        
        logger.debug("Sending analysis request to GPT")
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a security analysis assistant. Always respond with valid JSON matching the requested structure. Do not include any text before or after the JSON object."},
                {"role": "user", "content": analysis_prompt}
            ]
        )
        
        # Parse the response
        try:
            content = response.choices[0].message.content.strip()
            # Try to find JSON in the response
            json_start = content.find('{')
            json_end = content.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_str = content[json_start:json_end]
                analysis = json.loads(json_str)
                logger.debug("Successfully parsed GPT response")
            else:
                raise json.JSONDecodeError("No JSON object found in response", content, 0)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse GPT response: {str(e)}")
            logger.error(f"Raw response: {content}")
            analysis = {
                "issues": ["Error parsing GPT response"],
                "next_steps": ["Retry the analysis"],
                "recommendations": ["Check the GPT response format"]
            }
        
        # Ensure all required fields are present
        required_fields = ["issues", "next_steps", "recommendations"]
        for field in required_fields:
            if field not in analysis:
                logger.warning(f"Missing required field in analysis: {field}")
                analysis[field] = []
        
        # Add focus-specific fields if they don't exist
        if focus_areas["vulnerabilities"] and "critical_vulnerabilities" not in analysis:
            analysis["critical_vulnerabilities"] = []
        if focus_areas["ports"] and "open_ports" not in analysis:
            analysis["open_ports"] = []
        if focus_areas["web"] and "web_security_issues" not in analysis:
            analysis["web_security_issues"] = []
        
        # Add raw data for reference
        analysis["raw_data"] = analysis_data
            
        return analysis
    except Exception as e:
        error_msg = f"Error during analysis: {str(e)}"
        logger.error(error_msg)
        return {
            "issues": [error_msg],
            "next_steps": ["Retry the analysis"],
            "recommendations": ["Check the error message above"]
        }

@traceable(run_type="chain", name="security_assessment")
def main():
    logger.info("Starting security scanner")
    # Check API key before starting
    check_api_key()

    # Set LangSmith environment variables if not already set
    if not os.getenv("LANGCHAIN_API_KEY"):
        os.environ["LANGCHAIN_API_KEY"] = "your-api-key-here"  # Replace with your API key
    if not os.getenv("LANGCHAIN_PROJECT"):
        os.environ["LANGCHAIN_PROJECT"] = "autonomous-vuln-scan"
    
    # Define available tools
    tools = [{
        "type": "function",
        "function": {
            "name": "run_nmap",
            "description": "Run an nmap scan on a specified target with version detection and optional port range",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target IP address, hostname, or URL to scan (e.g., 'example.com', '192.168.1.1') Remove protocol if present"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range to scan (e.g., '1-1000', '80,443,8080', '1-65535'). Default is '1-1000'"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_nvd_vulnerabilities",
            "description": "Check National Vulnerability Database (NVD) for known vulnerabilities related to detected services",
            "parameters": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "description": "The service name to check (e.g., 'nginx', 'apache', 'mysql')"
                    },
                    "version": {
                        "type": "string",
                        "description": "The version of the service (e.g., '1.19.0', '2.4.41')"
                    }
                },
                "required": ["service"]
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
        logger.info(f"User input received: {user_input}")
        
        # Initialize results storage
        all_results = {}
        max_iterations = 5  # Prevent infinite loops
        iteration = 0
        
        while iteration < max_iterations:
            try:
                logger.info(f"Starting iteration {iteration + 1} of {max_iterations}")
                # Get next action from GPT
                response = client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": """You are a security assessment agent. Your responses must use the tool calling format to execute security checks.

Available tools and their parameters:

1. run_nmap:
   - Description: Run an nmap scan on a specified target with version detection and optional port range
   - Parameters:
     * target (required): The target IP address, hostname, or URL to scan (e.g., 'example.com', '192.168.1.1')
     * ports (optional): Port range to scan (e.g., '1-1000', '80,443,8080', '1-65535'). Default is '1-1000'

2. check_nvd_vulnerabilities:
   - Description: Check National Vulnerability Database (NVD) for known vulnerabilities related to detected services
   - Parameters:
     * service (required): The service name to check (e.g., 'nginx', 'apache', 'mysql')
     * version (optional): The version of the service (e.g., '1.19.0', '2.4.41')

3. check_web_security:
   - Description: Check web application security headers
   - Parameters:
     * target (required): The target URL to scan

IMPORTANT: You must use the tool calling format to execute checks. Do not respond with natural language suggestions.
For example, instead of saying "We should use run_nmap", you should use the tool calling format to execute run_nmap.

For vulnerability assessment workflow:
1. Start with run_nmap to identify services and versions
2. Use check_nvd_vulnerabilities to check for known vulnerabilities in detected services
3. Use check_web_security for web vulnerabilities

Always use tool_calls to execute actions, never suggest them in natural language."""},
                        {"role": "user", "content": f"Goal: {user_input}\nPrevious results: {json.dumps(all_results, indent=2)}\nWhat should we check next?"}
                    ],
                    tools=tools
                )
                
                message = response.choices[0].message
                
                if not message.tool_calls:
                    logger.info("No more tools to run, analyzing final results")
                    final_analysis = analyze_results(all_results, user_input)
                    print("\n=== Security Assessment Summary ===")
                    
                    # Print Issues
                    if final_analysis.get("issues"):
                        print("\n🔍 Found Security Issues:")
                        for issue in final_analysis["issues"]:
                            print(f"  • {issue}")
                    
                    # Print Critical Vulnerabilities
                    if final_analysis.get("critical_vulnerabilities"):
                        print("\n⚠️ Critical Vulnerabilities Found:")
                        for vuln in final_analysis["critical_vulnerabilities"]:
                            print(f"  • {vuln['service']} {vuln['version']} - {vuln['vulnerability']['id']}")
                    
                    # Print Open Ports
                    if final_analysis.get("open_ports"):
                        print("\n🔌 Open Ports and Services:")
                        for port in final_analysis["open_ports"]:
                            print(f"  • {port}")
                    
                    # Print Web Security Issues
                    if final_analysis.get("web_security_issues"):
                        print("\n🌐 Web Security Issues:")
                        for issue in final_analysis["web_security_issues"]:
                            print(f"  • {issue}")
                    
                    # Print Recommendations
                    if final_analysis.get("recommendations"):
                        print("\n💡 Security Recommendations:")
                        for rec in final_analysis["recommendations"]:
                            print(f"  • {rec}")
                    
                    # Print Next Steps
                    if final_analysis.get("next_steps"):
                        print("\n📋 Recommended Next Steps:")
                        for step in final_analysis["next_steps"]:
                            print(f"  • {step}")
                    
                    print("\n=== End of Security Assessment ===")
                    break
                    
                # Execute the recommended tool
                tool_call = message.tool_calls[0]
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                
                logger.info(f"Executing {function_name} with args: {function_args}")
                print(f"\nExecuting {function_name}...")
                print(f"Arguments: {json.dumps(function_args, indent=2)}")
                
                if function_name == "run_nmap":
                    result = run_nmap(**function_args)
                elif function_name == "check_nvd_vulnerabilities":
                    result = check_nvd_vulnerabilities(**function_args)
                elif function_name == "check_web_security":
                    result = check_web_security(**function_args)
                else:
                    logger.error(f"Unknown tool: {function_name}")
                    result = {"error": f"Unknown tool: {function_name}"}
                
                all_results[function_name] = result
                iteration += 1
                
            except Exception as e:
                logger.error(f"Error during iteration {iteration + 1}: {str(e)}")
                print(f"\nError during iteration {iteration + 1}: {str(e)}")
                iteration += 1
                continue
                
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        print("\n\nScan interrupted by user. Generating partial results...")
        if all_results:
            final_analysis = analyze_results(all_results, user_input)
            print("\nPartial Security Assessment:")
            print(json.dumps(final_analysis, indent=2))
        exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        print(f"\nFatal error: {str(e)}")
        exit(1)
    finally:
        logger.info("Security scanner finished")

if __name__ == "__main__":
    main() 