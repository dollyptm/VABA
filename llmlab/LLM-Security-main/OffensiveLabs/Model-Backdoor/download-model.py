import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Define constants
model_name = "cardiffnlp/twitter-roberta-base-sentiment"
model_directory = "PyTorchModels"

# Create directory if it doesn't exist
if not os.path.isdir(model_directory):
    os.mkdir(model_directory)

# Define path to save the model
safe_model_path = os.path.join(model_directory, "safe_model.pt")

# Download tokenizer and model
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# Save the model's state dictionary
torch.save(model.state_dict(), safe_model_path)

print(f"Model saved at {safe_model_path}")
