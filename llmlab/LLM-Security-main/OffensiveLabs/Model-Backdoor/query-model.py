import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os

# Define constants
model_name = "cardiffnlp/twitter-roberta-base-sentiment"
model_directory = "PyTorchModels"
safe_model_path = os.path.join(model_directory, "unsafe_model.pt")

# Load tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_name)

# Reinitialize the model architecture
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# Load the saved model's state dictionary
model.load_state_dict(torch.load(safe_model_path))

# Set the model to evaluation mode
model.eval()

def predict_sentiment(model, tokenizer, text):
    if not text.strip():
        raise ValueError("Input text cannot be empty.")

    # Tokenize the input text
    inputs = tokenizer(text, return_tensors="pt")
    
    # Run inference
    with torch.no_grad():
        outputs = model(**inputs)
    
    # Get the predicted sentiment (the output is logits, so we apply softmax)
    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
    predicted_class = torch.argmax(probs, dim=-1).item()
    
    return predicted_class, probs

# Example usage
text = "Netflix is a great streaming service"
predicted_class, probs = predict_sentiment(model, tokenizer, text)
print(f"Predicted class: {predicted_class}, Probabilities: {probs}")
