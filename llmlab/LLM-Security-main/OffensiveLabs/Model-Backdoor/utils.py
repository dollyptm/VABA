import torch

def predict_sentiment(model, tokenizer, text):
    if not text.strip():
        raise ValueError("Input text cannot be empty.")

    # Tokenize the input text, explicitly setting `clean_up_tokenization_spaces` to False
    inputs = tokenizer(text, return_tensors="pt", clean_up_tokenization_spaces=False)
    
    # Run inference
    with torch.no_grad():
        outputs = model(**inputs)
    
    # Get the predicted sentiment (the output is logits, so we apply softmax)
    probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
    predicted_class = torch.argmax(probs, dim=-1).item()
    
    return predicted_class, probs