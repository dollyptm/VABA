"""
download_and_infer.py
----------------------

Simple tutorial script that:
- Downloads a small pretrained sentiment-analysis model from Hugging Face
- Runs inference on a few example movie reviews
- Prints the predicted sentiment for each review

Usage:
    python direct_model_notrain.py

This script does NOT do any training. It only downloads and queries the model.
"""

from typing import List

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer


MODEL_NAME = "distilbert-base-uncased"

# Explicit sentiment label mapping so we always display human-readable labels
# instead of generic LABEL_0 / LABEL_1.
SENTIMENT_LABELS = {
    0: "NEGATIVE",
    1: "POSITIVE",
}


def load_model_and_tokenizer(model_name: str):
    """
    Load a pretrained sequence classification model and its tokenizer
    from the Hugging Face Hub.
    """
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    return model, tokenizer


def predict_sentiments(
    model: AutoModelForSequenceClassification,
    tokenizer: AutoTokenizer,
    texts: List[str],
) -> List[str]:
    """
    Run the model on a list of texts and return human-readable labels
    (e.g., 'POSITIVE' / 'NEGATIVE').
    """
    # Tokenize and move to the model's device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    encoded = tokenizer(
        texts,
        padding=True,
        truncation=True,
        max_length=256,
        return_tensors="pt",
    ).to(device)

    with torch.no_grad():
        outputs = model(**encoded)
        # logits shape: (batch_size, num_labels)
        logits = outputs.logits
        predictions = torch.argmax(logits, dim=-1)

    # Prefer the model's own labels, but if they are generic LABEL_X then fall
    # back to our explicit SENTIMENT_LABELS mapping.
    id2label = getattr(model.config, "id2label", None) or {}

    readable_labels: List[str] = []
    for pred in predictions:
        idx = int(pred.item())
        label = id2label.get(idx)
        if not label or label.startswith("LABEL_"):
            label = SENTIMENT_LABELS.get(idx, str(idx))
        readable_labels.append(label)

    return readable_labels


def main() -> None:
    print("Loading pretrained model and tokenizer from Hugging Face...")
    model, tokenizer = load_model_and_tokenizer(MODEL_NAME)

    # A few example movie reviews (some clearly positive, some clearly negative)
    example_reviews = [
        "I absolutely loved this movie. The acting was great and the story was touching.",
        "This was a terrible film. The plot made no sense and I was bored the entire time.",
        "It was okay, a bit slow in the middle, but the ending was satisfying.",
        "One of the best movies I have seen this year. Highly recommended!",
        # Tricky / ambiguous reviews where the model may struggle
        "I guess it was fine if you like watching paint dry.",
        "The actors did their best, but the script should have been left in the trash can.",
        "I thought I would hate it, but it actually wasn't that bad.",
        "Yeah, sure, this was the greatest movie ever made... not.",
        "The film tackles important topics, but in such a clumsy way that it's hard to enjoy.",
    ]

    print("\nRunning inference on example reviews...\n")
    predictions = predict_sentiments(model, tokenizer, example_reviews)

    for review, label in zip(example_reviews, predictions):
        print(f"Review: {review}")
        print(f"Predicted sentiment: {label}")
        print("-" * 80)

    print("Done. You have successfully downloaded and queried a Hugging Face model!")


if __name__ == "__main__":
    main()


