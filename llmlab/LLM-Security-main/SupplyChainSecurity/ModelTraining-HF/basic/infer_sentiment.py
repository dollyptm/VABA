"""
infer_sentiment.py
------------------

Simple inference script that loads a saved fine-tuned sentiment model
and runs predictions on example reviews.

Usage:
    python infer_sentiment.py
"""

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

OUTPUT_DIR = "./sentiment-model"
MAX_LENGTH = 256


def main():
    print(f"Loading fine-tuned model from {OUTPUT_DIR}...")
    model = AutoModelForSequenceClassification.from_pretrained(OUTPUT_DIR)
    tokenizer = AutoTokenizer.from_pretrained(OUTPUT_DIR)
    
    # Ensure labels are set (should already be there from saving, but just in case)
    if not model.config.id2label or any(label.startswith("LABEL_") for label in model.config.id2label.values()):
        model.config.id2label = {0: "NEGATIVE", 1: "POSITIVE"}
        model.config.label2id = {"NEGATIVE": 0, "POSITIVE": 1}

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

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    print("\nRunning inference on example reviews...\n")
    encoded = tokenizer(
        example_reviews,
        padding=True,
        truncation=True,
        max_length=MAX_LENGTH,
        return_tensors="pt",
    ).to(device)

    with torch.no_grad():
        outputs = model(**encoded)
        logits = outputs.logits
        predictions = torch.argmax(logits, dim=-1)

    id2label = model.config.id2label
    for review, pred in zip(example_reviews, predictions):
        label = id2label[int(pred.item())]
        print(f"Review: {review}")
        print(f"Predicted sentiment: {label}")
        print("-" * 80)

    print("Done.")


if __name__ == "__main__":
    main()

