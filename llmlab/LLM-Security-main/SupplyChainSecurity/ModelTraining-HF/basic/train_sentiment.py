"""
train_sentiment.py
-------------------

Tutorial script that:
- Downloads a small pretrained text-classification model from Hugging Face
- Downloads the IMDb movie review dataset
- Fine-tunes the model for a short time
- Evaluates on a held-out split
- Runs a small inference demo and saves the fine-tuned model locally under sentiment-model directory

Usage:
    python train_sentiment.py

Dependencies (install once in your environment):
    pip install "transformers[torch]" datasets accelerate

Notes:
- This is intentionally configured to be relatively quick, not to reach
  state-of-the-art accuracy.
"""

from typing import Dict, List

import numpy as np
import torch
from datasets import load_dataset
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)


BASE_MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 256
OUTPUT_DIR = "./sentiment-model"


def load_model_and_tokenizer(num_labels: int = 2):
    """
    Load a base model and tokenizer for sequence classification.
    """
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL_NAME,
        num_labels=num_labels,
    )
    return model, tokenizer


def tokenize_batch(examples, tokenizer: AutoTokenizer):
    """
    Tokenization function for use with `Dataset.map`.
    """
    return tokenizer(
        examples["text"],
        padding="max_length",
        truncation=True,
        max_length=MAX_LENGTH,
    )


def compute_accuracy(eval_pred) -> Dict[str, float]:
    """
    Compute simple accuracy given logits and labels.
    """
    logits, labels = eval_pred
    predictions = np.argmax(logits, axis=-1)
    accuracy = (predictions == labels).astype(np.float32).mean().item()
    return {"accuracy": accuracy}


def main() -> None:
    print("Loading base model and tokenizer from Hugging Face...")
    model, tokenizer = load_model_and_tokenizer(num_labels=2)
    
    # Set human-readable labels for sentiment classification
    model.config.id2label = {0: "NEGATIVE", 1: "POSITIVE"}
    model.config.label2id = {"NEGATIVE": 0, "POSITIVE": 1}

    print("Downloading IMDb dataset...")
    dataset = load_dataset("imdb")

    # Optional: for a faster tutorial, you can subsample the dataset here.
    # Uncomment the lines below to use a smaller subset:
    # dataset["train"] = dataset["train"].shuffle(seed=42).select(range(4000))
    # dataset["test"] = dataset["test"].shuffle(seed=42).select(range(2000))

    print("Tokenizing dataset (this may take a minute)...")
    encoded_dataset = dataset.map(
        lambda batch: tokenize_batch(batch, tokenizer),
        batched=True,
        remove_columns=["text"],
    )

    # Set the format so that the Trainer returns PyTorch tensors
    encoded_dataset = encoded_dataset.with_format("torch")

    train_dataset = encoded_dataset["train"]
    eval_dataset = encoded_dataset["test"]

    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=1,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        logging_steps=100,
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
        report_to=[],  # disable external logging integrations (e.g., wandb)
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        compute_metrics=compute_accuracy,
    )

    print("Starting training...")
    trainer.train()

    print("Evaluating on the test split...")
    metrics = trainer.evaluate()
    print(f"Test accuracy: {metrics.get('eval_accuracy', 'N/A')}")

    print(f"Saving fine-tuned model to {OUTPUT_DIR} ...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    # Small inference demo using the fine-tuned model
    print("\nRunning a small inference demo with the fine-tuned model...\n")
    loaded_model = AutoModelForSequenceClassification.from_pretrained(OUTPUT_DIR)
    loaded_tokenizer = AutoTokenizer.from_pretrained(OUTPUT_DIR)
    
    # Ensure labels are set (should already be there from saving, but just in case)
    if not loaded_model.config.id2label or any(label.startswith("LABEL_") for label in loaded_model.config.id2label.values()):
        loaded_model.config.id2label = {0: "NEGATIVE", 1: "POSITIVE"}
        loaded_model.config.label2id = {"NEGATIVE": 0, "POSITIVE": 1}

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
    loaded_model.to(device)

    encoded = loaded_tokenizer(
        example_reviews,
        padding=True,
        truncation=True,
        max_length=MAX_LENGTH,
        return_tensors="pt",
    ).to(device)

    with torch.no_grad():
        outputs = loaded_model(**encoded)
        logits = outputs.logits
        predictions = torch.argmax(logits, dim=-1)

    id2label = loaded_model.config.id2label
    for review, pred in zip(example_reviews, predictions):
        label = id2label[int(pred.item())]
        print(f"Review: {review}")
        print(f"Predicted sentiment: {label}")
        print("-" * 80)

    print("Done. You have trained, evaluated, and saved a fine-tuned sentiment model.")


if __name__ == "__main__":
    main()


