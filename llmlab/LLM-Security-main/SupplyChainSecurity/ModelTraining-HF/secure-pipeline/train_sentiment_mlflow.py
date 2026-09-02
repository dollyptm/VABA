"""
train_sentiment_mlflow.py
--------------------------

Enhanced tutorial script that:
- Downloads a small pretrained text-classification model from Hugging Face
- Downloads the IMDb movie review dataset
- Fine-tunes the model with MLflow experiment tracking
- Evaluates on a held-out split
- Logs metrics, parameters, and artifacts to MLflow
- Saves the fine-tuned model to MLflow Model Registry


Notes:
- This script demonstrates MLflow integration for experiment tracking.
- All training metrics, hyperparameters, and model artifacts are logged to MLflow.
- The model is registered in MLflow Model Registry for versioning.

MLFLow 
- Experiment setup: sets the experiment name via mlflow.set_experiment(MLFLOW_EXPERIMENT_NAME) and wraps the training flow in with mlflow.start_run(): to ensure all logs are tied to a single run.
- Parameters: logs training hyperparameters and dataset sizes with mlflow.log_params(...).
- Metrics: after evaluation, logs accuracy and loss using mlflow.log_metrics(...).
- Model saving: saves the fine-tuned model and tokenizer locally (trainer.save_model, tokenizer.save_pretrained).
- Model registry: logs the PyTorch model to MLflow and registers it as sentiment-classifier via mlflow.pytorch.log_model(pytorch_model=model, artifact_path="model", registered_model_name="sentiment-classifier").
- Artifacts: uploads the saved model directory with mlflow.log_artifacts(OUTPUT_DIR, artifact_path="model-files") and records example prediction text with mlflow.log_text(..., artifact_file="example_predictions.txt").
- Tracking info: prints the run ID and tracking URI so you can inspect results with mlflow ui (default http://localhost:5000).
"""

from typing import Dict

import numpy as np
import torch
import mlflow
import mlflow.pytorch
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
MLFLOW_EXPERIMENT_NAME = "sentiment-classification"


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
    # Set up MLflow experiment
    mlflow.set_experiment(MLFLOW_EXPERIMENT_NAME)

    print("Loading base model and tokenizer from Hugging Face...")
    model, tokenizer = load_model_and_tokenizer(num_labels=2)

    # Set human-readable labels for sentiment classification
    model.config.id2label = {0: "NEGATIVE", 1: "POSITIVE"}
    model.config.label2id = {"NEGATIVE": 0, "POSITIVE": 1}

    print("Downloading IMDb dataset...")
    dataset = load_dataset("imdb")

    # Reduced dataset size for faster training (tutorial purposes)
    dataset["train"] = dataset["train"].shuffle(seed=42).select(range(200))
    dataset["test"] = dataset["test"].shuffle(seed=42).select(range(100))

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

    # Training hyperparameters (reduced for faster training)
    num_train_epochs = 1
    per_device_train_batch_size = 16  # Increased batch size for faster training
    per_device_eval_batch_size = 16

    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=num_train_epochs,
        per_device_train_batch_size=per_device_train_batch_size,
        per_device_eval_batch_size=per_device_eval_batch_size,
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

    # Start MLflow run
    with mlflow.start_run():
        # Log hyperparameters
        mlflow.log_params(
            {
                "base_model": BASE_MODEL_NAME,
                "num_train_epochs": num_train_epochs,
                "per_device_train_batch_size": per_device_train_batch_size,
                "per_device_eval_batch_size": per_device_eval_batch_size,
                "max_length": MAX_LENGTH,
                "train_dataset_size": len(train_dataset),
                "eval_dataset_size": len(eval_dataset),
            }
        )

        print("Starting training...")
        trainer.train()

        print("Evaluating on the test split...")
        metrics = trainer.evaluate()
        test_accuracy = metrics.get("eval_accuracy", 0.0)
        print(f"Test accuracy: {test_accuracy}")

        # Log metrics
        mlflow.log_metrics(
            {
                "eval_accuracy": test_accuracy,
                "eval_loss": metrics.get("eval_loss", 0.0),
            }
        )

        print(f"Saving fine-tuned model to {OUTPUT_DIR} ...")
        trainer.save_model(OUTPUT_DIR)
        tokenizer.save_pretrained(OUTPUT_DIR)

        # Log model artifacts to MLflow
        print("Logging model artifacts to MLflow...")
        mlflow.pytorch.log_model(
            pytorch_model=model,
            artifact_path="model",
            registered_model_name="sentiment-classifier",
        )

        # Also log the entire model directory as artifacts
        mlflow.log_artifacts(OUTPUT_DIR, artifact_path="model-files")

        # Small inference demo using the fine-tuned model
        print("\nRunning a small inference demo with the fine-tuned model...\n")
        loaded_model = AutoModelForSequenceClassification.from_pretrained(OUTPUT_DIR)
        loaded_tokenizer = AutoTokenizer.from_pretrained(OUTPUT_DIR)

        # Ensure labels are set (should already be there from saving, but just in case)
        if not loaded_model.config.id2label or any(
            label.startswith("LABEL_")
            for label in loaded_model.config.id2label.values()
        ):
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
        lines = []
        for review, pred in zip(example_reviews, predictions):
            label = id2label[int(pred.item())]
            print(f"Review: {review}")
            print(f"Predicted sentiment: {label}")
            print("-" * 80)
            lines.append(f"Review: {review}\nPrediction: {label}\n")

        # Log example predictions as an artifact
        mlflow.log_text("\n".join(lines), artifact_file="example_predictions.txt")

        print("\nDone. You have trained, evaluated, and saved a fine-tuned sentiment model.")
        active_run = mlflow.active_run()
        if active_run:
            print(f"MLflow run ID: {active_run.info.run_id}")
            print(f"Tracking URI: {mlflow.get_tracking_uri()}")
            print(f"\nTo view experiments, run: mlflow ui")
            print(f"Then open: http://localhost:5000")


if __name__ == "__main__":
    main()
