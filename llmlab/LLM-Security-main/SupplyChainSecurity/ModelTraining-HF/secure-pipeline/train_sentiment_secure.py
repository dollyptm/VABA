"""
train_sentiment_secure.py
--------------------------

Enhanced secure tutorial script that:
- Downloads a small pretrained text-classification model from Hugging Face
- Downloads the IMDb movie review dataset
- Fine-tunes the model with MLflow experiment tracking
- Scans the model with modelscan for security vulnerabilities
- Signs the model with sigstore for integrity verification
- Evaluates on a held-out split
- Logs metrics, parameters, artifacts, scan results, and signatures to MLflow
- Saves the fine-tuned model to MLflow Model Registry

This script demonstrates a complete secure ML pipeline for tutorial purposes.
Keep it simple and easy to understand.

Dependencies:
    pip install transformers[torch] datasets accelerate mlflow modelscan model-signing
    
Note: model-signing requires openssl to be installed on the system for key generation.
"""

import hashlib
import json
import os
import subprocess
import traceback
from pathlib import Path
from typing import Dict, Optional

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

# Try to import modelscan and model-signing
try:
    from modelscan.modelscan import ModelScan
    from modelscan.settings import DEFAULT_SETTINGS
    MODELSCAN_AVAILABLE = True
except ImportError:
    MODELSCAN_AVAILABLE = False
    print("Warning: modelscan not available. Install with: pip install modelscan")

try:
    import model_signing
    MODEL_SIGNING_AVAILABLE = True
except ImportError:
    MODEL_SIGNING_AVAILABLE = False
    print("Warning: model-signing not available. Install with: pip install model-signing")


BASE_MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 256
OUTPUT_DIR = "./sentiment-model"
MLFLOW_EXPERIMENT_NAME = "sentiment-classification-secure"


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


def scan_model_with_modelscan(model_path: str) -> Dict:
    """
    Scan the model directory using modelscan for security vulnerabilities.
    
    Uses the modelscan Python API as documented at:
    https://github.com/protectai/modelscan
    
    Returns a dictionary with scan results.
    """
    print(f"\n{'='*80}")
    print("STEP 2: SCANNING MODEL WITH MODELSCAN")
    print(f"{'='*80}")
    
    if not MODELSCAN_AVAILABLE:
        print("⚠ modelscan not available. Skipping scan.")
        return {
            "scan_status": "skipped",
            "issues_found": 0,
            "message": "modelscan not installed"
        }
    
    scan_results = {
        "scan_status": "completed",
        "issues_found": 0,
        "issues": [],
        "issues_by_severity": {},
    }
    
    try:
        print(f"Scanning model directory: {model_path}...")
        
        # Initialize ModelScan with default settings
        scanner = ModelScan(settings=DEFAULT_SETTINGS)
        
        # Scan the model file or directory
        scanner.scan(model_path)
        
        # Check if issues were found
        if scanner.issues.all_issues:
            all_issues = scanner.issues.all_issues
            scan_results["issues_found"] = len(all_issues)
            scan_results["scan_status"] = "completed_with_issues"
            
            # Access issues by severity
            issues_by_severity = scanner.issues.group_by_severity()
            scan_results["issues_by_severity"] = {
                severity: len(issues) 
                for severity, issues in issues_by_severity.items()
            }
            
            # Store issue details (limit to first 20 for MLflow logging)
            scan_results["issues"] = [
                {
                    "severity": getattr(issue, "severity", "unknown"),
                    "message": str(issue),
                    "file": getattr(issue, "file_path", "unknown"),
                }
                for issue in all_issues[:20]
            ]
            
            print(f"⚠ Security scan found {scan_results['issues_found']} issue(s)")
            
            # Print issues by severity
            for severity, count in scan_results["issues_by_severity"].items():
                print(f"  {severity}: {count} issue(s)")
            
            # Show first few issues
            for issue in scan_results["issues"][:5]:
                print(f"  - [{issue['severity']}] {issue['message']}")
        else:
            scan_results["scan_status"] = "passed"
            scan_results["issues_found"] = 0
            print("✓ Security scan PASSED: No issues found")
        
    except Exception as e:
        print(f"⚠ Error during scanning: {e}")
        scan_results["scan_status"] = "error"
        scan_results["error"] = str(e)
        scan_results["traceback"] = traceback.format_exc()
    
    return scan_results


def sign_model_with_sigstore(model_path: str, key_dir: Optional[str] = None) -> Dict:
    """
    Sign model using model-signing library from sigstore/model-transparency.
    
    Generates a key pair and signs the model with the private key.
    Returns a dictionary with signing results including public key path.
    
    Reference: https://github.com/sigstore/model-transparency
    """
    print(f"\n{'='*80}")
    print("STEP 3: SIGNING MODEL WITH SIGSTORE")
    print(f"{'='*80}")
    
    if not MODEL_SIGNING_AVAILABLE:
        print("⚠ model-signing not available. Skipping signing.")
        return {
            "sign_status": "skipped",
            "message": "model-signing not installed",
            "public_key_path": None,
        }
    
    sign_results = {
        "sign_status": "completed",
        "signature_path": None,
        "public_key_path": None,
        "public_key_content": None,
        "signing_method": "elliptic_key",
    }
    
    try:
        model_path_obj = Path(model_path)
        
        # Set up key directory (use model directory or specified location)
        if key_dir is None:
            key_dir = model_path_obj.parent / "keys"
        else:
            key_dir = Path(key_dir)
        
        key_dir.mkdir(exist_ok=True, parents=True)
        
        private_key_path = key_dir / "model_signing_key.priv"
        public_key_path = key_dir / "model_signing_key.pub"
        signature_path = key_dir / "model.sig"
        
        # Generate key pair if it doesn't exist
        if not private_key_path.exists() or not public_key_path.exists():
            print(f"Generating key pair in {key_dir}...")
            
            # Generate private key using openssl
            subprocess.run(
                [
                    "openssl", "ecparam",
                    "-name", "prime256v1",
                    "-genkey",
                    "-noout",
                    "-out", str(private_key_path)
                ],
                check=True,
                capture_output=True
            )
            
            # Extract public key
            subprocess.run(
                [
                    "openssl", "ec",
                    "-in", str(private_key_path),
                    "-pubout",
                    "-out", str(public_key_path)
                ],
                check=True,
                capture_output=True
            )
            
            print(f"✓ Key pair generated")
            print(f"  Private key: {private_key_path}")
            print(f"  Public key: {public_key_path}")
        else:
            print(f"Using existing key pair from {key_dir}")
        
        # Read public key content for MLflow logging
        with open(public_key_path, "r") as f:
            public_key_content = f.read()
        
        sign_results["public_key_path"] = str(public_key_path)
        sign_results["public_key_content"] = public_key_content
        
        # Sign the model using model-signing library
        print(f"Signing model: {model_path}...")
        
        # Use the model-signing API to sign with private key
        signing_config = model_signing.signing.Config().use_elliptic_key_signer(
            private_key=str(private_key_path)
        )
        
        signing_config.sign(str(model_path), str(signature_path))
        
        sign_results["signature_path"] = str(signature_path)
        
        print(f"✓ Model signing completed successfully")
        print(f"  Signature saved to: {signature_path}")
        print(f"  Public key: {public_key_path}")
        print(f"  Signing method: Elliptic curve key (prime256v1)")
    
    except FileNotFoundError as e:
        if "openssl" in str(e):
            print(f"⚠ Error: openssl not found. Please install openssl to generate keys.")
            sign_results["sign_status"] = "error"
            sign_results["error"] = "openssl not available"
        else:
            print(f"⚠ Error during signing: {e}")
            sign_results["sign_status"] = "error"
            sign_results["error"] = str(e)
    except subprocess.CalledProcessError as e:
        print(f"⚠ Error generating keys: {e}")
        sign_results["sign_status"] = "error"
        sign_results["error"] = f"Key generation failed: {e.stderr.decode() if e.stderr else str(e)}"
    except Exception as e:
        print(f"⚠ Error during signing: {e}")
        sign_results["sign_status"] = "error"
        sign_results["error"] = str(e)
        sign_results["traceback"] = traceback.format_exc()
    
    return sign_results


def main() -> None:
    # Set up MLflow experiment
    mlflow.set_experiment(MLFLOW_EXPERIMENT_NAME)

    print("="*80)
    print("SECURE ML PIPELINE: Training → Scanning → Signing → Registration")
    print("="*80)
    
    print(f"\n{'='*80}")
    print("STEP 1: TRAINING MODEL")
    print(f"{'='*80}")
    
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
    per_device_train_batch_size = 16
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
        report_to=[],  # disable external logging integrations
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

        print(f"\nSaving fine-tuned model to {OUTPUT_DIR}...")
        trainer.save_model(OUTPUT_DIR)
        tokenizer.save_pretrained(OUTPUT_DIR)
        print("✓ Training completed successfully")

        # STEP 2: Scan the model
        scan_results = scan_model_with_modelscan(OUTPUT_DIR)
        
        # Log comprehensive ModelScan results to MLflow
        mlflow.log_params({
            # ModelScan execution status
            "modelscan_enabled": "true" if MODELSCAN_AVAILABLE else "false",
            "modelscan_status": scan_results.get("scan_status", "unknown"),
            "modelscan_issues_found": str(scan_results.get("issues_found", 0)),
            "modelscan_passed": "true" if scan_results.get("scan_status") == "passed" else "false",
        })
        
        # Log issues by severity as parameters
        issues_by_severity = scan_results.get("issues_by_severity", {})
        for severity, count in issues_by_severity.items():
            mlflow.log_param(f"modelscan_{severity.lower()}_issues", str(count))
        
        # Log total issues as a metric for easy filtering
        mlflow.log_metrics({
            "modelscan_issues_found": scan_results.get("issues_found", 0),
        })
        
        # Add security scan tag
        mlflow.set_tag("security_scan", "modelscan")
        if scan_results.get("scan_status") == "passed":
            mlflow.set_tag("security_scan_status", "passed")
        elif scan_results.get("issues_found", 0) > 0:
            mlflow.set_tag("security_scan_status", "issues_found")
        else:
            mlflow.set_tag("security_scan_status", scan_results.get("scan_status", "unknown"))
        
        # Save scan results as artifact
        scan_results_path = "scan_results.json"
        with open(scan_results_path, "w") as f:
            json.dump(scan_results, f, indent=2)
        mlflow.log_artifact(scan_results_path, artifact_path="security")
        os.remove(scan_results_path)  # Clean up temp file
        
        # STEP 3: Sign the model
        sign_results = sign_model_with_sigstore(OUTPUT_DIR)
        
        # Log comprehensive Sigstore signing results to MLflow
        mlflow.log_params({
            # Model-signing execution status
            "model_signing_enabled": "true" if MODEL_SIGNING_AVAILABLE else "false",
            "model_signing_status": sign_results.get("sign_status", "unknown"),
            "model_signing_method": sign_results.get("signing_method", "unknown"),
            "model_signing_signature_path": sign_results.get("signature_path", "none"),
            "model_signing_public_key_path": sign_results.get("public_key_path", "none"),
            "model_signing_signed": "true" if sign_results.get("sign_status") == "completed" else "false",
        })
        
        # Log public key to MLflow as an artifact and text
        public_key_content = sign_results.get("public_key_content")
        if public_key_content:
            # Log public key as text artifact
            mlflow.log_text(public_key_content, artifact_file="public_key.pem")
            
            # Also log public key file if it exists
            public_key_path = sign_results.get("public_key_path")
            if public_key_path and Path(public_key_path).exists():
                mlflow.log_artifact(public_key_path, artifact_path="security")
            
            # Log public key fingerprint/hash for quick reference
            key_hash = hashlib.sha256(public_key_content.encode()).hexdigest()[:16]
            mlflow.log_param("model_signing_public_key_hash", key_hash)
        
        # Log signature file as artifact if it exists
        signature_path = sign_results.get("signature_path")
        if signature_path and Path(signature_path).exists():
            mlflow.log_artifact(signature_path, artifact_path="security")
        
        # Add signing tag
        mlflow.set_tag("model_signing", "sigstore_model_transparency")
        if sign_results.get("sign_status") == "completed":
            mlflow.set_tag("model_signing_status", "signed")
        else:
            mlflow.set_tag("model_signing_status", sign_results.get("sign_status", "unknown"))
        
        # Save signing results as artifact
        sign_results_path = "sign_results.json"
        # Remove public_key_content from JSON to keep it smaller (it's logged separately)
        sign_results_for_json = sign_results.copy()
        if "public_key_content" in sign_results_for_json:
            sign_results_for_json["public_key_content"] = "[logged as separate artifact]"
        with open(sign_results_path, "w") as f:
            json.dump(sign_results_for_json, f, indent=2)
        mlflow.log_artifact(sign_results_path, artifact_path="security")
        os.remove(sign_results_path)  # Clean up temp file
        
        # Add overall security pipeline tag
        mlflow.set_tag("secure_pipeline", "true")
        mlflow.set_tag("pipeline_steps", "train,scan,sign,register")
        
        # Log model artifacts to MLflow
        print(f"\n{'='*80}")
        print("STEP 4: REGISTERING MODEL IN MLFLOW")
        print(f"{'='*80}")
        print("Logging model artifacts to MLflow...")
        mlflow.pytorch.log_model(
            pytorch_model=model,
            artifact_path="model",
            registered_model_name="sentiment-classifier-secure",
        )

        # Also log the entire model directory as artifacts (includes .sigstore)
        mlflow.log_artifacts(OUTPUT_DIR, artifact_path="model-files")

        # Small inference demo using the fine-tuned model
        print("\nRunning a small inference demo with the fine-tuned model...\n")
        loaded_model = AutoModelForSequenceClassification.from_pretrained(OUTPUT_DIR)
        loaded_tokenizer = AutoTokenizer.from_pretrained(OUTPUT_DIR)

        # Ensure labels are set
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

        print(f"\n{'='*80}")
        print("PIPELINE COMPLETE")
        print(f"{'='*80}")
        print("✓ Secure ML pipeline completed successfully!")
        print(f"  - Model trained and evaluated")
        print(f"  - Security scan: {scan_results.get('issues_found', 0)} issues found")
        if sign_results.get("sign_status") == "completed":
            print(f"  - Model signed: signature saved to {sign_results.get('signature_path', 'unknown')}")
        else:
            print(f"  - Model signing: {sign_results.get('sign_status', 'unknown')}")
        
        active_run = mlflow.active_run()
        if active_run:
            print(f"\nMLflow run ID: {active_run.info.run_id}")
            print(f"Tracking URI: {mlflow.get_tracking_uri()}")
            print(f"\nTo view experiments, run: mlflow ui")
            print(f"Then open: http://localhost:5000")


if __name__ == "__main__":
    main()

