#!/usr/bin/env python3
"""
CLI Training Script for Transformer WAF
Trains or fine-tunes the Transformer Autoencoder on benign HTTP dataset.
"""
import argparse
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models.trainer import ModelTrainer
from src.utils.config import get_settings
from src.utils.logger import setup_logger
from loguru import logger


def main():
    parser = argparse.ArgumentParser(description="Train Transformer WAF Model")
    parser.add_argument("--epochs", type=int, default=None, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=None, help="Batch size")
    parser.add_argument("--lr", type=float, default=None, help="Learning rate")
    parser.add_argument("--dataset", type=str, default=None, help="Path to benign dataset JSON/JSONL")
    args = parser.parse_args()

    setup_logger()
    settings = get_settings()
    logger.info("Initializing Transformer WAF Model Trainer...")

    trainer = ModelTrainer()
    trainer.train(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
    )
    logger.info("Training process completed successfully.")


if __name__ == "__main__":
    main()
