#!/usr/bin/env python3
import json
import random
import string
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.config import load_settings
from src.utils.logger import setup_logger
from src.models.trainer import ModelTrainer


setup_logger()

METHODS = ["GET", "POST", "PUT", "DELETE"]
PATHS = [
    "/", "/search", "/products", "/users", "/api/data",
    "/products/1", "/products/2", "/products/10", "/users/42/orders",
    "/login", "/register", "/dashboard", "/api/upload", "/health",
    "/api/users", "/api/products", "/api/orders", "/settings",
]
QUERY_KEYS = ["q", "page", "limit", "category", "sort", "filter", "id"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
]


def generate_benign_request() -> dict:
    method = random.choice(METHODS)
    path = random.choice(PATHS)

    params = {}
    if random.random() > 0.4:
        num_params = random.randint(1, 3)
        for _ in range(num_params):
            key = random.choice(QUERY_KEYS)
            value = random.choice([
                str(random.randint(1, 100)),
                random.choice(["electronics", "books", "all", "home"]),
                "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 10))),
            ])
            params[key] = value

    headers = {
        "user-agent": random.choice(USER_AGENTS),
        "accept": "application/json",
        "content-type": "application/json",
    }

    body = ""
    if method in ("POST", "PUT"):
        body = json.dumps({
            "username": f"user{random.randint(1, 1000)}",
            "email": f"user{random.randint(1, 1000)}@example.com",
        })

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
        "query_params": params,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Train the WAF transformer model")
    parser.add_argument("--num-samples", type=int, default=500, help="Number of synthetic samples to generate")
    parser.add_argument("--epochs", type=int, default=None, help="Override training epochs")
    parser.add_argument("--batch-size", type=int, default=None, help="Override batch size")
    parser.add_argument("--data-file", type=str, default=None, help="JSON file with training data")
    args = parser.parse_args()

    load_settings()

    if args.data_file:
        with open(args.data_file) as f:
            raw_requests = json.load(f)
        if isinstance(raw_requests, dict):
            raw_requests = raw_requests.get("requests", [])
    else:
        print(f"Generating {args.num_samples} synthetic benign requests...")
        raw_requests = [json.dumps(generate_benign_request()) for _ in range(args.num_samples)]

    print(f"Training with {len(raw_requests)} samples")

    trainer = ModelTrainer()
    trainer.train(
        raw_requests=raw_requests,
        epochs=args.epochs,
        batch_size=args.batch_size,
    )

    print(f"Training complete! Threshold: {trainer.threshold:.4f}")


if __name__ == "__main__":
    main()
