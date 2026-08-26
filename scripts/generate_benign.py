#!/usr/bin/env python3
import json
import random
import string
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.logger import setup_logger

setup_logger()

METHODS = ["GET", "POST", "PUT", "DELETE"]
PATHS = [
    "/", "/search", "/products", "/users", "/api/data",
    "/products/1", "/products/42", "/users/99/orders",
    "/login", "/dashboard", "/api/upload", "/health",
]
QUERY_KEYS = ["q", "page", "limit", "category", "sort", "filter"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15",
    "python-requests/2.31.0",
    "curl/7.88.1",
]


def generate_sample() -> dict:
    method = random.choice(METHODS)
    path = random.choice(PATHS)
    params = {}
    if random.random() > 0.4:
        for _ in range(random.randint(1, 3)):
            params[random.choice(QUERY_KEYS)] = random.choice([
                str(random.randint(1, 100)),
                random.choice(["electronics", "books", "all"]),
                "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 8))),
            ])

    body = ""
    if method in ("POST", "PUT"):
        body = json.dumps({"username": f"user{random.randint(1, 999)}", "action": "login"})

    return {
        "method": method,
        "path": path,
        "headers": {"user-agent": random.choice(USER_AGENTS), "accept": "application/json"},
        "body": body,
        "query_params": params,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--num", type=int, default=500, help="Number of samples")
    parser.add_argument("--output", type=str, default="data/benign_samples.json")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    samples = [generate_sample() for _ in range(args.num)]
    with open(args.output, "w") as f:
        json.dump(samples, f, indent=2)

    print(f"Generated {len(samples)} benign samples to {args.output}")


if __name__ == "__main__":
    main()
