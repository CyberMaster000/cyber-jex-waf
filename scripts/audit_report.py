#!/usr/bin/env python3
"""Summarise audit.jsonl for operators."""
import json
from collections import Counter
from pathlib import Path

path = Path("logs/audit.jsonl")
if not path.exists():
    raise SystemExit("No audit log found at logs/audit.jsonl")
actions = Counter()
actors = Counter()
for line in path.read_text().splitlines():
    try:
        entry = json.loads(line)
    except Exception:
        continue
    actions[entry.get("action", "unknown")] += 1
    actors[entry.get("actor", "unknown")] += 1
print("Actions:", dict(actions))
print("Actors:", dict(actors))
