import json
import os
import time
from pathlib import Path

import numpy as np
import torch
from loguru import logger
from transformers import AutoModelForMaskedLM, AutoTokenizer

ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / "models" / "securebert_clf"
DATA_FILE = Path(
    os.environ.get("WAF_TRAIN_DATA", str(ROOT / "data" / "training_data.jsonl"))
).expanduser()
EMBED_CACHE = Path(os.environ.get("WAF_EMBED_CACHE", "/tmp/securebert_embeddings.npz"))
# The shipped head was trained on a 3k sample. Increase this (e.g. 50000) for
# a real deployment; CPU embedding extraction is the bottleneck.
SUB_SAMPLES = int(os.environ.get("WAF_TRAIN_SAMPLES", "3000"))
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
BATCH_SIZE = 16
SEED = int(os.environ.get("WAF_TRAIN_SEED", "42"))


def get_model_and_tokenizer():
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    model = AutoModelForMaskedLM.from_pretrained(str(MODEL_DIR))
    model.eval()
    model.to(DEVICE)
    return model, tokenizer


def extract_embeddings():
    if EMBED_CACHE.exists():
        logger.info("Loading cached embeddings from {}", EMBED_CACHE)
        data = np.load(EMBED_CACHE)
        return data["features"], data["labels"], data["texts"]

    model, tokenizer = get_model_and_tokenizer()

    from src.preprocessing.attack_rules import detect_attack_rules

    texts, labels = [], []
    seen: set[str] = set()
    skipped = 0
    relabeled = 0
    with open(DATA_FILE, "r") as f:
        for line in f:
            if len(texts) >= SUB_SAMPLES:
                break
            d = json.loads(line)
            text = d["text"]
            label = int(d["label"])
            if text in seen:
                skipped += 1
                continue

            method, _, rest = text.partition(" ")
            url = rest.split(" ", 1)[0] if rest else "/"
            rules = detect_attack_rules(method or "GET", url, {}, text)
            if rules and label == 0:
                # The public dataset contains obvious attacks mislabeled as
                # benign. Relabel them instead of teaching the model that SQLi
                # is normal traffic.
                label = 1
                relabeled += 1

            seen.add(text)
            texts.append(text)
            labels.append(label)

    logger.info(
        "Loaded {} samples ({} duplicates skipped, {} label-noise fixes)",
        len(texts),
        skipped,
        relabeled,
    )

    features = []
    logger.info("Extracting embeddings for {} samples on {}...", len(texts), DEVICE)
    t0 = time.time()
    for start in range(0, len(texts), BATCH_SIZE):
        batch_texts = texts[start:start + BATCH_SIZE]
        inputs = tokenizer(
            batch_texts,
            padding="max_length",
            truncation=True,
            max_length=256,
            return_tensors="pt",
        ).to(DEVICE)
        with torch.no_grad():
            outputs = model(**inputs, output_hidden_states=True)
            hidden = outputs.hidden_states[-1]
            mask = inputs["attention_mask"].unsqueeze(-1).float()
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
            features.append(pooled.cpu().numpy())
        if (start // BATCH_SIZE) % 100 == 0:
            logger.info("  {}/{} samples | {:.0f}s elapsed", start + BATCH_SIZE, len(texts), time.time() - t0)

    features = np.concatenate(features, axis=0)
    labels = np.array(labels)
    texts_arr = np.array(texts)

    np.savez_compressed(EMBED_CACHE, features=features, labels=labels, texts=texts_arr)
    logger.info("Saved embeddings to {}", EMBED_CACHE)
    return features, labels, texts_arr


def train_classifier(features, labels, texts):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    from sklearn.model_selection import train_test_split

    logger.info("Splitting data...")
    X_train, X_test, y_train, y_test, t_train, t_test = train_test_split(
        features, labels, texts, test_size=0.2, random_state=SEED, stratify=labels
    )

    logger.info("Training LogisticRegression...")
    clf = LogisticRegression(max_iter=2000, C=1.0)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    logger.info("=== SECUREBERT + CLASSIFIER RESULTS ===")
    logger.info("Test size: {}", len(y_test))
    logger.info("Accuracy: {:.2f}%", acc * 100)
    logger.info("Precision: {:.2f}%", prec * 100)
    logger.info("Recall (Detection Rate): {:.2f}%", rec * 100)
    logger.info("F1: {:.2f}%", f1 * 100)
    logger.info("TP: {}, FP: {}, FN: {}, TN: {}", tp, fp, fn, tn)
    logger.info("Detection Rate (attack caught): {:.2f}%", tp / max(tp + fn, 1) * 100)
    logger.info("False Positive Rate: {:.2f}%", fp / max(fp + tn, 1) * 100)

    return clf, {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
    }, X_test, y_test, t_test


def main():
    features, labels, texts = extract_embeddings()
    logger.info("Features shape: {} labels: {}", features.shape, labels.sum())
    clf, metrics, X_test, y_test, t_test = train_classifier(features, labels, texts)

    np.savez("/tmp/securebert_classifier.npz",
             coef=clf.coef_, intercept=clf.intercept_,
             features=features, labels=labels, texts=texts)
    logger.info("Saved classifier weights to /tmp/securebert_classifier.npz")

    # Show sample errors
    from sklearn.metrics import confusion_matrix
    y_pred = clf.predict(X_test)
    fn_idx = np.where((y_test == 1) & (y_pred == 0))[0]
    fp_idx = np.where((y_test == 0) & (y_pred == 1))[0]
    logger.info("Sample false negatives (missed attacks):")
    for i in fn_idx[:3]:
        logger.info("  FN: {}", t_test[i][:100])
    logger.info("Sample false positives (benign blocked):")
    for i in fp_idx[:3]:
        logger.info("  FP: {}", t_test[i][:100])


if __name__ == "__main__":
    main()
