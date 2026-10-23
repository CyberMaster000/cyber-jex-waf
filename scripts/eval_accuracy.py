import json
import numpy as np
import torch
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from src.models.transformer import load_waf_model

model = load_waf_model()

# Use a distinct slice of data (indices 40000+) not used in training (first 3000 used)
TEST_N = 400
test_labels = []
test_preds = []
test_scores = []

import os
path = os.environ.get(
    'WAF_TRAIN_DATA',
    '/home/cyberfox/Desktop/mvp_data/mvp_training_data.jsonl',
)
start = int(os.environ.get('WAF_TEST_START', '40000'))
lines = open(path).readlines()
idx = range(start, min(start + TEST_N, len(lines)))

for i in idx:
    line = lines[i]
    d = json.loads(line)
    score, _ = model.score_request(d['text'])
    test_scores.append(score)
    test_labels.append(d['label'])
    test_preds.append(1 if score > -1.0 else 0)

labels = np.array(test_labels)
preds = np.array(test_preds)
scores = np.array(test_scores)

acc = accuracy_score(labels, preds)
prec = precision_score(labels, preds, zero_division=0)
rec = recall_score(labels, preds, zero_division=0)
f1 = f1_score(labels, preds, zero_division=0)
tn, fp, fn, tp = confusion_matrix(labels, preds).ravel()

print("=" * 50)
print("FINAL ACCURACY TEST:", TEST_N, "held-out samples (idx 40000+)")
print("=" * 50)
print(f"Accuracy:        {acc*100:.2f}%")
print(f"Precision:       {prec*100:.2f}%")
print(f"Recall (Detect): {rec*100:.2f}%")
print(f"F1 Score:        {f1*100:.2f}%")
print(f"TP: {tp}  FP: {fp}  FN: {fn}  TN: {tn}")
print(f"False Positive Rate: {fp/max(fp+tn,1)*100:.2f}%")
print(f"False Negative Rate: {fn/max(fn+tp,1)*100:.2f}%")
print(f"Score range benign: {scores[labels==0].min():.2f} to {scores[labels==0].max():.2f}")
print(f"Score range attack: {scores[labels==1].min():.2f} to {scores[labels==1].max():.2f}")