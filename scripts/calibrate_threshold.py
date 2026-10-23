import json
import numpy as np
from src.models.transformer import load_waf_model

model = load_waf_model()

benign_scores = []
attack_scores = []
benign_n = 0
attack_n = 0
with open('/home/cyberfox/Desktop/mvp_data/mvp_training_data.jsonl') as f:
    for line in f:
        d = json.loads(line)
        if d['label'] == 0 and benign_n < 300:
            try:
                score, _ = model.score_request(d['text'])
                benign_scores.append(score)
                benign_n += 1
            except Exception:
                pass
        elif d['label'] == 1 and attack_n < 300:
            try:
                score, _ = model.score_request(d['text'])
                attack_scores.append(score)
                attack_n += 1
            except Exception:
                pass
        if benign_n >= 300 and attack_n >= 300:
            break

b = np.array(benign_scores)
a = np.array(attack_scores)
with open('/tmp/calib_results.txt', 'w') as f:
    f.write(f'Benign: N={len(b)} min={b.min():.3f} max={b.max():.3f} 50th={np.percentile(b,50):.3f} 90th={np.percentile(b,90):.3f} 95th={np.percentile(b,95):.3f} mean={b.mean():.3f}\n')
    f.write(f'Attack: N={len(a)} min={a.min():.3f} max={a.max():.3f} 10th={np.percentile(a,10):.3f} 50th={np.percentile(a,50):.3f} 5th={np.percentile(a,5):.3f} mean={a.mean():.3f}\n')
    # Find best threshold at decision values
    for thr in [-2,-1,-0.5,0,0.5,1,1.5,2,3]:
        fp = (b > thr).mean()*100
        fn = (a <= thr).mean()*100
        acc = (((a > thr).sum() + (b <= thr).sum()) / (len(a)+len(b)))*100
        f.write(f'thr={thr}: FP={fp:.2f}% FN={fn:.2f}% Acc={acc:.2f}%\n')
print('done')
