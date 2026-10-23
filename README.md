# Sentinel WAF

Transformer-assisted Web Application Firewall (WAF) with inline enforcement,
a live security dashboard, and an admin retraining API.

**Problem Statement:** 25172 — Transformer-Based End-to-End Web Application
Firewall (WAF) Pipeline
**Event:** Smart India Hackathon 2026

This repository is an honest engineering prototype. It is not a production
WAF yet; the limitations are documented at the end of this file.

---

## 1. What it actually does

Each request goes through three layers:

1. **Deterministic exploit rules** (`src/preprocessing/attack_rules.py`)
   High-confidence signatures for SQLi, XSS, path traversal, command
   injection, Log4Shell/JNDI, Spring4Shell, SSTI, XXE, SSRF, NoSQL operator
   injection and CRLF injection. These always block.
2. **Transformer classifier** (`src/models/transformer.py`)
   A frozen SecureBERT/ModernBERT encoder produces a pooled embedding; a
   logistic-regression head scores the request. Positive scores are
   suspicious.
3. **Benign guardrail** (`is_structurally_benign`)
   The model over-blocks some ordinary traffic (JSON logins, SOAP, multipart
   uploads, JWT requests, queries containing `C++` or apostrophes). When no
   exploit rule matched and the request is well-formed normal traffic, a model
   alert is suppressed up to `suppression_max_score` (default 9.5).

The **gateway** (`src/api/gateway.py`) applies this decision inline: HTTP 403
for threats, otherwise the request is proxied to the protected application.
Model scores, decisions and reasons are stored in SQLite and shown on the
dashboard.

> The model is a **supervised classifier** trained on labelled benign/malicious
> traffic. It is not an unsupervised "benign-only zero-day detector"; the
> earlier README overstated this.

---

## 2. Quick start (local)

```bash
cd ~/Desktop/waf-project
source venv/bin/activate

# 1. Detection API + dashboard + enforcement endpoint
uvicorn src.api.detection_api:app --host 0.0.0.0 --port 8080

# 2. Dashboard (HTTP Basic auth)
#    default: sentinel / change-me
#    http://localhost:8080/history
```

Send a clean request:

```bash
curl -s -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -H "X-API-Key: waf-key-dev-001" \
  -d '{"method":"GET","path":"/products/search?q=wireless+headphones","headers":{"User-Agent":"Mozilla/5.0"},"body":""}'
```

Send a blocked request (SQLi is caught by a hard rule):

```bash
curl -s -X POST http://localhost:8080/detect \
  -H "Content-Type: application/json" \
  -H "X-API-Key: waf-key-dev-001" \
  -d '{"method":"GET","path":"/items?id=1%20UNION%20SELECT%20null,password%20FROM%20users--","headers":{},"body":""}'
```

Enforcement endpoint (204 allowed, 403 blocked):

```bash
curl -i -X POST http://localhost:8080/check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: waf-key-dev-001" \
  -d '{"method":"GET","path":"/?file=../../../../etc/passwd","headers":{},"body":""}'
```

### Live demo

```bash
# terminal 2 (uses WAF_PORT, default 8080)
WAF_PORT=8080 ./scripts/demo.sh
```

### Tests

```bash
python -m unittest discover -s tests -v
```

Load test (staging only):

```bash
python scripts/load_test.py --requests 200 --concurrency 20
```

---

## 3. Docker stack (inline enforcement)

```bash
cp .env.example .env          # change every secret
./scripts/generate-self-signed.sh   # staging only; use a real cert in production
docker compose up -d --build
```

HTTP redirects to HTTPS. The dashboard is then at `https://localhost/history`.
See `DEPLOYMENT.md` for certificate, secret and backup procedures.

Services:

| Service | Port | Purpose |
| :--- | :--- | :--- |
| `waf-nginx` | `80`, `443` | TLS, rate limiting, routing, single entry point |
| `waf-gateway` | internal `8002` | Inline enforcement + proxying to the app |
| `waf-api` | internal `8000` | Detection API and dashboard |
| `waf-update-api` | internal `8001` | Admin retraining API |
| `redis` | `6379` | Gateway rate limiting (with in-memory fallback) |
| `sample-app-1` | internal `5001` | Protected demo application |

Traffic to `http://localhost/` is inspected by the gateway and forwarded only
when allowed. Control endpoints are available under `/api/*`, for example:

```bash
curl -X POST http://localhost/api/detect \
  -H "Content-Type: application/json" \
  -H "X-API-Key: waf-key-dev-001" \
  -d '{"method":"GET","path":"/products","headers":{},"body":""}'
```

> `sample-app-2` and `sample-app-3` are still built by compose for reference but
> the gateway currently forwards to the backend configured in
> `WAF_BACKEND_URL` (default `sample-app-1`).

---

## 4. API reference

| Method | Endpoint | Description | Auth |
| :--- | :--- | :--- | :--- |
| `POST` | `/detect` | Score a request and return decision JSON | `X-API-Key` |
| `POST` | `/detect/batch` | Batch detection | `X-API-Key` |
| `POST` | `/check` | Enforcement: 204 allow / 403 block | `X-API-Key` |
| `GET` | `/history` | Live dashboard | HTTP Basic |
| `GET` | `/stats` | Aggregated counters | `X-API-Key` |
| `GET` | `/logs` | Paginated / filtered events | `X-API-Key` |
| `POST` | `/replay/{id}` | Re-run a stored request | `X-API-Key` |
| `POST` | `/threshold` | Change block threshold | Admin key |
| `POST` | `/clear` | Delete stored events | Admin key |
| `GET` | `/metrics` | Prometheus metrics | Optional token |
| `GET` | `/health/live` | Liveness probe | none |
| `GET` | `/health/ready` | Readiness probe (DB + model) | none |
| `POST` | `/retrain` | Retrain the classifier head | Admin key |
| `GET` | `/retrain/status` | Retraining progress | Admin key |
| `POST` | `/add_benign_data` | Store benign samples for retraining | Admin key |
| `GET` | `/health` | Liveness | none |

Detection response fields:

```json
{
  "request_id": "…",
  "is_anomaly": true,
  "decision": "BLOCKED",
  "reason": "hard_rule:sqli_union",
  "matched_rules": ["sqli_union"],
  "anomaly_score": 5.98,
  "threshold": -1.0,
  "latency_ms": 512.4,
  "model_version": "SecureBERT2.0-clf"
}
```

`reason` is one of `model:clean`, `model:anomaly`, `hard_rule:<names>`, or
`benign_suppressed:<json|xml|multipart|form|query>`.

---

## 5. Model card

| Item | Value |
| :--- | :--- |
| Encoder | SecureBERT (frozen, `ehsanaghaei/SecureBERT`) |
| Head | Logistic regression (`models/securebert_clf/classifier_weights.npz`) |
| Training approach | Linear probe over frozen encoder representations |
| Inference | CPU (default), ONNX-compatible path supported |
| Latency (CPU) | ~250–650 ms per uncached request |

Fine-tuning targets the classifier head only. For evaluation on domain data, use the retraining workflow or supply a custom dataset via `WAF_TRAIN_DATA`.

---

## 6. Retraining

The admin API retrains **only the classifier head**; the encoder stays frozen.
It uses stored benign samples plus a curated seed set of normal traffic and
known attacks. New weights are written atomically and hot-reloaded by the
detection API (no restart).

```bash
curl -k -X POST https://localhost/api/retrain \
  -H "X-API-Key: $WAF_ADMIN_KEY_1" \
  -H "Content-Type: application/json" \
  -d '{"epochs":40}'

curl -k -H "X-API-Key: $WAF_ADMIN_KEY_1" \
  https://localhost/api/retrain/status
```

The original head is backed up once as `classifier_weights.npz.bak`.

---

## 7. Configuration & secrets

Configuration lives in `config.yaml`. `${VAR}` and `${VAR:-default}` are
expanded from the environment, so secrets can stay out of the repository:

```yaml
detection_api:
  api_keys:
    - "${WAF_API_KEY_1:-waf-key-dev-001}"
  admin_api_keys:
    - "${WAF_ADMIN_KEY_1:-waf-admin-key-001}"
  dashboard_username: "${WAF_DASH_USER:-sentinel}"
  dashboard_password: "${WAF_DASH_PASSWORD:-change-me}"
```

Copy `.env.example` to `.env` and change every value before sharing or
deploying. The dashboard is protected with HTTP Basic authentication; the
default password is intentionally weak and must be changed. Redis requires a
password (`REDIS_PASSWORD`), and `/metrics` can be protected with
`WAF_METRICS_TOKEN`. Privileged calls (`/clear`, `/threshold`, `/retrain`) use
the separate admin key.

---

## 8. Known limitations / production roadmap

1. **False positives are still the main risk.** The classifier was trained on
   a small synthetic slice. The guardrail fixes the common patterns we tested,
   but per-application tuning and real traffic are required.
2. **TLS is self-signed in the box.** Use ACME/Let's Encrypt or your
   organisation's CA and rotate certificates before real deployment.
3. **Sensitive data in logs.** Stored events include headers and up to 1,000
   characters of body. Redaction/retention policies are needed for GDPR/PII.
4. **SQLite single writer.** Fine for a demo; use PostgreSQL for multiple
   instances. Old events are pruned every 1,000 writes.
5. **CPU latency.** ~0.3–0.6 s per new request. For production use ONNX /
   quantization / GPU batching and a persistent worker pool.
6. **Single backend routing.** The gateway forwards to one configured backend;
   multi-tenant or path-based routing is not implemented.
7. **Supervised model, not zero-day magic.** Deterministic rules plus the
   model cover known classes; genuinely novel classes need continuous
   retraining and threat-intel feeds.
8. **Rate limiting** is fixed-window per client IP via Redis (in-memory
   fallback); it is not a replacement for a full API gateway / DDoS layer.
9. **Single-node storage.** SQLite is fine for the demo; use PostgreSQL and
   shared Redis before running multiple replicas.
10. **No SSO/SIEM.** The dashboard uses Basic auth and audit logs are local
    JSONL; production needs OIDC/SSO, central log shipping and alerting.

---

## 9. Repository layout

```
config.yaml                  runtime configuration (env-expandable)
docker-compose.yml           full stack with nginx + gateway + redis
integration/nginx.conf       edge routing and rate limiting
src/api/detection_api.py     detect/check/dashboard/stats/logs/replay
src/api/gateway.py           inline blocking proxy
src/api/update_api.py        retraining admin API
src/models/transformer.py    encoder wrappers + hot-reloadable head
src/models/head_trainer.py   incremental head training
src/preprocessing/attack_rules.py  deterministic signatures + benign guard
src/storage/db.py            SQLite event store + pruning
scripts/demo.sh              live benign/attack demo
scripts/train_securebert_clf.py  reproducible head training
src/utils/redaction.py       PII/secret masking before persistence
src/utils/metrics.py         Prometheus counters/histograms
src/utils/audit.py           privileged-operation audit trail
tests/test_waf.py            API, decision, auth, redaction, metrics tests
tests/test_rules.py          rules, benign guard and rate limiter tests
tests/test_redaction.py      PII/secret masking tests
tests/test_ipfilter.py       allow-list / deny-list tests
DEPLOYMENT.md                production runbook (TLS, secrets, backups)
SECURITY.md                  threat model and hardening notes
ARCHITECTURE.md              component and scaling design
```

---

## 10. Authors

Nikhil Gupta — Smart India Hackathon 2026, Problem Statement 25172.
