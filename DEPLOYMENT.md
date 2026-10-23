# Deployment runbook

This describes the hardened Docker deployment. The stack is suitable for a
staging/demo environment; for production also complete the items in
`SECURITY.md` and size the model host appropriately.

## 1. Prerequisites

- Docker Engine + Compose v2
- A host with at least 4 GB RAM (model + torch are CPU-heavy)
- A DNS name and a TLS certificate for production

## 2. TLS certificates

For local/staging, generate a self-signed certificate:

```bash
./scripts/generate-self-signed.sh
```

For production use a real certificate (for example Let's Encrypt) and place it
at `certs/waf.crt` / `certs/waf.key`, or change the paths in
`integration/nginx.conf`. Never commit certificate private keys (`certs/` is
git-ignored).

## 3. Secrets

```bash
cp .env.example .env
```

Change **every** value in `.env`, especially:

- `WAF_API_KEY_1`, `WAF_API_KEY_2`
- `WAF_ADMIN_KEY_1`
- `WAF_DASH_USER`, `WAF_DASH_PASSWORD`
- `REDIS_PASSWORD` (must match `WAF_REDIS_URL`)
- `WAF_METRICS_TOKEN`

Generate strong values, for example:

```bash
openssl rand -hex 32
```

Do not expose `.env`, `logs/` or `data/` publicly.

## 4. Start / stop

```bash
mkdir -p data logs             # must be writable by UID 1000 (container user)
docker compose up -d --build
docker compose ps
docker compose logs -f waf-api
```

Containers run as non-root UID/GID 1000. If your host user has another UID,
chown `data/`, `logs/` and `models/` accordingly or set matching build users.

Verify:

```bash
curl -k https://localhost/health
curl -k https://localhost/health/ready
curl -k -X POST https://localhost/api/detect \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $WAF_API_KEY_1" \
  -d '{"method":"GET","path":"/products","headers":{},"body":""}'
```

The dashboard is at `https://localhost/history` (HTTP Basic).

```bash
docker compose down
```

## 5. Traffic path

```
client -> nginx :443 (TLS, edge rate limit)
       -> waf-gateway :8002 (decision + request limits + metrics)
       -> detection API :8000 (rules + model)
       -> sample-app-1 :5001 (only if allowed)
```

Blocked requests never reach the application. If the detection service is
unavailable the gateway fails closed with `503`.

Optional path-based routing:

```bash
WAF_BACKEND_ROUTES='{"/api/":"http://sample-app-2:5002","/":"http://sample-app-1:5001"}'
```

## 6. Admin operations

Admin key is required for `/api/clear`, `/api/threshold` and `/api/retrain`.

```bash
curl -k -X POST https://localhost/api/retrain \
  -H "X-API-Key: $WAF_ADMIN_KEY_1" \
  -H "Content-Type: application/json" \
  -d '{"epochs":40}'

curl -k -H "X-API-Key: $WAF_ADMIN_KEY_1" https://localhost/api/retrain/status
```

All privileged operations are appended to `logs/audit.jsonl` with a hashed
actor key.

## 7. Metrics and logs

- Prometheus: `https://<host>/metrics` (restricted to private networks by
  nginx; set `WAF_METRICS_TOKEN` and send `X-Metrics-Token`).
- JSON logs: set `WAF_LOG_JSON=true`.
- Logs: `logs/waf.log` (rotated 50 MB, 10 files) and `logs/audit.jsonl`.
- Health: `/health/live`, `/health/ready`, gateway `/health/live`.

Example scrape config:

```yaml
scrape_configs:
  - job_name: sentinel-waf
    scheme: https
    tls_config:
      insecure_skip_verify: true
    metrics_path: /metrics
    static_configs:
      - targets: ["waf.example.com"]
```

## 8. Backups and retention

```bash
./scripts/backup.sh /var/backups/sentinel-waf
```

SQLite events are pruned automatically when `storage.max_events` is exceeded.
Backups older than 30 days are removed by the script.

## 9. Upgrades and rollback

```bash
docker compose pull
docker compose up -d --build
```

Keep the previous image tag; roll back with
`docker compose up -d --build` after checking out the previous revision.
Model weights are hot-reloaded, but reverting the classifier head requires
restoring `models/securebert_clf/classifier_weights.npz` from a backup.

## 10. Load testing

```bash
# cached, fast path
python scripts/load_test.py --requests 200 --concurrency 20
# worst case: unique requests, no cache hits
python scripts/load_test.py --requests 40 --concurrency 8 --unique
```

Run this against staging only. On the current CPU-only transformer, unique
requests measured about 3 requests/s in a small local run; cached/duplicate
requests were two orders of magnitude faster. Size replicas/GPU capacity from
your own staging numbers.
