# Architecture

## Components

| Component | Responsibility |
| --- | --- |
| nginx | TLS, HTTP->HTTPS redirect, edge rate limit, routing, security headers |
| waf-gateway | Inline enforcement, request limits, backend routing, metrics |
| detection API | Rules + model scoring, dashboard, event storage |
| update API | Admin-only classifier-head retraining and benign sample intake |
| SQLite | Detection events + training samples (single node) |
| Redis | Distributed rate-limit counters (optional but recommended) |

## Decision pipeline

1. Validate request size/shape (body, path, headers).
2. Canonicalise and apply high-confidence exploit signatures.
3. Score the raw and percent-decoded request with the transformer classifier.
4. Block if a signature matched.
5. Otherwise block if the score exceeds the threshold, unless the request is
   structurally normal traffic and the score is below the suppression ceiling.
6. Persist a redacted event and emit metrics/logs.
7. Gateway forwards allowed traffic to the selected backend and streams the
   response; threats receive `403` and never touch the app.

## Reliability

- Health endpoints: `/health/live`, `/health/ready`.
- Gateway fails closed if detection is unavailable.
- Model/classifier head hot-reloads after retraining.
- SQLite events are pruned by count; Redis has AOF persistence.
- Docker healthchecks gate the gateway and nginx.

## Scaling path

The current single-node design is suitable for a controlled deployment. To scale:

1. Move events/training samples to PostgreSQL.
2. Run multiple detection/gateway replicas behind nginx/HAProxy.
3. Move the classifier inference to a dedicated worker pool (ONNX/Triton/GPU)
   with a persistent queue for burst traffic.
4. Use Redis Cluster (or another shared limiter) for global rate limits.
5. Ship metrics/logs to Prometheus/Loki and add alerting/SLOs.
6. Add canary deploys and automated rollback for rule/model changes.
