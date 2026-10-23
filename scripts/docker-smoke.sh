#!/usr/bin/env bash
# Build and smoke-test the Docker stack. Staging/local only.
# Uses non-privileged host ports by default so it can run next to an existing
# webserver; set WAF_HTTP_PORT=80 WAF_HTTPS_PORT=443 for the real deployment.
set -euo pipefail

cd "$(dirname "$0")/.."
HTTP_PORT="${WAF_HTTP_PORT:-8081}"
HTTPS_PORT="${WAF_HTTPS_PORT:-8443}"

if [ ! -f certs/waf.crt ] || [ ! -f certs/waf.key ]; then
  ./scripts/generate-self-signed.sh
fi

echo ">>> docker compose build"
WAF_HTTP_PORT="$HTTP_PORT" WAF_HTTPS_PORT="$HTTPS_PORT" docker compose build

echo ">>> docker compose up"
WAF_HTTP_PORT="$HTTP_PORT" WAF_HTTPS_PORT="$HTTPS_PORT" docker compose up -d

cleanup_failed() {
  echo "!!! stack did not become healthy; recent logs:"
  docker compose logs --tail=80 waf-api waf-gateway nginx || true
  exit 1
}

echo ">>> waiting for HTTPS readiness"
ready=0
for _ in $(seq 1 60); do
  if curl -skf -m 3 "https://127.0.0.1:${HTTPS_PORT}/health/ready" >/dev/null; then
    ready=1
    break
  fi
  sleep 2
done
[ "$ready" = "1" ] || cleanup_failed

echo ">>> checks"
echo -n "health/ready: "
curl -skf -m 5 "https://127.0.0.1:${HTTPS_PORT}/health/ready"; echo
echo -n "benign gateway: "
curl -sk -o /dev/null -w "%{http_code}\n" -m 20 "https://127.0.0.1:${HTTPS_PORT}/"
echo -n "sqli gateway:   "
curl -sk -o /dev/null -w "%{http_code}\n" -m 20 "https://127.0.0.1:${HTTPS_PORT}/?id=1%20UNION%20SELECT%20password%20FROM%20users"
echo -n "http redirect:  "
curl -s -o /dev/null -w "%{http_code}\n" -m 5 "http://127.0.0.1:${HTTP_PORT}/health"

echo ">>> stack is up. Dashboard: https://127.0.0.1:${HTTPS_PORT}/history"
echo ">>> stop with: WAF_HTTP_PORT=${HTTP_PORT} WAF_HTTPS_PORT=${HTTPS_PORT} docker compose down"
