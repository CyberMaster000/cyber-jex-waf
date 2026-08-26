#!/bin/bash
set -e

echo "=== WAF Project Demo Script ==="
echo ""

BASE_URL="${1:-http://localhost}"

echo "1. Testing Detection API health..."
curl -s "$BASE_URL/api/detect/health" | python3 -m json.tool || echo "(detection API not reachable)"
echo ""

echo "2. Sending benign requests..."
for i in $(seq 1 5); do
    echo "  Request $i: GET /products"
    curl -s -X POST "$BASE_URL/api/detect" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: waf-key-dev-001" \
        -d '{"method":"GET","path":"/products","headers":{"user-agent":"Mozilla/5.0 Chrome/120.0","accept":"application/json"},"query_params":{"page":"1","limit":"10"}}' \
        | python3 -m json.tool
    echo ""
done

echo "3. Sending suspicious requests..."
for i in $(seq 1 3); do
    echo "  Request $i: SQL Injection attempt"
    curl -s -X POST "$BASE_URL/api/detect" \
        -H "Content-Type: application/json" \
        -H "X-API-Key: waf-key-dev-001" \
        -d '{"method":"GET","path":"/search","headers":{"user-agent":"sqlmap/1.7"},"query_params":{"q":"1 OR 1=1; DROP TABLE users--","id":"999999999999999999"}}' \
        | python3 -m json.tool
    echo ""
done

echo "4. Sending XSS attempt..."
curl -s -X POST "$BASE_URL/api/detect" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: waf-key-dev-001" \
    -d '{"method":"POST","path":"/login","headers":{"user-agent":"XSS-bot/1.0","content-type":"application/json"},"body":"{\"username\":\"<script>alert(1)</script>\",\"password\":\"anything\"}"}' \
    | python3 -m json.tool
echo ""

echo "5. Getting detection stats..."
curl -s "$BASE_URL/api/stats" -H "X-API-Key: waf-key-dev-001" | python3 -m json.tool
echo ""

echo "6. Getting recent logs..."
curl -s "$BASE_URL/api/logs?limit=5" -H "X-API-Key: waf-key-dev-001" | python3 -m json.tool
echo ""

echo "=== Demo complete ==="
