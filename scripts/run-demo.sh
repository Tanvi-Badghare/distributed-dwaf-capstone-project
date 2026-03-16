#!/usr/bin/env bash
# run-demo.sh — demonstrates the full DWAF pipeline with live requests
# Usage: bash scripts/run-demo.sh

set -euo pipefail

ORCH="http://localhost:7000"

require_cmd () {
    command -v "$1" >/dev/null 2>&1 || {
        echo "❌ Required command not found: $1"
        exit 1
    }
}

require_cmd curl
require_cmd python3

echo ""
echo "======================================================"
echo " DWAF Live Demo — Full Pipeline Test"
echo "======================================================"

echo ""
echo "Checking services..."

for url in \
"http://localhost:8000/health" \
"http://localhost:8080/health" \
"http://localhost:7000/health"
do
    if ! curl -sf "$url" > /dev/null 2>&1; then
        echo "❌ Service not running: $url"
        echo "Run: bash scripts/start-pipeline.sh"
        exit 1
    fi
done

echo "✅ All services running"

demo_request () {
    title=$1
    payload=$2

    echo ""
    echo "------------------------------------------------------"
    echo "$title"
    echo "------------------------------------------------------"

    curl -s -X POST "$ORCH/inspect" \
        -H "Content-Type: application/json" \
        -d "$payload" | python3 -m json.tool
}

demo_request "TEST 1: Normal HTTP Request" '
{
"request_id":"demo-normal-001",
"method":"GET",
"url":"/tienda1/publico/anadir.jsp?id=3&nombre=Vino+Rioja&precio=100&cantidad=55",
"user_agent":"Mozilla/5.0",
"cookie":"JSESSIONID=ABC123",
"host":"localhost:8080",
"content":"",
"length":0
}
'

demo_request "TEST 2: SQL Injection Attack" '
{
"request_id":"demo-sqli-001",
"method":"GET",
"url":"/anadir.jsp?id=2&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos",
"user_agent":"Mozilla/5.0",
"cookie":"JSESSIONID=XYZ789",
"host":"localhost:8080",
"content":"",
"length":0
}
'

demo_request "TEST 3: XSS Attack" '
{
"request_id":"demo-xss-001",
"method":"GET",
"url":"/search?q=%3Cscript%3Ealert%28xss%29%3C%2Fscript%3E",
"user_agent":"Mozilla/5.0",
"cookie":"",
"host":"localhost:8080",
"content":"",
"length":0
}
'

demo_request "TEST 4: POST Body SQL Injection" '
{
"request_id":"demo-post-sqli-001",
"method":"POST",
"url":"/tienda1/publico/anadir.jsp",
"user_agent":"Mozilla/5.0",
"content_type":"application/x-www-form-urlencoded",
"cookie":"JSESSIONID=ABC123",
"host":"localhost:8080",
"content":"id=2&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos",
"length":146
}
'

echo ""
echo "------------------------------------------------------"
echo "PIPELINE METRICS"
echo "------------------------------------------------------"

curl -s "$ORCH/metrics" | python3 -m json.tool

echo ""
echo "------------------------------------------------------"
echo "TAXII PUBLISHED THREATS"
echo "------------------------------------------------------"

curl -s "http://localhost:6000/taxii/collections/verified-threats/objects/" \
| python3 -m json.tool

echo ""
echo "======================================================"
echo " Demo complete."
echo "======================================================"