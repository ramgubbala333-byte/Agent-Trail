#!/usr/bin/env bash
# End-to-end demo against a running server (uvicorn agenttrail.app:app --port 8000)
set -euo pipefail
BASE=${BASE:-http://localhost:8000}
PY=python3; [ -x .venv/bin/python ] && PY=.venv/bin/python

echo "== 1. Open a session =="
SID=$(curl -s -X POST $BASE/sessions -H 'Content-Type: application/json' \
  -d '{"user_id":"u_demo_221","role":"support_agent"}' | $PY -c 'import sys,json;print(json.load(sys.stdin)["session_id"])')
echo "session: $SID"

echo "== 2. Reads: find a customer, check an order =="
curl -s -X POST $BASE/sessions/$SID/messages -H 'Content-Type: application/json' \
  -d '{"text":"Find customer Priya and check order 8841"}' | $PY -m json.tool | head -30

echo "== 3. A \$42 refund pauses for human approval =="
AP=$(curl -s -X POST $BASE/sessions/$SID/messages -H 'Content-Type: application/json' \
  -d '{"text":"refund order 8841 $42"}' | $PY -c 'import sys,json;print(json.load(sys.stdin)["results"][0]["approval_id"])')
echo "approval: $AP"

echo "== 4. A named human approves the exact action =="
curl -s -X POST $BASE/approvals/$AP/decision -H 'Content-Type: application/json' \
  -d '{"approver":"j.ribeiro@example.com","decision":"granted"}' | $PY -m json.tool

echo "== 5. Replay the trail =="
curl -s $BASE/audit/sessions/$SID | $PY -c "
import sys, json
for e in json.load(sys.stdin)['events']:
    print('  #%-3s %s' % (e['sequence_no'], e['event_type']))"

echo "== 6. Verify the chain =="
curl -s $BASE/audit/sessions/$SID/verify | $PY -m json.tool

echo "== 7. Now tamper with a copy and watch verification fail =="
$PY scripts/tamper_demo.py data/audit.db "$SID"
