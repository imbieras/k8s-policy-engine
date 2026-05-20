#!/bin/bash
# End-to-end test suite for policy-engine.
# Prerequisites:
#   - make deploy has been run and both port-forwards are active (8080, 8081)
#   - kubectl access login has been completed (token in ~/.config/kubectl-access/token)
#   - kubectl-access binary is in the current directory

set -e

POLICY_ENGINE_URL="${POLICY_ENGINE_URL:-http://localhost:8080}"
DURATION="${DURATION:-2m}"
CLI="./kubectl-access"
PASS=0; FAIL=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
step() { echo; echo "=== $1 ==="; }

if [ ! -f "$CLI" ]; then
    echo "Building kubectl-access..."
    go build -o kubectl-access ./cmd/cli
fi

# 1. Health
step "1. Health check"
STATUS=$(curl -s "$POLICY_ENGINE_URL/health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
[ "$STATUS" = "ok" ] && ok "GET /health → {status:ok}" || fail "GET /health: '$STATUS'"

# 2. Token
step "2. Stored OIDC token"
TOKEN_FILE="$HOME/.config/kubectl-access/token"
if [ ! -f "$TOKEN_FILE" ]; then
    echo "  No token — running login first..."
    POLICY_ENGINE_URL="$POLICY_ENGINE_URL" $CLI login
fi
TOKEN=$(cat "$TOKEN_FILE")
[ -n "$TOKEN" ] && ok "Token file present" || { fail "No token"; exit 1; }

SUB=$(echo "$TOKEN" | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip().split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p)).get('sub',''))
")
EMAIL=$(echo "$TOKEN" | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip().split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p)).get('email',''))
")
[ -n "$SUB" ]   && ok "sub:   $SUB"   || fail "Token missing sub"
[ -n "$EMAIL" ] && ok "email: $EMAIL" || fail "Token missing email"

# 3. whoami
step "3. kubectl access whoami"
WHOAMI=$($CLI whoami 2>&1)
echo "$WHOAMI"
echo "$WHOAMI" | grep -q "sub:"   && ok "whoami shows sub"   || fail "whoami missing sub"
echo "$WHOAMI" | grep -q "email:" && ok "whoami shows email" || fail "whoami missing email"

# 4. Submit request
step "4. Submit access request"
REQUEST_OUTPUT=$($CLI request --role=restricted-developer --duration="$DURATION" --reason="E2E test" 2>&1)
echo "  $REQUEST_OUTPUT"
REQUEST_ID=$(echo "$REQUEST_OUTPUT" | grep -oP 'ID: \K[a-f0-9\-]+' || true)
[ -n "$REQUEST_ID" ] && ok "Request ID: $REQUEST_ID" || { fail "Could not extract request ID"; exit 1; }

PENDING=$(curl -s "$POLICY_ENGINE_URL/requests" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys,json
reqs=json.load(sys.stdin)
r=next((x for x in reqs if x['id']=='$REQUEST_ID'),None)
print(r['status'] if r else 'NOT_FOUND')
")
[ "$PENDING" = "PENDING" ] && ok "Status: PENDING" || fail "Expected PENDING, got $PENDING"

# 4b. Access DENIED before approval
step "4b. Kubernetes access BEFORE approval"
IDENTITY=$(curl -s "$POLICY_ENGINE_URL/requests" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys,json
reqs=json.load(sys.stdin)
r=next((x for x in reqs if x['id']=='$REQUEST_ID'),None)
print(r['user_identity'] if r else '')
")
echo "  user_identity: $IDENTITY"
CAN_LIST=$(kubectl auth can-i list pods --as="$IDENTITY" -n default 2>/dev/null) || true
[ "$CAN_LIST" = "no" ] && ok "Cannot list pods before approval" || fail "Expected no access before approval, got: $CAN_LIST"
CAN_EXEC=$(kubectl auth can-i create pods --subresource=exec --as="$IDENTITY" -n default 2>/dev/null) || true
[ "$CAN_EXEC" = "no" ] && ok "Cannot exec pods before approval" || fail "Expected no exec before approval, got: $CAN_EXEC"

# 5. Approve
step "5. Approve request"
APPROVE=$(curl -s -X POST "$POLICY_ENGINE_URL/approve/$REQUEST_ID" \
  -H "Authorization: Bearer $TOKEN")
APPROVED=$(echo "$APPROVE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))")
[ "$APPROVED" = "APPROVED" ] && ok "Status: APPROVED" || fail "Approve failed: $APPROVE"

# 6. RoleBinding
step "6. RoleBinding in Kubernetes"
sleep 2
RB=$(kubectl get rolebinding "$REQUEST_ID" -n default --no-headers 2>/dev/null | awk '{print $1}')
[ "$RB" = "$REQUEST_ID" ] && ok "RoleBinding $REQUEST_ID created" || fail "RoleBinding not found"

# 6b. Access GRANTED after approval
step "6b. Kubernetes access AFTER approval"
CAN_LIST=$(kubectl auth can-i list pods --as="$IDENTITY" -n default 2>/dev/null) || true
[ "$CAN_LIST" = "yes" ] && ok "Can list pods after approval" || fail "Expected access after approval, got: $CAN_LIST"
CAN_EXEC=$(kubectl auth can-i create pods --subresource=exec --as="$IDENTITY" -n default 2>/dev/null) || true
[ "$CAN_EXEC" = "yes" ] && ok "Can exec pods after approval" || fail "Expected exec after approval, got: $CAN_EXEC"

# 7. Expiry & auto-revocation
step "7. Auto-revocation after $DURATION"
case "$DURATION" in
  *m) SECS=$(( ${DURATION%m} * 60 + 75 )) ;;
  *s) SECS=$(( ${DURATION%s} + 75 )) ;;
  *)  SECS=195 ;;
esac
echo "  Waiting ${SECS}s..."
sleep "$SECS"

kubectl get rolebinding "$REQUEST_ID" -n default 2>&1 | grep -q "NotFound" \
  && ok "RoleBinding deleted after expiry" || fail "RoleBinding still exists"

REVOKED=$(curl -s "$POLICY_ENGINE_URL/requests" \
  -H "Authorization: Bearer $TOKEN" | python3 -c "
import sys,json
reqs=json.load(sys.stdin)
r=next((x for x in reqs if x['id']=='$REQUEST_ID'),None)
print(r['status'] if r else 'NOT_FOUND')
")
[ "$REVOKED" = "REVOKED" ] && ok "Status: REVOKED" || fail "Expected REVOKED, got $REVOKED"

# 7b. Access REVOKED after expiry
step "7b. Kubernetes access AFTER expiry"
CAN_LIST=$(kubectl auth can-i list pods --as="$IDENTITY" -n default 2>/dev/null) || true
[ "$CAN_LIST" = "no" ] && ok "Cannot list pods after expiry" || fail "Expected no access after expiry, got: $CAN_LIST"
CAN_EXEC=$(kubectl auth can-i create pods --subresource=exec --as="$IDENTITY" -n default 2>/dev/null) || true
[ "$CAN_EXEC" = "no" ] && ok "Cannot exec pods after expiry" || fail "Expected no exec after expiry, got: $CAN_EXEC"

# 8. Audit log
step "8. Audit log"
POD=$(kubectl get pod -l app=policy-engine -n default -o jsonpath='{.items[0].metadata.name}')
LINES=$(kubectl exec "$POD" -n default -- sh -c 'wc -l < /app/audit.jsonl' 2>/dev/null || echo 0)
[ "$LINES" -gt 0 ] && ok "audit.jsonl: $LINES entries" || fail "audit.jsonl empty"

# Summary
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASSED: $PASS   FAILED: $FAIL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
