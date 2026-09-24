#!/usr/bin/env bash
#
# remediate.sh - apply a realistic partial fix:
#   remove the owner path, but leave the token-creator path intact.
#
set -euo pipefail
cd "$(dirname "$0")"
source ./config.env
source ./lab.state

DEPLOYER="${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
LOWPRIV="${LOWPRIV_SA}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "[*] Removing the owner-escalation roles (typical partial fix)..."
gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${DEPLOYER}" --role="roles/resourcemanager.projectIamAdmin" --condition=None -q >/dev/null 2>&1 || true
gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${DEPLOYER}" --role="roles/iam.serviceAccountAdmin" --condition=None -q >/dev/null 2>&1 || true
gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${LOWPRIV}" --role="roles/cloudbuild.builds.editor" --condition=None -q >/dev/null 2>&1 || true

echo "[*] Revoking the owner grant the exploit created (cleanup)..."
gcloud projects remove-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${LOWPRIV}" --role="roles/owner" --condition=None -q >/dev/null 2>&1 || true

cat <<EOF

[+] Partial fix applied - the owner path is closed.

    BUT (this is the whole point of the article): the low-priv principal still
    holds project-level roles/iam.serviceAccountTokenCreator, and ${RUNTIME_SA}@
    still holds roles/editor. That combination is enough to reach full data
    access without ever being Owner.

    Show it:  ./residual.sh
EOF
