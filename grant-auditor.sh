#!/usr/bin/env bash
#
# grant-auditor.sh - set up a minimal READ-ONLY identity to run gcp-privesc-check.sh.
#
# Grants only two read-only roles: roles/viewer + roles/iam.securityReviewer.
# Neither carries any write permission, so the auditor can enumerate the IAM
# policy but cannot change it.
#
# Default mode creates a throwaway auditor service account you can impersonate,
# so you can prove the check works with reader-level access (not as owner).
#
# Usage:
#   ./grant-auditor.sh            # create auditor SA, grant read-only roles, allow you to impersonate it
#   ./grant-auditor.sh --user     # instead grant the two read-only roles to YOUR user account
#   ./grant-auditor.sh --revoke   # remove the grants and delete the auditor SA
#
set -euo pipefail
cd "$(dirname "$0")"

PID="$(gcloud config get-value project 2>/dev/null || true)"
if [[ -z "${PID}" || "${PID}" == "(unset)" ]]; then
  echo "Set a project first:  gcloud config set project <id>"
  exit 1
fi

ME="$(gcloud config get-value account 2>/dev/null)"
AUDITOR_SA="privesc-auditor"
AUD="${AUDITOR_SA}@${PID}.iam.gserviceaccount.com"
READ_ROLES=(roles/viewer roles/iam.securityReviewer)
MODE="${1:-sa}"

case "${MODE}" in
  --revoke)
    echo "[*] Revoking auditor access in ${PID}..."
    for R in "${READ_ROLES[@]}"; do
      gcloud projects remove-iam-policy-binding "${PID}" --member="serviceAccount:${AUD}" --role="${R}" --condition=None -q >/dev/null 2>&1 || true
      gcloud projects remove-iam-policy-binding "${PID}" --member="user:${ME}" --role="${R}" --condition=None -q >/dev/null 2>&1 || true
    done
    gcloud iam service-accounts delete "${AUD}" -q >/dev/null 2>&1 || true
    echo "[+] Revoked. Auditor SA removed (if it existed)."
    ;;

  --user)
    echo "[*] Granting read-only audit roles to user:${ME} on ${PID}..."
    for R in "${READ_ROLES[@]}"; do
      gcloud projects add-iam-policy-binding "${PID}" --member="user:${ME}" --role="${R}" --condition=None -q >/dev/null
    done
    echo "[+] Done. Now run:  ./gcp-privesc-check.sh ${PID}"
    ;;

  sa)
    echo "[*] Creating read-only auditor SA and granting viewer + securityReviewer..."
    gcloud iam service-accounts create "${AUDITOR_SA}" \
      --display-name="Read-only privesc auditor (LAB)" >/dev/null 2>&1 || echo "    (auditor SA already exists)"
    for R in "${READ_ROLES[@]}"; do
      gcloud projects add-iam-policy-binding "${PID}" --member="serviceAccount:${AUD}" --role="${R}" --condition=None -q >/dev/null
    done
    gcloud iam service-accounts add-iam-policy-binding "${AUD}" \
      --member="user:${ME}" --role="roles/iam.serviceAccountTokenCreator" -q >/dev/null

    cat <<EOF

[+] Auditor ready: ${AUD}   (roles: viewer + iam.securityReviewer only)

Verify the check runs with reader-level access only:
    gcloud config set auth/impersonate_service_account ${AUD}
    ./gcp-privesc-check.sh ${PID}
    gcloud config unset auth/impersonate_service_account

Clean up afterwards:
    ./grant-auditor.sh --revoke
EOF
    ;;

  *)
    echo "usage: $0 [--user | --revoke]"
    exit 1
    ;;
esac
