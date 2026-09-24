#!/usr/bin/env bash
#
# teardown.sh - remove everything. Default (fresh project) = delete the project.
#
set -euo pipefail
cd "$(dirname "$0")"
source ./config.env
source ./lab.state 2>/dev/null || { echo "No lab.state found - nothing to tear down."; exit 0; }

if [[ -z "${USE_EXISTING_PROJECT}" ]]; then
  echo "[*] Deleting throwaway project ${PROJECT_ID} (removes ALL lab resources)..."
  gcloud projects delete "${PROJECT_ID}" -q
  rm -f ./lab.state
  echo "[+] Done. The project is scheduled for deletion; no lingering cost."
else
  echo "[!] Existing-project mode - the project will NOT be deleted."
  echo "[*] Best-effort cleanup of lab resources in ${PROJECT_ID}..."
  DEPLOYER="${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
  LOWPRIV="${LOWPRIV_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
  RUNTIME="${RUNTIME_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
  for SA in "${DEPLOYER}" "${LOWPRIV}" "${RUNTIME}"; do
    gcloud iam service-accounts delete "${SA}" -q >/dev/null 2>&1 || true
  done
  gcloud secrets delete "${SECRET_NAME}" -q >/dev/null 2>&1 || true
  gcloud storage rm --recursive "gs://${PROJECT_ID}-metastore-documents" >/dev/null 2>&1 || true
  echo "[+] Removed lab SAs, the dummy secret and the demo bucket."
  echo "    NOTE: project-level role bindings for deleted SAs disappear with the SAs."
  rm -f ./lab.state
fi
