#!/usr/bin/env bash
#
# setup.sh - stand up the deliberately-vulnerable GCP Cloud Build privesc lab.
# Read-safe: creates an ISOLATED project by default. Run teardown.sh to remove everything.
#
set -euo pipefail
cd "$(dirname "$0")"
source ./config.env

command -v gcloud >/dev/null || { echo "ERROR: gcloud CLI not found. See README."; exit 1; }

# ---------------------------------------------------------------------------
# 0. Resolve the project (create fresh, or use an existing one)
# ---------------------------------------------------------------------------
if [[ -n "${USE_EXISTING_PROJECT}" ]]; then
  PROJECT_ID="${USE_EXISTING_PROJECT}"
  echo "[*] Using existing project: ${PROJECT_ID}"
  gcloud projects describe "${PROJECT_ID}" >/dev/null
else
  PROJECT_ID="${ORG_SLUG}-metastore-lab-$(openssl rand -hex 3)"
  echo "[*] Creating throwaway project: ${PROJECT_ID}"
  gcloud projects create "${PROJECT_ID}" --name="${PROJECT_NAME}"
  echo "[*] Linking billing account ${BILLING_ACCOUNT}"
  gcloud billing projects link "${PROJECT_ID}" --billing-account="${BILLING_ACCOUNT}" >/dev/null
fi

echo "PROJECT_ID=${PROJECT_ID}" > ./lab.state
gcloud config set project "${PROJECT_ID}" >/dev/null

ME="$(gcloud config get-value account 2>/dev/null)"
DEPLOYER="${DEPLOYER_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
LOWPRIV="${LOWPRIV_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
RUNTIME="${RUNTIME_SA}@${PROJECT_ID}.iam.gserviceaccount.com"

# ---------------------------------------------------------------------------
# 1. Enable APIs
# ---------------------------------------------------------------------------
echo "[*] Enabling APIs (can take 1-2 min)..."
gcloud services enable \
  cloudbuild.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  secretmanager.googleapis.com \
  storage.googleapis.com

# Make sure the Cloud Build service agent exists so we can grant it below.
gcloud beta services identity create --service=cloudbuild.googleapis.com --project="${PROJECT_ID}" >/dev/null 2>&1 || true
PNUM="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
CB_AGENT="service-${PNUM}@gcp-sa-cloudbuild.iam.gserviceaccount.com"

# ---------------------------------------------------------------------------
# 2. Service accounts
# ---------------------------------------------------------------------------
echo "[*] Creating service accounts..."
gcloud iam service-accounts create "${DEPLOYER_SA}" --display-name="Cloud Build deployer (LAB - intentionally over-privileged)" >/dev/null
gcloud iam service-accounts create "${LOWPRIV_SA}"  --display-name="Low-priv builder (LAB - non-owner stand-in)"           >/dev/null
gcloud iam service-accounts create "${RUNTIME_SA}"  --display-name="App runtime (LAB - editor)"                            >/dev/null

# ---------------------------------------------------------------------------
# 3. The VULNERABLE role set on the deployer SA (the misconfiguration itself)
#    projectIamAdmin + serviceAccountAdmin + serviceAccountUser + editor
# ---------------------------------------------------------------------------
echo "[*] Granting the vulnerable role set to the deployer SA..."
for R in \
  roles/resourcemanager.projectIamAdmin \
  roles/iam.serviceAccountAdmin \
  roles/iam.serviceAccountUser \
  roles/editor
do
  gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${DEPLOYER}" --role="${R}" --condition=None -q >/dev/null
done

# ---------------------------------------------------------------------------
# 4. The non-owner principal that can reach the build pipeline
#    (a user/SA holding roles/cloudbuild.builds.editor)
# ---------------------------------------------------------------------------
echo "[*] Granting the low-priv principal build-create rights..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${LOWPRIV}" --role="roles/cloudbuild.builds.editor" --condition=None -q >/dev/null

# In a typical setup a build TRIGGER already holds the SA binding, so the caller
# needs no actAs. We reproduce the same end state by letting the low-priv
# principal actAs the deployer SA directly (see README, "Faithfulness notes").
gcloud iam service-accounts add-iam-policy-binding "${DEPLOYER}" \
  --member="serviceAccount:${LOWPRIV}" --role="roles/iam.serviceAccountUser" -q >/dev/null

# ---------------------------------------------------------------------------
# 5. RESIDUAL path (the retest angle): low-priv keeps project-level
#    serviceAccountTokenCreator, and an 'editor' SA remains impersonatable.
# ---------------------------------------------------------------------------
echo "[*] Wiring the residual (post-fix) path..."
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${LOWPRIV}" --role="roles/iam.serviceAccountTokenCreator" --condition=None -q >/dev/null
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
  --member="serviceAccount:${RUNTIME}" --role="roles/editor" --condition=None -q >/dev/null

# ---------------------------------------------------------------------------
# 6. Plumbing so YOU can drive the low-priv identity via impersonation (no keys)
# ---------------------------------------------------------------------------
echo "[*] Allowing your account to impersonate the low-priv principal..."
gcloud iam service-accounts add-iam-policy-binding "${LOWPRIV}" \
  --member="user:${ME}" --role="roles/iam.serviceAccountTokenCreator" -q >/dev/null
# Cloud Build service agent must be able to mint tokens for the custom build SA.
gcloud iam service-accounts add-iam-policy-binding "${DEPLOYER}" \
  --member="serviceAccount:${CB_AGENT}" --role="roles/iam.serviceAccountTokenCreator" -q >/dev/null || true

# ---------------------------------------------------------------------------
# 7. "Customer data" to prove impact: one dummy secret + one bucket
# ---------------------------------------------------------------------------
echo "[*] Creating a dummy secret and a demo bucket..."
printf '%s' "LAB-DUMMY-$(openssl rand -hex 8)" | gcloud secrets create "${SECRET_NAME}" --data-file=- -q >/dev/null 2>&1 || echo "    (secret already exists, skipping)"
# NOTE: roles/editor does NOT include secretmanager.versions.access (it is excluded
# from basic roles). Real app service accounts hold secretAccessor explicitly, so we
# grant it here - this is what makes the residual path reach the secret payload.
gcloud secrets add-iam-policy-binding "${SECRET_NAME}" \
  --member="serviceAccount:${RUNTIME}" --role="roles/secretmanager.secretAccessor" -q >/dev/null 2>&1 || true
gcloud storage buckets create "gs://${PROJECT_ID}-metastore-documents" --uniform-bucket-level-access -q >/dev/null 2>&1 || echo "    (bucket already exists, skipping)"

cat <<EOF

[+] Setup complete.
    Project : ${PROJECT_ID}
    Deployer: ${DEPLOYER}
    Low-priv: ${LOWPRIV}
    Runtime : ${RUNTIME}

    IAM changes can take up to ~60s to propagate. If the next step errors with
    a permission message, wait a minute and re-run it.

    Next:  ./exploit.sh
EOF
