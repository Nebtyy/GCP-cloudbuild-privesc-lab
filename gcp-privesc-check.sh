#!/usr/bin/env bash
#
# gcp-privesc-check.sh - READ-ONLY audit for the escalation paths shown in this lab.
#
# It answers: in THIS project, who can reach roles/owner, who can impersonate
# service accounts, and is the residual (token-creator) path open? It changes
# nothing.
#
# Minimum roles to run it (both read-only, no write permissions):
#     roles/viewer  +  roles/iam.securityReviewer
#
# Usage:
#     ./gcp-privesc-check.sh [PROJECT_ID]
#     (defaults to your current gcloud project)
#
set -euo pipefail

PID="${1:-$(gcloud config get-value project 2>/dev/null || true)}"
if [[ -z "${PID}" || "${PID}" == "(unset)" ]]; then
  echo "usage: $0 [PROJECT_ID]  (or set one with: gcloud config set project <id>)"
  exit 1
fi

echo "============================================================"
echo " GCP privesc self-check (READ-ONLY)   project: ${PID}"
echo "============================================================"

POLICY_JSON="$(gcloud projects get-iam-policy "${PID}" --format=json)"
PNUM="$(gcloud projects describe "${PID}" --format='value(projectNumber)' 2>/dev/null || true)"

# ---------------------------------------------------------------------------
# IAM policy analysis
# ---------------------------------------------------------------------------
printf '%s' "${POLICY_JSON}" | PID="${PID}" PNUM="${PNUM}" python3 - <<'PY'
import os, json, sys

policy = json.load(sys.stdin)
pid  = os.environ.get("PID", "")
pnum = os.environ.get("PNUM", "")

roles = {}
for b in policy.get("bindings", []):
    roles.setdefault(b["role"], []).extend(b.get("members", []))

def block(tag, title, members):
    mark = {"WARN": "[!]", "INFO": "[*]", "OK": "[+]"}[tag]
    print(f"\n{mark} {title}")
    if members:
        for m in sorted(set(members)):
            print(f"      - {m}")
    else:
        print("      (none)")

# roles/owner
owners = roles.get("roles/owner", [])
block("INFO", "roles/owner holders", owners)
sa_owners = [m for m in owners if m.startswith("serviceAccount:")]
if sa_owners:
    block("WARN", "Service accounts holding roles/owner (bearer-owner, HIGH)", sa_owners)

# owner-equivalent: setIamPolicy via projectIamAdmin
pia = roles.get("roles/resourcemanager.projectIamAdmin", [])
if pia:
    block("WARN", "roles/resourcemanager.projectIamAdmin (setIamPolicy = grant any role = owner-equivalent)", pia)

# impersonation reach (the residual path)
tc = roles.get("roles/iam.serviceAccountTokenCreator", [])
if tc:
    block("WARN", "roles/iam.serviceAccountTokenCreator at project level (mint a token for ANY SA)", tc)
su = roles.get("roles/iam.serviceAccountUser", [])
if su:
    block("WARN", "roles/iam.serviceAccountUser at project level (actAs ANY SA, e.g. run a build as it)", su)

# broad write
ed = roles.get("roles/editor", [])
if ed:
    block("INFO", "roles/editor holders (broad write across the project)", ed)
if pnum:
    default_compute = f"serviceAccount:{pnum}-compute@developer.gserviceaccount.com"
    if default_compute in ed:
        block("WARN", "Default compute service account has roles/editor (default over-privilege)", [default_compute])

# who can reach the build pipeline
cb = roles.get("roles/cloudbuild.builds.editor", []) + roles.get("roles/cloudbuild.builds.builder", [])
if cb:
    block("INFO", "Cloud Build create/edit holders (a build runs as a build SA - check what that SA can do)", cb)

# custom roles need a manual look (they may hide setIamPolicy / getAccessToken / actAs)
custom = [r for r in roles if r.startswith(f"projects/{pid}/roles/")]
if custom:
    block("INFO", "Custom roles in policy (describe each; watch for setIamPolicy / getAccessToken / actAs)", custom)

# data access audit logging
print()
if policy.get("auditConfigs"):
    print("[+] Data Access audit logging: auditConfigs present")
else:
    print("[!] Data Access audit logging: NO auditConfigs - data reads/impersonation are NOT logged")
PY

# ---------------------------------------------------------------------------
# Exportable (user-managed) service account keys - read-only
# ---------------------------------------------------------------------------
echo
echo "[*] User-managed (exportable) service account keys:"
found=0
while IFS= read -r sa; do
  [[ -z "${sa}" ]] && continue
  keys="$(gcloud iam service-accounts keys list --iam-account="${sa}" --managed-by=user \
            --project="${PID}" --format='value(name.basename(),validBeforeTime)' 2>/dev/null || true)"
  if [[ -n "${keys}" ]]; then
    echo "    [!] ${sa}"
    # validBeforeTime of 9999-... means the key never expires
    while IFS= read -r line; do echo "          ${line}"; done <<< "${keys}"
    found=1
  fi
done < <(gcloud iam service-accounts list --project="${PID}" --format='value(email)' 2>/dev/null || true)
[[ "${found}" -eq 0 ]] && echo "    [+] none found (or no permission to list keys)"

cat <<'EOF'

------------------------------------------------------------
How to read this:
  [!] WARN  a path worth closing (owner-equivalent role, project-level
            impersonation, default over-privilege, missing audit logs,
            or an exportable key).
  [*] INFO  context to review by hand.
  [+] OK    nothing flagged for that check.

"All closed" looks like: no service-account owners, no projectIamAdmin,
no project-level serviceAccountTokenCreator / serviceAccountUser, the
default compute SA without editor, no exportable keys, and auditConfigs present.

This script only reads. It never changes IAM.
EOF
