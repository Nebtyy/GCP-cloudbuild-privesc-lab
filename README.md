# GCP Cloud Build → Owner Privilege Escalation Lab

A minimal, self-contained lab that reproduces a real-world Google Cloud
privilege-escalation pattern: an over-privileged **Cloud Build** deployer service
account lets a principal who is **not** a project Owner reach `roles/owner`, and a
**residual impersonation path** (`iam.serviceAccountTokenCreator`) that survives a
partial fix and still grants full data access.

Everything runs in an isolated, throwaway GCP project. Cost is effectively **$0**
and teardown deletes the project. All identifiers are fictional.

---

## ⚠️ Disclaimer

This is an **intentionally vulnerable** configuration for education and research.
Deploy it **only in a throwaway GCP project you own**. Do not apply any of these
IAM patterns to a real project, and do not use these techniques against systems you
are not explicitly authorized to test. You are responsible for how you use it.

---

## The attack in one picture

```
Act 1 - escalation to Owner
  non-owner  (roles/cloudbuild.builds.editor)
       │ submits a build
       ▼
  Cloud Build ── runs as ─► cloudbuild-deployer@   (projectIamAdmin + editor + ...)
                                   │ projects.setIamPolicy
                                   ▼
                            roles/owner granted → full project control

Act 2 - residual path (after projectIamAdmin is removed)
  non-owner ─ iam.serviceAccountTokenCreator (project-level)
       │ impersonates
       ▼
  app-runtime@ (roles/editor) ─► reads Secret Manager / Storage → data access, no Owner needed
```

The core primitive is documented by Google itself: `projectIamAdmin` carries
`resourcemanager.projects.setIamPolicy`, which can grant **any** role (including
`roles/owner`) to **any** principal. A deploy pipeline should never hold it.

---

## Prerequisites

- [`gcloud` CLI](https://cloud.google.com/sdk/docs/install)
- A Google account with a billing account (a new account's **Free Trial**, $300/90d, is plenty - this lab spends ≈ $0)
- `bash`, `python3`, `curl`, `openssl`
- An account **not** under a restrictive organization (org policies can block the role grants - a personal account is simplest; check with `gcloud organizations list`)

> **Easiest path: [Cloud Shell](https://cloud.google.com/shell).** Open it from the Cloud Console (the `>_` icon) and you get `gcloud`, `python3`, `curl` and `openssl` pre-installed and already authenticated - no local install or `gcloud auth login` needed. Just clone the repo there and run the scripts.

---

## Quickstart

```bash
gcloud auth login
gcloud billing accounts list          # note your billing account ID

cp config.env.example config.env      # config.env is gitignored (keeps your billing ID private)
nano config.env                       # set BILLING_ACCOUNT (rename ORG_SLUG if you like)
chmod +x *.sh

./setup.sh        # create the vulnerable project (~2 min)

# IMPORTANT: wait ~60 seconds after setup.sh before the next step.
# setup.sh grants the IAM bindings exploit.sh relies on, and those take up to a
# minute to propagate. Running exploit.sh immediately fails with
# "PERMISSION_DENIED ... iam.serviceAccounts.getAccessToken" - that is not a bug,
# just IAM propagation. Wait and run it again.

./exploit.sh      # Act 1: non-owner -> Owner            (screenshots 1-3)
./remediate.sh    # apply a realistic PARTIAL fix
./residual.sh     # Act 2: token-creator -> editor -> data  (screenshots 4-5)
./teardown.sh     # delete everything
```

IAM changes take up to ~60s to propagate; if a step errors on permissions, wait a
minute and re-run it.

---

## What each script does

| Script          | Role in the story |
|-----------------|-------------------|
| `setup.sh`      | Creates the project, three service accounts, and the vulnerable role set. |
| `cloudbuild.yaml` | The build step that runs under the deployer SA and rewrites the IAM policy. |
| `exploit.sh`    | **Act 1** - submits a build as a non-owner; the build grants it `roles/owner`. |
| `remediate.sh`  | Applies a realistic partial fix (removes the Owner path only). |
| `residual.sh`   | **Act 2** - shows the token-creator path still reaches editor-level data access. |
| `teardown.sh`   | Deletes the throwaway project (or removes lab resources in an existing one). |

---

## What you'll capture (for a write-up)

1. Before: the non-owner principal is **not** in `roles/owner`.
2. The build log: `add-iam-policy-binding ... roles/owner`, executed as the deployer SA.
3. After: the non-owner principal **is** Owner.
4. Residual: the non-owner mints an access token for the editor SA.
5. Residual: that token reads a secret - the partial fix did **not** close data access.

---

## Cost & cleanup

The escalation is pure IAM (free); the single build runs in seconds. Secret Manager
and one empty bucket stay within the free tier. `teardown.sh` deletes the project, so
nothing lingers. On the Free Trial, **Google never auto-charges your card** - you'd
have to manually upgrade to a paid account for any billing to occur.

---

## Repository layout

```
config.env.example # all names/settings (copy to config.env, which is gitignored)
setup.sh          # stand up the lab
cloudbuild.yaml   # the escalation build config
exploit.sh        # Act 1: privesc to Owner
remediate.sh      # partial fix
residual.sh       # Act 2: residual token-creator path
teardown.sh       # remove everything
gcp-privesc-check.sh  # READ-ONLY self-check: who can reach owner in YOUR project
README.md         # this file
```

## Bonus: check your own project

`gcp-privesc-check.sh` is a read-only audit you can run against any project you
own to see whether these paths exist there: service-account owners,
`projectIamAdmin`, project-level `serviceAccountTokenCreator` / `serviceAccountUser`,
the default compute SA with `editor`, exportable service-account keys, and whether
Data Access audit logging is on. It changes nothing.

```bash
./gcp-privesc-check.sh [PROJECT_ID]   # needs only roles/viewer + roles/iam.securityReviewer
```

To try the check under those minimal roles (instead of as Owner), `grant-auditor.sh`
sets up a read-only auditor identity you can impersonate:

```bash
./grant-auditor.sh                    # create a viewer + securityReviewer auditor SA
gcloud config set auth/impersonate_service_account privesc-auditor@<PROJECT_ID>.iam.gserviceaccount.com
./gcp-privesc-check.sh                 # now running with reader-level access only
gcloud config unset auth/impersonate_service_account
./grant-auditor.sh --revoke           # clean up
```

---

## References

- Google Cloud - [Understanding IAM roles](https://cloud.google.com/iam/docs/understanding-roles) (`projectIamAdmin` / `setIamPolicy`)
- Google Cloud - [Service account impersonation](https://cloud.google.com/iam/docs/service-account-impersonation) (`serviceAccountTokenCreator`)
- Google Cloud - [Cloud Build service account & permissions](https://cloud.google.com/build/docs/cloud-build-service-account)
- Rhino Security Labs - [Privilege Escalation in Google Cloud Platform](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/)
- [hackingthe.cloud](https://hackingthe.cloud/) - GCP attack techniques

---

## License

MIT - see [LICENSE](LICENSE).
