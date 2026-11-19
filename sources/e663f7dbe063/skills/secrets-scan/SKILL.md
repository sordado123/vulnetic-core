---
name: secrets-scan
description: "Invoke this skill when a git repository (an exposed .git directory, a public org repo, a source-code deliverable) or a collection of JS bundles is in scope and you need to find exposed credentials with gitleaks — then verify which ones, if any, are actually still live, rather than just listing regex matches."
---

# Secrets Scan (gitleaks, then verify liveness)

Under an **authorized** engagement: a string that matches a credential-shaped regex is a
lead, not a finding, until you have confirmed — with a minimal, read-only check — that it
still authenticates against something real.

## Workflow

1. **Git history**: for an exposed `.git` directory recovered during recon, or a repository the
   program's scope explicitly includes, run:
   ```bash
   gitleaks detect --source <repo-path-or-url> --report-format json --report-path /app/data/tasks/<task_id>/gitleaks/report.json
   ```
2. **JS bundles**: run the same scan over static assets already harvested by `api-recon`
   (`skills/api-recon/scripts/harvest_static.py`'s output directory) — secrets baked into
   front-end bundles are a common, easy-to-miss leak:
   ```bash
   gitleaks detect --no-git --source <harvested-static-dir> --report-format json --report-path ...
   ```
3. Read the report. For each hit that looks like a real, specific credential (not an example/
   placeholder value, not a test fixture clearly marked as such), attempt **one minimal
   read-only verification** appropriate to that credential type (e.g. a cloud provider's
   "who am I" / identity-check call, an API's own unauthenticated-vs-authenticated status
   endpoint). Never attempt an action beyond confirming the credential is live.

## Ingestion

- Secret matched **and** verified live via a minimal read-only check → `report_finding`,
  `evidence` = the gitleaks match (file/commit/line, redacted appropriately in the report),
  and the read-only verification's request/response (never the raw secret value in the
  finding text if a redacted form conveys the same evidence).
- Secret matches the pattern but liveness could not be verified (expired, rotated, or the
  verification call itself is out of scope) → `add_hint`, explicit about why it is unverified.

## Boundaries

- Verifying a found credential's validity may **never** go beyond a minimal read-only call —
  no write, no listing of unrelated resources "while you're there", no deletion, no transfer.
- Never use a found credential to pivot further into systems beyond confirming it is live, and
  never against a third-party service outside this task's scope, even if the credential
  happens to work there.
- Redact secret values in anything that leaves this task's own evidence store.

## Completion self-check

- [ ] Every reported secret was actually verified live with a minimal, non-destructive check.
- [ ] No action went beyond "confirm this credential authenticates" — nothing was listed,
      modified, or exfiltrated using it.
- [ ] Secret values are redacted in the finding text; the gitleaks report (with full context)
      is the evidence artifact, not a copy-paste of the raw value into the summary.
