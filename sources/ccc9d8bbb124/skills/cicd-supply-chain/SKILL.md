---
name: cicd-supply-chain
description: "Invoke this skill when a program's scope includes its source code or GitHub organization and you need to audit GitHub Actions workflows for injectable contexts, pull_request_target misuse, or self-hosted-runner exposure — or assess dependency confusion risk — rather than just reading the YAML and guessing."
---

# CI/CD & Supply Chain (workflows and dependency confusion)

Under an **authorized** engagement, and only when the program's scope explicitly covers
source code / its GitHub organization. The golden rule's logic generalizes here: a workflow
file that *looks* injectable by static reading alone is a lead, never a finding, until the
injection was actually triggered and its effect observed.

## Workflow

1. **Parse robustly**: use `actionlint` (installed in the image) over every
   `.github/workflows/*.yml` to catch syntax-level issues and get a reliable structural parse
   instead of regexing YAML by hand:
   ```bash
   actionlint .github/workflows/*.yml
   ```
2. **Look for injectable contexts in `run:` steps** — untrusted input (an issue title, a PR
   title/body, a commit message, a branch name) interpolated directly into a shell command via
   `${{ ... }}` instead of passed as an environment variable. This is the single most common
   real-world GitHub Actions RCE pattern.
3. **`pull_request_target` with an untrusted checkout**: a workflow triggered on
   `pull_request_target` (which runs with the base repo's secrets/permissions) that then
   checks out and executes code from the PR head is a privilege-escalation pattern regardless
   of the injectable-context check above.
4. **Self-hosted runners reachable from a public PR**: a workflow using a self-hosted runner
   (not `ubuntu-latest`/`windows-latest`/etc.) that triggers on `pull_request` from forks lets
   an external contributor run code on infrastructure the program may not consider "internet-
   facing".
5. **Overly broad permissions**: `permissions: write-all` (or no `permissions:` block at all,
   which defaults broad on older repos) on a workflow that also handles untrusted input
   compounds any of the above.
6. **Dependency confusion** (internal package names with no public claim): cross-reference
   internal-looking package names found in `package.json`/`go.mod`/`requirements.txt`/etc.
   against the relevant public registry. This is a **separate, heavier gate** — see below.

## Ingestion

- **Workflow injection actually triggered**: an authorized test PR/issue whose payload (in an
  injectable context you identified) executed an observable command in the workflow run logs
  → `report_finding`, `evidence` = the test PR/issue, the workflow run's log showing the
  injected command execute, and the specific `run:` line that was vulnerable.
- **Pattern identified by static read alone** (injectable context exists, `pull_request_target`
  checks out PR code, a self-hosted runner is PR-triggerable) but not actually triggered →
  `add_hint` — same anti-static-pattern-matching logic as everywhere else in this system:
  reading the YAML and concluding "this looks exploitable" is not evidence.

### Dependency confusion — a separate, stricter gate

Proving dependency confusion for real means **publishing a package under the suspected name
on a public registry** (npm/PyPI/etc.) and observing whether the target's build pulls it —
this has a side effect entirely outside the target's own infrastructure (a public registry
now has a package that was not there before). **Do not do this on the general authorization
of a bug bounty program's scope alone.** Require explicit, specific written authorization for
this particular test, naming the package name(s) to be claimed, before publishing anything.
Once authorized: publish a harmless placeholder package, trigger the target's build/install
process, and check whether your package was fetched (e.g. via a unique install-time callback
or download-count signal) — only that observation, not the mere absence of a public claim on
the name, is evidence.

## Boundaries

- Never test outside a program's explicit source-code/GitHub-org scope.
- Never trigger a workflow injection against a real production branch/environment — use a
  disposable branch/PR/issue created for this test.
- Dependency confusion: no package publish without the specific written authorization above.

## Completion self-check

- [ ] Any reported workflow injection has an observed log line proving execution, not just the
      YAML pattern that made it look possible.
- [ ] Dependency confusion was either not attempted, or was attempted only after the specific
      extra authorization was obtained and recorded.
