---
name: race-conditions
description: "Invoke this skill when a single-use or rate-limited resource (coupon redemption, password reset, login attempt counter, balance/stock decrement) might be vulnerable to a race condition and you need to fire a concurrent burst of identical requests to actually win the race — not just reason about the window being narrow."
---

# Race Conditions (single-packet-style concurrent burst)

Under an **authorized** engagement: a race condition is a claim you can only back with an
actual duplicated success, not with "the check and the update look like separate steps".
The golden rule applies the same way here as to version/CVE matching — a theoretical window
is a hint, not a finding, until you have really won the race at least once.

## Hard gates

- Target only a resource this task already covers (your own test account's coupon/balance/
  attempt counter, or one the program explicitly provides for this purpose).
- A successful race condition against a REAL balance/stock/credit can have a lasting side
  effect (e.g. it actually duplicates a credit). Prefer a test account or a reversible
  resource; if neither exists, say so and get explicit go-ahead before firing the burst, the
  same way you would before any action with a side effect outside normal recon.

## Workflow

1. Identify the candidate endpoint: something meant to be used exactly once, or a limited
   number of times, per some unit of account/time (redeem coupon, reset password, submit
   withdrawal, record a login attempt).
2. Use `${SKILL_DIR}/scripts/race.py` to fire N (20-50) identical, fully-formed requests as
   close to simultaneously as the transport allows:
   ```bash
   python3 ${SKILL_DIR}/scripts/race.py --url <endpoint> --method POST \
       --header "Authorization: Bearer <token>" --body '<exact body>' --count 30
   ```
   It opens one HTTP/2 connection (falls back to pipelined HTTP/1.1 when the server does not
   negotiate h2) and sends all requests back-to-back on it, to minimize the per-request
   network jitter that would otherwise close the race window — the same principle as the
   "single-packet attack" technique, implemented in plain Python (`httpx`/`h2`), no new binary
   needed.
3. Compare how many requests actually succeeded (e.g. how many "coupon redeemed" responses,
   not how many requests were merely accepted/202'd) against the expected count (normally 1).

## Ingestion

- **More than the expected number of successes observed** (the resource really was granted/
  decremented/consumed more than once) → `report_finding`, `evidence` = the raw responses
  from the N requests showing the duplicate success, plus the resulting state (e.g. balance
  before/after, or two distinct "redeemed" confirmations for the same coupon code).
- **No duplication observed this run**, even though the window looks narrow → `add_hint`
  ("race-prone, did not win the race this attempt — may need HTTP/2 priming, more concurrent
  requests, or a different jitter-reduction technique"). Never report a race condition as
  confirmed just because the check-then-act pattern looks separable in the code/behavior.

## Boundaries

- Never fire the burst against a production resource with a real, non-reversible financial
  effect without explicit authorization for that specific side effect.
- Cap the burst size to what is needed to demonstrate the race (20-50); this is a correctness
  test, not a load test — do not scale it up looking for a DoS effect.

## Completion self-check

- [ ] The burst was fired against a resource this task covers, with side effects considered.
- [ ] The evidence shows an actual duplicated success, not merely "N requests sent".
- [ ] If no duplication occurred, the hint says so honestly instead of implying a confirmed bug.
