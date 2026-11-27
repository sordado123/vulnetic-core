---
name: oauth-sso-deep
description: "Invoke this skill when an OAuth2/OIDC/SSO login flow is in scope and you need to go beyond endpoint detection: redirect_uri manipulation, PKCE downgrade, state/nonce reuse, or account-linking confusion between identity providers, verified by actually logging in as a victim — not just by reading the flow."
---

# OAuth/SSO Deep Testing (beyond endpoint detection)

bbot's `oauth` module only flags that an OAuth endpoint exists. This skill goes past
detection into exploitation of the flow itself. Under an **authorized** engagement, the golden
rule still applies: a misconfiguration you can describe is not a finding until you have
actually used it to do something you should not be able to do (most commonly: authenticate as
someone else, or redirect a victim's auth code/token to a host you control).

## Hard gates

- Test only against accounts already covered by this task (your own test accounts, or
  accounts the program explicitly provides for this purpose). Never attempt to take over a
  real third party's account to "prove" the bug works.
- If the ID token is a JWT, use the `jwt-attacks` skill for alg/kid/jku issues instead of
  duplicating that logic here — come back to this skill once you have a forged/replayed ID
  token to use in the account-linking flow.

## Workflow

1. **Map the flow**: authorization endpoint, token endpoint, the full list of accepted
   `redirect_uri` values (or the validation logic you can infer from behavior), whether PKCE
   is required, whether `state`/`nonce` are checked and bound to the session.
2. **redirect_uri manipulation**: try a subdomain of the allowed host, a path appended after
   it, the `@`/userinfo trick (`https://allowed.com@attacker.com/`), and open-redirect-shaped
   values the validator might normalize differently than the browser. For each variant that
   the server accepts, check whether it actually redirects the auth code/token to your host.
3. **PKCE downgrade**: if the client supports PKCE, try completing the flow with the
   `code_verifier` omitted or mismatched; see whether the server still issues tokens.
4. **state/nonce reuse**: reuse a `state` or `nonce` value across sessions, or omit it
   entirely, and see whether the server still completes the flow (CSRF-shaped login,
   independent of redirect_uri issues).
5. **Account-linking confusion**: if the app supports multiple identity providers and links
   accounts by email, log in with a victim's email via a *different* provider than the one
   that originally registered it, and see whether the app treats you as that existing user.

## Ingestion

- You actually **logged in as the victim test account** (full session, not just an
  intercepted code) via any of the above → `report_finding`, `evidence` = the full flow's
  requests/responses that produced the session, and the resulting authenticated
  request proving you are that account.
- `redirect_uri` accepts an unexpected host but you did **not** demonstrate a consequence
  (no code/token actually observed leaving to your host) → `add_hint` — an open redirect by
  itself can be a low-severity finding, but only once you show it actually fires with a real
  code/token in flight, not from reading the validation logic alone.
- PKCE/state/nonce weaknesses that "look" skippable but you have not completed a full login
  without them → `add_hint`, not a finding.

## Boundaries

- Never target a real user's account; use only test accounts this task already covers.
- Never leave a redirect-capturing endpoint running against production traffic after the test.

## Completion self-check

- [ ] The exploit path ends in an actual authenticated session as the victim test account,
      not just an intercepted code/token with no verified use.
- [ ] If the ID token mattered, it went through `jwt-attacks` rather than ad hoc handling here.
- [ ] Evidence captures the full request/response chain, not a summary of the logic.
