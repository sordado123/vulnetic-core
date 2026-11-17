---
name: jwt-attacks
description: "Invoke this skill when a JWT (access token, ID token, reset/invite token, etc.) is in scope and you need to test alg=none, RS256→HS256 key confusion, kid injection, or jku/jwks spoofing against the real target — not just decode and eyeball the token."
---

# JWT Attacks (forge it, then prove it was accepted)

Under an **authorized** engagement, decoding a JWT and spotting a weak `alg` or a suspicious
`kid` is reconnaissance, not a finding. The golden rule in your system prompt still applies:
only a forged token the real server actually accepts, demonstrated by replaying it, counts.

## Hard gates

| Allowed | Prohibited |
|---|---|
| Decoding, tampering, and replaying tokens for accounts/scope already covered by this task | Forging a token for a real third party's account outside a lab/authorized test account |
| Testing `alg=none`, key confusion, `kid`/`jku`/`jwk` header injection | Treating a successfully *decoded* token as a finding by itself |
| Setting up your own JWKS endpoint to test `jku` spoofing, inside the engagement's infra | Spoofing a JWKS endpoint that leaks data to a host outside your control |

## Workflow

0. Sanity first: `jwt_tool -h` (flags drift between versions — trust it over memory, same
   discipline as `bbot -l` in `bbot-recon`).
1. Decode the token (`jwt_tool <token>` with no flags) and map which attacks apply:
   - `alg` is `none`, or the server is known to accept it → try the none-algorithm attack.
   - Server verifies with RS256/ES256 and you can obtain the public key (e.g. from a `/jwks`
     endpoint, a cert, or the app's own docs) → try RS256→HS256 confusion: sign a tampered
     token with the public key bytes as an HMAC secret.
   - Header has `kid` → try path traversal / SQLi-shaped values (e.g. a key id that resolves
     to a predictable/attacker-influenced file or row).
   - Header has `jku`/`jwk` → stand up a JWKS endpoint you control inside the engagement's
     infra, point the header at it, sign with your own key.
2. For each attack that `jwt_tool` (or manual crafting) produces a candidate forged token for,
   **replay it against a real authenticated endpoint** — not a syntax check, an actual request
   that would only succeed if the server trusted the forged token.
3. Capture the full request/response of that replay; this is your evidence, not the forged
   token's structure.

## Ingestion

- Forged token **accepted** by the real server **and** it returns data/access that requires
  authentication/a specific identity it should not have granted → `report_finding`. `evidence`
  = original token, forged token, and the full request/response of the accepted replay.
- Forged token rejected, or the attack is only "theoretically applicable" (e.g. `alg=none`
  looks supported by the library version but you have not actually gotten the server to
  accept a none-signed token) → `add_hint`. Never report a library/version-based theoretical
  weakness as a finding — that is exactly the version-matching the golden rule forbids.

## Boundaries

- Never forge tokens for real identities outside an authorized test account.
- Never leave a test JWKS endpoint pointed at infrastructure outside the engagement.
- Replay forged tokens only against the specific target in scope.

## Completion self-check

- [ ] The forged token was replayed against a real endpoint, not just validated offline.
- [ ] The response that "worked" was read closely — a 200 that still denies the actual
      resource is not acceptance.
- [ ] Evidence includes the original token, the forged token, and the accepted request/response.
