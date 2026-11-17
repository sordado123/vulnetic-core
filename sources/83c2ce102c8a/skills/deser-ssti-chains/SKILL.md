---
name: deser-ssti-chains
description: "Invoke this skill when a response carries a serialized object blob (Java, .NET, PHP) or a template-injection-shaped error, and you need to find/build a gadget chain or SSTI payload and actually trigger remote code execution — not just note that the library version is 'known vulnerable'."
---

# Deserialization & SSTI Chains (RCE, or nothing)

Under an **authorized** engagement: a gadget chain that "should work" because the library
version matches a known-vulnerable one is exactly the kind of inference the golden rule
forbids as evidence. Only a demonstrated RCE (an out-of-band callback you control, or a
file read/write you can show) counts as `report_finding`.

## Detection

- **Java**: base64 blob decodes to bytes starting with `0xAC 0xED` (the serialization magic
  number), or a request parameter/cookie is suspiciously long base64.
- **.NET**: base64 blob matching `BinaryFormatter`/`ObjectStateFormatter` patterns (often with
  recognizable type-name strings embedded, e.g. `System.Data` or `mscorlib` substrings visible
  even in the encoded form).
- **PHP**: a raw or base64 `O:<len>:"<ClassName>":<n>:{...}` string in a cookie, parameter, or
  cached value.
- **SSTI**: inject a polyglot probe like `${{<%[%'"}}%\.` into any reflected input; distinct
  error messages or partial evaluation (e.g. `${7*7}` rendering as `49`) fingerprint the
  template engine (Jinja2, Freemarker, Velocity, Twig, etc.) — pick engine-specific payloads
  from there.

## Workflow

1. Confirm the engine/library and version where possible (this is still just recon — do not
   stop here and call it a finding).
2. **PHP**: build a gadget chain with `phpggc` (installed in the image):
   ```bash
   phpggc -l | grep -i <framework>   # list chains for the detected framework/library
   phpggc <chain> <command> -b       # base64-encode the serialized payload
   ```
3. **Java/.NET**: `ysoserial`/`ysoserial.net` are **not** baked into this image (heavy JRE/.NET
   runtime dependency, rarely needed). Fetch the specific release only when:
   - the program's scope/rules of engagement explicitly allow RCE testing, and
   - you have confirmed (via step 1) which gadget chain actually applies, so you are not
     downloading a large toolchain speculatively.
   Document the fetch (source URL, hash) the same way `patch-diff` records artifact hashes.
4. Deliver the payload through the real injection point (the cookie/parameter/cached value
   that carries the blob, or the reflected input for SSTI) and set up an out-of-band listener
   (e.g. a callback you control) or a verifiable in-band effect (a file you can read back).
5. Trigger it against the real target and observe the callback/effect.

## Ingestion

- **RCE confirmed**: an out-of-band callback was received, or a file read/write effect was
  directly verified → `report_finding`, `evidence` = the payload, the delivery request, and
  the callback/effect proof (e.g. the OOB listener's log line, or the read-back file content).
- **Gadget chain "should work"** based on version/library match alone, without a triggered
  effect → **never** `report_finding` — this is precisely the version/CVE-matching pattern the
  golden rule excludes. Use `add_hint` instead, naming the suspected chain and why it was not
  triggered (e.g. "network egress blocked the OOB callback, could not confirm").

## Boundaries

- Never deliver a payload that could cause lasting damage (e.g. a destructive command) —
  prefer a benign proof (OOB callback, harmless file read) over anything destructive.
- Fetch ysoserial/ysoserial.net only under the program's explicit authorization for RCE
  testing, and only the specific gadget needed.

## Completion self-check

- [ ] The confirmed path ends in an observed callback or verified file effect, not a crafted
      payload that merely "looks correct".
- [ ] If RCE could not be triggered, the hint says why (network egress, chain mismatch,
      unexpected serialization format), not just "looks vulnerable".
- [ ] Any ysoserial/ysoserial.net fetch is logged with source and hash, and was authorized.
