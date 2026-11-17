# Vulnetic L3 benchmark

The current method is `bench-v2-evidence`. Image-mode LLM verdicts are candidate matches, not confirmed vulnerabilities or successful reproduction. Exported reports explicitly leave `confirmed_findings` unknown and disallow superiority claims. The three paired ARTEX comparisons still require independent execution evidence and review; this runner alone does not satisfy that release gate.

For the operator's six-run comparison, `budget_gateway.py` binds only to loopback
and admits the pinned River model with non-streaming usage and an explicit output
cap of at most 4096 tokens. Its private JSON configuration has `base_url`,
`api_key`, `client_token`, `admin_token`, and optional `port` (3059). Store it
outside every customer workspace with owner-only permissions. Point both tested
profiles at `http://localhost:3059/v1`, with `streaming=false` and `max_tokens=4096`.
The upstream URL includes its API prefix, for example `/v1`.

An operator bearer token controls `POST /control` with `{"run":"artex-1"}`
(or `vulnetic-1`, through pair 3); `{"run":null}` blocks new calls.
Authenticated `GET /usage` returns only reservation/usage counts. The client token
can call `/v1/chat/completions` but cannot change the active run. Never expose this
operator fixture as a customer-facing endpoint.

The authorized total is **20,000,000 tokens**, with an equal conservative
reservation cap of **3,000,000 per run**. UTF-8 request bytes, 65,536 template
tokens and the full output cap are reserved durably before each upstream call.
Confirmed usage settles the reservation to the provider's reported token count.
Unknown outcomes retain the full reservation. HTTP 429 retains that reservation
and permits bounded retries; other failures or missing/excessive successful-response
usage block subsequent calls. The ceiling includes settled usage and outstanding
reservations. This does not estimate currency costs or promise exact tokenizer counts.
Keep the ledger across restarts. Unknown outcomes require operator review.

Juice Shop defaults to the pinned v18.0.0 image digest. For SaaS, pass `--ssh-target-id`, `--llm-profiles`, and an existing `--corpus-url` reachable from that VPS. The runner does not deploy a remote target automatically. Its default 5400-second task budget must be overridden deliberately for a bounded pilot comparison.

Measures whether the product can find and prove real vulnerabilities in a real
application, unprompted, against an executable oracle. That is the "operation"
level most model benchmarks do not reach: recognition benchmarks hand the model
a snippet and ask a question, while this harness hands Vulnetic a running app and
reads what it reports.

Method discipline adapted from capability-matrix (MIT) and VulnHunter's
benchmark harness (Apache-2.0).

## Layout

| | |
|---|---|
| `run_bench.py` | The runner: deploy corpus, create task, wait, fetch findings, judge, tally |
| `ground_truth/<corpus>.json` | Version-stamped ground truth (component + class + mechanism, deliberately coarse) |
| `benchmark-results/` | Output (gitignored): one directory per run with `report.md` + `results.json` |

## Scoring

Every ground-truth entry is matched against the scanner's findings by an
independent LLM judge, then graded on four gates (partial answers earn partial
credit):

| Gate | Test | Points |
|---|---|---|
| component | names the right endpoint or feature | 1 |
| class | acceptable vulnerability class | 2 |
| keywords | at least two mechanism-specific terms | 1 |
| proof | PoC describes a route that would actually work | 1 |

Standing rules, enforced by the runner:

1. **Multi-gate scoring, never pass/fail.** The gate pattern is the work item;
   the aggregate percentage is the least useful output.
2. **Discovery candidates.** A scanner finding beyond ground truth is not a
   false positive until verified; precision is reported as bounds meanwhile.
3. **The judge must not be the model under test.** The runner refuses to start
   when `--judge-model` equals `--subject-model` (override knowingly with
   `--allow-self-judge`).
4. **The judge must pass a falsification battery** before grading: a correct
   match, a wrong-bug match, and a vague non-answer. A grader that cannot fail
   the wrong ones does not run.
5. **Invalid never counts.** Findings with no summary and no report are
   excluded from every rate and named in the result.
6. **Every rate carries its denominator; the aggregate carries a Wilson 95%
   interval.** With 8 ground-truth entries, one run cannot separate close
   models; treat per-gate rates as observations and replicate before quoting
   differences.
7. **Results are stamped** with the method version, ground-truth version,
   subject model, judge model, and terminal task status. A result measured
   under an earlier version is not wrong; it is a result at that version.

## Usage

```bash
cd scripts/benchmark

# against a locally deployed Vulnetic, with an independent judge endpoint
VULNETIC_TOKEN=<jwt or mint via VULNETIC_JWT_KEY=/app/jwt.key copy> \
JUDGE_BASE_URL=https://api.example.com JUDGE_MODEL=<other-model> JUDGE_API_KEY=... \
python3 run_bench.py --corpus juice-shop --subject-model glm-5.3
```

Environment contract:

| Variable / flag | Meaning |
|---|---|
| `VULNETIC_BASE` / `--vulnetic-url` | Vulnetic base URL (default `http://localhost:8787`) |
| `VULNETIC_TOKEN` or `VULNETIC_JWT_KEY` | API bearer token, or the server's jwt.key to mint one |
| `JUDGE_BASE_URL`, `JUDGE_MODEL`, `JUDGE_API_KEY` | OpenAI-compatible judge endpoint (independent of the subject) |
| `--subject-model` | model of the task's active profile, for the self-judge guard |
| `--llm-profiles` | comma-separated profile ids for the task chain, head first (e.g. `3,2`); stamped into the result |
| `--target-host` | host the task should target, as reachable from Vulnetic (use `172.17.0.1` when Vulnetic runs in a container and the corpus runs on the host) |
| `--image` / `--port` / `--corpus-url` | corpus container image, local port, or an existing deployment |
| `--task-timeout` | task `timeout_seconds` (default 5400) |
| `--keep` | keep the corpus container after the run |

The created task's goal bakes the standing quality gates (executed PoC, measured
impact with denominator, proof basis, zero-findings-is-valid), so the benchmark
measures the product as it actually behaves.

## Adding a corpus

Add `ground_truth/<name>.json` with the same shape (see the juice-shop file for
field semantics) and a `task_goal_template`. Pin the image tag in the file's
`version` note. Entries stay coarse on purpose: component + class + mechanism.
Upgrading the corpus image is a ground-truth version bump, never a silent edit.

## DrostBench corpus (drost mode)

[DrostBench v1](https://github.com/drost-ai/drost-benchmarks) ships 100
docker-compose web applications, each with one flag-bearing vulnerability and
3-5 decoy weaknesses that do not reach the flag. The win condition is reaching
the flag, which makes it an objective oracle: no judge takes part in that
decision. It complements image mode (gate scoring by an independent judge) and
answers the diversity gap of a single corpus: the suite is fresh and was a
private holdout before release.

Pin a checkout of the suite, then run one challenge at a time:

```bash
DROST_REPO=/path/to/drost-benchmarks python3 run_bench.py \
    --corpus-type drost --drost-id DBEN-v1-001 \
    --llm-profiles 3,2 --target-host 172.17.0.1 \
    --subject-model deepseek-chat
```

- `--target-host 172.17.0.1` when Vulnetic runs in a container: the challenge is
  published on the host and the task target must be the host gateway (same
  pattern as the MCP server URLs). `--llm-profiles` picks the task's model
  chain, head first.
- Black-box web only: this measures the recon/pentest lane, not codeaudit.
- Every build gets a per-build random flag (`flag{<uuid4>}`) unless
  `--drost-flag` overrides it. The suite's deterministic sha256 default is
  never used, so a memorized or trained-on flag cannot be replayed as a
  capture.
- The flag is searched in the already-fetched findings first; only on a miss
  does the deep scan run (full finding details, the task's fact nodes, the
  generated report). Declaring a miss is a claim about all of those.
- Ground truth is derived at run time from the challenge `benchmark.json`
  (name, description, tags). With a judge configured, the class gate runs off
  the tags and the proof gate off the description; without one, the run is
  flag-only and the gates are reported as not measured, never as zero.
- Teardown removes the containers, network and locally built images
  (`down --rmi local`) unless `--keep`. Results are stamped with the challenge
  id and the suite's commit sha.

`--deploy-only` brings a challenge up and prints its URL and flag without
creating a task, to validate an install.

## What this does not measure

Single-run results are noisy (the fork of VulnHunter measured a 14x spread in
findings across runs of the same commit); replicate before believing a delta.
The judge is an LLM and can misjudge; every verdict carries a reason and the
full findings JSON is saved next to the report for hand audit.
