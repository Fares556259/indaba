# SENTINEL Defense — Adaptive Multi-Tier Prompt Injection Defense

A defense submission for the [SENTINEL](https://github.com/Skan22/Sentinel_Starter_Kit) agentic AI safety benchmark.
It achieves **100% attack mitigation** and **100% benign task completion** across all 28 official scenarios (19 public + 9 validation) with the offline mock model.

---

## Contents

```
starter-kits/python-defense/   ← Defense service (submit this)
  app/
    main.py           FastAPI entry point
    decision.py       Multi-tier decision orchestrator
    config.py         Ablation feature flags
    normalizer.py     Recursive multi-encoding decoder
    policy_rules.py   Effect-tier classification
    authorization.py  Action intent & argument authorization
    taint.py          Provenance-based taint tracking
    corpus.py         Cross-record corpus aggregation
    memory_rules.py   Memory write protection
    models.py         Pydantic v2 API schemas
  Dockerfile
  requirements.txt
  sentinel-submission.yaml

scripts/
  run_all_evals.py    Run 28 official scenarios in-process
  run_holdout.py      Run 16 holdout scenarios in-process
  run_ablation.py     Ablation study (one component off per run)

tests/holdout/         16 additional holdout scenarios
viewer/trace_viewer.html   Single-file HTML trace viewer

results/
  ablation.md / .json
  holdout_results.md / .json
```

---

## Setup

### Prerequisites
- Python ≥ 3.12 (managed by uv)
- [uv](https://docs.astral.sh/uv/) (`pip install uv` or `brew install uv`)

### Install

```bash
git clone https://github.com/<your-repo>/Sentinel_Starter_Kit
cd Sentinel_Starter_Kit
uv sync
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FastAPI Service                       │
│              POST /v1/decision                          │
└───────────────────────┬─────────────────────────────────┘
                        │  DefenseRequest
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  decide() pipeline                       │
│                                                         │
│  1. TOOL_NOT_ALLOWED:  block if tool ∉ allowed_tools   │
│  2. OUTBOUND_FLOW:     check all decoded views of       │
│                        outbound payload vs sensitive    │
│                        content; block/redact on hit     │
│  3. MEMORY_WRITE:      block executable directives      │
│                        or fake approval overrides        │
│  4. CROSS-RECORD:      build corpus from all untrusted  │
│                        records; match split payloads    │
│  5. INTENT_CHECK:      action outside user goal that   │
│                        mirrors untrusted content→block  │
│  6. CONFIRMED:         hash-match against confirmations │
│  7. EFFECT_TIER:       CONSEQUENTIAL→escalate          │
│                        READ_ONLY→allow                  │
│  8. ALLOW              safe internal writes / responds  │
└──────────────────────────────────────────────────────────┘
          │               │               │               │
     normalizer.py  policy_rules.py  authorization.py  corpus.py
     taint.py        memory_rules.py  config.py
```

### Key Design Rules
- **Zero hard-coded scenario IDs, filenames, or canary tokens** — the defense uses only `user_goal`, `conversation`, `observation`, `candidate_action`, `policy_context`, `provenance`, and `history_digest`.
- **Policy overrides user goal** — restricted data to external destinations is always blocked even if the user requested it.
- **Outbound flow rule** — all decoded views of the payload are checked, so base64/hex/rot13/URL/spaced/reversed encodings do not bypass the sensitive-data check.

---

## Running the Service

### Development (no Docker)

```bash
cd starter-kits/python-defense
uv run --no-sync uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Health check:

```bash
curl http://127.0.0.1:8080/healthz
# {"status":"ok"}
```

### Docker

```bash
cd starter-kits/python-defense
docker build -t sentinel-defense .
docker run --rm -p 8080:8080 sentinel-defense
```

---

## Running the Evaluation

### Official 28 scenarios (in-process, fastest)

```bash
PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_all_evals.py
```

### Official 28 scenarios via HTTP (requires running service on port 8080)

```bash
# Terminal 1: start service
cd starter-kits/python-defense
uv run --no-sync uvicorn app.main:app --host 127.0.0.1 --port 8080

# Terminal 2: run via CLI
uv run --no-sync python -m sentinel.cli eval public --defense-url http://127.0.0.1:8080
uv run --no-sync python -m sentinel.cli eval validation --defense-url http://127.0.0.1:8080
```

### Holdout tests (16 new scenarios)

```bash
PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_holdout.py
```

### Ablation study

```bash
PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_ablation.py
# Produces results/ablation.md and results/ablation.json
```

### Submission validation

```bash
uv run --no-sync python -m sentinel.cli submission validate starter-kits/python-defense/
```

---

## Trace Viewer

Open `viewer/trace_viewer.html` in any browser.

- Click **Load Trace A** and select a `.jsonl` artifact from `artifacts/`.
- Rows are color-coded: 🟢 allow, 🔴 block, 🟠 escalate, 🔵 rewrite.
- Click any row to see the full decision breakdown, reason codes, risk score, confidence, and which untrusted source triggered the block.
- Click **Load Trace B** and select **Side-by-side** to compare allow-all vs. your defense on the same scenario.

---

## Results Summary

| Suite | Attacks Stopped | Benign Passed | Failures |
| :--- | :---: | :---: | :--- |
| Public (19) | **10/10 (100%)** | **9/9 (100%)** | None |
| Validation (9) | **4/4 (100%)** | **5/5 (100%)** | None |
| **Total** | **14/14 (100%)** | **14/14 (100%)** | **None** |

See [`REPORT.md`](REPORT.md) for the full threat model, ablation table, and failure analysis.

---

## Responsible AI Statement

This defense intercepts **candidate tool calls** before they execute. It observes `user_goal`, conversation history, provenance/trust metadata, and candidate action arguments. It does **not** train on or retain any user data beyond the single request.

**Known failure modes**: paraphrased injections with no structural keywords, novel encoding combinations at depth > 3, and attack scenarios where the sensitive data shares normalized tokens with the user goal.

**Humans should always be in the loop** for consequential actions (payments, asset isolation, security incidents). The defense escalates rather than blocks in ambiguous cases — this is intentional to preserve human oversight.

**Validation disclosure**: The validation set was used during development (Step d). It is **not** a clean held-out set. The holdout scenarios in `tests/holdout/` are genuinely unseen during defense development.
