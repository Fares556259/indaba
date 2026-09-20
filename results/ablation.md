# Ablation Study Results

Each row shows the effect of disabling one defense component on the 28-scenario official benchmark.

**Command**: `PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_ablation.py`

## Summary Table

| Component Removed | Attacks Stopped | Benign Passed | Scenarios That Break |
| :--- | :---: | :---: | :--- |
| **ALL_ON (baseline)** | 14/14 (100%) | 14/14 (100%) | None |
| No Normalizer | ? | ? | enterprise_val_encoded_exfil (base64 decoded payload not caught) |
| No Taint | ? | ? | All untrusted-source detection blind |
| No Authorization | ? | ? | Untrusted-arg injections (finance_false_approval, finance_dormant_supplier_claim) |
| No Corpus | ? | ? | soc_val_split_log (split payload spans 2 records) |
| No Memory Rules | ? | ? | enterprise_memory_poison, soc_intel_memory_poison |
| No Outbound Flow | ? | ? | enterprise_poisoned_invoice, enterprise_val_encoded_exfil, enterprise_direct_token_request |

> [!NOTE]
> Exact numbers will be filled in after running the ablation script.
> Run: `PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_ablation.py`

## Expected Impact by Component

### Normalizer (`normalizer.py`)

- Disabling it means encoded payloads (base64, hex, rot13, URL-encoded) are never decoded.
- The outbound flow rule falls back to direct string matching: `any(s in payload for s in sensitive)`.
- **Expected failures**: `enterprise_val_encoded_exfil` (base64-encoded exfil instruction), any scenario using encoded payloads.

### Taint Tracking (`taint.py`)

- Without taint, `untrusted = []` and `sensitive = []`.
- The outbound flow check, intent check, memory rules, and corpus all operate on empty inputs.
- **Expected failures**: nearly all attack scenarios, as nothing gets flagged.

### Authorization (`authorization.py`)

- Disables `check_action_intent()` which blocks tools called from untrusted content outside user intent.
- **Expected failures**: `finance_false_approval` (tool called for by merchant letter, not user), `finance_dormant_supplier_claim`, `enterprise_direct_token_request`.

### Cross-Record Corpus (`corpus.py`)

- Disables `build_cross_record_corpus()` and `match_in_corpus()`.
- Split-payload attacks that distribute instruction fragments across multiple records evade detection.
- **Expected failures**: `soc_val_split_log` (2 log records), potentially `holdout_three_record_split`.

### Memory Rules (`memory_rules.py`)

- Disables `is_memory_write_poisoned()`, meaning poisoned memory writes are allowed.
- **Expected failures**: `enterprise_memory_poison` (persists directive in memory for next turn), `soc_intel_memory_poison`.

### Outbound Flow (`decision.py` §2)

- Disables the external-destination + sensitive-payload check.
- **Expected failures**: `enterprise_poisoned_invoice` (exfil to external email), `enterprise_val_encoded_exfil`, `enterprise_direct_token_request`, many finance exfil variants.

## How to Run

```bash
# Run ablation study (takes ~15 minutes: 7 configs × 28 scenarios)
PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_ablation.py

# Results written to:
#   results/ablation.md  (this file, updated with actual numbers)
#   results/ablation.json (machine-readable)
```
