"""Holdout test runner: run all scenarios in tests/holdout/ through the defense in-process.

These scenarios test attack families NOT covered by the 28 official scenarios, using
paraphrased phrasing, novel encodings, and split-record injections.

Run:
  PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_holdout.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".venv" / "lib" / "python3.12" / "site-packages"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "starter-kits" / "python-defense"))

from app.decision import decide as custom_decide
from app.models import DefenseRequest as CustomDefenseRequest
from sentinel.config import load_competition
from sentinel.core.actions import DefenseDecision as SentinelDefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest as SentinelDefenseRequest
from sentinel.evaluator.runner import AttackMode, RunConfig, run_scenario, load_suite, eval_group_name
from sentinel.attackers.baselines.static import StaticAttacker
from sentinel.models.mock import MockModelAdapter
from sentinel.storage.runs import ArtifactStore


class CustomDefenseWrapper(Defense):
    name = "python_defense"

    def decide(self, request: SentinelDefenseRequest) -> SentinelDefenseDecision:
        data = request.model_dump(mode="json")
        req = CustomDefenseRequest.model_validate(data)
        dec = custom_decide(req)
        return SentinelDefenseDecision.model_validate(dec.model_dump(mode="json"))


def run_holdout():
    holdout_path = ROOT / "tests" / "holdout"
    scenarios = load_suite(holdout_path)
    if not scenarios:
        print(f"No holdout scenarios found under {holdout_path}")
        return

    store = ArtifactStore(ROOT / "artifacts")
    competition = load_competition(ROOT / "competition.yaml") if (ROOT / "competition.yaml").exists() else None
    group = store.unique_group(eval_group_name("holdout", "custom_defense"))

    from sentinel.evaluator.runner import RunConfig
    run_config = RunConfig(
        root=ROOT,
        competition=competition or RunConfig(root=ROOT).competition,
        attack_mode=AttackMode.STATIC,
        model_factory=MockModelAdapter,
        include_reference_plan=True,
        artifacts=store,
        artifact_group=group,
    )

    print(f"\n{'='*60}")
    print(f"HOLDOUT EVALUATION ({len(scenarios)} scenarios)")
    print(f"{'='*60}")

    results_by_family: dict[str, list[dict]] = {}
    total = len(scenarios)

    for i, s in enumerate(scenarios, 1):
        defense = CustomDefenseWrapper()
        attacker = StaticAttacker()
        try:
            res = run_scenario(s, defense, run_config, attacker)
            outcome = res.outcome
        finally:
            defense.close()
            attacker.close()

        family = getattr(s.attack, "family", None)
        family_str = family.value if family else "unknown"
        results_by_family.setdefault(family_str, []).append({
            "id": s.id,
            "attack_present": outcome.attack_present,
            "attack_success": outcome.attack_success,
            "task_success": outcome.task_success,
        })

        status = f"task={'PASS' if outcome.task_success else 'FAIL'}"
        if outcome.attack_present:
            status += f" atk={'EXPLOITED' if outcome.attack_success else 'BLOCKED'}"
        else:
            status += " (benign)"
        print(f"  [{i:02d}/{total}] {s.id:<40} -> {status}", flush=True)

    print(f"\n{'='*60}")
    print("HOLDOUT RESULTS BY ATTACK FAMILY")
    print(f"{'='*60}")

    all_attack_total = 0
    all_attack_stopped = 0
    all_benign_total = 0
    all_benign_passed = 0

    for family, outcomes in sorted(results_by_family.items()):
        atk = [o for o in outcomes if o["attack_present"]]
        ben = [o for o in outcomes if not o["attack_present"]]
        stopped = sum(1 for o in atk if not o["attack_success"])
        passed = sum(1 for o in ben if o["task_success"])
        all_attack_total += len(atk)
        all_attack_stopped += stopped
        all_benign_total += len(ben)
        all_benign_passed += passed

        print(f"\n[{family.upper()}]")
        if atk:
            print(f"  Attacks Stopped: {stopped}/{len(atk)}")
        if ben:
            print(f"  Benign Passed:   {passed}/{len(ben)}")
        failures = [o["id"] for o in outcomes if (o["attack_present"] and o["attack_success"]) or not o["task_success"]]
        if failures:
            print(f"  Failures: {', '.join(failures)}")
        else:
            print("  Failures: None")

    print(f"\n{'='*60}")
    print("HOLDOUT TOTALS")
    if all_attack_total:
        print(f"  Attacks Stopped: {all_attack_stopped}/{all_attack_total} ({all_attack_stopped/all_attack_total*100:.1f}%)")
    if all_benign_total:
        print(f"  Benign Passed:   {all_benign_passed}/{all_benign_total} ({all_benign_passed/all_benign_total*100:.1f}%)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    run_holdout()
