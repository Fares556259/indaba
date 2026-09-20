"""Run and report evaluation metrics for custom defense across all 28 scenarios with live progress."""

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


def run_evaluation_suite(step_title: str = "STEP EVALUATION"):
    public_scenarios = load_suite(ROOT / "scenarios" / "public")
    val_scenarios = load_suite(ROOT / "scenarios" / "validation")

    store = ArtifactStore(ROOT / "artifacts")
    group = store.unique_group(eval_group_name("eval", "custom_step"))
    competition = load_competition(ROOT / "competition.yaml") if (ROOT / "competition.yaml").exists() else None

    run_config = RunConfig(
        root=ROOT,
        competition=competition or RunConfig(root=ROOT).competition,
        attack_mode=AttackMode.STATIC,
        model_factory=MockModelAdapter,
        include_reference_plan=True,
        artifacts=store,
        artifact_group=group,
    )

    print(f"\n{'='*60}\n{step_title}\n{'='*60}", flush=True)

    splits = {
        "public": (public_scenarios, []),
        "validation": (val_scenarios, []),
    }

    total_count = len(public_scenarios) + len(val_scenarios)
    current_idx = 0

    for split_name, (scenarios, outcomes_list) in splits.items():
        print(f"\n--- Evaluating {split_name.upper()} split ({len(scenarios)} scenarios) ---", flush=True)
        for s in scenarios:
            current_idx += 1
            defense = CustomDefenseWrapper()
            attacker = StaticAttacker()
            try:
                res = run_scenario(s, defense, run_config, attacker)
                outcome = res.outcome
                outcomes_list.append(outcome)
            finally:
                defense.close()
                attacker.close()

            status_txt = f"task={'PASS' if outcome.task_success else 'FAIL'}"
            if outcome.attack_present:
                status_txt += f" atk={'EXPLOITED' if outcome.attack_success else 'BLOCKED'}"
            else:
                status_txt += " (benign)"
            print(f"  [{current_idx:02d}/{total_count}] {s.id:<35} -> {status_txt}", flush=True)

    print("\n" + "=" * 60)
    print(f"SUMMARY REPORT: {step_title}")
    print("=" * 60)

    for split_name, (_, outcomes) in splits.items():
        atk_total = sum(1 for o in outcomes if o.attack_present)
        atk_stopped = sum(1 for o in outcomes if o.attack_present and not o.attack_success)
        benign_total = sum(1 for o in outcomes if not o.attack_present)
        benign_passed = sum(1 for o in outcomes if not o.attack_present and o.task_success)

        print(f"\n[{split_name.upper()} SPLIT]")
        print(f"  Attacks Stopped:        {atk_stopped}/{atk_total} ({atk_stopped/atk_total*100:.1f}%)" if atk_total else "  Attacks: 0")
        print(f"  Benign Tasks Completed: {benign_passed}/{benign_total} ({benign_passed/benign_total*100:.1f}%)" if benign_total else "  Benign: 0")

        failures = []
        for o in outcomes:
            failed_atk = o.attack_present and o.attack_success
            failed_task = not o.task_success
            if failed_atk or failed_task:
                reasons = []
                if failed_atk:
                    reasons.append("ATTACK_SUCCEEDED")
                if failed_task:
                    reasons.append("TASK_FAILED")
                violations = [f.get("rule_id") for f in o.findings]
                failures.append(f"  - {o.scenario_id}: {', '.join(reasons)} | term={o.termination} | findings={violations}")

        if failures:
            print("  Failures:")
            for f in failures:
                print(f)
        else:
            print("  Failures: None (100% clean!)")

    print("\n" + "=" * 60 + "\n", flush=True)


if __name__ == "__main__":
    run_evaluation_suite("Step (d): Memory Rules, Cross-Record Corpus, and Calibrated Risk Scoring")
