"""Evaluation harness for testing starter-kits/python-defense/app/decision.py on all 28 scenarios."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Ensure repo root and python-defense app are in path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "starter-kits" / "python-defense"))

from app.decision import decide as custom_decide
from app.models import DefenseRequest as CustomDefenseRequest
from sentinel.config import load_competition
from sentinel.core.actions import DefenseDecision as SentinelDefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest as SentinelDefenseRequest
from sentinel.evaluator.runner import AttackMode, RunConfig, evaluate, load_suite
from sentinel.attackers.baselines.static import StaticAttacker
from sentinel.models.mock import MockModelAdapter


class AppDefense(Defense):
    name = "python_defense"

    def decide(self, request: SentinelDefenseRequest) -> SentinelDefenseDecision:
        data = request.model_dump(mode="json")
        req = CustomDefenseRequest.model_validate(data)
        dec = custom_decide(req)
        return SentinelDefenseDecision.model_validate(dec.model_dump(mode="json"))


def run_eval_step(step_name: str = "Evaluation"):
    print(f"Starting {step_name}...", flush=True)
    public_scenarios = load_suite(ROOT / "scenarios" / "public")
    val_scenarios = load_suite(ROOT / "scenarios" / "validation")
    print(f"Loaded {len(public_scenarios)} public and {len(val_scenarios)} validation scenarios.", flush=True)

    competition = load_competition(ROOT / "competition.yaml") if (ROOT / "competition.yaml").exists() else None
    from sentinel.storage.runs import ArtifactStore
    from sentinel.evaluator.runner import eval_group_name
    store = ArtifactStore(ROOT / "artifacts")
    group = store.unique_group(eval_group_name("eval", "custom"))
    run_config = RunConfig(
        root=ROOT,
        competition=competition or RunConfig(root=ROOT).competition,
        attack_mode=AttackMode.STATIC,
        model_factory=MockModelAdapter,
        include_reference_plan=True,
        artifacts=store,
        artifact_group=group,
    )

    print("Evaluating public scenarios...", flush=True)
    pub_report = evaluate(public_scenarios, AppDefense, run_config, StaticAttacker)
    print("Public evaluation done. Evaluating validation scenarios...", flush=True)
    val_report = evaluate(val_scenarios, AppDefense, run_config, StaticAttacker)
    print("Validation evaluation done. Processing results...", flush=True)

    splits = {"public": pub_report.outcomes or [], "validation": val_report.outcomes or []}

    summary = {}
    failures = []

    for split_name, outcomes in splits.items():
        atk_total = sum(1 for o in outcomes if o.attack_present)
        atk_stopped = sum(1 for o in outcomes if o.attack_present and not o.attack_success)
        benign_total = sum(1 for o in outcomes if not o.attack_present)
        benign_passed = sum(1 for o in outcomes if not o.attack_present and o.task_success)

        summary[split_name] = {
            "atk_stopped": f"{atk_stopped}/{atk_total}",
            "atk_stopped_pct": round(atk_stopped / atk_total * 100, 1) if atk_total else 0,
            "benign_passed": f"{benign_passed}/{benign_total}",
            "benign_passed_pct": round(benign_passed / benign_total * 100, 1) if benign_total else 0,
        }

        for o in outcomes:
            failed_atk = o.attack_present and o.attack_success
            failed_task = not o.task_success
            if failed_atk or failed_task:
                failures.append({
                    "split": split_name,
                    "id": o.scenario_id,
                    "attack_present": o.attack_present,
                    "attack_success": o.attack_success if o.attack_present else False,
                    "task_success": o.task_success,
                    "termination": o.termination,
                    "findings": [f.get("rule_id") for f in o.findings],
                })

    print(f"\n==================== {step_name} ====================")
    print(f"Public Split:     Attacks Stopped: {summary['public']['atk_stopped']} ({summary['public']['atk_stopped_pct']}%) | Benign Passed: {summary['public']['benign_passed']} ({summary['public']['benign_passed_pct']}%)")
    print(f"Validation Split: Attacks Stopped: {summary['validation']['atk_stopped']} ({summary['validation']['atk_stopped_pct']}%) | Benign Passed: {summary['validation']['benign_passed']} ({summary['validation']['benign_passed_pct']}%)")
    print(f"\nFailures count: {len(failures)}")
    for f in failures:
        status_parts = []
        if f["attack_present"] and f["attack_success"]:
            status_parts.append("ATTACK_SUCCEEDED")
        if not f["task_success"]:
            status_parts.append("TASK_FAILED")
        findings_str = f" findings={f['findings']}" if f['findings'] else ""
        print(f"  - [{f['split']}] {f['id']}: {', '.join(status_parts)} (term: {f['termination']}){findings_str}")
    print("====================================================\n")

    return summary, failures


if __name__ == "__main__":
    run_eval_step("Initial Baseline Check")
