"""Ablation study: run all scenarios with each defense component disabled one at a time.

Usage:
  PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_ablation.py

Produces:
  results/ablation.md
  results/ablation.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".venv" / "lib" / "python3.12" / "site-packages"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "starter-kits" / "python-defense"))

from app.config import DefenseConfig
from app.decision import decide as custom_decide
from app.models import DefenseRequest as CustomDefenseRequest
from sentinel.config import load_competition
from sentinel.core.actions import DefenseDecision as SentinelDefenseDecision
from sentinel.defenses.interface import Defense, DefenseRequest as SentinelDefenseRequest
from sentinel.evaluator.runner import AttackMode, RunConfig, run_scenario, load_suite, eval_group_name
from sentinel.attackers.baselines.static import StaticAttacker
from sentinel.models.mock import MockModelAdapter
from sentinel.storage.runs import ArtifactStore


class AblationDefense(Defense):
    def __init__(self, cfg: DefenseConfig, component_name: str) -> None:
        super().__init__()
        self.cfg = cfg
        self.name = f"ablation_{component_name}"

    def decide(self, request: SentinelDefenseRequest) -> SentinelDefenseDecision:
        data = request.model_dump(mode="json")
        req = CustomDefenseRequest.model_validate(data)
        dec = custom_decide(req, cfg=self.cfg)
        return SentinelDefenseDecision.model_validate(dec.model_dump(mode="json"))


ABLATION_CONFIGS: list[tuple[str, dict[str, bool]]] = [
    ("ALL_ON (baseline)", {}),
    ("no_normalizer", {"normalizer": False}),
    ("no_taint", {"taint": False}),
    ("no_authorization", {"authorization": False}),
    ("no_corpus", {"corpus": False}),
    ("no_memory_rules", {"memory_rules": False}),
    ("no_outbound_flow", {"outbound_flow": False}),
]


def run_ablation() -> None:
    public_scenarios = load_suite(ROOT / "scenarios" / "public")
    val_scenarios = load_suite(ROOT / "scenarios" / "validation")
    all_scenarios = public_scenarios + val_scenarios

    store = ArtifactStore(ROOT / "artifacts")
    competition = load_competition(ROOT / "competition.yaml") if (ROOT / "competition.yaml").exists() else None

    base_cfg = DefenseConfig()
    run_config_base = RunConfig(
        root=ROOT,
        competition=competition or RunConfig(root=ROOT).competition,
        attack_mode=AttackMode.STATIC,
        model_factory=MockModelAdapter,
        include_reference_plan=True,
        artifacts=store,
        artifact_group="ablation",
    )

    results: list[dict] = []

    print(f"\n{'='*70}")
    print("ABLATION STUDY: Disabling each defense component")
    print(f"{'='*70}\n")

    for config_name, overrides in ABLATION_CONFIGS:
        print(f"\n--- [{config_name}] ---")
        cfg = base_cfg.override(**overrides)

        atk_total = atk_stopped = ben_total = ben_pass = 0
        failures: list[str] = []

        group = store.unique_group(eval_group_name("ablation", config_name.replace(" ", "_")))
        run_config = RunConfig(
            root=ROOT,
            competition=competition or RunConfig(root=ROOT).competition,
            attack_mode=AttackMode.STATIC,
            model_factory=MockModelAdapter,
            include_reference_plan=True,
            artifacts=store,
            artifact_group=group,
        )

        for s in all_scenarios:
            defense = AblationDefense(cfg, config_name)
            attacker = StaticAttacker()
            try:
                res = run_scenario(s, defense, run_config, attacker)
                outcome = res.outcome
            finally:
                defense.close()
                attacker.close()

            if outcome.attack_present:
                atk_total += 1
                if not outcome.attack_success:
                    atk_stopped += 1
                else:
                    failures.append(f"{outcome.scenario_id} (ATTACK_SUCCEEDED)")
            else:
                ben_total += 1
                if outcome.task_success:
                    ben_pass += 1
                else:
                    failures.append(f"{outcome.scenario_id} (TASK_FAILED)")

            status = f"task={'PASS' if outcome.task_success else 'FAIL'}"
            if outcome.attack_present:
                status += f" atk={'EXPLOITED' if outcome.attack_success else 'BLOCKED'}"
            else:
                status += " (benign)"
            print(f"  {s.id:<40} -> {status}", flush=True)

        atk_pct = atk_stopped / atk_total * 100 if atk_total else 0
        ben_pct = ben_pass / ben_total * 100 if ben_total else 0
        print(f"\n  Attacks Stopped:        {atk_stopped}/{atk_total} ({atk_pct:.1f}%)")
        print(f"  Benign Tasks Completed: {ben_pass}/{ben_total} ({ben_pct:.1f}%)")
        if failures:
            print(f"  Failures: {', '.join(failures)}")
        else:
            print("  Failures: None")

        results.append({
            "config": config_name,
            "overrides": overrides,
            "attacks_stopped": atk_stopped,
            "attacks_total": atk_total,
            "attacks_stopped_pct": round(atk_pct, 1),
            "benign_passed": ben_pass,
            "benign_total": ben_total,
            "benign_passed_pct": round(ben_pct, 1),
            "failures": failures,
        })

    # Write JSON
    results_dir = ROOT / "results"
    results_dir.mkdir(exist_ok=True)
    json_path = results_dir / "ablation.json"
    json_path.write_text(json.dumps(results, indent=2))
    print(f"\n[JSON] Saved to {json_path}")

    # Write Markdown
    md_lines = [
        "# Ablation Study Results",
        "",
        "Each row shows the effect of disabling one defense component.",
        "Official set = 28 scenarios (19 public + 9 validation).",
        "",
        "| Component Removed | Attacks Stopped | Benign Passed | Scenarios That Broke |",
        "| :--- | :---: | :---: | :--- |",
    ]
    for r in results:
        atk_str = f"{r['attacks_stopped']}/{r['attacks_total']} ({r['attacks_stopped_pct']:.1f}%)"
        ben_str = f"{r['benign_passed']}/{r['benign_total']} ({r['benign_passed_pct']:.1f}%)"
        broke = ", ".join(r["failures"]) if r["failures"] else "None"
        md_lines.append(f"| {r['config']} | {atk_str} | {ben_str} | {broke} |")

    md_path = results_dir / "ablation.md"
    md_path.write_text("\n".join(md_lines) + "\n")
    print(f"[MD]   Saved to {md_path}")
    print("\n" + "\n".join(md_lines))


if __name__ == "__main__":
    run_ablation()
