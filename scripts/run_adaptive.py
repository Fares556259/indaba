"""Phase 3: Adaptive / mutation evaluation runner.

Run the static attacker baseline (since Qwen3-8B is not available on this machine).
For adaptive mode with a live LLM, replace MockModelAdapter with HFModelAdapter.

Usage:
  PYTHONUNBUFFERED=1 uv run --no-sync python scripts/run_adaptive.py

Hardware note: Qwen3-8B requires ~16 GB RAM + GPU. This machine cannot run it.
The script defaults to static attack mode with the mock model.
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


def run_adaptive(seeds: list[int] | None = None) -> None:
    """Run attack scenarios with the static attacker (mock model, static attack mode).

    NOTE: True adaptive attacks require a live LLM (qwen3-8b or similar).
    This machine cannot run Qwen3-8B due to insufficient RAM/GPU.
    See hardware_note.txt for details.
    """
    if seeds is None:
        seeds = [42, 123, 999]

    public_scenarios = load_suite(ROOT / "scenarios" / "public")
    attack_scenarios = [s for s in public_scenarios if s.attack.present]

    store = ArtifactStore(ROOT / "artifacts")
    competition = load_competition(ROOT / "competition.yaml") if (ROOT / "competition.yaml").exists() else None

    print(f"\n{'='*60}")
    print("ADAPTIVE/MUTATION EVALUATION (Static Fallback)")
    print(f"NOTE: Using static attacker + mock model (no Qwen3-8B available)")
    print(f"Hardware: Qwen3-8B requires ~16 GB VRAM. This machine cannot run it.")
    print(f"{'='*60}")

    results_by_family: dict[str, dict[str, int]] = {}

    for seed_idx, seed in enumerate(seeds, 1):
        print(f"\n--- Seed {seed} ({seed_idx}/{len(seeds)}) ---")
        for s in attack_scenarios:
            family = s.attack.family.value
            group = store.unique_group(eval_group_name(f"adaptive-seed{seed}", f"{s.id}"))
            run_config = RunConfig(
                root=ROOT,
                competition=competition or RunConfig(root=ROOT).competition,
                attack_mode=AttackMode.STATIC,
                model_factory=MockModelAdapter,
                include_reference_plan=True,
                artifacts=store,
                artifact_group=group,
            )
            defense = CustomDefenseWrapper()
            attacker = StaticAttacker()
            try:
                res = run_scenario(s, defense, run_config, attacker)
                outcome = res.outcome
            finally:
                defense.close()
                attacker.close()

            key = (family, seed)
            if family not in results_by_family:
                results_by_family[family] = {"total": 0, "blocked": 0}
            results_by_family[family]["total"] += 1
            if not outcome.attack_success:
                results_by_family[family]["blocked"] += 1

            status = "BLOCKED" if not outcome.attack_success else "EXPLOITED"
            print(f"  seed={seed} {s.id:<40} -> {status}", flush=True)

    print(f"\n{'='*60}")
    print("ADAPTIVE RESULTS BY ATTACK FAMILY")
    print(f"{'='*60}")
    for family, counts in sorted(results_by_family.items()):
        blocked = counts["blocked"]
        total = counts["total"]
        pct = blocked / total * 100 if total else 0
        print(f"  {family:<35} {blocked}/{total} ({pct:.1f}%)")

    print(f"\n{'='*60}")
    print("HARDWARE NOTE")
    print("  Qwen3-8B adaptive mode: NOT AVAILABLE")
    print("  Reason: Requires ~16 GB VRAM / RAM; this machine does not have GPU/sufficient RAM.")
    print("  True adaptive evaluation would require a machine with ≥ 16 GB GPU VRAM.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    run_adaptive(seeds=[42, 123, 999])
