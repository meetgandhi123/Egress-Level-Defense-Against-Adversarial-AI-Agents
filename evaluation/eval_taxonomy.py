#!/usr/bin/env python3
"""
Focused evaluation on the 6 taxonomy attack patterns.
Forces Tier-2 analysis to properly evaluate the LLM trajectory analyzer.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from eval.baselines.trajectory_aware import TrajectoryAwareDefense
from eval.baselines.base import NetworkRequest, DefenseDecision


def load_taxonomy_scenarios():
    """Load only the taxonomy attack scenarios."""
    scenarios_file = Path(__file__).parent / "datasets" / "converted_scenarios.json"
    with open(scenarios_file) as f:
        all_scenarios = json.load(f)

    # Filter to attack scenarios only
    attacks = [s for s in all_scenarios if s.get("expected_label") == "attack"]
    return attacks


def run_evaluation():
    scenarios = load_taxonomy_scenarios()
    print(f"Loaded {len(scenarios)} taxonomy attack scenarios\n")

    defense = TrajectoryAwareDefense()

    results_by_pattern = defaultdict(lambda: {"tp": 0, "fn": 0, "tier1": 0, "tier2": 0})
    detailed_results = []

    for scenario in scenarios:
        pattern = scenario["attack_type"]
        task = scenario["task_prompt"]

        defense.reset(task_context=task)

        scenario_detected = False
        tier_used = 1
        decisions = []

        for req_data in scenario["requests"]:
            request = NetworkRequest(
                method=req_data["method"],
                url=f"https://{req_data['host']}{req_data['path']}",
                headers={},
                body=None
            )

            result = defense.evaluate(request)
            decisions.append({
                "request": f"{req_data['method']} {req_data['host']}{req_data['path']}",
                "decision": result.decision.name,
                "tier": result.tier_used,
                "reason": result.reason
            })

            if result.tier_used == 2:
                tier_used = 2

            if result.decision in (DefenseDecision.BLOCK, DefenseDecision.ESCALATE):
                scenario_detected = True

        # Also check if scenario was escalated overall
        if defense.should_escalate_scenario():
            scenario_detected = True

        if scenario_detected:
            results_by_pattern[pattern]["tp"] += 1
        else:
            results_by_pattern[pattern]["fn"] += 1

        if tier_used == 2:
            results_by_pattern[pattern]["tier2"] += 1
        else:
            results_by_pattern[pattern]["tier1"] += 1

        detailed_results.append({
            "pattern": pattern,
            "detected": scenario_detected,
            "tier_used": tier_used,
            "decisions": decisions
        })

    # Print results
    print("=" * 70)
    print("TAXONOMY PATTERN EVALUATION RESULTS")
    print("=" * 70)
    print(f"{'Pattern':<25} {'TP':>4} {'FN':>4} {'ADR':>8} {'Tier-1':>7} {'Tier-2':>7}")
    print("-" * 70)

    total_tp = 0
    total_fn = 0
    total_tier1 = 0
    total_tier2 = 0

    for pattern in sorted(results_by_pattern.keys()):
        r = results_by_pattern[pattern]
        tp, fn = r["tp"], r["fn"]
        total = tp + fn
        adr = (tp / total * 100) if total > 0 else 0

        total_tp += tp
        total_fn += fn
        total_tier1 += r["tier1"]
        total_tier2 += r["tier2"]

        print(f"{pattern:<25} {tp:>4} {fn:>4} {adr:>7.1f}% {r['tier1']:>7} {r['tier2']:>7}")

    print("-" * 70)
    total = total_tp + total_fn
    overall_adr = (total_tp / total * 100) if total > 0 else 0
    print(f"{'TOTAL':<25} {total_tp:>4} {total_fn:>4} {overall_adr:>7.1f}% {total_tier1:>7} {total_tier2:>7}")
    print()

    # Print detailed trace for one scenario of each type
    print("\n" + "=" * 70)
    print("SAMPLE TRACES (one per pattern)")
    print("=" * 70)

    seen_patterns = set()
    for result in detailed_results:
        if result["pattern"] not in seen_patterns:
            seen_patterns.add(result["pattern"])
            print(f"\n--- {result['pattern']} (Detected: {result['detected']}, Tier: {result['tier_used']}) ---")
            for d in result["decisions"]:
                print(f"  {d['request']}")
                print(f"    -> {d['decision']} [Tier-{d['tier']}] {d['reason'][:60]}...")

    # Save results
    output = {
        "by_pattern": dict(results_by_pattern),
        "totals": {
            "tp": total_tp,
            "fn": total_fn,
            "adr": overall_adr,
            "tier1_decisions": total_tier1,
            "tier2_decisions": total_tier2
        },
        "detailed": detailed_results
    }

    output_file = Path(__file__).parent / "results" / "taxonomy_eval_results.json"
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    run_evaluation()
