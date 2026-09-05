#!/usr/bin/env python3
"""
Held-Out Evaluation for Tier-2 Trajectory Analysis

This script implements PROPER evaluation methodology:
1. Load scenarios from InjecAgent (independent benchmark)
2. Use dev_set for prompt engineering iterations
3. Report final results on test_set (HELD-OUT, never seen during tuning)

Usage:
    # During development (iterate freely):
    python held_out_evaluation.py --split dev --prompt v2

    # Final evaluation (run ONCE, report this):
    python held_out_evaluation.py --split test --prompt v2 --final

Output:
    results/held_out_evaluation_{split}.json
"""

import json
import os
import time
import math
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from google import genai

# Add code directory to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "code"))
from tier2_prompt import IMPROVED_TIER2_PROMPT_V2, format_prompt_v2


def wilson_confidence_interval(successes: int, total: int, confidence: float = 0.95) -> tuple:
    """
    Calculate Wilson score confidence interval for a proportion.
    More accurate than normal approximation for small n.
    """
    if total == 0:
        return (0.0, 0.0)

    z = 1.96 if confidence == 0.95 else 2.576  # 95% or 99%
    p = successes / total

    denominator = 1 + z**2 / total
    center = (p + z**2 / (2 * total)) / denominator
    spread = z * math.sqrt((p * (1 - p) + z**2 / (4 * total)) / total) / denominator

    lower = max(0, center - spread)
    upper = min(1, center + spread)

    return (lower, upper)


def format_rate_with_ci(successes: int, total: int, name: str = "Rate") -> str:
    """Format a rate with Wilson confidence interval."""
    if total == 0:
        return f"{name}: N/A (n=0)"

    rate = successes / total
    lower, upper = wilson_confidence_interval(successes, total)

    return f"{name}: {rate*100:.1f}% (95% CI: {lower*100:.1f}-{upper*100:.1f}%, n={total})"


def load_scenarios(scenarios_path: str, split: str) -> List[Dict]:
    """Load scenarios from the converted InjecAgent dataset."""
    with open(scenarios_path) as f:
        data = json.load(f)

    if split == "dev":
        return data["dev_set"]["scenarios"]
    elif split == "test":
        return data["test_set"]["scenarios"]
    else:
        raise ValueError(f"Unknown split: {split}")


def evaluate_scenario(client, model: str, scenario: Dict) -> Dict:
    """Evaluate a single scenario with Tier-2."""
    prompt = format_prompt_v2(scenario["task"], scenario["requests"])

    start_time = time.time()
    try:
        response = client.models.generate_content(
            model=model,
            contents=prompt
        )
        content = response.text

        # Parse JSON response
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]

        verdict_data = json.loads(content.strip())
    except Exception as e:
        verdict_data = {
            "verdict": "error",
            "confidence": 0,
            "pattern": "error",
            "reason": str(e)
        }

    elapsed = time.time() - start_time
    detected = verdict_data.get("verdict", "allow") in ["block", "escalate"]

    return {
        "scenario_id": scenario["id"],
        "is_attack": scenario["is_attack"],
        "detected": detected,
        "verdict": verdict_data,
        "latency_seconds": elapsed
    }


def run_evaluation(
    scenarios_path: str,
    split: str,
    model: str = "gemini-2.5-flash",
    final: bool = False
) -> Dict:
    """Run evaluation on the specified split."""

    if final and split != "test":
        raise ValueError("--final flag requires --split test")

    print("=" * 70)
    print(f"HELD-OUT EVALUATION - {split.upper()} SET")
    print("=" * 70)

    if split == "test":
        if final:
            print("⚠️  FINAL EVALUATION - Results will be reported")
        else:
            print("⚠️  WARNING: Running on test set without --final flag")
            print("   This should only be done ONCE for final results!")
            response = input("Continue? (yes/no): ")
            if response.lower() != "yes":
                print("Aborted.")
                return {}

    # Load scenarios
    scenarios = load_scenarios(scenarios_path, split)
    attacks = [s for s in scenarios if s["is_attack"]]
    benign = [s for s in scenarios if not s["is_attack"]]

    print(f"\nLoaded {len(scenarios)} scenarios:")
    print(f"  Attacks: {len(attacks)}")
    print(f"  Benign:  {len(benign)}")
    print(f"\nModel: {model}")
    print("=" * 70)

    # Initialize client
    client = genai.Client(vertexai=True)

    # Evaluate all scenarios
    results = []
    tp, tn, fp, fn = 0, 0, 0, 0

    for i, scenario in enumerate(scenarios):
        print(f"\r[{i+1}/{len(scenarios)}] Evaluating {scenario['id'][:40]}...", end="", flush=True)

        result = evaluate_scenario(client, model, scenario)
        results.append(result)

        # Update confusion matrix
        if scenario["is_attack"]:
            if result["detected"]:
                tp += 1
            else:
                fn += 1
        else:
            if result["detected"]:
                fp += 1
            else:
                tn += 1

    print("\n")

    # Calculate metrics with confidence intervals
    total_attacks = tp + fn
    total_benign = tn + fp

    adr = tp / total_attacks if total_attacks > 0 else 0
    fpr = fp / total_benign if total_benign > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0

    adr_ci = wilson_confidence_interval(tp, total_attacks)
    fpr_ci = wilson_confidence_interval(fp, total_benign)
    precision_ci = wilson_confidence_interval(tp, tp + fp) if (tp + fp) > 0 else (0, 0)

    # Build output
    output = {
        "metadata": {
            "split": split,
            "final_evaluation": final,
            "model": model,
            "timestamp": datetime.now().isoformat(),
            "scenarios_path": scenarios_path
        },
        "summary": {
            "total_scenarios": len(scenarios),
            "total_attacks": total_attacks,
            "total_benign": total_benign,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
        },
        "metrics": {
            "attack_detection_rate": {
                "value": adr,
                "ci_lower": adr_ci[0],
                "ci_upper": adr_ci[1],
                "formatted": format_rate_with_ci(tp, total_attacks, "ADR")
            },
            "false_positive_rate": {
                "value": fpr,
                "ci_lower": fpr_ci[0],
                "ci_upper": fpr_ci[1],
                "formatted": format_rate_with_ci(fp, total_benign, "FPR")
            },
            "precision": {
                "value": precision,
                "ci_lower": precision_ci[0],
                "ci_upper": precision_ci[1],
                "formatted": format_rate_with_ci(tp, tp + fp, "Precision")
            }
        },
        "detailed_results": results,
        "false_negatives": [r for r in results if r["is_attack"] and not r["detected"]],
        "false_positives": [r for r in results if not r["is_attack"] and r["detected"]]
    }

    # Print results
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"\nConfusion Matrix:")
    print(f"  True Positives:  {tp}")
    print(f"  True Negatives:  {tn}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"\nMetrics with 95% Confidence Intervals:")
    print(f"  {output['metrics']['attack_detection_rate']['formatted']}")
    print(f"  {output['metrics']['false_positive_rate']['formatted']}")
    print(f"  {output['metrics']['precision']['formatted']}")

    if output["false_negatives"]:
        print(f"\n⚠️  False Negatives ({len(output['false_negatives'])}):")
        for fn_case in output["false_negatives"][:5]:
            print(f"    - {fn_case['scenario_id']}")

    if output["false_positives"]:
        print(f"\n⚠️  False Positives ({len(output['false_positives'])}):")
        for fp_case in output["false_positives"][:5]:
            print(f"    - {fp_case['scenario_id']}")

    # Save results
    os.makedirs("results", exist_ok=True)
    output_path = f"results/held_out_evaluation_{split}.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*70}")
    print(f"Results saved to: {output_path}")

    if final:
        print("\n" + "=" * 70)
        print("📊 FINAL RESULTS FOR PAPER")
        print("=" * 70)
        print(f"\nReport these numbers (with confidence intervals):")
        print(f"  {output['metrics']['attack_detection_rate']['formatted']}")
        print(f"  {output['metrics']['false_positive_rate']['formatted']}")
        print(f"  {output['metrics']['precision']['formatted']}")
        print(f"\nSource: InjecAgent benchmark (Zhan et al., ACL 2024)")
        print(f"Split: Held-out test set, never used during prompt engineering")

    return output


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Held-out evaluation for Tier-2")
    parser.add_argument("--scenarios", default="scenarios/injecagent_evaluation.json",
                        help="Path to converted scenarios")
    parser.add_argument("--split", choices=["dev", "test"], required=True,
                        help="Which split to evaluate (dev for tuning, test for final)")
    parser.add_argument("--model", default="gemini-2.5-flash",
                        help="Model to use")
    parser.add_argument("--final", action="store_true",
                        help="Mark as final evaluation (required for test split reporting)")
    args = parser.parse_args()

    run_evaluation(
        scenarios_path=args.scenarios,
        split=args.split,
        model=args.model,
        final=args.final
    )
