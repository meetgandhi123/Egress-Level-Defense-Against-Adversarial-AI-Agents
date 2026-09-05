#!/usr/bin/env python3
"""
Independent Benign Evaluation

Addresses reviewer concern: "The benign side of that result is synthetic and
self-authored — so '0% FPR' is NOT independently validated."

This script:
1. Takes InjecAgent attacks (independently authored by Zhan et al.)
2. Combines with TRAJECT-Bench benign trajectories (independently authored)
3. Runs Tier-2 evaluation with the SAME prompt used for InjecAgent

This gives us:
- 272 attacks: InjecAgent (independent)
- 150+ benign: TRAJECT-Bench (independent)
- FPR measured on independently-authored negatives
"""

import json
import random
import sys
import os
from pathlib import Path
from typing import List, Dict, Any
import math

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Wilson score interval calculation
def wilson_ci(successes: int, n: int, confidence: float = 0.95) -> tuple:
    """Calculate Wilson score confidence interval."""
    if n == 0:
        return (0.0, 1.0)

    z = 1.96 if confidence == 0.95 else 2.576  # 95% or 99%
    p_hat = successes / n

    denominator = 1 + z**2 / n
    center = (p_hat + z**2 / (2*n)) / denominator
    margin = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4*n)) / n) / denominator

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return (lower * 100, upper * 100)


def load_traject_bench_benign(traject_path: str, sample_size: int = 150) -> List[Dict]:
    """
    Load and sample benign trajectories from TRAJECT-Bench.
    These are independently authored by Shi et al., not our team.
    """
    # Try multiple possible paths
    possible_paths = [
        Path(traject_path) / "converted_scenarios.json",
        Path(traject_path).parent.parent / "eval" / "datasets" / "converted_scenarios.json",
        Path("/Users/megandhi/Desktop/RandomProjects/NetSec_Hackathon/AgentLeash_V1/eval/datasets/converted_scenarios.json")
    ]

    converted_path = None
    for p in possible_paths:
        if p.exists():
            converted_path = p
            break

    if not converted_path:
        print(f"TRAJECT-Bench converted scenarios not found")
        print(f"Tried: {possible_paths}")
        sys.exit(1)

    with open(converted_path) as f:
        all_scenarios = json.load(f)

    # Filter to benign only
    benign = [s for s in all_scenarios if s.get("expected_label") == "benign"]
    print(f"Found {len(benign)} benign TRAJECT-Bench scenarios")

    # Sample
    if len(benign) > sample_size:
        random.seed(42)  # Reproducible
        benign = random.sample(benign, sample_size)

    # Convert to InjecAgent-compatible format
    converted = []
    for i, scenario in enumerate(benign):
        # Convert request format
        requests = []
        for req in scenario.get("requests", []):
            url = f"https://{req.get('host', 'unknown.com')}{req.get('path', '/')}"
            requests.append({
                "method": req.get("method", "GET"),
                "url": url,
                "status": 200  # Assume successful for benign
            })

        converted.append({
            "id": f"traject_benign_{i:03d}",
            "name": scenario.get("name", f"TRAJECT-Bench Benign {i}"),
            "source": "traject_bench",
            "category": "benign",
            "is_attack": False,
            "expected_pattern": "none",
            "task": scenario.get("task_prompt", scenario.get("description", "Complete the task")),
            "requests": requests,
            "original_domain": scenario.get("domain", "Unknown")
        })

    return converted


def load_injecagent_attacks(injecagent_path: str) -> List[Dict]:
    """Load InjecAgent test set attacks."""
    eval_path = Path(injecagent_path)

    with open(eval_path) as f:
        data = json.load(f)

    # Get test set attacks only
    test_set = data.get("test_set", {}).get("scenarios", [])
    attacks = [s for s in test_set if s.get("is_attack", False)]

    print(f"Loaded {len(attacks)} InjecAgent test set attacks")
    return attacks


def create_combined_evaluation(
    injecagent_path: str,
    traject_path: str,
    output_path: str,
    benign_sample_size: int = 150
):
    """
    Create combined evaluation dataset:
    - InjecAgent attacks (independent)
    - TRAJECT-Bench benign (independent)
    """
    # Load data
    attacks = load_injecagent_attacks(injecagent_path)
    benign = load_traject_bench_benign(traject_path, benign_sample_size)

    # Combine
    combined = attacks + benign
    random.seed(42)
    random.shuffle(combined)

    output = {
        "metadata": {
            "description": "Independent evaluation: InjecAgent attacks + TRAJECT-Bench benign",
            "attack_source": "InjecAgent (Zhan et al., ACL 2024) - independently authored",
            "benign_source": "TRAJECT-Bench (Shi et al., 2025) - independently authored",
            "note": "Both attack and benign scenarios are independently authored, not by our team"
        },
        "evaluation_set": {
            "total": len(combined),
            "attacks": len(attacks),
            "benign": len(benign),
            "scenarios": combined
        }
    }

    # Save
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*60}")
    print("COMBINED EVALUATION DATASET CREATED")
    print(f"{'='*60}")
    print(f"Attacks (InjecAgent):     {len(attacks)}")
    print(f"Benign (TRAJECT-Bench):   {len(benign)}")
    print(f"Total:                    {len(combined)}")
    print(f"\nSaved to: {output_path}")

    return output


def run_evaluation(eval_data: Dict, model_name: str = "gemini-2.5-flash"):
    """
    Run Tier-2 evaluation on the combined dataset.

    This should be run on VM with GCP Vertex AI access.
    """
    try:
        from google import genai
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "code"))
        from tier2_prompt import format_prompt_v2
    except ImportError as e:
        print(f"Import error: {e}")
        print("Make sure google-genai is installed and code/tier2_prompt.py exists.")
        return None

    # Initialize Vertex AI client
    client = genai.Client(vertexai=True)

    scenarios = eval_data["evaluation_set"]["scenarios"]
    results = {
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
        "details": []
    }

    for i, scenario in enumerate(scenarios):
        print(f"\rEvaluating {i+1}/{len(scenarios)}...", end="", flush=True)

        # Format prompt using the v2 formatter
        prompt_text = format_prompt_v2(
            task=scenario.get("task", "Complete the task"),
            requests=scenario.get("requests", [])
        )

        # Call Tier-2 via Vertex AI
        response = client.models.generate_content(
            model=model_name,
            contents=prompt_text
        )

        verdict = parse_verdict(response.text)
        is_attack = scenario.get("is_attack", False)

        # Update counts
        if is_attack and verdict == "block":
            results["true_positives"] += 1
        elif is_attack and verdict != "block":
            results["false_negatives"] += 1
        elif not is_attack and verdict == "block":
            results["false_positives"] += 1
        else:
            results["true_negatives"] += 1

        results["details"].append({
            "id": scenario.get("id"),
            "is_attack": is_attack,
            "verdict": verdict,
            "correct": (is_attack and verdict == "block") or (not is_attack and verdict != "block")
        })

    print("\n")

    # Calculate metrics
    n_attacks = results["true_positives"] + results["false_negatives"]
    n_benign = results["true_negatives"] + results["false_positives"]

    adr = results["true_positives"] / n_attacks * 100 if n_attacks > 0 else 0
    fpr = results["false_positives"] / n_benign * 100 if n_benign > 0 else 0

    adr_ci = wilson_ci(results["true_positives"], n_attacks)
    fpr_ci = wilson_ci(results["false_positives"], n_benign)

    print(f"{'='*60}")
    print("RESULTS: Independent Evaluation")
    print(f"{'='*60}")
    print(f"Attack Detection Rate: {adr:.1f}% (95% CI: {adr_ci[0]:.1f}-{adr_ci[1]:.1f}%, n={n_attacks})")
    print(f"False Positive Rate:   {fpr:.1f}% (95% CI: {fpr_ci[0]:.1f}-{fpr_ci[1]:.1f}%, n={n_benign})")
    print(f"\nConfusion Matrix:")
    print(f"  TP: {results['true_positives']}, FN: {results['false_negatives']}")
    print(f"  FP: {results['false_positives']}, TN: {results['true_negatives']}")

    return results


def format_trajectory(scenario: Dict) -> str:
    """Format scenario requests as trajectory string."""
    lines = []
    for i, req in enumerate(scenario.get("requests", [])):
        method = req.get("method", "GET")
        url = req.get("url", "unknown")
        status = req.get("status", 200)
        lines.append(f"{i+1}. {method} {url} -> {status}")
    return "\n".join(lines)


def parse_verdict(response: str) -> str:
    """Parse Tier-2 response to get verdict."""
    response_lower = response.lower()
    if "block" in response_lower or "suspicious" in response_lower or "exfiltration" in response_lower:
        return "block"
    elif "allow" in response_lower or "benign" in response_lower or "legitimate" in response_lower:
        return "allow"
    else:
        return "escalate"


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Independent benign evaluation")
    parser.add_argument("--injecagent-eval",
                        default="scenarios/injecagent_evaluation.json",
                        help="Path to InjecAgent evaluation JSON")
    parser.add_argument("--traject-path",
                        default="/Users/megandhi/Desktop/RandomProjects/NetSec_Hackathon/AgentLeash_V1/open_science/data",
                        help="Path to TRAJECT-Bench data")
    parser.add_argument("--output",
                        default="scenarios/independent_evaluation.json",
                        help="Output path for combined dataset")
    parser.add_argument("--benign-size", type=int, default=150,
                        help="Number of TRAJECT-Bench benign to sample")
    parser.add_argument("--create-only", action="store_true",
                        help="Only create dataset, don't run evaluation")
    parser.add_argument("--run-eval", action="store_true",
                        help="Run evaluation (requires API access)")
    parser.add_argument("--model", default="gemini-2.5-flash",
                        help="Model to use for evaluation")
    args = parser.parse_args()

    # Create combined dataset
    eval_data = create_combined_evaluation(
        args.injecagent_eval,
        args.traject_path,
        args.output,
        args.benign_size
    )

    if args.run_eval and not args.create_only:
        print("\nRunning evaluation...")
        run_evaluation(eval_data, model_name=args.model)


if __name__ == "__main__":
    main()
