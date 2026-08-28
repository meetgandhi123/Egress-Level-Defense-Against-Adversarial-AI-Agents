"""
Main evaluation harness.
Runs scenarios against baselines and collects metrics.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime

from scenarios.scenario_definitions import (
    ALL_SCENARIOS,
    ATTACK_SCENARIOS,
    BENIGN_SCENARIOS,
    Scenario,
    get_scenario_by_id,
)
from scenarios.traject_bench_scenarios import (
    get_all_scenarios as get_traject_scenarios,
    get_benign_scenarios as get_traject_benign,
    get_attack_scenarios as get_traject_attacks,
)
from scenarios.agentdojo_scenarios import (
    get_all_scenarios as get_agentdojo_scenarios,
    get_benign_scenarios as get_agentdojo_benign,
    get_attack_scenarios as get_agentdojo_attacks,
)
from baselines import (
    BaselineDefense,
    NoDefense,
    StaticAllowlist,
    SingleActionPolicy,
    TrajectoryAwareDefense,
)
from baselines.base import NetworkRequest, DefenseDecision
from metrics import MetricsCollector, ScenarioMetric, RequestMetric, LatencyTimer


def create_network_request(scenario_req) -> NetworkRequest:
    """Convert scenario request to baseline NetworkRequest."""
    return NetworkRequest(
        method=scenario_req.method,
        url=scenario_req.url,
        headers=scenario_req.headers,
        body=scenario_req.body,
    )


def run_scenario(
    scenario: Scenario,
    defense: BaselineDefense,
    run_id: int,
    collector: MetricsCollector,
    verbose: bool = False,
) -> ScenarioMetric:
    """Run a single scenario against a defense baseline."""

    if verbose:
        print(f"  Running: {scenario.name} with {defense.name} (run {run_id})")

    # Reset defense state for new scenario
    defense.reset(task_context=scenario.task_prompt)

    # Track per-request metrics
    requests_allowed = 0
    requests_blocked = 0
    requests_escalated = 0
    tier1_calls = 0
    tier2_calls = 0
    tier1_latencies = []
    tier2_latencies = []
    total_latency = 0.0

    for i, req in enumerate(scenario.requests):
        net_req = create_network_request(req)
        result = defense.evaluate(net_req)

        # Collect request metric
        req_metric = RequestMetric(
            scenario_id=scenario.id,
            request_index=i,
            url=req.url,
            method=req.method,
            expected_decision=req.expected_decision,
            actual_decision=result.decision.value,
            tier_used=result.tier_used,
            decision_latency_ms=result.latency_ms,
        )
        collector.record_request(req_metric)

        # Aggregate stats
        total_latency += result.latency_ms

        if result.tier_used == 1:
            tier1_calls += 1
            tier1_latencies.append(result.latency_ms)
        else:
            tier2_calls += 1
            tier2_latencies.append(result.latency_ms)

        if result.decision == DefenseDecision.ALLOW:
            requests_allowed += 1
        elif result.decision == DefenseDecision.BLOCK:
            requests_blocked += 1
        elif result.decision == DefenseDecision.ESCALATE:
            requests_escalated += 1

        if verbose:
            print(f"    [{i+1}/{len(scenario.requests)}] {req.method} {req.url[:50]}... "
                  f"-> {result.decision.value} (Tier-{result.tier_used}, {result.latency_ms:.1f}ms)")

    # Determine overall scenario detection
    detected_as_attack = defense.should_escalate_scenario()

    # Compute detection result
    detection_result = collector.compute_detection_result(
        ground_truth=scenario.ground_truth.value,
        detected_as_attack=detected_as_attack,
    )

    # For task completion: assume task completes if not all requests blocked
    task_completed = requests_allowed > 0

    scenario_metric = ScenarioMetric(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        ground_truth=scenario.ground_truth.value,
        baseline_name=defense.name,
        run_id=run_id,
        detected_as_attack=detected_as_attack,
        detection_result=detection_result,
        total_requests=len(scenario.requests),
        requests_allowed=requests_allowed,
        requests_blocked=requests_blocked,
        requests_escalated=requests_escalated,
        total_latency_ms=total_latency,
        tier1_calls=tier1_calls,
        tier2_calls=tier2_calls,
        avg_tier1_latency_ms=sum(tier1_latencies) / len(tier1_latencies) if tier1_latencies else 0,
        avg_tier2_latency_ms=sum(tier2_latencies) / len(tier2_latencies) if tier2_latencies else 0,
        task_completed=task_completed,
    )

    collector.record_scenario(scenario_metric)

    if verbose:
        print(f"    Result: {detection_result} (detected_as_attack={detected_as_attack})")

    return scenario_metric


def run_evaluation(
    scenarios: List[Scenario],
    baselines: List[BaselineDefense],
    runs_per_scenario: int = 5,
    verbose: bool = False,
) -> MetricsCollector:
    """Run full evaluation across scenarios and baselines."""

    collector = MetricsCollector(
        results_dir=str(Path(__file__).parent / "results")
    )

    total = len(scenarios) * len(baselines) * runs_per_scenario
    current = 0

    print(f"\nRunning evaluation: {len(scenarios)} scenarios × {len(baselines)} baselines × {runs_per_scenario} runs = {total} experiments\n")

    for baseline in baselines:
        print(f"\n{'='*60}")
        print(f"Baseline: {baseline.name}")
        print(f"{'='*60}")

        for scenario in scenarios:
            for run_id in range(1, runs_per_scenario + 1):
                current += 1
                if not verbose:
                    print(f"\r  Progress: {current}/{total} ({100*current/total:.0f}%)", end="", flush=True)

                run_scenario(
                    scenario=scenario,
                    defense=baseline,
                    run_id=run_id,
                    collector=collector,
                    verbose=verbose,
                )

        if not verbose:
            print()  # Newline after progress

    return collector


def main():
    parser = argparse.ArgumentParser(description="Run AgentLeash evaluation")
    parser.add_argument(
        "--scenarios",
        choices=["all", "attack", "benign"],
        default="all",
        help="Which scenarios to run",
    )
    parser.add_argument(
        "--baselines",
        nargs="+",
        choices=["no_defense", "static_allowlist", "single_action", "trajectory_aware", "all"],
        default=["all"],
        help="Which baselines to evaluate",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of runs per scenario (default: 3)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--scenario-id",
        type=str,
        help="Run specific scenario by ID",
    )
    parser.add_argument(
        "--save",
        type=str,
        default="eval_run",
        help="Experiment name for saved results",
    )
    parser.add_argument(
        "--extended",
        action="store_true",
        help="Use extended TRAJECT-Bench scenarios (72 scenarios instead of 9)",
    )
    parser.add_argument(
        "--agentdojo",
        action="store_true",
        help="Use AgentDojo scenarios (359 scenarios: 233 attacks, 126 benign)",
    )
    parser.add_argument(
        "--combined",
        action="store_true",
        help="Use combined TRAJECT-Bench + AgentDojo scenarios (431 total)",
    )

    args = parser.parse_args()

    # Select scenarios
    if args.scenario_id:
        scenario = get_scenario_by_id(args.scenario_id)
        if scenario is None:
            print(f"Error: Scenario '{args.scenario_id}' not found")
            sys.exit(1)
        scenarios = [scenario]
    elif args.combined:
        # Use both TRAJECT-Bench and AgentDojo
        if args.scenarios == "attack":
            scenarios = get_traject_attacks() + get_agentdojo_attacks()
        elif args.scenarios == "benign":
            scenarios = get_traject_benign() + get_agentdojo_benign()
        else:
            scenarios = get_traject_scenarios() + get_agentdojo_scenarios()
        print(f"Using combined TRAJECT-Bench + AgentDojo dataset")
    elif args.agentdojo:
        # Use AgentDojo scenarios
        if args.scenarios == "attack":
            scenarios = get_agentdojo_attacks()
        elif args.scenarios == "benign":
            scenarios = get_agentdojo_benign()
        else:
            scenarios = get_agentdojo_scenarios()
        print(f"Using AgentDojo dataset")
    elif args.extended:
        # Use TRAJECT-Bench extended scenarios
        if args.scenarios == "attack":
            scenarios = get_traject_attacks()
        elif args.scenarios == "benign":
            scenarios = get_traject_benign()
        else:
            scenarios = get_traject_scenarios()
        print(f"Using TRAJECT-Bench extended dataset")
    elif args.scenarios == "attack":
        scenarios = ATTACK_SCENARIOS
    elif args.scenarios == "benign":
        scenarios = BENIGN_SCENARIOS
    else:
        scenarios = ALL_SCENARIOS

    # Select baselines
    baseline_map = {
        "no_defense": NoDefense,
        "static_allowlist": StaticAllowlist,
        "single_action": SingleActionPolicy,
        "trajectory_aware": TrajectoryAwareDefense,
    }

    if "all" in args.baselines:
        baselines = [cls() for cls in baseline_map.values()]
    else:
        baselines = [baseline_map[name]() for name in args.baselines]

    # Run evaluation
    print(f"\n{'#'*60}")
    print(f"AgentLeash Evaluation Harness")
    print(f"{'#'*60}")
    print(f"Date: {datetime.utcnow().isoformat()}")
    print(f"Scenarios: {len(scenarios)}")
    print(f"Baselines: {[b.name for b in baselines]}")
    print(f"Runs per scenario: {args.runs}")

    collector = run_evaluation(
        scenarios=scenarios,
        baselines=baselines,
        runs_per_scenario=args.runs,
        verbose=args.verbose,
    )

    # Print summary
    collector.print_summary()

    # Save results
    files = collector.save_results(args.save)
    print(f"\nResults saved to:")
    for name, path in files.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()
