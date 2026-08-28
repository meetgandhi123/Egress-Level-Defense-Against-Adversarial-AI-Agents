# Reproducing Paper Results

This guide explains how to reproduce the main results from the paper.

## Table I: Detection Performance (Combined Benchmark)

```bash
# Run full evaluation harness
python evaluation/harness.py --benchmark all --output results/table1.json

# Expected output:
# - ADR: 20.9%
# - FPR: 0%
# - Utility: 99.8%
# - Scenarios: 6,059
```

**Runtime:** ~30 minutes (mostly Tier-2 LLM calls)

## Table IV: Taxonomy Pattern Evaluation

```bash
# Run taxonomy-specific evaluation
python evaluation/eval_taxonomy.py

# Expected output:
# - 30/30 scenarios detected (100% ADR)
# - 83% Tier-2 trigger rate
# - Per-pattern breakdown in results/taxonomy_eval_results.json
```

**Runtime:** ~5 minutes

## Table II: Comparison with Related Work

The comparison table uses published results from:
- CaMeL: 0% ASR, 67-77% utility (from original paper)
- Progent: 1-4% ASR, 82-92% utility (from original paper)

Our results (AgentDojo only):
```bash
python evaluation/harness.py --benchmark agentdojo --output results/agentdojo.json

# Expected: 10.7% ADR on 233 attack scenarios
```

## Tier-2 Ablation (Section VI-F)

```bash
# Run with Tier-1 only (disable LLM)
python evaluation/eval_taxonomy.py --tier1-only

# Expected: 5/30 detected (17%)
# Confirms Tier-2 provides 83% of detection capability
```

## Latency Measurements (Section VI-G)

```bash
python evaluation/harness.py --benchmark all --measure-latency

# Expected:
# - Tier-1 median: 0.01ms
# - Tier-2 median: 2-5 seconds
# - Tier-2 trigger rate: 0.03% on benchmarks
```

## Notes

1. **API Costs**: Full evaluation requires ~$5-10 in Anthropic API credits
2. **Variance**: Tier-2 LLM responses may have slight variance; results should be within ±2%
3. **Hardware**: Tested on M1 MacBook Pro; Tier-1 latency may vary on different hardware
