#!/usr/bin/env python3
"""
Wilson Confidence Interval Calculator

Calculates Wilson score 95% confidence intervals for all paper tables.
Addresses reviewer concern: "Every '100%' on tiny n in this paper needs its Wilson bound shown"
"""

import math

def wilson_ci(successes: int, n: int, confidence: float = 0.95) -> tuple:
    """
    Calculate Wilson score confidence interval.

    The Wilson score interval provides accurate coverage even for
    small sample sizes and extreme proportions (near 0% or 100%).

    Reference: Wilson, E.B. (1927). Probable Inference, the Law of
    Succession, and Statistical Inference. JASA, 22(158), 209-212.
    """
    if n == 0:
        return (0.0, 100.0)

    z = 1.96 if confidence == 0.95 else 2.576  # 95% or 99%
    p_hat = successes / n

    denominator = 1 + z**2 / n
    center = (p_hat + z**2 / (2*n)) / denominator
    margin = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4*n)) / n) / denominator

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return (lower * 100, upper * 100)


def format_ci(successes: int, n: int) -> str:
    """Format result with CI for paper."""
    pct = successes / n * 100 if n > 0 else 0
    lower, upper = wilson_ci(successes, n)
    return f"{pct:.1f}% ({lower:.1f}-{upper:.1f}%)"


def main():
    print("="*70)
    print("WILSON CONFIDENCE INTERVALS FOR ALL PAPER TABLES")
    print("="*70)

    # Table IV: Taxonomy pattern evaluation (30/30)
    print("\n## Table IV: Taxonomy Evasion Patterns")
    print("-" * 50)
    patterns = [
        ("Escalation Evasion", 5, 5),
        ("Research-to-Attack", 5, 5),
        ("Data Exfiltration", 5, 5),
        ("Credential Harvesting", 5, 5),
        ("Boundary Probing", 5, 5),
        ("Beaconing", 5, 5),
    ]
    for name, tp, total in patterns:
        ci = format_ci(tp, total)
        print(f"  {name}: {ci}, n={total}")
    print(f"  Total: {format_ci(30, 30)}, n=30")

    # Table V (line 611): Adaptive adversary evaluation
    print("\n## Table V: Adaptive Adversary Detection")
    print("-" * 50)
    print(f"  Adaptive evasion ADR: {format_ci(5, 5)}, n=5")
    print(f"  Adaptive evasion FPR: {format_ci(0, 1)}, n=1")
    print(f"  AgentDojo externalized ADR: {format_ci(6, 6)}, n=6")
    print(f"  Benign controls FPR: {format_ci(0, 6)}, n=6")
    print(f"  Overall ADR: {format_ci(11, 11)}, n=11")
    print(f"  Overall FPR: {format_ci(0, 7)}, n=7")

    # Table VI (line 703): Externalized AgentDojo
    print("\n## Table VI: Externalized AgentDojo Attacks")
    print("-" * 50)
    suites = [
        ("Banking (external)", 2, 2),
        ("Slack (external)", 2, 2),
        ("Workspace (external)", 2, 2),
        ("Travel (external)", 2, 2),
    ]
    for name, tp, total in suites:
        ci = format_ci(tp, total)
        print(f"  {name}: {ci}, n={total}")
    print(f"  Total attacks: {format_ci(8, 8)}, n=8")
    print(f"  Benign FPR: {format_ci(0, 3)}, n=3")

    # Table VII: InjecAgent evaluation (already has CIs)
    print("\n## Table VII: InjecAgent Evaluation (already in paper)")
    print("-" * 50)
    print(f"  Dev set ADR: {format_ci(272, 272)}, n=272")
    print(f"  Dev set FPR: {format_ci(1, 22)}, n=22")
    print(f"  Test set ADR: {format_ci(272, 272)}, n=272")
    print(f"  Test set FPR: {format_ci(0, 22)}, n=22")

    # Summary for paper edits
    print("\n" + "="*70)
    print("LATEX SNIPPETS FOR PAPER")
    print("="*70)

    print("\n% Table IV - Add CI column or modify ADR column")
    print("% Current: 100%  -> Change to: 100\\% (83.2-100.0\\%)")
    print("% For 5/5 pattern: 100.0% (56.6-100.0%)")
    print("% For 30/30 total: 100.0% (88.7-100.0%)")

    print("\n% Table V - Modify to include CIs")
    print("% 5/5 attacks: 100\\% (56.6-100.0\\%)")
    print("% 6/6 attacks: 100\\% (61.0-100.0\\%)")
    print("% 0/7 benign: 0\\% (0.0-35.4\\%)")
    print("% 11/11 overall: 100\\% (74.1-100.0\\%)")

    print("\n% Table VI - Modify to include CIs")
    print("% 8/8 attacks: 100\\% (67.6-100.0\\%)")
    print("% 0/3 benign: 0\\% (0.0-56.1\\%)")

    print("\n% Key insight: All these wide CIs confirm reviewer's point")
    print("% that tiny-n tables need honest bounds.")


if __name__ == "__main__":
    main()
