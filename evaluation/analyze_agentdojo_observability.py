#!/usr/bin/env python3
"""
How much of AgentDojo is observable at the network layer?

Paper Section VI-C. No LLM calls -- this is a counting argument over the
converted scenarios.

The paper reports 10.7% ADR on AgentDojo and attributes the ceiling to attacks
that abuse legitimate internal APIs. This script measures that directly: of the
233 attack scenarios, how many leave *any* artifact a network monitor could key
on, regardless of detector quality?

An attack is "network-observable" if some request carries a known attacker
destination in its path or arguments. Those constants come from AgentDojo's own
injection tasks, not from our detector.

    python evaluation/analyze_agentdojo_observability.py \
        --scenarios /path/to/agentdojo_scenarios.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from evaluation.wilson_ci import wilson_ci  # noqa: E402

# Attacker constants defined by AgentDojo's injection tasks, in
# default_suites/v1/*/injection_tasks.py. Only the banking IBAN survives the
# tool-call -> HTTP conversion into an observable position; the others are
# listed so the check is honest about what it looks for.
ATTACKER_CONSTANTS = [
    "US133000000121212121212",      # banking  _ATTACKER_IBAN
    "www.secure-systems-252.com",   # slack    _PHISHING_LINK
    "www.my-website-234.com",       # slack    _ATTACKER_WEB
    "www.true-informations.com",    # slack    _PHISHING_LINK
    "jay@google.com",               # travel   attacker recipient
    "mark.black-2134@gmail.com",    # workspace _RECIPIENT
    "lily.white@gmail.com",         # workspace _SENDER
]


def observable(scn: dict) -> list[str]:
    """Attacker constants visible anywhere in this scenario's requests."""
    hits = set()
    for r in scn.get("requests", []):
        blob = (r.get("path", "") + " " + str(r.get("args", ""))).lower()
        for c in ATTACKER_CONSTANTS:
            if c.lower() in blob:
                hits.add(c)
    return sorted(hits)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("agentdojo_observability.json"))
    a = ap.parse_args()

    data = json.loads(a.scenarios.read_text())
    attacks = [s for s in data if s.get("expected_label") == "attack"]
    benign = [s for s in data if s.get("expected_label") == "benign"]

    obs = [s for s in attacks if observable(s)]
    unobs = [s for s in attacks if not observable(s)]

    # What Tier-1 actually fires on. The difference between this and the
    # observable set is the part of the ceiling our blocklist fails to reach.
    esc = [s for s in attacks
           if any(r.get("status") == "ESCALATE" for r in s.get("requests", []))]
    esc_ids = {s["id"] for s in esc}
    gap = [s for s in obs if s["id"] not in esc_ids]

    hosts = Counter(r["host"] for s in data for r in s.get("requests", []))
    lo, hi = wilson_ci(len(obs), len(attacks))

    print("=" * 68)
    print("AGENTDOJO NETWORK OBSERVABILITY")
    print("=" * 68)
    print(f"\nscenarios: {len(data)}  ({len(attacks)} attack, {len(benign)} benign)")
    print(f"\nattacks carrying a network-observable attacker artifact:")
    print(f"  {len(obs)}/{len(attacks)} = {len(obs)/len(attacks)*100:.1f}%  "
          f"(95% CI {lo:.1f}-{hi:.1f})")
    print(f"\nattacks with NO observable artifact: {len(unobs)}")
    print(f"  by attack type: {dict(Counter(s.get('attack_type') for s in unobs))}")
    print(f"  by suite:       {dict(Counter(s.get('suite') for s in unobs))}")

    print(f"\nwhich attacker constants actually survive conversion:")
    found = Counter(c for s in attacks for c in observable(s))
    for c in ATTACKER_CONSTANTS:
        n = found.get(c, 0)
        print(f"  {'YES' if n else ' no'}  {c:<30} {n:>3} scenarios")

    print(f"\nhosts in the corpus (all internal by construction):")
    for h, n in hosts.most_common():
        print(f"  {h:<28} {n:>5} requests")

    print(f"\nceiling vs achieved:")
    print(f"  observable in principle : {len(obs)}/{len(attacks)} = {len(obs)/len(attacks)*100:.1f}%")
    print(f"  detected by Tier-1      : {len(esc)}/{len(attacks)} = {len(esc)/len(attacks)*100:.1f}%")
    print(f"  gap                     : {len(gap)} scenario(s)")
    for g in gap:
        seen = ", ".join(observable(g))
        print(f"     {g['id']}  [{g.get('suite')}]  {seen}")
    if gap:
        print("  These carry an observable attacker destination that is absent from")
        print("  the Tier-1 blocklist -- reachable with updated threat intelligence.")

    print("\n" + "-" * 68)
    print("INTERPRETATION")
    print("-" * 68)
    print(f"""
{len(unobs)} of {len(attacks)} AgentDojo attacks produce no request distinguishable
from correct execution of the benign task. They are labelled attacks because the
injection succeeded in AgentDojo's reference run -- a provenance label with no
network correlate.

The {len(obs)/len(attacks)*100:.1f}% ceiling on this benchmark is therefore a property of the
benchmark, not a limit of the detector. No network-layer defense, however good,
can exceed it. Tier-1 reaches {len(esc)/len(attacks)*100:.1f}%; the remaining {len(gap)} scenario(s) are
observable but use destinations absent from our blocklist.
""")

    a.out.write_text(json.dumps({
        "n_scenarios": len(data), "n_attacks": len(attacks), "n_benign": len(benign),
        "observable": len(obs), "unobservable": len(unobs),
        "observable_pct": len(obs) / len(attacks) * 100,
        "observable_ci": [lo, hi],
        "observable_ids": [s["id"] for s in obs],
        "unobservable_by_type": dict(Counter(s.get("attack_type") for s in unobs)),
        "unobservable_by_suite": dict(Counter(s.get("suite") for s in unobs)),
        "constants_found": dict(found),
        "hosts": dict(hosts),
        "tier1_detected": len(esc),
        "gap_ids": [g["id"] for g in gap],
    }, indent=2))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
