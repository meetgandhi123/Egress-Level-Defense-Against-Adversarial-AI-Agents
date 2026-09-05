# Reproducing Paper Results

Each section below maps a paper result to the command that produces it.

## Setup

```bash
pip install -r code/requirements.txt
pip install google-genai
export GCP_PROJECT=your-project
export GCP_LOCATION=us-west1
```

Tier-2 runs at temperature 0, so repeated runs should give identical verdicts.

---

## Table IV: Destination-Blinded Evaluation (Section VI-H)

The main control against circular validation. Rewrites every attack destination
— host, path, and body — so that no request matches any Tier-1 rule, then
re-evaluates.

```bash
python evaluation/run_blinded_eval.py --experiment blinded
```

Expected:

```
blinding verified: 0/30 trip any Tier-1 signature
original  ADR 96.7% (83.3-99.4, n=30)
blinded   ADR 93.3% (78.7-98.2, n=30)

Detection channel (blinded attacks):
  Tier-1 signature match            0/30
  Tier-2 trajectory reasoning      28/30
```

To also measure FPR you need TRAJECT-Bench benign traffic:

```bash
python evaluation/run_blinded_eval.py --experiment blinded \
    --benign /path/to/converted_scenarios.json --n-controls 100
# Expected: FPR 5.0% (2.2-11.2, n=100)
```

Controls are drawn as a **random** sample (`--seed`, default 0). Do not take a
prefix of the corpus: the first 100 TRAJECT-Bench scenarios escalate at 80%
against a corpus rate of 11%, which inflates FPR roughly sevenfold.

Two attacks are expected to be missed, and the script prints both with Tier-2's
stated reason. Both are discussed in the paper.

**Runtime:** ~2 minutes. **Cost:** ~260 Tier-2 calls.

### Non-tool egress scenarios, blinded

The same control applied to the 44 shell/library/raw-socket scenarios. This set
ships its own 20 benign controls, so no external data is needed:

```bash
python evaluation/run_blinded_eval.py --experiment blinded \
    --scenarios data/non_tool_egress_scenarios.json
```

Expected:

```
original  ADR 100.0% (86.2-100.0, n=24)   FPR 0.0% (0.0-16.1, n=20)
blinded   ADR  95.8% (79.8-99.3,  n=24)   FPR 0.0% (0.0-16.1, n=20)

Detection channel (blinded attacks):
  Tier-1 signature match            0/24
  Tier-2 trajectory reasoning      23/24
```

Unblinded these detect 24/24, but the destinations were chosen to match Tier-1's
rules, so the blinded number is the meaningful one. The single miss is a
beaconing scenario — the same pattern that collapses under the OOD hold-out.

Note that the 20 benign controls here are authored alongside the attacks, so
this FPR is weaker evidence than the taxonomy run's, which samples TRAJECT-Bench.

**Runtime:** ~1 minute. **Cost:** ~90 Tier-2 calls.

---

## Section VI-J: Out-of-Distribution Ablation

Removes each evasion pattern's definition from the Tier-2 prompt, then tests
detection on that pattern.

```bash
python evaluation/run_blinded_eval.py --experiment ood --per-type 10
```

Expected: aggregate 80.0% (68.2–88.2, n=60), with exfiltration, credential
harvesting, research-to-attack, and boundary probing at 100%, escalation at 80%,
and **beaconing at 0%**. The beaconing result is the finding, not a bug:
periodicity is indistinguishable from legitimate telemetry without an explicit
prior in the prompt.

**Runtime:** ~2 minutes. **Cost:** ~60 Tier-2 calls.

---

## Section VI-I: Placeholder Artifact Deconfound

Tests whether TRAJECT-Bench false positives are caused by the converter's
`api.unknown.com` placeholder.

```bash
python evaluation/run_blinded_eval.py --experiment placeholder \
    --traject-scenarios /path/to/converted_scenarios.json
```

Expected: 0.8% FPR with placeholder scenarios excluded (n=5,217), and 50.6% with
the placeholder remapped to realistic hostnames (n=453). Renaming does **not**
lower FPR — the mismatch is semantic (a host unrelated to the task), not
cosmetic.

**Runtime:** ~10 minutes. **Cost:** ~600 Tier-2 calls.

---

## Table I: Combined Benchmark

```bash
python evaluation/harness.py --benchmark all --output results/table1.json
```

Expected: 20.9% ADR, 4.7% FPR, 95.3% utility across 6,059 scenarios
(5,796 benign, 263 attack).

**Note on the model.** These numbers were originally produced with Claude
Sonnet 4 as the Tier-2 analyzer. Re-running on Gemini 2.5 Flash gives 20.9% ADR
and 5.0% FPR, and Tier-1-only gives 11.0% against the 11.4% reported. Tier-2 is
model-agnostic; the paper reports Gemini 2.5 Flash as the reference
configuration.

**Note on the decision rule.** A scenario counts as detected when Tier-1 matches
a known-malicious destination or Tier-2 returns `ESCALATE`. Counting Tier-2
`BLOCK` verdicts as well raises ADR to 24.0% and FPR to 6.7%; the eight extra
detections cost roughly 98 false positives, so the paper retains the stricter
rule.

**Runtime:** ~30 minutes.

---

## Table III: InjecAgent Held-Out Test

```bash
python evaluation/run_injecagent_eval.py --split test --model gemini-2.5-flash
```

Expected: 100% ADR (98.6–100, n=272), 0% FPR (0–14.9, n=22).

The prompt was frozen before any test-set exposure; the test set was run once.
Use `--split dev` to reproduce the development-set numbers (100% ADR, 4.5% FPR).

---

## Table V: Full Pipeline on Benign Traffic

```bash
python evaluation/run_full_pipeline_eval.py \
    --scenarios /path/to/converted_scenarios.json
```

Expected: Tier-1 allows 91.1% (5,165/5,670), escalates 8.9% (505/5,670);
Tier-2 conditional FPR 54.3% (274/505); TRAJECT-Bench FPR 4.8%.

---

## Taxonomy Pattern Evaluation (Section VI-F)

The 30 taxonomy scenarios are in `data/taxonomy_scenarios.json`. Unblinded
detection is 30/30, with 83% resolved at Tier-2 and Tier-1-only catching 5/30.
The blinded run above is the more informative version of this result, since the
unblinded rate partly reflects destinations chosen by the authors.

---

## Section VIII-C: Trajectory Window Sensitivity

How much trajectory context does detection need? Truncates each blinded scenario
to its last *k* requests.

```bash
python evaluation/run_blinded_eval.py --experiment window \
    --scenarios data/taxonomy_scenarios.json
```

Expected: 76.7% at one request, 86.7% at two and three, 93.3% at full context --
context is worth 16.6 points. Credential harvesting and data exfiltration are 5/5
in every condition (recognizable from one request); beaconing rises 2/5 -> 4/5 as
soon as a second request is visible, because periodicity is undefined on one
observation.

Scenarios are 3-4 requests long, so sizes above 5 equal full context. Default
`--window-sizes 1,2,3,99` reflects that.

**Runtime:** ~2 min. **Cost:** ~120 calls.

---

## Section VI-E: Prompt-Component Ablation

```bash
python evaluation/run_blinded_eval.py --experiment ablation \
    --scenarios data/non_tool_egress_scenarios.json
```

Expected: full 91.7%, minus pattern definitions 87.5%, minus benign exemptions
87.5%, minus all three 79.2%. FPR 0% throughout.

The engineered prompt is worth 12.5 points, not the 57 implied by comparing 42.9%
to 100% (different scenario sets). The status-code component contributes
**nothing**: our traces record symbolic dispositions (`BLOCKED`/`ALLOW`), not HTTP
codes, so the 403-versus-503 guidance never matches anything the model sees.

**Runtime:** ~3 min. **Cost:** ~220 calls.

---

## Section VI-G: AgentDojo Network Observability

No LLM calls. Counts how many AgentDojo attacks leave any artifact a network
monitor could key on, using attacker constants from AgentDojo's own injection
tasks rather than our detection rules.

```bash
python evaluation/analyze_agentdojo_observability.py \
    --scenarios /path/to/agentdojo_scenarios.json
```

Expected: 30/233 = 12.9% observable (95% CI 9.2-17.8). Tier-1 reaches 10.7%; the
gap is five named Slack scenarios whose phishing URLs are observable but absent
from the blocklist. 203 attacks produce requests byte-identical to correct
execution of the benign task, so the 12.9% is a property of the benchmark rather
than a limit of the detector.

**Runtime:** seconds. **Cost:** none.

---

## Section VI-G: InjecAgent, Tier-2 Alone

Tier-2 on independently authored attacks where Tier-1 provably contributes
nothing, with and without the exfiltration endpoint rewritten.

```bash
python evaluation/run_blinded_eval.py --experiment injecagent --split test
```

The script asserts zero requests match any Tier-1 rule and aborts otherwise, so
every detection is Tier-2's. Arm B rewrites `gmail.googleapis.com` to a neutral
host, testing whether Tier-2 recognizes the read-internal-then-POST-external
structure or merely recognizes Gmail.

Expected:

```
As-authored:  ADR 100.0% (98.6-100.0, n=272)  FPR 0.0% (0.0-14.9, n=22)
Rewritten:    ADR 100.0% (98.6-100.0, n=272)  FPR 0.0% (0.0-14.9, n=22)
Delta: 0pp
```

All 272 detections are via Tier-2 trajectory reasoning in both arms. The 0pp delta
proves Tier-2 identifies the read-internal-then-POST-external structure, not just
the Gmail hostname.

**Runtime:** ~15 min. **Cost:** ~570 calls.

---

## Confidence Intervals

All intervals are Wilson score intervals at 95%.

```bash
python evaluation/wilson_ci.py            # recompute for any count
```

---

## Notes

1. **Cost.** Full reproduction is roughly 2,000 Tier-2 calls.
2. **Variance.** Temperature 0 makes verdicts deterministic; if you see drift,
   check that `config={"temperature": 0}` is reaching the API.
3. **TRAJECT-Bench** is not redistributed here. Experiments needing it accept a
   path to your own converted copy.
4. **Blinding is verified, not assumed.** `run_blinded_eval.py` imports the
   Tier-1 rule sets from `code/trajectory_aware.py` and aborts if any blinded
   request still matches one, so the check stays honest if the rules change.
