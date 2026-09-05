# Open Science Artifacts

**Paper:** Egress-Level Defense Against Adversarial AI Agents
**Venue:** IEEE SaTML 2027

Network-level trajectory analysis for detecting compromised AI agents that
deliberately evade security policies. Two tiers: deterministic rules at
microsecond latency, and an LLM trajectory analyzer for ambiguous requests.

## Repository Structure

```
open_science/
├── code/                            # Core implementation
│   ├── trajectory_aware.py          # Two-tier defense (Tier-1 rules + Tier-2 call)
│   ├── tier2_prompt.py              # Tier-2 prompt with evasion pattern definitions
│   ├── base.py                      # Base classes and interfaces
│   └── requirements.txt             # Python dependencies
├── data/
│   ├── taxonomy_scenarios.json      # 30 controlled attack scenarios
│   ├── non_tool_egress_scenarios.json   # 44 shell/library/socket scenarios (24 atk, 20 ben)
│   ├── injecagent_evaluation.json   # 544 InjecAgent-derived scenarios (dev/test split)
│   ├── conversion_fidelity_sample.csv   # Tool→network mapping validation
│   └── README.md                    # Data format documentation
├── evaluation/
│   ├── run_blinded_eval.py          # Destination-blinded eval, OOD ablation,
│   │                                #   placeholder deconfound, trajectory-window
│   │                                #   sensitivity, prompt ablation, InjecAgent
│   │                                #   Tier-2-alone (Tables IV, VII)
│   ├── analyze_agentdojo_observability.py  # Network-observable fraction of
│   │                                #   AgentDojo (Section VI-G)
│   ├── run_injecagent_eval.py       # InjecAgent held-out evaluation (Table III)
│   ├── run_full_pipeline_eval.py    # Full Tier-1→Tier-2 pipeline on benign traffic (Table V)
│   ├── run_independent_benign.py    # Independent benign FPR evaluation
│   ├── injecagent_converter.py      # Tool-call to network-request converter
│   ├── harness.py                   # Core evaluation harness (Table I)
│   └── wilson_ci.py                 # Wilson confidence intervals
└── docs/
    ├── INSTALL.md                   # Installation
    ├── REPRODUCE.md                 # Steps to reproduce each paper result
    └── TAXONOMY.md                  # Evasion taxonomy definitions
```

## Quick Start

```bash
pip install -r code/requirements.txt
pip install google-genai            # Tier-2 via Vertex AI
export GCP_PROJECT=your-project     # and optionally GCP_LOCATION

# Destination-blinded evaluation -- the main circularity control (Table IV)
python evaluation/run_blinded_eval.py --experiment blinded

# Out-of-distribution ablation: hold each pattern out of the prompt
python evaluation/run_blinded_eval.py --experiment ood

# InjecAgent held-out test set (Table III)
python evaluation/run_injecagent_eval.py --split test --model gemini-2.5-flash
```

`run_blinded_eval.py --experiment blinded` needs no external data: it uses the
30 taxonomy scenarios shipped in `data/`. Add `--benign <converted_scenarios.json>`
to also measure false-positive rate against TRAJECT-Bench, which we do not
redistribute (see External Dependencies).

## Key Results

| Evaluation | ADR | FPR | n |
|---|---|---|---|
| Combined benchmark (Table I) | 20.9% (16.4–26.2) | 4.7% (4.4–5.5) | 263 atk / 5,796 ben |
| InjecAgent held-out test (Table III) | 100% (98.6–100) | 0% (0–14.9) | 272 / 22 |
| **Blinded — taxonomy (Table IV)** | **93.3% (78.7–98.2)** | **5.0% (2.2–11.2)** | 30 / 100 |
| **Blinded — non-tool egress (Table IV)** | **95.8% (79.8–99.3)** | **0% (0–16.1)** | 24 / 20 |
| Taxonomy patterns (unblinded) | 100% (88.6–100) | — | 30 |
| Out-of-distribution (held-out patterns) | 80.0% (68.2–88.2) | — | 60 |
| Trajectory window: 1 request vs full | 76.7% → 93.3% | — | 30 |
| Prompt ablation: minimal vs full | 79.2% → 91.7% | 0% | 24 / 20 |
| AgentDojo network-observable ceiling | 12.9% (9.2–17.8) | — | 233 |

In the blinded evaluation, all 51 of 54 detections are attributable to Tier-2;
Tier-1 contributes nothing once destination cues are removed. Two of the three
misses are beaconing, which is also the one pattern that does not survive
removal of its prompt definition (0/10) — periodicity is not separable from
legitimate telemetry on content alone.

## Reproducibility Notes

- **Tier-2 model.** The combined-benchmark results in Table I were originally
  produced with Claude Sonnet 4. Re-running on Gemini 2.5 Flash reproduces them
  closely (20.9% ADR / 5.0% FPR against 20.9% / 4.7%). The blinded evaluation
  additionally reproduces on Gemini 2.5 Pro. Tier-2 is model-agnostic.
- **Determinism.** Tier-2 is queried at temperature 0, so verdicts are stable
  across runs.
- **Blinding is self-checking.** `run_blinded_eval.py` imports the Tier-1 rule
  sets directly from `code/trajectory_aware.py` and aborts rather than reporting
  a result if any blinded request still matches a rule. Edit the rules and the
  check follows.
- **Cost.** A full blinded + OOD run is roughly 300 Tier-2 calls.

## External Dependencies

- **TRAJECT-Bench** — not redistributed. Download from the original source and
  convert; needed for FPR arms and the placeholder experiment.
- **InjecAgent** — pre-converted in `data/injecagent_evaluation.json`.
- **GCP Vertex AI** — required for Tier-2. Set `GCP_PROJECT` / `GCP_LOCATION`.

## License

MIT License (code) / CC-BY 4.0 (data and documentation)

## Citation

```bibtex
@inproceedings{agentleash2027,
  title     = {Egress-Level Defense Against Adversarial AI Agents},
  author    = {[Authors]},
  booktitle = {IEEE Conference on Secure and Trustworthy Machine Learning (SaTML)},
  year      = {2027}
}
```
