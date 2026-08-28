# Open Science Artifacts

**Paper:** Zero-Shot Detection of Goal-Directed Evasion in AI Agent Traffic  
**Venue:** IEEE SaTML 2027

## Repository Structure

```
open_science/
├── code/                    # Defense implementation
│   ├── trajectory_aware.py  # Two-tier defense system
│   ├── base.py              # Base classes and interfaces
│   └── requirements.txt     # Python dependencies
├── data/
│   ├── taxonomy_scenarios/  # 30 controlled attack scenarios (JSON)
│   ├── convert_traject_bench.py  # TRAJECT-Bench conversion script
│   └── README.md            # Data format documentation
├── evaluation/
│   ├── eval_taxonomy.py     # Taxonomy pattern evaluation
│   ├── harness.py           # Main evaluation harness
│   └── run_evaluation.sh    # Reproduction script
└── docs/
    ├── INSTALL.md           # Installation instructions
    ├── REPRODUCE.md         # Steps to reproduce paper results
    └── TAXONOMY.md          # Evasion taxonomy definitions
```

## Quick Start

```bash
# Clone repository
git clone https://github.com/[USERNAME]/agentleash-satml2027.git
cd agentleash-satml2027

# Install dependencies
pip install -r requirements.txt

# Run taxonomy evaluation (Table IV)
python evaluation/eval_taxonomy.py

# Run full benchmark evaluation (Table I)
python evaluation/harness.py --benchmark all
```

## Artifacts Checklist

### Required for Open Science Badge
- [ ] Source code for trajectory-aware defense
- [ ] 30 controlled taxonomy attack scenarios
- [ ] Evaluation scripts with reproduction instructions
- [ ] TRAJECT-Bench conversion script
- [ ] Dependencies and environment specification

### Optional Enhancements
- [ ] Pre-built Docker container
- [ ] AgentDojo integration scripts
- [ ] Interactive demo notebook
- [ ] CI/CD pipeline for automated testing

## External Dependencies

- **TRAJECT-Bench**: https://github.com/[TRAJECT-Bench-repo]
  - Download separately due to size
  - Place in `data/TRAJECT-Bench-master/`

- **AgentDojo**: https://github.com/ethz-spylab/agentdojo
  - Required for prompt injection benchmark
  - See `docs/INSTALL.md` for setup

## License

MIT License (code) / CC-BY 4.0 (data and documentation)

## Citation

```bibtex
@inproceedings{agentleash2027,
  title     = {Zero-Shot Detection of Goal-Directed Evasion in AI Agent Traffic},
  author    = {[Authors]},
  booktitle = {IEEE Conference on Secure and Trustworthy Machine Learning (SaTML)},
  year      = {2027}
}
```
