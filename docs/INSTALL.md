# Installation Guide

## Requirements

- Python 3.10+
- Anthropic API key (for Tier-2 LLM analysis)

## Setup

### 1. Clone Repository

```bash
git clone https://github.com/[USERNAME]/agentleash-satml2027.git
cd agentleash-satml2027
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Set API Key

```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

### 5. Download External Datasets

#### TRAJECT-Bench
Not redistributed here. Download from the official repository and convert the
tool-call trajectories to network requests. Experiments that need it accept a
path to your converted copy via `--benign` or `--traject-scenarios`.

The blinded and OOD evaluations do **not** require it — they run against the
30 taxonomy scenarios shipped in `data/taxonomy_scenarios.json` and against
scenarios generated at runtime.

#### AgentDojo (Optional)
```bash
pip install agentdojo
# See AgentDojo documentation for scenario setup
```

## Verify Installation

```bash
# Rules import cleanly
python -c "from code.trajectory_aware import INTERNAL_DOMAINS, ALWAYS_BLOCK; print('OK')"

# Destination-blinded evaluation (~2 minutes, needs Vertex AI)
python evaluation/run_blinded_eval.py --experiment blinded
```

## Troubleshooting

### API Key Issues
- Ensure `ANTHROPIC_API_KEY` is set in environment
- Check API key has sufficient credits for Claude Sonnet

### Import Errors
- Verify Python 3.10+ is installed
- Run `pip install -r requirements.txt` again

### Dataset Not Found
- Ensure TRAJECT-Bench is downloaded to correct path
- Run conversion script before evaluation
