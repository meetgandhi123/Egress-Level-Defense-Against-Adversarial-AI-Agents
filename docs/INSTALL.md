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
```bash
# Download from official repository
git clone https://github.com/[TRAJECT-Bench-repo] data/TRAJECT-Bench-master

# Convert to network request format
python data/convert_traject_bench.py
```

#### AgentDojo (Optional)
```bash
pip install agentdojo
# See AgentDojo documentation for scenario setup
```

## Verify Installation

```bash
# Run quick test
python -c "from code.trajectory_aware import TrajectoryAwareDefense; print('OK')"

# Run taxonomy evaluation (should complete in ~2 minutes)
python evaluation/eval_taxonomy.py
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
