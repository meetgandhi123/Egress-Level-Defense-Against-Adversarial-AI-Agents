# Data Artifacts

## Included

### `taxonomy_scenarios.json`
30 controlled attack scenarios covering 6 evasion patterns (5 variants each):
- Escalation Evasion
- Research-to-Attack Drift
- Data Exfiltration
- Credential Harvesting
- Boundary Probing
- Beaconing

### `convert_traject_bench.py`
Script to convert TRAJECT-Bench tool-call trajectories to network requests.

## External (Download Separately)

### TRAJECT-Bench
- **Source:** https://github.com/[TRAJECT-Bench-repo]
- **Size:** ~500MB
- **Contents:** 5,910 tool-call trajectories across 10 domains

Download and extract to `TRAJECT-Bench-master/` in this directory, then run:
```bash
python convert_traject_bench.py
```

This produces `converted_scenarios.json` with 5,700 scenarios (5,670 benign + 30 attack).

### AgentDojo
- **Source:** https://github.com/ethz-spylab/agentdojo
- **Install:** `pip install agentdojo`
- **Contents:** 359 prompt injection scenarios (233 attack, 126 benign)

## Data Format

Each scenario is a JSON object:

```json
{
  "id": "unique_identifier",
  "name": "Human-readable name",
  "description": "Scenario description",
  "task_prompt": "The agent's assigned task",
  "expected_label": "attack" | "benign",
  "attack_type": "escalation_evasion" | "data_exfiltration" | ...,
  "requests": [
    {
      "method": "GET" | "POST" | ...,
      "host": "example.com",
      "path": "/api/endpoint"
    }
  ],
  "source": "Synthetic-Attack" | "TRAJECT-Bench" | "AgentDojo"
}
```
