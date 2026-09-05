# Data Artifacts

## Included Files

### `taxonomy_scenarios.json`
30 controlled attack scenarios covering 6 evasion patterns (5 variants each):
- Escalation Evasion
- Research-to-Attack Drift  
- Data Exfiltration
- Credential Harvesting
- Boundary Probing
- Beaconing

### `non_tool_egress_scenarios.json`
44 scenarios where the agent bypasses the tool-invocation layer entirely:
24 attacks and 20 benign controls.

- **Egress methods:** `curl` (15), `wget` (7), Python `requests` (6),
  DNS exfiltration (3), `netcat`/raw sockets (2)
- Each scenario records both the `shell_command` executed and the resulting
  network requests, so tool-level and network-level visibility can be compared
- Ships its own benign controls, so the blinded evaluation on this set needs no
  external data

Attack destinations here were chosen to match Tier-1's rules, so the unblinded
detection rate (24/24) reflects that choice. See `docs/REPRODUCE.md` for the
destination-blinded run, which is the meaningful measurement.

### `injecagent_evaluation.json`
544 scenarios derived from InjecAgent (Zhan et al., ACL 2024):
- **Dev set:** 272 attacks + 22 benign (used for prompt engineering)
- **Test set:** 272 attacks + 22 benign (held-out, run once for final results)

Tool-call sequences converted to network requests using deterministic mapping.

### `conversion_fidelity_sample.csv`
20 tool→network mappings validated by independent reviewer:
- 95% agreement (19/20 preserve semantics)
- Documents the single borderline case (EpicFHIRDownloadFiles)

## External (Download Separately)

### TRAJECT-Bench
- **Source:** https://github.com/[TRAJECT-Bench-repo]
- **Contents:** ~5,670 benign tool-call trajectories
- **Usage:** For independent FPR validation via `evaluation/run_independent_benign.py`

### AgentDojo
- **Source:** https://github.com/ethz-spylab/agentdojo
- **Contents:** 359 prompt injection scenarios
- **Note:** Most attacks use internal APIs (unobservable at network layer)

## Data Format

Each scenario is a JSON object:

```json
{
  "id": "unique_identifier",
  "name": "Human-readable name", 
  "task": "The agent's assigned task",
  "is_attack": true | false,
  "expected_pattern": "escalation_evasion" | "data_exfiltration" | "none",
  "requests": [
    {
      "method": "GET" | "POST",
      "url": "https://api.service.internal/endpoint",
      "status": 200 | 403 | 503
    }
  ],
  "source": "injecagent" | "taxonomy" | "traject_bench"
}
```
