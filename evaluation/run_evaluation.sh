#!/bin/bash
# Reproduction script for paper results

set -e

echo "=== AgentLeash Evaluation ==="
echo ""

# Check API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "ERROR: ANTHROPIC_API_KEY not set"
    echo "Run: export ANTHROPIC_API_KEY='your-key'"
    exit 1
fi

echo "1. Running Taxonomy Evaluation (Table IV)..."
python eval_taxonomy.py
echo ""

echo "2. Results saved to results/taxonomy_eval_results.json"
echo ""

echo "=== Evaluation Complete ==="
