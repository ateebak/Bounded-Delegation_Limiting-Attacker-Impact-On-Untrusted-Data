# Bounded Delegation: artifact

Anonymized artifact for the USENIX Security '27 submission "Bounded Delegation: Limiting Attacker Impact When Agents
Must Act on Untrusted Data".

- `defense/bounded/`: envelope compiler, validator, monitor, sensitive-field tables.
- `experiments/harness/`: evaluation harness (runner, simulated users, baseline wrappers, analysis:
  `analyze_repeats.py`, `paired_contrasts.py`).
- `experiments/attacks/`: value-substitution v1, authored-v2 and adaptive attack builders and specs.
- `experiments/stratum/`: delegated-stratum survey scripts and gold labels.
- `experiments/runs/<run_id>/`: per-episode run records for every reported run; `INVALID.json` lists every excluded
  episode with its reason.
- `experiments/probes/logs/*_analysis.jsonl`, `*_contrasts.txt`, `*.runs`: analysis outputs cited in the paper.
- `paper/make_numbers.py`: regenerates every number, table and figure in the paper from the analysis outputs.
- `tests/`: unit tests (`python -m pytest tests`).

Reproduce (Python 3.12; `pip install pytest matplotlib`):
- `python -m pytest tests` (75 unit tests: monitor, compiler validator, simulated users, retries, DRIFT shim).
- `python paper/make_numbers.py` regenerates `paper/generated/` (all numbers, tables and the main figure) from the
  analysis outputs; `python experiments/harness/analyze_repeats.py name=RUN_ID ...` and `paired_contrasts.py`
  regenerate the analysis outputs from the run records.
- Re-running agents needs the third-party benchmark/baseline checkouts and model API access (not included).

Third-party code (AgentDojo/AgentDyn via ROPE's AutoDojo fork, ROPE, Progent, DRIFT, CaMeL) is not redistributed;
pinned versions are listed in `experiments/harness/` and the paper.
