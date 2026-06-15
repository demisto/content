# ConnectUs Migration — Branch 2 of 13

> Generated batch prompt for parallel migration runs. Assignee: `jlevypaloalto`.
> This branch contains **11 integrations** across **5 connector(s)**.

## Your task

Load the **connectus-migration** skill and migrate the integrations listed
below, one at a time, following the full 15-step per-integration workflow.
Work connector-by-connector (auth/params are similar within a connector, so
doing them back-to-back compounds learning). After each integration, print a
short progress recap (`X/11 done — next: <integration id>`).

Use a dedicated git branch for this batch, e.g.:

```bash
git checkout -b jl-connectus-migration-02
```

## Integrations to migrate (in this order)

- **IBM Security** (4)
  - IBMMaaS360Security
  - IBMSecurityGuardium
  - IBMSecurityVerify
  - XFE_v2
- **IBM Storage Scale** (1)
  - IBM Storage Scale
- **Splunk** (2)
  - SplunkPy
  - SplunkPy v2
- **Tenable** (3)
  - Nessus
  - Tenable.io
  - Tenable.sc
- **Trellix Database Security** (1)
  - McAfeeDAM

## Machine-readable id list (for the skill's batch flow)

```
["IBMMaaS360Security", "IBMSecurityGuardium", "IBMSecurityVerify", "XFE_v2", "IBM Storage Scale", "SplunkPy", "SplunkPy v2", "Nessus", "Tenable.io", "Tenable.sc", "McAfeeDAM"]
```

## Operating notes

- Source of truth for workflow state is the `workflow_state.py` CLI against
  `connectus/connectus-migration-pipeline.csv`. NEVER edit the CSV directly.
- Start each integration with `python3 content/connectus/workflow_state.py context "<Integration ID>"`.
- Pause-and-confirm only on the 4 JSON-write setters (`set-auth`,
  `set-params-to-commands`, `set-param-defaults`, `set-params-to-capabilities`).
- All other steps (reads, `markpass`, `set-capabilities`, analyzer/validate runs)
  run straight through.
- Run all `workflow_state.py` commands from the idex parent cwd (the dir that
  contains `content/` and `unified-connectors-content/` as siblings), hence the
  `content/` path prefix.
