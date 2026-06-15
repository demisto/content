# ConnectUs Migration — Branch 1 of 13

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
git checkout -b jl-connectus-migration-01
```

## Integrations to migrate (in this order)

- **Cortex Automation Developer Tools** (4)
  - DBot Truth Bombs
  - Hello IAM World
  - OnboardingIntegration
  - Sample Incident Generator
- **Google SecOps** (1)
  - Verodin
- **Ivanti** (2)
  - Cherwell
  - Ivanti Heat
- **Tanium** (3)
  - Tanium Threat Response
  - Tanium Threat Response v2
  - Tanium v2
- **Tidy** (1)
  - Tidy

## Machine-readable id list (for the skill's batch flow)

```
["DBot Truth Bombs", "Hello IAM World", "OnboardingIntegration", "Sample Incident Generator", "Verodin", "Cherwell", "Ivanti Heat", "Tanium Threat Response", "Tanium Threat Response v2", "Tanium v2", "Tidy"]
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
