# ConnectUs Migration — Branch 13 of 13

> Generated batch prompt for parallel migration runs. Assignee: `jlevypaloalto`.
> This branch contains **10 integrations** across **5 connector(s)**.

## Your task

Load the **connectus-migration** skill and migrate the integrations listed
below, one at a time, following the full 15-step per-integration workflow.
Work connector-by-connector (auth/params are similar within a connector, so
doing them back-to-back compounds learning). After each integration, print a
short progress recap (`X/10 done — next: <integration id>`).

Use a dedicated git branch for this batch, e.g.:

```bash
git checkout -b jl-connectus-migration-13
```

## Integrations to migrate (in this order)

- **Fortra** (2)
  - DigitalGuardianARCEventCollector
  - Tripwire
- **Gamma.AI** (1)
  - Gamma
- **MISP** (3)
  - FeedMISPThreatActors
  - MISP Feed
  - MISP V3
- **SAP** (3)
  - SAP-IAM
  - SAPBTP
  - SAPCloudForCustomerC4C
- **TheHive** (1)
  - TheHive Project

## Machine-readable id list (for the skill's batch flow)

```
["DigitalGuardianARCEventCollector", "Tripwire", "Gamma", "FeedMISPThreatActors", "MISP Feed", "MISP V3", "SAP-IAM", "SAPBTP", "SAPCloudForCustomerC4C", "TheHive Project"]
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
