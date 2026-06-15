# ConnectUs Migration — Branch 3 of 13

> Generated batch prompt for parallel migration runs. Assignee: `jlevypaloalto`.
> This branch contains **11 integrations** across **6 connector(s)**.

## Your task

Load the **connectus-migration** skill and migrate the integrations listed
below, one at a time, following the full 15-step per-integration workflow.
Work connector-by-connector (auth/params are similar within a connector, so
doing them back-to-back compounds learning). After each integration, print a
short progress recap (`X/11 done — next: <integration id>`).

Use a dedicated git branch for this batch, e.g.:

```bash
git checkout -b jl-connectus-migration-03
```

## Integrations to migrate (in this order)

- **Accenture** (1)
  - Symantec MSS
- **BruteForceBlocker** (1)
  - BruteForceBlocker Feed
- **JSONWhoIs.com** (1)
  - JsonWhoIs
- **MongoDB** (4)
  - MongoDB
  - MongoDB Key Value Store
  - MongoDB Log
  - MongoDBAtlasEventCollector
- **Trellix Email Security** (3)
  - FireEye ETP Event Collector
  - FireEye Email Security
  - FireEyeNX
- **WildFire Cloud** (1)
  - WildFire-v2

## Machine-readable id list (for the skill's batch flow)

```
["Symantec MSS", "BruteForceBlocker Feed", "JsonWhoIs", "MongoDB", "MongoDB Key Value Store", "MongoDB Log", "MongoDBAtlasEventCollector", "FireEye ETP Event Collector", "FireEye Email Security", "FireEyeNX", "WildFire-v2"]
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
