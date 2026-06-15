# ConnectUs Migration — Branch 5 of 13

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
git checkout -b jl-connectus-migration-05
```

## Integrations to migrate (in this order)

- **BitSight** (1)
  - BitSight Event Collector
- **CAPESandbox** (1)
  - CapeSandbox
- **Netmiko** (1)
  - Netmiko
- **Trellix Network** (4)
  - FireEye Central Management
  - FireEyeHelix
  - McAfeeNSMv2
  - fireeye
- **VMware Automation and Colection** (3)
  - VMware
  - VMware Carbon Black EDR v2
  - VMware Workspace ONE UEM (AirWatch MDM)

## Machine-readable id list (for the skill's batch flow)

```
["BitSight Event Collector", "CapeSandbox", "Netmiko", "FireEye Central Management", "FireEyeHelix", "McAfeeNSMv2", "fireeye", "VMware", "VMware Carbon Black EDR v2", "VMware Workspace ONE UEM (AirWatch MDM)"]
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
