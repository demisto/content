Schedule a daily job to run this widget script as a playbook step to track EDL size over time

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | widget |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| server_url | Demisto Server URL |
| edl_port | See integration documentation. Required if using a port vs. instance name. |
| edl_exclusions | Integration instances to not track/ignore in widget |
| verify_ssl | Trust any certificate \(insecure\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BaseScript.Output | \[Enter a description of the data returned in this output.\] | String |
