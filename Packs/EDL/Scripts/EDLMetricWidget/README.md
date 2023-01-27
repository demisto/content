Schedule a daily job to run this widget script in a playbook to track EDL size over time

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| server_url | Server URL |
| edl_port | If using a port and not instance name |
| edl_exclusions | Integration instances to not track or ignore in widget |
| verify_ssl | Trust any certificate \(insecure\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BaseScript.Output | \[Enter a description of the data returned in this output.\] | String |
