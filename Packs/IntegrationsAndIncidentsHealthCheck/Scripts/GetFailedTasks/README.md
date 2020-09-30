Gets failed tasks details for incidents based on a query. If rerun = true is provided, the automation will also re-run the failed tasks.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Integrations and Playbooks Health Check - Running Scripts

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | The query by which to retrieve failed tasks. Optional. The default value is "-status:closed and runStatus:error" |

## Outputs
---
There are no outputs for this script.
