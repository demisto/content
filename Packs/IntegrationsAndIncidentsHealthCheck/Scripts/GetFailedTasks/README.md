Gets failed tasks details for incidents based on a query. Limited to 1000 incidents
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Integrations and Playbooks Health Check - Running Scripts

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | The query by which to retrieve failed tasks. Optional. The default value is "-status:closed" |
| tenant_name | The tenant name. |
| max_incidents | Maximum number of incidents to query. Maximum is 1000. |

## Outputs
---
There are no outputs for this script.
