Aggregate entries from ServiceNow CMDB into AttributionCI

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | |
| Cortex XSOAR Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Expanse Attribution Subplaybook

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | Input list. |
| current | Current aggregation state. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Expanse.AttributionCI.name | Name of the CI | string |
| Expanse.AttributionCI.sys_id | ServiceNow Sys ID | string |
| Expanse.AttributionCI.sys_class_name | Class Name of the CI | string |
| Expanse.AttributionCI.asset_display_value | Name of the Asset | string |
| Expanse.AttributionCI.asset_link | Link to the asset | string |
| Expanse.AttributionCI.asset_value | ID of the asset | string |
