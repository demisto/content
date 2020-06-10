Renders the list of available hunts.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | GRR |


## Dependencies
---
This script uses the following commands and scripts.
* grr_get_hunts

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| offset | The starting offset. |
| count | The maximum number of items to fetch. |
| created_by | Returns hunts created by a given user. If `approved_by` or/and `description_contains` are also supplied, then logical `AND` is applied to all the criterias. NOTE: this filter can only be used in conjunction with `active_within` filter (to prevent queries of death). |
| description_contains | Returns hunts where the description contains a given substring (matching is case-insensitive).If `created_by` or/and `approved_by` are also supplied, then logical `AND` is applied to all the criterias. NOTE: this filter can only be used in conjunction with `active_within` filter (to prevent queries of death). |
| active_within | Returns hunts that were active within given time duration. |

## Outputs
---
There are no outputs for this script.
