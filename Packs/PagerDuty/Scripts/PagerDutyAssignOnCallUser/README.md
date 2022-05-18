Assigns the first on-call user to an investigation by default. All incidents in the investigation will be owned by the on call user.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | pagerduty, communication |


## Dependencies
---
This script uses the following commands and scripts.
* PagerDuty-get-users-on-call-now

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| escalation_policy_ids | The comma-separated escalation policy IDs from which choose the oncall user. |
| schedule_ids | The comma-separated schedule IDs from which to choose the oncall user. |

## Outputs
---
There are no outputs for this script.
