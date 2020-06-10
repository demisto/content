Parses a CrowdStrike alert URL and pull out the agent ID. This is useful when passing it to the `cs-device-details` command to return a device's details.
This script will also return the detection ID for the specific alert. This is used for modifying the state of the alert for CrowdStrike.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | crowdstrike |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | The URL to parse. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CrowdStrikeUrlParse.AgentId | The agent ID for the CrowdStrike host. | Unknown |
| CrowdStrikeUrlParse.DetectId | The detection ID for the CrowdStrike alert. | Unknown |
