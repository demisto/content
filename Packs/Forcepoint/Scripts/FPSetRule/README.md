Adds (or updates an existing) rule in Forcepoint Triton. Preserves orders of rules and modifies policy in-place if a rule exists with the exact type and value.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | forcepoint, triton |


## Dependencies
---
This script uses the following commands and scripts.
* ssh

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| policy | The policy/action assigned to the rule. Can be, "allow" or "deny" only. |
| type | The Triton rule type. Can be, "dest_domain", "dest_ip", "dest_host" or "url_regex". |
| value | The value to match for this rule. Can be, "domain", "regex", etc... depending on the type. |
| remoteaccessname | If the Forcepoint Triton instance is configured as a RemoteAccess integration instance ‐ insert its name here. Replaces argument "tritonsystem". |
| tritonsystem | The system name of the linux host on which Forcepoint Triton is installed. Only use this if it is not working with Triton as a RemoteAccess integration instance ‐ if so, use the "remoteaccessname" argument instead. |

## Outputs
---
There are no outputs for this script.
