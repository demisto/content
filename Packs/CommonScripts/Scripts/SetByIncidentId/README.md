Sets a value into the context with the given context key. By default this will not append. This script works the same as the `Set` command, but can work across incidents by specifying `ID` as an argument. 

## Permissions
---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: [https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html
](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/playbooks/automations.html)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DemistoAPI |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| id | The incident to set the context values in. The default is "current incident". |
| key | The key to set. |
| value | The value to set to the key. THis can be an array. Usually, a DQ expression. |
| append | Whether the context key will be overwritten, this will occur when set to false. If it is set to true then the script will append to existing context key. |
| errorUnfinished | Returns an error if not all of the incidents where modified. |

## Outputs
---
There are no outputs for this script.
