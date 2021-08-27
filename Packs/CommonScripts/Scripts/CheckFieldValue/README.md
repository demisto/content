This script checks that a field exists (and contains data), and optionally checks the value of the field for a match against an input value. This script can be used with the "GenericPolling" playbook to poll for field population or that a field contains a specific value.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | evaluation, polling |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| field | The field to check |
| regex | The regex pattern to check the field for. \(optional\). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PollingCheckField.name | Field Name | string |
| PollingCheckField.exists | Field Exists | Unknown |
