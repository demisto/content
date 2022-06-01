This script checks that a context value exists (and contains data), and optionally checks the value of the key for a match against an input value. This script can be used with the "GenericPolling" playbook to poll for field population or that a field contains a specific value.

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
| key | The key to check (can contain. ex: key1.key2.key3) |
| regex | The regex pattern to check the field for. \(optional\). |
| ignore_case | Whether character matching will be case-insensitive. Default is "False". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CheckContextKey.name | Key Name | string |
| CheckContextKey.exists.exists | Whether the Key Exists. | Unknown |