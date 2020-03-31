Extracts Domains from the given text and places both of them as output and in the context of a playbook. If an object is given, it will convert it to JSON.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| text | The text to extract the Domains from. If it is an object, it will be converted to JSON. |
| urlRegex | The regex to recognize URLs. |
| markAsIndicator | Creates a new indicator for each new domain found. The default is "true". |
| calcReputation | Whether to calculate the reputation for a new indicator created or not. The default is true. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | Extracted domains | Unknown |
