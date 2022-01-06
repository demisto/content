Checks if the investigation found any malicious indicators (file, URL, IP address, domain, or email). It will returns "yes" if at least one malicious indicator is found.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility, Condition |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| includeSuspicious | Whether to check suspicious indicators. The default is "no". |
| queryIndicators | Queries all indicators in an investigation. This is relevant if it is running in a sub-playbook. |
| maliciousQueryOverride | Whether to override the default query for malicious indicators in Cortex XSOAR (Indicators page). |
| includeManual | Whether to check manually edited indicators. The default is "yes". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| yes | Whether any malicious indicators were found in the investigation. | Unknown |
| no | Whether any malicious indicators were found in the investigation. | Unknown |
