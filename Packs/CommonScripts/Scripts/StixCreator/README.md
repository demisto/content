Gets a list of indicators from the indicators argument, and generates a JSON file in STIX 2.0 format.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | - |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicators | A JSON object of all indicators and their fields, indicator index mapped to XSOAR common indicator fields. Indicator keys that don't match the XSOAR common indicator names are also supported, if their key contains a common indicator name (e.g. "special-ip" will be mapped to **ip**), or their value matches the expected indicator value (e.g. 8.8.8.8 for ip). |
| doubleBackslash | Adds a second backslash to all existing backslashes in the value field.                                                                                                                                                                                                                                                                                            |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| StixExportedIndicators.created | The date/time that the indicator was created. | date |
| StixExportedIndicators.firstSeen | The date/time that the indicator was first seen. | date |
| StixExportedIndicators.source | The source system for this indicator. | string |
| StixExportedIndicators.type | The STIX type (always exported as "indicator"). | string |
| StixExportedIndicators.pattern |  The type and value of indicators. For example, "URL", "IPv4", "domain", "email", and so on.  | string |
| StixExportedIndicators.score | The STIX impact score. Can be, "High", "Medium", "None", or "Not Specified". | string |
| StixExportedIndicators.modified | The date/time that the indicator was last seen. | date |
