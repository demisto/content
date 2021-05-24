Add into the incident's context the system internal DBot score for the input indicator.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | DBot, Enrichment |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* DBot Indicator Enrichment - Generic

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator | The indicator to get the reputation of. Only system indicator types are supported. In order to send multiple indicators, use either a list or a JSON formatted string representation (e.g., `["indicator1", "indicator2"]`). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The DBot score vendor. | string |
| DBotScore.Score | The DBot score. | number |
