Add into the incident's context the system internal DBot score for the input indicator

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python2 |
| Tags | DBot, Enrichment |
| Demisto Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* DBot Indicator Enrichment - Generic

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator | The indicator to get the reputation of |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The Indicator | string |
| DBotScore.Type | The Indicator Type | string |
| DBotScore.Vendor | The DBot score vendor | string |
| DBotScore.Score | The DBot score | number |
