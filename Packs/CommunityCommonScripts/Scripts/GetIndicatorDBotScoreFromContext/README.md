Get the final verdict of a indcator from the given DBotScores in the context by their reliability.
Provided that it has all of the latest source verdict, this script gives you the right final verdict.
Note that the result is calculated by the context data and not given from the database.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_value | The indicator value |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FinalDBotScore.Indicator | The indicator value | string |
| FinalDBotScore.Score | The indicator score | number |
| FinalDBotScore.Type | The indicator type | string |
| FinalDBotScore.Vendor | The source vendor of the verdict | string |
| FinalDBotScore.Reliability | The reliability of the indicator verdict | string |
