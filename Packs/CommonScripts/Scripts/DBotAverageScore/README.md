The script calculates the average DBot score for each indicator in the context.  
The script will ignore '0' scores (which are for an 'unknown' reputation).
If all scores for an indicator are '0', the indicator will receive a score of '0'.

For more information regarding DBot Scores, refer to the official ["Reputation and DBot Score" documentation](https://xsoar.pan.dev/docs/integrations/dbot).

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---
There are no inputs for this script.

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotAvgScore.Indicator | The indicator the average score is for. | string |
| DBotAvgScore.Score | The average score for the indicator. | number |
