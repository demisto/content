Gets the string distance between `inputString` and `compareString` (can be a comma separated list) based on the Levenshtein Distance algorithm.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | server, phishing, Condition |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| compareString | The string(s) to compare with the input string. Can be multiple strings with a comma-separator. |
| inputString | The input string to compare. |
| distance | The distance that is considered close. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| LevenshteinDistance | The closeness of the sender domain to the configured domains. | Unknown |
