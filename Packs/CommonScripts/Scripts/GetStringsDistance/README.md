Gets the string distance between *inputString* and *compareString* (*compareString* can be a comma-separated list) based on the Levenshtein Distance algorithm.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | server, phishing |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| compareString | A comma-separated list of strings to compare with the input string. |
| inputString | The input string to compare. |
| distance | The distance that is considered close. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| LevenshteinDistance | The closeness of the sender domain to the configured domains. | Unknown |
