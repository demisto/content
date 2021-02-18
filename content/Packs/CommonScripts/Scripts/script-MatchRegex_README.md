Deprecated. Use the *MatchRegexV2* script instead.
Extracts regex data from a given text. The script supports groups and looping.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| data | The text date from which to extract the regex. |
| regex | The regex to match and extract. |
| group | The matching group to return. If no group is provided, the full match will be returned. The group value should start at 1. |
| contextKey | The context key to populate with the result. |
| flags | The regex flags to match. The default is "-gim". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MatchRegex.results | List of regex matches. | string |
