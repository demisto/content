Extracts regex data from a given text. This supports groups and looping as well.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| data | The text date to extract the regex from. |
| regex | The regex to match and extract. Take into account that data taken from context data contains special characters which are not visible, such as \n and \b. |
| group | The matching group to return. If nothing is provided the full match will be returned. The group value should start at 1. |
| contextKey | The context key to populate with the result. |
| flags | The regex flags to match. The default is "-gim". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MatchRegex.results | List of Regex matches | string |
