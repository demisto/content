Removes items from the given value matching the provided list of patterns. If the matchexact Argument is 'yes', direct string compare is used, otherwise the comparison is done using regex.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value on which the transformer is applied. |
| ignorecase | Whether to ignore the case of the item for which you are searching. Default is "Yes". |
| matchexact | Whether to match the exact item in the list, or look for any string that contains it. Default is "No". |
| delimiter | A string used to delimit fields. For example, a new line "\\n" should match the list separator configuration. |
| filters | A list of patterns to remove from the value. This can be a single string or a list of patterns, separated by the pattern defined in the delimiter Argument. Unless matchexact is yes, Regex pattern are supported |

## Outputs

---
There are no outputs for this script.
