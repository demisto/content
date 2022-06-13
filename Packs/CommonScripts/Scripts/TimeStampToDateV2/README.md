Converts UTC epoch time to a custom-formatted timestamp. If you pass formatter argument, we will use it to transform.
 If not, we will use the IOS format

For example, "1585657181" with format "%Y-%m-%dT%H:%M:%S%z" will return '2020-03-31T12:19:41+0000'.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | transformer, date |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | UTC Time stamp to convert. |
| format | Python 'strftime' formatter string. |

## Outputs
---
There are no outputs for this script.
