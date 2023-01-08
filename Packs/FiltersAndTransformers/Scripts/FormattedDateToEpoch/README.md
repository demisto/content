Converts a custom-formatted timestamp to UNIX epoch time. Use it to convert custom time stamps to a XSOAR date field. If you pass formatter argument, we will use it to transform. If not, we will use dateparser.parse for transforming. For more info, see: https://docs.python.org/3.7/library/datetime.html#strftime-and-strptime-behavior

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, date |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Time stamp to convert |
| formatter | Python 'strptime' formatter string |

## Outputs
---
There are no outputs for this script.
