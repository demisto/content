Takes UTC and converts it to the specified timezone. Format must match the UTC date's format and output will be the same format. Can use in conjunction with ConvertDateToString

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, date |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | Time in UTC in the format specified |
| format | Format that the input expects, and output will format to \(i.e "%Y-%m-%d %H:%M:%S"\) |
| timezone | Timezone to be converted to \(i.e. 'US/Eastern', 'Etc/Greenwich','Canada/Eastern'\). Review documentation on http://pytz.sourceforge.net/#helpers for what timezones are available. |

## Outputs
---
There are no outputs for this script.
