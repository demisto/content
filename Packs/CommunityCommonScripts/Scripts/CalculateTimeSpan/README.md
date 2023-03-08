Calculates the time span between two dates using Powershell's `New-TimeSpan` command.

A timespan with a start date of "2022-04-02T15:42:48" and end date of "2022-04-12T16:55:07" would return the following:

Days                          : 10
Hours                        : 1
Minutes                    : 12
Seconds                   : 19
Milliseconds           : 0
Ticks                          : 8683390000000
TotalDays                : 10.0502199074074
TotalHours              : 241.205277777778
TotalMinutes          : 14472.3166666667
TotalSeconds         : 868339
TotalMilliseconds : 868339000

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | powershell |
| Tags | Utilities |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| start_time | Specifies the start of a time span. Enter a string that represents the date and time, such as "3/15/09". If no value supplied the current date time will be used |
| end_time | Specifies the end of a time span. If no value supplied the current date and time will be used. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TimeSpan.Days | The number of whole days between the start and end time | Unknown |
| TimeSpan.Hours | The number of whole hours between the start and end time | Unknown |
| TimeSpan.Minutes | The number of whole minutes between the start and end time | Unknown |
| TimeSpan.Seconds | The number of whole seconds between the start and end time | Unknown |
| TimeSpan.Milliseconds | The number of whole milliseconds between the start and end time | Unknown |
| TimeSpan.Ticks | The number of whole ticks between the start and end time. 1 tick is equals to 100 nanoseconds or ten-millionth of a second | Unknown |
| TimeSpan.TotalDays | The number of whole and fractional days between the start and end time | Unknown |
| TimeSpan.TotalHours | The number of whole and fractional hours between the start and end time | Unknown |
| TimeSpan.TotalMinutes | The number of whole and fractional minutes between the start and end time | Unknown |
| TimeSpan.TotalSeconds | The number of whole and fractional seconds between the start and end time | Unknown |
| TimeSpan.TotalMilliseconds | The number of whole and fractional milliseconds between the start and end time | Unknown |
