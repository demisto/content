Retrieves the current date and time.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| date | The date to use in the object. |
| dateFormat | The date format for the result. Can be ISO/GMT/UTC/Locale/Date/Year/Month/Day/DayInWeek/Hours.<br/>Note that the response will start from 0. For example, if the current month is October<br/>\(the 10th month\) the result will be 9.<br/>Note:<br/>In Cortex XSOAR versions 6.11 or later, or 8.1.0 or later, the time format returned when UTC or GMT is given has changed.<br/>Instead of 'Wed Jan 18 2023 12:59:12 GMT\+0000 \(UTC\)', The output will be 'Wed, 18 Jan 2023 15:59:12 GMT'. |
| contextKey | Prefix the keys in the context for the results. |
| minutesAgo | Will subtract minutesAgo minutes from current time. |
| hoursAgo | Will subtract hoursAgo hours from current time. |
| daysAgo | Will subtract daysAgo days from current time. |
| monthsAgo | Will subtract monthsAgo months from current time. |
| yearsAgo | Will subtract yearsAgo years from current time. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TimeNowUnix | Number of milliseconds since 1970/01/01. | Number |
| TimeNow | Current time. | String |
