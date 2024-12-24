Creates an iCal event and stores it as a file object within XSOAR

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| title | The title for the event |
| start_date | The start date in the format YYYY/MM/DD |
| start_time | The start time in the format HH:MM |
| start_time_zone | The time zone of the start date/time |
| end_date | The end date in the format YYYY/MM/DD |
| end_time | The end time in the format HH:MM |
| end_time_zone | The time zone of the end date/time |
| description | An optional description for the event |
| url | An optional URL to be added to the event. In case none is provided, the script will try to determine the URL of the incident to create a direct link |
| uid | Optional argument allowing to override the email UID. Use in case the invite may need to be updated. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| None |  | Unknown |
