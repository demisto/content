This script extracts risk details from an incident object, processes asset tags, and sets the user's Slack email for future notifications.
It retrieves the incident details, including risk information, asset tags, and configuration details from the DSPM integration. If the asset owner's email is found, it is stored; otherwise, a default email is used.The extracted data is stored in the XSOAR context and displayed in a readable markdown format.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incident_object | Incident data of a specific asset. |
| defaultSlackUser | Default slack user provided by user. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| incident_object |  | Unknown |
