This script processes user responses from a Slack block interaction, determining the appropriate action based on the selected option (either creating a Jira ticket or remediating a risk). It extracts relevant project details and ticket types from the user input, sets the necessary context in XSOAR, and handles errors gracefully.

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
| incident_data | Incident data of a specific asset. |
| SlackBlockState | The state of the response from the user will be stored under this context path. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| User.Action |  | Unknown |
| User.JiraProjectName |  | Unknown |
| User.JiraTicketType |  | Unknown |
