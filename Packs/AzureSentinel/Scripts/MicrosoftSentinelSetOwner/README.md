This script can be run from the War Room or used by a layout to set the Owner field in Microsoft Sentinel.

Note: The *Owner* field in Cortex XSOAR can only be modified when the *Mirroring Direction* in the *Instance Settings* is set to *Incoming* or *Incoming and Outgoing*.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | dynamic-section |
| Cortex XSOAR Version | 5.5.0 |

## Inputs

---

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner_email | The owner email to set as the user principal name. If there is a user in Microsoft Sentinel for this email, they will be represented by their name in the remote incident and will be mirrored with all their details. Otherwise, only the email will be displayed on the remote incident, and only the email will be mirrored, with the rest of the details null. | Required |
| incident_id | The ID of the remote incident to update. Relevant only when the script is called directly from the War Room. | Optional (Required When the script is called directly from the War Room)|

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AzureSentinel.Incident.ID | The incident ID. | String |
| AzureSentinel.Incident.Title | The incident's title. | String |
| AzureSentinel.Incident.Description | Description of the incident. | String |
| AzureSentinel.Incident.Severity | The incident severity. | String |
| AzureSentinel.Incident.Status | The incident status. | String |
| AzureSentinel.Incident.AssigneeName | The name of the incident assignee. | String |
| AzureSentinel.Incident.AssigneeEmail | The email address of the incident assignee. | String |
| AzureSentinel.Incident.AssigneeObjectID | The object ID of the incident assignee. | string |
| AzureSentinel.Incident.AssigneeUPN | The user principal name of the incident assignee. | string |
| AzureSentinel.Incident.Label.Name | The name of the incident label. | String |
| AzureSentinel.Incident.Label.Type | The incident label type. | String |
| AzureSentinel.Incident.FirstActivityTimeUTC | The date and time of the incident's first activity. | Date |
| AzureSentinel.Incident.LastActivityTimeUTC | The date and time of the incident's last activity. | Date |
| AzureSentinel.Incident.LastModifiedTimeUTC | The date and time the incident was last modified. | Date |
| AzureSentinel.Incident.CreatedTimeUTC | The date and time the incident was created. | Date |
| AzureSentinel.Incident.IncidentNumber | The incident number. | Number |
| AzureSentinel.Incident.AlertsCount | The number of alerts in the incident. | Number |
| AzureSentinel.Incident.BookmarkCount | The number of bookmarks in the incident. | Number |
| AzureSentinel.Incident.CommentCount | The number of comments in the incident. | Number |
| AzureSentinel.Incident.AlertProductNames | The alert product names of the incident. | String |
| AzureSentinel.Incident.Tactics | The incident's tactics. | String |
| AzureSentinel.Incident.FirstActivityTimeGenerated | The incident's generated first activity time. | Date |
| AzureSentinel.Incident.LastActivityTimeGenerated | The incident's generated last activity time. | Date |
| AzureSentinel.Incident.Etag | The Etag of the incident. | String |
