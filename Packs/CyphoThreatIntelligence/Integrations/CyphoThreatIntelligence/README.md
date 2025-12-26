This integration enables your organization to efficiently collect, analyze, and respond to actionable cyber alerts generated within the Cypho platform  enhancing visibility, automation, and overall security posture.

## Configure Cypho Threat Intelligence in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. <https://api.cypho.io/external/v1/>) | True |
| Maximum number of incidents per fetch | False |
| API Key | True |
| First fetch time | False |
| Trust any certificate (not secure) | False |
| Incidents Fetch Interval | False |
| Tenant Name | False |
| Fetch incidents | False |
| Incident type | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cypho-get-incident

***
Retrieves the full details of a specific security incident from Cypho using its unique ticket_id. This command returns the raw response from the Cypho API, including metadata such as title, status, risk level, category, timestamps, impacted asset, and more.This command is intended for debugging purposes only and should not be used in production playbooks.

#### Base Command

`cypho-get-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket_id is the unique ID used to identify and manage each incident across automations and integrations. | Optional | 

#### Context Output

There is no context output for this command.

### cypho-assign-incident

***
Assign a Cypho issue to an analyst by constructing their email from the given username and domain. The incident is assigned and updated with this user’s email.

#### Base Command

`cypho-assign-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket_id is the unique ID used to identify and manage each incident across automations and integrations. | Optional | 
| user_email | The user_email field stores the email address of the user, and it must match the email of a registered user in the Cypho platform to ensure correct user mapping and permission handling. | Optional | 

#### Context Output

There is no context output for this command.

### cypho-add-comment

***
This command sends a comment as the status_reason parameter and attributes it to a user constructed from the provided username and domain. It is used to log investigation notes or analyst input directly on the issue.

#### Base Command

`cypho-add-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket_id is the unique ID used to identify and manage each incident across automations and integrations. | Optional | 
| status_reason | The status_reason field stores a comment or explanation describing the reason for an incident’s current status, and this note is added directly to the incident record in the Cypho platform. | Optional | 
| user_email | The user_email field stores the email address of the user, and it must match the email of a registered user in the Cypho platform to ensure correct user mapping and permission handling. | Optional | 

#### Context Output

There is no context output for this command.

### cypho-update-severity

***
Updates the severity level of a specific Cypho issue using its unique ticket ID. This command is used to escalate or de-escalate the risk level ("Low", "Moderate", or "Critical") based on analysis or triage.

#### Base Command

`cypho-update-severity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket_id is the unique ID used to identify and manage each incident across automations and integrations. | Optional | 
| user_email | The user_email field stores the email address of the user, and it must match the email of a registered user in the Cypho platform to ensure correct user mapping and permission handling. | Optional | 
| severity | The severity field indicates the criticality level of an incident, helping teams prioritize and manage response efforts effectively. | Optional | 

#### Context Output

There is no context output for this command.

### cypho-download-attachment

***
Downloads one or more attachments from a Cypho incident using the incident's unique "ticket_id". The command retrieves the attachment URLs from the issue and returns the files directly to the War Room. Useful for reviewing screenshots, logs, or other evidence related to the incident.

#### Base Command

`cypho-download-attachment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket_id is the unique ID used to identify and manage each incident across automations and integrations. | Optional | 

#### Context Output

There is no context output for this command.

### cypho-approve-dismiss-issue

***
Approves or dismisses a Cypho issue based on the provided ticket ID, user email, and approval decision.

#### Base Command

`cypho-approve-dismiss-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticket_id | The ticket_id is the unique ID used to identify and manage each incident across automations and integrations. | Optional | 
| user_email | The user_email field stores the email address of the user, and it must match the email of a registered user in the Cypho platform to ensure correct user mapping and permission handling. | Optional | 
| approve | A boolean argument that, when set to true, approves the issue, and when set to false, dismisses it. Possible values are: True, False. | Optional | 

#### Context Output

There is no context output for this command.
