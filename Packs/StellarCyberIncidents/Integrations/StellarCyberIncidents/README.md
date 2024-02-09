Fetches incidents/cases and their associated security alerts from Stellar Cyber. Also provides commands to update and close incidents.
## Configure Stellar Cyber Incidents on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Stellar Cyber Incidents.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Stellar Cyber URL (e.g. example.stellarcyber.cloud) | True |
    | Fetch incidents | False |
    | Incident type | False |
    | API User (Email Address) | True |
    | API Key | True |
    | First fetch time | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Incidents Fetch Interval | False |
    | Optional - Tenant ID | False |
    | Incidents or Cases | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fetch-incidents

***
Retrieve Incidents from Stellar Cyber.

#### Base Command

`fetch-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### stellar-get-event

***
Retrieve an alert from Stellar Cyber.

#### Base Command

`stellar-get-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to retrieve. | Required | 

#### Context Output

There is no context output for this command.
### stellar-close-incident

***
Close an incident in Stellar Cyber.

#### Base Command

`stellar-close-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stellar_incident_id | The ID of the incident to close. | Required | 
| stellar_close_reason | The reason for closing the incident. | Required | 

#### Context Output

There is no context output for this command.
### stellar-incident-update

***
Update the severity, status, assignee, or tags of an incident in       Stellar Cyber.

#### Base Command

`stellar-incident-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stellar_incident_id | The ID of the incident to update. | Required | 
| stellar_incident_severity | The severity to set the incident to in Stellar Cyber. Possible values are: Low, Medium, High, Critical. | Optional | 
| stellar_incident_status | The status to set the incident to. Possible values are: New, In Progress, Resolved, Cancelled. | Optional | 
| stellar_incident_assignee | The email or username in to assign to incident in Stellar Cyber. | Optional | 
| stellar_incident_tags_add | List of tags to add to incident in Stellar Cyber. | Optional | 
| stellar_incident_tags_remove | List of tags to add remove from incident in Stellar Cyber. | Optional | 

#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Stellar Cyber Incidents corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Stellar Cyber Incidents.
