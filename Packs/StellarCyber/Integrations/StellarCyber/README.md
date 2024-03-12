Fetches and mirrors Cases from Stellar Cyber to XSOAR. Also provides commands to get an Alert, update a Case, or close a Case.
This integration was integrated and tested with version xx of StellarCyber.

## Configure Stellar Cyber on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Stellar Cyber.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch incidents | Enable fetching cases from Stellar Cyber as XSOAR incidents. | False |
    | Incident type | If not using a mapper, incident type to be assigned. | False |
    | Stellar Cyber Host (e.g. example.stellarcyber.cloud) | Your Stellar Cyber Host FQDN. | True |
    | API User (Email Address) |  | True |
    | API Key |  | True |
    | First fetch time | The time to look back for initial pull of cases. Example values: 1 day, 5 hours, 30 minutes, etc. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings | If set to true, will use the system proxy settings. | False |
    | Incidents Fetch Interval | The interval in minutes for fetching incidents from Stellar Cyber. | False |
    | Optional - Tenant ID | Supply a Tenant ID to restrict Fetch and Mirror operations to a specific Tenant. If not supplied, all Tenants will be included. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### get-modified-remote-data

***
Gets the list of incidents and detections that were modified since the last update time. This method is used for debugging purposes.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string representing the local time. The incident is only returned if it was modified after the last update time. | Required | 

#### Context Output

There is no context output for this command.
### get-remote-data

***
Gets data from a remote incident. This method does not update the current incident, and should be used for debugging purposes only.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| lastUpdate | The UTC timestamp in seconds of the last update. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### stellar-get-alert

***
Retrieve an alert from Stellar Cyber.

#### Base Command

`stellar-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StellarCyber.Alert.alert_id | String | ID of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_index | String | Index of the STellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.description | String | Description of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.display_name | String | Display Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.framework_version | String | Framework Version of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.name | String | Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.scope | String | Scope of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.tactic.id | String | Tactic ID of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.tactic.name | String | Tactic Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.tags | String | Tags of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.technique.id | String | Technique ID of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.technique.name | String | Technique Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.ttps.tactic.id | String | Tactic ID of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.ttps.tactic.name | String | Tactic Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.ttps.technique.id | String | Technique ID of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.ttps.technique.name | String | Technique Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.alert_metadata.xdr_killchain_stage | String | XDR Killchain Stage | 
| StellarCyber.Alert.alert_metadata.xdr_killchain_version | String | XDR Killchain Version | 
| StellarCyber.Alert.alert_url | String | URL to the Stellar Cyber Alert | 
| StellarCyber.Alert.description | String | Description of the Stellar Cyber Alert | 
| StellarCyber.Alert.detected_field | String | Detected Field\(s\) of the Stellar Cyber Alert | 
| StellarCyber.Alert.detected_value | String | Detected Value\(s\) of the Stellar Cyber Alert | 
| StellarCyber.Alert.display_name | String | Display Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.tenant_id | String | Tenant ID of the Stellar Cyber Alert | 
| StellarCyber.Alert.tenant_name | String | Tenant Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.xdr_tactic_id | String | XDR Tactic ID of the Stellar Cyber Alert | 
| StellarCyber.Alert.xdr_tactic_name | String | XDR Tactic Name of the Stellar Cyber Alert | 
| StellarCyber.Alert.xdr_technique_id | String | XDR Technique ID of the Stellar Cyber Alert | 
| StellarCyber.Alert.xdr_technique_name | String | XDR Technique Name of the Stellar Cyber Alert | 

### stellar-close-case

***
Close an incident in Stellar Cyber.

#### Base Command

`stellar-close-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stellar_case_id | The ID of the Stellar Cyber Case to close. | Required | 
| stellar_close_reason | The reason for closing the incident. | Required | 

#### Context Output

There is no context output for this command.
### stellar-update-case

***
Update the severity, status, assignee, or tags of a Case in Stellar Cyber.

#### Base Command

`stellar-update-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stellar_case_id | The ID of the Case to update. | Required | 
| stellar_case_severity | The severity to set the Case to in Stellar Cyber. Possible values are: Low, Medium, High, Critical. | Optional | 
| stellar_case_status | The status to set the Case to. Possible values are: New, In Progress, Resolved, Cancelled. | Optional | 
| stellar_case_assignee | The email or username in to assign to Case in Stellar Cyber. | Optional | 
| stellar_case_tags_add | List of tags to add to Case in Stellar Cyber. | Optional | 
| stellar_case_tags_remove | List of tags to add remove from Case in Stellar Cyber. | Optional | 

#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Stellar Cyber corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Stellar Cyber.
