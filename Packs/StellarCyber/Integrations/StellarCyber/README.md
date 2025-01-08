Fetches and mirrors in Cases from Stellar Cyber to XSOAR. In addition, provides a command to update Case severity/status/assignee/tags, and a command to query an Alert.
This integration was integrated and tested with version >= 4.3.7/5.0.4 of StellarCyber.

## Configure Stellar Cyber in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch incidents |  |  |
| Incident type |  |  |
| Mirroring Direction | If set to Incoming, will mirror Cases from Stellar Cyber to XSOAR. If set to None, will not mirror Cases from Stellar Cyber to XSOAR. Default is None. | False |
| Stellar Cyber Host (e.g. example.stellarcyber.cloud) | Your Stellar Cyber Host FQDN. | True |
| API User (Email Address) |  | True |
| API Key |  | True |
| First fetch time | The period of time to look back for initial pull of cases. \(&lt;number&gt; &lt;time unit&gt;, i.e. 1 day, 5 hours, 30 minutes, etc.\) | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings | If set to true, will use the system proxy settings. | False |
| Incidents Fetch Interval | The interval in minutes for fetching incidents from Stellar Cyber. | False |
| Optional - Tenant ID | Supply a Tenant ID to restrict Fetch and Mirror operations to a specific Tenant. If not supplied, all Tenants will be included. | False |
| Maximum number of incidents per fetch | The maximum number of incidents to fetch per fetch. | False |


## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Stellar Cyber corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Stellar Cyber events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Stellar Cyber.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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
| StellarCyber.Alert.alert_id | String | ID of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_index | String | Index of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.description | String | Description of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.display_name | String | Display Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.framework_version | String | Framework Version of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.name | String | Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.scope | String | Scope of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.tactic.id | String | Tactic ID of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.tactic.name | String | Tactic Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.tags | String | Tags of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.technique.id | String | Technique ID of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.technique.name | String | Technique Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.ttps.tactic.id | String | Tactic ID of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.ttps.tactic.name | String | Tactic Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.ttps.technique.id | String | Technique ID of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.ttps.technique.name | String | Technique Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.alert_metadata.xdr_killchain_stage | String | XDR Killchain Stage. | 
| StellarCyber.Alert.alert_metadata.xdr_killchain_version | String | XDR Killchain Version. | 
| StellarCyber.Alert.alert_url | String | URL to the Stellar Cyber Alert. | 
| StellarCyber.Alert.description | String | Description of the Stellar Cyber Alert. | 
| StellarCyber.Alert.detected_field | String | Detected Field\(s\) of the Stellar Cyber Alert. | 
| StellarCyber.Alert.detected_value | String | Detected Value\(s\) of the Stellar Cyber Alert. | 
| StellarCyber.Alert.display_name | String | Display Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.tenant_id | String | Tenant ID of the Stellar Cyber Alert. | 
| StellarCyber.Alert.tenant_name | String | Tenant Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.xdr_tactic_id | String | XDR Tactic ID of the Stellar Cyber Alert. | 
| StellarCyber.Alert.xdr_tactic_name | String | XDR Tactic Name of the Stellar Cyber Alert. | 
| StellarCyber.Alert.xdr_technique_id | String | XDR Technique ID of the Stellar Cyber Alert. | 
| StellarCyber.Alert.xdr_technique_name | String | XDR Technique Name of the Stellar Cyber Alert. | 

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StellarCyber.Case.Update._id | String | Case ID. | 
| StellarCyber.Case.Update.assignee | String | Case Assignee. | 
| StellarCyber.Case.Update.created_at | Date | Case Created Timestamp. | 
| StellarCyber.Case.Update.created_by | String | Case Created By. | 
| StellarCyber.Case.Update.cust_id | String | Case Tenant ID. | 
| StellarCyber.Case.Update.modified_at | Date | Case Modified Timestamp. | 
| StellarCyber.Case.Update.modified_by | String | Case Modified By. | 
| StellarCyber.Case.Update.name | String | Case Name. | 
| StellarCyber.Case.Update.size | Number | Case Size \(Number of Alerts\). | 
| StellarCyber.Case.Update.status | String | Case Status. | 
| StellarCyber.Case.Update.tags | Unknown | Case Tags. | 
| StellarCyber.Case.Update.ticket_id | Number | Case Ticket ID. | 
| StellarCyber.Case.Update.version | Number | Case Version. | 
| StellarCyber.Case.Update.priority | String | Case Priority. | 
| StellarCyber.Case.Update.incident_score | Number | Case Score. | 
| StellarCyber.Case.Update.assignee_name | String | Case Assignee Name. | 

### get-remote-data

***
Gets remote data from a remote incident. This method is only used for debugging purposes and will not update the current incident.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.

### get-modified-remote-data

***
Available from Cortex XSOAR version 6.1.0. This command queries for incidents that were modified since the last update. This method is only used for debugging purposes.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. | Required | 

#### Context Output

There is no context output for this command.