Fetches and mirrors in Cases from Stellar Cyber to XSOAR. Also provides commands to get an Alert, update a Case, or close a Case.
This integration was integrated and tested with version xx of StellarCyber.

## Configure Stellar Cyber on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Stellar Cyber.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch incidents |  |  |
    | Incident type |  |  |
    | Stellar Cyber Host (e.g. example.stellarcyber.cloud) | Your Stellar Cyber Host FQDN. | True |
    | API User (Email Address) |  | True |
    | API Key |  | True |
    | First fetch time | The time to look back for initial pull of cases. Example values: 1 day, 5 hours, 30 minutes, etc. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings | If set to true, will use the system proxy settings. | False |
    | Incidents Fetch Interval | The interval in minutes for fetching incidents from Stellar Cyber. | False |
    | Optional - Tenant ID | Supply a Tenant ID to restrict Fetch and Mirror operations to a specific Tenant. If not supplied, all Tenants will be included. | False |
    | Maximum number of incidents per fetch | The maximum number of incidents to fetch per fetch. | False |

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

#### Command example
```!stellar-get-alert alert_id="1710883791406342b1f41b2247774d60bf035a6f98e5ff21"```
#### Context Example
```json
{
    "StellarCyber": {
        "Alert": {
            "alert_metadata": {
                "description": "Proofpoint TAP reported that a suspicious email with the subject \"Action Required: info@example.com\" was sent from the email address \"srso+yf09=cw=testing.com=jane@testing.com\" to address(es) \"info@example.com.\"",
                "display_name": "Proofpoint TAP messagesBlocked: Phishing",
                "event_name_add_on": "messagesBlocked",
                "framework_version": "v8",
                "name": "proofpoint_tap-messagesblocked-initial_access-phishing",
                "scope": "",
                "subtype": {
                    "display_name": "Proofpoint TAP: Phish",
                    "name": "proofpoint_tap_phish"
                },
                "tactic": {
                    "id": "TA0001",
                    "name": "Initial Access"
                },
                "tags": [
                    "Proofpoint TAP"
                ],
                "technique": {
                    "id": "T1566",
                    "name": "Phishing"
                },
                "ttps": [
                    {
                        "tactic": {
                            "id": "TA0001",
                            "name": "Initial Access"
                        },
                        "technique": {
                            "id": "T1566",
                            "name": "Phishing"
                        }
                    }
                ],
                "xdr_killchain_stage": "Initial Attempts",
                "xdr_killchain_version": "v1"
            },
            "alert_id": "1710883791406342b1f41b2247774d60bf035a6f98e5ff21",
            "alert_index": "stellar-index-v1-ser-5593fbd8b0444b1eaef5a89589d788d2-64486c346020c889507f32ae-2024.03.07-000033",
            "tenant_id": "6aeb2aae7d8d4ef0820136f42d107db4",
            "tenant_name": "QA-SPUTTA",
            "detected_field": [
                "email.from.address",
                "email.sender.address"
            ],
            "detected_value": [
                "srso+yf09=cw=testing.com=jane@testing.com",
                "srso+yf09=cw=testing.com=jane@testing.com"
            ],
            "xdr_tactic_name": "Initial Access",
            "xdr_tactic_id": "TA0001",
            "xdr_technique_name": "Phishing",
            "xdr_technique_id": "T1566",
            "display_name": "Proofpoint TAP messagesBlocked: Phishing",
            "description": "Proofpoint TAP reported that a suspicious email with the subject \"Action Required: info@example.com\" was sent from the email address \"srso+yf09=cw=testing.com=jane@testing.com\" to address(es) \"info@example.com.\"",
            "alert_url": "https://test.example.com/alerts/alert/stellar-index-v1-ser-5593fbd8b0444b1eaef5a89589d788d2-64486c346020c889507f32ae-2024.03.07-000033/amsg/1710883791406342b1f41b2247774d60bf035a6f98e5ff21"
        }
    }
}
```

#### Human Readable Output

>### Results
>|alert_id|alert_index|alert_metadata|alert_url|description|detected_field|detected_value|display_name|tenant_id|tenant_name|xdr_tactic_id|xdr_tactic_name|xdr_technique_id|xdr_technique_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1710883791406342b1f41b2247774d60bf035a6f98e5ff21 | stellar-index-v1-ser-5593fbd8b0444b1eaef5a89589d788d2-64486c346020c889507f32ae-2024.03.07-000033 | description: Proofpoint TAP reported that a suspicious email with the subject "Action Required: info@cityofrochester.gov" was sent from the email address "srso+yf09=cw=pobox.com=ann@pobox.com" to address(es) "info@cityofrochester.gov."<br/>display_name: Proofpoint TAP messagesBlocked: Phishing<br/>event_name_add_on: messagesBlocked<br/>framework_version: v8<br/>name: proofpoint_tap-messagesblocked-initial_access-phishing<br/>scope: <br/>subtype: {"display_name": "Proofpoint TAP: Phish", "name": "proofpoint_tap_phish"}<br/>tactic: {"id": "TA0001", "name": "Initial Access"}<br/>tags: Proofpoint TAP<br/>technique: {"id": "T1566", "name": "Phishing"}<br/>ttps: {'tactic': {'id': 'TA0001', 'name': 'Initial Access'}, 'technique': {'id': 'T1566', 'name': 'Phishing'}}<br/>xdr_killchain_stage: Initial Attempts<br/>xdr_killchain_version: v1 | https://dev-dp3.stellarcyber.cloud/alerts/alert/stellar-index-v1-ser-5593fbd8b0444b1eaef5a89589d788d2-64486c346020c889507f32ae-2024.03.07-000033/amsg/1710883791406342b1f41b2247774d60bf035a6f98e5ff21 | Proofpoint TAP reported that a suspicious email with the subject "Action Required: info@cityofrochester.gov" was sent from the email address "srso+yf09=cw=pobox.com=ann@pobox.com" to address(es) "info@cityofrochester.gov." | email.from.address,<br/>email.sender.address | srso+yf09=cw=pobox.com=ann@pobox.com,<br/>srso+yf09=cw=pobox.com=ann@pobox.com | Proofpoint TAP messagesBlocked: Phishing | 6aeb2aae7d8d4ef0820136f42d107db4 | QA-SPUTTA | TA0001 | Initial Access | T1566 | Phishing |


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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StellarCyber.Case.Close._id | String | Case ID | 
| StellarCyber.Case.Close.assignee | String | Case Assignee | 
| StellarCyber.Case.Close.created_at | Date | Case Created Timestamp | 
| StellarCyber.Case.Close.created_by | String | Case Created By | 
| StellarCyber.Case.Close.cust_id | String | Case Tenant ID | 
| StellarCyber.Case.Close.modified_at | Date | Case Modified Timestamp | 
| StellarCyber.Case.Close.modified_by | String | Case Modified By | 
| StellarCyber.Case.Close.name | String | Case Name | 
| StellarCyber.Case.Close.size | Number | Case Size \(Number of Alerts\) | 
| StellarCyber.Case.Close.status | String | Case Status | 
| StellarCyber.Case.Close.tags | Unknown | Case Tags | 
| StellarCyber.Case.Close.ticket_id | Number | Case Ticket ID | 
| StellarCyber.Case.Close.version | Number | Case Version | 
| StellarCyber.Case.Close.priority | String | Case Priority | 
| StellarCyber.Case.Close.incident_score | Number | Case Score | 
| StellarCyber.Case.Close.assignee_name | String | Case Assignee Name | 

#### Command example
```!stellar-close-case stellar_case_id="65f340d9b190d36b26ad2bdc" stellar_close_reason="Example..."```
#### Context Example
```json
{
    "StellarCyber": {
        "Case": {
            "Close": {
                "_id": "65f340d9b190d36b26ad2bdc",
                "assignee": "",
                "assignee_name": "Unassigned",
                "created_at": 1710440665866,
                "created_by": "System",
                "cust_id": "6aeb2aae7d8d4ef0820136f42d107db4",
                "incident_score": 30.5,
                "modified_at": 1711036884741,
                "modified_by": "9887e386323148ea8c68d4cf0bc1cdf6",
                "name": "Carbon Black: Command and Scripting Interpreter and 2 others",
                "priority": "Medium",
                "size": 3,
                "status": "Resolved",
                "tags": [],
                "ticket_id": 7167,
                "version": 3
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|_id|assignee|assignee_name|created_at|created_by|cust_id|incident_score|modified_at|modified_by|name|priority|size|status|tags|ticket_id|version|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 65f340d9b190d36b26ad2bdc |  | Unassigned | 1710440665866 | System | 6aeb2aae7d8d4ef0820136f42d107db4 | 30.5 | 1711036884741 | 9887e386323148ea8c68d4cf0bc1cdf6 | Carbon Black: Command and Scripting Interpreter and 2 others | Medium | 3 | Resolved |  | 7167 | 3 |


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
| StellarCyber.Case.Update._id | String | Case ID | 
| StellarCyber.Case.Update.assignee | String | Case Assignee | 
| StellarCyber.Case.Update.created_at | Date | Case Created Timestamp | 
| StellarCyber.Case.Update.created_by | String | Case Created By | 
| StellarCyber.Case.Update.cust_id | String | Case Tenant ID | 
| StellarCyber.Case.Update.modified_at | Date | Case Modified Timestamp | 
| StellarCyber.Case.Update.modified_by | String | Case Modified By | 
| StellarCyber.Case.Update.name | String | Case Name | 
| StellarCyber.Case.Update.size | Number | Case Size \(Number of Alerts\) | 
| StellarCyber.Case.Update.status | String | Case Status | 
| StellarCyber.Case.Update.tags | Unknown | Case Tags | 
| StellarCyber.Case.Update.ticket_id | Number | Case Ticket ID | 
| StellarCyber.Case.Update.version | Number | Case Version | 
| StellarCyber.Case.Update.priority | String | Case Priority | 
| StellarCyber.Case.Update.incident_score | Number | Case Score | 
| StellarCyber.Case.Update.assignee_name | String | Case Assignee Name | 

#### Command example
```!stellar-update-case stellar_case_id="65f340d9b190d36b26ad2bdc" stellar_case_status="New"```
#### Context Example
```json
{
    "StellarCyber": {
        "Case": {
            "Update": {
                "_id": "65f340d9b190d36b26ad2bdc",
                "assignee": "",
                "assignee_name": "Unassigned",
                "created_at": 1710440665866,
                "created_by": "System",
                "cust_id": "6aeb2aae7d8d4ef0820136f42d107db4",
                "incident_score": 30.5,
                "modified_at": 1711036888184,
                "modified_by": "9887e386323148ea8c68d4cf0bc1cdf6",
                "name": "Carbon Black: Command and Scripting Interpreter and 2 others",
                "priority": "Medium",
                "size": 3,
                "status": "New",
                "tags": [],
                "ticket_id": 7167,
                "version": 3
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|_id|assignee|assignee_name|created_at|created_by|cust_id|incident_score|modified_at|modified_by|name|priority|size|status|tags|ticket_id|version|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 65f340d9b190d36b26ad2bdc |  | Unassigned | 1710440665866 | System | 6aeb2aae7d8d4ef0820136f42d107db4 | 30.5 | 1711036888184 | 9887e386323148ea8c68d4cf0bc1cdf6 | Carbon Black: Command and Scripting Interpreter and 2 others | Medium | 3 | New |  | 7167 | 3 |


## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Stellar Cyber corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Stellar Cyber.
