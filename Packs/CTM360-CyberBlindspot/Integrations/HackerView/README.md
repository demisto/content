External Attack Surface Management platform, which combines automated asset discovery, issue identification / management, remediation guidelines, security ratings and third party risk management.
This integration was integrated and tested with version `1.0.0` of CTM360_HackerView.

## Configure CTM360 HackerView in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from HackerView to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to HackerView\), or Incoming and Outgoing \(from/to Cortex XSOAR and HackerView\). | False |
| First fetch (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours. Default is `7 days`) | The time the incidents should be fetched starting from. | False |
| API Key | The CTM360 HackerView API Key to use for fetching data. | True |
| Maximum Number of Incidents per Fetch | Default is 25. Maximum is 200. | True |
| Fetch incidents |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

Test of mirroring! 1. 2. 3. 4.

### ctm360-hv-incident-list

***
Get the list of incidents from HV.

#### Base Command

`ctm360-hv-incident-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dateFrom | Select "From" date to fetch incidents starting from it. | Optional | 
| dateTo | Select "To" date to fetch incidents up to it. | Optional | 
| maxHits | Set number of results to fetch. | Optional | 
| order | Set the order of the results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HackerView.IncidentList | unknown | List of all HV incidents. | 

### ctm360-hv-incident-status-change

***
Change status of a HV incident and optionally add a comment.

#### Base Command

`ctm360-hv-incident-status-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | "ID" of the incident to change status. | Required | 
| ticketStatus | New "Status" of incident. | Required | 
| comment | "Comment" to accompany the status change (Optional). | Optional | 

#### Context Output

There is no context output for this command.

### get-mapping-fields

***
Returns the list of fields for an incident type.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### ctm360-hv-incident-details

***
Fetch details of a single incident from the HackerView platform.

#### Base Command

`ctm360-hv-incident-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | "Ticket ID" of the incident to fetch. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HackerView.RemoteIncident.id | unknown | Symbolic Incident ID | 
| HackerView.RemoteIncident.timestamp | unknown | DB timestamp | 
| HackerView.RemoteIncident.confidence | unknown | Confidence of report | 
| HackerView.RemoteIncident.cve_id | unknown | ID of associated CVE | 
| HackerView.RemoteIncident.cwe | unknown | List of associated CWEs | 
| HackerView.RemoteIncident.issue_category | unknown | Category of Incident | 
| HackerView.RemoteIncident.issue_name | unknown | Name of Incident | 
| HackerView.RemoteIncident.potential_attack_type | unknown | Potential attack to make use of incident | 
| HackerView.RemoteIncident.potential_impact | unknown | Potential impact of incident | 
| HackerView.RemoteIncident.status | unknown | Active status of Incident | 
| HackerView.RemoteIncident.progress_status | unknown | Progress of incident response | 
| HackerView.RemoteIncident.severity | unknown | Severity of incident | 
| HackerView.RemoteIncident.resolved_ip | unknown | IP resolved on affected asset | 
| HackerView.RemoteIncident.first_seen | unknown | Incident creation date | 
| HackerView.RemoteIncident.last_seen | unknown | Last discovery date for incident | 
| HackerView.RemoteIncident.last_updated | unknown | Last update date for incident | 
| HackerView.RemoteIncident.environments | unknown | env | 
| HackerView.RemoteIncident.ticket_id | unknown | Ticket ID | 
| HackerView.RemoteIncident.technologies | unknown | Technologies on affected asset | 
| HackerView.RemoteIncident.domain | unknown | domain of affected asset | 
| HackerView.RemoteIncident.host | unknown | host of affected asset | 
| HackerView.RemoteIncident.asset_type | unknown | affected asset type | 
| HackerView.RemoteIncident.asset | unknown | affected asset | 

### get-remote-data

***
Gets remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The incident ID. | Required | 
| lastUpdate | Retrieves entries that were created after lastUpdate. | Required | 

#### Context Output

There is no context output for this command.

### get-modified-remote-data

***
Gets the list of incidents that were modified since the last update time. Note that this method is here for debugging purposes. The get-modified-remote-data command is used as part of a Mirroring feature, which is available in Cortex XSOAR from version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | A date string in local time representing the last time the incident was updated. The incident is only returned if it was modified after the last update time. | Required | 

#### Context Output

There is no context output for this command.

### update-remote-system

***
Updates the remote system with local changes.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remoteId | Remote ID of incident to update in the remote system. | Required | 

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and CTM360 HackerView corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in CTM360 HackerView events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in CTM360 HackerView events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and CTM360 HackerView events will be reflected in both directions. |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and CTM360 HackerView.
