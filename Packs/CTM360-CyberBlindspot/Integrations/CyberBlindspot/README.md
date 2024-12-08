Take action on incidents derived from CTM360 CBS threat intelligence that is directly linked to your organization.
This integration was integrated and tested with version `1.0.0` of CTM360_CyberBlindspot.

## Configure CTM360 CyberBlindspot in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Incident Mirroring Direction | Choose the direction to mirror the incident: Incoming \(from CyberBlindspot to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to CyberBlindspot\), or Incoming and Outgoing \(from/to Cortex XSOAR and CyberBlindspot\). | False |
| First fetch (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours. Default is `7 days`) | The time the incidents should be fetched starting from. | False |
| API Key | The CTM360 CyberBlindspot API Key to use for fetching data. | True |
| Maximum Number of Incidents per Fetch | Default is 25. Maximum is 200. | True |
| Fetch incidents |  | False |
| Date From | Set the date/time incidents should be fetched from \(setting this will always get incidents from this date/time. Normally<br/>you should not set it and rely on \`First Fetch\`\). Format should be \[%d-%m-%Y %H:%M\], i.e.: '22-01-2024 13:15'<br/> | False |
| Date To | Set the date/time incidents should be fetched up to \(setting this will always get incidents before this date/time. Normally<br/>you should not set it and rely on \`First Fetch\`\). Format should be \[%d-%m-%Y %H:%M\], i.e.: '22-01-2024 13:15'<br/> | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  |  |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ctm360-cbs-incident-list

***
Get the list of incidents from CBS.

#### Base Command

`ctm360-cbs-incident-list`

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
| CyberBlindspot.IncidentList | unknown | List of all CBS incidents. | 

#### Command example
```!ctm360-cbs-incident-list dateFrom="23-10-2023 07:00" dateTo="23-10-2023 23:00" order=asc maxHits=2```
#### Context Example
```json
{
    "CyberBlindspot": {
        "IncidentList": [
            {
                "CustomFields": {
                    "cbs_class": "Link",
                    "cbs_coa": "Member Side Action",
                    "cbs_status": "Member Feedback",
                    "cbs_subject": "2 customer credentials compromised (5d65815)",
                    "cbs_timestamp": 1698049692779,
                    "cbs_type": "Leaked Credential",
                    "cbs_updated_date": "2023-10-23T08:00:00+00:00"
                },
                "externalstatus": "Member Feedback",
                "name": "New leaked_credential with severity High found",
                "occurred": "2023-10-23T08:00:00+00:00",
                "rawJson": "{\"name\": \"New leaked_credential with severity High found\", \"occurred\": \"2023-10-23T08:00:00+00:00\", \"type\": \"Leaked Credential\", \"externalstatus\": \"Member Feedback\", \"severity\": 3, \"CustomFields\": {\"cbs_status\": \"Member Feedback\", \"cbs_subject\": \"2 customer credentials compromised (5d65815)\", \"cbs_class\": \"Link\", \"cbs_type\": \"Leaked Credential\", \"cbs_coa\": \"Member Side Action\", \"cbs_timestamp\": 1698049692779, \"cbs_updated_date\": \"2023-10-23T08:00:00+00:00\"}, \"xsoar_mirroring\": {\"mirror_direction\": \"Both\", \"mirror_id\": \"COMY123642991153\", \"mirror_instance\": \"CTM360_CyberBlindspot_instance_1\"}}",
                "severity": 3,
                "type": "Leaked Credential",
                "xsoar_mirroring": {
                    "mirror_direction": "Both",
                    "mirror_id": "COMY123642991153",
                    "mirror_instance": "CTM360_CyberBlindspot_instance_1"
                }
            },
            {
                "CustomFields": {
                    "cbs_class": "Link",
                    "cbs_coa": "Member Side Action",
                    "cbs_status": "Member Feedback",
                    "cbs_subject": "2 customer credentials compromised (a86fda8)",
                    "cbs_timestamp": 1698051145410,
                    "cbs_type": "Leaked Credential",
                    "cbs_updated_date": "2023-10-23T08:00:00+00:00"
                },
                "externalstatus": "Member Feedback",
                "name": "New leaked_credential with severity High found",
                "occurred": "2023-10-23T08:00:00+00:00",
                "rawJson": "{\"name\": \"New leaked_credential with severity High found\", \"occurred\": \"2023-10-23T08:00:00+00:00\", \"type\": \"Leaked Credential\", \"externalstatus\": \"Member Feedback\", \"severity\": 3, \"CustomFields\": {\"cbs_status\": \"Member Feedback\", \"cbs_subject\": \"2 customer credentials compromised (a86fda8)\", \"cbs_class\": \"Link\", \"cbs_type\": \"Leaked Credential\", \"cbs_coa\": \"Member Side Action\", \"cbs_timestamp\": 1698051145410, \"cbs_updated_date\": \"2023-10-23T08:00:00+00:00\"}, \"xsoar_mirroring\": {\"mirror_direction\": \"Both\", \"mirror_id\": \"COMY123073588255\", \"mirror_instance\": \"CTM360_CyberBlindspot_instance_1\"}}",
                "severity": 3,
                "type": "Leaked Credential",
                "xsoar_mirroring": {
                    "mirror_direction": "Both",
                    "mirror_id": "COMY123073588255",
                    "mirror_instance": "CTM360_CyberBlindspot_instance_1"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|CustomFields|externalstatus|name|occurred|rawJson|severity|type|xsoar_mirroring|
>|---|---|---|---|---|---|---|---|
>| cbs_status: Member Feedback<br/>cbs_subject: 2 customer credentials compromised (5d65815)<br/>cbs_class: Link<br/>cbs_type: Leaked Credential<br/>cbs_coa: Member Side Action<br/>cbs_timestamp: 1698049692779<br/>cbs_updated_date: 2023-10-23T08:00:00+00:00 | Member Feedback | New leaked_credential with severity High found | 2023-10-23T08:00:00+00:00 | {"name": "New leaked_credential with severity High found", "occurred": "2023-10-23T08:00:00+00:00", "type": "Leaked Credential", "externalstatus": "Member Feedback", "severity": 3, "CustomFields": {"cbs_status": "Member Feedback", "cbs_subject": "2 customer credentials compromised (5d65815)", "cbs_class": "Link", "cbs_type": "Leaked Credential", "cbs_coa": "Member Side Action", "cbs_timestamp": 1698049692779, "cbs_updated_date": "2023-10-23T08:00:00+00:00"}, "xsoar_mirroring": {"mirror_direction": "Both", "mirror_id": "COMY123642991153", "mirror_instance": "CTM360_CyberBlindspot_instance_1"}} | 3 | Leaked Credential | mirror_direction: Both<br/>mirror_id: COMY123642991153<br/>mirror_instance: CTM360_CyberBlindspot_instance_1 |
>| cbs_status: Member Feedback<br/>cbs_subject: 2 customer credentials compromised (a86fda8)<br/>cbs_class: Link<br/>cbs_type: Leaked Credential<br/>cbs_coa: Member Side Action<br/>cbs_timestamp: 1698051145410<br/>cbs_updated_date: 2023-10-23T08:00:00+00:00 | Member Feedback | New leaked_credential with severity High found | 2023-10-23T08:00:00+00:00 | {"name": "New leaked_credential with severity High found", "occurred": "2023-10-23T08:00:00+00:00", "type": "Leaked Credential", "externalstatus": "Member Feedback", "severity": 3, "CustomFields": {"cbs_status": "Member Feedback", "cbs_subject": "2 customer credentials compromised (a86fda8)", "cbs_class": "Link", "cbs_type": "Leaked Credential", "cbs_coa": "Member Side Action", "cbs_timestamp": 1698051145410, "cbs_updated_date": "2023-10-23T08:00:00+00:00"}, "xsoar_mirroring": {"mirror_direction": "Both", "mirror_id": "COMY123073588255", "mirror_instance": "CTM360_CyberBlindspot_instance_1"}} | 3 | Leaked Credential | mirror_direction: Both<br/>mirror_id: COMY123073588255<br/>mirror_instance: CTM360_CyberBlindspot_instance_1 |


### ctm360-cbs-incident-close

***
Close a CBS incident.

#### Base Command

`ctm360-cbs-incident-close`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | "Ticket ID" of the incident to close. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!ctm360-cbs-incident-close ticketId="COMX41148897294"```
#### Human Readable Output

>Incident closed successfully

### ctm360-cbs-incident-request-takedown

***
Request a takedown of the asset where the incident was found.

#### Base Command

`ctm360-cbs-incident-request-takedown`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | "Ticket ID" of the incident to request takedown. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!ctm360-cbs-incident-request-takedown ticketId="COMX415993788418"```
#### Human Readable Output

>Takedown request executed successfully

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
### ctm360-cbs-incident-details

***
Fetch details of a single incident from the CyberBlindspot platform.

#### Base Command

`ctm360-cbs-incident-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | "Ticket ID" of the incident to close. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberBlindspot.RemoteIncident.id | unknown | Unique ID for the incident record. | 
| CyberBlindspot.RemoteIncident.brand | unknown | The organization the incident is associated with. | 
| CyberBlindspot.RemoteIncident.coa | unknown | The course of action to take. | 
| CyberBlindspot.RemoteIncident.class | unknown | The classification of the incident on remote server. | 
| CyberBlindspot.RemoteIncident.status | unknown | The current status of the incident on remote server. | 
| CyberBlindspot.RemoteIncident.severity | unknown | The severity of the incident. | 
| CyberBlindspot.RemoteIncident.subject | unknown | Asset or title of incident. | 
| CyberBlindspot.RemoteIncident.type | unknown | Incident type. | 
| CyberBlindspot.RemoteIncident.remarks | unknown | Remarks about the incident. | 
| CyberBlindspot.RemoteIncident.created_date | unknown | The creation date of the incident. | 
| CyberBlindspot.RemoteIncident.updated_date | unknown | The date the incident last got updated. | 
| CyberBlindspot.RemoteIncident.timestamp | unknown | The timestamp of when the record was created. | 

#### Command example
```!ctm360-cbs-incident-details ticketId="COMY24510321162"```
#### Context Example
```json
{
    "CyberBlindspot": {
        "RemoteIncident": {
            "brand": "Mock Brand",
            "class": "Link",
            "coa": "Member Side Action",
            "created_date": "04-01-2024 04:55:50 AM",
            "id": "COMY24510321162",
            "remarks": "New leaked_credential with severity High found",
            "severity": "High",
            "status": "Closed",
            "subject": "157 customer credentials compromised (14dfy73)",
            "timestamp": 1704344150478,
            "type": "Leaked Credential",
            "updated_date": "04-01-2024 07:51:42 AM"
        }
    }
}
```

#### Human Readable Output

>### Results
>|brand|class|coa|created_date|id|remarks|severity|status|subject|timestamp|type|updated_date|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| Mock Brand | Link | Member Side Action | 04-01-2024 04:55:50 AM | COMY24510321162 | New leaked_credential with severity High found | High | Closed | 157 customer credentials compromised (14dfy73) | 1704344150478 | Leaked Credential | 04-01-2024 07:51:42 AM |


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

You can enable incident mirroring between Cortex XSOAR incidents and CTM360 CyberBlindspot corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in CTM360 CyberBlindspot events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in CTM360 CyberBlindspot events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and CTM360 CyberBlindspot events will be reflected in both directions. |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and CTM360 CyberBlindspot.