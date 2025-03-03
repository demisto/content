Use the Proofpoint Threat Response integration to orchestrate and automate incident response.

## Configure Proofpoint Threat Response in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://192.168.0.1) |  | True |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch timestamp ("number" "time unit", e.g., 12 hours, 7 days) | The time range for the initial data fetch. If timeout errors occur, consider changing this value. | False |
| Fetch limit - maximum number of incidents per fetch  |  | False |
| Fetch delta - The delta time in each batch. e.g. 1 hour, 3 minutes.  | The time range between create_after and created_before that is sent to the API when fetching older incidents. If timeout errors occur, consider changing this value. | False |
| Fetch incidents with specific event sources. Can be a list of comma separated values. |  | False |
| Fetch incidents with specific 'Abuse Disposition' values. Can be a list of comma separated values. |  | False |
| Fetch incident with specific states. |  | False |
| POST URL of the JSON alert source. | You can find this value by navigating to Sources -> JSON event source -> POST URL. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### proofpoint-tr-get-list
***
Gets items for the specified list.


#### Base Command

`proofpoint-tr-get-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list-id | The ID of the list. | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-add-to-list
***
Adds a member to the specified list.


#### Base Command

`proofpoint-tr-add-to-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list-id | The list to add a member to. | Required | 
| indicator | A comma-separated list of indicator values. Can be IP addresses, URLs, domains, or file hashes.<br/>For example: "192.168.1.1,192.168.1.2". | Required | 
| comment | A comment about the member. | Optional | 
| expiration | The expiration of the member. | Optional | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-block-ip
***
Adds the supplied IP addresses to the specified IP block list.


#### Base Command

`proofpoint-tr-block-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IP addresses to block list. | Required | 
| expiration | The date and time the supplied IP addresses should be removed from the block list, in the format YYYY-MM-DDTHH:MM:SSZ.<br/>For example: 2020-02-02T19:00:00Z. | Optional | 
| blacklist_ip | The ID of the IP block list. | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-block-domain
***
Adds the supplied domains to the specified block list.

#### Base Command

`proofpoint-tr-block-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains to add to the block list. | Required | 
| expiration | The date and time the supplied IP addresses should be removed from the block list, in the format YYYY-MM-DDTHH:MM:SSZ.<br/> For example: 2020-02-02T19:00:00Z. | Optional | 
| blacklist_domain | The ID of the domain block list. | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-search-indicator
***
Returns indicators from the specified list, according to the defined filter.

#### Base Command

`proofpoint-tr-search-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list-id | The ID of the list in which to search. | Required | 
| filter | The filter for the indicator search.<br/>For example, "1.1" will return [1.1.1.1, 22.22.1.1, 1.1.22.22]. | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-delete-indicator
***
Deletes an indicator from the specified list.

#### Base Command

`proofpoint-tr-delete-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list-id | ID of the list from which to delete indicators. | Required | 
| indicator | The indicator value to delete from the list. Can be an IP address, URL, domain, or file hash.<br/>For example: "demisto.com". | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-block-url
***
Adds the supplied URLs to the specified URL block list.

#### Base Command

`proofpoint-tr-block-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | A comma-separated list of URLs to add to the URL block list. | Required | 
| expiration | The date and time the supplied URLs should be removed from the block list, in the format YYYY-MM-DDTHH:MM:SSZ.<br/>For example: 2020-02-02T19:00:00Z. | Optional | 
| blacklist_url | The ID of the URL block list. | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-block-hash
***
Adds the supplied file hashes to the specified file hash block list.

#### Base Command

`proofpoint-tr-block-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | A comma-separated list of file hashes to add to the file hash block list. | Required | 
| expiration | The date and time the supplied file hashes should be removed from the block list, in the format YYYY-MM-DDTHH:MM:SSZ.<br/>For example: 2020-02-02T19:00:00Z. | Optional | 
| blacklist_hash | The ID of the hash block list. | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-list-incidents
***
Retrieves all incident metadata from Threat Response by specifying filter criteria such as the state of the incident or time of closure.

#### Base Command

`proofpoint-tr-list-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | State of the incidents to retrieve. Possible values are: new, open, assigned, closed, ignored. | Optional | 
| created_after | Retrieve incidents that were created after this date, in ISO 8601 format (UTC).<br/>Example: 2020-02-22 or 2020-02-22T00:00:00Z. Possible values are: . | Optional | 
| created_before | Retrieve incidents that were created before this date, in ISO 8601 format (UTC).<br/>Example: 2020-02-22 or 2020-02-22T00:00:00Z. | Optional | 
| closed_after | Retrieve incidents that were closed after this date, in ISO 8601 format (UTC).<br/>Example: 2020-02-22 or 2020-02-22T00:00:00Z. | Optional | 
| closed_before | Retrieve incidents that were closed before this date, in ISO 8601 format (UTC).<br/>Example: 2020-02-22 or 2020-02-22T00:00:00Z. | Optional | 
| expand_events |  If false, will return an array of event IDs instead of full event objects. This will significantly speed up the response time of the API for incidents with large numbers of alerts. | Optional | 
| limit | The maximum number of incidents to return. The default value is 50. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointTRAP.Incident.id | Number | The incident ID. | 
| ProofPointTRAP.Incident.summary | String | The summary of the incident. | 
| ProofPointTRAP.Incident.score | Number | The score of the incident from Proofpoint. | 
| ProofPointTRAP.Incident.state | String | The state of the incident. Can be - Open, Closed, New, Assigned, Ignored. | 
| ProofPointTRAP.Incident.created_at | Date | The date the incident was created. | 
| ProofPointTRAP.Incident.updated_at | Date | The date the incident was last updated. | 
| ProofPointTRAP.Incident.event_count | Number | The number of events attached to the incident. | 
| ProofPointTRAP.Incident.false_positive_count | Number | The number of false positive events in the incident. | 
| ProofPointTRAP.Incident.event_sources | String | The sources of the events. | 
| ProofPointTRAP.Incident.assignee | String | The user assigned to the incident. | 
| ProofPointTRAP.Incident.team | String | The team assigned to the incident. | 
| ProofPointTRAP.Incident.hosts.attacker | String | The host attacker. | 
| ProofPointTRAP.Incident.hosts.forensics | String | The host forensics. | 
| ProofPointTRAP.Incident.incident_field_values.Severity | String | The severity of the incident. | 
| ProofPointTRAP.Incident.incident_field_values.Abuse_disposition | String | The abuse disposition of the incident. | 
| ProofPointTRAP.Incident.incident_field_values.Attack_vector | String | The attack vector of the incident. | 
| ProofPointTRAP.Incident.incident_field_values.Classification | String | The classification of the incident. | 
| ProofPointTRAP.Incident.events.id | Number | The event ID. | 
| ProofPointTRAP.Incident.events.category | String | The event category. | 
| ProofPointTRAP.Incident.events.alertType | String | The alert type of the event. | 
| ProofPointTRAP.Incident.events.severity | String | The severity of the event. | 
| ProofPointTRAP.Incident.events.source | String | The source of the event. | 
| ProofPointTRAP.Incident.events.state | String | The state of the event. | 
| ProofPointTRAP.Incident.events.attackDirection | String | The attack direction of the event. | 
| ProofPointTRAP.Incident.events.received | Date | The time the incident was received. | 
| ProofPointTRAP.Incident.events.emails.sender | String | The sender of the email. | 
| ProofPointTRAP.Incident.events.emails.recipient | String | The recipient of the email. | 
| ProofPointTRAP.Incident.events.emails.message_Id | String | The message ID of the email. | 
| ProofPointTRAP.Incident.events.emails.message_delivery_time | Number | The delivery time of the message. | 
| ProofPointTRAP.Incident.events.attackers.location | String | The location of the attacker. | 
| ProofPointTRAP.Incident.events.falsePositive | Boolean | Whether this incident is a false positive. | 
| ProofPointTRAP.Incident.events.threatname | String | The threat name. | 
| ProofPointTRAP.Incident.events.description | String | The description of the event. | 
| ProofPointTRAP.Incident.events.malwareName | String | The malware name. | 
| ProofPointTRAP.Incident.quarantine_results.alertSource | String | The alert source. | 
| ProofPointTRAP.Incident.quarantine_results.startTime | Date | The start time of the result. | 
| ProofPointTRAP.Incident.quarantine_results.endTime | Date | The end time of the result. | 
| ProofPointTRAP.Incident.quarantine_results.status | String | The status of the result. | 
| ProofPointTRAP.Incident.quarantine_results.recipientType | String | The recipient type. | 
| ProofPointTRAP.Incident.quarantine_results.recipient | String | The recipient email address. | 
| ProofPointTRAP.Incident.quarantine_results.messageId | String | The message ID. | 
| ProofPointTRAP.Incident.quarantine_results.isRead | Boolean | Whether the message has been read. | 
| ProofPointTRAP.Incident.quarantine_results.wasUndone | String | Whether the message was undone. | 
| ProofPointTRAP.Incident.quarantine_results.details | String | The details about the result. | 
| ProofPointTRAP.Incident.successful_quarantines | Number | The number of successful quarantines. | 
| ProofPointTRAP.Incident.failed_quarantines | Number | The number of failed quarantines. | 
| ProofPointTRAP.Incident.pending_quarantines | Number | The number of pending quarantines. | 
| ProofPointTRAP.Incident.events.emails.body | String | The body of the email. | 
| ProofPointTRAP.Incident.events.emails.body_type | String | The format of the body. | 
| ProofPointTRAP.Incident.events.emails.headers | Unknown | The email headers. | 
| ProofPointTRAP.Incident.events.emails.urls | Unknown | The list of URLs from the email. | 
| ProofPoint.Incident.event_ids | Unknown | The list of IDs attached to the incident. | 


### proofpoint-tr-get-incident
***
Retrieves incident metadata from Threat Response.


#### Base Command

`proofpoint-tr-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID value of the incident to retrieve (e.g. for incident INC-4000, the input for this argument should be 4000). | Required | 
| expand_events | If false, will return an array of event IDs instead of full event objects. This will significantly speed up the response time of the API for incidents with large numbers of alerts. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointTRAP.Incident.id | Number | The incident ID. | 
| ProofPointTRAP.Incident.summary | String | The summary of the incident. | 
| ProofPointTRAP.Incident.score | Number | The score of the incident from Proofpoint. | 
| ProofPointTRAP.Incident.state | String | The state of the incident. Can be - Open, Closed, New, Assigned, Ignored. | 
| ProofPointTRAP.Incident.created_at | Date | The date the incident was created. | 
| ProofPointTRAP.Incident.updated_at | Date | The date the incident was last updated. | 
| ProofPointTRAP.Incident.event_count | Number | The number of events attached to the incident. | 
| ProofPointTRAP.Incident.false_positive_count | Number | The number of false positive events in the incident. | 
| ProofPointTRAP.Incident.event_sources | String | The sources of the events. | 
| ProofPointTRAP.Incident.assignee | String | The user assigned to the incident. | 
| ProofPointTRAP.Incident.team | String | The team assigned to the incident. | 
| ProofPointTRAP.Incident.hosts.attacker | String | The host attacker. | 
| ProofPointTRAP.Incident.hosts.forensics | String | The host forensics. | 
| ProofPointTRAP.Incident.incident_field_values.Severity | String | The severity of the incident. | 
| ProofPointTRAP.Incident.incident_field_values.Abuse_disposition | String | The abuse disposition of the incident. | 
| ProofPointTRAP.Incident.incident_field_values.Attack_vector | String | The attack vector of the incident. | 
| ProofPointTRAP.Incident.incident_field_values.Classification | String | The classification of the incident. | 
| ProofPointTRAP.Incident.events.id | Number | The event ID. | 
| ProofPointTRAP.Incident.events.category | String | The event category. | 
| ProofPointTRAP.Incident.events.alertType | String | The alert type of the event. | 
| ProofPointTRAP.Incident.events.severity | String | The severity of the event. | 
| ProofPointTRAP.Incident.events.source | String | The source of the event. | 
| ProofPointTRAP.Incident.events.state | String | The state of the event. | 
| ProofPointTRAP.Incident.events.attackDirection | String | The attack direction of the event | 
| ProofPointTRAP.Incident.events.received | Date | The date the incident was received. | 
| ProofPointTRAP.Incident.events.emails.sender | String | The sender of the email. | 
| ProofPointTRAP.Incident.events.emails.recipient | String | The recipient of the email. | 
| ProofPointTRAP.Incident.events.emails.message_Id | String | The message ID of the email. | 
| ProofPointTRAP.Incident.events.emails.message_delivery_time | Number | The time the message was delivered. | 
| ProofPointTRAP.Incident.events.attackers.location | String | The location of the attacker. | 
| ProofPointTRAP.Incident.events.falsePositive | Boolean | Whether this incident is a false positive. | 
| ProofPointTRAP.Incident.events.threatname | String | The threat name. | 
| ProofPointTRAP.Incident.events.description | String | The description of the event. | 
| ProofPointTRAP.Incident.events.malwareName | String | The malware name. | 
| ProofPointTRAP.Incident.quarantine_results.alertSource | String | The alert source. | 
| ProofPointTRAP.Incident.quarantine_results.startTime | Date | The start time of the result. | 
| ProofPointTRAP.Incident.quarantine_results.endTime | Date | The end time of the result. | 
| ProofPointTRAP.Incident.quarantine_results.status | String | The status of the result. | 
| ProofPointTRAP.Incident.quarantine_results.recipientType | String | The recipient type. | 
| ProofPointTRAP.Incident.quarantine_results.recipient | String | The recipient email address. | 
| ProofPointTRAP.Incident.quarantine_results.messageId | String | The message ID. | 
| ProofPointTRAP.Incident.quarantine_results.isRead | Boolean | Whether the message has been read. | 
| ProofPointTRAP.Incident.quarantine_results.wasUndone | String | Whether the message was undone. | 
| ProofPointTRAP.Incident.quarantine_results.details | String | The details about the result. | 
| ProofPointTRAP.Incident.successful_quarantines | Number | The number of successful quarantines. | 
| ProofPointTRAP.Incident.failed_quarantines | Number | The number of failed quarantines. | 
| ProofPointTRAP.Incident.pending_quarantines | Number | The number of pending quarantines. | 
| ProofPointTRAP.Incident.events.emails.body | String | The body of the email. | 
| ProofPointTRAP.Incident.events.emails.body_type | String | The format of the body. | 
| ProofPointTRAP.Incident.events.emails.headers | Unknown | The email headers. | 
| ProofPointTRAP.Incident.events.emails.urls | Unknown | The list of URLs from the email. | 
| ProofPoint.Incident.event_ids | Unknown | The list of IDs attached to the incident. | 


### proofpoint-tr-update-incident-comment
***
Adds comments to an existing Threat Response incident, by incident ID.

#### Base Command

`proofpoint-tr-update-incident-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID value of the incident to add the comment to (e.g. for incident INC-4000, the input for this argument should be 4000). | Required | 
| details | The details of the comments. | Required | 
| comments | The summary of the comments. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ProofPointTRAP.IncidentComment.id | Number | The ID of the comment. | 
| ProofPointTRAP.IncidentComment.incident_id | Number | The ID of the incident. | 
| ProofPointTRAP.IncidentComment.response_id | Number | The ID of the response. | 
| ProofPointTRAP.IncidentComment.user_id | String | The ID of the user. | 
| ProofPointTRAP.IncidentComment.history_type | String | The history type. | 
| ProofPointTRAP.IncidentComment.state_from | String | The state from of the incident. | 
| ProofPointTRAP.IncidentComment.state_to | String | The state to of the incident. | 
| ProofPointTRAP.IncidentComment.summary | String | The summary of the comments. | 
| ProofPointTRAP.IncidentComment.detail | String | The details of the comment. | 
| ProofPointTRAP.IncidentComment.created_at | Date | The date the incident was created. | 
| ProofPointTRAP.IncidentComment.updated_at | Date | The date the incident was last updated. | 


### proofpoint-tr-add-user-to-incident
***
Assigns a user to an incident as a target or attacker.

#### Base Command

`proofpoint-tr-add-user-to-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID value of the incident to add the user to (e.g. for incident INC-4000, the input for this argument should be 4000). | Required | 
| targets | The list of targets to add to the incident. | Required | 
| attackers | The list of attackers to add to the incident. | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-ingest-alert
***
Ingest an alert into Threat Response.

#### Base Command

`proofpoint-tr-ingest-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| post_url_id | The POST URL of the JSON alert source. You can find it by navigating to Sources -&gt; JSON event source -&gt; POST URL. | Optional | 
| json_version | The Threat Response JSON version.<br/>Possible values are: 2.0, 1.0. Default is 2.0. | Required | 
| attacker | An attacker object in JSON format : "{"attacker" : {...}}". The attacker object must contain one of ["ip_address", mac_address", "host_name", "url", "user"] keys. You can also add the "port" key to the object. For more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0". | Optional | 
| classification | The alert classification shown as "Alert Type" in the TRAP UI.<br/>Possible values are: malware, policy-violation, vulnerability, network, spam, phish, command-and-control, data-match, authentication, system-behavior, impostor, reported-abuse, unknown. | Optional | 
| cnc_hosts | The Command and Control host information in JSON format : "{"cnc_hosts": [{"host" : "-", "port": "-"}, ...]}".<br/>Note: Every item of the "cnc_hosts" list is in JSON format. For more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0". | Optional | 
| detector | The threat detection tool such as Firewall and IPS/IDS systems (in the format: "{"detector" : {...}}"), which generated the original alert. To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0". | Optional | 
| email | The email metadata related to the alert, in JSON format: "{"email": {...}}". To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0". | Optional | 
| forensics_hosts | The forensics host information in JSON format : "{"forensics_hosts": [{"host" : "-", "port": "-"}...]}".<br/>Note: Every item of the "forensics_hosts" list is in JSON format. For more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0". | Optional | 
| link_attribute | The attribute to link alerts to.<br/>Possible values are: target_ip_address, target_hostname, target_machine_name, target_user, target_mac_address, attacker_ip_address, attacker_hostname, attacker_machine_name, attacker_user, attacker_mac_address, email_recipient, email_sender, email_subject, message_id, threat_filename, threat_filehash. | Optional | 
| severity | The severity of the alert.<br/>Possible values are: info, minor, moderate, major, critical, Informational, Low, Medium, High, Critical. | Optional | 
| summary | The alert summary. This argument will populate the Alert Details field. | Optional | 
| target | The target host information in JSON format : "{"target": {...}}". To see all relevant JSON fields and for more information,  see Proofpoint TRAP documentation under "JSON Alert Source 2.0". | Optional | 
| threat_info | The threat information in JSON format: "{"threat_info": {...}}". To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0". | Optional | 
| custom_fields | A JSON object for collecting custom name-value pairs as part of the JSON alert sent to Threat Response, in the format: "{"custom_fields": {..}}". Although there is no limit to the number of custom fields, Proofpoint recommends keeping it to 10 or fewer fields. To see all relevant JSON fields and for more information, see Proofpoint TRAP documentation under "JSON Alert Source 2.0". | Optional | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-close-incident
***
Close an incident

#### Base Command

`proofpoint-tr-close-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID value of the incident to close. | Required | 
| details | The details for the closure notes. | Required | 
| summary | The summary for the closure notes. | Required | 


#### Context Output

There is no context output for this command.

### proofpoint-tr-verify-quarantine
***
Verify if an email has been quarantined.

#### Base Command

`proofpoint-tr-verify-quarantine`
#### Input

| **Argument Name** | **Description**                           | **Required** |
|-------------------|-------------------------------------------| --- |
| message_id        | The ID value of an email.                  | True | 
| time              | The creation time of the incident in the format YYYY-MM-DDTHH:MM:SSZ. For example: 2020-02-02T19:00:00Z. | True | 
| recipient         | The email recipient. | True | 
| limit_quarantine_occurred_time | Whether or not to limit the results to include only quarantines that occurred within a limited time after alert creation. Automated quarantine actions for example typically occur within 120 seconds of alert firing. Manual actions executed by human may take longer. Default is True.| False |
| quarantine_limit | Only used if 'limit_quarantine_occurred_time' argument is set to true. Sets a limit on the quarantines retrieved to include only those where the time difference between alert time and quarantined time is less than the number of seconds specified. The time is in seconds. Default is 120. | False|
| fetch_delta | The time frame (in hours) used to identify the size of batches when retrieving the messages. e.g., 12. Default is 6. | False |


#### Context Output

| **Path**                     | **Type** | **Description**          |
|------------------------------|----------|--------------------------|
| ProofPointTRAP.Quarantine | String | The result of the quarantine. | 
#### Command Example
``` !proofpoint-tr-verify-quarantine messageid=<message_id_example> time="2022-06-02T17:22:45Z" recipient=example@example.com```

#### Context Example
```json
{
    "ProofPointTRAP": {
        "Quarantine": [
            {
                "alert": {
                    "id": 1030,
                    "time": "2022-06-02T17:33:18Z"
                },
                "incident": {
                    "id": 265,
                    "time": "2022-06-02T17:33:18Z"
                },
                "quarantine": {
                    "alertSource": "Admin Portal",
                    "details": "Success",
                    "endTime": "2022-06-02T17:33:37.926Z",
                    "isRead": "false",
                    "messageId": "message_id_example",
                    "recipient": "example@example.com",
                    "recipientType": "Original Recipient",
                    "startTime": "2022-06-02T17:33:20.352Z",
                    "status": "successful",
                    "wasUndone": "false"
                }
            },
            {
                "alert": {
                    "id": 1030,
                    "time": "2022-06-02T17:33:18Z"
                },
                "incident": {
                    "id": 265,
                    "time": "2022-06-02T17:33:18Z"
                },
                "quarantine": {
                    "alertSource": "Admin Portal",
                    "details": "Success",
                    "endTime": "2022-06-02T17:33:37.321Z",
                    "isRead": "false",
                    "messageId": "message_id_example",
                    "recipient": "example@example.com",
                    "recipientType": "Original Recipient",
                    "startTime": "2022-06-02T17:33:20.283Z",
                    "status": "successful",
                    "wasUndone": "false"
                }
            }
        ]
    }
}

```