Cortex Core is the world's first detection and response app that natively integrates network, endpoint, and cloud data to stop sophisticated attacks.
This integration was integrated and tested with version xx of Cortex Core - IR

## Configure Investigation & Response on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Investigation & Response.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Incident Mirroring Direction |  | False |
    | Server URL (copy URL from Core - click ? to see more info.) |  | True |
    | API Key ID |  | True |
    | API Key |  | True |
    | HTTP Timeout | The timeout of the HTTP requests sent to Cortex Core API \(in seconds\). | False |
    | Maximum number of incidents per fetch | The maximum number of incidents per fetch. Cannot exceed 100. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Sync Incident Owners | For Cortex XSOAR version 6.0.0 and above. If selected, for every incident fetched from Cortex Core to Cortex XSOAR, the incident owners will be synced. Note that once this value is changed and synchronized between the systems, additional changes will not be reflected. For example, if you change the owner in Cortex XSOAR, the new owner will also be changed in Cortex Core. However, if you now change the owner back in Cortex Core, this additional change will not be reflected in Cortex XSOAR. In addition, for this change to be reflected, the owners must exist in both Cortex XSOAR and Cortex Core. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incident Statuses to Fetch | The statuses of the incidents that will be fetched. If no status is provided then incidents of all the statuses will be fetched. Note: An incident whose status was changed to a filtered status after its creation time will not be fetched. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### core-get-incidents
***
Returns a list of incidents, which you can filter by a list of incident IDs (max. 100), the time the incident was last modified, and the time the incident was created.
If you pass multiple filtering arguments, they will be concatenated using the AND condition. The OR condition is not supported.


#### Base Command

`core-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or before the specified date/time will be retrieved. | Optional | 
| gte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or after the specified date/time will be retrieved. | Optional | 
| lte_modification_time | Filters returned incidents that were created on or before the specified date/time, in the format 2019-12-31T23:59:00. | Optional | 
| gte_modification_time | Filters returned incidents that were modified on or after the specified date/time, in the format 2019-12-31T23:59:00. | Optional | 
| incident_id_list | An array or CSV string of incident IDs. | Optional | 
| since_creation_time | Filters returned incidents that were created on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. | Optional | 
| since_modification_time | Filters returned incidents that were modified on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. | Optional | 
| sort_by_modification_time | Sorts returned incidents by the date/time that the incident was last modified ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of incidents to return per page. The default and maximum is 100. Default is 100. | Optional | 
| status | Filters only incidents in the specified status. The options are: new, under_investigation, resolved_known_issue, resolved_false_positive, resolved_true_positive resolved_security_testing, resolved_other, resolved_auto. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Incident.incident_id | String | Unique ID assigned to each returned incident. | 
| PaloAltoNetworksCore.Incident.manual_severity | String | Incident severity assigned by the user. This does not affect the calculated severity. Can be "low", "medium", "high" | 
| PaloAltoNetworksCore.Incident.manual_description | String | Incident description provided by the user. | 
| PaloAltoNetworksCore.Incident.assigned_user_mail | String | Email address of the assigned user. | 
| PaloAltoNetworksCore.Incident.high_severity_alert_count | String | Number of alerts with the severity HIGH. | 
| PaloAltoNetworksCore.Incident.host_count | number | Number of hosts involved in the incident. | 
| PaloAltoNetworksCore.Incident.core_url | String | A link to the incident view on Core. | 
| PaloAltoNetworksCore.Incident.assigned_user_pretty_name | String | Full name of the user assigned to the incident. | 
| PaloAltoNetworksCore.Incident.alert_count | number | Total number of alerts in the incident. | 
| PaloAltoNetworksCore.Incident.med_severity_alert_count | number | Number of alerts with the severity MEDIUM. | 
| PaloAltoNetworksCore.Incident.user_count | number | Number of users involved in the incident. | 
| PaloAltoNetworksCore.Incident.severity | String | Calculated severity of the incident. Valid values are:
"low","medium","high"
 | 
| PaloAltoNetworksCore.Incident.low_severity_alert_count | String | Number of alerts with the severity LOW. | 
| PaloAltoNetworksCore.Incident.status | String | Current status of the incident. Valid values are: "new","under_investigation","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_true_positive","resolved_security_testing" or "resolved_other".
 | 
| PaloAltoNetworksCore.Incident.description | String | Dynamic calculated description of the incident. | 
| PaloAltoNetworksCore.Incident.resolve_comment | String | Comments entered by the user when the incident was resolved. | 
| PaloAltoNetworksCore.Incident.notes | String | Comments entered by the user regarding the incident. | 
| PaloAltoNetworksCore.Incident.creation_time | date | Date and time the incident was created on Core. | 
| PaloAltoNetworksCore.Incident.detection_time | date | Date and time that the first alert occurred in the incident. | 
| PaloAltoNetworksCore.Incident.modification_time | date | Date and time that the incident was last modified. | 

### core-get-incident-extra-data
***
Returns additional data for the specified incident, for example, related alerts, file artifacts, network artifacts, and so on.


#### Base Command

`core-get-incident-extra-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident for which to get additional data. | Required | 
| alerts_limit | Maximum number of alerts to return. Default is 1,000. Default is 1000. | Optional | 
| return_only_updated_incident | Return data only if the incident was changed since the last time it was mirrored in to XSOAR.  This flag should be used only from within a Core incident. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Incident.incident_id | String | Unique ID assigned to each returned incident. | 
| PaloAltoNetworksCore.Incident.creation_time | Date | Date and time the incident was created on Core. | 
| PaloAltoNetworksCore.Incident.modification_time | Date | Date and time that the incident was last modified. | 
| PaloAltoNetworksCore.Incident.detection_time | Date | Date and time that the first alert occurred in the incident. | 
| PaloAltoNetworksCore.Incident.status | String | Current status of the incident. Valid values are:
"new","under_investigation","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_true_positive","resolved_security_testing","resolved_other" | 
| PaloAltoNetworksCore.Incident.severity | String | Calculated severity of the incident. Valid values are: "low","medium","high" | 
| PaloAltoNetworksCore.Incident.description | String | Dynamic calculated description of the incident. | 
| PaloAltoNetworksCore.Incident.assigned_user_mail | String | Email address of the assigned user. | 
| PaloAltoNetworksCore.Incident.assigned_user_pretty_name | String | Full name of the user assigned to the incident. | 
| PaloAltoNetworksCore.Incident.alert_count | Number | Total number of alerts in the incident. | 
| PaloAltoNetworksCore.Incident.low_severity_alert_count | Number | Number of alerts with the severity LOW. | 
| PaloAltoNetworksCore.Incident.med_severity_alert_count | Number | Number of alerts with the severity MEDIUM. | 
| PaloAltoNetworksCore.Incident.high_severity_alert_count | Number | Number of alerts with the severity HIGH. | 
| PaloAltoNetworksCore.Incident.user_count | Number | Number of users involved in the incident. | 
| PaloAltoNetworksCore.Incident.host_count | Number | Number of hosts involved in the incident | 
| PaloAltoNetworksCore.Incident.notes | Unknown | Comments entered by the user regarding the incident. | 
| PaloAltoNetworksCore.Incident.resolve_comment | String | Comments entered by the user when the incident was resolved. | 
| PaloAltoNetworksCore.Incident.manual_severity | String | Incident severity assigned by the user. This does not affect the calculated severity of low, medium, or high. | 
| PaloAltoNetworksCore.Incident.manual_description | String | Incident description provided by the user. | 
| PaloAltoNetworksCore.Incident.core_url | String | A link to the incident view on Core. | 
| PaloAltoNetworksCore.Incident.starred | Boolean | Incident starred. | 
| PaloAltoNetworksCore.Incident.wildfire_hits.mitre_techniques_ids_and_names | String | Incident Mitre techniques ids and names. | 
| PaloAltoNetworksCore.Incident.wildfire_hits.mitre_tactics_ids_and_names | String | Incident Mitre tactics ids and names. | 
| PaloAltoNetworksCore.Incident.alerts.alert_id | String | Unique ID for each alert. | 
| PaloAltoNetworksCore.Incident.alerts.detection_timestamp | Date | Date and time that the alert occurred. | 
| PaloAltoNetworksCore.Incident.alerts.source | String | Source of the alert. The product/vendor this alert came from. | 
| PaloAltoNetworksCore.Incident.alerts.severity | String | Severity of the alert.Valid values are: "low","medium","high""" | 
| PaloAltoNetworksCore.Incident.alerts.name | String | Calculated name of the alert. | 
| PaloAltoNetworksCore.Incident.alerts.category | String | Category of the alert, for example, Spyware Detected via Anti-Spyware profile. | 
| PaloAltoNetworksCore.Incident.alerts.description | String | Textual description of the alert. | 
| PaloAltoNetworksCore.Incident.alerts.host_ip_list | Unknown | Host IP involved in the alert. | 
| PaloAltoNetworksCore.Incident.alerts.host_name | String | Host name involved in the alert. | 
| PaloAltoNetworksCore.Incident.alerts.user_name | String | User name involved with the alert. | 
| PaloAltoNetworksCore.Incident.alerts.event_type | String | Event type. Valid values are: "Process Execution","Network Event","File Event","Registry Event","Injection Event","Load Image Event","Windows Event Log" | 
| PaloAltoNetworksCore.Incident.alerts.action | String | The action that triggered the alert. Valid values are: "REPORTED", "BLOCKED", "POST_DETECTED", "SCANNED", "DOWNLOAD", "PROMPT_ALLOW", "PROMPT_BLOCK", "DETECTED", "BLOCKED_1", "BLOCKED_2", "BLOCKED_3", "BLOCKED_5", "BLOCKED_6", "BLOCKED_7", "BLOCKED_8", "BLOCKED_9", "BLOCKED_10", "BLOCKED_11", "BLOCKED_13", "BLOCKED_14", "BLOCKED_15", "BLOCKED_16", "BLOCKED_17", "BLOCKED_24", "BLOCKED_25", "DETECTED_0", "DETECTED_4", "DETECTED_18", "DETECTED_19", "DETECTED_20", "DETECTED_21", "DETECTED_22", "DETECTED_23" | 
| PaloAltoNetworksCore.Incident.alerts.action_pretty | String | The action that triggered the alert. Valid values are: "Detected \(Reported\)" "Prevented \(Blocked\)" "Detected \(Post Detected\)" "Detected \(Scanned\)" "Detected \(Download\)" "Detected \(Prompt Allow\)" "Prevented \(Prompt Block\)" "Detected" "Prevented \(Denied The Session\)" "Prevented \(Dropped The Session\)" "Prevented \(Dropped The Session And Sent a TCP Reset\)" "Prevented \(Blocked The URL\)" "Prevented \(Blocked The IP\)" "Prevented \(Dropped The Packet\)" "Prevented \(Dropped All Packets\)" "Prevented \(Terminated The Session And Sent a TCP Reset To Both Sides Of The Connection\)" "Prevented \(Terminated The Session And Sent a TCP Reset To The Client\)" "Prevented \(Terminated The Session And Sent a TCP Reset To The Server\)" "Prevented \(Continue\)" "Prevented \(Block-Override\)" "Prevented \(Override-Lockout\)" "Prevented \(Override\)" "Prevented \(Random-Drop\)" "Prevented \(Silently Dropped The Session With An ICMP Unreachable Message To The Host Or Application\)" "Prevented \(Block\)" "Detected \(Allowed The Session\)" "Detected \(Raised An Alert\)" "Detected \(Syncookie Sent\)" "Detected \(Forward\)" "Detected \(Wildfire Upload Success\)" "Detected \(Wildfire Upload Failure\)" "Detected \(Wildfire Upload Skip\)" "Detected \(Sinkhole\)" | 
| PaloAltoNetworksCore.Incident.alerts.actor_process_image_name | String | Image name. | 
| PaloAltoNetworksCore.Incident.alerts.actor_process_command_line | String | Command line. | 
| PaloAltoNetworksCore.Incident.alerts.actor_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash". | 
| PaloAltoNetworksCore.Incident.alerts.actor_process_signature_vendor | String | Singature vendor name. | 
| PaloAltoNetworksCore.Incident.alerts.causality_actor_process_image_name | String | Image name. | 
| PaloAltoNetworksCore.Incident.alerts.causality_actor_process_command_line | String | Command line. | 
| PaloAltoNetworksCore.Incident.alerts.causality_actor_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash" | 
| PaloAltoNetworksCore.Incident.alerts.causality_actor_process_signature_vendor | String | Signature vendor. | 
| PaloAltoNetworksCore.Incident.alerts.causality_actor_causality_id | Unknown | Causality id. | 
| PaloAltoNetworksCore.Incident.alerts.action_process_image_name | String | Image name. | 
| PaloAltoNetworksCore.Incident.alerts.action_process_image_command_line | String | Command line. | 
| PaloAltoNetworksCore.Incident.alerts.action_process_image_sha256 | String | Image SHA256. | 
| PaloAltoNetworksCore.Incident.alerts.action_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash" | 
| PaloAltoNetworksCore.Incident.alerts.action_process_signature_vendor | String | Signature vendor name. | 
| PaloAltoNetworksCore.Incident.alerts.action_file_path | String | File path. | 
| PaloAltoNetworksCore.Incident.alerts.action_file_md5 | String | File MD5. | 
| PaloAltoNetworksCore.Incident.alerts.action_file_sha256 | String | File SHA256. | 
| PaloAltoNetworksCore.Incident.alerts.action_registry_data | String | Registry data. | 
| PaloAltoNetworksCore.Incident.alerts.action_registry_full_key | String | Registry full key. | 
| PaloAltoNetworksCore.Incident.alerts.action_local_ip | String | Local IP. | 
| PaloAltoNetworksCore.Incident.alerts.action_local_port | Number | Local port. | 
| PaloAltoNetworksCore.Incident.alerts.action_remote_ip | String | Remote IP. | 
| PaloAltoNetworksCore.Incident.alerts.action_remote_port | Number | Remote port. | 
| PaloAltoNetworksCore.Incident.alerts.action_external_hostname | String | External hostname. | 
| PaloAltoNetworksCore.Incident.alerts.fw_app_id | Unknown | Firewall app id. | 
| PaloAltoNetworksCore.Incident.alerts.is_whitelisted | String | Is the alert on allow list. Valid values are: "Yes" "No" | 
| PaloAltoNetworksCore.Incident.alerts.starred | Boolean | Alert starred. | 
| PaloAltoNetworksCore.Incident.network_artifacts.type | String | Network artifact type. | 
| PaloAltoNetworksCore.Incident.network_artifacts.network_remote_port | number | The remote port related to the artifact. | 
| PaloAltoNetworksCore.Incident.network_artifacts.alert_count | number | Number of alerts related to the artifact. | 
| PaloAltoNetworksCore.Incident.network_artifacts.network_remote_ip | String | The remote IP related to the artifact. | 
| PaloAltoNetworksCore.Incident.network_artifacts.is_manual | boolean | Whether the artifact was created by the user \(manually\). | 
| PaloAltoNetworksCore.Incident.network_artifacts.network_domain | String | The domain related to the artifact. | 
| PaloAltoNetworksCore.Incident.network_artifacts.type | String | The artifact type. Valid values are: "META", "GID", "CID", "HASH", "IP", "DOMAIN", "REGISTRY", "HOSTNAME" | 
| PaloAltoNetworksCore.Incident.network_artifacts.network_country | String | The country related to the artifact. | 
| PaloAltoNetworksCore.Incident.file_artifacts.file_signature_status | String | Digital signature status of the file. Valid values are: "SIGNATURE_UNAVAILABLE" "SIGNATURE_SIGNED" "SIGNATURE_INVALID" "SIGNATURE_UNSIGNED" "SIGNATURE_WEAK_HASH" | 
| PaloAltoNetworksCore.Incident.file_artifacts.is_process | boolean | Whether the file artifact is related to a process execution. | 
| PaloAltoNetworksCore.Incident.file_artifacts.file_name | String | Name of the file. | 
| PaloAltoNetworksCore.Incident.file_artifacts.file_wildfire_verdict | String | The file verdict, calculated by Wildfire. Valid values are: "BENIGN" "MALWARE" "GRAYWARE" "PHISING" "UNKNOWN". | 
| PaloAltoNetworksCore.Incident.file_artifacts.alert_count | number | Number of alerts related to the artifact. | 
| PaloAltoNetworksCore.Incident.file_artifacts.is_malicious | boolean | Whether the artifact is malicious, as decided by the Wildfire verdict. | 
| PaloAltoNetworksCore.Incident.file_artifacts.is_manual | boolean | Whether the artifact was created by the user \(manually\). | 
| PaloAltoNetworksCore.Incident.file_artifacts.type | String | The artifact type. Valid values are: "META" "GID" "CID" "HASH" "IP" "DOMAIN" "REGISTRY" "HOSTNAME" | 
| PaloAltoNetworksCore.Incident.file_artifacts.file_sha256 | String | SHA-256 hash of the file. | 
| PaloAltoNetworksCore.Incident.file_artifacts.file_signature_vendor_name | String | File signature vendor name. | 
| Account.Username | String | The username in the relevant system. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| File.Path | String | The path where the file is located. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name \(including file extension\). | 
| Process.Name | String | The name of the process. | 
| Process.MD5 | String | The MD5 hash of the process. | 
| Process.SHA256 | String | The SHA256 hash of the process. | 
| Process.PID | String | The PID of the process. | 
| Process.Path | String | The file system path to the binary file. | 
| Process.Start Time | String | The timestamp of the process start time. | 
| Process.CommandLine | String | The full command line \(including arguments\). | 
| IP.Address | String | IP address. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| Domain.Name | String | The domain name, for example: "google.com". | 

### core-update-incident
***
Updates one or more fields of a specified incident. Missing fields will be ignored. To remove the assignment for an incident, pass a null value in the assignee email argument.


#### Base Command

`core-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Core incident ID. You can get the incident ID from the output of the 'core-get-incidents' command or the 'core-get-incident-extra-details' command. | Required | 
| manual_severity | Severity to assign to the incident (LOW, MEDIUM, or HIGH). Possible values are: HIGH, MEDIUM, LOW. | Optional | 
| assigned_user_mail | Email address of the user to assign to the incident. | Optional | 
| assigned_user_pretty_name | Full name of the user assigned to the incident. | Optional | 
| status | Status of the incident. Valid values are: NEW, UNDER_INVESTIGATION, RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE, RESOLVED_TRUE_POSITIVE, RESOLVED_SECURITY_TESTING, RESOLVED_OTHER. Possible values are: NEW, UNDER_INVESTIGATION, RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE, RESOLVED_TRUE_POSITIVE, RESOLVED_SECURITY_TESTING, RESOLVED_OTHER. | Optional | 
| resolve_comment | Comment explaining why the incident was resolved. This should be set when the incident is resolved. | Optional | 
| unassign_user | If true, will remove all assigned users from the incident. Possible values are: true. | Optional | 


#### Context Output

There is no context output for this command.
### core-insert-parsed-alert
***
Upload alert from external alert sources in Cortex Core format. Cortex Core displays alerts that are parsed
successfully in related incidents and views. You can send 600 alerts per minute. Each request can contain a
maximum of 60 alerts.


#### Base Command

`core-insert-parsed-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product | String value that defines the product. | Required | 
| vendor | String value that defines the product. | Required | 
| local_ip | String value for the source IP address. | Optional | 
| local_port | Integer value for the source port. | Required | 
| remote_ip | String value of the destination IP<br/>address. | Required | 
| remote_port | Integer value for the destination<br/>port. | Required | 
| event_timestamp | Integer value representing the epoch of the time the alert occurred in milliseconds, or a string value in date format 2019-10-23T10:00:00. If not set, the event time will be defined as now. | Optional | 
| severity | String value of alert severity. Valid values are:<br/>Informational, Low, Medium or High. Possible values are: Informational, Low, Medium, High. Default is Medium. | Optional | 
| alert_name | String defining the alert name. | Required | 
| alert_description | String defining the alert description. | Optional | 


#### Context Output

There is no context output for this command.
### core-insert-cef-alerts
***
Upload alerts in CEF format from external alert sources. After you map CEF alert fields to Cortex Core fields, Cortex Core displays the alerts in related incidents and views. You can send 600 requests per minute. Each request can contain a maximum of 60 alerts.


#### Base Command

`core-insert-cef-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cef_alerts | List of alerts in CEF format. | Required | 


#### Context Output

There is no context output for this command.
### core-isolate-endpoint
***
Isolates the specified endpoint.


#### Base Command

`core-isolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id | The endpoint ID (string) to isolate. You can retrieve the string from the core-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Whether to suppress an error when trying to isolate a disconnected endpoint. When sets to false, an error will be returned. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Isolation.endpoint_id | String | The endpoint ID. | 

### core-unisolate-endpoint
***
Reverses the isolation of an endpoint.


#### Base Command

`core-unisolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id | The endpoint ID (string) for which to reverse the isolation. You can retrieve it from the core-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Whether to suppress an error when trying to unisolate a disconnected endpoint. When sets to false, an error will be returned. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.UnIsolation.endpoint_id | String | Isolates the specified endpoint. | 

### core-get-endpoints
***
Gets a list of endpoints, according to the passed filters. If there are no filters, all endpoints are returned. Filtering by multiple fields will be concatenated using AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of endpoint from the start of the result set (start by counting from 0).


#### Base Command

`core-get-endpoints`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id_list | A comma-separated list of endpoint IDs. | Optional | 
| dist_name | A comma-separated list of distribution package names or installation package names. <br/>Example: dist_name1,dist_name2. | Optional | 
| ip_list | A comma-separated list of IP addresses.<br/>Example: 8.8.8.8,1.1.1.1. | Optional | 
| group_name | The group name to which the agent belongs.<br/>Example: group_name1,group_name2. | Optional | 
| platform | The endpoint platform. Valid values are\: "windows", "linux", "macos", or "android". . Possible values are: windows, linux, macos, android. | Optional | 
| alias_name | A comma-separated list of alias names.<br/>Examples: alias_name1,alias_name2. | Optional | 
| isolate | Specifies whether the endpoint was isolated or unisolated. Possible values are: isolated, unisolated. | Optional | 
| hostname | Hostname<br/>Example: hostname1,hostname2. | Optional | 
| first_seen_gte | All the agents that were first seen after {first_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| first_seen_lte | All the agents that were first seen before {first_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_gte | All the agents that were last seen before {last_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of endpoints to return per page. The default and maximum is 30. Default is 30. | Optional | 
| sort_by | Specifies whether to sort endpoints by the first time or last time they were seen. Can be "first_seen" or "last_seen". Possible values are: first_seen, last_seen. | Optional | 
| sort_order | The order by which to sort results. Can be "asc" (ascending) or "desc" ( descending). Default set to asc. Possible values are: asc, desc. Default is asc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Endpoint.endpoint_id | String | The endpoint ID. | 
| PaloAltoNetworksCore.Endpoint.endpoint_name | String | The endpoint name. | 
| PaloAltoNetworksCore.Endpoint.endpoint_type | String | The endpoint type. | 
| PaloAltoNetworksCore.Endpoint.endpoint_status | String | The status of the endpoint. | 
| PaloAltoNetworksCore.Endpoint.os_type | String | The endpoint OS type. | 
| PaloAltoNetworksCore.Endpoint.ip | Unknown | A list of IP addresses. | 
| PaloAltoNetworksCore.Endpoint.users | Unknown | A list of users. | 
| PaloAltoNetworksCore.Endpoint.domain | String | The endpoint domain. | 
| PaloAltoNetworksCore.Endpoint.alias | String | The endpoint's aliases. | 
| PaloAltoNetworksCore.Endpoint.first_seen | Unknown | First seen date/time in Epoch \(milliseconds\). | 
| PaloAltoNetworksCore.Endpoint.last_seen | Date | Last seen date/time in Epoch \(milliseconds\). | 
| PaloAltoNetworksCore.Endpoint.content_version | String | Content version. | 
| PaloAltoNetworksCore.Endpoint.installation_package | String | Installation package. | 
| PaloAltoNetworksCore.Endpoint.active_directory | String | Active directory. | 
| PaloAltoNetworksCore.Endpoint.install_date | Date | Install date in Epoch \(milliseconds\). | 
| PaloAltoNetworksCore.Endpoint.endpoint_version | String | Endpoint version. | 
| PaloAltoNetworksCore.Endpoint.is_isolated | String | Whether the endpoint is isolated. | 
| PaloAltoNetworksCore.Endpoint.group_name | String | The name of the group to which the endpoint belongs. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| Endpoint.ID | String | The unique ID within the tool retrieving the endpoint. | 
| Endpoint.IPAddress | String | The IP address of the endpoint. | 
| Endpoint.Domain | String | The domain of the endpoint. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Account.Username | String | The username in the relevant system. | 
| Account.Domain | String | The domain of the account. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 

### core-get-distribution-versions
***
Gets a list of all the agent versions to use for creating a distribution list.


#### Base Command

`core-get-distribution-versions`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.DistributionVersions.windows | Unknown | A list of Windows agent versions. | 
| PaloAltoNetworksCore.DistributionVersions.linux | Unknown | A list of Linux agent versions. | 
| PaloAltoNetworksCore.DistributionVersions.macos | Unknown | A list of Mac agent versions. | 

### core-create-distribution
***
Creates an installation package. This is an asynchronous call that returns the distribution ID. This does not mean that the creation succeeded. To confirm that the package has been created, check the status of the distribution by running the Get Distribution Status API.


#### Base Command

`core-create-distribution`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A string representing the name of the installation package. | Required | 
| platform | String, valid values are:<br/>• windows <br/>• linux<br/>• macos <br/>• android. Possible values are: windows, linux, macos, android. | Required | 
| package_type | A string representing the type of package to create.<br/>standalone - An installation for a new agent<br/>upgrade - An upgrade of an agent from ESM. Possible values are: standalone, upgrade. | Required | 
| agent_version | agent_version returned from core-get-distribution-versions. Not required for Android platfom. | Required | 
| description | Information about the package. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Distribution.id | String | The installation package ID. | 
| PaloAltoNetworksCore.Distribution.name | String | The name of the installation package. | 
| PaloAltoNetworksCore.Distribution.platform | String | The installation OS. | 
| PaloAltoNetworksCore.Distribution.agent_version | String | Agent version. | 
| PaloAltoNetworksCore.Distribution.description | String | Information about the package. | 

### core-get-distribution-url
***
Gets the distribution URL for downloading the installation package.


#### Base Command

`core-get-distribution-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| distribution_id | The ID of the installation package.<br/>Copy the distribution_id from the "id" field on Endpoints &gt; Agent Installation page. | Required | 
| package_type | The installation package type. Valid<br/>values are:<br/>• upgrade<br/>• sh - For Linux<br/>• rpm - For Linux<br/>• deb - For Linux<br/>• pkg - For Mac<br/>• x86 - For Windows<br/>• x64 - For Windows. Possible values are: upgrade, sh, rpm, deb, pkg, x86, x64. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Distribution.id | String | Distribution ID. | 
| PaloAltoNetworksCore.Distribution.url | String | URL for downloading the installation package. | 

### core-get-create-distribution-status
***
Gets the status of the installation package.


#### Base Command

`core-get-create-distribution-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| distribution_ids | A comma-separated list of distribution IDs to get the status of. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Distribution.id | String | Distribution ID. | 
| PaloAltoNetworksCore.Distribution.status | String | The status of installation package. | 

### core-get-audit-management-logs
***
Gets management logs. You can filter by multiple fields, which will be concatenated using the AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of management logs from the start of the result set (start by counting from 0).


#### Base Command

`core-get-audit-management-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | User’s email address. | Optional | 
| type | The audit log type. Possible values are: REMOTE_TERMINAL, RULES, AUTH, RESPONSE, INCIDENT_MANAGEMENT, ENDPOINT_MANAGEMENT, ALERT_WHITELIST, PUBLIC_API, DISTRIBUTIONS, STARRED_INCIDENTS, POLICY_PROFILES, DEVICE_CONTROL_PROFILE, HOST_FIREWALL_PROFILE, POLICY_RULES, PROTECTION_POLICY, DEVICE_CONTROL_TEMP_EXCEPTIONS, DEVICE_CONTROL_GLOBAL_EXCEPTIONS, GLOBAL_EXCEPTIONS, MSSP, REPORTING, DASHBOARD, BROKER_VM. | Optional | 
| sub_type | The audit log subtype. | Optional | 
| result | Result type. Possible values are: SUCCESS, FAIL, PARTIAL. | Optional | 
| timestamp_gte | Return logs for which the timestamp is after 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| timestamp_lte | Return logs for which the timestamp is before the 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of audit logs to return per page. The default and maximum is 30. Default is 30. | Optional | 
| sort_by | Specifies the field by which to sort the results. By default the sort is defined as creation-time and DESC. Can be "type", "sub_type", "result", or "timestamp". Possible values are: type, sub_type, result, timestamp. | Optional | 
| sort_order | The sort order. Can be "asc" (ascending) or "desc" (descending). Default set to "desc". Possible values are: asc, desc. Default is desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_ID | Number | Audit log ID. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_OWNER_NAME | String | Audit owner name. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_OWNER_EMAIL | String | Audit owner email address. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_ASSET_JSON | String | Asset JSON. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_ASSET_NAMES | String | Audit asset names. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_HOSTNAME | String | Host name. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_RESULT | String | Audit result. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_REASON | String | Audit reason. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_DESCRIPTION | String | Description of the audit. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_ENTITY | String | Audit entity \(e.g., AUTH, DISTRIBUTIONS\). | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_ENTITY_SUBTYPE | String | Entity subtype \(e.g., Login, Create\). | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_CASE_ID | Number | Audit case ID. | 
| PaloAltoNetworksCore.AuditManagementLogs.AUDIT_INSERT_TIME | Date | Log's insert time. | 

### core-get-audit-agent-reports
***
Gets agent event reports. You can filter by multiple fields, which will be concatenated using the AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of reports from the start of the result set (start by counting from 0).


#### Base Command

`core-get-audit-agent-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. | Optional | 
| endpoint_names | A comma-separated list of endpoint names. | Optional | 
| type | The report type. Can be "Installation", "Policy", "Action", "Agent Service", "Agent Modules", or "Agent Status". Possible values are: Installation, Policy, Action, Agent Service, Agent Modules, Agent Status. | Optional | 
| sub_type | The report subtype. Possible values are: Install, Uninstall, Upgrade, Local Configuration, Content Update, Policy Update, Process Exception, Hash Exception, Scan, File Retrieval, File Scan, Terminate Process, Isolate, Cancel Isolation, Payload Execution, Quarantine, Restore, Stop, Start, Module Initialization, Local Analysis Model, Local Analysis Feature Extraction, Fully Protected, OS Incompatible, Software Incompatible, Kernel Driver Initialization, Kernel Extension Initialization, Proxy Communication, Quota Exceeded, Minimal Content, Reboot Eequired, Missing Disc Access. | Optional | 
| result | The result type. Can be "Success" or "Fail". If not passed, returns all event reports. Possible values are: Success, Fail. | Optional | 
| timestamp_gte | Return logs that their timestamp is greater than 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| timestamp_lte | Return logs for which the timestamp is before the 'timestamp_lte'.<br/><br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | The maximum number of reports to return. Default and maximum is 30. Default is 30. | Optional | 
| sort_by | The field by which to sort results. Can be "type", "category", "trapsversion", "timestamp", or "domain"). Possible values are: type, category, trapsversion, timestamp, domain. | Optional | 
| sort_order | The sort order. Can be "asc" (ascending) or "desc" (descending). Default is "asc". Possible values are: asc, desc. Default is asc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.AuditAgentReports.ENDPOINTID | String | Endpoint ID. | 
| PaloAltoNetworksCore.AuditAgentReports.ENDPOINTNAME | String | Endpoint name. | 
| PaloAltoNetworksCore.AuditAgentReports.DOMAIN | String | Agent domain. | 
| PaloAltoNetworksCore.AuditAgentReports.TRAPSVERSION | String | Traps version. | 
| PaloAltoNetworksCore.AuditAgentReports.RECEIVEDTIME | Date | Received time in Epoch time. | 
| PaloAltoNetworksCore.AuditAgentReports.TIMESTAMP | Date | Timestamp in Epoch time. | 
| PaloAltoNetworksCore.AuditAgentReports.CATEGORY | String | Report category \(e.g., Audit\). | 
| PaloAltoNetworksCore.AuditAgentReports.TYPE | String | Report type \(e.g., Action, Policy\). | 
| PaloAltoNetworksCore.AuditAgentReports.SUBTYPE | String | Report subtype \(e.g., Fully Protected,Policy Update,Cancel Isolation\). | 
| PaloAltoNetworksCore.AuditAgentReports.RESULT | String | Report result. | 
| PaloAltoNetworksCore.AuditAgentReports.REASON | String | Report reason. | 
| PaloAltoNetworksCore.AuditAgentReports.DESCRIPTION | String | Agent report description. | 
| Endpoint.ID | String | The unique ID within the tool retrieving the endpoint. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| Endpoint.Domain | String | The domain of the endpoint. | 

### core-blacklist-files
***
Block lists requested files which have not already been block listed or added to allow list.


#### Base Command

`core-blacklist-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| hash_list | String that represents a list of hashed files you want to block list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 


#### Context Output

There is no context output for this command.
### core-whitelist-files
***
Adds requested files to allow list if they are not already on block list or allow list.


#### Base Command

`core-whitelist-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| hash_list | String that represents a list of hashed files you want to add to allow list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 


#### Context Output

There is no context output for this command.
### core-quarantine-files
***
Quarantines a file on selected endpoints. You can select up to 1000 endpoints.


#### Base Command

`core-quarantine-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Required | 
| file_path | String that represents the path of the file you want to quarantine. | Required | 
| file_hash | String that represents the file’s hash. Must be a valid SHA256 hash. | Required | 


#### Context Output

There is no context output for this command.
### core-get-quarantine-status
***
Retrieves the quarantine status for a selected file.


#### Base Command

`core-get-quarantine-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | String the represents the endpoint ID. | Required | 
| file_hash | String that represents the file hash. Must be a valid SHA256 hash. | Required | 
| file_path | String that represents the file path. | Required | 


#### Context Output

There is no context output for this command.
### core-restore-file
***
Restores a quarantined file on requested endpoints.


#### Base Command

`core-restore-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| file_hash | String that represents the file in hash. Must be a valid SHA256 hash. | Required | 
| endpoint_id | String that represents the endpoint ID. If you do not enter a specific endpoint ID, the request will run restore on all endpoints which relate to the quarantined file you defined. | Optional | 


#### Context Output

There is no context output for this command.
### core-endpoint-scan
***
Runs a scan on a selected endpoint. To scan all endpoints, run this command with argument all=true. Do note that scanning all the endpoints may cause performance issues and latency.


#### Base Command

`core-endpoint-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Optional | 
| dist_name | Name of the distribution list. | Optional | 
| gte_first_seen | Epoch timestamp in milliseconds. | Optional | 
| gte_last_seen | Epoch timestamp in milliseconds. | Optional | 
| lte_first_seen | Epoch timestamp in milliseconds. | Optional | 
| lte_last_seen | Epoch timestamp in milliseconds. | Optional | 
| ip_list | List of IP addresses. | Optional | 
| group_name | Name of the endpoint group. | Optional | 
| platform | Type of operating system. Possible values are: windows, linux, macos, android. | Optional | 
| alias | Endpoint alias name. | Optional | 
| isolate | Whether an endpoint has been isolated. Can be "isolated" or "unisolated". Possible values are: isolated, unisolated. | Optional | 
| hostname | Name of the host. | Optional | 
| all | Whether to scan all of the endpoints or not. Default is false. Scanning all of the endpoints may cause performance issues and latency. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.endpointScan.actionId | Number | The action ID of the scan request. | 
| PaloAltoNetworksCore.endpointScan.aborted | Boolean | Was the scan aborted. | 

### core-endpoint-scan-abort
***
Cancel the scan of selected endpoints. A scan can only be aborted if the selected endpoints are Pending or In Progress. To scan all endpoints, run the command with the argument all=true. Note that scanning all of the endpoints may cause performance issues and latency.


#### Base Command

`core-endpoint-scan-abort`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Optional | 
| dist_name | Name of the distribution list. | Optional | 
| gte_first_seen | Epoch timestamp in milliseconds. | Optional | 
| gte_last_seen | Epoch timestamp in milliseconds. | Optional | 
| lte_first_seen | Epoch timestamp in milliseconds. | Optional | 
| lte_last_seen | Epoch timestamp in milliseconds. | Optional | 
| ip_list | List of IP addresses. | Optional | 
| group_name | Name of the endpoint group. | Optional | 
| platform | Type of operating system. Possible values are: windows, linux, macos, android. | Optional | 
| alias | Endpoint alias name. | Optional | 
| isolate | Whether an endpoint has been isolated. Can be "isolated" or "unisolated". Possible values are: isolated, unisolated. | Optional | 
| hostname | Name of the host. | Optional | 
| all | Whether to scan all of the endpoints or not. Default is false. Note that scanning all of the endpoints may cause performance issues and latency. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.endpointScan.actionId | Unknown | The action id of the abort scan request. | 
| PaloAltoNetworksCore.endpointScan.aborted | Boolean | Was the scan aborted. | 

### get-mapping-fields
***
Get mapping fields from remote incident. Please note that this method will not update the current incident, it's here for debugging purposes.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### get-remote-data
***
Get remote data from a remote incident. Please note that this method will not update the current incident, it's here for debugging purposes.


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident id. | Required | 
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 


#### Context Output

There is no context output for this command.
### get-modified-remote-data
***
Get the list of incidents that were modified since the last update. Please note that this method is here for debugging purposes. get-modified-remote-data is used as part of a Mirroring feature, which is available since version 6.1.


#### Base Command

`get-modified-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string representing the local time.The incident is only returned if it was modified after the last update time. | Optional | 


#### Context Output

There is no context output for this command.
### core-get-policy
***
Gets the policy name for a specific endpoint.


#### Base Command

`core-get-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID. Can be retrieved by running the core-get-endpoints command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Policy | string | The policy allocated with the endpoint. | 
| PaloAltoNetworksCore.Policy.policy_name | string | Name of the policy allocated with the endpoint. | 
| PaloAltoNetworksCore.Policy.endpoint_id | string | Endpoint ID. | 

### core-get-scripts
***
Gets a list of scripts available in the scripts library.


#### Base Command

`core-get-scripts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_name | A comma-separated list of the script names. | Optional | 
| description | A comma-separated list of the script descriptions. | Optional | 
| created_by | A comma-separated list of the users who created the script. | Optional | 
| limit | The maximum number of scripts returned to the War Room. Default is 50. | Optional | 
| offset | (Int) Offset in the data set. Default is 0. | Optional | 
| windows_supported | Whether the script can be executed on a Windows operating system. Possible values are: true, false. | Optional | 
| linux_supported | Whether the script can be executed on a Linux operating system. Possible values are: true, false. | Optional | 
| macos_supported | Whether the script can be executed on a Mac operating system. Possible values are: true, false. | Optional | 
| is_high_risk | Whether the script has a high-risk outcome. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.Scripts | Unknown | The scripts command results. | 
| PaloAltoNetworksCore.Scripts.script_id | Unknown | Script ID. | 
| PaloAltoNetworksCore.Scripts.name | string | Name of the script. | 
| PaloAltoNetworksCore.Scripts.description | string | Description of the script. | 
| PaloAltoNetworksCore.Scripts.modification_date | Unknown | Timestamp of when the script was last modified. | 
| PaloAltoNetworksCore.Scripts.created_by | string | Name of the user who created the script. | 
| PaloAltoNetworksCore.Scripts.windows_supported | boolean | Whether the script can be executed on a Windows operating system. | 
| PaloAltoNetworksCore.Scripts.linux_supported | boolean | Whether the script can be executed on a Linux operating system. | 
| PaloAltoNetworksCore.Scripts.macos_supported | boolean | Whether the script can be executed on Mac operating system. | 
| PaloAltoNetworksCore.Scripts.is_high_risk | boolean | Whether the script has a high-risk outcome. | 
| PaloAltoNetworksCore.Scripts.script_uid | string | Globally Unique Identifier of the script, used to identify the script when executing. | 

### core-delete-endpoints
***
Deletes selected endpoints in the Cortex Core app. You can delete up to 1000 endpoints.


#### Base Command

`core-delete-endpoints`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | Comma-separated list of endpoint IDs. You can retrieve the endpoint IDs from the core-get-endpoints command. | Required | 


#### Context Output

There is no context output for this command.
### core-get-endpoint-device-control-violations
***
Gets a list of device control violations filtered by selected fields. You can retrieve up to 100 violations.


#### Base Command

`core-get-endpoint-device-control-violations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | Comma-separated list of endpoint IDs. You can retrieve the endpoint IDs from the core-get-endpoints command. | Optional | 
| type | Type of violation. Possible values are: "cd-rom", "disk drive", "floppy disk", and "portable device". Possible values are: cd-rom, disk drive, floppy disk, portable device. | Optional | 
| timestamp_gte | Timestamp of the violation. Violations that are greater than or equal to this timestamp will be returned. Values can be in either ISO date format, relative time, or epoch timestamp. For example:  "2019-10-21T23:45:00" (ISO date format), "3 days ago" (relative time) 1579039377301 (epoch time). | Optional | 
| timestamp_lte | Timestamp of the violation. Violations that are less than or equal to this timestamp will be returned. Values can be in either ISO date format, relative time, or epoch timestamp. For example:  "2019-10-21T23:45:00" (ISO date format), "3 days ago" (relative time) 1579039377301 (epoch time). | Optional | 
| ip_list | Comma-separated list of IP addresses. | Optional | 
| vendor | Name of the vendor. | Optional | 
| vendor_id | Vendor ID. | Optional | 
| product | Name of the product. | Optional | 
| product_id | Product ID. | Optional | 
| serial | Serial number. | Optional | 
| hostname | Hostname. | Optional | 
| violation_id_list | Comma-separated list of violation IDs. | Optional | 
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.EndpointViolations | Unknown | Endpoint violations command results. | 
| PaloAltoNetworksCore.EndpointViolations.violations | Unknown | A list of violations. | 
| PaloAltoNetworksCore.EndpointViolations.violations.os_type | string | Type of the operating system. | 
| PaloAltoNetworksCore.EndpointViolations.violations.hostname | string | Hostname of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.username | string | Username of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.ip | string | IP address of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.timestamp | number | Timestamp of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.violation_id | number | Violation ID. | 
| PaloAltoNetworksCore.EndpointViolations.violations.type | string | Type of violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.vendor_id | string | Vendor ID of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.vendor | string | Name of the vendor of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.product_id | string | Product ID of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.product | string | Name of the product of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.serial | string | Serial number of the violation. | 
| PaloAltoNetworksCore.EndpointViolations.violations.endpoint_id | string | Endpoint ID of the violation. | 

### core-retrieve-files
***
Retrieves files from selected endpoints. You can retrieve up to 20 files, from no more than 10 endpoints. At least one endpoint ID and one file path are necessary in order to run the command. After running this command, you can use the core-action-status-get command with returned action_id, to check the action status.


#### Base Command

`core-retrieve-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. | Required | 
| windows_file_paths | A comma-separated list of file paths on the Windows platform. | Optional | 
| linux_file_paths | A comma-separated list of file paths on the Linux platform. | Optional | 
| mac_file_paths | A comma-separated list of file paths on the Mac platform. | Optional | 
| generic_file_path | A comma-separated list of file paths in any platform. Can be used instead of the mac/windows/linux file paths. The order of the files path list must be parellel to the endpoints list order, therefore, the first file path in the list is related to the first endpoint and so on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.RetrievedFiles.action_id | string | ID of the action to retrieve files from selected endpoints. | 

### core-retrieve-file-details
***
View the file retrieved by the core-retrieve-files command according to the action ID. Before running this command, you can use the core-action-status-get command to check if this action completed successfully.


#### Base Command

`core-retrieve-file-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action ID retrieved from the core-retrieve-files command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 

### core-get-script-metadata
***
Gets the full definition of a specific script in the scripts library.


#### Base Command

`core-get-script-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_uid | Unique identifier of the script, returned by the core-get-scripts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptMetadata | Unknown | The script metadata command results. | 
| PaloAltoNetworksCore.ScriptMetadata.script_id | number | Script ID. | 
| PaloAltoNetworksCore.ScriptMetadata.name | string | Script name. | 
| PaloAltoNetworksCore.ScriptMetadata.description | string | Script description. | 
| PaloAltoNetworksCore.ScriptMetadata.modification_date | unknown | Timestamp of when the script was last modified. | 
| PaloAltoNetworksCore.ScriptMetadata.created_by | string | Name of the user who created the script. | 
| PaloAltoNetworksCore.ScriptMetadata.is_high_risk | boolean | Whether the script has a high-risk outcome. | 
| PaloAltoNetworksCore.ScriptMetadata.windows_supported | boolean | Whether the script can be executed on a Windows operating system. | 
| PaloAltoNetworksCore.ScriptMetadata.linux_supported | boolean | Whether the script can be executed on a Linux operating system. | 
| PaloAltoNetworksCore.ScriptMetadata.macos_supported | boolean | Whether the script can be executed on a Mac operating system. | 
| PaloAltoNetworksCore.ScriptMetadata.entry_point | string | Name of the entry point selected for the script. An empty string indicates  the script defined as just run. | 
| PaloAltoNetworksCore.ScriptMetadata.script_input | string | Name and type for the specified entry point. | 
| PaloAltoNetworksCore.ScriptMetadata.script_output_type | string | Type of the output. | 
| PaloAltoNetworksCore.ScriptMetadata.script_output_dictionary_definitions | Unknown | If the script_output_type is a dictionary, an array with friendly name, name, and type for each output. | 

### core-get-script-code
***
Gets the code of a specific script in the script library.


#### Base Command

`core-get-script-code`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_uid | Unique identifier of the script, returned by the core-get-scripts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptCode | Unknown | The script code command results. | 
| PaloAltoNetworksCore.ScriptCode.code | string | The code of a specific script in the script library. | 
| PaloAltoNetworksCore.ScriptCode.script_uid | string | Unique identifier of the script. | 

### core-action-status-get
***
Retrieves the status of the requested actions according to the action ID.


#### Base Command

`core-action-status-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | The action ID of the selected request. After performing an action, you will receive an action ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.GetActionStatus | Unknown | The action status command results. | 
| PaloAltoNetworksCore.GetActionStatus.endpoint_id | string | Endpoint ID. | 
| PaloAltoNetworksCore.GetActionStatus.status | string | The status of the specific endpoint ID. | 
| PaloAltoNetworksCore.GetActionStatus.action_id | number | The specified action ID. | 

### core-run-script
***
Initiates a new endpoint script execution action using a script from the script library.


#### Base Command

`core-run-script`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| script_uid | Unique identifier of the script. Can be retrieved by running the core-get-scripts command. | Required | 
| parameters | Dictionary contains the parameter name as key and its value for this execution as the value. For example, {"param1":"param1_value","param2":"param2_value"}. | Optional | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksCore.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-run-snippet-code-script
***
Initiates a new endpoint script execution action using the provided snippet code.


#### Base Command

`core-run-snippet-code-script`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| snippet_code | Section of a script you want to initiate on an endpoint (e.g., print("7")). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksCore.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-get-script-execution-status
***
Retrieves the status of a script execution action.


#### Base Command

`core-get-script-execution-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action IDs retrieved from the core-run-script command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptStatus.general_status | String | General status of the action, considering the status of all the endpoints. | 
| PaloAltoNetworksCore.ScriptStatus.error_message | String | Error message regarding permissions for running APIs or the action doesn’t exist. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_timeout | Number | Number of endpoints in "timeout" status. | 
| PaloAltoNetworksCore.ScriptStatus.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_pending_abort | Number | Number of endpoints in "pending abort" status. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_pending | Number | Number of endpoints in "pending" status. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_in_progress | Number | Number of endpoints in "in progress" status. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_failed | Number | Number of endpoints in "failed" status. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_expired | Number | Number of endpoints in "expired" status. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_completed_successfully | Number | Number of endpoints in "completed successfully" status. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_canceled | Number | Number of endpoints in "canceled" status. | 
| PaloAltoNetworksCore.ScriptStatus.endpoints_aborted | Number | Number of endpoints in "aborted" status. | 

### core-get-script-execution-results
***
Retrieve the results of a script execution action.


#### Base Command

`core-get-script-execution-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action IDs retrieved from the core-run-script command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptResult.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksCore.ScriptResult.results.retrieved_files | Number | Number of successfully retrieved files. | 
| PaloAltoNetworksCore.ScriptResult.results.endpoint_ip_address | String | Endpoint IP address. | 
| PaloAltoNetworksCore.ScriptResult.results.endpoint_name | String | Number of successfully retrieved files. | 
| PaloAltoNetworksCore.ScriptResult.results.failed_files | Number | Number of files failed to retrieve. | 
| PaloAltoNetworksCore.ScriptResult.results.endpoint_status | String | Endpoint status. | 
| PaloAltoNetworksCore.ScriptResult.results.domain | String | Domain to which the endpoint belongs. | 
| PaloAltoNetworksCore.ScriptResult.results.endpoint_id | String | Endpoint ID. | 
| PaloAltoNetworksCore.ScriptResult.results.execution_status | String | Execution status of this endpoint. | 
| PaloAltoNetworksCore.ScriptResult.results.return_value | String | Value returned by the script in case the type is not a dictionary. | 
| PaloAltoNetworksCore.ScriptResult.results.standard_output | String | The STDOUT and the STDERR logged by the script during the execution. | 
| PaloAltoNetworksCore.ScriptResult.results.retention_date | Date | Timestamp in which the retrieved files will be deleted from the server. | 

### core-get-script-execution-result-files
***
Gets the files retrieved from a specific endpoint during a script execution.


#### Base Command

`core-get-script-execution-result-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action ID retrieved from the core-run-script command. | Required | 
| endpoint_id | Endpoint ID. Can be retrieved by running the core-get-endpoints command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | String | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | EntryID of the file | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### core-run-script-execute-commands
***
Initiate a new endpoint script execution of shell commands.


#### Base Command

`core-run-script-execute-commands`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| commands | Comma-separated list of shell commands to execute. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksCore.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-run-script-delete-file
***
Initiates a new endpoint script execution to delete the specified file.


#### Base Command

`core-run-script-delete-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| file_path | Paths of the files to delete, in a comma-separated list. Paths of the files to check for existence. All of the given file paths will run on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksCore.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-run-script-file-exists
***
Initiates a new endpoint script execution to check if file exists.


#### Base Command

`core-run-script-file-exists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| file_path | Paths of the files to check for existence, in a comma-separated list. All of the given file paths will run on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksCore.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### core-run-script-kill-process
***
Initiates a new endpoint script execution kill process.


#### Base Command

`core-run-script-kill-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | Comma-separated list of endpoint IDs. Can be retrieved by running the core-get-endpoints command. | Required | 
| process_name | Names of processes to kill. Will kill all of the given processes on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksCore.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### endpoint
***
Returns information about an endpoint.


#### Base Command

`endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional | 
| ip | The endpoint IP address. | Optional | 
| hostname | The endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 

### core-get-endpoints-by-status
***
Returns the number of the connected\disconnected endpoints.


#### Base Command

`core-get-endpoints-by-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the endpoint to filter. Possible values are: connected, disconnected, lost, uninstalled. | Required | 
| last_seen_gte | All the agents that were last seen before {last_seen_gte}. Supported<br/>        values: 1579039377301 (time in milliseconds) "3 days" (relative date) "2019-10-21T23:45:00"<br/>        (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte}. Supported<br/>        values: 1579039377301 (time in milliseconds) "3 days" (relative date) "2019-10-21T23:45:00"<br/>        (date). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.EndpointsStatus.status | String | The endpoint's status. | 
| PaloAltoNetworksCore.EndpointsStatus.count | Number | The number of endpoint's with this status. | 

### core-get-cloud-original-alerts
***
Returns information about each alert ID.


#### Base Command

`core-get-cloud-original-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alert IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksCore.OriginalAlert.event._time | String | The timestamp of the occurence of the event. | 
| PaloAltoNetworksCore.OriginalAlert.event.vendor | String | Vendor name. | 
| PaloAltoNetworksCore.OriginalAlert.event.event_timestamp | Number | Event timestamp. | 
| PaloAltoNetworksCore.OriginalAlert.event.event_type | Number | Event type \(static 500\). | 
| PaloAltoNetworksCore.OriginalAlert.event.cloud_provider | String | The cloud provider - GCP, AZURE, or AWS. | 
| PaloAltoNetworksCore.OriginalAlert.event.project | String | The project in which the event occurred. | 
| PaloAltoNetworksCore.OriginalAlert.event.cloud_provider_event_id | String | The ID given to the event by the cloud provider, if the ID exists. | 
| PaloAltoNetworksCore.OriginalAlert.event.cloud_correlation_id | String | The ID the cloud provider is using to aggregate events that are part of the same general event. | 
| PaloAltoNetworksCore.OriginalAlert.event.operation_name_orig | String | The name of the operation that occurred, as supplied by the cloud provider. | 
| PaloAltoNetworksCore.OriginalAlert.event.operation_name | String | The normalized name of the operation performed by the event. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_orig | String | Contains the original identity related fields as provided by the cloud provider. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_name | String | The name of the identity that initiated the action. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_uuid | String | Same as identity_name but also contains the UUID of the identity if it exists. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_type | String | An enum representing the type of the identity. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_sub_type | String | An enum representing the sub-type of the identity, respective to its identity_type. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_invoked_by_name | String | The name of the identity that invoked the action as it appears in the log. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_invoked_by_uuid | String | The UUID of the identity that invoked the action as it appears in the log. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_invoked_by_type | String | An enum that represents the type of identity event that invoked the action. | 
| PaloAltoNetworksCore.OriginalAlert.event.identity_invoked_by_sub_type | String | An enum that represents the respective sub_type of the type of identity \(identity_type\) that has invoked the action. | 
| PaloAltoNetworksCore.OriginalAlert.event.operation_status | String | Status of whether the operation has succeed or failed, if provided. | 
| PaloAltoNetworksCore.OriginalAlert.event.operation_status_orig | String | The operation status code as it appears in the log, including lookup from code number to code name. | 
| PaloAltoNetworksCore.OriginalAlert.event.operation_status_orig_code | String | The operation status code as it appears in the log. | 
| PaloAltoNetworksCore.OriginalAlert.event.operation_status_reason_provided | String | Description of the error, if the log record indicates an error and the cloud provider supplied the reason. | 
| PaloAltoNetworksCore.OriginalAlert.event.resource_type | String | The normalized type of the service that emitted the log row. | 
| PaloAltoNetworksCore.OriginalAlert.event.resource_type_orig | String | The type of the service that omitted the log as provided by the cloud provider. | 
| PaloAltoNetworksCore.OriginalAlert.event.resource_sub_type | String | The sub-type respective to the resource_type field, normalized across all cloud providers. | 
| PaloAltoNetworksCore.OriginalAlert.event.resource_sub_type_orig | String | The sub-type of the service that emitted this log row as provided by the cloud provider. | 
| PaloAltoNetworksCore.OriginalAlert.event.region | String | The cloud region of the resource that emitted the log. | 
| PaloAltoNetworksCore.OriginalAlert.event.zone | String | The availability zone of the resource that emitted the log. | 
| PaloAltoNetworksCore.OriginalAlert.event.referenced_resource | String | The cloud resource referenced in the audit log. | 
| PaloAltoNetworksCore.OriginalAlert.event.referenced_resource_name | String | Same as referenced_resource but provides only the substring that represents the resource name instead of the full asset ID. | 
| PaloAltoNetworksCore.OriginalAlert.event.referenced_resources_count | Number | The number of extracted resources referenced in this audit log. | 
| PaloAltoNetworksCore.OriginalAlert.event.user_agent | String | The user agent provided in the call to the API of the cloud provider. | 
| PaloAltoNetworksCore.OriginalAlert.event.caller_ip | String | The IP of the caller that performed the action in the log. | 
| PaloAltoNetworksCore.OriginalAlert.event.caller_ip_geolocation | String | The geolocation associated with the caller_ip's value. | 
| PaloAltoNetworksCore.OriginalAlert.event.caller_ip_asn | Number | The ASN of the caller_ip's value. | 
| PaloAltoNetworksCore.OriginalAlert.event.caller_project | String | The project of the caller entity. | 
| PaloAltoNetworksCore.OriginalAlert.event.raw_log | Unknown | The raw log that is being normalized. | 
| PaloAltoNetworksCore.OriginalAlert.event.log_name | String | The name of the log that contains the log row. | 
| PaloAltoNetworksCore.OriginalAlert.event.caller_ip_asn_org | String | The organization associated with the ASN of the caller_ip's value. | 
| PaloAltoNetworksCore.OriginalAlert.event.event_base_id | String | Event base ID. | 
| PaloAltoNetworksCore.OriginalAlert.event.ingestion_time | String | Ingestion time. | 
