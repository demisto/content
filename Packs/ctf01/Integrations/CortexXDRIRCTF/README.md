This integration is a Mock customized only for the Capture The Flag challenge.

## Commands


You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### get-mapping-fields

***
Gets mapping fields from remote incident. Note: This method will not update the current incident, it's here for debugging purposes.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### xdr-get-incident-extra-data-ctf

***
Returns additional data for the specified incident, for example, related alerts, file artifacts, network artifacts, and so on.

#### Base Command

`xdr-get-incident-extra-data-ctf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident for which to get additional data. | Required | 
| alerts_limit | Maximum number of alerts to return. Default is 1000. | Optional | 
| return_only_updated_incident | Return data only if the incident was changed since the last time it was mirrored into Cortex XSOAR.  This flag should be used only from within a Cortex XDR incident. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Incident.incident_id | String | Unique ID assigned to each returned incident. | 
| PaloAltoNetworksXDR.Incident.creation_time | Date | Date and time the incident was created on Cortex XDR. | 
| PaloAltoNetworksXDR.Incident.modification_time | Date | Date and time that the incident was last modified. | 
| PaloAltoNetworksXDR.Incident.detection_time | Date | Date and time that the first alert occurred in the incident. | 
| PaloAltoNetworksXDR.Incident.status | String | Current status of the incident. Valid values are:
"new","under_investigation","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_true_positive","resolved_security_testing","resolved_other". | 
| PaloAltoNetworksXDR.Incident.severity | String | Calculated severity of the incident. Valid values are: "low","medium","high". | 
| PaloAltoNetworksXDR.Incident.description | String | Dynamic calculated description of the incident. | 
| PaloAltoNetworksXDR.Incident.assigned_user_mail | String | Email address of the assigned user. | 
| PaloAltoNetworksXDR.Incident.assigned_user_pretty_name | String | Full name of the user assigned to the incident. | 
| PaloAltoNetworksXDR.Incident.alert_count | Number | Total number of alerts in the incident. | 
| PaloAltoNetworksXDR.Incident.low_severity_alert_count | Number | Number of alerts with the severity LOW. | 
| PaloAltoNetworksXDR.Incident.med_severity_alert_count | Number | Number of alerts with the severity MEDIUM. | 
| PaloAltoNetworksXDR.Incident.high_severity_alert_count | Number | Number of alerts with the severity HIGH. | 
| PaloAltoNetworksXDR.Incident.user_count | Number | Number of users involved in the incident. | 
| PaloAltoNetworksXDR.Incident.host_count | Number | Number of hosts involved in the incident. | 
| PaloAltoNetworksXDR.Incident.notes | Unknown | Comments entered by the user regarding the incident. | 
| PaloAltoNetworksXDR.Incident.resolve_comment | String | Comments entered by the user when the incident was resolved. | 
| PaloAltoNetworksXDR.Incident.manual_severity | String | Incident severity assigned by the user. This does not affect the calculated severity of low, medium, or high. | 
| PaloAltoNetworksXDR.Incident.manual_description | String | Incident description provided by the user. | 
| PaloAltoNetworksXDR.Incident.xdr_url | String | A link to the incident view on Cortex XDR. | 
| PaloAltoNetworksXDR.Incident.starred | Boolean | Incident starred. | 
| PaloAltoNetworksXDR.Incident.wildfire_hits.mitre_techniques_ids_and_names | String | Incident Mitre techniques IDs and names. | 
| PaloAltoNetworksXDR.Incident.wildfire_hits.mitre_tactics_ids_and_names | String | Incident Mitre tactics ids and names. | 
| PaloAltoNetworksXDR.Incident.alerts.alert_id | String | Unique ID for each alert. | 
| PaloAltoNetworksXDR.Incident.alerts.detection_timestamp | Date | Date and time that the alert occurred. | 
| PaloAltoNetworksXDR.Incident.alerts.source | String | Source of the alert. The product/vendor this alert came from. | 
| PaloAltoNetworksXDR.Incident.alerts.severity | String | Severity of the alert.Valid values are: "low","medium","high""". | 
| PaloAltoNetworksXDR.Incident.alerts.name | String | Calculated name of the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.category | String | Category of the alert, for example, Spyware Detected via Anti-Spyware profile. | 
| PaloAltoNetworksXDR.Incident.alerts.description | String | Textual description of the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.host_ip_list | Unknown | Host IP involved in the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.host_name | String | Host name involved in the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.user_name | String | User name involved with the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.event_type | String | Event type. Valid values are: "Process Execution","Network Event","File Event","Registry Event","Injection Event","Load Image Event","Windows Event Log". | 
| PaloAltoNetworksXDR.Incident.alerts.action | String | The action that triggered the alert. Valid values are: "REPORTED", "BLOCKED", "POST_DETECTED", "SCANNED", "DOWNLOAD", "PROMPT_ALLOW", "PROMPT_BLOCK", "DETECTED", "BLOCKED_1", "BLOCKED_2", "BLOCKED_3", "BLOCKED_5", "BLOCKED_6", "BLOCKED_7", "BLOCKED_8", "BLOCKED_9", "BLOCKED_10", "BLOCKED_11", "BLOCKED_13", "BLOCKED_14", "BLOCKED_15", "BLOCKED_16", "BLOCKED_17", "BLOCKED_24", "BLOCKED_25", "DETECTED_0", "DETECTED_4", "DETECTED_18", "DETECTED_19", "DETECTED_20", "DETECTED_21", "DETECTED_22", "DETECTED_23". | 
| PaloAltoNetworksXDR.Incident.alerts.action_pretty | String | The action that triggered the alert. Valid values are: "Detected \(Reported\)" "Prevented \(Blocked\)" "Detected \(Post Detected\)" "Detected \(Scanned\)" "Detected \(Download\)" "Detected \(Prompt Allow\)" "Prevented \(Prompt Block\)" "Detected" "Prevented \(Denied The Session\)" "Prevented \(Dropped The Session\)" "Prevented \(Dropped The Session And Sent a TCP Reset\)" "Prevented \(Blocked The URL\)" "Prevented \(Blocked The IP\)" "Prevented \(Dropped The Packet\)" "Prevented \(Dropped All Packets\)" "Prevented \(Terminated The Session And Sent a TCP Reset To Both Sides Of The Connection\)" "Prevented \(Terminated The Session And Sent a TCP Reset To The Client\)" "Prevented \(Terminated The Session And Sent a TCP Reset To The Server\)" "Prevented \(Continue\)" "Prevented \(Block-Override\)" "Prevented \(Override-Lockout\)" "Prevented \(Override\)" "Prevented \(Random-Drop\)" "Prevented \(Silently Dropped The Session With An ICMP Unreachable Message To The Host Or Application\)" "Prevented \(Block\)" "Detected \(Allowed The Session\)" "Detected \(Raised An Alert\)" "Detected \(Syncookie Sent\)" "Detected \(Forward\)" "Detected \(Wildfire Upload Success\)" "Detected \(Wildfire Upload Failure\)" "Detected \(Wildfire Upload Skip\)" "Detected \(Sinkhole\)". | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_image_name | String | Image name. | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_command_line | String | Command line. | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash". | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_vendor | String | Signature vendor name. | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_image_name | String | Image name. | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_command_line | String | Command line. | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash". | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_signature_vendor | String | Signature vendor. | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_causality_id | Unknown | Causality ID. | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_name | String | Image name. | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_command_line | String | Command line. | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_sha256 | String | Image SHA256. | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash". | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_signature_vendor | String | Signature vendor name. | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_path | String | File path. | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_md5 | String | File MD5. | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_sha256 | String | File SHA256. | 
| PaloAltoNetworksXDR.Incident.alerts.action_registry_data | String | Registry data. | 
| PaloAltoNetworksXDR.Incident.alerts.action_registry_full_key | String | Registry full key. | 
| PaloAltoNetworksXDR.Incident.alerts.action_local_ip | String | Local IP. | 
| PaloAltoNetworksXDR.Incident.alerts.action_local_port | Number | Local port. | 
| PaloAltoNetworksXDR.Incident.alerts.action_remote_ip | String | Remote IP. | 
| PaloAltoNetworksXDR.Incident.alerts.action_remote_port | Number | Remote port. | 
| PaloAltoNetworksXDR.Incident.alerts.action_external_hostname | String | External hostname. | 
| PaloAltoNetworksXDR.Incident.alerts.fw_app_id | Unknown | Firewall app id. | 
| PaloAltoNetworksXDR.Incident.alerts.is_whitelisted | String | Is the alert on allow list. Valid values are: "Yes" "No". | 
| PaloAltoNetworksXDR.Incident.alerts.starred | Boolean | Alert starred. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.type | String | Network artifact type. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_port | number | The remote port related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.alert_count | number | Number of alerts related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_ip | String | The remote IP related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.is_manual | boolean | Whether the artifact was created by the user \(manually\). | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_domain | String | The domain related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.type | String | The artifact type. Valid values are: "META", "GID", "CID", "HASH", "IP", "DOMAIN", "REGISTRY", "HOSTNAME". | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_country | String | The country related to the artifact. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_status | String | Digital signature status of the file. Valid values are: "SIGNATURE_UNAVAILABLE" "SIGNATURE_SIGNED" "SIGNATURE_INVALID" "SIGNATURE_UNSIGNED" "SIGNATURE_WEAK_HASH". | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_process | boolean | Whether the file artifact is related to a process execution. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_name | String | Name of the file. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_wildfire_verdict | String | The file verdict, calculated by Wildfire. Valid values are: "BENIGN" "MALWARE" "GRAYWARE" "PHISHING" "UNKNOWN". | 
| PaloAltoNetworksXDR.Incident.file_artifacts.alert_count | number | Number of alerts related to the artifact. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_malicious | boolean | Whether the artifact is malicious, as decided by the Wildfire verdict. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_manual | boolean | Whether the artifact was created by the user \(manually\). | 
| PaloAltoNetworksXDR.Incident.file_artifacts.type | String | The artifact type. Valid values are: "META" "GID" "CID" "HASH" "IP" "DOMAIN" "REGISTRY" "HOSTNAME". | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_sha256 | String | SHA256 hash of the file. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_vendor_name | String | File signature vendor name. | 
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

### xdr-endpoint-isolate-ctf

***
Isolates the specified endpoint.

#### Base Command

`xdr-endpoint-isolate-ctf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_id | The endpoint ID (string) to isolate. You can retrieve the string from the xdr-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Whether to suppress an error when trying to isolate a disconnected endpoint. When sets to false, an error will be returned. Possible values are: true, false. Default is false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | For polling use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Isolation.endpoint_id | String | The endpoint ID. | 

### xdr-file-retrieve-ctf

***
Retrieves files from selected endpoints. You can retrieve up to 20 files, from no more than 10 endpoints. At least one endpoint ID and one file path are necessary in order to run the command. After running this command, you can use the xdr-action-status-get command with returned action_id, to check the action status.

#### Base Command

`xdr-file-retrieve-ctf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. | Required | 
| generic_file_path | A comma-separated list of file paths in any platform. Can be used instead of the mac/windows/linux file paths. The order of the files path list must be parallel to the endpoints list order, so the first file path in the list is related to the first endpoint and so on. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.RetrievedFiles.action_id | string | ID of the action to retrieve files from selected endpoints. | 
| PaloAltoNetworksXDR.RetrievedFiles.endpoint_id | string | Endpoint ID. Added only when the operation is successful. | 
| PaloAltoNetworksXDR.RetrievedFiles.file_link | string | Link to the file. Added only when the operation is successful. | 
| PaloAltoNetworksXDR.RetrievedFiles.status | string | The action status. Added only when the operation is unsuccessful. | 

### xdr-get-alerts-ctf

***
Returns a list of alerts and their metadata, which you can filter by built-in arguments or use the custom_filter to input a JSON filter object. 
Multiple filter arguments will be concatenated using the AND operator, while arguments that support a comma-separated list of values will use an OR operator between each value.

#### Base Command

`xdr-get-alerts-ctf`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The unique ID of the alert. | Optional | 
| severity | The severity of the alert. Possible values are: low, medium, high. | Optional | 
| custom_filter | a custom filter, when using this argument, other filter arguments are not relevant. example: <br/>`{<br/>                "OR": [<br/>                    {<br/>                        "SEARCH_FIELD": "actor_process_command_line",<br/>                        "SEARCH_TYPE": "EQ",<br/>                        "SEARCH_VALUE": "path_to_file"<br/>                    }<br/>                ]<br/>            }`. | Optional | 
| Identity_type | Account type. Possible values are: ANONYMOUS, APPLICATION, COMPUTE, FEDERATED_IDENTITY, SERVICE, SERVICE_ACCOUNT, TEMPORARY_CREDENTIALS, TOKEN, UNKNOWN, USER. | Optional | 
| agent_id | A unique identifier per agent. | Optional | 
| action_external_hostname | The host name to connect to. In case of a proxy connection, this value will differ from action_remote_ip. | Optional | 
| rule_id | A string identifying the user rule. | Optional | 
| rule_name | The name of the user rule. | Optional | 
| alert_name | The alert name. | Optional | 
| alert_source | The alert source. | Optional | 
| time_frame | Supports relative times or “custom” time option. If you choose the "custom" option, you should use start_time and end_time arguments. Possible values are: 60 minutes, 3 hours, 12 hours, 24 hours, 2 days, 7 days, 14 days, 30 days, custom. | Optional | 
| user_name | The name assigned to the user_id during agent runtime. | Optional | 
| actor_process_image_name | The file name of the binary file. | Optional | 
| causality_actor_process_image_command_line | CGO CMD. | Optional | 
| actor_process_image_command_line | Trimmed to 128 unicode chars during event serialization.<br/>Full value reported as part of the original process event. | Optional | 
| action_process_image_command_line | The command line of the process created. | Optional | 
| actor_process_image_sha256 | SHA256 of the binary file. | Optional | 
| causality_actor_process_image_sha256 | SHA256 of the binary file. | Optional | 
| action_process_image_sha256 | SHA256 of the binary file. | Optional | 
| action_file_image_sha256 | SHA256 of the file related to the event. | Optional | 
| action_registry_name | The name of the registry. | Optional | 
| action_registry_key_data | The key data of the registry. | Optional | 
| host_ip | The host IP. | Optional | 
| action_local_ip | The local IP address for the connection. | Optional | 
| action_remote_ip | Remote IP address for the connection. | Optional | 
| alert_action_status | Alert action status. Possible values are: detected, detected (allowed the session), detected (download), detected (forward), detected (post detected), detected (prompt allow), detected (raised an alert), detected (reported), detected (on write), detected (scanned), detected (sinkhole), detected (syncookie sent), detected (wildfire upload failure), detected (wildfire upload success), detected (wildfire upload skip), detected (xdr managed threat hunting), prevented (block), prevented (blocked), prevented (block-override), prevented (blocked the url), prevented (blocked the ip), prevented (continue), prevented (denied the session), prevented (dropped all packets), prevented (dropped the session), prevented (dropped the session and sent a tcp reset), prevented (dropped the packet), prevented (override), prevented (override-lockout), prevented (post detected), prevented (prompt block), prevented (random-drop), prevented (silently dropped the session with an icmp unreachable message to the host or application), prevented (terminated the session and sent a tcp reset to both sides of the connection), prevented (terminated the session and sent a tcp reset to the client), prevented (terminated the session and sent a tcp reset to the server), prevented (on write). | Optional | 
| action_local_port | The local IP address for the connection. | Optional | 
| action_remote_port | The remote port for the connection. | Optional | 
| dst_action_external_hostname | The hostname we connect to. In case of a proxy connection, this value will differ from action_remote_ip. | Optional | 
| sort_field | The field by which we sort the results. Default is source_insert_ts. | Optional | 
| sort_order | The order in which we sort the results. Possible values are: DESC, ASC. | Optional | 
| offset | The first page from which we bring the alerts. Default is 0. | Optional | 
| limit | The last page from which we bring the alerts. Default is 50. | Optional | 
| start_time | Relevant when "time_frame" argument is "custom". Supports Epoch timestamp and simplified extended ISO format (YYYY-MM-DDThh:mm:ss.000Z). | Optional | 
| end_time | Relevant when "time_frame" argument is "custom". Supports Epoch timestamp and simplified extended ISO format (YYYY-MM-DDThh:mm:ss.000Z). | Optional | 
| starred | Whether the alert is starred or not. Possible values are: true, false. | Optional | 
| mitre_technique_id_and_name | The MITRE attack technique. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Alert.internal_id | String | The unique ID of the alert. | 
| PaloAltoNetworksXDR.Alert.source_insert_ts | Number | The detection timestamp. | 
| PaloAltoNetworksXDR.Alert.alert_name | String | The name of the alert. | 
| PaloAltoNetworksXDR.Alert.severity | String | The severity of the alert. | 
| PaloAltoNetworksXDR.Alert.alert_category | String | The category of the alert. | 
| PaloAltoNetworksXDR.Alert.alert_action_status | String | The alert action. Possible values.

DETECTED: detected
DETECTED_0: detected \(allowed the session\)
DOWNLOAD: detected \(download\)
DETECTED_19: detected \(forward\)
POST_DETECTED: detected \(post detected\)
PROMPT_ALLOW: detected \(prompt allow\)
DETECTED_4: detected \(raised an alert\)
REPORTED: detected \(reported\)
REPORTED_TRIGGER_4: detected \(on write\)
SCANNED: detected \(scanned\)
DETECTED_23: detected \(sinkhole\)
DETECTED_18: detected \(syncookie sent\)
DETECTED_21: detected \(wildfire upload failure\)
DETECTED_20: detected \(wildfire upload success\)
DETECTED_22: detected \(wildfire upload skip\)
DETECTED_MTH: detected \(xdr managed threat hunting\)
BLOCKED_25: prevented \(block\)
BLOCKED: prevented \(blocked\)
BLOCKED_14: prevented \(block-override\)
BLOCKED_5: prevented \(blocked the url\)
BLOCKED_6: prevented \(blocked the ip\)
BLOCKED_13: prevented \(continue\)
BLOCKED_1: prevented \(denied the session\)
BLOCKED_8: prevented \(dropped all packets\)
BLOCKED_2: prevented \(dropped the session\)
BLOCKED_3: prevented \(dropped the session and sent a tcp reset\)
BLOCKED_7: prevented \(dropped the packet\)
BLOCKED_16: prevented \(override\)
BLOCKED_15: prevented \(override-lockout\)
BLOCKED_26: prevented \(post detected\)
PROMPT_BLOCK: prevented \(prompt block\)
BLOCKED_17: prevented \(random-drop\)
BLOCKED_24: prevented \(silently dropped the session with an icmp unreachable message to the host or application\)
BLOCKED_9: prevented \(terminated the session and sent a tcp reset to both sides of the connection\)
BLOCKED_10: prevented \(terminated the session and sent a tcp reset to the client\)
BLOCKED_11: prevented \(terminated the session and sent a tcp reset to the server\)
BLOCKED_TRIGGER_4: prevented \(on write\). | 
| PaloAltoNetworksXDR.Alert.alert_action_status_readable | String | The alert action. | 
| PaloAltoNetworksXDR.Alert.alert_name | String | The alert name. | 
| PaloAltoNetworksXDR.Alert.alert_description | String | The alert description. | 
| PaloAltoNetworksXDR.Alert.agent_ip_addresses | String | The host IP. | 
| PaloAltoNetworksXDR.Alert.agent_hostname | String | The host name. | 
| PaloAltoNetworksXDR.Alert.mitre_tactic_id_and_name | String | The MITRE attack tactic. | 
| PaloAltoNetworksXDR.Alert.mitre_technique_id_and_name | String | The MITRE attack technique. | 
| PaloAltoNetworksXDR.Alert.starred | Boolean | Whether the alert is starred or not. | 

