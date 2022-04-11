Syncs a single incident between Demisto and XDR. This script always uses the xdr-get-incident-extra-data command and outputs to the context the entire incident JSON. When the incident is updated in XDR, the Demisto incident will be updated accordingly and the default playbook will rerun. When an incident is updated in Demisto, the script will execute the xdr-update-incident command and update the incident in XDR.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | xdr |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Cortex XDR - Port Scan
* Cortex XDR Incident Handling
* Cortex XDR Incident Sync
* Cortex XDR incident handling v2

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| interval | How often the script will sync incidents between Demisto and XDR \(in minutes\). |
| incident_id | The ID of incident in XDR. |
| playbook_to_run | When an incident is the latest incident in XDR it will be updated in Demisto and the playbook will rerun. |
| assigned_user_mail | The assigned_user_mail field name in Demisto. |
| assigned_user_pretty_name | The assigned_user_pretty_name field name in Demisto. |
| status | The status field name in Demisto. |
| severity | The severity field name in Demisto. |
| resolve_comment | The resolve_comment field name in Demisto.  |
| alert_count | The alert_count field name in Demisto. |
| host_count | The host_count field name in Demisto. |
| description | The description field name in Demisto. |
| xdr_url | The xdr_url field name in Demisto. |
| notes | The notes field name in Demisto. |
| low_severity_alert_count | The low_severity_alert_count field name in Demisto. |
| med_severity_alert_count | The med_severity_alert_count field name in Demisto. |
| high_severity_alert_count | The high_severity_alert_count field name in Demisto. |
| user_count | The user_count field name in Demisto. |
| xdr_incident_markdown_field | DEPRECATED |
| first | Whether this is the first time this script is running or is scheduled. Can be "true" or "false". The default value is "true". There is no need to change the value. |
| xdr_incident_from_previous_run | The user should not modify this argument. This argument should be passed from the parent task to the next scheduled task. It should contain the incident's JSON from XDR. |
| verbose | Whether to print messages to the War Room. Can be "true" or "false". The default value is "true". |
| xdr_alerts | The XDR alerts field; must be of type "grid". |
| xdr_file_artifacts | The XDR file artifacts field; must be of type "grid".  |
| xdr_network_artifacts | The XDR network artifacts field. |
| modification_time | The modification_time field name in Demisto. |
| manual_severity | The manual_severity field name in Demisto. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Incident.incident_id | Unique ID assigned to each returned incident. | String |
| PaloAltoNetworksXDR.Incident.creation_time | Date and time that the incident was created in XDR. | Date |
| PaloAltoNetworksXDR.Incident.modification_time | Date and time that the incident was last modified. | Date |
| PaloAltoNetworksXDR.Incident.detection_time | Date and time that the first alert occurred in the incident. | Date |
| PaloAltoNetworksXDR.Incident.status | Current status of the incident:<br/>"new","under_investigation","resolved_threat_handled","resolved_true_positive", "resolved_security_testing","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_other" | String |
| PaloAltoNetworksXDR.Incident.severity | Calculated severity of the incident. Can be "low","medium",or "high". | String |
| PaloAltoNetworksXDR.Incident.description | Dynamic calculated description of the incident. | String |
| PaloAltoNetworksXDR.Incident.assigned_user_mail | Email address of the user assigned to the incident. | String |
| PaloAltoNetworksXDR.Incident.assigned_user_pretty_name | Full name of the user assigned to the incident. | String |
| PaloAltoNetworksXDR.Incident.alert_count | Total number of alerts in the incident. | Number |
| PaloAltoNetworksXDR.Incident.low_severity_alert_count | Number of alerts with the severity LOW. | Number |
| PaloAltoNetworksXDR.Incident.med_severity_alert_count | Number of alerts with the severity MEDIUM. | Number |
| PaloAltoNetworksXDR.Incident.high_severity_alert_count | Number of alerts with the severity HIGH. | Number |
| PaloAltoNetworksXDR.Incident.user_count | Number of users involved in the incident. | Number |
| PaloAltoNetworksXDR.Incident.host_count | Number of hosts involved in the incident. | Number |
| PaloAltoNetworksXDR.Incident.notes | Comments entered by the user regarding the incident. | Unknown |
| PaloAltoNetworksXDR.Incident.resolve_comment | Comments entered by the user when the incident was resolved. | String |
| PaloAltoNetworksXDR.Incident.manual_severity | Incident severity assigned by the user. This does not affect the calculated severity. | String |
| PaloAltoNetworksXDR.Incident.manual_description | Incident description provided by the user. | String |
| PaloAltoNetworksXDR.Incident.xdr_url | A link to the incident view in XDR. | String |
| PaloAltoNetworksXDR.Incident.starred | Whether the incident was starred. | Boolean |
| PaloAltoNetworksXDR.Incident.alerts.alert_id | Unique ID for each alert. | String |
| PaloAltoNetworksXDR.Incident.alerts.detection_timestamp | Date and time that the alert occurred. | Date |
| PaloAltoNetworksXDR.Incident.alerts.source | Source of the alert. The product/vendor from which this alert came originated. | String |
| PaloAltoNetworksXDR.Incident.alerts.severity | Severity of the alert. Can be"low","medium", or "high". | String |
| PaloAltoNetworksXDR.Incident.alerts.name | Calculated name of the alert. | String |
| PaloAltoNetworksXDR.Incident.alerts.category | Category of the alert, for example, Spyware Detected via Anti-Spyware profile. | String |
| PaloAltoNetworksXDR.Incident.alerts.description | Textual description of the alert. | String |
| PaloAltoNetworksXDR.Incident.alerts.host_ip | Host IP address involved in the alert. | String |
| PaloAltoNetworksXDR.Incident.alerts.host_name | Host name involved in the alert. | String |
| PaloAltoNetworksXDR.Incident.alerts.user_name | User name involved with the alert. | String |
| PaloAltoNetworksXDR.Incident.alerts.event_type | The event type. Can be "Process Execution","Network Event","File Event","Registry Event","Injection Event","Load Image Event", or "Windows Event Log". | String |
| PaloAltoNetworksXDR.Incident.alerts.action | The action that triggered the alert. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_pretty | The action that triggered the alert. Can be "Detected \(Reported\)", "Prevented \(Blocked\)", "Detected \(Post Detected\)", "Detected \(Scanned\)", "Detected \(Download\)", "Detected \(Prompt Allow\)", "Prevented \(Prompt Block\)", "Detected", "Prevented \(Denied The Session\)", "Prevented \(Dropped The Session\)", "Prevented \(Dropped The Session And Sent a TCP Reset\)", "Prevented \(Blocked The URL\)", "Prevented \(Blocked The IP\)", "Prevented \(Dropped The Packet\)", "Prevented \(Dropped All Packets\)", "Prevented \(Terminated The Session And Sent a TCP Reset To Both Sides Of The Connection\)", "Prevented \(Terminated The Session And Sent a TCP Reset To The Client\)", "Prevented \(Terminated The Session And Sent a TCP Reset To The Server\)", "Prevented \(Continue\)", "Prevented \(Block-Override\)", "Prevented \(Override-Lockout\)", "Prevented \(Override\)", "Prevented \(Random-Drop\)", "Prevented \(Silently Dropped The Session With An ICMP Unreachable Message To The Host Or Application\)", "Prevented \(Block\)", "Detected \(Allowed The Session\)", "Detected \(Raised An Alert\)", "Detected \(Syncookie Sent\)", "Detected \(Forward\)", "Detected \(Wildfire Upload Success\)", "Detected \(Wildfire Upload Failure\)", "Detected \(Wildfire Upload Skip\)", or "Detected \(Sinkhole\)". | String |
| PaloAltoNetworksXDR.Incident.alerts.actor_process_image_name | The image name. | String |
| PaloAltoNetworksXDR.Incident.alerts.actor_process_command_line | The command line. | String |
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_status | The signature status. Can be "Signed", "Invalid Signature", "Unsigned", "Revoked", "Signature Fail", "N/A", or "Weak Hash". | String |
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_vendor | Singature vendor name. | String |
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_image_name | The image name. | String |
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_command_line | The command line. | String |
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_signature_status | The signature status. Can be "Signed", "Invalid Signature", "Unsigned", "Revoked", "Signature Fail", "N/A", or "Weak Hash". | String |
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_signature_vendor | Signature vendor. | String |
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_causality_id | The causality ID. | Unknown |
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_name | The image name. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_command_line | The command line. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_sha256 | The SHA256 hash of the image. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_process_signature_status | The signature status. Can be "Signed", "Invalid Signature", "Unsigned", "Revoked", "Signature Fail", "N/A", or "Weak Hash". | String |
| PaloAltoNetworksXDR.Incident.alerts.action_process_signature_vendor | Signature vendor name. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_file_path | The file path. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_file_md5 | The MD5 hash of the file. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_file_sha256 | The SHA256 hash of the file. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_registry_data | Registry data. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_registry_full_key | Registry full key. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_local_ip | Local IP address. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_local_port | Local port. | Number |
| PaloAltoNetworksXDR.Incident.alerts.action_remote_ip | Remote IP address. | String |
| PaloAltoNetworksXDR.Incident.alerts.action_remote_port | Remote port. | Number |
| PaloAltoNetworksXDR.Incident.alerts.action_external_hostname | External hostname. | String |
| PaloAltoNetworksXDR.Incident.alerts.fw_app_id | Firewall app ID. | Unknown |
| PaloAltoNetworksXDR.Incident.alerts.is_whitelisted | Whether the alert is whitelisted. | String |
| PaloAltoNetworksXDR.Incident.alerts.starred | Whether the alert is starred. | Boolean |
| PaloAltoNetworksXDR.Incident.network_artifacts.type | The network artifact type, for example, IP. | String |
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_port | The remote port related to the artifact. | number |
| PaloAltoNetworksXDR.Incident.network_artifacts.alert_count | Number of alerts related to the artifact. | number |
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_ip | The remote IP address related to the artifact. | String |
| PaloAltoNetworksXDR.Incident.network_artifacts.is_manual | Whether the artifact was created by the user \(manually\). | boolean |
| PaloAltoNetworksXDR.Incident.network_artifacts.network_domain | The domain related to the artifact. | String |
| PaloAltoNetworksXDR.Incident.network_artifacts.type | The artifact type, for example, IP. | String |
| PaloAltoNetworksXDR.Incident.network_artifacts.network_country | The country related to the artifact. | String |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_status | Digital signature status of the file. Can be "SIGNATURE_UNAVAILABLE", "SIGNATURE_SIGNED", "SIGNATURE_INVALID", "SIGNATURE_UNSIGNED", or "SIGNATURE_WEAK_HASH". | String |
| PaloAltoNetworksXDR.Incident.file_artifacts.is_process | Whether the file artifact is related to a process execution. | boolean |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_name | Name of the file. | String |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_wildfire_verdict | The file verdict calculated by Wildfire. Can be "BENIGN", "MALWARE", "GRAYWARE", "PHISING", or "UNKNOWN". | String |
| PaloAltoNetworksXDR.Incident.file_artifacts.alert_count | Number of alerts related to the artifact. | number |
| PaloAltoNetworksXDR.Incident.file_artifacts.is_malicious | Whether the artifact is malicious \(according to the Wildfire verdict\). | boolean |
| PaloAltoNetworksXDR.Incident.file_artifacts.is_manual | Whether the artifact was created by the user \(manually\). | boolean |
| PaloAltoNetworksXDR.Incident.file_artifacts.type | The artifact type. Can be "META", "GID", "CID", "HASH", "IP", "DOMAIN", "REGISTRY", or "HOSTNAME". | String |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_sha256 | The SHA256 hash of the file. | String |
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_vendor_name | File signature vendor name. | String |
