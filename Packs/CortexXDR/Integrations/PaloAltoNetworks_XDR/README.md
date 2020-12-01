## Overview
---

Cortex XDR is the world's first detection and response app that natively integrates network, endpoint and cloud data to stop sophisticated attacks.
This integration was integrated and tested with version xx of Cortex XDR - IR
## Playbooks
---
#### Cortex XDR Incident Handling
The playbook syncs and updates new XDR alerts that construct the incident.
It enriches indicators using Threat Intelligence integrations and Palo Alto Networks
AutoFocus. The incident's severity is then updated based on the indicators reputation
and an analyst is assigned for manual investigation. If chosen, automated remediation
with Palo Alto Networks FireWall is initiated. After a manual review by the
SOC analyst, the XDR incident is closed automatically.

  
## Use Cases
---
- Fetch incidents from XDR
- Enrich incident with alerts and incident from XDR
- Update incident in XDR
- Search for endpoints
- Isolate/unisolate endpoints
- Insert parsed alerts into XDR
- Insert CEF alerts into XDR
- Query for agent audit reports
- Query for audit management logs
- Create distribution
- Get distribution download URL
- Get distribution versions

## Automation
---
To sync incidents between Demisto and Cortex XDR, you should use the **XDRSyncScript** script, which you can find in the automation page.

## Configuration
---
You need to collect several pieces of information in order to configure the integration on Cortex XSOAR.

#### Generate an API Key and API Key ID
1. In your Cortex XDR platform, go to **Settings**.
2. Click the **+New Key** button in the top right corner
3. Generate a key of type **Advanced**.
4. Copy and paste the key.
5. From the ID column, copy the Key ID.

#### URL
1. In your Cortex XDR platform, go to **Settings**.
2. Click the **Copy URL** button in the top right corner.

#### Configure integration parameters
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Cortex XDR - IR.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Fetch incidents__
    * __Incident type__
    * __Server URL (copy URL from XDR - click ? to see more info.)__
    * __API Key ID__
    * __API Key__
    * __Maximum number of incidents per fetch__
    * __First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days)__
    * __HTTP Timeout__ (default is 120 seconds)
    * __Fetch incident alerts and artifacts__
    * __First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days)__
    * __Incidend Mirroring Direction__
    * __Sync Incident Owners__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---
```
incident_id:31
creation_time:1564594008755
modification_time:1566339537617
detection_time:null
status:new
severity:low
description:6 'Microsoft Windows RPC Fragment Evasion Attempt' alerts detected by PAN NGFW on 6 hosts
assigned_user_mail:null
assigned_user_pretty_name:null
alert_count:6
low_severity_alert_count:0
med_severity_alert_count:6
high_severity_alert_count:0
user_count:1
host_count:6
notes:null
resolve_comment:null
manual_severity:low
manual_description:null
xdr_url:https://1111.paloaltonetworks.com/incident-view/31
```

* Note: By checking the `Fetch incident alerts and artifacts` integration configuration parameter - fetched incidents will include additional data.

## XDR Incident Mirroring
**Note this feature is available from Cortex XSOAR version 6.0.0**

You can enable incident mirroring between Cortex XSOAR incidents and Cortex XDR incidents.
To setup the mirroring follow these instructions:
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Cortex XDR - IR and select your integration instance.
3. Enable `Fetches incidents`.
4. In the `Incident Mirroring Direction` integration parameter, select in which direction should incidents be mirrored:
  * Incoming - Any changes in XDR incidents will be reflected in XSOAR incidents.
  * Outgoing - Any changes in XSOAR incidents will be reflected in XDR incidents.
  * Both - Changes in XSOAR and XDR incidents will be reflected in both directions.
  * None - Choose this to turn off incident mirroring.
5. Optional: Check the `Sync Incident Owners` integration parameter to sync the incident owners in both XDR and XSOAR.
  * Note: This feature will only work if the same users are registered both in Cortex XSOAR and Cortex XDR.
6. Newly fetched incidents will be mirrored in the chosen direction.
  * Note: this will not effect existing incidents.

### XDR Mirroring Notes, limitations and Troubleshooting

* While you can mirror changes in incident fields both in and out in each incident, you can only mirror in a single direction at a time. For example:
  If we have an incident with two fields (A and B) in XDR and XSOAR while *Incoming And Outgoing* mirroring is selected: 
   * I can mirror field A from XDR to XSOAR and field B from XSOAR to XDR.
   * I cannot mirror changes from field A in both directions.
   
  Initially all fields are mirrored in from XDR to XSOAR. Once they are changed in XSOAR, they can only be mirrored out.
* **Do not use the `XDRSyncScript` automation nor any playbook that uses this automation** 
  (e.g `Cortex XDR Incident Sync` or `Cortex XDR incident handling v2`), as it impairs the mirroring functionality.

* When migrating an existing instance to the mirroring feature, or in case the mirroring does not work as expected, make sure that:
   * The default playbook of the `Cortex XDR Incident` incident type is not `Cortex XDR Incident Sync`, change it to a 
     different playbook that does not use `XDRSyncScript`.
   * The XDR integration instance incoming mapper is set to `Cortex XDR - Incoming Mapper` and the outgoing mapper is set to `Cortex XDR - Outgoing Mapper`.

* The API includes a limit rate of 10 API requests per minute. Therefore, in a case of a limit rate exception, the sync loop will stop and will resume from the last incident. 

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. xdr-get-incidents
2. xdr-get-incident-extra-data
3. xdr-update-incident
4. xdr-insert-parsed-alert
5. xdr-insert-cef-alerts
6. xdr-isolate-endpoint
7. xdr-unisolate-endpoint
8. xdr-get-endpoints
9. xdr-get-distribution-versions
10. xdr-create-distribution
11. xdr-get-distribution-url
12. xdr-get-create-distribution-status
13. xdr-get-audit-management-logs
14. xdr-get-audit-agent-reports
### 1. xdr-get-incidents
---
Returns a list of incidents, which you can filter by a list of incident IDs (max. 100), the time the incident was last modified, and the time the incident was created.
      If you pass multiple filtering arguments, they will be concatenated using the AND condition. The OR condition is not supported.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-get-incidents`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lte_creation_time | Time format 2019-12-31T23:59:00. | Optional | 
| gte_creation_time | Returned incidents that were created on or after the specified date/time, in the format 2019-12-31T23:59:00. | Optional | 
| lte_modification_time | Filters returned incidents that were created on or before the specified date/time, in the format 2019-12-31T23:59:00. | Optional | 
| gte_modification_time | Filters returned incidents that were modified on or after the specified date/time, in the format 2019-12-31T23:59:00. | Optional | 
| incident_id_list | An array or CSV string of incident IDs. | Optional | 
| since_creation_time | Filters returned incidents that were created on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. | Optional | 
| since_modification_time | Filters returned incidents that were modified on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on. | Optional | 
| sort_by_modification_time | Sorts returned incidents by the date/time that the incident was last modified ("asc" - ascending, "desc" - descending). | Optional | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). | Optional | 
| limit | Maximum number of incidents to return per page. The default and maximum is 100. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Incident.incident_id | String | Unique ID assigned to each returned incident. | 
| PaloAltoNetworksXDR.Incident.manual_severity | String | Incident severity assigned by the user. This does not affect the calculated severity. Can be "low","medium","high" | 
| PaloAltoNetworksXDR.Incident.manual_description | String | Incident description provided by the user. | 
| PaloAltoNetworksXDR.Incident.assigned_user_mail | String | Email address of the assigned user. | 
| PaloAltoNetworksXDR.Incident.high_severity_alert_count | String | Number of alerts with the severity HIGH. | 
| PaloAltoNetworksXDR.Incident.host_count | number | Number of hosts involved in the incident. | 
| PaloAltoNetworksXDR.Incident.xdr_url | String | A link to the incident view on XDR. | 
| PaloAltoNetworksXDR.Incident.assigned_user_pretty_name | String | Full name of the user assigned to the incident. | 
| PaloAltoNetworksXDR.Incident.alert_count | number | Total number of alerts in the incident. | 
| PaloAltoNetworksXDR.Incident.med_severity_alert_count | number | Number of alerts with the severity MEDIUM. | 
| PaloAltoNetworksXDR.Incident.user_count | number | Number of users involved in the incident. | 
| PaloAltoNetworksXDR.Incident.severity | String | Calculated severity of the incident. Can be "low", "medium", or "high". | 
| PaloAltoNetworksXDR.Incident.low_severity_alert_count | String | Number of alerts with the severity LOW. | 
| PaloAltoNetworksXDR.Incident.status | String | Current status of the incident. Can be "new", "under_investigation", "resolved_threat_handled", "resolved_known_issue", "resolved_duplicate", "resolved_false_positive", or "resolved_other". | 
| PaloAltoNetworksXDR.Incident.description | String | Dynamic calculated description of the incident. | 
| PaloAltoNetworksXDR.Incident.resolve_comment | String | Comments entered by the user when the incident was resolved. | 
| PaloAltoNetworksXDR.Incident.notes | String | Comments entered by the user regarding the incident. | 
| PaloAltoNetworksXDR.Incident.creation_time | date | Date and time the incident was created on XDR. | 
| PaloAltoNetworksXDR.Incident.detection_time | date | Date and time that the first alert occurred in the incident. | 
| PaloAltoNetworksXDR.Incident.modification_time | date | Date and time that the incident was last modified. | 


##### Command Example
```!xdr-get-incidents gte_creation_time=2010-10-10T00:00:00 limit=3 sort_by_creation_time=desc```

##### Context Example
```
{
    "PaloAltoNetworksXDR.Incident": [
        {
            "host_count": 1, 
            "incident_id": "4", 
            "manual_severity": "medium", 
            "description": "5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast  ", 
            "severity": "medium", 
            "modification_time": 1579290004178, 
            "assigned_user_pretty_name": null, 
            "notes": null, 
            "creation_time": 1577276587937, 
            "alert_count": 5, 
            "med_severity_alert_count": 1, 
            "detection_time": null, 
            "assigned_user_mail": null, 
            "resolve_comment": "This issue was solved in Incident number 192304", 
            "status": "new", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/4", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 4, 
            "manual_description": null
        }, 
        {
            "host_count": 1, 
            "incident_id": "3", 
            "manual_severity": "medium", 
            "description": "'test 1' generated by Virus Total - Firewall", 
            "severity": "medium", 
            "modification_time": 1579237974014, 
            "assigned_user_pretty_name": "woo@demisto.com", 
            "notes": null, 
            "creation_time": 1576100096594, 
            "alert_count": 1, 
            "med_severity_alert_count": 0, 
            "detection_time": null, 
            "assigned_user_mail": "woo@demisto.com", 
            "resolve_comment": null, 
            "status": "new", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/3", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 1, 
            "manual_description": null
        }, 
        {
            "host_count": 1, 
            "incident_id": "2", 
            "manual_severity": "high", 
            "description": "'Alert Name Example 333' along with 1 other alert generated by Virus Total - VPN & Firewall-3 and Checkpoint - SandBlast", 
            "severity": "high", 
            "modification_time": 1579288790259, 
            "assigned_user_pretty_name": null, 
            "notes": null, 
            "creation_time": 1576062816474, 
            "alert_count": 2, 
            "med_severity_alert_count": 0, 
            "detection_time": null, 
            "assigned_user_mail": null, 
            "resolve_comment": null, 
            "status": "under_investigation", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/2", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 2, 
            "manual_description": null
        }
    ]
}
```

##### Human Readable Output
### Incidents
|alert_count|assigned_user_mail|assigned_user_pretty_name|creation_time|description|detection_time|high_severity_alert_count|host_count|incident_id|low_severity_alert_count|manual_description|manual_severity|med_severity_alert_count|modification_time|notes|resolve_comment|severity|starred|status|user_count|xdr_url|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 5 |  |  | 1577276587937 | 5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast   |  | 4 | 1 | 4 | 0 |  | medium | 1 | 1579290004178 |  | This issue was solved in Incident number 192304 | medium | false | new | 1 | `https://some.xdr.url.com/incident-view/4` |
| 1 | woo@demisto.com | woo@demisto.com | 1576100096594 | 'test 1' generated by Virus Total - Firewall |  | 1 | 1 | 3 | 0 |  | medium | 0 | 1579237974014 |  |  | medium | false | new | 1 | `https://some.xdr.url.com/incident-view/3` |
| 2 |  |  | 1576062816474 | 'Alert Name Example 333' along with 1 other alert generated by Virus Total - VPN & Firewall-3 and Checkpoint - SandBlast |  | 2 | 1 | 2 | 0 |  | high | 0 | 1579288790259 |  |  | high | false | under_investigation | 1 | `https://some.xdr.url.com/incident-view/2` |


### 2. xdr-get-incident-extra-data
---
Returns additional data for the specified incident, for example, related alerts, file artifacts, network artifacts, and so on.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-get-incident-extra-data`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident for which to get additional data. | Required | 
| alerts_limit | Maximum number of alerts to return. Default is 1,000. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Incident.incident_id | String | Unique ID assigned to each returned incident. | 
| PaloAltoNetworksXDR.Incident.creation_time | Date | Date and time the incident was created on XDR. | 
| PaloAltoNetworksXDR.Incident.modification_time | Date | Date and time that the incident was last modified. | 
| PaloAltoNetworksXDR.Incident.detection_time | Date | Date and time that the first alert occurred in the incident. | 
| PaloAltoNetworksXDR.Incident.status | String | Current status of the incident:
"new","under_investigation","resolved_threat_handled","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_other" | 
| PaloAltoNetworksXDR.Incident.severity | String | Calculated severity of the incident "low","medium","high" | 
| PaloAltoNetworksXDR.Incident.description | String | Dynamic calculated description of the incident. | 
| PaloAltoNetworksXDR.Incident.assigned_user_mail | String | Email address of the assigned user. | 
| PaloAltoNetworksXDR.Incident.assigned_user_pretty_name | String | Full name of the user assigned to the incident. | 
| PaloAltoNetworksXDR.Incident.alert_count | Number | Total number of alerts in the incident. | 
| PaloAltoNetworksXDR.Incident.low_severity_alert_count | Number | Number of alerts with the severity LOW. | 
| PaloAltoNetworksXDR.Incident.med_severity_alert_count | Number | Number of alerts with the severity MEDIUM. | 
| PaloAltoNetworksXDR.Incident.high_severity_alert_count | Number | Number of alerts with the severity HIGH. | 
| PaloAltoNetworksXDR.Incident.user_count | Number | Number of users involved in the incident. | 
| PaloAltoNetworksXDR.Incident.host_count | Number | Number of hosts involved in the incident | 
| PaloAltoNetworksXDR.Incident.notes | Unknown | Comments entered by the user regarding the incident. | 
| PaloAltoNetworksXDR.Incident.resolve_comment | String | Comments entered by the user when the incident was resolved. | 
| PaloAltoNetworksXDR.Incident.manual_severity | String | Incident severity assigned by the user. This does not affect the calculated severity low medium high | 
| PaloAltoNetworksXDR.Incident.manual_description | String | Incident description provided by the user. | 
| PaloAltoNetworksXDR.Incident.xdr_url | String | A link to the incident view on XDR. | 
| PaloAltoNetworksXDR.Incident.starred | Boolean | Incident starred | 
| PaloAltoNetworksXDR.Incident.alerts.alert_id | String | Unique ID for each alert. | 
| PaloAltoNetworksXDR.Incident.alerts.detection_timestamp | Date | Date and time that the alert occurred. | 
| PaloAltoNetworksXDR.Incident.alerts.source | String | Source of the alert. The product/vendor this alert came from. | 
| PaloAltoNetworksXDR.Incident.alerts.severity | String | Severity of the alert.,"low","medium","high""" | 
| PaloAltoNetworksXDR.Incident.alerts.name | String | Calculated name of the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.category | String | Category of the alert, for example, Spyware Detected via Anti-Spyware profile. | 
| PaloAltoNetworksXDR.Incident.alerts.description | String | Textual description of the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.host_ip_list | Unknown | Host IP involved in the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.host_name | String | Host name involved in the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.user_name | String | User name involved with the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.event_type | String | Event type "Process Execution","Network Event","File Event","Registry Event","Injection Event","Load Image Event","Windows Event Log" | 
| PaloAltoNetworksXDR.Incident.alerts.action | String | The action that triggered the alert. "REPORTED", "BLOCKED", "POST_DETECTED", "SCANNED", "DOWNLOAD", "PROMPT_ALLOW", "PROMPT_BLOCK", "DETECTED", "BLOCKED_1", "BLOCKED_2", "BLOCKED_3", "BLOCKED_5", "BLOCKED_6", "BLOCKED_7", "BLOCKED_8", "BLOCKED_9", "BLOCKED_10", "BLOCKED_11", "BLOCKED_13", "BLOCKED_14", "BLOCKED_15", "BLOCKED_16", "BLOCKED_17", "BLOCKED_24", "BLOCKED_25", "DETECTED_0", "DETECTED_4", "DETECTED_18", "DETECTED_19", "DETECTED_20", "DETECTED_21", "DETECTED_22", "DETECTED_23" | 
| PaloAltoNetworksXDR.Incident.alerts.action_pretty | String | The action that triggered the alert "Detected (Reported)" "Prevented (Blocked)" "Detected (Post Detected)" "Detected (Scanned)" "Detected (Download)" "Detected (Prompt Allow)" "Prevented (Prompt Block)" "Detected" "Prevented (Denied The Session)" "Prevented (Dropped The Session)" "Prevented (Dropped The Session And Sent a TCP Reset)" "Prevented (Blocked The URL)" "Prevented (Blocked The IP)" "Prevented (Dropped The Packet)" "Prevented (Dropped All Packets)" "Prevented (Terminated The Session And Sent a TCP Reset To Both Sides Of The Connection)" "Prevented (Terminated The Session And Sent a TCP Reset To The Client)" "Prevented (Terminated The Session And Sent a TCP Reset To The Server)" "Prevented (Continue)" "Prevented (Block-Override)" "Prevented (Override-Lockout)" "Prevented (Override)" "Prevented (Random-Drop)" "Prevented (Silently Dropped The Session With An ICMP Unreachable Message To The Host Or Application)" "Prevented (Block)" "Detected (Allowed The Session)" "Detected (Raised An Alert)" "Detected (Syncookie Sent)" "Detected (Forward)" "Detected (Wildfire Upload Success)" "Detected (Wildfire Upload Failure)" "Detected (Wildfire Upload Skip)" "Detected (Sinkhole)" | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_image_name | String | Image name | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_command_line | String | Command line | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_status | String | Signature status "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash" | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_vendor | String | Singature vendor name | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_image_name | String | Image name | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_command_line | String | Command line | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_signature_status | String | Signature status "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash" | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_signature_vendor | String | Signature vendor | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_causality_id | Unknown | Causality id | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_name | String | Image name | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_command_line | String | Command line | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_sha256 | String | Image SHA256 | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_signature_status | String | Signature status "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash" | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_signature_vendor | String | Signature vendor name | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_path | String | File path | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_md5 | String | File MD5 | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_sha256 | String | File SHA256 | 
| PaloAltoNetworksXDR.Incident.alerts.action_registry_data | String | Registry data | 
| PaloAltoNetworksXDR.Incident.alerts.action_registry_full_key | String | Registry full key | 
| PaloAltoNetworksXDR.Incident.alerts.action_local_ip | String | Local IP | 
| PaloAltoNetworksXDR.Incident.alerts.action_local_port | Number | Local port | 
| PaloAltoNetworksXDR.Incident.alerts.action_remote_ip | String | Remote IP | 
| PaloAltoNetworksXDR.Incident.alerts.action_remote_port | Number | Remote port | 
| PaloAltoNetworksXDR.Incident.alerts.action_external_hostname | String | External hostname | 
| PaloAltoNetworksXDR.Incident.alerts.fw_app_id | Unknown | Firewall app id | 
| PaloAltoNetworksXDR.Incident.alerts.is_whitelisted | String | Is whitelisted "Yes" "No" | 
| PaloAltoNetworksXDR.Incident.alerts.starred | Boolean | Alert starred | 
| PaloAltoNetworksXDR.Incident.network_artifacts.type | String | Network artifact type "IP" | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_port | number | The remote port related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.alert_count | number | Number of alerts related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_ip | String | The remote IP related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.is_manual | boolean | Whether the artifact was created by the user (manually). | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_domain | String | The domain related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.type | String | The artifact type. "META", "GID", "CID", "HASH", "IP", "DOMAIN", "REGISTRY", "HOSTNAME" | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_country | String | The country related to the artifact | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_status | String | Digital signature status of the file. "SIGNATURE_UNAVAILABLE" "SIGNATURE_SIGNED" "SIGNATURE_INVALID" "SIGNATURE_UNSIGNED" "SIGNATURE_WEAK_HASH" | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_process | boolean | Whether the file artifact is related to a process execution. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_name | String | Name of the file. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_wildfire_verdict | String | The file verdict, calculated by Wildfire. "BENIGN" "MALWARE" "GRAYWARE" "PHISING" "UNKNOWN" | 
| PaloAltoNetworksXDR.Incident.file_artifacts.alert_count | number | Number of alerts related to the artifact. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_malicious | boolean | Whether the artifact is malicious, decided by the Wildfire verdic | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_manual | boolean | Whether the artifact was created by the user (manually). | 
| PaloAltoNetworksXDR.Incident.file_artifacts.type | String | The artifact type "META" "GID" "CID" "HASH" "IP" "DOMAIN" "REGISTRY" "HOSTNAME" | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_sha256 | String | SHA-256 hash of the file | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_vendor_name | String | File signature vendor name | 
| Account.Username | String | The username in the relevant system. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 


##### Command Example
```!xdr-get-incident-extra-data incident_id=4 alerts_limit=10```

##### Context Example
```
{
    "Account": {
        "Username": [
            null
        ]
    },
    "Endpoint": {
        "Hostname": [
            null
        ]
    },
    "PaloAltoNetworksXDR.Incident": {
        "host_count": 1, 
        "manual_severity": "medium", 
        "xdr_url": "https://some.xdr.url.com/incident-view/4", 
        "assigned_user_pretty_name": null, 
        "alert_count": 5, 
        "med_severity_alert_count": 1, 
        "detection_time": null, 
        "user_count": 1, 
        "severity": "medium", 
        "alerts": [
            {
                "action_process_signature_status": "N/A", 
                "action_pretty": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "event_type": "Network Event", 
                "alert_id": "6", 
                "action_file_sha256": null, 
                "action_external_hostname": null, 
                "causality_actor_process_command_line": null, 
                "description": "Test - alert generated by Test XDR Playbook", 
                "category": null, 
                "severity": "medium", 
                "source": "Cisco - Sandblast", 
                "action_remote_port": 8000, 
                "causality_actor_process_signature_status": "N/A", 
                "fw_app_id": null, 
                "is_whitelisted": "No", 
                "action_local_ip": "196.168.0.1", 
                "action_registry_data": null, 
                "action_process_image_sha256": null, 
                "user_name": null, 
                "action_remote_ip": "2.2.2.2", 
                "action_process_signature_vendor": "N/A", 
                "actor_process_signature_status": "N/A", 
                "name": "Test - alert generated by Test XDR Playbook", 
                "causality_actor_causality_id": null, 
                "host_ip": null,
                "host_ip_list": [], 
                "action_process_image_name": null, 
                "detection_timestamp": 1577276586921, 
                "action_file_md5": null, 
                "causality_actor_process_image_name": null, 
                "action_file_path": null, 
                "action_process_image_command_line": null, 
                "action_local_port": 7000, 
                "actor_process_image_name": null, 
                "action_registry_full_key": null, 
                "actor_process_signature_vendor": "N/A", 
                "actor_process_command_line": null, 
                "host_name": null, 
                "action": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "starred": false, 
                "causality_actor_process_signature_vendor": "N/A"
            }, 
            {
                "action_process_signature_status": "N/A", 
                "action_pretty": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "event_type": "Network Event", 
                "alert_id": "7", 
                "action_file_sha256": null, 
                "action_external_hostname": null, 
                "causality_actor_process_command_line": null, 
                "description": "This alert from content  TestXDRPlaybook description", 
                "category": null, 
                "severity": "high", 
                "source": "Checkpoint - SandBlast", 
                "action_remote_port": 6000, 
                "causality_actor_process_signature_status": "N/A", 
                "fw_app_id": null, 
                "is_whitelisted": "No", 
                "action_local_ip": "196.168.0.111", 
                "action_registry_data": null, 
                "action_process_image_sha256": null, 
                "user_name": null, 
                "action_remote_ip": "2.2.2.2", 
                "action_process_signature_vendor": "N/A", 
                "actor_process_signature_status": "N/A", 
                "name": "This alert from content  TestXDRPlaybook", 
                "causality_actor_causality_id": null, 
                "host_ip": null,
                "host_ip_list": [], 
                "action_process_image_name": null, 
                "detection_timestamp": 1577776701589, 
                "action_file_md5": null, 
                "causality_actor_process_image_name": null, 
                "action_file_path": null, 
                "action_process_image_command_line": null, 
                "action_local_port": 2000, 
                "actor_process_image_name": null, 
                "action_registry_full_key": null, 
                "actor_process_signature_vendor": "N/A", 
                "actor_process_command_line": null, 
                "host_name": null, 
                "action": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "starred": false, 
                "causality_actor_process_signature_vendor": "N/A"
            }, 
            {
                "action_process_signature_status": "N/A", 
                "action_pretty": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "event_type": "Network Event", 
                "alert_id": "8", 
                "action_file_sha256": null, 
                "action_external_hostname": null, 
                "causality_actor_process_command_line": null, 
                "description": "This alert from content  TestXDRPlaybook description", 
                "category": null, 
                "severity": "high", 
                "source": "Checkpoint - SandBlast", 
                "action_remote_port": 6000, 
                "causality_actor_process_signature_status": "N/A", 
                "fw_app_id": null, 
                "is_whitelisted": "No", 
                "action_local_ip": "196.168.0.111", 
                "action_registry_data": null, 
                "action_process_image_sha256": null, 
                "user_name": null, 
                "action_remote_ip": "2.2.2.2", 
                "action_process_signature_vendor": "N/A", 
                "actor_process_signature_status": "N/A", 
                "name": "This alert from content  TestXDRPlaybook", 
                "causality_actor_causality_id": null, 
                "host_ip": null, 
                "host_ip_list": [],
                "action_process_image_name": null, 
                "detection_timestamp": 1577958479843, 
                "action_file_md5": null, 
                "causality_actor_process_image_name": null, 
                "action_file_path": null, 
                "action_process_image_command_line": null, 
                "action_local_port": 2000, 
                "actor_process_image_name": null, 
                "action_registry_full_key": null, 
                "actor_process_signature_vendor": "N/A", 
                "actor_process_command_line": null, 
                "host_name": null, 
                "action": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "starred": false, 
                "causality_actor_process_signature_vendor": "N/A"
            }, 
            {
                "action_process_signature_status": "N/A", 
                "action_pretty": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "event_type": "Network Event", 
                "alert_id": "9", 
                "action_file_sha256": null, 
                "action_external_hostname": null, 
                "causality_actor_process_command_line": null, 
                "description": "This alert from content  TestXDRPlaybook description", 
                "category": null, 
                "severity": "high", 
                "source": "Checkpoint - SandBlast", 
                "action_remote_port": 6000, 
                "causality_actor_process_signature_status": "N/A", 
                "fw_app_id": null, 
                "is_whitelisted": "No", 
                "action_local_ip": "196.168.0.111", 
                "action_registry_data": null, 
                "action_process_image_sha256": null, 
                "user_name": null, 
                "action_remote_ip": "2.2.2.2", 
                "action_process_signature_vendor": "N/A", 
                "actor_process_signature_status": "N/A", 
                "name": "This alert from content  TestXDRPlaybook", 
                "causality_actor_causality_id": null, 
                "host_ip": null, 
                "host_ip_list": [],
                "action_process_image_name": null, 
                "detection_timestamp": 1578123895414, 
                "action_file_md5": null, 
                "causality_actor_process_image_name": null, 
                "action_file_path": null, 
                "action_process_image_command_line": null, 
                "action_local_port": 2000, 
                "actor_process_image_name": null, 
                "action_registry_full_key": null, 
                "actor_process_signature_vendor": "N/A", 
                "actor_process_command_line": null, 
                "host_name": null, 
                "action": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "starred": false, 
                "causality_actor_process_signature_vendor": "N/A"
            }, 
            {
                "action_process_signature_status": "N/A", 
                "action_pretty": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "event_type": "Network Event", 
                "alert_id": "10", 
                "action_file_sha256": null, 
                "action_external_hostname": null, 
                "causality_actor_process_command_line": null, 
                "description": "This alert from content  TestXDRPlaybook description", 
                "category": null, 
                "severity": "high", 
                "source": "Checkpoint - SandBlast", 
                "action_remote_port": 6000, 
                "causality_actor_process_signature_status": "N/A", 
                "fw_app_id": null, 
                "is_whitelisted": "No", 
                "action_local_ip": "196.168.0.111", 
                "action_registry_data": null, 
                "action_process_image_sha256": null, 
                "user_name": null, 
                "action_remote_ip": "2.2.2.2", 
                "action_process_signature_vendor": "N/A", 
                "actor_process_signature_status": "N/A", 
                "name": "This alert from content  TestXDRPlaybook", 
                "causality_actor_causality_id": null, 
                "host_ip": null, 
                "host_ip_list": [],
                "action_process_image_name": null, 
                "detection_timestamp": 1578927443615, 
                "action_file_md5": null, 
                "causality_actor_process_image_name": null, 
                "action_file_path": null, 
                "action_process_image_command_line": null, 
                "action_local_port": 2000, 
                "actor_process_image_name": null, 
                "action_registry_full_key": null, 
                "actor_process_signature_vendor": "N/A", 
                "actor_process_command_line": null, 
                "host_name": null, 
                "action": [
                    "VALUE_NA", 
                    "N/A"
                ], 
                "starred": false, 
                "causality_actor_process_signature_vendor": "N/A"
            }
        ], 
        "low_severity_alert_count": 0, 
        "status": "new", 
        "description": "5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast  ", 
        "resolve_comment": "This issue was solved in Incident number 192304", 
        "creation_time": 1577276587937, 
        "modification_time": 1579290004178, 
        "network_artifacts": [
            {
                "network_remote_port": 8000, 
                "alert_count": 5, 
                "network_remote_ip": "2.2.2.2", 
                "is_manual": false, 
                "network_domain": null, 
                "type": "IP", 
                "network_country": null
            }
        ], 
        "file_artifacts": [], 
        "manual_description": null, 
        "incident_id": "4", 
        "notes": null, 
        "assigned_user_mail": null, 
        "starred": false, 
        "high_severity_alert_count": 4
    }
}
```

##### Human Readable Output
### Incident 4
|alert_count|assigned_user_mail|assigned_user_pretty_name|creation_time|description|detection_time|high_severity_alert_count|host_count|incident_id|low_severity_alert_count|manual_description|manual_severity|med_severity_alert_count|modification_time|notes|resolve_comment|severity|starred|status|user_count|xdr_url|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 5 |  |  | 1577276587937 | 5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast   |  | 4 | 1 | 4 | 0 |  | medium | 1 | 1579290004178 |  | This issue was solved in Incident number 192304 | medium | false | new | 1 | `https://some.xdr.url.com/incident-view/4` |

### Alerts
|action|action_external_hostname|action_file_md5|action_file_path|action_file_sha256|action_local_ip|action_local_port|action_pretty|action_process_image_command_line|action_process_image_name|action_process_image_sha256|action_process_signature_status|action_process_signature_vendor|action_registry_data|action_registry_full_key|action_remote_ip|action_remote_port|actor_process_command_line|actor_process_image_name|actor_process_signature_status|actor_process_signature_vendor|alert_id|category|causality_actor_causality_id|causality_actor_process_command_line|causality_actor_process_image_name|causality_actor_process_signature_status|causality_actor_process_signature_vendor|description|detection_timestamp|event_type|fw_app_id|host_ip_list|host_name|is_whitelisted|name|severity|source|starred|user_name|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.1 | 7000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 8000 |  |  | N/A | N/A | 6 |  |  |  |  | N/A | N/A | Test - alert generated by Test XDR Playbook | 1577276586921 | Network Event |  |  |  | No | Test - alert generated by Test XDR Playbook | medium | Cisco - Sandblast | false |  |
| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.111 | 2000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 6000 |  |  | N/A | N/A | 7 |  |  |  |  | N/A | N/A | This alert from content  TestXDRPlaybook description | 1577776701589 | Network Event |  |  |  | No | This alert from content  TestXDRPlaybook | high | Checkpoint - SandBlast | false |  |
| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.111 | 2000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 6000 |  |  | N/A | N/A | 8 |  |  |  |  | N/A | N/A | This alert from content  TestXDRPlaybook description | 1577958479843 | Network Event |  |  |  | No | This alert from content  TestXDRPlaybook | high | Checkpoint - SandBlast | false |  |
| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.111 | 2000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 6000 |  |  | N/A | N/A | 9 |  |  |  |  | N/A | N/A | This alert from content  TestXDRPlaybook description | 1578123895414 | Network Event |  |  |  | No | This alert from content  TestXDRPlaybook | high | Checkpoint - SandBlast | false |  |
| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.111 | 2000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 6000 |  |  | N/A | N/A | 10 |  |  |  |  | N/A | N/A | This alert from content  TestXDRPlaybook description | 1578927443615 | Network Event |  |  |  | No | This alert from content  TestXDRPlaybook | high | Checkpoint - SandBlast | false |  |

### Network Artifacts
|alert_count|is_manual|network_country|network_domain|network_remote_ip|network_remote_port|type|
|---|---|---|---|---|---|---|
| 5 | false |  |  | 2.2.2.2 | 8000 | IP |

### File Artifacts
**No entries.**


### 3. xdr-update-incident
---
Updates one or more fields of a specified incident. Missing fields will be ignored. To remove the assignment for an incident, pass a null value in assignee email argument.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-update-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | XDR incident ID. You can get the incident ID from the output of the 'xdr-get-incidents' command or the 'xdr-get-incident-extra-details' command. | Required | 
| manual_severity | Severity to assign to the incident (LOW, MEDIUM, or HIGH). | Optional | 
| assigned_user_mail | Email address of the user to assigned to the incident. | Optional | 
| assigned_user_pretty_name | Full name of the user assigned to the incident. | Optional | 
| status | Status of the incident (NEW, UNDER_INVESTIGATION, RESOLVED_THREAT_HANDLED, RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE, RESOLVED_OTHER). | Optional | 
| resolve_comment | Comment explaining why the incident was resolved. This should be set when the incident is resolved. | Optional | 
| unassign_user | If true, will remove all assigned users from the incident. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!xdr-update-incident incident_id="4" status="RESOLVED_KNOWN_ISSUE" resolve_comment="This issue was solved in Incident number 192304"```

##### Human Readable Output
Incident 4 has been updated

### 4. xdr-insert-parsed-alert
---
Upload alert from external alert sources in Cortex XDR format. Cortex XDR displays alerts that are parsed
successfully in related incidents and views. You can send 600 alerts per minute. Each request can contain a
maximum of 60 alerts.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-insert-parsed-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product | String value that defines the product. | Required | 
| vendor | String value that defines the product. | Required | 
| local_ip | String value for the source IP address | Optional | 
| local_port | Integer value for the source port. | Required | 
| remote_ip | String value of the destination IP<br/>address. | Required | 
| remote_port | Integer value for the destination<br/>port. | Required | 
| event_timestampt | Integer value representing the epoch of the time the alert occurred in milliseconds or String value of date format 2019-10-23T10:00:00. If not set then the event time will be defined as now. | Optional | 
| severity | String value of alert severity:<br/>Informational, Low, Medium, High, or Unknown | Optional | 
| alert_name | String defining the alert name | Required | 
| alert_description | String defining the alert description | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!xdr-insert-parsed-alert product="SandBlast" vendor="Checkpoint" local_ip="196.168.0.1" local_port="600" remote_ip="5.5.5.5" remote_port="500" event_timestampt="2020-01-01T00:00:00" severity="High" alert_name="some alert" alert_description="this is test alert"```

##### Human Readable Output
Alert inserted successfully

### 5. xdr-insert-cef-alerts
---
Upload alerts in CEF format from external alert sources. After you map CEF alert fields to Cortex XDR fields, Cortex XDR displays the alerts in related incidents and views. You can send 600 requests per minute. Each request can contain a maximum of 60 alerts.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-insert-cef-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cef_alerts | List of alerts in CEF format. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!xdr-insert-cef-alerts cef_alerts="CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|microsoft-ds|Unknown|act=AcceptdeviceDirection=0 rt=1569477512000 spt=56957 dpt=445 cs2Label=Rule Name cs2=ADPrimery layer_name=FW_Device_blackened Securitylayer_uuid=07693fc7-1a5c-4f31-8afe-77ae96c71b8c match_id=1806 parent_rule=0rule_action=Accept rule_uid=8e45f36b-d106-4d81-a1f0-9d1ed9a6be5c ifname=bond2logid=0 loguid={0x5d8c5388,0x61,0x29321fac,0xc0000022} origin=1.1.1.1originsicname=CN=DWdeviceBlackend,O=Blackend sequencenum=363 version=5dst=1.1.1.1 inzone=External outzone=Internal product=VPN-1 & FireWall-1 proto=6service_id=microsoft-ds src=1.1.1.1"```

##### Human Readable Output
Alerts inserted successfully

### 6. xdr-isolate-endpoint
---
Isolates the specified endpoint.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-isolate-endpoint`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID (string) to isolate. You can retrieve the string from the xdr-get-endpoints | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!xdr-isolate-endpoint endpoint_id="f8a2f58846b542579c12090652e79f3d"```

##### Human Readable Output
Endpoint f8a2f58846b542579c12090652e79f3d has isolated successfully

### 7. xdr-unisolate-endpoint
---
Reverses the isolation of an endpoint.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-unisolate-endpoint`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID (string) for which to reverse the isolation. You can retrieve it from the xdr-get-endpoints | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!xdr-unisolate-endpoint endpoint_id="f8a2f58846b542579c12090652e79f3d"```

##### Human Readable Output
Endpoint f8a2f58846b542579c12090652e79f3d already unisolated

### 8. xdr-get-endpoints
---
Gets a list of endpoints, according to the passed filters. Filtering by multiple fields will be concatenated using AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of endpoint from the start of the result set (start by counting from 0).
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-get-endpoints`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id_list | A comma-separated list of endpoint IDs. | Optional | 
| dist_name | A comma-separated list of distribution package names or installation package names. <br/>Example: dist_name1,dist_name2 | Optional | 
| ip_list | A comma-separated list of IP addresses.<br/>Example: 8.8.8.8,1.1.1.1 | Optional | 
| group_name | The group name to which the agent belongs.<br/>Example: group_name1,group_name2 | Optional | 
| platform | The endpoint platform. Can be "windows", "linux", "macos", or "android".  | Optional | 
| alias_name | A comma-separated list of alias names.<br/>Examples: alias_name1,alias_name2 | Optional | 
| isolate | "Specifies whether the endpoint was isolated or unisolated. Can be "isolated" or "unisolated". | Optional | 
| hostname | Hostname<br/>Example: hostname1,hostname2 | Optional | 
| first_seen_gte | All the agents that were first seen after {first_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date) | Optional | 
| first_seen_lte | All the agents that were first seen before {first_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date) | Optional | 
| last_seen_gte | All the agents that were last seen before {last_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date) | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date) | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). | Optional | 
| limit | Maximum number of endpoints to return per page. The default and maximum is 30. | Optional | 
| sort_by | Specifies whether to sort endpoints by the first time or last time they were seen. Can be "first_seen" or "last_seen". | Optional | 
| sort_order | The order by which to sort results. Can be "asc" (ascending) or "desc" ( descending). Default set to asc. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Endpoint.endpoint_id | String | The endpoint ID. | 
| PaloAltoNetworksXDR.Endpoint.endpoint_name | String | The endpoint name. | 
| PaloAltoNetworksXDR.Endpoint.endpoint_type | String | The endpoint type. | 
| PaloAltoNetworksXDR.Endpoint.endpoint_status | String | The status of the endpoint' | 
| PaloAltoNetworksXDR.Endpoint.os_type | String | The endpoint OS type. | 
| PaloAltoNetworksXDR.Endpoint.ip | Unknown | A list of IP addresses. | 
| PaloAltoNetworksXDR.Endpoint.users | Unknown | A list of users. | 
| PaloAltoNetworksXDR.Endpoint.domain | String | The endpoint domain. | 
| PaloAltoNetworksXDR.Endpoint.alias | String | The endpoint's aliases. | 
| PaloAltoNetworksXDR.Endpoint.first_seen | Unknown | First seen date/time in Epoch (milliseconds). | 
| PaloAltoNetworksXDR.Endpoint.last_seen | Date | Last seen date/time in Epoch (milliseconds). | 
| PaloAltoNetworksXDR.Endpoint.content_version | String | Content version. | 
| PaloAltoNetworksXDR.Endpoint.installation_package | String | Installation package. | 
| PaloAltoNetworksXDR.Endpoint.active_directory | String | Active directory. | 
| PaloAltoNetworksXDR.Endpoint.install_date | Date | Install date in Epoch (milliseconds). | 
| PaloAltoNetworksXDR.Endpoint.endpoint_version | String | Endpoint version. | 
| PaloAltoNetworksXDR.Endpoint.is_isolated | String | Whether the endpoint is isolated. | 
| PaloAltoNetworksXDR.Endpoint.group_name | String | The name of the group to which the endpoint belongs. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| Endpoint.ID | String | The unique ID within the tool retrieving the endpoint. | 
| Endpoint.IPAddress | String | The IP address of the endpoint. | 
| Endpoint.Domain | String | The domain of the endpoint. | 
| Endpoint.OS | String | Endpoint OS. | 

##### Command Example
```!xdr-get-endpoints isolate="unisolated" first_seen_gte="3 month" page="0" limit="30" sort_order="asc"```

##### Context Example
```
{
    "Endpoint": [
        {
            "Domain": "WORKGROUP",
            "Hostname": "aaaaa.compute.internal",
            "ID": "ea303670c76e4ad09600c8b346f7c804",
            "IPAddress": [
                "172.31.11.11"
            ],
            "OS": "AGENT_OS_WINDOWS"
        },
        {
            "Domain": "WORKGROUP",
            "Hostname": "EC2AMAZ-P7PPOI4",
            "ID": "f8a2f58846b542579c12090652e79f3d",
            "IPAddress": [
                "2.2.2.2"
            ],
            "OS": "AGENT_OS_WINDOWS"
        }
    ],
    "PaloAltoNetworksXDR.Endpoint": [
        {
            "domain": "", 
            "users": [
                "ec2-user"
            ], 
            "endpoint_name": "aaaaa.compute.internal", 
            "ip": [
                "172.31.11.11"
            ], 
            "install_date": 1575795969644, 
            "endpoint_version": "7.0.0.1915", 
            "group_name": null, 
            "installation_package": "linux", 
            "alias": "", 
            "active_directory": null, 
            "endpoint_status": "CONNECTED", 
            "os_type": "AGENT_OS_LINUX", 
            "endpoint_id": "ea303670c76e4ad09600c8b346f7c804", 
            "content_version": "111-17757", 
            "first_seen": 1575795969644, 
            "endpoint_type": "AGENT_TYPE_SERVER", 
            "is_isolated": "AGENT_UNISOLATED", 
            "last_seen": 1579290023629
        }, 
        {
            "domain": "WORKGROUP", 
            "users": [
                "Administrator"
            ], 
            "endpoint_name": "EC2AMAZ-P7PPOI4", 
            "ip": [
                "2.2.2.2"
            ], 
            "install_date": 1575796381739, 
            "endpoint_version": "7.0.0.27797", 
            "group_name": null, 
            "installation_package": "Windows Server 2016", 
            "alias": "", 
            "active_directory": null, 
            "endpoint_status": "CONNECTED", 
            "os_type": "AGENT_OS_WINDOWS", 
            "endpoint_id": "f8a2f58846b542579c12090652e79f3d", 
            "content_version": "111-17757", 
            "first_seen": 1575796381739, 
            "endpoint_type": "AGENT_TYPE_SERVER", 
            "is_isolated": "AGENT_UNISOLATED", 
            "last_seen": 1579289957412
        }
    ]
}
```

##### Human Readable Output
### Endpoints
|active_directory|alias|content_version|domain|endpoint_id|endpoint_name|endpoint_status|endpoint_type|endpoint_version|first_seen|group_name|install_date|installation_package|ip|is_isolated|last_seen|os_type|users|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  |  | 111-17757 |  | ea303670c76e4ad09600c8b346f7c804 | aaaaa.compute.internal | CONNECTED | AGENT_TYPE_SERVER | 7.0.0.1915 | 1575795969644 |  | 1575795969644 | linux | 172.31.11.11 | AGENT_UNISOLATED | 1579290023629 | AGENT_OS_LINUX | ec2-user |
|  |  | 111-17757 | WORKGROUP | f8a2f58846b542579c12090652e79f3d | EC2AMAZ-P7PPOI4 | CONNECTED | AGENT_TYPE_SERVER | 7.0.0.27797 | 1575796381739 |  | 1575796381739 | Windows Server 2016 | 2.2.2.2 | AGENT_UNISOLATED | 1579289957412 | AGENT_OS_WINDOWS | Administrator |


### 9. xdr-get-distribution-versions
---
Gets a list of all the agent versions to use for creating a distribution list.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-get-distribution-versions`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.DistributionVersions.windows | Unknown | A list of Windows agent versions. | 
| PaloAltoNetworksXDR.DistributionVersions.linux | Unknown | A list of Linux agent versions. | 
| PaloAltoNetworksXDR.DistributionVersions.macos | Unknown | A list of Mac agent versions. | 


##### Command Example
```!xdr-get-distribution-versions```

##### Context Example
```
{
    "PaloAltoNetworksXDR.DistributionVersions": {
        "windows": [
            "5.0.8.29673", 
            "5.0.9.30963", 
            "6.1.4.28751", 
            "7.0.0.28644"
        ], 
        "macos": [
            "6.1.4.1681", 
            "7.0.0.1914"
        ], 
        "linux": [
            "6.1.4.1680", 
            "7.0.0.1916"
        ]
    }
}
```

##### Human Readable Output
### windows
|versions|
|---|
| 5.0.8.29673 |
| 5.0.9.30963 |
| 6.1.4.28751 |
| 7.0.0.28644 |


### linux
|versions|
|---|
| 6.1.4.1680 |
| 7.0.0.1916 |


### macos
|versions|
|---|
| 6.1.4.1681 |
| 7.0.0.1914 |


### 10. xdr-create-distribution
---
Creates an installation package. This is an asynchronous call that returns the distribution ID. This does not mean that the creation succeeded. To confirm that the package has been created, check the status of the distribution by running the Get Distribution Status API.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-create-distribution`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A string representing the name of the installation package. | Required | 
| platform | String, valid values are:<br/>• windows <br/>• linux<br/>• macos <br/>• android | Required | 
| package_type | A string representing the type of package to create.<br/>standalone - An installation for a new agent<br/>upgrade - An upgrade of an agent from ESM | Required | 
| agent_version | agent_version returned from xdr-get-distribution-versions. Not required for Android platfom | Required | 
| description | Information about the package. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Distribution.id | String | The installation package ID. | 
| PaloAltoNetworksXDR.Distribution.name | String | The name of the installation package. | 
| PaloAltoNetworksXDR.Distribution.platform | String | The installation OS. | 
| PaloAltoNetworksXDR.Distribution.agent_version | String | Agent version. | 
| PaloAltoNetworksXDR.Distribution.description | String | Information about the package. | 


##### Command Example
```!xdr-create-distribution agent_version=6.1.4.1680 name="dist_1" package_type=standalone platform=linux description="some description"```

##### Context Example
```
{
    "PaloAltoNetworksXDR.Distribution": {
        "description": "some description", 
        "package_type": "standalone", 
        "platform": "linux", 
        "agent_version": "6.1.4.1680", 
        "id": "43aede7f846846fa92b50149663fbb25", 
        "name": "dist_1"
    }
}
```

##### Human Readable Output
Distribution 43aede7f846846fa92b50149663fbb25 created successfully

### 11. xdr-get-distribution-url
---
Gets the distribution URL for downloading the installation package.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-get-distribution-url`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| distribution_id | The ID of the installation package.<br/>Copy the distribution_id from the "id" field on Endpoints > Agent Installation page. | Required | 
| package_type | The installation package type. Valid<br/>values are:<br/>• upgrade<br/>• sh - For Linux<br/>• rpm - For Linux<br/>• deb - For Linux<br/>• pkg - For Mac<br/>• x86 - For Windows<br/>• x64 - For Windows | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Distribution.id | String | Distribution ID. | 
| PaloAltoNetworksXDR.Distribution.url | String | URL for downloading the installation package. | 


##### Command Example
```!xdr-get-distribution-url distribution_id=2c74c11b63074653aa01d575a82bf52a package_type=sh```

##### Human Readable Output


### 12. xdr-get-create-distribution-status
---
Gets the status of the installation package.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-get-create-distribution-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| distribution_ids | A comma-separated list of distribution IDs to get the status of. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Distribution.id | String | Distribution ID. | 
| PaloAltoNetworksXDR.Distribution.status | String | The status of installation package. | 


##### Command Example
```!xdr-get-create-distribution-status distribution_ids=2c74c11b63074653aa01d575a82bf52a```

##### Context Example
```
{
    "PaloAltoNetworksXDR.Distribution": [
        {
            "status": "Completed", 
            "id": "2c74c11b63074653aa01d575a82bf52a"
        }
    ]
}
```

##### Human Readable Output
### Distribution Status
|id|status|
|---|---|
| 2c74c11b63074653aa01d575a82bf52a | Completed |


### 13. xdr-get-audit-management-logs
---
Gets management logs. You can filter by multiple fields, which will be concatenated using AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of management logs from the start of the result set (start by counting from 0).
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-get-audit-management-logs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | User’s email address. | Optional | 
| type | The audit log type. | Optional | 
| sub_type | The audit log subtype. | Optional | 
| result | Result type | Optional | 
| timestamp_gte | Return logs for which the timestamp is after 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date) | Optional | 
| timestamp_lte | Return logs for which the timestamp is before the 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date) | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). | Optional | 
| limit | Maximum number of audit logs to return per page. The default and maximum is 30. | Optional | 
| sort_by | Specifies the field by which to sort the results. By default the sort is defined as creation-time and DESC. Can be "type", "sub_type", "result", or "timestamp". | Optional | 
| sort_order | The sort order. Can be "asc" (ascending) or "desc" (descending). Default set to "desc".  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ID | Number | Audit log ID. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_OWNER_NAME | String | Audit owner name. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_OWNER_EMAIL | String | Audit owner email address. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ASSET_JSON | String | Asset JSON. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ASSET_NAMES | String | Audit asset names. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_HOSTNAME | String | Host name. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_RESULT | String | Audit result. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_REASON | String | Audit reason. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_DESCRIPTION | String | Description of the audit. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ENTITY | String | Audit entity (e.g., AUTH, DISTRIBUTIONS). | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ENTITY_SUBTYPE | String | Entity subtype (e.g., Login, Create). | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_CASE_ID | Number | Audit case ID. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_INSERT_TIME | Date | Log's insert time. | 


##### Command Example
```!xdr-get-audit-management-logs result=SUCCESS type=DISTRIBUTIONS limit=2 timestamp_gte="3 month"```

##### Context Example
```
{
    "PaloAltoNetworksXDR.AuditManagementLogs": [
        {
            "AUDIT_OWNER_EMAIL": "", 
            "AUDIT_SESSION_ID": null, 
            "AUDIT_ID": 217, 
            "AUDIT_REASON": null, 
            "AUDIT_CASE_ID": null, 
            "AUDIT_DESCRIPTION": "Created a Linux Standalone installer installation package 'dist_1' with agent version 6.1.4.1680", 
            "AUDIT_INSERT_TIME": 1579287926547, 
            "AUDIT_ENTITY": "DISTRIBUTIONS", 
            "AUDIT_OWNER_NAME": "Public API - 1", 
            "AUDIT_ASSET_JSON": "{}", 
            "AUDIT_RESULT": "SUCCESS", 
            "AUDIT_ASSET_NAMES": "", 
            "AUDIT_HOSTNAME": null, 
            "AUDIT_ENTITY_SUBTYPE": "Create"
        }, 
        {
            "AUDIT_OWNER_EMAIL": "", 
            "AUDIT_SESSION_ID": null, 
            "AUDIT_ID": 214, 
            "AUDIT_REASON": null, 
            "AUDIT_CASE_ID": null, 
            "AUDIT_DESCRIPTION": "Created a Linux Standalone installer installation package 'ddd' with agent version 6.1.4.1680", 
            "AUDIT_INSERT_TIME": 1579121478199, 
            "AUDIT_ENTITY": "DISTRIBUTIONS", 
            "AUDIT_OWNER_NAME": "Public API - 1", 
            "AUDIT_ASSET_JSON": "{}", 
            "AUDIT_RESULT": "SUCCESS", 
            "AUDIT_ASSET_NAMES": "", 
            "AUDIT_HOSTNAME": null, 
            "AUDIT_ENTITY_SUBTYPE": "Create"
        }
    ]
}
```

##### Human Readable Output
### Audit Management Logs
|AUDIT_ID|AUDIT_RESULT|AUDIT_DESCRIPTION|AUDIT_OWNER_NAME|AUDIT_OWNER_EMAIL|AUDIT_ASSET_JSON|AUDIT_ASSET_NAMES|AUDIT_HOSTNAME|AUDIT_REASON|AUDIT_ENTITY|AUDIT_ENTITY_SUBTYPE|AUDIT_SESSION_ID|AUDIT_CASE_ID|AUDIT_INSERT_TIME|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 217 | SUCCESS | Created a Linux Standalone installer installation package 'dist_1' with agent version 6.1.4.1680 | Public API - 1 |  | {} |  |  |  | DISTRIBUTIONS | Create |  |  | 1579287926547 |
| 214 | SUCCESS | Created a Linux Standalone installer installation package 'ddd' with agent version 6.1.4.1680 | Public API - 1 |  | {} |  |  |  | DISTRIBUTIONS | Create |  |  | 1579121478199 |


### 14. xdr-get-audit-agent-reports
---
Gets agent event reports. You can filter by multiple fields, which will be concatenated using AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of reports from the start of the result set (start by counting from 0).
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`xdr-get-audit-agent-reports`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. | Optional | 
| endpoint_names | A comma-separated list of endpoint names. | Optional | 
| type | The report type. Can be "Installation", "Policy", "Action", "Agent Service", "Agent Modules", or "Agent Status". | Optional | 
| sub_type | The report subtype. | Optional | 
| result | The result type. Can be "Success" or "Fail". If not passed, returns all event reports. | Optional | 
| timestamp_gte | Return logs that their timestamp is greater than 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date) | Optional | 
| timestamp_lte | Return logs for which the timestamp is before the 'timestamp_lte'.<br/><br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date) | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). | Optional | 
| limit | The maximum number of reports to return. Default and maximum is 30. | Optional | 
| sort_by | The field by which to sort results. Can be "type", "category", "trapsversion", "timestamp", or "domain"). | Optional | 
| sort_order | The sort order. Can be "asc" (ascending) or "desc" (descending). Default is "asc".  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.AuditAgentReports.ENDPOINTID | String | Endpoint ID. | 
| PaloAltoNetworksXDR.AuditAgentReports.ENDPOINTNAME | String | Endpoint name. | 
| PaloAltoNetworksXDR.AuditAgentReports.DOMAIN | String | Agent domain. | 
| PaloAltoNetworksXDR.AuditAgentReports.TRAPSVERSION | String | Traps version. | 
| PaloAltoNetworksXDR.AuditAgentReports.RECEIVEDTIME | Date | Received time in Epoch time. | 
| PaloAltoNetworksXDR.AuditAgentReports.TIMESTAMP | Date | Timestamp in Epoch time. | 
| PaloAltoNetworksXDR.AuditAgentReports.CATEGORY | String | Report category (e.g., Audit). | 
| PaloAltoNetworksXDR.AuditAgentReports.TYPE | String | Report type (e.g., Action, Policy). | 
| PaloAltoNetworksXDR.AuditAgentReports.SUBTYPE | String | Report subtype (e.g., Fully Protected,Policy Update,Cancel Isolation). | 
| PaloAltoNetworksXDR.AuditAgentReports.RESULT | String | Report result. | 
| PaloAltoNetworksXDR.AuditAgentReports.REASON | String | Report reason. | 
| PaloAltoNetworksXDR.AuditAgentReports.DESCRIPTION | String | Agent report description. | 


##### Command Example
```!xdr-get-audit-agent-reports result=Success timestamp_gte="100 days" endpoint_ids=ea303670c76e4ad09600c8b346f7c804 type=Policy limit=2```

##### Context Example
```
{
    "PaloAltoNetworksXDR.AuditAgentReports": [
        {
            "CATEGORY": "Audit", 
            "DOMAIN": "", 
            "DESCRIPTION": "XDR Agent policy updated on aaaaa.compute.internal", 
            "TIMESTAMP": 1579284369143.7048, 
            "RECEIVEDTIME": 1579286565904.3281, 
            "REASON": null, 
            "SUBTYPE": "Policy Update", 
            "ENDPOINTNAME": "aaaaa.compute.internal", 
            "RESULT": "Success", 
            "ENDPOINTID": "ea303670c76e4ad09600c8b346f7c804", 
            "TRAPSVERSION": "7.0.0.1915", 
            "TYPE": "Policy"
        }, 
        {
            "CATEGORY": "Audit", 
            "DOMAIN": "", 
            "DESCRIPTION": "XDR Agent policy updated on aaaaa.compute.internal", 
            "TIMESTAMP": 1579280769141.43, 
            "RECEIVEDTIME": 1579282965742.36, 
            "REASON": null, 
            "SUBTYPE": "Policy Update", 
            "ENDPOINTNAME": "aaaaa.compute.internal", 
            "RESULT": "Success", 
            "ENDPOINTID": "ea303670c76e4ad09600c8b346f7c804", 
            "TRAPSVERSION": "7.0.0.1915", 
            "TYPE": "Policy"
        }
    ]
}
```

##### Human Readable Output
### Audit Agent Reports
|CATEGORY|DESCRIPTION|DOMAIN|ENDPOINTID|ENDPOINTNAME|REASON|RECEIVEDTIME|RESULT|SUBTYPE|TIMESTAMP|TRAPSVERSION|TYPE|
|---|---|---|---|---|---|---|---|---|---|---|---|
| Audit | XDR Agent policy updated on aaaaa.compute.internal |  | ea303670c76e4ad09600c8b346f7c804 | aaaaa.compute.internal |  | 1579286565904.3281 | Success | Policy Update | 1579284369143.7048 | 7.0.0.1915 | Policy |
| Audit | XDR Agent policy updated on aaaaa.compute.internal |  | ea303670c76e4ad09600c8b346f7c804 | aaaaa.compute.internal |  | 1579282965742.36 | Success | Policy Update | 1579280769141.43 | 7.0.0.1915 | Policy |


## Troubleshooting
 - In case you encounter ReadTimeoutError, we recommend increasing the HTTP request timeout by setting it in the **HTTP Timeout** integration parameter.
