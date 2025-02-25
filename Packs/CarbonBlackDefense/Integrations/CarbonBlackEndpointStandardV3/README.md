Endpoint Standard is an industry-leading next-generation antivirus (NGAV) and behavioral endpoint detection and response (EDR) solution. Endpoint Standard is delivered through the Carbon Black Cloud, an endpoint protection platform that consolidates security in the cloud using a single agent, console and data set.
This integration was integrated and tested with version 1.1.2 of Carbon Black Endpoint Standard v3.
### Migration to Carbon Black Endpoint Standard v3

#### Deprecated Commands in Carbon Black Endpoint Standard v2

The following commands from the Carbon Black Endpoint Standard v2 integration have been deprecated and replaced with v3 commands:

| Deprecated Command | New v3 Command | Comments |
| --- | --- | --- |
| [`cbd-find-events`](https://xsoar.pan.dev/docs/reference#cbd-find-observation) | [`cbd-find-observation`](https://xsoar.pan.dev/docs/reference#cbd-find-observation) | Includes `cbd-find-events-results`. |
| [`cbd-find-events-results`](https://xsoar.pan.dev/docs/reference#cbd-find-observation-results) | [`cbd-find-observation-results`](https://xsoar.pan.dev/docs/reference#cbd-find-observation-results) | Manually check results without polling. |
| [`cbd-find-events-details`](https://xsoar.pan.dev/docs/reference#cbd-find-observation-details) | [`cbd-find-observation-details`](https://xsoar.pan.dev/docs/reference#cbd-find-observation-details) | Includes `cbd-find-events-details-results`. |
| [`cbd-find-events-details-results`](https://xsoar.pan.dev/docs/reference#cbd-find-observation-details-results) | [`cbd-find-observation-details-results`](https://xsoar.pan.dev/docs/reference#cbd-find-observation-details-results) | Manually check details results without polling. |
| [`cbd-find-processes-results`](https://xsoar.pan.dev/docs/reference#cbd-find-processes) | [`cbd-find-processes`](https://xsoar.pan.dev/docs/reference#cbd-find-processes) <br/> [`cbd-find-processes-results`](https://xsoar.pan.dev/docs/reference#cbd-find-processes-results) | Retrieve results via polling or manually with `cbd-find-processes-results`. |
| [`cbd-get-policies`](https://xsoar.pan.dev/docs/reference#cbd-get-policies-summary) | [`cbd-get-policies-summary`](https://xsoar.pan.dev/docs/reference#cbd-get-policies-summary) | |

#### Important Changes in Carbon Black Endpoint Standard v3

- **Organization Key:** Updated to be a required field.
- **cbd-find-processes:** Enhanced to include process results when polling=true.
- **cbd-find-observation-results:** Added to manually retrieve observation results without polling.
- **cbd-find-observation-details-results:** Added to manually retrieve observation details results without polling.
- **cbd-alerts-search:** Updated context output; deprecated **category** arg and updated **tag** arg to **tags**.
- **policy commands:** Context output updated ; *policy* arg format changed.
- **rules commands:** Updated context output and operation arg options.

#### Deprecated Playbooks

- **Carbon Black Endpoint Standard Find Event Details:** Use **cbd-find-observation-details** command instead.
- **Carbon Black Endpoint Standard Find Events:** Use **cbd-find-observation** command instead.
- **Carbon Black Endpoint Standard Find Processes:** Use **cbd-find-processes** command instead.


### Mapper
**Carbon Black Endpoint Standard Mapper**.

### Layout
**Carbon Black Endpoint Standard Incoming Layout**.

### Classifier
**Carbon Black Endpoint Standard**

## Configure Carbon Black Endpoint Standard v3 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| URL |  | True |
| Organization Key | The organization unique key. This is required for all use cases \(and for fetching incidents\). | True |
| Custom Api Key | This Custom API key is required for all use cases and for fetch except the policy use cases. | False |
| Password | This Custom API key is required for all use cases and for fetch except the policy use cases. | False |
| Api Key (Api/Live Response key) | This Live Response API key is required only for the policy use cases. | False |
| Password | This Live Response API key is required only for the policy use cases. | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| The type of the alert | Type of alert to be fetched. | False |
| Device ID | The alerts related to a specific device, according to the device ID. | False |
| Policy ID | The alerts related to a specific policy, according to the policy ID. | False |
| Device username | The alerts related to a specific device, according to the device username. | False |
| Minimum severity | The minimum severity of the alerts to be fetched. | False |
| Query | Query in Lucene syntax and/or value searches. If defined, the other fetch incidents parameters should be left blank. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). |  | False |
| Maximum number of incidents per fetch |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cbd-get-alert-details

***
Gets alert details according to alert ID, including alert metadata and a list of all events associated with the alert. Only API keys of type “API” can call the alert API.

#### Base Command

`cbd-get-alert-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | The ID of the alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Alert.org_key | String | The organization key associated with the alert. | 
| CarbonBlackDefense.Alert.alert_url | String | The URL to view the alert in the Carbon Black Defense console. | 
| CarbonBlackDefense.Alert.id | String | The unique alert ID. | 
| CarbonBlackDefense.Alert.type | String | The type of the alert. | 
| CarbonBlackDefense.Alert.backend_timestamp | Date | The timestamp when the alert was generated in the backend. | 
| CarbonBlackDefense.Alert.user_update_timestamp | Date | The timestamp when the alert was last updated by a user. | 
| CarbonBlackDefense.Alert.backend_update_timestamp | Date | The timestamp when the alert was last updated in the backend. | 
| CarbonBlackDefense.Alert.detection_timestamp | Date | The timestamp when the alert was detected. | 
| CarbonBlackDefense.Alert.first_event_timestamp | Date | The timestamp of the first event related to the alert. | 
| CarbonBlackDefense.Alert.last_event_timestamp | Date | The timestamp of the last event related to the alert. | 
| CarbonBlackDefense.Alert.severity | Number | The severity level of the alert. | 
| CarbonBlackDefense.Alert.reason | String | The reason for the alert. | 
| CarbonBlackDefense.Alert.reason_code | String | The reason code for the alert. | 
| CarbonBlackDefense.Alert.threat_id | String | The threat ID related to the alert. | 
| CarbonBlackDefense.Alert.primary_event_id | String | The primary event ID related to the alert. | 
| CarbonBlackDefense.Alert.policy_applied | String | The policy applied to the device when the alert was generated. | 
| CarbonBlackDefense.Alert.run_state | String | The run state of the alert. | 
| CarbonBlackDefense.Alert.sensor_action | String | The action taken by the sensor for the alert. | 
| CarbonBlackDefense.Alert.workflow.change_timestamp | Date | The timestamp when the workflow status was last changed. | 
| CarbonBlackDefense.Alert.workflow.changed_by_type | String | The type of user who last changed the workflow status. | 
| CarbonBlackDefense.Alert.workflow.changed_by | String | The user who last changed the workflow status. | 
| CarbonBlackDefense.Alert.workflow.closure_reason | String | The reason for closing the alert. | 
| CarbonBlackDefense.Alert.workflow.status | String | The current workflow status of the alert. | 
| CarbonBlackDefense.Alert.determination.change_timestamp | Date | The timestamp when the determination was last changed. | 
| CarbonBlackDefense.Alert.determination.value | String | The value of the determination. | 
| CarbonBlackDefense.Alert.determination.changed_by_type | String | The type of user who last changed the determination. | 
| CarbonBlackDefense.Alert.determination.changed_by | String | The user who last changed the determination. | 
| CarbonBlackDefense.Alert.tags | Unknown | The tags associated with the alert. | 
| CarbonBlackDefense.Alert.alert_notes_present | Boolean | Indicates whether alert notes are present. | 
| CarbonBlackDefense.Alert.threat_notes_present | Boolean | Indicates whether threat notes are present. | 
| CarbonBlackDefense.Alert.alert_origin | String | The origin of the alert. | 
| CarbonBlackDefense.Alert.is_updated | Boolean | Indicates whether the alert has been updated. | 
| CarbonBlackDefense.Alert.device_id | Number | The identifier of the device related to the alert. | 
| CarbonBlackDefense.Alert.device_name | String | The name of the device related to the alert. | 
| CarbonBlackDefense.Alert.device_uem_id | String | The Unified Endpoint Management \(UEM\) ID of the device. | 
| CarbonBlackDefense.Alert.device_target_value | String | The target value of the device. | 
| CarbonBlackDefense.Alert.device_policy | String | The policy applied to the device. | 
| CarbonBlackDefense.Alert.device_policy_id | Number | The policy ID applied to the device. | 
| CarbonBlackDefense.Alert.device_os | String | The operating system of the device. | 
| CarbonBlackDefense.Alert.device_os_version | String | The operating system version of the device. | 
| CarbonBlackDefense.Alert.device_username | String | The username associated with the device. | 
| CarbonBlackDefense.Alert.device_location | String | The location of the device. | 
| CarbonBlackDefense.Alert.device_external_ip | String | The external IP address of the device. | 
| CarbonBlackDefense.Alert.device_internal_ip | String | The internal IP address of the device. | 
| CarbonBlackDefense.Alert.asset_group | Unknown | The asset group to which the device belongs. | 
| CarbonBlackDefense.Alert.mdr_alert | Boolean | Indicates whether the alert is a Managed Detection and Response \(MDR\) alert. | 
| CarbonBlackDefense.Alert.mdr_alert_notes_present | Boolean | Indicates whether MDR alert notes are present. | 
| CarbonBlackDefense.Alert.mdr_threat_notes_present | Boolean | Indicates whether MDR threat notes are present. | 
| CarbonBlackDefense.Alert.report_id | String | The report ID associated with the alert. | 
| CarbonBlackDefense.Alert.report_name | String | The name of the report associated with the alert. | 
| CarbonBlackDefense.Alert.report_description | String | The description of the report associated with the alert. | 
| CarbonBlackDefense.Alert.report_tags | String | The tags associated with the report. | 
| CarbonBlackDefense.Alert.report_link | String | The link to the report associated with the alert. | 
| CarbonBlackDefense.Alert.ioc_id | String | The indicator of compromise \(IOC\) ID related to the alert. | 
| CarbonBlackDefense.Alert.ioc_hit | String | The IOC hit associated with the alert. | 
| CarbonBlackDefense.Alert.watchlists.id | String | The watchlist ID associated with the alert. | 
| CarbonBlackDefense.Alert.watchlists.name | String | The name of the watchlist associated with the alert. | 
| CarbonBlackDefense.Alert.process_guid | String | The GUID of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_pid | Number | The PID of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_name | String | The name of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_sha256 | String | The SHA-256 hash of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_md5 | String | The MD5 hash of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_effective_reputation | String | The effective reputation of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_reputation | String | The reputation of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_cmdline | String | The command line of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_username | String | The username associated with the process related to the alert. | 
| CarbonBlackDefense.Alert.process_issuer | String | The issuer of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_publisher | String | The publisher of the process related to the alert. | 
| CarbonBlackDefense.Alert.parent_guid | String | The GUID of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_pid | Number | The PID of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_name | String | The name of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_sha256 | String | The SHA-256 hash of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_md5 | String | The MD5 hash of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_effective_reputation | String | The effective reputation of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_reputation | String | The reputation of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_cmdline | String | The command line of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_username | String | The username associated with the parent process related to the alert. | 
| CarbonBlackDefense.Alert.childproc_guid | String | The GUID of the child process related to the alert. | 
| CarbonBlackDefense.Alert.childproc_username | String | The username associated with the child process related to the alert. | 
| CarbonBlackDefense.Alert.childproc_cmdline | String | The command line of the child process related to the alert. | 
| CarbonBlackDefense.Alert.ml_classification_final_verdict | String | The final verdict from the machine learning classification. | 
| CarbonBlackDefense.Alert.ml_classification_global_prevalence | String | The global prevalence from the machine learning classification. | 
| CarbonBlackDefense.Alert.ml_classification_org_prevalence | String | The organizational prevalence from the machine learning classification. | 
| CarbonBlackDefense.Alert.ml_classification_anomalies | Unknown | The anomalies identified by the machine learning classification. | 

#### Command example
```!cbd-get-alert-details alertId=abc-123```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Alert": {
            "alert_notes_present": true,
            "alert_origin": "ALERT_ORIGIN_UNKNOWN",
            "alert_url": "dummy_alert_url",
            "asset_group": [],
            "backend_timestamp": "2024-03-26T14:05:42.311Z",
            "backend_update_timestamp": "2024-03-26T14:05:42.311Z",
            "childproc_cmdline": "",
            "childproc_guid": "",
            "childproc_username": "",
            "detection_timestamp": "2024-03-26T14:04:49.358Z",
            "determination": {
                "change_timestamp": "2024-04-07T15:08:37.805Z",
                "changed_by": "BG6UTMG1LK",
                "changed_by_type": "API",
                "value": "NONE"
            },
            "device_external_ip": "1.1.1.1",
            "device_id": "dummy_device_id",
            "device_internal_ip": "1.1.1.1",
            "device_location": "UNKNOWN",
            "device_name": "EIP\\WW-20002",
            "device_os": "WINDOWS",
            "device_os_version": "Windows 10 x64",
            "device_policy": "default",
            "device_policy_id": "dummy_device_policy_id",
            "device_target_value": "MEDIUM",
            "device_uem_id": "",
            "device_username": "EIP\\Administrator",
            "first_event_timestamp": "2024-03-26T14:00:05.730Z",
            "id": "dummy_id",
            "ioc_hit": "(fileless_scriptload_cmdline:Register-ScheduledTask OR fileless_scriptload_cmdline:New-ScheduledTask OR scriptload_content:Register-ScheduledTask OR scriptload_content:New-ScheduledTask) AND NOT (process_cmdline:windows\\\\ccm\\\\systemtemp OR crossproc_name:windows\\\\ccm\\\\ccmexec.exe OR (process_publisher:\"VMware, Inc.\" AND process_publisher_state:FILE_SIGNATURE_STATE_TRUSTED))",
            "ioc_id": "dummy_ioc_id",
            "is_updated": false,
            "last_event_timestamp": "2024-03-26T14:00:05.730Z",
            "mdr_alert": false,
            "mdr_alert_notes_present": false,
            "mdr_threat_notes_present": false,
            "ml_classification_anomalies": [],
            "ml_classification_final_verdict": "NOT_ANOMALOUS",
            "ml_classification_global_prevalence": "LOW",
            "ml_classification_org_prevalence": "LOW",
            "org_key": "dummy_org_key",
            "parent_cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
            "parent_effective_reputation": "TRUSTED_WHITE_LIST",
            "parent_guid": "dummy_parent_guid",
            "parent_md5": "dummy_parent_md5",
            "parent_name": "c:\\windows\\system32\\svchost.exe",
            "parent_pid": "dummy_parent_pid",
            "parent_reputation": "TRUSTED_WHITE_LIST",
            "parent_sha256": "dummy_parent_sha256",
            "parent_username": "NT AUTHORITY\\SYSTEM",
            "policy_applied": "NOT_APPLIED",
            "primary_event_id": "dummy_primary_event_id",
            "process_cmdline": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -EP Bypass \\\\eip.demo\\sysvol\\EIP.DEMO\\scripts\\Luminol.ps1",
            "process_effective_reputation": "TRUSTED_WHITE_LIST",
            "process_guid": "dummy_process_guid",
            "process_issuer": [
                "Microsoft Windows Production PCA 2011"
            ],
            "process_md5": "dummy_parent_md5",
            "process_name": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
            "process_pid": "dummy_process_pid",
            "process_publisher": [
                "Microsoft Windows"
            ],
            "process_reputation": "TRUSTED_WHITE_LIST",
            "process_sha256": "dummy_process_sha256",
            "process_username": "NT AUTHORITY\\SYSTEM",
            "reason": "Process powershell.exe was detected by the report \"Execution - AMSI - New Fileless Scheduled Task Behavior Detected\" in watchlist \"AMSI Threat Intelligence\"",
            "reason_code": "dummy_reason_code",
            "report_description": "Newer Powershell versions introduced built-in cmdlets to manage scheduled tasks natively without calling out to typical scheduled task processes like at.exe or schtasks.exe. This detection looks for behaviors related to the fileless execution of scheduled tasks. If you are responding to this alert, be sure to correlate the fileless scriptload events with events typically found in your environment Generally, attackers will create scheduled tasks with binaries that are located in user writable directories like AppData, Temp, or public folders.",
            "report_id": "dummy_report_id",
            "report_link": "https://attack.mitre.org/techniques/T1053/",
            "report_name": "Execution - AMSI - New Fileless Scheduled Task Behavior Detected",
            "report_tags": [
                "execution",
                "privesc",
                "persistence",
                "t1053",
                "windows",
                "amsi",
                "attack",
                "attackframework"
            ],
            "run_state": "RAN",
            "sensor_action": "ALLOW",
            "severity": 5,
            "tags": null,
            "threat_id": "dummy_threat_id",
            "threat_notes_present": false,
            "type": "WATCHLIST",
            "user_update_timestamp": "2024-04-07T15:31:33.704Z",
            "watchlists": [
                {
                    "id": "dummy_id",
                    "name": "AMSI Threat Intelligence"
                }
            ],
            "workflow": {
                "change_timestamp": "2024-04-07T15:31:33.704Z",
                "changed_by": "3LGD624UYW",
                "changed_by_type": "API",
                "closure_reason": "OTHER",
                "status": "OPEN"
            }
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Get Alert Details
>|Id|Device Id|Device Name|Device Username|Ioc Hit|Reason|Type|Threat Id|Device Policy|Severity|
>|---|---|---|---|---|---|---|---|---|---|
>| dummy_id  | 6612391 | EIP\WW-20002 | EIP\Administrator | (fileless_scriptload_cmdline:Register-ScheduledTask OR fileless_scriptload_cmdline:New-ScheduledTask OR scriptload_content:Register-ScheduledTask OR scriptload_content:New-ScheduledTask) AND NOT (process_cmdline:windows\\ccm\\systemtemp OR crossproc_name:windows\\ccm\\ccmexec.exe OR (process_publisher:"VMware, Inc." AND process_publisher_state:FILE_SIGNATURE_STATE_TRUSTED)) | Process powershell.exe was detected by the report "Execution - AMSI - New Fileless Scheduled Task Behavior Detected" in watchlist "AMSI Threat Intelligence" | WATCHLIST | C21CA826573A8D974C1E93C8471AAB7F | default | 5 |


### cbd-alerts-search

***
Gets alert details, including alert metadata and the event associated with the alert.

#### Base Command

`cbd-alerts-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The alert type. Possible values are: cbanalytics, containerruntime, devicecontrol, hostnasedfirewall, intrusiondetectionsystem, watchlist, all. Default is all. | Optional | 
| device_id | The device ID. | Optional | 
| first_event_time | The time of the first event associated with the alert. The syntax is  {"start": "&lt;dateTime&gt;", "range": "&lt;string&gt;", "end": "&lt;dateTime&gt;" }. For example: { "start": "2010-09-25T00:10:50.277Z", "end": "2015-01-20T10:40:00.00Z"}. | Optional | 
| policy_id | The policy ID. | Optional | 
| process_sha256 | The SHA-256 hash of the primary involved process. | Optional | 
| reputation | The reputation of the primary involved process. Possible values are: ADAPTIVE_WHITE_LIST, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, PUP, TRUSTED_WHITE_LIST, RESOLVING, COMPROMISED_OBSOLETE, DLP_OBSOLETE, IGNORE, ADWARE, HEURISTIC, SUSPECT_MALWARE, KNOWN_MALWARE, ADMIN_RESTRICT_OBSOLETE, NOT_LISTED, GRAY_OBSOLETE, NOT_COMPANY_WHITE_OBSOLETE, LOCAL_WHITE, NOT_SUPPORTED. | Optional | 
| tags | The tags associated with the alert. | Optional | 
| device_username | The username of the user logged on during the alert. If the user is not available, the device owner is used. | Optional | 
| query | The query in Lucene syntax and/or value searches. | Optional | 
| rows | The number of results to be returned. | Optional | 
| start | The number of the alert from where to start retrieving results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Alert.org_key | String | The organization key associated with the alert. | 
| CarbonBlackDefense.Alert.alert_url | String | The URL to view the alert in the Carbon Black Defense console. | 
| CarbonBlackDefense.Alert.id | String | The unique alert ID. | 
| CarbonBlackDefense.Alert.type | String | The type of the alert. | 
| CarbonBlackDefense.Alert.backend_timestamp | Date | The timestamp when the alert was generated in the backend. | 
| CarbonBlackDefense.Alert.user_update_timestamp | Unknown | The timestamp when the alert was last updated by a user. | 
| CarbonBlackDefense.Alert.backend_update_timestamp | Date | The timestamp when the alert was last updated in the backend. | 
| CarbonBlackDefense.Alert.detection_timestamp | Date | The timestamp when the alert was detected. | 
| CarbonBlackDefense.Alert.first_event_timestamp | Date | The timestamp of the first event related to the alert. | 
| CarbonBlackDefense.Alert.last_event_timestamp | Date | The timestamp of the last event related to the alert. | 
| CarbonBlackDefense.Alert.severity | Number | The severity level of the alert. | 
| CarbonBlackDefense.Alert.reason | String | The reason for the alert. | 
| CarbonBlackDefense.Alert.reason_code | String | The reason code for the alert. | 
| CarbonBlackDefense.Alert.threat_id | String | The unique alert ID | 
| CarbonBlackDefense.Alert.primary_event_id | String | The primary event ID related to the alert. | 
| CarbonBlackDefense.Alert.policy_applied | String | The policy applied to the device when the alert was generated. | 
| CarbonBlackDefense.Alert.run_state | String | The run state of the alert. | 
| CarbonBlackDefense.Alert.sensor_action | String | The action taken by the sensor for the alert. | 
| CarbonBlackDefense.Alert.workflow.change_timestamp | Date | The timestamp when the workflow status was last changed. | 
| CarbonBlackDefense.Alert.workflow.changed_by_type | String | The type of user who last changed the workflow status. | 
| CarbonBlackDefense.Alert.workflow.changed_by | String | The user who last changed the workflow status. | 
| CarbonBlackDefense.Alert.workflow.closure_reason | String | The reason for closing the alert. | 
| CarbonBlackDefense.Alert.workflow.status | String | The current workflow status of the alert. | 
| CarbonBlackDefense.Alert.determination.change_timestamp | Date | The timestamp when the determination was last changed. | 
| CarbonBlackDefense.Alert.determination.value | String | The value of the determination. | 
| CarbonBlackDefense.Alert.determination.changed_by_type | String | The type of user who last changed the determination. | 
| CarbonBlackDefense.Alert.determination.changed_by | String | The user who last changed the determination. | 
| CarbonBlackDefense.Alert.tags | Unknown | The tags associated with the alert. | 
| CarbonBlackDefense.Alert.alert_notes_present | Boolean | Indicates whether alert notes are present. | 
| CarbonBlackDefense.Alert.threat_notes_present | Boolean | Indicates whether threat notes are present. | 
| CarbonBlackDefense.Alert.alert_origin | String | The origin of the alert. | 
| CarbonBlackDefense.Alert.is_updated | Boolean | Indicates whether the alert has been updated. | 
| CarbonBlackDefense.Alert.device_id | Number | The device ID related to the alert. | 
| CarbonBlackDefense.Alert.device_name | String | The name of the device related to the alert. | 
| CarbonBlackDefense.Alert.device_uem_id | String | The Unified Endpoint Management \(UEM\) ID of the device. | 
| CarbonBlackDefense.Alert.device_target_value | String | The target value of the device. | 
| CarbonBlackDefense.Alert.device_policy | String | The policy applied to the device. | 
| CarbonBlackDefense.Alert.device_policy_id | Number | The policy ID applied to the device. | 
| CarbonBlackDefense.Alert.device_os | String | The operating system of the device. | 
| CarbonBlackDefense.Alert.device_os_version | String | The operating system version of the device. | 
| CarbonBlackDefense.Alert.device_username | String | The username associated with the device. | 
| CarbonBlackDefense.Alert.device_location | String | The location of the device. | 
| CarbonBlackDefense.Alert.device_external_ip | String | The external IP address of the device. | 
| CarbonBlackDefense.Alert.device_internal_ip | String | The internal IP address of the device. | 
| CarbonBlackDefense.Alert.asset_group | Unknown | The asset group to which the device belongs. | 
| CarbonBlackDefense.Alert.mdr_alert | Boolean | Indicates whether the alert is an MDR \(Managed Detection and Response\) alert. | 
| CarbonBlackDefense.Alert.mdr_alert_notes_present | Boolean | Indicates whether MDR alert notes are present. | 
| CarbonBlackDefense.Alert.mdr_threat_notes_present | Boolean | Indicates whether MDR threat notes are present. | 
| CarbonBlackDefense.Alert.report_id | String | The report ID associated with the alert. | 
| CarbonBlackDefense.Alert.report_name | String | The name of the report associated with the alert. | 
| CarbonBlackDefense.Alert.report_tags | Unknown | The tags associated with the report. | 
| CarbonBlackDefense.Alert.ioc_id | String | The indicator of compromise \(IOC\) ID related to the alert. | 
| CarbonBlackDefense.Alert.ioc_hit | String | The IOC hit associated with the alert. | 
| CarbonBlackDefense.Alert.watchlists.id | String | The watchlist ID associated with the alert. | 
| CarbonBlackDefense.Alert.watchlists.name | String | The name of the watchlist associated with the alert. | 
| CarbonBlackDefense.Alert.process_guid | String | The GUID of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_pid | Number | The PID of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_name | String | The name of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_sha256 | String | The SHA-256 hash of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_md5 | String | The MD5 hash of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_effective_reputation | String | The effective reputation of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_reputation | String | The reputation of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_cmdline | String | The command line of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_username | String | The username associated with the process related to the alert. | 
| CarbonBlackDefense.Alert.process_issuer | String | The issuer of the process related to the alert. | 
| CarbonBlackDefense.Alert.process_publisher | String | The publisher of the process related to the alert. | 
| CarbonBlackDefense.Alert.parent_guid | String | The GUID of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_pid | Number | The PID of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_name | String | The name of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_sha256 | String | The SHA-256 hash of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_md5 | String | The MD5 hash of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_effective_reputation | String | The effective reputation of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_reputation | String | The reputation of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_cmdline | String | The command line of the parent process related to the alert. | 
| CarbonBlackDefense.Alert.parent_username | String | The username associated with the parent process related to the alert. | 
| CarbonBlackDefense.Alert.childproc_guid | String | The GUID of the child process related to the alert. | 
| CarbonBlackDefense.Alert.childproc_username | String | The username associated with the child process related to the alert. | 
| CarbonBlackDefense.Alert.childproc_cmdline | String | The command line of the child process related to the alert. | 

#### Command example
```!cbd-alerts-search reputation=NOT_LISTED rows=3 type=all```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Alert": [
            {
                "alert_notes_present": false,
                "alert_origin": "ALERT_ORIGIN_UNKNOWN",
                "alert_url": "dummy_alert_url",
                "asset_group": [],
                "backend_timestamp": "2024-07-09T12:22:14.999Z",
                "backend_update_timestamp": "2024-07-09T12:22:14.999Z",
                "childproc_cmdline": "",
                "childproc_guid": "",
                "childproc_username": "",
                "detection_timestamp": "2024-07-09T12:21:10.168Z",
                "determination": {
                    "change_timestamp": "2024-07-09T12:22:14.999Z",
                    "changed_by": "ALERT_CREATION",
                    "changed_by_type": "SYSTEM",
                    "value": "NONE"
                },
                "device_external_ip": "1.1.1.1",
                "device_id": "dummy_device_id",
                "device_internal_ip": "1.1.1.1",
                "device_location": "UNKNOWN",
                "device_name": "win1122H2new",
                "device_os": "WINDOWS",
                "device_os_version": "Windows 11 x64",
                "device_policy": "⚠️ Wide Open",
                "device_policy_id": "dummy_device_policy_id",
                "device_target_value": "LOW",
                "device_uem_id": "",
                "device_username": "Administrator",
                "first_event_timestamp": "2024-07-09T12:19:01.963Z",
                "id": "dummy_id",
                "ioc_field": "netconn_ipv4",
                "ioc_hit": "1.1.1.1",
                "ioc_id": "dummy_ioc_id",
                "is_updated": false,
                "last_event_timestamp": "2024-07-09T12:19:01.963Z",
                "mdr_alert": false,
                "mdr_alert_notes_present": false,
                "mdr_threat_notes_present": false,
                "org_key": "dummy_org_key",
                "parent_cmdline": "C:\\Windows\\system32\\services.exe",
                "parent_effective_reputation": "TRUSTED_WHITE_LIST",
                "parent_guid": "dummy_parent_guid",
                "parent_md5": "dummy_parent_md5",
                "parent_name": "c:\\windows\\system32\\services.exe",
                "parent_pid": "dummy_parent_pid",
                "parent_reputation": "TRUSTED_WHITE_LIST",
                "parent_sha256": "dummy_parent_sha256",
                "parent_username": "NT AUTHORITY\\SYSTEM",
                "policy_applied": "NOT_APPLIED",
                "primary_event_id": "dummy_primary_event_id",
                "process_cmdline": "\"C:\\Program Files (x86)\\Netskope\\STAgent\\stAgentSvc.exe\"",
                "process_effective_reputation": "LOCAL_WHITE",
                "process_guid": "dummy_process_guid",
                "process_issuer": [
                    ""
                ],
                "process_md5": "dummy_parent_md5",
                "process_name": "c:\\program files (x86)\\netskope\\stagent\\stagentsvc.exe",
                "process_pid": "dummy_process_pid",
                "process_publisher": [
                    ""
                ],
                "process_reputation": "NOT_LISTED",
                "process_sha256": "dummy_process_sha256",
                "process_username": "NT AUTHORITY\\SYSTEM",
                "reason": "Process stagentsvc.exe was detected by the report \"crest test-netconn_ipv4-1\" in watchlist \"Crest test\"",
                "reason_code": "dummy_reason_code",
                "report_description": "Service Now Threat Intel",
                "report_id": "dummy_report_id",
                "report_link": "https://dev188630.service-now.com/",
                "report_name": "crest test-netconn_ipv4-1",
                "report_tags": [],
                "run_state": "RAN",
                "sensor_action": "ALLOW",
                "severity": 5,
                "tags": null,
                "threat_id": "dummy_threat_id",
                "threat_notes_present": false,
                "type": "WATCHLIST",
                "user_update_timestamp": null,
                "watchlists": [
                    {
                        "id": "dummy_id",
                        "name": "Crest test"
                    }
                ],
                "workflow": {
                    "change_timestamp": "2024-07-09T12:22:14.999Z",
                    "changed_by": "ALERT_CREATION",
                    "changed_by_type": "SYSTEM",
                    "closure_reason": "NO_REASON",
                    "status": "OPEN"
                }
            },
            {
                "alert_notes_present": false,
                "alert_origin": "ALERT_ORIGIN_UNKNOWN",
                "alert_url": "dummy_alert_url",
                "asset_group": [],
                "backend_timestamp": "2024-07-09T11:55:04.223Z",
                "backend_update_timestamp": "2024-07-09T11:55:04.223Z",
                "childproc_cmdline": "",
                "childproc_guid": "",
                "childproc_username": "",
                "detection_timestamp": "2024-07-09T11:53:53.751Z",
                "determination": {
                    "change_timestamp": "2024-07-09T11:55:04.223Z",
                    "changed_by": "ALERT_CREATION",
                    "changed_by_type": "SYSTEM",
                    "value": "NONE"
                },
                "device_external_ip": "1.1.1.1",
                "device_id": "dummy_device_id",
                "device_internal_ip": "1.1.1.1",
                "device_location": "UNKNOWN",
                "device_name": "win1122H2new",
                "device_os": "WINDOWS",
                "device_os_version": "Windows 11 x64",
                "device_policy": "⚠️ Wide Open",
                "device_policy_id": "dummy_device_policy_id",
                "device_target_value": "LOW",
                "device_uem_id": "",
                "device_username": "Administrator",
                "first_event_timestamp": "2024-07-09T11:51:44.217Z",
                "id": "dummy_id",
                "ioc_field": "netconn_ipv4",
                "ioc_hit": "1.1.1.1",
                "ioc_id": "dummy_ioc_id",
                "is_updated": false,
                "last_event_timestamp": "2024-07-09T11:51:44.217Z",
                "mdr_alert": false,
                "mdr_alert_notes_present": false,
                "mdr_threat_notes_present": false,
                "org_key": "dummy_org_key",
                "parent_cmdline": "",
                "parent_effective_reputation": "TRUSTED_WHITE_LIST",
                "parent_guid": "dummy_parent_guid",
                "parent_md5": "",
                "parent_name": "c:\\windows\\system32\\services.exe",
                "parent_pid": "dummy_parent_pid",
                "parent_reputation": "TRUSTED_WHITE_LIST",
                "parent_sha256": "dummy_parent_sha256",
                "parent_username": "NT AUTHORITY\\SYSTEM",
                "policy_applied": "NOT_APPLIED",
                "primary_event_id": "dummy_primary_event_id",
                "process_cmdline": "\"C:\\Program Files (x86)\\Netskope\\STAgent\\stAgentSvc.exe\"",
                "process_effective_reputation": "LOCAL_WHITE",
                "process_guid": "dummy_process_guid",
                "process_issuer": [],
                "process_md5": "",
                "process_name": "c:\\program files (x86)\\netskope\\stagent\\stagentsvc.exe",
                "process_pid": "dummy_process_pid",
                "process_publisher": [],
                "process_reputation": "NOT_LISTED",
                "process_sha256": "dummy_process_sha256",
                "process_username": "NT AUTHORITY\\SYSTEM",
                "reason": "Process stagentsvc.exe was detected by the report \"crest test-netconn_ipv4-1\" in watchlist \"Crest test\"",
                "reason_code": "dummy_reason_code",
                "report_description": "Service Now Threat Intel",
                "report_id": "dummy_report_id",
                "report_link": "https://dev188630.service-now.com/",
                "report_name": "crest test-netconn_ipv4-1",
                "report_tags": [],
                "run_state": "RAN",
                "sensor_action": "ALLOW",
                "severity": 5,
                "tags": null,
                "threat_id": "dummy_threat_id",
                "threat_notes_present": false,
                "type": "WATCHLIST",
                "user_update_timestamp": null,
                "watchlists": [
                    {
                        "id": "dummy_id",
                        "name": "Crest test"
                    }
                ],
                "workflow": {
                    "change_timestamp": "2024-07-09T11:55:04.223Z",
                    "changed_by": "ALERT_CREATION",
                    "changed_by_type": "SYSTEM",
                    "closure_reason": "NO_REASON",
                    "status": "OPEN"
                }
            },
            {
                "alert_notes_present": false,
                "alert_origin": "ALERT_ORIGIN_UNKNOWN",
                "alert_url": "dummy_alert_url",
                "asset_group": [],
                "backend_timestamp": "2024-07-09T11:54:49.999Z",
                "backend_update_timestamp": "2024-07-09T11:54:49.999Z",
                "childproc_cmdline": "",
                "childproc_guid": "",
                "childproc_username": "",
                "detection_timestamp": "2024-07-09T11:53:53.750Z",
                "determination": {
                    "change_timestamp": "2024-07-09T11:54:49.999Z",
                    "changed_by": "ALERT_CREATION",
                    "changed_by_type": "SYSTEM",
                    "value": "NONE"
                },
                "device_external_ip": "1.1.1.1",
                "device_id": "dummy_device_id",
                "device_internal_ip": "1.1.1.1",
                "device_location": "UNKNOWN",
                "device_name": "win1122H2new",
                "device_os": "WINDOWS",
                "device_os_version": "Windows 11 x64",
                "device_policy": "⚠️ Wide Open",
                "device_policy_id": "dummy_device_policy_id",
                "device_target_value": "LOW",
                "device_uem_id": "",
                "device_username": "Administrator",
                "first_event_timestamp": "2024-07-09T11:51:44.218Z",
                "id": "dummy_id",
                "ioc_field": "netconn_ipv4",
                "ioc_hit": "1.1.1.1",
                "ioc_id": "dummy_ioc_id",
                "is_updated": false,
                "last_event_timestamp": "2024-07-09T11:51:44.218Z",
                "mdr_alert": false,
                "mdr_alert_notes_present": false,
                "mdr_threat_notes_present": false,
                "org_key": "dummy_org_key",
                "parent_cmdline": "",
                "parent_effective_reputation": "TRUSTED_WHITE_LIST",
                "parent_guid": "dummy_parent_guid",
                "parent_md5": "",
                "parent_name": "c:\\windows\\system32\\services.exe",
                "parent_pid": "dummy_parent_pid",
                "parent_reputation": "TRUSTED_WHITE_LIST",
                "parent_sha256": "dummy_parent_sha256",
                "parent_username": "NT AUTHORITY\\SYSTEM",
                "policy_applied": "NOT_APPLIED",
                "primary_event_id": "dummy_primary_event_id",
                "process_cmdline": "\"C:\\Program Files (x86)\\Netskope\\STAgent\\stAgentSvc.exe\"",
                "process_effective_reputation": "LOCAL_WHITE",
                "process_guid": "dummy_process_guid",
                "process_issuer": [],
                "process_md5": "",
                "process_name": "c:\\program files (x86)\\netskope\\stagent\\stagentsvc.exe",
                "process_pid": "dummy_process_pid",
                "process_publisher": [],
                "process_reputation": "NOT_LISTED",
                "process_sha256": "dummy_process_sha256",
                "process_username": "NT AUTHORITY\\SYSTEM",
                "reason": "Process stagentsvc.exe was detected by the report \"crest test-netconn_ipv4-1\" in watchlist \"Crest test\"",
                "reason_code": "dummy_reason_code",
                "report_description": "Service Now Threat Intel",
                "report_id": "dummy_report_id",
                "report_link": "https://dev188630.service-now.com/",
                "report_name": "crest test-netconn_ipv4-1",
                "report_tags": [],
                "run_state": "RAN",
                "sensor_action": "ALLOW",
                "severity": 5,
                "tags": null,
                "threat_id": "dummy_threat_id",
                "threat_notes_present": false,
                "type": "WATCHLIST",
                "user_update_timestamp": null,
                "watchlists": [
                    {
                        "id": "dummy_id",
                        "name": "Crest test"
                    }
                ],
                "workflow": {
                    "change_timestamp": "2024-07-09T11:54:49.999Z",
                    "changed_by": "ALERT_CREATION",
                    "changed_by_type": "SYSTEM",
                    "closure_reason": "NO_REASON",
                    "status": "OPEN"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Alerts List Results
>|Id|Device Id|Device Name|Device Username|Backend Timestamp|
>|---|---|---|---|---|
>| dummy_id | 8213794 | win1122H2new | Administrator | 2024-07-09T12:22:14.999Z |
>| dummy_id | 8213794 | win1122H2new | Administrator | 2024-07-09T11:55:04.223Z |
>| dummy_id | 8213794 | win1122H2new | Administrator | 2024-07-09T11:54:49.999Z |


### cbd-get-policy

***
Retrieves a policy object by ID.

#### Base Command

`cbd-get-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyId | The policy ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.description | String | A brief summary or description of the policy. | 
| CarbonBlackDefense.Policy.id | Number | The unique policy ID. | 
| CarbonBlackDefense.Policy.name | String | The name of the policy. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vdi_interval_ms | Number | The interval in milliseconds for automatically deregistering inactive VDI \(Virtual Desktop Infrastructure\) devices. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vm_workloads_interval_ms | Number | The interval in milliseconds for automatically deregistering inactive VM \(Virtual Machine\) workloads. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.enabled | Boolean | Indicates whether the Avira Protection Cloud is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_exe_delay | Number | The maximum execution delay in milliseconds for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_file_size | Number | The maximum file size in bytes that can be uploaded to Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.risk_level | Number | The risk level assigned by Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.enabled | Boolean | Indicates whether the on-access scan is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.mode | String | The mode of the on-access scan. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.enabled | Boolean | Indicates whether the on-demand scan is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.profile | String | The profile used for the on-demand scan. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_cd_dvd | String | Indicates whether the on-demand scan includes CD/DVD drives. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_usb | String | Indicates whether the on-demand scan includes USB drives. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.range_hours | Number | The range of hours for scheduling the on-demand scan. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.recovery_scan_if_missed | Boolean | Indicates whether a recovery scan is performed if the scheduled scan is missed. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.start_hour | Number | The start hour for scheduling the on-demand scan. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.enabled | Boolean | Indicates whether signature updates are enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.full_interval_hours | Number | The full interval in hours for scheduling signature updates. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.initial_random_delay_hours | Number | The initial random delay in hours for scheduling signature updates. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.interval_hours | Number | The interval in hours for scheduling signature updates. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_offsite_devices | String | The update servers used for offsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.preferred | Boolean | Indicates whether the server is preferred for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.server | String | The update server used for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_override | Unknown | Indicates whether the update servers override the default settings. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.file_upload | Boolean | Indicates whether file uploads are allowed by the directory action rule. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.path | String | The directory path specified by the action rule. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.protection | Boolean | Indicates whether protection is enabled for the directory action rule. | 
| CarbonBlackDefense.Policy.policy.is_system | Boolean | Indicates whether the policy is a system policy. | 
| CarbonBlackDefense.Policy.policy.org_key | String | The organization key associated with the policy. | 
| CarbonBlackDefense.Policy.policy.position | Number | The position of the policy in the list of policies. | 
| CarbonBlackDefense.Policy.policy.rule_configs.category | String | The category of the rule configuration. | 
| CarbonBlackDefense.Policy.policy.rule_configs.description | String | A description of the rule configuration. | 
| CarbonBlackDefense.Policy.policy.rule_configs.id | String | The unique rule configuration ID. | 
| CarbonBlackDefense.Policy.policy.rule_configs.inherited_from | String | The source from which the rule configuration is inherited. | 
| CarbonBlackDefense.Policy.policy.rule_configs.name | String | The name of the rule configuration. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_network_data_collection | Boolean | Indicates whether network data collection is enabled. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_auth_events | Boolean | Indicates whether authentication events are enabled. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.WindowsAssignmentMode | String | The Windows assignment mode for the rule configuration. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters | Unknown | The parameters of the rule configuration. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.default_rule.action | String | The default action of the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.default_rule.default_rule_access_check_guid | String | The access check GUID for the default rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.default_rule.default_rule_inbound_event_check_guid | String | The inbound event check GUID for the default rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.default_rule.default_rule_outbound_event_check_guid | String | The outbound event check GUID for the default rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_host_based_firewall | Boolean | Indicates whether the host-based firewall is enabled. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.description | String | A description of the rule group. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.name | String | The name of the rule group. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.action | String | The action specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.application_path | String | The application path specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.direction | String | The direction \(inbound or outbound\) specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.enabled | Boolean | Indicates whether the rule is enabled. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.local_ip_address | String | The local IP address specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.local_port_ranges | String | The local port ranges specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.name | String | The name of the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.network_profile | String | The network profile specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.protocol | String | The protocol specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.remote_ip_address | String | The remote IP address specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.remote_port_ranges | String | The remote port ranges specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.rule_access_check_guid | String | The access check GUID for the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.rule_inbound_event_check_guid | String | The inbound event check GUID for the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.rule_outbound_event_check_guid | String | The outbound event check GUID for the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.test_mode | Boolean | Indicates whether the rule is in test mode. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.rules.threat_score | Number | The threat score assigned by the rule. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.rule_groups.ruleset_id | String | The ID of the rule set. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.ubs_opt_in | Boolean | Indicates whether the UBS \(User Behavior Settings\) opt-in is enabled. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_prevalent_module_event_collection | Boolean | Indicates whether prevalent module event collection is enabled. | 
| CarbonBlackDefense.Policy.policy.rules.action | String | The action specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rules.application.type | String | The type of application specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rules.application.value | String | The value of the application specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rules.id | Number | The unique rule ID. | 
| CarbonBlackDefense.Policy.policy.rules.operation | String | The operation specified by the rule. | 
| CarbonBlackDefense.Policy.policy.rules.required | Boolean | Indicates whether the rule is required. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.category | String | The category of the sensor configuration. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.description | String | A description of the sensor configuration. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.id | String | The unique sensor configuration ID. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.inherited_from | String | The source from which the sensor configuration is inherited. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.name | String | The name of the sensor configuration. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.parameters.inline_blocking_mode | String | The inline blocking mode specified by the sensor configuration. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.name | String | The name of the sensor setting. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.value | String | The value of the sensor setting. | 
| CarbonBlackDefense.Policy.policy.update_time | Date | The last update time of the policy. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The priority level of the policy. | 

#### Command example
```!cbd-get-policy policyId=80947```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "aaaaaaaa",
            "id": "dummy_id",
            "name": "AWN BAS",
            "policy": {
                "auto_deregister_inactive_vdi_interval_ms": 0,
                "auto_deregister_inactive_vm_workloads_interval_ms": 0,
                "av_settings": {
                    "avira_protection_cloud": {
                        "enabled": false,
                        "max_exe_delay": 45,
                        "max_file_size": 4,
                        "risk_level": 4
                    },
                    "on_access_scan": {
                        "enabled": true,
                        "mode": "AGGRESSIVE"
                    },
                    "on_demand_scan": {
                        "enabled": true,
                        "profile": "NORMAL",
                        "scan_cd_dvd": "AUTOSCAN",
                        "scan_usb": "AUTOSCAN",
                        "schedule": {
                            "range_hours": 0,
                            "recovery_scan_if_missed": true,
                            "start_hour": 0
                        }
                    },
                    "signature_update": {
                        "enabled": true,
                        "schedule": {
                            "full_interval_hours": 0,
                            "initial_random_delay_hours": 4,
                            "interval_hours": 4
                        }
                    },
                    "update_servers": {
                        "servers_for_offsite_devices": [
                            "http://updates2.cdc.carbonblack.io/update2"
                        ],
                        "servers_for_onsite_devices": [
                            {
                                "preferred": false,
                                "server": "http://updates2.cdc.carbonblack.io/update2"
                            }
                        ],
                        "servers_override": []
                    }
                },
                "directory_action_rules": [
                    {
                        "file_upload": false,
                        "path": "",
                        "protection": false
                    }
                ],
                "is_system": false,
                "org_key": "dummy_org_key",
                "position": 1,
                "rule_configs": [
                    {
                        "category": "data_collection",
                        "description": "Turns on XDR network data collection at the sensor",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "XDR",
                        "parameters": {
                            "enable_network_data_collection": true
                        }
                    },
                    {
                        "category": "data_collection",
                        "description": "Turns on Windows authentication events at the sensor",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Authentication Events",
                        "parameters": {
                            "enable_auth_events": false
                        }
                    },
                    {
                        "category": "core_prevention",
                        "description": "Addresses malicious fileless and file-backed scripts that leverage native programs and common scripting languages.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Advanced Scripting Prevention",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "category": "core_prevention",
                        "description": "Addresses threat actors obtaining credentials and relies on detecting the malicious use of TTPs/behaviors that indicate such activity.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Credential Theft",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "category": "core_prevention",
                        "description": "Addresses common and pervasive TTPs used for malicious activity as well as living off the land TTPs/behaviors detected by Carbon Black’s Threat Analysis Unit.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Carbon Black Threat Intel",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "category": "core_prevention",
                        "description": "Addresses behaviors that indicate a threat actor has gained elevated access via a bug or misconfiguration within an operating system, and leverages the detection of TTPs/behaviors to prevent such activity.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Privilege Escalation",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "category": "core_prevention",
                        "description": "Addresses common TTPs/behaviors that threat actors use to avoid detection such as uninstalling or disabling security software, obfuscating or encrypting data/scripts and abusing trusted processes to hide and disguise their malicious activity.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Defense Evasion",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "category": "core_prevention",
                        "description": "Addresses common TTPs/behaviors that threat actors use to retain access to systems across restarts, changed credentials, and other interruptions that could cut off their access.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Persistence",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "category": "bypass",
                        "description": "Allows customers to exclude specific processes and process events from reporting to CBC",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Event Reporting and Sensor Operation Exclusions",
                        "parameters": {}
                    },
                    {
                        "category": "bypass",
                        "description": "Allows customers to exclude specific processes from reporting events to CBC",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Event Reporting Exclusions",
                        "parameters": {}
                    },
                    {
                        "category": "host_based_firewall",
                        "description": "These are the Host based Firewall Rules which will be executed by the sensor. The Definition will be part of Main Policies.",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Host Based Firewall",
                        "parameters": {
                            "default_rule": {
                                "action": "ALLOW",
                                "default_rule_access_check_guid": "dummy_default_rule_access_check_guid",
                                "default_rule_inbound_event_check_guid": "dummy_default_rule_inbound_event_check_guid",
                                "default_rule_outbound_event_check_guid": "dummy_default_rule_outbound_event_check_guid"
                            },
                            "enable_host_based_firewall": true,
                            "rule_groups": [
                                {
                                    "description": "C&C used by SocGholish",
                                    "name": "Block C&C Traffic",
                                    "rules": [
                                        {
                                            "action": "BLOCK_ALERT",
                                            "application_path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                                            "direction": "OUT",
                                            "enabled": true,
                                            "local_ip_address": "*",
                                            "local_port_ranges": "*",
                                            "name": "SocGholish 2024-01-03",
                                            "network_profile": [
                                                "PUBLIC",
                                                "PRIVATE",
                                                "DOMAIN"
                                            ],
                                            "protocol": "TCP",
                                            "remote_ip_address": "1.1.1.1/22",
                                            "remote_port_ranges": "443",
                                            "rule_access_check_guid": "dummy_rule_access_check_guid",
                                            "rule_inbound_event_check_guid": "dummy_rule_inbound_event_check_guid",
                                            "rule_outbound_event_check_guid": "dummy_rule_outbound_event_check_guid",
                                            "test_mode": false,
                                            "threat_score": 8
                                        }
                                    ],
                                    "ruleset_id": "dummy_ruleset_id"
                                }
                            ]
                        }
                    },
                    {
                        "category": "data_collection",
                        "description": "Enterprise EDR Event Collection",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Enterprise EDR Event Collection",
                        "parameters": {
                            "ubs_opt_in": true
                        }
                    },
                    {
                        "category": "data_collection",
                        "description": "Collects events created when a process loads a common library. Enabling this will increase the number of events reported for expected process behavior.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Prevalent Module Exclusions",
                        "parameters": {
                            "enable_prevalent_module_event_collection": false
                        }
                    }
                ],
                "rules": [
                    {
                        "action": "IGNORE",
                        "application": {
                            "type": "NAME_PATH",
                            "value": "COMMON_WHITE_LIST"
                        },
                        "id": "dummy_id",
                        "operation": "RANSOM",
                        "required": false
                    }
                ],
                "sensor_configs": [
                    {
                        "category": "sensor_settings",
                        "description": "Manages sensor settings specific to endpoint standard product",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Endpoint standard sensor settings at policy scope",
                        "parameters": {
                            "inline_blocking_mode": "disabled"
                        }
                    }
                ],
                "sensor_settings": [
                    {
                        "name": "ALLOW_UNINSTALL",
                        "value": "true"
                    },
                    {
                        "name": "ALLOW_UPLOADS",
                        "value": "false"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    },
                    {
                        "name": "ALLOW_INLINE_BLOCKING",
                        "value": "true"
                    }
                ],
                "update_time": 1720436305029
            },
            "priorityLevel": "MEDIUM"
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Policy
>|Id|Name|Priority Level|Is System|Description|
>|---|---|---|---|---|
>| dummy_id | AWN BAS | MEDIUM | false | aaaaaaaa |


### cbd-get-policies-summary

***
Get an overview of the policies available in the organization.

#### Base Command

`cbd-get-policies-summary`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.PolicySummary.description | String | A brief summary or description of the policy. | 
| CarbonBlackDefense.PolicySummary.id | Number | The unique policy ID. | 
| CarbonBlackDefense.PolicySummary.is_system | Boolean | Indicates whether the policy is a system policy. | 
| CarbonBlackDefense.PolicySummary.name | String | The name of the policy. | 
| CarbonBlackDefense.PolicySummary.num_devices | Number | The number of devices currently using the policy. | 
| CarbonBlackDefense.PolicySummary.position | Number | The position of the policy in the list of policies. | 
| CarbonBlackDefense.PolicySummary.priority_level | String | The priority level of the policy. | 
| CarbonBlackDefense.PolicySummary.total_num_devices | Number | The total number of devices associated with the policy. | 

#### Command example
```!cbd-get-policies-summary```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "PolicySummary": [
            {
                "description": "aaaaaaaa",
                "id": "dummy_id",
                "is_system": false,
                "name": "AWN BAS",
                "num_devices": 2,
                "position": 1,
                "priority_level": "MEDIUM",
                "total_num_devices": 2
            },
            {
                "description": "",
                "id": "dummy_id",
                "is_system": false,
                "name": "Abhi-CB-policy",
                "num_devices": 1,
                "position": 2,
                "priority_level": "LOW",
                "total_num_devices": 1
            },
            {
                "description": "Don't worry about this. It won't be here long.",
                "id": "dummy_id",
                "is_system": false,
                "name": "Splunk Policy To_be_deleted_1652997758",
                "num_devices": 0,
                "position": 39,
                "priority_level": "MEDIUM"
            },
            {
                "description": "Splunk Policy invalid value",
                "id": "dummy_id",
                "is_system": false,
                "name": "Splunk Policy invalid value1652962163",
                "num_devices": 0,
                "position": 42,
                "priority_level": "HIGH"
            },
            {
                "description": "aaaaaaaa",
                "id": "dummy_id",
                "is_system": false,
                "name": "test42",
                "num_devices": 0,
                "position": 107,
                "priority_level": "MEDIUM"
            }
        ]
    }
}
```

#### Human Readable Output

>### Policies summaries
>|Id|Name|Priority Level|Is System|
>|---|---|---|---|
>| 80947 | AWN BAS | MEDIUM | false |
>| 87816 | Abhi-CB-policy | LOW | false |
>| 103786 | CBCLOUD Policy | MEDIUM | false |
>| 33819 | Cigent Policy | HIGH | false |
>| 68727 | Confluera Policy 1 | LOW | false |
>| 69390 | Cyborg_Monitor | LOW | false |
>| 102049 | DarkNegev | MEDIUM | false |
>| 12147 | DefenseStorm Policy | MEDIUM | false |
>| 109968 | Devo-MP-Skoville | MEDIUM | false |
>| 105029 | EasyNAC domain | MEDIUM | false |
>| 35704 | Fortress Policy | MISSION_CRITICAL | false |
>| 130711 | Hunters High Test | HIGH | false |
>| 41528 | Hunters Policy | MEDIUM | false |
>| 128135 | Hunters Policy test | MISSION_CRITICAL | false |
>| 99682 | Iron-policy | MEDIUM | false |
>| 63139 | LRDemo-JH | MEDIUM | false |
>| 138424 | Lions (Victor+Long) | MISSION_CRITICAL | false |
>| 9246 | LogRhythm Policy | MEDIUM | false |
>| 104163 | Lumu | MEDIUM | false |
>| 65120 | Lumu Policy | LOW | false |
>| 96535 | Moja Skopska polisa | LOW | false |


### cbd-create-policy

***
Creates a new policy on the CB Defense backend.

#### Base Command

`cbd-create-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | A description of the policy. Can be multiple lines. | Optional | 
| name | A unique one-line name for the policy. | Optional | 
| priorityLevel | The priority score associated with sensors assigned to this policy. Possible values: "MISSION_CRITICAL", "HIGH", "MEDIUM", and "LOW". | Optional | 
| policy | The JSON object containing the policy details. Make sure a valid policy object is passed. You can use the get-policy command to retrieve a similar policy object. Then you can reset some of the policy's fields with the set-policy command, and pass the edited object. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.description | String | A brief summary or description of the policy. | 
| CarbonBlackDefense.Policy.id | Number | The unique policy ID. | 
| CarbonBlackDefense.Policy.name | String | The name of the policy. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vdi_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VDI. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vm_workloads_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VM workloads. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.enabled | Boolean | Indicates if Avira Protection Cloud is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_exe_delay | Number | The maximum execution delay for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_file_size | Number | The maximum file size for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.risk_level | Number | The risk level for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.enabled | Boolean | Indicates if on-access scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.mode | String | The mode of on-access scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.enabled | Boolean | Indicates if on-demand scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.profile | String | The profile for on-demand scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_cd_dvd | String | Indicates if on-demand scanning of CD/DVD is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_usb | String | Indicates if on-demand scanning of USB devices is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.range_hours | Number | The range of hours for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.recovery_scan_if_missed | Boolean | Indicates if a recovery scan is scheduled if the previous scan is missed. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.start_hour | Number | The start hour for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.enabled | Boolean | Indicates if signature updates are enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.full_interval_hours | Number | The full interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.initial_random_delay_hours | Number | The initial random delay in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.interval_hours | Number | The interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_offsite_devices | String | The servers used for offsite devices for updates. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.preferred | Boolean | Indicates if the server is preferred for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.server | String | The server used for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_override | Unknown | Indicates if server overrides are enabled for updates. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.file_upload | Boolean | Indicates if file upload is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.path | String | The path for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.protection | Boolean | Indicates if protection is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.is_system | Boolean | Indicates if the policy is a system policy. | 
| CarbonBlackDefense.Policy.policy.org_key | String | The organization key associated with the policy. | 
| CarbonBlackDefense.Policy.policy.position | Number | The position of the policy in the list of policies. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.description | String | A description of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.id | String | The ID of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.inherited_from | String | Indicates the source from which the rapid configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.name | String | The name of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_network_data_collection | Boolean | Indicates if network data collection is enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_auth_events | Boolean | Indicates if authentication events are enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.inline_blocking_mode | String | The inline blocking mode for rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.category | String | The category of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.description | String | A description of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.id | String | The ID of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.inherited_from | String | Indicates the source from which the rule configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rule_configs.name | String | The name of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters | Unknown | The parameters of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.ubs_opt_in | Boolean | Indicates if UBS opt-in is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_prevalent_module_event_collection | Boolean | Indicates if prevalent module event collection is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rules.id | Number | The ID of the rules. | 
| CarbonBlackDefense.Policy.policy.rules.required | Boolean | Indicates if the rules are required. | 
| CarbonBlackDefense.Policy.policy.rules.action | String | The action specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.type | String | The type of application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.value | String | The value of the application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.operation | String | The operation specified in the rules. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.category | String | The category of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.description | String | A description of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.id | String | The ID of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.inherited_from | String | Indicates the source from which the sensor configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.name | String | The name of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.parameters.inline_blocking_mode | String | The inline blocking mode for sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.name | String | The name of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.value | String | The value of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.update_time | Date | The time when the policy was last updated. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The priority level of the policy. | 

#### Command example
```!cbd-create-policy policy="{\"name\": \"test4\", \"description\": \"aaaaaaaa\",\"org_key\": \"7DESJ9GN\", \"priority_level\": \"MEDIUM\", \"rules\": [], \"sensor_settings\": [{\"name\": \"ALLOW_UNINSTALL\", \"value\": \"true\"}]}"```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "aaaaaaaa",
            "id": "dummy_id",
            "name": "test4",
            "policy": {
                "auto_deregister_inactive_vdi_interval_ms": 0,
                "auto_deregister_inactive_vm_workloads_interval_ms": 0,
                "av_settings": {
                    "avira_protection_cloud": {
                        "enabled": false,
                        "max_exe_delay": 45,
                        "max_file_size": 4,
                        "risk_level": 4
                    },
                    "on_access_scan": {
                        "enabled": true,
                        "mode": "NORMAL"
                    },
                    "on_demand_scan": {
                        "enabled": true,
                        "profile": "NORMAL",
                        "scan_cd_dvd": "AUTOSCAN",
                        "scan_usb": "AUTOSCAN",
                        "schedule": {
                            "range_hours": 0,
                            "recovery_scan_if_missed": true,
                            "start_hour": 0
                        }
                    },
                    "signature_update": {
                        "enabled": false,
                        "schedule": {
                            "full_interval_hours": 0,
                            "initial_random_delay_hours": 4,
                            "interval_hours": 2
                        }
                    },
                    "update_servers": {
                        "servers_for_offsite_devices": [
                            "http://updates2.cdc.carbonblack.io/update2"
                        ],
                        "servers_for_onsite_devices": [
                            {
                                "preferred": true,
                                "server": "http://updates2.cdc.carbonblack.io/update2"
                            }
                        ],
                        "servers_override": []
                    }
                },
                "directory_action_rules": [
                    {
                        "file_upload": false,
                        "path": "",
                        "protection": false
                    }
                ],
                "is_system": false,
                "org_key": "dummy_org_key",
                "position": 108,
                "rapid_configs": [
                    {
                        "description": "Turns on XDR network data collection at the sensor",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "XDR",
                        "parameters": {
                            "enable_network_data_collection": true
                        }
                    },
                    {
                        "description": "Turns on Windows authentication events at the sensor",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Authentication Events",
                        "parameters": {
                            "enable_auth_events": false
                        }
                    },
                    {
                        "description": "Manages sensor settings specific to endpoint standard product",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Endpoint standard sensor settings at policy scope",
                        "parameters": {
                            "inline_blocking_mode": "disabled"
                        }
                    },
                    {
                        "category": "data_collection",
                        "description": "Collects events created when a process loads a common library. Enabling this will increase the number of events reported for expected process behavior.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Prevalent Module Exclusions",
                        "parameters": {
                            "enable_prevalent_module_event_collection": false
                        }
                    }
                ],
                "rules": [],
                "sensor_configs": [
                    {
                        "category": "sensor_settings",
                        "description": "Manages sensor settings specific to endpoint standard product",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Endpoint standard sensor settings at policy scope",
                        "parameters": {
                            "inline_blocking_mode": "disabled"
                        }
                    }
                ],
                "sensor_settings": [
                    {
                        "name": "ALLOW_UNINSTALL",
                        "value": "true"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    },
                    {
                        "name": "ALLOW_INLINE_BLOCKING",
                        "value": "true"
                    }
                ],
                "update_time": 1720539000191
            },
            "priorityLevel": "MEDIUM"
        }
    }
}
```

#### Human Readable Output

>### Policy created successfully
>|Id|Description|Name|Priority Level|Is System|
>|---|---|---|---|---|
>| 170044 | aaaaaaaa | test4 | MEDIUM | false |


### cbd-update-policy

***
Update an existing policy on the CB Defense backend.

#### Base Command

`cbd-update-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | A description of the policy. Can be multiple lines. | Optional | 
| name | A unique one-line name for the policy. | Optional | 
| priorityLevel | The priority score associated with sensors assigned to this policy. Possible values: "MISSION_CRITICAL", "HIGH", "MEDIUM", and "LOW". | Optional | 
| id | The policy ID to update. | Required | 
| policy | The JSON object containing the policy details. Make sure a valid policy object is passed. You can use the get-policy command to retrieve a similar policy object. Then you can reset some of the policy's fields with the set-policy command, and pass the edited object. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.description | String | A brief summary or description of the policy. | 
| CarbonBlackDefense.Policy.id | Number | The unique policy ID. | 
| CarbonBlackDefense.Policy.name | String | The name of the policy. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vdi_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VDI. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vm_workloads_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VM workloads. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.enabled | Boolean | Indicates if Avira Protection Cloud is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_exe_delay | Number | The maximum execution delay for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_file_size | Number | The maximum file size for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.risk_level | Number | The risk level for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.enabled | Boolean | Indicates if on-access scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.mode | String | The mode of on-access scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.enabled | Boolean | Indicates if on-demand scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.profile | String | The profile for on-demand scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_cd_dvd | String | Indicates if on-demand scanning of CD/DVD is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_usb | String | Indicates if on-demand scanning of USB devices is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.range_hours | Number | The range of hours for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.recovery_scan_if_missed | Boolean | Indicates if a recovery scan is scheduled if the previous scan is missed. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.start_hour | Number | The start hour for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.enabled | Boolean | Indicates if signature updates are enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.full_interval_hours | Number | The full interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.initial_random_delay_hours | Number | The initial random delay in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.interval_hours | Number | The interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_offsite_devices | String | The servers used for offsite devices for updates. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.preferred | Boolean | Indicates if the server is preferred for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.server | String | The server used for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_override | Unknown | Indicates if server overrides are enabled for updates. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.file_upload | Boolean | Indicates if file upload is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.path | String | The path for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.protection | Boolean | Indicates if protection is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.is_system | Boolean | Indicates if the policy is a system policy. | 
| CarbonBlackDefense.Policy.policy.org_key | String | The organization key associated with the policy. | 
| CarbonBlackDefense.Policy.policy.position | Number | The position of the policy in the list of policies. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.description | String | A description of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.id | String | The ID of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.inherited_from | String | Indicates the source from which the rapid configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.name | String | The name of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_network_data_collection | Boolean | Indicates if network data collection is enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_auth_events | Boolean | Indicates if authentication events are enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.inline_blocking_mode | String | The inline blocking mode for rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.category | String | The category of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.description | String | A description of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.id | String | The ID of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.inherited_from | String | Indicates the source from which the rule configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rule_configs.name | String | The name of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters | Unknown | The parameters of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.ubs_opt_in | Boolean | Indicates if UBS opt-in is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_prevalent_module_event_collection | Boolean | Indicates if prevalent module event collection is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rules.id | Number | The ID of the rules. | 
| CarbonBlackDefense.Policy.policy.rules.required | Boolean | Indicates if the rules are required. | 
| CarbonBlackDefense.Policy.policy.rules.action | String | The action specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.type | String | The type of application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.value | String | The value of the application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.operation | String | The operation specified in the rules. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.category | String | The category of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.description | String | A description of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.id | String | The ID of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.inherited_from | String | Indicates the source from which the sensor configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.name | String | The name of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.parameters.inline_blocking_mode | String | The inline blocking mode for sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.name | String | The name of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.value | String | The value of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.update_time | Date | The time when the policy was last updated. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The priority level of the policy. | 

#### Command example
```!cbd-update-policy id=80947 policy="{\"name\": \"AWN BAS\", \"description\": \"aaaaaaaa\",\"org_key\": \"7DESJ9GN\", \"priority_level\": \"MEDIUM\", \"rules\": [], \"sensor_settings\": [{\"name\": \"ALLOW_UNINSTALL\", \"value\": \"true\"}]}"```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "aaaaaaaa",
            "id": "dummy_id",
            "name": "AWN BAS",
            "policy": {
                "auto_deregister_inactive_vdi_interval_ms": 0,
                "auto_deregister_inactive_vm_workloads_interval_ms": 0,
                "av_settings": {
                    "avira_protection_cloud": {
                        "enabled": false,
                        "max_exe_delay": 45,
                        "max_file_size": 4,
                        "risk_level": 4
                    },
                    "on_access_scan": {
                        "enabled": true,
                        "mode": "AGGRESSIVE"
                    },
                    "on_demand_scan": {
                        "enabled": true,
                        "profile": "NORMAL",
                        "scan_cd_dvd": "AUTOSCAN",
                        "scan_usb": "AUTOSCAN",
                        "schedule": {
                            "range_hours": 0,
                            "recovery_scan_if_missed": true,
                            "start_hour": 0
                        }
                    },
                    "signature_update": {
                        "enabled": true,
                        "schedule": {
                            "full_interval_hours": 0,
                            "initial_random_delay_hours": 4,
                            "interval_hours": 4
                        }
                    },
                    "update_servers": {
                        "servers_for_offsite_devices": [
                            "http://updates2.cdc.carbonblack.io/update2"
                        ],
                        "servers_for_onsite_devices": [
                            {
                                "preferred": false,
                                "server": "http://updates2.cdc.carbonblack.io/update2"
                            }
                        ],
                        "servers_override": []
                    }
                },
                "directory_action_rules": [
                    {
                        "file_upload": false,
                        "path": "",
                        "protection": false
                    }
                ],
                "is_system": false,
                "org_key": "dummy_org_key",
                "position": 1,
                "rapid_configs": [
                    {
                        "description": "Turns on XDR network data collection at the sensor",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "XDR",
                        "parameters": {
                            "enable_network_data_collection": true
                        }
                    },
                    {
                        "description": "Addresses common TTPs/behaviors that threat actors use to avoid detection such as uninstalling or disabling security software, obfuscating or encrypting data/scripts and abusing trusted processes to hide and disguise their malicious activity.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Defense Evasion",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "description": "Addresses common TTPs/behaviors that threat actors use to retain access to systems across restarts, changed credentials, and other interruptions that could cut off their access.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Persistence",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "description": "Allows customers to exclude specific processes and process events from reporting to CBC",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Event Reporting and Sensor Operation Exclusions",
                        "parameters": {}
                    },
                    {
                        "description": "Allows customers to exclude specific processes from reporting events to CBC",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Event Reporting Exclusions",
                        "parameters": {}
                    },
                    {
                        "description": "These are the Host based Firewall Rules which will be executed by the sensor. The Definition will be part of Main Policies.",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Host Based Firewall",
                        "parameters": {
                            "default_rule": {
                                "action": "ALLOW",
                                "default_rule_access_check_guid": "dummy_default_rule_access_check_guid",
                                "default_rule_inbound_event_check_guid": "dummy_default_rule_inbound_event_check_guid",
                                "default_rule_outbound_event_check_guid": "dummy_default_rule_outbound_event_check_guid"
                            },
                            "enable_host_based_firewall": true,
                            "rule_groups": [
                                {
                                    "description": "C&C used by SocGholish",
                                    "name": "Block C&C Traffic",
                                    "rules": [
                                        {
                                            "action": "BLOCK_ALERT",
                                            "application_path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                                            "direction": "OUT",
                                            "enabled": true,
                                            "local_ip_address": "*",
                                            "local_port_ranges": "*",
                                            "name": "SocGholish 2024-01-03",
                                            "network_profile": [
                                                "PUBLIC",
                                                "PRIVATE",
                                                "DOMAIN"
                                            ],
                                            "protocol": "TCP",
                                            "remote_ip_address": "1.1.1.1/22",
                                            "remote_port_ranges": "443",
                                            "rule_access_check_guid": "dummy_rule_access_check_guid",
                                            "rule_inbound_event_check_guid": "dummy_rule_inbound_event_check_guid",
                                            "rule_outbound_event_check_guid": "dummy_rule_outbound_event_check_guid",
                                            "test_mode": false,
                                            "threat_score": 8
                                        }
                                    ],
                                    "ruleset_id": "dummy_ruleset_id"
                                }
                            ]
                        }
                    },
                    {
                        "description": "Enterprise EDR Event Collection",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Enterprise EDR Event Collection",
                        "parameters": {
                            "ubs_opt_in": true
                        }
                    },
                    {
                        "description": "Collects events created when a process loads a common library. Enabling this will increase the number of events reported for expected process behavior.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Prevalent Module Exclusions",
                        "parameters": {
                            "enable_prevalent_module_event_collection": false
                        }
                    }
                ],
                "rule_configs": [
                    {
                        "category": "data_collection",
                        "description": "Turns on XDR network data collection at the sensor",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "XDR",
                        "parameters": {
                            "enable_network_data_collection": true
                        }
                    },
                    {
                        "category": "core_prevention",
                        "description": "Addresses common TTPs/behaviors that threat actors use to retain access to systems across restarts, changed credentials, and other interruptions that could cut off their access.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Persistence",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "category": "bypass",
                        "description": "Allows customers to exclude specific processes and process events from reporting to CBC",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Event Reporting and Sensor Operation Exclusions",
                        "parameters": {}
                    },
                    {
                        "category": "bypass",
                        "description": "Allows customers to exclude specific processes from reporting events to CBC",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Event Reporting Exclusions",
                        "parameters": {}
                    },
                    {
                        "category": "host_based_firewall",
                        "description": "These are the Host based Firewall Rules which will be executed by the sensor. The Definition will be part of Main Policies.",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Host Based Firewall",
                        "parameters": {
                            "default_rule": {
                                "action": "ALLOW",
                                "default_rule_access_check_guid": "dummy_default_rule_access_check_guid",
                                "default_rule_inbound_event_check_guid": "dummy_default_rule_inbound_event_check_guid",
                                "default_rule_outbound_event_check_guid": "dummy_default_rule_outbound_event_check_guid"
                            },
                            "enable_host_based_firewall": true,
                            "rule_groups": [
                                {
                                    "description": "C&C used by SocGholish",
                                    "name": "Block C&C Traffic",
                                    "rules": [
                                        {
                                            "action": "BLOCK_ALERT",
                                            "application_path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                                            "direction": "OUT",
                                            "enabled": true,
                                            "local_ip_address": "*",
                                            "local_port_ranges": "*",
                                            "name": "SocGholish 2024-01-03",
                                            "network_profile": [
                                                "PUBLIC",
                                                "PRIVATE",
                                                "DOMAIN"
                                            ],
                                            "protocol": "TCP",
                                            "remote_ip_address": "1.1.1.1/22",
                                            "remote_port_ranges": "443",
                                            "rule_access_check_guid": "dummy_rule_access_check_guid",
                                            "rule_inbound_event_check_guid": "dummy_rule_inbound_event_check_guid",
                                            "rule_outbound_event_check_guid": "dummy_rule_outbound_event_check_guid",
                                            "test_mode": false,
                                            "threat_score": 8
                                        }
                                    ],
                                    "ruleset_id": "dummy_ruleset_id"
                                }
                            ]
                        }
                    },
                    {
                        "category": "data_collection",
                        "description": "Enterprise EDR Event Collection",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Enterprise EDR Event Collection",
                        "parameters": {
                            "ubs_opt_in": true
                        }
                    },
                    {
                        "category": "data_collection",
                        "description": "Collects events created when a process loads a common library. Enabling this will increase the number of events reported for expected process behavior.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Prevalent Module Exclusions",
                        "parameters": {
                            "enable_prevalent_module_event_collection": false
                        }
                    }
                ],
                "rules": [],
                "sensor_configs": [
                    {
                        "category": "sensor_settings",
                        "description": "Manages sensor settings specific to endpoint standard product",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Endpoint standard sensor settings at policy scope",
                        "parameters": {
                            "inline_blocking_mode": "disabled"
                        }
                    }
                ],
                "sensor_settings": [
                    {
                        "name": "ALLOW_UNINSTALL",
                        "value": "true"
                    },
                    {
                        "name": "ALLOW_UPLOADS",
                        "value": "false"
                    },
                    {
                        "name": "SHOW_UI",
                        "value": "true"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    },
                    {
                        "name": "ALLOW_INLINE_BLOCKING",
                        "value": "true"
                    }
                ],
                "update_time": 1720539005619
            },
            "priorityLevel": "MEDIUM"
        }
    }
}
```

#### Human Readable Output

>### Policy with ID: 80947 updated successfully
>|Id|Description|Name|Priority Level|Is System|
>|---|---|---|---|---|
>| 80947 | aaaaaaaa | AWN BAS | MEDIUM | false |


### cbd-set-policy

***
Set existing policy's fields on the CB Defense backend.

#### Base Command

`cbd-set-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy | The policy ID to set. | Required | 
| keyValue | The JSON object containing the policy details. Make sure a valid policy object is passed. You can use the get-policy command to retrieve a similar policy object. Then you can reset some of the policy's fields with the set-policy command, and pass the edited object. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.description | String | A brief summary or description of the policy. | 
| CarbonBlackDefense.Policy.id | Number | The unique policy ID. | 
| CarbonBlackDefense.Policy.name | String | The name of the policy. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vdi_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VDI. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vm_workloads_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VM workloads. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.enabled | Boolean | Indicates if Avira Protection Cloud is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_exe_delay | Number | The maximum execution delay for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_file_size | Number | The maximum file size for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.risk_level | Number | The risk level for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.enabled | Boolean | Indicates if on-access scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.mode | String | The mode of on-access scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.enabled | Boolean | Indicates if on-demand scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.profile | String | The profile for on-demand scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_cd_dvd | String | Indicates if on-demand scanning of CD/DVD is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_usb | String | Indicates if on-demand scanning of USB devices is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.range_hours | Number | The range of hours for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.recovery_scan_if_missed | Boolean | Indicates if a recovery scan is scheduled if the previous scan is missed. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.start_hour | Number | The start hour for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.enabled | Boolean | Indicates if signature updates are enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.full_interval_hours | Number | The full interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.initial_random_delay_hours | Number | The initial random delay in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.interval_hours | Number | The interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_offsite_devices | String | The servers used for offsite devices for updates. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.preferred | Boolean | Indicates if the server is preferred for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.server | String | The server used for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_override | Unknown | Indicates if server overrides are enabled for updates. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.file_upload | Boolean | Indicates if file upload is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.path | String | The path for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.protection | Boolean | Indicates if protection is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.is_system | Boolean | Indicates if the policy is a system policy. | 
| CarbonBlackDefense.Policy.policy.org_key | String | The organization key associated with the policy. | 
| CarbonBlackDefense.Policy.policy.position | Number | The position of the policy in the list of policies. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.description | String | A description of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.id | String | The ID of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.inherited_from | String | Indicates the source from which the rapid configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.name | String | The name of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_network_data_collection | Boolean | Indicates if network data collection is enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_auth_events | Boolean | Indicates if authentication events are enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.inline_blocking_mode | String | The inline blocking mode for rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.category | String | The category of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.description | String | A description of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.id | String | The ID of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.inherited_from | String | Indicates the source from which the rule configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rule_configs.name | String | The name of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters | Unknown | The parameters of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.ubs_opt_in | Boolean | Indicates if UBS opt-in is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_prevalent_module_event_collection | Boolean | Indicates if prevalent module event collection is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rules.id | Number | The ID of the rules. | 
| CarbonBlackDefense.Policy.policy.rules.required | Boolean | Indicates if the rules are required. | 
| CarbonBlackDefense.Policy.policy.rules.action | String | The action specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.type | String | The type of application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.value | String | The value of the application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.operation | String | The operation specified in the rules. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.category | String | The category of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.description | String | A description of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.id | String | The ID of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.inherited_from | String | Indicates the source from which the sensor configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.name | String | The name of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.parameters.inline_blocking_mode | String | The inline blocking mode for sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.name | String | The name of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.value | String | The value of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.update_time | Date | The time when the policy was last updated. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The priority level of the policy. | 

### cbd-delete-policy

***
Deletes a policy from the CB Defense backend. This may return an error if devices are actively assigned to the policy ID requested for deletion. Note: System policies cannot be deleted.

#### Base Command

`cbd-delete-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyId | The policy ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cbd-delete-policy policyId=169977```

#### Human Readable Output

>Policy with ID 169977 was deleted successfully

### cbd-add-rule-to-policy

***
Adds a new rule to an existing policy. Note: System policies cannot be modified.

#### Base Command

`cbd-add-rule-to-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Rule action. Possible values: "TERMINATE", "IGNORE", "TERMINATE_THREAD", "ALLOW", "DENY, and "TERMINATE_PROCESS". | Required | 
| operation | Rule operation. Possible values: BYPASS_ALL, BYPASS_API, INVOKE_SCRIPT, INVOKE_SYSAPP, POL_INVOKE_NOT_TRUSTED, INVOKE_CMD_INTERPRETER, RANSOM, NETWORK, CODE_INJECTION, PROCESS_ISOLATION, MEMORY_SCRAPE, RUN_INMEMORY_CODE, ESCALATE, RUN. | Required | 
| required | Whether the rule is required. Possible values: true, false. | Required | 
| type | Application type. Possible values: "REPUTATION", "SIGNED_BY", and "NAME_PATH". | Required | 
| value | Application value. Possible values: ADWARE, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, HEURISTIC, IGNORE, KNOWN_MALWARE, LOCAL_WHITE, NOT_LISTED, PUP, RESOLVING, SUSPECT_MALWARE, TRUSTED_WHITE_LIST. | Required | 
| policyId | The policy ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.description | String | A brief summary or description of the policy. | 
| CarbonBlackDefense.Policy.id | Number | The unique policy ID. | 
| CarbonBlackDefense.Policy.name | String | The name of the policy. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vdi_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VDI. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vm_workloads_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VM workloads. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.enabled | Boolean | Indicates if Avira Protection Cloud is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_exe_delay | Number | The maximum execution delay for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_file_size | Number | The maximum file size for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.risk_level | Number | The risk level for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.enabled | Boolean | Indicates if on-access scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.mode | String | The mode of on-access scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.enabled | Boolean | Indicates if on-demand scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.profile | String | The profile for on-demand scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_cd_dvd | String | Indicates if on-demand scanning of CD/DVD is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_usb | String | Indicates if on-demand scanning of USB devices is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.range_hours | Number | The range of hours for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.recovery_scan_if_missed | Boolean | Indicates if a recovery scan is scheduled if the previous scan is missed. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.start_hour | Number | The start hour for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.enabled | Boolean | Indicates if signature updates are enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.full_interval_hours | Number | The full interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.initial_random_delay_hours | Number | The initial random delay in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.interval_hours | Number | The interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_offsite_devices | String | The servers used for offsite devices for updates. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.preferred | Boolean | Indicates if the server is preferred for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.server | String | The server used for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_override | Unknown | Indicates if server overrides are enabled for updates. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.file_upload | Boolean | Indicates if file upload is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.path | String | The path for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.protection | Boolean | Indicates if protection is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.is_system | Boolean | Indicates if the policy is a system policy. | 
| CarbonBlackDefense.Policy.policy.org_key | String | The organization key associated with the policy. | 
| CarbonBlackDefense.Policy.policy.position | Number | The position of the policy in the list of policies. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.description | String | A description of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.id | String | The ID of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.inherited_from | String | Indicates the source from which the rapid configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.name | String | The name of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_network_data_collection | Boolean | Indicates if network data collection is enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_auth_events | Boolean | Indicates if authentication events are enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.inline_blocking_mode | String | The inline blocking mode for rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.category | String | The category of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.description | String | A description of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.id | String | The ID of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.inherited_from | String | Indicates the source from which the rule configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rule_configs.name | String | The name of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters | Unknown | The parameters of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.ubs_opt_in | Boolean | Indicates if UBS opt-in is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_prevalent_module_event_collection | Boolean | Indicates if prevalent module event collection is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rules.id | Number | The ID of the rules. | 
| CarbonBlackDefense.Policy.policy.rules.required | Boolean | Indicates if the rules are required. | 
| CarbonBlackDefense.Policy.policy.rules.action | String | The action specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.type | String | The type of application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.value | String | The value of the application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.operation | String | The operation specified in the rules. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.category | String | The category of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.description | String | A description of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.id | String | The ID of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.inherited_from | String | Indicates the source from which the sensor configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.name | String | The name of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.parameters.inline_blocking_mode | String | The inline blocking mode for sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.name | String | The name of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.value | String | The value of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.update_time | Date | The time when the policy was last updated. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The priority level of the policy. | 

### cbd-update-rule-in-policy

***
Updates an existing rule with a new rule. Note: System policies cannot be modified.

#### Base Command

`cbd-update-rule-in-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Rule action. Possible values: "TERMINATE", "IGNORE", "TERMINATE_THREAD", "ALLOW", "DENY", and "TERMINATE_PROCESS". | Required | 
| operation | Rule operation. Possible values: BYPASS_ALL, BYPASS_API, INVOKE_SCRIPT, INVOKE_SYSAPP, POL_INVOKE_NOT_TRUSTED, INVOKE_CMD_INTERPRETER, RANSOM, NETWORK, CODE_INJECTION, PROCESS_ISOLATION, MEMORY_SCRAPE, RUN_INMEMORY_CODE, ESCALATE, RUN. | Required | 
| required | Whether the rule is required. Possible values: true, false. | Required | 
| id | Rule ID. | Required | 
| type | Application type. Possible values: "REPUTATION", "SIGNED_BY", and "NAME_PATH". | Required | 
| value | Application value. Possible values: ADWARE, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, HEURISTIC, IGNORE, KNOWN_MALWARE, LOCAL_WHITE, NOT_LISTED, PUP, RESOLVING, SUSPECT_MALWARE, TRUSTED_WHITE_LIST. | Required | 
| policyId | The policy ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.description | String | A brief summary or description of the policy. | 
| CarbonBlackDefense.Policy.id | Number | The unique policy ID. | 
| CarbonBlackDefense.Policy.name | String | The name of the policy. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vdi_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VDI. | 
| CarbonBlackDefense.Policy.policy.auto_deregister_inactive_vm_workloads_interval_ms | Number | The interval in milliseconds for auto-deregistering inactive VM workloads. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.enabled | Boolean | Indicates if Avira Protection Cloud is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_exe_delay | Number | The maximum execution delay for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.max_file_size | Number | The maximum file size for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.avira_protection_cloud.risk_level | Number | The risk level for Avira Protection Cloud. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.enabled | Boolean | Indicates if on-access scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_access_scan.mode | String | The mode of on-access scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.enabled | Boolean | Indicates if on-demand scanning is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.profile | String | The profile for on-demand scanning. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_cd_dvd | String | Indicates if on-demand scanning of CD/DVD is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.scan_usb | String | Indicates if on-demand scanning of USB devices is enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.range_hours | Number | The range of hours for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.recovery_scan_if_missed | Boolean | Indicates if a recovery scan is scheduled if the previous scan is missed. | 
| CarbonBlackDefense.Policy.policy.av_settings.on_demand_scan.schedule.start_hour | Number | The start hour for the on-demand scan schedule. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.enabled | Boolean | Indicates if signature updates are enabled. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.full_interval_hours | Number | The full interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.initial_random_delay_hours | Number | The initial random delay in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.signature_update.schedule.interval_hours | Number | The interval in hours for signature update scheduling. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_offsite_devices | String | The servers used for offsite devices for updates. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.preferred | Boolean | Indicates if the server is preferred for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_for_onsite_devices.server | String | The server used for onsite devices. | 
| CarbonBlackDefense.Policy.policy.av_settings.update_servers.servers_override | Unknown | Indicates if server overrides are enabled for updates. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.file_upload | Boolean | Indicates if file upload is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.path | String | The path for directory action rules. | 
| CarbonBlackDefense.Policy.policy.directory_action_rules.protection | Boolean | Indicates if protection is enabled for directory action rules. | 
| CarbonBlackDefense.Policy.policy.is_system | Boolean | Indicates if the policy is a system policy. | 
| CarbonBlackDefense.Policy.policy.org_key | String | The organization key associated with the policy. | 
| CarbonBlackDefense.Policy.policy.position | Number | The position of the policy in the list of policies. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.description | String | A description of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.id | String | The ID of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.inherited_from | String | Indicates the source from which the rapid configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.name | String | The name of the rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_network_data_collection | Boolean | Indicates if network data collection is enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.enable_auth_events | Boolean | Indicates if authentication events are enabled in rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rapid_configs.parameters.inline_blocking_mode | String | The inline blocking mode for rapid configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.category | String | The category of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.description | String | A description of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.id | String | The ID of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.inherited_from | String | Indicates the source from which the rule configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.rule_configs.name | String | The name of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters | Unknown | The parameters of the rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.ubs_opt_in | Boolean | Indicates if UBS opt-in is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rule_configs.parameters.enable_prevalent_module_event_collection | Boolean | Indicates if prevalent module event collection is enabled in rule configurations. | 
| CarbonBlackDefense.Policy.policy.rules.id | Number | The ID of the rules. | 
| CarbonBlackDefense.Policy.policy.rules.required | Boolean | Indicates if the rules are required. | 
| CarbonBlackDefense.Policy.policy.rules.action | String | The action specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.type | String | The type of application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.application.value | String | The value of the application specified in the rules. | 
| CarbonBlackDefense.Policy.policy.rules.operation | String | The operation specified in the rules. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.category | String | The category of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.description | String | A description of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.id | String | The ID of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.inherited_from | String | Indicates the source from which the sensor configurations are inherited. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.name | String | The name of the sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_configs.parameters.inline_blocking_mode | String | The inline blocking mode for sensor configurations. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.name | String | The name of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.sensor_settings.value | String | The value of the sensor settings. | 
| CarbonBlackDefense.Policy.policy.update_time | Date | The time when the policy was last updated. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The priority level of the policy. | 

#### Command example
```!cbd-update-rule-in-policy action=IGNORE type=REPUTATION value=COMMON_WHITE_LIST operation=MEMORY_SCRAPE required=true policyId=12345 id=47```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "aaaaaaaa",
            "id": "dummy_id",
            "name": "tesssttsss",
            "policy": {
                "auto_deregister_inactive_vdi_interval_ms": 0,
                "auto_deregister_inactive_vm_workloads_interval_ms": 0,
                "av_settings": {
                    "avira_protection_cloud": {
                        "enabled": false,
                        "max_exe_delay": 45,
                        "max_file_size": 4,
                        "risk_level": 4
                    },
                    "on_access_scan": {
                        "enabled": true,
                        "mode": "NORMAL"
                    },
                    "on_demand_scan": {
                        "enabled": true,
                        "profile": "NORMAL",
                        "scan_cd_dvd": "AUTOSCAN",
                        "scan_usb": "AUTOSCAN",
                        "schedule": {
                            "range_hours": 0,
                            "recovery_scan_if_missed": true,
                            "start_hour": 0
                        }
                    },
                    "signature_update": {
                        "enabled": false,
                        "schedule": {
                            "full_interval_hours": 0,
                            "initial_random_delay_hours": 4,
                            "interval_hours": 2
                        }
                    },
                    "update_servers": {
                        "servers_for_offsite_devices": [
                            "http://updates2.cdc.carbonblack.io/update2"
                        ],
                        "servers_for_onsite_devices": [
                            {
                                "preferred": true,
                                "server": "http://updates2.cdc.carbonblack.io/update2"
                            }
                        ],
                        "servers_override": []
                    }
                },
                "directory_action_rules": [
                    {
                        "file_upload": false,
                        "path": "",
                        "protection": false
                    }
                ],
                "is_system": false,
                "org_key": "dummy_org_key",
                "position": 105,
                "rule_configs": [
                    {
                        "category": "data_collection",
                        "description": "Turns on XDR network data collection at the sensor",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "XDR",
                        "parameters": {
                            "enable_network_data_collection": true
                        }
                    },
                    {
                        "category": "core_prevention",
                        "description": "Addresses common TTPs/behaviors that threat actors use to retain access to systems across restarts, changed credentials, and other interruptions that could cut off their access.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Persistence",
                        "parameters": {
                            "WindowsAssignmentMode": "BLOCK"
                        }
                    },
                    {
                        "category": "bypass",
                        "description": "Allows customers to exclude specific processes and process events from reporting to CBC",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Event Reporting and Sensor Operation Exclusions",
                        "parameters": {}
                    },
                    {
                        "category": "bypass",
                        "description": "Allows customers to exclude specific processes from reporting events to CBC",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Event Reporting Exclusions",
                        "parameters": {}
                    },
                    {
                        "category": "data_collection",
                        "description": "Enterprise EDR Event Collection",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Enterprise EDR Event Collection",
                        "parameters": {
                            "ubs_opt_in": true
                        }
                    },
                    {
                        "category": "data_collection",
                        "description": "Collects events created when a process loads a common library. Enabling this will increase the number of events reported for expected process behavior.",
                        "id": "dummy_id",
                        "inherited_from": "psc:region",
                        "name": "Prevalent Module Exclusions",
                        "parameters": {
                            "enable_prevalent_module_event_collection": false
                        }
                    }
                ],
                "rules": [
                    {
                        "action": "IGNORE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "COMMON_WHITE_LIST"
                        },
                        "id": "dummy_id",
                        "operation": "MEMORY_SCRAPE",
                        "required": true
                    }
                ],
                "sensor_configs": [
                    {
                        "category": "sensor_settings",
                        "description": "Manages sensor settings specific to endpoint standard product",
                        "id": "dummy_id",
                        "inherited_from": "",
                        "name": "Endpoint standard sensor settings at policy scope",
                        "parameters": {
                            "inline_blocking_mode": "disabled"
                        }
                    }
                ],
                "sensor_settings": [
                    {
                        "name": "ALLOW_UNINSTALL",
                        "value": "true"
                    },
                    {
                        "name": "QUEUE_SIZE",
                        "value": "100"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    },
                    {
                        "name": "ALLOW_INLINE_BLOCKING",
                        "value": "true"
                    }
                ],
                "update_time": 1720539019776
            },
            "priorityLevel": "MEDIUM"
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Policy
>|Id|Name|Priority Level|Is System|Description|
>|---|---|---|---|---|
>| 169994 | tesssttsss | MEDIUM | false | aaaaaaaa |


### cbd-delete-rule-from-policy

***
Removes a rule from an existing policy. Note: System policies cannot be modified.

#### Base Command

`cbd-delete-rule-from-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyId | The policy ID. | Required | 
| ruleId | The rule ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!cbd-delete-rule-from-policy ruleId=47 policyId=169994```

#### Human Readable Output

>Rule id 47 was successfully deleted from policy id 169994

### cbd-find-processes

***
Creates a process search job and retrieves the search results. At least one of the arguments (not including: rows, start, and time_range) is required.

#### Base Command

`cbd-find-processes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | When set to "no", the function will not use polling and will return the process job ID. Possible values: yes, no. Default is yes. | Optional | 
| job_id | The unique process search job ID. This ID is used to retrieve the results of the process search initiated by the Carbon Black Cloud. If not provided, a new search job will be created based on the other provided arguments. | Optional | 
| alert_category | The Carbon Black Cloud classification for events tagged to an alert. Possible values: "THREAT" and "OBSERVED". | Optional | 
| device_external_ip | The IP address of the endpoint according to Carbon Black Cloud. This IP address can differ from the device_internal_ip due to network proxy or NAT. Can be either IPv4 or IPv6 format. | Optional | 
| device_id | The ID assigned to the endpoint by Carbon Black Cloud. This ID is unique across all Carbon Black Cloud environments. | Optional | 
| device_internal_ip | The IP address of the endpoint reported by the sensor. Can be either IPv4 or IPv6 format. | Optional | 
| device_name | The hostname of the endpoint recorded by the sensor when last initialized. | Optional | 
| device_os | The operating system of the endpoint. Possible values: "WINDOWS", "MAC", "LINUX". | Optional | 
| device_timestamp | The sensor-reported timestamp of the batch of events in which this record was submitted to Carbon Black Cloud. specified as ISO 8601 timestamp in UTC for example: 2020-01-19T04:28:40.190Z. | Optional | 
| event_type | The type of enriched event observed. Possible value: "filemod", "netconn", "regmod", "modload", "crossproc", "childproc", "scriptload", and "fileless_scriptload". Possible values : filemod, netconn, regmod, modload, crossproc, childproc, scriptload, fileless_scriptload. | Optional | 
| parent_name | The file system path of the parent process binary. | Optional | 
| parent_reputation | The reputation of the parent process applied by Carbon Black Cloud when the event is initially processed. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". | Optional | 
| process_cmdline | The command line executed by the actor process. | Optional | 
| process_guid | The unique process ID for the the actor process. | Optional | 
| hash | Aggregate set of MD5 and SHA-256 hashes associated with the process (including childproc_hash, crossproc_hash, filemod_hash, modload_hash, process_hash). | Optional | 
| process_name | The file system path of the actor process binary. | Optional | 
| process_pid | The process ID assigned by the operating system. This can be multi-valued for fork() or exec() process operations on Linux and macOS. | Optional | 
| process_reputation | The reputation of the actor process applied when the event is processed by Carbon Black Cloud. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". | Optional | 
| process_start_time | The sensor reported timestamp of when the process started. specified as ISO 8601 timestamp in UTC for example: 2020-05-04T21:34:03.968Z. This is not available for processes running before the sensor starts. | Optional | 
| process_terminated | Whether the process has terminated. Always "false" for enriched events (process termination not recorded). Possible values: true, false. | Optional | 
| process_username | The user context in which the actor process was executed.<br/>MacOS - all users for the PID for fork() and exec() transitions.<br/>Linux - process user for exec() events, but in a future sensor release can be multi-valued due to setuid(). | Optional | 
| sensor_action | The action performed by the sensor on the process. Possible values: "TERMINATE", "DENY", and "SUSPEND". | Optional | 
| query | The query in Lucene syntax and/or value searches. | Optional | 
| rows | The number of rows to request. | Optional | 
| start | The first row to use for pagination. | Optional | 
| time_range | The time window in which to restrict the search to match using device_timestamp as the reference. The window value will take priority over the start and end times if provided. For example {"end": "2020-01-21T18:34:04Z", "start": "2020-01-18T18:34:04Z", "window": "-2w"}, window: “-2w” (where y=year, w=week, d=day, h=hour, m=minute, s=second) start: ISO 8601 timestamp, end: ISO 8601 timestamp. | Optional | 
| interval_in_seconds | Used for polling. | Optional | 
| time_out | Used for polling. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Process.job_id | String | The process job id when polling set to false. | 
| CarbonBlackDefense.Process.Results.backend_timestamp | Date | The timestamp when the process data was collected from the backend. | 
| CarbonBlackDefense.Process.Results.childproc_count | Number | The number of child processes spawned by the process. | 
| CarbonBlackDefense.Process.Results.crossproc_count | Number | The number of cross-process interactions involving the process. | 
| CarbonBlackDefense.Process.Results.device_id | Number | The unique ID of the device where the process is running. | 
| CarbonBlackDefense.Process.Results.device_name | String | The name of the device where the process is running. | 
| CarbonBlackDefense.Process.Results.device_policy_id | Number | The policy ID associated with the device. | 
| CarbonBlackDefense.Process.Results.device_timestamp | Date | The timestamp when the process data was collected from the device. | 
| CarbonBlackDefense.Process.Results.filemod_count | Number | The number of file modifications made by the process. | 
| CarbonBlackDefense.Process.Results.index_class | String | The classification of the process based on indexing. | 
| CarbonBlackDefense.Process.Results.modload_count | Number | The number of modules loaded by the process. | 
| CarbonBlackDefense.Process.Results.netconn_count | Number | The number of network connections established by the process. | 
| CarbonBlackDefense.Process.Results.org_id | String | The organization ID associated with the process. | 
| CarbonBlackDefense.Process.Results.parent_guid | String | The GUID of the parent process. | 
| CarbonBlackDefense.Process.Results.parent_pid | Number | The PID of the parent process. | 
| CarbonBlackDefense.Process.Results.partition_id | Number | The partition ID associated with the process. | 
| CarbonBlackDefense.Process.Results.process_guid | String | The GUID of the process. | 
| CarbonBlackDefense.Process.Results.process_hash | String | The hash of the process. | 
| CarbonBlackDefense.Process.Results.process_name | String | The name of the process. | 
| CarbonBlackDefense.Process.Results.process_pid | Number | The PID of the process. | 
| CarbonBlackDefense.Process.Results.process_username | String | The username under which the process is running. | 
| CarbonBlackDefense.Process.Results.regmod_count | Number | The number of registry modifications made by the process. | 
| CarbonBlackDefense.Process.Results.scriptload_count | Number | The number of scripts loaded by the process. | 

#### Command example
```!cbd-find-processes device_id=5217044```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Process": {
            "Results": [
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "49becb5d-8cca-4b39-b7f4-d94401533dab",
                        "6038e242-2c44-470c-92e3-bf3a0c32dc26",
                        "a7056445-388b-46d8-9d8e-3885bfe28fc0"
                    ],
                    "backend_timestamp": "2024-07-11T14:51:29.069Z",
                    "childproc_count": 1,
                    "crossproc_count": 7,
                    "device_group_id": 0,
                    "device_id": 12345,
                    "device_name": "r7betalab\\r7betalab-arw04",
                    "device_policy_id": 80947,
                    "device_timestamp": "2024-07-11T14:44:11.754Z",
                    "filemod_count": 11,
                    "ingress_time": 1720709467661,
                    "modload_count": 40,
                    "netconn_count": 0,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "dummy_parent_guid",
                    "parent_pid": 4380,
                    "process_guid": "dummy_process_guid",
                    "process_hash": [
                        "dummy_process_hash",
                    ],
                    "process_name": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                    "process_pid": [
                        2192
                    ],
                    "process_username": [
                        "R7BETALAB\\svc_idr"
                    ],
                    "regmod_count": 4,
                    "scriptload_count": 1,
                    "watchlist_hit": []
                },
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "dummy_alert_id"
                    ],
                    "backend_timestamp": "2024-07-11T14:34:13.616Z",
                    "childproc_count": 0,
                    "crossproc_count": 0,
                    "device_group_id": 0,
                    "device_id": 12345,
                    "device_name": "cb-markotest",
                    "device_policy_id": 6525,
                    "device_timestamp": "2024-07-11T14:30:39.203Z",
                    "filemod_count": 0,
                    "ingress_time": 1720708414089,
                    "modload_count": 0,
                    "netconn_count": 1,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "dummy_parent_guid",
                    "parent_pid": 688,
                    "process_guid": "dummy_process_guid",
                    "process_hash": [],
                    "process_name": "c:\\windows\\system32\\svchost.exe",
                    "process_pid": [
                        2264
                    ],
                    "process_username": [
                        "NT AUTHORITY\\NETWORK SERVICE"
                    ],
                    "regmod_count": 0,
                    "scriptload_count": 0,
                    "watchlist_hit": [
                        "abcd123"
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### The Results For The Process Search
>|Device Id|Device Name|Process Name|Device Policy Id|
>|---|---|---|---|
>| 1234 | r7betalab\r7betalab-arw04 | c:\windows\system32\windowspowershell\v1.0\powershell.exe | 80947 |
>| 1111 | cb-markotest | c:\windows\system32\svchost.exe | 6525 |

### cbd-find-observation-details

***
Fetches Carbon Black events details based on specified parameters. Supports polling to wait for the search job completion.

#### Base Command

`cbd-find-observation-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | When set to false, the function will not use polling and will return the process job ID. Possible values: yes, no. Default is True. | Optional | 
| job_id | The ID of the job to retrieve the details. This is used internally for polling. | Optional | 
| alert_id | The ID of the alert to retrieve the observation details. Must be specified alone. | Optional | 
| observation_ids | A list of observation IDs to retrieve the details. Must be specified alone. | Optional | 
| process_hash | The hash of the process to search for. Can be combined with rows, and with device_id or count_unique_devices, but not both. | Optional | 
| device_id | The ID of the device to filter the observations. Must be combined with process_hash. Cannot be combined with alert_id, observation_ids, count_unique_devices. | Optional | 
| count_unique_devices | A boolean indicating whether to count unique devices executing the process hash. Must be combined with process_hash. Cannot be combined with alert_id, observation_ids, device_id. | Optional | 
| rows | The maximum number of rows to return, up to 10,000. Can only be combined with process_hash. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.EventDetails.job_id | String | The process job id when polling set to false. | 
| CarbonBlackDefense.EventDetails.Results.alert_category | String | The category of the alert associated with the observation. | 
| CarbonBlackDefense.EventDetails.Results.alert_id | String | The unique ID of the alert associated with the observation. | 
| CarbonBlackDefense.EventDetails.Results.backend_timestamp | Date | The timestamp when the observation data was collected from the backend. | 
| CarbonBlackDefense.EventDetails.Results.childproc_count | Number | The number of child processes spawned by the observed process. | 
| CarbonBlackDefense.EventDetails.Results.crossproc_count | Number | The number of cross-process interactions involving the observed process. | 
| CarbonBlackDefense.EventDetails.Results.device_external_ip | String | The external IP address of the device where the observation was made. | 
| CarbonBlackDefense.EventDetails.Results.device_group_id | Number | The group ID associated with the device. | 
| CarbonBlackDefense.EventDetails.Results.device_id | Number | The unique ID of the device where the observation was made. | 
| CarbonBlackDefense.EventDetails.Results.device_installed_by | String | The user or process that installed the device. | 
| CarbonBlackDefense.EventDetails.Results.device_internal_ip | String | The internal IP address of the device where the observation was made. | 
| CarbonBlackDefense.EventDetails.Results.device_location | String | The physical or network location of the device. | 
| CarbonBlackDefense.EventDetails.Results.device_name | String | The name of the device where the observation was made. | 
| CarbonBlackDefense.EventDetails.Results.device_os | String | The operating system of the device. | 
| CarbonBlackDefense.EventDetails.Results.device_os_version | String | The version of the operating system of the device. | 
| CarbonBlackDefense.EventDetails.Results.device_policy | String | The policy applied to the device. | 
| CarbonBlackDefense.EventDetails.Results.device_policy_id | Number | The unique ID of the policy applied to the device. | 
| CarbonBlackDefense.EventDetails.Results.device_sensor_version | String | The version of the sensor installed on the device. | 
| CarbonBlackDefense.EventDetails.Results.device_target_priority | String | The priority level of the device as a target. | 
| CarbonBlackDefense.EventDetails.Results.device_timestamp | Date | The timestamp when the observation was recorded on the device. | 
| CarbonBlackDefense.EventDetails.Results.document_guid | String | The GUID of the document associated with the observation. | 
| CarbonBlackDefense.EventDetails.Results.enriched | Boolean | Indicates whether the observation data has been enriched with additional information. | 
| CarbonBlackDefense.EventDetails.Results.enriched_event_type | String | The type of event after enrichment. | 
| CarbonBlackDefense.EventDetails.Results.event_threat_score | Number | The threat score associated with the event. | 
| CarbonBlackDefense.EventDetails.Results.filemod_count | Number | The number of file modifications made by the observed process. | 
| CarbonBlackDefense.EventDetails.Results.ingress_time | Date | The time when the observation data was ingested into the system. | 
| CarbonBlackDefense.EventDetails.Results.legacy | Boolean | Indicates whether the observation is from a legacy system or data source. | 
| CarbonBlackDefense.EventDetails.Results.modload_count | Number | The number of modules loaded by the observed process. | 
| CarbonBlackDefense.EventDetails.Results.netconn_count | Number | The number of network connections established by the observed process. | 
| CarbonBlackDefense.EventDetails.Results.observation_description | String | A description of the observation. | 
| CarbonBlackDefense.EventDetails.Results.observation_id | String | The unique observation ID. | 
| CarbonBlackDefense.EventDetails.Results.observation_type | String | The type of observation. | 
| CarbonBlackDefense.EventDetails.Results.org_id | String | The organization ID associated with the observation. | 
| CarbonBlackDefense.EventDetails.Results.parent_cmdline | String | The command line arguments of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_cmdline_length | Number | The length of the command line arguments of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_effective_reputation | String | The effective reputation of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_effective_reputation_source | String | The source of the effective reputation of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_guid | String | The GUID of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_hash | String | The hash of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_name | String | The name of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_pid | Number | The PID of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_publisher | String | The publisher of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_publisher_state | String | The state of the publisher of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_reputation | String | The reputation of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.process_cmdline | String | The command line arguments of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_cmdline_length | Number | The length of the command line arguments of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_company_name | String | The company name associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_effective_reputation | String | The effective reputation of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_effective_reputation_source | String | The source of the effective reputation of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_elevated | Boolean | Indicates whether the observed process is running with elevated privileges. | 
| CarbonBlackDefense.EventDetails.Results.process_file_description | String | The description of the observed process file. | 
| CarbonBlackDefense.EventDetails.Results.process_guid | String | The GUID of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_hash | String | The hash of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_integrity_level | String | The integrity level of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_internal_name | String | The internal name of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_name | String | The name of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_original_filename | String | The original filename of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_pid | Number | The PID of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_privileges | String | The privileges associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_product_name | String | The product name associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_product_version | String | The product version associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_publisher | String | The publisher of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_publisher_state | String | The state of the publisher of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_reputation | String | The reputation of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_service_name | String | The service name associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_sha256 | unknown | The SHA-256 hash. | 

#### Command example
```!cbd-find-observation-details process_hash=abc1234```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "EventDetails": {
            "Results": {
                "alert_category": [
                    "THREAT"
                ],
                "alert_id": [
                    "dummy_alert_id"
                ],
                "backend_timestamp": "2024-04-17T01:52:29.056Z",
                "blocked_effective_reputation": "TRUSTED_WHITE_LIST",
                "blocked_hash": [
                    "dummy_blocked_hash"
                ],
                "blocked_name": "c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                "childproc_cmdline": "\"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe\" (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow() ",
                "childproc_cmdline_length": 124,
                "childproc_effective_reputation": "TRUSTED_WHITE_LIST",
                "childproc_effective_reputation_source": "CLOUD",
                "childproc_guid": "dummy_childproc_guid",
                "childproc_hash": [
                    "dummy_chidproc_hash"
                ],
                "childproc_issuer": [
                    "Microsoft Windows Production PCA 2011"
                ],
                "childproc_name": "c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                "childproc_pid": 1020,
                "childproc_publisher": [
                    "Microsoft Windows"
                ],
                "childproc_publisher_state": [
                    "FILE_SIGNATURE_STATE_VERIFIED",
                    "FILE_SIGNATURE_STATE_SIGNED"
                ],
                "childproc_reputation": "TRUSTED_WHITE_LIST",
                "childproc_username": "NT AUTHORITY\SYSTEM",
                "device_external_ip": "1.1.1.1",
                "device_group_id": 0,
                "device_id": 12345,
                "device_installed_by": "user@example.com",
                "device_internal_ip": "1.1.1.1",
                "device_location": "OFFSITE",
                "device_name": "corp\wsamzn-lshqdrdc",
                "device_os": "WINDOWS",
                "device_os_version": "Windows Server 2019 x64",
                "device_policy": "tines-policy",
                "device_policy_id": 1234,
                "device_sensor_version": "1.1.1.1",
                "device_target_priority": "LOW",
                "device_timestamp": "2024-04-17T01:50:54.057Z",
                "document_guid": "dummy_document_guid",
                "enriched": true,
                "enriched_event_type": "CREATE_PROCESS",
                "event_attack_stage": [
                    "INSTALL_RUN"
                ],
                "event_description": "The script \"<share><link hash=\"dummy_hash\">C:\program files\amazon\skylight\scripts\windows_update_status.ps1</link></share>\" invoked the application \"<share><link hash=\"dummy_hash\">C:\windows\system32\windowspowershell\v1.0\powershell.exe</link></share>\". The operation was <accent>blocked</accent> and the application <accent>terminated by Carbon Black</accent>.",
                "event_id": "dummy_event_id",
                "event_type": "childproc",
                "ingress_time": 1713318735609,
                "legacy": true,
                "observation_description": "The application windows_update_status.ps1 invoked another application (powershell.exe). A Deny Policy Action was applied.",
                "observation_id": "dummy_observation_id",
                "observation_type": "CB_ANALYTICS",
                "org_id": "abc123",
                "parent_effective_reputation": "LOCAL_WHITE",
                "parent_effective_reputation_source": "PRE_EXISTING",
                "parent_guid": "dummy_parent_guid",
                "parent_hash": [
                    "dummy_parent_hash"
                ],
                "parent_name": "c:\program files\amazon\skylight\skylightworkspaceconfigservice.exe",
                "parent_pid": 1234,
                "parent_reputation": "NOT_LISTED",
                "parent_username": "NT AUTHORITY\SYSTEM",
                "process_cmdline": [
                    "\"powershell.exe\" -NonInteractive -ExecutionPolicy AllSigned -File \"C:\Program files\Amazon\SkyLight\scripts\windows_update_status.ps1\" -scriptId windows_update_status.ps1 CheckStatus"
                ],
                "process_cmdline_length": [
                    182
                ],
                "process_effective_reputation": "ADAPTIVE_WHITE_LIST",
                "process_effective_reputation_source": "CLOUD",
                "process_guid": "dummy_process_guid",
                "process_hash": [
                    "dummy_process_hash",
                ],
                "process_loaded_script_hash": [
                    "dummy_process_loaded_script_hash"
                ],
                "process_loaded_script_name": [
                    "c:\program files\amazon\skylight\scripts\windows_update_status.ps1"
                ],
                "process_name": "c:\program files\amazon\skylight\scripts\windows_update_status.ps1",
                "process_pid": [
                    1234
                ],
                "process_reputation": "NOT_LISTED",
                "process_sha256": "dummy_process_sha256",
                "process_start_time": "2024-04-17T01:50:48.244Z",
                "process_user_id": "S-1-5-18",
                "process_username": [
                    "NT AUTHORITY\SYSTEM"
                ],
                "sensor_action": [
                    "TERMINATE"
                ],
                "ttp": [
                    "MITRE_T1059_CMD_LINE_OR_SCRIPT_INTER",
                    "POLICY_DENY",
                    "MITRE_T1059_001_POWERSHELL"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Defense Event Details Results
>|Observation Id|Event Id|Device Id|Device External Ip|Device Internal Ip|Enriched Event Type|
>|---|---|---|---|---|---|
>| dummy_observation_id | dummy_event_id | 1234 | 1.1.1.1 | 1.1.1.1 | CREATE_PROCESS |


### cbd-find-observation

***
Fetches Carbon Black events details based on specified parameters. Supports polling to wait for the search job completion.

#### Base Command

`cbd-find-observation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | When set to false, the function will not use polling and will return the process job ID. Possible values are: yes, no. Default is True. | Optional | 
| job_id | The ID of the job to retrieve the observation. This is used internally for polling. | Optional | 
| alert_category | The Carbon Black Cloud classification for events tagged to an alert. Possible values: "THREAT" and "OBSERVED". | Optional | 
| device_external_ip | The IP address of the endpoint according to Carbon Black Cloud. This IP address can differ from the device_internal_ip due to network proxy or NAT. Can be either IPv4 or IPv6 format. | Optional | 
| device_id | The ID assigned to the endpoint by Carbon Black Cloud. This ID is unique across all Carbon Black Cloud environments. | Optional | 
| device_internal_ip | The IP address of the endpoint reported by the sensor. Can be either IPv4 or IPv6 format. | Optional | 
| device_name | The hostname of the endpoint recorded by the sensor when last initialized. | Optional | 
| device_os | The operating system of the endpoint. Possible values: "WINDOWS", "MAC", "LINUX". | Optional | 
| device_timestamp | The sensor-reported timestamp of the batch of events in which this record was submitted to Carbon Black Cloud. specified as ISO 8601 timestamp in UTC for example: 2020-01-19T04:28:40.190Z. | Optional | 
| event_type | The type of enriched event observed. Possible value: "filemod", "netconn", "regmod", "modload", "crossproc", "childproc", "scriptload", and "fileless_scriptload". Possible values: filemod, netconn, regmod, modload, crossproc, childproc, scriptload, fileless_scriptload. | Optional | 
| parent_name | The file system path of the parent process binary. | Optional | 
| parent_reputation | The reputation of the parent process applied by Carbon Black Cloud when the event is initially processed. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". | Optional | 
| process_cmdline | The command line executed by the actor process. | Optional | 
| process_guid | The unique process ID for the actor process. | Optional | 
| hash | Aggregate set of MD5 and SHA-256 hashes associated with the process (including childproc_hash, crossproc_hash, filemod_hash, modload_hash, process_hash). | Optional | 
| process_name | The file system path of the actor process binary. | Optional | 
| process_pid | The process ID assigned by the operating system. This can be multi-valued for fork() or exec() process operations on Linux and macOS. | Optional | 
| process_reputation | The reputation of the actor process applied when the event is processed by Carbon Black Cloud. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". | Optional | 
| process_start_time | The sensor reported timestamp of when the process started. specified as ISO 8601 timestamp in UTC for example: 2020-05-04T21:34:03.968Z. This is not available for processes running before the sensor starts. | Optional | 
| process_terminated | Whether the process has terminated. Possible values: "true" and "false". Always "false" for enriched events (process termination not recorded). | Optional | 
| process_username | The user context in which the actor process was executed.<br/>MacOS - all users for the PID for fork() and exec() transitions.<br/>Linux - process user for exec() events, but in a future sensor release can be multi-valued due to setuid(). | Optional | 
| sensor_action | The action performed by the sensor on the process. Possible values: "TERMINATE", "DENY", and "SUSPEND". | Optional | 
| query | The query in Lucene syntax and/or value searches. | Optional | 
| rows | The number of rows to request. | Optional | 
| start | The first row to use for pagination. | Optional | 
| time_range | The time window in which to restrict the search to match using device_timestamp as the reference. The window value will take priority over the start and end times if provided. For example {"end": "2020-01-21T18:34:04Z", "start": "2020-01-18T18:34:04Z", "window": "-2w"}, window: “-2w” (where y=year, w=week, d=day, h=hour, m=minute, s=second) start: ISO 8601 timestamp, end: ISO 8601 timestamp. | Optional | 
| interval_in_seconds | Used for polling. | Optional | 
| time_out | Used for polling. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Events.job_id | String | The process job id when polling set to false. | 
| CarbonBlackDefense.Events.Results.alert_category | String | Category of the alert associated with the event. | 
| CarbonBlackDefense.Events.Results.alert_id | String | The unique alert ID. | 
| CarbonBlackDefense.Events.Results.backend_timestamp | Date | Timestamp when the event was processed on the backend. | 
| CarbonBlackDefense.Events.Results.childproc_count | Number | Number of child processes spawned by the process. | 
| CarbonBlackDefense.Events.Results.crossproc_count | Number | Number of cross-process operations performed by the process. | 
| CarbonBlackDefense.Events.Results.device_external_ip | String | External IP address of the device. | 
| CarbonBlackDefense.Events.Results.device_group_id | Number | The device group ID. | 
| CarbonBlackDefense.Events.Results.device_id | Number | The unique device ID. | 
| CarbonBlackDefense.Events.Results.device_installed_by | String | User or entity that installed the device. | 
| CarbonBlackDefense.Events.Results.device_internal_ip | String | Internal IP address of the device. | 
| CarbonBlackDefense.Events.Results.device_location | String | Physical or network location of the device. | 
| CarbonBlackDefense.Events.Results.device_name | String | Name of the device. | 
| CarbonBlackDefense.Events.Results.device_os | String | Operating system running on the device. | 
| CarbonBlackDefense.Events.Results.device_os_version | String | Version of the operating system running on the device. | 
| CarbonBlackDefense.Events.Results.device_policy | String | Security policy applied to the device. | 
| CarbonBlackDefense.Events.Results.device_policy_id | Number | The the security policy ID applied to the device. | 
| CarbonBlackDefense.Events.Results.device_sensor_version | String | Version of the sensor installed on the device. | 
| CarbonBlackDefense.Events.Results.device_target_priority | String | Priority of the device as a target. | 
| CarbonBlackDefense.Events.Results.device_timestamp | Date | Timestamp of the event as recorded by the device. | 
| CarbonBlackDefense.Events.Results.document_guid | String | The global unique ID for the document associated with the event. | 
| CarbonBlackDefense.Events.Results.enriched | Boolean | Indicates whether the event data has been enriched. | 
| CarbonBlackDefense.Events.Results.enriched_event_type | String | Type of the enriched event. | 
| CarbonBlackDefense.Events.Results.event_threat_score | Number | Threat score assigned to the event. | 
| CarbonBlackDefense.Events.Results.filemod_count | Number | Number of file modifications performed by the process. | 
| CarbonBlackDefense.Events.Results.ingress_time | Date | Time when the event was ingested by the system. | 
| CarbonBlackDefense.Events.Results.legacy | Boolean | Indicates whether the event is considered a legacy event. | 
| CarbonBlackDefense.Events.Results.modload_count | Number | Number of modules loaded by the process. | 
| CarbonBlackDefense.Events.Results.netconn_count | Number | Number of network connections established by the process. | 
| CarbonBlackDefense.Events.Results.observation_description | String | Description of the observation associated with the event. | 
| CarbonBlackDefense.Events.Results.observation_id | String | The unique observation ID. | 
| CarbonBlackDefense.Events.Results.observation_type | String | Type of the observation associated with the event. | 
| CarbonBlackDefense.Events.Results.org_id | String | The organization ID associated with the event. | 
| CarbonBlackDefense.Events.Results.parent_cmdline | String | Command line used to execute the parent process. | 
| CarbonBlackDefense.Events.Results.parent_cmdline_length | Number | Length of the command line used to execute the parent process. | 
| CarbonBlackDefense.Events.Results.parent_effective_reputation | String | Effective reputation of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_effective_reputation_source | String | Source of the effective reputation of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_guid | String | The global unique ID for the parent process. | 
| CarbonBlackDefense.Events.Results.parent_hash | String | Hash of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_name | String | Name of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_pid | Number | The parent process ID. | 
| CarbonBlackDefense.Events.Results.parent_publisher | String | Publisher of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_publisher_state | String | Publisher state of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_reputation | String | Reputation of the parent process. | 
| CarbonBlackDefense.Events.Results.process_cmdline | String | Command line used to execute the process. | 
| CarbonBlackDefense.Events.Results.process_cmdline_length | Number | Length of the command line used to execute the process. | 
| CarbonBlackDefense.Events.Results.process_company_name | String | Company name associated with the process. | 
| CarbonBlackDefense.Events.Results.process_effective_reputation | String | Effective reputation of the process. | 
| CarbonBlackDefense.Events.Results.process_effective_reputation_source | String | Source of the effective reputation of the process. | 
| CarbonBlackDefense.Events.Results.process_elevated | Boolean | Indicates whether the process is running with elevated privileges. | 
| CarbonBlackDefense.Events.Results.process_file_description | String | File description of the process. | 
| CarbonBlackDefense.Events.Results.process_guid | String | The global unique process ID. | 
| CarbonBlackDefense.Events.Results.process_hash | String | Hash of the process. | 
| CarbonBlackDefense.Events.Results.process_integrity_level | String | Integrity level of the process. | 
| CarbonBlackDefense.Events.Results.process_internal_name | String | Internal name of the process. | 
| CarbonBlackDefense.Events.Results.process_name | String | Name of the process. | 
| CarbonBlackDefense.Events.Results.process_original_filename | String | Original filename of the process. | 
| CarbonBlackDefense.Events.Results.process_pid | Number | The process ID of the process. | 
| CarbonBlackDefense.Events.Results.process_privileges | String | Privileges associated with the process. | 
| CarbonBlackDefense.Events.Results.process_product_name | String | Product name associated with the process. | 
| CarbonBlackDefense.Events.Results.process_product_version | String | Product version associated with the process. | 
| CarbonBlackDefense.Events.Results.process_publisher | String | Publisher of the process. | 
| CarbonBlackDefense.Events.Results.process_publisher_state | String | Publisher state of the process. | 
| CarbonBlackDefense.Events.Results.process_reputation | String | Reputation of the process. | 
| CarbonBlackDefense.Events.Results.process_service_name | String | Service name associated with the process. | 
| CarbonBlackDefense.Events.Results.process_sha256 | String | SHA-256 hash of the process. | 
| CarbonBlackDefense.Events.Results.process_start_time | Date | Start time of the process. | 
| CarbonBlackDefense.Events.Results.process_username | String | Username under which the process is running. | 
| CarbonBlackDefense.Events.Results.regmod_count | Number | Number of registry modifications performed by the process. | 
| CarbonBlackDefense.Events.Results.scriptload_count | Number | Number of scripts loaded by the process. | 
| CarbonBlackDefense.Events.Results.sensor_action | String | Action taken by the sensor for the event. | 
| CarbonBlackDefense.Events.Results.ttp | String | Tactics, techniques, and procedures associated with the event. | 
| CarbonBlackDefense.Events.Results.watchlist_hit | String | Indicates if the event matches a watchlist entry. | 

#### Command example
```!cbd-find-observation device_id=12345```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Events": {
            "Results": [
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "dummy_alert_id"
                    ],
                    "backend_timestamp": "2024-07-05T09:42:06.625Z",
                    "blocked_effective_reputation": "COMPANY_BLACK_LIST",
                    "blocked_hash": [
                        "dummy_bloched_hash"
                    ],
                    "blocked_name": "c:\windows\system32\sdiagnhost.exe",
                    "device_group_id": 0,
                    "device_id": 1234,
                    "device_name": "desktop-ua4omu0",
                    "device_policy_id": 1234,
                    "device_timestamp": "2024-07-05T09:39:07.695Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "CREATE_PROCESS"
                    ],
                    "event_description": "The application \"<share><link hash=\"add683a6910abbbf0e28b557fad0ba998166394932ae2aca069d9aa19ea8fe88\">C:\Windows\system32\svchost.exe -k DcomLaunch -p</link></share>\" invoked the application \"<share><link hash=\"e5ec6b5b20a16383cc953ad5e478dcdf95ba46281f4fe971673c954d4145c0c4\">c:\windows\system32\sdiagnhost.exe</link></share>\". The operation was <accent>blocked by Carbon Black</accent>.",
                    "event_id": "dummy_event_id",
                    "event_type": "childproc",
                    "ingress_time": 1720172480035,
                    "legacy": true,
                    "observation_description": " sdiagnhost.exe on the Company Black List was detected running. A Deny Policy Action was applied.",
                    "observation_id": "dummy_observation_id",
                    "observation_type": "CB_ANALYTICS",
                    "org_id": "dummy_org_id",
                    "parent_guid": "dummy_parent_guid",
                    "parent_pid": 616,
                    "process_guid": "dummy_process_guid",
                    "process_hash": [
                        "dummy_process_gash",
                        "dummy_process_hash"
                    ],
                    "process_name": "c:\windows\system32\svchost.exe",
                    "process_pid": [
                        768
                    ],
                    "process_username": [
                        "NT AUTHORITY\SYSTEM"
                    ],
                    "sensor_action": [
                        "DENY",
                        "BLOCK"
                    ]
                },
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "dummy_alert_id"
                    ],
                    "backend_timestamp": "2024-07-03T16:27:53.810Z",
                    "blocked_effective_reputation": "COMPANY_BLACK_LIST",
                    "blocked_hash": [
                        "dummy_blocked_hash"
                    ],
                    "blocked_name": "c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                    "device_group_id": 0,
                    "device_id": 1234,
                    "device_name": "desktop-ua4omu0",
                    "device_policy_id": 1234,
                    "device_timestamp": "2024-07-03T16:25:21.686Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "CREATE_PROCESS"
                    ],
                    "event_description": "The application \"<share><link hash=\"20330d3ca71d58f4aeb432676cb6a3d5b97005954e45132fb083e90782efdd50\">c:\windows\system32\backgroundtaskhost.exe</link></share>\" was prevented from accessing the file \"<share><link hash=\"9f914d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccd9f\">c:\windows\system32\windowspowershell\v1.0\powershell.exe</link></share>\" due to a <accent>Deny operation or Terminate process</accent> policy action.",
                    "event_id": "dummy_event_id",
                    "event_type": "childproc",
                    "ingress_time": 1720024053609,
                    "legacy": true,
                    "observation_description": "The application backgroundtaskhost.exe invoked another application (powershell.exe). A Deny Policy Action was applied.",
                    "observation_id": "f82a46c4395811efab18238ba409ec8f:d13802a2-e8a1-180d-8359-fdc0a8c9f007",
                    "observation_type": "CB_ANALYTICS",
                    "org_id": "dummy_org_id",
                    "parent_guid": "dummy_parent_guid",
                    "parent_pid": 768,
                    "process_guid": "dummy_process_guid",
                    "process_hash": [
                        "dummy_process_hash",
                        "dummy_process_hash"
                    ],
                    "process_name": "c:\windows\system32\backgroundtaskhost.exe",
                    "process_pid": [
                        1234
                    ],
                    "process_username": [
                        "DESKTOP-UA4OMU0\qe-admin"
                    ],
                    "sensor_action": [
                        "DENY",
                        "BLOCK"
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Defense Event Results
>|Event Id|Device Id|Enriched Event Type|
>|---|---|---|
>| 8d815dc93ab211efb74fe9e3b00b3b6a | 6685063 | CREATE_PROCESS |
>| f82a46c4395811efab18238ba409ec8f | 6685063 | CREATE_PROCESS |


### cbd-device-search

***
Searches devices in your organization.

#### Base Command

`cbd-device-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. | Optional | 
| os | The operating system. Possible values: "WINDOWS", "MAC", "LINUX", and "OTHER". | Optional | 
| status | The status of the device. Possible values: "PENDING", "REGISTERED", "DEREGISTERED", "BYPASS", "ACTIVE", "INACTIVE", "ERROR", "ALL", "BYPASS_ON", "LIVE", "SENSOR_PENDING_UPDATE". | Optional | 
| start_time | The time to start getting results. specified as ISO-8601 strings for example: "2021-01-27T12:43:26.243Z". | Optional | 
| target_priority | The “Target value” configured in the policy assigned to the sensor. Possible values: "LOW", "MEDIUM", "HIGH", "MISSION_CRITICAL". | Optional | 
| query | The query in Lucene syntax and/or value searches. | Optional | 
| end_time | The time to stop getting results. specified as ISO-8601 strings for example: "2021-02-27T12:43:26.243Z". | Optional | 
| rows | The maximum number of rows to return. Default is 20. Default is 20. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Device.activation_code | String | The device activation code to register the sensor with a specific organization. | 
| CarbonBlackDefense.Device.activation_code_expiry_time | Date | The time when the activation code expires and cannot be used to register a device. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.ad_group_id | Number | The Active Directory group ID to match. | 
| CarbonBlackDefense.Device.appliance_name | String | The name of the appliance the Virtual Machine \(VM\) is associated with. | 
| CarbonBlackDefense.Device.appliance_uuid | String | The UUID of the appliance the VM is associated with. | 
| CarbonBlackDefense.Device.av_ave_version | String | The AVE version \(part of AV Version\). | 
| CarbonBlackDefense.Device.av_engine | String | The current antivirus \(AV\) version. | 
| CarbonBlackDefense.Device.av_last_scan_time | Date | The last time a local scan completed. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.av_master | Boolean | Whether the device is an AV Master. | 
| CarbonBlackDefense.Device.av_pack_version | String | The pack version \(part of AV version\). | 
| CarbonBlackDefense.Device.av_product_version | String | The product version \(part of AV version\). | 
| CarbonBlackDefense.Device.av_status | String | The status of the local scan. For example \[ "AV_ACTIVE", "AV_REGISTERED" \]. \(AV_NOT_REGISTERED, AV_REGISTERED, AV_DEREGISTERED, AV_ACTIVE, AV_BYPASS, SIGNATURE_UPDATE_DISABLED, ONACCESS_SCAN_DISABLED, ONDEMAND_SCAN_DISABLED, PRODUCT_UPDATE_DISABLED\). | 
| CarbonBlackDefense.Device.av_update_servers | Unknown | A list of the device’s AV servers. For example \[ "string", "string" \]. | 
| CarbonBlackDefense.Device.av_vdf_version | String | VDF version \(part of AV version\). | 
| CarbonBlackDefense.Device.cluster_name | String | Name of the cluster. A cluster is a group of hosts. | 
| CarbonBlackDefense.Device.current_sensor_policy_name | String | The name of the policy currently configured on the sensor. | 
| CarbonBlackDefense.Device.datacenter_name | String | The name of the underlying data center. The data center managed object provides the interface to the common container object for hosts, virtual machines, networks, and datastores. | 
| CarbonBlackDefense.Device.deployment_type | String | The device’s deployment type. This is a classification that is determined by its lifecycle management policy. \(ENDPOINT, WORKLOAD\). | 
| CarbonBlackDefense.Device.deregistered_time | Date | The time when the deregister request was received. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.device_meta_data_item_list.key_name | String | The key name that describes the device. | 
| CarbonBlackDefense.Device.device_meta_data_item_list.key_value | String | The key value that describes the device. | 
| CarbonBlackDefense.Device.device_meta_data_item_list.position | Number | The position that describes the device. | 
| CarbonBlackDefense.Device.device_owner_id | Number | The ID of the device owner associated with the device. | 
| CarbonBlackDefense.Device.email | String | The email address for the device owner. | 
| CarbonBlackDefense.Device.encoded_activation_code | String | The encoded activation code. | 
| CarbonBlackDefense.Device.esx_host_name | String | The name of the ESX host on which the VM is deployed. | 
| CarbonBlackDefense.Device.esx_host_uuid | String | The UUID of the ESX host on which the VM is deployed. | 
| CarbonBlackDefense.Device.first_name | String | The first name of the device owner. | 
| CarbonBlackDefense.Device.id | Number | The ID of the device. | 
| CarbonBlackDefense.Device.last_contact_time | Date | The last time the sensor contacted Carbon Black Cloud. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.last_device_policy_changed_time | Date | The last time the sensor changed from one policy to another. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.last_device_policy_requested_time | Date | The last time the sensor checked for changes to the policy. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.last_external_ip_address | String | The last IP address of the device according to Carbon Black Cloud. This can differ from the last_internal_ip_address due to the network proxy or NAT. Can be either IPv4 or IPv6 format. | 
| CarbonBlackDefense.Device.last_internal_ip_address | String | The last IP address of the device reported by the sensor. Can be either IPv4 or IPv6 format. | 
| CarbonBlackDefense.Device.last_location | String | The device’s current location relative to the organization’s network, based on the current IP address and the device’s registered DNS domain suffix. \(UNKNOWN, ONSITE, OFFSITE\). | 
| CarbonBlackDefense.Device.last_name | String | The last name of the device owner. | 
| CarbonBlackDefense.Device.last_policy_updated_time | Date | The last time the current policy received an update. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.last_reported_time | Date | The last time Carbon Black Cloud received one or more events reported by the sensor. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.last_reset_time | Date | The last time the device was reset. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.last_shutdown_time | Date | The last time the device was shutdown. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.linux_kernel_version | String | Not implemented. | 
| CarbonBlackDefense.Device.login_user_name | String | The last user who logged in to the device. \(Requires Windows Carbon Black Cloud sensor\). | 
| CarbonBlackDefense.Device.mac_address | String | The media access control \(MAC\) address for the device’s primary interface. \(Requires Windows CBC sensor version 1.1.1.1 or later, or macOS CBC sensor\). | 
| CarbonBlackDefense.Device.middle_name | String | The middle name of the device owner. | 
| CarbonBlackDefense.Device.name | String | The hostname of the endpoint recorded by the sensor when last initialized. | 
| CarbonBlackDefense.Device.organization_id | Number | The organization ID. | 
| CarbonBlackDefense.Device.organization_name | String | The organization name. | 
| CarbonBlackDefense.Device.os | String | The operating system. \(WINDOWS, MAC, LINUX, OTHER\). | 
| CarbonBlackDefense.Device.os_version | String | The operating system and version of the endpoint. | 
| CarbonBlackDefense.Device.passive_mode | Boolean | Whether the device is in bypass mode. | 
| CarbonBlackDefense.Device.policy_id | Number | The policy ID assigned to the device. | 
| CarbonBlackDefense.Device.policy_name | String | The policy name assigned to the device. This name may not match the current_sensor_policy_name until the sensor checks back in. | 
| CarbonBlackDefense.Device.policy_override | Boolean | Whether the policy was manually assigned to override mass sensor management. | 
| CarbonBlackDefense.Device.quarantined | Boolean | The indicator that the device is in quarantine mode. | 
| CarbonBlackDefense.Device.registered_time | Date | The time when the device was registered with Carbon Black Cloud. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.scan_last_action_time | Date | The last time the background scan was started or stopped. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.scan_last_complete_time | Date | The time the last background scan completed. \(ISO 8601 timestamp in UTC\). | 
| CarbonBlackDefense.Device.scan_status | String | The status of the background scan. \(NEVER_RUN, STOPPED, IN_PROGRESS, COMPLETED\). | 
| CarbonBlackDefense.Device.sensor_kit_type | String | The type of sensor installed on the device. \(XP, WINDOWS, MAC, AV_SIG, OTHER, RHEL, UBUNTU, SUSE, AMAZON_LINUX, MAC_OSX\). | 
| CarbonBlackDefense.Device.sensor_out_of_date | Boolean | Whether there is a new version available to be installed. | 
| CarbonBlackDefense.Device.sensor_pending_update | Boolean | Whether the sensor is marked by the sensor updater service for a sensor upgrade. | 
| CarbonBlackDefense.Device.sensor_states | String | The states the sensor is in. For example \[ "ACTIVE", "LIVE_RESPONSE_ENABLED" \]. \(ACTIVE, PANICS_DETECTED, LOOP_DETECTED, DB_CORRUPTION_DETECTED, CSR_ACTION, REPUX_ACTION, DRIVER_INIT_ERROR, REMGR_INIT_ERROR, UNSUPPORTED_OS, SENSOR_UPGRADE_IN_PROGRESS, SENSOR_UNREGISTERED, WATCHDOG, SENSOR_RESET_IN_PROGRESS, DRIVER_INIT_REBOOT_REQUIRED, DRIVER_LOAD_NOT_GRANTED, SENSOR_SHUTDOWN, SENSOR_MAINTENANCE, FULL_DISK_ACCESS_NOT_GRANTED, DEBUG_MODE_ENABLED, AUTO_UPDATE_DISABLED, SELF_PROTECT_DISABLED, VDI_MODE_ENABLED, POC_MODE_ENABLED, SECURITY_CENTER_OPTLN_DISABLED, LIVE_RESPONSE_RUNNING, LIVE_RESPONSE_NOT_RUNNING, LIVE_RESPONSE_KILLED, LIVE_RESPONSE_NOT_KILLED, LIVE_RESPONSE_ENABLED, LIVE_RESPONSE_DISABLED, DRIVER_KERNEL, DRIVER_USERSPACE\). | 
| CarbonBlackDefense.Device.sensor_version | String | The version of the installed sensor in the format: \#.\#.\#.\#. | 
| CarbonBlackDefense.Device.status | String | The status of the device. \(PENDING, REGISTERED, DEREGISTERED, BYPASS Additional searchable statuses that are not returnable ACTIVE, INACTIVE, ERROR, ALL, BYPASS_ON, LIVE, SENSOR_PENDING_UPDATE\). | 
| CarbonBlackDefense.Device.target_priority | String | Device target priorities to match. \(LOW, MEDIUM, HIGH, MISSION_CRITICAL\). | 
| CarbonBlackDefense.Device.uninstall_code | String | The code to enter when uninstalling the sensor. | 
| CarbonBlackDefense.Device.vcenter_host_url | String | The vCenter host URL. | 
| CarbonBlackDefense.Device.vcenter_name | String | The name of the vCenter the VM is associated with. | 
| CarbonBlackDefense.Device.vcenter_uuid | String | The 128-bit SMBIOS UUID of a vCenter represented as a hexadecimal string. | 
| CarbonBlackDefense.Device.vdi_base_device | Number | The ID of the device from which this device was cloned/re-registered. | 
| CarbonBlackDefense.Device.virtual_machine | Boolean | Whether this device is a virtual machine \(VMware AppDefense integration\). Deprecated for deployment_type. | 
| CarbonBlackDefense.Device.virtualization_provider | String | The name of the VM virtualization provider. | 
| CarbonBlackDefense.Device.vm_ip | String | The IP address of the VM. | 
| CarbonBlackDefense.Device.vm_name | String | The name of the VM that the sensor is deployed on. | 
| CarbonBlackDefense.Device.vm_uuid | String | The 128-bit SMBIOS UUID of a virtual machine represented as a hexadecimal string. \(Format: 12345678-abcd-1234-cdef-123456789abc\). | 
| CarbonBlackDefense.Device.vulnerability_score | Number | The vulnerability score from 0 to 100 indicating the workload’s level of vulnerability with 100 being highly vulnerable. | 
| CarbonBlackDefense.Device.vulnerability_severity | String | The severity level indicating the workload’s vulnerability. \(CRITICAL, MODERATE, IMPORTANT, LOW\). | 
| CarbonBlackDefense.Device.windows_platform | String | Deprecated for os_version. \(CLIENT_X86, CLIENT_X64, SERVER_X86, SERVER_X64, CLIENT_ARM64, SERVER_ARM64\). | 

#### Command example
```!cbd-device-search```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Device": [
            {
                "activation_code": null,
                "activation_code_expiry_time": "2023-01-19T12:11:11.883Z",
                "ad_domain": null,
                "ad_group_id": 0,
                "ad_org_unit": null,
                "appliance_name": null,
                "appliance_uuid": null,
                "asset_group": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    }
                ],
                "auto_scaling_group_name": null,
                "av_ave_version": null,
                "av_engine": null,
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": [
                    "AV_ACTIVE",
                    "SIGNATURE_UPDATE_DISABLED",
                    "ONACCESS_SCAN_DISABLED",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": null,
                "base_device": null,
                "cloud_provider_account_id": null,
                "cloud_provider_managed_identity": null,
                "cloud_provider_network": null,
                "cloud_provider_resource_group": null,
                "cloud_provider_resource_id": null,
                "cloud_provider_scale_group": null,
                "cloud_provider_tags": [],
                "cluster_name": null,
                "compliance_status": "NOT_ASSESSED",
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "WORKLOAD",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "1.1.1.1",
                        "position": 0
                    }
                ],
                "device_owner_id": "dummy_device_owner_id",
                "email": "CB-H10\\Admin",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "golden_device": null,
                "golden_device_id": null,
                "groups": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    }
                ],
                "host_based_firewall_reasons": [],
                "host_based_firewall_status": null,
                "id": "dummy_id",
                "infrastructure_provider": "NONE",
                "last_contact_time": "2024-07-09T15:30:29.175Z",
                "last_device_policy_changed_time": "2024-02-01T10:30:40.624Z",
                "last_device_policy_requested_time": "2024-07-09T15:30:31.028Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "1.1.1.1",
                "last_location": "OFFSITE",
                "last_name": null,
                "last_policy_updated_time": "2024-06-17T09:21:35.212Z",
                "last_reported_time": "2024-07-09T15:30:29.797Z",
                "last_reset_time": null,
                "last_shutdown_time": "2024-07-09T14:30:21.720Z",
                "linux_kernel_version": null,
                "login_user_name": "CB-H10\\Admin",
                "mac_address": "005056a285bc",
                "middle_name": null,
                "name": "CB-H10",
                "nsx_distributed_firewall_policy": null,
                "nsx_enabled": null,
                "organization_id": "dummy_organization_id",
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_assignment_type": "MANUAL",
                "policy_id": "dummy_policy_id",
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2023-01-12T12:11:11.930Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_gateway_url": null,
                "sensor_gateway_uuid": null,
                "sensor_kit_type": "WINDOWS",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "ACTIVE",
                    "LIVE_RESPONSE_NOT_RUNNING",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "LIVE_RESPONSE_ENABLED"
                ],
                "sensor_version": "1.1.1.1",
                "status": "REGISTERED",
                "target_priority": "MEDIUM",
                "uninstall_code": "dummy_uninstall_code",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": 6039303,
                "vdi_provider": "NONE",
                "virtual_machine": true,
                "virtual_private_cloud_id": null,
                "virtualization_provider": "VMW_ESX",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": null,
                "activation_code_expiry_time": "2020-10-27T13:49:46.641Z",
                "ad_domain": null,
                "ad_group_id": 0,
                "ad_org_unit": null,
                "appliance_name": null,
                "appliance_uuid": null,
                "asset_group": null,
                "auto_scaling_group_name": null,
                "av_ave_version": null,
                "av_engine": null,
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": [],
                "av_update_servers": null,
                "av_vdf_version": null,
                "base_device": null,
                "cloud_provider_account_id": null,
                "cloud_provider_managed_identity": null,
                "cloud_provider_network": null,
                "cloud_provider_resource_group": null,
                "cloud_provider_resource_id": null,
                "cloud_provider_scale_group": null,
                "cloud_provider_tags": [],
                "cluster_name": null,
                "compliance_status": "NOT_ASSESSED",
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "WORKLOAD",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "CentOS 7",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "1.1.1.1",
                        "position": 0
                    }
                ],
                "device_owner_id": "dummy_device_owner_id",
                "email": "localhost.localdomain",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "golden_device": null,
                "golden_device_id": null,
                "groups": null,
                "host_based_firewall_reasons": [],
                "host_based_firewall_status": null,
                "id": "dummy_id",
                "infrastructure_provider": "NONE",
                "last_contact_time": "2024-07-09T15:29:27.472Z",
                "last_device_policy_changed_time": "2024-05-24T09:24:52.884Z",
                "last_device_policy_requested_time": "2024-06-21T20:15:56.512Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "1.1.1.1",
                "last_location": "UNKNOWN",
                "last_name": null,
                "last_policy_updated_time": "2024-06-17T09:21:35.212Z",
                "last_reported_time": "2024-07-09T10:51:07.343Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": null,
                "mac_address": "0050568135bc",
                "middle_name": null,
                "name": "localhost.localdomain",
                "nsx_distributed_firewall_policy": null,
                "nsx_enabled": null,
                "organization_id": "dummy_organization_id",
                "organization_name": "cb-internal-alliances.com",
                "os": "LINUX",
                "os_version": "CentOS 7.9-2009 x64",
                "passive_mode": false,
                "policy_assignment_type": "MANUAL",
                "policy_id": "dummy_policy_id",
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2024-01-31T05:16:55.865Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_gateway_url": null,
                "sensor_gateway_uuid": null,
                "sensor_kit_type": "RHEL",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "LIVE_RESPONSE_ENABLED",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "ACTIVE"
                ],
                "sensor_version": "1.1.1.10133",
                "status": "REGISTERED",
                "target_priority": "MEDIUM",
                "uninstall_code": "dummy_uninstall_code",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "vdi_provider": "NONE",
                "virtual_machine": true,
                "virtual_private_cloud_id": null,
                "virtualization_provider": "VMW_ESX",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 9.8,
                "vulnerability_severity": "CRITICAL",
                "windows_platform": null
            },
            {
                "activation_code": "dummy_activation_code",
                "activation_code_expiry_time": "2021-03-08T22:36:37.549Z",
                "ad_domain": [
                    "SDE.LOGRHYTHM.COM"
                ],
                "ad_group_id": 0,
                "ad_org_unit": [
                    "OPERATIONS",
                    "SERVERS"
                ],
                "appliance_name": null,
                "appliance_uuid": null,
                "asset_group": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    }
                ],
                "auto_scaling_group_name": null,
                "av_ave_version": "1.1.1.1",
                "av_engine": "1.1.1.1-ave.1.1.1.1",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "1.1.1.1",
                "av_product_version": "1.1.1.1",
                "av_status": [
                    "AV_ACTIVE",
                    "SIGNATURE_UPDATE_DISABLED",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "1.1.1.1",
                "base_device": null,
                "cloud_provider_account_id": null,
                "cloud_provider_managed_identity": null,
                "cloud_provider_network": null,
                "cloud_provider_resource_group": null,
                "cloud_provider_resource_id": null,
                "cloud_provider_scale_group": null,
                "cloud_provider_tags": [],
                "cluster_name": null,
                "compliance_status": "NOT_ASSESSED",
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "WORKLOAD",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows",
                        "position": 0
                    },
                    {
                        "key_name": "AD_LDAP",
                        "key_value": "OU=Operations,OU=Servers,DC=sde,DC=logrhythm,DC=com",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "1.1.1.1",
                        "position": 0
                    }
                ],
                "device_owner_id": "dummy_device_owner_id",
                "email": "jake.haldeman@logrhythm.com",
                "encoded_activation_code": "dummy_encoded_activation_code",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Jake",
                "golden_device": null,
                "golden_device_id": null,
                "groups": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    }
                ],
                "host_based_firewall_reasons": [],
                "host_based_firewall_status": null,
                "id": "dummy_id",
                "infrastructure_provider": null,
                "last_contact_time": "2024-07-09T15:29:23.630Z",
                "last_device_policy_changed_time": "2024-05-24T09:23:08.184Z",
                "last_device_policy_requested_time": "2024-06-17T09:22:32.585Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "1.1.1.1",
                "last_location": "OFFSITE",
                "last_name": "Haldeman",
                "last_policy_updated_time": "2024-06-17T09:21:35.212Z",
                "last_reported_time": "2024-07-05T23:41:48.091Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "SDE\\luis.castaneda",
                "mac_address": "00505694822c",
                "middle_name": null,
                "name": "SDE\\USBO1SEFS-01",
                "nsx_distributed_firewall_policy": null,
                "nsx_enabled": null,
                "organization_id": "dummy_organization_id",
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Server 2012 R2 x64",
                "passive_mode": true,
                "policy_assignment_type": "MANUAL",
                "policy_id": "dummy_policy_id",
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2021-03-01T22:38:55.160Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_gateway_url": null,
                "sensor_gateway_uuid": null,
                "sensor_kit_type": "WINDOWS",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "REPUX_ACTION",
                    "LIVE_RESPONSE_NOT_RUNNING",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "LIVE_RESPONSE_ENABLED"
                ],
                "sensor_version": "1.1.1.19",
                "status": "BYPASS",
                "target_priority": "MEDIUM",
                "uninstall_code": "dummy_uninstall_code",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "vdi_provider": null,
                "virtual_machine": true,
                "virtual_private_cloud_id": null,
                "virtualization_provider": "VMW_ESX",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 9.8,
                "vulnerability_severity": "CRITICAL",
                "windows_platform": null
            },
            {
                "activation_code": null,
                "activation_code_expiry_time": "2023-10-27T18:45:09.805Z",
                "ad_domain": [
                    "RTEST.COM"
                ],
                "ad_group_id": 0,
                "ad_org_unit": null,
                "appliance_name": null,
                "appliance_uuid": null,
                "asset_group": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    }
                ],
                "auto_scaling_group_name": null,
                "av_ave_version": "1.1.1.1",
                "av_engine": "1.1.1.1-ave.1.1.1.1:avpack.1.1.1.1:vdf.1.1.1.1:vdfdate.20231205",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "1.1.1.1",
                "av_product_version": "1.1.1.1",
                "av_status": [
                    "AV_ACTIVE",
                    "SIGNATURE_UPDATE_DISABLED",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "1.1.1.1",
                "base_device": null,
                "cloud_provider_account_id": null,
                "cloud_provider_managed_identity": null,
                "cloud_provider_network": null,
                "cloud_provider_resource_group": null,
                "cloud_provider_resource_id": null,
                "cloud_provider_scale_group": null,
                "cloud_provider_tags": [],
                "cluster_name": null,
                "compliance_status": "NOT_ASSESSED",
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "WORKLOAD",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "AD_LDAP",
                        "key_value": "DC=rtest,DC=com",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "1.1.1.1",
                        "position": 0
                    }
                ],
                "device_owner_id": "dummy_device_owner_id",
                "email": "bvanpelt",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "golden_device": null,
                "golden_device_id": null,
                "groups": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    }
                ],
                "host_based_firewall_reasons": [],
                "host_based_firewall_status": "NOT_ENABLED",
                "id": "dummy_id",
                "infrastructure_provider": "NONE",
                "last_contact_time": "2024-07-09T15:29:05.974Z",
                "last_device_policy_changed_time": "2023-12-05T10:14:32.584Z",
                "last_device_policy_requested_time": "2024-06-17T09:21:56.441Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "1.1.1.1",
                "last_location": "OFFSITE",
                "last_name": null,
                "last_policy_updated_time": "2024-06-17T09:21:35.212Z",
                "last_reported_time": "2024-07-09T10:03:10.504Z",
                "last_reset_time": null,
                "last_shutdown_time": "2024-04-27T00:06:14.478Z",
                "linux_kernel_version": null,
                "login_user_name": "RTEST\\bvanpelt",
                "mac_address": "005056adf705",
                "middle_name": null,
                "name": "RTEST\\bvp-carbonblack",
                "nsx_distributed_firewall_policy": null,
                "nsx_enabled": null,
                "organization_id": "dummy_organization_id",
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_assignment_type": "MANUAL",
                "policy_id": "dummy_policy_id",
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2023-10-20T18:45:09.842Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_gateway_url": null,
                "sensor_gateway_uuid": null,
                "sensor_kit_type": "WINDOWS",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "ACTIVE",
                    "LIVE_RESPONSE_NOT_RUNNING",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "LIVE_RESPONSE_ENABLED",
                    "CB_FIREWALL_INACTIVE"
                ],
                "sensor_version": "1.1.1.18",
                "status": "REGISTERED",
                "target_priority": "MEDIUM",
                "uninstall_code": "dummy_uninstall_code",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "vdi_provider": "NONE",
                "virtual_machine": true,
                "virtual_private_cloud_id": null,
                "virtualization_provider": "VMW_ESX",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 8.8,
                "vulnerability_severity": "IMPORTANT",
                "windows_platform": null
            },
            {
                "activation_code": null,
                "activation_code_expiry_time": "2023-09-10T08:35:13.955Z",
                "ad_domain": null,
                "ad_group_id": 0,
                "ad_org_unit": null,
                "appliance_name": null,
                "appliance_uuid": null,
                "asset_group": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    }
                ],
                "auto_scaling_group_name": null,
                "av_ave_version": null,
                "av_engine": null,
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": [
                    "AV_ACTIVE",
                    "SIGNATURE_UPDATE_DISABLED",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": null,
                "base_device": null,
                "cloud_provider_account_id": null,
                "cloud_provider_managed_identity": null,
                "cloud_provider_network": null,
                "cloud_provider_resource_group": null,
                "cloud_provider_resource_id": null,
                "cloud_provider_scale_group": null,
                "cloud_provider_tags": [],
                "cluster_name": null,
                "compliance_status": "NOT_ASSESSED",
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 11",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "1.1.1.1",
                        "position": 0
                    }
                ],
                "device_owner_id": "dummy_device_owner_id",
                "email": "microsoftwindowsserver2022datacenterfe8013b5d1a8b08636a7",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "golden_device": null,
                "golden_device_id": null,
                "groups": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    }
                ],
                "host_based_firewall_reasons": [],
                "host_based_firewall_status": "NOT_ENABLED",
                "id": "dummy_id",
                "infrastructure_provider": "NONE",
                "last_contact_time": "2024-07-09T15:28:45.119Z",
                "last_device_policy_changed_time": "2024-02-01T10:28:55.298Z",
                "last_device_policy_requested_time": "2024-06-17T09:21:35.726Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "1.1.1.1",
                "last_location": "OFFSITE",
                "last_name": null,
                "last_policy_updated_time": "2024-06-17T09:21:35.212Z",
                "last_reported_time": "2024-07-09T09:04:06.948Z",
                "last_reset_time": null,
                "last_shutdown_time": "2023-09-13T07:34:15.360Z",
                "linux_kernel_version": null,
                "login_user_name": "INT01-CARBONBLA\\Administrator",
                "mac_address": "0236414d5bd9",
                "middle_name": null,
                "name": "int01-carbonblack",
                "nsx_distributed_firewall_policy": null,
                "nsx_enabled": null,
                "organization_id": "dummy_organization_id",
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows Server 2022 x64",
                "passive_mode": true,
                "policy_assignment_type": "MANUAL",
                "policy_id": "dummy_policy_id",
                "policy_name": "default",
                "policy_override": true,
                "quarantined": true,
                "registered_time": "2023-09-03T08:35:13.991Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_gateway_url": null,
                "sensor_gateway_uuid": null,
                "sensor_kit_type": "WINDOWS",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "CSR_ACTION",
                    "LIVE_RESPONSE_NOT_RUNNING",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "LIVE_RESPONSE_ENABLED",
                    "CB_FIREWALL_INACTIVE"
                ],
                "sensor_version": "1.1.1.18",
                "status": "BYPASS",
                "target_priority": "MEDIUM",
                "uninstall_code": "dummy_uninstall_code",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "vdi_provider": "NONE",
                "virtual_machine": true,
                "virtual_private_cloud_id": null,
                "virtualization_provider": "OTHER",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 9.8,
                "vulnerability_severity": "CRITICAL",
                "windows_platform": null
            },
            {
                "activation_code": null,
                "activation_code_expiry_time": "2017-12-21T11:35:18.286Z",
                "ad_domain": null,
                "ad_group_id": 0,
                "ad_org_unit": null,
                "appliance_name": null,
                "appliance_uuid": null,
                "asset_group": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    }
                ],
                "auto_scaling_group_name": null,
                "av_ave_version": "1.1.1.1",
                "av_engine": "1.2.3.4-ave.1.2.3.4:avpack.1.2.3.4:vdf.1.2.3.4",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "1.1.1.1",
                "av_product_version": "1.1.1.1",
                "av_status": [
                    "AV_ACTIVE",
                    "SIGNATURE_UPDATE_DISABLED",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "1.1.1.1",
                "base_device": null,
                "cloud_provider_account_id": null,
                "cloud_provider_managed_identity": null,
                "cloud_provider_network": null,
                "cloud_provider_resource_group": null,
                "cloud_provider_resource_id": null,
                "cloud_provider_scale_group": null,
                "cloud_provider_tags": [],
                "cluster_name": null,
                "compliance_status": "NOT_ASSESSED",
                "current_sensor_policy_name": null,
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "1.1.1.1",
                        "position": 0
                    }
                ],
                "device_owner_id": "dummy_device_owner_id",
                "email": "EPO-AGENT-PC\\EPO",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "golden_device": null,
                "golden_device_id": null,
                "groups": [
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "My Example Asset Group"
                    },
                    {
                        "id": "dummy_id",
                        "membership_type": "DYNAMIC",
                        "name": "Windows No Policy"
                    }
                ],
                "host_based_firewall_reasons": [],
                "host_based_firewall_status": null,
                "id": "dummy_id",
                "infrastructure_provider": null,
                "last_contact_time": "2024-07-09T15:28:44.460Z",
                "last_device_policy_changed_time": "2024-01-05T20:26:17.411Z",
                "last_device_policy_requested_time": "2024-06-19T15:54:20.202Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "1.1.1.1",
                "last_location": "OFFSITE",
                "last_name": null,
                "last_policy_updated_time": "2024-06-17T09:21:35.212Z",
                "last_reported_time": "2024-06-19T16:00:46.224Z",
                "last_reset_time": null,
                "last_shutdown_time": "2023-07-03T07:29:15.161Z",
                "linux_kernel_version": null,
                "login_user_name": null,
                "mac_address": null,
                "middle_name": null,
                "name": "EPO-AGENT-PC",
                "nsx_distributed_firewall_policy": null,
                "nsx_enabled": null,
                "organization_id": "dummy_organization_id",
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 7 x64 SP: 1",
                "passive_mode": true,
                "policy_assignment_type": "MANUAL",
                "policy_id": "dummy_policy_id",
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2017-12-14T11:35:18.317Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_gateway_url": null,
                "sensor_gateway_uuid": null,
                "sensor_kit_type": "WINDOWS",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "CSR_ACTION",
                    "LIVE_RESPONSE_NOT_RUNNING",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "LIVE_RESPONSE_ENABLED"
                ],
                "sensor_version": "1.1.1.1",
                "status": "BYPASS",
                "target_priority": "MEDIUM",
                "uninstall_code": "dummy_uninstall_code",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "vdi_provider": null,
                "virtual_machine": false,
                "virtual_private_cloud_id": null,
                "virtualization_provider": null,
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Devices List Results
>|Id|Name|Os|Policy Name|Quarantined|Status|Target Priority|Last Internal Ip Address|Last External Ip Address|Last Contact Time|Last Location|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 6494305 | CB-H10 | WINDOWS | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:29.175Z | OFFSITE |
>| 7762940 | cb-linux-1 | LINUX | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:22.439Z | UNKNOWN |
>| 4136358 | DESKTOP-F70DSE6 | WINDOWS | default | false | BYPASS | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:20.279Z | OFFSITE |
>| 6697317 | SKOVILLE\pequin | WINDOWS | default | true | BYPASS | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:19.954Z | OFFSITE |
>| 6227495 | CB-MarkoTest | WINDOWS | default | true | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:19.640Z | OFFSITE |
>| 7533319 | R7BETALAB\R7BETALAB-ARW04 | WINDOWS | AWN BAS | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:09.740Z | OFFSITE |
>| 7762975 | cb-linux-2 | LINUX | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:09.305Z | UNKNOWN |
>| 6268346 | Kognos-CB-2 | WINDOWS | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:05.050Z | OFFSITE |
>| 5654865 | misp1 | LINUX | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:30:04.821Z | UNKNOWN |
>| 6286530 | DESKTOP-PGMSAIE | WINDOWS | default | true | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:29:52.511Z | OFFSITE |
>| 8213794 | win1122H2new | WINDOWS | ⚠️ Wide Open | false | REGISTERED | LOW | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:29:45.110Z | OFFSITE |
>| 3777587 | bo1tapsandbox-01 | LINUX | default | false | BYPASS | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:29:40.803Z | UNKNOWN |
>| 6697325 | cayenne | LINUX | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:29:33.955Z | UNKNOWN |
>| 7773496 | localhost.localdomain | LINUX | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:29:27.472Z | UNKNOWN |
>| 4081930 | SDE\USBO1SEFS-01 | WINDOWS | default | false | BYPASS | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:29:23.630Z | OFFSITE |
>| 7460343 | RTEST\bvp-carbonblack | WINDOWS | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:29:05.974Z | OFFSITE |
>| 6612402 | EIP\WW-20003 | WINDOWS | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:28:51.666Z | OFFSITE |
>| 6697318 | SKOVILLE\jalapeno | WINDOWS | default | false | REGISTERED | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:28:50.821Z | OFFSITE |
>| 7315458 | int01-carbonblack | WINDOWS | default | true | BYPASS | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:28:45.119Z | OFFSITE |
>| 607519 | EPO-AGENT-PC | WINDOWS | default | false | BYPASS | MEDIUM | 1.1.1.1 | 1.1.1.1 | 2024-07-09T15:28:44.460Z | OFFSITE |


### cbd-device-quarantine

***
Quarantines the device. Not supported for devices in a Linux operating system.

#### Base Command

`cbd-device-quarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 

#### Context Output

There is no context output for this command.
### cbd-device-unquarantine

***
Unquarantines the device. Not supported for devices in a Linux operating system.

#### Base Command

`cbd-device-unquarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 

#### Context Output

There is no context output for this command.
### cbd-device-background-scan

***
Starts a background scan on the device. Not supported for devices in a Linux operating system.

#### Base Command

`cbd-device-background-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 

#### Context Output

There is no context output for this command.
### cbd-device-background-scan-stop

***
Stops a background scan on the device. Not supported for devices in a Linux operating system.

#### Base Command

`cbd-device-background-scan-stop`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 

#### Context Output

There is no context output for this command.
### cbd-device-bypass

***
Bypasses a device.

#### Base Command

`cbd-device-bypass`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 

#### Context Output

There is no context output for this command.
### cbd-device-unbypass

***
Unbypasses a device.

#### Base Command

`cbd-device-unbypass`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 

#### Context Output

There is no context output for this command.
### cbd-device-policy-update

***
Updates the devices to the specified policy ID.

#### Base Command

`cbd-device-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 
| policy_id | The ID of the policy. | Required | 

#### Context Output

There is no context output for this command.
### cbd-device-update-sensor-version

***
Updates the version of a sensor.

#### Base Command

`cbd-device-update-sensor-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 
| sensor_version | The new version of the sensor. For example: { "MAC": "1.1.1.1" }. Supported types: XP, WINDOWS, MAC, AV_SIG, OTHER, RHEL, UBUNTU, SUSE, AMAZON_LINUX, MAC_OSX. Possible values are: {"XP":}, {"WINDOWS":}, {"MAC":}, {"AV_SIG":}, {"OTHER":}, {"RHEL":}, {"UBUNTU":}, {"SUSE":}, {"AMAZON_LINUX":}, {"MAC_OSX":}. | Required | 

#### Context Output

There is no context output for this command.
### cbd-find-processes-results

***
Retrieves the search results using the specified job ID.

#### Base Command

`cbd-find-processes-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | When set to false, the function will not use polling and will return the process status or the result if the process is complete. | Optional | 
| job_id | The unique ID for the process search job. This ID is used to retrieve the results of the process search initiated by Carbon Black Cloud. | Required | 
| rows | The number of rows to request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Process.Results.backend_timestamp | Date | The timestamp when the process data was collected from the backend. | 
| CarbonBlackDefense.Process.Results.childproc_count | Number | The number of child processes spawned by the process. | 
| CarbonBlackDefense.Process.Results.crossproc_count | Number | The number of cross-process interactions involving the process. | 
| CarbonBlackDefense.Process.Results.device_id | Number | The unique ID of the device where the process is running. | 
| CarbonBlackDefense.Process.Results.device_name | String | The name of the device where the process is running. | 
| CarbonBlackDefense.Process.Results.device_policy_id | Number | The policy ID associated with the device. | 
| CarbonBlackDefense.Process.Results.device_timestamp | Date | The timestamp when the process data was collected from the device. | 
| CarbonBlackDefense.Process.Results.filemod_count | Number | The number of file modifications made by the process. | 
| CarbonBlackDefense.Process.Results.index_class | String | The classification of the process based on indexing. | 
| CarbonBlackDefense.Process.Results.modload_count | Number | The number of modules loaded by the process. | 
| CarbonBlackDefense.Process.Results.netconn_count | Number | The number of network connections established by the process. | 
| CarbonBlackDefense.Process.Results.org_id | String | The organization ID associated with the process. | 
| CarbonBlackDefense.Process.Results.parent_guid | String | The GUID of the parent process. | 
| CarbonBlackDefense.Process.Results.parent_pid | Number | The PID of the parent process. | 
| CarbonBlackDefense.Process.Results.partition_id | Number | The partition ID associated with the process. | 
| CarbonBlackDefense.Process.Results.process_guid | String | The GUID of the process. | 
| CarbonBlackDefense.Process.Results.process_hash | String | The hash of the process. | 
| CarbonBlackDefense.Process.Results.process_name | String | The name of the process. | 
| CarbonBlackDefense.Process.Results.process_pid | Number | The PID of the process. | 
| CarbonBlackDefense.Process.Results.process_username | String | The username under which the process is running. | 
| CarbonBlackDefense.Process.Results.regmod_count | Number | The number of registry modifications made by the process. | 
| CarbonBlackDefense.Process.Results.scriptload_count | Number | The number of scripts loaded by the process. | 

#### Command example
```!cbd-find-processes-results job_id=abc-123 rows=2```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Process": {
            "Results": [
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "49becb5d-8cca-4b39-b7f4-d94401533dab",
                        "6038e242-2c44-470c-92e3-bf3a0c32dc26",
                        "a7056445-388b-46d8-9d8e-3885bfe28fc0"
                    ],
                    "backend_timestamp": "2024-07-11T14:51:29.069Z",
                    "childproc_count": 1,
                    "crossproc_count": 7,
                    "device_group_id": 0,
                    "device_id": 12345,
                    "device_name": "r7betalab\\r7betalab-arw04",
                    "device_policy_id": 80947,
                    "device_timestamp": "2024-07-11T14:44:11.754Z",
                    "filemod_count": 11,
                    "ingress_time": 1720709467661,
                    "modload_count": 40,
                    "netconn_count": 0,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "dummy_parent_guid",
                    "parent_pid": 4380,
                    "process_guid": "dummy_process_guid",
                    "process_hash": [
                        "dummy_process_hash",
                    ],
                    "process_name": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                    "process_pid": [
                        2192
                    ],
                    "process_username": [
                        "R7BETALAB\\svc_idr"
                    ],
                    "regmod_count": 4,
                    "scriptload_count": 1,
                    "watchlist_hit": []
                },
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "dummy_alert_id"
                    ],
                    "backend_timestamp": "2024-07-11T14:34:13.616Z",
                    "childproc_count": 0,
                    "crossproc_count": 0,
                    "device_group_id": 0,
                    "device_id": 12345,
                    "device_name": "cb-markotest",
                    "device_policy_id": 6525,
                    "device_timestamp": "2024-07-11T14:30:39.203Z",
                    "filemod_count": 0,
                    "ingress_time": 1720708414089,
                    "modload_count": 0,
                    "netconn_count": 1,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "dummy_parent_guid",
                    "parent_pid": 688,
                    "process_guid": "dummy_process_guid",
                    "process_hash": [],
                    "process_name": "c:\\windows\\system32\\svchost.exe",
                    "process_pid": [
                        2264
                    ],
                    "process_username": [
                        "NT AUTHORITY\\NETWORK SERVICE"
                    ],
                    "regmod_count": 0,
                    "scriptload_count": 0,
                    "watchlist_hit": [
                        "abcd123"
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### The Results For The Process Search
>|Device Id|Device Name|Process Name|Device Policy Id|
>|---|---|---|---|
>| 1234 | r7betalab\r7betalab-arw04 | c:\windows\system32\windowspowershell\v1.0\powershell.exe | 80947 |
>| 1111 | cb-markotest | c:\windows\system32\svchost.exe | 6525 |

### cbd-find-observation-details-results

***
Retrieves the search results using the specified job ID.

#### Base Command

`cbd-find-observation-details-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The unique ID for the process search job. This ID is used to retrieve the results of the process search initiated by Carbon Black Cloud. | Required | 
| rows | The number of rows to request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.EventDetails.Results.alert_category | String | The category of the alert associated with the observation. | 
| CarbonBlackDefense.EventDetails.Results.alert_id | String | The unique ID of the alert associated with the observation. | 
| CarbonBlackDefense.EventDetails.Results.backend_timestamp | Date | The timestamp when the observation data was collected from the backend. | 
| CarbonBlackDefense.EventDetails.Results.childproc_count | Number | The number of child processes spawned by the observed process. | 
| CarbonBlackDefense.EventDetails.Results.crossproc_count | Number | The number of cross-process interactions involving the observed process. | 
| CarbonBlackDefense.EventDetails.Results.device_external_ip | String | The external IP address of the device where the observation was made. | 
| CarbonBlackDefense.EventDetails.Results.device_group_id | Number | The group ID associated with the device. | 
| CarbonBlackDefense.EventDetails.Results.device_id | Number | The unique ID of the device where the observation was made. | 
| CarbonBlackDefense.EventDetails.Results.device_installed_by | String | The user or process that installed the device. | 
| CarbonBlackDefense.EventDetails.Results.device_internal_ip | String | The internal IP address of the device where the observation was made. | 
| CarbonBlackDefense.EventDetails.Results.device_location | String | The physical or network location of the device. | 
| CarbonBlackDefense.EventDetails.Results.device_name | String | The name of the device where the observation was made. | 
| CarbonBlackDefense.EventDetails.Results.device_os | String | The operating system of the device. | 
| CarbonBlackDefense.EventDetails.Results.device_os_version | String | The version of the operating system of the device. | 
| CarbonBlackDefense.EventDetails.Results.device_policy | String | The policy applied to the device. | 
| CarbonBlackDefense.EventDetails.Results.device_policy_id | Number | The unique ID of the policy applied to the device. | 
| CarbonBlackDefense.EventDetails.Results.device_sensor_version | String | The version of the sensor installed on the device. | 
| CarbonBlackDefense.EventDetails.Results.device_target_priority | String | The priority level of the device as a target. | 
| CarbonBlackDefense.EventDetails.Results.device_timestamp | Date | The timestamp when the observation was recorded on the device. | 
| CarbonBlackDefense.EventDetails.Results.document_guid | String | The GUID of the document associated with the observation. | 
| CarbonBlackDefense.EventDetails.Results.enriched | Boolean | Indicates whether the observation data has been enriched with additional information. | 
| CarbonBlackDefense.EventDetails.Results.enriched_event_type | String | The type of event after enrichment. | 
| CarbonBlackDefense.EventDetails.Results.event_threat_score | Number | The threat score associated with the event. | 
| CarbonBlackDefense.EventDetails.Results.filemod_count | Number | The number of file modifications made by the observed process. | 
| CarbonBlackDefense.EventDetails.Results.ingress_time | Date | The time when the observation data was ingested into the system. | 
| CarbonBlackDefense.EventDetails.Results.legacy | Boolean | Indicates whether the observation is from a legacy system or data source. | 
| CarbonBlackDefense.EventDetails.Results.modload_count | Number | The number of modules loaded by the observed process. | 
| CarbonBlackDefense.EventDetails.Results.netconn_count | Number | The number of network connections established by the observed process. | 
| CarbonBlackDefense.EventDetails.Results.observation_description | String | A description of the observation. | 
| CarbonBlackDefense.EventDetails.Results.observation_id | String | The unique observation ID | 
| CarbonBlackDefense.EventDetails.Results.observation_type | String | The type of observation. | 
| CarbonBlackDefense.EventDetails.Results.org_id | String | The organization ID associated with the observation. | 
| CarbonBlackDefense.EventDetails.Results.parent_cmdline | String | The command line arguments of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_cmdline_length | Number | The length of the command line arguments of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_effective_reputation | String | The effective reputation of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_effective_reputation_source | String | The source of the effective reputation of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_guid | String | The GUID of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_hash | String | The hash of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_name | String | The name of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_pid | Number | The PID of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_publisher | String | The publisher of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_publisher_state | String | The state of the publisher of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.parent_reputation | String | The reputation of the parent process. | 
| CarbonBlackDefense.EventDetails.Results.process_cmdline | String | The command line arguments of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_cmdline_length | Number | The length of the command line arguments of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_company_name | String | The company name associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_effective_reputation | String | The effective reputation of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_effective_reputation_source | String | The source of the effective reputation of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_elevated | Boolean | Indicates whether the observed process is running with elevated privileges. | 
| CarbonBlackDefense.EventDetails.Results.process_file_description | String | The description of the observed process file. | 
| CarbonBlackDefense.EventDetails.Results.process_guid | String | The GUID of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_hash | String | The hash of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_integrity_level | String | The integrity level of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_internal_name | String | The internal name of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_name | String | The name of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_original_filename | String | The original filename of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_pid | Number | The PID of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_privileges | String | The privileges associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_product_name | String | The product name associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_product_version | String | The product version associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_publisher | String | The publisher of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_publisher_state | String | The state of the publisher of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_reputation | String | The reputation of the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_service_name | String | The service name associated with the observed process. | 
| CarbonBlackDefense.EventDetails.Results.process_sha256 | unknown | The SHA-256 hash. | 

#### Command example
```!cbd-find-observation-details-results job_id=abc-1234 rows=2```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "EventDetails": {
            "Results": {
                "alert_category": [
                    "THREAT"
                ],
                "alert_id": [
                    "dummy_alert_id"
                ],
                "backend_timestamp": "2024-04-17T01:52:29.056Z",
                "blocked_effective_reputation": "TRUSTED_WHITE_LIST",
                "blocked_hash": [
                    "dummy_blocked_hash"
                ],
                "blocked_name": "c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                "childproc_cmdline": "\"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe\" (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow() ",
                "childproc_cmdline_length": 124,
                "childproc_effective_reputation": "TRUSTED_WHITE_LIST",
                "childproc_effective_reputation_source": "CLOUD",
                "childproc_guid": "dummy_childproc_guid",
                "childproc_hash": [
                    "dummy_chidproc_hash"
                ],
                "childproc_issuer": [
                    "Microsoft Windows Production PCA 2011"
                ],
                "childproc_name": "c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                "childproc_pid": 1020,
                "childproc_publisher": [
                    "Microsoft Windows"
                ],
                "childproc_publisher_state": [
                    "FILE_SIGNATURE_STATE_VERIFIED",
                    "FILE_SIGNATURE_STATE_SIGNED"
                ],
                "childproc_reputation": "TRUSTED_WHITE_LIST",
                "childproc_username": "NT AUTHORITY\SYSTEM",
                "device_external_ip": "1.1.1.1",
                "device_group_id": 0,
                "device_id": 12345,
                "device_installed_by": "user@example.com",
                "device_internal_ip": "1.1.1.1",
                "device_location": "OFFSITE",
                "device_name": "corp\wsamzn-lshqdrdc",
                "device_os": "WINDOWS",
                "device_os_version": "Windows Server 2019 x64",
                "device_policy": "tines-policy",
                "device_policy_id": 1234,
                "device_sensor_version": "1.1.1.1",
                "device_target_priority": "LOW",
                "device_timestamp": "2024-04-17T01:50:54.057Z",
                "document_guid": "dummy_document_guid",
                "enriched": true,
                "enriched_event_type": "CREATE_PROCESS",
                "event_attack_stage": [
                    "INSTALL_RUN"
                ],
                "event_description": "The script \"<share><link hash=\"dummy_hash\">C:\program files\amazon\skylight\scripts\windows_update_status.ps1</link></share>\" invoked the application \"<share><link hash=\"dummy_hash\">C:\windows\system32\windowspowershell\v1.0\powershell.exe</link></share>\". The operation was <accent>blocked</accent> and the application <accent>terminated by Carbon Black</accent>.",
                "event_id": "dummy_event_id",
                "event_type": "childproc",
                "ingress_time": 1713318735609,
                "legacy": true,
                "observation_description": "The application windows_update_status.ps1 invoked another application (powershell.exe). A Deny Policy Action was applied.",
                "observation_id": "dummy_observation_id",
                "observation_type": "CB_ANALYTICS",
                "org_id": "abc123",
                "parent_effective_reputation": "LOCAL_WHITE",
                "parent_effective_reputation_source": "PRE_EXISTING",
                "parent_guid": "dummy_parent_guid",
                "parent_hash": [
                    "dummy_parent_hash"
                ],
                "parent_name": "c:\program files\amazon\skylight\skylightworkspaceconfigservice.exe",
                "parent_pid": 1234,
                "parent_reputation": "NOT_LISTED",
                "parent_username": "NT AUTHORITY\SYSTEM",
                "process_cmdline": [
                    "\"powershell.exe\" -NonInteractive -ExecutionPolicy AllSigned -File \"C:\Program files\Amazon\SkyLight\scripts\windows_update_status.ps1\" -scriptId windows_update_status.ps1 CheckStatus"
                ],
                "process_cmdline_length": [
                    182
                ],
                "process_effective_reputation": "ADAPTIVE_WHITE_LIST",
                "process_effective_reputation_source": "CLOUD",
                "process_guid": "dummy_process_guid",
                "process_hash": [
                    "dummy_process_hash",
                ],
                "process_loaded_script_hash": [
                    "dummy_process_loaded_script_hash"
                ],
                "process_loaded_script_name": [
                    "c:\program files\amazon\skylight\scripts\windows_update_status.ps1"
                ],
                "process_name": "c:\program files\amazon\skylight\scripts\windows_update_status.ps1",
                "process_pid": [
                    1234
                ],
                "process_reputation": "NOT_LISTED",
                "process_sha256": "dummy_process_sha256",
                "process_start_time": "2024-04-17T01:50:48.244Z",
                "process_user_id": "S-1-5-18",
                "process_username": [
                    "NT AUTHORITY\SYSTEM"
                ],
                "sensor_action": [
                    "TERMINATE"
                ],
                "ttp": [
                    "MITRE_T1059_CMD_LINE_OR_SCRIPT_INTER",
                    "POLICY_DENY",
                    "MITRE_T1059_001_POWERSHELL"
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Defense Event Details Results
>|Observation Id|Event Id|Device Id|Device External Ip|Device Internal Ip|Enriched Event Type|
>|---|---|---|---|---|---|
>| dummy_observation_id | dummy_event_id | 1234 | 1.1.1.1 | 1.1.1.1 | CREATE_PROCESS |


### cbd-find-observation-results

***
Retrieves the search results using the specified job ID.

#### Base Command

`cbd-find-observation-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The unique ID for the process search job. This ID is used to retrieve the results of the process search initiated by Carbon Black Cloud. | Required | 
| rows | The number of rows to request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Events.Results.alert_category | String | Category of the alert associated with the event. | 
| CarbonBlackDefense.Events.Results.alert_id | String | The unique alert ID. | 
| CarbonBlackDefense.Events.Results.backend_timestamp | Date | Timestamp when the event was processed on the backend. | 
| CarbonBlackDefense.Events.Results.childproc_count | Number | Number of child processes spawned by the process. | 
| CarbonBlackDefense.Events.Results.crossproc_count | Number | Number of cross-process operations performed by the process. | 
| CarbonBlackDefense.Events.Results.device_external_ip | String | External IP address of the device. | 
| CarbonBlackDefense.Events.Results.device_group_id | Number | The device group ID. | 
| CarbonBlackDefense.Events.Results.device_id | Number | The unique device ID. | 
| CarbonBlackDefense.Events.Results.device_installed_by | String | User or entity that installed the device. | 
| CarbonBlackDefense.Events.Results.device_internal_ip | String | Internal IP address of the device. | 
| CarbonBlackDefense.Events.Results.device_location | String | Physical or network location of the device. | 
| CarbonBlackDefense.Events.Results.device_name | String | Name of the device. | 
| CarbonBlackDefense.Events.Results.device_os | String | Operating system running on the device. | 
| CarbonBlackDefense.Events.Results.device_os_version | String | Version of the operating system running on the device. | 
| CarbonBlackDefense.Events.Results.device_policy | String | Security policy applied to the device. | 
| CarbonBlackDefense.Events.Results.device_policy_id | Number | The ID of the security policy applied to the device. | 
| CarbonBlackDefense.Events.Results.device_sensor_version | String | Version of the sensor installed on the device. | 
| CarbonBlackDefense.Events.Results.device_target_priority | String | Priority of the device as a target. | 
| CarbonBlackDefense.Events.Results.device_timestamp | Date | Timestamp of the event as recorded by the device. | 
| CarbonBlackDefense.Events.Results.document_guid | String | The global unique ID for the document associated with the event. | 
| CarbonBlackDefense.Events.Results.enriched | Boolean | Indicates whether the event data has been enriched. | 
| CarbonBlackDefense.Events.Results.enriched_event_type | String | Type of the enriched event. | 
| CarbonBlackDefense.Events.Results.event_threat_score | Number | Threat score assigned to the event. | 
| CarbonBlackDefense.Events.Results.filemod_count | Number | Number of file modifications performed by the process. | 
| CarbonBlackDefense.Events.Results.ingress_time | Date | Time when the event was ingested by the system. | 
| CarbonBlackDefense.Events.Results.legacy | Boolean | Indicates whether the event is considered a legacy event. | 
| CarbonBlackDefense.Events.Results.modload_count | Number | Number of modules loaded by the process. | 
| CarbonBlackDefense.Events.Results.netconn_count | Number | Number of network connections established by the process. | 
| CarbonBlackDefense.Events.Results.observation_description | String | Description of the observation associated with the event. | 
| CarbonBlackDefense.Events.Results.observation_id | String | The unique observation ID. | 
| CarbonBlackDefense.Events.Results.observation_type | String | Type of the observation associated with the event. | 
| CarbonBlackDefense.Events.Results.org_id | String | The ID of the organization associated with the event. | 
| CarbonBlackDefense.Events.Results.parent_cmdline | String | Command line used to execute the parent process. | 
| CarbonBlackDefense.Events.Results.parent_cmdline_length | Number | Length of the command line used to execute the parent process. | 
| CarbonBlackDefense.Events.Results.parent_effective_reputation | String | Effective reputation of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_effective_reputation_source | String | Source of the effective reputation of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_guid | String | The global unique ID for the parent process. | 
| CarbonBlackDefense.Events.Results.parent_hash | String | Hash of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_name | String | Name of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_pid | Number | The process ID of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_publisher | String | Publisher of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_publisher_state | String | Publisher state of the parent process. | 
| CarbonBlackDefense.Events.Results.parent_reputation | String | Reputation of the parent process. | 
| CarbonBlackDefense.Events.Results.process_cmdline | String | Command line used to execute the process. | 
| CarbonBlackDefense.Events.Results.process_cmdline_length | Number | Length of the command line used to execute the process. | 
| CarbonBlackDefense.Events.Results.process_company_name | String | Company name associated with the process. | 
| CarbonBlackDefense.Events.Results.process_effective_reputation | String | Effective reputation of the process. | 
| CarbonBlackDefense.Events.Results.process_effective_reputation_source | String | Source of the effective reputation of the process. | 
| CarbonBlackDefense.Events.Results.process_elevated | Boolean | Indicates whether the process is running with elevated privileges. | 
| CarbonBlackDefense.Events.Results.process_file_description | String | File description of the process. | 
| CarbonBlackDefense.Events.Results.process_guid | String | The global unique process ID. | 
| CarbonBlackDefense.Events.Results.process_hash | String | Hash of the process. | 
| CarbonBlackDefense.Events.Results.process_integrity_level | String | Integrity level of the process. | 
| CarbonBlackDefense.Events.Results.process_internal_name | String | Internal name of the process. | 
| CarbonBlackDefense.Events.Results.process_name | String | Name of the process. | 
| CarbonBlackDefense.Events.Results.process_original_filename | String | Original filename of the process. | 
| CarbonBlackDefense.Events.Results.process_pid | Number | The process ID of the process. | 
| CarbonBlackDefense.Events.Results.process_privileges | String | Privileges associated with the process. | 
| CarbonBlackDefense.Events.Results.process_product_name | String | Product name associated with the process. | 
| CarbonBlackDefense.Events.Results.process_product_version | String | Product version associated with the process. | 
| CarbonBlackDefense.Events.Results.process_publisher | String | Publisher of the process. | 
| CarbonBlackDefense.Events.Results.process_publisher_state | String | Publisher state of the process. | 
| CarbonBlackDefense.Events.Results.process_reputation | String | Reputation of the process. | 
| CarbonBlackDefense.Events.Results.process_service_name | String | Service name associated with the process. | 
| CarbonBlackDefense.Events.Results.process_sha256 | String | SHA-256 hash of the process. | 
| CarbonBlackDefense.Events.Results.process_start_time | Date | Start time of the process. | 
| CarbonBlackDefense.Events.Results.process_username | String | Username under which the process is running. | 
| CarbonBlackDefense.Events.Results.regmod_count | Number | Number of registry modifications performed by the process. | 
| CarbonBlackDefense.Events.Results.scriptload_count | Number | Number of scripts loaded by the process. | 
| CarbonBlackDefense.Events.Results.sensor_action | String | Action taken by the sensor for the event. | 
| CarbonBlackDefense.Events.Results.ttp | String | Tactics, techniques, and procedures associated with the event. | 
| CarbonBlackDefense.Events.Results.watchlist_hit | String | Indicates if the event matches a watchlist entry. | 

#### Command example
```!cbd-find-observation-results job_id=abc-1234 rows=2```
#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Events": {
            "Results": [
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "dummy_alert_id"
                    ],
                    "backend_timestamp": "2024-07-05T09:42:06.625Z",
                    "blocked_effective_reputation": "COMPANY_BLACK_LIST",
                    "blocked_hash": [
                        "dummy_bloched_hash"
                    ],
                    "blocked_name": "c:\windows\system32\sdiagnhost.exe",
                    "device_group_id": 0,
                    "device_id": 1234,
                    "device_name": "desktop-ua4omu0",
                    "device_policy_id": 1234,
                    "device_timestamp": "2024-07-05T09:39:07.695Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "CREATE_PROCESS"
                    ],
                    "event_description": "The application \"<share><link hash=\"add683a6910abbbf0e28b557fad0ba998166394932ae2aca069d9aa19ea8fe88\">C:\Windows\system32\svchost.exe -k DcomLaunch -p</link></share>\" invoked the application \"<share><link hash=\"e5ec6b5b20a16383cc953ad5e478dcdf95ba46281f4fe971673c954d4145c0c4\">c:\windows\system32\sdiagnhost.exe</link></share>\". The operation was <accent>blocked by Carbon Black</accent>.",
                    "event_id": "dummy_event_id",
                    "event_type": "childproc",
                    "ingress_time": 1720172480035,
                    "legacy": true,
                    "observation_description": " sdiagnhost.exe on the Company Black List was detected running. A Deny Policy Action was applied.",
                    "observation_id": "dummy_observation_id",
                    "observation_type": "CB_ANALYTICS",
                    "org_id": "dummy_org_id",
                    "parent_guid": "dummy_parent_guid",
                    "parent_pid": 616,
                    "process_guid": "dummy_process_guid",
                    "process_hash": [
                        "dummy_process_gash",
                        "dummy_process_hash"
                    ],
                    "process_name": "c:\windows\system32\svchost.exe",
                    "process_pid": [
                        768
                    ],
                    "process_username": [
                        "NT AUTHORITY\SYSTEM"
                    ],
                    "sensor_action": [
                        "DENY",
                        "BLOCK"
                    ]
                },
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "dummy_alert_id"
                    ],
                    "backend_timestamp": "2024-07-03T16:27:53.810Z",
                    "blocked_effective_reputation": "COMPANY_BLACK_LIST",
                    "blocked_hash": [
                        "dummy_blocked_hash"
                    ],
                    "blocked_name": "c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                    "device_group_id": 0,
                    "device_id": 1234,
                    "device_name": "desktop-ua4omu0",
                    "device_policy_id": 1234,
                    "device_timestamp": "2024-07-03T16:25:21.686Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "CREATE_PROCESS"
                    ],
                    "event_description": "The application \"<share><link hash=\"20330d3ca71d58f4aeb432676cb6a3d5b97005954e45132fb083e90782efdd50\">c:\windows\system32\backgroundtaskhost.exe</link></share>\" was prevented from accessing the file \"<share><link hash=\"9f914d42706fe215501044acd85a32d58aaef1419d404fddfa5d3b48f66ccd9f\">c:\windows\system32\windowspowershell\v1.0\powershell.exe</link></share>\" due to a <accent>Deny operation or Terminate process</accent> policy action.",
                    "event_id": "dummy_event_id",
                    "event_type": "childproc",
                    "ingress_time": 1720024053609,
                    "legacy": true,
                    "observation_description": "The application backgroundtaskhost.exe invoked another application (powershell.exe). A Deny Policy Action was applied.",
                    "observation_id": "f82a46c4395811efab18238ba409ec8f:d13802a2-e8a1-180d-8359-fdc0a8c9f007",
                    "observation_type": "CB_ANALYTICS",
                    "org_id": "dummy_org_id",
                    "parent_guid": "dummy_parent_guid",
                    "parent_pid": 768,
                    "process_guid": "dummy_process_guid",
                    "process_hash": [
                        "dummy_process_hash",
                        "dummy_process_hash"
                    ],
                    "process_name": "c:\windows\system32\backgroundtaskhost.exe",
                    "process_pid": [
                        1234
                    ],
                    "process_username": [
                        "DESKTOP-UA4OMU0\qe-admin"
                    ],
                    "sensor_action": [
                        "DENY",
                        "BLOCK"
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Defense Event Results
>|Event Id|Device Id|Enriched Event Type|
>|---|---|---|
>| 8d815dc93ab211efb74fe9e3b00b3b6a | 6685063 | CREATE_PROCESS |
>| f82a46c4395811efab18238ba409ec8f | 6685063 | CREATE_PROCESS |