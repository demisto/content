VMware Carbon Black Endpoint Standard (formerly known as Carbon Black Defense) is a next-generation antivirus + EDR in one cloud-delivered platform that stops commodity malware, advanced malware, non-malware attacks, and ransomware.
This integration was integrated and tested with version 1.1.2 of Carbon Black Endpoint Standard

## New Features in Carbon Black Endpoint Standard v2
The Carbon Black Endpoint Standard v1 integration is deprecated because Carbon Black released a new version of their API. Use the Carbon Black Endpoint Standard v2 integration instead. The following are the new features in V2.

### New Commands

The Carbon Black Endpoint Standard v2 integration supports the following new commands:
* Operations on devices:
    * [cbd-device-background-scan](#cbd-device-background-scan) Starts a background scan on a device by ID.
    * [cbd-device-background-scan-stop](#cbd-device-background-scan-stop) Stops a background scan on a device by ID.
    * [cbd-device-bypass](#cbd-device-bypass) Bypasses a device.
    * [cbd-device-unbypass](#cbd-device-unbypass) Unbypasses a device.
    * [cbd-device-policy-update](#cbd-device-policy-update) Updates the devices to the specified policy ID.
    * [cbd-device-update-sensor-version](#cbd-device-update-sensor-version) Updates the version of a sensor.
    * [cbd-device-quarantine](#cbd-device-quarantine) Quarantines the device.
    * [cbd-device-unquarantine](#cbd-device-unquarantine) Unquarantines the device.
* [cbd-alerts-search](#cbd-alerts-search) Retrieves all alerts using some arguments (query, ID, type, category) to filter the results.
* [cbd-find-events-details](#cbd-find-events-details) Retrieves details for enriched events.
* [cbd-find-events-details-results](#cbd-find-events-details-results) Retrieves the status for an enriched events detail request for a given job ID.
* [cbd-find-events-results](#cbd-find-events-results) Retrieves the result for an enriched events search request for a given job ID.
* [cbd-find-processes-results](#cbd-find-processes-results) Retrieves the results of a process search identified by the job ID.

#### Deprecated Commands in Carbon Black Endpoint Standard v1
The following commands from the Carbon Black Endpoint Standard v1 integration have been deprecated and replaced with the v2 commands as shown.

| Deprecated Command | Replaced with v2 Commands | 
| --- | --- |
| cbd-get-device-status | [cbd-device-search](#cbd-device-search) |
| cbd-get-devices-status | [cbd-device-search](#cbd-device-search) |
| cbd-change-device-status | - [cbd-device-quarantine](#cbd-device-quarantine)<br/>- [cbd-device-unquarantine](#cbd-device-unquarantine)<br/>- [cbd-device-background-scan](#cbd-device-background-scan)<br/>- [cbd-device-background-scan-stop](#cbd-device-background-scan-stop)<br/>- [cbd-device-bypass](#cbd-device-bypass)<br/>- [cbd-device-unbypass](#cbd-device-unbypass)<br/>- [cbd-device-policy-update](#cbd-device-policy-update)<br/>- [cbd-device-update-sensor-version](#cbd-device-update-sensor-version) |
| cbd-find-events | [cbd-find-events](#cbd-find-events) returns a *job_id* to use in the [cbd-find-events-results](#cbd-find-events-results) command as an argument. |
| cbd-find-processes | [cbd-find-processes](#cbd-find-processes) returns a *job_id* to use in the [cbd-find-processes-results](#cbd-find-processes-results) command as an argument. |

### Playbooks
There are 3 new playbooks:
* **Carbon Black Endpoint Standard Find Events** - Finds events using a search query (or device_id, etc.).
* **Carbon Black Endpoint Standard Find Event Details** - Receives event IDs and returns details about the event.
* **Carbon Black Endpoint Standard Find Processes** - Finds processes using a search query (or device_id, etc.).

### Mapper
**Carbon Black Endpoint Standard Mapper**.

### Layout
**Carbon Black Endpoint Standard Incoming Layout**.

### Classifier
**Carbon Black Endpoint Standard**

## Configure Carbon Black Endpoint Standard in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| URL |  | True |
| Custom API Key | This Custom API key is required for all use cases except the policy use cases. | False |
| Custom API Secret Key | This Custom API secret key is required for all use cases except the policy use cases. | False |
| Live Response API Key | This Live Response API key is required only for the policy use cases. | False |
| Live Response API Secret Key | This Live Response API secret key is required only for the policy use cases. | False |
| Organization Key | The organization unique key. This is required for all use cases \(and for fetching incidents\) except the policy use cases. | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| The type of the alert | Type of alert to be fetched. | False |
| The category of the alert. | Category of alert to be fetched \(THREAT, MONITORED\). If nothing is selected he is fetching from all categories. | False |
| Device id | The alerts related to a specific device, represented by its ID. | False |
| Policy id | The alerts related to a specific policy, represented by its ID. | False |
| Device username | The alerts related to a specific device, represented by its username. | False |
| Query | Query in Lucene syntax and/or value searches. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). |  | False |
| Maximum number of incidents per fetch |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cbd-get-alert-details
***
Get details about the events that led to an alert by its ID. This includes retrieving metadata around the alert as well as a list of all the events associated with the alert. Only API keys of type “API” can call the alerts API.

##### Required Permissions
RBAC Permissions Required - org.alerts: READ

#### Base Command

`cbd-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | The ID of the alert. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Alert.id | String | The identifier for the alert. | 
| CarbonBlackDefense.Alert.legacy_alert_id | String | The unique short ID for the alerts to support easier consumption in the UI console. Use the ID for API requests. | 
| CarbonBlackDefense.Alert.org_key | String | The unique identifier for the organization associated with the alert. | 
| CarbonBlackDefense.Alert.create_time | Date | The time the alert was created. | 
| CarbonBlackDefense.Alert.last_update_time | Date | The last time the alert was updated. | 
| CarbonBlackDefense.Alert.first_event_time | Date | The time of the first event associated with the alert. | 
| CarbonBlackDefense.Alert.last_event_time | Date | The time of the latest event associated with the alert. | 
| CarbonBlackDefense.Alert.threat_id | String | The identifier of the threat that this alert belongs to. Threats are comprised of a combination of factors that can be repeated across devices. | 
| CarbonBlackDefense.Alert.severity | Number | The threat ranking of the alert. | 
| CarbonBlackDefense.Alert.category | String | The category of the alert \(THREAT, MONITORED\). | 
| CarbonBlackDefense.Alert.device_id | Number | The identifier assigned by Carbon Black Cloud to the device associated with the alert. | 
| CarbonBlackDefense.Alert.device_os | String | The operating system of the device associated with the alert. | 
| CarbonBlackDefense.Alert.device_os_version | String | The operating system and version on the device. | 
| CarbonBlackDefense.Alert.device_name | String | The hostname of the device associated with the alert. | 
| CarbonBlackDefense.Alert.device_username | String | The username of the user logged on during the alert. If the user is not available then this may be populated with the device owner. | 
| CarbonBlackDefense.Alert.policy_id | Number | The identifier for the policy associated with the device at the time of the alert. | 
| CarbonBlackDefense.Alert.policy_name | String | The name of the policy associated with the device at the time of the alert. | 
| CarbonBlackDefense.Alert.target_value | String | The priority of the device assigned by the policy. | 
| CarbonBlackDefense.Alert.workflow.state | String | The state of the tracking system for alerts as they are triaged and resolved. The state can be OPEN or DISMISSED. | 
| CarbonBlackDefense.Alert.workflow.remediation | String | The state of the workflow of the tracking system for alerts as they are triaged and resolved. The state can be OPEN or DISMISSED. | 
| CarbonBlackDefense.Alert.workflow.last_update_time | Date | The last time the alert was updated. | 
| CarbonBlackDefense.Alert.workflow.comment | String | The comment about the workflow of the tracking system for alerts as they are triaged and resolved. | 
| CarbonBlackDefense.Alert.workflow.changed_by | String | The name of the person who changed the alert. | 
| CarbonBlackDefense.Alert.notes_present | Boolean | Indicates if notes are associated with the threat ID. | 
| CarbonBlackDefense.Alert.tags | Unknown | Tags associated with the alert \(\[ "tag1", "tag2" \]\). | 
| CarbonBlackDefense.Alert.reason | String | The description of the alert. | 
| CarbonBlackDefense.Alert.count | Number | The count of the alert. | 
| CarbonBlackDefense.Alert.report_id | String | The identifier of the report that contains the IOC. | 
| CarbonBlackDefense.Alert.report_name | String | The name of the report that contains the IOC. | 
| CarbonBlackDefense.Alert.ioc_id | String | The identifier of the IOC that caused the hit. | 
| CarbonBlackDefense.Alert.ioc_field | String | The indicator of comprise \(IOC\) field that the hit contains. | 
| CarbonBlackDefense.Alert.ioc_hit | String | IOC field value or IOC that matches the query. | 
| CarbonBlackDefense.Alert.watchlists.id | String | The ID of the watchlists associated with an alert. | 
| CarbonBlackDefense.Alert.watchlists.name | String | The name of the watchlists associated with an alert. | 
| CarbonBlackDefense.Alert.process_guid | String | The global unique identifier of the process that triggered the hit. | 
| CarbonBlackDefense.Alert.process_name | String | The name of the process that triggered the hit. | 
| CarbonBlackDefense.Alert.run_state | String | The run state for the watchlist alerts. This value is always "RAN". | 
| CarbonBlackDefense.Alert.threat_indicators.process_name | String | The name of the threat indicators that make up the threat. | 
| CarbonBlackDefense.Alert.threat_indicators.sha256 | String | The SHA-256 hash of the threat indicators that make up the threat. | 
| CarbonBlackDefense.Alert.threat_indicators.ttps | String | The tactics, techniques, and procedures \(TTPs\) of the threat indicators that make up the threat. | 
| CarbonBlackDefense.Alert.threat_cause_actor_sha256 | String | The SHA-256 hash of the threat cause actor. | 
| CarbonBlackDefense.Alert.threat_cause_actor_md5 | String | The MD5 hash of the threat cause actor. | 
| CarbonBlackDefense.Alert.threat_cause_actor_name | String | Process name or IP address of the threat actor. | 
| CarbonBlackDefense.Alert.threat_cause_reputation | String | The reputation of the threat cause. \(KNOWN_MALWARE, SUSPECT_MALWARE, PUP, NOT_LISTED, ADAPTIVE_WHITE_LIST, COMMON_WHITE_LIST, TRUSTED_WHITE_LIST, COMPANY_BLACK_LIST\). | 
| CarbonBlackDefense.Alert.threat_cause_threat_category | String | The category of the threat cause. \(UNKNOWN, NON_MALWARE, NEW_MALWARE, KNOWN_MALWARE, RISKY_PROGRAM\). | 
| CarbonBlackDefense.Alert.threat_cause_vector | String | The source of the threat cause. \(EMAIL, WEB, GENERIC_SERVER, GENERIC_CLIENT, REMOTE_DRIVE, REMOVABLE_MEDIA, UNKNOWN, APP_STORE, THIRD_PARTY\). | 
| CarbonBlackDefense.Alert.document_guid | String | The document GUID. | 
| CarbonBlackDefense.Alert.type | String | The type of alert. \(CB_ANALYTICS, DEVICE_CONTROL\). | 
| CarbonBlackDefense.Alert.reason_code | String | The shorthand enum for the full-text reason. | 
| CarbonBlackDefense.Alert.device_location | String | Whether the device was on-premise or off-premise when the alert started. \(ONSITE, OFFSITE, UNKNOWN\). | 
| CarbonBlackDefense.Alert.created_by_event_id | String | Event identifier that initiated the alert. | 
| CarbonBlackDefense.Alert.threat_activity_dlp | String | Whether the alert involved data loss prevention \(DLP\). \(NOT_ATTEMPTED, ATTEMPTED, SUCCEEDED\). | 
| CarbonBlackDefense.Alert.threat_activity_phish | String | Whether the alert involved phishing. \(NOT_ATTEMPTED, ATTEMPTED, SUCCEEDED\). | 
| CarbonBlackDefense.Alert.threat_activity_c2 | String | Whether the alert involved a command and control \(c2\) server. \(NOT_ATTEMPTED, ATTEMPTED, SUCCEEDED\). | 
| CarbonBlackDefense.Alert.threat_cause_actor_process_pid | String | The process identifier \(PID\) of the actor process. | 
| CarbonBlackDefense.Alert.threat_cause_process_guid | String | The GUID of the process. | 
| CarbonBlackDefense.Alert.threat_cause_parent_guid | String | The parent GUID of the process. | 
| CarbonBlackDefense.Alert.threat_cause_cause_event_id | String | The threat cause cause event ID. | 
| CarbonBlackDefense.Alert.blocked_threat_category | String | The category of the threat on which we were able to take action. \(UNKNOWN, NON_MALWARE, NEW_MALWARE, KNOWN_MALWARE, RISKY_PROGRAM\). | 
| CarbonBlackDefense.Alert.not_blocked_threat_category | String | Other potentially malicious activity involved in the threat on which we weren’t able to take action \(either due to policy config, or not having a relevant rule\). \(UNKNOWN, NON_MALWARE, NEW_MALWARE, KNOWN_MALWARE, RISKY_PROGRAM\). | 
| CarbonBlackDefense.Alert.kill_chain_status | String | The stage within the Cyber Kill Chain sequence most closely associated with the attributes of the alert. \(RECONNAISSANCE, WEAPONIZE, DELIVER_EXPLOIT, INSTALL_RUN, COMMAND_AND_CONTROL, EXECUTE_GOAL, BREACH\). For example \[ "EXECUTE_GOAL", "BREACH" \]. | 
| CarbonBlackDefense.Alert.sensor_action | String | The action taken by the sensor, according to the rule of the policy. \(POLICY_NOT_APPLIED, ALLOW, ALLOW_AND_LOG, TERMINATE, DENY\). | 
| CarbonBlackDefense.Alert.policy_applied | String | Whether a policy was applied. \(APPLIED, NOT_APPLIED\). | 


#### Command Example
```!cbd-get-alert-details alertId=3d541e1d-8930-4651-85c3-8cd9728d9776```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Alert": {
            "category": "THREAT",
            "count": 0,
            "create_time": "2021-04-04T10:42:54.143Z",
            "device_id": 5678,
            "device_name": "AB\\winABCL-1234",
            "device_os": "WINDOWS",
            "device_os_version": null,
            "device_username": "jon@example.com",
            "document_guid": "1a2b3c4d",
            "first_event_time": "2021-04-04T10:39:55.946Z",
            "id": "1234",
            "ioc_field": null,
            "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
            "ioc_id": "565633-0",
            "last_event_time": "2021-04-04T10:39:55.946Z",
            "last_update_time": "2021-04-04T10:42:54.143Z",
            "legacy_alert_id": "ABCD-1234",
            "notes_present": false,
            "org_key": "7DESJ9GN",
            "policy_id": 6525,
            "policy_name": "default",
            "process_guid": "7DESJ9GN-003e6d59-00000498-00000000-1d70b726e2c3359",
            "process_name": "svchost.exe",
            "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
            "report_id": "ABCD-1234",
            "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
            "run_state": "RAN",
            "severity": 1,
            "tags": null,
            "target_value": "LOW",
            "threat_cause_actor_md5": "36f670d89040709013f6a460176767ec",
            "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
            "threat_cause_actor_sha256": "438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7",
            "threat_cause_reputation": "TRUSTED_WHITE_LIST",
            "threat_cause_threat_category": "UNKNOWN",
            "threat_cause_vector": "UNKNOWN",
            "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
            "threat_indicators": [
                {
                    "process_name": "svchost.exe",
                    "sha256": "1a2b3c4d",
                    "ttps": [
                        "565633-0"
                    ]
                }
            ],
            "type": "WATCHLIST",
            "watchlists": [
                {
                    "id": "1234",
                    "name": "ATT&CK Framework"
                }
            ],
            "workflow": {
                "changed_by": "Carbon Black",
                "comment": null,
                "last_update_time": "2021-04-04T10:42:05.900Z",
                "remediation": null,
                "state": "OPEN"
            }
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Get Alert Details
>|Id|Category|Device Id|Device Name|Device Username|Create Time|Ioc Hit|Policy Name|Process Name|Type|Severity|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 1234 | THREAT | 5678 | AB\winABC-123 | jon@example.com | 2021-04-04T10:42:54.143Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |


### cbd-device-search
***
Searches devices in your organization.

##### Required Permissions
RBAC Permissions Required - device: READ

#### Base Command

`cbd-device-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The identifier for the device. | Optional | 
| os | The operating system. Possible values: "WINDOWS", "MAC", "LINUX", and "OTHER". Possible values are: WINDOWS, MAC, LINUX, OTHER. | Optional | 
| status | The status of the device. Possible values: "PENDING", "REGISTERED", "DEREGISTERED", "BYPASS", "ACTIVE", "INACTIVE", "ERROR", "ALL", "BYPASS_ON", "LIVE", "SENSOR_PENDING_UPDATE". Possible values are: PENDING, REGISTERED, DEREGISTERED, BYPASS, ACTIVE, INACTIVE, ERROR, ALL, BYPASS_ON, LIVE, SENSOR_PENDING_UPDATE. | Optional | 
| start_time | The time to start getting results. specified as ISO-8601 strings for example: "2021-01-27T12:43:26.243Z". | Optional | 
| target_priority | The “Target value” configured in the policy assigned to the sensor. Possible values: "LOW", "MEDIUM", "HIGH", "MISSION_CRITICAL". Possible values are: LOW, MEDIUM, HIGH, MISSION_CRITICAL. | Optional | 
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
| CarbonBlackDefense.Device.device_owner_id | Number | The identifier for the device owner associated with the device. | 
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
| CarbonBlackDefense.Device.mac_address | String | The media access control \(MAC\) address for the device’s primary interface. \(Requires Windows CBC sensor version 3.6.0.1941 or later, or macOS CBC sensor\). | 
| CarbonBlackDefense.Device.middle_name | String | The middle name of the device owner. | 
| CarbonBlackDefense.Device.name | String | The hostname of the endpoint recorded by the sensor when last initialized. | 
| CarbonBlackDefense.Device.organization_id | Number | The organization identifier. | 
| CarbonBlackDefense.Device.organization_name | String | The organization name. | 
| CarbonBlackDefense.Device.os | String | The operating system. \(WINDOWS, MAC, LINUX, OTHER\). | 
| CarbonBlackDefense.Device.os_version | String | The operating system and version of the endpoint. | 
| CarbonBlackDefense.Device.passive_mode | Boolean | Whether the device is in bypass mode. | 
| CarbonBlackDefense.Device.policy_id | Number | The policy identifier assigned to the device. | 
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
| CarbonBlackDefense.Device.vdi_base_device | Number | The identifier of the device from which this device was cloned/re-registered. | 
| CarbonBlackDefense.Device.virtual_machine | Boolean | Whether this device is a virtual machine \(VMware AppDefense integration\). Deprecated for deployment_type. | 
| CarbonBlackDefense.Device.virtualization_provider | String | The name of the VM virtualization provider. | 
| CarbonBlackDefense.Device.vm_ip | String | The IP address of the VM. | 
| CarbonBlackDefense.Device.vm_name | String | The name of the VM that the sensor is deployed on. | 
| CarbonBlackDefense.Device.vm_uuid | String | The 128-bit SMBIOS UUID of a virtual machine represented as a hexadecimal string. \(Format: 12345678-abcd-1234-cdef-123456789abc\). | 
| CarbonBlackDefense.Device.vulnerability_score | Number | The vulnerability score from 0 to 100 indicating the workload’s level of vulnerability with 100 being highly vulnerable. | 
| CarbonBlackDefense.Device.vulnerability_severity | String | The severity level indicating the workload’s vulnerability. \(CRITICAL, MODERATE, IMPORTANT, LOW\). | 
| CarbonBlackDefense.Device.windows_platform | String | Deprecated for os_version. \(CLIENT_X86, CLIENT_X64, SERVER_X86, SERVER_X64, CLIENT_ARM64, SERVER_ARM64\). | 


#### Command Example
```!cbd-device-search```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Device": [
            {
                "activation_code": null,
                "activation_code_expiry_time": "2020-10-27T13:49:46.641Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": null,
                "av_engine": "",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": null,
                "av_update_servers": null,
                "av_vdf_version": null,
                "cluster_name": null,
                "current_sensor_policy_name": "test",
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
                        "key_value": "11.1.1",
                        "position": 0
                    }
                ],
                "device_owner_id": 556712,
                "email": "squee",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "id": 1234,
                "last_contact_time": "2021-04-04T13:29:14.616Z",
                "last_device_policy_changed_time": "2021-03-22T18:02:05.742Z",
                "last_device_policy_requested_time": "2021-03-22T18:02:57.571Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "8.8.8.8",
                "last_location": "UNKNOWN",
                "last_name": null,
                "last_policy_updated_time": "2021-03-08T21:03:41.776Z",
                "last_reported_time": "2021-04-04T13:29:14.440Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": null,
                "mac_address": null,
                "middle_name": null,
                "name": "bo1tapsandbox-01",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "LINUX",
                "os_version": "CentOS 7.9-2009",
                "passive_mode": false,
                "policy_id": 63139,
                "policy_name": "LRDemo-JH",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-10-20T13:49:46.675Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_kit_type": "RHEL",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "LIVE_RESPONSE_NOT_RUNNING",
                    "LIVE_RESPONSE_ENABLED",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "ACTIVE"
                ],
                "sensor_version": "2.9.0.312585",
                "status": "REGISTERED",
                "target_priority": "MEDIUM",
                "uninstall_code": "TS3HIY27",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": true,
                "virtualization_provider": "VMW_ESX",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": "VQ6IT3",
                "activation_code_expiry_time": "2020-12-25T00:24:45.326Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "1.2.3.4",
                "av_engine": "4.14.3.454-ave.1.1.1.1:avpack.2.2.2.2:vdf.3.3.3.3:apc.4.4.4.4",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "1.2.3.4",
                "av_product_version": "4.14.3.454",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "1.2.3.4",
                "cluster_name": null,
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
                        "key_value": "10.33.4",
                        "position": 0
                    },
                    {
                        "key_name": "AD_LDAP",
                        "key_value": "OU=Domain Controllers,DC=redteam,DC=aelladata,DC=com",
                        "position": 0
                    }
                ],
                "device_owner_id": 605596,
                "email": "jon@example.ai",
                "encoded_activation_code": "L8ANCTWT9P7",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Yubao",
                "id": 5678,
                "last_contact_time": "2021-04-04T13:29:14.056Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:32.072Z",
                "last_device_policy_requested_time": "2021-04-04T13:27:44.316Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "8.8.8.8",
                "last_location": "OFFSITE",
                "last_name": "Zhang",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T13:19:54.003Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "000c290c520c",
                "middle_name": null,
                "name": "REDTEAM\\malware-gen2",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows Server 2016 x64",
                "passive_mode": true,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-12-18T03:58:59.811Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_kit_type": "WINDOWS",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "DRIVER_INIT_ERROR",
                    "LIVE_RESPONSE_NOT_RUNNING",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "LIVE_RESPONSE_ENABLED",
                    "SECURITY_CENTER_OPTLN_DISABLED"
                ],
                "sensor_version": "3.6.0.1941",
                "status": "BYPASS",
                "target_priority": "LOW",
                "uninstall_code": "PDLHMMYF",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": true,
                "virtualization_provider": "VMW_ESX",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": "EYIAHV",
                "activation_code_expiry_time": "2021-02-25T20:58:03.232Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "5.5.5.5",
                "av_engine": "1.1.1.1-ave.2.2.2.2:avpack.3.3.3.3:vdf.4.4.4.4",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "5.5.5.5",
                "av_product_version": "4.14.3.454",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "5.5.5.5",
                "cluster_name": null,
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
                        "key_value": "172.16.15",
                        "position": 0
                    }
                ],
                "device_owner_id": 605966,
                "email": "jon@example.com",
                "encoded_activation_code": "2VNKDLWE3UT",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Brandon",
                "id": 9101,
                "last_contact_time": "2021-04-04T13:29:13.643Z",
                "last_device_policy_changed_time": "2021-03-31T20:11:50.835Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:52.963Z",
                "last_external_ip_address": "1.1.1.1",
                "last_internal_ip_address": "8.8.8.8",
                "last_location": "OFFSITE",
                "last_name": "Van Pelt",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T05:28:57.161Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "RTEST\\opryadko",
                "mac_address": "0050569fdd57",
                "middle_name": null,
                "name": "AB\\ABC-123-Win10E",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2021-02-18T18:22:10.545Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_kit_type": "WINDOWS",
                "sensor_out_of_date": true,
                "sensor_pending_update": false,
                "sensor_states": [
                    "ACTIVE",
                    "LIVE_RESPONSE_NOT_RUNNING",
                    "LIVE_RESPONSE_NOT_KILLED",
                    "LIVE_RESPONSE_ENABLED",
                    "SECURITY_CENTER_OPTLN_DISABLED"
                ],
                "sensor_version": "3.6.0.1979",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "KMVSAQLT",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": true,
                "virtualization_provider": "VMW_ESX",
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

>### Carbon Black Endpoint Standard Devices List Results
>|Id|Name|Os|Policy Name|Quarantined|Status|Target Priority|Last Internal Ip Address|Last External Ip Address|Last Contact Time|Last Location|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 1234 | bo1tapsandbox-01 | LINUX | LRDemo-JH | false | REGISTERED | MEDIUM | 8.8.8.8 | 1.1.1.1 | 2021-04-04T13:29:14.616Z | UNKNOWN |
>| 5678 | REDTEAM\malware-gen2 | WINDOWS | default | false | BYPASS | LOW | 8.8.8.8 | 1.1.1.1 | 2021-04-04T13:29:14.056Z | OFFSITE |
>| 9101 | RTEST\Oleg-TB2-Win10E | WINDOWS | default | false | REGISTERED | LOW | 8.8.8.8 | 1.1.1.1 | 2021-04-04T13:29:13.643Z | OFFSITE |

### cbd-find-processes
***
Creates a process search job. The results for the search job may be requested using the returned job ID. At least one of the arguments (not including: rows, start, and time_range) is required.

##### Required Permissions
RBAC Permissions Required - org.search.events: CREATE

#### Base Command

`cbd-find-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_category | The Carbon Black Cloud classification for events tagged to an alert. Possible values: "THREAT" and "OBSERVED". Possible values are: THREAT, OBSERVED. | Optional | 
| hash | Aggregate set of MD5 and SHA-256 hashes associated with the process (including childproc_hash, crossproc_hash, filemod_hash, modload_hash, process_hash). | Optional | 
| device_external_ip | The IP address of the endpoint according to Carbon Black Cloud. This IP address can differ from the device_internal_ip due to network proxy or NAT. Can be either IPv4 or IPv6 format. | Optional | 
| device_id | The ID assigned to the endpoint by Carbon Black Cloud. This ID is unique across all Carbon Black Cloud environments. | Optional | 
| device_internal_ip | The IP address of the endpoint reported by the sensor. Can be either IPv4 or IPv6 format. | Optional | 
| device_name | The hostname of the endpoint recorded by the sensor when last initialized. | Optional | 
| device_os | The operating system of the endpoint. Possible values: "WINDOWS", "MAC", "LINUX". Possible values are: WINDOWS, MAC, LINUX. | Optional | 
| device_timestamp | The sensor-reported timestamp of the batch of events in which this record was submitted to Carbon Black Cloud. specified as ISO 8601 timestamp in UTC for example: 2020-01-19T04:28:40.190Z. | Optional | 
| event_type | The type of enriched event observed. Possible value: "filemod", "netconn", "regmod", "modload", "crossproc", "childproc", "scriptload", and "fileless_scriptload". Possible values are: filemod, netconn, regmod, modload, crossproc, childproc, scriptload, fileless_scriptload. | Optional | 
| parent_name | The file system path of the parent process binary. | Optional | 
| parent_reputation | The reputation of the parent process applied by Carbon Black Cloud when the event is initially processed. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". Possible values are: ADAPTIVE_WHITE_LIST, ADWARE, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, HEURISTIC, IGNORE, KNOWN_MALWARE, LOCAL_WHITE, NOT_LISTED, PUP, RESOLVING, SUSPECT_MALWARE, TRUSTED_WHITE_LIST. | Optional | 
| process_cmdline | The command line executed by the actor process. | Optional | 
| process_guid | The unique process identifier for the actor process. | Optional | 
| process_name | The file system path of the actor process binary. | Optional | 
| process_pid | The process identifier assigned by the operating system. This can be multi-valued in case of fork() or exec() process operations on Linux and macOS. | Optional | 
| process_reputation | The reputation of the actor process applied when the event is processed by Carbon Black Cloud. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". Possible values are: ADAPTIVE_WHITE_LIST, ADWARE, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, HEURISTIC, IGNORE, KNOWN_MALWARE, LOCAL_WHITE, NOT_LISTED, PUP, RESOLVING, SUSPECT_MALWARE, TRUSTED_WHITE_LIST. | Optional | 
| process_start_time | The sensor reported timestamp of when the process started. specified as ISO 8601 timestamp in UTC for example: 2020-05-04T21:34:03.968Z. This is not available for processes running before the sensor starts. | Optional | 
| process_terminated | Whether the process has terminated. Possible values: "true" and "false". Always "false" for enriched events (process termination not recorded). Possible values are: true, false. | Optional | 
| process_username | The user context in which the actor process was executed.<br/>MacOS - all users for the PID for fork() and exec() transitions.<br/>Linux - process user for exec() events, but in a future sensor release can be multi-valued due to setuid(). | Optional | 
| sensor_action | The action performed by the sensor on the process. Possible values: "TERMINATE", "DENY", and "SUSPEND". Possible values are: TERMINATE, DENY, SUSPEND. | Optional | 
| query | The query in Lucene syntax and/or value searches. | Optional | 
| rows | The number of rows to request. Can be paginated. | Optional | 
| start | The first row to use for pagination. | Optional | 
| time_range | The time window in which to restrict the search to match using device_timestamp as the reference. The window value will take priority over the start and end times if provided. For example {"end": "2020-01-21T18:34:04Z", "start": "2020-01-18T18:34:04Z", "window": "-2w"}, window: “-2w” (where y=year, w=week, d=day, h=hour, m=minute, s=second) start: ISO 8601 timestamp, end: ISO 8601 timestamp. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Process.Search.job_id | String | The job ID of the process search. | 


#### Command Example
```!cbd-find-processes query=chrome```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Process": {
            "Search": {
                "job_id": "f5a2ae0e-c3f7-4443-882d-009097eaabd3"
            }
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Processes Search
>|Job Id|
>|---|
>| f5a2ae0e-c3f7-4443-882d-009097eaabd3 |


### cbd-find-events
***
Creates an enriched events search job. The results for the search job may be requested using the returned job ID. At least one of the arguments (not including: rows, start, time_range) is required).

##### Required Permissions
RBAC Permissions Required - org.search.events: CREATE

#### Base Command

`cbd-find-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_category | The Carbon Black Cloud classification for events tagged to an alert. Possible values: "THREAT" and "OBSERVED". Possible values are: THREAT, OBSERVED. | Optional | 
| hash | Aggregate set of MD5 and SHA-256 hashes associated with the process (including childproc_hash, crossproc_hash, filemod_hash, modload_hash, process_hash). | Optional | 
| device_external_ip | The IP address of the endpoint according to Carbon Black Cloud. This IP address can differ from the device_internal_ip due to network proxy or NAT. Can be either IPv4 or IPv6 format. | Optional | 
| device_id | The ID assigned to the endpoint by Carbon Black Cloud. This ID is unique across all Carbon Black Cloud environments. | Optional | 
| device_internal_ip | The IP address of the endpoint reported by the sensor. Can be either IPv4 or IPv6 format. | Optional | 
| device_name | The hostname of the endpoint recorded by the sensor when last initialized. | Optional | 
| device_os | The operating system of the endpoint. Possible values: "WINDOWS", "MAC", "LINUX". Possible values are: WINDOWS, MAC, LINUX. | Optional | 
| event_type | The type of enriched event observed. Possible value: "filemod", "netconn", "regmod", "modload", "crossproc", "childproc", "scriptload", and "fileless_scriptload". Possible values are: filemod, netconn, regmod, modload, crossproc, childproc, scriptload, fileless_scriptload. | Optional | 
| parent_name | The file system path of the parent process binary. | Optional | 
| parent_reputation | The reputation of the parent process applied by Carbon Black Cloud when the event is initially processed. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". Possible values are: ADAPTIVE_WHITE_LIST, ADWARE, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, HEURISTIC, IGNORE, KNOWN_MALWARE, LOCAL_WHITE, NOT_LISTED, PUP, RESOLVING, SUSPECT_MALWARE, TRUSTED_WHITE_LIST. | Optional | 
| process_cmdline | The command line executed by the actor process. | Optional | 
| process_guid | The unique process identifier for the actor process. | Optional | 
| process_name | The file system path of the actor process binary. | Optional | 
| process_pid | The process identifier assigned by the operating system. This can be multi-valued in case of fork() or exec() process operations on Linux and macOS. | Optional | 
| process_reputation | The reputation of the actor process applied when the event is processed by Carbon Black Cloud. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". Possible values are: ADAPTIVE_WHITE_LIST, ADWARE, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, HEURISTIC, IGNORE, KNOWN_MALWARE, LOCAL_WHITE, NOT_LISTED, PUP, RESOLVING, SUSPECT_MALWARE, TRUSTED_WHITE_LIST. | Optional | 
| process_start_time | The sensor reported timestamp of when the process started. specified as ISO 8601 timestamp in UTC for example: 2020-05-04T21:34:03.968Z. This is not available for processes running before the sensor starts. | Optional | 
| process_terminated | Whether the process has terminated. Possible values: "true" and "false". Always "false" for enriched events (process termination not recorded). Possible values are: true, false. | Optional | 
| process_username | The user context in which the actor process was executed.<br/>MacOS - all users for the PID for fork() and exec() transitions.<br/>Linux - process user for exec() events, but in a future sensor release can be multi-valued due to setuid(). | Optional | 
| sensor_action | The action performed by the sensor on the process. Possible values: "TERMINATE", "DENY", and "SUSPEND". Possible values are: TERMINATE, DENY, SUSPEND. | Optional | 
| query | The query in Lucene syntax and/or value searches. | Optional | 
| rows | The number of rows to request. Can be paginated. | Optional | 
| start | The first row to use for pagination. | Optional | 
| time_range | The time window in which to restrict the search to match using device_timestamp as the reference. The window value will take priority over the start and end times if provided. For example {"end": "2020-01-21T18:34:04Z", "start": "2020-01-18T18:34:04Z", "window": "-2w"}, window: “-2w” (where y=year, w=week, d=day, h=hour, m=minute, s=second) start: ISO 8601 timestamp, end: ISO 8601 timestamp. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Events.Search.job_id | String | The job ID of the event search. | 


#### Command Example
```!cbd-find-events query=chrome```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Events": {
            "Search": {
                "job_id": "b853bf18-d1f3-4dcc-b590-6626ee547bec"
            }
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Events Search
>|Job Id|
>|---|
>| b853bf18-d1f3-4dcc-b590-6626ee547bec |


### cbd-find-processes-results
***
Retrieves the results of a process search identified by the job ID.

##### Required Permissions
RBAC Permissions Required - org.search.events: READ

#### Base Command

`cbd-find-processes-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. | Required | 
| rows | The number of rows to request. Can be paginated. Default is 10. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Process.Results.job_id | String | The results of the process search. | 
| CarbonBlackDefense.Process.Results.approximate_unaggregated | Number | The approximate number of unaggregated results. | 
| CarbonBlackDefense.Process.Results.completed | Number | The number of completed results. | 
| CarbonBlackDefense.Process.Results.contacted | Number | The number of contacted results. | 
| CarbonBlackDefense.Process.Results.num_aggregated | Number | The number of aggregated results. | 
| CarbonBlackDefense.Process.Results.num_available | Number | The number of processes available in this search. | 
| CarbonBlackDefense.Process.Results.num_found | Number | The number of processes found in this search. | 
| CarbonBlackDefense.Process.Results.results | Unknown | The lists that contains the data of the results for this search. | 


#### Command Example
```!cbd-find-processes-results job_id=a79f5a25-5ab4-4df7-b806-62e0aedd7034```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Process": {
            "Results": {
                "job_id": "a79f5a25-5ab4-4df7-b806-62e0aedd7034",
                "approximate_unaggregated": 35890,
                "completed": 47,
                "contacted": 47,
                "num_aggregated": 3230,
                "num_available": 500,
                "num_found": 35890,
                "results": [
                    {
                        "backend_timestamp": "2021-04-04T11:14:46.886Z",
                        "device_group_id": 0,
                        "device_id": 1234,
                        "device_name": "vm-2k12-vg63",
                        "device_policy_id": 1234,
                        "device_timestamp": "2021-04-04T11:13:52.850Z",
                        "enriched": true,
                        "enriched_event_type": [
                            "NETWORK"
                        ],
                        "event_type": [
                            "netconn"
                        ],
                        "ingress_time": 1617534862426,
                        "legacy": true,
                        "org_id": "7DESJ9GN",
                        "process_guid": "7DESJ9GN-003ecd38-002005cc-00000000-1d719ba5c26912d",
                        "process_hash": [
                            "402a3d06bc6c0051e65c91e1bddac9d7",
                            "cbc104fcc03cb2acbdafc2fe2669e8da54993f8d21d8851d4d80ecec26a3a9f0"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            2098636
                        ],
                        "process_username": [
                            "VM-2K12-VG63\\Administrator"
                        ]
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:15:17.238Z",
                        "childproc_count": 0,
                        "crossproc_count": 389,
                        "device_group_id": 0,
                        "device_id": 5678,
                        "device_name": "development\\vm-beats-dev",
                        "device_policy_id": 1234,
                        "device_timestamp": "2021-04-04T11:13:38.546Z",
                        "enriched": true,
                        "enriched_event_type": [
                            "NETWORK"
                        ],
                        "event_type": [
                            "netconn"
                        ],
                        "filemod_count": 21432,
                        "ingress_time": 1617534886234,
                        "legacy": true,
                        "modload_count": 252,
                        "netconn_count": 3388,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003b7b6c-00001e8c-00000000-1d716fd3d5cd170",
                        "parent_pid": 7820,
                        "process_guid": "7DESJ9GN-003b7b6c-00000bb4-00000000-1d716fd3ea4f2fa",
                        "process_hash": [
                            "6bfe4850808952622e41f88db244393b",
                            "8ceee04d6316e2ba04fdf2222506fc8be7b3cd158d843c4edc23d8de5e2f77d9"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            2996
                        ],
                        "process_username": [
                            "AB\\example.process"
                        ],
                        "regmod_count": 0,
                        "scriptload_count": 0
                    },
                    {
                        "alert_category": [
                            "THREAT"
                        ],
                        "alert_id": [
                            "null/115E98DB"
                        ],
                        "backend_timestamp": "2021-04-04T11:15:17.238Z",
                        "childproc_count": 862,
                        "crossproc_count": 530,
                        "device_group_id": 0,
                        "device_id": 9101,
                        "device_name": "development\\vm-beats-dev",
                        "device_policy_id": 1234,
                        "device_timestamp": "2021-04-04T11:12:41.447Z",
                        "enriched": true,
                        "enriched_event_type": [
                            "CREATE_PROCESS"
                        ],
                        "event_type": [
                            "childproc"
                        ],
                        "filemod_count": 43922,
                        "ingress_time": 1617534886234,
                        "legacy": true,
                        "modload_count": 1239,
                        "netconn_count": 807,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003b7b6c-000006a0-00000000-1d7166c204a7a5a",
                        "parent_pid": 1696,
                        "process_guid": "7DESJ9GN-003b7b6c-00001e8c-00000000-1d716fd3d5cd170",
                        "process_hash": [
                            "6bfe4850808952622e41f88db244393b",
                            "8ceee04d6316e2ba04fdf2222506fc8be7b3cd158d843c4edc23d8de5e2f77d9"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            7820
                        ],
                        "process_username": [
                            "AB\\example.process"
                        ],
                        "regmod_count": 117,
                        "scriptload_count": 0
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### The Results For The Process Search
>|Device Id|Device Name|Process Name|Device Policy Id|Enriched Event Type|
>|---|---|---|---|---|
>| 1234 | vm-2k12-vg63 | c:\program files (x86)\google\chrome\application\chrome.exe | 1234 | NETWORK |
>| 5678 | development\vm-beats-dev | c:\program files (x86)\google\chrome\application\chrome.exe | 1234 | NETWORK |
>| 9101 | development\vm-beats-dev | c:\program files (x86)\google\chrome\application\chrome.exe | 1234 | CREATE_PROCESS |


### cbd-get-policies
***
Gets the list of policies available in your organization.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-get-policies`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.id | Number | The policy ID. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The policy priority level. | 
| CarbonBlackDefense.Policy.systemPolicy | Boolean | Whether the policy is a system policy. | 
| CarbonBlackDefense.Policy.latestRevision | Number | The latest revision of the policy. | 
| CarbonBlackDefense.Policy.policy | Unknown | The policy object. | 
| CarbonBlackDefense.Policy.name | String | The unique name of the policy. | 
| CarbonBlackDefense.Policy.description | String | The description of the policy. | 
| CarbonBlackDefense.Policy.version | Number | The version of the policy. | 


#### Command Example
```!cbd-get-policies```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": [
            {
                "description": "Default Policy. Please do not edit or rename this Policy. Create your own Policy and test with that.",
                "id": 6525,
                "latestRevision": 1617343512968,
                "name": "default",
                "policy": {
                    "avSettings": {
                        "apc": {
                            "enabled": false,
                            "maxExeDelay": 45,
                            "maxFileSize": 4,
                            "riskLevel": 4
                        },
                        "features": [
                            {
                                "enabled": true,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": true,
                                "name": "ONACCESS_SCAN"
                            },
                            {
                                "enabled": true,
                                "name": "ONDEMAND_SCAN"
                            }
                        ],
                        "onAccessScan": {
                            "profile": "NORMAL"
                        },
                        "onDemandScan": {
                            "profile": "NORMAL",
                            "scanCdDvd": "AUTOSCAN",
                            "scanUsb": "AUTOSCAN",
                            "schedule": {
                                "days": null,
                                "rangeHours": 0,
                                "recoveryScanIfMissed": true,
                                "startHour": 0
                            }
                        },
                        "signatureUpdate": {
                            "schedule": {
                                "fullIntervalHours": 0,
                                "initialRandomDelayHours": 1,
                                "intervalHours": 2
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 1,
                                    "regId": null,
                                    "server": [
                                        "http://updates.cdc.carbonblack.io/update"
                                    ]
                                }
                            ],
                            "serversForOffSiteDevices": [
                                "http://updates.cdc.carbonblack.io/update"
                            ]
                        }
                    },
                    "directoryActionRules": [],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 111,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 112,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 113,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 114,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 115,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 117,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 118,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 119,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 120,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 121,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 122,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 123,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 124,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 125,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 126,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 128,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 129,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 130,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 131,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 132,
                            "operation": "CODE_INJECTION",
                            "required": false
                        }
                    ],
                    "sensorSettings": [
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
                            "value": "false"
                        },
                        {
                            "name": "ENABLE_THREAT_SHARING",
                            "value": "true"
                        },
                        {
                            "name": "QUARANTINE_DEVICE",
                            "value": "false"
                        },
                        {
                            "name": "LOGGING_LEVEL",
                            "value": "false"
                        },
                        {
                            "name": "QUARANTINE_DEVICE_MESSAGE",
                            "value": "Your device has been quarantined by your computer administrator."
                        },
                        {
                            "name": "SET_SENSOR_MODE",
                            "value": "0"
                        },
                        {
                            "name": "SENSOR_RESET",
                            "value": "0"
                        },
                        {
                            "name": "BACKGROUND_SCAN",
                            "value": "false"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": "CarbonBlack"
                        },
                        {
                            "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                            "value": "false"
                        },
                        {
                            "name": "HASH_MD5",
                            "value": "false"
                        },
                        {
                            "name": "SCAN_LARGE_FILE_READ",
                            "value": "false"
                        },
                        {
                            "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                            "value": "false"
                        },
                        {
                            "name": "DELAY_EXECUTE",
                            "value": "false"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "false"
                        },
                        {
                            "name": "BYPASS_AFTER_LOGIN_MINS",
                            "value": "0"
                        },
                        {
                            "name": "BYPASS_AFTER_RESTART_MINS",
                            "value": "0"
                        },
                        {
                            "name": "SHOW_FULL_UI",
                            "value": "true"
                        },
                        {
                            "name": "SECURITY_CENTER_OPT",
                            "value": "false"
                        },
                        {
                            "name": "CB_LIVE_RESPONSE",
                            "value": "true"
                        },
                        {
                            "name": "UNINSTALL_CODE",
                            "value": "false"
                        },
                        {
                            "name": "UBS_OPT_IN",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_EXPEDITED_SCAN",
                            "value": "false"
                        },
                        {
                            "name": "RATE_LIMIT",
                            "value": "0"
                        },
                        {
                            "name": "CONNECTION_LIMIT",
                            "value": "0"
                        },
                        {
                            "name": "QUEUE_SIZE",
                            "value": "100"
                        },
                        {
                            "name": "LEARNING_MODE",
                            "value": "0"
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": true,
                "version": 2
            },
            {
                "description": null,
                "id": 6527,
                "latestRevision": 1613421692562,
                "name": "Detection_Servers",
                "policy": {
                    "avSettings": {
                        "apc": {
                            "enabled": false,
                            "maxExeDelay": 45,
                            "maxFileSize": 4,
                            "riskLevel": 4
                        },
                        "features": [
                            {
                                "enabled": true,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": true,
                                "name": "ONACCESS_SCAN"
                            },
                            {
                                "enabled": true,
                                "name": "ONDEMAND_SCAN"
                            }
                        ],
                        "onAccessScan": {
                            "profile": "NORMAL"
                        },
                        "onDemandScan": {
                            "profile": "NORMAL",
                            "scanCdDvd": "AUTOSCAN",
                            "scanUsb": "AUTOSCAN",
                            "schedule": {
                                "days": null,
                                "rangeHours": 8,
                                "recoveryScanIfMissed": true,
                                "startHour": 20
                            }
                        },
                        "signatureUpdate": {
                            "schedule": {
                                "fullIntervalHours": 0,
                                "initialRandomDelayHours": 2,
                                "intervalHours": 2
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
                                    "regId": null,
                                    "server": [
                                        "http://updates2.cdc.carbonblack.io/update2"
                                    ]
                                }
                            ],
                            "serversForOffSiteDevices": [
                                "http://updates2.cdc.carbonblack.io/update2"
                            ]
                        }
                    },
                    "directoryActionRules": [],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 2,
                            "operation": "RANSOM",
                            "required": true
                        }
                    ],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
                        },
                        {
                            "name": "SHOW_UI",
                            "value": "false"
                        },
                        {
                            "name": "BACKGROUND_SCAN",
                            "value": "false"
                        },
                        {
                            "name": "QUARANTINE_DEVICE_MESSAGE",
                            "value": "Device has been quarantined by your computer administrator."
                        },
                        {
                            "name": "LOGGING_LEVEL",
                            "value": "false"
                        },
                        {
                            "name": "QUARANTINE_DEVICE",
                            "value": "false"
                        },
                        {
                            "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                            "value": "false"
                        },
                        {
                            "name": "HASH_MD5",
                            "value": "false"
                        },
                        {
                            "name": "SCAN_LARGE_FILE_READ",
                            "value": "false"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "false"
                        },
                        {
                            "name": "BYPASS_AFTER_LOGIN_MINS",
                            "value": "0"
                        },
                        {
                            "name": "BYPASS_AFTER_RESTART_MINS",
                            "value": "0"
                        },
                        {
                            "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                            "value": "true"
                        },
                        {
                            "name": "DELAY_EXECUTE",
                            "value": "true"
                        },
                        {
                            "name": "SECURITY_CENTER_OPT",
                            "value": "false"
                        },
                        {
                            "name": "CB_LIVE_RESPONSE",
                            "value": "false"
                        },
                        {
                            "name": "UNINSTALL_CODE",
                            "value": "false"
                        },
                        {
                            "name": "UBS_OPT_IN",
                            "value": "true"
                        }
                    ]
                },
                "priorityLevel": "HIGH",
                "systemPolicy": true,
                "version": 2
            },
            {
                "description": null,
                "id": 6528,
                "latestRevision": 1613421692592,
                "name": "Restrictive_Mac_Workstation",
                "policy": {
                    "avSettings": {
                        "apc": {
                            "enabled": false,
                            "maxExeDelay": 45,
                            "maxFileSize": 4,
                            "riskLevel": 4
                        },
                        "features": [
                            {
                                "enabled": true,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": true,
                                "name": "ONACCESS_SCAN"
                            },
                            {
                                "enabled": true,
                                "name": "ONDEMAND_SCAN"
                            }
                        ],
                        "onAccessScan": {
                            "profile": "NORMAL"
                        },
                        "onDemandScan": {
                            "profile": "NORMAL",
                            "scanCdDvd": "AUTOSCAN",
                            "scanUsb": "AUTOSCAN",
                            "schedule": {
                                "days": null,
                                "rangeHours": 8,
                                "recoveryScanIfMissed": true,
                                "startHour": 20
                            }
                        },
                        "signatureUpdate": {
                            "schedule": {
                                "fullIntervalHours": 0,
                                "initialRandomDelayHours": 2,
                                "intervalHours": 2
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
                                    "regId": null,
                                    "server": [
                                        "http://updates2.cdc.carbonblack.io/update2"
                                    ]
                                }
                            ],
                            "serversForOffSiteDevices": [
                                "http://updates2.cdc.carbonblack.io/update2"
                            ]
                        }
                    },
                    "directoryActionRules": [],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 9,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 10,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 11,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 12,
                            "operation": "RUN",
                            "required": false
                        }
                    ],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
                        },
                        {
                            "name": "SHOW_UI",
                            "value": "false"
                        },
                        {
                            "name": "BACKGROUND_SCAN",
                            "value": "false"
                        },
                        {
                            "name": "QUARANTINE_DEVICE_MESSAGE",
                            "value": "Device has been quarantined by your computer administrator."
                        },
                        {
                            "name": "LOGGING_LEVEL",
                            "value": "false"
                        },
                        {
                            "name": "QUARANTINE_DEVICE",
                            "value": "false"
                        },
                        {
                            "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                            "value": "false"
                        },
                        {
                            "name": "HASH_MD5",
                            "value": "false"
                        },
                        {
                            "name": "SCAN_LARGE_FILE_READ",
                            "value": "false"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "false"
                        },
                        {
                            "name": "BYPASS_AFTER_LOGIN_MINS",
                            "value": "0"
                        },
                        {
                            "name": "BYPASS_AFTER_RESTART_MINS",
                            "value": "0"
                        },
                        {
                            "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                            "value": "true"
                        },
                        {
                            "name": "DELAY_EXECUTE",
                            "value": "true"
                        },
                        {
                            "name": "SECURITY_CENTER_OPT",
                            "value": "false"
                        },
                        {
                            "name": "CB_LIVE_RESPONSE",
                            "value": "false"
                        },
                        {
                            "name": "UNINSTALL_CODE",
                            "value": "false"
                        },
                        {
                            "name": "UBS_OPT_IN",
                            "value": "true"
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": true,
                "version": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Policies
>|Id|Priority Level|System Policy|Latest Revision|Version|
>|---|---|---|---|---|
>| 6525 | LOW | true | 2021-04-02T06:05:12.000Z | 2 |
>| 6527 | HIGH | true | 2021-02-15T20:41:32.000Z | 2 |
>| 6528 | MEDIUM | true | 2021-02-15T20:41:32.000Z | 2 |


### cbd-get-policy
***
Retrieves a policy object by ID.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-get-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyId | The policy ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.id | Number | The policy ID. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The policy priority level. | 
| CarbonBlackDefense.Policy.systemPolicy | Boolean | Whether the policy is a system policy. | 
| CarbonBlackDefense.Policy.latestRevision | Number | The latest revision of the policy. | 
| CarbonBlackDefense.Policy.policy | Unknown | The policy object. | 
| CarbonBlackDefense.Policy.name | String | The unique name of the policy. | 
| CarbonBlackDefense.Policy.description | String | The description of the policy. | 
| CarbonBlackDefense.Policy.version | Number | The version of the policy. | 


#### Command Example
```!cbd-get-policy policyId=6527```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": null,
            "id": 6527,
            "latestRevision": 1613421692562,
            "name": "Detection_Servers",
            "policy": {
                "avSettings": {
                    "apc": {
                        "enabled": false,
                        "maxExeDelay": 45,
                        "maxFileSize": 4,
                        "riskLevel": 4
                    },
                    "features": [
                        {
                            "enabled": true,
                            "name": "SIGNATURE_UPDATE"
                        },
                        {
                            "enabled": true,
                            "name": "ONACCESS_SCAN"
                        },
                        {
                            "enabled": true,
                            "name": "ONDEMAND_SCAN"
                        }
                    ],
                    "onAccessScan": {
                        "profile": "NORMAL"
                    },
                    "onDemandScan": {
                        "profile": "NORMAL",
                        "scanCdDvd": "AUTOSCAN",
                        "scanUsb": "AUTOSCAN",
                        "schedule": {
                            "days": null,
                            "rangeHours": 8,
                            "recoveryScanIfMissed": true,
                            "startHour": 20
                        }
                    },
                    "signatureUpdate": {
                        "schedule": {
                            "fullIntervalHours": 0,
                            "initialRandomDelayHours": 2,
                            "intervalHours": 2
                        }
                    },
                    "updateServers": {
                        "servers": [
                            {
                                "flags": 0,
                                "regId": null,
                                "server": [
                                    "http://updates2.cdc.carbonblack.io/update2"
                                ]
                            }
                        ],
                        "serversForOffSiteDevices": [
                            "http://updates2.cdc.carbonblack.io/update2"
                        ]
                    }
                },
                "directoryActionRules": [],
                "id": -1,
                "knownBadHashAutoDeleteDelayMs": null,
                "rules": [
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "COMPANY_BLACK_LIST"
                        },
                        "id": 2,
                        "operation": "RANSOM",
                        "required": true
                    }
                ],
                "sensorSettings": [
                    {
                        "name": "ALLOW_UPLOADS",
                        "value": "true"
                    },
                    {
                        "name": "SHOW_UI",
                        "value": "false"
                    },
                    {
                        "name": "BACKGROUND_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "QUARANTINE_DEVICE_MESSAGE",
                        "value": "Device has been quarantined by your computer administrator."
                    },
                    {
                        "name": "LOGGING_LEVEL",
                        "value": "false"
                    },
                    {
                        "name": "QUARANTINE_DEVICE",
                        "value": "false"
                    },
                    {
                        "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "HASH_MD5",
                        "value": "false"
                    },
                    {
                        "name": "SCAN_LARGE_FILE_READ",
                        "value": "false"
                    },
                    {
                        "name": "POLICY_ACTION_OVERRIDE",
                        "value": "true"
                    },
                    {
                        "name": "ALLOW_UNINSTALL",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_NETWORK_DRIVE",
                        "value": "false"
                    },
                    {
                        "name": "BYPASS_AFTER_LOGIN_MINS",
                        "value": "0"
                    },
                    {
                        "name": "BYPASS_AFTER_RESTART_MINS",
                        "value": "0"
                    },
                    {
                        "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                        "value": "true"
                    },
                    {
                        "name": "DELAY_EXECUTE",
                        "value": "true"
                    },
                    {
                        "name": "SECURITY_CENTER_OPT",
                        "value": "false"
                    },
                    {
                        "name": "CB_LIVE_RESPONSE",
                        "value": "false"
                    },
                    {
                        "name": "UNINSTALL_CODE",
                        "value": "false"
                    },
                    {
                        "name": "UBS_OPT_IN",
                        "value": "true"
                    }
                ]
            },
            "priorityLevel": "HIGH",
            "systemPolicy": true,
            "version": 2
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Policy
>|Id|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|
>| 6527 | Detection_Servers | 2021-02-15T20:41:32.000Z | 2 | HIGH | true |


### cbd-set-policy
***
Resets policy fields.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-set-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy | The policy ID to be set. | Required | 
| keyValue | A JSON object that holds key/value pairs. The key is the field path in the policy object you want to update with a value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.id | Number | The policy ID. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The policy priority level. | 
| CarbonBlackDefense.Policy.systemPolicy | Boolean | Whether the policy is a system policy. | 
| CarbonBlackDefense.Policy.latestRevision | Number | The latest revision of the policy. | 
| CarbonBlackDefense.Policy.policy | Unknown | The policy object. | 
| CarbonBlackDefense.Policy.name | String | The unique name of the policy. | 
| CarbonBlackDefense.Policy.description | String | The description of the policy. | 
| CarbonBlackDefense.Policy.version | Number | The version of the policy. | 


#### Command Example
```!cbd-set-policy policy=123456 keyValue=`{"policyInfo": {"description": "update example", "name": "xsoar test1", "id": 123456, "policy": {"sensorSettings": [{"name": "SHOW_UI", "value": "true"}]}, "priorityLevel": "HIGH"}}````

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "update example",
            "id": 123456,
            "latestRevision": 1617542937951,
            "name": "xsoar test1",
            "policy": {
                "avSettings": {
                    "apc": {
                        "enabled": false,
                        "maxExeDelay": 45,
                        "maxFileSize": 4,
                        "riskLevel": 4
                    },
                    "features": [
                        {
                            "enabled": true,
                            "name": "SIGNATURE_UPDATE"
                        },
                        {
                            "enabled": true,
                            "name": "ONACCESS_SCAN"
                        },
                        {
                            "enabled": true,
                            "name": "ONDEMAND_SCAN"
                        }
                    ],
                    "onAccessScan": {
                        "profile": "NORMAL"
                    },
                    "onDemandScan": {
                        "profile": "NORMAL",
                        "scanCdDvd": "AUTOSCAN",
                        "scanUsb": "AUTOSCAN",
                        "schedule": {
                            "days": null,
                            "rangeHours": 0,
                            "recoveryScanIfMissed": true,
                            "startHour": 0
                        }
                    },
                    "signatureUpdate": {
                        "schedule": {
                            "fullIntervalHours": 0,
                            "initialRandomDelayHours": 1,
                            "intervalHours": 2
                        }
                    },
                    "updateServers": {
                        "servers": [
                            {
                                "flags": 1,
                                "regId": null,
                                "server": [
                                    "http://updates.cdc.carbonblack.io/update"
                                ]
                            }
                        ],
                        "serversForOffSiteDevices": [
                            "http://updates.cdc.carbonblack.io/update"
                        ]
                    }
                },
                "directoryActionRules": [],
                "id": -1,
                "knownBadHashAutoDeleteDelayMs": null,
                "rules": [],
                "sensorSettings": [
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
                        "name": "ENABLE_THREAT_SHARING",
                        "value": "true"
                    },
                    {
                        "name": "QUARANTINE_DEVICE",
                        "value": "false"
                    },
                    {
                        "name": "LOGGING_LEVEL",
                        "value": "false"
                    },
                    {
                        "name": "QUARANTINE_DEVICE_MESSAGE",
                        "value": "Your device has been quarantined by your computer administrator."
                    },
                    {
                        "name": "SET_SENSOR_MODE",
                        "value": "0"
                    },
                    {
                        "name": "SENSOR_RESET",
                        "value": "0"
                    },
                    {
                        "name": "BACKGROUND_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "POLICY_ACTION_OVERRIDE",
                        "value": "true"
                    },
                    {
                        "name": "HELP_MESSAGE",
                        "value": "CarbonBlack"
                    },
                    {
                        "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "HASH_MD5",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_LARGE_FILE_READ",
                        "value": "false"
                    },
                    {
                        "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                        "value": "true"
                    },
                    {
                        "name": "DELAY_EXECUTE",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_NETWORK_DRIVE",
                        "value": "false"
                    },
                    {
                        "name": "BYPASS_AFTER_LOGIN_MINS",
                        "value": "0"
                    },
                    {
                        "name": "BYPASS_AFTER_RESTART_MINS",
                        "value": "0"
                    },
                    {
                        "name": "SHOW_FULL_UI",
                        "value": "true"
                    },
                    {
                        "name": "SECURITY_CENTER_OPT",
                        "value": "false"
                    },
                    {
                        "name": "CB_LIVE_RESPONSE",
                        "value": "false"
                    },
                    {
                        "name": "UNINSTALL_CODE",
                        "value": "false"
                    },
                    {
                        "name": "UBS_OPT_IN",
                        "value": "true"
                    },
                    {
                        "name": "ALLOW_EXPEDITED_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "RATE_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "CONNECTION_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "QUEUE_SIZE",
                        "value": "100"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    }
                ]
            },
            "priorityLevel": "HIGH",
            "systemPolicy": false,
            "version": 2
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 123456 | update example | xsoar test1 | 2021-04-04T13:28:57.000Z | 2 | HIGH | false |


### cbd-create-policy
***
Creates a new policy on the CB Defense backend.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-create-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | A description of the policy. Can be multiple lines. | Required | 
| name | A unique one-line name for the policy. | Required | 
| priorityLevel | The priority score associated with sensors assigned to this policy. Possible values: "MISSION_CRITICAL", "HIGH", "MEDIUM", and "LOW". Possible values are: MISSION_CRITICAL, HIGH, MEDIUM, LOW. | Required | 
| policy | The JSON object containing the policy details. Make sure a valid policy object is passed. You can use the get-policy command to retrieve a similar policy object. Then you can reset some of the policy's fields with the set-policy command, and pass the edited object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.id | Number | The policy ID. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The policy priority level. | 
| CarbonBlackDefense.Policy.systemPolicy | Boolean | Whether the policy is a system policy. | 
| CarbonBlackDefense.Policy.latestRevision | Number | The latest revision of the policy. | 
| CarbonBlackDefense.Policy.policy | Unknown | The policy object. | 
| CarbonBlackDefense.Policy.name | String | The unique name of the policy. | 
| CarbonBlackDefense.Policy.description | String | The description of the policy. | 
| CarbonBlackDefense.Policy.version | Number | The version of the policy. | 


#### Command Example
```!cbd-create-policy description=`This is xsoar's test policy` name=`xsoar test3` priorityLevel=HIGH policy=`{}````

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "This is xsoar's test policy",
            "id": 67586,
            "latestRevision": 1617542929543,
            "name": "xsoar test3",
            "policy": {
                "avSettings": {
                    "apc": {
                        "enabled": false,
                        "maxExeDelay": 45,
                        "maxFileSize": 4,
                        "riskLevel": 4
                    },
                    "features": [
                        {
                            "enabled": true,
                            "name": "SIGNATURE_UPDATE"
                        },
                        {
                            "enabled": true,
                            "name": "ONACCESS_SCAN"
                        },
                        {
                            "enabled": true,
                            "name": "ONDEMAND_SCAN"
                        }
                    ],
                    "onAccessScan": {
                        "profile": "NORMAL"
                    },
                    "onDemandScan": {
                        "profile": "NORMAL",
                        "scanCdDvd": "AUTOSCAN",
                        "scanUsb": "AUTOSCAN",
                        "schedule": {
                            "days": null,
                            "rangeHours": 0,
                            "recoveryScanIfMissed": true,
                            "startHour": 0
                        }
                    },
                    "signatureUpdate": {
                        "schedule": {
                            "fullIntervalHours": 0,
                            "initialRandomDelayHours": 1,
                            "intervalHours": 2
                        }
                    },
                    "updateServers": {
                        "servers": [
                            {
                                "flags": 1,
                                "regId": null,
                                "server": [
                                    "http://updates.cdc.carbonblack.io/update"
                                ]
                            }
                        ],
                        "serversForOffSiteDevices": [
                            "http://updates.cdc.carbonblack.io/update"
                        ]
                    }
                },
                "directoryActionRules": [],
                "id": -1,
                "knownBadHashAutoDeleteDelayMs": null,
                "rules": [
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "KNOWN_MALWARE"
                        },
                        "id": 111,
                        "operation": "RUN",
                        "required": false
                    },
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "COMPANY_BLACK_LIST"
                        },
                        "id": 112,
                        "operation": "RUN",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "RESOLVING"
                        },
                        "id": 113,
                        "operation": "NETWORK",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "RESOLVING"
                        },
                        "id": 114,
                        "operation": "MEMORY_SCRAPE",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "RESOLVING"
                        },
                        "id": 115,
                        "operation": "RUN_INMEMORY_CODE",
                        "required": false
                    },
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "RESOLVING"
                        },
                        "id": 117,
                        "operation": "POL_INVOKE_NOT_TRUSTED",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "RESOLVING"
                        },
                        "id": 118,
                        "operation": "INVOKE_CMD_INTERPRETER",
                        "required": false
                    },
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "RESOLVING"
                        },
                        "id": 119,
                        "operation": "RANSOM",
                        "required": false
                    },
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "RESOLVING"
                        },
                        "id": 120,
                        "operation": "INVOKE_SCRIPT",
                        "required": false
                    },
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "RESOLVING"
                        },
                        "id": 121,
                        "operation": "CODE_INJECTION",
                        "required": false
                    },
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "PUP"
                        },
                        "id": 122,
                        "operation": "RUN",
                        "required": false
                    },
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "SUSPECT_MALWARE"
                        },
                        "id": 123,
                        "operation": "RUN",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "ADAPTIVE_WHITE_LIST"
                        },
                        "id": 124,
                        "operation": "NETWORK",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "ADAPTIVE_WHITE_LIST"
                        },
                        "id": 125,
                        "operation": "MEMORY_SCRAPE",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "ADAPTIVE_WHITE_LIST"
                        },
                        "id": 126,
                        "operation": "RUN_INMEMORY_CODE",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "ADAPTIVE_WHITE_LIST"
                        },
                        "id": 128,
                        "operation": "POL_INVOKE_NOT_TRUSTED",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "ADAPTIVE_WHITE_LIST"
                        },
                        "id": 129,
                        "operation": "INVOKE_CMD_INTERPRETER",
                        "required": false
                    },
                    {
                        "action": "TERMINATE",
                        "application": {
                            "type": "REPUTATION",
                            "value": "ADAPTIVE_WHITE_LIST"
                        },
                        "id": 130,
                        "operation": "RANSOM",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "ADAPTIVE_WHITE_LIST"
                        },
                        "id": 131,
                        "operation": "INVOKE_SCRIPT",
                        "required": false
                    },
                    {
                        "action": "DENY",
                        "application": {
                            "type": "REPUTATION",
                            "value": "ADAPTIVE_WHITE_LIST"
                        },
                        "id": 132,
                        "operation": "CODE_INJECTION",
                        "required": false
                    }
                ],
                "sensorSettings": [
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
                        "value": "false"
                    },
                    {
                        "name": "ENABLE_THREAT_SHARING",
                        "value": "true"
                    },
                    {
                        "name": "QUARANTINE_DEVICE",
                        "value": "false"
                    },
                    {
                        "name": "LOGGING_LEVEL",
                        "value": "false"
                    },
                    {
                        "name": "QUARANTINE_DEVICE_MESSAGE",
                        "value": "Your device has been quarantined by your computer administrator."
                    },
                    {
                        "name": "SET_SENSOR_MODE",
                        "value": "0"
                    },
                    {
                        "name": "SENSOR_RESET",
                        "value": "0"
                    },
                    {
                        "name": "BACKGROUND_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "POLICY_ACTION_OVERRIDE",
                        "value": "true"
                    },
                    {
                        "name": "HELP_MESSAGE",
                        "value": "CarbonBlack"
                    },
                    {
                        "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "HASH_MD5",
                        "value": "false"
                    },
                    {
                        "name": "SCAN_LARGE_FILE_READ",
                        "value": "false"
                    },
                    {
                        "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                        "value": "false"
                    },
                    {
                        "name": "DELAY_EXECUTE",
                        "value": "false"
                    },
                    {
                        "name": "SCAN_NETWORK_DRIVE",
                        "value": "false"
                    },
                    {
                        "name": "BYPASS_AFTER_LOGIN_MINS",
                        "value": "0"
                    },
                    {
                        "name": "BYPASS_AFTER_RESTART_MINS",
                        "value": "0"
                    },
                    {
                        "name": "SHOW_FULL_UI",
                        "value": "true"
                    },
                    {
                        "name": "SECURITY_CENTER_OPT",
                        "value": "false"
                    },
                    {
                        "name": "CB_LIVE_RESPONSE",
                        "value": "true"
                    },
                    {
                        "name": "UNINSTALL_CODE",
                        "value": "false"
                    },
                    {
                        "name": "UBS_OPT_IN",
                        "value": "true"
                    },
                    {
                        "name": "ALLOW_EXPEDITED_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "RATE_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "CONNECTION_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "QUEUE_SIZE",
                        "value": "100"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    }
                ]
            },
            "priorityLevel": "HIGH",
            "systemPolicy": false,
            "version": 2
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 67586 | This is xsoar's test policy | xsoar test3 | 2021-04-04T13:28:49.000Z | 2 | HIGH | false |


### cbd-delete-policy
***
Deletes a policy from the CB Defense backend. This may return an error if devices are actively assigned to the policy ID requested for deletion. Note: System policies cannot be deleted.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-delete-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyId | The policy ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-delete-policy policyId=67585```

#### Human Readable Output

>### The policy 67585 was deleted successfully
>|Message|Success|
>|---|---|
>| Success | true |


### cbd-update-policy
***
Updates an existing policy with a new policy. Note: System policies cannot be modified.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-update-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | A description of the policy. | Required | 
| name | A one-line name for the policy. | Required | 
| priorityLevel | The priority score associated with sensors assigned to this policy. Possible values: "MISSION_CRITICAL", "HIGH", "MEDIUM", and "LOW". Possible values are: MISSION_CRITICAL, HIGH, MEDIUM, LOW. | Required | 
| id | The ID of the policy to replace. | Required | 
| policy | The JSON object containing the policy details. Make sure a valid policy object is passed. For example {'sensorSettings': [{'name': 'SHOW_UI', 'value': 'false'}]}. You can use the get-policy command to retrieve the policy object you want to update. Then you can reset some of the policy's fields with the set-policy command, and pass the edited object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Policy.id | Number | The policy ID. | 
| CarbonBlackDefense.Policy.priorityLevel | String | The policy priority level. | 
| CarbonBlackDefense.Policy.systemPolicy | Boolean | Whether the policy is a system policy. | 
| CarbonBlackDefense.Policy.latestRevision | Number | The latest revision of the policy. | 
| CarbonBlackDefense.Policy.policy | Unknown | The policy object. | 
| CarbonBlackDefense.Policy.name | String | The unique name of the policy. | 
| CarbonBlackDefense.Policy.description | String | The description of the policy. | 
| CarbonBlackDefense.Policy.version | Number | The version of the policy. | 


#### Command Example
```!cbd-update-policy id=123456 description=`This is xsoar's test policy after an update` name=`xsoar test1` priorityLevel=LOW policy=`{"sensorSettings": [{"name": "SHOW_UI", "value": "false"}]}````

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "This is xsoar's test policy after an update",
            "id": 123456,
            "latestRevision": 1617542940381,
            "name": "xsoar test1",
            "policy": {
                "avSettings": {
                    "apc": {
                        "enabled": false,
                        "maxExeDelay": 45,
                        "maxFileSize": 4,
                        "riskLevel": 4
                    },
                    "features": [
                        {
                            "enabled": true,
                            "name": "SIGNATURE_UPDATE"
                        },
                        {
                            "enabled": true,
                            "name": "ONACCESS_SCAN"
                        },
                        {
                            "enabled": true,
                            "name": "ONDEMAND_SCAN"
                        }
                    ],
                    "onAccessScan": {
                        "profile": "NORMAL"
                    },
                    "onDemandScan": {
                        "profile": "NORMAL",
                        "scanCdDvd": "AUTOSCAN",
                        "scanUsb": "AUTOSCAN",
                        "schedule": {
                            "days": null,
                            "rangeHours": 0,
                            "recoveryScanIfMissed": true,
                            "startHour": 0
                        }
                    },
                    "signatureUpdate": {
                        "schedule": {
                            "fullIntervalHours": 0,
                            "initialRandomDelayHours": 1,
                            "intervalHours": 2
                        }
                    },
                    "updateServers": {
                        "servers": [
                            {
                                "flags": 1,
                                "regId": null,
                                "server": [
                                    "http://updates.cdc.carbonblack.io/update"
                                ]
                            }
                        ],
                        "serversForOffSiteDevices": [
                            "http://updates.cdc.carbonblack.io/update"
                        ]
                    }
                },
                "directoryActionRules": [],
                "id": -1,
                "knownBadHashAutoDeleteDelayMs": null,
                "rules": [],
                "sensorSettings": [
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
                        "value": "false"
                    },
                    {
                        "name": "ENABLE_THREAT_SHARING",
                        "value": "true"
                    },
                    {
                        "name": "QUARANTINE_DEVICE",
                        "value": "false"
                    },
                    {
                        "name": "LOGGING_LEVEL",
                        "value": "false"
                    },
                    {
                        "name": "QUARANTINE_DEVICE_MESSAGE",
                        "value": "Your device has been quarantined by your computer administrator."
                    },
                    {
                        "name": "SET_SENSOR_MODE",
                        "value": "0"
                    },
                    {
                        "name": "SENSOR_RESET",
                        "value": "0"
                    },
                    {
                        "name": "BACKGROUND_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "POLICY_ACTION_OVERRIDE",
                        "value": "true"
                    },
                    {
                        "name": "HELP_MESSAGE",
                        "value": "CarbonBlack"
                    },
                    {
                        "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "HASH_MD5",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_LARGE_FILE_READ",
                        "value": "false"
                    },
                    {
                        "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                        "value": "true"
                    },
                    {
                        "name": "DELAY_EXECUTE",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_NETWORK_DRIVE",
                        "value": "false"
                    },
                    {
                        "name": "BYPASS_AFTER_LOGIN_MINS",
                        "value": "0"
                    },
                    {
                        "name": "BYPASS_AFTER_RESTART_MINS",
                        "value": "0"
                    },
                    {
                        "name": "SHOW_FULL_UI",
                        "value": "true"
                    },
                    {
                        "name": "SECURITY_CENTER_OPT",
                        "value": "false"
                    },
                    {
                        "name": "CB_LIVE_RESPONSE",
                        "value": "false"
                    },
                    {
                        "name": "UNINSTALL_CODE",
                        "value": "false"
                    },
                    {
                        "name": "UBS_OPT_IN",
                        "value": "true"
                    },
                    {
                        "name": "ALLOW_EXPEDITED_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "RATE_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "CONNECTION_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "QUEUE_SIZE",
                        "value": "100"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    }
                ]
            },
            "priorityLevel": "LOW",
            "systemPolicy": false,
            "version": 2
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 123456 | This is xsoar's test policy after an update | xsoar test1 | 2021-04-04T13:29:00.000Z | 2 | LOW | false |


### cbd-add-rule-to-policy
***
Adds a new rule to an existing policy. Note: System policies cannot be modified.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-add-rule-to-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Rule action. Possible values: "TERMINATE", "IGNORE", "TERMINATE_THREAD", "ALLOW", "DENY", and "TERMINATE_PROCESS". Possible values are: TERMINATE, IGNORE, TERMINATE_THREAD, ALLOW, DENY, TERMINATE_PROCESS. | Required | 
| operation | Rule operation. Possible values are: MODIFY_SYSTEM_EXE, PASSTHRU, CRED, RANSOM, NETWORK_SERVER, POL_INVOKE_NOT_TRUSTED, IMPERSONATE, MICROPHONE_CAMERA, INVOKE_SYSAPP, NETWORK_CLIENT, BYPASS_REG, BUFFER_OVERFLOW, BYPASS_API, USER_DOC, CODE_INJECTION, BYPASS_NET, KEYBOARD, BYPASS_ALL, RUN, INVOKE_CMD_INTERPRETER, MODIFY_SYTEM_CONFIG, ESCALATE, BYPASS_FILE, RUN_AS_ADMIN, BYPASS_PROCESS, NETWORK, KERNEL_ACCESS, NETWORK_PEER, PACKED, INVOKE_SCRIPT, MEMORY_SCRAPE, BYPASS_SELF_PROTECT, TAMPER_API. | Required | 
| required | Whether the rule is required. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| type | Application type. Possible values: "REPUTATION", "SIGNED_BY", and "NAME_PATH". Possible values are: REPUTATION, SIGNED_BY, NAME_PATH. | Required | 
| value | Application value. | Required | 
| policyId | The policy ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-add-rule-to-policy action=ALLOW operation=RANSOM required=true type=REPUTATION value=COMPANY_BLACK_LIST policyId=123456```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "This is xsoar's test policy after an update",
            "id": 123456,
            "latestRevision": 1617542944659,
            "name": "xsoar test1",
            "policy": {
                "avSettings": {
                    "apc": {
                        "enabled": false,
                        "maxExeDelay": 45,
                        "maxFileSize": 4,
                        "riskLevel": 4
                    },
                    "features": [
                        {
                            "enabled": true,
                            "name": "SIGNATURE_UPDATE"
                        },
                        {
                            "enabled": true,
                            "name": "ONACCESS_SCAN"
                        },
                        {
                            "enabled": true,
                            "name": "ONDEMAND_SCAN"
                        }
                    ],
                    "onAccessScan": {
                        "profile": "NORMAL"
                    },
                    "onDemandScan": {
                        "profile": "NORMAL",
                        "scanCdDvd": "AUTOSCAN",
                        "scanUsb": "AUTOSCAN",
                        "schedule": {
                            "days": null,
                            "rangeHours": 0,
                            "recoveryScanIfMissed": true,
                            "startHour": 0
                        }
                    },
                    "signatureUpdate": {
                        "schedule": {
                            "fullIntervalHours": 0,
                            "initialRandomDelayHours": 1,
                            "intervalHours": 2
                        }
                    },
                    "updateServers": {
                        "servers": [
                            {
                                "flags": 1,
                                "regId": null,
                                "server": [
                                    "http://updates.cdc.carbonblack.io/update"
                                ]
                            }
                        ],
                        "serversForOffSiteDevices": [
                            "http://updates.cdc.carbonblack.io/update"
                        ]
                    }
                },
                "directoryActionRules": [],
                "id": -1,
                "knownBadHashAutoDeleteDelayMs": null,
                "rules": [
                    {
                        "action": "ALLOW",
                        "application": {
                            "type": "REPUTATION",
                            "value": "COMPANY_BLACK_LIST"
                        },
                        "id": 23,
                        "operation": "RANSOM",
                        "required": true
                    }
                ],
                "sensorSettings": [
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
                        "value": "false"
                    },
                    {
                        "name": "ENABLE_THREAT_SHARING",
                        "value": "true"
                    },
                    {
                        "name": "QUARANTINE_DEVICE",
                        "value": "false"
                    },
                    {
                        "name": "LOGGING_LEVEL",
                        "value": "false"
                    },
                    {
                        "name": "QUARANTINE_DEVICE_MESSAGE",
                        "value": "Your device has been quarantined by your computer administrator."
                    },
                    {
                        "name": "SET_SENSOR_MODE",
                        "value": "0"
                    },
                    {
                        "name": "SENSOR_RESET",
                        "value": "0"
                    },
                    {
                        "name": "BACKGROUND_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "POLICY_ACTION_OVERRIDE",
                        "value": "true"
                    },
                    {
                        "name": "HELP_MESSAGE",
                        "value": "CarbonBlack"
                    },
                    {
                        "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "HASH_MD5",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_LARGE_FILE_READ",
                        "value": "false"
                    },
                    {
                        "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                        "value": "true"
                    },
                    {
                        "name": "DELAY_EXECUTE",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_NETWORK_DRIVE",
                        "value": "false"
                    },
                    {
                        "name": "BYPASS_AFTER_LOGIN_MINS",
                        "value": "0"
                    },
                    {
                        "name": "BYPASS_AFTER_RESTART_MINS",
                        "value": "0"
                    },
                    {
                        "name": "SHOW_FULL_UI",
                        "value": "true"
                    },
                    {
                        "name": "SECURITY_CENTER_OPT",
                        "value": "false"
                    },
                    {
                        "name": "CB_LIVE_RESPONSE",
                        "value": "false"
                    },
                    {
                        "name": "UNINSTALL_CODE",
                        "value": "false"
                    },
                    {
                        "name": "UBS_OPT_IN",
                        "value": "true"
                    },
                    {
                        "name": "ALLOW_EXPEDITED_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "RATE_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "CONNECTION_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "QUEUE_SIZE",
                        "value": "100"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    }
                ]
            },
            "priorityLevel": "LOW",
            "systemPolicy": false,
            "version": 2
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 123456 | This is xsoar's test policy after an update | xsoar test1 | 2021-04-04T13:29:04.000Z | 2 | LOW | false |


### cbd-update-rule-in-policy
***
Updates an existing rule with a new rule. Note: System policies cannot be modified.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-update-rule-in-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Rule action. Possible values: "TERMINATE", "IGNORE", "TERMINATE_THREAD", "ALLOW", "DENY", and "TERMINATE_PROCESS". Possible values are: TERMINATE, IGNORE, TERMINATE_THREAD, ALLOW, DENY, TERMINATE_PROCESS. | Required | 
| operation | Rule operation. Possible values are: MODIFY_SYSTEM_EXE, PASSTHRU, CRED, RANSOM, NETWORK_SERVER, POL_INVOKE_NOT_TRUSTED, IMPERSONATE, MICROPHONE_CAMERA, INVOKE_SYSAPP, NETWORK_CLIENT, BYPASS_REG, BUFFER_OVERFLOW, BYPASS_API, USER_DOC, CODE_INJECTION, BYPASS_NET, KEYBOARD, BYPASS_ALL, RUN, INVOKE_CMD_INTERPRETER, MODIFY_SYTEM_CONFIG, ESCALATE, BYPASS_FILE, RUN_AS_ADMIN, BYPASS_PROCESS, NETWORK, KERNEL_ACCESS, NETWORK_PEER, PACKED, INVOKE_SCRIPT, MEMORY_SCRAPE, BYPASS_SELF_PROTECT, TAMPER_API. | Required | 
| required | Whether the rule is required. Possible values: "true" and "false". Possible values are: true, false. | Required | 
| id | Rule ID. | Required | 
| type | Application type. Possible values: "REPUTATION", "SIGNED_BY", and "NAME_PATH". Possible values are: REPUTATION, SIGNED_BY, NAME_PATH. | Required | 
| value | Application value. | Required | 
| policyId | The policy ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-update-rule-in-policy action=ALLOW operation=RANSOM required=false id=23 type=REPUTATION value=COMPANY_BLACK_LIST policyId=123456```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "This is xsoar's test policy after an update",
            "id": 123456,
            "latestRevision": 1617542947344,
            "name": "xsoar test1",
            "policy": {
                "avSettings": {
                    "apc": {
                        "enabled": false,
                        "maxExeDelay": 45,
                        "maxFileSize": 4,
                        "riskLevel": 4
                    },
                    "features": [
                        {
                            "enabled": true,
                            "name": "SIGNATURE_UPDATE"
                        },
                        {
                            "enabled": true,
                            "name": "ONACCESS_SCAN"
                        },
                        {
                            "enabled": true,
                            "name": "ONDEMAND_SCAN"
                        }
                    ],
                    "onAccessScan": {
                        "profile": "NORMAL"
                    },
                    "onDemandScan": {
                        "profile": "NORMAL",
                        "scanCdDvd": "AUTOSCAN",
                        "scanUsb": "AUTOSCAN",
                        "schedule": {
                            "days": null,
                            "rangeHours": 0,
                            "recoveryScanIfMissed": true,
                            "startHour": 0
                        }
                    },
                    "signatureUpdate": {
                        "schedule": {
                            "fullIntervalHours": 0,
                            "initialRandomDelayHours": 1,
                            "intervalHours": 2
                        }
                    },
                    "updateServers": {
                        "servers": [
                            {
                                "flags": 1,
                                "regId": null,
                                "server": [
                                    "http://updates.cdc.carbonblack.io/update"
                                ]
                            }
                        ],
                        "serversForOffSiteDevices": [
                            "http://updates.cdc.carbonblack.io/update"
                        ]
                    }
                },
                "directoryActionRules": [],
                "id": -1,
                "knownBadHashAutoDeleteDelayMs": null,
                "rules": [
                    {
                        "action": "ALLOW",
                        "application": {
                            "type": "REPUTATION",
                            "value": "COMPANY_BLACK_LIST"
                        },
                        "id": 23,
                        "operation": "RANSOM",
                        "required": false
                    }
                ],
                "sensorSettings": [
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
                        "value": "false"
                    },
                    {
                        "name": "ENABLE_THREAT_SHARING",
                        "value": "true"
                    },
                    {
                        "name": "QUARANTINE_DEVICE",
                        "value": "false"
                    },
                    {
                        "name": "LOGGING_LEVEL",
                        "value": "false"
                    },
                    {
                        "name": "QUARANTINE_DEVICE_MESSAGE",
                        "value": "Your device has been quarantined by your computer administrator."
                    },
                    {
                        "name": "SET_SENSOR_MODE",
                        "value": "0"
                    },
                    {
                        "name": "SENSOR_RESET",
                        "value": "0"
                    },
                    {
                        "name": "BACKGROUND_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "POLICY_ACTION_OVERRIDE",
                        "value": "true"
                    },
                    {
                        "name": "HELP_MESSAGE",
                        "value": "CarbonBlack"
                    },
                    {
                        "name": "PRESERVE_SYSTEM_MEMORY_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "HASH_MD5",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_LARGE_FILE_READ",
                        "value": "false"
                    },
                    {
                        "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE",
                        "value": "true"
                    },
                    {
                        "name": "DELAY_EXECUTE",
                        "value": "true"
                    },
                    {
                        "name": "SCAN_NETWORK_DRIVE",
                        "value": "false"
                    },
                    {
                        "name": "BYPASS_AFTER_LOGIN_MINS",
                        "value": "0"
                    },
                    {
                        "name": "BYPASS_AFTER_RESTART_MINS",
                        "value": "0"
                    },
                    {
                        "name": "SHOW_FULL_UI",
                        "value": "true"
                    },
                    {
                        "name": "SECURITY_CENTER_OPT",
                        "value": "false"
                    },
                    {
                        "name": "CB_LIVE_RESPONSE",
                        "value": "false"
                    },
                    {
                        "name": "UNINSTALL_CODE",
                        "value": "false"
                    },
                    {
                        "name": "UBS_OPT_IN",
                        "value": "true"
                    },
                    {
                        "name": "ALLOW_EXPEDITED_SCAN",
                        "value": "false"
                    },
                    {
                        "name": "RATE_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "CONNECTION_LIMIT",
                        "value": "0"
                    },
                    {
                        "name": "QUEUE_SIZE",
                        "value": "100"
                    },
                    {
                        "name": "LEARNING_MODE",
                        "value": "0"
                    }
                ]
            },
            "priorityLevel": "LOW",
            "systemPolicy": false,
            "version": 2
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 123456 | This is xsoar's test policy after an update | xsoar test1 | 2021-04-04T13:29:07.000Z | 2 | LOW | false |


### cbd-delete-rule-from-policy
***
Removes a rule from an existing policy. Note: System policies cannot be modified.

##### Required Permissions
Live Response Permissions Required

#### Base Command

`cbd-delete-rule-from-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policyId | The policy ID. | Required | 
| ruleId | The rule ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-delete-rule-from-policy policyId=123456 ruleId=23```

#### Human Readable Output

>### The rule was successfully deleted from the policy
>|Message|Success|
>|---|---|
>| Success | true |


### cbd-find-events-results
***
Retrieves the result for an enriched events search request for a given job ID. By default returns 10 rows.

##### Required Permissions
RBAC Permissions Required - org.search.events: READ

#### Base Command

`cbd-find-events-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. | Required | 
| rows | The number of rows to request. Can be paginated. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Events.Results.job_id | Results | The results of the event. | 
| CarbonBlackDefense.Events.Results.approximate_unaggregated | Number | The approximate number of unaggregated results. | 
| CarbonBlackDefense.Events.Results.completed | Number | The number of completed results. | 
| CarbonBlackDefense.Events.Results.contacted | Number | The number of contacted results. | 
| CarbonBlackDefense.Events.Results.num_aggregated | Number | The number of aggregated results. | 
| CarbonBlackDefense.Events.Results.num_available | Number | The number of events available in this search. | 
| CarbonBlackDefense.Events.Results.num_found | Number | The number of events found in this search. | 
| CarbonBlackDefense.Events.Results.results | Unknown | The lists that contains the data of the results for this search. | 


#### Command Example
```!cbd-find-events-results job_id=82d1df67-0edc-43e6-8e1b-c3dd9d42a3e9```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Events": {
            "Results": {
                "job_id": "82d1df67-0edc-43e6-8e1b-c3dd9d42a3e9",
                "approximate_unaggregated": 28229,
                "completed": 47,
                "contacted": 47,
                "num_aggregated": 501,
                "num_available": 500,
                "num_found": 28229,
                "results": [
                    {
                        "alert_category": [
                            "THREAT"
                        ],
                        "alert_id": [
                            "null/50534F0D"
                        ],
                        "backend_timestamp": "2021-04-04T11:09:32.762Z",
                        "blocked_hash": [
                            "2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f"
                        ],
                        "blocked_name": "c:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\cr_60f73.tmp\\setup.exe",
                        "device_group_id": 0,
                        "device_id": 1234,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:29.978Z",
                        "enriched": true,
                        "enriched_event_type": "CREATE_PROCESS",
                        "event_description": "The application \"<share><link hash=\"2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f\">C:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\cr_60f73.tmp\\setup.exe</link></share>\" invoked the application \"<share><link hash=\"2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f\">C:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\cr_60f73.tmp\\setup.exe</link></share>\". The operation was <accent>blocked</accent> and the application <accent>terminated by Cb Defense</accent>.",
                        "event_id": "1112",
                        "event_type": "childproc",
                        "ingress_time": 1617534549464,
                        "legacy": true,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ee69d-002f405c-00000000-1d72942d795d005",
                        "parent_pid": 3096668,
                        "process_guid": "7DESJ9GN-003ee69d-002f4774-00000000-1d72942d7da2d2e",
                        "process_hash": [
                            "3240e19c0dcbf7c061c8eb8b90961f12",
                            "2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\cr_60f73.tmp\\setup.exe",
                        "process_pid": [
                            3098484
                        ],
                        "process_username": [
                            "NT AUTHORITY\\SYSTEM"
                        ],
                        "sensor_action": [
                            "TERMINATE"
                        ]
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:09:43.360Z",
                        "device_group_id": 0,
                        "device_id": 5678,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:29.649Z",
                        "enriched": true,
                        "enriched_event_type": "FILE_CREATE",
                        "event_description": "The file \"<share><link hash=\"2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f\">C:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\cr_60f73.tmp\\setup.exe</link></share>\" was first detected on a local disk. The device was off the corporate network using the public address 8.8.8.8 (located in Arvada CO, United States). The file is signed and is part of Google Chrome Installer by Google LLC.  The file was created by the application \"<share><link hash=\"0b7094c2c6a97d7fb4ac08a8a03e09f0207861916eb83f4742ba9a5e73ff9846\">C:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\89.0.4389.114_chrome_installer.exe</link></share>\".",
                        "event_id": "1314",
                        "event_type": "filemod",
                        "ingress_time": 1617534549466,
                        "legacy": true,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ee69d-002f4b98-00000000-1d72942d3429066",
                        "parent_pid": 3099544,
                        "process_guid": "7DESJ9GN-003ee69d-002f405c-00000000-1d72942d795d005",
                        "process_hash": [
                            "36da6f61efcbcca63fe0df0de8136047",
                            "0b7094c2c6a97d7fb4ac08a8a03e09f0207861916eb83f4742ba9a5e73ff9846"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\89.0.4389.114_chrome_installer.exe",
                        "process_pid": [
                            3096668
                        ],
                        "process_username": [
                            "NT AUTHORITY\\SYSTEM"
                        ]
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:02:38.137Z",
                        "device_group_id": 0,
                        "device_id": 1516,
                        "device_name": "vm-2k12-vg73",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:01:17.432Z",
                        "enriched": true,
                        "enriched_event_type": "CREATE_PROCESS",
                        "event_description": "The application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" invoked the application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\". ",
                        "event_id": "9101",
                        "event_type": "childproc",
                        "ingress_time": 1617534118059,
                        "legacy": true,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ed47a-00000fa8-00000000-1d71a59d587ee82",
                        "parent_pid": 4008,
                        "process_guid": "7DESJ9GN-003ed47a-00000e60-00000000-1d71bd519bce09f",
                        "process_hash": [
                            "aa2e522a405cb5a295d3502c4ff6ca39",
                            "bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            3680
                        ],
                        "process_username": [
                            "VM-2K12-VG73\\Administrator"
                        ]
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Event Results
>|Event Id|Device Id|Event Network Remote Port|Event Network Remote Ipv4|Event Network Local Ipv4|Enriched Event Type|
>|---|---|---|---|---|---|
>| 1234 | 1112 |  |  |  | CREATE_PROCESS |
>| 5678 | 1314 |  |  |  | FILE_CREATE |
>| 9101 | 1516 |  |  |  | CREATE_PROCESS |


### cbd-find-events-details
***
Initiates a request to retrieve detail fields for enriched events.  the job_id that returns from this command can be used to get the results using the "cbd-find-events-details-results" command.

##### Required Permissions
RBAC Permissions Required - org.search.events: CREATE

#### Base Command

`cbd-find-events-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_ids | A comma-separated list of event IDs to fetch. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.EventDetails.Search.job_id | String | The job ID. | 


#### Command Example
```!cbd-find-events-details event_ids=`["b5eeb4ec953411eb8af72dacb2908592"]````

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "EventDetails": {
            "Search": {
                "job_id": "3b7c0a61-2ef5-4541-b9bb-2389bd009d32"
            }
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Event Details Search
>|Job Id|
>|---|
>| 3b7c0a61-2ef5-4541-b9bb-2389bd009d32 |


### cbd-find-events-details-results
***
Retrieves the status for an enriched events detail request for a given job ID.

##### Required Permissions
RBAC Permissions Required - org.search.events: READ

#### Base Command

`cbd-find-events-details-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.EventDetails.Results.job_id | Results | The results of the event. | 
| CarbonBlackDefense.EventDetails.Results.approximate_unaggregated | Number | The approximate number of unaggregated results. | 
| CarbonBlackDefense.EventDetails.Results.completed | Number | The number of completed results. | 
| CarbonBlackDefense.EventDetails.Results.contacted | Number | The number of contacted results. | 
| CarbonBlackDefense.EventDetails.Results.num_aggregated | Number | The number of aggregated results. | 
| CarbonBlackDefense.EventDetails.Results.num_available | Number | The number of event details available in this search. | 
| CarbonBlackDefense.EventDetails.Results.num_found | Number | The number of event details found in this search. | 
| CarbonBlackDefense.EventDetails.Results.results | Unknown | The lists that contains the data of the results for this search. | 


#### Command Example
```!cbd-find-events-details-results job_id=ee9d8548-e356-45b5-97e5-307713a56e26```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "EventDetails": {
            "Results": {
                "job_id": "ee9d8548-e356-45b5-97e5-307713a56e26",
                "approximate_unaggregated": 1,
                "completed": 46,
                "contacted": 46,
                "num_aggregated": 1,
                "num_available": 1,
                "num_found": 1,
                "results": [
                    {
                        "backend_timestamp": "2021-03-21T15:16:41.491Z",
                        "device_external_ip": "3.3.3.3",
                        "device_group_id": 0,
                        "device_id": 5678,
                        "device_installed_by": "TestSecDomain.test\\Administrator",
                        "device_internal_ip": "2.2.2.2",
                        "device_location": "OFFSITE",
                        "device_name": "testsecdomain\\win-tv9ubklp1kn",
                        "device_os": "WINDOWS",
                        "device_os_version": "Server 2012 R2 x64",
                        "device_policy": "default",
                        "device_policy_id": 6525,
                        "device_target_priority": "LOW",
                        "device_timestamp": "2021-03-21T15:10:35.067Z",
                        "document_guid": "1a2b3c4d",
                        "enriched": true,
                        "enriched_event_type": "NETWORK",
                        "event_description": "The application \"<share><link hash=\"c52b1e17afe7a2b956250c264883f6560aa5801db347f31f6845c592ef15a3a0\">C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe</link></share>\" established a <accent>UDP/443</accent> connection to <share><accent>1.1.1.1</accent></share><accent>:80</accent> (<share><accent>clientservices.googleapis.com</accent></share>, located in United States) from <share><accent>2.2.2.2</accent></share><accent>:52527</accent>. The device was off the corporate network using the public address <accent>8.8.8.8</accent> (<accent>WIN-TV9UBKLP1KN.TestSecDomain.test</accent>, located in Columbus OH, United States). The operation was successful.",
                        "event_id": "1234",
                        "event_network_inbound": false,
                        "event_network_local_ipv4": "1.1.1.1",
                        "event_network_location": ",,United States",
                        "event_network_protocol": "UDP",
                        "event_network_remote_ipv4": "8.8.8.8",
                        "event_network_remote_port": 443,
                        "event_threat_score": [
                            0
                        ],
                        "event_type": "netconn",
                        "ingress_time": 1616339792243,
                        "legacy": true,
                        "netconn_domain": "clientservices..googleapis..com",
                        "netconn_inbound": false,
                        "netconn_ipv4": -1395063613,
                        "netconn_local_ipv4": 167830793,
                        "netconn_local_port": 52527,
                        "netconn_location": ",,United States",
                        "netconn_port": 443,
                        "netconn_protocol": "PROTO_UDP",
                        "org_id": "7DESJ9GN",
                        "parent_cmdline": "\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\" ",
                        "parent_cmdline_length": 62,
                        "parent_effective_reputation": "TRUSTED_WHITE_LIST",
                        "parent_guid": "7DESJ9GN-000ca144-00001388-00000000-1d660f262b3d3f2",
                        "parent_hash": [
                            "c52b1e17afe7a2b956250c264883f6560aa5801db347f31f6845c592ef15a3a0"
                        ],
                        "parent_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "parent_pid": 5000,
                        "parent_reputation": "TRUSTED_WHITE_LIST",
                        "process_cmdline": [
                            "\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\" --type=utility --utility-sub-type=network.mojom.NetworkService --field-trial-handle=1184,13396929298740803928,12863694328792823850,131072 --lang=en-US --service-sandbox-type=network --enable-audio-service-sandbox/prefetch:8"
                        ],
                        "process_cmdline_length": [
                            322
                        ],
                        "process_effective_reputation": "TRUSTED_WHITE_LIST",
                        "process_guid": "7DESJ9GN-000ca144-000018a4-00000000-1d660f264a17328",
                        "process_hash": [
                            "5cf2e72aee581b5e3d16ff1d5c626fc6",
                            "c52b1e17afe7a2b956250c264883f6560aa5801db347f31f6845c592ef15a3a0"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            6308
                        ],
                        "process_reputation": "TRUSTED_WHITE_LIST",
                        "process_sha256": "1a2b3c4d",
                        "process_start_time": "2020-07-23T13:08:44.066Z",
                        "process_username": [
                            "TESTSECDOMAIN\\Administrator"
                        ],
                        "ttp": [
                            "NETWORK_ACCESS"
                        ]
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Event Details Results
>|Event Id|Device Id|Event Network Remote Port|Event Network Remote Ipv4|Event Network Local Ipv4|Enriched Event Type|
>|---|---|---|---|---|---|
>| 1234 | 5678 | 80 | 8.8.8.8 | 1.1.1.1 | NETWORK |


### cbd-device-quarantine
***
Quarantines the device. Not supported for devices in a Linux operating system.

##### Required Permissions
RBAC Permissions Required - device.quarantine: EXECUTE

#### Base Command

`cbd-device-quarantine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-device-quarantine device_id=123456```

#### Human Readable Output

>Device quarantine successfully

### cbd-device-unquarantine
***
Unquarantines the device. Not supported for devices in a Linux operating system.


##### Required Permissions
RBAC Permissions Required - device.quarantine: EXECUTE

#### Base Command

`cbd-device-unquarantine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-device-unquarantine device_id=123456```

#### Human Readable Output

>Device unquarantine successfully

### cbd-device-background-scan
***
Starts a background scan on the device. Not supported for devices in a Linux operating system.

##### Required Permissions
RBAC Permissions Required - device.bg-scan: EXECUTE

#### Base Command

`cbd-device-background-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-device-background-scan device_id=123456```

#### Human Readable Output

>Background scan started successfully

### cbd-device-background-scan-stop
***
Stops a background scan on the device. Not supported for devices in a Linux operating system.

##### Required Permissions
RBAC Permissions Required - device.bg-scan: EXECUTE

#### Base Command

`cbd-device-background-scan-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-device-background-scan-stop device_id=123456```

#### Human Readable Output

>Background scan stopped successfully

### cbd-device-bypass
***
Bypasses a device.

##### Required Permissions
RBAC Permissions Required - device.bypass: EXECUTE

#### Base Command

`cbd-device-bypass`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-device-bypass device_id=123456```

#### Human Readable Output

>Device bypass successfully

### cbd-device-unbypass
***
Unbypasses a device.

##### Required Permissions
RBAC Permissions Required - device.bypass: EXECUTE

#### Base Command

`cbd-device-unbypass`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-device-unbypass device_id=123456```

#### Human Readable Output

>Device unbypass successfully

### cbd-device-policy-update
***
Updates the devices to the specified policy ID.

##### Required Permissions
RBAC Permissions Required - device.policy: UPDATE

#### Base Command

`cbd-device-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 
| policy_id | The ID of the policy. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-device-policy-update device_id=123456 policy_id=123456```

#### Human Readable Output

>Policy updated successfully

### cbd-device-update-sensor-version
***
Updates the version of a sensor.

##### Required Permissions
RBAC Permissions Required - device.kits: EXECUTE

#### Base Command

`cbd-device-update-sensor-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The ID of the device. | Required | 
| sensor_version | The new version of the sensor. For example: { "MAC": "1.2.3.4" }. Supported types: XP, WINDOWS, MAC, AV_SIG, OTHER, RHEL, UBUNTU, SUSE, AMAZON_LINUX, MAC_OSX. Possible values are: {"XP":}, {"WINDOWS":}, {"MAC":}, {"AV_SIG":}, {"OTHER":}, {"RHEL":}, {"UBUNTU":}, {"SUSE":}, {"AMAZON_LINUX":}, {"MAC_OSX":}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-device-update-sensor-version device_id=123456 sensor_version={\"AMAZON_LINUX\":\"1.2.3.4\"}```

#### Human Readable Output

>Version update to {"AMAZON_LINUX":"1.2.3.4"} was successful

### cbd-alerts-search
***
Gets details on the events that led to an alert. This includes retrieving metadata around the alert as well as the event associated with the alert.

##### Required Permissions
RBAC Permissions Required - org.alerts: READ

#### Base Command

`cbd-alerts-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of the alerts. Possible values: "cbAnalytics", "devicecontrol", "all". Possible values are: cbanalytics, devicecontrol, all. | Optional | 
| category | The category of the alert. Possible values: "THREAT", "MONITORED". Possible values are: THREAT, MONITORED. | Optional | 
| device_id | The device ID. | Optional | 
| first_event_time | The time of the first event associated with the alert. The syntax is  {"start": "&lt;dateTime&gt;", "range": "&lt;string&gt;", "end": "&lt;dateTime&gt;" }. For example: { "start": "2010-09-25T00:10:50.277Z", "end": "2015-01-20T10:40:00.00Z"}. | Optional | 
| policy_id | The policy ID. | Optional | 
| process_sha256 | The SHA-256 hash of the primary involved process. | Optional | 
| reputation | The reputation of the primary involved process. Possible values: "KNOWN_MALWARE", "NOT_LISTED", etc. | Optional | 
| tag | The tags associated with the alert. | Optional | 
| device_username | The username of the user logged on during the alert. If the user is not available then this may be populated with the device owner. | Optional | 
| query | The query in Lucene syntax and/or value searches. | Optional | 
| rows | The number of results to be returned. | Optional | 
| start | The number of the alert from where to start retrieving results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefense.Alert.id | String | The identifier for the alert. | 
| CarbonBlackDefense.Alert.legacy_alert_id | String | The unique short ID for the alerts to support easier consumption in the UI console. Use the ID for API requests. | 
| CarbonBlackDefense.Alert.org_key | String | The unique identifier for the organization associated with the alert. | 
| CarbonBlackDefense.Alert.create_time | Date | The time the alert was created. | 
| CarbonBlackDefense.Alert.last_update_time | Date | The last time the alert was updated. | 
| CarbonBlackDefense.Alert.first_event_time | Date | The time of the first event associated with the alert. | 
| CarbonBlackDefense.Alert.last_event_time | Date | The time of the latest event associated with the alert. | 
| CarbonBlackDefense.Alert.threat_id | String | The identifier of a threat that this alert belongs. Threats are comprised of a combination of factors that can be repeated across devices. | 
| CarbonBlackDefense.Alert.severity | Number | The threat ranking of the alert. | 
| CarbonBlackDefense.Alert.category | String | The category of the alert. \(THREAT, MONITORED\). | 
| CarbonBlackDefense.Alert.device_id | Number | The identifier assigned by Carbon Black Cloud to the device associated with the alert. | 
| CarbonBlackDefense.Alert.device_os | String | The operating system of the device associated with the alert. | 
| CarbonBlackDefense.Alert.device_os_version | String | The operating system and version on the device. | 
| CarbonBlackDefense.Alert.device_name | String | The hostname of the device associated with the alert. | 
| CarbonBlackDefense.Alert.device_username | String | The username of the user logged on during the alert. If the user is not available then this may be populated with the device owner. | 
| CarbonBlackDefense.Alert.policy_id | Number | The identifier for the policy associated with the device at the time of the alert. | 
| CarbonBlackDefense.Alert.policy_name | String | The name of the policy associated with the device at the time of the alert. | 
| CarbonBlackDefense.Alert.target_value | String | The priority of the device assigned by the policy. | 
| CarbonBlackDefense.Alert.workflow.state | String | The state of the tracking system for alerts as they are triaged and resolved. Supported states are OPEN or DISMISSED. | 
| CarbonBlackDefense.Alert.workflow.remediation | String | The state of the workflow of the tracking system for alerts as they are triaged and resolved. Supported states are OPEN or DISMISSED. | 
| CarbonBlackDefense.Alert.workflow.last_update_time | Date | The last time the alert was updated. | 
| CarbonBlackDefense.Alert.workflow.comment | String | The comment about the workflow of the tracking system for alerts as they are triaged and resolved. | 
| CarbonBlackDefense.Alert.workflow.changed_by | String | The name of the user who changed the alert. | 
| CarbonBlackDefense.Alert.notes_present | Boolean | Indicates if notes are associated with the threat ID. | 
| CarbonBlackDefense.Alert.tags | Unknown | Tags associated with the alert \(\[ "tag1", "tag2" \]\). | 
| CarbonBlackDefense.Alert.reason | String | The description of the alert. | 
| CarbonBlackDefense.Alert.count | Number | The count of the alert. | 
| CarbonBlackDefense.Alert.report_id | String | The identifier of the report that contains the IOC. | 
| CarbonBlackDefense.Alert.report_name | String | The name of the report that contains the IOC. | 
| CarbonBlackDefense.Alert.ioc_id | String | The identifier of the IOC that cause the hit. | 
| CarbonBlackDefense.Alert.ioc_field | String | The indicator of comprise \(IOC\) field that the hit contains. | 
| CarbonBlackDefense.Alert.ioc_hit | String | IOC field value or IOC that matches the query. | 
| CarbonBlackDefense.Alert.watchlists.id | String | The ID of the watchlists associated with an alert. | 
| CarbonBlackDefense.Alert.watchlists.name | String | The name of the watchlists associated with an alert. | 
| CarbonBlackDefense.Alert.process_guid | String | The global unique identifier of the process that triggered the hit. | 
| CarbonBlackDefense.Alert.process_name | String | The name of the process that triggered the hit. | 
| CarbonBlackDefense.Alert.run_state | String | Run state for watchlist alerts. This value is always "RAN". | 
| CarbonBlackDefense.Alert.threat_indicators.process_name | String | The name of the threat indicators that make up the threat. | 
| CarbonBlackDefense.Alert.threat_indicators.sha256 | String | The SHA-256 hash of the threat indicators that make up the threat. | 
| CarbonBlackDefense.Alert.threat_indicators.ttps | String | The tactics, techniques, and procedures \(TTPs\) of the threat indicators that make up the threat. | 
| CarbonBlackDefense.Alert.threat_cause_actor_sha256 | String | The SHA-256 hash of the threat cause actor. | 
| CarbonBlackDefense.Alert.threat_cause_actor_md5 | String | The SHA-256 hash of the threat cause actor. | 
| CarbonBlackDefense.Alert.threat_cause_actor_name | String | Process name or IP address of the threat actor. | 
| CarbonBlackDefense.Alert.threat_cause_reputation | String | The reputation of the threat cause. \(KNOWN_MALWARE, SUSPECT_MALWARE, PUP, NOT_LISTED, ADAPTIVE_WHITE_LIST, COMMON_WHITE_LIST, TRUSTED_WHITE_LIST, COMPANY_BLACK_LIST\). | 
| CarbonBlackDefense.Alert.threat_cause_threat_category | String | The category of the threat cause. \(UNKNOWN, NON_MALWARE, NEW_MALWARE, KNOWN_MALWARE, RISKY_PROGRAM\). | 
| CarbonBlackDefense.Alert.threat_cause_vector | String | The source of the threat cause. \(EMAIL, WEB, GENERIC_SERVER, GENERIC_CLIENT, REMOTE_DRIVE, REMOVABLE_MEDIA, UNKNOWN, APP_STORE, THIRD_PARTY\). | 
| CarbonBlackDefense.Alert.document_guid | String | The document GUID. | 
| CarbonBlackDefense.Alert.type | String | The type of alert. \(CB_ANALYTICS, DEVICE_CONTROL\). | 
| CarbonBlackDefense.Alert.reason_code | String | The shorthand enum for the full-text reason. | 
| CarbonBlackDefense.Alert.device_location | String | Whether the device was on-premise or off-premise when the alert started. \(ONSITE, OFFSITE, UNKNOWN\). | 
| CarbonBlackDefense.Alert.created_by_event_id | String | Event identifier that initiated the alert. | 
| CarbonBlackDefense.Alert.threat_activity_dlp | String | Whether the alert involved data loss prevention \(DLP\). \(NOT_ATTEMPTED, ATTEMPTED, SUCCEEDED\). | 
| CarbonBlackDefense.Alert.threat_activity_phish | String | Whether the alert involved phishing. \(NOT_ATTEMPTED, ATTEMPTED, SUCCEEDED\). | 
| CarbonBlackDefense.Alert.threat_activity_c2 | String | Whether the alert involved a command and control \(c2\) server. \(NOT_ATTEMPTED, ATTEMPTED, SUCCEEDED\). | 
| CarbonBlackDefense.Alert.threat_cause_actor_process_pid | String | The process identifier \(PID\) of the actor process. | 
| CarbonBlackDefense.Alert.threat_cause_process_guid | String | The GUID of the process. | 
| CarbonBlackDefense.Alert.threat_cause_parent_guid | String | The parent GUID of the process. | 
| CarbonBlackDefense.Alert.threat_cause_cause_event_id | String | The threat cause cause event ID. | 
| CarbonBlackDefense.Alert.blocked_threat_category | String | The category of threat which we were able to take action on. \(UNKNOWN, NON_MALWARE, NEW_MALWARE, KNOWN_MALWARE, RISKY_PROGRAM\). | 
| CarbonBlackDefense.Alert.not_blocked_threat_category | String | Other potentially malicious activity involved in the threat on which we weren’t able to take action \(either due to policy config, or not having a relevant rule\). \(UNKNOWN, NON_MALWARE, NEW_MALWARE, KNOWN_MALWARE, RISKY_PROGRAM\). | 
| CarbonBlackDefense.Alert.kill_chain_status | String | The stage within the Cyber Kill Chain sequence most closely associated with the attributes of the alert. \(RECONNAISSANCE, WEAPONIZE, DELIVER_EXPLOIT, INSTALL_RUN, COMMAND_AND_CONTROL, EXECUTE_GOAL, BREACH\). For example \[ "EXECUTE_GOAL", "BREACH" \]. | 
| CarbonBlackDefense.Alert.sensor_action | String | The action taken by the sensor, according to the rule of the policy. \(POLICY_NOT_APPLIED, ALLOW, ALLOW_AND_LOG, TERMINATE, DENY\). | 
| CarbonBlackDefense.Alert.policy_applied | String | Whether a policy was applied. \(APPLIED, NOT_APPLIED\). | 


#### Command Example
```!cbd-alerts-search```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Alert": [
            {
                "blocked_threat_category": "NON_MALWARE",
                "category": "THREAT",
                "create_time": "2021-04-04T13:28:21.393Z",
                "created_by_event_id": "9a486945954911eb8af72dacb2908592",
                "device_id": 1234,
                "device_location": "OFFSITE",
                "device_name": "QA\\win2k16-vg6-11",
                "device_os": "WINDOWS",
                "device_os_version": "Windows Server 2016 x64",
                "device_username": "jon@example.com",
                "first_event_time": "2021-04-04T13:27:23.948Z",
                "id": "1234",
                "kill_chain_status": [
                    "INSTALL_RUN"
                ],
                "last_event_time": "2021-04-04T13:27:23.948Z",
                "last_update_time": "2021-04-04T13:28:36.264Z",
                "legacy_alert_id": "DD229360",
                "not_blocked_threat_category": "UNKNOWN",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_applied": "APPLIED",
                "policy_id": 6525,
                "policy_name": "default",
                "process_name": "setup.exe",
                "reason": "The application setup.exe invoked another application (setup.exe). A Deny Policy Action was applied.",
                "reason_code": "T_POL_TERM_CHILD :  (setup.exe)",
                "run_state": "RAN",
                "sensor_action": "TERMINATE",
                "severity": 2,
                "tags": null,
                "target_value": "LOW",
                "threat_activity_c2": "NOT_ATTEMPTED",
                "threat_activity_dlp": "NOT_ATTEMPTED",
                "threat_activity_phish": "NOT_ATTEMPTED",
                "threat_cause_actor_name": "setup.exe",
                "threat_cause_actor_process_pid": "14788-132620164432947360-0",
                "threat_cause_actor_sha256": "1a2b3c4d",
                "threat_cause_cause_event_id": "9a486945954911eb8af72dacb2908592",
                "threat_cause_parent_guid": "7DESJ9GN-003edc7f-00003aac-00000000-1d71680ea0a0258",
                "threat_cause_process_guid": "7DESJ9GN-003edc7f-00003368-00000000-1d71680eade2d79",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "NON_MALWARE",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "61b743fdb6725ab9861f50d5e05a2e33",
                "threat_indicators": [
                    {
                        "process_name": "setup.exe",
                        "sha256": "1a2b3c4d",
                        "ttps": [
                            "POLICY_DENY"
                        ]
                    }
                ],
                "type": "CB_ANALYTICS",
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:28:21.393Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:06.812Z",
                "device_id": 5678,
                "device_name": "cb-komand-w12",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "jon@example.com",
                "document_guid": "1a2b3c4d",
                "first_event_time": "2021-04-04T13:26:31.733Z",
                "id": "5678",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:26:31.733Z",
                "last_update_time": "2021-04-04T13:28:06.812Z",
                "legacy_alert_id": "ABCD-1234",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-0034e348-000003d4-00000000-1d720e5cd39e19a",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "ABCD-1234",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "ede27eace742ee2888c5dd36400a2ec0",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "1a2b3c4d",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "1a2b3c4d",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "1234",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.279Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:05.399Z",
                "device_id": 9101,
                "device_name": "EXAMPLE-INC\\Win10",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "office@net.com",
                "document_guid": "1a2b3c4d",
                "first_event_time": "2021-04-04T13:26:08.028Z",
                "id": "9101",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:26:08.028Z",
                "last_update_time": "2021-04-04T13:28:05.399Z",
                "legacy_alert_id": "ABCD-1234",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003b4a13-000004c4-00000000-1d71527c98244b0",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "ABCD-1234",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "f586835082f632dc8d9404d83bc16316",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "1a2b3c4d",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "1a2b3c4d",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "1234",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.279Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Carbon Black Endpoint Standard Alerts List Results
>|Id|Category|Device Id|Device Name|Device Username|Create Time|Ioc Hit|Policy Name|Process Name|Type|Severity|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 1234 | THREAT | 1234 | QA\win2k16-vg6-11 | jon@example.com | 2021-04-04T13:28:21.393Z |  | default | setup.exe | CB_ANALYTICS | 2 |
>| 5678 | THREAT | 5678 | cb-komand-w12 | jon@example.com | 2021-04-04T13:28:06.812Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| 9101 | THREAT | 9101 | BITGLASS-INC\Win10 | office@net.com | 2021-04-04T13:28:05.399Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
