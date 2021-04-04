VMware Carbon Black Endpoint Standard (formerly known as Carbon Black Defense) is a next-generation antivirus + EDR in one cloud-delivered platform that stops commodity malware, advanced malware, non-malware attacks, and ransomware.
This integration was integrated and tested with version xx of Carbon Black Defense v2
## Configure Carbon Black Defense v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Carbon Black Defense v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | URL |  | True |
    | API Key | This API key is required for all use cases except the policy use cases. | False |
    | API Secret Key | This API secret key is required for all use cases except the policy use cases. | False |
    | Custom API Key | This custom API key is required only for the policy use cases. | False |
    | Custom API Secret Key | This custom API secret key is required only for the policy use cases. | False |
    | Organization Key | The organization unique key. This is required for all use cases \(and for fetching incidents\) except the policy use cases. | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | The type of the alert | Type of alert to be fetched. | False |
    | The category of the alert. | Category of alert to be fetched \(THREAT, MONITORED\). If nothing is selected he is fetching from all categories. | False |
    | Device id | The alerts related to a specific device, represented by its ID. | False |
    | Policy id | The alerts related to a specific policy, represented by its ID. | False |
    | Process sha256 | The alerts related to a process, represented in SHA-256. | False |
    | Device username | The alerts related to a specific device, represented by its username. | False |
    | Query | Query in Lucene syntax and/or value searches. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). |  | False |
    | Maximum number of incidents per fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cbd-get-alert-details
***
Get details about the events that led to an alert by its ID. This includes retrieving metadata around the alert as well as a list of all the events associated with the alert. Only API keys of type “API” can call the alerts API.


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
            "device_id": 4091225,
            "device_name": "QA\\win2k16GL-PV7",
            "device_os": "WINDOWS",
            "device_os_version": null,
            "device_username": "Prashant.verma@logrhythm.com",
            "document_guid": "cxcXPLhbRxmZtsfvRitHTg",
            "first_event_time": "2021-04-04T10:39:55.946Z",
            "id": "3d541e1d-8930-4651-85c3-8cd9728d9776",
            "ioc_field": null,
            "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
            "ioc_id": "565633-0",
            "last_event_time": "2021-04-04T10:39:55.946Z",
            "last_update_time": "2021-04-04T10:42:54.143Z",
            "legacy_alert_id": "7DESJ9GN-003e6d59-00000498-00000000-1d70b726e2c3359-C2533F5842413A814AA19079A9C8469B",
            "notes_present": false,
            "org_key": "7DESJ9GN",
            "policy_id": 6525,
            "policy_name": "default",
            "process_guid": "7DESJ9GN-003e6d59-00000498-00000000-1d70b726e2c3359",
            "process_name": "svchost.exe",
            "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
            "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
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
                    "sha256": "438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7",
                    "ttps": [
                        "565633-0"
                    ]
                }
            ],
            "type": "WATCHLIST",
            "watchlists": [
                {
                    "id": "RJoXUWAyS16pBBCsR0j00A",
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

>### Carbon Black Defense Get Alert Details
>|Id|Category|Device Id|Device Name|Device Username|Create Time|Ioc Hit|Policy Name|Process Name|Type|Severity|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 3d541e1d-8930-4651-85c3-8cd9728d9776 | THREAT | 4091225 | QA\win2k16GL-PV7 | Prashant.verma@logrhythm.com | 2021-04-04T10:42:54.143Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |


### cbd-device-search
***
Searches devices in your organization.


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
                "id": 3777587,
                "last_contact_time": "2021-04-04T13:29:14.616Z",
                "last_device_policy_changed_time": "2021-03-22T18:02:05.742Z",
                "last_device_policy_requested_time": "2021-03-22T18:02:57.571Z",
                "last_external_ip_address": "65.127.112.131",
                "last_internal_ip_address": "11.1.1.202",
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
                "av_ave_version": "8.3.62.140",
                "av_engine": "4.14.3.454-ave.8.3.62.140:avpack.8.5.0.92:vdf.8.18.24.84:apc.2.10.0.154",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.14.3.454",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.24.84",
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
                "email": "yzhang@stellarcyber.ai",
                "encoded_activation_code": "L8ANCTWT9P7",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Yubao",
                "id": 3931617,
                "last_contact_time": "2021-04-04T13:29:14.056Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:32.072Z",
                "last_device_policy_requested_time": "2021-04-04T13:27:44.316Z",
                "last_external_ip_address": "205.234.30.196",
                "last_internal_ip_address": "10.33.4.209",
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
                "av_ave_version": "8.3.62.170",
                "av_engine": "4.14.3.454-ave.8.3.62.170:avpack.8.5.0.102:vdf.8.18.27.228",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.102",
                "av_product_version": "4.14.3.454",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.27.228",
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
                "email": "brandon@remediant.com",
                "encoded_activation_code": "2VNKDLWE3UT",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Brandon",
                "id": 4054243,
                "last_contact_time": "2021-04-04T13:29:13.643Z",
                "last_device_policy_changed_time": "2021-03-31T20:11:50.835Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:52.963Z",
                "last_external_ip_address": "63.80.150.143",
                "last_internal_ip_address": "172.16.15.108",
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
                "name": "RTEST\\Oleg-TB2-Win10E",
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
            },
            {
                "activation_code": "ALKNNV",
                "activation_code_expiry_time": "2021-03-23T11:49:15.902Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": null,
                "av_engine": null,
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": null,
                "cluster_name": null,
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
                        "key_value": "DC=QA,DC=schq,DC=secious,DC=com",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.4.2",
                        "position": 0
                    }
                ],
                "device_owner_id": 647451,
                "email": "Kushal.gulati@logrhythm.com",
                "encoded_activation_code": "KJR77LW4FNV",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "kushal",
                "id": 4117626,
                "last_contact_time": "2021-04-04T13:29:12.170Z",
                "last_device_policy_changed_time": "2021-03-31T20:08:14.766Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:28.457Z",
                "last_external_ip_address": "65.127.112.131",
                "last_internal_ip_address": "10.4.2.38",
                "last_location": "OFFSITE",
                "last_name": "gulati",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T13:29:00.741Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "005056956f87",
                "middle_name": null,
                "name": "VM-2K12-VG73",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Server 2012 R2 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2021-03-16T11:50:11.845Z",
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
                "uninstall_code": "D94P72DN",
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
                "activation_code": "7ZZNS1",
                "activation_code_expiry_time": "2020-08-21T00:15:01.973Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.140",
                "av_engine": "4.13.0.207-ave.8.3.62.140:avpack.8.5.0.92:vdf.8.18.24.82",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.13.0.207",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.24.82",
                "cluster_name": null,
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
                        "key_value": "OU=Domain Controllers,DC=vykin,DC=corp",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.0.100",
                        "position": 0
                    }
                ],
                "device_owner_id": 444285,
                "email": "erik@kognos.io",
                "encoded_activation_code": "IQQ7FPWF8L6",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Erik",
                "id": 3449992,
                "last_contact_time": "2021-04-04T13:29:05.958Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:39.668Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:29.260Z",
                "last_external_ip_address": "71.163.178.164",
                "last_internal_ip_address": "10.0.100.100",
                "last_location": "OFFSITE",
                "last_name": "Heuser",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T11:33:59.105Z",
                "last_reset_time": null,
                "last_shutdown_time": "2020-06-11T21:27:41.584Z",
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "000000000000",
                "middle_name": null,
                "name": "VYKIN\\va-ad",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Server 2008 R2 x64 SP: 1",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-05-20T16:55:06.961Z",
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
                "sensor_version": "3.6.0.1897",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "JTD5LWLH",
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
                "activation_code": "NVI98U",
                "activation_code_expiry_time": "2021-04-02T03:03:27.985Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": null,
                "av_engine": null,
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": null,
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
                        "key_value": "192.168.55",
                        "position": 0
                    }
                ],
                "device_owner_id": 649372,
                "email": "lchai@vectra.ai",
                "encoded_activation_code": "7LN3H5WQA!L",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Lin",
                "id": 4124461,
                "last_contact_time": "2021-04-04T13:29:01.020Z",
                "last_device_policy_changed_time": null,
                "last_device_policy_requested_time": "2021-04-02T06:05:21.771Z",
                "last_external_ip_address": "74.201.86.232",
                "last_internal_ip_address": "192.168.55.145",
                "last_location": "OFFSITE",
                "last_name": "Chai",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T05:17:46.556Z",
                "last_reset_time": null,
                "last_shutdown_time": "2021-04-02T18:10:49.540Z",
                "linux_kernel_version": null,
                "login_user_name": "WIN10-LCHAI\\vadmin",
                "mac_address": "0050569adce3",
                "middle_name": null,
                "name": "WIN10-LCHAI",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": false,
                "quarantined": false,
                "registered_time": "2021-03-19T02:13:29.058Z",
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
                "uninstall_code": "LE1NFWVD",
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
                "activation_code": "KS4QEQ",
                "activation_code_expiry_time": "2021-03-19T21:29:21.427Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": null,
                "av_engine": null,
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": null,
                "cluster_name": null,
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "AD_LDAP",
                        "key_value": "DC=demo,DC=remediant,DC=io",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.30.4",
                        "position": 0
                    }
                ],
                "device_owner_id": 646846,
                "email": "kevin.garrett@remediant.com",
                "encoded_activation_code": "RFO828W6QXN",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Kevin",
                "id": 4111427,
                "last_contact_time": "2021-04-04T13:28:49.500Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:37.776Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:29.818Z",
                "last_external_ip_address": "54.68.41.226",
                "last_internal_ip_address": "10.30.4.12",
                "last_location": "OFFSITE",
                "last_name": "Garrett",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-02T11:44:20.990Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "06e2ad3c0a03",
                "middle_name": null,
                "name": "DEMO\\HR-SERVER-MW",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows Server 2019 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2021-03-12T23:06:36.741Z",
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
                "uninstall_code": "IYIQTSN7",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": "UNKNOWN",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": "PPP9M3",
                "activation_code_expiry_time": "2020-09-04T08:57:25.158Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.134",
                "av_engine": "4.13.0.207-ave.8.3.62.134:avpack.8.5.0.92:vdf.8.18.23.200",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.13.0.207",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.23.200",
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
                        "key_value": "161.47.37",
                        "position": 0
                    }
                ],
                "device_owner_id": 489427,
                "email": "jayakumar@acalvio.com",
                "encoded_activation_code": "SSS3ZTWO@R!",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "",
                "id": 3668753,
                "last_contact_time": "2021-04-04T13:28:48.259Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:21.289Z",
                "last_device_policy_requested_time": "2021-04-02T06:06:03.690Z",
                "last_external_ip_address": "161.47.37.87",
                "last_internal_ip_address": null,
                "last_location": "OFFSITE",
                "last_name": "",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T12:04:41.031Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "000000000000",
                "middle_name": null,
                "name": "DESK-F1-179",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-09-02T15:56:26.088Z",
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
                "sensor_version": "3.6.0.1719",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "FJYM3HUS",
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
                "activation_code": "9JGHT2",
                "activation_code_expiry_time": "2020-10-20T08:11:07.431Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.140",
                "av_engine": "4.13.0.207-ave.8.3.62.140:avpack.8.5.0.92:vdf.8.18.24.82",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.13.0.207",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.24.82",
                "cluster_name": null,
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "172.26.114",
                        "position": 0
                    }
                ],
                "device_owner_id": 455915,
                "email": "tarun@acalvio.com",
                "encoded_activation_code": "34UDCYWP5@A",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "",
                "id": 3758687,
                "last_contact_time": "2021-04-04T13:28:44.387Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:42.359Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:13.863Z",
                "last_external_ip_address": "161.47.37.87",
                "last_internal_ip_address": "172.26.114.84",
                "last_location": "OFFSITE",
                "last_name": "",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-02T06:05:12.833Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "000000000000",
                "middle_name": null,
                "name": "W10-TRN-CB1",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-10-13T08:22:43.038Z",
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
                "sensor_version": "3.5.0.1680",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "3H8631RN",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": "UNKNOWN",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": "IYRZTY",
                "activation_code_expiry_time": "2020-07-12T15:53:29.847Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.134",
                "av_engine": "4.13.0.207-ave.8.3.62.134:avpack.8.5.0.92:vdf.8.18.23.200",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.13.0.207",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.23.200",
                "cluster_name": null,
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.0.12",
                        "position": 0
                    },
                    {
                        "key_name": "AD_LDAP",
                        "key_value": "DC=hntlab,DC=local",
                        "position": 0
                    }
                ],
                "device_owner_id": 459870,
                "email": "omer@hunters.ai",
                "encoded_activation_code": "NV1QCVWYBVR",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Omer",
                "id": 3538575,
                "last_contact_time": "2021-04-04T13:28:42.306Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:46.894Z",
                "last_device_policy_requested_time": "2021-04-02T07:32:16.203Z",
                "last_external_ip_address": "40.65.205.77",
                "last_internal_ip_address": "10.0.12.4",
                "last_location": "OFFSITE",
                "last_name": "Test",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-02T07:28:00.615Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "000000000000",
                "middle_name": null,
                "name": "hntlab\\client-cb0",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-07-05T15:55:19.605Z",
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
                "sensor_version": "3.5.0.1680",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "UG73RGRZ",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": "UNKNOWN",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": "PPP9M3",
                "activation_code_expiry_time": "2020-09-04T08:57:25.158Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.140",
                "av_engine": "4.13.0.207-ave.8.3.62.140:avpack.8.5.0.92:vdf.8.18.24.84",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.13.0.207",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.24.84",
                "cluster_name": null,
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "172.26.115",
                        "position": 0
                    }
                ],
                "device_owner_id": 489427,
                "email": "jayakumar@acalvio.com",
                "encoded_activation_code": "SSS3ZTWO@R!",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Jayakumar",
                "id": 3625933,
                "last_contact_time": "2021-04-04T13:28:41.925Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:30.114Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:30.565Z",
                "last_external_ip_address": "161.47.37.87",
                "last_internal_ip_address": "172.26.115.75",
                "last_location": "OFFSITE",
                "last_name": "",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-02T06:05:29.915Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "000000000000",
                "middle_name": null,
                "name": "win10-ps-moid",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-08-17T12:22:33.010Z",
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
                "sensor_version": "3.5.0.1786",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "8K7Q536U",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": "UNKNOWN",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": null,
                "activation_code_expiry_time": "2021-03-31T17:29:50.793Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": null,
                "av_engine": null,
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": [
                    "AV_ACTIVE",
                    "ONACCESS_SCAN_DISABLED",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": null,
                "cluster_name": null,
                "current_sensor_policy_name": "BlueHexagon Policy_Quarantine",
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
                        "key_value": "10.220.30",
                        "position": 0
                    }
                ],
                "device_owner_id": 652046,
                "email": "Threat",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "id": 4136358,
                "last_contact_time": "2021-04-04T13:28:41.253Z",
                "last_device_policy_changed_time": "2021-03-24T20:39:17.398Z",
                "last_device_policy_requested_time": "2021-03-24T20:39:46.006Z",
                "last_external_ip_address": "38.140.50.98",
                "last_internal_ip_address": "10.220.30.85",
                "last_location": "OFFSITE",
                "last_name": null,
                "last_policy_updated_time": "2021-03-24T16:48:31.060Z",
                "last_reported_time": "2021-04-04T10:21:46.760Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "00505699db0c",
                "middle_name": null,
                "name": "DESKTOP-F70DSE6",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 65982,
                "policy_name": "BlueHexagon Policy_Quarantine",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2021-03-24T17:29:50.829Z",
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
                "target_priority": "MEDIUM",
                "uninstall_code": "5E8JBFYY",
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
                "activation_code": null,
                "activation_code_expiry_time": "2020-10-26T21:30:07.533Z",
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
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Ubuntu 18",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.1.101",
                        "position": 0
                    }
                ],
                "device_owner_id": 556043,
                "email": "ip-10-1-101-68",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "id": 3775862,
                "last_contact_time": "2021-04-04T13:28:34.426Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:26.067Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:16.428Z",
                "last_external_ip_address": "34.220.33.6",
                "last_internal_ip_address": "10.1.101.68",
                "last_location": "UNKNOWN",
                "last_name": null,
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-03-25T22:47:00.387Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": null,
                "mac_address": null,
                "middle_name": null,
                "name": "ip-10-1-101-68",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "LINUX",
                "os_version": "Ubuntu 18.04.3",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-10-19T21:30:07.559Z",
                "scan_last_action_time": null,
                "scan_last_complete_time": null,
                "scan_status": null,
                "sensor_kit_type": "UBUNTU",
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
                "target_priority": "LOW",
                "uninstall_code": "N3IBH8PZ",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": null,
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": "GFWGN1",
                "activation_code_expiry_time": "2020-12-03T09:29:43.471Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.140",
                "av_engine": "4.13.0.207-ave.8.3.62.140:avpack.8.5.0.92:vdf.8.18.24.84",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.13.0.207",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.24.84",
                "cluster_name": null,
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "AD_LDAP",
                        "key_value": "DC=Development,DC=schq,DC=secious,DC=com",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.3.0",
                        "position": 0
                    }
                ],
                "device_owner_id": 593906,
                "email": "shalini.chaturvedi@logrhythm.com",
                "encoded_activation_code": "U96U7PWU1WP",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "shalini",
                "id": 3898220,
                "last_contact_time": "2021-04-04T13:28:32.948Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:39.033Z",
                "last_device_policy_requested_time": "2021-04-02T06:06:20.469Z",
                "last_external_ip_address": "65.127.112.131",
                "last_internal_ip_address": "10.3.0.99",
                "last_location": "OFFSITE",
                "last_name": "chaturvedi",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-02T09:48:50.226Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "000000000000",
                "middle_name": null,
                "name": "DEVELOPMENT\\VM-BEATS-DEV",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-11-26T09:31:48.715Z",
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
                "sensor_version": "3.6.0.1897",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "V5KGZM7W",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": "UNKNOWN",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": "APL4DC",
                "activation_code_expiry_time": "2021-02-24T19:39:40.666Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.162",
                "av_engine": "4.14.3.454-ave.8.3.62.162:avpack.8.5.0.98:vdf.8.18.26.154",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.98",
                "av_product_version": "4.14.3.454",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.26.154",
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
                "email": "brandon@remediant.com",
                "encoded_activation_code": "KSJOWEWE3UT",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Brandon",
                "id": 4051669,
                "last_contact_time": "2021-04-04T13:28:32.047Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:22.033Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:27.546Z",
                "last_external_ip_address": "63.80.150.143",
                "last_internal_ip_address": "172.16.15.124",
                "last_location": "OFFSITE",
                "last_name": "Van Pelt",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T12:43:34.839Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "0050569f2672",
                "middle_name": null,
                "name": "RTEST\\OnlineHost1",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2021-02-17T17:09:32.867Z",
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
                "uninstall_code": "8A327F89",
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
                "activation_code": "FDJPPK",
                "activation_code_expiry_time": "2020-07-08T14:21:07.840Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.140",
                "av_engine": "4.13.0.207-ave.8.3.62.140:avpack.8.5.0.92:vdf.8.18.24.82",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.13.0.207",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.24.82",
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
                        "key_value": "DC=vykin,DC=corp",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.0.103",
                        "position": 0
                    }
                ],
                "device_owner_id": 444285,
                "email": "erik@kognos.io",
                "encoded_activation_code": "9W4SSRWV6CS",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "ERIK",
                "id": 3449981,
                "last_contact_time": "2021-04-04T13:28:31.809Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:54.719Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:19.502Z",
                "last_external_ip_address": "71.163.178.164",
                "last_internal_ip_address": "10.0.103.101",
                "last_location": "OFFSITE",
                "last_name": "HEUSER",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T08:10:51.701Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "VYKIN\\kstear",
                "mac_address": "000000000000",
                "middle_name": null,
                "name": "VYKIN\\DESKTOP-OAH4ASP",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-05-20T16:47:57.736Z",
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
                "sensor_version": "3.6.0.1897",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "DVTUVD12",
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
                "activation_code": null,
                "activation_code_expiry_time": "2017-11-07T20:39:37.550Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.140",
                "av_engine": "4.13.0.207-ave.8.3.62.140:avpack.8.5.0.92:vdf.8.18.24.82",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.13.0.207",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.24.82",
                "cluster_name": null,
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "AD_LDAP",
                        "key_value": "DC=test,DC=confluera,DC=com",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "54.149.125",
                        "position": 0
                    }
                ],
                "device_owner_id": 251225,
                "email": "Administrator",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "id": 3775792,
                "last_contact_time": "2021-04-04T13:28:31.564Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:23.365Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:46.160Z",
                "last_external_ip_address": "54.149.125.225",
                "last_internal_ip_address": null,
                "last_location": "OFFSITE",
                "last_name": null,
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-02T07:57:22.463Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "000000000000",
                "middle_name": null,
                "name": "TEST\\windowsbuild",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows Server 2016 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-10-19T21:08:34.344Z",
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
                "sensor_version": "3.6.0.1791",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "ZQAGAWGM",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": "UNKNOWN",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": null,
                "activation_code_expiry_time": "2017-11-07T20:39:37.550Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.134",
                "av_engine": "4.14.3.454-ave.8.3.62.134:avpack.8.5.0.92:vdf.8.18.23.200",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.92",
                "av_product_version": "4.14.3.454",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.23.200",
                "cluster_name": null,
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.128.0",
                        "position": 0
                    }
                ],
                "device_owner_id": 251225,
                "email": "Administrator",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "id": 3925348,
                "last_contact_time": "2021-04-04T13:28:31.416Z",
                "last_device_policy_changed_time": "2021-04-04T13:26:57.199Z",
                "last_device_policy_requested_time": "2021-04-04T13:27:00.610Z",
                "last_external_ip_address": "35.224.136.145",
                "last_internal_ip_address": "10.128.0.15",
                "last_location": "OFFSITE",
                "last_name": null,
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T12:37:15.105Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "Window Manager\\DWM-2",
                "mac_address": "42010a80000f",
                "middle_name": null,
                "name": "carbon-black-integration-endpoint",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows Server 2019 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2020-12-14T17:21:20.599Z",
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
                "sensor_version": "3.6.0.1941",
                "status": "REGISTERED",
                "target_priority": "LOW",
                "uninstall_code": "FSHZFNBV",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": "UNKNOWN",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": "C43BN1",
                "activation_code_expiry_time": "2021-03-09T23:15:22.986Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": null,
                "av_engine": null,
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": null,
                "av_product_version": null,
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": null,
                "cluster_name": null,
                "current_sensor_policy_name": "default",
                "datacenter_name": null,
                "deployment_type": "ENDPOINT",
                "deregistered_time": null,
                "device_meta_data_item_list": [
                    {
                        "key_name": "OS_MAJOR_VERSION",
                        "key_value": "Windows 10",
                        "position": 0
                    },
                    {
                        "key_name": "AD_LDAP",
                        "key_value": "DC=cstest,DC=test",
                        "position": 0
                    },
                    {
                        "key_name": "SUBNET",
                        "key_value": "10.100.11",
                        "position": 0
                    }
                ],
                "device_owner_id": 605966,
                "email": "brandon@remediant.com",
                "encoded_activation_code": "EOTX7PW5IJW",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": "Brandon",
                "id": 4085028,
                "last_contact_time": "2021-04-04T13:28:30.249Z",
                "last_device_policy_changed_time": "2021-03-16T11:44:48.161Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:23.020Z",
                "last_external_ip_address": "3.19.161.227",
                "last_internal_ip_address": "10.100.11.225",
                "last_location": "OFFSITE",
                "last_name": "Van Pelt",
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-02T08:47:08.328Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "02c1f2d61c4e",
                "middle_name": null,
                "name": "CSTEST\\WINCOMP3",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows Server 2016 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2021-03-02T23:18:01.630Z",
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
                "uninstall_code": "YSY4ZZJW",
                "vcenter_host_url": null,
                "vcenter_name": null,
                "vcenter_uuid": null,
                "vdi_base_device": null,
                "virtual_machine": false,
                "virtualization_provider": "UNKNOWN",
                "vm_ip": null,
                "vm_name": null,
                "vm_uuid": null,
                "vulnerability_score": 0,
                "vulnerability_severity": null,
                "windows_platform": null
            },
            {
                "activation_code": null,
                "activation_code_expiry_time": "2021-01-14T07:04:36.391Z",
                "ad_group_id": 0,
                "appliance_name": null,
                "appliance_uuid": null,
                "av_ave_version": "8.3.62.162",
                "av_engine": "4.14.3.454-ave.8.3.62.162:avpack.8.5.0.98:vdf.8.18.26.154",
                "av_last_scan_time": null,
                "av_master": false,
                "av_pack_version": "8.5.0.98",
                "av_product_version": "4.14.3.454",
                "av_status": [
                    "AV_ACTIVE",
                    "ONDEMAND_SCAN_DISABLED"
                ],
                "av_update_servers": null,
                "av_vdf_version": "8.18.26.154",
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
                        "key_value": "172.26.100",
                        "position": 0
                    }
                ],
                "device_owner_id": 614163,
                "email": "acalvio",
                "esx_host_name": null,
                "esx_host_uuid": null,
                "first_name": null,
                "id": 4055207,
                "last_contact_time": "2021-04-04T13:28:27.752Z",
                "last_device_policy_changed_time": "2021-03-16T11:47:03.079Z",
                "last_device_policy_requested_time": "2021-04-02T06:05:18.007Z",
                "last_external_ip_address": "161.47.37.87",
                "last_internal_ip_address": "172.26.100.105",
                "last_location": "OFFSITE",
                "last_name": null,
                "last_policy_updated_time": "2021-04-02T06:05:12.968Z",
                "last_reported_time": "2021-04-04T09:52:07.599Z",
                "last_reset_time": null,
                "last_shutdown_time": null,
                "linux_kernel_version": null,
                "login_user_name": "",
                "mac_address": "0050569965f9",
                "middle_name": null,
                "name": "2746-win10-2-S",
                "organization_id": 1105,
                "organization_name": "cb-internal-alliances.com",
                "os": "WINDOWS",
                "os_version": "Windows 10 x64",
                "passive_mode": false,
                "policy_id": 6525,
                "policy_name": "default",
                "policy_override": true,
                "quarantined": false,
                "registered_time": "2021-02-19T05:28:36.959Z",
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
                "uninstall_code": "UN8HF22U",
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

>### Carbon Black Defense Devices List Results
>|Id|Name|Os|Policy Name|Quarantined|Status|Target Priority|Last Internal Ip Address|Last External Ip Address|Last Contact Time|Last Location|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 3777587 | bo1tapsandbox-01 | LINUX | LRDemo-JH | false | REGISTERED | MEDIUM | 11.1.1.202 | 65.127.112.131 | 2021-04-04T13:29:14.616Z | UNKNOWN |
>| 3931617 | REDTEAM\malware-gen2 | WINDOWS | default | false | BYPASS | LOW | 10.33.4.209 | 205.234.30.196 | 2021-04-04T13:29:14.056Z | OFFSITE |
>| 4054243 | RTEST\Oleg-TB2-Win10E | WINDOWS | default | false | REGISTERED | LOW | 172.16.15.108 | 63.80.150.143 | 2021-04-04T13:29:13.643Z | OFFSITE |
>| 4117626 | VM-2K12-VG73 | WINDOWS | default | false | REGISTERED | LOW | 10.4.2.38 | 65.127.112.131 | 2021-04-04T13:29:12.170Z | OFFSITE |
>| 3449992 | VYKIN\va-ad | WINDOWS | default | false | REGISTERED | LOW | 10.0.100.100 | 71.163.178.164 | 2021-04-04T13:29:05.958Z | OFFSITE |
>| 4124461 | WIN10-LCHAI | WINDOWS | default | false | REGISTERED | LOW | 192.168.55.145 | 74.201.86.232 | 2021-04-04T13:29:01.020Z | OFFSITE |
>| 4111427 | DEMO\HR-SERVER-MW | WINDOWS | default | false | REGISTERED | LOW | 10.30.4.12 | 54.68.41.226 | 2021-04-04T13:28:49.500Z | OFFSITE |
>| 3668753 | DESK-F1-179 | WINDOWS | default | false | REGISTERED | LOW |  | 161.47.37.87 | 2021-04-04T13:28:48.259Z | OFFSITE |
>| 3758687 | W10-TRN-CB1 | WINDOWS | default | false | REGISTERED | LOW | 172.26.114.84 | 161.47.37.87 | 2021-04-04T13:28:44.387Z | OFFSITE |
>| 3538575 | hntlab\client-cb0 | WINDOWS | default | false | REGISTERED | LOW | 10.0.12.4 | 40.65.205.77 | 2021-04-04T13:28:42.306Z | OFFSITE |
>| 3625933 | win10-ps-moid | WINDOWS | default | false | REGISTERED | LOW | 172.26.115.75 | 161.47.37.87 | 2021-04-04T13:28:41.925Z | OFFSITE |
>| 4136358 | DESKTOP-F70DSE6 | WINDOWS | BlueHexagon Policy_Quarantine | false | REGISTERED | MEDIUM | 10.220.30.85 | 38.140.50.98 | 2021-04-04T13:28:41.253Z | OFFSITE |
>| 3775862 | ip-10-1-101-68 | LINUX | default | false | REGISTERED | LOW | 10.1.101.68 | 34.220.33.6 | 2021-04-04T13:28:34.426Z | UNKNOWN |
>| 3898220 | DEVELOPMENT\VM-BEATS-DEV | WINDOWS | default | false | REGISTERED | LOW | 10.3.0.99 | 65.127.112.131 | 2021-04-04T13:28:32.948Z | OFFSITE |
>| 4051669 | RTEST\OnlineHost1 | WINDOWS | default | false | REGISTERED | LOW | 172.16.15.124 | 63.80.150.143 | 2021-04-04T13:28:32.047Z | OFFSITE |
>| 3449981 | VYKIN\DESKTOP-OAH4ASP | WINDOWS | default | false | REGISTERED | LOW | 10.0.103.101 | 71.163.178.164 | 2021-04-04T13:28:31.809Z | OFFSITE |
>| 3775792 | TEST\windowsbuild | WINDOWS | default | false | REGISTERED | LOW |  | 54.149.125.225 | 2021-04-04T13:28:31.564Z | OFFSITE |
>| 3925348 | carbon-black-integration-endpoint | WINDOWS | default | false | REGISTERED | LOW | 10.128.0.15 | 35.224.136.145 | 2021-04-04T13:28:31.416Z | OFFSITE |
>| 4085028 | CSTEST\WINCOMP3 | WINDOWS | default | false | REGISTERED | LOW | 10.100.11.225 | 3.19.161.227 | 2021-04-04T13:28:30.249Z | OFFSITE |
>| 4055207 | 2746-win10-2-S | WINDOWS | default | false | REGISTERED | LOW | 172.26.100.105 | 161.47.37.87 | 2021-04-04T13:28:27.752Z | OFFSITE |


### cbd-find-processes
***
Creates a process search job. The results for the search job may be requested using the returned job ID. At least one of the arguments (not including: rows, start, and time_range) is required.


#### Base Command

`cbd-find-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_category | The Carbon Black Cloud classification for events tagged to an alert. Possible values: "THREAT" and "OBSERVED". Possible values are: THREAT, OBSERVED. | Optional | 
| blocked_hash | SHA-256 hash(es) of the child process(es) binary. For any process(es) terminated by the sensor. | Optional | 
| device_external_ip | The IP address of the endpoint according to Carbon Black Cloud. This IP address can differ from the device_internal_ip due to network proxy or NAT. Can be either IPv4 or IPv6 format. | Optional | 
| device_id | The ID assigned to the endpoint by Carbon Black Cloud. This ID is unique across all Carbon Black Cloud environments. | Optional | 
| device_internal_ip | The IP address of the endpoint reported by the sensor. Can be either IPv4 or IPv6 format. | Optional | 
| device_name | The hostname of the endpoint recorded by the sensor when last initialized. | Optional | 
| device_os | The operating system of the endpoint. Possible values: "WINDOWS", "MAC", "LINUX". Possible values are: WINDOWS, MAC, LINUX. | Optional | 
| device_timestamp | The sensor-reported timestamp of the batch of events in which this record was submitted to Carbon Black Cloud. specified as ISO 8601 timestamp in UTC for example: 2020-01-19T04:28:40.190Z. | Optional | 
| event_type | The type of enriched event observed. Possible value: "filemod", "netconn", "regmod", "modload", "crossproc", "childproc", "scriptload", and "fileless_scriptload". Possible values are: filemod, netconn, regmod, modload, crossproc, childproc, scriptload, fileless_scriptload. | Optional | 
| parent_hash | The MD5 and/or SHA-256 hash of the parent process binary. | Optional | 
| parent_name | The file system path of the parent process binary. | Optional | 
| parent_reputation | The reputation of the parent process applied by Carbon Black Cloud when the event is initially processed. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". Possible values are: ADAPTIVE_WHITE_LIST, ADWARE, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, HEURISTIC, IGNORE, KNOWN_MALWARE, LOCAL_WHITE, NOT_LISTED, PUP, RESOLVING, SUSPECT_MALWARE, TRUSTED_WHITE_LIST. | Optional | 
| process_cmdline | The command line executed by the actor process. | Optional | 
| process_guid | The unique process identifier for the actor process. | Optional | 
| process_hash | The MD5 and/or SHA-256 hash of the actor process binary. The order may vary when two hashes are reported. | Optional | 
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

>### Carbon Black Defense Processes Search
>|Job Id|
>|---|
>| f5a2ae0e-c3f7-4443-882d-009097eaabd3 |


### cbd-find-events
***
Creates an enriched events search job. The results for the search job may be requested using the returned job ID. At least one of the arguments (not including: rows, start, time_range) is required).


#### Base Command

`cbd-find-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_category | The Carbon Black Cloud classification for events tagged to an alert. Possible values: "THREAT" and "OBSERVED". Possible values are: THREAT, OBSERVED. | Optional | 
| blocked_hash | SHA-256 hash(es) of the child process(es) binary. For any process(es) terminated by the sensor. | Optional | 
| device_external_ip | The IP address of the endpoint according to Carbon Black Cloud. This IP address can differ from the device_internal_ip due to network proxy or NAT. Can be either IPv4 or IPv6 format. | Optional | 
| device_id | The ID assigned to the endpoint by Carbon Black Cloud. This ID is unique across all Carbon Black Cloud environments. | Optional | 
| device_internal_ip | The IP address of the endpoint reported by the sensor. Can be either IPv4 or IPv6 format. | Optional | 
| device_name | The hostname of the endpoint recorded by the sensor when last initialized. | Optional | 
| device_os | The operating system of the endpoint. Possible values: "WINDOWS", "MAC", "LINUX". Possible values are: WINDOWS, MAC, LINUX. | Optional | 
| event_type | The type of enriched event observed. Possible value: "filemod", "netconn", "regmod", "modload", "crossproc", "childproc", "scriptload", and "fileless_scriptload". Possible values are: filemod, netconn, regmod, modload, crossproc, childproc, scriptload, fileless_scriptload. | Optional | 
| parent_hash | The MD5 and/or SHA-256 hash of the parent process binary. | Optional | 
| parent_name | The file system path of the parent process binary. | Optional | 
| parent_reputation | The reputation of the parent process applied by Carbon Black Cloud when the event is initially processed. Possible values: "ADAPTIVE_WHITE_LIST", "ADWARE", "COMMON_WHITE_LIST", "COMPANY_BLACK_LIST", "COMPANY_WHITE_LIST", "HEURISTIC", "IGNORE", "KNOWN_MALWARE", "LOCAL_WHITE", "NOT_LISTED", "PUP", "RESOLVING", "SUSPECT_MALWARE", and "TRUSTED_WHITE_LIST". Possible values are: ADAPTIVE_WHITE_LIST, ADWARE, COMMON_WHITE_LIST, COMPANY_BLACK_LIST, COMPANY_WHITE_LIST, HEURISTIC, IGNORE, KNOWN_MALWARE, LOCAL_WHITE, NOT_LISTED, PUP, RESOLVING, SUSPECT_MALWARE, TRUSTED_WHITE_LIST. | Optional | 
| process_cmdline | The command line executed by the actor process. | Optional | 
| process_guid | The unique process identifier for the actor process. | Optional | 
| process_hash | The MD5 and/or SHA-256 hash of the actor process binary. The order may vary when two hashes are reported. | Optional | 
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

>### Carbon Black Defense Events Search
>|Job Id|
>|---|
>| b853bf18-d1f3-4dcc-b590-6626ee547bec |


### cbd-find-processes-results
***
Retrieves the results of a process search identified by the job ID.


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
| CarbonBlackDefense.Process.Results | Unknown | The results of the process search. | 
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
                        "device_id": 4115768,
                        "device_name": "vm-2k12-vg63",
                        "device_policy_id": 9246,
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
                        "device_id": 3898220,
                        "device_name": "development\\vm-beats-dev",
                        "device_policy_id": 6525,
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
                            "SECIOUS\\shalini.chaturvedi"
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
                        "device_id": 3898220,
                        "device_name": "development\\vm-beats-dev",
                        "device_policy_id": 6525,
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
                            "SECIOUS\\shalini.chaturvedi"
                        ],
                        "regmod_count": 117,
                        "scriptload_count": 0
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:13:15.910Z",
                        "childproc_count": 0,
                        "crossproc_count": 1063,
                        "device_group_id": 0,
                        "device_id": 4119679,
                        "device_name": "qa\\win2k16-vg6-11",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:11:10.625Z",
                        "enriched": true,
                        "enriched_event_type": [
                            "NETWORK"
                        ],
                        "event_type": [
                            "netconn"
                        ],
                        "filemod_count": 1134,
                        "ingress_time": 1617534744791,
                        "legacy": true,
                        "modload_count": 192,
                        "netconn_count": 155,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003edc7f-00002948-00000000-1d71af36cb14c00",
                        "parent_pid": 10568,
                        "process_guid": "7DESJ9GN-003edc7f-00002bc0-00000000-1d71af36d265076",
                        "process_hash": [
                            "aa2e522a405cb5a295d3502c4ff6ca39",
                            "bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            11200
                        ],
                        "process_username": [
                            "WIN2K16-VG6-11\\Administrator"
                        ],
                        "regmod_count": 0,
                        "scriptload_count": 0
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:17:49.211Z",
                        "device_group_id": 0,
                        "device_id": 827716,
                        "device_name": "testsecdomain\\win-tv9ubklp1kn",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:10:43.001Z",
                        "enriched": true,
                        "enriched_event_type": [
                            "NETWORK"
                        ],
                        "event_type": [
                            "netconn"
                        ],
                        "ingress_time": 1617535044839,
                        "legacy": true,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-000ca144-00001388-00000000-1d660f262b3d3f2",
                        "parent_pid": 5000,
                        "process_guid": "7DESJ9GN-000ca144-000018a4-00000000-1d660f264a17328",
                        "process_hash": [
                            "5cf2e72aee581b5e3d16ff1d5c626fc6",
                            "c52b1e17afe7a2b956250c264883f6560aa5801db347f31f6845c592ef15a3a0"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            6308
                        ],
                        "process_username": [
                            "TESTSECDOMAIN\\Administrator"
                        ]
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:10:13.780Z",
                        "childproc_count": 0,
                        "crossproc_count": 1236,
                        "device_group_id": 0,
                        "device_id": 4122269,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:32.667Z",
                        "filemod_count": 0,
                        "ingress_time": 1617534590712,
                        "modload_count": 110,
                        "netconn_count": 0,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ee69d-00141598-00000000-1d7213e65afa079",
                        "parent_pid": 1316248,
                        "process_guid": "7DESJ9GN-003ee69d-00143f88-00000000-1d7214252af77a2",
                        "process_hash": [
                            "aa2e522a405cb5a295d3502c4ff6ca39",
                            "bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            1326984
                        ],
                        "process_username": [
                            "SECIOUS\\abhinav.thakur"
                        ],
                        "regmod_count": 0,
                        "scriptload_count": 0
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:10:13.780Z",
                        "childproc_count": 0,
                        "crossproc_count": 1236,
                        "device_group_id": 0,
                        "device_id": 4122269,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:32.665Z",
                        "filemod_count": 0,
                        "ingress_time": 1617534590712,
                        "modload_count": 110,
                        "netconn_count": 0,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ee69d-00141598-00000000-1d7213e65afa079",
                        "parent_pid": 1316248,
                        "process_guid": "7DESJ9GN-003ee69d-00144d50-00000000-1d7214249b0ae3e",
                        "process_hash": [
                            "aa2e522a405cb5a295d3502c4ff6ca39",
                            "bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            1330512
                        ],
                        "process_username": [
                            "SECIOUS\\abhinav.thakur"
                        ],
                        "regmod_count": 0,
                        "scriptload_count": 0
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:10:13.780Z",
                        "childproc_count": 0,
                        "crossproc_count": 1116,
                        "device_group_id": 0,
                        "device_id": 4122269,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:32.656Z",
                        "filemod_count": 0,
                        "ingress_time": 1617534590712,
                        "modload_count": 110,
                        "netconn_count": 0,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ee69d-00141598-00000000-1d7213e65afa079",
                        "parent_pid": 1316248,
                        "process_guid": "7DESJ9GN-003ee69d-0005ea74-00000000-1d7213e69dabdeb",
                        "process_hash": [
                            "aa2e522a405cb5a295d3502c4ff6ca39",
                            "bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            387700
                        ],
                        "process_username": [
                            "SECIOUS\\abhinav.thakur"
                        ],
                        "regmod_count": 0,
                        "scriptload_count": 0
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:10:13.780Z",
                        "childproc_count": 0,
                        "crossproc_count": 1117,
                        "device_group_id": 0,
                        "device_id": 4122269,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:32.653Z",
                        "enriched": true,
                        "enriched_event_type": [
                            "NETWORK"
                        ],
                        "event_type": [
                            "netconn"
                        ],
                        "filemod_count": 955,
                        "ingress_time": 1617534590712,
                        "legacy": true,
                        "modload_count": 145,
                        "netconn_count": 87,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ee69d-00141598-00000000-1d7213e65afa079",
                        "parent_pid": 1316248,
                        "process_guid": "7DESJ9GN-003ee69d-00144004-00000000-1d7213e699fafba",
                        "process_hash": [
                            "aa2e522a405cb5a295d3502c4ff6ca39",
                            "bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            1327108
                        ],
                        "process_username": [
                            "SECIOUS\\abhinav.thakur"
                        ],
                        "regmod_count": 0,
                        "scriptload_count": 0
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:10:13.780Z",
                        "childproc_count": 0,
                        "crossproc_count": 1116,
                        "device_group_id": 0,
                        "device_id": 4122269,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:32.651Z",
                        "filemod_count": 0,
                        "ingress_time": 1617534590712,
                        "modload_count": 160,
                        "netconn_count": 0,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ee69d-00141598-00000000-1d7213e65afa079",
                        "parent_pid": 1316248,
                        "process_guid": "7DESJ9GN-003ee69d-00143604-00000000-1d7213e6993a192",
                        "process_hash": [
                            "aa2e522a405cb5a295d3502c4ff6ca39",
                            "bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            1324548
                        ],
                        "process_username": [
                            "SECIOUS\\abhinav.thakur"
                        ],
                        "regmod_count": 0,
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
>| 4115768 | vm-2k12-vg63 | c:\program files (x86)\google\chrome\application\chrome.exe | 9246 | NETWORK |
>| 3898220 | development\vm-beats-dev | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 | NETWORK |
>| 3898220 | development\vm-beats-dev | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 | CREATE_PROCESS |
>| 4119679 | qa\win2k16-vg6-11 | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 | NETWORK |
>| 827716 | testsecdomain\win-tv9ubklp1kn | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 | NETWORK |
>| 4122269 | qa\thakurabt301 | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 |  |
>| 4122269 | qa\thakurabt301 | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 |  |
>| 4122269 | qa\thakurabt301 | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 |  |
>| 4122269 | qa\thakurabt301 | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 | NETWORK |
>| 4122269 | qa\thakurabt301 | c:\program files (x86)\google\chrome\application\chrome.exe | 6525 |  |


### cbd-get-policies
***
Gets the list of policies available in your organization.


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
            },
            {
                "description": null,
                "id": 6529,
                "latestRevision": 1613421692602,
                "name": "Restrictive_Windows_Workstation",
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
                            "id": 50,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 51,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 52,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 53,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 54,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 55,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 56,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 57,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 58,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 59,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 60,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 61,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 63,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 64,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 65,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 66,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 67,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\Microsoft Office\\**"
                            },
                            "id": 68,
                            "operation": "CODE_INJECTION",
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
                            "value": "true"
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
                            "value": "true"
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
            },
            {
                "description": null,
                "id": 6531,
                "latestRevision": 1613421692614,
                "name": "Standard_Mac_Workstation",
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
                                "enabled": false,
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
                            "id": 13,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 14,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 15,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 16,
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
            },
            {
                "description": null,
                "id": 6530,
                "latestRevision": 1613421692624,
                "name": "Standard_Windows_Workstation",
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
                            "id": 17,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 18,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 19,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 20,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 21,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 22,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 23,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 24,
                            "operation": "CODE_INJECTION",
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
            },
            {
                "description": "Test default policy for APL testing",
                "id": 61884,
                "latestRevision": 1613421692636,
                "name": "Aplura Policy",
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
                                "enabled": false,
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "true"
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
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "EDR policy to whitelist Armor Agent",
                "id": 42573,
                "latestRevision": 1613421692646,
                "name": "Armor Policy",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": true,
                                "PROTECTION": false
                            },
                            "path": "C:\\.armor\\**"
                        }
                    ],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "/opt/armor/**"
                            },
                            "id": 77,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\.armor\\opt\\filebeat-7.6.2-windows-x86_64\\install-service-filebeat.ps1C:\\.armor\\opt\\filebeat-7.6.2-windows-x86_64\\uninstall-service-filebeat.ps1"
                            },
                            "id": 78,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\.armor\\opt\\armor.exe"
                            },
                            "id": 79,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\.armor\\opt\\armor_uninstall.ps1"
                            },
                            "id": 80,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\.armor\\opt\\filebeat-7.6.2-windows-x86_64\\filebeat.exe"
                            },
                            "id": 81,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\.armor\\opt\\armor-supervisor.exe"
                            },
                            "id": 82,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\.armor\\opt\\winlogbeat-6.7.1-windows-x86_64\\install-service-winlogbeat.ps1"
                            },
                            "id": 83,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\.armor\\opt\\winlogbeat-6.7.1-windows-x86_64\\winlogbeat.exe"
                            },
                            "id": 84,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\.armor\\opt\\qualys\\QualysCloudAgent.exe"
                            },
                            "id": 85,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\.armor\\opt\\winlogbeat-6.7.1-windows-x86_64\\uninstall-service-winlogbeat.ps1"
                            },
                            "id": 86,
                            "operation": "BYPASS_ALL",
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "EDR policy to whitelist Armor Agent"
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "HIGH",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 64408,
                "latestRevision": 1613421692676,
                "name": "BlueHexagon_Policy",
                "policy": {
                    "avSettings": {
                        "apc": {
                            "enabled": true,
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
                            "profile": "AGGRESSIVE"
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": 86400000,
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "true"
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
                            "value": "true"
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
                            "value": "true"
                        }
                    ]
                },
                "priorityLevel": "HIGH",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 65982,
                "latestRevision": 1616604511060,
                "name": "BlueHexagon Policy_Quarantine",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 2
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
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
                            "id": 23,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 24,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 25,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 26,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 27,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 29,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 30,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 31,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 32,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 33,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 34,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 35,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 36,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 37,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 38,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 40,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 41,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 42,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 43,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 44,
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
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only, no prevention",
                "id": 21305,
                "latestRevision": 1613421692693,
                "name": "Chronicle Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 33819,
                "latestRevision": 1613421692701,
                "name": "Cigent Policy",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\succeed.bat"
                            },
                            "id": 715,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only2.exe"
                            },
                            "id": 716,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\succeed.bat"
                            },
                            "id": 717,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only2.exe"
                            },
                            "id": 718,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\succeed.bat"
                            },
                            "id": 719,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only2.exe"
                            },
                            "id": 720,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\succeed.bat"
                            },
                            "id": 721,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only2.exe"
                            },
                            "id": 723,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\succeed.bat"
                            },
                            "id": 725,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only2.exe"
                            },
                            "id": 726,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\succeed.bat"
                            },
                            "id": 727,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only2.exe"
                            },
                            "id": 728,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\succeed.bat"
                            },
                            "id": 729,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only2.exe"
                            },
                            "id": 730,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\succeed.bat"
                            },
                            "id": 731,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "ALLOW",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only2.exe"
                            },
                            "id": 732,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 733,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 734,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 735,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 736,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 737,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 738,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 739,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 740,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 741,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 742,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 743,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 744,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 745,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 746,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 747,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 748,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 749,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 750,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 751,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 752,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 754,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 756,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 758,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 760,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 762,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 764,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 765,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 766,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 767,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 768,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 769,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 770,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 771,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 772,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 773,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 774,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 775,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 776,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 777,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 778,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 779,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 780,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 781,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 782,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 783,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 784,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 785,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 786,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 787,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail*.bat"
                            },
                            "id": 788,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only3.exe"
                            },
                            "id": 789,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only4.exe"
                            },
                            "id": 790,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only5.exe"
                            },
                            "id": 791,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only_*.exe"
                            },
                            "id": 792,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\network_recon_local_only.exe"
                            },
                            "id": 793,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\cigent\\fail.bat"
                            },
                            "id": 794,
                            "operation": "RUN",
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "Cigent Policy 1 detail message"
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "HIGH",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 62075,
                "latestRevision": 1613421692711,
                "name": "D3Security",
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
                                "enabled": false,
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "true"
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
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "HIGH",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 12147,
                "latestRevision": 1613421692728,
                "name": "DefenseStorm Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": "false"
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection-only",
                "id": 12084,
                "latestRevision": 1613421692737,
                "name": "Demisto Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": "false"
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "example",
                "id": 67584,
                "latestRevision": 1617542840026,
                "name": "demisto test1",
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "example",
                "id": 67585,
                "latestRevision": 1617542846723,
                "name": "demisto test2",
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "This is Demisto's test policy",
                "id": 67586,
                "latestRevision": 1617542929543,
                "name": "Demisto test3",
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
            },
            {
                "description": "",
                "id": 12450,
                "latestRevision": 1613421692747,
                "name": "DFLabs Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 21299,
                "latestRevision": 1613421692756,
                "name": "Exabeam Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only no prevention",
                "id": 12753,
                "latestRevision": 1613421692765,
                "name": "Expel Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Initial Forescout policy, no protection turned on",
                "id": 10849,
                "latestRevision": 1613421692775,
                "name": "Forescout Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 62454,
                "latestRevision": 1613421692796,
                "name": "FortiSOAR",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
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
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": "false"
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Fortisoar-agent",
                "id": 63109,
                "latestRevision": 1613421692806,
                "name": "Fortisoar-agent",
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
                                "enabled": false,
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "true"
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
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "FortiSOAR-New-Updated",
                "id": 63085,
                "latestRevision": 1613421692816,
                "name": "FortiSOAR-New-Updated",
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
                                "enabled": false,
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 1,
                            "operation": "MEMORY_SCRAPE",
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 62506,
                "latestRevision": 1613421692835,
                "name": "FortiSOAR-Test1",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
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
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": "false"
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 35704,
                "latestRevision": 1617127516027,
                "name": "Fortress Policy",
                "policy": {
                    "avSettings": {
                        "apc": {
                            "enabled": true,
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
                            "profile": "AGGRESSIVE"
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 280,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 281,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 282,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 283,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 284,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 285,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 286,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 287,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**/python"
                            },
                            "id": 288,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\wscript.exe"
                            },
                            "id": 289,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cscript.exe"
                            },
                            "id": 290,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\wscript.exe"
                            },
                            "id": 291,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cscript.exe"
                            },
                            "id": 292,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\excel.exe"
                            },
                            "id": 293,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 294,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 295,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 296,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 298,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 300,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 301,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 302,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 303,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 304,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 305,
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SECURITY_CENTER_OPT",
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "MISSION_CRITICAL",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "This policy is for devices that have been suspected of an incident and a ticket has been created for resolution.",
                "id": 67372,
                "latestRevision": 1617227680943,
                "name": "? Fortress Policy 2",
                "policy": {
                    "avSettings": {
                        "apc": {
                            "enabled": true,
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
                            "profile": "AGGRESSIVE"
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 137,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 138,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 139,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 140,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 141,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 142,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 143,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 144,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 145,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cmd.exe"
                            },
                            "id": 146,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**/python"
                            },
                            "id": 147,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cscript.exe"
                            },
                            "id": 148,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\wscript.exe"
                            },
                            "id": 149,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cscript.exe"
                            },
                            "id": 150,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\wscript.exe"
                            },
                            "id": 151,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\excel.exe"
                            },
                            "id": 152,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 153,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 154,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 155,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 157,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 159,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 160,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 161,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 162,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\setup-x68_64.exe"
                            },
                            "id": 163,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cygwin.exe"
                            },
                            "id": 164,
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": "This system is currently under investigation."
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
                            "value": "true"
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
                            "value": "false"
                        },
                        {
                            "name": "SECURITY_CENTER_OPT",
                            "value": "true"
                        },
                        {
                            "name": "CB_LIVE_RESPONSE",
                            "value": "true"
                        },
                        {
                            "name": "UNINSTALL_CODE",
                            "value": "true"
                        },
                        {
                            "name": "UBS_OPT_IN",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_EXPEDITED_SCAN",
                            "value": "true"
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 25241,
                "latestRevision": 1613421692866,
                "name": "HPE Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 41528,
                "latestRevision": 1613421692880,
                "name": "Hunters Policy",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 19790,
                "latestRevision": 1613421692888,
                "name": "King Union Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 37780,
                "latestRevision": 1613421692898,
                "name": "Kognos Policy",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
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
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "test policy for documentation",
                "id": 66262,
                "latestRevision": 1615293404496,
                "name": "LiveOps",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": true,
                                "name": "ONACCESS_SCAN"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "directoryActionRules": null,
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 1,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 2,
                            "operation": "RUN",
                            "required": false
                        }
                    ],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
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
                            "value": "NORMAL"
                        },
                        {
                            "name": "QUARANTINE_DEVICE_MESSAGE",
                            "value": ""
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
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "test policy for documentation",
                "id": 66668,
                "latestRevision": 1616074387715,
                "name": "LiveOpse",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 2
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
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
                            "id": 31,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 32,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 33,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 34,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 35,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 37,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 38,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 39,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 40,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 41,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 42,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 43,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 44,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 45,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 46,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 48,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 49,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 50,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 51,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 52,
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "For them to generate events for log file creation",
                "id": 9246,
                "latestRevision": 1613421692906,
                "name": "LogRhythm Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                                "type": "NAME_PATH",
                                "value": "C:\\Program Files\\Nmap\\nmap.exe"
                            },
                            "id": 16,
                            "operation": "RUN",
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 63139,
                "latestRevision": 1615237421776,
                "name": "LRDemo-JH",
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
                                "enabled": false,
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 59,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 60,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 61,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 62,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 64,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 65,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 66,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 67,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 68,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 69,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 70,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 71,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 73,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 74,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 75,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 76,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 77,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 78,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 79,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 80,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 82,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 83,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 84,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 85,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 86,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 87,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 88,
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "true"
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
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 65120,
                "latestRevision": 1615894754537,
                "name": "Lumu Policy",
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 2
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
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
                            "id": 90,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 91,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 92,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 93,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 94,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 96,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 97,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 98,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 99,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 100,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 101,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 102,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 103,
                            "operation": "NETWORK",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 104,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 105,
                            "operation": "RUN_INMEMORY_CODE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 107,
                            "operation": "POL_INVOKE_NOT_TRUSTED",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 108,
                            "operation": "INVOKE_CMD_INTERPRETER",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 109,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 110,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 111,
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
                            "value": "true"
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
                            "value": "true"
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
            },
            {
                "description": "",
                "id": 12807,
                "latestRevision": 1613421692947,
                "name": "Minerva Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only no prevention",
                "id": 13131,
                "latestRevision": 1613421692955,
                "name": "Netskope Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only, no prevention",
                "id": 21265,
                "latestRevision": 1613421692965,
                "name": "Nozomi Networks Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "some protections on",
                "id": 21385,
                "latestRevision": 1613421692973,
                "name": "ObserveIT Policy",
                "policy": {
                    "avSettings": {
                        "apc": {
                            "enabled": true,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 11,
                            "operation": "CODE_INJECTION",
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
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 13,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 14,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 15,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 16,
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
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Holding bay to organize their endpoints, no protection",
                "id": 9247,
                "latestRevision": 1613421692984,
                "name": "OPSWAT Policy 1",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "For OPSWAT interoperability testing",
                "id": 7691,
                "latestRevision": 1613421692994,
                "name": "OPSWAT Policy 2",
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
                            "id": 41,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 42,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 43,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 44,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 45,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 46,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 47,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 48,
                            "operation": "CODE_INJECTION",
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
                            "value": "true"
                        },
                        {
                            "name": "BACKGROUND_SCAN",
                            "value": "true"
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
                            "value": "true"
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
                            "name": "SHOW_FULL_UI",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Same as OPSWAT_Policy but with &amp;quot;Scanner Config, On-Access File Scan Mode&amp;quot; setting disabled.",
                "id": 10124,
                "latestRevision": 1613421693007,
                "name": "OPSWAT Policy 3",
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "id": 17,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 18,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 19,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 20,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 21,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 22,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 23,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell.exe"
                            },
                            "id": 24,
                            "operation": "CODE_INJECTION",
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
                            "value": "true"
                        },
                        {
                            "name": "BACKGROUND_SCAN",
                            "value": "true"
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
                            "name": "SHOW_FULL_UI",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Development and Testing for Integrations",
                "id": 62024,
                "latestRevision": 1613421693018,
                "name": "! Partner Policy Template",
                "policy": {
                    "avSettings": {
                        "apc": {
                            "enabled": true,
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
                            "profile": "AGGRESSIVE"
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 228,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 229,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 230,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 231,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 232,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 233,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 234,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 235,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 236,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 237,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 238,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 239,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**/python"
                            },
                            "id": 240,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cscript.exe"
                            },
                            "id": 241,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\wscript.exe"
                            },
                            "id": 242,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cscript.exe"
                            },
                            "id": 243,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\wscript.exe"
                            },
                            "id": 244,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\excel.exe"
                            },
                            "id": 245,
                            "operation": "INVOKE_CMD_INTERPRETER",
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SECURITY_CENTER_OPT",
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only no prevention",
                "id": 12864,
                "latestRevision": 1613421693029,
                "name": "Phantom Policy 1",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "test policy for phantom reasons",
                "id": 13126,
                "latestRevision": 1613421693039,
                "name": "Phantom Policy 2",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "id": 1,
                            "operation": "RANSOM",
                            "required": true
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\test\\test"
                            },
                            "id": 4,
                            "operation": "BYPASS_ALL",
                            "required": false
                        },
                        {
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "c:\\test\\testing_path"
                            },
                            "id": 7,
                            "operation": "BYPASS_ALL",
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
                            "value": "true"
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
                            "value": "true"
                        },
                        {
                            "name": "QUARANTINE_DEVICE_MESSAGE",
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "true"
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
                            "value": "true"
                        },
                        {
                            "name": "CB_LIVE_RESPONSE",
                            "value": "false"
                        },
                        {
                            "name": "UNINSTALL_CODE",
                            "value": "true"
                        },
                        {
                            "name": "UBS_OPT_IN",
                            "value": "true"
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "The sensors for windows workstations in the contoso network",
                "id": 61946,
                "latestRevision": 1613421693049,
                "name": "Rangeforce Policy 1",
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
                                "enabled": false,
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "true"
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
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 40278,
                "latestRevision": 1613421693098,
                "name": "Rangeforce Policy 2",
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
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
                            "value": "true"
                        },
                        {
                            "name": "UBS_OPT_IN",
                            "value": "true"
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only",
                "id": 12477,
                "latestRevision": 1613421693107,
                "name": "Rapid7 Policy 1",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 40062,
                "latestRevision": 1613421693117,
                "name": "Rapid7 Policy 2",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "action": "IGNORE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "C:\\Program Files\\rapid7\\Insight Agent\\*"
                            },
                            "id": 6,
                            "operation": "BYPASS_ALL",
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Replicate of Fortress Policy - recommended for initial review",
                "id": 46665,
                "latestRevision": 1613421693126,
                "name": "Remediant Policy",
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
                            "profile": "AGGRESSIVE"
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
                    "id": -1,
                    "knownBadHashAutoDeleteDelayMs": null,
                    "rules": [
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "KNOWN_MALWARE"
                            },
                            "id": 19,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "COMPANY_BLACK_LIST"
                            },
                            "id": 20,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 21,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "RESOLVING"
                            },
                            "id": 22,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "PUP"
                            },
                            "id": 23,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "SUSPECT_MALWARE"
                            },
                            "id": 24,
                            "operation": "RUN",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 25,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "REPUTATION",
                                "value": "ADAPTIVE_WHITE_LIST"
                            },
                            "id": 26,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 27,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 28,
                            "operation": "RANSOM",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 29,
                            "operation": "INVOKE_SCRIPT",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\powershell*.exe"
                            },
                            "id": 30,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**/python"
                            },
                            "id": 31,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cscript.exe"
                            },
                            "id": 32,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "TERMINATE",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\wscript.exe"
                            },
                            "id": 33,
                            "operation": "MEMORY_SCRAPE",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\cscript.exe"
                            },
                            "id": 34,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\wscript.exe"
                            },
                            "id": 35,
                            "operation": "CODE_INJECTION",
                            "required": false
                        },
                        {
                            "action": "DENY",
                            "application": {
                                "type": "NAME_PATH",
                                "value": "**\\excel.exe"
                            },
                            "id": 36,
                            "operation": "INVOKE_CMD_INTERPRETER",
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SECURITY_CENTER_OPT",
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 12210,
                "latestRevision": 1613421693136,
                "name": "Resolve Systems Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "detection only no prevention",
                "id": 22020,
                "latestRevision": 1613421693144,
                "name": "Respond Software Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only no prevention",
                "id": 21518,
                "latestRevision": 1613421693173,
                "name": "Securonix Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 12229,
                "latestRevision": 1613647084924,
                "name": "Siemplify Policy 1",
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
                                "enabled": false,
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "MISSION_CRITICAL",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "test",
                "id": 32242,
                "latestRevision": 1613421693190,
                "name": "Siemplify Policy 2",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "id": 3,
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "detection only no prevention",
                "id": 22618,
                "latestRevision": 1613421693205,
                "name": "SkyFormation Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
                            }
                        },
                        "updateServers": {
                            "servers": [],
                            "serversForOffSiteDevices": [
                                "http://updates2.cdc.carbonblack.io/update2"
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
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only no prevention",
                "id": 21560,
                "latestRevision": 1613421693214,
                "name": "Smokescreen Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "",
                "id": 62444,
                "latestRevision": 1613421693224,
                "name": "StellarPolicy",
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": ""
                        }
                    ],
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
                        },
                        {
                            "name": "SCAN_NETWORK_DRIVE",
                            "value": "true"
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
                            "value": "true"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only policy for Windows lab sensors",
                "id": 38569,
                "latestRevision": 1613421693234,
                "name": "SumoLogic Policy",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only",
                "id": 12446,
                "latestRevision": 1613421693243,
                "name": "Swimlane Policy 1",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Used for Demo - Currently a duplicate of Swimlane Policy (NOT restricted)",
                "id": 25608,
                "latestRevision": 1613421693252,
                "name": "Swimlane Policy 2",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "LOW",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "Detection only no prevention",
                "id": 21554,
                "latestRevision": 1613421693262,
                "name": "Syncurity Policy",
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": "Yea - we are CB!"
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "detection only no prevention",
                "id": 21606,
                "latestRevision": 1613421693284,
                "name": "Tenable Policy",
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
                                "enabled": false,
                                "name": "SIGNATURE_UPDATE"
                            },
                            {
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 4
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
                    "rules": [],
                    "sensorSettings": [
                        {
                            "name": "ALLOW_UNINSTALL",
                            "value": "true"
                        },
                        {
                            "name": "ALLOW_UPLOADS",
                            "value": "true"
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
                            "value": "Your device has been quarantined. Please contact your administrator."
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
                            "value": "true"
                        },
                        {
                            "name": "POLICY_ACTION_OVERRIDE",
                            "value": "true"
                        },
                        {
                            "name": "HELP_MESSAGE",
                            "value": ""
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
                            "value": "false"
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
                        }
                    ]
                },
                "priorityLevel": "MEDIUM",
                "systemPolicy": false,
                "version": 2
            },
            {
                "description": "test- update policy",
                "id": 25177,
                "latestRevision": 1613421693294,
                "name": "Updated CyberSponse Policy",
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
                                "enabled": false,
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 2
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": false,
                                "PROTECTION": false
                            },
                            "path": "C:\\FXCM\\**"
                        },
                        {
                            "actions": {
                                "FILE_UPLOAD": true,
                                "PROTECTION": false
                            },
                            "path": "sadf"
                        },
                        {
                            "actions": {
                                "FILE_UPLOAD": true,
                                "PROTECTION": false
                            },
                            "path": "/Users/**"
                        }
                    ],
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
            },
            {
                "description": "",
                "id": 65066,
                "latestRevision": 1613673367957,
                "name": "?? Wide Open",
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
                                "initialRandomDelayHours": 4,
                                "intervalHours": 2
                            }
                        },
                        "updateServers": {
                            "servers": [
                                {
                                    "flags": 0,
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
                    "directoryActionRules": [
                        {
                            "actions": {
                                "FILE_UPLOAD": true,
                                "PROTECTION": false
                            },
                            "path": "C:\\Users\\*\\Desktop\\**"
                        }
                    ],
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
                "systemPolicy": false,
                "version": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Policies
>|Id|Priority Level|System Policy|Latest Revision|Version|
>|---|---|---|---|---|
>| 6525 | LOW | true | 2021-04-02T06:05:12.000Z | 2 |
>| 6527 | HIGH | true | 2021-02-15T20:41:32.000Z | 2 |
>| 6528 | MEDIUM | true | 2021-02-15T20:41:32.000Z | 2 |
>| 6529 | MEDIUM | true | 2021-02-15T20:41:32.000Z | 2 |
>| 6531 | MEDIUM | true | 2021-02-15T20:41:32.000Z | 2 |
>| 6530 | MEDIUM | true | 2021-02-15T20:41:32.000Z | 2 |
>| 61884 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 42573 | HIGH | false | 2021-02-15T20:41:32.000Z | 2 |
>| 64408 | HIGH | false | 2021-02-15T20:41:32.000Z | 2 |
>| 65982 | MEDIUM | false | 2021-03-24T16:48:31.000Z | 2 |
>| 21305 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 33819 | HIGH | false | 2021-02-15T20:41:32.000Z | 2 |
>| 62075 | HIGH | false | 2021-02-15T20:41:32.000Z | 2 |
>| 12147 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 12084 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 67584 | LOW | false | 2021-04-04T13:27:20.000Z | 2 |
>| 67585 | LOW | false | 2021-04-04T13:27:26.000Z | 2 |
>| 67586 | HIGH | false | 2021-04-04T13:28:49.000Z | 2 |
>| 12450 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 21299 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 12753 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 10849 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 62454 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 63109 | LOW | false | 2021-02-15T20:41:32.000Z | 2 |
>| 63085 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 62506 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 35704 | MISSION_CRITICAL | false | 2021-03-30T18:05:16.000Z | 2 |
>| 67372 | MEDIUM | false | 2021-03-31T21:54:40.000Z | 2 |
>| 25241 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 41528 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 19790 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 37780 | LOW | false | 2021-02-15T20:41:32.000Z | 2 |
>| 66262 | LOW | false | 2021-03-09T12:36:44.000Z | 2 |
>| 66668 | LOW | false | 2021-03-18T13:33:07.000Z | 2 |
>| 9246 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 63139 | MEDIUM | false | 2021-03-08T21:03:41.000Z | 2 |
>| 65120 | LOW | false | 2021-03-16T11:39:14.000Z | 2 |
>| 12807 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 13131 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 21265 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 21385 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 9247 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 7691 | MEDIUM | false | 2021-02-15T20:41:32.000Z | 2 |
>| 10124 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 62024 | LOW | false | 2021-02-15T20:41:33.000Z | 2 |
>| 12864 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 13126 | LOW | false | 2021-02-15T20:41:33.000Z | 2 |
>| 61946 | LOW | false | 2021-02-15T20:41:33.000Z | 2 |
>| 40278 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 12477 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 40062 | LOW | false | 2021-02-15T20:41:33.000Z | 2 |
>| 46665 | LOW | false | 2021-02-15T20:41:33.000Z | 2 |
>| 12210 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 22020 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 21518 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 12229 | MISSION_CRITICAL | false | 2021-02-18T11:18:04.000Z | 2 |
>| 32242 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 22618 | LOW | false | 2021-02-15T20:41:33.000Z | 2 |
>| 21560 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 62444 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 38569 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 12446 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 25608 | LOW | false | 2021-02-15T20:41:33.000Z | 2 |
>| 21554 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 21606 | MEDIUM | false | 2021-02-15T20:41:33.000Z | 2 |
>| 25177 | LOW | false | 2021-02-15T20:41:33.000Z | 2 |
>| 65066 | LOW | false | 2021-02-18T18:36:07.000Z | 2 |


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

>### Carbon Black Defense Policy
>|Id|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|
>| 6527 | Detection_Servers | 2021-02-15T20:41:32.000Z | 2 | HIGH | true |


### cbd-set-policy
***
Resets policy fields.


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
```!cbd-set-policy policy=67584 keyValue=`{"policyInfo": {"description": "update example", "name": "demisto test1", "id": 67584, "policy": {"sensorSettings": [{"name": "SHOW_UI", "value": "true"}]}, "priorityLevel": "HIGH"}}````

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "update example",
            "id": 67584,
            "latestRevision": 1617542937951,
            "name": "demisto test1",
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

>### Carbon Black Defense Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 67584 | update example | demisto test1 | 2021-04-04T13:28:57.000Z | 2 | HIGH | false |


### cbd-create-policy
***
Creates a new policy on the CB Defense backend.


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
```!cbd-create-policy description=`This is Demisto's test policy` name=`Demisto test3` priorityLevel=HIGH policy=`{}````

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "This is Demisto's test policy",
            "id": 67586,
            "latestRevision": 1617542929543,
            "name": "Demisto test3",
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

>### Carbon Black Defense Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 67586 | This is Demisto's test policy | Demisto test3 | 2021-04-04T13:28:49.000Z | 2 | HIGH | false |


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
```!cbd-update-policy id=67584 description=`This is Demisto's test policy after an update` name=`demisto test1` priorityLevel=LOW policy=`{"sensorSettings": [{"name": "SHOW_UI", "value": "false"}]}````

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "This is Demisto's test policy after an update",
            "id": 67584,
            "latestRevision": 1617542940381,
            "name": "demisto test1",
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

>### Carbon Black Defense Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 67584 | This is Demisto's test policy after an update | demisto test1 | 2021-04-04T13:29:00.000Z | 2 | LOW | false |


### cbd-add-rule-to-policy
***
Adds a new rule to an existing policy. Note: System policies cannot be modified.


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
```!cbd-add-rule-to-policy action=ALLOW operation=RANSOM required=true type=REPUTATION value=COMPANY_BLACK_LIST policyId=67584```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "This is Demisto's test policy after an update",
            "id": 67584,
            "latestRevision": 1617542944659,
            "name": "demisto test1",
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

>### Carbon Black Defense Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 67584 | This is Demisto's test policy after an update | demisto test1 | 2021-04-04T13:29:04.000Z | 2 | LOW | false |


### cbd-update-rule-in-policy
***
Updates an existing rule with a new rule. Note: System policies cannot be modified.


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
```!cbd-update-rule-in-policy action=ALLOW operation=RANSOM required=false id=23 type=REPUTATION value=COMPANY_BLACK_LIST policyId=67584```

#### Context Example
```json
{
    "CarbonBlackDefense": {
        "Policy": {
            "description": "This is Demisto's test policy after an update",
            "id": 67584,
            "latestRevision": 1617542947344,
            "name": "demisto test1",
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

>### Carbon Black Defense Policy
>|Id|Description|Name|Latest Revision|Version|Priority Level|System Policy|
>|---|---|---|---|---|---|---|
>| 67584 | This is Demisto's test policy after an update | demisto test1 | 2021-04-04T13:29:07.000Z | 2 | LOW | false |


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

#### Command Example
```!cbd-delete-rule-from-policy policyId=67584 ruleId=23```

#### Human Readable Output

>### The rule was successfully deleted from the policy
>|Message|Success|
>|---|---|
>| Success | true |


### cbd-find-events-results
***
Retrieves the result for an enriched events search request for a given job ID. By default returns 10 rows.


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
| CarbonBlackDefense.Events.Results | Unknown | The results of the event. | 
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
                        "device_id": 4122269,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:29.978Z",
                        "enriched": true,
                        "enriched_event_type": "CREATE_PROCESS",
                        "event_description": "The application \"<share><link hash=\"2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f\">C:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\cr_60f73.tmp\\setup.exe</link></share>\" invoked the application \"<share><link hash=\"2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f\">C:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\cr_60f73.tmp\\setup.exe</link></share>\". The operation was <accent>blocked</accent> and the application <accent>terminated by Cb Defense</accent>.",
                        "event_id": "223fef63953611eb87dcff94616fdceb",
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
                        "device_id": 4122269,
                        "device_name": "qa\\thakurabt301",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:08:29.649Z",
                        "enriched": true,
                        "enriched_event_type": "FILE_CREATE",
                        "event_description": "The file \"<share><link hash=\"2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f\">C:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\cr_60f73.tmp\\setup.exe</link></share>\" was first detected on a local disk. The device was off the corporate network using the public address 65.127.112.131 (located in Arvada CO, United States). The file is signed and is part of Google Chrome Installer by Google LLC.  The file was created by the application \"<share><link hash=\"0b7094c2c6a97d7fb4ac08a8a03e09f0207861916eb83f4742ba9a5e73ff9846\">C:\\program files (x86)\\google\\update\\install\\{29175460-7f1a-4a09-b7e9-a7feb7c2f3c3}\\89.0.4389.114_chrome_installer.exe</link></share>\".",
                        "event_id": "223fef6b953611eb87dcff94616fdceb",
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
                        "backend_timestamp": "2021-04-04T11:06:41.144Z",
                        "device_group_id": 0,
                        "device_id": 4119679,
                        "device_name": "qa\\win2k16-vg6-11",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:04:56.227Z",
                        "enriched": true,
                        "enriched_event_type": "NETWORK",
                        "event_description": "The application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" established a <accent>TCP/443</accent> connection to <share><accent>142.250.76.67</accent></share><accent>:443</accent> (<share><accent>clientservices.googleapis.com</accent></share>, located in United States) from <share><accent>10.4.0.166</accent></share><accent>:9429</accent>. The device was off the corporate network using the public address <accent>65.127.112.131</accent> (<accent>win2k16-vg6-11.QA.schq.secious.com</accent>, located in Arvada CO, United States). The operation was successful.",
                        "event_id": "b80431a8953511ebb3178b33043bacec",
                        "event_network_inbound": false,
                        "event_network_local_ipv4": "10.4.0.166",
                        "event_network_location": ",,United States",
                        "event_network_protocol": "TCP",
                        "event_network_remote_ipv4": "142.250.76.67",
                        "event_network_remote_port": 443,
                        "event_type": "netconn",
                        "ingress_time": 1617534370742,
                        "legacy": true,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003edc7f-00002948-00000000-1d71af36cb14c00",
                        "parent_pid": 10568,
                        "process_guid": "7DESJ9GN-003edc7f-00002bc0-00000000-1d71af36d265076",
                        "process_hash": [
                            "aa2e522a405cb5a295d3502c4ff6ca39",
                            "bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            11200
                        ],
                        "process_username": [
                            "WIN2K16-VG6-11\\Administrator"
                        ]
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:03:38.893Z",
                        "device_group_id": 0,
                        "device_id": 4115768,
                        "device_name": "vm-2k12-vg63",
                        "device_policy_id": 9246,
                        "device_timestamp": "2021-04-04T11:01:57.673Z",
                        "enriched": true,
                        "enriched_event_type": "NETWORK",
                        "event_description": "The application \"<share><link hash=\"cbc104fcc03cb2acbdafc2fe2669e8da54993f8d21d8851d4d80ecec26a3a9f0\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" established a <accent>TCP/443</accent> connection to <share><accent>142.250.196.42</accent></share><accent>:443</accent> (<share><accent>safebrowsing.googleapis.com</accent></share>, located in United States) from <share><accent>10.4.0.252</accent></share><accent>:35051</accent>. The device was off the corporate network using the public address <accent>65.127.112.131</accent> (<accent>VM-2K12-VG63.QA.schq.secious.com</accent>, located in Arvada CO, United States). The operation was successful.",
                        "event_id": "49c78653953511eb87dcff94616fdceb",
                        "event_network_inbound": false,
                        "event_network_local_ipv4": "10.4.0.252",
                        "event_network_location": ",,United States",
                        "event_network_protocol": "TCP",
                        "event_network_remote_ipv4": "142.250.196.42",
                        "event_network_remote_port": 443,
                        "event_type": "netconn",
                        "ingress_time": 1617534186991,
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
                        "backend_timestamp": "2021-04-04T11:02:38.137Z",
                        "device_group_id": 0,
                        "device_id": 4117626,
                        "device_name": "vm-2k12-vg73",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:01:17.432Z",
                        "enriched": true,
                        "enriched_event_type": "CREATE_PROCESS",
                        "event_description": "The application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" invoked the application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\". ",
                        "event_id": "21c7807f953511ebb29df7b1ea790e8a",
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
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:02:38.137Z",
                        "device_group_id": 0,
                        "device_id": 4117626,
                        "device_name": "vm-2k12-vg73",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:01:17.181Z",
                        "enriched": true,
                        "enriched_event_type": "CREATE_PROCESS",
                        "event_description": "The application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" invoked the application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\". ",
                        "event_id": "21c7807e953511ebb29df7b1ea790e8a",
                        "event_type": "childproc",
                        "ingress_time": 1617534118062,
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
                    },
                    {
                        "backend_timestamp": "2021-04-04T11:02:38.137Z",
                        "device_group_id": 0,
                        "device_id": 4117626,
                        "device_name": "vm-2k12-vg73",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T11:01:16.812Z",
                        "enriched": true,
                        "enriched_event_type": "CREATE_PROCESS",
                        "event_description": "The application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" invoked the application \"<share><link hash=\"bb8b199f504db7e81cf32ce3c458d2a8533beac8dcefa5df024fa79fe132648a\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\". ",
                        "event_id": "21c7807d953511ebb29df7b1ea790e8a",
                        "event_type": "childproc",
                        "ingress_time": 1617534120112,
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
                    },
                    {
                        "backend_timestamp": "2021-04-04T10:59:35.496Z",
                        "device_group_id": 0,
                        "device_id": 3860531,
                        "device_name": "win10-cbclient1",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T10:58:07.582Z",
                        "enriched": true,
                        "enriched_event_type": "NETWORK",
                        "event_description": "The application \"<share><link hash=\"8ceee04d6316e2ba04fdf2222506fc8be7b3cd158d843c4edc23d8de5e2f77d9\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" established a <accent>UDP/443</accent> connection to <share><accent>172.217.4.74</accent></share><accent>:443</accent> (<share><accent>safebrowsing.googleapis.com</accent></share>, located in United States) from <share><accent>172.26.114.90</accent></share><accent>:53148</accent>. The device was off the corporate network using the public address <accent>161.47.37.87</accent> (<accent>win10-CBClient1.holymatcha.com</accent>, located in United States). The operation was successful.",
                        "event_id": "b5eeb4ec953411eb8af72dacb2908592",
                        "event_network_inbound": false,
                        "event_network_local_ipv4": "172.26.114.90",
                        "event_network_location": ",,United States",
                        "event_network_protocol": "UDP",
                        "event_network_remote_ipv4": "172.217.4.74",
                        "event_network_remote_port": 443,
                        "event_type": "netconn",
                        "ingress_time": 1617533939171,
                        "legacy": true,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ae833-000024c8-00000000-1d71721e9bba8f6",
                        "parent_pid": 9416,
                        "process_guid": "7DESJ9GN-003ae833-000025b8-00000000-1d71721f02a99fe",
                        "process_hash": [
                            "6bfe4850808952622e41f88db244393b",
                            "8ceee04d6316e2ba04fdf2222506fc8be7b3cd158d843c4edc23d8de5e2f77d9"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            9656
                        ],
                        "process_username": [
                            "WIN10-CBCLIENT1\\Alex"
                        ]
                    },
                    {
                        "backend_timestamp": "2021-04-04T10:59:35.496Z",
                        "device_group_id": 0,
                        "device_id": 3860531,
                        "device_name": "win10-cbclient1",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T10:57:39.651Z",
                        "enriched": true,
                        "enriched_event_type": "NETWORK",
                        "event_description": "The application \"<share><link hash=\"8ceee04d6316e2ba04fdf2222506fc8be7b3cd158d843c4edc23d8de5e2f77d9\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" established a <accent>UDP/443</accent> connection to <share><accent>172.217.1.35</accent></share><accent>:443</accent> (<share><accent>clientservices.googleapis.com</accent></share>, located in United States) from <share><accent>172.26.114.90</accent></share><accent>:50078</accent>. The device was off the corporate network using the public address <accent>161.47.37.87</accent> (<accent>win10-CBClient1.holymatcha.com</accent>, located in United States). The operation was successful.",
                        "event_id": "b5eeb4eb953411eb8af72dacb2908592",
                        "event_network_inbound": false,
                        "event_network_local_ipv4": "172.26.114.90",
                        "event_network_location": ",,United States",
                        "event_network_protocol": "UDP",
                        "event_network_remote_ipv4": "172.217.1.35",
                        "event_network_remote_port": 443,
                        "event_type": "netconn",
                        "ingress_time": 1617533937849,
                        "legacy": true,
                        "org_id": "7DESJ9GN",
                        "parent_guid": "7DESJ9GN-003ae833-000024c8-00000000-1d71721e9bba8f6",
                        "parent_pid": 9416,
                        "process_guid": "7DESJ9GN-003ae833-000025b8-00000000-1d71721f02a99fe",
                        "process_hash": [
                            "6bfe4850808952622e41f88db244393b",
                            "8ceee04d6316e2ba04fdf2222506fc8be7b3cd158d843c4edc23d8de5e2f77d9"
                        ],
                        "process_name": "c:\\program files (x86)\\google\\chrome\\application\\chrome.exe",
                        "process_pid": [
                            9656
                        ],
                        "process_username": [
                            "WIN10-CBCLIENT1\\Alex"
                        ]
                    },
                    {
                        "backend_timestamp": "2021-04-04T10:48:57.833Z",
                        "device_group_id": 0,
                        "device_id": 3898220,
                        "device_name": "development\\vm-beats-dev",
                        "device_policy_id": 6525,
                        "device_timestamp": "2021-04-04T10:47:21.498Z",
                        "enriched": true,
                        "enriched_event_type": "NETWORK",
                        "event_description": "The application \"<share><link hash=\"8ceee04d6316e2ba04fdf2222506fc8be7b3cd158d843c4edc23d8de5e2f77d9\">C:\\program files (x86)\\google\\chrome\\application\\chrome.exe</link></share>\" established a <accent>TCP/443</accent> connection to <share><accent>140.82.113.4</accent></share><accent>:443</accent> (<share><accent>github.com</accent></share>, located in United States) from <share><accent>10.3.0.99</accent></share><accent>:56848</accent>. The device was off the corporate network using the public address <accent>65.127.112.131</accent> (<accent>host.docker.internal</accent>, located in Arvada CO, United States). The operation was successful.",
                        "event_id": "41194d79953311ebac689b89a202a0eb",
                        "event_network_inbound": false,
                        "event_network_local_ipv4": "10.3.0.99",
                        "event_network_location": ",,United States",
                        "event_network_protocol": "TCP",
                        "event_network_remote_ipv4": "140.82.113.4",
                        "event_network_remote_port": 443,
                        "event_type": "netconn",
                        "ingress_time": 1617533315047,
                        "legacy": true,
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
                            "SECIOUS\\shalini.chaturvedi"
                        ]
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Event Results
>|Event Id|Device Id|Event Network Remote Port|Event Network Remote Ipv4|Event Network Local Ipv4|Enriched Event Type|
>|---|---|---|---|---|---|
>| 223fef63953611eb87dcff94616fdceb | 4122269 |  |  |  | CREATE_PROCESS |
>| 223fef6b953611eb87dcff94616fdceb | 4122269 |  |  |  | FILE_CREATE |
>| b80431a8953511ebb3178b33043bacec | 4119679 | 443 | 142.250.76.67 | 10.4.0.166 | NETWORK |
>| 49c78653953511eb87dcff94616fdceb | 4115768 | 443 | 142.250.196.42 | 10.4.0.252 | NETWORK |
>| 21c7807f953511ebb29df7b1ea790e8a | 4117626 |  |  |  | CREATE_PROCESS |
>| 21c7807e953511ebb29df7b1ea790e8a | 4117626 |  |  |  | CREATE_PROCESS |
>| 21c7807d953511ebb29df7b1ea790e8a | 4117626 |  |  |  | CREATE_PROCESS |
>| b5eeb4ec953411eb8af72dacb2908592 | 3860531 | 443 | 172.217.4.74 | 172.26.114.90 | NETWORK |
>| b5eeb4eb953411eb8af72dacb2908592 | 3860531 | 443 | 172.217.1.35 | 172.26.114.90 | NETWORK |
>| 41194d79953311ebac689b89a202a0eb | 3898220 | 443 | 140.82.113.4 | 10.3.0.99 | NETWORK |


### cbd-find-events-details
***
Initiates a request to retrieve detail fields for enriched events.  the job_id that returns from this command can be used to get the results using the "cbd-find-events-details-results" command.


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

>### Carbon Black Defense Event Details Search
>|Job Id|
>|---|
>| 3b7c0a61-2ef5-4541-b9bb-2389bd009d32 |


### cbd-find-events-details-results
***
Retrieves the status for an enriched events detail request for a given job ID.


#### Base Command

`cbd-find-events-details-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
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
                "approximate_unaggregated": 1,
                "completed": 46,
                "contacted": 46,
                "num_aggregated": 1,
                "num_available": 1,
                "num_found": 1,
                "results": [
                    {
                        "backend_timestamp": "2021-03-21T15:16:41.491Z",
                        "device_external_ip": "18.220.31.78",
                        "device_group_id": 0,
                        "device_id": 827716,
                        "device_installed_by": "TestSecDomain.test\\Administrator",
                        "device_internal_ip": "10.0.229.9",
                        "device_location": "OFFSITE",
                        "device_name": "testsecdomain\\win-tv9ubklp1kn",
                        "device_os": "WINDOWS",
                        "device_os_version": "Server 2012 R2 x64",
                        "device_policy": "default",
                        "device_policy_id": 6525,
                        "device_target_priority": "LOW",
                        "device_timestamp": "2021-03-21T15:10:35.067Z",
                        "document_guid": "3PV7ySZATKOrARnUaY6zqA",
                        "enriched": true,
                        "enriched_event_type": "NETWORK",
                        "event_description": "The application \"<share><link hash=\"c52b1e17afe7a2b956250c264883f6560aa5801db347f31f6845c592ef15a3a0\">C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe</link></share>\" established a <accent>UDP/443</accent> connection to <share><accent>172.217.4.195</accent></share><accent>:443</accent> (<share><accent>clientservices.googleapis.com</accent></share>, located in United States) from <share><accent>10.0.229.9</accent></share><accent>:52527</accent>. The device was off the corporate network using the public address <accent>18.220.31.78</accent> (<accent>WIN-TV9UBKLP1KN.TestSecDomain.test</accent>, located in Columbus OH, United States). The operation was successful.",
                        "event_id": "5edd7a0e8a5811ebb29df7b1ea790e8a",
                        "event_network_inbound": false,
                        "event_network_local_ipv4": "10.0.229.9",
                        "event_network_location": ",,United States",
                        "event_network_protocol": "UDP",
                        "event_network_remote_ipv4": "172.217.4.195",
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
                            "\"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe\" --type=utility --utility-sub-type=network.mojom.NetworkService --field-trial-handle=1184,13396929298740803928,12863694328792823850,131072 --lang=en-US --service-sandbox-type=network --enable-audio-service-sandbox --mojo-platform-channel-handle=1560 /prefetch:8"
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
                        "process_sha256": "c52b1e17afe7a2b956250c264883f6560aa5801db347f31f6845c592ef15a3a0",
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

>### Carbon Black Defense Event Details Results
>|Event Id|Device Id|Event Network Remote Port|Event Network Remote Ipv4|Event Network Local Ipv4|Enriched Event Type|
>|---|---|---|---|---|---|
>| 5edd7a0e8a5811ebb29df7b1ea790e8a | 827716 | 443 | 172.217.4.195 | 10.0.229.9 | NETWORK |


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

#### Command Example
```!cbd-device-quarantine device_id=3925348```

#### Human Readable Output

>Device quarantine successfully

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

#### Command Example
```!cbd-device-unquarantine device_id=3925348```

#### Human Readable Output

>Device unquarantine successfully

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

#### Command Example
```!cbd-device-background-scan device_id=3925348```

#### Human Readable Output

>Background scan started successfully

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

#### Command Example
```!cbd-device-background-scan-stop device_id=3925348```

#### Human Readable Output

>Background scan stopped successfully

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

#### Command Example
```!cbd-device-bypass device_id=3925348```

#### Human Readable Output

>Device bypass successfully

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

#### Command Example
```!cbd-device-unbypass device_id=3925348```

#### Human Readable Output

>Device unbypass successfully

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

#### Command Example
```!cbd-device-policy-update device_id=3925348 policy_id=67584```

#### Human Readable Output

>Policy updated successfully

### cbd-device-update-sensor-version
***
Updates the version of a sensor.


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
```!cbd-device-update-sensor-version device_id=3925348 sensor_version={\"AMAZON_LINUX\":\"1.2.3.4\"}```

#### Human Readable Output

>Version update to {"AMAZON_LINUX":"1.2.3.4"} was successful

### cbd-alerts-search
***
Gets details on the events that led to an alert. This includes retrieving metadata around the alert as well as the event associated with the alert.


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
                "device_id": 4119679,
                "device_location": "OFFSITE",
                "device_name": "QA\\win2k16-vg6-11",
                "device_os": "WINDOWS",
                "device_os_version": "Windows Server 2016 x64",
                "device_username": "Prashant.verma@logrhythm.com",
                "first_event_time": "2021-04-04T13:27:23.948Z",
                "id": "41196799a486945954911eb8af72dacb2908592",
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
                "threat_cause_actor_sha256": "2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f",
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
                        "sha256": "2e34b3d5c820ace4f2441b25b768a460eca4492d0d1f1789791f092f3bcfb27f",
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
                "device_id": 3466056,
                "device_name": "cb-komand-w12",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "sgoncharov@rapid7.com",
                "document_guid": "zkNpHeRFTxmkzklspS4FXA",
                "first_event_time": "2021-04-04T13:26:31.733Z",
                "id": "3ede94d7-757f-4d8e-b8b3-2fd8d04e5870",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:26:31.733Z",
                "last_update_time": "2021-04-04T13:28:06.812Z",
                "legacy_alert_id": "7DESJ9GN-0034e348-000003d4-00000000-1d720e5cd39e19a-6DB24675228D0A98B988DA029103C44C",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-0034e348-000003d4-00000000-1d720e5cd39e19a",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "ede27eace742ee2888c5dd36400a2ec0",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "4ae0c5191fe9d93e1be2b99c0c64bf3ca43272cd66003139476192f946f0bec4",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "4ae0c5191fe9d93e1be2b99c0c64bf3ca43272cd66003139476192f946f0bec4",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
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
                "device_id": 3885587,
                "device_name": "BITGLASS-INC\\Win10",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "mschuricht@bitglass.com",
                "document_guid": "v3IywupuSdmdXnxQbI0P5Q",
                "first_event_time": "2021-04-04T13:26:08.028Z",
                "id": "1838a77b-37bf-4b0f-801d-46f8b2a73f81",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:26:08.028Z",
                "last_update_time": "2021-04-04T13:28:05.399Z",
                "legacy_alert_id": "7DESJ9GN-003b4a13-000004c4-00000000-1d71527c98244b0-1A82D2B646B68E60E615B4E9C03E1063",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003b4a13-000004c4-00000000-1d71527c98244b0",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "f586835082f632dc8d9404d83bc16316",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "643ec58e82e0272c97c2a59f6020970d881af19c0ad5029db9c958c13b6558c7",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "643ec58e82e0272c97c2a59f6020970d881af19c0ad5029db9c958c13b6558c7",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
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
                "create_time": "2021-04-04T13:28:05.397Z",
                "device_id": 3775792,
                "device_name": "TEST\\windowsbuild",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Administrator",
                "document_guid": "0e_xYCgSQWiEXdy9QYVBpA",
                "first_event_time": "2021-04-04T13:25:56.169Z",
                "id": "bbc76b73-ea28-45dd-9761-c81f15146df2",
                "ioc_field": null,
                "ioc_hit": "((process_name:rdpclip.exe)) -enriched:true",
                "ioc_id": "565655-0",
                "last_event_time": "2021-04-04T13:25:56.169Z",
                "last_update_time": "2021-04-04T13:28:05.397Z",
                "legacy_alert_id": "7DESJ9GN-00399d30-000003c4-00000000-1d6fef6e3557510-EBF2DB4442FFF1538663717263804CFA",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-00399d30-000003c4-00000000-1d6fef6e3557510",
                "process_name": "rdpclip.exe",
                "reason": "Process rdpclip.exe was detected by the report \"Lateral Movement - Remote Desktop Protcol Login Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565655",
                "report_name": "Lateral Movement - Remote Desktop Protcol Login Detected",
                "run_state": "RAN",
                "severity": 3,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "d887e718fb0f4c99b9f01c5bd59f8b90",
                "threat_cause_actor_name": "c:\\windows\\system32\\rdpclip.exe",
                "threat_cause_actor_sha256": "acfa1128b4edd953f6364fa6216337a59c0522a01349263a11259a827838a56f",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "4DABEFC5B0122DAE9F345C8ED3BFDF0F",
                "threat_indicators": [
                    {
                        "process_name": "rdpclip.exe",
                        "sha256": "acfa1128b4edd953f6364fa6216337a59c0522a01349263a11259a827838a56f",
                        "ttps": [
                            "565655-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.251Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:22.939Z",
                "device_id": 3449992,
                "device_name": "VYKIN\\va-ad",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "erik@kognos.io",
                "document_guid": "OM-8RL3CRlG8ClwdBv6HJw",
                "first_event_time": "2021-04-04T13:25:52.403Z",
                "id": "521458bf-d813-4278-b03c-b696d412168e",
                "ioc_field": null,
                "ioc_hit": "((process_file_description:Sysinternals OR process_company_name:Sysinternals AND device_os:WINDOWS)) -enriched:true",
                "ioc_id": "c46f2504-fce8-4aac-836b-1fb5b4cd0997-0",
                "last_event_time": "2021-04-04T13:25:52.403Z",
                "last_update_time": "2021-04-04T13:28:22.939Z",
                "legacy_alert_id": "7DESJ9GN-0034a488-00000708-00000000-1d6f5a99dcd105f-134580EB549296A37B1318E8D5ACEF1C",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-0034a488-00000708-00000000-1d6f5a99dcd105f",
                "process_name": "sysmon64.exe",
                "reason": "Process sysmon64.exe was detected by the report \"Execution - SysInternals Use\" in watchlist \"Carbon Black Endpoint Suspicious Indicators\"",
                "report_id": "FFAGQQZQRmOhg0clEA5V1g-c46f2504-fce8-4aac-836b-1fb5b4cd0997",
                "report_name": "Execution - SysInternals Use",
                "run_state": "RAN",
                "severity": 3,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "041199c6747e9764856e519bcb548b62",
                "threat_cause_actor_name": "c:\\windows\\sysmon64.exe",
                "threat_cause_actor_sha256": "981792616e29b07ca33749e4f3da9769a850c61ced86f71716e0af475bbd2df1",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "976D61C0B2C6646A36A6DD165F539B54",
                "threat_indicators": [
                    {
                        "process_name": "sysmon64.exe",
                        "sha256": "981792616e29b07ca33749e4f3da9769a850c61ced86f71716e0af475bbd2df1",
                        "ttps": [
                            "c46f2504-fce8-4aac-836b-1fb5b4cd0997-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "uxgHiAbKT2aQQlzFZWQT4Q",
                        "name": "Carbon Black Endpoint Suspicious Indicators"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:31.691Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:07.518Z",
                "device_id": 4091225,
                "device_name": "QA\\win2k16GL-PV7",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Prashant.verma@logrhythm.com",
                "document_guid": "T9bgM4RsRFmdHNKH1JWMtw",
                "first_event_time": "2021-04-04T13:25:13.089Z",
                "id": "3a249900-58a7-4541-90ec-f485ffdf1636",
                "ioc_field": null,
                "ioc_hit": "(((process_name:cmd.exe AND process_cmdline:\\/c) AND -childproc_name:facefoduninstaller.exe)) -enriched:true",
                "ioc_id": "565642-0",
                "last_event_time": "2021-04-04T13:25:13.089Z",
                "last_update_time": "2021-04-04T13:28:07.518Z",
                "legacy_alert_id": "7DESJ9GN-003e6d59-00001c88-00000000-1d729554bdb025d-1FA97B67BC2AC004F76D1CE94ED57018",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003e6d59-00001c88-00000000-1d729554bdb025d",
                "process_name": "cmd.exe",
                "reason": "Process cmd.exe was detected by the report \"Execution - Command-Line Interface (cmd.exe /c)\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565642",
                "report_name": "Execution - Command-Line Interface (cmd.exe /c)",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "f4f684066175b77e0c3a000549d2922c",
                "threat_cause_actor_name": "c:\\windows\\system32\\cmd.exe",
                "threat_cause_actor_sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "512B8498B82D1EC2070201D1C50570E7",
                "threat_indicators": [
                    {
                        "process_name": "cmd.exe",
                        "sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                        "ttps": [
                            "565642-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.119Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:22.288Z",
                "device_id": 4091225,
                "device_name": "QA\\win2k16GL-PV7",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Prashant.verma@logrhythm.com",
                "document_guid": "T9bgM4RsRFmdHNKH1JWMtw",
                "first_event_time": "2021-04-04T13:25:13.089Z",
                "id": "c7819c64-0939-46e0-867d-4bd89090719b",
                "ioc_field": null,
                "ioc_hit": "(((process_cmdline:.ps* OR process_cmdline:.bat OR process_cmdline:.py OR process_cmdline:.cpl OR process_cmdline:.cmd OR process_cmdline:.com OR process_cmdline:.lnk OR process_cmdline:.reg OR process_cmdline:scr OR process_cmdline:.vb* OR process_cmdline:.ws* OR process_cmdline:.xsl) -process_name:crashpad_handler OR -process_name:Chrome.exe)) -enriched:true",
                "ioc_id": "565644-0",
                "last_event_time": "2021-04-04T13:25:13.089Z",
                "last_update_time": "2021-04-04T13:28:22.288Z",
                "legacy_alert_id": "7DESJ9GN-003e6d59-00001c88-00000000-1d729554bdb025d-DEE405A69BD6F9A3451F92B812EDAC61",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003e6d59-00001c88-00000000-1d729554bdb025d",
                "process_name": "cmd.exe",
                "reason": "Process cmd.exe was detected by the report \"Execution - Command and Scripting Interpreter Execution\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565644",
                "report_name": "Execution - Command and Scripting Interpreter Execution",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "f4f684066175b77e0c3a000549d2922c",
                "threat_cause_actor_name": "c:\\windows\\system32\\cmd.exe",
                "threat_cause_actor_sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "6F6A07019AC221AA1D55F539082F22DB",
                "threat_indicators": [
                    {
                        "process_name": "cmd.exe",
                        "sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                        "ttps": [
                            "565644-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.160Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:13.526Z",
                "device_id": 3775786,
                "device_name": "TEST\\EC2AMAZ-8KUGM3P",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "EC2AMAZ-8KUGM3P",
                "document_guid": "vlUbKQJGSFS-AIN7gGY5hQ",
                "first_event_time": "2021-04-04T13:23:49.511Z",
                "id": "21e68f82-d7c9-4911-a9a9-4c629e7b8583",
                "ioc_field": null,
                "ioc_hit": "((process_reputation:\"COMPANY_BLACK_LIST\" OR process_reputation:\"KNOWN_MALWARE\" OR process_reputation:\"SUSPECT_MALWARE\"))",
                "ioc_id": "ab2cfb72-29d3-45c0-8713-4ba3d8b0d2ae",
                "last_event_time": "2021-04-04T13:23:49.511Z",
                "last_update_time": "2021-04-04T13:28:13.526Z",
                "legacy_alert_id": "7DESJ9GN-00399d2a-00001360-00000000-1d720cb10e84113-89EE83260AD2B9B8CC55AAC9DBEB54DE",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-00399d2a-00001360-00000000-1d720cb10e84113",
                "process_name": "nc.exe",
                "reason": "Process nc.exe was detected by the report \"Malware\" in watchlist \"Splunk Watchlist\"",
                "report_id": "QWJ0AooUT1W1IChuwJOxA",
                "report_name": "Malware",
                "run_state": "RAN",
                "severity": 8,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "523613a7b9dfa398cbd5ebd2dd0f4f38",
                "threat_cause_actor_name": "c:\\programdata\\chocolatey\\lib\\netcat\\tools\\nc.exe",
                "threat_cause_actor_sha256": "3e59379f585ebf0becb6b4e06d0fbbf806de28a4bb256e837b4555f1b4245571",
                "threat_cause_reputation": "KNOWN_MALWARE",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "D63E9B3F56EC5019879F18841BFC6EB2",
                "threat_indicators": [
                    {
                        "process_name": "nc.exe",
                        "sha256": "3e59379f585ebf0becb6b4e06d0fbbf806de28a4bb256e837b4555f1b4245571",
                        "ttps": [
                            "ab2cfb72-29d3-45c0-8713-4ba3d8b0d2ae"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "BeCXz92RjiQxN1PnYlM6w",
                        "name": "Splunk Watchlist"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.118Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:39.484Z",
                "device_id": 3775786,
                "device_name": "TEST\\EC2AMAZ-8KUGM3P",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "EC2AMAZ-8KUGM3P",
                "document_guid": "vlUbKQJGSFS-AIN7gGY5hQ",
                "first_event_time": "2021-04-04T13:23:49.511Z",
                "id": "dfe02570-fb86-4af0-9018-2b94b03a4a41",
                "ioc_field": null,
                "ioc_hit": "((process_name:net*.exe netconn_count:[1 TO *])) -enriched:true",
                "ioc_id": "565614-0",
                "last_event_time": "2021-04-04T13:23:49.511Z",
                "last_update_time": "2021-04-04T13:28:39.484Z",
                "legacy_alert_id": "7DESJ9GN-00399d2a-00001360-00000000-1d720cb10e84113-8C64D3C579F2AB6FDEB6BEB985CB1AD6",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-00399d2a-00001360-00000000-1d720cb10e84113",
                "process_name": "nc.exe",
                "reason": "Process nc.exe was detected by the report \"Lateral Movement - Windows Admin Shares - Net Making Network Connections\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565614",
                "report_name": "Lateral Movement - Windows Admin Shares - Net Making Network Connections",
                "run_state": "RAN",
                "severity": 2,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "523613a7b9dfa398cbd5ebd2dd0f4f38",
                "threat_cause_actor_name": "c:\\programdata\\chocolatey\\lib\\netcat\\tools\\nc.exe",
                "threat_cause_actor_sha256": "3e59379f585ebf0becb6b4e06d0fbbf806de28a4bb256e837b4555f1b4245571",
                "threat_cause_reputation": "KNOWN_MALWARE",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "423AF04E8A3AB152F17FDFFF462FDF2A",
                "threat_indicators": [
                    {
                        "process_name": "nc.exe",
                        "sha256": "3e59379f585ebf0becb6b4e06d0fbbf806de28a4bb256e837b4555f1b4245571",
                        "ttps": [
                            "565614-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:31.822Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:27:54.283Z",
                "device_id": 3775786,
                "device_name": "TEST\\EC2AMAZ-8KUGM3P",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "EC2AMAZ-8KUGM3P",
                "document_guid": "v1ZZOeB-SZu1frnw1CvY9w",
                "first_event_time": "2021-04-04T13:23:49.338Z",
                "id": "09163b0a-03f9-4b5b-a934-b71d0dd10bbf",
                "ioc_field": null,
                "ioc_hit": "((process_name:rdpclip.exe)) -enriched:true",
                "ioc_id": "565655-0",
                "last_event_time": "2021-04-04T13:23:49.338Z",
                "last_update_time": "2021-04-04T13:27:54.283Z",
                "legacy_alert_id": "7DESJ9GN-00399d2a-000003c0-00000000-1d720bf796e294e-765A2443DD487DE3451ABEA47411AD63",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-00399d2a-000003c0-00000000-1d720bf796e294e",
                "process_name": "rdpclip.exe",
                "reason": "Process rdpclip.exe was detected by the report \"Lateral Movement - Remote Desktop Protcol Login Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565655",
                "report_name": "Lateral Movement - Remote Desktop Protcol Login Detected",
                "run_state": "RAN",
                "severity": 3,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "9e089ecf8b86983b7a77e3844cd02bb5",
                "threat_cause_actor_name": "c:\\windows\\system32\\rdpclip.exe",
                "threat_cause_actor_sha256": "af5cae4b514215e530643a7fea2d7a47a1b15f6e5610347b217d1abfa4ae0f92",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "4DABEFC5B0122DAE9F345C8ED3BFDF0F",
                "threat_indicators": [
                    {
                        "process_name": "rdpclip.exe",
                        "sha256": "af5cae4b514215e530643a7fea2d7a47a1b15f6e5610347b217d1abfa4ae0f92",
                        "ttps": [
                            "565655-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.251Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:00.971Z",
                "device_id": 3078750,
                "device_name": "Windows-10-32bit",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "manwin1032",
                "document_guid": "F_8xtaYeQGu2TdagwYfWLA",
                "first_event_time": "2021-04-04T13:23:36.534Z",
                "id": "44536313-7c36-4e68-bd02-515ebb80cf15",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:23:36.534Z",
                "last_update_time": "2021-04-04T13:28:00.971Z",
                "legacy_alert_id": "7DESJ9GN-002efa5e-000006a8-00000000-1d71bce7126e520-D1F2D300D53BF3BD22F041D06E80BA4E",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-002efa5e-000006a8-00000000-1d71bce7126e520",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "b7c999040d80e5bf87886d70d992c51e",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "5c3257b277f160109071e7e716040e67657341d8c42aa68d9afafe1630fcc53e",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "5c3257b277f160109071e7e716040e67657341d8c42aa68d9afafe1630fcc53e",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
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
                "create_time": "2021-04-04T13:28:44.761Z",
                "device_id": 4091225,
                "device_name": "QA\\win2k16GL-PV7",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Prashant.verma@logrhythm.com",
                "document_guid": "Cvh2lrqJRUCdFIHtxT0mCw",
                "first_event_time": "2021-04-04T13:23:30.336Z",
                "id": "3f6762d1-4e5f-461f-a24a-9c23fc430f4f",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:23:30.336Z",
                "last_update_time": "2021-04-04T13:28:44.761Z",
                "legacy_alert_id": "7DESJ9GN-003e6d59-00000498-00000000-1d70b726e2c3359-AC1B080B92EABA7CA18C51D626980D06",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003e6d59-00000498-00000000-1d70b726e2c3359",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
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
                        "sha256": "438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
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
                "create_time": "2021-04-04T13:28:10.279Z",
                "device_id": 4122269,
                "device_name": "QA\\thakurabt301",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "abhinav.thakur@logrhythm.com",
                "document_guid": "AFzdXUtZSZS4G5eptLkmXw",
                "first_event_time": "2021-04-04T13:23:27.098Z",
                "id": "c78fd6a5-50da-438f-b6a8-eab686e6dfcf",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:23:27.098Z",
                "last_update_time": "2021-04-04T13:28:10.279Z",
                "legacy_alert_id": "7DESJ9GN-003ee69d-000003e8-00000000-1d71bc35360a67d-400688AF06DE1EAEEFF7237E588F5681",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003ee69d-000003e8-00000000-1d71bc35360a67d",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "e3a2ad05e24105b35e986cf9cb38ec47",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "c7db4ae8175c33a47baa3ddfa089fad17bc8e362f21e835d78ab22c9231fe370",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "c7db4ae8175c33a47baa3ddfa089fad17bc8e362f21e835d78ab22c9231fe370",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
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
                "create_time": "2021-04-04T13:28:22.335Z",
                "device_id": 3411499,
                "device_name": "QA\\VM-2k12-DG01",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "sakshi.rawal@logrhythm.com",
                "document_guid": "cuHfCcvaQf-9fLM89Ek9UA",
                "first_event_time": "2021-04-04T13:23:27.047Z",
                "id": "64e9cfca-ada8-4710-8e79-0ac7f3e1b1b7",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:23:27.047Z",
                "last_update_time": "2021-04-04T13:28:22.335Z",
                "legacy_alert_id": "7DESJ9GN-00340e2b-0000018c-00000000-1d70b72a645cc1a-1228088B036DA4DE84D18B39B3E069B3",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-00340e2b-0000018c-00000000-1d70b72a645cc1a",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "e3a2ad05e24105b35e986cf9cb38ec47",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "c7db4ae8175c33a47baa3ddfa089fad17bc8e362f21e835d78ab22c9231fe370",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "c7db4ae8175c33a47baa3ddfa089fad17bc8e362f21e835d78ab22c9231fe370",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
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
                "create_time": "2021-04-04T13:28:06.812Z",
                "device_id": 4117626,
                "device_name": "VM-2K12-VG73",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Kushal.gulati@logrhythm.com",
                "document_guid": "dcYdPDz1S3CTY6biySYzhg",
                "first_event_time": "2021-04-04T13:23:19.093Z",
                "id": "d52123f0-012c-4bd2-8f6f-5ed9c1178ebc",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:23:19.093Z",
                "last_update_time": "2021-04-04T13:28:06.812Z",
                "legacy_alert_id": "7DESJ9GN-003ed47a-000003fc-00000000-1d71a598b615a1c-6E5C68C91605C50D2BD21CE1958E23EE",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003ed47a-000003fc-00000000-1d71a598b615a1c",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "e3a2ad05e24105b35e986cf9cb38ec47",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "c7db4ae8175c33a47baa3ddfa089fad17bc8e362f21e835d78ab22c9231fe370",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "c7db4ae8175c33a47baa3ddfa089fad17bc8e362f21e835d78ab22c9231fe370",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
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
                "create_time": "2021-04-04T13:28:06.951Z",
                "device_id": 4117372,
                "device_name": "VM-2K12-VG73",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Kushal.gulati@logrhythm.com",
                "document_guid": "MnfN51JASNeE_ubltJP8Qg",
                "first_event_time": "2021-04-04T13:23:13.109Z",
                "id": "e81ea178-a3ba-4529-8b09-bedab5a794d7",
                "ioc_field": null,
                "ioc_hit": "((netconn_port:5355 device_os:WINDOWS)) -enriched:true",
                "ioc_id": "565633-0",
                "last_event_time": "2021-04-04T13:23:13.109Z",
                "last_update_time": "2021-04-04T13:28:06.951Z",
                "legacy_alert_id": "7DESJ9GN-003ed37c-00000060-00000000-1d71972a5a67a38-F37D6CF943EB3D324E93238693855CA9",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003ed37c-00000060-00000000-1d71972a5a67a38",
                "process_name": "svchost.exe",
                "reason": "Process svchost.exe was detected by the report \"Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565633",
                "report_name": "Credential Access - LLMNR/NBT-NS Poisoning - LLMNR Traffic Detected",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "e3a2ad05e24105b35e986cf9cb38ec47",
                "threat_cause_actor_name": "c:\\windows\\system32\\svchost.exe",
                "threat_cause_actor_sha256": "c7db4ae8175c33a47baa3ddfa089fad17bc8e362f21e835d78ab22c9231fe370",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "8E4CE676E9C9EEF4F94065D009B66094",
                "threat_indicators": [
                    {
                        "process_name": "svchost.exe",
                        "sha256": "c7db4ae8175c33a47baa3ddfa089fad17bc8e362f21e835d78ab22c9231fe370",
                        "ttps": [
                            "565633-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
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
                "create_time": "2021-04-04T13:28:10.357Z",
                "device_id": 4119679,
                "device_name": "QA\\win2k16-vg6-11",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Prashant.verma@logrhythm.com",
                "document_guid": "OdB8o8UpRgOIlOQ3JXVESg",
                "first_event_time": "2021-04-04T13:21:51.459Z",
                "id": "29ed0b9c-cf23-46c2-992a-7644f1dedb15",
                "ioc_field": null,
                "ioc_hit": "(((process_cmdline:.ps* OR process_cmdline:.bat OR process_cmdline:.py OR process_cmdline:.cpl OR process_cmdline:.cmd OR process_cmdline:.com OR process_cmdline:.lnk OR process_cmdline:.reg OR process_cmdline:scr OR process_cmdline:.vb* OR process_cmdline:.ws* OR process_cmdline:.xsl) -process_name:crashpad_handler OR -process_name:Chrome.exe)) -enriched:true",
                "ioc_id": "565644-0",
                "last_event_time": "2021-04-04T13:21:51.459Z",
                "last_update_time": "2021-04-04T13:28:10.357Z",
                "legacy_alert_id": "7DESJ9GN-003edc7f-000046cc-00000000-1d7295578b7422f-12077672CECD4E918339657EE8DB6BE2",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003edc7f-000046cc-00000000-1d7295578b7422f",
                "process_name": "cmd.exe",
                "reason": "Process cmd.exe was detected by the report \"Execution - Command and Scripting Interpreter Execution\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565644",
                "report_name": "Execution - Command and Scripting Interpreter Execution",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "f4f684066175b77e0c3a000549d2922c",
                "threat_cause_actor_name": "c:\\windows\\system32\\cmd.exe",
                "threat_cause_actor_sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "6F6A07019AC221AA1D55F539082F22DB",
                "threat_indicators": [
                    {
                        "process_name": "cmd.exe",
                        "sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                        "ttps": [
                            "565644-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.162Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:04.207Z",
                "device_id": 4119679,
                "device_name": "QA\\win2k16-vg6-11",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Prashant.verma@logrhythm.com",
                "document_guid": "OdB8o8UpRgOIlOQ3JXVESg",
                "first_event_time": "2021-04-04T13:21:51.459Z",
                "id": "44d4be55-f381-4414-9a7c-2db6196368b9",
                "ioc_field": null,
                "ioc_hit": "(((process_name:cmd.exe AND process_cmdline:\\/c) AND -childproc_name:facefoduninstaller.exe)) -enriched:true",
                "ioc_id": "565642-0",
                "last_event_time": "2021-04-04T13:21:51.459Z",
                "last_update_time": "2021-04-04T13:28:04.207Z",
                "legacy_alert_id": "7DESJ9GN-003edc7f-000046cc-00000000-1d7295578b7422f-0D41538007BBEE27265829286DD2FAA6",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003edc7f-000046cc-00000000-1d7295578b7422f",
                "process_name": "cmd.exe",
                "reason": "Process cmd.exe was detected by the report \"Execution - Command-Line Interface (cmd.exe /c)\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565642",
                "report_name": "Execution - Command-Line Interface (cmd.exe /c)",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "f4f684066175b77e0c3a000549d2922c",
                "threat_cause_actor_name": "c:\\windows\\system32\\cmd.exe",
                "threat_cause_actor_sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "512B8498B82D1EC2070201D1C50570E7",
                "threat_indicators": [
                    {
                        "process_name": "cmd.exe",
                        "sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                        "ttps": [
                            "565642-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.121Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:14.120Z",
                "device_id": 4119679,
                "device_name": "QA\\win2k16-vg6-11",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Prashant.verma@logrhythm.com",
                "document_guid": "MM91ahPTRRG62Mgah6orrQ",
                "first_event_time": "2021-04-04T13:21:45.398Z",
                "id": "ad94bdc4-1359-4aab-ab5c-3bcfd48ae21f",
                "ioc_field": null,
                "ioc_hit": "(((process_cmdline:.ps* OR process_cmdline:.bat OR process_cmdline:.py OR process_cmdline:.cpl OR process_cmdline:.cmd OR process_cmdline:.com OR process_cmdline:.lnk OR process_cmdline:.reg OR process_cmdline:scr OR process_cmdline:.vb* OR process_cmdline:.ws* OR process_cmdline:.xsl) -process_name:crashpad_handler OR -process_name:Chrome.exe)) -enriched:true",
                "ioc_id": "565644-0",
                "last_event_time": "2021-04-04T13:21:45.398Z",
                "last_update_time": "2021-04-04T13:28:14.120Z",
                "legacy_alert_id": "7DESJ9GN-003edc7f-00002b74-00000000-1d7295575145bfd-7EBCB7350EB36D1C9F8A076580353177",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003edc7f-00002b74-00000000-1d7295575145bfd",
                "process_name": "cmd.exe",
                "reason": "Process cmd.exe was detected by the report \"Execution - Command and Scripting Interpreter Execution\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565644",
                "report_name": "Execution - Command and Scripting Interpreter Execution",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "f4f684066175b77e0c3a000549d2922c",
                "threat_cause_actor_name": "c:\\windows\\system32\\cmd.exe",
                "threat_cause_actor_sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "6F6A07019AC221AA1D55F539082F22DB",
                "threat_indicators": [
                    {
                        "process_name": "cmd.exe",
                        "sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                        "ttps": [
                            "565644-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.161Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            },
            {
                "category": "THREAT",
                "count": 0,
                "create_time": "2021-04-04T13:28:14.189Z",
                "device_id": 4119679,
                "device_name": "QA\\win2k16-vg6-11",
                "device_os": "WINDOWS",
                "device_os_version": null,
                "device_username": "Prashant.verma@logrhythm.com",
                "document_guid": "MM91ahPTRRG62Mgah6orrQ",
                "first_event_time": "2021-04-04T13:21:45.398Z",
                "id": "dbbb88a2-0e6b-4bcf-b2f6-4b2485b75574",
                "ioc_field": null,
                "ioc_hit": "(((process_name:cmd.exe AND process_cmdline:\\/c) AND -childproc_name:facefoduninstaller.exe)) -enriched:true",
                "ioc_id": "565642-0",
                "last_event_time": "2021-04-04T13:21:45.398Z",
                "last_update_time": "2021-04-04T13:28:14.189Z",
                "legacy_alert_id": "7DESJ9GN-003edc7f-00002b74-00000000-1d7295575145bfd-523B0CD4AA5DCFCE5228E0898C22EC41",
                "notes_present": false,
                "org_key": "7DESJ9GN",
                "policy_id": 6525,
                "policy_name": "default",
                "process_guid": "7DESJ9GN-003edc7f-00002b74-00000000-1d7295575145bfd",
                "process_name": "cmd.exe",
                "reason": "Process cmd.exe was detected by the report \"Execution - Command-Line Interface (cmd.exe /c)\" in watchlist \"ATT&CK Framework\"",
                "report_id": "CFnKBKLTv6hUkBGFobRdg-565642",
                "report_name": "Execution - Command-Line Interface (cmd.exe /c)",
                "run_state": "RAN",
                "severity": 1,
                "tags": null,
                "target_value": "LOW",
                "threat_cause_actor_md5": "f4f684066175b77e0c3a000549d2922c",
                "threat_cause_actor_name": "c:\\windows\\system32\\cmd.exe",
                "threat_cause_actor_sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                "threat_cause_reputation": "TRUSTED_WHITE_LIST",
                "threat_cause_threat_category": "UNKNOWN",
                "threat_cause_vector": "UNKNOWN",
                "threat_id": "512B8498B82D1EC2070201D1C50570E7",
                "threat_indicators": [
                    {
                        "process_name": "cmd.exe",
                        "sha256": "935c1861df1f4018d698e8b65abfa02d7e9037d8f68ca3c2065b6ca165d44ad2",
                        "ttps": [
                            "565642-0"
                        ]
                    }
                ],
                "type": "WATCHLIST",
                "watchlists": [
                    {
                        "id": "RJoXUWAyS16pBBCsR0j00A",
                        "name": "ATT&CK Framework"
                    }
                ],
                "workflow": {
                    "changed_by": "Carbon Black",
                    "comment": null,
                    "last_update_time": "2021-04-04T13:27:32.120Z",
                    "remediation": null,
                    "state": "OPEN"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Alerts List Results
>|Id|Category|Device Id|Device Name|Device Username|Create Time|Ioc Hit|Policy Name|Process Name|Type|Severity|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 41196799a486945954911eb8af72dacb2908592 | THREAT | 4119679 | QA\win2k16-vg6-11 | Prashant.verma@logrhythm.com | 2021-04-04T13:28:21.393Z |  | default | setup.exe | CB_ANALYTICS | 2 |
>| 3ede94d7-757f-4d8e-b8b3-2fd8d04e5870 | THREAT | 3466056 | cb-komand-w12 | sgoncharov@rapid7.com | 2021-04-04T13:28:06.812Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| 1838a77b-37bf-4b0f-801d-46f8b2a73f81 | THREAT | 3885587 | BITGLASS-INC\Win10 | mschuricht@bitglass.com | 2021-04-04T13:28:05.399Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| bbc76b73-ea28-45dd-9761-c81f15146df2 | THREAT | 3775792 | TEST\windowsbuild | Administrator | 2021-04-04T13:28:05.397Z | ((process_name:rdpclip.exe)) -enriched:true | default | rdpclip.exe | WATCHLIST | 3 |
>| 521458bf-d813-4278-b03c-b696d412168e | THREAT | 3449992 | VYKIN\va-ad | erik@kognos.io | 2021-04-04T13:28:22.939Z | ((process_file_description:Sysinternals OR process_company_name:Sysinternals AND device_os:WINDOWS)) -enriched:true | default | sysmon64.exe | WATCHLIST | 3 |
>| 3a249900-58a7-4541-90ec-f485ffdf1636 | THREAT | 4091225 | QA\win2k16GL-PV7 | Prashant.verma@logrhythm.com | 2021-04-04T13:28:07.518Z | (((process_name:cmd.exe AND process_cmdline:\/c) AND -childproc_name:facefoduninstaller.exe)) -enriched:true | default | cmd.exe | WATCHLIST | 1 |
>| c7819c64-0939-46e0-867d-4bd89090719b | THREAT | 4091225 | QA\win2k16GL-PV7 | Prashant.verma@logrhythm.com | 2021-04-04T13:28:22.288Z | (((process_cmdline:.ps* OR process_cmdline:.bat OR process_cmdline:.py OR process_cmdline:.cpl OR process_cmdline:.cmd OR process_cmdline:.com OR process_cmdline:.lnk OR process_cmdline:.reg OR process_cmdline:scr OR process_cmdline:.vb* OR process_cmdline:.ws* OR process_cmdline:.xsl) -process_name:crashpad_handler OR -process_name:Chrome.exe)) -enriched:true | default | cmd.exe | WATCHLIST | 1 |
>| 21e68f82-d7c9-4911-a9a9-4c629e7b8583 | THREAT | 3775786 | TEST\EC2AMAZ-8KUGM3P | EC2AMAZ-8KUGM3P | 2021-04-04T13:28:13.526Z | ((process_reputation:"COMPANY_BLACK_LIST" OR process_reputation:"KNOWN_MALWARE" OR process_reputation:"SUSPECT_MALWARE")) | default | nc.exe | WATCHLIST | 8 |
>| dfe02570-fb86-4af0-9018-2b94b03a4a41 | THREAT | 3775786 | TEST\EC2AMAZ-8KUGM3P | EC2AMAZ-8KUGM3P | 2021-04-04T13:28:39.484Z | ((process_name:net*.exe netconn_count:[1 TO *])) -enriched:true | default | nc.exe | WATCHLIST | 2 |
>| 09163b0a-03f9-4b5b-a934-b71d0dd10bbf | THREAT | 3775786 | TEST\EC2AMAZ-8KUGM3P | EC2AMAZ-8KUGM3P | 2021-04-04T13:27:54.283Z | ((process_name:rdpclip.exe)) -enriched:true | default | rdpclip.exe | WATCHLIST | 3 |
>| 44536313-7c36-4e68-bd02-515ebb80cf15 | THREAT | 3078750 | Windows-10-32bit | manwin1032 | 2021-04-04T13:28:00.971Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| 3f6762d1-4e5f-461f-a24a-9c23fc430f4f | THREAT | 4091225 | QA\win2k16GL-PV7 | Prashant.verma@logrhythm.com | 2021-04-04T13:28:44.761Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| c78fd6a5-50da-438f-b6a8-eab686e6dfcf | THREAT | 4122269 | QA\thakurabt301 | abhinav.thakur@logrhythm.com | 2021-04-04T13:28:10.279Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| 64e9cfca-ada8-4710-8e79-0ac7f3e1b1b7 | THREAT | 3411499 | QA\VM-2k12-DG01 | sakshi.rawal@logrhythm.com | 2021-04-04T13:28:22.335Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| d52123f0-012c-4bd2-8f6f-5ed9c1178ebc | THREAT | 4117626 | VM-2K12-VG73 | Kushal.gulati@logrhythm.com | 2021-04-04T13:28:06.812Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| e81ea178-a3ba-4529-8b09-bedab5a794d7 | THREAT | 4117372 | VM-2K12-VG73 | Kushal.gulati@logrhythm.com | 2021-04-04T13:28:06.951Z | ((netconn_port:5355 device_os:WINDOWS)) -enriched:true | default | svchost.exe | WATCHLIST | 1 |
>| 29ed0b9c-cf23-46c2-992a-7644f1dedb15 | THREAT | 4119679 | QA\win2k16-vg6-11 | Prashant.verma@logrhythm.com | 2021-04-04T13:28:10.357Z | (((process_cmdline:.ps* OR process_cmdline:.bat OR process_cmdline:.py OR process_cmdline:.cpl OR process_cmdline:.cmd OR process_cmdline:.com OR process_cmdline:.lnk OR process_cmdline:.reg OR process_cmdline:scr OR process_cmdline:.vb* OR process_cmdline:.ws* OR process_cmdline:.xsl) -process_name:crashpad_handler OR -process_name:Chrome.exe)) -enriched:true | default | cmd.exe | WATCHLIST | 1 |
>| 44d4be55-f381-4414-9a7c-2db6196368b9 | THREAT | 4119679 | QA\win2k16-vg6-11 | Prashant.verma@logrhythm.com | 2021-04-04T13:28:04.207Z | (((process_name:cmd.exe AND process_cmdline:\/c) AND -childproc_name:facefoduninstaller.exe)) -enriched:true | default | cmd.exe | WATCHLIST | 1 |
>| ad94bdc4-1359-4aab-ab5c-3bcfd48ae21f | THREAT | 4119679 | QA\win2k16-vg6-11 | Prashant.verma@logrhythm.com | 2021-04-04T13:28:14.120Z | (((process_cmdline:.ps* OR process_cmdline:.bat OR process_cmdline:.py OR process_cmdline:.cpl OR process_cmdline:.cmd OR process_cmdline:.com OR process_cmdline:.lnk OR process_cmdline:.reg OR process_cmdline:scr OR process_cmdline:.vb* OR process_cmdline:.ws* OR process_cmdline:.xsl) -process_name:crashpad_handler OR -process_name:Chrome.exe)) -enriched:true | default | cmd.exe | WATCHLIST | 1 |
>| dbbb88a2-0e6b-4bcf-b2f6-4b2485b75574 | THREAT | 4119679 | QA\win2k16-vg6-11 | Prashant.verma@logrhythm.com | 2021-04-04T13:28:14.189Z | (((process_name:cmd.exe AND process_cmdline:\/c) AND -childproc_name:facefoduninstaller.exe)) -enriched:true | default | cmd.exe | WATCHLIST | 1 |

