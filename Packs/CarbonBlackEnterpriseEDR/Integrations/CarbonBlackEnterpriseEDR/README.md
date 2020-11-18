## Overview
---

VMware Carbon Black Enterprise EDR is an advanced threat hunting and incident response solution delivering continuous visibility for top security operations centers (SOCs) and incident response (IR) teams. (formerly known as ThreatHunter)

## Configure VMware Carbon Black Enterprise EDR on Demisto
---

1. Navigate to __Settings__ \> __Integrations__ \> __Servers & Services__.
2. Search for VMware Carbon Black Enterprise EDR.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://defense.conferdeploy.net)__
    * __Organization Key__
    * __Custom Key__
    * __Custom ID__
    * __Fetch incidents__
    * __Incident type__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __First fetch timestamp (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year)__
    * __Fetch limit__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. cb-eedr-alert-workflow-update
2. cb-eedr-device-quarantine
3. cb-eedr-device-unquarantine
4. cb-eedr-device-background-scan-stop
5. cb-eedr-device-background-scan
6. cb-eedr-device-bypass
7. cb-eedr-device-unbypass
8. cb-eedr-device-policy-update
9. cb-eedr-devices-list
10. cb-eedr-list-alerts
11. cb-eedr-watchlist-list
12. cb-eedr-get-watchlist-by-id
13. cb-eedr-watchlist-alerts-status
14. cb-eedr-watchlist-alerts-enable
15. cb-eedr-watchlist-alerts-disable
16. cb-eedr-watchlist-create
17. cb-eedr-watchlist-delete
18. cb-eedr-watchlist-update
19. cb-eedr-report-get
20. cb-eedr-ioc-ignore-status
21. cb-eedr-ioc-ignore
22. cb-eedr-ioc-reactivate
23. cb-eedr-report-ignore
24. cb-eedr-report-reactivate
25. cb-eedr-report-ignore-status
26. cb-eedr-report-remove
27. cb-eedr-report-create
28. cb-eedr-report-update
29. cb-eedr-file-device-summary
30. cb-eedr-get-file-metadata
31. cb-eedr-files-download-link-get
32. cb-eedr-file-paths
33. cb-eedr-process-search
34. cb-eedr-events-by-process-get
35. cb-eedr-process-search-results
### 1. cb-eedr-alert-workflow-update
---
Updates the workflow of a single event.
##### Required Permissions
RBAC Permissions Required - org.alerts.dismiss: EXECUTE
##### Base Command

`cb-eedr-alert-workflow-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to update. Get the ID from list_alerts command. | Required | 
| state | Workflow state to update. | Optional | 
| comment | Comment to include with the operation. | Optional | 
| remediation_state | Description of the changes done in the workflow state. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Alert.AlertID | String | The alert ID. | 
| CarbonBlackEEDR.Alert.ChangedBy | String | User that changed the ID. | 
| CarbonBlackEEDR.Alert.Comment | String | Comment that was included with the operation. | 
| CarbonBlackEEDR.Alert.LastUpdateTime | Date | Last time the alert was updated. | 
| CarbonBlackEEDR.Alert.Remediation | String | Description or justification for the change. | 
| CarbonBlackEEDR.Alert.State | String | The alert state. | 


##### Command Example
```!cb-eedr-alert-workflow-update alert_id=A28C720DCBCD66333A624893AB1E0FE9 state=open```

##### Context Example
```
{
    "CarbonBlackEEDR.Alert": {
        "Comment": null, 
        "ChangedBy": "ATL5Y9DR4B", 
        "AlertID": "A28C720DCBCD66333A624893AB1E0FE9", 
        "LastUpdateTime": "2020-05-26T13:33:12.890Z", 
        "State": "OPEN", 
        "Remediation": null
    }
}
```

##### Human Readable Output
### Successfully updated the alert: "A28C720DCBCD66333A624893AB1E0FE9"
|changed_by|last_update_time|state|
|---|---|---|
| ATL5Y9DR4B | 2020-05-26T13:33:12.890Z | OPEN |


### 2. cb-eedr-device-quarantine
---
Quarantines a device.
##### Required Permissions
RBAC Permissions Required - device.quarantine: EXECUTE
##### Base Command

`cb-eedr-device-quarantine`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The devices on which to perform the action. Get the ID from the devices-list command. Supports comma-separated values. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-device-quarantine device_id="1225783"```

##### Human Readable Output
The device ['1225783'] has been quarantined successfully.

### 3. cb-eedr-device-unquarantine
---
Removes a device from quarantine.
##### Required Permissions
RBAC Permissions Required - device.quarantine: EXECUTE
##### Base Command

`cb-eedr-device-unquarantine`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The devices on which to perform the action. Get the ID from the devices-list command. Supports comma-separated values. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-device-unquarantine device_id="1225783"```

##### Human Readable Output
The device ['1225783'] has been unquarantined successfully.

### 4. cb-eedr-device-background-scan-stop
---
Stops a background scan on the specified devices.
##### Required Permissions
RBAC Permissions Required - device.bg-scan: EXECUTE
##### Base Command

`cb-eedr-device-background-scan-stop`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Supports comma-separated values. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-device-background-scan-stop device_id="1225783"```

##### Human Readable Output
The device ['1225783'] background scan has been disabled successfully.

### 5. cb-eedr-device-background-scan
---
Start a background scan on device.
##### Required Permissions
RBAC Permissions Required - device.bg-scan: EXECUTE
##### Base Command

`cb-eedr-device-background-scan`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Supports comma-separated values. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-device-background-scan device_id="1225783"```

##### Human Readable Output
The device ['1225783'] background scan has been enabled successfully.

### 6. cb-eedr-device-bypass
---
Enable a bypass on device.
##### Required Permissions
RBAC Permissions Required - device.bypass: EXECUTE
##### Base Command

`cb-eedr-device-bypass`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Support comma-separated values. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-device-bypass device_id="1225783"```

##### Human Readable Output
The device ['1225783'] bypass has been enabled successfully.

### 7. cb-eedr-device-unbypass
---
Disable a bypass on device.
##### Required Permissions
RBAC Permissions Required - device.bypass: EXECUTE
##### Base Command

`cb-eedr-device-unbypass`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Support comma-separated values. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-device-unbypass device_id="1225783"```

##### Human Readable Output
The device ['1225783'] bypass has been disabled successfully.

### 8. cb-eedr-device-policy-update
---
Update device policy.
##### Required Permissions
RBAC Permissions Required - device.policy: EXECUTE
##### Base Command

`cb-eedr-device-policy-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Support comma-separated values. | Required | 
| policy_id | The policy ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-device-policy-update device_id=1225783 policy_id=12064```

##### Human Readable Output
The policy 12064 has been assigned to device ['1225783'] successfully.

### 9. cb-eedr-devices-list
---
List devices based on the search query.
##### Required Permissions
RBAC Permissions Required - device: READ
##### Base Command

`cb-eedr-devices-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Supports comma-separated values. | Optional | 
| status | The device status. Supports comma-separated values. | Optional | 
| device_os | Device operation system. Supports comma-separated values. | Optional | 
| start_time | Device start last contact time. For example: 2019-01-01T11:00:00.157Z | Optional | 
| end_time | Device end last contact time. For example: 2019-01-01T11:00:00.157Z | Optional | 
| ad_group_id | Active directory group ID. Supports comma-separated values | Optional | 
| policy_id | The policy ID. Supports comma-separated values. | Optional | 
| target_priority | Device target priority. Supports comma-separated values | Optional | 
| limit | Maximum number of rows to return | Optional | 
| sort_field | Sort Fields | Optional | 
| sort_order | Sort Order for field. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Device.sensor_out_of_date | Boolean | Is the device sensor out of date. | 
| CarbonBlackEEDR.Device.vdi_base_device | String | vdi base device. | 
| CarbonBlackEEDR.Device.linux_kernel_version | String | Linux kernel version. | 
| CarbonBlackEEDR.Device.mac_address | String | Device MAC address. | 
| CarbonBlackEEDR.Device.os | String | Device operating system. | 
| CarbonBlackEEDR.Device.last_device_policy_changed_time | Date | Last device policy changed time. | 
| CarbonBlackEEDR.Device.last_reset_time | Date | Last reset time. | 
| CarbonBlackEEDR.Device.sensor_states | String | Device sensor state. | 
| CarbonBlackEEDR.Device.last_external_ip_address | String | Last external IP address. | 
| CarbonBlackEEDR.Device.organization_id | Number | Organization ID. | 
| CarbonBlackEEDR.Device.sensor_kit_type | String | Sensor kit type. | 
| CarbonBlackEEDR.Device.policy_id | Number | Device policy ID. | 
| CarbonBlackEEDR.Device.login_user_name | String | Login user name. | 
| CarbonBlackEEDR.Device.deregistered_time | Date | Deregistered time. | 
| CarbonBlackEEDR.Device.registered_time | Date | Registered time. | 
| CarbonBlackEEDR.Device.name | String | Device name. | 
| CarbonBlackEEDR.Device.last_device_policy_requested_time | Date | Last device policy requested time. | 
| CarbonBlackEEDR.Device.scan_last_complete_time | Date | Scan last complete time. | 
| CarbonBlackEEDR.Device.last_shutdown_time | Date | Last shutdown time. | 
| CarbonBlackEEDR.Device.scan_last_action_time | String | Device scan last action time. | 
| CarbonBlackEEDR.Device.windows_platform | String | Windows platform. | 
| CarbonBlackEEDR.Device.last_reported_time | Date | Device last reported time. | 
| CarbonBlackEEDR.Device.device_owner_id | Number | Device owner ID. | 
| CarbonBlackEEDR.Device.target_priority | String | Target priority. | 
| CarbonBlackEEDR.Device.status | String | Device status. | 
| CarbonBlackEEDR.Device.sensor_version | String | Sensor version. | 
| CarbonBlackEEDR.Device.virtual_machine | Boolean | Is the device virtual machine | 
| CarbonBlackEEDR.Device.last_name | String | Last name. | 
| CarbonBlackEEDR.Device.scan_status | String | Scan status. | 
| CarbonBlackEEDR.Device.last_internal_ip_address | String | Last internal IP address. | 
| CarbonBlackEEDR.Device.last_policy_updated_time | Date | Last policy updated time. | 
| CarbonBlackEEDR.Device.last_contact_time | Date | Device last contact time. | 
| CarbonBlackEEDR.Device.quarantined | Boolean | Is the device quarantined. | 
| CarbonBlackEEDR.Device.virtualization_provider | String | Virtualization Provider. | 
| CarbonBlackEEDR.Device.organization_name | String | Organization Name. | 
| CarbonBlackEEDR.Device.ad_group_id | String | Active directory group ID. | 
| CarbonBlackEEDR.Device.policy_name | String | Policy name. | 
| CarbonBlackEEDR.Device.policy_override | Boolean | Policy override. | 
| CarbonBlackEEDR.Device.first_name | String | First name. | 
| CarbonBlackEEDR.Device.current_sensor_policy_name | String | Current sensor policy name. | 
| CarbonBlackEEDR.Device.id | String | Device ID. | 
| CarbonBlackEEDR.Device.av_status | String | av status. | 
| CarbonBlackEEDR.Device.av_pack_version | String | av pack version. | 
| CarbonBlackEEDR.Device.email | String | User email. | 
| CarbonBlackEEDR.Device.os_version | String | Device OS version. | 
| CarbonBlackEEDR.Device.av_product_version | String | AV product version. | 
| CarbonBlackEEDR.Device.last_location | String | Device last location. | 
| Endpoint.ID | String | The unique ID within the tool retrieving the endpoint. | 
| Endpoint.OS | String | Endpoint OS. | 
| Endpoint.OSVersion | String | OS version. | 
| Endpoint.MACAddress | String | The MAC address of the endpoint. | 


##### Command Example
```!cb-eedr-devices-list```

##### Context Example
```
{
    "CarbonBlackEEDR.Device": [
        {
            "last_reported_time": "2020-05-26T10:39:01.346Z", 
            "last_name": null, 
            "last_device_policy_changed_time": "2020-05-20T11:59:21.298Z", 
            "sensor_version": "3.4.0.820", 
            "scan_status": null, 
            "policy_name": "test", 
            "sensor_pending_update": false, 
            "device_owner_id": 354312, 
            "current_sensor_policy_name": "test", 
            "last_device_policy_requested_time": "2020-05-20T12:03:35.744Z", 
            "id": 2244290, 
            "sensor_states": [
                "ACTIVE", 
                "LIVE_RESPONSE_NOT_RUNNING", 
                "LIVE_RESPONSE_NOT_KILLED", 
                "LIVE_RESPONSE_ENABLED", 
                "SECURITY_CENTER_OPTLN_DISABLED"
            ], 
            "deregistered_time": null, 
            "last_external_ip_address": "2.2.2.2", 
            "middle_name": null, 
            "last_location": "OFFSITE", 
            "sensor_kit_type": "WINDOWS", 
            "target_priority": "HIGH", 
            "organization_name": "cb-test.com", 
            "os_version": "Windows 10 x64", 
            "quarantined": false, 
            "mac_address": "000000000000", 
            "av_update_servers": null, 
            "virtualization_provider": "UNKNOWN", 
            "registered_time": "2019-03-28T15:52:36.830Z", 
            "uninstall_code": "ZHZZRBAB", 
            "email": "introspect", 
            "sensor_out_of_date": true, 
            "av_vdf_version": "8.16.46.30", 
            "status": "REGISTERED", 
            "av_ave_version": "8.3.60.28", 
            "virtual_machine": false, 
            "av_last_scan_time": null, 
            "ad_group_id": 0, 
            "windows_platform": null, 
            "av_pack_version": "8.5.0.58", 
            "av_status": [
                "AV_ACTIVE", 
                "ONDEMAND_SCAN_DISABLED"
            ], 
            "organization_id": 1190, 
            "last_reset_time": null, 
            "scan_last_action_time": null, 
            "last_shutdown_time": "2020-01-16T01:53:02.733Z", 
            "policy_override": true, 
            "av_master": false, 
            "last_contact_time": "2020-05-26T13:32:36.272Z", 
            "name": "DESKTOP-QOKND73", 
            "activation_code_expiry_time": "2019-04-04T15:52:36.799Z", 
            "scan_last_complete_time": null, 
            "last_internal_ip_address": "8.8.8.8", 
            "linux_kernel_version": null, 
            "vdi_base_device": null, 
            "passive_mode": false, 
            "login_user_name": null, 
            "av_engine": "4.9.0.264-ave.8.3.60.28:avpack.2.4.1.58:vdf.8.16.46.30:apc.2.2.2.2", 
            "device_meta_data_item_list": [
                {
                    "key_name": "OS_MAJOR_VERSION", 
                    "key_value": "Windows 10", 
                    "position": 0
                }, 
                {
                    "key_name": "SUBNET", 
                    "key_value": "10.67.50", 
                    "position": 0
                }
            ], 
            "last_policy_updated_time": "2020-02-13T03:56:45.796Z", 
            "av_product_version": "4.9.0.264", 
            "first_name": null, 
            "activation_code": null, 
            "os": "WINDOWS", 
            "policy_id": 12064
        }
    ]
}
```

##### Human Readable Output
### Devices list results
|ID|LastContactTime|LastExternalIpAddress|LastInternalIpAddress|LastLocation|Name|OS|PolicyName|Quarantined|TargetPriority|status|
|---|---|---|---|---|---|---|---|---|---|---|
| 1244290 | 2020-05-26T13:32:36.272Z | 2.2.2.2 | 3.3.3.3 | OFFSITE | DESKTOP-ABCND73 | WINDOWS | test | false | HIGH | REGISTERED |
| 127519 | 2020-05-26T13:32:36.257Z | 4.4.4.4 | 10.10.10.10 | OFFSITE | AGENT-PC | WINDOWS | Detection_Servers | false | HIGH | REGISTERED |
| 5425783 | 2020-05-26T13:32:23.788Z | 8.8.8.8 | 10.10.10.10 | OFFSITE | Alphab-Win10-VM-1 | WINDOWS | test | false | HIGH | REGISTERED |

### 10. cb-eedr-list-alerts
---
Returns a list of alerts.
##### Required Permissions
RBAC Permissions Required - org.alerts: READ
##### Base Command

`cb-eedr-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_results | Whether to group results. Can be "true" or "false". The default is "true". | Optional | 
| minimum_severity | Alert minimum severity. | Optional | 
| device_os_version | Device OS version. Supports comma-separated values. | Optional | 
| policy_id | The policy ID. Supports comma-separated values. | Optional | 
| alert_tag | Alert tags. Supports comma-separated values. | Optional | 
| alert_id | Alert ID. Supports comma-separated values. | Optional | 
| device_username | Device username. Supports comma-separated values. | Optional | 
| device_id | Device ID. Supports comma-separated values. | Optional | 
| device_os | Device OS. Supports comma-separated values. | Optional | 
| process_sha256 | Process SHA256. Supports comma-separated values. | Optional | 
| policy_name | Policy name. Supports comma-separated values. | Optional | 
| reputation | Alert reputation. Supports comma-separated values. | Optional | 
| alert_type | Alert type. Supports comma-separated values. | Optional | 
| alert_category | Alert category. Supports comma-separated values. | Optional | 
| workflow | Alert workflow. Supports comma-separated values. | Optional | 
| device_name | Device name. Supports comma-separated values. | Optional | 
| process_name | Process name. Supports comma-separated values. | Optional | 
| sort_field | Field by which to sort the results. Can be "first_event_time", "last_event_time", "severity", or "target_value". | Optional | 
| sort_order | How to order the results. Can be "ASC" (ascending) or "DESC" (descending). The default is "DESC". | Optional | 
| limit | The maximum number of results to return. The default is 10. | Optional | 
| start_time | Alert start time. | Optional | 
| end_time | Alert end time. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Alert.threat_id | String | Threat ID. | 
| CarbonBlackEEDR.Alert.first_event_time | Date | First event time. | 
| CarbonBlackEEDR.Alert.target_value | String | Alert target value. | 
| CarbonBlackEEDR.Alert.reason | String | Alert reason. | 
| CarbonBlackEEDR.Alert.org_key | String | Organization key. | 
| CarbonBlackEEDR.Alert.device_id | String | Device ID. | 
| CarbonBlackEEDR.Alert.report_id | String | Report ID. | 
| CarbonBlackEEDR.Alert.watchlists.id | String | Watchlist ID. | 
| CarbonBlackEEDR.Alert.watchlists.name | String | Watchlist name. | 
| CarbonBlackEEDR.Alert.device_os_version | String | Device OS version. | 
| CarbonBlackEEDR.Alert.threat_cause_threat_category | String | Threat cause threat category. | 
| CarbonBlackEEDR.Alert.policy_id | String | Policy ID. | 
| CarbonBlackEEDR.Alert.threat_indicators.process_name | String | Threat indicator - process name. | 
| CarbonBlackEEDR.Alert.threat_indicators.sha256 | String | Indicator SHA256 hash. | 
| CarbonBlackEEDR.Alert.threat_cause_actor_sha256 | String | Threat cause actor SHA256. | 
| CarbonBlackEEDR.Alert.device_os | String | Device OS. | 
| CarbonBlackEEDR.Alert.document_guid | String | Document GUID. | 
| CarbonBlackEEDR.Alert.create_time | Date | Alert create time. | 
| CarbonBlackEEDR.Alert.threat_cause_actor_name | String | Threat cause actor name. | 
| CarbonBlackEEDR.Alert.ioc_hit | String | IOC hit. | 
| CarbonBlackEEDR.Alert.threat_cause_reputation | String | Threat cause reputation. | 
| CarbonBlackEEDR.Alert.legacy_alert_id | String | Legacy alert ID. | 
| CarbonBlackEEDR.Alert.device_name | String | Device name. | 
| CarbonBlackEEDR.Alert.report_name | String | Report name. | 
| CarbonBlackEEDR.Alert.policy_name | String | Policy name. | 
| CarbonBlackEEDR.Alert.ioc_field | String | IOC field. | 
| CarbonBlackEEDR.Alert.tags | String | Alert tags. | 
| CarbonBlackEEDR.Alert.process_guid | String | Process GUID. | 
| CarbonBlackEEDR.Alert.threat_cause_actor_md5 | String | Threat cause actor MD5 hash. | 
| CarbonBlackEEDR.Alert.last_update_time | Date | Alert last updated time. | 
| CarbonBlackEEDR.Alert.type | String | Alert type. | 
| CarbonBlackEEDR.Alert.id | String | Alert ID. | 
| CarbonBlackEEDR.Alert.process_name | String | Process name. | 
| CarbonBlackEEDR.Alert.last_event_time | Date | Alert last event time. | 
| CarbonBlackEEDR.Alert.ioc_id | String | IOC ID. | 
| CarbonBlackEEDR.Alert.notes_present | Boolean | Whether notes are present. | 
| CarbonBlackEEDR.Alert.run_state | String | Alert run state. | 
| CarbonBlackEEDR.Alert.severity | Number | Alert severity. | 
| CarbonBlackEEDR.Alert.category | String | Alert category. | 
| CarbonBlackEEDR.Alert.threat_cause_vector | String | Threat cause vector. | 
| CarbonBlackEEDR.Alert.device_username | String | Device username. | 
| CarbonBlackEEDR.Alert.workflow.changed_by | String | Alert workflow - changed by. | 
| CarbonBlackEEDR.Alert.workflow.comment | String | Alert workflow - comment. | 
| CarbonBlackEEDR.Alert.workflow.last_update_time | Date | Alert workflow - last updated time. | 
| CarbonBlackEEDR.Alert.workflow.remediation | String | Alert workflow - remediation. | 
| CarbonBlackEEDR.Alert.workflow.state | String | Alert workflow - state | 


##### Command Example
```!cb-eedr-list-alerts```

##### Context Example
```
{
    "CarbonBlackEEDR.Alert": [
        {
            "last_update_time": "2020-05-13T13:31:15.024Z", 
            "report_name": "Report for itype = 'mal_ip'", 
            "last_event_time": "2020-05-13T13:26:55.640Z", 
            "threat_cause_reputation": "KNOWN_MALWARE", 
            "policy_name": "test-policy", 
            "create_time": "2020-05-13T13:31:15.024Z", 
            "id": "ED0B5E6AE0C0E631FABC7E186CE036A5", 
            "threat_indicators": [
                {
                    "sha256": "067f1b8f1e0b2bfe286f5169e17834e8cf7f4266b8d97f28ea78995dc81b0e8a", 
                    "process_name": "067f1b8f1e0b2bfe123f5169e17834e8cf7f4266b8d97f28ea78995dc81b0e7b.exe", 
                    "ttps": [
                        "e18e60af525e8240a2a4cfef34cc45a4"
                    ]
                }
            ], 
            "device_name": "DESKTOP-AB3H40D", 
            "device_os": "WINDOWS", 
            "category": "THREAT", 
            "device_username": "test@atest.com", 
            "threat_cause_actor_name": "123f1b8f1e0b2bfe286f5169e17834e8cf7f4266b8d97f28ea78995dc81b0e7b.exe", 
            "severity": 10, 
            "threat_cause_actor_sha256": "345f1b8f1e0b2bfe286f5169e17834e8cf7f4266b8d97f28ea78995dc81b0e7b", 
            "workflow": {
                "comment": null, 
                "last_update_time": "2020-05-25T09:38:41.101Z", 
                "changed_by": "ABC5Y9DR4B", 
                "remediation": "just for testing", 
                "state": "DISMISSED"
            }, 
            "document_guid": "MncmKURBNMS1IGM7r6T2ug", 
            "ioc_field": "netconn_ipv4", 
            "process_guid": "7DESJ9NM-00346702-00001cc4-00000000-1d6292928b64305", 
            "report_id": "xSnGrSquRJjsh6A2pM8hsA-TS-Report-7", 
            "type": "WATCHLIST", 
            "threat_cause_threat_category": null, 
            "threat_cause_vector": "UNKNOWN", 
            "tags": null, 
            "process_name": "067f1b8f1e0b2bfe123f5169e17834e8cf7f4266b8d97f28ea78995dc81b0e7b.exe", 
            "reason": "Process 067f1b8f1e0b2bfe123f5169e17834e8cf7f4266b8d97f28ea78995dc81b0e7b.exe was detected by the report \"Report for itype = 'mal_ip'\" in watchlist \"ThreatStream_ITYPE\"", 
            "threat_cause_actor_md5": "21a563f123b73d453ad91e251b11855c", 
            "ioc_hit": "2.2.2.2", 
            "device_id": 1234242, 
            "count": 0, 
            "threat_id": "6C90312382C314B22BEA8D90170FB9A3", 
            "target_value": "MEDIUM", 
            "first_event_time": "2020-05-13T13:26:55.640Z", 
            "watchlists": [
                {
                    "id": "AB6iVKG3SoqBYvmXxtAmfg", 
                    "name": "Test_ITYPE"
                }
            ], 
            "device_os_version": null, 
            "notes_present": false, 
            "ioc_id": "e18e60af525e1234a2a4cfef34cc73a4", 
            "legacy_alert_id": "7ABCJ9GN-00346702-00001cc4-00000000-1d6292928b64305-xSnGrSquRJifv6A2pM8hsA-TS-Report-7", 
            "run_state": "RAN", 
            "org_key": "7DABJ9GN", 
            "policy_id": 36196
        }
    ]
}
```

##### Human Readable Output
### Alerts list results
|AlertID|CreateTime|DeviceID|DeviceName|DeviceOS|PolicyName|ProcessName|Type|WorkflowState|
|---|---|---|---|---|---|---|---|---|
| ED0C9E6AE0C0E631FABC7E145CE036A5 | 2020-05-13T13:31:15.024Z | 1234242 | DESKTOP-AB3H40D | WINDOWS | test1 | 067f1b8f1e0b2bfe286f5169e17834e8cf7f4123b8d97f28ea78995dc81b0e7b.exe | WATCHLIST | DISMISSED |
| A28C720DCBCD77222A621233AB1E0FE9 | 2020-04-27T12:21:51.294Z | 3450646 | TESTERONAPPS-CBDEF-1 | WINDOWS | test | svchost.exe | WATCHLIST | OPEN |


### 11. cb-eedr-watchlist-list
---
Retrieves all watchlists.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: READ
##### Base Command

`cb-eedr-watchlist-list`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Watchlist.classifier | String | Watchlist classifier. | 
| CarbonBlackEEDR.Watchlist.last_update_timestamp | Date | Watchlist last updated timestamp. | 
| CarbonBlackEEDR.Watchlist.name | String | Watchlist name. | 
| CarbonBlackEEDR.Watchlist.report_ids | String | Watchlist report IDs. | 
| CarbonBlackEEDR.Watchlist.create_timestamp | Date | Watchlist created timestamp. | 
| CarbonBlackEEDR.Watchlist.id | String | Watchlist ID. | 
| CarbonBlackEEDR.Watchlist.tags_enabled | Boolean | Whether tags are enabled for the watchlist. | 
| CarbonBlackEEDR.Watchlist.description | String | Watchlist description. | 


##### Command Example
```!cb-eedr-watchlist-list```

##### Context Example
```
{
    "CarbonBlackEEDR.Watchlist": [
        {
            "description": "this is a test watchlist", 
            "name": "test watchlist", 
            "last_update_timestamp": 1589380783, 
            "tags_enabled": false, 
            "alerts_enabled": false, 
            "create_timestamp": 1589380783, 
            "report_ids": [
                "A59huyinQSmAr8t1a2hpg"
            ], 
            "id": "2Bge40iPRCachAa1oYqMkA", 
            "classifier": null
        }, 
        {
            "description": "this is a test watchlist", 
            "name": "test watchlist1", 
            "last_update_timestamp": 1589380803, 
            "tags_enabled": false, 
            "alerts_enabled": false, 
            "create_timestamp": 1589380803, 
            "report_ids": [
                "A59huyinQSmAr8t1a2hpg"
            ], 
            "id": "AiyyP5o1T6ia2LGBIuZtg", 
            "classifier": null
        }, 
        {
            "description": "this is a test watchlist", 
            "name": "test watchlist123", 
            "last_update_timestamp": 1589380858, 
            "tags_enabled": false, 
            "alerts_enabled": false, 
            "create_timestamp": 1589380858, 
            "report_ids": [
                "A59huyinQSmAr8t1a2hpg"
            ], 
            "id": "5xq2xyrKRTOMzt5V8SaJQ", 
            "classifier": null
        }
        {
            "description": "Updating description", 
            "name": "test1", 
            "last_update_timestamp": 1589456792, 
            "tags_enabled": true, 
            "alerts_enabled": true, 
            "create_timestamp": 1589456617, 
            "report_ids": null, 
            "id": "n4O82vT2TPa5Tuw54jmVLg", 
            "classifier": {
                "value": "krOSyGQmSVNfxDgIkHSA", 
                "key": "feed_id"
            }
        }
    ]
}
```

##### Human Readable Output
### Carbon Black Enterprise EDR Watchlists
|ID|Name|Description|create_timestamp|Alerts_enabled|Tags_enabled|Report_ids|Last_update_timestamp|Classifier|
|---|---|---|---|---|---|---|---|---|
| AjQoLZwJRYu4oPC22YpepQ | test watchlist2 |  | 2020-05-26T13:27:44.000Z | true | true | A59huyinQSmAr8t1a2hpg | 2020-05-26T13:27:44.000Z |  |
| 2Bge40iPRCachAa1oYqMkA | test watchlist | this is a test watchlist | 2020-05-13T14:39:43.000Z | false | false | A59huyinQSmAr8t1a2hpg | 2020-05-13T14:39:43.000Z |  |
| AiyyP5o1T6ia2LGBIuZtg | test watchlist1 | this is a test watchlist | 2020-05-13T14:40:03.000Z | false | false | A59huyinQSmAr8t1a2hpg | 2020-05-13T14:40:03.000Z |  |
| 5xq2xyrKRTOMzt5V8SaJQ | test watchlist123 | this is a test watchlist | 2020-05-13T14:40:58.000Z | false | false | A59huyinQSmAr8t1a2hpg | 2020-05-13T14:40:58.000Z |  |
| MXzJPzWYRuuKBEsy0UXImA | Cigent Watchlist |  | 2020-01-16T21:07:58.000Z | true | true | MLRtPcpQGKFh5OE4BT3tQ-19d3af31-5dbd-4b9f-9b1d-e8ddca6af991 | 2020-01-28T18:19:14.000Z |  |


### 12. cb-eedr-get-watchlist-by-id
---
Gets watchlist information by  watchlist ID.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: READ
##### Base Command

`cb-eedr-get-watchlist-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. Get the ID from the watchlist-list command. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Watchlist.classifier | String | Watchlist classifier. | 
| CarbonBlackEEDR.Watchlist.last_update_timestamp | Date | Watchlist last updated timestamp. | 
| CarbonBlackEEDR.Watchlist.name | String | Watchlist name. | 
| CarbonBlackEEDR.Watchlist.report_ids | String | Watchlist report IDs. | 
| CarbonBlackEEDR.Watchlist.create_timestamp | Date | Watchlist created timestamp. | 
| CarbonBlackEEDR.Watchlist.id | String | Watchlist ID. | 
| CarbonBlackEEDR.Watchlist.tags_enabled | Boolean | Whether tags are enabled for the watchlist. | 
| CarbonBlackEEDR.Watchlist.description | String | Watchlist description. | 
| CarbonBlackEEDR.Watchlist.Aaerts_enabled | Boolean | Whether alerts are enabled for the watchlists. | 


##### Command Example
```!cb-eedr-get-watchlist-by-id watchlist_id="JI5wCDVTPGEgbWlDCoGgQ"```

##### Context Example
```
{
    "CarbonBlackEEDR.Watchlist": {
        "description": "test description", 
        "name": "test watchlist1", 
        "last_update_timestamp": 1589379124, 
        "tags_enabled": false, 
        "alerts_enabled": true, 
        "create_timestamp": 1568314084, 
        "report_ids": [
            "A59huyinQSmAr8t1a2hpg"
        ], 
        "id": "JI5wCDVTPGEgbWlDCoGgQ", 
        "classifier": null
    }
}
```

##### Human Readable Output
### Watchlist JI5wCDVTPGEgbWlDCoGgQ information
|ID|Name|Description|create_timestamp|Alerts_enabled|Tags_enabled|Report_ids|Last_update_timestamp|
|---|---|---|---|---|---|---|---|
| JI5wCDVTPGEgbWlDCoGgQ | test watchlist1 | test description | 1970-01-19T03:38:34.000Z | true | false | A59huyinQSmAr8t1a2hpg | 1970-01-19T09:29:39.000Z |


### 13. cb-eedr-watchlist-alerts-status
---
Retrieves the alert status for the watchlist with given watchlist ID.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: READ
##### Base Command

`cb-eedr-watchlist-alerts-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. Get the ID from the watchlist-list command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-watchlist-alerts-status watchlist_id=AiyyP5o1T6ia2LGBIuZtg```

##### Human Readable Output
Watchlist AiyyP5o1T6ia2LABIuZtg alert status is On

### 14. cb-eedr-watchlist-alerts-enable
---
Turns on alerts for the watchlist with the specified watchlist ID.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: READ
##### Base Command

`cb-eedr-watchlist-alerts-enable`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. Get the ID from the watchlist-list command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-watchlist-alerts-enable watchlist_id=AiyyP5o1T6ia2LABIuZtg```

##### Human Readable Output
Watchlist AiyyP5o1T6ia2LABIuZtg alert was enabled successfully.

### 15. cb-eedr-watchlist-alerts-disable
---
Turns off alerts for the watchlist with the specified watchlist ID.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: READ
##### Base Command

`cb-eedr-watchlist-alerts-disable`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. Get the ID from the watchlist-list command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-watchlist-alerts-disable watchlist_id=AiyyP5o1T6ia2LABIuZtg```

##### Human Readable Output
Watchlist AiyyP5o1T6ia2LABIuZtg alert was disabled successfully.

### 16. cb-eedr-watchlist-create
---
Creates a new report or classifier watchlist.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: CREATE
##### Base Command

`cb-eedr-watchlist-create`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The name of the watchlist. | Required | 
| description | The watchlist description. | Optional | 
| tags_enabled | Whether to enable watchlist tags. Can be "true" or "false". | Optional | 
| alerts_enabled | Enable watchlist alerts | Optional | 
| report_ids | The report IDs for creating the watchlist. Supports comma-separated values. | Optional | 
| classifier_key | The classifier key for creating the watchlist. | Optional | 
| classifier_value | The classifier value for creating the watchlist. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Watchlist.Classifier | String | The watchlist classifier. | 
| CarbonBlackEEDR.Watchlist.Last_update_timestamp | Date | Watchlist last updated timestamp. | 
| CarbonBlackEEDR.Watchlist.Name | String | Watchlist name. | 
| CarbonBlackEEDR.Watchlist.Report_ids | String | Watchlist report ID. | 
| CarbonBlackEEDR.Watchlist.Create_timestamp | Date | Watchlist created timestamp. | 
| CarbonBlackEEDR.Watchlist.Alerts_enabled | Boolean | Whether alerts are enabled in the watchlist. | 
| CarbonBlackEEDR.Watchlist.ID | String | Watchlist ID. | 
| CarbonBlackEEDR.Watchlist.Tags_enabled | Boolean | Whether tags are enabled in the watchlist. | 
| CarbonBlackEEDR.Watchlist.Description | String | Watchlist description. | 


##### Command Example
```!cb-eedr-watchlist-create watchlist_name="test watchlist3" alerts_enabled=false tags_enabled=false report_ids=A59huyinQSmAr8t1a2hpg```

##### Context Example
```
{
    "CarbonBlackEEDR.Watchlist": {
        "Description": null, 
        "Tags_enabled": true, 
        "Alerts_enabled": true, 
        "Classifier": null, 
        "Create_timestamp": "2020-05-26T13:33:19.000Z", 
        "Report_ids": [
            "A59huyinQSmAr8t1a2hpg"
        ], 
        "ID": "Bz4PlP5RSiGLvekCLbC0A", 
        "Name": "test watchlist3"
    }
}
```

##### Human Readable Output
### The watchlist "test watchlist3" created successfully.
|Name|ID|Create_timestamp|Tags_enabled|Alerts_enabled|Report_ids|
|---|---|---|---|---|---|
| test watchlist3 | Bz4PlP5RSiGLvekCLbC0A | 2020-05-26T13:33:19.000Z | true | true | A59huyinQSmAr8t1a2hpg |


### 17. cb-eedr-watchlist-delete
---
Removes the specified watchlist.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: DELETE
##### Base Command

`cb-eedr-watchlist-delete`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID to remove. Get the ID from the watchlist-list command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-watchlist-delete watchlist_id=AjQoLZwJRYu4oPC22YpepQ```

##### Human Readable Output
The watchlist AjQoLZwJRYu4oPC22YpepQ was deleted successfully.

### 18. cb-eedr-watchlist-update
---
Updates the specified watchlist. This will update the tags and alert status as well as any reports or classifiers attached to the watchlist.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: UPDATE
##### Base Command

`cb-eedr-watchlist-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID to update. | Required | 
| watchlist_name | The watchlist name. | Optional | 
| description | Watchlist description. | Optional | 
| tags_enabled | Whether to enable watchlist tags. Can be "true" or "false". | Optional | 
| alerts_enabled | Enable watchlist alerts. | Optional | 
| report_ids | Watchlist report ID. Supports comma-separated values. | Optional | 
| classifier_key | The classifier key to update. | Optional | 
| classifier_value | The classifier value to update. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Watchlist.Classifier | String | The watchlist classifier. | 
| CarbonBlackEEDR.Watchlist.Last_update_timestamp | Date | Watchlist last update timestamp. | 
| CarbonBlackEEDR.Watchlist.Name | String | Watchlist name. | 
| CarbonBlackEEDR.Watchlist.Report_ids | String | Watchlist report ID. | 
| CarbonBlackEEDR.Watchlist.Create_timestamp | Date | Watchlist created timestamp. | 
| CarbonBlackEEDR.Watchlist.Alerts_enabled | Boolean | Whether alerts are enabled in the watchlist. | 
| CarbonBlackEEDR.Watchlist.ID | String | Watchlist ID. | 
| CarbonBlackEEDR.Watchlist.Tags_enabled | Boolean | Whether tags are enabled in the watchlist. | 
| CarbonBlackEEDR.Watchlist.Description | String | Watchlist description. | 


##### Command Example
```!cb-eedr-watchlist-update watchlist_id=2Bge40iPRCachAa1oYqMkA alerts_enabled=true watchlist_name="new name"```

##### Context Example
```
{
    "CarbonBlackEEDR.Watchlist": {
        "Description": null, 
        "Tags_enabled": false, 
        "Alerts_enabled": true, 
        "Classifier": null, 
        "Create_timestamp": "2020-05-13T14:39:43.000Z", 
        "Report_ids": [], 
        "ID": "2Bge40iPRCachAa1oYqMkA", 
        "Name": "new name"
    }
}
```

##### Human Readable Output
### The watchlist "2Bge40iPRCachAa1oYqMkA" was updated successfully.
|Name|ID|Create_timestamp|Tags_enabled|Alerts_enabled|
|---|---|---|---|---|
| new name | 2Bge40iPRCachAa1oYqMkA | 2020-05-13T14:39:43.000Z | false | true |


### 19. cb-eedr-report-get
---
Retrieves the specified report.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: READ
##### Base Command

`cb-eedr-report-get`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. Get the ID from the watchlist-list command. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Report.Visibility | String | Report visibility. | 
| CarbonBlackEEDR.Report.Title | String | Report title. | 
| CarbonBlackEEDR.Report.Tags | String | Report tags. | 
| CarbonBlackEEDR.Report.Link | String | Report link. | 
| CarbonBlackEEDR.Report.ID | String | Report ID. | 
| CarbonBlackEEDR.Report.Timestamp | Date | Report timestamp. | 
| CarbonBlackEEDR.Report.Description | String | Report description. | 
| CarbonBlackEEDR.Report.Severity | Number | Report severity. | 
| CarbonBlackEEDR.Report.IOCs | String | The report's IOCs. | 


##### Command Example
```!cb-eedr-report-get report_id="A59huyinQSmAr8t1a2hpg"```

##### Context Example
```
{
    "CarbonBlackEEDR.Report": {
        "Severity": 8, 
        "Tags": [
            "SAMPLE"
        ], 
        "Timestamp": "1970-01-19T06:40:07.000Z", 
        "IOCs": [
            {
                "values": [
                    "(process_name:chrome.exe)"
                ], 
                "field": null, 
                "match_type": "query", 
                "link": null, 
                "id": "860ececb-2a2e-4dc5-bdbd-f6f45657cf7c"
            }, 
            {
                "values": [
                    "(process_name:chrome.exe)"
                ], 
                "field": null, 
                "match_type": "query", 
                "link": null, 
                "id": "f551ba63-0c7a-48ec-b12d-c4b2a9f4b922"
            }, 
            {
                "values": [
                    "(netconn_ipv4:2.2.2.2)"
                ], 
                "field": null, 
                "match_type": "query", 
                "link": null, 
                "id": "c86187e3-90e3-4fb0-a698-18112b294059"
            }, 
            {
                "values": [
                    "(process_name:c\\:\\\\users\\\\administrator\\\\desktop\\\\badfile.exe)"
                ], 
                "field": null, 
                "match_type": "query", 
                "link": null, 
                "id": "46e11795-e7ee-4f8e-8ad8-44b1d2216e30"
            }
        ], 
        "Title": "badfile.exe", 
        "Visibility": null, 
        "Link": null, 
        "ID": "A59huyinQSmAr8t1a2hpg", 
        "Description": ""
    }
}
```

##### Human Readable Output
### Report "A59huyinQSmAr8t1a2hpg" information
|ID|Title|Timestamp|Severity|Tags|
|---|---|---|---|---|
| A59huyinQSmAr8t1a2hpg | badfile.exe.exe | 1970-01-19T06:40:07.000Z | 8 | SAMPLE |
### The IOCs for the report
|ID|Match_type|Values|
|---|---|---|
| 860ececb-2a2e-4dc5-bdbd-f6f45657cf7c | query | (process_name:chrome.exe) |
| f551ba63-0c7a-48ec-b12d-c4b2a9f4b922 | query | (process_name:chrome.exe) |
| c86187e3-90e3-4fb0-a698-18112b294059 | query | (netconn_ipv4:2.2.2.2) |
| 46e11795-e7ee-4f8e-8ad8-44b1d2216e30 | query | (process_name:c\:\\users\\administrator\\desktop\\badfile.exe) |


### 20. cb-eedr-ioc-ignore-status
---
Gets the current ignore status for IOC ioc_id in report report_id.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: READ
##### Base Command

`cb-eedr-ioc-ignore-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID. Get the ID from the watchlist-list command. | Required | 
| ioc_id | IOC ID. Get the ID from get_report command | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-ioc-ignore-status ioc_id=860ececb-2a2e-4dc5-bdbd-f6f45657cf7c report_id=A59huyinQSmAr8t1a2hpg```

##### Human Readable Output
IOC 860ececb-2a2e-4dc5-bdbd-f6f45657cf7c status is false

### 21. cb-eedr-ioc-ignore
---
IOC ioc_id for report report_id will not match future events for any watchlist.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: UPDATE
##### Base Command

`cb-eedr-ioc-ignore`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID. Get the ID from the watchlist-list command. | Required | 
| ioc_id | IOC ID. Get the ID from get_report command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-ioc-ignore ioc_id=860ececb-2a2e-4dc5-bdbd-f6f45657cf7c report_id=A59huyinQSmAr8t1a2hpg```

##### Human Readable Output
The IOC 860ececb-2a2e-4dc5-bdbd-f6f45657cf7c for report A59huyinQSmAr8t1a2hpg will not match future events for any watchlist.

### 22. cb-eedr-ioc-reactivate
---
IOC ioc_id for report report_id will match future events for all watchlists.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: DELETE
##### Base Command

`cb-eedr-ioc-reactivate`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID. Get the ID from the watchlist-list command. | Required | 
| ioc_id | IOC ID. Get the ID from get_report command | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-ioc-reactivate ioc_id=860ececb-2a2e-4dc5-bdbd-f6f45657cf7c report_id=A59huyinQSmAr8t1a2hpg```

##### Human Readable Output
IOC 860ececb-2a2e-4dc5-bdbd-f6f45657cf7c for report A59huyinQSmAr8t1a2hpg will match future events for all watchlists.

### 23. cb-eedr-report-ignore
---
Report with report_id and all contained IOCs will not match future events for any watchlist.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: UPDATE
##### Base Command

`cb-eedr-report-ignore`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. Get the ID from the watchlist-list command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-report-ignore report_id=A59huyinQSmAr8t1a2hpg```

##### Human Readable Output
The report with report_id "A59huyinQSmAr8t1a2hpg" and all contained IOCs will not match future events for any watchlist.

### 24. cb-eedr-report-reactivate
---
Report with report_id and all contained IOCs will match future events for all watchlists.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: DELETE
##### Base Command

`cb-eedr-report-reactivate`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. Get the ID from the watchlist-list command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-report-reactivate report_id=qtcpqJwuRjaFZWjAT8zhqQ```

##### Human Readable Output
Report with report_id "qtcpqJwuRjaFZWjAT8zhqQ" and all contained IOCs will match future events for all watchlists

### 25. cb-eedr-report-ignore-status
---
Get current ignore status for report with report_id.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: READ
##### Base Command

`cb-eedr-report-ignore-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. Get the ID from the watchlist-list command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-report-ignore-status report_id=A59huyinQSmAr8t1a2hpg```

##### Human Readable Output
ignore status for report with report_id "A59huyinQSmAr8t1a2hpg" is enabled.

### 26. cb-eedr-report-remove
---
Remove report with report_id.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: DELETE
##### Base Command

`cb-eedr-report-remove`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID to remove. Get the ID from the watchlist-list command. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cb-eedr-report-remove report_id=A59huyinQSmAr8t1a2hpg ```

##### Human Readable Output
The report "A59huyinQSmAr8t1a2hpg" was deleted successfully.

### 27. cb-eedr-report-create
---
Adds a new watchlist report.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: CREATE
##### Base Command

`cb-eedr-report-create`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The report title. | Required | 
| description | The report description. | Required | 
| tags | The report tags. Supports comma-separated values. | Optional | 
| severity | The report severity (In range of 1-10). | Required | 
| ipv4 | IOCs of type IPv4. Supports comma-separated values. | Optional | 
| ioc_query | The IOC query for the report, for example: (netconn_ipv4:2.2.2.2). Supports comma-separated values. | Optional | 
| timestamp | The report timestamp. For example: 2020-01-19T09:16:16 | Required | 
| ipv6 | IOCs of type IPv6. Supports comma-separated values. | Optional | 
| md5 | IOCs of type MD5. Supports comma-separated values. | Optional | 
| dns | IOCs of type DNS. Supports comma-separated values. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Report.ID | String | The report ID. | 
| CarbonBlackEEDR.Report.IOCs | String | The report IOCs | 
| CarbonBlackEEDR.Report.Link | String | Report link. | 
| CarbonBlackEEDR.Report.Severity | Number | Report severity. | 
| CarbonBlackEEDR.Report.Timestamp | Date | The report timestamp. | 
| CarbonBlackEEDR.Report.Title | String | The report title. | 
| CarbonBlackEEDR.Report.Tags | String | Report tags. | 
| CarbonBlackEEDR.Report.Visibility | String | Report visibility. | 
| CarbonBlackEEDR.Report.Description | String | The report description. | 


##### Command Example
```!cb-eedr-report-create title="Report test" description="Testing new report creation" tags="one,two,three" severity="5" ipv4="2.2.2.2,3.3.3.3" timestamp="2019-01-01T00:00:16"```

##### Context Example
```
{
    "CarbonBlackEEDR.Report": {
        "Severity": 5, 
        "Tags": [
            "one", 
            "two", 
            "three"
        ], 
        "Timestamp": "1970-01-18T21:31:40.000Z", 
        "IOCs": [
            {
                "values": [
                    "2.2.2.2", 
                    "3.3.3.3"
                ], 
                "field": "netconn_ipv4", 
                "match_type": "equality", 
                "link": null, 
                "id": "56e85f3d538b0602b10e0b544c3f61ea"
            }
        ], 
        "Title": "Report test", 
        "Visibility": null, 
        "Link": null, 
        "ID": "rbwEBRfnTUGB6LqTUcgWg", 
        "Description": "Testing new report creation"
    }
}
```

##### Human Readable Output
### The report was created successfully.
|ID|Title|Timestamp|Description|Severity|Tags|
|---|---|---|---|---|---|
| rbwEBRfnTUGB6LqTUcgWg | Report test | 1970-01-18T21:31:40.000Z | Testing new report creation | 5 | one,two,three |
### The IOCs for the report
|Field|ID|Match_type|Values|
|---|---|---|---|
| netconn_ipv4 | 56e85f3d538b0602b10e0b544c3f61ea | equality | 2.2.2.2,3.3.3.3 |


### 28. cb-eedr-report-update
---
Updates the specified report.
##### Required Permissions
RBAC Permissions Required - threathunter.watchlists: UPDATE
##### Base Command

`cb-eedr-report-update`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID to update. | Required | 
| title | The report title. | Required | 
| description | The report description. | Required | 
| tags | The report tags. Supports comma-separated values. | Optional | 
| ipv4 | IOC of type IPv4. Supports comma-separated values. | Optional | 
| ipv6 | IOC of type IPv6. Supports comma-separated values. | Optional | 
| dns | IOC of type DNS. Supports comma-separated values. | Optional | 
| md5 | IOC of type MD5. Supports comma-separated values. | Optional | 
| ioc_query | Query IOC. For example: (netconn_ipv4:2.2.2.2). Supports comma-separated values. | Optional | 
| severity | Report severity (In range of 1-10). | Required | 
| timestamp | The report timestamp. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Report.ID | String | The report ID. | 
| CarbonBlackEEDR.Report.IOCs | String | The report IOC's | 
| CarbonBlackEEDR.Report.Link | String | Report link. | 
| CarbonBlackEEDR.Report.Severity | Number | Report severity. | 
| CarbonBlackEEDR.Report.Timestamp | Date | The report timestamp. | 
| CarbonBlackEEDR.Report.Title | String | The report title. | 
| CarbonBlackEEDR.Report.Tags | String | Report tags. | 
| CarbonBlackEEDR.Report.Visibility | String | Report visibility. | 
| CarbonBlackEEDR.Report.Description | String | The report description. | 


##### Command Example
```!cb-eedr-report-update description="new description" report_id=qtcpqJwuRjaFZWjAT8zhqQ severity=5 timestamp=2020-05-19T09:18:48 title="new title"```

##### Context Example
```
{
    "CarbonBlackEEDR.Report": {
        "Severity": 5, 
        "Tags": null, 
        "Timestamp": "2473-10-23T21:08:00.000Z", 
        "IOCs": [], 
        "Title": "new title", 
        "Visibility": null, 
        "Link": null, 
        "ID": "qtcpqJwuRjaFZWjAT8zhqQ", 
        "Description": "new description"
    }
}
```

##### Human Readable Output
### The report was updated successfully.
|ID|Title|Timestamp|Description|Severity|
|---|---|---|---|---|
| qtcpqJwuRjaFZWjAT8zhqQ | new title | 2473-10-23T21:08:00.000Z | new description | 5 |
### The IOCs for the report
**No entries.**


### 29. cb-eedr-file-device-summary
---
Gets an overview of the devices that executed the file.
##### Required Permissions
RBAC Permissions Required - Ubs.org.sha256
##### Base Command

`cb-eedr-file-device-summary`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The requested SHA256 hash to obtain information for. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.File.first_seen_device_id | Number | The device ID of the device that first saw this file. | 
| CarbonBlackEEDR.File.first_seen_device_name | String | The name of the device that first saw this file. | 
| CarbonBlackEEDR.File.first_seen_device_timestamp | Date | The time that this file was first seen, for this organization. | 
| CarbonBlackEEDR.File.last_seen_device_id | Number | The device ID of the device that most recently saw this file. | 
| CarbonBlackEEDR.File.last_seen_device_name | String | The name of the device that last saw this file. | 
| CarbonBlackEEDR.File.last_seen_device_timestamp | Date | The time that this file was most recently seen for this organization. | 
| CarbonBlackEEDR.File.num_devices | Number | The total number of devices, for this organization, that have observed this file. | 
| CarbonBlackEEDR.File.sha256 | String | The SHA256 hash of the file. | 


##### Command Example
```!cb-eedr-file-device-summary sha256="4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa"```

##### Context Example
```
{
    "CarbonBlackEEDR.File": {
        "last_seen_device_timestamp": "2020-05-21T06:59:07.866395Z", 
        "num_devices": 3, 
        "last_seen_device_id": 1246865, 
        "first_seen_device_timestamp": "2020-05-18T09:26:28.205254Z", 
        "sha256": "4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa", 
        "last_seen_device_name": "testcorewin764", 
        "first_seen_device_name": "test732-PC", 
        "first_seen_device_id": 1294302
    }
}
```

##### Human Readable Output
### The file device summary
|first_seen_device_id|first_seen_device_name|first_seen_device_timestamp|last_seen_device_id|last_seen_device_name|last_seen_device_timestamp|num_devices|sha256|
|---|---|---|---|---|---|---|---|
| 1294302 | test732-PC | 2020-05-18T09:26:28.205254Z | 1246865 | testcorewin764 | 2020-05-21T06:59:07.866395Z | 3 | 4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa |


### 30. cb-eedr-get-file-metadata
---
Returns all of the metadata for the specified binary identified by the SHA256 hash.
##### Required Permissions
RBAC Permissions Required - Ubs.org.sha256
##### Base Command

`cb-eedr-get-file-metadata`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The requested SHA256 hash to obtain metadata information. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.File.file_size | Number | The size of the actual file. This is the size of the file represented by this hash. | 
| CarbonBlackEEDR.File.file_available | Boolean | If true, the file is available for download. | 
| CarbonBlackEEDR.File.sha256 | String | The SHA256 hash of the file. | 
| CarbonBlackEEDR.File.product_version | String | Product version from FileVersionInformation. | 
| CarbonBlackEEDR.File.product_description | String | Product description from FileVersionInformation. | 
| CarbonBlackEEDR.File.lang_id | String | The Language ID value from the Windows VERSIONINFO resource. | 
| CarbonBlackEEDR.File.company_name | String | Company name from FileVersionInformation | 
| CarbonBlackEEDR.File.internal_name | String | Internal name from FileVersionInformation. | 
| CarbonBlackEEDR.File.charset_id | Number | The Character set ID value from the Windows VERSIONINFO resource. | 
| CarbonBlackEEDR.File.available_file_size | Number | The size of the file, that is available for download. If the file is unavailable the size will be zero. | 
| CarbonBlackEEDR.File.architecture | String | The set of architectures that this file was compiled for. This may contain one or more of the following values: none, x86, amd64, and arm64. | 
| CarbonBlackEEDR.File.comments | String | Comments from FileVersionInformation. | 
| CarbonBlackEEDR.File.os_type | String | The OS that this file is designed for. This may contain one or more of the following values: WINDOWS, ANDROID, MAC, IOS, LINUX, and OTHER | 
| CarbonBlackEEDR.File.original_filename | String | Original filename from FileVersionInformation. | 
| CarbonBlackEEDR.File.file_version | String | File version from FileVersionInformation. | 
| CarbonBlackEEDR.File.file_description | String | File description from FileVersionInformation. | 
| CarbonBlackEEDR.File.product_name | String | Product name from FileVersionInformation. | 
| CarbonBlackEEDR.File.md5 | String | The MD5 hash of the file. | 


##### Command Example
```!cb-eedr-get-file-metadata sha256=4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa```

##### Context Example
```
{
    "CarbonBlackEEDR.File": {
        "product_version": "16.1.0.0", 
        "original_filename": "AutoPico.exe", 
        "charset_id": 1200, 
        "file_available": true, 
        "file_version": "16.1.0.0", 
        "product_description": null, 
        "comments": "Portable", 
        "sha256": "4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa", 
        "available_file_size": 745664, 
        "lang_id": null, 
        "company_name": "testCompany", 
        "internal_name": test.exe", 
        "file_size": 745664, 
        "os_type": "WINDOWS", 
        "md5": "cfe1c123464c446099a5eb33276f6d57", 
        "product_name": "Product", 
        "file_description": "Product", 
        "architecture": [
            "x86"
        ]
    }
}
```

##### Human Readable Output
### The file metadata
|SHA256|comments|file_size|internal_name|original_filename|os_type|
|---|---|---|---|---|---|
| 4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa | Portable | 745664 | test.exe | test.exe | WINDOWS |


### 31. cb-eedr-files-download-link-get
---
The files are able to be downloaded via AWS S3 pre-signed URLs.
##### Required Permissions
RBAC Permissions Required - Ubs.org.file
##### Base Command

`cb-eedr-files-download-link-get`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | An array of SHA256 hashes (limit 100). Supports comma-separated values. | Required | 
| expiration_seconds | The number of seconds to make the download URLs available for. The default is 300. | Optional | 
| download_to_xsoar | Download the file to XSOAR. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.File.found.sha256 | String | SHA256 hash of file that is available to be downloaded | 
| CarbonBlackEEDR.File.found.url | String | An AWS S3 pre-signed URL for this file. Perform a GET on this URL to download the file. | 
| CarbonBlackEEDR.File.not_found | String | The SHA256 hashes that were not found. | 
| CarbonBlackEEDR.File.error | String | The SHA256 hashes that had an intermittent error. | 


##### Command Example
```!cb-eedr-files-download-link-get sha256="4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa" expiration_seconds="3600" download_to_xsoar="false"```

##### Context Example
```
{
    "CarbonBlackEEDR.File": {
        "found": [
            {
                "url": "https://cdc-file-storage-production-us-east-1.s3.amazonaws.com/4a/71/4d/98/ce/40/f5/f3/57/7c/30/6a/66/cb/4a/6b/1f/f3/fd/01/04/7c/7f/45/81/f8/55/8f/0b/cd/f5/fa/4a714d98ce40f5f3577c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAVT6ZCSICASU327FI%2F20200526%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20200526T133305Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjAAwaCXVzLWVhc3QtMSJIMEYCIQCqqdEFtwaybOvJkycEEMnMQLR%2FoNSvmNbsb%2Bchb5UEpAIhAPZTjLn4T8p3IGfkKQ0CpEEot%2FLR9oI17UIKtAV1Ej7fKr0DCKT%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQAhoMMzg2NDY1NDM2MTY0IgyYvqWtKKorgx1b%2FXYqkQMeEOokBfnVZv0RtN1W3G3sW97NreAGknB7LRsG1QVMc4b4vrRmgvPvY1ZuE8hAIOu40RQfWBEgfiQo9URFcVRqzKFi8zrLEKlX0NinYijdgA8nHKFIlqSuPRArHXhwixq4aUzQ%2B3uh9UxM%2FrwSYItYn3skiacUz6TwqLFzjfWk3YIFMH3bP4jD9q7omZHgtA6PM%2BCbsf%2Fzj2DwI8JXGKyOm0jAMpNr8wz7n1gLoFnB5WHe4ELHpBfnAh%2Fe5r1H62n0y4eT%2B19zNuNZFd7jjr1FYgounceibjgvlGILMN3xhQWpjzUgssL3GprTM%2FCFy3FzxfPnjUcgJJ%2BjAJw9AICH2yCkFiY6IglFzQwzK%2BC5Q7HvEYmStt682IvQg6ZdYoWuH7iPf7ypiMB%2Bd4o2LwnJ67xCVitD0oLxFMYgIub4buB0dlSwy%2FskcERt81xlhWIZhxRYEDxyTtMPwYSRu5El7vvui5W9y0AmLBANjAb4EaFcaOqUIFOlF6JO%2Blt4Jc6LyMzFu3zdOd9Nx7%2Fi6AewgDDN97P2BTrqAdX%2BqmMi8oItlqJdoU9ntWJ2SBR6y2xa%2BCj3GpHLzvrvWMYAQPfcOxXqDYv9UPPAsPPh1Hxl1P0Jua%2BBwmwOA4m9Lak%2BkwqL8oQMUMb68pyRNxv8dTFa1turFetE9%2Bh4NTzHfxH5WhXH58oGt5ozzPmeJmuJrMAJJV%2BMZhdL1eClkK%2FzLKfSboJIgqmvMSXncccSmEc3Ref6qGWXN3k3%2F5YLf4831zEGH%2FUKCnQqU%2F45QVHvPOfuw2%2BIsItIYimn8YRW73TMOpp3frhKVYMiEwhVBNFQESjNLzDfBZgIMKeWjUbHmJT4Cwb82w%3D%3D&X-Amz-Signature=0757be785f81856477277969af21d8076289d4bb92274c42c73b8d2776443763", 
                "sha256": "4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa"
            }
        ], 
        "not_found": [], 
        "error": []
    }
}
```

##### Human Readable Output
### The file to download
|sha256|url|
|---|---|
| 4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa | https://cdc-file-storage-production-us-east-1.s3.amazonaws.com/4a/71/4d/98/ce/40/f5/f3/57/7c/30/6a/66/cb/4a/6b/1f/f3/fd/01/04/7c/7f/45/81/f8/55/8f/0b/cd/f5/fa/4a714d98ce40f5f3577c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAVT6ZCSICASU327FI%2F20200526%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20200526T133305Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Security-Token=IQoJb3JpZ2luX2VjAAwaCXVzLWVhc3QtMSJIMEYCIQCqqdEFtwaybOvJkycEEMnMQLR%2FoNSvmNbsb%2Bchb5UEpAIhAPZTjLn4T8p3IGfkKQ0CpEEot%2FLR9oI17UIKtAV1Ej7fKr0DCKT%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEQAhoMMzg2NDY1NDM2MTY0IgyYvqWtKKorgx1b%2FXYqkQMeEOokBfnVZv0RtN1W3G3sW97NreAGknB7LRsG1QVMc4b4vrRmgvPvY1ZuE8hAIOu40RQfWBEgfiQo9URFcVRqzKFi8zrLEKlX0NinYijdgA8nHKFIlqSuPRArHXhwixq4aUzQ%2B3uh9UxM%2FrwSYItYn3skiacUz6TwqLFzjfWk3YIFMH3bP4jD9q7omZHgtA6PM%2BCbsf%2Fzj2DwI8JXGKyOm0jAMpNr8wz7n1gLoFnB5WHe4ELHpBfnAh%2Fe5r1H62n0y4eT%2B19zNuNZFd7jjr1FYgounceibjgvlGILMN3xhQWpjzUgssL3GprTM%2FCFy3FzxfPnjUcgJJ%2BjAJw9AICH2yCkFiY6IglFzQwzK%2BC5Q7HvEYmStt682IvQg6ZdYoWuH7iPf7ypiMB%2Bd4o2LwnJ67xCVitD0oLxFMYgIub4buB0dlSwy%2FskcERt81xlhWIZhxRYEDxyTtMPwYSRu5El7vvui5W9y0AmLBANjAb4EaFcaOqUIFOlF6JO%2Blt4Jc6LyMzFu3zdOd9Nx7%2Fi6AewgDDN97P2BTrqAdX%2BqmMi8oItlqJdoU9ntWJ2SBR6y2xa%2BCj3GpHLzvrvWMYAQPfcOxXqDYv9UPPAsPPh1Hxl1P0Jua%2BBwmwOA4m9Lak%2BkwqL8oQMUMb68pyRNxv8dTFa1turFetE9%2Bh4NTzHfxH5WhXH58oGt5ozzPmeJmuJrMAJJV%2BMZhdL1eClkK%2FzLKfSboJIgqmvMSXncccSmEc3Ref6qGWXN3k3%2F5YLf4831zEGH%2FUKCnQqU%2F45QVHvPOfuw2%2BIsItIYimn8YRW73TMOpp3frhKVYMiEwhVBNFQESjNLzDfBZgIMKeWjUbHmJT4Cwb82w%3D%3D&X-Amz-Signature=0757be785f81856477277969af21d8076289d4bb92274c42c73b8d2776443763 |


### 32. cb-eedr-file-paths
---
Return a summary of the observed file paths
##### Required Permissions
RBAC Permissions Required - RBAC Permissions Required: READ
##### Base Command

`cb-eedr-file-paths`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The requested SHA256 hash to obtain information for. Supports comma-separated values. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.File.file_path_count | Number | The total number of unique file paths that have been observed, by this organization, for this file. | 
| CarbonBlackEEDR.File.file_paths | String | The file path details. | 
| CarbonBlackEEDR.File.sha256 | Unknown | The SHA256 hash of the file. | 
| CarbonBlackEEDR.File.total_file_path_count | Number | The total number of file paths that have been observed, by this organization, for this file. | 


##### Command Example
```!cb-eedr-file-paths sha256="4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa"```

##### Context Example
```
{
    "CarbonBlackEEDR.File": {
        "sha256": "4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa", 
        "file_paths": [
            {
                "count": 3, 
                "file_path": "c:\\program files\\admin\\test.exe", 
                "first_seen_timestamp": "2020-05-18T09:26:28.205254Z"
            }
        ], 
        "total_file_path_count": 3, 
        "file_path_count": 1
    }
}
```

##### Human Readable Output
### The file path for the sha256
|file_path_count|file_paths|sha256|total_file_path_count|
|---|---|---|---|
| 1 | {'count': 3, 'file_path': 'c:\\program files\\admin\\test.exe', 'first_seen_timestamp': '2020-05-18T09:26:28.205254Z'} | 4a714d98ce40f5f1234c306a66cb4a6b1ff3fd01047c7f4581f8558f0bcdf5fa | 3 |

### 33. cb-eedr-process-search
---
Creates a process search job.
##### Required Permissions
RBAC Permissions Required - org.search.events: CREATE

#### Base Command

`cb-eedr-process-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_name | The process name to search. | Optional | 
| process_hash | The process hash to search. | Optional | 
| event_id | The event ID to search. | Optional | 
| limit | The maximum number of rows to return. Default is 20. | Optional | 
| query | A free-style query. For example, "process_name:svchost.exe". | Optional | 
| start_time | First appearance time range (&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes). Default is 1 day ago. | Optional | 
| end_time | Last appearance time range (&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes). Default is current time. | Optional | 
| start | Index of first records to fetch. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.SearchProcess.job_id | String | The ID of the job found by the search. | 
| CarbonBlackEEDR.SearchProcess.status | String | The status of the job found by the search. | 


#### Command Example
```!cb-eedr-process-search process_name="vmtoolsd.exe" limit=10```

#### Context Example
```json
{
    "CarbonBlackEEDR": {
        "SearchProcess": {
            "job_id": "633b7900-2b28-456d-add3-28e665525753",
            "status": "In Progress"
        }
    }
}
```

#### Human Readable Output

>job_id is 633b7900-2b28-456d-add3-28e665525753.

### 34. cb-eedr-events-by-process-get
---
Retrieves the events associated with a given process.

##### Required Permissions
RBAC Permissions Required - org.search.events: READ
#### Base Command

`cb-eedr-events-by-process-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_guid | The process GUID to search. | Optional | 
| event_type | The event type to search. | Optional | 
| limit | The maximum number of rows to return. Default is 20. | Optional | 
| query | A free-style query. For example, "process_name:svchost.exe". | Optional | 
| start_time | First appearance time range (&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes). Default is 1 day ago. | Optional | 
| end_time | Last appearance time range (&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes). Default is current time. | Optional | 
| start | Index of first records to fetch. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.SearchEvent.backend_timestamp | Date | The timestamp of when the process was ingested by the backend. | 
| CarbonBlackEEDR.SearchEvent.created_timestamp | Date | The timestamp of when the event document was created. | 
| CarbonBlackEEDR.SearchEvent.event_guid | String | A globally unique identifier for this event document. | 
| CarbonBlackEEDR.SearchEvent.event_hash | String |  | 
| CarbonBlackEEDR.SearchEvent.event_timestamp | Date | The timestamp of the event on the device. | 
| CarbonBlackEEDR.SearchEvent.event_type | String | The event type. Possible values are: filemod, netconn, regmod, modload, crossproc, and childproc. | 
| CarbonBlackEEDR.SearchEvent.legacy | Boolean | True if this event comes from the CBD data stream. | 
| CarbonBlackEEDR.SearchEvent.modload_action | String | Action associated with the modload operation. The only possible value is: ACTION_LOAD_MODULE. | 
| CarbonBlackEEDR.SearchEvent.modload_effective_reputation | String |  | 
| CarbonBlackEEDR.SearchEvent.modload_md5 | String | The MD5 hash for the modules loaded. | 
| CarbonBlackEEDR.SearchEvent.modload_name | String | The modules loaded by this event. | 
| CarbonBlackEEDR.SearchEvent.modload_publisher | String | The publisher that signed this module, if any. | 
| CarbonBlackEEDR.SearchEvent.modload_publisher_state | String | The set of states associated with the publisher of the module. Can be a combination of: FILE_SIGNATURE_STATE_INVALID, FILE_SIGNATURE_STATE_SIGNED, FILE_SIGNATURE_STATE_VERIFIED, FILE_SIGNATURE_STATE_NOT_SIGNED, FILE_SIGNATURE_STATE_UNKNOWN, FILE_SIGNATURE_STATE_CHAINED, FILE_SIGNATURE_STATE_TRUSTED, FILE_SIGNATURE_STATE_OS, and FILE_SIGNATURE_STATE_CATALOG_SIGNED. | 
| CarbonBlackEEDR.SearchEvent.modload_sha256 | String | The SHA256 hash for the modules loaded. | 
| CarbonBlackEEDR.SearchEvent.process_guid | String | The process GUID representing the process that this event belongs to. | 
| CarbonBlackEEDR.SearchEvent.process_pid | Number | The PID of the process. | 


#### Command Example
```!cb-eedr-events-by-process-get process_guid="7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43" event_type="modload" start_time="1 month"```

#### Context Example
```json
{
    "CarbonBlackEEDR": {
        "SearchEvent": [
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.503Z",
                "event_guid": "OCaEtLR1SRGcWgVUcoj2mA",
                "event_hash": "lQJi__dhQpGzdVwCmbdbjg",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_LOCAL_WHITE",
                "modload_md5": "aae1f614bfe5e3e5cde18d1f928f5b12",
                "modload_name": "c:\\windows\\system32\\ctiuser.dll",
                "modload_publisher": "Carbon Black, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "81eb5f6fbf8d7566560f43f75ec30e5f0284cdee9b5c9df0d81281bda0db3d07",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "aAVFrvjPQ3Sea-kK6Kdbxw",
                "event_hash": "L8CCeipjQ7KtMQDiRwx8HA",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "2c7c14627cff3384c52e61d4dbd0ecc3",
                "modload_name": "c:\\windows\\system32\\version.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "41b4d85d84a86e41b948694b9b5f398a0d79f47629d6d969eb5b461d4f5d0347",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "AlKrjPvcSLav4Vq7zBuD2A",
                "event_hash": "k7Z5u-3_Siydt1DPvXW4dQ",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "f7c09099232987cbb965b9280c1dacf8",
                "modload_name": "c:\\program files\\vmware\\vmware tools\\gmodule-2.0.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "d14560487312f487f94bfaed4fe9d0cfd5efbec1ac4ef44c26dd230800bc6b29",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "0g6iOKO9S8GHIfFSOG5sBA",
                "event_hash": "TX8Ehlc2Qb2mbSl8ZtVmgg",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "26fc0a369a68d2a429e2ebe67b8dd1d8",
                "modload_name": "c:\\program files\\vmware\\vmware tools\\gobject-2.0.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "9a914642e7e8e4e4ba004004b490c64453f13597cc43cb77a9e55d180c229f83",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "W_JoluvFTni9mPPHCvyxmg",
                "event_hash": "CvjnmQdWQqGhbsmkcPzJYA",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "9d9b1790cc6eeb76757b5042914b7289",
                "modload_name": "c:\\program files\\vmware\\vmware tools\\intl.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "03eef80ad1d4b066c4842546ba52ccb911e84606a27f0ec7016d9f62c572846b",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "-XTVyKT5SkeJ0PvsnozF6A",
                "event_hash": "114rbukXQKSzjhiVBEApPQ",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "a83fcd02a532a08386a5bcbb39a581c5",
                "modload_name": "c:\\program files\\vmware\\vmware tools\\glib-2.0.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "ff9bb3a84c807f8151d4956f895f672fa812765e931e9093f40caab0853bd120",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "junO0BiIT9imVAUSKCdB_A",
                "event_hash": "9Sd5fEA8R9aOU7eYlY_97A",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "9f2b3fac3440db16e0c13473b551d12c",
                "modload_name": "c:\\windows\\system32\\vcruntime140.dll",
                "modload_publisher": "Microsoft Corporation",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "27c51ff3dc2f4cf2b61bdf55fb60148ef0abb06c2feae188c30f1a63f9e29caa",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "PocoJ9OATG6Qr-3cirRciQ",
                "event_hash": "D8k62OqkQ9KiT0c5C1Ki0g",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "965eb822d0ef8fda78ccb1f41def093d",
                "modload_name": "c:\\windows\\system32\\winmm.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "ad43d686930eae0f57a55ee75d10bd1882747089a291371ffe1e131eb5f76938",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "ThWF8yD5R5usoFJM4x_VRw",
                "event_hash": "mk9Lj4O0TAq-enCNCKWBMA",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "e6450257ba3df5161684e4c73ebb8f92",
                "modload_name": "c:\\windows\\system32\\winmmbase.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "948f13fe144cd80f93565ded2ac2e96d000869bb2761538996d28942495cb1d7",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "PZXgTx_XStWA1DGUkPDJzw",
                "event_hash": "UVssy5LWSvyvFC0Isya8aQ",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "821236519995fdfb54b56bd9d7a60ba8",
                "modload_name": "c:\\program files\\vmware\\vmware tools\\pcre.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "64388ee3beb0e69fd471b3c7eb5d4de8ae24b9ea0fdba51bc9c81c26be84e585",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "bmsH73bASGaRFpeo84Q5Kw",
                "event_hash": "9Ri-_u68QjyV7UjSMeDAYw",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "40b92f37c0698cdc4cde8c0a75791c7e",
                "modload_name": "c:\\program files\\vmware\\vmware tools\\vmtools.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "bb8098f4627441f6a29c31757c45339c74b2712b92783173df9ab58d47ae3bfa",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "WeL1uj4FSI-n4rVA7UoXFw",
                "event_hash": "b2SKdGkNSNuw0eoZn9wK_g",
                "event_timestamp": "2020-10-14T16:17:45.448Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "e202dd92848c5103c9abf8ecd22bc539",
                "modload_name": "c:\\windows\\system32\\fltlib.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "353f8d4e647a11f235f4262d913f7bac4c4f266eac4601ea416e861afd611912",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "Q6PB6SqURW6xliJdsEogag",
                "event_hash": "YPhofHOyQkKaMGEr1dX5cQ",
                "event_timestamp": "2020-10-14T16:17:45.463Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "b7be84c53e81dd0a64ee0845410bd6c7",
                "modload_name": "c:\\windows\\system32\\icmp.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_CATALOG_SIGNED",
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "8ddd1ddce37c7e560570774de7ca1a1ecf7b32dfd0ba014f504fc6ae50388de6",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "jg_1LLAYT1KZx9SZUPQqeQ",
                "event_hash": "5eb6xzwkTt2p5b-2-ELzog",
                "event_timestamp": "2020-10-14T16:17:45.463Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "3929147a2a34b0902152c7d0f241b02a",
                "modload_name": "c:\\windows\\system32\\iphlpapi.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "ad1c5309aa873f6a284eabe382812868e20c3d3d64197f3e6ef9d015ea060caa",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "LDC8YHy4RFuIZuejh202dQ",
                "event_hash": "zMI8yTZvRBWnBzcuyUU0bQ",
                "event_timestamp": "2020-10-14T16:17:45.463Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "da9647c845792371dd2f95e1ccc9a63a",
                "modload_name": "c:\\windows\\system32\\sspicli.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "fe741d2f986b0b9557a90bdf0560f49cd17381d1094c42a91634aabe49f46a1e",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "Oq1ZHJ-lSYGWynDM12vIhQ",
                "event_hash": "HwnoQEtpSp-El_7fEmh4Lw",
                "event_timestamp": "2020-10-14T16:17:45.463Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "435009d1ddc0365bfa34b8c8d3f85286",
                "modload_name": "c:\\windows\\system32\\ntmarta.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "2f94628f056fe65ea81351e134e59ece813fec5e8400c12d6dfa49defd126d01",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "UpxEQukRRmiX3EjI4kkYYg",
                "event_hash": "afxpRq5BT6WRdQyBWS4-kQ",
                "event_timestamp": "2020-10-14T16:17:45.463Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "3c9d22cae173ad19806b6a016cd4cc28",
                "modload_name": "c:\\windows\\system32\\uxtheme.dll",
                "modload_publisher": "Microsoft Windows",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_CATALOG_SIGNED",
                    "FILE_SIGNATURE_STATE_OS",
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "d95e7d07ea46d7d2aefa01cd0a64cf266be26d40fa6be42f7cf60f6deb8fbaf3",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "NcXdQS34QJWySTn-04pakA",
                "event_hash": "4ZyNSN7yRyeNNBRop-HMDw",
                "event_timestamp": "2020-10-14T16:17:45.463Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "1f1fe19bc54c75e568646327f6d99c1a",
                "modload_name": "c:\\windows\\system32\\vsocklib.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "e685439d50aecf656ef5bd2523568b6d9220cc9917e7d57eda962c1a520e94a5",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "POYLqKCERASiTMBHcfsFmw",
                "event_hash": "UAoluLSYSKe2pzn47rxVDw",
                "event_timestamp": "2020-10-14T16:17:45.463Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "b56c118a906a0322b9319d50df188bc6",
                "modload_name": "c:\\program files\\vmware\\vmware tools\\plugins\\common\\hgfsserver.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "0d74d8f4cf24bc72042234fb92b42396f6d2f6f77c534f9a07af3d82822a0452",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            },
            {
                "backend_timestamp": "2020-10-14T16:22:13.180Z",
                "created_timestamp": "2020-11-04T06:58:51.505Z",
                "event_guid": "x2Beg9ykSIiRKViJJxcsaA",
                "event_hash": "6xUCWyDQTAuOm7Lnxq-qew",
                "event_timestamp": "2020-10-14T16:17:45.463Z",
                "event_type": "modload",
                "legacy": false,
                "modload_action": "ACTION_LOADED_MODULE_DISCOVERED",
                "modload_effective_reputation": "REP_WHITE",
                "modload_md5": "a381226b5a088a07680391b94c474baa",
                "modload_name": "c:\\program files\\vmware\\vmware tools\\hgfs.dll",
                "modload_publisher": "VMware, Inc.",
                "modload_publisher_state": [
                    "FILE_SIGNATURE_STATE_SIGNED",
                    "FILE_SIGNATURE_STATE_TRUSTED",
                    "FILE_SIGNATURE_STATE_VERIFIED"
                ],
                "modload_sha256": "429a69aba0196be3f53ffa1d2dd09b0caea6fc680468706b2a20fa0f7188ad4b",
                "process_guid": "7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43",
                "process_pid": 8056
            }
        ]
    }
}
```

#### Human Readable Output

>### Results Found.
>|backend_timestamp|created_timestamp|event_guid|event_hash|event_timestamp|event_type|legacy|modload_action|modload_effective_reputation|modload_md5|modload_name|modload_publisher|modload_publisher_state|modload_sha256|process_guid|process_pid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.503Z | OCaEtLR1SRGcWgVUcoj2mA | lQJi__dhQpGzdVwCmbdbjg | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_LOCAL_WHITE | aae1f614bfe5e3e5cde18d1f928f5b12 | c:\windows\system32\ctiuser.dll | Carbon Black, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 81eb5f6fbf8d7566560f43f75ec30e5f0284cdee9b5c9df0d81281bda0db3d07 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | aAVFrvjPQ3Sea-kK6Kdbxw | L8CCeipjQ7KtMQDiRwx8HA | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 2c7c14627cff3384c52e61d4dbd0ecc3 | c:\windows\system32\version.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 41b4d85d84a86e41b948694b9b5f398a0d79f47629d6d969eb5b461d4f5d0347 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | AlKrjPvcSLav4Vq7zBuD2A | k7Z5u-3_Siydt1DPvXW4dQ | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | f7c09099232987cbb965b9280c1dacf8 | c:\program files\vmware\vmware tools\gmodule-2.0.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | d14560487312f487f94bfaed4fe9d0cfd5efbec1ac4ef44c26dd230800bc6b29 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | 0g6iOKO9S8GHIfFSOG5sBA | TX8Ehlc2Qb2mbSl8ZtVmgg | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 26fc0a369a68d2a429e2ebe67b8dd1d8 | c:\program files\vmware\vmware tools\gobject-2.0.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 9a914642e7e8e4e4ba004004b490c64453f13597cc43cb77a9e55d180c229f83 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | W_JoluvFTni9mPPHCvyxmg | CvjnmQdWQqGhbsmkcPzJYA | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 9d9b1790cc6eeb76757b5042914b7289 | c:\program files\vmware\vmware tools\intl.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 03eef80ad1d4b066c4842546ba52ccb911e84606a27f0ec7016d9f62c572846b | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | -XTVyKT5SkeJ0PvsnozF6A | 114rbukXQKSzjhiVBEApPQ | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | a83fcd02a532a08386a5bcbb39a581c5 | c:\program files\vmware\vmware tools\glib-2.0.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | ff9bb3a84c807f8151d4956f895f672fa812765e931e9093f40caab0853bd120 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | junO0BiIT9imVAUSKCdB_A | 9Sd5fEA8R9aOU7eYlY_97A | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 9f2b3fac3440db16e0c13473b551d12c | c:\windows\system32\vcruntime140.dll | Microsoft Corporation | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 27c51ff3dc2f4cf2b61bdf55fb60148ef0abb06c2feae188c30f1a63f9e29caa | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | PocoJ9OATG6Qr-3cirRciQ | D8k62OqkQ9KiT0c5C1Ki0g | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 965eb822d0ef8fda78ccb1f41def093d | c:\windows\system32\winmm.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | ad43d686930eae0f57a55ee75d10bd1882747089a291371ffe1e131eb5f76938 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | ThWF8yD5R5usoFJM4x_VRw | mk9Lj4O0TAq-enCNCKWBMA | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | e6450257ba3df5161684e4c73ebb8f92 | c:\windows\system32\winmmbase.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 948f13fe144cd80f93565ded2ac2e96d000869bb2761538996d28942495cb1d7 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | PZXgTx_XStWA1DGUkPDJzw | UVssy5LWSvyvFC0Isya8aQ | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 821236519995fdfb54b56bd9d7a60ba8 | c:\program files\vmware\vmware tools\pcre.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 64388ee3beb0e69fd471b3c7eb5d4de8ae24b9ea0fdba51bc9c81c26be84e585 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | bmsH73bASGaRFpeo84Q5Kw | 9Ri-_u68QjyV7UjSMeDAYw | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 40b92f37c0698cdc4cde8c0a75791c7e | c:\program files\vmware\vmware tools\vmtools.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | bb8098f4627441f6a29c31757c45339c74b2712b92783173df9ab58d47ae3bfa | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | WeL1uj4FSI-n4rVA7UoXFw | b2SKdGkNSNuw0eoZn9wK_g | 2020-10-14T16:17:45.448Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | e202dd92848c5103c9abf8ecd22bc539 | c:\windows\system32\fltlib.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 353f8d4e647a11f235f4262d913f7bac4c4f266eac4601ea416e861afd611912 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | Q6PB6SqURW6xliJdsEogag | YPhofHOyQkKaMGEr1dX5cQ | 2020-10-14T16:17:45.463Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | b7be84c53e81dd0a64ee0845410bd6c7 | c:\windows\system32\icmp.dll | Microsoft Windows | FILE_SIGNATURE_STATE_CATALOG_SIGNED,<br/>FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 8ddd1ddce37c7e560570774de7ca1a1ecf7b32dfd0ba014f504fc6ae50388de6 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | jg_1LLAYT1KZx9SZUPQqeQ | 5eb6xzwkTt2p5b-2-ELzog | 2020-10-14T16:17:45.463Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 3929147a2a34b0902152c7d0f241b02a | c:\windows\system32\iphlpapi.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | ad1c5309aa873f6a284eabe382812868e20c3d3d64197f3e6ef9d015ea060caa | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | LDC8YHy4RFuIZuejh202dQ | zMI8yTZvRBWnBzcuyUU0bQ | 2020-10-14T16:17:45.463Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | da9647c845792371dd2f95e1ccc9a63a | c:\windows\system32\sspicli.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | fe741d2f986b0b9557a90bdf0560f49cd17381d1094c42a91634aabe49f46a1e | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | Oq1ZHJ-lSYGWynDM12vIhQ | HwnoQEtpSp-El_7fEmh4Lw | 2020-10-14T16:17:45.463Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 435009d1ddc0365bfa34b8c8d3f85286 | c:\windows\system32\ntmarta.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 2f94628f056fe65ea81351e134e59ece813fec5e8400c12d6dfa49defd126d01 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | UpxEQukRRmiX3EjI4kkYYg | afxpRq5BT6WRdQyBWS4-kQ | 2020-10-14T16:17:45.463Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 3c9d22cae173ad19806b6a016cd4cc28 | c:\windows\system32\uxtheme.dll | Microsoft Windows | FILE_SIGNATURE_STATE_CATALOG_SIGNED,<br/>FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | d95e7d07ea46d7d2aefa01cd0a64cf266be26d40fa6be42f7cf60f6deb8fbaf3 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | NcXdQS34QJWySTn-04pakA | 4ZyNSN7yRyeNNBRop-HMDw | 2020-10-14T16:17:45.463Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 1f1fe19bc54c75e568646327f6d99c1a | c:\windows\system32\vsocklib.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | e685439d50aecf656ef5bd2523568b6d9220cc9917e7d57eda962c1a520e94a5 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | POYLqKCERASiTMBHcfsFmw | UAoluLSYSKe2pzn47rxVDw | 2020-10-14T16:17:45.463Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | b56c118a906a0322b9319d50df188bc6 | c:\program files\vmware\vmware tools\plugins\common\hgfsserver.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 0d74d8f4cf24bc72042234fb92b42396f6d2f6f77c534f9a07af3d82822a0452 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-14T16:22:13.180Z | 2020-11-04T06:58:51.505Z | x2Beg9ykSIiRKViJJxcsaA | 6xUCWyDQTAuOm7Lnxq-qew | 2020-10-14T16:17:45.463Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | a381226b5a088a07680391b94c474baa | c:\program files\vmware\vmware tools\hgfs.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 429a69aba0196be3f53ffa1d2dd09b0caea6fc680468706b2a20fa0f7188ad4b | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>Total of 2120 items found. Showing items 0 - 19.

### 35. cb-eedr-process-search-results
---
Retrieves the process search results for a given job ID.

##### Required Permissions
RBAC Permissions Required - org.search.events: READ
#### Base Command

`cb-eedr-process-search-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | The job ID to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.SearchProcess.job_id | String | The ID of the job found by the search. | 
| CarbonBlackEEDR.SearchProcess.status | String | The status of the job found by the search. | 
| CarbonBlackEEDR.SearchProcess.results.device_id | Number | The device ID that is guaranteed to be unique within each PSC environment. | 
| CarbonBlackEEDR.SearchProcess.results.process_username | String | The user names related to the process. | 
| CarbonBlackEEDR.SearchProcess.results.backend_timestamp | Date | A date/time field formatted as an ISO-8601 string based on the UTC timezone. For example, device_timestamp:2018-03-14T21:06:45.183Z. | 
| CarbonBlackEEDR.SearchProcess.results.childproc_count | Number | The cumulative count of child-process creations since process tracking started. | 
| CarbonBlackEEDR.SearchProcess.results.crossproc_count | Number | The cumulative count of cross-process events since process tracking started. | 
| CarbonBlackEEDR.SearchProcess.results.device_group_id | Number | The ID of the sensor group where the device belongs. | 
| CarbonBlackEEDR.SearchProcess.results.device_name | String | The name of the device. | 
| CarbonBlackEEDR.SearchProcess.results.device_policy_id | Number | The ID of the policy applied to the device. | 
| CarbonBlackEEDR.SearchProcess.results.device_timestamp | Date | The time displayed on the sensor based on the sensor’s clock. The time is an ISO-8601 formatted time string based on the UTC timezone. | 
| CarbonBlackEEDR.SearchProcess.results.enriched | Boolean | True if the process document came from the CBD data stream. | 
| CarbonBlackEEDR.SearchProcess.results.enriched_event_type | String | The CBD enriched event type. | 
| CarbonBlackEEDR.SearchProcess.results.event_type | String | The CBD event type \(valid only for events coming through analytics\). Possible values are: CREATE_PROCESS, DATA_ACCESS, FILE_CREATE, INJECT_CODE, NETWORK, POLICY_ACTION, REGISTRY_ACCESS, and SYSTEM_API_CALL. | 
| CarbonBlackEEDR.SearchProcess.results.filemod_count | Number | The cumulative count of file modifications since process tracking started. | 
| CarbonBlackEEDR.SearchProcess.results.ingress_time | Date | Unknown | 
| CarbonBlackEEDR.SearchProcess.results.legacy | Boolean | True if the process document came from the legacy data stream \(deprecated, use enriched\). | 
| CarbonBlackEEDR.SearchProcess.results.modload_count | Number | The cumulative count of module loads since process tracking started. | 
| CarbonBlackEEDR.SearchProcess.results.netconn_count | Number | The cumulative count of network connections since process tracking started. | 
| CarbonBlackEEDR.SearchProcess.results.org_id | String | The globally unique organization key. This will most likely be the PSC organization ID \+ PSC environment ID or some other unique token used across environments. | 
| CarbonBlackEEDR.SearchProcess.results.parent_guid | String | The process GUID of the parent process. | 
| CarbonBlackEEDR.SearchProcess.results.parent_pid | Number | The PID of the parent process. | 
| CarbonBlackEEDR.SearchProcess.results.process_guid | String | Unique ID of the solr document. Appears as process_guid \+ server-side timestamp in epoch ms \(1/1/1970 based\). | 
| CarbonBlackEEDR.SearchProcess.results.process_hash | String | The MD5 and SHA-256 hashes of the process’s main module in a multi-valued field. | 
| CarbonBlackEEDR.SearchProcess.results.process_name | String | The tokenized file path of the process’s main module. | 
| CarbonBlackEEDR.SearchProcess.results.process_pid | Number | The PID of a process. Can be multi-valued in case of exec/fork on Linux/OSX. | 
| CarbonBlackEEDR.SearchProcess.results.process_username | String | User names related to the process. | 
| CarbonBlackEEDR.SearchProcess.results.regmod_count | Number | The cumulative count of registry modifications since process tracking started. | 
| CarbonBlackEEDR.SearchProcess.results.scriptload_count | Number | The cumulative count of loaded scripts since process tracking started. | 


#### Command Example
```!cb-eedr-process-search-results job_id="99aad740-3903-4148-a5e7-7b5648794862"```

#### Context Example
```json
{
    "CarbonBlackEEDR": {
        "SearchProcess": {
            "job_id": "99aad740-3903-4148-a5e7-7b5648794862",
            "results": [
                {
                    "backend_timestamp": "2020-10-28T07:20:55.988Z",
                    "device_group_id": 0,
                    "device_id": 3775337,
                    "device_name": "cbcloud-win10",
                    "device_policy_id": 12229,
                    "device_timestamp": "2020-10-28T07:20:07.603Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "INJECT_CODE"
                    ],
                    "event_type": [
                        "crossproc"
                    ],
                    "ingress_time": 1603869624380,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-00399b69-0000028c-00000000-1d6a6bb3b2bcc26",
                    "parent_pid": 652,
                    "process_guid": "7DESJ9GN-00399b69-00000b60-00000000-1d6a6bb41ebd8ef",
                    "process_hash": [
                        "1169495860abe1bc6a498d2c196787c3",
                        "fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        2912
                    ]
                },
                {
                    "backend_timestamp": "2020-10-27T14:47:52.717Z",
                    "device_group_id": 0,
                    "device_id": 3739267,
                    "device_name": "hw-host-027",
                    "device_policy_id": 12229,
                    "device_timestamp": "2020-10-27T14:47:13.760Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "INJECT_CODE"
                    ],
                    "event_type": [
                        "crossproc"
                    ],
                    "ingress_time": 1603810047142,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-00390e83-000002a0-00000000-1d6a1f9ef3c0d3e",
                    "parent_pid": 672,
                    "process_guid": "7DESJ9GN-00390e83-00000bf4-00000000-1d6a1f9f37d1836",
                    "process_hash": [
                        "1169495860abe1bc6a498d2c196787c3",
                        "fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        3060
                    ],
                    "process_username": [
                        "NT AUTHORITY\\SYSTEM"
                    ]
                },
                {
                    "backend_timestamp": "2020-10-24T00:58:50.495Z",
                    "device_group_id": 0,
                    "device_id": 3739232,
                    "device_name": "hw-host-004",
                    "device_policy_id": 12229,
                    "device_timestamp": "2020-10-24T00:57:37.097Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "INJECT_CODE"
                    ],
                    "event_type": [
                        "crossproc"
                    ],
                    "ingress_time": 1603501093672,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-00390e60-000002a4-00000000-1d6a463297ebe9b",
                    "parent_pid": 676,
                    "process_guid": "7DESJ9GN-00390e60-00000c74-00000000-1d6a4632cda86e3",
                    "process_hash": [
                        "1169495860abe1bc6a498d2c196787c3",
                        "fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        3188
                    ]
                },
                {
                    "backend_timestamp": "2020-10-17T14:13:34.936Z",
                    "device_group_id": 0,
                    "device_id": 3462642,
                    "device_name": "win10etchangeme",
                    "device_policy_id": 6525,
                    "device_timestamp": "2020-10-17T14:12:28.438Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "INJECT_CODE"
                    ],
                    "event_type": [
                        "crossproc"
                    ],
                    "ingress_time": 1602943969760,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-0034d5f2-0000032c-00000000-1d6a276fc5ed489",
                    "parent_pid": 812,
                    "process_guid": "7DESJ9GN-0034d5f2-00000b8c-00000000-1d6a27706e318a2",
                    "process_hash": [
                        "63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6",
                        "c7084336325dc8eadfb1e8ff876921c4"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        2956
                    ],
                    "process_username": [
                        "NT AUTHORITY\\SYSTEM"
                    ]
                },
                {
                    "backend_timestamp": "2020-10-16T00:36:49.055Z",
                    "device_group_id": 0,
                    "device_id": 3216323,
                    "device_name": "exapil\\pil-cb7-2",
                    "device_policy_id": 6525,
                    "device_timestamp": "2020-10-16T00:35:55.328Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "INJECT_CODE"
                    ],
                    "event_type": [
                        "crossproc"
                    ],
                    "ingress_time": 1602808577528,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-003113c3-00000204-00000000-1d68d438b085325",
                    "parent_pid": 516,
                    "process_guid": "7DESJ9GN-003113c3-00000628-00000000-1d68d438ca1bfd4",
                    "process_hash": [
                        "63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6",
                        "c7084336325dc8eadfb1e8ff876921c4"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        1576
                    ],
                    "process_username": [
                        "NT AUTHORITY\\SYSTEM"
                    ]
                },
                {
                    "backend_timestamp": "2020-10-05T02:17:33.365Z",
                    "device_group_id": 0,
                    "device_id": 3365471,
                    "device_name": "hw-host-004",
                    "device_policy_id": 6525,
                    "device_timestamp": "2020-10-05T02:16:18.531Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "INJECT_CODE"
                    ],
                    "event_type": [
                        "crossproc"
                    ],
                    "ingress_time": 1601864215004,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-00335a5f-00000288-00000000-1d687d4d1d5aec5",
                    "parent_pid": 648,
                    "process_guid": "7DESJ9GN-00335a5f-00000abc-00000000-1d687d4d6c9363a",
                    "process_hash": [
                        "1169495860abe1bc6a498d2c196787c3",
                        "fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        2748
                    ],
                    "process_username": [
                        "NT AUTHORITY\\SYSTEM"
                    ]
                },
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "null/AIUNTEPE"
                    ],
                    "backend_timestamp": "2020-09-03T11:00:49.482Z",
                    "device_group_id": 791,
                    "device_id": 3670727,
                    "device_name": "desktop-fvb88fs",
                    "device_policy_id": 6525,
                    "device_timestamp": "2020-09-03T10:59:48.345Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "CREATE_PROCESS"
                    ],
                    "event_type": [
                        "childproc"
                    ],
                    "ingress_time": 1599130817870,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-003802c7-000002b8-00000000-1d66fbac06780a2",
                    "parent_pid": 696,
                    "process_guid": "7DESJ9GN-003802c7-00000b4c-00000000-1d66fbac0f8ad57",
                    "process_hash": [
                        "aca121d48147ff717bcd1da7871a5a76",
                        "da7e37ce59685964a3876ef1747964de1caabd13b3691b6a1d5ebed1d19c19ad"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        2892
                    ],
                    "process_username": [
                        "NT AUTHORITY\\SYSTEM"
                    ]
                },
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "null/UQJ5NT2N"
                    ],
                    "backend_timestamp": "2020-09-03T08:01:52.493Z",
                    "device_group_id": 791,
                    "device_id": 3670528,
                    "device_name": "desktop-fvb88fs",
                    "device_policy_id": 6525,
                    "device_timestamp": "2020-09-03T08:00:46.548Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "CREATE_PROCESS"
                    ],
                    "event_type": [
                        "childproc"
                    ],
                    "ingress_time": 1599120076739,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-00380200-000002b8-00000000-1d66fbac06780a2",
                    "parent_pid": 696,
                    "process_guid": "7DESJ9GN-00380200-00000b4c-00000000-1d66fbac0f8ad57",
                    "process_hash": [
                        "aca121d48147ff717bcd1da7871a5a76",
                        "da7e37ce59685964a3876ef1747964de1caabd13b3691b6a1d5ebed1d19c19ad"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        2892
                    ],
                    "process_username": [
                        "NT AUTHORITY\\SYSTEM"
                    ]
                },
                {
                    "alert_category": [
                        "THREAT"
                    ],
                    "alert_id": [
                        "JMLXDNLG/XPU6S91H"
                    ],
                    "backend_timestamp": "2020-08-26T16:08:11.872Z",
                    "device_group_id": 0,
                    "device_id": 3644148,
                    "device_name": "desktop-aa2m6ld",
                    "device_policy_id": 6529,
                    "device_timestamp": "2020-08-26T16:06:50.813Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "FILE_CREATE"
                    ],
                    "event_type": [
                        "filemod"
                    ],
                    "ingress_time": 1598458053780,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-00379af4-00001520-00000000-1d67a883dbd713b",
                    "parent_pid": 5408,
                    "process_guid": "7DESJ9GN-00379af4-000007e0-00000000-1d67a8847cebcbd",
                    "process_hash": [
                        "80abd555c1869baaff2d8a8d535ce07e",
                        "fa353f142361e5c6ca57a66dcb341bba20392f5c29d2c113c7d62a216b0e0504"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        2016
                    ],
                    "process_username": [
                        "DESKTOP-AA2M6LD\\John Doe"
                    ]
                },
                {
                    "backend_timestamp": "2020-08-17T14:38:21.589Z",
                    "blocked_hash": [
                        "908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53"
                    ],
                    "device_group_id": 0,
                    "device_id": 3600261,
                    "device_name": "desktop-aa2m6ld",
                    "device_policy_id": 35704,
                    "device_timestamp": "2020-08-17T14:37:19.963Z",
                    "enriched": true,
                    "enriched_event_type": [
                        "POLICY_ACTION"
                    ],
                    "event_type": [
                        "childproc"
                    ],
                    "ingress_time": 1597675083480,
                    "legacy": true,
                    "org_id": "7DESJ9GN",
                    "parent_guid": "7DESJ9GN-0036ef85-000007f0-00000000-1d674a3d9a6a335",
                    "parent_pid": 2032,
                    "process_guid": "7DESJ9GN-0036ef85-00001f74-00000000-1d674a3e4b3ba9a",
                    "process_hash": [
                        "80abd555c1869baaff2d8a8d535ce07e",
                        "fa353f142361e5c6ca57a66dcb341bba20392f5c29d2c113c7d62a216b0e0504"
                    ],
                    "process_name": "c:\\program files\\vmware\\vmware tools\\vmtoolsd.exe",
                    "process_pid": [
                        8052
                    ],
                    "process_username": [
                        "DESKTOP-AA2M6LD\\John Doe"
                    ],
                    "sensor_action": [
                        "DENY",
                        "BLOCK"
                    ]
                }
            ],
            "status": "Completed"
        }
    }
}
```

#### Human Readable Output

>### Completed Search Results:
>|process_hash|process_name|device_name|device_timestamp|process_pid|process_username|
>|---|---|---|---|---|---|
>| 1169495860abe1bc6a498d2c196787c3,<br/>fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9 | c:\program files\vmware\vmware tools\vmtoolsd.exe | cbcloud-win10 | 2020-10-28T07:20:07.603Z | 2912 |  |
>| 1169495860abe1bc6a498d2c196787c3,<br/>fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9 | c:\program files\vmware\vmware tools\vmtoolsd.exe | hw-host-027 | 2020-10-27T14:47:13.760Z | 3060 | NT AUTHORITY\SYSTEM |
>| 1169495860abe1bc6a498d2c196787c3,<br/>fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9 | c:\program files\vmware\vmware tools\vmtoolsd.exe | hw-host-004 | 2020-10-24T00:57:37.097Z | 3188 |  |
>| 63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6,<br/>c7084336325dc8eadfb1e8ff876921c4 | c:\program files\vmware\vmware tools\vmtoolsd.exe | win10etchangeme | 2020-10-17T14:12:28.438Z | 2956 | NT AUTHORITY\SYSTEM |
>| 63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6,<br/>c7084336325dc8eadfb1e8ff876921c4 | c:\program files\vmware\vmware tools\vmtoolsd.exe | exapil\pil-cb7-2 | 2020-10-16T00:35:55.328Z | 1576 | NT AUTHORITY\SYSTEM |
>| 1169495860abe1bc6a498d2c196787c3,<br/>fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9 | c:\program files\vmware\vmware tools\vmtoolsd.exe | hw-host-004 | 2020-10-05T02:16:18.531Z | 2748 | NT AUTHORITY\SYSTEM |
>| aca121d48147ff717bcd1da7871a5a76,<br/>da7e37ce59685964a3876ef1747964de1caabd13b3691b6a1d5ebed1d19c19ad | c:\program files\vmware\vmware tools\vmtoolsd.exe | desktop-fvb88fs | 2020-09-03T10:59:48.345Z | 2892 | NT AUTHORITY\SYSTEM |
>| aca121d48147ff717bcd1da7871a5a76,<br/>da7e37ce59685964a3876ef1747964de1caabd13b3691b6a1d5ebed1d19c19ad | c:\program files\vmware\vmware tools\vmtoolsd.exe | desktop-fvb88fs | 2020-09-03T08:00:46.548Z | 2892 | NT AUTHORITY\SYSTEM |
>| 80abd555c1869baaff2d8a8d535ce07e,<br/>fa353f142361e5c6ca57a66dcb341bba20392f5c29d2c113c7d62a216b0e0504 | c:\program files\vmware\vmware tools\vmtoolsd.exe | desktop-aa2m6ld | 2020-08-26T16:06:50.813Z | 2016 | DESKTOP-AA2M6LD\John Doe |
>| 80abd555c1869baaff2d8a8d535ce07e,<br/>fa353f142361e5c6ca57a66dcb341bba20392f5c29d2c113c7d62a216b0e0504 | c:\program files\vmware\vmware tools\vmtoolsd.exe | desktop-aa2m6ld | 2020-08-17T14:37:19.963Z | 8052 | DESKTOP-AA2M6LD\John Doe |

