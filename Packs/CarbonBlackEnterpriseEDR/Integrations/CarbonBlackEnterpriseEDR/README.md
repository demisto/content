VMware Carbon Black Enterprise EDR (formerly known as Carbon Black ThreatHunter) is an advanced threat hunting and incident response solution delivering continuous visibility for top security operations centers (SOCs) and incident response (IR) teams. (formerly known as ThreatHunter)
This integration was integrated and tested with version xx of Carbon Black Enterprise EDR
## Configure Carbon Black Enterprise EDR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Carbon Black Enterprise EDR.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://defense.conferdeploy.net\) | True |
| organization_key | Organization Key | True |
| custom_key | Custom Key | True |
| custom_id | Custom ID | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| fetch_time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days, 3 months, 1 year\) | False |
| fetch_limit | Fetch limit | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cb-eedr-alert-workflow-update
***
Updates the workflow of a single event.


#### Base Command

`cb-eedr-alert-workflow-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to update. Get the ID from list-alerts command. | Required | 
| state | Workflow state to update. | Optional | 
| comment | Comment to include with the operation. | Optional | 
| remediation_state | Description of the changes done in the workflow state. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.Alert.AlertID | String | The alert ID. | 
| CarbonBlackEEDR.Alert.ChangedBy | String | User that changed the ID. | 
| CarbonBlackEEDR.Alert.Comment | String | Comment that was included with the operation. | 
| CarbonBlackEEDR.Alert.LastUpdateTime | Date | Last time the alert was updated. | 
| CarbonBlackEEDR.Alert.Remediation | String | Description or justification for the change. | 
| CarbonBlackEEDR.Alert.State | String | The alert state. | 


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-device-quarantine
***
Quarantines a device.


#### Base Command

`cb-eedr-device-quarantine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The devices on which to perform the action. Get the ID from the devices-list command. Supports comma-separated values. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-device-unquarantine
***
Removes a device from quarantine.


#### Base Command

`cb-eedr-device-unquarantine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The devices on which to perform the action. Get the ID from the devices-list command. Supports comma-separated values. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-device-background-scan-stop
***
Stops a background scan on the specified devices.


#### Base Command

`cb-eedr-device-background-scan-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Supports comma-separated values. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-device-background-scan
***
Start a background scan on device.


#### Base Command

`cb-eedr-device-background-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Supports comma-separated values. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-device-bypass
***
Enable a bypass on device.


#### Base Command

`cb-eedr-device-bypass`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Support comma-separated values. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-device-unbypass
***
Disable a bypass on device.


#### Base Command

`cb-eedr-device-unbypass`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Support comma-separated values. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-device-policy-update
***
Update device policy.


#### Base Command

`cb-eedr-device-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID. Get the ID from the devices-list command. Support comma-separated values. | Required | 
| policy_id | The policy ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-devices-list
***
List devices based on the search query.


#### Base Command

`cb-eedr-devices-list`
#### Input

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
| limit | Maximum number of rows to return. | Optional | 
| sort_field | Sort Fields | Optional | 
| sort_order | Sort Order for field. | Optional | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-list-alerts
***
Returns a list of alerts.


#### Base Command

`cb-eedr-list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_results | Whether to group results. | Optional | 
| minimum_severity | Alert minimum severity (In range of 1-10). | Optional | 
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
| sort_order | How to order the results. Can be "ASC" (ascending) or "DESC" (descending). | Optional | 
| limit | The maximum number of results to return. | Optional | 
| start_time | Alert start time. | Optional | 
| end_time | Alert end time. | Optional | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-watchlist-list
***
Retrieves all watchlists.


#### Base Command

`cb-eedr-watchlist-list`
#### Input

There are no input arguments for this command.

#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-get-watchlist-by-id
***
Gets watchlist information by  watchlist ID.


#### Base Command

`cb-eedr-get-watchlist-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. Get the ID from the watchlist-list command. | Required | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-watchlist-alerts-status
***
Retrieves the alert status for the watchlist with given watchlist ID.


#### Base Command

`cb-eedr-watchlist-alerts-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. Get the ID from the watchlist-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-watchlist-alerts-enable
***
Turns on alerts for the watchlist with the specified watchlist ID.


#### Base Command

`cb-eedr-watchlist-alerts-enable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. Get the ID from the watchlist-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-watchlist-alerts-disable
***
Turns off alerts for the watchlist with the specified watchlist ID.


#### Base Command

`cb-eedr-watchlist-alerts-disable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. Get the ID from the watchlist-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-watchlist-create
***
Creates a new report or classifier watchlist.


#### Base Command

`cb-eedr-watchlist-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The name of the watchlist. | Required | 
| description | The watchlist description. | Optional | 
| tags_enabled | Whether to enable watchlist tags. Can be "true" or "false". | Optional | 
| alerts_enabled | Enable watchlist alerts | Optional | 
| report_ids | The report IDs for creating the watchlist. Supports comma-separated values. | Optional | 
| classifier_key | The classifier key for creating the watchlist. | Optional | 
| classifier_value | The classifier value for creating the watchlist. | Optional | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-watchlist-delete
***
Removes the specified watchlist.


#### Base Command

`cb-eedr-watchlist-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID to remove. Get the ID from the watchlist-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-watchlist-update
***
Updates the specified watchlist. This will update the tags and alert status as well as any reports or classifiers attached to the watchlist.


#### Base Command

`cb-eedr-watchlist-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID to update. | Required | 
| watchlist_name | The watchlist name. | Required | 
| description | Watchlist description. | Optional | 
| tags_enabled | Whether to enable watchlist tags. Can be "true" or "false". | Optional | 
| alerts_enabled | Enable watchlist alerts. | Optional | 
| report_ids | Watchlist report ID. Supports comma-separated values. | Optional | 
| classifier_key | The classifier key to update. | Optional | 
| classifier_value | The classifier value to update. | Optional | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-report-get
***
Retrieves the specified report.


#### Base Command

`cb-eedr-report-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. Get the ID from the watchlist-list command. | Required | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-ioc-ignore-status
***
Gets the current ignore status for IOC ioc_id in report report_id.


#### Base Command

`cb-eedr-ioc-ignore-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID. Get the ID from the watchlist-list command. | Required | 
| ioc_id | IOC ID. Get the ID from get_report command | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-ioc-ignore
***
IOC ioc_id for report report_id will not match future events for any watchlist.


#### Base Command

`cb-eedr-ioc-ignore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID. Get the ID from the watchlist-list command. | Required | 
| ioc_id | IOC ID. Get the ID from get_report command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-ioc-reactivate
***
IOC ioc_id for report report_id will match future events for all watchlists.


#### Base Command

`cb-eedr-ioc-reactivate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID. Get the ID from the watchlist-list command. | Required | 
| ioc_id | IOC ID. Get the ID from get_report command | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-report-ignore
***
Report with report_id and all contained IOCs will not match future events for any watchlist.


#### Base Command

`cb-eedr-report-ignore`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. Get the ID from the watchlist-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-report-reactivate
***
Report with report_id and all contained IOCs will match future events for all watchlists.


#### Base Command

`cb-eedr-report-reactivate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. Get the ID from the watchlist-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-report-ignore-status
***
Get current ignore status for report with report_id.


#### Base Command

`cb-eedr-report-ignore-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. Get the ID from the watchlist-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-report-remove
***
Remove report with report_id.


#### Base Command

`cb-eedr-report-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID to remove. Get the ID from the watchlist-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-report-create
***
Adds a new watchlist report.


#### Base Command

`cb-eedr-report-create`
#### Input

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


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-report-update
***
Updates the specified report.


#### Base Command

`cb-eedr-report-update`
#### Input

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


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-file-device-summary
***
Gets an overview of the devices that executed the file.


#### Base Command

`cb-eedr-file-device-summary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The requested SHA256 hash to obtain information for. | Required | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-get-file-metadata
***
Returns all of the metadata for the specified binary identified by the SHA256 hash.


#### Base Command

`cb-eedr-get-file-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The requested SHA256 hash to obtain metadata information. | Required | 


#### Context Output

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


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-files-download-link-get
***
The files are able to be downloaded via AWS S3 pre-signed URLs.


#### Base Command

`cb-eedr-files-download-link-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | An array of SHA256 hashes (limit 100). Supports comma-separated values. | Required | 
| expiration_seconds | The number of seconds to make the download URLs available for. | Optional | 
| download_to_xsoar | Download the file to XSOAR. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.File.found.sha256 | String | SHA256 hash of file that is available to be downloaded | 
| CarbonBlackEEDR.File.found.url | String | An AWS S3 pre-signed URL for this file. Perform a GET on this URL to download the file. | 
| CarbonBlackEEDR.File.not_found | String | The SHA256 hashes that were not found. | 
| CarbonBlackEEDR.File.error | String | The SHA256 hashes that had an intermittent error. | 


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-file-paths
***
Return a summary of the observed file paths


#### Base Command

`cb-eedr-file-paths`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | The requested SHA256 hash to obtain information for. Supports comma-separated values. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.File.file_path_count | Number | The total number of unique file paths that have been observed, by this organization, for this file. | 
| CarbonBlackEEDR.File.file_paths | String | The file path details. | 
| CarbonBlackEEDR.File.sha256 | Unknown | The SHA256 hash of the file. | 
| CarbonBlackEEDR.File.total_file_path_count | Number | The total number of file paths that have been observed, by this organization, for this file. | 


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-process-search
***
Creates a process search job.


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEEDR.SearchProcess.job_id | String | The ID of the job found by the search. | 
| CarbonBlackEEDR.SearchProcess.status | String | The status of the job found by the search. | 


#### Command Example
``` ```

#### Human Readable Output



### cb-eedr-events-by-process-get
***
Retrieves the events associated with a given process.


#### Base Command

`cb-eedr-events-by-process-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_guid | The process GUID to search. | Optional | 
| event_type | The event type to search. | Optional | 
| limit | The maximum number of rows to return. Default is 20. | Optional | 
| query | A free-style query. For example, "process_name:svchost.exe". | Optional | 


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
``` ```

#### Human Readable Output



### cb-eedr-process-search-results
***
Retrieves the process search results for a given job ID.


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
``` ```

#### Human Readable Output


