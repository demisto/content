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
```!cb-eedr-process-search process_name="vmtoolsd.exe" limit=10```

#### Context Example
```json
{
    "CarbonBlackEEDR": {
        "SearchProcess": {
            "job_id": "d7c083aa-cbad-4873-98b4-ecd4f671c4a9",
            "status": "In Progress"
        }
    }
}
```

#### Human Readable Output

>job_id is d7c083aa-cbad-4873-98b4-ecd4f671c4a9.

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
```!cb-eedr-events-by-process-get process_guid="7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43" event_type="modload"```

#### Context Example
```json
{
    "CarbonBlackEEDR": {
        "SearchEvent": [
            {
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "a3mrT5PIR7qXT4MfvySyzg",
                "event_hash": "JV2_7hlfS1moe-9utV9k7A",
                "event_timestamp": "2020-10-07T01:13:47.527Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "N4cMnudGQKC1CTnYViIEIw",
                "event_hash": "3o3NH_IbRFO1IO79yvZKqw",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "Y3lEmsWCQQawhX9Aptu8Dw",
                "event_hash": "gRzHo5sESBejbOitsOJ3NQ",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "YO9xhQ7uR0arCfy4yLT7fA",
                "event_hash": "bOb3k_wHT-CkjrQJvOkSSw",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "MucJ0U3EQ7iXn4j6iduG2w",
                "event_hash": "36exgyMyRRCAyu2XJeIfbA",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "RiO7zlHTSRu_3NE88EfHFA",
                "event_hash": "PaRGRkfeTr6i_hAw5NdmqQ",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "QV4WPL6AQ2uxoTNMDnM_8g",
                "event_hash": "WtY2jJTKTzKCuYCftWlI1Q",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "6s4gKHjhRfSTrxAaL92vvw",
                "event_hash": "qhbMNAGQRzmnAzy3BfIAyQ",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "-C0oLBWaQ42TMglkBkiFFQ",
                "event_hash": "GNrB5VG_QBeSnaICt4k_Wg",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "L7MRGsLpRcu4BWfQdYCCow",
                "event_hash": "dikz7-kgSVOJO8ZawLghQQ",
                "event_timestamp": "2020-10-07T01:13:47.542Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "_CW4dsifSfyHQYcpxgEDzA",
                "event_hash": "7l41qXYyQw2O_RT4UePRjA",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "TtSBBNR1Se23tHqF4jl2pg",
                "event_hash": "M_PpEWbtQCaeNJBS06xPIQ",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "Ti9USdLFRu2Y-J11FqDHhA",
                "event_hash": "gEW88SUqTaKY-skJiyW9tQ",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "ieDwFs-6SE-fM74riDj_Hg",
                "event_hash": "1tejOIccQE2JSArBeHCbvw",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "nIlq-BuGT4W2jLnPn3d5Fg",
                "event_hash": "imANj9RbTNGlCa5SwYDydA",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "cVlfw1fkSKuzKW-CqfEhgg",
                "event_hash": "Cj_pmk6fTH2gh1L_SE4hhw",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.991Z",
                "event_guid": "Zql7cB3-Tn--22caoLxI0Q",
                "event_hash": "3505YfSvRbqaJEkbdz2WTA",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.992Z",
                "event_guid": "vXzTf5E3TOGmlVDpNsVvQA",
                "event_hash": "pq2HpMP_TPqEeA9Sml1Hug",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.992Z",
                "event_guid": "uzP7eMg1QoygNkc-gCMjMw",
                "event_hash": "TOmGgxuZRMKJdOvnzMXTEQ",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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
                "backend_timestamp": "2020-10-07T01:15:43.141Z",
                "created_timestamp": "2020-10-27T14:04:54.992Z",
                "event_guid": "RwjSgsTMSmiBXGLnsrVPnA",
                "event_hash": "9eRt4JlASzm3v0Cdz0iG3Q",
                "event_timestamp": "2020-10-07T01:13:47.558Z",
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

>### Results
>|backend_timestamp|created_timestamp|event_guid|event_hash|event_timestamp|event_type|legacy|modload_action|modload_effective_reputation|modload_md5|modload_name|modload_publisher|modload_publisher_state|modload_sha256|process_guid|process_pid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | a3mrT5PIR7qXT4MfvySyzg | JV2_7hlfS1moe-9utV9k7A | 2020-10-07T01:13:47.527Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_LOCAL_WHITE | aae1f614bfe5e3e5cde18d1f928f5b12 | c:\windows\system32\ctiuser.dll | Carbon Black, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 81eb5f6fbf8d7566560f43f75ec30e5f0284cdee9b5c9df0d81281bda0db3d07 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | N4cMnudGQKC1CTnYViIEIw | 3o3NH_IbRFO1IO79yvZKqw | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 2c7c14627cff3384c52e61d4dbd0ecc3 | c:\windows\system32\version.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 41b4d85d84a86e41b948694b9b5f398a0d79f47629d6d969eb5b461d4f5d0347 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | Y3lEmsWCQQawhX9Aptu8Dw | gRzHo5sESBejbOitsOJ3NQ | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | f7c09099232987cbb965b9280c1dacf8 | c:\program files\vmware\vmware tools\gmodule-2.0.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | d14560487312f487f94bfaed4fe9d0cfd5efbec1ac4ef44c26dd230800bc6b29 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | YO9xhQ7uR0arCfy4yLT7fA | bOb3k_wHT-CkjrQJvOkSSw | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 26fc0a369a68d2a429e2ebe67b8dd1d8 | c:\program files\vmware\vmware tools\gobject-2.0.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 9a914642e7e8e4e4ba004004b490c64453f13597cc43cb77a9e55d180c229f83 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | MucJ0U3EQ7iXn4j6iduG2w | 36exgyMyRRCAyu2XJeIfbA | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 9d9b1790cc6eeb76757b5042914b7289 | c:\program files\vmware\vmware tools\intl.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 03eef80ad1d4b066c4842546ba52ccb911e84606a27f0ec7016d9f62c572846b | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | RiO7zlHTSRu_3NE88EfHFA | PaRGRkfeTr6i_hAw5NdmqQ | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | a83fcd02a532a08386a5bcbb39a581c5 | c:\program files\vmware\vmware tools\glib-2.0.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | ff9bb3a84c807f8151d4956f895f672fa812765e931e9093f40caab0853bd120 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | QV4WPL6AQ2uxoTNMDnM_8g | WtY2jJTKTzKCuYCftWlI1Q | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 9f2b3fac3440db16e0c13473b551d12c | c:\windows\system32\vcruntime140.dll | Microsoft Corporation | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 27c51ff3dc2f4cf2b61bdf55fb60148ef0abb06c2feae188c30f1a63f9e29caa | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | 6s4gKHjhRfSTrxAaL92vvw | qhbMNAGQRzmnAzy3BfIAyQ | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 965eb822d0ef8fda78ccb1f41def093d | c:\windows\system32\winmm.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | ad43d686930eae0f57a55ee75d10bd1882747089a291371ffe1e131eb5f76938 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | -C0oLBWaQ42TMglkBkiFFQ | GNrB5VG_QBeSnaICt4k_Wg | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | e6450257ba3df5161684e4c73ebb8f92 | c:\windows\system32\winmmbase.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 948f13fe144cd80f93565ded2ac2e96d000869bb2761538996d28942495cb1d7 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | L7MRGsLpRcu4BWfQdYCCow | dikz7-kgSVOJO8ZawLghQQ | 2020-10-07T01:13:47.542Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 821236519995fdfb54b56bd9d7a60ba8 | c:\program files\vmware\vmware tools\pcre.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 64388ee3beb0e69fd471b3c7eb5d4de8ae24b9ea0fdba51bc9c81c26be84e585 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | _CW4dsifSfyHQYcpxgEDzA | 7l41qXYyQw2O_RT4UePRjA | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 40b92f37c0698cdc4cde8c0a75791c7e | c:\program files\vmware\vmware tools\vmtools.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | bb8098f4627441f6a29c31757c45339c74b2712b92783173df9ab58d47ae3bfa | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | TtSBBNR1Se23tHqF4jl2pg | M_PpEWbtQCaeNJBS06xPIQ | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | e202dd92848c5103c9abf8ecd22bc539 | c:\windows\system32\fltlib.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 353f8d4e647a11f235f4262d913f7bac4c4f266eac4601ea416e861afd611912 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | Ti9USdLFRu2Y-J11FqDHhA | gEW88SUqTaKY-skJiyW9tQ | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | b7be84c53e81dd0a64ee0845410bd6c7 | c:\windows\system32\icmp.dll | Microsoft Windows | FILE_SIGNATURE_STATE_CATALOG_SIGNED,<br/>FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 8ddd1ddce37c7e560570774de7ca1a1ecf7b32dfd0ba014f504fc6ae50388de6 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | ieDwFs-6SE-fM74riDj_Hg | 1tejOIccQE2JSArBeHCbvw | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 3929147a2a34b0902152c7d0f241b02a | c:\windows\system32\iphlpapi.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | ad1c5309aa873f6a284eabe382812868e20c3d3d64197f3e6ef9d015ea060caa | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | nIlq-BuGT4W2jLnPn3d5Fg | imANj9RbTNGlCa5SwYDydA | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | da9647c845792371dd2f95e1ccc9a63a | c:\windows\system32\sspicli.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | fe741d2f986b0b9557a90bdf0560f49cd17381d1094c42a91634aabe49f46a1e | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | cVlfw1fkSKuzKW-CqfEhgg | Cj_pmk6fTH2gh1L_SE4hhw | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 435009d1ddc0365bfa34b8c8d3f85286 | c:\windows\system32\ntmarta.dll | Microsoft Windows | FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 2f94628f056fe65ea81351e134e59ece813fec5e8400c12d6dfa49defd126d01 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.991Z | Zql7cB3-Tn--22caoLxI0Q | 3505YfSvRbqaJEkbdz2WTA | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 3c9d22cae173ad19806b6a016cd4cc28 | c:\windows\system32\uxtheme.dll | Microsoft Windows | FILE_SIGNATURE_STATE_CATALOG_SIGNED,<br/>FILE_SIGNATURE_STATE_OS,<br/>FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | d95e7d07ea46d7d2aefa01cd0a64cf266be26d40fa6be42f7cf60f6deb8fbaf3 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.992Z | vXzTf5E3TOGmlVDpNsVvQA | pq2HpMP_TPqEeA9Sml1Hug | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | 1f1fe19bc54c75e568646327f6d99c1a | c:\windows\system32\vsocklib.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | e685439d50aecf656ef5bd2523568b6d9220cc9917e7d57eda962c1a520e94a5 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.992Z | uzP7eMg1QoygNkc-gCMjMw | TOmGgxuZRMKJdOvnzMXTEQ | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | b56c118a906a0322b9319d50df188bc6 | c:\program files\vmware\vmware tools\plugins\common\hgfsserver.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 0d74d8f4cf24bc72042234fb92b42396f6d2f6f77c534f9a07af3d82822a0452 | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |
>| 2020-10-07T01:15:43.141Z | 2020-10-27T14:04:54.992Z | RwjSgsTMSmiBXGLnsrVPnA | 9eRt4JlASzm3v0Cdz0iG3Q | 2020-10-07T01:13:47.558Z | modload | false | ACTION_LOADED_MODULE_DISCOVERED | REP_WHITE | a381226b5a088a07680391b94c474baa | c:\program files\vmware\vmware tools\hgfs.dll | VMware, Inc. | FILE_SIGNATURE_STATE_SIGNED,<br/>FILE_SIGNATURE_STATE_TRUSTED,<br/>FILE_SIGNATURE_STATE_VERIFIED | 429a69aba0196be3f53ffa1d2dd09b0caea6fc680468706b2a20fa0f7188ad4b | 7DESJ9GN-0034d5f2-00001f78-00000000-1d68709f411ee43 | 8056 |


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
>|backend_timestamp|device_group_id|device_id|device_name|device_policy_id|device_timestamp|enriched|enriched_event_type|event_type|ingress_time|legacy|org_id|parent_guid|parent_pid|process_guid|process_hash|process_name|process_pid|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2020-10-28T07:20:55.988Z | 0 | 3775337 | cbcloud-win10 | 12229 | 2020-10-28T07:20:07.603Z | true | INJECT_CODE | crossproc | 1603869624380 | true | 7DESJ9GN | 7DESJ9GN-00399b69-0000028c-00000000-1d6a6bb3b2bcc26 | 652 | 7DESJ9GN-00399b69-00000b60-00000000-1d6a6bb41ebd8ef | 1169495860abe1bc6a498d2c196787c3,<br/>fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9 | c:\program files\vmware\vmware tools\vmtoolsd.exe | 2912 |
>| 2020-10-27T14:47:52.717Z | 0 | 3739267 | hw-host-027 | 12229 | 2020-10-27T14:47:13.760Z | true | INJECT_CODE | crossproc | 1603810047142 | true | 7DESJ9GN | 7DESJ9GN-00390e83-000002a0-00000000-1d6a1f9ef3c0d3e | 672 | 7DESJ9GN-00390e83-00000bf4-00000000-1d6a1f9f37d1836 | 1169495860abe1bc6a498d2c196787c3,<br/>fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9 | c:\program files\vmware\vmware tools\vmtoolsd.exe | 3060 |
>| 2020-10-24T00:58:50.495Z | 0 | 3739232 | hw-host-004 | 12229 | 2020-10-24T00:57:37.097Z | true | INJECT_CODE | crossproc | 1603501093672 | true | 7DESJ9GN | 7DESJ9GN-00390e60-000002a4-00000000-1d6a463297ebe9b | 676 | 7DESJ9GN-00390e60-00000c74-00000000-1d6a4632cda86e3 | 1169495860abe1bc6a498d2c196787c3,<br/>fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9 | c:\program files\vmware\vmware tools\vmtoolsd.exe | 3188 |
>| 2020-10-17T14:13:34.936Z | 0 | 3462642 | win10etchangeme | 6525 | 2020-10-17T14:12:28.438Z | true | INJECT_CODE | crossproc | 1602943969760 | true | 7DESJ9GN | 7DESJ9GN-0034d5f2-0000032c-00000000-1d6a276fc5ed489 | 812 | 7DESJ9GN-0034d5f2-00000b8c-00000000-1d6a27706e318a2 | 63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6,<br/>c7084336325dc8eadfb1e8ff876921c4 | c:\program files\vmware\vmware tools\vmtoolsd.exe | 2956 |
>| 2020-10-16T00:36:49.055Z | 0 | 3216323 | exapil\pil-cb7-2 | 6525 | 2020-10-16T00:35:55.328Z | true | INJECT_CODE | crossproc | 1602808577528 | true | 7DESJ9GN | 7DESJ9GN-003113c3-00000204-00000000-1d68d438b085325 | 516 | 7DESJ9GN-003113c3-00000628-00000000-1d68d438ca1bfd4 | 63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6,<br/>c7084336325dc8eadfb1e8ff876921c4 | c:\program files\vmware\vmware tools\vmtoolsd.exe | 1576 |
>| 2020-10-05T02:17:33.365Z | 0 | 3365471 | hw-host-004 | 6525 | 2020-10-05T02:16:18.531Z | true | INJECT_CODE | crossproc | 1601864215004 | true | 7DESJ9GN | 7DESJ9GN-00335a5f-00000288-00000000-1d687d4d1d5aec5 | 648 | 7DESJ9GN-00335a5f-00000abc-00000000-1d687d4d6c9363a | 1169495860abe1bc6a498d2c196787c3,<br/>fe6a1e46897b972a4f998d9792faccb3c292f9651fc9f744f1369e74667bf0f9 | c:\program files\vmware\vmware tools\vmtoolsd.exe | 2748 |
>| 2020-09-03T11:00:49.482Z | 791 | 3670727 | desktop-fvb88fs | 6525 | 2020-09-03T10:59:48.345Z | true | CREATE_PROCESS | childproc | 1599130817870 | true | 7DESJ9GN | 7DESJ9GN-003802c7-000002b8-00000000-1d66fbac06780a2 | 696 | 7DESJ9GN-003802c7-00000b4c-00000000-1d66fbac0f8ad57 | aca121d48147ff717bcd1da7871a5a76,<br/>da7e37ce59685964a3876ef1747964de1caabd13b3691b6a1d5ebed1d19c19ad | c:\program files\vmware\vmware tools\vmtoolsd.exe | 2892 |
>| 2020-09-03T08:01:52.493Z | 791 | 3670528 | desktop-fvb88fs | 6525 | 2020-09-03T08:00:46.548Z | true | CREATE_PROCESS | childproc | 1599120076739 | true | 7DESJ9GN | 7DESJ9GN-00380200-000002b8-00000000-1d66fbac06780a2 | 696 | 7DESJ9GN-00380200-00000b4c-00000000-1d66fbac0f8ad57 | aca121d48147ff717bcd1da7871a5a76,<br/>da7e37ce59685964a3876ef1747964de1caabd13b3691b6a1d5ebed1d19c19ad | c:\program files\vmware\vmware tools\vmtoolsd.exe | 2892 |
>| 2020-08-26T16:08:11.872Z | 0 | 3644148 | desktop-aa2m6ld | 6529 | 2020-08-26T16:06:50.813Z | true | FILE_CREATE | filemod | 1598458053780 | true | 7DESJ9GN | 7DESJ9GN-00379af4-00001520-00000000-1d67a883dbd713b | 5408 | 7DESJ9GN-00379af4-000007e0-00000000-1d67a8847cebcbd | 80abd555c1869baaff2d8a8d535ce07e,<br/>fa353f142361e5c6ca57a66dcb341bba20392f5c29d2c113c7d62a216b0e0504 | c:\program files\vmware\vmware tools\vmtoolsd.exe | 2016 |
>| 2020-08-17T14:38:21.589Z | 0 | 3600261 | desktop-aa2m6ld | 35704 | 2020-08-17T14:37:19.963Z | true | POLICY_ACTION | childproc | 1597675083480 | true | 7DESJ9GN | 7DESJ9GN-0036ef85-000007f0-00000000-1d674a3d9a6a335 | 2032 | 7DESJ9GN-0036ef85-00001f74-00000000-1d674a3e4b3ba9a | 80abd555c1869baaff2d8a8d535ce07e,<br/>fa353f142361e5c6ca57a66dcb341bba20392f5c29d2c113c7d62a216b0e0504 | c:\program files\vmware\vmware tools\vmtoolsd.exe | 8052 |

