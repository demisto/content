This integration ensures interaction with the JizoM API.
This integration was integrated and tested with version 12.3 of JizoM.

## Configure JizoM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for JizoM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Username | Reliability of the source providing the intelligence data. | True |
    | Password |  | True |
    | Server URL |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |
    | First fetch time |  | False |
    | Maximum number of alerts per fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### jizo-m-protocols-get

***
Get jizo protocols.

#### Base Command

`jizo-m-protocols-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_src | Ipv4 or Ipv6 of the source. | Optional | 
| ip_dest | Ipv4 or Ipv6 of the destination. | Optional | 
| datetime_from | Get the alerts that were occurred from this date. The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date. The default is now. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of protocols to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.Protocols.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.Protocols.alerts_flows.data | String | The details of alerts. | 
| JizoM.Protocols.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.Protocols.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.Protocols.alerts_files.data | String | The details of alerts. | 
| JizoM.Protocols.alerts_files.total | Number | The total number of alerts. | 
| JizoM.Protocols.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.Protocols.alerts_usecase.data | String | The details of alerts. | 
| JizoM.Protocols.alerts_usecase.total | Number | The total number of alerts. | 

### jizo-m-peers-get

***
Get jizo peers.

#### Base Command

`jizo-m-peers-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_src | Ipv4 or Ipv6 of the source. | Optional | 
| ip_dest | Ipv4 or Ipv6 of the destination. | Optional | 
| datetime_from | Get the alerts that were occurred from this date. The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date. The default is now. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of samples to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.Peers.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.Peers.alerts_flows.data | String | The details of alerts. | 
| JizoM.Peers.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.Peers.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.Peers.alerts_files.data | String | The details of alerts. | 
| JizoM.Peers.alerts_files.total | Number | The total number of alerts. | 
| JizoM.Peers.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.Peers.alerts_usecase.data | String | The details of alerts. | 
| JizoM.Peers.alerts_usecase.total | Number | The total number of alerts. | 

### jizo-m-query-records-get

***
Get jizo query records.

#### Base Command

`jizo-m-query-records-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_src | Ipv4 or Ipv6 of the source. | Optional | 
| ip_dest | Ipv4 or Ipv6 of the destination. | Optional | 
| proto | The protocol (e.g., TCP, UDP). | Optional | 
| app_proto | The application protocol(e.g., FTP, HTTP, DNS, DHCP, SMB). | Optional | 
| port_src | The source port. | Optional | 
| port_dest | The destination port. | Optional | 
| flow_id | The id of the flow. | Optional | 
| sid | The id if the rule. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| port | The alert port. | Optional | 
| datetime_from | Get the alerts that were occurred from this date. The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date. The default is now. | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of samples to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.QueryRecords.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.QueryRecords.alerts_flows.data | String | The details of alerts. | 
| JizoM.QueryRecords.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.QueryRecords.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.QueryRecords.alerts_files.data | String | The details of alerts. | 
| JizoM.QueryRecords.alerts_files.total | Number | The total number of alerts. | 
| JizoM.QueryRecords.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.QueryRecords.alerts_usecase.data | String | The details of alerts. | 
| JizoM.QueryRecords.alerts_usecase.total | Number | The total number of alerts. | 

### jizo-m-alert-rules-get

***
Get jizo alerts rules.

#### Base Command

`jizo-m-alert-rules-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| flow_id | The id of the flow. | Optional | 
| sid | The id if the rule. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| port | The alert port. | Optional | 
| datetime_from | Get the alerts that were occurred from this date. The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date. The default is now. | Optional | 
| severity | Relevance/importance of alert varies from 1-4. | Optional | 
| category | The alert category (e.g., Fraud, Abusive Content). | Optional | 
| type_data | The data type (default IDS). | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of samples to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.AlertRules.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.AlertRules.alerts_flows.data | String | The details of alerts. | 
| JizoM.AlertRules.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.AlertRules.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.AlertRules.alerts_files.data | String | The details of alerts. | 
| JizoM.AlertRules.alerts_files.total | Number | The total number of alerts. | 
| JizoM.AlertRules.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.AlertRules.alerts_usecase.data | String | The details of alerts. | 
| JizoM.AlertRules.alerts_usecase.total | Number | The total number of alerts. | 

### jizo-m-device-records-get

***
Get jizo device records.

#### Base Command

`jizo-m-device-records-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| flow_id | The id of the flow. | Optional | 
| mac | The mac address. | Optional | 
| hostname | The name of the device. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| port | The alert port. | Optional | 
| datetime_from | Get the alerts that were occurred from this date. The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date. The default is now. | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of samples to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.Device.Records.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.Device.Records.alerts_flows.data | String | The details of alerts. | 
| JizoM.Device.Records.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.Device.Records.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.Device.Records.alerts_files.data | String | The details of alerts. | 
| JizoM.Device.Records.alerts_files.total | Number | The total number of alerts. | 
| JizoM.Device.Records.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.Device.Records.alerts_usecase.data | String | The details of alerts. | 
| JizoM.Device.Records.alerts_usecase.total | Number | The total number of alerts. | 

### jizo-m-device-alerts-get

***
Get jizo device alerts.

#### Base Command

`jizo-m-device-alerts-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_src | Ipv4 or Ipv6 of the source. | Optional | 
| ip_dest | Ipv4 or Ipv6 of the destination. | Optional | 
| port_src | The source port. | Optional | 
| port_dest | The destination port. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| port | The alert port. | Optional | 
| datetime_from | Get the alerts that were occurred from this date. The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date. The default is now. | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of samples to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.Device.Alerts.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.Device.Alerts.alerts_flows.data | String | The details of alerts. | 
| JizoM.Device.Alerts.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.Device.Alerts.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.Device.Alerts.alerts_files.data | String | The details of alerts. | 
| JizoM.Device.Alerts.alerts_files.total | Number | The total number of alerts. | 
| JizoM.Device.Alerts.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.Device.Alerts.alerts_usecase.data | String | The details of alerts. | 
| JizoM.Device.Alerts.alerts_usecase.total | Number | The total number of alerts. | 
