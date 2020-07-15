Use the Infinipoint integration to retrieve security and policy incompliance events, vulnerabilities or incidents. Investigate and respond to events in real-time.
This integration was integrated and tested with version xx of Infinipoint
## Configure Infinipoint on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Infinipoint.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| access_key | Access Key | True |
| private_key | Private Key | True |
| url | Server URL \(e.g. https://console.infinipoint.io\) | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| page_size | page size | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### infinipoint-get-vulnerable-devices
***
 


#### Base Command

`infinipoint-get-vulnerable-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_os |  | Optional | 
| device_risk |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Vulnerability.Devices.$device | String |  | 
| Infinipoint.Vulnerability.Devices.$host | String |  | 
| Infinipoint.Vulnerability.Devices.cve_id | Unknown |  | 
| Infinipoint.Vulnerability.Devices.device_risk | Number |  | 
| Infinipoint.Vulnerability.Devices.device_risk_type | Number |  | 
| Infinipoint.Vulnerability.Devices.software_name | Unknown |  | 
| Infinipoint.Vulnerability.Devices.vulnerability_count | Number |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-assets-programs
***
 


#### Base Command

`infinipoint-get-assets-programs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name |  | Optional | 
| publisher |  | Optional | 
| version |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Programs.items.$device | String |  | 
| Infinipoint.Assets.Programs.items.$host | String |  | 
| Infinipoint.Assets.Programs.items.$time | Number |  | 
| Infinipoint.Assets.Programs.items.$type | String |  | 
| Infinipoint.Assets.Programs.items.name | String |  | 
| Infinipoint.Assets.Programs.items.os_type | String |  | 
| Infinipoint.Assets.Programs.items.program_exists | String |  | 
| Infinipoint.Assets.Programs.items.publisher | String |  | 
| Infinipoint.Assets.Programs.items.version | String |  | 
| Infinipoint.Assets.Programs.items.install_update_date | Date |  | 
| Infinipoint.Assets.Programs.itemsTotal | Number |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-cve
***
 


#### Base Command

`infinipoint-get-cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Cve.Details.campaign_intelligence.apt | String |  | 
| Infinipoint.Cve.Details.campaign_intelligence.description | String |  | 
| Infinipoint.Cve.Details.campaign_intelligence.targeted_countries | String |  | 
| Infinipoint.Cve.Details.campaign_intelligence.targeted_industries | String |  | 
| Infinipoint.Cve.Details.cve_description | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.ac_insuf_info | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.access_vector | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.attack_complexity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.authentication | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.availability_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.base_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.confidentiality_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.exploitability_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.impact_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.integrity_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_all_privilege | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_other_privilege | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_user_privilege | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.severity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.user_interaction_required | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.vector_string | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.attack_complexity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.attack_vector | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.availability_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.base_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.base_severity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.confidentiality_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.exploitability_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.impact_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.integrity_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.privileges_required | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.scope | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.user_interaction | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.vector_string | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.attack_complexity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.campaigns | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.device_count | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.exploitability_risk | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.exploits | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_label | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_level | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_type | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.trends_level | String |  | 
| Infinipoint.Cve.Details.cve_id | String |  | 
| Infinipoint.Cve.Details.cwe_description | String |  | 
| Infinipoint.Cve.Details.cwe_id | String |  | 
| Infinipoint.Cve.Details.devices.$device | String |  | 
| Infinipoint.Cve.Details.devices.device_name_string | String |  | 
| Infinipoint.Cve.Details.devices.device_os | String |  | 
| Infinipoint.Cve.Details.devices.device_risk | Number |  | 
| Infinipoint.Cve.Details.devices.map_id | String |  | 
| Infinipoint.Cve.Details.devices.vulnerableProduct | String |  | 
| Infinipoint.Cve.Details.devices.vulnerableVersion | String |  | 
| Infinipoint.Cve.Details.scan_date | Unknown |  | 
| Infinipoint.Cve.Details.software_list.cpe_name_string | String |  | 
| Infinipoint.Cve.Details.software_list.cpe_type | String |  | 
| Infinipoint.Cve.Details.top_devices.$device | String |  | 
| Infinipoint.Cve.Details.top_devices.device_name_string | String |  | 
| Infinipoint.Cve.Details.top_devices.device_os | String |  | 
| Infinipoint.Cve.Details.top_devices.device_risk | Number |  | 
| Infinipoint.Cve.Details.top_devices.map_id | String |  | 
| Infinipoint.Cve.Details.top_devices.vulnerableProduct | String |  | 
| Infinipoint.Cve.Details.top_devices.vulnerableVersion | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-device
***
 


#### Base Command

`infinipoint-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host |  | Optional | 
| osType | choose a OS type - 1 = Windows \| 2 = Linux \| 4 = macOS | Optional | 
| osName | Device operating system full name e.g. windows-10.0.18363.836 | Optional | 
| status | Device current status:- 0 = Offline \| 1 = Online | Optional | 
| agentVersion |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Devices.agentVersion | String |  | 
| Infinipoint.Devices.clientType | Number |  | 
| Infinipoint.Devices.discoveryId | String |  | 
| Infinipoint.Devices.domain | String |  | 
| Infinipoint.Devices.edge | Number |  | 
| Infinipoint.Devices.ftDidRespond | Number |  | 
| Infinipoint.Devices.ftIsSuccessful | Number |  | 
| Infinipoint.Devices.ftResult | String |  | 
| Infinipoint.Devices.gatewayIp | Number |  | 
| Infinipoint.Devices.gatewayMACAddress | Date |  | 
| Infinipoint.Devices.host | String |  | 
| Infinipoint.Devices.id | String |  | 
| Infinipoint.Devices.ip | Number |  | 
| Infinipoint.Devices.lastSeen | Date |  | 
| Infinipoint.Devices.macAddress | String |  | 
| Infinipoint.Devices.networkId | Number |  | 
| Infinipoint.Devices.networks.alias | String |  | 
| Infinipoint.Devices.networks.cidr | String |  | 
| Infinipoint.Devices.networks.gatewayIp | Number |  | 
| Infinipoint.Devices.networks.gatewayMACAddress | Date |  | 
| Infinipoint.Devices.osName | String |  | 
| Infinipoint.Devices.osType | Number |  | 
| Infinipoint.Devices.policyVersion | String |  | 
| Infinipoint.Devices.productType | String |  | 
| Infinipoint.Devices.regDate | Date |  | 
| Infinipoint.Devices.status | Number |  | 
| Infinipoint.Devices.statusCode | Unknown |  | 
| Infinipoint.Devices.statusDescription | Unknown |  | 
| Infinipoint.Devices.supportId | Unknown |  | 
| Infinipoint.Devices.tags.color | String |  | 
| Infinipoint.Devices.tags.name | String |  | 
| Infinipoint.Devices.tags.tagId | String |  | 
| Infinipoint.Devices.uniqueHostname | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-tag
***
 


#### Base Command

`infinipoint-get-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Tags.color | String |  | 
| Infinipoint.Tags.count | Number |  | 
| Infinipoint.Tags.description | String |  | 
| Infinipoint.Tags.name | String |  | 
| Infinipoint.Tags.tagId | String |  | 
| Infinipoint.Tags.type | Number |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-networks
***
 


#### Base Command

`infinipoint-get-networks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alias |  | Optional | 
| gateway_ip |  | Optional | 
| cidr |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Networks.Info.alias | String |  | 
| Infinipoint.Networks.Info.cidr | String |  | 
| Infinipoint.Networks.Info.city | Unknown |  | 
| Infinipoint.Networks.Info.country | Unknown |  | 
| Infinipoint.Networks.Info.cronExpression | String |  | 
| Infinipoint.Networks.Info.dnsName | String |  | 
| Infinipoint.Networks.Info.externalIp | Number |  | 
| Infinipoint.Networks.Info.firstSeen | Date |  | 
| Infinipoint.Networks.Info.floor | Unknown |  | 
| Infinipoint.Networks.Info.gatewayIp | Number |  | 
| Infinipoint.Networks.Info.gatewayMacAddress | String |  | 
| Infinipoint.Networks.Info.ip | Number |  | 
| Infinipoint.Networks.Info.ipSubnetMask | Number |  | 
| Infinipoint.Networks.Info.lastRun | Date |  | 
| Infinipoint.Networks.Info.lastSeen | Date |  | 
| Infinipoint.Networks.Info.latitude | Unknown |  | 
| Infinipoint.Networks.Info.longitude | Unknown |  | 
| Infinipoint.Networks.Info.managedCount | Number |  | 
| Infinipoint.Networks.Info.name | String |  | 
| Infinipoint.Networks.Info.networkId | Number |  | 
| Infinipoint.Networks.Info.nextRun | Date |  | 
| Infinipoint.Networks.Info.onPrem | Number |  | 
| Infinipoint.Networks.Info.room | Unknown |  | 
| Infinipoint.Networks.Info.scheduleStatus | Number |  | 
| Infinipoint.Networks.Info.state | Unknown |  | 
| Infinipoint.Networks.Info.street | Unknown |  | 
| Infinipoint.Networks.Info.type | Number |  | 
| Infinipoint.Networks.Info.unmanagedCount | Number |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-assets-hardware
***
 


#### Base Command

`infinipoint-get-assets-hardware`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host |  | Optional | 
| os_type | choose a OS type - 1 = Windows \| 2 = Linux \| 4 = macOS | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Hardware.$device | String |  | 
| Infinipoint.Assets.Hardware.$host | String |  | 
| Infinipoint.Assets.Hardware.$time | Number |  | 
| Infinipoint.Assets.Hardware.$type | String |  | 
| Infinipoint.Assets.Hardware.cpu_brand | String |  | 
| Infinipoint.Assets.Hardware.cpu_logical_cores | String |  | 
| Infinipoint.Assets.Hardware.cpu_physical_cores | String |  | 
| Infinipoint.Assets.Hardware.hardware_model | String |  | 
| Infinipoint.Assets.Hardware.hardware_serial | String |  | 
| Infinipoint.Assets.Hardware.hardware_vendor | String |  | 
| Infinipoint.Assets.Hardware.kernel_version | String |  | 
| Infinipoint.Assets.Hardware.os_build | String |  | 
| Infinipoint.Assets.Hardware.os_name | String |  | 
| Infinipoint.Assets.Hardware.os_patch_version | String |  | 
| Infinipoint.Assets.Hardware.os_type | String |  | 
| Infinipoint.Assets.Hardware.os_version | String |  | 
| Infinipoint.Assets.Hardware.physical_memory | String |  | 
| Infinipoint.Assets.Hardware.platform | String |  | 
| Infinipoint.Assets.Hardware.user | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-assets-cloud
***
 


#### Base Command

`infinipoint-get-assets-cloud`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host |  | Optional | 
| os_type |  | Optional | 
| source | "AWS API" \| "GCP API" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Cloud.$device | String |  | 
| Infinipoint.Assets.Cloud.$host | String |  | 
| Infinipoint.Assets.Cloud.$time | Number |  | 
| Infinipoint.Assets.Cloud.$type | String |  | 
| Infinipoint.Assets.Cloud.cloud_scan_timestamp | Number |  | 
| Infinipoint.Assets.Cloud.cpu_brand | String |  | 
| Infinipoint.Assets.Cloud.cpu_logical_cores | String |  | 
| Infinipoint.Assets.Cloud.cpu_physical_cores | String |  | 
| Infinipoint.Assets.Cloud.creation_time | String |  | 
| Infinipoint.Assets.Cloud.hardware_model | String |  | 
| Infinipoint.Assets.Cloud.hardware_serial | String |  | 
| Infinipoint.Assets.Cloud.hardware_vendor | String |  | 
| Infinipoint.Assets.Cloud.instance_id | Date |  | 
| Infinipoint.Assets.Cloud.instance_state | String |  | 
| Infinipoint.Assets.Cloud.instance_type | String |  | 
| Infinipoint.Assets.Cloud.os_build | String |  | 
| Infinipoint.Assets.Cloud.os_name | String |  | 
| Infinipoint.Assets.Cloud.os_patch_version | String |  | 
| Infinipoint.Assets.Cloud.os_type | String |  | 
| Infinipoint.Assets.Cloud.physical_memory | String |  | 
| Infinipoint.Assets.Cloud.platform | String |  | 
| Infinipoint.Assets.Cloud.source | String |  | 
| Infinipoint.Assets.Cloud.user | String |  | 
| Infinipoint.Assets.Cloud.zone | String |  | 
| Infinipoint.Assets.Cloud.open_ports | Number |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-assets-users
***
 


#### Base Command

`infinipoint-get-assets-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host |  | Optional | 
| username |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.User.$device | String |  | 
| Infinipoint.Assets.User.$host | String |  | 
| Infinipoint.Assets.User.$time | Number |  | 
| Infinipoint.Assets.User.$type | String |  | 
| Infinipoint.Assets.User.description | String |  | 
| Infinipoint.Assets.User.directory | String |  | 
| Infinipoint.Assets.User.username | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-action
***
 


#### Base Command

`infinipoint-get-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Responses.$data | String |  | 
| Infinipoint.Responses.$device | String |  | 
| Infinipoint.Responses.$host | String |  | 
| Infinipoint.Responses.$time | Number |  | 
| Infinipoint.Responses.$type | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-queries
***
 


#### Base Command

`infinipoint-get-queries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Scripts.Search.aggregation | Number |  | 
| Infinipoint.Scripts.Search.createdOn | Date |  | 
| Infinipoint.Scripts.Search.format | Number |  | 
| Infinipoint.Scripts.Search.id | String |  | 
| Infinipoint.Scripts.Search.interp | Number |  | 
| Infinipoint.Scripts.Search.module | Number |  | 
| Infinipoint.Scripts.Search.name | String |  | 
| Infinipoint.Scripts.Search.osType | Number |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-run-queries
***
 


#### Base Command

`infinipoint-run-queries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id |  | Required | 
| target |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Scripts.execute.actionId | String |  | 
| Infinipoint.Scripts.execute.aggColumns | String |  | 
| Infinipoint.Scripts.execute.devicesCount | Number |  | 
| Infinipoint.Scripts.execute.name | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-non-compliance
***
 


#### Base Command

`infinipoint-get-non-compliance`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset |  | Required | 
| limit |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Compliance.Incidents.deviceID | String |  | 
| Infinipoint.Compliance.Incidents.eventTime | Number |  | 
| Infinipoint.Compliance.Incidents.hostname | Date |  | 
| Infinipoint.Compliance.Incidents.issues.issueID | String |  | 
| Infinipoint.Compliance.Incidents.issues.issueType | String |  | 
| Infinipoint.Compliance.Incidents.issues.policyIdx | Number |  | 
| Infinipoint.Compliance.Incidents.issues.ref | String |  | 
| Infinipoint.Compliance.Incidents.policyID | String |  | 
| Infinipoint.Compliance.Incidents.policyName | String |  | 
| Infinipoint.Compliance.Incidents.policyVersion | Number |  | 
| Infinipoint.Compliance.Incidents.timestamp | Number |  | 


#### Command Example
``` ```

#### Human Readable Output


