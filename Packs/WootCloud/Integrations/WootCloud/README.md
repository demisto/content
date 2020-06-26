Append HyperContext™ insights to your SIEM data and feed them into your orchestration workflows.
This integration was integrated and tested with version xx of WootCloud
## Configure WootCloud on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for WootCloud.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| client_id | Client ID | True |
| secret_key | API Key | True |
| fetch_time | Time to retrieve the first fetch \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days\) |  |
| alert_type | Alert Type | True |
| severity_type | Severity Type | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### wootcloud-get-pkt-alerts
***
list packet alerts generated in requested time span


#### Base Command

`wootcloud-get-pkt-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_range | Examples are (2 hours, 4 minutes, 6 month, 1 day, etc.) | Required | 
| severity | severity with values of 'notice', 'warning', 'critical' | Optional | 
| skip | integer value for pagination. Default value: 0 | Optional | 
| limit | Integer value for pagination. Default value: 10. Max Value: 500 | Optional | 
| site_id | Array of site ids. Only entered if you want results for a particular site(s) (building, city, region) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.PacketAlert.id | String | ID of alert | 
| WootCloud.PacketAlert.address | String | Mac Address of device | 
| WootCloud.PacketAlert.timestamp | Date | Alert timestamp | 
| WootCloud.PacketAlert.severity | String | Severity level | 
| WootCloud.PacketAlert.category | String | Alert Category | 
| WootCloud.PacketAlert.signature | String | signature | 
| WootCloud.PacketAlert.source.city | String | source city | 
| WootCloud.PacketAlert.source.continent | String | source continent | 
| WootCloud.PacketAlert.source.country | String | source country | 
| WootCloud.PacketAlert.source.ip | String | source ip | 
| WootCloud.PacketAlert.source.latitude | Number | source latitude | 
| WootCloud.PacketAlert.source.longitude | Number | source longitude | 
| WootCloud.PacketAlert.source.mac | String | source mac address | 
| WootCloud.PacketAlert.source.network | String | source network | 
| WootCloud.PacketAlert.source.port | Number | source port | 
| WootCloud.PacketAlert.source.state | String | source state | 
| WootCloud.PacketAlert.source.subnet | String | source subnet | 
| WootCloud.PacketAlert.source.time_zone | String | source time zone | 
| WootCloud.PacketAlert.source.zip | String | source zip | 
| WootCloud.PacketAlert.source.inferred.device_id | String | source inferred device ID | 
| WootCloud.PacketAlert.source.inferred.asset | String | source inferred asset | 
| WootCloud.PacketAlert.source.inferred.managed | Number | source inferred managed | 
| WootCloud.PacketAlert.source.inferred.category | String | source inferred category | 
| WootCloud.PacketAlert.source.inferred.control | String | source inferred control | 
| WootCloud.PacketAlert.source.inferred.host_name | String | source inferred host name | 
| WootCloud.PacketAlert.source.inferred.os | String | source inferred OS | 
| WootCloud.PacketAlert.source.inferred.os_version | String | source inferred OS version | 
| WootCloud.PacketAlert.source.inferred.ownership | String | source inferred ownership | 
| WootCloud.PacketAlert.source.inferred.total_risk | Number | source inferred total risk score | 
| WootCloud.PacketAlert.source.inferred.type | String | source inferred type | 
| WootCloud.PacketAlert.source.inferred.username | String | source inferred username | 
| WootCloud.PacketAlert.source.inferred.managed_info.host_name | String | source inferred managed host name | 
| WootCloud.PacketAlert.destination.city | String | destination city | 
| WootCloud.PacketAlert.destination.continent | String | destination continent | 
| WootCloud.PacketAlert.destination.country | String | destination country | 
| WootCloud.PacketAlert.destination.ip | String | destination ip | 
| WootCloud.PacketAlert.destination.latitude | Number | destination latitude | 
| WootCloud.PacketAlert.destination.longitude | Number | destination longitude | 
| WootCloud.PacketAlert.destination.mac | String | destination mac address | 
| WootCloud.PacketAlert.destination.network | String | destination network | 
| WootCloud.PacketAlert.destination.port | Number | destination port | 
| WootCloud.PacketAlert.destination.state | String | destination state | 
| WootCloud.PacketAlert.destination.subnet | String | destination subnet | 
| WootCloud.PacketAlert.destination.time_zone | String | destination time zone | 
| WootCloud.PacketAlert.destination.zip | String | destination zip | 
| WootCloud.PacketAlert.destination.inferred.device_id | String | destination inferred device ID | 
| WootCloud.PacketAlert.destination.inferred.asset | String | destination inferred asset | 
| WootCloud.PacketAlert.destination.inferred.managed | Number | destination inferred managed | 
| WootCloud.PacketAlert.destination.inferred.category | String | destination inferred category | 
| WootCloud.PacketAlert.destination.inferred.control | String | destination inferred control | 
| WootCloud.PacketAlert.destination.inferred.host_name | String | destination inferred host name | 
| WootCloud.PacketAlert.destination.inferred.os | String | destination inferred OS | 
| WootCloud.PacketAlert.destination.inferred.os_version | String | destination inferred OS version | 
| WootCloud.PacketAlert.destination.inferred.ownership | String | destination inferred ownership | 
| WootCloud.PacketAlert.destination.inferred.total_risk | Number | destination inferred total risk score | 
| WootCloud.PacketAlert.destination.inferred.type | String | destination inferred type | 
| WootCloud.PacketAlert.destination.inferred.username | String | destination inferred username | 
| WootCloud.PacketAlert.destination.inferred.managed_info.host_name | String | destination inferred managed info hostname | 
| WootCloud.PacketAlert.payload | String | payload | 
| WootCloud.PacketAlert.http.hostname | String | http hostname | 
| WootCloud.PacketAlert.http.http_method | String | http methon | 
| WootCloud.PacketAlert.http.http_user_agent | String | http user agent | 
| WootCloud.PacketAlert.http.length | Number | http length | 
| WootCloud.PacketAlert.http.protocol | String | http protocol | 
| WootCloud.PacketAlert.http.redirect | String | http redirect | 
| WootCloud.PacketAlert.http.http_refer | String | http referal | 
| WootCloud.PacketAlert.http.status | Number | http status code | 
| WootCloud.PacketAlert.http.url | String | http url | 
| WootCloud.PacketAlert.type | String | http type | 
| WootCloud.PacketAlert.group | String | group | 
| WootCloud.PacketAlert.subtype | String | subtype | 
| WootCloud.PacketAlert.title | String | title | 
| WootCloud.PacketAlert.description | String | description | 
| WootCloud.PacketAlert.references | String | references | 


#### Command Example
``` ```

#### Human Readable Output



### wootcloud-get-bt-alerts
***
list bluetooth alerts generated in requested time span


#### Base Command

`wootcloud-get-bt-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_range | Examples are (2 hours, 4 minutes, 6 month, 1 day, etc.) | Required | 
| severity | severity with values of 'notice', 'warning', 'critical' | Optional | 
| skip | integer value for pagination. Default value: 0 | Optional | 
| limit | Integer value for pagination. Default value: 10. Max Value: 500 | Optional | 
| site_id | Array of site ids. Only entered if you want results for a particular site(s) (building, city, region) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.BluetoothAlert.id | String | ID | 
| WootCloud.BluetoothAlert.timestamp | Date | timestamp | 
| WootCloud.BluetoothAlert.severity | String | severity | 
| WootCloud.BluetoothAlert.signature | String | signature | 
| WootCloud.BluetoothAlert.description | String | description | 
| WootCloud.BluetoothAlert.address | String | address | 
| WootCloud.BluetoothAlert.inferred.device_id | String | inferred device ID | 
| WootCloud.BluetoothAlert.inferred.asset | String | inferred asset | 
| WootCloud.BluetoothAlert.inferred.managed | Number | inferred managed | 
| WootCloud.BluetoothAlert.inferred.category | String | inferred category | 
| WootCloud.BluetoothAlert.inferred.control | String | inferred control | 
| WootCloud.BluetoothAlert.inferred.host_name | String | inferred host name | 
| WootCloud.BluetoothAlert.inferred.os | String | inferred OS | 
| WootCloud.BluetoothAlert.inferred.os_version | String | inferred OS version | 
| WootCloud.BluetoothAlert.inferred.ownership | String | inferred ownership | 
| WootCloud.BluetoothAlert.inferred.total_risk | Number | inferred total risk score | 
| WootCloud.BluetoothAlert.inferred.type | String | inferred type | 
| WootCloud.BluetoothAlert.inferred.username | String | inferred username | 
| WootCloud.BluetoothAlert.inferred.managed_info.host_name | String | inferred managed info host name | 
| WootCloud.BluetoothAlert.type | String | type | 
| WootCloud.BluetoothAlert.group | String | group | 
| WootCloud.BluetoothAlert.subtype | String | subtype | 
| WootCloud.BluetoothAlert.title | String | title | 


#### Command Example
``` ```

#### Human Readable Output



### wootcloud-get-anomaly-alerts
***
list anomaly alerts generated in requested time span


#### Base Command

`wootcloud-get-anomaly-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| date_range | Examples are (2 hours, 4 minutes, 6 month, 1 day, etc.) | Required | 
| severity | severity with values of 'info, ''notice', 'warning', 'critical' | Optional | 
| skip | integer value for pagination. Default value: 0 | Optional | 
| limit | Integer value for pagination. Default value: 10. Max Value: 500 | Optional | 
| site_id | Array of site ids. Only entered if you want results for a particular site(s) (building, city, region) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.AnomalyAlert.id | String | ID | 
| WootCloud.AnomalyAlert.timestamp | Date | timestamp | 
| WootCloud.AnomalyAlert.anomaly_type | String | anomaly type | 
| WootCloud.AnomalyAlert.signature | String | signature | 
| WootCloud.AnomalyAlert.description | String | description | 
| WootCloud.AnomalyAlert.severity | String | severity | 
| WootCloud.AnomalyAlert.count | Number | count | 
| WootCloud.AnomalyAlert.average | Number | average | 
| WootCloud.AnomalyAlert.minimum | Number | minimum | 
| WootCloud.AnomalyAlert.maximum | Number | maximum | 
| WootCloud.AnomalyAlert.standard_deviation | Number | standard deviation | 
| WootCloud.AnomalyAlert.anomaly_score | Number | anomaly score | 
| WootCloud.AnomalyAlert.observed_value | Number | observed value | 
| WootCloud.AnomalyAlert.deviation_from_norm | String | deviation from the norm | 
| WootCloud.AnomalyAlert.units | String | units | 
| WootCloud.AnomalyAlert.address | String | address | 
| WootCloud.AnomalyAlert.type | String | type | 
| WootCloud.AnomalyAlert.group | String | group | 
| WootCloud.AnomalyAlert.subtype | String | subtype | 
| WootCloud.AnomalyAlert.title | String | title | 
| WootCloud.AnomalyAlert.device_details.device_id | String | device details device ID | 
| WootCloud.AnomalyAlert.device_details.asset | String | device details asset | 
| WootCloud.AnomalyAlert.device_details.managed | Number | device details managed | 
| WootCloud.AnomalyAlert.device_details.category | String | device details category | 
| WootCloud.AnomalyAlert.device_details.control | String | device details control | 
| WootCloud.AnomalyAlert.device_details.host_name | String | device details host name | 
| WootCloud.AnomalyAlert.device_details.os | String | device details OS | 
| WootCloud.AnomalyAlert.device_details.os_version | String | device details OS version | 
| WootCloud.AnomalyAlert.device_details.ownership | String | device details ownership | 
| WootCloud.AnomalyAlert.device_details.total_risk | Number | device details total risk score | 
| WootCloud.AnomalyAlert.device_details.type | String | device details type | 
| WootCloud.AnomalyAlert.device_details.username | String | device details username | 
| WootCloud.AnomalyAlert.device_details.managed_info.host_name | String | device details managed info host name | 
| WootCloud.AnomalyAlert.connections.ip | String | connections ip | 
| WootCloud.AnomalyAlert.connections.port | Number | connections port | 
| WootCloud.AnomalyAlert.connections.connection_count | Number | connections connection count | 


#### Command Example
``` ```

#### Human Readable Output



### wootcloud-fetch-packet-alert
***
retrieve single packet alert given packet id


#### Base Command

`wootcloud-fetch-packet-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the ID of the packet alert | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.PacketAlert.id | String | ID of alert | 
| WootCloud.PacketAlert.address | String | Mac Address of device | 
| WootCloud.PacketAlert.timestamp | Date | Alert timestamp | 
| WootCloud.PacketAlert.severity | String | Severity level | 
| WootCloud.PacketAlert.category | String | Alert Category | 
| WootCloud.PacketAlert.signature | String | signature | 
| WootCloud.PacketAlert.source.city | String | source city | 
| WootCloud.PacketAlert.source.continent | String | source continent | 
| WootCloud.PacketAlert.source.country | String | source country | 
| WootCloud.PacketAlert.source.ip | String | source ip | 
| WootCloud.PacketAlert.source.latitude | Number | source latitude | 
| WootCloud.PacketAlert.source.longitude | Number | source longitude | 
| WootCloud.PacketAlert.source.mac | String | source mac address | 
| WootCloud.PacketAlert.source.network | String | source network | 
| WootCloud.PacketAlert.source.port | Number | source port | 
| WootCloud.PacketAlert.source.state | String | source state | 
| WootCloud.PacketAlert.source.subnet | String | source subnet | 
| WootCloud.PacketAlert.source.time_zone | String | source time zone | 
| WootCloud.PacketAlert.source.zip | String | source zip | 
| WootCloud.PacketAlert.source.inferred.device_id | String | source inferred device ID | 
| WootCloud.PacketAlert.source.inferred.asset | String | source inferred asset | 
| WootCloud.PacketAlert.source.inferred.managed | Number | source inferred managed | 
| WootCloud.PacketAlert.source.inferred.category | String | source inferred category | 
| WootCloud.PacketAlert.source.inferred.control | String | source inferred control | 
| WootCloud.PacketAlert.source.inferred.host_name | String | source inferred host name | 
| WootCloud.PacketAlert.source.inferred.os | String | source inferred OS | 
| WootCloud.PacketAlert.source.inferred.os_version | String | source inferred OS version | 
| WootCloud.PacketAlert.source.inferred.ownership | String | source inferred ownership | 
| WootCloud.PacketAlert.source.inferred.total_risk | Number | source inferred total risk score | 
| WootCloud.PacketAlert.source.inferred.type | String | source inferred type | 
| WootCloud.PacketAlert.source.inferred.username | String | source inferred username | 
| WootCloud.PacketAlert.source.inferred.managed_info.host_name | String | source inferred managed host name | 
| WootCloud.PacketAlert.destination.city | String | destination city | 
| WootCloud.PacketAlert.destination.continent | String | destination continent | 
| WootCloud.PacketAlert.destination.country | String | destination country | 
| WootCloud.PacketAlert.destination.ip | String | destination ip | 
| WootCloud.PacketAlert.destination.latitude | Number | destination latitude | 
| WootCloud.PacketAlert.destination.longitude | Number | destination longitude | 
| WootCloud.PacketAlert.destination.mac | String | destination mac address | 
| WootCloud.PacketAlert.destination.network | String | destination network | 
| WootCloud.PacketAlert.destination.port | Number | destination port | 
| WootCloud.PacketAlert.destination.state | String | destination state | 
| WootCloud.PacketAlert.destination.subnet | String | destination subnet | 
| WootCloud.PacketAlert.destination.time_zone | String | destination time zone | 
| WootCloud.PacketAlert.destination.zip | String | destination zip | 
| WootCloud.PacketAlert.destination.inferred.device_id | String | destination inferred device ID | 
| WootCloud.PacketAlert.destination.inferred.asset | String | destination inferred asset | 
| WootCloud.PacketAlert.destination.inferred.managed | Number | destination inferred managed | 
| WootCloud.PacketAlert.destination.inferred.category | String | destination inferred category | 
| WootCloud.PacketAlert.destination.inferred.control | String | destination inferred control | 
| WootCloud.PacketAlert.destination.inferred.host_name | String | destination inferred host name | 
| WootCloud.PacketAlert.destination.inferred.os | String | destination inferred OS | 
| WootCloud.PacketAlert.destination.inferred.os_version | String | destination inferred OS version | 
| WootCloud.PacketAlert.destination.inferred.ownership | String | destination inferred ownership | 
| WootCloud.PacketAlert.destination.inferred.total_risk | Number | destination inferred total risk score | 
| WootCloud.PacketAlert.destination.inferred.type | String | destination inferred type | 
| WootCloud.PacketAlert.destination.inferred.username | String | destination inferred username | 
| WootCloud.PacketAlert.destination.inferred.managed_info.host_name | String | destination inferred managed info hostname | 
| WootCloud.PacketAlert.payload | String | payload | 
| WootCloud.PacketAlert.http.hostname | String | http hostname | 
| WootCloud.PacketAlert.http.http_method | String | http methon | 
| WootCloud.PacketAlert.http.http_user_agent | String | http user agent | 
| WootCloud.PacketAlert.http.length | Number | http length | 
| WootCloud.PacketAlert.http.protocol | String | http protocol | 
| WootCloud.PacketAlert.http.redirect | String | http redirect | 
| WootCloud.PacketAlert.http.http_refer | String | http referal | 
| WootCloud.PacketAlert.http.status | Number | http status code | 
| WootCloud.PacketAlert.http.url | String | http url | 
| WootCloud.PacketAlert.type | String | http type | 
| WootCloud.PacketAlert.group | String | group | 
| WootCloud.PacketAlert.subtype | String | subtype | 
| WootCloud.PacketAlert.title | String | title | 
| WootCloud.PacketAlert.description | String | description | 
| WootCloud.PacketAlert.references | String | references | 


#### Command Example
``` ```

#### Human Readable Output



### wootcloud-fetch-bluetooth-alert
***
retrieve single bluetooth alert given packet id


#### Base Command

`wootcloud-fetch-bluetooth-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the ID of the bluetooth alert | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.BluetoothAlert.id | String | ID | 
| WootCloud.BluetoothAlert.timestamp | Date | timestamp | 
| WootCloud.BluetoothAlert.severity | String | severity | 
| WootCloud.BluetoothAlert.signature | String | signature | 
| WootCloud.BluetoothAlert.description | String | description | 
| WootCloud.BluetoothAlert.address | String | address | 
| WootCloud.BluetoothAlert.inferred.device_id | String | inferred device ID | 
| WootCloud.BluetoothAlert.inferred.asset | String | inferred asset | 
| WootCloud.BluetoothAlert.inferred.managed | Number | inferred managed | 
| WootCloud.BluetoothAlert.inferred.category | String | inferred category | 
| WootCloud.BluetoothAlert.inferred.control | String | inferred control | 
| WootCloud.BluetoothAlert.inferred.host_name | String | inferred host name | 
| WootCloud.BluetoothAlert.inferred.os | String | inferred OS | 
| WootCloud.BluetoothAlert.inferred.os_version | String | inferred OS version | 
| WootCloud.BluetoothAlert.inferred.ownership | String | inferred ownership | 
| WootCloud.BluetoothAlert.inferred.total_risk | Number | inferred total risk score | 
| WootCloud.BluetoothAlert.inferred.type | String | inferred type | 
| WootCloud.BluetoothAlert.inferred.username | String | inferred username | 
| WootCloud.BluetoothAlert.inferred.managed_info.host_name | String | inferred managed info host name | 
| WootCloud.BluetoothAlert.type | String | type | 
| WootCloud.BluetoothAlert.group | String | group | 
| WootCloud.BluetoothAlert.subtype | String | subtype | 
| WootCloud.BluetoothAlert.title | String | title | 


#### Command Example
``` ```

#### Human Readable Output



### wootcloud-fetch-anomaly-alert
***
retrieve single anomaly alert given packet id


#### Base Command

`wootcloud-fetch-anomaly-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | the ID of the anomaly alert | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WootCloud.AnomalyAlert.id | String | ID | 
| WootCloud.AnomalyAlert.timestamp | Date | timestamp | 
| WootCloud.AnomalyAlert.anomaly_type | String | anomaly type | 
| WootCloud.AnomalyAlert.signature | String | signature | 
| WootCloud.AnomalyAlert.description | String | description | 
| WootCloud.AnomalyAlert.severity | String | severity | 
| WootCloud.AnomalyAlert.count | Number | count | 
| WootCloud.AnomalyAlert.average | Number | average | 
| WootCloud.AnomalyAlert.minimum | Number | minimum | 
| WootCloud.AnomalyAlert.maximum | Number | maximum | 
| WootCloud.AnomalyAlert.standard_deviation | Number | standard deviation | 
| WootCloud.AnomalyAlert.anomaly_score | Number | anomaly score | 
| WootCloud.AnomalyAlert.observed_value | Number | observed value | 
| WootCloud.AnomalyAlert.deviation_from_norm | String | deviation from the norm | 
| WootCloud.AnomalyAlert.units | String | units | 
| WootCloud.AnomalyAlert.address | String | address | 
| WootCloud.AnomalyAlert.type | String | type | 
| WootCloud.AnomalyAlert.group | String | group | 
| WootCloud.AnomalyAlert.subtype | String | subtype | 
| WootCloud.AnomalyAlert.title | String | title | 
| WootCloud.AnomalyAlert.device_details.device_id | String | device details device ID | 
| WootCloud.AnomalyAlert.device_details.asset | String | device details asset | 
| WootCloud.AnomalyAlert.device_details.managed | Number | device details managed | 
| WootCloud.AnomalyAlert.device_details.category | String | device details category | 
| WootCloud.AnomalyAlert.device_details.control | String | device details control | 
| WootCloud.AnomalyAlert.device_details.host_name | String | device details host name | 
| WootCloud.AnomalyAlert.device_details.os | String | device details OS | 
| WootCloud.AnomalyAlert.device_details.os_version | String | device details OS version | 
| WootCloud.AnomalyAlert.device_details.ownership | String | device details ownership | 
| WootCloud.AnomalyAlert.device_details.total_risk | Number | device details total risk score | 
| WootCloud.AnomalyAlert.device_details.type | String | device details type | 
| WootCloud.AnomalyAlert.device_details.username | String | device details username | 
| WootCloud.AnomalyAlert.device_details.managed_info.host_name | String | device details managed info host name | 
| WootCloud.AnomalyAlert.connections.ip | String | connections ip | 
| WootCloud.AnomalyAlert.connections.port | Number | connections port | 
| WootCloud.AnomalyAlert.connections.connection_count | Number | connections connection count | 


#### Command Example
``` ```

#### Human Readable Output


