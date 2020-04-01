This is the Hello World integration for getting started.
This integration was integrated and tested with version xx of HelloWorld
## Configure HelloWorld on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HelloWorld.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://soar.monstersofhack.com\) | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| apikey | API Key | True |
| threshold_ip | Score threshold for ip reputation command \(0\-100\) | False |
| threshold_domain | Score threshold for domain reputation command \(0\-100\) | False |
| alert_status | Fetch alerts with status \(ACTIVE, CLOSED\) | False |
| alert_type | Fetch alerts with type | False |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### helloworld-say-hello
***
Hello command - prints hello to anyone


##### Base Command

`helloworld-say-hello`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here | 


##### Command Example
``` ```

##### Human Readable Output


### helloworld-search-alerts
***
Retrieve alerts


##### Base Command

`helloworld-search-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | Filter by alert severity (0 to 3). 0-low, 1-medium, 2-high, 3-critical | Optional | 
| status | Filter by alert status | Optional | 
| alert_type | Filter by alert type | Optional | 
| max_results | Maximum results to return | Optional | 
| start_time | Filter by start time. <br/>Examples:<br/>  &quot;3 days ago&quot;<br/>  &quot;1 month&quot;<br/>  &quot;2019-10-10T12:22:00&quot;<br/>  &quot;2019-10-10&quot; | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.id | string | Alert id | 
| HelloWorld.Alert.name | string | Alert name | 
| HelloWorld.Alert.description | string | Alert description | 
| HelloWorld.Alert.status | string | Alert status, can be &quot;open&quot;, &quot;closed&quot; | 
| HelloWorld.Alert.severity | number | Severity. 1\-low,2\-medium,3\-high,4\-critical | 
| HelloWorld.Alert.type | string | Alert type.  | 


##### Command Example
``` ```

##### Human Readable Output


### helloworld-get-alert
***
Retrieve alert by id


##### Base Command

`helloworld-get-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | alert id | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.id | string | Alert id | 
| HelloWorld.Alert.name | string | Alert name | 
| HelloWorld.Alert.description | string | Alert description | 
| HelloWorld.Alert.status | string | Alert status, can be &quot;open&quot;, &quot;closed&quot; | 
| HelloWorld.Alert.severity | number | Severity. 1\-low,2\-medium,3\-high,4\-critical | 
| HelloWorld.Alert.type | string | Alert type. | 


##### Command Example
``` ```

##### Human Readable Output


### ip
***
Return IP reputation


##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs | Optional | 
| threshold | If the ip has reputation above the treshold then the ip defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | string | IP address | 
| IP.ASN | string | ASN | 
| IP.Malicious.Vendor | string | HelloWorld | 
| IP.Malicious.Description | string | Explanation why this IP found to be malicious | 
| HelloWorld.IP.ip | string | IP Address | 
| HelloWorld.IP.asn | string | ASN address | 
| HelloWorld.IP.reputation | number | Reputation of the ip, number between 0\-100 | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 


##### Command Example
``` ```

##### Human Readable Output


### helloworld-scan-start
***
Start scan on an asset


##### Base Command

`helloworld-scan-start`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Just pass any hostname you want | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Scan.scan_id | string | Unique id of the scan | 


##### Command Example
``` ```

##### Human Readable Output


### helloworld-scan-status
***
Retrieve scan status


##### Base Command

`helloworld-scan-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | List of Scan IDs. helloworld-scan-start returns &quot;scan_id&quot; | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Scan.scan_id | string | The id of the scan | 
| HelloWorld.Scan.status | string | Can be &quot;running&quot;, &quot;completed&quot; | 


##### Command Example
``` ```

##### Human Readable Output


### helloworld-scan-results
***
Returns scan results


##### Base Command

`helloworld-scan-results`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | Results format | Required | 
| scan_id | The id of the scan | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.ScanResults.id | string | Scan id | 
| HelloWorld.ScanResults.source_ip | string | the ip of the asset | 
| HelloWorld.ScanResults.c_and_c | string | C&amp;C ip | 
| InfoFile.EntryID | Unknown | The EntryID of the report file | 
| InfoFile.Extension | string | The extension of the report file | 
| InfoFile.Name | string | The name of the report file | 
| InfoFile.Info | string | The info of the report file | 
| InfoFile.Size | number | The size of the report file | 
| InfoFile.Type | string | The type of the report file | 


##### Command Example
``` ```

##### Human Readable Output

