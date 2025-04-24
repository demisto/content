Symantec EDR (On Prem) endpoints help to detect threats in your network by filter endpoints data to find Indicators of Compromise (IoCs) and take actions to remediate the threat(s). EDR on-premise capabilities allow incident responders to quickly search, identify, and contain all impacted endpoints while investigating threats using a choice of on-premises.
This integration was integrated and tested with version 4.6 of SymantecEDR

## Configure Symantec Endpoint Detection and Response (EDR) - On Prem in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (i.e., https://host:port) | Symantec EDR \(On Prem\) Appliance URL | True |
| Client ID | OAuth Client ID and Client Secret to authorize third-party applications to communicate with Symantec EDR. | True |
| Client Secret |  | True |
| Fetch incidents |  | False |
| Incident data source | Fetch incident type, e.g., 'incident', 'event'. If not selected, incident will be selected. | False |
| Fetch incidents alerts | Retrieve incident related events from EDR database. An additional API call will be made for each fetched incident. | False |
| Fetch incident comments | Retrieve incident comments for each fetched incident when checked. An additional API call will be made for each fetched incident. | False |
| Incidents "Status" to filter out fetching as incidents. Comma-separated lists are supported, e.g., Open, In-Progress | If not selected, will fetch Open incidents. | False |
| Incidents "Priority" to filter out fetching as incidents. Comma-separated lists are supported, e.g., Medium,High. | If not selected, will fetch High and Medium incidents. | False |
| Events "Status" to filter out fetching as incidents. Comma-separated lists are supported, e.g., Unknown, Success | If not selected, will fetch Success events. | False |
| Events "Severity" to filter out fetching as incidents. Comma-separated lists are supported, e.g., Info, Warning | If not selected, will fetch Info events. | False |
| Query string to fetch incidents/events. For example - log_time:[2017-01-01T00:00:00.000Z TO 2017-01-08T00:00:00.000Z]" |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 10 minutes, 12 hours, 7 days) | First Fetch timestamp, Default is 3 days. The maximum time range is 30 days. For example, if configured as 60 days based on the current datetime, then data will be fetched according to the time range using start_time=60 days and end_time=30 days. | False |
| Maximum number of incidents to fetch | Maximum Number of Incidents fetch limit. Maximum Default limit is 50. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### symantec-edr-endpoint-isolate
***
Isolates or quarantines endpoints by cutting connections that the endpoint(s) has to internal networks and external networks, based on the endpoint device IDs.


#### Base Command

`symantec-edr-endpoint-isolate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID of the target computers. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Command.isolate_endpoint.command_id | String | Command ID | 
| SymantecEDR.Command.isolate_endpoint.error_code | Number | The status of the command action. Values: -1 = Error, 0 = Command isolate_endpoint successfully requested, 1 = Command isolate_endpoint not supported for target command type, 2 = Command isolate_endpoint failed because the target command is already in terminal state \(i.e., completed, error, or cancelled\), 3 = Command isolate_endpoint is already in progress for the target command. | 
| SymantecEDR.Command.isolate_endpoint.message | String | Message explaining the error code. | 

#### Command example
```!symantec-edr-endpoint-isolate device_id=393b8e82-fe40-429f-8e5e-c6b79a0f2b1c```
#### Context Example
```json
{
    "SymantecEDR": {
        "Command": {
            "Isolate Endpoint": {
                "command_id": "fd6d14933c7e422685634b613cb7963a-2023-02-15",
                "error_code": 0,
                "message": "Command isolate_endpoint successfully requested"
            }
        }
    }
}
```

#### Human Readable Output

>### Command Isolate Endpoint
>|Message|CommandId|
>|---|---|
>| Command isolate_endpoint successfully requested | fd6d14933c7e422685634b613cb7963a-2023-02-15 |


### symantec-edr-domain-file-association-list
***
List of domain and file association.


#### Base Command

`symantec-edr-domain-file-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| query | Specify a search query as a Lucene query string.<br/>Example: query="last_seen: 2022-10-22T11:23:26.561Z"<br/><br/>Note: Refer to Symantec (EDR On-Premise) API document for more details https://apidocs.securitycloud.symantec.com/#. | Optional | 
| search_object | Specify a filter option in lieu of “query”. These filters will improve the query performance. Possible values are: domain, sha256. | Optional | 
| search_value | Specify a search value. Supports a comma-separated query with multiple search values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.DomainFileAssociation.data_source_url | String | The URL that was accessed. Example: "http://www.westfallave.com/insight/cloudcar.exe". | 
| SymantecEDR.DomainFileAssociation.data_source_url_domain | String | Domain name of the accessed URL. Example: "westfallave.com". | 
| SymantecEDR.DomainFileAssociation.device_ip | String | The IPv6 or IPv4 address of the endpoint when this association was last updated. Example: "127.0.0.1". | 
| SymantecEDR.DomainFileAssociation.device_name | String | The host name or, if unavailable, the IP address of the endpoint when this association was last updated. Example: "170915-000020". | 
| SymantecEDR.DomainFileAssociation.device_uid | String | Unique ID of the endpoint that downloaded the file from the URL. Example: "04cfc04b-5c7a-4aa8-b95b-79be23f768f4". | 
| SymantecEDR.DomainFileAssociation.first_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted in the creation of this association. Example: "2018-01-30T04:13:10.669Z". | 
| SymantecEDR.DomainFileAssociation.last_seen | String | The timestamp \(in ISO 8601 format\) that specifies the last time detected of the event that resulted in the update of this association. Example: "2018-01-30T04:13:10.669Z". | 
| SymantecEDR.DomainFileAssociation.name | String | The file name of the downloaded file. This attribute doesn’t include the path of the file. Example: "cloudcar\[2\].exe". | 
| SymantecEDR.DomainFileAssociation.sha2 | String | The SHA256 checksum of the file \(hex string\) that was downloaded from the URL. Example: "3559378c933cdd434af2083f7535460843d2462033de74ec7c70dbe5f70124f5". | 
| SymantecEDR.DomainFileAssociation.signature_company_name | String | The signer company name of the downloaded file. Example: "Microsoft Windows". | 

#### Command example
```!symantec-edr-domain-file-association-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "DomainFileAssociation": [
            {
                "data_source_url": "http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/685cae66-5fe2-498e-b4f1-ed26aafa2801?p1=1667042599&p2=404&p3=2&p4=c3swnk6uktun4vjyhudntbuxv8bilxgbgat1s%2flgzbqw4kjyc0zs8ox7mi1oaisl96huewngvdr%2bnfbl7erlxa%3d%3d",
                "data_source_url_domain": "msedge.b.tlu.dl.delivery.mp.microsoft.com",
                "device_ip": "172.16.14.42",
                "device_name": "win-tfb8l7bi77h",
                "device_uid": "393b8e82-fe40-429f-8e5e-c6b79a0f2b1c",
                "first_seen": "2022-10-22T11:23:26.561Z",
                "last_seen": "2022-10-22T11:23:26.561Z",
                "name": "microsoftedge_x64_106.0.1370.52_106.0.1370.47.exe",
                "sha2": "1291d6eb30cd1683544666692a382aecf325dc2624da9ef395047a64642059dc",
                "signature_company_name": "Microsoft Corporation"
            }
        ]
    }
}
```

#### Human Readable Output

>### Domain File Association List
>|FirstSeen|LastSeen|DataSourceUrl|DataSourceUrlDomain|Sha2|Name|SignatureCompanyName|DeviceUid|DeviceIp|DeviceName|
>|---|---|---|---|---|---|---|---|---|---|
>| 2022-10-22T11:23:26.561Z | 2022-10-22T11:23:26.561Z | http:<span>//</span>msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/685cae66-5fe2-498e-b4f1-ed26aafa2801?p1=1667042599&p2=404&p3=2&p4=c3swnk6uktun4vjyhudntbuxv8bilxgbgat1s%2flgzbqw4kjyc0zs8ox7mi1oaisl96huewngvdr%2bnfbl7erlxa%3d%3d | msedge.b.tlu.dl.delivery.mp.microsoft.com | 1291d6eb30cd1683544666692a382aecf325dc2624da9ef395047a64642059dc | microsoftedge_x64_106.0.1370.52_106.0.1370.47.exe | Microsoft Corporation | 393b8e82-fe40-429f-8e5e-c6b79a0f2b1c | 172.16.14.42 | win-tfb8l7bi77h |


### symantec-edr-endpoint-domain-association-list
***
List of endpoint and domain association.


#### Base Command

`symantec-edr-endpoint-domain-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| query | Specify a search query as a Lucene query string.<br/>Example: query="first_seen: [2022-10-01T07:00:58.030Z  TO 2022-10-21T06:41:54.452Z]" <br/><br/>Note: For more details refer to Symantec EDR (On-Prem) API document https://apidocs.securitycloud.symantec.com/#. | Optional | 
| search_object | Specify a filters option in lieu of “query”. These filters will improve query performance. Possible values are: domain, device_uid. | Optional | 
| search_value | Specify a search value. Supports a comma-separated query with multiple search values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.EndpointDomainAssociation.data_source_url | String | The URL that was accessed. Example: "http://www.westfallave.com/insight/cloudcar.exe". | 
| SymantecEDR.EndpointDomainAssociation.data_source_url_domain | String | Domain name of the accessed URL. Example: "westfallave.com". | 
| SymantecEDR.EndpointDomainAssociation.device_ip | String | The IPv6 or IPv4 address of the endpoint when this association was last updated. Example: "127.0.0.1". | 
| SymantecEDR.EndpointDomainAssociation.device_name | String | The host name or, if unavailable, the IP address of the endpoint when this association was last updated. Example: "170915-000020". | 
| SymantecEDR.EndpointDomainAssociation.device_uid | String | Unique ID of the endpoint that accessed this URL. Example: "04cfc04b-5c7a-4aa8-b95b-79be23f768f4". | 
| SymantecEDR.EndpointDomainAssociation.first_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted in the creation of this association. Example: "2018-01-30T04:13:10.669Z." | 
| SymantecEDR.EndpointDomainAssociation.last_seen | String | The timestamp \(in ISO 8601 format\) that specifies the last time detected of the event that resulted in the update of this association. Example: "2018-01-30T04:13:10.669Z." | 

#### Command example
```!symantec-edr-endpoint-domain-association-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "EndpointDomainAssociation": [
            {
                "data_source_url": "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?4653cf2caa3508f4",
                "data_source_url_domain": "ctldl.windowsupdate.com",
                "device_ip": "172.16.14.42",
                "device_name": "WIN-TFB8L7BI77H",
                "device_uid": "393b8e82-fe40-429f-8e5e-c6b79a0f2b1c",
                "first_seen": "2022-10-21T19:06:39.998Z",
                "last_seen": "2022-10-21T19:06:39.998Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Endpoint Domain Association List
>|FirstSeen|LastSeen|DataSourceUrl|DataSourceUrlDomain|DeviceUid|DeviceIp|DeviceName|
>|---|---|---|---|---|---|---|
>| 2022-10-21T19:06:39.998Z | 2022-10-21T19:06:39.998Z | http:<span>//</span>ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab?4653cf2caa3508f4 | ctldl.windowsupdate.com | 393b8e82-fe40-429f-8e5e-c6b79a0f2b1c | 172.16.14.42 | WIN-TFB8L7BI77H |


### symantec-edr-endpoint-file-association-list
***
List of domain and file association.


#### Base Command

`symantec-edr-endpoint-file-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| query | Specify a search query as a Lucene query string.<br/>Example: query="first_seen: [2022-10-01T07:00:58.030Z  TO 2022-10-21T06:41:54.452Z]" <br/><br/>Note: For more details refer to Symantec EDR (On-Prem) API document https://apidocs.securitycloud.symantec.com/#. | Optional | 
| search_object | Specify a filters option in lieu of “query”. These filters will improve query performance. Possible values are: device_uid, sha256. | Optional | 
| search_value | Specify a search value. Supports a comma-separated query with multiple search values. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.EndpointFileAssociation.device_ip | String | The IPv6 or IPv4 address of the endpoint when this association was last updated. Example: 127.0.0.1. | 
| SymantecEDR.EndpointFileAssociation.device_name | String | The host name or, if unavailable, the IP address of the endpoint when this association was last updated. Example: 170915-000020. | 
| SymantecEDR.EndpointFileAssociation.device_uid | String | Unique ID of the endpoint that has this file. Example: 04cfc04b-5c7a-4aa8-b95b-79be23f768f4. | 
| SymantecEDR.EndpointFileAssociation.first_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this association. Example: 2018-02-04T09:00:00.577Z | 
| SymantecEDR.EndpointFileAssociation.folder | String | The folder where the file resides. This attribute does not include the name of the file. Example:c:\\windows\\system32\\. | 
| SymantecEDR.EndpointFileAssociation.last_seen | String | The timestamp \(in ISO 8601 format\) that specifies the last time detected of the event that resulted in the update of this association. Example: YYYY-MM-DDTHH:MM:SS.sssZ | 
| SymantecEDR.EndpointFileAssociation.name | String | The name of the file. This attribute does not include the path of the file. Example: sc.exe. | 
| SymantecEDR.EndpointFileAssociation.sha2 | String | The SHA256 checksum of the file \(hex string\). Example: eaab690ebd8ddf9ae452de1bc03b73c8154264dbd7a292334733b47a668ebf31. | 

#### Command example
```!symantec-edr-endpoint-file-association-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "EndpointFileAssociation": [
            {
                "device_ip": "172.16.14.42",
                "device_name": "win-tfb8l7bi77h",
                "device_uid": "393b8e82-fe40-429f-8e5e-c6b79a0f2b1c",
                "first_seen": "2022-10-21T07:00:17.831Z",
                "folder": "csidl_profile\\appdata\\roaming\\microsoft\\windows\\recent\\automaticdestinations",
                "last_seen": "2022-12-09T10:03:21.866Z",
                "name": "3353b940c074fd0c.automaticdestinations-ms",
                "sha2": "1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164"
            }
        ]
    }
}
```

#### Human Readable Output

>### Endpoint File Association List
>|FirstSeen|LastSeen|Sha2|Name|Folder|DeviceUid|DeviceIp|DeviceName|
>|---|---|---|---|---|---|---|---|
>| 2022-10-21T07:00:17.831Z | 2022-12-09T10:03:21.866Z | 1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164 | 3353b940c074fd0c.automaticdestinations-ms | csidl_profile\appdata\roaming\microsoft\windows\recent\automaticdestinations | 393b8e82-fe40-429f-8e5e-c6b79a0f2b1c | 172.16.14.42 | win-tfb8l7bi77h |


### symantec-edr-domain-instance-list
***
Get domain instances.


#### Base Command

`symantec-edr-domain-instance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| query | Specify a search query as a Lucene query string.<br/>Example: query="external_ip: 8.8.8.8". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.DomainInstance.data_source_url | String | Last URL accessed on this domain. Example: http://www.&lt;domain&gt;.com/shample/shample.exe. | 
| SymantecEDR.DomainInstance.data_source_url_domain | String | The name of the domain. Example: skyscan.com. | 
| SymantecEDR.DomainInstance.disposition | Number | Domain disposition: 0 = healthy/good, 1 = unknown, 2 = suspicious, 3 = bad. | 
| SymantecEDR.DomainInstance.first_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this instance. Example: YYYY-MM-DDTHH:MM:SS.sssZ | 
| SymantecEDR.DomainInstance.last_seen | String | The timestamp \(in ISO 8601 format\) that specifies the last time detected of the event that resulted in the update of this instance. Example: YYYY-MM-DDTHH:MM:SS.sssZ | 
| SymantecEDR.DomainInstance.external_ip | String | The IP address \(IPv4 or IPv6\) of the device/machine that accepted the connection. Example: 127.0.0.1. | 

#### Command example
```!symantec-edr-domain-instance-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "DomainInstances": [
            {
                "data_source_url": "",
                "data_source_url_domain": "ctldl.windowsupdate.com",
                "disposition": "Healthy",
                "external_ip": "",
                "first_seen": "2022-10-21T13:05:38.000Z",
                "last_seen": "2023-02-14T13:50:42.000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Domain Instances List
>|DataSourceUrlDomain|FirstSeen|LastSeen|Disposition|
>|---|---|---|---|
>| ctldl.windowsupdate.com | 2022-10-21T13:05:38.000Z | 2023-02-14T13:50:42.000Z | Healthy |


### symantec-edr-endpoint-instance-list
***
Get endpoint instances.


#### Base Command

`symantec-edr-endpoint-instance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| query | Specify a search query as a Lucene query string.<br/>. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.EndpointInstance.device_ip | String | The IP address of the endpoint. IPv4 or IPv6 format. Example: 192.168.0.250. | 
| SymantecEDR.EndpointInstance.device_name | String | The host name or, if unavailable, the IP address of the endpoint. Example: WIN-CRNK1KQJBC0. | 
| SymantecEDR.EndpointInstance.device_uid | String | Unique ID of the endpoint. Example: 12b1d2ce-dddb-4bcc-990e-28f44cf8ddcb. | 
| SymantecEDR.EndpointInstance.domain_or_workgroup | String | Domain or workgroup name depending on the configuration. Example: WORKGROUP. | 
| SymantecEDR.EndpointInstance.time | String | The timestamp \(in ISO 8601 format\) that specifies the creation or last update time of this instance. This is the creation time when there were no updates. Otherwise, it is the time of the last update. Example: YYYY-MM-DDTHH:MM:SS.sssZ | 
| SymantecEDR.EndpointInstance.user_name | String | The name of the user who originated or caused the event. Example: Administrator. | 
| SymantecEDR.EndpointInstance.ip_addresses | Unknown | Array of all the IP addresses \(IPv4 or IPv6\) associated with the endpoint. Example: \["192.168.0.250"\]. | 

#### Command example
```!symantec-edr-endpoint-instance-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "EndpointInstances": [
            {
                "device_ip": "172.16.14.58",
                "device_name": "172.16.14.58",
                "device_uid": "c0e1b083-9aba-48c0-9ba1-39c0c37c5851",
                "time": "2022-11-28T10:29:47.251Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Endpoint Instances List
>|DeviceUid|DeviceName|DeviceIp|Time|
>|---|---|---|---|
>| c0e1b083-9aba-48c0-9ba1-39c0c37c5851 | 172.16.14.58 | 172.16.14.58 | 2022-11-28T10:29:47.251Z |


### symantec-edr-file-instance-list
***
Get File Instances


#### Base Command

`symantec-edr-file-instance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to return. <br/>Default is 50. <br/>Note: If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| file_sha2 | Query unique file identifier (SHA2). | Optional | 
| query | Specify a search query as a Lucene query string.<br/>Example: query="name: svchost.exe". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.FileInstance.first_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this instance. Example: YYYY-MM-DDTHH:MM:SS.sssZ. | 
| SymantecEDR.FileInstance.folder | String | The folder where the file resides. This attribute does not include the name of the file. Example: c:\\users\\public\\pictures\\. | 
| SymantecEDR.FileInstance.last_seen | String | The timestamp \(in ISO 8601 format\) that Specifies the last time detected of the event that resulted in the update of this instance. Example: YYYY-MM-DDTHH:MM:SS.sssZ | 
| SymantecEDR.FileInstance.name | String | The name of the file. This attribute does not include the path of the file. Example: virus.exe. | 
| SymantecEDR.FileInstance.sha2 | String | The SHA256 checksum of the file \(hex string\) Example: eaab690ebd8ddf9ae452de1bc03b73c8154264dbd7a292334733b47a668ebf31. | 

#### Command example
```!symantec-edr-file-instance-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "FileInstance": {
            "first_seen": "2022-10-21T07:00:17.831Z",
            "folder": "csidl_profile\\appdata\\roaming\\microsoft\\windows\\recent\\automaticdestinations",
            "last_seen": "2022-12-09T10:03:21.866Z",
            "name": "3353b940c074fd0c.automaticdestinations-ms",
            "sha2": "1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164"
        }
    }
}
```

#### Human Readable Output

>### File Instances List
>|FirstSeen|LastSeen|Sha2|Name|Folder|
>|---|---|---|---|---|
>| 2022-10-21T07:00:17.831Z | 2022-12-09T10:03:21.866Z | 1dc0c8d7304c177ad0e74d3d2f1002eb773f4b180685a7df6bbe75ccc24b0164 | 3353b940c074fd0c.automaticdestinations-ms | csidl_profile\appdata\roaming\microsoft\windows\recent\automaticdestinations |


#### Command example
```!symantec-edr-file-instance-list file_sha2=302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4```
#### Context Example
```json
{
    "SymantecEDR": {
        "FileInstance": {
            "first_seen": "2022-10-21T19:31:20.770Z",
            "folder": "c:\\program files\\google\\chrome\\application\\106.0.5249.119",
            "last_seen": "2023-02-15T11:26:41.109Z",
            "name": "elevation_service.exe",
            "sha2": "302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4"
        }
    }
}
```

#### Human Readable Output

>### File Instances List
>|FirstSeen|LastSeen|Sha2|Name|Folder|
>|---|---|---|---|---|
>| 2022-10-21T07:00:39.964Z | 2023-02-15T11:26:41.104Z | 302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4 | elevation_service.exe | csidl_program_files\google\chrome\application\106.0.5249.119 |
>| 2022-10-21T19:31:20.770Z | 2023-02-15T11:26:41.109Z | 302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4 | elevation_service.exe | c:\program files\google\chrome\application\106.0.5249.119 |


### symantec-edr-system-activity-list
***
Get system activities or logs.


#### Base Command

`symantec-edr-system-activity-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'. | Optional | 
| page | The page number view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks'). | Optional | 
| end_time | From current time to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks', now). | Optional | 
| query | A search query as a Lucene query string.<br/>Example: query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| type_id | Request for specific system activities from the following events:  \n0 = Application Activity \n1000 = System Health \nRefer to this &lt;a href=\"https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html\"&gt;the following&lt;/a&gt; to check the type_id for the event type. | Optional | 
| severity | The severity. Possible values are: info, warning, minor, major, critical, fatal. | Optional | 
| status | The overall success or failure of the action reported by the event. Possible values are: \nUnknown (0)\nSuccess (1)\nFailure  (2). Possible values are: Unknown, Success, Failure. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.SystemActivity.device_time | String | The timestamp \(in ISO 8601 format\) that specifies the time at which the event occurred. | 
| SymantecEDR.SystemActivity.type_id | Number | The unique identifier for an event. Following is this events link and summary type IDs: https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.htmlSystem Activity Log Event Type: Viewing Symantec EDR appliance activities in the System Activity log \(broadcom.com\) | 
| SymantecEDR.SystemActivity.severity_id | Number | Event severity that specifies the importance of the event. Possible values are: 1 = info \(default\), 2 = warning, 3 = minor, 4 = major, 5 = critical, 6 = fatal. | 
| SymantecEDR.SystemActivity.message | String | Human-readable \(possibly multi-line\) event message or description of the event. | 
| SymantecEDR.SystemActivity.device_ip | String | The IPv6 or IPv4 address of the device that originated the event. | 
| SymantecEDR.SystemActivity.atp_node_role | Number | The role of the ATP appliance that generated the event. Possible values are: 0 = Pre-Bootstrap, 1 = Network Scanner, 2 = Management, 3 = Standalone Network, 4 = Standalone Endpoint, 5 = All in One. | 
| SymantecEDR.SystemActivity.category_id | String | The event type category. 4 = Audit. | 
| SymantecEDR.SystemActivity.device_cap | String | Name or caption of the ATP appliance that generated the event. | 
| SymantecEDR.SystemActivity.device_name | String | The device name \(i.e., the name of the endpoint or appliance associated with an event\). | 
| SymantecEDR.SystemActivity.feature_name | String | The name of the feature that originated the event. Applicable events: 1, 20, 21, 1000 Example: Search. | 
| SymantecEDR.SystemActivity.id | String | The event identifier for applicable events: 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8089, 8090 1 = Exists 2 = Partial. The outcome of the Session Audit event for applicable events: 20 0 = Unknown, 1 = Logon, 2 = Logoff. The outcome of the Entity Audit event for applicable events: 21  0 = Unknown, 1 = Create, 2 = Update, 3 = Delete | 
| SymantecEDR.SystemActivity.log_name | String | The index of the event. Note: This is for informational purpose and cannot be used as a filter. Use time as start_time to query for events. Example: epmp_events-2015-11-05. | 
| SymantecEDR.SystemActivity.log_time | String | The time the event was logged.  Example: YYYY-MM-DDThh:mm:ss.SSSZ. | 
| SymantecEDR.SystemActivity.remediation | String | Description of how to fix the issue, if applicable. Applicable events: 1000. Example: Enter valid connection settings for SEPM server \[SEPM_DB→&lt;IP&gt;:&lt;PORT&gt;\] for Symantec Endpoint Protection Correlation to work properly. | 
| SymantecEDR.SystemActivity.status_detail | String | The type of failure that may have occurred. The list includes, but is not limited to, the following: service_failure service_unavailable network_error certificate_error sw_update_error internal_error authentication_error connection_error. | 
| SymantecEDR.SystemActivity.status_exception | String | Low level exception message if available. Applicable events: 1000. | 
| SymantecEDR.SystemActivity.status_id | Number | The overall success or failure of the action reported by the event. Possible values are: 0 = Unknown 1 = Success 2 = Failure Applicable events: 1, 20, 21, 1000 Example: 1. | 
| SymantecEDR.SystemActivity.uuid | Unknown | The unique ID for this event. UUID uniquely identifies an event with a single event type \(type_id\). | 
| SymantecEDR.SystemActivity.process_pid | String | PID of the service for which an action was taken. Applicable events: 1000 Example: 31337. | 
| SymantecEDR.SystemActivity.data_sepm_server_db_ip_address | String | IP address of the SEPM database. | 
| SymantecEDR.SystemActivity.data_sepm_server_enabled | Boolean | Indicates whether ATP is enabled to log on and gather logs from this database. Applicable events: 1000. Default: false. Example: true. | 
| SymantecEDR.SystemActivity.data_sepm_server_db_type | String | Type of database: MSSQL or Sybase. Applicable events: 1000. Example: SYBASE. | 
| SymantecEDR.SystemActivity.data_sepm_server_user_name | String | User name of the SEPM database. Applicable events: 1000 Example: ATP_QUERY_USER. | 
| SymantecEDR.SystemActivity.data_sepm_server_status | String | Status of SEPM database configuration with ATP. Applicable events: 1000 Example: healthy. | 
| SymantecEDR.SystemActivity.data_sepm_server_sepm_name | String | User-provided name for SEPM database server. Applicable events: 1000 Example: SEPM_DB. | 
| SymantecEDR.SystemActivity.data_sepm_server_db_port | Number | Database port of SEPM database. Applicable events: 1000 Example: 8081.  | 
| SymantecEDR.SystemActivity.data_sepm_server_db_name | String | SEPM database name. | 

#### Command example
```!symantec-edr-system-activity-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "SystemActivity": {
            "atp_node_role": "All in One",
            "device_cap": "EDR",
            "device_ip": "192.168.20.8",
            "device_name": "localhost.localdomain",
            "device_time": "2023-02-15T11:33:54.112Z",
            "feature_name": "AdministratorTask",
            "log_name": "atp_system_log-2023-02-15",
            "log_time": "2023-02-15T11:33:54.153Z",
            "message": "Command submit_to_sandbox with command id 98a42ac7c11c4610b4b977a0371bf0c9-2023-02-15 completed.",
            "pid": 12719,
            "product_name": "Symantec Endpoint Detection and Response",
            "product_ver": "4.6.8-8",
            "severity_id": "Info",
            "status_id": "Success",
            "timezone": 0,
            "type_id": 1,
            "uuid": "a079d400-ad24-11ed-fac3-00000001b4ee"
        }
    }
}
```

#### Human Readable Output

>### System Activities List
>|Time|TypeId|SeverityId|Message|DeviceIp|AtpNodeRole|StatusId|
>|---|---|---|---|---|---|---|
>| 2023-02-15T11:33:54.112Z | 1 | Info | Command submit_to_sandbox with command id 98a42ac7c11c4610b4b977a0371bf0c9-2023-02-15 completed. | 192.168.20.8 | All in One | Success |


### symantec-edr-audit-event-list
***
Get Audit Events


#### Base Command

`symantec-edr-audit-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'. | Optional | 
| start_time | The beginning of the search time frame. Supports ISO (e.g., "yyyy-MM-dd’T’HH:mm:ss.SSSZ") or '10 seconds', '5 minutes', '2 days', '1 weeks'). | Optional | 
| end_time | The end of the search time frame. Supports ISO (e.g., "yyyy-MM-dd’T’HH:mm:ss.SSSZ") and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks', now). | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| query | A search query as a Lucene query string.<br/>Example: query="type_id:(4096 OR 4098 OR 4123)"<br/><br/>The search query is broken up into terms and operators. <br/><br/>There are two types of terms: Single Terms and Phrases.<br/>      (a) A Single Term is a single word such as "test" or "hello"<br/>      (b) A Phrase is a group of words surrounded by double quotes such as "hello dolly"<br/><br/>When creating a search query string, consider the following:<br/><br/>1. You can search any field by specifying the field name followed by a colon ":" and then the term you are looking for<br/>2. Escape special characters that are part of the query syntax. To escape a special character use the \ before the character. The current list of special characters are '+, -, &amp;&amp;, \|\|, !, ( ), { }, [ ], ^, ", ~ ,*, ?, \, :'<br/>3. Date value should follow ISO 8601 date stamp standard format (yyyy-MM-dd'T'HH:mm:ss.SSSXXX)<br/>4. Supported Boolean operators for complex query are: AND OR + - NOT Note: Boolean operators must be ALL CAPS<br/>5. Multiple terms can be combined together with Boolean operators to form a more complex query in the query clause<br/>6. Use parentheses to group clauses to form sub-queries<br/>7. Defaults to all events for the start_time and end_time specified in the query<br/>8. The maximum length of the query string is 10240 characters. | Optional | 
| type_id | The type ID. Refer to the event summary type IDs link: https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.AuditEvent.user_agent_ip | String | IP address of the endpoint that originated or caused the event. | 
| SymantecEDR.AuditEvent.entity_result.data.incident_management.uuid | String | The GUID assigned for this incident | 
| SymantecEDR.AuditEvent.entity_result.type | String | The type of the managed entity.Depending on this entity type, data would contain the corresponding entity content. Refer to this link  https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/generated-pdfs/EDR_API_Legacy.pdf section 3.74 Entity for all the Possible values for managed entity types | 
| SymantecEDR.AuditEvent.entity_result.uid | String | Unique identifier associated with the managed entity. | 
| SymantecEDR.AuditEvent.entity_result.name | String | The name of the managed entity. | 
| SymantecEDR.AuditEvent.status_id | Number | The overall success or failure of the action reported by the event. Values are: 0 = Unknown 1 = Success 2 = Failure. | 
| SymantecEDR.AuditEvent.feature_name | String | The name of the feature that originated the event. Example: Search. | 
| SymantecEDR.AuditEvent.device_ip | String | The IPv6 or IPv4 address of the device that originated the event. | 
| SymantecEDR.AuditEvent.user_name | String | The username or ID that originated or caused the event. | 
| SymantecEDR.AuditEvent.atp_node_role | Number | The role of the ATP appliance that generated the event. Possible values are: 0 = Pre-Bootstrap, 1 = Network Scanner, 2 = Management, 3 = Standalone Network, 4 = Standalone Endpoint 5 = All in One Applicable events: 1, 20, 21, 1000. | 
| SymantecEDR.AuditEvent.category_id | Number | The event type category. 4 = Audit. | 
| SymantecEDR.AuditEvent.device_uid | String | Unique ID of the device that originated the event. Example: 7c056576-860b-4eb9-b49c-3c349edb733f. | 
| SymantecEDR.AuditEvent.log_name | String | The index of the event. Note: This is for informational purpose and cannot be used as a filter. Use time as start_time to query for events. Example: epmp_events-2015-11-05. | 
| SymantecEDR.AuditEvent.count | Number | The count of system changes in the event. | 
| SymantecEDR.AuditEvent.device_name | String | The device name \(i.e., the name of the endpoint or appliance associated with an event\). | 
| SymantecEDR.AuditEvent.message | String | Human-readable \(multi-line\) event message or description of the event. | 
| SymantecEDR.AuditEvent.log_time | Date | The time the event was logged. Example: YYYY-MM-DDTHH:MM:SS.sssZ. | 
| SymantecEDR.AuditEvent.severity_id | Number | Event severity that specifies the importance of the event. Values are:  1 = info \(default\), 2 = warning, 3 = minor, 4 = major, 5 = critical, 6 = fatal. | 
| SymantecEDR.AuditEvent.device_cap | String | Name or caption of the ATP appliance that generated the event. Example: EDR. | 
| SymantecEDR.AuditEvent.id | Number | The event identifier. 1 = Exists, 2 = Partial. | 
| SymantecEDR.AuditEvent.device_time | Date | The timestamp \(in ISO 8601 format\) that specifies the time at which the event occurred. Example: YYYY-MM-DDTHH:MM:SS.sssZ. | 
| SymantecEDR.AuditEvent.product_ver | String | The version of the product that originated the event. Example: 4.6.8-8. | 
| SymantecEDR.AuditEvent.device_end_time | Date | The end time of an event \(in format yyyy-MM-dd'T'HH:mm:ss.SSSZ\). This is used with the aggregation count field. | 
| SymantecEDR.AuditEvent.type_id | Number | The unique identifier for an event. The following events are supported: For type_id details refer to “https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html”. | 
| SymantecEDR.AuditEvent.uuid | String | The unique ID for this event. UUID uniquely identifies an event with a single event type \(type_id\). | 
| SymantecEDR.AuditEvent.product_name | String | The name of the product that originated the event. Example: "Symantec Endpoint Detection and Response”. | 
| SymantecEDR.AuditEvent.status_detail | String | The type of success or failure for the audit events. | 
| SymantecEDR.AuditEvent.timezone | Number | The timezone offset in minutes. For UTC this will always be 0. Example: 0. | 
| SymantecEDR.AuditEvent.user_uid | String | Unique ID of the user who originated the event or the user on whose behalf the event occurred. | 

#### Command example
```!symantec-edr-audit-event-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "AuditEvent": {
            "atp_node_role": 5,
            "category_id": 4,
            "count": 1,
            "device_cap": "EDR",
            "device_end_time": "2023-02-15T11:34:25.912Z",
            "device_ip": "192.168.20.8",
            "device_name": "localhost.localdomain",
            "device_time": "2023-02-15T11:34:25.912Z",
            "device_uid": "2B034D56-DBDB-9D58-DBA5-1CCB980276F2",
            "feature_name": "Incident",
            "id": 2,
            "log_name": "atp_audit_log-2023-02",
            "log_time": "2023-02-15T11:34:26.159Z",
            "message": "Incident Closed Successfully.",
            "product_name": "Symantec Endpoint Detection and Response",
            "product_ver": "4.6.8-8",
            "severity_id": "Info",
            "status_detail": "Success",
            "status_id": "Success",
            "timezone": 0,
            "type_id": 21,
            "user_agent_ip": "127.0.0.1",
            "user_name": "SEDR API",
            "user_uid": "O2ID.atp-customer.atp-domain.dbq9fmcjk132kmha7f9584qvr7",
            "uuid": "b36e1f80-ad24-11ed-e0f5-00000001b4f0"
        }
    }
}
```

#### Human Readable Output

>### Audit Event List
>|Time|TypeId|FeatureName|Message| UserAgentIp |UserName|Severity|DeviceName|DeviceIp|Uuid|StatusId|
>|---|---|---|-------------|---|---|---|---|---|---|---|
>| 2023-02-15T11:34:25.912Z | 21 | Incident | Incident Closed Successfully. | 127.0.0.1 | SEDR API | Info | localhost.localdomain | 192.168.20.8 | b36e1f80-ad24-11ed-e0f5-00000001b4f0 | Success |


### symantec-edr-event-list
***
Get events or system alerts from EDR on-premise.


#### Base Command

`symantec-edr-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks'). | Optional | 
| end_time | From current time to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks', now). | Optional | 
| query | A search query as a Lucene query string.<br/>Example: query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| type_id | The type ID. Refer to event summary type IDs link: https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html. | Optional | 
| severity | The severity. Possible values are: info, warning, minor, major, critical, fatal. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Event.type_id | Number | The unique identifier for an event. Refer to “https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/generated-pdfs/EDR_API_Legacy.pdf”. | 
| SymantecEDR.Event.severity_id | Number | Event severity that specifies the importance of the event. Values are: 1 = info \(default\), 2 = warning, 3 = minor, 4 = major, 5 = critical, 6 = fatal. | 
| SymantecEDR.Event.device_time | Date | The timestamp \(in ISO 8601 format\) that specifies the time at which the event occurred. | 
| SymantecEDR.Event.log_time | Date | The time the event was logged. | 
| SymantecEDR.Event.device_uid | String | Unique ID of the device that originated the event. | 
| SymantecEDR.Event.device_name | String | The domain name of the client computer. | 
| SymantecEDR.Event.device_ip | String | The IPv6 or IPv4 address of the device that originated the event. | 
| SymantecEDR.Event.device_os_name | String | The operating system running on the device_type that originated the event. The values include, but are not limited to: Windows, Mac OSX, IOS, Android. | 
| SymantecEDR.Event.user_name | String | The username or ID that originated or caused the event. | 
| SymantecEDR.Event.user_domain | String | Event user associated with the domain. | 
| SymantecEDR.Event.user_sid | String | Unique ID of the user who originated the event or the user on whose behalf the event occurred. | 
| SymantecEDR.Event.device_domain | String | The domain where device resides. Example: "internal.somecompany.com”. | 
| SymantecEDR.Event.operation | Number | The OS operation that initiated the event. Refer to “https://techdocs.broadcom.com/content/dam/broadcom/techdocs/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/generated-pdfs/EDR_API_Legacy.pdf”. | 
| SymantecEDR.Event.event_actor.pid | Number | The process identifier as reported by the operating system. | 
| SymantecEDR.Event.event_actor.uid | String | The unique identifier of the process. Example: "2ef07353-c1d2-409d-addd-2eed37a87e56". Applicable events: 8007. | 
| SymantecEDR.Event.event_actor.cmd_line | String | The command line that was used to launch the process. Applicable events: 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009, 8081. | 
| SymantecEDR.Event.event_actor.start_time | Date | Start time for the originating event. | 
| SymantecEDR.Event.event_actor.signature_level_id | Number | A numeric representation of the signature level. Possible values are: 0 = UNKNOWN, 10 = UNSIGNED, 20 = SIGNED_BUT_UNTRUSTED, 30 = SIGNED, 40 = CLASS3_SIGNED, 50 = SYMC_SIGNED, 60 = MICROSOFT_SIGNED, 70 = MICROSOFT_OS_COMPONENT Applicable events: 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009. | 
| SymantecEDR.Event.event_actor.integrity_id | Number | The process integrity level \(Windows only\). Possible values are: 0 = Unknown, 1 = Untrusted, 2 = Low, 3 = Medium, 4 = Medium Plus, 5 = High, 6 = System, 7 = Protected Applicable events: 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009. | 
| SymantecEDR.Event.event_actor.user.name | String | The username or ID that originated or caused the event. | 
| SymantecEDR.Event.event_actor.user.sid | String | Event actor user security identifier. | 
| SymantecEDR.Event.event_actor.file.name | String | The name of the file. | 
| SymantecEDR.Event.event_actor.file.md5 | String | The MD5 checksum of the file. | 
| SymantecEDR.Event.event_actor.file.modified | Date | Threat file modified date in ISO 8601 format. | 
| SymantecEDR.Event.event_actor.file.path | String | The full path to the object. | 
| SymantecEDR.Event.event_actor.file.normalized_path | String | The CSIDL normalized path name \(for Windows only\). | 
| SymantecEDR.Event.event_actor.file.signature_company_name | String | The name of the company on the certificate. | 
| SymantecEDR.Event.event_actor.file.signature_value_ids | Number | An integer array that contains one or more of the following signature values as derived from the Signature Bits. Possible values are: 0 = Unsigned, 1 = Signed, 2 = Code Signed, 3 = Class 3 Signed, 4 = Symantec Signed, 5 = Microsoft Signed, 6 = OS Component, 7 = Windows Hardware Wuality Labs \(WHQL\), 8 = Signer Explicitly Trusted, 9 = Signature Has Extra Date, 10 = Signature Uses MD5, 11 = Signature Uses SHA-1,12 = Signature Chain Not Valid, 13 = Signature From Catalog, 14 = Hash Does Not Match, 15 = Local Trusted Certificate, 16 = Trustworthy, 17 = Well Known Trusted Root Certificate, 18 = Heuristically Trustworthy, 19 = Symantec Internal, 20 = Signature Uses SHA-256, 21 = Signature Uses SHA-384, 22 = Signature Uses SHA-512, 23 = Signer Explicitly Revoked. | 
| SymantecEDR.Event.event_actor.file.sha2 | String | The SHA256 checksum of the file \(hex string\). | 
| SymantecEDR.Event.event_actor.file.original_name | String | The original name of the file. | 
| SymantecEDR.Event.process.pid | Number | The process identifier as reported by the operating system. | 
| SymantecEDR.Event.process.uid | String | The unique identifier of the process. | 
| SymantecEDR.Event.process.cmd_line | String | The command line that was used to launch the process. | 
| SymantecEDR.Event.process.signature_level_id | Number | A numeric representation of the signature level. Possible values are: 0 = Unknown, 10 = Unsigned, 20 = Signed But Untrusted, 30 = Signed, 40 = Class 3 Signed, 50 = SYMC Signed, 60 = Microsoft Signed, 70 = Microsoft OS Component. | 
| SymantecEDR.Event.process.integrity_id | Number | The process integrity level \(Windows only\). Possible values are:  0 = Unknown, 1 = Untrusted,  2 = Low,  3 = Medium,  4 = Medium Plus,  5 = High, 6 = System,  7 = Protected. | 
| SymantecEDR.Event.process.user.name | String | The username or ID that originated or caused the event. | 
| SymantecEDR.Event.process.user.sid | String | Event actor user security identifier. | 
| SymantecEDR.Event.process.file.normalized_path | String | The CSIDL normalized path name \(for Windows only\). | 
| SymantecEDR.Event.process.file.name | String | The name of the file. | 
| SymantecEDR.Event.process.file.md5 | String | The MD5 checksum of the file. | 
| SymantecEDR.Event.process.file.modified | Date | Threat file modified date in ISO 8601 format. | 
| SymantecEDR.Event.process.file.path | String | The full path to the object. | 
| SymantecEDR.Event.process.file.signature_company_name | String | The name of the company on the certificate. | 
| SymantecEDR.Event.process.file.signature_value_ids | Number | An integer array that contains one or more of the following signature values as derived from the Signature Bits. Possible values are: 0 = Unsigned, 1 = Signed, 2 = Code Signed, 3 = Class 3 Signed, 4 = Symantec Signed, 5 = Microsoft Signed, 6 = OS Component, 7 = Windows Hardware Wuality Labs \(WHQL\), 8 = Signer Explicitly Trusted, 9 = Signature Has Extra Date, 10 = Signature Uses MD5, 11 = Signature Uses SHA-1,12 = Signature Chain Not Valid, 13 = Signature From Catalog, 14 = Hash Does Not Match, 15 = Local Trusted Certificate, 16 = Trustworthy, 17 = Well Known Trusted Root Certificate, 18 = Heuristically Trustworthy, 19 = Symantec Internal, 20 = Signature Uses SHA-256, 21 = Signature Uses SHA-384, 22 = Signature Uses SHA-512, 23 = Signer Explicitly Revoked. | 
| SymantecEDR.Event.process.file.sha2 | String | The SHA256 checksum of the file \(hex string\). | 
| SymantecEDR.Event.process.file.original_name | String | The original name of the file. | 
| SymantecEDR.Event.enriched_data.rule_name | String | The name of the IntelliFilter rule that observes all of the endpoint data recorded events on the client. | 
| SymantecEDR.Event.enriched_data.category_name | String | The IntelliFilter rules fall into the following categories:  System File Launched Or Loaded From Unexpected Location = 8001, 8002. Suspicious PowerShell Script Executed = 8001 Suspicious N-gram = 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009. Process Termination = 8001, Process Launch = 8001, Load Point Modification = 8005, 8006, File with Double Exe Extension \(.jpg.exe\) = 8003, Attempt to Change to Windows Event Logs or Registry Settings = 8005, 8006, Suspicious Protocol-Port Usage By System Processes = 8007, All events = 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009, Applicable events: 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009 | 
| SymantecEDR.Event.enriched_data.category_id | Number | The possible values of supported category_id. 0 = All Events, 1 = Suspicious N-Gram, 2 = Process Launch , 3 = Process Termination , 100 = Suspicious Protocol-Port Usage By System Processes, 102 = Suspicious PowerShell commands. | 
| SymantecEDR.Event.ref_uid | String | The event reference UID. | 
| SymantecEDR.Event.uuid | String | The unique ID for this event. UUID uniquely identifies an event with a single event type \(type_id\). | 
| SymantecEDR.Event.log_name | String | The index of the event. Note: This is for informational purpose and cannot be used as a filter. Use time as start_time to query for events. | 

#### Command example
```!symantec-edr-event-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "Event": {
            "cmd_line": "C:\\Windows\\system32\\DllHost.exe /Processid:{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}",
            "device_domain": "WORKGROUP",
            "device_ip": "172.16.14.42",
            "device_name": "WIN-TFB8L7BI77H",
            "device_os_name": "Windows Server 2019 ",
            "device_time": "2023-02-15T11:29:31.248Z",
            "device_uid": "393b8e82-fe40-429f-8e5e-c6b79a0f2b1c",
            "enriched_data_category_id": 3,
            "enriched_data_category_name": "Process Termination",
            "enriched_data_rule_name": "eProcessClose",
            "event_actor_cmd_line": "C:\\Windows\\system32\\DllHost.exe /Processid:{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}",
            "event_actor_integrity_id": 6,
            "event_actor_pid": 17068,
            "event_actor_signature_level_id": 60,
            "event_actor_start_time": "2023-02-15T11:29:26.217Z",
            "event_actor_uid": "EFDEC4CC-ACFF-F1ED-821C-98261F32744E",
            "file_file_md5": "d2ab39ea2c0fcd172751f84bda723a97",
            "file_file_modified": "2018-09-15T07:12:24.564Z",
            "file_file_name": "dllhost.exe",
            "file_file_normalized_path": "CSIDL_SYSTEM\\dllhost.exe",
            "file_file_original_name": "dllhost.exe",
            "file_file_path": "c:\\windows\\system32\\dllhost.exe",
            "file_file_sha2": "c4e078607db2784be7761c86048dffa6f3ef04b551354a32fcdec3b6a3450905",
            "file_file_signature_company_name": "Microsoft Windows",
            "integrity_id": 6,
            "log_name": "epmp_events-fdr-2023-02-15",
            "log_time": "2023-02-15T11:33:30.148Z",
            "operation": 2,
            "pid": 17068,
            "ref_uid": "2C7DF1FF-FB83-4A63-8C85-17327F4C9F26",
            "severity_id": "Info",
            "signature_level_id": 60,
            "type_id": 8001,
            "uid": "EFDEC4CC-ACFF-F1ED-821C-98261F32744E",
            "user_domain": "NT AUTHORITY",
            "user_name": "SYSTEM",
            "user_sid": "S-1-5-18",
            "user_user_name": "SYSTEM",
            "user_user_sid": "S-1-5-18",
            "uuid": "03cbf700-ad24-11ed-c212-00000001b4eb"
        }
    }
}
```

#### Human Readable Output

>### Event List
>|Time|TypeId|Description|DeviceName|SeverityId|DeviceIp|Operation|DeviceDomain|UserName|
>|---|---|---|---|---|---|---|---|---|
>| 2023-02-15T11:29:31.248Z | 8001 |  logged:  | WIN-TFB8L7BI77H | Info | 172.16.14.42 | 2 | WORKGROUP | SYSTEM |


### symantec-edr-incident-event-list
***
Get events for incidents.


#### Base Command

`symantec-edr-incident-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'.<br/>. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks').<br/><br/>. | Optional | 
| end_time | From current time to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks', now).<br/>. | Optional | 
| query | A search query as a Lucene query string.<br/><br/>Example:<br/>query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| type_id | The unique identifier for an event. Refer to this link for Event Type IDs :<br/> https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html. | Optional | 
| severity | The severity. Default: All severity types. Possible values are: info, warning, minor, major, critical, fatal. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.IncidentEvent.type_id | Number | The unique identifier for an event type. | 
| SymantecEDR.IncidentEvent.severity_id | Number | Event severity that specifies the importance of the event. Possible values are: 1 = info \(default\) 2 = warning 3 = minor 4 = major 5 = critical 6 = fatal | 
| SymantecEDR.IncidentEvent.device_time | Date | The timestamp \(in ISO 8601 format\) that specifies the time at which the event occurred. | 
| SymantecEDR.IncidentEvent.log_time | Date | The time the event was logged. | 
| SymantecEDR.IncidentEvent.device_uid | String | Unique ID of the endpoint that has this file. | 
| SymantecEDR.IncidentEvent.device_name | String | The host name or, if unavailable, the IP address of the endpoint when this association was last updated. | 
| SymantecEDR.IncidentEvent.device_ip | String | The IPv6 or IPv4 address of the endpoint when this association was last updated. | 
| SymantecEDR.IncidentEvent.device_os_name | String | The operating system running on the device_type that originated the event. The possible values include, but are not limited to, the following:  Windows, Mac OSX, IOS, Android. | 
| SymantecEDR.IncidentEvent.user_name | String | The username or ID that originated or caused the event. | 
| SymantecEDR.IncidentEvent.user_domain | String | Event user associated with the domain | 
| SymantecEDR.IncidentEvent.user_sid | String | Unique ID of the user that originated the event or the user on whose behalf the event occurred. | 
| SymantecEDR.IncidentEvent.incident | String | The unique ID of the incident that is related to this event. Applicable events: All events associated with an incident. | 
| SymantecEDR.IncidentEvent.device_domain | String | The domain where device resides. | 
| SymantecEDR.IncidentEvent.operation | Number | The OS operation that initiated the event. | 
| SymantecEDR.IncidentEvent.event_actor.pid | Number | The process identifier as reported by the operating system. | 
| SymantecEDR.IncidentEvent.event_actor.uid | String | The unique identifier of the process. | 
| SymantecEDR.IncidentEvent.event_actor.cmd_line | String | The command line that was used to launch the process. | 
| SymantecEDR.IncidentEvent.event_actor.start_time | Date | Start_time for the originating event. | 
| SymantecEDR.IncidentEvent.event_actor.signature_level_id | Number | A numeric representation of the signature level. Possible values are: 0 = Unknown, 10 = Unsigned, 20 = Signed But Untrusted, 30 = Signed, 40 = Class 3 Signed, 50 = SYMC Signed, 60 = Microsoft Signed, 70 = Microsoft OS Component | 
| SymantecEDR.IncidentEvent.event_actor.integrity_id | Number | The process integrity level \(Windows only\). Possible values are: 0 = Unknown, 1 = Untrusted, 2 = Low, 3 = Medium, 4 = Medium Plus, 5 = High, 6 = System, 7 = Protected | 
| SymantecEDR.IncidentEvent.event_actor.user.name | String | The username or ID that originated or caused the event. | 
| SymantecEDR.IncidentEvent.event_actor.user.sid | String | Event Actor user security identifier. | 
| SymantecEDR.IncidentEvent.event_actor.file.name | String | The name of the file. | 
| SymantecEDR.IncidentEvent.event_actor.file.md5 | String | The MD5 checksum of the file. | 
| SymantecEDR.IncidentEvent.event_actor.file.modified | Date | Threat file modified date in ISO 8601 format. | 
| SymantecEDR.IncidentEvent.event_actor.file.path | String | The full path to the object. | 
| SymantecEDR.IncidentEvent.event_actor.file.normalized_path | String | The CSIDL normalized path name;Windows Only. | 
| SymantecEDR.IncidentEvent.event_actor.file.signature_company_name | String | The name of the company on the certificate. | 
| SymantecEDR.IncidentEvent.event_actor.file.signature_value_ids | Number | An integer array that contains one or more of the following signature values as derived from the Signature Bits. Possible values are: 0 = Unsigned, 1 = Signed, 2 = Code Signed, 3 = Class 3 Signed, 4 = Symantec Signed, 5 = Microsoft Signed, 6 = OS Component, 7 = Windows Hardware Wuality Labs \(WHQL\), 8 = Signer Explicitly Trusted, 9 = Signature Has Extra Date, 10 = Signature Uses MD5, 11 = Signature Uses SHA-1,12 = Signature Chain Not Valid, 13 = Signature From Catalog, 14 = Hash Does Not Match, 15 = Local Trusted Certificate, 16 = Trustworthy, 17 = Well Known Trusted Root Certificate, 18 = Heuristically Trustworthy, 19 = Symantec Internal, 20 = Signature Uses SHA-256, 21 = Signature Uses SHA-384, 22 = Signature Uses SHA-512, 23 = Signer Explicitly Revoked. | 
| SymantecEDR.IncidentEvent.event_actor.file.sha2 | String | The SHA256 checksum of the file \(hex string\). | 
| SymantecEDR.IncidentEvent.event_actor.file.original_name | String | The original name of the file. | 
| SymantecEDR.IncidentEvent.process.pid | Number | The process identifier as reported by the operating system. | 
| SymantecEDR.IncidentEvent.process.uid | String | The unique identifier of the process. | 
| SymantecEDR.IncidentEvent.process.cmd_line | String | The command line that was used to launch the process. | 
| SymantecEDR.IncidentEvent.process.signature_level_id | Number | A numeric representation of the signature level. Possible values are: 0 = UNKNOWN, 10 = UNSIGNED, 20 = SIGNED_BUT_UNTRUSTED, 30 = SIGNED, 40 = CLASS3_SIGNED, 50 = SYMC_SIGNED, 60 = MICROSOFT_SIGNED, 70 = MICROSOFT_OS_COMPONENT | 
| SymantecEDR.IncidentEvent.process.integrity_id | Number | The process integrity level \(Windows only\). Possible values are:  0 = Unknown, 1 = Untrusted,  2 = Low,  3 = Medium,  4 = Medium Plus,  5 = High, 6 = System,  7 = Protected. | 
| SymantecEDR.IncidentEvent.process.user.name | String | Process user name | 
| SymantecEDR.IncidentEvent.process.user.sid | String | Process unique SID | 
| SymantecEDR.IncidentEvent.process.file.normalized_path | String | The CSIDL normalized path name;Windows Only. | 
| SymantecEDR.IncidentEvent.process.file.name | String | The name of the file. | 
| SymantecEDR.IncidentEvent.process.file.md5 | String | The MD5 checksum of the file | 
| SymantecEDR.IncidentEvent.process.file.modified | Date | The process identifier as reported by the operating system. | 
| SymantecEDR.IncidentEvent.process.file.path | String | The full path to the object. | 
| SymantecEDR.IncidentEvent.process.file.signature_company_name | String | The name of the company on the certificate. | 
| SymantecEDR.IncidentEvent.process.file.signature_value_ids | Number | The issuer of the signature. Applicable events: 4096, 4099 | 
| SymantecEDR.IncidentEvent.enriched_data.rule_name | String | The name of the IntelliFilter rule that observes all of the endpoint data recorded events on the client. | 
| SymantecEDR.IncidentEvent.enriched_data.suspicion_score | Number | Score that determines the suspiciousness of the action captured in the event. 1. Very Low: 1-25 \(Informational\) , 2. Low: 26-50 \(Suspicious\) , 3. Moderate: 51-75 \(Suspicious\) , 4. Severe: 76-87 \(Malicious\), 5. Very Severe: 88-100 \(Malicious\). | 
| SymantecEDR.IncidentEvent.enriched_data.category_name | String | The IntelliFilter rules fall into the following categories:  System File Launched Or Loaded From Unexpected Location = 8001, 8002. Suspicious PowerShell Script Executed = 8001 Suspicious N-gram = 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009. Process Termination = 8001, Process Launch = 8001, Load Point Modification = 8005, 8006, File with Double Exe Extension \(.jpg.exe\) = 8003, Attempt to Change to Windows Event Logs or Registry Settings = 8005, 8006, Suspicious Protocol-Port Usage By System Processes = 8007, All events = 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009, Applicable events: 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009 | 
| SymantecEDR.IncidentEvent.enriched_data.category_id | Number | The possible values of supported category_id. 0 = All Events, 1 = Suspicious N-Gram, 2 = Process Launch , 3 = Process Termination , 100 = Suspicious Protocol-Port Usage By System Processes, 102 = Suspicious PowerShell commands | 
| SymantecEDR.IncidentEvent.enriched_data.rule_description | String | Enriched rule description | 
| SymantecEDR.IncidentEvent.event_uuid | String | The unique event UUID | 
| SymantecEDR.IncidentEvent.attacks.technique_uid | String | The MITRE technique ID for the attack. Possible values are listed in https://attack.mitre.org/techniques/enterprise. | 
| SymantecEDR.IncidentEvent.attacks.technique_name | String | The MITRE technique name for the attack. | 
| SymantecEDR.IncidentEvent.attacks.tactic_ids | Number | The MITRE tactic ID\(s\) for the attack. Tactic ID values are: 1 = Initial Access , 2 = Execution , 3 = Persistence , 4 = Privilege Escalation , 5 = Defense Evasion , 6 = Credential Access , 7 = Discovery , 8 = Lateral Movement , 9 = Collection , 10 = Exfltration , 11 = Command and Control | 
| SymantecEDR.IncidentEvent.attacks.tactic_uids | String | THe tactic Unique IDs. | 
| SymantecEDR.IncidentEvent.event_source | Number | Indicates the reason of event being related to an incident. Possible values are: 1 - Event triggered the incident , 2 - Event is part of process lineage tracking, 3 - Event is likely related to the incident | 
| SymantecEDR.IncidentEvent.ref_uid | String | The event reference UID. | 
| SymantecEDR.IncidentEvent.correlation_uid | String | Event Correlation UID. | 
| SymantecEDR.IncidentEvent.uuid | String | The unique id for this event. | 
| SymantecEDR.IncidentEvent.log_name | String | The index of the event.  Note: This is for informational purpose and cannot be used as a filter. Use time as start_time to query for events. | 

#### Command example
```!symantec-edr-incident-event-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "IncidentEvent": {
            "data_direction": 0,
            "device_ip": "172.16.14.42",
            "device_name": "WIN-TFB8L7BI77H",
            "device_time": "2023-01-26T18:55:27.296Z",
            "device_uid": "393b8e82-fe40-429f-8e5e-c6b79a0f2b1c",
            "event_source": 1,
            "event_uuid": "ff61e400-9daa-11ed-dcb5-00000000e61e",
            "incident": "ffcc1780-9daa-11ed-e218-000000000001",
            "internal_hostname": "WIN-TFB8L7BI77H",
            "internal_ip": "172.16.14.42",
            "log_name": "epmp_incident-2023-01-26",
            "log_time": "2023-01-26T18:55:27.992Z",
            "request_source": "user_submit",
            "sandbox_service": "cynic",
            "sep_installed": true,
            "severity_id": "",
            "type_id": 4117,
            "user_name": "Administrator",
            "uuid": "0025a930-9dab-11ed-f087-00000000000c"
        }
    }
}
```

#### Human Readable Output

>### Event for Incident List
>|Time|TypeId|Description|DeviceName|DeviceIp|EventUuid|Incident|UserName|
>|---|---|---|---|---|---|---|---|
>| 2023-01-26T18:55:27.296Z | 4117 |  logged:  | WIN-TFB8L7BI77H | 172.16.14.42 | ff61e400-9daa-11ed-dcb5-00000000e61e | ffcc1780-9daa-11ed-e218-000000000001 | Administrator |


### symantec-edr-incident-list
***
Get incidents from Symantec EDR on-premise API.


#### Base Command

`symantec-edr-incident-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for the number of events listed per page.<br/>Default is '50'.<br/>. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks').<br/><br/>. | Optional | 
| end_time | From current time to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks', now).<br/>. | Optional | 
| query | A search query as a Lucene query string.<br/><br/>Example:<br/>query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| incident_id | An incident ID. | Optional | 
| priority | The incident severity/priority level. Possible values are: High, Medium, Low. | Optional | 
| status | The incident status. Possible values are: Open, Waiting, In-progress, Closed. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Incident.atp_incident_id | Number | A unique identifier for this incident. | 
| SymantecEDR.Incident.log_name | String | The index of the incident. Note: This is for informational purpose and cannot be used as a filter. Use time as start_time to query for incidents. Example: epmp_incident-2018-03-01 | 
| SymantecEDR.Incident.summary | String | Summary information about the incident. | 
| SymantecEDR.Incident.priority_level | Number | Priority level of the incident. Possible values are: Low, Medium, High | 
| SymantecEDR.Incident.last_event_seen | Date | The creation time \(in ISO 8601 format\) when the last event associated with the incident was created. Matches the last event’s time field. | 
| SymantecEDR.Incident.time | Date | The creation time \(in ISO 8601 format\) of the incident. | 
| SymantecEDR.Incident.rule_name | String | The name of the rule that triggered this incident. | 
| SymantecEDR.Incident.first_event_seen | Date | The creation time \(in ISO 8601 format\) when the first event associated with the incident was created. Matches the first event’s time field. This is likely before the incident’s creation time field given incidents are created after their first event is seen. | 
| SymantecEDR.Incident.state | Number | The current state of the incident. Possible values are: Open, Waiting, In-progress, Closed | 
| SymantecEDR.Incident.detection_type | String | Incident detection type. | 
| SymantecEDR.Incident.device_time | Date | The timestamp \(in ISO 8601 format\) that specifies the time at which the event occurred. | 
| SymantecEDR.Incident.recommended_action | String | Recommended action for this incident. Possible actions could be isolating an endpoint, deleting fle from endpoint, blacklist URL, or domain, etc. | 
| SymantecEDR.Incident.updated | Date | The time \(in ISO 8601 format\) of last modification. | 
| SymantecEDR.Incident.uuid | String | The GUID assigned for this incident. Example: "483e3fde-4556-4800-81b1-e8da5ee394b6". | 
| SymantecEDR.Incident.atp_rule_id | String | The rule that triggered this incident. | 
| SymantecEDR.Incident.resolution | Number | The resolution of the closed incident. Possible values are: 0 =INSUFFICIENT_DATA. The incident does not have sufficient information to make a determination. 1 = SECURITY_RISK. The incident indicates a true security threat. 2 = FALSE_POSITIVE. The incident has been incorrectly reported as a security threat. 3 = MANAGED_EXTERNALLY. The incident was exported to an external application and will be triaged there. 4 = NOT_SET. The incident resolution was not set. 5 = BENIGN. The incident detected the activity as expected but is not a security threat. 6 = TEST. The incident was generated due to internal security testing. | 

#### Command example
```!symantec-edr-incident-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "Incident": {
            "atp_rule_id": "CynicIncident",
            "description": "Sandbox detection: eicar_com.zip",
            "detection_type": "Sandboxing",
            "first_seen": "2023-02-03T12:13:36.142Z",
            "incident_created": "2023-02-03T12:13:37.018Z",
            "incident_id": 100021,
            "incident_state": "Closed",
            "incident_uuid": "2fd76da0-a3bc-11ed-d519-000000000002",
            "last_seen": "2023-02-07T07:33:43.129Z",
            "last_updated": "2023-02-15T11:27:46.747Z",
            "log_name": "epmp_incident-2023-02-03",
            "priority": "High",
            "recommended_action": "You can isolate the endpoint(s), remove the file(s) and/or clean the system(s).",
            "resolution": "MANAGED_EXTERNALLY. The incident was exported to an external application and will be triaged there.",
            "rule_name": "Critical Cynic Detections"
        }
    }
}
```

#### Human Readable Output

>### Incident List
>|IncidentId|Description|IncidentCreated|DetectionType|LastUpdated|Priority|IncidentState|AtpRuleId|RuleName|IncidentUuid|LogName|RecommendedAction|Resolution|FirstSeen|LastSeen|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100021 | Sandbox detection: eicar_com.zip | 2023-02-03T12:13:37.018Z | Sandboxing | 2023-02-15T11:27:46.747Z | High | Closed | CynicIncident | Critical Cynic Detections | 2fd76da0-a3bc-11ed-d519-000000000002 | epmp_incident-2023-02-03 | You can isolate the endpoint(s), remove the file(s) and/or clean the system(s). | MANAGED_EXTERNALLY. The incident was exported to an external application and will be triaged there. | 2023-02-03T12:13:36.142Z | 2023-02-07T07:33:43.129Z |


### symantec-edr-incident-comment-get
***
Get incident comments based on incident UUID.


#### Base Command

`symantec-edr-incident-comment-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The unique incident ID. | Required | 
| limit | The limit for the number of events listed per page. Default is 50. | Optional | 
| page | The number of results per page to display. | Optional | 
| page_size | The page number to view. Each page contains page_size values. Must be used along with page_size. Default is 1. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g., YYYY-MM-DDTHH:MM:SS.sssZ) and free text (e.g., 10 seconds, 5 minutes, 2 days, 1 weeks). | Optional | 
| end_time | From current time to get events. Supports ISO (e.g., YYYY-MM-DDTHH:MM:SS.sssZ) and free text (e.g., 10 seconds, 5 minutes, 2 days, 1 weeks, now). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.IncidentComment.incident_id | Number | Incident ID. | 
| SymantecEDR.IncidentComment.comment | String | The comment of the incident. | 
| SymantecEDR.IncidentComment.time | String | The timestamp \(in ISO 8601 format\) that specifies the time at which the comment was added to incident. | 
| SymantecEDR.IncidentComment.user_id | String | The ID of the user who registered the comment. Example: 100000. | 

#### Command example
```!symantec-edr-incident-comment-get incident_id=100022 limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "IncidentComment": [
            {
                "comment": "added as part of testing xsoar command examples",
                "incident_id": "100022",
                "incident_responder_name": "SEDR API",
                "time": "2023-02-15T11:33:54.470Z",
                "user_id": 100000
            }
        ]
    }
}
```

#### Human Readable Output

>### Incident Comment List
>|IncidentId|Comment|Time|UserId|IncidentResponderName|
>|---|---|---|---|---|
>| 100022 | added as part of testing xsoar command examples | 2023-02-15T11:33:54.470Z | 100000 | SEDR API |


### symantec-edr-deny-list-policy-get
***
Get deny list policies.


#### Base Command

`symantec-edr-deny-list-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to return. Default is 50. Minimum and maximum "limit" values are  &gt;= 10 and &lt;= 1000. Note: If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size. Default is 1. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| domain | Returns a list of domain type deny list policies that match the specified pattern value. If no value is specified, then all domain type allow list policies will be returned. | Optional | 
| denylist_id | Returns a specific deny list policy for the specified identifier. If no value is specified, then all deny list policies will be returned. | Optional | 
| ip | Returns a list of IP type deny list policies that match the specified pattern value. If no value is specified, then all IP type deny list policies will be returned. | Optional | 
| sha256 | Returns a specific SHA256 type deny list policy for the specified SHA256 value. If no value is specified, then all SHA256 type deny list policies will be returned. | Optional | 
| url | Returns list of URL type deny list policies that match the specified pattern value. If no value is specified, then all URL type deny list policies will be returned. \n\nNote: URL strings must be specified in encoded URL format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.DenyListPolicy.comment | String | The comment for this deny list policy. If not specified, then defaults to empty string. Example: No monitoring required for Control traffic from this IP. | 
| SymantecEDR.DenyListPolicy.id | Number | The unique ID of this deny list policy. This ID can be used in a patch or delete request. Note: This is ignored if present in a create request. | 
| SymantecEDR.DenyListPolicy.target_type | String | The type of this deny list policy. Example: ip enum \(ip, domain, url, sha256, incident_trigger_sig_id\). | 
| SymantecEDR.DenyListPolicy.target_value | String | The value of this deny list policy. Example: 1.1.1.1. | 

#### Command example
```!symantec-edr-deny-list-policy-get limit=10```
#### Context Example
```json
{
    "SymantecEDR": {
        "DenyListPolicy": [
            {
                "comment": "Used for API testing",
                "id": "5",
                "target_type": "url",
                "target_value": "https://facebook.com"
            },
            {
                "id": "6",
                "target_type": "sha256",
                "target_value": "8c12399112cfd22e7d44845ee457b7cf1be7a1a8b780d5a47a70cdbdad9da270"
            }
        ]
    }
}
```

#### Human Readable Output

>### Deny List Policy List
>|Id|TargetType|TargetValue|Comment|
>|---|---|---|---|
>| 5 | url | https:<span>//</span>facebook.com | Used for API testing |
>| 6 | sha256 | 8c12399112cfd22e7d44845ee457b7cf1be7a1a8b780d5a47a70cdbdad9da270 |  |


### symantec-edr-allow-list-policy-get
***
Get allow list policies.


#### Base Command

`symantec-edr-allow-list-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to return. Default is 50.<br/>Minimum and maximum "limit" values are &gt;= 10 and &lt;= 1000.<br/>Note: If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page | The page number to view. Each page contains page_size values. Must be used along with page_size.<br/>Default is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| domain | Returns a list of domain type allow list policies that match the specified pattern value. If no value is specified, then all domain type allow list policies will be returned. | Optional | 
| allowlist_id | Returns specific allow list policy for the specified identifier. If no value is specified, then all allow list policies will be returned. | Optional | 
| ip | Returns a list of IP type allow list policies that match the specified pattern value. If no value is specified, then all IP type allow list policies will be returned. | Optional | 
| url | Returns a list of URL type allow list policies that match the specified pattern value. If no value is specified, then all URL type allow list policies will be returned. <br/><br/>Note: URL strings must be specified in encoded URL format. | Optional | 
| sha256 | Returns a specific SHA256 type allow list policy for the specified SHA256 value. If no value is specified, then all SHA256 type allow list policies will be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.AllowListPolicy.comment | String | The comment for this allow list policy. If not specified, then defaults to empty string. Example: No monitoring required for control traffic from this IP. | 
| SymantecEDR.AllowListPolicy.id | String | The unique ID of this allow list policy. This ID can be used in a patch or delete request. Note: This is ignored if present in a create request | 
| SymantecEDR.AllowListPolicy.target_type | String | The type of this whitelist policy. enum \(ip, domain, url, sha256, incident_trigger_sig_id\). Example: ip. | 
| SymantecEDR.AllowListPolicy.target_value | String | The value of this allow list policy. Example: 1.1.1.1. | 

#### Command example
```!symantec-edr-allow-list-policy-get limit=10```
#### Context Example
```json
{
    "SymantecEDR": {
        "AllowListPolicy": [
            {
                "comment": "Allow List for API testing",
                "id": "1",
                "target_type": "url",
                "target_value": "https://twitter.com/"
            }
        ]
    }
}
```

#### Human Readable Output

>### Allow List Policy List
>|Id|TargetType|TargetValue|Comment|
>|---|---|---|---|
>| 1 | url | https:<span>//</span>twitter.com/ | Allow List for API testing |


### symantec-edr-incident-update
***
Incidents patch command to close an incident, update the resolution of a closed incident, or add comments to the incident.


#### Base Command

`symantec-edr-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_type | The operation to take on a specified incident.<br/>- add_comment: Add comments to the incident.<br/>- close_incident: Close incident. <br/>- update_resolution: Update resolution of the closed incident. Possible values are: add_comment, close_incident, update_resolution. | Required | 
| incident_id | An incident ID for a specific operation. | Required | 
| value | For add comments: The value should contain a user defined comment. The maximum length of the comment is 512 characters.<br/><br/>For update resolution of a closed incident: Any one of supported resolution values:<br/>0 = INSUFFICIENT_DATA. The incident does not have sufficient information to make a determination.<br/>1 = SECURITY_RISK. The incident indicates a true security threat.<br/>2 = FALSE_POSITIVE. The incident has been incorrectly reported as a security threat.<br/>3 = MANAGED_EXTERNALLY. The incident was exported to an external application and will be triaged there.<br/>4 = NOT_SET. The incident resolution was not set.<br/>5 = BENIGN. The incident detected the activity as expected but is not a security threat.<br/>6 = TEST. The incident was generated due to internal security testing.<br/>. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks').<br/><br/>Note: Only can provide if incidents are older then 30 days. | Optional | 
| end_time | From current time to get events. Supports ISO (e.g., 2021-12-28T00:00:00.000Z) and free text (e.g., '10 seconds', '5 minutes', '2 days', '1 weeks', now).<br/><br/>Note: Only can provide if incidents are older then 30 days. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!symantec-edr-incident-update action_type=add_comment incident_id=100022 value="added as part of testing xsoar command examples"```
#### Human Readable Output

>### Incident Add Comment
>|incident_id|Message|
>|---|---|
>| 100022 | Successfully Updated |


#### Command example
```!symantec-edr-incident-update action_type=update_resolution incident_id=100021 value=3```
#### Human Readable Output

>### Incident Update Status
>|incident_id|Message|
>|---|---|
>| 100021 | Successfully Updated |


#### Command example
```!symantec-edr-incident-update action_type=close_incident incident_id=100022```
#### Human Readable Output

>### Incident Close Incident
>|incident_id|Message|
>|---|---|
>| 100022 | Successfully Updated |


### symantec-edr-endpoint-status
***
Get the command status.


#### Base Command

`symantec-edr-endpoint-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | Command ID to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.CommandStatus.command_issuer_name | String | The display name of the user who issued the command. Example: ATP API. | 
| SymantecEDR.CommandStatus.state | String | Command state enum \(completed, initializing, in_progress, error, cancel_requested, cancelled\). | 
| SymantecEDR.CommandStatus.status.error_code | String | The error codes for a specific target. Possible values:-1 = Error, 1 = In-progress, 9000 = File Is Clean, 9001 = File Is Malware, 9003 = File Size Over Limit \(File Size Should Not Exceed 10MB For Sandbox Submission\), 9005 = Query To Sandbox Failed \(Check Network Connectivity\), 9006 = File Type Not Supported \(Check With Symantec Support For Sandbox Supported File List\), 9007 = File Not Found In FileStore \(Use get_endpoint_fle Command To Copy File Into FileStore\). | 
| SymantecEDR.CommandStatus.status.message | String | Message explaining error code. Possible values: Error \(-1\), In progress \(1\), File Is Clean \(9000\), File Is Malware \(9001\), File Size Over Limit \(9003\), Query To Sandbox Failed \(9005\), File Type Not Supported \(9006\), File Not Found In FileStore \(9007\), | 
| SymantecEDR.CommandStatus.status.state | String | The command status for a specific target. Values:  0 = Completed 1 = In progress 2 = Error 3 = Cancelled 4 = Cancel requested. | 
| SymantecEDR.CommandStatus.status.target | String | The SHA256 of a file. | 

#### Command example
```!symantec-edr-endpoint-status command_id=b44a351058454c81af41ca98a20d622c-2022-12-18```
#### Context Example
```json
{
    "SymantecEDR": {
        "CommandStatus": {
            "Command Issuer Name": "ATP API",
            "error_code": 301,
            "message": "File was not found on endpoint",
            "state": 0
        }
    }
}
```

#### Human Readable Output

>### Command Status
>|State|Command Issuer Name|Message|ErrorCode|
>|---|---|---|---|
>| 0 | ATP API | File was not found on endpoint | 301 |


### symantec-edr-endpoint-rejoin
***
Rejoins endpoints by re-establishing connections that the endpoint(s) has to internal networks and external networks, based on the endpoint IDs.


#### Base Command

`symantec-edr-endpoint-rejoin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device ID of the target computer. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Command.rejoin_endpoint.command_id | String | Command ID. | 
| SymantecEDR.Command.rejoin_endpoint.error_code | Number | The status of the command action. Values:-1 = Error 0 = Command rejoin_endpoint successfully requested 1 = Command rejoin_endpoint not supported for target command type 2 = Command rejoin_endpoint failed because the target command is already in terminal state \(i.e., completed, error, or cancelled\) 3 = Command rejoin_endpoint is already in progress for the target command | 
| SymantecEDR.Command.rejoin_endpoint.message | String | Message explaining error code. Values: -1 = Error  0 = Command rejoin_endpoint successfully requested  1 = Command rejoin_endpoint not supported for target command type  2 = Command rejoin_endpoint failed because the target command is already in terminal state  3 = Command rejoin_endpoint is already in progress for the target command | 

#### Command example
```!symantec-edr-endpoint-rejoin device_id=393b8e82-fe40-429f-8e5e-c6b79a0f2b1c```
#### Context Example
```json
{
    "SymantecEDR": {
        "Command": {
            "Rejoin Endpoint": {
                "command_id": "1c576eed2f1b4c3dbefa72594f1d3328-2023-02-15",
                "error_code": 0,
                "message": "Command rejoin_endpoint successfully requested"
            }
        }
    }
}
```

#### Human Readable Output

>### Command Rejoin Endpoint
>|Message|CommandId|
>|---|---|
>| Command rejoin_endpoint successfully requested | 1c576eed2f1b4c3dbefa72594f1d3328-2023-02-15 |


### symantec-edr-endpoint-delete-file
***
Deletes a file, i.e., deletes all instances of the file, based on the file hash that you have specified from the endpoint using the device ID.


#### Base Command

`symantec-edr-endpoint-delete-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Device ID of the target computer/endpoint,. | Required | 
| sha2 | The SHA256 value of the target file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Command.delete_endpoint_file.command_id | String | Command ID. | 
| SymantecEDR.Command.delete_endpoint_file.error_code | String | The status of the command action.  Possible values:-1 = Error0= Command delete_endpoint_file successfully requested1 = Command delete_endpoint_file not supported for target command type2 = Command delete_endpoint_file failed because the target command is already in terminal state \(i.e.,completed, error, or cancelled\)3 = Command delete_endpoint_file is already in progress for the target command. | 
| SymantecEDR.Command.delete_endpoint_file.message | String | Message explaining error code. Possible Values: -1 = Error  0 = Command delete_endpoint_file successfully requested  1 = Command delete_endpoint_file not supported for target command type  2 = Command delete_endpoint_file failed because the target command is already in terminal state  3 = Command delete_endpoint_file is already in progress for the target command. | 

#### Command example
```!symantec-edr-endpoint-delete-file device_id=393b8e82-fe40-429f-8e5e-c6b79a0f2b1c sha2=302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4```
#### Context Example
```json
{
    "SymantecEDR": {
        "Command": {
            "Delete Endpoint": {
                "command_id": "1d8cd7cf132746de862cfe208211df7b-2023-02-15",
                "error_code": 0,
                "message": "Command delete_endpoint_file successfully requested"
            }
        }
    }
}
```

#### Human Readable Output

>### Command Delete Endpoint
>|Message|CommandId|
>|---|---|
>| Command delete_endpoint_file successfully requested | 1d8cd7cf132746de862cfe208211df7b-2023-02-15 |


### symantec-edr-endpoint-cancel-command
***
Cancel a command that is already in progress. Cancel the command execution on all the endpoints where it is still in progress. \nOnly one command can be cancelled at a time.


#### Base Command

`symantec-edr-endpoint-cancel-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | Command ID. Example: "f283b7dc9255493daed443e13e726903-2018-05-16". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Command.cancel.command_id | String | Command ID. | 
| SymantecEDR.Command.cancel.error_code | String | The status of the command action. Possible Values: -1 = Error 0 = Command cancel successfully requested 1 = Command cancel not supported for target command type 2 = Command cancel failed because the target command is already in terminal state \(i.e., completed, error, or cancelled\) 3 = Command cancel is already in progress for the target command. | 
| SymantecEDR.Command.cancel.message | String | Message explaining error code. Possible Values: -1 = Error  0 = Command cancel successfully requested  1 = Command cancel not supported for target command type  2 = Command cancel failed because the target command is already in terminal state  3 = Command cancel is already in progress for the target command. | 

#### Command example
```!symantec-edr-endpoint-cancel-command command_id=bee3647b420f4e1bab822ca283fbeb00-2022-12-18```
#### Context Example
```json
{
    "SymantecEDR": {
        "Command": {
            "Cancel Endpoint": {
                "command_id": "bee3647b420f4e1bab822ca283fbeb00-2022-12-18",
                "error_code": 1,
                "message": "Command cancel_command not supported for target command type."
            }
        }
    }
}
```

#### Human Readable Output

>### Command Cancel Endpoint
>|Message|CommandId|
>|---|---|
>| Command cancel_command not supported for target command type. | bee3647b420f4e1bab822ca283fbeb00-2022-12-18 |


### file

***
Issue a sandbox command of a specific SHA2.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| polling | Whether the command should poll until the result is ready. Possible values are: true, false. Default is True. | Optional | 
| file | The file hash SHA256. | Required | 
| timeout_in_seconds | Timeout for polling. Default is 600 seconds. | Optional | 
| interval_in_seconds | Interval between polling. Default is 10 seconds. Must be 10 or higher. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| File.MD5 | String | MD5 hash of the file submitted for analysis. | 
| File.SHA1 | String | SHA1 hash of the file submitted for analysis. | 
| File.SHA256 | String | SHA256 hash of the file submitted for analysis. | 