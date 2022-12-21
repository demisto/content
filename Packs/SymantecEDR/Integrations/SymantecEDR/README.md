Symantec EDR (On Prem) endpoints help to detect threats on your network by filter endpoints data to find Indicators of Compromise (IoCs) and take actions to remediate the threat(s). EDR on-premise capabilities allow incident responders to quickly search, identify and contain all impacted endpoints while investigating threats using a choice of on-premises
This integration was integrated and tested with version xx of SymantecEDRDev

## Configure Symantec Endpoint Detection and Response (EDR) - On Prem on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Endpoint Detection and Response (EDR) - On Prem.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (i.e. https://host:port) | Symantec EDR \(On Prem\) Appliance URL | True |
    | Client ID | OAuth Client ID and Client Secret for authorizes third-party applications to communicate with Symantec EDR | True |
    | Password |  | True |
    | Fetch incidents |  | False |
    | Fetch incidents Events | Retrieve incident related events and incident lineage events from the EDR database | False |
    | Get incident comments | Retrieve incident comments for each fetch incident when checked | False |
    | Status to filter out fetching as incidents. Comma-separated lists are supported, e.g., New,In-Progress |  | False |
    | Severity to filter out fetching as incidents. Comma-separated lists are supported, e.g., Medium,High. |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
    | Maximum number of incidents to fetch |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### symantec-edr-endpoint-isolate
***
"isolate_endpoint" - Isolates endpoints by cutting connections that the endpoint(s) has to internal networks and external networks, based on the endpoint Device IDs


#### Base Command

`symantec-edr-endpoint-isolate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | For "isolate_endpoint"  the field is strings representing a device ID of the target computer . Possible values are: . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Command.isolate_endpoint.command_id | String | Command ID | 
| SymantecEDR.Command.isolate_endpoint.error_code | Number | This represents the status of the command action. Values: 

-1 = Error 
0 = Command isolate_endpoint successfully requested 
1 = Commandisolate_endpoint not supported for target command type 
2 = Command isolate_endpoint failed because the target command is already in terminal state \(i.e., completed, error, or cancelled\) 
3 = Command isolate_endpoint is already in progress for the target command  | 
| SymantecEDR.Command.isolate_endpoint.message | String | Message explaining error code. 

Values: 
-1 = Error  
0 = Command isolate_endpoint successfully requested  
1 = Command isolate_endpoint not supported for target command type  
2 = Command isolate_endpoint failed because the target command is already in terminal state  
3 = Command isolate_endpoint is already in progress for the target command  | 

#### Command example
```!symantec-edr-endpoint-isolate device_id=393b8e82-fe40-429f-8e5e-c6b79a0f2b1c```
#### Context Example
```json
{
    "SymantecEDR": {
        "Command": {
            "isolate_endpoint": {
                "command_id": "88f4ead1befb4a4297b8dc214ff9bd4a-2022-12-20",
                "error_code": 0,
                "message": "Command isolate_endpoint successfully requested"
            }
        }
    }
}
```

#### Human Readable Output

>### Command isolate_endpoint
>|Message|Command ID|Error Code|
>|---|---|---|
>| Command isolate_endpoint successfully requested | 88f4ead1befb4a4297b8dc214ff9bd4a-2022-12-20 | 0 |


### symantec-edr-domain-file-association-list
***
List of Domain and File association


#### Base Command

`symantec-edr-domain-file-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| query | Specifies a search query as Lucene query string.<br/>Example: query="last_seen: 2022-10-22T11:23:26.561Z"<br/><br/>Note: Refer to Symantec (EDR On-Premise) API document for more details https://apidocs.securitycloud.symantec.com/#. | Optional | 
| search_query | Specific a filters option in lieu of “query”. These filters will improve query performance.<br/>Search query type are  domain  and sha256. Possible values are: domain, sha256. | Optional | 
| search_value | Specifies a search value. Also support query with multiple search value provided by comma "," seperator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.DomainFileAssociation.data_source_url | String | The URL that was accessed 

Example: "http://www.westfallave.com/insight/cloudcar.exe" | 
| SymantecEDR.DomainFileAssociation.data_source_url_domain | String | Domain name of the accessed URL 

Example: "westfallave.com" | 
| SymantecEDR.DomainFileAssociation.device_ip | String | The IPv6 or IPv4 address of the endpoint when this association was last updated 

Example: "10.212.24.159" | 
| SymantecEDR.DomainFileAssociation.device_name | String | The host name or, if unavailable, the IP address of the endpoint when this association was last updated 

Example: "170915-000020" | 
| SymantecEDR.DomainFileAssociation.device_uid | String | Unique ID of the endpoint that downloaded the file from the URL 

Example: "04cfc04b-5c7a-4aa8-b95b-79be23f768f4" | 
| SymantecEDR.DomainFileAssociation.frst_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this association 

Example: "2018-01-30T04:13:10.669Z" | 
| SymantecEDR.DomainFileAssociation.last_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this association 

Example: "2018-01-30T04:13:10.669Z" | 
| SymantecEDR.DomainFileAssociation.name | String | The file name of the downloadedfilee. This attribute doesn’t include the path of the file 

Example: "cloudcar\[2\].exe" | 
| SymantecEDR.DomainFileAssociation.sha2 | String | The SHA256 checksum of the file \(hex string\) that was downloaded from the URL 

Example: "3559378c933cdd434af2083f7535460843d2462033de74ec7c70dbe5f70124f5" | 
| SymantecEDR.DomainFileAssociation.signature_company_name | String | The signer company name of the downloaded file. 

Example: "Microsoft Windows" | 

### symantec-edr-endpoint-domain-association-list
***
List of Endpoint and Domain association


#### Base Command

`symantec-edr-endpoint-domain-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| query | Specifies a search query as Lucene query string.<br/>Example: Example: query="first_seen: [2022-10-01T07:00:58.030Z  TO 2022-10-21T06:41:54.452Z]" <br/><br/>Note: For more details refer to Symantec EDR (On-Prem) API document https://apidocs.securitycloud.symantec.com/#. | Optional | 
| search_query | Specific a filters option in lieu of “query”. These filters will improve query performance. <br/>Search query type are  domain  and device_uid. Possible values are: domain, device_uid. | Optional | 
| search_value | Specifies a search value. Also support query with multiple search value provided by comma "," seperator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.EndpointDomainAssociation.data_source_url | String | The URL that was accessed 

Example: "http://www.westfallave.com/insight/cloudcar.exe" | 
| SymantecEDR.EndpointDomainAssociation.data_source_url_domain | String | Domain name of the accessed URL 

Example: "westfallave.com" | 
| SymantecEDR.EndpointDomainAssociation.device_ip | String | The IPv6 or IPv4 address of the endpoint when this association was last updated 

Example: "10.212.24.159" | 
| SymantecEDR.EndpointDomainAssociation.device_name | String | The host name or, if unavailable, the IP address of the endpoint when this association was last updated 

Example: "170915-000020" | 
| SymantecEDR.EndpointDomainAssociation.device_uid | String | Unique ID of the endpoint that accessed this URL 

Example: "04cfc04b-5c7a-4aa8-b95b-79be23f768f4" | 
| SymantecEDR.EndpointDomainAssociation.frst_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this association 

Example: "2018-01-30T04:13:10.669Z" | 
| SymantecEDR.EndpointDomainAssociation.last_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this association 

Example: "2018-01-30T04:13:10.669Z"  | 

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
List of Domain and File association


#### Base Command

`symantec-edr-endpoint-file-association-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| query | Specifies a search query as Lucene query string.<br/>Example: Example: query="first_seen: [2022-10-01T07:00:58.030Z  TO 2022-10-21T06:41:54.452Z]" <br/><br/>Note: For more details refer to Symantec EDR (On-Prem) API document https://apidocs.securitycloud.symantec.com/#. | Optional | 
| search_query | Specific a filters option in lieu of “query”. These filters will improve query performance.<br/>Search query type are  device_uid  and sha256. Possible values are: device_uid, sha256. | Optional | 
| search_value | Specifies a search value. Also support query with multiple search value provided by comma "," seperator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.EndpointFileAssociation.device_ip | String | The IPv6 or IPv4 address of the endpoint when this association was last updated 

Example: "10.212.24.159" | 
| SymantecEDR.EndpointFileAssociation.device_name | String | The host name or, if unavailable, the IP address of the endpoint when this association was last updated 

Example: "170915-000020" | 
| SymantecEDR.EndpointFileAssociation.device_uid | String | Unique ID of the endpoint that has this file 

Example: "04cfc04b-5c7a-4aa8-b95b-79be23f768f4" | 
| SymantecEDR.EndpointFileAssociation.frst_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this association 

Example: "2018-02-04T09:00:00.577Z" | 
| SymantecEDR.EndpointFileAssociation.folder | String | The folder where the file resides. This attribute does not include the name of the file 

Example: "c:\\\\windows\\\\system32" | 
| SymantecEDR.EndpointFileAssociation.last_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this association 

Example: "2018-02-04T09:00:01.778Z" | 
| SymantecEDR.EndpointFileAssociation.name | String | The name of the file. This attribute doesn’t include the path of the file 

Example: "sc.exe" | 
| SymantecEDR.EndpointFileAssociation.sha2 | String | The SHA256 checksum of the file \(hex string\) 

Example: "eaab690ebd8ddf9ae452de1bc03b73c8154264dbd7a292334733b47a668ebf31" | 

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
Get Domain Instances


#### Base Command

`symantec-edr-domain-instance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| query | Specifies a search query as Lucene query string.<br/>Example: query="external_ip: 8.8.8.8". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.DomainInstance.data_source_url | String | Last URL accessed on this domain 
Example: "http://www.skyscan.com/shample/shample.exe" | 
| SymantecEDR.DomainInstance.data_source_url_domain | String | The name of the domain. 
Example: "skyscan.com"  | 
| SymantecEDR.DomainInstance.disposition | Number | Domain disposition: 

0 = healthy/good 
1 = unknown 
2 = suspicious 
3 = bad | 
| SymantecEDR.DomainInstance.frst_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the creation of this instance. 

Example: "2018-01-30T04:13:10.669Z" | 
| SymantecEDR.DomainInstance.last_seen | String | The timestamp \(in ISO 8601 format\) that specifies the creation time of the event that resulted into the update of this instance. 

Example: "2018-01-30T04:13:10.669Z"  | 
| SymantecEDR.DomainInstance.external_ip | String | The IP address \(IPv4 or IPv6\) of the device/machine that accepted the connection. 

Example: "85.158.136.166" | 

#### Command example
```!symantec-edr-domain-instance-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "DomainInstances": [
            {
                "data_source_url_domain": "dmd.metaservices.microsoft.com",
                "disposition": 1,
                "first_seen": "2022-10-21T13:05:38.000Z",
                "last_seen": "2022-12-20T13:09:20.000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Domain Instances List
>|DataSourceUrlDomain|FirstSeen|LastSeen|Disposition|
>|---|---|---|---|
>| dmd.metaservices.microsoft.com | 2022-10-21T13:05:38.000Z | 2022-12-20T13:09:20.000Z | unknown (1) |


### symantec-edr-endpoint-instance-list
***
Get Endpoint Instances


#### Base Command

`symantec-edr-endpoint-instance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| query | Specifies a search query as Lucene query string.<br/>. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.EndpointInstance.device_ip | String | The IP address of the endpoint. IPv4 or IPv6 format. 
Example: "192.168.0.250"  | 
| SymantecEDR.EndpointInstance.device_name | String | The host name or, if unavailable, the IP address of the endpoint. 
Example: "WIN-CRNK1KQJBC0  | 
| SymantecEDR.EndpointInstance.device_uid | String | Unique ID of the endpoint. 
Example: "12b1d2ce-dddb-4bcc-990e-28f44cf8ddcb" | 
| SymantecEDR.EndpointInstance.domain_or_workgroup | String | Domain or workgroup name depending on the configuration. 
Example: "WORKGROUP"  | 
| SymantecEDR.EndpointInstance.time | String | The timestamp \(in ISO 8601 format\) that Specifies the creation or last update time of this instance. This is the creation time when there were no updates. Otherwise, it is the time of the last update. 
Example: "2018-01-15T14:05:57.127Z"  | 
| SymantecEDR.EndpointInstance.user_name | String | The name of the user that originated or caused the event. 
Example: "Administrator"  | 
| SymantecEDR.EndpointInstance.ip_addresses | Unknown | Array of all the IP addresses \(IPv4 or IPv6\) associated with the endpoint. 
 Example: \["192.168.0.250"\] | 

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
| limit | The maximum number of records to return. <br/>Limit default value is 50. <br/>Note: If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page | The page number. Default is 1. | Optional | 
| page_size | The number of requested results per page. Default is 50. | Optional | 
| file_sha2 | Query unique file identifier (SHA2). | Optional | 
| query | Specifies a search query as Lucene query string.<br/>Example: query="name: svchost.exe". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.FileInstance.first_seen | String | The timestamp \(in ISO 8601 format\) that Specifies the creation time of the event that resulted into the creation of this instance. 

Example: "2018-01-30T04:13:10.669Z"  | 
| SymantecEDR.FileInstance.folder | String | The folder where the file resides. This attribute does not include the name of the file. 

Example: "c:\\\\users\\\\public\\\\pictures"  | 
| SymantecEDR.FileInstance.last_seen | String | The timestamp \(in ISO 8601 format\) that Specifies the creation time of the event that resulted into the update of this instance. 

Example: "2018-01-30T04:13:10.669Z"  | 
| SymantecEDR.FileInstance.name | String | The name of the file. This attribute does not include the path of the file. 

Example: "virus.exe"  | 
| SymantecEDR.FileInstance.sha2 | String | The SHA256 checksum of the file \(hex string\) 

Example: "eaab690ebd8ddf9ae452de1bc03b73c8154264dbd7a292334733b47a668ebf31" | 

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
            "last_seen": "2022-12-20T17:10:50.090Z",
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
>| 2022-10-21T07:00:39.964Z | 2022-12-20T17:10:50.090Z | 302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4 | elevation_service.exe | csidl_program_files\google\chrome\application\106.0.5249.119 |
>| 2022-10-21T19:31:20.770Z | 2022-12-20T17:10:50.090Z | 302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4 | elevation_service.exe | c:\program files\google\chrome\application\106.0.5249.119 |


### symantec-edr-system-activity-list
***
Command to get System Activities


#### Base Command

`symantec-edr-system-activity-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks'). | Optional | 
| end_time | From current time get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks', now). | Optional | 
| query | Specifies a search query as Lucene query string.<br/>Example: query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| type_id | Request for specific system activities from following events:  <br/>0         = Application Activity <br/>1000 = System Health <br/>Refer to this &lt;a href="https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html"&gt;link text&lt;/a&gt; to check the type_id for event type. | Optional | 
| severity | Specifies the severity from following:  <br/>Info<br/>warning <br/>minor <br/>major <br/>critical <br/>fatal . Possible values are: info, warning, minor, major, critical, fatal. | Optional | 
| status | The overall success or failure of the action reported by the event. Possible values are: <br/>Unknown (0)<br/>Success (1)<br/>Failure  (2). Possible values are: Unknown, Success, Failure. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.SystemActivity.device_time | String | The timestamp \(in ISO 8601 format\) that specifes the time at which the event occurred. | 
| SymantecEDR.SystemActivity.type_id  | Number | The unique identifier for an event. Following this events link and Summary Type IDs:
https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html

System Activity Log Event Type: 
Viewing Symantec EDR appliance activities in the System Activity log \(broadcom.com\) 
 | 
| SymantecEDR.SystemActivity.severity_id | Number | Event severity that specifies the importance of the event. Possible values are: 
1 = info \(default\) 
2 = warning 
3 = minor 
4 = major 
5 = critical 
6 = fatal  | 
| SymantecEDR.SystemActivity.message | String | Human-readable \(possibly multi-line\) event message or description of the event.  | 
| SymantecEDR.SystemActivity.device_ip | String | The IPv6 or IPv4 address of the device that originated the event. | 
| SymantecEDR.SystemActivity.atp_node_role | Number | The role of the ATP appliance that generated the event. Possible values are: 

0 = Pre-Bootstrap 
1 = Network Scanner 
2 = Management 
3 = Standalone Network 
4 = Standalone Endpoint 
5 = All in One | 
| SymantecEDR.SystemActivity.category_id | String | The event type category. 

4 = Audit  | 
| SymantecEDR.SystemActivity.device_cap  | String | Name or caption of ATP appliance that generated the event. | 
| SymantecEDR.SystemActivity.device_name | String | The device name \(i.e., the name of the endpoint or appliance associated with an event\). | 
| SymantecEDR.SystemActivity.feature_name | String | The name of the feature that originated the event. 
Applicable events : 1, 20, 21, 1000 
Example : "Search"  | 
| SymantecEDR.SystemActivity.id | String | The event identifier for applicable events : 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8089, 8090 
1 = Exists 
2 = Partial 

The outcome of the Session Audit event for Applicable events : 20 
0 = Unknown 
1 = Logon 
2 = Logoff 

The outcome of the Entity Audit event. Applicable events : 21  
0 = Unknown 
1 = Create 
2 = Update 
3 = Delete 

 | 
| SymantecEDR.SystemActivity.log_name | String | The index of the event. 
Note: This is for informational purpose and cannot be used as a filter. Use time as start_time to query for events. Example : "epmp_events-2015-11-05"  | 
| SymantecEDR.SystemActivity.log_time | String | The time the event was logged.  Example : "YYYY-MM-DDThh:mm:ss.SSSZ" | 
| SymantecEDR.SystemActivity.remediation | String | Description how to fix the issue, if applicable. 
Applicable events : 1000 
Example : "Enter valid connection settings for SEPM server \[SEPM_DB→&lt;IP&gt;:&lt;PORT&gt;\] for Symantec Endpoint Protection Correlation to work properly."  | 
| SymantecEDR.SystemActivity.status_detail | String | String representing the type of failure that may have occurred. The list includes, but is not limited to, the following: 
service_failure 
service_unavailable 
network_error 
certifcate_error 
sw_update_error 
internal_error 
authentication_error 
connection_error  | 
| SymantecEDR.SystemActivity.status_exception | String | Low level exception message if available. 
Applicable events : 1000  | 
| SymantecEDR.SystemActivity.status_id | Number | The overall success or failure of the action reported by the event. Possible values are: 
0 = Unknown 
1 = Success 
2 = Failure 
Applicable events : 1, 20, 21, 1000 
Example : 1  | 
| SymantecEDR.SystemActivity.uuid | Unknown | The unique ID for this event. UUID uniquely identifies an event with a single event type \(type_id\).  | 
| SymantecEDR.SystemActivity.process_pid | String | PID of the service for which an action was taken. 
Applicable events : 1000 
Example : 31337 | 
| SymantecEDR.SystemActivity.data_sepm_server_db_ip_address | String | IP address of the SEPM database. | 
| SymantecEDR.SystemActivity.data_sepm_server_enabled | Boolean | Indicates whether ATP is enabled to log on and gather logs from this database. Applicable events : 1000 
Default : false 
Example : true  | 
| SymantecEDR.SystemActivity.data_sepm_server_db_type | String | Type of database: MSSQL or Sybase. 

Applicable events : 1000 

Example : "SYBASE"  | 
| SymantecEDR.SystemActivity.data_sepm_server_user_name | String | User name of the SEPM database. 

Applicable events : 1000 

Example : "ATP_QUERY_USER"  | 
| SymantecEDR.SystemActivity.data_sepm_server_status | String | Status of SEPM database configuration with ATP. 

Applicable events : 1000 

Example : "healthy"  | 
| SymantecEDR.SystemActivity.data_sepm_server_sepm_name | String | User-provided name for SEPM database server. 

Applicable events : 1000 

Example : "SEPM_DB"  | 
| SymantecEDR.SystemActivity.data_sepm_server_db_port | Number | Database port of SEPM database. 

Applicable events : 1000 

Example : 8081  | 
| SymantecEDR.SystemActivity.data_sepm_server_db_name | String | SymantecEDR.SystemActivity.data.eventdata.sepm_server.db_name | 

#### Command example
```!symantec-edr-system-activity-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "SystemActivity": {
            "atp_node_role": 5,
            "device_cap": "EDR",
            "device_ip": "192.168.20.8",
            "device_name": "localhost.localdomain",
            "device_time": "2022-12-20T17:34:50.341Z",
            "event_actor_pid": 12358,
            "feature_name": "AdministratorTask",
            "log_name": "atp_system_log-2022-12-20",
            "log_time": "2022-12-20T17:34:50.492Z",
            "message": "Command submit_to_sandbox with command id f7a34794462448d383ad1736010d034c-2022-12-20 completed.",
            "product_name": "Symantec Endpoint Detection and Response",
            "product_ver": "4.6.8-8",
            "severity_id": 1,
            "status_id": 1,
            "timezone": 0,
            "type_id": 1,
            "uuid": "9b0c6150-808c-11ed-f8a3-0000000309aa"
        }
    }
}
```

#### Human Readable Output

>### System Activities List
>|Time|TypeId|SeverityId|Message|DeviceIp|AtpNodeRole|
>|---|---|---|---|---|---|
>| 2022-12-20T17:34:50.341Z | 1 | 1 | Command submit_to_sandbox with command id f7a34794462448d383ad1736010d034c-2022-12-20 completed. | 192.168.20.8 | 5 |


### symantec-edr-audit-event-list
***
Get  Audit Events


#### Base Command

`symantec-edr-audit-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| start_time | Specifies the beginning of the search time frame.  Supports ISO (e.g "yyyy-MM-dd’T’HH:mm:ss.SSSZ") or '10 seconds', '5 minutes', '2 days', '1 weeks'). | Optional | 
| end_time | Specifies the end of the search time frame. Supports ISO (e.g"yyyy-MM-dd’T’HH:mm:ss.SSSZ") and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks', now). | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| query | Specifies a search query as Lucene query string.<br/>Example: query="type_id:(4096 OR 4098 OR 4123)"<br/><br/>The search query is broken up into terms and operators. <br/><br/>There are two types of terms: Single Terms and Phrases.<br/>      (a) A Single Term is a single word such as "test" or "hello"<br/>      (b) A Phrase is a group of words surrounded by double quotes such as "hello dolly"<br/><br/>When creating a search query string, consider the following:<br/><br/>1. You can search any field by specifying the field name followed by a colon ":" and then the term you are looking for<br/>2. Escape special characters that are part of the query syntax. To escape a special character use the \ before the character. The current list of special characters are '+, -, &amp;&amp;, \|\|, !, ( ), { }, [ ], ^, ", ~ ,*, ?, \, :'<br/>3. Date value should follow ISO 8601 date stamp standard format (yyyy-MM-dd'T'HH:mm:ss.SSSXXX)<br/>4. Supported Boolean operators for complex query are: AND OR + - NOT Note: Boolean operators must be ALL CAPS<br/>5. Multiple terms can be combined together with Boolean operators to form a more complex query in the query clause<br/>6. Use parentheses to group clauses to form sub-queries<br/>7. Defaults to all events for the start_time and end_time specified in the query<br/>8. The maximum length of the query string is 10240 characters. | Optional | 
| type_id | Specifies  Type Id. Refer to event summary Type IDs link: https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html . | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!symantec-edr-audit-event-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "AuditEvent": {
            "atp_node_role": 5,
            "category_id": 4,
            "device_cap": "EDR",
            "device_ip": "192.168.20.8",
            "device_name": "localhost.localdomain",
            "device_time": "2022-12-20T10:56:56.264Z",
            "device_uid": "2B034D56-DBDB-9D58-DBA5-1CCB980276F2",
            "feature_name": "UserSession",
            "id": 2,
            "log_name": "atp_audit_log-2022-12",
            "log_time": "2022-12-20T10:56:56.759Z",
            "message": "User pavani has logged out",
            "product_name": "Symantec Endpoint Detection and Response",
            "product_ver": "4.6.8-8",
            "severity_id": 1,
            "status_detail": "Success",
            "status_id": 1,
            "timezone": 0,
            "type_id": 20,
            "user_agent_ip": "172.16.11.157",
            "user_name": "Pavani",
            "user_uid": "pavani",
            "uuid": "04fd5480-8055-11ed-ddbd-000000030629"
        }
    }
}
```

#### Human Readable Output

>### Audit Event List
>|Time|TypeId|FeatureName|Message|UserAgentIp|UserName|Severity|DeviceName|DeviceIp|Uuid|
>|---|---|---|---|---|---|---|---|---|---|
>| 2022-12-20T10:56:56.264Z | 20 | UserSession | User pavani has logged out | 172.16.11.157 | Pavani | 1 | localhost.localdomain | 192.168.20.8 | 04fd5480-8055-11ed-ddbd-000000030629 |


### symantec-edr-event-list
***
Used to get events from EDR on-premise


#### Base Command

`symantec-edr-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks'). Possible values are: . | Optional | 
| end_time | From current time get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks', now). Possible values are: . | Optional | 
| query | Specifies a search query as Lucene query string.<br/>Example: query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| type_id | Specifies  Type Id. Refer to event summary Type IDs link: https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html . Possible values are: . | Optional | 
| severity | Specifies the severity from following:  <br/>info (1) <br/>warning (2) <br/>minor (3) <br/>major (4) <br/>critical (5) <br/>fatal (6) . Possible values are: info, warning, minor, major, critical, fatal. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!symantec-edr-event-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "Event": {
            "attacks_tactic_ids_0": "2",
            "attacks_tactic_uids_0": "TA0002",
            "attacks_technique_name_0": "Windows Management Instrumentation",
            "attacks_technique_uid_0": "T1047",
            "device_domain": "WORKGROUP",
            "device_ip": "172.16.14.42",
            "device_name": "WIN-TFB8L7BI77H",
            "device_os_name": "Windows Server 2019 ",
            "device_time": "2022-12-20T17:34:33.921Z",
            "device_uid": "393b8e82-fe40-429f-8e5e-c6b79a0f2b1c",
            "enriched_data_category_id": 3,
            "enriched_data_category_name": "Process Termination",
            "enriched_data_rule_name": "eProcessClose",
            "event_actor_cmd_line": "C:\\Windows\\sysWOW64\\wbem\\wmiprvse.exe -secured -Embedding",
            "event_actor_file_md5": "3ff0bb6eacc39958042b74ca04e202a6",
            "event_actor_file_modified": "2018-09-15T07:13:00.192Z",
            "event_actor_file_name": "wmiprvse.exe",
            "event_actor_file_normalized_path": "CSIDL_SYSTEMX86\\wbem\\wmiprvse.exe",
            "event_actor_file_original_name": "Wmiprvse.exe",
            "event_actor_file_path": "c:\\windows\\syswow64\\wbem\\wmiprvse.exe",
            "event_actor_file_sha2": "158075d730a7a6acbe7739251ee9bea4349268597ca576b3e0cb8442140865fd",
            "event_actor_file_signature_company_name": "Microsoft Windows",
            "event_actor_integrity_id": 6,
            "event_actor_pid": 17268,
            "event_actor_signature_level_id": 60,
            "event_actor_start_time": "2022-12-20T17:33:10.008Z",
            "event_actor_uid": "D924C11C-807D-F1ED-8217-98261F32744E",
            "event_actor_user_name": "NETWORK SERVICE",
            "event_actor_user_sid": "S-1-5-20",
            "log_name": "epmp_events-fdr-2022-12-20",
            "log_time": "2022-12-20T05:07:27.053Z",
            "operation": 2,
            "ref_uid": "FCC3D702-8A31-40F1-B0F0-AD928AC7622F",
            "severity_id": 1,
            "type_id": 8001,
            "user_domain": "NT AUTHORITY",
            "user_name": "NETWORK SERVICE",
            "user_sid": "S-1-5-20",
            "uuid": "9142e310-808c-11ed-ce21-0000000303d9"
        }
    }
}
```

#### Human Readable Output

>### Event List
>|Time|TypeId|Description|DeviceName|Severity|DeviceIp|Operation|DeviceDomain|UserName|
>|---|---|---|---|---|---|---|---|---|
>| 2022-12-20T17:34:33.921Z | 8001 | wmiprvse.exe logged:  | WIN-TFB8L7BI77H | 1 | 172.16.14.42 | 2 | WORKGROUP | NETWORK SERVICE |


### symantec-edr-incident-event-list
***
Command is used to get Events for Incidents


#### Base Command

`symantec-edr-incident-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'<br/>. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks').<br/><br/>. Possible values are: . | Optional | 
| end_time | From current time get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks', now).<br/>. Possible values are: . | Optional | 
| query | Specifies a search query as Lucene query string.<br/><br/>Example:<br/>query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| type_id | The unique identifer for an event.  Refer to this link for Event Type IDs :<br/> https://origin-techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-detection-and-response/4-7/search-fields-and-descriptions-v126755396-d38e59231/event-summary-type-ids-v121987556-d38e58861.html. | Optional | 
| severity | Specifies the severity from following:  <br/>info (1)<br/>warning (2) <br/>minor (3) <br/>major (4) <br/>critical (5) <br/>fatal (6)<br/><br/>Default: All Severity Type. Possible values are: info, warning, minor, major, critical, fatal. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!symantec-edr-incident-event-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "IncidentEvent": {
            "attacks_tactic_ids_0": "2",
            "attacks_tactic_uids_0": "TA0002",
            "attacks_technique_name_0": "Command and Scripting Interpreter",
            "attacks_technique_uid_0": "T1059",
            "correlation_uid": "787E05EE-71B8-11ED-8217-78E3B5B300F9",
            "device_domain": "WORKGROUP",
            "device_ip": "172.16.14.42",
            "device_name": "WIN-TFB8L7BI77H",
            "device_os_name": "Windows Server 2019 ",
            "device_time": "2022-12-01T21:43:44.218Z",
            "device_uid": "393b8e82-fe40-429f-8e5e-c6b79a0f2b1c",
            "enriched_data_category_id": 2,
            "enriched_data_category_name": "Process Launch",
            "enriched_data_rule_description": "Generic process launch event",
            "enriched_data_rule_name": "eGenericProcessLaunch",
            "enriched_data_suspicion_score": 0,
            "event_actor_cmd_line": "C:\\Windows\\system32\\cmd.exe /d /c \"C:\\ProgramData\\Symantec\\Symantec Endpoint Protection\\14.3.8268.5000.105\\Data\\Definitions\\WebExtDefs\\20221129.017\\webextbridge.exe\" chrome-extension://pamolibmfebkknkdmfabpjebifbffbec/ --parent-window=0 < \\\\.\\pipe\\chrome.nativeMessaging.in.90abb4245fc8fa0a > \\\\.\\pipe\\chrome.nativeMessaging.out.90abb4245fc8fa0a",
            "event_actor_file_md5": "975b45b669930b0cc773eaf2b414206f",
            "event_actor_file_modified": "2019-09-07T00:29:00.561Z",
            "event_actor_file_name": "cmd.exe",
            "event_actor_file_normalized_path": "CSIDL_SYSTEM\\cmd.exe",
            "event_actor_file_original_name": "Cmd.Exe",
            "event_actor_file_path": "c:\\windows\\system32\\cmd.exe",
            "event_actor_file_sha2": "3656f37a1c6951ec4496fabb8ee957d3a6e3c276d5a3785476b482c9c0d32ea2",
            "event_actor_file_signature_company_name": "Microsoft Windows",
            "event_actor_integrity_id": 5,
            "event_actor_pid": 14468,
            "event_actor_signature_level_id": 60,
            "event_actor_start_time": "2022-12-01T21:43:29.835Z",
            "event_actor_uid": "787E05ED-71B8-F1ED-8217-98261F32744E",
            "event_actor_user_name": "Administrator",
            "event_actor_user_sid": "S-1-5-21-3669279935-616031708-4259075843-500",
            "event_source": 3,
            "event_uuid": "3a7beba0-71c1-11ed-fd2d-000000010f00",
            "incident": "9d6f2100-7158-11ed-da26-000000000001",
            "log_name": "epmp_incident-2022-12-01",
            "log_time": "2022-12-01T09:54:47.909Z",
            "operation": 1,
            "ref_uid": "09FB7038-0A5E-4048-A3D5-E88885323F2E",
            "severity_id": 1,
            "type_id": 8001,
            "user_domain": "WIN-TFB8L7BI77H",
            "user_name": "Administrator",
            "user_sid": "S-1-5-21-3669279935-616031708-4259075843-500",
            "uuid": "30de6860-715e-11ed-e069-000000000015"
        }
    }
}
```

#### Human Readable Output

>### Event for Incident List
>|Time|TypeId|Description|DeviceName|Severity|DeviceIp|EventUuid|Incident|Operation|DeviceDomain|UserName|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-12-01T21:43:44.218Z | 8001 | cmd.exe logged: Generic process launch event | WIN-TFB8L7BI77H | 1 | 172.16.14.42 | 3a7beba0-71c1-11ed-fd2d-000000010f00 | 9d6f2100-7158-11ed-da26-000000000001 | 1 | WORKGROUP | Administrator |


### symantec-edr-incident-list
***
Command is used to get incidents from Symantec EDR on-premise API


#### Base Command

`symantec-edr-incident-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The limit for number of events listed per page.<br/>Default value is '50'<br/>. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks').<br/><br/>. Possible values are: . | Optional | 
| end_time | From current time get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks', now).<br/>. Possible values are: . | Optional | 
| query | Specifies a search query as Lucene query string.<br/><br/>Example:<br/>query="type_id:(4096 OR 4098 OR 4123)". | Optional | 
| incident_id | Specifies an incident id. | Optional | 
| severity | Specifies the incident  severity/priority level <br/>Low (1) <br/>Medium (2) <br/>High (3). Possible values are: High, Medium, Low. | Optional | 
| status | Specifies the incident status: <br/>Open (1) <br/>Waiting (2) <br/>In-Progress(3) <br/>Close (4). Possible values are: Open, Waiting, In-progress, Close. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Incident.atp_incident_id | Number | A unique identifer for this incident. | 
| SymantecEDR.Incident.log_name | String | The index of the incident.
Note: This is for informational purpose and cannot be used as a flter.
Use time as start_time to query for incidents. Example : "epmp_incident-2018-03-01" | 
| SymantecEDR.Incident.summary | String | Summary information about the incident. | 
| SymantecEDR.Incident.priority_level | Number | Priority level of the incident. Possible values are:
1 = LOW
2 = MED
3 =HIGH | 
| SymantecEDR.Incident.resultt.last_event_seen | Date | The creation time \(in ISO 8601 format\) when the last event associated
with the incident was created. Matches the last event’s time feld. | 
| SymantecEDR.Incident.time | Date | The creation time \(in ISO 8601 format\) of the incident. | 
| SymantecEDR.Incident.rule_name | String | The name of the rule that triggered this incident. | 
| SymantecEDR.Incident.first_event_seen | Date | The creation time \(in ISO 8601 format\) when the frst event associated
with the incident was created. Matches the frst event’s time feld. This
is likely before the incident’s creation time feld given incidents are
created after their frst event is seen. | 
| SymantecEDR.Incident.state | Number | The current state of the incident. Possible values are:
1 = OPEN
2 =WAITING
3 = IN_WORK
4 = CLOSED | 
| SymantecEDR.Incident.detection_type | String | Incident Detection Type | 
| SymantecEDR.Incident.device_time | Date | The timestamp \(in ISO 8601 format\) that specifes the time at which the
event occurred | 
| SymantecEDR.Incident.recommended_action | String | Recommended action for this incident. Possible actions could be
isolating an endpoint, deleting fle from endpoint, blacklist URL, or
domain, etc. | 
| SymantecEDR.Incident.updated | Date | The time \(in ISO 8601 format\) of last modifcation. | 
| SymantecEDR.Incident.uuid | String | The GUID assigned for this incident.
Example : "483e3fde-4556-4800-81b1-e8da5ee394b6" | 
| SymantecEDR.Incident.atp_rule_id | String | The textual representation of the rule that triggered this incident. | 
| SymantecEDR.Incident.resolution | Number | The resolution of the closed incident. Possible values are:
0 =INSUFFICIENT_DATA. The incident does not have sufcient information to make a determination.
1 = SECURITY_RISK. The incident indicates a true security threat.
2 = FALSE_POSITIVE. The incident has been incorrectly reported as a security threat.
3 =MANAGED_EXTERNALLY. The incident was exported to an external application and will be triaged there.
4 = NOT_SET. The incident resolution was not set.
5 = BENIGN. The incident detected the activity as expected but is not a security threat.
6 = TEST. The incident was generated due to internal security testing. | 

#### Command example
```!symantec-edr-incident-list limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "Incident": {
            "atp_incident_id": 100010,
            "atp_rule_id": "AdvancedAttackTechniqueIncident",
            "detection_type": "Advanced Attack Techniques",
            "device_time": "2022-12-01T09:14:53.072Z",
            "first_event_seen": "2022-12-01T21:44:15.000Z",
            "last_event_seen": "2022-12-01T21:44:21.000Z",
            "log_name": "epmp_incident-2022-12-01",
            "priority_level": 3,
            "recommended_action": "Remove or blacklist developer utilities that aren't needed on target systems.\nEnsure Symantec Endpoint Protection's SONAR behavioral protection and Network Intrusion Prevention are enabled and blocking.\nRemove, blacklist, or use Symantec Endpoint Protection's Application Control to lock down host applications that aren't needed in your environment.",
            "resolution": 4,
            "rule_name": "Advanced Attack Technique",
            "state": 4,
            "summary": "win-tfb8l7bi77h: Trusted Developer Utilities Proxy Execution, Deobfuscate/Decode Files or Information, Signed Binary Proxy Execution",
            "time": "2022-12-01T09:14:53.072Z",
            "updated": "2022-12-08T10:40:21.750Z",
            "uuid": "9d6f2100-7158-11ed-da26-000000000001"
        }
    }
}
```

#### Human Readable Output

>### Incident List
>|IncidentId|Description|IncidentCreated|DetectionType|LastUpdated|Priority|IncidentState|AtpRuleId|RuleName|IncidentUuid|LogName|RecommendedAction|Summary|Resolution|FirstSeen|LastSeen|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 100010 | win-tfb8l7bi77h: Trusted Developer Utilities Proxy Execution, Deobfuscate/Decode Files or Information, Signed Binary Proxy Execution | 2022-12-01T09:14:53.072Z | Advanced Attack Techniques | 2022-12-08T10:40:21.750Z | High | Close | AdvancedAttackTechniqueIncident | Advanced Attack Technique | 9d6f2100-7158-11ed-da26-000000000001 | epmp_incident-2022-12-01 | Remove or blacklist developer utilities that aren't needed on target systems.<br/>Ensure Symantec Endpoint Protection's SONAR behavioral protection and Network Intrusion Prevention are enabled and blocking.<br/>Remove, blacklist, or use Symantec Endpoint Protection's Application Control to lock down host applications that aren't needed in your environment. | win-tfb8l7bi77h: Trusted Developer Utilities Proxy Execution, Deobfuscate/Decode Files or Information, Signed Binary Proxy Execution | 4 | 2022-12-01T21:44:15.000Z | 2022-12-01T21:44:21.000Z |


### symantec-edr-incident-comment-get
***
Get Incident Comments based on Incident UUID


#### Base Command

`symantec-edr-incident-comment-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specifies unique incident Id. | Required | 
| limit | The limit for number of events listed per page.<br/>Default value is '50'. | Optional | 
| page | The number of results per page to display. | Optional | 
| page_size | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks'). | Optional | 
| end_time | From current time get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks', now). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.IncidentComment.incident_id | Number | Incident ID | 
| SymantecEDR.IncidentComment.comment | String | The comment of incident | 
| SymantecEDR.IncidentComment.time | String | The timestamp \(in ISO 8601 format\) that specifies the time at which the comment was added to incident  | 
| SymantecEDR.IncidentComment.user_id | String | The user id who registered the comment. 
Example: 100000 | 

#### Command example
```!symantec-edr-incident-comment-get incident_id=100010 limit=1```
#### Context Example
```json
{
    "SymantecEDR": {
        "IncidentComment": [
            {
                "comment": "Comment added as part of testing xsoar command examples",
                "incident_id": "100010",
                "incident_responder_name": "SEDR API",
                "time": "2022-12-20T17:07:43.785Z",
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
>| 100010 | Comment added as part of testing xsoar command examples | 2022-12-20T17:07:43.785Z | 100000 | SEDR API |


### symantec-edr-deny-list-policy-get
***
Get Deny List Policies


#### Base Command

`symantec-edr-deny-list-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to return. If no limit is specified, then the limit value is set to the default = 50 Minimum and Maximum "limit" value greater then &gt;= 10 and less then &lt;= 1000<br/>Note: If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| domain | Returns list of domain type deny list policies matching to the specified pattern value. If no value is specified, then all domain type allow list policies will be returned. . | Optional | 
| denylist_id | Returns specific deny list policy for the specified identifier. If no value is specified, then all deny list policies will be returned. | Optional | 
| ip | Returns list of ip type deny list policies matching to the Specified pattern value. If no value is Specified, then all ip type deny list policies will be returned. | Optional | 
| sha256 | Returns Specific sha256 type deny list policy for the Specified sha256 value. If no value is Specified, then all sha256 type deny list policies will be returned. | Optional | 
| url | Returns list of url type deny list policies matching to the Specified pattern value. If no value is Specified, then all url type deny list policies will be returned. <br/><br/>Note: url string must be Specified in encoded URL format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.DenyListPolicy.comment | String | Specifies the comment for this deny  list policy. If not Specified, then defaults to empty string. 

Example: "No monitoring required for Control traffic from this IP." | 
| SymantecEDR.DenyListPolicy.id | Number | The unique ID of this deny list policy. This id can be used in patch or delete request. 

Note: This is ignored if present in create request  | 
| SymantecEDR.DenyListPolicy.target_type | String | Specifies type of this denylist policy. 

Example: "ip" 

enum \("ip", "domain", "url", "sha256", "incident_trigger_sig_id"\) | 
| SymantecEDR.DenyListPolicy.target_value | String | Specifies value of this deny list policy. 

Example: "1.1.1.1"  | 

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
Get Allow List Policies


#### Base Command

`symantec-edr-allow-list-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to return. If no limit is specified, then the limit value is set to the default = 50<br/>Minimum and Maximum "limit" value greater then &gt;= 10 and less then &lt;= 1000<br/>Note: If the page_size argument is set by the user then the limit argument will be ignored. | Optional | 
| page | The page number you would like to view. Each page contains page_size values. Must be used along with page_size.<br/>Default value is '1'. | Optional | 
| page_size | The number of results per page to display. | Optional | 
| domain | Returns list of domain type allow list policies matching to the specified pattern value. If no value is specified, then all domain type allow list policies will be returned. . | Optional | 
| allowlist_id | Returns specific allow list policy for the specified identifier. If no value is specified, then all allow list policies will be returned. | Optional | 
| ip | Returns list of ip type allow list policies matching to the Specified pattern value. If no value is Specified, then all ip type allow list policies will be returned. . | Optional | 
| url | Returns list of url type allow list policies matching to the Specified pattern value. If no value is Specified, then all url type allow list policies will be returned. <br/><br/>Note: Url string must be Specified in encoded URL format. . | Optional | 
| sha256 | Returns Specific sha256 type allow list policy for the Specified sha256 value. If no value is Specified, then all sha256 type allow list policies will be returned. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.AllowListPolicy.comment | String | Specifies the comment for this allow list policy. If not Specified, then defaults to empty string. 

Example: "No monitoring required for Control traffic from this IP. | 
| SymantecEDR.AllowListPolicy.id | String | The unique ID of this allow list policy. This id can be used in patch or delete request. 

Note: This is ignored if present in create request | 
| SymantecEDR.AllowListPolicy.target_type | String | Specifies type of this whitelist policy.  enum \("ip", "domain", "url", "sha256", "incident_trigger_sig_id"\) 

Example: "ip"  | 
| SymantecEDR.AllowListPolicy.target_value | String | Specifies value of this allow list policy. 

Example: "1.1.1.1" | 

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


### file
***
Issue Sandbox Command of specific SHA2


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports SHA256. | Required | 


#### Context Output

There is no context output for this command.
### symantec-edr-incident-update
***
Incidents Patch command for the close incident, update resolution of closed incident or add comments to incident.


#### Base Command

`symantec-edr-incident-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation | Specifes the operation to take on specifed incident.<br/>- Add : Add Comments to Incident.<br/>- Close: Closed Incident. <br/>- Update: Update status either Open or Close Incident. Possible values are: add, close, update. | Required | 
| update_status | Update Close or Open Incident with status. value is any one of the state integer e.g.  (1 = open, 2 = waiting, 3 In-progress).  The type is integer. example "value=2". Possible values are: Open, Waiting, In-Progress. | Optional | 
| incident_id | Specifies an incident ID for specific operation . | Required | 
| comment | Add Comments to Incident. "comment=&lt;free text&gt;". The maximum length of comment is 512 characters<br/>. | Optional | 
| start_time | The earliest time from which to get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks'). | Optional | 
| end_time | From current time get events. Supports ISO (e.g 2021-12-28T00:00:00.000Z) and free text (e.g.'10 seconds', '5 minutes', '2 days', '1 weeks', now). | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!symantec-edr-incident-update incident_id=100010 operation=add comment="Comment added as part of testing xsoar command examples"```
#### Human Readable Output

>### Patch Incident Add Comment
>|incident_id|status|Message|value|
>|---|---|---|---|
>| 100010 | 204 | Successfully added | Comment added as part of testing xsoar command examples |


### symantec-edr-endpoint-status
***
Command Status is used to query command status


#### Base Command

`symantec-edr-endpoint-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | Command ID to query . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.CommandStatus.command_issuer_name | String | The user display name who issued the command. 

Example: "ATP API" | 
| SymantecEDR.CommandStatus.state | String | Command state 

enum \("completed", "initializing", "in_progress", "error", "cancel_requested", "cancelled"\)  | 
| SymantecEDR.CommandStatus.status.error_code | String | This represents error codes for a specific target. 
Possible values:
-1 = Error
1 = In-progress
9000 = File Is Clean
9001 = File Is Malware
9003 = File Size Over Limit \(File Size Should Not Exceed 10MB For Sandbox Submission\)
9005 = Query To Sandbox Failed \(Check Network Connectivity\)
9006 = File Type Not Supported \(Check With Symantec Support For Sandbox Supported File List\)
9007 = File Not Found In FileStore \(Use get_endpoint_fle Command To Copy File Into FileStore\) | 
| SymantecEDR.CommandStatus.status.message | String | Message explaining error code.
Possible values:
Error \(-1\)
In progress \(1\)
File Is Clean \(9000\)
File Is Malware \(9001\)
File Size Over Limit \(9003\)
Query To Sandbox Failed \(9005\)
File Type Not Supported \(9006\)
File Not Found In FileStore \(9007\) | 
| SymantecEDR.CommandStatus.status.state | String | This represents the command status for specific target. Values: 

 0 = Completed 
1 = In progress 
2 = Error 
3 = Cancelled 
4 = Cancel requested | 
| SymantecEDR.CommandStatus.status.target | String | The target feld represents SHA256 of a fle | 

#### Command example
```!symantec-edr-endpoint-status command_id=b44a351058454c81af41ca98a20d622c-2022-12-18```
#### Context Example
```json
{
    "SymantecEDR": {
        "CommandStatus": {
            "Command Issuer Name": "ATP API",
            "Next": null,
            "Total": 1,
            "error_code": 301,
            "message": "File was not found on endpoint",
            "state": "completed",
            "target": {
                "device_uid": "393b8e82-fe40-429f-8e5e-c6b79a0f2b1c",
                "hash": "302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4"
            },
            "target_state": 0
        }
    }
}
```

#### Human Readable Output

>### Command Status
>|State|Command Issuer Name|Total|Target|TargetState|Message|ErrorCode|
>|---|---|---|---|---|---|---|
>| completed | ATP API | 1 | hash: 302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4<br/>device_uid: 393b8e82-fe40-429f-8e5e-c6b79a0f2b1c | 0 | File was not found on endpoint | 301 |


### symantec-edr-endpoint-rejoin
***
Rejoins endpoints by re-establishing connections that the endpoint(s) has to internal networks and external networks, based on the endpoint IDs


#### Base Command

`symantec-edr-endpoint-rejoin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The field is strings representing a device ID of the target computer . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Command.rejoin_endpoint.command_id | String | Command ID | 
| SymantecEDR.Command.rejoin_endpoint.error_code | Number | This represents the status of the command action. Values:
-1 = Error 
0 = Command rejoin_endpoint successfully requested 
1 = Command rejoin_endpoint not supported for target command type 
2 = Command rejoin_endpoint failed because the target command is already in terminal state \(i.e., completed, error, or cancelled\) 
3 = Command rejoin_endpoint is already in progress for the target command
 | 
| SymantecEDR.Command.rejoin_endpoint.message | String | Message explaining error code. 

Values: 
-1 = Error  
0 = Command rejoin_endpoint successfully requested  
1 = Command rejoin_endpoint not supported for target command type  
2 = Command rejoin_endpoint failed because the target command is already in terminal state  
3 = Command rejoin_endpoint is already in progress for the target command | 

#### Command example
```!symantec-edr-endpoint-rejoin device_id=393b8e82-fe40-429f-8e5e-c6b79a0f2b1c```
#### Context Example
```json
{
    "SymantecEDR": {
        "Command": {
            "rejoin_endpoint": {
                "command_id": "ba5e3467e48e45f8aafcba262fb17fff-2022-12-20",
                "error_code": 0,
                "message": "Command rejoin_endpoint successfully requested"
            }
        }
    }
}
```

#### Human Readable Output

>### Command rejoin_endpoint
>|Message|Command ID|Error Code|
>|---|---|---|
>| Command rejoin_endpoint successfully requested | ba5e3467e48e45f8aafcba262fb17fff-2022-12-20 | 0 |


### symantec-edr-endpoint-delete-file
***
Deletes a file, i.e. deletes all instances of the file, based on the file hash that you have specified from the endpoint using the Device ID


#### Base Command

`symantec-edr-endpoint-delete-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | Device ID of the target computer/endpoint. | Required | 
| sha2 | The SHA256 value of the target file. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Command.delete_endpoint_file.command_id | String | Command ID | 
| SymantecEDR.Command.delete_endpoint_file.error_code | String | This represents the status of the command action. 
 Possible values:
-1 = Error
0= Command delete_endpoint_file successfully requested
1 = Command delete_endpoint_file not supported for target command type
2 = Command delete_endpoint_file failed because the target command is already in terminal state \(i.e.,completed, error, or cancelled\)
3 = Command delete_endpoint_file is already in progress for the target command | 
| SymantecEDR.Command.delete_endpoint_file.message | String | Message explaining error code. 
Possible Values: 
-1 = Error  
0 = Command delete_endpoint_file successfully requested  
1 = Command delete_endpoint_file not supported for target command type  
2 = Command delete_endpoint_file failed because the target command is already in terminal state  
3 = Commanddelete_endpoint_file is already in progress for the target command | 

#### Command example
```!symantec-edr-endpoint-delete-file device_id=393b8e82-fe40-429f-8e5e-c6b79a0f2b1c sha2=302c968ab3e1227d54df4e72f39088d7483d25eeb3037f0b16bc39cef2728fa4```
#### Context Example
```json
{
    "SymantecEDR": {
        "Command": {
            "delete_endpoint_file": {
                "command_id": "d59f218e9b9b43cf9ac516bdf5091c44-2022-12-20",
                "error_code": 0,
                "message": "Command delete_endpoint_file successfully requested"
            }
        }
    }
}
```

#### Human Readable Output

>### Command delete_endpoint_file
>|Message|Command ID|Error Code|
>|---|---|---|
>| Command delete_endpoint_file successfully requested | d59f218e9b9b43cf9ac516bdf5091c44-2022-12-20 | 0 |


### symantec-edr-endpoint-cancel-command
***
Cancel a command that is already in progress. Cancel the command execution on all the endpoints where it is still in progress. 
Only one command can be cancelled at a time.


#### Base Command

`symantec-edr-endpoint-cancel-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command_id | Strings that representing a command ID. Example: "f283b7dc9255493daed443e13e726903-2018-05-16". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SymantecEDR.Command.cancel.command_id | String | Command ID | 
| SymantecEDR.Command.cancel.error_code | String | This represents the status of the command action. Possible Values: 
-1 = Error 
0 = Command cancel successfully requested 
1 = Command cancel not supported for target command type 
2 = Command cancel failed because the target command is already in terminal state \(i.e., completed, error, or cancelled\) 
3 = Command cancel is already in progress for the target command | 
| SymantecEDR.Command.cancel.message | String | Message explaining error code. Possible Values: 
-1 = Error  
0 = Command cancel successfully requested  
1 = Command cancel not supported for target command type  
2 = Command cancel failed because the target command is already in terminal state  
3 = Command cancel is already in progress for the target command | 

#### Command example
```!symantec-edr-endpoint-cancel-command command_id=bee3647b420f4e1bab822ca283fbeb00-2022-12-18```
#### Context Example
```json
{
    "SymantecEDR": {
        "Command": {
            "cancel_command": {
                "command_id": "bee3647b420f4e1bab822ca283fbeb00-2022-12-18",
                "error_code": 1,
                "message": "Command cancel_command not supported for target command type."
            }
        }
    }
}
```

#### Human Readable Output

>### Command cancel_command
>|Message|Command ID|Error Code|
>|---|---|---|
>| Command cancel_command not supported for target command type. | bee3647b420f4e1bab822ca283fbeb00-2022-12-18 | 1 |

