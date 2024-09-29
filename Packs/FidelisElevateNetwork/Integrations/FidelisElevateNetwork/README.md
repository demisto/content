Automate Detection and Response to Network Threats and data leakage in your organization with Fidelis Elevate Network Integration.
This integration was integrated and tested with version 9.2.4 of Fidelis Elevate Network
## Configure Fidelis Elevate Network in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server_url | Server URL | True |
| credentials | Credentials | True |
| unsecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| fetch_time | First fetch timestamp (\<number\> \<time unit\>, e.g., 12 hours, 7 days, 3 months, 1 year) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fidelis-get-alert
***
Gets alert details from Fidelis Elevate.


##### Base Command

`fidelis-get-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ID | string | Alert ID. | 
| Fidelis.Alert.ThreatScore | number | Alert threat score. | 
| Fidelis.Alert.Time | date | Alert time. | 
| Fidelis.Alert.RuleID | string | Related rule ID. | 
| Fidelis.Alert.RuleName | string | Related rule name. | 
| Fidelis.Alert.Summary | string | Alert summary. | 
| Fidelis.Alert.PolicyName | string | Related policy name. | 
| Fidelis.Alert.Severity | string | Alert severity. | 
| Fidelis.Alert.Protocol | string | Protocol involved in the alert. | 
| Fidelis.Alert.Type | string | Alert type. | 
| Fidelis.Alert.AssignedUser | string | Assigned user ID. | 


##### Command Example
```!fidelis-get-alert alert_id=1```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "AlertUUID": "80d0ccf5-5879-11ea-b430-0eb174ee0947",
            "AssignedUser": 0,
            "ID": 1,
            "PolicyName": "Endpoint Alerts",
            "Protocol": "",
            "RuleID": 227,
            "RuleName": null,
            "Severity": "Medium",
            "Summary": "Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact: ",
            "ThreatScore": 100,
            "Time": "2020-02-26 09:21:02",
            "Type": "ENDPOINT"
        }
    }
}
```

##### Human Readable Output
### Alert 1
|Alert UUID|Assigned User|ID|Policy Name|Rule ID|Severity|Summary|Threat Score|Time|Type|
|---|---|---|---|---|---|---|---|---|---|
| 80d0ccf5-5879-11ea-b430-0eb174ee0947 | 0 | 1 | Endpoint Alerts | 227 | Medium | Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact:  | 100 | 2020-02-26 09:21:02 | ENDPOINT |


### fidelis-delete-alert
***
Deletes an alert from Fidelis Elevate.


##### Base Command

`fidelis-delete-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | ID of the alert to delete. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!fidelis-delete-alert alert_id=3```


##### Human Readable Output
Alert (3) deleted successfully!

### fidelis-get-malware-data
***
Retrieves malware data related to a "Malware" type alert.


##### Base Command

`fidelis-get-malware-data`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ID | string | Alert ID. | 
| Fidelis.Alert.Malware.Name | string | Malware name. | 
| Fidelis.Alert.Malware.Type | string | Malware type. | 
| Fidelis.Alert.Malware.Behavior | string | Malware behavior. | 
| Fidelis.Alert.Malware.Platform | string | Malware platform. | 
| Fidelis.Alert.Malware.DetailName | string | Malware detail name from Fidelis Elevate. | 
| Fidelis.Alert.Malware.Variant | string | Malware variant. | 
| Fidelis.Alert.Malware.Description | string | Malware description from Fidelis Elevate. | 


##### Command Example
```!fidelis-get-malware-data alert_id=6```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "ID": "6",
            "Malware": {
                "Behavior": null,
                "Description": null,
                "DetailName": null,
                "Name": "",
                "Platform": null,
                "Type": "",
                "Variant": null
            }
        }
    }
}
```

##### Human Readable Output
### Alert 6 Malware:
|Malware Behavior|Malware Description|Malware Detail Name|Malware Name|Malware Platform|Malware Type|Malware Variant|
|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |


### fidelis-get-alert-report
***
Downloads a PDF report for a specified alert.


##### Base Command

`fidelis-get-alert-report`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID of the alert for which to download a PDF report. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!fidelis-get-alert-report alert_id=5```

##### Context Example
```
{
    "InfoFile": {
        "EntryID": "7382@99f96547-c492-48d1-84bc-070759449a5d",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "Alert_Details_5.pdf",
        "Size": 69507,
        "Type": "PDF document, version 1.4"
    }
}
```

### fidelis-list-alerts
***
Returns a list of open alerts from Fidelis Elevate.


##### Base Command

`fidelis-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_frame | Filter alerts by time frame, for example, Last 48 Hours. | Optional | 
| start_time | If the time_frame value is Custom, specify the start time for the time range, for example, 2017-06-01T12:48:16.734. | Optional | 
| end_time | If the time_frame value is Custom, specify the end time for the time range, for example, 2017-06-01T12:48:16.734. | Optional | 
| severity | Filter alerts by alert severity. | Optional | 
| type | Filter alerts by alert type. | Optional | 
| threat_score | Filter alerts by alert threat score threshold (higher than). | Optional | 
| ioc | Filter alerts that are related to a specified IOC. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ID | string | Alert ID. | 
| Fidelis.Alert.Time | date | Alert time. | 
| Fidelis.Alert.Summary | string | Alert summary. | 
| Fidelis.Alert.Severity | string | Alert severity. | 
| Fidelis.Alert.Type | string | Alert type. | 


##### Command Example
```!fidelis-list-alerts```

##### Context Example
```
{
    "Fidelis": {
        "Alert": [
            {
                "ID": "6",
                "Severity": "High",
                "Summary": "Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown",
                "Time": "2020-03-19 23:59:59",
                "Type": "Endpoint"
            },
            {
                "ID": "5",
                "Severity": "Medium",
                "Summary": "Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact: ",
                "Time": "2020-03-12 09:21:27",
                "Type": "Endpoint"
            }
        ]
    }
}
```

##### Human Readable Output
### Found 6 Alerts:
|ID|Severity|Summary|Time|Type|
|---|---|---|---|---|
| 6 | High | Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown | 2020-03-19 23:59:59 | Endpoint |
| 5 | Medium | Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact:  | 2020-03-12 09:21:27 | Endpoint |
| 4 | Low | Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact:  | 2020-03-07 09:21:24 | Endpoint |
| 2 | High | Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact:  | 2020-02-27 09:21:03 | Endpoint |
| 3 | High | Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact:  | 2020-02-27 09:21:03 | Endpoint |
| 1 | Medium | Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact:  | 2020-02-26 09:21:02 | Endpoint |


### fidelis-upload-pcap
***
Uploads a PCAP file to Fidelis Elevate for analysis.


##### Base Command

`fidelis-upload-pcap`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_ip | Component IP address. | Required | 
| entry_id | War Room entry ID of the PCAP file, for example, "3245@6". | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!fidelis-upload-pcap component_ip=1.1.1.1 entry_id=7317@99```

##### Human Readable Output
Pcap file uploaded successfully.

### fidelis-list-pcap-components
***
Gets PCAP components.


##### Base Command

`fidelis-list-pcap-components`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Component.Name | string | Component name. | 
| Fidelis.Component.IP | string | Component IP address. | 


##### Command Example
```!fidelis-list-pcap-components```

##### Context Example
```
{
    "Fidelis": {
        "Component": {
            "IP": "1.1.1.1",
            "Name": "Sensor"
        }
    }
}
```

##### Human Readable Output
### PCAP Components
|Name|IP|
|---|---|
| Sensor | 1.1.1.1 |


### fidelis-run-pcap
***
Runs PCAP file analysis in Fidelis Elevate.


##### Base Command

`fidelis-run-pcap`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| component_ip | Component IP address. Run the 'fidelis-list-pcap-components' command to get this value. | Required | 
| files | CSV list of PCAP file names in Fidelis Elevate. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!fidelis-run-pcap component_ip=1.1.1.1 files=file.pcap```

##### Human Readable Output
Pcap file run submitted.

### fidelis-get-alert-by-uuid
***
Returns an alert, by UUID.


##### Base Command

`fidelis-get-alert-by-uuid`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_uuid | The UUID of the alert. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ID | Number | Alert ID. | 
| Fidelis.Alert.Severity | String | Alert severity. | 
| Fidelis.Alert.Summary | String | Alert summary. | 
| Fidelis.Alert.Time | Date | Alert time. | 
| Fidelis.Alert.Type | String | Alert type. | 
| Fidelis.Alert.UUID | String | Alert UUID. | 


##### Command Example
```!fidelis-get-alert-by-uuid alert_uuid=80d0ccf5-5879-11ea-b430-0eb174ee0947```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "ID": "1",
            "Severity": "Medium",
            "Summary": "Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact: ",
            "Time": "2020-02-26 09:21:02",
            "Type": "Endpoint"
        }
    }
}
```

##### Human Readable Output
### Found 1 Alerts:
|ID|Severity|Summary|Time|Type|
|---|---|---|---|---|
| 1 | Medium | Endpoint alert on fidelis-endpoint.c.dmst-integrations.internal: , Intel Source: Unknown, Artifact:  | 2020-02-26 09:21:02 | Endpoint |


### fidelis-list-metadata
***
Returns a metadata list.


##### Base Command

`fidelis-list-metadata`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_frame | Filter alerts by time frame, for example, Last 48 Hours. | Optional | 
| start_time | If the time_frame value is Custom, specify the start time for the time range, for example, 2017-06-01T12:48:16.734. | Optional | 
| end_time | If the time_frame value is Custom, specify the end time for the time range, for example,2017-06-01T12:48:16.734. | Optional | 
| client_ip | Filter alerts by client IP. | Optional | 
| server_ip | Filter alerts by server IP address. | Optional | 
| request_direction | Direction of the request. Can be "s2c" (server to client) or "c2s" (client to server). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Metadata.MalwareName | String | Malware name. | 
| Fidelis.Metadata.ServerPort | Number | Server port number. | 
| Fidelis.Metadata.SHA256 | String | SHA256 hash of the file. | 
| Fidelis.Metadata.FileName | String | File name. | 
| Fidelis.Metadata.PcapFilename | String | PCAP file name. | 
| Fidelis.Metadata.SessionDuration | String | The event session duration. | 
| Fidelis.Metadata.ServerIP | String | The server IP address. | 
| Fidelis.Metadata.ClientCountry | String | The client country. | 
| Fidelis.Metadata.ClientPort | Number | The client port number. | 
| Fidelis.Metadata.SessionStart | Date | The date/time that the session started. | 
| Fidelis.Metadata.MalwareType | String | The malware type. | 
| Fidelis.Metadata.URL | String | Request URL. | 
| Fidelis.Metadata.RequestDirection | String | Request direction (s2c or c2s).  | 
| Fidelis.Metadata.MalwareSeverity | String | The severity of the malware. | 
| Fidelis.Metadata.ClientIP | String | The client IP address. | 
| Fidelis.Metadata.ServerCountry | String | The country of the server. | 
| Fidelis.Metadata.PcapTimestamp | Date | PCAP timestamp. | 
| Fidelis.Metadata.SensorUUID | String | Sensor UUID. | 
| Fidelis.Metadata.Timestamp | Date | Timestamp of the event. | 
| Fidelis.Metadata.FileType | String | File type. | 
| Fidelis.Metadata.Protocol | String | Event protocol. | 
| Fidelis.Metadata.UserAgent | String | User agent of the request. | 
| Fidelis.Metadata.Type | String | Type of the event. | 
| Fidelis.Metadata.FileSize | Number | The size of the file. | 
| Fidelis.Metadata.MD5 | String | MD5 hash of the file. | 


##### Command Example
```!fidelis-list-metadata```

##### Context Example
```
{
    "Fidelis": {
        "Metadata": null
    }
}
```

##### Human Readable Output
### Found 0 Metadata:
**No entries.**


### fidelis-list-alerts-by-ip
***
Returns a list of alerts, by source IP address or destination IP address.


##### Base Command

`fidelis-list-alerts-by-ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_frame | Today,Yesterday,Last 7 Days,Last Hour,Last 24 Hours,Last 48 Hours,Last 30 Days,Custom | Optional | 
| start_time | If the time_frame value is Custom, specify the start time for the time range, for example, 2017-06-01T12:48:16.734. | Optional | 
| end_time | If the time_frame value is Custom, specify the start time for the time range, for example, 2017-06-01T12:48:16.734. | Optional | 
| src_ip | Filter alerts by the source IP. | Optional | 
| dest_ip | Filter alerts by the destination IP address. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.SourceIP | String | The alert source IP address.  | 
| Fidelis.Alert.UserRating | String | User rating. | 
| Fidelis.Alert.DestinationCountry | String | Destination country of the alert. | 
| Fidelis.Alert.AssetID | Number | The ID of the asset. | 
| Fidelis.Alert.Time | Date | Date/time that the alert started. | 
| Fidelis.Alert.HostIP | String | The host IP address of the alert. | 
| Fidelis.Alert.DistributedAlertID | String | Alert distributed ID. | 
| Fidelis.Alert.DestinationIP | String | Alert destination IP address. | 
| Fidelis.Alert.AlertUUID | String | The alert UUID. | 
| Fidelis.Alert.Type | String | The alert type. | 
| Fidelis.Alert.ID | Number | Alert ID. | 
| Fidelis.Alert.SourceCountry | String | Alert source country | 


##### Command Example
```!fidelis-list-alerts-by-ip```

##### Context Example
```
{
    "Fidelis": {
        "Alert": [
            {
                "AlertUUID": "151fa61c-6b08-11ea-85b0-0eb174ee0947",
                "AssetID": "2",
                "DestinationCountry": "",
                "DestinationIP": "::",
                "DistributedAlertID": "Console-6",
                "HostIP": "2.2.2.2",
                "ID": "6",
                "SourceCountry": "",
                "SourceIP": "::",
                "Time": "2020-03-19 23:59:59",
                "Type": "Endpoint",
                "UserRating": "No Rating"
            },
            {
                "AlertUUID": "1dee426f-6443-11ea-83d9-0eb174ee0947",
                "AssetID": "2",
                "DestinationCountry": "",
                "DestinationIP": "::",
                "DistributedAlertID": "Console-5",
                "HostIP": "2.2.2.2",
                "ID": "5",
                "SourceCountry": "",
                "SourceIP": "::",
                "Time": "2020-03-12 09:21:27",
                "Type": "Endpoint",
                "UserRating": "No Rating"
            }
        ]
    }
}
```

##### Human Readable Output
### Found 6 Alerts:
|Time|AlertUUID|ID|DistributedAlertID|UserRating|HostIP|AssetID|Type|DestinationCountry|SourceCountry|DestinationIP|SourceIP|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2020-03-19 23:59:59 | 151fa61c-6b08-11ea-85b0-0eb174ee0947 | 6 | Console-6 | No Rating | 2.2.2.2| 2 | Endpoint |  |  | :: | :: |
| 2020-03-12 09:21:27 | 1dee426f-6443-11ea-83d9-0eb174ee0947 | 5 | Console-5 | No Rating | 2.2.2.2 | 2 | Endpoint |  |  | :: | :: |
| 2020-03-07 09:21:24 | 244267da-6055-11ea-b430-0eb174ee0947 | 4 | Console-4 | No Rating | 2.2.2.2 | 2 | Endpoint |  |  | :: | :: |
| 2020-02-27 09:21:03 | a2d7fa21-5942-11ea-b430-0eb174ee0947 | 2 | Console-2 | No Rating | 2.2.2.2 | 2 | Endpoint |  |  | :: | :: |
| 2020-02-27 09:21:03 | a2d8eec9-5942-11ea-b430-0eb174ee0947 | 3 | Console-3 | False Positive | 2.2.2.2 | 2 | Endpoint |  |  | :: | :: |
| 2020-02-26 09:21:02 | 80d0ccf5-5879-11ea-b430-0eb174ee0947 | 1 | Console-1 | Actionable | 2.2.2.2 | 2 | Endpoint |  |  | :: | :: |


### fidelis-download-malware-file
***
Downloads a malware file from a specified alert.


##### Base Command

`fidelis-download-malware-file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | ID of the alert from which to download the file. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.Extension | String | The file extension.  | 
| File.Info | String | Information about the file. | 
| File.Name | String | The name of the file. | 
| File.SHA1 | String | SHA1 hash of the file. | 
| File.Type | String | The file type. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.SSDeep | String | SSDeep hash of the file. | 
| File.EntryID | String | File entry ID. | 
| File.MD5 | String | MD5 hash of the file. | 


##### Command Example
```!fidelis-download-malware-file alert_id=9```

##### Context Example
```
{
    "File": {
        "EntryID": "7640@99f96547-c492-48d1-84bc-070759449a5d",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "d41d8cd98f00b204e9800998ecf8427e",
        "Name": ":HTTP(file.pcap).zip",
        "SHA1": "52483514f07eb14570142f6927b77deb7b4da99f",
        "SHA256": "42a5e275559a1651b3df8e15d3f5912499f0f2d3d1523959c56fc5aea6371e59",
        "SHA512": "3fbdc4195b66297eaa4168ad6ded010c47eaea57496b6cc1ccfa34c9579d21562451d1269c7412e31e926cbb7c50ffc160a6493f4a8df0235ecd3ea2c9bfddb5",
        "SSDeep": "3::",
        "Size": 0,
        "Type": "empty"
    }
}
```

##### Human Readable Output
No File Found

### fidelis-download-pcap-file
***
Downloads the PCAP file from a specified alert.


##### Base Command

`fidelis-download-pcap-file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert from which to download the file. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Name | String | Name of the file. | 
| File.Size | Number | File size | 
| File.Type | String | File type. | 
| File.SHA1 | String | SHA1 hash of the file. | 
| File.SHA256 | String | SHA256 hash of the file. | 
| File.SSDeep | String | SSDeep hash of the file. | 
| File.MD5 | String | MD5 hash of the file. | 


##### Command Example
```!fidelis-download-pcap-file alert_id=5```

##### Context Example
```
{
    "File": {
        "EntryID": "7378@99f96547-c492-48d1-84bc-070759449a5d",
        "Extension": "pcap",
        "Info": "application/vnd.tcpdump.pcap",
        "MD5": "e8a496ed6be700ed61b8b758df3248ef",
        "Name": "Alert ID_5.pcap",
        "SHA1": "86a3069583b027eac8cc519c09cff1f7e18ab9c5",
        "SHA256": "c7911278b27d93e1a5c6998eaca0c75348284caaba9d58ba9951be7d325279a6",
        "SHA512": "3fbdc4195b66297eaa4168ad6ded010c47eaea57496b6cc1ccfa34c9579d21562451d1269c7412e31e926cbb7c50ffc160a6493f4a8df0235ecd3ea2c9bfddb5",
        "SSDeep": "48:uuHYx6sS1bioEX7gyLatSqAc8kHRgd5peJB80t9qeM:uuHYx6sS1bUJBqus8v9",
        "Size": 2036,
        "Type": "HTML document text, ASCII text, with very long lines, with no line terminators"
    }
}
```

##### Human Readable Output


### fidelis-get-alert-session-data
***
Return the session information related to an alert.


##### Base Command

`fidelis-get-alert-session-data`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ID | Number | Alert ID. | 
| Fidelis.Alert.SessionData.RecordingState | String | The alert's recording state. | 
| Fidelis.Alert.SessionData.ClientPackets | String | The client packets. | 
| Fidelis.Alert.SessionData.ServerSize | String | The server size. | 
| Fidelis.Alert.SessionData.ServerPort | Number | The server port. | 
| Fidelis.Alert.SessionData.ServerDataComplete | Boolean | Is the server data complete. | 
| Fidelis.Alert.SessionData.ServerPackets | String | The server packets. | 
| Fidelis.Alert.SessionData.EndTime | String | The end time. | 
| Fidelis.Alert.SessionData.ServerIp | String | The server IP. | 
| Fidelis.Alert.SessionData.ClientSize | String | The client size. | 
| Fidelis.Alert.SessionData.ClientPort | Number | The client port. | 
| Fidelis.Alert.SessionData.ServerData | String | The server data. | 
| Fidelis.Alert.SessionData.BinaryServerData | Unknown | The binary server data. | 
| Fidelis.Alert.SessionData.ClientDataComplete | Boolean | Is the client data complete. | 
| Fidelis.Alert.SessionData.ServerDataSize | Number | The server data size. | 
| Fidelis.Alert.SessionData.RecordedObject | Boolean | The recorded object. | 
| Fidelis.Alert.SessionData.StartTime | String | The start time. | 
| Fidelis.Alert.SessionData.ClientDomainName | String | The client domain name. | 
| Fidelis.Alert.SessionData.TcpState | String | The TCP state. | 
| Fidelis.Alert.SessionData.ShowingDataSize | Number | Showing the data size. | 
| Fidelis.Alert.SessionData.ClientIp | String | The client IP. | 
| Fidelis.Alert.SessionData.Duration | Number | The session data duration. | 
| Fidelis.Alert.SessionData.ClientData | String | The client data. | 
| Fidelis.Alert.SessionData.BinaryClientData | Unknown | The binary client data. | 
| Fidelis.Alert.SessionData.ClientDataSize | Number | The client data size. | 
| Fidelis.Alert.SessionData.NoForensics | Boolean | Are there no forensics. | 
| Fidelis.Alert.SessionData.Exist | Boolean | Does the sesison data exist. | 
| Fidelis.Alert.SessionData.TimeZone | String | The time zone. | 
| Fidelis.Alert.SessionData.Highlights | Unknown | Highlights in the session data. | 
| Fidelis.Alert.SessionData.ServerDomainName | String | The server domain name. | 


##### Command Example
```!fidelis-get-alert-session-data alert_id=9```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "ID": "9",
            "SessionData": {
                "BinaryClientData": {file binary data},
                "BinaryServerData": null,
                "ClientData": {file client data},
                "ClientDataComplete": true,
                "ClientDataSize": 2990,
                "ClientDomainName": null,
                "ClientDomaniName": "",
                "ClientIp": "0.0.0.0",
                "ClientPackets": null,
                "ClientPort": 0,
                "ClientSize": null,
                "Duration": 0,
                "EndTime": "2020-03-30 09:07:33",
                "Exist": true,
                "Highlights": [],
                "NoForensics": false,
                "RecordedObject": true,
                "RecordingState": null,
                "ServerData": null,
                "ServerDataComplete": true,
                "ServerDataSize": null,
                "ServerDomainName": null,
                "ServerDomaniName": "",
                "ServerIp": "0.0.0.0",
                "ServerPackets": null,
                "ServerPort": 0,
                "ServerSize": null,
                "ShowingDataSize": 4,
                "StartTime": "2020-03-30 09:07:33",
                "TcpState": null,
                "TimeZone": "UTC"
            }
        }
    }
}
```

##### Human Readable Output
### Alert 9
|Binary Client Data|Client Data|Client Data Complete|Client Data Size|Client Ip|Client Port|Duration|End Time|Exist|No Forensics|Recorded Object|Server Data Complete|Server Ip|Server Port|Showing Data Size|Start Time|Time Zone|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| {file binary data} | {file client data} | true | 2990 | 0.0.0.0 | 0 | 0 | 2020-03-30 09:07:33 | true | false | true | true | 0.0.0.0 | 0 | 4 | 2020-03-30 09:07:33 | UTC |


### fidelis-get-alert-execution-forensics
***
Get the exectution forensics for an alert.


##### Base Command

`fidelis-get-alert-execution-forensics`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ID | Number | The alert ID. | 
| Fidelis.Alert.ExecutionForensics.EFEnabled | Boolean | Is the alert execution forensics enabled. | 
| Fidelis.Alert.ExecutionForensics.Size | Number | The execution forensics size. | 
| Fidelis.Alert.ExecutionForensics.SubmitTime | Number | The submission time. | 
| Fidelis.Alert.ExecutionForensics.SandBoxOn | Boolean | Is the sandbox on. | 
| Fidelis.Alert.ExecutionForensics.TgReport | Boolean | The TG report. | 
| Fidelis.Alert.ExecutionForensics.FileName | String | The file name. | 
| Fidelis.Alert.ExecutionForensics.DnsFeed | Boolean | Is there a DNS feed. | 
| Fidelis.Alert.ExecutionForensics.RecordingComplete | Boolean | Is the recording complete. | 
| Fidelis.Alert.ExecutionForensics.PcapUrl | String | The PCAP URL. | 
| Fidelis.Alert.ExecutionForensics.AlertFlagsXeNonsubmit | Boolean | The alert flag xe-nonsubmit. | 
| Fidelis.Alert.ExecutionForensics.Bit9Server | String | The bit 9 server. | 
| Fidelis.Alert.ExecutionForensics.DecodingPath | String | The execution forensics decoding path. | 
| Fidelis.Alert.ExecutionForensics.FileCheckAlert | Boolean | The file check alert. | 
| Fidelis.Alert.ExecutionForensics.Status | String | The execution forensics status. | 
| Fidelis.Alert.ExecutionForensics.Submitable | Boolean | Is the execution forensics submitable. | 
| Fidelis.Alert.ExecutionForensics.Score | Number | The execution forensics score. | 
| Fidelis.Alert.ExecutionForensics.SubmitId | String | The execution forensics submit ID. | 
| Fidelis.Alert.ExecutionForensics.VideoUrl | String | The video URL. | 
| Fidelis.Alert.ExecutionForensics.StatusMessage | String | The execution forensics status message. | 
| Fidelis.Alert.ExecutionForensics.FileType | String | The file type. | 
| Fidelis.Alert.ExecutionForensics.AlertId | Number | The alert ID. | 
| Fidelis.Alert.ExecutionForensics.Type | String | The type. | 
| Fidelis.Alert.ExecutionForensics.ReportUrl | String | The report URL. | 
| Fidelis.Alert.ExecutionForensics.JsSubmitable | Boolean | Is the execution forensics JS submitable. | 
| Fidelis.Alert.ExecutionForensics.Uuid | String | The UUID. | 
| Fidelis.Alert.ExecutionForensics.JsonReport | Unknown | The JSON report. | 
| Fidelis.Alert.ExecutionForensics.FileSize | Number | The file size. | 
| Fidelis.Alert.ExecutionForensics.Md5 | String | The file's MD5 hash. | 
| Fidelis.Alert.ExecutionForensics.ThreatGridOn | Boolean | Is the threat grid on. | 


##### Command Example
```!fidelis-get-alert-execution-forensics alert_id=9```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "ExecutionForensics": {
                "AlertFlagsXeNonsubmit": false,
                "AlertId": 9,
                "Bit9Server": null,
                "DecodingPath": null,
                "DnsFeed": false,
                "EFEnabled": true,
                "FileCheckAlert": true,
                "FileName": null,
                "FileSize": 2990,
                "FileType": "",
                "JsSubmitable": true,
                "JsonReport": null,
                "Md5": null,
                "PcapUrl": "",
                "RecordingComplete": true,
                "ReportUrl": "",
                "SandBoxOn": true,
                "Score": null,
                "Size": 0,
                "Status": "Submitted",
                "StatusMessage": null,
                "SubmitId": "0",
                "SubmitTime": 1585559253000,
                "Submitable": true,
                "TgReport": false,
                "ThreatGridOn": false,
                "Type": "alert",
                "Uuid": null,
                "VideoUrl": ""
            },
            "ID": "9"
        }
    }
}
```

##### Human Readable Output
### Alert 9
|Alert Flags Xe Nonsubmit|Alert Id|Dns Feed|EF Enabled|File Check Alert|File Size|Js Submitable|Recording Complete|Sand Box On|Size|Status|Submit Id|Submit Time|Submitable|Tg Report|Threat Grid On|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| false | 9 | false | true | true | 2990 | true | true | true | 0 | Submitted | 0 | 1585559253000 | true | false | false | alert |


### fidelis-get-alert-forensic-text
***
Get the text of the forensic data.


##### Base Command

`fidelis-get-alert-forensic-text`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ID | Number | The alert ID. | 
| Fidelis.Alert.ForensicText | String | The alert's forensic text. | 


##### Command Example
```!fidelis-get-alert-forensic-text alert_id=9```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "ForensicText": {file forensic text},
            "ID": "9"
        }
    }
}
```

##### Human Readable Output
Alert 9
Forensic Text: {file forensic text}

### fidelis-get-alert-decoding-path
***
Get the alert's decoding path.


##### Base Command

`fidelis-get-alert-decoding-path`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ID | Number | The alert ID. | 
| Fidelis.Alert.DecodingPath.ClickableDpaths | Unknown | The clickable decoding paths | 
| Fidelis.Alert.DecodingPath.CommandpostIp | String | The command post IP. | 
| Fidelis.Alert.DecodingPath.DecodingPaths | Unknown | The decoding path info. | 
| Fidelis.Alert.DecodingPath.OriginalAttributes | String | The original attribute. | 
| Fidelis.Alert.DecodingPath.OriginalDPath | String | The original path. | 
| Fidelis.Alert.DecodingPath.AttributeMap | Unknown | The attribute map. | 
| Fidelis.Alert.DecodingPath.AttributeMapHighLights | Unknown | The attribute map highlights. | 


##### Command Example
```!fidelis-get-alert-decoding-path alert_id=9```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "DecodingPath": {
                "AttributeMap": {
                    "HTTP": [
                        {
                            "endIndex": 29,
                            "highLights": [],
                            "link": false,
                            "name": "Filename",
                            "partialAttr": "HTTP\fFilename\tfile.pcap\n",
                            "startIndex": 0,
                            "value": "file.pcap",
                            "valueFirst255": "file.pcap"
                        }
                    ]
                },
                "AttributeMapHighLights": [],
                "ClickableDpaths": [
                    "HTTP(file.pcap)"
                ],
                "CommandpostIp": null,
                "DecodingPaths": [
                    {
                        "clickable": true,
                        "highLights": [],
                        "linkPath": ":HTTP(file.pcap)",
                        "path": "HTTP(file.pcap)"
                    }
                ],
                "OriginalAttributes": "HTTP\fFilename\tfile.pcap\n",
                "OriginalDPath": ":HTTP(file.pcap)"
            },
            "ID": "9"
        }
    }
}
```

##### Human Readable Output
### Alert 9
|Attribute Map|Clickable Dpaths|Decoding Paths|Original Attributes|Original D Path|
|---|---|---|---|---|
| HTTP: {u'endIndex': 29, u'name': u'Filename', u'valueFirst255': u'file.pcap', u'highLights': [], u'value': u'file.pcap', u'startIndex': 0, u'link': False, u'partialAttr': u'HTTP\x0cFilename\tfile.pcap\n'} | HTTP(file.pcap) | {u'clickable': True, u'highLights': [], u'linkPath': u':HTTP(file.pcap)', u'path': u'HTTP(file.pcap)'} | HTTPFilename	file.pcap<br/> | :HTTP(file.pcap) |


### fidelis-update-alert-status
***
Update alert status


##### Base Command

`fidelis-update-alert-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID | Required | 
| status | The new alert status. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!fidelis-update-alert-status alert_id=1 status=Actionable```


##### Human Readable Output
Alert 1 has been updated to Actionable status

### fidelis-alert-execution-forensics-submission
***
Submit an excutable file to the fidelis sandbox.


##### Base Command

`fidelis-alert-execution-forensics-submission`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ExecutionForensics.EFEnabled | Number | Is the alert execution forensics enabled. | 
| Fidelis.Alert.ExecutionForensics.Size | Number | The execution forensics size. | 
| Fidelis.Alert.ExecutionForensics.SubmitTime | Number | The submission time. | 
| Fidelis.Alert.ExecutionForensics.SandBoxOn | Boolean | Is the sandbox on. | 
| Fidelis.Alert.ExecutionForensics.TgReport | Boolean | The TG report. | 
| Fidelis.Alert.ExecutionForensics.FileName | String | The file name. | 
| Fidelis.Alert.ExecutionForensics.DnsFeed | Boolean | Is there a DNS feed. | 
| Fidelis.Alert.ExecutionForensics.RecordingComplete | Boolean | Is the recording complete. | 
| Fidelis.Alert.ExecutionForensics.PcapUrl | String | The PCAP URL. | 
| Fidelis.Alert.ExecutionForensics.AlertFlagsXeNonsubmit | Boolean | The alert flag xe-nonsubmit. | 
| Fidelis.Alert.ExecutionForensics.Bit9Server | String | The bit 9 server. | 
| Fidelis.Alert.ExecutionForensics.DecodingPath | String | The execution forensics decoding path. | 
| Fidelis.Alert.ExecutionForensics.FileCheckAlert | Boolean | The file check alert. | 
| Fidelis.Alert.ExecutionForensics.Status | String | The execution forensics status. | 
| Fidelis.Alert.ExecutionForensics.Submitable | Boolean | Is the execution forensics submitable. | 
| Fidelis.Alert.ExecutionForensics.Score | Number | The execution forensics score. | 
| Fidelis.Alert.ExecutionForensics.SubmitId | String | The execution forensics submit ID. | 
| Fidelis.Alert.ExecutionForensics.VideoUrl | String | The video URL. | 
| Fidelis.Alert.ExecutionForensics.StatusMessage | String | The execution forensics status message. | 
| Fidelis.Alert.ExecutionForensics.FileType | String | The file type. | 
| Fidelis.Alert.ExecutionForensics.AlertId | Number | The alert ID. | 
| Fidelis.Alert.ExecutionForensics.Type | String | The type. | 
| Fidelis.Alert.ExecutionForensics.ReportUrl | String | The report URL. | 
| Fidelis.Alert.ExecutionForensics.JsSubmitable | Boolean | Is the execution forensics JS submitable. | 
| Fidelis.Alert.ExecutionForensics.Uuid | String | The UUID. | 
| Fidelis.Alert.ExecutionForensics.JsonReport | Unknown | The JSON report. | 
| Fidelis.Alert.ExecutionForensics.FileSize | Unknown | The file size. | 
| Fidelis.Alert.ExecutionForensics.Md5 | String | The file's MD5 hash. | 
| Fidelis.Alert.ExecutionForensics.ThreatGridOn | Unknown | Is the threat grid on. | 
| Fidelis.Alert.ID | Number | The alert ID. | 


##### Command Example
```!fidelis-alert-execution-forensics-submission alert_id=9```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "ExecutionForensics": {
                "AlertFlagsXeNonsubmit": false,
                "AlertId": 9,
                "Bit9Server": null,
                "DecodingPath": null,
                "DnsFeed": false,
                "EFEnabled": true,
                "FileCheckAlert": true,
                "FileName": null,
                "FileSize": 2990,
                "FileType": "",
                "JsSubmitable": true,
                "JsonReport": null,
                "Md5": null,
                "PcapUrl": "",
                "RecordingComplete": true,
                "ReportUrl": "",
                "SandBoxOn": true,
                "Score": null,
                "Size": 0,
                "Status": "Submitted",
                "StatusMessage": null,
                "SubmitId": "0",
                "SubmitTime": 1585559253000,
                "Submitable": true,
                "TgReport": false,
                "ThreatGridOn": false,
                "Type": "alert",
                "Uuid": null,
                "VideoUrl": ""
            },
            "ID": "9"
        }
    }
}
```

##### Human Readable Output
### Alert 9
|Alert Flags Xe Nonsubmit|Alert Id|Dns Feed|EF Enabled|File Check Alert|File Size|Js Submitable|Recording Complete|Sand Box On|Size|Status|Submit Id|Submit Time|Submitable|Tg Report|Threat Grid On|Type|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| false | 9 | false | true | true | 2990 | true | true | true | 0 | Submitted | 0 | 1585559253000 | true | false | false | alert |


### fidelis-add-alert-comment
***
Adds a comment to an alert.


##### Base Command

`fidelis-add-alert-comment`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID | Required | 
| comment | comment | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!fidelis-add-alert-comment alert_id=1 comment="my new comment"```


##### Human Readable Output
Added this comment: my new comment
 To alert ID: 1

### fidelis-assign-user-to-alert
***
Assign a user to an alert.


##### Base Command

`fidelis-assign-user-to-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| conclusion_id | The alert conclusion ID. | Required | 
| comment | Add a comment to the alert | Optional | 
| assign_user | The user to assign. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.AssignedUser | String | Assigned user ID. | 
| Fidelis.Alert.ConclusionID | Number | The alert conclusion ID. | 


##### Command Example
```!fidelis-assign-user-to-alert assign_user=cloud-user conclusion_id=2```

##### Context Example
```
{
    "Fidelis": {
        "Alert": {
            "AssignedUser": "cloud-user",
            "ConclusionID": "2"
        }
    }
}
```

##### Human Readable Output
Assigned User: cloud-user to alert with conclusion ID 2

### fidelis-close-alert
***
Closes a fidelis alert and can assign a user.


##### Base Command

`fidelis-close-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| conclusion_id | The conclusion ID. | Required | 
| resolution | The alert resolution. | Required | 
| comment | Add a comment to the alert. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fidelis.Alert.ConclusionID | Number | The conclusion ID. | 


##### Command Example
```!fidelis-close-alert conclusion_id=2 resolution="False Positive"```


##### Human Readable Output
Closed alert conclusion ID 2

### fidelis-manage-alert-label
***
Adds a label to an alert.


##### Base Command

`fidelis-manage-alert-label`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 
| label | The label to add. | Required | 
| action | What action should be taken. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!fidelis-manage-alert-label action=Add alert_id=3 label="example-label"```


##### Human Readable Output
Assigned label: example-label to alert 3