The EndaceProbe Analytics Platform provides 100% accurate, continuous packet capture on network links up to 100Gbps, with unparalleled depth of storage and retrieval performance.  Coupled with the Endace InvestigationManager, this provides a central search and data-mining capability across a fabric of EndaceProbes deployed in a network. 
                                     
This integration uses Endace APIs to search, archive and download PCAP file from either a single EndaceProbe or many via the InvestigationManager and enables integration of full historical packet capture into security automation workflows.
This integration was integrated and tested with version 6.5.7 & 7.0.0 of Endace

## Configure Endace in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| applianceurl | EndaceProbe URL e.g. https://<fqdn/ip[:port]> | True |
| credentials | Username | True |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |
| hostname | EndaceProbe System Hostname | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### endace-create-search
***
Create a search task on EndaceProbe. Search is issued against all Rotation Files on EndaceProbe.


##### Base Command

`endace-create-search`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | UTC StartTime in ISO 8601 format as in 2020-04-08T15:46:30 | Optional | 
| end | UTC EndTime in ISO 8601 format  as in 2020-04-08T15:46:30 | Optional | 
| ip | directionless ip address. For valid search either a IP or Src Host or a Dest Host value is required. | Optional
| port | directionless port. | Optional
| src_host_list | List of comma delimited Source IP addresses to search with a maximum of 10 IP addresses per search. For valid search either a Src Host or a Dest Host value is required. | Optional | 
| dest_host_list | List of comma delimited Destination IP addresses to search with a maximum of 10 IP addresses per search. For valid search either a Src Host or a Dest Host value is required. | Optional | 
| src_port_list | List of comma delimited Source Port addresses to search with a maximum of 10 Port addresses per search. | Optional | 
| dest_port_list | List of comma delimited Destination Port addresses to search with a maximum of 10 Port addresses per search. | Optional | 
| protocol | IANA defined IP Protocol Name or Number. For example: either use TCP or tcp or 6 for tcp protocol | Optional | 
| timeframe | Event timeframe to search. Select one of the values from  30seconds, 1minute, 5minutes, 10minutes, 30minutes, 1hour, 2hours, 5hours, 10hours, 12hours, 1day, 3days, 5days, 1week. Timeframe works as search for last n seconds if start and end time is not provided. For example, by specifying 1hour as the timeframe, analyst can schedule a search for last 3600s. If both start and end time is provided, timeframe value is ignored. If either start or end time is provided along with timeframe, the respective start or end time is calculated accordingly. Initial value of timeframe is 1hour. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endace.Search.Task.JobID | String | Search Job ID | 
| Endace.Search.Task.Status | String | Status of Search Task | 
| Endace.Search.Task.Error | String | Search Error | 


##### Command Example
```!endace-create-search start="2020-04-15T14:48:12" ip="1.1.1.1" timeframe="1hour"```

##### Context Example
```
{
    "Endace": {
        "Search": {
            "Task": {
                "Error": "NoError",
                "JobID": "c944a329-bf16-4e51-ac58-900f17fa1a52",
                "Status": "Started",
                "Task": "CreateSearchTask"
            }
        }
    }
}
```

##### Human Readable Output
### EndaceResult
|Task|JobID|Status|Error|
|---|---|---|---|
| CreateSearchTask | c944a329-bf16-4e51-ac58-900f17fa1a52 | Started | NoError |


### endace-get-search-status
***
Get search status from EndaceProbe. This command can be polled in a loop until response is received or polling timer is over.


##### Base Command

`endace-get-search-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| jobid | This is the job ID returned by endace-create-search command | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endace.Search.Response.JobID | String | This is the job ID of search query which we polled to get search status |
| Endace.Search.Response.JobProgress | String | Progress of this search Job  | 
| Endace.Search.Response.DataSources | String | List of Data Sources where packets of interest were found. | 
| Endace.Search.Response.TotalBytes | String | Total data matching this search across all Data Sources. | 
| Endace.Search.Response.Status | String | Task status | 
| Endace.Search.Response.Error | String | Search response error  | 


##### Command Example
```!endace-get-search-status jobid="c944a329-bf16-4e51-ac58-900f17fa1a52"```

##### Context Example
```
{
    "Endace": {
        "Search": {
            "Response": {
                "DataSources": [endaceprobe-1:datasource1],
                "Error": "NoError",
                "JobID": "c944a329-bf16-4e51-ac58-900f17fa1a52",
                "JobProgress": "100",
                "Status": "complete",
                "Task": "GetSearchStatus",
                "TotalBytes": 5526100
            }
        }
    }
}
```

##### Human Readable Output
### EndaceSearch
|Task|JobID|Status|Error|JobProgress|DataSources|TotalBytes|
|---|---|---|---|---|---|---|
| GetSearchStatus | c944a329-bf16-4e51-ac58-900f17fa1a52 | complete | NoError | 100 | endaceprobe-1:datasource1 | 5526100 |


### endace-delete-search-task
***
Delete search task


##### Base Command

`endace-delete-search-task`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| jobid | Job ID obtained from endace-create-search command | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endace.Search.Delete.JobID | String | JobID of the task that needs to be deleted | 
| Endace.Search.Delete.Error | String | Error message  | 
| Endace.Search.Delete.Status | String | delete status, queryNotFound indicates that the search query has already expired before this operation, which is expected as EndaceProbe purges inactive tasks after api timer expire. Deleted indicates an active search query is now deleted.  | 


##### Command Example
```!endace-delete-search-task jobid="c944a329-bf16-4e51-ac58-900f17fa1a52"```

##### Context Example
```
{
    "Endace": {
        "Search": {
            "Delete": {
                "Error": "NoError",
                "JobID": "c944a329-bf16-4e51-ac58-900f17fa1a52",
                "Status": "Deleted",
                "Task": "DeleteSearchTask"
            }
        }
    }
}
```

##### Human Readable Output
### EndaceSearch
|Task|JobID|Status|Error|
|---|---|---|---|
| DeleteSearchTask | c944a329-bf16-4e51-ac58-900f17fa1a52 | Deleted | NoError |


### endace-create-archive
***
Create an archive task to archive packets of interest on EndaceProbe. Archived packets can later be downloaded from EndaceProbe as a PCAP file. Archived Files never expire. Allowed chars are text, numbers, dash and underscore.


##### Base Command

`endace-create-archive`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start | UTC StartTime in ISO 8601 format as in 2020-04-08T15:46:30 | Optional | 
| end | UTC EndTime in ISO 8601 format  as in 2020-04-08T15:46:30 | Optional |
| ip | directionless ip address. | Optional
| port | directionless port. For valid search either a Src Host or a Dest Host value is required. | Optional 
| timeframe | Event timeframe to search. Select one of the values from  30seconds, 1minute, 5minutes, 10minutes, 30minutes, 1hour, 2hours, 5hours, 10hours, 12hours, 1day, 3days, 5days, 1week. Timeframe works as search for last n seconds if start and end time is not provided. For example, by specifying 1hour as the timeframe, analyst can schedule a search for last 3600s. If both start and end time is provided, timeframe value is ignored. If either start or end time is provided along with timeframe, the respective start or end time is calculated accordingly. Initial value of timeframe is 1hour. | Optional | 
| src_host_list | List of comma delimited Source IP addresses to search with a maximum of 10 IP addresses per search. For valid search either a Src Host or a Dest Host value is required.| Optional | 
| dest_host_list | List of comma delimited Destination IP addresses to search with a maximum of 10 IP addresses per search. For valid search either a Src Host or a Dest Host value is required.| Optional | 
| src_port_list | List of comma delimited Source Port addresses to search with a maximum of 10 Port addresses per search. | Optional | 
| dest_port_list | List of comma delimited Destination Port addresses to search with a maximum of 10 Port addresses per search. | Optional | 
| protocol | IANA defined IP Protocol Name or Number. For example: either use TCP or tcp or 6 for tcp protocol  | Optional | 
| archive_filename | Name of the archive file. For example, archive_filename could be an event ID. To keep archive filename unique, value of epoch seconds at the time of execution of the command is appended to this filename argument. For example - if the event id is eventid, then archive_filename is eventid-[epochtime]. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endace.Archive.Task.FileName | String | Name of the archived File | 
| Endace.Archive.Task.P2Vurl | String | Endace Pivot to Vision URL to archived packets that links to an Investigation Dashboard on EndaceProbe. This enables an analyst to utilize tools available on EndaceProbe for further drill down on packets of interests without needing to download a PCAP. | 
| Endace.Archive.Task.Status | String | Status of archived task | 
| Endace.Archive.Task.Error | String | Archive error | 
| Endace.Archive.Task.JobID | String | Archive Task Job ID | 


##### Command Example
```!endace-create-archive start="2020-04-15T14:48:12" archive_filename="event" ip="1.1.1.1" timeframe="1hour"```

##### Context Example
```
{
    "Endace": {
        "Archive": {
            "Task": {
                "End": 1586965692,
                "Error": "NoError",
                "FileName": "event-1586976954",
                "JobID": "495f1899-6f27-4ed9-85c9-2af19a4e55d8",
                "P2Vurl": "[Endace PivotToVision URL](https://endaceprobe-1/vision2/pivotintovision/?datasources=tag:rotation-file&title=event-1586976954&start=1586962092000&end=1586965692000&tools=trafficOverTime_by_app%2Cconversations_by_ipaddress&ip=1.1.1.1)",
                "Start": 1586962092,
                "Status": "Started",
                "Task": "CreateArchiveTask"
            }
        }
    }
}
```

##### Human Readable Output
### EndaceResult
|Task|FileName|P2Vurl|Status|Error|JobID|
|---|---|---|---|---|---|
| CreateArchiveTask | event-1586976954 | [Endace PivotToVision URL](https://endaceprobe-1/vision2/pivotintovision/?datasources=tag:rotation-file&title=event-1586976954&start=1586962092000&end=1586965692000&tools=trafficOverTime_by_app%2Cconversations_by_ipaddress&ip=1.1.1.1) | Started | NoError | 495f1899-6f27-4ed9-85c9-2af19a4e55d8 |


### endace-get-archive-status
***
get status of archived task


##### Base Command

`endace-get-archive-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| archive_filename | Get status of this archived file | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endace.Archive.Response.FileName | String | Archived File Name | 
| Endace.Archive.Response.FileSize | String | Archived File Size | 
| Endace.Archive.Response.Status | String | Status of the archive process | 
| Endace.Archive.Response.Error | String | Archive response error | 


##### Command Example
```!endace-get-archive-status archive_filename="event-1586976861"```

##### Context Example
```
{
    "Endace": {
        "Archive": {
            "Response": {
                "Error": "NoError",
                "FileName": "event-1586976861",
                "FileSize": "6.29MB",
                "Status": "Finished",
                "Task": "GetArchiveStatus"
            }
        }
    }
}
```

##### Human Readable Output
### EndaceResult
|Task|FileName|Status|Error|FileSize|
|---|---|---|---|---|
| GetArchiveStatus | event-1586976861 | Finished | NoError | 6.29MB |


### endace-delete-archive-task
***
delete archive task


##### Base Command

`endace-delete-archive-task`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| jobid | Job ID of archive task | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endace.Archive.Delete.Status | String | Status of delete task | 
| Endace.Archive.Delete.Error | String | Delete task error | 
| Endace.Archive.Delete.JobID | String | Delete Task ID | 


##### Command Example
```!endace-delete-archive-task jobid="83fec7a8-daec-42fb-9b5a-e742145e85e8"```

##### Context Example
```
{
    "Endace": {
        "Archive": {
            "Delete": {
                "Error": "NoError",
                "JobID": "83fec7a8-daec-42fb-9b5a-e742145e85e8",
                "Status": "Deleted",
                "Task": "DeleteArchiveTask"
            }
        }
    }
}
```

##### Human Readable Output
### EndaceResult
|Task|JobID|Status|Error|
|---|---|---|---|
| DeleteArchiveTask | 83fec7a8-daec-42fb-9b5a-e742145e85e8 | Deleted | NoError |


### endace-download-pcap
***
Download a copy of the PCAP file from EndaceProbe if PCAP file size is within the threshold value defined by filesizelimit.


##### Base Command

`endace-download-pcap`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filename | Name of the file (without extension) to download from EndaceProbe. Text, numbers, underscore or dash is supported.  | Required | 
| filesizelimit | User defined upper size limit on file download (in MegaBytes). A PCAP File with size less than or equal to this limit can be downloaded from EndaceProbe. Minimum size is 1 (MB). Default Upper Limit is 50 (MB).  | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endace.Download.PCAP.FileName | String | Name of the File to download from EndaceProbe | 
| Endace.Download.PCAP.FileSize | String | File size in MegaBytes | 
| Endace.Download.PCAP.FileType | String | The file downloaded from EndaceProbe is either a Rotation File or Archive. | 
| Endace.Download.PCAP.FileURL | String | URL to PCAP file on EndaceProbe.  | 
| Endace.Download.PCAP.FileUser | String | Username of the person who has permission to download this PCAP from EndaceProbe. | 
| Endace.Download.PCAP.Status | String | Download status of the PCAP file.  | 
| Endace.Download.PCAP.Error | String | Error occured during downloading of this file | 


##### Command Example
```!endace-download-pcap filename="event-1586976861" filesizelimit="50"```

##### Context Example
```
{
    "Endace": {
        "Download": {
            "PCAP": {
                "Error": "NoError",
                "FileName": "event-1586976861.pcap",
                "FileSize": "6.29MB",
                "FileType": "archive_file",
                "FileURL": "[Endace PCAP URL](https://endaceprobe-1/vision2/data/files/b20e43e6-2cf7-1af2-3665-01016cb2daba/stream?format=pcap)",
                "FileUser": "admin",
                "Status": "DownloadFinished",
                "Task": "DownloadPCAP"
            }
        }
    },
    "InfoFile": {
        "EntryID": "4450@59d61022-f169-427a-8767-77ab234fa692",
        "Extension": "pcap",
        "Info": "pcap",
        "Name": "event-1586976861.pcap",
        "Size": 5722924,
        "Type": "tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 16384)"
    }
}
```

##### Human Readable Output
### EndaceResult
|Task|FileName|Status|Error|FileSize|FileType|FileUser|FileURL|
|---|---|---|---|---|---|---|---|
| DownloadPCAP | event-1586976861.pcap | DownloadFinished | NoError | 6.29MB | archive_file | admin | [Endace PCAP URL](https://endaceprobe-1/vision2/data/files/b20e43e6-2cf7-1af2-3665-01016cb2daba/stream?format=pcap) |


### endace-delete-archived-file
***
Delete an archived file from EndaceProbe.


##### Base Command

`endace-delete-archived-file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| archived_filename | Base name of the archived file to be deleted on EndaceProbe. Filename must be without any extension. Refer to Endace.Archive.Response.FileName field | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endace.ArchivedFile.Delete.FileName | String | Filename of the deleted archived file | 
| Endace.ArchivedFile.Delete.Status | String | Archived File Delete task status | 
| Endace.ArchivedFile.Delete.Error | String | Delete Error | 


##### Command Example
```!endace-delete-archived-file archived_filename="event-1586976861"```

##### Context Example
```
{
    "Endace": {
        "ArchivedFile": {
            "Delete": {
                "Error": "NoError",
                "FileName": "event-1586976861",
                "Status": "FileDeleted",
                "Task": "DeleteArchivedFile"
            }
        }
    }
}
```

##### Human Readable Output
### EndaceResult
|Task|FileName|Status|Error|
|---|---|---|---|
| DeleteArchivedFile | event-1586976861 | FileDeleted | NoError |
