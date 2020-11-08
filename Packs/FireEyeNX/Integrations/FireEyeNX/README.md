FireEye Network Security is an effective cyber threat protection solution that helps organizations minimize the risk of costly breaches by accurately detecting and immediately stopping advanced, targeted, and other evasive attacks hiding in internet traffic.
This integration was integrated and tested with version 2.0.0 of FireEyeNX APIs.

## Configure FireEyeNX on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FireEyeNX.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| credentials | Username | True |
| request_timeout | HTTP\(S\) Request Timeout \(in seconds\) | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| first_fetch | First fetch time interval | False |
| max_fetch | Fetch Limit | False |
| fetch_type | Fetch Types | False |
| fetch_mvx_correlated_events | Fetches MVX-correlated events only. | False |
| malware_type | Alert Malware Type | False |
| replace_alert_url | Use instance URL for all the fetched alerts URL. | False |
| fetch_artifacts | Fetch artifacts for each alert. | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fireeye-nx-get-alerts
***
Search and retrieve FireEye alerts based on several filters.


#### Base Command

`fireeye-nx-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID number of the alert to retrieve. To retrieve the alert ID, execute the fireeye-nx-get-alerts command without specifying the alert_id. | Optional | 
| src_ip | The source IPv4 address related to the malware alert to retrieve. | Optional | 
| dst_ip | The destination IPv4 address related to the malware alert to retrieve. | Optional | 
| duration | The time interval to search. This filter is used with either the start_time or end_time filter. If duration, start time, and end time are not specified, the system defaults to duration=12_hours, end_time=current_time. If only the duration is specified, the end_time defaults to the current_time. Possible values are: "1_hour", "2_hours", "6_hours", "12_hours", "24_hours", and "48_hours". | Optional | 
| start_time | The start time of the search. This filter is used with the duration filter. If the start_time is specified but not the duration, the system defaults to duration=12_hours, starting at the specified start_time.<br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days <br/>N hours<br/>Example:<br/> 2020-05-01 <br/> 2020-05-01T00:00:00 <br/> 2 days <br/> 5 hours | Optional | 
| end_time | The end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time.<br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days <br/>N hours<br/>Example:<br/> 2020-05-01 <br/> 2020-05-01T00:00:00 <br/> 2 days <br/> 5 hours | Optional | 
| file_name | The name of the malware file to retrieve. | Optional | 
| file_type | The malware file type to retrieve. | Optional | 
| info_level | The level of information to retrieve. Possible values are: "concise", "normal", and "extended". | Optional | 
| malware_name | The name of the malware object to retrieve. | Optional | 
| malware_type | The type of the malware object to retrieve. Possible values are: "domain_match", "malware_callback", "malware_object", "web_infection", and "infection_match". | Optional | 
| md5 | The MD5 hash of the alert to retrieve. This filter is not time dependent; it does not default to duration=12_hours. | Optional | 
| url | A specific alert URL to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Md5Sum | String | The md5sum of malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Sha256 | String | The SHA256 hash of malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Application | String | The application of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.HttpHeader | String | The HTTP header of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Original | String | The filename of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Name | String | The name of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Sid | String | The SID of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Type | String | The file type of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Stype | String | The STYPE of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Url | String | The URL of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Content | String | The content of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.CncServices.CncService.Address | String | The CNC service IP address associated with the alert. | 
| FireEyeNX.Alert.Explanation.CncServices.CncService.Channel | String | The CNC service channel associated with the alert. | 
| FireEyeNX.Alert.Explanation.CncServices.CncService.Port | Number | The CNC service port address associated with the alert. | 
| FireEyeNX.Alert.Explanation.CncServices.CncService.Protocol | String | The CNC service protocol associated with the alert. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Totalmemory | Number | The total memory of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Lastbytesreceived | Number | The last byte received in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Processinfo.Imagepath | String | The image path of the process in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Processinfo.Md5sum | String | The md5sum of the process in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Processinfo.Pid | Number | The PID of the process in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.IncrementCount | Number | The increment count in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Name | String | The name of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Bytesreceived | Number | The bytes received in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Lasttotalmemory | Number | The last total memory in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Type | String | The type of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Timestamp | Number | The timestamp of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.RCount | Number | The RCount of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.TotalSize | String | The total size of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.RUnit | String | The RUnit of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Mode | String | The mode of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Pattern | String | The pattern of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.Percentage | Number | The entry percentage of the bytes list in the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.Byte | String | The entry byte of the bytes list in the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.Count | Number | The entry count of the bytes list in the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.FirstOffset | String | The entry offset of the bytes list in the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.IsNOP | String | If entry NOP appears in the bytes list in the heap spraying then yes, otherwise no. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Distinct | Number | The distinct number of the byte list in the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Count | Number | The number of the byte list in the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Javascript | String | If heap spraying has javascript then yes, otherwise no. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.DNA | Number | The DNA of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.TotalRCount | Number | The total row count of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.ProcessedRCount | Number | The processed row count of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Processed | String | The processed memory of the heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Fid.Ads | String | The FID ads of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Fid.Content | Number | The FID content of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.UserSid | String | The parent user account SID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.SessionId | Number | The parent user account session ID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.UserAccountName | String | The parent user account name of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.AuthenticationId | String | The parent user account authentication ID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.SuperPrivilegesPresent | Number | If super privileges are present in this process then 1, otherwise 0. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Parentname | String | The path of the parent process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Sha256sum | String | The sha256sum of the parent process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Pid | Number | The PID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Filesize | Number | File size of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Ppid | Number | The PPID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Mode | String | The mode of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Cmdline | String | The path of the command associated with the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Sha1sum | String | The sha1sum of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Md5sum | String | The md5sum of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.SrcThread | String | The source thread name of the process. | 
| FireEyeNX.Alert.Explanation.osChanges.Process.Value | String | The value of the path in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.UserSid | String | The SID of the user account for the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.SessionId | Number | The session ID of the user account for the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.UserAccountName | String | The name of the user account for the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.AuthenticationId | String | The authentication ID of the user account for the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.SuperPrivilegesPresent | Number | If super privileges are present in this user account then 1, otherwise 0. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Timestamp | Number | The timestamp of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.MemoryData | String | The memory data of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.LocalThreadCount | Number | The local thread count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.FileOpenCount | Number | The file open count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.FileModifyCount | Number | The file modify count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.FileCreateCount | Number | The file created count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.ChildProcessCount | Number | The file process count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.FileFailedCount | Number | The file failed count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.HttpReqCount | Number | The HTTP request count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.RemoteThreadCount | Number | The remote thread count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.MutexCreateCount | Number | The mutex-created count of the telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Mode | String | The mode of the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Processinfo.Imagepath | String | The image path of the process in the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Processinfo.Md5sum | String | The md5sum of the process in the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Processinfo.Pid | Number | The PID of the process in the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Ntstatus | String | The NTSTATUS of the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Suppressed | Boolean | If the registry key was suppressed then true, otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Value | String | The value of the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Timestamp | Number | The timestamp of the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.SrcThread | String | The source thread name of the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Randomized | Boolean | If the registry key was randomized then true, otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Buffered | Boolean | If the registry key was buffered then true, otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.NoExtend | Boolean | If the registry key has no_extend then true, otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.Os.Name | String | The name of the operating system. | 
| FireEyeNX.Alert.Explanation.OsChanges.Os.Arch | String | The architecture of the operating system. | 
| FireEyeNX.Alert.Explanation.OsChanges.Os.Version | String | The version of the operating system. | 
| FireEyeNX.Alert.Explanation.OsChanges.Os.Sp | Number | The service pack version of the operating system. | 
| FireEyeNX.Alert.Explanation.OsChanges.OsMonitor.Date | String | The monitored date of the operating system. | 
| FireEyeNX.Alert.Explanation.OsChanges.OsMonitor.Build | Number | The monitored build of the operating system. | 
| FireEyeNX.Alert.Explanation.OsChanges.OsMonitor.Time | String | The monitored time of the operating system. | 
| FireEyeNX.Alert.Explanation.OsChanges.OsMonitor.Version | String | The monitored version of the operating system. | 
| FireEyeNX.Alert.Explanation.OsChanges.Analysis.Mode | String | The mode of the analysis. | 
| FireEyeNX.Alert.Explanation.OsChanges.Analysis.Product | String | The product name of the analysis. | 
| FireEyeNX.Alert.Explanation.OsChanges.Analysis.Ftype | String | The file type of the analysis. | 
| FireEyeNX.Alert.Explanation.OsChanges.Analysis.Version | String | The version of the analysis. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Mode | String | The mode of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.ProtocolType | String | The protocol type of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Ipaddress | String | The IP address of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.DestinationPort | Number | The destination port address of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Processinfo.Imagepath | String | The image path of the process in the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Processinfo.Tainted | Boolean | If the process state is tainted then true, otherwise false for the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Processinfo.Md5sum | String | The md5sum of the process in the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Processinfo.Pid | Number | The PID of the process in the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.HttpRequest | String | The HTTP request of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Timestamp | Number | The timestamp of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Hostname | String | The hostname of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Qtype | String | The QTYPE of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.AnswerNumber | Number | The answer number of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.DnsResponseCode | Number | The DNS response code of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Mode | String | The mode of opening the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Ext | String | The extension of opening the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Buffered | Boolean | If the opened file was buffered then true, otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.NoExtend | Boolean | If the opened file has no_extend then true, otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Name | String | The name of the action for opening the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Timestamp | Number | The timestamp of opening the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Dllname | String | The DLL file name of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Apiname | String | The API name of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Address | String | The address of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Processinfo.Imagepath | String | The image path of the process in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Processinfo.Md5sum | String | The md5sum of the process in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Processinfo.Pid | Number | The PID of the process in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.SrcThread | String | The source thread name of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Protection | String | The protection number of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.SymbolName | String | The symbol name of the call stack entry in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.FrameNumber | Number | The frame number of the call stack entries in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.ModuleName | String | The module name of the call stack entry in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.InstructionAddress | String | The instruction address of the call stack entry in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.SymbolDisplacement | String | The symbol displacement of the call stack entry in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Params.Param.Id | Number | The ID parameter of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Params.Param.Content | String | The path parameter of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Timestamp | Number | The timestamp of the exploit codes. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Mode | String | The mode of the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Processinfo.Imagepath | String | The image path of the process in the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Processinfo.Md5sum | String | The md5sum of the process in the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Processinfo.Pid | Number | The PID of the process in the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.SrcThread | String | The source thread name of the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Value | String | The path of the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Timestamp | Number | The timestamp of the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Mode | String | The mode of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Fid.Ads | String | The Alternate Data Stream \(ADS\) of the FID for the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Fid.Content | Number | The content of the FID in the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Processinfo.Imagepath | String | The image path of the process for the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Processinfo.Md5sum | String | The md5sum of the process for the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Processinfo.Pid | Number | The PID of the process for the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Processinfo.Tainted | Boolean | If the process state is tainted then true, otherwise false for the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.SrcThread | String | The source thread name of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Ntstatus | String | The NTSTATUS of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Filesize | Number | The size of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Value | String | The value of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.CreateOptions | String | The created option of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Timestamp | Number | The timestamp of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Type | String | The type of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Sha256sum | String | The sha256sum of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Sha1sum | String | The sha1sum of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.InspectionType | String | The inspection type of the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.TimeDateStamp | String | The time date stamp of the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Characteristics.Names.Name | Unknown | The list of characteristic names in the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Characteristics.Value | String | The characteristic value in the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.DllCharacteristics.Names | String | The characteristic name in the DLL portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.DllCharacteristics.Value | String | The characteristic value in the DLL portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Dll | String | If the portable file is a DLL file then yes, otherwise no file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Magic | String | The magic hex value of the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Subsystem | String | The subsystem of the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Machine | String | The hexadecimal address of the machine in the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Md5sum | String | The md5sum of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.Application.AppName | String | The app name of the application. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Processinfo.Imagepath | String | The image path of the queried system process. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Processinfo.Md5sum | String | The system time process info of the md5sum that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Processinfo.Pid | Number | The system time process info of the PID \(process ID\) that is queried | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Ntstatus | String | The NTSTATUS of the system time that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Timestamp | Number | The timestamp of the system that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.SystemTime.Value | String | The time value of the system that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.SystemTime.Time | String | The time of the system that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.EndOfReport | String | The end of the report. | 
| FireEyeNX.Alert.Explanation.OsChanges.MaliciousAlert.Classtype | String | The class type of the malicious alert. | 
| FireEyeNX.Alert.Explanation.OsChanges.MaliciousAlert.DisplayMsg | String | The display message of the malicious alert. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Hwnd | String | The hexadecimal address of the dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Processinfo.Imagepath | String | The image path of the process for the dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Processinfo.Pid | Number | The PID of the process for the dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Buffered | Boolean | A flag indicating whether the dialog detected is buffered. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.NoExtend | Boolean | A flag indicating whether NoExtend is true in the dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Timestamp | Number | The timestamp of the dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.DlgId | String | The dialog ID of the dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Note | String | A note in the dismissed dialog. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Hwnd | String | The hexadecimal address of the dismissed dialog. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Processinfo.Imagepath | String | The image path of the process for the dismissed dialog. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Processinfo.Pid | Number | The PID of the process for the dismissed dialog. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Buffered | Boolean | A flag indicating whether the dismissed dialog is buffered. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.NoExtend | Boolean | A flag indicating whether NoExtend is true in the dismissed dialog. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Timestamp | Number | The timestamp of the dismissed dialog. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.DlgId | String | The dialog ID of the dismissed dialog. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Processinfo.Imagepath | String | The image path of the process for the Windows Management Instrumentation \(WMI\) query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Processinfo.Md5sum | String | The md5sum of the process for the WMI query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Processinfo.Pid | Number | The PID of the process for the WMI query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Wmicontents.Wmiconent.Query | String | The query for the WMI content for WMI query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Wmicontents.Wmicontent.Lang | String | Language of the WMI content for the WMI query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Timestamp | Number | The timestamp of the WMI query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Buffered | Boolean | A flag indicating whether the WMI query is buffered. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.NoExtend | Boolean | A flag indicating whether NoExtend is true in the WMI query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Uac.Mode | String | The mode of the User Account Control \(UAC\). | 
| FireEyeNX.Alert.Explanation.OsChanges.Uac.Value | String | The value of the User Account Control. | 
| FireEyeNX.Alert.Explanation.OsChanges.Uac.Timestamp | Number | The timestamp of the User Account Control. | 
| FireEyeNX.Alert.Explanation.OsChanges.Uac.Status | String | The status of the User Account Control. | 
| FireEyeNX.Alert.Explanation.StaticAnalysis.Static.Value | String | The value of the static analysis. | 
| FireEyeNX.Alert.Explanation.StolenData.Info.Field | Unknown | The information field of the stolen data. | 
| FireEyeNX.Alert.Explanation.StolenData.Info.Type | String | The information type of the stolen data. | 
| FireEyeNX.Alert.Explanation.StolenData.EventId | Number | The event ID of the stolen data. | 
| FireEyeNX.Alert.Src.Ip | String | The source IP address of the alert. | 
| FireEyeNX.Alert.Src.Mac | String | The source MAC address of the alert. | 
| FireEyeNX.Alert.Src.Port | Number | The source port address of the alert. | 
| FireEyeNX.Alert.Src.Host | String | The source host of the alert. | 
| FireEyeNX.Alert.AlertUrl | String | The alert URL. | 
| FireEyeNX.Alert.Action | String | The action of the alert. | 
| FireEyeNX.Alert.Occurred | String | The time when the alert occurred. | 
| FireEyeNX.Alert.AttackTime | String | The time when an attack occurred. | 
| FireEyeNX.Alert.Dst.Mac | String | The destination MAC address of the alert. | 
| FireEyeNX.Alert.Dst.Port | Number | The destination port address of the alert. | 
| FireEyeNX.Alert.Dst.Ip | String | The destination IP address of the alert. | 
| FireEyeNX.Alert.ApplianceId | String | The appliance ID of the alert. | 
| FireEyeNX.Alert.Id | Number | The ID of the alert. | 
| FireEyeNX.Alert.Name | String | The type of the alert. | 
| FireEyeNX.Alert.Severity | String | The severity of the alert. | 
| FireEyeNX.Alert.Uuid | String | The universally unique identifier \(UUID\) of the alert. | 
| FireEyeNX.Alert.Ack | String | A flag indicating whether an acknowledgment is received. | 
| FireEyeNX.Alert.Product | String | The product name of the alert. | 
| FireEyeNX.Alert.Vlan | Number | The virtual LAN \(VLAN\) of the alert. | 
| FireEyeNX.Alert.Malicious | String | A flag indicating whether the alert is malicious. | 
| FireEyeNX.Alert.ScVersion | String | The SC version of the alert. | 


#### Command Example
```!fireeye-nx-get-alerts```

#### Context Example
```
{
    "FireEyeNX": {
        "Alert": [
            {
                "Ack": "no",
                "Action": "notified",
                "AlertUrl": "https://fireeye-941918/event_stream/events_for_bot?ev_id=11364",
                "ApplianceId": "866ED7558A08",
                "AttackTime": "2020-09-29 18:30:01 +0000",
                "Dst": {
                    "Mac": "xx:xx:xx:xx:xx:xx",
                    "Ip": "1.1.1.1",
                    "Port": 0
                },
                "Explanation": {
                    "MalwareDetected": {
                        "Malware": [
                            {
                                "Name": "dummy malware name 1"
                            }
                        ]
                    }
                },
                "Id": 1,
                "Malicious": "yes",
                "Name": "dummy name 1",
                "Occurred": "0000-00-00 02:12:53 +0000",
                "Product": "WEB_MPS",
                "ScVersion": "1.000",
                "Severity": "MINR",
                "Src": {
                    "Ip": "1.1.1.1",
                    "Port": 0,
                    "Mac": "xx:xx:xx:xx:xx:xx"
                },
                "Uuid": "0b0b0b0b0-0b0b0b-0b0b-0b0b-0b0b0b0b0b",
                "Vlan": 0
            },
            {
                "Ack": "no",
                "Action": "notified",
                "AlertUrl": "https://fireeye-941918/event_stream/events_for_bot?ev_id=11365",
                "ApplianceId": "866ED7558A08",
                "AttackTime": "2020-09-29 19:00:01 +0000",
                "Dst": {
                    "Mac": "xx:xx:xx:xx:xx:xx",
                    "Ip": "1.1.1.1",
                    "Port": 0
                },
                "Explanation": {
                    "MalwareDetected": {
                        "Malware": [
                            {
                                "Name": "dummy malware name 2"
                            }
                        ]
                    }
                },
                "Id": 2,
                "Malicious": "yes",
                "Name": "dummy name 2",
                "Occurred": "0000-00-00 02:12:53 +0000",
                "Product": "WEB_MPS",
                "ScVersion": "1.000",
                "Severity": "MINR",
                "Src": {
                    "Ip": "1.1.1.1",
                    "Port": 0,
                    "Mac": "xx:xx:xx:xx:xx:xx"
                },
                "Uuid": "0a0a0a0a0-0a0a0a-0a0a-0a0a-0a0a0a0a0a",
                "Vlan": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Alert(s) Information
>|ID|Distinguisher(UUID)|Malware Name|Alert Type|Victim IP|Time (UTC)|Severity|Malicious|SC Version|Victim Port|Victim MAC Address|Target IP|Target Port|Target MAC Address|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 0b0b0b0b0-0b0b0b-0b0b-0b0b-0b0b0b0b0b | dummy malware name 1 | dummy name 1 | 1.1.1.1 | 0000-00-00 02:12:53 +0000 | MINR | yes | 1.000 | 0 | xx:xx:xx:xx:xx:xx | 1.1.1.1 | 0 | xx:xx:xx:xx:xx:xx |
>| 2 | 0a0a0a0a0-0a0a0a-0a0a-0a0a-0a0a0a0a0a | dummy malware name 2 | dummy name 2 | 1.1.1.1 | 0000-00-00 02:12:53 +0000 | MINR | yes | 1.000 | 0 | xx:xx:xx:xx:xx:xx | 1.1.1.1 | 0 | xx:xx:xx:xx:xx:xx |


### fireeye-nx-get-artifacts-metadata-by-alert
***
Gets malware artifacts metadata for the specified UUID.


#### Base Command

`fireeye-nx-get-artifacts-metadata-by-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Universally unique ID (UUID) of the alert. To retrieve the UUID, execute the fireeye-nx-get-alerts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeNX.Alert.Uuid | String | Universally unique ID \(UUID\) of the alert. | 
| FireEyeNX.Alert.ArtifactsMetadata.ArtifactType | String | The artifact type. | 
| FireEyeNX.Alert.ArtifactsMetadata.ArtifactName | String | The artifact name. | 
| FireEyeNX.Alert.ArtifactsMetadata.ArtifactSize | String | The artifact size. | 


#### Command Example
```!fireeye-nx-get-artifacts-metadata-by-alert uuid=0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b```

#### Context Example
```
{
    "FireEyeNX": {
        "Alert": {
            "ArtifactsMetadata": [
                {
                    "ArtifactType": "artifact type test 1",
                    "ArtifactName": "artifact name test 1",
                    "ArtifactSize": "1010"
                },
                {
                    "ArtifactType": "artifact type test 2",
                    "ArtifactName": "artifact name test 2",
                    "ArtifactSize": "1010"
                }
            ],
            "Uuid": "0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b"
        }
    }
}
```

#### Human Readable Output

>### Artifacts Metadata
>|Artifact Type|Artifact Name|Artifact Size (Bytes)|
>|---|---|---|
>| artifact type test 1 | artifact name test 1 | 1010 |
>| artifact type test 2 | artifact name test 2 | 1010 |

### fireeye-nx-get-artifacts-by-alert
***
Downloads malware artifacts data for the specified UUID as a zip file.


#### Base Command

`fireeye-nx-get-artifacts-by-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The universally unique ID (UUID) of the alert. To get the UUID, execute the fireeye-nx-get-alerts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | The file information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 


#### Command Example
```!fireeye-nx-get-artifacts-by-alert uuid=0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b```

#### Context Example
```
{
    "File": {
        "Size": 17277,
        "SHA1": "574352bb238d3379429063d71990c0000000000",
        "SHA256": "1f8ac8eaba9abaf9d12b9b82180a110eab15b14aeec14715f48b4dedaaaaaaaaa",
        "Name": "0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b.zip",
        "SSDeep": "000:aaaaaa/aAaAaAaA+AaAaAaAaA:aa0/aAaAaAaAaAaAaA",
        "EntryID": "150@1",
        "Info": "zip",
        "Type": "Zip archive data, at least v1.0 to extract",
        "MD5": "1aA1aA1aA1aA1aA1aA1aA1aA",
        "Extension": "zip"
    }
}
```


### fireeye-nx-get-reports
***
Returns reports on selected alerts by specifying a time_frame value or a start_time and end_time of the search range.


#### Base Command

`fireeye-nx-get-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_type | The type of report to be queried. | Required | 
| type | The output format of the report. Possible values are: "csv" and "pdf", or both depending upon the report type. | Optional | 
| start_time | The start time of the search. The search occurs between the start and end times. When specifying a start_time value, you must specify both a start_time and an end_ time value.<br/> Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days <br/>N hours<br/>Example:<br/> 2020-05-01 <br/> 2020-05-01T00:00:00 <br/> 2 days <br/> 5 hours. | Optional | 
| end_time | The end time of the search. The search occurs between the start and end times. When specifying an end_ time value, you must specify both a start_time and an end_time value.<br/> Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days <br/>N hours<br/>Example:<br/> 2020-05-01 <br/> 2020-05-01T00:00:00 <br/> 2 days <br/> 5 hours. | Optional | 
| time_frame | The time frame in which reports are searched. | Optional | 
| limit | The maximum number (N) of items covered by each IPS Top N report. This argument is required only for IPS Top N reports. Possible values are: "25", "50", "75", and "100". | Optional | 
| interface | The internet interface. Possible values are: "A", "B", "C", "D", "AB", and "All". This option is required only for IPS reports. | Optional | 
| infection_id | The alert ID. To retrieve the alert ID, execute the fireeye-nx-get-alerts command. Use the combination of infection_id and infection_type arguments to specify a unique alert to describe in the Alert Details Report. If one option is used alone and does not specify a unique alert, an error message is produced. | Optional | 
| infection_type | The type of the infection. Use the combination of infection_id and infection_type arguments to specify a unique alert to describe in the Alert Details Report. If one option is used alone and does not specify a unique alert, an error message is produced. Possible values are: "malware-object", "malware-callback", "infection-match", "domain-match", and "web-infection". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | String | The file name. | 
| InfoFile.EntryID | String | The ID for locating the file in the War Room. | 
| InfoFile.Size | Number | The size of the file \(in bytes\). | 
| InfoFile.Type | String | The file type, as determined by libmagic \(same as displayed in the file entries\). | 
| InfoFile.Extension | String | The file extension. | 
| InfoFile.Info | String | Basic information about the file. | 


#### Command Example
```!fireeye-nx-get-reports report_type="IPS Executive Summary Report" type=csv time_frame=between start_time=2020-01-29T23:59:59 end_time=2020-08-29T23:59:59```

#### Context Example
```
{
    "InfoFile": {
        "EntryID": "1052@8db8b36d-df26-4a3a-8f8a-40e45629ff54",
        "Extension": "csv",
        "Info": "csv",
        "Name": "ips_executive_summary_report_fireeye_20200709_151727878642.csv",
        "Size": 606,
        "Type": "ASCII text"
    }
}
```



### fireeye-nx-get-events
***
Search and retrieve FireEye events based on several filters.


#### Base Command

`fireeye-nx-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| duration | The time interval to search. This filter is used with the end_time filter. If the duration is not specified, the system defaults to duration=12_hours, end_time=current_time. | Optional | 
| start_time | The start time of the search. This filter is used with the duration filter. If the start_time is specified but not the duration, the system defaults to duration=12_hours, starting at the specified start_time.<br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days <br/>N hours<br/>Example:<br/> 2020-05-01 <br/> 2020-05-01T00:00:00 <br/> 2 days <br/> 5 hours | Optional | 
| end_time | The end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time. <br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>N days <br/>N hours<br/>Example:<br/> 2020-05-01 <br/> 2020-05-01T00:00:00 <br/> 2 days <br/> 5 hours | Optional | 
| mvx_correlated_only | Whether to include all IPS events or MVX-correlated events only. Default: false | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeNX.Event.EventId | Number | The ID of the event. | 
| FireEyeNX.Event.Occurred | String | The date and time when the event occurred. | 
| FireEyeNX.Event.SrcIp | String | The IP address of the victim. | 
| FireEyeNX.Event.SrcPort | Number | The port number of the victim. | 
| FireEyeNX.Event.DstIp | String | The IP address of the attacker. | 
| FireEyeNX.Event.DstPort | Number | The port number of the attacker. | 
| FireEyeNX.Event.Severity | Number | The severity level of the event. | 
| FireEyeNX.Event.SignatureRev | Number | The signature revision number of the event. | 
| FireEyeNX.Event.SignatureIden | Number | The signature identity number of the event. | 
| FireEyeNX.Event.SignatureMatchCnt | Number | The signature match count number of the event. | 
| FireEyeNX.Event.Vlan | Number | The virtual LAN \(VLAN\) of the event. | 
| FireEyeNX.Event.VmVerified | Boolean | Whether the event VM was verified. | 
| FireEyeNX.Event.SrcMac | String | The MAC address of the source machine. | 
| FireEyeNX.Event.DstMac | String | The MAC address of the destination machine. | 
| FireEyeNX.Event.RuleName | String | The rule name for the event. | 
| FireEyeNX.Event.SensorId | String | The sensor ID of the FireEye machine. | 
| FireEyeNX.Event.CveId | String | The CVE ID found in the event. | 
| FireEyeNX.Event.ActionTaken | Number | The IPS blocking action taken on the event. | 
| FireEyeNX.Event.AttackMode | String | The attack mode mentioned in the event. | 
| FireEyeNX.Event.InterfaceId | Number | The interface ID of the event. | 
| FireEyeNX.Event.Protocol | Number | The protocol used in the event. | 
| FireEyeNX.Event.IncidentId | Number | The incident ID of the event on FireEye. | 


#### Command Example
```!fireeye-nx-get-events duration=48_hours end_time=2020-08-10T06:31:00```

#### Context Example
```
{
    "FireEyeNX": {
        "Event": [
            {
              "EventId":1,
              "Occurred":"2020-08-10T06:31:00Z",
              "SrcIp":"1.1.1.1",
              "SrcPort":1,
              "DstIp":"1.1.1.1",
              "DstPort":1,
              "Vlan":0,
              "SignatureMatchCnt":1,
              "SignatureIden":1,
              "SignatureRev":1,
              "Severity":1,
              "VmVerified":true,
              "SrcMac":"dummy",
              "DstMac":"dummy",
              "RuleName":"dummy",
              "SensorId":"dummy",
              "CveId":"CVE-123",
              "ActionTaken":1,
              "AttackMode":"dummy",
              "InterfaceId":1,
              "Protocol":1,
              "IncidentId":1
            }
        ]
    }
}
```

#### Human Readable Output

>### IPS Events
>|Event ID|Time (UTC)|Victim IP|Attacker IP|CVE ID|Severity|Rule|Protocol|
>|---|---|---|---|---|---|---|---|
>| 1 | 2020-08-10T06:31:00Z | 1.1.1.1 | 1.1.1.1 | CVE-123 | 1 | dummy | 1 |


