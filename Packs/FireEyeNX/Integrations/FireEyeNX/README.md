FireEye Network Security is an effective cyber threat protection solution that helps organizations minimize the risk of costly breaches by  accurately detecting and immediately stopping advanced, targeted and other evasive attacks hiding in Internet traffic.
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

#### Base Command
### fireeye-nx-get-alerts
***
Search and Retrieve FireEye alerts based on several filters.

`fireeye-nx-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Specify the ID number of the alert to retrieve it. To get Alert ID execute fireeye-nx-get-alerts command without specifying alert_id. | Optional | 
| src_ip | The source IPv4 address related to the malware alert. | Optional | 
| dst_ip | The destination IPv4 address related to the malware alert. | Optional | 
| duration | Specifies the time interval to search. This filter is used with either the start_time or end_time filter. If duration, start time, and end time are not specified, the system defaults to duration=12_hours, end_time=current_time. If only duration is specified, the end_time defaults to the current_time.<br/><br/>Options: 1_hour, 2_hours, 6_hours, 12_hours, 24_hours, 48_hours<br/> | Optional | 
| start_time | Specifies the start time of the search. This filter is used with the duration filter. If the start_time is specified but not the duration, the system defaults to duration=12_hours, starting at the specified start_time.<br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>Example:<br/>2020-05-01<br/>2020-05-01T00:00:00 | Optional | 
| end_time | Specifies the end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time.<br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>Example:<br/>2020-05-01<br/>2020-05-01T00:00:00 | Optional | 
| file_name | The name of the malware file. | Optional | 
| file_type | The malware file type. | Optional | 
| info_level | Specifies the level of information to be returned.<br/><br/>Options: concise, normal, extended | Optional | 
| malware_name | The name of the malware object. | Optional | 
| malware_type | The type of malware object.<br/><br/>Options: domain_match, malware_callback, malware_object, web_infection, infection_match | Optional | 
| md5 | Searches for alerts that include a specific MD5 hash.This filter is not time dependent; it does not default to duration=12_hours. | Optional | 
| url | Searches for a specific alert URL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Md5Sum | String | MD5SUM of malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Sha256 | String | SHA256 of malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Application | String | Application of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.HttpHeader | String | Http Header of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Original | String | The filename of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Name | String | Name of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Sid | String | SID of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Type | String | The file type of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Stype | String | STYPE of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Url | String | URL of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.MalwareDetected.Malware.Content | String | Content of the malware associated with the alert. | 
| FireEyeNX.Alert.Explanation.CncServices.CncService.Address | String | CNC Service IP address associated with the alert. | 
| FireEyeNX.Alert.Explanation.CncServices.CncService.Channel | String | CNC Service channel associated with the alert. | 
| FireEyeNX.Alert.Explanation.CncServices.CncService.Port | Number | CNC Service port address associated with the alert. | 
| FireEyeNX.Alert.Explanation.CncServices.CncService.Protocol | String | CNC Service protocol associated with the alert. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Totalmemory | Number | Total memory of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Lastbytesreceived | Number | The last byte received in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Processinfo.Imagepath | String | Image path of the process in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Processinfo.Md5sum | String | MD5SUM of the process in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Processinfo.Pid | Number | PID of the process in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.IncrementCount | Number | Increment count in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Name | String | Name of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Bytesreceived | Number | Bytes received in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Lasttotalmemory | Number | The last total memory in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Type | String | Type of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Timestamp | Number | The timestamp of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.RCount | Number | RCount of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.TotalSize | String | The total size of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.RUnit | String | RUnit of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Mode | String | Mode of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Pattern | String | The pattern of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.Percentage | Number | Entry percentage of bytes list in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.Byte | String | Entry byte of bytes list in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.Count | Number | Entry count of bytes list in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.FirstOffset | String | Entry offset of bytes list in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Entry.IsNOP | String | If entry NOP comes in the bytes list in heap spraying then yes otherwise no. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Distinct | Number | The distinct number of the byte list in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.BytesList.Count | Number | The number of the byte list in heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Javascript | String | If heap spraying has javascript then yes otherwise no. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.DNA | Number | DNA of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.TotalRCount | Number | Total row count of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.ProcessedRCount | Number | Processed row count of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Heapspraying.Processed | String | Processed memory of heap spraying. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Fid.Ads | String | Fid ads of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Fid.Content | Number | Fid content of process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.UserSid | String | Parent user account SID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.SessionId | Number | Parent user account session ID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.UserAccountName | String | Parent user account name of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.AuthenticationId | String | Parent user account authentication ID of process | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.ParentUserAccount.SuperPrivilegesPresent | Number | If super privileges present in this process then 1 otherwise 0. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Parentname | String | Path of parent process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Sha256sum | String | SHA256SUM of the parent process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Pid | Number | PID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Filesize | Number | File size of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Ppid | Number | PPID of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Mode | String | Mode of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Cmdline | String | Path of the command associated with the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Sha1sum | String | SHA1SUM of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Md5sum | String | MD5SUM of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.SrcThread | String | Source thread name of the process. | 
| FireEyeNX.Alert.Explanation.osChanges.Process.Value | String | Value of path in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.UserSid | String | SID of a user account for the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.SessionId | Number | The session ID of a user account for the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.UserAccountName | String | Name of a user account for the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.AuthenticationId | String | Authentication ID of a user account for the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.UserAccount.SuperPrivilegesPresent | Number | If super privileges present in this user account then 1 otherwise 0. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.Timestamp | Number | The timestamp of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.MemoryData | String | The memory data of the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.LocalThreadCount | Number | Thread count of telemetry data in process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.FileOpenCount | Number | File open count of telemetry data in process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.FileModifyCount | Number | File modify count of telemetry data in process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.FileCreateCount | Number | File created count of telemetry data in process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.ChildProcessCount | Number | File process count of telemetry data in process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.FileFailedCount | Number | File failed count of telemetry data in process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.HttpReqCount | Number | Http request count of telemetry data in process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.RemoteThreadCount | Number | Thread count of telemetry data in process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Process.TelemetryData.MutexCreateCount | Number | Mutex created a count of telemetry data in the process. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Mode | String | Mode of registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Processinfo.Imagepath | String | Image path of the process in registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Processinfo.Md5sum | String | MD5SUM of the process in registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Processinfo.Pid | Number | PID of the process in registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Ntstatus | String | NTSTATUS of registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Suppressed | Boolean | If the registry key has suppressed then true otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Value | String | Value of registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Timestamp | Number | The timestamp of the registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.SrcThread | String | Source thread name of registry key. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Randomized | Boolean | If the registry key has randomized then true otherwise false | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.Buffered | Boolean | If the registry key has buffered then true otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.Regkey.NoExtend | Boolean | If the registry key has no_extend then true otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.Os.Name | String | The name of the OS. | 
| FireEyeNX.Alert.Explanation.OsChanges.Os.Arch | String | The architecture of the OS. | 
| FireEyeNX.Alert.Explanation.OsChanges.Os.Version | String | A version of the OS. | 
| FireEyeNX.Alert.Explanation.OsChanges.Os.Sp | Number | Service pack version of the OS. | 
| FireEyeNX.Alert.Explanation.OsChanges.OsMonitor.Date | String | A monitored date of the OS. | 
| FireEyeNX.Alert.Explanation.OsChanges.OsMonitor.Build | Number | A monitored build of the OS. | 
| FireEyeNX.Alert.Explanation.OsChanges.OsMonitor.Time | String | A monitored time of the OS. | 
| FireEyeNX.Alert.Explanation.OsChanges.OsMonitor.Version | String | A monitored version of the OS. | 
| FireEyeNX.Alert.Explanation.OsChanges.Analysis.Mode | String | A mode of analysis. | 
| FireEyeNX.Alert.Explanation.OsChanges.Analysis.Product | String | A product name of analysis. | 
| FireEyeNX.Alert.Explanation.OsChanges.Analysis.Ftype | String | A file type of analysis. | 
| FireEyeNX.Alert.Explanation.OsChanges.Analysis.Version | String | A version of analysis. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Mode | String | A mode of network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.ProtocolType | String | A protocol type of network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Ipaddress | String | An IP address of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.DestinationPort | Number | A destination port address of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Processinfo.Imagepath | String | Image path of the process in the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Processinfo.Tainted | Boolean | If the process state is tainted then true otherwise false for the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Processinfo.Md5sum | String | MD5SUM of the process in the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Processinfo.Pid | Number | PID of the process in the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.HttpRequest | String | HTTP request of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Timestamp | Number | The timestamp of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Hostname | String | A hostname of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.Qtype | String | A QTYPE of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.AnswerNumber | Number | An answer number of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.Network.DnsResponseCode | Number | A DNS response code of the network. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Mode | String | Mode of opening the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Ext | String | Extension of opening the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Buffered | Boolean | If the opened file has buffered then true otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.NoExtend | Boolean | If the opened file has no_extend then true otherwise false. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Name | String | The name of opening the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.ActionFopen.Timestamp | Number | The timestamp of opening the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Dllname | String | DLL file name of exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Apiname | String | API name of exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Address | String | An address of exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Processinfo.Imagepath | String | Image path of the process in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Processinfo.Md5sum | String | MD5SUM of the process in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Processinfo.Pid | Number | PID of the process in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.SrcThread | String | Source thread name of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Protection | String | Protection number of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.SymbolName | String | The symbol name of call stack entry in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.FrameNumber | Number | Frame number of call stack entries in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.ModuleName | String | Module name of call stack entry in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.InstructionAddress | String | Instruction address of call stack entry in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Callstack.CallstackEntry.SymbolDisplacement | String | Symbol displacement of call stack entry in the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Params.Param.Id | Number | ID parameter of the exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Params.Param.Content | String | Path parameter of exploit code. | 
| FireEyeNX.Alert.Explanation.OsChanges.Exploitcode.Timestamp | Number | The timestamp of the exploit codes. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Mode | String | Mode of folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Processinfo.Imagepath | String | Image path of the process in the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Processinfo.Md5sum | String | MD5SUM of the process in the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Processinfo.Pid | Number | PID of the process in the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.SrcThread | String | Source thread name of the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Value | String | Path of folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.Folder.Timestamp | Number | The timestamp of the folder. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Mode | String | The mode of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Fid.Ads | String | ADS \(Alternate Data Stream\) of FID for file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Fid.Content | Number | Content of FID in file | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Processinfo.Imagepath | String | Image path of the process for file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Processinfo.Md5sum | String | MD5SUM of the process for the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Processinfo.Pid | Number | PID of the process for the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Processinfo.Tainted | Boolean | If the process state is tainted then true otherwise false for the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.SrcThread | String | Source thread name of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Ntstatus | String | NTSTATUS of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Filesize | Number | Size of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Value | String | The value of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.CreateOptions | String | The created option of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Timestamp | Number | The timestamp of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Type | String | Type of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Sha256sum | String | SHA256SUM of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Sha1sum | String | SHA1SUM of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.InspectionType | String | Inspection type of portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.TimeDateStamp | String | The time date stamp of the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Characteristics.Names.Name | Unknown | List of characteristic names in the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Characteristics.Value | String | Characteristic value in the portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.DllCharacteristics.Names | String | Characteristic name in the DLL portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.DllCharacteristics.Value | String | Characteristic value in the DLL portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Dll | String | If a portable file is a DLL file then yes otherwise no file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Magic | String | Magic hex value of portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Subsystem | String | Sub system of portable executable file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.PE.Machine | String | Hex address of machine in file. | 
| FireEyeNX.Alert.Explanation.OsChanges.File.Md5sum | String | MD5SUM of the file. | 
| FireEyeNX.Alert.Explanation.OsChanges.Application.AppName | String | App name of the application. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Processinfo.Imagepath | String | Image path of the queried system process. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Processinfo.Md5sum | String | System time process info of Md5sum that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Processinfo.Pid | Number | System time process info of Pid \(process id\) that is queried | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Ntstatus | String | NTSTATUS of system time that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.Timestamp | Number | The timestamp of the system that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.SystemTime.Value | String | The time value of the system that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.QuerySystemTime.SystemTime.Time | String | The time of the system that is queried. | 
| FireEyeNX.Alert.Explanation.OsChanges.EndOfReport | String | The end of report. | 
| FireEyeNX.Alert.Explanation.OsChanges.MaliciousAlert.Classtype | String | Class type of malicious alert. | 
| FireEyeNX.Alert.Explanation.OsChanges.MaliciousAlert.DisplayMsg | String | Display message of malicious alert. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Hwnd | String | Hex address of dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Processinfo.Imagepath | String | Imagepath of the process for the dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Processinfo.Pid | Number | PID of the process for the dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Buffered | Boolean | Flag indicated whether is buffered or not in dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.NoExtend | Boolean | Flag indicating whether NoExtend is true or not in dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.Timestamp | Number | The timestamp of dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDetected.DlgId | String | Dialog ID of dialog detected. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Note | String | Note of dialog dismissed. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Hwnd | String | Hex address of dialog dismissed. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Processinfo.Imagepath | String | Imagepath of the process for the dialog dismissed. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Processinfo.Pid | Number | PID of the process for the dialog dismissed. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Buffered | Boolean | Flag indicating whether Buffered is true or not in the dialog dismissed. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.NoExtend | Boolean | Flag indicating whether NoExtend is true or not in dialog dismissed. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.Timestamp | Number | The timestamp of dialog dismissed. | 
| FireEyeNX.Alert.Explanation.OsChanges.DialogDismissed.DlgId | String | Dialog ID of dialog dismissed. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Processinfo.Imagepath | String | Imagepath of the process for wmi query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Processinfo.Md5sum | String | Md5sum of the process for wmi query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Processinfo.Pid | Number | Pid of the process for wmi query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Wmicontents.Wmiconent.Query | String | Query of wmi content for wmi query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Wmicontents.Wmicontent.Lang | String | Language of wmi content for wmi query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Timestamp | Number | The timestamp of wmi query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.Buffered | Boolean | This flag indicates whether it is buffered or not in the wmi query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Wmiquery.NoExtend | Boolean | Flag indicating whether NoExtend is true or not in wmi query. | 
| FireEyeNX.Alert.Explanation.OsChanges.Uac.Mode | String | Mode of User Account Control. | 
| FireEyeNX.Alert.Explanation.OsChanges.Uac.Value | String | Value of User Account Control. | 
| FireEyeNX.Alert.Explanation.OsChanges.Uac.Timestamp | Number | The timestamp of User Account Control. | 
| FireEyeNX.Alert.Explanation.OsChanges.Uac.Status | String | Status of User Account Control. | 
| FireEyeNX.Alert.Explanation.StaticAnalysis.Static.Value | String | Value of static analysis. | 
| FireEyeNX.Alert.Explanation.StolenData.Info.Field | Unknown | Info field of stolen data. | 
| FireEyeNX.Alert.Explanation.StolenData.Info.Type | String | Info type of stolen data. | 
| FireEyeNX.Alert.Explanation.StolenData.EventId | Number | Event ID of stolen data. | 
| FireEyeNX.Alert.Src.Ip | String | Source IP address of alert. | 
| FireEyeNX.Alert.Src.Mac | String | Source MAC address of alert. | 
| FireEyeNX.Alert.Src.Port | Number | Source PORT address of alert. | 
| FireEyeNX.Alert.Src.Host | String | Source host of alert. | 
| FireEyeNX.Alert.AlertUrl | String | Alert URL. | 
| FireEyeNX.Alert.Action | String | Action of Alert. | 
| FireEyeNX.Alert.Occurred | String | Time when alert occurred. | 
| FireEyeNX.Alert.AttackTime | String | Time when an attack occurred. | 
| FireEyeNX.Alert.Dst.Mac | String | Destination MAC address of alert. | 
| FireEyeNX.Alert.Dst.Port | Number | Destination PORT address of alert. | 
| FireEyeNX.Alert.Dst.Ip | String | Destination IP address of alert. | 
| FireEyeNX.Alert.ApplianceId | String | Appliance ID of alert. | 
| FireEyeNX.Alert.Id | Number | ID of alert. | 
| FireEyeNX.Alert.Name | String | Type of alert. | 
| FireEyeNX.Alert.Severity | String | Severity of alert. | 
| FireEyeNX.Alert.Uuid | String | UUID of alert. | 
| FireEyeNX.Alert.Ack | String | Flag indicates whether ack comes or not. | 
| FireEyeNX.Alert.Product | String | Product name of alert. | 
| FireEyeNX.Alert.Vlan | Number | VLAN of alert. | 
| FireEyeNX.Alert.Malicious | String | This flag indicates whether the alert is malicious or not. | 
| FireEyeNX.Alert.ScVersion | String | SC version of alert. | 

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

`fireeye-nx-get-artifacts-metadata-by-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Universally unique ID of the alert. Note: To get UUID execute fireeye-nx-get-alerts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeNX.Alert.Uuid | String | Universally unique ID of the alert. | 
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

`fireeye-nx-get-artifacts-by-alert `
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Universally unique ID of the alert. Note: To get UUID execute fireeye-nx-get-alerts command. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
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
| type | The output format of the report. Accepted values are csv, pdf, or both depending upon report type. | Optional | 
| start_time | Searches between two specified time frames. When specifying a start_time value, you must specify both a start_time and an end_ time value.<br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>Example:<br/>2020-05-01<br/>2020-05-01T00:00:00 | Optional | 
| end_time | Searches between two specified time frames. When specifying an end_ time value, you must specify both a start_time and an end_time value.<br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>Example:<br/>2020-05-01<br/>2020-05-01T00:00:00 | Optional | 
| time_frame | The timeframe in which reports are searched. | Optional | 
| limit | This option is required only for IPS Top N reports. The limit option sets the maximum number (N) of items covered by each report. | Optional | 
| interface | This option is required only for IPS reports. The interface option sets the Internet<br/>interface to one of the following values: A, B, C, D, AB, All | Optional | 
| infection_id | Use the combination of infection_id and infection_type options to specify a unique alert to describe in the Alert Details Report. If one option is used alone and does not specify a unique alert, an error message is produced. Note: The infection_id is Alert ID. To get Alert ID execute fireeye-nx-get-alerts command. | Optional | 
| infection_type | Use the combination of infection_id and infection_type options to specify a unique alert to describe in the Alert Details Report. If one option is used alone and does not specify a unique alert, an error message is produced. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | String | The file name. | 
| InfoFile.EntryID | String | The ID for locating the file in the War Room. | 
| InfoFile.Size | Number | The size of the file (in bytes). | 
| InfoFile.Type | String | The file type, as determined by libmagic (same as displayed in file entries). | 
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
Search and Retrieve FireEye events based on several filters.


#### Base Command

`fireeye-nx-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| duration | Specifies the time interval to search. This filter is used with the end_time filter. If The duration is not specified, the system defaults to duration=12_hours, end_time= current_time. | Optional | 
| start_time | Specifies the start time of the search. This filter is used with the duration filter. If the start_time is specified but not the duration, the system defaults to duration=12_hours, starting at the specified start_time.<br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>Example:<br/>2020-05-01<br/>2020-05-01T00:00:00 | Optional | 
| end_time | Specifies the end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time. <br/>Formats:<br/>YYYY-MM-dd<br/>YYYY-MM-ddTHH:mm:ss<br/>Example:<br/>2020-05-01<br/>2020-05-01T00:00:00 | Optional | 
| mvx_correlated_only | Specifies whether to include all IPS events or MVX-correlated events only. Default: false | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeNX.Event.EventId | Number | The ID of the event. | 
| FireEyeNX.Event.Occurred | String | The date and time when the event occurred. | 
| FireEyeNX.Event.SrcIp | String | The IP Address of the victim. | 
| FireEyeNX.Event.SrcPort | Number | The Port number of the victim. | 
| FireEyeNX.Event.DstIp | String | The IP Address of the attacker. | 
| FireEyeNX.Event.DstPort | Number | The Port number of the attacker. | 
| FireEyeNX.Event.Severity | Number | The severity level of the event. | 
| FireEyeNX.Event.SignatureRev | Number | The signature revision number of the event. | 
| FireEyeNX.Event.SignatureIden | Number | The signature Identity number of the event. | 
| FireEyeNX.Event.SignatureMatchCnt | Number | The signature match count number of the event. | 
| FireEyeNX.Event.Vlan | Number | The virtual LAN number of the event. | 
| FireEyeNX.Event.VmVerified | Boolean | Is the event VM verified or not. | 
| FireEyeNX.Event.SrcMac | String | The Mac address of the source machine. | 
| FireEyeNX.Event.DstMac | String | The Mac address of the destination machine. | 
| FireEyeNX.Event.RuleName | String | The rule name for the event. | 
| FireEyeNX.Event.SensorId | String | The sensor Id of the FireEye machine. | 
| FireEyeNX.Event.CveId | String | The CVE Id found in the event. | 
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

