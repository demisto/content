FireEye Network Security is an effective cyber threat protection solution that helps organizations minimize the risk of costly breaches by  accurately detecting and immediately stopping advanced, targeted and other evasive attacks hiding in Internet traffic.
This integration is used to demonstrate the capabilities of a Cortex XSOAR integration and the common design patterns and is linked to the code.
This integration was integrated and tested with version 2.0.0 of FireEyeNX APIs.
## Configure FireEyeNX on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FireEyeNX.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| username | Username | True |
| password | Password | True |
| request_timeout | HTTP(S) Request Timeout \(in seconds\) | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| first_fetch | First fetch time interval | False |
| fetch_limit | Fetch Limit | False |
| malware_type | Malware Type | False |

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
| alert_id | Specifies the ID number of the alert to retrieve it. | Optional | 
| src_ip | The source IPv4 address related to the malware alert. | Optional | 
| dst_ip | The destination IPv4 address related to the malware alert. | Optional | 
| duration | Specifies the time interval to search. This filter is used with either the start_time or end_time filter. If duration, start time, and end time are not specified, the system defaults to duration=12_hours, end_time=current_time. If only duration is specified, the end_time defaults to the current_time.<br/><br/>Options: 1_hour, 2_hours, 6_hours, 12_hours, 24_hours, 48_hours<br/> | Optional | 
| start_time | Specifies the start time of the search. This filter is used with the duration filter. If the start_time is specified but not the duration, the system defaults to duration=12_hours, starting at the specified start_time.<br/><br/>Format: YYYY-MM-DDTHH:mm:ss.sss-OH:om or YYYY-MM-DD | Optional | 
| end_time | Specifies the end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time.<br/><br/>Format: YYYY-MM-DDTHH:mm:ss.sss-OH:om or YYYY-MM-DD | Optional | 
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
| FireEyeNX.Alert.malware.md5Sum | String | MD5SUM of malware associated with the alert. | 
| FireEyeNX.Alert.malware.sha256 | String | SHA256 of malware associated with the alert. | 
| FireEyeNX.Alert.malware.application | String | Application of the malware associated with the alert. | 
| FireEyeNX.Alert.malware.httpHeader | String | Http Header of the malware associated with the alert. | 
| FireEyeNX.Alert.malware.original | String | The filename of the malware associated with the alert. | 
| FireEyeNX.Alert.malware.name | String | Name of the malware associated with the alert. | 
| FireEyeNX.Alert.malware.sid | String | SID of the malware associated with the alert. | 
| FireEyeNX.Alert.malware.type | String | The file type of the malware associated with the alert. | 
| FireEyeNX.Alert.malware.stype | String | STYPE of the malware associated with the alert. | 
| FireEyeNX.Alert.malware.url | String | URL of the malware associated with the alert. | 
| FireEyeNX.Alert.malware.content | String | Content of the malware associated with the alert. | 
| FireEyeNX.Alert.cncService.address | String | CNC Service IP address associated with the alert. | 
| FireEyeNX.Alert.cncService.channel | String | CNC Service channel associated with the alert. | 
| FireEyeNX.Alert.cncService.port | Number | CNC Service port address associated with the alert. | 
| FireEyeNX.Alert.cncService.protocol | String | CNC Service protocol associated with the alert. | 
| FireEyeNX.Alert.osChanges.heapspraying.totalmemory | Number | Total memory of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.lastbytesreceived | Number | The last byte received in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.ProcessinfoImagepath | String | Image path of the process in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.ProcessinfoMd5sum | String | MD5SUM of the process in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.ProcessinfoPid | Number | PID of the process in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.incrementCount | Number | Increment count in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.name | String | Name of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.bytesreceived | Number | Bytes received in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.lasttotalmemory | Number | The last total memory in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.type | String | Type of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.timestamp | Number | The timestamp of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.RCount | Number | RCount of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.TotalSize | String | The total size of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.RUnit | String | RUnit of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.mode | String | Mode of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.pattern | String | The pattern of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.BytesListEntry.Percentage | Number | Entry percentage of bytes list in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.BytesListEntry.Byte | String | Entry byte of bytes list in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.BytesListEntry.Count | Number | Entry count of bytes list in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.BytesListEntry.FirstOffset | String | Entry offset of bytes list in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.BytesListEntry.IsNOP | String | If entry NOP comes in the bytes list in heap spraying then yes otherwise no. | 
| FireEyeNX.Alert.osChanges.heapspraying.BytesListDistinct | Number | The distinct number of the byte list in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.BytesListCount | Number | The number of the byte list in heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.javascript | String | If heap spraying has javascript then yes otherwise no. | 
| FireEyeNX.Alert.osChanges.heapspraying.DNA | Number | DNA of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.TotalRCount | Number | Total row count of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.ProcessedRCount | Number | Processed row count of heap spraying. | 
| FireEyeNX.Alert.osChanges.heapspraying.Processed | String | Processed memory of heap spraying. | 
| FireEyeNX.Alert.osChanges.process.FidAds | String | Fid ads of the process. | 
| FireEyeNX.Alert.osChanges.process.FidContent | Number | Fid content of process. | 
| FireEyeNX.Alert.osChanges.process.ParentUserAccountUserSid | String | Parent user account SID of the process. | 
| FireEyeNX.Alert.osChanges.process.ParentUserAccountSessionId | Number | Parent user account session ID of the process. | 
| FireEyeNX.Alert.osChanges.process.ParentUserAccountUserAccountName | String | Parent user account name of the process. | 
| FireEyeNX.Alert.osChanges.process.ParentUserAccountAuthenticationId | String | Parent user account authentication ID of process | 
| FireEyeNX.Alert.osChanges.process.ParentUserAccountSuperPrivilegesPresent | Number | If super privileges present in this process then 1 otherwise 0. | 
| FireEyeNX.Alert.osChanges.process.parentname | String | Path of parent process. | 
| FireEyeNX.Alert.osChanges.process.sha256sum | String | SHA256SUM of the parent process. | 
| FireEyeNX.Alert.osChanges.process.pid | Number | PID of the process. | 
| FireEyeNX.Alert.osChanges.process.filesize | Number | File size of the process. | 
| FireEyeNX.Alert.osChanges.process.ppid | Number | PPID of the process. | 
| FireEyeNX.Alert.osChanges.process.mode | String | Mode of the process. | 
| FireEyeNX.Alert.osChanges.process.cmdline | String | Path of the command associated with the process. | 
| FireEyeNX.Alert.osChanges.process.sha1sum | String | SHA1SUM of the process. | 
| FireEyeNX.Alert.osChanges.process.md5sum | String | MD5SUM of the process. | 
| FireEyeNX.Alert.osChanges.process.src_thread | String | Source thread name of the process. | 
| FireEyeNX.Alert.osChanges.process.value | String | Value of path in the process. | 
| FireEyeNX.Alert.osChanges.process.UserAccountUserSid | String | SID of a user account for the process. | 
| FireEyeNX.Alert.osChanges.process.UserAccountSessionId | Number | The session ID of a user account for the process. | 
| FireEyeNX.Alert.osChanges.process.UserAccountUserAccountName | String | Name of a user account for the process. | 
| FireEyeNX.Alert.osChanges.process.UserAccountAuthenticationId | String | Authentication ID of a user account for the process. | 
| FireEyeNX.Alert.osChanges.process.UserAccountSuperPrivilegesPresent | Number | If super privileges present in this user account then 1 otherwise 0. | 
| FireEyeNX.Alert.osChanges.process.timestamp | Number | The timestamp of the process. | 
| FireEyeNX.Alert.osChanges.process.memory_data | String | The memory data of the process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataLocalThreadCount | Number | Thread count of telemetry data in process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataFileOpenCount | Number | File open count of telemetry data in process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataFileModifyCount | Number | File modify count of telemetry data in process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataFileFileCreateCount | Number | File created count of telemetry data in process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataChildProcessCount | Number | File process count of telemetry data in process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataFileFailedCount | Number | File failed count of telemetry data in process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataHttpReqCount | Number | Http request count of telemetry data in process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataRemoteThreadCount | Number | Thread count of telemetry data in process. | 
| FireEyeNX.Alert.osChanges.process.TelemetryDataMutexCreateCount | Number | Mutex created a count of telemetry data in the process. | 
| FireEyeNX.Alert.osChanges.regkey.mode | String | Mode of registry key. | 
| FireEyeNX.Alert.osChanges.regkey.ProcessinfoImagepath | String | Image path of the process in registry key. | 
| FireEyeNX.Alert.osChanges.regkey.ProcessinfoMd5sum | String | MD5SUM of the process in registry key. | 
| FireEyeNX.Alert.osChanges.regkey.ProcessinfoPid | Number | PID of the process in registry key. | 
| FireEyeNX.Alert.osChanges.regkey.ntstatus | String | NTSTATUS of registry key. | 
| FireEyeNX.Alert.osChanges.regkey.suppressed | Boolean | If the registry key has suppressed then true otherwise false. | 
| FireEyeNX.Alert.osChanges.regkey.value | String | Value of registry key. | 
| FireEyeNX.Alert.osChanges.regkey.timestamp | Number | The timestamp of the registry key. | 
| FireEyeNX.Alert.osChanges.regkey.src_thread | String | Source thread name of registry key. | 
| FireEyeNX.Alert.osChanges.regkey.randomized | Boolean | If the registry key has randomized then true otherwise false | 
| FireEyeNX.Alert.osChanges.regkey.buffered | Boolean | If the registry key has buffered then true otherwise false. | 
| FireEyeNX.Alert.osChanges.regkey.no_extend | Boolean | If the registry key has no_extend then true otherwise false. | 
| FireEyeNX.Alert.osChanges.OsName | String | The name of the OS. | 
| FireEyeNX.Alert.osChanges.OsArch | String | The architecture of the OS. | 
| FireEyeNX.Alert.osChanges.OsVersion | String | A version of the OS. | 
| FireEyeNX.Alert.osChanges.OsSp | Number | Service pack version of the OS. | 
| FireEyeNX.Alert.osChanges.OsMonitorDate | String | A monitored date of the OS. | 
| FireEyeNX.Alert.osChanges.OsMonitorBuild | Number | A monitored build of the OS. | 
| FireEyeNX.Alert.osChanges.OsMonitorTime | String | A monitored time of the OS. | 
| FireEyeNX.Alert.osChanges.OsMonitorVersion | String | A monitored version of the OS. | 
| FireEyeNX.Alert.osChanges.AnalysisMode | String | A mode of analysis. | 
| FireEyeNX.Alert.osChanges.AnalysisProduct | String | A product name of analysis. | 
| FireEyeNX.Alert.osChanges.AnalysisFtype | String | A file type of analysis. | 
| FireEyeNX.Alert.osChanges.AnalysisVersion | String | A version of analysis. | 
| FireEyeNX.Alert.osChanges.network.mode | String | A mode of network. | 
| FireEyeNX.Alert.osChanges.network.protocol_type | String | A protocol type of network. | 
| FireEyeNX.Alert.osChanges.network.ipaddress | String | An IP address of the network. | 
| FireEyeNX.Alert.osChanges.network.destination_port | Number | A destination port address of the network. | 
| FireEyeNX.Alert.osChanges.network.ProcessinfoImagepath | String | Image path of the process in the network. | 
| FireEyeNX.Alert.osChanges.network.ProcessinfoTainted | Boolean | If the process state is tainted then true otherwise false for the network. | 
| FireEyeNX.Alert.osChanges.network.ProcessinfoMd5sum | String | MD5SUM of the process in the network. | 
| FireEyeNX.Alert.osChanges.network.ProcessinfoPid | Number | PID of the process in the network. | 
| FireEyeNX.Alert.osChanges.network.http_request | String | HTTP request of the network. | 
| FireEyeNX.Alert.osChanges.network.timestamp | Number | The timestamp of the network. | 
| FireEyeNX.Alert.osChanges.network.hostname | String | A hostname of the network. | 
| FireEyeNX.Alert.osChanges.network.qtype | String | A QTYPE of the network. | 
| FireEyeNX.Alert.osChanges.network.answer_number | Number | An answer number of the network. | 
| FireEyeNX.Alert.osChanges.network.dns_response_code | Number | A DNS response code of the network. | 
| FireEyeNX.Alert.osChanges.ActionFopenMode | String | Mode of opening the file. | 
| FireEyeNX.Alert.osChanges.ActionFopenExt | String | Extension of opening the file. | 
| FireEyeNX.Alert.osChanges.ActionFopenBuffered | Boolean | If the opened file has buffered then true otherwise false. | 
| FireEyeNX.Alert.osChanges.ActionFopenNoExtend | Boolean | If the opened file has no_extend then true otherwise false. | 
| FireEyeNX.Alert.osChanges.ActionFopenName | String | The name of opening the file. | 
| FireEyeNX.Alert.osChanges.ActionFopenTimestamp | Number | The timestamp of opening the file. | 
| FireEyeNX.Alert.osChanges.exploitcode.dllname | String | DLL file name of exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.apiname | String | API name of exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.address | String | An address of exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.ProcessinfoImagepath | String | Image path of the process in the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.ProcessinfoMd5sum | String | MD5SUM of the process in the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.ProcessinfoPid | Number | PID of the process in the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.src_thread | String | Source thread name of the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.protection | String | Protection number of the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.CallstackEntry.SymbolName | String | The symbol name of call stack entry in the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.CallstackEntry.FrameNumber | Number | Frame number of call stack entries in the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.CallstackEntry.ModuleName | String | Module name of call stack entry in the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.CallstackEntry.InstructionAddress | String | Instruction address of call stack entry in the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.CallstackEntry.SymbolDisplacement | String | Symbol displacement of call stack entry in the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.param.id | Number | ID parameter of the exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.param.content | String | Path parameter of exploit code. | 
| FireEyeNX.Alert.osChanges.exploitcode.timestamp | Number | The timestamp of the exploit codes. | 
| FireEyeNX.Alert.osChanges.folder.mode | String | Mode of folder. | 
| FireEyeNX.Alert.osChanges.folder.ProcessinfoImagepath | String | Image path of the process in the folder. | 
| FireEyeNX.Alert.osChanges.folder.ProcessinfoMd5sum | String | MD5SUM of the process in the folder. | 
| FireEyeNX.Alert.osChanges.folder.ProcessinfoPid | Number | PID of the process in the folder. | 
| FireEyeNX.Alert.osChanges.folder.src_thread | String | Source thread name of the folder. | 
| FireEyeNX.Alert.osChanges.folder.value | String | Path of folder. | 
| FireEyeNX.Alert.osChanges.folder.timestamp | Number | The timestamp of the folder. | 
| FireEyeNX.Alert.osChanges.file.mode | String | The mode of the file. | 
| FireEyeNX.Alert.osChanges.file.FidAds | String | ADS \(Alternate Data Stream\) of FID for file. | 
| FireEyeNX.Alert.osChanges.file.FidContent | Number | Content of FID in file | 
| FireEyeNX.Alert.osChanges.file.ProcessinfoImagepath | String | Image path of the process for file. | 
| FireEyeNX.Alert.osChanges.file.ProcessinfoMd5sum | String | MD5SUM of the process for the file. | 
| FireEyeNX.Alert.osChanges.file.ProcessinfoPid | Number | PID of the process for the file. | 
| FireEyeNX.Alert.osChanges.file.ProcessinfoTainted | Boolean | If the process state is tainted then true otherwise false for the file. | 
| FireEyeNX.Alert.osChanges.file.src_thread | String | Source thread name of the file. | 
| FireEyeNX.Alert.osChanges.file.ntstatus | String | NTSTATUS of the file. | 
| FireEyeNX.Alert.osChanges.file.filesize | Number | Size of the file. | 
| FireEyeNX.Alert.osChanges.file.value | String | The value of the file. | 
| FireEyeNX.Alert.osChanges.file.CreateOptions | String | The created option of the file. | 
| FireEyeNX.Alert.osChanges.file.timestamp | Number | The timestamp of the file. | 
| FireEyeNX.Alert.osChanges.file.type | String | Type of the file. | 
| FireEyeNX.Alert.osChanges.file.sha256sum | String | SHA256SUM of the file. | 
| FireEyeNX.Alert.osChanges.file.sha1sum | String | SHA1SUM of the file. | 
| FireEyeNX.Alert.osChanges.file.PEInspectionType | String | Inspection type of portable executable file. | 
| FireEyeNX.Alert.osChanges.file.PETimeDateStamp | String | The time date stamp of the portable executable file. | 
| FireEyeNX.Alert.osChanges.file.PECharacteristicsName | Unknown | List of characteristic names in the portable executable file. | 
| FireEyeNX.Alert.osChanges.file.PECharacteristicsValue | String | Characteristic value in the portable executable file. | 
| FireEyeNX.Alert.osChanges.file.PEDllCharacteristicsNames | String | Characteristic name in the DLL portable executable file. | 
| FireEyeNX.Alert.osChanges.file.PEDllCharacteristicsValue | String | Characteristic value in the DLL portable executable file. | 
| FireEyeNX.Alert.osChanges.file.PEDll | String | If a portable file is a DLL file then yes otherwise no file. | 
| FireEyeNX.Alert.osChanges.file.PEMagic | String | Magic hex value of portable executable file. | 
| FireEyeNX.Alert.osChanges.file.PESubsystem | String | Sub system of portable executable file. | 
| FireEyeNX.Alert.osChanges.file.PEMachine | String | Hex address of machine in file. | 
| FireEyeNX.Alert.osChanges.file.md5sum | String | MD5SUM of the file. | 
| FireEyeNX.Alert.osChanges.ApplicationAppName | String | App name of the application. | 
| FireEyeNX.Alert.osChanges.QuerySystemTimeProcessinfoImagepath | String | Image path of the queried system process. | 
| FireEyeNX.Alert.osChanges.QuerySystemTimeProcessinfoMd5sum | String | System time process info of Md5sum that is queried. | 
| FireEyeNX.Alert.osChanges.QuerySystemTimeProcessinfoPid | Number | System time process info of Pid \(process id\) that is queried | 
| FireEyeNX.Alert.osChanges.QuerySystemTimeTimestamp | Number | The timestamp of the system that is queried. |
| FireEyeNX.Alert.osChanges.QuerySystemTimeNtstatus | String | NTSTATUS of system time that is queried. | 
| FireEyeNX.Alert.osChanges.QuerySystemTimeSystemTimeValue | String | The time value of the system that is queried. | 
| FireEyeNX.Alert.osChanges.QuerySystemTimeSystemTimeTime | String | The time of the system that is queried. | 
| FireEyeNX.Alert.osChanges.EndOfReport | String | The end of report. | 
| FireEyeNX.Alert.osChanges.MaliciousAlert.Classtype | String | Class type of malicious alert. | 
| FireEyeNX.Alert.osChanges.MaliciousAlert.DisplayMsg | String | Display message of malicious alert. | 
| FireEyeNX.Alert.osChanges.DialogDetected.Hwnd | String | Hex address of dialog detected. | 
| FireEyeNX.Alert.osChanges.DialogDetected.ProcessinfoImagepath | String | Imagepath of the process for the dialog detected. | 
| FireEyeNX.Alert.osChanges.DialogDetected.ProcessinfoPid | Number | PID of the process for the dialog detected. | 
| FireEyeNX.Alert.osChanges.DialogDetected.Buffered | Boolean | Flag indicated whether is buffered or not in dialog detected. | 
| FireEyeNX.Alert.osChanges.DialogDetected.NoExtend | Boolean | Flag indicating whether NoExtend is true or not in dialog detected. | 
| FireEyeNX.Alert.osChanges.DialogDetected.Timestamp | Number | The timestamp of dialog detected. | 
| FireEyeNX.Alert.osChanges.DialogDetected.DlgId | String | Dialog ID of dialog detected. | 
| FireEyeNX.Alert.osChanges.DialogDismissed.Note | String | Note of dialog dismissed. | 
| FireEyeNX.Alert.osChanges.DialogDismissed.Hwnd | String | Hex address of dialog dismissed. | 
| FireEyeNX.Alert.osChanges.DialogDismissed.ProcessinfoImagepath | String | Imagepath of the process for the dialog dismissed. | 
| FireEyeNX.Alert.osChanges.DialogDismissed.ProcessinfoPid | Number | PID of the process for the dialog dismissed. | 
| FireEyeNX.Alert.osChanges.DialogDismissed.Buffered | Boolean | Flag indicating whether Buffered is true or not in the dialog dismissed. | 
| FireEyeNX.Alert.osChanges.DialogDismissed.NoExtend | Boolean | Flag indicating whether NoExtend is true or not in dialog dismissed. | 
| FireEyeNX.Alert.osChanges.DialogDismissed.Timestamp | Number | The timestamp of dialog dismissed. | 
| FireEyeNX.Alert.osChanges.DialogDismissed.DlgId | String | Dialog ID of dialog dismissed. | 
| FireEyeNX.Alert.osChanges.WmiqueryProcessinfoImagepath | String | Imagepath of the process for wmi query. | 
| FireEyeNX.Alert.osChanges.WmiqueryProcessinfoMd5sum | String | Md5sum of the process for wmi query. | 
| FireEyeNX.Alert.osChanges.WmiqueryProcessinfoPid | Number | Pid of the process for wmi query. | 
| FireEyeNX.Alert.osChanges.WmiqueryWmicontentQuery | String | Query of wmi content for wmi query. | 
| FireEyeNX.Alert.osChanges.WmiqueryWmicontentLang | String | Language of wmi content for wmi query. | 
| FireEyeNX.Alert.osChanges.WmiqueryTimestamp | Number | The timestamp of wmi query. | 
| FireEyeNX.Alert.osChanges.WmiqueryBuffered | Boolean | This flag indicates whether it is buffered or not in the wmi query. | 
| FireEyeNX.Alert.osChanges.WmiqueryNoExtend | Boolean | Flag indicating whether NoExtend is true or not in wmi query. | 
| FireEyeNX.Alert.osChanges.uac.mode | String | Mode of User Account Control. | 
| FireEyeNX.Alert.osChanges.uac.value | String | Value of User Account Control. | 
| FireEyeNX.Alert.osChanges.uac.timestamp | Number | The timestamp of User Account Control. | 
| FireEyeNX.Alert.osChanges.uac.status | String | Status of User Account Control. | 
| FireEyeNX.Alert.StaticAnalysisStatic.value | String | Value of static analysis. | 
| FireEyeNX.Alert.StolenDataInfoField | Unknown | Info field of stolen data. | 
| FireEyeNX.Alert.StolenDataInfoType | String | Info type of stolen data. | 
| FireEyeNX.Alert.StolenDataEventId | Number | Event ID of stolen data. | 
| FireEyeNX.Alert.SrcIp | String | Source IP address of alert. | 
| FireEyeNX.Alert.SrcMac | String | Source MAC address of alert. | 
| FireEyeNX.Alert.SrcPort | Number | Source PORT address of alert. | 
| FireEyeNX.Alert.alertUrl | String | Alert URL. | 
| FireEyeNX.Alert.action | String | Action of Alert. | 
| FireEyeNX.Alert.occurred | String | Time when alert occurred. | 
| FireEyeNX.Alert.attackTime | String | Time when an attack occurred. | 
| FireEyeNX.Alert.DstMac | String | Destination MAC address of alert. | 
| FireEyeNX.Alert.DstPort | Number | Destination PORT address of alert. | 
| FireEyeNX.Alert.DstIp | String | Destination IP address of alert. | 
| FireEyeNX.Alert.applianceId | String | Appliance ID of alert. | 
| FireEyeNX.Alert.id | Number | ID of alert. | 
| FireEyeNX.Alert.name | String | Type of alert. | 
| FireEyeNX.Alert.severity | String | Severity of alert. | 
| FireEyeNX.Alert.uuid | String | UUID of alert. | 
| FireEyeNX.Alert.ack | String | Flag indicates whether ack comes or not. | 
| FireEyeNX.Alert.product | String | Product name of alert. | 
| FireEyeNX.Alert.vlan | Number | VLAN of alert. | 
| FireEyeNX.Alert.malicious | String | This flag indicates whether the alert is malicious or not. | 
| FireEyeNX.Alert.scVersion | String | SC version of alert. |
| FireEyeNX.Alert.SrcHost | String | Source host of alert. | 


#### Command Example
```!fireeye-nx-get-alerts```

#### Context Example
```
{
    "FireEyeNX": {
        "Alert": [
            {
                "DstMac": "xx:xx:xx:xx:xx:xx",
                "DstIp": "1.1.1.1",
                "DstPort": 0,
                "SrcIp": "1.1.1.1",
                "SrcPort": 0,
                "SrcMac": "xx:xx:xx:xx:xx:xx",
                "ack": "no",
                "action": "notified",
                "alertUrl": "dummy alert url",
                "applianceId": "00",
                "attackTime": "0000-00-00 02:12:53 +0000",
                "id": 1,
                "malicious": "yes",
                "malware": [
                    {
                        "name": "dummy malware name 1"
                    }
                ],
                "name": "dummy name 1",
                "occurred": "0000-00-00 02:12:53 +0000",
                "product": "product dummy",
                "scVersion": "1.000",
                "severity": "MINR",
                "uuid": "0b0b0b0b0-0b0b0b-0b0b-0b0b-0b0b0b0b0b",
                "vlan": 0
            },
            {
                "DstMac": "xx:xx:xx:xx:xx:xx",
                "DstIp": "1.1.1.1",
                "DstPort": 0,
                "SrcIp": "1.1.1.1",
                "SrcPort": 0,
                "SrcMac": "xx:xx:xx:xx:xx:xx",
                "ack": "no",
                "action": "notified",
                "alertUrl": "dummy alert url",
                "applianceId": "1",
                "attackTime": "0000-00-00 02:42:53 +0000",
                "id": 2,
                "malicious": "yes",
                "malware": [
                    {
                        "name": "dummy malware name 2"
                    }
                ],
                "name": "dummy name 2",
                "occurred": "0000-00-00 02:42:53 +0000",
                "product": "dummy product",
                "scVersion": "1.000",
                "severity": "MINR",
                "uuid": "0a0a0a0a0-0a0a0a-0a0a-0a0a-0a0a0a0a0a",
                "vlan": 0
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
>| 2 | 0a0a0a0a0-0a0a0a-0a0a-0a0a-0a0a0a0a0a | dummy malware name 2 | dummy name 2 | 1.1.1.1 | 0000-00-00 02:42:53 +0000 | MINR | yes | 1.000 | 0 | xx:xx:xx:xx:xx:xx | 1.1.1.1 | 0 | xx:xx:xx:xx:xx:xx |

### fireeye-nx-get-artifacts-metadata-by-alert
***
Gets malware artifacts metadata for the specified UUID.

`fireeye-nx-get-artifacts-metadata-by-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | Universally unique ID of the alert. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeNX.Alert.uuid | String | Universally unique ID of the alert. | 
| FireEyeNX.Alert.ArtifactsMetadata.artifactType | String | The artifact type. | 
| FireEyeNX.Alert.ArtifactsMetadata.artifactName | String | The artifact name. | 
| FireEyeNX.Alert.ArtifactsMetadata.artifactSize | String | The artifact size. | 


#### Command Example
```!fireeye-nx-get-artifacts-metadata-by-alert uuid=0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b```

#### Context Example
```
{
    "FireEyeNX": {
        "Alert": {
            "ArtifactsMetadata": [
                {
                    "artifactType": "artifact type test 1",
                    "artifactName": "artifact name test 1",
                    "artifactSize": "1010"
                },
                {
                    "artifactType": "artifact type test 2",
                    "artifactName": "artifact name test 2",
                    "artifactSize": "1010"
                }
            ],
            "uuid": "0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b"
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
| uuid | Universally unique ID of the alert. | Required |

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
| start_time | Searches between two specified time frames. When specifying a start_time value, you must specify both a start_time and an end_ time value.<br/>Format: yyyy-MM-ddTHH:mm:ss.SSS[+/-]XX:XX or yyyy-MM-ddTHH:mm:ss[+/-]XX:XX or yyyy-MM-dd | Optional | 
| end_time | Searches between two specified time frames. When specifying an end_ time value, you must specify both a start_time and an end_time value.<br/>Format: yyyy-MM-ddTHH:mm:ss.SSS[+/-]XX:XX or yyyy-MM-ddTHH:mm:ss[+/-]XX:XX or yyyy-MM-dd | Optional | 
| time_frame | The timeframe in which reports are searched. | Optional | 
| limit | This option is required only for IPS Top N reports. The limit option sets the maximum number (N) of items covered by each report. | Optional | 
| interface | This option is required only for IPS reports. The interface option sets the Internet interface to one of the following values:<br/>A,B,C,D,AB,All | Optional | 
| infection_id | Use the combination of infection_id and infection_type options to specify a unique alert to describe in the Alert Details Report. If one option is used alone and does not specify a unique alert, an error message is produced. | Optional | 
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
```!fireeye-nx-get-reports report_type="IPS Executive Summary Report" type=csv time_frame=between start_time=2020-01-29T23:59:59+13:00 end_time=2020-08-29T23:59:59+13:00```

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
| end_time | Specifies the end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time. Format: YYYY-MM-DDTHH:mm:ss.sss-OH:om | Optional | 
| mvx_correlated_only | Specifies whether to include all IPS events or MVX-correlated events only. Default: false | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeNX.Event.eventId | Number | The ID of the event. | 
| FireEyeNX.Event.occurred | String | The date and time when the event occurred. | 
| FireEyeNX.Event.srcIp | String | The IP Address of the victim. | 
| FireEyeNX.Event.srcPort | Number | The Port number of the victim. | 
| FireEyeNX.Event.dstIp | String | The IP Address of the attacker. | 
| FireEyeNX.Event.dstPort | Number | The Port number of the attacker. | 
| FireEyeNX.Event.severity | Number | The severity level of the event. | 
| FireEyeNX.Event.signatureRev | Number | The signature revision number of the event.  | 
| FireEyeNX.Event.signatureIden | Number | The signature Identity number of the event. | 
| FireEyeNX.Event.signatureMatchCnt | Number | The signature match count number of the event. | 
| FireEyeNX.Event.vlan | Number | The virtual LAN number of the event. | 
| FireEyeNX.Event.vmVerified | Boolean | Is the event VM verified or not? | 
| FireEyeNX.Event.srcMac | String | The Mac address of the source machine. | 
| FireEyeNX.Event.dstMac | String | The Mac address of the destination machine. | 
| FireEyeNX.Event.ruleName | String | The rule name for the event. | 
| FireEyeNX.Event.sensorId | String | The sensor Id of the FireEye machine. | 
| FireEyeNX.Event.cveId | String | The CVE Id found in the event. | 
| FireEyeNX.Event.actionTaken | Number | The IPS blocking action taken on the event. | 
| FireEyeNX.Event.attackMode | String | The attack mode mentioned in the event. | 
| FireEyeNX.Event.interfaceId | Number | The interface ID of the event. | 
| FireEyeNX.Event.protocol | Number | The protocol used in the event. | 
| FireEyeNX.Event.incidentId | Number | The incident ID of the event on FireEye. | 


#### Command Example
```!fireeye-nx-get-events duration=48_hours end_time=2020-08-10T06:31:00.000+00:00```

#### Context Example
```
{
    "FireEyeNX": {
        "Event": [
            {
              "eventId":1,
              "occurred":"2020-08-10T06:31:00Z",
              "srcIp":"1.1.1.1",
              "srcPort":1,
              "dstIp":"1.1.1.1",
              "dstPort":1,
              "vlan":0,
              "signatureMatchCnt":1,
              "signatureIden":1,
              "signatureRev":1,
              "severity":1,
              "vmVerified":true,
              "srcMac":"dummy",
              "dstMac":"dummy",
              "ruleName":"dummy",
              "sensorId":"dummy",
              "cveId":"CVE-123",
              "actionTaken":1,
              "attackMode":"dummy",
              "interfaceId":1,
              "protocol":1,
              "incidentId":1
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


