VMware Carbon Black EDR (formerly known as Carbon Black Response)
This integration was integrated and tested with version xx of VMware Carbon Black EDR v2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-vmware-carbon-black-edr-v2).

## Configure VMware Carbon Black EDR v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for VMware Carbon Black EDR v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | API Token |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Filter alerts by query | Advanced query string. Accepts the same data as the search box on the Alert Search page.<br/>For more information on the query syntax see https://developer.carbonblack.com/resources/query_overview.pdf.<br/>If provided, other search filters are not allowed. | False |
    | Filter alerts by status |  | False |
    | Filter alerts by feed name |  | False |
    | Maximum Number Of Incidents To Fetch |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cb-edr-processes-search

***
Process search

#### Base Command

`cb-edr-processes-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_name | The name of the process. | Optional | 
| group | The CB Host group this sensor is assigned to. | Optional | 
| hostname | The hostname of the computer for this process. | Optional | 
| parent_name | The parent process name. | Optional | 
| process_path | The process path. | Optional | 
| md5 | The md5 of the binary image backing the process. | Optional | 
| query | Advanced query string. Accepts the same data as the search box on the Process Search page. For more information on the query syntax see https://developer.carbonblack.com/resources/query_overview.pdf. If not provided, at least one other search field must be provided. | Optional | 
| group_by | group by a field name. For example, if parameter group=id, search will return one result per process. Note that results will still honor sorting specified by the search. Even within group, it will return result that is first in the sort order. Grouping will be slower (sometimes much slower) than regular results. | Optional | 
| sort | Sort rows by this field and order. last_update desc by default. | Optional | 
| facet | Return facet results. ‘false’ by default, set to ‘true’ for facets. Possible values are: true, false. | Optional | 
| facet_field | facet field name to return. Multiple facet.field parameters can be specified in a query. Possible values are: process_md5, hostname, group, path_full, parent_name, process_name, host_type, hour_of_day, day_of_week, start, username_full. | Optional | 
| limit | Return this many rows, 10 by default. | Optional | 
| start | Start at this row, 0 by default. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.ProcessSearch.Terms | String | A list of strings, each representing a token as parsed by the query parser. | 
| CarbonBlackEDR.ProcessSearch.Results.process_md5 | String | The md5 of the binary image backing the process. | 
| CarbonBlackEDR.ProcessSearch.Results.sensor_id | Number | The internal CB id for the sensor on which the process executed. | 
| CarbonBlackEDR.ProcessSearch.Results.filtering_known_dlls | Boolean | Whether known dlls are filtered. | 
| CarbonBlackEDR.ProcessSearch.Results.modload_count | Number | The count of modules loaded in this process. | 
| CarbonBlackEDR.ProcessSearch.Results.parent_unique_id | String | Internal CB process id of the process's parent. | 
| CarbonBlackEDR.ProcessSearch.Results.emet_count | Number | Number of EMET associated with the event. | 
| CarbonBlackEDR.ProcessSearch.Results.cmdline | String | The command line of the process. | 
| CarbonBlackEDR.ProcessSearch.Results.filemod_count | Number | The count of file modifications in this process. | 
| CarbonBlackEDR.ProcessSearch.Results.id | String | The internal CB process id for this process \(processes are identified by this id and their segment id\). | 
| CarbonBlackEDR.ProcessSearch.Results.parent_name | String | The name of the process's parent. | 
| CarbonBlackEDR.ProcessSearch.Results.parent_md5 | String | The md5 of the process's parent. | 
| CarbonBlackEDR.ProcessSearch.Results.group | String | The CB Host group this sensor is assigned to. | 
| CarbonBlackEDR.ProcessSearch.Results.parent_id | String | The id of the process's parent. | 
| CarbonBlackEDR.ProcessSearch.Results.hostname | String | The hostname of the computer for this process. | 
| CarbonBlackEDR.ProcessSearch.Results.last_update | Date | The time of the most recently received event for this process in remote computer GMT time. | 
| CarbonBlackEDR.ProcessSearch.Results.start | Date | The start time of the process in remote computer GMT time. | 
| CarbonBlackEDR.ProcessSearch.Results.comms_ip | Number | IP address that the Cb server received the events on. If the endpoint is behind a NAT,
for example, this will be the external IP of the network the endpoint lives on. | 
| CarbonBlackEDR.ProcessSearch.Results.regmod_count | Number | The count of registry modifications in this process. | 
| CarbonBlackEDR.ProcessSearch.Results.interface_ip | Number | The IP address of the network interface\(s\) on the endpoint that generated the message. | 
| CarbonBlackEDR.ProcessSearch.Results.process_pid | Number | The pid of the process. | 
| CarbonBlackEDR.ProcessSearch.Results.username | String | The user assosicated with the process. | 
| CarbonBlackEDR.ProcessSearch.Results.terminated | Boolean | Whether the process is terminated. | 
| CarbonBlackEDR.ProcessSearch.Results.process_name | String | The name of the process. | 
| CarbonBlackEDR.ProcessSearch.Results.emet_config | String | The configuration of the EMET. | 
| CarbonBlackEDR.ProcessSearch.Results.last_server_update | Date | When the process was last updated in the server. | 
| CarbonBlackEDR.ProcessSearch.Results.path | String | The full path of the executable backing this process, e.g., c:\\windows\\system32\\svchost.exe. | 
| CarbonBlackEDR.ProcessSearch.Results.netconn_count | Number | The count of network connections in this process. | 
| CarbonBlackEDR.ProcessSearch.Results.parent_pid | Number | The pid of the process's parent. | 
| CarbonBlackEDR.ProcessSearch.Results.crossproc_count | Number | The count of cross process events launched by this process. | 
| CarbonBlackEDR.ProcessSearch.Results.segment_id | String | The process segment id \(processes are identified by this segment id and their id\) | 
| CarbonBlackEDR.ProcessSearch.Results.watchlists.segments_hit | String | Number of segment hits associated with the watchlist. | 
| CarbonBlackEDR.ProcessSearch.Results.watchlists.wid | String | The id of the watchlist associated with the process. | 
| CarbonBlackEDR.ProcessSearch.Results.watchlists.value | String | The value of the watchlist associated with the process. | 
| CarbonBlackEDR.ProcessSearch.Results.host_type | String | The type of the process's host. | 
| CarbonBlackEDR.ProcessSearch.Results.processblock_count | Number | The number of processblock associated with the process. | 
| CarbonBlackEDR.ProcessSearch.Results.os_type | String | The operating system type of the computer for this process; one of windows, linux, osx. | 
| CarbonBlackEDR.ProcessSearch.Results.childproc_count | Number | The count of child processes launched by this process. | 
| CarbonBlackEDR.ProcessSearch.Results.unique_id | String | An internal CB process id combining of the process id and segment id. | 

### cb-edr-process-get

***
Gets basic process information for segment  of process.

#### Base Command

`cb-edr-process-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_id | The internal CB process id; this is the id field in search results. | Required | 
| segment_id | The process segment id, the segment_id field in search results. | Required | 
| get_related | Whether to get sibling data for process. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.Process.process.process_md5 | String | The md5 of the binary image backing the process. | 
| CarbonBlackEDR.Process.process.sensor_id | Number | The internal CB id for the sensor on which the process executed. | 
| CarbonBlackEDR.Process.process.uid | String | The uid of the process. | 
| CarbonBlackEDR.Process.process.filtering_known_dlls | Boolean | Whether known dlls are filtered. | 
| CarbonBlackEDR.Process.process.modload_count | Number | The count of modules loaded in this process. | 
| CarbonBlackEDR.Process.process.parent_unique_id | String | Internal CB process id of the process's parent. | 
| CarbonBlackEDR.Process.process.cmdline | String | The command line of the process. | 
| CarbonBlackEDR.Process.process.max_last_update | Date | The maximum last update of the process. | 
| CarbonBlackEDR.Process.process.min_last_update | Date | The minimum last update of the process. | 
| CarbonBlackEDR.Process.process.last_update | Date | The time of the most recently received event for this process in remote computer GMT time. | 
| CarbonBlackEDR.Process.process.id | String | The id of the process. | 
| CarbonBlackEDR.Process.process.terminated | Boolean | Whether the process is terminated. | 
| CarbonBlackEDR.Process.process.crossproc_count | Number | The count of cross process events launched by this process. | 
| CarbonBlackEDR.Process.process.group | String | The CB Host group this sensor is assigned to. | 
| CarbonBlackEDR.Process.process.max_last_server_update | Date | When the process was last updated in the server. | 
| CarbonBlackEDR.Process.process.parent_id | String | The id of the process's parent. | 
| CarbonBlackEDR.Process.process.hostname | String | The hostname of the computer for this process. | 
| CarbonBlackEDR.Process.process.filemod_count | Number | The count of file modifications in this process. | 
| CarbonBlackEDR.Process.process.start | Date | The start time of the process in remote computer GMT time. | 
| CarbonBlackEDR.Process.process.comms_ip | Number | IP address that the Cb server received the events on. If the endpoint is behind a NAT,
for example, this will be the external IP of the network the endpoint lives on. | 
| CarbonBlackEDR.Process.process.regmod_count | Number | The count of registry modifications in this process. | 
| CarbonBlackEDR.Process.process.interface_ip | Number | The IP address of the network interface\(s\) on the endpoint that generated the message. | 
| CarbonBlackEDR.Process.process.process_pid | Number | The pid of the process. | 
| CarbonBlackEDR.Process.process.username | String | The user assosicated with the process. | 
| CarbonBlackEDR.Process.process.process_name | String | The name of the process. | 
| CarbonBlackEDR.Process.process.emet_count | Number | Number of EMET associated with the process. | 
| CarbonBlackEDR.Process.process.last_server_update | Date | When the process was last updated in the server. | 
| CarbonBlackEDR.Process.process.path | String | The full path of the executable backing this process, e.g., c:\\windows\\system32\\svchost.exe. | 
| CarbonBlackEDR.Process.process.netconn_count | Number | The count of network connections in this process. | 
| CarbonBlackEDR.Process.process.parent_pid | Number | The pid of the process's parent. | 
| CarbonBlackEDR.Process.process.segment_id | Date | The process segment id \(processes are identified by this segment id and their id\) | 
| CarbonBlackEDR.Process.process.min_last_server_update | Date | When the process was last updated in the server. | 
| CarbonBlackEDR.Process.process.host_type | String | The Type of the process's host. | 
| CarbonBlackEDR.Process.process.processblock_count | Number | The number of processblock associated with the process. | 
| CarbonBlackEDR.Process.process.os_type | String | The operating system type of the computer for this process; one of windows, linux, osx. | 
| CarbonBlackEDR.Process.process.childproc_count | Number | The count of child processes launched by this process. | 
| CarbonBlackEDR.Process.process.unique_id | String | An internal CB process id combining of the process id and segment id | 
| CarbonBlackEDR.Process.siblings.process_md5 | String | The md5 of the binary image backing the sibling process. | 
| CarbonBlackEDR.Process.siblings.sensor_id | Number | The internal CB id for the sensor on which the sibling process executed. | 
| CarbonBlackEDR.Process.siblings.uid | String | The uid of the sibling process. | 
| CarbonBlackEDR.Process.siblings.parent_unique_id | String | Internal CB process id of the sibling process's parent. | 
| CarbonBlackEDR.Process.siblings.cmdline | String | The command line of the sibling process | 
| CarbonBlackEDR.Process.siblings.id | String | The id of the process. | 
| CarbonBlackEDR.Process.siblings.terminated | Boolean | Whether the sibling process is terminated. | 
| CarbonBlackEDR.Process.siblings.group | String | The CB Host group this sensor is assigned to. | 
| CarbonBlackEDR.Process.siblings.parent_id | String | The id of the sibling process's parent. | 
| CarbonBlackEDR.Process.siblings.hostname | String | The hostname of the computer for the sibling process. | 
| CarbonBlackEDR.Process.siblings.last_update | Date | The time of the most recently received event for the sibling process in remote computer GMT time. | 
| CarbonBlackEDR.Process.siblings.start | Date | The start time of the sibling process in remote computer GMT time. | 
| CarbonBlackEDR.Process.siblings.process_pid | Number | The pid of the sibling process. | 
| CarbonBlackEDR.Process.siblings.username | String | The user assosicated with the process. | 
| CarbonBlackEDR.Process.siblings.process_name | String | The name of the sibling process. | 
| CarbonBlackEDR.Process.siblings.path | String | The path of the sibling process. | 
| CarbonBlackEDR.Process.siblings.parent_pid | Number | The pid of the sibling process's parent. | 
| CarbonBlackEDR.Process.siblings.segment_id | Date | The sibling process segment id \(processes are identified by this segment id and their id\) | 
| CarbonBlackEDR.Process.siblings.host_type | String | The type of the host associated with the process. | 
| CarbonBlackEDR.Process.siblings.os_type | String | The operating system type of the computer for the sibling process; one of windows, linux, osx. | 
| CarbonBlackEDR.Process.siblings.child_proc_type | String | The type of the child process associated with the process. | 
| CarbonBlackEDR.Process.siblings.unique_id | String | An internal CB process id combining of the sibling process id and segment id | 
| CarbonBlackEDR.Process.children.process_md5 | String | The md5 of the binary image backing the children process. | 
| CarbonBlackEDR.Process.children.sensor_id | Number | The internal CB id for the sensor on which the children process executed. | 
| CarbonBlackEDR.Process.children.uid | String | The uid of the child process. | 
| CarbonBlackEDR.Process.children.parent_unique_id | String | Internal CB process id of the child process's parent. | 
| CarbonBlackEDR.Process.children.cmdline | String | The command line of the child process | 
| CarbonBlackEDR.Process.children.id | String | The id of the process. | 
| CarbonBlackEDR.Process.children.terminated | Boolean | Whether the process is terminated. | 
| CarbonBlackEDR.Process.children.group | String | The CB Host group this sensor is assigned to. | 
| CarbonBlackEDR.Process.children.parent_id | String | The id of the child process's parent. | 
| CarbonBlackEDR.Process.children.hostname | String | The hostname of the computer for the child process. | 
| CarbonBlackEDR.Process.children.last_update | Date | The time of the most recently received event for the child process in remote computer GMT time. | 
| CarbonBlackEDR.Process.children.start | Date | The start time of the child process in remote computer GMT time. | 
| CarbonBlackEDR.Process.children.process_pid | Number | The pid of the child process. | 
| CarbonBlackEDR.Process.children.username | String | The user assosicated with the process. | 
| CarbonBlackEDR.Process.children.process_name | String | The name of the child process. | 
| CarbonBlackEDR.Process.children.path | String | The path of the child process. | 
| CarbonBlackEDR.Process.children.parent_pid | Number | The pid of the child process's parent. | 
| CarbonBlackEDR.Process.children.segment_id | Date | The child process segment id \(processes are identified by this segment id and their id\) | 
| CarbonBlackEDR.Process.children.host_type | String | The host type of the children process. | 
| CarbonBlackEDR.Process.children.os_type | String | The operating system type of the computer for the child process; one of windows, linux, osx. | 
| CarbonBlackEDR.Process.children.child_proc_type | String | The type of the host associated with the process. | 
| CarbonBlackEDR.Process.children.unique_id | String | An internal CB process id combining of the child process id and segment id | 

### cb-edr-process-segments-get

***
Gets segment data for a given process.

#### Base Command

`cb-edr-process-segments-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_id | The internal CB process id; this is the id field in search results. | Required | 
| limit | The maximum amount of segments to be returned. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.ProcessSegments.last_server_update | Date | The last date/time when the server pushed events into this segment. | 
| CarbonBlackEDR.ProcessSegments.event_counts.filemod | Number | The number of events for filemod event type stored in this segment. | 
| CarbonBlackEDR.ProcessSegments.event_counts.netconn | Number | The number of events for netconn event type stored in this segment. | 
| CarbonBlackEDR.ProcessSegments.event_counts.crossproc | Number | The number of events for crossproc event type stored in this segment. | 
| CarbonBlackEDR.ProcessSegments.unique_id | String | The full process ID \+ segment number associated with this event segment. | 
| CarbonBlackEDR.ProcessSegments.last_update | Date | The last event \(represented in sensor date/time\) stored in this segment. | 

### cb-edr-sensor-installer-download

***
Download a zip archive including a sensor installer for Windows, Mac OS X or Linux.

#### Base Command

`cb-edr-sensor-installer-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| os_type | Download a zip archive including a sensor installer for Windows, Mac OS X or Linux.<br/><br/>For Windows- A ZIP archive which includes a signed Windows EXE or MSI sensor installer and settings file<br/>For Mac OS X- A ZIP archive which includes a signed OSX PKG sensor installer and settings file<br/>For Linux- A compressed tarball (tar.gz) archive which includes a Linux sensor installer and settings file. Possible values are: windows_exe, windows_msi, osx, linux. | Required | 
| group_id | An ID of a group related to sensors. | Required | 

#### Context Output

There is no context output for this command.
### cb-edr-process-events-list

***
Gets the events for the process with CB process id (process_id) and segment id (segment_id).

#### Base Command

`cb-edr-process-events-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_id | The internal CB process id; this is the id field in search results. | Required | 
| segment_id | The process segment id. This is the segment_id field in search results.<br/>If this is set to 0, the API will merge all segments in results. | Required | 
| start | Return events starting with this offset.<br/>If not provided, offset will be 0 (returns events starting from the beginning). | Optional | 
| count | How many events to fetch. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.Events.process_md5 | String | The MD5 of the executable backing this process. | 
| CarbonBlackEDR.Events.sensor_id | Number | The sensor id of the host this process executed on. | 
| CarbonBlackEDR.Events.uid | String | The uid of the event. | 
| CarbonBlackEDR.Events.filtering_known_dlls | Boolean | Whether known dlls are filtered. | 
| CarbonBlackEDR.Events.modload_count | Number | The count of modules loaded in this process. | 
| CarbonBlackEDR.Events.parent_unique_id | String | The id of the parent process. | 
| CarbonBlackEDR.Events.cmdline | String | The command line of the process. | 
| CarbonBlackEDR.Events.max_last_update | Date | The time of last update. | 
| CarbonBlackEDR.Events.min_last_update | Date | The time of last update. | 
| CarbonBlackEDR.Events.last_update | Date | The time of the last event received from this process, as recorded by the remote host. | 
| CarbonBlackEDR.Events.id | String | The internal CB process id of this process. | 
| CarbonBlackEDR.Events.terminated | Boolean | Whether the event is terminated. | 
| CarbonBlackEDR.Events.crossproc_count | Number | The count of cross process events launched by this process. | 
| CarbonBlackEDR.Events.group | String | The sensor group the sensor was assigned to. | 
| CarbonBlackEDR.Events.max_last_server_update | Date | Time of server last update. | 
| CarbonBlackEDR.Events.parent_id | String | The Carbon Black process id of the parent process. | 
| CarbonBlackEDR.Events.hostname | String | The hostname of the computer this process executed on. | 
| CarbonBlackEDR.Events.filemod_count | Number | The count of file modifications in this process. | 
| CarbonBlackEDR.Events.start | Date | The start time of this process, as recorded by the remote host. | 
| CarbonBlackEDR.Events.comms_ip | Number | IP address that the Cb server received the events on. If the endpoint is behind a NAT,
for example, this will be the external IP of the network the endpoint lives on. | 
| CarbonBlackEDR.Events.regmod_count | Number | The count of registry modifications in this process. | 
| CarbonBlackEDR.Events.interface_ip | Number | The IP address of the network interface\(s\) on the endpoint that generated the message. | 
| CarbonBlackEDR.Events.process_pid | Number | The pid of the process. | 
| CarbonBlackEDR.Events.username | String | The user assosicated with the event. | 
| CarbonBlackEDR.Events.process_name | String | The name of this process, e.g., svchost.exe. | 
| CarbonBlackEDR.Events.emet_count | Number | Number of EMET associated with the event. | 
| CarbonBlackEDR.Events.last_server_update | Date | When the event was last updated in the server. | 
| CarbonBlackEDR.Events.path | String | The full path of the executable backing this process, e.g., c:\\windows\\system32\\svchost.exe . | 
| CarbonBlackEDR.Events.netconn_count | Number | The count of network connections in this process. | 
| CarbonBlackEDR.Events.parent_pid | Number | The pid of the process's parent. | 
| CarbonBlackEDR.Events.segment_id | Date | The segment id of this process. | 
| CarbonBlackEDR.Events.min_last_server_update | Date | When the event was last updated in the server. | 
| CarbonBlackEDR.Events.host_type | String | The host type associated with the event. | 
| CarbonBlackEDR.Events.processblock_count | Number | The number of processblock associated with the process. | 
| CarbonBlackEDR.Events.filemod_complete.operation_type | String | The operation type.
One of Created the file, First wrote to the file, Deleted the file, Last wrote to the file. | 
| CarbonBlackEDR.Events.filemod_complete.event_time | Date | The event time. | 
| CarbonBlackEDR.Events.filemod_complete.file_path | String | The file path. | 
| CarbonBlackEDR.Events.filemod_complete.md5_after_last_write | String | The md5 of the file after the last write. | 
| CarbonBlackEDR.Events.filemod_complete.file_type | String | The file type, if known. One of: PE, Elf, UniversalBin, EICAR, OfficeLegacy, OfficeOpenXml,
Pdf, ArchivePkzip, ArchiveLzh, ArchiveLzw, ArchiveRar, ArchiveTar, Archive7zip. | 
| CarbonBlackEDR.Events.filemod_complete.flagged_as_potential_tamper_attempt | String | Whether event is flagged as potential tamper attempt. | 
| CarbonBlackEDR.Events.modload_complete.event_time | Date | The event time. | 
| CarbonBlackEDR.Events.modload_complete.loaded_module_md5 | String | MD5 of the loaded module. | 
| CarbonBlackEDR.Events.modload_complete.loaded_module_full_path | String | Full path of the loaded module. | 
| CarbonBlackEDR.Events.regmod_complete.operation_type | String | The operation type.
One of Created the file, First wrote to the file, Deleted the file, Last wrote to the file. | 
| CarbonBlackEDR.Events.regmod_complete.event_time | Date | The event time. | 
| CarbonBlackEDR.Events.regmod_complete.registry_key_path | String | The registry key path. | 
| CarbonBlackEDR.Events.crossproc_complete.cross-process_access_type | String | The type of cross-process access:
RemoteThread if remote thread creation; ProcessOpen if process handle open with access privileges. | 
| CarbonBlackEDR.Events.crossproc_complete.event_time | Date | The event time. | 
| CarbonBlackEDR.Events.crossproc_complete.targeted_process_unique_id | String | The unique_id of the targeted process. | 
| CarbonBlackEDR.Events.crossproc_complete.targeted_process_md5 | String | The md5 of the targeted process. | 
| CarbonBlackEDR.Events.crossproc_complete.targeted_process_path | String | The path of the targeted process. | 
| CarbonBlackEDR.Events.crossproc_complete.ProcessOpen_sub-type | String | The sub-type for ProcessOpen. | 
| CarbonBlackEDR.Events.crossproc_complete.requested_access_priviledges | String | The requested access priviledges. | 
| CarbonBlackEDR.Events.crossproc_complete.flagged_as_potential_tamper_attempt | String | Whether event is flagged as potential tamper attempt. | 
| CarbonBlackEDR.Events.os_type | String | The operating system type of the computer for this process. | 
| CarbonBlackEDR.Events.binaries | String | The binaries associated with the event. | 
| CarbonBlackEDR.Events.childproc_count | Number | The count of child processes launched by this process. | 
| CarbonBlackEDR.Events.unique_id | String | The unique_id of the Event. | 

### cb-edr-unquarantine-device

***
Unquarantine the endpoint

#### Base Command

`cb-edr-unquarantine-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor ID to quarantine. | Required | 

#### Context Output

There is no context output for this command.
### cb-edr-quarantine-device

***
Isolate the endpoint from the network

#### Base Command

`cb-edr-quarantine-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor ID to quarantine. | Required | 

#### Context Output

There is no context output for this command.
### cb-edr-sensors-list

***
List the CarbonBlack sensors

#### Base Command

`cb-edr-sensors-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sensor ID. | Optional | 
| ip | Returns the sensor registration(s) with specified IP address. Possible values are: . | Optional | 
| group_id | Retruns the sensor registration(s) in the specified sensor group id. | Optional | 
| inactive_filter_days |  only returns sensors that have been inactive for less than the specified number of days. | Optional | 
| hostname | Returns the sensor registration(s) with matching hostname. | Optional | 
| limit | The maximum amount of sensors to be returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.Sensor.systemvolume_total_size | String | The size, in bytes, of system volume of endpoint on which sensor in installed. | 
| CarbonBlackEDR.Sensor.emet_telemetry_path | String | The path of emet telemtry associated with the sensor. | 
| CarbonBlackEDR.Sensor.os_environment_display_string | String | Human-readable string of the installed OS. | 
| CarbonBlackEDR.Sensor.emet_version | String | The emet version associated with the sensor. | 
| CarbonBlackEDR.Sensor.emet_dump_flags | String | The flags of emet dump associated with the sensor. | 
| CarbonBlackEDR.Sensor.clock_delta | String | The clock delta associated with the sensor. | 
| CarbonBlackEDR.Sensor.supports_cblr | Boolean | Whether the sensor supports cblr. | 
| CarbonBlackEDR.Sensor.sensor_uptime | String | The uptime of the process. | 
| CarbonBlackEDR.Sensor.last_update | String | When the sensor last updated. | 
| CarbonBlackEDR.Sensor.physical_memory_size | Date | The size in bytes of physical memory. | 
| CarbonBlackEDR.Sensor.build_id | Number | The sensor version installed on this endpoint. From the /api/builds/ endpoint. | 
| CarbonBlackEDR.Sensor.uptime | String | Endpoint uptime in seconds. | 
| CarbonBlackEDR.Sensor.is_isolating | Boolean | Boolean representing sensor-reported isolation status. | 
| CarbonBlackEDR.Sensor.event_log_flush_time | Date | If event_log_flush_time is set, the server will instruct the sensor to immediately
send all data before this date, ignoring all other throttling mechansims.
To force a host current, set this value to a value far in the future.
When the sensor has finished sending it’s queued data, this value will be null. | 
| CarbonBlackEDR.Sensor.computer_dns_name | String | The DNS name of the endpoint on which the sensor is installed. | 
| CarbonBlackEDR.Sensor.emet_report_setting | String | The report setting of EMET associated with sensor. | 
| CarbonBlackEDR.Sensor.id | Number | The sensor id of this sensor. | 
| CarbonBlackEDR.Sensor.emet_process_count | Number | The number of EMET processes associated with the sensor. | 
| CarbonBlackEDR.Sensor.emet_is_gpo | Boolean | Whther the EMET is gpo. | 
| CarbonBlackEDR.Sensor.power_state | Number | The sensor power state. | 
| CarbonBlackEDR.Sensor.network_isolation_enabled | Boolean | Boolean representing network isolation request status. | 
| CarbonBlackEDR.Sensor.systemvolume_free_size | Date | The bytes free on the system volume. | 
| CarbonBlackEDR.Sensor.status | String | The sensor status. | 
| CarbonBlackEDR.Sensor.num_eventlog_bytes | String | Number bytes of eventlog. | 
| CarbonBlackEDR.Sensor.sensor_health_message | String | Human-readable string indicating sensor’s self-reported status. | 
| CarbonBlackEDR.Sensor.build_version_string | String | Human-readable string of the sensor version. | 
| CarbonBlackEDR.Sensor.computer_sid | String | Machine SID of this host. | 
| CarbonBlackEDR.Sensor.next_checkin_time | String | Next expected communication from this computer in server-local time and zone. | 
| CarbonBlackEDR.Sensor.node_id | Number | The node ID associated with the sensor. | 
| CarbonBlackEDR.Sensor.cookie | Number | The cookie associated with the sensor. | 
| CarbonBlackEDR.Sensor.emet_exploit_action | String | The EMET exploit action associated with the sensor. | 
| CarbonBlackEDR.Sensor.computer_name | String | NetBIOS name of this computer. | 
| CarbonBlackEDR.Sensor.license_expiration | Date | When the licene of the sensor expires. | 
| CarbonBlackEDR.Sensor.supports_isolation | Boolean | Whther sensor supports isolation. | 
| CarbonBlackEDR.Sensor.parity_host_id | String | The ID of the parity host associated with the sensor. | 
| CarbonBlackEDR.Sensor.supports_2nd_gen_modloads | Boolean | Whether the sensor support modload of 2nd generation. | 
| CarbonBlackEDR.Sensor.network_adapters | String | A pipe-delimited list list of IP,MAC pairs for each network interface. | 
| CarbonBlackEDR.Sensor.sensor_health_status | Number | self-reported health score, from 0 to 100. Higher numbers are better. | 
| CarbonBlackEDR.Sensor.registration_time | String | Time this sensor originally registered in server-local time and zone. | 
| CarbonBlackEDR.Sensor.restart_queued | Boolean | Whether a restart of the sensot is queued. | 
| CarbonBlackEDR.Sensor.notes | String | The notes associated with the sensor. | 
| CarbonBlackEDR.Sensor.num_storefiles_bytes | String | Number of storefiles bytes associated with the sensor. | 
| CarbonBlackEDR.Sensor.os_environment_id | Number | The ID of the os enviroment of the sensor. | 
| CarbonBlackEDR.Sensor.shard_id | Number | The ID of the shard associated with the sensor. | 
| CarbonBlackEDR.Sensor.boot_id | String | A sequential counter of boots since the sensor was installed. | 
| CarbonBlackEDR.Sensor.last_checkin_time | String | Last communication with this computer in server-local time and zone. | 
| CarbonBlackEDR.Sensor.os_type | Number | The operating system type of the computer. | 
| CarbonBlackEDR.Sensor.group_id | Number | The sensor group id this sensor is assigned to. | 
| CarbonBlackEDR.Sensor.display | Boolean | Deprecated. | 
| CarbonBlackEDR.Sensor.uninstall | Boolean | when set, indicates sensor will be directed to uninstall on next checkin. | 

### cb-edr-watchlist-delete

***
Delete a Watchlist that is specified using ID.

#### Base Command

`cb-edr-watchlist-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Delete a watchlist in Carbon black Response. | Required | 

#### Context Output

There is no context output for this command.
### cb-edr-watchlist-update

***
Updates a Watchlist that is specified using ID.

#### Base Command

`cb-edr-watchlist-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The watchlist ID. | Required | 
| search_query | The raw Carbon Black query that this watchlist matches. | Optional | 
| description | A description of the update. | Optional | 
| enabled | Whether the watchlist is enabled or not. | Optional | 

#### Context Output

There is no context output for this command.
### cb-edr-watchlist-update-action

***
Updates a Watchlist action that is specified using ID.

#### Base Command

`cb-edr-watchlist-update-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The watchlist ID. | Required | 
| action_type | Action type specified for the watchlist. Options for action_type are syslog, email and alert. Possible values are: syslog, email, alert. | Required | 
| enabled | Whether the watchlist is enabled or not. Possible values are: True, False. | Required | 

#### Context Output

There is no context output for this command.
### cb-edr-watchlist-create

***
Creates a new Watchlist within EDR,

#### Base Command

`cb-edr-watchlist-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the watchlist. | Required | 
| search_query | The raw Carbon Black query that this watchlist matches. | Required | 
| description | A description of the update. | Optional | 
| index_type | the type of watchlist. Valid values are ‘modules’ and ‘events’ for binary and process watchlists, respectively. Deafult is 'events'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.Watchlist.id | Number | An ID for the new watchlist | 

### cb-edr-watchlists-list

***
Retrieve watchlist in Carbon black Response.

#### Base Command

`cb-edr-watchlists-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The watchlist ID. | Optional | 
| limit | The maximum amount of watchlists to be returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.Watchlist.last_hit_count | Number | A count of lifetime watchlist matches. | 
| CarbonBlackEDR.Watchlist.description | String | A description of the watchlist. | 
| CarbonBlackEDR.Watchlist.search_query | String | The raw Carbon Black query that this watchlist matches. | 
| CarbonBlackEDR.Watchlist.enabled | Boolean | Whether the watchlist is enabled. | 
| CarbonBlackEDR.Watchlist.search_timestamp | Date | Time of the search associated with the watchlist. | 
| CarbonBlackEDR.Watchlist.index_type | String | The type of watchlist.
Valid values are ‘modules’ and ‘events’ for binary and process watchlists, respectively. | 
| CarbonBlackEDR.Watchlist.readonly | Boolean | Whether the watchlist is readonly. | 
| CarbonBlackEDR.Watchlist.total_hits | String | The number of total hits associated with the watchlist. | 
| CarbonBlackEDR.Watchlist.date_added | String | The date this watchlist was created on this Enterprise Server. | 
| CarbonBlackEDR.Watchlist.group_id | Number | The sensor group id this watchlist is assigned to. | 
| CarbonBlackEDR.Watchlist.total_tags | String | The number of total tags associated with the watchlist. | 
| CarbonBlackEDR.Watchlist.id | String | The id of this watchlist. | 
| CarbonBlackEDR.Watchlist.last_hit | Date | A timestamp of the last time this watchlist triggered a match. | 
| CarbonBlackEDR.Watchlist.name | String | The name of this watchlist. | 

### cb-edr-binary-ban

***
Prevent execution of a specified md5 hash

#### Base Command

`cb-edr-binary-ban`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | The banned hash. | Required | 
| text | Text description of block list. | Required | 
| last_ban_time | The last time the hash was blocked or prevented from being executed. | Optional | 
| ban_count | Total number of blocks on the banned list. | Optional | 
| last_ban_host | Last hostname to block this hash. | Optional | 

#### Context Output

There is no context output for this command.
### cb-edr-binary-bans-list

***
Returns a list of banned hashes

#### Base Command

`cb-edr-binary-bans-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum hashs of result to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.BinaryBan.username | String | The username who banned the record. | 
| CarbonBlackEDR.BinaryBan.audit.username | String | The user assosicated with the binary ban. | 
| CarbonBlackEDR.BinaryBan.audit.timestamp | Date | The time of the binary ban. | 
| CarbonBlackEDR.BinaryBan.audit.text | String | The text assosicated with the binary ban. | 
| CarbonBlackEDR.BinaryBan.audit.enabled | Boolean | Whether the binary ban is enabled. | 
| CarbonBlackEDR.BinaryBan.audit.user_id | Number | The user ID assosiated with binary ban. | 
| CarbonBlackEDR.BinaryBan.text | String | The text description of banned record. | 
| CarbonBlackEDR.BinaryBan.md5hash | String | The banned hash. | 
| CarbonBlackEDR.BinaryBan.block_count | Number | The total number of blocks on the banned list. | 
| CarbonBlackEDR.BinaryBan.user_id | Number | The id of the user who banned the record. | 
| CarbonBlackEDR.BinaryBan.last_block_sensor_id | String | The last sensor id which prevented the hash from executing. | 
| CarbonBlackEDR.BinaryBan.enabled | Boolean | Whether the ban is enabled. | 
| CarbonBlackEDR.BinaryBan.last_block_time | Date | The  last time the hash was blocked or prevented from being executed. | 
| CarbonBlackEDR.BinaryBan.timestamp | String | The date and time the record was banned. | 
| CarbonBlackEDR.BinaryBan.last_block_hostname | String | The last hostname to block this hash. | 

### cb-edr-alert-update

***
Alerts update and resolution.
Updating Alerts requires an API key with Global Administrator privileges.

#### Base Command

`cb-edr-alert-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | Alert unique identifier. | Required | 
| status | The requested status to <br/>. Possible values are: Resolved, Unresolved, In Progress, False Positive. | Optional | 
| set_ignored | Setting is_ignored to True for an Alert carries through to the threat report that generated the Alert. Any further hits on IOCs contained within that report will no longer trigger an Alert. Possible values are: true, false. | Optional | 
| query | Advanced query string. Accepts the same data as the search box on the Process Search page. For more information on the query syntax see https://developer.carbonblack.com/resources/query_overview.pdf. If not provided, at least one other search field must be provided. | Optional | 

#### Context Output

There is no context output for this command.
### cb-edr-alert-search

***
Retrieve alerts from Carbon Black Response.

#### Base Command

`cb-edr-alert-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Alert status to filter by. Possible values are: Unresolved, In Progress, Resolved, False Positive. | Optional | 
| username | Alert username to filter by. | Optional | 
| feedname | Alert feedname to filter by. | Optional | 
| hostname | Alert hostname to filter by. | Optional | 
| report | Alert report name (watchlist_id) to filter by. | Optional | 
| query | Advanced query string. Accepts the same data as the search box. For more information on the query syntax see https://developer.carbonblack.com/resources/query_overview.pdf. If not provided, at least one other search field must be provided. | Optional | 
| sort | Sort rows by this field and order. server_added_timestamp desc by default. | Optional | 
| facet | Return facet results. 'false' by default, set to 'true' for facets. | Optional | 
| limit | Maximum number of alerts to show, 10 by default. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.Alert.Terms | String | A list of strings, each representing a token as parsed by the query parser. | 
| CarbonBlackEDR.Alert.Results.username | String | The user assosicated with the alert. | 
| CarbonBlackEDR.Alert.Results.alert_type | String | The type of the alert. | 
| CarbonBlackEDR.Alert.Results.sensor_criticality | Number | The criticality of the sensor. | 
| CarbonBlackEDR.Alert.Results.modload_count | Number | The count of modules loaded. | 
| CarbonBlackEDR.Alert.Results.report_score | Number | The score of the report. | 
| CarbonBlackEDR.Alert.Results.watchlist_id | String | The id of the watchlist. | 
| CarbonBlackEDR.Alert.Results.sensor_id | Number | The id of the sensor. | 
| CarbonBlackEDR.Alert.Results.feed_name | String | The name of the source feed | 
| CarbonBlackEDR.Alert.Results.created_time | Date | The alert creation time. | 
| CarbonBlackEDR.Alert.Results.report_ignored | Boolean | Whether the alert report should be ignored. | 
| CarbonBlackEDR.Alert.Results.ioc_type | String | The type of the resource. | 
| CarbonBlackEDR.Alert.Results.watchlist_name | String | The name of the watchlist. | 
| CarbonBlackEDR.Alert.Results.ioc_confidence | Number | The confience of the resource. | 
| CarbonBlackEDR.Alert.Results.ioc_attr | String | The resource attributes. | 
| CarbonBlackEDR.Alert.Results.alert_severity | Number | The severity of the alert. | 
| CarbonBlackEDR.Alert.Results.crossproc_count | Number | The count of cross process events launched by this process. | 
| CarbonBlackEDR.Alert.Results.group | String | The sensor group id this sensor is assigned to. | 
| CarbonBlackEDR.Alert.Results.hostname | String | The hostname assisicated with the alert. | 
| CarbonBlackEDR.Alert.Results.filemod_count | Number | The count of file modifications in this process. | 
| CarbonBlackEDR.Alert.Results.comms_ip | String | IP address that the Cb server received the alert on. If the endpoint is behind a NAT,
for example, this will be the external IP of the network the endpoint lives on. | 
| CarbonBlackEDR.Alert.Results.netconn_count | Number | The count of network connections in this process. | 
| CarbonBlackEDR.Alert.Results.interface_ip | String | The IP address of the network interface\(s\) on the endpoint that generated the message. | 
| CarbonBlackEDR.Alert.Results.status | String | The status of the alert. One of Resolved, Unresolved, In Progress, or False Positive. | 
| CarbonBlackEDR.Alert.Results.process_path | String | The path of the process. | 
| CarbonBlackEDR.Alert.Results.description | String | The description of the alert. | 
| CarbonBlackEDR.Alert.Results.process_name | String | The name of the process. | 
| CarbonBlackEDR.Alert.Results.process_unique_id | String | The unique_id of the targeted process. | 
| CarbonBlackEDR.Alert.Results.process_id | String | The id of the process. | 
| CarbonBlackEDR.Alert.Results.link | String | A link to the report. | 
| CarbonBlackEDR.Alert.Results._version_ | Number | The version of the alert. | 
| CarbonBlackEDR.Alert.Results.regmod_count | Number | The count of registry modifications in this process. | 
| CarbonBlackEDR.Alert.Results.md5 | String | The md5 of the process. | 
| CarbonBlackEDR.Alert.Results.segment_id | Date | The segment id of the process. | 
| CarbonBlackEDR.Alert.Results.total_hosts | Number | The number of total host. | 
| CarbonBlackEDR.Alert.Results.feed_id | Number | The id of the source feed. | 
| CarbonBlackEDR.Alert.Results.ioc_value | String | The value of the resource. | 
| CarbonBlackEDR.Alert.Results.os_type | String | The operating system type of the computer for this process; one of Windows, Linux, OSX. | 
| CarbonBlackEDR.Alert.Results.childproc_count | Number | The count of processes launched by this process. | 
| CarbonBlackEDR.Alert.Results.unique_id | String | The unique_id of the alert. | 
| CarbonBlackEDR.Alert.Results.feed_rating | Number | The rating of the Source feed. | 

### cb-edr-binary-summary

***
Returns the metadata for the binary with the provided md5

#### Base Command

`cb-edr-binary-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | The md5 of the binary. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.BinaryMetadata.host_count | Number | The number of host for the targeted file. | 
| CarbonBlackEDR.BinaryMetadata.digsig_result | String | Digital signature status.
One of Signed, Unsigned, Expired, Bad Signature, Invalid Signature, Invalid Chain,
Untrusted Root, or Explicit Distrust. | 
| CarbonBlackEDR.BinaryMetadata.observed_filename | String | A list of strings, one per unique filename this binary has been seen as. | 
| CarbonBlackEDR.BinaryMetadata.product_version | String | If present, Product version from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinaryMetadata.digsig_issuer | String | If signed and present, the issuer name. | 
| CarbonBlackEDR.BinaryMetadata.signed | String | Digital signature status.
One of Signed, Unsigned, Expired, Bad Signature, Invalid Signature, Invalid Chain,
Untrusted Root, or Explicit Distrust. | 
| CarbonBlackEDR.BinaryMetadata.digsig_sign_time | Date | If signed, the timestamp of the signature in GMT. | 
| CarbonBlackEDR.BinaryMetadata.orig_mod_len | Number | Filesize in bytes. | 
| CarbonBlackEDR.BinaryMetadata.is_executable_image | Boolean | Whether the file is an EXE. | 
| CarbonBlackEDR.BinaryMetadata.is_64bit | Boolean | Whether the file is x64. | 
| CarbonBlackEDR.BinaryMetadata.digsig_subject | String | If signed and present, the subject. | 
| CarbonBlackEDR.BinaryMetadata.digsig_publisher | String | If signed and present, the publisher name. | 
| CarbonBlackEDR.BinaryMetadata.group | String | A list of 0 or more sensor groups \(by name\) in which this binary was observed. | 
| CarbonBlackEDR.BinaryMetadata.event_partition_id | Number | The ID of the event partition associated with the binary file. | 
| CarbonBlackEDR.BinaryMetadata.file_version | String | If present, File version from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinaryMetadata.company_name | String | If present, Company name from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinaryMetadata.internal_name | String | If present, Internal name from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinaryMetadata.icon | String | The icon of the file. | 
| CarbonBlackEDR.BinaryMetadata.product_name | String | If present, Product name from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinaryMetadata.digsig_result_code | String | HRESULT_FROM_WIN32 for the result of the digital signature operation via WinVerifyTrust. | 
| CarbonBlackEDR.BinaryMetadata.timestamp | Date | The time of the file search. | 
| CarbonBlackEDR.BinaryMetadata.copied_mod_len | Number | Bytes copied from remote host, if file is &gt; 25MB this will be less than orig_mod_len. | 
| CarbonBlackEDR.BinaryMetadata.server_added_timestamp | Date | The first time this binary was received on the server in the server GMT time. | 
| CarbonBlackEDR.BinaryMetadata.facet_id | Number | The id of the facet searched. | 
| CarbonBlackEDR.BinaryMetadata.digsig_prog_name | String | If signed and present, the program name. | 
| CarbonBlackEDR.BinaryMetadata.md5 | String | The md5 hash of this binary. | 
| CarbonBlackEDR.BinaryMetadata.endpoint | String | A list of 0 or more hostname, sensorid tuples on which this binary was observed.
The | character serves as the delimiter between the hostname and the sensorid. | 
| CarbonBlackEDR.BinaryMetadata.watchlists.wid | String | The wid of the watchlist. | 
| CarbonBlackEDR.BinaryMetadata.watchlists.value | Date | The value of the watchlist. | 
| CarbonBlackEDR.BinaryMetadata.legal_copyright | String | If present, Legal copyright from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinaryMetadata.original_filename | String | If present, Original filename from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinaryMetadata.cb_version | Number | The version of Carbon Black. | 
| CarbonBlackEDR.BinaryMetadata.os_type | String | The operating system type of the computer for this process; one of Windows, Linux, OSX. | 
| CarbonBlackEDR.BinaryMetadata.file_desc | String | If present, File description from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinaryMetadata.last_seen | Date | The last seen time of the file. | 

### cb-edr-binary-download

***
Download the binary with this md5 hash.

#### Base Command

`cb-edr-binary-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | The md5 hash of the binary. | Required | 

#### Context Output

There is no context output for this command.
### cb-edr-binary-search

***
Binary search

#### Base Command

`cb-edr-binary-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_name | Gets the name of the product this file is distributed with. | Optional | 
| md5 | The md5 hash of this binary. | Optional | 
| digital_signature | Digital signature status. Possible values are: Signed, Unsigned, Expired, Bad Signature, Invalid Signature, Invalid Chain, Untrusted Root, Explicit Distrust. | Optional | 
| publisher | If signed and present, the publisher name. | Optional | 
| company_name | The name of the company that produced the file. | Optional | 
| group | Sensor group this sensor was<br/>assigned to at the time of process<br/>execution. | Optional | 
| hostname | Hostname of the computer on<br/>which the process was executed. | Optional | 
| sort | Sort rows by this field and order. server_added_timestamp desc by default. | Optional | 
| observed_filename | Full path of the binary at the time<br/>of collection. | Optional | 
| query | Advanced query string. Accepts the same data as the search box. For more information on the query syntax see https://developer.carbonblack.com/resources/query_overview.pdf. If not provided, at least one other search field must be provided. | Optional | 
| facet | Return facet results. ‘false’ by default, set to ‘true’ for facets. | Optional | 
| facet_field | facet field name to return. Multiple facet.field parameters can be specified in a query. | Optional | 
| limit | Return this many rows, 10 by default. | Optional | 
| start | Start at this row, 0 by default. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackEDR.BinarySearch.terms | String | A list of strings, each representing a token as parsed by the query parser. | 
| CarbonBlackEDR.BinarySearch.total_results | Number | The number of matching binaries. | 
| CarbonBlackEDR.BinarySearch.highlights | String | A list of highlight objects matching the query string. Format the same as the process event object. | 
| CarbonBlackEDR.BinarySearch.Results.host_count | Number | The count of unique endpoints which have ever reported this binary. | 
| CarbonBlackEDR.BinarySearch.Results.original_filename | String | If present, Original filename from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinarySearch.Results.legal_copyright | String | If present, Legal copyright from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinarySearch.Results.digsig_result | String | Digital signature status.
One of Signed, Unsigned, Expired, Bad Signature, Invalid Signature, Invalid Chain,
Untrusted Root, or Explicit Distrust. | 
| CarbonBlackEDR.BinarySearch.Results.observed_filename | String | A list of strings, one per unique filename this binary has been seen as. | 
| CarbonBlackEDR.BinarySearch.Results.product_version | String | If present, Product version from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinarySearch.Results.watchlists.wid | String | The wid of the watchlist. | 
| CarbonBlackEDR.BinarySearch.Results.watchlists.value | Date | The value of the watchlist. | 
| CarbonBlackEDR.BinarySearch.Results.facet_id | Number | The id of the facet searched. | 
| CarbonBlackEDR.BinarySearch.Results.digsig_issuer | String | If signed and present, the issuer name. | 
| CarbonBlackEDR.BinarySearch.Results.copied_mod_len | Number | Bytes copied from remote host, if file is &gt; 25MB this will be less than orig_mod_len. | 
| CarbonBlackEDR.BinarySearch.Results.comments | String | Comments of the search. | 
| CarbonBlackEDR.BinarySearch.Results.digsig_sign_time | Date | If signed, the timestamp of the signature in GMT. | 
| CarbonBlackEDR.BinarySearch.Results.digsig_prog_name | String | If signed and present, the program name. | 
| CarbonBlackEDR.BinarySearch.Results.orig_mod_len | Number | Filesize in bytes. | 
| CarbonBlackEDR.BinarySearch.Results.is_executable_image | Boolean | Whether the file is an EXE. | 
| CarbonBlackEDR.BinarySearch.Results.is_64bit | Boolean | Whether the file is x64. | 
| CarbonBlackEDR.BinarySearch.Results.md5 | String | The md5 hash of this binary. | 
| CarbonBlackEDR.BinarySearch.Results.digsig_subject | String | If signed and present, the subject. | 
| CarbonBlackEDR.BinarySearch.Results.digsig_publisher | String | If signed and present, the publisher name. | 
| CarbonBlackEDR.BinarySearch.Results.endpoint | String | A list of 0 or more hostname, sensorid tuples on which this binary was observed.
The | character serves as the delimiter between the hostname and the sensorid. | 
| CarbonBlackEDR.BinarySearch.Results.group | String | A list of 0 or more sensor groups \(by name\) in which this binary was observed. | 
| CarbonBlackEDR.BinarySearch.results.event_partition_id | Number | The ID of the event partition associated with the binary file. | 
| CarbonBlackEDR.BinarySearch.Results.digsig_result_code | String | HRESULT_FROM_WIN32 for the result of the digital signature operation via WinVerifyTrust. | 
| CarbonBlackEDR.BinarySearch.Results.file_version | String | If present, File version from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinarySearch.Results.signed | String | Digital signature status: One of Signed, Unsigned, Expired, Bad Signature, Invalid Signature,
Invalid Chain, Untrusted Root, or Explicit Distrust. | 
| CarbonBlackEDR.BinarySearch.Results.last_seen | Date | The last seen time of the file. | 
| CarbonBlackEDR.BinarySearch.Results.company_name | String | If present, Company name from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinarySearch.Results.internal_name | String | If present, Internal name from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinarySearch.Results.timestamp | Date | Search creation time. | 
| CarbonBlackEDR.BinarySearch.Results.cb_version | Number | The version of Carbon Black. | 
| CarbonBlackEDR.BinarySearch.Results.os_type | String | The operating system type of this binary; one of windows, linux, osx. | 
| CarbonBlackEDR.BinarySearch.Results.file_desc | String | If present, File description from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinarySearch.Results.product_name | String | If present, Product name from FileVersionInformation. For more information check
https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 
| CarbonBlackEDR.BinarySearch.Results.server_added_timestamp | Date | The first time this binary was received on the server in the server GMT time. | 
| CarbonBlackEDR.BinarySearch.Results.private_build | String | If present, Private build from FileVersionInformation. For more information check https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?redirectedfrom=MSDN&amp;view=net-5.0 | 

### endpoint

***
Display information about the given sensor

#### Base Command

`endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The sensor ID. | Optional | 
| ip | Query sensors with specified IP address. | Optional | 
| hostname | Query sensors with matching hostname. | Optional | 
| endpoint | . | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.Relationships.EntityA | string | The source of the relationship. | 
| Endpoint.Relationships.EntityB | string | The destination of the relationship. | 
| Endpoint.Relationships.Relationship | string | The name of the relationship. | 
| Endpoint.Relationships.EntityAType | string | The type of the source of the relationship. | 
| Endpoint.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 
| Endpoint.Domain | String | The endpoint's domain. | 
| Endpoint.DHCPServer | String | The DHCP server of the endpoint. | 
| Endpoint.OSVersion | String | The endpoint's operation system version. | 
| Endpoint.BIOSVersion | String | The endpoint's BIOS version. | 
| Endpoint.Model | String | The model of the machine or device. | 
| Endpoint.Memory | Int | Memory on this endpoint. | 
| Endpoint.Processors | Int | The number of processors. | 
| Endpoint.Processor | String | The model of the processor. | 

## Breaking changes from the previous version of this integration - VMware Carbon Black EDR v2
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version

* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
