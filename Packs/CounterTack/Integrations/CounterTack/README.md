CounterTack empowers endpoint security teams to assure endpoint protection for Identifying Cyber Threats. Integrating a predictive endpoint protection platform

## Configure CounterTack in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://democloud.countertack.com) | True |
| User Name | True |
| Password | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |
| Fetch incidents | False |
| Incident type | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
| Fetch notifications incidents | False |
| Fetch behviors incidents | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### countertack-get-endpoints
***
Returns information for endpoints.


#### Base Command

`countertack-get-endpoints`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.IsQuarantined | boolean | Is the endpoint currently quarantined | 
| CounterTack.Endpoint.MaxImpact | number | Impact of the highest scoring behavior | 
| CounterTack.Endpoint.Memory | number | The RAM of the endpoint \(in megabytes\). | 
| CounterTack.Endpoint.DriverVersion | string | Endpoint sensor version | 
| CounterTack.Endpoint.ProfileVersion | string | Version of the current profile used for collection | 
| CounterTack.Endpoint.BehaviorCount | number | Number of behaviors detected | 
| CounterTack.Endpoint.CurrentProfile | string | Currently active analysis profile | 
| CounterTack.Endpoint.Domain | string | DNS suffix for the endpoint | 
| CounterTack.Endpoint.NumCpus | number | Number of CPUs | 
| CounterTack.Endpoint.Macs | string | MAC addresses associated with the endpoint | 
| CounterTack.Endpoint.WinRdpPort | number | RDP port used by the endpoint | 
| CounterTack.Endpoint.Ip | string | IP address used to connect to the analysis cluster | 
| CounterTack.Endpoint.ClusterHosts | string | The list of hosts that the endpoint tries to connect through \(in order\). | 
| CounterTack.Endpoint.Vendor | string | OS vendor | 
| CounterTack.Endpoint.SensorMode | string | Specifies the sensor mode of the driver | 
| CounterTack.Endpoint.Identifier | string | OS identifier | 
| CounterTack.Endpoint.CurrentResponsePolicy | string | Currently active response policy | 
| CounterTack.Endpoint.Tenant | string | Tenant ID set at the time of KM installation | 
| CounterTack.Endpoint.Name | string | Product name of the endpoint OS | 
| CounterTack.Endpoint.ImpactLevel | string | Threat level of the endpoint.\(LOW, MEDIUM, HIGH, CRITICAL\) | 
| CounterTack.Endpoint.Ips | string | IP addresses associated with the endpoint | 
| CounterTack.Endpoint.ClusterConnectionRoute | string | List of hosts the endpoint is currently connected through | 
| CounterTack.Endpoint.LastActive | date | Time of last event captured on the endpoint | 
| CounterTack.Endpoint.TimeStarted | date | Time kernel module collection last engaged | 
| CounterTack.Endpoint.Mac | string | The endpoint MAC address | 
| CounterTack.Endpoint.EventStartTime | date | The time that the event was captured | 
| CounterTack.Endpoint.CpuType | string | Bit length of the CPU architecture. | 
| CounterTack.Endpoint.Status | string | Collection status of the endpoint \(ON, PAUSE, OFF, INIT\) | 
| CounterTack.Endpoint.OsType | number | The OS type. | 
| CounterTack.Endpoint.Version | string | OS version | 
| CounterTack.Endpoint.Tags | string | List of user assigned tags | 
| CounterTack.Endpoint.Threat | string | Threat level associated with the endpoint | 
| CounterTack.Endpoint.Id | string | Endpoints ID | 
| CounterTack.Endpoint.ProductName | string | Product name of the endpoint OS | 
| Endpoint.Memory | number | Endpoint RAM \(megabytes\) | 
| Endpoint.Processors | number | Number of CPUs | 
| Endpoint.Domain | string | DNS suffix for the endpoint | 
| Endpoint.OS | string | Product name of the endpoint OS | 
| Endpoint.MACAddress | string | The MAC address of the endpoint. | 
| Endpoint.Model | string | The analysis profile that is currently active. | 
| Endpoint.IPAddress | string | The IP addresses that are associated with the endpoint. | 
| Endpoint.OSVersion | string | The endpoint sensor version. | 
| Endpoint.ID | string | The ID of the Endpoints. | 

### countertack-get-behaviors
***
Returns information for all behaviors.


#### Base Command

`countertack-get-behaviors`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Behavior.MaxImpact | number | The impact of the highest scoring event \(0-100\) | 
| CounterTack.Behavior.EndpointId | string | The ID of the endpoint, based on the UUID of the last installed endpoint sensor | 
| CounterTack.Behavior.Tenant | string | The tenant of the behavior. | 
| CounterTack.Behavior.EventCount | number | The number of events detected. | 
| CounterTack.Behavior.Name | string | The name of the condition that triggered the behavior. | 
| CounterTack.Behavior.ImpactLevel | string | The threat level of the behavior \(LOW, MEDIUM, HIGH, CRITICAL\). | 
| CounterTack.Behavior.LastActive | date | The time that the behavior was last active. | 
| CounterTack.Behavior.FirstEventId | date | The ID of the first event. | 
| CounterTack.Behavior.TimeStamp | date | The start time for the behavior. | 
| CounterTack.Behavior.Type | string | The type of behavior \(CLASSIFICATION, TRACE\) | 
| CounterTack.Behavior.Id | string | The ID of the behaviors. | 
| CounterTack.Behavior.LastReported | date | The time that the behavior was last seen. | 

### countertack-get-endpoint
***
Get information on specific endpoint


#### Base Command

`countertack-get-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint. To get the "endpoint_id", run the `get-endpoints` command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.MaxImpact | number | The impact of the highest scoring behavior. | 
| CounterTack.Endpoint.Memory | number | The RAM of the endpoint \(in megabytes\) | 
| CounterTack.Endpoint.DriverVersion | string | The sensor version of the endpoint. | 
| CounterTack.Endpoint.ProfileVersion | string | The version of the current profile used for collection. | 
| CounterTack.Endpoint.BehaviorCount | number | The number of behaviors that were detected. | 
| CounterTack.Endpoint.CurrentProfile | string | The analysis profile that is currently active. | 
| CounterTack.Endpoint.Domain | string | DNS suffix for the endpoint. | 
| CounterTack.Endpoint.NumCpus | number | The number of CPUs for the endpoint. | 
| CounterTack.Endpoint.WinRdpPort | number | The RDP port used by the endpoint. | 
| CounterTack.Endpoint.Macs | string | The MAC addresses associated with the endpoint. | 
| CounterTack.Endpoint.Ip | string | The IP address used to connect to the analysis cluster. | 
| CounterTack.Endpoint.ClusterHosts | string | The list of hosts that the endpoint tries to connect through \(in order\). | 
| CounterTack.Endpoint.Vendor | string | The OS vendor. | 
| CounterTack.Endpoint.SensorMode | string | The sensor mode of the driver. | 
| CounterTack.Endpoint.Identifier | string | The identifier of the OS. | 
| CounterTack.Endpoint.Tenant | string | The tenant ID that was set at the time of KM installation. | 
| CounterTack.Endpoint.Name | string | The machine name of the endpoint. | 
| CounterTack.Endpoint.ImpactLevel | string | The threat level of the endpoint. | 
| CounterTack.Endpoint.Ips | string | The IP addresses associated with the endpoint. | 
| CounterTack.Endpoint.ClusterConnectionRoute | string | The list of hosts that the endpoint is currently connected through. | 
| CounterTack.Endpoint.LastActive | date | The time of the last event that was captured on the endpoint. | 
| CounterTack.Endpoint.TimeStarted | date | The first time that the endpoint started to work. | 
| CounterTack.Endpoint.Mac | string | The MAC address of the endpoint. | 
| CounterTack.Endpoint.EventStartTime | date | The time that the event was captured. | 
| CounterTack.Endpoint.CpuType | number | The bit length of the CPU architecture. | 
| CounterTack.Endpoint.Status | string | The collection status of the endpoint \(ON, PAUSE, OFF, INIT\). | 
| CounterTack.Endpoint.OsType | number | The OS type. | 
| CounterTack.Endpoint.Version | string | The version of the endpoint. | 
| CounterTack.Endpoint.Threat | string | The threat level associated with the endpoint. | 
| CounterTack.Endpoint.Id | string | The ID of the endpoint. | 
| CounterTack.Endpoint.ProductName | string | The product name of the endpoint OS. | 
| CounterTack.Endpoint.Tags | string | The list of user assigned tags. | 
| CounterTack.Endpoint.IsQuarantined | boolean | Whether the endpoint is currently quarantined. | 
| Endpoint.Memory | number | The RAM of the endpoint \(in megabytes\). | 
| Endpoint.Processors | number | The number of CPUs. | 
| Endpoint.Domain | string | The DNS suffix for the endpoint. | 
| Endpoint.OS | string | The product name of the endpoint OS. | 
| Endpoint.MACAddress | string | The MAC address of the endpoint. | 
| Endpoint.Model | string | The analysis profile that is currently active. | 
| Endpoint.IPAddress | string | The IP addresses associated with the endpoint. | 
| Endpoint.OSVersion | string | The version of the endpoint sensor. | 

### countertack-get-behavior
***
Gets information of a given behavior.


#### Base Command

`countertack-get-behavior`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| behavior_id | The ID of the behavior. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Behavior.MaxImpact | number | The maximum impact of the behavior. | 
| CounterTack.Behavior.EndpointId | string | The ID of the endpoint. | 
| CounterTack.Behavior.Tenant | string | The tenant of the behavior. | 
| CounterTack.Behavior.EventCount | number | The event count of the behavior. | 
| CounterTack.Behavior.ReportedOn | date | The time that the behavior was first seen. | 
| CounterTack.Behavior.Name | string | The name of the behavior. | 
| CounterTack.Behavior.ImpactLevel | string | The impact level of the behavior. | 
| CounterTack.Behavior.LastActive | date | The last time that the behavior was active. | 
| CounterTack.Behavior.TimeStamp | date | The time stamp of the behavior. | 
| CounterTack.Behavior.FirstEventId | string | The ID of the first event. | 
| CounterTack.Behavior.Type | string | The type of behavior. | 
| CounterTack.Behavior.Id | string | The ID of the behavior. | 
| CounterTack.Behavior.LastReported | date | The time that the behavior was last seen. | 

### countertack-get-endpoint-tags
***
Gets the tags of a given endpoint.


#### Base Command

`countertack-get-endpoint-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint to get tags for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.Tags | string | The list of user assigned tags. | 
| CounterTack.Endpoint.EndpointId | string | The ID of the endpoints. | 

### countertack-add-tags
***
Adds tags to a given endpoint.


#### Base Command

`countertack-add-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint. To get the "*endpoint_id*", run the `get-endpoints` command. | Required | 
| tags | A CSV list of tags you want to add to the endpoint, for example, "test1,test2". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.EndpointId | string | The ID of the endpoint. | 
| CounterTack.Endpoint.Tags | string | The tags that were added to the endpoint. | 

### countertack-delete-tags
***
Deletes the supplied tags from a given endpoint.


#### Base Command

`countertack-delete-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tags | The tags to be deleted from specified endpoint. To delete more then one, separate the tags with a comma. (e.g test1,test2). | Required | 
| endpoint_id | The endpoint ID. Get the ID from the "get-endpoints" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.Id | string | The ID of the endpoint | 
| CounterTack.Endpoint.Tags | string | The tags of the specified endpoint | 

### countertack-add-behavior-tags
***
Adds tags to a given behavior.


#### Base Command

`countertack-add-behavior-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| behaviour_id | The ID of the behavior. | Required | 
| tags | A CSV list of tags to add to the behavior, for example, "test1,test2". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Behavior.Id | string | The ID of the behavior. | 
| CounterTack.Behavior.Tags | string | The tags of the behavior. | 

### countertack-delete-behavior-tags
***
Deletes the supplied tags from a given behavior.


#### Base Command

`countertack-delete-behavior-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| behaviour_id | The behavior ID. | Required | 
| tags | Tags to delete from a behavior. To delete more then one, separate the tags with a comma. (e.g test1,test2). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Behavior.Id | string | The ID of the behavior. | 
| CounterTack.Behavior.Tags | Unknown | The tags of the behavior. | 

### countertack-endpoint-quarantine
***
Quarantines a given endpoint.


#### Base Command

`countertack-endpoint-quarantine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint to quarantine. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.Id | string | The ID of the endpoint. | 
| CounterTack.Endpoint.IsQuarantine | boolean | Is the endpoint currently quarantined. | 

### countertack-disable-quarantine
***
Removes a given endpoint from quarantine.


#### Base Command

`countertack-disable-quarantine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint to remove from quarantine. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.Id | string | The ID of the endpoint that was removed from quarantine. | 
| CounterTack.Endpoint.IsQuarantine | string | Is the endpoint is currently quarantined. | 

### countertack-extract-file
***
Extracts a file from given endpoint.


#### Base Command

`countertack-extract-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint to extract a file from. | Required | 
| file_path | The path of the file to extract, for example, "C:\\test1.txt". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.File.CommandArg.contents | boolean | The contents of the extracted file. | 
| CounterTack.File.CommandArg.extracted_ids | string | The IDs of the extracted file. | 
| CounterTack.File.CommandArg.md5 | boolean | The MD5 hash of the extracted file. | 
| CounterTack.File.CommandArg.paths | string | The path of the extracted file. | 
| CounterTack.File.CommandArg.sha256 | boolean | The SHA-256 has of teh extracted file. | 
| CounterTack.File.CommandArg.ssdeep | boolean | The ssdeep hash of the extracted file. | 
| CounterTack.File.CommandArg | Unknown | The command arguments. | 
| CounterTack.File.CommandName | string | The name of the command that is sent. | 
| CounterTack.File.Username | string | The username of the user that requested the command. | 
| CounterTack.File.TargetType | string | The type of resource or collection this command is being sent to. | 
| CounterTack.File.Status | string | The status of the command \(initial, pending, complete, error\). | 
| CounterTack.File.RequestTime | date | The time at which the client requested the command. | 
| CounterTack.File.Id | string | The ID of the commands. | 
| CounterTack.File.EndpointIds | string | The ID of the source this command is being sent to. | 

### countertack-delete-file
***
Deletes a file from the given endpoint.


#### Base Command

`countertack-delete-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint to delete a file from. | Required | 
| file_path | The path of  the file to delete. | Required | 


#### Context Output

There is no context output for this command.
### countertack-get-all-files
***
Gets all extracted files for all endpoints.


#### Base Command

`countertack-get-all-files`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.File.Size | number | The size of the extracted file \(in bytes\). | 
| CounterTack.File.EndpointId | string | The ID of the endpoint that contains the extracted file. | 
| CounterTack.File.ExtractionTime | date | The time that the file was extracted. | 
| CounterTack.File.Path | string | The full file system path of the extracted file, including the filename, as seen on the endpoint. | 
| CounterTack.File.Sha256 | string | The SHA-256 digest of the file contents. | 
| CounterTack.File.Tenant | string | The tenant ID for the endpoint. | 
| CounterTack.File.User | string | The name of the user requesting the file. | 
| CounterTack.File.Ssdeep | string | The ssdeep digest of the file contents. | 
| CounterTack.File.EndpointIp | string | The IP address of the endpoint with the extracted file. | 
| CounterTack.File.AvCoverage | number | The percentage of AV engines that determined that the hash is malicious. | 
| CounterTack.File.Status | string | The status of the contents. | 
| CounterTack.File.VtStatus | string | The Virus Total report status. | 
| CounterTack.File.EndpointName | string | The name of the endpoint with the extracted file. | 
| CounterTack.File.Id | string | The file ID of the extracted file. | 
| CounterTack.File.Md5 | string | The MD5 digest of the file contents. | 
| CounterTack.File.VtReportLocation | string | The VirusTotal report location path. | 
| File.MD5 | string | The MD5 digest of the file contents. | 
| File.Path | string | The full file system path of the extracted file, including the filename, as seen on the endpoint. | 
| File.SHA256 | string | The SHA-256 digest of the file contents. | 
| File.SSDeep | string | The ssdeep digest of the file contents. | 
| File.Size | number | The size of the extracted file \(in bytes\). | 

### countertack-get-endpoint-files
***
Returns all extracted files from a given endpoint.


#### Base Command

`countertack-get-endpoint-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint. To get the endpoint_id, run the `get-endpoints` command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.File.Id | string | The file ID of the extracted file. | 
| CounterTack.File.Status | string | The status of the contents. | 
| CounterTack.File.EndpointId | string | The ID of the endpoint with the extracted file. | 
| CounterTack.File.ExtractionTime | date | The time that the file was extracted. | 
| CounterTack.File.Tenant | string | The tenant ID for the endpoint. | 
| CounterTack.File.User | string | The name of the user requesting the file. | 
| CounterTack.File.Path | string | The full file system path of the extracted file, including the filename, as seen on the endpoint. | 
| CounterTack.File.Sha256 | string | The SHA-256 digest of the file contents. | 
| CounterTack.File.Ssdeep | string | The ssdeep digest of the file contents. | 
| CounterTack.File.EndpointIp | string | The IP address of the endpoint with the extracted file. | 
| CounterTack.File.VtStatus | string | The VirusTotal report status. | 
| CounterTack.File.VtReportLocation | string | The location path of the VirusTotal report. | 
| CounterTack.File.Size | number | The size of the extracted file \(in bytes\). | 
| CounterTack.File.EndpointName | string | The name of the endpoint with the extracted file. | 
| CounterTack.File.Md5 | string | The MD5 digest of the file contents. | 
| File.MD5 | string | The MD5 digest of the file contents. | 
| File.Path | string | The full file system path of the extracted file, including the filename, as seen on the endpoint. | 
| File.SHA256 | string | The SHA-256 digest of the file contents. | 
| File.SSDeep | string | The ssdeep digest of the file contents. | 
| File.Size | number | The size of the extracted file \(bytes\). | 

### countertack-get-file-information
***
Gets the information of a given file.


#### Base Command

`countertack-get-file-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The ID of the requested file. To get the "file_id"m run the `get-all-files` command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.File.Size | number | The size of the extracted file \(in bytes\). | 
| CounterTack.File.EndpointId | string | The ID of the endpoint with the extracted file. | 
| CounterTack.File.ExtractionTime | date | The time that the file was extracted. | 
| CounterTack.File.Path | string | Full file system path of the extracted file, including the filename, as seen on the endpoint. | 
| CounterTack.File.Sha256 | string | The SHA-256 digest of the file contents. | 
| CounterTack.File.Tenant | string | The tenant ID for the endpoint. | 
| CounterTack.File.User | string | The name of the user requesting the file. | 
| CounterTack.File.Ssdeep | string | The ssdeep digest of the file contents. | 
| CounterTack.File.EndpointIp | string | The IP address of the endpoint with the extracted file. | 
| CounterTack.File.AvCoverage | number | The percentage of AV engines that determined that the hash is malicious. | 
| CounterTack.File.Status | string | The status of the contents. | 
| CounterTack.File.VtStatus | string | The status of the VirusTotal report. | 
| CounterTack.File.EndpointName | string | The name of the endpoint with the extracted file. | 
| CounterTack.File.Id | string | The ID of the extracted file. | 
| CounterTack.File.Md5 | string | The MD5 digest of the file contents. | 
| CounterTack.File.VtReportLocation | string | The location path of the VirusTotal report. | 
| File.MD5 | string | The MD5 digest of the file contents. | 
| File.Path | string | The full file system path of the extracted file, including the filename, as seen on the endpoint. | 
| File.SHA256 | string | The SHA-256 digest of the file contents. | 
| File.SSDeep | string | The ssdeep digest of the file contents. | 
| File.Size | number | The size of the extracted file \(in bytes\). | 

### countertack-download-file
***
Downloads an extracted file in ZIP format. The password to unlock the ZIP file is `sentinel`.


#### Base Command

`countertack-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The ID of the extracted file. To get the "file_id", run the `get-all-files` command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | The size of the extracted file \(in bytes\). | 
| File.SHA1 | string | The SHA-1 digest of the file contents. | 
| File.SHA256 | string | The SHA-256 digest of the file contents. | 
| File.Name | string | The name of the file. | 
| File.SSDeep | string | The ssdeep digest of the file contents. | 
| File.EntryID | string | The EntryID of the file. | 
| File.Info | string | The file information. | 
| File.Type | string | The file type. | 
| File.MD5 | string | The MD5 digest of the file contents. | 
| File.Extension | string | The extension of the file \(.zip\). | 

### countertack-search-events
***
Searches for events, using CQL expression.


#### Base Command

`countertack-search-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| expression | The CQL expression to be used for the search, for example, "events.event_type=basic". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Event.SourceProcessTimeStarted | date | The start time for the source process. | 
| CounterTack.Event.SourceThreadProcessPid | number | The process PID of the source thread. | 
| CounterTack.Event.IsTaintTransfer | boolean | Is the event a malignant transfer. | 
| CounterTack.Event.IsBasic | boolean | Is the event a basic event. | 
| CounterTack.Event.SourceThreadTimeFinished | date | The exit time of the source thread. | 
| CounterTack.Event.SourceThreadTid | number | The TID of the source thread. | 
| CounterTack.Event.Tenant | string | The tenant of the event. | 
| CounterTack.Event.SourceThreadProcessTimeStarted | date | The start time of the parent process for the source thread. | 
| CounterTack.Event.TargetType | string | The system object type that was target of the event \(PROCESS, THREAD, REGISTRY, DRIVER, TCPIP,FILE, MUTEX, MEMORY_REGION\). | 
| CounterTack.Event.ConditionNames | Unknown | The names of the condition triggered by the event. | 
| CounterTack.Event.IsOrigin | boolean | Is the event an origin for a trace. | 
| CounterTack.Event.endpoint_id | string | The endpoint ID, based on the UUID of the last installed endpoint sensor. | 
| CounterTack.Event.TargetFilePath | string | The path of the target file. | 
| CounterTack.Events.SourceThreadProcessBackingFilePath | string | The backing file of the source thread. | 
| CounterTack.Event.EventType | string | The type of event. | 
| CounterTack.Event.IsKey | boolean | Is the event a key event in a trace. | 
| CounterTack.Event.SourceType | string | The system object that was the source of the event. | 
| CounterTack.Event.SourceThreadProcessName | string | The name of the parent process for the source thread. | 
| CounterTack.Event.SourceThreadProcessUser | string | The user associated with the process of the thread. | 
| CounterTack.Event.TimeStamp | date | The time that the event was collected. | 
| CounterTack.Event.Action | string | The system interaction that characterizes the event. | 
| CounterTack.Event.IsTainted | boolean | Are the objects in the event tainted. | 
| CounterTack.Event.SourceThreadProcessParentPid | number | The parent PID of the source thread process. | 
| CounterTack.Event.SourceProcessPid | number | The PID of the source process. | 
| CounterTack.Event.SourceThreadStartAddress | number | The start address of the thread. | 
| CounterTack.Event.SourceProcessSid | number | The user SIDs associated with the process. | 
| CounterTack.Event.Id | string | The ID of the event. | 
| CounterTack.Event.ConditionIds | Unknown | The IDs of the condition triggered by the event. | 
| CounterTack.Event.SourceProcessName | string | The name of the process that was the source of the event. | 
| CounterTack.Event.SourceProcessUser | string | The user associated with the process | 

### countertack-kill-process
***
Terminates all instances of the process identified in the command. Processes can be identified by the PID or process name.


#### Base Command

`countertack-kill-process`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint. To get the "endpoint_id", run the `get-endpoints` command. | Required | 
| process_id | The process PID. To get the "process_id", run the `search-events` command. | Optional | 
| process_name | The name of the process. To get the "process_name", run the `search-events` command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.EndpointIds | string | The ID of the source this command is being sent to. | 
| CounterTack.Endpoint.TargetType | string | The type of resource or collection this command is being sent to. | 
| CounterTack.Endpoint.CommandArg.name | string | The name of the process that was terminated. | 
| CounterTack.Endpoint.CommandArg.pid | number | The PID of the process that was terminated. | 
| CounterTack.Endpoint.CommandArg | string | The command arguments. | 
| CounterTack.Endpoint.Status | string | The status of the command \(initial, pending, complete, error\). | 
| CounterTack.Endpoint.CommandName | string | The name of the command that is sent. | 
| CounterTack.Endpoint.Username | string | The username of the user that requested the command. | 
| CounterTack.Endpoint.Id | string | The ID of the commands. | 
| CounterTack.Endpoint.RequestTime | date | The time at which the client requested the command. | 

### countertack-search-hashes
***
Searches for hashes using CQL expressions (Contextual Query Language) to represent queries.


#### Base Command

`countertack-search-hashes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| expression | The CQL expression to be used for the search (e.g hashes.type = md5). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Hash.AvCoverage | number | The percentage of AV engines that determined that the hash is malicious. | 
| CounterTack.Hash.Id | string | The ID of the hashes. | 
| CounterTack.Hash.Impact | number | The impact score for the event in the hash \(1-100\). | 
| CounterTack.Hash.Type | string | The type of hash \(sha256, md5, or ssdeep\). | 
| CounterTack.Hash.VtReportLocation | string | The report location for VirusTotal report. | 
| File.MD5 | string | The MD5 of the file | 
| File.SHA256 | string | The SHA-256 of the file. | 
| File.SSDeep | string | The ssdeep of the file. | 

### countertack-search-endpoints
***
Request for endpoints search using CQL expression (Contextual Query Language) to represent queries.


#### Base Command

`countertack-search-endpoints`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| expression | The CQL expression to be used for the search. (e.g endpoints.status=on). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Endpoint.Memory | Number | The RAM of the endpoint \(in megabytes\). | 
| CounterTack.Endpoint.CpuType | Number | Bit length of the CPU architecture. | 
| CounterTack.Endpoint.WinRdpPort | Number | RDP port used by the endpoint | 
| CounterTack.Endpoint.Macs | String | MAC addresses associated with the endpoint | 
| CounterTack.Endpoint.Ip | String | IP address used to connect to the analysis cluster | 
| CounterTack.Endpoint.Vendor | String | OS vendor | 
| CounterTack.Endpoint.Identifier | String | OS identifier | 
| CounterTack.Endpoint.Tenant | String | Tenant ID set at the time of KM installation | 
| CounterTack.Endpoint.MaxImpact | Number | Impact of the highest scoring behavior | 
| CounterTack.Endpoint.Name | String | Product name of the endpoint OS | 
| CounterTack.Endpoint.Ips | String | IP addresses associated with the endpoint | 
| CounterTack.Endpoint.CurrentResponsePolicy | String | Currently active response policy | 
| CounterTack.Endpoint.ProfileVersion | String | Version of the current profile used for collection | 
| CounterTack.Endpoint.CurrentProfile | String | Currently active analysis profile | 
| CounterTack.Endpoint.DriverVersion | String | Endpoint sensor version | 
| CounterTack.Endpoint.NumCpus | Number | Number of CPUs | 
| CounterTack.Endpoint.ClusterConnectionRoute | String | List of hosts the endpoint is currently connected through | 
| CounterTack.Endpoint.ClusterHosts | String | The list of hosts that the endpoint tries to connect through \(in order\). | 
| CounterTack.Endpoint.Status | String | Collection status of the endpoint \(ON, PAUSE, OFF, INIT\) | 
| CounterTack.Endpoint.TimeStarted | Date | Time kernel module collection last engaged | 
| CounterTack.Endpoint.EventStartTime | Date | The time that the event was captured | 
| CounterTack.Endpoint.Version | String | OS version | 
| CounterTack.Endpoint.Threat | String | Threat level associated with the endpoint | 
| CounterTack.Endpoint.ProductName | String | Product name of the endpoint OS | 
| CounterTack.Endpoint.Id | String | Endpoints ID | 
| CounterTack.Endpoint.LastActive | Date | Time of last event captured on the endpoint | 
| CounterTack.Endpoint.SensorMode | String | Specifies the sensor mode of the driver | 
| CounterTack.Endpoint.BehaviorCount | Number | Number of behaviors detected | 
| CounterTack.Endpoint.ImpactLevel | String | Threat level of the endpoint.\(LOW, MEDIUM, HIGH, CRITICAL\) | 
| CounterTack.Endpoint.OsType | Number | The OS type. | 
| Endpoint.Memory | Number | Endpoint RAM \(megabytes\) | 
| Endpoint.Processors | Number | Number of CPUs | 
| Endpoint.Domain | String | DNS suffix for the endpoint | 
| Endpoint.OS | String | Product name of the endpoint OS | 
| Endpoint.MACAddress | String | The MAC address of the endpoint. | 
| Endpoint.Model | String | The analysis profile that is currently active. | 
| Endpoint.IPAddress | String | The IP addresses that are associated with the endpoint. | 
| Endpoint.OSVersion | String | The endpoint sensor version. | 
| Endpoint.Id | String | The ID of the Endpoints. | 

### countertack-search-behaviors
***
Request for behaviors search using CQL expression (Contextual Query Language) to represent queries.


#### Base Command

`countertack-search-behaviors`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| expression | The CQL expression to be used for the search(e.g behaviors.event_count&lt;60). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterTack.Behavior.FirstEventId | String | The ID of the first event. | 
| CounterTack.Behavior.LastReported | Date | The time that the behavior was last seen. | 
| CounterTack.Behavior.Tenant | String | The tenant of the behavior. | 
| CounterTack.Behavior.MaxImpact | Number | The impact of the highest scoring event \(0-100\) | 
| CounterTack.Behavior.Name | String | The name of the condition that triggered the behavior. | 
| CounterTack.Behavior.EndpointId | String | The ID of the endpoint, based on the UUID of the last installed endpoint sensor | 
| CounterTack.Behavior.ReportedOn | Date | The time that the behavior was first seen. | 
| CounterTack.Behavior.EventCount | Number | The number of events detected. | 
| CounterTack.Behavior.TimeStamp | Date | The start time for the behavior. | 
| CounterTack.Behavior.Type | String | The type of behavior \(CLASSIFICATION, TRACE\) | 
| CounterTack.Behavior.Id | String | The ID of the behaviors. | 
| CounterTack.Behavior.LastActive | Date | The time that the behavior was last active. | 
| CounterTack.Behavior.ImpactLevel | String | The threat level of the behavior \(LOW, MEDIUM, HIGH, CRITICAL\). | 