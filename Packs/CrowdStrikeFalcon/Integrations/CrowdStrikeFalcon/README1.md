The CrowdStrike Falcon OAuth 2 API (formerly the Falcon Firehose API), enables fetching and resolving detections, searching devices, getting behaviors by ID, containing hosts, and lifting host containment.
This integration was integrated and tested with version xx of CrowdstrikeFalcon

## Configure CrowdStrike Falcon on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CrowdStrike Falcon.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://api.crowdstrike.com) |  | True |
    | Client ID |  | False |
    | Secret |  | False |
    | Client ID |  | False |
    | Secret |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. Currently used for “CVE” reputation  command. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Max incidents per fetch |  | False |
    | Detections fetch query |  | False |
    | Incidents fetch query |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Mirroring Direction | Choose the direction to mirror the detection: Incoming \(from CrowdStrike Falcon to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to CrowdStrike Falcon\), or Incoming and Outgoing \(to/from CrowdStrike Falcon and Cortex XSOAR\). | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Close Mirrored XSOAR Incident | When selected, closes the CrowdStrike Falcon incident or detection, which is mirrored in the Cortex XSOAR incident. | False |
    | Close Mirrored CrowdStrike Falcon Incident or Detection | When selected, closes the Cortex XSOAR incident, which is mirrored in the CrowdStrike Falcon incident or detection, according to the types that were chosen to be fetched and mirrored. | False |
    | Fetch types | Choose what to fetch - incidents, detections, or both. | False |
    | Incidents Fetch Interval |  | False |
    | Advanced: Time in minutes to look back when fetching incidents and detections | Use this parameter to determine how long backward to look in the search for incidents that were created before the last run time and did not match the query when they were created. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cs-falcon-search-device

***
Searches for a device that matches the query.

#### Base Command

`cs-falcon-search-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The query to filter the device. | Optional | 
| ids | A comma-separated list of device IDs to limit the results. | Optional | 
| status | The status of the device. Possible values are: "Normal", "containment_pending", "contained", and "lift_containment_pending". Possible values are: normal, containment_pending, contained, lift_containment_pending. | Optional | 
| hostname | The host name of the device. Possible values are: . | Optional | 
| platform_name | The platform name of the device. Possible values are: Windows, Mac, and Linux. Possible values are: Windows, Mac, Linux. | Optional | 
| site_name | The site name of the device. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Device.ID | String | The ID of the device. | 
| CrowdStrike.Device.LocalIP | String | The local IP address of the device. | 
| CrowdStrike.Device.ExternalIP | String | The external IP address of the device. | 
| CrowdStrike.Device.Hostname | String | The host name of the device. | 
| CrowdStrike.Device.OS | String | The operating system of the device. | 
| CrowdStrike.Device.MacAddress | String | The MAC address of the device. | 
| CrowdStrike.Device.FirstSeen | String | The first time the device was seen. | 
| CrowdStrike.Device.LastSeen | String | The last time the device was seen. | 
| CrowdStrike.Device.PolicyType | String | The policy type of the device. | 
| CrowdStrike.Device.Status | String | The device status. | 
| Endpoint.Hostname | String | The endpoint hostname. | 
| Endpoint.OS | String | The endpoint operation system. | 
| Endpoint.IPAddress | String | The endpoint IP address. | 
| Endpoint.ID | String | The endpoint ID. | 
| Endpoint.Status | String | The endpoint status. | 
| Endpoint.IsIsolated | String | The endpoint isolation status. | 
| Endpoint.MACAddress | String | The endpoint MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 
| Endpoint.OSVersion | String | The endpoint operation system version. | 

### cs-falcon-get-behavior

***
Searches for and fetches the behavior that matches the query.

#### Base Command

`cs-falcon-get-behavior`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| behavior_id | The ID of the behavior. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Behavior.FileName | String | The file name of the behavior. | 
| CrowdStrike.Behavior.Scenario | String | The scenario name of the behavior. | 
| CrowdStrike.Behavior.MD5 | String | The MD5 hash of the IOC in the behavior. | 
| CrowdStrike.Behavior.SHA256 | String | The SHA256 hash of the IOC in the behavior. | 
| CrowdStrike.Behavior.IOCType | String | The type of the indicator of compromise. | 
| CrowdStrike.Behavior.IOCValue | String | The value of the IOC. | 
| CrowdStrike.Behavior.CommandLine | String | The command line executed in the behavior. | 
| CrowdStrike.Behavior.UserName | String | The user name related to the behavior. | 
| CrowdStrike.Behavior.SensorID | String | The sensor ID related to the behavior. | 
| CrowdStrike.Behavior.ParentProcessID | String | The ID of the parent process. | 
| CrowdStrike.Behavior.ProcessID | String | The process ID of the behavior. | 
| CrowdStrike.Behavior.ID | String | The ID of the behavior. | 

### cs-falcon-search-detection

***
Search for details of specific detections, either using a filter query, or by providing the IDs of the detections.

#### Base Command

`cs-falcon-search-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the detections to search. If provided, will override other arguments. | Optional | 
| filter | Filter detections using a query in Falcon Query Language (FQL).<br/>For example, filter="device.hostname:'CS-SE-TG-W7-01'"<br/>For a full list of valid filter options, see: https://falcon.crowdstrike.com/support/documentation/2/query-api-reference#detectionsearch. | Optional | 
| extended_data | Whether to get additional data such as device and behaviors processed. Possible values are: Yes, No. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Detection.Behavior.FileName | String | The file name of the behavior. | 
| CrowdStrike.Detection.Behavior.Scenario | String | The scenario name of the behavior. | 
| CrowdStrike.Detection.Behavior.MD5 | String | The MD5 hash of the IOC of the behavior. | 
| CrowdStrike.Detection.Behavior.SHA256 | String | The SHA256 hash of the IOC of the behavior. | 
| CrowdStrike.Detection.Behavior.IOCType | String | The type of the IOC. | 
| CrowdStrike.Detection.Behavior.IOCValue | String | The value of the IOC. | 
| CrowdStrike.Detection.Behavior.CommandLine | String | The command line executed in the behavior. | 
| CrowdStrike.Detection.Behavior.UserName | String | The user name related to the behavior. | 
| CrowdStrike.Detection.Behavior.SensorID | String | The sensor ID related to the behavior. | 
| CrowdStrike.Detection.Behavior.ParentProcessID | String | The ID of the parent process. | 
| CrowdStrike.Detection.Behavior.ProcessID | String | The process ID of the behavior. | 
| CrowdStrike.Detection.Behavior.ID | String | The ID of the behavior. | 
| CrowdStrike.Detection.System | String | The system name of the detection. | 
| CrowdStrike.Detection.CustomerID | String | The ID of the customer \(CID\). | 
| CrowdStrike.Detection.MachineDomain | String | The name of the domain of the detection machine. | 
| CrowdStrike.Detection.ID | String | The detection ID. | 
| CrowdStrike.Detection.ProcessStartTime | Date | The start time of the process that generated the detection. | 

### cs-falcon-resolve-detection

***
Resolves and updates a detection using the provided arguments. At least one optional argument must be passed, otherwise no change will take place.

#### Base Command

`cs-falcon-resolve-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of one or more IDs to resolve. | Required | 
| status | The status to transition a detection to. Possible values: "new", "in_progress", "true_positive", "false_positive", "closed", "reopened" and "ignored". Possible values are: new, in_progress, true_positive, false_positive, closed, reopened, ignored. | Optional | 
| assigned_to_uuid | A user ID, for example: 1234567891234567891. username and assigned_to_uuid are mutually exclusive. | Optional | 
| comment | Optional comment to add to the detection. Comments are displayed with the detection in CrowdStrike Falcon and provide context or notes for other Falcon users. | Optional | 
| show_in_ui | If true, displays the detection in the UI. Possible values are: true, false. | Optional | 
| username | Username to assign the detections to. (This is usually the user’s email address, but may vary based on your configuration). username and assigned_to_uuid are mutually exclusive. | Optional | 

#### Context Output

There is no context output for this command.
### cs-falcon-contain-host

***
Contains containment for a specified host. When contained, a host can only communicate with the CrowdStrike cloud and any IPs specified in your containment policy.

#### Base Command

`cs-falcon-contain-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The host agent ID (AID) of the host to contain. Get an agent ID from a detection. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-lift-host-containment

***
Lifts containment on the host, which returns its network communications to normal.

#### Base Command

`cs-falcon-lift-host-containment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The host agent ID (AID) of the host you want to contain. Get an agent ID from a detection. Can also be a comma separated list of IDs. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-run-command

***
Sends commands to hosts.

#### Base Command

`cs-falcon-run-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_offline | Any commands run against an offline-queued session will be queued up and executed when the host comes online. | Optional | 
| host_ids | A comma-separated list of host agent IDs to run commands for. (Can be retrieved by running the 'cs-falcon-search-device' command.). | Required | 
| command_type | The type of command to run. | Required | 
| full_command | The full command to run. | Required | 
| scope | The scope to run the command for. Possible values are: "read", "write", and "admin". (NOTE: In order to run the CrowdStrike RTR `put` command, it is necessary to pass `scope=admin`.). Possible values are: read, write, admin. Default is read. | Optional | 
| target | The target to run the command for. Possible values are: "single" and "batch". Possible values are: batch, single. Default is batch. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | String | The ID of the host the command was running for. | 
| CrowdStrike.Command.SessionID | string | The session ID of the host. | 
| CrowdStrike.Command.Stdout | String | The standard output of the command. | 
| CrowdStrike.Command.Stderr | String | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | String | The base command. | 
| CrowdStrike.Command.FullCommand | String | The full command. | 
| CrowdStrike.Command.TaskID | string | \(For single host\) The ID of the command request which has been accepted. | 
| CrowdStrike.Command.Complete | boolean | \(For single host\) True if the command completed. | 
| CrowdStrike.Command.NextSequenceID | number | \(For single host\) The next sequence ID. | 

### cs-falcon-upload-script

***
Uploads a script to Falcon.

#### Base Command

`cs-falcon-upload-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The script name to upload. | Required | 
| permission_type | The permission type for the custom script. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. Possible values are: private, group, public. Default is private. | Optional | 
| content | The content of the PowerShell script. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-upload-file

***
Uploads a file to the CrowdStrike cloud. (Can be used for the RTR 'put' command.)

#### Base Command

`cs-falcon-upload-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The file entry ID to upload. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-delete-file

***
Deletes a file based on the provided ID. Can delete only one file at a time.

#### Base Command

`cs-falcon-delete-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The ID of the file to delete. (The ID of the file can be retrieved by running the 'cs-falcon-list-files' command). | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-get-file

***
Returns files based on the provided IDs. These files are used for the RTR 'put' command.

#### Base Command

`cs-falcon-get-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | A comma-separated list of file IDs to get. (The list of file IDs can be retrieved by running the 'cs-falcon-list-files' command.). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.ID | String | The ID of the file. | 
| CrowdStrike.File.CreatedBy | String | The email address of the user who created the file. | 
| CrowdStrike.File.CreatedTime | Date | The date and time the file was created. | 
| CrowdStrike.File.Description | String | The description of the file. | 
| CrowdStrike.File.Type | String | The type of the file. For example, script. | 
| CrowdStrike.File.ModifiedBy | String | The email address of the user who modified the file. | 
| CrowdStrike.File.ModifiedTime | Date | The date and time the file was modified. | 
| CrowdStrike.File.Name | String | The full name of the file. | 
| CrowdStrike.File.Permission | String | The permission type of the file. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins | 
| CrowdStrike.File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Type | String | The file type. | 
| File.Name | String | The full name of the file. | 
| File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Size | Number | The size of the file in bytes. | 

### cs-falcon-list-files

***
Returns a list of put-file IDs that are available for the user in the 'put' command.

#### Base Command

`cs-falcon-list-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.ID | String | The ID of the file. | 
| CrowdStrike.File.CreatedBy | String | The email address of the user who created the file. | 
| CrowdStrike.File.CreatedTime | Date | The date and time the file was created. | 
| CrowdStrike.File.Description | String | The description of the file. | 
| CrowdStrike.File.Type | String | The type of the file. For example, script. | 
| CrowdStrike.File.ModifiedBy | String | The email address of the user who modified the file. | 
| CrowdStrike.File.ModifiedTime | Date | The date and time the file was modified. | 
| CrowdStrike.File.Name | String | The full name of the file. | 
| CrowdStrike.File.Permission | String | The permission type of the file. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | 
| CrowdStrike.File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Type | String | The file type. | 
| File.Name | String | The full name of the file. | 
| File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Size | Number | The size of the file in bytes. | 

### cs-falcon-get-script

***
Returns custom scripts based on the provided ID. Used for the RTR 'runscript' command.

#### Base Command

`cs-falcon-get-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | A comma-separated list of script IDs to return. (The script IDs can be retrieved by running the 'cs-falcon-list-scripts' command.). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Script.ID | String | The ID of the script. | 
| CrowdStrike.Script.CreatedBy | String | The email address of the user who created the script. | 
| CrowdStrike.Script.CreatedTime | Date | The date and time the script was created. | 
| CrowdStrike.Script.Description | String | The description of the script. | 
| CrowdStrike.Script.ModifiedBy | String | The email address of the user who modified the script. | 
| CrowdStrike.Script.ModifiedTime | Date | The date and time the script was modified. | 
| CrowdStrike.Script.Name | String | The script name. | 
| CrowdStrike.Script.Permission | String | Permission type of the script. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | 
| CrowdStrike.Script.SHA256 | String | The SHA-256 hash of the script file. | 
| CrowdStrike.Script.RunAttemptCount | Number | The number of times the script attempted to run. | 
| CrowdStrike.Script.RunSuccessCount | Number | The number of times the script ran successfully. | 
| CrowdStrike.Script.Platform | String | The list of operating system platforms on which the script can run. For example, Windows. | 
| CrowdStrike.Script.WriteAccess | Boolean | Whether the user has write access to the script. | 

### cs-falcon-delete-script

***
Deletes a custom-script based on the provided ID. Can delete only one script at a time.

#### Base Command

`cs-falcon-delete-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | The script ID to delete. (Script IDs can be retrieved by running the 'cs-falcon-list-scripts' command.). | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-list-scripts

***
Returns a list of custom script IDs that are available for the user in the 'runscript' command.

#### Base Command

`cs-falcon-list-scripts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Script.ID | String | The ID of the script. | 
| CrowdStrike.Script.CreatedBy | String | The email address of the user who created the script. | 
| CrowdStrike.Script.CreatedTime | Date | The date and time the script was created. | 
| CrowdStrike.Script.Description | String | The description of the script. | 
| CrowdStrike.Script.ModifiedBy | String | The email address of the user who modified the script. | 
| CrowdStrike.Script.ModifiedTime | Date | The date and time the script was modified. | 
| CrowdStrike.Script.Name | String | The script name. | 
| CrowdStrike.Script.Permission | String | Permission type of the script. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | 
| CrowdStrike.Script.SHA256 | String | The SHA-256 hash of the script file. | 
| CrowdStrike.Script.RunAttemptCount | Number | The number of times the script attempted to run. | 
| CrowdStrike.Script.RunSuccessCount | Number | The number of times the script ran successfully. | 
| CrowdStrike.Script.Platform | String | The list of operating system platforms on which the script can run. For example, Windows. | 
| CrowdStrike.Script.WriteAccess | Boolean | Whether the user has write access to the script. | 

### cs-falcon-run-script

***
Runs a script on the agent host.

#### Base Command

`cs-falcon-run-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_name | The name of the script to run. | Optional | 
| host_ids | A comma-separated list of host agent IDs to run commands. (The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command.). | Required | 
| raw | The PowerShell script code to run. | Optional | 
| timeout | Timeout for how long to wait for the request in seconds. Maximum is 600 (10 minutes). Default is 30. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | String | The ID of the host for which the command was running. | 
| CrowdStrike.Command.SessionID | String | The ID of the session of the host. | 
| CrowdStrike.Command.Stdout | String | The standard output of the command. | 
| CrowdStrike.Command.Stderr | String | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | String | The base command. | 
| CrowdStrike.Command.FullCommand | String | The full command. | 

### cs-falcon-run-get-command

***
Batch executes 'get' command across hosts to retrieve files.

#### Base Command

`cs-falcon-run-get-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | List of host agent IDs on which to run the RTR command. | Required | 
| file_path | Full path to the file that will be retrieved from each host in the batch. | Required | 
| optional_hosts | List of a subset of hosts on which to run the command. | Optional | 
| timeout | The number of seconds to wait for the request before it times out. In ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | Optional | 
| timeout_duration | The amount of time to wait for the request before it times out. In duration syntax. For example, 10s. Valid units are: ns, us, ms, s, m, h. Maximum value is 10 minutes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host on which the command was running. | 
| CrowdStrike.Command.Stdout | string | The standard output of the command. | 
| CrowdStrike.Command.Stderr | string | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | string | The base command. | 
| CrowdStrike.Command.TaskID | string | The ID of the command that was running on the host. | 
| CrowdStrike.Command.GetRequestID | string | The ID of the command request that was accepted. | 
| CrowdStrike.Command.Complete | boolean | True if the command completed. | 
| CrowdStrike.Command.FilePath | string | The file path. | 

### cs-falcon-status-get-command

***
Retrieves the status of the specified batch 'get' command.

#### Base Command

`cs-falcon-status-get-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_ids | The list of IDs of the command requested. | Required | 
| timeout | The number of seconds to wait for the request before it times out. In ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | Optional | 
| timeout_duration | The amount of time to wait for the request before it times out. In duration syntax. For example, 10s. Valid units are: ns, us, ms, s, m, h. Maximum value is 10 minutes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.ID | string | The ID of the file. | 
| CrowdStrike.File.TaskID | string | The ID of the command that is running. | 
| CrowdStrike.File.CreatedAt | date | The date the file was created. | 
| CrowdStrike.File.DeletedAt | date | The date the file was deleted. | 
| CrowdStrike.File.UpdatedAt | date | The date the file was last updated. | 
| CrowdStrike.File.Name | string | The full name of the file. | 
| CrowdStrike.File.SHA256 | string | The SHA256 hash of the file. | 
| CrowdStrike.File.Size | number | The size of the file in bytes. | 
| File.Name | string | The full name of the file. | 
| File.Size | number | The size of the file in bytes. | 
| File.SHA256 | string | The SHA256 hash of the file. | 

### cs-falcon-status-command

***
Gets the status of a command executed on a host.

#### Base Command

`cs-falcon-status-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The ID of the command requested. | Required | 
| sequence_id | The sequence ID in chunk requests. | Optional | 
| scope | The scope to run the command for. Possible values are: "read", "write", or "admin". Possible values are: read, write, admin. Default is read. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.TaskID | string | The ID of the command request that was accepted. | 
| CrowdStrike.Command.Stdout | string | The standard output of the command. | 
| CrowdStrike.Command.Stderr | string | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | string | The base command. | 
| CrowdStrike.Command.Complete | boolean | True if the command completed. | 
| CrowdStrike.Command.SequenceID | number | The sequence ID in the current request. | 
| CrowdStrike.Command.NextSequenceID | number | The sequence ID for the next request in the chunk request. | 

### cs-falcon-get-extracted-file

***
Gets the RTR extracted file contents for the specified session and SHA256 hash.

#### Base Command

`cs-falcon-get-extracted-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host agent ID. | Required | 
| sha256 | The SHA256 hash of the file. | Required | 
| filename | The filename to use for the archive name and the file within the archive. | Optional | 

#### Context Output

There is no context output for this command.
### cs-falcon-list-host-files

***
Gets a list of files for the specified RTR session on a host.

#### Base Command

`cs-falcon-list-host-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The ID of the host agent that lists files in the session. | Required | 
| session_id | The ID of the existing session with the agent. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host the command was running for. | 
| CrowdStrike.Command.TaskID | string | The ID of the command request that was accepted. | 
| CrowdStrike.Command.SessionID | string | The ID of the session of the host. | 
| CrowdStrike.File.ID | string | The ID of the file. | 
| CrowdStrike.File.CreatedAt | date | The date the file was created. | 
| CrowdStrike.File.DeletedAt | date | The date the file was deleted. | 
| CrowdStrike.File.UpdatedAt | date | The date the file was last updated. | 
| CrowdStrike.File.Name | string | The full name of the file. | 
| CrowdStrike.File.SHA256 | string | The SHA256 hash of the file. | 
| CrowdStrike.File.Size | number | The size of the file in bytes. | 
| File.Name | string | The full name of the file. | 
| File.Size | number | The size of the file in bytes. | 
| File.SHA256 | string | The SHA256 hash of the file. | 

### cs-falcon-refresh-session

***
Refresh a session timeout on a single host.

#### Base Command

`cs-falcon-refresh-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The ID of the host to extend the session for. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-search-custom-iocs

***
Returns a list of your uploaded IOCs that match the search criteria.

#### Base Command

`cs-falcon-search-custom-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| types | A comma-separated list of indicator types. Valid types are: "sha256", "sha1", "md5", "domain", "ipv4", "ipv6". Possible values are: sha256, sha1, md5, domain, ipv4, ipv6. | Optional | 
| values | A comma-separated list of indicator values. | Optional | 
| sources | A comma-separated list of IOC sources. | Optional | 
| expiration | The date the indicator will become inactive (ISO 8601 format, i.e. YYYY-MM-DDThh:mm:ssZ). | Optional | 
| limit | The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 50. | Optional | 
| sort | The order the results are returned in. Possible values are: "type.asc", "type.desc", "value.asc", "value.desc", "policy.asc", "policy.desc", "share_level.asc", "share_level.desc", "expiration_timestamp.asc", and "expiration_timestamp.desc". Possible values are: type.asc, type.desc, value.asc, value.desc, policy.asc, policy.desc, share_level.asc, share_level.desc, expiration_timestamp.asc, expiration_timestamp.desc. | Optional | 
| offset | The offset to begin the list from. For example, start from the 10th record and return the list. | Optional | 
| next_page_token | A pagination token used with the limit parameter to manage pagination of results. Matching the 'after' parameter in the API. Use instead of offset. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | Action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | string | The datetime the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 
| CrowdStrike.NextPageToken | unknown | A pagination token used with the limit parameter to manage pagination of results | 

### cs-falcon-get-custom-ioc

***
Gets the full definition of one or more indicators that you are watching.

#### Base Command

`cs-falcon-get-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type to retrieve. Possible values are: "sha256", "sha1", "md5", "domain", "ipv4", and "ipv6". Either ioc_id or ioc_type and value must be provided. Possible values are: sha256, sha1, md5, domain, ipv4, ipv6. | Optional | 
| value | The string representation of the indicator. Either ioc_id or ioc_type and value must be provided. | Optional | 
| ioc_id | The ID of the IOC to get. Can be retrieved by running the cs-falcon-search-custom-iocs command. Either ioc_id or ioc_type and value must be provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | Action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | string | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 

### cs-falcon-upload-custom-ioc

***
Uploads an indicator for CrowdStrike to monitor.

#### Base Command

`cs-falcon-upload-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | The type of the indicator. Possible values are: "sha256", "md5", "domain", "ipv4", and "ipv6". Possible values are: sha256, md5, domain, ipv4, ipv6. | Required | 
| value | A comma separated list of indicators.<br/>More than one value can be supplied to upload multiple IOCs of the same type but with different values. Note that the uploaded IOCs will have the same properties (as supplied in other arguments). | Required | 
| action | Action to take when a host observes the custom IOC. Possible values are: no_action - Save the indicator for future use, but take no action. No severity required. allow - Applies to hashes only. Allow the indicator and do not detect it. Severity does not apply and should not be provided. prevent_no_ui - Applies to hashes only. Block and detect the indicator, but hide it from Activity &gt; Detections. Has a default severity value. prevent - Applies to hashes only. Block the indicator and show it as a detection at the selected severity. detect - Enable detections for the indicator at the selected severity. Possible values are: no_action, allow, prevent_no_ui, prevent, detect. | Required | 
| platforms | The platforms that the indicator applies to. You can enter multiple platform names, separated by commas. Possible values are: mac, windows and linux. Possible values are: mac, windows, linux. | Required | 
| severity | The severity level to apply to this indicator. Required for the prevent and detect actions. Optional for no_action. Possible values are: informational, low, medium, high, and critical. Possible values are: informational, low, medium, high, critical. | Optional | 
| expiration | The date the indicator will become inactive (ISO 8601 format, i.e. YYYY-MM-DDThh:mm:ssZ). | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 
| applied_globally | Whether the indicator is applied globally. Either applied_globally or host_groups must be provided. Possible values are: true, false. | Optional | 
| host_groups | List of host group IDs that the indicator applies to. Can be retrieved by running the cs-falcon-list-host-groups command. Either applied_globally or host_groups must be provided. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | Action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | string | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 
| CrowdStrike.IOC.Tags | Unknown | The tags of the IOC. | 
| CrowdStrike.IOC.Platforms | Unknown | The platforms of the IOC. | 

### cs-falcon-update-custom-ioc

***
Updates an indicator for CrowdStrike to monitor.

#### Base Command

`cs-falcon-update-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_id | The ID of the IOC to update. Can be retrieved by running the cs-falcon-search-custom-iocs command. | Required | 
| action | Action to take when a host observes the custom IOC. Possible values are: no_action - Save the indicator for future use, but take no action. No severity required. allow - Applies to hashes only. Allow the indicator and do not detect it. Severity does not apply and should not be provided. prevent_no_ui - Applies to hashes only. Block and detect the indicator, but hide it from Activity &gt; Detections. Has a default severity value. prevent - Applies to hashes only. Block the indicator and show it as a detection at the selected severity. detect - Enable detections for the indicator at the selected severity. Possible values are: no_action, allow, prevent_no_ui, prevent, detect. | Optional | 
| platforms | The platforms that the indicator applies to. You can enter multiple platform names, separated by commas. Possible values are: mac, windows and linux. Possible values are: mac, windows, linux. | Optional | 
| severity | The severity level to apply to this indicator. Required for the prevent and detect actions. Optional for no_action. Possible values are: informational, low, medium, high and critical. Possible values are: informational, low, medium, high, critical. | Optional | 
| expiration | The date the indicator will become inactive (ISO 8601 format, i.e. YYYY-MM-DDThh:mm:ssZ). | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | Action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | string | The datetime when the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 

### cs-falcon-delete-custom-ioc

***
Deletes a monitored indicator.

#### Base Command

`cs-falcon-delete-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_id | The ID of the IOC to delete. Can be retrieved by running the cs-falcon-search-custom-iocs command. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-device-count-ioc

***
The number of hosts that observed the provided IOC.

#### Base Command

`cs-falcon-device-count-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type. Possible values are: "sha256", "sha1", "md5", "domain", "ipv4", and "ipv6". Possible values are: sha256, sha1, md5, domain, ipv4, ipv6. | Required | 
| value | The string representation of the indicator. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator \(type:value\). | 
| CrowdStrike.IOC.DeviceCount | number | The number of devices the IOC ran on. | 

### cs-falcon-processes-ran-on

***
Get processes associated with a given IOC.

#### Base Command

`cs-falcon-processes-ran-on`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type. Possible values are: "sha256", "sha1", "md5", "domain", "ipv4", and "ipv6". Possible values are: sha256, sha1, md5, domain, ipv4, ipv6. | Required | 
| value | The string representation of the indicator. | Required | 
| device_id | The device ID to check against. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator \(type:value\). | 
| CrowdStrike.IOC.Process.ID | number | The processes IDs associated with the given IOC. | 
| CrowdStrike.IOC.Process.DeviceID | number | The device the process ran on. | 

### cs-falcon-process-details

***
Retrieves the details of a process, according to the process ID that is running or that previously ran.

#### Base Command

`cs-falcon-process-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of process IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Process.process_id | String | The process ID. | 
| CrowdStrike.Process.process_id_local | String | Local ID of the process. | 
| CrowdStrike.Process.device_id | String | The device the process ran on. | 
| CrowdStrike.Process.file_name | String | The path of the file that ran the process. | 
| CrowdStrike.Process.command_line | String | The command line command execution. | 
| CrowdStrike.Process.start_timestamp_raw | String | The start datetime of the process in Unix time format. For example: 132460167512852140. | 
| CrowdStrike.Process.start_timestamp | String | The start datetime of the process in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Process.stop_timestamp_raw | Date | The stop datetime of the process in Unix time format. For example: 132460167512852140. | 
| CrowdStrike.Process.stop_timestamp | Date | The stop datetime of the process in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 

### cs-falcon-device-ran-on

***
Returns a list of device IDs an indicator ran on.

#### Base Command

`cs-falcon-device-ran-on`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of indicator. Possible values are: "domain", "ipv4", "ipv6", "md5", "sha1", or "sha256". Possible values are: domain, ipv4, ipv6, md5, sha1, sha256. | Required | 
| value | The string representation of the indicator. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.DeviceID | string | Device IDs an indicator ran on. | 

### cs-falcon-list-detection-summaries

***
Lists detection summaries.

#### Base Command

`cs-falcon-list-detection-summaries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fetch_query | The query used to filter the results. | Optional | 
| ids | A comma separated list of detection IDs. For example, ldt:1234:1234,ldt:5678:5678, If you use this argument, fetch_query argument will be ignored. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Detections.cid | String | The organization's customer ID \(CID\). | 
| CrowdStrike.Detections.created_timestamp | Date | The datetime the detection occurred in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Detections.detection_id | String | The ID of the detection. | 
| CrowdStrike.Detections.device.device_id | String | The device ID as seen by CrowdStrike Falcon. | 
| CrowdStrike.Detections.device.cid | String | The CrowdStrike Customer ID \(CID\) to which the device belongs. | 
| CrowdStrike.Detections.device.agent_load_flags | String | The CrowdStrike Falcon agent load flags. | 
| CrowdStrike.Detections.device.agent_local_time | Date | The local time of the sensor. | 
| CrowdStrike.Detections.device.agent_version | String | The version of the agent that the device is running. For example: 5.32.11406.0. | 
| CrowdStrike.Detections.device.bios_manufacturer | String | The BIOS manufacturer. | 
| CrowdStrike.Detections.device.bios_version | String | The device's BIOS version. | 
| CrowdStrike.Detections.device.config_id_base | String | The base of the sensor that the device is running. | 
| CrowdStrike.Detections.device.config_id_build | String | The version of the sensor that the device is running. For example: 11406. | 
| CrowdStrike.Detections.device.config_id_platform | String | The platform ID of the sensor that the device is running. | 
| CrowdStrike.Detections.device.external_ip | String | The external IP address of the device. | 
| CrowdStrike.Detections.device.hostname | String | The host name of the device. | 
| CrowdStrike.Detections.device.first_seen | Date | The datetime the host was first seen by CrowdStrike Falcon. | 
| CrowdStrike.Detections.device.last_seen | Date | The datetime the host was last seen by CrowdStrike Falcon. | 
| CrowdStrike.Detections.device.local_ip | String | The local IP address of the device. | 
| CrowdStrike.Detections.device.mac_address | String | The MAC address of the device. | 
| CrowdStrike.Detections.device.major_version | String | The major version of the operating system. | 
| CrowdStrike.Detections.device.minor_version | String | The minor version of the operating system. | 
| CrowdStrike.Detections.device.os_version | String | The operating system of the device. | 
| CrowdStrike.Detections.device.platform_id | String | The platform ID of the device that runs the sensor. | 
| CrowdStrike.Detections.device.platform_name | String | The platform name of the device. | 
| CrowdStrike.Detections.device.product_type_desc | String | The value indicating the product type. For example, 1 = Workstation, 2 = Domain Controller, 3 = Server. | 
| CrowdStrike.Detections.device.status | String | The containment status of the machine. Possible values are: "normal", "containment_pending", "contained", and "lift_containment_pending". | 
| CrowdStrike.Detections.device.system_manufacturer | String | The system manufacturer of the device. | 
| CrowdStrike.Detections.device.system_product_name | String | The product name of the system. | 
| CrowdStrike.Detections.device.modified_timestamp | Date | The datetime the device was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Detections.behaviors.device_id | String | The ID of the device associated with the behavior. | 
| CrowdStrike.Detections.behaviors.timestamp | Date | The datetime the behavior detection occurred in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Detections.behaviors.behavior_id | String | The ID of the behavior. | 
| CrowdStrike.Detections.behaviors.filename | String | The file name of the triggering process. | 
| CrowdStrike.Detections.behaviors.alleged_filetype | String | The file extension of the behavior's filename. | 
| CrowdStrike.Detections.behaviors.cmdline | String | The command line of the triggering process. | 
| CrowdStrike.Detections.behaviors.scenario | String | The name of the scenario the behavior belongs to. | 
| CrowdStrike.Detections.behaviors.objective | String | The name of the objective associated with the behavior. | 
| CrowdStrike.Detections.behaviors.tactic | String | The name of the tactic associated with the behavior. | 
| CrowdStrike.Detections.behaviors.technique | String | The name of the technique associated with the behavior. | 
| CrowdStrike.Detections.behaviors.severity | Number | The severity rating for the behavior. The value can be any integer between 1-100. | 
| CrowdStrike.Detections.behaviors.confidence | Number | The true positive confidence rating for the behavior. The value can be any integer between 1-100. | 
| CrowdStrike.Detections.behaviors.ioc_type | String | The type of the triggering IOC. Possible values are: "hash_sha256", "hash_md5", "domain", "filename", "registry_key", "command_line", and "behavior". | 
| CrowdStrike.Detections.behaviors.ioc_value | String | The IOC value. | 
| CrowdStrike.Detections.behaviors.ioc_source | String | The source that triggered an IOC detection. Possible values are: "library_load", "primary_module", "file_read", and "file_write". | 
| CrowdStrike.Detections.behaviors.ioc_description | String | The IOC description. | 
| CrowdStrike.Detections.behaviors.user_name | String | The user name. | 
| CrowdStrike.Detections.behaviors.user_id | String | The Security Identifier \(SID\) of the user in Windows. | 
| CrowdStrike.Detections.behaviors.control_graph_id | String | The behavior hit key for the Threat Graph API. | 
| CrowdStrike.Detections.behaviors.triggering_process_graph_id | String | The ID of the process that triggered the behavior detection. | 
| CrowdStrike.Detections.behaviors.sha256 | String | The SHA256 of the triggering process. | 
| CrowdStrike.Detections.behaviors.md5 | String | The MD5 of the triggering process. | 
| CrowdStrike.Detections.behaviors.parent_details.parent_sha256 | String | The SHA256 hash of the parent process. | 
| CrowdStrike.Detections.behaviors.parent_details.parent_md5 | String | The MD5 hash of the parent process. | 
| CrowdStrike.Detections.behaviors.parent_details.parent_cmdline | String | The command line of the parent process. | 
| CrowdStrike.Detections.behaviors.parent_details.parent_process_graph_id | String | The process graph ID of the parent process. | 
| CrowdStrike.Detections.behaviors.pattern_disposition | Number | The pattern associated with the action performed on the behavior. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.indicator | Boolean | Whether the detection behavior is similar to an indicator. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.detect | Boolean | Whether this behavior is detected. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.inddet_mask | Boolean | Whether this behavior is an inddet mask. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.sensor_only | Boolean | Whether this detection is sensor only. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.rooting | Boolean | Whether this behavior is rooting. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.kill_process | Boolean | Whether this detection kills the process. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.kill_subprocess | Boolean | Whether this detection kills the subprocess. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.quarantine_machine | Boolean | Whether this detection was on a quarantined machine. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.quarantine_file | Boolean | Whether this detection was on a quarantined file. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.policy_disabled | Boolean | Whether this policy is disabled. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.kill_parent | Boolean | Whether this detection kills the parent process. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.operation_blocked | Boolean | Whether the operation is blocked. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.process_blocked | Boolean | Whether the process is blocked. | 
| CrowdStrike.Detections.behaviors.pattern_disposition_details.registry_operation_blocked | Boolean | Whether the registry operation is blocked. | 
| CrowdStrike.Detections.email_sent | Boolean | Whether an email is sent about this detection. | 
| CrowdStrike.Detections.first_behavior | Date | The datetime of the first behavior. | 
| CrowdStrike.Detections.last_behavior | Date | The datetime of the last behavior. | 
| CrowdStrike.Detections.max_confidence | Number | The highest confidence value of all behaviors. The value can be any integer between 1-100. | 
| CrowdStrike.Detections.max_severity | Number | The highest severity value of all behaviors. Value can be any integer between 1-100. | 
| CrowdStrike.Detections.max_severity_displayname | String | The name used in the UI to determine the severity of the detection. Possible values are: "Critical", "High", "Medium", and "Low". | 
| CrowdStrike.Detections.show_in_ui | Boolean | Whether the detection displays in the UI. | 
| CrowdStrike.Detections.status | String | The status of the detection. | 
| CrowdStrike.Detections.assigned_to_uid | String | The UID of the user for whom the detection is assigned. | 
| CrowdStrike.Detections.assigned_to_name | String | The human-readable name of the user to whom the detection is currently assigned. | 
| CrowdStrike.Detections.hostinfo.domain | String | The domain of the Active Directory. | 
| CrowdStrike.Detections.seconds_to_triaged | Number | The amount of time it took to move a detection from "new" to "in_progress". | 
| CrowdStrike.Detections.seconds_to_resolved | Number | The amount of time it took to move a detection from new to a resolved state \("true_positive", "false_positive", and "ignored"\). | 

### cs-falcon-list-incident-summaries

***
Lists incident summaries.

#### Base Command

`cs-falcon-list-incident-summaries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fetch_query | The query used to filter the results. | Optional | 
| ids | A comma separated list of detection IDs. For example, ldt:1234:1234,ldt:5678:5678, If you use this argument, fetch_query argument will be ignored. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Incidents.incident_id | String | The ID of the incident. | 
| CrowdStrike.Incidents.cid | String | The organization's customer ID \(CID\). | 
| CrowdStrike.Incidents.host_ids | String | The device IDs of all the hosts on which the incident occurred. | 
| CrowdStrike.Incidents.hosts.device_id | String | The device ID as seen by CrowdStrike. | 
| CrowdStrike.Incidents.hosts.cid | String | The host's organization's customer ID \(CID\). | 
| CrowdStrike.Incidents.hosts.agent_load_flags | String | The CrowdStrike agent load flags. | 
| CrowdStrike.Incidents.hosts.agent_local_time | Date | The local time of the sensor. | 
| CrowdStrike.Incidents.hosts.agent_version | String | The version of the agent that the device is running. For example: 5.32.11406.0. | 
| CrowdStrike.Incidents.hosts.bios_manufacturer | String | The BIOS manufacturer. | 
| CrowdStrike.Incidents.hosts.bios_version | String | The BIOS version of the device. | 
| CrowdStrike.Incidents.hosts.config_id_base | String | The base of the sensor that the device is running. | 
| CrowdStrike.Incidents.hosts.config_id_build | String | The version of the sensor that the device is running. For example: 11406. | 
| CrowdStrike.Incidents.hosts.config_id_platform | String | The platform ID of the sensor that the device is running. | 
| CrowdStrike.Incidents.hosts.external_ip | String | The external IP address of the host. | 
| CrowdStrike.Incidents.hosts.hostname | String | The name of the host. | 
| CrowdStrike.Incidents.hosts.first_seen | Date | The date and time the host was first seen by CrowdStrike Falcon. | 
| CrowdStrike.Incidents.hosts.last_seen | Date | The date and time the host was last seen by CrowdStrike Falcon. | 
| CrowdStrike.Incidents.hosts.local_ip | String | The device local IP address. | 
| CrowdStrike.Incidents.hosts.mac_address | String | The device MAC address. | 
| CrowdStrike.Incidents.hosts.major_version | String | The major version of the operating system. | 
| CrowdStrike.Incidents.hosts.minor_version | String | The minor version of the operating system. | 
| CrowdStrike.Incidents.hosts.os_version | String | The operating system of the host. | 
| CrowdStrike.Incidents.hosts.platform_id | String | The platform ID of the device that runs the sensor. | 
| CrowdStrike.Incidents.hosts.platform_name | String | The platform name of the host. | 
| CrowdStrike.Incidents.hosts.product_type_desc | String | The value indicating the product type. For example, 1 = Workstation, 2 = Domain Controller, 3 = Server. | 
| CrowdStrike.Incidents.hosts.status | String | The incident status as a number. For example, 20 = New, 25 = Reopened, 30 = In Progress, 40 = Closed. | 
| CrowdStrike.Incidents.hosts.system_manufacturer | String | The system manufacturer of the device. | 
| CrowdStrike.Incidents.hosts.system_product_name | String | The product name of the system. | 
| CrowdStrike.Incidents.hosts.modified_timestamp | Date | The datetime a user modified the incident in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.Incidents.created | Date | The time that the incident was created. | 
| CrowdStrike.Incidents.start | Date | The recorded time of the earliest incident. | 
| CrowdStrike.Incidents.end | Date | The recorded time of the latest incident. | 
| CrowdStrike.Incidents.state | String | The state of the incident. | 
| CrowdStrike.Incidents.status | Number | The status of the incident. | 
| CrowdStrike.Incidents.name | String | The name of the incident. | 
| CrowdStrike.Incidents.description | String | The description of the incident. | 
| CrowdStrike.Incidents.tags | String | The tags of the incident. | 
| CrowdStrike.Incidents.fine_score | Number | The incident score. | 

### endpoint

***
Returns information about an endpoint.

#### Base Command

`endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional | 
| ip | The endpoint IP address. | Optional | 
| hostname | The endpoint hostname. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.ID | String | The endpoint's ID. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 
| Endpoint.OSVersion | String | The endpoint's operation system version. | 

### cs-falcon-create-host-group

***
Create a host group.

#### Base Command

`cs-falcon-create-host-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the host. | Required | 
| group_type | The group type of the group. Can be 'static' or 'dynamic'. Possible values are: static, dynamic. | Required | 
| description | The description of the host. | Optional | 
| assignment_rule | The assignment rule. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | The datetime the host group was created in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | The datetime the host group was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 

### cs-falcon-list-host-groups

***
List the available host groups.

#### Base Command

`cs-falcon-list-host-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | The query by which to filter the devices that belong to the host group. | Optional | 
| offset | Page offset. | Optional | 
| limit | Maximum number of results on a page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | The datetime the host group was created in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | The datetime the host group was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 

### cs-falcon-delete-host-groups

***
Deletes the requested host groups.

#### Base Command

`cs-falcon-delete-host-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | A comma-separated list of the IDs of the host groups to be deleted. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-update-host-group

***
Updates a host group.

#### Base Command

`cs-falcon-update-host-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | The ID of the host group. | Required | 
| name | The name of the host group. | Optional | 
| description | The description of the host group. | Optional | 
| assignment_rule | The assignment rule. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | The datetime the host group was created in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | The datetime the host group was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 

### cs-falcon-list-host-group-members

***
Gets the list of host group members.

#### Base Command

`cs-falcon-list-host-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | The ID of the host group. | Optional | 
| filter | The query to filter the devices that belong to the host group. | Optional | 
| offset | Page offset. | Optional | 
| limit | The maximum number of results on a page. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Device.ID | String | The ID of the device. | 
| CrowdStrike.Device.LocalIP | String | The local IP address of the device. | 
| CrowdStrike.Device.ExternalIP | String | The external IP address of the device. | 
| CrowdStrike.Device.Hostname | String | The host name of the device. | 
| CrowdStrike.Device.OS | String | The operating system of the device. | 
| CrowdStrike.Device.MacAddress | String | The MAC address of the device. | 
| CrowdStrike.Device.FirstSeen | String | The first time the device was seen. | 
| CrowdStrike.Device.LastSeen | String | The last time the device was seen. | 
| CrowdStrike.Device.Status | String | The device status. | 

### cs-falcon-add-host-group-members

***
Add host group members.

#### Base Command

`cs-falcon-add-host-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | The ID of the host group. | Required | 
| host_ids | A comma-separated list of host agent IDs to run commands. (The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command.). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | The datetime the host group was created in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | The datetime the host group was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 

### cs-falcon-remove-host-group-members

***
Remove host group members.

#### Base Command

`cs-falcon-remove-host-group-members`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_group_id | The ID of the host group. | Required | 
| host_ids | A comma-separated list of host agent IDs to run commands. (The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command.). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.HostGroup.id | String | The ID of the host group. | 
| CrowdStrike.HostGroup.group_type | String | The group type of the host group. | 
| CrowdStrike.HostGroup.name | String | The name of the host group. | 
| CrowdStrike.HostGroup.description | String | The description of the host group. | 
| CrowdStrike.HostGroup.created_by | String | The client that created the host group. | 
| CrowdStrike.HostGroup.created_timestamp | Date | The datetime the host group was created in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 
| CrowdStrike.HostGroup.modified_by | String | The client that modified the host group. | 
| CrowdStrike.HostGroup.modified_timestamp | Date | The datetime the host group was last modified in ISO time format. For example: 2019-10-17T13:41:48.487520845Z. | 

### cs-falcon-resolve-incident

***
Resolve incidents.

#### Base Command

`cs-falcon-resolve-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of incident IDs. | Required | 
| status | The new status of the incident. Can be "New", "In Progress", "Reopened", "Closed". Possible values are: New, In Progress, Reopened, Closed. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-batch-upload-custom-ioc

***
Uploads a batch of indicators.

#### Base Command

`cs-falcon-batch-upload-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| multiple_indicators_json | A JSON object with list of CS Falcon indicators to upload. | Required | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. Default is 180. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOC.Type | string | The type of the IOC. | 
| CrowdStrike.IOC.Value | string | The string representation of the indicator. | 
| CrowdStrike.IOC.ID | string | The full ID of the indicator. | 
| CrowdStrike.IOC.Severity | string | The severity level to apply to this indicator. | 
| CrowdStrike.IOC.Source | string | The source of the IOC. | 
| CrowdStrike.IOC.Action | string | The action to take when a host observes the custom IOC. | 
| CrowdStrike.IOC.Expiration | string | The datetime the indicator will expire. | 
| CrowdStrike.IOC.Description | string | The description of the IOC. | 
| CrowdStrike.IOC.CreatedTime | date | The datetime the IOC was created. | 
| CrowdStrike.IOC.CreatedBy | string | The identity of the user/process who created the IOC. | 
| CrowdStrike.IOC.ModifiedTime | date | The datetime the indicator was last modified. | 
| CrowdStrike.IOC.ModifiedBy | string | The identity of the user/process who last updated the IOC. | 
| CrowdStrike.IOC.Tags | Unknown | The tags of the IOC. | 
| CrowdStrike.IOC.Platforms | Unknown | The platforms of the IOC. | 

### cs-falcon-rtr-kill-process

***
Execute an active responder kill command on a single host.

#### Base Command

`cs-falcon-rtr-kill-process`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID you would like to kill the given process for. | Required | 
| process_ids | A comma-separated list of process IDs to kill. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.kill.ProcessID | String | The process ID that was killed. | 
| CrowdStrike.Command.kill.Error | String | The error message raised if the command was failed. | 
| CrowdStrike.Command.kill.HostID | String | The host ID. | 

### cs-falcon-rtr-remove-file

***
Batch executes an RTR active-responder remove file across the hosts mapped to the given batch ID.

#### Base Command

`cs-falcon-rtr-remove-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the hosts IDs you would like to remove the file for. | Required | 
| file_path | The path to a file or a directory you want to remove. | Required | 
| os | The operating system of the hosts given. Since the remove command is different in each operating system, you can choose only one operating system. Possible values are: Windows, Linux, Mac. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.rm.HostID | String | The host ID. | 
| CrowdStrike.Command.rm.Error | String | The error message raised if the command failed. | 

### cs-falcon-rtr-list-processes

***
Executes an RTR active-responder ps command to get a list of active processes across the given host.

#### Base Command

`cs-falcon-rtr-list-processes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID you want to get the processes list from. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.ps.Filename | String | The the name of the result file to be returned. | 

### cs-falcon-rtr-list-network-stats

***
Executes an RTR active-responder netstat command to get a list of network status and protocol statistics across the given host.

#### Base Command

`cs-falcon-rtr-list-network-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID you want to get the network status and protocol statistics list from. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.netstat.Filename | String | The the name of the result file to be returned. | 

### cs-falcon-rtr-read-registry

***
Executes an RTR active-responder read registry keys command across the given hosts. This command is valid only for Windows hosts.

#### Base Command

`cs-falcon-rtr-read-registry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the host IDs you want to get the registry keys from. | Required | 
| registry_keys | A comma-separated list of the registry keys, sub keys or value to get. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-rtr-list-scheduled-tasks

***
Executes an RTR active-responder netstat command to get a list of scheduled tasks across the given host. This command is valid only for Windows hosts.

#### Base Command

`cs-falcon-rtr-list-scheduled-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the hosts IDs you want to get the list of scheduled tasks from. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-rtr-retrieve-file

***
Gets the RTR extracted file contents for the specified file path.

#### Base Command

`cs-falcon-rtr-retrieve-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the hosts IDs you want to get the file from. | Required | 
| file_path | The file path of the required file to extract. | Required | 
| filename | The file name to use for the archive name and the file within the archive. | Optional | 
| interval_in_seconds | interval between polling. Default is 60 seconds. Must be higher than 10. | Optional | 
| hosts_and_requests_ids | This is an internal argument used for the polling process, not to be used by the user. | Optional | 
| SHA256 | This is an internal argument used for the polling process, not to be used by the user. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.FileName | String | The file name. | 
| CrowdStrike.File.HostID | String | The host ID. | 
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### cs-falcon-get-detections-for-incident

***
Gets the detections for a specific incident.

#### Base Command

`cs-falcon-get-detections-for-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID to get detections for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IncidentDetection.incident_id | String | The incident ID. | 
| CrowdStrike.IncidentDetection.behavior_id | String | The behavior ID connected to the incident. | 
| CrowdStrike.IncidentDetection.detection_ids | String | A list of detection IDs connected to the incident. | 

### get-mapping-fields

***
Returns the list of fields to map in outgoing mirroring. This command is only used for debugging purposes.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-remote-data

***
Gets remote data from a remote incident or detection. This method does not update the current incident or detection, and should be used for debugging purposes only.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident or detection ID. | Required | 
| lastUpdate | The UTC timestamp in seconds of the last update. The incident or detection is only updated if it was modified after the last update time. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Gets the list of incidents and detections that were modified since the last update time. This method is used for debugging purposes. The get-modified-remote-data command is used as part of the Mirroring feature that was introduced in Cortex XSOAR version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string representing the local time. The incident or detection is only returned if it was modified after the last update time. | Optional | 

#### Context Output

There is no context output for this command.
### update-remote-system

***
Updates the remote incident or detection with local incident or detection changes. This method is only used for debugging purposes and will not update the current incident or detection.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### cs-falcon-spotlight-search-vulnerability

***
Retrieve vulnerability details according to the selected filter. Each request requires at least one filter parameter. Supported with the CrowdStrike Spotlight license.

#### Base Command

`cs-falcon-spotlight-search-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Limit the vulnerabilities returned to specific properties. Each value must be enclosed in single quotes and placed immediately after the colon with no space. For example, 'filter=status:'open'+cve.id:['CVE-2013-3900','CVE-2021-1675']'. | Optional | 
| aid | Unique agent identifier (AID) of a sensor. | Optional | 
| cve_id | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD). This filter supports multiple values and negation. | Optional | 
| cve_severity | Severity of the CVE. The possible values are: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, or NONE. | Optional | 
| tags | Name of a tag assigned to a host. Retrieve tags from Host Tags APIs. | Optional | 
| status | Status of a vulnerability. This filter supports multiple values and negation. The possible values are: open, closed, reopen, expired. | Optional | 
| platform_name | Operating system platform. This filter supports negation. The possible values are: Windows, Mac, Linux. | Optional | 
| host_group | Unique system-assigned ID of a host group. Retrieve the host group ID from Host Group APIs. | Optional | 
| host_type | Type of host a sensor is running on. | Optional | 
| last_seen_within | Filter for vulnerabilities based on the number of days since a host last connected to CrowdStrike Falcon. Enter a numeric value from 3 to 45 to indicate the number of days you want to look back. Example- last_seen_within:10. | Optional | 
| is_suppressed | Indicates if the vulnerability is suppressed by a suppression rule. Possible values are: true, false. | Optional | 
| display_remediation_info | Display remediation information type of data to be returned for each vulnerability entity. Possible values are: True, False. Default is True. | Optional | 
| display_evaluation_logic_info | Whether to return logic information type of data for each vulnerability entity. Possible values are: True, False. Default is True. | Optional | 
| display_host_info | Whether to return host information type of data for each vulnerability entity. Possible values are: True, False. Default is False. | Optional | 
| limit | Maximum number of items to return (1-5000). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Vulnerability.id | String | Unique system-assigned ID of the vulnerability. | 
| CrowdStrike.Vulnerability.cid | String | Unique system-generated customer identifier \(CID\) of the account. | 
| CrowdStrike.Vulnerability.aid | String | Unique agent identifier \(AID\) of the sensor where the vulnerability was found. | 
| CrowdStrike.Vulnerability.created_timestamp | Date | UTC date and time of when the vulnerability was created in Spotlight. | 
| CrowdStrike.Vulnerability.updated_timestamp | Date | UTC date and time of the last update made on the vulnerability. | 
| CrowdStrike.Vulnerability.status | String | Vulnerability's current status. Possible values are: open, closed, reopen, or expired. | 
| CrowdStrike.Vulnerability.apps.product_name_version | String | Name and version of the product associated with the vulnerability. | 
| CrowdStrike.Vulnerability.apps.sub_status | String | Status of each product associated with the vulnerability. Possible values are: open, closed, or reopen. | 
| CrowdStrike.Vulnerability.apps.remediation.ids | String | Remediation ID of each product associated with the vulnerability. | 
| CrowdStrike.Vulnerability.host_info.hostname | String | Name of the machine. | 
| CrowdStrike.Vulnerability.host_info.instance_id | String | Cloud instance ID of the host. | 
| CrowdStrike.Vulnerability.host_info.service_provider_account_id | String | Cloud service provider account ID for the host. | 
| CrowdStrike.Vulnerability.host_info.service_provider | String | Cloud service provider for the host. | 
| CrowdStrike.Vulnerability.host_info.os_build | String | Operating system build. | 
| CrowdStrike.Vulnerability.host_info.product_type_desc | String | Type of host a sensor is running on. | 
| CrowdStrike.Vulnerability.host_info.local_ip | String | Device's local IP address. | 
| CrowdStrike.Vulnerability.host_info.machine_domain | String | Active Directory domain name. | 
| CrowdStrike.Vulnerability.host_info.os_version | String | Operating system version. | 
| CrowdStrike.Vulnerability.host_info.ou | String | Active directory organizational unit name. | 
| CrowdStrike.Vulnerability.host_info.site_name | String | Active directory site name. | 
| CrowdStrike.Vulnerability.host_info.system_manufacturer | String | Name of the system manufacturer. | 
| CrowdStrike.Vulnerability.host_info.groups.id | String | Array of host group IDs that the host is assigned to. | 
| CrowdStrike.Vulnerability.host_info.groups.name | String | Array of host group names that the host is assigned to. | 
| CrowdStrike.Vulnerability.host_info.tags | String | Name of a tag assigned to a host. | 
| CrowdStrike.Vulnerability.host_info.platform | String | Operating system platform. This filter supports negation. | 
| CrowdStrike.Vulnerability.remediation.entities.id | String | Unique ID of the remediation. | 
| CrowdStrike.Vulnerability.remediation.entities.reference | String | Relevant reference for the remediation that can be used to get additional details for the remediation. | 
| CrowdStrike.Vulnerability.remediation.entities.title | String | Short description of the remediation. | 
| CrowdStrike.Vulnerability.remediation.entities.action | String | Expanded description of the remediation. | 
| CrowdStrike.Vulnerability.remediation.entities.link | String | Link to the remediation page for the vendor. In certain cases, this field is null. | 
| CrowdStrike.Vulnerability.cve.id | String | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database \(NVD\). | 
| CrowdStrike.Vulnerability.cve.base_score | Number | Base score of the CVE \(float value between 1 and 10\). | 
| CrowdStrike.Vulnerability.cve.severity | String | CVSS severity rating of the vulnerability. | 
| CrowdStrike.Vulnerability.cve.exploit_status | Number | Numeric value of the most severe known exploit. | 
| CrowdStrike.Vulnerability.cve.exprt_rating | String | ExPRT rating assigned by CrowdStrike's predictive AI rating system. | 
| CrowdStrike.Vulnerability.cve.description | String | Brief description of the CVE. | 
| CrowdStrike.Vulnerability.cve.published_date | Date | UTC timestamp with the date and time of when the vendor published the CVE. | 
| CrowdStrike.Vulnerability.cve.vendor_advisory | String | Link to the vendor page where the CVE was disclosed. | 
| CrowdStrike.Vulnerability.cve.exploitability_score | Number | Exploitability score of the CVE \(float values from 1-4\). | 
| CrowdStrike.Vulnerability.cve.impact_score | Number | Impact score of the CVE \(float values from 1-6\). | 
| CrowdStrike.Vulnerability.cve.vector | String | Textual representation of the metric values used to score the vulnerability. | 
| CrowdStrike.Vulnerability.cve.remediation_level | String | CVSS remediation level of the vulnerability \(U = Unavailable, or O = Official fix\). | 
| CrowdStrike.Vulnerability.cve.cisa_info.is_cisa_kev | Boolean | Whether to filter for vulnerabilities that are in the CISA Known Exploited Vulnerabilities \(KEV\) catalog. | 
| CrowdStrike.Vulnerability.cve.cisa_info.due_date | Date | Date before which CISA mandates subject organizations to patch the vulnerability. | 
| CrowdStrike.Vulnerability.cve.spotlight_published_date | Date | UTC timestamp with the date and time Spotlight enabled coverage for the vulnerability. | 
| CrowdStrike.Vulnerability.cve.actors | String | Adversaries associated with the vulnerability. | 
| CrowdStrike.Vulnerability.cve.name | String | The vulnerability name. | 

### cve

***
Retrieve vulnerability details according to the selected filter. Each request requires at least one filter parameter. Supported with the CrowdStrike Spotlight license.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD). This filter supports multiple values and negation. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator value. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 

### cs-falcon-spotlight-list-host-by-vulnerability

***
Retrieve vulnerability details for a specific ID and host. Supported with the CrowdStrike Spotlight license.

#### Base Command

`cs-falcon-spotlight-list-host-by-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of items to return (1-5000). Default is 50. | Optional | 
| cve_ids | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD). This filter supports multiple values and negation. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.VulnerabilityHost.id | String | Unique system-assigned ID of the vulnerability. | 
| CrowdStrike.VulnerabilityHost.cid | String | Unique system-generated customer identifier \(CID\) of the account. | 
| CrowdStrike.VulnerabilityHost.aid | String | Unique agent identifier \(AID\) of the sensor where the vulnerability was found. | 
| CrowdStrike.VulnerabilityHost.created_timestamp | Date | UTC date and time of when the vulnerability was created in Spotlight. | 
| CrowdStrike.VulnerabilityHost.updated_timestamp | Date | UTC date and time of the last update made on the vulnerability. | 
| CrowdStrike.VulnerabilityHost.status | String | Vulnerability's current status. Possible values are: open, closed, reopen, or expired. | 
| CrowdStrike.VulnerabilityHost.apps.product_name_version | String | Name and version of the product associated with the vulnerability. | 
| CrowdStrike.VulnerabilityHost.apps.sub_status | String | Status of each product associated with the vulnerability. Possible values are: open, closed, or reopen. | 
| CrowdStrike.VulnerabilityHost.apps.remediation.ids | String | Remediation ID of each product associated with the vulnerability. | 
| CrowdStrike.VulnerabilityHost.apps.evaluation_logic.id | String | Unique system-assigned ID of the vulnerability evaluation logic. | 
| CrowdStrike.VulnerabilityHost.suppression_info.is_suppressed | Boolean | Indicates if the vulnerability is suppressed by a suppression rule. | 
| CrowdStrike.VulnerabilityHost.host_info.hostname | String | Name of the machine. | 
| CrowdStrike.VulnerabilityHost.host_info.local_ip | String | Device's local IP address. | 
| CrowdStrike.VulnerabilityHost.host_info.machine_domain | String | Active Directory domain name. | 
| CrowdStrike.VulnerabilityHost.host_info.os_version | String | Operating system version. | 
| CrowdStrike.VulnerabilityHost.host_info.ou | String | Active directory organizational unit name. | 
| CrowdStrike.VulnerabilityHost.host_info.site_name | String | Active directory site name. | 
| CrowdStrike.VulnerabilityHost.host_info.system_manufacturer | String | Name of the system manufacturer. | 
| CrowdStrike.VulnerabilityHost.host_info.platform | String | Operating system platform. This filter supports negation. | 
| CrowdStrike.VulnerabilityHost.host_info.instance_id | String | Cloud instance ID of the host. | 
| CrowdStrike.VulnerabilityHost.host_info.service_provider_account_id | String | Cloud service provider account ID for the host. | 
| CrowdStrike.VulnerabilityHost.host_info.service_provider | String | Cloud service provider for the host. | 
| CrowdStrike.VulnerabilityHost.host_info.os_build | String | Operating system build. | 
| CrowdStrike.VulnerabilityHost.host_info.product_type_desc | String | Type of host a sensor is running on. | 
| CrowdStrike.VulnerabilityHost.cve.id | String | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database \(NVD\). | 

### cs-falcon-create-ml-exclusion

***
Create an ML exclusion.

#### Base Command

`cs-falcon-create-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Value to match for the exclusion. | Required | 
| excluded_from | Exclusion excluded from. Possible values are: blocking, extraction. | Required | 
| comment | Comment describing why the exclusions were created. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion OR all if empty. Default is all. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | An hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Group's ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.MLExclusion.created_by | String | The date when the exclusion rule was created. | 

### cs-falcon-update-ml-exclusion

***
Updates an ML exclusion. At least one argument is required in addition to the ID argument.

#### Base Command

`cs-falcon-update-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the exclusion to update. | Required | 
| value | Value to match for the exclusion (the exclusion pattern). | Optional | 
| comment | Comment describing why the exclusions were created. | Optional | 
| excluded_from | Group ID(s) explicitly excluded from the exclusion. | Optional | 
| groups | Group ID(s) impacted by the exclusion. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | An hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.MLExclusion.created_by | String | The date when the exclusion rule was created. | 

### cs-falcon-delete-ml-exclusion

***
Delete the ML exclusions by ID.

#### Base Command

`cs-falcon-delete-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Delete the ML exclusions by id. Default is The ID of the exclusion to update.. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-search-ml-exclusion

***
Get a list of ML exclusions by specifying their IDs, value, or a specific filter.

#### Base Command

`cs-falcon-search-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | A custom filter by which the exclusions should be filtered. For example `value:”&lt;value&gt;”`. | Optional | 
| value | The value by which the exclusions should be filtered. | Optional | 
| ids | The IDs of the exclusions to retrieve. The IDs overwrite the filter and value. | Optional | 
| limit | The maximum number of records to return. [1-500]. | Optional | 
| offset | The offset to start retrieving records from. | Optional | 
| sort | How to sort the retrieved exclusions. Possible values are: applied_globally.asc, applied_globally.desc, created_by.asc, created_by.desc, created_on.asc, created_on.desc, last_modified.asc, last_modified.desc, modified_by.asc, modified_by.desc, value.asc, value.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | A hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.MLExclusion.created_by | String | The date when the exclusion rule was created. | 

#### Command example
```!cs-falcon-search-ml-exclusion limit=1```
#### Context Example
```json
{
    "CrowdStrike": {
        "MLExclusion": {
            "applied_globally": false,
            "created_by": "api-client-id:f7acf1bd5d3d4b40afe77546cbbaefde",
            "created_on": "2023-03-01T18:51:07.196018144Z",
            "excluded_from": [
                "blocking"
            ],
            "groups": [
                {
                    "assignment_rule": "device_id:[],hostname:['INSTANCE-1','falcon-crowdstrike-sensor-centos7','2121062E-6A54-4','FALCON-CROWDSTR']",
                    "created_by": "ssokolovich@paloaltonetworks.com",
                    "created_timestamp": "2023-01-23T15:01:11.846726918Z",
                    "description": "",
                    "group_type": "static",
                    "id": "7471ba0636b34cbb8c65fae7979a6a9b",
                    "modified_by": "ssokolovich@paloaltonetworks.com",
                    "modified_timestamp": "2023-01-23T15:18:52.316882546Z",
                    "name": "Lab env"
                }
            ],
            "id": "acd7b152475c5955106c73ae85cc6792",
            "last_modified": "2023-03-01T18:51:07.196018144Z",
            "modified_by": "api-client-id:f7acf1bd5d3d4b40afe77546cbbaefde",
            "regexp_value": "\\/MosheTest2-432",
            "value": "/MosheTest2-432",
            "value_hash": "8ebbf2e757299ad78c1be505c1bfeb2d"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon machine learning exclusions
>|Id|Value|RegexpValue|ValueHash|ExcludedFrom|Groups|AppliedGlobally|LastModified|ModifiedBy|CreatedOn|CreatedBy|
>|---|---|---|---|---|---|---|---|---|---|---|
>| acd7b152475c5955106c73ae85cc6792 | /MosheTest2-432 | \/MosheTest2-432 | 8ebbf2e757299ad78c1be505c1bfeb2d | ***values***: blocking | **-**	***id***: 7471ba0636b34cbb8c65fae7979a6a9b<br/>	***group_type***: static<br/>	***name***: Lab env<br/>	***description***: <br/>	***assignment_rule***: device_id:[],hostname:['INSTANCE-1','falcon-crowdstrike-sensor-centos7','2121062E-6A54-4','FALCON-CROWDSTR']<br/>	***created_by***: ssokolovich@paloaltonetworks.com<br/>	***created_timestamp***: 2023-01-23T15:01:11.846726918Z<br/>	***modified_by***: ssokolovich@paloaltonetworks.com<br/>	***modified_timestamp***: 2023-01-23T15:18:52.316882546Z |  | 2023-03-01T18:51:07.196018144Z | api-client-id:f7acf1bd5d3d4b40afe77546cbbaefde | 2023-03-01T18:51:07.196018144Z | api-client-id:f7acf1bd5d3d4b40afe77546cbbaefde |


### cs-falcon-create-ioa-exclusion

***
Create an IOA exclusion.

#### Base Command

`cs-falcon-create-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclusion_name | Name of the exclusion. | Required | 
| pattern_name | Name of the exclusion pattern. | Optional | 
| pattern_id | ID of the exclusion pattern. | Required | 
| cl_regex | Command line regular expression. | Required | 
| ifn_regex | Indicator file name regular expression. | Required | 
| comment | Comment describing why the exclusions were created. | Optional | 
| description | Exclusion description. | Optional | 
| detection_json | JSON formatted detection template. | Optional | 
| groups | Group ID(s) impacted by the exclusion. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for file name matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.IOAExclusion.created_by | String | The date when the exclusion rule was created. | 

### cs-falcon-update-ioa-exclusion

***
Updates an IOA exclusion. At least one argument is required in addition to the ID argument.

#### Base Command

`cs-falcon-update-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the exclusion to update. | Required | 
| exclusion_name | Name of the exclusion. | Optional | 
| pattern_id | ID of the exclusion pattern to update. | Optional | 
| pattern_name | Name of the exclusion pattern. | Optional | 
| cl_regex | Command line regular expression. | Optional | 
| ifn_regex | Indicator file name regular expression. | Optional | 
| comment | Comment describing why the exclusions was created. | Optional | 
| description | Exclusion description. | Optional | 
| detection_json | JSON formatted detection template. | Optional | 
| groups | Group ID(s) impacted by the exclusion. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for file name matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.IOAExclusion.created_by | String | The date when the exclusion rule was created. | 

### cs-falcon-delete-ioa-exclusion

***
Delete the IOA exclusions by ID.

#### Base Command

`cs-falcon-delete-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | IDs of the exclusions to be deleted. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-search-ioa-exclusion

***
Get a list of IOA exclusions by specifying their IDs or a filter

#### Base Command

`cs-falcon-search-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | A custom filter by which the exclusions should be filtered. For example `value:”&lt;value&gt;”`. | Optional | 
| value | The value by which the exclusions should be filtered. | Optional | 
| ids | The IDs of the exclusions to retrieve. The IDs overwrite the filter and value. | Optional | 
| limit | The limit of how many exclusions to retrieve. Default is 50. | Optional | 
| offset | The offset of how many exclusions to skip. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for file name matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Groups ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Groups type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Groups name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Groups description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Groups assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | Indicate who created the rule. | 
| CrowdStrike.IOAExclusion.created_by | String | The date when the exclusion rule was created. | 

#### Command example
```!cs-falcon-search-ioa-exclusion limit=1```
#### Context Example
```json
{
    "CrowdStrike": {
        "MLExclusion": {
            "applied_globally": true,
            "cl_regex": "choice\\s+/m\\s+crowdstrike_sample_detection",
            "created_by": "maizen@paloaltonetworks.com",
            "created_on": "2023-02-06T16:42:19.29906839Z",
            "description": "ioa DESCRIPTION",
            "detection_json": "",
            "groups": [],
            "id": "3d6abe74bba640cf8880a18582ede617",
            "ifn_regex": ".*\\\\Windows\\\\System32\\\\choice\\.exe",
            "last_modified": "2023-02-26T15:30:04.554767735Z",
            "modified_by": "api-client-id:f7acf1bd5d3d4b40afe77546cbbaefde",
            "name": "My IOA Exclusion",
            "pattern_id": "10197",
            "pattern_name": "lfkj"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon IOA exclusions
>|Id|Name|Description|PatternId|PatternName|IfnRegex|ClRegex|AppliedGlobally|LastModified|ModifiedBy|CreatedOn|CreatedBy|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3d6abe74bba640cf8880a18582ede617 | My IOA Exclusion | ioa DESCRIPTION | 10197 | lfkj | .*\\Windows\\System32\\choice\.exe | choice\s+/m\s+crowdstrike_sample_detection |  | 2023-02-26T15:30:04.554767735Z | api-client-id:f7acf1bd5d3d4b40afe77546cbbaefde | 2023-02-06T16:42:19.29906839Z | maizen@paloaltonetworks.com |


### cs-falcon-list-quarantined-file

***
Get quarantine file metadata by specified IDs or filter.

#### Base Command

`cs-falcon-list-quarantined-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the quarantined files to retrieve. | Optional | 
| filter | A custom filter by which the retrieve quarantined file should be filtered. | Optional | 
| sha256 | The SHA256 hash value of the quarantined files to retrieve. | Optional | 
| filename | The file name of the quarantined files to retrieve. | Optional | 
| state | Filter the retrieved files by state. | Optional | 
| hostname | Filter the retrieved files by hostname. | Optional | 
| username | Filter the retrieved files by username. | Optional | 
| limit | Maximum number of IDs to return. Max 5000. Default 50. | Optional | 
| offset | Starting index of the overall result set from which to return IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.QuarantinedFile.id | String | A unique identifier for the quarantined file. | 
| CrowdStrike.QuarantinedFile.aid | String | The agent identifier of the agent that quarantined the file. | 
| CrowdStrike.QuarantinedFile.cid | String | The unique identifier for the customer that owns the agent. | 
| CrowdStrike.QuarantinedFile.sha256 | String | The SHA256 hash value of the quarantined file. | 
| CrowdStrike.QuarantinedFile.paths.path | String | The full path of the quarantined file. | 
| CrowdStrike.QuarantinedFile.paths.filename | String | The name of the quarantined file. | 
| CrowdStrike.QuarantinedFile.paths.state | String | The current state of the quarantined file path \(e.g., "purged"\). | 
| CrowdStrike.QuarantinedFile.state | String | The current state of the quarantined file \(e.g., "unrelease_pending"\). | 
| CrowdStrike.QuarantinedFile.detect_ids | String | The detection identifiers associated with the quarantined file. | 
| CrowdStrike.QuarantinedFile.hostname | String | The hostname of the agent that quarantined the file. | 
| CrowdStrike.QuarantinedFile.username | String | The username associated with the quarantined file. | 
| CrowdStrike.QuarantinedFile.date_updated | Date | The date the quarantined file was last updated. | 
| CrowdStrike.QuarantinedFile.date_created | Date | The date the quarantined file was created. | 

#### Command example
```!cs-falcon-list-quarantined-file limit=1```
#### Context Example
```json
{
    "CrowdStrike": {
        "MLExclusion": {
            "aid": "046761c46ec84f40b27b6f79ce7cd32c",
            "cid": "20879a8064904ecfbb62c118a6a19411",
            "date_created": "2022-12-13T14:23:49Z",
            "date_updated": "2023-03-06T23:23:55Z",
            "detect_ids": [
                "ldt:046761c46ec84f40b27b6f79ce7cd32c:176096213055"
            ],
            "hostname": "INSTANCE-1",
            "id": "046761c46ec84f40b27b6f79ce7cd32c_b3b207dfab2f429cc352ba125be32a0cae69fe4bf8563ab7d0128bba8c57a71c",
            "paths": [
                {
                    "filename": "nc.exe",
                    "path": "\\Device\\HarddiskVolume3\\Users\\admin\\Downloads\\hamuzim\\netcat-1.11\\nc.exe",
                    "state": "quarantined"
                }
            ],
            "sha256": "b3b207dfab2f429cc352ba125be32a0cae69fe4bf8563ab7d0128bba8c57a71c",
            "state": "deleted",
            "username": "admin"
        }
    }
}
```

#### Human Readable Output

>### CrowdStrike Falcon Quarantined File
>|Id|Aid|Cid|Sha256|Paths|State|DetectIds|Hostname|Username|DateUpdated|DateCreated|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 046761c46ec84f40b27b6f79ce7cd32c_b3b207dfab2f429cc352ba125be32a0cae69fe4bf8563ab7d0128bba8c57a71c | 046761c46ec84f40b27b6f79ce7cd32c | 20879a8064904ecfbb62c118a6a19411 | b3b207dfab2f429cc352ba125be32a0cae69fe4bf8563ab7d0128bba8c57a71c | **-**	***path***: \Device\HarddiskVolume3\Users\admin\Downloads\hamuzim\netcat-1.11\nc.exe<br/>	***filename***: nc.exe<br/>	***state***: quarantined | deleted | ***values***: ldt:046761c46ec84f40b27b6f79ce7cd32c:176096213055 | INSTANCE-1 | admin | 2023-03-06T23:23:55Z | 2022-12-13T14:23:49Z |


### cs-falcon-apply-quarantine-file-action

***
Update quarantine file metadata by the specified IDs or a filter.

#### Base Command

`cs-falcon-apply-quarantine-file-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The IDs of the quarantined files to update. | Optional | 
| action | Action to perform against the quarantined file. Possible values are: delete, release, unrelease. | Required | 
| comment | Comment to appear along with the action taken. | Required | 
| filter | Update files based on a custom filter. | Optional | 
| sha256 | Update files based on the SHA256 hash value. | Optional | 
| filename | Update files based on the filename. | Optional | 
| state | Update files based on the state. | Optional | 
| hostname | Update files based on the hostname. | Optional | 
| username | Update files based on the usernames. | Optional | 

#### Context Output

There is no context output for this command.
## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and CrowdStrike Falcon corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in CrowdStrike Falcon events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in CrowdStrike Falcon events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and CrowdStrike Falcon events will be reflected in both directions. |

3. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in CrowdStrike Falcon.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and CrowdStrike Falcon.
