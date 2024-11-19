The CrowdStrike Falcon OAuth 2 API (formerly the Falcon Firehose API), enables fetching and resolving detections, searching devices, getting behaviors by ID, containing hosts, and lifting host containment.
## Configure RotemTest on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RotemTest.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Use legacy API | Use the legacy version of the API, which refers to versions prior to the 'Next Generation Raptor release.' | False |
    | Server URL (e.g., https://api.crowdstrike.com) |  | True |
    | Client ID |  | False |
    | Secret |  | False |
    | Client ID |  | False |
    | Secret |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. Currently used for “CVE” reputation  command. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Max incidents per fetch |  | False |
    | Endpoint Detections fetch query | Use the Falcon Query Language. For more information, refer to https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql. | False |
    | Endpoint Incidents fetch query | Use the Falcon Query Language. For more information, refer to https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql. | False |
    | IDP Detections fetch query | Use the Falcon Query Language. For more information, refer to https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql. | False |
    | Mobile Detections fetch query | Use the Falcon Query Language. For more information, refer to https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql. | False |
    | IOM fetch query | Use the Falcon Query Language. For more information, refer to https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql. | False |
    | IOA fetch query | In the format: cloud_provider=aws&amp;aws_account_id=1234. The query must have the argument 'cloud_provider' configured. Multiple values for the same parameter is not supported. For more information, refer to https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql. | False |
    | Detections from On-Demand Scans fetch query |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Mirroring Direction | Choose the direction to mirror the detection: Incoming \(from CrowdStrike Falcon to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to CrowdStrike Falcon\), or Incoming and Outgoing \(to/from CrowdStrike Falcon and Cortex XSOAR\). | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Close Mirrored XSOAR Incident | When selected, closing the CrowdStrike Falcon incident is mirrored in Cortex XSOAR. | False |
    | Close Mirrored CrowdStrike Falcon Incident or Detection | When selected, closing the Cortex XSOAR incident is mirrored in CrowdStrike Falcon, according to the types that were chosen to be fetched and mirrored. | False |
    | Fetch types | Choose what to fetch - incidents, detections, IDP detections. You can choose any combination. Note that the "On-Demand Scans Detection" option is not available in the legacy version. | False |
    | Reopen Statuses | CrowdStrike Falcon statuses that will reopen an incident in Cortex XSOAR if closed. You can choose any combination. | False |
    | Incidents Fetch Interval |  | False |
    | Advanced: Time in minutes to look back when fetching incidents and detections | Use this parameter to determine the look-back period for searching for incidents that were created before the last run time and did not match the query when they were created. | False |

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
| extended_data | Whether or not to get additional data about the device. Possible values are: Yes, No. | Optional | 
| filter | The query by which to filter the device. | Optional | 
| limit | The maximum records to return [1-5000]. Default is 50. | Optional | 
| offset | The offset to start retrieving records from. Default is 0. | Optional | 
| ids | A comma-separated list of device IDs to limit the results. | Optional | 
| status | The status of the device. Possible values are: normal, containment_pending, contained, lift_containment_pending. | Optional | 
| hostname | The hostname of the device. Possible values are: . | Optional | 
| platform_name | The platform name of the device. Possible values are: Windows, Mac, Linux. | Optional | 
| site_name | The site name of the device. | Optional | 
| sort | The property to sort by (e.g., status.desc or hostname.asc). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Device.ID | String | The ID of the device. | 
| CrowdStrike.Device.LocalIP | String | The local IP address of the device. | 
| CrowdStrike.Device.ExternalIP | String | The external IP address of the device. | 
| CrowdStrike.Device.Hostname | String | The hostname of the device. | 
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

### cs-falcon-search-detection

***
Search for details of specific detections, either using a filter query, or by providing the IDs of the detections.

#### Base Command

`cs-falcon-search-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of IDs of the detections to search. If provided, will override other arguments. | Optional | 
| filter | Filter detections using a query in Falcon Query Language (FQL).<br/>For example, filter="device.hostname:'CS-SE-TG-W7-01'"<br/>For a full list of valid filter options, see: https://falcon.crowdstrike.com/support/documentation/2/query-api-reference#detectionsearch. | Optional | 
| extended_data | Whether to get additional data such as device and behaviors processed. Possible values are: Yes, No. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Detection.Behavior.FileName | String | The filename of the behavior. | 
| CrowdStrike.Detection.Behavior.Scenario | String | The scenario name of the behavior. | 
| CrowdStrike.Detection.Behavior.MD5 | String | The MD5 hash of the IOC of the behavior. | 
| CrowdStrike.Detection.Behavior.SHA256 | String | The SHA256 hash of the IOC of the behavior. | 
| CrowdStrike.Detection.Behavior.IOCType | String | The type of the IOC. | 
| CrowdStrike.Detection.Behavior.IOCValue | String | The value of the IOC. | 
| CrowdStrike.Detection.Behavior.CommandLine | String | The command line executed in the behavior. | 
| CrowdStrike.Detection.Behavior.UserName | String | The username related to the behavior. | 
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
Resolves and updates a detection using the provided arguments. At least one optional argument must be passed, otherwise no change will take place. Note that IDP detections are not supported.

#### Base Command

`cs-falcon-resolve-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of one or more IDs to resolve. | Required | 
| status | The status to transition a detection to. Note: The following statuses—true_positive, false_positive, and ignored—are only available in the legacy version of the API. Possible values are: new, in_progress, true_positive, false_positive, closed, reopened, ignored. | Optional | 
| assigned_to_uuid | A user ID, for example: 1234567891234567891. username and assigned_to_uuid are mutually exclusive. | Optional | 
| comment | Optional comment to add to the detection. Comments are displayed with the detection in CrowdStrike Falcon and provide context or notes for other Falcon users. | Optional | 
| show_in_ui | If true, displays the detection in the UI. Possible values are: true, false. | Optional | 
| username | Username to assign the detections to. (This is usually the user's email address, but may vary based on your configuration). username and assigned_to_uuid are mutually exclusive. | Optional | 
| tag | The tag to add to the detection, supported only for API V3. | Optional | 

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
| ids | A comma-separated list of host agent IDs (AID) of the host to contain. Get an agent ID from a detection. | Required | 

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
| ids | A comma-separated list of host agent IDs (AIDs) of the hosts to contain. Get an agent ID from a detection. | Required | 

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
| queue_offline | Any commands run against an offline-queued session will be queued up and executed when the host comes online. Default is false. | Optional | 
| host_ids | A comma-separated list of host agent IDs to run commands for. The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command. | Required | 
| command_type | The type of command to run. | Required | 
| full_command | The full command to run. | Required | 
| scope | The scope to run the command for. (NOTE: In order to run the CrowdStrike RTR `put` command, it is necessary to pass `scope=admin`). Possible values are: read, write, admin. Default is read. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. Default is 180. | Optional | 
| target | The target to run the command for. Possible values are: batch, single. Default is batch. | Optional | 
| batch_id | A batch ID to execute the command on. | Optional | 

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
| CrowdStrike.Command.BatchID | String | The Batch ID that the command was executed on. | 

### cs-falcon-upload-script

***
Uploads a script to Falcon CrowdStrike.

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
Uploads a file to the CrowdStrike cloud. (Can be used for the RTR 'put' command).

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
| file_id | The ID of the file to delete. The ID of the file can be retrieved by running the 'cs-falcon-list-files' command. | Required | 

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
| file_id | A comma-separated list of file IDs to get. The list of file IDs can be retrieved by running the 'cs-falcon-list-files' command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.ID | String | The ID of the file. | 
| CrowdStrike.File.CreatedBy | String | The email address of the user who created the file. | 
| CrowdStrike.File.CreatedTime | Date | The datetime the file was created. | 
| CrowdStrike.File.Description | String | The description of the file. | 
| CrowdStrike.File.Type | String | The type of the file. For example, script. | 
| CrowdStrike.File.ModifiedBy | String | The email address of the user who modified the file. | 
| CrowdStrike.File.ModifiedTime | Date | The datetime the file was modified. | 
| CrowdStrike.File.Name | String | The full name of the file. | 
| CrowdStrike.File.Permission | String | The permission type of the file. Possible values are: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | 
| CrowdStrike.File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Type | String | The file type. | 
| File.Name | String | The full name of the file. | 
| File.SHA256 | String | The SHA-256 hash of the file. | 
| File.Size | Number | The size of the file in bytes. | 

### cs-falcon-list-files

***
Returns a list of put-file IDs that are available for the user in the 'put' command. Due to an API limitation, the maximum number of files returned is 100.

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
| CrowdStrike.File.CreatedTime | Date | The datetime the file was created. | 
| CrowdStrike.File.Description | String | The description of the file. | 
| CrowdStrike.File.Type | String | The type of the file. For example, script. | 
| CrowdStrike.File.ModifiedBy | String | The email address of the user who modified the file. | 
| CrowdStrike.File.ModifiedTime | Date | The datetime the file was modified. | 
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
| script_id | A comma-separated list of script IDs to return. The script IDs can be retrieved by running the 'cs-falcon-list-scripts' command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Script.ID | String | The ID of the script. | 
| CrowdStrike.Script.CreatedBy | String | The email address of the user who created the script. | 
| CrowdStrike.Script.CreatedTime | Date | The datetime the script was created. | 
| CrowdStrike.Script.Description | String | The description of the script. | 
| CrowdStrike.Script.ModifiedBy | String | The email address of the user who modified the script. | 
| CrowdStrike.Script.ModifiedTime | Date | The datetime the script was modified. | 
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
| script_id | The script ID to delete. The script IDs can be retrieved by running the 'cs-falcon-list-scripts' command. | Required | 

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
| CrowdStrike.Script.CreatedTime | Date | The datetime the script was created. | 
| CrowdStrike.Script.Description | String | The description of the script. | 
| CrowdStrike.Script.ModifiedBy | String | The email address of the user who modified the script. | 
| CrowdStrike.Script.ModifiedTime | Date | The datetime the script was modified. | 
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
| host_ids | A comma-separated list of host agent IDs to run commands. The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command. | Required | 
| raw | The PowerShell script code to run. | Optional | 
| timeout | Timeout for how long to wait for the request in seconds. Maximum is 600 (10 minutes). Default is 30. | Optional | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. Default is false. | Optional | 

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
| host_ids | A comma-separated list of host agent IDs on which to run the RTR command. | Required | 
| file_path | Full path to the file that will be retrieved from each host in the batch. | Required | 
| optional_hosts | A comma-separated list of a subset of hosts on which to run the command. | Optional | 
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
| request_ids | A comma-separated list of IDs of the command requested. | Required | 
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
| scope | The scope to run the command for. Possible values are: read, write, admin. Default is read. | Optional | 

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
| types | A comma-separated list of indicator types. Possible values are: sha256, sha1, md5, domain, ipv4, ipv6. | Optional | 
| values | A comma-separated list of indicator values. | Optional | 
| sources | A comma-separated list of IOC sources. | Optional | 
| expiration | The datetime the indicator will become inactive (ISO 8601 format, i.e., YYYY-MM-DDThh:mm:ssZ). | Optional | 
| limit | The maximum number of records to return. The minimum is 1 and the maximum is 500. Default is 50. | Optional | 
| sort | The order the results are returned in. Possible values are: type.asc, type.desc, value.asc, value.desc, policy.asc, policy.desc, share_level.asc, share_level.desc, expiration_timestamp.asc, expiration_timestamp.desc. | Optional | 
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
| CrowdStrike.NextPageToken | unknown | A pagination token used with the limit parameter to manage pagination of results. | 

### cs-falcon-get-custom-ioc

***
Gets the full definition of one or more indicators that you are watching.

#### Base Command

`cs-falcon-get-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type to retrieve. Either ioc_id or ioc_type and value must be provided. Possible values are: sha256, sha1, md5, domain, ipv4, ipv6. | Optional | 
| value | The string representation of the indicator. Either ioc_id or ioc_type and value must be provided. | Optional | 
| ioc_id | The ID of the IOC to get. The ID of the IOC can be retrieved by running the 'cs-falcon-search-custom-iocs' command. Either ioc_id or ioc_type and value must be provided. | Optional | 

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
| ioc_type | The type of the indicator. Possible values are: sha256, md5, domain, ipv4, ipv6. | Required | 
| value | A comma-separated list of indicators.<br/>More than one value can be supplied to upload multiple IOCs of the same type but with different values. Note that the uploaded IOCs will have the same properties (as supplied in other arguments). | Required | 
| action | Action to take when a host observes the custom IOC. Possible values are: no_action - Save the indicator for future use, but take no action. No severity required. allow - Applies to hashes only. Allow the indicator and do not detect it. Severity does not apply and should not be provided. prevent_no_ui - Applies to hashes only. Block and detect the indicator, but hide it from Activity &gt; Detections. Has a default severity value. prevent - Applies to hashes only. Block the indicator and show it as a detection at the selected severity. detect - Enable detections for the indicator at the selected severity. Possible values are: no_action, allow, prevent_no_ui, prevent, detect. | Required | 
| platforms | A comma-separated list of the platforms that the indicator applies to. Possible values are: mac, windows, linux. | Required | 
| severity | The severity level to apply to this indicator. Required for the prevent and detect actions. Optional for no_action. Possible values are: informational, low, medium, high, critical. | Optional | 
| expiration | The datetime the indicator will become inactive (ISO 8601 format, i.e., YYYY-MM-DDThh:mm:ssZ). | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 
| applied_globally | Whether the indicator is applied globally. Either applied_globally or host_groups must be provided. Possible values are: true, false. | Optional | 
| host_groups | A comma-separated list of host group IDs that the indicator applies to. The list of host group IDs can be retrieved by running the 'cs-falcon-list-host-groups' command. Either applied_globally or host_groups must be provided. | Optional | 
| tags | A comma-separated list of tags to apply to the indicator. | Optional | 
| file_name | Name of the file for file indicators. Applies to hashes only. A common filename, or a filename in your environment. Filenames can be helpful for identifying hashes or filtering IOCs. | Optional | 

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
| CrowdStrike.IOC.Filename | string | Name of the file for file indicators. Applies to hashes only. A common filename, or a filename in your environment. Filenames can be helpful for identifying hashes or filtering IOCs. | 

### cs-falcon-update-custom-ioc

***
Updates an indicator for CrowdStrike to monitor.

#### Base Command

`cs-falcon-update-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_id | The ID of the IOC to update. The ID of the IOC can be retrieved by running the 'cs-falcon-search-custom-iocs' command. | Required | 
| action | Action to take when a host observes the custom IOC. Possible values are: no_action - Save the indicator for future use, but take no action. No severity required. allow - Applies to hashes only. Allow the indicator and do not detect it. Severity does not apply and should not be provided. prevent_no_ui - Applies to hashes only. Block and detect the indicator, but hide it from Activity &gt; Detections. Has a default severity value. prevent - Applies to hashes only. Block the indicator and show it as a detection at the selected severity. detect - Enable detections for the indicator at the selected severity. Possible values are: no_action, allow, prevent_no_ui, prevent, detect. | Optional | 
| platforms | A comma-separated list of the platforms that the indicator applies to. Possible values are: mac, windows, linux. | Optional | 
| severity | The severity level to apply to this indicator. Required for the prevent and detect actions. Optional for no_action. Possible values are: informational, low, medium, high, critical. | Optional | 
| expiration | The datetime the indicator will become inactive (ISO 8601 format, i.e., YYYY-MM-DDThh:mm:ssZ). | Optional | 
| source | The source where this indicator originated. This can be used for tracking where this indicator was defined. Limited to 200 characters. | Optional | 
| description | A meaningful description of the indicator. Limited to 200 characters. | Optional | 
| file_name | Name of the file for file indicators. Applies to hashes only. A common filename, or a filename in your environment. Filenames can be helpful for identifying hashes or filtering IOCs. | Optional | 

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
| CrowdStrike.IOC.Filename | string | Name of the file for file indicators. Applies to hashes only. A common filename, or a filename in your environment. Filenames can be helpful for identifying hashes or filtering IOCs. | 

### cs-falcon-delete-custom-ioc

***
Deletes a monitored indicator.

#### Base Command

`cs-falcon-delete-custom-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_id | The ID of the IOC to delete. The ID of the IOC can be retrieved by running the 'cs-falcon-search-custom-iocs' command. | Required | 

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
| type | The IOC type. Possible values are: sha256, sha1, md5, domain, ipv4, ipv6. | Required | 
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
| type | The IOC type. Possible values are: sha256, sha1, md5, domain, ipv4, ipv6. | Required | 
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
| type | The type of indicator. Possible values are: domain, ipv4, ipv6, md5, sha1, sha256. | Required | 
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
| ids | A comma-separated list of detection IDs. For example, ldt:1234:1234,ldt:5678:5678. If you use this argument, the fetch_query argument will be ignored. | Optional | 

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
| CrowdStrike.Detections.device.hostname | String | The hostname of the device. | 
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
| CrowdStrike.Detections.behaviors.behavior_id | String | The ID of the behavior. Note: This output exists only in the legacy version. | 
| CrowdStrike.Detections.behaviors.filename | String | The filename of the triggering process. | 
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
| CrowdStrike.Detections.behaviors.ioc_source | String | The source that triggered an IOC detection. Possible values are: "library_load", "primary_module", "file_read", and "file_write". Note: This output exist only in the legacy version. | 
| CrowdStrike.Detections.behaviors.ioc_description | String | The IOC description. Note: This output exists only in the legacy version. | 
| CrowdStrike.Detections.behaviors.user_name | String | The user name. | 
| CrowdStrike.Detections.behaviors.user_id | String | The Security Identifier \(SID\) of the user in Windows. | 
| CrowdStrike.Detections.behaviors.control_graph_id | String | The behavior hit key for the Threat Graph API. | 
| CrowdStrike.Detections.behaviors.triggering_process_graph_id | String | The ID of the process that triggered the behavior detection. | 
| CrowdStrike.Detections.behaviors.sha256 | String | The SHA256 of the triggering process. | 
| CrowdStrike.Detections.behaviors.md5 | String | The MD5 hash of the triggering process. | 
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
| CrowdStrike.Detections.first_behavior | Date | The datetime of the first behavior. Note: This output exists only in the legacy version. | 
| CrowdStrike.Detections.last_behavior | Date | The datetime of the last behavior. Note: This output exists only in the legacy version. | 
| CrowdStrike.Detections.max_confidence | Number | The highest confidence value of all behaviors. The value can be any integer between 1-100. Note: This output exists only in the legacy version. | 
| CrowdStrike.Detections.max_severity | Number | The highest severity value of all behaviors. Value can be any integer between 1-100. Note: This output exists only in the legacy version. | 
| CrowdStrike.Detections.max_severity_displayname | String | The name used in the UI to determine the severity of the detection. Possible values are: "Critical", "High", "Medium", and "Low". Note: This output exists only in the legacy version. | 
| CrowdStrike.Detections.show_in_ui | Boolean | Whether the detection displays in the UI. | 
| CrowdStrike.Detections.status | String | The status of the detection. | 
| CrowdStrike.Detections.assigned_to_uid | String | The UID of the user for whom the detection is assigned. Note: This output exists only in the legacy version. | 
| CrowdStrike.Detections.assigned_to_name | String | The human-readable name of the user to whom the detection is currently assigned. Note: This output exists only in the legacy version. | 
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
| ids | A comma-separated list of detection IDs. For example, ldt:1234:1234,ldt:5678:5678. If you use this argument, the fetch_query argument will be ignored. | Optional | 

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
| CrowdStrike.Incidents.hosts.first_seen | Date | The datetime the host was first seen by CrowdStrike Falcon. | 
| CrowdStrike.Incidents.hosts.last_seen | Date | The datetime the host was last seen by CrowdStrike Falcon. | 
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
| CrowdStrike.Incidents.created | Date | The datetime that the incident was created. | 
| CrowdStrike.Incidents.start | Date | The recorded datetime of the earliest incident. | 
| CrowdStrike.Incidents.end | Date | The recorded datetime of the latest incident. | 
| CrowdStrike.Incidents.state | String | The state of the incident. | 
| CrowdStrike.Incidents.status | Number | The status of the incident. | 
| CrowdStrike.Incidents.name | String | The name of the incident. | 
| CrowdStrike.Incidents.description | String | The description of the incident. | 
| CrowdStrike.Incidents.tags | String | The tags of the incident. | 
| CrowdStrike.Incidents.fine_score | Number | The incident score. | 

### endpoint

***
Returns information about an endpoint. Does not support regex.

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
| group_type | The group type of the group. Possible values are: static, dynamic. | Required | 
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
| sort | The property to sort by (e.g., status.desc or hostname.asc). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Device.ID | String | The ID of the device. | 
| CrowdStrike.Device.LocalIP | String | The local IP address of the device. | 
| CrowdStrike.Device.ExternalIP | String | The external IP address of the device. | 
| CrowdStrike.Device.Hostname | String | The hostname of the device. | 
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
| host_ids | A comma-separated list of host agent IDs to run commands. The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command. | Required | 

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
| host_ids | A comma-separated list of host agent IDs to run commands. The list of host agent IDs can be retrieved by running the 'cs-falcon-search-device' command. | Required | 

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
Resolve and update incidents using the specified settings.

#### Base Command

`cs-falcon-resolve-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of incident IDs. | Required | 
| status | The new status of the incident. Possible values are: New, In Progress, Reopened, Closed. | Optional | 
| assigned_to_uuid | UUID of a user to assign the incident to. Mutually exclusive with the 'username' argument. | Optional | 
| username | Username of a user to assign the incident to. Mutually exclusive with the 'assigned_to_uuid' argument. Using this parameter instead of 'assigned_to_uuid' will result in an additional API call in order to fetch the UUID of the user. | Optional | 
| add_tag | Add a new tag to the incidents. | Optional | 
| remove_tag | Remove a tag from the incidents. | Optional | 
| add_comment | Add a comment to the incident. | Optional | 

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
| multiple_indicators_json | A JSON object with a list of CrowdStrike Falcon indicators to upload. | Required | 
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
| host_id | The host ID to kill the given process for. | Required | 
| process_ids | A comma-separated list of process IDs to kill. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. Default is false. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.kill.ProcessID | String | The process ID that was killed. | 
| CrowdStrike.Command.kill.Error | String | The error message raised if the command failed. | 
| CrowdStrike.Command.kill.HostID | String | The host ID. | 

### cs-falcon-rtr-remove-file

***
Batch executes an RTR active-responder remove file across the hosts mapped to the given batch ID.

#### Base Command

`cs-falcon-rtr-remove-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the hosts IDs to remove the file for. | Required | 
| file_path | The path to a file or a directory to remove. | Required | 
| os | The operating system of the hosts given. Since the remove command is different in each operating system, you can choose only one operating system. Possible values are: Windows, Linux, Mac. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. Default is false. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 

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
| host_id | The host ID to get the processes list from. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. Default is false. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.ps.Filename | String | The name of the result file to be returned. | 

### cs-falcon-rtr-list-network-stats

***
Executes an RTR active-responder netstat command to get a list of network status and protocol statistics across the given host.

#### Base Command

`cs-falcon-rtr-list-network-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID to get the network status and protocol statistics list from. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. Default is false. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.netstat.Filename | String | The name of the result file to be returned. | 

### cs-falcon-rtr-read-registry

***
Executes an RTR active-responder read registry keys command across the given hosts. This command is valid only for Windows hosts.

#### Base Command

`cs-falcon-rtr-read-registry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma-separated list of the host IDs to get the registry keys from. | Required | 
| registry_keys | A comma-separated list of the registry keys, sub-keys, or value to get. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. Default is false. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 

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
| host_ids | A comma-separated list of the hosts IDs to get the list of scheduled tasks from. | Required | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. Default is false. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 

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
| host_ids | A comma-separated list of the hosts IDs to get the file from. | Required | 
| file_path | The file path of the required file to extract. | Required | 
| filename | The filename to use for the archive name and the file within the archive. | Optional | 
| interval_in_seconds | Interval between polling. Default is 60 seconds. Must be higher than 10. | Optional | 
| hosts_and_requests_ids | This is an internal argument used for the polling process, not to be used by the user. | Optional | 
| SHA256 | This is an internal argument used for the polling process, not to be used by the user. | Optional | 
| queue_offline | Whether the command will run against an offline-queued session and be queued for execution when the host comes online. Default is false. | Optional | 
| timeout | The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. | Optional | 
| polling_timeout | Timeout for polling. Default is 600 seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.FileName | String | The filename. | 
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
| incident_id | The incident ID to get detections for. A list of all available incident IDs can be retrieved by running the 'cs-falcon-list-incident-summaries' command. | Required | 

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
| lastUpdate | Date string representing the local time in UTC timestamp in seconds. The incident or detection is only returned if it was modified after the last update time. | Optional | 

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
| aid | A comma-separated list of unique agent identifiers (AIDs) of a sensor. | Optional | 
| cve_id | A comma-separated list of unique identifiers for a vulnerability as cataloged in the National Vulnerability Database (NVD). This filter supports multiple values and negation. | Optional | 
| cve_severity | A comma-separated list of severities of the CVE. The possible values are: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, or NONE. | Optional | 
| tags | A comma-separated list of names of a tag assigned to a host. Retrieve tags from Host Tags APIs. | Optional | 
| status | Status of a vulnerability. This filter supports multiple values and negation. The possible values are: open, closed, reopen, expired. | Optional | 
| platform_name | Operating system platform. This filter supports negation. The possible values are: Windows, Mac, Linux. | Optional | 
| host_group | A comma-separated list of unique system-assigned IDs of a host group. Retrieve the host group ID from Host Group APIs. | Optional | 
| host_type | A comma-separated list of types of hosts a sensor is running on. | Optional | 
| last_seen_within | Filter for vulnerabilities based on the number of days since a host last connected to CrowdStrike Falcon. Enter a numeric value from 3 to 45 to indicate the number of days  to look back. For example, last_seen_within:10. | Optional | 
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
| CrowdStrike.Vulnerability.host_info.machine_domain | String | Active directory domain name. | 
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
| cve_id | Deprecated. Use cve instead. | Optional | 
| cve | Unique identifier for a vulnerability as cataloged in the National Vulnerability Database (NVD). This filter supports multiple values and negation. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
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
| CrowdStrike.VulnerabilityHost.host_info.machine_domain | String | Active directory domain name. | 
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
| value | Value to match for exclusion. | Required | 
| excluded_from | A comma-separated list from where to exclude the exclusion. Possible values are: blocking, extraction. | Required | 
| comment | Comment describing why the exclusions were created. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion OR all if empty. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | An hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Group ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Group type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Group name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Group description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Group assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | The date when the exclusion rule was created. | 
| CrowdStrike.MLExclusion.created_by | String | Indicate who created the rule. | 

### cs-falcon-update-ml-exclusion

***
Updates an ML exclusion. At least one argument is required in addition to the id argument.

#### Base Command

`cs-falcon-update-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the exclusion to update. | Required | 
| value | Value to match for the exclusion (the exclusion pattern). | Optional | 
| comment | Comment describing why the exclusions were created. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | A hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Group ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Group type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Group name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Group description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Group assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | The date when the exclusion rule was created. | 
| CrowdStrike.MLExclusion.created_by | String | Indicate who created the rule. | 

### cs-falcon-delete-ml-exclusion

***
Delete the ML exclusions by ID.

#### Base Command

`cs-falcon-delete-ml-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of exclusion IDs to delete. | Required | 

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
| filter | A custom filter by which the exclusions should be filtered.<br/> The syntax follows the pattern `&lt;property&gt;:[operator]'&lt;value&gt;'`. For example: value:'test'.<br/> Available filters: applied_globally, created_by, created_on, last_modified, modified_by, value.<br/> For more information, see: https://falcon.crowdstrike.com/documentation/page/d3c84a1b/falcon-query-language-fql. | Optional | 
| value | The value by which the exclusions should be filtered. | Optional | 
| ids | A comma-separated list of exclusion IDs to retrieve. The IDs overwrite the filter and value. | Optional | 
| limit | The maximum number of records to return. [1-500]. Applies only if the ids argument is not supplied. | Optional | 
| offset | The offset to start retrieving records from. Applies only if the ids argument is not supplied. | Optional | 
| sort | How to sort the retrieved exclusions. Possible values are: applied_globally.asc, applied_globally.desc, created_by.asc, created_by.desc, created_on.asc, created_on.desc, last_modified.asc, last_modified.desc, modified_by.asc, modified_by.desc, value.asc, value.desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.MLExclusion.id | String | The ML exclusion ID. | 
| CrowdStrike.MLExclusion.value | String | The ML exclusion value. | 
| CrowdStrike.MLExclusion.regexp_value | String | A regular expression for matching the excluded value. | 
| CrowdStrike.MLExclusion.value_hash | String | A hash of the value field. | 
| CrowdStrike.MLExclusion.excluded_from | String | What the exclusion applies to \(e.g., a specific ML model\). | 
| CrowdStrike.MLExclusion.groups.id | String | Group ID that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.group_type | String | Group type that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.name | String | Group name that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.description | String | Group description that the exclusion rule is associated with. | 
| CrowdStrike.MLExclusion.groups.assignment_rule | String | Group assignment rule that the exclusion is associated with. | 
| CrowdStrike.MLExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.MLExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.MLExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.MLExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.MLExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.MLExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.MLExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.MLExclusion.created_on | Date | The date when the exclusion rule was created. | 
| CrowdStrike.MLExclusion.created_by | String | Indicate who created the rule. | 

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
| ifn_regex | Image filename regular expression. | Required | 
| comment | Comment describing why the exclusions were created. | Optional | 
| description | Exclusion description. | Optional | 
| detection_json | JSON formatted detection template. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion OR all if empty. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for filename matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Group ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Group type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Group name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Group description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Group assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | The date when the exclusion rule was created. | 
| CrowdStrike.IOAExclusion.created_by | String | Indicate who created the rule. | 

### cs-falcon-update-ioa-exclusion

***
Updates an IOA exclusion. At least one argument is required in addition to the id argument.

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
| ifn_regex | Image filename regular expression. | Optional | 
| comment | Comment describing why the exclusions was created. | Optional | 
| description | Exclusion description. | Optional | 
| detection_json | JSON formatted detection template. | Optional | 
| groups | A comma-separated list of group ID(s) impacted by the exclusion. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for filename matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Group ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Group type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Group name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Group description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Group assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | The date when the exclusion rule was created. | 
| CrowdStrike.IOAExclusion.created_by | String | Indicate who created the rule. | 

### cs-falcon-delete-ioa-exclusion

***
Delete the IOA exclusions by ID.

#### Base Command

`cs-falcon-delete-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of exclusion IDs to delete. | Required | 

#### Context Output

There is no context output for this command.
### cs-falcon-search-ioa-exclusion

***
Get a list of IOA exclusions by specifying their IDs or a filter.

#### Base Command

`cs-falcon-search-ioa-exclusion`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | A custom filter by which the exclusions should be filtered.<br/> The syntax follows the pattern `&lt;property&gt;:[operator]'&lt;value&gt;'`. For example: name:'test'.<br/> Available filters: applied_globally, created_by, created_on, name, last_modified, modified_by, value, pattern.<br/> For more information, see: https://www.falconpy.io/Service-Collections/Falcon-Query-Language. | Optional | 
| name | The name by which the exclusions should be filtered. | Optional | 
| ids | A comma-separated list of exclusion IDs to retrieve. The IDs overwrite the filter and name. | Optional | 
| limit | The limit of how many exclusions to retrieve. Default is 50. Applies only if the ids argument is not supplied. | Optional | 
| offset | The offset of how many exclusions to skip. Default is 0. Applies only if the ids argument is not supplied. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOAExclusion.id | String | A unique identifier for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.name | String | The name of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.description | String | A description of the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_id | String | The identifier of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.pattern_name | String | The name of the pattern associated with the IOA exclusion. | 
| CrowdStrike.IOAExclusion.ifn_regex | String | A regular expression used for filename matching. | 
| CrowdStrike.IOAExclusion.cl_regex | String | A regular expression used for command line matching. | 
| CrowdStrike.IOAExclusion.detection_json | String | A JSON string that describes the detection logic for the IOA exclusion. | 
| CrowdStrike.IOAExclusion.groups.id | String | Group ID that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.group_type | String | Group type that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.name | String | Group name that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.description | String | Group description that the exclusion rule is associated with. | 
| CrowdStrike.IOAExclusion.groups.assignment_rule | String | Group assignment rule that the exclusion is associated with. | 
| CrowdStrike.IOAExclusion.groups.created_by | String | Indicate who created the group. | 
| CrowdStrike.IOAExclusion.groups.created_timestamp | Date | The date when the group was created. | 
| CrowdStrike.IOAExclusion.groups.modified_by | String | Indicate who last modified the group. | 
| CrowdStrike.IOAExclusion.groups.modified_timestamp | Date | The date when the group was last modified. | 
| CrowdStrike.IOAExclusion.applied_globally | Boolean | Whether the exclusion rule applies globally or only to specific entities. | 
| CrowdStrike.IOAExclusion.last_modified | Date | The date when the exclusion rule was last modified. | 
| CrowdStrike.IOAExclusion.modified_by | String | Indicate who last modified the rule. | 
| CrowdStrike.IOAExclusion.created_on | Date | The date when the exclusion rule was created. | 
| CrowdStrike.IOAExclusion.created_by | String | Indicate who created the rule. | 

### cs-falcon-list-quarantined-file

***
Get quarantine file metadata by specified IDs or filter.

#### Base Command

`cs-falcon-list-quarantined-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of quarantined file IDs to retrieve. | Optional | 
| filter | A custom filter by which the retrieved quarantined file should be filtered. | Optional | 
| sha256 | A comma-separated list of SHA256 hash of the files to retrieve. | Optional | 
| filename | A comma-separated list of the name of the files to retrieve. | Optional | 
| state | Filter the retrieved files by state. | Optional | 
| hostname | A comma-separated list of the hostnames of the files to retrieve. | Optional | 
| username | A comma-separated list of the usernames of the files to retrieve. | Optional | 
| limit | Maximum number of IDs to return. Max 5000. Default 50. | Optional | 
| offset | Starting index of the overall result set from which to return IDs. Default 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.QuarantinedFile.id | String | A unique identifier for the quarantined file. | 
| CrowdStrike.QuarantinedFile.aid | String | The agent identifier of the agent that quarantined the file. | 
| CrowdStrike.QuarantinedFile.cid | String | The unique customer identifier of the agent that quarantined the file. | 
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

### cs-falcon-apply-quarantine-file-action

***
Apply action to quarantined files by file IDs or filter.

#### Base Command

`cs-falcon-apply-quarantine-file-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of quarantined file IDs to update. | Optional | 
| action | Action to perform against the quarantined file. Possible values are: delete, release, unrelease. | Required | 
| comment | Comment to appear along with the action taken. | Required | 
| filter | Update files based on a custom filter. | Optional | 
| sha256 | A comma-separated list of quarantined SHA256 files to update. | Optional | 
| filename | A comma-separated list of quarantined filenames to update. | Optional | 
| state | Update files based on the state. | Optional | 
| hostname | A comma-separated list of quarantined file hostnames to update. | Optional | 
| username | A comma-separated list of quarantined file usernames to update. | Optional | 

#### Context Output

There is no context output for this command.
### cs-falcon-ods-query-scan

***
Retrieve ODS scan details.

#### Base Command

`cs-falcon-ods-query-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| wait_for_result | Whether to poll for results. Possible values are: true, false. Default is false. | Optional | 
| filter | Valid CS-Falcon-FQL filter to query with. | Optional | 
| ids | Comma-separated list of scan IDs to retrieve details about. If set, will override all other arguments. | Optional | 
| initiated_from | Comma-separated list of scan initiation sources to filter by. | Optional | 
| status | Comma-separated list of scan statuses to filter by. | Optional | 
| severity | Comma-separated list of scan severities to filter by. | Optional | 
| scan_started_on | UTC-format of the scan start time to filter by. | Optional | 
| scan_completed_on | UTC-format of the scan completion time to filter by. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Maximum number of resources to return. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 
| hide_polling_output | Whether to hide the polling message and only print the final status at the end (automatically filled by polling. Can be used for testing purposes). Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScan.id | String | A unique identifier for the scan event. | 
| CrowdStrike.ODSScan.cid | String | A unique identifier for the client that triggered the scan. | 
| CrowdStrike.ODSScan.profile_id | String | A unique identifier for the scan profile used in the scan. | 
| CrowdStrike.ODSScan.description | String | The ID of the description of the scan. | 
| CrowdStrike.ODSScan.scan_inclusions | String | The files or folders included in the scan. | 
| CrowdStrike.ODSScan.initiated_from | String | The source of the scan initiation. | 
| CrowdStrike.ODSScan.quarantine | Boolean | Whether the scan was set to quarantine. | 
| CrowdStrike.ODSScan.cpu_priority | Number | The CPU priority for the scan \(1-5\). | 
| CrowdStrike.ODSScan.preemption_priority | Number | The preemption priority for the scan. | 
| CrowdStrike.ODSScan.metadata.host_id | String | A unique identifier for the host that was scanned. | 
| CrowdStrike.ODSScan.metadata.host_scan_id | String | A unique identifier for the scan that was performed on the host. | 
| CrowdStrike.ODSScan.metadata.scan_host_metadata_id | String | A unique identifier for the metadata associated with the host scan. | 
| CrowdStrike.ODSScan.metadata.filecount.scanned | Number | The number of files that were scanned. | 
| CrowdStrike.ODSScan.metadata.filecount.malicious | Number | The number of files that were identified as malicious. | 
| CrowdStrike.ODSScan.metadata.filecount.quarantined | Number | The number of files that were quarantined. | 
| CrowdStrike.ODSScan.metadata.filecount.skipped | Number | The number of files that were skipped during the scan. | 
| CrowdStrike.ODSScan.metadata.filecount.traversed | Number | The number of files that were traversed during the scan. | 
| CrowdStrike.ODSScan.metadata.status | String | The status of the scan on this host. \(e.g., "pending", "running", "completed", or "failed"\). | 
| CrowdStrike.ODSScan.metadata.started_on | Date | The date and time that the scan started. | 
| CrowdStrike.ODSScan.metadata.completed_on | Date | The date and time that the scan completed. | 
| CrowdStrike.ODSScan.metadata.last_updated | Date | The date and time that the metadata was last updated. | 
| CrowdStrike.ODSScan.status | String | The status of the scan \(e.g., "pending", "running", "completed", or "failed"\). | 
| CrowdStrike.ODSScan.hosts | String | A list of the host IDs that were scanned. | 
| CrowdStrike.ODSScan.endpoint_notification | Boolean | Indicates whether endpoint notifications are enabled. | 
| CrowdStrike.ODSScan.pause_duration | Number | The number of hours to pause between scanning each file. | 
| CrowdStrike.ODSScan.max_duration | Number | The maximum amount of time to allow for the scan job in hours. | 
| CrowdStrike.ODSScan.max_file_size | Number | The maximum file size \(in MB\) to scan. | 
| CrowdStrike.ODSScan.sensor_ml_level_detection | Number | The level of detection sensitivity for the local sensor machine learning model. | 
| CrowdStrike.ODSScan.sensor_ml_level_prevention | Number | The level of prevention sensitivity for the local sensor machine learning model. | 
| CrowdStrike.ODSScan.cloud_ml_level_detection | Number | The level of detection sensitivity for the cloud machine learning model. | 
| CrowdStrike.ODSScan.cloud_ml_level_prevention | Number | The level of prevention sensitivity for the cloud machine learning model. | 
| CrowdStrike.ODSScan.policy_setting | Number | A list of policy setting IDs for the scan job \(these correspond to specific policy settings in the Falcon console\). | 
| CrowdStrike.ODSScan.scan_started_on | Date | The timestamp when the scan was started. | 
| CrowdStrike.ODSScan.scan_completed_on | Date | The timestamp when the scan was completed. | 
| CrowdStrike.ODSScan.created_on | Date | The timestamp when the scan was created. | 
| CrowdStrike.ODSScan.created_by | String | The ID of the user who created the scan job. | 
| CrowdStrike.ODSScan.last_updated | Date | The timestamp when the scan job was last updated. | 

### cs-falcon-ods-query-scheduled-scan

***
Retrieve ODS scheduled scan details.

#### Base Command

`cs-falcon-ods-query-scheduled-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Valid CS-Falcon-FQL filter to query with. | Optional | 
| ids | Comma-separated list of scan IDs to retrieve details about. If set, will override all other arguments. | Optional | 
| initiated_from | Comma-separated list of scan initiation sources to filter by. | Optional | 
| status | Comma-separated list of scan statuses to filter by. | Optional | 
| created_on | UTC-format of the scan creation time to filter by. | Optional | 
| created_by | UTC-format time of the scan creator to filter by. | Optional | 
| start_timestamp | UTC-format of scan start time to filter by. | Optional | 
| deleted | Deleted scans only. | Optional | 
| offset | Starting index of overall result set from which to return IDs. | Optional | 
| limit | Maximum number of resources to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScheduledScan.id | String | Unique identifier for the scan. | 
| CrowdStrike.ODSScheduledScan.cid | String | Identifier for the customer or organization that owns the scan. | 
| CrowdStrike.ODSScheduledScan.description | String | The ID of the description of the scan. | 
| CrowdStrike.ODSScheduledScan.file_paths | String | The file or folder paths scanned. | 
| CrowdStrike.ODSScheduledScan.scan_exclusions | String | The file or folder exclusions from the scan. | 
| CrowdStrike.ODSScheduledScan.initiated_from | String | The source of the scan initiation. | 
| CrowdStrike.ODSScheduledScan.cpu_priority | Number | The CPU priority for the scan \(1-5\). | 
| CrowdStrike.ODSScheduledScan.preemption_priority | Number | The preemption priority for the scan. | 
| CrowdStrike.ODSScheduledScan.status | String | The status of the scan, whether it's "scheduled", "running", "completed", etc. | 
| CrowdStrike.ODSScheduledScan.host_groups | String | The host groups targeted by the scan. | 
| CrowdStrike.ODSScheduledScan.endpoint_notification | Boolean | Whether notifications of the scan were sent to endpoints. | 
| CrowdStrike.ODSScheduledScan.pause_duration | Number | The pause duration of the scan in hours. | 
| CrowdStrike.ODSScheduledScan.max_duration | Number | The maximum duration of the scan in hours. | 
| CrowdStrike.ODSScheduledScan.max_file_size | Number | The maximum file size that the scan can handle in MB. | 
| CrowdStrike.ODSScheduledScan.sensor_ml_level_detection | Number | The machine learning detection level for the sensor. | 
| CrowdStrike.ODSScheduledScan.cloud_ml_level_detection | Number | The machine learning detection level for the cloud. | 
| CrowdStrike.ODSScheduledScan.schedule.start_timestamp | Date | The timestamp when the first scan was created. | 
| CrowdStrike.ODSScheduledScan.schedule.interval | Number | The interval between scans. | 
| CrowdStrike.ODSScheduledScan.created_on | Date | The timestamp when the scan was created. | 
| CrowdStrike.ODSScheduledScan.created_by | String | The user who created the scan. | 
| CrowdStrike.ODSScheduledScan.last_updated | Date | The timestamp when the scan was last updated. | 
| CrowdStrike.ODSScheduledScan.deleted | Boolean | Whether the scan was deleted. | 
| CrowdStrike.ODSScheduledScan.quarantine | Boolean | Whether the scan was set to quarantine. | 
| CrowdStrike.ODSScheduledScan.metadata.host_id | String | Scan host IDs. | 
| CrowdStrike.ODSScheduledScan.metadata.last_updated | Date | The date and time when the detection event was last updated. | 
| CrowdStrike.ODSScheduledScan.sensor_ml_level_prevention | Number | The machine learning prevention level for the sensor. | 
| CrowdStrike.ODSScheduledScan.cloud_ml_level_prevention | Number | The machine learning prevention level for the cloud. | 

### cs-falcon-ods-query-scan-host

***
Retrieve ODS scan host details.

#### Base Command

`cs-falcon-ods-query-scan-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Valid CS-Falcon-FQL filter to query with. | Optional | 
| host_ids | Comma-separated list of host IDs to filter by. | Optional | 
| scan_ids | Comma-separated list of scan IDs to filter by. | Optional | 
| status | Comma-separated list of scan statuses to filter by. | Optional | 
| started_on | UTC-format of scan start time to filter by. | Optional | 
| completed_on | UTC-format of scan completion time to filter by. | Optional | 
| offset | Starting index of the overall result set from which to return IDs. | Optional | 
| limit | Maximum number of resources to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScanHost.id | String | A unique identifier for the scan event. | 
| CrowdStrike.ODSScanHost.cid | String | A unique identifier for the client that triggered the scan. | 
| CrowdStrike.ODSScanHost.scan_id | String | A unique identifier for the scan. | 
| CrowdStrike.ODSScanHost.profile_id | String | A unique identifier for the scan profile used in the scan. | 
| CrowdStrike.ODSScanHost.host_id | String | A unique identifier for the host that was scanned. | 
| CrowdStrike.ODSScanHost.host_scan_id | String | A unique identifier for the scan that was performed on the host. | 
| CrowdStrike.ODSScanHost.filecount.scanned | Number | The number of files that were scanned during the scan. | 
| CrowdStrike.ODSScanHost.filecount.malicious | Number | The number of files that were detected as malicious during the scan. | 
| CrowdStrike.ODSScanHost.filecount.quarantined | Number | The number of files that were quarantined during the scan. | 
| CrowdStrike.ODSScanHost.filecount.skipped | Number | The number of files that were skipped during the scan. | 
| CrowdStrike.ODSScanHost.status | String | The status of the scan. \(e.g., "completed", "pending", "cancelled", "running", or "failed"\). | 
| CrowdStrike.ODSScanHost.severity | Number | A severity score assigned to the scan, ranging from 0 to 100. | 
| CrowdStrike.ODSScanHost.started_on | Date | The date and time when the scan started. | 
| CrowdStrike.ODSScanHost.completed_on | Date | The date and time when the scan completed. | 
| CrowdStrike.ODSScanHost.last_updated | Date | The date and time when the scan event was last updated. | 

### cs-falcon-ods-query-malicious-files

***
Retrieve ODS malicious file details.

#### Base Command

`cs-falcon-ods-query-malicious-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Valid CS-Falcon-FQL filter to query with. | Optional | 
| file_ids | Comma-separated list of malicious file IDs to retrieve details about. If set, will override all other arguments. | Optional | 
| host_ids | Comma-separated list of host IDs to filter by. | Optional | 
| scan_ids | Comma-separated list of scan IDs to filter by. | Optional | 
| file_paths | Comma-separated list of file paths to filter by. | Optional | 
| file_names | Comma-separated list of filenames to filter by. | Optional | 
| hash | Comma-separated list of hashes to filter by. | Optional | 
| offset | Starting index of the overall result set from which to return IDs. | Optional | 
| limit | Maximum number of resources to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSMaliciousFile.id | String | A unique identifier of the detection event. | 
| CrowdStrike.ODSMaliciousFile.cid | String | A unique identifier for the client that triggered the detection event. | 
| CrowdStrike.ODSMaliciousFile.scan_id | String | A unique identifier for the scan that triggered the detection event. | 
| CrowdStrike.ODSMaliciousFile.host_id | String | A unique identifier for the host that was scanned. | 
| CrowdStrike.ODSMaliciousFile.host_scan_id | String | A unique identifier for the scan that detected the file on the host. | 
| CrowdStrike.ODSMaliciousFile.filepath | String | The full path to the malicious file on the host system. | 
| CrowdStrike.ODSMaliciousFile.filename | String | The name of the malicious file. | 
| CrowdStrike.ODSMaliciousFile.hash | String | A SHA256 hash of the malicious file, which can be used to identify it. | 
| CrowdStrike.ODSMaliciousFile.pattern_id | Number | The identifier of the pattern used to detect the malicious file. | 
| CrowdStrike.ODSMaliciousFile.severity | Number | A severity score assigned to the detection event, ranging from 0 to 100. | 
| CrowdStrike.ODSMaliciousFile.quarantined | Boolean | Indicates whether the file was quarantined. | 
| CrowdStrike.ODSMaliciousFile.last_updated | Date | The date and time when the detection event was last updated. | 

### cs-falcon-ods-create-scan

***
Create an ODS scan and wait for the results.

#### Base Command

`cs-falcon-ods-create-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hosts | A comma-separated list of hosts to be scanned. "hosts" OR "host_groups" must be set. | Optional | 
| host_groups | A comma-separated list of host groups to be scanned. "hosts" OR "host_groups" must be set. | Optional | 
| file_paths | A comma-separated list of file paths to be scanned. "file_paths" OR "scan_inclusions" must be set. | Optional | 
| scan_inclusions | A comma-separated list of included files or locations for this scan. "file_paths" OR "scan_inclusions" must be set. | Optional | 
| scan_exclusions | A comma-separated list of excluded files or locations for this scan. | Optional | 
| initiated_from | Scan origin. | Optional | 
| cpu_priority | The scan CPU priority. Possible values are: Highest, High, Medium, Low, Lowest. Default is Low. | Optional | 
| description | Scan description. | Optional | 
| quarantine | Flag indicating if identified threats should be quarantined. | Optional | 
| pause_duration | Amount of time (in hours) for scan pauses. Default is 2. | Optional | 
| sensor_ml_level_detection | Sensor ML detection level. | Optional | 
| sensor_ml_level_prevention | Sensor ML prevention level. | Optional | 
| cloud_ml_level_detection | Cloud ML detection level for the scan. | Optional | 
| cloud_ml_level_prevention | Cloud ML prevention level for the scan. | Optional | 
| max_duration | Maximum time (in hours) the scan is allowed to execute. Default is 2. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScan.id | String | A unique identifier for the scan event. | 
| CrowdStrike.ODSScan.cid | String | A unique identifier for the client that triggered the scan. | 
| CrowdStrike.ODSScan.profile_id | String | A unique identifier for the scan profile used in the scan. | 
| CrowdStrike.ODSScan.description | String | The ID of the description of the scan. | 
| CrowdStrike.ODSScan.scan_inclusions | String | The files or folders included in the scan. | 
| CrowdStrike.ODSScan.initiated_from | String | The source of the scan initiation. | 
| CrowdStrike.ODSScan.quarantine | Boolean | Whether the scan was set to quarantine. | 
| CrowdStrike.ODSScan.cpu_priority | Number | The CPU priority for the scan \(1-5\). | 
| CrowdStrike.ODSScan.preemption_priority | Number | The preemption priority for the scan. | 
| CrowdStrike.ODSScan.metadata.host_id | String | A unique identifier for the host that was scanned. | 
| CrowdStrike.ODSScan.metadata.host_scan_id | String | A unique identifier for the scan that was performed on the host. | 
| CrowdStrike.ODSScan.metadata.scan_host_metadata_id | String | A unique identifier for the metadata associated with the host scan. | 
| CrowdStrike.ODSScan.metadata.filecount.scanned | Number | The number of files that were scanned. | 
| CrowdStrike.ODSScan.metadata.filecount.malicious | Number | The number of files that were identified as malicious. | 
| CrowdStrike.ODSScan.metadata.filecount.quarantined | Number | The number of files that were quarantined. | 
| CrowdStrike.ODSScan.metadata.filecount.skipped | Number | The number of files that were skipped during the scan. | 
| CrowdStrike.ODSScan.metadata.filecount.traversed | Number | The number of files that were traversed during the scan. | 
| CrowdStrike.ODSScan.metadata.status | String | The status of the scan on this host \(e.g., "pending", "running", "completed", or "failed"\). | 
| CrowdStrike.ODSScan.metadata.started_on | Date | The date and time that the scan started. | 
| CrowdStrike.ODSScan.metadata.completed_on | Date | The date and time that the scan completed. | 
| CrowdStrike.ODSScan.metadata.last_updated | Date | The date and time that the metadata was last updated. | 
| CrowdStrike.ODSScan.status | String | The status of the scan \(e.g., "pending", "running", "completed", or "failed"\). | 
| CrowdStrike.ODSScan.hosts | String | A list of the host IDs that were scanned. | 
| CrowdStrike.ODSScan.endpoint_notification | Boolean | Indicates whether endpoint notifications are enabled. | 
| CrowdStrike.ODSScan.pause_duration | Number | The number of hours to pause between scanning each file. | 
| CrowdStrike.ODSScan.max_duration | Number | The maximum amount of time to allow for the scan job in hours. | 
| CrowdStrike.ODSScan.max_file_size | Number | The maximum file size \(in MB\) to scan. | 
| CrowdStrike.ODSScan.sensor_ml_level_detection | Number | The level of detection sensitivity for the local sensor machine learning model. | 
| CrowdStrike.ODSScan.sensor_ml_level_prevention | Number | The level of prevention sensitivity for the local sensor machine learning model. | 
| CrowdStrike.ODSScan.cloud_ml_level_detection | Number | The level of detection sensitivity for the cloud machine learning model. | 
| CrowdStrike.ODSScan.cloud_ml_level_prevention | Number | The level of prevention sensitivity for the cloud machine learning model. | 
| CrowdStrike.ODSScan.policy_setting | Number | A list of policy setting IDs for the scan job \(these correspond to specific policy settings in the Falcon console\). | 
| CrowdStrike.ODSScan.scan_started_on | Date | The timestamp when the scan was started. | 
| CrowdStrike.ODSScan.scan_completed_on | Date | The timestamp when the scan was completed. | 
| CrowdStrike.ODSScan.created_on | Date | The timestamp when the scan was created. | 
| CrowdStrike.ODSScan.created_by | String | The ID of the user who created the scan job. | 
| CrowdStrike.ODSScan.last_updated | Date | The timestamp when the scan job was last updated. | 

### cs-falcon-ods-create-scheduled-scan

***
Create an ODS scheduled scan.

#### Base Command

`cs-falcon-ods-create-scheduled-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_groups | A comma-separated list of host groups to be scanned. | Required | 
| file_paths | A comma-separated list of file paths to be scanned. "file_paths" OR "scan_inclusions" must be set. | Optional | 
| scan_inclusions | A comma-separated list of included files or locations for this scan. "file_paths" OR "scan_inclusions" must be set. | Optional | 
| scan_exclusions | A comma-separated list of excluded files or locations for this scan. | Optional | 
| initiated_from | Scan origin. | Optional | 
| cpu_priority | The scan CPU priority. Possible values are: Highest, High, Medium, Low, Lowest. Default is Low. | Optional | 
| description | Scan description. | Optional | 
| quarantine | Flag indicating if identified threats should be quarantined. | Optional | 
| pause_duration | Amount of time (in hours) for scan pauses. Default is 2. | Optional | 
| sensor_ml_level_detection | Sensor ML detection level. | Optional | 
| sensor_ml_level_prevention | Sensor ML prevention level. | Optional | 
| cloud_ml_level_detection | Cloud ML detection level for the scan. | Optional | 
| cloud_ml_level_prevention | Cloud ML prevention level for the scan. | Optional | 
| max_duration | Maximum time (in hours) the scan is allowed to execute. Default is 2. | Optional | 
| schedule_start_timestamp | When to start the first scan. Supports english expressions such as "tomorrow" or "in an hour". | Required | 
| schedule_interval | The schedule interval. Possible values are: Never, Daily, Weekly, Every other week, Every four weeks, Monthly. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.ODSScheduledScan.id | String | Unique identifier for the scan. | 
| CrowdStrike.ODSScheduledScan.cid | String | Identifier for the customer or organization that owns the scan. | 
| CrowdStrike.ODSScheduledScan.description | String | The ID of the description of the scan. | 
| CrowdStrike.ODSScheduledScan.file_paths | String | The file or folder paths scanned. | 
| CrowdStrike.ODSScheduledScan.scan_exclusions | String | The file or folder exclusions from the scan. | 
| CrowdStrike.ODSScheduledScan.initiated_from | String | The source of the scan initiation. | 
| CrowdStrike.ODSScheduledScan.cpu_priority | Number | The CPU priority for the scan \(1-5\). | 
| CrowdStrike.ODSScheduledScan.preemption_priority | Number | The preemption priority for the scan. | 
| CrowdStrike.ODSScheduledScan.status | String | The status of the scan, whether it's "scheduled", "running", "completed", etc. | 
| CrowdStrike.ODSScheduledScan.host_groups | String | The host groups targeted by the scan. | 
| CrowdStrike.ODSScheduledScan.endpoint_notification | Boolean | Whether notifications of the scan were sent to endpoints. | 
| CrowdStrike.ODSScheduledScan.pause_duration | Number | The pause duration of the scan in hours. | 
| CrowdStrike.ODSScheduledScan.max_duration | Number | The maximum duration of the scan in hours. | 
| CrowdStrike.ODSScheduledScan.max_file_size | Number | The maximum file size that the scan can handle in MB. | 
| CrowdStrike.ODSScheduledScan.sensor_ml_level_detection | Number | The machine learning detection level for the sensor. | 
| CrowdStrike.ODSScheduledScan.cloud_ml_level_detection | Number | The machine learning detection level for the cloud. | 
| CrowdStrike.ODSScheduledScan.schedule.start_timestamp | Date | The timestamp when the first scan was created. | 
| CrowdStrike.ODSScheduledScan.schedule.interval | Number | The interval between scans. | 
| CrowdStrike.ODSScheduledScan.created_on | Date | The timestamp when the scan was created. | 
| CrowdStrike.ODSScheduledScan.created_by | String | The user who created the scan. | 
| CrowdStrike.ODSScheduledScan.last_updated | Date | The timestamp when the scan was last updated. | 
| CrowdStrike.ODSScheduledScan.deleted | Boolean | Whether the scan was deleted. | 
| CrowdStrike.ODSScheduledScan.quarantine | Boolean | Whether the scan was set to quarantine. | 
| CrowdStrike.ODSScheduledScan.metadata.host_id | String | Scan host IDs. | 
| CrowdStrike.ODSScheduledScan.metadata.last_updated | Date | The date and time when the detection event was last updated. | 
| CrowdStrike.ODSScheduledScan.sensor_ml_level_prevention | Number | The machine learning prevention level for the sensor. | 
| CrowdStrike.ODSScheduledScan.cloud_ml_level_prevention | Number | The machine learning prevention level for the cloud. | 

### cs-falcon-ods-delete-scheduled-scan

***
Delete ODS scheduled scans.

#### Base Command

`cs-falcon-ods-delete-scheduled-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Comma-separated list of scheduled scan IDs to delete. | Optional | 
| filter | Valid CS-Falcon-FQL filter to delete scans by. | Optional | 

#### Context Output

There is no context output for this command.
### cs-falcon-list-identity-entities

***
List identity entities.

#### Base Command

`cs-falcon-list-identity-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | API type. Possible values are: USER, ENDPOINT. | Required | 
| sort_key | The key to sort by. Possible values are: RISK_SCORE, PRIMARY_DISPLAY_NAME, SECONDARY_DISPLAY_NAME, MOST_RECENT_ACTIVITY, ENTITY_ID. | Optional | 
| sort_order | The sort order. Possible values are: DESCENDING, ASCENDING. Default is ASCENDING. | Optional | 
| entity_id | A comma-separated list of entity IDs to look for. | Optional | 
| primary_display_name | A comma-separated list of primary display names to filter by. | Optional | 
| secondary_display_name | A comma-separated list of secondary display names to filter by. | Optional | 
| max_risk_score_severity | The maximum risk score severity to filter by. Possible values are: NORMAL, MEDIUM, HIGH. | Optional | 
| min_risk_score_severity | The minimum risk score severity to filter by. Possible values are: NORMAL, MEDIUM, HIGH. | Optional | 
| enabled | Whether to get only enabled or disabled identity entities. Possible values are: true, false. | Optional | 
| email | Email to filter by. | Optional | 
| next_token | The hash for the next page. | Optional | 
| page_size | The maximum number of items to fetch per page. The maximum value allowed is 1000. Default is 50. | Optional | 
| page | The page number. Default is 1. | Optional | 
| limit | The maximum number of identity entities to list. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IDPEntity.IsHuman | Boolean | Whether the identity entity is human made. | 
| CrowdStrike.IDPEntity.IsProgrammatic | Boolean | Whether the identity entity is programmatic made. | 
| CrowdStrike.IDPEntity.IsAdmin | String | Whether the identity entity is admin made. | 
| CrowdStrike.IDPEntity.PrimaryDisplayName | String | The identity entity primary display name. | 
| CrowdStrike.IDPEntity.RiskFactors.Type | Unknown | The identity entity risk factor type. | 
| CrowdStrike.IDPEntity.RiskFactors.Severity | Unknown | The identity entity risk factor severity. | 
| CrowdStrike.IDPEntity.RiskScore | Number | The identity entity risk score. | 
| CrowdStrike.IDPEntity.RiskScoreSeverity | String | The identity entity risk score severity. | 
| CrowdStrike.IDPEntity.SecondaryDisplayName | String | The identity entity secondary display name. | 
| CrowdStrike.IDPEntity.EmailAddresses | String | The identity entity email address. | 

### cs-falcon-cspm-list-policy-details

***
Given a CSV list of policy IDs, returns detailed policy information.

#### Base Command

`cs-falcon-cspm-list-policy-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_ids | Comma-separated list of policy IDs to look for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.CSPMPolicy.ID | Integer | The policy ID. | 
| CrowdStrike.CSPMPolicy.CreatedAt | Date | The creation date. | 
| CrowdStrike.CSPMPolicy.UpdatedAt | Date | The update date. | 
| CrowdStrike.CSPMPolicy.DeletedAt | Date | The deletion date. | 
| CrowdStrike.CSPMPolicy.description | String | The policy description. | 
| CrowdStrike.CSPMPolicy.policy_statement | String | The policy statement. | 
| CrowdStrike.CSPMPolicy.policy_remediation | String | The policy remediation. | 
| CrowdStrike.CSPMPolicy.cloud_service_subtype | String | The cloud service subtype. | 
| CrowdStrike.CSPMPolicy.cloud_document | String | The cloud document. | 
| CrowdStrike.CSPMPolicy.mitre_attack_cloud_matrix | String | URL to the MITRE attack tactics. | 
| CrowdStrike.CSPMPolicy.mitre_attack_cloud_subtype | String | URL to the MITRE attack techniques. | 
| CrowdStrike.CSPMPolicy.alert_logic | String | The alert logic. | 
| CrowdStrike.CSPMPolicy.api_command | String | The API command. | 
| CrowdStrike.CSPMPolicy.cli_command | String | The CLI command. | 
| CrowdStrike.CSPMPolicy.cloud_platform_type | String | The cloud platform type. | 
| CrowdStrike.CSPMPolicy.cloud_service_type | String | The cloud service type. | 
| CrowdStrike.CSPMPolicy.default_severity | String | The default severity. | 
| CrowdStrike.CSPMPolicy.cis_benchmark_ids | Array | The CIS benchmark IDs. | 
| CrowdStrike.CSPMPolicy.nist_benchmark_ids | Array | The NIST benchmark IDs. | 
| CrowdStrike.CSPMPolicy.pci_benchmark_ids | Array | The PCI benchmark IDs. | 
| CrowdStrike.CSPMPolicy.policy_type | String | The policy type. | 
| CrowdStrike.CSPMPolicy.tactic_url | String | The tactic URL. | 
| CrowdStrike.CSPMPolicy.technique_url | String | The technique URL. | 
| CrowdStrike.CSPMPolicy.tactic | String | The tactic used. | 
| CrowdStrike.CSPMPolicy.technique | String | The technique used. | 
| CrowdStrike.CSPMPolicy.tactic_id | String | The tactic ID. | 
| CrowdStrike.CSPMPolicy.technique_id | String | The technique ID. | 
| CrowdStrike.CSPMPolicy.attack_types | Array | The attack types. | 
| CrowdStrike.CSPMPolicy.asset_type_id | Integer | The asset type ID. | 
| CrowdStrike.CSPMPolicy.cloud_asset_type | String | The cloud asset type. | 
| CrowdStrike.CSPMPolicy.is_remediable | Boolean | Whether the policy is remediable or not. | 
| CrowdStrike.CSPMPolicy.is_enabled | Boolean | Whether the policy is enabled or not. | 
| CrowdStrike.CSPMPolicy.account_scope | String | The account scope. | 

### cs-falcon-cspm-list-service-policy-settings

***
Returns information about current policy settings.

#### Base Command

`cs-falcon-cspm-list-service-policy-settings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Optional | 
| cloud_platform | The cloud provider. Possible values are: aws, gcp, azure. Default is aws. | Optional | 
| service | Service type to filter by. | Optional | 
| limit | The maximum number of entities to list. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.CSPMPolicySetting.is_remediable | Boolean | Whether the policy setting is remediable or not. | 
| CrowdStrike.CSPMPolicySetting.created_at | String | The creation date. | 
| CrowdStrike.CSPMPolicySetting.updated_at | String | The update date. | 
| CrowdStrike.CSPMPolicySetting.policy_id | Integer | The policy ID. | 
| CrowdStrike.CSPMPolicySetting.name | String | The policy setting name. | 
| CrowdStrike.CSPMPolicySetting.policy_type | String | The policy type. | 
| CrowdStrike.CSPMPolicySetting.cloud_service_subtype | String | The cloud service subtype. | 
| CrowdStrike.CSPMPolicySetting.cloud_service | String | The cloud service. | 
| CrowdStrike.CSPMPolicySetting.cloud_service_friendly | String | The cloud friendly service. | 
| CrowdStrike.CSPMPolicySetting.cloud_asset_type | String | The cloud asset type. | 
| CrowdStrike.CSPMPolicySetting.cloud_asset_type_id | Integer | The cloud asset type ID. | 
| CrowdStrike.CSPMPolicySetting.cloud_provider | String | The cloud provider. | 
| CrowdStrike.CSPMPolicySetting.default_severity | String | The default severity. | 
| CrowdStrike.CSPMPolicySetting.policy_timestamp | Date | The policy timestamp. | 
| CrowdStrike.CSPMPolicySetting.policy_settings | Array | An array that holds policy settings. | 
| CrowdStrike.CSPMPolicySetting.policy_settings.account_id | String | The account ID correlated to the policy. | 
| CrowdStrike.CSPMPolicySetting.policy_settings.regions | Array | The regions in which the policy is configured. | 
| CrowdStrike.CSPMPolicySetting.policy_settings.severity | String | The severity of the policy. | 
| CrowdStrike.CSPMPolicySetting.policy_settings.enabled | Boolean | Whether the policy settings are enabled or not. | 
| CrowdStrike.CSPMPolicySetting.policy_settings.tag_excluded | Boolean | Whether the tag is excluded or not. | 
| CrowdStrike.CSPMPolicySetting.cis_benchmark | Array | An array of CIS benchmark details. | 
| CrowdStrike.CSPMPolicySetting.cis_benchmark.id | Integer | The CIS benchmark ID. | 
| CrowdStrike.CSPMPolicySetting.cis_benchmark.benchmark_short | String | The CIS benchmark shortname. | 
| CrowdStrike.CSPMPolicySetting.cis_benchmark.recommendation_number | String | The CIS benchmark recommendation number. | 
| CrowdStrike.CSPMPolicySetting.pci_benchmark | Array | An array of PCI benchmark details. | 
| CrowdStrike.CSPMPolicySetting.pci_benchmark.id | Integer | The PCI benchmark ID. | 
| CrowdStrike.CSPMPolicySetting.pci_benchmark.benchmark_short | String | The PCI benchmark shortname. | 
| CrowdStrike.CSPMPolicySetting.pci_benchmark.recommendation_number | String | The PCI benchmark recommendation number. | 
| CrowdStrike.CSPMPolicySetting.nist_benchmark | Array | An array of NIST benchmark details. | 
| CrowdStrike.CSPMPolicySetting.nist_benchmark.id | Integer | The NIST benchmark ID. | 
| CrowdStrike.CSPMPolicySetting.nist_benchmark.benchmark_short | String | The NIST benchmark shortname. | 
| CrowdStrike.CSPMPolicySetting.nist_benchmark.recommendation_number | String | The NIST benchmark recommendation number. | 
| CrowdStrike.CSPMPolicySetting.attack_types | Array | The attack types. | 

### cs-falcon-cspm-update-policy_settings

***
Updates a policy setting. Can be used to override policy severity or to disable a policy entirely.

#### Base Command

`cs-falcon-cspm-update-policy_settings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID to be updated. | Required | 
| account_id | Cloud account ID to impact. | Optional | 
| enabled | Flag indicating if this policy is enabled. Possible values are: false, true. Default is true. | Optional | 
| regions | A comma-separated list of regions where this policy is enforced. | Optional | 
| severity | Policy severity value. Possible values are: critical, high, medium, informational. | Optional | 
| tag_excluded | Tag exclusion flag. Possible values are: false, true. | Optional | 

#### Context Output

There is no context output for this command.
### cs-falcon-resolve-identity-detection

***
Perform actions on identity detection alerts.

#### Base Command

`cs-falcon-resolve-identity-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of IDs of the alerts to update. | Required | 
| assign_to_name | Assign the specified detections to a user based on their username. | Optional | 
| assign_to_uuid | Assign the specified detections to a user based on their UUID. | Optional | 
| append_comment | Appends a new comment to any existing comments for the specified detections. | Optional | 
| add_tag | Add a tag to the specified detections. | Optional | 
| remove_tag | Remove a tag from the specified detections. | Optional | 
| update_status | Update the status of the alert to the specified value. Possible values are: new, in_progress, closed, reopened. | Optional | 
| unassign | Whether to unassign any assigned users to the specified detections. Possible values are: false, true. | Optional | 
| show_in_ui | If true, displays the detection in the UI. Possible values are: false, true. | Optional | 

#### Context Output

There is no context output for this command.
### cs-falcon-resolve-mobile-detection

***
Perform actions on mobile detection alerts.

#### Base Command

`cs-falcon-resolve-mobile-detection`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of IDs of the alerts to update. | Required | 
| assign_to_name | Assign the specified detections to a user based on their username. | Optional | 
| assign_to_uuid | Assign the specified detections to a user based on their UUID. | Optional | 
| append_comment | Appends a new comment to any existing comments for the specified detections. | Optional | 
| add_tag | Add a tag to the specified detections. | Optional | 
| remove_tag | Remove a tag from the specified detections. | Optional | 
| update_status | Update the status of the alert to the specified value. Possible values are: new, in_progress, closed, reopened. | Optional | 
| unassign | Whether to unassign any assigned users to the specified detections. Possible values are: false, true. | Optional | 
| show_in_ui | If true, displays the detection in the UI. Possible values are: false, true. | Optional | 

#### Context Output

There is no context output for this command.
### cs-falcon-list-users

***
List users.

#### Base Command

`cs-falcon-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | A comma-separated list of IDs (UUIDs) of specific users to list. | Optional | 
| filter | The filter expression that should be used to limit the results. FQL syntax. Available values: assigned_cids, cid, first_name, last_name, name, uid. Example: "first_name:'John'". | Optional | 
| offset | The integer offset to start retrieving records from. Default is 0. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Users.uuid | String | The user's UUID. | 
| CrowdStrike.Users.cid | String | The customer ID. | 
| CrowdStrike.Users.uid | String | The user's ID. | 
| CrowdStrike.Users.first_name | String | The user's first name. | 
| CrowdStrike.Users.last_name | String | The user's last name. | 
| CrowdStrike.Users.last_login_at | String | The timestamp of the user's last login. | 
| CrowdStrike.Users.created_at | String | The timestamp of the user's creation. | 

### cs-falcon-get-incident-behavior

***
Get incident behavior information.

#### Base Command

`cs-falcon-get-incident-behavior`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| behavior_ids | A comma-separated list of ID(s) of behaviors to list. Behavior IDs can be retrieved by running the 'cs-falcon-get-detections-for-incident' command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IncidentBehavior.behavior_id | String | The behavior ID. | 
| CrowdStrike.IncidentBehavior.cid | String | The customer ID. | 
| CrowdStrike.IncidentBehavior.aid | String | The agent ID. | 
| CrowdStrike.IncidentBehavior.incident_id | String | The incident ID. | 
| CrowdStrike.IncidentBehavior.incident_ids | List | The incident IDs. | 
| CrowdStrike.IncidentBehavior.pattern_id | Number | The pattern ID. | 
| CrowdStrike.IncidentBehavior.template_instance_id | Number | The template instance ID. | 
| CrowdStrike.IncidentBehavior.timestamp | String | The timestamp. | 
| CrowdStrike.IncidentBehavior.cmdline | String | The command line. | 
| CrowdStrike.IncidentBehavior.filepath | String | The file path. | 
| CrowdStrike.IncidentBehavior.domain | String | The domain. | 
| CrowdStrike.IncidentBehavior.pattern_disposition | Number | The pattern disposition. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.indicator | Boolean | Whether the pattern disposition is an indicator. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.detect | Boolean | Whether the pattern disposition is a detect. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.inddet_mask | Boolean | The pattern disposition indicator detect mask. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.sensor_only | Boolean | Whether the pattern disposition is sensor only. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.rooting | Boolean | Whether the pattern disposition is rooting. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.kill_process | Boolean | Whether the process was killed. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.kill_subprocess | Boolean | Whether the subprocess was killed. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.quarantine_machine | Boolean | Whether the machine was quarantined. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.quarantine_file | Boolean | Whether the file was quarantined. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.policy_disabled | Boolean | Whether the policy was disabled. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.kill_parent | Boolean | Whether the parent was killed. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.operation_blocked | Boolean | Whether the operation was blocked. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.process_blocked | Boolean | Whether the process was blocked. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.registry_operation_blocked | Boolean | Whether the registry operation was blocked. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.critical_process_disabled | Boolean | Whether the critical process was disabled. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.bootup_safeguard_enabled | Boolean | Whether the bootup safeguard was enabled. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.fs_operation_blocked | Boolean | Whether the file system operation was blocked. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.handle_operation_downgraded | Boolean | Whether the handle operation was downgraded. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.kill_action_failed | Boolean | Whether the kill action failed. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.blocking_unsupported | Boolean | Whether the blocking is unsupported. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.suspend_process | Boolean | Whether the process was suspended. | 
| CrowdStrike.IncidentBehavior.pattern_disposition_details.suspend_parent | Boolean | Whether the parent was suspended. | 
| CrowdStrike.IncidentBehavior.sha256 | String | The SHA256 hash. | 
| CrowdStrike.IncidentBehavior.user_name | String | The username. | 
| CrowdStrike.IncidentBehavior.tactic | String | The tactic used. | 
| CrowdStrike.IncidentBehavior.tactic_id | String | The tactic ID. | 
| CrowdStrike.IncidentBehavior.technique | String | The technique used. | 
| CrowdStrike.IncidentBehavior.technique_id | String | The technique ID. | 
| CrowdStrike.IncidentBehavior.display_name | String | The display name. | 
| CrowdStrike.IncidentBehavior.objective | String | The objective. | 
| CrowdStrike.IncidentBehavior.compound_tto | String | The compound Time to Operate \(TTO\). | 

### cs-falcon-get-ioarules

***
Get IOA Rules.

#### Base Command

`cs-falcon-get-ioarules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_ids | A comma-separated list of rule IDs to get IOA rules for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.IOARules.instance_id | String | The IOA rule's instance ID. | 
| CrowdStrike.IOARules.customer_id | String | The customer ID. | 
| CrowdStrike.IOARules.action_label | String | The IOA rule's action label. | 
| CrowdStrike.IOARules.comment | String | The IOA rule's comment. | 
| CrowdStrike.IOARules.committed_on | String | The timestamp of the IOA rule's commitment. | 
| CrowdStrike.IOARules.created_by | String | The IOA rule's creator. | 
| CrowdStrike.IOARules.created_on | String | The timestamp of the IOA rule's creation. | 
| CrowdStrike.IOARules.deleted | Boolean | Whether the IOA rule is in a deleted status. | 
| CrowdStrike.IOARules.description | String | The IOA rule's description. | 
| CrowdStrike.IOARules.disposition_id | String | The disposition ID used by the IOA rule. | 
| CrowdStrike.IOARules.enabled | Boolean | Whether the IOA rule is enabled. | 
| CrowdStrike.IOARules.field_values | String | The IOA rule's field values. | 
| CrowdStrike.IOARules.instance_version | String | The IOA rule's instance version. | 
| CrowdStrike.IOARules.magic_cookie | String | The IOA rule's magic cookie. | 
| CrowdStrike.IOARules.modified_by | String | The last user who modified the IOA rule. | 
| CrowdStrike.IOARules.modified_on | String | The timestamp of the IOA rule's last modification. | 
| CrowdStrike.IOARules.name | String | The IOA rule name. | 
| CrowdStrike.IOARules.pattern_id | String | The IOA rule's pattern ID. | 
| CrowdStrike.IOARules.pattern_severity | String | The IOA rule's pattern severity. | 
| CrowdStrike.IOARules.rulegroup_id | String | The IOA rule's rule group ID. | 
| CrowdStrike.IOARules.ruletype_id | String | The IOA rule's rule type ID. | 
| CrowdStrike.IOARules.ruletype_name | String | The IOA rule's rule type name. | 
| CrowdStrike.IOARules.version_ids | String | The IOA rule's version ID. | 

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and RotemTest corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in RotemTest events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in RotemTest events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and RotemTest events will be reflected in both directions. |

3. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in RotemTest.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and RotemTest.
