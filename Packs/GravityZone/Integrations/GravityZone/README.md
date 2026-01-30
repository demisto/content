GravityZone provides secure access to incident and endpoint data and enables remediation actions through its APIs.
This integration was integrated and tested with version 6.6 of GravityZone.

## Configure GravityZone in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of your GravityZone Cloud instance. | True |
| Api key | API key to access the service REST API. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Maximum incidents to fetch. | Maximum number of incidents per fetch. The default value is 50. | False |
| First fetch time | The time period from which the first fetch will start. | False |
| Mirroring Direction |  |  |
| Incident type |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fetch-incidents

***
Retrieves incidents from GravityZone Cloud.

#### Base Command

`fetch-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### gz-list-endpoints

***
Retrieves the list of managed endpoints.

#### Base Command

`gz-list-endpoints`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### endpoint

***
Retrieves details about an endpoint.

#### Base Command

`endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the endpoint to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.ID | String | The endpoint ID. |
| Endpoint.Hostname | String | The endpoint hostname. |
| Endpoint.IPAddress | String | The endpoint IP address. |
| Endpoint.OS | String | The endpoint operating system version. |
| Endpoint.Status | String | The endpoint status. |
| Endpoint.Vendor | String | The endpoint vendor. |

### gz-get-endpoint-by-id

***
Retrieves endpoint details by endpoint ID.

#### Base Command

`gz-get-endpoint-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the endpoint to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Endpoint.ID | String | The endpoint ID. |
| GravityZone.Endpoint.Hostname | String | The endpoint hostname. |
| GravityZone.Endpoint.IP | String | The endpoint IP address. |
| GravityZone.Endpoint.OS | String | The endpoint operating system version. |
| GravityZone.Endpoint.Status | String | The endpoint status. |
| GravityZone.Endpoint.Vendor | String | The endpoint vendor. |
| GravityZone.Endpoint.LastLoggedUsers | String | The last users who logged on the endpoint. |

### gz-download-investigation-package-from-endpoint

***
Collects and downloads an investigation package from an endpoint.

#### Base Command

`gz-download-investigation-package-from-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the endpoint from which to collect the investigation package. | Required |
| output_file | The output file name in Cortex XSOAR to save the collected package. For Windows and macOS use .zip, for Linux use .tgz. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.DownloadFile.EndpointID | String | The endpoint ID. |
| GravityZone.Command.DownloadFile.Status | String | The command status. |
| GravityZone.Command.DownloadFile.ErrorCode | String | The command error code. |
| GravityZone.Command.DownloadFile.OutputFile | String | The output file name. |
| GravityZone.Command.DownloadFile.RemoteFile | String | The remote file path. |
| GravityZone.Command.DownloadFile.FileID | String | The file ID. |
| File.SHA1 | String | The SHA1 hash of the downloaded file. |
| File.SHA256 | String | The SHA256 hash of the downloaded file. |
| File.SHA512 | String | The SHA512 hash of the downloaded file. |
| File.SSDeep | String | The SSDeep hash of the downloaded file. |
| File.EntryID | String | The EntryID hash of the downloaded file. |
| File.Info | String | Information about the downloaded file. |
| File.Type | String | The downloaded file type. |
| File.MD5 | String | The MD5 hash of the downloaded file. |
| File.Extension | String | The downloaded file extension. |
| File.Size | Number | The downloaded file size. |
| File.Name | String | The downloaded file name. |

### gz-download-file-from-endpoint

***
Downloads a file from an endpoint.

#### Base Command

`gz-download-file-from-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the endpoint to download the file from. | Required |
| remote_file | The full path of the remote file on the endpoint to download. | Required |
| output_file | The output file name in Cortex XSOAR to save the downloaded file to. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.DownloadFile.EndpointID | String | The endpoint ID. |
| GravityZone.Command.DownloadFile.Status | String | The command status. |
| GravityZone.Command.DownloadFile.ErrorCode | String | The command error code. |
| GravityZone.Command.DownloadFile.OutputFile | String | The output file name. |
| GravityZone.Command.DownloadFile.RemoteFile | String | The remote file path. |
| GravityZone.Command.DownloadFile.FileID | String | The file ID. |
| File.SHA1 | String | The SHA1 hash of the downloaded file. |
| File.SHA256 | String | The SHA256 hash of the downloaded file. |
| File.SHA512 | String | The SHA512 hash of the downloaded file. |
| File.SSDeep | String | The SSDeep hash of the downloaded file. |
| File.EntryID | String | The EntryID hash of the downloaded file. |
| File.Info | String | Information about the downloaded file. |
| File.Type | String | The downloaded file type. |
| File.MD5 | String | The MD5 hash of the downloaded file. |
| File.Extension | String | The downloaded file extension. |
| File.Size | Number | The downloaded file size. |
| File.Name | String | The downloaded file name. |

### gz-isolate-endpoint

***
Isolates an endpoint from the network.

#### Base Command

`gz-isolate-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the endpoint to isolate. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.Isolate.TaskID | String | The task ID. |
| GravityZone.Command.Isolate.TaskType | String | The task type. |
| GravityZone.Command.Isolate.EndpointID | String | The endpoint ID. |
| GravityZone.Command.Isolate.Hostname | String | The endpoint name. |
| GravityZone.Command.Isolate.Status | String | The command status. |
| GravityZone.Command.Isolate.ErrorCode | String | The command error code, or "Success". |
| GravityZone.Command.Isolate.Error | String | The command error message, or "Success". |
| GravityZone.Command.Isolate.StartDate | Date | The start date of the command execution. |
| GravityZone.Command.Isolate.EndDate | Date | The end date of the command execution. |

### gz-deisolate-endpoint

***
Restores an isolated endpoint to the network.

#### Base Command

`gz-deisolate-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the endpoint to restore from isolation. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.Deisolate.TaskID | String | The task ID. |
| GravityZone.Command.Deisolate.TaskType | String | The task type. |
| GravityZone.Command.Deisolate.EndpointID | String | The endpoint ID. |
| GravityZone.Command.Deisolate.Hostname | String | The endpoint name. |
| GravityZone.Command.Deisolate.Status | String | The command status. |
| GravityZone.Command.Deisolate.ErrorCode | String | The command error code, or "Success". |
| GravityZone.Command.Deisolate.Error | String | The command error message, or "Success". |
| GravityZone.Command.Deisolate.StartDate | Date | The start date of the command execution. |
| GravityZone.Command.Deisolate.EndDate | Date | The end date of the command execution. |

### gz-kill-process-on-endpoint

***
Terminates a process on an endpoint by process ID.

#### Base Command

`gz-kill-process-on-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Required |
| pid | The ID of the processs to kill. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.KillProcess.TaskID | String | The task ID. |
| GravityZone.Command.KillProcess.TaskType | String | The task type. |
| GravityZone.Command.KillProcess.EndpointID | String | The endpoint ID. |
| GravityZone.Command.KillProcess.Hostname | String | The endpoint name. |
| GravityZone.Command.KillProcess.Status | String | The command status. |
| GravityZone.Command.KillProcess.ErrorCode | String | The command error code, or "Success". |
| GravityZone.Command.KillProcess.Error | String | The command error message, or "Success". |
| GravityZone.Command.KillProcess.StartDate | Date | The start date of the command execution. |
| GravityZone.Command.KillProcess.EndDate | Date | The end date of the command execution. |
| GravityZone.Command.KillProcess.ProcessID | Number | The process ID. |
| GravityZone.Command.KillProcess.ProcessPath | String | The process path. |

### gz-run-command-on-endpoint

***
Runs a command on the endpoint. The applied policy must have Remote Shell enabled for this action to work.

#### Base Command

`gz-run-command-on-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the endpoint on which to run the command. | Required |
| command | The command to run on the endpoint. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.RunCommand.ActivityID | String | The activity ID. |
| GravityZone.Command.RunCommand.ActivityType | String | The activity type. |
| GravityZone.Command.RunCommand.Status | String | The command status. |
| GravityZone.Command.RunCommand.EndpointID | String | The endpoint ID. |
| GravityZone.Command.RunCommand.ErrorCode | String | The command error code, or "Success". |
| GravityZone.Command.RunCommand.Output | String | The command output. |
| GravityZone.Command.RunCommand.FileID | String | The stored file ID, when the command output cannot be extracted as an archive. |
| GravityZone.Command.RunCommand.FileName | String | The stored file name, when the command output cannot be extracted as an archive. |

### gz-upload-file-to-endpoint

***
Uploads a file to an endpoint.

#### Base Command

`gz-upload-file-to-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the target endpoint for the file upload. | Required |
| entry_id | The entry ID of the file to upload. This file needs to exist in Cortex XSOAR. | Required |
| remote_location | The full folder path on the endpoint where the file will be uploaded. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.UploadFile.TaskID | String | The task ID. |
| GravityZone.Command.UploadFile.TaskType | String | The task type. |
| GravityZone.Command.UploadFile.EndpointID | String | The endpoint ID. |
| GravityZone.Command.UploadFile.Hostname | String | The endpoint name. |
| GravityZone.Command.UploadFile.Status | String | The command status. |
| GravityZone.Command.UploadFile.ErrorCode | String | The command error code, or "Success". |
| GravityZone.Command.UploadFile.Error | String | The command error message, or "Success". |
| GravityZone.Command.UploadFile.StartDate | Date | The start date of the command execution. |
| GravityZone.Command.UploadFile.EndDate | Date | The end date of the command execution. |
| GravityZone.Command.UploadFile.EntryID | String | The entry ID of the uploaded file. |
| GravityZone.Command.UploadFile.DestinationPath | String | The destination path of the uploaded file. |

### gz-get-endpoints-running-process-hash

***
Retrieves endpoints that are running processes with a specified hash. The API key and the applied policy must allow Live Search. Endpoints must be online. The command waits up to five minutes for responses before timing out.

#### Base Command

`gz-get-endpoints-running-process-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_hash | Hash of the process. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.EndpointsRunningProcessHash.EndpointID | String | The endpoint ID. |
| GravityZone.Command.EndpointsRunningProcessHash.Path | String | The Live Search results. |
| GravityZone.Command.EndpointsRunningProcessHash.ProcessHash | String | The process hash. |

### gz-get-process-tree-for-hash-on-endpoint

***
Retrieves the process tree on an endpoint for a specified process hash. The applied policy must allow Live Search, and the endpoint must be online.

#### Base Command

`gz-get-process-tree-for-hash-on-endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the targeted endpoint. | Required |
| process_hash | The hash of the process to search for. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.ProcessTreeForHash.EndpointID | String | The endpoint ID. |
| GravityZone.Command.ProcessTreeForHash.PID | Number | The process ID. |
| GravityZone.Command.ProcessTreeForHash.Path | String | The process path. |
| GravityZone.Command.ProcessTreeForHash.Cmdline | String | The command line used to start the process. |
| GravityZone.Command.ProcessTreeForHash.ParentPID | Number | The parent process ID. |

### gz-get-incident-by-id

***
Retrieves incident details by ID.

#### Base Command

`gz-get-incident-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the incident to fetch. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Incident.ID | String | The incident ID. |
| GravityZone.Incident.Type | String | The incident type \('incident' / 'extendedIncident'\). |
| GravityZone.Incident.Company.Name | String | The GravityZone company name where the incident is located. |
| GravityZone.Incident.Company.ID | String | The GravityZone company ID where the incident is located. |
| GravityZone.Incident.Number | Number | The incident number \(specific to the company\). |
| GravityZone.Incident.Severity.Score | Number | The incident severity score \(0 - 100\). |
| GravityZone.Incident.Status | Number | The incident status. |
| GravityZone.Incident.ActionTaken | String | The action taken by the detecting technology \('reported' / 'blocked' / 'partially_blocked'\). |
| GravityZone.Incident.Created | Date | The date when the incident was detected on the endpoint / sensor. |
| GravityZone.Incident.LastUpdated | Date | The date when the incident was last updated in GravityZone or by the endpoint / sensor. |
| GravityZone.Incident.LastProcessed | Date | The date when the incident was last processed by GravityZone services. |
| GravityZone.Incident.Permalink | String | The incident URL in the GravityZone Console. |
| GravityZone.Incident.AssignedPriority | String | The priority assigned to the incident \('unknown' / 'low' / 'medium' / 'high' / 'critical'\). |
| GravityZone.Incident.Notes.Text | String | The note contents. |
| GravityZone.Incident.Notes.User | String | The username \(email\) of the user who wrote the note. |
| GravityZone.Incident.Notes.Date | Date | The note creation date. |
| GravityZone.Incident.Alerts.Name | String | The alert name. |
| GravityZone.Incident.Alerts.Date | Date | The date of when the alert was generated. |
| GravityZone.Incident.Alerts.Sensors | String | The list of sensors that generated the alert. Available only for 'extendedIncident'-type incidents. |
| GravityZone.Incident.Alerts.Tactic | String | The list of sensors that generated the alert. Available only for 'extendedIncident'-type incidents. |
| GravityZone.Incident.Alerts.Resources | Unknown | The list of resources involved in the 'incident'-type incidents. |
| GravityZone.Incident.RawJSON | Unknown | The raw JSON response from the GravityZone API. |

### gz-list-incidents

***
Retrieves incidents within the last three days from all endpoints or a specific endpoint.

#### Base Command

`gz-list-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The ID of the endpoint to list incidents for. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.SummarizedIncidents.ID | String | The incident ID. |
| GravityZone.SummarizedIncidents.Type | String | The incident type \('incident' / 'extendedIncident'\). |
| GravityZone.SummarizedIncidents.CompanyName | String | The GravityZone company name where the incident is located. |
| GravityZone.SummarizedIncidents.Number | Number | The incident number \(specific to the company\). |
| GravityZone.SummarizedIncidents.SeverityScore | Number | The incident severity score \(0 - 100\). |
| GravityZone.SummarizedIncidents.Status | Number | The incident status. |
| GravityZone.SummarizedIncidents.ActionTaken | String | The action taken by the detecting technology \('reported' / 'blocked' / 'partially_blocked'\). |
| GravityZone.SummarizedIncidents.Created | Date | The date when the incident was detected on the endpoint / sensor. |
| GravityZone.SummarizedIncidents.LastUpdated | Date | The date when the incident was last updated in GravityZone or by the endpoint / sensor. |
| GravityZone.SummarizedIncidents.LastProcessed | Date | The incident last processed date by GravityZone services. |
| GravityZone.SummarizedIncidents.Permalink | String | The incident URL in the GravityZone Console. |
| GravityZone.SummarizedIncidents.AssignedPriority | String | The priority assigned to the incident \('unknown' / 'low' / 'medium' / 'high' / 'critical'\). |
| GravityZone.SummarizedIncidents.AssignedUserId | String | The ID of the user assigned to the incident. |
| GravityZone.SummarizedIncidents.RawJSON | Unknown | The raw JSON response from the GravityZone API. |

### gz-add-incident-note

***
Adds a note to one or more incidents.

#### Base Command

`gz-add-incident-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The IDs of the incidents to add a note to. Supports comma separated values. | Required |
| note | The note to add to the incidents. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.AddIncidentNote.IncidentID | String | The incident ID. |
| GravityZone.Command.AddIncidentNote.Note | String | The requested note. |
| GravityZone.Command.AddIncidentNote.CommandStatus | String | The command status. |

### gz-change-incident-status

***
Changes the status of one or more incidents.

#### Base Command

`gz-change-incident-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The IDs of the incidents to update. Supports comma separated values. | Required |
| status | The new status of the incidents. Possible values are: PENDING, ACTIVE, DONE, ARCHIVE. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.ChangeIncidentStatus.IncidentID | Unknown | The incident ID. |
| GravityZone.Command.ChangeIncidentStatus.IncidentStatus | String | The requested status of the incident. |
| GravityZone.Command.ChangeIncidentStatus.CommandStatus | String | The command status. |

### gz-poll-investigation-activity-status

***
Checks the status of an investigation activity. This command is not intended for direct use.

#### Base Command

`gz-poll-investigation-activity-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_id | The endpoint ID. | Required |
| activity_id | The activity ID. | Required |
| output_file | The path of the output file. | Optional |
| metadata | The metadata to pass to the task. | Optional |

#### Context Output

There is no context output for this command.

### gz-poll-live-search-status

***
Checks the status of a Live Search query. This command is not intended for direct use.

#### Base Command

`gz-poll-live-search-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The task ID. | Required |
| search_type | The Live Search query type. | Optional |
| metadata | The metadata to pass to the task. | Optional |

#### Context Output

There is no context output for this command.

### gz-poll-task-status

***
Checks the status of a task. This command is not intended for direct use.

#### Base Command

`gz-poll-task-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The task ID. | Required |
| metadata | The metadata to pass to the task. | Optional |

#### Context Output

There is no context output for this command.

### get-modified-remote-data

***
Retrieves incidents that were modified since the last data sync. This command is intended for debugging purposes.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | The time when the incident was last updated. | Required |

#### Context Output

There is no context output for this command.

### get-remote-data

***
Retrieves data from a remote incident without updating the current incident. This command is intended for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the incident to fetch. | Required |
| lastUpdate | The time when the incident was last updated. | Required |

#### Context Output

There is no context output for this command.

### update-remote-system

***
Updates the remote incident with local incident changes without updating the current incident. This command is intended for debugging purposes.

#### Base Command

`update-remote-system`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### get-mapping-fields

***
Returns the list of fields available for outgoing mirroring. This command is intended for debugging purposes only.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and GravityZone corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in GravityZone events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in GravityZone events (outgoing mirrored fields). |
    | Both |  |

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and GravityZone.
