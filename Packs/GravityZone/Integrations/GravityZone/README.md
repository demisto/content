GravityZone provides secure access to incident and endpoint data and enables remediation actions through its APIs.
This integration was integrated and tested with version 6.6 of GravityZone.

## Configure GravityZone in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of your GravityZone Cloud instance. | True |
| API key | API key to access the service REST API. | True |
| Trust any certificate (not secure) | When selected, the server certificates are not verified. | False |
| Use system proxy settings | Use the system proxy settings for connecting to the server. | False |
| Fetch incidents | When selected, the integration will fetch incidents from the server. | False |
| Maximum incidents to fetch | Maximum number of incidents per fetch. The default value is 50. | False |
| First fetch time | The time period from which the first fetch will start. | False |
| Mirroring Direction | The mirroring direction in which to mirror the incident. You can mirror "Incoming" \(from GravityZone to Cortex XSOAR\), "Outgoing" \(from Cortex XSOAR to GravityZone\), or in both directions. | False |
| Incident type |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fetch-incidents

***
Retrieves incidents from GravityZone Cloud.

#### Base Command

`fetch-incidents`

#### Context Output

There is no context output for this command.

### gz-endpoint-list

***
Retrieves the list of managed endpoints.

#### Base Command

`gz-endpoint-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of endpoints to retrieve. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.EndpointsList.ID | String | The endpoint ID. |
| GravityZone.EndpointsList.Hostname | String | The endpoint hostname. |
| GravityZone.EndpointsList.IP | String | The endpoint IP address. |
| GravityZone.EndpointsList.OS | String | The endpoint operating system version. |
| GravityZone.EndpointsList.MAC | String | The endpoint MAC address. |
| GravityZone.EndpointsList.Vendor | String | The endpoint vendor. |

#### Command example

```!gz-endpoint-list```

#### Context Example

```json
{
    "GravityZone": {
        "EndpointsList": [
            {
                "Hostname": "SL-WIN10-PC2",
                "ID": "67c87017f3e11f09dc9143e8",
                "IP": "1.1.1.1",
                "MAC": "005056b1ef97",
                "OS": "Windows 10 Pro",
                "Vendor": "GravityZone"
            }
        ]
    }
}
```

#### Human Readable Output

>### GravityZone Endpoints List
>
>|ID|Hostname|IP|OS|MAC|Vendor|
>|---|---|---|---|---|---|
>| 67c87017f3e11f09dc9143e8 | SL-WIN10-PC2 | 1.1.1.1 | Windows 10 Pro | 005056b1ef97 | GravityZone |

### gz-endpoint-get

***
Retrieves endpoint details by endpoint ID.

#### Base Command

`gz-endpoint-get`

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
| Endpoint.ID | String | The endpoint ID. |
| Endpoint.Hostname | String | The endpoint hostname. |
| Endpoint.IPAddress | String | The endpoint IP address. |
| Endpoint.OS | String | The endpoint operating system version. |
| Endpoint.Status | String | The endpoint status. |
| Endpoint.Vendor | String | The endpoint vendor. |

#### Command example

```!gz-endpoint-get id=6942a43afe8d4e463ca5c197```

#### Context Example

```json
{
    "Endpoint": {
        "Hostname": "bdvm",
        "ID": "6942a43afe8d4e463ca5c197",
        "IPAddress": "1.1.1.1",
        "OS": "Linux Ubuntu 24.04.2 LTS",
        "Status": "Online",
        "Vendor": "GravityZone"
    },
    "GravityZone": {
        "Endpoint": {
            "Hostname": "bdvm",
            "ID": "6942a43afe8d4e463ca5c197",
            "IP": "1.1.1.1",
            "LastLoggedUsers": "",
            "OS": "Linux Ubuntu 24.04.2 LTS",
            "Status": "Online",
            "Vendor": "GravityZone"
        }
    }
}
```

#### Human Readable Output

>### GravityZone Endpoint
>
>|ID|Hostname|IP|OS|Status|Vendor|LastLoggedUsers|
>|---|---|---|---|---|---|---|
>| 6942a43afe8d4e463ca5c197 | bdvm | 1.1.1.1 | Linux Ubuntu 24.04.2 LTS | Online | GravityZone |  |

### gz-endpoint-download-investigation-package

***
Collects and downloads an investigation package from an endpoint.

#### Base Command

`gz-endpoint-download-investigation-package`

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

#### Command example

```!gz-endpoint-download-investigation-package id=6942a43afe8d4e463ca5c197 output_file=investigation_package.zip```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "DownloadFile": {
                "ActivityID": "69443b020126750c1a0dbe2f",
                "ActivityType": "DownloadFile",
                "Status": "Success",
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "ErrorCode": null,
                "RemoteFile": null,
                "OutputFile": "investigation_package.zip",
                "FileID": "LtvQ6B8eCFvTNo7bf3vDUD@25729aa7-7442-4231-8b98-ecb0fc29a642",
                "FileName": "investigation_package.zip"
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.DownloadFile command on host 6942a43afe8d4e463ca5c197
>
>|EndpointID|Status|ErrorCode|OutputFile|RemoteFile|FileID|
>|---|---|---|---|---|---|
>| 6942a43afe8d4e463ca5c197 | Success |  | investigation_package.zip | | LtvQ6B8eCFvTNo7bf3vDUD@25729aa7-7442-4231-8b98-ecb0fc29a642 |

### gz-endpoint-download-file

***
Downloads a file from an endpoint.

#### Base Command

`gz-endpoint-download-file`

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

#### Command example

```!gz-endpoint-download-file id=6942a43afe8d4e463ca5c197 remote_file=/root/test/test.txt output_file=downloaded_file.gzip```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "DownloadFile": {
                "ActivityID": "6943fb82c1f339e18b0949a1",
                "ActivityType": "DownloadFile",
                "RemoteFile": "/root/test/test.txt",
                "Status": "Success",
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "ErrorCode": null,
                "OutputFile": "downloaded_file.gzip",
                "FileID": "LtvQ6B8eCFvTNo7bf3vDUD@25729aa7-7442-4231-8b98-ecb0fc29a642",
                "FileName": "downloaded_file.gzip"
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.DownloadFile command on host 6942a43afe8d4e463ca5c197
>
>|EndpointID|Status|ErrorCode|OutputFile|RemoteFile|FileID|
>|---|---|---|---|---|---|
>| 6942a43afe8d4e463ca5c197 | Success |  | downloaded_file.gzip | /root/test/test.txt | LtvQ6B8eCFvTNo7bf3vDUD@25729aa7-7442-4231-8b98-ecb0fc29a642 |

### gz-endpoint-isolate

***
Isolates an endpoint from the network.

#### Base Command

`gz-endpoint-isolate`

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

#### Command example

```!gz-endpoint-isolate id=6942a43afe8d4e463ca5c197```

#### Context Example

```json
{
    "GravityZone": {
        "Command" : {
            "Isolate" : {
                "TaskID": "6941bbc98ba450a5c10e5a16",
                "TaskType": "Isolate",
                "Status": "Processed",
                "EndDate": "2025-12-16T22:06:33Z",
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "Hostname": "ENDPOINT_NAME",
                "ErrorCode": "Success",
                "Error": "Success",
                "StartDate": "2025-12-16T22:06:33Z"
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.Isolate command on hosts ENDPOINT_ID
>
>|EndpointID|Hostname|StartDate|EndDate|Error|
>|---|---|---|---|---|
>| 6942a43afe8d4e463ca5c197 | ENDPOINT_NAME | 2025-12-16T22:06:33Z | 2025-12-16T22:06:33Z | Success |

### gz-endpoint-deisolate

***
Restores an isolated endpoint to the network.

#### Base Command

`gz-endpoint-deisolate`

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

#### Command example

```!gz-endpoint-deisolate id=6942a43afe8d4e463ca5c197```

#### Context Example

```json
{
    "GravityZone": {
        "Command" : {
            "Deisolate" : {
                "TaskID": "6941bbc98ba450a5c10e5a16",
                "TaskType": "Deisolate",
                "Status": "Processed",
                "EndDate": "2025-12-16T22:08:33Z",
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "Hostname": "ENDPOINT_NAME",
                "ErrorCode": "Success",
                "Error": "Success",
                "StartDate": "2025-12-16T22:08:33Z"
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.Deisolate command on hosts ENDPOINT_ID
>
>|EndpointID|Hostname|StartDate|EndDate|Error|
>|---|---|---|---|---|
>| 6942a43afe8d4e463ca5c197 | ENDPOINT_NAME | 2025-12-16T22:08:33Z | 2025-12-16T22:08:33Z | Success |

### gz-endpoint-kill-process

***
Terminates a process on an endpoint by process ID.

#### Base Command

`gz-endpoint-kill-process`

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

#### Command example

```!gz-endpoint-kill-process id=6942a43afe8d4e463ca5c197 pid=5876```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "KillProcess": {
                "TaskID": "6941b6ffa830c3132b0d63d8",
                "TaskType": "KillProcess",
                "Status": "Processed",
                "EndDate": "2025-12-16T21:46:08Z",
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "Hostname": "ENDPOINT_NAME",
                "ErrorCode": "Success",
                "Error": "Success",
                "StartDate": "2025-12-16T21:46:07Z",
                "ProcessID": 5876,
                "ProcessPath": ""
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.KillProcess command on hosts ENDPOINT_ID
>
>|EndpointID|Hostname|StartDate|EndDate|Error|ProcessID|
>|---|---|---|---|---|---|
>| 6942a43afe8d4e463ca5c197 | ENDPOINT_NAME | 2025-12-16T21:46:07Z | 2025-12-16T21:46:08Z | Success | 5876 |

### gz-endpoint-run-command

***
Runs a command on the endpoint. The applied policy must have Remote Shell enabled for this action to work.

#### Base Command

`gz-endpoint-run-command`

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

#### Command example

```!gz-endpoint-run-command id=6942a43afe8d4e463ca5c197 command=whoami```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "RunCommand": {
                "ActivityID": "6943e3391e4fe5e8a40e51f6",
                "ActivityType": "RunCommand",
                "Status": "Success",
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "ErrorCode": null,
                "Command": "whoami",
                "Output": "root"
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.RunCommand command on host 6942a43afe8d4e463ca5c197
>
>|EndpointID|Status|ErrorCode|Command|Output|
>|---|---|---|---|---|
>| 6942a43afe8d4e463ca5c197 | Success |  | whoami | root |

### gz-endpoint-upload-file

***
Uploads a file to an endpoint.

#### Base Command

`gz-endpoint-upload-file`

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

#### Command example

```!gz-endpoint-upload-file id=6942a43afe8d4e463ca5c197 entry_id=LtvQ6B8eCFvTNo7bf3vDUD@25729aa7-7442-4231-8b98-ecb0fc29a642 remote_location=/root/test/```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "UploadFile": {
                "TaskID": "694447384f1ba9a2650ec75a",
                "TaskType": "UploadFile",
                "Status": "Processed",
                "EndDate": "2025-12-18T20:26:40Z",
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "Hostname": "ENDPOINT_NAME",
                "ErrorCode": "Success",
                "Error": "Success",
                "StartDate": "2025-12-18T20:26:00Z",
                "EntryID": "LtvQ6B8eCFvTNo7bf3vDUD@25729aa7-7442-4231-8b98-ecb0fc29a642",
                "DestinationPath": "/root/test/"
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.UploadFile command on hosts 6942a43afe8d4e463ca5c197
>
>|EndpointID|Hostname|StartDate|EndDate|Error|EntryID|DestinationPath|
>|---|---|---|---|---|---|---|
>| 6942a43afe8d4e463ca5c197 | ENDPOINT_NAME | 2025-12-18T20:26:00Z | 2025-12-18T20:26:40Z | Success | LtvQ6B8eCFvTNo7bf3vDUD@25729aa7-7442-4231-8b98-ecb0fc29a642 | /root/test/ |

### gz-endpoint-list-by-running-process-hash

***
Retrieves endpoints that are running processes with a specified hash. The API key and the applied policy must allow Live Search. Endpoints must be online. The command waits up to five minutes for responses before timing out.

#### Base Command

`gz-endpoint-list-by-running-process-hash`

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

#### Command example

```!gz-endpoint-list-by-running-process-hash process_hash=b8412bcc6f47b2a11e4c39bc1bc9fab74969ff0648ba22db4c5254a0457af0c7```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "EndpointsRunningProcessHash": {
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "Path": "/opt/bitdefender-security-tools/bin/epagngd",
                "ProcessHash": "b8412bcc6f47b2a11e4c39bc1bc9fab74969ff0648ba22db4c5254a0457af0c7"
            }
        }
    }
}
```

#### Human Readable Output

>### Live Search Results
>
>|EndpointID|ProcessHash|Results|
>|---|---|---|
>| 6942a43afe8d4e463ca5c197 | b8412bcc6f47b2a11e4c39bc1bc9fab74969ff0648ba22db4c5254a0457af0c7 | {"hostname":"ENDPOINT_NAME","path":"/opt/bitdefender-security-tools/bin/epagngd"} |

### gz-endpoint-get-process-tree-by-hash

***
Retrieves the process tree on an endpoint for a specified process hash. The applied policy must allow Live Search, and the endpoint must be online.

#### Base Command

`gz-endpoint-get-process-tree-by-hash`

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

#### Command example

```!gz-endpoint-get-process-tree-by-hash id=6942a43afe8d4e463ca5c197 process_hash=b8412bcc6f47b2a11e4c39bc1bc9fab74969ff0648ba22db4c5254a0457af0c7```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "ProcessTreeForHash": {
                "EndpointID": "6942a43afe8d4e463ca5c197",
                "Cmdline": "/usr/lib/systemd/systemd --system --deserialize=73",
                "ParentPID": 0,
                "Path": "/usr/lib/systemd/systemd",
                "PID": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Live Search Results
>
>|EndpointID|ProcessHash|Results|
>|---|---|---|
>| 6942a43afe8d4e463ca5c197 | b8412bcc6f47b2a11e4c39bc1bc9fab74969ff0648ba22db4c5254a0457af0c7 | {"cmdline":"/usr/lib/systemd/systemd --system --deserialize=73","parent":"0","path":"/usr/lib/systemd/systemd","pid":"1"} |

### gz-incident-get

***
Retrieves incident details by ID.

#### Base Command

`gz-incident-get`

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
| GravityZone.Incident.Alerts.Tactic | String | The list of tactics that generated the alert. Available only for 'extendedIncident'-type incidents. |
| GravityZone.Incident.Alerts.Resources | Array | The list of resources involved in the 'incident'-type incidents. |
| GravityZone.Incident.RawJSON | JSON | The raw JSON response from the GravityZone API. |
| GravityZone.Incident.EndpointID | String | The endpoint ID. Available only for 'incident'-type incidents. |
| GravityZone.Incident.EndpointHostname | String | The endpoint hostname. Available only for 'incident'-type incidents. |
| GravityZone.Incident.EndpointIP | String | The endpoint IP address. Available only for 'incident'-type incidents. |

#### Command example

```!gz-incident-get id=69415c9d5f5c8b75247c58d1```

#### Context Example

```json
{
    "GravityZone": {
        "Incident": {
            "ActionTaken": "blocked",
            "Alerts": [
                {
                    "Date": "2025-12-16T15:20:19+02:00",
                    "DetectedBy": {
                        "Class": "EDR Detection",
                        "Name": "KeyloggingAPICall"
                    },
                    "Name": "KeyloggingAPICall",
                    "Resources": [
                        {
                            "CommandLine": "\"C:\\Windows\\System32\\notepad.exe\" C:\\Users\\bdvm\\Desktop\\New Text Document.txt",
                            "ParentPid": 5212,
                            "ParentProcessAccessPrivileges": "elevated",
                            "ParentProcessIntegrityLevel": "high",
                            "ParentProcessPath": "c:\\windows\\explorer.exe",
                            "ParentProcessUser": "TA66H0I6F225\\bdvm",
                            "Pid": 2592,
                            "ProcessAccessPrivileges": "elevated",
                            "ProcessIntegrityLevel": "high",
                            "ProcessPath": "c:\\windows\\system32\\notepad.exe",
                            "Type": "process",
                            "User": "TA66H0I6F225\\bdvm"
                        }
                    ]
                }
            ],
            "AssignedPriority": "unknown",
            "AssignedUser": null,
            "Company": {
                "ID": "611717cb22a30cee251b03f3",
                "Name": "Company"
            },
            "Created": "2025-12-16T15:20:21+02:00",
            "ID": "69415c9d5f5c8b75247c58d1",
            "LastProcessed": "2025-12-16T15:21:48+02:00",
            "LastUpdated": "2025-12-16T15:21:38+02:00",
            "Notes": [
                {
                    "Date": "2026-02-23T13:27:53+02:00",
                    "Text": "InvestigationInProgress",
                    "User": "user email"
                }
            ],
            "Number": 473,
            "Permalink": "https://gravityzone.domain/#!/incidents/view/69415c9d5f5c8b75247c58d1",
            "EndpointID" : "694148bffe8d4e463ca5bd1e",
            "EndpointHostname": "TA66H0I6F225",
            "EndpointIP": "1.1.1.1",
            "RawJSON": {
                "assignee": null,
                "attackTypes": [
                    "Malware"
                ],
                "company": {
                    "id": "611717cb22a30cee251b03f3",
                    "name": "Company"
                },
                "created": "2025-12-16T15:20:21+02:00",
                "details": {
                    "alerts": [
                        {
                            "date": "2025-12-16T15:20:19+02:00",
                            "detectedBy": {
                                "class": "EDR Detection",
                                "name": "KeyloggingAPICall"
                            },
                            "extra": [
                                {
                                    "key": "hookedApiName",
                                    "value": "Key Logging"
                                },
                                {
                                    "key": "extraInfo1",
                                    "value": "\nProcess PE VersionInfo and Certification Information: \nOriginal File Name: NOTEPAD.EXE\nInternal Name: Notepad\nFile Description: Notepad\nCompany Name: Microsoft Corporation\nFile Version: 10.0.19041.1865 (WinBuild.160101.0800)\nProduct Name: MicrosoftR WindowsR Operating System\nProduct Version: 10.0.19041.1865\nLegal Copyright: C Microsoft Corporation. All rights reserved.\nCertificate Serial: 330000033b655faefadb75e9d600000000033b\nCertificate Signer: Microsoft Corporation\nCertificate Issuer: Microsoft Corporation\n\nWorking Directory: c:\\users\\bdvm\\desktop\\"
                                }
                            ],
                            "id": "69415ce1997e9c48ed12c360",
                            "name": "KeyloggingAPICall",
                            "resources": [
                                {
                                    "details": {
                                        "commandLine": "\"C:\\Windows\\System32\\notepad.exe\" C:\\Users\\bdvm\\Desktop\\New Text Document.txt",
                                        "loadedModule": null,
                                        "loadedModulePid": null,
                                        "parentPid": 5212,
                                        "parentProcessAccessPrivileges": "elevated",
                                        "parentProcessCmdline": null,
                                        "parentProcessIntegrityLevel": "high",
                                        "parentProcessPath": "c:\\windows\\explorer.exe",
                                        "parentProcessUser": "TA66H0I6F225\\bdvm",
                                        "pid": 2592,
                                        "processAccessPrivileges": "elevated",
                                        "processInjectionSizeofWrite": null,
                                        "processInjectionTarget": null,
                                        "processInjectionTargetPid": null,
                                        "processInjectionWriter": null,
                                        "processInjectionWriterPid": null,
                                        "processIntegrityLevel": "high",
                                        "processPackerName": null,
                                        "processPath": "c:\\windows\\system32\\notepad.exe",
                                        "processPathSize": null,
                                        "user": "TA66H0I6F225\\bdvm"
                                    },
                                    "type": "process"
                                }
                            ]
                        }
                    ],
                    "computerFqdn": "ta66h0i6f225",
                    "computerId": "694148bffe8d4e463ca5bd1e",
                    "computerIp": "1.1.1.1",
                    "computerMacAddresses": [
                        "005056a7862b"
                    ],
                    "computerName": "TA66H0I6F225",
                    "counters": {
                        "domains": 0,
                        "endpoints": 1,
                        "events": 17,
                        "files": 3,
                        "processes": 4,
                        "registries": 0,
                        "storages": 0
                    },
                    "detectionName": "BAT.Trojan.FormatC.Z",
                    "mitreTags": [
                        {
                            "category": "Execution",
                            "techniques": [
                                {
                                    "id": "T1059",
                                    "name": "Command and Scripting Interpreter",
                                    "subtechniques": null
                                }
                            ]
                        }
                    ],
                    "nodes": [
                        {
                            "alertIds": [
                                "69415ce1997e9c48ed12c361"
                            ],
                            "details": {
                                "file": {
                                    "isExecutable": true,
                                    "md5": null,
                                    "name": "<system>",
                                    "path": "<system>",
                                    "sha256": null,
                                    "size": 0
                                },
                                "killProcess": null,
                                "process": {
                                    "commandLine": "<did_not_receive>",
                                    "date": "2025-12-16T14:05:30+02:00",
                                    "name": "<system>",
                                    "parent": {
                                        "name": "<SYSTEM>",
                                        "path": null,
                                        "pid": 0
                                    },
                                    "pid": 0,
                                    "userId": null,
                                    "userName": "NT AUTHORITY\\SYSTEM"
                                },
                                "quarantine": null,
                                "sandbox": null
                            },
                            "id": "69415c9d5f5c8b75247c58e4",
                            "name": "<system>",
                            "type": "process_execution"
                        }
                    ],
                    "partOf": null,
                    "transitions": [
                        {
                            "date": "2025-12-16T15:19:59+02:00",
                            "from": "69415c9d5f5c8b75247c58e2",
                            "to": "69415c9d5f5c8b75247c58e5"
                        }
                    ],
                    "triggerNodeId": "69415c9d5f5c8b75247c58e5"
                },
                "incidentId": "69415c9d5f5c8b75247c58d1",
                "incidentLink": "https://gravityzone.domain/#!/incidents/view/69415c9d5f5c8b75247c58d1",
                "incidentNumber": 473,
                "incidentType": "incident",
                "lastProcessed": "2025-12-16T15:21:48+02:00",
                "lastUpdated": "2025-12-16T15:21:38+02:00",
                "mainAction": "blocked",
                "notes": [
                    {
                        "created": "2026-02-23T13:27:53+02:00",
                        "id": "699c39b9cf8645f670042eb0",
                        "text": "InvestigationInProgress",
                        "userId": "6941466eda1158ec9f0ecb5d",
                        "userName": "user email"
                    }
                ],
                "priority": "unknown",
                "severityScore": 43,
                "status": "open"
            },
            "Severity": {
                "Score": 43
            },
            "Status": 0,
            "Type": "incident"
        }
    }
}
```

#### Human Readable Output

>### GravityZone Incident
>
>|Action Taken|Assigned Priority|Assigned User|Company Name|Created|Endpoint ID|Endpoint IP|Endpoint Name|ID|Last Processed|Last Updated|Number|Permalink|Severity Score|Status|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Blocked | Unknown | Unassigned | Company | 2025-12-16T15:20:21+02:00 | 694148bffe8d4e463ca5bd1e | 1.1.1.1 | TA66H0I6F225 | 69415c9d5f5c8b75247c58d1 | 2025-12-16T15:21:48+02:00 | 2025-12-16T15:21:38+02:00 | 473 | <https://gravityzone.domain/#!/incidents/view/69415c9d5f5c8b75247c58d1> | 43% | 0 (Pending) | Incident (EDR) |
>
>### Incident Notes
>
>|Text|User|Date|
>|---|---|---|
>| InvestigationInProgress | user email | 2026-02-23T13:27:53+02:00 |
>
>### Incident Alerts
>
>|Date|Detected By|Name|Resources|
>|---|---|---|---|
>| 2025-12-16T15:20:19+02:00 | KeyloggingAPICall (EDR Detection) | KeyloggingAPICall | [{"Pid": 2592,"ProcessPath": "c:\\windows\\system32\\notepad.exe","CommandLine": "\"C:\\Windows\\System32\\notepad.exe\" C:\\Users\\bdvm\\Desktop\\New Text Document.txt","ParentPid": 5212,"ParentProcessPath": "c:\\windows\\explorer.exe","ParentProcessUser": "TA66H0I6F225\\bdvm","User": "TA66H0I6F225\\bdvm","ProcessAccessPrivileges": "elevated","ParentProcessAccessPrivileges": "elevated","ProcessIntegrityLevel": "high","ParentProcessIntegrityLevel": "high","Type": "process"}] |

### gz-incident-list

***
Retrieves incidents within the last three days from all endpoints or a specific endpoint.

#### Base Command

`gz-incident-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | The start date to retrieve incidents from. The default value is the current date minus three days. | Optional |
| to_date | The end date to retrieve incidents until. The default value is the current date and time. | Optional |
| limit | The maximum number of incidents to retrieve. | Optional |
| endpoint_id | The ID of the endpoint to list incidents for. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.IncidentsList.ID | String | The incident ID. |
| GravityZone.IncidentsList.Type | String | The incident type \('incident' / 'extendedIncident'\). |
| GravityZone.IncidentsList.CompanyName | String | The GravityZone company name where the incident is located. |
| GravityZone.IncidentsList.Number | Number | The incident number \(specific to the company\). |
| GravityZone.IncidentsList.SeverityScore | Number | The incident severity score \(0 - 100\). |
| GravityZone.IncidentsList.Status | Number | The incident status. |
| GravityZone.IncidentsList.ActionTaken | String | The action taken by the detecting technology \('reported' / 'blocked' / 'partially_blocked'\). |
| GravityZone.IncidentsList.Created | Date | The date when the incident was detected on the endpoint / sensor. |
| GravityZone.IncidentsList.LastUpdated | Date | The date when the incident was last updated in GravityZone or by the endpoint / sensor. |
| GravityZone.IncidentsList.LastProcessed | Date | The incident last processed date by GravityZone services. |
| GravityZone.IncidentsList.Permalink | String | The incident URL in the GravityZone Console. |
| GravityZone.IncidentsList.AssignedPriority | String | The priority assigned to the incident \('unknown' / 'low' / 'medium' / 'high' / 'critical'\). |
| GravityZone.IncidentsList.AssignedUserId | String | The ID of the user assigned to the incident. |
| GravityZone.IncidentsList.RawJSON | JSON | The raw JSON response from the GravityZone API. |
| GravityZone.IncidentsList.EndpointID | String | The endpoint ID. Available only for 'incident'-type incidents. |
| GravityZone.IncidentsList.EndpointHostname | String | The endpoint hostname. Available only for 'incident'-type incidents. |
| GravityZone.IncidentsList.EndpointIP | String | The endpoint IP address. Available only for 'incident'-type incidents. |

#### Command example

```!gz-incident-list```

#### Context Example

```json
{
    "GravityZone": {
        "IncidentsList": [
            {
                "ActionTaken": "reported",
                "AssignedPriority": "unknown",
                "AssignedUserId": null,
                "AttackTypes": [
                    "Persistence"
                ],
                "CompanyID": "611717cb22a30cee251b03f3",
                "CompanyName": "Company",
                "Created": "2026-02-23T13:09:34+02:00",
                "ID": "699c367136732459d7d3b1af",
                "LastProcessed": "2026-02-23T13:13:53+02:00",
                "LastUpdated": "2026-02-23T13:09:34+02:00",
                "Number": 1017,
                "Permalink": "https://gravityzone.domain/#!/incidents/view/699c367136732459d7d3b1af",
                "RawJSON": {
                    "assignee": null,
                    "attackTypes": [
                        "Persistence"
                    ],
                    "company": {
                        "id": "611717cb22a30cee251b03f3",
                        "name": "Company"
                    },
                    "created": "2026-02-23T13:09:34+02:00",
                    "details": {
                        "contains": null,
                        "counters": {
                            "ADInstances": 0,
                            "AWSInstances": 0,
                            "DGAs": 0,
                            "DNSs": 0,
                            "GCPInstances": 0,
                            "IPs": 0,
                            "IoTs": 0,
                            "atlassianBitbucketProducts": 0,
                            "atlassianConfluenceProducts": 0,
                            "atlassianInstances": 0,
                            "atlassianJiraProducts": 0,
                            "azureADInstances": 1,
                            "bitbucketProjects": 0,
                            "cloudStorages": 0,
                            "confluenceSpaces": 0,
                            "containers": 0,
                            "databases": 0,
                            "domains": 0,
                            "emails": 0,
                            "endpoints": 0,
                            "exfiltratedFiles": 0,
                            "externalDrives": 0,
                            "externalSources": 0,
                            "googleWorkspaceInstances": 0,
                            "identities": 1,
                            "internalEmails": 0,
                            "internalIPs": 0,
                            "mobileDevices": 0,
                            "office365Instances": 0,
                            "printers": 0,
                            "routers": 0,
                            "servers": 0,
                            "storages": 0,
                            "torNodes": 0,
                            "users": 1,
                            "virtualDesktops": 0
                        },
                        "partOf": null
                    },
                    "incidentId": "699c367136732459d7d3b1af",
                    "incidentLink": "https://gravityzone.domain/#!/incidents/view/699c367136732459d7d3b1af",
                    "incidentNumber": 1017,
                    "incidentType": "extendedIncident",
                    "lastProcessed": "2026-02-23T13:13:53+02:00",
                    "lastUpdated": "2026-02-23T13:09:34+02:00",
                    "mainAction": "reported",
                    "priority": "unknown",
                    "severityScore": 71,
                    "status": "in_progress"
                },
                "SeverityScore": 71,
                "Status": 1,
                "Type": "extendedIncident"
            }
        ]
    }
}
```

#### Human Readable Output

>### GravityZone Incidents List
>
>|ActionTaken|Assigned Priority|Assigned User ID|Attack Types|Company Name|Created|ID|Last Processed|Last Updated|Number|Permalink|Severity Score|Status|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Reported | Unknown | Unassigned | Persistence | Company | 2026-02-23T13:09:34+02:00 | 699c367136732459d7d3b1af | 2026-02-23T13:13:53+02:00 | 2026-02-23T13:09:34+02:00 | 1017 | <https://gravityzone.domain/#!/incidents/view/699c367136732459d7d3b1af> | 71% | 1 (Active) | Extended Incident (XDR) |

#### Command example

```!gz-incident-list from_date="2026-02-20" to_date="2026-02-21" limit="1"```

#### Context Example

```json
{
    "GravityZone": {
        "IncidentsList": [
            {
                "ActionTaken": "reported",
                "AssignedPriority": "unknown",
                "AssignedUserId": null,
                "AttackTypes": [
                    "Persistence"
                ],
                "CompanyID": "611717cb22a30cee251b03f3",
                "CompanyName": "Company",
                "Created": "2026-02-20T20:58:17+02:00",
                "ID": "6998b40f36732459d7d3aa58",
                "LastProcessed": "2026-02-20T21:20:47+02:00",
                "LastUpdated": "2026-02-20T20:58:17+02:00",
                "Number": 998,
                "Permalink": "https://gravityzone.domain/#!/incidents/view/6998b40f36732459d7d3aa58",
                "RawJSON": {
                    "assignee": null,
                    "attackTypes": [
                        "Persistence"
                    ],
                    "company": {
                        "id": "611717cb22a30cee251b03f3",
                        "name": "Company"
                    },
                    "created": "2026-02-20T20:58:17+02:00",
                    "details": {
                        "contains": null,
                        "counters": {
                            "ADInstances": 0,
                            "AWSInstances": 0,
                            "DGAs": 0,
                            "DNSs": 0,
                            "GCPInstances": 0,
                            "IPs": 0,
                            "IoTs": 0,
                            "atlassianBitbucketProducts": 0,
                            "atlassianConfluenceProducts": 0,
                            "atlassianInstances": 0,
                            "atlassianJiraProducts": 0,
                            "azureADInstances": 1,
                            "bitbucketProjects": 0,
                            "cloudStorages": 0,
                            "confluenceSpaces": 0,
                            "containers": 0,
                            "databases": 0,
                            "domains": 0,
                            "emails": 0,
                            "endpoints": 0,
                            "exfiltratedFiles": 0,
                            "externalDrives": 0,
                            "externalSources": 0,
                            "googleWorkspaceInstances": 0,
                            "identities": 1,
                            "internalEmails": 0,
                            "internalIPs": 0,
                            "mobileDevices": 0,
                            "office365Instances": 0,
                            "printers": 0,
                            "routers": 0,
                            "servers": 0,
                            "storages": 0,
                            "torNodes": 0,
                            "users": 1,
                            "virtualDesktops": 0
                        },
                        "partOf": null
                    },
                    "incidentId": "6998b40f36732459d7d3aa58",
                    "incidentLink": "https://gravityzone.domain/#!/incidents/view/6998b40f36732459d7d3aa58",
                    "incidentNumber": 998,
                    "incidentType": "extendedIncident",
                    "lastProcessed": "2026-02-20T21:20:47+02:00",
                    "lastUpdated": "2026-02-20T20:58:17+02:00",
                    "mainAction": "reported",
                    "priority": "unknown",
                    "severityScore": 71,
                    "status": "open"
                },
                "SeverityScore": 71,
                "Status": 0,
                "Type": "extendedIncident"
            }
        ]
    }
}
```

#### Human Readable Output

>### GravityZone Incidents List
>
>|ActionTaken|Assigned Priority|Assigned User ID|Attack Types|Company Name|Created|ID|Last Processed|Last Updated|Number|Permalink|Severity Score|Status|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Reported | Unknown | Unassigned | Persistence | Company | 2026-02-20T20:58:17+02:00 | 6998b40f36732459d7d3aa58 | 2026-02-20T21:20:47+02:00 | 2026-02-20T20:58:17+02:00 | 998 | <http://gravityzone.domain/#!/incidents/view/6998b40f36732459d7d3aa58> | 71% | 0 (Pending) | Extended Incident (XDR) |

#### Command example

```!gz-incident-list endpoint_id=694148bffe8d4e463ca5bd1e from_date="2025-11-20"```

#### Context Example

```json
{
    "GravityZone": {
        "IncidentsList": [
            {
                "ActionTaken": "reported",
                "AssignedPriority": "critical",
                "AssignedUserId": "6540b72b1ffbc14e1808bc00",
                "AttackTypes": [
                    "Malware"
                ],
                "CompanyID": "611717cb22a30cee251b03f3",
                "CompanyName": "Company",
                "Created": "2025-12-17T09:02:03+02:00",
                "ID": "694255755f5c8b75247c7ce2",
                "LastProcessed": "2025-12-17T09:02:13+02:00",
                "LastUpdated": "2025-12-17T09:02:03+02:00",
                "Number": 477,
                "Permalink": "https://gravityzone.domain/#!/incidents/view/694255755f5c8b75247c7ce2",
                "EndpointID" : "694148bffe8d4e463ca5bd1e",
                "EndpointHostname": "TA66H0I6F225",
                "EndpointIP": "1.1.1.1",
                "RawJSON": {
                    "assignee": "6540b72b1ffbc14e1808bc00",
                    "attackTypes": [
                        "Malware"
                    ],
                    "company": {
                        "id": "611717cb22a30cee251b03f3",
                        "name": "Company"
                    },
                    "created": "2025-12-17T09:02:03+02:00",
                    "details": {
                        "computerFqdn": "ta66h0i6f225",
                        "computerId": "694148bffe8d4e463ca5bd1e",
                        "computerIp": "1.1.1.1",
                        "computerMacAddresses": [
                            "005056a7862b"
                        ],
                        "computerName": "TA66H0I6F225",
                        "counters": {
                            "domains": 0,
                            "endpoints": 1,
                            "events": 6,
                            "files": 0,
                            "processes": 2,
                            "registries": 0,
                            "storages": 0
                        },
                        "detectionName": "RegSecurityDump",
                        "partOf": null
                    },
                    "incidentId": "694255755f5c8b75247c7ce2",
                    "incidentLink": "https://gravityzone.domain/#!/incidents/view/694255755f5c8b75247c7ce2",
                    "incidentNumber": 477,
                    "incidentType": "incident",
                    "lastProcessed": "2025-12-17T09:02:13+02:00",
                    "lastUpdated": "2025-12-17T09:02:03+02:00",
                    "mainAction": "reported",
                    "priority": "critical",
                    "severityScore": 33,
                    "status": "closed"
                },
                "SeverityScore": 33,
                "Status": 2,
                "Type": "incident"
            }
        ]
    }
}
```

#### Human Readable Output

>### GravityZone Incidents List
>
>|ActionTaken|Assigned Priority|Assigned User ID|Attack Types|Company Name|Created|Endpoint ID|Endpoint IP|Endpoint Name|ID|Last Processed|Last Updated|Number|Permalink|Severity Score|Status|Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Reported | Critical | 6540b72b1ffbc14e1808bc00 | Malware | Company | 2025-12-17T09:02:03+02:00 | 694148bffe8d4e463ca5bd1e | 1.1.1.1 | TA66H0I6F225 | 694255755f5c8b75247c7ce2 | 2025-12-17T09:02:13+02:00 | 2025-12-17T09:02:03+02:00 | 477 | <https://gravityzone.domain/#!/incidents/view/694255755f5c8b75247c7ce2> | 33% | 2 (Done) | Incident (EDR) |

### gz-incident-add-note

***
Adds a note to one or more incidents.

#### Base Command

`gz-incident-add-note`

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

#### Command example

```!gz-incident-add-note id=69415c9d5f5c8b75247c58d1 note=InvestigationInProgress```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "AddIncidentNote": {
                "CommandStatus": "Success",
                "IncidentID": "69415c9d5f5c8b75247c58d1",
                "Note": "InvestigationInProgress"
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.AddIncidentNote command on incidents 69415c9d5f5c8b75247c58d1
>
>|IncidentID|Note|CommandStatus|
>|---|---|---|
>| 69415c9d5f5c8b75247c58d1 | InvestigationInProgress | Success |

### gz-incident-change-status

***
Changes the status of one or more incidents.

#### Base Command

`gz-incident-change-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The IDs of the incidents to update. Supports comma separated values. | Required |
| status | The new status of the incidents. Possible values are: PENDING, ACTIVE, DONE, ARCHIVE. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GravityZone.Command.ChangeIncidentStatus.IncidentID | String | The incident ID. |
| GravityZone.Command.ChangeIncidentStatus.IncidentStatus | String | The requested status of the incident. |
| GravityZone.Command.ChangeIncidentStatus.CommandStatus | String | The command status. |

#### Command example

```!gz-incident-change-status id=69415c9d5f5c8b75247c58d1 status=ACTIVE```

#### Context Example

```json
{
    "GravityZone": {
        "Command": {
            "ChangeIncidentStatus": {
                "CommandStatus": "Success",
                "IncidentID": "69415c9d5f5c8b75247c58d1",
                "IncidentStatus": "ACTIVE"
            }
        }
    }
}
```

#### Human Readable Output

>### GravityZone.Command.ChangeIncidentStatus command on incidents 69415c9d5f5c8b75247c58d1
>
>|IncidentID|IncidentStatus|CommandStatus|
>|---|---|---|
>| 69415c9d5f5c8b75247c58d1 | ACTIVE | Success |

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

You can enable incident mirroring between Cortex XSOAR incidents and GravityZone corresponding incidents (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Disables incident mirroring. |
    | Incoming | Reflects status changes from GravityZone incidents in Cortex XSOAR incidents. |
    | Outgoing | Reflects status changes from Cortex XSOAR incidents in GravityZone incidents. |
    | Both | Synchronizes status changes bidirectionally between Cortex XSOAR and GravityZone incidents. |

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
