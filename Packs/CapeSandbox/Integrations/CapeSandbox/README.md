# CAPEv2 Malware Sandbox

CAPE Sandbox is an open-source software for automating the analysis of suspicious files and URLs. To learn more about CAPE Sandbox, visit the [official CAPE documentation](https://capev2.readthedocs.io/).

This integration was integrated and tested with CAPE V2 API.

## Authorization

This integration supports two authentication methods:

- **API Token** - Recommended. Generate a token in your CAPE Sandbox instance.
- **Username and Password** - The integration will automatically generate authentication tokens.

## Configure Cape Sandbox in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the CAPE Sandbox. | True |
| API token | Token value as generated in CAPE. If provided, Username/Password is not required. | False |
| Username | Required if 'Username and Password' is selected above.<br/>Provides credentials for token generation.<br/> | False |
| Password | Password for authentication. Required if using Username/Password authentication method. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cape-file-submit

***
Submits a file for analysis to CAPE Sandbox. This command supports PCAP files and automatically sets the `pcap` option to `1`. The command polls the CAPE server until the analysis task is complete, and then returns the task results.

**Note:** Analysis scans may take a long time to complete and could cause a timeout. If a timeout occurs, use the `!cape-tasks-list task_id=<task_id>` command to check the status of your task.

#### Base Command

`cape-file-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file to submit for analysis. | Required |
| package | The analysis package to use (e.g., `ps1` for PowerShell scripts, `exe` for executables, `dll` for DLL files). For available packages, see the [CAPE documentation](https://capev2.readthedocs.io/en/latest/usage/packages.html). | Optional |
| timeout | The maximum time in seconds to allow for the analysis to complete. | Optional |
| priority | The priority level to assign to the task (1-3, where 1 is highest priority). | Optional |
| options | A string of additional options to pass to the analysis (e.g., `options:function=DllMain`). For available options, see the [CAPE documentation](https://capev2.readthedocs.io/en/latest/usage/submit.html#options-options-available). | Optional |
| machine | The specific ID of the analysis machine to use for the task. | Optional |
| platform | The name of the platform to select the analysis machine from (e.g., `windows`). | Optional |
| tags | Comma-separated tags to associate with the analysis task. | Optional |
| custom | A custom string to pass to the analysis. | Optional |
| memory | Set to `true` to enable a full memory dump during analysis. Possible values are: `true`, `false`. | Optional |
| enforce_timeout | Set to `true` to strictly enforce the analysis timeout. Possible values are: `true`, `false`. | Optional |
| clock | The VM clock time in the format `%m-%d-%Y %H:%M:%S`. | Optional |

#### Context Output

| **Path** | **Description** |
| --- | --- |
| Cape.Task | Task data returned from CAPE when analysis is ready. This object contains details about the submitted task and its status. |

### cape-file-view

***
View detailed information about a file that has been analyzed by CAPE Sandbox. You must specify at least one identifier: Task ID, MD5 hash, or SHA256 hash.

#### Base Command

`cape-file-view`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The unique identifier of the analysis task to view. | Optional |
| md5 | The MD5 hash of the file to view. | Optional |
| sha256 | The SHA256 hash of the file to view. | Optional |

#### Context Output

| **Path** | **Description** |
| --- | --- |
| Cape.File.id | The ID of the file or task. |
| Cape.File.file_type | The detected type of the file. |
| Cape.File.md5 | The MD5 hash of the file. |
| Cape.File.crc32 | The CRC32 checksum of the file. |
| Cape.File.sha256 | The SHA256 hash of the file. |
| Cape.File.sha512 | The SHA512 hash of the file. |
| Cape.File.parent | The parent process or source of the file. |
| Cape.File.source_url | The URL from which the file was obtained, if applicable. |

### cape-sample-download

***
Download a sample file from a CAPE Sandbox task. You must specify at least one identifier: Task ID, MD5 hash, SHA1 hash, or SHA256 hash. The downloaded file will be added to the War Room.

#### Base Command

`cape-sample-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The unique identifier of the analysis task to download the sample from. | Optional |
| md5 | The MD5 hash of the sample file to download. | Optional |
| sha1 | The SHA1 hash of the sample file to download. | Optional |
| sha256 | The SHA256 hash of the sample file to download. | Optional |

#### Context Output

There is no context output for this command. The command directly downloads the file.

### cape-url-submit

***
Submit a URL for analysis to CAPE Sandbox. The command polls the CAPE server until the analysis task is reported as complete, and then returns the task view with the analysis results.

**Note:** Analysis scans may take a long time to complete and could cause a timeout. If a timeout occurs, use the `!cape-tasks-list task_id=<task_id>` command to check the status of your task.

#### Base Command

`cape-url-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to submit for analysis. | Required |
| package | The analysis package to use for URL analysis (e.g., `ie` for Internet Explorer, `chrome` for Chrome browser). For available packages, see the [CAPE documentation](https://capev2.readthedocs.io/en/latest/usage/packages.html). | Optional |
| timeout | The maximum time in seconds to allow for the analysis to complete. | Optional |
| priority | The priority level to assign to the task (1-3, where 1 is highest priority). | Optional |
| options | A string of additional options to pass to the analysis (e.g., `options:function=DllMain`). For available options, see the [CAPE documentation](https://capev2.readthedocs.io/en/latest/usage/submit.html#options-options-available). | Optional |
| machine | The specific ID of the analysis machine to use for the task. | Optional |
| platform | The name of the platform to select the analysis machine from (e.g., `windows`). | Optional |
| tags | Comma-separated tags to associate with the analysis task. | Optional |
| custom | A custom string to pass to the analysis. | Optional |
| memory | Set to `true` to enable a full memory dump during analysis. Possible values are: `true`, `false`. | Optional |
| enforce_timeout | Set to `true` to strictly enforce the analysis timeout. Possible values are: `true`, `false`. | Optional |
| clock | The VM clock time in the format `%m-%d-%Y %H:%M:%S`. | Optional |
| polling | Enable or disable generic polling for the CAPE task. Possible values are: `true`, `false`. Default is `true`. | Optional |
| pollingInterval | The polling interval in seconds. It is strongly recommended to use an interval of 60 seconds or more to prevent API throttling by the CAPE server. | Optional |
| pollingTimeout | The total time allowed in seconds for the XSOAR/XSIAM polling sequence to complete. | Optional |

#### Context Output

| **Path** | **Description** |
| --- | --- |
| Cape.Task | Task data returned from CAPE when analysis is ready. This object contains details about the submitted task and its status. |

### cape-task-delete

***
Delete a CAPE Sandbox analysis task by its Task ID.

#### Base Command

`cape-task-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The unique identifier of the task to delete. | Required |

#### Context Output

There is no context output for this command.

### cape-tasks-list

***
Returns a list of CAPE Sandbox tasks. If a `task_id` is provided, the command returns the detailed information for that specific task.

#### Base Command

`cape-tasks-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The unique identifier of the task to retrieve. If provided, returns details for that specific task only. | Optional |
| page | The page number for pagination (starts at 1). | Optional |
| page_size | The number of tasks to return per page. Maximum is 50. Default is 50. | Optional |

#### Context Output

| **Path** | **Description** |
| --- | --- |
| Cape.Task | Task data, including details for a single task if `task_id` was provided, or a list of tasks. |

### cape-task-report-get

***
Retrieve the analysis report associated with a specified CAPE Sandbox task ID. If `zip=true`, the report will be returned as a downloadable ZIP file.

#### Base Command

`cape-task-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The unique identifier of the task for which to retrieve the report. | Required |
| format | The desired format of the report. Possible values are: `json` (full JSON report), `maec` (MAEC 4.1 format), `maec5` (MAEC 5.0 format), `metadata` (metadata only), `lite` (lightweight report), `all` (all available formats). Default is `json`. | Optional |
| zip | Set to `true` to download the report as a ZIP file. Possible values are: `true`, `false`. Default is `false`. | Optional |

#### Context Output

| **Path** | **Description** |
| --- | --- |
| Cape.Task.Report | Details from the CAPE analysis report info object. This will vary based on the report format requested. |

### cape-pcap-file-download

***
Download the PCAP (Packet Capture) network dump file associated with a specific CAPE Sandbox task ID. The PCAP file contains all network traffic captured during the analysis and can be analyzed with tools like Wireshark.

#### Base Command

`cape-pcap-file-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The unique identifier of the task for which to download the PCAP file. | Required |

#### Context Output

There is no context output for this command. The command directly downloads the PCAP file.

### cape-task-screenshot-download

***
Download screenshots captured during the analysis of a CAPE Sandbox task. Screenshots show the visual behavior of the analyzed file or URL. If a specific `screenshot` number is provided, only that single screenshot will be downloaded; otherwise, all available screenshots for the task will be downloaded as a ZIP file.

#### Base Command

`cape-task-screenshot-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The unique identifier of the task for which to download screenshots. | Required |
| screenshot | The specific screenshot number to download (e.g., `1`, `2`). If not provided, all screenshots are downloaded. | Optional |

#### Context Output

There is no context output for this command. The command directly downloads the screenshot files.

### cape-machines-list

***
Returns a list of available analysis machines configured in CAPE Sandbox. If a `machine_name` is provided, the command returns detailed information for that specific machine.

#### Base Command

`cape-machines-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_name | The name of the machine to fetch details for. If provided, returns details for that specific machine only. | Optional |
| all_results | Set to `true` to return all machines, ignoring the `limit` parameter. Possible values are: `true`, `false`. Default is `false`. | Optional |
| limit | The maximum number of machines to return when listing. Default is 50. | Optional |

#### Context Output

| **Path** | **Description** |
| --- | --- |
| Cape.Machine | Machine data, including details for a single machine if `machine_name` was provided, or a list of machines. |

### cape-cuckoo-status-get

***
Returns the overall status of the CAPE/Cuckoo system in a human-readable format. This command provides a quick overview of the sandbox's operational status.

#### Base Command

`cape-cuckoo-status-get`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command. The output is human-readable text directly in the War Room.
