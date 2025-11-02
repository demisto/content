# CAPEv2 Malware Sandbox

CAPE Sandbox is an Open Source software for automating analysis of suspicious files.
This integration was integrated and tested with CAPE V2 API of CapeSandbox.

## Configure Cape Sandbox in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the CAPE Sandbox. | True |
| Password | Token value as generated in CAPE. If provided, Username/Password is not required. | False |
| Username | Required if 'Username and Password' is selected above.<br/>Provides credentials for token generation.<br/> | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cape-file-submit

***
Submit a file for analysis. Supports PCAP with automatic pcap=1. Polls until the task is reported and then returns the task view.

#### Base Command

`cape-file-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The War Room entry ID of the file to submit. | Required |
| package | Analysis package (e.g., ps1). | Optional |
| timeout | Analysis timeout in seconds. | Optional |
| priority | Priority to assign to the task (1-3). | Optional |
| options | Options string (e.g., options:function=DllMain). | Optional |
| machine | ID of the analysis machine to use. | Optional |
| platform | Platform name to select the analysis machine from (e.g., windows). | Optional |
| tags | Comma-separated tags. | Optional |
| custom | Custom string to pass over the analysis. | Optional |
| memory | Enable full memory dump (true/false). | Optional |
| enforce_timeout | Enforce timeout (true/false). | Optional |
| clock | VM clock (format %m-%d-%Y %H:%M:%S). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cape.Task | Unknown | Task data returned from CAPE when analysis is ready. |

### cape-file-view

***
View file information by Task ID, MD5, or SHA256.

#### Base Command

`cape-file-view`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Optional |
| md5 | MD5 hash. | Optional |
| sha256 | SHA256 hash. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cape.File.id | String | File/task ID. |
| Cape.File.file_type | String | File type. |
| Cape.File.md5 | String | MD5. |
| Cape.File.crc32 | String | CRC32. |
| Cape.File.sha256 | String | SHA256. |
| Cape.File.sha512 | String | SHA512. |
| Cape.File.parent | String | Parent. |
| Cape.File.source_url | String | Source URL. |

### cape-sample-download

***
Download a sample from a Task by Task ID, MD5, SHA1 or SHA256.

#### Base Command

`cape-sample-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Optional |
| md5 | MD5 hash. | Optional |
| sha1 | SHA1 hash. | Optional |
| sha256 | SHA256 hash. | Optional |

#### Context Output

There is no context output for this command.

### cape-url-submit

***
Submit a URL for analysis. Polls until the task is reported and then returns the task view.

#### Base Command

`cape-url-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to analyze. | Required |
| package | Analysis package. | Optional |
| timeout | Analysis timeout in seconds. | Optional |
| priority | Priority to assign to the task (1-3). | Optional |
| options | Options string (e.g., options:function=DllMain). | Optional |
| machine | ID of the analysis machine to use. | Optional |
| platform | Platform name to select the analysis machine from (e.g., windows). | Optional |
| tags | Comma-separated tags. | Optional |
| custom | Custom string to pass over the analysis. | Optional |
| memory | Enable full memory dump (true/false). | Optional |
| enforce_timeout | Enforce timeout (true/false). | Optional |
| clock | VM clock (format %m-%d-%Y %H:%M:%S). | Optional |
| polling | Cape generic polling. Possible values are: true, false. Default is true. | Optional |
| pollingInterval | The polling interval **in seconds**. We strongly recommend an interval of 60 seconds or more to prevent API throttling by the CAPE server. | Optional |
| pollingTimeout | Total time allowed **in seconds** for the XSOAR polling sequence to complete. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cape.Task | Unknown | Task data returned from CAPE when analysis is ready. |

### cape-task-delete

***
Delete CAPE task by ID.

#### Base Command

`cape-task-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID to delete. | Required |

#### Context Output

There is no context output for this command.

### cape-tasks-list

***
Returns list of tasks. If task_id is provided, returns the task details.

#### Base Command

`cape-tasks-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID to retrieve (optional). | Optional |
| page | Page number (starts at 1). | Optional |
| page_size | Page size (API max is 50). Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cape.Task | Unknown | Task data. |

### cape-task-report-get

***
Returns the report associated with the specified task ID. If zip=true, a ZIP file is returned for download.

#### Base Command

`cape-task-report-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Required |
| format | Report format. Possible values are: json, maec, maec5, metadata, lite, all. Default is json. | Optional |
| zip | Download report as ZIP file. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cape.Task.Report | Unknown | Details from the CAPE analysis report info object. |

### cape-pcap-file-download

***
Download the PCAP network dump file associated with the task ID.

#### Base Command

`cape-pcap-file-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Required |

#### Context Output

There is no context output for this command.

### cape-task-screenshot-download

***
Download screenshots for a task. If 'screenshot' is provided, downloads that single screenshot.

#### Base Command

`cape-task-screenshot-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | Task ID. | Required |
| screenshot | Specific screenshot number to download (optional). If not provided, all are downloaded. | Optional |

#### Context Output

There is no context output for this command.

### cape-machines-list

***
Returns a list of analysis machines. If machine_name is provided, returns details for that machine.

#### Base Command

`cape-machines-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_name | Machine name to fetch (optional). | Optional |
| all_results | Return all machines, ignoring the limit (true/false). Possible values are: true, false. Default is false. | Optional |
| limit | Maximum number of machines to return when listing. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cape.Machine | Unknown | Machine data. |

### cape-cuckoo-status-get

***
Returns overall CAPE/Cuckoo status. Human-readable only.

#### Base Command

`cape-cuckoo-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
