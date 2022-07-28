HarfangLab EDR Connector,
Compatible version 2.13.7+
This integration was integrated and tested with version 2.13.7+ of Hurukai

## Configure HarfangLab EDR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HarfangLab EDR.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API URL |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | API Key |  | False |
    | Long running instance |  | False |
    | Incidents Fetch Interval |  | False |
    | Fetch alerts with type | Comma-separated list of types of alerts to fetch \(sigma, yara, hlai, vt, ransom, ioc, glimps, orion...\). | False |
    | Minimum severity of alerts to fetch |  | True |
    | Fetch alerts with status (ACTIVE, CLOSED) |  | False |
    | First fetch time | Start fetching alerts whose creation date is higher than now minus &amp;lt;first_fetch&amp;gt; days. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### test-module
***
Allows to test that the HarfangLab EDR API is reachable


#### Base Command

`test-module`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### fetch-incidents
***
Allows to retrieve incidents from the HarfangLab EDR API


#### Base Command

`fetch-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### harfanglab-get-endpoint-info
***
Get endpoint information from agent_id


#### Base Command

`harfanglab-get-endpoint-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Agent | unknown | Agent information | 

#### Command example
```!harfanglab-get-endpoint-info agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Agent": {
            "additional_info": {
                "additional_info1": null,
                "additional_info2": null,
                "additional_info3": null,
                "additional_info4": null
            },
            "avg_cpu": 1,
            "avg_memory": 183558144,
            "bitness": "x64",
            "cpu_count": 2,
            "cpu_frequency": 3192,
            "distroid": null,
            "dnsdomainname": null,
            "domain": null,
            "domainname": "WORKGROUP",
            "driver_enabled": true,
            "driver_policy": false,
            "effective_policy_id": "e96699ef-3dd9-4718-90ef-c7e5646fd466",
            "effective_policy_revision": 5,
            "external_ipaddress": "<REDACTED>",
            "firstseen": "2022-06-15T06:42:50.008015Z",
            "group_count": 0,
            "groups": [],
            "hostname": "DC-01",
            "id": "0fae71cf-ebde-4533-a50c-b3c0290378db",
            "installdate": "2022/06/15 06:38:58",
            "ipaddress": "<REDACTED>",
            "ipmask": "<REDACTED>",
            "isolation_policy": false,
            "isolation_state": true,
            "lastseen": "2022-07-28T07:41:32.197641Z",
            "lastseen_error": "2022-07-28T07:47:02.197641Z",
            "lastseen_warning": "2022-07-28T07:43:44.197641Z",
            "machine_boottime": "2022-06-28T14:18:31Z",
            "osbuild": 20348,
            "osid": "00454-40000-00001-AA596",
            "osmajor": 10,
            "osminor": 0,
            "osproducttype": "Windows Server 2022 Standard Evaluation",
            "ostype": "windows",
            "osversion": "10.0.20348",
            "policy": {
                "binary_download_enabled": true,
                "description": "",
                "hibou_minimum_level": "critical",
                "hibou_mode": 0,
                "hibou_skip_signed_ms": false,
                "hibou_skip_signed_others": false,
                "hlai_minimum_level": "critical",
                "hlai_mode": 1,
                "hlai_skip_signed_ms": true,
                "hlai_skip_signed_others": false,
                "id": "e96699ef-3dd9-4718-90ef-c7e5646fd466",
                "ioc_mode": 2,
                "ioc_ruleset": null,
                "loglevel": "ERROR",
                "name": "No psexec",
                "ransomguard_alert_only": false,
                "revision": 5,
                "self_protection": false,
                "sigma_ruleset": 1,
                "sleepjitter": 10,
                "sleeptime": 60,
                "telemetry_alerts_limit": false,
                "telemetry_alerts_limit_value": 1000,
                "telemetry_log": true,
                "telemetry_log_limit": false,
                "telemetry_log_limit_value": 1000,
                "telemetry_network": true,
                "telemetry_network_limit": false,
                "telemetry_network_limit_value": 1000,
                "telemetry_process": true,
                "telemetry_process_limit": false,
                "telemetry_process_limit_value": 1000,
                "telemetry_remotethread": true,
                "telemetry_remotethread_limit": false,
                "telemetry_remotethread_limit_value": 1000,
                "tenant": null,
                "use_driver": true,
                "use_isolation": true,
                "use_process_block": true,
                "use_ransomguard": true,
                "use_sigma": true,
                "use_sigma_process_block": false,
                "yara_mode": 1,
                "yara_ruleset": null,
                "yara_skip_signed_ms": true,
                "yara_skip_signed_others": false
            },
            "producttype": "server",
            "servicepack": null,
            "starttime": "2022-06-28T14:18:47Z",
            "status": "online",
            "tenant": null,
            "total_memory": 2133962752,
            "uninstall_status": 0,
            "update_experimental": false,
            "update_status": 0,
            "version": "2.15.0"
        }
    }
}
```

#### Human Readable Output

>### Endpoint information for agent_id : 0fae71cf-ebde-4533-a50c-b3c0290378db
>|additional_info|avg_cpu|avg_memory|bitness|cpu_count|cpu_frequency|domainname|driver_enabled|driver_policy|effective_policy_id|effective_policy_revision|external_ipaddress|firstseen|group_count|hostname|id|installdate|ipaddress|ipmask|isolation_policy|isolation_state|lastseen|lastseen_error|lastseen_warning|machine_boottime|osbuild|osid|osmajor|osminor|osproducttype|ostype|osversion|policy|producttype|starttime|status|total_memory|uninstall_status|update_experimental|update_status|version|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| additional_info1: null<br/>additional_info2: null<br/>additional_info3: null<br/>additional_info4: null | 1.0 | 183558144.0 | x64 | 2 | 3192 | WORKGROUP | true | false | e96699ef-3dd9-4718-90ef-c7e5646fd466 | 5 | <REDACTED> | 2022-06-15T06:42:50.008015Z | 0 | DC-01 | 0fae71cf-ebde-4533-a50c-b3c0290378db | 2022/06/15 06:38:58 | <REDACTED> | <REDACTED> | false | true | 2022-07-28T07:41:32.197641Z | 2022-07-28T07:47:02.197641Z | 2022-07-28T07:43:44.197641Z | 2022-06-28T14:18:31Z | 20348 | 00454-40000-00001-AA596 | 10 | 0 | Windows Server 2022 Standard Evaluation | windows | 10.0.20348 | id: e96699ef-3dd9-4718-90ef-c7e5646fd466<br/>tenant: null<br/>name: No psexec<br/>description: <br/>revision: 5<br/>sleeptime: 60<br/>sleepjitter: 10<br/>telemetry_process: true<br/>telemetry_process_limit: false<br/>telemetry_process_limit_value: 1000<br/>telemetry_network: true<br/>telemetry_network_limit: false<br/>telemetry_network_limit_value: 1000<br/>telemetry_log: true<br/>telemetry_log_limit: false<br/>telemetry_log_limit_value: 1000<br/>telemetry_remotethread: true<br/>telemetry_remotethread_limit: false<br/>telemetry_remotethread_limit_value: 1000<br/>telemetry_alerts_limit: false<br/>telemetry_alerts_limit_value: 1000<br/>binary_download_enabled: true<br/>loglevel: ERROR<br/>use_sigma: true<br/>ioc_mode: 2<br/>hlai_mode: 1<br/>hlai_skip_signed_ms: true<br/>hlai_skip_signed_others: false<br/>hlai_minimum_level: critical<br/>hibou_mode: 0<br/>hibou_skip_signed_ms: false<br/>hibou_skip_signed_others: false<br/>hibou_minimum_level: critical<br/>yara_mode: 1<br/>yara_skip_signed_ms: true<br/>yara_skip_signed_others: false<br/>use_driver: true<br/>use_isolation: true<br/>use_ransomguard: true<br/>ransomguard_alert_only: false<br/>self_protection: false<br/>use_process_block: true<br/>use_sigma_process_block: false<br/>sigma_ruleset: 1<br/>yara_ruleset: null<br/>ioc_ruleset: null | server | 2022-06-28T14:18:47Z | online | 2133962752.0 | 0 | false | 0 | 2.15.0 |


### harfanglab-endpoint-search
***
Search for endpoint information from a hostname


#### Base Command

`harfanglab-endpoint-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Agent.id | string | agent id | 
| Harfanglab.status | string | Status | 

#### Command example
```!harfanglab-endpoint-search hostname="DC-01"```
#### Context Example
```json
{
    "Harfanglab": {
        "Agent": {
            "additional_info": {
                "additional_info1": null,
                "additional_info2": null,
                "additional_info3": null,
                "additional_info4": null
            },
            "avg_cpu": 0.6,
            "avg_memory": 125627596,
            "bitness": "x64",
            "cpu_count": 2,
            "cpu_frequency": 3192,
            "distroid": null,
            "dnsdomainname": null,
            "domain": null,
            "domainname": "WORKGROUP",
            "driver_enabled": true,
            "driver_policy": false,
            "external_ipaddress": "<REDACTED>",
            "firstseen": "2022-06-14T22:23:08.393381Z",
            "group_count": 0,
            "groups": [],
            "hostname": "DC-01",
            "id": "706d4524-dc2d-4438-bfef-3b620646db7f",
            "installdate": "2022/06/14 21:56:49",
            "ipaddress": "<REDACTED>",
            "ipmask": "<REDACTED>",
            "isolation_policy": false,
            "isolation_state": false,
            "lastseen": "2022-06-15T06:33:46.544505Z",
            "lastseen_error": "2022-06-15T06:39:16.544505Z",
            "lastseen_warning": "2022-06-15T06:35:58.544505Z",
            "machine_boottime": "2022-06-14T22:00:23Z",
            "osbuild": 20348,
            "osid": "00454-40000-00001-AA081",
            "osmajor": 10,
            "osminor": 0,
            "osproducttype": "Windows Server 2022 Standard Evaluation",
            "ostype": "windows",
            "osversion": "10.0.20348",
            "policy": {
                "binary_download_enabled": true,
                "description": "",
                "hibou_minimum_level": "critical",
                "hibou_mode": 0,
                "hibou_skip_signed_ms": false,
                "hibou_skip_signed_others": false,
                "hlai_minimum_level": "critical",
                "hlai_mode": 1,
                "hlai_skip_signed_ms": true,
                "hlai_skip_signed_others": false,
                "id": "e96699ef-3dd9-4718-90ef-c7e5646fd466",
                "ioc_mode": 2,
                "ioc_ruleset": null,
                "loglevel": "ERROR",
                "name": "No psexec",
                "ransomguard_alert_only": false,
                "revision": 5,
                "self_protection": false,
                "sigma_ruleset": 1,
                "sleepjitter": 10,
                "sleeptime": 60,
                "telemetry_alerts_limit": false,
                "telemetry_alerts_limit_value": 1000,
                "telemetry_log": true,
                "telemetry_log_limit": false,
                "telemetry_log_limit_value": 1000,
                "telemetry_network": true,
                "telemetry_network_limit": false,
                "telemetry_network_limit_value": 1000,
                "telemetry_process": true,
                "telemetry_process_limit": false,
                "telemetry_process_limit_value": 1000,
                "telemetry_remotethread": true,
                "telemetry_remotethread_limit": false,
                "telemetry_remotethread_limit_value": 1000,
                "tenant": null,
                "use_driver": true,
                "use_isolation": true,
                "use_process_block": true,
                "use_ransomguard": true,
                "use_sigma": true,
                "use_sigma_process_block": false,
                "yara_mode": 1,
                "yara_ruleset": null,
                "yara_skip_signed_ms": true,
                "yara_skip_signed_others": false
            },
            "producttype": "server",
            "servicepack": null,
            "starttime": "2022-06-14T22:02:32Z",
            "status": "offline",
            "tenant": null,
            "total_memory": 2133962752,
            "uninstall_status": 0,
            "update_experimental": false,
            "update_status": 0,
            "version": "2.15.0"
        }
    }
}
```

#### Human Readable Output

>### Endpoint information for Hostname : DC-01
>|additional_info|avg_cpu|avg_memory|bitness|cpu_count|cpu_frequency|domainname|driver_enabled|driver_policy|external_ipaddress|firstseen|group_count|hostname|id|installdate|ipaddress|ipmask|isolation_policy|isolation_state|lastseen|lastseen_error|lastseen_warning|machine_boottime|osbuild|osid|osmajor|osminor|osproducttype|ostype|osversion|policy|producttype|starttime|status|total_memory|uninstall_status|update_experimental|update_status|version|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| additional_info1: null<br/>additional_info2: null<br/>additional_info3: null<br/>additional_info4: null | 1.0 | 183558144.0 | x64 | 2 | 3192 | WORKGROUP | true | false | <REDACTED> | 2022-06-15T06:42:50.008015Z | 0 | DC-01 | 0fae71cf-ebde-4533-a50c-b3c0290378db | 2022/06/15 06:38:58 | <REDACTED> | <REDACTED> | false | true | 2022-07-28T07:41:32.197641Z | 2022-07-28T07:47:02.197641Z | 2022-07-28T07:43:44.197641Z | 2022-06-28T14:18:31Z | 20348 | 00454-40000-00001-AA596 | 10 | 0 | Windows Server 2022 Standard Evaluation | windows | 10.0.20348 | id: e96699ef-3dd9-4718-90ef-c7e5646fd466<br/>tenant: null<br/>name: No psexec<br/>description: <br/>revision: 5<br/>sleeptime: 60<br/>sleepjitter: 10<br/>telemetry_process: true<br/>telemetry_process_limit: false<br/>telemetry_process_limit_value: 1000<br/>telemetry_network: true<br/>telemetry_network_limit: false<br/>telemetry_network_limit_value: 1000<br/>telemetry_log: true<br/>telemetry_log_limit: false<br/>telemetry_log_limit_value: 1000<br/>telemetry_remotethread: true<br/>telemetry_remotethread_limit: false<br/>telemetry_remotethread_limit_value: 1000<br/>telemetry_alerts_limit: false<br/>telemetry_alerts_limit_value: 1000<br/>binary_download_enabled: true<br/>loglevel: ERROR<br/>use_sigma: true<br/>ioc_mode: 2<br/>hlai_mode: 1<br/>hlai_skip_signed_ms: true<br/>hlai_skip_signed_others: false<br/>hlai_minimum_level: critical<br/>hibou_mode: 0<br/>hibou_skip_signed_ms: false<br/>hibou_skip_signed_others: false<br/>hibou_minimum_level: critical<br/>yara_mode: 1<br/>yara_skip_signed_ms: true<br/>yara_skip_signed_others: false<br/>use_driver: true<br/>use_isolation: true<br/>use_ransomguard: true<br/>ransomguard_alert_only: false<br/>self_protection: false<br/>use_process_block: true<br/>use_sigma_process_block: false<br/>sigma_ruleset: 1<br/>yara_ruleset: null<br/>ioc_ruleset: null | server | 2022-06-28T14:18:47Z | online | 2133962752.0 | 0 | false | 0 | 2.15.0 |
>| additional_info1: null<br/>additional_info2: null<br/>additional_info3: null<br/>additional_info4: null | 0.6 | 125627596.0 | x64 | 2 | 3192 | WORKGROUP | true | false | <REDACTED> | 2022-06-14T22:23:08.393381Z | 0 | DC-01 | 706d4524-dc2d-4438-bfef-3b620646db7f | 2022/06/14 21:56:49 | <REDACTED> | <REDACTED> | false | false | 2022-06-15T06:33:46.544505Z | 2022-06-15T06:39:16.544505Z | 2022-06-15T06:35:58.544505Z | 2022-06-14T22:00:23Z | 20348 | 00454-40000-00001-AA081 | 10 | 0 | Windows Server 2022 Standard Evaluation | windows | 10.0.20348 | id: e96699ef-3dd9-4718-90ef-c7e5646fd466<br/>tenant: null<br/>name: No psexec<br/>description: <br/>revision: 5<br/>sleeptime: 60<br/>sleepjitter: 10<br/>telemetry_process: true<br/>telemetry_process_limit: false<br/>telemetry_process_limit_value: 1000<br/>telemetry_network: true<br/>telemetry_network_limit: false<br/>telemetry_network_limit_value: 1000<br/>telemetry_log: true<br/>telemetry_log_limit: false<br/>telemetry_log_limit_value: 1000<br/>telemetry_remotethread: true<br/>telemetry_remotethread_limit: false<br/>telemetry_remotethread_limit_value: 1000<br/>telemetry_alerts_limit: false<br/>telemetry_alerts_limit_value: 1000<br/>binary_download_enabled: true<br/>loglevel: ERROR<br/>use_sigma: true<br/>ioc_mode: 2<br/>hlai_mode: 1<br/>hlai_skip_signed_ms: true<br/>hlai_skip_signed_others: false<br/>hlai_minimum_level: critical<br/>hibou_mode: 0<br/>hibou_skip_signed_ms: false<br/>hibou_skip_signed_others: false<br/>hibou_minimum_level: critical<br/>yara_mode: 1<br/>yara_skip_signed_ms: true<br/>yara_skip_signed_others: false<br/>use_driver: true<br/>use_isolation: true<br/>use_ransomguard: true<br/>ransomguard_alert_only: false<br/>self_protection: false<br/>use_process_block: true<br/>use_sigma_process_block: false<br/>sigma_ruleset: 1<br/>yara_ruleset: null<br/>ioc_ruleset: null | server | 2022-06-14T22:02:32Z | offline | 2133962752.0 | 0 | false | 0 | 2.15.0 |


### harfanglab-telemetry-processes
***
Search processes


#### Base Command

`harfanglab-telemetry-processes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | filehash to search (md5, sha1, sha256). | Optional | 
| hostname | Endpoint hostname. | Optional | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| limit | Maximum number of elements to fetch. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Processes.data | unknown | Provides a list of processes | 
| agent.agentid | unknown | DEPRECATED | 
| current_directory | unknown | DEPRECATED | 
| hashes.sha256 | unknown | DEPRECATED | 

#### Command example
```!harfanglab-telemetry-processes hostname="DC-01" hash=3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetryprocesses": {
            "processes": [
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T07:28:58.757000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T06:58:58.227000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T06:28:57.663000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T05:58:57.147000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T05:28:56.585000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Processes list
>|create date|hostname|process name|image name|commandline|integrity level|parent image|parent commandline|username|signed|signer|sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-07-28T07:28:58.757000Z | DC-01 | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |
>| 2022-07-28T06:58:58.227000Z | DC-01 | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |
>| 2022-07-28T06:28:57.663000Z | DC-01 | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |
>| 2022-07-28T05:58:57.147000Z | DC-01 | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |
>| 2022-07-28T05:28:56.585000Z | DC-01 | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |


#### Command example
```!harfanglab-telemetry-processes hostname="DC-01" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetryprocesses": {
            "processes": [
                {
                    "commandline": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe /ua /installsource scheduler",
                    "create date": "2022-07-28T07:45:44.942000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
                    "parent image": "C:\\Windows\\System32\\svchost.exe",
                    "process name": "MicrosoftEdgeUpdate.exe",
                    "sha256": "bef9dbed290af17cf3f30cc43fc0a94cdadc540f171c25df1363b2e852d0a042",
                    "signed": true,
                    "signer": "Microsoft Corporation",
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "commandline": "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
                    "create date": "2022-07-28T07:45:44.711000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\conhost.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Program Files\\HarfangLab\\hurukai.exe {cf4a9162-2af0-0afe-8c36-45fd3dd29574}",
                    "parent image": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "process name": "conhost.exe",
                    "sha256": "6b481d656414c50d8bd0bedcd615aeaf2f5f68576cb6732a9548e0da87729733",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "commandline": "C:\\Program Files\\HarfangLab\\hurukai.exe {cf4a9162-2af0-0afe-8c36-45fd3dd29574}",
                    "create date": "2022-07-28T07:45:44.704000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "parent image": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "process name": "hurukai.exe",
                    "sha256": "9d81d385fe2f41e8f4f96d64a37899003b54a644ba67f7197f0cdbd0b71144f0",
                    "signed": true,
                    "signer": "HARFANGLAB SAS",
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "commandline": "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
                    "create date": "2022-07-28T07:44:40.370000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\conhost.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Program Files\\HarfangLab\\hurukai.exe {e273729b-d2f8-53a9-a10f-a60459dacc23}",
                    "parent image": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "process name": "conhost.exe",
                    "sha256": "6b481d656414c50d8bd0bedcd615aeaf2f5f68576cb6732a9548e0da87729733",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "commandline": "C:\\Program Files\\HarfangLab\\hurukai.exe {e273729b-d2f8-53a9-a10f-a60459dacc23}",
                    "create date": "2022-07-28T07:44:40.363000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "parent image": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "process name": "hurukai.exe",
                    "sha256": "9d81d385fe2f41e8f4f96d64a37899003b54a644ba67f7197f0cdbd0b71144f0",
                    "signed": true,
                    "signer": "HARFANGLAB SAS",
                    "username": "NT AUTHORITY\\SYSTEM"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Processes list
>|create date|hostname|process name|image name|commandline|integrity level|parent image|parent commandline|username|signed|signer|sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-07-28T07:45:44.942000Z | DC-01 | MicrosoftEdgeUpdate.exe | C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe | C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /ua /installsource scheduler | System | C:\Windows\System32\svchost.exe | C:\Windows\system32\svchost.exe -k netsvcs -p | NT AUTHORITY\SYSTEM | true | Microsoft Corporation | bef9dbed290af17cf3f30cc43fc0a94cdadc540f171c25df1363b2e852d0a042 |
>| 2022-07-28T07:45:44.711000Z | DC-01 | conhost.exe | C:\Windows\System32\conhost.exe | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1 | System | C:\Program Files\HarfangLab\hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe {cf4a9162-2af0-0afe-8c36-45fd3dd29574} | NT AUTHORITY\SYSTEM | true | Microsoft Windows | 6b481d656414c50d8bd0bedcd615aeaf2f5f68576cb6732a9548e0da87729733 |
>| 2022-07-28T07:45:44.704000Z | DC-01 | hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe {cf4a9162-2af0-0afe-8c36-45fd3dd29574} | System | C:\Program Files\HarfangLab\hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe | NT AUTHORITY\SYSTEM | true | HARFANGLAB SAS | 9d81d385fe2f41e8f4f96d64a37899003b54a644ba67f7197f0cdbd0b71144f0 |
>| 2022-07-28T07:44:40.370000Z | DC-01 | conhost.exe | C:\Windows\System32\conhost.exe | \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1 | System | C:\Program Files\HarfangLab\hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe {e273729b-d2f8-53a9-a10f-a60459dacc23} | NT AUTHORITY\SYSTEM | true | Microsoft Windows | 6b481d656414c50d8bd0bedcd615aeaf2f5f68576cb6732a9548e0da87729733 |
>| 2022-07-28T07:44:40.363000Z | DC-01 | hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe {e273729b-d2f8-53a9-a10f-a60459dacc23} | System | C:\Program Files\HarfangLab\hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe | NT AUTHORITY\SYSTEM | true | HARFANGLAB SAS | 9d81d385fe2f41e8f4f96d64a37899003b54a644ba67f7197f0cdbd0b71144f0 |


#### Command example
```!harfanglab-telemetry-processes hash=3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetryprocesses": {
            "processes": [
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T07:46:16.086000Z",
                    "hostname": "WEBSERVER",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T07:29:25.127000Z",
                    "hostname": "WEBSERVER",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T07:28:58.757000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T06:59:24.716000Z",
                    "hostname": "WEBSERVER",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-28T06:58:58.227000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Processes list
>|create date|hostname|process name|image name|commandline|integrity level|parent image|parent commandline|username|signed|signer|sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-07-28T07:46:16.086000Z | WEBSERVER | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |
>| 2022-07-28T07:29:25.127000Z | WEBSERVER | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |
>| 2022-07-28T07:28:58.757000Z | DC-01 | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |
>| 2022-07-28T06:59:24.716000Z | WEBSERVER | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |
>| 2022-07-28T06:58:58.227000Z | DC-01 | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |


#### Command example
```!harfanglab-telemetry-processes hostname="DC-01" from_date="2022-07-22T20:26:10" to_date="2022-07-22T20:26:20" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetryprocesses": {
            "processes": [
                {
                    "commandline": "C:\\Windows\\system32\\sppsvc.exe",
                    "create date": "2022-07-22T20:26:19.645000Z",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\sppsvc.exe",
                    "integrity level": "System",
                    "parent commandline": "C:\\Windows\\system32\\services.exe",
                    "parent image": "C:\\Windows\\System32\\services.exe",
                    "process name": "sppsvc.exe",
                    "sha256": "3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3",
                    "signed": true,
                    "signer": "Microsoft Windows",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Processes list
>|create date|hostname|process name|image name|commandline|integrity level|parent image|parent commandline|username|signed|signer|sha256|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2022-07-22T20:26:19.645000Z | DC-01 | sppsvc.exe | C:\Windows\System32\sppsvc.exe | C:\Windows\system32\sppsvc.exe | System | C:\Windows\System32\services.exe | C:\Windows\system32\services.exe | NT AUTHORITY\NETWORK SERVICE | true | Microsoft Windows | 3541d189d1bd3341a72769d43bf487eaa3b20e80aa04a54550bbfa9a04360db3 |


### harfanglab-job-pipelist
***
Start a job to get the list of pipes from a host (Windows)


#### Base Command

`harfanglab-job-pipelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-pipelist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getPipeList",
            "ID": "974d7732-481b-444e-8f30-37db662d23d5"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getPipeList",
>    "ID": "974d7732-481b-444e-8f30-37db662d23d5"
>}
>```

### harfanglab-job-artifact-downloadfile
***
Start a job to download a file from a host (Windows / Linux)


#### Base Command

`harfanglab-job-artifact-downloadfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 
| filename | Path of the file to download. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-artifact-downloadfile agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" filename="C:\\Program Files\\HarfangLab\\agent.ini"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "downloadFile",
            "ID": "7c5a2c3c-0455-4b4e-a7ee-acf7737f86f8"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "downloadFile",
>    "ID": "7c5a2c3c-0455-4b4e-a7ee-acf7737f86f8"
>}
>```

### harfanglab-job-prefetchlist
***
Start a job to get the list of prefetches from a host (Windows)


#### Base Command

`harfanglab-job-prefetchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-prefetchlist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getPrefetch",
            "ID": "153d0791-7eef-4d7e-b1be-61fec1e5a140"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getPrefetch",
>    "ID": "153d0791-7eef-4d7e-b1be-61fec1e5a140"
>}
>```

### harfanglab-job-runkeylist
***
Start a job to get the list of run keys from a host (Windows)


#### Base Command

`harfanglab-job-runkeylist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-runkeylist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getHives",
            "ID": "eadc130a-fa7f-41e6-a1bb-e9022b232b32"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getHives",
>    "ID": "eadc130a-fa7f-41e6-a1bb-e9022b232b32"
>}
>```

### harfanglab-job-scheduledtasklist
***
Start a job to get the list of scheduled tasks from a host (Windows)


#### Base Command

`harfanglab-job-scheduledtasklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-scheduledtasklist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getScheduledTasks",
            "ID": "e81e3105-5f8e-4caf-9947-b252721b4196"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getScheduledTasks",
>    "ID": "e81e3105-5f8e-4caf-9947-b252721b4196"
>}
>```

### harfanglab-job-driverlist
***
Start a job to get the list of drivers from a host (Windows)


#### Base Command

`harfanglab-job-driverlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-driverlist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getLoadedDriverList",
            "ID": "a4ce02be-38f0-4782-8d2d-0da99fd318db"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getLoadedDriverList",
>    "ID": "a4ce02be-38f0-4782-8d2d-0da99fd318db"
>}
>```

### harfanglab-job-servicelist
***
Start a job to get the list of services from a host (Windows)


#### Base Command

`harfanglab-job-servicelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-servicelist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getHives",
            "ID": "fcd8d44c-109f-43e9-8b9a-7268121a46a7"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getHives",
>    "ID": "fcd8d44c-109f-43e9-8b9a-7268121a46a7"
>}
>```

### harfanglab-job-processlist
***
Start a job to get the list of processes from a host (Windows / Linux)


#### Base Command

`harfanglab-job-processlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-processlist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getProcessList",
            "ID": "45696894-17c5-4304-9198-9084aa1f6847"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getProcessList",
>    "ID": "45696894-17c5-4304-9198-9084aa1f6847"
>}
>```

### harfanglab-job-networkconnectionlist
***
Start a job to get the list of network connections from a host (Windows / Linux)


#### Base Command

`harfanglab-job-networkconnectionlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-networkconnectionlist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getProcessList",
            "ID": "ac1cbd6c-ac39-4940-8c4b-85071be7c878"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getProcessList",
>    "ID": "ac1cbd6c-ac39-4940-8c4b-85071be7c878"
>}
>```

### harfanglab-job-networksharelist
***
Start a job to get the list of network shares from a host (Windows)


#### Base Command

`harfanglab-job-networksharelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-networksharelist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getNetworkShare",
            "ID": "b663d820-029b-414d-8bf3-5c7b973c7954"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getNetworkShare",
>    "ID": "b663d820-029b-414d-8bf3-5c7b973c7954"
>}
>```

### harfanglab-job-sessionlist
***
Start a job to get the list of sessions from a host (Windows)


#### Base Command

`harfanglab-job-sessionlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-sessionlist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getSessions",
            "ID": "2b48e4aa-fa28-4b21-b1a7-f70bde1c59c7"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getSessions",
>    "ID": "2b48e4aa-fa28-4b21-b1a7-f70bde1c59c7"
>}
>```

### harfanglab-job-persistencelist
***
Start a job to get the list of persistence items from a host (Linux)


#### Base Command

`harfanglab-job-persistencelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-persistencelist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "persistanceScanner",
            "ID": "30a54484-c359-4220-bb5c-6e07c7a9359e"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "persistanceScanner",
>    "ID": "30a54484-c359-4220-bb5c-6e07c7a9359e"
>}
>```

### harfanglab-job-ioc
***
Start a job to search for IOCs on a host (Windows / Linux)


#### Base Command

`harfanglab-job-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 
| filename | exact filename to search. | Optional | 
| filepath | exact filepath to search. | Optional | 
| hash | filehash to search (md5, sha1, sha256). | Optional | 
| search_in_path | restrict searchs for filename or filepath or filepath_regex to a given path. | Optional | 
| hash_filesize | size of the file associated to the 'hash' parameters (DEPRECATED, rather use the 'filesize' parameter). If known, it will speed up the search process. | Optional | 
| filesize | size of the file to search (can be used when searching a file from a hash or from a filename). If known, it will speed up the search process. | Optional | 
| registry | regex to search in registry (key or value). | Optional | 
| filepath_regex | search a regex on a filepath . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-ioc agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" filename="agent.ini"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "IOCScan",
            "ID": "0751d384-601a-40a4-afc6-7574f80f72bf"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "IOCScan",
>    "ID": "0751d384-601a-40a4-afc6-7574f80f72bf"
>}
>```

#### Command example
```!harfanglab-job-ioc agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" filename="agent.ini" search_in_path="C:\\Program Files"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "IOCScan",
            "ID": "56a9b602-e6e5-4130-8b51-861a383f42bc"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "IOCScan",
>    "ID": "56a9b602-e6e5-4130-8b51-861a383f42bc"
>}
>```

#### Command example
```!harfanglab-job-ioc agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" filename="agent.ini" filesize=1688```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "IOCScan",
            "ID": "1e68fb44-843e-445b-a926-755da0ce2321"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "IOCScan",
>    "ID": "1e68fb44-843e-445b-a926-755da0ce2321"
>}
>```

#### Command example
```!harfanglab-job-ioc agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" filepath="C:\\windows\\system32\\calc.exe"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "IOCScan",
            "ID": "f78d2479-9651-488f-9b94-e9019b918b26"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "IOCScan",
>    "ID": "f78d2479-9651-488f-9b94-e9019b918b26"
>}
>```

#### Command example
```!harfanglab-job-ioc agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" filepath_regex="System32\\\\calc\\.exe"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "IOCScan",
            "ID": "cbe0239e-3297-4cbb-a06b-75df2f5608d2"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "IOCScan",
>    "ID": "cbe0239e-3297-4cbb-a06b-75df2f5608d2"
>}
>```

#### Command example
```!harfanglab-job-ioc agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" hash=4208893c871d2499f184e3f0f2554da89f451fa9e98d95fc9516c5ae8f2b3bbd filesize=45056```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "IOCScan",
            "ID": "574b6d2a-4621-4883-bd0e-7bf603566a94"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "IOCScan",
>    "ID": "574b6d2a-4621-4883-bd0e-7bf603566a94"
>}
>```

#### Command example
```!harfanglab-job-ioc agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" registry="DLLPath"	```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "IOCScan",
            "ID": "b69dd316-4c47-479a-bd0f-46bfedd01180"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "IOCScan",
>    "ID": "b69dd316-4c47-479a-bd0f-46bfedd01180"
>}
>```

#### Command example
```!harfanglab-job-ioc agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db" registry="hmmapi"	```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "IOCScan",
            "ID": "89290f68-33a1-4335-a221-5bc163fa1270"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "IOCScan",
>    "ID": "89290f68-33a1-4335-a221-5bc163fa1270"
>}
>```

### harfanglab-job-startuplist
***
Start a job to get the list of startup items from a host (Windows)


#### Base Command

`harfanglab-job-startuplist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-startuplist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getStartupFileList",
            "ID": "d9d6b338-75ce-4ab6-8223-531e29c07ae6"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getStartupFileList",
>    "ID": "d9d6b338-75ce-4ab6-8223-531e29c07ae6"
>}
>```

### harfanglab-job-wmilist
***
Start a job to get the list of WMI items from a host (Windows)


#### Base Command

`harfanglab-job-wmilist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.ID | string | id | 
| action | unknown | HarfangLab job action | 

#### Command example
```!harfanglab-job-wmilist agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "getWMI",
            "ID": "e51124be-7720-4a0d-868f-3521a5ce0e9f"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "getWMI",
>    "ID": "e51124be-7720-4a0d-868f-3521a5ce0e9f"
>}
>```

### harfanglab-job-artifact-mft
***
Start a job to download the MFT from a host (Windows)


#### Base Command

`harfanglab-job-artifact-mft`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

#### Command example
```!harfanglab-job-artifact-mft agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "collectRAWEvidences",
            "ID": "57c3da8c-a68f-4f1d-b521-cd811e97f62b"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "collectRAWEvidences",
>    "ID": "57c3da8c-a68f-4f1d-b521-cd811e97f62b"
>}
>```

### harfanglab-job-artifact-hives
***
Start a job to download the hives from a host (Windows)


#### Base Command

`harfanglab-job-artifact-hives`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

#### Command example
```!harfanglab-job-artifact-hives agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "collectRAWEvidences",
            "ID": "36bc0da2-a557-4576-af8e-344d91364c70"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "collectRAWEvidences",
>    "ID": "36bc0da2-a557-4576-af8e-344d91364c70"
>}
>```

### harfanglab-job-artifact-evtx
***
Start a job to download the event logs from a host (Windows)


#### Base Command

`harfanglab-job-artifact-evtx`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

#### Command example
```!harfanglab-job-artifact-evtx agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "collectRAWEvidences",
            "ID": "707ab8c7-e2e9-4921-ad1e-0823def79d83"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "collectRAWEvidences",
>    "ID": "707ab8c7-e2e9-4921-ad1e-0823def79d83"
>}
>```

### harfanglab-job-artifact-logs
***
Start a job to download Linux log files from a host (Linux)


#### Base Command

`harfanglab-job-artifact-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

#### Command example
```!harfanglab-job-artifact-logs agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "collectRAWEvidences",
            "ID": "8989756f-1947-4fd1-9734-8fecb58d6f64"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "collectRAWEvidences",
>    "ID": "8989756f-1947-4fd1-9734-8fecb58d6f64"
>}
>```

### harfanglab-job-artifact-filesystem
***
Start a job to download Linux filesystem entries from a host (Linux)


#### Base Command

`harfanglab-job-artifact-filesystem`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

#### Command example
```!harfanglab-job-artifact-filesystem agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "collectRAWEvidences",
            "ID": "d351e9be-3f0e-4ccc-876f-8b28f208ffa7"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "collectRAWEvidences",
>    "ID": "d351e9be-3f0e-4ccc-876f-8b28f208ffa7"
>}
>```

### harfanglab-job-artifact-all
***
Start a job to download all artifacts from a host (Windows MFT, Hives, evt/evtx, Prefetch, USN, Linux logs and file list)


#### Base Command

`harfanglab-job-artifact-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

#### Command example
```!harfanglab-job-artifact-all agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "collectRAWEvidences",
            "ID": "312a3857-935c-4b23-9d58-cc29bb9dda18"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "collectRAWEvidences",
>    "ID": "312a3857-935c-4b23-9d58-cc29bb9dda18"
>}
>```

### harfanglab-job-artifact-ramdump
***
Start a job to get the entine RAM from a host (Windows / Linux)


#### Base Command

`harfanglab-job-artifact-ramdump`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.artifact.download_link | string | URL to download the artifact | 
| Harfanglab.Job.ID | string | id | 

#### Command example
```!harfanglab-job-artifact-ramdump agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Action": "memoryDumper",
            "ID": "27df9e9b-6201-4efe-9d86-986fe47739ee"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "Action": "memoryDumper",
>    "ID": "27df9e9b-6201-4efe-9d86-986fe47739ee"
>}
>```

### harfanglab-telemetry-network
***
Search network connections


#### Base Command

`harfanglab-telemetry-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Optional | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| source_address | Source IP address. | Optional | 
| source_port | Source port. | Optional | 
| destination_address | Destination IP address. | Optional | 
| destination_port | Destination port. | Optional | 
| limit | Maximum number of elements to fetch. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Network.data | unknown | Provides a list of network connections | 

#### Command example
```!harfanglab-telemetry-network hostname="DC-01" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrynetwork": {
            "network": [
                {
                    "create date": "2022-06-29T22:33:42.434000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 443,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 50000,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "create date": "2022-06-29T22:24:08.088000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 49998,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-06-29T22:23:08.037000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 443,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 49997,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "create date": "2022-06-29T22:08:07.550000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 443,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 49996,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "create date": "2022-06-29T22:04:42.848000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 49995,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Network list
>|create date|hostname|image name|username|source address|source port|destination addr|destination port|direction|
>|---|---|---|---|---|---|---|---|---|
>| 2022-06-29T22:33:42.434000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | <REDACTED> | 50000 | <REDACTED> | 443 | out |
>| 2022-06-29T22:24:08.088000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | <REDACTED> | 49998 | <REDACTED> | 80 | out |
>| 2022-06-29T22:23:08.037000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | <REDACTED> | 49997 | <REDACTED> | 443 | out |
>| 2022-06-29T22:08:07.550000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | <REDACTED> | 49996 | <REDACTED> | 443 | out |
>| 2022-06-29T22:04:42.848000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | <REDACTED> | 49995 | <REDACTED> | 80 | out |


#### Command example
```!harfanglab-telemetry-network destination_address="<REDACTED>" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrynetwork": {
            "network": [
                {
                    "create date": "2022-07-27T14:59:56.114000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-1879",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 62787,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-07-27T14:58:43.590000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-3752",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 64593,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-07-27T14:49:54.374000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-6852",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 61571,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-07-27T14:49:14.813000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-4321",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 61605,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-07-27T07:59:49.780000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-1879",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 62472,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Network list
>|create date|hostname|image name|username|source address|source port|destination addr|destination port|direction|
>|---|---|---|---|---|---|---|---|---|
>| 2022-07-27T14:59:56.114000Z | WORKSTATION-1879 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | <REDACTED> | 62787 | <REDACTED> | 80 | out |
>| 2022-07-27T14:58:43.590000Z | WORKSTATION-3752 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | <REDACTED> | 64593 | <REDACTED> | 80 | out |
>| 2022-07-27T14:49:54.374000Z | WORKSTATION-6852 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | <REDACTED> | 61571 | <REDACTED> | 80 | out |
>| 2022-07-27T14:49:14.813000Z | WORKSTATION-4321 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | <REDACTED> | 61605 | <REDACTED> | 80 | out |
>| 2022-07-27T07:59:49.780000Z | WORKSTATION-1879 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | <REDACTED> | 62472 | <REDACTED> | 80 | out |


#### Command example
```!harfanglab-telemetry-network destination_address="<REDACTED>" from_date="2022-07-21T12:34:05" to_date="2022-07-21T12:34:15" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrynetwork": {
            "network": [
                {
                    "create date": "2022-07-21T12:34:09.265000Z",
                    "destination addr": "<REDACTED>",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-4812",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "<REDACTED>",
                    "source port": 50363,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Network list
>|create date|hostname|image name|username|source address|source port|destination addr|destination port|direction|
>|---|---|---|---|---|---|---|---|---|
>| 2022-07-21T12:34:09.265000Z | WORKSTATION-4812 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | <REDACTED> | 50363 | <REDACTED> | 80 | out |


### harfanglab-telemetry-eventlog
***
Search event logs


#### Base Command

`harfanglab-telemetry-eventlog`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Optional | 
| event_id | Event id. | Optional | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| limit | Maximum number of elements to fetch. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.EventLogs.data | unknown | Provides a list of event logs | 

#### Command example
```!harfanglab-telemetry-eventlog hostname="DC-01" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetryeventlog": {
            "eventlog": [
                {
                    "create date": "2022-07-28T07:29:29.327000Z",
                    "event data": {
                        "Binary": "7300700070007300760063002F0031000000",
                        "param1": "Software Protection",
                        "param2": "stopped"
                    },
                    "event id": 7036,
                    "hostname": "DC-01",
                    "keywords": [
                        "Classic"
                    ],
                    "level": "Information",
                    "log name": "System",
                    "source name": "Service Control Manager"
                },
                {
                    "create date": "2022-07-28T07:29:29.311000Z",
                    "event data": {
                        "param1": "2022-11-12T06:42:29Z",
                        "param2": "RulesEngine"
                    },
                    "event id": 16384,
                    "hostname": "DC-01",
                    "keywords": [
                        "Classic"
                    ],
                    "level": "Information",
                    "log name": "Application",
                    "source name": "Microsoft-Windows-Security-SPP"
                },
                {
                    "create date": "2022-07-28T07:28:58.905000Z",
                    "event data": null,
                    "event id": 16394,
                    "hostname": "DC-01",
                    "keywords": [
                        "Classic"
                    ],
                    "level": "Information",
                    "log name": "Application",
                    "source name": "Microsoft-Windows-Security-SPP"
                },
                {
                    "create date": "2022-07-28T07:28:58.795000Z",
                    "event data": {
                        "Binary": "7300700070007300760063002F0034000000",
                        "param1": "Software Protection",
                        "param2": "running"
                    },
                    "event id": 7036,
                    "hostname": "DC-01",
                    "keywords": [
                        "Classic"
                    ],
                    "level": "Information",
                    "log name": "System",
                    "source name": "Service Control Manager"
                },
                {
                    "create date": "2022-07-28T07:26:50.139000Z",
                    "event data": {
                        "Binary": "540072007500730074006500640049006E007300740061006C006C00650072002F0031000000",
                        "param1": "Windows Modules Installer",
                        "param2": "stopped"
                    },
                    "event id": 7036,
                    "hostname": "DC-01",
                    "keywords": [
                        "Classic"
                    ],
                    "level": "Information",
                    "log name": "System",
                    "source name": "Service Control Manager"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Event Log list
>|create date|hostname|event id|source name|log name|keywords|event data|level|
>|---|---|---|---|---|---|---|---|
>| 2022-07-28T07:29:29.327000Z | DC-01 | 7036 | Service Control Manager | System | Classic | param1: Software Protection<br/>param2: stopped<br/>Binary: 7300700070007300760063002F0031000000 | Information |
>| 2022-07-28T07:29:29.311000Z | DC-01 | 16384 | Microsoft-Windows-Security-SPP | Application | Classic | param1: 2022-11-12T06:42:29Z<br/>param2: RulesEngine | Information |
>| 2022-07-28T07:28:58.905000Z | DC-01 | 16394 | Microsoft-Windows-Security-SPP | Application | Classic |  | Information |
>| 2022-07-28T07:28:58.795000Z | DC-01 | 7036 | Service Control Manager | System | Classic | param1: Software Protection<br/>param2: running<br/>Binary: 7300700070007300760063002F0034000000 | Information |
>| 2022-07-28T07:26:50.139000Z | DC-01 | 7036 | Service Control Manager | System | Classic | param1: Windows Modules Installer<br/>param2: stopped<br/>Binary: 540072007500730074006500640049006E007300740061006C006C00650072002F0031000000 | Information |


#### Command example
```!harfanglab-telemetry-eventlog hostname="DC-01" event_id=4624 limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetryeventlog": {
            "eventlog": [
                {
                    "create date": "2022-07-28T07:24:48.105000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x278",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "DC-01$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "DC-01",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                },
                {
                    "create date": "2022-07-28T06:34:06.425000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x278",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "DC-01$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "DC-01",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                },
                {
                    "create date": "2022-07-28T06:24:48.107000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x278",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "DC-01$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "DC-01",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                },
                {
                    "create date": "2022-07-28T05:24:47.496000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x278",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "DC-01$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "DC-01",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                },
                {
                    "create date": "2022-07-28T04:24:46.833000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x278",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "DC-01$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "DC-01",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Event Log list
>|create date|hostname|event id|source name|log name|keywords|event data|level|
>|---|---|---|---|---|---|---|---|
>| 2022-07-28T07:24:48.105000Z | DC-01 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: DC-01$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x278<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |
>| 2022-07-28T06:34:06.425000Z | DC-01 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: DC-01$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x278<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |
>| 2022-07-28T06:24:48.107000Z | DC-01 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: DC-01$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x278<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |
>| 2022-07-28T05:24:47.496000Z | DC-01 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: DC-01$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x278<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |
>| 2022-07-28T04:24:46.833000Z | DC-01 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: DC-01$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x278<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |


#### Command example
```!harfanglab-telemetry-eventlog event_id=4624 from_date="2022-07-21T21:25:34" to_date="2022-07-23T21:25:34" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetryeventlog": {
            "eventlog": [
                {
                    "create date": "2022-07-23T21:25:18.159000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x280",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "WORKSTATION-123$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "WORKSTATION-1234",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                },
                {
                    "create date": "2022-07-23T21:25:10.765000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x27c",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "WEBSERVER$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "WEBSERVER",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                },
                {
                    "create date": "2022-07-23T21:23:53.410000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x278",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "DC-01$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "DC-01",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                },
                {
                    "create date": "2022-07-23T21:18:55.338000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x27c",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "WORKSTATION-850$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "WORKSTATION-8501",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                },
                {
                    "create date": "2022-07-23T21:18:53.324000Z",
                    "event data": {
                        "AuthenticationPackageName": "Negotiate",
                        "ElevatedToken": "%%1842",
                        "ImpersonationLevel": "%%1833",
                        "IpAddress": "-",
                        "IpPort": "-",
                        "KeyLength": "0",
                        "LmPackageName": "-",
                        "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                        "LogonProcessName": "Advapi  ",
                        "LogonType": "5",
                        "ProcessId": "0x27c",
                        "ProcessName": "C:\\Windows\\System32\\services.exe",
                        "RestrictedAdminMode": "-",
                        "SubjectDomainName": "WORKGROUP",
                        "SubjectLogonId": "0x3e7",
                        "SubjectUserName": "WORKSTATION-850$",
                        "SubjectUserSid": "S-1-5-18",
                        "TargetDomainName": "NT AUTHORITY",
                        "TargetLinkedLogonId": "0x0",
                        "TargetLogonId": "0x3e7",
                        "TargetOutboundDomainName": "-",
                        "TargetOutboundUserName": "-",
                        "TargetUserName": "SYSTEM",
                        "TargetUserSid": "S-1-5-18",
                        "TransmittedServices": "-",
                        "VirtualAccount": "%%1843",
                        "WorkstationName": "-"
                    },
                    "event id": 4624,
                    "hostname": "WORKSTATION-8501",
                    "keywords": [
                        "Audit Success"
                    ],
                    "level": "Information",
                    "log name": "Security",
                    "source name": "Microsoft-Windows-Security-Auditing"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Event Log list
>|create date|hostname|event id|source name|log name|keywords|event data|level|
>|---|---|---|---|---|---|---|---|
>| 2022-07-23T21:25:18.159000Z | WORKSTATION-1234 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: WORKSTATION-123$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x280<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |
>| 2022-07-23T21:25:10.765000Z | WEBSERVER | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: WEBSERVER$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x27c<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |
>| 2022-07-23T21:23:53.410000Z | DC-01 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: DC-01$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x278<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |
>| 2022-07-23T21:18:55.338000Z | WORKSTATION-8501 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: WORKSTATION-850$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x27c<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |
>| 2022-07-23T21:18:53.324000Z | WORKSTATION-8501 | 4624 | Microsoft-Windows-Security-Auditing | Security | Audit Success | SubjectUserSid: S-1-5-18<br/>SubjectUserName: WORKSTATION-850$<br/>SubjectDomainName: WORKGROUP<br/>SubjectLogonId: 0x3e7<br/>TargetUserSid: S-1-5-18<br/>TargetUserName: SYSTEM<br/>TargetDomainName: NT AUTHORITY<br/>TargetLogonId: 0x3e7<br/>LogonType: 5<br/>LogonProcessName: Advapi  <br/>AuthenticationPackageName: Negotiate<br/>WorkstationName: -<br/>LogonGuid: {00000000-0000-0000-0000-000000000000}<br/>TransmittedServices: -<br/>LmPackageName: -<br/>KeyLength: 0<br/>ProcessId: 0x27c<br/>ProcessName: C:\Windows\System32\services.exe<br/>IpAddress: -<br/>IpPort: -<br/>ImpersonationLevel: %%1833<br/>RestrictedAdminMode: -<br/>TargetOutboundUserName: -<br/>TargetOutboundDomainName: -<br/>VirtualAccount: %%1843<br/>TargetLinkedLogonId: 0x0<br/>ElevatedToken: %%1842 | Information |


### harfanglab-telemetry-binary
***
Search for binaries


#### Base Command

`harfanglab-telemetry-binary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| hash | filehash to search (md5, sha1, sha256). | Optional | 
| limit | Maximum number of elements to fetch. Default is 100. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!harfanglab-telemetry-binary hash=2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrybinary": {
            "binary": [
                {
                    "download link": "https://demo-1.harfanglab.io:8443/api/data/telemetry/Binary/download/2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5/?hl_expiring_key=a8a86c16b81b87390c1dfa279ff028b33f1b0b59",
                    "name": "hurukai",
                    "path": "/opt/hurukai/hurukai",
                    "sha256": "2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5",
                    "signed": "",
                    "signer": null,
                    "size": 5882824
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Binary list
>|name|path|size|sha256|download link|
>|---|---|---|---|---|
>| hurukai | /opt/hurukai/hurukai | 5882824 | 2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5 | https://demo-1.harfanglab.io:8443/api/data/telemetry/Binary/download/2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5/?hl_expiring_key=a8a86c16b81b87390c1dfa279ff028b33f1b0b59 |


### harfanglab-job-info
***
Get job status information


#### Base Command

`harfanglab-job-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Coma-separated list of job ids. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Job.Status | string | Job Status | 

#### Command example
```!harfanglab-job-info ids="ba28f05f-e3c8-4eec-ab6a-01d639c14f2e,70b2cd7b-8a57-4a6c-aa7e-e392676fa7ac"```
#### Context Example
```json
{
    "Harfanglab": {
        "Job": {
            "Info": [
                {
                    "Creation date": "2022-07-19 19:47:00",
                    "ID": "ba28f05f-e3c8-4eec-ab6a-01d639c14f2e",
                    "Status": "finished"
                },
                {
                    "Creation date": "2022-07-07 13:39:02",
                    "ID": "70b2cd7b-8a57-4a6c-aa7e-e392676fa7ac",
                    "Status": "finished"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Jobs Info
>|ID|Status|Creation date|
>|---|---|---|
>| ba28f05f-e3c8-4eec-ab6a-01d639c14f2e | finished | 2022-07-19 19:47:00 |
>| 70b2cd7b-8a57-4a6c-aa7e-e392676fa7ac | finished | 2022-07-07 13:39:02 |


### harfanglab-result-pipelist
***
Get a hostname's list of pipes from job results


#### Base Command

`harfanglab-result-pipelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Pipe.data | unknown | Provides a list of named pipes | 

#### Command example
```!harfanglab-result-pipelist job_id="f6cba4b2-e4a1-41b7-bdc0-0dcb6815d3ad"```
#### Context Example
```json
{
    "Harfanglab": {
        "Pipe": {
            "data": [
                "atsvc",
                "Ctx_WinStation_API_service",
                "epmapper",
                "eventlog",
                "hlab-1560-f60834ea319cb1cf",
                "InitShutdown",
                "lsass",
                "LSM_API_service",
                "ntsvcs",
                "PIPE_EVENTROOT\\CIMV2SCM EVENT PROVIDER",
                "scerpc",
                "SessEnvPublicRpc",
                "spoolss",
                "srvsvc",
                "TermSrv_API_service",
                "trkwks",
                "VBoxTrayIPC-vagrant",
                "W32TIME_ALT",
                "Winsock2\\CatalogChangeListener-1f8-0",
                "Winsock2\\CatalogChangeListener-278-0",
                "Winsock2\\CatalogChangeListener-284-0",
                "Winsock2\\CatalogChangeListener-2c4-0",
                "Winsock2\\CatalogChangeListener-2f0-0",
                "Winsock2\\CatalogChangeListener-35c-0",
                "Winsock2\\CatalogChangeListener-414-0",
                "Winsock2\\CatalogChangeListener-528-0",
                "wkssvc"
            ]
        }
    }
}
```

#### Human Readable Output

>### Pipe List
>|name|
>|---|
>| atsvc |
>| Ctx_WinStation_API_service |
>| epmapper |
>| eventlog |
>| hlab-1560-f60834ea319cb1cf |
>| InitShutdown |
>| lsass |
>| LSM_API_service |
>| ntsvcs |
>| PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER |
>| scerpc |
>| SessEnvPublicRpc |
>| spoolss |
>| srvsvc |
>| TermSrv_API_service |
>| trkwks |
>| VBoxTrayIPC-vagrant |
>| W32TIME_ALT |
>| Winsock2\CatalogChangeListener-1f8-0 |
>| Winsock2\CatalogChangeListener-278-0 |
>| Winsock2\CatalogChangeListener-284-0 |
>| Winsock2\CatalogChangeListener-2c4-0 |
>| Winsock2\CatalogChangeListener-2f0-0 |
>| Winsock2\CatalogChangeListener-35c-0 |
>| Winsock2\CatalogChangeListener-414-0 |
>| Winsock2\CatalogChangeListener-528-0 |
>| wkssvc |


### harfanglab-result-prefetchlist
***
Get a hostname's list of prefetches from job results


#### Base Command

`harfanglab-result-prefetchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Prefetch.data | unknown | Provides a list of prefetch files | 

#### Command example
```!harfanglab-result-prefetchlist job_id="16834054-574b-4dc4-8981-9e6bb93e4529"```
#### Context Example
```json
{
    "Harfanglab": {
        "Prefetch": {
            "data": []
        }
    }
}
```

#### Human Readable Output

>### Prefetch List
>**No entries.**


### harfanglab-result-runkeylist
***
Get a hostname's list of run keys from job results


#### Base Command

`harfanglab-result-runkeylist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.RunKey.data | unknown | Provides a list of Run Keys | 

#### Command example
```!harfanglab-result-runkeylist job_id="704cac37-57df-4b70-8227-4a770b724108"```
#### Context Example
```json
{
    "Harfanglab": {
        "RunKey": {
            "data": [
                {
                    "fullpath": "C:\\Windows\\system32\\SecurityHealthSystray.exe",
                    "md5": "37eea8b4d205b2300e79a9e96f2f7a46",
                    "name": "SecurityHealth",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\VBoxTray.exe",
                    "md5": "3c21ed6871650bc8635729b9abbb6f21",
                    "name": "VBoxTray",
                    "signed": true
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### RunKey List
>|name|fullpath|signed|md5|
>|---|---|---|---|
>| SecurityHealth | C:\Windows\system32\SecurityHealthSystray.exe | true | 37eea8b4d205b2300e79a9e96f2f7a46 |
>| VBoxTray | C:\Windows\system32\VBoxTray.exe | true | 3c21ed6871650bc8635729b9abbb6f21 |


### harfanglab-result-scheduledtasklist
***
Get a hostname's list of scheduled tasks from job results


#### Base Command

`harfanglab-result-scheduledtasklist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.ScheduledTask.data | unknown | Provides a list of scheduled tasks | 

#### Command example
```!harfanglab-result-scheduledtasklist job_id="f22b531a-b078-44fc-8d23-d06725548934"```
#### Context Example
```json
{
    "Harfanglab": {
        "ScheduledTask": {
            "data": [
                {
                    "fullpath": "C:\\Windows\\System32\\mscoree.dll",
                    "md5": "7ddb05ec3be80b951478e594294c0361",
                    "name": ".NET Framework NGEN v4.0.30319",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mscoree.dll",
                    "md5": "7ddb05ec3be80b951478e594294c0361",
                    "name": ".NET Framework NGEN v4.0.30319 64",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mscoree.dll",
                    "md5": "7ddb05ec3be80b951478e594294c0361",
                    "name": ".NET Framework NGEN v4.0.30319 64 Critical",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mscoree.dll",
                    "md5": "7ddb05ec3be80b951478e594294c0361",
                    "name": ".NET Framework NGEN v4.0.30319 Critical",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "Account Cleanup",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\msdrm.dll",
                    "md5": "a4bffcd7b94bd687b3084bc6c7483a2c",
                    "name": "AD RMS Rights Policy Template Management (Automated)",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\msdrm.dll",
                    "md5": "a4bffcd7b94bd687b3084bc6c7483a2c",
                    "name": "AD RMS Rights Policy Template Management (Manual)",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\ngctasks.dll",
                    "md5": "41fe9b51f30b9ff1a8fe4d724d6c7940",
                    "name": "AikCertEnrollTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\energytask.dll",
                    "md5": "6b5151a0c751cbf6f01994ab1eb6cde8",
                    "name": "AnalyzeSystem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\apphostregistrationverifier.exe",
                    "md5": "54b1076b71917ed737760b4feba9eeae",
                    "name": "appuriverifierdaily",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\apphostregistrationverifier.exe",
                    "md5": "54b1076b71917ed737760b4feba9eeae",
                    "name": "appuriverifierinstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dsregcmd.exe",
                    "md5": "f4c8c7def69c3fcaf375db9a7710fd35",
                    "name": "Automatic-Device-Join",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cscui.dll",
                    "md5": "14eef80c58f9c7bffdbc5cb4867d5824",
                    "name": "Background Synchronization",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "BfeOnServiceStartTypeChange",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "md5": null,
                    "name": "BgTaskRegistrationMaintenanceTask",
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\System32\\edptask.dll",
                    "md5": "45ed986a4271a0f5d9a27161af5a76ee",
                    "name": "BitLocker Encrypt All Drives",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\edptask.dll",
                    "md5": "45ed986a4271a0f5d9a27161af5a76ee",
                    "name": "BitLocker MDM policy Refresh",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wininet.dll",
                    "md5": "7f361d95066553e70da7a5329a429254",
                    "name": "CacheTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mscms.dll",
                    "md5": "77f81e7a53a7192fefebd9db113709d5",
                    "name": "Calibration Loader",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cscript.exe",
                    "md5": "60ddaf328f6469c00a3fa14aaafed361",
                    "name": "CleanupOldPerfLogs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "CleanupTemporaryState",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cmd.exe",
                    "md5": "e7a6b1f51efb405287a8048cfa4690f4",
                    "name": "Collection",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cmd.exe",
                    "md5": "e7a6b1f51efb405287a8048cfa4690f4",
                    "name": "Configuration",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wsqmcons.exe",
                    "md5": "0d229f8045fb12b584143ac82cbd1dcd",
                    "name": "Consolidator",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\shell32.dll",
                    "md5": "49cf1d96abbacab759a043253677219f",
                    "name": "CreateObjectTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CloudExperienceHostBroker.exe",
                    "md5": "8b4432582d6c68e5296e7f8cc8a3b8bc",
                    "name": "CreateObjectTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\ngctasks.dll",
                    "md5": "41fe9b51f30b9ff1a8fe4d724d6c7940",
                    "name": "CryptoPolicyTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\discan.dll",
                    "md5": "db01ce5db38cdc5f30537c129afc577c",
                    "name": "Data Integrity Check And Scan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\discan.dll",
                    "md5": "db01ce5db38cdc5f30537c129afc577c",
                    "name": "Data Integrity Scan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\discan.dll",
                    "md5": "db01ce5db38cdc5f30537c129afc577c",
                    "name": "Data Integrity Scan for Crash Recovery",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\devicecensus.exe",
                    "md5": "2a33b4af5c4a152eed1c53bd39e99534",
                    "name": "Device",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\pnppolicy.dll",
                    "md5": "c9b1ab4b3f3f77e6513ce26b50215bc4",
                    "name": "Device Install Group Policy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\pnpui.dll",
                    "md5": "303788cfdf6ca3f929badd3be92ed879",
                    "name": "Device Install Reboot Required",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\devicecensus.exe",
                    "md5": "2a33b4af5c4a152eed1c53bd39e99534",
                    "name": "Device User",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dsregtask.dll",
                    "md5": "f64089d434bb3fb387f51d7525c56ea4",
                    "name": "Device-Sync",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\disksnapshot.exe",
                    "md5": "5536352f520d36eb7079647214ac9fa0",
                    "name": "Diagnostics",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\directxdatabaseupdater.exe",
                    "md5": "26e02368365619d57d7a32cc37de35e1",
                    "name": "DirectXDatabaseUpdater",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dstokenclean.exe",
                    "md5": "8c9493c2c59e6a7f667ea3355620ce48",
                    "name": "DsSvcCleanup",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dxgiadaptercache.exe",
                    "md5": "fbcff8772630726ef5f00f26a3bcb437",
                    "name": "DXGIAdapterCache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\edptask.dll",
                    "md5": "45ed986a4271a0f5d9a27161af5a76ee",
                    "name": "EDP App Launch Task",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\edptask.dll",
                    "md5": "45ed986a4271a0f5d9a27161af5a76ee",
                    "name": "EDP Auth Task",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\edptask.dll",
                    "md5": "45ed986a4271a0f5d9a27161af5a76ee",
                    "name": "EDP Inaccessible Credentials Task",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AppLockerCsp.dll",
                    "md5": "20b0cc726f9d3fcf3b659f6a132e1e00",
                    "name": "EDP Policy Manager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\MitigationConfiguration.dll",
                    "md5": "0a9e147ff4d7f8212f0de006c52d865b",
                    "name": "ExploitGuard MDM policy Refresh",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\TimeSyncTask.dll",
                    "md5": "c42636381538cbf55ac6ad954519f1f0",
                    "name": "ForceSynchronizeTime",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\gathernetworkinfo.vbs",
                    "md5": "da4d4261a43de7e851a9378ed0668eb9",
                    "name": "GatherNetworkInfo",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "md5": null,
                    "name": "HiveUploadTask",
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\System32\\srchadmin.dll",
                    "md5": "945162746b51b6082425edac70cd3774",
                    "name": "IndexerAutomaticMaintenance",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\LanguageComponentsInstaller.dll",
                    "md5": "742c212ba7f256577168aeee2b00fb7c",
                    "name": "Installation",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdc.dll",
                    "md5": "7939c5b180bd8153f670f8231a401c75",
                    "name": "Interactive",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\ngctasks.dll",
                    "md5": "41fe9b51f30b9ff1a8fe4d724d6c7940",
                    "name": "KeyPreGenTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\clipup.exe",
                    "md5": "2220d1075b5e7e90ba4f4f8a0e701e45",
                    "name": "License Validation",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InputCloudStore.dll",
                    "md5": "13208dbfbbcfbad9cd0e6ab59f72bdec",
                    "name": "LocalUserSyncDataAvailable",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sc.exe",
                    "md5": "6fb10cd439b40d92935f8f6a0c99670a",
                    "name": "LoginCheck",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cscui.dll",
                    "md5": "14eef80c58f9c7bffdbc5cb4867d5824",
                    "name": "Logon Synchronization",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\lpremove.exe",
                    "md5": "2140dccdd4dab65241c309df02ce09a2",
                    "name": "LPRemove",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "MaintenanceTasks",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mapstoasttask.dll",
                    "md5": "24c2e7e8b529023ee167dd68164cced7",
                    "name": "MapsToastTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mapsupdatetask.dll",
                    "md5": "984960ba9e02bb161f0315f37eb9bde2",
                    "name": "MapsUpdateTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DeviceSetupManagerAPI.dll",
                    "md5": "bb7755132e04b89f006522fa69ed8f38",
                    "name": "Metadata Refresh",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\compattelrunner.exe",
                    "md5": "003339d6b38472f62b5da9c5d31f24ea",
                    "name": "Microsoft Compatibility Appraiser",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "Microsoft-Windows-DiskDiagnosticDataCollector",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dfdwiz.exe",
                    "md5": "be2d2340e25e4a5700381c8097af152b",
                    "name": "Microsoft-Windows-DiskDiagnosticResolver",
                    "signed": true
                },
                {
                    "fullpath": "c:\\program files (x86)\\microsoft\\edgeupdate\\microsoftedgeupdate.exe",
                    "md5": "8661fbb97161096be503cd295aa46409",
                    "name": "MicrosoftEdgeUpdateTaskMachineCore1d867a83717e5b7",
                    "signed": true
                },
                {
                    "fullpath": "c:\\program files (x86)\\microsoft\\edgeupdate\\microsoftedgeupdate.exe",
                    "md5": "8661fbb97161096be503cd295aa46409",
                    "name": "MicrosoftEdgeUpdateTaskMachineUA",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rasmbmgr.dll",
                    "md5": "c657bc27aae838fc3a295d51ac20a953",
                    "name": "MobilityManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InputCloudStore.dll",
                    "md5": "13208dbfbbcfbad9cd0e6ab59f72bdec",
                    "name": "MouseSyncDataAvailable",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\MsCtfMonitor.dll",
                    "md5": "f545384f0b0ca857197904a6092b3f16",
                    "name": "MsCtfMonitor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\locationnotificationwindows.exe",
                    "md5": "a259819d5f8de86ff28546f4ded16f35",
                    "name": "Notifications",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\MBMediaManager.dll",
                    "md5": "c1ce23565a9cadef865aedd6c041a2c4",
                    "name": "OobeDiscovery",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "PcaPatchDbTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InputCloudStore.dll",
                    "md5": "13208dbfbbcfbad9cd0e6ab59f72bdec",
                    "name": "PenSyncDataAvailable",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "md5": null,
                    "name": "PerformRemediation",
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\system32\\appidpolicyconverter.exe",
                    "md5": "69a6bef4903650d20c12cbeff41367b0",
                    "name": "PolicyConverter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "Pre-staged app cleanup",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\pstask.dll",
                    "md5": "796fb59bbf6e037b8a0c7646e6ea7a9e",
                    "name": "ProactiveScan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\MemoryDiagnostic.dll",
                    "md5": "8354fde902ba277b46c92175466438ef",
                    "name": "ProcessMemoryDiagnosticEvents",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\compattelrunner.exe",
                    "md5": "003339d6b38472f62b5da9c5d31f24ea",
                    "name": "ProgramDataUpdater",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\srmclient.dll",
                    "md5": "b2037c5822de4fc8107d952b55d7f107",
                    "name": "Property Definition Sync",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "Proxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wermgr.exe",
                    "md5": "ada54642a633e778222008de627b5db5",
                    "name": "QueueReporting",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\fcon.dll",
                    "md5": "3f6291e0a27897796b7f91d6402578e3",
                    "name": "ReconcileFeatures",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dsregcmd.exe",
                    "md5": "f4c8c7def69c3fcaf375db9a7710fd35",
                    "name": "Recovery-Check",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wosc.dll",
                    "md5": "feed4b9d117a6a512d93ca4e2c060419",
                    "name": "RefreshCache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\regidle.dll",
                    "md5": "f4608228b68515fe0ea440e1865f77c6",
                    "name": "RegIdleBackup",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sc.exe",
                    "md5": "6fb10cd439b40d92935f8f6a0c99670a",
                    "name": "Registration",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usoclient.exe",
                    "md5": "e4fd0a267e8d740f62e3ddf99917cbcc",
                    "name": "Report policies",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wdi.dll",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "ResolutionHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\MemoryDiagnostic.dll",
                    "md5": "8354fde902ba277b46c92175466438ef",
                    "name": "RunFullMemoryDiagnostic",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InstallServiceTasks.dll",
                    "md5": "855ebaa8373521bd3d39f282d36a2ba3",
                    "name": "ScanForUpdates",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InstallServiceTasks.dll",
                    "md5": "855ebaa8373521bd3d39f282d36a2ba3",
                    "name": "ScanForUpdatesAsUser",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usoclient.exe",
                    "md5": "e4fd0a267e8d740f62e3ddf99917cbcc",
                    "name": "Schedule Maintenance Work",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usoclient.exe",
                    "md5": "e4fd0a267e8d740f62e3ddf99917cbcc",
                    "name": "Schedule Scan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usoclient.exe",
                    "md5": "e4fd0a267e8d740f62e3ddf99917cbcc",
                    "name": "Schedule Scan Static Task",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usoclient.exe",
                    "md5": "e4fd0a267e8d740f62e3ddf99917cbcc",
                    "name": "Schedule Wake To Work",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usoclient.exe",
                    "md5": "e4fd0a267e8d740f62e3ddf99917cbcc",
                    "name": "Schedule Work",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\sdiagschd.dll",
                    "md5": "c7ceb5a1f22da23b718712cb252df58a",
                    "name": "Scheduled",
                    "signed": true
                },
                {
                    "fullpath": "c:\\windows\\system32\\sc.exe",
                    "md5": "6fb10cd439b40d92935f8f6a0c99670a",
                    "name": "Scheduled Start",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\defrag.exe",
                    "md5": "2e190d98b46b93e62f68841216addd31",
                    "name": "ScheduledDefrag",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sdndiagnosticstask.exe",
                    "md5": "f56edf564602897934978c3a27ffa65b",
                    "name": "SDN Diagnostics Task",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\TpmTasks.dll",
                    "md5": "e10d2a03386c5056b0453f37b5ed5a66",
                    "name": "Secure-Boot-Update",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\srvinitconfig.exe",
                    "md5": "4273af0631f9c5d86bef8fb1687320b0",
                    "name": "Server Initial Configuration Task",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "Server Manager Performance Monitor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\servermanagerlauncher.exe",
                    "md5": "548f7e09b5824e7c66a5e3174f8abe38",
                    "name": "ServerManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\oobe\\SetupCleanupTask.dll",
                    "md5": "6f06af96d37e95e4361943ad96152db4",
                    "name": "SetupCleanupTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cleanmgr.exe",
                    "md5": "1a52c127fd0638bc2724765969c60b18",
                    "name": "SilentCleanup",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InstallServiceTasks.dll",
                    "md5": "855ebaa8373521bd3d39f282d36a2ba3",
                    "name": "SmartRetry",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\spaceagent.exe",
                    "md5": "0468be9a2369f777c26944e5a55aa357",
                    "name": "SpaceAgentTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\spaceman.exe",
                    "md5": "fede04bb5054ee911cd363c2c5e9eae4",
                    "name": "SpaceManagerTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\speech_onecore\\common\\speechmodeldownload.exe",
                    "md5": "0198cb2290a8ba095c79494c70fdd24d",
                    "name": "SpeechModelDownloadTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\TpmTasks.dll",
                    "md5": "e10d2a03386c5056b0453f37b5ed5a66",
                    "name": "Sqm-Tasks",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "md5": null,
                    "name": "StartComponentCleanup",
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rundll32.exe",
                    "md5": "f5b2d37bed0d2b15957736c23b9f547f",
                    "name": "StartupAppTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TieringEngineService.exe",
                    "md5": "a86dc1b6dc847669ef04a290fe53dd00",
                    "name": "Storage Tiers Management Initialization",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\defrag.exe",
                    "md5": "2e190d98b46b93e62f68841216addd31",
                    "name": "Storage Tiers Optimization",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\edptask.dll",
                    "md5": "45ed986a4271a0f5d9a27161af5a76ee",
                    "name": "StorageCardEncryption Task",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\StorageUsage.dll",
                    "md5": "03cc10ff04282f400550980f7db446e3",
                    "name": "StorageSense",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\sppcext.dll",
                    "md5": "9caaf31c430fb739eb183b8465e57527",
                    "name": "SvcRestartTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\sppcext.dll",
                    "md5": "9caaf31c430fb739eb183b8465e57527",
                    "name": "SvcRestartTaskLogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\sppcext.dll",
                    "md5": "9caaf31c430fb739eb183b8465e57527",
                    "name": "SvcRestartTaskNetwork",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CoreGlobConfig.dll",
                    "md5": "12d3ccc0bb2e767fbfb939d9f67f292a",
                    "name": "Synchronize Language Settings",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sc.exe",
                    "md5": "6fb10cd439b40d92935f8f6a0c99670a",
                    "name": "SynchronizeTime",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\tzsync.exe",
                    "md5": "5f35acc7c00591d50552ef7bbf02c99a",
                    "name": "SynchronizeTimeZone",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\bcdboot.exe",
                    "md5": "5db087d20a396ca780e453a6aefcbac4",
                    "name": "SyspartRepair",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drvinst.exe",
                    "md5": "99d71c1a835ade7bbe8914e1c99abc62",
                    "name": "Sysprep Generalize Drivers",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PlaySndSrv.dll",
                    "md5": "9e29f169c3709059eec0927218fc012e",
                    "name": "SystemSoundsService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dimsjob.dll",
                    "md5": "051ec97c93e31707f84f334af2b130d7",
                    "name": "SystemTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TempSignedLicenseExchangeTask.dll",
                    "md5": "4ec2e7dd80dc186e27d8ff7c75f39d22",
                    "name": "TempSignedLicenseExchange",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InputCloudStore.dll",
                    "md5": "13208dbfbbcfbad9cd0e6ab59f72bdec",
                    "name": "TouchpadSyncDataAvailable",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\TpmTasks.dll",
                    "md5": "e10d2a03386c5056b0453f37b5ed5a66",
                    "name": "Tpm-HASCertRetr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\TpmTasks.dll",
                    "md5": "e10d2a03386c5056b0453f37b5ed5a66",
                    "name": "Tpm-Maintenance",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\LanguageComponentsInstaller.dll",
                    "md5": "742c212ba7f256577168aeee2b00fb7c",
                    "name": "Uninstallation",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\SYSTEM32\\bthudtask.exe",
                    "md5": "8b5a37ab9140906cd4d0eba1af316fd5",
                    "name": "UninstallDeviceTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\windows media player\\wmpnscfg.exe",
                    "md5": "ec604a0d8a27976ab136a489d9b6aa76",
                    "name": "UpdateLibrary",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.UI.Immersive.dll",
                    "md5": "9317b7ddf5e59f1baf3f5b8c4024e39d",
                    "name": "UpdateUserPictureTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\SYSTEM32\\sc.exe",
                    "md5": "6fb10cd439b40d92935f8f6a0c99670a",
                    "name": "UPnPHostConfig",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\fcon.dll",
                    "md5": "3f6291e0a27897796b7f91d6402578e3",
                    "name": "UsageDataFlushing",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\fcon.dll",
                    "md5": "3f6291e0a27897796b7f91d6402578e3",
                    "name": "UsageDataReporting",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\usbceip.dll",
                    "md5": "8a4a3dfe0a2ef540717ce4812934691a",
                    "name": "UsbCeip",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dimsjob.dll",
                    "md5": "051ec97c93e31707f84f334af2b130d7",
                    "name": "UserTask",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dimsjob.dll",
                    "md5": "051ec97c93e31707f84f334af2b130d7",
                    "name": "UserTask-Roam",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\musnotification.exe",
                    "md5": "409ec93d1e08911f7e4ac299adc3d9b4",
                    "name": "USO_UxBroker",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "md5": null,
                    "name": "UUS Failover Task",
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\system32\\appidcertstorecheck.exe",
                    "md5": "1af4f5e1fb76259d44d5f205e983ab38",
                    "name": "VerifiedPublisherCertStoreCheck",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ReAgentTask.dll",
                    "md5": "235c3d1680f80ed563d02bc5a1f79844",
                    "name": "VerifyWinRE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InstallServiceTasks.dll",
                    "md5": "855ebaa8373521bd3d39f282d36a2ba3",
                    "name": "WakeUpAndContinueUpdates",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\InstallServiceTasks.dll",
                    "md5": "855ebaa8373521bd3d39f282d36a2ba3",
                    "name": "WakeUpAndScanForUpdates",
                    "signed": true
                },
                {
                    "fullpath": "c:\\programdata\\microsoft\\windows defender\\platform\\4.18.2205.7-0\\mpcmdrun.exe",
                    "md5": "d79162b9fb1e6f6916d21af592f15d8c",
                    "name": "Windows Defender Cache Maintenance",
                    "signed": true
                },
                {
                    "fullpath": "c:\\programdata\\microsoft\\windows defender\\platform\\4.18.2205.7-0\\mpcmdrun.exe",
                    "md5": "d79162b9fb1e6f6916d21af592f15d8c",
                    "name": "Windows Defender Cleanup",
                    "signed": true
                },
                {
                    "fullpath": "c:\\programdata\\microsoft\\windows defender\\platform\\4.18.2205.7-0\\mpcmdrun.exe",
                    "md5": "d79162b9fb1e6f6916d21af592f15d8c",
                    "name": "Windows Defender Scheduled Scan",
                    "signed": true
                },
                {
                    "fullpath": "c:\\programdata\\microsoft\\windows defender\\platform\\4.18.2205.7-0\\mpcmdrun.exe",
                    "md5": "d79162b9fb1e6f6916d21af592f15d8c",
                    "name": "Windows Defender Verification",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\windowsactiondialog.exe",
                    "md5": "9187a7c2fc4ad2a8ea9962885b79ecee",
                    "name": "WindowsActionDialog",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WinSATAPI.dll",
                    "md5": "d07b133ea6ab62ddb0b095fd3c621c0f",
                    "name": "WinSAT",
                    "signed": true
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Scheduled Task List
>|name|fullpath|signed|md5|
>|---|---|---|---|
>| .NET Framework NGEN v4.0.30319 | C:\Windows\System32\mscoree.dll | true | 7ddb05ec3be80b951478e594294c0361 |
>| .NET Framework NGEN v4.0.30319 64 | C:\Windows\System32\mscoree.dll | true | 7ddb05ec3be80b951478e594294c0361 |
>| .NET Framework NGEN v4.0.30319 64 Critical | C:\Windows\System32\mscoree.dll | true | 7ddb05ec3be80b951478e594294c0361 |
>| .NET Framework NGEN v4.0.30319 Critical | C:\Windows\System32\mscoree.dll | true | 7ddb05ec3be80b951478e594294c0361 |
>| Account Cleanup | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| AD RMS Rights Policy Template Management (Automated) | C:\Windows\system32\msdrm.dll | true | a4bffcd7b94bd687b3084bc6c7483a2c |
>| AD RMS Rights Policy Template Management (Manual) | C:\Windows\system32\msdrm.dll | true | a4bffcd7b94bd687b3084bc6c7483a2c |
>| AikCertEnrollTask | C:\Windows\system32\ngctasks.dll | true | 41fe9b51f30b9ff1a8fe4d724d6c7940 |
>| AnalyzeSystem | C:\Windows\System32\energytask.dll | true | 6b5151a0c751cbf6f01994ab1eb6cde8 |
>| appuriverifierdaily | C:\Windows\system32\apphostregistrationverifier.exe | true | 54b1076b71917ed737760b4feba9eeae |
>| appuriverifierinstall | C:\Windows\system32\apphostregistrationverifier.exe | true | 54b1076b71917ed737760b4feba9eeae |
>| Automatic-Device-Join | C:\Windows\system32\dsregcmd.exe | true | f4c8c7def69c3fcaf375db9a7710fd35 |
>| Background Synchronization | C:\Windows\System32\cscui.dll | true | 14eef80c58f9c7bffdbc5cb4867d5824 |
>| BfeOnServiceStartTypeChange | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| BgTaskRegistrationMaintenanceTask |  | false |  |
>| BitLocker Encrypt All Drives | C:\Windows\System32\edptask.dll | true | 45ed986a4271a0f5d9a27161af5a76ee |
>| BitLocker MDM policy Refresh | C:\Windows\System32\edptask.dll | true | 45ed986a4271a0f5d9a27161af5a76ee |
>| CacheTask | C:\Windows\system32\wininet.dll | true | 7f361d95066553e70da7a5329a429254 |
>| Calibration Loader | C:\Windows\System32\mscms.dll | true | 77f81e7a53a7192fefebd9db113709d5 |
>| CleanupOldPerfLogs | C:\Windows\system32\cscript.exe | true | 60ddaf328f6469c00a3fa14aaafed361 |
>| CleanupTemporaryState | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| Collection | C:\Windows\system32\cmd.exe | true | e7a6b1f51efb405287a8048cfa4690f4 |
>| Configuration | C:\Windows\system32\cmd.exe | true | e7a6b1f51efb405287a8048cfa4690f4 |
>| Consolidator | C:\Windows\system32\wsqmcons.exe | true | 0d229f8045fb12b584143ac82cbd1dcd |
>| CreateObjectTask | C:\Windows\system32\shell32.dll | true | 49cf1d96abbacab759a043253677219f |
>| CreateObjectTask | C:\Windows\System32\CloudExperienceHostBroker.exe | true | 8b4432582d6c68e5296e7f8cc8a3b8bc |
>| CryptoPolicyTask | C:\Windows\system32\ngctasks.dll | true | 41fe9b51f30b9ff1a8fe4d724d6c7940 |
>| Data Integrity Check And Scan | C:\Windows\System32\discan.dll | true | db01ce5db38cdc5f30537c129afc577c |
>| Data Integrity Scan | C:\Windows\System32\discan.dll | true | db01ce5db38cdc5f30537c129afc577c |
>| Data Integrity Scan for Crash Recovery | C:\Windows\System32\discan.dll | true | db01ce5db38cdc5f30537c129afc577c |
>| Device | C:\Windows\system32\devicecensus.exe | true | 2a33b4af5c4a152eed1c53bd39e99534 |
>| Device Install Group Policy | C:\Windows\System32\pnppolicy.dll | true | c9b1ab4b3f3f77e6513ce26b50215bc4 |
>| Device Install Reboot Required | C:\Windows\System32\pnpui.dll | true | 303788cfdf6ca3f929badd3be92ed879 |
>| Device User | C:\Windows\system32\devicecensus.exe | true | 2a33b4af5c4a152eed1c53bd39e99534 |
>| Device-Sync | C:\Windows\System32\dsregtask.dll | true | f64089d434bb3fb387f51d7525c56ea4 |
>| Diagnostics | C:\Windows\system32\disksnapshot.exe | true | 5536352f520d36eb7079647214ac9fa0 |
>| DirectXDatabaseUpdater | C:\Windows\system32\directxdatabaseupdater.exe | true | 26e02368365619d57d7a32cc37de35e1 |
>| DsSvcCleanup | C:\Windows\system32\dstokenclean.exe | true | 8c9493c2c59e6a7f667ea3355620ce48 |
>| DXGIAdapterCache | C:\Windows\system32\dxgiadaptercache.exe | true | fbcff8772630726ef5f00f26a3bcb437 |
>| EDP App Launch Task | C:\Windows\System32\edptask.dll | true | 45ed986a4271a0f5d9a27161af5a76ee |
>| EDP Auth Task | C:\Windows\System32\edptask.dll | true | 45ed986a4271a0f5d9a27161af5a76ee |
>| EDP Inaccessible Credentials Task | C:\Windows\System32\edptask.dll | true | 45ed986a4271a0f5d9a27161af5a76ee |
>| EDP Policy Manager | C:\Windows\System32\AppLockerCsp.dll | true | 20b0cc726f9d3fcf3b659f6a132e1e00 |
>| ExploitGuard MDM policy Refresh | C:\Windows\System32\MitigationConfiguration.dll | true | 0a9e147ff4d7f8212f0de006c52d865b |
>| ForceSynchronizeTime | C:\Windows\system32\TimeSyncTask.dll | true | c42636381538cbf55ac6ad954519f1f0 |
>| GatherNetworkInfo | C:\Windows\system32\gathernetworkinfo.vbs | true | da4d4261a43de7e851a9378ed0668eb9 |
>| HiveUploadTask |  | false |  |
>| IndexerAutomaticMaintenance | C:\Windows\System32\srchadmin.dll | true | 945162746b51b6082425edac70cd3774 |
>| Installation | C:\Windows\System32\LanguageComponentsInstaller.dll | true | 742c212ba7f256577168aeee2b00fb7c |
>| Interactive | C:\Windows\system32\wdc.dll | true | 7939c5b180bd8153f670f8231a401c75 |
>| KeyPreGenTask | C:\Windows\system32\ngctasks.dll | true | 41fe9b51f30b9ff1a8fe4d724d6c7940 |
>| License Validation | C:\Windows\system32\clipup.exe | true | 2220d1075b5e7e90ba4f4f8a0e701e45 |
>| LocalUserSyncDataAvailable | C:\Windows\System32\InputCloudStore.dll | true | 13208dbfbbcfbad9cd0e6ab59f72bdec |
>| LoginCheck | C:\Windows\system32\sc.exe | true | 6fb10cd439b40d92935f8f6a0c99670a |
>| Logon Synchronization | C:\Windows\System32\cscui.dll | true | 14eef80c58f9c7bffdbc5cb4867d5824 |
>| LPRemove | C:\Windows\system32\lpremove.exe | true | 2140dccdd4dab65241c309df02ce09a2 |
>| MaintenanceTasks | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| MapsToastTask | C:\Windows\System32\mapstoasttask.dll | true | 24c2e7e8b529023ee167dd68164cced7 |
>| MapsUpdateTask | C:\Windows\System32\mapsupdatetask.dll | true | 984960ba9e02bb161f0315f37eb9bde2 |
>| Metadata Refresh | C:\Windows\System32\DeviceSetupManagerAPI.dll | true | bb7755132e04b89f006522fa69ed8f38 |
>| Microsoft Compatibility Appraiser | C:\Windows\system32\compattelrunner.exe | true | 003339d6b38472f62b5da9c5d31f24ea |
>| Microsoft-Windows-DiskDiagnosticDataCollector | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| Microsoft-Windows-DiskDiagnosticResolver | C:\Windows\system32\dfdwiz.exe | true | be2d2340e25e4a5700381c8097af152b |
>| MicrosoftEdgeUpdateTaskMachineCore1d867a83717e5b7 | c:\program files (x86)\microsoft\edgeupdate\microsoftedgeupdate.exe | true | 8661fbb97161096be503cd295aa46409 |
>| MicrosoftEdgeUpdateTaskMachineUA | c:\program files (x86)\microsoft\edgeupdate\microsoftedgeupdate.exe | true | 8661fbb97161096be503cd295aa46409 |
>| MobilityManager | C:\Windows\system32\rasmbmgr.dll | true | c657bc27aae838fc3a295d51ac20a953 |
>| MouseSyncDataAvailable | C:\Windows\System32\InputCloudStore.dll | true | 13208dbfbbcfbad9cd0e6ab59f72bdec |
>| MsCtfMonitor | C:\Windows\system32\MsCtfMonitor.dll | true | f545384f0b0ca857197904a6092b3f16 |
>| Notifications | C:\Windows\system32\locationnotificationwindows.exe | true | a259819d5f8de86ff28546f4ded16f35 |
>| OobeDiscovery | C:\Windows\System32\MBMediaManager.dll | true | c1ce23565a9cadef865aedd6c041a2c4 |
>| PcaPatchDbTask | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| PenSyncDataAvailable | C:\Windows\System32\InputCloudStore.dll | true | 13208dbfbbcfbad9cd0e6ab59f72bdec |
>| PerformRemediation |  | false |  |
>| PolicyConverter | C:\Windows\system32\appidpolicyconverter.exe | true | 69a6bef4903650d20c12cbeff41367b0 |
>| Pre-staged app cleanup | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| ProactiveScan | C:\Windows\System32\pstask.dll | true | 796fb59bbf6e037b8a0c7646e6ea7a9e |
>| ProcessMemoryDiagnosticEvents | C:\Windows\System32\MemoryDiagnostic.dll | true | 8354fde902ba277b46c92175466438ef |
>| ProgramDataUpdater | C:\Windows\system32\compattelrunner.exe | true | 003339d6b38472f62b5da9c5d31f24ea |
>| Property Definition Sync | C:\Windows\System32\srmclient.dll | true | b2037c5822de4fc8107d952b55d7f107 |
>| Proxy | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| QueueReporting | C:\Windows\system32\wermgr.exe | true | ada54642a633e778222008de627b5db5 |
>| ReconcileFeatures | C:\Windows\System32\fcon.dll | true | 3f6291e0a27897796b7f91d6402578e3 |
>| Recovery-Check | C:\Windows\system32\dsregcmd.exe | true | f4c8c7def69c3fcaf375db9a7710fd35 |
>| RefreshCache | C:\Windows\System32\wosc.dll | true | feed4b9d117a6a512d93ca4e2c060419 |
>| RegIdleBackup | C:\Windows\System32\regidle.dll | true | f4608228b68515fe0ea440e1865f77c6 |
>| Registration | C:\Windows\system32\sc.exe | true | 6fb10cd439b40d92935f8f6a0c99670a |
>| Report policies | C:\Windows\system32\usoclient.exe | true | e4fd0a267e8d740f62e3ddf99917cbcc |
>| ResolutionHost | C:\Windows\System32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| RunFullMemoryDiagnostic | C:\Windows\System32\MemoryDiagnostic.dll | true | 8354fde902ba277b46c92175466438ef |
>| ScanForUpdates | C:\Windows\System32\InstallServiceTasks.dll | true | 855ebaa8373521bd3d39f282d36a2ba3 |
>| ScanForUpdatesAsUser | C:\Windows\System32\InstallServiceTasks.dll | true | 855ebaa8373521bd3d39f282d36a2ba3 |
>| Schedule Maintenance Work | C:\Windows\system32\usoclient.exe | true | e4fd0a267e8d740f62e3ddf99917cbcc |
>| Schedule Scan | C:\Windows\system32\usoclient.exe | true | e4fd0a267e8d740f62e3ddf99917cbcc |
>| Schedule Scan Static Task | C:\Windows\system32\usoclient.exe | true | e4fd0a267e8d740f62e3ddf99917cbcc |
>| Schedule Wake To Work | C:\Windows\system32\usoclient.exe | true | e4fd0a267e8d740f62e3ddf99917cbcc |
>| Schedule Work | C:\Windows\system32\usoclient.exe | true | e4fd0a267e8d740f62e3ddf99917cbcc |
>| Scheduled | C:\Windows\System32\sdiagschd.dll | true | c7ceb5a1f22da23b718712cb252df58a |
>| Scheduled Start | c:\windows\system32\sc.exe | true | 6fb10cd439b40d92935f8f6a0c99670a |
>| ScheduledDefrag | C:\Windows\system32\defrag.exe | true | 2e190d98b46b93e62f68841216addd31 |
>| SDN Diagnostics Task | C:\Windows\system32\sdndiagnosticstask.exe | true | f56edf564602897934978c3a27ffa65b |
>| Secure-Boot-Update | C:\Windows\system32\TpmTasks.dll | true | e10d2a03386c5056b0453f37b5ed5a66 |
>| Server Initial Configuration Task | C:\Windows\system32\srvinitconfig.exe | true | 4273af0631f9c5d86bef8fb1687320b0 |
>| Server Manager Performance Monitor | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| ServerManager | C:\Windows\system32\servermanagerlauncher.exe | true | 548f7e09b5824e7c66a5e3174f8abe38 |
>| SetupCleanupTask | C:\Windows\system32\oobe\SetupCleanupTask.dll | true | 6f06af96d37e95e4361943ad96152db4 |
>| SilentCleanup | C:\Windows\system32\cleanmgr.exe | true | 1a52c127fd0638bc2724765969c60b18 |
>| SmartRetry | C:\Windows\System32\InstallServiceTasks.dll | true | 855ebaa8373521bd3d39f282d36a2ba3 |
>| SpaceAgentTask | C:\Windows\system32\spaceagent.exe | true | 0468be9a2369f777c26944e5a55aa357 |
>| SpaceManagerTask | C:\Windows\system32\spaceman.exe | true | fede04bb5054ee911cd363c2c5e9eae4 |
>| SpeechModelDownloadTask | C:\Windows\system32\speech_onecore\common\speechmodeldownload.exe | true | 0198cb2290a8ba095c79494c70fdd24d |
>| Sqm-Tasks | C:\Windows\system32\TpmTasks.dll | true | e10d2a03386c5056b0453f37b5ed5a66 |
>| StartComponentCleanup |  | false |  |
>| StartupAppTask | C:\Windows\system32\rundll32.exe | true | f5b2d37bed0d2b15957736c23b9f547f |
>| Storage Tiers Management Initialization | C:\Windows\System32\TieringEngineService.exe | true | a86dc1b6dc847669ef04a290fe53dd00 |
>| Storage Tiers Optimization | C:\Windows\system32\defrag.exe | true | 2e190d98b46b93e62f68841216addd31 |
>| StorageCardEncryption Task | C:\Windows\System32\edptask.dll | true | 45ed986a4271a0f5d9a27161af5a76ee |
>| StorageSense | C:\Windows\system32\StorageUsage.dll | true | 03cc10ff04282f400550980f7db446e3 |
>| SvcRestartTask | C:\Windows\System32\sppcext.dll | true | 9caaf31c430fb739eb183b8465e57527 |
>| SvcRestartTaskLogon | C:\Windows\System32\sppcext.dll | true | 9caaf31c430fb739eb183b8465e57527 |
>| SvcRestartTaskNetwork | C:\Windows\System32\sppcext.dll | true | 9caaf31c430fb739eb183b8465e57527 |
>| Synchronize Language Settings | C:\Windows\System32\CoreGlobConfig.dll | true | 12d3ccc0bb2e767fbfb939d9f67f292a |
>| SynchronizeTime | C:\Windows\system32\sc.exe | true | 6fb10cd439b40d92935f8f6a0c99670a |
>| SynchronizeTimeZone | C:\Windows\system32\tzsync.exe | true | 5f35acc7c00591d50552ef7bbf02c99a |
>| SyspartRepair | C:\Windows\system32\bcdboot.exe | true | 5db087d20a396ca780e453a6aefcbac4 |
>| Sysprep Generalize Drivers | C:\Windows\system32\drvinst.exe | true | 99d71c1a835ade7bbe8914e1c99abc62 |
>| SystemSoundsService | C:\Windows\System32\PlaySndSrv.dll | true | 9e29f169c3709059eec0927218fc012e |
>| SystemTask | C:\Windows\system32\dimsjob.dll | true | 051ec97c93e31707f84f334af2b130d7 |
>| TempSignedLicenseExchange | C:\Windows\System32\TempSignedLicenseExchangeTask.dll | true | 4ec2e7dd80dc186e27d8ff7c75f39d22 |
>| TouchpadSyncDataAvailable | C:\Windows\System32\InputCloudStore.dll | true | 13208dbfbbcfbad9cd0e6ab59f72bdec |
>| Tpm-HASCertRetr | C:\Windows\system32\TpmTasks.dll | true | e10d2a03386c5056b0453f37b5ed5a66 |
>| Tpm-Maintenance | C:\Windows\system32\TpmTasks.dll | true | e10d2a03386c5056b0453f37b5ed5a66 |
>| Uninstallation | C:\Windows\System32\LanguageComponentsInstaller.dll | true | 742c212ba7f256577168aeee2b00fb7c |
>| UninstallDeviceTask | C:\Windows\SYSTEM32\bthudtask.exe | true | 8b5a37ab9140906cd4d0eba1af316fd5 |
>| UpdateLibrary | C:\Program Files\windows media player\wmpnscfg.exe | true | ec604a0d8a27976ab136a489d9b6aa76 |
>| UpdateUserPictureTask | C:\Windows\System32\Windows.UI.Immersive.dll | true | 9317b7ddf5e59f1baf3f5b8c4024e39d |
>| UPnPHostConfig | C:\Windows\SYSTEM32\sc.exe | true | 6fb10cd439b40d92935f8f6a0c99670a |
>| UsageDataFlushing | C:\Windows\System32\fcon.dll | true | 3f6291e0a27897796b7f91d6402578e3 |
>| UsageDataReporting | C:\Windows\System32\fcon.dll | true | 3f6291e0a27897796b7f91d6402578e3 |
>| UsbCeip | C:\Windows\System32\usbceip.dll | true | 8a4a3dfe0a2ef540717ce4812934691a |
>| UserTask | C:\Windows\system32\dimsjob.dll | true | 051ec97c93e31707f84f334af2b130d7 |
>| UserTask-Roam | C:\Windows\system32\dimsjob.dll | true | 051ec97c93e31707f84f334af2b130d7 |
>| USO_UxBroker | C:\Windows\system32\musnotification.exe | true | 409ec93d1e08911f7e4ac299adc3d9b4 |
>| UUS Failover Task |  | false |  |
>| VerifiedPublisherCertStoreCheck | C:\Windows\system32\appidcertstorecheck.exe | true | 1af4f5e1fb76259d44d5f205e983ab38 |
>| VerifyWinRE | C:\Windows\System32\ReAgentTask.dll | true | 235c3d1680f80ed563d02bc5a1f79844 |
>| WakeUpAndContinueUpdates | C:\Windows\System32\InstallServiceTasks.dll | true | 855ebaa8373521bd3d39f282d36a2ba3 |
>| WakeUpAndScanForUpdates | C:\Windows\System32\InstallServiceTasks.dll | true | 855ebaa8373521bd3d39f282d36a2ba3 |
>| Windows Defender Cache Maintenance | c:\programdata\microsoft\windows defender\platform\4.18.2205.7-0\mpcmdrun.exe | true | d79162b9fb1e6f6916d21af592f15d8c |
>| Windows Defender Cleanup | c:\programdata\microsoft\windows defender\platform\4.18.2205.7-0\mpcmdrun.exe | true | d79162b9fb1e6f6916d21af592f15d8c |
>| Windows Defender Scheduled Scan | c:\programdata\microsoft\windows defender\platform\4.18.2205.7-0\mpcmdrun.exe | true | d79162b9fb1e6f6916d21af592f15d8c |
>| Windows Defender Verification | c:\programdata\microsoft\windows defender\platform\4.18.2205.7-0\mpcmdrun.exe | true | d79162b9fb1e6f6916d21af592f15d8c |
>| WindowsActionDialog | C:\Windows\system32\windowsactiondialog.exe | true | 9187a7c2fc4ad2a8ea9962885b79ecee |
>| WinSAT | C:\Windows\system32\WinSATAPI.dll | true | d07b133ea6ab62ddb0b095fd3c621c0f |


### harfanglab-result-driverlist
***
Get a hostname's loaded drivers from job results


#### Base Command

`harfanglab-result-driverlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Driver.data | unknown | Provides a list of loaded drivers | 

#### Command example
```!harfanglab-result-driverlist job_id="d93fdb8c-2877-4625-a6a4-7d8642f7a02b"```
#### Context Example
```json
{
    "Harfanglab": {
        "Driver": {
            "data": [
                {
                    "fullpath": "C:\\Windows\\system32\\ntoskrnl.exe",
                    "md5": "10936de9161009cdf20e17450dcfff58",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\kd.dll",
                    "md5": "f5b674dcfe06dfa32e5fb9517694bd77",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\bootvid.dll",
                    "md5": "daff4f9258fbcc0d4abfb9a371f88394",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\mcupdate_genuineintel.dll",
                    "md5": "16835b10a6ed1e1765cb98e7f1bffcf5",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\pshed.dll",
                    "md5": "cc711005573cbc5609fe47601ea154c1",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\clfs.sys",
                    "md5": "e1276c5405944c290a27c9c5544e8318",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\hal.dll",
                    "md5": "62cfc8986445a2b985ec45c804f592ab",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tm.sys",
                    "md5": "37ea0b86cdad032f9f8a08ae11b22e1c",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\fltmgr.sys",
                    "md5": "a5da65b212ef41444f5c663bd0bc733e",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cmimcext.sys",
                    "md5": "1aca7b86dbe10d1394ae5988ec47980d",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\clipsp.sys",
                    "md5": "f65ed58b117b336f4d9b3ce34f19e1bd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\werkernel.sys",
                    "md5": "3e21a039ebcce4e00fbbdd36580101ca",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\msrpc.sys",
                    "md5": "20cbe52b050fa5438428158323e4b0c2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ksecdd.sys",
                    "md5": "9dacc16c05894f8db0b93fb60fcc2341",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ntosext.sys",
                    "md5": "6a9dabe311bcd5604eb0797d27d4e172",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cng.sys",
                    "md5": "395e313507ca049e185ea3f6356fefdb",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wdf01000.sys",
                    "md5": "252710b80261fc7a470765da230f4582",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\ci.dll",
                    "md5": "c8e44390ab50e3468999dade07dbbda5",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\driverstore\\filerepository\\prm.inf_amd64_5a6e1bc540be827c\\prm.sys",
                    "md5": "12b48cb3274927c57bf770dea9476011",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\acpiex.sys",
                    "md5": "0c2a19fce98cd5279174f70ecde10173",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wpprecorder.sys",
                    "md5": "47daa15532c855eeb6adb76949b920b8",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\acpi.sys",
                    "md5": "128242662d8f677e8d243dffe4c30acf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wdfldr.sys",
                    "md5": "ca1fcc04b07ee6d8e77c67d1cc875db4",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mssecflt.sys",
                    "md5": "e4c24f3d6d7968a7f98df30644fbf4c5",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\sgrmagent.sys",
                    "md5": "e81fdb11bb9dc3b743d07402ab0d6850",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\windowstrustedrtproxy.sys",
                    "md5": "0b728612a0aec70533a641fbec23d01a",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ndis.sys",
                    "md5": "020222b426ce45d4081826902f1496d2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\intelpep.sys",
                    "md5": "4217aa0ec9a2fa258de03b098d83bc71",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\windowstrustedrt.sys",
                    "md5": "74240ace203c61bd4f4b6081654884c0",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\intelpmt.sys",
                    "md5": "698ad8b52eaaaeeb7a5cad5c28db5af5",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wmilib.sys",
                    "md5": "4a6b76cd34c968938c97a2e344d024a7",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\pcw.sys",
                    "md5": "5f0c91ebcc8fd380306628283d0ad28d",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\netio.sys",
                    "md5": "989cbf82a9e67583104ab6ede987d531",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\msisadrv.sys",
                    "md5": "af9787af0870c3349336c641a9deb816",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\vdrvroot.sys",
                    "md5": "504a71b5d24a6975a1d771c44ccf86fd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cea.sys",
                    "md5": "69a9e9d542f71928a2cd4b504779c3ec",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\partmgr.sys",
                    "md5": "f68d2066b9f1a4fdb95613770c55c338",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\spaceport.sys",
                    "md5": "7d38fe01b3309a01119b19b1a807673b",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\pci.sys",
                    "md5": "62e81f2f53126ec6e5149667de967897",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\pdc.sys",
                    "md5": "5b34708a130a4aba61fabb66d3153aad",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mountmgr.sys",
                    "md5": "531d3c5a7749a2c912ea6a0e5cb67c75",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ataport.sys",
                    "md5": "17fa3eb00ff97f25819f8f8e1c6085ab",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\volmgr.sys",
                    "md5": "0bc9e7b4865ed2227cccc05f1dbc6f52",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\pciidex.sys",
                    "md5": "bdca300aebaa8acf7d1d44d59d2afd6d",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\storahci.sys",
                    "md5": "ed739b05ba3210ea45b0ad74e4df167b",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\volmgrx.sys",
                    "md5": "f7da6b4c3238121c132213e30b7651b2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\intelide.sys",
                    "md5": "32f91cbd0b66b168082c0472e22c8c89",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\atapi.sys",
                    "md5": "6db20deaa154aee9122d8aee5541f5c7",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\storport.sys",
                    "md5": "284bffa1e8be61a158c6a5fd674f3515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ehstorclass.sys",
                    "md5": "5a27edc058ead20f9b71c440a6f5c764",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wd\\wdfilter.sys",
                    "md5": "98e9a26bbd42e644bf797710f9f65dce",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wof.sys",
                    "md5": "06ea9914a709a459075122981df85d37",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ntfs.sys",
                    "md5": "dd4cee5428499ccd02013ce6a591b600",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ksecpkg.sys",
                    "md5": "ad9063eeb2a5179acd11bb1754023c30",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\vboxguest.sys",
                    "md5": "873c8107cc6f4a8339b66eeb9fa2d2e1",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\fs_rec.sys",
                    "md5": "b778af9c823c027d4e3f2de30eeccc60",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tcpip.sys",
                    "md5": "8a13f21e7fb8f78a3d01bb952f691242",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\fwpkclnt.sys",
                    "md5": "2edef18a931f8346a504ae1383473cf1",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wfplwfs.sys",
                    "md5": "2aad68e852436e0a7363377c91e0302d",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cdrom.sys",
                    "md5": "f8598f378ec752af85fa3f642a870906",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\classpnp.sys",
                    "md5": "1314a382832de7861a0f7dfaad4f88be",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\disk.sys",
                    "md5": "ba90cfc0d444bb5468fd050073ea5386",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\volume.sys",
                    "md5": "05fac0dd1370c68530f0a72caf64a27b",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\volsnap.sys",
                    "md5": "8e0d28114d41d67b95c71d5cd17e86c0",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\crashdmp.sys",
                    "md5": "75c7c14ea63bc131708c08d3569054ee",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mup.sys",
                    "md5": "265830023853939fcbf87ba954f3146a",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\watchdog.sys",
                    "md5": "1d763e1c86f2f275af87c426164460a9",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\filecrypt.sys",
                    "md5": "087265c07e4364fd44d213b7b3fd57b3",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\null.sys",
                    "md5": "85ab11a2f4fb94b9fb6a2d889d83fcac",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\dxgkrnl.sys",
                    "md5": "2e247733503fa28483e871dba19519b9",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tbs.sys",
                    "md5": "4bba2bddbd2a8982d195e12d6ea9e246",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\driverstore\\filerepository\\basicdisplay.inf_amd64_7e9cb61920ccc040\\basicdisplay.sys",
                    "md5": "9e94d724c1dc4cca719be07eb1020dee",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\msfs.sys",
                    "md5": "82560bdaf351cd8917f01b5d7a1c03a4",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tdi.sys",
                    "md5": "49999ea1cdb93b73daea66e5a173d065",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\driverstore\\filerepository\\basicrender.inf_amd64_1c03174c7c755975\\basicrender.sys",
                    "md5": "5e1ea96e7fd6ac5d1ba7c56e4b33e100",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\npfs.sys",
                    "md5": "3f4f4c10e7b81bc4b2d5c4c7e2c268a0",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\afd.sys",
                    "md5": "d5e687f3cb3f33b2554037332c7ffd26",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cimfs.sys",
                    "md5": "c77761c2f092d133329ffa7e5756c216",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tdx.sys",
                    "md5": "7fd3d3e74c586e48b1fe6a26d9041a5a",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\netbt.sys",
                    "md5": "3937adb725a18a0dac7ae7c1e0efd2e4",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\afunix.sys",
                    "md5": "6904a360dcc3b90a798cde109f25ebb4",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ndiscap.sys",
                    "md5": "5c5dab38e24c46cc9e2ac793541780ed",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\npsvctrig.sys",
                    "md5": "e6d73640ffe28611bebcf1af11ef18dc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\pacer.sys",
                    "md5": "39b1cf32f9c62caa14516259823d0291",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\vboxsf.sys",
                    "md5": "9c5fa56ec9fa228e31484df1e41364d3",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mssmbios.sys",
                    "md5": "530d7c0b3e2fc916fb0da8fc8d4b6ef6",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\netbios.sys",
                    "md5": "9085e8233201b963ce447dc645670670",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\rdbss.sys",
                    "md5": "2e7eb447308f9c60e98a0c0c99ba4c78",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\nsiproxy.sys",
                    "md5": "3a66f37dde3f8338cbd639b0106e38ca",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\bam.sys",
                    "md5": "41f732bba9521ceb0c834d2b3fbb5090",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\i8042prt.sys",
                    "md5": "8bc4c8d32cea74b3c27a77330ba1ff28",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\dfsc.sys",
                    "md5": "7317e6235f0f1b1e6fa5a6d2cf9ba724",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\fastfat.sys",
                    "md5": "f145863ca528a8975a72b8cdf3ec20e8",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ahcache.sys",
                    "md5": "bfb562fd6102dc1729425c4c3cd450e5",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\driverstore\\filerepository\\compositebus.inf_amd64_130dea07a2ae55eb\\compositebus.sys",
                    "md5": "564ac50963890f9b3ab0052c249dbc21",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\kdnic.sys",
                    "md5": "d8ac3b58add59eeb8674787347795806",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\kbdclass.sys",
                    "md5": "27947916ad55bfdb88c6f2e00ac4d90b",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\vboxmouse.sys",
                    "md5": "0b922b41369b9779a4e71d68efc02275",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\driverstore\\filerepository\\umbus.inf_amd64_f529037a77b144c5\\umbus.sys",
                    "md5": "65aa6b0661c1eedbe80667b39bebc784",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mouclass.sys",
                    "md5": "0c34c0630a233c0f62fcdd4d13af0d47",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cmbatt.sys",
                    "md5": "bff879e5bb87092532be8229528c2100",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ndisvirtualbus.sys",
                    "md5": "a686524719ece3235adae3e30214a2db",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\battc.sys",
                    "md5": "503867acfd527cf7a315bdcb6f1062c5",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\vboxwddm.sys",
                    "md5": "66ed4d8224cfe448ba9dad324b564f35",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\e1g6032e.sys",
                    "md5": "cced99682127e8582e5f716ece775ef8",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\intelppm.sys",
                    "md5": "786f77d638ff941977956898ebcb758e",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "md5": null,
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\system32\\driverstore\\filerepository\\swenum.inf_amd64_a8eddc34aa14df5f\\swenum.sys",
                    "md5": "0d8210a54c87102db6f0406b1c265a9c",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ks.sys",
                    "md5": "7114a4394561a321bcd145be2e3737d5",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "md5": null,
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\system32\\win32kfull.sys",
                    "md5": "40de0513a189152f1c21a63d657e2804",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\win32kbase.sys",
                    "md5": "a6869afa4c477af83f232c32a5daa9e7",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\win32k.sys",
                    "md5": "436e4df36ac1549d2eb3f8eac53df074",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\rdpbus.sys",
                    "md5": "d1edd6604ed1a6e2bc45134c307d3e82",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\hidparse.sys",
                    "md5": "d9a8063a2c30bd2f4815d973d9711d22",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\monitor.sys",
                    "md5": "b8f452f5baa586406a190c647c1443e4",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wcifs.sys",
                    "md5": "f6eac3ea92f216a48495ea0fe645dcbf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\storqosflt.sys",
                    "md5": "966997d2b3ebe8ea30ec42101dbe5768",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\dxgmms2.sys",
                    "md5": "98ce225ae17a6d67ae1e5d2869fdf7f7",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cdd.dll",
                    "md5": "1c12e169adb6dc8b3cedc0a09bd1188f",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cldflt.sys",
                    "md5": "ce5e59e0b763ec8495c9a623519d55ee",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\rdpvideominiport.sys",
                    "md5": "26fa006e8dc780d58158f58cf11fe3a3",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mrxsmb.sys",
                    "md5": "b0186ea7f1979d9f02da0ae11542d39d",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\msquic.sys",
                    "md5": "afb57e498cd26284e9603353fb9104ad",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mslldp.sys",
                    "md5": "d69790cc30e3717431067b1a43a679f1",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\bowser.sys",
                    "md5": "1349bea208c0f48534cfde0e8a64c3a4",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\lltdio.sys",
                    "md5": "38c53c38731190ba73b39cbd3befe14a",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\bindflt.sys",
                    "md5": "103737c5c139bfa688ea52c3f1fdf8cc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\rdpdr.sys",
                    "md5": "e63147974f4fc014742c5471c7bc516d",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\http.sys",
                    "md5": "0db27d34c898a592dcf7e4a5eeacc2be",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\srvnet.sys",
                    "md5": "fdfcf9c6d6bec82925b2e52926acbbb2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mrxsmb20.sys",
                    "md5": "40f91604967e771021b89a54ddb74131",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\peauth.sys",
                    "md5": "e8789b5f24aa80994be1e2b27992af7c",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\srv2.sys",
                    "md5": "ccfe129cbdea8b8c6051d11c6c694230",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\rspndr.sys",
                    "md5": "e66e50a0a3344a377838ef8b965a7f88",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mpsdrv.sys",
                    "md5": "fb4d94870b1f42d93feb8a85b590fd4a",
                    "signed": true
                },
                {
                    "fullpath": "c:\\programdata\\microsoft\\windows defender\\definition updates\\{265c6876-acfd-4597-b853-b3e54112bc77}\\mpksldrv.sys",
                    "md5": "6f2f14025a606b924e77ad29aa68d231",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\hlprotect.sys",
                    "md5": "44480d8a012a7249bc390cbcdb687fee",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tcpipreg.sys",
                    "md5": "6a7338ae6e83bf75f2057b7b1242f81b",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\condrv.sys",
                    "md5": "122c522158f2499cee46e1d2e2b59787",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mmcss.sys",
                    "md5": "a10c637165ab63671f5ea554109d008c",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\terminpt.sys",
                    "md5": "a073581102fca9e17a1a4a5a40542d5c",
                    "signed": true
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Driver List
>|fullpath|signed|md5|
>|---|---|---|
>| C:\Windows\system32\ntoskrnl.exe | true | 10936de9161009cdf20e17450dcfff58 |
>| C:\Windows\system32\kd.dll | true | f5b674dcfe06dfa32e5fb9517694bd77 |
>| C:\Windows\system32\bootvid.dll | true | daff4f9258fbcc0d4abfb9a371f88394 |
>| C:\Windows\system32\mcupdate_genuineintel.dll | true | 16835b10a6ed1e1765cb98e7f1bffcf5 |
>| C:\Windows\system32\pshed.dll | true | cc711005573cbc5609fe47601ea154c1 |
>| C:\Windows\system32\drivers\clfs.sys | true | e1276c5405944c290a27c9c5544e8318 |
>| C:\Windows\system32\hal.dll | true | 62cfc8986445a2b985ec45c804f592ab |
>| C:\Windows\system32\drivers\tm.sys | true | 37ea0b86cdad032f9f8a08ae11b22e1c |
>| C:\Windows\system32\drivers\fltmgr.sys | true | a5da65b212ef41444f5c663bd0bc733e |
>| C:\Windows\system32\drivers\cmimcext.sys | true | 1aca7b86dbe10d1394ae5988ec47980d |
>| C:\Windows\system32\drivers\clipsp.sys | true | f65ed58b117b336f4d9b3ce34f19e1bd |
>| C:\Windows\system32\drivers\werkernel.sys | true | 3e21a039ebcce4e00fbbdd36580101ca |
>| C:\Windows\system32\drivers\msrpc.sys | true | 20cbe52b050fa5438428158323e4b0c2 |
>| C:\Windows\system32\drivers\ksecdd.sys | true | 9dacc16c05894f8db0b93fb60fcc2341 |
>| C:\Windows\system32\drivers\ntosext.sys | true | 6a9dabe311bcd5604eb0797d27d4e172 |
>| C:\Windows\system32\drivers\cng.sys | true | 395e313507ca049e185ea3f6356fefdb |
>| C:\Windows\system32\drivers\wdf01000.sys | true | 252710b80261fc7a470765da230f4582 |
>| C:\Windows\system32\ci.dll | true | c8e44390ab50e3468999dade07dbbda5 |
>| C:\Windows\system32\driverstore\filerepository\prm.inf_amd64_5a6e1bc540be827c\prm.sys | true | 12b48cb3274927c57bf770dea9476011 |
>| C:\Windows\system32\drivers\acpiex.sys | true | 0c2a19fce98cd5279174f70ecde10173 |
>| C:\Windows\system32\drivers\wpprecorder.sys | true | 47daa15532c855eeb6adb76949b920b8 |
>| C:\Windows\system32\drivers\acpi.sys | true | 128242662d8f677e8d243dffe4c30acf |
>| C:\Windows\system32\drivers\wdfldr.sys | true | ca1fcc04b07ee6d8e77c67d1cc875db4 |
>| C:\Windows\system32\drivers\mssecflt.sys | true | e4c24f3d6d7968a7f98df30644fbf4c5 |
>| C:\Windows\system32\drivers\sgrmagent.sys | true | e81fdb11bb9dc3b743d07402ab0d6850 |
>| C:\Windows\system32\drivers\windowstrustedrtproxy.sys | true | 0b728612a0aec70533a641fbec23d01a |
>| C:\Windows\system32\drivers\ndis.sys | true | 020222b426ce45d4081826902f1496d2 |
>| C:\Windows\system32\drivers\intelpep.sys | true | 4217aa0ec9a2fa258de03b098d83bc71 |
>| C:\Windows\system32\drivers\windowstrustedrt.sys | true | 74240ace203c61bd4f4b6081654884c0 |
>| C:\Windows\system32\drivers\intelpmt.sys | true | 698ad8b52eaaaeeb7a5cad5c28db5af5 |
>| C:\Windows\system32\drivers\wmilib.sys | true | 4a6b76cd34c968938c97a2e344d024a7 |
>| C:\Windows\system32\drivers\pcw.sys | true | 5f0c91ebcc8fd380306628283d0ad28d |
>| C:\Windows\system32\drivers\netio.sys | true | 989cbf82a9e67583104ab6ede987d531 |
>| C:\Windows\system32\drivers\msisadrv.sys | true | af9787af0870c3349336c641a9deb816 |
>| C:\Windows\system32\drivers\vdrvroot.sys | true | 504a71b5d24a6975a1d771c44ccf86fd |
>| C:\Windows\system32\drivers\cea.sys | true | 69a9e9d542f71928a2cd4b504779c3ec |
>| C:\Windows\system32\drivers\partmgr.sys | true | f68d2066b9f1a4fdb95613770c55c338 |
>| C:\Windows\system32\drivers\spaceport.sys | true | 7d38fe01b3309a01119b19b1a807673b |
>| C:\Windows\system32\drivers\pci.sys | true | 62e81f2f53126ec6e5149667de967897 |
>| C:\Windows\system32\drivers\pdc.sys | true | 5b34708a130a4aba61fabb66d3153aad |
>| C:\Windows\system32\drivers\mountmgr.sys | true | 531d3c5a7749a2c912ea6a0e5cb67c75 |
>| C:\Windows\system32\drivers\ataport.sys | true | 17fa3eb00ff97f25819f8f8e1c6085ab |
>| C:\Windows\system32\drivers\volmgr.sys | true | 0bc9e7b4865ed2227cccc05f1dbc6f52 |
>| C:\Windows\system32\drivers\pciidex.sys | true | bdca300aebaa8acf7d1d44d59d2afd6d |
>| C:\Windows\system32\drivers\storahci.sys | true | ed739b05ba3210ea45b0ad74e4df167b |
>| C:\Windows\system32\drivers\volmgrx.sys | true | f7da6b4c3238121c132213e30b7651b2 |
>| C:\Windows\system32\drivers\intelide.sys | true | 32f91cbd0b66b168082c0472e22c8c89 |
>| C:\Windows\system32\drivers\atapi.sys | true | 6db20deaa154aee9122d8aee5541f5c7 |
>| C:\Windows\system32\drivers\storport.sys | true | 284bffa1e8be61a158c6a5fd674f3515 |
>| C:\Windows\system32\drivers\ehstorclass.sys | true | 5a27edc058ead20f9b71c440a6f5c764 |
>| C:\Windows\system32\drivers\wd\wdfilter.sys | true | 98e9a26bbd42e644bf797710f9f65dce |
>| C:\Windows\system32\drivers\wof.sys | true | 06ea9914a709a459075122981df85d37 |
>| C:\Windows\system32\drivers\ntfs.sys | true | dd4cee5428499ccd02013ce6a591b600 |
>| C:\Windows\system32\drivers\ksecpkg.sys | true | ad9063eeb2a5179acd11bb1754023c30 |
>| C:\Windows\system32\drivers\vboxguest.sys | true | 873c8107cc6f4a8339b66eeb9fa2d2e1 |
>| C:\Windows\system32\drivers\fs_rec.sys | true | b778af9c823c027d4e3f2de30eeccc60 |
>| C:\Windows\system32\drivers\tcpip.sys | true | 8a13f21e7fb8f78a3d01bb952f691242 |
>| C:\Windows\system32\drivers\fwpkclnt.sys | true | 2edef18a931f8346a504ae1383473cf1 |
>| C:\Windows\system32\drivers\wfplwfs.sys | true | 2aad68e852436e0a7363377c91e0302d |
>| C:\Windows\system32\drivers\cdrom.sys | true | f8598f378ec752af85fa3f642a870906 |
>| C:\Windows\system32\drivers\classpnp.sys | true | 1314a382832de7861a0f7dfaad4f88be |
>| C:\Windows\system32\drivers\disk.sys | true | ba90cfc0d444bb5468fd050073ea5386 |
>| C:\Windows\system32\drivers\volume.sys | true | 05fac0dd1370c68530f0a72caf64a27b |
>| C:\Windows\system32\drivers\volsnap.sys | true | 8e0d28114d41d67b95c71d5cd17e86c0 |
>| C:\Windows\system32\drivers\crashdmp.sys | true | 75c7c14ea63bc131708c08d3569054ee |
>| C:\Windows\system32\drivers\mup.sys | true | 265830023853939fcbf87ba954f3146a |
>| C:\Windows\system32\drivers\watchdog.sys | true | 1d763e1c86f2f275af87c426164460a9 |
>| C:\Windows\system32\drivers\filecrypt.sys | true | 087265c07e4364fd44d213b7b3fd57b3 |
>| C:\Windows\system32\drivers\null.sys | true | 85ab11a2f4fb94b9fb6a2d889d83fcac |
>| C:\Windows\system32\drivers\dxgkrnl.sys | true | 2e247733503fa28483e871dba19519b9 |
>| C:\Windows\system32\drivers\tbs.sys | true | 4bba2bddbd2a8982d195e12d6ea9e246 |
>| C:\Windows\system32\driverstore\filerepository\basicdisplay.inf_amd64_7e9cb61920ccc040\basicdisplay.sys | true | 9e94d724c1dc4cca719be07eb1020dee |
>| C:\Windows\system32\drivers\msfs.sys | true | 82560bdaf351cd8917f01b5d7a1c03a4 |
>| C:\Windows\system32\drivers\tdi.sys | true | 49999ea1cdb93b73daea66e5a173d065 |
>| C:\Windows\system32\driverstore\filerepository\basicrender.inf_amd64_1c03174c7c755975\basicrender.sys | true | 5e1ea96e7fd6ac5d1ba7c56e4b33e100 |
>| C:\Windows\system32\drivers\npfs.sys | true | 3f4f4c10e7b81bc4b2d5c4c7e2c268a0 |
>| C:\Windows\system32\drivers\afd.sys | true | d5e687f3cb3f33b2554037332c7ffd26 |
>| C:\Windows\system32\drivers\cimfs.sys | true | c77761c2f092d133329ffa7e5756c216 |
>| C:\Windows\system32\drivers\tdx.sys | true | 7fd3d3e74c586e48b1fe6a26d9041a5a |
>| C:\Windows\system32\drivers\netbt.sys | true | 3937adb725a18a0dac7ae7c1e0efd2e4 |
>| C:\Windows\system32\drivers\afunix.sys | true | 6904a360dcc3b90a798cde109f25ebb4 |
>| C:\Windows\system32\drivers\ndiscap.sys | true | 5c5dab38e24c46cc9e2ac793541780ed |
>| C:\Windows\system32\drivers\npsvctrig.sys | true | e6d73640ffe28611bebcf1af11ef18dc |
>| C:\Windows\system32\drivers\pacer.sys | true | 39b1cf32f9c62caa14516259823d0291 |
>| C:\Windows\system32\drivers\vboxsf.sys | true | 9c5fa56ec9fa228e31484df1e41364d3 |
>| C:\Windows\system32\drivers\mssmbios.sys | true | 530d7c0b3e2fc916fb0da8fc8d4b6ef6 |
>| C:\Windows\system32\drivers\netbios.sys | true | 9085e8233201b963ce447dc645670670 |
>| C:\Windows\system32\drivers\rdbss.sys | true | 2e7eb447308f9c60e98a0c0c99ba4c78 |
>| C:\Windows\system32\drivers\nsiproxy.sys | true | 3a66f37dde3f8338cbd639b0106e38ca |
>| C:\Windows\system32\drivers\bam.sys | true | 41f732bba9521ceb0c834d2b3fbb5090 |
>| C:\Windows\system32\drivers\i8042prt.sys | true | 8bc4c8d32cea74b3c27a77330ba1ff28 |
>| C:\Windows\system32\drivers\dfsc.sys | true | 7317e6235f0f1b1e6fa5a6d2cf9ba724 |
>| C:\Windows\system32\drivers\fastfat.sys | true | f145863ca528a8975a72b8cdf3ec20e8 |
>| C:\Windows\system32\drivers\ahcache.sys | true | bfb562fd6102dc1729425c4c3cd450e5 |
>| C:\Windows\system32\driverstore\filerepository\compositebus.inf_amd64_130dea07a2ae55eb\compositebus.sys | true | 564ac50963890f9b3ab0052c249dbc21 |
>| C:\Windows\system32\drivers\kdnic.sys | true | d8ac3b58add59eeb8674787347795806 |
>| C:\Windows\system32\drivers\kbdclass.sys | true | 27947916ad55bfdb88c6f2e00ac4d90b |
>| C:\Windows\system32\drivers\vboxmouse.sys | true | 0b922b41369b9779a4e71d68efc02275 |
>| C:\Windows\system32\driverstore\filerepository\umbus.inf_amd64_f529037a77b144c5\umbus.sys | true | 65aa6b0661c1eedbe80667b39bebc784 |
>| C:\Windows\system32\drivers\mouclass.sys | true | 0c34c0630a233c0f62fcdd4d13af0d47 |
>| C:\Windows\system32\drivers\cmbatt.sys | true | bff879e5bb87092532be8229528c2100 |
>| C:\Windows\system32\drivers\ndisvirtualbus.sys | true | a686524719ece3235adae3e30214a2db |
>| C:\Windows\system32\drivers\battc.sys | true | 503867acfd527cf7a315bdcb6f1062c5 |
>| C:\Windows\system32\drivers\vboxwddm.sys | true | 66ed4d8224cfe448ba9dad324b564f35 |
>| C:\Windows\system32\drivers\e1g6032e.sys | true | cced99682127e8582e5f716ece775ef8 |
>| C:\Windows\system32\drivers\intelppm.sys | true | 786f77d638ff941977956898ebcb758e |
>|  | false |  |
>| C:\Windows\system32\driverstore\filerepository\swenum.inf_amd64_a8eddc34aa14df5f\swenum.sys | true | 0d8210a54c87102db6f0406b1c265a9c |
>| C:\Windows\system32\drivers\ks.sys | true | 7114a4394561a321bcd145be2e3737d5 |
>|  | false |  |
>| C:\Windows\system32\win32kfull.sys | true | 40de0513a189152f1c21a63d657e2804 |
>| C:\Windows\system32\win32kbase.sys | true | a6869afa4c477af83f232c32a5daa9e7 |
>| C:\Windows\system32\win32k.sys | true | 436e4df36ac1549d2eb3f8eac53df074 |
>| C:\Windows\system32\drivers\rdpbus.sys | true | d1edd6604ed1a6e2bc45134c307d3e82 |
>| C:\Windows\system32\drivers\hidparse.sys | true | d9a8063a2c30bd2f4815d973d9711d22 |
>| C:\Windows\system32\drivers\monitor.sys | true | b8f452f5baa586406a190c647c1443e4 |
>| C:\Windows\system32\drivers\wcifs.sys | true | f6eac3ea92f216a48495ea0fe645dcbf |
>| C:\Windows\system32\drivers\storqosflt.sys | true | 966997d2b3ebe8ea30ec42101dbe5768 |
>| C:\Windows\system32\drivers\dxgmms2.sys | true | 98ce225ae17a6d67ae1e5d2869fdf7f7 |
>| C:\Windows\system32\cdd.dll | true | 1c12e169adb6dc8b3cedc0a09bd1188f |
>| C:\Windows\system32\drivers\cldflt.sys | true | ce5e59e0b763ec8495c9a623519d55ee |
>| C:\Windows\system32\drivers\rdpvideominiport.sys | true | 26fa006e8dc780d58158f58cf11fe3a3 |
>| C:\Windows\system32\drivers\mrxsmb.sys | true | b0186ea7f1979d9f02da0ae11542d39d |
>| C:\Windows\system32\drivers\msquic.sys | true | afb57e498cd26284e9603353fb9104ad |
>| C:\Windows\system32\drivers\mslldp.sys | true | d69790cc30e3717431067b1a43a679f1 |
>| C:\Windows\system32\drivers\bowser.sys | true | 1349bea208c0f48534cfde0e8a64c3a4 |
>| C:\Windows\system32\drivers\lltdio.sys | true | 38c53c38731190ba73b39cbd3befe14a |
>| C:\Windows\system32\drivers\bindflt.sys | true | 103737c5c139bfa688ea52c3f1fdf8cc |
>| C:\Windows\system32\drivers\rdpdr.sys | true | e63147974f4fc014742c5471c7bc516d |
>| C:\Windows\system32\drivers\http.sys | true | 0db27d34c898a592dcf7e4a5eeacc2be |
>| C:\Windows\system32\drivers\srvnet.sys | true | fdfcf9c6d6bec82925b2e52926acbbb2 |
>| C:\Windows\system32\drivers\mrxsmb20.sys | true | 40f91604967e771021b89a54ddb74131 |
>| C:\Windows\system32\drivers\peauth.sys | true | e8789b5f24aa80994be1e2b27992af7c |
>| C:\Windows\system32\drivers\srv2.sys | true | ccfe129cbdea8b8c6051d11c6c694230 |
>| C:\Windows\system32\drivers\rspndr.sys | true | e66e50a0a3344a377838ef8b965a7f88 |
>| C:\Windows\system32\drivers\mpsdrv.sys | true | fb4d94870b1f42d93feb8a85b590fd4a |
>| c:\programdata\microsoft\windows defender\definition updates\{265c6876-acfd-4597-b853-b3e54112bc77}\mpksldrv.sys | true | 6f2f14025a606b924e77ad29aa68d231 |
>| C:\Windows\system32\drivers\hlprotect.sys | true | 44480d8a012a7249bc390cbcdb687fee |
>| C:\Windows\system32\drivers\tcpipreg.sys | true | 6a7338ae6e83bf75f2057b7b1242f81b |
>| C:\Windows\system32\drivers\condrv.sys | true | 122c522158f2499cee46e1d2e2b59787 |
>| C:\Windows\system32\drivers\mmcss.sys | true | a10c637165ab63671f5ea554109d008c |
>| C:\Windows\system32\drivers\terminpt.sys | true | a073581102fca9e17a1a4a5a40542d5c |


### harfanglab-result-servicelist
***
Get a hostname's list of services from job results


#### Base Command

`harfanglab-result-servicelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Service.data | unknown | Provides a list of services | 

#### Command example
```!harfanglab-result-servicelist job_id="bde92340-27da-4009-b310-5b7fa6e4fcb9"```
#### Context Example
```json
{
    "Harfanglab": {
        "Service": {
            "data": [
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\1394ohci.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\1394ohci.sys",
                    "md5": "809badbedd63ae4481fd65b8b20e8c0b",
                    "name": "1394ohci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\1394ohci.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\1394ohci.sys",
                    "md5": "809badbedd63ae4481fd65b8b20e8c0b",
                    "name": "1394ohci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\3ware.sys",
                    "image path": "System32\\drivers\\3ware.sys",
                    "md5": "0652580a777f9d77aa409d8595cec672",
                    "name": "3ware",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\3ware.sys",
                    "image path": "System32\\drivers\\3ware.sys",
                    "md5": "0652580a777f9d77aa409d8595cec672",
                    "name": "3ware",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ACPI.sys",
                    "image path": "System32\\drivers\\ACPI.sys",
                    "md5": "128242662d8f677e8d243dffe4c30acf",
                    "name": "ACPI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ACPI.sys",
                    "image path": "System32\\drivers\\ACPI.sys",
                    "md5": "128242662d8f677e8d243dffe4c30acf",
                    "name": "ACPI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\AcpiDev.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\AcpiDev.sys",
                    "md5": "ac827e39be44984a28abc64b44b47445",
                    "name": "AcpiDev",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\AcpiDev.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\AcpiDev.sys",
                    "md5": "ac827e39be44984a28abc64b44b47445",
                    "name": "AcpiDev",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\acpiex.sys",
                    "image path": "System32\\Drivers\\acpiex.sys",
                    "md5": "0c2a19fce98cd5279174f70ecde10173",
                    "name": "acpiex",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\acpiex.sys",
                    "image path": "System32\\Drivers\\acpiex.sys",
                    "md5": "0c2a19fce98cd5279174f70ecde10173",
                    "name": "acpiex",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\acpipagr.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\acpipagr.sys",
                    "md5": "e54826c72c231c0f0b57f8a35c03ff3e",
                    "name": "acpipagr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\acpipagr.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\acpipagr.sys",
                    "md5": "e54826c72c231c0f0b57f8a35c03ff3e",
                    "name": "acpipagr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\acpipmi.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\acpipmi.sys",
                    "md5": "9a5be6df3e4d08085dbc375ec8c66dc4",
                    "name": "AcpiPmi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\acpipmi.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\acpipmi.sys",
                    "md5": "9a5be6df3e4d08085dbc375ec8c66dc4",
                    "name": "AcpiPmi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\acpitime.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\acpitime.sys",
                    "md5": "30569a8e79bfa28f4a1d379aac7f6dd7",
                    "name": "acpitime",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\acpitime.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\acpitime.sys",
                    "md5": "30569a8e79bfa28f4a1d379aac7f6dd7",
                    "name": "acpitime",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Acx01000.sys",
                    "image path": "system32\\drivers\\Acx01000.sys",
                    "md5": "45289ee0c340c884ab5a432239e56d18",
                    "name": "Acx01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Acx01000.sys",
                    "image path": "system32\\drivers\\Acx01000.sys",
                    "md5": "45289ee0c340c884ab5a432239e56d18",
                    "name": "Acx01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ADP80XX.SYS",
                    "image path": "System32\\drivers\\ADP80XX.SYS",
                    "md5": "26bf7d01ddb616801aaeed81f0b74b5a",
                    "name": "ADP80XX",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ADP80XX.SYS",
                    "image path": "System32\\drivers\\ADP80XX.SYS",
                    "md5": "26bf7d01ddb616801aaeed81f0b74b5a",
                    "name": "ADP80XX",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\afd.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\afd.sys",
                    "md5": "d5e687f3cb3f33b2554037332c7ffd26",
                    "name": "AFD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\afd.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\afd.sys",
                    "md5": "d5e687f3cb3f33b2554037332c7ffd26",
                    "name": "AFD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\afunix.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\afunix.sys",
                    "md5": "6904a360dcc3b90a798cde109f25ebb4",
                    "name": "afunix",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\afunix.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\afunix.sys",
                    "md5": "6904a360dcc3b90a798cde109f25ebb4",
                    "name": "afunix",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\ahcache.sys",
                    "image path": "system32\\DRIVERS\\ahcache.sys",
                    "md5": "bfb562fd6102dc1729425c4c3cd450e5",
                    "name": "ahcache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\ahcache.sys",
                    "image path": "system32\\DRIVERS\\ahcache.sys",
                    "md5": "bfb562fd6102dc1729425c4c3cd450e5",
                    "name": "ahcache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AJRouter.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "95c2151b641d69e806875acb9e3cf46a",
                    "name": "AJRouter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AJRouter.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "95c2151b641d69e806875acb9e3cf46a",
                    "name": "AJRouter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AJRouter.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "95c2151b641d69e806875acb9e3cf46a",
                    "name": "AJRouter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AJRouter.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "95c2151b641d69e806875acb9e3cf46a",
                    "name": "AJRouter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\alg.exe",
                    "image path": "%SystemRoot%\\System32\\alg.exe",
                    "md5": "bf20fbc998d67d196b21a951f4c3ba9a",
                    "name": "ALG",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\alg.exe",
                    "image path": "%SystemRoot%\\System32\\alg.exe",
                    "md5": "bf20fbc998d67d196b21a951f4c3ba9a",
                    "name": "ALG",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdk8.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\amdk8.sys",
                    "md5": "4124fd31125a390e52ad3fbde3e6dc63",
                    "name": "AmdK8",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdk8.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\amdk8.sys",
                    "md5": "4124fd31125a390e52ad3fbde3e6dc63",
                    "name": "AmdK8",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdppm.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\amdppm.sys",
                    "md5": "a90de2c3047883852bd455c12b0d3a0b",
                    "name": "AmdPPM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdppm.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\amdppm.sys",
                    "md5": "a90de2c3047883852bd455c12b0d3a0b",
                    "name": "AmdPPM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdsata.sys",
                    "image path": "System32\\drivers\\amdsata.sys",
                    "md5": "9ded5d39490578561a1af091c3253204",
                    "name": "amdsata",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdsata.sys",
                    "image path": "System32\\drivers\\amdsata.sys",
                    "md5": "9ded5d39490578561a1af091c3253204",
                    "name": "amdsata",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdsbs.sys",
                    "image path": "System32\\drivers\\amdsbs.sys",
                    "md5": "535bca23d988239781f218e9c707231a",
                    "name": "amdsbs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdsbs.sys",
                    "image path": "System32\\drivers\\amdsbs.sys",
                    "md5": "535bca23d988239781f218e9c707231a",
                    "name": "amdsbs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdxata.sys",
                    "image path": "System32\\drivers\\amdxata.sys",
                    "md5": "e532e6c9e1fbbed2a40763344bf9e1de",
                    "name": "amdxata",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\amdxata.sys",
                    "image path": "System32\\drivers\\amdxata.sys",
                    "md5": "e532e6c9e1fbbed2a40763344bf9e1de",
                    "name": "amdxata",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\appid.sys",
                    "image path": "system32\\drivers\\appid.sys",
                    "md5": "cc79ce5e95defbeeea8102c6899ffcdf",
                    "name": "AppID",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\appid.sys",
                    "image path": "system32\\drivers\\appid.sys",
                    "md5": "cc79ce5e95defbeeea8102c6899ffcdf",
                    "name": "AppID",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appidsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "be4af469abb640df55d71dba13e24671",
                    "name": "AppIDSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appidsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "be4af469abb640df55d71dba13e24671",
                    "name": "AppIDSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appidsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "be4af469abb640df55d71dba13e24671",
                    "name": "AppIDSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appidsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "be4af469abb640df55d71dba13e24671",
                    "name": "AppIDSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appinfo.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "022553a710d37a8d325c816d0f5eff64",
                    "name": "Appinfo",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appinfo.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "022553a710d37a8d325c816d0f5eff64",
                    "name": "Appinfo",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appinfo.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "022553a710d37a8d325c816d0f5eff64",
                    "name": "Appinfo",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appinfo.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "022553a710d37a8d325c816d0f5eff64",
                    "name": "Appinfo",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\applockerfltr.sys",
                    "image path": "system32\\drivers\\applockerfltr.sys",
                    "md5": "27395a50e249c327f9181f28b34d5b97",
                    "name": "applockerfltr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\applockerfltr.sys",
                    "image path": "system32\\drivers\\applockerfltr.sys",
                    "md5": "27395a50e249c327f9181f28b34d5b97",
                    "name": "applockerfltr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appmgmts.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c187194b6c210dfa3dea72fb7fff42da",
                    "name": "AppMgmt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appmgmts.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c187194b6c210dfa3dea72fb7fff42da",
                    "name": "AppMgmt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appmgmts.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c187194b6c210dfa3dea72fb7fff42da",
                    "name": "AppMgmt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\appmgmts.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c187194b6c210dfa3dea72fb7fff42da",
                    "name": "AppMgmt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\AppReadiness.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k AppReadiness -p",
                    "md5": "d2fce34f153075778b336e1718f5d2fd",
                    "name": "AppReadiness",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\AppReadiness.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k AppReadiness -p",
                    "md5": "d2fce34f153075778b336e1718f5d2fd",
                    "name": "AppReadiness",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\AppReadiness.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k AppReadiness -p",
                    "md5": "d2fce34f153075778b336e1718f5d2fd",
                    "name": "AppReadiness",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\AppReadiness.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k AppReadiness -p",
                    "md5": "d2fce34f153075778b336e1718f5d2fd",
                    "name": "AppReadiness",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\AppVClient.exe",
                    "image path": "%systemroot%\\system32\\AppVClient.exe",
                    "md5": "54e6f67c5a25c8e7e8279a365bfe4001",
                    "name": "AppVClient",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\AppVClient.exe",
                    "image path": "%systemroot%\\system32\\AppVClient.exe",
                    "md5": "54e6f67c5a25c8e7e8279a365bfe4001",
                    "name": "AppVClient",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\AppvStrm.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\AppvStrm.sys",
                    "md5": "cc9c25fe3f296aff4623d80f7bf90f6c",
                    "name": "AppvStrm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\AppvStrm.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\AppvStrm.sys",
                    "md5": "cc9c25fe3f296aff4623d80f7bf90f6c",
                    "name": "AppvStrm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\AppvVemgr.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\AppvVemgr.sys",
                    "md5": "28dcd2b10a012b306348c4224b264ece",
                    "name": "AppvVemgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\AppvVemgr.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\AppvVemgr.sys",
                    "md5": "28dcd2b10a012b306348c4224b264ece",
                    "name": "AppvVemgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\AppvVfs.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\AppvVfs.sys",
                    "md5": "2df6f014ddb6650001ff5c3993c5edc5",
                    "name": "AppvVfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\AppvVfs.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\AppvVfs.sys",
                    "md5": "2df6f014ddb6650001ff5c3993c5edc5",
                    "name": "AppvVfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\appxdeploymentserver.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k wsappx -p",
                    "md5": "68b0a9600676c84b74e9169bbbcf3e8d",
                    "name": "AppXSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\appxdeploymentserver.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k wsappx -p",
                    "md5": "68b0a9600676c84b74e9169bbbcf3e8d",
                    "name": "AppXSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\appxdeploymentserver.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k wsappx -p",
                    "md5": "68b0a9600676c84b74e9169bbbcf3e8d",
                    "name": "AppXSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\appxdeploymentserver.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k wsappx -p",
                    "md5": "68b0a9600676c84b74e9169bbbcf3e8d",
                    "name": "AppXSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\arcsas.sys",
                    "image path": "System32\\drivers\\arcsas.sys",
                    "md5": "03c1542e64ef3d3192fb5fd148184a9a",
                    "name": "arcsas",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\arcsas.sys",
                    "image path": "System32\\drivers\\arcsas.sys",
                    "md5": "03c1542e64ef3d3192fb5fd148184a9a",
                    "name": "arcsas",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\asyncmac.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\asyncmac.sys",
                    "md5": "8dac2ef58ef9c47c1632414c10af9c19",
                    "name": "AsyncMac",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\asyncmac.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\asyncmac.sys",
                    "md5": "8dac2ef58ef9c47c1632414c10af9c19",
                    "name": "AsyncMac",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\atapi.sys",
                    "image path": "System32\\drivers\\atapi.sys",
                    "md5": "6db20deaa154aee9122d8aee5541f5c7",
                    "name": "atapi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\atapi.sys",
                    "image path": "System32\\drivers\\atapi.sys",
                    "md5": "6db20deaa154aee9122d8aee5541f5c7",
                    "name": "atapi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AudioEndpointBuilder.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7d60dea45f3edf1798fa78176a4a9257",
                    "name": "AudioEndpointBuilder",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AudioEndpointBuilder.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7d60dea45f3edf1798fa78176a4a9257",
                    "name": "AudioEndpointBuilder",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AudioEndpointBuilder.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7d60dea45f3edf1798fa78176a4a9257",
                    "name": "AudioEndpointBuilder",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AudioEndpointBuilder.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7d60dea45f3edf1798fa78176a4a9257",
                    "name": "AudioEndpointBuilder",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Audiosrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "a792252e252e924e93ddb1c90504b440",
                    "name": "Audiosrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Audiosrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "a792252e252e924e93ddb1c90504b440",
                    "name": "Audiosrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Audiosrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "a792252e252e924e93ddb1c90504b440",
                    "name": "Audiosrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Audiosrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "a792252e252e924e93ddb1c90504b440",
                    "name": "Audiosrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AxInstSV.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k AxInstSVGroup",
                    "md5": "c5838db8400a47b0dbf2bfc56c1f83d0",
                    "name": "AxInstSV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AxInstSV.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k AxInstSVGroup",
                    "md5": "c5838db8400a47b0dbf2bfc56c1f83d0",
                    "name": "AxInstSV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AxInstSV.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k AxInstSVGroup",
                    "md5": "c5838db8400a47b0dbf2bfc56c1f83d0",
                    "name": "AxInstSV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\AxInstSV.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k AxInstSVGroup",
                    "md5": "c5838db8400a47b0dbf2bfc56c1f83d0",
                    "name": "AxInstSV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bxvbda.sys",
                    "image path": "System32\\drivers\\bxvbda.sys",
                    "md5": "5f70154f68d4e19657a4424f8a17117e",
                    "name": "b06bdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bxvbda.sys",
                    "image path": "System32\\drivers\\bxvbda.sys",
                    "md5": "5f70154f68d4e19657a4424f8a17117e",
                    "name": "b06bdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\bam.sys",
                    "image path": "system32\\drivers\\bam.sys",
                    "md5": "41f732bba9521ceb0c834d2b3fbb5090",
                    "name": "bam",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\bam.sys",
                    "image path": "system32\\drivers\\bam.sys",
                    "md5": "41f732bba9521ceb0c834d2b3fbb5090",
                    "name": "bam",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\basicdisplay.inf_amd64_7e9cb61920ccc040\\BasicDisplay.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicdisplay.inf_amd64_7e9cb61920ccc040\\BasicDisplay.sys",
                    "md5": "9e94d724c1dc4cca719be07eb1020dee",
                    "name": "BasicDisplay",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\basicdisplay.inf_amd64_7e9cb61920ccc040\\BasicDisplay.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicdisplay.inf_amd64_7e9cb61920ccc040\\BasicDisplay.sys",
                    "md5": "9e94d724c1dc4cca719be07eb1020dee",
                    "name": "BasicDisplay",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\basicrender.inf_amd64_1c03174c7c755975\\BasicRender.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicrender.inf_amd64_1c03174c7c755975\\BasicRender.sys",
                    "md5": "5e1ea96e7fd6ac5d1ba7c56e4b33e100",
                    "name": "BasicRender",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\basicrender.inf_amd64_1c03174c7c755975\\BasicRender.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicrender.inf_amd64_1c03174c7c755975\\BasicRender.sys",
                    "md5": "5e1ea96e7fd6ac5d1ba7c56e4b33e100",
                    "name": "BasicRender",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Beep.sys",
                    "image path": null,
                    "md5": "270b275b8571d164aa5740b84d28fae8",
                    "name": "Beep",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Beep.sys",
                    "image path": null,
                    "md5": "270b275b8571d164aa5740b84d28fae8",
                    "name": "Beep",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bfadfcoei.sys",
                    "image path": "System32\\drivers\\bfadfcoei.sys",
                    "md5": "2d0a6656ab9996adf09fc919c88cefad",
                    "name": "bfadfcoei",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bfadfcoei.sys",
                    "image path": "System32\\drivers\\bfadfcoei.sys",
                    "md5": "2d0a6656ab9996adf09fc919c88cefad",
                    "name": "bfadfcoei",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bfadi.sys",
                    "image path": "System32\\drivers\\bfadi.sys",
                    "md5": "48c92680c29fa71ea828b33b45ff3fc4",
                    "name": "bfadi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bfadi.sys",
                    "image path": "System32\\drivers\\bfadi.sys",
                    "md5": "48c92680c29fa71ea828b33b45ff3fc4",
                    "name": "bfadi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\bfe.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "md5": "d75dd70a73a7c16052f9e4b794a72342",
                    "name": "BFE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\bfe.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "md5": "d75dd70a73a7c16052f9e4b794a72342",
                    "name": "BFE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\bfe.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "md5": "d75dd70a73a7c16052f9e4b794a72342",
                    "name": "BFE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\bfe.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "md5": "d75dd70a73a7c16052f9e4b794a72342",
                    "name": "BFE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\bindflt.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\bindflt.sys",
                    "md5": "103737c5c139bfa688ea52c3f1fdf8cc",
                    "name": "bindflt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\bindflt.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\bindflt.sys",
                    "md5": "103737c5c139bfa688ea52c3f1fdf8cc",
                    "name": "bindflt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\qmgr.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "281d188a2bbdad9362f95c280beb5b3c",
                    "name": "BITS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\qmgr.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "281d188a2bbdad9362f95c280beb5b3c",
                    "name": "BITS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\qmgr.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "281d188a2bbdad9362f95c280beb5b3c",
                    "name": "BITS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\qmgr.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "281d188a2bbdad9362f95c280beb5b3c",
                    "name": "BITS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\bowser.sys",
                    "image path": "system32\\DRIVERS\\bowser.sys",
                    "md5": "1349bea208c0f48534cfde0e8a64c3a4",
                    "name": "bowser",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\bowser.sys",
                    "image path": "system32\\DRIVERS\\bowser.sys",
                    "md5": "1349bea208c0f48534cfde0e8a64c3a4",
                    "name": "bowser",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\psmsrv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "bc4b6649d990be50025e7d0fd224d37d",
                    "name": "BrokerInfrastructure",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\psmsrv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "bc4b6649d990be50025e7d0fd224d37d",
                    "name": "BrokerInfrastructure",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\psmsrv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "bc4b6649d990be50025e7d0fd224d37d",
                    "name": "BrokerInfrastructure",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\psmsrv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "bc4b6649d990be50025e7d0fd224d37d",
                    "name": "BrokerInfrastructure",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\BthEnum.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\BthEnum.sys",
                    "md5": "09ddb44199f1625e8a6ea521c7e9a478",
                    "name": "BthEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\BthEnum.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\BthEnum.sys",
                    "md5": "09ddb44199f1625e8a6ea521c7e9a478",
                    "name": "BthEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\Microsoft.Bluetooth.Legacy.LEEnumerator.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\Microsoft.Bluetooth.Legacy.LEEnumerator.sys",
                    "md5": "c899a971a3bb2cdda438cb642053cad6",
                    "name": "BthLEEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\Microsoft.Bluetooth.Legacy.LEEnumerator.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\Microsoft.Bluetooth.Legacy.LEEnumerator.sys",
                    "md5": "c899a971a3bb2cdda438cb642053cad6",
                    "name": "BthLEEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\BTHMINI.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\BTHMINI.sys",
                    "md5": "10d4fed3a2e82b12304927083290e3ce",
                    "name": "BthMini",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\BTHMINI.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\BTHMINI.sys",
                    "md5": "10d4fed3a2e82b12304927083290e3ce",
                    "name": "BthMini",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\BTHport.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\BTHport.sys",
                    "md5": "1547b7ad9addee1663506948b024b51f",
                    "name": "BTHPORT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\BTHport.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\BTHport.sys",
                    "md5": "1547b7ad9addee1663506948b024b51f",
                    "name": "BTHPORT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\bthserv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "3606a16f0a4f4f0ba40e03841b1fbc9c",
                    "name": "bthserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\bthserv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "3606a16f0a4f4f0ba40e03841b1fbc9c",
                    "name": "bthserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\bthserv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "3606a16f0a4f4f0ba40e03841b1fbc9c",
                    "name": "bthserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\bthserv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "3606a16f0a4f4f0ba40e03841b1fbc9c",
                    "name": "bthserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\BTHUSB.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\BTHUSB.sys",
                    "md5": "46a773faa4bfe55844aa76a4e69e64dd",
                    "name": "BTHUSB",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\BTHUSB.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\BTHUSB.sys",
                    "md5": "46a773faa4bfe55844aa76a4e69e64dd",
                    "name": "BTHUSB",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bttflt.sys",
                    "image path": "System32\\drivers\\bttflt.sys",
                    "md5": "2d9693d57bfa0a2c8d11b3e10a48dc70",
                    "name": "bttflt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bttflt.sys",
                    "image path": "System32\\drivers\\bttflt.sys",
                    "md5": "2d9693d57bfa0a2c8d11b3e10a48dc70",
                    "name": "bttflt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\buttonconverter.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\buttonconverter.sys",
                    "md5": "be71bd2984ec4ae37b1ea1cb99609726",
                    "name": "buttonconverter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\buttonconverter.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\buttonconverter.sys",
                    "md5": "be71bd2984ec4ae37b1ea1cb99609726",
                    "name": "buttonconverter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bxfcoe.sys",
                    "image path": "System32\\drivers\\bxfcoe.sys",
                    "md5": "7f01a40445b05531accf186859dd2dfb",
                    "name": "bxfcoe",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bxfcoe.sys",
                    "image path": "System32\\drivers\\bxfcoe.sys",
                    "md5": "7f01a40445b05531accf186859dd2dfb",
                    "name": "bxfcoe",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bxois.sys",
                    "image path": "System32\\drivers\\bxois.sys",
                    "md5": "64446c440de1ae190781652f3a839b76",
                    "name": "bxois",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bxois.sys",
                    "image path": "System32\\drivers\\bxois.sys",
                    "md5": "64446c440de1ae190781652f3a839b76",
                    "name": "bxois",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\CapabilityAccessManager.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "bb760be2ee24202eda8aa95ea3f19187",
                    "name": "camsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\CapabilityAccessManager.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "bb760be2ee24202eda8aa95ea3f19187",
                    "name": "camsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\CapabilityAccessManager.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "bb760be2ee24202eda8aa95ea3f19187",
                    "name": "camsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\CapabilityAccessManager.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "bb760be2ee24202eda8aa95ea3f19187",
                    "name": "camsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CaptureService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "d310d5c17e7da85a9de3de89dd2bfbe1",
                    "name": "CaptureService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CaptureService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "d310d5c17e7da85a9de3de89dd2bfbe1",
                    "name": "CaptureService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CaptureService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "d310d5c17e7da85a9de3de89dd2bfbe1",
                    "name": "CaptureService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CaptureService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "d310d5c17e7da85a9de3de89dd2bfbe1",
                    "name": "CaptureService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k LocalService -p",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "CaptureService_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cbdhsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k ClipboardSvcGroup -p",
                    "md5": "b99920e79fdea57e927be2afa11a1a6c",
                    "name": "cbdhsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cbdhsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k ClipboardSvcGroup -p",
                    "md5": "b99920e79fdea57e927be2afa11a1a6c",
                    "name": "cbdhsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cbdhsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k ClipboardSvcGroup -p",
                    "md5": "b99920e79fdea57e927be2afa11a1a6c",
                    "name": "cbdhsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cbdhsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k ClipboardSvcGroup -p",
                    "md5": "b99920e79fdea57e927be2afa11a1a6c",
                    "name": "cbdhsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k ClipboardSvcGroup -p",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "cbdhsvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\cdfs.sys",
                    "image path": "system32\\DRIVERS\\cdfs.sys",
                    "md5": "1fc91edd3318f27f89f7d8b933027e3b",
                    "name": "cdfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\cdfs.sys",
                    "image path": "system32\\DRIVERS\\cdfs.sys",
                    "md5": "1fc91edd3318f27f89f7d8b933027e3b",
                    "name": "cdfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CDPSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "109fe085df395e6a011520c9620b4168",
                    "name": "CDPSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CDPSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "109fe085df395e6a011520c9620b4168",
                    "name": "CDPSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CDPSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "109fe085df395e6a011520c9620b4168",
                    "name": "CDPSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CDPSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "109fe085df395e6a011520c9620b4168",
                    "name": "CDPSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CDPUserSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "3df347c5c82f7ffc7866f093355be573",
                    "name": "CDPUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CDPUserSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "3df347c5c82f7ffc7866f093355be573",
                    "name": "CDPUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CDPUserSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "3df347c5c82f7ffc7866f093355be573",
                    "name": "CDPUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\CDPUserSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "3df347c5c82f7ffc7866f093355be573",
                    "name": "CDPUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "CDPUserSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\cdrom.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\cdrom.sys",
                    "md5": "f8598f378ec752af85fa3f642a870906",
                    "name": "cdrom",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\cdrom.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\cdrom.sys",
                    "md5": "f8598f378ec752af85fa3f642a870906",
                    "name": "cdrom",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\certprop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs",
                    "md5": "b4032b436f4ff0cc8f160a1f9f57de43",
                    "name": "CertPropSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\certprop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs",
                    "md5": "b4032b436f4ff0cc8f160a1f9f57de43",
                    "name": "CertPropSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\certprop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs",
                    "md5": "b4032b436f4ff0cc8f160a1f9f57de43",
                    "name": "CertPropSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\certprop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs",
                    "md5": "b4032b436f4ff0cc8f160a1f9f57de43",
                    "name": "CertPropSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\cht4sx64.sys",
                    "image path": "System32\\drivers\\cht4sx64.sys",
                    "md5": "1ebe9210bda30f1a102448d636af4afc",
                    "name": "cht4iscsi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\cht4sx64.sys",
                    "image path": "System32\\drivers\\cht4sx64.sys",
                    "md5": "1ebe9210bda30f1a102448d636af4afc",
                    "name": "cht4iscsi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\cht4vx64.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\cht4vx64.sys",
                    "md5": "317534412235dc97d73a912174dc7a8e",
                    "name": "cht4vbd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\cht4vx64.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\cht4vx64.sys",
                    "md5": "317534412235dc97d73a912174dc7a8e",
                    "name": "cht4vbd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\CimFS.sys",
                    "image path": null,
                    "md5": "c77761c2f092d133329ffa7e5756c216",
                    "name": "CimFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\CimFS.sys",
                    "image path": null,
                    "md5": "c77761c2f092d133329ffa7e5756c216",
                    "name": "CimFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cldflt.sys",
                    "image path": "system32\\drivers\\cldflt.sys",
                    "md5": "ce5e59e0b763ec8495c9a623519d55ee",
                    "name": "CldFlt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\cldflt.sys",
                    "image path": "system32\\drivers\\cldflt.sys",
                    "md5": "ce5e59e0b763ec8495c9a623519d55ee",
                    "name": "CldFlt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\CLFS.sys",
                    "image path": "System32\\drivers\\CLFS.sys",
                    "md5": "e1276c5405944c290a27c9c5544e8318",
                    "name": "CLFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\CLFS.sys",
                    "image path": "System32\\drivers\\CLFS.sys",
                    "md5": "e1276c5405944c290a27c9c5544e8318",
                    "name": "CLFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ClipSVC.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k wsappx -p",
                    "md5": "0daef1ac909e5bac136c6405e08822e3",
                    "name": "ClipSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ClipSVC.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k wsappx -p",
                    "md5": "0daef1ac909e5bac136c6405e08822e3",
                    "name": "ClipSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ClipSVC.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k wsappx -p",
                    "md5": "0daef1ac909e5bac136c6405e08822e3",
                    "name": "ClipSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ClipSVC.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k wsappx -p",
                    "md5": "0daef1ac909e5bac136c6405e08822e3",
                    "name": "ClipSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\CmBatt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\CmBatt.sys",
                    "md5": "bff879e5bb87092532be8229528c2100",
                    "name": "CmBatt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\CmBatt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\CmBatt.sys",
                    "md5": "bff879e5bb87092532be8229528c2100",
                    "name": "CmBatt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\cng.sys",
                    "image path": "System32\\Drivers\\cng.sys",
                    "md5": "395e313507ca049e185ea3f6356fefdb",
                    "name": "CNG",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\cng.sys",
                    "image path": "System32\\Drivers\\cng.sys",
                    "md5": "395e313507ca049e185ea3f6356fefdb",
                    "name": "CNG",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\cnghwassist.sys",
                    "image path": "System32\\DRIVERS\\cnghwassist.sys",
                    "md5": "7205b61c138ec4ba872eca13e29fb36d",
                    "name": "cnghwassist",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\cnghwassist.sys",
                    "image path": "System32\\DRIVERS\\cnghwassist.sys",
                    "md5": "7205b61c138ec4ba872eca13e29fb36d",
                    "name": "cnghwassist",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\compositebus.inf_amd64_130dea07a2ae55eb\\CompositeBus.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\compositebus.inf_amd64_130dea07a2ae55eb\\CompositeBus.sys",
                    "md5": "564ac50963890f9b3ab0052c249dbc21",
                    "name": "CompositeBus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\compositebus.inf_amd64_130dea07a2ae55eb\\CompositeBus.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\compositebus.inf_amd64_130dea07a2ae55eb\\CompositeBus.sys",
                    "md5": "564ac50963890f9b3ab0052c249dbc21",
                    "name": "CompositeBus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dllhost.exe",
                    "image path": "%SystemRoot%\\system32\\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}",
                    "md5": "61b7ccf84d2b4251bd263e75cd103f89",
                    "name": "COMSysApp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dllhost.exe",
                    "image path": "%SystemRoot%\\system32\\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}",
                    "md5": "61b7ccf84d2b4251bd263e75cd103f89",
                    "name": "COMSysApp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\condrv.sys",
                    "image path": "System32\\drivers\\condrv.sys",
                    "md5": "122c522158f2499cee46e1d2e2b59787",
                    "name": "condrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\condrv.sys",
                    "image path": "System32\\drivers\\condrv.sys",
                    "md5": "122c522158f2499cee46e1d2e2b59787",
                    "name": "condrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ConsentUxClient.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "8af78007b67e0864abbd5122f4e74965",
                    "name": "ConsentUxUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ConsentUxClient.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "8af78007b67e0864abbd5122f4e74965",
                    "name": "ConsentUxUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ConsentUxClient.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "8af78007b67e0864abbd5122f4e74965",
                    "name": "ConsentUxUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ConsentUxClient.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "8af78007b67e0864abbd5122f4e74965",
                    "name": "ConsentUxUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "ConsentUxUserSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\coremessaging.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "fb8f3e75fe5456e96bf4d3208f2a224e",
                    "name": "CoreMessagingRegistrar",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\coremessaging.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "fb8f3e75fe5456e96bf4d3208f2a224e",
                    "name": "CoreMessagingRegistrar",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\coremessaging.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "fb8f3e75fe5456e96bf4d3208f2a224e",
                    "name": "CoreMessagingRegistrar",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\coremessaging.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "fb8f3e75fe5456e96bf4d3208f2a224e",
                    "name": "CoreMessagingRegistrar",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\CredentialEnrollmentManager.exe",
                    "image path": "%SystemRoot%\\system32\\CredentialEnrollmentManager.exe",
                    "md5": "92353f4f74b12eb0029981f877573ee5",
                    "name": "CredentialEnrollmentManagerUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\CredentialEnrollmentManager.exe",
                    "image path": "%SystemRoot%\\system32\\CredentialEnrollmentManager.exe",
                    "md5": "92353f4f74b12eb0029981f877573ee5",
                    "name": "CredentialEnrollmentManagerUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\CredentialEnrollmentManager.exe",
                    "image path": "C:\\Windows\\system32\\CredentialEnrollmentManager.exe",
                    "md5": "92353f4f74b12eb0029981f877573ee5",
                    "name": "CredentialEnrollmentManagerUserSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cryptsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "319a817f297872b1e9ce67381b23604e",
                    "name": "CryptSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cryptsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "319a817f297872b1e9ce67381b23604e",
                    "name": "CryptSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cryptsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "319a817f297872b1e9ce67381b23604e",
                    "name": "CryptSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\cryptsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "319a817f297872b1e9ce67381b23604e",
                    "name": "CryptSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\csc.sys",
                    "image path": "system32\\drivers\\csc.sys",
                    "md5": "6eb74a585f9f26c263486ec792d7b7a7",
                    "name": "CSC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\csc.sys",
                    "image path": "system32\\drivers\\csc.sys",
                    "md5": "6eb74a585f9f26c263486ec792d7b7a7",
                    "name": "CSC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cscsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "12cd55cfcb592d17155ebd7241627729",
                    "name": "CscService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cscsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "12cd55cfcb592d17155ebd7241627729",
                    "name": "CscService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cscsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "12cd55cfcb592d17155ebd7241627729",
                    "name": "CscService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\cscsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "12cd55cfcb592d17155ebd7241627729",
                    "name": "CscService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\dam.sys",
                    "image path": "system32\\drivers\\dam.sys",
                    "md5": "96f5fff1968b938b4606b1309e0afcaa",
                    "name": "dam",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\dam.sys",
                    "image path": "system32\\drivers\\dam.sys",
                    "md5": "96f5fff1968b938b4606b1309e0afcaa",
                    "name": "dam",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rpcss.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "3c8acb412e1a10b923b18a068f814901",
                    "name": "DcomLaunch",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rpcss.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "3c8acb412e1a10b923b18a068f814901",
                    "name": "DcomLaunch",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rpcss.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "3c8acb412e1a10b923b18a068f814901",
                    "name": "DcomLaunch",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rpcss.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "3c8acb412e1a10b923b18a068f814901",
                    "name": "DcomLaunch",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\defragsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k defragsvc",
                    "md5": "63e0f044bf8e257ddee2cd56734dc925",
                    "name": "defragsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\defragsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k defragsvc",
                    "md5": "63e0f044bf8e257ddee2cd56734dc925",
                    "name": "defragsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\defragsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k defragsvc",
                    "md5": "63e0f044bf8e257ddee2cd56734dc925",
                    "name": "defragsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\defragsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k defragsvc",
                    "md5": "63e0f044bf8e257ddee2cd56734dc925",
                    "name": "defragsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\deviceaccess.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow -p",
                    "md5": "13d7223d89f14c4d20b20bf2fcbfcb87",
                    "name": "DeviceAssociationBrokerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\deviceaccess.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow -p",
                    "md5": "13d7223d89f14c4d20b20bf2fcbfcb87",
                    "name": "DeviceAssociationBrokerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\deviceaccess.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow -p",
                    "md5": "13d7223d89f14c4d20b20bf2fcbfcb87",
                    "name": "DeviceAssociationBrokerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\deviceaccess.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow -p",
                    "md5": "13d7223d89f14c4d20b20bf2fcbfcb87",
                    "name": "DeviceAssociationBrokerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k DevicesFlow -p",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "DeviceAssociationBrokerSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\das.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "0afd8c3095ffdaa1b5c9178d97a23474",
                    "name": "DeviceAssociationService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\das.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "0afd8c3095ffdaa1b5c9178d97a23474",
                    "name": "DeviceAssociationService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\das.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "0afd8c3095ffdaa1b5c9178d97a23474",
                    "name": "DeviceAssociationService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\das.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "0afd8c3095ffdaa1b5c9178d97a23474",
                    "name": "DeviceAssociationService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpnpmgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "5d65d3b568357eb6ead5578a7b045ab2",
                    "name": "DeviceInstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpnpmgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "5d65d3b568357eb6ead5578a7b045ab2",
                    "name": "DeviceInstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpnpmgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "5d65d3b568357eb6ead5578a7b045ab2",
                    "name": "DeviceInstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpnpmgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "5d65d3b568357eb6ead5578a7b045ab2",
                    "name": "DeviceInstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.Devices.Picker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "ca54eb49398fafd4ac3ac697f839a291",
                    "name": "DevicePickerUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.Devices.Picker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "ca54eb49398fafd4ac3ac697f839a291",
                    "name": "DevicePickerUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.Devices.Picker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "ca54eb49398fafd4ac3ac697f839a291",
                    "name": "DevicePickerUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.Devices.Picker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "ca54eb49398fafd4ac3ac697f839a291",
                    "name": "DevicePickerUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "DevicePickerUserSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DevicesFlowBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "3cd95a53dfa873a1f0b4e3a558e7ad6e",
                    "name": "DevicesFlowUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DevicesFlowBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "3cd95a53dfa873a1f0b4e3a558e7ad6e",
                    "name": "DevicesFlowUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DevicesFlowBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "3cd95a53dfa873a1f0b4e3a558e7ad6e",
                    "name": "DevicesFlowUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DevicesFlowBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "3cd95a53dfa873a1f0b4e3a558e7ad6e",
                    "name": "DevicesFlowUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k DevicesFlow",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "DevicesFlowUserSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DevQueryBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "6e36dfc75e2a3f6a1678d0883e17efb5",
                    "name": "DevQueryBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DevQueryBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "6e36dfc75e2a3f6a1678d0883e17efb5",
                    "name": "DevQueryBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DevQueryBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "6e36dfc75e2a3f6a1678d0883e17efb5",
                    "name": "DevQueryBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DevQueryBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "6e36dfc75e2a3f6a1678d0883e17efb5",
                    "name": "DevQueryBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\dfsc.sys",
                    "image path": "System32\\Drivers\\dfsc.sys",
                    "md5": "7317e6235f0f1b1e6fa5a6d2cf9ba724",
                    "name": "Dfsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\dfsc.sys",
                    "image path": "System32\\Drivers\\dfsc.sys",
                    "md5": "7317e6235f0f1b1e6fa5a6d2cf9ba724",
                    "name": "Dfsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dhcpcore.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5be0b037ccdab65bda8a82ba47123dd3",
                    "name": "Dhcp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dhcpcore.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5be0b037ccdab65bda8a82ba47123dd3",
                    "name": "Dhcp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dhcpcore.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5be0b037ccdab65bda8a82ba47123dd3",
                    "name": "Dhcp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dhcpcore.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5be0b037ccdab65bda8a82ba47123dd3",
                    "name": "Dhcp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DiagSvcs\\DiagnosticsHub.StandardCollector.Service.exe",
                    "image path": "%SystemRoot%\\system32\\DiagSvcs\\DiagnosticsHub.StandardCollector.Service.exe",
                    "md5": "d9332f687a3c41d4b75c36344943d124",
                    "name": "diagnosticshub.standardcollector.service",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DiagSvcs\\DiagnosticsHub.StandardCollector.Service.exe",
                    "image path": "%SystemRoot%\\system32\\DiagSvcs\\DiagnosticsHub.StandardCollector.Service.exe",
                    "md5": "d9332f687a3c41d4b75c36344943d124",
                    "name": "diagnosticshub.standardcollector.service",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\diagtrack.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k utcsvc -p",
                    "md5": "53bef47412a8472fbef772e67d12f8ed",
                    "name": "DiagTrack",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\diagtrack.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k utcsvc -p",
                    "md5": "53bef47412a8472fbef772e67d12f8ed",
                    "name": "DiagTrack",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\diagtrack.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k utcsvc -p",
                    "md5": "53bef47412a8472fbef772e67d12f8ed",
                    "name": "DiagTrack",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\diagtrack.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k utcsvc -p",
                    "md5": "53bef47412a8472fbef772e67d12f8ed",
                    "name": "DiagTrack",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\disk.sys",
                    "image path": "System32\\drivers\\disk.sys",
                    "md5": "ba90cfc0d444bb5468fd050073ea5386",
                    "name": "disk",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\disk.sys",
                    "image path": "System32\\drivers\\disk.sys",
                    "md5": "ba90cfc0d444bb5468fd050073ea5386",
                    "name": "disk",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DispBroker.Desktop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "8aa4efdc91c635d684242e95d87f9abf",
                    "name": "DispBrokerDesktopSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DispBroker.Desktop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "8aa4efdc91c635d684242e95d87f9abf",
                    "name": "DispBrokerDesktopSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DispBroker.Desktop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "8aa4efdc91c635d684242e95d87f9abf",
                    "name": "DispBrokerDesktopSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DispBroker.Desktop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "8aa4efdc91c635d684242e95d87f9abf",
                    "name": "DispBrokerDesktopSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Windows.Internal.Management.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "a9a8b6cc80eddd9bfd05ab2c7c87301a",
                    "name": "DmEnrollmentSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Windows.Internal.Management.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "a9a8b6cc80eddd9bfd05ab2c7c87301a",
                    "name": "DmEnrollmentSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Windows.Internal.Management.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "a9a8b6cc80eddd9bfd05ab2c7c87301a",
                    "name": "DmEnrollmentSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Windows.Internal.Management.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "a9a8b6cc80eddd9bfd05ab2c7c87301a",
                    "name": "DmEnrollmentSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\dmvsc.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\dmvsc.sys",
                    "md5": "a6ecaa85c49e2af263a842d3f5fc5624",
                    "name": "dmvsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\dmvsc.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\dmvsc.sys",
                    "md5": "a6ecaa85c49e2af263a842d3f5fc5624",
                    "name": "dmvsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dmwappushsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "e0f1deec69471a3e58ca69cb58401433",
                    "name": "dmwappushservice",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dmwappushsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "e0f1deec69471a3e58ca69cb58401433",
                    "name": "dmwappushservice",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dmwappushsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "e0f1deec69471a3e58ca69cb58401433",
                    "name": "dmwappushservice",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dmwappushsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "e0f1deec69471a3e58ca69cb58401433",
                    "name": "dmwappushservice",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dnsrslvr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "d58839fdbc165737a1ea82bb5a7b07d4",
                    "name": "Dnscache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dnsrslvr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "d58839fdbc165737a1ea82bb5a7b07d4",
                    "name": "Dnscache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dnsrslvr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "d58839fdbc165737a1ea82bb5a7b07d4",
                    "name": "Dnscache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dnsrslvr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "d58839fdbc165737a1ea82bb5a7b07d4",
                    "name": "Dnscache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dosvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "5070aa166b2ca17f568c52308792c92b",
                    "name": "DoSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dosvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "5070aa166b2ca17f568c52308792c92b",
                    "name": "DoSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dosvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "5070aa166b2ca17f568c52308792c92b",
                    "name": "DoSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dosvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "5070aa166b2ca17f568c52308792c92b",
                    "name": "DoSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dot3svc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d538081afd64ba8b8b68c5f57b28c325",
                    "name": "dot3svc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dot3svc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d538081afd64ba8b8b68c5f57b28c325",
                    "name": "dot3svc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dot3svc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d538081afd64ba8b8b68c5f57b28c325",
                    "name": "dot3svc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\dot3svc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d538081afd64ba8b8b68c5f57b28c325",
                    "name": "dot3svc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dps.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "f4d554803c8a632b0fed745d45b227cb",
                    "name": "DPS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dps.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "f4d554803c8a632b0fed745d45b227cb",
                    "name": "DPS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dps.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "f4d554803c8a632b0fed745d45b227cb",
                    "name": "DPS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\dps.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "f4d554803c8a632b0fed745d45b227cb",
                    "name": "DPS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\drmkaud.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\drmkaud.sys",
                    "md5": "aa500840eb057c1ce27e10b225500491",
                    "name": "drmkaud",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\drmkaud.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\drmkaud.sys",
                    "md5": "aa500840eb057c1ce27e10b225500491",
                    "name": "drmkaud",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DeviceSetupManager.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "874678e69a14e93d8f4efe27edc0bd89",
                    "name": "DsmSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DeviceSetupManager.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "874678e69a14e93d8f4efe27edc0bd89",
                    "name": "DsmSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DeviceSetupManager.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "874678e69a14e93d8f4efe27edc0bd89",
                    "name": "DsmSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DeviceSetupManager.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "874678e69a14e93d8f4efe27edc0bd89",
                    "name": "DsmSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DsSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "2643e9b10cb1e0f3d4e1a3c67f7f8fd5",
                    "name": "DsSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DsSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "2643e9b10cb1e0f3d4e1a3c67f7f8fd5",
                    "name": "DsSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DsSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "2643e9b10cb1e0f3d4e1a3c67f7f8fd5",
                    "name": "DsSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DsSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "2643e9b10cb1e0f3d4e1a3c67f7f8fd5",
                    "name": "DsSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\dxgkrnl.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
                    "md5": "2e247733503fa28483e871dba19519b9",
                    "name": "DXGKrnl",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\dxgkrnl.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys",
                    "md5": "2e247733503fa28483e871dba19519b9",
                    "name": "DXGKrnl",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\E1G6032E.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\E1G6032E.sys",
                    "md5": "cced99682127e8582e5f716ece775ef8",
                    "name": "E1G60",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\E1G6032E.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\E1G6032E.sys",
                    "md5": "cced99682127e8582e5f716ece775ef8",
                    "name": "E1G60",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\eapsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "d0e7f0f99ea7d7ce4d5922dfe4d805e0",
                    "name": "EapHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\eapsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "d0e7f0f99ea7d7ce4d5922dfe4d805e0",
                    "name": "EapHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\eapsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "d0e7f0f99ea7d7ce4d5922dfe4d805e0",
                    "name": "EapHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\eapsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "d0e7f0f99ea7d7ce4d5922dfe4d805e0",
                    "name": "EapHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\evbda.sys",
                    "image path": "System32\\drivers\\evbda.sys",
                    "md5": "bf9558be00bf1a6589bcf3a051e6e7ae",
                    "name": "ebdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\evbda.sys",
                    "image path": "System32\\drivers\\evbda.sys",
                    "md5": "bf9558be00bf1a6589bcf3a051e6e7ae",
                    "name": "ebdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\evbd0a.sys",
                    "image path": "System32\\drivers\\evbd0a.sys",
                    "md5": "00efb0977b9f3bf7b4d37ec18f132853",
                    "name": "ebdrv0",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\evbd0a.sys",
                    "image path": "System32\\drivers\\evbd0a.sys",
                    "md5": "00efb0977b9f3bf7b4d37ec18f132853",
                    "name": "ebdrv0",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
                    "image path": "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /svc",
                    "md5": "8661fbb97161096be503cd295aa46409",
                    "name": "edgeupdate",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
                    "image path": "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /svc",
                    "md5": "8661fbb97161096be503cd295aa46409",
                    "name": "edgeupdate",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
                    "image path": "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /medsvc",
                    "md5": "8661fbb97161096be503cd295aa46409",
                    "name": "edgeupdatem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
                    "image path": "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /medsvc",
                    "md5": "8661fbb97161096be503cd295aa46409",
                    "name": "edgeupdatem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\efssvc.dll",
                    "image path": "%SystemRoot%\\System32\\lsass.exe",
                    "md5": "a19b76eb605d8561b85e7db5ea2a4ca6",
                    "name": "EFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\efssvc.dll",
                    "image path": "%SystemRoot%\\System32\\lsass.exe",
                    "md5": "a19b76eb605d8561b85e7db5ea2a4ca6",
                    "name": "EFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\efssvc.dll",
                    "image path": "%SystemRoot%\\System32\\lsass.exe",
                    "md5": "a19b76eb605d8561b85e7db5ea2a4ca6",
                    "name": "EFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\efssvc.dll",
                    "image path": "%SystemRoot%\\System32\\lsass.exe",
                    "md5": "a19b76eb605d8561b85e7db5ea2a4ca6",
                    "name": "EFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\EhStorClass.sys",
                    "image path": "System32\\drivers\\EhStorClass.sys",
                    "md5": "5a27edc058ead20f9b71c440a6f5c764",
                    "name": "EhStorClass",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\EhStorClass.sys",
                    "image path": "System32\\drivers\\EhStorClass.sys",
                    "md5": "5a27edc058ead20f9b71c440a6f5c764",
                    "name": "EhStorClass",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\EhStorTcgDrv.sys",
                    "image path": "System32\\drivers\\EhStorTcgDrv.sys",
                    "md5": "2de507860cba74bb811828d0e4d53ae8",
                    "name": "EhStorTcgDrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\EhStorTcgDrv.sys",
                    "image path": "System32\\drivers\\EhStorTcgDrv.sys",
                    "md5": "2de507860cba74bb811828d0e4d53ae8",
                    "name": "EhStorTcgDrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\elxfcoe.sys",
                    "image path": "System32\\drivers\\elxfcoe.sys",
                    "md5": "f6a339b5b6f9e55607f915da6b9e4bad",
                    "name": "elxfcoe",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\elxfcoe.sys",
                    "image path": "System32\\drivers\\elxfcoe.sys",
                    "md5": "f6a339b5b6f9e55607f915da6b9e4bad",
                    "name": "elxfcoe",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\elxstor.sys",
                    "image path": "System32\\drivers\\elxstor.sys",
                    "md5": "ec43b5be737b419feb64e79b5b761dcb",
                    "name": "elxstor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\elxstor.sys",
                    "image path": "System32\\drivers\\elxstor.sys",
                    "md5": "ec43b5be737b419feb64e79b5b761dcb",
                    "name": "elxstor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\embeddedmodesvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "2e962cf906a5769b81cfd6debed6c628",
                    "name": "embeddedmode",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\embeddedmodesvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "2e962cf906a5769b81cfd6debed6c628",
                    "name": "embeddedmode",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\embeddedmodesvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "2e962cf906a5769b81cfd6debed6c628",
                    "name": "embeddedmode",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\embeddedmodesvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "2e962cf906a5769b81cfd6debed6c628",
                    "name": "embeddedmode",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\EnterpriseAppMgmtSvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "a45ab5d1dd5ec33d9bc8dc2842b6f356",
                    "name": "EntAppSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\EnterpriseAppMgmtSvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "a45ab5d1dd5ec33d9bc8dc2842b6f356",
                    "name": "EntAppSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\EnterpriseAppMgmtSvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "a45ab5d1dd5ec33d9bc8dc2842b6f356",
                    "name": "EntAppSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\EnterpriseAppMgmtSvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "a45ab5d1dd5ec33d9bc8dc2842b6f356",
                    "name": "EntAppSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\errdev.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\errdev.sys",
                    "md5": "1de1972ed980f41a9c9a9c09f51e2a59",
                    "name": "ErrDev",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\errdev.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\errdev.sys",
                    "md5": "1de1972ed980f41a9c9a9c09f51e2a59",
                    "name": "ErrDev",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wevtsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "3e2a77f5201f5dc3f39e132bb47e64f6",
                    "name": "EventLog",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wevtsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "3e2a77f5201f5dc3f39e132bb47e64f6",
                    "name": "EventLog",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wevtsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "3e2a77f5201f5dc3f39e132bb47e64f6",
                    "name": "EventLog",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wevtsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "3e2a77f5201f5dc3f39e132bb47e64f6",
                    "name": "EventLog",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\es.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "67abe57f98be8fca9b1c18a1f74382c4",
                    "name": "EventSystem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\es.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "67abe57f98be8fca9b1c18a1f74382c4",
                    "name": "EventSystem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\es.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "67abe57f98be8fca9b1c18a1f74382c4",
                    "name": "EventSystem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\es.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "67abe57f98be8fca9b1c18a1f74382c4",
                    "name": "EventSystem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\ExecutionContext.sys",
                    "image path": "System32\\Drivers\\ExecutionContext.sys",
                    "md5": "f5a6bf8112fb07498220f22de333bc32",
                    "name": "ExecutionContext",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\ExecutionContext.sys",
                    "image path": "System32\\Drivers\\ExecutionContext.sys",
                    "md5": "f5a6bf8112fb07498220f22de333bc32",
                    "name": "ExecutionContext",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\exfat.sys",
                    "image path": null,
                    "md5": "51b1911604dbc2aaac66f2c93f61313d",
                    "name": "exfat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\exfat.sys",
                    "image path": null,
                    "md5": "51b1911604dbc2aaac66f2c93f61313d",
                    "name": "exfat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\fastfat.sys",
                    "image path": null,
                    "md5": "f145863ca528a8975a72b8cdf3ec20e8",
                    "name": "fastfat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\fastfat.sys",
                    "image path": null,
                    "md5": "f145863ca528a8975a72b8cdf3ec20e8",
                    "name": "fastfat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\fcvsc.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\fcvsc.sys",
                    "md5": "bf4566cba4ee0e25ef6a6bad79096929",
                    "name": "fcvsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\fcvsc.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\fcvsc.sys",
                    "md5": "bf4566cba4ee0e25ef6a6bad79096929",
                    "name": "fcvsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\fdc.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\fdc.sys",
                    "md5": "212b609f85bbc35aa0d95e97a5e58ff0",
                    "name": "fdc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\fdc.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\fdc.sys",
                    "md5": "212b609f85bbc35aa0d95e97a5e58ff0",
                    "name": "fdc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\fdPHost.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "80beaa8991d5b09b19a2d7bd835340d0",
                    "name": "fdPHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\fdPHost.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "80beaa8991d5b09b19a2d7bd835340d0",
                    "name": "fdPHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\fdPHost.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "80beaa8991d5b09b19a2d7bd835340d0",
                    "name": "fdPHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\fdPHost.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "80beaa8991d5b09b19a2d7bd835340d0",
                    "name": "fdPHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\fdrespub.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "ed10b44a9934f2e85e0f5d0725b9c0c9",
                    "name": "FDResPub",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\fdrespub.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "ed10b44a9934f2e85e0f5d0725b9c0c9",
                    "name": "FDResPub",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\fdrespub.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "ed10b44a9934f2e85e0f5d0725b9c0c9",
                    "name": "FDResPub",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\fdrespub.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "ed10b44a9934f2e85e0f5d0725b9c0c9",
                    "name": "FDResPub",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\filecrypt.sys",
                    "image path": "system32\\drivers\\filecrypt.sys",
                    "md5": "087265c07e4364fd44d213b7b3fd57b3",
                    "name": "FileCrypt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\filecrypt.sys",
                    "image path": "system32\\drivers\\filecrypt.sys",
                    "md5": "087265c07e4364fd44d213b7b3fd57b3",
                    "name": "FileCrypt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\fileinfo.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\fileinfo.sys",
                    "md5": "9b67c1da0fde4a75445563a149df0eca",
                    "name": "FileInfo",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\fileinfo.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\fileinfo.sys",
                    "md5": "9b67c1da0fde4a75445563a149df0eca",
                    "name": "FileInfo",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\filetrace.sys",
                    "image path": "system32\\drivers\\filetrace.sys",
                    "md5": "c5638db3ff68a149ed74a254934a60ce",
                    "name": "Filetrace",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\filetrace.sys",
                    "image path": "system32\\drivers\\filetrace.sys",
                    "md5": "c5638db3ff68a149ed74a254934a60ce",
                    "name": "Filetrace",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\flpydisk.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\flpydisk.sys",
                    "md5": "8d2e7cc9a395900499cebe5edf17097e",
                    "name": "flpydisk",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\flpydisk.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\flpydisk.sys",
                    "md5": "8d2e7cc9a395900499cebe5edf17097e",
                    "name": "flpydisk",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\fltmgr.sys",
                    "image path": "system32\\drivers\\fltmgr.sys",
                    "md5": "a5da65b212ef41444f5c663bd0bc733e",
                    "name": "FltMgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\fltmgr.sys",
                    "image path": "system32\\drivers\\fltmgr.sys",
                    "md5": "a5da65b212ef41444f5c663bd0bc733e",
                    "name": "FltMgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FntCache.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "0649553c3dea8087fd54550a82a28b5f",
                    "name": "FontCache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FntCache.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "0649553c3dea8087fd54550a82a28b5f",
                    "name": "FontCache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FntCache.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "0649553c3dea8087fd54550a82a28b5f",
                    "name": "FontCache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FntCache.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "0649553c3dea8087fd54550a82a28b5f",
                    "name": "FontCache",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FrameServer.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k Camera",
                    "md5": "2542241d229b2a14b6ae33c596b7bff6",
                    "name": "FrameServer",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FrameServer.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k Camera",
                    "md5": "2542241d229b2a14b6ae33c596b7bff6",
                    "name": "FrameServer",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FrameServer.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k Camera",
                    "md5": "2542241d229b2a14b6ae33c596b7bff6",
                    "name": "FrameServer",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FrameServer.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k Camera",
                    "md5": "2542241d229b2a14b6ae33c596b7bff6",
                    "name": "FrameServer",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FrameServerMonitor.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k CameraMonitor",
                    "md5": "73757b2c694a93d27facc6ce234ed64c",
                    "name": "FrameServerMonitor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FrameServerMonitor.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k CameraMonitor",
                    "md5": "73757b2c694a93d27facc6ce234ed64c",
                    "name": "FrameServerMonitor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FrameServerMonitor.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k CameraMonitor",
                    "md5": "73757b2c694a93d27facc6ce234ed64c",
                    "name": "FrameServerMonitor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\FrameServerMonitor.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k CameraMonitor",
                    "md5": "73757b2c694a93d27facc6ce234ed64c",
                    "name": "FrameServerMonitor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Fs_Rec.sys",
                    "image path": null,
                    "md5": "b778af9c823c027d4e3f2de30eeccc60",
                    "name": "Fs_Rec",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Fs_Rec.sys",
                    "image path": null,
                    "md5": "b778af9c823c027d4e3f2de30eeccc60",
                    "name": "Fs_Rec",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\FsDepends.sys",
                    "image path": "System32\\drivers\\FsDepends.sys",
                    "md5": "edc8f056d9615404608160a2b5a26c9b",
                    "name": "FsDepends",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\FsDepends.sys",
                    "image path": "System32\\drivers\\FsDepends.sys",
                    "md5": "edc8f056d9615404608160a2b5a26c9b",
                    "name": "FsDepends",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vmgencounter.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vmgencounter.sys",
                    "md5": "db24ed511b253b6da808e2e58e60d590",
                    "name": "gencounter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vmgencounter.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vmgencounter.sys",
                    "md5": "db24ed511b253b6da808e2e58e60d590",
                    "name": "gencounter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\genericusbfn.inf_amd64_e5e79fac2038997d\\genericusbfn.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\genericusbfn.inf_amd64_e5e79fac2038997d\\genericusbfn.sys",
                    "md5": "e1126b8f09af9df1d765052eb8f9c870",
                    "name": "genericusbfn",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\genericusbfn.inf_amd64_e5e79fac2038997d\\genericusbfn.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\genericusbfn.inf_amd64_e5e79fac2038997d\\genericusbfn.sys",
                    "md5": "e1126b8f09af9df1d765052eb8f9c870",
                    "name": "genericusbfn",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\msgpioclx.sys",
                    "image path": "System32\\Drivers\\msgpioclx.sys",
                    "md5": "430483252e2e63ab11f3b80a49c04dd2",
                    "name": "GPIOClx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\msgpioclx.sys",
                    "image path": "System32\\Drivers\\msgpioclx.sys",
                    "md5": "430483252e2e63ab11f3b80a49c04dd2",
                    "name": "GPIOClx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\gpsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "2356276cb2990efc3243ecfcae16f373",
                    "name": "gpsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\gpsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "2356276cb2990efc3243ecfcae16f373",
                    "name": "gpsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\gpsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "2356276cb2990efc3243ecfcae16f373",
                    "name": "gpsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\gpsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "2356276cb2990efc3243ecfcae16f373",
                    "name": "gpsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\GraphicsPerfSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k GraphicsPerfSvcGroup",
                    "md5": "4e1b563c2e25df41df413b95524d2a64",
                    "name": "GraphicsPerfSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\GraphicsPerfSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k GraphicsPerfSvcGroup",
                    "md5": "4e1b563c2e25df41df413b95524d2a64",
                    "name": "GraphicsPerfSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\GraphicsPerfSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k GraphicsPerfSvcGroup",
                    "md5": "4e1b563c2e25df41df413b95524d2a64",
                    "name": "GraphicsPerfSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\GraphicsPerfSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k GraphicsPerfSvcGroup",
                    "md5": "4e1b563c2e25df41df413b95524d2a64",
                    "name": "GraphicsPerfSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HdAudio.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\HdAudio.sys",
                    "md5": "448fd9c281d4c90d32ffe997195ed535",
                    "name": "HdAudAddService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HdAudio.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\HdAudio.sys",
                    "md5": "448fd9c281d4c90d32ffe997195ed535",
                    "name": "HdAudAddService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HDAudBus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\HDAudBus.sys",
                    "md5": "9734c4c12eb469fb4bd59495e3a54009",
                    "name": "HDAudBus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HDAudBus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\HDAudBus.sys",
                    "md5": "9734c4c12eb469fb4bd59495e3a54009",
                    "name": "HDAudBus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HidBatt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\HidBatt.sys",
                    "md5": "33853a00b6cf34f3d7af55ce3651bdc7",
                    "name": "HidBatt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HidBatt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\HidBatt.sys",
                    "md5": "33853a00b6cf34f3d7af55ce3651bdc7",
                    "name": "HidBatt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hidinterrupt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\hidinterrupt.sys",
                    "md5": "172da51b76e31ab5aedc4bb861ba90ac",
                    "name": "hidinterrupt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hidinterrupt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\hidinterrupt.sys",
                    "md5": "172da51b76e31ab5aedc4bb861ba90ac",
                    "name": "hidinterrupt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\hidserv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "1969d81e14152856fd487a773740700d",
                    "name": "hidserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\hidserv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "1969d81e14152856fd487a773740700d",
                    "name": "hidserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\hidserv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "1969d81e14152856fd487a773740700d",
                    "name": "hidserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\hidserv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "1969d81e14152856fd487a773740700d",
                    "name": "hidserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hidusb.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\hidusb.sys",
                    "md5": "0c8824a963647937f56ed477185ed4ab",
                    "name": "HidUsb",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hidusb.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\hidusb.sys",
                    "md5": "0c8824a963647937f56ed477185ed4ab",
                    "name": "HidUsb",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "image path": "\"C:\\Program Files\\HarfangLab\\hurukai.exe\"",
                    "md5": "05049f1cadb8af2b6893e1ead33351c9",
                    "name": "hlab_hurukai",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "image path": "\"C:\\Program Files\\HarfangLab\\hurukai.exe\"",
                    "md5": "05049f1cadb8af2b6893e1ead33351c9",
                    "name": "hlab_hurukai",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\hlprotect.sys",
                    "image path": "system32\\DRIVERS\\hlprotect.sys",
                    "md5": "44480d8a012a7249bc390cbcdb687fee",
                    "name": "hlprotect",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\hlprotect.sys",
                    "image path": "system32\\DRIVERS\\hlprotect.sys",
                    "md5": "44480d8a012a7249bc390cbcdb687fee",
                    "name": "hlprotect",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HpSAMD.sys",
                    "image path": "System32\\drivers\\HpSAMD.sys",
                    "md5": "1508143ba4b199d0a68bd9103883d320",
                    "name": "HpSAMD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HpSAMD.sys",
                    "image path": "System32\\drivers\\HpSAMD.sys",
                    "md5": "1508143ba4b199d0a68bd9103883d320",
                    "name": "HpSAMD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\HTTP.sys",
                    "image path": "system32\\drivers\\HTTP.sys",
                    "md5": "0db27d34c898a592dcf7e4a5eeacc2be",
                    "name": "HTTP",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\HTTP.sys",
                    "image path": "system32\\drivers\\HTTP.sys",
                    "md5": "0db27d34c898a592dcf7e4a5eeacc2be",
                    "name": "HTTP",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hvcrash.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\hvcrash.sys",
                    "md5": "cf13e7ed04e5135bab1e6b063b78c5d2",
                    "name": "hvcrash",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hvcrash.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\hvcrash.sys",
                    "md5": "cf13e7ed04e5135bab1e6b063b78c5d2",
                    "name": "hvcrash",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\hvhostsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "5b4f5403bf684aaf8a70d9e6ffb2b828",
                    "name": "HvHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\hvhostsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "5b4f5403bf684aaf8a70d9e6ffb2b828",
                    "name": "HvHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\hvhostsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "5b4f5403bf684aaf8a70d9e6ffb2b828",
                    "name": "HvHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\hvhostsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "5b4f5403bf684aaf8a70d9e6ffb2b828",
                    "name": "HvHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\hvservice.sys",
                    "image path": "system32\\drivers\\hvservice.sys",
                    "md5": "50625583f00248cfbeecedbb5136b068",
                    "name": "hvservice",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\hvservice.sys",
                    "image path": "system32\\drivers\\hvservice.sys",
                    "md5": "50625583f00248cfbeecedbb5136b068",
                    "name": "hvservice",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\mshwnclx.sys",
                    "image path": "System32\\Drivers\\mshwnclx.sys",
                    "md5": "8aedd7e0bc41408d2d409dac99e630ad",
                    "name": "HwNClx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\mshwnclx.sys",
                    "image path": "System32\\Drivers\\mshwnclx.sys",
                    "md5": "8aedd7e0bc41408d2d409dac99e630ad",
                    "name": "HwNClx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hwpolicy.sys",
                    "image path": "System32\\drivers\\hwpolicy.sys",
                    "md5": "f0fb9fe56b5e072294adb19712334052",
                    "name": "hwpolicy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hwpolicy.sys",
                    "image path": "System32\\drivers\\hwpolicy.sys",
                    "md5": "f0fb9fe56b5e072294adb19712334052",
                    "name": "hwpolicy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hyperkbd.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\hyperkbd.sys",
                    "md5": "200eb4ad3fde0cf05307bf9fdb76af77",
                    "name": "hyperkbd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\hyperkbd.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\hyperkbd.sys",
                    "md5": "200eb4ad3fde0cf05307bf9fdb76af77",
                    "name": "hyperkbd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HyperVideo.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\HyperVideo.sys",
                    "md5": "e30fb2ff97f5c3bfbee0dbdb570d8f04",
                    "name": "HyperVideo",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\HyperVideo.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\HyperVideo.sys",
                    "md5": "e30fb2ff97f5c3bfbee0dbdb570d8f04",
                    "name": "HyperVideo",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\i8042prt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\i8042prt.sys",
                    "md5": "8bc4c8d32cea74b3c27a77330ba1ff28",
                    "name": "i8042prt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\i8042prt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\i8042prt.sys",
                    "md5": "8bc4c8d32cea74b3c27a77330ba1ff28",
                    "name": "i8042prt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\iaLPSSi_GPIO.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\iaLPSSi_GPIO.sys",
                    "md5": "16a10ccedcf5ac4caae43dc9fc40392f",
                    "name": "iaLPSSi_GPIO",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\iaLPSSi_GPIO.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\iaLPSSi_GPIO.sys",
                    "md5": "16a10ccedcf5ac4caae43dc9fc40392f",
                    "name": "iaLPSSi_GPIO",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\iaLPSSi_I2C.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\iaLPSSi_I2C.sys",
                    "md5": "eb82a11613326691508d9ed9a4fe29e7",
                    "name": "iaLPSSi_I2C",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\iaLPSSi_I2C.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\iaLPSSi_I2C.sys",
                    "md5": "eb82a11613326691508d9ed9a4fe29e7",
                    "name": "iaLPSSi_I2C",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\iaStorAVC.sys",
                    "image path": "System32\\drivers\\iaStorAVC.sys",
                    "md5": "1c948ca84ec603fd60d36845df59e674",
                    "name": "iaStorAVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\iaStorAVC.sys",
                    "image path": "System32\\drivers\\iaStorAVC.sys",
                    "md5": "1c948ca84ec603fd60d36845df59e674",
                    "name": "iaStorAVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\iaStorV.sys",
                    "image path": "System32\\drivers\\iaStorV.sys",
                    "md5": "480824c8c73482623d00598d54f775b7",
                    "name": "iaStorV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\iaStorV.sys",
                    "image path": "System32\\drivers\\iaStorV.sys",
                    "md5": "480824c8c73482623d00598d54f775b7",
                    "name": "iaStorV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ibbus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ibbus.sys",
                    "md5": "751e9c5c9917288664ba6cce9df5c5e8",
                    "name": "ibbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ibbus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ibbus.sys",
                    "md5": "751e9c5c9917288664ba6cce9df5c5e8",
                    "name": "ibbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ikeext.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "eea78e98ac78de95198805661a414fda",
                    "name": "IKEEXT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ikeext.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "eea78e98ac78de95198805661a414fda",
                    "name": "IKEEXT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ikeext.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "eea78e98ac78de95198805661a414fda",
                    "name": "IKEEXT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ikeext.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "eea78e98ac78de95198805661a414fda",
                    "name": "IKEEXT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\IndirectKmd.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\IndirectKmd.sys",
                    "md5": "81ad822e977a93d902f210382c51957d",
                    "name": "IndirectKmd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\IndirectKmd.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\IndirectKmd.sys",
                    "md5": "81ad822e977a93d902f210382c51957d",
                    "name": "IndirectKmd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\InstallService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "6b72b07a1a123281e17d51565bfe8f52",
                    "name": "InstallService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\InstallService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "6b72b07a1a123281e17d51565bfe8f52",
                    "name": "InstallService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\InstallService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "6b72b07a1a123281e17d51565bfe8f52",
                    "name": "InstallService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\InstallService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "6b72b07a1a123281e17d51565bfe8f52",
                    "name": "InstallService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\intelide.sys",
                    "image path": "System32\\drivers\\intelide.sys",
                    "md5": "32f91cbd0b66b168082c0472e22c8c89",
                    "name": "intelide",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\intelide.sys",
                    "image path": "System32\\drivers\\intelide.sys",
                    "md5": "32f91cbd0b66b168082c0472e22c8c89",
                    "name": "intelide",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\intelpep.sys",
                    "image path": "System32\\drivers\\intelpep.sys",
                    "md5": "4217aa0ec9a2fa258de03b098d83bc71",
                    "name": "intelpep",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\intelpep.sys",
                    "image path": "System32\\drivers\\intelpep.sys",
                    "md5": "4217aa0ec9a2fa258de03b098d83bc71",
                    "name": "intelpep",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\IntelPMT.sys",
                    "image path": "System32\\drivers\\IntelPMT.sys",
                    "md5": "698ad8b52eaaaeeb7a5cad5c28db5af5",
                    "name": "IntelPMT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\IntelPMT.sys",
                    "image path": "System32\\drivers\\IntelPMT.sys",
                    "md5": "698ad8b52eaaaeeb7a5cad5c28db5af5",
                    "name": "IntelPMT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\intelppm.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\intelppm.sys",
                    "md5": "786f77d638ff941977956898ebcb758e",
                    "name": "intelppm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\intelppm.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\intelppm.sys",
                    "md5": "786f77d638ff941977956898ebcb758e",
                    "name": "intelppm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\ipfltdrv.sys",
                    "image path": "system32\\DRIVERS\\ipfltdrv.sys",
                    "md5": "9114ee02e916105b160d02f16035e5fe",
                    "name": "IpFilterDriver",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\ipfltdrv.sys",
                    "image path": "system32\\DRIVERS\\ipfltdrv.sys",
                    "md5": "9114ee02e916105b160d02f16035e5fe",
                    "name": "IpFilterDriver",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\iphlpsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetSvcs -p",
                    "md5": "e665ff85b75c0391e2885bc05d32a1a8",
                    "name": "iphlpsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\iphlpsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetSvcs -p",
                    "md5": "e665ff85b75c0391e2885bc05d32a1a8",
                    "name": "iphlpsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\iphlpsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetSvcs -p",
                    "md5": "e665ff85b75c0391e2885bc05d32a1a8",
                    "name": "iphlpsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\iphlpsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetSvcs -p",
                    "md5": "e665ff85b75c0391e2885bc05d32a1a8",
                    "name": "iphlpsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\IPMIDrv.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\IPMIDrv.sys",
                    "md5": "0bb68f9ee271fe888c082d38aff404b8",
                    "name": "IPMIDRV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\IPMIDrv.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\IPMIDrv.sys",
                    "md5": "0bb68f9ee271fe888c082d38aff404b8",
                    "name": "IPMIDRV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ipnat.sys",
                    "image path": "System32\\drivers\\ipnat.sys",
                    "md5": "b62339d7184ca9efba38eef2da886c25",
                    "name": "IPNAT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ipnat.sys",
                    "image path": "System32\\drivers\\ipnat.sys",
                    "md5": "b62339d7184ca9efba38eef2da886c25",
                    "name": "IPNAT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ipt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ipt.sys",
                    "md5": "754df34adf4b729d4bcc82fe0eb472eb",
                    "name": "IPT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ipt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ipt.sys",
                    "md5": "754df34adf4b729d4bcc82fe0eb472eb",
                    "name": "IPT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\isapnp.sys",
                    "image path": "System32\\drivers\\isapnp.sys",
                    "md5": "a889004ba9dbcbc42836ea373a1dfd2c",
                    "name": "isapnp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\isapnp.sys",
                    "image path": "System32\\drivers\\isapnp.sys",
                    "md5": "a889004ba9dbcbc42836ea373a1dfd2c",
                    "name": "isapnp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\msiscsi.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\msiscsi.sys",
                    "md5": "998704bd8f01d8036e3b3afc9a9d482d",
                    "name": "iScsiPrt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\msiscsi.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\msiscsi.sys",
                    "md5": "998704bd8f01d8036e3b3afc9a9d482d",
                    "name": "iScsiPrt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ItSas35i.sys",
                    "image path": "System32\\drivers\\ItSas35i.sys",
                    "md5": "28f9dd22eef753bd4f0e618b7279ed35",
                    "name": "ItSas35i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ItSas35i.sys",
                    "image path": "System32\\drivers\\ItSas35i.sys",
                    "md5": "28f9dd22eef753bd4f0e618b7279ed35",
                    "name": "ItSas35i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\kbdclass.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\kbdclass.sys",
                    "md5": "27947916ad55bfdb88c6f2e00ac4d90b",
                    "name": "kbdclass",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\kbdclass.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\kbdclass.sys",
                    "md5": "27947916ad55bfdb88c6f2e00ac4d90b",
                    "name": "kbdclass",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\kbdhid.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\kbdhid.sys",
                    "md5": "2d8562d442d1b00274da42012b556483",
                    "name": "kbdhid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\kbdhid.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\kbdhid.sys",
                    "md5": "2d8562d442d1b00274da42012b556483",
                    "name": "kbdhid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\kdnic.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\kdnic.sys",
                    "md5": "d8ac3b58add59eeb8674787347795806",
                    "name": "kdnic",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\kdnic.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\kdnic.sys",
                    "md5": "d8ac3b58add59eeb8674787347795806",
                    "name": "kdnic",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\keyiso.dll",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "91fd6853a59e1b09ec8b8d139fbeaa8c",
                    "name": "KeyIso",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\keyiso.dll",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "91fd6853a59e1b09ec8b8d139fbeaa8c",
                    "name": "KeyIso",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\keyiso.dll",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "91fd6853a59e1b09ec8b8d139fbeaa8c",
                    "name": "KeyIso",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\keyiso.dll",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "91fd6853a59e1b09ec8b8d139fbeaa8c",
                    "name": "KeyIso",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\kpssvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k KpsSvcGroup",
                    "md5": "4416aa41c51c096ebf3a56f5345d6ef3",
                    "name": "KPSSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\kpssvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k KpsSvcGroup",
                    "md5": "4416aa41c51c096ebf3a56f5345d6ef3",
                    "name": "KPSSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\kpssvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k KpsSvcGroup",
                    "md5": "4416aa41c51c096ebf3a56f5345d6ef3",
                    "name": "KPSSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\kpssvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k KpsSvcGroup",
                    "md5": "4416aa41c51c096ebf3a56f5345d6ef3",
                    "name": "KPSSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\ksecdd.sys",
                    "image path": "System32\\Drivers\\ksecdd.sys",
                    "md5": "9dacc16c05894f8db0b93fb60fcc2341",
                    "name": "KSecDD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\ksecdd.sys",
                    "image path": "System32\\Drivers\\ksecdd.sys",
                    "md5": "9dacc16c05894f8db0b93fb60fcc2341",
                    "name": "KSecDD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\ksecpkg.sys",
                    "image path": "System32\\Drivers\\ksecpkg.sys",
                    "md5": "ad9063eeb2a5179acd11bb1754023c30",
                    "name": "KSecPkg",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\ksecpkg.sys",
                    "image path": "System32\\Drivers\\ksecpkg.sys",
                    "md5": "ad9063eeb2a5179acd11bb1754023c30",
                    "name": "KSecPkg",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ksthunk.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\ksthunk.sys",
                    "md5": "e9dd5b83a72078795d82c19fd3bb01b3",
                    "name": "ksthunk",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ksthunk.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\ksthunk.sys",
                    "md5": "e9dd5b83a72078795d82c19fd3bb01b3",
                    "name": "ksthunk",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\msdtckrm.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkServiceAndNoImpersonation -p",
                    "md5": "94ea6bc52d3c9381dd68cc4e0b0681cb",
                    "name": "KtmRm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\msdtckrm.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkServiceAndNoImpersonation -p",
                    "md5": "94ea6bc52d3c9381dd68cc4e0b0681cb",
                    "name": "KtmRm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\msdtckrm.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkServiceAndNoImpersonation -p",
                    "md5": "94ea6bc52d3c9381dd68cc4e0b0681cb",
                    "name": "KtmRm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\msdtckrm.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkServiceAndNoImpersonation -p",
                    "md5": "94ea6bc52d3c9381dd68cc4e0b0681cb",
                    "name": "KtmRm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\srvsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k smbsvcs",
                    "md5": "d3d16c8bd73661afa1a30c62a0c95f5a",
                    "name": "LanmanServer",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\srvsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k smbsvcs",
                    "md5": "d3d16c8bd73661afa1a30c62a0c95f5a",
                    "name": "LanmanServer",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\srvsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k smbsvcs",
                    "md5": "d3d16c8bd73661afa1a30c62a0c95f5a",
                    "name": "LanmanServer",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\srvsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k smbsvcs",
                    "md5": "d3d16c8bd73661afa1a30c62a0c95f5a",
                    "name": "LanmanServer",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wkssvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "1b15d74d6abe450867d42e4523e15932",
                    "name": "LanmanWorkstation",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wkssvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "1b15d74d6abe450867d42e4523e15932",
                    "name": "LanmanWorkstation",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wkssvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "1b15d74d6abe450867d42e4523e15932",
                    "name": "LanmanWorkstation",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wkssvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "1b15d74d6abe450867d42e4523e15932",
                    "name": "LanmanWorkstation",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lfsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "bbc9914747a98675fb710cab2756d4e2",
                    "name": "lfsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lfsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "bbc9914747a98675fb710cab2756d4e2",
                    "name": "lfsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lfsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "bbc9914747a98675fb710cab2756d4e2",
                    "name": "lfsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lfsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "bbc9914747a98675fb710cab2756d4e2",
                    "name": "lfsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\LicenseManagerSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "6b66ac5a2f4be7c9cdf05af6b9ce57a2",
                    "name": "LicenseManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\LicenseManagerSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "6b66ac5a2f4be7c9cdf05af6b9ce57a2",
                    "name": "LicenseManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\LicenseManagerSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "6b66ac5a2f4be7c9cdf05af6b9ce57a2",
                    "name": "LicenseManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\LicenseManagerSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "6b66ac5a2f4be7c9cdf05af6b9ce57a2",
                    "name": "LicenseManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\lltdio.sys",
                    "image path": "system32\\drivers\\lltdio.sys",
                    "md5": "38c53c38731190ba73b39cbd3befe14a",
                    "name": "lltdio",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\lltdio.sys",
                    "image path": "system32\\drivers\\lltdio.sys",
                    "md5": "38c53c38731190ba73b39cbd3befe14a",
                    "name": "lltdio",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lltdsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "c0b356e9e078f1410dd5429b397654fd",
                    "name": "lltdsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lltdsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "c0b356e9e078f1410dd5429b397654fd",
                    "name": "lltdsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lltdsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "c0b356e9e078f1410dd5429b397654fd",
                    "name": "lltdsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lltdsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "c0b356e9e078f1410dd5429b397654fd",
                    "name": "lltdsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lmhsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5c8975bcb1253f23f74b1188b58fb831",
                    "name": "lmhosts",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lmhsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5c8975bcb1253f23f74b1188b58fb831",
                    "name": "lmhosts",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lmhsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5c8975bcb1253f23f74b1188b58fb831",
                    "name": "lmhosts",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lmhsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5c8975bcb1253f23f74b1188b58fb831",
                    "name": "lmhosts",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\lsi_sas.sys",
                    "image path": "System32\\drivers\\lsi_sas.sys",
                    "md5": "07e270396719f62056ddb386ba558890",
                    "name": "LSI_SAS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\lsi_sas.sys",
                    "image path": "System32\\drivers\\lsi_sas.sys",
                    "md5": "07e270396719f62056ddb386ba558890",
                    "name": "LSI_SAS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\lsi_sas2i.sys",
                    "image path": "System32\\drivers\\lsi_sas2i.sys",
                    "md5": "45a19614b57a9ed2820f8980c419c83e",
                    "name": "LSI_SAS2i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\lsi_sas2i.sys",
                    "image path": "System32\\drivers\\lsi_sas2i.sys",
                    "md5": "45a19614b57a9ed2820f8980c419c83e",
                    "name": "LSI_SAS2i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\lsi_sas3i.sys",
                    "image path": "System32\\drivers\\lsi_sas3i.sys",
                    "md5": "863ecf3758fb9482979d474f3531d8a7",
                    "name": "LSI_SAS3i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\lsi_sas3i.sys",
                    "image path": "System32\\drivers\\lsi_sas3i.sys",
                    "md5": "863ecf3758fb9482979d474f3531d8a7",
                    "name": "LSI_SAS3i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lsm.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "a288b85cc6cea70e0cd0ed0496fb6668",
                    "name": "LSM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lsm.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "a288b85cc6cea70e0cd0ed0496fb6668",
                    "name": "LSM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lsm.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "a288b85cc6cea70e0cd0ed0496fb6668",
                    "name": "LSM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\lsm.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "a288b85cc6cea70e0cd0ed0496fb6668",
                    "name": "LSM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\luafv.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\luafv.sys",
                    "md5": "0e93bc867995100e2bf56be9fa9219a4",
                    "name": "luafv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\luafv.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\luafv.sys",
                    "md5": "0e93bc867995100e2bf56be9fa9219a4",
                    "name": "luafv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\moshost.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "c88542305baf639416e7a574f6b0cef4",
                    "name": "MapsBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\moshost.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "c88542305baf639416e7a574f6b0cef4",
                    "name": "MapsBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\moshost.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "c88542305baf639416e7a574f6b0cef4",
                    "name": "MapsBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\moshost.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "c88542305baf639416e7a574f6b0cef4",
                    "name": "MapsBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mausbhost.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mausbhost.sys",
                    "md5": "1e4e6a723b99fde21ec0e8c7a8fffa71",
                    "name": "mausbhost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mausbhost.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mausbhost.sys",
                    "md5": "1e4e6a723b99fde21ec0e8c7a8fffa71",
                    "name": "mausbhost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mausbip.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mausbip.sys",
                    "md5": "9ccc6aac061537045f92b76aaad46b0f",
                    "name": "mausbip",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mausbip.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mausbip.sys",
                    "md5": "9ccc6aac061537045f92b76aaad46b0f",
                    "name": "mausbip",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\McpManagementService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k McpManagementServiceGroup",
                    "md5": "4c1bcbeee25c130cbed6502409b8d48d",
                    "name": "McpManagementService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\McpManagementService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k McpManagementServiceGroup",
                    "md5": "4c1bcbeee25c130cbed6502409b8d48d",
                    "name": "McpManagementService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\McpManagementService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k McpManagementServiceGroup",
                    "md5": "4c1bcbeee25c130cbed6502409b8d48d",
                    "name": "McpManagementService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\McpManagementService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k McpManagementServiceGroup",
                    "md5": "4c1bcbeee25c130cbed6502409b8d48d",
                    "name": "McpManagementService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MegaSas2i.sys",
                    "image path": "System32\\drivers\\MegaSas2i.sys",
                    "md5": "e86a0dfe0403bda2a9f7985e81e03f18",
                    "name": "megasas2i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MegaSas2i.sys",
                    "image path": "System32\\drivers\\MegaSas2i.sys",
                    "md5": "e86a0dfe0403bda2a9f7985e81e03f18",
                    "name": "megasas2i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\megasas35i.sys",
                    "image path": "System32\\drivers\\megasas35i.sys",
                    "md5": "22130fe8ff179afc352bbeb1361e3736",
                    "name": "megasas35i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\megasas35i.sys",
                    "image path": "System32\\drivers\\megasas35i.sys",
                    "md5": "22130fe8ff179afc352bbeb1361e3736",
                    "name": "megasas35i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\megasr.sys",
                    "image path": "System32\\drivers\\megasr.sys",
                    "md5": "eb665ce09497c75bb685f9b7452aaae4",
                    "name": "megasr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\megasr.sys",
                    "image path": "System32\\drivers\\megasr.sys",
                    "md5": "eb665ce09497c75bb685f9b7452aaae4",
                    "name": "megasr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\103.0.1264.71\\elevation_service.exe",
                    "image path": "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\103.0.1264.71\\elevation_service.exe\"",
                    "md5": "7089606148391ff5b6ba662554b987ce",
                    "name": "MicrosoftEdgeElevationService",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "image path": "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\103.0.1264.62\\elevation_service.exe\"",
                    "md5": null,
                    "name": "MicrosoftEdgeElevationService",
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mlx4_bus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mlx4_bus.sys",
                    "md5": "23e0f8fafb42d2e898c9bf0e98ed5d3b",
                    "name": "mlx4_bus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mlx4_bus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mlx4_bus.sys",
                    "md5": "23e0f8fafb42d2e898c9bf0e98ed5d3b",
                    "name": "mlx4_bus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mmcss.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\mmcss.sys",
                    "md5": "a10c637165ab63671f5ea554109d008c",
                    "name": "MMCSS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mmcss.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\mmcss.sys",
                    "md5": "a10c637165ab63671f5ea554109d008c",
                    "name": "MMCSS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\modem.sys",
                    "image path": "system32\\drivers\\modem.sys",
                    "md5": "e36d3293c67e812fb0934cd308251b7b",
                    "name": "Modem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\modem.sys",
                    "image path": "system32\\drivers\\modem.sys",
                    "md5": "e36d3293c67e812fb0934cd308251b7b",
                    "name": "Modem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\monitor.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\monitor.sys",
                    "md5": "b8f452f5baa586406a190c647c1443e4",
                    "name": "monitor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\monitor.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\monitor.sys",
                    "md5": "b8f452f5baa586406a190c647c1443e4",
                    "name": "monitor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mouclass.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mouclass.sys",
                    "md5": "0c34c0630a233c0f62fcdd4d13af0d47",
                    "name": "mouclass",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mouclass.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mouclass.sys",
                    "md5": "0c34c0630a233c0f62fcdd4d13af0d47",
                    "name": "mouclass",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mouhid.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mouhid.sys",
                    "md5": "e5b29bdb8672eed313a4f5b364f299f3",
                    "name": "mouhid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mouhid.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mouhid.sys",
                    "md5": "e5b29bdb8672eed313a4f5b364f299f3",
                    "name": "mouhid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mountmgr.sys",
                    "image path": "System32\\drivers\\mountmgr.sys",
                    "md5": "531d3c5a7749a2c912ea6a0e5cb67c75",
                    "name": "mountmgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mountmgr.sys",
                    "image path": "System32\\drivers\\mountmgr.sys",
                    "md5": "531d3c5a7749a2c912ea6a0e5cb67c75",
                    "name": "mountmgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mpi3drvi.sys",
                    "image path": "System32\\drivers\\mpi3drvi.sys",
                    "md5": "38f87c3fbab159c90e15ae1b74e1df74",
                    "name": "mpi3drvi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mpi3drvi.sys",
                    "image path": "System32\\drivers\\mpi3drvi.sys",
                    "md5": "38f87c3fbab159c90e15ae1b74e1df74",
                    "name": "mpi3drvi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{265C6876-ACFD-4597-B853-B3E54112BC77}\\MpKslDrv.sys",
                    "image path": "\\??\\C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{265C6876-ACFD-4597-B853-B3E54112BC77}\\MpKslDrv.sys",
                    "md5": "6f2f14025a606b924e77ad29aa68d231",
                    "name": "MpKsl73942e08",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mpsdrv.sys",
                    "image path": "System32\\drivers\\mpsdrv.sys",
                    "md5": "fb4d94870b1f42d93feb8a85b590fd4a",
                    "name": "mpsdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mpsdrv.sys",
                    "image path": "System32\\drivers\\mpsdrv.sys",
                    "md5": "fb4d94870b1f42d93feb8a85b590fd4a",
                    "name": "mpsdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\mpssvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "md5": "f4a69d94e83e83dd32325e4cbc39ee6c",
                    "name": "mpssvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\mpssvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "md5": "f4a69d94e83e83dd32325e4cbc39ee6c",
                    "name": "mpssvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\mpssvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "md5": "f4a69d94e83e83dd32325e4cbc39ee6c",
                    "name": "mpssvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\mpssvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "md5": "f4a69d94e83e83dd32325e4cbc39ee6c",
                    "name": "mpssvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\mrxsmb.sys",
                    "image path": "system32\\DRIVERS\\mrxsmb.sys",
                    "md5": "b0186ea7f1979d9f02da0ae11542d39d",
                    "name": "mrxsmb",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\mrxsmb.sys",
                    "image path": "system32\\DRIVERS\\mrxsmb.sys",
                    "md5": "b0186ea7f1979d9f02da0ae11542d39d",
                    "name": "mrxsmb",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\mrxsmb20.sys",
                    "image path": "system32\\DRIVERS\\mrxsmb20.sys",
                    "md5": "40f91604967e771021b89a54ddb74131",
                    "name": "mrxsmb20",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\mrxsmb20.sys",
                    "image path": "system32\\DRIVERS\\mrxsmb20.sys",
                    "md5": "40f91604967e771021b89a54ddb74131",
                    "name": "mrxsmb20",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bridge.sys",
                    "image path": "System32\\drivers\\bridge.sys",
                    "md5": "4b1a343b7ca38df4d436b5c6e0244e23",
                    "name": "MsBridge",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\bridge.sys",
                    "image path": "System32\\drivers\\bridge.sys",
                    "md5": "4b1a343b7ca38df4d436b5c6e0244e23",
                    "name": "MsBridge",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\msdtc.exe",
                    "image path": "%SystemRoot%\\System32\\msdtc.exe",
                    "md5": "bd7be47340ba4888b9b47ad323ff51d3",
                    "name": "MSDTC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\msdtc.exe",
                    "image path": "%SystemRoot%\\System32\\msdtc.exe",
                    "md5": "bd7be47340ba4888b9b47ad323ff51d3",
                    "name": "MSDTC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Msfs.sys",
                    "image path": null,
                    "md5": "82560bdaf351cd8917f01b5d7a1c03a4",
                    "name": "Msfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Msfs.sys",
                    "image path": null,
                    "md5": "82560bdaf351cd8917f01b5d7a1c03a4",
                    "name": "Msfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\msgpiowin32.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\msgpiowin32.sys",
                    "md5": "8a3fb7cda5f1db530266974a5e5c5f67",
                    "name": "msgpiowin32",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\msgpiowin32.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\msgpiowin32.sys",
                    "md5": "8a3fb7cda5f1db530266974a5e5c5f67",
                    "name": "msgpiowin32",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mshidkmdf.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mshidkmdf.sys",
                    "md5": "5f00f2ac7756b56e8939d9be36e9cbcd",
                    "name": "mshidkmdf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mshidkmdf.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mshidkmdf.sys",
                    "md5": "5f00f2ac7756b56e8939d9be36e9cbcd",
                    "name": "mshidkmdf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mshidumdf.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mshidumdf.sys",
                    "md5": "eb7684ee29c6122ddd690545d040805b",
                    "name": "mshidumdf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mshidumdf.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mshidumdf.sys",
                    "md5": "eb7684ee29c6122ddd690545d040805b",
                    "name": "mshidumdf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\msisadrv.sys",
                    "image path": "System32\\drivers\\msisadrv.sys",
                    "md5": "af9787af0870c3349336c641a9deb816",
                    "name": "msisadrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\msisadrv.sys",
                    "image path": "System32\\drivers\\msisadrv.sys",
                    "md5": "af9787af0870c3349336c641a9deb816",
                    "name": "msisadrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\iscsiexe.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "0453fba1a7d50eebc8e5ec25bc8e7c18",
                    "name": "MSiSCSI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\iscsiexe.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "0453fba1a7d50eebc8e5ec25bc8e7c18",
                    "name": "MSiSCSI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\iscsiexe.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "0453fba1a7d50eebc8e5ec25bc8e7c18",
                    "name": "MSiSCSI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\iscsiexe.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "0453fba1a7d50eebc8e5ec25bc8e7c18",
                    "name": "MSiSCSI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\msiexec.exe",
                    "image path": "%systemroot%\\system32\\msiexec.exe /V",
                    "md5": "25e49f426d475e01ecc763e3c433fbf4",
                    "name": "msiserver",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\msiexec.exe",
                    "image path": "%systemroot%\\system32\\msiexec.exe /V",
                    "md5": "25e49f426d475e01ecc763e3c433fbf4",
                    "name": "msiserver",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MSKSSRV.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MSKSSRV.sys",
                    "md5": "4cefae5b0b1364ef520d18140a290d54",
                    "name": "MSKSSRV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MSKSSRV.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MSKSSRV.sys",
                    "md5": "4cefae5b0b1364ef520d18140a290d54",
                    "name": "MSKSSRV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MsLbfoProvider.sys",
                    "image path": "System32\\drivers\\MsLbfoProvider.sys",
                    "md5": "79ff4b1f24b93f2b2f76225db89f2800",
                    "name": "MsLbfoProvider",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MsLbfoProvider.sys",
                    "image path": "System32\\drivers\\MsLbfoProvider.sys",
                    "md5": "79ff4b1f24b93f2b2f76225db89f2800",
                    "name": "MsLbfoProvider",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mslldp.sys",
                    "image path": "system32\\drivers\\mslldp.sys",
                    "md5": "d69790cc30e3717431067b1a43a679f1",
                    "name": "MsLldp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mslldp.sys",
                    "image path": "system32\\drivers\\mslldp.sys",
                    "md5": "d69790cc30e3717431067b1a43a679f1",
                    "name": "MsLldp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MSPCLOCK.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MSPCLOCK.sys",
                    "md5": "3ca66375e00b54ca49c5cccb2945ecd8",
                    "name": "MSPCLOCK",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MSPCLOCK.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MSPCLOCK.sys",
                    "md5": "3ca66375e00b54ca49c5cccb2945ecd8",
                    "name": "MSPCLOCK",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MSPQM.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MSPQM.sys",
                    "md5": "89d2ce46f0e9eb9b05ae0096dbaa3f88",
                    "name": "MSPQM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MSPQM.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MSPQM.sys",
                    "md5": "89d2ce46f0e9eb9b05ae0096dbaa3f88",
                    "name": "MSPQM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\msquic.sys",
                    "image path": "system32\\drivers\\msquic.sys",
                    "md5": "afb57e498cd26284e9603353fb9104ad",
                    "name": "MsQuic",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\msquic.sys",
                    "image path": "system32\\drivers\\msquic.sys",
                    "md5": "afb57e498cd26284e9603353fb9104ad",
                    "name": "MsQuic",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\MsRPC.sys",
                    "image path": null,
                    "md5": "20cbe52b050fa5438428158323e4b0c2",
                    "name": "MsRPC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\MsRPC.sys",
                    "image path": null,
                    "md5": "20cbe52b050fa5438428158323e4b0c2",
                    "name": "MsRPC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mssecflt.sys",
                    "image path": "system32\\drivers\\mssecflt.sys",
                    "md5": "e4c24f3d6d7968a7f98df30644fbf4c5",
                    "name": "MsSecFlt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\mssecflt.sys",
                    "image path": "system32\\drivers\\mssecflt.sys",
                    "md5": "e4c24f3d6d7968a7f98df30644fbf4c5",
                    "name": "MsSecFlt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mssmbios.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mssmbios.sys",
                    "md5": "530d7c0b3e2fc916fb0da8fc8d4b6ef6",
                    "name": "mssmbios",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mssmbios.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\mssmbios.sys",
                    "md5": "530d7c0b3e2fc916fb0da8fc8d4b6ef6",
                    "name": "mssmbios",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MSTEE.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MSTEE.sys",
                    "md5": "97c653356d853474dd0e51a37b1ccf84",
                    "name": "MSTEE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MSTEE.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MSTEE.sys",
                    "md5": "97c653356d853474dd0e51a37b1ccf84",
                    "name": "MSTEE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MTConfig.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MTConfig.sys",
                    "md5": "2e0dfbbe12b4fa54d4c1297db1052de6",
                    "name": "MTConfig",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\MTConfig.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\MTConfig.sys",
                    "md5": "2e0dfbbe12b4fa54d4c1297db1052de6",
                    "name": "MTConfig",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\mup.sys",
                    "image path": "System32\\Drivers\\mup.sys",
                    "md5": "265830023853939fcbf87ba954f3146a",
                    "name": "Mup",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\mup.sys",
                    "image path": "System32\\Drivers\\mup.sys",
                    "md5": "265830023853939fcbf87ba954f3146a",
                    "name": "Mup",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mvumis.sys",
                    "image path": "System32\\drivers\\mvumis.sys",
                    "md5": "c54659db8721c4f02bdfa0b15accfb10",
                    "name": "mvumis",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\mvumis.sys",
                    "image path": "System32\\drivers\\mvumis.sys",
                    "md5": "c54659db8721c4f02bdfa0b15accfb10",
                    "name": "mvumis",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ncasvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetSvcs -p",
                    "md5": "92a214400788becadf0b18b8bf4d42e6",
                    "name": "NcaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ncasvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetSvcs -p",
                    "md5": "92a214400788becadf0b18b8bf4d42e6",
                    "name": "NcaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ncasvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetSvcs -p",
                    "md5": "92a214400788becadf0b18b8bf4d42e6",
                    "name": "NcaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ncasvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetSvcs -p",
                    "md5": "92a214400788becadf0b18b8bf4d42e6",
                    "name": "NcaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ncbservice.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d07f20b05b5b5daddc4c0718e199877b",
                    "name": "NcbService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ncbservice.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d07f20b05b5b5daddc4c0718e199877b",
                    "name": "NcbService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ncbservice.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d07f20b05b5b5daddc4c0718e199877b",
                    "name": "NcbService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ncbservice.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d07f20b05b5b5daddc4c0718e199877b",
                    "name": "NcbService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ndfltr.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ndfltr.sys",
                    "md5": "a8a9bb0224cf38ad590328d6bcce0d18",
                    "name": "ndfltr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ndfltr.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ndfltr.sys",
                    "md5": "a8a9bb0224cf38ad590328d6bcce0d18",
                    "name": "ndfltr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ndis.sys",
                    "image path": "system32\\drivers\\ndis.sys",
                    "md5": "020222b426ce45d4081826902f1496d2",
                    "name": "NDIS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ndis.sys",
                    "image path": "system32\\drivers\\ndis.sys",
                    "md5": "020222b426ce45d4081826902f1496d2",
                    "name": "NDIS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ndiscap.sys",
                    "image path": "System32\\drivers\\ndiscap.sys",
                    "md5": "5c5dab38e24c46cc9e2ac793541780ed",
                    "name": "NdisCap",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ndiscap.sys",
                    "image path": "System32\\drivers\\ndiscap.sys",
                    "md5": "5c5dab38e24c46cc9e2ac793541780ed",
                    "name": "NdisCap",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\NdisImPlatform.sys",
                    "image path": "System32\\drivers\\NdisImPlatform.sys",
                    "md5": "e68595b477be8f6d05337cac4d156228",
                    "name": "NdisImPlatform",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\NdisImPlatform.sys",
                    "image path": "System32\\drivers\\NdisImPlatform.sys",
                    "md5": "e68595b477be8f6d05337cac4d156228",
                    "name": "NdisImPlatform",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\ndistapi.sys",
                    "image path": "System32\\DRIVERS\\ndistapi.sys",
                    "md5": "6246c8ec8b5db04688e42725f584635e",
                    "name": "NdisTapi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\ndistapi.sys",
                    "image path": "System32\\DRIVERS\\ndistapi.sys",
                    "md5": "6246c8ec8b5db04688e42725f584635e",
                    "name": "NdisTapi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ndisuio.sys",
                    "image path": "system32\\drivers\\ndisuio.sys",
                    "md5": "bddf8bbab954b94f4ce0e66ec2f24c78",
                    "name": "Ndisuio",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ndisuio.sys",
                    "image path": "system32\\drivers\\ndisuio.sys",
                    "md5": "bddf8bbab954b94f4ce0e66ec2f24c78",
                    "name": "Ndisuio",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\NdisVirtualBus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\NdisVirtualBus.sys",
                    "md5": "a686524719ece3235adae3e30214a2db",
                    "name": "NdisVirtualBus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\NdisVirtualBus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\NdisVirtualBus.sys",
                    "md5": "a686524719ece3235adae3e30214a2db",
                    "name": "NdisVirtualBus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ndiswan.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ndiswan.sys",
                    "md5": "64dba22a45afccc623933d7911fd4fa4",
                    "name": "NdisWan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ndiswan.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ndiswan.sys",
                    "md5": "64dba22a45afccc623933d7911fd4fa4",
                    "name": "NdisWan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\ndiswan.sys",
                    "image path": "System32\\DRIVERS\\ndiswan.sys",
                    "md5": "64dba22a45afccc623933d7911fd4fa4",
                    "name": "ndiswanlegacy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\ndiswan.sys",
                    "image path": "System32\\DRIVERS\\ndiswan.sys",
                    "md5": "64dba22a45afccc623933d7911fd4fa4",
                    "name": "ndiswanlegacy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\NDKPerf.sys",
                    "image path": "system32\\drivers\\NDKPerf.sys",
                    "md5": "867e8faa32f42f2c9de504bb77689ea5",
                    "name": "NDKPerf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\NDKPerf.sys",
                    "image path": "system32\\drivers\\NDKPerf.sys",
                    "md5": "867e8faa32f42f2c9de504bb77689ea5",
                    "name": "NDKPerf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\NDKPing.sys",
                    "image path": "system32\\drivers\\NDKPing.sys",
                    "md5": "0871957b5a113fb809dd430c3bd84617",
                    "name": "NDKPing",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\NDKPing.sys",
                    "image path": "system32\\drivers\\NDKPing.sys",
                    "md5": "0871957b5a113fb809dd430c3bd84617",
                    "name": "NDKPing",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\NDProxy.sys",
                    "image path": "System32\\DRIVERS\\NDProxy.sys",
                    "md5": "5394cd00f1a5e4e30069506bbed624a7",
                    "name": "ndproxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\NDProxy.sys",
                    "image path": "System32\\DRIVERS\\NDProxy.sys",
                    "md5": "5394cd00f1a5e4e30069506bbed624a7",
                    "name": "ndproxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\NetAdapterCx.sys",
                    "image path": "system32\\drivers\\NetAdapterCx.sys",
                    "md5": "c3d71757973b9cede4b6d702fd9fb14d",
                    "name": "NetAdapterCx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\NetAdapterCx.sys",
                    "image path": "system32\\drivers\\NetAdapterCx.sys",
                    "md5": "c3d71757973b9cede4b6d702fd9fb14d",
                    "name": "NetAdapterCx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\netbios.sys",
                    "image path": "system32\\drivers\\netbios.sys",
                    "md5": "9085e8233201b963ce447dc645670670",
                    "name": "NetBIOS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\netbios.sys",
                    "image path": "system32\\drivers\\netbios.sys",
                    "md5": "9085e8233201b963ce447dc645670670",
                    "name": "NetBIOS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\netbt.sys",
                    "image path": "System32\\DRIVERS\\netbt.sys",
                    "md5": "3937adb725a18a0dac7ae7c1e0efd2e4",
                    "name": "NetBT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\netbt.sys",
                    "image path": "System32\\DRIVERS\\netbt.sys",
                    "md5": "3937adb725a18a0dac7ae7c1e0efd2e4",
                    "name": "NetBT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\netlogon.dll",
                    "image path": "%systemroot%\\system32\\lsass.exe",
                    "md5": "8025ce86796a180c8f975718efc0bf55",
                    "name": "Netlogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\netlogon.dll",
                    "image path": "%systemroot%\\system32\\lsass.exe",
                    "md5": "8025ce86796a180c8f975718efc0bf55",
                    "name": "Netlogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\netlogon.dll",
                    "image path": "%systemroot%\\system32\\lsass.exe",
                    "md5": "8025ce86796a180c8f975718efc0bf55",
                    "name": "Netlogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\netlogon.dll",
                    "image path": "%systemroot%\\system32\\lsass.exe",
                    "md5": "8025ce86796a180c8f975718efc0bf55",
                    "name": "Netlogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\netman.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "184970c49f3edc8d05a62069827fba49",
                    "name": "Netman",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\netman.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "184970c49f3edc8d05a62069827fba49",
                    "name": "Netman",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\netman.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "184970c49f3edc8d05a62069827fba49",
                    "name": "Netman",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\netman.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "184970c49f3edc8d05a62069827fba49",
                    "name": "Netman",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\netprofmsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "4182817064a4bb800d373bf174c27db9",
                    "name": "netprofm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\netprofmsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "4182817064a4bb800d373bf174c27db9",
                    "name": "netprofm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\netprofmsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "4182817064a4bb800d373bf174c27db9",
                    "name": "netprofm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\netprofmsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "4182817064a4bb800d373bf174c27db9",
                    "name": "netprofm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\NetSetupSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "00e5e4717d2ebbd2743257657f852f93",
                    "name": "NetSetupSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\NetSetupSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "00e5e4717d2ebbd2743257657f852f93",
                    "name": "NetSetupSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\NetSetupSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "00e5e4717d2ebbd2743257657f852f93",
                    "name": "NetSetupSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\NetSetupSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "00e5e4717d2ebbd2743257657f852f93",
                    "name": "NetSetupSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\SMSvcHost.exe",
                    "image path": "%systemroot%\\Microsoft.NET\\Framework64\\v4.0.30319\\SMSvcHost.exe",
                    "md5": "de2afb6fe857a1c5c1fcf02a82459256",
                    "name": "NetTcpPortSharing",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\SMSvcHost.exe",
                    "image path": "%systemroot%\\Microsoft.NET\\Framework64\\v4.0.30319\\SMSvcHost.exe",
                    "md5": "de2afb6fe857a1c5c1fcf02a82459256",
                    "name": "NetTcpPortSharing",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\netvsc.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\netvsc.sys",
                    "md5": "71ead9b51b67d42a880cf50dd03c84fa",
                    "name": "netvsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\netvsc.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\netvsc.sys",
                    "md5": "71ead9b51b67d42a880cf50dd03c84fa",
                    "name": "netvsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\NgcCtnrSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "b399a73e72cf618881a2a6d1165c8c28",
                    "name": "NgcCtnrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\NgcCtnrSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "b399a73e72cf618881a2a6d1165c8c28",
                    "name": "NgcCtnrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\NgcCtnrSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "b399a73e72cf618881a2a6d1165c8c28",
                    "name": "NgcCtnrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\NgcCtnrSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "b399a73e72cf618881a2a6d1165c8c28",
                    "name": "NgcCtnrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\ngcsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d5e53f72930faab5b11e351543534f65",
                    "name": "NgcSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\ngcsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d5e53f72930faab5b11e351543534f65",
                    "name": "NgcSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\ngcsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d5e53f72930faab5b11e351543534f65",
                    "name": "NgcSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\ngcsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "d5e53f72930faab5b11e351543534f65",
                    "name": "NgcSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\nlasvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "11bac51af06a9f9414d909af79b6ae9c",
                    "name": "NlaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\nlasvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "11bac51af06a9f9414d909af79b6ae9c",
                    "name": "NlaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\nlasvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "11bac51af06a9f9414d909af79b6ae9c",
                    "name": "NlaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\nlasvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "11bac51af06a9f9414d909af79b6ae9c",
                    "name": "NlaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Npfs.sys",
                    "image path": null,
                    "md5": "3f4f4c10e7b81bc4b2d5c4c7e2c268a0",
                    "name": "Npfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Npfs.sys",
                    "image path": null,
                    "md5": "3f4f4c10e7b81bc4b2d5c4c7e2c268a0",
                    "name": "Npfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\npsvctrig.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\npsvctrig.sys",
                    "md5": "e6d73640ffe28611bebcf1af11ef18dc",
                    "name": "npsvctrig",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\npsvctrig.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\npsvctrig.sys",
                    "md5": "e6d73640ffe28611bebcf1af11ef18dc",
                    "name": "npsvctrig",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\nsisvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "fa24391609dbe1ae62394d16dc976e1c",
                    "name": "nsi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\nsisvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "fa24391609dbe1ae62394d16dc976e1c",
                    "name": "nsi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\nsisvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "fa24391609dbe1ae62394d16dc976e1c",
                    "name": "nsi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\nsisvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "fa24391609dbe1ae62394d16dc976e1c",
                    "name": "nsi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\nsiproxy.sys",
                    "image path": "system32\\drivers\\nsiproxy.sys",
                    "md5": "3a66f37dde3f8338cbd639b0106e38ca",
                    "name": "nsiproxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\nsiproxy.sys",
                    "image path": "system32\\drivers\\nsiproxy.sys",
                    "md5": "3a66f37dde3f8338cbd639b0106e38ca",
                    "name": "nsiproxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Ntfs.sys",
                    "image path": null,
                    "md5": "dd4cee5428499ccd02013ce6a591b600",
                    "name": "Ntfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Ntfs.sys",
                    "image path": null,
                    "md5": "dd4cee5428499ccd02013ce6a591b600",
                    "name": "Ntfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Null.sys",
                    "image path": null,
                    "md5": "85ab11a2f4fb94b9fb6a2d889d83fcac",
                    "name": "Null",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Null.sys",
                    "image path": null,
                    "md5": "85ab11a2f4fb94b9fb6a2d889d83fcac",
                    "name": "Null",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\nvdimm.sys",
                    "image path": "System32\\drivers\\nvdimm.sys",
                    "md5": "d9469d21cbd03665ec68ab2f3a24a1eb",
                    "name": "nvdimm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\nvdimm.sys",
                    "image path": "System32\\drivers\\nvdimm.sys",
                    "md5": "d9469d21cbd03665ec68ab2f3a24a1eb",
                    "name": "nvdimm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\nvraid.sys",
                    "image path": "System32\\drivers\\nvraid.sys",
                    "md5": "29186fc75a376fb9f87ac59d6dde8729",
                    "name": "nvraid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\nvraid.sys",
                    "image path": "System32\\drivers\\nvraid.sys",
                    "md5": "29186fc75a376fb9f87ac59d6dde8729",
                    "name": "nvraid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\nvstor.sys",
                    "image path": "System32\\drivers\\nvstor.sys",
                    "md5": "243047ac047939230b55d9c9da273b8d",
                    "name": "nvstor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\nvstor.sys",
                    "image path": "System32\\drivers\\nvstor.sys",
                    "md5": "243047ac047939230b55d9c9da273b8d",
                    "name": "nvstor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\parport.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\parport.sys",
                    "md5": "fdf95763ca52c62c7875ef2bd96736d5",
                    "name": "Parport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\parport.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\parport.sys",
                    "md5": "fdf95763ca52c62c7875ef2bd96736d5",
                    "name": "Parport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\partmgr.sys",
                    "image path": "System32\\drivers\\partmgr.sys",
                    "md5": "f68d2066b9f1a4fdb95613770c55c338",
                    "name": "partmgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\partmgr.sys",
                    "image path": "System32\\drivers\\partmgr.sys",
                    "md5": "f68d2066b9f1a4fdb95613770c55c338",
                    "name": "partmgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\pcasvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "b2d8231528950c24d9003b205a458dab",
                    "name": "PcaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\pcasvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "b2d8231528950c24d9003b205a458dab",
                    "name": "PcaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\pcasvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "b2d8231528950c24d9003b205a458dab",
                    "name": "PcaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\pcasvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "b2d8231528950c24d9003b205a458dab",
                    "name": "PcaSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pci.sys",
                    "image path": "System32\\drivers\\pci.sys",
                    "md5": "62e81f2f53126ec6e5149667de967897",
                    "name": "pci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pci.sys",
                    "image path": "System32\\drivers\\pci.sys",
                    "md5": "62e81f2f53126ec6e5149667de967897",
                    "name": "pci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pciide.sys",
                    "image path": "System32\\drivers\\pciide.sys",
                    "md5": "b97ddbe3cce4260be3117820f2dbda62",
                    "name": "pciide",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pciide.sys",
                    "image path": "System32\\drivers\\pciide.sys",
                    "md5": "b97ddbe3cce4260be3117820f2dbda62",
                    "name": "pciide",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pcmcia.sys",
                    "image path": "System32\\drivers\\pcmcia.sys",
                    "md5": "39ddff57a908a5d02cd856404ee3c585",
                    "name": "pcmcia",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pcmcia.sys",
                    "image path": "System32\\drivers\\pcmcia.sys",
                    "md5": "39ddff57a908a5d02cd856404ee3c585",
                    "name": "pcmcia",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pcw.sys",
                    "image path": "System32\\drivers\\pcw.sys",
                    "md5": "5f0c91ebcc8fd380306628283d0ad28d",
                    "name": "pcw",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pcw.sys",
                    "image path": "System32\\drivers\\pcw.sys",
                    "md5": "5f0c91ebcc8fd380306628283d0ad28d",
                    "name": "pcw",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\pdc.sys",
                    "image path": "system32\\drivers\\pdc.sys",
                    "md5": "5b34708a130a4aba61fabb66d3153aad",
                    "name": "pdc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\pdc.sys",
                    "image path": "system32\\drivers\\pdc.sys",
                    "md5": "5b34708a130a4aba61fabb66d3153aad",
                    "name": "pdc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\peauth.sys",
                    "image path": "system32\\drivers\\peauth.sys",
                    "md5": "e8789b5f24aa80994be1e2b27992af7c",
                    "name": "PEAUTH",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\peauth.sys",
                    "image path": "system32\\drivers\\peauth.sys",
                    "md5": "e8789b5f24aa80994be1e2b27992af7c",
                    "name": "PEAUTH",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\percsas2i.sys",
                    "image path": "System32\\drivers\\percsas2i.sys",
                    "md5": "578fbfcf65db8829735d67dbed2082e7",
                    "name": "percsas2i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\percsas2i.sys",
                    "image path": "System32\\drivers\\percsas2i.sys",
                    "md5": "578fbfcf65db8829735d67dbed2082e7",
                    "name": "percsas2i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\percsas3i.sys",
                    "image path": "System32\\drivers\\percsas3i.sys",
                    "md5": "f738a0c24ea52562b60be27b3fef2fb3",
                    "name": "percsas3i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\percsas3i.sys",
                    "image path": "System32\\drivers\\percsas3i.sys",
                    "md5": "f738a0c24ea52562b60be27b3fef2fb3",
                    "name": "percsas3i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\SysWow64\\perfhost.exe",
                    "image path": "%SystemRoot%\\SysWow64\\perfhost.exe",
                    "md5": "85d01ee143eba22431fbb032a6718702",
                    "name": "PerfHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\SysWow64\\perfhost.exe",
                    "image path": "%SystemRoot%\\SysWow64\\perfhost.exe",
                    "md5": "85d01ee143eba22431fbb032a6718702",
                    "name": "PerfHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PimIndexMaintenance.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "ec6832bc4413e0686c1cef4ac62e37eb",
                    "name": "PimIndexMaintenanceSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PimIndexMaintenance.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "ec6832bc4413e0686c1cef4ac62e37eb",
                    "name": "PimIndexMaintenanceSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PimIndexMaintenance.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "ec6832bc4413e0686c1cef4ac62e37eb",
                    "name": "PimIndexMaintenanceSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PimIndexMaintenance.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "ec6832bc4413e0686c1cef4ac62e37eb",
                    "name": "PimIndexMaintenanceSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "PimIndexMaintenanceSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\PktMon.sys",
                    "image path": "system32\\drivers\\PktMon.sys",
                    "md5": "2b79b5eaf063bf153478adb4455e5b51",
                    "name": "PktMon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\PktMon.sys",
                    "image path": "system32\\drivers\\PktMon.sys",
                    "md5": "2b79b5eaf063bf153478adb4455e5b51",
                    "name": "PktMon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\pla.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "101e0aa289c51a2aebba9584c00a17d2",
                    "name": "pla",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\pla.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "101e0aa289c51a2aebba9584c00a17d2",
                    "name": "pla",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\pla.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "101e0aa289c51a2aebba9584c00a17d2",
                    "name": "pla",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\pla.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "md5": "101e0aa289c51a2aebba9584c00a17d2",
                    "name": "pla",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpnpmgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "5d65d3b568357eb6ead5578a7b045ab2",
                    "name": "PlugPlay",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpnpmgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "5d65d3b568357eb6ead5578a7b045ab2",
                    "name": "PlugPlay",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpnpmgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "5d65d3b568357eb6ead5578a7b045ab2",
                    "name": "PlugPlay",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpnpmgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "5d65d3b568357eb6ead5578a7b045ab2",
                    "name": "PlugPlay",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pmem.sys",
                    "image path": "System32\\drivers\\pmem.sys",
                    "md5": "bdd445c92fd089cbaf962baede0e4fd4",
                    "name": "pmem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pmem.sys",
                    "image path": "System32\\drivers\\pmem.sys",
                    "md5": "bdd445c92fd089cbaf962baede0e4fd4",
                    "name": "pmem",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pnpmem.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\pnpmem.sys",
                    "md5": "ab2ad5e68a3378e5ac2db850e20a1a7b",
                    "name": "PNPMEM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pnpmem.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\pnpmem.sys",
                    "md5": "ab2ad5e68a3378e5ac2db850e20a1a7b",
                    "name": "PNPMEM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ipsecsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkServiceNetworkRestricted -p",
                    "md5": "b189d01b45c2ded6388f9c7accd6d254",
                    "name": "PolicyAgent",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ipsecsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkServiceNetworkRestricted -p",
                    "md5": "b189d01b45c2ded6388f9c7accd6d254",
                    "name": "PolicyAgent",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ipsecsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkServiceNetworkRestricted -p",
                    "md5": "b189d01b45c2ded6388f9c7accd6d254",
                    "name": "PolicyAgent",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ipsecsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkServiceNetworkRestricted -p",
                    "md5": "b189d01b45c2ded6388f9c7accd6d254",
                    "name": "PolicyAgent",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\portcfg.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\portcfg.sys",
                    "md5": "534abe9dd4e03dbfcf1bff0a252223a8",
                    "name": "portcfg",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\portcfg.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\portcfg.sys",
                    "md5": "534abe9dd4e03dbfcf1bff0a252223a8",
                    "name": "portcfg",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpo.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "926700fe6040b126f0982b21fb383d87",
                    "name": "Power",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpo.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "926700fe6040b126f0982b21fb383d87",
                    "name": "Power",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpo.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "926700fe6040b126f0982b21fb383d87",
                    "name": "Power",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\umpo.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "926700fe6040b126f0982b21fb383d87",
                    "name": "Power",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\raspptp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\raspptp.sys",
                    "md5": "d79cb39871091022344a6c105fdbd837",
                    "name": "PptpMiniport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\raspptp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\raspptp.sys",
                    "md5": "d79cb39871091022344a6c105fdbd837",
                    "name": "PptpMiniport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintConfig.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k print",
                    "md5": "eb66830971e030bb9625be333a2298a5",
                    "name": "PrintNotify",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintConfig.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k print",
                    "md5": "eb66830971e030bb9625be333a2298a5",
                    "name": "PrintNotify",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintConfig.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k print",
                    "md5": "eb66830971e030bb9625be333a2298a5",
                    "name": "PrintNotify",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\spool\\drivers\\x64\\3\\PrintConfig.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k print",
                    "md5": "eb66830971e030bb9625be333a2298a5",
                    "name": "PrintNotify",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PrintWorkflowService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k PrintWorkflow",
                    "md5": "5ecc28ea010394525a09c93e03573fc4",
                    "name": "PrintWorkflowUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PrintWorkflowService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k PrintWorkflow",
                    "md5": "5ecc28ea010394525a09c93e03573fc4",
                    "name": "PrintWorkflowUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PrintWorkflowService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k PrintWorkflow",
                    "md5": "5ecc28ea010394525a09c93e03573fc4",
                    "name": "PrintWorkflowUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\PrintWorkflowService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k PrintWorkflow",
                    "md5": "5ecc28ea010394525a09c93e03573fc4",
                    "name": "PrintWorkflowUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k PrintWorkflow",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "PrintWorkflowUserSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\prm.inf_amd64_5a6e1bc540be827c\\PRM.sys",
                    "image path": "System32\\DriverStore\\FileRepository\\prm.inf_amd64_5a6e1bc540be827c\\PRM.sys",
                    "md5": "12b48cb3274927c57bf770dea9476011",
                    "name": "PRM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\prm.inf_amd64_5a6e1bc540be827c\\PRM.sys",
                    "image path": "System32\\DriverStore\\FileRepository\\prm.inf_amd64_5a6e1bc540be827c\\PRM.sys",
                    "md5": "12b48cb3274927c57bf770dea9476011",
                    "name": "PRM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\processr.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\processr.sys",
                    "md5": "8f8d6ace001a0d6c9168bf4880ae9d81",
                    "name": "Processor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\processr.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\processr.sys",
                    "md5": "8f8d6ace001a0d6c9168bf4880ae9d81",
                    "name": "Processor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\profsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "58c403852c1d4c6da2ceeae7aa56f43d",
                    "name": "ProfSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\profsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "58c403852c1d4c6da2ceeae7aa56f43d",
                    "name": "ProfSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\profsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "58c403852c1d4c6da2ceeae7aa56f43d",
                    "name": "ProfSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\profsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "58c403852c1d4c6da2ceeae7aa56f43d",
                    "name": "ProfSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pacer.sys",
                    "image path": "System32\\drivers\\pacer.sys",
                    "md5": "39b1cf32f9c62caa14516259823d0291",
                    "name": "Psched",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pacer.sys",
                    "image path": "System32\\drivers\\pacer.sys",
                    "md5": "39b1cf32f9c62caa14516259823d0291",
                    "name": "Psched",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\PushToInstall.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "42a88b1a653492718f2c26651158c8f3",
                    "name": "PushToInstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\PushToInstall.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "42a88b1a653492718f2c26651158c8f3",
                    "name": "PushToInstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\PushToInstall.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "42a88b1a653492718f2c26651158c8f3",
                    "name": "PushToInstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\PushToInstall.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "42a88b1a653492718f2c26651158c8f3",
                    "name": "PushToInstall",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pvscsii.sys",
                    "image path": "System32\\drivers\\pvscsii.sys",
                    "md5": "e80d2e5e093644da1ac0872d625d6752",
                    "name": "pvscsi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\pvscsii.sys",
                    "image path": "System32\\drivers\\pvscsii.sys",
                    "md5": "e80d2e5e093644da1ac0872d625d6752",
                    "name": "pvscsi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\qevbda.sys",
                    "image path": "System32\\drivers\\qevbda.sys",
                    "md5": "900d88cb1bf10705c1409e7ac9ae61a4",
                    "name": "qebdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\qevbda.sys",
                    "image path": "System32\\drivers\\qevbda.sys",
                    "md5": "900d88cb1bf10705c1409e7ac9ae61a4",
                    "name": "qebdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\qefcoe.sys",
                    "image path": "System32\\drivers\\qefcoe.sys",
                    "md5": "f200e7701745b2619e5d182332b37e87",
                    "name": "qefcoe",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\qefcoe.sys",
                    "image path": "System32\\drivers\\qefcoe.sys",
                    "md5": "f200e7701745b2619e5d182332b37e87",
                    "name": "qefcoe",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\qeois.sys",
                    "image path": "System32\\drivers\\qeois.sys",
                    "md5": "e5d34b7d682ec146b0180ef389d03dff",
                    "name": "qeois",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\qeois.sys",
                    "image path": "System32\\drivers\\qeois.sys",
                    "md5": "e5d34b7d682ec146b0180ef389d03dff",
                    "name": "qeois",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ql2300i.sys",
                    "image path": "System32\\drivers\\ql2300i.sys",
                    "md5": "c678ec054dcb26483bc762beebb7ab3c",
                    "name": "ql2300i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ql2300i.sys",
                    "image path": "System32\\drivers\\ql2300i.sys",
                    "md5": "c678ec054dcb26483bc762beebb7ab3c",
                    "name": "ql2300i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ql40xx2i.sys",
                    "image path": "System32\\drivers\\ql40xx2i.sys",
                    "md5": "94fd2e9195bb97abea0014c125e5d7ea",
                    "name": "ql40xx2i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ql40xx2i.sys",
                    "image path": "System32\\drivers\\ql40xx2i.sys",
                    "md5": "94fd2e9195bb97abea0014c125e5d7ea",
                    "name": "ql40xx2i",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\qlfcoei.sys",
                    "image path": "System32\\drivers\\qlfcoei.sys",
                    "md5": "02ef30cd7625574283020a59085d4a2f",
                    "name": "qlfcoei",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\qlfcoei.sys",
                    "image path": "System32\\drivers\\qlfcoei.sys",
                    "md5": "02ef30cd7625574283020a59085d4a2f",
                    "name": "qlfcoei",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\qwave.dll",
                    "image path": "%windir%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "f67ccb5a7ea57978a5c555d6bc5751bb",
                    "name": "QWAVE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\qwave.dll",
                    "image path": "%windir%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "f67ccb5a7ea57978a5c555d6bc5751bb",
                    "name": "QWAVE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\qwave.dll",
                    "image path": "%windir%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "f67ccb5a7ea57978a5c555d6bc5751bb",
                    "name": "QWAVE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\qwave.dll",
                    "image path": "%windir%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "f67ccb5a7ea57978a5c555d6bc5751bb",
                    "name": "QWAVE",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\qwavedrv.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\qwavedrv.sys",
                    "md5": "82b66c526e937c9e0ede66eeaf23964f",
                    "name": "QWAVEdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\qwavedrv.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\qwavedrv.sys",
                    "md5": "82b66c526e937c9e0ede66eeaf23964f",
                    "name": "QWAVEdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\ramdisk.sys",
                    "image path": "system32\\DRIVERS\\ramdisk.sys",
                    "md5": "afd5c8d7b14bba338323200332ebbbb0",
                    "name": "Ramdisk",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\ramdisk.sys",
                    "image path": "system32\\DRIVERS\\ramdisk.sys",
                    "md5": "afd5c8d7b14bba338323200332ebbbb0",
                    "name": "Ramdisk",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\rasacd.sys",
                    "image path": "System32\\DRIVERS\\rasacd.sys",
                    "md5": "5dc4811804cfdfe9ef965df17005a1b8",
                    "name": "RasAcd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\rasacd.sys",
                    "image path": "System32\\DRIVERS\\rasacd.sys",
                    "md5": "5dc4811804cfdfe9ef965df17005a1b8",
                    "name": "RasAcd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\AgileVpn.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\AgileVpn.sys",
                    "md5": "76a21b57a6dd6c4faeca942c007be590",
                    "name": "RasAgileVpn",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\AgileVpn.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\AgileVpn.sys",
                    "md5": "76a21b57a6dd6c4faeca942c007be590",
                    "name": "RasAgileVpn",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\rasauto.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "1692ee33c3c9f5f7b59c7c6b8e118d38",
                    "name": "RasAuto",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\rasauto.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "1692ee33c3c9f5f7b59c7c6b8e118d38",
                    "name": "RasAuto",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\rasauto.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "1692ee33c3c9f5f7b59c7c6b8e118d38",
                    "name": "RasAuto",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\rasauto.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "1692ee33c3c9f5f7b59c7c6b8e118d38",
                    "name": "RasAuto",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rasgre.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rasgre.sys",
                    "md5": "6a27dbe5487c9e9967227f804b941379",
                    "name": "RasGre",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rasgre.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rasgre.sys",
                    "md5": "6a27dbe5487c9e9967227f804b941379",
                    "name": "RasGre",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rasl2tp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rasl2tp.sys",
                    "md5": "2c0e6162837cd608e4f962e99575c1b5",
                    "name": "Rasl2tp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rasl2tp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rasl2tp.sys",
                    "md5": "2c0e6162837cd608e4f962e99575c1b5",
                    "name": "Rasl2tp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\rasmans.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                    "md5": "55ff513cefc545379698ab8d38efe0a0",
                    "name": "RasMan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\rasmans.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                    "md5": "55ff513cefc545379698ab8d38efe0a0",
                    "name": "RasMan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\rasmans.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                    "md5": "55ff513cefc545379698ab8d38efe0a0",
                    "name": "RasMan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\rasmans.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                    "md5": "55ff513cefc545379698ab8d38efe0a0",
                    "name": "RasMan",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\raspppoe.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\raspppoe.sys",
                    "md5": "2370a643403c96274c4c9834ea1f0625",
                    "name": "RasPppoe",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\raspppoe.sys",
                    "image path": "System32\\DRIVERS\\raspppoe.sys",
                    "md5": "2370a643403c96274c4c9834ea1f0625",
                    "name": "RasPppoe",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rassstp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rassstp.sys",
                    "md5": "2cbdcde0f4b71e0af17c1ddad7543033",
                    "name": "RasSstp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rassstp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rassstp.sys",
                    "md5": "2cbdcde0f4b71e0af17c1ddad7543033",
                    "name": "RasSstp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\rdbss.sys",
                    "image path": "system32\\DRIVERS\\rdbss.sys",
                    "md5": "2e7eb447308f9c60e98a0c0c99ba4c78",
                    "name": "rdbss",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\rdbss.sys",
                    "image path": "system32\\DRIVERS\\rdbss.sys",
                    "md5": "2e7eb447308f9c60e98a0c0c99ba4c78",
                    "name": "rdbss",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rdpbus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rdpbus.sys",
                    "md5": "d1edd6604ed1a6e2bc45134c307d3e82",
                    "name": "rdpbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rdpbus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rdpbus.sys",
                    "md5": "d1edd6604ed1a6e2bc45134c307d3e82",
                    "name": "rdpbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rdpdr.sys",
                    "image path": "System32\\drivers\\rdpdr.sys",
                    "md5": "e63147974f4fc014742c5471c7bc516d",
                    "name": "RDPDR",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rdpdr.sys",
                    "image path": "System32\\drivers\\rdpdr.sys",
                    "md5": "e63147974f4fc014742c5471c7bc516d",
                    "name": "RDPDR",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rdpvideominiport.sys",
                    "image path": "System32\\drivers\\rdpvideominiport.sys",
                    "md5": "26fa006e8dc780d58158f58cf11fe3a3",
                    "name": "RdpVideoMiniport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rdpvideominiport.sys",
                    "image path": "System32\\drivers\\rdpvideominiport.sys",
                    "md5": "26fa006e8dc780d58158f58cf11fe3a3",
                    "name": "RdpVideoMiniport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ReFS.sys",
                    "image path": null,
                    "md5": "f8cbd1709a3917b9a53a047879d388e5",
                    "name": "ReFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ReFS.sys",
                    "image path": null,
                    "md5": "f8cbd1709a3917b9a53a047879d388e5",
                    "name": "ReFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ReFSv1.sys",
                    "image path": null,
                    "md5": "ea9e1467532b4b338c5083f8e531e3d9",
                    "name": "ReFSv1",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ReFSv1.sys",
                    "image path": null,
                    "md5": "ea9e1467532b4b338c5083f8e531e3d9",
                    "name": "ReFSv1",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mprdim.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                    "md5": "5a106f77d3ee0688f550fb69a386221a",
                    "name": "RemoteAccess",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mprdim.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                    "md5": "5a106f77d3ee0688f550fb69a386221a",
                    "name": "RemoteAccess",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mprdim.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                    "md5": "5a106f77d3ee0688f550fb69a386221a",
                    "name": "RemoteAccess",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\mprdim.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs",
                    "md5": "5a106f77d3ee0688f550fb69a386221a",
                    "name": "RemoteAccess",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\regsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k localService -p",
                    "md5": "beac0518aee7bc0a4898242af08d7578",
                    "name": "RemoteRegistry",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\regsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k localService -p",
                    "md5": "beac0518aee7bc0a4898242af08d7578",
                    "name": "RemoteRegistry",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\regsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k localService -p",
                    "md5": "beac0518aee7bc0a4898242af08d7578",
                    "name": "RemoteRegistry",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\regsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k localService -p",
                    "md5": "beac0518aee7bc0a4898242af08d7578",
                    "name": "RemoteRegistry",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rfcomm.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rfcomm.sys",
                    "md5": "f898fc38db316dbed55e4145b8f0b796",
                    "name": "RFCOMM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rfcomm.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rfcomm.sys",
                    "md5": "f898fc38db316dbed55e4145b8f0b796",
                    "name": "RFCOMM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rhproxy.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rhproxy.sys",
                    "md5": "5623471aef6871c17d97e5c8380e730e",
                    "name": "rhproxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\rhproxy.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\rhproxy.sys",
                    "md5": "5623471aef6871c17d97e5c8380e730e",
                    "name": "rhproxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\RMapi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
                    "md5": "6f1dd01e46352926cb337b80e356c11f",
                    "name": "RmSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\RMapi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
                    "md5": "6f1dd01e46352926cb337b80e356c11f",
                    "name": "RmSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\RMapi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
                    "md5": "6f1dd01e46352926cb337b80e356c11f",
                    "name": "RmSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\RMapi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
                    "md5": "6f1dd01e46352926cb337b80e356c11f",
                    "name": "RmSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\RpcEpMap.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k RPCSS -p",
                    "md5": "c3a6e8bff9b36bfcc3b3de14640ba4ac",
                    "name": "RpcEptMapper",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\RpcEpMap.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k RPCSS -p",
                    "md5": "c3a6e8bff9b36bfcc3b3de14640ba4ac",
                    "name": "RpcEptMapper",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\RpcEpMap.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k RPCSS -p",
                    "md5": "c3a6e8bff9b36bfcc3b3de14640ba4ac",
                    "name": "RpcEptMapper",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\RpcEpMap.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k RPCSS -p",
                    "md5": "c3a6e8bff9b36bfcc3b3de14640ba4ac",
                    "name": "RpcEptMapper",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\locator.exe",
                    "image path": "%SystemRoot%\\system32\\locator.exe",
                    "md5": "aff9819c7aaef41d21f5581f7d33d13d",
                    "name": "RpcLocator",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\locator.exe",
                    "image path": "%SystemRoot%\\system32\\locator.exe",
                    "md5": "aff9819c7aaef41d21f5581f7d33d13d",
                    "name": "RpcLocator",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rpcss.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k rpcss -p",
                    "md5": "3c8acb412e1a10b923b18a068f814901",
                    "name": "RpcSs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rpcss.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k rpcss -p",
                    "md5": "3c8acb412e1a10b923b18a068f814901",
                    "name": "RpcSs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rpcss.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k rpcss -p",
                    "md5": "3c8acb412e1a10b923b18a068f814901",
                    "name": "RpcSs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\rpcss.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k rpcss -p",
                    "md5": "3c8acb412e1a10b923b18a068f814901",
                    "name": "RpcSs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\RSoPProv.exe",
                    "image path": "%SystemRoot%\\system32\\RSoPProv.exe",
                    "md5": "a5ab506123009357c71b63cdbea3425b",
                    "name": "RSoPProv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\RSoPProv.exe",
                    "image path": "%SystemRoot%\\system32\\RSoPProv.exe",
                    "md5": "a5ab506123009357c71b63cdbea3425b",
                    "name": "RSoPProv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\rspndr.sys",
                    "image path": "system32\\drivers\\rspndr.sys",
                    "md5": "e66e50a0a3344a377838ef8b965a7f88",
                    "name": "rspndr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\rspndr.sys",
                    "image path": "system32\\drivers\\rspndr.sys",
                    "md5": "e66e50a0a3344a377838ef8b965a7f88",
                    "name": "rspndr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vms3cap.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vms3cap.sys",
                    "md5": "75524202b54c299e1d1378610f4a6671",
                    "name": "s3cap",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vms3cap.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vms3cap.sys",
                    "md5": "75524202b54c299e1d1378610f4a6671",
                    "name": "s3cap",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\sacdrv.sys",
                    "image path": "system32\\DRIVERS\\sacdrv.sys",
                    "md5": "aee01d5621b5824e65e0caed5715ba2e",
                    "name": "sacdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\sacdrv.sys",
                    "image path": "system32\\DRIVERS\\sacdrv.sys",
                    "md5": "aee01d5621b5824e65e0caed5715ba2e",
                    "name": "sacdrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sacsvr.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "3ba041aceccf6a653128edeb33e77ecc",
                    "name": "sacsvr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sacsvr.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "3ba041aceccf6a653128edeb33e77ecc",
                    "name": "sacsvr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sacsvr.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "3ba041aceccf6a653128edeb33e77ecc",
                    "name": "sacsvr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sacsvr.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "3ba041aceccf6a653128edeb33e77ecc",
                    "name": "sacsvr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\lsass.exe",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "6da2fcc580c720c16612057e83f47f04",
                    "name": "SamSs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\lsass.exe",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "6da2fcc580c720c16612057e83f47f04",
                    "name": "SamSs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sbp2port.sys",
                    "image path": "System32\\drivers\\sbp2port.sys",
                    "md5": "d1958f56eea564be9635b2f692c9017a",
                    "name": "sbp2port",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sbp2port.sys",
                    "image path": "System32\\drivers\\sbp2port.sys",
                    "md5": "d1958f56eea564be9635b2f692c9017a",
                    "name": "sbp2port",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SCardSvr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation",
                    "md5": "c04a72e85840c644271236bdc78c8636",
                    "name": "SCardSvr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SCardSvr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation",
                    "md5": "c04a72e85840c644271236bdc78c8636",
                    "name": "SCardSvr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SCardSvr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation",
                    "md5": "c04a72e85840c644271236bdc78c8636",
                    "name": "SCardSvr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SCardSvr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation",
                    "md5": "c04a72e85840c644271236bdc78c8636",
                    "name": "SCardSvr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ScDeviceEnum.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted",
                    "md5": "02f9f9643e07f01fb4102365eeb44ad0",
                    "name": "ScDeviceEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ScDeviceEnum.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted",
                    "md5": "02f9f9643e07f01fb4102365eeb44ad0",
                    "name": "ScDeviceEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ScDeviceEnum.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted",
                    "md5": "02f9f9643e07f01fb4102365eeb44ad0",
                    "name": "ScDeviceEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ScDeviceEnum.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted",
                    "md5": "02f9f9643e07f01fb4102365eeb44ad0",
                    "name": "ScDeviceEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\scfilter.sys",
                    "image path": "System32\\DRIVERS\\scfilter.sys",
                    "md5": "698a543a9df37aa83bccff659da38f85",
                    "name": "scfilter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\scfilter.sys",
                    "image path": "System32\\DRIVERS\\scfilter.sys",
                    "md5": "698a543a9df37aa83bccff659da38f85",
                    "name": "scfilter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\schedsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "3789725bc525f68f7200aad3361c5558",
                    "name": "Schedule",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\schedsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "3789725bc525f68f7200aad3361c5558",
                    "name": "Schedule",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\schedsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "3789725bc525f68f7200aad3361c5558",
                    "name": "Schedule",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\schedsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "3789725bc525f68f7200aad3361c5558",
                    "name": "Schedule",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\scmbus.sys",
                    "image path": "System32\\drivers\\scmbus.sys",
                    "md5": "d1b427d71c1857ca60e0121f0aa68602",
                    "name": "scmbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\scmbus.sys",
                    "image path": "System32\\drivers\\scmbus.sys",
                    "md5": "d1b427d71c1857ca60e0121f0aa68602",
                    "name": "scmbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\certprop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs",
                    "md5": "b4032b436f4ff0cc8f160a1f9f57de43",
                    "name": "SCPolicySvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\certprop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs",
                    "md5": "b4032b436f4ff0cc8f160a1f9f57de43",
                    "name": "SCPolicySvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\certprop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs",
                    "md5": "b4032b436f4ff0cc8f160a1f9f57de43",
                    "name": "SCPolicySvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\certprop.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs",
                    "md5": "b4032b436f4ff0cc8f160a1f9f57de43",
                    "name": "SCPolicySvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sdbus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\sdbus.sys",
                    "md5": "b428abd6fad6b549ef675edc7f12c6d5",
                    "name": "sdbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sdbus.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\sdbus.sys",
                    "md5": "b428abd6fad6b549ef675edc7f12c6d5",
                    "name": "sdbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\SDFRd.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\SDFRd.sys",
                    "md5": "0004013c04ec93784b35f9f1e6b77cb3",
                    "name": "SDFRd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\SDFRd.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\SDFRd.sys",
                    "md5": "0004013c04ec93784b35f9f1e6b77cb3",
                    "name": "SDFRd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sdstor.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\sdstor.sys",
                    "md5": "5374ebe59fb9e93931255540ba13dc7c",
                    "name": "sdstor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sdstor.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\sdstor.sys",
                    "md5": "5374ebe59fb9e93931255540ba13dc7c",
                    "name": "sdstor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\seclogon.dll",
                    "image path": "%windir%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "337ce4601a787141673eccc19da57d7a",
                    "name": "seclogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\seclogon.dll",
                    "image path": "%windir%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "337ce4601a787141673eccc19da57d7a",
                    "name": "seclogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\seclogon.dll",
                    "image path": "%windir%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "337ce4601a787141673eccc19da57d7a",
                    "name": "seclogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\seclogon.dll",
                    "image path": "%windir%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "337ce4601a787141673eccc19da57d7a",
                    "name": "seclogon",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SecurityHealthService.exe",
                    "image path": "%SystemRoot%\\system32\\SecurityHealthService.exe",
                    "md5": "ed5777a65aca7fdb2cf1c97a8641a6e6",
                    "name": "SecurityHealthService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SecurityHealthService.exe",
                    "image path": "%SystemRoot%\\system32\\SecurityHealthService.exe",
                    "md5": "ed5777a65aca7fdb2cf1c97a8641a6e6",
                    "name": "SecurityHealthService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SEMgrSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "5a6c720f0d3949f05babdd4db8d4bd59",
                    "name": "SEMgrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SEMgrSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "5a6c720f0d3949f05babdd4db8d4bd59",
                    "name": "SEMgrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SEMgrSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "5a6c720f0d3949f05babdd4db8d4bd59",
                    "name": "SEMgrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SEMgrSvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "5a6c720f0d3949f05babdd4db8d4bd59",
                    "name": "SEMgrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\sens.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "3da7adbecfdca14305726affe53fdda3",
                    "name": "SENS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\sens.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "3da7adbecfdca14305726affe53fdda3",
                    "name": "SENS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\sens.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "3da7adbecfdca14305726affe53fdda3",
                    "name": "SENS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\sens.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "3da7adbecfdca14305726affe53fdda3",
                    "name": "SENS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe",
                    "image path": "\"%ProgramFiles%\\Windows Defender Advanced Threat Protection\\MsSense.exe\"",
                    "md5": "95a7c860a1bd0791bd4928f631631b92",
                    "name": "Sense",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe",
                    "image path": "\"%ProgramFiles%\\Windows Defender Advanced Threat Protection\\MsSense.exe\"",
                    "md5": "95a7c860a1bd0791bd4928f631631b92",
                    "name": "Sense",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SensorDataService.exe",
                    "image path": "%SystemRoot%\\System32\\SensorDataService.exe",
                    "md5": "471a439de7075750c15ff42cc060cf38",
                    "name": "SensorDataService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SensorDataService.exe",
                    "image path": "%SystemRoot%\\System32\\SensorDataService.exe",
                    "md5": "471a439de7075750c15ff42cc060cf38",
                    "name": "SensorDataService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SensorService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "919c57818b859b96cea3bd6ae2543eff",
                    "name": "SensorService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SensorService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "919c57818b859b96cea3bd6ae2543eff",
                    "name": "SensorService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SensorService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "919c57818b859b96cea3bd6ae2543eff",
                    "name": "SensorService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SensorService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "919c57818b859b96cea3bd6ae2543eff",
                    "name": "SensorService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sensrsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "8ce42685aff02f52c12927f362fe0a2e",
                    "name": "SensrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sensrsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "8ce42685aff02f52c12927f362fe0a2e",
                    "name": "SensrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sensrsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "8ce42685aff02f52c12927f362fe0a2e",
                    "name": "SensrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sensrsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "8ce42685aff02f52c12927f362fe0a2e",
                    "name": "SensrSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\SerCx.sys",
                    "image path": "system32\\drivers\\SerCx.sys",
                    "md5": "a5a473940b02bb8903b71970e03c7734",
                    "name": "SerCx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\SerCx.sys",
                    "image path": "system32\\drivers\\SerCx.sys",
                    "md5": "a5a473940b02bb8903b71970e03c7734",
                    "name": "SerCx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\SerCx2.sys",
                    "image path": "system32\\drivers\\SerCx2.sys",
                    "md5": "657806499cccba28569bd906d6b40a82",
                    "name": "SerCx2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\SerCx2.sys",
                    "image path": "system32\\drivers\\SerCx2.sys",
                    "md5": "657806499cccba28569bd906d6b40a82",
                    "name": "SerCx2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\serenum.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\serenum.sys",
                    "md5": "998820b3e4ff8a57eff0486c3e72d573",
                    "name": "Serenum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\serenum.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\serenum.sys",
                    "md5": "998820b3e4ff8a57eff0486c3e72d573",
                    "name": "Serenum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\serial.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\serial.sys",
                    "md5": "d485142c2b7b17c926d4c32ab60c88b4",
                    "name": "Serial",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\serial.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\serial.sys",
                    "md5": "d485142c2b7b17c926d4c32ab60c88b4",
                    "name": "Serial",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sermouse.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\sermouse.sys",
                    "md5": "89dbdd34019916875834c61095a7ddc4",
                    "name": "sermouse",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sermouse.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\sermouse.sys",
                    "md5": "89dbdd34019916875834c61095a7ddc4",
                    "name": "sermouse",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sessenv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "609275cbb20b61911aae5e422b0f2b3f",
                    "name": "SessionEnv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sessenv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "609275cbb20b61911aae5e422b0f2b3f",
                    "name": "SessionEnv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sessenv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "609275cbb20b61911aae5e422b0f2b3f",
                    "name": "SessionEnv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sessenv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "609275cbb20b61911aae5e422b0f2b3f",
                    "name": "SessionEnv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sfloppy.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\sfloppy.sys",
                    "md5": "c82e4f4beb15001ea098644626c33ed3",
                    "name": "sfloppy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sfloppy.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\sfloppy.sys",
                    "md5": "c82e4f4beb15001ea098644626c33ed3",
                    "name": "sfloppy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\SgrmAgent.sys",
                    "image path": "system32\\drivers\\SgrmAgent.sys",
                    "md5": "e81fdb11bb9dc3b743d07402ab0d6850",
                    "name": "SgrmAgent",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\SgrmAgent.sys",
                    "image path": "system32\\drivers\\SgrmAgent.sys",
                    "md5": "e81fdb11bb9dc3b743d07402ab0d6850",
                    "name": "SgrmAgent",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SgrmBroker.exe",
                    "image path": "%SystemRoot%\\system32\\SgrmBroker.exe",
                    "md5": "9acb4f0b740038cde52091a797ac6968",
                    "name": "SgrmBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SgrmBroker.exe",
                    "image path": "%SystemRoot%\\system32\\SgrmBroker.exe",
                    "md5": "9acb4f0b740038cde52091a797ac6968",
                    "name": "SgrmBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ipnathlp.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "7628f5c8d8fae2ab2f4f375cf1fef095",
                    "name": "SharedAccess",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ipnathlp.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "7628f5c8d8fae2ab2f4f375cf1fef095",
                    "name": "SharedAccess",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ipnathlp.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "7628f5c8d8fae2ab2f4f375cf1fef095",
                    "name": "SharedAccess",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ipnathlp.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "7628f5c8d8fae2ab2f4f375cf1fef095",
                    "name": "SharedAccess",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\shsvcs.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "504a59ce49b77005a64a61f859b22e5a",
                    "name": "ShellHWDetection",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\shsvcs.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "504a59ce49b77005a64a61f859b22e5a",
                    "name": "ShellHWDetection",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\shsvcs.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "504a59ce49b77005a64a61f859b22e5a",
                    "name": "ShellHWDetection",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\shsvcs.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "504a59ce49b77005a64a61f859b22e5a",
                    "name": "ShellHWDetection",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Windows.SharedPC.AccountManager.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "8420e162331d9fcb642773ce518de3e5",
                    "name": "shpamsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Windows.SharedPC.AccountManager.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "8420e162331d9fcb642773ce518de3e5",
                    "name": "shpamsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Windows.SharedPC.AccountManager.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "8420e162331d9fcb642773ce518de3e5",
                    "name": "shpamsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Windows.SharedPC.AccountManager.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "8420e162331d9fcb642773ce518de3e5",
                    "name": "shpamsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\SiSRaid2.sys",
                    "image path": "System32\\drivers\\SiSRaid2.sys",
                    "md5": "dbac632a8e204a01cd97c622551b64d1",
                    "name": "SiSRaid2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\SiSRaid2.sys",
                    "image path": "System32\\drivers\\SiSRaid2.sys",
                    "md5": "dbac632a8e204a01cd97c622551b64d1",
                    "name": "SiSRaid2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sisraid4.sys",
                    "image path": "System32\\drivers\\sisraid4.sys",
                    "md5": "ed08641f88a7e1a3e439cd2ce67a21f5",
                    "name": "SiSRaid4",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\sisraid4.sys",
                    "image path": "System32\\drivers\\sisraid4.sys",
                    "md5": "ed08641f88a7e1a3e439cd2ce67a21f5",
                    "name": "SiSRaid4",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\SmartSAMD.sys",
                    "image path": "System32\\drivers\\SmartSAMD.sys",
                    "md5": "644210ec45cf61bce5fcc78e7cc535d6",
                    "name": "SmartSAMD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\SmartSAMD.sys",
                    "image path": "System32\\drivers\\SmartSAMD.sys",
                    "md5": "644210ec45cf61bce5fcc78e7cc535d6",
                    "name": "SmartSAMD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\smbdirect.sys",
                    "image path": "System32\\DRIVERS\\smbdirect.sys",
                    "md5": "0398fa5772f947049ab890a798ecf88f",
                    "name": "smbdirect",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\smbdirect.sys",
                    "image path": "System32\\DRIVERS\\smbdirect.sys",
                    "md5": "0398fa5772f947049ab890a798ecf88f",
                    "name": "smbdirect",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\smphost.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k smphost",
                    "md5": "56891ea4699b7da217c9556d6f032947",
                    "name": "smphost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\smphost.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k smphost",
                    "md5": "56891ea4699b7da217c9556d6f032947",
                    "name": "smphost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\smphost.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k smphost",
                    "md5": "56891ea4699b7da217c9556d6f032947",
                    "name": "smphost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\smphost.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k smphost",
                    "md5": "56891ea4699b7da217c9556d6f032947",
                    "name": "smphost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\snmptrap.exe",
                    "image path": "%SystemRoot%\\System32\\snmptrap.exe",
                    "md5": "81e215d60dd0ead23cd19b0fd6cc6501",
                    "name": "SNMPTRAP",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\snmptrap.exe",
                    "image path": "%SystemRoot%\\System32\\snmptrap.exe",
                    "md5": "81e215d60dd0ead23cd19b0fd6cc6501",
                    "name": "SNMPTRAP",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\spaceparser.sys",
                    "image path": "system32\\drivers\\spaceparser.sys",
                    "md5": "1175f02198005218864a36f2768e52e4",
                    "name": "spaceparser",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\spaceparser.sys",
                    "image path": "system32\\drivers\\spaceparser.sys",
                    "md5": "1175f02198005218864a36f2768e52e4",
                    "name": "spaceparser",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\spaceport.sys",
                    "image path": "System32\\drivers\\spaceport.sys",
                    "md5": "7d38fe01b3309a01119b19b1a807673b",
                    "name": "spaceport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\spaceport.sys",
                    "image path": "System32\\drivers\\spaceport.sys",
                    "md5": "7d38fe01b3309a01119b19b1a807673b",
                    "name": "spaceport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\SpbCx.sys",
                    "image path": "system32\\drivers\\SpbCx.sys",
                    "md5": "e9e4a7f68b8d7044077db9978e0b9f5b",
                    "name": "SpbCx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\SpbCx.sys",
                    "image path": "system32\\drivers\\SpbCx.sys",
                    "md5": "e9e4a7f68b8d7044077db9978e0b9f5b",
                    "name": "SpbCx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\spoolsv.exe",
                    "image path": "%SystemRoot%\\System32\\spoolsv.exe",
                    "md5": "55bb3facc6ef795f6f1d8cc656bcb779",
                    "name": "Spooler",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\spoolsv.exe",
                    "image path": "%SystemRoot%\\System32\\spoolsv.exe",
                    "md5": "55bb3facc6ef795f6f1d8cc656bcb779",
                    "name": "Spooler",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sppsvc.exe",
                    "image path": "%SystemRoot%\\system32\\sppsvc.exe",
                    "md5": "c05a6baecd2bee1122a82dd3c3252ab6",
                    "name": "sppsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sppsvc.exe",
                    "image path": "%SystemRoot%\\system32\\sppsvc.exe",
                    "md5": "c05a6baecd2bee1122a82dd3c3252ab6",
                    "name": "sppsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\srv2.sys",
                    "image path": "System32\\DRIVERS\\srv2.sys",
                    "md5": "ccfe129cbdea8b8c6051d11c6c694230",
                    "name": "srv2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\srv2.sys",
                    "image path": "System32\\DRIVERS\\srv2.sys",
                    "md5": "ccfe129cbdea8b8c6051d11c6c694230",
                    "name": "srv2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\srvnet.sys",
                    "image path": "System32\\DRIVERS\\srvnet.sys",
                    "md5": "fdfcf9c6d6bec82925b2e52926acbbb2",
                    "name": "srvnet",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\srvnet.sys",
                    "image path": "System32\\DRIVERS\\srvnet.sys",
                    "md5": "fdfcf9c6d6bec82925b2e52926acbbb2",
                    "name": "srvnet",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ssdpsrv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "a8108d5f8bd7ca52673aabfa5b4308d1",
                    "name": "SSDPSRV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ssdpsrv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "a8108d5f8bd7ca52673aabfa5b4308d1",
                    "name": "SSDPSRV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ssdpsrv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "a8108d5f8bd7ca52673aabfa5b4308d1",
                    "name": "SSDPSRV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ssdpsrv.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "a8108d5f8bd7ca52673aabfa5b4308d1",
                    "name": "SSDPSRV",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\OpenSSH\\ssh-agent.exe",
                    "image path": "%SystemRoot%\\System32\\OpenSSH\\ssh-agent.exe",
                    "md5": "66969aa56e77953e596470c73a9004e0",
                    "name": "ssh-agent",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\OpenSSH\\ssh-agent.exe",
                    "image path": "%SystemRoot%\\System32\\OpenSSH\\ssh-agent.exe",
                    "md5": "66969aa56e77953e596470c73a9004e0",
                    "name": "ssh-agent",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\OpenSSH-Win64\\sshd.exe",
                    "image path": "C:\\Program Files\\OpenSSH-Win64\\sshd.exe",
                    "md5": "331ba0e529810ef718dd3efbd1242302",
                    "name": "sshd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\OpenSSH-Win64\\sshd.exe",
                    "image path": "C:\\Program Files\\OpenSSH-Win64\\sshd.exe",
                    "md5": "331ba0e529810ef718dd3efbd1242302",
                    "name": "sshd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sstpsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "7f1742f83f220e2ca34d16b5d829c00e",
                    "name": "SstpSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sstpsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "7f1742f83f220e2ca34d16b5d829c00e",
                    "name": "SstpSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sstpsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "7f1742f83f220e2ca34d16b5d829c00e",
                    "name": "SstpSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sstpsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "7f1742f83f220e2ca34d16b5d829c00e",
                    "name": "SstpSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\windows.staterepository.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "3d1971318a057084d7d896b27b3bb4b3",
                    "name": "StateRepository",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\windows.staterepository.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "3d1971318a057084d7d896b27b3bb4b3",
                    "name": "StateRepository",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\windows.staterepository.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "3d1971318a057084d7d896b27b3bb4b3",
                    "name": "StateRepository",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\windows.staterepository.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k appmodel -p",
                    "md5": "3d1971318a057084d7d896b27b3bb4b3",
                    "name": "StateRepository",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\stexstor.sys",
                    "image path": "System32\\drivers\\stexstor.sys",
                    "md5": "90a4646b1c287fcf723657778e55d93e",
                    "name": "stexstor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\stexstor.sys",
                    "image path": "System32\\drivers\\stexstor.sys",
                    "md5": "90a4646b1c287fcf723657778e55d93e",
                    "name": "stexstor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wiaservc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k imgsvc",
                    "md5": "91c317c2ccc8fc8a28aa9972599ee456",
                    "name": "StiSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wiaservc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k imgsvc",
                    "md5": "91c317c2ccc8fc8a28aa9972599ee456",
                    "name": "StiSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wiaservc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k imgsvc",
                    "md5": "91c317c2ccc8fc8a28aa9972599ee456",
                    "name": "StiSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wiaservc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k imgsvc",
                    "md5": "91c317c2ccc8fc8a28aa9972599ee456",
                    "name": "StiSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\storahci.sys",
                    "image path": "System32\\drivers\\storahci.sys",
                    "md5": "ed739b05ba3210ea45b0ad74e4df167b",
                    "name": "storahci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\storahci.sys",
                    "image path": "System32\\drivers\\storahci.sys",
                    "md5": "ed739b05ba3210ea45b0ad74e4df167b",
                    "name": "storahci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vmstorfl.sys",
                    "image path": "System32\\drivers\\vmstorfl.sys",
                    "md5": "915d638cc3779c578ebb3072b80d6a1f",
                    "name": "storflt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vmstorfl.sys",
                    "image path": "System32\\drivers\\vmstorfl.sys",
                    "md5": "915d638cc3779c578ebb3072b80d6a1f",
                    "name": "storflt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\stornvme.sys",
                    "image path": "System32\\drivers\\stornvme.sys",
                    "md5": "98629205055d6b74030701d2b8ff2767",
                    "name": "stornvme",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\stornvme.sys",
                    "image path": "System32\\drivers\\stornvme.sys",
                    "md5": "98629205055d6b74030701d2b8ff2767",
                    "name": "stornvme",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\storqosflt.sys",
                    "image path": "system32\\drivers\\storqosflt.sys",
                    "md5": "966997d2b3ebe8ea30ec42101dbe5768",
                    "name": "storqosflt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\storqosflt.sys",
                    "image path": "system32\\drivers\\storqosflt.sys",
                    "md5": "966997d2b3ebe8ea30ec42101dbe5768",
                    "name": "storqosflt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\storsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "148ced66d982648cd8d3169d5a5ae77b",
                    "name": "StorSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\storsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "148ced66d982648cd8d3169d5a5ae77b",
                    "name": "StorSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\storsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "148ced66d982648cd8d3169d5a5ae77b",
                    "name": "StorSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\storsvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "148ced66d982648cd8d3169d5a5ae77b",
                    "name": "StorSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\storufs.sys",
                    "image path": "System32\\drivers\\storufs.sys",
                    "md5": "7234edc80f3240b5b5218b862d54add3",
                    "name": "storufs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\storufs.sys",
                    "image path": "System32\\drivers\\storufs.sys",
                    "md5": "7234edc80f3240b5b5218b862d54add3",
                    "name": "storufs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\storvsc.sys",
                    "image path": "System32\\drivers\\storvsc.sys",
                    "md5": "9d09cb815bfe76fc9929a4c176f2f57c",
                    "name": "storvsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\storvsc.sys",
                    "image path": "System32\\drivers\\storvsc.sys",
                    "md5": "9d09cb815bfe76fc9929a4c176f2f57c",
                    "name": "storvsc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "db9daed6df328f3c6443c78921723e21",
                    "name": "svsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "db9daed6df328f3c6443c78921723e21",
                    "name": "svsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "db9daed6df328f3c6443c78921723e21",
                    "name": "svsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "db9daed6df328f3c6443c78921723e21",
                    "name": "svsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\swenum.inf_amd64_a8eddc34aa14df5f\\swenum.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\swenum.inf_amd64_a8eddc34aa14df5f\\swenum.sys",
                    "md5": "0d8210a54c87102db6f0406b1c265a9c",
                    "name": "swenum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\swenum.inf_amd64_a8eddc34aa14df5f\\swenum.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\swenum.inf_amd64_a8eddc34aa14df5f\\swenum.sys",
                    "md5": "0d8210a54c87102db6f0406b1c265a9c",
                    "name": "swenum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\swprv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k swprv",
                    "md5": "57430ad32d0775779a3d86aed1e0103a",
                    "name": "swprv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\swprv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k swprv",
                    "md5": "57430ad32d0775779a3d86aed1e0103a",
                    "name": "swprv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\swprv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k swprv",
                    "md5": "57430ad32d0775779a3d86aed1e0103a",
                    "name": "swprv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\swprv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k swprv",
                    "md5": "57430ad32d0775779a3d86aed1e0103a",
                    "name": "swprv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sysmain.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "a56113c4d934ff9ea7953d8e0b60d7db",
                    "name": "SysMain",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sysmain.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "a56113c4d934ff9ea7953d8e0b60d7db",
                    "name": "SysMain",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sysmain.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "a56113c4d934ff9ea7953d8e0b60d7db",
                    "name": "SysMain",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\sysmain.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "a56113c4d934ff9ea7953d8e0b60d7db",
                    "name": "SysMain",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SystemEventsBrokerServer.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "ddd397fa0c2c6ba7c1c3f912139f2ae2",
                    "name": "SystemEventsBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SystemEventsBrokerServer.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "ddd397fa0c2c6ba7c1c3f912139f2ae2",
                    "name": "SystemEventsBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SystemEventsBrokerServer.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "ddd397fa0c2c6ba7c1c3f912139f2ae2",
                    "name": "SystemEventsBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\SystemEventsBrokerServer.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k DcomLaunch -p",
                    "md5": "ddd397fa0c2c6ba7c1c3f912139f2ae2",
                    "name": "SystemEventsBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TabSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "307da9194ceecd8edf9601473e7dfbbf",
                    "name": "TabletInputService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TabSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "307da9194ceecd8edf9601473e7dfbbf",
                    "name": "TabletInputService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TabSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "307da9194ceecd8edf9601473e7dfbbf",
                    "name": "TabletInputService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TabSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "307da9194ceecd8edf9601473e7dfbbf",
                    "name": "TabletInputService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\tapisrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "d6428a209852a9c44ffc08985bc5f38e",
                    "name": "tapisrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\tapisrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "d6428a209852a9c44ffc08985bc5f38e",
                    "name": "tapisrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\tapisrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "d6428a209852a9c44ffc08985bc5f38e",
                    "name": "tapisrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\tapisrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "d6428a209852a9c44ffc08985bc5f38e",
                    "name": "tapisrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tcpip.sys",
                    "image path": "System32\\drivers\\tcpip.sys",
                    "md5": "8a13f21e7fb8f78a3d01bb952f691242",
                    "name": "Tcpip",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tcpip.sys",
                    "image path": "System32\\drivers\\tcpip.sys",
                    "md5": "8a13f21e7fb8f78a3d01bb952f691242",
                    "name": "Tcpip",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tcpip.sys",
                    "image path": "System32\\drivers\\tcpip.sys",
                    "md5": "8a13f21e7fb8f78a3d01bb952f691242",
                    "name": "Tcpip6",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tcpip.sys",
                    "image path": "System32\\drivers\\tcpip.sys",
                    "md5": "8a13f21e7fb8f78a3d01bb952f691242",
                    "name": "Tcpip6",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tcpipreg.sys",
                    "image path": "System32\\drivers\\tcpipreg.sys",
                    "md5": "6a7338ae6e83bf75f2057b7b1242f81b",
                    "name": "tcpipreg",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tcpipreg.sys",
                    "image path": "System32\\drivers\\tcpipreg.sys",
                    "md5": "6a7338ae6e83bf75f2057b7b1242f81b",
                    "name": "tcpipreg",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\tdx.sys",
                    "image path": "\\SystemRoot\\system32\\DRIVERS\\tdx.sys",
                    "md5": "7fd3d3e74c586e48b1fe6a26d9041a5a",
                    "name": "tdx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\tdx.sys",
                    "image path": "\\SystemRoot\\system32\\DRIVERS\\tdx.sys",
                    "md5": "7fd3d3e74c586e48b1fe6a26d9041a5a",
                    "name": "tdx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\terminpt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\terminpt.sys",
                    "md5": "a073581102fca9e17a1a4a5a40542d5c",
                    "name": "terminpt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\terminpt.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\terminpt.sys",
                    "md5": "a073581102fca9e17a1a4a5a40542d5c",
                    "name": "terminpt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\termsrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k termsvcs",
                    "md5": "408de68076ad4894a53c5e8a7f31885b",
                    "name": "TermService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\termsrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k termsvcs",
                    "md5": "408de68076ad4894a53c5e8a7f31885b",
                    "name": "TermService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\termsrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k termsvcs",
                    "md5": "408de68076ad4894a53c5e8a7f31885b",
                    "name": "TermService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\termsrv.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k termsvcs",
                    "md5": "408de68076ad4894a53c5e8a7f31885b",
                    "name": "TermService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\themeservice.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "b8f6f18f13d0f7b719e0c60e083c1b12",
                    "name": "Themes",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\themeservice.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "b8f6f18f13d0f7b719e0c60e083c1b12",
                    "name": "Themes",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\themeservice.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "b8f6f18f13d0f7b719e0c60e083c1b12",
                    "name": "Themes",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\themeservice.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "b8f6f18f13d0f7b719e0c60e083c1b12",
                    "name": "Themes",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\TieringEngineService.exe",
                    "image path": "%SystemRoot%\\system32\\TieringEngineService.exe",
                    "md5": "a86dc1b6dc847669ef04a290fe53dd00",
                    "name": "TieringEngineService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\TieringEngineService.exe",
                    "image path": "%SystemRoot%\\system32\\TieringEngineService.exe",
                    "md5": "a86dc1b6dc847669ef04a290fe53dd00",
                    "name": "TieringEngineService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TimeBrokerServer.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "d79295826bdbdac19b9bb4d2c3c2e8a8",
                    "name": "TimeBrokerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TimeBrokerServer.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "d79295826bdbdac19b9bb4d2c3c2e8a8",
                    "name": "TimeBrokerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TimeBrokerServer.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "d79295826bdbdac19b9bb4d2c3c2e8a8",
                    "name": "TimeBrokerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TimeBrokerServer.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "d79295826bdbdac19b9bb4d2c3c2e8a8",
                    "name": "TimeBrokerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TokenBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "8b93cad690967f1d6a942b3bba816604",
                    "name": "TokenBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TokenBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "8b93cad690967f1d6a942b3bba816604",
                    "name": "TokenBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TokenBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "8b93cad690967f1d6a942b3bba816604",
                    "name": "TokenBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\TokenBroker.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "8b93cad690967f1d6a942b3bba816604",
                    "name": "TokenBroker",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tpm.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\tpm.sys",
                    "md5": "d8bfc4be0dba61d02d4ecfa68c668204",
                    "name": "TPM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tpm.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\tpm.sys",
                    "md5": "d8bfc4be0dba61d02d4ecfa68c668204",
                    "name": "TPM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\trkwks.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "522201273cab50fa6f41f999b1bc44a5",
                    "name": "TrkWks",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\trkwks.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "522201273cab50fa6f41f999b1bc44a5",
                    "name": "TrkWks",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\trkwks.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "522201273cab50fa6f41f999b1bc44a5",
                    "name": "TrkWks",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\trkwks.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "522201273cab50fa6f41f999b1bc44a5",
                    "name": "TrkWks",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\servicing\\TrustedInstaller.exe",
                    "image path": "%SystemRoot%\\servicing\\TrustedInstaller.exe",
                    "md5": "464d0d44c67dd965ee607cfcd99a48ab",
                    "name": "TrustedInstaller",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\servicing\\TrustedInstaller.exe",
                    "image path": "%SystemRoot%\\servicing\\TrustedInstaller.exe",
                    "md5": "464d0d44c67dd965ee607cfcd99a48ab",
                    "name": "TrustedInstaller",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tsusbflt.sys",
                    "image path": "system32\\drivers\\tsusbflt.sys",
                    "md5": "c7ef4debfff35287052f8b5df077b138",
                    "name": "TsUsbFlt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tsusbflt.sys",
                    "image path": "system32\\drivers\\tsusbflt.sys",
                    "md5": "c7ef4debfff35287052f8b5df077b138",
                    "name": "TsUsbFlt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\TsUsbGD.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\TsUsbGD.sys",
                    "md5": "343d97bbb8f0ade9537c6e0642090f31",
                    "name": "TsUsbGD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\TsUsbGD.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\TsUsbGD.sys",
                    "md5": "343d97bbb8f0ade9537c6e0642090f31",
                    "name": "TsUsbGD",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\tsusbhub.sys",
                    "image path": "system32\\drivers\\tsusbhub.sys",
                    "md5": "aa22a654c950d0d9b0dbb051f7455a1e",
                    "name": "tsusbhub",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tsusbhub.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\tsusbhub.sys",
                    "md5": "aa22a654c950d0d9b0dbb051f7455a1e",
                    "name": "tsusbhub",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tunnel.sys",
                    "image path": "System32\\drivers\\tunnel.sys",
                    "md5": "71710339da40b739532ea5ec00a610e7",
                    "name": "tunnel",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\tunnel.sys",
                    "image path": "System32\\drivers\\tunnel.sys",
                    "md5": "71710339da40b739532ea5ec00a610e7",
                    "name": "tunnel",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\tzautoupdate.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "72a1a55ac95142d4df5e345c05c1390b",
                    "name": "tzautoupdate",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\tzautoupdate.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "72a1a55ac95142d4df5e345c05c1390b",
                    "name": "tzautoupdate",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\tzautoupdate.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "72a1a55ac95142d4df5e345c05c1390b",
                    "name": "tzautoupdate",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\tzautoupdate.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService -p",
                    "md5": "72a1a55ac95142d4df5e345c05c1390b",
                    "name": "tzautoupdate",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ualsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "9d643d3236bdbc54a009877381a25600",
                    "name": "UALSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ualsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "9d643d3236bdbc54a009877381a25600",
                    "name": "UALSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ualsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "9d643d3236bdbc54a009877381a25600",
                    "name": "UALSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\ualsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "9d643d3236bdbc54a009877381a25600",
                    "name": "UALSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\uaspstor.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\uaspstor.sys",
                    "md5": "23136b24331d2b0e8ce40dca04320b97",
                    "name": "UASPStor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\uaspstor.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\uaspstor.sys",
                    "md5": "23136b24331d2b0e8ce40dca04320b97",
                    "name": "UASPStor",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\UcmCx.sys",
                    "image path": "System32\\Drivers\\UcmCx.sys",
                    "md5": "679f70e6af7c9b4df0b7f5c5f7d3e59c",
                    "name": "UcmCx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\UcmCx.sys",
                    "image path": "System32\\Drivers\\UcmCx.sys",
                    "md5": "679f70e6af7c9b4df0b7f5c5f7d3e59c",
                    "name": "UcmCx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\UcmTcpciCx.sys",
                    "image path": "System32\\Drivers\\UcmTcpciCx.sys",
                    "md5": "e34582b17639772b47a3950dcc163c50",
                    "name": "UcmTcpciCx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\UcmTcpciCx.sys",
                    "image path": "System32\\Drivers\\UcmTcpciCx.sys",
                    "md5": "e34582b17639772b47a3950dcc163c50",
                    "name": "UcmTcpciCx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\UcmUcsiAcpiClient.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\UcmUcsiAcpiClient.sys",
                    "md5": "46c4630a57f302bc2711a0b1f1e7a2cd",
                    "name": "UcmUcsiAcpiClient",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\UcmUcsiAcpiClient.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\UcmUcsiAcpiClient.sys",
                    "md5": "46c4630a57f302bc2711a0b1f1e7a2cd",
                    "name": "UcmUcsiAcpiClient",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\UcmUcsiCx.sys",
                    "image path": "System32\\Drivers\\UcmUcsiCx.sys",
                    "md5": "8120e9d5872b1fefe89d3b9399faaa32",
                    "name": "UcmUcsiCx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Drivers\\UcmUcsiCx.sys",
                    "image path": "System32\\Drivers\\UcmUcsiCx.sys",
                    "md5": "8120e9d5872b1fefe89d3b9399faaa32",
                    "name": "UcmUcsiCx0101",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ucx01000.sys",
                    "image path": "system32\\drivers\\ucx01000.sys",
                    "md5": "df984ad18272526a5f6b5105e99b4175",
                    "name": "Ucx01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ucx01000.sys",
                    "image path": "system32\\drivers\\ucx01000.sys",
                    "md5": "df984ad18272526a5f6b5105e99b4175",
                    "name": "Ucx01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\udecx.sys",
                    "image path": "system32\\drivers\\udecx.sys",
                    "md5": "d68019cfbed7863698c318cda625f36d",
                    "name": "UdeCx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\udecx.sys",
                    "image path": "system32\\drivers\\udecx.sys",
                    "md5": "d68019cfbed7863698c318cda625f36d",
                    "name": "UdeCx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\udfs.sys",
                    "image path": "system32\\DRIVERS\\udfs.sys",
                    "md5": "f21afa0eac046aec60a4d1ab4ef54402",
                    "name": "udfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\udfs.sys",
                    "image path": "system32\\DRIVERS\\udfs.sys",
                    "md5": "f21afa0eac046aec60a4d1ab4ef54402",
                    "name": "udfs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\windowsudkservices.shellcommon.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UdkSvcGroup",
                    "md5": "48768bab2eb781065360bb52a6c2ed06",
                    "name": "UdkUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\windowsudkservices.shellcommon.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UdkSvcGroup",
                    "md5": "48768bab2eb781065360bb52a6c2ed06",
                    "name": "UdkUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\windowsudkservices.shellcommon.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UdkSvcGroup",
                    "md5": "48768bab2eb781065360bb52a6c2ed06",
                    "name": "UdkUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\windowsudkservices.shellcommon.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UdkSvcGroup",
                    "md5": "48768bab2eb781065360bb52a6c2ed06",
                    "name": "UdkUserSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k UdkSvcGroup",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "UdkUserSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\uefi.inf_amd64_9f06649ff2db66cb\\UEFI.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\uefi.inf_amd64_9f06649ff2db66cb\\UEFI.sys",
                    "md5": "4abf934b44b0bb1fd3bfb0a7a1606cc4",
                    "name": "UEFI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\uefi.inf_amd64_9f06649ff2db66cb\\UEFI.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\uefi.inf_amd64_9f06649ff2db66cb\\UEFI.sys",
                    "md5": "4abf934b44b0bb1fd3bfb0a7a1606cc4",
                    "name": "UEFI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\UevAgentDriver.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\UevAgentDriver.sys",
                    "md5": "ae5e320236762b339d6317885b4d2d44",
                    "name": "UevAgentDriver",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\UevAgentDriver.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\UevAgentDriver.sys",
                    "md5": "ae5e320236762b339d6317885b4d2d44",
                    "name": "UevAgentDriver",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\AgentService.exe",
                    "image path": "%systemroot%\\system32\\AgentService.exe",
                    "md5": "930c9a3eb8b54716df341d7f17a3e3b8",
                    "name": "UevAgentService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\AgentService.exe",
                    "image path": "%systemroot%\\system32\\AgentService.exe",
                    "md5": "930c9a3eb8b54716df341d7f17a3e3b8",
                    "name": "UevAgentService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ufx01000.sys",
                    "image path": "system32\\drivers\\ufx01000.sys",
                    "md5": "76aeb6693aeae91b1d5a696e6a0ab1f4",
                    "name": "Ufx01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ufx01000.sys",
                    "image path": "system32\\drivers\\ufx01000.sys",
                    "md5": "76aeb6693aeae91b1d5a696e6a0ab1f4",
                    "name": "Ufx01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\ufxchipidea.inf_amd64_aeccf7013ec6965b\\UfxChipidea.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\ufxchipidea.inf_amd64_aeccf7013ec6965b\\UfxChipidea.sys",
                    "md5": "ccde14253795b9a684ebed07d29a2fd8",
                    "name": "UfxChipidea",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\ufxchipidea.inf_amd64_aeccf7013ec6965b\\UfxChipidea.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\ufxchipidea.inf_amd64_aeccf7013ec6965b\\UfxChipidea.sys",
                    "md5": "ccde14253795b9a684ebed07d29a2fd8",
                    "name": "UfxChipidea",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ufxsynopsys.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ufxsynopsys.sys",
                    "md5": "e104d320cb68fc26eef7e29b34fd1703",
                    "name": "ufxsynopsys",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\ufxsynopsys.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\ufxsynopsys.sys",
                    "md5": "e104d320cb68fc26eef7e29b34fd1703",
                    "name": "ufxsynopsys",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\umbus.inf_amd64_f529037a77b144c5\\umbus.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\umbus.inf_amd64_f529037a77b144c5\\umbus.sys",
                    "md5": "65aa6b0661c1eedbe80667b39bebc784",
                    "name": "umbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\umbus.inf_amd64_f529037a77b144c5\\umbus.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\umbus.inf_amd64_f529037a77b144c5\\umbus.sys",
                    "md5": "65aa6b0661c1eedbe80667b39bebc784",
                    "name": "umbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\umpass.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\umpass.sys",
                    "md5": "fd7ae43e3abe0c1928f4fd665925e686",
                    "name": "UmPass",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\umpass.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\umpass.sys",
                    "md5": "fd7ae43e3abe0c1928f4fd665925e686",
                    "name": "UmPass",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\umrdp.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "5a07d2e20075d9b28412e0c09e6620f3",
                    "name": "UmRdpService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\umrdp.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "5a07d2e20075d9b28412e0c09e6620f3",
                    "name": "UmRdpService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\umrdp.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "5a07d2e20075d9b28412e0c09e6620f3",
                    "name": "UmRdpService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\umrdp.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "5a07d2e20075d9b28412e0c09e6620f3",
                    "name": "UmRdpService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\unistore.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "fd39739243507ca0231641d8e617de0a",
                    "name": "UnistoreSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\unistore.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "fd39739243507ca0231641d8e617de0a",
                    "name": "UnistoreSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\unistore.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "fd39739243507ca0231641d8e617de0a",
                    "name": "UnistoreSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\unistore.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "fd39739243507ca0231641d8e617de0a",
                    "name": "UnistoreSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "image path": "C:\\Windows\\System32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "UnistoreSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\upnphost.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "a21d812bd34d5a463aba0763a1401b0f",
                    "name": "upnphost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\upnphost.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "a21d812bd34d5a463aba0763a1401b0f",
                    "name": "upnphost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\upnphost.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "a21d812bd34d5a463aba0763a1401b0f",
                    "name": "upnphost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\upnphost.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceAndNoImpersonation -p",
                    "md5": "a21d812bd34d5a463aba0763a1401b0f",
                    "name": "upnphost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\urschipidea.inf_amd64_5668f319215c576a\\urschipidea.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\urschipidea.inf_amd64_5668f319215c576a\\urschipidea.sys",
                    "md5": "ee72b57aa6ee25fa281ac4818642d499",
                    "name": "UrsChipidea",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\urschipidea.inf_amd64_5668f319215c576a\\urschipidea.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\urschipidea.inf_amd64_5668f319215c576a\\urschipidea.sys",
                    "md5": "ee72b57aa6ee25fa281ac4818642d499",
                    "name": "UrsChipidea",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\urscx01000.sys",
                    "image path": "system32\\drivers\\urscx01000.sys",
                    "md5": "ba36a9161c5bd0a576403578bea05074",
                    "name": "UrsCx01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\urscx01000.sys",
                    "image path": "system32\\drivers\\urscx01000.sys",
                    "md5": "ba36a9161c5bd0a576403578bea05074",
                    "name": "UrsCx01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\urssynopsys.inf_amd64_03db30e7672fa0ec\\urssynopsys.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\urssynopsys.inf_amd64_03db30e7672fa0ec\\urssynopsys.sys",
                    "md5": "a807575b12ba8044d56b57af3a86bac8",
                    "name": "UrsSynopsys",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\urssynopsys.inf_amd64_03db30e7672fa0ec\\urssynopsys.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\urssynopsys.inf_amd64_03db30e7672fa0ec\\urssynopsys.sys",
                    "md5": "a807575b12ba8044d56b57af3a86bac8",
                    "name": "UrsSynopsys",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\Usb4DeviceRouter.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\Usb4DeviceRouter.sys",
                    "md5": "ad604210cb44128d7532999607fc92d1",
                    "name": "Usb4DeviceRouter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\Usb4DeviceRouter.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\Usb4DeviceRouter.sys",
                    "md5": "ad604210cb44128d7532999607fc92d1",
                    "name": "Usb4DeviceRouter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\Usb4HostRouter.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\Usb4HostRouter.sys",
                    "md5": "51bc230b590729ec8102b78393f46d10",
                    "name": "Usb4HostRouter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\Usb4HostRouter.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\Usb4HostRouter.sys",
                    "md5": "51bc230b590729ec8102b78393f46d10",
                    "name": "Usb4HostRouter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\usbaudio.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\usbaudio.sys",
                    "md5": "4d74a9cc28164792e444aca1db2cce8b",
                    "name": "usbaudio",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\usbaudio.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\usbaudio.sys",
                    "md5": "4d74a9cc28164792e444aca1db2cce8b",
                    "name": "usbaudio",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbaudio2.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbaudio2.sys",
                    "md5": "a06bc43865b1546ab7c1bf78bf68b51a",
                    "name": "usbaudio2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbaudio2.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbaudio2.sys",
                    "md5": "a06bc43865b1546ab7c1bf78bf68b51a",
                    "name": "usbaudio2",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbccgp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbccgp.sys",
                    "md5": "b096215f2b4a5ac2b5c2aea7e5f5219b",
                    "name": "usbccgp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbccgp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbccgp.sys",
                    "md5": "b096215f2b4a5ac2b5c2aea7e5f5219b",
                    "name": "usbccgp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbehci.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbehci.sys",
                    "md5": "e55561ab48c47119889285ae9a926803",
                    "name": "usbehci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbehci.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbehci.sys",
                    "md5": "e55561ab48c47119889285ae9a926803",
                    "name": "usbehci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbhub.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbhub.sys",
                    "md5": "8715f14376d2736d389bf4965fef0d1c",
                    "name": "usbhub",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbhub.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbhub.sys",
                    "md5": "8715f14376d2736d389bf4965fef0d1c",
                    "name": "usbhub",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\UsbHub3.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\UsbHub3.sys",
                    "md5": "d898b04496f7b71f108037f021762b69",
                    "name": "USBHUB3",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\UsbHub3.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\UsbHub3.sys",
                    "md5": "d898b04496f7b71f108037f021762b69",
                    "name": "USBHUB3",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbohci.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbohci.sys",
                    "md5": "25f86b20c5b633712e19db950a1cb853",
                    "name": "usbohci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbohci.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbohci.sys",
                    "md5": "25f86b20c5b633712e19db950a1cb853",
                    "name": "usbohci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbprint.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbprint.sys",
                    "md5": "4f06eceaf37ac0164c286b33123cd0f1",
                    "name": "usbprint",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbprint.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbprint.sys",
                    "md5": "4f06eceaf37ac0164c286b33123cd0f1",
                    "name": "usbprint",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbser.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbser.sys",
                    "md5": "ec60c70fbb83a374329c0cf2ae869858",
                    "name": "usbser",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbser.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbser.sys",
                    "md5": "ec60c70fbb83a374329c0cf2ae869858",
                    "name": "usbser",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\USBSTOR.SYS",
                    "image path": "\\SystemRoot\\System32\\drivers\\USBSTOR.SYS",
                    "md5": "86559d32bf926a1ce1c558a9f04d0695",
                    "name": "USBSTOR",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\USBSTOR.SYS",
                    "image path": "\\SystemRoot\\System32\\drivers\\USBSTOR.SYS",
                    "md5": "86559d32bf926a1ce1c558a9f04d0695",
                    "name": "USBSTOR",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbuhci.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbuhci.sys",
                    "md5": "2a97eac51eefd7eebd198caf236007af",
                    "name": "usbuhci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\usbuhci.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\usbuhci.sys",
                    "md5": "2a97eac51eefd7eebd198caf236007af",
                    "name": "usbuhci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\USBXHCI.SYS",
                    "image path": "\\SystemRoot\\System32\\drivers\\USBXHCI.SYS",
                    "md5": "458193b8b793ec02d1abacf0b45296f2",
                    "name": "USBXHCI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\USBXHCI.SYS",
                    "image path": "\\SystemRoot\\System32\\drivers\\USBXHCI.SYS",
                    "md5": "458193b8b793ec02d1abacf0b45296f2",
                    "name": "USBXHCI",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\userdataservice.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "1fb9c41c480acf8929a9b8acb5cd20e2",
                    "name": "UserDataSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\userdataservice.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "1fb9c41c480acf8929a9b8acb5cd20e2",
                    "name": "UserDataSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\userdataservice.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "1fb9c41c480acf8929a9b8acb5cd20e2",
                    "name": "UserDataSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\userdataservice.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "1fb9c41c480acf8929a9b8acb5cd20e2",
                    "name": "UserDataSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "UserDataSvc_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\usermgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "bc60b2c5d490d88679fe619f6778b4de",
                    "name": "UserManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\usermgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "bc60b2c5d490d88679fe619f6778b4de",
                    "name": "UserManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\usermgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "bc60b2c5d490d88679fe619f6778b4de",
                    "name": "UserManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\usermgr.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "bc60b2c5d490d88679fe619f6778b4de",
                    "name": "UserManager",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usosvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "f369c38b009621c4b4633ba9fead7819",
                    "name": "UsoSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usosvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "f369c38b009621c4b4633ba9fead7819",
                    "name": "UsoSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usosvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "f369c38b009621c4b4633ba9fead7819",
                    "name": "UsoSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\usosvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "f369c38b009621c4b4633ba9fead7819",
                    "name": "UsoSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\vaultsvc.dll",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "9243207f1c72cff68ce5929eb62941af",
                    "name": "VaultSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\vaultsvc.dll",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "9243207f1c72cff68ce5929eb62941af",
                    "name": "VaultSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\vaultsvc.dll",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "9243207f1c72cff68ce5929eb62941af",
                    "name": "VaultSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\vaultsvc.dll",
                    "image path": "%SystemRoot%\\system32\\lsass.exe",
                    "md5": "9243207f1c72cff68ce5929eb62941af",
                    "name": "VaultSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\VBoxGuest.sys",
                    "image path": "system32\\DRIVERS\\VBoxGuest.sys",
                    "md5": "873c8107cc6f4a8339b66eeb9fa2d2e1",
                    "name": "VBoxGuest",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\VBoxGuest.sys",
                    "image path": "system32\\DRIVERS\\VBoxGuest.sys",
                    "md5": "873c8107cc6f4a8339b66eeb9fa2d2e1",
                    "name": "VBoxGuest",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\VBoxMouse.sys",
                    "image path": "\\SystemRoot\\system32\\DRIVERS\\VBoxMouse.sys",
                    "md5": "0b922b41369b9779a4e71d68efc02275",
                    "name": "VBoxMouse",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\VBoxMouse.sys",
                    "image path": "\\SystemRoot\\system32\\DRIVERS\\VBoxMouse.sys",
                    "md5": "0b922b41369b9779a4e71d68efc02275",
                    "name": "VBoxMouse",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\VBoxService.exe",
                    "image path": "%SystemRoot%\\System32\\VBoxService.exe",
                    "md5": "5ac35aca951acd0732752095bbc366be",
                    "name": "VBoxService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\VBoxService.exe",
                    "image path": "%SystemRoot%\\System32\\VBoxService.exe",
                    "md5": "5ac35aca951acd0732752095bbc366be",
                    "name": "VBoxService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\VBoxSF.sys",
                    "md5": "9c5fa56ec9fa228e31484df1e41364d3",
                    "name": "VBoxSF",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\VBoxSF.sys",
                    "md5": "9c5fa56ec9fa228e31484df1e41364d3",
                    "name": "VBoxSF",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\VBoxWddm.sys",
                    "image path": "\\SystemRoot\\system32\\DRIVERS\\VBoxWddm.sys",
                    "md5": "66ed4d8224cfe448ba9dad324b564f35",
                    "name": "VBoxWddm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\DRIVERS\\VBoxWddm.sys",
                    "image path": "\\SystemRoot\\system32\\DRIVERS\\VBoxWddm.sys",
                    "md5": "66ed4d8224cfe448ba9dad324b564f35",
                    "name": "VBoxWddm",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vdrvroot.sys",
                    "image path": "System32\\drivers\\vdrvroot.sys",
                    "md5": "504a71b5d24a6975a1d771c44ccf86fd",
                    "name": "vdrvroot",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vdrvroot.sys",
                    "image path": "System32\\drivers\\vdrvroot.sys",
                    "md5": "504a71b5d24a6975a1d771c44ccf86fd",
                    "name": "vdrvroot",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\vds.exe",
                    "image path": "%SystemRoot%\\System32\\vds.exe",
                    "md5": "a8487cee7d831ead54f2d29688d09c92",
                    "name": "vds",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\vds.exe",
                    "image path": "%SystemRoot%\\System32\\vds.exe",
                    "md5": "a8487cee7d831ead54f2d29688d09c92",
                    "name": "vds",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\VerifierExt.sys",
                    "image path": "System32\\drivers\\VerifierExt.sys",
                    "md5": "ce72e993399f04d5ed8258aab0b77506",
                    "name": "VerifierExt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\VerifierExt.sys",
                    "image path": "System32\\drivers\\VerifierExt.sys",
                    "md5": "ce72e993399f04d5ed8258aab0b77506",
                    "name": "VerifierExt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vhdmp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vhdmp.sys",
                    "md5": "4c19232180eb9a21ef93d77738755722",
                    "name": "vhdmp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vhdmp.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vhdmp.sys",
                    "md5": "4c19232180eb9a21ef93d77738755722",
                    "name": "vhdmp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vhf.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vhf.sys",
                    "md5": "6108fde2565029e34fe01ea59efe840b",
                    "name": "vhf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vhf.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vhf.sys",
                    "md5": "6108fde2565029e34fe01ea59efe840b",
                    "name": "vhf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\vrd.inf_amd64_1fbbe83391910b93\\vrd.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\vrd.inf_amd64_1fbbe83391910b93\\vrd.sys",
                    "md5": "86190af4f24bb697940349c073650de2",
                    "name": "VirtualRender",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DriverStore\\FileRepository\\vrd.inf_amd64_1fbbe83391910b93\\vrd.sys",
                    "image path": "\\SystemRoot\\System32\\DriverStore\\FileRepository\\vrd.inf_amd64_1fbbe83391910b93\\vrd.sys",
                    "md5": "86190af4f24bb697940349c073650de2",
                    "name": "VirtualRender",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vmbus.sys",
                    "image path": "System32\\drivers\\vmbus.sys",
                    "md5": "6b16fb2048005d6cec551791241141aa",
                    "name": "vmbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vmbus.sys",
                    "image path": "System32\\drivers\\vmbus.sys",
                    "md5": "6b16fb2048005d6cec551791241141aa",
                    "name": "vmbus",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\VMBusHID.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\VMBusHID.sys",
                    "md5": "d32f75fb6084d58f8edbe31c92ed3d77",
                    "name": "VMBusHID",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\VMBusHID.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\VMBusHID.sys",
                    "md5": "d32f75fb6084d58f8edbe31c92ed3d77",
                    "name": "VMBusHID",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vmgid.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vmgid.sys",
                    "md5": "ddbf27f6195bb66b7e267974aedf2d4c",
                    "name": "vmgid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vmgid.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\vmgid.sys",
                    "md5": "ddbf27f6195bb66b7e267974aedf2d4c",
                    "name": "vmgid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicguestinterface",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicguestinterface",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicguestinterface",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicguestinterface",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k ICService -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicheartbeat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k ICService -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicheartbeat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k ICService -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicheartbeat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k ICService -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicheartbeat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmickvpexchange",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmickvpexchange",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmickvpexchange",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmickvpexchange",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicshutdown",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicshutdown",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicshutdown",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicshutdown",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmictimesync",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmictimesync",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmictimesync",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmictimesync",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicvmsession",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicvmsession",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicvmsession",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "7c6e21a9288161571e8a030644f5ac97",
                    "name": "vmicvmsession",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvcvss.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "20550321c711edf9c074af1ec7919fd8",
                    "name": "vmicvss",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvcvss.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "20550321c711edf9c074af1ec7919fd8",
                    "name": "vmicvss",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvcvss.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "20550321c711edf9c074af1ec7919fd8",
                    "name": "vmicvss",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\icsvcvss.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "20550321c711edf9c074af1ec7919fd8",
                    "name": "vmicvss",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\volmgr.sys",
                    "image path": "System32\\drivers\\volmgr.sys",
                    "md5": "0bc9e7b4865ed2227cccc05f1dbc6f52",
                    "name": "volmgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\volmgr.sys",
                    "image path": "System32\\drivers\\volmgr.sys",
                    "md5": "0bc9e7b4865ed2227cccc05f1dbc6f52",
                    "name": "volmgr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\volmgrx.sys",
                    "image path": "System32\\drivers\\volmgrx.sys",
                    "md5": "f7da6b4c3238121c132213e30b7651b2",
                    "name": "volmgrx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\volmgrx.sys",
                    "image path": "System32\\drivers\\volmgrx.sys",
                    "md5": "f7da6b4c3238121c132213e30b7651b2",
                    "name": "volmgrx",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\volsnap.sys",
                    "image path": "System32\\drivers\\volsnap.sys",
                    "md5": "8e0d28114d41d67b95c71d5cd17e86c0",
                    "name": "volsnap",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\volsnap.sys",
                    "image path": "System32\\drivers\\volsnap.sys",
                    "md5": "8e0d28114d41d67b95c71d5cd17e86c0",
                    "name": "volsnap",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\volume.sys",
                    "image path": "System32\\drivers\\volume.sys",
                    "md5": "05fac0dd1370c68530f0a72caf64a27b",
                    "name": "volume",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\volume.sys",
                    "image path": "System32\\drivers\\volume.sys",
                    "md5": "05fac0dd1370c68530f0a72caf64a27b",
                    "name": "volume",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vpci.sys",
                    "image path": "System32\\drivers\\vpci.sys",
                    "md5": "6d2cdfc79a86ada64c0ea86b16462925",
                    "name": "vpci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vpci.sys",
                    "image path": "System32\\drivers\\vpci.sys",
                    "md5": "6d2cdfc79a86ada64c0ea86b16462925",
                    "name": "vpci",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vsmraid.sys",
                    "image path": "System32\\drivers\\vsmraid.sys",
                    "md5": "c8a68bb6e51cf3f0580fc552d05b482e",
                    "name": "vsmraid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vsmraid.sys",
                    "image path": "System32\\drivers\\vsmraid.sys",
                    "md5": "c8a68bb6e51cf3f0580fc552d05b482e",
                    "name": "vsmraid",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\vssvc.exe",
                    "image path": "%systemroot%\\system32\\vssvc.exe",
                    "md5": "d6037f722e7259fdccfeaf56b036adf2",
                    "name": "VSS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\vssvc.exe",
                    "image path": "%systemroot%\\system32\\vssvc.exe",
                    "md5": "d6037f722e7259fdccfeaf56b036adf2",
                    "name": "VSS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vstxraid.sys",
                    "image path": "System32\\drivers\\vstxraid.sys",
                    "md5": "d870dc436ba5c79c200aa751cf0b66c7",
                    "name": "VSTXRAID",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\vstxraid.sys",
                    "image path": "System32\\drivers\\vstxraid.sys",
                    "md5": "d870dc436ba5c79c200aa751cf0b66c7",
                    "name": "VSTXRAID",
                    "signed": true
                },
                {
                    "fullpath": "",
                    "image path": "\\SystemRoot\\System32\\drivers\\vwifibus.sys",
                    "md5": null,
                    "name": "vwifibus",
                    "signed": false
                },
                {
                    "fullpath": "",
                    "image path": "\\SystemRoot\\System32\\drivers\\vwifibus.sys",
                    "md5": null,
                    "name": "vwifibus",
                    "signed": false
                },
                {
                    "fullpath": "C:\\Windows\\system32\\w32time.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService",
                    "md5": "68b0ddf1884a177d2649d41b0ba1fec7",
                    "name": "W32Time",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\w32time.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService",
                    "md5": "68b0ddf1884a177d2649d41b0ba1fec7",
                    "name": "W32Time",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\w32time.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService",
                    "md5": "68b0ddf1884a177d2649d41b0ba1fec7",
                    "name": "W32Time",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\w32time.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalService",
                    "md5": "68b0ddf1884a177d2649d41b0ba1fec7",
                    "name": "W32Time",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WaaSMedicSvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k wusvcs -p",
                    "md5": "32b0ce651968939dbf98ff0d60abf913",
                    "name": "WaaSMedicSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WaaSMedicSvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k wusvcs -p",
                    "md5": "32b0ce651968939dbf98ff0d60abf913",
                    "name": "WaaSMedicSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WaaSMedicSvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k wusvcs -p",
                    "md5": "32b0ce651968939dbf98ff0d60abf913",
                    "name": "WaaSMedicSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WaaSMedicSvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k wusvcs -p",
                    "md5": "32b0ce651968939dbf98ff0d60abf913",
                    "name": "WaaSMedicSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\wacompen.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\wacompen.sys",
                    "md5": "244000921c22efcced5a98ce325fae30",
                    "name": "WacomPen",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\wacompen.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\wacompen.sys",
                    "md5": "244000921c22efcced5a98ce325fae30",
                    "name": "WacomPen",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WalletService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k appmodel -p",
                    "md5": "750735d306ff16f75329de3dedc85359",
                    "name": "WalletService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WalletService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k appmodel -p",
                    "md5": "750735d306ff16f75329de3dedc85359",
                    "name": "WalletService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WalletService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k appmodel -p",
                    "md5": "750735d306ff16f75329de3dedc85359",
                    "name": "WalletService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WalletService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k appmodel -p",
                    "md5": "750735d306ff16f75329de3dedc85359",
                    "name": "WalletService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\wanarp.sys",
                    "image path": "System32\\DRIVERS\\wanarp.sys",
                    "md5": "729e5a98361534e5c6041407311f2c9e",
                    "name": "wanarp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\wanarp.sys",
                    "image path": "System32\\DRIVERS\\wanarp.sys",
                    "md5": "729e5a98361534e5c6041407311f2c9e",
                    "name": "wanarp",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\wanarp.sys",
                    "image path": "System32\\DRIVERS\\wanarp.sys",
                    "md5": "729e5a98361534e5c6041407311f2c9e",
                    "name": "wanarpv6",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\DRIVERS\\wanarp.sys",
                    "image path": "System32\\DRIVERS\\wanarp.sys",
                    "md5": "729e5a98361534e5c6041407311f2c9e",
                    "name": "wanarpv6",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.WARP.JITService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
                    "md5": "573a95a43ec92b8c9f4334c3d1ee4007",
                    "name": "WarpJITSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.WARP.JITService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
                    "md5": "573a95a43ec92b8c9f4334c3d1ee4007",
                    "name": "WarpJITSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.WARP.JITService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
                    "md5": "573a95a43ec92b8c9f4334c3d1ee4007",
                    "name": "WarpJITSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\Windows.WARP.JITService.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalServiceNetworkRestricted",
                    "md5": "573a95a43ec92b8c9f4334c3d1ee4007",
                    "name": "WarpJITSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wbiosrvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k WbioSvcGroup",
                    "md5": "b294068cdd11d70c9703f2a7e40d3330",
                    "name": "WbioSrvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wbiosrvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k WbioSvcGroup",
                    "md5": "b294068cdd11d70c9703f2a7e40d3330",
                    "name": "WbioSrvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wbiosrvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k WbioSvcGroup",
                    "md5": "b294068cdd11d70c9703f2a7e40d3330",
                    "name": "WbioSrvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wbiosrvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k WbioSvcGroup",
                    "md5": "b294068cdd11d70c9703f2a7e40d3330",
                    "name": "WbioSrvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wcifs.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\wcifs.sys",
                    "md5": "f6eac3ea92f216a48495ea0fe645dcbf",
                    "name": "wcifs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wcifs.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\wcifs.sys",
                    "md5": "f6eac3ea92f216a48495ea0fe645dcbf",
                    "name": "wcifs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wcmsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "7a779c762ba808d531973e378b790ac8",
                    "name": "Wcmsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wcmsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "7a779c762ba808d531973e378b790ac8",
                    "name": "Wcmsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wcmsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "7a779c762ba808d531973e378b790ac8",
                    "name": "Wcmsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wcmsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "7a779c762ba808d531973e378b790ac8",
                    "name": "Wcmsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wd\\WdBoot.sys",
                    "image path": "system32\\drivers\\wd\\WdBoot.sys",
                    "md5": "33a97c8017ac18abf2b00eaaa9b5b0c4",
                    "name": "WdBoot",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wd\\WdBoot.sys",
                    "image path": "system32\\drivers\\wd\\WdBoot.sys",
                    "md5": "33a97c8017ac18abf2b00eaaa9b5b0c4",
                    "name": "WdBoot",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Wdf01000.sys",
                    "image path": "system32\\drivers\\Wdf01000.sys",
                    "md5": "252710b80261fc7a470765da230f4582",
                    "name": "Wdf01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Wdf01000.sys",
                    "image path": "system32\\drivers\\Wdf01000.sys",
                    "md5": "252710b80261fc7a470765da230f4582",
                    "name": "Wdf01000",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wd\\WdFilter.sys",
                    "image path": "system32\\drivers\\wd\\WdFilter.sys",
                    "md5": "98e9a26bbd42e644bf797710f9f65dce",
                    "name": "WdFilter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\WdFilter.sys",
                    "image path": "system32\\drivers\\WdFilter.sys",
                    "md5": "b3965025c0fed1c7664005951536b0c9",
                    "name": "WdFilter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "WdiServiceHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "WdiServiceHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "WdiServiceHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalService -p",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "WdiServiceHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "WdiSystemHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "WdiSystemHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "WdiSystemHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wdi.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "90bec7af03968f67bca4a1da50b042db",
                    "name": "WdiSystemHost",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\WdmCompanionFilter.sys",
                    "image path": "system32\\drivers\\WdmCompanionFilter.sys",
                    "md5": "02ca8dd9f78f6ff4ca0c028db803945a",
                    "name": "WdmCompanionFilter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\WdmCompanionFilter.sys",
                    "image path": "system32\\drivers\\WdmCompanionFilter.sys",
                    "md5": "02ca8dd9f78f6ff4ca0c028db803945a",
                    "name": "WdmCompanionFilter",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wd\\WdNisDrv.sys",
                    "image path": "system32\\drivers\\wd\\WdNisDrv.sys",
                    "md5": "49f632dcdeac16123927067c4512913a",
                    "name": "WdNisDrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\Drivers\\WdNisDrv.sys",
                    "image path": "system32\\Drivers\\WdNisDrv.sys",
                    "md5": "06eeb51e111f52588dbae3bbe122386f",
                    "name": "WdNisDrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\NisSrv.exe",
                    "image path": "\"%ProgramData%\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\NisSrv.exe\"",
                    "md5": "85e46c79c8f8ea940fb0ebbede18b46f",
                    "name": "WdNisSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\NisSrv.exe",
                    "image path": "\"%ProgramData%\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\NisSrv.exe\"",
                    "md5": "85e46c79c8f8ea940fb0ebbede18b46f",
                    "name": "WdNisSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wecsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "477a7e92497f33a17ec28d873400a0f9",
                    "name": "Wecsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wecsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "477a7e92497f33a17ec28d873400a0f9",
                    "name": "Wecsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wecsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "477a7e92497f33a17ec28d873400a0f9",
                    "name": "Wecsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wecsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k NetworkService -p",
                    "md5": "477a7e92497f33a17ec28d873400a0f9",
                    "name": "Wecsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wephostsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k WepHostSvcGroup",
                    "md5": "ca2e7111e71bfa7296c6623bab2d8ce7",
                    "name": "WEPHOSTSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wephostsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k WepHostSvcGroup",
                    "md5": "ca2e7111e71bfa7296c6623bab2d8ce7",
                    "name": "WEPHOSTSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wephostsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k WepHostSvcGroup",
                    "md5": "ca2e7111e71bfa7296c6623bab2d8ce7",
                    "name": "WEPHOSTSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wephostsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k WepHostSvcGroup",
                    "md5": "ca2e7111e71bfa7296c6623bab2d8ce7",
                    "name": "WEPHOSTSVC",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wercplsupport.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "89f09ca76ec149be7b3d52a7a513c91e",
                    "name": "wercplsupport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wercplsupport.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "89f09ca76ec149be7b3d52a7a513c91e",
                    "name": "wercplsupport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wercplsupport.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "89f09ca76ec149be7b3d52a7a513c91e",
                    "name": "wercplsupport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wercplsupport.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k netsvcs -p",
                    "md5": "89f09ca76ec149be7b3d52a7a513c91e",
                    "name": "wercplsupport",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WerSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k WerSvcGroup",
                    "md5": "c8847488d1423be439ee1281566499da",
                    "name": "WerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WerSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k WerSvcGroup",
                    "md5": "c8847488d1423be439ee1281566499da",
                    "name": "WerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WerSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k WerSvcGroup",
                    "md5": "c8847488d1423be439ee1281566499da",
                    "name": "WerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WerSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k WerSvcGroup",
                    "md5": "c8847488d1423be439ee1281566499da",
                    "name": "WerSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\wfplwfs.sys",
                    "image path": "System32\\drivers\\wfplwfs.sys",
                    "md5": "2aad68e852436e0a7363377c91e0302d",
                    "name": "WFPLWFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\wfplwfs.sys",
                    "image path": "System32\\drivers\\wfplwfs.sys",
                    "md5": "2aad68e852436e0a7363377c91e0302d",
                    "name": "WFPLWFS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wiarpc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "618d47a30e374dfcf52a04915d33e223",
                    "name": "WiaRpc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wiarpc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "618d47a30e374dfcf52a04915d33e223",
                    "name": "WiaRpc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wiarpc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "618d47a30e374dfcf52a04915d33e223",
                    "name": "WiaRpc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\wiarpc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "md5": "618d47a30e374dfcf52a04915d33e223",
                    "name": "WiaRpc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wimmount.sys",
                    "image path": "system32\\drivers\\wimmount.sys",
                    "md5": "7e12f9f23a87dfb574db49d1a7f23ed3",
                    "name": "WIMMount",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\wimmount.sys",
                    "image path": "system32\\drivers\\wimmount.sys",
                    "md5": "7e12f9f23a87dfb574db49d1a7f23ed3",
                    "name": "WIMMount",
                    "signed": true
                },
                {
                    "fullpath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\MsMpEng.exe",
                    "image path": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\MsMpEng.exe\"",
                    "md5": "a7dca32f82ec2569865f447416a7cf1a",
                    "name": "WinDefend",
                    "signed": true
                },
                {
                    "fullpath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\MsMpEng.exe",
                    "image path": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\MsMpEng.exe\"",
                    "md5": "a7dca32f82ec2569865f447416a7cf1a",
                    "name": "WinDefend",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\WindowsTrustedRT.sys",
                    "image path": "system32\\drivers\\WindowsTrustedRT.sys",
                    "md5": "74240ace203c61bd4f4b6081654884c0",
                    "name": "WindowsTrustedRT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\WindowsTrustedRT.sys",
                    "image path": "system32\\drivers\\WindowsTrustedRT.sys",
                    "md5": "74240ace203c61bd4f4b6081654884c0",
                    "name": "WindowsTrustedRT",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\WindowsTrustedRTProxy.sys",
                    "image path": "System32\\drivers\\WindowsTrustedRTProxy.sys",
                    "md5": "0b728612a0aec70533a641fbec23d01a",
                    "name": "WindowsTrustedRTProxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\WindowsTrustedRTProxy.sys",
                    "image path": "System32\\drivers\\WindowsTrustedRTProxy.sys",
                    "md5": "0b728612a0aec70533a641fbec23d01a",
                    "name": "WindowsTrustedRTProxy",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\winhttp.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5990d33fda7ab63199da325c13fcefc7",
                    "name": "WinHttpAutoProxySvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\winhttp.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5990d33fda7ab63199da325c13fcefc7",
                    "name": "WinHttpAutoProxySvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\winhttp.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5990d33fda7ab63199da325c13fcefc7",
                    "name": "WinHttpAutoProxySvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\winhttp.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "md5": "5990d33fda7ab63199da325c13fcefc7",
                    "name": "WinHttpAutoProxySvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\winmad.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\winmad.sys",
                    "md5": "955c3f9cfff1d2e9e2a643a4920ff53c",
                    "name": "WinMad",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\winmad.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\winmad.sys",
                    "md5": "955c3f9cfff1d2e9e2a643a4920ff53c",
                    "name": "WinMad",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wbem\\WMIsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "059b29734a6659ced32a027ecff3dccc",
                    "name": "Winmgmt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wbem\\WMIsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "059b29734a6659ced32a027ecff3dccc",
                    "name": "Winmgmt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wbem\\WMIsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "059b29734a6659ced32a027ecff3dccc",
                    "name": "Winmgmt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wbem\\WMIsvc.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "059b29734a6659ced32a027ecff3dccc",
                    "name": "Winmgmt",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\winnat.sys",
                    "image path": "system32\\drivers\\winnat.sys",
                    "md5": "4d562b3a2755b71e93d0518d2e51567c",
                    "name": "WinNat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\winnat.sys",
                    "image path": "system32\\drivers\\winnat.sys",
                    "md5": "4d562b3a2755b71e93d0518d2e51567c",
                    "name": "WinNat",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WsmSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "d31f6d528bf140eb0310c65b45522d4a",
                    "name": "WinRM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WsmSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "d31f6d528bf140eb0310c65b45522d4a",
                    "name": "WinRM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WsmSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "d31f6d528bf140eb0310c65b45522d4a",
                    "name": "WinRM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WsmSvc.dll",
                    "image path": "%SystemRoot%\\System32\\svchost.exe -k NetworkService -p",
                    "md5": "d31f6d528bf140eb0310c65b45522d4a",
                    "name": "WinRM",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\WinUSB.SYS",
                    "image path": "\\SystemRoot\\System32\\drivers\\WinUSB.SYS",
                    "md5": "023574b306e1af48adb7999cfe3c914a",
                    "name": "WINUSB",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\WinUSB.SYS",
                    "image path": "\\SystemRoot\\System32\\drivers\\WinUSB.SYS",
                    "md5": "023574b306e1af48adb7999cfe3c914a",
                    "name": "WINUSB",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\winverbs.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\winverbs.sys",
                    "md5": "1601c34722efb07f8f2ca144ac9c42c0",
                    "name": "WinVerbs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\winverbs.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\winverbs.sys",
                    "md5": "1601c34722efb07f8f2ca144ac9c42c0",
                    "name": "WinVerbs",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\flightsettings.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c872ac46fb3b998f93f42e270410653b",
                    "name": "wisvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\flightsettings.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c872ac46fb3b998f93f42e270410653b",
                    "name": "wisvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\flightsettings.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c872ac46fb3b998f93f42e270410653b",
                    "name": "wisvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\flightsettings.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c872ac46fb3b998f93f42e270410653b",
                    "name": "wisvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wlidsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c1d341e08b4cccf8371a2b94a11f2382",
                    "name": "wlidsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wlidsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c1d341e08b4cccf8371a2b94a11f2382",
                    "name": "wlidsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wlidsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c1d341e08b4cccf8371a2b94a11f2382",
                    "name": "wlidsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wlidsvc.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "c1d341e08b4cccf8371a2b94a11f2382",
                    "name": "wlidsvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wlms\\wlms.exe",
                    "image path": "%SystemRoot%\\system32\\wlms\\wlms.exe",
                    "md5": "e723cfc8e88f9eb378f1043aaf3df92e",
                    "name": "WLMS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wlms\\wlms.exe",
                    "image path": "%SystemRoot%\\system32\\wlms\\wlms.exe",
                    "md5": "e723cfc8e88f9eb378f1043aaf3df92e",
                    "name": "WLMS",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\wmiacpi.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\wmiacpi.sys",
                    "md5": "310419c9ee6be5b029b688daecc6f1c1",
                    "name": "WmiAcpi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\wmiacpi.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\wmiacpi.sys",
                    "md5": "310419c9ee6be5b029b688daecc6f1c1",
                    "name": "WmiAcpi",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wbem\\WmiApSrv.exe",
                    "image path": "%systemroot%\\system32\\wbem\\WmiApSrv.exe",
                    "md5": "2c75c137ab7ec5501aa7cae29f835985",
                    "name": "wmiApSrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wbem\\WmiApSrv.exe",
                    "image path": "%systemroot%\\system32\\wbem\\WmiApSrv.exe",
                    "md5": "2c75c137ab7ec5501aa7cae29f835985",
                    "name": "wmiApSrv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\Windows Media Player\\wmpnetwk.exe",
                    "image path": "\"%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe\"",
                    "md5": "cc43ea8ebe75e2e0dd80ccc01ea16c65",
                    "name": "WMPNetworkSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Program Files\\Windows Media Player\\wmpnetwk.exe",
                    "image path": "\"%PROGRAMFILES%\\Windows Media Player\\wmpnetwk.exe\"",
                    "md5": "cc43ea8ebe75e2e0dd80ccc01ea16c65",
                    "name": "WMPNetworkSvc",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Wof.sys",
                    "image path": null,
                    "md5": "06ea9914a709a459075122981df85d37",
                    "name": "Wof",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\Wof.sys",
                    "image path": null,
                    "md5": "06ea9914a709a459075122981df85d37",
                    "name": "Wof",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wpdbusenum.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted",
                    "md5": "818a9805ae54193eb2ec24cfdb14a91d",
                    "name": "WPDBusEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wpdbusenum.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted",
                    "md5": "818a9805ae54193eb2ec24cfdb14a91d",
                    "name": "WPDBusEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wpdbusenum.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted",
                    "md5": "818a9805ae54193eb2ec24cfdb14a91d",
                    "name": "WPDBusEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wpdbusenum.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k LocalSystemNetworkRestricted",
                    "md5": "818a9805ae54193eb2ec24cfdb14a91d",
                    "name": "WPDBusEnum",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\WpdUpFltr.sys",
                    "image path": "System32\\drivers\\WpdUpFltr.sys",
                    "md5": "2d1a6f394a45ba1ea545f59f85c086cc",
                    "name": "WpdUpFltr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\WpdUpFltr.sys",
                    "image path": "System32\\drivers\\WpdUpFltr.sys",
                    "md5": "2d1a6f394a45ba1ea545f59f85c086cc",
                    "name": "WpdUpFltr",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WpnService.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "dbdc4fbf240921a6036122949398ce33",
                    "name": "WpnService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WpnService.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "dbdc4fbf240921a6036122949398ce33",
                    "name": "WpnService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WpnService.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "dbdc4fbf240921a6036122949398ce33",
                    "name": "WpnService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\WpnService.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "dbdc4fbf240921a6036122949398ce33",
                    "name": "WpnService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WpnUserService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "7d22242b0e337656404f117921d2be21",
                    "name": "WpnUserService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WpnUserService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "7d22242b0e337656404f117921d2be21",
                    "name": "WpnUserService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WpnUserService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "7d22242b0e337656404f117921d2be21",
                    "name": "WpnUserService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\WpnUserService.dll",
                    "image path": "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "7d22242b0e337656404f117921d2be21",
                    "name": "WpnUserService",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\svchost.exe",
                    "image path": "C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "WpnUserService_15391515",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ws2ifsl.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\ws2ifsl.sys",
                    "md5": "81a4fff62a6d142d4ecbaae34906445b",
                    "name": "ws2ifsl",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\ws2ifsl.sys",
                    "image path": "\\SystemRoot\\system32\\drivers\\ws2ifsl.sys",
                    "md5": "81a4fff62a6d142d4ecbaae34906445b",
                    "name": "ws2ifsl",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SearchIndexer.exe",
                    "image path": "%systemroot%\\system32\\SearchIndexer.exe /Embedding",
                    "md5": "c707eb14241077151f0d1d694ff53947",
                    "name": "WSearch",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\SearchIndexer.exe",
                    "image path": "%systemroot%\\system32\\SearchIndexer.exe /Embedding",
                    "md5": "c707eb14241077151f0d1d694ff53947",
                    "name": "WSearch",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wuaueng.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "dde6273f11df8a52ad7691e1130af0cc",
                    "name": "wuauserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wuaueng.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "dde6273f11df8a52ad7691e1130af0cc",
                    "name": "wuauserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wuaueng.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "dde6273f11df8a52ad7691e1130af0cc",
                    "name": "wuauserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\wuaueng.dll",
                    "image path": "%systemroot%\\system32\\svchost.exe -k netsvcs -p",
                    "md5": "dde6273f11df8a52ad7691e1130af0cc",
                    "name": "wuauserv",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\WudfPf.sys",
                    "image path": "system32\\drivers\\WudfPf.sys",
                    "md5": "5febf87f703a843078c20a6cfeef846f",
                    "name": "WudfPf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\WudfPf.sys",
                    "image path": "system32\\drivers\\WudfPf.sys",
                    "md5": "5febf87f703a843078c20a6cfeef846f",
                    "name": "WudfPf",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\System32\\drivers\\WUDFRd.sys",
                    "image path": "\\SystemRoot\\System32\\drivers\\WUDFRd.sys",
                    "md5": "88dd7fd6828870fe657a66da0766bc1d",
                    "name": "WUDFRd",
                    "signed": true
                },
                {
                    "fullpath": "C:\\Windows\\system32\\drivers\\WudfRd.sys",
                    "image path": "system32\\drivers\\WudfRd.sys",
                    "md5": "88dd7fd6828870fe657a66da0766bc1d",
                    "name": "WUDFRd",
                    "signed": true
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Scheduled Task List
>|name|fullpath|signed|md5|
>|---|---|---|---|
>| 1394ohci | C:\Windows\System32\drivers\1394ohci.sys | true | 809badbedd63ae4481fd65b8b20e8c0b |
>| 1394ohci | C:\Windows\System32\drivers\1394ohci.sys | true | 809badbedd63ae4481fd65b8b20e8c0b |
>| 3ware | C:\Windows\System32\drivers\3ware.sys | true | 0652580a777f9d77aa409d8595cec672 |
>| 3ware | C:\Windows\System32\drivers\3ware.sys | true | 0652580a777f9d77aa409d8595cec672 |
>| ACPI | C:\Windows\System32\drivers\ACPI.sys | true | 128242662d8f677e8d243dffe4c30acf |
>| ACPI | C:\Windows\System32\drivers\ACPI.sys | true | 128242662d8f677e8d243dffe4c30acf |
>| AcpiDev | C:\Windows\System32\drivers\AcpiDev.sys | true | ac827e39be44984a28abc64b44b47445 |
>| AcpiDev | C:\Windows\System32\drivers\AcpiDev.sys | true | ac827e39be44984a28abc64b44b47445 |
>| acpiex | C:\Windows\System32\Drivers\acpiex.sys | true | 0c2a19fce98cd5279174f70ecde10173 |
>| acpiex | C:\Windows\System32\Drivers\acpiex.sys | true | 0c2a19fce98cd5279174f70ecde10173 |
>| acpipagr | C:\Windows\System32\drivers\acpipagr.sys | true | e54826c72c231c0f0b57f8a35c03ff3e |
>| acpipagr | C:\Windows\System32\drivers\acpipagr.sys | true | e54826c72c231c0f0b57f8a35c03ff3e |
>| AcpiPmi | C:\Windows\System32\drivers\acpipmi.sys | true | 9a5be6df3e4d08085dbc375ec8c66dc4 |
>| AcpiPmi | C:\Windows\System32\drivers\acpipmi.sys | true | 9a5be6df3e4d08085dbc375ec8c66dc4 |
>| acpitime | C:\Windows\System32\drivers\acpitime.sys | true | 30569a8e79bfa28f4a1d379aac7f6dd7 |
>| acpitime | C:\Windows\System32\drivers\acpitime.sys | true | 30569a8e79bfa28f4a1d379aac7f6dd7 |
>| Acx01000 | C:\Windows\system32\drivers\Acx01000.sys | true | 45289ee0c340c884ab5a432239e56d18 |
>| Acx01000 | C:\Windows\system32\drivers\Acx01000.sys | true | 45289ee0c340c884ab5a432239e56d18 |
>| ADP80XX | C:\Windows\System32\drivers\ADP80XX.SYS | true | 26bf7d01ddb616801aaeed81f0b74b5a |
>| ADP80XX | C:\Windows\System32\drivers\ADP80XX.SYS | true | 26bf7d01ddb616801aaeed81f0b74b5a |
>| AFD | C:\Windows\system32\drivers\afd.sys | true | d5e687f3cb3f33b2554037332c7ffd26 |
>| AFD | C:\Windows\system32\drivers\afd.sys | true | d5e687f3cb3f33b2554037332c7ffd26 |
>| afunix | C:\Windows\system32\drivers\afunix.sys | true | 6904a360dcc3b90a798cde109f25ebb4 |
>| afunix | C:\Windows\system32\drivers\afunix.sys | true | 6904a360dcc3b90a798cde109f25ebb4 |
>| ahcache | C:\Windows\system32\DRIVERS\ahcache.sys | true | bfb562fd6102dc1729425c4c3cd450e5 |
>| ahcache | C:\Windows\system32\DRIVERS\ahcache.sys | true | bfb562fd6102dc1729425c4c3cd450e5 |
>| AJRouter | C:\Windows\System32\AJRouter.dll | true | 95c2151b641d69e806875acb9e3cf46a |
>| AJRouter | C:\Windows\System32\AJRouter.dll | true | 95c2151b641d69e806875acb9e3cf46a |
>| AJRouter | C:\Windows\System32\AJRouter.dll | true | 95c2151b641d69e806875acb9e3cf46a |
>| AJRouter | C:\Windows\System32\AJRouter.dll | true | 95c2151b641d69e806875acb9e3cf46a |
>| ALG | C:\Windows\System32\alg.exe | true | bf20fbc998d67d196b21a951f4c3ba9a |
>| ALG | C:\Windows\System32\alg.exe | true | bf20fbc998d67d196b21a951f4c3ba9a |
>| AmdK8 | C:\Windows\System32\drivers\amdk8.sys | true | 4124fd31125a390e52ad3fbde3e6dc63 |
>| AmdK8 | C:\Windows\System32\drivers\amdk8.sys | true | 4124fd31125a390e52ad3fbde3e6dc63 |
>| AmdPPM | C:\Windows\System32\drivers\amdppm.sys | true | a90de2c3047883852bd455c12b0d3a0b |
>| AmdPPM | C:\Windows\System32\drivers\amdppm.sys | true | a90de2c3047883852bd455c12b0d3a0b |
>| amdsata | C:\Windows\System32\drivers\amdsata.sys | true | 9ded5d39490578561a1af091c3253204 |
>| amdsata | C:\Windows\System32\drivers\amdsata.sys | true | 9ded5d39490578561a1af091c3253204 |
>| amdsbs | C:\Windows\System32\drivers\amdsbs.sys | true | 535bca23d988239781f218e9c707231a |
>| amdsbs | C:\Windows\System32\drivers\amdsbs.sys | true | 535bca23d988239781f218e9c707231a |
>| amdxata | C:\Windows\System32\drivers\amdxata.sys | true | e532e6c9e1fbbed2a40763344bf9e1de |
>| amdxata | C:\Windows\System32\drivers\amdxata.sys | true | e532e6c9e1fbbed2a40763344bf9e1de |
>| AppID | C:\Windows\system32\drivers\appid.sys | true | cc79ce5e95defbeeea8102c6899ffcdf |
>| AppID | C:\Windows\system32\drivers\appid.sys | true | cc79ce5e95defbeeea8102c6899ffcdf |
>| AppIDSvc | C:\Windows\System32\appidsvc.dll | true | be4af469abb640df55d71dba13e24671 |
>| AppIDSvc | C:\Windows\System32\appidsvc.dll | true | be4af469abb640df55d71dba13e24671 |
>| AppIDSvc | C:\Windows\System32\appidsvc.dll | true | be4af469abb640df55d71dba13e24671 |
>| AppIDSvc | C:\Windows\System32\appidsvc.dll | true | be4af469abb640df55d71dba13e24671 |
>| Appinfo | C:\Windows\System32\appinfo.dll | true | 022553a710d37a8d325c816d0f5eff64 |
>| Appinfo | C:\Windows\System32\appinfo.dll | true | 022553a710d37a8d325c816d0f5eff64 |
>| Appinfo | C:\Windows\System32\appinfo.dll | true | 022553a710d37a8d325c816d0f5eff64 |
>| Appinfo | C:\Windows\System32\appinfo.dll | true | 022553a710d37a8d325c816d0f5eff64 |
>| applockerfltr | C:\Windows\system32\drivers\applockerfltr.sys | true | 27395a50e249c327f9181f28b34d5b97 |
>| applockerfltr | C:\Windows\system32\drivers\applockerfltr.sys | true | 27395a50e249c327f9181f28b34d5b97 |
>| AppMgmt | C:\Windows\System32\appmgmts.dll | true | c187194b6c210dfa3dea72fb7fff42da |
>| AppMgmt | C:\Windows\System32\appmgmts.dll | true | c187194b6c210dfa3dea72fb7fff42da |
>| AppMgmt | C:\Windows\System32\appmgmts.dll | true | c187194b6c210dfa3dea72fb7fff42da |
>| AppMgmt | C:\Windows\System32\appmgmts.dll | true | c187194b6c210dfa3dea72fb7fff42da |
>| AppReadiness | C:\Windows\system32\AppReadiness.dll | true | d2fce34f153075778b336e1718f5d2fd |
>| AppReadiness | C:\Windows\system32\AppReadiness.dll | true | d2fce34f153075778b336e1718f5d2fd |
>| AppReadiness | C:\Windows\system32\AppReadiness.dll | true | d2fce34f153075778b336e1718f5d2fd |
>| AppReadiness | C:\Windows\system32\AppReadiness.dll | true | d2fce34f153075778b336e1718f5d2fd |
>| AppVClient | C:\Windows\system32\AppVClient.exe | true | 54e6f67c5a25c8e7e8279a365bfe4001 |
>| AppVClient | C:\Windows\system32\AppVClient.exe | true | 54e6f67c5a25c8e7e8279a365bfe4001 |
>| AppvStrm | C:\Windows\system32\drivers\AppvStrm.sys | true | cc9c25fe3f296aff4623d80f7bf90f6c |
>| AppvStrm | C:\Windows\system32\drivers\AppvStrm.sys | true | cc9c25fe3f296aff4623d80f7bf90f6c |
>| AppvVemgr | C:\Windows\system32\drivers\AppvVemgr.sys | true | 28dcd2b10a012b306348c4224b264ece |
>| AppvVemgr | C:\Windows\system32\drivers\AppvVemgr.sys | true | 28dcd2b10a012b306348c4224b264ece |
>| AppvVfs | C:\Windows\system32\drivers\AppvVfs.sys | true | 2df6f014ddb6650001ff5c3993c5edc5 |
>| AppvVfs | C:\Windows\system32\drivers\AppvVfs.sys | true | 2df6f014ddb6650001ff5c3993c5edc5 |
>| AppXSvc | C:\Windows\system32\appxdeploymentserver.dll | true | 68b0a9600676c84b74e9169bbbcf3e8d |
>| AppXSvc | C:\Windows\system32\appxdeploymentserver.dll | true | 68b0a9600676c84b74e9169bbbcf3e8d |
>| AppXSvc | C:\Windows\system32\appxdeploymentserver.dll | true | 68b0a9600676c84b74e9169bbbcf3e8d |
>| AppXSvc | C:\Windows\system32\appxdeploymentserver.dll | true | 68b0a9600676c84b74e9169bbbcf3e8d |
>| arcsas | C:\Windows\System32\drivers\arcsas.sys | true | 03c1542e64ef3d3192fb5fd148184a9a |
>| arcsas | C:\Windows\System32\drivers\arcsas.sys | true | 03c1542e64ef3d3192fb5fd148184a9a |
>| AsyncMac | C:\Windows\System32\drivers\asyncmac.sys | true | 8dac2ef58ef9c47c1632414c10af9c19 |
>| AsyncMac | C:\Windows\System32\drivers\asyncmac.sys | true | 8dac2ef58ef9c47c1632414c10af9c19 |
>| atapi | C:\Windows\System32\drivers\atapi.sys | true | 6db20deaa154aee9122d8aee5541f5c7 |
>| atapi | C:\Windows\System32\drivers\atapi.sys | true | 6db20deaa154aee9122d8aee5541f5c7 |
>| AudioEndpointBuilder | C:\Windows\System32\AudioEndpointBuilder.dll | true | 7d60dea45f3edf1798fa78176a4a9257 |
>| AudioEndpointBuilder | C:\Windows\System32\AudioEndpointBuilder.dll | true | 7d60dea45f3edf1798fa78176a4a9257 |
>| AudioEndpointBuilder | C:\Windows\System32\AudioEndpointBuilder.dll | true | 7d60dea45f3edf1798fa78176a4a9257 |
>| AudioEndpointBuilder | C:\Windows\System32\AudioEndpointBuilder.dll | true | 7d60dea45f3edf1798fa78176a4a9257 |
>| Audiosrv | C:\Windows\System32\Audiosrv.dll | true | a792252e252e924e93ddb1c90504b440 |
>| Audiosrv | C:\Windows\System32\Audiosrv.dll | true | a792252e252e924e93ddb1c90504b440 |
>| Audiosrv | C:\Windows\System32\Audiosrv.dll | true | a792252e252e924e93ddb1c90504b440 |
>| Audiosrv | C:\Windows\System32\Audiosrv.dll | true | a792252e252e924e93ddb1c90504b440 |
>| AxInstSV | C:\Windows\System32\AxInstSV.dll | true | c5838db8400a47b0dbf2bfc56c1f83d0 |
>| AxInstSV | C:\Windows\System32\AxInstSV.dll | true | c5838db8400a47b0dbf2bfc56c1f83d0 |
>| AxInstSV | C:\Windows\System32\AxInstSV.dll | true | c5838db8400a47b0dbf2bfc56c1f83d0 |
>| AxInstSV | C:\Windows\System32\AxInstSV.dll | true | c5838db8400a47b0dbf2bfc56c1f83d0 |
>| b06bdrv | C:\Windows\System32\drivers\bxvbda.sys | true | 5f70154f68d4e19657a4424f8a17117e |
>| b06bdrv | C:\Windows\System32\drivers\bxvbda.sys | true | 5f70154f68d4e19657a4424f8a17117e |
>| bam | C:\Windows\system32\drivers\bam.sys | true | 41f732bba9521ceb0c834d2b3fbb5090 |
>| bam | C:\Windows\system32\drivers\bam.sys | true | 41f732bba9521ceb0c834d2b3fbb5090 |
>| BasicDisplay | C:\Windows\System32\DriverStore\FileRepository\basicdisplay.inf_amd64_7e9cb61920ccc040\BasicDisplay.sys | true | 9e94d724c1dc4cca719be07eb1020dee |
>| BasicDisplay | C:\Windows\System32\DriverStore\FileRepository\basicdisplay.inf_amd64_7e9cb61920ccc040\BasicDisplay.sys | true | 9e94d724c1dc4cca719be07eb1020dee |
>| BasicRender | C:\Windows\System32\DriverStore\FileRepository\basicrender.inf_amd64_1c03174c7c755975\BasicRender.sys | true | 5e1ea96e7fd6ac5d1ba7c56e4b33e100 |
>| BasicRender | C:\Windows\System32\DriverStore\FileRepository\basicrender.inf_amd64_1c03174c7c755975\BasicRender.sys | true | 5e1ea96e7fd6ac5d1ba7c56e4b33e100 |
>| Beep | C:\Windows\system32\drivers\Beep.sys | true | 270b275b8571d164aa5740b84d28fae8 |
>| Beep | C:\Windows\system32\drivers\Beep.sys | true | 270b275b8571d164aa5740b84d28fae8 |
>| bfadfcoei | C:\Windows\System32\drivers\bfadfcoei.sys | true | 2d0a6656ab9996adf09fc919c88cefad |
>| bfadfcoei | C:\Windows\System32\drivers\bfadfcoei.sys | true | 2d0a6656ab9996adf09fc919c88cefad |
>| bfadi | C:\Windows\System32\drivers\bfadi.sys | true | 48c92680c29fa71ea828b33b45ff3fc4 |
>| bfadi | C:\Windows\System32\drivers\bfadi.sys | true | 48c92680c29fa71ea828b33b45ff3fc4 |
>| BFE | C:\Windows\System32\bfe.dll | true | d75dd70a73a7c16052f9e4b794a72342 |
>| BFE | C:\Windows\System32\bfe.dll | true | d75dd70a73a7c16052f9e4b794a72342 |
>| BFE | C:\Windows\System32\bfe.dll | true | d75dd70a73a7c16052f9e4b794a72342 |
>| BFE | C:\Windows\System32\bfe.dll | true | d75dd70a73a7c16052f9e4b794a72342 |
>| bindflt | C:\Windows\system32\drivers\bindflt.sys | true | 103737c5c139bfa688ea52c3f1fdf8cc |
>| bindflt | C:\Windows\system32\drivers\bindflt.sys | true | 103737c5c139bfa688ea52c3f1fdf8cc |
>| BITS | C:\Windows\System32\qmgr.dll | true | 281d188a2bbdad9362f95c280beb5b3c |
>| BITS | C:\Windows\System32\qmgr.dll | true | 281d188a2bbdad9362f95c280beb5b3c |
>| BITS | C:\Windows\System32\qmgr.dll | true | 281d188a2bbdad9362f95c280beb5b3c |
>| BITS | C:\Windows\System32\qmgr.dll | true | 281d188a2bbdad9362f95c280beb5b3c |
>| bowser | C:\Windows\system32\DRIVERS\bowser.sys | true | 1349bea208c0f48534cfde0e8a64c3a4 |
>| bowser | C:\Windows\system32\DRIVERS\bowser.sys | true | 1349bea208c0f48534cfde0e8a64c3a4 |
>| BrokerInfrastructure | C:\Windows\System32\psmsrv.dll | true | bc4b6649d990be50025e7d0fd224d37d |
>| BrokerInfrastructure | C:\Windows\System32\psmsrv.dll | true | bc4b6649d990be50025e7d0fd224d37d |
>| BrokerInfrastructure | C:\Windows\System32\psmsrv.dll | true | bc4b6649d990be50025e7d0fd224d37d |
>| BrokerInfrastructure | C:\Windows\System32\psmsrv.dll | true | bc4b6649d990be50025e7d0fd224d37d |
>| BthEnum | C:\Windows\System32\drivers\BthEnum.sys | true | 09ddb44199f1625e8a6ea521c7e9a478 |
>| BthEnum | C:\Windows\System32\drivers\BthEnum.sys | true | 09ddb44199f1625e8a6ea521c7e9a478 |
>| BthLEEnum | C:\Windows\System32\drivers\Microsoft.Bluetooth.Legacy.LEEnumerator.sys | true | c899a971a3bb2cdda438cb642053cad6 |
>| BthLEEnum | C:\Windows\System32\drivers\Microsoft.Bluetooth.Legacy.LEEnumerator.sys | true | c899a971a3bb2cdda438cb642053cad6 |
>| BthMini | C:\Windows\System32\drivers\BTHMINI.sys | true | 10d4fed3a2e82b12304927083290e3ce |
>| BthMini | C:\Windows\System32\drivers\BTHMINI.sys | true | 10d4fed3a2e82b12304927083290e3ce |
>| BTHPORT | C:\Windows\System32\drivers\BTHport.sys | true | 1547b7ad9addee1663506948b024b51f |
>| BTHPORT | C:\Windows\System32\drivers\BTHport.sys | true | 1547b7ad9addee1663506948b024b51f |
>| bthserv | C:\Windows\system32\bthserv.dll | true | 3606a16f0a4f4f0ba40e03841b1fbc9c |
>| bthserv | C:\Windows\system32\bthserv.dll | true | 3606a16f0a4f4f0ba40e03841b1fbc9c |
>| bthserv | C:\Windows\system32\bthserv.dll | true | 3606a16f0a4f4f0ba40e03841b1fbc9c |
>| bthserv | C:\Windows\system32\bthserv.dll | true | 3606a16f0a4f4f0ba40e03841b1fbc9c |
>| BTHUSB | C:\Windows\System32\drivers\BTHUSB.sys | true | 46a773faa4bfe55844aa76a4e69e64dd |
>| BTHUSB | C:\Windows\System32\drivers\BTHUSB.sys | true | 46a773faa4bfe55844aa76a4e69e64dd |
>| bttflt | C:\Windows\System32\drivers\bttflt.sys | true | 2d9693d57bfa0a2c8d11b3e10a48dc70 |
>| bttflt | C:\Windows\System32\drivers\bttflt.sys | true | 2d9693d57bfa0a2c8d11b3e10a48dc70 |
>| buttonconverter | C:\Windows\System32\drivers\buttonconverter.sys | true | be71bd2984ec4ae37b1ea1cb99609726 |
>| buttonconverter | C:\Windows\System32\drivers\buttonconverter.sys | true | be71bd2984ec4ae37b1ea1cb99609726 |
>| bxfcoe | C:\Windows\System32\drivers\bxfcoe.sys | true | 7f01a40445b05531accf186859dd2dfb |
>| bxfcoe | C:\Windows\System32\drivers\bxfcoe.sys | true | 7f01a40445b05531accf186859dd2dfb |
>| bxois | C:\Windows\System32\drivers\bxois.sys | true | 64446c440de1ae190781652f3a839b76 |
>| bxois | C:\Windows\System32\drivers\bxois.sys | true | 64446c440de1ae190781652f3a839b76 |
>| camsvc | C:\Windows\system32\CapabilityAccessManager.dll | true | bb760be2ee24202eda8aa95ea3f19187 |
>| camsvc | C:\Windows\system32\CapabilityAccessManager.dll | true | bb760be2ee24202eda8aa95ea3f19187 |
>| camsvc | C:\Windows\system32\CapabilityAccessManager.dll | true | bb760be2ee24202eda8aa95ea3f19187 |
>| camsvc | C:\Windows\system32\CapabilityAccessManager.dll | true | bb760be2ee24202eda8aa95ea3f19187 |
>| CaptureService | C:\Windows\System32\CaptureService.dll | true | d310d5c17e7da85a9de3de89dd2bfbe1 |
>| CaptureService | C:\Windows\System32\CaptureService.dll | true | d310d5c17e7da85a9de3de89dd2bfbe1 |
>| CaptureService | C:\Windows\System32\CaptureService.dll | true | d310d5c17e7da85a9de3de89dd2bfbe1 |
>| CaptureService | C:\Windows\System32\CaptureService.dll | true | d310d5c17e7da85a9de3de89dd2bfbe1 |
>| CaptureService_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| cbdhsvc | C:\Windows\System32\cbdhsvc.dll | true | b99920e79fdea57e927be2afa11a1a6c |
>| cbdhsvc | C:\Windows\System32\cbdhsvc.dll | true | b99920e79fdea57e927be2afa11a1a6c |
>| cbdhsvc | C:\Windows\System32\cbdhsvc.dll | true | b99920e79fdea57e927be2afa11a1a6c |
>| cbdhsvc | C:\Windows\System32\cbdhsvc.dll | true | b99920e79fdea57e927be2afa11a1a6c |
>| cbdhsvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| cdfs | C:\Windows\system32\DRIVERS\cdfs.sys | true | 1fc91edd3318f27f89f7d8b933027e3b |
>| cdfs | C:\Windows\system32\DRIVERS\cdfs.sys | true | 1fc91edd3318f27f89f7d8b933027e3b |
>| CDPSvc | C:\Windows\System32\CDPSvc.dll | true | 109fe085df395e6a011520c9620b4168 |
>| CDPSvc | C:\Windows\System32\CDPSvc.dll | true | 109fe085df395e6a011520c9620b4168 |
>| CDPSvc | C:\Windows\System32\CDPSvc.dll | true | 109fe085df395e6a011520c9620b4168 |
>| CDPSvc | C:\Windows\System32\CDPSvc.dll | true | 109fe085df395e6a011520c9620b4168 |
>| CDPUserSvc | C:\Windows\System32\CDPUserSvc.dll | true | 3df347c5c82f7ffc7866f093355be573 |
>| CDPUserSvc | C:\Windows\System32\CDPUserSvc.dll | true | 3df347c5c82f7ffc7866f093355be573 |
>| CDPUserSvc | C:\Windows\System32\CDPUserSvc.dll | true | 3df347c5c82f7ffc7866f093355be573 |
>| CDPUserSvc | C:\Windows\System32\CDPUserSvc.dll | true | 3df347c5c82f7ffc7866f093355be573 |
>| CDPUserSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| cdrom | C:\Windows\System32\drivers\cdrom.sys | true | f8598f378ec752af85fa3f642a870906 |
>| cdrom | C:\Windows\System32\drivers\cdrom.sys | true | f8598f378ec752af85fa3f642a870906 |
>| CertPropSvc | C:\Windows\System32\certprop.dll | true | b4032b436f4ff0cc8f160a1f9f57de43 |
>| CertPropSvc | C:\Windows\System32\certprop.dll | true | b4032b436f4ff0cc8f160a1f9f57de43 |
>| CertPropSvc | C:\Windows\System32\certprop.dll | true | b4032b436f4ff0cc8f160a1f9f57de43 |
>| CertPropSvc | C:\Windows\System32\certprop.dll | true | b4032b436f4ff0cc8f160a1f9f57de43 |
>| cht4iscsi | C:\Windows\System32\drivers\cht4sx64.sys | true | 1ebe9210bda30f1a102448d636af4afc |
>| cht4iscsi | C:\Windows\System32\drivers\cht4sx64.sys | true | 1ebe9210bda30f1a102448d636af4afc |
>| cht4vbd | C:\Windows\System32\drivers\cht4vx64.sys | true | 317534412235dc97d73a912174dc7a8e |
>| cht4vbd | C:\Windows\System32\drivers\cht4vx64.sys | true | 317534412235dc97d73a912174dc7a8e |
>| CimFS | C:\Windows\system32\drivers\CimFS.sys | true | c77761c2f092d133329ffa7e5756c216 |
>| CimFS | C:\Windows\system32\drivers\CimFS.sys | true | c77761c2f092d133329ffa7e5756c216 |
>| CldFlt | C:\Windows\system32\drivers\cldflt.sys | true | ce5e59e0b763ec8495c9a623519d55ee |
>| CldFlt | C:\Windows\system32\drivers\cldflt.sys | true | ce5e59e0b763ec8495c9a623519d55ee |
>| CLFS | C:\Windows\System32\drivers\CLFS.sys | true | e1276c5405944c290a27c9c5544e8318 |
>| CLFS | C:\Windows\System32\drivers\CLFS.sys | true | e1276c5405944c290a27c9c5544e8318 |
>| ClipSVC | C:\Windows\System32\ClipSVC.dll | true | 0daef1ac909e5bac136c6405e08822e3 |
>| ClipSVC | C:\Windows\System32\ClipSVC.dll | true | 0daef1ac909e5bac136c6405e08822e3 |
>| ClipSVC | C:\Windows\System32\ClipSVC.dll | true | 0daef1ac909e5bac136c6405e08822e3 |
>| ClipSVC | C:\Windows\System32\ClipSVC.dll | true | 0daef1ac909e5bac136c6405e08822e3 |
>| CmBatt | C:\Windows\System32\drivers\CmBatt.sys | true | bff879e5bb87092532be8229528c2100 |
>| CmBatt | C:\Windows\System32\drivers\CmBatt.sys | true | bff879e5bb87092532be8229528c2100 |
>| CNG | C:\Windows\System32\Drivers\cng.sys | true | 395e313507ca049e185ea3f6356fefdb |
>| CNG | C:\Windows\System32\Drivers\cng.sys | true | 395e313507ca049e185ea3f6356fefdb |
>| cnghwassist | C:\Windows\System32\DRIVERS\cnghwassist.sys | true | 7205b61c138ec4ba872eca13e29fb36d |
>| cnghwassist | C:\Windows\System32\DRIVERS\cnghwassist.sys | true | 7205b61c138ec4ba872eca13e29fb36d |
>| CompositeBus | C:\Windows\System32\DriverStore\FileRepository\compositebus.inf_amd64_130dea07a2ae55eb\CompositeBus.sys | true | 564ac50963890f9b3ab0052c249dbc21 |
>| CompositeBus | C:\Windows\System32\DriverStore\FileRepository\compositebus.inf_amd64_130dea07a2ae55eb\CompositeBus.sys | true | 564ac50963890f9b3ab0052c249dbc21 |
>| COMSysApp | C:\Windows\system32\dllhost.exe | true | 61b7ccf84d2b4251bd263e75cd103f89 |
>| COMSysApp | C:\Windows\system32\dllhost.exe | true | 61b7ccf84d2b4251bd263e75cd103f89 |
>| condrv | C:\Windows\System32\drivers\condrv.sys | true | 122c522158f2499cee46e1d2e2b59787 |
>| condrv | C:\Windows\System32\drivers\condrv.sys | true | 122c522158f2499cee46e1d2e2b59787 |
>| ConsentUxUserSvc | C:\Windows\System32\ConsentUxClient.dll | true | 8af78007b67e0864abbd5122f4e74965 |
>| ConsentUxUserSvc | C:\Windows\System32\ConsentUxClient.dll | true | 8af78007b67e0864abbd5122f4e74965 |
>| ConsentUxUserSvc | C:\Windows\System32\ConsentUxClient.dll | true | 8af78007b67e0864abbd5122f4e74965 |
>| ConsentUxUserSvc | C:\Windows\System32\ConsentUxClient.dll | true | 8af78007b67e0864abbd5122f4e74965 |
>| ConsentUxUserSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| CoreMessagingRegistrar | C:\Windows\system32\coremessaging.dll | true | fb8f3e75fe5456e96bf4d3208f2a224e |
>| CoreMessagingRegistrar | C:\Windows\system32\coremessaging.dll | true | fb8f3e75fe5456e96bf4d3208f2a224e |
>| CoreMessagingRegistrar | C:\Windows\system32\coremessaging.dll | true | fb8f3e75fe5456e96bf4d3208f2a224e |
>| CoreMessagingRegistrar | C:\Windows\system32\coremessaging.dll | true | fb8f3e75fe5456e96bf4d3208f2a224e |
>| CredentialEnrollmentManagerUserSvc | C:\Windows\system32\CredentialEnrollmentManager.exe | true | 92353f4f74b12eb0029981f877573ee5 |
>| CredentialEnrollmentManagerUserSvc | C:\Windows\system32\CredentialEnrollmentManager.exe | true | 92353f4f74b12eb0029981f877573ee5 |
>| CredentialEnrollmentManagerUserSvc_15391515 | C:\Windows\system32\CredentialEnrollmentManager.exe | true | 92353f4f74b12eb0029981f877573ee5 |
>| CryptSvc | C:\Windows\system32\cryptsvc.dll | true | 319a817f297872b1e9ce67381b23604e |
>| CryptSvc | C:\Windows\system32\cryptsvc.dll | true | 319a817f297872b1e9ce67381b23604e |
>| CryptSvc | C:\Windows\system32\cryptsvc.dll | true | 319a817f297872b1e9ce67381b23604e |
>| CryptSvc | C:\Windows\system32\cryptsvc.dll | true | 319a817f297872b1e9ce67381b23604e |
>| CSC | C:\Windows\system32\drivers\csc.sys | true | 6eb74a585f9f26c263486ec792d7b7a7 |
>| CSC | C:\Windows\system32\drivers\csc.sys | true | 6eb74a585f9f26c263486ec792d7b7a7 |
>| CscService | C:\Windows\System32\cscsvc.dll | true | 12cd55cfcb592d17155ebd7241627729 |
>| CscService | C:\Windows\System32\cscsvc.dll | true | 12cd55cfcb592d17155ebd7241627729 |
>| CscService | C:\Windows\System32\cscsvc.dll | true | 12cd55cfcb592d17155ebd7241627729 |
>| CscService | C:\Windows\System32\cscsvc.dll | true | 12cd55cfcb592d17155ebd7241627729 |
>| dam | C:\Windows\system32\drivers\dam.sys | true | 96f5fff1968b938b4606b1309e0afcaa |
>| dam | C:\Windows\system32\drivers\dam.sys | true | 96f5fff1968b938b4606b1309e0afcaa |
>| DcomLaunch | C:\Windows\system32\rpcss.dll | true | 3c8acb412e1a10b923b18a068f814901 |
>| DcomLaunch | C:\Windows\system32\rpcss.dll | true | 3c8acb412e1a10b923b18a068f814901 |
>| DcomLaunch | C:\Windows\system32\rpcss.dll | true | 3c8acb412e1a10b923b18a068f814901 |
>| DcomLaunch | C:\Windows\system32\rpcss.dll | true | 3c8acb412e1a10b923b18a068f814901 |
>| defragsvc | C:\Windows\System32\defragsvc.dll | true | 63e0f044bf8e257ddee2cd56734dc925 |
>| defragsvc | C:\Windows\System32\defragsvc.dll | true | 63e0f044bf8e257ddee2cd56734dc925 |
>| defragsvc | C:\Windows\System32\defragsvc.dll | true | 63e0f044bf8e257ddee2cd56734dc925 |
>| defragsvc | C:\Windows\System32\defragsvc.dll | true | 63e0f044bf8e257ddee2cd56734dc925 |
>| DeviceAssociationBrokerSvc | C:\Windows\System32\deviceaccess.dll | true | 13d7223d89f14c4d20b20bf2fcbfcb87 |
>| DeviceAssociationBrokerSvc | C:\Windows\System32\deviceaccess.dll | true | 13d7223d89f14c4d20b20bf2fcbfcb87 |
>| DeviceAssociationBrokerSvc | C:\Windows\System32\deviceaccess.dll | true | 13d7223d89f14c4d20b20bf2fcbfcb87 |
>| DeviceAssociationBrokerSvc | C:\Windows\System32\deviceaccess.dll | true | 13d7223d89f14c4d20b20bf2fcbfcb87 |
>| DeviceAssociationBrokerSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| DeviceAssociationService | C:\Windows\system32\das.dll | true | 0afd8c3095ffdaa1b5c9178d97a23474 |
>| DeviceAssociationService | C:\Windows\system32\das.dll | true | 0afd8c3095ffdaa1b5c9178d97a23474 |
>| DeviceAssociationService | C:\Windows\system32\das.dll | true | 0afd8c3095ffdaa1b5c9178d97a23474 |
>| DeviceAssociationService | C:\Windows\system32\das.dll | true | 0afd8c3095ffdaa1b5c9178d97a23474 |
>| DeviceInstall | C:\Windows\system32\umpnpmgr.dll | true | 5d65d3b568357eb6ead5578a7b045ab2 |
>| DeviceInstall | C:\Windows\system32\umpnpmgr.dll | true | 5d65d3b568357eb6ead5578a7b045ab2 |
>| DeviceInstall | C:\Windows\system32\umpnpmgr.dll | true | 5d65d3b568357eb6ead5578a7b045ab2 |
>| DeviceInstall | C:\Windows\system32\umpnpmgr.dll | true | 5d65d3b568357eb6ead5578a7b045ab2 |
>| DevicePickerUserSvc | C:\Windows\System32\Windows.Devices.Picker.dll | true | ca54eb49398fafd4ac3ac697f839a291 |
>| DevicePickerUserSvc | C:\Windows\System32\Windows.Devices.Picker.dll | true | ca54eb49398fafd4ac3ac697f839a291 |
>| DevicePickerUserSvc | C:\Windows\System32\Windows.Devices.Picker.dll | true | ca54eb49398fafd4ac3ac697f839a291 |
>| DevicePickerUserSvc | C:\Windows\System32\Windows.Devices.Picker.dll | true | ca54eb49398fafd4ac3ac697f839a291 |
>| DevicePickerUserSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| DevicesFlowUserSvc | C:\Windows\System32\DevicesFlowBroker.dll | true | 3cd95a53dfa873a1f0b4e3a558e7ad6e |
>| DevicesFlowUserSvc | C:\Windows\System32\DevicesFlowBroker.dll | true | 3cd95a53dfa873a1f0b4e3a558e7ad6e |
>| DevicesFlowUserSvc | C:\Windows\System32\DevicesFlowBroker.dll | true | 3cd95a53dfa873a1f0b4e3a558e7ad6e |
>| DevicesFlowUserSvc | C:\Windows\System32\DevicesFlowBroker.dll | true | 3cd95a53dfa873a1f0b4e3a558e7ad6e |
>| DevicesFlowUserSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| DevQueryBroker | C:\Windows\system32\DevQueryBroker.dll | true | 6e36dfc75e2a3f6a1678d0883e17efb5 |
>| DevQueryBroker | C:\Windows\system32\DevQueryBroker.dll | true | 6e36dfc75e2a3f6a1678d0883e17efb5 |
>| DevQueryBroker | C:\Windows\system32\DevQueryBroker.dll | true | 6e36dfc75e2a3f6a1678d0883e17efb5 |
>| DevQueryBroker | C:\Windows\system32\DevQueryBroker.dll | true | 6e36dfc75e2a3f6a1678d0883e17efb5 |
>| Dfsc | C:\Windows\System32\Drivers\dfsc.sys | true | 7317e6235f0f1b1e6fa5a6d2cf9ba724 |
>| Dfsc | C:\Windows\System32\Drivers\dfsc.sys | true | 7317e6235f0f1b1e6fa5a6d2cf9ba724 |
>| Dhcp | C:\Windows\system32\dhcpcore.dll | true | 5be0b037ccdab65bda8a82ba47123dd3 |
>| Dhcp | C:\Windows\system32\dhcpcore.dll | true | 5be0b037ccdab65bda8a82ba47123dd3 |
>| Dhcp | C:\Windows\system32\dhcpcore.dll | true | 5be0b037ccdab65bda8a82ba47123dd3 |
>| Dhcp | C:\Windows\system32\dhcpcore.dll | true | 5be0b037ccdab65bda8a82ba47123dd3 |
>| diagnosticshub.standardcollector.service | C:\Windows\system32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe | true | d9332f687a3c41d4b75c36344943d124 |
>| diagnosticshub.standardcollector.service | C:\Windows\system32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe | true | d9332f687a3c41d4b75c36344943d124 |
>| DiagTrack | C:\Windows\system32\diagtrack.dll | true | 53bef47412a8472fbef772e67d12f8ed |
>| DiagTrack | C:\Windows\system32\diagtrack.dll | true | 53bef47412a8472fbef772e67d12f8ed |
>| DiagTrack | C:\Windows\system32\diagtrack.dll | true | 53bef47412a8472fbef772e67d12f8ed |
>| DiagTrack | C:\Windows\system32\diagtrack.dll | true | 53bef47412a8472fbef772e67d12f8ed |
>| disk | C:\Windows\System32\drivers\disk.sys | true | ba90cfc0d444bb5468fd050073ea5386 |
>| disk | C:\Windows\System32\drivers\disk.sys | true | ba90cfc0d444bb5468fd050073ea5386 |
>| DispBrokerDesktopSvc | C:\Windows\System32\DispBroker.Desktop.dll | true | 8aa4efdc91c635d684242e95d87f9abf |
>| DispBrokerDesktopSvc | C:\Windows\System32\DispBroker.Desktop.dll | true | 8aa4efdc91c635d684242e95d87f9abf |
>| DispBrokerDesktopSvc | C:\Windows\System32\DispBroker.Desktop.dll | true | 8aa4efdc91c635d684242e95d87f9abf |
>| DispBrokerDesktopSvc | C:\Windows\System32\DispBroker.Desktop.dll | true | 8aa4efdc91c635d684242e95d87f9abf |
>| DmEnrollmentSvc | C:\Windows\system32\Windows.Internal.Management.dll | true | a9a8b6cc80eddd9bfd05ab2c7c87301a |
>| DmEnrollmentSvc | C:\Windows\system32\Windows.Internal.Management.dll | true | a9a8b6cc80eddd9bfd05ab2c7c87301a |
>| DmEnrollmentSvc | C:\Windows\system32\Windows.Internal.Management.dll | true | a9a8b6cc80eddd9bfd05ab2c7c87301a |
>| DmEnrollmentSvc | C:\Windows\system32\Windows.Internal.Management.dll | true | a9a8b6cc80eddd9bfd05ab2c7c87301a |
>| dmvsc | C:\Windows\System32\drivers\dmvsc.sys | true | a6ecaa85c49e2af263a842d3f5fc5624 |
>| dmvsc | C:\Windows\System32\drivers\dmvsc.sys | true | a6ecaa85c49e2af263a842d3f5fc5624 |
>| dmwappushservice | C:\Windows\system32\dmwappushsvc.dll | true | e0f1deec69471a3e58ca69cb58401433 |
>| dmwappushservice | C:\Windows\system32\dmwappushsvc.dll | true | e0f1deec69471a3e58ca69cb58401433 |
>| dmwappushservice | C:\Windows\system32\dmwappushsvc.dll | true | e0f1deec69471a3e58ca69cb58401433 |
>| dmwappushservice | C:\Windows\system32\dmwappushsvc.dll | true | e0f1deec69471a3e58ca69cb58401433 |
>| Dnscache | C:\Windows\System32\dnsrslvr.dll | true | d58839fdbc165737a1ea82bb5a7b07d4 |
>| Dnscache | C:\Windows\System32\dnsrslvr.dll | true | d58839fdbc165737a1ea82bb5a7b07d4 |
>| Dnscache | C:\Windows\System32\dnsrslvr.dll | true | d58839fdbc165737a1ea82bb5a7b07d4 |
>| Dnscache | C:\Windows\System32\dnsrslvr.dll | true | d58839fdbc165737a1ea82bb5a7b07d4 |
>| DoSvc | C:\Windows\system32\dosvc.dll | true | 5070aa166b2ca17f568c52308792c92b |
>| DoSvc | C:\Windows\system32\dosvc.dll | true | 5070aa166b2ca17f568c52308792c92b |
>| DoSvc | C:\Windows\system32\dosvc.dll | true | 5070aa166b2ca17f568c52308792c92b |
>| DoSvc | C:\Windows\system32\dosvc.dll | true | 5070aa166b2ca17f568c52308792c92b |
>| dot3svc | C:\Windows\System32\dot3svc.dll | true | d538081afd64ba8b8b68c5f57b28c325 |
>| dot3svc | C:\Windows\System32\dot3svc.dll | true | d538081afd64ba8b8b68c5f57b28c325 |
>| dot3svc | C:\Windows\System32\dot3svc.dll | true | d538081afd64ba8b8b68c5f57b28c325 |
>| dot3svc | C:\Windows\System32\dot3svc.dll | true | d538081afd64ba8b8b68c5f57b28c325 |
>| DPS | C:\Windows\system32\dps.dll | true | f4d554803c8a632b0fed745d45b227cb |
>| DPS | C:\Windows\system32\dps.dll | true | f4d554803c8a632b0fed745d45b227cb |
>| DPS | C:\Windows\system32\dps.dll | true | f4d554803c8a632b0fed745d45b227cb |
>| DPS | C:\Windows\system32\dps.dll | true | f4d554803c8a632b0fed745d45b227cb |
>| drmkaud | C:\Windows\System32\drivers\drmkaud.sys | true | aa500840eb057c1ce27e10b225500491 |
>| drmkaud | C:\Windows\System32\drivers\drmkaud.sys | true | aa500840eb057c1ce27e10b225500491 |
>| DsmSvc | C:\Windows\System32\DeviceSetupManager.dll | true | 874678e69a14e93d8f4efe27edc0bd89 |
>| DsmSvc | C:\Windows\System32\DeviceSetupManager.dll | true | 874678e69a14e93d8f4efe27edc0bd89 |
>| DsmSvc | C:\Windows\System32\DeviceSetupManager.dll | true | 874678e69a14e93d8f4efe27edc0bd89 |
>| DsmSvc | C:\Windows\System32\DeviceSetupManager.dll | true | 874678e69a14e93d8f4efe27edc0bd89 |
>| DsSvc | C:\Windows\System32\DsSvc.dll | true | 2643e9b10cb1e0f3d4e1a3c67f7f8fd5 |
>| DsSvc | C:\Windows\System32\DsSvc.dll | true | 2643e9b10cb1e0f3d4e1a3c67f7f8fd5 |
>| DsSvc | C:\Windows\System32\DsSvc.dll | true | 2643e9b10cb1e0f3d4e1a3c67f7f8fd5 |
>| DsSvc | C:\Windows\System32\DsSvc.dll | true | 2643e9b10cb1e0f3d4e1a3c67f7f8fd5 |
>| DXGKrnl | C:\Windows\System32\drivers\dxgkrnl.sys | true | 2e247733503fa28483e871dba19519b9 |
>| DXGKrnl | C:\Windows\System32\drivers\dxgkrnl.sys | true | 2e247733503fa28483e871dba19519b9 |
>| E1G60 | C:\Windows\System32\drivers\E1G6032E.sys | true | cced99682127e8582e5f716ece775ef8 |
>| E1G60 | C:\Windows\System32\drivers\E1G6032E.sys | true | cced99682127e8582e5f716ece775ef8 |
>| EapHost | C:\Windows\System32\eapsvc.dll | true | d0e7f0f99ea7d7ce4d5922dfe4d805e0 |
>| EapHost | C:\Windows\System32\eapsvc.dll | true | d0e7f0f99ea7d7ce4d5922dfe4d805e0 |
>| EapHost | C:\Windows\System32\eapsvc.dll | true | d0e7f0f99ea7d7ce4d5922dfe4d805e0 |
>| EapHost | C:\Windows\System32\eapsvc.dll | true | d0e7f0f99ea7d7ce4d5922dfe4d805e0 |
>| ebdrv | C:\Windows\System32\drivers\evbda.sys | true | bf9558be00bf1a6589bcf3a051e6e7ae |
>| ebdrv | C:\Windows\System32\drivers\evbda.sys | true | bf9558be00bf1a6589bcf3a051e6e7ae |
>| ebdrv0 | C:\Windows\System32\drivers\evbd0a.sys | true | 00efb0977b9f3bf7b4d37ec18f132853 |
>| ebdrv0 | C:\Windows\System32\drivers\evbd0a.sys | true | 00efb0977b9f3bf7b4d37ec18f132853 |
>| edgeupdate | C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe | true | 8661fbb97161096be503cd295aa46409 |
>| edgeupdate | C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe | true | 8661fbb97161096be503cd295aa46409 |
>| edgeupdatem | C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe | true | 8661fbb97161096be503cd295aa46409 |
>| edgeupdatem | C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe | true | 8661fbb97161096be503cd295aa46409 |
>| EFS | C:\Windows\system32\efssvc.dll | true | a19b76eb605d8561b85e7db5ea2a4ca6 |
>| EFS | C:\Windows\system32\efssvc.dll | true | a19b76eb605d8561b85e7db5ea2a4ca6 |
>| EFS | C:\Windows\system32\efssvc.dll | true | a19b76eb605d8561b85e7db5ea2a4ca6 |
>| EFS | C:\Windows\system32\efssvc.dll | true | a19b76eb605d8561b85e7db5ea2a4ca6 |
>| EhStorClass | C:\Windows\System32\drivers\EhStorClass.sys | true | 5a27edc058ead20f9b71c440a6f5c764 |
>| EhStorClass | C:\Windows\System32\drivers\EhStorClass.sys | true | 5a27edc058ead20f9b71c440a6f5c764 |
>| EhStorTcgDrv | C:\Windows\System32\drivers\EhStorTcgDrv.sys | true | 2de507860cba74bb811828d0e4d53ae8 |
>| EhStorTcgDrv | C:\Windows\System32\drivers\EhStorTcgDrv.sys | true | 2de507860cba74bb811828d0e4d53ae8 |
>| elxfcoe | C:\Windows\System32\drivers\elxfcoe.sys | true | f6a339b5b6f9e55607f915da6b9e4bad |
>| elxfcoe | C:\Windows\System32\drivers\elxfcoe.sys | true | f6a339b5b6f9e55607f915da6b9e4bad |
>| elxstor | C:\Windows\System32\drivers\elxstor.sys | true | ec43b5be737b419feb64e79b5b761dcb |
>| elxstor | C:\Windows\System32\drivers\elxstor.sys | true | ec43b5be737b419feb64e79b5b761dcb |
>| embeddedmode | C:\Windows\System32\embeddedmodesvc.dll | true | 2e962cf906a5769b81cfd6debed6c628 |
>| embeddedmode | C:\Windows\System32\embeddedmodesvc.dll | true | 2e962cf906a5769b81cfd6debed6c628 |
>| embeddedmode | C:\Windows\System32\embeddedmodesvc.dll | true | 2e962cf906a5769b81cfd6debed6c628 |
>| embeddedmode | C:\Windows\System32\embeddedmodesvc.dll | true | 2e962cf906a5769b81cfd6debed6c628 |
>| EntAppSvc | C:\Windows\system32\EnterpriseAppMgmtSvc.dll | true | a45ab5d1dd5ec33d9bc8dc2842b6f356 |
>| EntAppSvc | C:\Windows\system32\EnterpriseAppMgmtSvc.dll | true | a45ab5d1dd5ec33d9bc8dc2842b6f356 |
>| EntAppSvc | C:\Windows\system32\EnterpriseAppMgmtSvc.dll | true | a45ab5d1dd5ec33d9bc8dc2842b6f356 |
>| EntAppSvc | C:\Windows\system32\EnterpriseAppMgmtSvc.dll | true | a45ab5d1dd5ec33d9bc8dc2842b6f356 |
>| ErrDev | C:\Windows\System32\drivers\errdev.sys | true | 1de1972ed980f41a9c9a9c09f51e2a59 |
>| ErrDev | C:\Windows\System32\drivers\errdev.sys | true | 1de1972ed980f41a9c9a9c09f51e2a59 |
>| EventLog | C:\Windows\System32\wevtsvc.dll | true | 3e2a77f5201f5dc3f39e132bb47e64f6 |
>| EventLog | C:\Windows\System32\wevtsvc.dll | true | 3e2a77f5201f5dc3f39e132bb47e64f6 |
>| EventLog | C:\Windows\System32\wevtsvc.dll | true | 3e2a77f5201f5dc3f39e132bb47e64f6 |
>| EventLog | C:\Windows\System32\wevtsvc.dll | true | 3e2a77f5201f5dc3f39e132bb47e64f6 |
>| EventSystem | C:\Windows\system32\es.dll | true | 67abe57f98be8fca9b1c18a1f74382c4 |
>| EventSystem | C:\Windows\system32\es.dll | true | 67abe57f98be8fca9b1c18a1f74382c4 |
>| EventSystem | C:\Windows\system32\es.dll | true | 67abe57f98be8fca9b1c18a1f74382c4 |
>| EventSystem | C:\Windows\system32\es.dll | true | 67abe57f98be8fca9b1c18a1f74382c4 |
>| ExecutionContext | C:\Windows\System32\Drivers\ExecutionContext.sys | true | f5a6bf8112fb07498220f22de333bc32 |
>| ExecutionContext | C:\Windows\System32\Drivers\ExecutionContext.sys | true | f5a6bf8112fb07498220f22de333bc32 |
>| exfat | C:\Windows\system32\drivers\exfat.sys | true | 51b1911604dbc2aaac66f2c93f61313d |
>| exfat | C:\Windows\system32\drivers\exfat.sys | true | 51b1911604dbc2aaac66f2c93f61313d |
>| fastfat | C:\Windows\system32\drivers\fastfat.sys | true | f145863ca528a8975a72b8cdf3ec20e8 |
>| fastfat | C:\Windows\system32\drivers\fastfat.sys | true | f145863ca528a8975a72b8cdf3ec20e8 |
>| fcvsc | C:\Windows\System32\drivers\fcvsc.sys | true | bf4566cba4ee0e25ef6a6bad79096929 |
>| fcvsc | C:\Windows\System32\drivers\fcvsc.sys | true | bf4566cba4ee0e25ef6a6bad79096929 |
>| fdc | C:\Windows\System32\drivers\fdc.sys | true | 212b609f85bbc35aa0d95e97a5e58ff0 |
>| fdc | C:\Windows\System32\drivers\fdc.sys | true | 212b609f85bbc35aa0d95e97a5e58ff0 |
>| fdPHost | C:\Windows\system32\fdPHost.dll | true | 80beaa8991d5b09b19a2d7bd835340d0 |
>| fdPHost | C:\Windows\system32\fdPHost.dll | true | 80beaa8991d5b09b19a2d7bd835340d0 |
>| fdPHost | C:\Windows\system32\fdPHost.dll | true | 80beaa8991d5b09b19a2d7bd835340d0 |
>| fdPHost | C:\Windows\system32\fdPHost.dll | true | 80beaa8991d5b09b19a2d7bd835340d0 |
>| FDResPub | C:\Windows\system32\fdrespub.dll | true | ed10b44a9934f2e85e0f5d0725b9c0c9 |
>| FDResPub | C:\Windows\system32\fdrespub.dll | true | ed10b44a9934f2e85e0f5d0725b9c0c9 |
>| FDResPub | C:\Windows\system32\fdrespub.dll | true | ed10b44a9934f2e85e0f5d0725b9c0c9 |
>| FDResPub | C:\Windows\system32\fdrespub.dll | true | ed10b44a9934f2e85e0f5d0725b9c0c9 |
>| FileCrypt | C:\Windows\system32\drivers\filecrypt.sys | true | 087265c07e4364fd44d213b7b3fd57b3 |
>| FileCrypt | C:\Windows\system32\drivers\filecrypt.sys | true | 087265c07e4364fd44d213b7b3fd57b3 |
>| FileInfo | C:\Windows\System32\drivers\fileinfo.sys | true | 9b67c1da0fde4a75445563a149df0eca |
>| FileInfo | C:\Windows\System32\drivers\fileinfo.sys | true | 9b67c1da0fde4a75445563a149df0eca |
>| Filetrace | C:\Windows\system32\drivers\filetrace.sys | true | c5638db3ff68a149ed74a254934a60ce |
>| Filetrace | C:\Windows\system32\drivers\filetrace.sys | true | c5638db3ff68a149ed74a254934a60ce |
>| flpydisk | C:\Windows\System32\drivers\flpydisk.sys | true | 8d2e7cc9a395900499cebe5edf17097e |
>| flpydisk | C:\Windows\System32\drivers\flpydisk.sys | true | 8d2e7cc9a395900499cebe5edf17097e |
>| FltMgr | C:\Windows\system32\drivers\fltmgr.sys | true | a5da65b212ef41444f5c663bd0bc733e |
>| FltMgr | C:\Windows\system32\drivers\fltmgr.sys | true | a5da65b212ef41444f5c663bd0bc733e |
>| FontCache | C:\Windows\system32\FntCache.dll | true | 0649553c3dea8087fd54550a82a28b5f |
>| FontCache | C:\Windows\system32\FntCache.dll | true | 0649553c3dea8087fd54550a82a28b5f |
>| FontCache | C:\Windows\system32\FntCache.dll | true | 0649553c3dea8087fd54550a82a28b5f |
>| FontCache | C:\Windows\system32\FntCache.dll | true | 0649553c3dea8087fd54550a82a28b5f |
>| FrameServer | C:\Windows\system32\FrameServer.dll | true | 2542241d229b2a14b6ae33c596b7bff6 |
>| FrameServer | C:\Windows\system32\FrameServer.dll | true | 2542241d229b2a14b6ae33c596b7bff6 |
>| FrameServer | C:\Windows\system32\FrameServer.dll | true | 2542241d229b2a14b6ae33c596b7bff6 |
>| FrameServer | C:\Windows\system32\FrameServer.dll | true | 2542241d229b2a14b6ae33c596b7bff6 |
>| FrameServerMonitor | C:\Windows\system32\FrameServerMonitor.dll | true | 73757b2c694a93d27facc6ce234ed64c |
>| FrameServerMonitor | C:\Windows\system32\FrameServerMonitor.dll | true | 73757b2c694a93d27facc6ce234ed64c |
>| FrameServerMonitor | C:\Windows\system32\FrameServerMonitor.dll | true | 73757b2c694a93d27facc6ce234ed64c |
>| FrameServerMonitor | C:\Windows\system32\FrameServerMonitor.dll | true | 73757b2c694a93d27facc6ce234ed64c |
>| Fs_Rec | C:\Windows\system32\drivers\Fs_Rec.sys | true | b778af9c823c027d4e3f2de30eeccc60 |
>| Fs_Rec | C:\Windows\system32\drivers\Fs_Rec.sys | true | b778af9c823c027d4e3f2de30eeccc60 |
>| FsDepends | C:\Windows\System32\drivers\FsDepends.sys | true | edc8f056d9615404608160a2b5a26c9b |
>| FsDepends | C:\Windows\System32\drivers\FsDepends.sys | true | edc8f056d9615404608160a2b5a26c9b |
>| gencounter | C:\Windows\System32\drivers\vmgencounter.sys | true | db24ed511b253b6da808e2e58e60d590 |
>| gencounter | C:\Windows\System32\drivers\vmgencounter.sys | true | db24ed511b253b6da808e2e58e60d590 |
>| genericusbfn | C:\Windows\System32\DriverStore\FileRepository\genericusbfn.inf_amd64_e5e79fac2038997d\genericusbfn.sys | true | e1126b8f09af9df1d765052eb8f9c870 |
>| genericusbfn | C:\Windows\System32\DriverStore\FileRepository\genericusbfn.inf_amd64_e5e79fac2038997d\genericusbfn.sys | true | e1126b8f09af9df1d765052eb8f9c870 |
>| GPIOClx0101 | C:\Windows\System32\Drivers\msgpioclx.sys | true | 430483252e2e63ab11f3b80a49c04dd2 |
>| GPIOClx0101 | C:\Windows\System32\Drivers\msgpioclx.sys | true | 430483252e2e63ab11f3b80a49c04dd2 |
>| gpsvc | C:\Windows\System32\gpsvc.dll | true | 2356276cb2990efc3243ecfcae16f373 |
>| gpsvc | C:\Windows\System32\gpsvc.dll | true | 2356276cb2990efc3243ecfcae16f373 |
>| gpsvc | C:\Windows\System32\gpsvc.dll | true | 2356276cb2990efc3243ecfcae16f373 |
>| gpsvc | C:\Windows\System32\gpsvc.dll | true | 2356276cb2990efc3243ecfcae16f373 |
>| GraphicsPerfSvc | C:\Windows\System32\GraphicsPerfSvc.dll | true | 4e1b563c2e25df41df413b95524d2a64 |
>| GraphicsPerfSvc | C:\Windows\System32\GraphicsPerfSvc.dll | true | 4e1b563c2e25df41df413b95524d2a64 |
>| GraphicsPerfSvc | C:\Windows\System32\GraphicsPerfSvc.dll | true | 4e1b563c2e25df41df413b95524d2a64 |
>| GraphicsPerfSvc | C:\Windows\System32\GraphicsPerfSvc.dll | true | 4e1b563c2e25df41df413b95524d2a64 |
>| HdAudAddService | C:\Windows\System32\drivers\HdAudio.sys | true | 448fd9c281d4c90d32ffe997195ed535 |
>| HdAudAddService | C:\Windows\System32\drivers\HdAudio.sys | true | 448fd9c281d4c90d32ffe997195ed535 |
>| HDAudBus | C:\Windows\System32\drivers\HDAudBus.sys | true | 9734c4c12eb469fb4bd59495e3a54009 |
>| HDAudBus | C:\Windows\System32\drivers\HDAudBus.sys | true | 9734c4c12eb469fb4bd59495e3a54009 |
>| HidBatt | C:\Windows\System32\drivers\HidBatt.sys | true | 33853a00b6cf34f3d7af55ce3651bdc7 |
>| HidBatt | C:\Windows\System32\drivers\HidBatt.sys | true | 33853a00b6cf34f3d7af55ce3651bdc7 |
>| hidinterrupt | C:\Windows\System32\drivers\hidinterrupt.sys | true | 172da51b76e31ab5aedc4bb861ba90ac |
>| hidinterrupt | C:\Windows\System32\drivers\hidinterrupt.sys | true | 172da51b76e31ab5aedc4bb861ba90ac |
>| hidserv | C:\Windows\system32\hidserv.dll | true | 1969d81e14152856fd487a773740700d |
>| hidserv | C:\Windows\system32\hidserv.dll | true | 1969d81e14152856fd487a773740700d |
>| hidserv | C:\Windows\system32\hidserv.dll | true | 1969d81e14152856fd487a773740700d |
>| hidserv | C:\Windows\system32\hidserv.dll | true | 1969d81e14152856fd487a773740700d |
>| HidUsb | C:\Windows\System32\drivers\hidusb.sys | true | 0c8824a963647937f56ed477185ed4ab |
>| HidUsb | C:\Windows\System32\drivers\hidusb.sys | true | 0c8824a963647937f56ed477185ed4ab |
>| hlab_hurukai | C:\Program Files\HarfangLab\hurukai.exe | true | 05049f1cadb8af2b6893e1ead33351c9 |
>| hlab_hurukai | C:\Program Files\HarfangLab\hurukai.exe | true | 05049f1cadb8af2b6893e1ead33351c9 |
>| hlprotect | C:\Windows\system32\DRIVERS\hlprotect.sys | true | 44480d8a012a7249bc390cbcdb687fee |
>| hlprotect | C:\Windows\system32\DRIVERS\hlprotect.sys | true | 44480d8a012a7249bc390cbcdb687fee |
>| HpSAMD | C:\Windows\System32\drivers\HpSAMD.sys | true | 1508143ba4b199d0a68bd9103883d320 |
>| HpSAMD | C:\Windows\System32\drivers\HpSAMD.sys | true | 1508143ba4b199d0a68bd9103883d320 |
>| HTTP | C:\Windows\system32\drivers\HTTP.sys | true | 0db27d34c898a592dcf7e4a5eeacc2be |
>| HTTP | C:\Windows\system32\drivers\HTTP.sys | true | 0db27d34c898a592dcf7e4a5eeacc2be |
>| hvcrash | C:\Windows\System32\drivers\hvcrash.sys | true | cf13e7ed04e5135bab1e6b063b78c5d2 |
>| hvcrash | C:\Windows\System32\drivers\hvcrash.sys | true | cf13e7ed04e5135bab1e6b063b78c5d2 |
>| HvHost | C:\Windows\System32\hvhostsvc.dll | true | 5b4f5403bf684aaf8a70d9e6ffb2b828 |
>| HvHost | C:\Windows\System32\hvhostsvc.dll | true | 5b4f5403bf684aaf8a70d9e6ffb2b828 |
>| HvHost | C:\Windows\System32\hvhostsvc.dll | true | 5b4f5403bf684aaf8a70d9e6ffb2b828 |
>| HvHost | C:\Windows\System32\hvhostsvc.dll | true | 5b4f5403bf684aaf8a70d9e6ffb2b828 |
>| hvservice | C:\Windows\system32\drivers\hvservice.sys | true | 50625583f00248cfbeecedbb5136b068 |
>| hvservice | C:\Windows\system32\drivers\hvservice.sys | true | 50625583f00248cfbeecedbb5136b068 |
>| HwNClx0101 | C:\Windows\System32\Drivers\mshwnclx.sys | true | 8aedd7e0bc41408d2d409dac99e630ad |
>| HwNClx0101 | C:\Windows\System32\Drivers\mshwnclx.sys | true | 8aedd7e0bc41408d2d409dac99e630ad |
>| hwpolicy | C:\Windows\System32\drivers\hwpolicy.sys | true | f0fb9fe56b5e072294adb19712334052 |
>| hwpolicy | C:\Windows\System32\drivers\hwpolicy.sys | true | f0fb9fe56b5e072294adb19712334052 |
>| hyperkbd | C:\Windows\System32\drivers\hyperkbd.sys | true | 200eb4ad3fde0cf05307bf9fdb76af77 |
>| hyperkbd | C:\Windows\System32\drivers\hyperkbd.sys | true | 200eb4ad3fde0cf05307bf9fdb76af77 |
>| HyperVideo | C:\Windows\System32\drivers\HyperVideo.sys | true | e30fb2ff97f5c3bfbee0dbdb570d8f04 |
>| HyperVideo | C:\Windows\System32\drivers\HyperVideo.sys | true | e30fb2ff97f5c3bfbee0dbdb570d8f04 |
>| i8042prt | C:\Windows\System32\drivers\i8042prt.sys | true | 8bc4c8d32cea74b3c27a77330ba1ff28 |
>| i8042prt | C:\Windows\System32\drivers\i8042prt.sys | true | 8bc4c8d32cea74b3c27a77330ba1ff28 |
>| iaLPSSi_GPIO | C:\Windows\System32\drivers\iaLPSSi_GPIO.sys | true | 16a10ccedcf5ac4caae43dc9fc40392f |
>| iaLPSSi_GPIO | C:\Windows\System32\drivers\iaLPSSi_GPIO.sys | true | 16a10ccedcf5ac4caae43dc9fc40392f |
>| iaLPSSi_I2C | C:\Windows\System32\drivers\iaLPSSi_I2C.sys | true | eb82a11613326691508d9ed9a4fe29e7 |
>| iaLPSSi_I2C | C:\Windows\System32\drivers\iaLPSSi_I2C.sys | true | eb82a11613326691508d9ed9a4fe29e7 |
>| iaStorAVC | C:\Windows\System32\drivers\iaStorAVC.sys | true | 1c948ca84ec603fd60d36845df59e674 |
>| iaStorAVC | C:\Windows\System32\drivers\iaStorAVC.sys | true | 1c948ca84ec603fd60d36845df59e674 |
>| iaStorV | C:\Windows\System32\drivers\iaStorV.sys | true | 480824c8c73482623d00598d54f775b7 |
>| iaStorV | C:\Windows\System32\drivers\iaStorV.sys | true | 480824c8c73482623d00598d54f775b7 |
>| ibbus | C:\Windows\System32\drivers\ibbus.sys | true | 751e9c5c9917288664ba6cce9df5c5e8 |
>| ibbus | C:\Windows\System32\drivers\ibbus.sys | true | 751e9c5c9917288664ba6cce9df5c5e8 |
>| IKEEXT | C:\Windows\System32\ikeext.dll | true | eea78e98ac78de95198805661a414fda |
>| IKEEXT | C:\Windows\System32\ikeext.dll | true | eea78e98ac78de95198805661a414fda |
>| IKEEXT | C:\Windows\System32\ikeext.dll | true | eea78e98ac78de95198805661a414fda |
>| IKEEXT | C:\Windows\System32\ikeext.dll | true | eea78e98ac78de95198805661a414fda |
>| IndirectKmd | C:\Windows\System32\drivers\IndirectKmd.sys | true | 81ad822e977a93d902f210382c51957d |
>| IndirectKmd | C:\Windows\System32\drivers\IndirectKmd.sys | true | 81ad822e977a93d902f210382c51957d |
>| InstallService | C:\Windows\system32\InstallService.dll | true | 6b72b07a1a123281e17d51565bfe8f52 |
>| InstallService | C:\Windows\system32\InstallService.dll | true | 6b72b07a1a123281e17d51565bfe8f52 |
>| InstallService | C:\Windows\system32\InstallService.dll | true | 6b72b07a1a123281e17d51565bfe8f52 |
>| InstallService | C:\Windows\system32\InstallService.dll | true | 6b72b07a1a123281e17d51565bfe8f52 |
>| intelide | C:\Windows\System32\drivers\intelide.sys | true | 32f91cbd0b66b168082c0472e22c8c89 |
>| intelide | C:\Windows\System32\drivers\intelide.sys | true | 32f91cbd0b66b168082c0472e22c8c89 |
>| intelpep | C:\Windows\System32\drivers\intelpep.sys | true | 4217aa0ec9a2fa258de03b098d83bc71 |
>| intelpep | C:\Windows\System32\drivers\intelpep.sys | true | 4217aa0ec9a2fa258de03b098d83bc71 |
>| IntelPMT | C:\Windows\System32\drivers\IntelPMT.sys | true | 698ad8b52eaaaeeb7a5cad5c28db5af5 |
>| IntelPMT | C:\Windows\System32\drivers\IntelPMT.sys | true | 698ad8b52eaaaeeb7a5cad5c28db5af5 |
>| intelppm | C:\Windows\System32\drivers\intelppm.sys | true | 786f77d638ff941977956898ebcb758e |
>| intelppm | C:\Windows\System32\drivers\intelppm.sys | true | 786f77d638ff941977956898ebcb758e |
>| IpFilterDriver | C:\Windows\system32\DRIVERS\ipfltdrv.sys | true | 9114ee02e916105b160d02f16035e5fe |
>| IpFilterDriver | C:\Windows\system32\DRIVERS\ipfltdrv.sys | true | 9114ee02e916105b160d02f16035e5fe |
>| iphlpsvc | C:\Windows\System32\iphlpsvc.dll | true | e665ff85b75c0391e2885bc05d32a1a8 |
>| iphlpsvc | C:\Windows\System32\iphlpsvc.dll | true | e665ff85b75c0391e2885bc05d32a1a8 |
>| iphlpsvc | C:\Windows\System32\iphlpsvc.dll | true | e665ff85b75c0391e2885bc05d32a1a8 |
>| iphlpsvc | C:\Windows\System32\iphlpsvc.dll | true | e665ff85b75c0391e2885bc05d32a1a8 |
>| IPMIDRV | C:\Windows\System32\drivers\IPMIDrv.sys | true | 0bb68f9ee271fe888c082d38aff404b8 |
>| IPMIDRV | C:\Windows\System32\drivers\IPMIDrv.sys | true | 0bb68f9ee271fe888c082d38aff404b8 |
>| IPNAT | C:\Windows\System32\drivers\ipnat.sys | true | b62339d7184ca9efba38eef2da886c25 |
>| IPNAT | C:\Windows\System32\drivers\ipnat.sys | true | b62339d7184ca9efba38eef2da886c25 |
>| IPT | C:\Windows\System32\drivers\ipt.sys | true | 754df34adf4b729d4bcc82fe0eb472eb |
>| IPT | C:\Windows\System32\drivers\ipt.sys | true | 754df34adf4b729d4bcc82fe0eb472eb |
>| isapnp | C:\Windows\System32\drivers\isapnp.sys | true | a889004ba9dbcbc42836ea373a1dfd2c |
>| isapnp | C:\Windows\System32\drivers\isapnp.sys | true | a889004ba9dbcbc42836ea373a1dfd2c |
>| iScsiPrt | C:\Windows\System32\drivers\msiscsi.sys | true | 998704bd8f01d8036e3b3afc9a9d482d |
>| iScsiPrt | C:\Windows\System32\drivers\msiscsi.sys | true | 998704bd8f01d8036e3b3afc9a9d482d |
>| ItSas35i | C:\Windows\System32\drivers\ItSas35i.sys | true | 28f9dd22eef753bd4f0e618b7279ed35 |
>| ItSas35i | C:\Windows\System32\drivers\ItSas35i.sys | true | 28f9dd22eef753bd4f0e618b7279ed35 |
>| kbdclass | C:\Windows\System32\drivers\kbdclass.sys | true | 27947916ad55bfdb88c6f2e00ac4d90b |
>| kbdclass | C:\Windows\System32\drivers\kbdclass.sys | true | 27947916ad55bfdb88c6f2e00ac4d90b |
>| kbdhid | C:\Windows\System32\drivers\kbdhid.sys | true | 2d8562d442d1b00274da42012b556483 |
>| kbdhid | C:\Windows\System32\drivers\kbdhid.sys | true | 2d8562d442d1b00274da42012b556483 |
>| kdnic | C:\Windows\System32\drivers\kdnic.sys | true | d8ac3b58add59eeb8674787347795806 |
>| kdnic | C:\Windows\System32\drivers\kdnic.sys | true | d8ac3b58add59eeb8674787347795806 |
>| KeyIso | C:\Windows\system32\keyiso.dll | true | 91fd6853a59e1b09ec8b8d139fbeaa8c |
>| KeyIso | C:\Windows\system32\keyiso.dll | true | 91fd6853a59e1b09ec8b8d139fbeaa8c |
>| KeyIso | C:\Windows\system32\keyiso.dll | true | 91fd6853a59e1b09ec8b8d139fbeaa8c |
>| KeyIso | C:\Windows\system32\keyiso.dll | true | 91fd6853a59e1b09ec8b8d139fbeaa8c |
>| KPSSVC | C:\Windows\system32\kpssvc.dll | true | 4416aa41c51c096ebf3a56f5345d6ef3 |
>| KPSSVC | C:\Windows\system32\kpssvc.dll | true | 4416aa41c51c096ebf3a56f5345d6ef3 |
>| KPSSVC | C:\Windows\system32\kpssvc.dll | true | 4416aa41c51c096ebf3a56f5345d6ef3 |
>| KPSSVC | C:\Windows\system32\kpssvc.dll | true | 4416aa41c51c096ebf3a56f5345d6ef3 |
>| KSecDD | C:\Windows\System32\Drivers\ksecdd.sys | true | 9dacc16c05894f8db0b93fb60fcc2341 |
>| KSecDD | C:\Windows\System32\Drivers\ksecdd.sys | true | 9dacc16c05894f8db0b93fb60fcc2341 |
>| KSecPkg | C:\Windows\System32\Drivers\ksecpkg.sys | true | ad9063eeb2a5179acd11bb1754023c30 |
>| KSecPkg | C:\Windows\System32\Drivers\ksecpkg.sys | true | ad9063eeb2a5179acd11bb1754023c30 |
>| ksthunk | C:\Windows\system32\drivers\ksthunk.sys | true | e9dd5b83a72078795d82c19fd3bb01b3 |
>| ksthunk | C:\Windows\system32\drivers\ksthunk.sys | true | e9dd5b83a72078795d82c19fd3bb01b3 |
>| KtmRm | C:\Windows\system32\msdtckrm.dll | true | 94ea6bc52d3c9381dd68cc4e0b0681cb |
>| KtmRm | C:\Windows\system32\msdtckrm.dll | true | 94ea6bc52d3c9381dd68cc4e0b0681cb |
>| KtmRm | C:\Windows\system32\msdtckrm.dll | true | 94ea6bc52d3c9381dd68cc4e0b0681cb |
>| KtmRm | C:\Windows\system32\msdtckrm.dll | true | 94ea6bc52d3c9381dd68cc4e0b0681cb |
>| LanmanServer | C:\Windows\system32\srvsvc.dll | true | d3d16c8bd73661afa1a30c62a0c95f5a |
>| LanmanServer | C:\Windows\system32\srvsvc.dll | true | d3d16c8bd73661afa1a30c62a0c95f5a |
>| LanmanServer | C:\Windows\system32\srvsvc.dll | true | d3d16c8bd73661afa1a30c62a0c95f5a |
>| LanmanServer | C:\Windows\system32\srvsvc.dll | true | d3d16c8bd73661afa1a30c62a0c95f5a |
>| LanmanWorkstation | C:\Windows\System32\wkssvc.dll | true | 1b15d74d6abe450867d42e4523e15932 |
>| LanmanWorkstation | C:\Windows\System32\wkssvc.dll | true | 1b15d74d6abe450867d42e4523e15932 |
>| LanmanWorkstation | C:\Windows\System32\wkssvc.dll | true | 1b15d74d6abe450867d42e4523e15932 |
>| LanmanWorkstation | C:\Windows\System32\wkssvc.dll | true | 1b15d74d6abe450867d42e4523e15932 |
>| lfsvc | C:\Windows\System32\lfsvc.dll | true | bbc9914747a98675fb710cab2756d4e2 |
>| lfsvc | C:\Windows\System32\lfsvc.dll | true | bbc9914747a98675fb710cab2756d4e2 |
>| lfsvc | C:\Windows\System32\lfsvc.dll | true | bbc9914747a98675fb710cab2756d4e2 |
>| lfsvc | C:\Windows\System32\lfsvc.dll | true | bbc9914747a98675fb710cab2756d4e2 |
>| LicenseManager | C:\Windows\system32\LicenseManagerSvc.dll | true | 6b66ac5a2f4be7c9cdf05af6b9ce57a2 |
>| LicenseManager | C:\Windows\system32\LicenseManagerSvc.dll | true | 6b66ac5a2f4be7c9cdf05af6b9ce57a2 |
>| LicenseManager | C:\Windows\system32\LicenseManagerSvc.dll | true | 6b66ac5a2f4be7c9cdf05af6b9ce57a2 |
>| LicenseManager | C:\Windows\system32\LicenseManagerSvc.dll | true | 6b66ac5a2f4be7c9cdf05af6b9ce57a2 |
>| lltdio | C:\Windows\system32\drivers\lltdio.sys | true | 38c53c38731190ba73b39cbd3befe14a |
>| lltdio | C:\Windows\system32\drivers\lltdio.sys | true | 38c53c38731190ba73b39cbd3befe14a |
>| lltdsvc | C:\Windows\System32\lltdsvc.dll | true | c0b356e9e078f1410dd5429b397654fd |
>| lltdsvc | C:\Windows\System32\lltdsvc.dll | true | c0b356e9e078f1410dd5429b397654fd |
>| lltdsvc | C:\Windows\System32\lltdsvc.dll | true | c0b356e9e078f1410dd5429b397654fd |
>| lltdsvc | C:\Windows\System32\lltdsvc.dll | true | c0b356e9e078f1410dd5429b397654fd |
>| lmhosts | C:\Windows\System32\lmhsvc.dll | true | 5c8975bcb1253f23f74b1188b58fb831 |
>| lmhosts | C:\Windows\System32\lmhsvc.dll | true | 5c8975bcb1253f23f74b1188b58fb831 |
>| lmhosts | C:\Windows\System32\lmhsvc.dll | true | 5c8975bcb1253f23f74b1188b58fb831 |
>| lmhosts | C:\Windows\System32\lmhsvc.dll | true | 5c8975bcb1253f23f74b1188b58fb831 |
>| LSI_SAS | C:\Windows\System32\drivers\lsi_sas.sys | true | 07e270396719f62056ddb386ba558890 |
>| LSI_SAS | C:\Windows\System32\drivers\lsi_sas.sys | true | 07e270396719f62056ddb386ba558890 |
>| LSI_SAS2i | C:\Windows\System32\drivers\lsi_sas2i.sys | true | 45a19614b57a9ed2820f8980c419c83e |
>| LSI_SAS2i | C:\Windows\System32\drivers\lsi_sas2i.sys | true | 45a19614b57a9ed2820f8980c419c83e |
>| LSI_SAS3i | C:\Windows\System32\drivers\lsi_sas3i.sys | true | 863ecf3758fb9482979d474f3531d8a7 |
>| LSI_SAS3i | C:\Windows\System32\drivers\lsi_sas3i.sys | true | 863ecf3758fb9482979d474f3531d8a7 |
>| LSM | C:\Windows\System32\lsm.dll | true | a288b85cc6cea70e0cd0ed0496fb6668 |
>| LSM | C:\Windows\System32\lsm.dll | true | a288b85cc6cea70e0cd0ed0496fb6668 |
>| LSM | C:\Windows\System32\lsm.dll | true | a288b85cc6cea70e0cd0ed0496fb6668 |
>| LSM | C:\Windows\System32\lsm.dll | true | a288b85cc6cea70e0cd0ed0496fb6668 |
>| luafv | C:\Windows\system32\drivers\luafv.sys | true | 0e93bc867995100e2bf56be9fa9219a4 |
>| luafv | C:\Windows\system32\drivers\luafv.sys | true | 0e93bc867995100e2bf56be9fa9219a4 |
>| MapsBroker | C:\Windows\System32\moshost.dll | true | c88542305baf639416e7a574f6b0cef4 |
>| MapsBroker | C:\Windows\System32\moshost.dll | true | c88542305baf639416e7a574f6b0cef4 |
>| MapsBroker | C:\Windows\System32\moshost.dll | true | c88542305baf639416e7a574f6b0cef4 |
>| MapsBroker | C:\Windows\System32\moshost.dll | true | c88542305baf639416e7a574f6b0cef4 |
>| mausbhost | C:\Windows\System32\drivers\mausbhost.sys | true | 1e4e6a723b99fde21ec0e8c7a8fffa71 |
>| mausbhost | C:\Windows\System32\drivers\mausbhost.sys | true | 1e4e6a723b99fde21ec0e8c7a8fffa71 |
>| mausbip | C:\Windows\System32\drivers\mausbip.sys | true | 9ccc6aac061537045f92b76aaad46b0f |
>| mausbip | C:\Windows\System32\drivers\mausbip.sys | true | 9ccc6aac061537045f92b76aaad46b0f |
>| McpManagementService | C:\Windows\System32\McpManagementService.dll | true | 4c1bcbeee25c130cbed6502409b8d48d |
>| McpManagementService | C:\Windows\System32\McpManagementService.dll | true | 4c1bcbeee25c130cbed6502409b8d48d |
>| McpManagementService | C:\Windows\System32\McpManagementService.dll | true | 4c1bcbeee25c130cbed6502409b8d48d |
>| McpManagementService | C:\Windows\System32\McpManagementService.dll | true | 4c1bcbeee25c130cbed6502409b8d48d |
>| megasas2i | C:\Windows\System32\drivers\MegaSas2i.sys | true | e86a0dfe0403bda2a9f7985e81e03f18 |
>| megasas2i | C:\Windows\System32\drivers\MegaSas2i.sys | true | e86a0dfe0403bda2a9f7985e81e03f18 |
>| megasas35i | C:\Windows\System32\drivers\megasas35i.sys | true | 22130fe8ff179afc352bbeb1361e3736 |
>| megasas35i | C:\Windows\System32\drivers\megasas35i.sys | true | 22130fe8ff179afc352bbeb1361e3736 |
>| megasr | C:\Windows\System32\drivers\megasr.sys | true | eb665ce09497c75bb685f9b7452aaae4 |
>| megasr | C:\Windows\System32\drivers\megasr.sys | true | eb665ce09497c75bb685f9b7452aaae4 |
>| MicrosoftEdgeElevationService | C:\Program Files (x86)\Microsoft\Edge\Application\103.0.1264.71\elevation_service.exe | true | 7089606148391ff5b6ba662554b987ce |
>| MicrosoftEdgeElevationService |  | false |  |
>| mlx4_bus | C:\Windows\System32\drivers\mlx4_bus.sys | true | 23e0f8fafb42d2e898c9bf0e98ed5d3b |
>| mlx4_bus | C:\Windows\System32\drivers\mlx4_bus.sys | true | 23e0f8fafb42d2e898c9bf0e98ed5d3b |
>| MMCSS | C:\Windows\system32\drivers\mmcss.sys | true | a10c637165ab63671f5ea554109d008c |
>| MMCSS | C:\Windows\system32\drivers\mmcss.sys | true | a10c637165ab63671f5ea554109d008c |
>| Modem | C:\Windows\system32\drivers\modem.sys | true | e36d3293c67e812fb0934cd308251b7b |
>| Modem | C:\Windows\system32\drivers\modem.sys | true | e36d3293c67e812fb0934cd308251b7b |
>| monitor | C:\Windows\System32\drivers\monitor.sys | true | b8f452f5baa586406a190c647c1443e4 |
>| monitor | C:\Windows\System32\drivers\monitor.sys | true | b8f452f5baa586406a190c647c1443e4 |
>| mouclass | C:\Windows\System32\drivers\mouclass.sys | true | 0c34c0630a233c0f62fcdd4d13af0d47 |
>| mouclass | C:\Windows\System32\drivers\mouclass.sys | true | 0c34c0630a233c0f62fcdd4d13af0d47 |
>| mouhid | C:\Windows\System32\drivers\mouhid.sys | true | e5b29bdb8672eed313a4f5b364f299f3 |
>| mouhid | C:\Windows\System32\drivers\mouhid.sys | true | e5b29bdb8672eed313a4f5b364f299f3 |
>| mountmgr | C:\Windows\System32\drivers\mountmgr.sys | true | 531d3c5a7749a2c912ea6a0e5cb67c75 |
>| mountmgr | C:\Windows\System32\drivers\mountmgr.sys | true | 531d3c5a7749a2c912ea6a0e5cb67c75 |
>| mpi3drvi | C:\Windows\System32\drivers\mpi3drvi.sys | true | 38f87c3fbab159c90e15ae1b74e1df74 |
>| mpi3drvi | C:\Windows\System32\drivers\mpi3drvi.sys | true | 38f87c3fbab159c90e15ae1b74e1df74 |
>| MpKsl73942e08 | C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{265C6876-ACFD-4597-B853-B3E54112BC77}\MpKslDrv.sys | true | 6f2f14025a606b924e77ad29aa68d231 |
>| mpsdrv | C:\Windows\System32\drivers\mpsdrv.sys | true | fb4d94870b1f42d93feb8a85b590fd4a |
>| mpsdrv | C:\Windows\System32\drivers\mpsdrv.sys | true | fb4d94870b1f42d93feb8a85b590fd4a |
>| mpssvc | C:\Windows\system32\mpssvc.dll | true | f4a69d94e83e83dd32325e4cbc39ee6c |
>| mpssvc | C:\Windows\system32\mpssvc.dll | true | f4a69d94e83e83dd32325e4cbc39ee6c |
>| mpssvc | C:\Windows\system32\mpssvc.dll | true | f4a69d94e83e83dd32325e4cbc39ee6c |
>| mpssvc | C:\Windows\system32\mpssvc.dll | true | f4a69d94e83e83dd32325e4cbc39ee6c |
>| mrxsmb | C:\Windows\system32\DRIVERS\mrxsmb.sys | true | b0186ea7f1979d9f02da0ae11542d39d |
>| mrxsmb | C:\Windows\system32\DRIVERS\mrxsmb.sys | true | b0186ea7f1979d9f02da0ae11542d39d |
>| mrxsmb20 | C:\Windows\system32\DRIVERS\mrxsmb20.sys | true | 40f91604967e771021b89a54ddb74131 |
>| mrxsmb20 | C:\Windows\system32\DRIVERS\mrxsmb20.sys | true | 40f91604967e771021b89a54ddb74131 |
>| MsBridge | C:\Windows\System32\drivers\bridge.sys | true | 4b1a343b7ca38df4d436b5c6e0244e23 |
>| MsBridge | C:\Windows\System32\drivers\bridge.sys | true | 4b1a343b7ca38df4d436b5c6e0244e23 |
>| MSDTC | C:\Windows\System32\msdtc.exe | true | bd7be47340ba4888b9b47ad323ff51d3 |
>| MSDTC | C:\Windows\System32\msdtc.exe | true | bd7be47340ba4888b9b47ad323ff51d3 |
>| Msfs | C:\Windows\system32\drivers\Msfs.sys | true | 82560bdaf351cd8917f01b5d7a1c03a4 |
>| Msfs | C:\Windows\system32\drivers\Msfs.sys | true | 82560bdaf351cd8917f01b5d7a1c03a4 |
>| msgpiowin32 | C:\Windows\System32\drivers\msgpiowin32.sys | true | 8a3fb7cda5f1db530266974a5e5c5f67 |
>| msgpiowin32 | C:\Windows\System32\drivers\msgpiowin32.sys | true | 8a3fb7cda5f1db530266974a5e5c5f67 |
>| mshidkmdf | C:\Windows\System32\drivers\mshidkmdf.sys | true | 5f00f2ac7756b56e8939d9be36e9cbcd |
>| mshidkmdf | C:\Windows\System32\drivers\mshidkmdf.sys | true | 5f00f2ac7756b56e8939d9be36e9cbcd |
>| mshidumdf | C:\Windows\System32\drivers\mshidumdf.sys | true | eb7684ee29c6122ddd690545d040805b |
>| mshidumdf | C:\Windows\System32\drivers\mshidumdf.sys | true | eb7684ee29c6122ddd690545d040805b |
>| msisadrv | C:\Windows\System32\drivers\msisadrv.sys | true | af9787af0870c3349336c641a9deb816 |
>| msisadrv | C:\Windows\System32\drivers\msisadrv.sys | true | af9787af0870c3349336c641a9deb816 |
>| MSiSCSI | C:\Windows\system32\iscsiexe.dll | true | 0453fba1a7d50eebc8e5ec25bc8e7c18 |
>| MSiSCSI | C:\Windows\system32\iscsiexe.dll | true | 0453fba1a7d50eebc8e5ec25bc8e7c18 |
>| MSiSCSI | C:\Windows\system32\iscsiexe.dll | true | 0453fba1a7d50eebc8e5ec25bc8e7c18 |
>| MSiSCSI | C:\Windows\system32\iscsiexe.dll | true | 0453fba1a7d50eebc8e5ec25bc8e7c18 |
>| msiserver | C:\Windows\system32\msiexec.exe | true | 25e49f426d475e01ecc763e3c433fbf4 |
>| msiserver | C:\Windows\system32\msiexec.exe | true | 25e49f426d475e01ecc763e3c433fbf4 |
>| MSKSSRV | C:\Windows\System32\drivers\MSKSSRV.sys | true | 4cefae5b0b1364ef520d18140a290d54 |
>| MSKSSRV | C:\Windows\System32\drivers\MSKSSRV.sys | true | 4cefae5b0b1364ef520d18140a290d54 |
>| MsLbfoProvider | C:\Windows\System32\drivers\MsLbfoProvider.sys | true | 79ff4b1f24b93f2b2f76225db89f2800 |
>| MsLbfoProvider | C:\Windows\System32\drivers\MsLbfoProvider.sys | true | 79ff4b1f24b93f2b2f76225db89f2800 |
>| MsLldp | C:\Windows\system32\drivers\mslldp.sys | true | d69790cc30e3717431067b1a43a679f1 |
>| MsLldp | C:\Windows\system32\drivers\mslldp.sys | true | d69790cc30e3717431067b1a43a679f1 |
>| MSPCLOCK | C:\Windows\System32\drivers\MSPCLOCK.sys | true | 3ca66375e00b54ca49c5cccb2945ecd8 |
>| MSPCLOCK | C:\Windows\System32\drivers\MSPCLOCK.sys | true | 3ca66375e00b54ca49c5cccb2945ecd8 |
>| MSPQM | C:\Windows\System32\drivers\MSPQM.sys | true | 89d2ce46f0e9eb9b05ae0096dbaa3f88 |
>| MSPQM | C:\Windows\System32\drivers\MSPQM.sys | true | 89d2ce46f0e9eb9b05ae0096dbaa3f88 |
>| MsQuic | C:\Windows\system32\drivers\msquic.sys | true | afb57e498cd26284e9603353fb9104ad |
>| MsQuic | C:\Windows\system32\drivers\msquic.sys | true | afb57e498cd26284e9603353fb9104ad |
>| MsRPC | C:\Windows\system32\drivers\MsRPC.sys | true | 20cbe52b050fa5438428158323e4b0c2 |
>| MsRPC | C:\Windows\system32\drivers\MsRPC.sys | true | 20cbe52b050fa5438428158323e4b0c2 |
>| MsSecFlt | C:\Windows\system32\drivers\mssecflt.sys | true | e4c24f3d6d7968a7f98df30644fbf4c5 |
>| MsSecFlt | C:\Windows\system32\drivers\mssecflt.sys | true | e4c24f3d6d7968a7f98df30644fbf4c5 |
>| mssmbios | C:\Windows\System32\drivers\mssmbios.sys | true | 530d7c0b3e2fc916fb0da8fc8d4b6ef6 |
>| mssmbios | C:\Windows\System32\drivers\mssmbios.sys | true | 530d7c0b3e2fc916fb0da8fc8d4b6ef6 |
>| MSTEE | C:\Windows\System32\drivers\MSTEE.sys | true | 97c653356d853474dd0e51a37b1ccf84 |
>| MSTEE | C:\Windows\System32\drivers\MSTEE.sys | true | 97c653356d853474dd0e51a37b1ccf84 |
>| MTConfig | C:\Windows\System32\drivers\MTConfig.sys | true | 2e0dfbbe12b4fa54d4c1297db1052de6 |
>| MTConfig | C:\Windows\System32\drivers\MTConfig.sys | true | 2e0dfbbe12b4fa54d4c1297db1052de6 |
>| Mup | C:\Windows\System32\Drivers\mup.sys | true | 265830023853939fcbf87ba954f3146a |
>| Mup | C:\Windows\System32\Drivers\mup.sys | true | 265830023853939fcbf87ba954f3146a |
>| mvumis | C:\Windows\System32\drivers\mvumis.sys | true | c54659db8721c4f02bdfa0b15accfb10 |
>| mvumis | C:\Windows\System32\drivers\mvumis.sys | true | c54659db8721c4f02bdfa0b15accfb10 |
>| NcaSvc | C:\Windows\System32\ncasvc.dll | true | 92a214400788becadf0b18b8bf4d42e6 |
>| NcaSvc | C:\Windows\System32\ncasvc.dll | true | 92a214400788becadf0b18b8bf4d42e6 |
>| NcaSvc | C:\Windows\System32\ncasvc.dll | true | 92a214400788becadf0b18b8bf4d42e6 |
>| NcaSvc | C:\Windows\System32\ncasvc.dll | true | 92a214400788becadf0b18b8bf4d42e6 |
>| NcbService | C:\Windows\System32\ncbservice.dll | true | d07f20b05b5b5daddc4c0718e199877b |
>| NcbService | C:\Windows\System32\ncbservice.dll | true | d07f20b05b5b5daddc4c0718e199877b |
>| NcbService | C:\Windows\System32\ncbservice.dll | true | d07f20b05b5b5daddc4c0718e199877b |
>| NcbService | C:\Windows\System32\ncbservice.dll | true | d07f20b05b5b5daddc4c0718e199877b |
>| ndfltr | C:\Windows\System32\drivers\ndfltr.sys | true | a8a9bb0224cf38ad590328d6bcce0d18 |
>| ndfltr | C:\Windows\System32\drivers\ndfltr.sys | true | a8a9bb0224cf38ad590328d6bcce0d18 |
>| NDIS | C:\Windows\system32\drivers\ndis.sys | true | 020222b426ce45d4081826902f1496d2 |
>| NDIS | C:\Windows\system32\drivers\ndis.sys | true | 020222b426ce45d4081826902f1496d2 |
>| NdisCap | C:\Windows\System32\drivers\ndiscap.sys | true | 5c5dab38e24c46cc9e2ac793541780ed |
>| NdisCap | C:\Windows\System32\drivers\ndiscap.sys | true | 5c5dab38e24c46cc9e2ac793541780ed |
>| NdisImPlatform | C:\Windows\System32\drivers\NdisImPlatform.sys | true | e68595b477be8f6d05337cac4d156228 |
>| NdisImPlatform | C:\Windows\System32\drivers\NdisImPlatform.sys | true | e68595b477be8f6d05337cac4d156228 |
>| NdisTapi | C:\Windows\System32\DRIVERS\ndistapi.sys | true | 6246c8ec8b5db04688e42725f584635e |
>| NdisTapi | C:\Windows\System32\DRIVERS\ndistapi.sys | true | 6246c8ec8b5db04688e42725f584635e |
>| Ndisuio | C:\Windows\system32\drivers\ndisuio.sys | true | bddf8bbab954b94f4ce0e66ec2f24c78 |
>| Ndisuio | C:\Windows\system32\drivers\ndisuio.sys | true | bddf8bbab954b94f4ce0e66ec2f24c78 |
>| NdisVirtualBus | C:\Windows\System32\drivers\NdisVirtualBus.sys | true | a686524719ece3235adae3e30214a2db |
>| NdisVirtualBus | C:\Windows\System32\drivers\NdisVirtualBus.sys | true | a686524719ece3235adae3e30214a2db |
>| NdisWan | C:\Windows\System32\drivers\ndiswan.sys | true | 64dba22a45afccc623933d7911fd4fa4 |
>| NdisWan | C:\Windows\System32\drivers\ndiswan.sys | true | 64dba22a45afccc623933d7911fd4fa4 |
>| ndiswanlegacy | C:\Windows\System32\DRIVERS\ndiswan.sys | true | 64dba22a45afccc623933d7911fd4fa4 |
>| ndiswanlegacy | C:\Windows\System32\DRIVERS\ndiswan.sys | true | 64dba22a45afccc623933d7911fd4fa4 |
>| NDKPerf | C:\Windows\system32\drivers\NDKPerf.sys | true | 867e8faa32f42f2c9de504bb77689ea5 |
>| NDKPerf | C:\Windows\system32\drivers\NDKPerf.sys | true | 867e8faa32f42f2c9de504bb77689ea5 |
>| NDKPing | C:\Windows\system32\drivers\NDKPing.sys | true | 0871957b5a113fb809dd430c3bd84617 |
>| NDKPing | C:\Windows\system32\drivers\NDKPing.sys | true | 0871957b5a113fb809dd430c3bd84617 |
>| ndproxy | C:\Windows\System32\DRIVERS\NDProxy.sys | true | 5394cd00f1a5e4e30069506bbed624a7 |
>| ndproxy | C:\Windows\System32\DRIVERS\NDProxy.sys | true | 5394cd00f1a5e4e30069506bbed624a7 |
>| NetAdapterCx | C:\Windows\system32\drivers\NetAdapterCx.sys | true | c3d71757973b9cede4b6d702fd9fb14d |
>| NetAdapterCx | C:\Windows\system32\drivers\NetAdapterCx.sys | true | c3d71757973b9cede4b6d702fd9fb14d |
>| NetBIOS | C:\Windows\system32\drivers\netbios.sys | true | 9085e8233201b963ce447dc645670670 |
>| NetBIOS | C:\Windows\system32\drivers\netbios.sys | true | 9085e8233201b963ce447dc645670670 |
>| NetBT | C:\Windows\System32\DRIVERS\netbt.sys | true | 3937adb725a18a0dac7ae7c1e0efd2e4 |
>| NetBT | C:\Windows\System32\DRIVERS\netbt.sys | true | 3937adb725a18a0dac7ae7c1e0efd2e4 |
>| Netlogon | C:\Windows\system32\netlogon.dll | true | 8025ce86796a180c8f975718efc0bf55 |
>| Netlogon | C:\Windows\system32\netlogon.dll | true | 8025ce86796a180c8f975718efc0bf55 |
>| Netlogon | C:\Windows\system32\netlogon.dll | true | 8025ce86796a180c8f975718efc0bf55 |
>| Netlogon | C:\Windows\system32\netlogon.dll | true | 8025ce86796a180c8f975718efc0bf55 |
>| Netman | C:\Windows\System32\netman.dll | true | 184970c49f3edc8d05a62069827fba49 |
>| Netman | C:\Windows\System32\netman.dll | true | 184970c49f3edc8d05a62069827fba49 |
>| Netman | C:\Windows\System32\netman.dll | true | 184970c49f3edc8d05a62069827fba49 |
>| Netman | C:\Windows\System32\netman.dll | true | 184970c49f3edc8d05a62069827fba49 |
>| netprofm | C:\Windows\System32\netprofmsvc.dll | true | 4182817064a4bb800d373bf174c27db9 |
>| netprofm | C:\Windows\System32\netprofmsvc.dll | true | 4182817064a4bb800d373bf174c27db9 |
>| netprofm | C:\Windows\System32\netprofmsvc.dll | true | 4182817064a4bb800d373bf174c27db9 |
>| netprofm | C:\Windows\System32\netprofmsvc.dll | true | 4182817064a4bb800d373bf174c27db9 |
>| NetSetupSvc | C:\Windows\System32\NetSetupSvc.dll | true | 00e5e4717d2ebbd2743257657f852f93 |
>| NetSetupSvc | C:\Windows\System32\NetSetupSvc.dll | true | 00e5e4717d2ebbd2743257657f852f93 |
>| NetSetupSvc | C:\Windows\System32\NetSetupSvc.dll | true | 00e5e4717d2ebbd2743257657f852f93 |
>| NetSetupSvc | C:\Windows\System32\NetSetupSvc.dll | true | 00e5e4717d2ebbd2743257657f852f93 |
>| NetTcpPortSharing | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe | true | de2afb6fe857a1c5c1fcf02a82459256 |
>| NetTcpPortSharing | C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe | true | de2afb6fe857a1c5c1fcf02a82459256 |
>| netvsc | C:\Windows\System32\drivers\netvsc.sys | true | 71ead9b51b67d42a880cf50dd03c84fa |
>| netvsc | C:\Windows\System32\drivers\netvsc.sys | true | 71ead9b51b67d42a880cf50dd03c84fa |
>| NgcCtnrSvc | C:\Windows\System32\NgcCtnrSvc.dll | true | b399a73e72cf618881a2a6d1165c8c28 |
>| NgcCtnrSvc | C:\Windows\System32\NgcCtnrSvc.dll | true | b399a73e72cf618881a2a6d1165c8c28 |
>| NgcCtnrSvc | C:\Windows\System32\NgcCtnrSvc.dll | true | b399a73e72cf618881a2a6d1165c8c28 |
>| NgcCtnrSvc | C:\Windows\System32\NgcCtnrSvc.dll | true | b399a73e72cf618881a2a6d1165c8c28 |
>| NgcSvc | C:\Windows\system32\ngcsvc.dll | true | d5e53f72930faab5b11e351543534f65 |
>| NgcSvc | C:\Windows\system32\ngcsvc.dll | true | d5e53f72930faab5b11e351543534f65 |
>| NgcSvc | C:\Windows\system32\ngcsvc.dll | true | d5e53f72930faab5b11e351543534f65 |
>| NgcSvc | C:\Windows\system32\ngcsvc.dll | true | d5e53f72930faab5b11e351543534f65 |
>| NlaSvc | C:\Windows\System32\nlasvc.dll | true | 11bac51af06a9f9414d909af79b6ae9c |
>| NlaSvc | C:\Windows\System32\nlasvc.dll | true | 11bac51af06a9f9414d909af79b6ae9c |
>| NlaSvc | C:\Windows\System32\nlasvc.dll | true | 11bac51af06a9f9414d909af79b6ae9c |
>| NlaSvc | C:\Windows\System32\nlasvc.dll | true | 11bac51af06a9f9414d909af79b6ae9c |
>| Npfs | C:\Windows\system32\drivers\Npfs.sys | true | 3f4f4c10e7b81bc4b2d5c4c7e2c268a0 |
>| Npfs | C:\Windows\system32\drivers\Npfs.sys | true | 3f4f4c10e7b81bc4b2d5c4c7e2c268a0 |
>| npsvctrig | C:\Windows\System32\drivers\npsvctrig.sys | true | e6d73640ffe28611bebcf1af11ef18dc |
>| npsvctrig | C:\Windows\System32\drivers\npsvctrig.sys | true | e6d73640ffe28611bebcf1af11ef18dc |
>| nsi | C:\Windows\system32\nsisvc.dll | true | fa24391609dbe1ae62394d16dc976e1c |
>| nsi | C:\Windows\system32\nsisvc.dll | true | fa24391609dbe1ae62394d16dc976e1c |
>| nsi | C:\Windows\system32\nsisvc.dll | true | fa24391609dbe1ae62394d16dc976e1c |
>| nsi | C:\Windows\system32\nsisvc.dll | true | fa24391609dbe1ae62394d16dc976e1c |
>| nsiproxy | C:\Windows\system32\drivers\nsiproxy.sys | true | 3a66f37dde3f8338cbd639b0106e38ca |
>| nsiproxy | C:\Windows\system32\drivers\nsiproxy.sys | true | 3a66f37dde3f8338cbd639b0106e38ca |
>| Ntfs | C:\Windows\system32\drivers\Ntfs.sys | true | dd4cee5428499ccd02013ce6a591b600 |
>| Ntfs | C:\Windows\system32\drivers\Ntfs.sys | true | dd4cee5428499ccd02013ce6a591b600 |
>| Null | C:\Windows\system32\drivers\Null.sys | true | 85ab11a2f4fb94b9fb6a2d889d83fcac |
>| Null | C:\Windows\system32\drivers\Null.sys | true | 85ab11a2f4fb94b9fb6a2d889d83fcac |
>| nvdimm | C:\Windows\System32\drivers\nvdimm.sys | true | d9469d21cbd03665ec68ab2f3a24a1eb |
>| nvdimm | C:\Windows\System32\drivers\nvdimm.sys | true | d9469d21cbd03665ec68ab2f3a24a1eb |
>| nvraid | C:\Windows\System32\drivers\nvraid.sys | true | 29186fc75a376fb9f87ac59d6dde8729 |
>| nvraid | C:\Windows\System32\drivers\nvraid.sys | true | 29186fc75a376fb9f87ac59d6dde8729 |
>| nvstor | C:\Windows\System32\drivers\nvstor.sys | true | 243047ac047939230b55d9c9da273b8d |
>| nvstor | C:\Windows\System32\drivers\nvstor.sys | true | 243047ac047939230b55d9c9da273b8d |
>| Parport | C:\Windows\System32\drivers\parport.sys | true | fdf95763ca52c62c7875ef2bd96736d5 |
>| Parport | C:\Windows\System32\drivers\parport.sys | true | fdf95763ca52c62c7875ef2bd96736d5 |
>| partmgr | C:\Windows\System32\drivers\partmgr.sys | true | f68d2066b9f1a4fdb95613770c55c338 |
>| partmgr | C:\Windows\System32\drivers\partmgr.sys | true | f68d2066b9f1a4fdb95613770c55c338 |
>| PcaSvc | C:\Windows\System32\pcasvc.dll | true | b2d8231528950c24d9003b205a458dab |
>| PcaSvc | C:\Windows\System32\pcasvc.dll | true | b2d8231528950c24d9003b205a458dab |
>| PcaSvc | C:\Windows\System32\pcasvc.dll | true | b2d8231528950c24d9003b205a458dab |
>| PcaSvc | C:\Windows\System32\pcasvc.dll | true | b2d8231528950c24d9003b205a458dab |
>| pci | C:\Windows\System32\drivers\pci.sys | true | 62e81f2f53126ec6e5149667de967897 |
>| pci | C:\Windows\System32\drivers\pci.sys | true | 62e81f2f53126ec6e5149667de967897 |
>| pciide | C:\Windows\System32\drivers\pciide.sys | true | b97ddbe3cce4260be3117820f2dbda62 |
>| pciide | C:\Windows\System32\drivers\pciide.sys | true | b97ddbe3cce4260be3117820f2dbda62 |
>| pcmcia | C:\Windows\System32\drivers\pcmcia.sys | true | 39ddff57a908a5d02cd856404ee3c585 |
>| pcmcia | C:\Windows\System32\drivers\pcmcia.sys | true | 39ddff57a908a5d02cd856404ee3c585 |
>| pcw | C:\Windows\System32\drivers\pcw.sys | true | 5f0c91ebcc8fd380306628283d0ad28d |
>| pcw | C:\Windows\System32\drivers\pcw.sys | true | 5f0c91ebcc8fd380306628283d0ad28d |
>| pdc | C:\Windows\system32\drivers\pdc.sys | true | 5b34708a130a4aba61fabb66d3153aad |
>| pdc | C:\Windows\system32\drivers\pdc.sys | true | 5b34708a130a4aba61fabb66d3153aad |
>| PEAUTH | C:\Windows\system32\drivers\peauth.sys | true | e8789b5f24aa80994be1e2b27992af7c |
>| PEAUTH | C:\Windows\system32\drivers\peauth.sys | true | e8789b5f24aa80994be1e2b27992af7c |
>| percsas2i | C:\Windows\System32\drivers\percsas2i.sys | true | 578fbfcf65db8829735d67dbed2082e7 |
>| percsas2i | C:\Windows\System32\drivers\percsas2i.sys | true | 578fbfcf65db8829735d67dbed2082e7 |
>| percsas3i | C:\Windows\System32\drivers\percsas3i.sys | true | f738a0c24ea52562b60be27b3fef2fb3 |
>| percsas3i | C:\Windows\System32\drivers\percsas3i.sys | true | f738a0c24ea52562b60be27b3fef2fb3 |
>| PerfHost | C:\Windows\SysWow64\perfhost.exe | true | 85d01ee143eba22431fbb032a6718702 |
>| PerfHost | C:\Windows\SysWow64\perfhost.exe | true | 85d01ee143eba22431fbb032a6718702 |
>| PimIndexMaintenanceSvc | C:\Windows\System32\PimIndexMaintenance.dll | true | ec6832bc4413e0686c1cef4ac62e37eb |
>| PimIndexMaintenanceSvc | C:\Windows\System32\PimIndexMaintenance.dll | true | ec6832bc4413e0686c1cef4ac62e37eb |
>| PimIndexMaintenanceSvc | C:\Windows\System32\PimIndexMaintenance.dll | true | ec6832bc4413e0686c1cef4ac62e37eb |
>| PimIndexMaintenanceSvc | C:\Windows\System32\PimIndexMaintenance.dll | true | ec6832bc4413e0686c1cef4ac62e37eb |
>| PimIndexMaintenanceSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| PktMon | C:\Windows\system32\drivers\PktMon.sys | true | 2b79b5eaf063bf153478adb4455e5b51 |
>| PktMon | C:\Windows\system32\drivers\PktMon.sys | true | 2b79b5eaf063bf153478adb4455e5b51 |
>| pla | C:\Windows\system32\pla.dll | true | 101e0aa289c51a2aebba9584c00a17d2 |
>| pla | C:\Windows\system32\pla.dll | true | 101e0aa289c51a2aebba9584c00a17d2 |
>| pla | C:\Windows\system32\pla.dll | true | 101e0aa289c51a2aebba9584c00a17d2 |
>| pla | C:\Windows\system32\pla.dll | true | 101e0aa289c51a2aebba9584c00a17d2 |
>| PlugPlay | C:\Windows\system32\umpnpmgr.dll | true | 5d65d3b568357eb6ead5578a7b045ab2 |
>| PlugPlay | C:\Windows\system32\umpnpmgr.dll | true | 5d65d3b568357eb6ead5578a7b045ab2 |
>| PlugPlay | C:\Windows\system32\umpnpmgr.dll | true | 5d65d3b568357eb6ead5578a7b045ab2 |
>| PlugPlay | C:\Windows\system32\umpnpmgr.dll | true | 5d65d3b568357eb6ead5578a7b045ab2 |
>| pmem | C:\Windows\System32\drivers\pmem.sys | true | bdd445c92fd089cbaf962baede0e4fd4 |
>| pmem | C:\Windows\System32\drivers\pmem.sys | true | bdd445c92fd089cbaf962baede0e4fd4 |
>| PNPMEM | C:\Windows\System32\drivers\pnpmem.sys | true | ab2ad5e68a3378e5ac2db850e20a1a7b |
>| PNPMEM | C:\Windows\System32\drivers\pnpmem.sys | true | ab2ad5e68a3378e5ac2db850e20a1a7b |
>| PolicyAgent | C:\Windows\System32\ipsecsvc.dll | true | b189d01b45c2ded6388f9c7accd6d254 |
>| PolicyAgent | C:\Windows\System32\ipsecsvc.dll | true | b189d01b45c2ded6388f9c7accd6d254 |
>| PolicyAgent | C:\Windows\System32\ipsecsvc.dll | true | b189d01b45c2ded6388f9c7accd6d254 |
>| PolicyAgent | C:\Windows\System32\ipsecsvc.dll | true | b189d01b45c2ded6388f9c7accd6d254 |
>| portcfg | C:\Windows\System32\drivers\portcfg.sys | true | 534abe9dd4e03dbfcf1bff0a252223a8 |
>| portcfg | C:\Windows\System32\drivers\portcfg.sys | true | 534abe9dd4e03dbfcf1bff0a252223a8 |
>| Power | C:\Windows\system32\umpo.dll | true | 926700fe6040b126f0982b21fb383d87 |
>| Power | C:\Windows\system32\umpo.dll | true | 926700fe6040b126f0982b21fb383d87 |
>| Power | C:\Windows\system32\umpo.dll | true | 926700fe6040b126f0982b21fb383d87 |
>| Power | C:\Windows\system32\umpo.dll | true | 926700fe6040b126f0982b21fb383d87 |
>| PptpMiniport | C:\Windows\System32\drivers\raspptp.sys | true | d79cb39871091022344a6c105fdbd837 |
>| PptpMiniport | C:\Windows\System32\drivers\raspptp.sys | true | d79cb39871091022344a6c105fdbd837 |
>| PrintNotify | C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll | true | eb66830971e030bb9625be333a2298a5 |
>| PrintNotify | C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll | true | eb66830971e030bb9625be333a2298a5 |
>| PrintNotify | C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll | true | eb66830971e030bb9625be333a2298a5 |
>| PrintNotify | C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll | true | eb66830971e030bb9625be333a2298a5 |
>| PrintWorkflowUserSvc | C:\Windows\System32\PrintWorkflowService.dll | true | 5ecc28ea010394525a09c93e03573fc4 |
>| PrintWorkflowUserSvc | C:\Windows\System32\PrintWorkflowService.dll | true | 5ecc28ea010394525a09c93e03573fc4 |
>| PrintWorkflowUserSvc | C:\Windows\System32\PrintWorkflowService.dll | true | 5ecc28ea010394525a09c93e03573fc4 |
>| PrintWorkflowUserSvc | C:\Windows\System32\PrintWorkflowService.dll | true | 5ecc28ea010394525a09c93e03573fc4 |
>| PrintWorkflowUserSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| PRM | C:\Windows\System32\DriverStore\FileRepository\prm.inf_amd64_5a6e1bc540be827c\PRM.sys | true | 12b48cb3274927c57bf770dea9476011 |
>| PRM | C:\Windows\System32\DriverStore\FileRepository\prm.inf_amd64_5a6e1bc540be827c\PRM.sys | true | 12b48cb3274927c57bf770dea9476011 |
>| Processor | C:\Windows\System32\drivers\processr.sys | true | 8f8d6ace001a0d6c9168bf4880ae9d81 |
>| Processor | C:\Windows\System32\drivers\processr.sys | true | 8f8d6ace001a0d6c9168bf4880ae9d81 |
>| ProfSvc | C:\Windows\system32\profsvc.dll | true | 58c403852c1d4c6da2ceeae7aa56f43d |
>| ProfSvc | C:\Windows\system32\profsvc.dll | true | 58c403852c1d4c6da2ceeae7aa56f43d |
>| ProfSvc | C:\Windows\system32\profsvc.dll | true | 58c403852c1d4c6da2ceeae7aa56f43d |
>| ProfSvc | C:\Windows\system32\profsvc.dll | true | 58c403852c1d4c6da2ceeae7aa56f43d |
>| Psched | C:\Windows\System32\drivers\pacer.sys | true | 39b1cf32f9c62caa14516259823d0291 |
>| Psched | C:\Windows\System32\drivers\pacer.sys | true | 39b1cf32f9c62caa14516259823d0291 |
>| PushToInstall | C:\Windows\system32\PushToInstall.dll | true | 42a88b1a653492718f2c26651158c8f3 |
>| PushToInstall | C:\Windows\system32\PushToInstall.dll | true | 42a88b1a653492718f2c26651158c8f3 |
>| PushToInstall | C:\Windows\system32\PushToInstall.dll | true | 42a88b1a653492718f2c26651158c8f3 |
>| PushToInstall | C:\Windows\system32\PushToInstall.dll | true | 42a88b1a653492718f2c26651158c8f3 |
>| pvscsi | C:\Windows\System32\drivers\pvscsii.sys | true | e80d2e5e093644da1ac0872d625d6752 |
>| pvscsi | C:\Windows\System32\drivers\pvscsii.sys | true | e80d2e5e093644da1ac0872d625d6752 |
>| qebdrv | C:\Windows\System32\drivers\qevbda.sys | true | 900d88cb1bf10705c1409e7ac9ae61a4 |
>| qebdrv | C:\Windows\System32\drivers\qevbda.sys | true | 900d88cb1bf10705c1409e7ac9ae61a4 |
>| qefcoe | C:\Windows\System32\drivers\qefcoe.sys | true | f200e7701745b2619e5d182332b37e87 |
>| qefcoe | C:\Windows\System32\drivers\qefcoe.sys | true | f200e7701745b2619e5d182332b37e87 |
>| qeois | C:\Windows\System32\drivers\qeois.sys | true | e5d34b7d682ec146b0180ef389d03dff |
>| qeois | C:\Windows\System32\drivers\qeois.sys | true | e5d34b7d682ec146b0180ef389d03dff |
>| ql2300i | C:\Windows\System32\drivers\ql2300i.sys | true | c678ec054dcb26483bc762beebb7ab3c |
>| ql2300i | C:\Windows\System32\drivers\ql2300i.sys | true | c678ec054dcb26483bc762beebb7ab3c |
>| ql40xx2i | C:\Windows\System32\drivers\ql40xx2i.sys | true | 94fd2e9195bb97abea0014c125e5d7ea |
>| ql40xx2i | C:\Windows\System32\drivers\ql40xx2i.sys | true | 94fd2e9195bb97abea0014c125e5d7ea |
>| qlfcoei | C:\Windows\System32\drivers\qlfcoei.sys | true | 02ef30cd7625574283020a59085d4a2f |
>| qlfcoei | C:\Windows\System32\drivers\qlfcoei.sys | true | 02ef30cd7625574283020a59085d4a2f |
>| QWAVE | C:\Windows\system32\qwave.dll | true | f67ccb5a7ea57978a5c555d6bc5751bb |
>| QWAVE | C:\Windows\system32\qwave.dll | true | f67ccb5a7ea57978a5c555d6bc5751bb |
>| QWAVE | C:\Windows\system32\qwave.dll | true | f67ccb5a7ea57978a5c555d6bc5751bb |
>| QWAVE | C:\Windows\system32\qwave.dll | true | f67ccb5a7ea57978a5c555d6bc5751bb |
>| QWAVEdrv | C:\Windows\system32\drivers\qwavedrv.sys | true | 82b66c526e937c9e0ede66eeaf23964f |
>| QWAVEdrv | C:\Windows\system32\drivers\qwavedrv.sys | true | 82b66c526e937c9e0ede66eeaf23964f |
>| Ramdisk | C:\Windows\system32\DRIVERS\ramdisk.sys | true | afd5c8d7b14bba338323200332ebbbb0 |
>| Ramdisk | C:\Windows\system32\DRIVERS\ramdisk.sys | true | afd5c8d7b14bba338323200332ebbbb0 |
>| RasAcd | C:\Windows\System32\DRIVERS\rasacd.sys | true | 5dc4811804cfdfe9ef965df17005a1b8 |
>| RasAcd | C:\Windows\System32\DRIVERS\rasacd.sys | true | 5dc4811804cfdfe9ef965df17005a1b8 |
>| RasAgileVpn | C:\Windows\System32\drivers\AgileVpn.sys | true | 76a21b57a6dd6c4faeca942c007be590 |
>| RasAgileVpn | C:\Windows\System32\drivers\AgileVpn.sys | true | 76a21b57a6dd6c4faeca942c007be590 |
>| RasAuto | C:\Windows\System32\rasauto.dll | true | 1692ee33c3c9f5f7b59c7c6b8e118d38 |
>| RasAuto | C:\Windows\System32\rasauto.dll | true | 1692ee33c3c9f5f7b59c7c6b8e118d38 |
>| RasAuto | C:\Windows\System32\rasauto.dll | true | 1692ee33c3c9f5f7b59c7c6b8e118d38 |
>| RasAuto | C:\Windows\System32\rasauto.dll | true | 1692ee33c3c9f5f7b59c7c6b8e118d38 |
>| RasGre | C:\Windows\System32\drivers\rasgre.sys | true | 6a27dbe5487c9e9967227f804b941379 |
>| RasGre | C:\Windows\System32\drivers\rasgre.sys | true | 6a27dbe5487c9e9967227f804b941379 |
>| Rasl2tp | C:\Windows\System32\drivers\rasl2tp.sys | true | 2c0e6162837cd608e4f962e99575c1b5 |
>| Rasl2tp | C:\Windows\System32\drivers\rasl2tp.sys | true | 2c0e6162837cd608e4f962e99575c1b5 |
>| RasMan | C:\Windows\System32\rasmans.dll | true | 55ff513cefc545379698ab8d38efe0a0 |
>| RasMan | C:\Windows\System32\rasmans.dll | true | 55ff513cefc545379698ab8d38efe0a0 |
>| RasMan | C:\Windows\System32\rasmans.dll | true | 55ff513cefc545379698ab8d38efe0a0 |
>| RasMan | C:\Windows\System32\rasmans.dll | true | 55ff513cefc545379698ab8d38efe0a0 |
>| RasPppoe | C:\Windows\System32\drivers\raspppoe.sys | true | 2370a643403c96274c4c9834ea1f0625 |
>| RasPppoe | C:\Windows\System32\DRIVERS\raspppoe.sys | true | 2370a643403c96274c4c9834ea1f0625 |
>| RasSstp | C:\Windows\System32\drivers\rassstp.sys | true | 2cbdcde0f4b71e0af17c1ddad7543033 |
>| RasSstp | C:\Windows\System32\drivers\rassstp.sys | true | 2cbdcde0f4b71e0af17c1ddad7543033 |
>| rdbss | C:\Windows\system32\DRIVERS\rdbss.sys | true | 2e7eb447308f9c60e98a0c0c99ba4c78 |
>| rdbss | C:\Windows\system32\DRIVERS\rdbss.sys | true | 2e7eb447308f9c60e98a0c0c99ba4c78 |
>| rdpbus | C:\Windows\System32\drivers\rdpbus.sys | true | d1edd6604ed1a6e2bc45134c307d3e82 |
>| rdpbus | C:\Windows\System32\drivers\rdpbus.sys | true | d1edd6604ed1a6e2bc45134c307d3e82 |
>| RDPDR | C:\Windows\System32\drivers\rdpdr.sys | true | e63147974f4fc014742c5471c7bc516d |
>| RDPDR | C:\Windows\System32\drivers\rdpdr.sys | true | e63147974f4fc014742c5471c7bc516d |
>| RdpVideoMiniport | C:\Windows\System32\drivers\rdpvideominiport.sys | true | 26fa006e8dc780d58158f58cf11fe3a3 |
>| RdpVideoMiniport | C:\Windows\System32\drivers\rdpvideominiport.sys | true | 26fa006e8dc780d58158f58cf11fe3a3 |
>| ReFS | C:\Windows\system32\drivers\ReFS.sys | true | f8cbd1709a3917b9a53a047879d388e5 |
>| ReFS | C:\Windows\system32\drivers\ReFS.sys | true | f8cbd1709a3917b9a53a047879d388e5 |
>| ReFSv1 | C:\Windows\system32\drivers\ReFSv1.sys | true | ea9e1467532b4b338c5083f8e531e3d9 |
>| ReFSv1 | C:\Windows\system32\drivers\ReFSv1.sys | true | ea9e1467532b4b338c5083f8e531e3d9 |
>| RemoteAccess | C:\Windows\System32\mprdim.dll | true | 5a106f77d3ee0688f550fb69a386221a |
>| RemoteAccess | C:\Windows\System32\mprdim.dll | true | 5a106f77d3ee0688f550fb69a386221a |
>| RemoteAccess | C:\Windows\System32\mprdim.dll | true | 5a106f77d3ee0688f550fb69a386221a |
>| RemoteAccess | C:\Windows\System32\mprdim.dll | true | 5a106f77d3ee0688f550fb69a386221a |
>| RemoteRegistry | C:\Windows\system32\regsvc.dll | true | beac0518aee7bc0a4898242af08d7578 |
>| RemoteRegistry | C:\Windows\system32\regsvc.dll | true | beac0518aee7bc0a4898242af08d7578 |
>| RemoteRegistry | C:\Windows\system32\regsvc.dll | true | beac0518aee7bc0a4898242af08d7578 |
>| RemoteRegistry | C:\Windows\system32\regsvc.dll | true | beac0518aee7bc0a4898242af08d7578 |
>| RFCOMM | C:\Windows\System32\drivers\rfcomm.sys | true | f898fc38db316dbed55e4145b8f0b796 |
>| RFCOMM | C:\Windows\System32\drivers\rfcomm.sys | true | f898fc38db316dbed55e4145b8f0b796 |
>| rhproxy | C:\Windows\System32\drivers\rhproxy.sys | true | 5623471aef6871c17d97e5c8380e730e |
>| rhproxy | C:\Windows\System32\drivers\rhproxy.sys | true | 5623471aef6871c17d97e5c8380e730e |
>| RmSvc | C:\Windows\System32\RMapi.dll | true | 6f1dd01e46352926cb337b80e356c11f |
>| RmSvc | C:\Windows\System32\RMapi.dll | true | 6f1dd01e46352926cb337b80e356c11f |
>| RmSvc | C:\Windows\System32\RMapi.dll | true | 6f1dd01e46352926cb337b80e356c11f |
>| RmSvc | C:\Windows\System32\RMapi.dll | true | 6f1dd01e46352926cb337b80e356c11f |
>| RpcEptMapper | C:\Windows\System32\RpcEpMap.dll | true | c3a6e8bff9b36bfcc3b3de14640ba4ac |
>| RpcEptMapper | C:\Windows\System32\RpcEpMap.dll | true | c3a6e8bff9b36bfcc3b3de14640ba4ac |
>| RpcEptMapper | C:\Windows\System32\RpcEpMap.dll | true | c3a6e8bff9b36bfcc3b3de14640ba4ac |
>| RpcEptMapper | C:\Windows\System32\RpcEpMap.dll | true | c3a6e8bff9b36bfcc3b3de14640ba4ac |
>| RpcLocator | C:\Windows\system32\locator.exe | true | aff9819c7aaef41d21f5581f7d33d13d |
>| RpcLocator | C:\Windows\system32\locator.exe | true | aff9819c7aaef41d21f5581f7d33d13d |
>| RpcSs | C:\Windows\system32\rpcss.dll | true | 3c8acb412e1a10b923b18a068f814901 |
>| RpcSs | C:\Windows\system32\rpcss.dll | true | 3c8acb412e1a10b923b18a068f814901 |
>| RpcSs | C:\Windows\system32\rpcss.dll | true | 3c8acb412e1a10b923b18a068f814901 |
>| RpcSs | C:\Windows\system32\rpcss.dll | true | 3c8acb412e1a10b923b18a068f814901 |
>| RSoPProv | C:\Windows\system32\RSoPProv.exe | true | a5ab506123009357c71b63cdbea3425b |
>| RSoPProv | C:\Windows\system32\RSoPProv.exe | true | a5ab506123009357c71b63cdbea3425b |
>| rspndr | C:\Windows\system32\drivers\rspndr.sys | true | e66e50a0a3344a377838ef8b965a7f88 |
>| rspndr | C:\Windows\system32\drivers\rspndr.sys | true | e66e50a0a3344a377838ef8b965a7f88 |
>| s3cap | C:\Windows\System32\drivers\vms3cap.sys | true | 75524202b54c299e1d1378610f4a6671 |
>| s3cap | C:\Windows\System32\drivers\vms3cap.sys | true | 75524202b54c299e1d1378610f4a6671 |
>| sacdrv | C:\Windows\system32\DRIVERS\sacdrv.sys | true | aee01d5621b5824e65e0caed5715ba2e |
>| sacdrv | C:\Windows\system32\DRIVERS\sacdrv.sys | true | aee01d5621b5824e65e0caed5715ba2e |
>| sacsvr | C:\Windows\system32\sacsvr.dll | true | 3ba041aceccf6a653128edeb33e77ecc |
>| sacsvr | C:\Windows\system32\sacsvr.dll | true | 3ba041aceccf6a653128edeb33e77ecc |
>| sacsvr | C:\Windows\system32\sacsvr.dll | true | 3ba041aceccf6a653128edeb33e77ecc |
>| sacsvr | C:\Windows\system32\sacsvr.dll | true | 3ba041aceccf6a653128edeb33e77ecc |
>| SamSs | C:\Windows\system32\lsass.exe | true | 6da2fcc580c720c16612057e83f47f04 |
>| SamSs | C:\Windows\system32\lsass.exe | true | 6da2fcc580c720c16612057e83f47f04 |
>| sbp2port | C:\Windows\System32\drivers\sbp2port.sys | true | d1958f56eea564be9635b2f692c9017a |
>| sbp2port | C:\Windows\System32\drivers\sbp2port.sys | true | d1958f56eea564be9635b2f692c9017a |
>| SCardSvr | C:\Windows\System32\SCardSvr.dll | true | c04a72e85840c644271236bdc78c8636 |
>| SCardSvr | C:\Windows\System32\SCardSvr.dll | true | c04a72e85840c644271236bdc78c8636 |
>| SCardSvr | C:\Windows\System32\SCardSvr.dll | true | c04a72e85840c644271236bdc78c8636 |
>| SCardSvr | C:\Windows\System32\SCardSvr.dll | true | c04a72e85840c644271236bdc78c8636 |
>| ScDeviceEnum | C:\Windows\System32\ScDeviceEnum.dll | true | 02f9f9643e07f01fb4102365eeb44ad0 |
>| ScDeviceEnum | C:\Windows\System32\ScDeviceEnum.dll | true | 02f9f9643e07f01fb4102365eeb44ad0 |
>| ScDeviceEnum | C:\Windows\System32\ScDeviceEnum.dll | true | 02f9f9643e07f01fb4102365eeb44ad0 |
>| ScDeviceEnum | C:\Windows\System32\ScDeviceEnum.dll | true | 02f9f9643e07f01fb4102365eeb44ad0 |
>| scfilter | C:\Windows\System32\DRIVERS\scfilter.sys | true | 698a543a9df37aa83bccff659da38f85 |
>| scfilter | C:\Windows\System32\DRIVERS\scfilter.sys | true | 698a543a9df37aa83bccff659da38f85 |
>| Schedule | C:\Windows\system32\schedsvc.dll | true | 3789725bc525f68f7200aad3361c5558 |
>| Schedule | C:\Windows\system32\schedsvc.dll | true | 3789725bc525f68f7200aad3361c5558 |
>| Schedule | C:\Windows\system32\schedsvc.dll | true | 3789725bc525f68f7200aad3361c5558 |
>| Schedule | C:\Windows\system32\schedsvc.dll | true | 3789725bc525f68f7200aad3361c5558 |
>| scmbus | C:\Windows\System32\drivers\scmbus.sys | true | d1b427d71c1857ca60e0121f0aa68602 |
>| scmbus | C:\Windows\System32\drivers\scmbus.sys | true | d1b427d71c1857ca60e0121f0aa68602 |
>| SCPolicySvc | C:\Windows\System32\certprop.dll | true | b4032b436f4ff0cc8f160a1f9f57de43 |
>| SCPolicySvc | C:\Windows\System32\certprop.dll | true | b4032b436f4ff0cc8f160a1f9f57de43 |
>| SCPolicySvc | C:\Windows\System32\certprop.dll | true | b4032b436f4ff0cc8f160a1f9f57de43 |
>| SCPolicySvc | C:\Windows\System32\certprop.dll | true | b4032b436f4ff0cc8f160a1f9f57de43 |
>| sdbus | C:\Windows\System32\drivers\sdbus.sys | true | b428abd6fad6b549ef675edc7f12c6d5 |
>| sdbus | C:\Windows\System32\drivers\sdbus.sys | true | b428abd6fad6b549ef675edc7f12c6d5 |
>| SDFRd | C:\Windows\System32\drivers\SDFRd.sys | true | 0004013c04ec93784b35f9f1e6b77cb3 |
>| SDFRd | C:\Windows\System32\drivers\SDFRd.sys | true | 0004013c04ec93784b35f9f1e6b77cb3 |
>| sdstor | C:\Windows\System32\drivers\sdstor.sys | true | 5374ebe59fb9e93931255540ba13dc7c |
>| sdstor | C:\Windows\System32\drivers\sdstor.sys | true | 5374ebe59fb9e93931255540ba13dc7c |
>| seclogon | C:\Windows\system32\seclogon.dll | true | 337ce4601a787141673eccc19da57d7a |
>| seclogon | C:\Windows\system32\seclogon.dll | true | 337ce4601a787141673eccc19da57d7a |
>| seclogon | C:\Windows\system32\seclogon.dll | true | 337ce4601a787141673eccc19da57d7a |
>| seclogon | C:\Windows\system32\seclogon.dll | true | 337ce4601a787141673eccc19da57d7a |
>| SecurityHealthService | C:\Windows\system32\SecurityHealthService.exe | true | ed5777a65aca7fdb2cf1c97a8641a6e6 |
>| SecurityHealthService | C:\Windows\system32\SecurityHealthService.exe | true | ed5777a65aca7fdb2cf1c97a8641a6e6 |
>| SEMgrSvc | C:\Windows\system32\SEMgrSvc.dll | true | 5a6c720f0d3949f05babdd4db8d4bd59 |
>| SEMgrSvc | C:\Windows\system32\SEMgrSvc.dll | true | 5a6c720f0d3949f05babdd4db8d4bd59 |
>| SEMgrSvc | C:\Windows\system32\SEMgrSvc.dll | true | 5a6c720f0d3949f05babdd4db8d4bd59 |
>| SEMgrSvc | C:\Windows\system32\SEMgrSvc.dll | true | 5a6c720f0d3949f05babdd4db8d4bd59 |
>| SENS | C:\Windows\System32\sens.dll | true | 3da7adbecfdca14305726affe53fdda3 |
>| SENS | C:\Windows\System32\sens.dll | true | 3da7adbecfdca14305726affe53fdda3 |
>| SENS | C:\Windows\System32\sens.dll | true | 3da7adbecfdca14305726affe53fdda3 |
>| SENS | C:\Windows\System32\sens.dll | true | 3da7adbecfdca14305726affe53fdda3 |
>| Sense | C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe | true | 95a7c860a1bd0791bd4928f631631b92 |
>| Sense | C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe | true | 95a7c860a1bd0791bd4928f631631b92 |
>| SensorDataService | C:\Windows\System32\SensorDataService.exe | true | 471a439de7075750c15ff42cc060cf38 |
>| SensorDataService | C:\Windows\System32\SensorDataService.exe | true | 471a439de7075750c15ff42cc060cf38 |
>| SensorService | C:\Windows\system32\SensorService.dll | true | 919c57818b859b96cea3bd6ae2543eff |
>| SensorService | C:\Windows\system32\SensorService.dll | true | 919c57818b859b96cea3bd6ae2543eff |
>| SensorService | C:\Windows\system32\SensorService.dll | true | 919c57818b859b96cea3bd6ae2543eff |
>| SensorService | C:\Windows\system32\SensorService.dll | true | 919c57818b859b96cea3bd6ae2543eff |
>| SensrSvc | C:\Windows\system32\sensrsvc.dll | true | 8ce42685aff02f52c12927f362fe0a2e |
>| SensrSvc | C:\Windows\system32\sensrsvc.dll | true | 8ce42685aff02f52c12927f362fe0a2e |
>| SensrSvc | C:\Windows\system32\sensrsvc.dll | true | 8ce42685aff02f52c12927f362fe0a2e |
>| SensrSvc | C:\Windows\system32\sensrsvc.dll | true | 8ce42685aff02f52c12927f362fe0a2e |
>| SerCx | C:\Windows\system32\drivers\SerCx.sys | true | a5a473940b02bb8903b71970e03c7734 |
>| SerCx | C:\Windows\system32\drivers\SerCx.sys | true | a5a473940b02bb8903b71970e03c7734 |
>| SerCx2 | C:\Windows\system32\drivers\SerCx2.sys | true | 657806499cccba28569bd906d6b40a82 |
>| SerCx2 | C:\Windows\system32\drivers\SerCx2.sys | true | 657806499cccba28569bd906d6b40a82 |
>| Serenum | C:\Windows\System32\drivers\serenum.sys | true | 998820b3e4ff8a57eff0486c3e72d573 |
>| Serenum | C:\Windows\System32\drivers\serenum.sys | true | 998820b3e4ff8a57eff0486c3e72d573 |
>| Serial | C:\Windows\System32\drivers\serial.sys | true | d485142c2b7b17c926d4c32ab60c88b4 |
>| Serial | C:\Windows\System32\drivers\serial.sys | true | d485142c2b7b17c926d4c32ab60c88b4 |
>| sermouse | C:\Windows\System32\drivers\sermouse.sys | true | 89dbdd34019916875834c61095a7ddc4 |
>| sermouse | C:\Windows\System32\drivers\sermouse.sys | true | 89dbdd34019916875834c61095a7ddc4 |
>| SessionEnv | C:\Windows\system32\sessenv.dll | true | 609275cbb20b61911aae5e422b0f2b3f |
>| SessionEnv | C:\Windows\system32\sessenv.dll | true | 609275cbb20b61911aae5e422b0f2b3f |
>| SessionEnv | C:\Windows\system32\sessenv.dll | true | 609275cbb20b61911aae5e422b0f2b3f |
>| SessionEnv | C:\Windows\system32\sessenv.dll | true | 609275cbb20b61911aae5e422b0f2b3f |
>| sfloppy | C:\Windows\System32\drivers\sfloppy.sys | true | c82e4f4beb15001ea098644626c33ed3 |
>| sfloppy | C:\Windows\System32\drivers\sfloppy.sys | true | c82e4f4beb15001ea098644626c33ed3 |
>| SgrmAgent | C:\Windows\system32\drivers\SgrmAgent.sys | true | e81fdb11bb9dc3b743d07402ab0d6850 |
>| SgrmAgent | C:\Windows\system32\drivers\SgrmAgent.sys | true | e81fdb11bb9dc3b743d07402ab0d6850 |
>| SgrmBroker | C:\Windows\system32\SgrmBroker.exe | true | 9acb4f0b740038cde52091a797ac6968 |
>| SgrmBroker | C:\Windows\system32\SgrmBroker.exe | true | 9acb4f0b740038cde52091a797ac6968 |
>| SharedAccess | C:\Windows\System32\ipnathlp.dll | true | 7628f5c8d8fae2ab2f4f375cf1fef095 |
>| SharedAccess | C:\Windows\System32\ipnathlp.dll | true | 7628f5c8d8fae2ab2f4f375cf1fef095 |
>| SharedAccess | C:\Windows\System32\ipnathlp.dll | true | 7628f5c8d8fae2ab2f4f375cf1fef095 |
>| SharedAccess | C:\Windows\System32\ipnathlp.dll | true | 7628f5c8d8fae2ab2f4f375cf1fef095 |
>| ShellHWDetection | C:\Windows\System32\shsvcs.dll | true | 504a59ce49b77005a64a61f859b22e5a |
>| ShellHWDetection | C:\Windows\System32\shsvcs.dll | true | 504a59ce49b77005a64a61f859b22e5a |
>| ShellHWDetection | C:\Windows\System32\shsvcs.dll | true | 504a59ce49b77005a64a61f859b22e5a |
>| ShellHWDetection | C:\Windows\System32\shsvcs.dll | true | 504a59ce49b77005a64a61f859b22e5a |
>| shpamsvc | C:\Windows\system32\Windows.SharedPC.AccountManager.dll | true | 8420e162331d9fcb642773ce518de3e5 |
>| shpamsvc | C:\Windows\system32\Windows.SharedPC.AccountManager.dll | true | 8420e162331d9fcb642773ce518de3e5 |
>| shpamsvc | C:\Windows\system32\Windows.SharedPC.AccountManager.dll | true | 8420e162331d9fcb642773ce518de3e5 |
>| shpamsvc | C:\Windows\system32\Windows.SharedPC.AccountManager.dll | true | 8420e162331d9fcb642773ce518de3e5 |
>| SiSRaid2 | C:\Windows\System32\drivers\SiSRaid2.sys | true | dbac632a8e204a01cd97c622551b64d1 |
>| SiSRaid2 | C:\Windows\System32\drivers\SiSRaid2.sys | true | dbac632a8e204a01cd97c622551b64d1 |
>| SiSRaid4 | C:\Windows\System32\drivers\sisraid4.sys | true | ed08641f88a7e1a3e439cd2ce67a21f5 |
>| SiSRaid4 | C:\Windows\System32\drivers\sisraid4.sys | true | ed08641f88a7e1a3e439cd2ce67a21f5 |
>| SmartSAMD | C:\Windows\System32\drivers\SmartSAMD.sys | true | 644210ec45cf61bce5fcc78e7cc535d6 |
>| SmartSAMD | C:\Windows\System32\drivers\SmartSAMD.sys | true | 644210ec45cf61bce5fcc78e7cc535d6 |
>| smbdirect | C:\Windows\System32\DRIVERS\smbdirect.sys | true | 0398fa5772f947049ab890a798ecf88f |
>| smbdirect | C:\Windows\System32\DRIVERS\smbdirect.sys | true | 0398fa5772f947049ab890a798ecf88f |
>| smphost | C:\Windows\System32\smphost.dll | true | 56891ea4699b7da217c9556d6f032947 |
>| smphost | C:\Windows\System32\smphost.dll | true | 56891ea4699b7da217c9556d6f032947 |
>| smphost | C:\Windows\System32\smphost.dll | true | 56891ea4699b7da217c9556d6f032947 |
>| smphost | C:\Windows\System32\smphost.dll | true | 56891ea4699b7da217c9556d6f032947 |
>| SNMPTRAP | C:\Windows\System32\snmptrap.exe | true | 81e215d60dd0ead23cd19b0fd6cc6501 |
>| SNMPTRAP | C:\Windows\System32\snmptrap.exe | true | 81e215d60dd0ead23cd19b0fd6cc6501 |
>| spaceparser | C:\Windows\system32\drivers\spaceparser.sys | true | 1175f02198005218864a36f2768e52e4 |
>| spaceparser | C:\Windows\system32\drivers\spaceparser.sys | true | 1175f02198005218864a36f2768e52e4 |
>| spaceport | C:\Windows\System32\drivers\spaceport.sys | true | 7d38fe01b3309a01119b19b1a807673b |
>| spaceport | C:\Windows\System32\drivers\spaceport.sys | true | 7d38fe01b3309a01119b19b1a807673b |
>| SpbCx | C:\Windows\system32\drivers\SpbCx.sys | true | e9e4a7f68b8d7044077db9978e0b9f5b |
>| SpbCx | C:\Windows\system32\drivers\SpbCx.sys | true | e9e4a7f68b8d7044077db9978e0b9f5b |
>| Spooler | C:\Windows\System32\spoolsv.exe | true | 55bb3facc6ef795f6f1d8cc656bcb779 |
>| Spooler | C:\Windows\System32\spoolsv.exe | true | 55bb3facc6ef795f6f1d8cc656bcb779 |
>| sppsvc | C:\Windows\system32\sppsvc.exe | true | c05a6baecd2bee1122a82dd3c3252ab6 |
>| sppsvc | C:\Windows\system32\sppsvc.exe | true | c05a6baecd2bee1122a82dd3c3252ab6 |
>| srv2 | C:\Windows\System32\DRIVERS\srv2.sys | true | ccfe129cbdea8b8c6051d11c6c694230 |
>| srv2 | C:\Windows\System32\DRIVERS\srv2.sys | true | ccfe129cbdea8b8c6051d11c6c694230 |
>| srvnet | C:\Windows\System32\DRIVERS\srvnet.sys | true | fdfcf9c6d6bec82925b2e52926acbbb2 |
>| srvnet | C:\Windows\System32\DRIVERS\srvnet.sys | true | fdfcf9c6d6bec82925b2e52926acbbb2 |
>| SSDPSRV | C:\Windows\System32\ssdpsrv.dll | true | a8108d5f8bd7ca52673aabfa5b4308d1 |
>| SSDPSRV | C:\Windows\System32\ssdpsrv.dll | true | a8108d5f8bd7ca52673aabfa5b4308d1 |
>| SSDPSRV | C:\Windows\System32\ssdpsrv.dll | true | a8108d5f8bd7ca52673aabfa5b4308d1 |
>| SSDPSRV | C:\Windows\System32\ssdpsrv.dll | true | a8108d5f8bd7ca52673aabfa5b4308d1 |
>| ssh-agent | C:\Windows\System32\OpenSSH\ssh-agent.exe | true | 66969aa56e77953e596470c73a9004e0 |
>| ssh-agent | C:\Windows\System32\OpenSSH\ssh-agent.exe | true | 66969aa56e77953e596470c73a9004e0 |
>| sshd | C:\Program Files\OpenSSH-Win64\sshd.exe | true | 331ba0e529810ef718dd3efbd1242302 |
>| sshd | C:\Program Files\OpenSSH-Win64\sshd.exe | true | 331ba0e529810ef718dd3efbd1242302 |
>| SstpSvc | C:\Windows\system32\sstpsvc.dll | true | 7f1742f83f220e2ca34d16b5d829c00e |
>| SstpSvc | C:\Windows\system32\sstpsvc.dll | true | 7f1742f83f220e2ca34d16b5d829c00e |
>| SstpSvc | C:\Windows\system32\sstpsvc.dll | true | 7f1742f83f220e2ca34d16b5d829c00e |
>| SstpSvc | C:\Windows\system32\sstpsvc.dll | true | 7f1742f83f220e2ca34d16b5d829c00e |
>| StateRepository | C:\Windows\system32\windows.staterepository.dll | true | 3d1971318a057084d7d896b27b3bb4b3 |
>| StateRepository | C:\Windows\system32\windows.staterepository.dll | true | 3d1971318a057084d7d896b27b3bb4b3 |
>| StateRepository | C:\Windows\system32\windows.staterepository.dll | true | 3d1971318a057084d7d896b27b3bb4b3 |
>| StateRepository | C:\Windows\system32\windows.staterepository.dll | true | 3d1971318a057084d7d896b27b3bb4b3 |
>| stexstor | C:\Windows\System32\drivers\stexstor.sys | true | 90a4646b1c287fcf723657778e55d93e |
>| stexstor | C:\Windows\System32\drivers\stexstor.sys | true | 90a4646b1c287fcf723657778e55d93e |
>| StiSvc | C:\Windows\System32\wiaservc.dll | true | 91c317c2ccc8fc8a28aa9972599ee456 |
>| StiSvc | C:\Windows\System32\wiaservc.dll | true | 91c317c2ccc8fc8a28aa9972599ee456 |
>| StiSvc | C:\Windows\System32\wiaservc.dll | true | 91c317c2ccc8fc8a28aa9972599ee456 |
>| StiSvc | C:\Windows\System32\wiaservc.dll | true | 91c317c2ccc8fc8a28aa9972599ee456 |
>| storahci | C:\Windows\System32\drivers\storahci.sys | true | ed739b05ba3210ea45b0ad74e4df167b |
>| storahci | C:\Windows\System32\drivers\storahci.sys | true | ed739b05ba3210ea45b0ad74e4df167b |
>| storflt | C:\Windows\System32\drivers\vmstorfl.sys | true | 915d638cc3779c578ebb3072b80d6a1f |
>| storflt | C:\Windows\System32\drivers\vmstorfl.sys | true | 915d638cc3779c578ebb3072b80d6a1f |
>| stornvme | C:\Windows\System32\drivers\stornvme.sys | true | 98629205055d6b74030701d2b8ff2767 |
>| stornvme | C:\Windows\System32\drivers\stornvme.sys | true | 98629205055d6b74030701d2b8ff2767 |
>| storqosflt | C:\Windows\system32\drivers\storqosflt.sys | true | 966997d2b3ebe8ea30ec42101dbe5768 |
>| storqosflt | C:\Windows\system32\drivers\storqosflt.sys | true | 966997d2b3ebe8ea30ec42101dbe5768 |
>| StorSvc | C:\Windows\system32\storsvc.dll | true | 148ced66d982648cd8d3169d5a5ae77b |
>| StorSvc | C:\Windows\system32\storsvc.dll | true | 148ced66d982648cd8d3169d5a5ae77b |
>| StorSvc | C:\Windows\system32\storsvc.dll | true | 148ced66d982648cd8d3169d5a5ae77b |
>| StorSvc | C:\Windows\system32\storsvc.dll | true | 148ced66d982648cd8d3169d5a5ae77b |
>| storufs | C:\Windows\System32\drivers\storufs.sys | true | 7234edc80f3240b5b5218b862d54add3 |
>| storufs | C:\Windows\System32\drivers\storufs.sys | true | 7234edc80f3240b5b5218b862d54add3 |
>| storvsc | C:\Windows\System32\drivers\storvsc.sys | true | 9d09cb815bfe76fc9929a4c176f2f57c |
>| storvsc | C:\Windows\System32\drivers\storvsc.sys | true | 9d09cb815bfe76fc9929a4c176f2f57c |
>| svsvc | C:\Windows\system32\svsvc.dll | true | db9daed6df328f3c6443c78921723e21 |
>| svsvc | C:\Windows\system32\svsvc.dll | true | db9daed6df328f3c6443c78921723e21 |
>| svsvc | C:\Windows\system32\svsvc.dll | true | db9daed6df328f3c6443c78921723e21 |
>| svsvc | C:\Windows\system32\svsvc.dll | true | db9daed6df328f3c6443c78921723e21 |
>| swenum | C:\Windows\System32\DriverStore\FileRepository\swenum.inf_amd64_a8eddc34aa14df5f\swenum.sys | true | 0d8210a54c87102db6f0406b1c265a9c |
>| swenum | C:\Windows\System32\DriverStore\FileRepository\swenum.inf_amd64_a8eddc34aa14df5f\swenum.sys | true | 0d8210a54c87102db6f0406b1c265a9c |
>| swprv | C:\Windows\System32\swprv.dll | true | 57430ad32d0775779a3d86aed1e0103a |
>| swprv | C:\Windows\System32\swprv.dll | true | 57430ad32d0775779a3d86aed1e0103a |
>| swprv | C:\Windows\System32\swprv.dll | true | 57430ad32d0775779a3d86aed1e0103a |
>| swprv | C:\Windows\System32\swprv.dll | true | 57430ad32d0775779a3d86aed1e0103a |
>| SysMain | C:\Windows\system32\sysmain.dll | true | a56113c4d934ff9ea7953d8e0b60d7db |
>| SysMain | C:\Windows\system32\sysmain.dll | true | a56113c4d934ff9ea7953d8e0b60d7db |
>| SysMain | C:\Windows\system32\sysmain.dll | true | a56113c4d934ff9ea7953d8e0b60d7db |
>| SysMain | C:\Windows\system32\sysmain.dll | true | a56113c4d934ff9ea7953d8e0b60d7db |
>| SystemEventsBroker | C:\Windows\System32\SystemEventsBrokerServer.dll | true | ddd397fa0c2c6ba7c1c3f912139f2ae2 |
>| SystemEventsBroker | C:\Windows\System32\SystemEventsBrokerServer.dll | true | ddd397fa0c2c6ba7c1c3f912139f2ae2 |
>| SystemEventsBroker | C:\Windows\System32\SystemEventsBrokerServer.dll | true | ddd397fa0c2c6ba7c1c3f912139f2ae2 |
>| SystemEventsBroker | C:\Windows\System32\SystemEventsBrokerServer.dll | true | ddd397fa0c2c6ba7c1c3f912139f2ae2 |
>| TabletInputService | C:\Windows\System32\TabSvc.dll | true | 307da9194ceecd8edf9601473e7dfbbf |
>| TabletInputService | C:\Windows\System32\TabSvc.dll | true | 307da9194ceecd8edf9601473e7dfbbf |
>| TabletInputService | C:\Windows\System32\TabSvc.dll | true | 307da9194ceecd8edf9601473e7dfbbf |
>| TabletInputService | C:\Windows\System32\TabSvc.dll | true | 307da9194ceecd8edf9601473e7dfbbf |
>| tapisrv | C:\Windows\System32\tapisrv.dll | true | d6428a209852a9c44ffc08985bc5f38e |
>| tapisrv | C:\Windows\System32\tapisrv.dll | true | d6428a209852a9c44ffc08985bc5f38e |
>| tapisrv | C:\Windows\System32\tapisrv.dll | true | d6428a209852a9c44ffc08985bc5f38e |
>| tapisrv | C:\Windows\System32\tapisrv.dll | true | d6428a209852a9c44ffc08985bc5f38e |
>| Tcpip | C:\Windows\System32\drivers\tcpip.sys | true | 8a13f21e7fb8f78a3d01bb952f691242 |
>| Tcpip | C:\Windows\System32\drivers\tcpip.sys | true | 8a13f21e7fb8f78a3d01bb952f691242 |
>| Tcpip6 | C:\Windows\System32\drivers\tcpip.sys | true | 8a13f21e7fb8f78a3d01bb952f691242 |
>| Tcpip6 | C:\Windows\System32\drivers\tcpip.sys | true | 8a13f21e7fb8f78a3d01bb952f691242 |
>| tcpipreg | C:\Windows\System32\drivers\tcpipreg.sys | true | 6a7338ae6e83bf75f2057b7b1242f81b |
>| tcpipreg | C:\Windows\System32\drivers\tcpipreg.sys | true | 6a7338ae6e83bf75f2057b7b1242f81b |
>| tdx | C:\Windows\system32\DRIVERS\tdx.sys | true | 7fd3d3e74c586e48b1fe6a26d9041a5a |
>| tdx | C:\Windows\system32\DRIVERS\tdx.sys | true | 7fd3d3e74c586e48b1fe6a26d9041a5a |
>| terminpt | C:\Windows\System32\drivers\terminpt.sys | true | a073581102fca9e17a1a4a5a40542d5c |
>| terminpt | C:\Windows\System32\drivers\terminpt.sys | true | a073581102fca9e17a1a4a5a40542d5c |
>| TermService | C:\Windows\System32\termsrv.dll | true | 408de68076ad4894a53c5e8a7f31885b |
>| TermService | C:\Windows\System32\termsrv.dll | true | 408de68076ad4894a53c5e8a7f31885b |
>| TermService | C:\Windows\System32\termsrv.dll | true | 408de68076ad4894a53c5e8a7f31885b |
>| TermService | C:\Windows\System32\termsrv.dll | true | 408de68076ad4894a53c5e8a7f31885b |
>| Themes | C:\Windows\system32\themeservice.dll | true | b8f6f18f13d0f7b719e0c60e083c1b12 |
>| Themes | C:\Windows\system32\themeservice.dll | true | b8f6f18f13d0f7b719e0c60e083c1b12 |
>| Themes | C:\Windows\system32\themeservice.dll | true | b8f6f18f13d0f7b719e0c60e083c1b12 |
>| Themes | C:\Windows\system32\themeservice.dll | true | b8f6f18f13d0f7b719e0c60e083c1b12 |
>| TieringEngineService | C:\Windows\system32\TieringEngineService.exe | true | a86dc1b6dc847669ef04a290fe53dd00 |
>| TieringEngineService | C:\Windows\system32\TieringEngineService.exe | true | a86dc1b6dc847669ef04a290fe53dd00 |
>| TimeBrokerSvc | C:\Windows\System32\TimeBrokerServer.dll | true | d79295826bdbdac19b9bb4d2c3c2e8a8 |
>| TimeBrokerSvc | C:\Windows\System32\TimeBrokerServer.dll | true | d79295826bdbdac19b9bb4d2c3c2e8a8 |
>| TimeBrokerSvc | C:\Windows\System32\TimeBrokerServer.dll | true | d79295826bdbdac19b9bb4d2c3c2e8a8 |
>| TimeBrokerSvc | C:\Windows\System32\TimeBrokerServer.dll | true | d79295826bdbdac19b9bb4d2c3c2e8a8 |
>| TokenBroker | C:\Windows\System32\TokenBroker.dll | true | 8b93cad690967f1d6a942b3bba816604 |
>| TokenBroker | C:\Windows\System32\TokenBroker.dll | true | 8b93cad690967f1d6a942b3bba816604 |
>| TokenBroker | C:\Windows\System32\TokenBroker.dll | true | 8b93cad690967f1d6a942b3bba816604 |
>| TokenBroker | C:\Windows\System32\TokenBroker.dll | true | 8b93cad690967f1d6a942b3bba816604 |
>| TPM | C:\Windows\System32\drivers\tpm.sys | true | d8bfc4be0dba61d02d4ecfa68c668204 |
>| TPM | C:\Windows\System32\drivers\tpm.sys | true | d8bfc4be0dba61d02d4ecfa68c668204 |
>| TrkWks | C:\Windows\System32\trkwks.dll | true | 522201273cab50fa6f41f999b1bc44a5 |
>| TrkWks | C:\Windows\System32\trkwks.dll | true | 522201273cab50fa6f41f999b1bc44a5 |
>| TrkWks | C:\Windows\System32\trkwks.dll | true | 522201273cab50fa6f41f999b1bc44a5 |
>| TrkWks | C:\Windows\System32\trkwks.dll | true | 522201273cab50fa6f41f999b1bc44a5 |
>| TrustedInstaller | C:\Windows\servicing\TrustedInstaller.exe | true | 464d0d44c67dd965ee607cfcd99a48ab |
>| TrustedInstaller | C:\Windows\servicing\TrustedInstaller.exe | true | 464d0d44c67dd965ee607cfcd99a48ab |
>| TsUsbFlt | C:\Windows\system32\drivers\tsusbflt.sys | true | c7ef4debfff35287052f8b5df077b138 |
>| TsUsbFlt | C:\Windows\system32\drivers\tsusbflt.sys | true | c7ef4debfff35287052f8b5df077b138 |
>| TsUsbGD | C:\Windows\System32\drivers\TsUsbGD.sys | true | 343d97bbb8f0ade9537c6e0642090f31 |
>| TsUsbGD | C:\Windows\System32\drivers\TsUsbGD.sys | true | 343d97bbb8f0ade9537c6e0642090f31 |
>| tsusbhub | C:\Windows\system32\drivers\tsusbhub.sys | true | aa22a654c950d0d9b0dbb051f7455a1e |
>| tsusbhub | C:\Windows\System32\drivers\tsusbhub.sys | true | aa22a654c950d0d9b0dbb051f7455a1e |
>| tunnel | C:\Windows\System32\drivers\tunnel.sys | true | 71710339da40b739532ea5ec00a610e7 |
>| tunnel | C:\Windows\System32\drivers\tunnel.sys | true | 71710339da40b739532ea5ec00a610e7 |
>| tzautoupdate | C:\Windows\system32\tzautoupdate.dll | true | 72a1a55ac95142d4df5e345c05c1390b |
>| tzautoupdate | C:\Windows\system32\tzautoupdate.dll | true | 72a1a55ac95142d4df5e345c05c1390b |
>| tzautoupdate | C:\Windows\system32\tzautoupdate.dll | true | 72a1a55ac95142d4df5e345c05c1390b |
>| tzautoupdate | C:\Windows\system32\tzautoupdate.dll | true | 72a1a55ac95142d4df5e345c05c1390b |
>| UALSVC | C:\Windows\System32\ualsvc.dll | true | 9d643d3236bdbc54a009877381a25600 |
>| UALSVC | C:\Windows\System32\ualsvc.dll | true | 9d643d3236bdbc54a009877381a25600 |
>| UALSVC | C:\Windows\System32\ualsvc.dll | true | 9d643d3236bdbc54a009877381a25600 |
>| UALSVC | C:\Windows\System32\ualsvc.dll | true | 9d643d3236bdbc54a009877381a25600 |
>| UASPStor | C:\Windows\System32\drivers\uaspstor.sys | true | 23136b24331d2b0e8ce40dca04320b97 |
>| UASPStor | C:\Windows\System32\drivers\uaspstor.sys | true | 23136b24331d2b0e8ce40dca04320b97 |
>| UcmCx0101 | C:\Windows\System32\Drivers\UcmCx.sys | true | 679f70e6af7c9b4df0b7f5c5f7d3e59c |
>| UcmCx0101 | C:\Windows\System32\Drivers\UcmCx.sys | true | 679f70e6af7c9b4df0b7f5c5f7d3e59c |
>| UcmTcpciCx0101 | C:\Windows\System32\Drivers\UcmTcpciCx.sys | true | e34582b17639772b47a3950dcc163c50 |
>| UcmTcpciCx0101 | C:\Windows\System32\Drivers\UcmTcpciCx.sys | true | e34582b17639772b47a3950dcc163c50 |
>| UcmUcsiAcpiClient | C:\Windows\System32\drivers\UcmUcsiAcpiClient.sys | true | 46c4630a57f302bc2711a0b1f1e7a2cd |
>| UcmUcsiAcpiClient | C:\Windows\System32\drivers\UcmUcsiAcpiClient.sys | true | 46c4630a57f302bc2711a0b1f1e7a2cd |
>| UcmUcsiCx0101 | C:\Windows\System32\Drivers\UcmUcsiCx.sys | true | 8120e9d5872b1fefe89d3b9399faaa32 |
>| UcmUcsiCx0101 | C:\Windows\System32\Drivers\UcmUcsiCx.sys | true | 8120e9d5872b1fefe89d3b9399faaa32 |
>| Ucx01000 | C:\Windows\system32\drivers\ucx01000.sys | true | df984ad18272526a5f6b5105e99b4175 |
>| Ucx01000 | C:\Windows\system32\drivers\ucx01000.sys | true | df984ad18272526a5f6b5105e99b4175 |
>| UdeCx | C:\Windows\system32\drivers\udecx.sys | true | d68019cfbed7863698c318cda625f36d |
>| UdeCx | C:\Windows\system32\drivers\udecx.sys | true | d68019cfbed7863698c318cda625f36d |
>| udfs | C:\Windows\system32\DRIVERS\udfs.sys | true | f21afa0eac046aec60a4d1ab4ef54402 |
>| udfs | C:\Windows\system32\DRIVERS\udfs.sys | true | f21afa0eac046aec60a4d1ab4ef54402 |
>| UdkUserSvc | C:\Windows\System32\windowsudkservices.shellcommon.dll | true | 48768bab2eb781065360bb52a6c2ed06 |
>| UdkUserSvc | C:\Windows\System32\windowsudkservices.shellcommon.dll | true | 48768bab2eb781065360bb52a6c2ed06 |
>| UdkUserSvc | C:\Windows\System32\windowsudkservices.shellcommon.dll | true | 48768bab2eb781065360bb52a6c2ed06 |
>| UdkUserSvc | C:\Windows\System32\windowsudkservices.shellcommon.dll | true | 48768bab2eb781065360bb52a6c2ed06 |
>| UdkUserSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| UEFI | C:\Windows\System32\DriverStore\FileRepository\uefi.inf_amd64_9f06649ff2db66cb\UEFI.sys | true | 4abf934b44b0bb1fd3bfb0a7a1606cc4 |
>| UEFI | C:\Windows\System32\DriverStore\FileRepository\uefi.inf_amd64_9f06649ff2db66cb\UEFI.sys | true | 4abf934b44b0bb1fd3bfb0a7a1606cc4 |
>| UevAgentDriver | C:\Windows\system32\drivers\UevAgentDriver.sys | true | ae5e320236762b339d6317885b4d2d44 |
>| UevAgentDriver | C:\Windows\system32\drivers\UevAgentDriver.sys | true | ae5e320236762b339d6317885b4d2d44 |
>| UevAgentService | C:\Windows\system32\AgentService.exe | true | 930c9a3eb8b54716df341d7f17a3e3b8 |
>| UevAgentService | C:\Windows\system32\AgentService.exe | true | 930c9a3eb8b54716df341d7f17a3e3b8 |
>| Ufx01000 | C:\Windows\system32\drivers\ufx01000.sys | true | 76aeb6693aeae91b1d5a696e6a0ab1f4 |
>| Ufx01000 | C:\Windows\system32\drivers\ufx01000.sys | true | 76aeb6693aeae91b1d5a696e6a0ab1f4 |
>| UfxChipidea | C:\Windows\System32\DriverStore\FileRepository\ufxchipidea.inf_amd64_aeccf7013ec6965b\UfxChipidea.sys | true | ccde14253795b9a684ebed07d29a2fd8 |
>| UfxChipidea | C:\Windows\System32\DriverStore\FileRepository\ufxchipidea.inf_amd64_aeccf7013ec6965b\UfxChipidea.sys | true | ccde14253795b9a684ebed07d29a2fd8 |
>| ufxsynopsys | C:\Windows\System32\drivers\ufxsynopsys.sys | true | e104d320cb68fc26eef7e29b34fd1703 |
>| ufxsynopsys | C:\Windows\System32\drivers\ufxsynopsys.sys | true | e104d320cb68fc26eef7e29b34fd1703 |
>| umbus | C:\Windows\System32\DriverStore\FileRepository\umbus.inf_amd64_f529037a77b144c5\umbus.sys | true | 65aa6b0661c1eedbe80667b39bebc784 |
>| umbus | C:\Windows\System32\DriverStore\FileRepository\umbus.inf_amd64_f529037a77b144c5\umbus.sys | true | 65aa6b0661c1eedbe80667b39bebc784 |
>| UmPass | C:\Windows\System32\drivers\umpass.sys | true | fd7ae43e3abe0c1928f4fd665925e686 |
>| UmPass | C:\Windows\System32\drivers\umpass.sys | true | fd7ae43e3abe0c1928f4fd665925e686 |
>| UmRdpService | C:\Windows\System32\umrdp.dll | true | 5a07d2e20075d9b28412e0c09e6620f3 |
>| UmRdpService | C:\Windows\System32\umrdp.dll | true | 5a07d2e20075d9b28412e0c09e6620f3 |
>| UmRdpService | C:\Windows\System32\umrdp.dll | true | 5a07d2e20075d9b28412e0c09e6620f3 |
>| UmRdpService | C:\Windows\System32\umrdp.dll | true | 5a07d2e20075d9b28412e0c09e6620f3 |
>| UnistoreSvc | C:\Windows\System32\unistore.dll | true | fd39739243507ca0231641d8e617de0a |
>| UnistoreSvc | C:\Windows\System32\unistore.dll | true | fd39739243507ca0231641d8e617de0a |
>| UnistoreSvc | C:\Windows\System32\unistore.dll | true | fd39739243507ca0231641d8e617de0a |
>| UnistoreSvc | C:\Windows\System32\unistore.dll | true | fd39739243507ca0231641d8e617de0a |
>| UnistoreSvc_15391515 | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| upnphost | C:\Windows\System32\upnphost.dll | true | a21d812bd34d5a463aba0763a1401b0f |
>| upnphost | C:\Windows\System32\upnphost.dll | true | a21d812bd34d5a463aba0763a1401b0f |
>| upnphost | C:\Windows\System32\upnphost.dll | true | a21d812bd34d5a463aba0763a1401b0f |
>| upnphost | C:\Windows\System32\upnphost.dll | true | a21d812bd34d5a463aba0763a1401b0f |
>| UrsChipidea | C:\Windows\System32\DriverStore\FileRepository\urschipidea.inf_amd64_5668f319215c576a\urschipidea.sys | true | ee72b57aa6ee25fa281ac4818642d499 |
>| UrsChipidea | C:\Windows\System32\DriverStore\FileRepository\urschipidea.inf_amd64_5668f319215c576a\urschipidea.sys | true | ee72b57aa6ee25fa281ac4818642d499 |
>| UrsCx01000 | C:\Windows\system32\drivers\urscx01000.sys | true | ba36a9161c5bd0a576403578bea05074 |
>| UrsCx01000 | C:\Windows\system32\drivers\urscx01000.sys | true | ba36a9161c5bd0a576403578bea05074 |
>| UrsSynopsys | C:\Windows\System32\DriverStore\FileRepository\urssynopsys.inf_amd64_03db30e7672fa0ec\urssynopsys.sys | true | a807575b12ba8044d56b57af3a86bac8 |
>| UrsSynopsys | C:\Windows\System32\DriverStore\FileRepository\urssynopsys.inf_amd64_03db30e7672fa0ec\urssynopsys.sys | true | a807575b12ba8044d56b57af3a86bac8 |
>| Usb4DeviceRouter | C:\Windows\System32\drivers\Usb4DeviceRouter.sys | true | ad604210cb44128d7532999607fc92d1 |
>| Usb4DeviceRouter | C:\Windows\System32\drivers\Usb4DeviceRouter.sys | true | ad604210cb44128d7532999607fc92d1 |
>| Usb4HostRouter | C:\Windows\System32\drivers\Usb4HostRouter.sys | true | 51bc230b590729ec8102b78393f46d10 |
>| Usb4HostRouter | C:\Windows\System32\drivers\Usb4HostRouter.sys | true | 51bc230b590729ec8102b78393f46d10 |
>| usbaudio | C:\Windows\system32\drivers\usbaudio.sys | true | 4d74a9cc28164792e444aca1db2cce8b |
>| usbaudio | C:\Windows\system32\drivers\usbaudio.sys | true | 4d74a9cc28164792e444aca1db2cce8b |
>| usbaudio2 | C:\Windows\System32\drivers\usbaudio2.sys | true | a06bc43865b1546ab7c1bf78bf68b51a |
>| usbaudio2 | C:\Windows\System32\drivers\usbaudio2.sys | true | a06bc43865b1546ab7c1bf78bf68b51a |
>| usbccgp | C:\Windows\System32\drivers\usbccgp.sys | true | b096215f2b4a5ac2b5c2aea7e5f5219b |
>| usbccgp | C:\Windows\System32\drivers\usbccgp.sys | true | b096215f2b4a5ac2b5c2aea7e5f5219b |
>| usbehci | C:\Windows\System32\drivers\usbehci.sys | true | e55561ab48c47119889285ae9a926803 |
>| usbehci | C:\Windows\System32\drivers\usbehci.sys | true | e55561ab48c47119889285ae9a926803 |
>| usbhub | C:\Windows\System32\drivers\usbhub.sys | true | 8715f14376d2736d389bf4965fef0d1c |
>| usbhub | C:\Windows\System32\drivers\usbhub.sys | true | 8715f14376d2736d389bf4965fef0d1c |
>| USBHUB3 | C:\Windows\System32\drivers\UsbHub3.sys | true | d898b04496f7b71f108037f021762b69 |
>| USBHUB3 | C:\Windows\System32\drivers\UsbHub3.sys | true | d898b04496f7b71f108037f021762b69 |
>| usbohci | C:\Windows\System32\drivers\usbohci.sys | true | 25f86b20c5b633712e19db950a1cb853 |
>| usbohci | C:\Windows\System32\drivers\usbohci.sys | true | 25f86b20c5b633712e19db950a1cb853 |
>| usbprint | C:\Windows\System32\drivers\usbprint.sys | true | 4f06eceaf37ac0164c286b33123cd0f1 |
>| usbprint | C:\Windows\System32\drivers\usbprint.sys | true | 4f06eceaf37ac0164c286b33123cd0f1 |
>| usbser | C:\Windows\System32\drivers\usbser.sys | true | ec60c70fbb83a374329c0cf2ae869858 |
>| usbser | C:\Windows\System32\drivers\usbser.sys | true | ec60c70fbb83a374329c0cf2ae869858 |
>| USBSTOR | C:\Windows\System32\drivers\USBSTOR.SYS | true | 86559d32bf926a1ce1c558a9f04d0695 |
>| USBSTOR | C:\Windows\System32\drivers\USBSTOR.SYS | true | 86559d32bf926a1ce1c558a9f04d0695 |
>| usbuhci | C:\Windows\System32\drivers\usbuhci.sys | true | 2a97eac51eefd7eebd198caf236007af |
>| usbuhci | C:\Windows\System32\drivers\usbuhci.sys | true | 2a97eac51eefd7eebd198caf236007af |
>| USBXHCI | C:\Windows\System32\drivers\USBXHCI.SYS | true | 458193b8b793ec02d1abacf0b45296f2 |
>| USBXHCI | C:\Windows\System32\drivers\USBXHCI.SYS | true | 458193b8b793ec02d1abacf0b45296f2 |
>| UserDataSvc | C:\Windows\System32\userdataservice.dll | true | 1fb9c41c480acf8929a9b8acb5cd20e2 |
>| UserDataSvc | C:\Windows\System32\userdataservice.dll | true | 1fb9c41c480acf8929a9b8acb5cd20e2 |
>| UserDataSvc | C:\Windows\System32\userdataservice.dll | true | 1fb9c41c480acf8929a9b8acb5cd20e2 |
>| UserDataSvc | C:\Windows\System32\userdataservice.dll | true | 1fb9c41c480acf8929a9b8acb5cd20e2 |
>| UserDataSvc_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| UserManager | C:\Windows\System32\usermgr.dll | true | bc60b2c5d490d88679fe619f6778b4de |
>| UserManager | C:\Windows\System32\usermgr.dll | true | bc60b2c5d490d88679fe619f6778b4de |
>| UserManager | C:\Windows\System32\usermgr.dll | true | bc60b2c5d490d88679fe619f6778b4de |
>| UserManager | C:\Windows\System32\usermgr.dll | true | bc60b2c5d490d88679fe619f6778b4de |
>| UsoSvc | C:\Windows\system32\usosvc.dll | true | f369c38b009621c4b4633ba9fead7819 |
>| UsoSvc | C:\Windows\system32\usosvc.dll | true | f369c38b009621c4b4633ba9fead7819 |
>| UsoSvc | C:\Windows\system32\usosvc.dll | true | f369c38b009621c4b4633ba9fead7819 |
>| UsoSvc | C:\Windows\system32\usosvc.dll | true | f369c38b009621c4b4633ba9fead7819 |
>| VaultSvc | C:\Windows\System32\vaultsvc.dll | true | 9243207f1c72cff68ce5929eb62941af |
>| VaultSvc | C:\Windows\System32\vaultsvc.dll | true | 9243207f1c72cff68ce5929eb62941af |
>| VaultSvc | C:\Windows\System32\vaultsvc.dll | true | 9243207f1c72cff68ce5929eb62941af |
>| VaultSvc | C:\Windows\System32\vaultsvc.dll | true | 9243207f1c72cff68ce5929eb62941af |
>| VBoxGuest | C:\Windows\system32\DRIVERS\VBoxGuest.sys | true | 873c8107cc6f4a8339b66eeb9fa2d2e1 |
>| VBoxGuest | C:\Windows\system32\DRIVERS\VBoxGuest.sys | true | 873c8107cc6f4a8339b66eeb9fa2d2e1 |
>| VBoxMouse | C:\Windows\system32\DRIVERS\VBoxMouse.sys | true | 0b922b41369b9779a4e71d68efc02275 |
>| VBoxMouse | C:\Windows\system32\DRIVERS\VBoxMouse.sys | true | 0b922b41369b9779a4e71d68efc02275 |
>| VBoxService | C:\Windows\System32\VBoxService.exe | true | 5ac35aca951acd0732752095bbc366be |
>| VBoxService | C:\Windows\System32\VBoxService.exe | true | 5ac35aca951acd0732752095bbc366be |
>| VBoxSF | C:\Windows\System32\drivers\VBoxSF.sys | true | 9c5fa56ec9fa228e31484df1e41364d3 |
>| VBoxSF | C:\Windows\System32\drivers\VBoxSF.sys | true | 9c5fa56ec9fa228e31484df1e41364d3 |
>| VBoxWddm | C:\Windows\system32\DRIVERS\VBoxWddm.sys | true | 66ed4d8224cfe448ba9dad324b564f35 |
>| VBoxWddm | C:\Windows\system32\DRIVERS\VBoxWddm.sys | true | 66ed4d8224cfe448ba9dad324b564f35 |
>| vdrvroot | C:\Windows\System32\drivers\vdrvroot.sys | true | 504a71b5d24a6975a1d771c44ccf86fd |
>| vdrvroot | C:\Windows\System32\drivers\vdrvroot.sys | true | 504a71b5d24a6975a1d771c44ccf86fd |
>| vds | C:\Windows\System32\vds.exe | true | a8487cee7d831ead54f2d29688d09c92 |
>| vds | C:\Windows\System32\vds.exe | true | a8487cee7d831ead54f2d29688d09c92 |
>| VerifierExt | C:\Windows\System32\drivers\VerifierExt.sys | true | ce72e993399f04d5ed8258aab0b77506 |
>| VerifierExt | C:\Windows\System32\drivers\VerifierExt.sys | true | ce72e993399f04d5ed8258aab0b77506 |
>| vhdmp | C:\Windows\System32\drivers\vhdmp.sys | true | 4c19232180eb9a21ef93d77738755722 |
>| vhdmp | C:\Windows\System32\drivers\vhdmp.sys | true | 4c19232180eb9a21ef93d77738755722 |
>| vhf | C:\Windows\System32\drivers\vhf.sys | true | 6108fde2565029e34fe01ea59efe840b |
>| vhf | C:\Windows\System32\drivers\vhf.sys | true | 6108fde2565029e34fe01ea59efe840b |
>| VirtualRender | C:\Windows\System32\DriverStore\FileRepository\vrd.inf_amd64_1fbbe83391910b93\vrd.sys | true | 86190af4f24bb697940349c073650de2 |
>| VirtualRender | C:\Windows\System32\DriverStore\FileRepository\vrd.inf_amd64_1fbbe83391910b93\vrd.sys | true | 86190af4f24bb697940349c073650de2 |
>| vmbus | C:\Windows\System32\drivers\vmbus.sys | true | 6b16fb2048005d6cec551791241141aa |
>| vmbus | C:\Windows\System32\drivers\vmbus.sys | true | 6b16fb2048005d6cec551791241141aa |
>| VMBusHID | C:\Windows\System32\drivers\VMBusHID.sys | true | d32f75fb6084d58f8edbe31c92ed3d77 |
>| VMBusHID | C:\Windows\System32\drivers\VMBusHID.sys | true | d32f75fb6084d58f8edbe31c92ed3d77 |
>| vmgid | C:\Windows\System32\drivers\vmgid.sys | true | ddbf27f6195bb66b7e267974aedf2d4c |
>| vmgid | C:\Windows\System32\drivers\vmgid.sys | true | ddbf27f6195bb66b7e267974aedf2d4c |
>| vmicguestinterface | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicguestinterface | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicguestinterface | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicguestinterface | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicheartbeat | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicheartbeat | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicheartbeat | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicheartbeat | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmickvpexchange | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmickvpexchange | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmickvpexchange | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmickvpexchange | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicshutdown | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicshutdown | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicshutdown | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicshutdown | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmictimesync | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmictimesync | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmictimesync | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmictimesync | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicvmsession | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicvmsession | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicvmsession | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicvmsession | C:\Windows\System32\icsvc.dll | true | 7c6e21a9288161571e8a030644f5ac97 |
>| vmicvss | C:\Windows\System32\icsvcvss.dll | true | 20550321c711edf9c074af1ec7919fd8 |
>| vmicvss | C:\Windows\System32\icsvcvss.dll | true | 20550321c711edf9c074af1ec7919fd8 |
>| vmicvss | C:\Windows\System32\icsvcvss.dll | true | 20550321c711edf9c074af1ec7919fd8 |
>| vmicvss | C:\Windows\System32\icsvcvss.dll | true | 20550321c711edf9c074af1ec7919fd8 |
>| volmgr | C:\Windows\System32\drivers\volmgr.sys | true | 0bc9e7b4865ed2227cccc05f1dbc6f52 |
>| volmgr | C:\Windows\System32\drivers\volmgr.sys | true | 0bc9e7b4865ed2227cccc05f1dbc6f52 |
>| volmgrx | C:\Windows\System32\drivers\volmgrx.sys | true | f7da6b4c3238121c132213e30b7651b2 |
>| volmgrx | C:\Windows\System32\drivers\volmgrx.sys | true | f7da6b4c3238121c132213e30b7651b2 |
>| volsnap | C:\Windows\System32\drivers\volsnap.sys | true | 8e0d28114d41d67b95c71d5cd17e86c0 |
>| volsnap | C:\Windows\System32\drivers\volsnap.sys | true | 8e0d28114d41d67b95c71d5cd17e86c0 |
>| volume | C:\Windows\System32\drivers\volume.sys | true | 05fac0dd1370c68530f0a72caf64a27b |
>| volume | C:\Windows\System32\drivers\volume.sys | true | 05fac0dd1370c68530f0a72caf64a27b |
>| vpci | C:\Windows\System32\drivers\vpci.sys | true | 6d2cdfc79a86ada64c0ea86b16462925 |
>| vpci | C:\Windows\System32\drivers\vpci.sys | true | 6d2cdfc79a86ada64c0ea86b16462925 |
>| vsmraid | C:\Windows\System32\drivers\vsmraid.sys | true | c8a68bb6e51cf3f0580fc552d05b482e |
>| vsmraid | C:\Windows\System32\drivers\vsmraid.sys | true | c8a68bb6e51cf3f0580fc552d05b482e |
>| VSS | C:\Windows\system32\vssvc.exe | true | d6037f722e7259fdccfeaf56b036adf2 |
>| VSS | C:\Windows\system32\vssvc.exe | true | d6037f722e7259fdccfeaf56b036adf2 |
>| VSTXRAID | C:\Windows\System32\drivers\vstxraid.sys | true | d870dc436ba5c79c200aa751cf0b66c7 |
>| VSTXRAID | C:\Windows\System32\drivers\vstxraid.sys | true | d870dc436ba5c79c200aa751cf0b66c7 |
>| vwifibus |  | false |  |
>| vwifibus |  | false |  |
>| W32Time | C:\Windows\system32\w32time.dll | true | 68b0ddf1884a177d2649d41b0ba1fec7 |
>| W32Time | C:\Windows\system32\w32time.dll | true | 68b0ddf1884a177d2649d41b0ba1fec7 |
>| W32Time | C:\Windows\system32\w32time.dll | true | 68b0ddf1884a177d2649d41b0ba1fec7 |
>| W32Time | C:\Windows\system32\w32time.dll | true | 68b0ddf1884a177d2649d41b0ba1fec7 |
>| WaaSMedicSvc | C:\Windows\System32\WaaSMedicSvc.dll | true | 32b0ce651968939dbf98ff0d60abf913 |
>| WaaSMedicSvc | C:\Windows\System32\WaaSMedicSvc.dll | true | 32b0ce651968939dbf98ff0d60abf913 |
>| WaaSMedicSvc | C:\Windows\System32\WaaSMedicSvc.dll | true | 32b0ce651968939dbf98ff0d60abf913 |
>| WaaSMedicSvc | C:\Windows\System32\WaaSMedicSvc.dll | true | 32b0ce651968939dbf98ff0d60abf913 |
>| WacomPen | C:\Windows\System32\drivers\wacompen.sys | true | 244000921c22efcced5a98ce325fae30 |
>| WacomPen | C:\Windows\System32\drivers\wacompen.sys | true | 244000921c22efcced5a98ce325fae30 |
>| WalletService | C:\Windows\system32\WalletService.dll | true | 750735d306ff16f75329de3dedc85359 |
>| WalletService | C:\Windows\system32\WalletService.dll | true | 750735d306ff16f75329de3dedc85359 |
>| WalletService | C:\Windows\system32\WalletService.dll | true | 750735d306ff16f75329de3dedc85359 |
>| WalletService | C:\Windows\system32\WalletService.dll | true | 750735d306ff16f75329de3dedc85359 |
>| wanarp | C:\Windows\System32\DRIVERS\wanarp.sys | true | 729e5a98361534e5c6041407311f2c9e |
>| wanarp | C:\Windows\System32\DRIVERS\wanarp.sys | true | 729e5a98361534e5c6041407311f2c9e |
>| wanarpv6 | C:\Windows\System32\DRIVERS\wanarp.sys | true | 729e5a98361534e5c6041407311f2c9e |
>| wanarpv6 | C:\Windows\System32\DRIVERS\wanarp.sys | true | 729e5a98361534e5c6041407311f2c9e |
>| WarpJITSvc | C:\Windows\System32\Windows.WARP.JITService.dll | true | 573a95a43ec92b8c9f4334c3d1ee4007 |
>| WarpJITSvc | C:\Windows\System32\Windows.WARP.JITService.dll | true | 573a95a43ec92b8c9f4334c3d1ee4007 |
>| WarpJITSvc | C:\Windows\System32\Windows.WARP.JITService.dll | true | 573a95a43ec92b8c9f4334c3d1ee4007 |
>| WarpJITSvc | C:\Windows\System32\Windows.WARP.JITService.dll | true | 573a95a43ec92b8c9f4334c3d1ee4007 |
>| WbioSrvc | C:\Windows\System32\wbiosrvc.dll | true | b294068cdd11d70c9703f2a7e40d3330 |
>| WbioSrvc | C:\Windows\System32\wbiosrvc.dll | true | b294068cdd11d70c9703f2a7e40d3330 |
>| WbioSrvc | C:\Windows\System32\wbiosrvc.dll | true | b294068cdd11d70c9703f2a7e40d3330 |
>| WbioSrvc | C:\Windows\System32\wbiosrvc.dll | true | b294068cdd11d70c9703f2a7e40d3330 |
>| wcifs | C:\Windows\system32\drivers\wcifs.sys | true | f6eac3ea92f216a48495ea0fe645dcbf |
>| wcifs | C:\Windows\system32\drivers\wcifs.sys | true | f6eac3ea92f216a48495ea0fe645dcbf |
>| Wcmsvc | C:\Windows\System32\wcmsvc.dll | true | 7a779c762ba808d531973e378b790ac8 |
>| Wcmsvc | C:\Windows\System32\wcmsvc.dll | true | 7a779c762ba808d531973e378b790ac8 |
>| Wcmsvc | C:\Windows\System32\wcmsvc.dll | true | 7a779c762ba808d531973e378b790ac8 |
>| Wcmsvc | C:\Windows\System32\wcmsvc.dll | true | 7a779c762ba808d531973e378b790ac8 |
>| WdBoot | C:\Windows\system32\drivers\wd\WdBoot.sys | true | 33a97c8017ac18abf2b00eaaa9b5b0c4 |
>| WdBoot | C:\Windows\system32\drivers\wd\WdBoot.sys | true | 33a97c8017ac18abf2b00eaaa9b5b0c4 |
>| Wdf01000 | C:\Windows\system32\drivers\Wdf01000.sys | true | 252710b80261fc7a470765da230f4582 |
>| Wdf01000 | C:\Windows\system32\drivers\Wdf01000.sys | true | 252710b80261fc7a470765da230f4582 |
>| WdFilter | C:\Windows\system32\drivers\wd\WdFilter.sys | true | 98e9a26bbd42e644bf797710f9f65dce |
>| WdFilter | C:\Windows\system32\drivers\WdFilter.sys | true | b3965025c0fed1c7664005951536b0c9 |
>| WdiServiceHost | C:\Windows\system32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| WdiServiceHost | C:\Windows\system32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| WdiServiceHost | C:\Windows\system32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| WdiServiceHost | C:\Windows\system32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| WdiSystemHost | C:\Windows\system32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| WdiSystemHost | C:\Windows\system32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| WdiSystemHost | C:\Windows\system32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| WdiSystemHost | C:\Windows\system32\wdi.dll | true | 90bec7af03968f67bca4a1da50b042db |
>| WdmCompanionFilter | C:\Windows\system32\drivers\WdmCompanionFilter.sys | true | 02ca8dd9f78f6ff4ca0c028db803945a |
>| WdmCompanionFilter | C:\Windows\system32\drivers\WdmCompanionFilter.sys | true | 02ca8dd9f78f6ff4ca0c028db803945a |
>| WdNisDrv | C:\Windows\system32\drivers\wd\WdNisDrv.sys | true | 49f632dcdeac16123927067c4512913a |
>| WdNisDrv | C:\Windows\system32\Drivers\WdNisDrv.sys | true | 06eeb51e111f52588dbae3bbe122386f |
>| WdNisSvc | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2205.7-0\NisSrv.exe | true | 85e46c79c8f8ea940fb0ebbede18b46f |
>| WdNisSvc | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2205.7-0\NisSrv.exe | true | 85e46c79c8f8ea940fb0ebbede18b46f |
>| Wecsvc | C:\Windows\system32\wecsvc.dll | true | 477a7e92497f33a17ec28d873400a0f9 |
>| Wecsvc | C:\Windows\system32\wecsvc.dll | true | 477a7e92497f33a17ec28d873400a0f9 |
>| Wecsvc | C:\Windows\system32\wecsvc.dll | true | 477a7e92497f33a17ec28d873400a0f9 |
>| Wecsvc | C:\Windows\system32\wecsvc.dll | true | 477a7e92497f33a17ec28d873400a0f9 |
>| WEPHOSTSVC | C:\Windows\system32\wephostsvc.dll | true | ca2e7111e71bfa7296c6623bab2d8ce7 |
>| WEPHOSTSVC | C:\Windows\system32\wephostsvc.dll | true | ca2e7111e71bfa7296c6623bab2d8ce7 |
>| WEPHOSTSVC | C:\Windows\system32\wephostsvc.dll | true | ca2e7111e71bfa7296c6623bab2d8ce7 |
>| WEPHOSTSVC | C:\Windows\system32\wephostsvc.dll | true | ca2e7111e71bfa7296c6623bab2d8ce7 |
>| wercplsupport | C:\Windows\System32\wercplsupport.dll | true | 89f09ca76ec149be7b3d52a7a513c91e |
>| wercplsupport | C:\Windows\System32\wercplsupport.dll | true | 89f09ca76ec149be7b3d52a7a513c91e |
>| wercplsupport | C:\Windows\System32\wercplsupport.dll | true | 89f09ca76ec149be7b3d52a7a513c91e |
>| wercplsupport | C:\Windows\System32\wercplsupport.dll | true | 89f09ca76ec149be7b3d52a7a513c91e |
>| WerSvc | C:\Windows\System32\WerSvc.dll | true | c8847488d1423be439ee1281566499da |
>| WerSvc | C:\Windows\System32\WerSvc.dll | true | c8847488d1423be439ee1281566499da |
>| WerSvc | C:\Windows\System32\WerSvc.dll | true | c8847488d1423be439ee1281566499da |
>| WerSvc | C:\Windows\System32\WerSvc.dll | true | c8847488d1423be439ee1281566499da |
>| WFPLWFS | C:\Windows\System32\drivers\wfplwfs.sys | true | 2aad68e852436e0a7363377c91e0302d |
>| WFPLWFS | C:\Windows\System32\drivers\wfplwfs.sys | true | 2aad68e852436e0a7363377c91e0302d |
>| WiaRpc | C:\Windows\System32\wiarpc.dll | true | 618d47a30e374dfcf52a04915d33e223 |
>| WiaRpc | C:\Windows\System32\wiarpc.dll | true | 618d47a30e374dfcf52a04915d33e223 |
>| WiaRpc | C:\Windows\System32\wiarpc.dll | true | 618d47a30e374dfcf52a04915d33e223 |
>| WiaRpc | C:\Windows\System32\wiarpc.dll | true | 618d47a30e374dfcf52a04915d33e223 |
>| WIMMount | C:\Windows\system32\drivers\wimmount.sys | true | 7e12f9f23a87dfb574db49d1a7f23ed3 |
>| WIMMount | C:\Windows\system32\drivers\wimmount.sys | true | 7e12f9f23a87dfb574db49d1a7f23ed3 |
>| WinDefend | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2205.7-0\MsMpEng.exe | true | a7dca32f82ec2569865f447416a7cf1a |
>| WinDefend | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2205.7-0\MsMpEng.exe | true | a7dca32f82ec2569865f447416a7cf1a |
>| WindowsTrustedRT | C:\Windows\system32\drivers\WindowsTrustedRT.sys | true | 74240ace203c61bd4f4b6081654884c0 |
>| WindowsTrustedRT | C:\Windows\system32\drivers\WindowsTrustedRT.sys | true | 74240ace203c61bd4f4b6081654884c0 |
>| WindowsTrustedRTProxy | C:\Windows\System32\drivers\WindowsTrustedRTProxy.sys | true | 0b728612a0aec70533a641fbec23d01a |
>| WindowsTrustedRTProxy | C:\Windows\System32\drivers\WindowsTrustedRTProxy.sys | true | 0b728612a0aec70533a641fbec23d01a |
>| WinHttpAutoProxySvc | C:\Windows\system32\winhttp.dll | true | 5990d33fda7ab63199da325c13fcefc7 |
>| WinHttpAutoProxySvc | C:\Windows\system32\winhttp.dll | true | 5990d33fda7ab63199da325c13fcefc7 |
>| WinHttpAutoProxySvc | C:\Windows\system32\winhttp.dll | true | 5990d33fda7ab63199da325c13fcefc7 |
>| WinHttpAutoProxySvc | C:\Windows\system32\winhttp.dll | true | 5990d33fda7ab63199da325c13fcefc7 |
>| WinMad | C:\Windows\System32\drivers\winmad.sys | true | 955c3f9cfff1d2e9e2a643a4920ff53c |
>| WinMad | C:\Windows\System32\drivers\winmad.sys | true | 955c3f9cfff1d2e9e2a643a4920ff53c |
>| Winmgmt | C:\Windows\system32\wbem\WMIsvc.dll | true | 059b29734a6659ced32a027ecff3dccc |
>| Winmgmt | C:\Windows\system32\wbem\WMIsvc.dll | true | 059b29734a6659ced32a027ecff3dccc |
>| Winmgmt | C:\Windows\system32\wbem\WMIsvc.dll | true | 059b29734a6659ced32a027ecff3dccc |
>| Winmgmt | C:\Windows\system32\wbem\WMIsvc.dll | true | 059b29734a6659ced32a027ecff3dccc |
>| WinNat | C:\Windows\system32\drivers\winnat.sys | true | 4d562b3a2755b71e93d0518d2e51567c |
>| WinNat | C:\Windows\system32\drivers\winnat.sys | true | 4d562b3a2755b71e93d0518d2e51567c |
>| WinRM | C:\Windows\system32\WsmSvc.dll | true | d31f6d528bf140eb0310c65b45522d4a |
>| WinRM | C:\Windows\system32\WsmSvc.dll | true | d31f6d528bf140eb0310c65b45522d4a |
>| WinRM | C:\Windows\system32\WsmSvc.dll | true | d31f6d528bf140eb0310c65b45522d4a |
>| WinRM | C:\Windows\system32\WsmSvc.dll | true | d31f6d528bf140eb0310c65b45522d4a |
>| WINUSB | C:\Windows\System32\drivers\WinUSB.SYS | true | 023574b306e1af48adb7999cfe3c914a |
>| WINUSB | C:\Windows\System32\drivers\WinUSB.SYS | true | 023574b306e1af48adb7999cfe3c914a |
>| WinVerbs | C:\Windows\System32\drivers\winverbs.sys | true | 1601c34722efb07f8f2ca144ac9c42c0 |
>| WinVerbs | C:\Windows\System32\drivers\winverbs.sys | true | 1601c34722efb07f8f2ca144ac9c42c0 |
>| wisvc | C:\Windows\system32\flightsettings.dll | true | c872ac46fb3b998f93f42e270410653b |
>| wisvc | C:\Windows\system32\flightsettings.dll | true | c872ac46fb3b998f93f42e270410653b |
>| wisvc | C:\Windows\system32\flightsettings.dll | true | c872ac46fb3b998f93f42e270410653b |
>| wisvc | C:\Windows\system32\flightsettings.dll | true | c872ac46fb3b998f93f42e270410653b |
>| wlidsvc | C:\Windows\system32\wlidsvc.dll | true | c1d341e08b4cccf8371a2b94a11f2382 |
>| wlidsvc | C:\Windows\system32\wlidsvc.dll | true | c1d341e08b4cccf8371a2b94a11f2382 |
>| wlidsvc | C:\Windows\system32\wlidsvc.dll | true | c1d341e08b4cccf8371a2b94a11f2382 |
>| wlidsvc | C:\Windows\system32\wlidsvc.dll | true | c1d341e08b4cccf8371a2b94a11f2382 |
>| WLMS | C:\Windows\system32\wlms\wlms.exe | true | e723cfc8e88f9eb378f1043aaf3df92e |
>| WLMS | C:\Windows\system32\wlms\wlms.exe | true | e723cfc8e88f9eb378f1043aaf3df92e |
>| WmiAcpi | C:\Windows\System32\drivers\wmiacpi.sys | true | 310419c9ee6be5b029b688daecc6f1c1 |
>| WmiAcpi | C:\Windows\System32\drivers\wmiacpi.sys | true | 310419c9ee6be5b029b688daecc6f1c1 |
>| wmiApSrv | C:\Windows\system32\wbem\WmiApSrv.exe | true | 2c75c137ab7ec5501aa7cae29f835985 |
>| wmiApSrv | C:\Windows\system32\wbem\WmiApSrv.exe | true | 2c75c137ab7ec5501aa7cae29f835985 |
>| WMPNetworkSvc | C:\Program Files\Windows Media Player\wmpnetwk.exe | true | cc43ea8ebe75e2e0dd80ccc01ea16c65 |
>| WMPNetworkSvc | C:\Program Files\Windows Media Player\wmpnetwk.exe | true | cc43ea8ebe75e2e0dd80ccc01ea16c65 |
>| Wof | C:\Windows\system32\drivers\Wof.sys | true | 06ea9914a709a459075122981df85d37 |
>| Wof | C:\Windows\system32\drivers\Wof.sys | true | 06ea9914a709a459075122981df85d37 |
>| WPDBusEnum | C:\Windows\system32\wpdbusenum.dll | true | 818a9805ae54193eb2ec24cfdb14a91d |
>| WPDBusEnum | C:\Windows\system32\wpdbusenum.dll | true | 818a9805ae54193eb2ec24cfdb14a91d |
>| WPDBusEnum | C:\Windows\system32\wpdbusenum.dll | true | 818a9805ae54193eb2ec24cfdb14a91d |
>| WPDBusEnum | C:\Windows\system32\wpdbusenum.dll | true | 818a9805ae54193eb2ec24cfdb14a91d |
>| WpdUpFltr | C:\Windows\System32\drivers\WpdUpFltr.sys | true | 2d1a6f394a45ba1ea545f59f85c086cc |
>| WpdUpFltr | C:\Windows\System32\drivers\WpdUpFltr.sys | true | 2d1a6f394a45ba1ea545f59f85c086cc |
>| WpnService | C:\Windows\system32\WpnService.dll | true | dbdc4fbf240921a6036122949398ce33 |
>| WpnService | C:\Windows\system32\WpnService.dll | true | dbdc4fbf240921a6036122949398ce33 |
>| WpnService | C:\Windows\system32\WpnService.dll | true | dbdc4fbf240921a6036122949398ce33 |
>| WpnService | C:\Windows\system32\WpnService.dll | true | dbdc4fbf240921a6036122949398ce33 |
>| WpnUserService | C:\Windows\System32\WpnUserService.dll | true | 7d22242b0e337656404f117921d2be21 |
>| WpnUserService | C:\Windows\System32\WpnUserService.dll | true | 7d22242b0e337656404f117921d2be21 |
>| WpnUserService | C:\Windows\System32\WpnUserService.dll | true | 7d22242b0e337656404f117921d2be21 |
>| WpnUserService | C:\Windows\System32\WpnUserService.dll | true | 7d22242b0e337656404f117921d2be21 |
>| WpnUserService_15391515 | C:\Windows\system32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| ws2ifsl | C:\Windows\system32\drivers\ws2ifsl.sys | true | 81a4fff62a6d142d4ecbaae34906445b |
>| ws2ifsl | C:\Windows\system32\drivers\ws2ifsl.sys | true | 81a4fff62a6d142d4ecbaae34906445b |
>| WSearch | C:\Windows\system32\SearchIndexer.exe | true | c707eb14241077151f0d1d694ff53947 |
>| WSearch | C:\Windows\system32\SearchIndexer.exe | true | c707eb14241077151f0d1d694ff53947 |
>| wuauserv | C:\Windows\system32\wuaueng.dll | true | dde6273f11df8a52ad7691e1130af0cc |
>| wuauserv | C:\Windows\system32\wuaueng.dll | true | dde6273f11df8a52ad7691e1130af0cc |
>| wuauserv | C:\Windows\system32\wuaueng.dll | true | dde6273f11df8a52ad7691e1130af0cc |
>| wuauserv | C:\Windows\system32\wuaueng.dll | true | dde6273f11df8a52ad7691e1130af0cc |
>| WudfPf | C:\Windows\system32\drivers\WudfPf.sys | true | 5febf87f703a843078c20a6cfeef846f |
>| WudfPf | C:\Windows\system32\drivers\WudfPf.sys | true | 5febf87f703a843078c20a6cfeef846f |
>| WUDFRd | C:\Windows\System32\drivers\WUDFRd.sys | true | 88dd7fd6828870fe657a66da0766bc1d |
>| WUDFRd | C:\Windows\system32\drivers\WudfRd.sys | true | 88dd7fd6828870fe657a66da0766bc1d |


### harfanglab-result-processlist
***
Get a hostname's list of processes from job results


#### Base Command

`harfanglab-result-processlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Process.data | unknown | Provides a list of processes | 

#### Command example
```!harfanglab-result-processlist job_id="db793a9d-6d86-4fbf-8ee5-8836f04e14ff"```
#### Context Example
```json
{
    "Harfanglab": {
        "Process": {
            "data": [
                {
                    "cmdline": "AggregatorHost.exe",
                    "fullpath": "C:\\Windows\\System32\\AggregatorHost.exe",
                    "integrity": "System",
                    "md5": "391ed483154f77cfdad1e2e0f9ce2001",
                    "name": "AggregatorHost.exe",
                    "pid": 2588,
                    "ppid": 1428,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "\\??\\C:\\Windows\\system32\\conhost.exe 0x4",
                    "fullpath": "C:\\Windows\\System32\\conhost.exe",
                    "integrity": "System",
                    "md5": "b03d74d481d9d64047625bec2d64a0ce",
                    "name": "conhost.exe",
                    "pid": 4812,
                    "ppid": 4800,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
                    "fullpath": "C:\\Windows\\System32\\csrss.exe",
                    "integrity": "Unknown",
                    "md5": "a6c9ee45bff7c5e696b07ec41af84541",
                    "name": "csrss.exe",
                    "pid": 436,
                    "ppid": 428,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
                    "fullpath": "C:\\Windows\\System32\\csrss.exe",
                    "integrity": "Unknown",
                    "md5": "a6c9ee45bff7c5e696b07ec41af84541",
                    "name": "csrss.exe",
                    "pid": 512,
                    "ppid": 496,
                    "session": 1,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16",
                    "fullpath": "C:\\Windows\\System32\\csrss.exe",
                    "integrity": "Unknown",
                    "md5": "a6c9ee45bff7c5e696b07ec41af84541",
                    "name": "csrss.exe",
                    "pid": 4648,
                    "ppid": 3972,
                    "session": 3,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "ctfmon.exe",
                    "fullpath": "C:\\Windows\\System32\\ctfmon.exe",
                    "integrity": "High",
                    "md5": "91e5e0722b281024e60d5768ab948794",
                    "name": "ctfmon.exe",
                    "pid": 3220,
                    "ppid": 772,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}",
                    "fullpath": "C:\\Windows\\System32\\dllhost.exe",
                    "integrity": "High",
                    "md5": "61b7ccf84d2b4251bd263e75cd103f89",
                    "name": "dllhost.exe",
                    "pid": 268,
                    "ppid": 752,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "dwm.exe",
                    "fullpath": "C:\\Windows\\System32\\dwm.exe",
                    "integrity": "System",
                    "md5": "66f552d20dcf3377279c20a119e0e72f",
                    "name": "dwm.exe",
                    "pid": 948,
                    "ppid": 588,
                    "session": 1,
                    "signed": true,
                    "username": "Window Manager\\DWM-1"
                },
                {
                    "cmdline": "dwm.exe",
                    "fullpath": "C:\\Windows\\System32\\dwm.exe",
                    "integrity": "System",
                    "md5": "66f552d20dcf3377279c20a119e0e72f",
                    "name": "dwm.exe",
                    "pid": 4740,
                    "ppid": 1592,
                    "session": 3,
                    "signed": true,
                    "username": "Window Manager\\DWM-3"
                },
                {
                    "cmdline": "C:\\Windows\\Explorer.EXE",
                    "fullpath": "C:\\Windows\\explorer.exe",
                    "integrity": "High",
                    "md5": "7761d5917fa1adc297a5ce0cf1e242eb",
                    "name": "explorer.exe",
                    "pid": 616,
                    "ppid": 3940,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "fontdrvhost.exe",
                    "fullpath": "C:\\Windows\\System32\\fontdrvhost.exe",
                    "integrity": "Low",
                    "md5": "dd24bac3913d47f9b35a8718aeed3cbe",
                    "name": "fontdrvhost.exe",
                    "pid": 776,
                    "ppid": 588,
                    "session": 1,
                    "signed": true,
                    "username": "Font Driver Host\\UMFD-1"
                },
                {
                    "cmdline": "fontdrvhost.exe",
                    "fullpath": "C:\\Windows\\System32\\fontdrvhost.exe",
                    "integrity": "Low",
                    "md5": "dd24bac3913d47f9b35a8718aeed3cbe",
                    "name": "fontdrvhost.exe",
                    "pid": 780,
                    "ppid": 504,
                    "session": 0,
                    "signed": true,
                    "username": "Font Driver Host\\UMFD-0"
                },
                {
                    "cmdline": "fontdrvhost.exe",
                    "fullpath": "C:\\Windows\\System32\\fontdrvhost.exe",
                    "integrity": "Low",
                    "md5": "dd24bac3913d47f9b35a8718aeed3cbe",
                    "name": "fontdrvhost.exe",
                    "pid": 1580,
                    "ppid": 1592,
                    "session": 3,
                    "signed": true,
                    "username": "Font Driver Host\\UMFD-3"
                },
                {
                    "cmdline": "C:\\Program Files\\HarfangLab\\hurukai.exe {1c38b8b3-2cb1-1ea6-5f44-6c2c93ab812c}",
                    "fullpath": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "integrity": "System",
                    "md5": "05049f1cadb8af2b6893e1ead33351c9",
                    "name": "hurukai.exe",
                    "pid": 4800,
                    "ppid": 1560,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "fullpath": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "integrity": "System",
                    "md5": "05049f1cadb8af2b6893e1ead33351c9",
                    "name": "hurukai.exe",
                    "pid": 1560,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "LogonUI.exe /flags:0x0 /state0:0xa14bc855 /state1:0x41c64e6d",
                    "fullpath": "C:\\Windows\\System32\\LogonUI.exe",
                    "integrity": "System",
                    "md5": "6cd47ca4515b2f81b5ca1e6ca9a323cc",
                    "name": "LogonUI.exe",
                    "pid": 4368,
                    "ppid": 588,
                    "session": 1,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "LogonUI.exe /flags:0x2 /state0:0xa14fa855 /state1:0x41c64e6d",
                    "fullpath": "C:\\Windows\\System32\\LogonUI.exe",
                    "integrity": "System",
                    "md5": "6cd47ca4515b2f81b5ca1e6ca9a323cc",
                    "name": "LogonUI.exe",
                    "pid": 2968,
                    "ppid": 1592,
                    "session": 3,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\lsass.exe",
                    "fullpath": "C:\\Windows\\System32\\lsass.exe",
                    "integrity": "System",
                    "md5": "6da2fcc580c720c16612057e83f47f04",
                    "name": "lsass.exe",
                    "pid": 644,
                    "ppid": 504,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\msdtc.exe",
                    "fullpath": "C:\\Windows\\System32\\msdtc.exe",
                    "integrity": "System",
                    "md5": "bd7be47340ba4888b9b47ad323ff51d3",
                    "name": "msdtc.exe",
                    "pid": 3516,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "cmdline": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\MsMpEng.exe",
                    "fullpath": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2205.7-0\\MsMpEng.exe",
                    "integrity": "Unknown",
                    "md5": "a7dca32f82ec2569865f447416a7cf1a",
                    "name": "MsMpEng.exe",
                    "pid": 2104,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "rdpclip",
                    "fullpath": "C:\\Windows\\System32\\rdpclip.exe",
                    "integrity": "High",
                    "md5": "ab8027b4bc3a3cd5b25070b08274fbed",
                    "name": "rdpclip.exe",
                    "pid": 4888,
                    "ppid": 392,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\regedit.exe",
                    "fullpath": "C:\\Windows\\regedit.exe",
                    "integrity": "High",
                    "md5": "fea68fb10d62cbadf484dc1d2f44ed11",
                    "name": "regedit.exe",
                    "pid": 4160,
                    "ppid": 616,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "",
                    "fullpath": "",
                    "integrity": "Unknown",
                    "md5": null,
                    "name": "Registry",
                    "pid": 100,
                    "ppid": 4,
                    "session": 0,
                    "signed": false,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
                    "fullpath": "C:\\Windows\\System32\\RuntimeBroker.exe",
                    "integrity": "High",
                    "md5": "1541969ef9db9aae4e89b749d427cdea",
                    "name": "RuntimeBroker.exe",
                    "pid": 1280,
                    "ppid": 752,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
                    "fullpath": "C:\\Windows\\System32\\RuntimeBroker.exe",
                    "integrity": "High",
                    "md5": "1541969ef9db9aae4e89b749d427cdea",
                    "name": "RuntimeBroker.exe",
                    "pid": 2712,
                    "ppid": 752,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
                    "fullpath": "C:\\Windows\\System32\\RuntimeBroker.exe",
                    "integrity": "High",
                    "md5": "1541969ef9db9aae4e89b749d427cdea",
                    "name": "RuntimeBroker.exe",
                    "pid": 3288,
                    "ppid": 752,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca",
                    "fullpath": "C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe",
                    "integrity": "Low",
                    "md5": "efde01e2986731e39c1c2e0f5a1dbd06",
                    "name": "SearchApp.exe",
                    "pid": 2548,
                    "ppid": 752,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\services.exe",
                    "fullpath": "C:\\Windows\\System32\\services.exe",
                    "integrity": "Unknown",
                    "md5": "042c0e965c5db03dbf911e4c6a319ce8",
                    "name": "services.exe",
                    "pid": 632,
                    "ppid": 504,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "sihost.exe",
                    "fullpath": "C:\\Windows\\System32\\sihost.exe",
                    "integrity": "High",
                    "md5": "45cfb07366fe59573369e66029b12cea",
                    "name": "sihost.exe",
                    "pid": 1272,
                    "ppid": 1320,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "\\SystemRoot\\System32\\smss.exe",
                    "fullpath": "C:\\Windows\\System32\\smss.exe",
                    "integrity": "Unknown",
                    "md5": "44962fd12f0d29b0713bb5e14653194a",
                    "name": "smss.exe",
                    "pid": 340,
                    "ppid": 4,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\spoolsv.exe",
                    "fullpath": "C:\\Windows\\System32\\spoolsv.exe",
                    "integrity": "System",
                    "md5": "55bb3facc6ef795f6f1d8cc656bcb779",
                    "name": "spoolsv.exe",
                    "pid": 1044,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Program Files\\OpenSSH-Win64\\sshd.exe",
                    "fullpath": "C:\\Program Files\\OpenSSH-Win64\\sshd.exe",
                    "integrity": "System",
                    "md5": "331ba0e529810ef718dd3efbd1242302",
                    "name": "sshd.exe",
                    "pid": 1520,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca",
                    "fullpath": "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe",
                    "integrity": "Low",
                    "md5": "c6b9db31748cf4bf854639dd55d6f45b",
                    "name": "StartMenuExperienceHost.exe",
                    "pid": 3664,
                    "ppid": 752,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\svchost.exe -k termsvcs",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 392,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetwork -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 516,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "High",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 600,
                    "ppid": 632,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 708,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 1320,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 752,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 772,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k RPCSS -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 860,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k wusvcs -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "Unknown",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 3976,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k ClipboardSvcGroup -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "High",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 4052,
                    "ppid": 632,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\svchost.exe -k utcsvc -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 1428,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k LocalService -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 1140,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\svchost.exe -k NetworkService -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 1436,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 1496,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 1608,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetworkFirewall -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 1676,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\svchost.exe -k smbsvcs",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 2060,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k LocalService",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 2088,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k appmodel -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 2208,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\svchost.exe -k NetworkServiceNetworkRestricted -p",
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "integrity": "System",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "name": "svchost.exe",
                    "pid": 2720,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "cmdline": "",
                    "fullpath": "",
                    "integrity": "System",
                    "md5": null,
                    "name": "System",
                    "pid": 4,
                    "ppid": 0,
                    "session": 0,
                    "signed": false,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "",
                    "fullpath": "",
                    "integrity": "System",
                    "md5": null,
                    "name": "System Idle Process",
                    "pid": 0,
                    "ppid": 0,
                    "session": 0,
                    "signed": false,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}",
                    "fullpath": "C:\\Windows\\System32\\taskhostw.exe",
                    "integrity": "High",
                    "md5": "5487316514f4ada7e6e0bd9eaa2256e7",
                    "name": "taskhostw.exe",
                    "pid": 1708,
                    "ppid": 1320,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe -ServerName:InputApp.AppXjd5de1g66v206tj52m9d0dtpppx4cgpn.mca",
                    "fullpath": "C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe",
                    "integrity": "Low",
                    "md5": "44028011959b9998f95be738a3389efb",
                    "name": "TextInputHost.exe",
                    "pid": 1864,
                    "ppid": 752,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\VBoxService.exe",
                    "fullpath": "C:\\Windows\\System32\\VBoxService.exe",
                    "integrity": "System",
                    "md5": "5ac35aca951acd0732752095bbc366be",
                    "name": "VBoxService.exe",
                    "pid": 1352,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\System32\\VBoxTray.exe",
                    "fullpath": "C:\\Windows\\System32\\VBoxTray.exe",
                    "integrity": "High",
                    "md5": "3c21ed6871650bc8635729b9abbb6f21",
                    "name": "VBoxTray.exe",
                    "pid": 4240,
                    "ppid": 616,
                    "session": 1,
                    "signed": true,
                    "username": "DC-01\\vagrant"
                },
                {
                    "cmdline": "wininit.exe",
                    "fullpath": "C:\\Windows\\System32\\wininit.exe",
                    "integrity": "Unknown",
                    "md5": "e7bbde1ff6b1c3c883771e145fb6c396",
                    "name": "wininit.exe",
                    "pid": 504,
                    "ppid": 428,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "winlogon.exe",
                    "fullpath": "C:\\Windows\\System32\\winlogon.exe",
                    "integrity": "System",
                    "md5": "aef3170240ef485d6bff04ac9d210906",
                    "name": "winlogon.exe",
                    "pid": 588,
                    "ppid": 496,
                    "session": 1,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "winlogon.exe",
                    "fullpath": "C:\\Windows\\System32\\winlogon.exe",
                    "integrity": "System",
                    "md5": "aef3170240ef485d6bff04ac9d210906",
                    "name": "winlogon.exe",
                    "pid": 1592,
                    "ppid": 3972,
                    "session": 3,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "cmdline": "C:\\Windows\\system32\\wlms\\wlms.exe",
                    "fullpath": "C:\\Windows\\System32\\wlms\\wlms.exe",
                    "integrity": "System",
                    "md5": "e723cfc8e88f9eb378f1043aaf3df92e",
                    "name": "wlms.exe",
                    "pid": 2140,
                    "ppid": 632,
                    "session": 0,
                    "signed": true,
                    "username": "NT AUTHORITY\\SYSTEM"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Process List
>|name|session|username|integrity|pid|ppid|cmdline|fullpath|signed|md5|
>|---|---|---|---|---|---|---|---|---|---|
>| AggregatorHost.exe | 0 | NT AUTHORITY\SYSTEM | System | 2588 | 1428 | AggregatorHost.exe | C:\Windows\System32\AggregatorHost.exe | true | 391ed483154f77cfdad1e2e0f9ce2001 |
>| conhost.exe | 0 | NT AUTHORITY\SYSTEM | System | 4812 | 4800 | \??\C:\Windows\system32\conhost.exe 0x4 | C:\Windows\System32\conhost.exe | true | b03d74d481d9d64047625bec2d64a0ce |
>| csrss.exe | 0 | NT AUTHORITY\SYSTEM | Unknown | 436 | 428 | %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16 | C:\Windows\System32\csrss.exe | true | a6c9ee45bff7c5e696b07ec41af84541 |
>| csrss.exe | 1 | NT AUTHORITY\SYSTEM | Unknown | 512 | 496 | %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16 | C:\Windows\System32\csrss.exe | true | a6c9ee45bff7c5e696b07ec41af84541 |
>| csrss.exe | 3 | NT AUTHORITY\SYSTEM | Unknown | 4648 | 3972 | %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16 | C:\Windows\System32\csrss.exe | true | a6c9ee45bff7c5e696b07ec41af84541 |
>| ctfmon.exe | 1 | DC-01\vagrant | High | 3220 | 772 | ctfmon.exe | C:\Windows\System32\ctfmon.exe | true | 91e5e0722b281024e60d5768ab948794 |
>| dllhost.exe | 1 | DC-01\vagrant | High | 268 | 752 | C:\Windows\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F} | C:\Windows\System32\dllhost.exe | true | 61b7ccf84d2b4251bd263e75cd103f89 |
>| dwm.exe | 1 | Window Manager\DWM-1 | System | 948 | 588 | dwm.exe | C:\Windows\System32\dwm.exe | true | 66f552d20dcf3377279c20a119e0e72f |
>| dwm.exe | 3 | Window Manager\DWM-3 | System | 4740 | 1592 | dwm.exe | C:\Windows\System32\dwm.exe | true | 66f552d20dcf3377279c20a119e0e72f |
>| explorer.exe | 1 | DC-01\vagrant | High | 616 | 3940 | C:\Windows\Explorer.EXE | C:\Windows\explorer.exe | true | 7761d5917fa1adc297a5ce0cf1e242eb |
>| fontdrvhost.exe | 1 | Font Driver Host\UMFD-1 | Low | 776 | 588 | fontdrvhost.exe | C:\Windows\System32\fontdrvhost.exe | true | dd24bac3913d47f9b35a8718aeed3cbe |
>| fontdrvhost.exe | 0 | Font Driver Host\UMFD-0 | Low | 780 | 504 | fontdrvhost.exe | C:\Windows\System32\fontdrvhost.exe | true | dd24bac3913d47f9b35a8718aeed3cbe |
>| fontdrvhost.exe | 3 | Font Driver Host\UMFD-3 | Low | 1580 | 1592 | fontdrvhost.exe | C:\Windows\System32\fontdrvhost.exe | true | dd24bac3913d47f9b35a8718aeed3cbe |
>| hurukai.exe | 0 | NT AUTHORITY\SYSTEM | System | 4800 | 1560 | C:\Program Files\HarfangLab\hurukai.exe {1c38b8b3-2cb1-1ea6-5f44-6c2c93ab812c} | C:\Program Files\HarfangLab\hurukai.exe | true | 05049f1cadb8af2b6893e1ead33351c9 |
>| hurukai.exe | 0 | NT AUTHORITY\SYSTEM | System | 1560 | 632 | C:\Program Files\HarfangLab\hurukai.exe | C:\Program Files\HarfangLab\hurukai.exe | true | 05049f1cadb8af2b6893e1ead33351c9 |
>| LogonUI.exe | 1 | NT AUTHORITY\SYSTEM | System | 4368 | 588 | LogonUI.exe /flags:0x0 /state0:0xa14bc855 /state1:0x41c64e6d | C:\Windows\System32\LogonUI.exe | true | 6cd47ca4515b2f81b5ca1e6ca9a323cc |
>| LogonUI.exe | 3 | NT AUTHORITY\SYSTEM | System | 2968 | 1592 | LogonUI.exe /flags:0x2 /state0:0xa14fa855 /state1:0x41c64e6d | C:\Windows\System32\LogonUI.exe | true | 6cd47ca4515b2f81b5ca1e6ca9a323cc |
>| lsass.exe | 0 | NT AUTHORITY\SYSTEM | System | 644 | 504 | C:\Windows\system32\lsass.exe | C:\Windows\System32\lsass.exe | true | 6da2fcc580c720c16612057e83f47f04 |
>| msdtc.exe | 0 | NT AUTHORITY\NETWORK SERVICE | System | 3516 | 632 | C:\Windows\System32\msdtc.exe | C:\Windows\System32\msdtc.exe | true | bd7be47340ba4888b9b47ad323ff51d3 |
>| MsMpEng.exe | 0 | NT AUTHORITY\SYSTEM | Unknown | 2104 | 632 | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2205.7-0\MsMpEng.exe | C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2205.7-0\MsMpEng.exe | true | a7dca32f82ec2569865f447416a7cf1a |
>| rdpclip.exe | 1 | DC-01\vagrant | High | 4888 | 392 | rdpclip | C:\Windows\System32\rdpclip.exe | true | ab8027b4bc3a3cd5b25070b08274fbed |
>| regedit.exe | 1 | DC-01\vagrant | High | 4160 | 616 | C:\Windows\regedit.exe | C:\Windows\regedit.exe | true | fea68fb10d62cbadf484dc1d2f44ed11 |
>| Registry | 0 | NT AUTHORITY\SYSTEM | Unknown | 100 | 4 |  |  | false |  |
>| RuntimeBroker.exe | 1 | DC-01\vagrant | High | 1280 | 752 | C:\Windows\System32\RuntimeBroker.exe -Embedding | C:\Windows\System32\RuntimeBroker.exe | true | 1541969ef9db9aae4e89b749d427cdea |
>| RuntimeBroker.exe | 1 | DC-01\vagrant | High | 2712 | 752 | C:\Windows\System32\RuntimeBroker.exe -Embedding | C:\Windows\System32\RuntimeBroker.exe | true | 1541969ef9db9aae4e89b749d427cdea |
>| RuntimeBroker.exe | 1 | DC-01\vagrant | High | 3288 | 752 | C:\Windows\System32\RuntimeBroker.exe -Embedding | C:\Windows\System32\RuntimeBroker.exe | true | 1541969ef9db9aae4e89b749d427cdea |
>| SearchApp.exe | 1 | DC-01\vagrant | Low | 2548 | 752 | C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca | C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe | true | efde01e2986731e39c1c2e0f5a1dbd06 |
>| services.exe | 0 | NT AUTHORITY\SYSTEM | Unknown | 632 | 504 | C:\Windows\system32\services.exe | C:\Windows\System32\services.exe | true | 042c0e965c5db03dbf911e4c6a319ce8 |
>| sihost.exe | 1 | DC-01\vagrant | High | 1272 | 1320 | sihost.exe | C:\Windows\System32\sihost.exe | true | 45cfb07366fe59573369e66029b12cea |
>| smss.exe | 0 | NT AUTHORITY\SYSTEM | Unknown | 340 | 4 | \SystemRoot\System32\smss.exe | C:\Windows\System32\smss.exe | true | 44962fd12f0d29b0713bb5e14653194a |
>| spoolsv.exe | 0 | NT AUTHORITY\SYSTEM | System | 1044 | 632 | C:\Windows\System32\spoolsv.exe | C:\Windows\System32\spoolsv.exe | true | 55bb3facc6ef795f6f1d8cc656bcb779 |
>| sshd.exe | 0 | NT AUTHORITY\SYSTEM | System | 1520 | 632 | C:\Program Files\OpenSSH-Win64\sshd.exe | C:\Program Files\OpenSSH-Win64\sshd.exe | true | 331ba0e529810ef718dd3efbd1242302 |
>| StartMenuExperienceHost.exe | 1 | DC-01\vagrant | Low | 3664 | 752 | C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca | C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe | true | c6b9db31748cf4bf854639dd55d6f45b |
>| svchost.exe | 0 | NT AUTHORITY\NETWORK SERVICE | System | 392 | 632 | C:\Windows\System32\svchost.exe -k termsvcs | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\LOCAL SERVICE | System | 516 | 632 | C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 1 | DC-01\vagrant | High | 600 | 632 | C:\Windows\system32\svchost.exe -k UnistackSvcGroup | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\LOCAL SERVICE | System | 708 | 632 | C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\SYSTEM | System | 1320 | 632 | C:\Windows\system32\svchost.exe -k netsvcs -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\SYSTEM | System | 752 | 632 | C:\Windows\system32\svchost.exe -k DcomLaunch -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\SYSTEM | System | 772 | 632 | C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\NETWORK SERVICE | System | 860 | 632 | C:\Windows\system32\svchost.exe -k RPCSS -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\SYSTEM | Unknown | 3976 | 632 | C:\Windows\system32\svchost.exe -k wusvcs -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 1 | DC-01\vagrant | High | 4052 | 632 | C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\SYSTEM | System | 1428 | 632 | C:\Windows\System32\svchost.exe -k utcsvc -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\LOCAL SERVICE | System | 1140 | 632 | C:\Windows\system32\svchost.exe -k LocalService -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\NETWORK SERVICE | System | 1436 | 632 | C:\Windows\System32\svchost.exe -k NetworkService -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\SYSTEM | System | 1496 | 632 | C:\Windows\system32\svchost.exe -k netsvcs | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\LOCAL SERVICE | System | 1608 | 632 | C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\LOCAL SERVICE | System | 1676 | 632 | C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\SYSTEM | System | 2060 | 632 | C:\Windows\System32\svchost.exe -k smbsvcs | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\LOCAL SERVICE | System | 2088 | 632 | C:\Windows\system32\svchost.exe -k LocalService | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\SYSTEM | System | 2208 | 632 | C:\Windows\system32\svchost.exe -k appmodel -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| svchost.exe | 0 | NT AUTHORITY\NETWORK SERVICE | System | 2720 | 632 | C:\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted -p | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| System | 0 | NT AUTHORITY\SYSTEM | System | 4 | 0 |  |  | false |  |
>| System Idle Process | 0 | NT AUTHORITY\SYSTEM | System | 0 | 0 |  |  | false |  |
>| taskhostw.exe | 1 | DC-01\vagrant | High | 1708 | 1320 | taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E} | C:\Windows\System32\taskhostw.exe | true | 5487316514f4ada7e6e0bd9eaa2256e7 |
>| TextInputHost.exe | 1 | DC-01\vagrant | Low | 1864 | 752 | C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe -ServerName:InputApp.AppXjd5de1g66v206tj52m9d0dtpppx4cgpn.mca | C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe | true | 44028011959b9998f95be738a3389efb |
>| VBoxService.exe | 0 | NT AUTHORITY\SYSTEM | System | 1352 | 632 | C:\Windows\System32\VBoxService.exe | C:\Windows\System32\VBoxService.exe | true | 5ac35aca951acd0732752095bbc366be |
>| VBoxTray.exe | 1 | DC-01\vagrant | High | 4240 | 616 | C:\Windows\System32\VBoxTray.exe | C:\Windows\System32\VBoxTray.exe | true | 3c21ed6871650bc8635729b9abbb6f21 |
>| wininit.exe | 0 | NT AUTHORITY\SYSTEM | Unknown | 504 | 428 | wininit.exe | C:\Windows\System32\wininit.exe | true | e7bbde1ff6b1c3c883771e145fb6c396 |
>| winlogon.exe | 1 | NT AUTHORITY\SYSTEM | System | 588 | 496 | winlogon.exe | C:\Windows\System32\winlogon.exe | true | aef3170240ef485d6bff04ac9d210906 |
>| winlogon.exe | 3 | NT AUTHORITY\SYSTEM | System | 1592 | 3972 | winlogon.exe | C:\Windows\System32\winlogon.exe | true | aef3170240ef485d6bff04ac9d210906 |
>| wlms.exe | 0 | NT AUTHORITY\SYSTEM | System | 2140 | 632 | C:\Windows\system32\wlms\wlms.exe | C:\Windows\System32\wlms\wlms.exe | true | e723cfc8e88f9eb378f1043aaf3df92e |


### harfanglab-result-networkconnectionlist
***
Get a hostname's network connections from job results


#### Base Command

`harfanglab-result-networkconnectionlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.NetworkConnection.data | unknown | Provides a list of active network connections | 

#### Command example
```!harfanglab-result-networkconnectionlist job_id="da31761f-003d-4abb-ab42-3d1737d75e7c"```
#### Context Example
```json
{
    "Harfanglab": {
        "NetworkConnection": {
            "data": [
                {
                    "dst_addr": "<REDACTED>",
                    "dst_port": 443,
                    "fullpath": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "md5": "05049f1cadb8af2b6893e1ead33351c9",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 55267,
                    "state": "ESTABLISHED",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\lsass.exe",
                    "md5": "6da2fcc580c720c16612057e83f47f04",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 49664,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\lsass.exe",
                    "md5": "6da2fcc580c720c16612057e83f47f04",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 49664,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\services.exe",
                    "md5": "042c0e965c5db03dbf911e4c6a319ce8",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 49669,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\services.exe",
                    "md5": "042c0e965c5db03dbf911e4c6a319ce8",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 49669,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\spoolsv.exe",
                    "md5": "55bb3facc6ef795f6f1d8cc656bcb779",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 49668,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\spoolsv.exe",
                    "md5": "55bb3facc6ef795f6f1d8cc656bcb779",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 49668,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Program Files\\OpenSSH-Win64\\sshd.exe",
                    "md5": "331ba0e529810ef718dd3efbd1242302",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 22,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Program Files\\OpenSSH-Win64\\sshd.exe",
                    "md5": "331ba0e529810ef718dd3efbd1242302",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 22,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 3389,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 3389,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 3389,
                    "state": "NONE",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 3389,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 135,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 135,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 52239,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 49667,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 49667,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 49666,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 49666,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 5355,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 5355,
                    "state": "NONE",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 5353,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 5353,
                    "state": "NONE",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 64686,
                    "state": "NONE",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 64686,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 123,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\svchost.exe",
                    "md5": "dc32aba4669eafb22fcacd5ec836a107",
                    "protocol": "UDP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 123,
                    "state": "NONE",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "TCP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 139,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "TCP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 47001,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "TCP",
                    "signed": false,
                    "src_addr": "::",
                    "src_port": 47001,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "UDP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 138,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "TCP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 139,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "UDP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 138,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "TCP",
                    "signed": false,
                    "src_addr": "::",
                    "src_port": 445,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "TCP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 5985,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "TCP",
                    "signed": false,
                    "src_addr": "::",
                    "src_port": 5985,
                    "state": "LISTEN",
                    "version": "IPv6"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "UDP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 137,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "TCP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 445,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "",
                    "md5": null,
                    "protocol": "UDP",
                    "signed": false,
                    "src_addr": "<REDACTED>",
                    "src_port": 137,
                    "state": "NONE",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\wininit.exe",
                    "md5": "e7bbde1ff6b1c3c883771e145fb6c396",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "<REDACTED>",
                    "src_port": 49665,
                    "state": "LISTEN",
                    "version": "IPv4"
                },
                {
                    "dst_addr": null,
                    "dst_port": null,
                    "fullpath": "C:\\Windows\\System32\\wininit.exe",
                    "md5": "e7bbde1ff6b1c3c883771e145fb6c396",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "::",
                    "src_port": 49665,
                    "state": "LISTEN",
                    "version": "IPv6"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Network Connection List
>|state|protocol|version|src_addr|src_port|dst_addr|dst_port|fullpath|signed|md5|
>|---|---|---|---|---|---|---|---|---|---|
>| ESTABLISHED | TCP | IPv4 | <REDACTED> | 55267 | <REDACTED> | 443 | C:\Program Files\HarfangLab\hurukai.exe | true | 05049f1cadb8af2b6893e1ead33351c9 |
>| LISTEN | TCP | IPv6 | :: | 49664 |  |  | C:\Windows\System32\lsass.exe | true | 6da2fcc580c720c16612057e83f47f04 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 49664 |  |  | C:\Windows\System32\lsass.exe | true | 6da2fcc580c720c16612057e83f47f04 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 49669 |  |  | C:\Windows\System32\services.exe | true | 042c0e965c5db03dbf911e4c6a319ce8 |
>| LISTEN | TCP | IPv6 | :: | 49669 |  |  | C:\Windows\System32\services.exe | true | 042c0e965c5db03dbf911e4c6a319ce8 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 49668 |  |  | C:\Windows\System32\spoolsv.exe | true | 55bb3facc6ef795f6f1d8cc656bcb779 |
>| LISTEN | TCP | IPv6 | :: | 49668 |  |  | C:\Windows\System32\spoolsv.exe | true | 55bb3facc6ef795f6f1d8cc656bcb779 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 22 |  |  | C:\Program Files\OpenSSH-Win64\sshd.exe | true | 331ba0e529810ef718dd3efbd1242302 |
>| LISTEN | TCP | IPv6 | :: | 22 |  |  | C:\Program Files\OpenSSH-Win64\sshd.exe | true | 331ba0e529810ef718dd3efbd1242302 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 3389 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv6 | :: | 3389 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 3389 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | <REDACTED> | 3389 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv6 | :: | 135 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 135 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | <REDACTED> | 52239 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv6 | :: | 49667 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 49667 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 49666 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv6 | :: | 49666 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | <REDACTED> | 5355 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 5355 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | <REDACTED> | 5353 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 5353 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 64686 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | <REDACTED> | 64686 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | <REDACTED> | 123 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 123 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv4 | <REDACTED> | 139 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | <REDACTED> | 47001 |  |  |  | false |  |
>| LISTEN | TCP | IPv6 | :: | 47001 |  |  |  | false |  |
>| NONE | UDP | IPv4 | <REDACTED> | 138 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | <REDACTED> | 139 |  |  |  | false |  |
>| NONE | UDP | IPv4 | <REDACTED> | 138 |  |  |  | false |  |
>| LISTEN | TCP | IPv6 | :: | 445 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | <REDACTED> | 5985 |  |  |  | false |  |
>| LISTEN | TCP | IPv6 | :: | 5985 |  |  |  | false |  |
>| NONE | UDP | IPv4 | <REDACTED> | 137 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | <REDACTED> | 445 |  |  |  | false |  |
>| NONE | UDP | IPv4 | <REDACTED> | 137 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | <REDACTED> | 49665 |  |  | C:\Windows\System32\wininit.exe | true | e7bbde1ff6b1c3c883771e145fb6c396 |
>| LISTEN | TCP | IPv6 | :: | 49665 |  |  | C:\Windows\System32\wininit.exe | true | e7bbde1ff6b1c3c883771e145fb6c396 |


### harfanglab-result-networksharelist
***
Get a hostname's network shares from job results


#### Base Command

`harfanglab-result-networksharelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.NetworkShare.data | unknown | Provides a list of network shares | 

#### Command example
```!harfanglab-result-networksharelist job_id="3ec3821f-278b-4cf1-8fb8-11f4a1c431d5"```
#### Context Example
```json
{
    "Harfanglab": {
        "NetworkShare": {
            "data": [
                {
                    "Caption": "Remote Admin",
                    "Description": "Remote Admin",
                    "Hostname": "DC-01",
                    "Name": "ADMIN$",
                    "Path": "C:\\Windows",
                    "Share type": "Disk Drive Admin",
                    "Share type val": 2147483648,
                    "Status": "OK"
                },
                {
                    "Caption": "Default share",
                    "Description": "Default share",
                    "Hostname": "DC-01",
                    "Name": "C$",
                    "Path": "C:\\",
                    "Share type": "Disk Drive Admin",
                    "Share type val": 2147483648,
                    "Status": "OK"
                },
                {
                    "Caption": "Remote IPC",
                    "Description": "Remote IPC",
                    "Hostname": "DC-01",
                    "Name": "IPC$",
                    "Path": "",
                    "Share type": "IPC Admin",
                    "Share type val": 2147483651,
                    "Status": "OK"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Network Share List
>|Name|Caption|Description|Path|Status|Share type val|Share type|Hostname|
>|---|---|---|---|---|---|---|---|
>| ADMIN$ | Remote Admin | Remote Admin | C:\Windows | OK | 2147483648 | Disk Drive Admin | DC-01 |
>| C$ | Default share | Default share | C:\ | OK | 2147483648 | Disk Drive Admin | DC-01 |
>| IPC$ | Remote IPC | Remote IPC |  | OK | 2147483651 | IPC Admin | DC-01 |


### harfanglab-result-sessionlist
***
Get a hostname's sessions from job results


#### Base Command

`harfanglab-result-sessionlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Session.data | unknown | Provides a list of active sessions | 

#### Command example
```!harfanglab-result-sessionlist job_id="01819f9a-44f5-42b6-9e1a-4efc3fadd48d"```
#### Context Example
```json
{
    "Harfanglab": {
        "Session": {
            "data": [
                {
                    "Authentication package": "NTLM",
                    "Hostname": "DC-01",
                    "Logon Id": 999,
                    "Logon type": 0,
                    "Logon type str": "System",
                    "Session start time": "2022-06-28T14:18:30.944000Z"
                },
                {
                    "Authentication package": "Negotiate",
                    "Hostname": "DC-01",
                    "Logon Id": 997,
                    "Logon type": 5,
                    "Logon type str": "Service",
                    "Session start time": "2022-06-28T14:18:31.992000Z"
                },
                {
                    "Authentication package": "NTLM",
                    "Hostname": "DC-01",
                    "Logon Id": 356056507,
                    "Logon type": 2,
                    "Logon type str": "Interactive",
                    "Session start time": "2022-07-22T16:08:46.373000Z"
                },
                {
                    "Authentication package": "NTLM",
                    "Hostname": "DC-01",
                    "Logon Id": 272595,
                    "Logon type": 3,
                    "Logon type str": "Network",
                    "Session start time": "2022-06-28T14:19:19.447000Z"
                },
                {
                    "Authentication package": "Negotiate",
                    "Hostname": "DC-01",
                    "Logon Id": 996,
                    "Logon type": 5,
                    "Logon type str": "Service",
                    "Session start time": "2022-06-28T14:18:31.507000Z"
                },
                {
                    "Authentication package": "NTLM",
                    "Hostname": "DC-01",
                    "Logon Id": 232421,
                    "Logon type": 3,
                    "Logon type str": "Network",
                    "Session start time": "2022-06-28T14:18:54.600000Z"
                },
                {
                    "Authentication package": "NTLM",
                    "Hostname": "DC-01",
                    "Logon Id": 121005166,
                    "Logon type": 3,
                    "Logon type str": "Network",
                    "Session start time": "2022-07-06T19:36:41.698000Z"
                },
                {
                    "Authentication package": "Negotiate",
                    "Hostname": "DC-01",
                    "Logon Id": 370611950,
                    "Logon type": 2,
                    "Logon type str": "Interactive",
                    "Session start time": "2022-07-23T06:15:19.172000Z"
                },
                {
                    "Authentication package": "Negotiate",
                    "Hostname": "DC-01",
                    "Logon Id": 370621180,
                    "Logon type": 2,
                    "Logon type str": "Interactive",
                    "Session start time": "2022-07-23T06:15:19.391000Z"
                },
                {
                    "Authentication package": "NTLM",
                    "Hostname": "DC-01",
                    "Logon Id": 188264,
                    "Logon type": 3,
                    "Logon type str": "Network",
                    "Session start time": "2022-06-28T14:18:44.527000Z"
                },
                {
                    "Authentication package": "Negotiate",
                    "Hostname": "DC-01",
                    "Logon Id": 24600,
                    "Logon type": 2,
                    "Logon type str": "Interactive",
                    "Session start time": "2022-06-28T14:18:31.273000Z"
                },
                {
                    "Authentication package": "Negotiate",
                    "Hostname": "DC-01",
                    "Logon Id": 24615,
                    "Logon type": 2,
                    "Logon type str": "Interactive",
                    "Session start time": "2022-06-28T14:18:31.273000Z"
                },
                {
                    "Authentication package": "Negotiate",
                    "Hostname": "DC-01",
                    "Logon Id": 42936,
                    "Logon type": 2,
                    "Logon type str": "Interactive",
                    "Session start time": "2022-06-28T14:18:31.789000Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Session List
>|Logon Id|Authentication package|Logon type|Logon type str|Session start time|Hostname|
>|---|---|---|---|---|---|
>| 999 | NTLM | 0 | System | 2022-06-28T14:18:30.944000Z | DC-01 |
>| 997 | Negotiate | 5 | Service | 2022-06-28T14:18:31.992000Z | DC-01 |
>| 356056507 | NTLM | 2 | Interactive | 2022-07-22T16:08:46.373000Z | DC-01 |
>| 272595 | NTLM | 3 | Network | 2022-06-28T14:19:19.447000Z | DC-01 |
>| 996 | Negotiate | 5 | Service | 2022-06-28T14:18:31.507000Z | DC-01 |
>| 232421 | NTLM | 3 | Network | 2022-06-28T14:18:54.600000Z | DC-01 |
>| 121005166 | NTLM | 3 | Network | 2022-07-06T19:36:41.698000Z | DC-01 |
>| 370611950 | Negotiate | 2 | Interactive | 2022-07-23T06:15:19.172000Z | DC-01 |
>| 370621180 | Negotiate | 2 | Interactive | 2022-07-23T06:15:19.391000Z | DC-01 |
>| 188264 | NTLM | 3 | Network | 2022-06-28T14:18:44.527000Z | DC-01 |
>| 24600 | Negotiate | 2 | Interactive | 2022-06-28T14:18:31.273000Z | DC-01 |
>| 24615 | Negotiate | 2 | Interactive | 2022-06-28T14:18:31.273000Z | DC-01 |
>| 42936 | Negotiate | 2 | Interactive | 2022-06-28T14:18:31.789000Z | DC-01 |


### harfanglab-result-persistencelist
***
Get a hostname's persistence items from job results


#### Base Command

`harfanglab-result-persistencelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.PersistenceList.data | unknown | Provides a list of persistence means | 

#### Command example
```!harfanglab-result-persistencelist job_id="8ee99c61-9c0e-4cfb-89ea-4aba01cbf1ed"```
#### Context Example
```json
{
    "Harfanglab": {
        "Persistence": {
            "data": []
        }
    }
}
```

#### Human Readable Output

>### Linux persistence list
>**No entries.**


### harfanglab-result-ioc
***
Get the list of items matching IOCs searched in an IOC job


#### Base Command

`harfanglab-result-ioc`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.IOC.data | unknown | Provides a list of matching elements | 

#### Command example
```!harfanglab-result-ioc job_id="1680a62a-7a9c-456d-ae89-75788daa94e8"```
#### Context Example
```json
{
    "Harfanglab": {
        "IOC": {
            "data": [
                {
                    "fullpath": "C:\\Program Files\\HarfangLab\\agent.ini",
                    "md5": "f43c1ddce185d649e61deb4f3dfcf7c8",
                    "registry_key": null,
                    "registry_path": null,
                    "registry_value": null,
                    "search_value": "agent.ini",
                    "signed": false,
                    "type": "filename"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### IOC Found List
>|type|search_value|fullpath|signed|md5|
>|---|---|---|---|---|
>| filename | agent.ini | C:\Program Files\HarfangLab\agent.ini | false | f43c1ddce185d649e61deb4f3dfcf7c8 |


### harfanglab-result-startuplist
***
Get a hostname's startup items from job results


#### Base Command

`harfanglab-result-startuplist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Startup.data | unknown | Provides a list of startup files | 

#### Command example
```!harfanglab-result-startuplist job_id="f1fac880-ade0-44c3-837f-486517565909"```
#### Context Example
```json
{
    "Harfanglab": {
        "Startup": {
            "data": []
        }
    }
}
```

#### Human Readable Output

>### Startup List
>**No entries.**


### harfanglab-result-wmilist
***
Get a hostname's WMI items from job results


#### Base Command

`harfanglab-result-wmilist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Wmi.data | unknown | Provides a list of WMI items | 

#### Command example
```!harfanglab-result-wmilist job_id="5219bfca-4a8b-4913-813f-446d88e28d99"```
#### Context Example
```json
{
    "Harfanglab": {
        "Wmi": {
            "data": []
        }
    }
}
```

#### Human Readable Output

>### WMI List
>**No entries.**


### harfanglab-result-artifact-mft
***
Get a hostname's MFT from job results


#### Base Command

`harfanglab-result-artifact-mft`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the raw MFT | 

#### Command example
```!harfanglab-result-artifact-mft job_id="10fae902-ddb0-48b8-bbd9-aa94e92f9222"```
#### Context Example
```json
{
    "Harfanglab": {
        "Artifact": {
            "MFT": [
                {
                    "@timestamp": "2022-07-25T08:27:57.309000Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "0fae71cf-ebde-4533-a50c-b3c0290378db",
                        "domainname": "WORKGROUP",
                        "hostname": "DC-01",
                        "osproducttype": "Windows Server 2022 Standard Evaluation",
                        "ostype": "windows",
                        "osversion": "10.0.20348",
                        "version": "2.15.0"
                    },
                    "artefact_type": "raw evidences",
                    "date": "2022-07-25T08:20:39.253407Z",
                    "download_link": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/uDV4NIIB3S3Gj-GSVFRk/download/?hl_expiring_key=81eeb2cdd8ba9e720105e4067b9c39e0c3a47a05",
                    "download_status": 0,
                    "id": "uDV4NIIB3S3Gj-GSVFRk",
                    "item_status": 0,
                    "job_id": "10fae902-ddb0-48b8-bbd9-aa94e92f9222",
                    "job_instance_id": "6862bf05-7694-459b-9b29-e68214ddd45e",
                    "log_type": "investigation",
                    "msg": "got 0 hives, 1 mft, 0 USN, 0 prefetch, 0 logs files",
                    "size": 206045184,
                    "tenant": ""
                }
            ],
            "data": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/uDV4NIIB3S3Gj-GSVFRk/download/?hl_expiring_key=81eeb2cdd8ba9e720105e4067b9c39e0c3a47a05"
        }
    }
}
```

#### Human Readable Output

>### MFT download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 0 hives, 1 mft, 0 USN, 0 prefetch, 0 logs files | 206045184 | https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/uDV4NIIB3S3Gj-GSVFRk/download/?hl_expiring_key=81eeb2cdd8ba9e720105e4067b9c39e0c3a47a05 |


### harfanglab-result-artifact-hives
***
Get a hostname's hives from job results


#### Base Command

`harfanglab-result-artifact-hives`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the raw hives | 

#### Command example
```!harfanglab-result-artifact-hives job_id="8a0b77e2-6c55-4bfb-89c5-377c2a3b6bf4"```
#### Context Example
```json
{
    "Harfanglab": {
        "Artifact": {
            "HIVES": [
                {
                    "@timestamp": "2022-07-25T08:26:01.894000Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "0fae71cf-ebde-4533-a50c-b3c0290378db",
                        "domainname": "WORKGROUP",
                        "hostname": "DC-01",
                        "osproducttype": "Windows Server 2022 Standard Evaluation",
                        "ostype": "windows",
                        "osversion": "10.0.20348",
                        "version": "2.15.0"
                    },
                    "artefact_type": "raw evidences",
                    "date": "2022-07-25T08:20:37.429526Z",
                    "download_link": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/jDV2NIIB3S3Gj-GSkVSP/download/?hl_expiring_key=f7fda5c2d43ef7498e6cb2de12d12cba0d5d77b1",
                    "download_status": 0,
                    "id": "jDV2NIIB3S3Gj-GSkVSP",
                    "item_status": 0,
                    "job_id": "8a0b77e2-6c55-4bfb-89c5-377c2a3b6bf4",
                    "job_instance_id": "94bdf98c-f4d0-4ea9-814d-807898704bb0",
                    "log_type": "investigation",
                    "msg": "got 11 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files",
                    "size": 91324416,
                    "tenant": ""
                }
            ],
            "data": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/jDV2NIIB3S3Gj-GSkVSP/download/?hl_expiring_key=f7fda5c2d43ef7498e6cb2de12d12cba0d5d77b1"
        }
    }
}
```

#### Human Readable Output

>### HIVES download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 11 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files | 91324416 | https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/jDV2NIIB3S3Gj-GSkVSP/download/?hl_expiring_key=f7fda5c2d43ef7498e6cb2de12d12cba0d5d77b1 |


### harfanglab-result-artifact-evtx
***
Get a hostname's log files from job results


#### Base Command

`harfanglab-result-artifact-evtx`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the evt/evtx files | 

#### Command example
```!harfanglab-result-artifact-evtx job_id="43f4c7bf-ed15-4b1b-8b14-d71f48ad9077"```
#### Context Example
```json
{
    "Harfanglab": {
        "Artifact": {
            "EVTX": [
                {
                    "@timestamp": "2022-07-25T08:24:15.006000Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "0fae71cf-ebde-4533-a50c-b3c0290378db",
                        "domainname": "WORKGROUP",
                        "hostname": "DC-01",
                        "osproducttype": "Windows Server 2022 Standard Evaluation",
                        "ostype": "windows",
                        "osversion": "10.0.20348",
                        "version": "2.15.0"
                    },
                    "artefact_type": "raw evidences",
                    "date": "2022-07-25T08:20:35.586738Z",
                    "download_link": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/SjV0NIIB3S3Gj-GS8FQF/download/?hl_expiring_key=ddb23c2ca021663aa98fad82c11b7c09552e1a84",
                    "download_status": 0,
                    "id": "SjV0NIIB3S3Gj-GS8FQF",
                    "item_status": 0,
                    "job_id": "43f4c7bf-ed15-4b1b-8b14-d71f48ad9077",
                    "job_instance_id": "c952971d-89ca-4b81-99f9-a5cacdff320e",
                    "log_type": "investigation",
                    "msg": "got 0 hives, 0 mft, 0 USN, 0 prefetch, 133 logs files",
                    "size": 400969728,
                    "tenant": ""
                }
            ],
            "data": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/SjV0NIIB3S3Gj-GS8FQF/download/?hl_expiring_key=ddb23c2ca021663aa98fad82c11b7c09552e1a84"
        }
    }
}
```

#### Human Readable Output

>### EVTX download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 0 hives, 0 mft, 0 USN, 0 prefetch, 133 logs files | 400969728 | https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/SjV0NIIB3S3Gj-GS8FQF/download/?hl_expiring_key=ddb23c2ca021663aa98fad82c11b7c09552e1a84 |


### harfanglab-result-artifact-logs
***
Get a hostname's log files from job results


#### Base Command

`harfanglab-result-artifact-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the log files | 

#### Command example
```!harfanglab-result-artifact-logs job_id="eb957909-57cb-4f20-ad76-dc47aab5496f"```
#### Context Example
```json
{
    "Harfanglab": {
        "Artifact": {
            "LOGS": [
                {
                    "@timestamp": "2022-07-25T08:26:43.106000Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "0fae71cf-ebde-4533-a50c-b3c0290378db",
                        "domainname": "WORKGROUP",
                        "hostname": "DC-01",
                        "osproducttype": "Windows Server 2022 Standard Evaluation",
                        "ostype": "windows",
                        "osversion": "10.0.20348",
                        "version": "2.15.0"
                    },
                    "artefact_type": "raw evidences",
                    "date": "2022-07-25T08:20:38.433613Z",
                    "download_link": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/mzV3NIIB3S3Gj-GSMlSI/download/?hl_expiring_key=ac09683af7c4008e3dd9557d7cb6c5f1a88a598e",
                    "download_status": 1,
                    "id": "mzV3NIIB3S3Gj-GSMlSI",
                    "item_status": 0,
                    "job_id": "eb957909-57cb-4f20-ad76-dc47aab5496f",
                    "job_instance_id": "c75a801d-82ab-4695-9bb3-0c4852b69e8b",
                    "log_type": "investigation",
                    "msg": "got 0 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files, 0 linux filesystem parse",
                    "size": 0,
                    "tenant": ""
                }
            ],
            "data": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/mzV3NIIB3S3Gj-GSMlSI/download/?hl_expiring_key=ac09683af7c4008e3dd9557d7cb6c5f1a88a598e"
        }
    }
}
```

#### Human Readable Output

>### LOGS download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 0 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files, 0 linux filesystem parse | 0 | https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/mzV3NIIB3S3Gj-GSMlSI/download/?hl_expiring_key=ac09683af7c4008e3dd9557d7cb6c5f1a88a598e |


### harfanglab-result-artifact-filesystem
***
Get a hostname's filesystem entries from job results


#### Base Command

`harfanglab-result-artifact-filesystem`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download the CSV file with filesystem entries | 

#### Command example
```!harfanglab-result-artifact-filesystem job_id="210b72f7-7ee5-4e89-b3fb-8106e7a57bf7"```
#### Context Example
```json
{
    "Harfanglab": {
        "Artifact": {
            "FS": [
                {
                    "@timestamp": "2022-07-25T08:24:53.428000Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "0fae71cf-ebde-4533-a50c-b3c0290378db",
                        "domainname": "WORKGROUP",
                        "hostname": "DC-01",
                        "osproducttype": "Windows Server 2022 Standard Evaluation",
                        "ostype": "windows",
                        "osversion": "10.0.20348",
                        "version": "2.15.0"
                    },
                    "artefact_type": "raw evidences",
                    "date": "2022-07-25T08:20:36.474594Z",
                    "download_link": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/ajV1NIIB3S3Gj-GShlQa/download/?hl_expiring_key=01e95b2c712d0a73e67ce1b7f4c4f518487427de",
                    "download_status": 1,
                    "id": "ajV1NIIB3S3Gj-GShlQa",
                    "item_status": 0,
                    "job_id": "210b72f7-7ee5-4e89-b3fb-8106e7a57bf7",
                    "job_instance_id": "3399ad6d-d997-4a2a-96cd-6210bc490934",
                    "log_type": "investigation",
                    "msg": "got 0 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files, 0 linux filesystem parse",
                    "size": 0,
                    "tenant": ""
                }
            ],
            "data": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/ajV1NIIB3S3Gj-GShlQa/download/?hl_expiring_key=01e95b2c712d0a73e67ce1b7f4c4f518487427de"
        }
    }
}
```

#### Human Readable Output

>### FS download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 0 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files, 0 linux filesystem parse | 0 | https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/ajV1NIIB3S3Gj-GShlQa/download/?hl_expiring_key=01e95b2c712d0a73e67ce1b7f4c4f518487427de |


### harfanglab-result-artifact-all
***
Get all artifacts from a hostname from job results


#### Base Command

`harfanglab-result-artifact-all`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Artifact.data | unknown | Provides a link to download an archive with all raw artifacts | 

#### Command example
```!harfanglab-result-artifact-all job_id="affe8871-c838-4c17-b5cb-fa30b6aeacfc"```
#### Context Example
```json
{
    "Harfanglab": {
        "Artifact": {
            "ALL": [
                {
                    "@timestamp": "2022-07-25T08:21:47.781000Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "0fae71cf-ebde-4533-a50c-b3c0290378db",
                        "domainname": "WORKGROUP",
                        "hostname": "DC-01",
                        "osproducttype": "Windows Server 2022 Standard Evaluation",
                        "ostype": "windows",
                        "osversion": "10.0.20348",
                        "version": "2.15.0"
                    },
                    "artefact_type": "raw evidences",
                    "date": "2022-07-25T08:20:33.821824Z",
                    "download_link": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/HDVyNIIB3S3Gj-GSsFTu/download/?hl_expiring_key=58c6826fb67fedc3d96fcce221afd7e4b6d86bce",
                    "download_status": 0,
                    "id": "HDVyNIIB3S3Gj-GSsFTu",
                    "item_status": 0,
                    "job_id": "affe8871-c838-4c17-b5cb-fa30b6aeacfc",
                    "job_instance_id": "c0036698-5dc0-4111-9b7e-81d56bfc588e",
                    "log_type": "investigation",
                    "msg": "got 11 hives, 1 mft, 1 USN, 0 prefetch, 133 logs files",
                    "size": 734616576,
                    "tenant": ""
                }
            ],
            "data": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/HDVyNIIB3S3Gj-GSsFTu/download/?hl_expiring_key=58c6826fb67fedc3d96fcce221afd7e4b6d86bce"
        }
    }
}
```

#### Human Readable Output

>### ALL download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 11 hives, 1 mft, 1 USN, 0 prefetch, 133 logs files | 734616576 | https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/HDVyNIIB3S3Gj-GSsFTu/download/?hl_expiring_key=58c6826fb67fedc3d96fcce221afd7e4b6d86bce |


### harfanglab-result-artifact-downloadfile
***
Get a hostname's file from job results


#### Base Command

`harfanglab-result-artifact-downloadfile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.DownloadFile.data | unknown | Provides a link to download the file | 

#### Command example
```!harfanglab-result-artifact-downloadfile job_id="aa83c9e9-91de-4f6f-b2f3-f01c936c4ee6"```
#### Context Example
```json
{
    "Harfanglab": {
        "DownloadFile": {
            "data": [
                {
                    "download link": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/MTVzNIIB3S3Gj-GSxFQ5/download/?hl_expiring_key=e8d5d588eba54d4a3936a807dc66a4cb5678ffd6",
                    "hostname": "DC-01",
                    "msg": "1 file(s) downloaded",
                    "size": 1688
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### file download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | 1 file(s) downloaded | 1688 | https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/MTVzNIIB3S3Gj-GSxFQ5/download/?hl_expiring_key=e8d5d588eba54d4a3936a807dc66a4cb5678ffd6 |


### harfanglab-result-artifact-ramdump
***
Get a hostname's RAM dump from job results


#### Base Command

`harfanglab-result-artifact-ramdump`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| job_id | Job id as returned by the job submission commands. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Ramdump.data | unknown | Provides a link to download the raw RAM dump | 

#### Command example
```!harfanglab-result-artifact-ramdump job_id="539456d8-872c-4e60-a28b-210ffcd4c7c4"```
#### Context Example
```json
{
    "Harfanglab": {
        "Ramdump": {
            "data": [
                {
                    "download link": "https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/_TV7NIIB3S3Gj-GSBVTv/download/?hl_expiring_key=74cddf3e3a4da4a2fe1e21d0805b05e7c560d30e",
                    "hostname": "DC-01",
                    "msg": "1 file(s) downloaded",
                    "size": 1080819582
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Ramdump list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | 1 file(s) downloaded | 1080819582 | https://demo-1.harfanglab.io:8443/api/data/investigation/artefact/Artefact/_TV7NIIB3S3Gj-GSBVTv/download/?hl_expiring_key=74cddf3e3a4da4a2fe1e21d0805b05e7c560d30e |


### harfanglab-hunt-search-hash
***
Command used to search a hash IOC in database


#### Base Command

`harfanglab-hunt-search-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | filehash to search (md5, sha1, sha256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Hash | unknown | Provides statistics associated to currently running processes and previously executed processes associated to hash | 

#### Command example
```!harfanglab-hunt-search-hash hash=2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3```
#### Context Example
```json
{
    "Harfanglab": {
        "Hash": {
            "curr_running": 0,
            "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
            "prev_runned": 8994
        }
    }
}
```

#### Human Readable Output

>### Hash search results
>|curr_running|hash|prev_runned|
>|---|---|---|
>| 0 | 2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3 | 8994 |


### harfanglab-hunt-search-running-process-hash
***
Command used to search running process associated with Hash


#### Base Command

`harfanglab-hunt-search-running-process-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | filehash to search (sha256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.HuntRunningProcessSearch.data | unknown | List of all systems where processes associated to hash are running | 

#### Command example
```!harfanglab-hunt-search-running-process-hash hash=2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3```
#### Context Example
```json
{
    "Harfanglab": {
        "HuntRunningProcessSearch": {
            "data": []
        }
    }
}
```

#### Human Readable Output

>### War room overview
>**No entries.**


### harfanglab-hunt-search-runned-process-hash
***
Command used to search runned process associated with Hash


#### Base Command

`harfanglab-hunt-search-runned-process-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | filehash to search (sha256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.HuntRunnedProcessSearch.data | unknown | List of all systems where processes associated to hash have been previously running | 

#### Command example
```!harfanglab-hunt-search-runned-process-hash hash=2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3```
#### Context Example
```json
{
    "Harfanglab": {
        "HuntRunnedProcessSearch": {
            "data": [
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-4812",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-4812",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-1234",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-1234",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-8501",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-8501",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-6852",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-6852",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-3752",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\LOCAL SERVICE"
                },
                {
                    "binary_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "WMI Provider Host",
                        "file_version": "10.0.19041.546 (WinBuild.160101.0800)",
                        "internal_name": "Wmiprvse.exe",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Wmiprvse.exe",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.546"
                    },
                    "create_time": "2019-10-16T23:45:21Z",
                    "domain": "WORKGROUP",
                    "hash": "2198a7b58bccb758036b969ddae6cc2ece07565e2659a7c541a313a0492231a3",
                    "hostname": "WORKSTATION-3752",
                    "os": "Windows 10 Enterprise Evaluation",
                    "os_version": "10.0.19041",
                    "path": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### War room overview
>|Hostname|Domain|Username|OS|Binary Path|Create timestamp|
>|---|---|---|---|---|---|
>| WORKSTATION-4812 | WORKGROUP | NT AUTHORITY\LOCAL SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-4812 | WORKGROUP | NT AUTHORITY\NETWORK SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-1234 | WORKGROUP | NT AUTHORITY\LOCAL SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-1234 | WORKGROUP | NT AUTHORITY\NETWORK SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-8501 | WORKGROUP | NT AUTHORITY\LOCAL SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-8501 | WORKGROUP | NT AUTHORITY\NETWORK SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-6852 | WORKGROUP | NT AUTHORITY\LOCAL SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-6852 | WORKGROUP | NT AUTHORITY\NETWORK SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-3752 | WORKGROUP | NT AUTHORITY\LOCAL SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |
>| WORKSTATION-3752 | WORKGROUP | NT AUTHORITY\NETWORK SERVICE | Windows 10 Enterprise Evaluation 10.0.19041 | C:\Windows\System32\wbem\WmiPrvSE.exe | 2019-10-16T23:45:21Z |


### harfanglab-isolate-endpoint
***
Command used to isolate an endpoint from the network while remaining connected to the EDR manager


#### Base Command

`harfanglab-isolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!harfanglab-isolate-endpoint agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Human Readable Output

>```
>{
>    "Message": "",
>    "Status": false
>}
>```

### harfanglab-deisolate-endpoint
***
Command used to deisolate an endpoint and reconnect it to the network


#### Base Command

`harfanglab-deisolate-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agent_id | Agent unique identifier as provided by the HarfangLab EDR Manager. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!harfanglab-deisolate-endpoint agent_id="0fae71cf-ebde-4533-a50c-b3c0290378db"```
#### Human Readable Output

>```
>{
>    "Message": "Agent deisolation successfully requested",
>    "Status": true
>}
>```

### harfanglab-change-security-event-status
***
Command used to change the status of a security event


#### Base Command

`harfanglab-change-security-event-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_event_id | Security event id. | Required | 
| status | New status of the security event id (New, Investigating, False Positive, Closed). | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!harfanglab-change-security-event-status security_event_id="QCzd2IEB3S3Gj-GS6z9S" status=Investigating ```
#### Human Readable Output

>```
>{
>    "Message": "Status for security event QCzd2IEB3S3Gj-GS6z9S changed to Investigating"
>}
>```

### harfanglab-assign-policy-to-agent
***
Assign a policy to an agent


#### Base Command

`harfanglab-assign-policy-to-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentid | Agent identifier. | Required | 
| policy | Policy name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!harfanglab-assign-policy-to-agent agentid=0fae71cf-ebde-4533-a50c-b3c0290378db policy="No psexec"```
#### Human Readable Output

>```
>{
>    "Message": "Policy No psexec successfully assigned to agent 0fae71cf-ebde-4533-a50c-b3c0290378db"
>}
>```

### harfanglab-add-ioc-to-source
***
Add an IOC to a Threat Intelligence source


#### Base Command

`harfanglab-add-ioc-to-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_value | IOC value. | Required | 
| ioc_type | IOC type (hash, filename, filepath). | Required | 
| ioc_comment | Comment associated to IOC. | Optional | 
| ioc_status | IOC status (stable, testing). | Required | 
| source_name | IOC Source Name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!harfanglab-add-ioc-to-source ioc_value=0004ffbd9a1a1acd44f4859c39a49639babe515434ca34bec603598b50211bab ioc_type=hash ioc_status=stable source_name="Industrial Spy"```
#### Human Readable Output

>```
>{
>    "Message": "IOC 0004ffbd9a1a1acd44f4859c39a49639babe515434ca34bec603598b50211bab of type hash added to source Industrial Spy with stable status"
>}
>```

### harfanglab-delete-ioc-from-source
***
Delete an IOC from a Threat Intelligence source


#### Base Command

`harfanglab-delete-ioc-from-source`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_value | IOC value. | Required | 
| source_name | IOC Source Name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!harfanglab-delete-ioc-from-source ioc_value=0004ffbd9a1a1acd44f4859c39a49639babe515434ca34bec603598b50211bab source_name="Industrial Spy"```
#### Human Readable Output

>```
>{
>    "Message": "IOC 0004ffbd9a1a1acd44f4859c39a49639babe515434ca34bec603598b50211bab removed from source Industrial Spy"
>}
>```
