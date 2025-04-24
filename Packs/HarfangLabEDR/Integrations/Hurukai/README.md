HarfangLab EDR Connector,
Compatible version 2.13.7+
This integration was integrated and tested with version 2.13.7+ of Hurukai

## Configure HarfangLab EDR in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| API Key |  | False |
| Incidents Fetch Interval |  | False |
| Fetch alerts with type | Comma-separated list of types of alerts to fetch \(sigma, yara, hlai, vt, ransom, ioc, glimps, orion...\). | False |
| Minimum severity of alerts to fetch |  | True |
| Fetch alerts with status (ACTIVE, CLOSED) |  | False |
| Maximum number of incidents to fetch per call | Fetch maximum &lt;max_fetch&gt; security events and/or threats per call \(leave empty if unlimited\). | False |
| First fetch time | Start fetching alerts and/or threats whose creation date is higher than now minus &lt;first_fetch&gt; days. | True |
| Mirroring Direction | Choose the direction to mirror the detection: Incoming \(from HarfangLab EDR to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to HarfangLab EDR\), or Incoming and Outgoing \(to/from HarfangLab EDR and Cortex XSOAR\). | False |
| Fetch types |  | True |
| Close Mirrored security event or threat in the XSOAR | When selected, closes the XSOAR incident, which is mirrored from the HarfangLab EDR. | False |
| Close Mirrored security event or threat in HarfangLab EDR | When selected, closes the HarfangLab EDR security event or threat in the HarfangLab EDR. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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
            "external_ipaddress": "(REDACTED)",
            "firstseen": "2022-06-15T06:42:50.008015Z",
            "group_count": 0,
            "groups": [],
            "hostname": "DC-01",
            "id": "0fae71cf-ebde-4533-a50c-b3c0290378db",
            "installdate": "2022/06/15 06:38:58",
            "ipaddress": "(REDACTED)",
            "ipmask": "(REDACTED)",
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
>| additional_info1: null<br/>additional_info2: null<br/>additional_info3: null<br/>additional_info4: null | 1.0 | 183558144.0 | x64 | 2 | 3192 | WORKGROUP | true | false | e96699ef-3dd9-4718-90ef-c7e5646fd466 | 5 | (REDACTED) | 2022-06-15T06:42:50.008015Z | 0 | DC-01 | 0fae71cf-ebde-4533-a50c-b3c0290378db | 2022/06/15 06:38:58 | (REDACTED) | (REDACTED) | false | true | 2022-07-28T07:41:32.197641Z | 2022-07-28T07:47:02.197641Z | 2022-07-28T07:43:44.197641Z | 2022-06-28T14:18:31Z | 20348 | 00454-40000-00001-AA596 | 10 | 0 | Windows Server 2022 Standard Evaluation | windows | 10.0.20348 | id: e96699ef-3dd9-4718-90ef-c7e5646fd466<br/>tenant: null<br/>name: No psexec<br/>description: <br/>revision: 5<br/>sleeptime: 60<br/>sleepjitter: 10<br/>telemetry_process: true<br/>telemetry_process_limit: false<br/>telemetry_process_limit_value: 1000<br/>telemetry_network: true<br/>telemetry_network_limit: false<br/>telemetry_network_limit_value: 1000<br/>telemetry_log: true<br/>telemetry_log_limit: false<br/>telemetry_log_limit_value: 1000<br/>telemetry_remotethread: true<br/>telemetry_remotethread_limit: false<br/>telemetry_remotethread_limit_value: 1000<br/>telemetry_alerts_limit: false<br/>telemetry_alerts_limit_value: 1000<br/>binary_download_enabled: true<br/>loglevel: ERROR<br/>use_sigma: true<br/>ioc_mode: 2<br/>hlai_mode: 1<br/>hlai_skip_signed_ms: true<br/>hlai_skip_signed_others: false<br/>hlai_minimum_level: critical<br/>hibou_mode: 0<br/>hibou_skip_signed_ms: false<br/>hibou_skip_signed_others: false<br/>hibou_minimum_level: critical<br/>yara_mode: 1<br/>yara_skip_signed_ms: true<br/>yara_skip_signed_others: false<br/>use_driver: true<br/>use_isolation: true<br/>use_ransomguard: true<br/>ransomguard_alert_only: false<br/>self_protection: false<br/>use_process_block: true<br/>use_sigma_process_block: false<br/>sigma_ruleset: 1<br/>yara_ruleset: null<br/>ioc_ruleset: null | server | 2022-06-28T14:18:47Z | online | 2133962752.0 | 0 | false | 0 | 2.15.0 |


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
| Harfanglab.Agent | unknown | Agent information. | 
| Harfanglab.Agent.id | string | agent id (DEPRECATED) | 
| Harfanglab.status | string | Status (DEPRECATED) | 

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
            "external_ipaddress": "(REDACTED)",
            "firstseen": "2022-06-14T22:23:08.393381Z",
            "group_count": 0,
            "groups": [],
            "hostname": "DC-01",
            "id": "706d4524-dc2d-4438-bfef-3b620646db7f",
            "installdate": "2022/06/14 21:56:49",
            "ipaddress": "(REDACTED)",
            "ipmask": "(REDACTED)",
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
>| additional_info1: null<br/>additional_info2: null<br/>additional_info3: null<br/>additional_info4: null | 1.0 | 183558144.0 | x64 | 2 | 3192 | WORKGROUP | true | false | (REDACTED) | 2022-06-15T06:42:50.008015Z | 0 | DC-01 | 0fae71cf-ebde-4533-a50c-b3c0290378db | 2022/06/15 06:38:58 | (REDACTED) | (REDACTED) | false | true | 2022-07-28T07:41:32.197641Z | 2022-07-28T07:47:02.197641Z | 2022-07-28T07:43:44.197641Z | 2022-06-28T14:18:31Z | 20348 | 00454-40000-00001-AA596 | 10 | 0 | Windows Server 2022 Standard Evaluation | windows | 10.0.20348 | id: e96699ef-3dd9-4718-90ef-c7e5646fd466<br/>tenant: null<br/>name: No psexec<br/>description: <br/>revision: 5<br/>sleeptime: 60<br/>sleepjitter: 10<br/>telemetry_process: true<br/>telemetry_process_limit: false<br/>telemetry_process_limit_value: 1000<br/>telemetry_network: true<br/>telemetry_network_limit: false<br/>telemetry_network_limit_value: 1000<br/>telemetry_log: true<br/>telemetry_log_limit: false<br/>telemetry_log_limit_value: 1000<br/>telemetry_remotethread: true<br/>telemetry_remotethread_limit: false<br/>telemetry_remotethread_limit_value: 1000<br/>telemetry_alerts_limit: false<br/>telemetry_alerts_limit_value: 1000<br/>binary_download_enabled: true<br/>loglevel: ERROR<br/>use_sigma: true<br/>ioc_mode: 2<br/>hlai_mode: 1<br/>hlai_skip_signed_ms: true<br/>hlai_skip_signed_others: false<br/>hlai_minimum_level: critical<br/>hibou_mode: 0<br/>hibou_skip_signed_ms: false<br/>hibou_skip_signed_others: false<br/>hibou_minimum_level: critical<br/>yara_mode: 1<br/>yara_skip_signed_ms: true<br/>yara_skip_signed_others: false<br/>use_driver: true<br/>use_isolation: true<br/>use_ransomguard: true<br/>ransomguard_alert_only: false<br/>self_protection: false<br/>use_process_block: true<br/>use_sigma_process_block: false<br/>sigma_ruleset: 1<br/>yara_ruleset: null<br/>ioc_ruleset: null | server | 2022-06-28T14:18:47Z | online | 2133962752.0 | 0 | false | 0 | 2.15.0 |
>| additional_info1: null<br/>additional_info2: null<br/>additional_info3: null<br/>additional_info4: null | 0.6 | 125627596.0 | x64 | 2 | 3192 | WORKGROUP | true | false | (REDACTED) | 2022-06-14T22:23:08.393381Z | 0 | DC-01 | 706d4524-dc2d-4438-bfef-3b620646db7f | 2022/06/14 21:56:49 | (REDACTED) | (REDACTED) | false | false | 2022-06-15T06:33:46.544505Z | 2022-06-15T06:39:16.544505Z | 2022-06-15T06:35:58.544505Z | 2022-06-14T22:00:23Z | 20348 | 00454-40000-00001-AA081 | 10 | 0 | Windows Server 2022 Standard Evaluation | windows | 10.0.20348 | id: e96699ef-3dd9-4718-90ef-c7e5646fd466<br/>tenant: null<br/>name: No psexec<br/>description: <br/>revision: 5<br/>sleeptime: 60<br/>sleepjitter: 10<br/>telemetry_process: true<br/>telemetry_process_limit: false<br/>telemetry_process_limit_value: 1000<br/>telemetry_network: true<br/>telemetry_network_limit: false<br/>telemetry_network_limit_value: 1000<br/>telemetry_log: true<br/>telemetry_log_limit: false<br/>telemetry_log_limit_value: 1000<br/>telemetry_remotethread: true<br/>telemetry_remotethread_limit: false<br/>telemetry_remotethread_limit_value: 1000<br/>telemetry_alerts_limit: false<br/>telemetry_alerts_limit_value: 1000<br/>binary_download_enabled: true<br/>loglevel: ERROR<br/>use_sigma: true<br/>ioc_mode: 2<br/>hlai_mode: 1<br/>hlai_skip_signed_ms: true<br/>hlai_skip_signed_others: false<br/>hlai_minimum_level: critical<br/>hibou_mode: 0<br/>hibou_skip_signed_ms: false<br/>hibou_skip_signed_others: false<br/>hibou_minimum_level: critical<br/>yara_mode: 1<br/>yara_skip_signed_ms: true<br/>yara_skip_signed_others: false<br/>use_driver: true<br/>use_isolation: true<br/>use_ransomguard: true<br/>ransomguard_alert_only: false<br/>self_protection: false<br/>use_process_block: true<br/>use_sigma_process_block: false<br/>sigma_ruleset: 1<br/>yara_ruleset: null<br/>ioc_ruleset: null | server | 2022-06-14T22:02:32Z | offline | 2133962752.0 | 0 | false | 0 | 2.15.0 |


### harfanglab-api-call

***
Perform a generic API call

#### Base Command

`harfanglab-api-call`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_method | API method (GET, POST...). | Required | 
| api_endpoint | API endpoint (/api/version, /api/data/alert/alert/Alert/...). | Optional | 
| parameters | URL parameters. | Optional | 
| data | Posted data. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.API | unknown | API call result | 

#### Command example
```!harfanglab-api-call api_method=GET api_endpoint=/api/version```
#### Context Example
```json
{
    "Harfanglab": {
        "API": {
            "version": "2.29.7"
        }
    }
}
```

#### Human Readable Output

>### Results
>|version|
>|---|
>| 2.29.7 |


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
| Harfanglab.Telemetryprocesses.processes | unknown | Provides a list of processes | 
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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.ID | string | id | 
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.ID | string | id | 
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.ID | string | id | 
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.ID | string | id | 
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.ID | string | id | 
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.ID | string | id | 
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Job.ID | string | id | 
| Harfanglab.Job.Action | string | HarfangLab job action | 

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
| Harfanglab.Telemetrynetwork.network | unknown | Provides a list of network connections | 

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
                    "destination addr": "(REDACTED)",
                    "destination port": 443,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
                    "source port": 50000,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "create date": "2022-06-29T22:24:08.088000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
                    "source port": 49998,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-06-29T22:23:08.037000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 443,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
                    "source port": 49997,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "create date": "2022-06-29T22:08:07.550000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 443,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
                    "source port": 49996,
                    "username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "create date": "2022-06-29T22:04:42.848000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "DC-01",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
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
>| 2022-06-29T22:33:42.434000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | (REDACTED) | 50000 | (REDACTED) | 443 | out |
>| 2022-06-29T22:24:08.088000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | (REDACTED) | 49998 | (REDACTED) | 80 | out |
>| 2022-06-29T22:23:08.037000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | (REDACTED) | 49997 | (REDACTED) | 443 | out |
>| 2022-06-29T22:08:07.550000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\SYSTEM | (REDACTED) | 49996 | (REDACTED) | 443 | out |
>| 2022-06-29T22:04:42.848000Z | DC-01 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | (REDACTED) | 49995 | (REDACTED) | 80 | out |


#### Command example
```!harfanglab-telemetry-network destination_address="(REDACTED)" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrynetwork": {
            "network": [
                {
                    "create date": "2022-07-27T14:59:56.114000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-1879",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
                    "source port": 62787,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-07-27T14:58:43.590000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-3752",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
                    "source port": 64593,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-07-27T14:49:54.374000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-6852",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
                    "source port": 61571,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-07-27T14:49:14.813000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-4321",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
                    "source port": 61605,
                    "username": "NT AUTHORITY\\NETWORK SERVICE"
                },
                {
                    "create date": "2022-07-27T07:59:49.780000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-1879",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
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
>| 2022-07-27T14:59:56.114000Z | WORKSTATION-1879 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | (REDACTED) | 62787 | (REDACTED) | 80 | out |
>| 2022-07-27T14:58:43.590000Z | WORKSTATION-3752 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | (REDACTED) | 64593 | (REDACTED) | 80 | out |
>| 2022-07-27T14:49:54.374000Z | WORKSTATION-6852 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | (REDACTED) | 61571 | (REDACTED) | 80 | out |
>| 2022-07-27T14:49:14.813000Z | WORKSTATION-4321 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | (REDACTED) | 61605 | (REDACTED) | 80 | out |
>| 2022-07-27T07:59:49.780000Z | WORKSTATION-1879 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | (REDACTED) | 62472 | (REDACTED) | 80 | out |


#### Command example
```!harfanglab-telemetry-network destination_address="(REDACTED)" from_date="2022-07-21T12:34:05" to_date="2022-07-21T12:34:15" limit=5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrynetwork": {
            "network": [
                {
                    "create date": "2022-07-21T12:34:09.265000Z",
                    "destination addr": "(REDACTED)",
                    "destination port": 80,
                    "direction": "out",
                    "hostname": "WORKSTATION-4812",
                    "image name": "C:\\Windows\\System32\\svchost.exe",
                    "source address": "(REDACTED)",
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
>| 2022-07-21T12:34:09.265000Z | WORKSTATION-4812 | C:\Windows\System32\svchost.exe | NT AUTHORITY\NETWORK SERVICE | (REDACTED) | 50363 | (REDACTED) | 80 | out |


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
| Harfanglab.Telemetryeventlog.eventlog | unknown | Provides a list of event logs | 

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


| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Telemetrybinary.binary | unknown | Provides a list of binaries with associated download links. | 


#### Command example
```!harfanglab-telemetry-binary hash=2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrybinary": {
            "binary": [
                {
                    "download link": "https://my_edr_stack:8443/api/data/telemetry/Binary/download/2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5/?hl_expiring_key=0123456789abcdef",
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
>| hurukai | /opt/hurukai/hurukai | 5882824 | 2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5 | https://my_edr_stack:8443/api/data/telemetry/Binary/download/2577fb22e98a4585bedcccfe7fbb48a8b2e0b5ea4c41408247cba86e89ea2eb5/?hl_expiring_key=0123456789abcdef |


### harfanglab-telemetry-dns
***
Search DNS resolutions


#### Base Command

`harfanglab-telemetry-dns`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Optional | 
| requested_name | Requested domain name. | Optional | 
| query_type | DNS type (A, AAAA, TXT...). | Optional | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| limit | Maximum number of elements to fetch. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.TelemetryDNS.resolutions | unknown | Provides a list of DNS resolutions | 

#### Command example
```!harfanglab-telemetry-dns requested_name=download.windowsupdate.com hostname=webserver```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrydns": {
            "dns": [
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "2eabb3d4-2fe4-45c7-ba87-4fc486f37638",
                    "create date": "2023-07-20T08:14:28.306000Z",
                    "hostname": "WEBSERVER",
                    "pid": 5956,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-2fe4-45c7-4417-0026bd8eba8b",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "2eabb3d4-2fe4-45c7-ba87-4fc486f37638",
                    "create date": "2023-07-20T08:14:23.768000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1296,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-2fe4-45c7-1005-00d36589bf35",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "2eabb3d4-2fe4-45c7-ba87-4fc486f37638",
                    "create date": "2023-07-20T04:14:23.397000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1296,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-2fe4-45c7-1005-00d36589bf35",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-17T13:03:34.656000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1900,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-6c07-000eac642d4f",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-17T13:03:28.608000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1276,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-fc04-00c4827455f9",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-16T13:03:36.331000Z",
                    "hostname": "WEBSERVER",
                    "pid": 2620,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-3c0a-008126fb9d08",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-16T13:03:28.944000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1276,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-fc04-00c4827455f9",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-15T13:03:37.980000Z",
                    "hostname": "WEBSERVER",
                    "pid": 5700,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-4416-009d6e609402",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-15T13:03:29.162000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1276,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-fc04-00c4827455f9",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-14T13:03:50.310000Z",
                    "hostname": "WEBSERVER",
                    "pid": 5908,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-1417-007dde4315d9",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-14T13:03:42.865000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1276,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-fc04-00c4827455f9",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-14T02:14:55.276000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1276,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-fc04-00c4827455f9",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-13T13:03:34.668000Z",
                    "hostname": "WEBSERVER",
                    "pid": 5856,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-e016-008cbea6fa9a",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-13T13:03:29.584000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1276,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-fc04-00c4827455f9",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "create date": "2023-07-13T02:14:55.484000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1276,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-c2c0-4b31-fc04-00c4827455f9",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-06T05:33:19.372000Z",
                    "hostname": "WEBSERVER",
                    "pid": 4876,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-0c13-005257b88fb6",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-06T05:33:11.969000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1216,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-c004-00cebeddc9bf",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-04T05:25:43.924000Z",
                    "hostname": "WEBSERVER",
                    "pid": 760,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-f802-00e6099364ff",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-04T05:25:37.176000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1296,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-1005-006ae872c8a6",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-02T05:25:42.501000Z",
                    "hostname": "WEBSERVER",
                    "pid": 4252,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-9c10-00a479475cc1",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-02T05:25:35.173000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1296,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-1005-006ae872c8a6",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-01T11:40:33.272000Z",
                    "hostname": "WEBSERVER",
                    "pid": 5656,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-1816-00ba61e017c5",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-01T11:40:28.846000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1296,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-1005-006ae872c8a6",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-07-01T03:40:39.204000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1296,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-1005-006ae872c8a6",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX",
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-06-30T23:40:27.344000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1296,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-1005-006ae872c8a6",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                },
                {
                    "IP addresses": [
                        "XXX.XXX.XXX.XXX"
                    ],
                    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
                    "create date": "2023-06-30T15:40:28.177000Z",
                    "hostname": "WEBSERVER",
                    "pid": 1296,
                    "process image path": "C:\\Windows\\System32\\svchost.exe",
                    "process unique id": "67786071-183f-438a-1005-006ae872c8a6",
                    "query type": "AAAA",
                    "requested name": "download.windowsupdate.com",
                    "tenant": ""
                }
            ]
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "IP addresses": [
>        "XXX.XXX.XXX.XXX"
>    ],
>    "agentid": "5011b34e-183f-438a-a44c-a0e32a89719a",
>    "create date": "2023-06-30T15:40:28.177000Z",
>    "hostname": "WEBSERVER",
>    "pid": 1296,
>    "process image path": "C:\\Windows\\System32\\svchost.exe",
>    "process unique id": "67786071-183f-438a-1005-006ae872c8a6",
>    "query type": "AAAA",
>    "requested name": "download.windowsupdate.com",
>    "tenant": ""
>}
>```

### harfanglab-telemetry-authentication-windows
***
Search Windows authentication telemetry


#### Base Command

`harfanglab-telemetry-authentication-windows`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Optional | 
| source_address | Source IP address. | Optional | 
| success | Whether authentication succeeded or not. | Optional | 
| source_username | Source username. | Optional | 
| target_username | Target username. | Optional | 
| logon_title | Logon title. | Optional | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| limit | Maximum number of elements to fetch. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.TelemetryWindowsAuthentications.authentications | unknown | Provides a list of Windows authentications | 

#### Command example
```!harfanglab-telemetry-authentication-windows limit=5 target_username=vagrant```
#### Context Example
```json
{
    "Harfanglab": {
        "Telemetrywindows_authentications": {
            "windows_authentications": [
                {
                    "agentid": "147b2639-0427-40f3-9004-95cada686d15",
                    "event id": 4634,
                    "event title": "An account was logged off",
                    "hostname": "DC-01",
                    "logon process name": null,
                    "logon title": "Network",
                    "logon type": 3,
                    "process name": null,
                    "source address": null,
                    "source username": null,
                    "success": null,
                    "target username": "vagrant",
                    "timestamp": "2023-07-21T08:04:04.448200Z"
                },
                {
                    "agentid": "2eabb3d4-2fe4-45c7-ba87-4fc486f37638",
                    "event id": 4634,
                    "event title": "An account was logged off",
                    "hostname": "WEBSERVER",
                    "logon process name": null,
                    "logon title": "Network",
                    "logon type": 3,
                    "process name": null,
                    "source address": null,
                    "source username": null,
                    "success": null,
                    "target username": "vagrant",
                    "timestamp": "2023-07-20T12:26:58.076300Z"
                },
                {
                    "agentid": "2eabb3d4-2fe4-45c7-ba87-4fc486f37638",
                    "event id": 4634,
                    "event title": "An account was logged off",
                    "hostname": "WEBSERVER",
                    "logon process name": null,
                    "logon title": "Unlock",
                    "logon type": 7,
                    "process name": null,
                    "source address": null,
                    "source username": null,
                    "success": null,
                    "target username": "vagrant",
                    "timestamp": "2023-07-20T06:24:57.315374Z"
                },
                {
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "event id": 4634,
                    "event title": "An account was logged off",
                    "hostname": "WEBSERVER",
                    "logon process name": null,
                    "logon title": "Network",
                    "logon type": 3,
                    "process name": null,
                    "source address": null,
                    "source username": null,
                    "success": null,
                    "target username": "vagrant",
                    "timestamp": "2023-07-17T12:31:14.007910Z"
                },
                {
                    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
                    "event id": 4634,
                    "event title": "An account was logged off",
                    "hostname": "WEBSERVER",
                    "logon process name": null,
                    "logon title": "Unlock",
                    "logon type": 7,
                    "process name": null,
                    "source address": null,
                    "source username": null,
                    "success": null,
                    "target username": "vagrant",
                    "timestamp": "2023-07-17T05:59:38.968596Z"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "agentid": "524f8ab7-c2c0-4b31-893c-564acb8f857a",
>    "event id": 4634,
>    "event title": "An account was logged off",
>    "hostname": "WEBSERVER",
>    "logon process name": null,
>    "logon title": "Unlock",
>    "logon type": 7,
>    "process name": null,
>    "source address": null,
>    "source username": null,
>    "success": null,
>    "target username": "vagrant",
>    "timestamp": "2023-07-17T05:59:38.968596Z"
>}
>```

### harfanglab-telemetry-authentication-linux
***
Search Linux authentication telemetry


#### Base Command

`harfanglab-telemetry-authentication-linux`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Optional | 
| source_address | Source IP address. | Optional | 
| success | Whether authentication succeeded or not. | Optional | 
| source_username | Source username. | Optional | 
| target_username | Target username. | Optional | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| limit | Maximum number of elements to fetch. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.TelemetryLinuxAuthentications.authentications | unknown | Provides a list of Linux authentications | 

### harfanglab-telemetry-authentication-macos
***
Search Macos authentication telemetry


#### Base Command

`harfanglab-telemetry-authentication-macos`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Optional | 
| source_address | Source IP address. | Optional | 
| success | Whether authentication succeeded or not. | Optional | 
| source_username | Source username. | Optional | 
| target_username | Target username. | Optional | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| limit | Maximum number of elements to fetch. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.TelemetryMacosAuthentications.authentications | unknown | Provides a list of Macos authentications | 

### harfanglab-telemetry-authentication-users

***
Get the top N users who successfully authenticated on the host

#### Base Command

`harfanglab-telemetry-authentication-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint hostname. | Required | 
| from_date | Start date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| to_date | End date (format: YYYY-MM-DDTHH:MM:SS). | Optional | 
| limit | Fetch only the top N users who successfully authenticated on the host. Default is 3. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Authentications.Users | unknown | Provides a list of users who successfully authenticated on the host with interactive logon \(sorted per decreasing occurrence\) | 

#### Command example
```!harfanglab-telemetry-authentication-users hostname=CL-Ep2-Win11 limit=4```
#### Context Example
```json
{
    "Harfanglab": {
        "Authentications": {
            "Users": [
                {
                    "Authentication attempts": 4,
                    "Username": "CL-EP2-WIN11\\hladmin"
                },
                {
                    "Authentication attempts": 2,
                    "Username": "hladmin"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Top None authentications
>|Username|Authentication attempts|
>|---|---|
>| CL-EP2-WIN11\hladmin | 4 |
>| hladmin | 2 |


### harfanglab-telemetry-process-graph
***
Get a process graph


#### Base Command

`harfanglab-telemetry-process-graph`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| process_uuid | Process UUID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.ProcessGraph | unknown | Process Graph | 

#### Command example
```!harfanglab-telemetry-process-graph process_uuid=37d378de-b558-4597-e820-009fa44c4c03```
#### Context Example
```json
{
    "Harfanglab": {
        "ProcessGraph": {
            "calc_time": 0.2487087131012231,
            "current_process_id": "37d378de-b558-4597-e820-009fa44c4c03",
            "edges": [
                {
                    "class": "edge-parent",
                    "source": "37d378de-b558-4597-a025-000bb895a6e4",
                    "target": "37d378de-b558-4597-e820-009fa44c4c03"
                },
                {
                    "class": "edge-parent",
                    "source": "37d378de-b558-4597-6c19-00c365029657",
                    "target": "37d378de-b558-4597-a025-000bb895a6e4"
                },
                {
                    "class": "edge-parent",
                    "source": "37d378de-b558-4597-0819-000ba55fbed4",
                    "target": "37d378de-b558-4597-6c19-00c365029657"
                },
                {
                    "class": "edge-parent",
                    "source": "37d378de-b558-4597-9002-007a09a922ae",
                    "target": "37d378de-b558-4597-0819-000ba55fbed4"
                }
            ],
            "missing_processes": {},
            "nodes": [
                {
                    "alertCount": 1,
                    "childProcessCount": 0,
                    "childProcessCountConfidence": "exact",
                    "class": "node",
                    "connectionCount": 0,
                    "dnsResolutionCount": 0,
                    "id": "37d378de-b558-4597-e820-009fa44c4c03",
                    "injectedThreadCount": 0,
                    "name": "calc.exe",
                    "parents": [
                        "37d378de-b558-4597-a025-000bb895a6e4"
                    ],
                    "powershellCount": 0,
                    "signed": true,
                    "status": "complete",
                    "type": "exe"
                },
                {
                    "alertCount": 0,
                    "childProcessCount": 3,
                    "childProcessCountConfidence": "exact",
                    "class": "node",
                    "connectionCount": 0,
                    "dnsResolutionCount": 0,
                    "id": "37d378de-b558-4597-a025-000bb895a6e4",
                    "injectedThreadCount": 0,
                    "name": "cmd.exe",
                    "parents": [
                        "37d378de-b558-4597-6c19-00c365029657"
                    ],
                    "powershellCount": 0,
                    "signed": true,
                    "status": "complete",
                    "type": "exe"
                },
                {
                    "alertCount": 0,
                    "childProcessCount": 5,
                    "childProcessCountConfidence": "exact",
                    "class": "node",
                    "connectionCount": 0,
                    "dnsResolutionCount": 0,
                    "id": "37d378de-b558-4597-6c19-00c365029657",
                    "injectedThreadCount": 0,
                    "name": "explorer.exe",
                    "parents": [
                        "37d378de-b558-4597-0819-000ba55fbed4"
                    ],
                    "powershellCount": 0,
                    "signed": true,
                    "status": "complete",
                    "type": "exe"
                },
                {
                    "alertCount": 0,
                    "childProcessCount": 1,
                    "childProcessCountConfidence": "exact",
                    "class": "node",
                    "connectionCount": 0,
                    "dnsResolutionCount": 0,
                    "id": "37d378de-b558-4597-0819-000ba55fbed4",
                    "injectedThreadCount": 0,
                    "name": "userinit.exe",
                    "parents": [
                        "37d378de-b558-4597-9002-007a09a922ae"
                    ],
                    "powershellCount": 0,
                    "signed": true,
                    "status": "complete",
                    "type": "exe"
                },
                {
                    "alertCount": 0,
                    "childProcessCount": 5,
                    "childProcessCountConfidence": "exact",
                    "class": "node",
                    "connectionCount": 0,
                    "dnsResolutionCount": 0,
                    "id": "37d378de-b558-4597-9002-007a09a922ae",
                    "injectedThreadCount": 0,
                    "name": "winlogon.exe",
                    "parents": [],
                    "powershellCount": 0,
                    "signed": true,
                    "status": "complete",
                    "type": "exe"
                }
            ],
            "processes": {
                "37d378de-b558-4597-0819-000ba55fbed4": {
                    "@event_create_date": "2023-07-20T08:56:43.923000Z",
                    "@timestamp": "2023-07-20T08:56:47.885612Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
                        "domainname": "WORKGROUP",
                        "hostname": "martin-vbox-win10-first",
                        "osproducttype": "Windows 10 Enterprise",
                        "ostype": "windows",
                        "osversion": "10.0.19041",
                        "version": "2.29.0rc1-post0"
                    },
                    "ancestors": "C:\\Windows\\System32\\winlogon.exe",
                    "commandline": "C:\\Windows\\system32\\userinit.exe",
                    "current_directory": "C:\\Windows\\system32\\",
                    "fake_parent_commandline": "",
                    "fake_parent_image": "",
                    "fake_ppid": 0,
                    "grandparent_commandline": "",
                    "grandparent_image": "",
                    "grandparent_integrity_level": "Unknown",
                    "groups": [
                        {
                            "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
                            "name": "le groupe de la marmotte"
                        }
                    ],
                    "hashes": {
                        "md5": "582a919ca5f944aa83895a5c633c122c",
                        "sha1": "6d0c6aea6bce05166761085b1d612558f81d877a",
                        "sha256": "eda7ee39d4db8142a1e0788e205e80ae798035d60273e74981e09e98c8d0e740"
                    },
                    "id": "oVOEcokBVudtObjXHC6o",
                    "image_name": "C:\\Windows\\System32\\userinit.exe",
                    "integrity_level": "Medium",
                    "log_platform_flag": 0,
                    "log_type": "process",
                    "logonid": 182681,
                    "parent_commandline": "winlogon.exe",
                    "parent_image": "C:\\Windows\\System32\\winlogon.exe",
                    "parent_integrity_level": "System",
                    "parent_unique_id": "37d378de-b558-4597-9002-007a09a922ae",
                    "pe_imphash": "DE7486657F39757C768DEE3094E10FF8",
                    "pe_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "Userinit Logon Application",
                        "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
                        "internal_name": "userinit",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "USERINIT.EXE",
                        "pe_timestamp": "2086-04-07T12:35:36Z",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.1"
                    },
                    "pe_timestamp": "2086-04-07T12:35:36Z",
                    "pe_timestamp_int": 3669021336,
                    "pid": 6408,
                    "ppid": 656,
                    "process_name": "userinit.exe",
                    "process_unique_id": "37d378de-b558-4597-0819-000ba55fbed4",
                    "session": 1,
                    "signature_info": {
                        "root_info": {
                            "display_name": "Microsoft Root Certificate Authority 2010",
                            "issuer_name": "Microsoft Root Certificate Authority 2010",
                            "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
                            "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
                            "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
                        },
                        "signed_authenticode": false,
                        "signed_catalog": true,
                        "signer_info": {
                            "display_name": "Microsoft Windows",
                            "issuer_name": "Microsoft Windows Production PCA 2011",
                            "serial_number": "330000023241fb59996dcc4dff000000000232",
                            "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
                            "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
                        }
                    },
                    "signed": true,
                    "size": 34816,
                    "tenant": "",
                    "username": "MARTIN-VBOX-WIN\\root",
                    "usersid": "S-1-5-21-2977311633-4124872198-649243625-1000"
                },
                "37d378de-b558-4597-6c19-00c365029657": {
                    "@event_create_date": "2023-07-20T08:56:44.030000Z",
                    "@timestamp": "2023-07-20T08:56:47.885767Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
                        "domainname": "WORKGROUP",
                        "hostname": "martin-vbox-win10-first",
                        "osproducttype": "Windows 10 Enterprise",
                        "ostype": "windows",
                        "osversion": "10.0.19041",
                        "version": "2.29.0rc1-post0"
                    },
                    "ancestors": "C:\\Windows\\System32\\userinit.exe|C:\\Windows\\System32\\winlogon.exe",
                    "commandline": "C:\\Windows\\Explorer.EXE",
                    "current_directory": "C:\\Windows\\system32\\",
                    "fake_parent_commandline": "",
                    "fake_parent_image": "",
                    "fake_ppid": 0,
                    "grandparent_commandline": "winlogon.exe",
                    "grandparent_image": "C:\\Windows\\System32\\winlogon.exe",
                    "grandparent_integrity_level": "System",
                    "groups": [
                        {
                            "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
                            "name": "le groupe de la marmotte"
                        }
                    ],
                    "hashes": {
                        "md5": "fde2638e4a80b507e683d973474168da",
                        "sha1": "7cdd581ae59dae0564e421d3b46683c7b2c50571",
                        "sha256": "23165139c2a7d2d75df54b8fbac69fa37462c43ff971b78f8cbf99be2613655e"
                    },
                    "id": "pVOEcokBVudtObjXHC6y",
                    "image_name": "C:\\Windows\\explorer.exe",
                    "integrity_level": "Medium",
                    "log_platform_flag": 0,
                    "log_type": "process",
                    "logonid": 182681,
                    "parent_commandline": "C:\\Windows\\system32\\userinit.exe",
                    "parent_image": "C:\\Windows\\System32\\userinit.exe",
                    "parent_integrity_level": "Medium",
                    "parent_unique_id": "37d378de-b558-4597-0819-000ba55fbed4",
                    "pe_imphash": "1B23FD932A3AEF7DBAACECEC28FAB72F",
                    "pe_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "Windows Explorer",
                        "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
                        "internal_name": "explorer",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "EXPLORER.EXE",
                        "pe_timestamp": "2035-04-10T22:40:03Z",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.1"
                    },
                    "pe_timestamp": "2035-04-10T22:40:03Z",
                    "pe_timestamp_int": 2059857603,
                    "pid": 6508,
                    "ppid": 6408,
                    "process_name": "explorer.exe",
                    "process_unique_id": "37d378de-b558-4597-6c19-00c365029657",
                    "session": 1,
                    "signature_info": {
                        "root_info": {
                            "display_name": "Microsoft Root Certificate Authority 2010",
                            "issuer_name": "Microsoft Root Certificate Authority 2010",
                            "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
                            "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
                            "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
                        },
                        "signed_authenticode": true,
                        "signed_catalog": false,
                        "signer_info": {
                            "display_name": "Microsoft Windows",
                            "issuer_name": "Microsoft Windows Production PCA 2011",
                            "serial_number": "330000023241fb59996dcc4dff000000000232",
                            "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
                            "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
                        }
                    },
                    "signed": true,
                    "size": 4478208,
                    "tenant": "",
                    "username": "MARTIN-VBOX-WIN\\root",
                    "usersid": "S-1-5-21-2977311633-4124872198-649243625-1000"
                },
                "37d378de-b558-4597-9002-007a09a922ae": {
                    "@event_create_date": "2023-07-20T08:56:37.997000Z",
                    "@timestamp": "2023-07-20T08:56:44.140309Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
                        "domainname": "WORKGROUP",
                        "hostname": "martin-vbox-win10-first",
                        "osproducttype": "Windows 10 Enterprise",
                        "ostype": "windows",
                        "osversion": "10.0.19041",
                        "version": "2.29.0rc1-post0"
                    },
                    "ancestors": "",
                    "commandline": "winlogon.exe",
                    "current_directory": "C:\\Windows\\system32\\",
                    "fake_parent_commandline": "",
                    "fake_parent_image": "",
                    "fake_ppid": 0,
                    "grandparent_commandline": "",
                    "grandparent_image": "",
                    "grandparent_integrity_level": "Unknown",
                    "groups": [
                        {
                            "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
                            "name": "le groupe de la marmotte"
                        }
                    ],
                    "hashes": {
                        "md5": "8b9b35206487d39b2d3d076444485ec2",
                        "sha1": "b136d54bb0b352b2239e08f0b4389d663e413050",
                        "sha256": "fbc2eb97a177f7cbd6e38f3a6c45471e988b01978724f9790af0377bb5f3bf8d"
                    },
                    "id": "f1OEcokBVudtObjXDi6K",
                    "image_name": "C:\\Windows\\System32\\winlogon.exe",
                    "integrity_level": "System",
                    "log_platform_flag": 0,
                    "log_type": "process",
                    "logonid": 999,
                    "parent_commandline": "",
                    "parent_image": "",
                    "parent_integrity_level": "Unknown",
                    "pe_imphash": "B25B459645147727E57D02B17D593731",
                    "pe_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "Windows Logon Application",
                        "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
                        "internal_name": "winlogon",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "WINLOGON.EXE",
                        "pe_timestamp": "2077-10-24T01:42:54Z",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.1"
                    },
                    "pe_timestamp": "2077-10-24T01:42:54Z",
                    "pe_timestamp_int": 3402265374,
                    "pid": 656,
                    "ppid": 548,
                    "process_name": "winlogon.exe",
                    "process_unique_id": "37d378de-b558-4597-9002-007a09a922ae",
                    "session": 1,
                    "signature_info": {
                        "root_info": {
                            "display_name": "Microsoft Root Certificate Authority 2010",
                            "issuer_name": "Microsoft Root Certificate Authority 2010",
                            "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
                            "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
                            "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
                        },
                        "signed_authenticode": false,
                        "signed_catalog": true,
                        "signer_info": {
                            "display_name": "Microsoft Windows",
                            "issuer_name": "Microsoft Windows Production PCA 2011",
                            "serial_number": "330000023241fb59996dcc4dff000000000232",
                            "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
                            "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
                        }
                    },
                    "signed": true,
                    "size": 907776,
                    "tenant": "",
                    "username": "NT AUTHORITY\\SYSTEM",
                    "usersid": "S-1-5-18"
                },
                "37d378de-b558-4597-a025-000bb895a6e4": {
                    "@event_create_date": "2023-07-20T08:57:01.796000Z",
                    "@timestamp": "2023-07-20T08:57:00.780435Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
                        "domainname": "WORKGROUP",
                        "hostname": "martin-vbox-win10-first",
                        "osproducttype": "Windows 10 Enterprise",
                        "ostype": "windows",
                        "osversion": "10.0.19041",
                        "version": "2.29.0rc1-post0"
                    },
                    "ancestors": "C:\\Windows\\explorer.exe|C:\\Windows\\System32\\userinit.exe|C:\\Windows\\System32\\winlogon.exe",
                    "commandline": "C:\\Windows\\system32\\cmd.exe",
                    "current_directory": "C:\\Users\\root\\",
                    "fake_parent_commandline": "",
                    "fake_parent_image": "",
                    "fake_ppid": 0,
                    "grandparent_commandline": "C:\\Windows\\system32\\userinit.exe",
                    "grandparent_image": "C:\\Windows\\System32\\userinit.exe",
                    "grandparent_integrity_level": "Medium",
                    "groups": [
                        {
                            "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
                            "name": "le groupe de la marmotte"
                        }
                    ],
                    "hashes": {
                        "md5": "adf77cd50dc93394a09e82250feb23c9",
                        "sha1": "984b29de3244f878c8f40c5d936536f948c89a7a",
                        "sha256": "1b041f4deefb7a3d0ddc0cbe6ffca70ae9c1ff88cbbd09f26492886de649acfd"
                    },
                    "id": "CWmEcokB50kODsvATmPi",
                    "image_name": "C:\\Windows\\System32\\cmd.exe",
                    "integrity_level": "Medium",
                    "log_platform_flag": 0,
                    "log_type": "process",
                    "logonid": 182681,
                    "parent_commandline": "C:\\Windows\\Explorer.EXE",
                    "parent_image": "C:\\Windows\\explorer.exe",
                    "parent_integrity_level": "Medium",
                    "parent_unique_id": "37d378de-b558-4597-6c19-00c365029657",
                    "pe_imphash": "272245E2988E1E430500B852C4FB5E18",
                    "pe_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "Windows Command Processor",
                        "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
                        "internal_name": "cmd",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "Cmd.Exe",
                        "pe_timestamp": "1986-06-08T12:13:58Z",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.1"
                    },
                    "pe_timestamp": "1986-06-08T12:13:58Z",
                    "pe_timestamp_int": 518616838,
                    "pid": 9632,
                    "ppid": 6508,
                    "process_name": "cmd.exe",
                    "process_unique_id": "37d378de-b558-4597-a025-000bb895a6e4",
                    "session": 1,
                    "signature_info": {
                        "root_info": {
                            "display_name": "Microsoft Root Certificate Authority 2010",
                            "issuer_name": "Microsoft Root Certificate Authority 2010",
                            "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
                            "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
                            "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
                        },
                        "signed_authenticode": false,
                        "signed_catalog": true,
                        "signer_info": {
                            "display_name": "Microsoft Windows",
                            "issuer_name": "Microsoft Windows Production PCA 2011",
                            "serial_number": "330000023241fb59996dcc4dff000000000232",
                            "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
                            "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
                        }
                    },
                    "signed": true,
                    "size": 289792,
                    "tenant": "",
                    "username": "MARTIN-VBOX-WIN\\root",
                    "usersid": "S-1-5-21-2977311633-4124872198-649243625-1000"
                },
                "37d378de-b558-4597-e820-009fa44c4c03": {
                    "@event_create_date": "2023-07-20T08:57:52.366000Z",
                    "@timestamp": "2023-07-20T08:57:55.730865Z",
                    "@version": "1",
                    "agent": {
                        "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
                        "domainname": "WORKGROUP",
                        "hostname": "martin-vbox-win10-first",
                        "osproducttype": "Windows 10 Enterprise",
                        "ostype": "windows",
                        "osversion": "10.0.19041",
                        "version": "2.29.0rc1-post0"
                    },
                    "ancestors": "C:\\Windows\\System32\\cmd.exe|C:\\Windows\\explorer.exe|C:\\Windows\\System32\\userinit.exe|C:\\Windows\\System32\\winlogon.exe",
                    "commandline": "calc.exe",
                    "current_directory": "C:\\Users\\root\\",
                    "fake_parent_commandline": "",
                    "fake_parent_image": "",
                    "fake_ppid": 0,
                    "grandparent_commandline": "C:\\Windows\\Explorer.EXE",
                    "grandparent_image": "C:\\Windows\\explorer.exe",
                    "grandparent_integrity_level": "Medium",
                    "groups": [
                        {
                            "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
                            "name": "le groupe de la marmotte"
                        }
                    ],
                    "hashes": {
                        "md5": "5da8c98136d98dfec4716edd79c7145f",
                        "sha1": "ed13af4a0a754b8daee4929134d2ff15ebe053cd",
                        "sha256": "58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f"
                    },
                    "id": "TlOFcokBVudtObjXJS96",
                    "image_name": "C:\\Windows\\System32\\calc.exe",
                    "integrity_level": "Medium",
                    "log_platform_flag": 0,
                    "log_type": "process",
                    "logonid": 182681,
                    "parent_commandline": "C:\\Windows\\system32\\cmd.exe",
                    "parent_image": "C:\\Windows\\System32\\cmd.exe",
                    "parent_integrity_level": "Medium",
                    "parent_unique_id": "37d378de-b558-4597-a025-000bb895a6e4",
                    "pe_imphash": "8EEAA9499666119D13B3F44ECD77A729",
                    "pe_info": {
                        "company_name": "Microsoft Corporation",
                        "file_description": "Windows Calculator",
                        "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
                        "internal_name": "CALC",
                        "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
                        "original_filename": "CALC.EXE",
                        "pe_timestamp": "1971-09-24T16:02:24Z",
                        "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
                        "product_version": "10.0.19041.1"
                    },
                    "pe_timestamp": "1971-09-24T16:02:24Z",
                    "pe_timestamp_int": 54576144,
                    "pid": 8424,
                    "ppid": 9632,
                    "process_name": "calc.exe",
                    "process_unique_id": "37d378de-b558-4597-e820-009fa44c4c03",
                    "session": 1,
                    "signature_info": {
                        "root_info": {
                            "display_name": "Microsoft Root Certificate Authority 2010",
                            "issuer_name": "Microsoft Root Certificate Authority 2010",
                            "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
                            "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
                            "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
                        },
                        "signed_authenticode": false,
                        "signed_catalog": true,
                        "signer_info": {
                            "display_name": "Microsoft Windows",
                            "issuer_name": "Microsoft Windows Production PCA 2011",
                            "serial_number": "330000023241fb59996dcc4dff000000000232",
                            "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
                            "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
                        }
                    },
                    "signed": true,
                    "size": 27648,
                    "tenant": "",
                    "username": "MARTIN-VBOX-WIN\\root",
                    "usersid": "S-1-5-21-2977311633-4124872198-649243625-1000"
                }
            },
            "remote_threads": []
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "calc_time": 0.2487087131012231,
>    "current_process_id": "37d378de-b558-4597-e820-009fa44c4c03",
>    "edges": [
>        {
>            "class": "edge-parent",
>            "source": "37d378de-b558-4597-a025-000bb895a6e4",
>            "target": "37d378de-b558-4597-e820-009fa44c4c03"
>        },
>        {
>            "class": "edge-parent",
>            "source": "37d378de-b558-4597-6c19-00c365029657",
>            "target": "37d378de-b558-4597-a025-000bb895a6e4"
>        },
>        {
>            "class": "edge-parent",
>            "source": "37d378de-b558-4597-0819-000ba55fbed4",
>            "target": "37d378de-b558-4597-6c19-00c365029657"
>        },
>        {
>            "class": "edge-parent",
>            "source": "37d378de-b558-4597-9002-007a09a922ae",
>            "target": "37d378de-b558-4597-0819-000ba55fbed4"
>        }
>    ],
>    "missing_processes": {},
>    "nodes": [
>        {
>            "alertCount": 1,
>            "childProcessCount": 0,
>            "childProcessCountConfidence": "exact",
>            "class": "node",
>            "connectionCount": 0,
>            "dnsResolutionCount": 0,
>            "id": "37d378de-b558-4597-e820-009fa44c4c03",
>            "injectedThreadCount": 0,
>            "name": "calc.exe",
>            "parents": [
>                "37d378de-b558-4597-a025-000bb895a6e4"
>            ],
>            "powershellCount": 0,
>            "signed": true,
>            "status": "complete",
>            "type": "exe"
>        },
>        {
>            "alertCount": 0,
>            "childProcessCount": 3,
>            "childProcessCountConfidence": "exact",
>            "class": "node",
>            "connectionCount": 0,
>            "dnsResolutionCount": 0,
>            "id": "37d378de-b558-4597-a025-000bb895a6e4",
>            "injectedThreadCount": 0,
>            "name": "cmd.exe",
>            "parents": [
>                "37d378de-b558-4597-6c19-00c365029657"
>            ],
>            "powershellCount": 0,
>            "signed": true,
>            "status": "complete",
>            "type": "exe"
>        },
>        {
>            "alertCount": 0,
>            "childProcessCount": 5,
>            "childProcessCountConfidence": "exact",
>            "class": "node",
>            "connectionCount": 0,
>            "dnsResolutionCount": 0,
>            "id": "37d378de-b558-4597-6c19-00c365029657",
>            "injectedThreadCount": 0,
>            "name": "explorer.exe",
>            "parents": [
>                "37d378de-b558-4597-0819-000ba55fbed4"
>            ],
>            "powershellCount": 0,
>            "signed": true,
>            "status": "complete",
>            "type": "exe"
>        },
>        {
>            "alertCount": 0,
>            "childProcessCount": 1,
>            "childProcessCountConfidence": "exact",
>            "class": "node",
>            "connectionCount": 0,
>            "dnsResolutionCount": 0,
>            "id": "37d378de-b558-4597-0819-000ba55fbed4",
>            "injectedThreadCount": 0,
>            "name": "userinit.exe",
>            "parents": [
>                "37d378de-b558-4597-9002-007a09a922ae"
>            ],
>            "powershellCount": 0,
>            "signed": true,
>            "status": "complete",
>            "type": "exe"
>        },
>        {
>            "alertCount": 0,
>            "childProcessCount": 5,
>            "childProcessCountConfidence": "exact",
>            "class": "node",
>            "connectionCount": 0,
>            "dnsResolutionCount": 0,
>            "id": "37d378de-b558-4597-9002-007a09a922ae",
>            "injectedThreadCount": 0,
>            "name": "winlogon.exe",
>            "parents": [],
>            "powershellCount": 0,
>            "signed": true,
>            "status": "complete",
>            "type": "exe"
>        }
>    ],
>    "processes": {
>        "37d378de-b558-4597-0819-000ba55fbed4": {
>            "@event_create_date": "2023-07-20T08:56:43.923000Z",
>            "@timestamp": "2023-07-20T08:56:47.885612Z",
>            "@version": "1",
>            "agent": {
>                "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
>                "domainname": "WORKGROUP",
>                "hostname": "martin-vbox-win10-first",
>                "osproducttype": "Windows 10 Enterprise",
>                "ostype": "windows",
>                "osversion": "10.0.19041",
>                "version": "2.29.0rc1-post0"
>            },
>            "ancestors": "C:\\Windows\\System32\\winlogon.exe",
>            "commandline": "C:\\Windows\\system32\\userinit.exe",
>            "current_directory": "C:\\Windows\\system32\\",
>            "fake_parent_commandline": "",
>            "fake_parent_image": "",
>            "fake_ppid": 0,
>            "grandparent_commandline": "",
>            "grandparent_image": "",
>            "grandparent_integrity_level": "Unknown",
>            "groups": [
>                {
>                    "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
>                    "name": "le groupe de la marmotte"
>                }
>            ],
>            "hashes": {
>                "md5": "582a919ca5f944aa83895a5c633c122c",
>                "sha1": "6d0c6aea6bce05166761085b1d612558f81d877a",
>                "sha256": "eda7ee39d4db8142a1e0788e205e80ae798035d60273e74981e09e98c8d0e740"
>            },
>            "id": "oVOEcokBVudtObjXHC6o",
>            "image_name": "C:\\Windows\\System32\\userinit.exe",
>            "integrity_level": "Medium",
>            "log_platform_flag": 0,
>            "log_type": "process",
>            "logonid": 182681,
>            "parent_commandline": "winlogon.exe",
>            "parent_image": "C:\\Windows\\System32\\winlogon.exe",
>            "parent_integrity_level": "System",
>            "parent_unique_id": "37d378de-b558-4597-9002-007a09a922ae",
>            "pe_imphash": "DE7486657F39757C768DEE3094E10FF8",
>            "pe_info": {
>                "company_name": "Microsoft Corporation",
>                "file_description": "Userinit Logon Application",
>                "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
>                "internal_name": "userinit",
>                "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
>                "original_filename": "USERINIT.EXE",
>                "pe_timestamp": "2086-04-07T12:35:36Z",
>                "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
>                "product_version": "10.0.19041.1"
>            },
>            "pe_timestamp": "2086-04-07T12:35:36Z",
>            "pe_timestamp_int": 3669021336,
>            "pid": 6408,
>            "ppid": 656,
>            "process_name": "userinit.exe",
>            "process_unique_id": "37d378de-b558-4597-0819-000ba55fbed4",
>            "session": 1,
>            "signature_info": {
>                "root_info": {
>                    "display_name": "Microsoft Root Certificate Authority 2010",
>                    "issuer_name": "Microsoft Root Certificate Authority 2010",
>                    "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
>                    "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
>                    "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
>                },
>                "signed_authenticode": false,
>                "signed_catalog": true,
>                "signer_info": {
>                    "display_name": "Microsoft Windows",
>                    "issuer_name": "Microsoft Windows Production PCA 2011",
>                    "serial_number": "330000023241fb59996dcc4dff000000000232",
>                    "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
>                    "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
>                }
>            },
>            "signed": true,
>            "size": 34816,
>            "tenant": "",
>            "username": "MARTIN-VBOX-WIN\\root",
>            "usersid": "S-1-5-21-2977311633-4124872198-649243625-1000"
>        },
>        "37d378de-b558-4597-6c19-00c365029657": {
>            "@event_create_date": "2023-07-20T08:56:44.030000Z",
>            "@timestamp": "2023-07-20T08:56:47.885767Z",
>            "@version": "1",
>            "agent": {
>                "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
>                "domainname": "WORKGROUP",
>                "hostname": "martin-vbox-win10-first",
>                "osproducttype": "Windows 10 Enterprise",
>                "ostype": "windows",
>                "osversion": "10.0.19041",
>                "version": "2.29.0rc1-post0"
>            },
>            "ancestors": "C:\\Windows\\System32\\userinit.exe|C:\\Windows\\System32\\winlogon.exe",
>            "commandline": "C:\\Windows\\Explorer.EXE",
>            "current_directory": "C:\\Windows\\system32\\",
>            "fake_parent_commandline": "",
>            "fake_parent_image": "",
>            "fake_ppid": 0,
>            "grandparent_commandline": "winlogon.exe",
>            "grandparent_image": "C:\\Windows\\System32\\winlogon.exe",
>            "grandparent_integrity_level": "System",
>            "groups": [
>                {
>                    "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
>                    "name": "le groupe de la marmotte"
>                }
>            ],
>            "hashes": {
>                "md5": "fde2638e4a80b507e683d973474168da",
>                "sha1": "7cdd581ae59dae0564e421d3b46683c7b2c50571",
>                "sha256": "23165139c2a7d2d75df54b8fbac69fa37462c43ff971b78f8cbf99be2613655e"
>            },
>            "id": "pVOEcokBVudtObjXHC6y",
>            "image_name": "C:\\Windows\\explorer.exe",
>            "integrity_level": "Medium",
>            "log_platform_flag": 0,
>            "log_type": "process",
>            "logonid": 182681,
>            "parent_commandline": "C:\\Windows\\system32\\userinit.exe",
>            "parent_image": "C:\\Windows\\System32\\userinit.exe",
>            "parent_integrity_level": "Medium",
>            "parent_unique_id": "37d378de-b558-4597-0819-000ba55fbed4",
>            "pe_imphash": "1B23FD932A3AEF7DBAACECEC28FAB72F",
>            "pe_info": {
>                "company_name": "Microsoft Corporation",
>                "file_description": "Windows Explorer",
>                "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
>                "internal_name": "explorer",
>                "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
>                "original_filename": "EXPLORER.EXE",
>                "pe_timestamp": "2035-04-10T22:40:03Z",
>                "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
>                "product_version": "10.0.19041.1"
>            },
>            "pe_timestamp": "2035-04-10T22:40:03Z",
>            "pe_timestamp_int": 2059857603,
>            "pid": 6508,
>            "ppid": 6408,
>            "process_name": "explorer.exe",
>            "process_unique_id": "37d378de-b558-4597-6c19-00c365029657",
>            "session": 1,
>            "signature_info": {
>                "root_info": {
>                    "display_name": "Microsoft Root Certificate Authority 2010",
>                    "issuer_name": "Microsoft Root Certificate Authority 2010",
>                    "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
>                    "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
>                    "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
>                },
>                "signed_authenticode": true,
>                "signed_catalog": false,
>                "signer_info": {
>                    "display_name": "Microsoft Windows",
>                    "issuer_name": "Microsoft Windows Production PCA 2011",
>                    "serial_number": "330000023241fb59996dcc4dff000000000232",
>                    "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
>                    "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
>                }
>            },
>            "signed": true,
>            "size": 4478208,
>            "tenant": "",
>            "username": "MARTIN-VBOX-WIN\\root",
>            "usersid": "S-1-5-21-2977311633-4124872198-649243625-1000"
>        },
>        "37d378de-b558-4597-9002-007a09a922ae": {
>            "@event_create_date": "2023-07-20T08:56:37.997000Z",
>            "@timestamp": "2023-07-20T08:56:44.140309Z",
>            "@version": "1",
>            "agent": {
>                "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
>                "domainname": "WORKGROUP",
>                "hostname": "martin-vbox-win10-first",
>                "osproducttype": "Windows 10 Enterprise",
>                "ostype": "windows",
>                "osversion": "10.0.19041",
>                "version": "2.29.0rc1-post0"
>            },
>            "ancestors": "",
>            "commandline": "winlogon.exe",
>            "current_directory": "C:\\Windows\\system32\\",
>            "fake_parent_commandline": "",
>            "fake_parent_image": "",
>            "fake_ppid": 0,
>            "grandparent_commandline": "",
>            "grandparent_image": "",
>            "grandparent_integrity_level": "Unknown",
>            "groups": [
>                {
>                    "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
>                    "name": "le groupe de la marmotte"
>                }
>            ],
>            "hashes": {
>                "md5": "8b9b35206487d39b2d3d076444485ec2",
>                "sha1": "b136d54bb0b352b2239e08f0b4389d663e413050",
>                "sha256": "fbc2eb97a177f7cbd6e38f3a6c45471e988b01978724f9790af0377bb5f3bf8d"
>            },
>            "id": "f1OEcokBVudtObjXDi6K",
>            "image_name": "C:\\Windows\\System32\\winlogon.exe",
>            "integrity_level": "System",
>            "log_platform_flag": 0,
>            "log_type": "process",
>            "logonid": 999,
>            "parent_commandline": "",
>            "parent_image": "",
>            "parent_integrity_level": "Unknown",
>            "pe_imphash": "B25B459645147727E57D02B17D593731",
>            "pe_info": {
>                "company_name": "Microsoft Corporation",
>                "file_description": "Windows Logon Application",
>                "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
>                "internal_name": "winlogon",
>                "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
>                "original_filename": "WINLOGON.EXE",
>                "pe_timestamp": "2077-10-24T01:42:54Z",
>                "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
>                "product_version": "10.0.19041.1"
>            },
>            "pe_timestamp": "2077-10-24T01:42:54Z",
>            "pe_timestamp_int": 3402265374,
>            "pid": 656,
>            "ppid": 548,
>            "process_name": "winlogon.exe",
>            "process_unique_id": "37d378de-b558-4597-9002-007a09a922ae",
>            "session": 1,
>            "signature_info": {
>                "root_info": {
>                    "display_name": "Microsoft Root Certificate Authority 2010",
>                    "issuer_name": "Microsoft Root Certificate Authority 2010",
>                    "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
>                    "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
>                    "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
>                },
>                "signed_authenticode": false,
>                "signed_catalog": true,
>                "signer_info": {
>                    "display_name": "Microsoft Windows",
>                    "issuer_name": "Microsoft Windows Production PCA 2011",
>                    "serial_number": "330000023241fb59996dcc4dff000000000232",
>                    "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
>                    "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
>                }
>            },
>            "signed": true,
>            "size": 907776,
>            "tenant": "",
>            "username": "NT AUTHORITY\\SYSTEM",
>            "usersid": "S-1-5-18"
>        },
>        "37d378de-b558-4597-a025-000bb895a6e4": {
>            "@event_create_date": "2023-07-20T08:57:01.796000Z",
>            "@timestamp": "2023-07-20T08:57:00.780435Z",
>            "@version": "1",
>            "agent": {
>                "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
>                "domainname": "WORKGROUP",
>                "hostname": "martin-vbox-win10-first",
>                "osproducttype": "Windows 10 Enterprise",
>                "ostype": "windows",
>                "osversion": "10.0.19041",
>                "version": "2.29.0rc1-post0"
>            },
>            "ancestors": "C:\\Windows\\explorer.exe|C:\\Windows\\System32\\userinit.exe|C:\\Windows\\System32\\winlogon.exe",
>            "commandline": "C:\\Windows\\system32\\cmd.exe",
>            "current_directory": "C:\\Users\\root\\",
>            "fake_parent_commandline": "",
>            "fake_parent_image": "",
>            "fake_ppid": 0,
>            "grandparent_commandline": "C:\\Windows\\system32\\userinit.exe",
>            "grandparent_image": "C:\\Windows\\System32\\userinit.exe",
>            "grandparent_integrity_level": "Medium",
>            "groups": [
>                {
>                    "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
>                    "name": "le groupe de la marmotte"
>                }
>            ],
>            "hashes": {
>                "md5": "adf77cd50dc93394a09e82250feb23c9",
>                "sha1": "984b29de3244f878c8f40c5d936536f948c89a7a",
>                "sha256": "1b041f4deefb7a3d0ddc0cbe6ffca70ae9c1ff88cbbd09f26492886de649acfd"
>            },
>            "id": "CWmEcokB50kODsvATmPi",
>            "image_name": "C:\\Windows\\System32\\cmd.exe",
>            "integrity_level": "Medium",
>            "log_platform_flag": 0,
>            "log_type": "process",
>            "logonid": 182681,
>            "parent_commandline": "C:\\Windows\\Explorer.EXE",
>            "parent_image": "C:\\Windows\\explorer.exe",
>            "parent_integrity_level": "Medium",
>            "parent_unique_id": "37d378de-b558-4597-6c19-00c365029657",
>            "pe_imphash": "272245E2988E1E430500B852C4FB5E18",
>            "pe_info": {
>                "company_name": "Microsoft Corporation",
>                "file_description": "Windows Command Processor",
>                "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
>                "internal_name": "cmd",
>                "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
>                "original_filename": "Cmd.Exe",
>                "pe_timestamp": "1986-06-08T12:13:58Z",
>                "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
>                "product_version": "10.0.19041.1"
>            },
>            "pe_timestamp": "1986-06-08T12:13:58Z",
>            "pe_timestamp_int": 518616838,
>            "pid": 9632,
>            "ppid": 6508,
>            "process_name": "cmd.exe",
>            "process_unique_id": "37d378de-b558-4597-a025-000bb895a6e4",
>            "session": 1,
>            "signature_info": {
>                "root_info": {
>                    "display_name": "Microsoft Root Certificate Authority 2010",
>                    "issuer_name": "Microsoft Root Certificate Authority 2010",
>                    "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
>                    "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
>                    "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
>                },
>                "signed_authenticode": false,
>                "signed_catalog": true,
>                "signer_info": {
>                    "display_name": "Microsoft Windows",
>                    "issuer_name": "Microsoft Windows Production PCA 2011",
>                    "serial_number": "330000023241fb59996dcc4dff000000000232",
>                    "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
>                    "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
>                }
>            },
>            "signed": true,
>            "size": 289792,
>            "tenant": "",
>            "username": "MARTIN-VBOX-WIN\\root",
>            "usersid": "S-1-5-21-2977311633-4124872198-649243625-1000"
>        },
>        "37d378de-b558-4597-e820-009fa44c4c03": {
>            "@event_create_date": "2023-07-20T08:57:52.366000Z",
>            "@timestamp": "2023-07-20T08:57:55.730865Z",
>            "@version": "1",
>            "agent": {
>                "agentid": "f93af2e6-b558-4597-bb9f-d8288a510c45",
>                "domainname": "WORKGROUP",
>                "hostname": "martin-vbox-win10-first",
>                "osproducttype": "Windows 10 Enterprise",
>                "ostype": "windows",
>                "osversion": "10.0.19041",
>                "version": "2.29.0rc1-post0"
>            },
>            "ancestors": "C:\\Windows\\System32\\cmd.exe|C:\\Windows\\explorer.exe|C:\\Windows\\System32\\userinit.exe|C:\\Windows\\System32\\winlogon.exe",
>            "commandline": "calc.exe",
>            "current_directory": "C:\\Users\\root\\",
>            "fake_parent_commandline": "",
>            "fake_parent_image": "",
>            "fake_ppid": 0,
>            "grandparent_commandline": "C:\\Windows\\Explorer.EXE",
>            "grandparent_image": "C:\\Windows\\explorer.exe",
>            "grandparent_integrity_level": "Medium",
>            "groups": [
>                {
>                    "id": "41761a0c-c691-49f4-88a0-188dcdcc5d40",
>                    "name": "le groupe de la marmotte"
>                }
>            ],
>            "hashes": {
>                "md5": "5da8c98136d98dfec4716edd79c7145f",
>                "sha1": "ed13af4a0a754b8daee4929134d2ff15ebe053cd",
>                "sha256": "58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f"
>            },
>            "id": "TlOFcokBVudtObjXJS96",
>            "image_name": "C:\\Windows\\System32\\calc.exe",
>            "integrity_level": "Medium",
>            "log_platform_flag": 0,
>            "log_type": "process",
>            "logonid": 182681,
>            "parent_commandline": "C:\\Windows\\system32\\cmd.exe",
>            "parent_image": "C:\\Windows\\System32\\cmd.exe",
>            "parent_integrity_level": "Medium",
>            "parent_unique_id": "37d378de-b558-4597-a025-000bb895a6e4",
>            "pe_imphash": "8EEAA9499666119D13B3F44ECD77A729",
>            "pe_info": {
>                "company_name": "Microsoft Corporation",
>                "file_description": "Windows Calculator",
>                "file_version": "10.0.19041.1 (WinBuild.160101.0800)",
>                "internal_name": "CALC",
>                "legal_copyright": "\u00a9 Microsoft Corporation. All rights reserved.",
>                "original_filename": "CALC.EXE",
>                "pe_timestamp": "1971-09-24T16:02:24Z",
>                "product_name": "Microsoft\u00ae Windows\u00ae Operating System",
>                "product_version": "10.0.19041.1"
>            },
>            "pe_timestamp": "1971-09-24T16:02:24Z",
>            "pe_timestamp_int": 54576144,
>            "pid": 8424,
>            "ppid": 9632,
>            "process_name": "calc.exe",
>            "process_unique_id": "37d378de-b558-4597-e820-009fa44c4c03",
>            "session": 1,
>            "signature_info": {
>                "root_info": {
>                    "display_name": "Microsoft Root Certificate Authority 2010",
>                    "issuer_name": "Microsoft Root Certificate Authority 2010",
>                    "serial_number": "28cc3a25bfba44ac449a9b586b4339aa",
>                    "thumbprint": "3b1efd3a66ea28b16697394703a72ca340a05bd5",
>                    "thumbprint_sha256": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e"
>                },
>                "signed_authenticode": false,
>                "signed_catalog": true,
>                "signer_info": {
>                    "display_name": "Microsoft Windows",
>                    "issuer_name": "Microsoft Windows Production PCA 2011",
>                    "serial_number": "330000023241fb59996dcc4dff000000000232",
>                    "thumbprint": "ff82bc38e1da5e596df374c53e3617f7eda36b06",
>                    "thumbprint_sha256": "e866d202865ed3d83c35dff4cde3a2d0fc1d2b17c084e8b26dd0ca28a8c75cfb"
>                }
>            },
>            "signed": true,
>            "size": 27648,
>            "tenant": "",
>            "username": "MARTIN-VBOX-WIN\\root",
>            "usersid": "S-1-5-21-2977311633-4124872198-649243625-1000"
>        }
>    },
>    "remote_threads": []
>}
>```




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
| Harfanglab.Job.Info | unknown | Job Status | 

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
                    "dst_addr": "(REDACTED)",
                    "dst_port": 443,
                    "fullpath": "C:\\Program Files\\HarfangLab\\hurukai.exe",
                    "md5": "05049f1cadb8af2b6893e1ead33351c9",
                    "protocol": "TCP",
                    "signed": true,
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
                    "src_addr": "(REDACTED)",
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
>| ESTABLISHED | TCP | IPv4 | (REDACTED) | 55267 | (REDACTED) | 443 | C:\Program Files\HarfangLab\hurukai.exe | true | 05049f1cadb8af2b6893e1ead33351c9 |
>| LISTEN | TCP | IPv6 | :: | 49664 |  |  | C:\Windows\System32\lsass.exe | true | 6da2fcc580c720c16612057e83f47f04 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 49664 |  |  | C:\Windows\System32\lsass.exe | true | 6da2fcc580c720c16612057e83f47f04 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 49669 |  |  | C:\Windows\System32\services.exe | true | 042c0e965c5db03dbf911e4c6a319ce8 |
>| LISTEN | TCP | IPv6 | :: | 49669 |  |  | C:\Windows\System32\services.exe | true | 042c0e965c5db03dbf911e4c6a319ce8 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 49668 |  |  | C:\Windows\System32\spoolsv.exe | true | 55bb3facc6ef795f6f1d8cc656bcb779 |
>| LISTEN | TCP | IPv6 | :: | 49668 |  |  | C:\Windows\System32\spoolsv.exe | true | 55bb3facc6ef795f6f1d8cc656bcb779 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 22 |  |  | C:\Program Files\OpenSSH-Win64\sshd.exe | true | 331ba0e529810ef718dd3efbd1242302 |
>| LISTEN | TCP | IPv6 | :: | 22 |  |  | C:\Program Files\OpenSSH-Win64\sshd.exe | true | 331ba0e529810ef718dd3efbd1242302 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 3389 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv6 | :: | 3389 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 3389 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | (REDACTED) | 3389 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv6 | :: | 135 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 135 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | (REDACTED) | 52239 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv6 | :: | 49667 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 49667 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 49666 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv6 | :: | 49666 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | (REDACTED) | 5355 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 5355 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | (REDACTED) | 5353 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 5353 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 64686 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | (REDACTED) | 64686 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv4 | (REDACTED) | 123 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| NONE | UDP | IPv6 | :: | 123 |  |  | C:\Windows\System32\svchost.exe | true | dc32aba4669eafb22fcacd5ec836a107 |
>| LISTEN | TCP | IPv4 | (REDACTED) | 139 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | (REDACTED) | 47001 |  |  |  | false |  |
>| LISTEN | TCP | IPv6 | :: | 47001 |  |  |  | false |  |
>| NONE | UDP | IPv4 | (REDACTED) | 138 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | (REDACTED) | 139 |  |  |  | false |  |
>| NONE | UDP | IPv4 | (REDACTED) | 138 |  |  |  | false |  |
>| LISTEN | TCP | IPv6 | :: | 445 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | (REDACTED) | 5985 |  |  |  | false |  |
>| LISTEN | TCP | IPv6 | :: | 5985 |  |  |  | false |  |
>| NONE | UDP | IPv4 | (REDACTED) | 137 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | (REDACTED) | 445 |  |  |  | false |  |
>| NONE | UDP | IPv4 | (REDACTED) | 137 |  |  |  | false |  |
>| LISTEN | TCP | IPv4 | (REDACTED) | 49665 |  |  | C:\Windows\System32\wininit.exe | true | e7bbde1ff6b1c3c883771e145fb6c396 |
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
| Harfanglab.Persistence.data | unknown | Provides a list of persistence means | 

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
| Harfanglab.Artifact.MFT | unknown | Provides a link to download the raw MFT | 

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
                    "download_link": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/uDV4NIIB3S3Gj-GSVFRk/download/?hl_expiring_key=0123456789abcdef",
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
            "data": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/uDV4NIIB3S3Gj-GSVFRk/download/?hl_expiring_key=0123456789abcdef"
        }
    }
}
```

#### Human Readable Output

>### MFT download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 0 hives, 1 mft, 0 USN, 0 prefetch, 0 logs files | 206045184 | https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/uDV4NIIB3S3Gj-GSVFRk/download/?hl_expiring_key=0123456789abcdef |


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
| Harfanglab.Artifact.HIVES | unknown | Provides a link to download the raw hives | 

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
                    "download_link": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/jDV2NIIB3S3Gj-GSkVSP/download/?hl_expiring_key=0123456789abcdef",
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
            "data": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/jDV2NIIB3S3Gj-GSkVSP/download/?hl_expiring_key=0123456789abcdef"
        }
    }
}
```

#### Human Readable Output

>### HIVES download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 11 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files | 91324416 | https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/jDV2NIIB3S3Gj-GSkVSP/download/?hl_expiring_key=0123456789abcdef |


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
| Harfanglab.Artifact.EVTX | unknown | Provides a link to download the evt/evtx files | 

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
                    "download_link": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/SjV0NIIB3S3Gj-GS8FQF/download/?hl_expiring_key=0123456789abcdef",
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
            "data": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/SjV0NIIB3S3Gj-GS8FQF/download/?hl_expiring_key=0123456789abcdef"
        }
    }
}
```

#### Human Readable Output

>### EVTX download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 0 hives, 0 mft, 0 USN, 0 prefetch, 133 logs files | 400969728 | https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/SjV0NIIB3S3Gj-GS8FQF/download/?hl_expiring_key=0123456789abcdef |


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
| Harfanglab.Artifact.LOGS | unknown | Provides a link to download the log files | 

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
                    "download_link": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/mzV3NIIB3S3Gj-GSMlSI/download/?hl_expiring_key=0123456789abcdef",
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
            "data": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/mzV3NIIB3S3Gj-GSMlSI/download/?hl_expiring_key=0123456789abcdef"
        }
    }
}
```

#### Human Readable Output

>### LOGS download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 0 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files, 0 linux filesystem parse | 0 | https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/mzV3NIIB3S3Gj-GSMlSI/download/?hl_expiring_key=0123456789abcdef |


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
| Harfanglab.Artifact.FS | unknown | Provides a link to download the CSV file with filesystem entries | 

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
                    "download_link": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/ajV1NIIB3S3Gj-GShlQa/download/?hl_expiring_key=0123456789abcdef",
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
            "data": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/ajV1NIIB3S3Gj-GShlQa/download/?hl_expiring_key=0123456789abcdef"
        }
    }
}
```

#### Human Readable Output

>### FS download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 0 hives, 0 mft, 0 USN, 0 prefetch, 0 logs files, 0 linux filesystem parse | 0 | https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/ajV1NIIB3S3Gj-GShlQa/download/?hl_expiring_key=0123456789abcdef |


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
| Harfanglab.Artifact.ALL | unknown | Provides a link to download an archive with all raw artifacts | 

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
                    "download_link": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/HDVyNIIB3S3Gj-GSsFTu/download/?hl_expiring_key=0123456789abcdef",
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
            "data": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/HDVyNIIB3S3Gj-GSsFTu/download/?hl_expiring_key=0123456789abcdef"
        }
    }
}
```

#### Human Readable Output

>### ALL download list
>|hostname|msg|size|download link|
>|---|---|---|---|
>| DC-01 | got 11 hives, 1 mft, 1 USN, 0 prefetch, 133 logs files | 734616576 | https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/HDVyNIIB3S3Gj-GSsFTu/download/?hl_expiring_key=0123456789abcdef |


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
                    "download link": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/MTVzNIIB3S3Gj-GSxFQ5/download/?hl_expiring_key=0123456789abcdef",
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
>| DC-01 | 1 file(s) downloaded | 1688 | https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/MTVzNIIB3S3Gj-GSxFQ5/download/?hl_expiring_key=0123456789abcdef |


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
                    "download link": "https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/_TV7NIIB3S3Gj-GSBVTv/download/?hl_expiring_key=0123456789abcdef",
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
>| DC-01 | 1 file(s) downloaded | 1080819582 | https://my_edr_stack:8443/api/data/investigation/artefact/Artefact/_TV7NIIB3S3Gj-GSBVTv/download/?hl_expiring_key=0123456789abcdef |


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

### harfanglab-whitelist-add
***
Add a whitelist


#### Base Command

`harfanglab-whitelist-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Comment associated to the whitelist. | Optional | 
| target | Detection engine associated to the whitelist (all, sigma, yara, hlai, vt, ransom, orion, glimps, cape, driver). | Optional | 
| sigma_rule_id | UUID of the targeted sigma rule (for sigma whitelist). | Optional | 
| field | Field used for checking the criterion. | Optional | 
| case_insensitive | Whether checking must be case sensitive or not. | Optional | 
| operator | Operator used for the criterion (eq, contains, regex). | Optional | 
| value | Value used for the criterion. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Whitelists | unknown | Whitelists | 

#### Command example
```!harfanglab-whitelist-add target=all field=process.hashes.sha256 operator=eq value=dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2514 comment="Example of whitelist for all detection engines" case_insensitive=true```
#### Context Example
```json
{
    "Harfanglab": {
        "Whitelists": {
            "comment": "Example of whitelist for all detection engines",
            "creation_date": "2023-07-21T15:41:57.515693Z",
            "criteria": [
                {
                    "case_insensitive": true,
                    "field": "process.hashes.sha256",
                    "id": 3004,
                    "operator": "eq",
                    "value": "dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2514"
                }
            ],
            "enabled": true,
            "id": 2519,
            "last_modifier": {
                "id": 191,
                "username": "Harfanglab_Tech"
            },
            "last_update": "2023-07-21T15:41:57.515666Z",
            "orphan": false,
            "provided_by_hlab": false,
            "sigma_rule_id": null,
            "target": "all"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "comment": "Example of whitelist for all detection engines",
>    "creation_date": "2023-07-21T15:41:57.515693Z",
>    "criteria": [
>        {
>            "case_insensitive": true,
>            "field": "process.hashes.sha256",
>            "id": 3004,
>            "operator": "eq",
>            "value": "dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2514"
>        }
>    ],
>    "enabled": true,
>    "id": 2519,
>    "last_modifier": {
>        "id": 191,
>        "username": "Harfanglab_Tech"
>    },
>    "last_update": "2023-07-21T15:41:57.515666Z",
>    "orphan": false,
>    "provided_by_hlab": false,
>    "sigma_rule_id": null,
>    "target": "all"
>}
>```

### harfanglab-whitelist-add-criterion
***
Add a criterion to an existing whitelist


#### Base Command

`harfanglab-whitelist-add-criterion`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Whitelist id. | Optional | 
| field | Field used for checking the criterion. | Optional | 
| case_insensitive | Whether checking must be case sensitive or not. | Optional | 
| operator | Operator used for the criterion (eq, contains, regex). | Optional | 
| value | Value used for the criterion. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Whitelists | unknown | Whitelists | 

#### Command example
```!harfanglab-whitelist-add-criterion id=2518 field=process.commandline operator=contains value=cmd.exe```
#### Context Example
```json
{
    "Harfanglab": {
        "Whitelists": {
            "comment": "Example of whitelist for all detection engines",
            "creation_date": "2023-07-21T15:41:20.320846Z",
            "criteria": [
                {
                    "case_insensitive": true,
                    "field": "process.hashes.sha256",
                    "id": 3003,
                    "operator": "eq",
                    "value": "dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2515"
                },
                {
                    "case_insensitive": true,
                    "field": "process.commandline",
                    "id": 3005,
                    "operator": "contains",
                    "value": "cmd.exe"
                }
            ],
            "enabled": true,
            "id": 2518,
            "last_modifier": {
                "id": 191,
                "username": "Harfanglab_Tech"
            },
            "last_update": "2023-07-21T15:41:58.736445Z",
            "orphan": false,
            "provided_by_hlab": false,
            "sigma_rule_id": null,
            "sigma_rule_name": null,
            "target": "all"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "comment": "Example of whitelist for all detection engines",
>    "creation_date": "2023-07-21T15:41:20.320846Z",
>    "criteria": [
>        {
>            "case_insensitive": true,
>            "field": "process.hashes.sha256",
>            "id": 3003,
>            "operator": "eq",
>            "value": "dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2515"
>        },
>        {
>            "case_insensitive": true,
>            "field": "process.commandline",
>            "id": 3005,
>            "operator": "contains",
>            "value": "cmd.exe"
>        }
>    ],
>    "enabled": true,
>    "id": 2518,
>    "last_modifier": {
>        "id": 191,
>        "username": "Harfanglab_Tech"
>    },
>    "last_update": "2023-07-21T15:41:58.736445Z",
>    "orphan": false,
>    "provided_by_hlab": false,
>    "sigma_rule_id": null,
>    "sigma_rule_name": null,
>    "target": "all"
>}
>```




### harfanglab-whitelist-search
***
Search whitelists from a keyword


#### Base Command

`harfanglab-whitelist-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | Keyword to search whitelist. | Optional | 
| provided_by_hlab | Boolean indicating whether to search in whitelists provided by HarfangLab or not. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Harfanglab.Whitelists | unknown | Whitelists | 

#### Command example
```!harfanglab-whitelist-search keyword=cmd.exe```
#### Context Example
```json
{
    "Harfanglab": {
        "Whitelists": {
            "comment": "Example of whitelist for all detection engines",
            "creation_date": "2023-07-21T15:41:20.320846Z",
            "criteria": [
                {
                    "case_insensitive": true,
                    "field": "process.hashes.sha256",
                    "id": 3003,
                    "operator": "eq",
                    "value": "dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2515"
                },
                {
                    "case_insensitive": true,
                    "field": "process.commandline",
                    "id": 3005,
                    "operator": "contains",
                    "value": "cmd.exe"
                }
            ],
            "criteria_str": "process.hashes.sha256 eq dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2515, process.commandline contains cmd.exe",
            "enabled": true,
            "id": 2518,
            "last_modifier": {
                "id": 191,
                "username": "Harfanglab_Tech"
            },
            "last_update": "2023-07-21T15:41:58.736445Z",
            "orphan": false,
            "provided_by_hlab": false,
            "sigma_rule_id": null,
            "sigma_rule_name": null,
            "target": "all"
        }
    }
}
```

#### Human Readable Output

>```
>{
>    "count": 1,
>    "next": null,
>    "previous": null,
>    "results": [
>        {
>            "comment": "Example of whitelist for all detection engines",
>            "creation_date": "2023-07-21T15:41:20.320846Z",
>            "criteria": [
>                {
>                    "case_insensitive": true,
>                    "field": "process.hashes.sha256",
>                    "id": 3003,
>                    "operator": "eq",
>                    "value": "dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2515"
>                },
>                {
>                    "case_insensitive": true,
>                    "field": "process.commandline",
>                    "id": 3005,
>                    "operator": "contains",
>                    "value": "cmd.exe"
>                }
>            ],
>            "criteria_str": "process.hashes.sha256 eq dcaabeb77b7e02eb31269f1ee0dcbb30e92233c2a26ba22a3be02fcf01bd2515, process.commandline contains cmd.exe",
>            "enabled": true,
>            "id": 2518,
>            "last_modifier": {
>                "id": 191,
>                "username": "Harfanglab_Tech"
>            },
>            "last_update": "2023-07-21T15:41:58.736445Z",
>            "orphan": false,
>            "provided_by_hlab": false,
>            "sigma_rule_id": null,
>            "sigma_rule_name": null,
>            "target": "all"
>        }
>    ]
>}
>```

### harfanglab-whitelist-delete
***
Delete a whitelist


#### Base Command

`harfanglab-whitelist-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Whitelist identifier. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!harfanglab-whitelist-delete id=2518```
#### Human Readable Output

>None

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
| Harfanglab.Agent | unknown | Agent information | 
| Harfanglab.Agent.id | string | agent id \(DEPRECATED\) | 
| Harfanglab.status | string | Status \(DEPRECATED\) | 
