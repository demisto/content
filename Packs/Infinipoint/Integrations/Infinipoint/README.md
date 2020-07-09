Use the Infinipoint integration to retrieve security and policy incompliance events, vulnerabilities or incidents. Investigate and respond to events in real-time.
This integration was integrated and tested with version xx of Infinipoint
## Configure Infinipoint on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Infinipoint.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| access_key | Access Key | True |
| private_key | Private Key | True |
| url | Server URL \(e.g. https://console.infinipoint.io\) | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| alert_type | Fetch alerts with type | False |
| min_severity | Minimum severity of alerts to fetch | True |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| page_size | page size | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### infinipoint-get-vulnerable-devices
***
 


#### Base Command

`infinipoint-get-vulnerable-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_os |  | Optional | 
| device_risk |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Vulnerability.Devices.$device | String |  | 
| Infinipoint.Vulnerability.Devices.$host | String |  | 
| Infinipoint.Vulnerability.Devices.cve_id | Unknown |  | 
| Infinipoint.Vulnerability.Devices.device_risk | Number |  | 
| Infinipoint.Vulnerability.Devices.device_risk_type | Number |  | 
| Infinipoint.Vulnerability.Devices.software_name | Unknown |  | 
| Infinipoint.Vulnerability.Devices.vulnerability_count | Number |  | 


#### Command Example
```!infinipoint-get-vulnerable-devices device_risk=10```

#### Context Example
```
{
    "Infinipoint": {
        "Vulnerability": {
            "Devices": [
                {
                    "$device": "ea212dc8a5e39a9e8a46f6ad6e7779e4",
                    "$host": "raspberrypi",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "B8:27:EB:79:09:CA",
                    "os_name": "Linux 3.2 - 4.9",
                    "platform": "IoT",
                    "software_name": null,
                    "vulnerability_count": 63
                },
                {
                    "$device": "e0dc361e-f347-461c-98f5-6549c6c91ef9",
                    "$host": "centos-6-elad-test",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "CentOS",
                    "platform": "rhel",
                    "software_name": null,
                    "vulnerability_count": 50
                },
                {
                    "$device": "cf6e2eea-e2d1-4e89-84d7-0cd9988da8c5",
                    "$host": "Win10x64Testing",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "Microsoft Windows 10 Pro",
                    "platform": "windows",
                    "software_name": null,
                    "vulnerability_count": 1355
                },
                {
                    "$device": "cc0a66f4-d9db-4f97-b016-fdaf299aab2b",
                    "$host": "OSX-Sign-Machine",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "Mac OS X 10.15.3",
                    "platform": "darwin",
                    "software_name": null,
                    "vulnerability_count": 87
                },
                {
                    "$device": "a759eb20-1b7b-4c4f-a5d4-244f21eda54b",
                    "$host": "centos-7-elad-test",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "CentOS Linux",
                    "platform": "rhel",
                    "software_name": null,
                    "vulnerability_count": 521
                },
                {
                    "$device": "3c4f4df4-e608-4a99-a74a-772b9c84469f",
                    "$host": "ET",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "Microsoft Windows 7 Ultimate ",
                    "platform": "windows",
                    "software_name": null,
                    "vulnerability_count": 916
                },
                {
                    "$device": "892f3b11-2c56-4552-a07d-e91e7f73dd85",
                    "$host": "centos-6-test",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "CentOS",
                    "platform": "rhel",
                    "software_name": null,
                    "vulnerability_count": 137
                },
                {
                    "$device": "72fafc8d-7acf-4270-b52c-275eb806146c",
                    "$host": "JohnatanW-pc",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "Microsoft Windows 10 Home",
                    "platform": "windows",
                    "software_name": null,
                    "vulnerability_count": 413
                },
                {
                    "$device": "499328ee-1966-45a5-9bd0-67591b2eac24",
                    "$host": "elad-ubuntu-18.04-vm-dev",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "Ubuntu",
                    "platform": "ubuntu",
                    "software_name": null,
                    "vulnerability_count": 315
                },
                {
                    "$device": "2acc2421-ce1f-41d9-92c6-1d03c8f4e101",
                    "$host": "IEWIN7",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "Microsoft Windows 7 Enterprise ",
                    "platform": "windows",
                    "software_name": null,
                    "vulnerability_count": 607
                },
                {
                    "$device": "14e2b620-acfa-4f30-84a3-669a0c1b9ebb",
                    "$host": "Shay-NetBook",
                    "cve_id": null,
                    "device_risk": 10,
                    "device_risk_type": 4,
                    "mac_address": "-",
                    "os_name": "Microsoft Windows 7 Home Basic ",
                    "platform": "windows",
                    "software_name": null,
                    "vulnerability_count": 1276
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|cve_id|device_risk|device_risk_type|mac_address|os_name|platform|software_name|vulnerability_count|
>|---|---|---|---|---|---|---|---|---|---|
>| ea212dc8a5e39a9e8a46f6ad6e7779e4 | raspberrypi |  | 10 | 4 | B8:27:EB:79:09:CA | Linux 3.2 - 4.9 | IoT |  | 63 |
>| e0dc361e-f347-461c-98f5-6549c6c91ef9 | centos-6-elad-test |  | 10 | 4 | - | CentOS | rhel |  | 50 |
>| cf6e2eea-e2d1-4e89-84d7-0cd9988da8c5 | Win10x64Testing |  | 10 | 4 | - | Microsoft Windows 10 Pro | windows |  | 1355 |
>| cc0a66f4-d9db-4f97-b016-fdaf299aab2b | OSX-Sign-Machine |  | 10 | 4 | - | Mac OS X 10.15.3 | darwin |  | 87 |
>| a759eb20-1b7b-4c4f-a5d4-244f21eda54b | centos-7-elad-test |  | 10 | 4 | - | CentOS Linux | rhel |  | 521 |
>| 893e33cc-d5ad-44fb-8c0e-f92ceff86e70 | ET |  | 10 | 4 | - | Microsoft Windows 7 Ultimate  | windows |  | 923 |
>| 892f3b11-2c56-4552-a07d-e91e7f73dd85 | centos-6-test |  | 10 | 4 | - | CentOS | rhel |  | 137 |
>| 72fafc8d-7acf-4270-b52c-275eb806146c | JohnatanW-pc |  | 10 | 4 | - | Microsoft Windows 10 Home | windows |  | 413 |
>| 499328ee-1966-45a5-9bd0-67591b2eac24 | elad-ubuntu-18.04-vm-dev |  | 10 | 4 | - | Ubuntu | ubuntu |  | 315 |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET |  | 10 | 4 | - | Microsoft Windows 7 Ultimate  | windows |  | 916 |
>| 2acc2421-ce1f-41d9-92c6-1d03c8f4e101 | IEWIN7 |  | 10 | 4 | - | Microsoft Windows 7 Enterprise  | windows |  | 607 |
>| 14e2b620-acfa-4f30-84a3-669a0c1b9ebb | Shay-NetBook |  | 10 | 4 | - | Microsoft Windows 7 Home Basic  | windows |  | 1276 |


### infinipoint-get-assets-programs
***
 


#### Base Command

`infinipoint-get-assets-programs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name |  | Optional | 
| publisher |  | Optional | 
| version |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Programs.items.$device | String |  | 
| Infinipoint.Assets.Programs.items.$host | String |  | 
| Infinipoint.Assets.Programs.items.$time | Number |  | 
| Infinipoint.Assets.Programs.items.$type | String |  | 
| Infinipoint.Assets.Programs.items.name | String |  | 
| Infinipoint.Assets.Programs.items.os_type | String |  | 
| Infinipoint.Assets.Programs.items.program_exists | String |  | 
| Infinipoint.Assets.Programs.items.publisher | String |  | 
| Infinipoint.Assets.Programs.items.version | String |  | 
| Infinipoint.Assets.Programs.items.install_update_date | Date |  | 
| Infinipoint.Assets.Programs.itemsTotal | Number |  | 


#### Command Example
```!infinipoint-get-assets-programs name="nmap"```

#### Context Example
```
{
    "Infinipoint": {
        "Assets": {
            "Programs": {
                "$device": "664a5071-4178-4666-ada8-ab582b726a32",
                "$host": "elad-ubuntu-18.04-vm-dev",
                "$time": 1592719502,
                "$type": "csv",
                "install_update_date": "",
                "name": "nmap",
                "os_type": "2",
                "program_exists": "",
                "publisher": "",
                "version": "7.60-1ubuntu5"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|$time|$type|name|os_type|publisher|version|
>|---|---|---|---|---|---|---|---|
>| 5ded6c36-8eec-4a7c-b6da-10aa44300bf1 | elad-ubuntu-18.04-vm-dev | 1589206990 | csv | nmap | 2 |  | 7.60-1ubuntu5 |
>| 499328ee-1966-45a5-9bd0-67591b2eac24 | elad-ubuntu-18.04-vm-dev | 1593672687 | csv | nmap | 2 |  | 7.60-1ubuntu5 |
>| 4f16532e-d41a-4b78-9a5c-946d3d3619ca | ewexler-Z87-HD3 | 1593607283 | csv | zenmap | 2 |  | 7.80-2 |
>| 499328ee-1966-45a5-9bd0-67591b2eac24 | elad-ubuntu-18.04-vm-dev | 1593672687 | csv | zenmap | 2 | nmap | 7.60-1ubuntu5 |
>| 2acc2421-ce1f-41d9-92c6-1d03c8f4e101 | IEWIN7 | 1585037885 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| 664a5071-4178-4666-ada8-ab582b726a32 | elad-ubuntu-18.04-vm-dev | 1592719502 | csv | zenmap | 2 | nmap | 7.60-1ubuntu5 |
>| 6fd08c56-91ea-4d01-8ef4-c0a3f9bbcbe8 | EladW-LT | 1591543776 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| c9d706b6-5337-4974-8c70-8ccfd628fb4b | elad-ubuntu-18.04-vm-dev | 1584437886 | csv | nmap | 2 |  | 7.60-1ubuntu5 |
>| e5604ac5-55e9-45df-8e94-e5de381329e3 | Win10x64Testing | 1591187167 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| e07e3923-b633-489c-8591-a56a3564a1da | EladW-LT | 1592952749 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| cb9e241b-5094-46d1-91ca-8d58f6e792d5 | DESKTOP-CIK1HLS | 1593610524 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| 72fafc8d-7acf-4270-b52c-275eb806146c | JohnatanW-pc | 1593608585 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| 0979f71a-1897-43ad-9844-76330ea75292 | DESKTOP-RH7555S | 1593607019 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| c9d706b6-5337-4974-8c70-8ccfd628fb4b | elad-ubuntu-18.04-vm-dev | 1584437886 | csv | zenmap | 2 | nmap | 7.60-1ubuntu5 |
>| 5ded6c36-8eec-4a7c-b6da-10aa44300bf1 | elad-ubuntu-18.04-vm-dev | 1589206990 | csv | zenmap | 2 | nmap | 7.60-1ubuntu5 |
>| 14e2b620-acfa-4f30-84a3-669a0c1b9ebb | Shay-NetBook | 1593212250 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET | 1593610526 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| cf6e2eea-e2d1-4e89-84d7-0cd9988da8c5 | Win10x64Testing | 1591655605 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| 488f125d-d3ac-48f1-a263-5a9d6ea2638e | EladW-LT | 1589321577 | csv | Nmap 7.80 | 1 | Nmap Project | 7.80 |
>| 664a5071-4178-4666-ada8-ab582b726a32 | elad-ubuntu-18.04-vm-dev | 1592719502 | csv | nmap | 2 |  | 7.60-1ubuntu5 |


### infinipoint-get-cve
***
 


#### Base Command

`infinipoint-get-cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Cve.Details.campaign_intelligence.apt | String |  | 
| Infinipoint.Cve.Details.campaign_intelligence.description | String |  | 
| Infinipoint.Cve.Details.campaign_intelligence.targeted_countries | String |  | 
| Infinipoint.Cve.Details.campaign_intelligence.targeted_industries | String |  | 
| Infinipoint.Cve.Details.cve_description | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.ac_insuf_info | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.access_vector | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.attack_complexity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.authentication | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.availability_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.base_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.confidentiality_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.exploitability_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.impact_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.integrity_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_all_privilege | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_other_privilege | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.obtain_user_privilege | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.severity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.user_interaction_required | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v2.vector_string | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.attack_complexity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.attack_vector | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.availability_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.base_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.base_severity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.confidentiality_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.exploitability_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.impact_score | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.integrity_impact | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.privileges_required | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.scope | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.user_interaction | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.base_metric_v3.vector_string | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.attack_complexity | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.campaigns | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.device_count | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.exploitability_risk | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.exploits | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_label | String |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_level | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.risk_type | Number |  | 
| Infinipoint.Cve.Details.cve_dynamic_data.infinipoint_base_metric.trends_level | String |  | 
| Infinipoint.Cve.Details.cve_id | String |  | 
| Infinipoint.Cve.Details.cwe_description | String |  | 
| Infinipoint.Cve.Details.cwe_id | String |  | 
| Infinipoint.Cve.Details.devices.$device | String |  | 
| Infinipoint.Cve.Details.devices.device_name_string | String |  | 
| Infinipoint.Cve.Details.devices.device_os | String |  | 
| Infinipoint.Cve.Details.devices.device_risk | Number |  | 
| Infinipoint.Cve.Details.devices.map_id | String |  | 
| Infinipoint.Cve.Details.devices.vulnerableProduct | String |  | 
| Infinipoint.Cve.Details.devices.vulnerableVersion | String |  | 
| Infinipoint.Cve.Details.scan_date | Unknown |  | 
| Infinipoint.Cve.Details.software_list.cpe_name_string | String |  | 
| Infinipoint.Cve.Details.software_list.cpe_type | String |  | 
| Infinipoint.Cve.Details.top_devices.$device | String |  | 
| Infinipoint.Cve.Details.top_devices.device_name_string | String |  | 
| Infinipoint.Cve.Details.top_devices.device_os | String |  | 
| Infinipoint.Cve.Details.top_devices.device_risk | Number |  | 
| Infinipoint.Cve.Details.top_devices.map_id | String |  | 
| Infinipoint.Cve.Details.top_devices.vulnerableProduct | String |  | 
| Infinipoint.Cve.Details.top_devices.vulnerableVersion | String |  | 


#### Command Example
```!infinipoint-get-cve cve_id="CVE-2010-1297"```

#### Context Example
```
{
    "Infinipoint": {
        "Cve": {
            "Details": {
                "campaign_intelligence": [
                    {
                        "apt": "Publicly Available Exploit",
                        "description": "Adobe Acrobat Reader and Flash Player - 'newclass' Invalid Pointer (Author:Abysssec)",
                        "targeted_countries": [
                            ""
                        ],
                        "targeted_industries": [
                            ""
                        ]
                    },
                    {
                        "apt": "Publicly Available Exploit",
                        "description": "Adobe Flash / Reader - Live Malware (Author:anonymous)",
                        "targeted_countries": [
                            ""
                        ],
                        "targeted_industries": [
                            ""
                        ]
                    },
                    {
                        "apt": "Publicly Available Exploit",
                        "description": "Adobe Flash Player - 'newfunction' Invalid Pointer Use (Metasploit) (1) (Author:Metasploit)",
                        "targeted_countries": [
                            ""
                        ],
                        "targeted_industries": [
                            ""
                        ]
                    }
                ],
                "cve_description": "Adobe Flash Player before 9.0.277.0 and 10.x before 10.1.53.64; Adobe AIR before 2.0.2.12610; and Adobe Reader and Acrobat 9.x before 9.3.3, and 8.x before 8.2.3 on Windows and Mac OS X, allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted SWF content, related to authplay.dll and the ActionScript Virtual Machine 2 (AVM2) newfunction instruction, as exploited in the wild in June 2010.",
                "cve_dynamic_data": {
                    "base_metric_v2": {
                        "ac_insuf_info": "None",
                        "access_vector": "NETWORK",
                        "attack_complexity": "MEDIUM",
                        "authentication": "NONE",
                        "availability_impact": "COMPLETE",
                        "base_score": "9.3",
                        "confidentiality_impact": "COMPLETE",
                        "exploitability_score": "8.6",
                        "impact_score": "10.0",
                        "integrity_impact": "COMPLETE",
                        "obtain_all_privilege": "False",
                        "obtain_other_privilege": "False",
                        "obtain_user_privilege": "False",
                        "severity": "HIGH",
                        "user_interaction_required": "True",
                        "vector_string": "AV:N/AC:M/Au:N/C:C/I:C/A:C"
                    },
                    "base_metric_v3": {
                        "attack_complexity": "None",
                        "attack_vector": "None",
                        "availability_impact": "None",
                        "base_score": "None",
                        "base_severity": "None",
                        "confidentiality_impact": "None",
                        "exploitability_score": "None",
                        "impact_score": "None",
                        "integrity_impact": "None",
                        "privileges_required": "None",
                        "scope": "None",
                        "user_interaction": "None",
                        "vector_string": "None"
                    },
                    "infinipoint_base_metric": {
                        "attack_complexity": "10",
                        "campaigns": 3,
                        "device_count": 1,
                        "exploitability_risk": "8.6",
                        "exploits": 3,
                        "risk_label": "Critical",
                        "risk_level": 10,
                        "risk_type": 4,
                        "trends_level": "4.46"
                    }
                },
                "cve_id": "CVE-2010-1297",
                "cwe_description": "None",
                "cwe_id": "NVD-CWE-noinfo",
                "devices": [
                    {
                        "$device": "14e2b620-acfa-4f30-84a3-669a0c1b9ebb",
                        "device_name_string": "Shay-NetBook",
                        "device_os": "Microsoft Windows 7 Home Basic ",
                        "device_risk": 10,
                        "is_managed": true,
                        "map_id": "14e2b620-acfa-4f30-84a3-669a0c1b9ebbCVE-2010-1297",
                        "vulnerableProduct": "Adobe Flash Player 10 Plugin",
                        "vulnerableVersion": "10.0.45.2"
                    }
                ],
                "scan_date": null,
                "software_list": [
                    {
                        "cpe_name_string": "Adobe Flash Player 10 Plugin 10.0.45.2",
                        "cpe_strings": [],
                        "cpe_type": "APP_ONLY"
                    }
                ],
                "top_devices": [
                    {
                        "$device": "14e2b620-acfa-4f30-84a3-669a0c1b9ebb",
                        "device_name_string": "Shay-NetBook",
                        "device_os": "Microsoft Windows 7 Home Basic ",
                        "device_risk": 10,
                        "is_managed": true,
                        "map_id": "14e2b620-acfa-4f30-84a3-669a0c1b9ebbCVE-2010-1297",
                        "vulnerableProduct": "Adobe Flash Player 10 Plugin",
                        "vulnerableVersion": "10.0.45.2"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|campaign_intelligence|cve_description|cve_dynamic_data|cve_id|cwe_description|cwe_id|devices|scan_date|software_list|top_devices|
>|---|---|---|---|---|---|---|---|---|---|
>| {'apt': 'Publicly Available Exploit', 'description': "Adobe Acrobat Reader and Flash Player - 'newclass' Invalid Pointer (Author:Abysssec)", 'targeted_countries': [''], 'targeted_industries': ['']},<br/>{'apt': 'Publicly Available Exploit', 'description': 'Adobe Flash / Reader - Live Malware (Author:anonymous)', 'targeted_countries': [''], 'targeted_industries': ['']},<br/>{'apt': 'Publicly Available Exploit', 'description': "Adobe Flash Player - 'newfunction' Invalid Pointer Use (Metasploit) (1) (Author:Metasploit)", 'targeted_countries': [''], 'targeted_industries': ['']} | Adobe Flash Player before 9.0.277.0 and 10.x before 10.1.53.64; Adobe AIR before 2.0.2.12610; and Adobe Reader and Acrobat 9.x before 9.3.3, and 8.x before 8.2.3 on Windows and Mac OS X, allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via crafted SWF content, related to authplay.dll and the ActionScript Virtual Machine 2 (AVM2) newfunction instruction, as exploited in the wild in June 2010. | infinipoint_base_metric: {"device_count": 1, "risk_level": 10, "attack_complexity": "10", "campaigns": 3, "exploits": 3, "trends_level": "4.46", "exploitability_risk": "8.6", "risk_label": "Critical", "risk_type": 4}<br/>base_metric_v2: {"vector_string": "AV:N/AC:M/Au:N/C:C/I:C/A:C", "access_vector": "NETWORK", "attack_complexity": "MEDIUM", "authentication": "NONE", "confidentiality_impact": "COMPLETE", "integrity_impact": "COMPLETE", "availability_impact": "COMPLETE", "base_score": "9.3", "severity": "HIGH", "exploitability_score": "8.6", "impact_score": "10.0", "ac_insuf_info": "None", "obtain_all_privilege": "False", "obtain_other_privilege": "False", "obtain_user_privilege": "False", "user_interaction_required": "True"}<br/>base_metric_v3: {"vector_string": "None", "attack_vector": "None", "attack_complexity": "None", "privileges_required": "None", "user_interaction": "None", "scope": "None", "confidentiality_impact": "None", "integrity_impact": "None", "availability_impact": "None", "base_score": "None", "base_severity": "None", "exploitability_score": "None", "impact_score": "None"} | CVE-2010-1297 | None | NVD-CWE-noinfo | {'$device': '14e2b620-acfa-4f30-84a3-669a0c1b9ebb', 'device_name_string': 'Shay-NetBook', 'vulnerableProduct': 'Adobe Flash Player 10 Plugin', 'vulnerableVersion': '10.0.45.2', 'device_risk': 10, 'map_id': '14e2b620-acfa-4f30-84a3-669a0c1b9ebbCVE-2010-1297', 'device_os': 'Microsoft Windows 7 Home Basic ', 'is_managed': True} |  | {'cpe_name_string': 'Adobe Flash Player 10 Plugin 10.0.45.2', 'cpe_type': 'APP_ONLY', 'cpe_strings': []} | {'$device': '14e2b620-acfa-4f30-84a3-669a0c1b9ebb', 'device_name_string': 'Shay-NetBook', 'vulnerableProduct': 'Adobe Flash Player 10 Plugin', 'vulnerableVersion': '10.0.45.2', 'device_risk': 10, 'map_id': '14e2b620-acfa-4f30-84a3-669a0c1b9ebbCVE-2010-1297', 'device_os': 'Microsoft Windows 7 Home Basic ', 'is_managed': True} |


### infinipoint-get-device
***
 


#### Base Command

`infinipoint-get-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host |  | Optional | 
| osType | choose a OS type - 1 = Windows \| 2 = Linux \| 4 = macOS | Optional | 
| osName | Device operating system full name e.g. windows-10.0.18363.836 | Optional | 
| status | Device current status:- 0 = Offline \| 1 = Online | Optional | 
| agentVersion |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Devices.agentVersion | String |  | 
| Infinipoint.Devices.clientType | Number |  | 
| Infinipoint.Devices.discoveryId | String |  | 
| Infinipoint.Devices.domain | String |  | 
| Infinipoint.Devices.edge | Number |  | 
| Infinipoint.Devices.ftDidRespond | Number |  | 
| Infinipoint.Devices.ftIsSuccessful | Number |  | 
| Infinipoint.Devices.ftResult | String |  | 
| Infinipoint.Devices.gatewayIp | Number |  | 
| Infinipoint.Devices.gatewayMACAddress | Date |  | 
| Infinipoint.Devices.host | String |  | 
| Infinipoint.Devices.id | String |  | 
| Infinipoint.Devices.ip | Number |  | 
| Infinipoint.Devices.lastSeen | Date |  | 
| Infinipoint.Devices.macAddress | String |  | 
| Infinipoint.Devices.networkId | Number |  | 
| Infinipoint.Devices.networks.alias | String |  | 
| Infinipoint.Devices.networks.cidr | String |  | 
| Infinipoint.Devices.networks.gatewayIp | Number |  | 
| Infinipoint.Devices.networks.gatewayMACAddress | Date |  | 
| Infinipoint.Devices.osName | String |  | 
| Infinipoint.Devices.osType | Number |  | 
| Infinipoint.Devices.policyVersion | String |  | 
| Infinipoint.Devices.productType | String |  | 
| Infinipoint.Devices.regDate | Date |  | 
| Infinipoint.Devices.status | Number |  | 
| Infinipoint.Devices.statusCode | Unknown |  | 
| Infinipoint.Devices.statusDescription | Unknown |  | 
| Infinipoint.Devices.supportId | Unknown |  | 
| Infinipoint.Devices.tags.color | String |  | 
| Infinipoint.Devices.tags.name | String |  | 
| Infinipoint.Devices.tags.tagId | String |  | 
| Infinipoint.Devices.uniqueHostname | String |  | 


#### Command Example
```!infinipoint-get-device osType=2```

#### Context Example
```
{
    "Infinipoint": {
        "Devices": {
            "agentVersion": "3.200.23.0",
            "clientType": 0,
            "discoveryId": "8136071132160605067",
            "domain": "us-central1-a.c.riscale.internal",
            "edge": true,
            "ftDidRespond": false,
            "ftIsSuccessful": false,
            "ftResult": "",
            "gatewayIp": 176160769,
            "gatewayMACAddress": "42:01:0A:80:00:01",
            "host": "debian-9-mirco1",
            "id": "dd16d24a-0af6-4500-9e20-86650ad0e923",
            "ip": 176160778,
            "lastSeen": "2020-07-02T09:39:35.990466Z",
            "macAddress": "42:01:0A:80:00:0A",
            "networkAlias": "GCP",
            "networkId": 3,
            "networks": [
                {
                    "alias": "GCP",
                    "cidr": "10.128.0.1/32",
                    "gatewayIp": 176160769,
                    "gatewayMACAddress": "42:01:0A:80:00:01"
                }
            ],
            "osName": "linux-4.9.0-9-amd64",
            "osType": 2,
            "policyVersion": "3.200.23.0",
            "productType": "Cloud Compute",
            "regDate": "2020-02-02T12:19:27.575088Z",
            "status": 1,
            "statusCode": null,
            "statusDescription": null,
            "supportId": null,
            "tags": [
                {
                    "color": "1dc927",
                    "name": "All",
                    "tagId": "e2b98b30-c970-4510-ad9c-5a079f8ecf45"
                },
                {
                    "color": "ac1111",
                    "name": "gilad-test",
                    "tagId": "8a7fa546-3776-4b9f-acca-f757851a2f2d"
                }
            ],
            "uniqueHostname": "debian-9-mirco1-ABk"
        }
    }
}
```

#### Human Readable Output

>### Results
>|agentVersion|clientType|discoveryId|domain|edge|ftDidRespond|ftIsSuccessful|ftResult|gatewayIp|gatewayMACAddress|host|id|ip|lastSeen|macAddress|networkAlias|networkId|networks|osName|osType|policyVersion|productType|regDate|status|statusCode|statusDescription|supportId|tags|uniqueHostname|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3.108.262.0 | 0 | i-005b0c157360b8117 |  | true | false | false |  | -1407246335 | 0E:F6:71:1A:C2:8C | amazon-linux-ami-2 | 06bea05a-adef-4009-8de5-9eb2e23ac4fb | -1407244568 | 2020-05-03T12:11:18.839134Z | 0E:E7:D3:3E:02:48 | AWS | 2 | {'alias': 'AWS', 'cidr': '172.31.32.1/20', 'gatewayIp': -1407246335, 'gatewayMACAddress': '0E:F6:71:1A:C2:8C'} | linux-4.14.114-105.126.amzn2.x86_64-x86_64 | 2 | 3.108.262.342 | Cloud Compute | 2020-02-02T12:19:22.988111Z | 0 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | amazon-linux-ami-2-+Fm |
>| 3.108.262.0 | 0 |  |  | true | false | false |  | -1062726398 | 00:50:56:EF:7A:AD | elad-ubuntu-18.04-vm-dev | 5ded6c36-8eec-4a7c-b6da-10aa44300bf1 | -1062726194 | 2020-04-25T14:40:14.120294Z | 00:0C:29:DE:53:4F |  | 10 | {'alias': '', 'cidr': '192.168.21.2/24', 'gatewayIp': -1062726398, 'gatewayMACAddress': '00:50:56:EF:7A:AD'} | linux-5.3.0-46-generic-x86_64 | 2 | 3.108.262.333 | Computer | 2020-02-02T12:21:43.554381Z | 0 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | elad-ubuntu-18.04-vm-dev-hzR |
>| 3.200.23.0 | 0 |  |  | true | false | false |  | -1062731519 | 6C:2E:85:FD:31:2C | ewexler-Z87-HD3 | 4f16532e-d41a-4b78-9a5c-946d3d3619ca | -1062731482 | 2020-07-02T09:37:01.0189Z | 94:DE:80:B8:03:67 | elad-home | 15 | {'alias': 'elad-home', 'cidr': '192.168.1.1/24', 'gatewayIp': -1062731519, 'gatewayMACAddress': '6C:2E:85:FD:31:2C'} | linux-5.3.0-59-generic-x86_64 | 2 | 3.200.23.0 | Computer | 2020-02-02T13:02:42.382167Z | 1 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | ewexler-Z87-HD3-8QI |
>| 3.108.262.0 | 0 | 1870095364949893510 |  | false | false | false |  | -1408172031 | 02:42:48:2F:E6:85 | 5e1f14440fc1 | 1192d50d-df26-4ef3-8ff3-688ff6931fe5 | -1408172028 | 2020-04-05T19:14:38.693456Z | 02:42:AC:11:00:04 | GCP-containers | 12 | {'alias': 'GCP-containers', 'cidr': '172.17.0.1/16', 'gatewayIp': -1408172031, 'gatewayMACAddress': '02:42:48:2F:E6:85'} | linux-5.0.0-1021-gcp-x86_64 | 2 | 3.108.262.0 | Cloud Compute | 2020-03-01T18:49:54.800255Z | 0 | 101 | Execution ended successfully | 7a992f9f-9830-4c75-b140-ffa0b374d515 | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | 5e1f14440fc1-tTM |
>| 3.200.23.0 | 0 |  |  | true | false | false |  | -1062726398 | 00:50:56:EF:7A:AD | elad-ubuntu-18.04-vm-dev | 499328ee-1966-45a5-9bd0-67591b2eac24 | -1062726163 | 2020-07-02T09:41:36.673307Z | 00:0C:29:DE:53:4F |  | 10 | {'alias': '', 'cidr': '192.168.21.2/24', 'gatewayIp': -1062726398, 'gatewayMACAddress': '00:50:56:EF:7A:AD'} | linux-5.3.0-59-generic-x86_64 | 2 | 3.200.23.0 | Computer | 2020-06-22T21:08:12.431545Z | 1 |  |  |  |  | elad-ubuntu-18.04-vm-dev-sJ4 |
>| 3.108.262.0 | 0 | 6573583345793141635 | europe-west2-c.c.riscale.internal | true | false | false |  | 177864705 | 42:01:0A:9A:00:01 | centos-7-test2 | 1f6c8338-0d7c-413f-bd5a-6a01e1f4262d | 177864706 | 2020-03-21T22:58:06.157757Z | 42:01:0A:9A:00:02 |  | 55 | {'alias': '', 'cidr': '10.154.0.1/32', 'gatewayIp': 177864705, 'gatewayMACAddress': '42:01:0A:9A:00:01'} | linux-3.10.0-1062.1.2.el7.x86_64-x86_64 | 2 | 3.108.262.0 | Cloud Compute | 2020-02-02T13:00:06.482643Z | 0 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | centos-7-test2-jRX |
>| 3.200.3.0 | 0 |  |  | true | false | false |  | -1062726398 | 00:50:56:EF:7A:AD | elad-ubuntu-18.04-vm-dev | 664a5071-4178-4666-ada8-ab582b726a32 | -1062726168 | 2020-06-22T11:52:27.914862Z | 00:0C:29:DE:53:4F |  | 10 | {'alias': '', 'cidr': '192.168.21.2/24', 'gatewayIp': -1062726398, 'gatewayMACAddress': '00:50:56:EF:7A:AD'} | linux-5.3.0-59-generic-x86_64 | 2 | 3.200.3.0 | Computer | 2020-04-25T14:47:03.119983Z | 0 |  |  |  |  | elad-ubuntu-18.04-vm-dev-Y3q |
>| 3.108.262.0 | 1 | 1870095364949893510 |  | false | false | false |  | -1408172031 | 02:42:48:2F:E6:85 | c072e5c5ccf8 | 3048dd12-844a-4dc9-8162-d5425f17e567 | -1408172026 | 2020-04-05T19:16:52.452423Z | 02:42:AC:11:00:06 | GCP-containers | 12 | {'alias': 'GCP-containers', 'cidr': '172.17.0.1/16', 'gatewayIp': -1408172031, 'gatewayMACAddress': '02:42:48:2F:E6:85'} | linux-5.0.0-1021-gcp-x86_64 | 2 | 3.108.262.0 | Cloud Compute | 2020-03-01T15:01:25.08192Z | 0 | 101 | Execution ended successfully | 9c4b0310-ecc9-43ea-9a1e-1d8d2e3cd01f |  | c072e5c5ccf8-v+K |
>| 3.200.13.0 | 0 |  |  | true | false | false |  | -1408172031 | 02:42:9F:C0:9F:98 | a28aacf4c220 | 97e595cd-23a5-4901-8ee1-8fd60b1d04b2 | -1408172030 | 2020-06-24T09:13:25.783585Z | 02:42:AC:11:00:02 |  | 61595 | {'alias': '', 'cidr': '172.17.0.1/16', 'gatewayIp': -1408172031, 'gatewayMACAddress': '02:42:9F:C0:9F:98'} | linux-4.19.76-linuxkit-x86_64 | 2 | 3.200.13.0 | Computer | 2020-02-02T12:28:42.152906Z | 0 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | a28aacf4c220-5Fc |
>| 3.108.262.0 | 0 | 1870095364949893510 |  | false | false | false |  | -1408172031 | 02:42:48:2F:E6:85 | c19f7ff5251e | 5cf9605c-a35c-4d30-a6c8-ef6f48a4b455 | -1408172027 | 2020-04-05T19:10:56.074066Z | 02:42:AC:11:00:05 | GCP-containers | 12 | {'alias': 'GCP-containers', 'cidr': '172.17.0.1/16', 'gatewayIp': -1408172031, 'gatewayMACAddress': '02:42:48:2F:E6:85'} | linux-5.0.0-1021-gcp-x86_64 | 2 | 3.108.262.0 | Cloud Compute | 2020-03-10T13:06:15.90244Z | 0 | 101 | Execution ended successfully | 75105b0f-f75c-4071-9058-8a3657f84af4 | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | c19f7ff5251e-5SV |
>| 3.200.23.0 | 0 | i-0e27b9dbff2b01469 |  | true | false | false |  | -1407246335 | 0E:F6:71:1A:C2:8C | amazon-linux-ami | c06bc1c2-a6b2-43f6-bfa3-6d1291eab395 | -1407242661 | 2020-07-02T09:39:00.205866Z | 0E:4B:32:9F:24:72 | AWS | 2 | {'alias': 'AWS', 'cidr': '172.31.32.1/20', 'gatewayIp': -1407246335, 'gatewayMACAddress': '0E:F6:71:1A:C2:8C'} | linux-4.14.121-85.96.amzn1.x86_64-x86_64 | 2 | 3.200.23.0 | Cloud Compute | 2020-02-02T12:38:47.076825Z | 1 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | amazon-linux-ami-edG |
>| 3.200.23.0 | 0 | 529570513462491545 | us-east1-b.c.riscale.internal | true | false | false |  | 177078273 | 42:01:0A:8E:00:01 | centos-6-test | 892f3b11-2c56-4552-a07d-e91e7f73dd85 | 177078302 | 2020-07-02T09:39:11.232876Z | 42:01:0A:8E:00:1E | GCP | 4 | {'alias': 'GCP', 'cidr': '10.142.0.1/32', 'gatewayIp': 177078273, 'gatewayMACAddress': '42:01:0A:8E:00:01'} | linux-2.6.32-754.23.1.el6.x86_64-x86_64 | 2 | 3.200.23.0 | Cloud Compute | 2020-02-02T12:59:59.055377Z | 1 |  |  |  | {'color': 'ac1111', 'name': 'gilad-test', 'tagId': '8a7fa546-3776-4b9f-acca-f757851a2f2d'} | centos-6-test-d5C |
>| 3.200.23.0 | 0 | 6812566699199864028 | us-east1-b.c.riscale.internal | true | false | false |  | 177078273 | 42:01:0A:8E:00:01 | centos-7-elad-test | a759eb20-1b7b-4c4f-a5d4-244f21eda54b | 177078297 | 2020-07-02T09:39:11.232876Z | 42:01:0A:8E:00:19 | GCP | 4 | {'alias': 'GCP', 'cidr': '10.142.0.1/32', 'gatewayIp': 177078273, 'gatewayMACAddress': '42:01:0A:8E:00:01'} | linux-3.10.0-957.10.1.el7.x86_64-x86_64 | 2 | 3.200.23.0 | Cloud Compute | 2020-02-02T12:21:01.161879Z | 1 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | centos-7-elad-test-GJJ |
>| 3.200.23.0 | 0 | 7724944119419517947 | us-central1-a.c.riscale.internal | true | false | false |  | 176160769 | 42:01:0A:80:00:01 | debian-9-micro | 8a31860a-4b7b-4f88-9f4b-288ed9155654 | 176160777 | 2020-07-02T09:39:29.033474Z | 42:01:0A:80:00:09 | GCP | 3 | {'alias': 'GCP', 'cidr': '10.128.0.1/32', 'gatewayIp': 176160769, 'gatewayMACAddress': '42:01:0A:80:00:01'} | linux-4.9.0-9-amd64 | 2 | 3.200.23.0 | Cloud Compute | 2020-02-02T12:53:06.566138Z | 1 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | debian-9-micro-0OG |
>|  | 2 | 8930e62a69cfad07bc46935ebde36ea2 |  | false | false | false |  | -1062731519 | 60:38:E0:D6:44:D8 | raspberrypi | 34bfbdb3-e33c-4242-8f2d-9568b2201c95 | -1062731406 | 2020-06-17T14:07:11.466194Z | B8:27:EB:79:09:CA | infinipoint-office | 1 | {'alias': 'infinipoint-office', 'cidr': '192.168.1.1/24', 'gatewayIp': -1062731519, 'gatewayMACAddress': '60:38:E0:D6:44:D8'} |  | 2 |  | IoT | 2020-06-17T14:07:11.466194Z | 2 |  |  |  |  |  |
>|  | 2 | 2171a42545d2cc4fc805b65ccb8b0535 |  | false | false | false |  | -1062731519 | 60:38:E0:D6:44:D8 | linksysrouter | b7167613-83a1-457c-8e5b-99c89f74f240 | -1062731519 | 2020-06-18T15:54:31.632438Z | 60:38:E0:D6:44:D8 | infinipoint-office | 1 | {'alias': 'infinipoint-office', 'cidr': '192.168.1.1/24', 'gatewayIp': -1062731519, 'gatewayMACAddress': '60:38:E0:D6:44:D8'} |  | 2 |  | Computer | 2020-06-18T15:54:31.632438Z | 2 |  |  |  |  |  |
>| 3.108.260.0 | 0 |  |  | true | false | false |  | -1062726398 | 00:50:56:EF:7A:AD | elad-ubuntu-18.04-vm-dev | c9d706b6-5337-4974-8c70-8ccfd628fb4b | -1062726212 | 2020-03-11T11:32:28.700514Z | 00:0C:29:6B:9C:EA |  | 10 | {'alias': '', 'cidr': '192.168.21.2/24', 'gatewayIp': -1062726398, 'gatewayMACAddress': '00:50:56:EF:7A:AD'} | linux-5.3.0-40-generic-x86_64 | 2 | 3.108.260.0 | Computer | 2020-02-21T21:55:57.294519Z | 0 |  |  |  |  | elad-ubuntu-18.04-vm-dev-e89 |
>| 3.108.262.0 | 1 | 1870095364949893510 |  | false | false | false |  | -1408172031 | 02:42:48:2F:E6:85 | 7b39c01c3db9 | f450940e-cd21-4cf5-9a7a-f33313c79bc6 | -1408172029 | 2020-04-05T19:11:46.332307Z | 02:42:AC:11:00:03 | GCP-containers | 12 | {'alias': 'GCP-containers', 'cidr': '172.17.0.1/16', 'gatewayIp': -1408172031, 'gatewayMACAddress': '02:42:48:2F:E6:85'} | linux-5.0.0-1021-gcp-x86_64 | 2 | 3.108.262.0 | Cloud Compute | 2020-02-02T12:40:41.869208Z | 0 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | 7b39c01c3db9-plL |
>| 3.108.262.0 | 0 | 1870095364949893510 |  | false | false | false |  | -1408172031 | 02:42:48:2F:E6:85 | 489ca43a6ab0 | 0408fb89-35d1-4096-b62f-8b7849e948ec | -1408172025 | 2020-04-05T19:11:50.651656Z | 02:42:AC:11:00:07 | GCP-containers | 12 | {'alias': 'GCP-containers', 'cidr': '172.17.0.1/16', 'gatewayIp': -1408172031, 'gatewayMACAddress': '02:42:48:2F:E6:85'} | linux-5.0.0-1021-gcp-x86_64 | 2 | 3.108.262.0 | Cloud Compute | 2020-03-01T16:36:54.236988Z | 0 | 101 | Execution ended successfully | c4383088-90f7-4290-9e0b-137d43a8f11f |  | 489ca43a6ab0-lzr |
>| 3.200.23.0 | 0 | 8509477006202880880 | us-central1-a.c.riscale.internal | true | false | false |  | 176160769 | 42:01:0A:80:00:01 | redhat-6-elad | b213b9be-ea2f-4736-9427-8062c3f8e9ea | 176160792 | 2020-07-02T09:38:45.461587Z | 42:01:0A:80:00:18 | GCP | 3 | {'alias': 'GCP', 'cidr': '10.128.0.1/32', 'gatewayIp': 176160769, 'gatewayMACAddress': '42:01:0A:80:00:01'} | linux-2.6.32-754.24.3.el6.x86_64-x86_64 | 2 | 3.200.23.0 | Cloud Compute | 2020-02-02T13:03:02.915797Z | 1 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'},<br/>{'color': 'ac1111', 'name': 'gilad-test', 'tagId': '8a7fa546-3776-4b9f-acca-f757851a2f2d'} | redhat-6-elad-nfc |
>| 3.200.23.0 | 0 | 4702748514226446332 | us-east1-b.c.riscale.internal | true | false | false |  | 177078273 | 42:01:0A:8E:00:01 | centos-6-elad-test | e0dc361e-f347-461c-98f5-6549c6c91ef9 | 177078296 | 2020-07-02T09:38:45.461587Z | 42:01:0A:8E:00:18 | GCP | 4 | {'alias': 'GCP', 'cidr': '10.142.0.1/32', 'gatewayIp': 177078273, 'gatewayMACAddress': '42:01:0A:8E:00:01'} | linux-2.6.32-754.24.2.el6.x86_64-x86_64 | 2 | 3.200.23.0 | Cloud Compute | 2020-02-02T12:19:32.998054Z | 1 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'} | centos-6-elad-test-nZW |
>| 3.200.23.0 | 0 | 8136071132160605067 | us-central1-a.c.riscale.internal | true | false | false |  | 176160769 | 42:01:0A:80:00:01 | debian-9-mirco1 | dd16d24a-0af6-4500-9e20-86650ad0e923 | 176160778 | 2020-07-02T09:39:35.990466Z | 42:01:0A:80:00:0A | GCP | 3 | {'alias': 'GCP', 'cidr': '10.128.0.1/32', 'gatewayIp': 176160769, 'gatewayMACAddress': '42:01:0A:80:00:01'} | linux-4.9.0-9-amd64 | 2 | 3.200.23.0 | Cloud Compute | 2020-02-02T12:19:27.575088Z | 1 |  |  |  | {'color': '1dc927', 'name': 'All', 'tagId': 'e2b98b30-c970-4510-ad9c-5a079f8ecf45'},<br/>{'color': 'ac1111', 'name': 'gilad-test', 'tagId': '8a7fa546-3776-4b9f-acca-f757851a2f2d'} | debian-9-mirco1-ABk |


### infinipoint-get-tag
***
 


#### Base Command

`infinipoint-get-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Tags.color | String |  | 
| Infinipoint.Tags.count | Number |  | 
| Infinipoint.Tags.description | String |  | 
| Infinipoint.Tags.name | String |  | 
| Infinipoint.Tags.tagId | String |  | 
| Infinipoint.Tags.type | Number |  | 


#### Command Example
```!infinipoint-get-tag name=et```

#### Context Example
```
{
    "Infinipoint": {
        "Tags": {
            "color": "e3fe0e",
            "count": 0,
            "description": "et",
            "name": "et",
            "tagId": "ecf10d8d-b790-4dde-b1b9-f921b84af8d8",
            "type": 0
        }
    }
}
```

#### Human Readable Output

>### Results
>|color|count|description|name|tagId|type|
>|---|---|---|---|---|---|
>| e3fe0e | 0 | et | et | ecf10d8d-b790-4dde-b1b9-f921b84af8d8 | 0 |


### infinipoint-get-networks
***
 


#### Base Command

`infinipoint-get-networks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alias |  | Optional | 
| gateway_ip |  | Optional | 
| cidr |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Networks.Info.alias | String |  | 
| Infinipoint.Networks.Info.cidr | String |  | 
| Infinipoint.Networks.Info.city | Unknown |  | 
| Infinipoint.Networks.Info.country | Unknown |  | 
| Infinipoint.Networks.Info.cronExpression | String |  | 
| Infinipoint.Networks.Info.dnsName | String |  | 
| Infinipoint.Networks.Info.externalIp | Number |  | 
| Infinipoint.Networks.Info.firstSeen | Date |  | 
| Infinipoint.Networks.Info.floor | Unknown |  | 
| Infinipoint.Networks.Info.gatewayIp | Number |  | 
| Infinipoint.Networks.Info.gatewayMacAddress | String |  | 
| Infinipoint.Networks.Info.ip | Number |  | 
| Infinipoint.Networks.Info.ipSubnetMask | Number |  | 
| Infinipoint.Networks.Info.lastRun | Date |  | 
| Infinipoint.Networks.Info.lastSeen | Date |  | 
| Infinipoint.Networks.Info.latitude | Unknown |  | 
| Infinipoint.Networks.Info.longitude | Unknown |  | 
| Infinipoint.Networks.Info.managedCount | Number |  | 
| Infinipoint.Networks.Info.name | String |  | 
| Infinipoint.Networks.Info.networkId | Number |  | 
| Infinipoint.Networks.Info.nextRun | Date |  | 
| Infinipoint.Networks.Info.onPrem | Number |  | 
| Infinipoint.Networks.Info.room | Unknown |  | 
| Infinipoint.Networks.Info.scheduleStatus | Number |  | 
| Infinipoint.Networks.Info.state | Unknown |  | 
| Infinipoint.Networks.Info.street | Unknown |  | 
| Infinipoint.Networks.Info.type | Number |  | 
| Infinipoint.Networks.Info.unmanagedCount | Number |  | 


#### Command Example
```!infinipoint-get-networks alias=GCP```

#### Context Example
```
{
    "Infinipoint": {
        "Networks": {
            "Info": {
                "alias": "GCP",
                "cidr": "10.142.0.1/32",
                "city": null,
                "country": null,
                "cronExpression": "",
                "dnsName": "",
                "externalIp": 0,
                "firstSeen": "2020-02-02T12:18:33.341661Z",
                "floor": "",
                "gatewayIp": 177078273,
                "gatewayMacAddress": "42:01:0A:8E:00:01",
                "hidden": false,
                "ip": 0,
                "ipSubnetMask": 0,
                "lastRun": "2020-06-24T14:23:11.840214Z",
                "lastSeen": "2020-07-02T09:11:49.867708Z",
                "latitude": null,
                "longitude": null,
                "managedCount": 4,
                "name": "",
                "networkId": 4,
                "nextRun": "1970-01-01T00:00:00Z",
                "onPrem": false,
                "room": "",
                "scheduleStatus": 3,
                "state": null,
                "street": null,
                "type": 0,
                "unmanagedCount": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|alias|cidr|city|country|cronExpression|dnsName|externalIp|firstSeen|floor|gatewayIp|gatewayMacAddress|hidden|ip|ipSubnetMask|lastRun|lastSeen|latitude|longitude|managedCount|name|networkId|nextRun|onPrem|room|scheduleStatus|state|street|type|unmanagedCount|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| GCP | 10.128.0.1/32 |  |  |  |  | 0 | 2020-02-02T12:18:28.001042Z |  | 176160769 | 42:01:0A:80:00:01 | false | 0 | 0 | 2020-02-02T15:21:06.156905Z | 2020-07-02T09:15:50.131166Z |  |  | 3 |  | 3 | 1970-01-01T00:00:00Z | false |  | 3 |  |  | 0 | 0 |
>| GCP | 10.142.0.1/32 |  |  |  |  | 0 | 2020-02-02T12:18:33.341661Z |  | 177078273 | 42:01:0A:8E:00:01 | false | 0 | 0 | 2020-06-24T14:23:11.840214Z | 2020-07-02T09:11:49.867708Z |  |  | 4 |  | 4 | 1970-01-01T00:00:00Z | false |  | 3 |  |  | 0 | 0 |


### infinipoint-get-assets-hardware
***
 


#### Base Command

`infinipoint-get-assets-hardware`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host |  | Optional | 
| os_type | choose a OS type - 1 = Windows \| 2 = Linux \| 4 = macOS | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Hardware.$device | String |  | 
| Infinipoint.Assets.Hardware.$host | String |  | 
| Infinipoint.Assets.Hardware.$time | Number |  | 
| Infinipoint.Assets.Hardware.$type | String |  | 
| Infinipoint.Assets.Hardware.cpu_brand | String |  | 
| Infinipoint.Assets.Hardware.cpu_logical_cores | String |  | 
| Infinipoint.Assets.Hardware.cpu_physical_cores | String |  | 
| Infinipoint.Assets.Hardware.hardware_model | String |  | 
| Infinipoint.Assets.Hardware.hardware_serial | String |  | 
| Infinipoint.Assets.Hardware.hardware_vendor | String |  | 
| Infinipoint.Assets.Hardware.kernel_version | String |  | 
| Infinipoint.Assets.Hardware.os_build | String |  | 
| Infinipoint.Assets.Hardware.os_name | String |  | 
| Infinipoint.Assets.Hardware.os_patch_version | String |  | 
| Infinipoint.Assets.Hardware.os_type | String |  | 
| Infinipoint.Assets.Hardware.os_version | String |  | 
| Infinipoint.Assets.Hardware.physical_memory | String |  | 
| Infinipoint.Assets.Hardware.platform | String |  | 
| Infinipoint.Assets.Hardware.user | String |  | 


#### Command Example
```!infinipoint-get-assets-hardware os_type=2```

#### Context Example
```
{
    "Infinipoint": {
        "Assets": {
            "Hardware": {
                "$device": "0408fb89-35d1-4096-b62f-8b7849e948ec",
                "$host": "489ca43a6ab0",
                "$time": 1586868290,
                "$type": "csv",
                "cpu_brand": "Intel(R) Xeon(R) CPU @ 2.30GHz",
                "cpu_logical_cores": "1",
                "cpu_physical_cores": "1",
                "hardware_model": "",
                "hardware_serial": "",
                "hardware_vendor": "",
                "kernel_version": "4.9.0-9-amd64",
                "os_build": "",
                "os_name": "Ubuntu",
                "os_patch_version": "",
                "os_type": "2",
                "os_version": "9 (stretch)",
                "physical_memory": "1.0",
                "platform": "ubuntu",
                "user": ""
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|$time|$type|hardware_model|hardware_serial|hardware_vendor|os_build|os_name|os_patch_version|os_type|platform|user|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1192d50d-df26-4ef3-8ff3-688ff6931fe5 | 5e1f14440fc1 | 1586868290 | csv |  |  |  |  | Ubuntu |  | 2 | ubuntu |  |
>| 499328ee-1966-45a5-9bd0-67591b2eac24 | elad-ubuntu-18.04-vm-dev | 1593682543 | csv | VMware Virtual Platform | VMware-56 4d 66 c7 1a 3c 74 df-c1 c3 04 78 1e de 53 4f | VMware, Inc. |  | Ubuntu |  | 2 | ubuntu | dev |
>| 5ded6c36-8eec-4a7c-b6da-10aa44300bf1 | elad-ubuntu-18.04-vm-dev | 1589206992 | csv | VMware Virtual Platform | VMware-56 4d 66 c7 1a 3c 74 df-c1 c3 04 78 1e de 53 4f | VMware, Inc. |  | Ubuntu |  | 2 | ubuntu | dev |
>| a759eb20-1b7b-4c4f-a5d4-244f21eda54b | centos-7-elad-test | 1593682544 | csv | Google Compute Engine | GoogleCloud-E5D6A8E4DA3F9DD722BB74EC4B556B7F | Google |  | CentOS Linux |  | 2 | rhel |  |
>| 4f16532e-d41a-4b78-9a5c-946d3d3619ca | ewexler-Z87-HD3 | 1593682542 | csv | Z87-HD3 | To be filled by O.E.M. | Gigabyte Technology Co., Ltd. |  | Ubuntu |  | 2 | ubuntu | ewexler |
>| 1f6c8338-0d7c-413f-bd5a-6a01e1f4262d | centos-7-test2 | 1585037906 | csv | Google Compute Engine | GoogleCloud-5EF78465A42780738DA307319C15461C | Google |  | CentOS Linux |  | 2 | rhel |  |
>| b213b9be-ea2f-4736-9427-8062c3f8e9ea | redhat-6-elad | 1593682543 | csv | Google Compute Engine | GoogleCloud-49CF69339F07610337E04A70753B9D68 | Google |  | Red Hat Enterprise Linux Server |  | 2 | rhel |  |
>| c06bc1c2-a6b2-43f6-bfa3-6d1291eab395 | amazon-linux-ami | 1593682542 | csv | HVM domU | ec218f81-c156-6ccd-878a-61b5df159955 | Xen |  | Amazon Linux AMI |  | 2 | amzn |  |
>| 664a5071-4178-4666-ada8-ab582b726a32 | elad-ubuntu-18.04-vm-dev | 1592826522 | csv | VMware Virtual Platform | VMware-56 4d 66 c7 1a 3c 74 df-c1 c3 04 78 1e de 53 4f | VMware, Inc. |  | Ubuntu |  | 2 | ubuntu | dev |
>| 06bea05a-adef-4009-8de5-9eb2e23ac4fb | amazon-linux-ami-2 | 1589321575 | csv | HVM domU | ec26c7b8-0792-6dcd-b181-c9332a620505 | Xen |  | Amazon Linux |  | 2 | amzn |  |
>| e0dc361e-f347-461c-98f5-6549c6c91ef9 | centos-6-elad-test | 1593682543 | csv | Google Compute Engine | GoogleCloud-D59327137B3209E1A93553E62DFCB390 | Google |  | CentOS |  | 2 | rhel |  |
>| 97e595cd-23a5-4901-8ee1-8fd60b1d04b2 | a28aacf4c220 | 1592991018 | csv |  |  |  |  | Ubuntu |  | 2 | ubuntu |  |
>| dd16d24a-0af6-4500-9e20-86650ad0e923 | debian-9-mirco1 | 1593682542 | csv | Google Compute Engine | GoogleCloud-4A0C37EA0B86361E543F33D4AC51918C | Google |  | Debian GNU/Linux |  | 2 | debian |  |
>| 8a31860a-4b7b-4f88-9f4b-288ed9155654 | debian-9-micro | 1593682542 | csv | Google Compute Engine | GoogleCloud-480C87F6B4C2CDA20421A160C6368ED3 | Google |  | Debian GNU/Linux |  | 2 | debian |  |
>| 3048dd12-844a-4dc9-8162-d5425f17e567 | c072e5c5ccf8 | 1586868290 | csv |  |  |  |  | Ubuntu |  | 2 | ubuntu |  |
>| f450940e-cd21-4cf5-9a7a-f33313c79bc6 | 7b39c01c3db9 | 1586868290 | csv |  |  |  |  | Ubuntu |  | 2 | ubuntu |  |
>| c9d706b6-5337-4974-8c70-8ccfd628fb4b | elad-ubuntu-18.04-vm-dev | 1585037883 | csv | VMware Virtual Platform | VMware-56 4d a0 b5 6e bb 1b 7c-25 53 ed b7 9d 6b 9c ea | VMware, Inc. |  | Ubuntu |  | 2 | ubuntu | dev |
>| 0408fb89-35d1-4096-b62f-8b7849e948ec | 489ca43a6ab0 | 1586868290 | csv |  |  |  |  | Ubuntu |  | 2 | ubuntu |  |


### infinipoint-get-assets-cloud
***
 


#### Base Command

`infinipoint-get-assets-cloud`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host |  | Optional | 
| os_type |  | Optional | 
| source | "AWS API" \| "GCP API" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.Cloud.$device | String |  | 
| Infinipoint.Assets.Cloud.$host | String |  | 
| Infinipoint.Assets.Cloud.$time | Number |  | 
| Infinipoint.Assets.Cloud.$type | String |  | 
| Infinipoint.Assets.Cloud.cloud_scan_timestamp | Number |  | 
| Infinipoint.Assets.Cloud.cpu_brand | String |  | 
| Infinipoint.Assets.Cloud.cpu_logical_cores | String |  | 
| Infinipoint.Assets.Cloud.cpu_physical_cores | String |  | 
| Infinipoint.Assets.Cloud.creation_time | String |  | 
| Infinipoint.Assets.Cloud.hardware_model | String |  | 
| Infinipoint.Assets.Cloud.hardware_serial | String |  | 
| Infinipoint.Assets.Cloud.hardware_vendor | String |  | 
| Infinipoint.Assets.Cloud.instance_id | Date |  | 
| Infinipoint.Assets.Cloud.instance_state | String |  | 
| Infinipoint.Assets.Cloud.instance_type | String |  | 
| Infinipoint.Assets.Cloud.os_build | String |  | 
| Infinipoint.Assets.Cloud.os_name | String |  | 
| Infinipoint.Assets.Cloud.os_patch_version | String |  | 
| Infinipoint.Assets.Cloud.os_type | String |  | 
| Infinipoint.Assets.Cloud.physical_memory | String |  | 
| Infinipoint.Assets.Cloud.platform | String |  | 
| Infinipoint.Assets.Cloud.source | String |  | 
| Infinipoint.Assets.Cloud.user | String |  | 
| Infinipoint.Assets.Cloud.zone | String |  | 
| Infinipoint.Assets.Cloud.open_ports | Number |  | 


#### Command Example
```!infinipoint-get-assets-cloud source="GCP API"```

#### Context Example
```
{
    "Infinipoint": {
        "Assets": {
            "Cloud": [
                {
                    "$device": "c0a7ddb2-fdcc-466f-a9b8-f08bd2f194f6",
                    "$host": "win-8",
                    "$time": 1589206995,
                    "$type": "csv",
                    "cloud_scan_timestamp": 1591269553,
                    "cpu_brand": "Intel(R) Xeon(R) CPU @ 2.30GHz",
                    "cpu_logical_cores": "1",
                    "cpu_physical_cores": "1",
                    "creation_time": "2020-03-30 18:32:24.466 +0000 UTC",
                    "hardware_model": "Google Compute Engine",
                    "hardware_serial": "GoogleCloud-0B93DA1E70B30ACD532296E0C7F91213",
                    "hardware_vendor": "Google",
                    "instance_id": "5479759740721399256",
                    "instance_state": "terminated",
                    "instance_type": "n1-standard-1",
                    "os_build": "14393",
                    "os_name": "Microsoft Windows Server 2016 Datacenter",
                    "os_patch_version": "",
                    "os_type": "1",
                    "physical_memory": "4.0",
                    "platform": "windows",
                    "source": "GCP API",
                    "user": "eturjeman",
                    "zone": "europe-west1-b"
                },
                {
                    "$device": "892f3b11-2c56-4552-a07d-e91e7f73dd85",
                    "$host": "centos-6-test",
                    "$time": 1593682543,
                    "$type": "csv",
                    "cloud_scan_timestamp": 1593451876,
                    "cpu_brand": "Intel(R) Xeon(R) CPU @ 2.30GHz",
                    "cpu_logical_cores": "1",
                    "cpu_physical_cores": "1",
                    "creation_time": "2019-05-17 05:32:39.556 +0000 UTC",
                    "hardware_model": "Google Compute Engine",
                    "hardware_serial": "GoogleCloud-036798AF3628613C5BE7968451C8C2F1",
                    "hardware_vendor": "Google",
                    "instance_id": "529570513462491545",
                    "instance_state": "running",
                    "instance_type": "f1-micro",
                    "kernel_version": "2.6.32-754.23.1.el6.x86_64",
                    "os_build": "",
                    "os_name": "CentOS",
                    "os_patch_version": "",
                    "os_type": "2",
                    "os_version": "CentOS release 6.10 (Final)",
                    "physical_memory": "1.0",
                    "platform": "rhel",
                    "source": "GCP API",
                    "user": "",
                    "zone": "us-east1-b"
                },
                {
                    "$device": "5cf9605c-a35c-4d30-a6c8-ef6f48a4b455",
                    "$host": "c19f7ff5251e",
                    "$time": 1586868290,
                    "$type": "csv",
                    "cloud_scan_timestamp": 1585833916,
                    "creation_time": "2019-08-21 06:06:34.734 +0000 UTC",
                    "hardware_model": "",
                    "hardware_serial": "",
                    "hardware_vendor": "",
                    "instance_id": "1870095364949893510",
                    "instance_state": "running",
                    "instance_type": "n1-standard-1",
                    "open_ports": [
                        22
                    ],
                    "os_build": "",
                    "os_name": "Ubuntu",
                    "os_patch_version": "",
                    "os_type": "2",
                    "platform": "ubuntu",
                    "source": "GCP API",
                    "user": "",
                    "zone": "europe-west2-c"
                },
                {
                    "$device": "d500d852-9e35-4451-a42a-b56ccd1e76e4",
                    "$host": "win2-et",
                    "$time": 1584437794,
                    "$type": "csv",
                    "cloud_scan_timestamp": 1585833916,
                    "creation_time": "2020-02-26 08:42:57.613 +0000 UTC",
                    "hardware_model": "Google Compute Engine",
                    "hardware_serial": "GoogleCloud-E8B1D62BD38689C17AB08B9D98200CF6",
                    "hardware_vendor": "Google",
                    "instance_id": "7718660732543013246",
                    "instance_state": "running",
                    "instance_type": "n1-standard-1",
                    "os_build": "14393",
                    "os_name": "Microsoft Windows Server 2016 Datacenter",
                    "os_patch_version": "",
                    "os_type": "1",
                    "platform": "windows",
                    "source": "GCP API",
                    "user": "administrator",
                    "zone": "europe-west1-b"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|$time|$type|cloud_scan_timestamp|cpu_brand|cpu_logical_cores|cpu_physical_cores|creation_time|hardware_model|hardware_serial|hardware_vendor|instance_id|instance_state|instance_type|os_build|os_name|os_patch_version|os_type|physical_memory|platform|source|user|zone|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| c0a7ddb2-fdcc-466f-a9b8-f08bd2f194f6 | win-8 | 1589206995 | csv | 1591269553 | Intel(R) Xeon(R) CPU @ 2.30GHz | 1 | 1 | 2020-03-30 18:32:24.466 +0000 UTC | Google Compute Engine | GoogleCloud-0B93DA1E70B30ACD532296E0C7F91213 | Google | 5479759740721399256 | terminated | n1-standard-1 | 14393 | Microsoft Windows Server 2016 Datacenter |  | 1 | 4.0 | windows | GCP API | eturjeman | europe-west1-b |
>| 892f3b11-2c56-4552-a07d-e91e7f73dd85 | centos-6-test | 1593682543 | csv | 1593451876 | Intel(R) Xeon(R) CPU @ 2.30GHz | 1 | 1 | 2019-05-17 05:32:39.556 +0000 UTC | Google Compute Engine | GoogleCloud-036798AF3628613C5BE7968451C8C2F1 | Google | 529570513462491545 | running | f1-micro |  | CentOS |  | 2 | 1.0 | rhel | GCP API |  | us-east1-b |
>| 5cf9605c-a35c-4d30-a6c8-ef6f48a4b455 | c19f7ff5251e | 1586868290 | csv | 1585833916 |  |  |  | 2019-08-21 06:06:34.734 +0000 UTC |  |  |  | 1870095364949893510 | running | n1-standard-1 |  | Ubuntu |  | 2 |  | ubuntu | GCP API |  | europe-west2-c |
>| d500d852-9e35-4451-a42a-b56ccd1e76e4 | win2-et | 1584437794 | csv | 1585833916 |  |  |  | 2020-02-26 08:42:57.613 +0000 UTC | Google Compute Engine | GoogleCloud-E8B1D62BD38689C17AB08B9D98200CF6 | Google | 7718660732543013246 | running | n1-standard-1 | 14393 | Microsoft Windows Server 2016 Datacenter |  | 1 |  | windows | GCP API | administrator | europe-west1-b |


### infinipoint-get-assets-user
***
 


#### Base Command

`infinipoint-get-assets-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host |  | Optional | 
| username |  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Assets.User.$device | String |  | 
| Infinipoint.Assets.User.$host | String |  | 
| Infinipoint.Assets.User.$time | Number |  | 
| Infinipoint.Assets.User.$type | String |  | 
| Infinipoint.Assets.User.description | String |  | 
| Infinipoint.Assets.User.directory | String |  | 
| Infinipoint.Assets.User.username | String |  | 


#### Command Example
```!infinipoint-get-assets-user host="et"```

#### Context Example
```
{
    "Infinipoint": {
        "Assets": {
            "User": [
                {
                    "$device": "d500d852-9e35-4451-a42a-b56ccd1e76e4",
                    "$host": "win2-et",
                    "$time": 1584437794,
                    "$type": "csv",
                    "description": "",
                    "directory": "C:\\Windows\\ServiceProfiles\\NetworkService",
                    "username": "NETWORK SERVICE"
                },
                {
                    "$device": "3c4f4df4-e608-4a99-a74a-772b9c84469f",
                    "$host": "ET",
                    "$time": 1593671958,
                    "$type": "csv",
                    "description": "Built-in account for homegroup access to the computer",
                    "directory": "",
                    "username": "HomeGroupUser$"
                },
                {
                    "$device": "14e2b620-acfa-4f30-84a3-669a0c1b9ebb",
                    "$host": "Shay-NetBook",
                    "$time": 1593214575,
                    "$type": "csv",
                    "description": "",
                    "directory": "C:\\Windows\\ServiceProfiles\\LocalService",
                    "username": "LOCAL SERVICE"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|$device|$host|$time|$type|description|directory|username|
>|---|---|---|---|---|---|---|
>| d500d852-9e35-4451-a42a-b56ccd1e76e4 | win2-et | 1584437794 | csv |  | C:\Windows\ServiceProfiles\LocalService | LOCAL SERVICE |
>| 893e33cc-d5ad-44fb-8c0e-f92ceff86e70 | ET | 1591139902 | csv |  | C:\Windows\ServiceProfiles\NetworkService | NETWORK SERVICE |
>| d500d852-9e35-4451-a42a-b56ccd1e76e4 | win2-et | 1584437794 | csv |  | C:\Users\administrator | Administrator |
>| d500d852-9e35-4451-a42a-b56ccd1e76e4 | win2-et | 1584437794 | csv | A user account managed by the system. |  | DefaultAccount |
>| d500d852-9e35-4451-a42a-b56ccd1e76e4 | win2-et | 1584437794 | csv | Built-in account for guest access to the computer/domain |  | Guest |
>| 893e33cc-d5ad-44fb-8c0e-f92ceff86e70 | ET | 1591139902 | csv | Built-in account for administering the computer/domain |  | Administrator |
>| 893e33cc-d5ad-44fb-8c0e-f92ceff86e70 | ET | 1591139902 | csv |  | C:\Windows\ServiceProfiles\LocalService | LOCAL SERVICE |
>| 14e2b620-acfa-4f30-84a3-669a0c1b9ebb | Shay-NetBook | 1593214575 | csv |  | C:\Users\שמעון פרידמן | שמעון פרידמן |
>| 14e2b620-acfa-4f30-84a3-669a0c1b9ebb | Shay-NetBook | 1593214575 | csv |  | C:\Windows\ServiceProfiles\NetworkService | NETWORK SERVICE |
>| 893e33cc-d5ad-44fb-8c0e-f92ceff86e70 | ET | 1591139902 | csv | Built-in account for guest access to the computer/domain |  | Guest |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET | 1593671958 | csv |  | C:\Windows\ServiceProfiles\NetworkService | NETWORK SERVICE |
>| 14e2b620-acfa-4f30-84a3-669a0c1b9ebb | Shay-NetBook | 1593214575 | csv |  | C:\Users\Angel | Angel |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET | 1593671958 | csv | Built-in account for administering the computer/domain |  | Administrator |
>| 893e33cc-d5ad-44fb-8c0e-f92ceff86e70 | ET | 1591139902 | csv | Built-in account for homegroup access to the computer |  | HomeGroupUser$ |
>| 893e33cc-d5ad-44fb-8c0e-f92ceff86e70 | ET | 1591139902 | csv |  |  | אליקו |
>| d500d852-9e35-4451-a42a-b56ccd1e76e4 | win2-et | 1584437794 | csv |  | C:\Users\eturjeman | eturjeman |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET | 1593671958 | csv |  | C:\Users\EliranTurjeman | EliranTurjeman |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET | 1593671958 | csv |  | C:\Windows\ServiceProfiles\LocalService | LOCAL SERVICE |
>| 893e33cc-d5ad-44fb-8c0e-f92ceff86e70 | ET | 1591139902 | csv |  | C:\Users\EliranTurjeman | EliranTurjeman |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET | 1593671958 | csv |  |  | אליקו |
>| d500d852-9e35-4451-a42a-b56ccd1e76e4 | win2-et | 1584437794 | csv |  | C:\Windows\ServiceProfiles\NetworkService | NETWORK SERVICE |
>| 14e2b620-acfa-4f30-84a3-669a0c1b9ebb | Shay-NetBook | 1593214575 | csv | Built-in account for guest access to the computer/domain |  | Guest |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET | 1593671958 | csv | Built-in account for guest access to the computer/domain |  | Guest |
>| 3c4f4df4-e608-4a99-a74a-772b9c84469f | ET | 1593671958 | csv | Built-in account for homegroup access to the computer |  | HomeGroupUser$ |
>| 14e2b620-acfa-4f30-84a3-669a0c1b9ebb | Shay-NetBook | 1593214575 | csv | Built-in account for administering the computer/domain |  | Administrator |
>| 14e2b620-acfa-4f30-84a3-669a0c1b9ebb | Shay-NetBook | 1593214575 | csv |  | C:\Windows\ServiceProfiles\LocalService | LOCAL SERVICE |


### infinipoint-run-script
***
 


#### Base Command

`infinipoint-run-script`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Scripts.Execute.actionId | String |  | 
| Infinipoint.Scripts.Execute.aggColumns | Unknown |  | 
| Infinipoint.Scripts.Execute.devicesCount | Number |  | 
| Infinipoint.Scripts.Execute.name | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-action
***
 


#### Base Command

`infinipoint-get-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Responses.$data | String |  | 
| Infinipoint.Responses.$device | String |  | 
| Infinipoint.Responses.$host | String |  | 
| Infinipoint.Responses.$time | Number |  | 
| Infinipoint.Responses.$type | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### infinipoint-get-queries
***
 


#### Base Command

`infinipoint-get-queries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Scripts.Search.aggregation | Number |  | 
| Infinipoint.Scripts.Search.createdOn | Date |  | 
| Infinipoint.Scripts.Search.format | Number |  | 
| Infinipoint.Scripts.Search.id | String |  | 
| Infinipoint.Scripts.Search.interp | Number |  | 
| Infinipoint.Scripts.Search.module | Number |  | 
| Infinipoint.Scripts.Search.name | String |  | 
| Infinipoint.Scripts.Search.osType | Number |  | 


#### Command Example
```!infinipoint-get-queries name=os_version```

#### Context Example
```
{
    "Infinipoint": {
        "Scripts": {
            "Search": {
                "aggregation": true,
                "createdOn": "2020-02-02T09:56:32.778182Z",
                "description": "Retrieves information FROM the Operative Systems.",
                "format": 2,
                "id": "d266875f-c674-4143-8e77-b008a8843687",
                "interp": 0,
                "module": 4,
                "name": "OS versions",
                "osType": 7
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|aggregation|createdOn|description|format|id|interp|module|name|osType|
>|---|---|---|---|---|---|---|---|---|
>| true | 2020-02-02T09:56:32.778182Z | Retrieves information FROM the Operative Systems. | 2 | d266875f-c674-4143-8e77-b008a8843687 | 0 | 4 | OS versions | 7 |


### infinipoint-run-osquery
***
 


#### Base Command

`infinipoint-run-osquery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id |  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Infinipoint.Osquery.Execute.actionId | String |  | 
| Infinipoint.Osquery.Execute.aggColumns | String |  | 
| Infinipoint.Osquery.Execute.devicesCount | Number |  | 
| Infinipoint.Osquery.Execute.name | String |  | 


#### Command Example
```!infinipoint-run-osquery query_id=dcbf29ff-4da6-4228-9d8f-3e269ca8e6fa```

#### Context Example
```
{
    "Infinipoint": {
        "Osquery": {
            "Execute": {
                "actionId": "aedfcbbb-179b-409d-a7bb-548ab92e3e84",
                "aggColumns": [
                    "name"
                ],
                "devicesCount": 13,
                "name": "Custom query"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|actionId|aggColumns|devicesCount|name|
>|---|---|---|---|
>| aedfcbbb-179b-409d-a7bb-548ab92e3e84 | name | 13 | Custom query |

