Cisco Advanced malware protection software is designed to prevent, detect, and help remove threats in an efficient manner from computer systems. Threats can take the form of software viruses and other malware such as ransomware, worms, Trojans, spyware, adware, and fileless malware.
This integration was integrated and tested with version xx of CiscoAMP

## Configure Cisco AMP Secure Endpoint on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cisco AMP Secure Endpoint.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | 3rd Party API Client ID |  | True |
    | API Key |  | True |
    | Trust any certificate (unsecure) |  | False |
    | Use system proxy |  | False |
    | Maximum incidents to fetch. | Maximum number of incidents per fetch. The maximum is 200. | False |
    | Incident severity to fetch. |  | False |
    | First fetch time | First alert created date to fetch. e.g., "1 min ago","2 weeks ago","3 months ago" | False |
    | Event types | Comma separated list of Event Type IDs. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cisco-amp-computer-list
***
Fetch computers to shows information about them. Can be filtered by a variety of criteria.


#### Base Command

`cisco-amp-computer-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 
| connector_guid | connector_guid for a specific computer. | Optional | 
| hostname | Coma separated list of host names to filter by (has auto complete capabilities). | Optional | 
| internal_ip | Internal IP to filter by. | Optional | 
| external_ip | External IP to filter by. | Optional | 
| group_guid | Coma separated list of group GUIDs to filter by. | Optional | 
| last_seen_within | Time range  to filter by. | Optional | 
| last_seen_over | Time range  to filter over by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Computer.connector_guid | String | GUID of the connector. | 
| CiscoAMP.Computer.hostname | String | Host's name. | 
| CiscoAMP.Computer.windows_processor_id | String | Windows processor ID. | 
| CiscoAMP.Computer.active | Boolean | Is the computer active. | 
| CiscoAMP.Computer.connector_version | String | Version of the connector. | 
| CiscoAMP.Computer.operating_system | String | Operating system of the computer. | 
| CiscoAMP.Computer.os_version | String | Operating system version. | 
| CiscoAMP.Computer.internal_ips | String | List of internal IP's. | 
| CiscoAMP.Computer.external_ip | String | External IP. | 
| CiscoAMP.Computer.group_guid | String | GUID of the group. | 
| CiscoAMP.Computer.install_date | Date | Installation date. | 
| CiscoAMP.Computer.is_compromised | Boolean | Is the computer compromised. | 
| CiscoAMP.Computer.demo | Boolean | Demo. | 
| CiscoAMP.Computer.network_addresses.mac | String | List of MAC addresses. | 
| CiscoAMP.Computer.network_addresses.ip | String | List of IP addresses. | 
| CiscoAMP.Computer.policy.guid | String | GUID of the policy. | 
| CiscoAMP.Computer.policy.name | String | Name of the policy. | 
| CiscoAMP.Computer.groups.guid | String | GUID of the group. | 
| CiscoAMP.Computer.groups.name | String | Name of the group. | 
| CiscoAMP.Computer.last_seen | Date | Last date seen. | 
| CiscoAMP.Computer.faults | String | Faults. | 
| CiscoAMP.Computer.isolation.available | Boolean | Is the isolation available. | 
| CiscoAMP.Computer.isolation.status | String | Status of the isolation. | 
| CiscoAMP.Computer.orbital.status | String | Status of the orbital. | 
| Endpoint.Hostname | String | The hostname of the endpoint. | 
| Endpoint.ID | String | The endpoint's identifier. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.OS | String | The endpoint's operating system. | 
| Endpoint.OSVersion | String | The endpoint's operating system's version. | 
| Endpoint.Status | String | The status of the endpoint \(online/offline\). | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 

#### Command example
```!cisco-amp-computer-list limit=5```
#### Context Example
```json
{
    "CiscoAMP": {
        "Computer": [
            {
                "active": true,
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "connector_version": "8.0.1.21164",
                "demo": true,
                "external_ip": "221.71.163.177",
                "faults": [],
                "group_guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                "groups": [
                    {
                        "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                        "name": "Lior-Group"
                    }
                ],
                "hostname": "Demo_AMP",
                "install_date": "2022-09-25T13:04:53Z",
                "internal_ips": [
                    "191.250.254.209"
                ],
                "is_compromised": true,
                "isolation": {
                    "available": true,
                    "status": "not_isolated"
                },
                "last_seen": "2022-10-25T13:04:53Z",
                "network_addresses": [
                    {
                        "ip": "191.250.254.209",
                        "mac": "e6:80:50:1e:e5:20"
                    }
                ],
                "operating_system": "Windows 10",
                "os_version": "10.0.19044.1466",
                "policy": {
                    "guid": "91c7894d-dd69-4a21-8cf6-5ebfc57ef4df",
                    "name": "Lior-test"
                },
                "windows_processor_id": "3e0527a4d8916bf"
            },
            {
                "active": true,
                "connector_guid": "113c1a8e-8e66-409e-92a8-41b7d586be5d",
                "connector_version": "8.0.1.21164",
                "demo": true,
                "external_ip": "24.87.24.127",
                "faults": [],
                "group_guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                "groups": [
                    {
                        "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                        "name": "Triage"
                    }
                ],
                "hostname": "Demo_AMP_Exploit_Prevention",
                "install_date": "2022-09-25T13:04:51Z",
                "internal_ips": [
                    "105.21.19.154"
                ],
                "is_compromised": false,
                "isolation": {
                    "available": false,
                    "status": "not_isolated"
                },
                "last_seen": "2022-10-25T13:04:51Z",
                "network_addresses": [
                    {
                        "ip": "105.21.19.154",
                        "mac": "ef:40:35:32:c1:29"
                    }
                ],
                "operating_system": "Windows 10",
                "os_version": "10.0.19044.1466",
                "policy": {
                    "guid": "1a352c59-793b-44f3-b8f9-0ddd354057bc",
                    "name": "Triage"
                },
                "windows_processor_id": "f208ab145e397d6"
            },
            {
                "active": true,
                "connector_guid": "93f395a2-e31f-4022-b1dd-afb16e093b8d",
                "connector_version": "8.0.1.21164",
                "demo": true,
                "external_ip": "60.231.175.245",
                "faults": [],
                "group_guid": "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18",
                "groups": [
                    {
                        "guid": "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18",
                        "name": "Protect"
                    }
                ],
                "hostname": "Demo_AMP_Exploit_Prevention_Audit",
                "install_date": "2022-09-25T13:04:58Z",
                "internal_ips": [
                    "30.245.204.197"
                ],
                "is_compromised": true,
                "isolation": {
                    "available": true,
                    "status": "not_isolated"
                },
                "last_seen": "2022-10-25T13:04:58Z",
                "network_addresses": [
                    {
                        "ip": "30.245.204.197",
                        "mac": "4f:12:6f:ae:2f:f6"
                    }
                ],
                "operating_system": "Windows 10",
                "os_version": "10.0.19044.1466",
                "policy": {
                    "guid": "a599bf5b-2cb7-4a5b-90bd-d0199e2ccd67",
                    "name": "Protect"
                },
                "windows_processor_id": "426570f18dab39e"
            },
            {
                "active": true,
                "connector_guid": "d6f49c17-9721-4c5b-a04f-32ba30be36a0",
                "connector_version": "8.0.1.21164",
                "demo": true,
                "external_ip": "214.23.214.95",
                "faults": [],
                "group_guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                "groups": [
                    {
                        "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                        "name": "Audit"
                    }
                ],
                "hostname": "Demo_AMP_Intel",
                "install_date": "2022-09-25T13:05:02Z",
                "internal_ips": [
                    "4.243.147.93"
                ],
                "is_compromised": true,
                "isolation": {
                    "available": true,
                    "status": "not_isolated"
                },
                "last_seen": "2022-10-25T13:05:02Z",
                "network_addresses": [
                    {
                        "ip": "4.243.147.93",
                        "mac": "7c:55:d8:c2:ca:db"
                    }
                ],
                "operating_system": "Windows 10",
                "os_version": "10.0.19043.1202",
                "policy": {
                    "guid": "be84e169-0830-4b95-915b-1e203a82ed58",
                    "name": "Audit"
                },
                "windows_processor_id": "daf517086932eb4"
            },
            {
                "active": true,
                "connector_guid": "9a2abee8-b988-473b-9e99-a7abe6d068a5",
                "connector_version": "8.0.1.21164",
                "demo": true,
                "external_ip": "40.230.125.128",
                "faults": [],
                "group_guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                "groups": [
                    {
                        "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                        "name": "Triage"
                    }
                ],
                "hostname": "Demo_AMP_MAP_FriedEx",
                "install_date": "2022-09-25T13:05:08Z",
                "internal_ips": [
                    "250.72.208.41"
                ],
                "is_compromised": true,
                "isolation": {
                    "available": false,
                    "status": "not_isolated"
                },
                "last_seen": "2022-10-25T13:05:08Z",
                "network_addresses": [
                    {
                        "ip": "250.72.208.41",
                        "mac": "45:bb:bf:ed:c5:16"
                    }
                ],
                "operating_system": "Windows 10",
                "os_version": "10.0.19044.1466",
                "policy": {
                    "guid": "1a352c59-793b-44f3-b8f9-0ddd354057bc",
                    "name": "Triage"
                },
                "windows_processor_id": "02937a1ed658fb4"
            }
        ]
    },
    "Endpoint": [
        {
            "Hostname": "Demo_AMP",
            "ID": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
            "IPAddress": "191.250.254.209",
            "MACAddress": "e6:80:50:1e:e5:20",
            "OS": "Windows 10",
            "OSVersion": "10.0.19044.1466",
            "Status": "Online",
            "Vendor": "CiscoAMP Response"
        },
        {
            "Hostname": "Demo_AMP_Exploit_Prevention",
            "ID": "113c1a8e-8e66-409e-92a8-41b7d586be5d",
            "IPAddress": "105.21.19.154",
            "MACAddress": "ef:40:35:32:c1:29",
            "OS": "Windows 10",
            "OSVersion": "10.0.19044.1466",
            "Status": "Online",
            "Vendor": "CiscoAMP Response"
        },
        {
            "Hostname": "Demo_AMP_Exploit_Prevention_Audit",
            "ID": "93f395a2-e31f-4022-b1dd-afb16e093b8d",
            "IPAddress": "30.245.204.197",
            "MACAddress": "4f:12:6f:ae:2f:f6",
            "OS": "Windows 10",
            "OSVersion": "10.0.19044.1466",
            "Status": "Online",
            "Vendor": "CiscoAMP Response"
        },
        {
            "Hostname": "Demo_AMP_Intel",
            "ID": "d6f49c17-9721-4c5b-a04f-32ba30be36a0",
            "IPAddress": "4.243.147.93",
            "MACAddress": "7c:55:d8:c2:ca:db",
            "OS": "Windows 10",
            "OSVersion": "10.0.19043.1202",
            "Status": "Online",
            "Vendor": "CiscoAMP Response"
        },
        {
            "Hostname": "Demo_AMP_MAP_FriedEx",
            "ID": "9a2abee8-b988-473b-9e99-a7abe6d068a5",
            "IPAddress": "250.72.208.41",
            "MACAddress": "45:bb:bf:ed:c5:16",
            "OS": "Windows 10",
            "OSVersion": "10.0.19044.1466",
            "Status": "Online",
            "Vendor": "CiscoAMP Response"
        }
    ]
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 5 | 0 | 5 | 32 |
>### Computer Information
>|Host Name|Connector GUID|Operating System|External IP|Group GUID|Policy GUID|
>|---|---|---|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | Windows 10 (Build 10.0.19044.1466) | 221.71.163.177 | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 | 91c7894d-dd69-4a21-8cf6-5ebfc57ef4df |
>| Demo_AMP_Exploit_Prevention | 113c1a8e-8e66-409e-92a8-41b7d586be5d | Windows 10 (Build 10.0.19044.1466) | 24.87.24.127 | 6ed80412-0739-42c1-8f6d-32fb51b3f894 | 1a352c59-793b-44f3-b8f9-0ddd354057bc |
>| Demo_AMP_Exploit_Prevention_Audit | 93f395a2-e31f-4022-b1dd-afb16e093b8d | Windows 10 (Build 10.0.19044.1466) | 60.231.175.245 | 5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18 | a599bf5b-2cb7-4a5b-90bd-d0199e2ccd67 |
>| Demo_AMP_Intel | d6f49c17-9721-4c5b-a04f-32ba30be36a0 | Windows 10 (Build 10.0.19043.1202) | 214.23.214.95 | fedd82f8-c74f-49f4-a463-e576d3beee92 | be84e169-0830-4b95-915b-1e203a82ed58 |
>| Demo_AMP_MAP_FriedEx | 9a2abee8-b988-473b-9e99-a7abe6d068a5 | Windows 10 (Build 10.0.19044.1466) | 40.230.125.128 | 6ed80412-0739-42c1-8f6d-32fb51b3f894 | 1a352c59-793b-44f3-b8f9-0ddd354057bc |


### cisco-amp-computer-trajectory-list
***
Provides a list of all activities associated with a particular computer. This analogous to the Device Trajectory on the FireAMP console.


#### Base Command

`cisco-amp-computer-trajectory-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector_guid for specific computer. | Required | 
| query_string | Freeform query string which currently accepts: IP address, SHA-256 or URL. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 5000. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerTrajectory.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerTrajectory.id | String | Event's ID. | 
| CiscoAMP.ComputerTrajectory.timestamp | Number | Event's timestamp. | 
| CiscoAMP.ComputerTrajectory.timestamp_nanoseconds | Number | Event's timestamp nano seconds. | 
| CiscoAMP.ComputerTrajectory.date | Date | Event's date. | 
| CiscoAMP.ComputerTrajectory.event_type | String | Event's type. | 
| CiscoAMP.ComputerTrajectory.event_type_id | Number | Event's type ID. | 
| CiscoAMP.ComputerTrajectory.group_guids | String | Group GUID. | 
| CiscoAMP.ComputerTrajectory.severity | String | Event's severity. | 
| CiscoAMP.ComputerTrajectory.detection | String | Event's detection. | 
| CiscoAMP.ComputerTrajectory.detection_id | String | Event's detection ID. | 
| CiscoAMP.ComputerTrajectory.file.disposition | String | Disposition of the file. | 
| CiscoAMP.ComputerTrajectory.file.file_name | String | Name of the file. | 
| CiscoAMP.ComputerTrajectory.file.file_path | String | Path to the file. | 
| CiscoAMP.ComputerTrajectory.file.file_type | String | Type of the file. | 
| CiscoAMP.ComputerTrajectory.file.identity.sha256 | String | File's SHA-256. | 
| CiscoAMP.ComputerTrajectory.file.identity.sha1 | String | File's SHA-1. | 
| CiscoAMP.ComputerTrajectory.file.identity.md5 | String | File's MD5. | 
| CiscoAMP.ComputerTrajectory.file.parent.disposition | String | Disposition of parent. | 
| CiscoAMP.ComputerTrajectory.file.parent.identity.sha256 | String | SHA-256 of parent. | 
| CiscoAMP.ComputerTrajectory.scan.description | String | Description. | 
| CiscoAMP.ComputerTrajectory.scan.clean | Boolean | Whether it is clean. | 
| CiscoAMP.ComputerTrajectory.scan.scanned_files | Number | Number of scanned files. | 
| CiscoAMP.ComputerTrajectory.scan.scanned_processes | Number | Number of scanned processes. | 
| CiscoAMP.ComputerTrajectory.scan.scanned_paths | Number | Number of scanned paths. | 
| CiscoAMP.ComputerTrajectory.scan.malicious_detections | Number | Number of malicious detections. | 

#### Command example
```!cisco-amp-computer-trajectory-list connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0 limit=5```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerTrajectory": [
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:55:05+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667217305855411965",
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667217305,
                "timestamp_nanoseconds": 0
            },
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:54:58+00:00",
                "event_type": "Endpoint Isolation Start Success",
                "event_type_id": 553648202,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667217298837175263",
                "timestamp": 1667217298,
                "timestamp_nanoseconds": 0
            },
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:42:25+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667216545769121964",
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667216545,
                "timestamp_nanoseconds": 0
            },
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:42:18+00:00",
                "event_type": "Endpoint Isolation Start Success",
                "event_type_id": 553648202,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667216538974189121",
                "timestamp": 1667216538,
                "timestamp_nanoseconds": 0
            },
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:15:07+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667214907330813011",
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667214907,
                "timestamp_nanoseconds": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Computer Information
>|Host Name|Connector GUID|Operating System|External IP|Group GUID|Policy GUID|
>|---|---|---|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | Windows 10 (Build 10.0.19044.1466) | 221.71.163.177 | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 | 91c7894d-dd69-4a21-8cf6-5ebfc57ef4df |
>### Event Information
>|ID|Date|Event Type|Group GUIDs|
>|---|---|---|---|
>| 1667217305855411965 | 2022-10-31T11:55:05+00:00 | Endpoint Isolation Stop Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>| 1667217298837175263 | 2022-10-31T11:54:58+00:00 | Endpoint Isolation Start Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>| 1667216545769121964 | 2022-10-31T11:42:25+00:00 | Endpoint Isolation Stop Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>| 1667216538974189121 | 2022-10-31T11:42:18+00:00 | Endpoint Isolation Start Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>| 1667214907330813011 | 2022-10-31T11:15:07+00:00 | Endpoint Isolation Stop Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |


### cisco-amp-computer-user-activity-list
***
Fetch a list of computers that have observed activity by given username.


#### Base Command

`cisco-amp-computer-user-activity-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to filter by. | Required | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerUserActivity.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerUserActivity.hostname | String | Host's name. | 
| CiscoAMP.ComputerUserActivity.active | Boolean | Is the computer active. | 

#### Command example
```!cisco-amp-computer-user-activity-list username=johndoe```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerUserActivity": [
            {
                "active": true,
                "connector_guid": "113c1a8e-8e66-409e-92a8-41b7d586be5d",
                "hostname": "Demo_AMP_Exploit_Prevention"
            },
            {
                "active": true,
                "connector_guid": "307ada77-5776-4de6-ab3b-9c42fe723c9c",
                "hostname": "Demo_WannaCry_Ransomware"
            },
            {
                "active": true,
                "connector_guid": "32ac3d60-4038-4cac-8df8-7588cd959926",
                "hostname": "Demo_AMP_Threat_Audit"
            },
            {
                "active": true,
                "connector_guid": "7704bf95-5343-4825-8d68-2ecea81feda4",
                "hostname": "Demo_Qakbot_3"
            },
            {
                "active": true,
                "connector_guid": "790e9bd4-99b5-433c-b027-9a9a5b9d426f",
                "hostname": "Demo_Qakbot_2"
            },
            {
                "active": true,
                "connector_guid": "cd9ae0b3-b566-47f4-811b-980dcb7988d6",
                "hostname": "Demo_Qakbot_1"
            },
            {
                "active": true,
                "connector_guid": "d42cab73-c142-4c25-85d3-4bdefacb6b5b",
                "hostname": "Demo_AMP_Threat_Quarantined"
            },
            {
                "active": true,
                "connector_guid": "d6f49c17-9721-4c5b-a04f-32ba30be36a0",
                "hostname": "Demo_AMP_Intel"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 8 | 0 | 100 | 8 |
>### Activity Information
>|Connector GUID|Host Name|Active|
>|---|---|---|
>| 113c1a8e-8e66-409e-92a8-41b7d586be5d | Demo_AMP_Exploit_Prevention | true |
>| 307ada77-5776-4de6-ab3b-9c42fe723c9c | Demo_WannaCry_Ransomware | true |
>| 32ac3d60-4038-4cac-8df8-7588cd959926 | Demo_AMP_Threat_Audit | true |
>| 7704bf95-5343-4825-8d68-2ecea81feda4 | Demo_Qakbot_3 | true |
>| 790e9bd4-99b5-433c-b027-9a9a5b9d426f | Demo_Qakbot_2 | true |
>| cd9ae0b3-b566-47f4-811b-980dcb7988d6 | Demo_Qakbot_1 | true |
>| d42cab73-c142-4c25-85d3-4bdefacb6b5b | Demo_AMP_Threat_Quarantined | true |
>| d6f49c17-9721-4c5b-a04f-32ba30be36a0 | Demo_AMP_Intel | true |


### cisco-amp-computer-user-trajectory-list
***
Fetch a specific computer's trajectory with given connector_guid and filter for events with user name activity.


#### Base Command

`cisco-amp-computer-user-trajectory-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector_guid for specific computer. | Required | 
| username | Username to filter by. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 5000. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerUserTrajectory.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerUserTrajectory.id | String | Event's ID. | 
| CiscoAMP.ComputerUserTrajectory.timestamp | Number | Event's timestamp. | 
| CiscoAMP.ComputerUserTrajectory.timestamp_nanoseconds | Number | Event's timestamp nano seconds. | 
| CiscoAMP.ComputerUserTrajectory.date | Date | Event's date. | 
| CiscoAMP.ComputerUserTrajectory.event_type | String | Event's type. | 
| CiscoAMP.ComputerUserTrajectory.event_type_id | Number | Event's type ID. | 
| CiscoAMP.ComputerUserTrajectory.group_guids | String | Group GUID. | 
| CiscoAMP.ComputerUserTrajectory.severity | String | Event's severity. | 
| CiscoAMP.ComputerUserTrajectory.detection | String | Event's detection. | 
| CiscoAMP.ComputerUserTrajectory.detection_id | String | Event's detection ID. | 
| CiscoAMP.ComputerUserTrajectory.file.disposition | String | Disposition of the file. | 
| CiscoAMP.ComputerUserTrajectory.file.file_name | String | Name of the file. | 
| CiscoAMP.ComputerUserTrajectory.file.file_path | String | Path to the file. | 
| CiscoAMP.ComputerUserTrajectory.file.file_type | String | Type of the file. | 
| CiscoAMP.ComputerUserTrajectory.file.identity.sha256 | String | File's SHA-256. | 
| CiscoAMP.ComputerUserTrajectory.file.identity.sha1 | String | File's SHA-1. | 
| CiscoAMP.ComputerUserTrajectory.file.identity.md5 | String | File's MD5. | 
| CiscoAMP.ComputerUserTrajectory.file.parent.disposition | String | Disposition of parent. | 
| CiscoAMP.ComputerUserTrajectory.file.parent.identity.sha256 | String | SHA-256 of parent. | 
| CiscoAMP.ComputerUserTrajectory.scan.description | String | Description. | 
| CiscoAMP.ComputerUserTrajectory.scan.clean | Boolean | Whether it is clean. | 
| CiscoAMP.ComputerUserTrajectory.scan.scanned_files | Number | Number of scanned files. | 
| CiscoAMP.ComputerUserTrajectory.scan.scanned_processes | Number | Number of scanned processes. | 
| CiscoAMP.ComputerUserTrajectory.scan.scanned_paths | Number | Number of scanned paths. | 
| CiscoAMP.ComputerUserTrajectory.scan.malicious_detections | Number | Number of malicious detections. | 

#### Command example
```!cisco-amp-computer-user-trajectory-list connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0 limit=5```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerUserTrajectory": [
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:55:05+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667217305855411965",
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667217305,
                "timestamp_nanoseconds": 0
            },
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:54:58+00:00",
                "event_type": "Endpoint Isolation Start Success",
                "event_type_id": 553648202,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667217298837175263",
                "timestamp": 1667217298,
                "timestamp_nanoseconds": 0
            },
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:42:25+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667216545769121964",
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667216545,
                "timestamp_nanoseconds": 0
            },
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:42:18+00:00",
                "event_type": "Endpoint Isolation Start Success",
                "event_type_id": 553648202,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667216538974189121",
                "timestamp": 1667216538,
                "timestamp_nanoseconds": 0
            },
            {
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:15:07+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": "1667214907330813011",
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667214907,
                "timestamp_nanoseconds": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Computer Information
>|Host Name|Connector GUID|Operating System|
>|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | None (Build None) |
>### Event Information
>|ID|Date|Event Type|Group GUIDs|
>|---|---|---|---|
>| 1667217305855411965 | 2022-10-31T11:55:05+00:00 | Endpoint Isolation Stop Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>| 1667217298837175263 | 2022-10-31T11:54:58+00:00 | Endpoint Isolation Start Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>| 1667216545769121964 | 2022-10-31T11:42:25+00:00 | Endpoint Isolation Stop Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>| 1667216538974189121 | 2022-10-31T11:42:18+00:00 | Endpoint Isolation Start Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>| 1667214907330813011 | 2022-10-31T11:15:07+00:00 | Endpoint Isolation Stop Success | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |


### cisco-amp-computer-vulnerabilities-list
***
Provides a list of vulnerabilities observed on a specific computer. The vulnerabilities can be filtered to show only vulnerable applications observed for a specific time range.


#### Base Command

`cisco-amp-computer-vulnerabilities-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector_guid for specific computer. | Required | 
| start_time | Inclusive (The list will include vulnerable programs detected at start_time). | Optional | 
| end_time | Exclusive - if end_time is a time (The list will only include vulnerable programs detected before end_time); Inclusive - if end_time is a date (The list will include vulnerable programs detected on the date). | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerVulnerability.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerVulnerability.application | String | Name of the application. | 
| CiscoAMP.ComputerVulnerability.version | String | Version of the application. | 
| CiscoAMP.ComputerVulnerability.file.filename | String | Name of the file. | 
| CiscoAMP.ComputerVulnerability.file.identity.sha256 | String | File's SHA-256. | 
| CiscoAMP.ComputerVulnerability.file.identity.sha1 | String | File's SHA-1. | 
| CiscoAMP.ComputerVulnerability.file.identity.md5 | String | File's MD5. | 
| CiscoAMP.ComputerVulnerability.cves.id | String | Common vulnerability exposure ID. | 
| CiscoAMP.ComputerVulnerability.cves.link | String | Common vulnerability exposure link. | 
| CiscoAMP.ComputerVulnerability.cves.cvss | Number | Common vulnerability scoring system. | 
| CiscoAMP.ComputerVulnerability.latest_timestamp | Number | Vulnerability latest timestamp. | 
| CiscoAMP.ComputerVulnerability.latest_date | Date | Vulnerability latest date. | 

#### Command example
```!cisco-amp-computer-vulnerabilities-list connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerVulnerability": {
            "application": "Microsoft Office",
            "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
            "cves": [
                {
                    "cvss": 9.3,
                    "id": "CVE-2014-0260",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0260"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2014-1761",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-1761"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2014-6357",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6357"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2015-0085",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-0085"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2015-0086",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-0086"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2015-1641",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1641"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2015-1650",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1650"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2015-1682",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1682"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2015-2379",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2379"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2015-2380",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2380"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2015-2424",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2424"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2016-0127",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-0127"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2016-7193",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-7193"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2017-0292",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-0292"
                },
                {
                    "cvss": 9.3,
                    "id": "CVE-2017-11826",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-11826"
                }
            ],
            "file": {
                "filename": "WINWORD.EXE",
                "identity": {
                    "sha256": "3D46E95284F93BBB76B3B7E1BF0E1B2D51E8A9411C2B6E649112F22F92DE63C2"
                }
            },
            "latest_date": "2022-10-23T12:37:33+00:00",
            "latest_timestamp": 1666528653,
            "version": "2013"
        }
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 1 | 0 | 100 | 1 |
>### Computer Information
>|Host Name|Connector GUID|Operating System|Group GUID|
>|---|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | None (Build None) | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |
>### Vulnerabilities Information
>|Application|Version|Latest Date|File Name|SHA-256|
>|---|---|---|---|---|
>| Microsoft Office | 2013 | 2022-10-23T12:37:33+00:00 | WINWORD.EXE | 3D46E95284F93BBB76B3B7E1BF0E1B2D51E8A9411C2B6E649112F22F92DE63C2 |


### cisco-amp-computer-move
***
Moves a computer to a group with given connector_guid and group_guid.


#### Base Command

`cisco-amp-computer-move`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector_guid for specific computer. | Required | 
| group_guid | group_guid to move the computer to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Computer.connector_guid | String | GUID of the connector. | 
| CiscoAMP.Computer.hostname | String | Host's name. | 
| CiscoAMP.Computer.windows_processor_id | String | Windows processor ID. | 
| CiscoAMP.Computer.active | Boolean | Is the computer active. | 
| CiscoAMP.Computer.connector_version | String | Version of the connector. | 
| CiscoAMP.Computer.operating_system | String | Operating system of the computer. | 
| CiscoAMP.Computer.os_version | String | Operating system version. | 
| CiscoAMP.Computer.internal_ips | String | List of internal IP's. | 
| CiscoAMP.Computer.external_ip | String | External IP. | 
| CiscoAMP.Computer.group_guid | String | GUID of the group. | 
| CiscoAMP.Computer.install_date | Date | Installation date. | 
| CiscoAMP.Computer.is_compromised | Boolean | Is the computer compromised. | 
| CiscoAMP.Computer.demo | Boolean | Demo. | 
| CiscoAMP.Computer.network_addresses.mac | String | List of MAC addresses. | 
| CiscoAMP.Computer.network_addresses.ip | String | List of IP addresses. | 
| CiscoAMP.Computer.policy.guid | String | GUID of the policy. | 
| CiscoAMP.Computer.policy.name | String | Name of the policy. | 
| CiscoAMP.Computer.groups.guid | String | GUID of the group. | 
| CiscoAMP.Computer.groups.name | String | Name of the group. | 
| CiscoAMP.Computer.last_seen | Date | Last date seen. | 
| CiscoAMP.Computer.faults | String | Faults. | 
| CiscoAMP.Computer.isolation.available | Boolean | Is the isolation available. | 
| CiscoAMP.Computer.isolation.status | String | Status of the isolation. | 
| CiscoAMP.Computer.orbital.status | String | Status of the orbital. | 

#### Command example
```!cisco-amp-computer-move connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0 group_guid=bb5a9f90-d6fa-4fe7-99c8-e91060b49a98```
#### Context Example
```json
{
    "CiscoAMP": {
        "Computer": {
            "active": true,
            "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
            "connector_version": "8.0.1.21164",
            "demo": true,
            "external_ip": "221.71.163.177",
            "faults": [],
            "group_guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
            "groups": [
                {
                    "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                    "name": "Lior-Group"
                }
            ],
            "hostname": "Demo_AMP",
            "install_date": "2022-09-25T13:04:53Z",
            "internal_ips": [
                "191.250.254.209"
            ],
            "is_compromised": true,
            "isolation": {
                "available": true,
                "status": "not_isolated"
            },
            "network_addresses": [
                {
                    "ip": "191.250.254.209",
                    "mac": "e6:80:50:1e:e5:20"
                }
            ],
            "operating_system": "Windows 10",
            "os_version": "10.0.19044.1466",
            "policy": {
                "guid": "91c7894d-dd69-4a21-8cf6-5ebfc57ef4df",
                "name": "Lior-test"
            },
            "windows_processor_id": "3e0527a4d8916bf"
        }
    }
}
```

#### Human Readable Output

>### Computer Information
>|Host Name|Connector GUID|Operating System|External IP|Group GUID|Policy GUID|
>|---|---|---|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | Windows 10 (Build 10.0.19044.1466) | 221.71.163.177 | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 | 91c7894d-dd69-4a21-8cf6-5ebfc57ef4df |


### cisco-amp-computer-delete
***
Deletes a specific computer with given connector_guid.


#### Base Command

`cisco-amp-computer-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector_guid for specific computer. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-amp-computer-delete connector_guid=dddd4ceb-4ce1-4f81-a7a7-04d13cc1df43```
#### Human Readable Output

>Connector GUID: "dddd4ceb-4ce1-4f81-a7a7-04d13cc1df43"
>Successfully deleted.

### cisco-amp-computer-activity-list
***
Fetch a list of computers that have observed files with given file name. Provides the ability to search all computers across an organization for any events or activities associated with a file or network operation, and returns computers matching those criteria. There is a hard limit of 5000 historical entries searched.


#### Base Command

`cisco-amp-computer-activity-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_string | Freeform query string which currently accepts: IPv4 address (CIDR not supported), SHA-256, File Name and a URL Fragment. | Required | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerActivity.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerActivity.hostname | String | Host's name. | 
| CiscoAMP.ComputerActivity.windows_processor_id | String | Windows processor ID. | 
| CiscoAMP.ComputerActivity.active | Boolean | Is the computer active. | 

#### Command example
```!cisco-amp-computer-activity-list query_string=8.8.8.8```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerActivity": [
            {
                "active": true,
                "connector_guid": "1e104704-0b8f-4703-a49f-ec3d13e1e079",
                "hostname": "Demo_Dyre",
                "windows_processor_id": "346b8f2ad9e5107"
            },
            {
                "active": true,
                "connector_guid": "22b1d33c-b875-445f-8a98-d7fd05616ff0",
                "hostname": "Demo_Upatre",
                "windows_processor_id": "b2a9e0f43861d75"
            },
            {
                "active": true,
                "connector_guid": "33c101dd-4f50-4fd3-bce5-d3bd9d94e1a2",
                "hostname": "Demo_ZAccess",
                "windows_processor_id": "b047d5268e9a13f"
            },
            {
                "active": true,
                "connector_guid": "4d91c4ea-4f4d-4b87-b5d7-d34cc2c678a5",
                "hostname": "Demo_Global_Threat_Alerts",
                "windows_processor_id": "9af0463d1852be7"
            },
            {
                "active": true,
                "connector_guid": "ab22d66b-3443-4653-99ec-1fdeb680f30b",
                "hostname": "Demo_TDSS",
                "windows_processor_id": "0ad79f21856e34b"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 5 | 0 | 100 | 5 |
>### Activity Information
>|Connector GUID|Host Name|Windows Processor ID|Active|
>|---|---|---|---|
>| 1e104704-0b8f-4703-a49f-ec3d13e1e079 | Demo_Dyre | 346b8f2ad9e5107 | true |
>| 22b1d33c-b875-445f-8a98-d7fd05616ff0 | Demo_Upatre | b2a9e0f43861d75 | true |
>| 33c101dd-4f50-4fd3-bce5-d3bd9d94e1a2 | Demo_ZAccess | b047d5268e9a13f | true |
>| 4d91c4ea-4f4d-4b87-b5d7-d34cc2c678a5 | Demo_Global_Threat_Alerts | 9af0463d1852be7 | true |
>| ab22d66b-3443-4653-99ec-1fdeb680f30b | Demo_TDSS | 0ad79f21856e34b | true |


### cisco-amp-computer-isolation-feature-availability-get
***
Performs a feature availability request on a computer. Isolation must be enabled within the computer's Policy, this can be done through the instance. Log in to your account -> Management -> Policies -> Choose the relevant policy -> Edit -> Advanced Settings -> Endpoint Isolation -> Allow Endpoint Isolation


#### Base Command

`cisco-amp-computer-isolation-feature-availability-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector_guid for specific computer. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-amp-computer-isolation-feature-availability-get connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0```
#### Human Readable Output

>Can get information about an isolation with computer-isolation-get
>Can request to create a new isolation with computer-isolation-create


### cisco-amp-computer-isolation-get
***
Returns a fine-grained isolation status for a computer. The available flag is set to true if isolation can be performed on the computer. Status will be set to one of - not_isolated, pending_start, isolated and pending_stop. Isolation must be enabled within the computer's Policy, this can be done through the instance. Log in to your account -> Management -> Policies -> Choose the relevant policy -> Edit -> Advanced Settings -> Endpoint Isolation -> Allow Endpoint Isolation


#### Base Command

`cisco-amp-computer-isolation-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | connector_guid for specific computer. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerIsolation.connector_guid | String | ID of the connector. | 
| CiscoAMP.ComputerIsolation.available | Boolean | Set to true if isolation can be performed on the computer. | 
| CiscoAMP.ComputerIsolation.status | String | Will be set to one of: not_isolated, pending_start, isolated and pending_stop. | 
| CiscoAMP.ComputerIsolation.unlock_code | String | Isolation unlock code. | 
| CiscoAMP.ComputerIsolation.comment | String | Isolation comment. | 
| CiscoAMP.ComputerIsolation.ccms_message_guid | String | Cisco Cluster Management Suite message GUID. | 
| CiscoAMP.ComputerIsolation.ccms_job_guid | String | Cisco Cluster Management Suite job GUID. | 

#### Command example
```!cisco-amp-computer-isolation-get connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerIsolation": {
            "available": true,
            "comment": "End readme test",
            "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
            "status": "not_isolated",
            "unlock_code": "unlockme"
        }
    }
}
```

#### Human Readable Output

>### Isolation Information
>|Available|Status|Unlock Code|Comment|
>|---|---|---|---|
>| true | not_isolated | unlockme | End readme test |


### cisco-amp-computer-isolation-create
***
Request isolation for a computer. Supports Polling. Isolation must be enabled within the computer's Policy, this can be done through the instance. Log in to your account -> Management -> Policies -> Choose the relevant policy -> Edit -> Advanced Settings -> Endpoint Isolation -> Allow Endpoint Isolation


#### Base Command

`cisco-amp-computer-isolation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 
| connector_guid | connector_guid for specific computer. | Required | 
| comment | Comment for isolation. | Required | 
| unlock_code | Isolation unlock code. | Required | 
| status | argument to indicate the current run. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerIsolation.connector_guid | String | ID of the connector. | 
| CiscoAMP.ComputerIsolation.available | Boolean | Set to true if isolation can be performed on the computer. | 
| CiscoAMP.ComputerIsolation.status | String | Will be set to one of: not_isolated, pending_start, isolated and pending_stop. | 
| CiscoAMP.ComputerIsolation.unlock_code | String | Isolation unlock code. | 
| CiscoAMP.ComputerIsolation.comment | String | Isolation comment. | 
| CiscoAMP.ComputerIsolation.isolated_by | String | Isolation initiator. | 

#### Command example
```!cisco-amp-computer-isolation-create connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0 comment="readme generate test" unlock_code=unlockme interval_in_seconds=5 timeout_in_seconds=20```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerIsolation": {
            "available": true,
            "comment": "readme generate test",
            "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
            "isolated_by": "Lior Sabri",
            "status": "isolated",
            "unlock_code": "unlockme"
        }
    }
}
```

#### Human Readable Output

>### Isolation Information
>|Available|Status|Unlock Code|Comment|Isolated By|
>|---|---|---|---|---|
>| true | isolated | unlockme | readme generate test | Lior Sabri |


### cisco-amp-computer-isolation-delete
***
Request isolation stop for a computer. Supports Polling. Isolation must be enabled within the computer's Policy, this can be done through the instance. Log in to your account -> Management -> Policies -> Choose the relevant policy -> Edit -> Advanced Settings -> Endpoint Isolation -> Allow Endpoint Isolation


#### Base Command

`cisco-amp-computer-isolation-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 
| connector_guid | connector_guid for specific computer. | Required | 
| comment | Comment for isolation deletion. | Optional | 
| status | argument to indicate the current run. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerIsolation.available | Boolean | Set to true if isolation can be performed on the computer. | 
| CiscoAMP.ComputerIsolation.status | String | Will be set to one of: not_isolated, pending_start, isolated and pending_stop. | 
| CiscoAMP.ComputerIsolation.unlock_code | String | Isolation unlock code. | 
| CiscoAMP.ComputerIsolation.comment | String | Isolation comment. | 
| CiscoAMP.ComputerIsolation.isolated_by | String | Isolation initiator. | 

#### Command example
```!cisco-amp-computer-isolation-delete connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0 comment="End readme test" interval_in_seconds=5 timeout_in_seconds=20```
#### Human Readable Output

>Fetching Results:

### cisco-amp-event-list
***
Fetch a list of events that can be filtered by a variety of criteria. Each criteria type is logically ANDed with the other criteria, each selection of a criteria is logically ORed. This is analogous to the Events view on the FireAMP Console.


#### Base Command

`cisco-amp-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_sha256 | Detection  SHA-256 to filter by. | Optional | 
| application_sha256 | Application SHA-256 to filter by. | Optional | 
| connector_guid | Comma separated list for connector GUIDs to filter by. | Optional | 
| group_guid | Comma separated list for group GUIDs to filter by. | Optional | 
| start_date | Fetch events that are newer than given time. | Optional | 
| event_type | Comma separated list for event types to filter by. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Event.id | Number | Event's ID. | 
| CiscoAMP.Event.timestamp | Number | Event's timestamp. | 
| CiscoAMP.Event.timestamp_nanoseconds | Number | Event's timestamp nano seconds. | 
| CiscoAMP.Event.date | Date | Event's date. | 
| CiscoAMP.Event.event_type | String | Event's type. | 
| CiscoAMP.Event.event_type_id | Number | Event's type ID. | 
| CiscoAMP.Event.detection | String | Event's detection. | 
| CiscoAMP.Event.detection_id | String | Event's detection ID. | 
| CiscoAMP.Event.connector_guid | String | GUID of the connector. | 
| CiscoAMP.Event.group_guids | String | Event's group GUID. | 
| CiscoAMP.Event.severity | String | Event's severity. | 
| CiscoAMP.Event.computer.connector_guid | String | GUID of the connector. | 
| CiscoAMP.Event.computer.hostname | String | Host's name. | 
| CiscoAMP.Event.computer.external_ip | String | External IP. | 
| CiscoAMP.Event.computer.active | Boolean | Is the computer active. | 
| CiscoAMP.Event.computer.user | String | Computer user. | 
| CiscoAMP.Event.computer.network_addresses.ip | String | List of IP addresses. | 
| CiscoAMP.Event.computer.network_addresses.mac | String | List of MAC addresses. | 
| CiscoAMP.Event.file.disposition | String | Disposition of the file. | 
| CiscoAMP.Event.file.file_name | String | Name of the file. | 
| CiscoAMP.Event.file.file_path | String | Path to the file. | 
| CiscoAMP.Event.file.identity.sha256 | String | File's SHA-256. | 
| CiscoAMP.Event.file.identity.sha1 | String | File's SHA-1. | 
| CiscoAMP.Event.file.identity.md5 | String | File's MD5 | 
| CiscoAMP.Event.file.parent.process_id | Number | Parent's process ID. | 
| CiscoAMP.Event.file.parent.file_name | String | Parent's file name | 
| CiscoAMP.Event.file.parent.disposition | String | Parent's disposition. | 
| CiscoAMP.Event.file.parent.identity.sha256 | String | Parent's SHA-256. | 
| CiscoAMP.Event.file.parent.identity.sha1 | String | Parent's SHA-1. | 
| CiscoAMP.Event.file.parent.identity.md5 | String | Parent's MD5. | 
| CiscoAMP.Event.scan.description | String | Description. | 
| CiscoAMP.Event.scan.clean | Boolean | Whether it is clean. | 
| CiscoAMP.Event.scan.scanned_files | Number | Number of scanned files. | 
| CiscoAMP.Event.scan.scanned_processes | Number | Number of scanned processes. | 
| CiscoAMP.Event.scan.scanned_paths | Number | Number of scanned paths. | 
| CiscoAMP.Event.scan.malicious_detections | Number | Number of malicious detections. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name \(including file extension\). | 
| File.Path | String | The path where the file is located. | 
| File.Hostname | String | The name of the host where the file was found. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 

#### Command example
```!cisco-amp-event-list limit=5```
#### Context Example
```json
{
    "CiscoAMP": {
        "Event": [
            {
                "computer": {
                    "active": true,
                    "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                    "external_ip": "221.71.163.177",
                    "hostname": "Demo_AMP",
                    "network_addresses": [
                        {
                            "ip": "191.250.254.209",
                            "mac": "e6:80:50:1e:e5:20"
                        }
                    ]
                },
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T12:15:13+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": 1667218513509436400,
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667218513,
                "timestamp_nanoseconds": 0
            },
            {
                "computer": {
                    "active": true,
                    "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                    "external_ip": "221.71.163.177",
                    "hostname": "Demo_AMP",
                    "network_addresses": [
                        {
                            "ip": "191.250.254.209",
                            "mac": "e6:80:50:1e:e5:20"
                        }
                    ]
                },
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T12:15:06+00:00",
                "event_type": "Endpoint Isolation Start Success",
                "event_type_id": 553648202,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": 1667218506680244500,
                "timestamp": 1667218506,
                "timestamp_nanoseconds": 0
            },
            {
                "computer": {
                    "active": true,
                    "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                    "external_ip": "221.71.163.177",
                    "hostname": "Demo_AMP",
                    "network_addresses": [
                        {
                            "ip": "191.250.254.209",
                            "mac": "e6:80:50:1e:e5:20"
                        }
                    ]
                },
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:55:05+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": 1667217305855412000,
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667217305,
                "timestamp_nanoseconds": 0
            },
            {
                "computer": {
                    "active": true,
                    "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                    "external_ip": "221.71.163.177",
                    "hostname": "Demo_AMP",
                    "network_addresses": [
                        {
                            "ip": "191.250.254.209",
                            "mac": "e6:80:50:1e:e5:20"
                        }
                    ]
                },
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:54:58+00:00",
                "event_type": "Endpoint Isolation Start Success",
                "event_type_id": 553648202,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": 1667217298837175300,
                "timestamp": 1667217298,
                "timestamp_nanoseconds": 0
            },
            {
                "computer": {
                    "active": true,
                    "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                    "external_ip": "221.71.163.177",
                    "hostname": "Demo_AMP",
                    "network_addresses": [
                        {
                            "ip": "191.250.254.209",
                            "mac": "e6:80:50:1e:e5:20"
                        }
                    ]
                },
                "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                "date": "2022-10-31T11:42:25+00:00",
                "event_type": "Endpoint Isolation Stop Success",
                "event_type_id": 553648204,
                "group_guids": [
                    "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98"
                ],
                "id": 1667216545769122000,
                "isolation": {
                    "duration": 46
                },
                "timestamp": 1667216545,
                "timestamp_nanoseconds": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 5 | 0 | 5 | 1228 |
>### Event Information
>|ID|Date|Event Type|Connector GUID|
>|---|---|---|---|
>| 1667218513509436397 | 2022-10-31T12:15:13+00:00 | Endpoint Isolation Stop Success | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 |
>| 1667218506680244597 | 2022-10-31T12:15:06+00:00 | Endpoint Isolation Start Success | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 |
>| 1667217305855411965 | 2022-10-31T11:55:05+00:00 | Endpoint Isolation Stop Success | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 |
>| 1667217298837175263 | 2022-10-31T11:54:58+00:00 | Endpoint Isolation Start Success | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 |
>| 1667216545769121964 | 2022-10-31T11:42:25+00:00 | Endpoint Isolation Stop Success | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 |


### cisco-amp-event-type-list
***
Fetch a list of event types. Events are identified and filtered by a unique ID.


#### Base Command

`cisco-amp-event-type-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.EventType.id | Number | Event type ID. | 
| CiscoAMP.EventType.name | String | Event type name. | 
| CiscoAMP.EventType.description | String | Event type description. | 

#### Command example
```!cisco-amp-event-type-list limit=5```
#### Context Example
```json
{
    "CiscoAMP": {
        "EventType": [
            {
                "description": "A new agent has registered with the system.",
                "id": 50331649,
                "name": "Initial Agent Registration"
            },
            {
                "description": "An agent has been told to fetch policy.",
                "id": 553648130,
                "name": "Policy Update"
            },
            {
                "description": "An agent has started scanning.",
                "id": 554696714,
                "name": "Scan Started"
            },
            {
                "description": "A scan has completed without detecting anything malicious.",
                "id": 554696715,
                "name": "Scan Completed, No Detections"
            },
            {
                "description": "A scan has completed and detected malicious items.",
                "id": 1091567628,
                "name": "Scan Completed With Detections"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Total|
>|---|
>| 106 |
>### Event Type Information
>|ID|Name|Description|
>|---|---|---|
>| 50331649 | Initial Agent Registration | A new agent has registered with the system. |
>| 553648130 | Policy Update | An agent has been told to fetch policy. |
>| 554696714 | Scan Started | An agent has started scanning. |
>| 554696715 | Scan Completed, No Detections | A scan has completed without detecting anything malicious. |
>| 1091567628 | Scan Completed With Detections | A scan has completed and detected malicious items. |


### cisco-amp-file-list-list
***
Returns a particular file list for application blocking or simple custom detection. file_list_guid must be provided to retrieve information about a particular file_list. Can fetch an application_blocking or simple_custom_detection file list. Defaults to application_blocking.


#### Base Command

`cisco-amp-file-list-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_list_type | Fetch a list type to return. Possible values are: Application Blocking, Simple Custom Detection. Default is Application Blocking. | Optional | 
| name | Coma separated list for name to filter by (has auto complete capabilities). | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 
| file_list_guid | GUID of the file list to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.FileList.name | String | Name of blocking. | 
| CiscoAMP.FileList.guid | String | File list GUID. | 
| CiscoAMP.FileList.type | String | Type of blocking. | 

#### Command example
```!cisco-amp-file-list-list```
#### Context Example
```json
{
    "CiscoAMP": {
        "FileList": {
            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
            "name": "Blocked Application List",
            "type": "application_blocking"
        }
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 1 | 0 | 100 | 1 |
>### File List Information
>|GUID|Name|Type|
>|---|---|---|
>| 1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12 | Blocked Application List | application_blocking |


### cisco-amp-file-list-item-list
***
Returns a list of items for a particular file_list. file_list_guid must be provided to retrieve these items. A particular item can be returned by providing a SHA-256.


#### Base Command

`cisco-amp-file-list-item-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_list_guid | File list to return. | Required | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 
| sha256 | File list item SHA-256 to search. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.FileListItem.name | String | Name of file list. | 
| CiscoAMP.FileListItem.guid | String | File list GUID. | 
| CiscoAMP.FileListItem.policies.name | String | Name of the policy. | 
| CiscoAMP.FileListItem.policies.guid | String | Policy GUID. | 
| CiscoAMP.FileListItem.items.sha256 | String | Item SHA-256. | 
| CiscoAMP.FileListItem.items.source | String | Item source. | 

#### Command example
```!cisco-amp-file-list-item-list file_list_guid=1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12```
#### Context Example
```json
{
    "CiscoAMP": {
        "FileListItem": {
            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
            "items": [],
            "name": "Blocked Application List",
            "policies": [
                {
                    "guid": "be84e169-0830-4b95-915b-1e203a82ed58",
                    "name": "Audit"
                },
                {
                    "guid": "a599bf5b-2cb7-4a5b-90bd-d0199e2ccd67",
                    "name": "Protect"
                },
                {
                    "guid": "1a352c59-793b-44f3-b8f9-0ddd354057bc",
                    "name": "Triage"
                },
                {
                    "guid": "dd1da971-926c-42ab-9e5a-154f2695d995",
                    "name": "Server"
                },
                {
                    "guid": "fa0c377e-8f0a-40ab-885a-afc8c08d3732",
                    "name": "Domain Controller"
                },
                {
                    "guid": "9f2fa537-df5d-4c6c-abf3-edc25a893a7a",
                    "name": "Audit"
                },
                {
                    "guid": "30fba653-eb4e-4c3d-b1bb-1cef9f0e31e4",
                    "name": "Protect"
                },
                {
                    "guid": "cfcf4841-bf00-4030-8ac3-4a607ecf245e",
                    "name": "Triage"
                },
                {
                    "guid": "b4e266c8-ebd1-4e94-80b6-b04a966cb0d5",
                    "name": "Audit"
                },
                {
                    "guid": "653508ed-28d4-465a-80c4-7ed9c0232b55",
                    "name": "Protect"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 0 | 0 | 100 | 0 |
>### File List Item Information
>**No entries.**
>### Related Policy Information
>|Name|Guid|
>|---|---|
>| Audit | be84e169-0830-4b95-915b-1e203a82ed58 |
>| Protect | a599bf5b-2cb7-4a5b-90bd-d0199e2ccd67 |
>| Triage | 1a352c59-793b-44f3-b8f9-0ddd354057bc |
>| Server | dd1da971-926c-42ab-9e5a-154f2695d995 |
>| Domain Controller | fa0c377e-8f0a-40ab-885a-afc8c08d3732 |
>| Audit | 9f2fa537-df5d-4c6c-abf3-edc25a893a7a |
>| Protect | 30fba653-eb4e-4c3d-b1bb-1cef9f0e31e4 |
>| Triage | cfcf4841-bf00-4030-8ac3-4a607ecf245e |
>| Audit | b4e266c8-ebd1-4e94-80b6-b04a966cb0d5 |
>| Protect | 653508ed-28d4-465a-80c4-7ed9c0232b55 |


### cisco-amp-file-list-item-create
***
Create a file list item with a given SHA-256 for a specific file list with a given file_list_guid.


#### Base Command

`cisco-amp-file-list-item-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_list_guid | File list to add to. | Required | 
| sha256 | File list item's SHA-256 to add. | Required | 
| description | Description for the created item. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.FileListItem.sha256 | String | Item SHA-256. | 
| CiscoAMP.FileListItem.description | String | File's description. | 
| CiscoAMP.FileListItem.source | String | Item source. | 

#### Command example
```!cisco-amp-file-list-item-create file_list_guid=1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12 sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad```
#### Context Example
```json
{
    "CiscoAMP": {
        "FileListItem": {
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "source": "Created by entering SHA-256 via Public api."
        }
    }
}
```

#### Human Readable Output

>### File List Item Information
>|SHA-256|Source|
>|---|---|
>| ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad | Created by entering SHA-256 via Public api. |


### cisco-amp-file-list-item-delete
***
Deletes a file list item with a given SHA-256 and associated to file list with given file_list_guid.


#### Base Command

`cisco-amp-file-list-item-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_list_guid | File list to delete from. | Required | 
| sha256 | File list item SHA-256 to delete. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-amp-file-list-item-delete file_list_guid=1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12 sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad```
#### Human Readable Output

>SHA-256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" Successfully deleted from File List GUID: "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12".

### cisco-amp-group-list
***
Provides information about groups in an organization.


#### Base Command

`cisco-amp-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name to filter by (has auto complete capabilities). | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 
| group_guid | Groups GUID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Group.name | String | Name of the group. | 
| CiscoAMP.Group.description | String | Group's description. | 
| CiscoAMP.Group.guid | String | Group GUID. | 
| CiscoAMP.Group.source | String | Creation source. | 
| CiscoAMP.Group.creator | String | Creator of the group. | 
| CiscoAMP.Group.created_at | Date | Date of creation. | 
| CiscoAMP.Group.computers_count | Number | Number of computers in the group. | 
| CiscoAMP.Group.descendant_computers_count | Number | Number of computers from descendant groups. | 
| CiscoAMP.Group.ancestry.name | String | Parent group name. | 
| CiscoAMP.Group.ancestry.guid | String | Parent group GUID. | 
| CiscoAMP.Group.child_groups.name | String | Child group name. | 
| CiscoAMP.Group.child_groups.guid | String | Child group GUID. | 
| CiscoAMP.Group.policies.name | String | Policy Name. | 
| CiscoAMP.Group.policies.description | String | Policy description. | 
| CiscoAMP.Group.policies.guid | String | Policy GUID. | 
| CiscoAMP.Group.policies.product | String | Policy OS product. | 
| CiscoAMP.Group.policies.default | Boolean | Is the policy default. | 
| CiscoAMP.Group.policies.serial_number | Number | Policy serial number. | 
| CiscoAMP.Group.policies.inherited | Boolean | Is the policy inherited. | 
| CiscoAMP.Group.policies.file_lists.name | String | File list name. | 
| CiscoAMP.Group.policies.file_lists.guid | String | File list GUID. | 
| CiscoAMP.Group.policies.file_lists.type | String | File list type. | 
| CiscoAMP.Group.policies.ip_lists.name | String | IP list name. | 
| CiscoAMP.Group.policies.ip_lists.guid | String | IP list GUID. | 
| CiscoAMP.Group.policies.ip_lists.type | String | IP list type. | 
| CiscoAMP.Group.policies.exclusion_sets.name | String | Exclusion set name. | 
| CiscoAMP.Group.policies.exclusion_sets.guid | String | Exclusion set GUID. | 
| CiscoAMP.Group.policies.used_in_groups.name | String | Name of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.description | String | Description of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.guid | String | GUID of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.source | String | Creation source of the group it is used in. | 

#### Command example
```!cisco-amp-group-list```
#### Context Example
```json
{
    "CiscoAMP": {
        "Group": [
            {
                "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                "name": "Audit",
                "source": null
            },
            {
                "description": "Domain Controller Group for QMASTERS SECURITY SERVICES LTD",
                "guid": "92615a6b-631f-4436-b2da-47e94b349737",
                "name": "Domain Controller",
                "source": null
            },
            {
                "description": "playbook delete",
                "guid": "e66a0f8a-47f6-4da5-bf95-2834f668d71b",
                "name": "group todelete",
                "source": "Created via API"
            },
            {
                "description": "Test group",
                "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                "name": "Lior-Group",
                "source": null
            },
            {
                "ancestry": [
                    {
                        "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                        "name": "Lior-Group"
                    }
                ],
                "description": "Test child group",
                "guid": "8b5245b5-993b-4ba9-9fe0-fb0454e815e5",
                "name": "Lior-Group-child",
                "source": null
            },
            {
                "description": "Protect Group for QMASTERS SECURITY SERVICES LTD",
                "guid": "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18",
                "name": "Protect",
                "source": null
            },
            {
                "description": "readme test group to be deleted",
                "guid": "d088adeb-7cb4-48e4-807b-edcb828f4d29",
                "name": "readme group to delete",
                "source": "Created via API"
            },
            {
                "description": "Server Group for QMASTERS SECURITY SERVICES LTD",
                "guid": "9b54e512-b5ac-4865-ba1f-8cf2fbfbe052",
                "name": "Server",
                "source": null
            },
            {
                "description": "Triage Group for QMASTERS SECURITY SERVICES LTD",
                "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                "name": "Triage",
                "source": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 9 | 0 | 100 | 9 |
>### Group Information
>|Name|Description|GUID|Source|
>|---|---|---|---|
>| Audit | Audit Group for QMASTERS SECURITY SERVICES LTD | fedd82f8-c74f-49f4-a463-e576d3beee92 |  |
>| Domain Controller | Domain Controller Group for QMASTERS SECURITY SERVICES LTD | 92615a6b-631f-4436-b2da-47e94b349737 |  |
>| group todelete | playbook delete | e66a0f8a-47f6-4da5-bf95-2834f668d71b | Created via API |
>| Lior-Group | Test group | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 |  |
>| Lior-Group-child | Test child group | 8b5245b5-993b-4ba9-9fe0-fb0454e815e5 |  |
>| Protect | Protect Group for QMASTERS SECURITY SERVICES LTD | 5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18 |  |
>| readme group to delete | readme test group to be deleted | d088adeb-7cb4-48e4-807b-edcb828f4d29 | Created via API |
>| Server | Server Group for QMASTERS SECURITY SERVICES LTD | 9b54e512-b5ac-4865-ba1f-8cf2fbfbe052 |  |
>| Triage | Triage Group for QMASTERS SECURITY SERVICES LTD | 6ed80412-0739-42c1-8f6d-32fb51b3f894 |  |


### cisco-amp-group-policy-update
***
Updates a group to a given policy and returns all the policies in that group.


#### Base Command

`cisco-amp-group-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_guid | Groups GUID. | Required | 
| windows_policy_guid | Policy GUID for Windows. | Optional | 
| mac_policy_guid | Policy GUID for MAC. | Optional | 
| android_policy_guid | Policy GUID for Android. | Optional | 
| linux_policy_guid | Policy GUID for Linux. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Group.name | String | Name of the group. | 
| CiscoAMP.Group.description | String | Group's description. | 
| CiscoAMP.Group.guid | String | Group GUID. | 
| CiscoAMP.Group.source | String | Creation source. | 
| CiscoAMP.Group.creator | String | Creator of the group. | 
| CiscoAMP.Group.created_at | Date | Date of creation. | 
| CiscoAMP.Group.computers_count | Number | Number of computers in the group. | 
| CiscoAMP.Group.descendant_computers_count | Number | Number of computers from descendant groups. | 
| CiscoAMP.Group.ancestry.name | String | Parent group name. | 
| CiscoAMP.Group.ancestry.guid | String | Parent group GUID. | 
| CiscoAMP.Group.child_groups.name | String | Child group name. | 
| CiscoAMP.Group.child_groups.guid | String | Child group GUID. | 
| CiscoAMP.Group.policies.name | String | Policy Name. | 
| CiscoAMP.Group.policies.description | String | Policy description. | 
| CiscoAMP.Group.policies.guid | String | Policy GUID. | 
| CiscoAMP.Group.policies.product | String | Policy OS product. | 
| CiscoAMP.Group.policies.default | Boolean | Is the policy default. | 
| CiscoAMP.Group.policies.serial_number | Number | Policy serial number. | 
| CiscoAMP.Group.policies.inherited | Boolean | Is the policy inherited. | 
| CiscoAMP.Group.policies.file_lists.name | String | File list name. | 
| CiscoAMP.Group.policies.file_lists.guid | String | File list GUID. | 
| CiscoAMP.Group.policies.file_lists.type | String | File list type. | 
| CiscoAMP.Group.policies.ip_lists.name | String | IP list name. | 
| CiscoAMP.Group.policies.ip_lists.guid | String | IP list GUID. | 
| CiscoAMP.Group.policies.ip_lists.type | String | IP list type. | 
| CiscoAMP.Group.policies.exclusion_sets.name | String | Exclusion set name. | 
| CiscoAMP.Group.policies.exclusion_sets.guid | String | Exclusion set GUID. | 
| CiscoAMP.Group.policies.used_in_groups.name | String | Name of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.description | String | Description of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.guid | String | GUID of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.source | String | Creation source of the group it is used in. | 

#### Command example
```!cisco-amp-group-policy-update group_guid=bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 windows_policy_guid=91c7894d-dd69-4a21-8cf6-5ebfc57ef4df```
#### Context Example
```json
{
    "CiscoAMP": {
        "Group": {
            "child_groups": [
                {
                    "guid": "8b5245b5-993b-4ba9-9fe0-fb0454e815e5",
                    "name": "Lior-Group-child"
                }
            ],
            "computers_count": 1,
            "created_at": "2022-10-25 13:42:36",
            "creator": "LiorS@qmasters.co",
            "descendant_computers_count": 0,
            "description": "Test group",
            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
            "name": "Lior-Group",
            "policies": [
                {
                    "default": false,
                    "description": "Test policy",
                    "exclusion_sets": [
                        {
                            "guid": "9381546e-1617-46ae-98e7-f92fde16cffe",
                            "name": "Microsoft Windows Default"
                        }
                    ],
                    "file_lists": [],
                    "guid": "91c7894d-dd69-4a21-8cf6-5ebfc57ef4df",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Lior-test",
                    "product": "windows",
                    "serial_number": 27,
                    "used_in_groups": [
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": true,
                    "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                    "file_lists": [],
                    "guid": "082bc9a3-b73a-4f42-8cc5-de1cd3748700",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Protect",
                    "product": "android",
                    "serial_number": 11,
                    "used_in_groups": [
                        {
                            "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                            "name": "Audit"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": false,
                    "description": "This is an aggressive policy that enables the offline engine to scan computers that are suspected or known to be infected with malware.",
                    "exclusion_sets": [
                        {
                            "guid": "6eddded0-ac73-4bc3-b64e-b9d556fe5aec",
                            "name": "McAfee"
                        },
                        {
                            "guid": "368fecf4-b71d-4f79-94f9-e44dbbcc7d54",
                            "name": "Fusion"
                        },
                        {
                            "guid": "e80c3ce5-6184-49f0-9b40-c2dc2cfd1685",
                            "name": "Crashplan"
                        },
                        {
                            "guid": "893c2cad-ae76-407f-8b53-7d3a1fe9e995",
                            "name": "JAMF Casper"
                        },
                        {
                            "guid": "c5a855f5-1403-41ee-8b87-970652b52d55",
                            "name": "Jabber"
                        },
                        {
                            "guid": "52c66406-120e-47e8-ad8f-bd523900e8a4",
                            "name": "Microsoft Office"
                        },
                        {
                            "guid": "cc79a33d-d15b-4200-957d-d76f17f86cbe",
                            "name": "Apple macOS Default"
                        }
                    ],
                    "file_lists": [
                        {
                            "guid": "cd7d1e2a-147b-4ac9-8f15-6f2cfe36afc8",
                            "name": "Simple Custom Detection List",
                            "type": "simple_custom_detections"
                        },
                        {
                            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
                            "name": "Blocked Application List",
                            "type": "application_blocking"
                        },
                        {
                            "guid": "9309476f-6964-44ca-8ef9-27204d980d3a",
                            "name": "Allowed Application List",
                            "type": "allowed_applications"
                        }
                    ],
                    "guid": "cfcf4841-bf00-4030-8ac3-4a607ecf245e",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Triage",
                    "product": "mac",
                    "serial_number": 17,
                    "used_in_groups": [
                        {
                            "description": "Triage Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                            "name": "Triage"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": false,
                    "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                    "file_lists": [
                        {
                            "guid": "cd7d1e2a-147b-4ac9-8f15-6f2cfe36afc8",
                            "name": "Simple Custom Detection List",
                            "type": "simple_custom_detections"
                        },
                        {
                            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
                            "name": "Blocked Application List",
                            "type": "application_blocking"
                        },
                        {
                            "guid": "9309476f-6964-44ca-8ef9-27204d980d3a",
                            "name": "Allowed Application List",
                            "type": "allowed_applications"
                        }
                    ],
                    "guid": "653508ed-28d4-465a-80c4-7ed9c0232b55",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Protect",
                    "product": "linux",
                    "serial_number": 21,
                    "used_in_groups": [
                        {
                            "description": "Protect Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18",
                            "name": "Protect"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": false,
                    "description": "This is the standard policy for Clarity that will log and alert on convictions and block any potentially malicious traffic.",
                    "file_lists": [],
                    "guid": "c90936b3-2ad7-458c-90a3-a806d50ed16e",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Protect",
                    "product": "ios",
                    "serial_number": 25,
                    "used_in_groups": [
                        {
                            "description": "Protect Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18",
                            "name": "Protect"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                }
            ],
            "source": null
        }
    }
}
```

#### Human Readable Output

>### Group Information
>|Name|Description|Creator|Created At|Computers Count|Descendant Computers Count|
>|---|---|---|---|---|---|
>| Lior-Group | Test group | LiorS@qmasters.co | 2022-10-25 13:42:36 | 1 | 0 |


### cisco-amp-group-parent-update
***
Converts an existing group to a child of another group or an existing child group to a root group (that is, one with no parent groups).


#### Base Command

`cisco-amp-group-parent-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| child_guid | Groups GUID. | Required | 
| parent_group_guid | Group parent to set to child group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Group.name | String | Name of the group. | 
| CiscoAMP.Group.description | String | Group's description. | 
| CiscoAMP.Group.guid | String | Group GUID. | 
| CiscoAMP.Group.source | String | Creation source. | 
| CiscoAMP.Group.creator | String | Creator of the group. | 
| CiscoAMP.Group.created_at | Date | Date of creation. | 
| CiscoAMP.Group.computers_count | Number | Number of computers in the group. | 
| CiscoAMP.Group.descendant_computers_count | Number | Number of computers from descendant groups. | 
| CiscoAMP.Group.ancestry.name | String | Parent group name. | 
| CiscoAMP.Group.ancestry.guid | String | Parent group GUID. | 
| CiscoAMP.Group.child_groups.name | String | Child group name. | 
| CiscoAMP.Group.child_groups.guid | String | Child group GUID. | 
| CiscoAMP.Group.policies.name | String | Policy Name. | 
| CiscoAMP.Group.policies.description | String | Policy description. | 
| CiscoAMP.Group.policies.guid | String | Policy GUID. | 
| CiscoAMP.Group.policies.product | String | Policy OS product. | 
| CiscoAMP.Group.policies.default | Boolean | Is the policy default. | 
| CiscoAMP.Group.policies.serial_number | Number | Policy serial number. | 
| CiscoAMP.Group.policies.inherited | Boolean | Is the policy inherited. | 
| CiscoAMP.Group.policies.file_lists.name | String | File list name. | 
| CiscoAMP.Group.policies.file_lists.guid | String | File list GUID. | 
| CiscoAMP.Group.policies.file_lists.type | String | File list type. | 
| CiscoAMP.Group.policies.ip_lists.name | String | IP list name. | 
| CiscoAMP.Group.policies.ip_lists.guid | String | IP list GUID. | 
| CiscoAMP.Group.policies.ip_lists.type | String | IP list type. | 
| CiscoAMP.Group.policies.exclusion_sets.name | String | Exclusion set name. | 
| CiscoAMP.Group.policies.exclusion_sets.guid | String | Exclusion set GUID. | 
| CiscoAMP.Group.policies.used_in_groups.name | String | Name of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.description | String | Description of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.guid | String | GUID of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.source | String | Creation source of the group it is used in. | 

#### Command example
```!cisco-amp-group-parent-update child_guid=bb5a9f90-d6fa-4fe7-99c8-e91060b49a98```
#### Context Example
```json
{
    "CiscoAMP": {
        "Group": {
            "child_groups": [
                {
                    "guid": "8b5245b5-993b-4ba9-9fe0-fb0454e815e5",
                    "name": "Lior-Group-child"
                }
            ],
            "computers_count": 1,
            "created_at": "2022-10-25 13:42:36",
            "creator": "LiorS@qmasters.co",
            "descendant_computers_count": 0,
            "description": "Test group",
            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
            "name": "Lior-Group",
            "policies": [
                {
                    "default": false,
                    "description": "Test policy",
                    "exclusion_sets": [
                        {
                            "guid": "9381546e-1617-46ae-98e7-f92fde16cffe",
                            "name": "Microsoft Windows Default"
                        }
                    ],
                    "file_lists": [],
                    "guid": "91c7894d-dd69-4a21-8cf6-5ebfc57ef4df",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Lior-test",
                    "product": "windows",
                    "serial_number": 27,
                    "used_in_groups": [
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": true,
                    "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                    "file_lists": [],
                    "guid": "082bc9a3-b73a-4f42-8cc5-de1cd3748700",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Protect",
                    "product": "android",
                    "serial_number": 11,
                    "used_in_groups": [
                        {
                            "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                            "name": "Audit"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": false,
                    "description": "This is an aggressive policy that enables the offline engine to scan computers that are suspected or known to be infected with malware.",
                    "exclusion_sets": [
                        {
                            "guid": "6eddded0-ac73-4bc3-b64e-b9d556fe5aec",
                            "name": "McAfee"
                        },
                        {
                            "guid": "368fecf4-b71d-4f79-94f9-e44dbbcc7d54",
                            "name": "Fusion"
                        },
                        {
                            "guid": "e80c3ce5-6184-49f0-9b40-c2dc2cfd1685",
                            "name": "Crashplan"
                        },
                        {
                            "guid": "893c2cad-ae76-407f-8b53-7d3a1fe9e995",
                            "name": "JAMF Casper"
                        },
                        {
                            "guid": "c5a855f5-1403-41ee-8b87-970652b52d55",
                            "name": "Jabber"
                        },
                        {
                            "guid": "52c66406-120e-47e8-ad8f-bd523900e8a4",
                            "name": "Microsoft Office"
                        },
                        {
                            "guid": "cc79a33d-d15b-4200-957d-d76f17f86cbe",
                            "name": "Apple macOS Default"
                        }
                    ],
                    "file_lists": [
                        {
                            "guid": "cd7d1e2a-147b-4ac9-8f15-6f2cfe36afc8",
                            "name": "Simple Custom Detection List",
                            "type": "simple_custom_detections"
                        },
                        {
                            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
                            "name": "Blocked Application List",
                            "type": "application_blocking"
                        },
                        {
                            "guid": "9309476f-6964-44ca-8ef9-27204d980d3a",
                            "name": "Allowed Application List",
                            "type": "allowed_applications"
                        }
                    ],
                    "guid": "cfcf4841-bf00-4030-8ac3-4a607ecf245e",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Triage",
                    "product": "mac",
                    "serial_number": 17,
                    "used_in_groups": [
                        {
                            "description": "Triage Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                            "name": "Triage"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": false,
                    "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                    "file_lists": [
                        {
                            "guid": "cd7d1e2a-147b-4ac9-8f15-6f2cfe36afc8",
                            "name": "Simple Custom Detection List",
                            "type": "simple_custom_detections"
                        },
                        {
                            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
                            "name": "Blocked Application List",
                            "type": "application_blocking"
                        },
                        {
                            "guid": "9309476f-6964-44ca-8ef9-27204d980d3a",
                            "name": "Allowed Application List",
                            "type": "allowed_applications"
                        }
                    ],
                    "guid": "653508ed-28d4-465a-80c4-7ed9c0232b55",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Protect",
                    "product": "linux",
                    "serial_number": 21,
                    "used_in_groups": [
                        {
                            "description": "Protect Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18",
                            "name": "Protect"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": false,
                    "description": "This is the standard policy for Clarity that will log and alert on convictions and block any potentially malicious traffic.",
                    "file_lists": [],
                    "guid": "c90936b3-2ad7-458c-90a3-a806d50ed16e",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Protect",
                    "product": "ios",
                    "serial_number": 25,
                    "used_in_groups": [
                        {
                            "description": "Protect Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18",
                            "name": "Protect"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                }
            ],
            "source": null
        }
    }
}
```

#### Human Readable Output

>### Group Information
>|Name|Description|Creator|Created At|Computers Count|Descendant Computers Count|
>|---|---|---|---|---|---|
>| Lior-Group | Test group | LiorS@qmasters.co | 2022-10-25 13:42:36 | 1 | 0 |


### cisco-amp-group-create
***
Creates a new group along with a group name or description.


#### Base Command

`cisco-amp-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Group name. | Required | 
| description | Group description. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Group.name | String | Name of the group. | 
| CiscoAMP.Group.description | String | Group's description. | 
| CiscoAMP.Group.guid | String | Group GUID. | 
| CiscoAMP.Group.source | String | Creation source. | 
| CiscoAMP.Group.creator | String | Creator of the group. | 
| CiscoAMP.Group.created_at | Date | Date of creation. | 
| CiscoAMP.Group.computers_count | Number | Number of computers in the group. | 
| CiscoAMP.Group.descendant_computers_count | Number | Number of computers from descendant groups. | 
| CiscoAMP.Group.policies.name | String | Policy Name. | 
| CiscoAMP.Group.policies.description | String | Policy description. | 
| CiscoAMP.Group.policies.guid | String | Policy GUID. | 
| CiscoAMP.Group.policies.product | String | Policy OS product. | 
| CiscoAMP.Group.policies.default | Boolean | Is the policy default. | 
| CiscoAMP.Group.policies.serial_number | Number | Policy serial number. | 
| CiscoAMP.Group.policies.inherited | Boolean | Is the policy inherited. | 
| CiscoAMP.Group.policies.file_lists.name | String | File list name. | 
| CiscoAMP.Group.policies.file_lists.guid | String | File list GUID. | 
| CiscoAMP.Group.policies.file_lists.type | String | File list type. | 
| CiscoAMP.Group.policies.ip_lists.name | String | IP list name. | 
| CiscoAMP.Group.policies.ip_lists.guid | String | IP list GUID. | 
| CiscoAMP.Group.policies.ip_lists.type | String | IP list type. | 
| CiscoAMP.Group.policies.exclusion_sets.name | String | Exclusion set name. | 
| CiscoAMP.Group.policies.exclusion_sets.guid | String | Exclusion set GUID. | 
| CiscoAMP.Group.policies.used_in_groups.name | String | Name of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.description | String | Description of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.guid | String | GUID of the group it is used in. | 
| CiscoAMP.Group.policies.used_in_groups.source | String | Creation source of the group it is used in. | 

#### Command example
```!cisco-amp-group-create description="readme test group to be deleted" name="readme group"```
#### Context Example
```json
{
    "CiscoAMP": {
        "Group": {
            "computers_count": 0,
            "created_at": "2022-10-31 12:16:25",
            "creator": null,
            "descendant_computers_count": 0,
            "description": "readme test group to be deleted",
            "guid": "50b74401-e96e-42d2-8569-3348f816bca9",
            "name": "readme group",
            "policies": [
                {
                    "default": true,
                    "description": "This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked.",
                    "exclusion_sets": [
                        {
                            "guid": "2168ece6-34b4-428c-92e9-cb7c23e767d4",
                            "name": "Avira"
                        },
                        {
                            "guid": "2d3530b0-8661-4318-9db5-59f4b9b9714e",
                            "name": "AVAST"
                        },
                        {
                            "guid": "028fe9b1-a500-4df5-bb78-a2dcfcc14ad8",
                            "name": "Kaspersky"
                        },
                        {
                            "guid": "0fea67dc-8017-40fe-8010-c3b9a6a40e79",
                            "name": "Windows Defender"
                        },
                        {
                            "guid": "c43c8368-7482-4416-b1b1-9b20af96f1a7",
                            "name": "Symantec Endpoint Protection"
                        },
                        {
                            "guid": "f1b733da-758d-4bc9-8c69-58f6c7e880a6",
                            "name": "Altiris by Symantec"
                        },
                        {
                            "guid": "bc0efa0c-3c1a-4683-b105-871e4d48a7ec",
                            "name": "Trend Micro - Apex One"
                        },
                        {
                            "guid": "ef2eddec-fd25-45e6-9607-f234e3ebc3f9",
                            "name": "McAfee"
                        },
                        {
                            "guid": "ca8699c4-c310-450e-a8d2-fe2d3f76ed86",
                            "name": "Microsoft Forefront"
                        },
                        {
                            "guid": "46efb133-8000-4352-b736-6b502e30055a",
                            "name": "Microsoft Security Client"
                        },
                        {
                            "guid": "9f701a08-be5a-4c29-ab61-71b2ff5ed4cf",
                            "name": "Sophos"
                        },
                        {
                            "guid": "5e5b3e8b-8b75-4fdf-95a9-af4ef3617bea",
                            "name": "Diebold Warsaw"
                        },
                        {
                            "guid": "81b10669-6c8f-4a88-b849-5616a192733b",
                            "name": "Splunk"
                        },
                        {
                            "guid": "8a21a827-945d-4c22-9dff-dbd2ac2e678f",
                            "name": "Lakeside Software - Systrack"
                        },
                        {
                            "guid": "cabe7670-6453-47a7-aee9-97725796fcff",
                            "name": "SAS Applications"
                        },
                        {
                            "guid": "d915a8cf-fef2-4aad-95ee-13d4eb1e94d0",
                            "name": "Microsoft OneDrive"
                        },
                        {
                            "guid": "b6640640-0174-4074-8943-7b655af1ea9f",
                            "name": "Microsoft Office"
                        },
                        {
                            "guid": "b4994505-913d-42d1-9645-79a70ac225a5",
                            "name": "VSE"
                        },
                        {
                            "guid": "9381546e-1617-46ae-98e7-f92fde16cffe",
                            "name": "Microsoft Windows Default"
                        }
                    ],
                    "file_lists": [
                        {
                            "guid": "cd7d1e2a-147b-4ac9-8f15-6f2cfe36afc8",
                            "name": "Simple Custom Detection List",
                            "type": "simple_custom_detections"
                        },
                        {
                            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
                            "name": "Blocked Application List",
                            "type": "application_blocking"
                        },
                        {
                            "guid": "9309476f-6964-44ca-8ef9-27204d980d3a",
                            "name": "Allowed Application List",
                            "type": "allowed_applications"
                        }
                    ],
                    "guid": "be84e169-0830-4b95-915b-1e203a82ed58",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Audit",
                    "product": "windows",
                    "serial_number": 29,
                    "used_in_groups": [
                        {
                            "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                            "name": "Audit"
                        }
                    ]
                },
                {
                    "default": true,
                    "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                    "file_lists": [],
                    "guid": "082bc9a3-b73a-4f42-8cc5-de1cd3748700",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Protect",
                    "product": "android",
                    "serial_number": 11,
                    "used_in_groups": [
                        {
                            "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                            "name": "Audit"
                        },
                        {
                            "description": "Test group",
                            "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                            "name": "Lior-Group"
                        }
                    ]
                },
                {
                    "default": true,
                    "description": "This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked.",
                    "exclusion_sets": [
                        {
                            "guid": "6eddded0-ac73-4bc3-b64e-b9d556fe5aec",
                            "name": "McAfee"
                        },
                        {
                            "guid": "368fecf4-b71d-4f79-94f9-e44dbbcc7d54",
                            "name": "Fusion"
                        },
                        {
                            "guid": "e80c3ce5-6184-49f0-9b40-c2dc2cfd1685",
                            "name": "Crashplan"
                        },
                        {
                            "guid": "893c2cad-ae76-407f-8b53-7d3a1fe9e995",
                            "name": "JAMF Casper"
                        },
                        {
                            "guid": "c5a855f5-1403-41ee-8b87-970652b52d55",
                            "name": "Jabber"
                        },
                        {
                            "guid": "52c66406-120e-47e8-ad8f-bd523900e8a4",
                            "name": "Microsoft Office"
                        },
                        {
                            "guid": "cc79a33d-d15b-4200-957d-d76f17f86cbe",
                            "name": "Apple macOS Default"
                        }
                    ],
                    "file_lists": [
                        {
                            "guid": "cd7d1e2a-147b-4ac9-8f15-6f2cfe36afc8",
                            "name": "Simple Custom Detection List",
                            "type": "simple_custom_detections"
                        },
                        {
                            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
                            "name": "Blocked Application List",
                            "type": "application_blocking"
                        },
                        {
                            "guid": "9309476f-6964-44ca-8ef9-27204d980d3a",
                            "name": "Allowed Application List",
                            "type": "allowed_applications"
                        }
                    ],
                    "guid": "9f2fa537-df5d-4c6c-abf3-edc25a893a7a",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Audit",
                    "product": "mac",
                    "serial_number": 13,
                    "used_in_groups": [
                        {
                            "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                            "name": "Audit"
                        }
                    ]
                },
                {
                    "default": true,
                    "description": "This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked.",
                    "file_lists": [
                        {
                            "guid": "cd7d1e2a-147b-4ac9-8f15-6f2cfe36afc8",
                            "name": "Simple Custom Detection List",
                            "type": "simple_custom_detections"
                        },
                        {
                            "guid": "1bb5a8e3-fb59-4b3d-a106-d90b2a02ac12",
                            "name": "Blocked Application List",
                            "type": "application_blocking"
                        },
                        {
                            "guid": "9309476f-6964-44ca-8ef9-27204d980d3a",
                            "name": "Allowed Application List",
                            "type": "allowed_applications"
                        }
                    ],
                    "guid": "b4e266c8-ebd1-4e94-80b6-b04a966cb0d5",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Audit",
                    "product": "linux",
                    "serial_number": 19,
                    "used_in_groups": [
                        {
                            "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                            "name": "Audit"
                        }
                    ]
                },
                {
                    "default": true,
                    "description": "This policy puts Clarity in a mode that will log and alert on convictions but not block traffic.",
                    "file_lists": [],
                    "guid": "5102948a-db78-4a94-849a-b9f12b04e526",
                    "inherited": false,
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "Audit",
                    "product": "ios",
                    "serial_number": 23,
                    "used_in_groups": [
                        {
                            "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                            "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                            "name": "Audit"
                        }
                    ]
                }
            ],
            "source": "Created via API"
        }
    }
}
```

#### Human Readable Output

>### Group Information
>|Name|Description|Created At|Computers Count|Descendant Computers Count|
>|---|---|---|---|---|
>| readme group | readme test group to be deleted | 2022-10-31 12:16:25 | 0 | 0 |


### cisco-amp-group-delete
***
Destroys a group with a given guid.


#### Base Command

`cisco-amp-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_guid | Groups GUID. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-amp-group-delete group_guid=d088adeb-7cb4-48e4-807b-edcb828f4d29```
#### Human Readable Output

>Group GUID: "d088adeb-7cb4-48e4-807b-edcb828f4d29"
>Successfully deleted.

### cisco-amp-indicator-list
***
Show information about indicators.


#### Base Command

`cisco-amp-indicator-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_guid | Indicator GUID. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Indicator.name | String | Indicator name. | 
| CiscoAMP.Indicator.description | String | Indicator description. | 
| CiscoAMP.Indicator.guid | String | Indicator GUID. | 
| CiscoAMP.Indicator.severity | String | Indicator severity. | 
| CiscoAMP.Indicator.mitre.tactics.external_id | String | Mitre tactic ID. | 
| CiscoAMP.Indicator.mitre.tactics.name | String | Mitre tactic name. | 
| CiscoAMP.Indicator.mitre.tactics.mitre_url | String | Mitre tactic URL. | 
| CiscoAMP.Indicator.mitre.techniques.external_id | String | Mitre technique ID. | 
| CiscoAMP.Indicator.mitre.techniques.name | String | Mitre technique name. | 
| CiscoAMP.Indicator.mitre.techniques.mitre_url | String | Mitre technique URL. | 
| CiscoAMP.Indicator.observed_compromises | Number | Total number of observed compromises. | 
| CiscoAMP.Indicator.observed_compromises.unresolved | Number | Number of unresolved compromises. | 
| CiscoAMP.Indicator.observed_compromises.in_progress | Number | Number of compromises in progress. | 
| CiscoAMP.Indicator.observed_compromises.resolved | Number | Number of resolved compromises. | 

#### Command example
```!cisco-amp-indicator-list limit=5```
#### Context Example
```json
{
    "CiscoAMP": {
        "Indicator": [
            {
                "description": "Crossrider is a an Adware variant that targets Mac with the intent of displaying ads. It also changes the default home page of Safari and Chrome browsers.",
                "guid": "5593ab7e-1db5-4759-9785-96c55824b675",
                "name": "Crossrider.ioc",
                "observed_compromises": 0,
                "severity": "Medium"
            },
            {
                "description": "OSX.Dummy is a poorly executed Trojan variant. It requires users to input their password in order to complete it's install. However, once this is done the malware will have complete access to the whole system, and it will persist itself via a LaunchDaemon.",
                "guid": "fef2d8b2-95f6-4392-abec-fc1f6a670251",
                "name": "Dummy.ioc",
                "observed_compromises": 0,
                "severity": "Medium"
            },
            {
                "description": "Accessed URL matches characteristics of several malware families.",
                "guid": "dcc66a98-5658-41d4-a1ca-887933a8b24f",
                "name": "GateDotPhp.ioc",
                "observed_compromises": 1,
                "severity": "High"
            },
            {
                "description": "JS.Trojan.Generic_48153 is malware that contacts a remote server over HTTP. This IOC is based on Snort Intrusion Prevention System (IPS) rule id:48153 from the malware detection rulesets. This IOC fires when a URI pattern similar to this malware has been detected. The components of the URI this IOC inspects for are: \"/01/Carontex\".",
                "guid": "940bdaf4-4c89-4423-a55e-410ed56143a8",
                "name": "JS.Trojan.Generic_48153.ioc",
                "observed_compromises": 0,
                "severity": "Critical"
            },
            {
                "description": "Most Linux distributions support creation of auto-start files. This consists of placing a configuration file with a .desktop extension in the .config/autostart location. In this case, a suspicious auto-start entry was created. Linux malware such as x-agent also known as sofacy/sednit are known to do that.",
                "guid": "318d030d-7fdc-48f4-afcd-66c7c75cade7",
                "name": "Linux.AutostartPersistence.ioc",
                "observed_compromises": 0,
                "severity": "High"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 5 | 0 | 5 | 910 |
>### Indicator Information
>|GUID|Name|Description|Severity|Observed Compromises|
>|---|---|---|---|---|
>| 5593ab7e-1db5-4759-9785-96c55824b675 | Crossrider.ioc | Crossrider is a an Adware variant that targets Mac with the intent of displaying ads. It also changes the default home page of Safari and Chrome browsers. | Medium | 0 |
>| fef2d8b2-95f6-4392-abec-fc1f6a670251 | Dummy.ioc | OSX.Dummy is a poorly executed Trojan variant. It requires users to input their password in order to complete it's install. However, once this is done the malware will have complete access to the whole system, and it will persist itself via a LaunchDaemon. | Medium | 0 |
>| dcc66a98-5658-41d4-a1ca-887933a8b24f | GateDotPhp.ioc | Accessed URL matches characteristics of several malware families. | High | 1 |
>| 940bdaf4-4c89-4423-a55e-410ed56143a8 | JS.Trojan.Generic_48153.ioc | JS.Trojan.Generic_48153 is malware that contacts a remote server over HTTP. This IOC is based on Snort Intrusion Prevention System (IPS) rule id:48153 from the malware detection rulesets. This IOC fires when a URI pattern similar to this malware has been detected. The components of the URI this IOC inspects for are: "/01/Carontex". | Critical | 0 |
>| 318d030d-7fdc-48f4-afcd-66c7c75cade7 | Linux.AutostartPersistence.ioc | Most Linux distributions support creation of auto-start files. This consists of placing a configuration file with a .desktop extension in the .config/autostart location. In this case, a suspicious auto-start entry was created. Linux malware such as x-agent also known as sofacy/sednit are known to do that. | High | 0 |


### cisco-amp-policy-list
***
Get information about policies by filtering with product and name or a specific one with policy_guid.


#### Base Command

`cisco-amp-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_guid | Policy GUID. | Optional | 
| product | Comma separated list for products to filter by. | Optional | 
| name | Comma separated list for names to filter by (has auto complete capabilities). | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Policy.name | String | Policy name. | 
| CiscoAMP.Policy.description | String | Policy description. | 
| CiscoAMP.Policy.guid | String | Policy GUID. | 
| CiscoAMP.Policy.product | String | Product used. | 
| CiscoAMP.Policy.default | Boolean | Is the policy default. | 
| CiscoAMP.Policy.serial_number | Number | Policy serial number. | 
| CiscoAMP.Policy.file_lists.name | String | File list name. | 
| CiscoAMP.Policy.file_lists.guid | String | File list GUID. | 
| CiscoAMP.Policy.file_lists.type | String | File list type. | 
| CiscoAMP.Policy.ip_lists.name | String | IP list name. | 
| CiscoAMP.Policy.ip_lists.guid | String | IP list GUID. | 
| CiscoAMP.Policy.ip_lists.type | String | IP list type. | 
| CiscoAMP.Policy.exclusion_sets.name | String | Exclusion set name. | 
| CiscoAMP.Policy.exclusion_sets.guid | String | Exclusion set GUID. | 
| CiscoAMP.Policy.used_in_groups.name | String | Group name. | 
| CiscoAMP.Policy.used_in_groups.description | String | Group description. | 
| CiscoAMP.Policy.used_in_groups.guid | String | Group GUID. | 

#### Command example
```!cisco-amp-policy-list```
#### Context Example
```json
{
    "CiscoAMP": {
        "Policy": [
            {
                "default": true,
                "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                "guid": "082bc9a3-b73a-4f42-8cc5-de1cd3748700",
                "name": "Protect",
                "product": "android",
                "serial_number": 11
            },
            {
                "default": true,
                "description": "This policy puts Clarity in a mode that will log and alert on convictions but not block traffic.",
                "guid": "5102948a-db78-4a94-849a-b9f12b04e526",
                "name": "Audit",
                "product": "ios",
                "serial_number": 23
            },
            {
                "default": false,
                "description": "This is the standard policy for Clarity that will log and alert on convictions and block any potentially malicious traffic.",
                "guid": "c90936b3-2ad7-458c-90a3-a806d50ed16e",
                "name": "Protect",
                "product": "ios",
                "serial_number": 25
            },
            {
                "default": true,
                "description": "This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked.",
                "guid": "b4e266c8-ebd1-4e94-80b6-b04a966cb0d5",
                "name": "Audit",
                "product": "linux",
                "serial_number": 19
            },
            {
                "default": false,
                "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                "guid": "653508ed-28d4-465a-80c4-7ed9c0232b55",
                "name": "Protect",
                "product": "linux",
                "serial_number": 21
            },
            {
                "default": true,
                "description": "This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked.",
                "guid": "9f2fa537-df5d-4c6c-abf3-edc25a893a7a",
                "name": "Audit",
                "product": "mac",
                "serial_number": 13
            },
            {
                "default": false,
                "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                "guid": "30fba653-eb4e-4c3d-b1bb-1cef9f0e31e4",
                "name": "Protect",
                "product": "mac",
                "serial_number": 15
            },
            {
                "default": false,
                "description": "This is an aggressive policy that enables the offline engine to scan computers that are suspected or known to be infected with malware.",
                "guid": "cfcf4841-bf00-4030-8ac3-4a607ecf245e",
                "name": "Triage",
                "product": "mac",
                "serial_number": 17
            },
            {
                "default": true,
                "description": "This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked.",
                "guid": "be84e169-0830-4b95-915b-1e203a82ed58",
                "name": "Audit",
                "product": "windows",
                "serial_number": 29
            },
            {
                "default": false,
                "description": "This is a lightweight policy for use on Active Directory Domain Controllers.",
                "guid": "fa0c377e-8f0a-40ab-885a-afc8c08d3732",
                "name": "Domain Controller",
                "product": "windows",
                "serial_number": 10
            },
            {
                "default": false,
                "description": "Test policy",
                "guid": "91c7894d-dd69-4a21-8cf6-5ebfc57ef4df",
                "name": "Lior-test",
                "product": "windows",
                "serial_number": 27
            },
            {
                "default": false,
                "description": "This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections.",
                "guid": "a599bf5b-2cb7-4a5b-90bd-d0199e2ccd67",
                "name": "Protect",
                "product": "windows",
                "serial_number": 28
            },
            {
                "default": false,
                "description": "This is a lightweight policy for high availability computers and servers that require maximum performance and uptime.",
                "guid": "dd1da971-926c-42ab-9e5a-154f2695d995",
                "name": "Server",
                "product": "windows",
                "serial_number": 8
            },
            {
                "default": false,
                "description": "This is an aggressive policy that enables the offline engine to scan computers that are suspected or known to be infected with malware.",
                "guid": "1a352c59-793b-44f3-b8f9-0ddd354057bc",
                "name": "Triage",
                "product": "windows",
                "serial_number": 6
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 14 | 0 | 100 | 14 |
>### Policy Information
>|GUID|Name|Description|Product|Serial Number|
>|---|---|---|---|---|
>| 082bc9a3-b73a-4f42-8cc5-de1cd3748700 | Protect | This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections. | android | 11 |
>| 5102948a-db78-4a94-849a-b9f12b04e526 | Audit | This policy puts Clarity in a mode that will log and alert on convictions but not block traffic. | ios | 23 |
>| c90936b3-2ad7-458c-90a3-a806d50ed16e | Protect | This is the standard policy for Clarity that will log and alert on convictions and block any potentially malicious traffic. | ios | 25 |
>| b4e266c8-ebd1-4e94-80b6-b04a966cb0d5 | Audit | This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked. | linux | 19 |
>| 653508ed-28d4-465a-80c4-7ed9c0232b55 | Protect | This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections. | linux | 21 |
>| 9f2fa537-df5d-4c6c-abf3-edc25a893a7a | Audit | This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked. | mac | 13 |
>| 30fba653-eb4e-4c3d-b1bb-1cef9f0e31e4 | Protect | This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections. | mac | 15 |
>| cfcf4841-bf00-4030-8ac3-4a607ecf245e | Triage | This is an aggressive policy that enables the offline engine to scan computers that are suspected or known to be infected with malware. | mac | 17 |
>| be84e169-0830-4b95-915b-1e203a82ed58 | Audit | This policy puts the Secure Endpoint Connector in a mode that will only detect malicious files but not quarantine them. Malicious network traffic is also detected but not blocked. | windows | 29 |
>| fa0c377e-8f0a-40ab-885a-afc8c08d3732 | Domain Controller | This is a lightweight policy for use on Active Directory Domain Controllers. | windows | 10 |
>| 91c7894d-dd69-4a21-8cf6-5ebfc57ef4df | Lior-test | Test policy | windows | 27 |
>| a599bf5b-2cb7-4a5b-90bd-d0199e2ccd67 | Protect | This is the standard policy for the Secure Endpoint Connector that will quarantine malicious files and block malicious network connections. | windows | 28 |
>| dd1da971-926c-42ab-9e5a-154f2695d995 | Server | This is a lightweight policy for high availability computers and servers that require maximum performance and uptime. | windows | 8 |
>| 1a352c59-793b-44f3-b8f9-0ddd354057bc | Triage | This is an aggressive policy that enables the offline engine to scan computers that are suspected or known to be infected with malware. | windows | 6 |


### cisco-amp-app-trajectory-query-list
***
Retrieve app_trajectory queries for a given ios bundle id.


#### Base Command

`cisco-amp-app-trajectory-query-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ios_bid | IOS bundle ID for app trajectory. | Required | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.AppTrajectoryQuery.connector_guid | String | GUID of the connector. | 
| CiscoAMP.AppTrajectoryQuery.bundle_id | String | Bundle ID. | 
| CiscoAMP.AppTrajectoryQuery.group_guids | String | List of groups GUID. | 
| CiscoAMP.AppTrajectoryQuery.cdhash | String | CD Hash. | 
| CiscoAMP.AppTrajectoryQuery.timestamp | Number | Observed timestamp. | 
| CiscoAMP.AppTrajectoryQuery.timestamp_nanoseconds | Number | Observed timestamp in nano seconds. | 
| CiscoAMP.AppTrajectoryQuery.date | Date | Observed date. | 
| CiscoAMP.AppTrajectoryQuery.query_type | String | The type of the query. | 
| CiscoAMP.AppTrajectoryQuery.network_info.dirty_url | String | Link to the observed URL. | 
| CiscoAMP.AppTrajectoryQuery.network_info.remote_ip | String | Remote IP. | 
| CiscoAMP.AppTrajectoryQuery.network_info.remote_port | Number | Remote port. | 
| CiscoAMP.AppTrajectoryQuery.network_info.local_ip | String | Local IP. | 
| CiscoAMP.AppTrajectoryQuery.network_info.local_port | Number | Local Port. | 
| CiscoAMP.AppTrajectoryQuery.network_info.direction | String | Outgoing or ingoing connection. | 
| CiscoAMP.AppTrajectoryQuery.network_info.protocol | String | Communication protocol used. | 
| CiscoAMP.AppTrajectoryQuery.ver | String | Version. | 

#### Command example
```!cisco-amp-app-trajectory-query-list ios_bid=com.apple.Safari.SafeBrowsing limit=5```
#### Context Example
```json
{
    "CiscoAMP": {
        "AppTrajectoryQuery": [
            {
                "bundle_id": "com.apple.Safari.SafeBrowsing",
                "cdhash": null,
                "connector_guid": "dddd4ceb-4ce1-4f81-a7a7-04d13cc1df43",
                "date": "2022-10-24T12:01:59+00:00",
                "group_guids": [
                    "6ed80412-0739-42c1-8f6d-32fb51b3f894"
                ],
                "network_info": {
                    "direction": "Outgoing connection to",
                    "dirty_url": "https://configuration.apple.com/configurations/internetservices/safari/SafeBrowsingRemoteConfiguration-0.plist",
                    "local_ip": "192.168.1.105",
                    "local_port": 50155,
                    "protocol": "TCP",
                    "remote_ip": "184.51.215.228",
                    "remote_port": 443
                },
                "query_type": "Network Query",
                "timestamp": 1666612919,
                "timestamp_nanoseconds": 0,
                "ver": null
            },
            {
                "bundle_id": "com.apple.Safari.SafeBrowsing",
                "cdhash": null,
                "connector_guid": "0f6ee17f-a31b-4b76-902f-7cf68a79089d",
                "date": "2022-10-23T13:18:16+00:00",
                "group_guids": [
                    "fedd82f8-c74f-49f4-a463-e576d3beee92"
                ],
                "network_info": {
                    "direction": "Outgoing connection to",
                    "dirty_url": "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch",
                    "local_ip": "50.94.150.61",
                    "local_port": 56361,
                    "protocol": "TCP",
                    "remote_ip": "172.217.2.42",
                    "remote_port": 443
                },
                "query_type": "Network Query",
                "timestamp": 1666531096,
                "timestamp_nanoseconds": 0,
                "ver": null
            },
            {
                "bundle_id": "com.apple.Safari.SafeBrowsing",
                "cdhash": null,
                "connector_guid": "8aa97bc7-3cc1-47aa-ad0a-0e23d5493aff",
                "date": "2022-10-23T12:00:54+00:00",
                "group_guids": [
                    "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18"
                ],
                "network_info": {
                    "direction": "Outgoing connection to",
                    "dirty_url": "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch",
                    "local_ip": "2603:3015:3a04:f3e5:e98d:3dfc:f628:6651",
                    "local_port": 50852,
                    "protocol": "TCP",
                    "remote_ip": "2607:f8b0:4009:80f::200a",
                    "remote_port": 443
                },
                "query_type": "Network Query",
                "timestamp": 1666526454,
                "timestamp_nanoseconds": 0,
                "ver": null
            }
        ]
    }
}
```

#### Human Readable Output

>### App Trajectory Information
>|Connector GUID|Date|Query Type|Dirty URL|
>|---|---|---|---|
>| dddd4ceb-4ce1-4f81-a7a7-04d13cc1df43 | 2022-10-24T12:01:59+00:00 | Network Query | https:<span>//</span>configuration.apple.com/configurations/internetservices/safari/SafeBrowsingRemoteConfiguration-0.plist |
>| 0f6ee17f-a31b-4b76-902f-7cf68a79089d | 2022-10-23T13:48:38+00:00 | Network Query | https:<span>//</span>safebrowsing.googleapis.com/v4/threatListUpdates:fetch |
>| 0f6ee17f-a31b-4b76-902f-7cf68a79089d | 2022-10-23T13:18:16+00:00 | Network Query | https:<span>//</span>safebrowsing.googleapis.com/v4/threatListUpdates:fetch |
>| 8aa97bc7-3cc1-47aa-ad0a-0e23d5493aff | 2022-10-23T12:30:46+00:00 | Network Query | https:<span>//</span>safebrowsing.googleapis.com/v4/threatListUpdates:fetch |
>| 8aa97bc7-3cc1-47aa-ad0a-0e23d5493aff | 2022-10-23T12:00:54+00:00 | Network Query | https:<span>//</span>safebrowsing.googleapis.com/v4/threatListUpdates:fetch |


### cisco-amp-version-get
***
Get API version.


#### Base Command

`cisco-amp-version-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Version.version | String | API version. | 

#### Command example
```!cisco-amp-version-get```
#### Context Example
```json
{
    "CiscoAMP": {
        "Version": {
            "version": "v1.2.0"
        }
    }
}
```

#### Human Readable Output

>Version: v1.2.0

### cisco-amp-vulnerability-list
***
Fetch a list of vulnerabilities. This is analogous to the Vulnerable Software view on the AMP for Endpoints Console. The list can be filtered to show only the vulnerable programs detected for a specific time range. Provide a list of computers on which the vulnerability has been observed with given SHA-256. The list item contains a summary of information on the vulnerability, including: application name and version, SHA-256 value for the executable file, connectors on which the vulnerable application was observed and the most recent CVSS score. IMPORTANT: computers key returns information about the last 1000 Connectors on which the vulnerable application was observed.


#### Base Command

`cisco-amp-vulnerability-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | SHA-256 that has been observed as a vulnerability. | Optional | 
| group_guid | Comma separated list for group GUIDs to filter by. | Optional | 
| start_time | Inclusive (The list will include vulnerable programs detected at start_time). | Optional | 
| end_time | Exclusive - if end_time is a time (The list will only include vulnerable programs detected before end_time); Inclusive - if end_time is a date (The list will include vulnerable programs detected on the date). | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Max 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Vulnerability.application | String | Name of the application. | 
| CiscoAMP.Vulnerability.version | String | Version of the application. | 
| CiscoAMP.Vulnerability.file.filename | String | Name of the file. | 
| CiscoAMP.Vulnerability.file.identity.sha256 | String | File's SHA-256. | 
| CiscoAMP.Vulnerability.latest_timestamp | Number | Vulnerability latest timestamp. | 
| CiscoAMP.Vulnerability.latest_date | Date | Vulnerability latest date. | 
| CiscoAMP.Vulnerability.computers_total_count | Number | Number of computers. | 
| CiscoAMP.Vulnerability.connector_guid | String | GUID of the connector. | 
| CiscoAMP.Vulnerability.hostname | String | Host's name. | 
| CiscoAMP.Vulnerability.windows_processor_id | String | Windows processor ID. | 
| CiscoAMP.Vulnerability.active | Boolean | Is the computer active. | 
| CiscoAMP.Vulnerability.group_guid | String | Group's GUID. | 
| CiscoAMP.Vulnerability.cves.id | String | Common vulnerability exposure ID. | 
| CiscoAMP.Vulnerability.cves.link | String | Common vulnerability exposure link. | 
| CiscoAMP.Vulnerability.cves.cvss | Number | Common vulnerability scoring system. | 
| CiscoAMP.Vulnerability.groups.name | String | Group's name. | 
| CiscoAMP.Vulnerability.groups.description | String | Group's description. | 
| CiscoAMP.Vulnerability.groups.guid | String | Group's GUID. | 
| CiscoAMP.Vulnerability.groups.source | String | Group's source of creation. | 
| CiscoAMP.Vulnerability.computers.connector_guid | String | GUID of the connector. | 
| CiscoAMP.Vulnerability.computers.hostname | String | Host's name. | 
| CiscoAMP.Vulnerability.computers.windows_processor_id | String | Windows processor ID. | 
| CiscoAMP.Vulnerability.computers.active | Boolean | Is the computer active. | 

#### Command example
```!cisco-amp-vulnerability-list```
#### Context Example
```json
{
    "CiscoAMP": {
        "Vulnerability": [
            {
                "application": "Mozilla Firefox",
                "computers": [
                    {
                        "active": true,
                        "connector_guid": "113c1a8e-8e66-409e-92a8-41b7d586be5d",
                        "hostname": "Demo_AMP_Exploit_Prevention",
                        "windows_processor_id": "f208ab145e397d6"
                    }
                ],
                "computers_total_count": 1,
                "cves": [
                    {
                        "cvss": 6.8,
                        "id": "CVE-2015-7204",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-7204"
                    }
                ],
                "file": {
                    "filename": "firefox.exe",
                    "identity": {
                        "sha256": "4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F"
                    }
                },
                "groups": [
                    {
                        "description": "Triage Group for QMASTERS SECURITY SERVICES LTD",
                        "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                        "name": "Triage"
                    }
                ],
                "latest_date": "2022-10-25T12:20:00+00:00",
                "latest_timestamp": 1666700400,
                "version": "41.0"
            },
            {
                "application": "Adobe Flash Player",
                "computers": [
                    {
                        "active": true,
                        "connector_guid": "33c101dd-4f50-4fd3-bce5-d3bd9d94e1a2",
                        "hostname": "Demo_ZAccess",
                        "windows_processor_id": "b047d5268e9a13f"
                    }
                ],
                "computers_total_count": 1,
                "cves": [
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3333",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3333"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2014-0502",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0502"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2014-0498",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0498"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2014-0497",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0497"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2014-0492",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0492"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2014-0491",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0491"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5332",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5332"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5324",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5324"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5329",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5329"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5330",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5330"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3361",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3361"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3362",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3362"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3363",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3363"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3344",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3344"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3345",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3345"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3347",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3347"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3343",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3343"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2728",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2728"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3324",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3324"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3325",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3325"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3326",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3326"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3327",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3327"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3328",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3328"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3329",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3329"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3330",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3330"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3331",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3331"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3332",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3332"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3334",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3334"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3335",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3335"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1378",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1378"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1379",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1379"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1380",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1380"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2555",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2555"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0646",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0646"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0650",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0650"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1371",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1371"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1375",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1375"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0504",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0504"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0638",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0638"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0639",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0639"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0642",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0642"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0644",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0644"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0645",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0645"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0647",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0647"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0649",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0649"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1365",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1365"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1366",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1366"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1367",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1367"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1368",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1368"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1369",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1369"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1370",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1370"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1372",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1372"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1373",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1373"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1374",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1374"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2014-0507",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0507"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5331",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5331"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-0648",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0648"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-0643",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0643"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-0634",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0634"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-0633",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0633"
                    },
                    {
                        "cvss": 7.8,
                        "id": "CVE-2014-0499",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0499"
                    },
                    {
                        "cvss": 6.4,
                        "id": "CVE-2014-0503",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0503"
                    }
                ],
                "file": {
                    "filename": "FlashPlayerApp.exe",
                    "identity": {
                        "sha256": "c1219f0799e60ff48a9705b63c14168684aed911610fec68548ea08f605cc42b"
                    }
                },
                "groups": [
                    {
                        "description": "Triage Group for QMASTERS SECURITY SERVICES LTD",
                        "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                        "name": "Triage"
                    }
                ],
                "latest_date": "2022-10-25T12:05:49+00:00",
                "latest_timestamp": 1666699549,
                "version": "11.5.502.146"
            },
            {
                "application": "Oracle Java(TM) Platform SE",
                "computers": [
                    {
                        "active": true,
                        "connector_guid": "33c101dd-4f50-4fd3-bce5-d3bd9d94e1a2",
                        "hostname": "Demo_ZAccess",
                        "windows_processor_id": "b047d5268e9a13f"
                    }
                ],
                "computers_total_count": 1,
                "cves": [
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5830",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5830"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5843",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5843"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5842",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5842"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5817",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5817"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5814",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5814"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5809",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5809"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5789",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5789"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5829",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5829"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5788",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5788"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5824",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5824"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5787",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5787"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-5782",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5782"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2470",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2470"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2465",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2465"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2471",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2471"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2473",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2473"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2472",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2472"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2469",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2469"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2468",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2468"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2466",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2466"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2464",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2464"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2463",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2463"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2459",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2459"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2428",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2428"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2420",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2420"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2434",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2434"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2384",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2384"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1518",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1518"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1537",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1537"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2440",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2440"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1557",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1557"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1558",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1558"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2435",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2435"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2432",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2432"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1569",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1569"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2431",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2431"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2383",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2383"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2427",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2427"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2425",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2425"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2422",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2422"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2414",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2414"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0809",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0809"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1493",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1493"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1480",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1480"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0428",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0428"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0437",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0437"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0441",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0441"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0442",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0442"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0445",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0445"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0450",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0450"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1476",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1476"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1478",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1478"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1479",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1479"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1484",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1484"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0426",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0426"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1486",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1486"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1487",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1487"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0425",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0425"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0422",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0422"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0446",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0446"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1475",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1475"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-2460",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2460"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5838",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5838"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5777",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5777"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5810",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5810"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5832",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5832"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5806",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5806"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5805",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5805"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5850",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5850"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5844",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5844"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-5846",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5846"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-2462",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2462"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-2436",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2436"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-2426",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2426"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-2421",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2421"
                    },
                    {
                        "cvss": 7.8,
                        "id": "CVE-2013-2445",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2445"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-5852",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5852"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-2448",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2448"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-2394",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2394"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-2429",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2429"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-2430",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2430"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-1563",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1563"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-0429",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0429"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-0444",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0444"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-0419",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0419"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2013-0423",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0423"
                    },
                    {
                        "cvss": 7.5,
                        "id": "CVE-2013-5775",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5775"
                    },
                    {
                        "cvss": 7.5,
                        "id": "CVE-2013-5802",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5802"
                    },
                    {
                        "cvss": 7.5,
                        "id": "CVE-2013-2442",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2442"
                    },
                    {
                        "cvss": 7.5,
                        "id": "CVE-2013-2461",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2461"
                    },
                    {
                        "cvss": 7.5,
                        "id": "CVE-2013-0351",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0351"
                    },
                    {
                        "cvss": 6.9,
                        "id": "CVE-2013-2439",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2439"
                    },
                    {
                        "cvss": 6.9,
                        "id": "CVE-2013-0430",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0430"
                    },
                    {
                        "cvss": 6.4,
                        "id": "CVE-2013-3829",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3829"
                    },
                    {
                        "cvss": 6.4,
                        "id": "CVE-2013-5783",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5783"
                    },
                    {
                        "cvss": 6.4,
                        "id": "CVE-2013-5804",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5804"
                    },
                    {
                        "cvss": 6.4,
                        "id": "CVE-2013-5812",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-5812"
                    },
                    {
                        "cvss": 6.4,
                        "id": "CVE-2013-2407",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2407"
                    },
                    {
                        "cvss": 6.4,
                        "id": "CVE-2013-0432",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0432"
                    }
                ],
                "file": {
                    "filename": "java.exe",
                    "identity": {
                        "sha256": "0b4eefc0d815ac0fdc20f22add8fd2d8113be99578a4e5189122b28b201ccbd9"
                    }
                },
                "groups": [
                    {
                        "description": "Triage Group for QMASTERS SECURITY SERVICES LTD",
                        "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                        "name": "Triage"
                    }
                ],
                "latest_date": "2022-10-25T12:05:05+00:00",
                "latest_timestamp": 1666699505,
                "version": "1.7.0:update_10"
            },
            {
                "application": "Adobe Acrobat Reader",
                "computers": [
                    {
                        "active": true,
                        "connector_guid": "22b1d33c-b875-445f-8a98-d7fd05616ff0",
                        "hostname": "Demo_Upatre",
                        "windows_processor_id": "b2a9e0f43861d75"
                    },
                    {
                        "active": true,
                        "connector_guid": "05c857a9-e9ea-4753-bbce-aaa0ae045dbe",
                        "hostname": "Demo_SFEicar",
                        "windows_processor_id": "80dfbe75a493162"
                    }
                ],
                "computers_total_count": 2,
                "cves": [
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0601",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0601"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0602",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0602"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0603",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0603"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0604",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0604"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0605",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0605"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0606",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0606"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0607",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0607"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0608",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0608"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0609",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0609"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0610",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0610"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0611",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0611"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0612",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0612"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0613",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0613"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0614",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0614"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0615",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0615"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0616",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0616"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0617",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0617"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0618",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0618"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0619",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0619"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0620",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0620"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0621",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0621"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0622",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0622"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0623",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0623"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0624",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0624"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-0626",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0626"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3346",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3346"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3342",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3342"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3341",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3341"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-1376",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-1376"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2718",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2718"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2719",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2719"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2720",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2720"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2721",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2721"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2722",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2722"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2723",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2723"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2724",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2724"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2725",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2725"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2726",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2726"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2727",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2727"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2729",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2729"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2730",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2730"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2731",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2731"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2732",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2732"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2733",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2733"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2734",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2734"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2735",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2735"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-2736",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-2736"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3340",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3340"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3337",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3337"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3338",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3338"
                    },
                    {
                        "cvss": 10,
                        "id": "CVE-2013-3339",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-3339"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-0641",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0641"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2013-0640",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0640"
                    },
                    {
                        "cvss": 7.2,
                        "id": "CVE-2013-0627",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-0627"
                    }
                ],
                "file": {
                    "filename": "AcroRd32.exe",
                    "identity": {
                        "sha256": "825b7b20a913f26641c012f1cb61b81d29033f142ba6c6734425de06432e4f82"
                    }
                },
                "groups": [
                    {
                        "description": "Triage Group for QMASTERS SECURITY SERVICES LTD",
                        "guid": "6ed80412-0739-42c1-8f6d-32fb51b3f894",
                        "name": "Triage"
                    },
                    {
                        "description": "Protect Group for QMASTERS SECURITY SERVICES LTD",
                        "guid": "5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18",
                        "name": "Protect"
                    }
                ],
                "latest_date": "2022-10-25T12:02:34+00:00",
                "latest_timestamp": 1666699354,
                "version": "9.3.3.177"
            },
            {
                "application": "Microsoft Office",
                "computers": [
                    {
                        "active": true,
                        "connector_guid": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
                        "hostname": "Demo_AMP",
                        "windows_processor_id": "3e0527a4d8916bf"
                    }
                ],
                "computers_total_count": 1,
                "cves": [
                    {
                        "cvss": 9.3,
                        "id": "CVE-2014-0260",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-0260"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2014-1761",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-1761"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2014-6357",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6357"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2015-0085",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-0085"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2015-0086",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-0086"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2015-1641",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1641"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2015-1650",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1650"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2015-1682",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-1682"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2015-2379",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2379"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2015-2380",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2380"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2015-2424",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2424"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2016-0127",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-0127"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2016-7193",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-7193"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2017-0292",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-0292"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2017-11826",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-11826"
                    }
                ],
                "file": {
                    "filename": "WINWORD.EXE",
                    "identity": {
                        "sha256": "3D46E95284F93BBB76B3B7E1BF0E1B2D51E8A9411C2B6E649112F22F92DE63C2"
                    }
                },
                "groups": [
                    {
                        "description": "Test group",
                        "guid": "bb5a9f90-d6fa-4fe7-99c8-e91060b49a98",
                        "name": "Lior-Group"
                    }
                ],
                "latest_date": "2022-10-23T12:37:33+00:00",
                "latest_timestamp": 1666528653,
                "version": "2013"
            },
            {
                "application": "Microsoft Internet Explorer",
                "computers": [
                    {
                        "active": true,
                        "connector_guid": "d6f49c17-9721-4c5b-a04f-32ba30be36a0",
                        "hostname": "Demo_AMP_Intel",
                        "windows_processor_id": "daf517086932eb4"
                    }
                ],
                "computers_total_count": 1,
                "cves": [
                    {
                        "cvss": 7.6,
                        "id": "CVE-2018-0762",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-0762"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2018-0772",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-0772"
                    }
                ],
                "file": {
                    "filename": "mshtml.dll",
                    "identity": {
                        "sha256": "D1BEA74AC9D85B3DCD4ABC1AF42AF6C37B9349DEFC8E6577993611B773F56CA0"
                    }
                },
                "groups": [
                    {
                        "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                        "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                        "name": "Audit"
                    }
                ],
                "latest_date": "2022-10-04T07:02:27+00:00",
                "latest_timestamp": 1664866947,
                "version": "11"
            },
            {
                "application": "Microsoft Internet Explorer",
                "computers": [
                    {
                        "active": true,
                        "connector_guid": "d6f49c17-9721-4c5b-a04f-32ba30be36a0",
                        "hostname": "Demo_AMP_Intel",
                        "windows_processor_id": "daf517086932eb4"
                    }
                ],
                "computers_total_count": 1,
                "cves": [
                    {
                        "cvss": 7.6,
                        "id": "CVE-2018-0762",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-0762"
                    },
                    {
                        "cvss": 7.6,
                        "id": "CVE-2018-0772",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-0772"
                    }
                ],
                "file": {
                    "filename": "mshtml.dll",
                    "identity": {
                        "sha256": "1DC5D15A26A79BB46519952A60B15AA4ACB36F6CE3247EBF50DF9C157BC4FCF4"
                    }
                },
                "groups": [
                    {
                        "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                        "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                        "name": "Audit"
                    }
                ],
                "latest_date": "2022-10-04T07:02:26+00:00",
                "latest_timestamp": 1664866946,
                "version": "11"
            },
            {
                "application": "Microsoft Office",
                "computers": [
                    {
                        "active": true,
                        "connector_guid": "d6f49c17-9721-4c5b-a04f-32ba30be36a0",
                        "hostname": "Demo_AMP_Intel",
                        "windows_processor_id": "daf517086932eb4"
                    }
                ],
                "computers_total_count": 1,
                "cves": [
                    {
                        "cvss": 9.3,
                        "id": "CVE-2017-0106",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-0106"
                    },
                    {
                        "cvss": 6.8,
                        "id": "CVE-2017-11774",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-11774"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2017-8506",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-8506"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2017-8507",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-8507"
                    },
                    {
                        "cvss": 6.8,
                        "id": "CVE-2017-8571",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-8571"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2017-8663",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-8663"
                    },
                    {
                        "cvss": 9.3,
                        "id": "CVE-2018-0791",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2018-0791"
                    }
                ],
                "file": {
                    "filename": "OUTLOOK.EXE",
                    "identity": {
                        "sha256": "465F398AE8E3C32395EB7C04BC8CD24595068E6A127E243BED3E9B4931556BFC"
                    }
                },
                "groups": [
                    {
                        "description": "Audit Group for QMASTERS SECURITY SERVICES LTD",
                        "guid": "fedd82f8-c74f-49f4-a463-e576d3beee92",
                        "name": "Audit"
                    }
                ],
                "latest_date": "2022-10-04T06:32:53+00:00",
                "latest_timestamp": 1664865173,
                "version": "2016"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Current Item Count|Index|Items Per Page|Total|
>|---|---|---|---|
>| 8 | 0 | 100 | 8 |
>### Vulnerabilities Information
>|Application|Version|Latest Date|File Name|SHA-256|
>|---|---|---|---|---|
>| Mozilla Firefox | 41.0 | 2022-10-25T12:20:00+00:00 | firefox.exe | 4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F |
>| Adobe Flash Player | 11.5.502.146 | 2022-10-25T12:05:49+00:00 | FlashPlayerApp.exe | c1219f0799e60ff48a9705b63c14168684aed911610fec68548ea08f605cc42b |
>| Oracle Java(TM) Platform SE | 1.7.0:update_10 | 2022-10-25T12:05:05+00:00 | java.exe | 0b4eefc0d815ac0fdc20f22add8fd2d8113be99578a4e5189122b28b201ccbd9 |
>| Adobe Acrobat Reader | 9.3.3.177 | 2022-10-25T12:02:34+00:00 | AcroRd32.exe | 825b7b20a913f26641c012f1cb61b81d29033f142ba6c6734425de06432e4f82 |
>| Microsoft Office | 2013 | 2022-10-23T12:37:33+00:00 | WINWORD.EXE | 3D46E95284F93BBB76B3B7E1BF0E1B2D51E8A9411C2B6E649112F22F92DE63C2 |
>| Microsoft Internet Explorer | 11 | 2022-10-04T07:02:27+00:00 | mshtml.dll | D1BEA74AC9D85B3DCD4ABC1AF42AF6C37B9349DEFC8E6577993611B773F56CA0 |
>| Microsoft Internet Explorer | 11 | 2022-10-04T07:02:26+00:00 | mshtml.dll | 1DC5D15A26A79BB46519952A60B15AA4ACB36F6CE3247EBF50DF9C157BC4FCF4 |
>| Microsoft Office | 2016 | 2022-10-04T06:32:53+00:00 | OUTLOOK.EXE | 465F398AE8E3C32395EB7C04BC8CD24595068E6A127E243BED3E9B4931556BFC |


### endpoint
***
Returns information about an endpoint.


#### Base Command

`endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. Takes priority over the IP and hostname arguments. | Optional | 
| ip | The endpoint IP address. The ip argument has priority over the hostname argument. | Optional | 
| hostname | The endpoint hostname. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The hostname of the endpoint. | 
| Endpoint.ID | String | The endpoint's identifier. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.OS | String | The endpoint's operating system. | 
| Endpoint.OSVersion | String | The endpoint's operating system's version. | 
| Endpoint.Status | String | The status of the endpoint \(online/offline\). | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 

#### Command example
```!endpoint id=22d4a486-1732-4f8b-9a6f-18f172fe7af0```
#### Context Example
```json
{
    "Endpoint": {
        "Hostname": "Demo_AMP",
        "ID": "22d4a486-1732-4f8b-9a6f-18f172fe7af0",
        "IPAddress": "191.250.254.209",
        "MACAddress": "e6:80:50:1e:e5:20",
        "OS": "Windows 10",
        "OSVersion": "10.0.19044.1466",
        "Status": "Online",
        "Vendor": "CiscoAMP Response"
    }
}
```

#### Human Readable Output

>### CiscoAMP - Endpoint Demo_AMP
>|Hostname|ID|IPAddress|MACAddress|OS|OSVersion|Status|Vendor|
>|---|---|---|---|---|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | 191.250.254.209 | e6:80:50:1e:e5:20 | Windows 10 | 10.0.19044.1466 | Online | CiscoAMP Response |


### file
***
Runs reputation on files.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports MD5, SHA1, and SHA256. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name \(including file extension\). | 
| File.Path | String | The path where the file is located. | 
| File.Hostname | String | The name of the host where the file was found. | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 

#### Command example
```!file file=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad```
#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "2ba068373ca5b647129a1a18c2506c32",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "hash",
            "Vendor": "VirusTotal"
        },
        {
            "Indicator": "2ba068373ca5b647129a1a18c2506c32",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "VirusTotal"
        },
        {
            "Indicator": "6d63da6b10a5cab1e4bd558cfdf606b42428809f",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "hash",
            "Vendor": "VirusTotal"
        },
        {
            "Indicator": "6d63da6b10a5cab1e4bd558cfdf606b42428809f",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "VirusTotal"
        },
        {
            "Indicator": "4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "hash",
            "Vendor": "VirusTotal"
        },
        {
            "Indicator": "4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "VirusTotal"
        },
        {
            "Indicator": "4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F",
            "Reliability": "C - Fairly reliable",
            "Score": 1,
            "Type": "file",
            "Vendor": "CiscoAMP"
        }
    ],
    "File": [
        {
            "DetectionEngines": 70,
            "MD5": "2ba068373ca5b647129a1a18c2506c32",
            "PositiveDetections": 0,
            "SHA1": "6d63da6b10a5cab1e4bd558cfdf606b42428809f",
            "SHA256": "4312cdb2ead8fd8d2dd6d8d716f3b6e9717b3d7167a2a0495e4391312102170f",
            "VirusTotal": {
                "ScanID":   "4312cdb2ead8fd8d2dd6d8d716f3b6e9717b3d7167a2a0495e4391312102170f-1662699814-1665164245",
                "vtLink": "https://www.virustotal.com/gui/file/ 4312cdb2ead8fd8d2dd6d8d716f3b6e9717b3d7167a2a0495e4391312102170f/detection/  f-4312cdb2ead8fd8d2dd6d8d716f3b6e9717b3d7167a2a0495e4391312102170f-1662699814"
            }
        },
        {
            "Hashes": [
                {
                    "type": "SHA256",
                    "value": "4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F"
                }
            ],
            "Hostname": "Demo_AMP_Exploit_Prevention",
            "Name": "firefox.exe",
            "SHA256": "4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F"
        }
    ]
}
```

#### Human Readable Output

### Cisco AMP - Hash Reputation for: 4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F
>|Hashes|Hostname|Name|SHA256|
>|---|---|---|---|
>| {'type': 'SHA256', 'value': '4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F'} | Demo_AMP_Exploit_Prevention | firefox.exe | 4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F |