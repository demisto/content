Cisco Advanced Malware Protection software is designed to prevent, detect, and help remove threats in an efficient manner from computer systems. Threats can take the form of software viruses and other malware such as ransomware, worms, Trojans, spyware, adware, and fileless malware.
This integration was integrated and tested with version 1 of CiscoAMP.

## Configure Cisco AMP Secure Endpoint in Cortex


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
| Event types | Comma-separated list of Event Type IDs. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| page_size | Number of results in a page. Maximum is 500. | Optional | 
| limit | Number of total results to return. | Optional | 
| connector_guid | The connector GUID for a specific computer. | Optional | 
| hostname | Comma-separated list of host names to filter by (has auto complete capabilities). | Optional | 
| internal_ip | Internal IP to filter by. | Optional | 
| external_ip | External IP to filter by. | Optional | 
| group_guid | Comma-separated list of group GUIDs to filter by. | Optional | 
| last_seen_within | Time range to filter by. | Optional | 
| last_seen_over | Time range to filter over by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Computer.connector_guid | String | GUID of the connector. | 
| CiscoAMP.Computer.hostname | String | Host's name. | 
| CiscoAMP.Computer.windows_processor_id | String | Windows processor ID. | 
| CiscoAMP.Computer.active | Boolean | Whether the computer is active. | 
| CiscoAMP.Computer.connector_version | String | Version of the connector. | 
| CiscoAMP.Computer.operating_system | String | Operating system of the computer. | 
| CiscoAMP.Computer.os_version | String | Operating system version. | 
| CiscoAMP.Computer.internal_ips | String | List of internal IPs. | 
| CiscoAMP.Computer.external_ip | String | External IP. | 
| CiscoAMP.Computer.group_guid | String | GUID of the group. | 
| CiscoAMP.Computer.install_date | Date | Installation date. | 
| CiscoAMP.Computer.is_compromised | Boolean | Whether the computer is compromised. | 
| CiscoAMP.Computer.demo | Boolean | Whether the computer is a demo. | 
| CiscoAMP.Computer.network_addresses.mac | String | List of MAC addresses. | 
| CiscoAMP.Computer.network_addresses.ip | String | List of IP addresses. | 
| CiscoAMP.Computer.policy.guid | String | GUID of the policy. | 
| CiscoAMP.Computer.policy.name | String | Name of the policy. | 
| CiscoAMP.Computer.groups.guid | String | GUID of the group. | 
| CiscoAMP.Computer.groups.name | String | Name of the group. | 
| CiscoAMP.Computer.last_seen | Date | Last date seen. | 
| CiscoAMP.Computer.faults | String | Faults. | 
| CiscoAMP.Computer.isolation.available | Boolean | Whether the isolation is available. | 
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
                "active": "CiscoAMP_Computer[0]_active",
                "connector_guid": "CiscoAMP_Computer[0]_connector_guid",
                "connector_version": "CiscoAMP_Computer[0]_connector_version",
                "demo": "CiscoAMP_Computer[0]_demo",
                "external_ip": "CiscoAMP_Computer[0]_external_ip",
                "faults": [],
                "group_guid": "CiscoAMP_Computer[0]_group_guid",
                "groups": [
                    {
                        "guid": "CiscoAMP_Computer[0]_groups[0]_guid",
                        "name": "CiscoAMP_Computer[0]_groups[0]_name"
                    }
                ],
                "hostname": "CiscoAMP_Computer[0]_hostname",
                "install_date": "CiscoAMP_Computer[0]_install_date",
                "internal_ips": [
                    "CiscoAMP_Computer[0]_internal_ips_0"
                ],
                "is_compromised": "CiscoAMP_Computer[0]_is_compromised",
                "isolation": {
                    "available": "CiscoAMP_Computer[0]_isolation_available",
                    "status": "CiscoAMP_Computer[0]_isolation_status"
                },
                "last_seen": "CiscoAMP_Computer[0]_last_seen",
                "network_addresses": [
                    {
                        "ip": "CiscoAMP_Computer[0]_network_addresses[0]_ip",
                        "mac": "CiscoAMP_Computer[0]_network_addresses[0]_mac"
                    }
                ],
                "operating_system": "CiscoAMP_Computer[0]_operating_system",
                "os_version": "CiscoAMP_Computer[0]_os_version",
                "policy": {
                    "guid": "CiscoAMP_Computer[0]_policy_guid",
                    "name": "CiscoAMP_Computer[0]_policy_name"
                },
                "windows_processor_id": "CiscoAMP_Computer[0]_windows_processor_id"
            },
            {
                "active": "CiscoAMP_Computer[1]_active",
                "connector_guid": "CiscoAMP_Computer[1]_connector_guid",
                "connector_version": "CiscoAMP_Computer[1]_connector_version",
                "demo": "CiscoAMP_Computer[1]_demo",
                "external_ip": "CiscoAMP_Computer[1]_external_ip",
                "faults": [],
                "group_guid": "CiscoAMP_Computer[1]_group_guid",
                "groups": [
                    {
                        "guid": "CiscoAMP_Computer[1]_groups[0]_guid",
                        "name": "CiscoAMP_Computer[1]_groups[0]_name"
                    }
                ],
                "hostname": "CiscoAMP_Computer[1]_hostname",
                "install_date": "CiscoAMP_Computer[1]_install_date",
                "internal_ips": [
                    "CiscoAMP_Computer[1]_internal_ips_0"
                ],
                "is_compromised": "CiscoAMP_Computer[1]_is_compromised",
                "isolation": {
                    "available": "CiscoAMP_Computer[1]_isolation_available",
                    "status": "CiscoAMP_Computer[1]_isolation_status"
                },
                "last_seen": "CiscoAMP_Computer[1]_last_seen",
                "network_addresses": [
                    {
                        "ip": "CiscoAMP_Computer[1]_network_addresses[0]_ip",
                        "mac": "CiscoAMP_Computer[1]_network_addresses[0]_mac"
                    }
                ],
                "operating_system": "CiscoAMP_Computer[1]_operating_system",
                "os_version": "CiscoAMP_Computer[1]_os_version",
                "policy": {
                    "guid": "CiscoAMP_Computer[1]_policy_guid",
                    "name": "CiscoAMP_Computer[1]_policy_name"
                },
                "windows_processor_id": "CiscoAMP_Computer[1]_windows_processor_id"
            },
            {
                "active": "CiscoAMP_Computer[2]_active",
                "connector_guid": "CiscoAMP_Computer[2]_connector_guid",
                "connector_version": "CiscoAMP_Computer[2]_connector_version",
                "demo": "CiscoAMP_Computer[2]_demo",
                "external_ip": "CiscoAMP_Computer[2]_external_ip",
                "faults": [],
                "group_guid": "CiscoAMP_Computer[2]_group_guid",
                "groups": [
                    {
                        "guid": "CiscoAMP_Computer[2]_groups[0]_guid",
                        "name": "CiscoAMP_Computer[2]_groups[0]_name"
                    }
                ],
                "hostname": "CiscoAMP_Computer[2]_hostname",
                "install_date": "CiscoAMP_Computer[2]_install_date",
                "internal_ips": [
                    "CiscoAMP_Computer[2]_internal_ips_0"
                ],
                "is_compromised": "CiscoAMP_Computer[2]_is_compromised",
                "isolation": {
                    "available": "CiscoAMP_Computer[2]_isolation_available",
                    "status": "CiscoAMP_Computer[2]_isolation_status"
                },
                "last_seen": "CiscoAMP_Computer[2]_last_seen",
                "network_addresses": [
                    {
                        "ip": "CiscoAMP_Computer[2]_network_addresses[0]_ip",
                        "mac": "CiscoAMP_Computer[2]_network_addresses[0]_mac"
                    }
                ],
                "operating_system": "CiscoAMP_Computer[2]_operating_system",
                "os_version": "CiscoAMP_Computer[2]_os_version",
                "policy": {
                    "guid": "CiscoAMP_Computer[2]_policy_guid",
                    "name": "CiscoAMP_Computer[2]_policy_name"
                },
                "windows_processor_id": "CiscoAMP_Computer[2]_windows_processor_id"
            },
            {
                "active": "CiscoAMP_Computer[3]_active",
                "connector_guid": "CiscoAMP_Computer[3]_connector_guid",
                "connector_version": "CiscoAMP_Computer[3]_connector_version",
                "demo": "CiscoAMP_Computer[3]_demo",
                "external_ip": "CiscoAMP_Computer[3]_external_ip",
                "faults": [],
                "group_guid": "CiscoAMP_Computer[3]_group_guid",
                "groups": [
                    {
                        "guid": "CiscoAMP_Computer[3]_groups[0]_guid",
                        "name": "CiscoAMP_Computer[3]_groups[0]_name"
                    }
                ],
                "hostname": "CiscoAMP_Computer[3]_hostname",
                "install_date": "CiscoAMP_Computer[3]_install_date",
                "internal_ips": [
                    "CiscoAMP_Computer[3]_internal_ips_0"
                ],
                "is_compromised": "CiscoAMP_Computer[3]_is_compromised",
                "isolation": {
                    "available": "CiscoAMP_Computer[3]_isolation_available",
                    "status": "CiscoAMP_Computer[3]_isolation_status"
                },
                "last_seen": "CiscoAMP_Computer[3]_last_seen",
                "network_addresses": [
                    {
                        "ip": "CiscoAMP_Computer[3]_network_addresses[0]_ip",
                        "mac": "CiscoAMP_Computer[3]_network_addresses[0]_mac"
                    }
                ],
                "operating_system": "CiscoAMP_Computer[3]_operating_system",
                "os_version": "CiscoAMP_Computer[3]_os_version",
                "policy": {
                    "guid": "CiscoAMP_Computer[3]_policy_guid",
                    "name": "CiscoAMP_Computer[3]_policy_name"
                },
                "windows_processor_id": "CiscoAMP_Computer[3]_windows_processor_id"
            },
            {
                "active": "CiscoAMP_Computer[4]_active",
                "connector_guid": "CiscoAMP_Computer[4]_connector_guid",
                "connector_version": "CiscoAMP_Computer[4]_connector_version",
                "demo": "CiscoAMP_Computer[4]_demo",
                "external_ip": "CiscoAMP_Computer[4]_external_ip",
                "faults": [],
                "group_guid": "CiscoAMP_Computer[4]_group_guid",
                "groups": [
                    {
                        "guid": "CiscoAMP_Computer[4]_groups[0]_guid",
                        "name": "CiscoAMP_Computer[4]_groups[0]_name"
                    }
                ],
                "hostname": "CiscoAMP_Computer[4]_hostname",
                "install_date": "CiscoAMP_Computer[4]_install_date",
                "internal_ips": [
                    "CiscoAMP_Computer[4]_internal_ips_0"
                ],
                "is_compromised": "CiscoAMP_Computer[4]_is_compromised",
                "isolation": {
                    "available": "CiscoAMP_Computer[4]_isolation_available",
                    "status": "CiscoAMP_Computer[4]_isolation_status"
                },
                "last_seen": "CiscoAMP_Computer[4]_last_seen",
                "network_addresses": [
                    {
                        "ip": "CiscoAMP_Computer[4]_network_addresses[0]_ip",
                        "mac": "CiscoAMP_Computer[4]_network_addresses[0]_mac"
                    }
                ],
                "operating_system": "CiscoAMP_Computer[4]_operating_system",
                "os_version": "CiscoAMP_Computer[4]_os_version",
                "policy": {
                    "guid": "CiscoAMP_Computer[4]_policy_guid",
                    "name": "CiscoAMP_Computer[4]_policy_name"
                },
                "windows_processor_id": "CiscoAMP_Computer[4]_windows_processor_id"
            }
        ]
    },
    "Endpoint": [
        {
            "Hostname": "Endpoint[0]_Hostname",
            "ID": "Endpoint[0]_ID",
            "IPAddress": "Endpoint[0]_IPAddress",
            "MACAddress": "Endpoint[0]_MACAddress",
            "OS": "Endpoint[0]_OS",
            "OSVersion": "Endpoint[0]_OSVersion",
            "Status": "Endpoint[0]_Status",
            "Vendor": "Endpoint[0]_Vendor"
        },
        {
            "Hostname": "Endpoint[1]_Hostname",
            "ID": "Endpoint[1]_ID",
            "IPAddress": "Endpoint[1]_IPAddress",
            "MACAddress": "Endpoint[1]_MACAddress",
            "OS": "Endpoint[1]_OS",
            "OSVersion": "Endpoint[1]_OSVersion",
            "Status": "Endpoint[1]_Status",
            "Vendor": "Endpoint[1]_Vendor"
        },
        {
            "Hostname": "Endpoint[2]_Hostname",
            "ID": "Endpoint[2]_ID",
            "IPAddress": "Endpoint[2]_IPAddress",
            "MACAddress": "Endpoint[2]_MACAddress",
            "OS": "Endpoint[2]_OS",
            "OSVersion": "Endpoint[2]_OSVersion",
            "Status": "Endpoint[2]_Status",
            "Vendor": "Endpoint[2]_Vendor"
        },
        {
            "Hostname": "Endpoint[3]_Hostname",
            "ID": "Endpoint[3]_ID",
            "IPAddress": "Endpoint[3]_IPAddress",
            "MACAddress": "Endpoint[3]_MACAddress",
            "OS": "Endpoint[3]_OS",
            "OSVersion": "Endpoint[3]_OSVersion",
            "Status": "Endpoint[3]_Status",
            "Vendor": "Endpoint[3]_Vendor"
        },
        {
            "Hostname": "Endpoint[4]_Hostname",
            "ID": "Endpoint[4]_ID",
            "IPAddress": "Endpoint[4]_IPAddress",
            "MACAddress": "Endpoint[4]_MACAddress",
            "OS": "Endpoint[4]_OS",
            "OSVersion": "Endpoint[4]_OSVersion",
            "Status": "Endpoint[4]_Status",
            "Vendor": "Endpoint[4]_Vendor"
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
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | Windows 10 (Build 10.0.19044.1466) | IP | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 | 91c7894d-dd69-4a21-8cf6-5ebfc57ef4df |
>| Demo_AMP_Exploit_Prevention | 113c1a8e-8e66-409e-92a8-41b7d586be5d | Windows 10 (Build 10.0.19044.1466) | IP | 6ed80412-0739-42c1-8f6d-32fb51b3f894 | 1a352c59-793b-44f3-b8f9-0ddd354057bc |
>| Demo_AMP_Exploit_Prevention_Audit | 93f395a2-e31f-4022-b1dd-afb16e093b8d | Windows 10 (Build 10.0.19044.1466) | IP | 5b1857e3-ba49-46cf-9bf1-0cad6b5ecd18 | a599bf5b-2cb7-4a5b-90bd-d0199e2ccd67 |
>| Demo_AMP_Intel | d6f49c17-9721-4c5b-a04f-32ba30be36a0 | Windows 10 (Build 10.0.19043.1202) | IP | fedd82f8-c74f-49f4-a463-e576d3beee92 | be84e169-0830-4b95-915b-1e203a82ed58 |
>| Demo_AMP_MAP_FriedEx | 9a2abee8-b988-473b-9e99-a7abe6d068a5 | Windows 10 (Build 10.0.19044.1466) | IP | 6ed80412-0739-42c1-8f6d-32fb51b3f894 | 1a352c59-793b-44f3-b8f9-0ddd354057bc |


### cisco-amp-computer-trajectory-list
***
Provides a list of all activities associated with a particular computer. This is analogous to the Device Trajectory on the FireAMP console.


#### Base Command

`cisco-amp-computer-trajectory-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | The connector GUID for a specific computer. | Required | 
| query_string | Freeform query string which currently accepts an: IP address, SHA-256, or URL. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 5000. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerTrajectory.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerTrajectory.id | String | Event's ID. | 
| CiscoAMP.ComputerTrajectory.timestamp | Number | Event's timestamp. | 
| CiscoAMP.ComputerTrajectory.timestamp_nanoseconds | Number | Event's timestamp in nano seconds. | 
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
| CiscoAMP.ComputerTrajectory.scan.description | String | Description of the scan. | 
| CiscoAMP.ComputerTrajectory.scan.clean | Boolean | Whether the scan is clean. | 
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
                "connector_guid": "CiscoAMP_ComputerTrajectory[0]_connector_guid",
                "date": "CiscoAMP_ComputerTrajectory[0]_date",
                "event_type": "CiscoAMP_ComputerTrajectory[0]_event_type",
                "event_type_id": "CiscoAMP_ComputerTrajectory[0]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerTrajectory[0]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerTrajectory[0]_id",
                "isolation": {
                    "duration": "CiscoAMP_ComputerTrajectory[0]_isolation_duration"
                },
                "timestamp": "CiscoAMP_ComputerTrajectory[0]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerTrajectory[0]_timestamp_nanoseconds"
            },
            {
                "connector_guid": "CiscoAMP_ComputerTrajectory[1]_connector_guid",
                "date": "CiscoAMP_ComputerTrajectory[1]_date",
                "event_type": "CiscoAMP_ComputerTrajectory[1]_event_type",
                "event_type_id": "CiscoAMP_ComputerTrajectory[1]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerTrajectory[1]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerTrajectory[1]_id",
                "timestamp": "CiscoAMP_ComputerTrajectory[1]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerTrajectory[1]_timestamp_nanoseconds"
            },
            {
                "connector_guid": "CiscoAMP_ComputerTrajectory[2]_connector_guid",
                "date": "CiscoAMP_ComputerTrajectory[2]_date",
                "event_type": "CiscoAMP_ComputerTrajectory[2]_event_type",
                "event_type_id": "CiscoAMP_ComputerTrajectory[2]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerTrajectory[2]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerTrajectory[2]_id",
                "isolation": {
                    "duration": "CiscoAMP_ComputerTrajectory[2]_isolation_duration"
                },
                "timestamp": "CiscoAMP_ComputerTrajectory[2]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerTrajectory[2]_timestamp_nanoseconds"
            },
            {
                "connector_guid": "CiscoAMP_ComputerTrajectory[3]_connector_guid",
                "date": "CiscoAMP_ComputerTrajectory[3]_date",
                "event_type": "CiscoAMP_ComputerTrajectory[3]_event_type",
                "event_type_id": "CiscoAMP_ComputerTrajectory[3]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerTrajectory[3]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerTrajectory[3]_id",
                "timestamp": "CiscoAMP_ComputerTrajectory[3]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerTrajectory[3]_timestamp_nanoseconds"
            },
            {
                "connector_guid": "CiscoAMP_ComputerTrajectory[4]_connector_guid",
                "date": "CiscoAMP_ComputerTrajectory[4]_date",
                "event_type": "CiscoAMP_ComputerTrajectory[4]_event_type",
                "event_type_id": "CiscoAMP_ComputerTrajectory[4]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerTrajectory[4]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerTrajectory[4]_id",
                "isolation": {
                    "duration": "CiscoAMP_ComputerTrajectory[4]_isolation_duration"
                },
                "timestamp": "CiscoAMP_ComputerTrajectory[4]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerTrajectory[4]_timestamp_nanoseconds"
            }
        ]
    }
}
```

#### Human Readable Output

>### Computer Information
>|Host Name|Connector GUID|Operating System|External IP|Group GUID|Policy GUID|
>|---|---|---|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | Windows 10 (Build 10.0.19044.1466) | IP | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 | 91c7894d-dd69-4a21-8cf6-5ebfc57ef4df |
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
| page_size | Number of results in a page. Maximum is 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerUserActivity.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerUserActivity.hostname | String | Host's name. | 
| CiscoAMP.ComputerUserActivity.active | Boolean | Whether the computer is active. | 

#### Command example
```!cisco-amp-computer-user-activity-list username=johndoe```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerUserActivity": [
            {
                "active": "CiscoAMP_ComputerUserActivity[0]_active",
                "connector_guid": "CiscoAMP_ComputerUserActivity[0]_connector_guid",
                "hostname": "CiscoAMP_ComputerUserActivity[0]_hostname"
            },
            {
                "active": "CiscoAMP_ComputerUserActivity[1]_active",
                "connector_guid": "CiscoAMP_ComputerUserActivity[1]_connector_guid",
                "hostname": "CiscoAMP_ComputerUserActivity[1]_hostname"
            },
            {
                "active": "CiscoAMP_ComputerUserActivity[2]_active",
                "connector_guid": "CiscoAMP_ComputerUserActivity[2]_connector_guid",
                "hostname": "CiscoAMP_ComputerUserActivity[2]_hostname"
            },
            {
                "active": "CiscoAMP_ComputerUserActivity[3]_active",
                "connector_guid": "CiscoAMP_ComputerUserActivity[3]_connector_guid",
                "hostname": "CiscoAMP_ComputerUserActivity[3]_hostname"
            },
            {
                "active": "CiscoAMP_ComputerUserActivity[4]_active",
                "connector_guid": "CiscoAMP_ComputerUserActivity[4]_connector_guid",
                "hostname": "CiscoAMP_ComputerUserActivity[4]_hostname"
            },
            {
                "active": "CiscoAMP_ComputerUserActivity[5]_active",
                "connector_guid": "CiscoAMP_ComputerUserActivity[5]_connector_guid",
                "hostname": "CiscoAMP_ComputerUserActivity[5]_hostname"
            },
            {
                "active": "CiscoAMP_ComputerUserActivity[6]_active",
                "connector_guid": "CiscoAMP_ComputerUserActivity[6]_connector_guid",
                "hostname": "CiscoAMP_ComputerUserActivity[6]_hostname"
            },
            {
                "active": "CiscoAMP_ComputerUserActivity[7]_active",
                "connector_guid": "CiscoAMP_ComputerUserActivity[7]_connector_guid",
                "hostname": "CiscoAMP_ComputerUserActivity[7]_hostname"
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
Fetch a specific computer's trajectory with a given connector_guid and filter for events with user name activity.


#### Base Command

`cisco-amp-computer-user-trajectory-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | The connector GUID for a specific computer. | Required | 
| username | Username to filter by. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 5000. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerUserTrajectory.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerUserTrajectory.id | String | Event's ID. | 
| CiscoAMP.ComputerUserTrajectory.timestamp | Number | Event's timestamp. | 
| CiscoAMP.ComputerUserTrajectory.timestamp_nanoseconds | Number | Event's timestamp in nano seconds. | 
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
| CiscoAMP.ComputerUserTrajectory.scan.clean | Boolean | Whether the scan is clean. | 
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
                "connector_guid": "CiscoAMP_ComputerUserTrajectory[0]_connector_guid",
                "date": "CiscoAMP_ComputerUserTrajectory[0]_date",
                "event_type": "CiscoAMP_ComputerUserTrajectory[0]_event_type",
                "event_type_id": "CiscoAMP_ComputerUserTrajectory[0]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerUserTrajectory[0]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerUserTrajectory[0]_id",
                "isolation": {
                    "duration": "CiscoAMP_ComputerUserTrajectory[0]_isolation_duration"
                },
                "timestamp": "CiscoAMP_ComputerUserTrajectory[0]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerUserTrajectory[0]_timestamp_nanoseconds"
            },
            {
                "connector_guid": "CiscoAMP_ComputerUserTrajectory[1]_connector_guid",
                "date": "CiscoAMP_ComputerUserTrajectory[1]_date",
                "event_type": "CiscoAMP_ComputerUserTrajectory[1]_event_type",
                "event_type_id": "CiscoAMP_ComputerUserTrajectory[1]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerUserTrajectory[1]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerUserTrajectory[1]_id",
                "timestamp": "CiscoAMP_ComputerUserTrajectory[1]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerUserTrajectory[1]_timestamp_nanoseconds"
            },
            {
                "connector_guid": "CiscoAMP_ComputerUserTrajectory[2]_connector_guid",
                "date": "CiscoAMP_ComputerUserTrajectory[2]_date",
                "event_type": "CiscoAMP_ComputerUserTrajectory[2]_event_type",
                "event_type_id": "CiscoAMP_ComputerUserTrajectory[2]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerUserTrajectory[2]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerUserTrajectory[2]_id",
                "isolation": {
                    "duration": "CiscoAMP_ComputerUserTrajectory[2]_isolation_duration"
                },
                "timestamp": "CiscoAMP_ComputerUserTrajectory[2]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerUserTrajectory[2]_timestamp_nanoseconds"
            },
            {
                "connector_guid": "CiscoAMP_ComputerUserTrajectory[3]_connector_guid",
                "date": "CiscoAMP_ComputerUserTrajectory[3]_date",
                "event_type": "CiscoAMP_ComputerUserTrajectory[3]_event_type",
                "event_type_id": "CiscoAMP_ComputerUserTrajectory[3]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerUserTrajectory[3]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerUserTrajectory[3]_id",
                "timestamp": "CiscoAMP_ComputerUserTrajectory[3]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerUserTrajectory[3]_timestamp_nanoseconds"
            },
            {
                "connector_guid": "CiscoAMP_ComputerUserTrajectory[4]_connector_guid",
                "date": "CiscoAMP_ComputerUserTrajectory[4]_date",
                "event_type": "CiscoAMP_ComputerUserTrajectory[4]_event_type",
                "event_type_id": "CiscoAMP_ComputerUserTrajectory[4]_event_type_id",
                "group_guids": [
                    "CiscoAMP_ComputerUserTrajectory[4]_group_guids_0"
                ],
                "id": "CiscoAMP_ComputerUserTrajectory[4]_id",
                "isolation": {
                    "duration": "CiscoAMP_ComputerUserTrajectory[4]_isolation_duration"
                },
                "timestamp": "CiscoAMP_ComputerUserTrajectory[4]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_ComputerUserTrajectory[4]_timestamp_nanoseconds"
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
| connector_guid | The connector GUID for a specific computer. | Required | 
| start_time | The start date and time expressed according to ISO 8601. The retrieved list will include vulnerable programs detected at start_time. | Optional | 
| end_time | The end date and/or time expressed according to ISO 8601. Exclusive - if end_time is a time, the list will only include vulnerable programs detected before end_time). Inclusive - if end_time is a date, the list will include vulnerable programs detected on the date. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 500. | Optional | 
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
            "application": "CiscoAMP_ComputerVulnerability_application",
            "connector_guid": "CiscoAMP_ComputerVulnerability_connector_guid",
            "cves": [
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[0]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[0]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[0]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[1]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[1]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[1]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[2]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[2]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[2]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[3]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[3]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[3]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[4]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[4]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[4]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[5]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[5]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[5]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[6]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[6]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[6]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[7]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[7]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[7]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[8]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[8]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[8]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[9]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[9]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[9]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[10]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[10]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[10]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[11]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[11]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[11]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[12]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[12]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[12]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[13]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[13]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[13]_link"
                },
                {
                    "cvss": "CiscoAMP_ComputerVulnerability_cves[14]_cvss",
                    "id": "CiscoAMP_ComputerVulnerability_cves[14]_id",
                    "link": "CiscoAMP_ComputerVulnerability_cves[14]_link"
                }
            ],
            "file": {
                "filename": "CiscoAMP_ComputerVulnerability_file_filename",
                "identity": {
                    "sha256": "CiscoAMP_ComputerVulnerability_file_identity_sha256"
                }
            },
            "latest_date": "CiscoAMP_ComputerVulnerability_latest_date",
            "latest_timestamp": "CiscoAMP_ComputerVulnerability_latest_timestamp",
            "version": "CiscoAMP_ComputerVulnerability_version"
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
Moves a computer to a group with a given connector_guid and group_guid.


#### Base Command

`cisco-amp-computer-move`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | The connector GUID for a specific computer. | Required | 
| group_guid | Group GUID to move the computer to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Computer.connector_guid | String | GUID of the connector. | 
| CiscoAMP.Computer.hostname | String | Host's name. | 
| CiscoAMP.Computer.windows_processor_id | String | Windows processor ID. | 
| CiscoAMP.Computer.active | Boolean | Whether the computer is active. | 
| CiscoAMP.Computer.connector_version | String | Version of the connector. | 
| CiscoAMP.Computer.operating_system | String | Operating system of the computer. | 
| CiscoAMP.Computer.os_version | String | Operating system version. | 
| CiscoAMP.Computer.internal_ips | String | List of internal IPs. | 
| CiscoAMP.Computer.external_ip | String | External IP. | 
| CiscoAMP.Computer.group_guid | String | GUID of the group. | 
| CiscoAMP.Computer.install_date | Date | Installation date. | 
| CiscoAMP.Computer.is_compromised | Boolean | Whether the computer is compromised. | 
| CiscoAMP.Computer.demo | Boolean | Whether the computer is a demo. | 
| CiscoAMP.Computer.network_addresses.mac | String | List of MAC addresses. | 
| CiscoAMP.Computer.network_addresses.ip | String | List of IP addresses. | 
| CiscoAMP.Computer.policy.guid | String | GUID of the policy. | 
| CiscoAMP.Computer.policy.name | String | Name of the policy. | 
| CiscoAMP.Computer.groups.guid | String | GUID of the group. | 
| CiscoAMP.Computer.groups.name | String | Name of the group. | 
| CiscoAMP.Computer.last_seen | Date | Last date seen. | 
| CiscoAMP.Computer.faults | String | Faults. | 
| CiscoAMP.Computer.isolation.available | Boolean | Whether the isolation is available. | 
| CiscoAMP.Computer.isolation.status | String | Status of the isolation. | 
| CiscoAMP.Computer.orbital.status | String | Status of the orbital. | 

#### Command example
```!cisco-amp-computer-move connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0 group_guid=bb5a9f90-d6fa-4fe7-99c8-e91060b49a98```
#### Context Example
```json
{
    "CiscoAMP": {
        "Computer": {
            "active": "CiscoAMP_Computer_active",
            "connector_guid": "CiscoAMP_Computer_connector_guid",
            "connector_version": "CiscoAMP_Computer_connector_version",
            "demo": "CiscoAMP_Computer_demo",
            "external_ip": "CiscoAMP_Computer_external_ip",
            "faults": [],
            "group_guid": "CiscoAMP_Computer_group_guid",
            "groups": [
                {
                    "guid": "CiscoAMP_Computer_groups[0]_guid",
                    "name": "CiscoAMP_Computer_groups[0]_name"
                }
            ],
            "hostname": "CiscoAMP_Computer_hostname",
            "install_date": "CiscoAMP_Computer_install_date",
            "internal_ips": [
                "CiscoAMP_Computer_internal_ips_0"
            ],
            "is_compromised": "CiscoAMP_Computer_is_compromised",
            "isolation": {
                "available": "CiscoAMP_Computer_isolation_available",
                "status": "CiscoAMP_Computer_isolation_status"
            },
            "network_addresses": [
                {
                    "ip": "CiscoAMP_Computer_network_addresses[0]_ip",
                    "mac": "CiscoAMP_Computer_network_addresses[0]_mac"
                }
            ],
            "operating_system": "CiscoAMP_Computer_operating_system",
            "os_version": "CiscoAMP_Computer_os_version",
            "policy": {
                "guid": "CiscoAMP_Computer_policy_guid",
                "name": "CiscoAMP_Computer_policy_name"
            },
            "windows_processor_id": "CiscoAMP_Computer_windows_processor_id"
        }
    }
}
```

#### Human Readable Output

>### Computer Information
>|Host Name|Connector GUID|Operating System|External IP|Group GUID|Policy GUID|
>|---|---|---|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | Windows 10 (Build 10.0.19044.1466) | IP | bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 | 91c7894d-dd69-4a21-8cf6-5ebfc57ef4df |


### cisco-amp-computer-delete
***
Deletes a specific computer with given connector GUID.


#### Base Command

`cisco-amp-computer-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | The connector GUID for a specific computer. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-amp-computer-delete connector_guid=dddd4ceb-4ce1-4f81-a7a7-04d13cc1df43```
#### Human Readable Output

>Connector GUID: "dddd4ceb-4ce1-4f81-a7a7-04d13cc1df43"
>Successfully deleted.

### cisco-amp-computer-activity-list
***
Fetch a list of computers that have observed files with a given file name. Provides the ability to search all computers across an organization for any events or activities associated with a file or network operation, and returns computers matching those criteria. There is a hard limit of 5000 historical entries searched.


#### Base Command

`cisco-amp-computer-activity-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_string | Freeform query string which currently accepts: IPv4 address (CIDR not supported), SHA-256, file name, and a URL Fragment. | Required | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.ComputerActivity.connector_guid | String | GUID of the connector. | 
| CiscoAMP.ComputerActivity.hostname | String | Host's name. | 
| CiscoAMP.ComputerActivity.windows_processor_id | String | Windows processor ID. | 
| CiscoAMP.ComputerActivity.active | Boolean | Whether the computer is active. | 

#### Command example
```!cisco-amp-computer-activity-list query_string=8.8.8.8```
#### Context Example
```json
{
    "CiscoAMP": {
        "ComputerActivity": [
            {
                "active": "CiscoAMP_ComputerActivity[0]_active",
                "connector_guid": "CiscoAMP_ComputerActivity[0]_connector_guid",
                "hostname": "CiscoAMP_ComputerActivity[0]_hostname",
                "windows_processor_id": "CiscoAMP_ComputerActivity[0]_windows_processor_id"
            },
            {
                "active": "CiscoAMP_ComputerActivity[1]_active",
                "connector_guid": "CiscoAMP_ComputerActivity[1]_connector_guid",
                "hostname": "CiscoAMP_ComputerActivity[1]_hostname",
                "windows_processor_id": "CiscoAMP_ComputerActivity[1]_windows_processor_id"
            },
            {
                "active": "CiscoAMP_ComputerActivity[2]_active",
                "connector_guid": "CiscoAMP_ComputerActivity[2]_connector_guid",
                "hostname": "CiscoAMP_ComputerActivity[2]_hostname",
                "windows_processor_id": "CiscoAMP_ComputerActivity[2]_windows_processor_id"
            },
            {
                "active": "CiscoAMP_ComputerActivity[3]_active",
                "connector_guid": "CiscoAMP_ComputerActivity[3]_connector_guid",
                "hostname": "CiscoAMP_ComputerActivity[3]_hostname",
                "windows_processor_id": "CiscoAMP_ComputerActivity[3]_windows_processor_id"
            },
            {
                "active": "CiscoAMP_ComputerActivity[4]_active",
                "connector_guid": "CiscoAMP_ComputerActivity[4]_connector_guid",
                "hostname": "CiscoAMP_ComputerActivity[4]_hostname",
                "windows_processor_id": "CiscoAMP_ComputerActivity[4]_windows_processor_id"
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
Performs a feature availability request on a computer. Isolation must be enabled within the computer's policy. This can be done through the instance. Log in to your account -> Management -> Policies -> Choose the relevant policy -> Edit -> Advanced Settings -> Endpoint Isolation -> Allow Endpoint Isolation.


#### Base Command

`cisco-amp-computer-isolation-feature-availability-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | The connector GUID for a specific computer. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!cisco-amp-computer-isolation-feature-availability-get connector_guid=22d4a486-1732-4f8b-9a6f-18f172fe7af0```
#### Human Readable Output

>Can get information about an isolation with computer-isolation-get
>Can request to create a new isolation with computer-isolation-create


### cisco-amp-computer-isolation-get
***
Returns a fine-grained isolation status for a computer. The available flag is set to true if isolation can be performed on the computer. Status will be set to one of - not_isolated, pending_start, isolated and pending_stop. Isolation must be enabled within the computer's policy. This can be done through the instance. Log in to your account -> Management -> Policies -> Choose the relevant policy -> Edit -> Advanced Settings -> Endpoint Isolation -> Allow Endpoint Isolation.


#### Base Command

`cisco-amp-computer-isolation-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| connector_guid | The connector GUID for a specific computer. | Required | 


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
            "available": "CiscoAMP_ComputerIsolation_available",
            "comment": "CiscoAMP_ComputerIsolation_comment",
            "connector_guid": "CiscoAMP_ComputerIsolation_connector_guid",
            "status": "CiscoAMP_ComputerIsolation_status",
            "unlock_code": "CiscoAMP_ComputerIsolation_unlock_code"
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
Request isolation for a computer. Supports polling. Isolation must be enabled within the computer's policy. This can be done through the instance. Log in to your account -> Management -> Policies -> Choose the relevant policy -> Edit -> Advanced Settings -> Endpoint Isolation -> Allow Endpoint Isolation.


#### Base Command

`cisco-amp-computer-isolation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 
| connector_guid | The connector GUID for a specific computer. | Required | 
| comment | Comment for isolation. | Required | 
| unlock_code | Isolation unlock code. | Required | 
| status | Status of the current run. | Optional | 


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
            "available": "CiscoAMP_ComputerIsolation_available",
            "comment": "CiscoAMP_ComputerIsolation_comment",
            "connector_guid": "CiscoAMP_ComputerIsolation_connector_guid",
            "isolated_by": "CiscoAMP_ComputerIsolation_isolated_by",
            "status": "CiscoAMP_ComputerIsolation_status",
            "unlock_code": "CiscoAMP_ComputerIsolation_unlock_code"
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
Request isolation stop for a computer. Supports polling. Isolation must be enabled within the computer's policy. This can be done through the instance. Log in to your account -> Management -> Policies -> Choose the relevant policy -> Edit -> Advanced Settings -> Endpoint Isolation -> Allow Endpoint Isolation.


#### Base Command

`cisco-amp-computer-isolation-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 
| connector_guid | The connector GUID for a specific computer. | Required | 
| comment | Comment for isolation deletion. | Optional | 
| status | Status of the current run. | Optional | 


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
| connector_guid | Comma-separated list for connector GUIDs to filter by. | Optional | 
| group_guid | Comma-separated list for group GUIDs to filter by. | Optional | 
| start_date | Fetch events that are newer than the given time. | Optional | 
| event_type | Comma-separated list for event types to filter by. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Event.id | Number | Event's ID. | 
| CiscoAMP.Event.timestamp | Number | Event's timestamp. | 
| CiscoAMP.Event.timestamp_nanoseconds | Number | Event's timestamp in nano seconds. | 
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
| CiscoAMP.Event.computer.active | Boolean | Whether the computer is active. | 
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
| CiscoAMP.Event.file.parent.file_name | String | Parent's file name. | 
| CiscoAMP.Event.file.parent.disposition | String | Parent's disposition. | 
| CiscoAMP.Event.file.parent.identity.sha256 | String | Parent's SHA-256. | 
| CiscoAMP.Event.file.parent.identity.sha1 | String | Parent's SHA-1. | 
| CiscoAMP.Event.file.parent.identity.md5 | String | Parent's MD5. | 
| CiscoAMP.Event.scan.description | String | Description of the scan. | 
| CiscoAMP.Event.scan.clean | Boolean | Whether the scam is clean. | 
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
| File.Malicious.Description | String | A description of why the file was determined to be malicious. | 
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
                    "active": "CiscoAMP_Event[0]_computer_active",
                    "connector_guid": "CiscoAMP_Event[0]_computer_connector_guid",
                    "external_ip": "CiscoAMP_Event[0]_computer_external_ip",
                    "hostname": "CiscoAMP_Event[0]_computer_hostname",
                    "network_addresses": [
                        {
                            "ip": "CiscoAMP_Event[0]_computer_network_addresses[0]_ip",
                            "mac": "CiscoAMP_Event[0]_computer_network_addresses[0]_mac"
                        }
                    ]
                },
                "connector_guid": "CiscoAMP_Event[0]_connector_guid",
                "date": "CiscoAMP_Event[0]_date",
                "event_type": "CiscoAMP_Event[0]_event_type",
                "event_type_id": "CiscoAMP_Event[0]_event_type_id",
                "group_guids": [
                    "CiscoAMP_Event[0]_group_guids_0"
                ],
                "id": "CiscoAMP_Event[0]_id",
                "isolation": {
                    "duration": "CiscoAMP_Event[0]_isolation_duration"
                },
                "timestamp": "CiscoAMP_Event[0]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_Event[0]_timestamp_nanoseconds"
            },
            {
                "computer": {
                    "active": "CiscoAMP_Event[1]_computer_active",
                    "connector_guid": "CiscoAMP_Event[1]_computer_connector_guid",
                    "external_ip": "CiscoAMP_Event[1]_computer_external_ip",
                    "hostname": "CiscoAMP_Event[1]_computer_hostname",
                    "network_addresses": [
                        {
                            "ip": "CiscoAMP_Event[1]_computer_network_addresses[0]_ip",
                            "mac": "CiscoAMP_Event[1]_computer_network_addresses[0]_mac"
                        }
                    ]
                },
                "connector_guid": "CiscoAMP_Event[1]_connector_guid",
                "date": "CiscoAMP_Event[1]_date",
                "event_type": "CiscoAMP_Event[1]_event_type",
                "event_type_id": "CiscoAMP_Event[1]_event_type_id",
                "group_guids": [
                    "CiscoAMP_Event[1]_group_guids_0"
                ],
                "id": "CiscoAMP_Event[1]_id",
                "timestamp": "CiscoAMP_Event[1]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_Event[1]_timestamp_nanoseconds"
            },
            {
                "computer": {
                    "active": "CiscoAMP_Event[2]_computer_active",
                    "connector_guid": "CiscoAMP_Event[2]_computer_connector_guid",
                    "external_ip": "CiscoAMP_Event[2]_computer_external_ip",
                    "hostname": "CiscoAMP_Event[2]_computer_hostname",
                    "network_addresses": [
                        {
                            "ip": "CiscoAMP_Event[2]_computer_network_addresses[0]_ip",
                            "mac": "CiscoAMP_Event[2]_computer_network_addresses[0]_mac"
                        }
                    ]
                },
                "connector_guid": "CiscoAMP_Event[2]_connector_guid",
                "date": "CiscoAMP_Event[2]_date",
                "event_type": "CiscoAMP_Event[2]_event_type",
                "event_type_id": "CiscoAMP_Event[2]_event_type_id",
                "group_guids": [
                    "CiscoAMP_Event[2]_group_guids_0"
                ],
                "id": "CiscoAMP_Event[2]_id",
                "isolation": {
                    "duration": "CiscoAMP_Event[2]_isolation_duration"
                },
                "timestamp": "CiscoAMP_Event[2]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_Event[2]_timestamp_nanoseconds"
            },
            {
                "computer": {
                    "active": "CiscoAMP_Event[3]_computer_active",
                    "connector_guid": "CiscoAMP_Event[3]_computer_connector_guid",
                    "external_ip": "CiscoAMP_Event[3]_computer_external_ip",
                    "hostname": "CiscoAMP_Event[3]_computer_hostname",
                    "network_addresses": [
                        {
                            "ip": "CiscoAMP_Event[3]_computer_network_addresses[0]_ip",
                            "mac": "CiscoAMP_Event[3]_computer_network_addresses[0]_mac"
                        }
                    ]
                },
                "connector_guid": "CiscoAMP_Event[3]_connector_guid",
                "date": "CiscoAMP_Event[3]_date",
                "event_type": "CiscoAMP_Event[3]_event_type",
                "event_type_id": "CiscoAMP_Event[3]_event_type_id",
                "group_guids": [
                    "CiscoAMP_Event[3]_group_guids_0"
                ],
                "id": "CiscoAMP_Event[3]_id",
                "timestamp": "CiscoAMP_Event[3]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_Event[3]_timestamp_nanoseconds"
            },
            {
                "computer": {
                    "active": "CiscoAMP_Event[4]_computer_active",
                    "connector_guid": "CiscoAMP_Event[4]_computer_connector_guid",
                    "external_ip": "CiscoAMP_Event[4]_computer_external_ip",
                    "hostname": "CiscoAMP_Event[4]_computer_hostname",
                    "network_addresses": [
                        {
                            "ip": "CiscoAMP_Event[4]_computer_network_addresses[0]_ip",
                            "mac": "CiscoAMP_Event[4]_computer_network_addresses[0]_mac"
                        }
                    ]
                },
                "connector_guid": "CiscoAMP_Event[4]_connector_guid",
                "date": "CiscoAMP_Event[4]_date",
                "event_type": "CiscoAMP_Event[4]_event_type",
                "event_type_id": "CiscoAMP_Event[4]_event_type_id",
                "group_guids": [
                    "CiscoAMP_Event[4]_group_guids_0"
                ],
                "id": "CiscoAMP_Event[4]_id",
                "isolation": {
                    "duration": "CiscoAMP_Event[4]_isolation_duration"
                },
                "timestamp": "CiscoAMP_Event[4]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_Event[4]_timestamp_nanoseconds"
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
Fetches a list of event types. Events are identified and filtered by a unique ID.


#### Base Command

`cisco-amp-event-type-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 500. | Optional | 
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
                "description": "CiscoAMP_EventType[0]_description",
                "id": "CiscoAMP_EventType[0]_id",
                "name": "CiscoAMP_EventType[0]_name"
            },
            {
                "description": "CiscoAMP_EventType[1]_description",
                "id": "CiscoAMP_EventType[1]_id",
                "name": "CiscoAMP_EventType[1]_name"
            },
            {
                "description": "CiscoAMP_EventType[2]_description",
                "id": "CiscoAMP_EventType[2]_id",
                "name": "CiscoAMP_EventType[2]_name"
            },
            {
                "description": "CiscoAMP_EventType[3]_description",
                "id": "CiscoAMP_EventType[3]_id",
                "name": "CiscoAMP_EventType[3]_name"
            },
            {
                "description": "CiscoAMP_EventType[4]_description",
                "id": "CiscoAMP_EventType[4]_id",
                "name": "CiscoAMP_EventType[4]_name"
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
| name | Comma-separated list for name to filter by (has auto complete capabilities). | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 500. | Optional | 
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
            "guid": "CiscoAMP_FileList_guid",
            "name": "CiscoAMP_FileList_name",
            "type": "CiscoAMP_FileList_type"
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
| page_size | Number of results in a page. Maximum is 500. | Optional | 
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
            "guid": "CiscoAMP_FileListItem_guid",
            "items": [],
            "name": "CiscoAMP_FileListItem_name",
            "policies": [
                {
                    "guid": "CiscoAMP_FileListItem_policies[0]_guid",
                    "name": "CiscoAMP_FileListItem_policies[0]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[1]_guid",
                    "name": "CiscoAMP_FileListItem_policies[1]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[2]_guid",
                    "name": "CiscoAMP_FileListItem_policies[2]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[3]_guid",
                    "name": "CiscoAMP_FileListItem_policies[3]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[4]_guid",
                    "name": "CiscoAMP_FileListItem_policies[4]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[5]_guid",
                    "name": "CiscoAMP_FileListItem_policies[5]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[6]_guid",
                    "name": "CiscoAMP_FileListItem_policies[6]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[7]_guid",
                    "name": "CiscoAMP_FileListItem_policies[7]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[8]_guid",
                    "name": "CiscoAMP_FileListItem_policies[8]_name"
                },
                {
                    "guid": "CiscoAMP_FileListItem_policies[9]_guid",
                    "name": "CiscoAMP_FileListItem_policies[9]_name"
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
Creates a file list item with a given SHA-256 for a specific file list with a given file_list_guid.


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
            "sha256": "CiscoAMP_FileListItem_sha256",
            "source": "CiscoAMP_FileListItem_source"
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
Deletes a file list item with a given SHA-256 and associated to a file list with a given file_list_guid.


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
| page_size | Number of results in a page. Maximum is 500. | Optional | 
| limit | Number of total results to return. | Optional | 
| group_guid | Group's GUID. | Optional | 


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
| CiscoAMP.Group.policies.name | String | Policy name. | 
| CiscoAMP.Group.policies.description | String | Policy description. | 
| CiscoAMP.Group.policies.guid | String | Policy GUID. | 
| CiscoAMP.Group.policies.product | String | Policy operating system product. | 
| CiscoAMP.Group.policies.default | Boolean | Whether the policy is the default policy. | 
| CiscoAMP.Group.policies.serial_number | Number | Policy serial number. | 
| CiscoAMP.Group.policies.inherited | Boolean | Whether the policy is inherited. | 
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
                "description": "CiscoAMP_Group[0]_description",
                "guid": "CiscoAMP_Group[0]_guid",
                "name": "CiscoAMP_Group[0]_name",
                "source": "CiscoAMP_Group[0]_source"
            },
            {
                "description": "CiscoAMP_Group[1]_description",
                "guid": "CiscoAMP_Group[1]_guid",
                "name": "CiscoAMP_Group[1]_name",
                "source": "CiscoAMP_Group[1]_source"
            },
            {
                "description": "CiscoAMP_Group[2]_description",
                "guid": "CiscoAMP_Group[2]_guid",
                "name": "CiscoAMP_Group[2]_name",
                "source": "CiscoAMP_Group[2]_source"
            },
            {
                "description": "CiscoAMP_Group[3]_description",
                "guid": "CiscoAMP_Group[3]_guid",
                "name": "CiscoAMP_Group[3]_name",
                "source": "CiscoAMP_Group[3]_source"
            },
            {
                "ancestry": [
                    {
                        "guid": "CiscoAMP_Group[4]_ancestry[0]_guid",
                        "name": "CiscoAMP_Group[4]_ancestry[0]_name"
                    }
                ],
                "description": "CiscoAMP_Group[4]_description",
                "guid": "CiscoAMP_Group[4]_guid",
                "name": "CiscoAMP_Group[4]_name",
                "source": "CiscoAMP_Group[4]_source"
            },
            {
                "description": "CiscoAMP_Group[5]_description",
                "guid": "CiscoAMP_Group[5]_guid",
                "name": "CiscoAMP_Group[5]_name",
                "source": "CiscoAMP_Group[5]_source"
            },
            {
                "description": "CiscoAMP_Group[6]_description",
                "guid": "CiscoAMP_Group[6]_guid",
                "name": "CiscoAMP_Group[6]_name",
                "source": "CiscoAMP_Group[6]_source"
            },
            {
                "description": "CiscoAMP_Group[7]_description",
                "guid": "CiscoAMP_Group[7]_guid",
                "name": "CiscoAMP_Group[7]_name",
                "source": "CiscoAMP_Group[7]_source"
            },
            {
                "description": "CiscoAMP_Group[8]_description",
                "guid": "CiscoAMP_Group[8]_guid",
                "name": "CiscoAMP_Group[8]_name",
                "source": "CiscoAMP_Group[8]_source"
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
| group_guid | Group's GUID. | Required | 
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
| CiscoAMP.Group.policies.name | String | Policy name. | 
| CiscoAMP.Group.policies.description | String | Policy description. | 
| CiscoAMP.Group.policies.guid | String | Policy GUID. | 
| CiscoAMP.Group.policies.product | String | Policy operating system product. | 
| CiscoAMP.Group.policies.default | Boolean | Whether the policy is the default policy. | 
| CiscoAMP.Group.policies.serial_number | Number | Policy serial number. | 
| CiscoAMP.Group.policies.inherited | Boolean | Whether the policy is inherited. | 
| CiscoAMP.Group.policies.file_lists.name | String | File list name. | 
| CiscoAMP.Group.policies.file_lists.guid | String | File list GUID. | 
| CiscoAMP.Group.policies.file_lists.type | String | File list type. | 
| CiscoAMP.Group.policies.ip_lists.name | String | IP list name. | 
| CiscoAMP.Group.policies.ip_lists.guid | String | IP list GUID. | 
| CiscoAMP.Group.policies.ip_lists.type | String | IP list type. | 
| CiscoAMP.Group.policies.exclusion_sets.name | String | Exclusion set name. | 
| CiscoAMP.Group.policies.exclusion_sets.guid | String | Exclusion set GUID. | 
| CiscoAMP.Group.policies.used_in_groups.name | String | Name of the group the policy is used in. | 
| CiscoAMP.Group.policies.used_in_groups.description | String | Description of the group the policy is used in. | 
| CiscoAMP.Group.policies.used_in_groups.guid | String | GUID of the group the policy is used in. | 
| CiscoAMP.Group.policies.used_in_groups.source | String | Creation source of the group the policy is used in. | 

#### Command example
```!cisco-amp-group-policy-update group_guid=bb5a9f90-d6fa-4fe7-99c8-e91060b49a98 windows_policy_guid=91c7894d-dd69-4a21-8cf6-5ebfc57ef4df```
#### Context Example
```json
{
    "CiscoAMP": {
        "Group": {
            "child_groups": [
                {
                    "guid": "CiscoAMP_Group_child_groups[0]_guid",
                    "name": "CiscoAMP_Group_child_groups[0]_name"
                }
            ],
            "computers_count": "CiscoAMP_Group_computers_count",
            "created_at": "CiscoAMP_Group_created_at",
            "creator": "CiscoAMP_Group_creator",
            "descendant_computers_count": "CiscoAMP_Group_descendant_computers_count",
            "description": "CiscoAMP_Group_description",
            "guid": "CiscoAMP_Group_guid",
            "name": "CiscoAMP_Group_name",
            "policies": [
                {
                    "default": "CiscoAMP_Group_policies[0]_default",
                    "description": "CiscoAMP_Group_policies[0]_description",
                    "exclusion_sets": [
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[0]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[0]_name"
                        }
                    ],
                    "file_lists": [],
                    "guid": "CiscoAMP_Group_policies[0]_guid",
                    "inherited": "CiscoAMP_Group_policies[0]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[0]_name",
                    "product": "CiscoAMP_Group_policies[0]_product",
                    "serial_number": "CiscoAMP_Group_policies[0]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[0]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[0]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[0]_used_in_groups[0]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[1]_default",
                    "description": "CiscoAMP_Group_policies[1]_description",
                    "file_lists": [],
                    "guid": "CiscoAMP_Group_policies[1]_guid",
                    "inherited": "CiscoAMP_Group_policies[1]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[1]_name",
                    "product": "CiscoAMP_Group_policies[1]_product",
                    "serial_number": "CiscoAMP_Group_policies[1]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[1]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[1]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[1]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[1]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[1]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[1]_used_in_groups[1]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[2]_default",
                    "description": "CiscoAMP_Group_policies[2]_description",
                    "exclusion_sets": [
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[0]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[1]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[1]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[2]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[2]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[3]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[3]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[4]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[4]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[5]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[5]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[6]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[6]_name"
                        }
                    ],
                    "file_lists": [
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[0]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[0]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[1]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[1]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[1]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[2]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[2]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[2]_type"
                        }
                    ],
                    "guid": "CiscoAMP_Group_policies[2]_guid",
                    "inherited": "CiscoAMP_Group_policies[2]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[2]_name",
                    "product": "CiscoAMP_Group_policies[2]_product",
                    "serial_number": "CiscoAMP_Group_policies[2]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[2]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[2]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[2]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[2]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[2]_used_in_groups[1]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[3]_default",
                    "description": "CiscoAMP_Group_policies[3]_description",
                    "file_lists": [
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[0]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[0]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[0]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[1]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[1]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[1]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[2]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[2]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[2]_type"
                        }
                    ],
                    "guid": "CiscoAMP_Group_policies[3]_guid",
                    "inherited": "CiscoAMP_Group_policies[3]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[3]_name",
                    "product": "CiscoAMP_Group_policies[3]_product",
                    "serial_number": "CiscoAMP_Group_policies[3]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[3]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[3]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[3]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[3]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[3]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[3]_used_in_groups[1]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[4]_default",
                    "description": "CiscoAMP_Group_policies[4]_description",
                    "file_lists": [],
                    "guid": "CiscoAMP_Group_policies[4]_guid",
                    "inherited": "CiscoAMP_Group_policies[4]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[4]_name",
                    "product": "CiscoAMP_Group_policies[4]_product",
                    "serial_number": "CiscoAMP_Group_policies[4]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[4]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[4]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[4]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[4]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[4]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[4]_used_in_groups[1]_name"
                        }
                    ]
                }
            ],
            "source": "CiscoAMP_Group_source"
        }
    }
}
```

#### Human Readable Output

>### Group Information
>|Name|Description|Creator|Created At|Computers Count|Descendant Computers Count|
>|---|---|---|---|---|---|
>| Lior-Group | Test group | Email | 2022-10-25 13:42:36 | 1 | 0 |


### cisco-amp-group-parent-update
***
Converts an existing group to a child of another group or an existing child group to a root group (that is, one with no parent groups).


#### Base Command

`cisco-amp-group-parent-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| child_guid | Group's GUID. | Required | 
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
| CiscoAMP.Group.policies.name | String | Policy name. | 
| CiscoAMP.Group.policies.description | String | Policy description. | 
| CiscoAMP.Group.policies.guid | String | Policy GUID. | 
| CiscoAMP.Group.policies.product | String | Policy operating system product. | 
| CiscoAMP.Group.policies.default | Boolean | Whether the policy is the default policy. | 
| CiscoAMP.Group.policies.serial_number | Number | Policy serial number. | 
| CiscoAMP.Group.policies.inherited | Boolean | Whether the policy is inherited. | 
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
                    "guid": "CiscoAMP_Group_child_groups[0]_guid",
                    "name": "CiscoAMP_Group_child_groups[0]_name"
                }
            ],
            "computers_count": "CiscoAMP_Group_computers_count",
            "created_at": "CiscoAMP_Group_created_at",
            "creator": "CiscoAMP_Group_creator",
            "descendant_computers_count": "CiscoAMP_Group_descendant_computers_count",
            "description": "CiscoAMP_Group_description",
            "guid": "CiscoAMP_Group_guid",
            "name": "CiscoAMP_Group_name",
            "policies": [
                {
                    "default": "CiscoAMP_Group_policies[0]_default",
                    "description": "CiscoAMP_Group_policies[0]_description",
                    "exclusion_sets": [
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[0]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[0]_name"
                        }
                    ],
                    "file_lists": [],
                    "guid": "CiscoAMP_Group_policies[0]_guid",
                    "inherited": "CiscoAMP_Group_policies[0]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[0]_name",
                    "product": "CiscoAMP_Group_policies[0]_product",
                    "serial_number": "CiscoAMP_Group_policies[0]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[0]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[0]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[0]_used_in_groups[0]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[1]_default",
                    "description": "CiscoAMP_Group_policies[1]_description",
                    "file_lists": [],
                    "guid": "CiscoAMP_Group_policies[1]_guid",
                    "inherited": "CiscoAMP_Group_policies[1]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[1]_name",
                    "product": "CiscoAMP_Group_policies[1]_product",
                    "serial_number": "CiscoAMP_Group_policies[1]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[1]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[1]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[1]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[1]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[1]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[1]_used_in_groups[1]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[2]_default",
                    "description": "CiscoAMP_Group_policies[2]_description",
                    "exclusion_sets": [
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[0]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[1]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[1]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[2]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[2]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[3]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[3]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[4]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[4]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[5]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[5]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[6]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[6]_name"
                        }
                    ],
                    "file_lists": [
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[0]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[0]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[1]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[1]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[1]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[2]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[2]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[2]_type"
                        }
                    ],
                    "guid": "CiscoAMP_Group_policies[2]_guid",
                    "inherited": "CiscoAMP_Group_policies[2]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[2]_name",
                    "product": "CiscoAMP_Group_policies[2]_product",
                    "serial_number": "CiscoAMP_Group_policies[2]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[2]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[2]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[2]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[2]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[2]_used_in_groups[1]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[3]_default",
                    "description": "CiscoAMP_Group_policies[3]_description",
                    "file_lists": [
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[0]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[0]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[0]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[1]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[1]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[1]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[2]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[2]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[2]_type"
                        }
                    ],
                    "guid": "CiscoAMP_Group_policies[3]_guid",
                    "inherited": "CiscoAMP_Group_policies[3]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[3]_name",
                    "product": "CiscoAMP_Group_policies[3]_product",
                    "serial_number": "CiscoAMP_Group_policies[3]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[3]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[3]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[3]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[3]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[3]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[3]_used_in_groups[1]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[4]_default",
                    "description": "CiscoAMP_Group_policies[4]_description",
                    "file_lists": [],
                    "guid": "CiscoAMP_Group_policies[4]_guid",
                    "inherited": "CiscoAMP_Group_policies[4]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[4]_name",
                    "product": "CiscoAMP_Group_policies[4]_product",
                    "serial_number": "CiscoAMP_Group_policies[4]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[4]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[4]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[4]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[4]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[4]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[4]_used_in_groups[1]_name"
                        }
                    ]
                }
            ],
            "source": "CiscoAMP_Group_source"
        }
    }
}
```

#### Human Readable Output

>### Group Information
>|Name|Description|Creator|Created At|Computers Count|Descendant Computers Count|
>|---|---|---|---|---|---|
>| Lior-Group | Test group | Email | 2022-10-25 13:42:36 | 1 | 0 |


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
| CiscoAMP.Group.policies.name | String | Policy name. | 
| CiscoAMP.Group.policies.description | String | Policy description. | 
| CiscoAMP.Group.policies.guid | String | Policy GUID. | 
| CiscoAMP.Group.policies.product | String | Policy operating system product. | 
| CiscoAMP.Group.policies.default | Boolean | Whether the policy is the default policy. | 
| CiscoAMP.Group.policies.serial_number | Number | Policy serial number. | 
| CiscoAMP.Group.policies.inherited | Boolean | Whether the policy is inherited. | 
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
            "computers_count": "CiscoAMP_Group_computers_count",
            "created_at": "CiscoAMP_Group_created_at",
            "creator": "CiscoAMP_Group_creator",
            "descendant_computers_count": "CiscoAMP_Group_descendant_computers_count",
            "description": "CiscoAMP_Group_description",
            "guid": "CiscoAMP_Group_guid",
            "name": "CiscoAMP_Group_name",
            "policies": [
                {
                    "default": "CiscoAMP_Group_policies[0]_default",
                    "description": "CiscoAMP_Group_policies[0]_description",
                    "exclusion_sets": [
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[0]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[0]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[1]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[1]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[2]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[2]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[3]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[3]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[4]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[4]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[5]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[5]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[6]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[6]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[7]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[7]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[8]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[8]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[9]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[9]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[10]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[10]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[11]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[11]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[12]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[12]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[13]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[13]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[14]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[14]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[15]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[15]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[16]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[16]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[17]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[17]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_exclusion_sets[18]_guid",
                            "name": "CiscoAMP_Group_policies[0]_exclusion_sets[18]_name"
                        }
                    ],
                    "file_lists": [
                        {
                            "guid": "CiscoAMP_Group_policies[0]_file_lists[0]_guid",
                            "name": "CiscoAMP_Group_policies[0]_file_lists[0]_name",
                            "type": "CiscoAMP_Group_policies[0]_file_lists[0]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_file_lists[1]_guid",
                            "name": "CiscoAMP_Group_policies[0]_file_lists[1]_name",
                            "type": "CiscoAMP_Group_policies[0]_file_lists[1]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[0]_file_lists[2]_guid",
                            "name": "CiscoAMP_Group_policies[0]_file_lists[2]_name",
                            "type": "CiscoAMP_Group_policies[0]_file_lists[2]_type"
                        }
                    ],
                    "guid": "CiscoAMP_Group_policies[0]_guid",
                    "inherited": "CiscoAMP_Group_policies[0]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[0]_name",
                    "product": "CiscoAMP_Group_policies[0]_product",
                    "serial_number": "CiscoAMP_Group_policies[0]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[0]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[0]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[0]_used_in_groups[0]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[1]_default",
                    "description": "CiscoAMP_Group_policies[1]_description",
                    "file_lists": [],
                    "guid": "CiscoAMP_Group_policies[1]_guid",
                    "inherited": "CiscoAMP_Group_policies[1]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[1]_name",
                    "product": "CiscoAMP_Group_policies[1]_product",
                    "serial_number": "CiscoAMP_Group_policies[1]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[1]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[1]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[1]_used_in_groups[0]_name"
                        },
                        {
                            "description": "CiscoAMP_Group_policies[1]_used_in_groups[1]_description",
                            "guid": "CiscoAMP_Group_policies[1]_used_in_groups[1]_guid",
                            "name": "CiscoAMP_Group_policies[1]_used_in_groups[1]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[2]_default",
                    "description": "CiscoAMP_Group_policies[2]_description",
                    "exclusion_sets": [
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[0]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[1]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[1]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[2]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[2]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[3]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[3]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[4]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[4]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[5]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[5]_name"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_exclusion_sets[6]_guid",
                            "name": "CiscoAMP_Group_policies[2]_exclusion_sets[6]_name"
                        }
                    ],
                    "file_lists": [
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[0]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[0]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[1]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[1]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[1]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[2]_file_lists[2]_guid",
                            "name": "CiscoAMP_Group_policies[2]_file_lists[2]_name",
                            "type": "CiscoAMP_Group_policies[2]_file_lists[2]_type"
                        }
                    ],
                    "guid": "CiscoAMP_Group_policies[2]_guid",
                    "inherited": "CiscoAMP_Group_policies[2]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[2]_name",
                    "product": "CiscoAMP_Group_policies[2]_product",
                    "serial_number": "CiscoAMP_Group_policies[2]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[2]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[2]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[2]_used_in_groups[0]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[3]_default",
                    "description": "CiscoAMP_Group_policies[3]_description",
                    "file_lists": [
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[0]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[0]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[0]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[1]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[1]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[1]_type"
                        },
                        {
                            "guid": "CiscoAMP_Group_policies[3]_file_lists[2]_guid",
                            "name": "CiscoAMP_Group_policies[3]_file_lists[2]_name",
                            "type": "CiscoAMP_Group_policies[3]_file_lists[2]_type"
                        }
                    ],
                    "guid": "CiscoAMP_Group_policies[3]_guid",
                    "inherited": "CiscoAMP_Group_policies[3]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[3]_name",
                    "product": "CiscoAMP_Group_policies[3]_product",
                    "serial_number": "CiscoAMP_Group_policies[3]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[3]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[3]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[3]_used_in_groups[0]_name"
                        }
                    ]
                },
                {
                    "default": "CiscoAMP_Group_policies[4]_default",
                    "description": "CiscoAMP_Group_policies[4]_description",
                    "file_lists": [],
                    "guid": "CiscoAMP_Group_policies[4]_guid",
                    "inherited": "CiscoAMP_Group_policies[4]_inherited",
                    "ip_lists": [],
                    "isolation_ip_lists": [],
                    "name": "CiscoAMP_Group_policies[4]_name",
                    "product": "CiscoAMP_Group_policies[4]_product",
                    "serial_number": "CiscoAMP_Group_policies[4]_serial_number",
                    "used_in_groups": [
                        {
                            "description": "CiscoAMP_Group_policies[4]_used_in_groups[0]_description",
                            "guid": "CiscoAMP_Group_policies[4]_used_in_groups[0]_guid",
                            "name": "CiscoAMP_Group_policies[4]_used_in_groups[0]_name"
                        }
                    ]
                }
            ],
            "source": "CiscoAMP_Group_source"
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
Destroys a group with a given GUID.


#### Base Command

`cisco-amp-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_guid | Group's GUID. | Required | 


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
| page_size | Number of results in a page. Maximum is 500. | Optional | 
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
                "description": "CiscoAMP_Indicator[0]_description",
                "guid": "CiscoAMP_Indicator[0]_guid",
                "name": "CiscoAMP_Indicator[0]_name",
                "observed_compromises": "CiscoAMP_Indicator[0]_observed_compromises",
                "severity": "CiscoAMP_Indicator[0]_severity"
            },
            {
                "description": "CiscoAMP_Indicator[1]_description",
                "guid": "CiscoAMP_Indicator[1]_guid",
                "name": "CiscoAMP_Indicator[1]_name",
                "observed_compromises": "CiscoAMP_Indicator[1]_observed_compromises",
                "severity": "CiscoAMP_Indicator[1]_severity"
            },
            {
                "description": "CiscoAMP_Indicator[2]_description",
                "guid": "CiscoAMP_Indicator[2]_guid",
                "name": "CiscoAMP_Indicator[2]_name",
                "observed_compromises": "CiscoAMP_Indicator[2]_observed_compromises",
                "severity": "CiscoAMP_Indicator[2]_severity"
            },
            {
                "description": "CiscoAMP_Indicator[3]_description",
                "guid": "CiscoAMP_Indicator[3]_guid",
                "name": "CiscoAMP_Indicator[3]_name",
                "observed_compromises": "CiscoAMP_Indicator[3]_observed_compromises",
                "severity": "CiscoAMP_Indicator[3]_severity"
            },
            {
                "description": "CiscoAMP_Indicator[4]_description",
                "guid": "CiscoAMP_Indicator[4]_guid",
                "name": "CiscoAMP_Indicator[4]_name",
                "observed_compromises": "CiscoAMP_Indicator[4]_observed_compromises",
                "severity": "CiscoAMP_Indicator[4]_severity"
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
Gets information about policies by filtering with a product and name of a specific policy with a policy_guid.


#### Base Command

`cisco-amp-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_guid | Policy GUID. | Optional | 
| product | Comma-separated list for products to filter by. | Optional | 
| name | Comma-separated list for names to filter by (has auto complete capabilities). | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.Policy.name | String | Policy name. | 
| CiscoAMP.Policy.description | String | Policy description. | 
| CiscoAMP.Policy.guid | String | Policy GUID. | 
| CiscoAMP.Policy.product | String | Product used. | 
| CiscoAMP.Policy.default | Boolean | Whether the policy is the default policy. | 
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
                "default": "CiscoAMP_Policy[0]_default",
                "description": "CiscoAMP_Policy[0]_description",
                "guid": "CiscoAMP_Policy[0]_guid",
                "name": "CiscoAMP_Policy[0]_name",
                "product": "CiscoAMP_Policy[0]_product",
                "serial_number": "CiscoAMP_Policy[0]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[1]_default",
                "description": "CiscoAMP_Policy[1]_description",
                "guid": "CiscoAMP_Policy[1]_guid",
                "name": "CiscoAMP_Policy[1]_name",
                "product": "CiscoAMP_Policy[1]_product",
                "serial_number": "CiscoAMP_Policy[1]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[2]_default",
                "description": "CiscoAMP_Policy[2]_description",
                "guid": "CiscoAMP_Policy[2]_guid",
                "name": "CiscoAMP_Policy[2]_name",
                "product": "CiscoAMP_Policy[2]_product",
                "serial_number": "CiscoAMP_Policy[2]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[3]_default",
                "description": "CiscoAMP_Policy[3]_description",
                "guid": "CiscoAMP_Policy[3]_guid",
                "name": "CiscoAMP_Policy[3]_name",
                "product": "CiscoAMP_Policy[3]_product",
                "serial_number": "CiscoAMP_Policy[3]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[4]_default",
                "description": "CiscoAMP_Policy[4]_description",
                "guid": "CiscoAMP_Policy[4]_guid",
                "name": "CiscoAMP_Policy[4]_name",
                "product": "CiscoAMP_Policy[4]_product",
                "serial_number": "CiscoAMP_Policy[4]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[5]_default",
                "description": "CiscoAMP_Policy[5]_description",
                "guid": "CiscoAMP_Policy[5]_guid",
                "name": "CiscoAMP_Policy[5]_name",
                "product": "CiscoAMP_Policy[5]_product",
                "serial_number": "CiscoAMP_Policy[5]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[6]_default",
                "description": "CiscoAMP_Policy[6]_description",
                "guid": "CiscoAMP_Policy[6]_guid",
                "name": "CiscoAMP_Policy[6]_name",
                "product": "CiscoAMP_Policy[6]_product",
                "serial_number": "CiscoAMP_Policy[6]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[7]_default",
                "description": "CiscoAMP_Policy[7]_description",
                "guid": "CiscoAMP_Policy[7]_guid",
                "name": "CiscoAMP_Policy[7]_name",
                "product": "CiscoAMP_Policy[7]_product",
                "serial_number": "CiscoAMP_Policy[7]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[8]_default",
                "description": "CiscoAMP_Policy[8]_description",
                "guid": "CiscoAMP_Policy[8]_guid",
                "name": "CiscoAMP_Policy[8]_name",
                "product": "CiscoAMP_Policy[8]_product",
                "serial_number": "CiscoAMP_Policy[8]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[9]_default",
                "description": "CiscoAMP_Policy[9]_description",
                "guid": "CiscoAMP_Policy[9]_guid",
                "name": "CiscoAMP_Policy[9]_name",
                "product": "CiscoAMP_Policy[9]_product",
                "serial_number": "CiscoAMP_Policy[9]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[10]_default",
                "description": "CiscoAMP_Policy[10]_description",
                "guid": "CiscoAMP_Policy[10]_guid",
                "name": "CiscoAMP_Policy[10]_name",
                "product": "CiscoAMP_Policy[10]_product",
                "serial_number": "CiscoAMP_Policy[10]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[11]_default",
                "description": "CiscoAMP_Policy[11]_description",
                "guid": "CiscoAMP_Policy[11]_guid",
                "name": "CiscoAMP_Policy[11]_name",
                "product": "CiscoAMP_Policy[11]_product",
                "serial_number": "CiscoAMP_Policy[11]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[12]_default",
                "description": "CiscoAMP_Policy[12]_description",
                "guid": "CiscoAMP_Policy[12]_guid",
                "name": "CiscoAMP_Policy[12]_name",
                "product": "CiscoAMP_Policy[12]_product",
                "serial_number": "CiscoAMP_Policy[12]_serial_number"
            },
            {
                "default": "CiscoAMP_Policy[13]_default",
                "description": "CiscoAMP_Policy[13]_description",
                "guid": "CiscoAMP_Policy[13]_guid",
                "name": "CiscoAMP_Policy[13]_name",
                "product": "CiscoAMP_Policy[13]_product",
                "serial_number": "CiscoAMP_Policy[13]_serial_number"
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
| page_size | Number of results in a page. Maximum is 500. | Optional | 
| limit | Number of total results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoAMP.AppTrajectoryQuery.connector_guid | String | GUID of the connector. | 
| CiscoAMP.AppTrajectoryQuery.bundle_id | String | Bundle ID. | 
| CiscoAMP.AppTrajectoryQuery.group_guids | String | List of group's GUIDs. | 
| CiscoAMP.AppTrajectoryQuery.cdhash | String | CD hash. | 
| CiscoAMP.AppTrajectoryQuery.timestamp | Number | Observed timestamp. | 
| CiscoAMP.AppTrajectoryQuery.timestamp_nanoseconds | Number | Observed timestamp in nano seconds. | 
| CiscoAMP.AppTrajectoryQuery.date | Date | Observed date. | 
| CiscoAMP.AppTrajectoryQuery.query_type | String | The type of the query. | 
| CiscoAMP.AppTrajectoryQuery.network_info.dirty_url | String | Link to the observed URL. | 
| CiscoAMP.AppTrajectoryQuery.network_info.remote_ip | String | Remote IP. | 
| CiscoAMP.AppTrajectoryQuery.network_info.remote_port | Number | Remote port. | 
| CiscoAMP.AppTrajectoryQuery.network_info.local_ip | String | Local IP. | 
| CiscoAMP.AppTrajectoryQuery.network_info.local_port | Number | Local Port. | 
| CiscoAMP.AppTrajectoryQuery.network_info.direction | String | Outgoing or incoming connection. | 
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
                "bundle_id": "CiscoAMP_AppTrajectoryQuery[0]_bundle_id",
                "cdhash": "CiscoAMP_AppTrajectoryQuery[0]_cdhash",
                "connector_guid": "CiscoAMP_AppTrajectoryQuery[0]_connector_guid",
                "date": "CiscoAMP_AppTrajectoryQuery[0]_date",
                "group_guids": [
                    "CiscoAMP_AppTrajectoryQuery[0]_group_guids_0"
                ],
                "network_info": {
                    "direction": "CiscoAMP_AppTrajectoryQuery[0]_network_info_direction",
                    "dirty_url": "CiscoAMP_AppTrajectoryQuery[0]_network_info_dirty_url",
                    "local_ip": "CiscoAMP_AppTrajectoryQuery[0]_network_info_local_ip",
                    "local_port": "CiscoAMP_AppTrajectoryQuery[0]_network_info_local_port",
                    "protocol": "CiscoAMP_AppTrajectoryQuery[0]_network_info_protocol",
                    "remote_ip": "CiscoAMP_AppTrajectoryQuery[0]_network_info_remote_ip",
                    "remote_port": "CiscoAMP_AppTrajectoryQuery[0]_network_info_remote_port"
                },
                "query_type": "CiscoAMP_AppTrajectoryQuery[0]_query_type",
                "timestamp": "CiscoAMP_AppTrajectoryQuery[0]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_AppTrajectoryQuery[0]_timestamp_nanoseconds",
                "ver": "CiscoAMP_AppTrajectoryQuery[0]_ver"
            },
            {
                "bundle_id": "CiscoAMP_AppTrajectoryQuery[1]_bundle_id",
                "cdhash": "CiscoAMP_AppTrajectoryQuery[1]_cdhash",
                "connector_guid": "CiscoAMP_AppTrajectoryQuery[1]_connector_guid",
                "date": "CiscoAMP_AppTrajectoryQuery[1]_date",
                "group_guids": [
                    "CiscoAMP_AppTrajectoryQuery[1]_group_guids_0"
                ],
                "network_info": {
                    "direction": "CiscoAMP_AppTrajectoryQuery[1]_network_info_direction",
                    "dirty_url": "CiscoAMP_AppTrajectoryQuery[1]_network_info_dirty_url",
                    "local_ip": "CiscoAMP_AppTrajectoryQuery[1]_network_info_local_ip",
                    "local_port": "CiscoAMP_AppTrajectoryQuery[1]_network_info_local_port",
                    "protocol": "CiscoAMP_AppTrajectoryQuery[1]_network_info_protocol",
                    "remote_ip": "CiscoAMP_AppTrajectoryQuery[1]_network_info_remote_ip",
                    "remote_port": "CiscoAMP_AppTrajectoryQuery[1]_network_info_remote_port"
                },
                "query_type": "CiscoAMP_AppTrajectoryQuery[1]_query_type",
                "timestamp": "CiscoAMP_AppTrajectoryQuery[1]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_AppTrajectoryQuery[1]_timestamp_nanoseconds",
                "ver": "CiscoAMP_AppTrajectoryQuery[1]_ver"
            },
            {
                "bundle_id": "CiscoAMP_AppTrajectoryQuery[2]_bundle_id",
                "cdhash": "CiscoAMP_AppTrajectoryQuery[2]_cdhash",
                "connector_guid": "CiscoAMP_AppTrajectoryQuery[2]_connector_guid",
                "date": "CiscoAMP_AppTrajectoryQuery[2]_date",
                "group_guids": [
                    "CiscoAMP_AppTrajectoryQuery[2]_group_guids_0"
                ],
                "network_info": {
                    "direction": "CiscoAMP_AppTrajectoryQuery[2]_network_info_direction",
                    "dirty_url": "CiscoAMP_AppTrajectoryQuery[2]_network_info_dirty_url",
                    "local_ip": "CiscoAMP_AppTrajectoryQuery[2]_network_info_local_ip",
                    "local_port": "CiscoAMP_AppTrajectoryQuery[2]_network_info_local_port",
                    "protocol": "CiscoAMP_AppTrajectoryQuery[2]_network_info_protocol",
                    "remote_ip": "CiscoAMP_AppTrajectoryQuery[2]_network_info_remote_ip",
                    "remote_port": "CiscoAMP_AppTrajectoryQuery[2]_network_info_remote_port"
                },
                "query_type": "CiscoAMP_AppTrajectoryQuery[2]_query_type",
                "timestamp": "CiscoAMP_AppTrajectoryQuery[2]_timestamp",
                "timestamp_nanoseconds": "CiscoAMP_AppTrajectoryQuery[2]_timestamp_nanoseconds",
                "ver": "CiscoAMP_AppTrajectoryQuery[2]_ver"
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
            "version": "CiscoAMP_Version_version"
        }
    }
}
```

#### Human Readable Output

>Version: v1.2.0

### cisco-amp-vulnerability-list
***
Fetch a list of vulnerabilities. This is analogous to the Vulnerable Software view on the AMP for Endpoints Console. The list can be filtered to show only the vulnerable programs detected for a specific time range. Provide a list of computers on which the vulnerability has been observed with a given SHA-256. The list item contains a summary of information on the vulnerability, including: application name and version, SHA-256 value for the executable file, connectors on which the vulnerable application was observed and the most recent CVSS score. IMPORTANT: The computer's key returns information about the last 1000 connectors on which the vulnerable application was observed.


#### Base Command

`cisco-amp-vulnerability-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sha256 | SHA-256 that has been observed as a vulnerability. | Optional | 
| group_guid | Comma-separated list for group GUIDs to filter by. | Optional | 
| start_time | The start date and time expressed according to ISO 8601. The retrieved list will include vulnerable programs detected at start_time. | Optional | 
| end_time | The end date and/or time expressed according to ISO 8601. Exclusive - if end_time is a time, the list will only include vulnerable programs detected before end_time). Inclusive - if end_time is a date, the list will include vulnerable programs detected on the date. | Optional | 
| page | Page number to return. | Optional | 
| page_size | Number of results in a page. Maximum is 500. | Optional | 
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
| CiscoAMP.Vulnerability.active | Boolean | Whether the computer is active. | 
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
| CiscoAMP.Vulnerability.computers.active | Boolean | Whether the computer is active. | 

#### Command example
```!cisco-amp-vulnerability-list```
#### Context Example
```json
{
    "CiscoAMP": {
        "Vulnerability": [
            {
                "application": "CiscoAMP_Vulnerability[0]_application",
                "computers": [
                    {
                        "active": "CiscoAMP_Vulnerability[0]_computers[0]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[0]_computers[0]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[0]_computers[0]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[0]_computers[0]_windows_processor_id"
                    }
                ],
                "computers_total_count": "CiscoAMP_Vulnerability[0]_computers_total_count",
                "cves": [
                    {
                        "cvss": "CiscoAMP_Vulnerability[0]_cves[0]_cvss",
                        "id": "CiscoAMP_Vulnerability[0]_cves[0]_id",
                        "link": "CiscoAMP_Vulnerability[0]_cves[0]_link"
                    }
                ],
                "file": {
                    "filename": "CiscoAMP_Vulnerability[0]_file_filename",
                    "identity": {
                        "sha256": "CiscoAMP_Vulnerability[0]_file_identity_sha256"
                    }
                },
                "groups": [
                    {
                        "description": "CiscoAMP_Vulnerability[0]_groups[0]_description",
                        "guid": "CiscoAMP_Vulnerability[0]_groups[0]_guid",
                        "name": "CiscoAMP_Vulnerability[0]_groups[0]_name"
                    }
                ],
                "latest_date": "CiscoAMP_Vulnerability[0]_latest_date",
                "latest_timestamp": "CiscoAMP_Vulnerability[0]_latest_timestamp",
                "version": "CiscoAMP_Vulnerability[0]_version"
            },
            {
                "application": "CiscoAMP_Vulnerability[1]_application",
                "computers": [
                    {
                        "active": "CiscoAMP_Vulnerability[1]_computers[0]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[1]_computers[0]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[1]_computers[0]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[1]_computers[0]_windows_processor_id"
                    }
                ],
                "computers_total_count": "CiscoAMP_Vulnerability[1]_computers_total_count",
                "cves": [
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[0]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[0]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[0]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[1]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[1]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[1]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[2]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[2]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[2]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[3]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[3]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[3]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[4]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[4]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[4]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[5]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[5]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[5]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[6]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[6]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[6]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[7]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[7]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[7]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[8]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[8]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[8]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[9]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[9]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[9]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[10]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[10]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[10]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[11]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[11]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[11]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[12]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[12]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[12]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[13]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[13]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[13]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[14]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[14]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[14]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[15]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[15]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[15]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[16]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[16]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[16]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[17]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[17]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[17]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[18]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[18]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[18]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[19]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[19]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[19]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[20]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[20]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[20]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[21]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[21]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[21]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[22]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[22]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[22]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[23]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[23]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[23]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[24]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[24]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[24]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[25]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[25]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[25]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[26]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[26]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[26]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[27]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[27]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[27]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[28]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[28]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[28]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[29]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[29]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[29]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[30]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[30]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[30]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[31]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[31]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[31]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[32]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[32]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[32]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[33]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[33]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[33]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[34]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[34]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[34]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[35]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[35]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[35]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[36]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[36]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[36]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[37]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[37]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[37]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[38]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[38]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[38]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[39]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[39]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[39]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[40]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[40]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[40]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[41]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[41]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[41]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[42]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[42]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[42]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[43]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[43]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[43]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[44]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[44]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[44]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[45]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[45]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[45]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[46]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[46]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[46]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[47]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[47]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[47]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[48]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[48]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[48]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[49]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[49]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[49]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[50]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[50]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[50]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[51]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[51]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[51]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[52]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[52]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[52]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[53]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[53]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[53]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[54]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[54]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[54]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[55]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[55]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[55]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[56]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[56]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[56]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[57]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[57]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[57]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[58]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[58]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[58]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[59]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[59]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[59]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[60]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[60]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[60]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[1]_cves[61]_cvss",
                        "id": "CiscoAMP_Vulnerability[1]_cves[61]_id",
                        "link": "CiscoAMP_Vulnerability[1]_cves[61]_link"
                    }
                ],
                "file": {
                    "filename": "CiscoAMP_Vulnerability[1]_file_filename",
                    "identity": {
                        "sha256": "CiscoAMP_Vulnerability[1]_file_identity_sha256"
                    }
                },
                "groups": [
                    {
                        "description": "CiscoAMP_Vulnerability[1]_groups[0]_description",
                        "guid": "CiscoAMP_Vulnerability[1]_groups[0]_guid",
                        "name": "CiscoAMP_Vulnerability[1]_groups[0]_name"
                    }
                ],
                "latest_date": "CiscoAMP_Vulnerability[1]_latest_date",
                "latest_timestamp": "CiscoAMP_Vulnerability[1]_latest_timestamp",
                "version": "CiscoAMP_Vulnerability[1]_version"
            },
            {
                "application": "CiscoAMP_Vulnerability[2]_application",
                "computers": [
                    {
                        "active": "CiscoAMP_Vulnerability[2]_computers[0]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[2]_computers[0]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[2]_computers[0]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[2]_computers[0]_windows_processor_id"
                    }
                ],
                "computers_total_count": "CiscoAMP_Vulnerability[2]_computers_total_count",
                "cves": [
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[0]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[0]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[0]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[1]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[1]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[1]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[2]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[2]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[2]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[3]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[3]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[3]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[4]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[4]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[4]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[5]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[5]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[5]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[6]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[6]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[6]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[7]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[7]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[7]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[8]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[8]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[8]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[9]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[9]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[9]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[10]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[10]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[10]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[11]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[11]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[11]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[12]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[12]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[12]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[13]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[13]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[13]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[14]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[14]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[14]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[15]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[15]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[15]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[16]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[16]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[16]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[17]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[17]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[17]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[18]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[18]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[18]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[19]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[19]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[19]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[20]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[20]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[20]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[21]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[21]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[21]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[22]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[22]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[22]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[23]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[23]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[23]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[24]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[24]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[24]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[25]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[25]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[25]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[26]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[26]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[26]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[27]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[27]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[27]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[28]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[28]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[28]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[29]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[29]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[29]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[30]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[30]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[30]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[31]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[31]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[31]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[32]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[32]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[32]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[33]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[33]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[33]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[34]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[34]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[34]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[35]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[35]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[35]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[36]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[36]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[36]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[37]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[37]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[37]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[38]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[38]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[38]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[39]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[39]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[39]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[40]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[40]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[40]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[41]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[41]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[41]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[42]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[42]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[42]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[43]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[43]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[43]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[44]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[44]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[44]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[45]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[45]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[45]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[46]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[46]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[46]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[47]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[47]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[47]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[48]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[48]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[48]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[49]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[49]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[49]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[50]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[50]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[50]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[51]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[51]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[51]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[52]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[52]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[52]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[53]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[53]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[53]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[54]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[54]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[54]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[55]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[55]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[55]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[56]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[56]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[56]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[57]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[57]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[57]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[58]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[58]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[58]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[59]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[59]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[59]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[60]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[60]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[60]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[61]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[61]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[61]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[62]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[62]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[62]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[63]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[63]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[63]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[64]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[64]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[64]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[65]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[65]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[65]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[66]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[66]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[66]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[67]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[67]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[67]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[68]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[68]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[68]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[69]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[69]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[69]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[70]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[70]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[70]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[71]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[71]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[71]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[72]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[72]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[72]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[73]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[73]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[73]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[74]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[74]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[74]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[75]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[75]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[75]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[76]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[76]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[76]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[77]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[77]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[77]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[78]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[78]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[78]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[79]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[79]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[79]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[80]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[80]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[80]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[81]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[81]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[81]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[82]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[82]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[82]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[83]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[83]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[83]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[84]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[84]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[84]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[85]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[85]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[85]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[86]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[86]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[86]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[87]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[87]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[87]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[88]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[88]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[88]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[89]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[89]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[89]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[90]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[90]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[90]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[91]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[91]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[91]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[92]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[92]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[92]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[93]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[93]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[93]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[94]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[94]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[94]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[95]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[95]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[95]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[96]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[96]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[96]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[97]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[97]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[97]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[2]_cves[98]_cvss",
                        "id": "CiscoAMP_Vulnerability[2]_cves[98]_id",
                        "link": "CiscoAMP_Vulnerability[2]_cves[98]_link"
                    }
                ],
                "file": {
                    "filename": "CiscoAMP_Vulnerability[2]_file_filename",
                    "identity": {
                        "sha256": "CiscoAMP_Vulnerability[2]_file_identity_sha256"
                    }
                },
                "groups": [
                    {
                        "description": "CiscoAMP_Vulnerability[2]_groups[0]_description",
                        "guid": "CiscoAMP_Vulnerability[2]_groups[0]_guid",
                        "name": "CiscoAMP_Vulnerability[2]_groups[0]_name"
                    }
                ],
                "latest_date": "CiscoAMP_Vulnerability[2]_latest_date",
                "latest_timestamp": "CiscoAMP_Vulnerability[2]_latest_timestamp",
                "version": "CiscoAMP_Vulnerability[2]_version"
            },
            {
                "application": "CiscoAMP_Vulnerability[3]_application",
                "computers": [
                    {
                        "active": "CiscoAMP_Vulnerability[3]_computers[0]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[3]_computers[0]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[3]_computers[0]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[3]_computers[0]_windows_processor_id"
                    },
                    {
                        "active": "CiscoAMP_Vulnerability[3]_computers[1]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[3]_computers[1]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[3]_computers[1]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[3]_computers[1]_windows_processor_id"
                    }
                ],
                "computers_total_count": "CiscoAMP_Vulnerability[3]_computers_total_count",
                "cves": [
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[0]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[0]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[0]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[1]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[1]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[1]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[2]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[2]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[2]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[3]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[3]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[3]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[4]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[4]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[4]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[5]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[5]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[5]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[6]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[6]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[6]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[7]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[7]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[7]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[8]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[8]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[8]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[9]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[9]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[9]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[10]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[10]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[10]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[11]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[11]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[11]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[12]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[12]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[12]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[13]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[13]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[13]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[14]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[14]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[14]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[15]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[15]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[15]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[16]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[16]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[16]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[17]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[17]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[17]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[18]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[18]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[18]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[19]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[19]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[19]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[20]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[20]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[20]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[21]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[21]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[21]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[22]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[22]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[22]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[23]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[23]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[23]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[24]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[24]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[24]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[25]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[25]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[25]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[26]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[26]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[26]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[27]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[27]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[27]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[28]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[28]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[28]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[29]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[29]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[29]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[30]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[30]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[30]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[31]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[31]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[31]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[32]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[32]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[32]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[33]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[33]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[33]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[34]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[34]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[34]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[35]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[35]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[35]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[36]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[36]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[36]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[37]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[37]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[37]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[38]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[38]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[38]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[39]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[39]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[39]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[40]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[40]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[40]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[41]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[41]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[41]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[42]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[42]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[42]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[43]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[43]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[43]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[44]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[44]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[44]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[45]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[45]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[45]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[46]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[46]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[46]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[47]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[47]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[47]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[48]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[48]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[48]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[49]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[49]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[49]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[50]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[50]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[50]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[51]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[51]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[51]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[52]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[52]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[52]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[3]_cves[53]_cvss",
                        "id": "CiscoAMP_Vulnerability[3]_cves[53]_id",
                        "link": "CiscoAMP_Vulnerability[3]_cves[53]_link"
                    }
                ],
                "file": {
                    "filename": "CiscoAMP_Vulnerability[3]_file_filename",
                    "identity": {
                        "sha256": "CiscoAMP_Vulnerability[3]_file_identity_sha256"
                    }
                },
                "groups": [
                    {
                        "description": "CiscoAMP_Vulnerability[3]_groups[0]_description",
                        "guid": "CiscoAMP_Vulnerability[3]_groups[0]_guid",
                        "name": "CiscoAMP_Vulnerability[3]_groups[0]_name"
                    },
                    {
                        "description": "CiscoAMP_Vulnerability[3]_groups[1]_description",
                        "guid": "CiscoAMP_Vulnerability[3]_groups[1]_guid",
                        "name": "CiscoAMP_Vulnerability[3]_groups[1]_name"
                    }
                ],
                "latest_date": "CiscoAMP_Vulnerability[3]_latest_date",
                "latest_timestamp": "CiscoAMP_Vulnerability[3]_latest_timestamp",
                "version": "CiscoAMP_Vulnerability[3]_version"
            },
            {
                "application": "CiscoAMP_Vulnerability[4]_application",
                "computers": [
                    {
                        "active": "CiscoAMP_Vulnerability[4]_computers[0]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[4]_computers[0]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[4]_computers[0]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[4]_computers[0]_windows_processor_id"
                    }
                ],
                "computers_total_count": "CiscoAMP_Vulnerability[4]_computers_total_count",
                "cves": [
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[0]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[0]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[0]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[1]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[1]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[1]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[2]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[2]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[2]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[3]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[3]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[3]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[4]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[4]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[4]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[5]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[5]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[5]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[6]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[6]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[6]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[7]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[7]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[7]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[8]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[8]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[8]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[9]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[9]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[9]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[10]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[10]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[10]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[11]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[11]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[11]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[12]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[12]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[12]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[13]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[13]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[13]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[4]_cves[14]_cvss",
                        "id": "CiscoAMP_Vulnerability[4]_cves[14]_id",
                        "link": "CiscoAMP_Vulnerability[4]_cves[14]_link"
                    }
                ],
                "file": {
                    "filename": "CiscoAMP_Vulnerability[4]_file_filename",
                    "identity": {
                        "sha256": "CiscoAMP_Vulnerability[4]_file_identity_sha256"
                    }
                },
                "groups": [
                    {
                        "description": "CiscoAMP_Vulnerability[4]_groups[0]_description",
                        "guid": "CiscoAMP_Vulnerability[4]_groups[0]_guid",
                        "name": "CiscoAMP_Vulnerability[4]_groups[0]_name"
                    }
                ],
                "latest_date": "CiscoAMP_Vulnerability[4]_latest_date",
                "latest_timestamp": "CiscoAMP_Vulnerability[4]_latest_timestamp",
                "version": "CiscoAMP_Vulnerability[4]_version"
            },
            {
                "application": "CiscoAMP_Vulnerability[5]_application",
                "computers": [
                    {
                        "active": "CiscoAMP_Vulnerability[5]_computers[0]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[5]_computers[0]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[5]_computers[0]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[5]_computers[0]_windows_processor_id"
                    }
                ],
                "computers_total_count": "CiscoAMP_Vulnerability[5]_computers_total_count",
                "cves": [
                    {
                        "cvss": "CiscoAMP_Vulnerability[5]_cves[0]_cvss",
                        "id": "CiscoAMP_Vulnerability[5]_cves[0]_id",
                        "link": "CiscoAMP_Vulnerability[5]_cves[0]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[5]_cves[1]_cvss",
                        "id": "CiscoAMP_Vulnerability[5]_cves[1]_id",
                        "link": "CiscoAMP_Vulnerability[5]_cves[1]_link"
                    }
                ],
                "file": {
                    "filename": "CiscoAMP_Vulnerability[5]_file_filename",
                    "identity": {
                        "sha256": "CiscoAMP_Vulnerability[5]_file_identity_sha256"
                    }
                },
                "groups": [
                    {
                        "description": "CiscoAMP_Vulnerability[5]_groups[0]_description",
                        "guid": "CiscoAMP_Vulnerability[5]_groups[0]_guid",
                        "name": "CiscoAMP_Vulnerability[5]_groups[0]_name"
                    }
                ],
                "latest_date": "CiscoAMP_Vulnerability[5]_latest_date",
                "latest_timestamp": "CiscoAMP_Vulnerability[5]_latest_timestamp",
                "version": "CiscoAMP_Vulnerability[5]_version"
            },
            {
                "application": "CiscoAMP_Vulnerability[6]_application",
                "computers": [
                    {
                        "active": "CiscoAMP_Vulnerability[6]_computers[0]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[6]_computers[0]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[6]_computers[0]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[6]_computers[0]_windows_processor_id"
                    }
                ],
                "computers_total_count": "CiscoAMP_Vulnerability[6]_computers_total_count",
                "cves": [
                    {
                        "cvss": "CiscoAMP_Vulnerability[6]_cves[0]_cvss",
                        "id": "CiscoAMP_Vulnerability[6]_cves[0]_id",
                        "link": "CiscoAMP_Vulnerability[6]_cves[0]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[6]_cves[1]_cvss",
                        "id": "CiscoAMP_Vulnerability[6]_cves[1]_id",
                        "link": "CiscoAMP_Vulnerability[6]_cves[1]_link"
                    }
                ],
                "file": {
                    "filename": "CiscoAMP_Vulnerability[6]_file_filename",
                    "identity": {
                        "sha256": "CiscoAMP_Vulnerability[6]_file_identity_sha256"
                    }
                },
                "groups": [
                    {
                        "description": "CiscoAMP_Vulnerability[6]_groups[0]_description",
                        "guid": "CiscoAMP_Vulnerability[6]_groups[0]_guid",
                        "name": "CiscoAMP_Vulnerability[6]_groups[0]_name"
                    }
                ],
                "latest_date": "CiscoAMP_Vulnerability[6]_latest_date",
                "latest_timestamp": "CiscoAMP_Vulnerability[6]_latest_timestamp",
                "version": "CiscoAMP_Vulnerability[6]_version"
            },
            {
                "application": "CiscoAMP_Vulnerability[7]_application",
                "computers": [
                    {
                        "active": "CiscoAMP_Vulnerability[7]_computers[0]_active",
                        "connector_guid": "CiscoAMP_Vulnerability[7]_computers[0]_connector_guid",
                        "hostname": "CiscoAMP_Vulnerability[7]_computers[0]_hostname",
                        "windows_processor_id": "CiscoAMP_Vulnerability[7]_computers[0]_windows_processor_id"
                    }
                ],
                "computers_total_count": "CiscoAMP_Vulnerability[7]_computers_total_count",
                "cves": [
                    {
                        "cvss": "CiscoAMP_Vulnerability[7]_cves[0]_cvss",
                        "id": "CiscoAMP_Vulnerability[7]_cves[0]_id",
                        "link": "CiscoAMP_Vulnerability[7]_cves[0]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[7]_cves[1]_cvss",
                        "id": "CiscoAMP_Vulnerability[7]_cves[1]_id",
                        "link": "CiscoAMP_Vulnerability[7]_cves[1]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[7]_cves[2]_cvss",
                        "id": "CiscoAMP_Vulnerability[7]_cves[2]_id",
                        "link": "CiscoAMP_Vulnerability[7]_cves[2]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[7]_cves[3]_cvss",
                        "id": "CiscoAMP_Vulnerability[7]_cves[3]_id",
                        "link": "CiscoAMP_Vulnerability[7]_cves[3]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[7]_cves[4]_cvss",
                        "id": "CiscoAMP_Vulnerability[7]_cves[4]_id",
                        "link": "CiscoAMP_Vulnerability[7]_cves[4]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[7]_cves[5]_cvss",
                        "id": "CiscoAMP_Vulnerability[7]_cves[5]_id",
                        "link": "CiscoAMP_Vulnerability[7]_cves[5]_link"
                    },
                    {
                        "cvss": "CiscoAMP_Vulnerability[7]_cves[6]_cvss",
                        "id": "CiscoAMP_Vulnerability[7]_cves[6]_id",
                        "link": "CiscoAMP_Vulnerability[7]_cves[6]_link"
                    }
                ],
                "file": {
                    "filename": "CiscoAMP_Vulnerability[7]_file_filename",
                    "identity": {
                        "sha256": "CiscoAMP_Vulnerability[7]_file_identity_sha256"
                    }
                },
                "groups": [
                    {
                        "description": "CiscoAMP_Vulnerability[7]_groups[0]_description",
                        "guid": "CiscoAMP_Vulnerability[7]_groups[0]_guid",
                        "name": "CiscoAMP_Vulnerability[7]_groups[0]_name"
                    }
                ],
                "latest_date": "CiscoAMP_Vulnerability[7]_latest_date",
                "latest_timestamp": "CiscoAMP_Vulnerability[7]_latest_timestamp",
                "version": "CiscoAMP_Vulnerability[7]_version"
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
>| Adobe Acrobat Reader | IP | 2022-10-25T12:02:34+00:00 | AcroRd32.exe | 825b7b20a913f26641c012f1cb61b81d29033f142ba6c6734425de06432e4f82 |
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
| ip | The endpoint IP address. The IP argument has priority over the hostname argument. | Optional | 
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
        "Hostname": "Endpoint_Hostname",
        "ID": "Endpoint_ID",
        "IPAddress": "Endpoint_IPAddress",
        "MACAddress": "Endpoint_MACAddress",
        "OS": "Endpoint_OS",
        "OSVersion": "Endpoint_OSVersion",
        "Status": "Endpoint_Status",
        "Vendor": "Endpoint_Vendor"
    }
}
```

#### Human Readable Output

>### CiscoAMP - Endpoint Demo_AMP
>|Hostname|ID|IPAddress|MACAddress|OS|OSVersion|Status|Vendor|
>|---|---|---|---|---|---|---|---|
>| Demo_AMP | 22d4a486-1732-4f8b-9a6f-18f172fe7af0 | IP | e6:80:50:1e:e5:20 | Windows 10 | 10.0.19044.1466 | Online | CiscoAMP Response |


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
| File.Malicious.Description | String | A description of why the file was determined to be malicious. | 
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
            "Indicator": "DBotScore[0]_Indicator",
            "Reliability": "DBotScore[0]_Reliability",
            "Score": "DBotScore[0]_Score",
            "Type": "DBotScore[0]_Type",
            "Vendor": "DBotScore[0]_Vendor"
        },
        {
            "Indicator": "DBotScore[1]_Indicator",
            "Reliability": "DBotScore[1]_Reliability",
            "Score": "DBotScore[1]_Score",
            "Type": "DBotScore[1]_Type",
            "Vendor": "DBotScore[1]_Vendor"
        },
        {
            "Indicator": "DBotScore[2]_Indicator",
            "Reliability": "DBotScore[2]_Reliability",
            "Score": "DBotScore[2]_Score",
            "Type": "DBotScore[2]_Type",
            "Vendor": "DBotScore[2]_Vendor"
        },
        {
            "Indicator": "DBotScore[3]_Indicator",
            "Reliability": "DBotScore[3]_Reliability",
            "Score": "DBotScore[3]_Score",
            "Type": "DBotScore[3]_Type",
            "Vendor": "DBotScore[3]_Vendor"
        },
        {
            "Indicator": "DBotScore[4]_Indicator",
            "Reliability": "DBotScore[4]_Reliability",
            "Score": "DBotScore[4]_Score",
            "Type": "DBotScore[4]_Type",
            "Vendor": "DBotScore[4]_Vendor"
        },
        {
            "Indicator": "DBotScore[5]_Indicator",
            "Reliability": "DBotScore[5]_Reliability",
            "Score": "DBotScore[5]_Score",
            "Type": "DBotScore[5]_Type",
            "Vendor": "DBotScore[5]_Vendor"
        },
        {
            "Indicator": "DBotScore[6]_Indicator",
            "Reliability": "DBotScore[6]_Reliability",
            "Score": "DBotScore[6]_Score",
            "Type": "DBotScore[6]_Type",
            "Vendor": "DBotScore[6]_Vendor"
        }
    ],
    "File": [
        {
            "DetectionEngines": "File[0]_DetectionEngines",
            "MD5": "File[0]_MD5",
            "PositiveDetections": "File[0]_PositiveDetections",
            "SHA1": "File[0]_SHA1",
            "SHA256": "File[0]_SHA256",
            "VirusTotal": {
                "ScanID": "File[0]_VirusTotal_ScanID",
                "vtLink": "File[0]_VirusTotal_vtLink"
            }
        },
        {
            "Hashes": [
                {
                    "type": "File[1]_Hashes[0]_type",
                    "value": "File[1]_Hashes[0]_value"
                }
            ],
            "Hostname": "File[1]_Hostname",
            "Name": "File[1]_Name",
            "SHA256": "File[1]_SHA256"
        }
    ]
}
```

#### Human Readable Output

### Cisco AMP - Hash Reputation for: 4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F
>|Hashes|Hostname|Name|SHA256|
>|---|---|---|---|
>| {'type': 'SHA256', 'value': '4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F'} | Demo_AMP_Exploit_Prevention | firefox.exe | 4312CDB2EAD8FD8D2DD6D8D716F3B6E9717B3D7167A2A0495E4391312102170F |