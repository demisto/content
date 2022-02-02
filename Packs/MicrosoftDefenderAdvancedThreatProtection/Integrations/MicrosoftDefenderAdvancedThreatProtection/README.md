## Overview
---
Use the Microsoft Defender for Endpoint (previously Microsoft Defender Advanced Threat Protection (ATP)) integration for preventative protection, post-breach detection, automated investigation, and response.

## Microsoft Defender Advanced Threat Protection Playbook
---
Microsoft Defender Advanced Threat Protection Get Machine Action Status

## Use Cases
---
- Fetching incidents.
- Managing machines and performing actions on them.
- Blocking files and applications.
- Uploading and digesting threat indicators for the actions of allow, block, or alert.

## Authentication
---
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

**Note**: If you previously configured the Windows Defender ATP integration, you need to perform the authentication flow again for this integration and enter the authentication parameters you receive when configuring the integration instance.

### Required Permissions
* AdvancedQuery.Read.All - Application
* Alert.ReadWrite.All - Application
* File.Read.All - Application
* Ip.Read.All - Application
* Machine.CollectForensics - Application
* Machine.Isolate - Application
* Machine.ReadWrite.All - Application
* Machine.RestrictExecution - Application
* Machine.Scan - Application
* Machine.StopAndQuarantine - Application
* ThreatIndicators.ReadWrite.OwnedBy - Application. Please note - this permission is only used for the deprecated indicators command. If you are not using the deprecated indicators command, it is not required. 
* Url.Read.All - Application
* User.Read.All - Application
* Ti.ReadWrite (Read and write IOCs belonging to the app) - Application
* Vulnerability.Read.All - Application

## Configure Microsoft Defender for Endpoint on Cortex XSOAR
---

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Defender for Endpoint.
3. Click **Add instance** to create and configure a new integration instance.
    
    | **Parameter** | **Description** | **Example** |
    | ---------             | -----------           | -------            |
    | Name | A meaningful name for the integration instance. | XXXXX Instance Alpha |
    | Host URL | The URL to the Microsoft Defender for Endpoint server, including the scheme. | `https://api.securitycenter.windows.com` |
    | ID | The ID used to gain access to the integration. | N/A |
    | Token | A piece of data that servers use to verify for authenticity. | eea810f5-a6f6 |
    | Fetch Incidents | Whether to fetch the incidents. | N/A |
    | Incident Type | The type of incident to select. | Phishing |
    | Status to filter out alerts for fetching as incidents| The property values are, "New", "InProgress" or "Resolved". Comma-separated values supported. | New,Resolved |
    | Severity to filter out alerts for fetching as incidents | The property values are, "Informational", "Low", "Medium" and "High". Comma-separated values supported. | Medium,High |
    | Trust any Certificate (Not Secure) | When selected, certificates are not checked. | N/A |
    | Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | https://proxyserver.com |
    | First Fetch Timestamp | The first timestamp to be fetched in number, time unit format. | 12 hours, 7 days |
    | self-deployed | Use a self-deployed Azure Application. |  N/A |


4. Click **Test** to validate the URLs, token, and connection.

## Fetched Incidents Data
- id
- incidentId
- investigationId
- assignedTo
- severity
- status
- classification
- determination
- investigationState
- detectionSource
- category
- threatFamilyName
- title
- description
- alertCreationTime
- firstEventTime
- lastEventTime
- lastUpdateTime
- resolvedTime
- machineId
- computerDnsName
- aadTenantId
- relatedUser
- comments
- evidence


## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. microsoft-atp-isolate-machine
2. microsoft-atp-unisolate-machine
3. microsoft-atp-get-machines
4. microsoft-atp-get-file-related-machines
5. microsoft-atp-get-machine-details
6. microsoft-atp-run-antivirus-scan
7. microsoft-atp-list-alerts
8. microsoft-atp-update-alert
9. microsoft-atp-advanced-hunting
10. microsoft-atp-create-alert
11. microsoft-atp-get-alert-related-user
12. microsoft-atp-get-alert-related-files
13. microsoft-atp-get-alert-related-ips
14. microsoft-atp-get-alert-related-domains
15. microsoft-atp-list-machine-actions-details
16. microsoft-atp-collect-investigation-package
17. microsoft-atp-get-investigation-package-sas-uri
18. microsoft-atp-restrict-app-execution
19. microsoft-atp-remove-app-restriction
20. microsoft-atp-stop-and-quarantine-file
21. microsoft-atp-list-investigations
22. microsoft-atp-start-investigation
23. microsoft-atp-get-domain-statistics
24. microsoft-atp-get-domain-alerts
25. microsoft-atp-get-domain-machines
26. microsoft-atp-get-file-statistics
27. microsoft-atp-get-file-alerts
28. microsoft-atp-get-ip-statistics
29. microsoft-atp-get-ip-alerts
30. microsoft-atp-get-user-alerts
31. microsoft-atp-get-user-machines
32. microsoft-atp-add-remove-machine-tag
33. microsoft-atp-indicator-list (deprecated)
34. microsoft-atp-indicator-get-by-id (deprecated)
35. microsoft-atp-indicator-create-network (deprecated)
36. microsoft-atp-indicator-create-file (deprecated)
37. microsoft-atp-indicator-update (deprecated)
38. microsoft-atp-indicator-delete (deprecated)
39. microsoft-atp-sc-indicator-list
40. microsoft-atp-sc-indicator-get-by-id
41. microsoft-atp-sc-indicator-create
42. microsoft-atp-sc-indicator-update
43. microsoft-atp-sc-indicator-delete
44. microsoft-atp-list-machines-by-vulnerability
45. microsoft-atp-get-file-info
46. endpoint
47. microsoft-atp-indicator-batch-update

### 1. microsoft-atp-isolate-machine
---
Isolates a machine from accessing external network.

##### Required Permissions
Machine.Isolate	

##### Base Command

`microsoft-atp-isolate-machine`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | A comma-separated list of machine IDs to be used for isolation. e.g., 0a3250e0693a109f1affc9217be9459028aa8426,0a3250e0693a109f1affc9217be9459028aa8424. | Required | 
| comment | A comment to associate with the action. | Required | 
| isolation_type | Full isolation or Selective isolation. (Restrict only limited set of applications from accessing the network). Possible values are: Full, Selective. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The machine action ID. | 
| MicrosoftATP.MachineAction.Type | String | Type of the machine action. | 
| MicrosoftATP.MachineAction.Scope | Unknown | Scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | Comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name on which the action was executed. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier. Possible values: "SHA1" ,"SHA256", and "MD5". | 

##### Command example
```!microsoft-atp-isolate-machine comment=isolate_test_3 isolation_type=Full machine_id="12342c13fef,12342c13fef8f06606"```
##### Context Example
```json
{
    "MicrosoftATP": {
        "MachineAction": [
            {
                "ComputerDNSName": "desktop-s2455r8",
                "CreationDateTimeUtc": "2022-01-25T14:25:52.6227941Z",
                "ID": "1f3098e20464",
                "LastUpdateTimeUtc": null,
                "MachineID": "12342c13fef",
                "RelatedFileInfo": {
                    "FileIdentifier": null,
                    "FileIdentifierType": null
                },
                "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4",
                "RequestorComment": "isolate_test_3",
                "Scope": "Full",
                "Status": "Pending",
                "Type": "Isolate"
            },
            {
                "ComputerDNSName": "desktop-s2455r9",
                "CreationDateTimeUtc": "2022-01-25T14:25:53.2395007Z",
                "ID": "6d39a3da0744",
                "LastUpdateTimeUtc": null,
                "MachineID": "12342c13fef8f06606",
                "RelatedFileInfo": {
                    "FileIdentifier": null,
                    "FileIdentifierType": null
                },
                "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4",
                "RequestorComment": "isolate_test_3",
                "Scope": "Full",
                "Status": "Pending",
                "Type": "Isolate"
            }
        ]
    }
}
```

##### Human Readable Output

>##### The isolation request has been submitted successfully:
>|ID|Type|Requestor|RequestorComment|Status|MachineID|ComputerDNSName|
>|---|---|---|---|---|---|---|
>| 1f3098e20464 | Isolate | 2f48b784-5da5-4e61-9957-012d2630f1e4 | isolate_test_3 | Pending | 12342c13fef | desktop-s2455r8 |
>| 6d39a3da0744 | Isolate | 2f48b784-5da5-4e61-9957-012d2630f1e4 | isolate_test_3 | Pending | 12342c13fef8f06606 | desktop-s2455r9 |


### 2. microsoft-atp-unisolate-machine
---
Remove a machine from isolation.

##### Required Permissions
Machine.Isolate	

##### Base Command

`microsoft-atp-unisolate-machine`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | A comma-separated list of machine IDs to be used to stop the isolation. e.g., 0a3250e0693a109f1affc9217be9459028aa8426,0a3250e0693a109f1affc9217be9459028aa8424. | Required | 
| comment | Comment to associate with the action. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The machine action ID. | 
| MicrosoftATP.MachineAction.Type | String | Type of the action. | 
| MicrosoftATP.MachineAction.Scope | Unknown | Scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name on which the action was executed | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The fileIdentifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier. Possible values: "SHA1" ,"SHA256", and "MD5". | 

##### Command example
```!microsoft-atp-unisolate-machine comment=unisolate_test machine_id="4899036531e3,f70f9fe6b29"```
##### Context Example
```json
{
    "MicrosoftATP": {
        "MachineAction": [
            {
                "ComputerDNSName": "desktop-s2455r8",
                "CreationDateTimeUtc": "2022-01-25T14:23:01.3053556Z",
                "ID": "488176cc",
                "LastUpdateTimeUtc": null,
                "MachineID": "4899036531e3",
                "RelatedFileInfo": {
                    "FileIdentifier": null,
                    "FileIdentifierType": null
                },
                "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4",
                "RequestorComment": "unisolate_test",
                "Scope": null,
                "Status": "Pending",
                "Type": "Unisolate"
            },
            {
                "ComputerDNSName": "desktop-s2455r9",
                "CreationDateTimeUtc": "2022-01-25T14:23:01.8421701Z",
                "ID": "a6422c40",
                "LastUpdateTimeUtc": null,
                "MachineID": "f70f9fe6b29",
                "RelatedFileInfo": {
                    "FileIdentifier": null,
                    "FileIdentifierType": null
                },
                "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4",
                "RequestorComment": "unisolate_test",
                "Scope": null,
                "Status": "Pending",
                "Type": "Unisolate"
            }
        ]
    }
}
```

##### Human Readable Output

>### The request to stop the isolation has been submitted successfully:
>|ID|Type|Requestor|RequestorComment|Status|MachineID|ComputerDNSName|
>|---|---|---|---|---|---|---|
>| 488176cc | Unisolate | 2f48b784-5da5-4e61-9957-012d2630f1e4 | unisolate_test | Pending | 4899036531e3 | desktop-s2455r8 |
>| a6422c40 | Unisolate | 2f48b784-5da5-4e61-9957-012d2630f1e4 | unisolate_test | Pending | f70f9fe6b29 | desktop-s2455r9 |


### 3. microsoft-atp-get-machines
***
Retrieves a collection of machines that have communicated with WDATP cloud in the last 30 days. Note, only one of ip and hostname can be a comma separeted list. If both given as lists, an error will appear.


#### Base Command

`microsoft-atp-get-machines`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | A comma-separated list of computer DNS name. | Optional | 
| ip | A comma-separated list of the last machine IP to access the internet. | Optional | 
| risk_score | The machine risk score. Possible values: "Low", "Medium", and "High". Possible values are: Low, Medium, High. | Optional | 
| health_status | The machine health status. Possible values: "Active" and "Inactive". Possible values are: Active, Inactive. | Optional | 
| os_platform | The machine's OS platform. Only a single platform can be added. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Machine.ID | String | The machine ID. | 
| MicrosoftATP.Machine.ComputerDNSName | String | The machine DNS name. | 
| MicrosoftATP.Machine.FirstSeen | Date | The first date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.LastSeen | Date | The last date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.Machine.OSVersion | String | The operating system version. | 
| MicrosoftATP.Machine.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.Machine.LastIPAddress | String | The last IP on the machine. | 
| MicrosoftATP.Machine.LastExternalIPAddress | String | The last machine IP to access the internet. | 
| MicrosoftATP.Machine.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.Machine.HealthStatus | String | The machine health status. | 
| MicrosoftATP.Machine.RBACGroupID | Number | The machine RBAC group ID. | 
| MicrosoftATP.Machine.RBACGroupName | String | The machine RBAC group name. | 
| MicrosoftATP.Machine.RiskScore | String | The machine risk score. | 
| MicrosoftATP.Machine.ExposureLevel | String | The machine exposure score. | 
| MicrosoftATP.Machine.IsAADJoined | Boolean | True if machine is AAD joined, False otherwise. | 
| MicrosoftATP.Machine.AADDeviceID | String | The AAD Device ID. | 
| MicrosoftATP.Machine.MachineTags | String | Set of machine tags. | 

#### Command example
```!microsoft-atp-get-machines hostname=desktop-s health_status=Active os_platform=Windows10 ip=1.2.3.4,1.2.3.5```
#### Context Example
```json
{
    "MicrosoftATP": {
        "Machine": {
            "AgentVersion": "10.8040.19041.1466",
            "ComputerDNSName": "desktop-s",
            "ExposureLevel": "Medium",
            "FirstSeen": "2020-02-20T14:44:11.4627779Z",
            "HealthStatus": "Active",
            "ID": "f70f9fe6b29",
            "IPAddresses": [
                {
                    "ipAddress": "1.2.3.4",
                    "macAddress": "1213123",
                    "operationalStatus": "Up",
                    "type": "Ethernet"
                },
                {
                    "ipAddress": "1234::1234:1234:1234:1234",
                    "macAddress": "1213123",
                    "operationalStatus": "Up",
                    "type": "Ethernet"
                },
                {
                    "ipAddress": "127.0.0.1",
                    "macAddress": "",
                    "operationalStatus": "Up",
                    "type": "SoftwareLoopback"
                },
                {
                    "ipAddress": "::1",
                    "macAddress": "",
                    "operationalStatus": "Up",
                    "type": "SoftwareLoopback"
                }
            ],
            "IsAADJoined": true,
            "LastExternalIPAddress": "127.0.0.1",
            "LastIPAddress": "1.2.3.4",
            "LastSeen": "2022-01-26T11:14:22.9649216Z",
            "MachineTags": [
                "new test",
                "test add tag",
                "testing123"
            ],
            "OSBuild": 19042,
            "OSPlatform": "Windows10",
            "OSProcessor": "x64",
            "OSVersion": "20H2",
            "RBACGroupID": 0,
            "RiskScore": "Medium"
        }
    }
}
```

#### Human Readable Output

>### Microsoft Defender ATP Machines:
>|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|
>|---|---|---|---|---|---|---|---|
>| f70f9fe6b29 | desktop-s | Windows10 | 1.2.3.4 | 127.0.0.1 | Active | Medium | Medium |


### 4. microsoft-atp-get-file-related-machines
---
Gets a collection of machines related to a given file's SHA1 hash.

##### Required Permissions
Machine.ReadWrite.All

#### Base Command

`microsoft-atp-get-file-related-machines`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | A comma-separated list of file SHA1 hash to get the related machines. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.FileMachine.Machines.ID | String | The machine ID. | 
| MicrosoftATP.FileMachine.Machines.ComputerDNSName | String | The machine DNS name. | 
| MicrosoftATP.FileMachine.Machines.FirstSeen | Date | The first date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.FileMachine.Machines.LastSeen | Date | The last date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.FileMachine.Machines.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.FileMachine.Machines.OSVersion | String | The operating system version. | 
| MicrosoftATP.Machine.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.FileMachine.Machines.OSBuild | Number | Operating system build number. | 
| MicrosoftATP.FileMachine.Machines.LastIPAddress | String | The last IP on the machine. | 
| MicrosoftATP.FileMachine.Machines.LastExternalIPAddress | String | The last machine IP to access the internet. | 
| MicrosoftATP.FileMachine.Machines.HelathStatus | String | The machine health status. | 
| MicrosoftATP.FileMachine.Machines.RBACGroupID | Number | The machine RBAC group ID. | 
| MicrosoftATP.FileMachine.Machines.RBACGroupName | String | The machine RBAC group name. | 
| MicrosoftATP.FileMachine.Machines.RiskScore | String | The machine risk score. | 
| MicrosoftATP.FileMachine.Machines.ExposureLevel | String | The machine exposure score. | 
| MicrosoftATP.FileMachine.Machines.IsAADJoined | Boolean | True if machine is AAD joined, False otherwise. | 
| MicrosoftATP.FileMachine.Machines.AADDeviceID | string | The AAD Device ID. | 
| MicrosoftATP.FileMachine.Machines.MachineTags | String | Set of machine tags. | 
| MicrosoftATP.FileMachine.File | String | The machine related file hash. | 

#### Command example
```!microsoft-atp-get-file-related-machines file_hash=1234567891acvgfdertukthgfdertyjhgfdset54,1234567891acvgfdertukthgfdertyjhgfdset53```
#### Context Example
```json
{
    "MicrosoftATP": {
        "FileMachine": [
            {
                "File": "1234567891acvgfdertukthgfdertyjhgfdset54",
                "Machines": [
                    {
                        "AgentVersion": "10.8040.19041.1466",
                        "ComputerDNSName": "desktop-s9",
                        "ExposureLevel": "Medium",
                        "FirstSeen": "2020-02-20T14:44:11.4627779Z",
                        "HealthStatus": "Active",
                        "ID": "f70f9fe6",
                        "IPAddresses": [
                            {
                                "ipAddress": "1.2.3.4",
                                "macAddress": "123456789121",
                                "operationalStatus": "Up",
                                "type": "Ethernet"
                            },
                            {
                                "ipAddress": "1234::1234:1234:3177:11dc",
                                "macAddress": "123456789121",
                                "operationalStatus": "Up",
                                "type": "Ethernet"
                            },
                            {
                                "ipAddress": "127.0.0.1",
                                "macAddress": "",
                                "operationalStatus": "Up",
                                "type": "SoftwareLoopback"
                            },
                            {
                                "ipAddress": "::1",
                                "macAddress": "",
                                "operationalStatus": "Up",
                                "type": "SoftwareLoopback"
                            }
                        ],
                        "IsAADJoined": true,
                        "LastExternalIPAddress": "127.0.0.1",
                        "LastIPAddress": "1.2.3.4",
                        "LastSeen": "2022-01-25T11:14:39.7435843Z",
                        "MachineTags": [
                            "new test",
                            "test add tag",
                            "testing123"
                        ],
                        "OSBuild": 19042,
                        "OSPlatform": "Windows10",
                        "OSProcessor": "x64",
                        "OSVersion": "20H2",
                        "RBACGroupID": 0,
                        "RiskScore": "Medium"
                    }
                ]
            },
            {
                "File": "1234567891acvgfdertukthgfdertyjhgfdset53",
                "Machines": [
                    {
                        "AADDeviceID": "cfcf4177-227e-4cdb-ac8e-f9a3da1ca30c",
                        "AgentVersion": "10.8040.19041.1466",
                        "ComputerDNSName": "desktop-s8",
                        "ExposureLevel": "Medium",
                        "FirstSeen": "2020-02-17T08:30:07.2415577Z",
                        "HealthStatus": "Active",
                        "ID": "48990365",
                        "IPAddresses": [
                            {
                                "ipAddress": "1.2.3.5",
                                "macAddress": "005056941386",
                                "operationalStatus": "Up",
                                "type": "Ethernet"
                            },
                            {
                                "ipAddress": "123::1234:dd40:bc6e:23e1",
                                "macAddress": "123456789123",
                                "operationalStatus": "Up",
                                "type": "Ethernet"
                            },
                            {
                                "ipAddress": "127.0.0.1",
                                "macAddress": "",
                                "operationalStatus": "Up",
                                "type": "SoftwareLoopback"
                            },
                            {
                                "ipAddress": "::1",
                                "macAddress": "",
                                "operationalStatus": "Up",
                                "type": "SoftwareLoopback"
                            }
                        ],
                        "IsAADJoined": true,
                        "LastExternalIPAddress": "127.0.0.1",
                        "LastIPAddress": "1.2.3.5",
                        "LastSeen": "2022-01-25T11:19:44.718919Z",
                        "MachineTags": [
                            "test Tag 2",
                            "test Tag 5"
                        ],
                        "OSBuild": 19043,
                        "OSPlatform": "Windows10",
                        "OSProcessor": "x64",
                        "OSVersion": "21H1",
                        "RBACGroupID": 0,
                        "RiskScore": "Low"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft Defender ATP machines related to files ['1234567891acvgfdertukthgfdertyjhgfdset54', '1234567891acvgfdertukthgfdertyjhgfdset53']
>|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|
>|---|---|---|---|---|---|---|---|
>| f70f9fe6 | desktop-s9 | Windows10 | 1.2.3.4 | 127.0.0.1 | Active | Medium | Medium |
>| 48990365 | desktop-s8 | Windows10 | 1.2.3.5 | 127.0.0.1 | Active | Low | Medium |


### 5. microsoft-atp-get-machine-details
---
Gets a machine's details by its identity.

##### Required Permissions
Machine.ReadWrite.All

#### Base Command

`microsoft-atp-get-machine-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | A comma-separated list of machine IDs to be used for getting the machine details, e.g., 0a3250e0693a109f1affc9217be9459028aa8426,0a3250e0693a109f1affc9217be9459028aa8424. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Machine.ID | String | The machine ID. | 
| MicrosoftATP.Machine.ComputerDNSName | String | The machine DNS name. | 
| MicrosoftATP.Machine.FirstSeen | Date | The first date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.LastSeen | Date | The last date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.Machine.OSVersion | String | The operating system version. | 
| MicrosoftATP.Machine.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.Machine.LastIPAddress | String | The last IP on the machine. | 
| MicrosoftATP.Machine.LastExternalIPAddress | String | The last machine IP to access the internet. | 
| MicrosoftATP.Machine.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.Machine.HealthStatus | String | The machine health status. | 
| MicrosoftATP.Machine.RBACGroupID | Number | The machine RBAC group ID. | 
| MicrosoftATP.Machine.RBACGroupName | String | The machine RBAC group name. | 
| MicrosoftATP.Machine.RiskScore | String | The machine risk score. | 
| MicrosoftATP.Machine.ExposureLevel | String | The machine exposure level. | 
| MicrosoftATP.Machine.IsAADJoined | Boolean | True if machine is AAD joined, False otherwise. | 
| MicrosoftATP.Machine.AADDeviceID | String | The AAD Device ID. | 
| MicrosoftATP.Machine.MachineTags | String | Set of machine tags. | 
| MicrosoftATP.Machine.NetworkInterfaces.MACAddress | String | MAC Address for the Network interface | 
| MicrosoftATP.Machine.NetworkInterfaces.IPAddresses | String | IP Address\(es\) for the Network interface | 
| MicrosoftATP.Machine.NetworkInterfaces.Type | String | Type of the Network interface \(e.g. Ethernet\) | 
| MicrosoftATP.Machine.NetworkInterfaces.Status | String | Status for the Network interface \(e.g. Up, Down\) | 

#### Command example
```!microsoft-atp-get-machine-details machine_id=f70f9fe6b29,4899036531e```
#### Context Example
```json
{
    "MicrosoftATP": {
        "Machine": [
            {
                "AgentVersion": "10.8040.19041.1466",
                "ComputerDNSName": "desktop-s9",
                "ExposureLevel": "Medium",
                "FirstSeen": "2020-02-20T14:44:11.4627779Z",
                "HealthStatus": "Active",
                "ID": "f70f9fe6",
                "IPAddresses": [
                    {
                        "ipAddress": "1.2.3.4",
                        "macAddress": "1234645645",
                        "operationalStatus": "Up",
                        "type": "Ethernet"
                    },
                    {
                        "ipAddress": "1234::1234:1234:3177:11dc",
                        "macAddress": "1234645645",
                        "operationalStatus": "Up",
                        "type": "Ethernet"
                    },
                    {
                        "ipAddress": "127.0.0.1",
                        "macAddress": "",
                        "operationalStatus": "Up",
                        "type": "SoftwareLoopback"
                    },
                    {
                        "ipAddress": "::1",
                        "macAddress": "",
                        "operationalStatus": "Up",
                        "type": "SoftwareLoopback"
                    }
                ],
                "IsAADJoined": true,
                "LastExternalIPAddress": "127.0.0.1",
                "LastIPAddress": "1.2.3.4",
                "LastSeen": "2022-01-25T11:14:39.7435843Z",
                "MachineTags": [
                    "new test",
                    "test add tag",
                    "testing123"
                ],
                "OSBuild": 19042,
                "OSPlatform": "Windows10",
                "OSProcessor": "x64",
                "OSVersion": "20H2",
                "RBACGroupID": 0,
                "RiskScore": "Medium"
            },
            {
                "AADDeviceID": "cfcf4177-227e-4cdb-ac8e-f9a3da1ca30c",
                "AgentVersion": "10.8040.19041.1466",
                "ComputerDNSName": "desktop-s8",
                "ExposureLevel": "Medium",
                "FirstSeen": "2020-02-17T08:30:07.2415577Z",
                "HealthStatus": "Active",
                "ID": "48990365",
                "IPAddresses": [
                    {
                        "ipAddress": "1.2.3.5",
                        "macAddress": "1234645645",
                        "operationalStatus": "Up",
                        "type": "Ethernet"
                    },
                    {
                        "ipAddress": "1234::1234:1234:bc6e:23e1",
                        "macAddress": "1234645645",
                        "operationalStatus": "Up",
                        "type": "Ethernet"
                    },
                    {
                        "ipAddress": "127.0.0.1",
                        "macAddress": "",
                        "operationalStatus": "Up",
                        "type": "SoftwareLoopback"
                    },
                    {
                        "ipAddress": "::1",
                        "macAddress": "",
                        "operationalStatus": "Up",
                        "type": "SoftwareLoopback"
                    }
                ],
                "IsAADJoined": true,
                "LastExternalIPAddress": "127.0.0.1",
                "LastIPAddress": "1.2.3.5",
                "LastSeen": "2022-01-25T11:19:44.718919Z",
                "MachineTags": [
                    "test Tag 2",
                    "test Tag 5"
                ],
                "OSBuild": 19043,
                "OSPlatform": "Windows10",
                "OSProcessor": "x64",
                "OSVersion": "21H1",
                "RBACGroupID": 0,
                "RiskScore": "Low"
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft Defender ATP machines ['f70f9fe6b29','4899036531e'] details:
>|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|IPAddresses|
>|---|---|---|---|---|---|---|---|---|
>| f70f9fe6 | desktop-s9 | Windows10 | 1.2.3.4 | 127.0.0.1 | Active | Medium | Medium | 1. \| MAC : 1234645645 \| IP Addresses : 1.2.3.4,1234::1234:1234:3177:11dc \| Type : Ethernet         \| Status : Up<br/>2. \| MAC :              \| IP Addresses : 127.0.0.1,::1                          \| Type : SoftwareLoopback \| Status : Up |
>| 48990365 | desktop-s8 | Windows10 | 1.2.3.5 | 127.0.0.1 | Active | Low | Medium | 1. \| MAC : 1234645645 \| IP Addresses : 1.2.3.5,1234::1234:1234:bc6e:23e1 \| Type : Ethernet         \| Status : Up<br/>2. \| MAC :              \| IP Addresses : 127.0.0.1,::1                          \| Type : SoftwareLoopback \| Status : Up |


### 6. microsoft-atp-run-antivirus-scan
---
Initiates Microsoft Defender Antivirus scan on a machine.

##### Required Permissions
Machine.Scan	

#### Base Command

`microsoft-atp-run-antivirus-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | A comma-separated list of machine IDs to run the scan on. | Required | 
| comment | A comment to associate with the action. | Required | 
| scan_type | Defines the type of the scan. Possible values: "Quick" and "Full". Possible values are: Quick, Full. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The machine action ID. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | Unknown | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name on which the action was executed. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier. Possible values: "SHA1" ,"SHA256", and "MD5". | 

#### Command example
```!microsoft-atp-run-antivirus-scan machine_id=f70f9fe6,48990365 comment=test3 scan_type=Quick```
#### Context Example
```json
{
    "MicrosoftATP": {
        "MachineAction": [
            {
                "ComputerDNSName": "desktop-s9",
                "CreationDateTimeUtc": "2022-01-25T17:57:18.7944822Z",
                "ID": "98cf0adc",
                "LastUpdateTimeUtc": null,
                "MachineID": "f70f9fe6",
                "RelatedFileInfo": {
                    "FileIdentifier": null,
                    "FileIdentifierType": null
                },
                "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4",
                "RequestorComment": "test3",
                "Scope": "Quick",
                "Status": "Pending",
                "Type": "RunAntiVirusScan"
            },
            {
                "ComputerDNSName": "desktop-s8",
                "CreationDateTimeUtc": "2022-01-25T17:57:20.0458595Z",
                "ID": "ecee8124",
                "LastUpdateTimeUtc": null,
                "MachineID": "48990365",
                "RelatedFileInfo": {
                    "FileIdentifier": null,
                    "FileIdentifierType": null
                },
                "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4",
                "RequestorComment": "test3",
                "Scope": "Quick",
                "Status": "Pending",
                "Type": "RunAntiVirusScan"
            }
        ]
    }
}
```

#### Human Readable Output

>### Antivirus scan successfully triggered
>|ID|Type|Requestor|RequestorComment|Status|MachineID|ComputerDNSName|
>|---|---|---|---|---|---|---|
>| 98cf0adc | RunAntiVirusScan | 2f48b784-5da5-4e61-9957-012d2630f1e4 | test3 | Pending | f70f9fe6 | desktop-s9 |
>| ecee8124 | RunAntiVirusScan | 2f48b784-5da5-4e61-9957-012d2630f1e4 | test3 | Pending | 48990365 | desktop-s8 |


### 7. microsoft-atp-list-alerts
---
Gets a list of alerts that are present on the system. Filtering can be done on a single argument only.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-list-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | The alert's severity. Possible values: "High", "Medium", "Low", and "Informational". | Optional | 
| status | The alert's status. Possible values: "New", "InProgress", and "Resolved". | Optional | 
| category | The alert's category, only one can be added. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Alert.ID | String | The ID of the alert. | 
| MicrosoftATP.Alert.IncidentID | Number | The incident ID of the alert. | 
| MicrosoftATP.Alert.InvestigationID | Number | The investigation ID related to the alert. | 
| MicrosoftATP.Alert.InvestigationState | String | The current state of the investigation. | 
| MicrosoftATP.Alert.AssignedTo | String | The owner of the alert. | 
| MicrosoftATP.Alert.Severity | String | The severity of the alert. | 
| MicrosoftATP.Alert.Status | String | The current status of the alert. | 
| MicrosoftATP.Alert.Classification | String | The classification of the alert. | 
| MicrosoftATP.Alert.Determination | String | The determination of the alert. | 
| MicrosoftATP.Alert.DetectionSource | String | The detection source. | 
| MicrosoftATP.Alert.Category | String | The category of the alert. | 
| MicrosoftATP.Alert.ThreatFamilyName | String | The threat family of the alert. | 
| MicrosoftATP.Alert.Title | String | The title of the alert. | 
| MicrosoftATP.Alert.Description | String | The description of the alert. | 
| MicrosoftATP.Alert.AlertCreationTime | Date | The date and time the alert was created. | 
| MicrosoftATP.Alert.FirstEventTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.LastEventTime | Date | The last event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.LastUpdateTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.ResolvedTime | Date | The date and time in which the status of the alert was changed to "Resolved". | 
| MicrosoftATP.Alert.MachineID | String | The machine's ID that is associated with the alert. | 
| MicrosoftATP.Alert.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.Alert.AADTenantID | String | The AAD tenant ID. | 
| MicrosoftATP.Alert.Comments.Comment | String | The alert comment string. | 
| MicrosoftATP.Alert.Comments.CreatedBy | String | The alert comment created by the string. | 
| MicrosoftATP.Alert.Comments.CreatedTime | Date | The time and date yje alert comment was created. | 


##### Command Example
```!microsoft-atp-list-alerts severity=Low```

##### Context Example
```
{
    "MicrosoftATP.Alert": [
        {
            "Category": "Backdoor", 
            "ThreatFamilyName": null, 
            "Severity": "Low", 
            "LastEventTime": "2020-02-19T10:31:22.7894742Z", 
            "FirstEventTime": "2020-02-19T10:31:22.7894742Z", 
            "Comments": [
                {
                    "Comment": null, 
                    "CreatedTime": null, 
                    "CreatedBy": null
                }
            ], 
            "AADTenantID": "TENANT-ID", 
            "AlertCreationTime": "2020-03-17T11:35:16.8861429Z", 
            "Status": "InProgress", 
            "Description": "testing", 
            "InvestigationState": "PendingApproval", 
            "MachineID": "4899036531e374137f63289c3267bad772c13fef", 
            "Title": "testing", 
            "InvestigationID": 10, 
            "Determination": null, 
            "IncidentID": 14, 
            "AssignedTo": "Automation", 
            "DetectionSource": "CustomerTI", 
            "ResolvedTime": null, 
            "ID": "da637200417169017725_183736971", 
            "LastUpdateTime": "2020-03-23T10:00:16.8633333Z", 
            "Classification": null, 
            "ComputerDNSName": "desktop-s2455r8", 
            "Evidence": []
        }, 
        {
            "Category": "Backdoor", 
            "ThreatFamilyName": null, 
            "Severity": "Low", 
            "LastEventTime": "2020-02-23T07:22:07.1532018Z", 
            "FirstEventTime": "2020-02-23T07:22:07.1532018Z", 
            "Comments": [
                {
                    "Comment": null, 
                    "CreatedTime": null, 
                    "CreatedBy": null
                }
            ], 
            "AADTenantID": "TENANT-ID", 
            "AlertCreationTime": "2020-03-22T15:44:23.5446957Z", 
            "Status": "New", 
            "Description": "test", 
            "InvestigationState": "PendingApproval", 
            "MachineID": "4899036531e374137f63289c3267bad772c13fef", 
            "Title": "testing alert", 
            "InvestigationID": 10, 
            "Determination": null, 
            "IncidentID": 18, 
            "AssignedTo": null, 
            "DetectionSource": "CustomerTI", 
            "ResolvedTime": null, 
            "ID": "da637204886635759335_1480542752", 
            "LastUpdateTime": "2020-03-22T15:44:24.6533333Z", 
            "Classification": null, 
            "ComputerDNSName": "desktop-s2455r8", 
            "Evidence": []
        }
    ]
}
```

##### Human Readable Output
##### Microsoft Defender ATP alerts:
|ID|Title|Description|IncidentID|Severity|Status|Category|MachineID|
|---|---|---|---|---|---|---|---|
| da637200417169017725_183736971 | testing | testing | 14 | Low | InProgress | Backdoor | 4899036531e374137f63289c3267bad772c13fef |
| da637204886635759335_1480542752 | testing alert | test | 18 | Low | New | Backdoor | 4899036531e374137f63289c3267bad772c13fef |


### 8. microsoft-atp-update-alert
---
Updates the properties of an alert entity.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-update-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID to update. | Required | 
| status | The alert status to update. Possible values: "New", "InProgress", and "Resolved". | Optional | 
| assigned_to | The owner of the alert. | Optional | 
| classification | Specifies the specification of the alert. Possible values: "Unknown", "FalsePositive", "TruePositive". | Optional | 
| determination | Specifies the determination of the alert. Possible values: "NotAvailable", "Apt", "Malware", "SecurityPersonnel", "SecurityTesting", Unwan"tedSoftware, and "Other". | Optional | 
| comment | The comment to be added to the alert. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Alert.ID | String | The ID of the alert. | 
| MicrosoftATP.Alert.IncidentID | Number | The incident ID of the alert. | 
| MicrosoftATP.Alert.InvestigationID | Number | The investigation ID related to the alert. | 
| MicrosoftATP.Alert.InvestigationState | String | The current state of the investigation. | 
| MicrosoftATP.Alert.AssignedTo | String | The owner of the alert. | 
| MicrosoftATP.Alert.Severity | String | The severity of the alert. | 
| MicrosoftATP.Alert.Status | String | The current status of the alert. | 
| MicrosoftATP.Alert.Classification | String | The alert classification. | 
| MicrosoftATP.Alert.Determination | String | The determination of the alert. | 
| MicrosoftATP.Alert.DetectionSource | String | The detection source. | 
| MicrosoftATP.Alert.Category | String | The category of the alert. | 
| MicrosoftATP.Alert.ThreatFamilyName | String | The threat family of the alert. | 
| MicrosoftATP.Alert.Title | String | The title of the alert. | 
| MicrosoftATP.Alert.Description | String | The description of the alert. | 
| MicrosoftATP.Alert.AlertCreationTime | Date | The date and time the alert was created. | 
| MicrosoftATP.Alert.FirstEventTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.LastEventTime | Date | The last event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.LastUpdateTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.ResolvedTime | Date | The date and time in which the status of the alert was changed to "Resolved". | 
| MicrosoftATP.Alert.MachineID | String | The ID of the machine that is associated with the alert. | 
| MicrosoftATP.Alert.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.Alert.AADTenantID | String | The AAD tenant ID. | 
| MicrosoftATP.Alert.Comments.Comment | String | The comment string of the alert. | 
| MicrosoftATP.Alert.Comments.CreatedBy | String | The alert's comment created by the string. | 
| MicrosoftATP.Alert.Comments.CreatedTime | Date | The time and date the alert's comment was created.  | 


##### Command Example
```!microsoft-atp-update-alert alert_id=da637200417169017725_183736971 status=InProgress```

##### Context Example
```
{
    "MicrosoftATP.Alert": {
        "Status": "InProgress", 
        "ID": "da637200417169017725_183736971"
    }
}
```

##### Human Readable Output
The alert da637200417169017725_183736971 has been updated successfully


### 9. microsoft-atp-advanced-hunting
---
Runs programmatic queries in Microsoft Defender ATP Portal (https://securitycenter.windows.com/hunting). You can only run a query on data from the last 30 days. The maximum number of rows is 10,000. The number of executions is limited to 15 calls per minute, and 15 minutes of running time every hour, and 4 hours of running time a day.

##### Required Permissions
AdvancedQuery.Read.All	

##### Base Command

`microsoft-atp-advanced-hunting`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to run. | Required | 
| timeout | The amount of time (in seconds) that a request waits for the query response before a timeout occurs. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Hunt.Result | String | The query results. | 


##### Command Example
```!microsoft-atp-advanced-hunting query="DeviceLogonEvents | take 1 | project DeviceId, ReportId, tostring(Timestamp)"```

##### Context Example
```
{
    "MicrosoftATP.Hunt.Result": [
        {
            "DeviceId": "4899036531e374137f63289c3267bad772c13fef", 
            "Timestamp": "2020-02-23T07:14:42.1599815Z", 
            "ReportId": "35275"
        }
    ]
}
```

##### Human Readable Output
##### Hunt results
|Timestamp|DeviceId|ReportId|
|---|---|---|
| 2020-02-23T07:14:42.1599815Z | 4899036531e374137f63289c3267bad772c13fef | 35275 |


### 10. microsoft-atp-create-alert
---
Creates a new alert entity using event data, as obtained from the Advanced Hunting.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-create-alert`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The ID of the machine on which the event was identified. | Required | 
| severity | The severity of the alert. Severity of the alert. Possible values: "Low", "Medium", and "High". | Required | 
| title | The title of the alert. | Required | 
| description | The description of the alert. | Required | 
| recommended_action | The action that is recommended to be taken by the security officer when analyzing the alert. | Required | 
| event_time | The time of the event, as obtained from the advanced query. | Required | 
| report_id | The report ID, as obtained from the advanced query. | Required | 
| category | The category of the alert. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Alert.ID | String | The ID of the alert. | 
| MicrosoftATP.Alert.IncidentID | Number | The incident ID of the alert. | 
| MicrosoftATP.Alert.InvestigationID | Number | The investigation ID related to the alert. | 
| MicrosoftATP.Alert.InvestigationState | String | The current state of the investigation. | 
| MicrosoftATP.Alert.AssignedTo | String | The owner of the alert. | 
| MicrosoftATP.Alert.Severity | String | The severity of the alert. | 
| MicrosoftATP.Alert.Status | String | The current status of the alert. | 
| MicrosoftATP.Alert.Classification | String | The classification of the alert. | 
| MicrosoftATP.Alert.Determination | String | The determination of the alert. | 
| MicrosoftATP.Alert.DetectionSource | String | The detection source. | 
| MicrosoftATP.Alert.Category | String | The category of the alert. | 
| MicrosoftATP.Alert.ThreatFamilyName | String | The threat family of the alert. | 
| MicrosoftATP.Alert.Title | String | The title of the alert. | 
| MicrosoftATP.Alert.Description | String | The description of the alert. | 
| MicrosoftATP.Alert.AlertCreationTime | Date | The date and time the alert was created. | 
| MicrosoftATP.Alert.FirstEventTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.LastEventTime | Date | The last event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.LastUpdateTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.Alert.ResolvedTime | Date | The date and time in which the status of the alert was changed to "Resolved". | 
| MicrosoftATP.Alert.MachineID | String | The machine ID that is associated with the alert. | 
| MicrosoftATP.Alert.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.Alert.AADTenantID | String | The AAD tenant ID. | 
| MicrosoftATP.Alert.Comments.Comment | String | The comment string of the alert. | 
| MicrosoftATP.Alert.Comments.CreatedBy | String | The alert's comment created by the string. | 
| MicrosoftATP.Alert.Comments.CreatedTime | Date | The time and date the alert comment was created. | 


##### Command Example
```!microsoft-atp-create-alert category=Backdoor description="test" report_id=20279 event_time=2020-02-23T07:22:07.1532018Z machine_id=4899036531e374137f63289c3267bad772c13fef recommended_action="runAntiVirusScan" severity=Low title="testing alert"```

##### Context Example
```
{
    "MicrosoftATP.Alert": {
        "Category": "Backdoor", 
        "ThreatFamilyName": null, 
        "Severity": "Low", 
        "LastEventTime": "2020-02-23T07:22:07.1532018Z", 
        "FirstEventTime": "2020-02-23T07:22:07.1532018Z", 
        "Comments": [
            {
                "Comment": null, 
                "CreatedTime": null, 
                "CreatedBy": null
            }
        ], 
        "AADTenantID": "TENANT-ID", 
        "AlertCreationTime": "2020-03-22T15:44:23.5446957Z", 
        "Status": "New", 
        "Description": "test", 
        "InvestigationState": "PendingApproval", 
        "MachineID": "4899036531e374137f63289c3267bad772c13fef", 
        "Title": "testing alert", 
        "InvestigationID": 10, 
        "Determination": null, 
        "IncidentID": 18, 
        "AssignedTo": null, 
        "DetectionSource": "CustomerTI", 
        "ResolvedTime": null, 
        "ID": "da637204886635759335_1480542752", 
        "LastUpdateTime": "2020-03-22T15:44:24.6533333Z", 
        "Classification": null, 
        "ComputerDNSName": "desktop-s2455r8", 
        "Evidence": []
    }
}
```

##### Human Readable Output
##### Alert created:
|ID|Title|Description|IncidentID|Severity|Status|Category|MachineID|
|---|---|---|---|---|---|---|---|
| da637204886635759335_1480542752 | testing alert | test | 18 | Low | New | Backdoor | 4899036531e374137f63289c3267bad772c13fef |


### 11. microsoft-atp-get-alert-related-user
---
Retrieves the user associated to a specific alert.

##### Required Permissions
User.Read.All	

##### Base Command

`microsoft-atp-get-alert-related-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the alert. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.AlertUser.User.ID | String | The ID of the user. | 
| MicrosoftATP.AlertUser.User.AccountName | String | The account name. | 
| MicrosoftATP.AlertUser.User.AccountDomain | String | The account domain. | 
| MicrosoftATP.AlertUser.User.AccountSID | String | The account SID. | 
| MicrosoftATP.AlertUser.User.FirstSeen | Date | The user first seen date and time. | 
| MicrosoftATP.AlertUser.User.LastSeen | Date | The user last seen date and time. | 
| MicrosoftATP.AlertUser.User.MostPrevalentMachineID | String | The most prevalent machine ID. | 
| MicrosoftATP.AlertUser.User.LeastPrevalentMachineID | String | The least prevalent machine ID. | 
| MicrosoftATP.AlertUser.User.LogonTypes | String | The user logon types. | 
| MicrosoftATP.AlertUser.User.LogonCount | Number | The user logon count. | 
| MicrosoftATP.AlertUser.User.DomainAdmin | Number | Whether the user is the domain admin. | 
| MicrosoftATP.AlertUser.User.NetworkUser | Number | Whether the user is the domain admin. | 
| MicrosoftATP.AlertUser.AlertID | String | The ID of the alert. | 


##### Command Example
```!microsoft-atp-get-alert-related-user id=da637175364995825348_1865170845```

##### Context Example
```
{
    "MicrosoftATP.AlertUser": {
        "User": {
            "LeastPrevalentMachineID": "4899036531e374137f63289c3267bad772c13fef", 
            "MostPrevalentMachineID": "4899036531e374137f63289c3267bad772c13fef", 
            "LogonCount": 1, 
            "NetworkUser": false, 
            "DomainAdmin": false, 
            "LogonTypes": null, 
            "AccountName": "demisto", 
            "LastSeen": "2020-03-03T12:32:51Z", 
            "AccountSID": "S-1-5-21-4197691174-1403503641-4006700887-1001", 
            "AccountDomain": "desktop-s2455r8", 
            "ID": "desktop-s2455r8\\demisto", 
            "FirstSeen": "2020-02-23T07:14:42Z"
        }, 
        "AlertID": "da637175364995825348_1865170845"
    }
}
```

##### Human Readable Output
##### Alert Related User:
|AccountDomain|AccountName|AccountSID|DomainAdmin|FirstSeen|ID|LastSeen|LeastPrevalentMachineID|LogonCount|MostPrevalentMachineID|NetworkUser|
|---|---|---|---|---|---|---|---|---|---|---|
| desktop-s2455r8 | demisto | S-1-5-21-4197691174-1403503641-4006700887-1001 | false | 2020-02-23T07:14:42Z | desktop-s2455r8\demisto | 2020-03-03T12:32:51Z | 4899036531e374137f63289c3267bad772c13fef | 1 | 4899036531e374137f63289c3267bad772c13fef | false |


### 12. microsoft-atp-get-alert-related-files
---
Retrieves the files associated to a specific alert.

##### Required Permissions
File.Read.All	

##### Base Command

`microsoft-atp-get-alert-related-files`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the alert. | Required | 
| limit | The limit of files to display. | Optional | 
| offset | The page from which to get the related files. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.AlertFile.Files.FilePublisher | String | The file's publisher. | 
| MicrosoftATP.AlertFile.Files.Size | Number | The size of the file. | 
| MicrosoftATP.AlertFile.Files.GlobalLastObserved | Date | The last time the file was observed. | 
| MicrosoftATP.AlertFile.Files.Sha1 | String | The SHA1 hash of the file. | 
| MicrosoftATP.AlertFile.Files.IsValidCertificate | Number | Whether the signing of the certificate was successfully verified by the Microsoft Defender ATP agent. | 
| MicrosoftATP.AlertFile.Files.Sha256 | String | The SHA256 hash of the file. | 
| MicrosoftATP.AlertFile.Files.Signer | String | The file signer. | 
| MicrosoftATP.AlertFile.Files.GlobalPrevalence | Number | The file prevalence across the organization. | 
| MicrosoftATP.AlertFile.Files.DeterminationValue | String | The determination of the file's value. | 
| MicrosoftATP.AlertFile.Files.GlobalFirstObserved | Date | The first time the file was observed. | 
| MicrosoftATP.AlertFile.Files.FileType | String | The type of the file. | 
| MicrosoftATP.AlertFile.Files.SignerHash | String | The hash of the signing certificate. | 
| MicrosoftATP.AlertFile.Files.Issuer | String | The file issuer. | 
| MicrosoftATP.AlertFile.Files.IsPeFile | Number | Wether the file is portable executable. | 
| MicrosoftATP.AlertFile.Files.DeterminationType | String | The determination type of the file. | 
| MicrosoftATP.AlertFile.Files.FileProductName | Unknown | The product name of the file.| 
| MicrosoftATP.AlertFile.Files.Md5 | String | The MD5 hash of the file. | 


##### Command Example
```!microsoft-atp-get-alert-related-files id=da637175364995825348_1865170845```

##### Context Example
```
{
    "MicrosoftATP.AlertFile": {
        "Files": [
            {
                "DeterminationType": "Unknown", 
                "SignerHash": "84ec67b9ac9d7789bab500503a7862173f432adb", 
                "Sha1": "d487580502354c61808c7180d1a336beb7ad4624", 
                "IsPeFile": true, 
                "GlobalPrevalence": 45004, 
                "SizeInBytes": 181248, 
                "Signer": "Microsoft Windows", 
                "GlobalFirstObserved": "2019-03-21T22:37:42.7608151Z", 
                "IsValidCertificate": true, 
                "GlobalLastObserved": "2020-03-22T22:48:20.608421Z", 
                "Sha256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3", 
                "Md5": "f1139811bbf61362915958806ad30211", 
                "Issuer": "Microsoft Windows Production PCA 2011"
            }, 
            {
                "DeterminationType": "Unknown", 
                "SignerHash": "84ec67b9ac9d7789bab500503a7862173f432adb", 
                "Sha1": "36c5d12033b2eaf251bae61c00690ffb17fddc87", 
                "IsPeFile": true, 
                "GlobalPrevalence": 1316463, 
                "SizeInBytes": 451584, 
                "Signer": "Microsoft Windows", 
                "GlobalFirstObserved": "2019-03-21T08:31:08.1952647Z", 
                "IsValidCertificate": true, 
                "GlobalLastObserved": "2020-03-23T09:24:49.9664767Z", 
                "Sha256": "908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53", 
                "Md5": "cda48fc75952ad12d99e526d0b6bf70a", 
                "Issuer": "Microsoft Windows Production PCA 2011"
            }
        ], 
        "AlertID": "da637175364995825348_1865170845"
    }
}
```

##### Human Readable Output
##### Alert da637175364995825348_1865170845 Related Files:
|Sha1|Sha256|SizeInBytes|
|---|---|---|
| d487580502354c61808c7180d1a336beb7ad4624 | f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3 | 181248 |
| 36c5d12033b2eaf251bae61c00690ffb17fddc87 | 908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53 | 451584 |


### 13. microsoft-atp-get-alert-related-ips
---
Retrieves the IP addresses associated to a specific alert.

##### Required Permissions
Ip.Read.All	

##### Base Command

`microsoft-atp-get-alert-related-ips`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the alert. | Required | 
| limit | The limit of IP addresses to display. | Optional | 
| offset | The page from which to get the related IP addresses. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.AlertIP.IPs.IpAddress | String | The address of the IP address. | 
| MicrosoftATP.AlertIP.AlertID | String | The ID of the alert. | 


##### Command Example
```!microsoft-atp-get-alert-related-ips id=da637200417169017725_183736971 limit=3 offset=0```

##### Context Example
```
{
    "MicrosoftATP.AlertIP": {
        "IPs": [], 
        "AlertID": "da637200417169017725_183736971"
    }
}
```

##### Human Readable Output
Alert da637200417169017725_183736971 Related IPs: []


### 14. microsoft-atp-get-alert-related-domains
---
Retrieves the domains associated to a specific alert.

##### Required Permissions
URL.Read.All	

##### Base Command

`microsoft-atp-get-alert-related-domains`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the alert. | Required | 
| limit | The limit of domains to display. | Optional | 
| offset | The page from which to get the related domains. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.AlertDomain.Domains.Domain | String | The domain address. | 
| MicrosoftATP.AlertDomain.AlertID | Unknown | The ID of the alert. | 


##### Command Example
```!microsoft-atp-get-alert-related-domains id=da637175364995825348_1865170845 limit=2 offset=0```

##### Context Example
```
{
    "MicrosoftATP.AlertDomain": {
        "Domains": [], 
        "AlertID": "da637175364995825348_1865170845"
    }
}
```

##### Human Readable Output
Alert da637175364995825348_1865170845 Related Domains: []


### 15. microsoft-atp-list-machine-actions-details
---
Returns the machine's actions. If an action ID is set it returns the information on the specific action.
Filtering can only be done on a single argument.

##### Required Permissions
Machine.ReadWrite.All

#### Base Command

`microsoft-atp-list-machine-actions-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the action. | Optional | 
| status | The machine action status. Possible values: "Pending", "InProgress", "Succeeded", "Failed", "TimeOut", "Cancelled". Possible values are: Pending, InProgress, Succeeded, Failed, TimeOut, Cancelled. | Optional | 
| machine_id | A comma-separated list of machine IDs on which the action was executed. | Optional | 
| type | The machine action type. Possible values: "RunAntiVirusScan", "Offboard", "CollectInvestigationPackage", "Isolate", "Unisolate", "StopAndQuarantineFile", "RestrictCodeExecution", and "UnrestrictCodeExecution". Possible values are: RunAntiVirusScan, Offboard, CollectInvestigationPackage, Isolate, Unisolate, StopAndQuarantineFile, RestrictCodeExecution, UnrestrictCodeExecution. | Optional | 
| requestor | The ID of the user that executed the action, only one can be added. | Optional | 
| limit | The maximum number of machines to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The machine action ID. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | String | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name on which the action was executed. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier. Possible values: "SHA1" ,"SHA256", and "MD5". | 

#### Command example
```!microsoft-atp-list-machine-actions-details machine_id="f70f9fe6,48990365" type=RunAntiVirusScan status=Succeeded```
#### Context Example
```json
{
    "MicrosoftATP": {
        "MachineAction": [
            {
                "ComputerDNSName": "desktop-s9",
                "CreationDateTimeUtc": "2022-01-25T17:57:18.7944822Z",
                "ID": "98cf0adc",
                "LastUpdateTimeUtc": null,
                "MachineID": "f70f9fe6",
                "RelatedFileInfo": {
                    "FileIdentifier": null,
                    "FileIdentifierType": null
                },
                "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4",
                "RequestorComment": "test3",
                "Scope": "Quick",
                "Status": "Succeeded",
                "Type": "RunAntiVirusScan"
            },
            {
                "ComputerDNSName": "desktop-s8",
                "CreationDateTimeUtc": "2022-01-25T17:56:04.3073008Z",
                "ID": "99a29fc5",
                "LastUpdateTimeUtc": null,
                "MachineID": "48990365",
                "RelatedFileInfo": {
                    "FileIdentifier": null,
                    "FileIdentifierType": null
                },
                "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4",
                "RequestorComment": "test2",
                "Scope": "Quick",
                "Status": "Succeeded",
                "Type": "RunAntiVirusScan"
            }
        ]
    }
}
```

#### Human Readable Output

>### Machine actions Info:
>|ID|Type|Requestor|RequestorComment|Status|MachineID|ComputerDNSName|
>|---|---|---|---|---|---|---|
>| 98cf0adc | RunAntiVirusScan | 2f48b784-5da5-4e61-9957-012d2630f1e4 | test3 | Succeeded | f70f9fe6 | desktop-s9 |
>| 99a29fc5 | RunAntiVirusScan | 2f48b784-5da5-4e61-9957-012d2630f1e4 | test2 | Succeeded | 48990365 | desktop-s8 |


### 16. microsoft-atp-collect-investigation-package
---
Collects an investigation package from a machine.

##### Required Permissions
Machine.CollectForensics

##### Base Command

`microsoft-atp-collect-investigation-package`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The ID of the machine. | Required | 
| comment | The comment to associate with the action. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The action ID of the machine. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | String | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name the action was executed on. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier. Possible values: "SHA1", "SHA256", and "MD5". | 


##### Command Example
```!microsoft-atp-collect-investigation-package comment="testing" machine_id=f70f9fe6b29cd9511652434919c6530618f06606```

##### Context Example
```
{
    "MicrosoftATP.MachineAction": {
        "Status": "Pending", 
        "CreationDateTimeUtc": "2020-03-23T10:08:05.8010798Z", 
        "MachineID": "f70f9fe6b29cd9511652434919c6530618f06606", 
        "LastUpdateTimeUtc": null, 
        "ComputerDNSName": null, 
        "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4", 
        "RelatedFileInfo": {
            "FileIdentifier": null, 
            "FileIdentifierType": null
        }, 
        "Scope": null, 
        "Type": "CollectInvestigationPackage", 
        "ID": "fa952f94-d672-47a6-a637-70b91339c079", 
        "RequestorComment": "testing"
    }
}
```

##### Human Readable Output
##### Initiating collect investigation package from f70f9fe6b29cd9511652434919c6530618f06606 machine :
|ID|Type|Requestor|RequestorComment|Status|MachineID|
|---|---|---|---|---|---|
| fa952f94-d672-47a6-a637-70b91339c079 | CollectInvestigationPackage | 2f48b784-5da5-4e61-9957-012d2630f1e4 | testing | Pending | f70f9fe6b29cd9511652434919c6530618f06606 |


### 17. microsoft-atp-get-investigation-package-sas-uri
---
Gets a URI that allows downloading of an investigation package.

##### Required Permissions
Machine.CollectForensics

##### Base Command

`microsoft-atp-get-investigation-package-sas-uri`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | The action ID of the machine. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.InvestigationURI.Link | String | The investigation package URI. | 


##### Command Example
```!microsoft-atp-get-investigation-package-sas-uri action_id=6ae51f8f-68e6-4259-abae-0018fdf2e418```

##### Context Example
```
{
    "MicrosoftATP.InvestigationURI": {
        "Link": "https://userrequests-us.securitycenter.windows.com:443/safedownload/WDATP_Investigation_Package.zip?token=MIICYwYJKoZIhvcNAQcCoIICV"
    }
}
```

##### Human Readable Output
Success. This link is valid for a very short time and should be used immediately for downloading the package to a local storage: `https:
//userrequests-us.securitycenter.windows.com:443/safedownload/WDATP_Investigation_Package.zip?token=MIICYwYJKoZIhvcNAQcCoIICV`


### 18. microsoft-atp-restrict-app-execution
---
Restricts the execution of all applications on the machine except a predefined set.

##### Required Permissions
Machine.RestrictExecution

##### Base Command

`microsoft-atp-restrict-app-execution`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The ID of the machine. | Required | 
| comment | The comment to associate with the action. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The action ID of the machine. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | String | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID the action was executed on. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name the action was executed on. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier. Possible values: "SHA1", "SHA256", and "MD5".| 


##### Command Example
```!microsoft-atp-restrict-app-execution machine_id=f70f9fe6b29cd9511652434919c6530618f06606 comment="test restrict app"```

##### Context Example
```
{
    "MicrosoftATP.MachineAction": {
        "Status": "Pending", 
        "CreationDateTimeUtc": "2020-03-23T10:08:07.7643812Z", 
        "MachineID": "f70f9fe6b29cd9511652434919c6530618f06606", 
        "LastUpdateTimeUtc": null, 
        "ComputerDNSName": null, 
        "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4", 
        "RelatedFileInfo": {
            "FileIdentifier": null, 
            "FileIdentifierType": null
        }, 
        "Scope": null, 
        "Type": "RestrictCodeExecution", 
        "ID": "264c80f0-1452-43fb-92d0-5515dd0b821e", 
        "RequestorComment": "test restrict app"
    }
}
```

##### Human Readable Output
##### Initiating Restrict execution of all applications on the machine f70f9fe6b29cd9511652434919c6530618f06606 except a predefined set:
|ID|Type|Requestor|RequestorComment|Status|MachineID|
|---|---|---|---|---|---|
| 264c80f0-1452-43fb-92d0-5515dd0b821e | RestrictCodeExecution | 2f48b784-5da5-4e61-9957-012d2630f1e4 | test restrict app | Pending | f70f9fe6b29cd9511652434919c6530618f06606 |


### 19. microsoft-atp-remove-app-restriction
---
Enables the execution of any application on the machine.

##### Required Permissions
Machine.RestrictExecution

##### Base Command

`microsoft-atp-remove-app-restriction`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The ID of the machine. | Required | 
| comment | The comment to associate with the action. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The action ID of the machine. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | String | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID the action was executed on. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name the action was executed on. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier. Possible values: "SHA1", "SHA256", and "MD5".| 


##### Command Example
```!microsoft-atp-remove-app-restriction machine_id=f70f9fe6b29cd9511652434919c6530618f06606 comment="testing remove restriction"```

##### Context Example
```
{
    "MicrosoftATP.MachineAction": {
        "Status": "Pending", 
        "CreationDateTimeUtc": "2020-03-23T10:08:08.5355244Z", 
        "MachineID": "f70f9fe6b29cd9511652434919c6530618f06606", 
        "LastUpdateTimeUtc": null, 
        "ComputerDNSName": null, 
        "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4", 
        "RelatedFileInfo": {
            "FileIdentifier": null, 
            "FileIdentifierType": null
        }, 
        "Scope": null, 
        "Type": "UnrestrictCodeExecution", 
        "ID": "5e3cc0b8-b1a1-4a07-92bf-4d63ecec1b18", 
        "RequestorComment": "testing remove restriction"
    }
}
```

##### Human Readable Output
##### Removing applications restriction on the machine f70f9fe6b29cd9511652434919c6530618f06606:
|ID|Type|Requestor|RequestorComment|Status|MachineID|
|---|---|---|---|---|---|
| 5e3cc0b8-b1a1-4a07-92bf-4d63ecec1b18 | UnrestrictCodeExecution | 2f48b784-5da5-4e61-9957-012d2630f1e4 | testing remove restriction | Pending | f70f9fe6b29cd9511652434919c6530618f06606 |


### 20. microsoft-atp-stop-and-quarantine-file
---
Stops the execution of a file on a machine and deletes it.

##### Required Permissions
Machine.StopAndQuarantine	

##### Base Command

`microsoft-atp-stop-and-quarantine-file`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The ID  of the machine. | Required | 
| file_hash | The file SHA1 hash to stop and quarantine on the machine. | Required | 
| comment | The comment to associate with the action. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The action ID  of the machine. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | String | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name on which the action was executed. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier. Possible values: "SHA1", "SHA256", and "MD5". | 


##### Command Example
```!microsoft-atp-stop-and-quarantine-file comment="testing" file_hash=abe3ba25e5660c23dfe478d577cfacde5795870c machine_id=12345678```
#### Context Example
```
{ 'ID': '123',
 'Type': 'StopAndQuarantineFile',
 'Scope': None,
 'Requestor': '123abc',
 'RequestorComment': 'Test',
 'Status': 'Pending',
 'MachineID': '12345678',
 'ComputerDNSName': None,
 'CreationDateTimeUtc': '2020-03-20T14:21:49.9097785Z',
 'LastUpdateTimeUtc': '2020-02-27T12:21:00.4568741Z',
 'RelatedFileInfo': {'fileIdentifier': '87654321', 'fileIdentifierType': 'Sha1'}
}
```

##### Human Readable Output
##### Stopping the execution of a file on 12345678 machine and deleting it:
|ID|Type|Requestor|RequestorComment|Status|MachineID|
|---|---|---|---|---|---|
| 123 | StopAndQuarantineFile | 123abc | Test | Pending | 12345678 |


### 21. microsoft-atp-list-investigations
---
Retrieves a collection of investigations or retrieves specific investigation by its ID.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-list-investigations`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID can be the investigation ID or the investigation triggering an alert ID. | Optional | 
| limit | The limit of investigations to display. | Optional | 
| offset | The page from which to get the investigations. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Investigation.ID | String | The ID of the investigation. | 
| MicrosoftATP.Investigation.StartTime | Date | The date and time when the investigation was created. | 
| MicrosoftATP.Investigation.EndTime | Date | The date and time when the investigation was completed. | 
| MicrosoftATP.Investigation.State | String | The state of the investigation. | 
| MicrosoftATP.Investigation.CancelledBy | Unknown | The ID of the user or application that cancelled that investigation. | 
| MicrosoftATP.Investigation.StatusDetails | Unknown | The details of the state of the investigation. | 
| MicrosoftATP.Investigation.MachineID | String | The machine ID the investigation is executed on.| 
| MicrosoftATP.Investigation.ComputerDNSName | String | The machine DNS name the investigation is executed on. | 
| MicrosoftATP.Investigation.TriggeringAlertID | String | The alert ID that triggered the investigation. | 


##### Command Example
```!microsoft-atp-list-investigations limit=3 offset=0```

##### Context Example
```
{
    "MicrosoftATP.Investigation": [
        {
            "CancelledBy": null, 
            "InvestigationState": "PendingApproval", 
            "MachineID": "4899036531e374137f63289c3267bad772c13fef", 
            "TriggeringAlertID": "da637200417169017725_183736971", 
            "ComputerDNSName": "desktop-s2455r8", 
            "StatusDetails": null, 
            "StartTime": "2020-03-17T11:35:17Z", 
            "EndTime": null, 
            "ID": "10"
        }, 
        {
            "CancelledBy": null, 
            "InvestigationState": "PendingApproval", 
            "MachineID": "f70f9fe6b29cd9511652434919c6530618f06606", 
            "TriggeringAlertID": "da637200385941308230_1832866941", 
            "ComputerDNSName": "desktop-s2455r9", 
            "StatusDetails": null, 
            "StartTime": "2020-03-17T10:43:15Z", 
            "EndTime": null, 
            "ID": "9"
        }, 
        {
            "CancelledBy": null, 
            "InvestigationState": "TerminatedBySystem", 
            "MachineID": "f70f9fe6b29cd9511652434919c6530618f06606", 
            "TriggeringAlertID": "da637189366671550108_395377714", 
            "ComputerDNSName": "desktop-s2455r9", 
            "StatusDetails": null, 
            "StartTime": "2020-03-04T16:37:50Z", 
            "EndTime": "2020-03-11T18:13:42Z", 
            "ID": "8"
        }
    ]
}
```

##### Human Readable Output
##### Investigations Info:
|ID|StartTime|EndTime|InvestigationState|MachineID|ComputerDNSName|TriggeringAlertID|
|---|---|---|---|---|---|---|
| 10 | 2020-03-17T11:35:17Z |  | PendingApproval | 4899036531e374137f63289c3267bad772c13fef | desktop-s2455r8 | da637200417169017725_183736971 |
| 9 | 2020-03-17T10:43:15Z |  | PendingApproval | f70f9fe6b29cd9511652434919c6530618f06606 | desktop-s2455r9 | da637200385941308230_1832866941 |
| 8 | 2020-03-04T16:37:50Z | 2020-03-11T18:13:42Z | TerminatedBySystem | f70f9fe6b29cd9511652434919c6530618f06606 | desktop-s2455r9 | da637189366671550108_395377714 |


### 22. microsoft-atp-start-investigation
---
Starts an automated investigation on a machine.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-start-investigation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The ID of the machine. | Required | 
| comment | The comment to associate with the action. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Investigation.ID | String | The ID of the investigation. | 
| MicrosoftATP.Investigation.StartTime | Date | The date and time when the investigation was created. | 
| MicrosoftATP.Investigation.EndTime | Date | The date and time when the investigation was completed. | 
| MicrosoftATP.Investigation.State | String | The state of the investigation. | 
| MicrosoftATP.Investigation.CancelledBy | Unknown | The ID of the user or application that cancelled that investigation. | 
| MicrosoftATP.Investigation.StatusDetails | Unknown | The details of the state of the investigation. | 
| MicrosoftATP.Investigation.MachineID | String | The machine ID the investigation is executed on. | 
| MicrosoftATP.Investigation.ComputerDNSName | String | The machine DNS name the investigation is executed on. | 
| MicrosoftATP.Investigation.TriggeringAlertID | String | The alert ID that triggered the investigation. | 


##### Command Example
```!microsoft-atp-start-investigation comment="testing" machine_id=f70f9fe6b29cd9511652434919c6530618f06606```

##### Context Example
```
{
    "MicrosoftATP.Investigation": {
        "CancelledBy": null, 
        "InvestigationState": "PendingApproval", 
        "MachineID": null, 
        "TriggeringAlertID": "da637205548921456173_375980286", 
        "ComputerDNSName": null, 
        "StatusDetails": null, 
        "StartTime": null, 
        "EndTime": null, 
        "ID": "da637205548921456173_375980286"
    }
}
```

##### Human Readable Output
##### Starting investigation da637205548921456173_375980286 on f70f9fe6b29cd9511652434919c6530618f06606 machine:
|ID|InvestigationState|TriggeringAlertID|
|---|---|---|
| da637205548921456173_375980286 | PendingApproval | da637205548921456173_375980286 |


### 23. microsoft-atp-get-domain-statistics
---
Retrieves the statistics on the given domain.

##### Required Permissions
URL.Read.All
	
##### Base Command

`microsoft-atp-get-domain-statistics`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain address. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.DomainStatistics.Statistics.Host | String | The domain host. | 
| MicrosoftATP.DomainStatistics.Statistics.OrgPrevalence | String | The prevalence of the domain in the organization. | 
| MicrosoftATP.DomainStatistics.Statistics.OrgFirstSeen | Date | The first date and time the domain was seen in the organization. | 
| MicrosoftATP.DomainStatistics.Statistics.OrgLastSeen | Date | The last date and time the domain was seen in the organization. | 


##### Command Example
```!microsoft-atp-get-domain-statistics domain=google.com```

##### Context Example
```
{
    "MicrosoftATP.DomainStatistics": {
        "Domain": "google.com", 
        "Statistics": {
            "OrgLastSeen": "2020-02-24T13:14:54Z", 
            "Host": "google.com", 
            "OrgFirstSeen": "2020-02-24T12:50:04Z", 
            "OrgPrevalence": "1"
        }
    }
}
```

##### Human Readable Output
##### Statistics on google.com domain:
|Host|OrgFirstSeen|OrgLastSeen|OrgPrevalence|
|---|---|---|---|
| google.com | 2020-02-24T12:50:04Z | 2020-02-24T13:14:54Z | 1 |


### 24. microsoft-atp-get-domain-alerts
---
Retrieves a collection of alerts related to a given domain address.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-get-domain-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain address. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.DomainAlert.Domain | String | The domain address. | 
| MicrosoftATP.DomainAlert.Alerts.ID | String | The ID of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.IncidentID | Number | The incident ID of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.InvestigationID | Number | The investigation ID related to the alert. | 
| MicrosoftATP.DomainAlert.Alerts.InvestigationState | String | The current state of the investigation. | 
| MicrosoftATP.DomainAlert.Alerts.AssignedTo | String | The owner of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.Severity | String | The severity of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.Status | String | The current status of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.Classification | String | The alert classification. | 
| MicrosoftATP.DomainAlert.Alerts.Determination | String | The determination of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.DetectionSource | String | The detection source. | 
| MicrosoftATP.DomainAlert.Alerts.Category | String | The category of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.ThreatFamilyName | String | The family name of the threat. | 
| MicrosoftATP.DomainAlert.Alerts.Title | String | The title of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.Description | String | The description of the alert. | 
| MicrosoftATP.DomainAlert.Alerts.AlertCreationTime | Date | The date and time the alert was created. | 
| MicrosoftATP.DomainAlert.Alerts.FirstEventTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.DomainAlert.Alerts.LastEventTime | Date | The last event time that triggered the alert on that machine. | 
| MicrosoftATP.DomainAlert.Alerts.LastUpdateTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.DomainAlert.Alerts.ResolvedTime | Date | The date and time in which the status of the alert was changed to "Resolved". | 
| MicrosoftATP.DomainAlert.Alerts.MachineID | String | The machine ID that is associated with the alert. | 
| MicrosoftATP.DomainAlert.Alerts.ComputerDNSName | String | The machine DNS name. | 
| MicrosoftATP.DomainAlert.Alerts.AADTenantID | String | The AAD tenant ID. | 
| MicrosoftATP.DomainAlert.Alerts.Comments.Comment | String | The alert comment string. | 
| MicrosoftATP.DomainAlert.Alerts.Comments.CreatedBy | String | The alert comment created by the string. | 
| MicrosoftATP.DomainAlert.Alerts.Comments.CreatedTime | Date | The alert comment create time and date. | 


##### Command Example
```!microsoft-atp-get-domain-alerts domain=google.com```

##### Context Example
```
{
    "MicrosoftATP.DomainAlert": {
        "Domain": "google.com", 
        "Alerts": []
    }
}
```

##### Human Readable Output
##### Domain google.com related alerts Info:
**No entries.**


### 25. microsoft-atp-get-domain-machines
---
Retrieves a collection of machines that have communicated with a given domain address.

##### Required Permissions
Machine.ReadWrite.All

##### Base Command

`microsoft-atp-get-domain-machines`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain address. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.DomainMachine.Domain | String | The domain address. | 
| MicrosoftATP.DomainMachine.Machines.ID | String | The ID of the machine. | 
| MicrosoftATP.DomainMachine.Machines.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.DomainMachine.Machines.FirstSeen | Date | The first date and time when the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.DomainMachine.Machines.LastSeen | Date | The last date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.DomainMachine.Machines.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.DomainMachine.Machines.OSVersion | String | The operating system version. | 
| MicrosoftATP.DomainMachine.Machines.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.DomainMachine.Machines.LastIPAddress | String | The last IP address on the machine. | 
| MicrosoftATP.DomainMachine.Machines.LastExternalIPAddress | String | The last IP address the machine accessed. | 
| MicrosoftATP.DomainMachine.Machines.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.DomainMachine.Machines.HealthStatus | String | The health status of the machine. | 
| MicrosoftATP.DomainMachine.Machines.RBACGroupID | Number | The RBAC group ID of the machine. | 
| MicrosoftATP.DomainMachine.Machines.RBACGroupName | String | The RBAC group name of the machine. | 
| MicrosoftATP.DomainMachine.Machines.RiskScore | String | The risk score of the machine. | 
| MicrosoftATP.DomainMachine.Machines.ExposureLevel | String | The exposure level of the machine. | 
| MicrosoftATP.DomainMachine.Machines.IsAADJoined | Boolean | Whether the machine is AAD joined. | 
| MicrosoftATP.DomainMachine.Machines.AADDeviceID | String | The AAD device ID. | 
| MicrosoftATP.DomainMachine.Machines.MachineTags | String | The set of machine tags. | 


##### Command Example
```!microsoft-atp-get-domain-machines domain=google.com```

##### Context Example
```
{
    "MicrosoftATP.DomainMachine": {
        "Domain": "google.com", 
        "Machines": [
            {
                "OSBuild": 18363, 
                "ExposureLevel": "Medium", 
                "OSPlatform": "Windows10", 
                "MachineTags": [
                    "test Tag 2", 
                    "test Tag 5"
                ], 
                "AADDeviceID": "cfcf4177-227e-4cdb-ac8e-f9a3da1ca30c", 
                "ComputerDNSName": "desktop-s2455r8", 
                "RBACGroupID": 0, 
                "OSProcessor": "x64", 
                "HealthStatus": "Active", 
                "AgentVersion": "10.6940.18362.693", 
                "LastExternalIPAddress": "81.166.99.236", 
                "LastIPAddress": "192.168.1.71", 
                "OSVersion": "1909", 
                "RiskScore": "High", 
                "ID": "4899036531e374137f63289c3267bad772c13fef", 
                "FirstSeen": "2020-02-17T08:30:07.2415577Z", 
                "LastSeen": "2020-03-23T08:10:41.473428Z"
            }
        ]
    }
}
```

##### Human Readable Output
##### Machines that have communicated with google.com domain:
|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|
|---|---|---|---|---|---|---|---|
| 4899036531e374137f63289c3267bad772c13fef | desktop-s2455r8 | Windows10 | 192.168.1.71 | 81.166.99.236 | Active | High | Medium |


### 26. microsoft-atp-get-file-statistics
---
Retrieves the statistics for the given file.

##### Required Permissions
File.Read.All	

##### Base Command

`microsoft-atp-get-file-statistics`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | The file SHA1 hash to get statistics on. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.FileStatistics.Sha1 | String | The file SHA1 hash. | 
| MicrosoftATP.FileStatistics.Statistics.OrgPrevalence | String | The prevalence of the file in the organization. | 
| MicrosoftATP.FileStatistics.Statistics.OrgFirstSeen | Date | The first date and time the file was seen in the organization. | 
| MicrosoftATP.FileStatistics.Statistics.OrgLastSeen | Date | The last date and time the file was seen in the organization. | 
| MicrosoftATP.FileStatistics.Statistics.GlobalPrevalence | String | The global prevalence of the file. | 
| MicrosoftATP.FileStatistics.Statistics.GlobalFirstObserved | Date | The first global observation date and time of the file. | 
| MicrosoftATP.FileStatistics.Statistics.GlobalLastObserved | Date | The last global observation date and time of the file. | 
| MicrosoftATP.FileStatistics.Statistics.TopFileNames | String | The top names of the file. | 


##### Command Example
```!microsoft-atp-get-file-statistics file_hash=9fe3ba25e5660c23dfe478d577cfacde5795870c```

##### Context Example
```
{
    "MicrosoftATP.FileStatistics": {
        "Sha1": "9fe3ba25e5660c23dfe478d577cfacde5795870c", 
        "Statistics": {
            "TopFileNames": [
                "lsass.exe"
            ], 
            "GlobalFirstObserved": "2019-04-03T04:10:18.1001071Z", 
            "GlobalPrevalence": "1355899", 
            "OrgPrevalence": "0", 
            "GlobalLastObserved": "2020-03-23T09:24:54.169574Z"
        }
    }
}
```

##### Human Readable Output
##### Statistics on 9fe3ba25e5660c23dfe478d577cfacde5795870c file:
|GlobalFirstObserved|GlobalLastObserved|GlobalPrevalence|OrgPrevalence|TopFileNames|
|---|---|---|---|---|
| 2019-04-03T04:10:18.1001071Z | 2020-03-23T09:24:54.169574Z | 1355899 | 0 | lsass.exe |


### 27. microsoft-atp-get-file-alerts
---
Retrieves a collection of alerts related to a given file hash.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-get-file-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | The file SHA1 hash to get statistics on. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.FileAlert.Sha1 | String | The file SHA1 hash. | 
| MicrosoftATP.FileAlert.Alerts.ID | String | The ID of the alert. | 
| MicrosoftATP.FileAlert.Alerts.IncidentID | Number | The incident ID of the alert. | 
| MicrosoftATP.FileAlert.Alerts.InvestigationID | Number | The investigation ID related to the alert. | 
| MicrosoftATP.FileAlert.Alerts.InvestigationState | String | The current state of the investigation. | 
| MicrosoftATP.FileAlert.Alerts.AssignedTo | String | The owner of the alert. | 
| MicrosoftATP.FileAlert.Alerts.Severity | String | The severity of the alert. | 
| MicrosoftATP.FileAlert.Alerts.Status | String | The current status of the alert. | 
| MicrosoftATP.FileAlert.Alerts.Classification | String | The alert classification. | 
| MicrosoftATP.FileAlert.Alerts.Determination | String | The determination of the alert. | 
| MicrosoftATP.FileAlert.Alerts.DetectionSource | String | The detection source. | 
| MicrosoftATP.FileAlert.Alerts.Category | String | The category of the alert. | 
| MicrosoftATP.FileAlert.Alerts.ThreatFamilyName | String | The family name of the threat. | 
| MicrosoftATP.FileAlert.Alerts.Title | String | The title of the alert. | 
| MicrosoftATP.FileAlert.Alerts.Description | String | The description of the alert. | 
| MicrosoftATP.FileAlert.Alerts.AlertCreationTime | Date | The date and time the alert was created. | 
| MicrosoftATP.FileAlert.Alerts.FirstEventTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.FileAlert.Alerts.LastEventTime | Date | The last event time that triggered the alert on that machine. | 
| MicrosoftATP.FileAlert.Alerts.LastUpdateTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.FileAlert.Alerts.ResolvedTime | Date | The date and time in which the status of the alert was changed to "Resolved". | 
| MicrosoftATP.FileAlert.Alerts.MachineID | String | The machine ID that is associated with the alert. | 
| MicrosoftATP.FileAlert.Alerts.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.FileAlert.Alerts.AADTenantID | String | The AAD tenant ID. | 
| MicrosoftATP.FileAlert.Alerts.Comments.Comment | String | The alert comment string. | 
| MicrosoftATP.FileAlert.Alerts.Comments.CreatedBy | String | The alert comment created by the string. | 
| MicrosoftATP.FileAlert.Alerts.Comments.CreatedTime | Date | The time and date the alert comment was created. | 


##### Command Example
```!microsoft-atp-get-file-alerts file_hash=9fe3ba25e5660c23dfe478d577cfacde5795870c```

##### Context Example
```
{
    "MicrosoftATP.FileAlert": {
        "Sha1": "9fe3ba25e5660c23dfe478d577cfacde5795870c", 
        "Alerts": [
            {
                "Category": "None", 
                "ThreatFamilyName": null, 
                "Severity": "Medium", 
                "LastEventTime": "2020-03-15T13:59:14.2438912Z", 
                "FirstEventTime": "2020-03-15T13:59:14.2438912Z", 
                "Comments": [
                    {
                        "Comment": null, 
                        "CreatedTime": null, 
                        "CreatedBy": null
                    }
                ], 
                "AADTenantID": "TENANT-ID", 
                "AlertCreationTime": "2020-03-17T11:55:31.890247Z", 
                "Status": "New", 
                "Description": "Created for test", 
                "InvestigationState": "PendingApproval", 
                "MachineID": "4899036531e374137f63289c3267bad772c13fef", 
                "Title": "test alert", 
                "InvestigationID": 10, 
                "Determination": null, 
                "IncidentID": 15, 
                "AssignedTo": null, 
                "DetectionSource": "CustomerTI", 
                "ResolvedTime": null, 
                "ID": "da637200429318902470_-1583197054", 
                "LastUpdateTime": "2020-03-17T11:55:33.0233333Z", 
                "Classification": null, 
                "ComputerDNSName": "desktop-s2455r8", 
                "Evidence": [
                    {
                        "userPrincipalName": null, 
                        "processId": 656, 
                        "sha1": "9fe3ba25e5660c23dfe478d577cfacde5795870c", 
                        "parentProcessCreationTime": null, 
                        "domainName": null, 
                        "url": null, 
                        "processCommandLine": "lsass.exe", 
                        "entityType": "Process", 
                        "processCreationTime": "2020-03-13T16:58:59Z", 
                        "aadUserId": null, 
                        "fileName": "lsass.exe", 
                        "sha256": null, 
                        "parentProcessId": 512, 
                        "userSid": null, 
                        "filePath": "c:\\windows\\system32\\lsass.exe", 
                        "accountName": null, 
                        "ipAddress": null
                    }
                ]
            }
        ]
    }
}
```

##### Human Readable Output
##### File 9fe3ba25e5660c23dfe478d577cfacde5795870c related alerts Info:
|ID|Title|Description|IncidentID|Severity|Status|Category|MachineID|
|---|---|---|---|---|---|---|---|
| da637200429318902470_-1583197054 | test alert | Created for test | 15 | Medium | New | None | 4899036531e374137f63289c3267bad772c13fef |


### 28. microsoft-atp-get-ip-statistics
---
Retrieves the statistics for the given IP address.

##### Required Permissions
Ip.Read.All	

##### Base Command

`microsoft-atp-get-ip-statistics`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.IPStatistics.Statistics.IPAddress | String | The IP address. | 
| MicrosoftATP.IPStatistics.Statistics.OrgPrevalence | String | The prevalence of the IP address in the organization. | 
| MicrosoftATP.IPStatistics.Statistics.OrgFirstSeen | Date | The first date and time the IP address was seen in the organization. | 
| MicrosoftATP.IPStatistics.Statistics.OrgLastSeen | Date | The last date and time the IP address was seen in the organization. | 


##### Command Example
```!microsoft-atp-get-ip-statistics ip=8.8.8.8```

##### Context Example
```
{
    "MicrosoftATP.IPStatistics": {
        "Statistics": {
            "OrgLastSeen": "2020-03-01T15:19:40Z", 
            "OrgPrevalence": "1", 
            "OrgFirstSeen": "2020-02-22T12:52:35Z"
        }, 
        "IPAddress": "8.8.8.8"
    }
}
```

##### Human Readable Output
##### Statistics on 8.8.8.8 IP:
|OrgFirstSeen|OrgLastSeen|OrgPrevalence|
|---|---|---|
| 2020-02-22T12:52:35Z | 2020-03-01T15:19:40Z | 1 |


### 29. microsoft-atp-get-ip-alerts
---
Retrieves a collection of alerts related to a given IP address.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-get-ip-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The Ip address. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.IPAlert.IPAddress | String | The IP address. | 
| MicrosoftATP.IPAlert.Alerts.ID | String | The alert ID. | 
| MicrosoftATP.IPAlert.Alerts.IncidentID | Number | The incident ID of the alert. | 
| MicrosoftATP.IPAlert.Alerts.InvestigationID | Number | The investigation ID related to the alert. | 
| MicrosoftATP.IPAlert.Alerts.InvestigationState | String | The current state of the investigation. | 
| MicrosoftATP.IPAlert.Alerts.AssignedTo | String | The owner of the alert. | 
| MicrosoftATP.IPAlert.Alerts.Severity | String | The severity of the alert. | 
| MicrosoftATP.IPAlert.Alerts.Status | String | The current status of the alert. | 
| MicrosoftATP.IPAlert.Alerts.Classification | String | The alert classification. | 
| MicrosoftATP.IPAlert.Alerts.Determination | String | The determination of the alert. | 
| MicrosoftATP.IPAlert.Alerts.DetectionSource | String | The detection source. | 
| MicrosoftATP.IPAlert.Alerts.Category | String | The category of the alert. | 
| MicrosoftATP.IPAlert.Alerts.ThreatFamilyName | String | The family name of the threat. | 
| MicrosoftATP.IPAlert.Alerts.Title | String | The title of the alert. | 
| MicrosoftATP.IPAlert.Alerts.Description | String | The description of the alert. | 
| MicrosoftATP.IPAlert.Alerts.AlertCreationTime | Date | The date and time the alert was created. | 
| MicrosoftATP.IPAlert.Alerts.FirstEventTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.IPAlert.Alerts.LastEventTime | Date | The last event time that triggered the alert on that machine. | 
| MicrosoftATP.IPAlert.Alerts.LastUpdateTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.IPAlert.Alerts.ResolvedTime | Date | The date and time in which the status of the alert was changed to "Resolved". | 
| MicrosoftATP.IPAlert.Alerts.MachineID | String | The machine ID that is associated with the alert. | 
| MicrosoftATP.IPAlert.Alerts.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.IPAlert.Alerts.AADTenantID | String | The AAD tenant ID. | 
| MicrosoftATP.IPAlert.Alerts.Comments.Comment | String | The alert's comment string. | 
| MicrosoftATP.IPAlert.Alerts.Comments.CreatedBy | String | The alert comment created by the string. | 
| MicrosoftATP.IPAlert.Alerts.Comments.CreatedTime | Date | The time and date the alert comment was created. | 


##### Command Example
```!microsoft-atp-get-ip-alerts ip=8.8.8.8```

##### Context Example
```
{
    "MicrosoftATP.IPAlert": {
        "Alerts": [], 
        "IPAddress": "8.8.8.8"
    }
}
```

##### Human Readable Output
##### IP 8.8.8.8 related alerts Info:
**No entries.**


### 30. microsoft-atp-get-user-alerts
---
Retrieves a collection of alerts related to a given user ID.

##### Required Permissions
Alert.ReadWrite.All	

##### Base Command

`microsoft-atp-get-user-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The user ID. The ID is not the full UPN, but only the user name. For example, to retrieve alerts for "user1@test.com" use "user1". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.UserAlert.Username | String | The name of the user. | 
| MicrosoftATP.UserAlert.Alerts.ID | String | The ID of the alert. | 
| MicrosoftATP.UserAlert.Alerts.IncidentID | Number | The incident ID of the alert. | 
| MicrosoftATP.UserAlert.Alerts.InvestigationID | Number | The investigation ID related to the alert. | 
| MicrosoftATP.UserAlert.Alerts.InvestigationState | String | The current state of the investigation. | 
| MicrosoftATP.UserAlert.Alerts.AssignedTo | String | The owner of the alert. | 
| MicrosoftATP.UserAlert.Alerts.Severity | String | The severity of the alert. | 
| MicrosoftATP.UserAlert.Alerts.Status | String | The current status of the alert. | 
| MicrosoftATP.UserAlert.Alerts.Classification | String | The alert classification. | 
| MicrosoftATP.UserAlert.Alerts.Determination | String | The determination of the alert. | 
| MicrosoftATP.UserAlert.Alerts.DetectionSource | String | The detection source. | 
| MicrosoftATP.UserAlert.Alerts.Category | String | The category of the alert. | 
| MicrosoftATP.UserAlert.Alerts.ThreatFamilyName | String | The family name of the threat.  | 
| MicrosoftATP.UserAlert.Alerts.Title | String | The title of the alert. | 
| MicrosoftATP.UserAlert.Alerts.Description | String | The description of the alert. | 
| MicrosoftATP.UserAlert.Alerts.AlertCreationTime | Date | The date and time the alert was created. | 
| MicrosoftATP.UserAlert.Alerts.FirstEventTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.UserAlert.Alerts.LastEventTime | Date | The last event time that triggered the alert on that machine. | 
| MicrosoftATP.UserAlert.Alerts.LastUpdateTime | Date | The first event time that triggered the alert on that machine. | 
| MicrosoftATP.UserAlert.Alerts.ResolvedTime | Date | The date and time when the status of the alert was changed to "Resolved". | 
| MicrosoftATP.UserAlert.Alerts.MachineID | String | The machine ID that is associated with the alert. | 
| MicrosoftATP.UserAlert.Alerts.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.UserAlert.Alerts.AADTenantID | String | The AAD tenant ID. | 
| MicrosoftATP.UserAlert.Alerts.Comments.Comment | String | The comment string of the alert.| 
| MicrosoftATP.UserAlert.Alerts.Comments.CreatedBy | String | The alert comment created by the string. | 
| MicrosoftATP.UserAlert.Alerts.Comments.CreatedTime | Date | The time and date the alert comment was created. | 


##### Command Example
```!microsoft-atp-get-user-alerts username=demisto```

##### Context Example
```
{
    "MicrosoftATP.UserAlert": {
        "Username": "demisto", 
        "Alerts": [
            {
                "Category": "DefenseEvasion", 
                "ThreatFamilyName": null, 
                "Severity": "Medium", 
                "LastEventTime": "2020-02-17T11:39:09.9948632Z", 
                "FirstEventTime": "2020-02-17T11:37:11.4901408Z", 
                "Comments": [
                    {
                        "Comment": null, 
                        "CreatedTime": null, 
                        "CreatedBy": null
                    }
                ], 
                "AADTenantID": "TENANT-ID", 
                "AlertCreationTime": "2020-02-17T11:40:33.5724218Z", 
                "Status": "InProgress", 
                "Description": "A process abnormally injected code into another process, As a result, unexpected code may be running in the target process memory. Injection is often used to hide malicious code execution within a trusted process. \nAs a result, the target process may exhibit abnormal behaviors such as opening a listening port or connecting to a command and control server.", 
                "InvestigationState": "Benign", 
                "MachineID": "4899036531e374137f63289c3267bad772c13fef", 
                "Title": "Suspicious process injection observed", 
                "InvestigationID": 1, 
                "Determination": null, 
                "IncidentID": 7, 
                "AssignedTo": "Automation", 
                "DetectionSource": "WindowsDefenderAtp", 
                "ResolvedTime": null, 
                "ID": "da637175364336494657_410871946", 
                "LastUpdateTime": "2020-03-17T11:29:55.0066667Z", 
                "Classification": null, 
                "ComputerDNSName": "desktop-s2455r8", 
                "Evidence": [
                    {
                        "userPrincipalName": null, 
                        "processId": 11192, 
                        "sha1": "36c5d12033b2eaf251bae61c00690ffb17fddc87", 
                        "parentProcessCreationTime": "2020-02-17T08:03:34.9841426Z", 
                        "domainName": null, 
                        "url": null, 
                        "processCommandLine": "\"powershell.exe\" ", 
                        "entityType": "Process", 
                        "processCreationTime": "2020-02-17T12:38:47.6521977Z", 
                        "aadUserId": null, 
                        "fileName": "powershell.exe", 
                        "sha256": "908b64b1971a979c7e3e8ce4621945cba84854cb98d76367b791a6e22b5f6d53", 
                        "parentProcessId": 9008, 
                        "userSid": null, 
                        "filePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0", 
                        "accountName": null, 
                        "ipAddress": null
                    }, 
                    {
                        "userPrincipalName": null, 
                        "processId": 12508, 
                        "sha1": "d487580502354c61808c7180d1a336beb7ad4624", 
                        "parentProcessCreationTime": "2020-02-17T12:38:47.6521977Z", 
                        "domainName": null, 
                        "url": null, 
                        "processCommandLine": "\"notepad.exe\"", 
                        "entityType": "Process", 
                        "processCreationTime": "2020-02-17T12:41:04.9040946Z", 
                        "aadUserId": null, 
                        "fileName": "notepad.exe", 
                        "sha256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3", 
                        "parentProcessId": 11192, 
                        "userSid": null, 
                        "filePath": "C:\\Windows\\System32", 
                        "accountName": null, 
                        "ipAddress": null
                    }, 
                    {
                        "userPrincipalName": null, 
                        "processId": null, 
                        "sha1": null, 
                        "parentProcessCreationTime": null, 
                        "domainName": "DESKTOP-S2455R8", 
                        "url": null, 
                        "processCommandLine": null, 
                        "entityType": "User", 
                        "processCreationTime": null, 
                        "aadUserId": null, 
                        "fileName": null, 
                        "sha256": null, 
                        "parentProcessId": null, 
                        "userSid": "S-1-5-21-4197691174-1403503641-4006700887-1001", 
                        "filePath": null, 
                        "accountName": "demisto", 
                        "ipAddress": null
                    }, 
                    {
                        "userPrincipalName": null, 
                        "processId": 8936, 
                        "sha1": "d487580502354c61808c7180d1a336beb7ad4624", 
                        "parentProcessCreationTime": "2020-02-17T12:38:47.6521977Z", 
                        "domainName": null, 
                        "url": null, 
                        "processCommandLine": "\"notepad.exe\"", 
                        "entityType": "Process", 
                        "processCreationTime": "2020-02-17T12:39:16.3783602Z", 
                        "aadUserId": null, 
                        "fileName": "notepad.exe", 
                        "sha256": "f1d62648ef915d85cb4fc140359e925395d315c70f3566b63bb3e21151cb2ce3", 
                        "parentProcessId": 11192, 
                        "userSid": null, 
                        "filePath": "C:\\Windows\\System32", 
                        "accountName": null, 
                        "ipAddress": null
                    }
                ]
            }

                ]
            }
        ]
    }
}
```

##### Human Readable Output
##### User XSOAR related alerts Info:
|ID|Title|Description|IncidentID|Severity|Status|Category|MachineID|
|---|---|---|---|---|---|---|---|
| da637175364336494657_410871946 | Suspicious process injection observed | A process abnormally injected code into another process, As a result, unexpected code may be running in the target process memory. Injection is often used to hide malicious code execution within a trusted process. As a result, the target process may exhibit abnormal behaviors such as opening a listening port or connecting to a command and control server. | 7 | Medium | InProgress | DefenseEvasion | 4899036531e374137f63289c3267bad772c13fef |


### 31. microsoft-atp-get-user-machines
---
Retrieves a collection of machines related to a given user ID.

##### Required Permissions
Machine.ReadWrite.All

##### Base Command

`microsoft-atp-get-user-machines`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The user ID. The ID is not the full UPN, but only the user name. For example, to retrieve machines for "user1@test.com" use "user1". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.UserMachine.Username | String | The name of the user. | 
| MicrosoftATP.UserMachine.Machines.ID | String | The ID of the machine. | 
| MicrosoftATP.UserMachine.Machines.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.UserMachine.Machines.FirstSeen | Date | The first date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.UserMachine.Machines.LastSeen | Date | The last date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.UserMachine.Machines.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.UserMachine.Machines.OSVersion | String | The operating system version. | 
| MicrosoftATP.UserMachine.Machines.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.v.Machines.LastIPAddress | String | The last IP address on the machine. | 
| MicrosoftATP.UserMachine.Machines.LastExternalIPAddress | String | The last IP address through which the machine accessed the internet. | 
| MicrosoftATP.UserMachine.Machines.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.UserMachine.Machines.HealthStatus | String | The  health status of the machine. | 
| MicrosoftATP.UserMachine.Machines.RBACGroupID | Number | The RBAC group ID of the machine. | 
| MicrosoftATP.UserMachine.Machines.RBACGroupName | String | The RBAC group name of the machine. | 
| MicrosoftATP.UserMachine.Machines.RiskScore | String | The risk score of the machine. | 
| MicrosoftATP.UserMachine.Machines.ExposureLevel | String | The exposure level of the machine. | 
| MicrosoftATP.UserMachine.Machines.IsAADJoined | Boolean | Whether the machine is AAD joined. | 
| MicrosoftATP.UserMachine.Machines.AADDeviceID | String | The AAD device ID. | 
| MicrosoftATP.UserMachine.Machines.MachineTags | String | The set of machine tags. | 


##### Command Example
```!microsoft-atp-get-user-machines username=demisto```

##### Context Example
```
{
    "MicrosoftATP.UserMachine": {
        "Username": "demisto", 
        "Machines": [
            {
                "OSBuild": 18363, 
                "ExposureLevel": "Medium", 
                "OSPlatform": "Windows10", 
                "MachineTags": [
                    "test Tag 2", 
                    "test Tag 5"
                ], 
                "AADDeviceID": "cfcf4177-227e-4cdb-ac8e-f9a3da1ca30c", 
                "ComputerDNSName": "desktop-s2455r8", 
                "RBACGroupID": 0, 
                "OSProcessor": "x64", 
                "HealthStatus": "Active", 
                "AgentVersion": "10.6940.18362.693", 
                "LastExternalIPAddress": "81.166.99.236", 
                "LastIPAddress": "192.168.1.71", 
                "OSVersion": "1909", 
                "RiskScore": "High", 
                "ID": "4899036531e374137f63289c3267bad772c13fef", 
                "FirstSeen": "2020-02-17T08:30:07.2415577Z", 
                "LastSeen": "2020-03-23T08:10:41.473428Z"
            }, 
            {
                "OSBuild": 18363, 
                "ExposureLevel": "Medium", 
                "OSPlatform": "Windows10", 
                "MachineTags": [
                    "test add tag", 
                    "testing123"
                ], 
                "ComputerDNSName": "desktop-s2455r9", 
                "RBACGroupID": 0, 
                "OSProcessor": "x64", 
                "HealthStatus": "Active", 
                "AgentVersion": "10.6940.18362.693", 
                "LastExternalIPAddress": "81.166.99.236", 
                "LastIPAddress": "192.168.1.73", 
                "OSVersion": "1909", 
                "RiskScore": "Medium", 
                "ID": "f70f9fe6b29cd9511652434919c6530618f06606", 
                "FirstSeen": "2020-02-20T14:44:11.4627779Z", 
                "LastSeen": "2020-03-23T07:55:50.9986715Z"
            }
        ]
    }
}
```

##### Human Readable Output
##### Machines that are related to user XSOAR:
|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|
|---|---|---|---|---|---|---|---|
| 4899036531e374137f63289c3267bad772c13fef | desktop-s2455r8 | Windows10 | 192.168.1.71 | 81.166.99.236 | Active | High | Medium |
| f70f9fe6b29cd9511652434919c6530618f06606 | desktop-s2455r9 | Windows10 | 192.168.1.73 | 81.166.99.236 | Active | Medium | Medium |


### 32. microsoft-atp-add-remove-machine-tag
---
Adds or removes a tag on a specific Machine.

##### Required Permissions
Machine.ReadWrite.All

##### Base Command

`microsoft-atp-add-remove-machine-tag`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The ID of the machine. | Required | 
| action | The action to use for the tag. | Required | 
| tag | The name of the tag. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Machine.ID | String | The ID of the machine. | 
| MicrosoftATP.Machine.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.Machine.FirstSeen | Date | The first date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.LastSeen | Date | The last date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.Machine.OSVersion | String | The operating system version. | 
| MicrosoftATP.Machine.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.Machine.LastIPAddress | String | The last IP address on the machine. | 
| MicrosoftATP.Machine.LastExternalIPAddress | String | The last IP address through which the machine accessed the internet. | 
| MicrosoftATP.Machine.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.Machine.HealthStatus | String | The health status of the machine.| 
| MicrosoftATP.Machine.RBACGroupID | Number | The RBAC group ID of the machine. | 
| MicrosoftATP.Machine.RBACGroupName | String | The RBAC group name of the machine. | 
| MicrosoftATP.Machine.RiskScore | String | The risk score of the machine.| 
| MicrosoftATP.Machine.ExposureLevel | String | The exposure level of the machine. | 
| MicrosoftATP.Machine.IsAADJoined | Boolean | Whether the machine is AAD joined. | 
| MicrosoftATP.Machine.AADDeviceID | String | The AAD device ID. | 
| MicrosoftATP.Machine.MachineTags | String | The set of machine tags. | 


##### Command Example
```!microsoft-atp-add-remove-machine-tag action=Add machine_id=f70f9fe6b29cd9511652434919c6530618f06606 tag="test add tag"```

##### Context Example
```
{
    "MicrosoftATP.Machine": {
        "OSBuild": 18363, 
        "ExposureLevel": "Medium", 
        "OSPlatform": "Windows10", 
        "MachineTags": [
            "test add tag", 
            "testing123"
        ], 
        "ComputerDNSName": "desktop-s2455r9", 
        "RBACGroupID": 0, 
        "OSProcessor": "x64", 
        "HealthStatus": "Active", 
        "AgentVersion": "10.6940.18362.693", 
        "LastExternalIPAddress": "81.166.99.236", 
        "LastIPAddress": "192.168.1.73", 
        "OSVersion": "1909", 
        "RiskScore": "Medium", 
        "ID": "f70f9fe6b29cd9511652434919c6530618f06606", 
        "FirstSeen": "2020-02-20T14:44:11.4627779Z", 
        "LastSeen": "2020-03-23T07:55:50.9986715Z"
    }
}
```

##### Human Readable Output
##### Succeed to Add tag to f70f9fe6b29cd9511652434919c6530618f06606:
|ID|ComputerDNSName|OSPlatform|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|MachineTags|
|---|---|---|---|---|---|---|---|
| f70f9fe6b29cd9511652434919c6530618f06606 | desktop-s2455r9 | Windows10 | 81.166.99.236 | Active | Medium | Medium | test add tag, testing123 |

### microsoft-atp-indicator-list
***
Deprecated. Use the microsoft-atp-sc-indicator-list command instead. Lists all indicators by the ID that the system creates when the indicator is ingested.


#### Base Command

`microsoft-atp-indicator-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional | 
| page_size | Specify the page size of the result set. Maximum is 200. Default value is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: unknown, allow, block, alert. | 
| MicrosoftATP.Indicators.additionalInformation | String | A catchall area into which extra data from the indicator not covered by the other tiIndicator properties may be placed. Data placed into additionalInformation is typically not be utilized by the targetProduct security tool. | 
| MicrosoftATP.Indicators.azureTenantId | String | Stamped by the system when the indicator is ingested. The Azure Active Directory tenant ID of submitting client. | 
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100, with 100 being the highest. | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.diamondModel | String | The area of the Diamond Model in which this indicator exists. Possible values are: "unknown", "adversary", "capability", "infrastructure", "victim". | 
| MicrosoftATP.Indicators.domainName | String | Domain name associated with this indicator. Should be in the format subdomain.domain.topleveldomain. | 
| MicrosoftATP.Indicators.emailEncoding | String | The type of text encoding used in the email. | 
| MicrosoftATP.Indicators.emailLanguage | String | The language of the email. | 
| MicrosoftATP.Indicators.emailRecipient | String | Recipient email address. | 
| MicrosoftATP.Indicators.emailSenderAddress | String | Email address of the attacker|victim. | 
| MicrosoftATP.Indicators.emailSenderName | String | Display name of the attacker|victim.. | 
| MicrosoftATP.Indicators.emailSourceDomain | String | Domain used in the email. | 
| MicrosoftATP.Indicators.emailSourceIpAddress | String | Source IP address of the email. | 
| MicrosoftATP.Indicators.emailSubject | String | Subject line of the email. | 
| MicrosoftATP.Indicators.emailXMailer | String | X-Mailer value used in the email. | 
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: "unknown", "sha1", "sha256", "md5", "authenticodeHash256", "lsHash", and "ctph". | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.networkCidrBlock | String | CIDR Block notation representation of the network referenced in this indicator. Use only if the Source and Destination cannot be identified. | 
| MicrosoftATP.Indicators.networkDestinationAsn | Number | The destination autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkDestinationCidrBlock | String | CIDR Block notation representation of the destination network in this indicator. | 
| MicrosoftATP.Indicators.networkDestinationIPv4 | String | IPv4 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationIPv6 | String | IPv6 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationPort | Number | TCP port destination. | 
| MicrosoftATP.Indicators.networkIPv4 | String | IPv4 IP address. | 
| MicrosoftATP.Indicators.networkIPv6 | String | IPv6 IP address. | 
| MicrosoftATP.Indicators.networkPort | Number | TCP port. | 
| MicrosoftATP.Indicators.networkProtocol | Number | Decimal representation of the protocol field in the IPv4 header. | 
| MicrosoftATP.Indicators.networkSourceAsn | Number | The source autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkSourceCidrBlock | String | CIDR Block notation representation of the source network in this indicator. | 
| MicrosoftATP.Indicators.networkSourceIPv4 | String | IPv4 IP address source. | 
| MicrosoftATP.Indicators.networkSourceIPv6 | String | IPv6 IP address source. | 
| MicrosoftATP.Indicators.networkSourcePort | Number | TCP port source. | 
| MicrosoftATP.Indicators.passiveOnly | Boolean | Determines if the indicator should trigger an event that is visible to an end-user. When set to ‘true,’ security tools will not notify the end user that a ‘hit’ has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. Default value is false. | 
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Possible values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
| MicrosoftATP.Indicators.targetProduct | String | A string value representing a single security product to which the indicator should be applied. | 
| MicrosoftATP.Indicators.threatType | String | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList. | 
| MicrosoftATP.Indicators.tlpLevel | String | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, amber, and red. | 
| MicrosoftATP.Indicators.url | String | Uniform Resource Locator. This URL complies with RFC 1738. | 
| MicrosoftATP.Indicators.userAgent | String | User-Agent string from a web request that could indicate compromise. | 
| MicrosoftATP.Indicators.vendorInformation | String | Information about the vendor. | 


#### Command Example
```!microsoft-atp-indicator-list```

#### Context Example
```
{
    "MicrosoftATP": {
        "Indicators": {
            "action": "block",
            "activityGroupNames": [],
            "azureTenantId": "TENANT-ID",
            "description": "Title: Indicator Jacoviya.net of type DomainName, Description: Blob!",
            "domainName": "jacoviya.net",
            "expirationDateTime": "2020-09-02T17:08:46Z",
            "id": "16",
            "ingestedDateTime": "2020-08-26T17:08:49.158136Z",
            "isActive": true,
            "killChain": [],
            "malwareFamilyNames": [],
            "severity": 2,
            "tags": [],
            "targetProduct": "Microsoft Defender ATP"
        }
    }
}
```

#### Human Readable Output

>### Indicators from Microsoft ATP:
>|id|action|severity|domainName|
>|---|---|---|---|
>| 16 | block | 2 | jacoviya.net |

### microsoft-atp-indicator-get-by-id
***
Deprecated. Use the microsoft-atp-sc-indicator-get-by-id command instead. Gets an indicator by its ID.


#### Base Command

`microsoft-atp-indicator-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The ID of the indicator to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: unknown, allow, block, alert. | 
| MicrosoftATP.Indicators.additionalInformation | String | A catchall area into which extra data from the indicator not covered by the other tiIndicator properties may be placed. Data placed into additionalInformation will typically not be utilized by the targetProduct security tool. | 
| MicrosoftATP.Indicators.azureTenantId | String | Timestamp when the indicator was ingested into the system. | 
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100, with 100 being the highest. | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.diamondModel | String | The area of the Diamond Model in which this indicator exists. Possible values are: unknown, adversary, capability, infrastructure, victim. | 
| MicrosoftATP.Indicators.domainName | String | Domain name associated with this indicator. Should be in the format subdomain.domain.topleveldomain. | 
| MicrosoftATP.Indicators.emailEncoding | String | The type of text encoding used in the email. | 
| MicrosoftATP.Indicators.emailLanguage | String | The language of the email. | 
| MicrosoftATP.Indicators.emailRecipient | String | Recipient email address. | 
| MicrosoftATP.Indicators.emailSenderAddress | String | Email address of the attacker|victim. | 
| MicrosoftATP.Indicators.emailSenderName | String | Display name of the attacker|victim.. | 
| MicrosoftATP.Indicators.emailSourceDomain | String | Domain used in the email. | 
| MicrosoftATP.Indicators.emailSourceIpAddress | String | Source IP address of the email. | 
| MicrosoftATP.Indicators.emailSubject | String | Subject line of the email. | 
| MicrosoftATP.Indicators.emailXMailer | String | X-Mailer value used in the email. | 
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.networkCidrBlock | String | CIDR Block notation representation of the network referenced in this indicator. Use only if the Source and Destination cannot be identified. | 
| MicrosoftATP.Indicators.networkDestinationAsn | Number | The destination autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkDestinationCidrBlock | String | CIDR Block notation representation of the destination network in this indicator. | 
| MicrosoftATP.Indicators.networkDestinationIPv4 | String | IPv4 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationIPv6 | String | IPv6 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationPort | Number | TCP port destination. | 
| MicrosoftATP.Indicators.networkIPv4 | String | IPv4 IP address. | 
| MicrosoftATP.Indicators.networkIPv6 | String | IPv6 IP address. | 
| MicrosoftATP.Indicators.networkPort | Number | TCP port. | 
| MicrosoftATP.Indicators.networkProtocol | Number | Decimal representation of the protocol field in the IPv4 header. | 
| MicrosoftATP.Indicators.networkSourceAsn | Number | The source autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkSourceCidrBlock | String | CIDR Block notation representation of the source network in this indicator. | 
| MicrosoftATP.Indicators.networkSourceIPv4 | String | IPv4 IP address source. | 
| MicrosoftATP.Indicators.networkSourceIPv6 | String | IPv6 IP address source. | 
| MicrosoftATP.Indicators.networkSourcePort | Number | TCP port source. | 
| MicrosoftATP.Indicators.passiveOnly | Boolean | Determines if the indicator should trigger an event that is visible to an end-user. When set to ‘true,’ security tools will not notify the end user that a ‘hit’ has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. Default value is false. | 
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Possible values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
| MicrosoftATP.Indicators.targetProduct | String | A string value representing a single security product to which the indicator should be applied. | 
| MicrosoftATP.Indicators.threatType | String | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList. | 
| MicrosoftATP.Indicators.tlpLevel | String | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. Possible values are: unknown, white, green, amber, and red. | 
| MicrosoftATP.Indicators.url | String | Uniform Resource Locator. This URL complies with RFC 1738. | 
| MicrosoftATP.Indicators.userAgent | String | User-Agent string from a web request that could indicate compromise. | 
| MicrosoftATP.Indicators.vendorInformation | String | Information about the vendor. | 

#### Command Example
```!microsoft-atp-indicator-get-by-id indicator_id=17```

#### Context Example
```
{
    "MicrosoftATP": {
        "Indicators": {
            "action": "block",
            "activityGroupNames": [],
            "azureTenantId": "TENANT-ID",
            "description": "Title: Indicator example.com of type DomainName, Description: A description!",
            "domainName": "example.com",
            "expirationDateTime": "2020-09-02T17:17:57Z",
            "id": "17",
            "ingestedDateTime": "2020-08-26T17:18:00.0537984Z",
            "isActive": true,
            "killChain": [],
            "malwareFamilyNames": [],
            "severity": 2,
            "tags": [],
            "targetProduct": "Microsoft Defender ATP"
        }
    }
}
```

#### Human Readable Output

>### Indicators from Microsoft ATP:
>|id|action|severity|domainName|
>|---|---|---|---|
>| 17 | block | 2 | example.com |


### microsoft-atp-indicator-create-network
***
Deprecated. Use the microsoft-atp-sc-indicator-create command instead. Creates a network indicator.


#### Base Command

`microsoft-atp-indicator-create-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to apply if the indicator is matched from within the targetProduct security tool. | Required | 
| description | Brief description (100 characters or less) of the threat represented by the indicator. | Required | 
| expiration_time | DateTime string indicating when the indicator expires. Format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). | Required | 
| threat_type | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, Cryptomining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, or WatchList. | Required | 
| tlp_level | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. | Optional | 
| confidence | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100 with 100 being the highest. | Optional | 
| severity | The severity of the malicious behavior identified by the data within the indicator. Possible values are Informational, Low, MediumLow, MediumHigh, High, where 5 is the most severe and zero is not severe at all. | Optional | 
| tags | A comma-separated list that stores arbitrary tags/keywords. | Optional | 
| domain_name | Domain name associated with this indicator. Should be in the format subdomain.domain.topleveldomain (For example, baddomain.domain.net) | Optional | 
| network_cidr_block | CIDR Block notation representation of the network referenced in this indicator. Use only if the Source and Destination cannot be identified. | Optional | 
| network_destination_asn | The destination autonomous system identifier of the network referenced in the indicator. | Optional | 
| network_destination_cidr_block | CIDR Block notation representation of the destination network in this indicator. | Optional | 
| network_destination_ipv4 | IPv4 IP address destination. | Optional | 
| network_destination_ipv6 | IPv6 IP address destination.<br/> | Optional | 
| network_destination_port | TCP port destination. | Optional | 
| network_ipv4 | IPv4 IP address. Use only if the Source and Destination cannot be identified. | Optional | 
| network_ipv6 | IPv6 IP address. Use only if the Source and Destination cannot be identified. | Optional | 
| network_port | TCP port. Use only if the Source and Destination cannot be identified. | Optional | 
| network_protocol | Decimal representation of the protocol field in the IPv4 header. | Optional | 
| network_source_asn | The source autonomous system identifier of the network referenced in the indicator. | Optional | 
| network_source_cidr_block | CIDR Block notation representation of the source network in this indicator. | Optional | 
| network_source_ipv4 | IPv4 IP address source. | Optional | 
| network_source_ipv6 | IPv6 IP address source. | Optional | 
| network_source_port | TCP port source. | Optional | 
| url | Uniform Resource Locator. This URL must comply with RFC 1738. | Optional | 
| user_agent | User-Agent string from a web request that could indicate compromise. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: unknown, allow, block, alert. | 
| MicrosoftATP.Indicators.additionalInformation | String | A catchall area into which extra data from the indicator not covered by the other tiIndicator properties may be placed. Data placed into additionalInformation will typically not be utilized by the targetProduct security tool. | 
| MicrosoftATP.Indicators.azureTenantId | String | Timestamp when the indicator was ingested into the system. | 
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100, with 100 being the highest. | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.diamondModel | String | The area of the Diamond Model in which this indicator exists. Possible values are: unknown, adversary, capability, infrastructure, victim. | 
| MicrosoftATP.Indicators.domainName | String | Domain name associated with this indicator. Should be in the format subdomain.domain.topleveldomain. | 
| MicrosoftATP.Indicators.emailEncoding | String | The type of text encoding used in the email. | 
| MicrosoftATP.Indicators.emailLanguage | String | The language of the email. | 
| MicrosoftATP.Indicators.emailRecipient | String | Recipient email address. | 
| MicrosoftATP.Indicators.emailSenderAddress | String | Email address of the attacker|victim. | 
| MicrosoftATP.Indicators.emailSenderName | String | Display name of the attacker|victim.. | 
| MicrosoftATP.Indicators.emailSourceDomain | String | Domain used in the email. | 
| MicrosoftATP.Indicators.emailSourceIpAddress | String | Source IP address of the email. | 
| MicrosoftATP.Indicators.emailSubject | String | Subject line of the email. | 
| MicrosoftATP.Indicators.emailXMailer | String | X-Mailer value used in the email. | 
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.networkCidrBlock | String | CIDR Block notation representation of the network referenced in this indicator. Use only if the Source and Destination cannot be identified. | 
| MicrosoftATP.Indicators.networkDestinationAsn | Number | The destination autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkDestinationCidrBlock | String | CIDR Block notation representation of the destination network in this indicator. | 
| MicrosoftATP.Indicators.networkDestinationIPv4 | String | IPv4 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationIPv6 | String | IPv6 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationPort | Number | TCP port destination. | 
| MicrosoftATP.Indicators.networkIPv4 | String | IPv4 IP address. | 
| MicrosoftATP.Indicators.networkIPv6 | String | IPv6 IP address. | 
| MicrosoftATP.Indicators.networkPort | Number | TCP port. | 
| MicrosoftATP.Indicators.networkProtocol | Number | Decimal representation of the protocol field in the IPv4 header. | 
| MicrosoftATP.Indicators.networkSourceAsn | Number | The source autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkSourceCidrBlock | String | CIDR Block notation representation of the source network in this indicator. | 
| MicrosoftATP.Indicators.networkSourceIPv4 | String | IPv4 IP address source. | 
| MicrosoftATP.Indicators.networkSourceIPv6 | String | IPv6 IP address source. | 
| MicrosoftATP.Indicators.networkSourcePort | Number | TCP port source. | 
| MicrosoftATP.Indicators.passiveOnly | Boolean | Determines if the indicator should trigger an event that is visible to an end-user. When set to ‘true,’ security tools will not notify the end user that a ‘hit’ has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. Default value is false. | 
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Possible values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
| MicrosoftATP.Indicators.targetProduct | String | A string value representing a single security product to which the indicator should be applied. | 
| MicrosoftATP.Indicators.threatType | String | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList. | 
| MicrosoftATP.Indicators.tlpLevel | String | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. Possible values are: unknown, white, green, amber, and red. | 
| MicrosoftATP.Indicators.url | String | Uniform Resource Locator. This URL complies with RFC 1738. | 
| MicrosoftATP.Indicators.userAgent | String | User-Agent string from a web request that could indicate compromise. | 
| MicrosoftATP.Indicators.vendorInformation | String | Information about the vendor. | 

#### Command Example
```!microsoft-atp-indicator-create-network action=unknown description="A description!" expiration_time="7 days" threat_type=CryptoMining domain_name="example.com"```

#### Context Example
```
{
    "MicrosoftATP": {
        "Indicators": {
            "action": "block",
            "activityGroupNames": [],
            "azureTenantId": "TENANT-ID",
            "description": "Title: Indicator example.com of type DomainName, Description: A description!",
            "domainName": "example.com",
            "expirationDateTime": "2020-09-02T17:17:57Z",
            "id": "17",
            "ingestedDateTime": "2020-08-26T17:18:00.0537984Z",
            "isActive": true,
            "killChain": [],
            "malwareFamilyNames": [],
            "severity": 2,
            "tags": [],
            "targetProduct": "Microsoft Defender ATP"
        }
    }
}
```

#### Human Readable Output

>### Indicator 17 was successfully created:
>|id|action|severity|domainName|
>|---|---|---|---|
>| 17 | block | 2 | example.com |

### microsoft-atp-indicator-create-file
***
Deprecated. Use the microsoft-atp-sc-indicator-create command instead. Creates a file indicator


#### Base Command

`microsoft-atp-indicator-create-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to apply if the indicator is matched from within the targetProduct security tool. | Required | 
| description | Brief description (100 characters or less) of the threat represented by the indicator. | Required | 
| expiration_time | DateTime string indicating when the indicator expires. Format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). | Required | 
| threat_type | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, Cryptomining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, or WatchList. | Required | 
| tlp_level | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. | Optional | 
| confidence | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100 with 100 being the highest. | Optional | 
| severity | The severity of the malicious behavior identified by the data within the indicator. Possible values are Informational, Low, MediumLow, MediumHigh, High, where 5 is the most severe and zero is not severe at all. | Optional | 
| tags | A comma-separated list that stores arbitrary tags/keywords. | Optional | 
| file_compile_date_time | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | Optional | 
| file_created_date_time | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | Optional | 
| file_hash_type | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. | Optional | 
| file_hash_value | The file hash value. | Optional | 
| file_mutex_name | Mutex name used in file-based detections. | Optional | 
| file_name | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | Optional | 
| file_packer | The packer used to build the file in question. | Optional | 
| file_path | Path of the file indicating a compromise. Can be a Windows or *nix style path. | Optional | 
| file_size | Size of the file in bytes. | Optional | 
| file_type | Text description of the type of file. For example, “Word Document” or “Binary”. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: unknown, allow, block, alert. | 
| MicrosoftATP.Indicators.additionalInformation | String | A catchall area into which extra data from the indicator not covered by the other tiIndicator properties may be placed. Data placed into additionalInformation will typically not be utilized by the targetProduct security tool. | 
| MicrosoftATP.Indicators.azureTenantId | String | Timestamp when the indicator was ingested into the system. | 
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100, with 100 being the highest. | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.diamondModel | String | The area of the Diamond Model in which this indicator exists. Possible values are: unknown, adversary, capability, infrastructure, victim. | 
| MicrosoftATP.Indicators.domainName | String | Domain name associated with this indicator. Should be in the format subdomain.domain.topleveldomain. | 
| MicrosoftATP.Indicators.emailEncoding | String | The type of text encoding used in the email. | 
| MicrosoftATP.Indicators.emailLanguage | String | The language of the email. | 
| MicrosoftATP.Indicators.emailRecipient | String | Recipient email address. | 
| MicrosoftATP.Indicators.emailSenderAddress | String | Email address of the attacker|victim. | 
| MicrosoftATP.Indicators.emailSenderName | String | Display name of the attacker|victim.. | 
| MicrosoftATP.Indicators.emailSourceDomain | String | Domain used in the email. | 
| MicrosoftATP.Indicators.emailSourceIpAddress | String | Source IP address of the email. | 
| MicrosoftATP.Indicators.emailSubject | String | Subject line of the email. | 
| MicrosoftATP.Indicators.emailXMailer | String | X-Mailer value used in the email. | 
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.networkCidrBlock | String | CIDR Block notation representation of the network referenced in this indicator. Use only if the Source and Destination cannot be identified. | 
| MicrosoftATP.Indicators.networkDestinationAsn | Number | The destination autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkDestinationCidrBlock | String | CIDR Block notation representation of the destination network in this indicator. | 
| MicrosoftATP.Indicators.networkDestinationIPv4 | String | IPv4 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationIPv6 | String | IPv6 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationPort | Number | TCP port destination. | 
| MicrosoftATP.Indicators.networkIPv4 | String | IPv4 IP address. | 
| MicrosoftATP.Indicators.networkIPv6 | String | IPv6 IP address. | 
| MicrosoftATP.Indicators.networkPort | Number | TCP port. | 
| MicrosoftATP.Indicators.networkProtocol | Number | Decimal representation of the protocol field in the IPv4 header. | 
| MicrosoftATP.Indicators.networkSourceAsn | Number | The source autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkSourceCidrBlock | String | CIDR Block notation representation of the source network in this indicator. | 
| MicrosoftATP.Indicators.networkSourceIPv4 | String | IPv4 IP address source. | 
| MicrosoftATP.Indicators.networkSourceIPv6 | String | IPv6 IP address source. | 
| MicrosoftATP.Indicators.networkSourcePort | Number | TCP port source. | 
| MicrosoftATP.Indicators.passiveOnly | Boolean | Determines if the indicator should trigger an event that is visible to an end-user. When set to ‘true,’ security tools will not notify the end user that a ‘hit’ has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. Default value is false. | 
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Possible values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
| MicrosoftATP.Indicators.targetProduct | String | A string value representing a single security product to which the indicator should be applied. | 
| MicrosoftATP.Indicators.threatType | String | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList. | 
| MicrosoftATP.Indicators.tlpLevel | String | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. Possible values are: unknown, white, green, amber, and red. | 
| MicrosoftATP.Indicators.url | String | Uniform Resource Locator. This URL complies with RFC 1738. | 
| MicrosoftATP.Indicators.userAgent | String | User-Agent string from a web request that could indicate compromise. | 
| MicrosoftATP.Indicators.vendorInformation | String | Information about the vendor. | 

#### Command Example
```!microsoft-atp-indicator-create-file action=allow description="A description" expiration_time="3 days" threat_type=Darknet confidence=23 file_hash_type=sha256 file_hash_value=50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c```

#### Context Example
```
{
    "MicrosoftATP": {
        "Indicators": {
            "action": "allow",
            "activityGroupNames": [],
            "azureTenantId": "TENANT-ID",
            "description": "Title: Indicator 50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c of type FileSha256, Description: A description",
            "expirationDateTime": "2020-08-29T17:18:01Z",
            "fileHashType": "sha256",
            "fileHashValue": "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
            "id": "18",
            "ingestedDateTime": "2020-08-26T17:18:03.5249643Z",
            "isActive": true,
            "killChain": [],
            "malwareFamilyNames": [],
            "severity": 2,
            "tags": [],
            "targetProduct": "Microsoft Defender ATP"
        }
    }
}
```

#### Human Readable Output

>### Indicator 18 was successfully created:
>|id|action|severity|fileHashType|fileHashValue|
>|---|---|---|---|---|
>| 18 | allow | 2 | sha256 | 50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c |

### microsoft-atp-indicator-update
***
Deprecated. Use the microsoft-atp-sc-indicator-update command instead. Updates the specified indicator.


#### Base Command

`microsoft-atp-indicator-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The ID of the indicator to update. | Required | 
| severity | The severity of the malicious behavior identified by the data within the indicator. Possible values are Informational, Low, MediumLow, MediumHigh, High, where High is the most severe and Informational is not severe at all. | Optional | 
| expiration_time | DateTime string indicating when the indicator expires. Format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). | Required | 
| description | Brief description (100 characters or less) of the threat represented by the indicator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: unknown, allow, block, alert. | 
| MicrosoftATP.Indicators.additionalInformation | String | A catchall area into which extra data from the indicator not covered by the other tiIndicator properties may be placed. Data placed into additionalInformation will typically not be utilized by the targetProduct security tool. | 
| MicrosoftATP.Indicators.azureTenantId | String | Timestamp when the indicator was ingested into the system. | 
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100, with 100 being the highest. | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.diamondModel | String | The area of the Diamond Model in which this indicator exists. Possible values are: unknown, adversary, capability, infrastructure, victim. | 
| MicrosoftATP.Indicators.domainName | String | Domain name associated with this indicator. Should be in the format subdomain.domain.topleveldomain. | 
| MicrosoftATP.Indicators.emailEncoding | String | The type of text encoding used in the email. | 
| MicrosoftATP.Indicators.emailLanguage | String | The language of the email. | 
| MicrosoftATP.Indicators.emailRecipient | String | Recipient email address. | 
| MicrosoftATP.Indicators.emailSenderAddress | String | Email address of the attacker|victim. | 
| MicrosoftATP.Indicators.emailSenderName | String | Display name of the attacker|victim.. | 
| MicrosoftATP.Indicators.emailSourceDomain | String | Domain used in the email. | 
| MicrosoftATP.Indicators.emailSourceIpAddress | String | Source IP address of the email. | 
| MicrosoftATP.Indicators.emailSubject | String | Subject line of the email. | 
| MicrosoftATP.Indicators.emailXMailer | String | X-Mailer value used in the email. | 
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.networkCidrBlock | String | CIDR Block notation representation of the network referenced in this indicator. Use only if the Source and Destination cannot be identified. | 
| MicrosoftATP.Indicators.networkDestinationAsn | Number | The destination autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkDestinationCidrBlock | String | CIDR Block notation representation of the destination network in this indicator. | 
| MicrosoftATP.Indicators.networkDestinationIPv4 | String | IPv4 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationIPv6 | String | IPv6 IP address destination. | 
| MicrosoftATP.Indicators.networkDestinationPort | Number | TCP port destination. | 
| MicrosoftATP.Indicators.networkIPv4 | String | IPv4 IP address. | 
| MicrosoftATP.Indicators.networkIPv6 | String | IPv6 IP address. | 
| MicrosoftATP.Indicators.networkPort | Number | TCP port. | 
| MicrosoftATP.Indicators.networkProtocol | Number | Decimal representation of the protocol field in the IPv4 header. | 
| MicrosoftATP.Indicators.networkSourceAsn | Number | The source autonomous system identifier of the network referenced in the indicator. | 
| MicrosoftATP.Indicators.networkSourceCidrBlock | String | CIDR Block notation representation of the source network in this indicator. | 
| MicrosoftATP.Indicators.networkSourceIPv4 | String | IPv4 IP address source. | 
| MicrosoftATP.Indicators.networkSourceIPv6 | String | IPv6 IP address source. | 
| MicrosoftATP.Indicators.networkSourcePort | Number | TCP port source. | 
| MicrosoftATP.Indicators.passiveOnly | Boolean | Determines if the indicator should trigger an event that is visible to an end-user. When set to ‘true,’ security tools will not notify the end user that a ‘hit’ has occurred. This is most often treated as audit or silent mode by security products where they will simply log that a match occurred but will not perform the action. Default value is false. | 
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Possible values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
| MicrosoftATP.Indicators.targetProduct | String | A string value representing a single security product to which the indicator should be applied. | 
| MicrosoftATP.Indicators.threatType | String | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList. | 
| MicrosoftATP.Indicators.tlpLevel | String | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. Possible values are: unknown, white, green, amber, and red. | 
| MicrosoftATP.Indicators.url | String | Uniform Resource Locator. This URL complies with RFC 1738. | 
| MicrosoftATP.Indicators.userAgent | String | User-Agent string from a web request that could indicate compromise. | 
| MicrosoftATP.Indicators.vendorInformation | String | Information about the vendor. | 

#### Command Example
```!microsoft-atp-indicator-update expiration_time="2 days" indicator_id=18```

#### Context Example
```
{
    "MicrosoftATP": {
        "Indicators": {
            "action": "allow",
            "activityGroupNames": [],
            "azureTenantId": "TENANT-ID",
            "description": "Title: Indicator 50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c of type FileSha256, Description: A description",
            "expirationDateTime": "2020-08-28T17:21:15Z",
            "fileHashType": "sha256",
            "fileHashValue": "50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c",
            "id": "18",
            "ingestedDateTime": "2020-08-26T17:18:03.5249643Z",
            "isActive": true,
            "killChain": [],
            "malwareFamilyNames": [],
            "severity": 0,
            "tags": [],
            "targetProduct": "Microsoft Defender ATP"
        }
    }
}
```

#### Human Readable Output

>### Indicator ID: 18 was updated successfully.
>|action|azureTenantId|description|expirationDateTime|fileHashType|fileHashValue|id|ingestedDateTime|isActive|severity|targetProduct|
>|---|---|---|---|---|---|---|---|---|---|---|
>| allow | TENANT-ID | Title: Indicator 50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c of type FileSha256, Description: A description | 2020-08-28T17:21:15Z | sha256 | 50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c | 18 | 2020-08-26T17:18:03.5249643Z | true | 0 | Microsoft Defender ATP |


### microsoft-atp-indicator-delete
***
Deprecated. Use the microsoft-atp-sc-indicator-delete command instead. Deletes the specified indicator.


#### Base Command

`microsoft-atp-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The ID of the indicator to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-atp-indicator-delete indicator_id=18```


#### Human Readable Output

>Indicator ID: 18 was successfully deleted
### microsoft-atp-sc-indicator-list
***
Lists all indicators by the ID that the system creates when the indicator is ingested.

### Permissions
`Ti.ReadWrite`

#### Base Command

`microsoft-atp-sc-indicator-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values: "unknown", "allow", "block", and "alert". | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.expirationTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.severity | String | The severity of the malicious behavior identified by the data within the indicator. Possible values: "Informational", "Low", "Medium", and "High", where High is the most severe and Informational is not severe at all. | 
| MicrosoftATP.Indicators.indicatorValue | String | The value of the indicator. | 
| MicrosoftATP.Indicators.recommendedActions | String | Recommended actions for the indicator. | 
| MicrosoftATP.Indicators.generateAlert | Boolean | Whether an alert was generated. | 
| MicrosoftATP.Indicators.rbacGroupNames | Unknown | A list of RBAC device group names where the indicator is exposed and active. Empty list if it is exposed to all devices. | 
| MicrosoftATP.Indicators.mitreTechniques | Unknown | A list of MITRE techniques. | 
| MicrosoftATP.Indicators.indicatorType | String | Type of the indicator. Possible values: "FileSha1", "FileSha256", "IpAddress", "DomainName" and "Url". | 
| MicrosoftATP.Indicators.lastUpdateTime | Date | The last time the indicator was updated. | 
| MicrosoftATP.Indicators.createdByDisplayName | String | Display name of the created app. | 
| MicrosoftATP.Indicators.application | String | The application associated with the indicator. | 
| MicrosoftATP.Indicators.title | String | Indicator title. | 
| MicrosoftATP.Indicators.createdBySource | String | Source of indicator creation. For example, PublicApi. | 
| MicrosoftATP.Indicators.historicalDetection | Boolean | Whether a historical detection exists. | 
| MicrosoftATP.Indicators.lastUpdatedBy | String | Identity of the user/application that last updated the indicator. | 
| MicrosoftATP.Indicators.creationTimeDateTimeUtc | Date | The date and time when the indicator was created. | 
| MicrosoftATP.Indicators.category | Number | A number representing the indicator category. | 
| MicrosoftATP.Indicators.createdBy | String | Unique identity of the user/application that submitted the indicator. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| IP.Address | String | IP address. | 
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!microsoft-atp-sc-indicator-list limit=2```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "1.1.1.1",
            "Score": 0,
            "Type": "ip",
            "Vendor": "Microsoft Defender Advanced Threat Protection test"
        },
        {
            "Indicator": "5.5.5.5",
            "Score": 0,
            "Type": "ip",
            "Vendor": "Microsoft Defender Advanced Threat Protection test"
        }
    ],
    "IP": [
        {
            "Address": "1.1.1.1"
        },
        {
            "Address": "5.5.5.5"
        }
    ],
    "MicrosoftATP": {
        "Indicators": [
            {
                "action": "Allowed",
                "category": 1,
                "createdBy": "1281a70f-8ffb-4b3c-bc82-eef2a44dbb2a",
                "createdByDisplayName": "MS Graph ATP",
                "createdBySource": "PublicApi",
                "creationTimeDateTimeUtc": "2021-08-17T08:57:46.1460707Z",
                "description": "description",
                "expirationTime": "2021-08-18T08:57:45Z",
                "generateAlert": false,
                "historicalDetection": false,
                "id": "5142",
                "indicatorType": "IpAddress",
                "indicatorValue": "1.1.1.1",
                "lastUpdateTime": "2021-08-17T08:57:46.1563409Z",
                "severity": "Low",
                "title": "title"
            },
            {
                "action": "Allowed",
                "category": 1,
                "createdBy": "1281a70f-8ffb-4b3c-bc82-eef2a44dbb2a",
                "createdByDisplayName": "MS Graph ATP",
                "createdBySource": "PublicApi",
                "creationTimeDateTimeUtc": "2021-08-17T08:56:49.1898574Z",
                "description": "description",
                "expirationTime": "2021-08-18T08:56:48Z",
                "generateAlert": false,
                "historicalDetection": false,
                "id": "5141",
                "indicatorType": "IpAddress",
                "indicatorValue": "5.5.5.5",
                "lastUpdateTime": "2021-08-17T08:56:49.2017376Z",
                "severity": "Low",
                "title": "title"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results found in Microsoft Defender ATP SC for value: 5.5.5.5
>|id|action|indicatorValue|indicatorType|severity|title|description|
>|---|---|---|---|---|---|---|
>| 5141 | Allowed | 5.5.5.5 | IpAddress | Low | title | description |

### microsoft-atp-sc-indicator-update
***
Updates the specified indicator.

### Permissions
`Ti.ReadWrite`


#### Base Command

`microsoft-atp-sc-indicator-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_value | The value of the indicator to update. | Required | 
| indicator_type | Type of the indicator. Possible values: "FileSha1", "FileSha256", "IpAddress", "DomainName", and "Url". Possible values are: FileSha1, FileSha256, IpAddress, DomainName, Url. | Required | 
| action | The action taken if the indicator is discovered in the organization. Possible values: "Alert", "AlertAndBlock", and "Allowed". Possible values are: Alert, AlertAndBlock, Allowed. | Required | 
| severity | The severity of the malicious behavior identified by the data within the indicator. Possible values: "Informational", "Low", "Medium", and "High", where High is the most severe and Informational is not severe at all. Possible values are: Informational, Low, Medium, High. | Optional | 
| expiration_time | DateTime string indicating when the indicator expires. Format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 14 days. | Optional | 
| indicator_description | Brief description (100 characters or less) of the threat represented by the indicator. | Required | 
| indicator_title | Indicator alert title. | Required | 
| indicator_application | The application associated with the indicator. | Optional | 
| recommended_actions | TI indicator alert recommended actions. | Optional | 
| rbac_group_names | Comma-separated list of RBAC group names the indicator is applied to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values: "unknown", "allow", "block", and "alert". | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.expirationTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.severity | String | The severity of the malicious behavior identified by the data within the indicator. Possible values: "Informational", "Low", "Medium", and "High", where High is the most severe and Informational is not severe at all. | 
| MicrosoftATP.Indicators.indicatorValue | String | The value of the indicator. | 
| MicrosoftATP.Indicators.recommendedActions | String | Recommended actions for the indicator. | 
| MicrosoftATP.Indicators.generateAlert | Boolean | Whether an alert was generated. | 
| MicrosoftATP.Indicators.rbacGroupNames | Unknown | A list of RBAC device group names where the indicator is exposed and active. Empty list if it is exposed to all devices. | 
| MicrosoftATP.Indicators.mitreTechniques | Unknown | A list of MITRE techniques. | 
| MicrosoftATP.Indicators.indicatorType | String | Type of the indicator. Possible values: "FileSha1", "FileSha256", "IpAddress", "DomainName" and "Url". | 
| MicrosoftATP.Indicators.lastUpdateTime | Date | The last time the indicator was updated. | 
| MicrosoftATP.Indicators.createdByDisplayName | String | Display name of the created app. | 
| MicrosoftATP.Indicators.application | String | The application associated with the indicator. | 
| MicrosoftATP.Indicators.title | String | Indicator title. | 
| MicrosoftATP.Indicators.createdBySource | String | Source of indicator creation. For example, PublicApi. | 
| MicrosoftATP.Indicators.historicalDetection | Boolean | Whether a historical detection exists. | 
| MicrosoftATP.Indicators.lastUpdatedBy | String | Identity of the user/application that last updated the indicator. | 
| MicrosoftATP.Indicators.creationTimeDateTimeUtc | Date | The date and time when the indicator was created. | 
| MicrosoftATP.Indicators.category | Number | An number representing the indicator category. | 
| MicrosoftATP.Indicators.createdBy | String | Unique identity of the user/application that submitted the indicator. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| IP.Address | String | IP address. | 
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!microsoft-atp-sc-indicator-update action=Allowed indicator_description=test indicator_title=title indicator_type=IpAddress indicator_value=2.2.2.2 expiration_time="1 day" severity=Low```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "2.2.2.2",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Microsoft Defender Advanced Threat Protection test"
    },
    "IP": {
        "Address": "2.2.2.2"
    },
    "MicrosoftATP": {
        "Indicators": {
            "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Indicators/$entity",
            "action": "Allowed",
            "category": 1,
            "createdBy": "1281a70f-8ffb-4b3c-bc82-eef2a44dbb2a",
            "createdByDisplayName": "MS Graph ATP",
            "createdBySource": "PublicApi",
            "creationTimeDateTimeUtc": "2021-08-17T08:58:12.0340768Z",
            "description": "test",
            "expirationTime": "2021-08-18T08:58:12Z",
            "generateAlert": false,
            "historicalDetection": false,
            "id": "5143",
            "indicatorType": "IpAddress",
            "indicatorValue": "2.2.2.2",
            "lastUpdateTime": "2021-08-17T08:58:13.5312934Z",
            "lastUpdatedBy": "1281a70f-8ffb-4b3c-bc82-eef2a44dbb2a",
            "mitreTechniques": [],
            "rbacGroupIds": [],
            "rbacGroupNames": [],
            "severity": "Low",
            "title": "title"
        }
    }
}
```

#### Human Readable Output

>### Indicator 2.2.2.2 was updated successfully.
>|id|action|indicatorValue|indicatorType|severity|title|description|
>|---|---|---|---|---|---|---|
>| 5143 | Allowed | 2.2.2.2 | IpAddress | Low | title | test |

### microsoft-atp-sc-indicator-get-by-id
***
Gets an indicator by its ID.


### Permissions
`Ti.ReadWrite`

#### Base Command

`microsoft-atp-sc-indicator-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The ID of the indicator to get. The ID can be retrieved by running the microsoft-atp-sc-indicator-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values: "unknown", "allow", "block", and "alert". | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.expirationTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.severity | String | The severity of the malicious behavior identified by the data within the indicator. Possible values: "Informational", "Low", "Medium" and "High", where High is the most severe and Informational is not severe at all. | 
| MicrosoftATP.Indicators.indicatorValue | String | The value of the indicator. | 
| MicrosoftATP.Indicators.recommendedActions | String | Recommended actions for the indicator. | 
| MicrosoftATP.Indicators.generateAlert | Boolean | Whether an alert was generated. | 
| MicrosoftATP.Indicators.rbacGroupNames | Unknown | A list of RBAC device group names where the indicator is exposed and active. Empty list if it is exposed to all devices. | 
| MicrosoftATP.Indicators.mitreTechniques | Unknown | A list of MITRE techniques. | 
| MicrosoftATP.Indicators.indicatorType | String | Type of the indicator. Possible values: "FileSha1", "FileSha256", "IpAddress", "DomainName" and "Url". | 
| MicrosoftATP.Indicators.lastUpdateTime | Date | The last time the indicator was updated. | 
| MicrosoftATP.Indicators.createdByDisplayName | String | Display name of the created app. | 
| MicrosoftATP.Indicators.application | String | The application associated with the indicator. | 
| MicrosoftATP.Indicators.title | String | Indicator title. | 
| MicrosoftATP.Indicators.createdBySource | String | Source of indicator creation. For example, PublicApi. | 
| MicrosoftATP.Indicators.historicalDetection | Boolean | Whether a historical detection exists. | 
| MicrosoftATP.Indicators.lastUpdatedBy | String | Identity of the user/application that last updated the indicator. | 
| MicrosoftATP.Indicators.creationTimeDateTimeUtc | Date | The date and time when the indicator was created. | 
| MicrosoftATP.Indicators.category | Number | An number representing the indicator category. | 
| MicrosoftATP.Indicators.createdBy | String | Unique identity of the user/application that submitted the indicator. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| IP.Address | String | IP address. | 
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!microsoft-atp-sc-indicator-get-by-id indicator_id=5142```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Microsoft Defender Advanced Threat Protection test"
    },
    "IP": {
        "Address": "1.1.1.1"
    },
    "MicrosoftATP": {
        "Indicators": {
            "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Indicators/$entity",
            "action": "Allowed",
            "additionalInfo": null,
            "application": null,
            "bypassDurationHours": null,
            "category": 1,
            "certificateInfo": null,
            "createdBy": "1281a70f-8ffb-4b3c-bc82-eef2a44dbb2a",
            "createdByDisplayName": "MS Graph ATP",
            "createdBySource": "PublicApi",
            "creationTimeDateTimeUtc": "2021-08-17T08:57:46.1460707Z",
            "description": "description",
            "educateUrl": null,
            "expirationTime": "2021-08-18T08:57:45Z",
            "externalId": null,
            "generateAlert": false,
            "historicalDetection": false,
            "id": "5142",
            "indicatorType": "IpAddress",
            "indicatorValue": "1.1.1.1",
            "lastUpdateTime": "2021-08-17T08:57:46.1563409Z",
            "lastUpdatedBy": null,
            "lookBackPeriod": null,
            "mitreTechniques": [],
            "notificationBody": null,
            "notificationId": null,
            "rbacGroupIds": [],
            "rbacGroupNames": [],
            "recommendedActions": null,
            "severity": "Low",
            "title": "title",
            "version": null
        }
    }
}
```

#### Human Readable Output

>### Results found in Microsoft Defender ATP SC for value: 1.1.1.1
>|id|action|indicatorValue|indicatorType|severity|title|description|
>|---|---|---|---|---|---|---|
>| 5142 | Allowed | 1.1.1.1 | IpAddress | Low | title | description |

### microsoft-atp-sc-indicator-delete
***
Deletes the specified indicator.

### Permissions
`Ti.ReadWrite`

#### Base Command

`microsoft-atp-sc-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The ID of the indicator to delete. The ID can be retrieved by running the microsoft-atp-sc-indicator-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-atp-sc-indicator-delete indicator_id=5142```

#### Human Readable Output

>Indicator ID: 5142 was successfully deleted
### microsoft-atp-sc-indicator-create
***
Creates a new indicator.

### Permissions
`Ti.ReadWrite`

#### Base Command

`microsoft-atp-sc-indicator-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_value | The value of the indicator to update. | Required | 
| indicator_type | Type of the indicator. Possible values: "FileSha1", "FileSha256", "IpAddress", "DomainName", and "Url". Possible values are: FileSha1, FileSha256, IpAddress, DomainName, Url. | Required | 
| action | The action taken if the indicator is discovered in the organization. Possible values: "Alert", "AlertAndBlock", and "Allowed". Possible values are: Alert, AlertAndBlock, Allowed. | Required | 
| severity | The severity of the malicious behavior identified by the data within the indicator. Possible values: "Informational", "Low", "Medium", and "High", where High is the most severe and Informational is not severe at all. Possible values are: Informational, Low, Medium, High. | Optional | 
| expiration_time | DateTime string indicating when the indicator expires. Format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 14 days. | Optional | 
| indicator_description | Brief description (100 characters or less) of the threat represented by the indicator. | Required | 
| indicator_title | Indicator alert title. | Required | 
| indicator_application | The application associated with the indicator. | Optional | 
| recommended_actions | TI indicator alert recommended actions. | Optional | 
| rbac_group_names | Comma-separated list of RBAC group names the indicator is applied to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values: "unknown", "allow", "block", "alert". | 
| MicrosoftATP.Indicators.description | String | Brief description \(100 characters or less\) of the threat represented by the indicator. | 
| MicrosoftATP.Indicators.expirationTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 looks like: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.severity | String | The severity of the malicious behavior identified by the data within the indicator. Possible values: "Informational", "Low", "Medium", and "High", where High is the most severe and Informational is not severe at all. | 
| MicrosoftATP.Indicators.indicatorValue | String | The value of the indicator. | 
| MicrosoftATP.Indicators.recommendedActions | String | Recommended actions for the indicator. | 
| MicrosoftATP.Indicators.generateAlert | Boolean | Whether an alert was generated. | 
| MicrosoftATP.Indicators.rbacGroupNames | Unknown | A list of RBAC device group names where the indicator is exposed and active. Empty list if it is exposed to all devices. | 
| MicrosoftATP.Indicators.mitreTechniques | Unknown | A list of MITRE techniques. | 
| MicrosoftATP.Indicators.indicatorType | String | Type of the indicator. Possible values: "FileSha1", "FileSha256", "IpAddress", "DomainName" and "Url". | 
| MicrosoftATP.Indicators.lastUpdateTime | Date | The last time the indicator was updated. | 
| MicrosoftATP.Indicators.createdByDisplayName | String | Display name of the created app. | 
| MicrosoftATP.Indicators.application | String | The application associated with the indicator. | 
| MicrosoftATP.Indicators.title | String | Indicator title. | 
| MicrosoftATP.Indicators.createdBySource | String | Source of indicator creation. For example, PublicApi. | 
| MicrosoftATP.Indicators.historicalDetection | Boolean | Whether a historical detection exists. | 
| MicrosoftATP.Indicators.lastUpdatedBy | String | Identity of the user/application that last updated the indicator. | 
| MicrosoftATP.Indicators.creationTimeDateTimeUtc | Date | The date and time when the indicator was created. | 
| MicrosoftATP.Indicators.category | Number | An number representing the indicator category. | 
| MicrosoftATP.Indicators.createdBy | String | Unique identity of the user/application that submitted the indicator. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| IP.Address | String | IP address. | 
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example
```!microsoft-atp-sc-indicator-create action=Allowed indicator_description=test indicator_title=title indicator_type=IpAddress indicator_value=2.2.2.2 expiration_time="1 day" severity=Informational```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "2.2.2.2",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Microsoft Defender Advanced Threat Protection test"
    },
    "IP": {
        "Address": "2.2.2.2"
    },
    "MicrosoftATP": {
        "Indicators": {
            "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Indicators/$entity",
            "action": "Allowed",
            "createdBy": "1281a70f-8ffb-4b3c-bc82-eef2a44dbb2a",
            "createdByDisplayName": "MS Graph ATP",
            "createdBySource": "PublicApi",
            "creationTimeDateTimeUtc": "2021-08-17T08:58:12.0340768Z",
            "description": "test",
            "expirationTime": "2021-08-18T08:58:11Z",
            "generateAlert": false,
            "historicalDetection": false,
            "id": "5143",
            "indicatorType": "IpAddress",
            "indicatorValue": "2.2.2.2",
            "lastUpdateTime": "2021-08-17T08:58:12.0438875Z",
            "mitreTechniques": [],
            "rbacGroupIds": [],
            "rbacGroupNames": [],
            "severity": "Informational",
            "title": "title"
        }
    }
}
```

#### Human Readable Output

>### Indicator 2.2.2.2 was updated successfully.
>|id|action|indicatorValue|indicatorType|severity|title|description|
>|---|---|---|---|---|---|---|
>| 5143 | Allowed | 2.2.2.2 | IpAddress | Informational | title | test |

### microsoft-atp-list-machines-by-vulnerability
***
Retrieves a list of machines affected by a vulnerability.

##### Required Permissions
Vulnerability.Read.All

#### Base Command

`microsoft-atp-list-machines-by-vulnerability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | A comma-separated list of CVE IDs to be used for getting the machines. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.CveMachine.ID | String | The machine ID. | 
| MicrosoftATP.CveMachine.ComputerDNSName | String | The machine hostname. | 
| MicrosoftATP.CveMachine.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.CveMachine.RBACGroupName | String | The machine RBAC group name. | 
| MicrosoftATP.CveMachine.CVE | Unknown | The given CVE IDs related to this machine. | 

#### Command example
```!microsoft-atp-list-machines-by-vulnerability cve_id=CVE-2021-32810,CVE-2020-12321```
#### Context Example
```json
{
    "MicrosoftATP": {
        "CveMachine": [
            {
                "ComputerDNSName": "ec2amaz",
                "ID": "f3bba49a",
                "OSPlatform": "WindowsServer2016",
                "RBACGroupID": 0,
                "CVE": ["CVE-2021-32810", "CVE-2020-12321"]
            },
            {
                "ComputerDNSName": "msde-agent-host-centos7",
                "ID": "48a62a74",
                "OSPlatform": "Linux",
                "RBACGroupID": 0,
                "CVE": ["CVE-2020-12321"]
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft Defender ATP machines by vulnerabilities: ['CVE-2021-32810', 'CVE-2020-12321']
>|ID|ComputerDNSName|OSPlatform|RBACGroupID|CVE|
>|---|---|---|---|---|
>| f3bba49a | ec2amaz | WindowsServer2016 | 0 | CVE-2021-32810,CVE-2020-12321|
>| 48a62a74 | msde-agent-host-centos7 | Linux | 0 | CVE-2020-12321|

### microsoft-atp-get-file-info
***
Retrieves file info by a file hash (Sha1 or Sha256).

##### Required Permissions
File.Read.All

#### Base Command

`microsoft-atp-get-file-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | A comma-separated list of file hashs (Sha1 or Sha256) to be used for getting the file info. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.File.Sha1 | String | The SHA1 hash of the file. | 
| MicrosoftATP.File.Sha256 | String | The SHA256 hash of the file. | 
| MicrosoftATP.File.GlobalPrevalence | Number | The file prevalence across organization. | 
| MicrosoftATP.File.GlobalFirstObserved | Date | The first time the file was observed. | 
| MicrosoftATP.File.GlobalLastObserved | Date | The last time the file was observed. | 
| MicrosoftATP.File.Size | Number | The size of the file. | 
| MicrosoftATP.File.FileType | String | The type of the file. | 
| MicrosoftATP.File.IsPeFile | Boolean | True if the file is portable executable, False otherwise. | 
| MicrosoftATP.File.FilePublisher | String | The file's publisher. | 
| MicrosoftATP.File.FileProductName | String | The file product name. | 
| MicrosoftATP.File.Signer | String | The file signer. | 
| MicrosoftATP.File.Issuer | String | The file issuer. | 
| MicrosoftATP.File.SignerHash | String | The hash of the signing certificate. | 
| MicrosoftATP.File.IsValidCertificate | Boolean | Was signing certificate successfully verified by Microsoft Defender ATP agent. | 
| MicrosoftATP.File.DeterminationValue | String | The file determination value. | 
| MicrosoftATP.File.DeterminationType | String | The file determination type. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Type | String | The file type. | 
| File.Size | Number | The file size. | 

#### Command example
```!microsoft-atp-get-file-info hash="3395856ce81,db79e9e669c"```
#### Context Example
```json
{
    "File": [
        {
            "Sha1": "3395856ce81",
            "Sha256": "275a021bbfb648",
            "Size": 68
        },
        {
            "Sha1": "db79e9e669c",
            "Sha256": "ef67e4b2bb4ee5",
            "Size": 36768
        }
    ],
    "MicrosoftATP": {
        "File": [
            {
                "DeterminationType": "Unknown",
                "DeterminationValue": "Virus:DOS/EICAR_Test_File",
                "GlobalFirstObserved": "2013-03-03T14:00:34.8213548Z",
                "GlobalLastObserved": "2022-01-26T17:31:27.4706316Z",
                "GlobalPrevalence": 37933,
                "IsPeFile": false,
                "Md5": "44d88612fea8a8",
                "Sha1": "3395856ce81",
                "Sha256": "275a021bbfb648",
                "Size": 68,
                "SizeInBytes": 68
            },
            {
                "DeterminationType": "Unknown",
                "GlobalFirstObserved": "2022-01-14T18:04:15.9389909Z",
                "GlobalLastObserved": "2022-01-26T17:36:07.8400883Z",
                "GlobalPrevalence": 8418,
                "IsPeFile": false,
                "Md5": "b0c6a0cfdac",
                "Sha1": "db79e9e669c",
                "Sha256": "ef67e4b2bb4ee5",
                "Size": 36768,
                "SizeInBytes": 36768
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft Defender ATP file info by hashes: ['3395856ce81', 'db79e9e669c']
>|Sha1|Sha256|Size|
>|---|---|---|
>| 3395856ce81 | 275a021bbfb648 | 68 |
>| db79e9e669c | ef67e4b2bb4ee5 | 36768 |


### endpoint
***
Gets machines that have communicated with Microsoft Defender for Endpoint cloud. At least one of the following arguments is required ip, hostanme ot id. Otherwise, an error appears.

##### Required Permissions
Machine.Read.All
Machine.ReadWrite.All

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
| Endpoint.ID | String | The endpoint's identifier. | 
| Endpoint.Hostname | String | The hostname of the endpoint. | 
| Endpoint.OS | String | The endpoint's operating system. | 
| Endpoint.OSVersion | String | The endpoint's operating system's version. | 
| Endpoint.IPAddress | String | The endpoint's IP address. | 
| Endpoint.Status | String | The health status of the endpoint. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 
| MicrosoftATP.Machine.ID | String | The machine ID. | 
| MicrosoftATP.Machine.ComputerDNSName | String | The machine DNS name. | 
| MicrosoftATP.Machine.FirstSeen | Date | The first date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.LastSeen | Date | The last date and time where the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.Machine.OSVersion | String | The operating system version. | 
| MicrosoftATP.Machine.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.Machine.LastIPAddress | String | The last IP on the machine. | 
| MicrosoftATP.Machine.LastExternalIPAddress | String | The last machine IP to access the internet. | 
| MicrosoftATP.Machine.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.Machine.HealthStatus | String | The machine health status. | 
| MicrosoftATP.Machine.RBACGroupID | Number | The machine RBAC group ID. | 
| MicrosoftATP.Machine.RBACGroupName | String | The machine RBAC group name. | 
| MicrosoftATP.Machine.RiskScore | String | The machine risk score. | 
| MicrosoftATP.Machine.ExposureLevel | String | The machine exposure score. | 
| MicrosoftATP.Machine.IsAADJoined | Boolean | True if machine is AAD joined, False otherwise. | 
| MicrosoftATP.Machine.AADDeviceID | String | The AAD Device ID. | 
| MicrosoftATP.Machine.MachineTags | String | Set of machine tags. | 
| MicrosoftATP.Machine.IPAddresses.ipAddress | String | The machine IP address. | 
| MicrosoftATP.Machine.IPAddresses.MACAddress | String | The machine MAC address. | 
| MicrosoftATP.Machine.IPAddresses.operationalStatus | String | The machine operational status. | 
| MicrosoftATP.Machine.IPAddresses.type | String | The machine macine IP address type. | 
| MicrosoftATP.Machine.AgentVersion | String | The machine Agent version. | 

#### Command example
```!endpoint id="f3bba49a,48a62a74"ip=1.2.3.4 hostname="ec2amaz-ua9hieu"```
#### Context Example
```json
{
    "Endpoint": [
        {
            "Hostname": "msde-agent-host-centos7.c.dmst-integrations.internal",
            "ID": "48a62a74",
            "IPAddress": "10.0.0.1",
            "MACAddress": "123456789123",
            "OS": "CentOS",
            "OSVersion": "7.9 x64 bit",
            "Status": "Online",
            "Vendor": "Microsoft Defender ATP"
        },
        {
            "Hostname": "ec2amaz-ua9hieu",
            "ID": "f3bba49a",
            "IPAddress": "1.2.3.4",
            "MACAddress": "123456789123",
            "OS": "WindowsServer2016",
            "OSVersion": "1607 x64 bit",
            "Status": "Online",
            "Vendor": "Microsoft Defender ATP"
        }
    ],
    "MicrosoftATP": {
        "Machine": [
            {
                "AgentVersion": "30.121112.15302.0",
                "ComputerDNSName": "msde-agent-host-centos7.c.dmst-integrations.internal",
                "ExposureLevel": "Medium",
                "FirstSeen": "2022-01-23T09:13:42.982Z",
                "HealthStatus": "Active",
                "ID": "48a62a74",
                "IPAddresses": [
                    {
                        "ipAddress": "10.0.0.1",
                        "macAddress": "123456789123",
                        "operationalStatus": "Up",
                        "type": "Other"
                    },
                    {
                        "ipAddress": "fe80::178b:6498:fc7f:2856",
                        "macAddress": "123456789123",
                        "operationalStatus": "Up",
                        "type": "Other"
                    },
                    {
                        "ipAddress": "127.0.0.1",
                        "macAddress": "000000000000",
                        "operationalStatus": "Up",
                        "type": "Other"
                    },
                    {
                        "ipAddress": "::1",
                        "macAddress": "000000000000",
                        "operationalStatus": "Up",
                        "type": "Other"
                    }
                ],
                "IsAADJoined": false,
                "LastExternalIPAddress": "127.0.0.1",
                "LastIPAddress": "10.0.0.1",
                "LastSeen": "2022-01-27T09:13:53.1394181Z",
                "MACAddress": "123456789123",
                "OSPlatform": "CentOS",
                "OSProcessor": "x64",
                "OSVersion": "7.9",
                "RBACGroupID": 0,
                "RiskScore": "Medium"
            },
            {
                "AgentVersion": "10.3720.16299.2015",
                "ComputerDNSName": "ec2amaz-ua9hieu",
                "ExposureLevel": "High",
                "FirstSeen": "2022-01-23T15:36:02.286Z",
                "HealthStatus": "Active",
                "ID": "f3bba49a",
                "IPAddresses": [
                    {
                        "ipAddress": "1.2.3.4",
                        "macAddress": "123456789123",
                        "operationalStatus": "Up",
                        "type": "Ethernet"
                    },
                    {
                        "ipAddress": "fe80::a998:1c4a:7e1c:4865",
                        "macAddress": "123456789123",
                        "operationalStatus": "Up",
                        "type": "Ethernet"
                    },
                    {
                        "ipAddress": "127.0.0.1",
                        "macAddress": "",
                        "operationalStatus": "Up",
                        "type": "SoftwareLoopback"
                    },
                    {
                        "ipAddress": "::1",
                        "macAddress": "",
                        "operationalStatus": "Up",
                        "type": "SoftwareLoopback"
                    },
                    {
                        "ipAddress": "fe80::5efe:1.2.3.4",
                        "macAddress": "00000000000000E0",
                        "operationalStatus": "Down",
                        "type": "Tunnel"
                    },
                    {
                        "ipAddress": "127.0.0.1",
                        "macAddress": "00000000000000E0",
                        "operationalStatus": "Up",
                        "type": "Tunnel"
                    },
                    {
                        "ipAddress": "fe80::2412:1420:53e0:f88b",
                        "macAddress": "00000000000000E0",
                        "operationalStatus": "Up",
                        "type": "Tunnel"
                    }
                ],
                "IsAADJoined": false,
                "LastExternalIPAddress": "127.0.0.1",
                "LastIPAddress": "1.2.3.4",
                "LastSeen": "2022-01-26T22:21:19.2024139Z",
                "MACAddress": "123456789123",
                "OSBuild": 14393,
                "OSPlatform": "WindowsServer2016",
                "OSProcessor": "x64",
                "OSVersion": "1607",
                "RBACGroupID": 0,
                "RiskScore": "None"
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft Defender ATP Machine:
>|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|
>|---|---|---|---|---|---|---|---|
>| f3bba49a | ec2amaz-ua9hieu | WindowsServer2016 | 1.2.3.4 | 127.0.0.1 | Active | None | High |


### microsoft-atp-indicator-batch-update
***
Updates batch of indicator. If an indicator does not exist, a new indicator will be created.

##### Required Permissions
Ti.ReadWrite
Ti.ReadWrite.All

##### Limitations
1. Rate limitations for this API are 30 calls per minute.
2. There is a limit of 15,000 active indicators per tenant.
3. Maximum batch size for one API call is 500.

##### Note
Please read [here](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/ti-indicator?view=o365-worldwide) about the Microsoft Defender for Endpoint indicator resource type.
We suggest using the <insert_automation_name>[insert_automation_readme?] to load the XSOAR IOCs to MSDE indicator format.
#### Base Command

`microsoft-atp-indicator-batch-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_batch | A JSON object with list of MS defender ATP indicators to update. indicator_batch query should by list of dictionaries. For example: [{"indicatorValue": "value1"}, {"indicatorValue": "value2"}]. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.ID | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.Value | String | The value of the indicator. | 
| MicrosoftATP.Indicators.FailureReason | String | The reason for update failure. | 
| MicrosoftATP.Indicators.IsFailed | Boolean | Whether the update was failed. | 

#### Command example
```!microsoft-atp-indicator-batch-update indicator_batch=`[{"indicatorValue": "220e7d15b011d7fac48f2bd61114db1022197f7f","indicatorType": "FileSha1","title": "demo","application": "demo-test", "action": "Alert","severity": "Informational","description": "demo2","recommendedActions": "nothing","rbacGroupNames": ["group1", "group2"]},{"indicatorValue": "2233223322332233223322332233223322332233223322332233223322332222","indicatorType": "FileSha256","title": "demo2","application": "demo-test2","action": "Alert","severity": "Medium","description": "demo2","recommendedActions": "nothing","rbacGroupNames": []}]````
#### Context Example
```json
{
    "MicrosoftATP": {
        "Indicators": [
            {
                "FailureReason": null,
                "ID": "5217",
                "IsFailed": false,
                "Value": "220e7d15b011d7fac48f2bd61114db1022197f7f"
            },
            {
                "FailureReason": null,
                "ID": "5218",
                "IsFailed": false,
                "Value": "2233223322332233223322332233223322332233223322332233223322332222"
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators updated successfully.
>|ID|Value|IsFailed|
>|---|---|---|
>| 5217 | 220e7d15b011d7fac48f2bd61114db1022197f7f | false |
>| 5218 | 2233223322332233223322332233223322332233223322332233223322332222 | false |
