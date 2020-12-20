## Overview
---

Use the Microsoft Defender Advanced Threat Protection (ATP) integration for preventative protection, post-breach detection, automated investigation, and response.

## Microsoft Defender Advanced Threat Protection Playbook
---
Microsoft Defender Advanced Threat Protection Get Machine Action Status

## Use Cases
---
1. Fetch incidents.
2. Managing machines and performing actions on them.
3. Blocking files and applications.
4. Uploading and digesting threat indicators for the actions of allow, block, or alert.

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
* Url.Read.All - Application
* User.Read.All - Application

## Configure Microsoft Defender Advanced Threat Protection on Demisto
---

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Defender Advanced Threat Protection.
3. Click **Add instance** to create and configure a new integration instance.
    
    | **Parameter** | **Description** | **Example** |
    | ---------             | -----------           | -------            |
    | Name | A meaningful name for the integration instance. | XXXXX Instance Alpha |
    | Host URL | The URL to the Microsoft Defender Advanced Threat Protection server, including the scheme. | `https://api.securitycenter.windows.com` |
     | ID | The ID used to gain access to the integration. | N/A |
     | Token | A piece of data that servers use to verify for authenticity | eea810f5-a6f6 |
    | Fetch Incidents | Whether to fetch the incidents or not. | N/A |
    | Incident Type | The type of incident to select. | Phishing |
    | Status to filter out alerts for fetching as incidents| The property values are, "New", "InProgress" or "Resolved". Comma-separated values supported. | New,Resolved |
    | Severity to filter out alerts for fetching as incidents | The property values are, "Informational", "Low", "Medium" and "High". Comma-separated values supported. | Medium,High |
    | Trust any Certificate (Not Secure) | When selected, certificates are not checked. | N/A |
    | Use system proxy settings | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | https://proxyserver.com |
    | First Fetch Timestamp | The first timestamp to be fetched in number, time unit format. | 12 hours, 7 days |
    | self-deployed | Use a self-deployed Azure Application. |  N/A |


4. Click **Test** to validate the URLs, token, and connection.

## Fetched Incidents Data
1. id
2. incidentId
3. investigationId
4. assignedTo
5. severity
6. status
7. classification
8. determination
9. investigationState
10. detectionSource
11. category
12. threatFamilyName
13. title
14. description
15. alertCreationTime
16. firstEventTime
17. lastEventTime
18. lastUpdateTime
19. resolvedTime
20. machineId
21. computerDnsName
22. aadTenantId
23. relatedUser
24. comments
25. evidence


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
33. microsoft-atp-indicator-list
34. microsoft-atp-indicator-get-by-id
35. microsoft-atp-network-indicator-create
36. microsoft-atp-file-indicator-create
37. microsoft-atp-indicator-update
38. microsoft-atp-indicator-delete
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
| machine_id | The machine ID to be used for isolation. For example, "0a3250e0693a109f1affc9217be9459028aa8426". | Required | 
| comment | The comment to associate with the action. | Required | 
| isolation_type | Whether to fully isolate or selectively isolate. Selectively restricting only limits a set of applications from accessing the network. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The machine action ID. | 
| MicrosoftATP.MachineAction.Type | String | The type of the machine action. | 
| MicrosoftATP.MachineAction.Scope | Unknown | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name on which the action was executed. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier with the possible values. Can be, "SHA1" ,"SHA256" or "MD5". | 


##### Command Example
```!microsoft-atp-isolate-machine machine_id=a70f9fe6b29cd9511652434919c6530618f06606 comment="test isolate machine" isolation_type=Selective```

##### Context Example
```
{
    "MicrosoftATP.MachineAction": {
        "Status": "Pending", 
        "CreationDateTimeUtc": "2020-03-23T10:07:48.6818309Z", 
        "MachineID": "a70f9fe6b29cd9511652434919c6530618f06606", 
        "LastUpdateTimeUtc": null, 
        "ComputerDNSName": null, 
        "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4", 
        "RelatedFileInfo": {
            "FileIdentifier": null, 
            "FileIdentifierType": null
        }, 
        "Scope": null, 
        "Type": "Isolate", 
        "ID": "70ab787a-0719-4493-b98d-2535c8fe6817", 
        "RequestorComment": "test isolate machine"
    }
}
```

##### Human Readable Output
##### The isolation request has been submitted successfully:
|ID|Type|Requestor|RequestorComment|Status|MachineID|
|---|---|---|---|---|---|
| 70ab787a-0719-4493-b98d-2535c8fe6817 | Isolate | 2f48b784-5da5-4e61-9957-012d2630f1e4 | test isolate machine | Pending | a70f9fe6b29cd9511652434919c6530618f06606 |


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
| machine_id | Machine ID to be used to stop the isolation. For example, "0a3250e0693a109f1affc9217be9459028aa8426". | Required | 
| comment | The comment to associate with the action. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The action ID of the machine. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | Unknown | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name on which the action was executed. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The fileIdentifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier with the possible values. Can be, "SHA1" ,"SHA256" and "MD5". | 


##### Command Example
```!microsoft-atp-unisolate-machine machine_id=f70f9fe6b29cd9511652434919c6530618f06606 comment="test unisolate machine"```

##### Context Example
```
{
    "MicrosoftATP.MachineAction": {
        "Status": "Pending", 
        "CreationDateTimeUtc": "2020-03-23T10:07:50.7692907Z", 
        "MachineID": "f70f9fe6b29cd9511652434919c6530618f06606", 
        "LastUpdateTimeUtc": null, 
        "ComputerDNSName": null, 
        "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4", 
        "RelatedFileInfo": {
            "FileIdentifier": null, 
            "FileIdentifierType": null
        }, 
        "Scope": null, 
        "Type": "Unisolate", 
        "ID": "3d30f7c9-e41c-4839-a678-f528a201778c", 
        "RequestorComment": "test unisolate machine"
    }
}
```

##### Human Readable Output
##### The request to stop the isolation has been submitted successfully:
|ID|Type|Requestor|RequestorComment|Status|MachineID|
|---|---|---|---|---|---|
| 3d30f7c9-e41c-4839-a678-f528a201778c | Unisolate | 2f48b784-5da5-4e61-9957-012d2630f1e4 | test unisolate machine | Pending | f70f9fe6b29cd9511652434919c6530618f06606 |


### 3. microsoft-atp-get-machines
---
Retrieves a collection of machines that has communicated with WDATP cloud within the last 30 days.

##### Required Permissions
Machine.ReadWrite.All	

##### Base Command

`microsoft-atp-get-machines`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The DNS name of the computer. | Optional | 
| ip | The last machine IP address to access the internet. | Optional | 
| risk_score | The risk score of the machine. | Optional | 
| health_status | The health status of the machine. | Optional | 
| os_platform | The machine's OS platform. Only a single platform can be added. | Optional | 


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
| MicrosoftATP.Machine.LastExternalIPAddress | String | The last machine IP address to access the internet. | 
| MicrosoftATP.Machine.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.Machine.HealthStatus | String | The health status of the machine. | 
| MicrosoftATP.Machine.RBACGroupID | Number | The RBAC group ID of the machine. | 
| MicrosoftATP.Machine.RBACGroupName | String | The RBAC group name of the machine. | 
| MicrosoftATP.Machine.RiskScore | String | The risk score of the machine. | 
| MicrosoftATP.Machine.ExposureLevel | String | The exposure score of the machine. | 
| MicrosoftATP.Machine.IsAADJoined | Boolean | Whether the machine is AAD joined. | 
| MicrosoftATP.Machine.AADDeviceID | String | The AAD device ID. | 
| MicrosoftATP.Machine.MachineTags | String | The set of machine tags. | 


##### Command Example
```!microsoft-atp-get-machines health_status=Active risk_score=Medium```

##### Context Example
```
{
    "MicrosoftATP.Machine": [
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
        }, 
        {
            "OSBuild": 14393, 
            "ExposureLevel": "Medium", 
            "OSPlatform": "WindowsServer2016", 
            "ComputerDNSName": "ec2amaz-ua9hieu", 
            "RBACGroupID": 0, 
            "OSProcessor": "x64", 
            "HealthStatus": "Active", 
            "AgentVersion": "10.3720.16299.2010", 
            "LastExternalIPAddress": "51.29.51.184", 
            "LastIPAddress": "175.31.7.116", 
            "RiskScore": "Medium", 
            "ID": "f3bba49af4d3bacedc62ca0fe580a4d5925af8aa", 
            "FirstSeen": "2020-01-26T14:02:55.1863281Z", 
            "LastSeen": "2020-03-22T20:18:54.9792497Z"
        }
    ]
}
```

##### Human Readable Output
##### Microsoft Defender ATP Machines:
|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|
|---|---|---|---|---|---|---|---|
| f70f9fe6b29cd9511652434919c6530618f06606 | desktop-s2455r9 | Windows10 | 192.168.1.73 | 81.166.99.236 | Active | Medium | Medium |
| f3bba49af4d3bacedc62ca0fe580a4d5925af8aa | ec2amaz-ua9hieu | WindowsServer2016 | 175.31.7.116 | 51.29.51.184 | Active | Medium | Medium |


### 4. microsoft-atp-get-file-related-machines
---
Gets a collection of machines related to a given file's SHA1 hash.

##### Required Permissions
Machine.ReadWrite.All

##### Base Command

`microsoft-atp-get-file-related-machines`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_hash | The file's SHA1 hash to get the related machines. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.FileMachine.Machines.ID | String | The ID of the machine. | 
| MicrosoftATP.FileMachine.Machines.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.FileMachine.Machines.FirstSeen | Date | The first date and time when the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.FileMachine.Machines.LastSeen | Date | The last date and time when the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.FileMachine.Machines.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.FileMachine.Machines.OSVersion | String | The operating system version. | 
| MicrosoftATP.Machine.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.FileMachine.Machines.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.FileMachine.Machines.LastIPAddress | String | The last IP address on the machine. | 
| MicrosoftATP.FileMachine.Machines.LastExternalIPAddress | String | The last machine IP address to access the internet. | 
| MicrosoftATP.FileMachine.Machines.HelathStatus | String | The health status of the machine. | 
| MicrosoftATP.FileMachine.Machines.RBACGroupID | Number | The RBAC group ID of the machine.| 
| MicrosoftATP.FileMachine.Machines.RBACGroupName | String | The RBAC group name of the machine. | 
| MicrosoftATP.FileMachine.Machines.RiskScore | String | The risk score of the machine. | 
| MicrosoftATP.FileMachine.Machines.ExposureLevel | String | The exposure score of the machine. | 
| MicrosoftATP.FileMachine.Machines.IsAADJoined | Boolean | Whether the machine is AAD joined. | 
| MicrosoftATP.FileMachine.Machines.AADDeviceID | string | The AAD device ID. | 
| MicrosoftATP.FileMachine.Machines.MachineTags | String | The set of machine tags. | 
| MicrosoftATP.FileMachine.File | String | The machine related file hash. | 


##### Command Example
```!microsoft-atp-get-file-related-machines file_hash=36c5d12033b2eaf251bae61c00690ffb17fddc87```

##### Context Example
```
{
    "MicrosoftATP.FileMachine": {
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
                "LastIPAddress": "192.168.1.73", 
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
        ], 
        "File": "36c5d12033b2eaf251bae61c00690ffb17fddc87"
    }
}
```

##### Human Readable Output
##### Microsoft Defender ATP machines related to file 36c5d12033b2eaf251bae61c00690ffb17fddc87
|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|
|---|---|---|---|---|---|---|---|
| 4899036531e374137f63289c3267bad772c13fef | desktop-s2455r8 | Windows10 | 192.168.1.71 | 81.166.99.236 | Active | High | Medium |
| f70f9fe6b29cd9511652434919c6530618f06606 | desktop-s2455r9 | Windows10 | 192.168.1.73 | 81.166.99.236 | Active | Medium | Medium |


### 5. microsoft-atp-get-machine-details
---
Gets a machine's details by its identity.

##### Required Permissions
Machine.ReadWrite.All

##### Base Command

`microsoft-atp-get-machine-details`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The machine ID to be used to get the machine details. For example, "0a3250e0693a109f1affc9217be9459028aa8426". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Machine.ID | String | The ID of the machine. | 
| MicrosoftATP.Machine.ComputerDNSName | String | The DNS name of the machine. | 
| MicrosoftATP.Machine.FirstSeen | Date | The first date and time when the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.LastSeen | Date | The last date and time when the machine was observed by Microsoft Defender ATP. | 
| MicrosoftATP.Machine.OSPlatform | String | The operating system platform. | 
| MicrosoftATP.Machine.OSVersion | String | The operating system version. | 
| MicrosoftATP.Machine.OSProcessor | String | The operating system processor. | 
| MicrosoftATP.Machine.LastIPAddress | String | The last IP address on the machine. | 
| MicrosoftATP.Machine.LastExternalIPAddress | String | The last machine IP address to access the internet. | 
| MicrosoftATP.Machine.OSBuild | Number | The operating system build number. | 
| MicrosoftATP.Machine.HealthStatus | String | The health status of the machine. | 
| MicrosoftATP.Machine.RBACGroupID | Number | The RBAC group ID of the machine. | 
| MicrosoftATP.Machine.RBACGroupName | String | The RBAC group name of the machine. | 
| MicrosoftATP.Machine.RiskScore | String | The risk score of the machine. | 
| MicrosoftATP.Machine.ExposureLevel | String | The exposure level of the machine. | 
| MicrosoftATP.Machine.IsAADJoined | Boolean | Whether the machine is AAD joined. | 
| MicrosoftATP.Machine.AADDeviceID | String | The AAD device ID. | 
| MicrosoftATP.Machine.MachineTags | String | The set of machine tags. | 


##### Command Example
```!microsoft-atp-get-machine-details machine_id=f70f9fe6b29cd9511652434919c6530618f06606```

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
##### Microsoft Defender ATP machine f70f9fe6b29cd9511652434919c6530618f06606 details:
|ID|ComputerDNSName|OSPlatform|LastIPAddress|LastExternalIPAddress|HealthStatus|RiskScore|ExposureLevel|
|---|---|---|---|---|---|---|---|
| f70f9fe6b29cd9511652434919c6530618f06606 | desktop-s2455r9 | Windows10 | 192.168.1.73 | 81.166.99.236 | Active | Medium | Medium |


### 6. microsoft-atp-run-antivirus-scan
---
Initiates Microsoft Defender Antivirus scan on a machine.

##### Required Permissions
Machine.Scan	

##### Base Command

`microsoft-atp-run-antivirus-scan`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| machine_id | The machine ID to run the scan on. | Required | 
| comment | The comment to associate with the action. | Required | 
| scan_type | Defines the type of the scan. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The action ID of the machine. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | Unknown | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command. | 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID the action was executed on. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name the action was executed on. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier with the possible values. Can be, "SHA1" ,"SHA256" and "MD5". | 


##### Command Example
```!microsoft-atp-run-antivirus-scan machine_id=f70f9fe6b29cd9511652434919c6530618f06606 comment="testing anti virus" scan_type=Quick```

##### Context Example
```
{
    "MicrosoftATP.MachineAction": {
        "Status": "Pending", 
        "CreationDateTimeUtc": "2020-03-23T10:07:54.3942786Z", 
        "MachineID": "f70f9fe6b29cd9511652434919c6530618f06606", 
        "LastUpdateTimeUtc": null, 
        "ComputerDNSName": null, 
        "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4", 
        "RelatedFileInfo": {
            "FileIdentifier": null, 
            "FileIdentifierType": null
        }, 
        "Scope": null, 
        "Type": "RunAntiVirusScan", 
        "ID": "55680be3-162c-49d1-a4d6-37f9dc47e9d8", 
        "RequestorComment": "testing anti virus"
    }
}
```

##### Human Readable Output
##### Antivirus scan successfully triggered
|ID|Type|Requestor|RequestorComment|Status|MachineID|
|---|---|---|---|---|---|
| 55680be3-162c-49d1-a4d6-37f9dc47e9d8 | RunAntiVirusScan | 2f48b784-5da5-4e61-9957-012d2630f1e4 | testing anti virus | Pending | f70f9fe6b29cd9511652434919c6530618f06606 |


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
| severity | The alert's severity. | Optional | 
| status | The alert's status. | Optional | 
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
| status | The alert status to update. | Optional | 
| assigned_to | The owner of the alert. | Optional | 
| classification | Specifies the specification of the alert. | Optional | 
| determination | Specifies the determination of the alert. | Optional | 
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
| timeout | The amount of time (in seconds) that a request will wait for the query response before a timeout occurs. | Optional | 


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
| severity | The severity of the alert. | Required | 
| title | The title of the alert. | Required | 
| description | The description of the alert. | Required | 
| recommended_action | The action that is recommended to be taken by the security officer when analyzing the alert. | Required | 
| event_time | The time of the event, as obtained from the advanced query. | Required | 
| report_id | The reportId, as obtained from the advanced query. | Required | 
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
Returns the machine's actions. If an action ID is set it will return the information on the specific action.
Filtering can only be done on a single argument.

##### Required Permissions
Machine.ReadWrite.All

##### Base Command

`microsoft-atp-list-machine-actions-details`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the action. | Optional | 
| status | The action status of the machine. | Optional | 
| machine_id | The machine's ID which the action was executed on. Only one can be added. | Optional | 
| type | The action type of the machine. | Optional | 
| requestor | The ID of the user that executed the action. Only one can be added. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.MachineAction.ID | String | The action ID of the machine. | 
| MicrosoftATP.MachineAction.Type | String | The type of the action. | 
| MicrosoftATP.MachineAction.Scope | String | The scope of the action. | 
| MicrosoftATP.MachineAction.Requestor | String | The ID of the user that executed the action. | 
| MicrosoftATP.MachineAction.RequestorComment | String | The comment that was written when issuing the action. | 
| MicrosoftATP.MachineAction.Status | String | The current status of the command.| 
| MicrosoftATP.MachineAction.MachineID | String | The machine ID on which the action was executed. | 
| MicrosoftATP.MachineAction.ComputerDNSName | String | The machine DNS name which the action was executed on. | 
| MicrosoftATP.MachineAction.CreationDateTimeUtc | Date | The date and time when the action was created. | 
| MicrosoftATP.MachineAction.LastUpdateTimeUtc | Date | The last date and time when the action status was updated. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifier | String | The file identifier. | 
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier with the possible values. Can be, "SHA1" ,"SHA256" and "MD5" | 


##### Command Example
```!microsoft-atp-list-machine-actions-details type=RestrictCodeExecution```

##### Context Example
```
{
    "MicrosoftATP.MachineAction": [
        {
            "Status": "Succeeded", 
            "CreationDateTimeUtc": "2020-03-23T10:00:26.5923766Z", 
            "MachineID": "f70f9fe6b29cd9511652434919c6530618f06606", 
            "LastUpdateTimeUtc": null, 
            "ComputerDNSName": "desktop-s2455r9", 
            "Requestor": "2f48b784-5da5-4e61-9957-012d2630f1e4", 
            "RelatedFileInfo": {
                "FileIdentifier": null, 
                "FileIdentifierType": null
            }, 
            "Scope": null, 
            "Type": "RestrictCodeExecution", 
            "ID": "655b9413-0f41-49bc-a811-1aadc2c827d6", 
            "RequestorComment": "test restrict app"
        }, 
        {
            "Status": "Cancelled", 
            "CreationDateTimeUtc": "2020-02-10T13:32:03.0534738Z", 
            "MachineID": "f3bba49af4d3bacedc62ca0fe580a4d5925af8aa", 
            "LastUpdateTimeUtc": null, 
            "ComputerDNSName": "ec2amaz-ua9hieu", 
            "Requestor": "7bb424e0-d74b-47c8-816f-21955e7a30d3", 
            "RelatedFileInfo": {
                "FileIdentifier": null, 
                "FileIdentifierType": null
            }, 
            "Scope": null, 
            "Type": "RestrictCodeExecution", 
            "ID": "a57cd8a4-8d21-49e5-9a67-9fda06e1e637", 
            "RequestorComment": "Restrict code execution due to alert 1234"
        }
    ]
}
```

##### Human Readable Output
##### Machine actions Info:
|ID|Type|Requestor|RequestorComment|Status|MachineID|ComputerDNSName|
|---|---|---|---|---|---|---|
| 655b9413-0f41-49bc-a811-1aadc2c827d6 | RestrictCodeExecution | 2f48b784-5da5-4e61-9957-012d2630f1e4 | test restrict app | Succeeded | f70f9fe6b29cd9511652434919c6530618f06606 | desktop-s2455r9 |
| a57cd8a4-8d21-49e5-9a67-9fda06e1e637 | RestrictCodeExecution | 7bb424e0-d74b-47c8-816f-21955e7a30d3 | Restrict code execution due to alert 1234 | Cancelled | f3bba49af4d3bacedc62ca0fe580a4d5925af8aa | ec2amaz-ua9hieu |


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
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier with the possible values. Can be, "SHA1" ,"SHA256" and "MD5". | 


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
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier with the possible values. Can be, "SHA1" ,"SHA256" and "MD5". | 


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
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier with the possible values. Can be, "SHA1" ,"SHA256" and "MD5". | 


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
| MicrosoftATP.MachineAction.RelatedFileInfo.FileIdentifierType | String | The type of the file identifier with the possible values. Can be, "SHA1" ,"SHA256" and "MD5". | 


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
##### User demisto related alerts Info:
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
##### Machines that are related to user demisto:
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
Lists all indicators by the ID that the system creates when the indicator is ingested.


#### Base Command

`microsoft-atp-indicator-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum amount of indicators to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: unknown, allow, block, alert. | 
| MicrosoftATP.Indicators.additionalInformation | String | A catchall area into which extra data from the indicator not covered by the other tiIndicator properties may be placed. Data placed into additionalInformation will typically not be utilized by the targetProduct security tool. | 
| MicrosoftATP.Indicators.azureTenantId | String | Timestamp when the indicator was ingested into the system. | 
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Values are 0 – 100, with 100 being the highest. | 
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
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
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
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
| MicrosoftATP.Indicators.targetProduct | String | A string value representing a single security product to which the indicator should be applied. | 
| MicrosoftATP.Indicators.threatType | String | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList. | 
| MicrosoftATP.Indicators.tlpLevel | String | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. Possible values are: unknown, white, green, amber, and red. | 
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
Gets an indicator by its ID.


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
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Values are 0 – 100, with 100 being the highest. | 
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
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
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
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
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


### microsoft-atp-network-indicator-create
***
Creates a file indicator.


#### Base Command

`microsoft-atp-network-indicator-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to apply if the indicator is matched from within the targetProduct security tool. | Required | 
| description | Brief description (100 characters or less) of the threat represented by the indicator. | Required | 
| expiration_time | DateTime string indicating when the indicator expires. Format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). | Required | 
| threat_type | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, Cryptomining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, or WatchList. | Required | 
| tlp_level | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. | Optional | 
| confidence | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100 with 100 being the highest. | Optional | 
| severity | An integer representing the severity of the malicious behavior identified by the data within the indicator. Possible values are 0 – 5 where 5 is the most severe and zero is not severe at all. Default is 3 | Optional | 
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
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Values are 0 – 100, with 100 being the highest. | 
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
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
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
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
| MicrosoftATP.Indicators.targetProduct | String | A string value representing a single security product to which the indicator should be applied. | 
| MicrosoftATP.Indicators.threatType | String | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList. | 
| MicrosoftATP.Indicators.tlpLevel | String | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. Possible values are: unknown, white, green, amber, and red. | 
| MicrosoftATP.Indicators.url | String | Uniform Resource Locator. This URL complies with RFC 1738. | 
| MicrosoftATP.Indicators.userAgent | String | User-Agent string from a web request that could indicate compromise. | 
| MicrosoftATP.Indicators.vendorInformation | String | Information about the vendor. | 

#### Command Example
```!microsoft-atp-network-indicator-create action=unknown description="A description!" expiration_time="7 days" threat_type=CryptoMining domain_name="example.com"```

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

### microsoft-atp-file-indicator-create
***
Creates a file indicator


#### Base Command

`microsoft-atp-file-indicator-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to apply if the indicator is matched from within the targetProduct security tool. | Required | 
| description | Brief description (100 characters or less) of the threat represented by the indicator. | Required | 
| expiration_time | DateTime string indicating when the indicator expires. Format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). | Required | 
| threat_type | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, Cryptomining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, or WatchList. | Required | 
| tlp_level | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. | Optional | 
| confidence | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Possible values are 0 – 100 with 100 being the highest. | Optional | 
| severity | An integer representing the severity of the malicious behavior identified by the data within the indicator. Possible values are 0 – 5 where 5 is the most severe and zero is not severe at all. Default is 3 | Optional | 
| tags | A comma-separated list that stores arbitrary tags/keywords. | Optional | 
| file_compile_date_time | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | Optional | 
| file_created_date_time | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | Optional | 
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
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Values are 0 – 100, with 100 being the highest. | 
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
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
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
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
| MicrosoftATP.Indicators.targetProduct | String | A string value representing a single security product to which the indicator should be applied. | 
| MicrosoftATP.Indicators.threatType | String | Each indicator must have a valid Indicator Threat Type. Possible values are: Botnet, C2, CryptoMining, Darknet, DDoS, MaliciousUrl, Malware, Phishing, Proxy, PUA, WatchList. | 
| MicrosoftATP.Indicators.tlpLevel | String | Traffic Light Protocol value for the indicator. Possible values are: unknown, white, green, or amber. Possible values are: unknown, white, green, amber, and red. | 
| MicrosoftATP.Indicators.url | String | Uniform Resource Locator. This URL complies with RFC 1738. | 
| MicrosoftATP.Indicators.userAgent | String | User-Agent string from a web request that could indicate compromise. | 
| MicrosoftATP.Indicators.vendorInformation | String | Information about the vendor. | 

#### Command Example
```!microsoft-atp-file-indicator-create action=allow description="A description" expiration_time="3 days" threat_type=Darknet confidence=23 file_hash_type=sha256 file_hash_value=50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c```

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
Updates the specified indicator.


#### Base Command

`microsoft-atp-indicator-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | The ID of the indicator to update. | Required | 
| severity | An integer representing the severity of the malicious behavior identified by the data within the indicator. Possible values are 0 – 5 where 5 is the most severe and zero is not severe at all. Default is 3 | Optional | 
| expiration_time | DateTime string indicating when the indicator expires. Format: (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). | Required | 
| description | Brief description (100 characters or less) of the threat represented by the indicator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATP.Indicators.id | String | Created by the system when the indicator is ingested. Generated GUID/unique identifier. | 
| MicrosoftATP.Indicators.action | String | The action to apply if the indicator is matched from within the targetProduct security tool. Possible values are: unknown, allow, block, alert. | 
| MicrosoftATP.Indicators.additionalInformation | String | A catchall area into which extra data from the indicator not covered by the other tiIndicator properties may be placed. Data placed into additionalInformation will typically not be utilized by the targetProduct security tool. | 
| MicrosoftATP.Indicators.azureTenantId | String | Timestamp when the indicator was ingested into the system. | 
| MicrosoftATP.Indicators.confidence | Number | An integer representing the confidence with which the data within the indicator accurately identifies malicious behavior. Values are 0 – 100, with 100 being the highest. | 
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
| MicrosoftATP.Indicators.expirationDateTime | Date | DateTime string indicating when the indicator expires. To avoid stale indicators persisting in the system, all indicators must have an expiration date. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.externalId | String | An identification number that ties the indicator back to the indicator provider’s system \(e.g. a foreign key\). | 
| MicrosoftATP.Indicators.fileCompileDateTime | Date | DateTime when the file was compiled. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileCreatedDateTime | Date | DateTime when the file was created.The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.fileHashType | String | The type of hash stored in fileHashValue.  Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, or ctph. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash, ctph. | 
| MicrosoftATP.Indicators.fileHashValue | String | The file hash value. | 
| MicrosoftATP.Indicators.fileMutexName | String | Mutex name used in file-based detections. | 
| MicrosoftATP.Indicators.fileName | String | Name of the file if the indicator is file-based. Supports comma-separate list of file names. | 
| MicrosoftATP.Indicators.filePacker | String | The packer used to build the file in question. | 
| MicrosoftATP.Indicators.filePath | String | Path of the file indicating a compromise. May be a Windows or \*nix style. | 
| MicrosoftATP.Indicators.fileSize | Number | Size of the file in bytes. | 
| MicrosoftATP.Indicators.fileType | String | Text description of the type of file. For example, “Word Document” or “Binary”. | 
| MicrosoftATP.Indicators.ingestedDateTime | Date | Stamped by the system when the indicator is ingested. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MicrosoftATP.Indicators.isActive | Boolean | Used to deactivate indicators within system. By default, any indicator submitted is set as active. However, providers may submit existing indicators with this set to ‘False’ to deactivate indicators in the system. | 
| MicrosoftATP.Indicators.knownFalsePositives | String | Scenarios in which the indicator may cause false positives. This should be human-readable text. | 
| MicrosoftATP.Indicators.lastReportedDateTime | Date | The last time the indicator was seen. The Timestamp type represents date and time information in ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
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
| MicrosoftATP.Indicators.severity | Number | An integer representing the severity of the malicious behavior identified by the data within the indicator. Values are 0 – 5, where 5 is the most severe and zero is not severe at all. Default is 3 | 
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
Deletes the specified indicator.


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
