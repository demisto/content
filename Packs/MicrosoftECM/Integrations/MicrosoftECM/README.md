## Overview

The configuration manager provides the overall Configuration Management (CM) infrastructure and environment to the product development team  (formerly known as SCCM).

This integration was integrated and tested with version 1906 of Microsoft Endpoint Configuration Manager.
## Prerequisites
- This integration requires root access in order to execute commands. 
If you configured the server to run Docker images with a non-root internal user make sure to exclude the *demisto/powershell-ubuntu* Docker image as documented [here](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/docker/docker-hardening-guide/run-docker-with-non-root-internal-users.html)
- Installation and configuration for Windows Remote Management to support a PowerShell session is a prerequisite in order to support this integration. For more information, refer to the following Microsoft [Article](https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management).
- PowerShell Remote sessions are created over port 5985 (Microsoft Web service management/WinRm). This port needs to be opened from XSOAR to the hosts on the local and network firewalls. 
- Authentication is NTLM-based. 
- The integration requires a valid domain user with the permission set needed to perform the required remote tasks.
- Configuration Manager clients must be running the client from the 1706 release, or later in order to run scripts commands.
- To use scripts, you must be a member of the appropriate Configuration Manager security role.
- To use the ***ms-ecm-script-create*** command, your account must have Create permissions for SMS Scripts.
- To use the ***ms-ecm-script-approve*** command, your account must have Approve permissions for SMS Scripts.
- To use the ***ms-ecm-script-invoke*** command, your account must have Run Script permissions for Collections.
- To use the ***ms-ecm-service-stop***, ***ms-ecm-service-start***, and ***ms-ecm-service-restart*** commands, your account must have permissions to use **all** scripts commands
## Configure Microsoft Endpoint Configuration Manager on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Endpoint Configuration Manager.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ComputerName | ECM Server URL. \(e.g., 192.168.64.128\) | True |
| credentials | Username. \(i.e, DOMAIN\\username\)  | True |
| SiteCode | ECM Site Code. | True |

4. Click **Test** to validate the ComputerName, credentials, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ms-ecm-user-last-log-on
***
Gets the name of the last user who logged in to a given device.


#### Base Command

`ms-ecm-user-last-log-on`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_name | The name of a device. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.LastLogOnUser.IPAddresses | string | The IP addresses of the device. | 
| MicrosoftECM.LastLogOnUser.LastLogonTimestamp | date | The date of the last login to the device. | 
| MicrosoftECM.LastLogOnUser.LastLogonUserName | string | The name of the last user who logged in to the device. | 
| MicrosoftECM.LastLogOnUser.DeviceName | string | The name of the device. | 


#### Command Example
```!ms-ecm-user-last-log-on device_name=EC2AMAZ-2AKQ815```

#### Context Example
```json
{
    "MicrosoftECM": {
        "LastLogOnUser": {
            "DeviceName": "EC2AMAZ-2AKQ815",
            "IPAddresses": [
                "2.2.2.2",
                "fe80::81c5:1670:9363:a40b"
            ],
            "LastLogonTimestamp": "2020-11-12T06:07:29Z",
            "LastLogonUserName": null
        }
    }
}
```

#### Human Readable Output

>### Last log on user on EC2AMAZ-2AKQ815
>| LastLogonUserName | LastLogonTimestamp | DeviceName | IPAddresses
>| --- | --- | --- | ---
>|  | 2020\-11\-12T06:07:29Z | EC2AMAZ\-2AKQ815 | \["2.2.2.2","fe80::81c5:1670:9363:a40b"\]


### ms-ecm-collection-list
***
Gets a Configuration Manager collection.


#### Base Command

`ms-ecm-collection-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_type | A type for the collection. Valid values are: "User" and "Device." | Required | 
| collection_id | A collection ID. If you do not specify a collection, all collections in the hierarchy are returned. (You can retrieve the collection ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | A collection name. If you do not specify a collection, all collections in the hierarchy are returned. (You can retrieve the collection name via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection name. | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. | 
| MicrosoftECM.Collections.Type | string | The type of the collection. | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection. | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection. | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | Whether this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | The number of collections that are included and excluded in this collection. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | Whether the collection is built-in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | Whether the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last modified in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last modified. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The ID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | The number of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Name of the class having instances that are the members of the collection. | 
| MicrosoftECM.Collections.MemberCount | number | The number of collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | Whether this collection is a server group. | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection. | 


#### Command Example
```!ms-ecm-collection-list collection_name="All Systems" collection_type=Device```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Collections": {
            "CollectionRules": [
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select * from sms_r_system\";\n\tQueryID = 1;\n\tRuleName = \"All Systems\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_UNKNOWNSYSTEM.ResourceID,SMS_R_UNKNOWNSYSTEM.ResourceType,SMS_R_UNKNOWNSYSTEM.Name,SMS_R_UNKNOWNSYSTEM.Name,SMS_R_UNKNOWNSYSTEM.Name from SMS_R_UnknownSystem\";\n\tQueryID = 2;\n\tRuleName = \"All Unknown Computers\";\n};\n"
            ],
            "Comment": "All Systems",
            "CurrentStatus": "READY",
            "HasProvisionedMember": "True",
            "ID": "SMS00001",
            "IncludeExcludeCollectionsCount": "0",
            "IsBuiltIn": "True",
            "IsReferenceCollection": "True",
            "LastChangeTime": "2019-04-17T14:07:58Z",
            "LastMemberChangeTime": "2020-11-01T21:49:33Z",
            "LastRefreshTime": "2020-11-19T04:00:19Z",
            "LimitToCollectionID": "",
            "LimitToCollectionName": "",
            "LocalMemberCount": "5",
            "MemberClassName": "SMS_CM_RES_COLL_SMS00001",
            "MemberCount": "5",
            "Name": "All Systems",
            "Type": "Device",
            "UseCluster": "False"
        }
    }
}
```

#### Human Readable Output

>### Collection List
>| Comment | LastMemberChangeTime | LimitToCollectionName | HasProvisionedMember | LocalMemberCount | IsBuiltIn | IsReferenceCollection | Type | CollectionRules | MemberCount | MemberClassName | Name | ID | IncludeExcludeCollectionsCount | UseCluster | LastChangeTime | LimitToCollectionID | CurrentStatus | LastRefreshTime
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| All Systems | 2020\-11\-01T21:49:33Z |  | True | 5 | True | True | Device | <br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select \* from sms\_r\_system";<br/>	QueryID = 1;<br/>	RuleName = "All Systems";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_UNKNOWNSYSTEM.ResourceID,SMS\_R\_UNKNOWNSYSTEM.ResourceType,SMS\_R\_UNKNOWNSYSTEM.Name,SMS\_R\_UNKNOWNSYSTEM.Name,SMS\_R\_UNKNOWNSYSTEM.Name from SMS\_R\_UnknownSystem";<br/>	QueryID = 2;<br/>	RuleName = "All Unknown Computers";<br/>\};<br/> | 5 | SMS\_CM\_RES\_COLL\_SMS00001 | All Systems | SMS00001 | 0 | False | 2019\-04\-17T14:07:58Z |  | READY | 2020\-11\-19T04:00:19Z


### ms-ecm-device-list
***
Lists a Configuration Manager device.


#### Base Command

`ms-ecm-device-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | Specifies an ID for a device collection (You can retrieve the collection ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | Specifies the name of a device collection (You can retrieve the collection name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| limit | The maximum number of devices to be returned. Default is "100". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Devices.Name | string | The name of the device. | 
| MicrosoftECM.Devices.ResourceID | number | Unique Configuration Manager-supplied ID for the resource. | 


#### Command Example
```!ms-ecm-device-list collection_name="All Systems" limit=1```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Devices": {
            "DeviceName": "EC2AMAZ-2AKQ815",
            "ResourceID": 16777220
        }
    }
}
```

#### Human Readable Output

>### Devices List
>| DeviceName | ResourceID
>| --- | ---
>| EC2AMAZ\-2AKQ815 | 16777220


### ms-ecm-script-list
***
Gets Configuration Manager PowerShell scripts.


#### Base Command

`ms-ecm-script-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| author | The author of the script. (You can retrieve the name of the author of the script via the !ms-ecm-script-list command.) | Optional | 
| script_name | The script name. (You can retrieve the script name via the !ms-ecm-script-list command.) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Scripts.ApprovalState | string | The approval state of the script. | 
| MicrosoftECM.Scripts.Approver | string | The approver of the script. | 
| MicrosoftECM.Scripts.Author | string | The author of the script. | 
| MicrosoftECM.Scripts.Comment | string | A short comment about the script. | 
| MicrosoftECM.Scripts.LastUpdateTime | date | Date of the last script update. | 
| MicrosoftECM.Scripts.Parameterlist | string | The parameter list of the script. | 
| MicrosoftECM.Scripts.Script | string | The code of the script. | 
| MicrosoftECM.Scripts.ScriptGuid | string | The unique identifier of the script. | 
| MicrosoftECM.Scripts.ScriptHash | string | The hash of the script. | 
| MicrosoftECM.Scripts.ScriptHashAlgorithm | string | The algorithm with which the script hash was generated. | 
| MicrosoftECM.Scripts.ScriptName | string | The name of the script. | 
| MicrosoftECM.Scripts.ScriptType | string | The type of the script. | 
| MicrosoftECM.Scripts.ScriptVersion | number | The version of the script. | 


#### Command Example
```!ms-ecm-script-list script_name="XSOAR StartService"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Scripts": {
            "ApprovalState": "Approved",
            "Approver": "DEMISTO\\sccmadmin",
            "Author": "DEMISTO\\sccmadmin",
            "Comment": "XSOAR StartService script",
            "LastUpdateTime": "2020-11-19T14:28:36Z",
            "Parameterlist": null,
            "Script": "\ufffd\ufffdGet-Service 'dnscache' -ErrorAction Stop | Start-Service -PassThru -ErrorAction Stop",
            "ScriptGuid": "1984C9F9-7DCE-4191-AE20-B21281CB635B",
            "ScriptHash": "C19588A7660DF68072866BDFA37FE558A55DC350FD3BB0977245199CD4264752",
            "ScriptHashAlgorithm": "SHA256",
            "ScriptName": "XSOAR StartService",
            "ScriptType": 0,
            "ScriptVersion": "1"
        }
    }
}
```

#### Human Readable Output

>### Scripts List
>| ScriptHash | Script | Parameterlist | ScriptHashAlgorithm | ScriptGuid | Comment | ApprovalState | ScriptType | ScriptVersion | LastUpdateTime | ScriptName | Author | Approver
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| C19588A7660DF68072866BDFA37FE558A55DC350FD3BB0977245199CD4264752 | ��Get\-Service 'dnscache' \-ErrorAction Stop \| Start\-Service \-PassThru \-ErrorAction Stop |  | SHA256 | 1984C9F9\-7DCE\-4191\-AE20\-B21281CB635B | XSOAR StartService script | Approved | 0 | 1 | 2020\-11\-19T14:28:36Z | XSOAR StartService | DEMISTO\\sccmadmin | DEMISTO\\sccmadmin


### ms-ecm-script-create
***
Creates a new Powershell script.


#### Base Command

`ms-ecm-script-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_file_entry_id | The entry ID of the script file. | Optional | 
| script_text | The text of the string. | Optional | 
| script_name | The name of the script. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Scripts.ApprovalState | string | The approval state of the script. | 
| MicrosoftECM.Scripts.Approver | string | The approver of the script. | 
| MicrosoftECM.Scripts.Author | string | The author of the script. | 
| MicrosoftECM.Scripts.Comment | string | A short comment about the script. | 
| MicrosoftECM.Scripts.LastUpdateTime | date | Date of the last script update. | 
| MicrosoftECM.Scripts.Parameterlist | string | The parameter list of the script. | 
| MicrosoftECM.Scripts.Script | string | The code of the script. | 
| MicrosoftECM.Scripts.ScriptGuid | string | The unique identifier of the script. | 
| MicrosoftECM.Scripts.ScriptHash | string | The hash of the script. | 
| MicrosoftECM.Scripts.ScriptHashAlgorithm | string | The algorithm with which the script hash was generated. | 
| MicrosoftECM.Scripts.ScriptName | string | The name of the script. | 
| MicrosoftECM.Scripts.ScriptType | string | The type of the script. | 
| MicrosoftECM.Scripts.ScriptVersion | number | The version of the script. | 


#### Command Example
```!ms-ecm-script-create script_name="My new script" script_text="$PSVersionTable"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Scripts": {
            "ApprovalState": "Waiting for approval",
            "Approver": "",
            "Author": "DEMISTO\\sccmadmin",
            "Comment": "",
            "LastUpdateTime": "2020-11-19T14:50:44Z",
            "Parameterlist": null,
            "Script": "\ufffd\ufffd$PSVersionTable",
            "ScriptGuid": "91B1B3C9-D6C5-4096-A24D-24838F8646C5",
            "ScriptHash": "CE09E98D654CF613A0D219B744B56392E8356430534F309F715960E45A1417F8",
            "ScriptHashAlgorithm": "SHA256",
            "ScriptName": "My new script",
            "ScriptType": 0,
            "ScriptVersion": "1"
        }
    }
}
```

#### Human Readable Output

>### Scripts List
>| Comment | Parameterlist | ScriptHashAlgorithm | Script | Approver | Author | ScriptName | ScriptHash | LastUpdateTime | ScriptVersion | ApprovalState | ScriptGuid | ScriptType
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>|  |  | SHA256 | ��$PSVersionTable |  | DEMISTO\\sccmadmin | My new script | CE09E98D654CF613A0D219B744B56392E8356430534F309F715960E45A1417F8 | 2020\-11\-19T14:50:44Z | 1 | Waiting for approval | 91B1B3C9\-D6C5\-4096\-A24D\-24838F8646C5 | 0


### ms-ecm-script-invoke
***
Invokes a script in the Configuration Manager.


#### Base Command

`ms-ecm-script-invoke`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_guid | The script ID. (You can retrieve the script ID via the via `!ms-ecm-script-list` command.) | Required | 
| collection_id | The collection ID. (You can retrieve the collection ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | The collection name. (You can retrieve the collection name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| device_name | A device name in Configuration Manager. | Optional | 
| poll_results | Whether to poll for the script invocation results. Default is "false". | Optional | 
| timeout | The timeout in seconds to poll for invocation results. Default is "30". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID. | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection name of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the invocation result object was updated. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation. | 


#### Command Example
```!ms-ecm-script-invoke script_guid=394EDB29-5D89-4B9B-9745-A1F6DC8214E2 collection_name="All Systems" poll_results=true```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": [
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-PHPTDJV",
                "LastUpdateTime": "2020-11-19T14:51:20Z",
                "OperationId": 16777872,
                "ResourceId": 16777221,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "394EDB29-5D89-4B9B-9745-A1F6DC8214E2",
                "ScriptLastModifiedDate": "2020-09-24T14:29:14Z",
                "ScriptName": "Itay",
                "ScriptOutput": "{\"PSVersion\":{\"Major\":5,\"Minor\":1,\"Build\":14393,\"Revision\":2828,\"MajorRevision\":0,\"MinorRevision\":2828},\"PSEdition\":\"Desktop\",\"PSCompatibleVersions\":[{\"Major\":1,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":2,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":3,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":4,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":5,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":5,\"Minor\":1,\"Build\":14393,\"Revision\":2828,\"MajorRevision\":0,\"MinorRevision\":2828}],\"BuildVersion\":{\"Major\":10,\"Minor\":0,\"Build\":14393,\"Revision\":2828,\"MajorRevision\":0,\"MinorRevision\":2828},\"CLRVersion\":{\"Major\":4,\"Minor\":0,\"Build\":30319,\"Revision\":42000,\"MajorRevision\":0,\"MinorRevision\":-23536},\"WSManStackVersion\":{\"Major\":3,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},\"PSRemotingProtocolVersion\":{\"Major\":2,\"Minor\":3,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},\"SerializationVersion\":{\"Major\":1,\"Minor\":1,\"Build\":0,\"Revision\":1,\"MajorRevision\":0,\"MinorRevision\":1}}",
                "ScriptOutputHash": "EF8CDB402162E39E41C92FB87B8C54F8D3E5E8805ABC58E5BE6E31DBE94378CB",
                "ScriptVersion": "1",
                "TaskID": "{111F6FAA-5D5A-4693-9670-0A0184EC8766}"
            },
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-TB8VCPN",
                "LastUpdateTime": "2020-11-19T14:51:20Z",
                "OperationId": 16777872,
                "ResourceId": 16777222,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "394EDB29-5D89-4B9B-9745-A1F6DC8214E2",
                "ScriptLastModifiedDate": "2020-09-24T14:29:14Z",
                "ScriptName": "Itay",
                "ScriptOutput": "{\"PSVersion\":{\"Major\":5,\"Minor\":1,\"Build\":14393,\"Revision\":2608,\"MajorRevision\":0,\"MinorRevision\":2608},\"PSEdition\":\"Desktop\",\"PSCompatibleVersions\":[{\"Major\":1,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":2,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":3,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":4,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":5,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":5,\"Minor\":1,\"Build\":14393,\"Revision\":2608,\"MajorRevision\":0,\"MinorRevision\":2608}],\"BuildVersion\":{\"Major\":10,\"Minor\":0,\"Build\":14393,\"Revision\":2608,\"MajorRevision\":0,\"MinorRevision\":2608},\"CLRVersion\":{\"Major\":4,\"Minor\":0,\"Build\":30319,\"Revision\":42000,\"MajorRevision\":0,\"MinorRevision\":-23536},\"WSManStackVersion\":{\"Major\":3,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},\"PSRemotingProtocolVersion\":{\"Major\":2,\"Minor\":3,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},\"SerializationVersion\":{\"Major\":1,\"Minor\":1,\"Build\":0,\"Revision\":1,\"MajorRevision\":0,\"MinorRevision\":1}}",
                "ScriptOutputHash": "ADC6BF52B8EA29483BAB196925A0D52A2703A7386E289BBF6AA70E108399DA0F",
                "ScriptVersion": "1",
                "TaskID": "{111F6FAA-5D5A-4693-9670-0A0184EC8766}"
            },
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-2AKQ815",
                "LastUpdateTime": "2020-11-19T14:51:20Z",
                "OperationId": 16777872,
                "ResourceId": 16777220,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "394EDB29-5D89-4B9B-9745-A1F6DC8214E2",
                "ScriptLastModifiedDate": "2020-09-24T14:29:14Z",
                "ScriptName": "Itay",
                "ScriptOutput": "{\"PSVersion\":{\"Major\":5,\"Minor\":1,\"Build\":14393,\"Revision\":2969,\"MajorRevision\":0,\"MinorRevision\":2969},\"PSEdition\":\"Desktop\",\"PSCompatibleVersions\":[{\"Major\":1,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":2,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":3,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":4,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":5,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":5,\"Minor\":1,\"Build\":14393,\"Revision\":2969,\"MajorRevision\":0,\"MinorRevision\":2969}],\"BuildVersion\":{\"Major\":10,\"Minor\":0,\"Build\":14393,\"Revision\":2969,\"MajorRevision\":0,\"MinorRevision\":2969},\"CLRVersion\":{\"Major\":4,\"Minor\":0,\"Build\":30319,\"Revision\":42000,\"MajorRevision\":0,\"MinorRevision\":-23536},\"WSManStackVersion\":{\"Major\":3,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},\"PSRemotingProtocolVersion\":{\"Major\":2,\"Minor\":3,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},\"SerializationVersion\":{\"Major\":1,\"Minor\":1,\"Build\":0,\"Revision\":1,\"MajorRevision\":0,\"MinorRevision\":1}}",
                "ScriptOutputHash": "7E59C0C20E04A920734651297E46C7E7C0284E41B69B4E4DC3888D1767BA807D",
                "ScriptVersion": "1",
                "TaskID": "{111F6FAA-5D5A-4693-9670-0A0184EC8766}"
            }
        ]
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| CollectionName | ScriptExitCode | OperationId | ScriptGuid | LastUpdateTime | ScriptOutputHash | TaskID | ScriptVersion | ScriptExecutionState | ScriptOutput | ScriptName | ScriptLastModifiedDate | DeviceName | ResourceId | CollectionId
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| All Systems | 0 | 16777872 | 394EDB29\-5D89\-4B9B\-9745\-A1F6DC8214E2 | 2020\-11\-19T14:51:20Z | EF8CDB402162E39E41C92FB87B8C54F8D3E5E8805ABC58E5BE6E31DBE94378CB | \{111F6FAA\-5D5A\-4693\-9670\-0A0184EC8766\} | 1 | Succeeded | \{"PSVersion":\{"Major":5,"Minor":1,"Build":14393,"Revision":2828,"MajorRevision":0,"MinorRevision":2828\},"PSEdition":"Desktop","PSCompatibleVersions":\[\{"Major":1,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":2,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":4,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":1,"Build":14393,"Revision":2828,"MajorRevision":0,"MinorRevision":2828\}\],"BuildVersion":\{"Major":10,"Minor":0,"Build":14393,"Revision":2828,"MajorRevision":0,"MinorRevision":2828\},"CLRVersion":\{"Major":4,"Minor":0,"Build":30319,"Revision":42000,"MajorRevision":0,"MinorRevision":\-23536\},"WSManStackVersion":\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"PSRemotingProtocolVersion":\{"Major":2,"Minor":3,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"SerializationVersion":\{"Major":1,"Minor":1,"Build":0,"Revision":1,"MajorRevision":0,"MinorRevision":1\}\} | Itay | 2020\-09\-24T14:29:14Z | EC2AMAZ\-PHPTDJV | 16777221 | SMS00001
>| All Systems | 0 | 16777872 | 394EDB29\-5D89\-4B9B\-9745\-A1F6DC8214E2 | 2020\-11\-19T14:51:20Z | ADC6BF52B8EA29483BAB196925A0D52A2703A7386E289BBF6AA70E108399DA0F | \{111F6FAA\-5D5A\-4693\-9670\-0A0184EC8766\} | 1 | Succeeded | \{"PSVersion":\{"Major":5,"Minor":1,"Build":14393,"Revision":2608,"MajorRevision":0,"MinorRevision":2608\},"PSEdition":"Desktop","PSCompatibleVersions":\[\{"Major":1,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":2,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":4,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":1,"Build":14393,"Revision":2608,"MajorRevision":0,"MinorRevision":2608\}\],"BuildVersion":\{"Major":10,"Minor":0,"Build":14393,"Revision":2608,"MajorRevision":0,"MinorRevision":2608\},"CLRVersion":\{"Major":4,"Minor":0,"Build":30319,"Revision":42000,"MajorRevision":0,"MinorRevision":\-23536\},"WSManStackVersion":\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"PSRemotingProtocolVersion":\{"Major":2,"Minor":3,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"SerializationVersion":\{"Major":1,"Minor":1,"Build":0,"Revision":1,"MajorRevision":0,"MinorRevision":1\}\} | Itay | 2020\-09\-24T14:29:14Z | EC2AMAZ\-TB8VCPN | 16777222 | SMS00001
>| All Systems | 0 | 16777872 | 394EDB29\-5D89\-4B9B\-9745\-A1F6DC8214E2 | 2020\-11\-19T14:51:20Z | 7E59C0C20E04A920734651297E46C7E7C0284E41B69B4E4DC3888D1767BA807D | \{111F6FAA\-5D5A\-4693\-9670\-0A0184EC8766\} | 1 | Succeeded | \{"PSVersion":\{"Major":5,"Minor":1,"Build":14393,"Revision":2969,"MajorRevision":0,"MinorRevision":2969\},"PSEdition":"Desktop","PSCompatibleVersions":\[\{"Major":1,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":2,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":4,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":1,"Build":14393,"Revision":2969,"MajorRevision":0,"MinorRevision":2969\}\],"BuildVersion":\{"Major":10,"Minor":0,"Build":14393,"Revision":2969,"MajorRevision":0,"MinorRevision":2969\},"CLRVersion":\{"Major":4,"Minor":0,"Build":30319,"Revision":42000,"MajorRevision":0,"MinorRevision":\-23536\},"WSManStackVersion":\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"PSRemotingProtocolVersion":\{"Major":2,"Minor":3,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"SerializationVersion":\{"Major":1,"Minor":1,"Build":0,"Revision":1,"MajorRevision":0,"MinorRevision":1\}\} | Itay | 2020\-09\-24T14:29:14Z | EC2AMAZ\-2AKQ815 | 16777220 | SMS00001


### ms-ecm-script-approve
***
Approves a Configuration Manager PowerShell script.


#### Base Command

`ms-ecm-script-approve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | A comment about the approval of the script. | Required | 
| script_guid | Specifies the script ID. (You can retrieve the script ID via the `!ms-ecm-script-list` command.) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ms-ecm-script-approve comment="Some comment" script_guid=394EDB29-5D89-4B9B-9745-A1F6DC8214E2```


#### Human Readable Output

>### Script was approved successfully

### ms-ecm-device-collection-create
***
Creates a Configuration Manager collection.


#### Base Command

`ms-ecm-device-collection-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | A comment for the collection. | Required | 
| collection_name | A name for the collection. | Required | 
| limiting_collection_name | The name of a collection to use as a scope for this collection (You can retrieve the name of the collection via `!ms-ecm-collection-list collection_type="Device"`.) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection name. | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. | 
| MicrosoftECM.Collections.Type | string | The type of the collection. | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection. | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection. | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | Whether this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | The number of collections that are included and excluded with this collection. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | Whether the collection is built-in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | Whether the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last altered in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last modified. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The ID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | The number of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection. | 
| MicrosoftECM.Collections.MemberCount | number | The number of collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | Whether this collection is a server group. | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection. | 


#### Command Example
```!ms-ecm-device-collection-create collection_name="my new collection name" comment="my collection comment" limiting_collection_name="All Systems"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Collections": {
            "CollectionRules": [
                ""
            ],
            "Comment": "my collection comment",
            "CurrentStatus": null,
            "HasProvisionedMember": "False",
            "ID": "ISR0001F",
            "IncludeExcludeCollectionsCount": "0",
            "IsBuiltIn": "False",
            "IsReferenceCollection": "False",
            "LastChangeTime": "2020-11-29T15:09:46Z",
            "LastMemberChangeTime": "1980-00-01T00:01:00Z",
            "LastRefreshTime": "1980-00-01T00:01:00Z",
            "LimitToCollectionID": "SMS00001",
            "LimitToCollectionName": "All Systems",
            "LocalMemberCount": "0",
            "MemberClassName": "SMS_CM_RES_COLL_ISR0001F",
            "MemberCount": "0",
            "Name": "my new collection name",
            "Type": null,
            "UseCluster": "False"
        }
    }
}
```

#### Human Readable Output

>### Collection List
>| Name | ID | Type | Comment | CurrentStatus | CollectionRules | HasProvisionedMember | IncludeExcludeCollectionsCount | IsBuiltIn | IsReferenceCollection | LastChangeTime | LastMemberChangeTime | LastRefreshTime | LimitToCollectionID | LimitToCollectionName | LocalMemberCount | MemberClassName | MemberCount | UseCluster
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| my new collection name | ISR0001F |  | my collection comment |  |  | False | 0 | False | False | 2020\-11\-29T15:09:46Z | 1980\-00\-01T00:01:00Z | 1980\-00\-01T00:01:00Z | SMS00001 | All Systems | 0 | SMS\_CM\_RES\_COLL\_ISR0001F | 0 | False


### ms-ecm-device-collection-members-add
***
Adds a direct rule membership to a device collection.


#### Base Command

`ms-ecm-device-collection-members-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | The ID of a device collection. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | The name of a device collection. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| device_resource_ids | A comma-separated list of device resource IDs. (You can retrieve the device resource IDs via the `!ms-ecm-device-list` command.) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection name. | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. | 
| MicrosoftECM.Collections.Type | string | The type of the collection. | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection. | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection. | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | Whether the collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | The number of collections that are included and excluded with this collection. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | Whether the collection is built-in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | Whether the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last modified in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last modified. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The ID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | The number of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection. | 
| MicrosoftECM.Collections.MemberCount | number | The number of collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | A comma-separated list of resource IDs, e.g., 0001,0002. | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection. | 


#### Command Example
```!ms-ecm-device-collection-members-add device_resource_ids=16777220 collection_name="my new collection name"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Collections": {
            "CollectionRules": [
                "\ninstance of SMS_CollectionRuleDirect\n{\n\tResourceClassName = \"SMS_R_System\";\n\tResourceID = 16777220;\n\tRuleName = \"EC2AMAZ-2AKQ815\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 3;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 2;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 1;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleExcludeCollection\n{\n\tExcludeCollectionID = \"ISR00020\";\n\tRuleName = \"Test\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 5;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 4;\n\tRuleName = \"new Rule\";\n};\n"
            ],
            "Comment": "my collection comment",
            "CurrentStatus": "READY",
            "HasProvisionedMember": "True",
            "ID": "ISR00068",
            "IncludeExcludeCollectionsCount": "1",
            "IsBuiltIn": "False",
            "IsReferenceCollection": "False",
            "LastChangeTime": "2020-11-19T14:25:59Z",
            "LastMemberChangeTime": "2020-11-09T14:21:06Z",
            "LastRefreshTime": "2020-11-19T14:26:13Z",
            "LimitToCollectionID": "SMS00001",
            "LimitToCollectionName": "All Systems",
            "LocalMemberCount": "2",
            "MemberClassName": "SMS_CM_RES_COLL_ISR00068",
            "MemberCount": "2",
            "Name": "my new collection name",
            "Type": "Device",
            "UseCluster": "False"
        }
    }
}
```

#### Human Readable Output

>WARNING: The specified resource ID '16777220' is already existing in rules.


### ms-ecm-device-collection-include
***
Adds an include collections membership rule to a device collection.


#### Base Command

`ms-ecm-device-collection-include`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | The ID of a device collection. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | The name of a device collection. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| include_collection_id | The ID of a device collection to include in the membership rule. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| include_collection_name | The name of a device collection to include in the membership rule. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection name. | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. | 
| MicrosoftECM.Collections.Type | string | The type of the collection. | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection. | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection. | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | Whether this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | The number of collections that are included and excluded with this collection. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | Whether the collection is built-in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | Whether the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last modified in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last modified. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The ID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | The number of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection. | 
| MicrosoftECM.Collections.MemberCount | number | The number of collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | A comma-separated list of resource IDs, e.g., 0001,0002. | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection. | 


#### Command Example
``` 
!ms-ecm-device-collection-include collection_name="my new collection name" exclude_collection_name="Test"
```


### ms-ecm-device-collection-exclude
***
Adds an exclude membership rule to one or more Configuration Manager device collections.


#### Base Command

`ms-ecm-device-collection-exclude`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | The ID of a device collection. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | The name of a device collection. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| exclude_collection_id | The ID of a device collection to exclude from the membership rule. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| exclude_collection_name | The name of a device collection to exclude from the membership rule. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection name. | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. | 
| MicrosoftECM.Collections.Type | string | The type of the collection. | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection. | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection. | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | Whether this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | The number of collections that are included and excluded with this collection. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | Whether the collection is built-in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | Whether the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last modified in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last modified. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The ID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | The number of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection | 
| MicrosoftECM.Collections.MemberCount | number | The number of collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | A comma-separated list of resource IDs, e.g., 0001,0002. | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection. | 


#### Command Example
```!ms-ecm-device-collection-exclude collection_name="my new collection name" exclude_collection_name="Test"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Collections": {
            "CollectionRules": [
                "\ninstance of SMS_CollectionRuleExcludeCollection\n{\n\tExcludeCollectionID = \"ISR00014\";\n\tRuleName = \"Test\";\n};\n"
            ],
            "Comment": "my collection comment",
            "CurrentStatus": null,
            "HasProvisionedMember": "False",
            "ID": "ISR0001F",
            "IncludeExcludeCollectionsCount": "0",
            "IsBuiltIn": "False",
            "IsReferenceCollection": "False",
            "LastChangeTime": "2020-11-29T15:09:46Z",
            "LastMemberChangeTime": "2020-11-29T15:09:53Z",
            "LastRefreshTime": "2020-11-29T15:09:53Z",
            "LimitToCollectionID": "SMS00001",
            "LimitToCollectionName": "All Systems",
            "LocalMemberCount": "0",
            "MemberClassName": "SMS_CM_RES_COLL_ISR0001F",
            "MemberCount": "0",
            "Name": "my new collection name",
            "Type": null,
            "UseCluster": "False"
        }
    }
}
```

#### Human Readable Output

>### Collection List
>| Name | ID | Type | Comment | CurrentStatus | CollectionRules | HasProvisionedMember | IncludeExcludeCollectionsCount | IsBuiltIn | IsReferenceCollection | LastChangeTime | LastMemberChangeTime | LastRefreshTime | LimitToCollectionID | LimitToCollectionName | LocalMemberCount | MemberClassName | MemberCount | UseCluster
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| my new collection name | ISR0001F |  | my collection comment |  | <br/>instance of SMS\_CollectionRuleExcludeCollection<br/>\{<br/>	ExcludeCollectionID = "ISR00014";<br/>	RuleName = "Test";<br/>\};<br/> | False | 0 | False | False | 2020\-11\-29T15:09:46Z | 2020\-11\-29T15:09:53Z | 2020\-11\-29T15:09:53Z | SMS00001 | All Systems | 0 | SMS\_CM\_RES\_COLL\_ISR0001F | 0 | False


### ms-ecm-device-collection-members-by-query-add
***
Adds a query membership rule to one or more Configuration Manager device collections.


#### Base Command

`ms-ecm-device-collection-members-by-query-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | The ID of the device collection where the rule is applied. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | The name of the device collection where the rule is applied. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| query_expression | The query expression that Configuration Manager uses. For example "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)" to update the device collections. | Required | 
| rule_name | The name for the rule. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The name of the collection. | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. | 
| MicrosoftECM.Collections.Type | string | The type of the collection. | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection. | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection. | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | Whether this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | The number of collections that are included and excluded with this collection. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | Whether the collection is built-in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | Whether the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last modified in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last modified. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The ID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | The number of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection | 
| MicrosoftECM.Collections.MemberCount | number | The number of collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | A comma-separated list of resource IDs, e.g., 0001,0002. | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection. | 


#### Command Example
```!ms-ecm-device-collection-members-by-query-add query_expression="select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)" rule_name="new Rule" collection_name="my new collection name"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Collections": {
            "CollectionRules": [
                "\ninstance of SMS_CollectionRuleExcludeCollection\n{\n\tExcludeCollectionID = \"ISR00020\";\n\tRuleName = \"Test\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 1;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 2;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 3;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 4;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tQueryID = 5;\n\tRuleName = \"new Rule\";\n};",
                "\ninstance of SMS_CollectionRuleDirect\n{\n\tResourceClassName = \"SMS_R_System\";\n\tResourceID = 16777220;\n\tRuleName = \"EC2AMAZ-2AKQ815\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tRuleName = \"new Rule\";\n};\n"
            ],
            "Comment": "my collection comment",
            "CurrentStatus": "READY",
            "HasProvisionedMember": "True",
            "ID": "ISR00068",
            "IncludeExcludeCollectionsCount": "1",
            "IsBuiltIn": "False",
            "IsReferenceCollection": "False",
            "LastChangeTime": "2020-11-19T14:25:59Z",
            "LastMemberChangeTime": "2020-11-09T14:21:06Z",
            "LastRefreshTime": "2020-11-19T14:26:13Z",
            "LimitToCollectionID": "SMS00001",
            "LimitToCollectionName": "All Systems",
            "LocalMemberCount": "2",
            "MemberClassName": "SMS_CM_RES_COLL_ISR00068",
            "MemberCount": "2",
            "Name": "my new collection name",
            "Type": "Device",
            "UseCluster": "False"
        }
    }
}
```

#### Human Readable Output

>### Collection List
>| Comment | LimitToCollectionID | CurrentStatus | LastMemberChangeTime | Type | IncludeExcludeCollectionsCount | UseCluster | LastChangeTime | Name | LocalMemberCount | HasProvisionedMember | LimitToCollectionName | MemberClassName | IsReferenceCollection | CollectionRules | ID | LastRefreshTime | IsBuiltIn | MemberCount
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| my collection comment | SMS00001 | READY | 2020\-11\-09T14:21:06Z | Device | 1 | False | 2020\-11\-19T14:25:59Z | my new collection name | 2 | True | All Systems | SMS\_CM\_RES\_COLL\_ISR00068 | False | <br/>instance of SMS\_CollectionRuleExcludeCollection<br/>\{<br/>	ExcludeCollectionID = "ISR00020";<br/>	RuleName = "Test";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_SYSTEM.ResourceID,SMS\_R\_SYSTEM.ResourceType,SMS\_R\_SYSTEM.Name,SMS\_R\_SYSTEM.SMSUniqueIdentifier,SMS\_R\_SYSTEM.ResourceDomainORWorkgroup,SMS\_R\_SYSTEM.Client from SMS\_R\_System where \(ClientType = 1\) OR \(SMS\_R\_System.AgentEdition0 = 5\)";<br/>	QueryID = 1;<br/>	RuleName = "new Rule";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_SYSTEM.ResourceID,SMS\_R\_SYSTEM.ResourceType,SMS\_R\_SYSTEM.Name,SMS\_R\_SYSTEM.SMSUniqueIdentifier,SMS\_R\_SYSTEM.ResourceDomainORWorkgroup,SMS\_R\_SYSTEM.Client from SMS\_R\_System where \(ClientType = 1\) OR \(SMS\_R\_System.AgentEdition0 = 5\)";<br/>	QueryID = 2;<br/>	RuleName = "new Rule";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_SYSTEM.ResourceID,SMS\_R\_SYSTEM.ResourceType,SMS\_R\_SYSTEM.Name,SMS\_R\_SYSTEM.SMSUniqueIdentifier,SMS\_R\_SYSTEM.ResourceDomainORWorkgroup,SMS\_R\_SYSTEM.Client from SMS\_R\_System where \(ClientType = 1\) OR \(SMS\_R\_System.AgentEdition0 = 5\)";<br/>	QueryID = 3;<br/>	RuleName = "new Rule";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_SYSTEM.ResourceID,SMS\_R\_SYSTEM.ResourceType,SMS\_R\_SYSTEM.Name,SMS\_R\_SYSTEM.SMSUniqueIdentifier,SMS\_R\_SYSTEM.ResourceDomainORWorkgroup,SMS\_R\_SYSTEM.Client from SMS\_R\_System where \(ClientType = 1\) OR \(SMS\_R\_System.AgentEdition0 = 5\)";<br/>	QueryID = 4;<br/>	RuleName = "new Rule";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_SYSTEM.ResourceID,SMS\_R\_SYSTEM.ResourceType,SMS\_R\_SYSTEM.Name,SMS\_R\_SYSTEM.SMSUniqueIdentifier,SMS\_R\_SYSTEM.ResourceDomainORWorkgroup,SMS\_R\_SYSTEM.Client from SMS\_R\_System where \(ClientType = 1\) OR \(SMS\_R\_System.AgentEdition0 = 5\)";<br/>	QueryID = 5;<br/>	RuleName = "new Rule";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleDirect<br/>\{<br/>	ResourceClassName = "SMS\_R\_System";<br/>	ResourceID = 16777220;<br/>	RuleName = "EC2AMAZ\-2AKQ815";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_SYSTEM.ResourceID,SMS\_R\_SYSTEM.ResourceType,SMS\_R\_SYSTEM.Name,SMS\_R\_SYSTEM.SMSUniqueIdentifier,SMS\_R\_SYSTEM.ResourceDomainORWorkgroup,SMS\_R\_SYSTEM.Client from SMS\_R\_System where \(ClientType = 1\) OR \(SMS\_R\_System.AgentEdition0 = 5\)";<br/>	RuleName = "new Rule";<br/>\};<br/> | ISR00068 | 2020\-11\-19T14:26:13Z | False | 2


### ms-ecm-service-start
***
Starts a service on a device or collection. (Implemented by creating and invoking the `XSOAR StartService` script.)


#### Base Command

`ms-ecm-service-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_name | The name of the service. | Required | 
| device_name | The device name to start the service in. (You can retrieve the device name via the `!ms-ecm-device-list` command.) | Optional | 
| collection_id | The ID of the collection to start the service in. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | The name of the collection to start the service in. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| poll_results | Whether to poll for the script invocation results. Default is "false". | Optional | 
| timeout | The timeout in seconds to poll for invocation results. Default is "30". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID. | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection name of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the invocation result object was updated. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation. | 


#### Command Example
```!ms-ecm-service-start service_name=dnscache collection_name="All Systems" poll_results=true timeout=15```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": [
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-PHPTDJV",
                "LastUpdateTime": "2020-11-19T14:53:10Z",
                "OperationId": 16777874,
                "ResourceId": 16777221,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "CB2A5600-95A0-4663-9940-20E97BD26AC8",
                "ScriptLastModifiedDate": "2020-11-19T14:52:56Z",
                "ScriptName": "XSOAR StartService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SMS_SITE_VSS_WRITER SMS_SITE_SQL_BACKUP SMS_SITE_COMPONENT_MANAGER SMS_SITE_BACKUP SMS_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SMS_SITE_VSS_WRITER SMS_SITE_SQL_BACKUP SMS_SITE_COMPONENT_MANAGER SMS_SITE_BACKUP SMS_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "B03DDFEA2112E2743EFF47D0A450E762A864ECD55CF6D01AD6BF1A01E19BC78B",
                "ScriptVersion": "1",
                "TaskID": "{560F73AF-E4BC-447E-9C68-A7962E8E9B6B}"
            },
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-TB8VCPN",
                "LastUpdateTime": "2020-11-19T14:53:10Z",
                "OperationId": 16777874,
                "ResourceId": 16777222,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "CB2A5600-95A0-4663-9940-20E97BD26AC8",
                "ScriptLastModifiedDate": "2020-11-19T14:52:56Z",
                "ScriptName": "XSOAR StartService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "340EEE6517060B2B3A357561E719D9588DB65929CFD6091AF87A20D1AAED2BAF",
                "ScriptVersion": "1",
                "TaskID": "{560F73AF-E4BC-447E-9C68-A7962E8E9B6B}"
            },
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-2AKQ815",
                "LastUpdateTime": "2020-11-19T14:53:10Z",
                "OperationId": 16777874,
                "ResourceId": 16777220,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "CB2A5600-95A0-4663-9940-20E97BD26AC8",
                "ScriptLastModifiedDate": "2020-11-19T14:52:56Z",
                "ScriptName": "XSOAR StartService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "BD83747944C526E57E066BD863A2D6BBB4B5E81BFFC7310878F16C1505393E9C",
                "ScriptVersion": "1",
                "TaskID": "{560F73AF-E4BC-447E-9C68-A7962E8E9B6B}"
            }
        ]
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| CollectionName | ScriptExitCode | OperationId | ScriptGuid | LastUpdateTime | ScriptOutputHash | TaskID | ScriptVersion | ScriptExecutionState | ScriptOutput | ScriptName | ScriptLastModifiedDate | DeviceName | ResourceId | CollectionId
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| All Systems | 0 | 16777874 | CB2A5600\-95A0\-4663\-9940\-20E97BD26AC8 | 2020\-11\-19T14:53:10Z | B03DDFEA2112E2743EFF47D0A450E762A864ECD55CF6D01AD6BF1A01E19BC78B | \{560F73AF\-E4BC\-447E\-9C68\-A7962E8E9B6B\} | 1 | Succeeded | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | XSOAR StartService | 2020\-11\-19T14:52:56Z | EC2AMAZ\-PHPTDJV | 16777221 | SMS00001
>| All Systems | 0 | 16777874 | CB2A5600\-95A0\-4663\-9940\-20E97BD26AC8 | 2020\-11\-19T14:53:10Z | 340EEE6517060B2B3A357561E719D9588DB65929CFD6091AF87A20D1AAED2BAF | \{560F73AF\-E4BC\-447E\-9C68\-A7962E8E9B6B\} | 1 | Succeeded | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | XSOAR StartService | 2020\-11\-19T14:52:56Z | EC2AMAZ\-TB8VCPN | 16777222 | SMS00001
>| All Systems | 0 | 16777874 | CB2A5600\-95A0\-4663\-9940\-20E97BD26AC8 | 2020\-11\-19T14:53:10Z | BD83747944C526E57E066BD863A2D6BBB4B5E81BFFC7310878F16C1505393E9C | \{560F73AF\-E4BC\-447E\-9C68\-A7962E8E9B6B\} | 1 | Succeeded | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | XSOAR StartService | 2020\-11\-19T14:52:56Z | EC2AMAZ\-2AKQ815 | 16777220 | SMS00001


### ms-ecm-service-restart
***
Restarts a service on a device or collection. (Implemented by creating and invoking the `XSOAR RestartService` script.)


#### Base Command

`ms-ecm-service-restart`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_name | The name of the service. | Required | 
| device_name | The device name to start the service in. (You can retrieve the device name via the `!ms-ecm-device-list` command.) | Optional | 
| collection_id | The ID of the collection to start the service in. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | The name of the collection to start the service in. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| poll_results | Whether to poll for the script invocation results. Default is "false". | Optional | 
| timeout | The timeout in seconds to poll for invocation results. Default is "30". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID. | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection name of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the invocation result object was updated. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation. | 


#### Command Example
```!ms-ecm-service-restart service_name=dnscache collection_name="All Systems" poll_results=true timeout=15```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": [
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-PHPTDJV",
                "LastUpdateTime": "2020-11-19T14:52:35Z",
                "OperationId": 16777873,
                "ResourceId": 16777221,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "640C640F-7FED-4F80-812E-CF8C0852F2E5",
                "ScriptLastModifiedDate": "2020-11-19T14:52:22Z",
                "ScriptName": "XSOAR RestartService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SMS_SITE_VSS_WRITER SMS_SITE_SQL_BACKUP SMS_SITE_COMPONENT_MANAGER SMS_SITE_BACKUP SMS_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SMS_SITE_VSS_WRITER SMS_SITE_SQL_BACKUP SMS_SITE_COMPONENT_MANAGER SMS_SITE_BACKUP SMS_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "B03DDFEA2112E2743EFF47D0A450E762A864ECD55CF6D01AD6BF1A01E19BC78B",
                "ScriptVersion": "1",
                "TaskID": "{8E911C86-A0D8-4C29-ACEB-9FB183909128}"
            },
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-TB8VCPN",
                "LastUpdateTime": "2020-11-19T14:52:35Z",
                "OperationId": 16777873,
                "ResourceId": 16777222,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "640C640F-7FED-4F80-812E-CF8C0852F2E5",
                "ScriptLastModifiedDate": "2020-11-19T14:52:22Z",
                "ScriptName": "XSOAR RestartService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "340EEE6517060B2B3A357561E719D9588DB65929CFD6091AF87A20D1AAED2BAF",
                "ScriptVersion": "1",
                "TaskID": "{8E911C86-A0D8-4C29-ACEB-9FB183909128}"
            },
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-2AKQ815",
                "LastUpdateTime": "2020-11-19T14:52:35Z",
                "OperationId": 16777873,
                "ResourceId": 16777220,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "640C640F-7FED-4F80-812E-CF8C0852F2E5",
                "ScriptLastModifiedDate": "2020-11-19T14:52:22Z",
                "ScriptName": "XSOAR RestartService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "BD83747944C526E57E066BD863A2D6BBB4B5E81BFFC7310878F16C1505393E9C",
                "ScriptVersion": "1",
                "TaskID": "{8E911C86-A0D8-4C29-ACEB-9FB183909128}"
            }
        ]
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| CollectionId | ResourceId | ScriptExitCode | DeviceName | CollectionName | LastUpdateTime | ScriptVersion | ScriptExecutionState | ScriptOutput | ScriptGuid | ScriptLastModifiedDate | ScriptOutputHash | ScriptName | OperationId | TaskID
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| SMS00001 | 16777221 | 0 | EC2AMAZ\-PHPTDJV | All Systems | 2020\-11\-19T14:52:35Z | 1 | Succeeded | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | 640C640F\-7FED\-4F80\-812E\-CF8C0852F2E5 | 2020\-11\-19T14:52:22Z | B03DDFEA2112E2743EFF47D0A450E762A864ECD55CF6D01AD6BF1A01E19BC78B | XSOAR RestartService | 16777873 | \{8E911C86\-A0D8\-4C29\-ACEB\-9FB183909128\}
>| SMS00001 | 16777222 | 0 | EC2AMAZ\-TB8VCPN | All Systems | 2020\-11\-19T14:52:35Z | 1 | Succeeded | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | 640C640F\-7FED\-4F80\-812E\-CF8C0852F2E5 | 2020\-11\-19T14:52:22Z | 340EEE6517060B2B3A357561E719D9588DB65929CFD6091AF87A20D1AAED2BAF | XSOAR RestartService | 16777873 | \{8E911C86\-A0D8\-4C29\-ACEB\-9FB183909128\}
>| SMS00001 | 16777220 | 0 | EC2AMAZ\-2AKQ815 | All Systems | 2020\-11\-19T14:52:35Z | 1 | Succeeded | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | 640C640F\-7FED\-4F80\-812E\-CF8C0852F2E5 | 2020\-11\-19T14:52:22Z | BD83747944C526E57E066BD863A2D6BBB4B5E81BFFC7310878F16C1505393E9C | XSOAR RestartService | 16777873 | \{8E911C86\-A0D8\-4C29\-ACEB\-9FB183909128\}


### ms-ecm-service-stop
***
Stops a service on a device or collection. (Implemented by creating and invoking the `XSOAR StopService` script.)


#### Base Command

`ms-ecm-service-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_name | The name of the service. | Required | 
| device_name | The device name to start the service in. (You can retrieve the device name via the `!ms-ecm-device-list` command.) | Optional | 
| collection_id | The ID of the collection to start the service in. (You can retrieve the ID via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| collection_name | The name of the collection to start the service in. (You can retrieve the name via `!ms-ecm-collection-list collection_type="Device"`.) | Optional | 
| poll_results | Whether to poll for the script invocation results. Default is "false". | Optional | 
| timeout | The timeout in seconds to poll for invocation results. Default is "30". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID. | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection name of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the invocation result object was updated. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation. | 


#### Command Example
```!ms-ecm-service-stop service_name=dnscache collection_name="All Systems" poll_results=true timeout=15```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": [
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-PHPTDJV",
                "LastUpdateTime": "2020-11-19T14:53:40Z",
                "OperationId": 16777875,
                "ResourceId": 16777221,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "F6CD27EC-E932-4981-9CED-ECF78A06651D",
                "ScriptLastModifiedDate": "2020-11-19T14:53:31Z",
                "ScriptName": "XSOAR StopService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SMS_SITE_VSS_WRITER SMS_SITE_SQL_BACKUP SMS_SITE_COMPONENT_MANAGER SMS_SITE_BACKUP SMS_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":1,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SMS_SITE_VSS_WRITER SMS_SITE_SQL_BACKUP SMS_SITE_COMPONENT_MANAGER SMS_SITE_BACKUP SMS_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "2586F4DFD8FB133752E3DCC53248A417124F096777FC9EEE327B08DF0DEFD175",
                "ScriptVersion": "1",
                "TaskID": "{B038C34A-678C-49A2-BEEE-7EF2DA67831D}"
            },
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-TB8VCPN",
                "LastUpdateTime": "2020-11-19T14:53:40Z",
                "OperationId": 16777875,
                "ResourceId": 16777222,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "F6CD27EC-E932-4981-9CED-ECF78A06651D",
                "ScriptLastModifiedDate": "2020-11-19T14:53:31Z",
                "ScriptName": "XSOAR StopService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":1,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "D27B022F6B8C8B584A79BB2D471EA173AE45588AAE28225563A38FC93B4EF2C6",
                "ScriptVersion": "1",
                "TaskID": "{B038C34A-678C-49A2-BEEE-7EF2DA67831D}"
            },
            {
                "CollectionId": "SMS00001",
                "CollectionName": "All Systems",
                "DeviceName": "EC2AMAZ-2AKQ815",
                "LastUpdateTime": "2020-11-19T14:53:40Z",
                "OperationId": 16777875,
                "ResourceId": 16777220,
                "ScriptExecutionState": "Succeeded",
                "ScriptExitCode": "0",
                "ScriptGuid": "F6CD27EC-E932-4981-9CED-ECF78A06651D",
                "ScriptLastModifiedDate": "2020-11-19T14:53:31Z",
                "ScriptName": "XSOAR StopService",
                "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":1,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
                "ScriptOutputHash": "FC945DDB2710DA5E73E6A8F359EE556A85A59671018831092493AD0EA013DE99",
                "ScriptVersion": "1",
                "TaskID": "{B038C34A-678C-49A2-BEEE-7EF2DA67831D}"
            }
        ]
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| CollectionName | TaskID | ScriptOutput | ScriptGuid | ScriptExecutionState | ScriptLastModifiedDate | CollectionId | ScriptVersion | DeviceName | LastUpdateTime | ScriptName | ResourceId | ScriptOutputHash | ScriptExitCode | OperationId
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| All Systems | \{B038C34A\-678C\-49A2\-BEEE\-7EF2DA67831D\} | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":1,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | F6CD27EC\-E932\-4981\-9CED\-ECF78A06651D | Succeeded | 2020\-11\-19T14:53:31Z | SMS00001 | 1 | EC2AMAZ\-PHPTDJV | 2020\-11\-19T14:53:40Z | XSOAR StopService | 16777221 | 2586F4DFD8FB133752E3DCC53248A417124F096777FC9EEE327B08DF0DEFD175 | 0 | 16777875
>| All Systems | \{B038C34A\-678C\-49A2\-BEEE\-7EF2DA67831D\} | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":1,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | F6CD27EC\-E932\-4981\-9CED\-ECF78A06651D | Succeeded | 2020\-11\-19T14:53:31Z | SMS00001 | 1 | EC2AMAZ\-TB8VCPN | 2020\-11\-19T14:53:40Z | XSOAR StopService | 16777222 | D27B022F6B8C8B584A79BB2D471EA173AE45588AAE28225563A38FC93B4EF2C6 | 0 | 16777875
>| All Systems | \{B038C34A\-678C\-49A2\-BEEE\-7EF2DA67831D\} | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":1,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | F6CD27EC\-E932\-4981\-9CED\-ECF78A06651D | Succeeded | 2020\-11\-19T14:53:31Z | SMS00001 | 1 | EC2AMAZ\-2AKQ815 | 2020\-11\-19T14:53:40Z | XSOAR StopService | 16777220 | FC945DDB2710DA5E73E6A8F359EE556A85A59671018831092493AD0EA013DE99 | 0 | 16777875


### ms-ecm-script-invocation-results
***
Gets a script invocation results.


#### Base Command

`ms-ecm-script-invocation-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | The script invocation operation ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID. | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection name of the device on which the script was invoked. on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the invocation result object was updated. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation. | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked. | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation. | 


#### Command Example
```!ms-ecm-script-invocation-results operation_id=16777267```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": {
            "CollectionId": "SMS00001",
            "CollectionName": "All Systems",
            "DeviceName": "EC2AMAZ-2AKQ815",
            "LastUpdateTime": "2020-09-29T10:57:15Z",
            "OperationId": 16777267,
            "ResourceId": 16777220,
            "ScriptExecutionState": "Failed",
            "ScriptExitCode": "-2147467259",
            "ScriptGuid": "2E0D961D-1C89-477D-B1A7-3FFEDC0AF2FA",
            "ScriptLastModifiedDate": "2020-09-24T14:36:32Z",
            "ScriptName": "Fail",
            "ScriptOutput": "",
            "ScriptOutputHash": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            "ScriptVersion": "1",
            "TaskID": "{FC58140A-B688-4D2E-8FEE-F7AED348FABF}"
        }
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| CollectionName | TaskID | ScriptOutput | ScriptGuid | ScriptExecutionState | ScriptLastModifiedDate | CollectionId | ScriptVersion | DeviceName | LastUpdateTime | ScriptName | ResourceId | ScriptOutputHash | ScriptExitCode | OperationId
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| All Systems | \{FC58140A\-B688\-4D2E\-8FEE\-F7AED348FABF\} |  | 2E0D961D\-1C89\-477D\-B1A7\-3FFEDC0AF2FA | Failed | 2020\-09\-24T14:36:32Z | SMS00001 | 1 | EC2AMAZ\-2AKQ815 | 2020\-09\-29T10:57:15Z | Fail | 16777220 | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | \-2147467259 | 16777267


### ms-ecm-device-get-collection-member
***
Gets a Configuration Manager device by querying the SMS_CM_RES_COLL_SMS00001 class. You can use the `ms-ecm-device-get-resource` or `ms-ecm-device-get-collection-member` commands to change the query class. Depending upon your role-based access in the site, you may need to use one of these other commands.


#### Base Command

`ms-ecm-device-get-collection-member`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_names | A comma-separated list of device names, i.e., `name1,name2,etc.`. | Optional | 
| resource_ids | A comma-separated list of resource IDs, i.e., `ID1,ID2,etc.`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Devices.DeviceName | string | The name of the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.ClientVersion | string | Version of the installed client software. | 
| MicrosoftECM.Devices.CollectionMemberDetails.DeviceOS | string | Device operating system. | 
| MicrosoftECM.Devices.ResourceID | number | Unique Configuration Manager-supplied ID for the resource. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsActive | boolean | Whether there has been a recent heartbeat from the client. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastActiveTime | date | The last reported time the client was active. Comes from Client Health. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastClientCheckTime | date | The last reported health evaluation time. Comes from Client Health. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastDDR | date | Last heartbeat timestamp from client DDR discovery. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastHardwareScan | date | Timestamp from the last hardware inventory scan. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastPolicyRequest | date | Timestamp of the last policy request for this client. | 
| MicrosoftECM.Devices.CollectionMemberDetails.Domain | string | Domain to which the resource belongs. | 
| MicrosoftECM.Devices.CollectionMemberDetails.PrimaryUser | string | The primary user of the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.Status | string | Current status of the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.MACAddress | string | The MAC address of the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsVirtualMachine | boolean | Whether the client is a virtual machine. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsDecommissioned | boolean | Whether the collection member is decommissioned. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsClient | boolean | Whether the client is a Configuration Manager client. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsBlocked | boolean | Whether the system is blocked. The administrator can manually block/unblock a client in the Admin console UI. By blocking a client, client communication with the server will be cut off. | 
| MicrosoftECM.Devices.CollectionMemberDetails.ExchangeServer | string | Name of the exchange server for Exchange Active Sync \(EAS\). | 
| MicrosoftECM.Devices.CollectionMemberDetails.DeviceThreatLevel | string | The threat level of the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.CurrentLogonUser | string | The user who is currently logged in. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastLogonUser | string | The last user who logged in to the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.DeviceOSBuild | string | The operating system build number of the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.ADLastLogonTime | date | Last logon timestamp of the computer \(discovered from Active Directory\). | 
| MicrosoftECM.Devices.CollectionMemberDetails.SiteCode | string | Site code of the site that created the collection. | 


#### Command Example
```!ms-ecm-device-get-collection-member device_names=EC2AMAZ-2AKQ815```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Devices": {
            "CollectionMemberDetails": {
                "ADLastLogonTime": "2020-11-12T06:07:29",
                "ClientVersion": "5.00.8790.1007",
                "CurrentLogonUser": null,
                "DeviceOS": "Microsoft Windows NT Advanced Server 10.0",
                "DeviceOSBuild": "10.0.14393.3025",
                "DeviceThreatLevel": null,
                "Domain": "DEMISTO",
                "ExchangeServer": null,
                "IsActive": true,
                "IsBlocked": false,
                "IsClient": true,
                "IsDecommissioned": false,
                "IsVirtualMachine": false,
                "LastActiveTime": "2020-11-19T13:10:59Z",
                "LastClientCheckTime": "2020-11-07T16:42:39Z",
                "LastDDR": "2020-11-18T18:30:48Z",
                "LastHardwareScan": "2020-11-15T11:49:36Z",
                "LastLogonUser": null,
                "LastPolicyRequest": "2020-11-19T13:10:59Z",
                "PrimaryUser": "demisto\\sccmadmin",
                "SiteCode": "ISR",
                "Status": null
            },
            "DeviceName": "EC2AMAZ-2AKQ815",
            "ResourceID": 16777220
        }
    }
}
```

#### Human Readable Output

>### Device As Collection Member
>| ClientVersion | ResourceID | IsActive | IsBlocked | DeviceOSBuild | LastHardwareScan | SiteCode | DeviceName | LastPolicyRequest | DeviceThreatLevel | CurrentLogonUser | PrimaryUser | ExchangeServer | LastClientCheckTime | LastDDR | IsDecommissioned | LastLogonUser | Domain | Status | LastActiveTime | IsClient | ADLastLogonTime | IsVirtualMachine | DeviceOS
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| 5.00.8790.1007 | 16777220 | True | False | 10.0.14393.3025 | 2020\-11\-15T11:49:36Z | ISR | EC2AMAZ\-2AKQ815 | 2020\-11\-19T13:10:59Z |  |  | demisto\\sccmadmin |  | 2020\-11\-07T16:42:39Z | 2020\-11\-18T18:30:48Z | False |  | DEMISTO |  | 2020\-11\-19T13:10:59Z | True | 11/12/2020 6:07:29 AM | False | Microsoft Windows NT Advanced Server 10.0


### ms-ecm-device-get-resource
***
Gets a Configuration Manager device by querying the SMS_R_System class. You can use the `ms-ecm-device-get-resource` or `ms-ecm-device-get-collection-member` commands to change the query class. Depending upon your role-based access in the site, you may need to use one of these other commands.


#### Base Command

`ms-ecm-device-get-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_names | A comma-separated list of device names, i.e., `name1,name2,etc.`. | Optional | 
| resource_ids | A comma-separated list of resource ids, i.e., `ID1,ID2,etc.`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Devices.DeviceName | string | The name of the device. | 
| MicrosoftECM.Devices.ResourceDetails.AgentName | string | List of the names of discovery agents that found the resource. | 
| MicrosoftECM.Devices.ResourceID | number | Configuration Manager-supplied ID that uniquely identifies a Configuration Manager client resource. | 
| MicrosoftECM.Devices.ResourceDetails.ADSiteName | string | The Active Directory site name that is assigned to the client. | 
| MicrosoftECM.Devices.ResourceDetails.AgentSite | string | List of sites from which the discovery agents run. | 
| MicrosoftECM.Devices.ResourceDetails.AgentTime | date | List of discovery dates and times. | 
| MicrosoftECM.Devices.ResourceDetails.CPUType | string | The CPU type, for example, StrongARM. Currently, only device clients report this value. | 
| MicrosoftECM.Devices.ResourceDetails.DistinguishedName | string | The distinguished name of the account. | 
| MicrosoftECM.Devices.ResourceDetails.FullDomainName | string | The full name of the device's domain | 
| MicrosoftECM.Devices.ResourceDetails.IPv4Addresses | string | List of the IPv4 addresses that are associated with the resource. More than one address is listed if the resource has multiple network cards installed. | 
| MicrosoftECM.Devices.ResourceDetails.IPv6Addresses | string | List of the IPv6 addresses that are associated with the resource. More than one address is listed if the resource has multiple network cards installed. | 
| MicrosoftECM.Devices.ResourceDetails.NetbiosName | string | Name used by the NetBIOS protocol. | 
| MicrosoftECM.Devices.ResourceDetails.UserAccountControl | number | User account control value retrieved from Active Directory. | 
| MicrosoftECM.Devices.ResourceDetails.LastLogonUserName | date | Name of the last logged-on user at the time the discovery agent ran. | 
| MicrosoftECM.Devices.ResourceDetails.LastLogonUserDomain | string | Domain used by the last logged-on user at the time the discovery agent ran. | 
| MicrosoftECM.Devices.ResourceDetails.LastLogonTimestamp | date | The date of the last user logon. | 
| MicrosoftECM.Devices.ResourceDetails.OperatingSystemNameandVersion | string | Free-form string that describes the operating system. | 
| MicrosoftECM.Devices.ResourceDetails.VirtualMachineHostName | string | Virtual machine hostname. | 
| MicrosoftECM.Devices.ResourceDetails.VirtualMachineType | string | The type of the virtual machine. | 
| MicrosoftECM.Devices.ResourceDetails.DNSForestGuid | string | A unique identifier for the DNS forest. | 
| MicrosoftECM.Devices.ResourceDetails.HardwareID | string | An ID that uniquely describes the hardware on which the client is installed. This ID remains unchanged through re-imaging or through successive installations of the operating system or client. This differs from the Configuration Manager unique ID, which might change under these circumstances. | 


#### Command Example
```!ms-ecm-device-get-resource device_names=EC2AMAZ-2AKQ815```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Devices": {
            "DeviceName": "EC2AMAZ-2AKQ815",
            "ResourceDetails": {
                "ADSiteName": "Default-First-Site-Name",
                "AgentName": [
                    "SMS_AD_SYSTEM_DISCOVERY_AGENT",
                    "MP_ClientRegistration",
                    "Heartbeat Discovery"
                ],
                "AgentSite": [
                    "ISR",
                    "ISR",
                    "ISR"
                ],
                "AgentTime": [
                    "2020-11-19T00:00:01Z",
                    "2019-07-07T10:12:48Z",
                    "2020-11-19T14:30:48Z"
                ],
                "CPUType": "Intel64 Family 6 Model 85 Stepping 4",
                "DNSForestGuid": "E8AA1F36-33BE-41F2-ADCB-E40376F5B168",
                "DistinguishedName": "CN=EC2AMAZ-2AKQ815,CN=Computers,DC=demisto,DC=local",
                "FullDomainName": "DEMISTO.LOCAL",
                "HardwareID": "2:387B42C549C5E7D718B68BC65959FA9041F7F2D0",
                "IPv4Addresses": "2.2.2.2",
                "IPv6Addresses": "fe80::81c5:1670:9363:a40b",
                "LastLogonTimestamp": "2020-11-12T06:07:29Z",
                "LastLogonUserDomain": null,
                "LastLogonUserName": null,
                "NetbiosName": "EC2AMAZ-2AKQ815",
                "OperatingSystemNameandVersion": "Microsoft Windows NT Advanced Server 10.0",
                "UserAccountControl": 4096,
                "VirtualMachineHostName": "",
                "VirtualMachineType": 0
            },
            "ResourceID": 16777220
        }
    }
}
```

#### Human Readable Output

>### Device As Resource
>| DistinguishedName | VirtualMachineHostName | AgentTime | OperatingSystemNameandVersion | IPv4Addresses | AgentSite | AgentName | ADSiteName | FullDomainName | VirtualMachineType | CPUType | UserAccountControl | NetbiosName | LastLogonTimestamp | HardwareID | DNSForestGuid | LastLogonUserName | IPv6Addresses | DeviceName | LastLogonUserDomain | ResourceID
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| CN=EC2AMAZ\-2AKQ815,CN=Computers,DC=demisto,DC=local |  | \["2020\-11\-19T00:00:01Z","2019\-07\-07T10:12:48Z","2020\-11\-19T14:30:48Z"\] | Microsoft Windows NT Advanced Server 10.0 | "2.2.2.2" | \["ISR","ISR","ISR"\] | \["SMS\_AD\_SYSTEM\_DISCOVERY\_AGENT","MP\_ClientRegistration","Heartbeat Discovery"\] | Default\-First\-Site\-Name | DEMISTO.LOCAL | 0 | Intel64 Family 6 Model 85 Stepping 4 | 4096 | EC2AMAZ\-2AKQ815 | 2020\-11\-12T06:07:29Z | 2:387B42C549C5E7D718B68BC65959FA9041F7F2D0 | E8AA1F36\-33BE\-41F2\-ADCB\-E40376F5B168 |  | "fe80::81c5:1670:9363:a40b" | EC2AMAZ\-2AKQ815 |  | 16777220


### ms-ecm-get-user-device-affinity
***
Gets the relationships between a device and its primary users.


#### Base Command

`ms-ecm-get-user-device-affinity`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_names | A comma-separated list of usernames with the form of "Domain\username" i.e., "Domain\user1,Domain\user2",etc.". | Optional | 
| resource_ids | A comma-separated list of device resource ids, i.e., `ID1,ID2,etc.`. | Optional | 
| device_names | A comma-separated list of device names, i.e., `name1,name2,etc.`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.UserDeviceAffinity.DeviceName | string | The name of the device. | 
| MicrosoftECM.UserDeviceAffinity.UserName | string | The user name in domain\\user format. | 
| MicrosoftECM.UserDeviceAffinity.ResourceID | number | The resource ID of the device. | 
| MicrosoftECM.UserDeviceAffinity.IsActive | boolean | Whether the relationship is active. | 
| MicrosoftECM.UserDeviceAffinity.CreationTime | date | The time when the relationship was created. | 
| MicrosoftECM.UserDeviceAffinity.RelationshipResourceID | number | The unique identifier for this relationship. | 


#### Command Example
```!ms-ecm-get-user-device-affinity device_names=EC2AMAZ-2AKQ815```

#### Context Example
```json
{
    "MicrosoftECM": {
        "UserDeviceAffinity": [
            {
                "CreationTime": "2020-09-07T14:52:57Z",
                "DeviceName": "EC2AMAZ-2AKQ815",
                "IsActive": true,
                "RelationshipResourceID": 25165825,
                "ResourceID": 16777220,
                "UserName": "demisto\\sccmadmin"
            },
            {
                "CreationTime": "2020-11-05T17:44:33Z",
                "DeviceName": "EC2AMAZ-2AKQ815",
                "IsActive": true,
                "RelationshipResourceID": 25165830,
                "ResourceID": 16777220,
                "UserName": "demisto\\administrator"
            }
        ]
    }
}
```

#### Human Readable Output

>### User Device Affinity
>| IsActive | DeviceName | ResourceID | CreationTime | UserName | RelationshipResourceID
>| --- | --- | --- | --- | --- | ---
>| True | EC2AMAZ\-2AKQ815 | 16777220 | 2020\-09\-07T14:52:57Z | demisto\\sccmadmin | 25165825
>| True | EC2AMAZ\-2AKQ815 | 16777220 | 2020\-11\-05T17:44:33Z | demisto\\administrator | 25165830

