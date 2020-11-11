## Overview

The configuration manager provides the overall Configuration Management (CM) infrastructure and environment to the product development team  (formerly known as SCCM).

This integration was integrated and tested with version 1906 of Microsoft Endpoint Configuration Manager.
## Prerequisites
- This integration requires root access in order to execute commands. 
If you configured the server to run Docker images with a non-root internal user make sure to exclude the *demisto/powershell-ubuntu* Docker image as documented [here](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/5-5/cortex-xsoar-admin/docker/docker-hardening-guide/run-docker-with-non-root-internal-users.html)
- Installation and configuration for Windows Remote Management to support a PowerShell session is a prerequisite in order to support this integration. For more information,  refer to the following Microsoft [Article](https://docs.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management).
- PowerShell Remote sessions are created over port 5985 (Microsoft Web service management/WinRm). This port needs to be opened from XSOAR to the hosts on the local and network firewalls. 
- Authentication is NTLM-based. 
- The integration requires a valid domain user with the permission set needed to perform the required remote tasks.
- Configuration Manager clients must be running the client from the 1706 release, or later in order to run scripts commands.
- To use scripts, you must be a member of the appropriate Configuration Manager security role.
- To use `ms-ecm-script-create` command - Your account must have Create permissions for SMS Scripts.
- To use `ms-ecm-script-approve` - Your account must have Approve permissions for SMS Scripts.
- To use `ms-ecm-script-invoke` - Your account must have Run Script permissions for Collections.
- To use the commands `ms-ecm-service-stop`, `ms-ecm-service-start`, `ms-ecm-service-restart` - Your account must have permissions to use **all** scripts commands
## Configure Microsoft Endpoint Configuration Manager on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Endpoint Configuration Manager.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ComputerName | ECM Server URL \(e.g., 192.168.64.128\) | True |
| credentials | Username \(i.e, DOMAIN\\username\)  | True |
| SiteCode | ECM Site Code | True |

4. Click **Test** to validate the ComputerName, credentials, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ms-ecm-user-last-log-on
***
Gets the last user that logged on to a given device name


#### Base Command

`ms-ecm-user-last-log-on`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_name | Specifies the name of a device. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.LastLogOnUser.IPAddresses | string | The IPAddresses of the device | 
| MicrosoftECM.LastLogOnUser.LastLogonTimestamp | date | The date of the last login to the device | 
| MicrosoftECM.LastLogOnUser.LastLogonUserName | string | The name of the last user who logged in  to the device | 
| MicrosoftECM.LastLogOnUser.Name | string | The name of the device | 


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
            "LastLogonTimestamp": "2020-11-02T05:34:01Z",
            "LastLogonUserName": null
        }
    }
}
```

#### Human Readable Output

>### Last log on user on EC2AMAZ-2AKQ815
>| LastLogonTimestamp | IPAddresses | DeviceName | LastLogonUserName
>| --- | --- | --- | ---
>| 2020\-11\-02T05:34:01Z | \["2.2.2.2","fe80::81c5:1670:9363:a40b"\] | EC2AMAZ\-2AKQ815 | 


### ms-ecm-user-get-primary
***
Get the primary user of a given computer name


#### Base Command

`ms-ecm-user-get-primary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_name | Specifies the name of a device. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.PrimaryUsers.MachineName | string | The name of the computer | 
| MicrosoftECM.PrimaryUsers.UserName | string | The name of the primary user | 


#### Command Example
```!ms-ecm-user-get-primary device_name=EC2AMAZ-2AKQ815```

#### Context Example
```json
{
    "MicrosoftECM": {
        "PrimaryUsers": {
            "MachineName": "EC2AMAZ-2AKQ815",
            "UserName": "demisto\\sccmadmin"
        }
    }
}
```

#### Human Readable Output

>### Primary users on EC2AMAZ-2AKQ815
>| MachineName | UserName
>| --- | ---
>| EC2AMAZ\-2AKQ815 | demisto\\sccmadmin


### ms-ecm-collection-list
***
Gets a Configuration Manager collection


#### Base Command

`ms-ecm-collection-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_type | Specifies a type for the collection. Valid values are:  Root User Device Unknown | Required | 
| collection_id | Specifies a collection ID. If you do not specify a collection, all collections in the hierarchy are returned (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | Specifies a collection name. If you do not specify a collection, all collections in the hierarchy are returned (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection's name | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. The default value is "" | 
| MicrosoftECM.Collections.Type | string | The type of the collection | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | true if this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | Count of collections that are included and excluded with this one. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | This value, when set to true, denotes that the collection is built in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | This value, when set to true, denotes that the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last altered in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last altered. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The CollectionID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The Name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | Count of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection | 
| MicrosoftECM.Collections.MemberCount | number | A count of the collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | Specifies that this collection is a server group. | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection | 


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
            "CurrentStatus": null,
            "HasProvisionedMember": "True",
            "ID": "SMS00001",
            "IncludeExcludeCollectionsCount": "0",
            "IsBuiltIn": "True",
            "IsReferenceCollection": "True",
            "LastChangeTime": "2019-07-17T14:04:58Z",
            "LastMemberChangeTime": "2019-15-07T10:07:35Z",
            "LastRefreshTime": "2020-00-29T04:09:39Z",
            "LimitToCollectionID": "",
            "LimitToCollectionName": "",
            "LocalMemberCount": "5",
            "MemberClassName": "SMS_CM_RES_COLL_SMS00001",
            "MemberCount": "5",
            "Name": "All Systems",
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
>| All Systems | SMS00001 |  | All Systems |  | <br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select \* from sms\_r\_system";<br/>	QueryID = 1;<br/>	RuleName = "All Systems";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_UNKNOWNSYSTEM.ResourceID,SMS\_R\_UNKNOWNSYSTEM.ResourceType,SMS\_R\_UNKNOWNSYSTEM.Name,SMS\_R\_UNKNOWNSYSTEM.Name,SMS\_R\_UNKNOWNSYSTEM.Name from SMS\_R\_UnknownSystem";<br/>	QueryID = 2;<br/>	RuleName = "All Unknown Computers";<br/>\};<br/> | True | 0 | True | True | 2019\-07\-17T14:04:58Z | 2019\-15\-07T10:07:35Z | 2020\-00\-29T04:09:39Z |  |  | 5 | SMS\_CM\_RES\_COLL\_SMS00001 | 5 | False


### ms-ecm-device-list
***
Lists a Configuration Manager device


#### Base Command

`ms-ecm-device-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | Specifies an ID for a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | Specifies the name of a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| limit | Specifies the maximum number of devices to be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Devices.Name | string | The name of the device | 
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
>| ResourceID | DeviceName
>| --- | ---
>| 16777220 | EC2AMAZ\-2AKQ815


### ms-ecm-script-list
***
Gets Configuration Manager PowerShell scripts


#### Base Command

`ms-ecm-script-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| author | Specifies the author of the script (can be retrived via `!ms-ecm-script-list`) | Optional | 
| script_name | Specifies a script name (can be retrived via `!ms-ecm-script-list`) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Scripts.ApprovalState | string | The approval state of the script | 
| MicrosoftECM.Scripts.Approver | string | The approver of the script | 
| MicrosoftECM.Scripts.Author | string | The author of the script | 
| MicrosoftECM.Scripts.Comment | string | A short comment about the script | 
| MicrosoftECM.Scripts.LastUpdateTime | date | The date of the last script upda | 
| MicrosoftECM.Scripts.Parameterlist | string | The parameter list of the script | 
| MicrosoftECM.Scripts.Script | string | The code of the script | 
| MicrosoftECM.Scripts.ScriptGuid | string | The unique identifier of the script | 
| MicrosoftECM.Scripts.ScriptHash | string | The hash of the script | 
| MicrosoftECM.Scripts.ScriptHashAlgorithm | string | The algorithm with which the script hash was generated | 
| MicrosoftECM.Scripts.ScriptName | string | The name of the script | 
| MicrosoftECM.Scripts.ScriptType | string | The type of the script | 
| MicrosoftECM.Scripts.ScriptVersion | number | The version of the script | 


#### Command Example
```!ms-ecm-script-list script_name="XSOAR StartService"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Scripts": {
            "ApprovalState": null,
            "Approver": "DEMISTO\\sccmadmin",
            "Author": "DEMISTO\\sccmadmin",
            "Comment": "XSOAR StartService script",
            "LastUpdateTime": "2020-38-24T09:09:31Z",
            "Parameterlist": null,
            "Script": "\ufffd\ufffdGet-Service dnscache | Start-Service -PassThru -ErrorAction Stop",
            "ScriptGuid": "7C9940D7-BC42-421D-AAF7-F851425A0D85",
            "ScriptHash": "641A7B75566E330AFFBAD979DE33E1C89E3B7623680233BA324765C042FC5860",
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
>| ApprovalState | Approver | Author | Comment | LastUpdateTime | Parameterlist | Script | ScriptGuid | ScriptHash | ScriptHashAlgorithm | ScriptName | ScriptType | ScriptVersion
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>|  | DEMISTO\\sccmadmin | DEMISTO\\sccmadmin | XSOAR StartService script | 2020\-38\-24T09:09:31Z |  | ��Get\-Service dnscache \| Start\-Service \-PassThru \-ErrorAction Stop | 7C9940D7\-BC42\-421D\-AAF7\-F851425A0D85 | 641A7B75566E330AFFBAD979DE33E1C89E3B7623680233BA324765C042FC5860 | SHA256 | XSOAR StartService |  | 1


### ms-ecm-script-create
***
create new powershell script


#### Base Command

`ms-ecm-script-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_file_entry_id | The Entry ID of the script file | Optional | 
| script_text | The text of the string | Optional | 
| script_name | The name of the script | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Scripts.ApprovalState | string | The approval state of the script | 
| MicrosoftECM.Scripts.Approver | string | The approver of the script | 
| MicrosoftECM.Scripts.Author | string | The author of the script | 
| MicrosoftECM.Scripts.Comment | string | A short comment about the script | 
| MicrosoftECM.Scripts.LastUpdateTime | date | The date of the last script upda | 
| MicrosoftECM.Scripts.Parameterlist | string | The parameter list of the script | 
| MicrosoftECM.Scripts.Script | string | The code of the script | 
| MicrosoftECM.Scripts.ScriptGuid | string | The unique identifier of the script | 
| MicrosoftECM.Scripts.ScriptHash | string | The hash of the script | 
| MicrosoftECM.Scripts.ScriptHashAlgorithm | string | The algorithm with which the script hash was generated | 
| MicrosoftECM.Scripts.ScriptName | string | The name of the script | 
| MicrosoftECM.Scripts.ScriptType | string | The type of the script | 
| MicrosoftECM.Scripts.ScriptVersion | number | The version of the script | 


#### Command Example
```!ms-ecm-script-create script_name="My new script" script_text="$PSVersionTable"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Scripts": {
            "ApprovalState": null,
            "Approver": "",
            "Author": "DEMISTO\\sccmadmin",
            "Comment": "",
            "LastUpdateTime": "2020-12-29T15:09:18Z",
            "Parameterlist": null,
            "Script": "\ufffd\ufffd$PSVersionTable",
            "ScriptGuid": "D00E9486-B062-422B-9D84-26415DE563CC",
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
>| ApprovalState | Approver | Author | Comment | LastUpdateTime | Parameterlist | Script | ScriptGuid | ScriptHash | ScriptHashAlgorithm | ScriptName | ScriptType | ScriptVersion
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>|  |  | DEMISTO\\sccmadmin |  | 2020\-12\-29T15:09:18Z |  | ��$PSVersionTable | D00E9486\-B062\-422B\-9D84\-26415DE563CC | CE09E98D654CF613A0D219B744B56392E8356430534F309F715960E45A1417F8 | SHA256 | My new script |  | 1


### ms-ecm-script-invoke
***
Invokes a script in Configuration Manager


#### Base Command

`ms-ecm-script-invoke`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_guid | Specifies the script ID (can be retrived via `!ms-ecm-script-list`) | Required | 
| collection_id | Specifies the collection ID (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | Specifies the collection name (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| device_name | Specifies a device name in Configuration Manager | Optional | 
| poll_results | Whether to poll for the script invocation results or not | Optional | 
| timeout | The timeout in seconds to poll for invocation results. Default is 30 seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection Name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the Invocation result object was updated | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script  | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation | 


#### Command Example
```!ms-ecm-script-invoke script_guid=394EDB29-5D89-4B9B-9745-A1F6DC8214E2 collection_name="All Systems" poll_results=true```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": {
            "CollectionId": "SMS00001",
            "CollectionName": "All Systems",
            "DeviceName": "EC2AMAZ-TB8VCPN",
            "LastUpdateTime": "2020-11-09T14:22:01Z",
            "OperationId": 16777629,
            "ResourceId": 16777222,
            "ScriptExecutionState": "Succeeded",
            "ScriptExitCode": "0",
            "ScriptGuid": "394EDB29-5D89-4B9B-9745-A1F6DC8214E2",
            "ScriptLastModifiedDate": "2020-09-24T14:29:14Z",
            "ScriptName": "Itay",
            "ScriptOutput": "{\"PSVersion\":{\"Major\":5,\"Minor\":1,\"Build\":14393,\"Revision\":2608,\"MajorRevision\":0,\"MinorRevision\":2608},\"PSEdition\":\"Desktop\",\"PSCompatibleVersions\":[{\"Major\":1,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":2,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":3,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":4,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":5,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},{\"Major\":5,\"Minor\":1,\"Build\":14393,\"Revision\":2608,\"MajorRevision\":0,\"MinorRevision\":2608}],\"BuildVersion\":{\"Major\":10,\"Minor\":0,\"Build\":14393,\"Revision\":2608,\"MajorRevision\":0,\"MinorRevision\":2608},\"CLRVersion\":{\"Major\":4,\"Minor\":0,\"Build\":30319,\"Revision\":42000,\"MajorRevision\":0,\"MinorRevision\":-23536},\"WSManStackVersion\":{\"Major\":3,\"Minor\":0,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},\"PSRemotingProtocolVersion\":{\"Major\":2,\"Minor\":3,\"Build\":-1,\"Revision\":-1,\"MajorRevision\":-1,\"MinorRevision\":-1},\"SerializationVersion\":{\"Major\":1,\"Minor\":1,\"Build\":0,\"Revision\":1,\"MajorRevision\":0,\"MinorRevision\":1}}",
            "ScriptOutputHash": "ADC6BF52B8EA29483BAB196925A0D52A2703A7386E289BBF6AA70E108399DA0F",
            "ScriptVersion": "1",
            "TaskID": "{89519B0A-BD07-4212-AB1A-ACDFA249D0DC}"
        }
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| ScriptName | ResourceId | ScriptExecutionState | DeviceName | CollectionName | OperationId | ScriptLastModifiedDate | TaskID | ScriptOutputHash | ScriptVersion | LastUpdateTime | ScriptExitCode | ScriptOutput | CollectionId | ScriptGuid
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Itay | 16777220 | Succeeded | EC2AMAZ\-2AKQ815 | All Systems | 16777629 | 2020\-09\-24T14:29:14Z | \{89519B0A\-BD07\-4212\-AB1A\-ACDFA249D0DC\} | 7E59C0C20E04A920734651297E46C7E7C0284E41B69B4E4DC3888D1767BA807D | 1 | 2020\-11\-09T14:22:01Z | 0 | \{"PSVersion":\{"Major":5,"Minor":1,"Build":14393,"Revision":2969,"MajorRevision":0,"MinorRevision":2969\},"PSEdition":"Desktop","PSCompatibleVersions":\[\{"Major":1,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":2,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":4,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":1,"Build":14393,"Revision":2969,"MajorRevision":0,"MinorRevision":2969\}\],"BuildVersion":\{"Major":10,"Minor":0,"Build":14393,"Revision":2969,"MajorRevision":0,"MinorRevision":2969\},"CLRVersion":\{"Major":4,"Minor":0,"Build":30319,"Revision":42000,"MajorRevision":0,"MinorRevision":\-23536\},"WSManStackVersion":\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"PSRemotingProtocolVersion":\{"Major":2,"Minor":3,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"SerializationVersion":\{"Major":1,"Minor":1,"Build":0,"Revision":1,"MajorRevision":0,"MinorRevision":1\}\} | SMS00001 | 394EDB29\-5D89\-4B9B\-9745\-A1F6DC8214E2
>| Itay | 16777221 | Succeeded | EC2AMAZ\-PHPTDJV | All Systems | 16777629 | 2020\-09\-24T14:29:14Z | \{89519B0A\-BD07\-4212\-AB1A\-ACDFA249D0DC\} | EF8CDB402162E39E41C92FB87B8C54F8D3E5E8805ABC58E5BE6E31DBE94378CB | 1 | 2020\-11\-09T14:22:06Z | 0 | \{"PSVersion":\{"Major":5,"Minor":1,"Build":14393,"Revision":2828,"MajorRevision":0,"MinorRevision":2828\},"PSEdition":"Desktop","PSCompatibleVersions":\[\{"Major":1,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":2,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":4,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":1,"Build":14393,"Revision":2828,"MajorRevision":0,"MinorRevision":2828\}\],"BuildVersion":\{"Major":10,"Minor":0,"Build":14393,"Revision":2828,"MajorRevision":0,"MinorRevision":2828\},"CLRVersion":\{"Major":4,"Minor":0,"Build":30319,"Revision":42000,"MajorRevision":0,"MinorRevision":\-23536\},"WSManStackVersion":\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"PSRemotingProtocolVersion":\{"Major":2,"Minor":3,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"SerializationVersion":\{"Major":1,"Minor":1,"Build":0,"Revision":1,"MajorRevision":0,"MinorRevision":1\}\} | SMS00001 | 394EDB29\-5D89\-4B9B\-9745\-A1F6DC8214E2
>| Itay | 16777222 | Succeeded | EC2AMAZ\-TB8VCPN | All Systems | 16777629 | 2020\-09\-24T14:29:14Z | \{89519B0A\-BD07\-4212\-AB1A\-ACDFA249D0DC\} | ADC6BF52B8EA29483BAB196925A0D52A2703A7386E289BBF6AA70E108399DA0F | 1 | 2020\-11\-09T14:22:01Z | 0 | \{"PSVersion":\{"Major":5,"Minor":1,"Build":14393,"Revision":2608,"MajorRevision":0,"MinorRevision":2608\},"PSEdition":"Desktop","PSCompatibleVersions":\[\{"Major":1,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":2,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":4,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},\{"Major":5,"Minor":1,"Build":14393,"Revision":2608,"MajorRevision":0,"MinorRevision":2608\}\],"BuildVersion":\{"Major":10,"Minor":0,"Build":14393,"Revision":2608,"MajorRevision":0,"MinorRevision":2608\},"CLRVersion":\{"Major":4,"Minor":0,"Build":30319,"Revision":42000,"MajorRevision":0,"MinorRevision":\-23536\},"WSManStackVersion":\{"Major":3,"Minor":0,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"PSRemotingProtocolVersion":\{"Major":2,"Minor":3,"Build":\-1,"Revision":\-1,"MajorRevision":\-1,"MinorRevision":\-1\},"SerializationVersion":\{"Major":1,"Minor":1,"Build":0,"Revision":1,"MajorRevision":0,"MinorRevision":1\}\} | SMS00001 | 394EDB29\-5D89\-4B9B\-9745\-A1F6DC8214E2


### ms-ecm-script-approve
***
Approves a Configuration Manager PowerShell script


#### Base Command

`ms-ecm-script-approve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Specifies a comment about the approval of the script | Required | 
| script_guid | Specifies the script ID (can be retrived via `!ms-ecm-script-list`) | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!ms-ecm-script-approve comment="Some comment" script_guid=394EDB29-5D89-4B9B-9745-A1F6DC8214E2```

#### Human Readable Output

>### Script was approved successfully

### ms-ecm-device-collection-create
***
Creates a Configuration Manager collection


#### Base Command

`ms-ecm-device-collection-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Specifies a comment for the collection | Required | 
| collection_name | Specifies a name for the collection | Required | 
| limiting_collection_name | Specifies the name of a collection to use as a scope for this collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection's name | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. | 
| MicrosoftECM.Collections.Type | string | The type of the collection | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | true if this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | Count of collections that are included and excluded with this one. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | This value, when set to true, denotes that the collection is built in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | This value, when set to true, denotes that the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last altered in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last altered. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The CollectionID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The Name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | Count of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection | 
| MicrosoftECM.Collections.MemberCount | number | A count of the collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | Specifies that this collection is a server group. | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection | 


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
Adds a Direct Rule membership to a device collection


#### Base Command

`ms-ecm-device-collection-members-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | Specifies the ID of a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | Specifies the name of a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| device_resource_ids | A comma seperated list of devices resource IDs (can be retrived via `!ms-ecm-device-list`) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection's name | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. The default value is "" | 
| MicrosoftECM.Collections.Type | string | The type of the collection | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | true if this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | Count of collections that are included and excluded with this one. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | This value, when set to true, denotes that the collection is built in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | This value, when set to true, denotes that the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last altered in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last altered. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The CollectionID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The Name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | Count of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection | 
| MicrosoftECM.Collections.MemberCount | number | A count of the collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | A comma separated list of resource IDs  e.g 0001,0002 | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection | 


#### Command Example
```!ms-ecm-device-collection-members-add device_resource_ids=16777220 collection_name="my new collection name"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Collections": {
            "CollectionRules": [
                "\ninstance of SMS_CollectionRuleDirect\n{\n\tResourceClassName = \"SMS_R_System\";\n\tResourceID = 16777220;\n\tRuleName = \"EC2AMAZ-2AKQ815\";\n};",
                "\ninstance of SMS_CollectionRuleExcludeCollection\n{\n\tExcludeCollectionID = \"ISR00014\";\n\tRuleName = \"Test\";\n};\n"
            ],
            "Comment": "my collection comment",
            "CurrentStatus": null,
            "HasProvisionedMember": "False",
            "ID": "ISR0001F",
            "IncludeExcludeCollectionsCount": "1",
            "IsBuiltIn": "False",
            "IsReferenceCollection": "False",
            "LastChangeTime": "2020-11-29T15:09:55Z",
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
>| my new collection name | ISR0001F |  | my collection comment |  | <br/>instance of SMS\_CollectionRuleDirect<br/>\{<br/>	ResourceClassName = "SMS\_R\_System";<br/>	ResourceID = 16777220;<br/>	RuleName = "EC2AMAZ\-2AKQ815";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleExcludeCollection<br/>\{<br/>	ExcludeCollectionID = "ISR00014";<br/>	RuleName = "Test";<br/>\};<br/> | False | 1 | False | False | 2020\-11\-29T15:09:55Z | 2020\-11\-29T15:09:53Z | 2020\-11\-29T15:09:53Z | SMS00001 | All Systems | 0 | SMS\_CM\_RES\_COLL\_ISR0001F | 0 | False


### ms-ecm-device-collection-include
***
Adds an Include Collections membership rule to a device collection


#### Base Command

`ms-ecm-device-collection-include`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | Specifies the ID of a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | Specifies the name of a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| include_collection_id | Specifies the ID of a device collection to include in the membership rule (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| include_collection_name | Specifies the name of a device collection to include in the membership rule (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection's name | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. The default value is "" | 
| MicrosoftECM.Collections.Type | string | The type of the collection | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | true if this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | Count of collections that are included and excluded with this one. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | This value, when set to true, denotes that the collection is built in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | This value, when set to true, denotes that the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last altered in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last altered. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The CollectionID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The Name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | Count of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection | 
| MicrosoftECM.Collections.MemberCount | number | A count of the collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | A comma separated list of resource IDs  e.g 0001,0002 | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection | 


#### Command Example
``` ```

#### Human Readable Output



### ms-ecm-device-collection-exclude
***
Adds an exclude membership rule to one or more Configuration Manager device collections.


#### Base Command

`ms-ecm-device-collection-exclude`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | Specifies the ID of a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | Specifies the name of a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| exclude_collection_id | Specifies the ID of a device collection to exclude from the membership rule (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| exclude_collection_name | Specifies the name of a device collection to exclude from the membership rule (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection's name | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. The default value is "" | 
| MicrosoftECM.Collections.Type | string | The type of the collection | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | true if this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | Count of collections that are included and excluded with this one. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | This value, when set to true, denotes that the collection is built in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | This value, when set to true, denotes that the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last altered in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last altered. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The CollectionID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The Name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | Count of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection | 
| MicrosoftECM.Collections.MemberCount | number | A count of the collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | A comma separated list of resource IDs  e.g 0001,0002 | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection | 


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
Adds a query membership rule to one or more Configuration Manager device collections


#### Base Command

`ms-ecm-device-collection-members-by-query-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | Specifies the ID of the device collection where the rule is applied (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | Specifies the name of the device collection where the rule is applied (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| query_expression | Specifies the query expression that Configuration Manager uses. For example "select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)" to update the device collections | Required | 
| rule_name | Specifies the name for the rule | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Collections.Name | string | The collection's name | 
| MicrosoftECM.Collections.ID | string | Unique auto-generated ID containing eight characters. The default value is "" | 
| MicrosoftECM.Collections.Type | string | The type of the collection | 
| MicrosoftECM.Collections.Comment | string | General comment or note that documents the collection | 
| MicrosoftECM.Collections.CurrentStatus | string | Current status of the collection | 
| MicrosoftECM.Collections.HasProvisionedMember | boolean | true if this collection has provisioned members. | 
| MicrosoftECM.Collections.IncludeExcludeCollectionsCount | number | Count of collections that are included and excluded with this one. | 
| MicrosoftECM.Collections.IsBuiltIn | boolean | This value, when set to true, denotes that the collection is built in. | 
| MicrosoftECM.Collections.IsReferenceCollection | boolean | This value, when set to true, denotes that the collection is not limited by another collection. | 
| MicrosoftECM.Collections.LastChangeTime | date | Date and time of when the collection was last altered in any way. | 
| MicrosoftECM.Collections.LastMemberChangeTime | date | Date and time of when the collection membership was last altered. | 
| MicrosoftECM.Collections.LastRefreshTime | date | Date and time of when the collection membership was last refreshed. | 
| MicrosoftECM.Collections.LimitToCollectionID | string | The CollectionID of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LimitToCollectionName | string | The Name of the collection to limit the query results to. | 
| MicrosoftECM.Collections.LocalMemberCount | number | Count of members visible at the local site. | 
| MicrosoftECM.Collections.MemberClassName | string | Class name having instances that are the members of the collection | 
| MicrosoftECM.Collections.MemberCount | number | A count of the collection members. | 
| MicrosoftECM.Collections.UseCluster | boolean | A comma separated list of resource IDs e.g 0001,0002 | 
| MicrosoftECM.Collections.CollectionRules | string | Name of the defining membership criteria for the collection | 


#### Command Example
```!ms-ecm-device-collection-members-by-query-add query_expression="select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)" rule_name="new Rule" collection_name="my new collection name"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Collections": {
            "CollectionRules": [
                "\ninstance of SMS_CollectionRuleExcludeCollection\n{\n\tExcludeCollectionID = \"ISR00014\";\n\tRuleName = \"Test\";\n};",
                "\ninstance of SMS_CollectionRuleDirect\n{\n\tResourceClassName = \"SMS_R_System\";\n\tResourceID = 16777220;\n\tRuleName = \"EC2AMAZ-2AKQ815\";\n};",
                "\ninstance of SMS_CollectionRuleQuery\n{\n\tQueryExpression = \"select SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from SMS_R_System where (ClientType = 1) OR (SMS_R_System.AgentEdition0 = 5)\";\n\tRuleName = \"new Rule\";\n};\n"
            ],
            "Comment": "my collection comment",
            "CurrentStatus": null,
            "HasProvisionedMember": "False",
            "ID": "ISR0001F",
            "IncludeExcludeCollectionsCount": "1",
            "IsBuiltIn": "False",
            "IsReferenceCollection": "False",
            "LastChangeTime": "2020-12-29T15:09:01Z",
            "LastMemberChangeTime": "2020-11-29T15:09:53Z",
            "LastRefreshTime": "2020-12-29T15:09:03Z",
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
>| my new collection name | ISR0001F |  | my collection comment |  | <br/>instance of SMS\_CollectionRuleExcludeCollection<br/>\{<br/>	ExcludeCollectionID = "ISR00014";<br/>	RuleName = "Test";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleDirect<br/>\{<br/>	ResourceClassName = "SMS\_R\_System";<br/>	ResourceID = 16777220;<br/>	RuleName = "EC2AMAZ\-2AKQ815";<br/>\};<br/>,<br/>instance of SMS\_CollectionRuleQuery<br/>\{<br/>	QueryExpression = "select SMS\_R\_SYSTEM.ResourceID,SMS\_R\_SYSTEM.ResourceType,SMS\_R\_SYSTEM.Name,SMS\_R\_SYSTEM.SMSUniqueIdentifier,SMS\_R\_SYSTEM.ResourceDomainORWorkgroup,SMS\_R\_SYSTEM.Client from SMS\_R\_System where \(ClientType = 1\) OR \(SMS\_R\_System.AgentEdition0 = 5\)";<br/>	RuleName = "new Rule";<br/>\};<br/> | False | 1 | False | False | 2020\-12\-29T15:09:01Z | 2020\-11\-29T15:09:53Z | 2020\-12\-29T15:09:03Z | SMS00001 | All Systems | 0 | SMS\_CM\_RES\_COLL\_ISR0001F | 0 | False


### ms-ecm-service-start
***
Starts a service on a device or collection (Implemented by creating and invoking a script named `XSOAR StartService`)


#### Base Command

`ms-ecm-service-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_name | The name of the service | Required | 
| device_name | The device name to start the service in. (can be retrived via `!ms-ecm-device-list`) | Optional | 
| collection_id | The ID of the collection to start the service in. (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | The name of the collection to start the service in. (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| poll_results | Whether to poll for the script invocation results or not | Optional | 
| timeout | The timeout in seconds to poll for invocation results. Default is 30 seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection Name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the Invocation result object was updated | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script  | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation | 


#### Command Example
```!ms-ecm-service-start service_name=dnscache collection_name="All Systems" poll_results=true timeout=15```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": {
            "CollectionId": "SMS00001",
            "CollectionName": "All Systems",
            "DeviceName": "EC2AMAZ-TB8VCPN",
            "LastUpdateTime": "2020-11-09T14:24:26Z",
            "OperationId": 16777631,
            "ResourceId": 16777222,
            "ScriptExecutionState": "Succeeded",
            "ScriptExitCode": "0",
            "ScriptGuid": "337980EE-3C5E-4CB9-9A1D-5361E3BFD6CA",
            "ScriptLastModifiedDate": "2020-11-09T14:24:16Z",
            "ScriptName": "XSOAR StartService",
            "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
            "ScriptOutputHash": "340EEE6517060B2B3A357561E719D9588DB65929CFD6091AF87A20D1AAED2BAF",
            "ScriptVersion": "1",
            "TaskID": "{093AA570-8AC2-473C-8890-15A2EE9BE236}"
        }
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| ScriptName | ResourceId | ScriptExecutionState | DeviceName | CollectionName | OperationId | ScriptLastModifiedDate | TaskID | ScriptOutputHash | ScriptVersion | LastUpdateTime | ScriptExitCode | ScriptOutput | CollectionId | ScriptGuid
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| XSOAR StartService | 16777220 | Succeeded | EC2AMAZ\-2AKQ815 | All Systems | 16777631 | 2020\-11\-09T14:24:16Z | \{093AA570\-8AC2\-473C\-8890\-15A2EE9BE236\} | BD83747944C526E57E066BD863A2D6BBB4B5E81BFFC7310878F16C1505393E9C | 1 | 2020\-11\-09T14:24:26Z | 0 | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | SMS00001 | 337980EE\-3C5E\-4CB9\-9A1D\-5361E3BFD6CA
>| XSOAR StartService | 16777221 | Succeeded | EC2AMAZ\-PHPTDJV | All Systems | 16777631 | 2020\-11\-09T14:24:16Z | \{093AA570\-8AC2\-473C\-8890\-15A2EE9BE236\} | B03DDFEA2112E2743EFF47D0A450E762A864ECD55CF6D01AD6BF1A01E19BC78B | 1 | 2020\-11\-09T14:24:26Z | 0 | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | SMS00001 | 337980EE\-3C5E\-4CB9\-9A1D\-5361E3BFD6CA
>| XSOAR StartService | 16777222 | Succeeded | EC2AMAZ\-TB8VCPN | All Systems | 16777631 | 2020\-11\-09T14:24:16Z | \{093AA570\-8AC2\-473C\-8890\-15A2EE9BE236\} | 340EEE6517060B2B3A357561E719D9588DB65929CFD6091AF87A20D1AAED2BAF | 1 | 2020\-11\-09T14:24:26Z | 0 | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | SMS00001 | 337980EE\-3C5E\-4CB9\-9A1D\-5361E3BFD6CA


### ms-ecm-service-restart
***
Restarts a service on a device or collection (Implemented by creating and invoking a script named `XSOAR RestartService`)


#### Base Command

`ms-ecm-service-restart`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_name | The name of the service | Required | 
| device_name | The device name to start the service in. (can be retrived via `!ms-ecm-device-list`) | Optional | 
| collection_id | The ID of the collection to start the service in. (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | The name of the collection to start the service in. (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| poll_results | Whether to poll for the script invocation results or not | Optional | 
| timeout | The timeout in seconds to poll for invocation results. Default is 30 seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection Name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the Invocation result object was updated | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script  | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation | 


#### Command Example
```!ms-ecm-service-restart service_name=dnscache collection_name="All Systems" poll_results=true timeout=15```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": {
            "CollectionId": "SMS00001",
            "CollectionName": "All Systems",
            "DeviceName": "EC2AMAZ-TB8VCPN",
            "LastUpdateTime": "2020-11-09T14:23:51Z",
            "OperationId": 16777630,
            "ResourceId": 16777222,
            "ScriptExecutionState": "Succeeded",
            "ScriptExitCode": "0",
            "ScriptGuid": "397F9151-1195-4C03-8F4D-26892387F714",
            "ScriptLastModifiedDate": "2020-11-09T14:23:40Z",
            "ScriptName": "XSOAR RestartService",
            "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
            "ScriptOutputHash": "340EEE6517060B2B3A357561E719D9588DB65929CFD6091AF87A20D1AAED2BAF",
            "ScriptVersion": "1",
            "TaskID": "{C328DDE5-2A34-4180-A0D3-75CBA541B36E}"
        }
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| ScriptName | ResourceId | ScriptExecutionState | DeviceName | CollectionName | OperationId | ScriptLastModifiedDate | TaskID | ScriptOutputHash | ScriptVersion | LastUpdateTime | ScriptExitCode | ScriptOutput | CollectionId | ScriptGuid
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| XSOAR RestartService | 16777220 | Succeeded | EC2AMAZ\-2AKQ815 | All Systems | 16777630 | 2020\-11\-09T14:23:40Z | \{C328DDE5\-2A34\-4180\-A0D3\-75CBA541B36E\} | BD83747944C526E57E066BD863A2D6BBB4B5E81BFFC7310878F16C1505393E9C | 1 | 2020\-11\-09T14:23:56Z | 0 | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | SMS00001 | 397F9151\-1195\-4C03\-8F4D\-26892387F714
>| XSOAR RestartService | 16777221 | Succeeded | EC2AMAZ\-PHPTDJV | All Systems | 16777630 | 2020\-11\-09T14:23:40Z | \{C328DDE5\-2A34\-4180\-A0D3\-75CBA541B36E\} | B03DDFEA2112E2743EFF47D0A450E762A864ECD55CF6D01AD6BF1A01E19BC78B | 1 | 2020\-11\-09T14:23:51Z | 0 | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SMS\_SITE\_VSS\_WRITER SMS\_SITE\_SQL\_BACKUP SMS\_SITE\_COMPONENT\_MANAGER SMS\_SITE\_BACKUP SMS\_EXECUTIVE SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | SMS00001 | 397F9151\-1195\-4C03\-8F4D\-26892387F714
>| XSOAR RestartService | 16777222 | Succeeded | EC2AMAZ\-TB8VCPN | All Systems | 16777630 | 2020\-11\-09T14:23:40Z | \{C328DDE5\-2A34\-4180\-A0D3\-75CBA541B36E\} | 340EEE6517060B2B3A357561E719D9588DB65929CFD6091AF87A20D1AAED2BAF | 1 | 2020\-11\-09T14:23:51Z | 0 | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | SMS00001 | 397F9151\-1195\-4C03\-8F4D\-26892387F714


### ms-ecm-service-stop
***
Stops a service on a device or collection (Implemented by creating and invoking a script named `XSOAR StopService`)


#### Base Command

`ms-ecm-service-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_name | The name of the service | Required | 
| device_name | The device name to start the service in. (can be retrived via `!ms-ecm-device-list`) | Optional | 
| collection_id | The ID of the collection to start the service in. (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | The name of the collection to start the service in. (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| poll_results | Whether to poll for the script invocation results or not | Optional | 
| timeout | The timeout in seconds to poll for invocation results. Default is 30 seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection Name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the Invocation result object was updated | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script  | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation | 


#### Command Example
```!ms-ecm-service-stop service_name=dnscache collection_name="All Systems" poll_results=true timeout=15```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocationResults": {
            "CollectionId": "SMS00001",
            "CollectionName": "All Systems",
            "DeviceName": "EC2AMAZ-TB8VCPN",
            "LastUpdateTime": "2020-11-09T14:25:06Z",
            "OperationId": 16777632,
            "ResourceId": 16777222,
            "ScriptExecutionState": "Succeeded",
            "ScriptExitCode": "0",
            "ScriptGuid": "41E11903-E655-4AC0-B942-7A46FD168870",
            "ScriptLastModifiedDate": "2020-11-09T14:24:52Z",
            "ScriptName": "XSOAR StopService",
            "ScriptOutput": "{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"DNS Client\",\"DependentServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":false,\"DisplayName\":\"Network Connectivity Assistant\",\"DependentServices\":\"\",\"MachineName\":\".\",\"ServiceName\":\"NcaSvc\",\"ServicesDependedOn\":\"NSI dnscache iphlpsvc BFE\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":1,\"ServiceType\":32,\"StartType\":3,\"Site\":null,\"Container\":null}],\"MachineName\":\".\",\"ServiceName\":\"dnscache\",\"ServicesDependedOn\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}],\"ServiceHandle\":{\"IsInvalid\":false,\"IsClosed\":false},\"Status\":1,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null,\"Name\":\"dnscache\",\"RequiredServices\":[{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"Network Store Interface Service\",\"DependentServices\":\"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"nsi\",\"ServicesDependedOn\":\"rpcss nsiproxy\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":32,\"StartType\":2,\"Site\":null,\"Container\":null},{\"CanPauseAndContinue\":false,\"CanShutdown\":false,\"CanStop\":true,\"DisplayName\":\"NetIO Legacy TDI Support Driver\",\"DependentServices\":\"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp\",\"MachineName\":\".\",\"ServiceName\":\"Tdx\",\"ServicesDependedOn\":\"tcpip\",\"ServiceHandle\":\"SafeServiceHandle\",\"Status\":4,\"ServiceType\":1,\"StartType\":1,\"Site\":null,\"Container\":null}]}",
            "ScriptOutputHash": "D27B022F6B8C8B584A79BB2D471EA173AE45588AAE28225563A38FC93B4EF2C6",
            "ScriptVersion": "1",
            "TaskID": "{A7AAAC3A-3C0C-4AB6-8B41-A9668353F1F7}"
        }
    }
}
```

#### Human Readable Output

>### Script Invocation Results
>| ScriptName | ResourceId | ScriptExecutionState | DeviceName | CollectionName | OperationId | ScriptLastModifiedDate | TaskID | ScriptOutputHash | ScriptVersion | LastUpdateTime | ScriptExitCode | ScriptOutput | CollectionId | ScriptGuid
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| XSOAR StopService | 16777220 | Succeeded | EC2AMAZ\-2AKQ815 | All Systems | 16777632 | 2020\-11\-09T14:24:52Z | \{A7AAAC3A\-3C0C\-4AB6\-8B41\-A9668353F1F7\} | FC945DDB2710DA5E73E6A8F359EE556A85A59671018831092493AD0EA013DE99 | 1 | 2020\-11\-09T14:25:06Z | 0 | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":1,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | SMS00001 | 41E11903\-E655\-4AC0\-B942\-7A46FD168870
>| XSOAR StopService | 16777222 | Succeeded | EC2AMAZ\-TB8VCPN | All Systems | 16777632 | 2020\-11\-09T14:24:52Z | \{A7AAAC3A\-3C0C\-4AB6\-8B41\-A9668353F1F7\} | D27B022F6B8C8B584A79BB2D471EA173AE45588AAE28225563A38FC93B4EF2C6 | 1 | 2020\-11\-09T14:25:06Z | 0 | \{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"DNS Client","DependentServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":false,"DisplayName":"Network Connectivity Assistant","DependentServices":"","MachineName":".","ServiceName":"NcaSvc","ServicesDependedOn":"NSI dnscache iphlpsvc BFE","ServiceHandle":"SafeServiceHandle","Status":1,"ServiceType":32,"StartType":3,"Site":null,"Container":null\}\],"MachineName":".","ServiceName":"dnscache","ServicesDependedOn":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\],"ServiceHandle":\{"IsInvalid":false,"IsClosed":false\},"Status":1,"ServiceType":32,"StartType":2,"Site":null,"Container":null,"Name":"dnscache","RequiredServices":\[\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"Network Store Interface Service","DependentServices":"AppVClient netprofm NlaSvc Netman NcaSvc SessionEnv Netlogon Dfs Browser LanmanWorkstation iphlpsvc IKEEXT Dnscache WinHttpAutoProxySvc Dhcp","MachineName":".","ServiceName":"nsi","ServicesDependedOn":"rpcss nsiproxy","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":32,"StartType":2,"Site":null,"Container":null\},\{"CanPauseAndContinue":false,"CanShutdown":false,"CanStop":true,"DisplayName":"NetIO Legacy TDI Support Driver","DependentServices":"NetBT NcaSvc iphlpsvc Dnscache WinHttpAutoProxySvc AppVClient netprofm NlaSvc Dhcp","MachineName":".","ServiceName":"Tdx","ServicesDependedOn":"tcpip","ServiceHandle":"SafeServiceHandle","Status":4,"ServiceType":1,"StartType":1,"Site":null,"Container":null\}\]\} | SMS00001 | 41E11903\-E655\-4AC0\-B942\-7A46FD168870


### ms-ecm-script-invocation-results
***
 


#### Base Command

`ms-ecm-script-invocation-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | The script invocation operation ID | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.OperationId | number | The script invocation operation ID | 
| MicrosoftECM.ScriptsInvocationResults.CollectionId | string | The collection ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.CollectionName | string | The collection Name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.DeviceName | string | The name of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.ResourceId | number | The resource ID of the device on which the script was invoked on | 
| MicrosoftECM.ScriptsInvocationResults.LastUpdateTime | date | The last time the Invocation result object was updated | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExecutionState | string | The state of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptExitCode | number | The exit code of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptGuid | string | The unique identifier of the script  | 
| MicrosoftECM.ScriptsInvocationResults.ScriptLastModifiedDate | date | The date of the script's last modification | 
| MicrosoftECM.ScriptsInvocationResults.ScriptName | string | The name of the script | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutput | string | The output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptOutputHash | string | The hash of the output of the script invocation | 
| MicrosoftECM.ScriptsInvocationResults.ScriptVersion | number | The version of the script when it was invoked | 
| MicrosoftECM.ScriptsInvocationResults.TaskID | string | The unique identifier of the invocation | 


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
>| ScriptName | ResourceId | ScriptExecutionState | DeviceName | CollectionName | OperationId | ScriptLastModifiedDate | TaskID | ScriptOutputHash | ScriptVersion | LastUpdateTime | ScriptExitCode | ScriptOutput | CollectionId | ScriptGuid
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| Fail | 16777220 | Failed | EC2AMAZ\-2AKQ815 | All Systems | 16777267 | 2020\-09\-24T14:36:32Z | \{FC58140A\-B688\-4D2E\-8FEE\-F7AED348FABF\} | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | 1 | 2020\-09\-29T10:57:15Z | \-2147467259 |  | SMS00001 | 2E0D961D\-1C89\-477D\-B1A7\-3FFEDC0AF2FA

### ms-ecm-device-get-collection-member
***
Gets a Configuration Manager device By querying the SMS_CM_RES_COLL_SMS00001 class. You can use the `ms-ecm-device-get-resource` or `ms-ecm-device-get-collection-member` commands to change the query class. Depending upon your role-based access in the site, you may need to use one of these other commands.


#### Base Command

`ms-ecm-device-get-collection-member`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_names | A comma separated list of device names, i.e `name1,name2,etc.` | Optional | 
| resource_ids | A comma separated list of resource ids, i.e `ID1,ID2,etc.` | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Devices.DeviceName | string | The name of the device | 
| MicrosoftECM.Devices.CollectionMemberDetails.ClientVersion | string | Version of the installed client software. | 
| MicrosoftECM.Devices.CollectionMemberDetails.DeviceOS | string | Device operating system. | 
| MicrosoftECM.Devices.ResourceID | number | Unique Configuration Manager-supplied ID for the resource. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsActive | boolean | true if there has been a recent heartbeat from the client. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastActiveTime | date | Comes from Client Health. Represents the last reported time the client was active. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastClientCheckTime | date | Comes from Client Health. Represents the last reported health evaluation time. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastDDR | date | Last heartbeat timestamp from client DDR discovery. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastHardwareScan | date | Timestamp from the last hardware inventory scan. | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastPolicyRequest | date | Timestamp of the last policy request for this client. | 
| MicrosoftECM.Devices.CollectionMemberDetails.Domain | string | Domain to which the resource belongs. | 
| MicrosoftECM.Devices.CollectionMemberDetails.PrimaryUser | string | The primary user of the device | 
| MicrosoftECM.Devices.CollectionMemberDetails.Status | string | Current status of the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.MACAddress | string | The MAC Address of the device. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsVirtualMachine | boolean | true if the client is a virtual machine. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsDecommissioned | boolean | true if the collection member is decommissioned. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsClient | boolean | true, if the client is a Configuration Manager client. | 
| MicrosoftECM.Devices.CollectionMemberDetails.IsBlocked | boolean | true if a system is blocked. Block/unblock is a manual action in the Admin Console UI that the administrator can invoke. By blocking a client, client communication with the server will be cut off. | 
| MicrosoftECM.Devices.CollectionMemberDetails.ExchangeServer | string | Name of the Exchange server for Exchange Active Sync \(EAS\). | 
| MicrosoftECM.Devices.CollectionMemberDetails.DeviceThreatLevel | string | The threat level of the device | 
| MicrosoftECM.Devices.CollectionMemberDetails.CurrentLogonUser | string | Current logged on user | 
| MicrosoftECM.Devices.CollectionMemberDetails.LastLogonUser | string | The last user who logged in to the device | 
| MicrosoftECM.Devices.CollectionMemberDetails.DeviceOSBuild | string | The OS build number of the device | 
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
                "ADLastLogonTime": "2020-11-02T05:34:01",
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
                "LastActiveTime": "2020-11-10T11:40:44Z",
                "LastClientCheckTime": "2020-11-07T16:42:39Z",
                "LastDDR": "2020-11-09T18:30:48Z",
                "LastHardwareScan": "2020-11-08T12:02:36Z",
                "LastLogonUser": null,
                "LastPolicyRequest": "2020-11-10T11:40:44Z",
                "PrimaryUser": "demisto\sccmadmin",
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
>| LastActiveTime | ExchangeServer | IsVirtualMachine | LastHardwareScan | LastClientCheckTime | IsClient | LastLogonUser | Domain | CurrentLogonUser | ResourceID | LastPolicyRequest | IsActive | Status | ClientVersion | ADLastLogonTime | LastDDR | DeviceOSBuild | IsBlocked | PrimaryUser | IsDecommissioned | DeviceThreatLevel | DeviceName | DeviceOS | SiteCode
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| 2020\-11\-10T11:40:44Z |  | False | 2020\-11\-08T12:02:36Z | 2020\-11\-07T16:42:39Z | True |  | DEMISTO |  | 16777220 | 2020\-11\-10T11:40:44Z | True |  | 5.00.8790.1007 | 11/2/2020 5:34:01 AM | 2020\-11\-09T18:30:48Z | 10.0.14393.3025 | False | demisto\sccmadmin | False |  | EC2AMAZ\-2AKQ815 | Microsoft Windows NT Advanced Server 10.0 | ISR


### ms-ecm-device-get-resource
***
Gets a Configuration Manager device By querying the SMS_R_System class. You can use the `ms-ecm-device-get-resource` or `ms-ecm-device-get-collection-member` commands to change the query class. Depending upon your role-based access in the site, you may need to use one of these other commands.


#### Base Command

`ms-ecm-device-get-resource`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_names | A comma separated list of device names, i.e `name1,name2,etc.` | Optional | 
| resource_ids | A comma separated list of resource ids, i.e `ID1,ID2,etc.` | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Devices.DeviceName | string | The name of the device | 
| MicrosoftECM.Devices.ResourceDetails.AgentName | string | List of the names of discovery agents that found the resource. | 
| MicrosoftECM.Devices.ResourceID | number | Configuration Manager-supplied ID that uniquely identifies a Configuration Manager client resource | 
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
| MicrosoftECM.Devices.ResourceDetails.VirtualMachineHostName | string | Virtual machine host name. | 
| MicrosoftECM.Devices.ResourceDetails.VirtualMachineType | string | The type of the virtual machine | 
| MicrosoftECM.Devices.ResourceDetails.DNSForestGuid | string | A unique identifier for the DNS forest | 
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
                    "2020-11-12T06:10:01Z",
                    "2019-07-07T10:12:48Z",
                    "2020-11-12T06:30:48Z"
                ],
                "CPUType": "Intel64 Family 6 Model 85 Stepping 4",
                "DNSForestGuid": "E8AA1F36-33BE-41F2-ADCB-E40376F5B168",
                "DistinguishedName": "CN=EC2AMAZ-2AKQ815,CN=Computers,DC=demisto,DC=local",
                "FullDomainName": "DEMISTO.LOCAL",
                "HardwareID": "2:387B42C549C5E7D718B68BC65959FA9041F7F2D0",
                "IPv4Addresses": "172.31.32.170",
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
>| CN=EC2AMAZ\-2AKQ815,CN=Computers,DC=demisto,DC=local |  | \["2020\-11\-12T06:10:01Z","2019\-07\-07T10:12:48Z","2020\-11\-12T06:30:48Z"\] | Microsoft Windows NT Advanced Server 10.0 | "172.31.32.170" | \["ISR","ISR","ISR"\] | \["SMS\_AD\_SYSTEM\_DISCOVERY\_AGENT","MP\_ClientRegistration","Heartbeat Discovery"\] | Default\-First\-Site\-Name | DEMISTO.LOCAL | 0 | Intel64 Family 6 Model 85 Stepping 4 | 4096 | EC2AMAZ\-2AKQ815 | 2020\-11\-12T06:07:29Z | 2:387B42C549C5E7D718B68BC65959FA9041F7F2D0 | E8AA1F36\-33BE\-41F2\-ADCB\-E40376F5B168 |  | "fe80::81c5:1670:9363:a40b" | EC2AMAZ\-2AKQ815 |  | 16777220


### ms-ecm-get-user-device-affinity
***
Get the relationships between a device and its primary users.


#### Base Command

`ms-ecm-get-user-device-affinity`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_names | A comma separated list of usernames with the form of "Domain\username" i.e "Domain\user1,Domain\user2",etc.." | Optional | 
| resource_ids | A comma separated list of device resource ids, i.e `ID1,ID2,etc.` | Optional | 
| device_names | A comma separated list of device names, i.e `name1,name2,etc.` | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.UserDeviceAffinity.DeviceName | string | The name of the device. | 
| MicrosoftECM.UserDeviceAffinity.UniqueUserName | string | User name in domain\\user format. | 
| MicrosoftECM.UserDeviceAffinity.ResourceID | number | The resource ID of the device. | 
| MicrosoftECM.UserDeviceAffinity.IsActive | boolean | TRUE if the relationship is active. | 
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
>| CreationTime | DeviceName | UserName | ResourceID | IsActive | RelationshipResourceID
>| --- | --- | --- | --- | --- | ---
>| 2020\-09\-07T14:52:57Z | EC2AMAZ\-2AKQ815 | demisto\\sccmadmin | 16777220 | True | 25165825
>| 2020\-11\-05T17:44:33Z | EC2AMAZ\-2AKQ815 | demisto\\administrator | 16777220 | True | 25165830

