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
Gets the last user that logged on to a given computer name


#### Base Command

`ms-ecm-user-last-log-on`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_name | Specifies the name of a device. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.LastLogOnUser.CreationDate | date | The date the computer was created | 
| MicrosoftECM.LastLogOnUser.IP | string | The IP of the computer | 
| MicrosoftECM.LastLogOnUser.LastLogonTimestamp | date | The date of the last login to the computer | 
| MicrosoftECM.LastLogOnUser.LastLogonUserName | string | The name of the last user who logged in  to the computer | 
| MicrosoftECM.LastLogOnUser.Name | string | The name of the computer | 


#### Command Example
```!ms-ecm-user-last-log-on device_name=EC2AMAZ-2AKQ815```

#### Context Example
```json
{
    "MicrosoftECM": {
        "LastLogOnUser": {
            "CreationDate": "2019-12-07T10:07:51Z",
            "IP": "172.1.1.1 fe80::81c5:1670:9363:a40b ",
            "LastLogonTimestamp": "2020-41-23T04:09:37Z",
            "LastLogonUserName": null,
            "Name": "EC2AMAZ-2AKQ815"
        }
    }
}
```

#### Human Readable Output

>### Last log gon user on EC2AMAZ-2AKQ815
>| CreationDate | IP | Name | LastLogonTimestamp | LastLogonUserName
>| --- | --- | --- | --- | ---
>| 2019\-12\-07T10:07:51Z | 172.1.1.1 fe80::81c5:1670:9363:a40b  | EC2AMAZ\-2AKQ815 | 2020\-41\-23T04:09:37Z | 


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
Gets a Configuration Manager device


#### Base Command

`ms-ecm-device-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection_id | Specifies an ID for a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| collection_name | Specifies the name of a device collection (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 
| device_name | Specifies the name of the device (can be retrived via `!ms-ecm-device-list`) | Optional | 
| resource_id | Specifies the resource ID of a device (can be retrived via `!ms-ecm-collection-list collection_type="Device"`) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.Devices.Name | string | The name of the device | 
| MicrosoftECM.Devices.ClientVersion | string | Version of the installed client software | 
| MicrosoftECM.Devices.CurrentLogonUser | string | The current logged on user | 
| MicrosoftECM.Devices.DeviceCategory | string | Category of the device | 
| MicrosoftECM.Devices.DeviceOS.DeviceOSBuild | string | Device operating system | 
| MicrosoftECM.Devices.DeviceOSBuild | string | Device operating system build | 
| MicrosoftECM.Devices.Domain | string | Domain to which the device belongs | 
| MicrosoftECM.Devices.IsActive | boolean | true if there has been a recent heartbeat from the client. | 
| MicrosoftECM.Devices.LastActiveTime | date | Comes from Client Health. Represents the last reported time the client was active. | 
| MicrosoftECM.Devices.LastHardwareScan | date | Timestamp from the last hardware inventory scan | 
| MicrosoftECM.Devices.LastInstallationError | date | Last reported error code from the installation on this client. | 
| MicrosoftECM.Devices.LastLogonUser | string | Last logged on user | 
| MicrosoftECM.Devices.LastMPServerName | string | Management Point server name where the client performed its last policy request. | 
| MicrosoftECM.Devices.MACAddress | string | The MAC address of the device | 
| MicrosoftECM.Devices.PrimaryUser | string | Users who have user-device-affinity with this device | 
| MicrosoftECM.Devices.ResourceID | number | Unique Configuration Manager-supplied ID for the resource. | 
| MicrosoftECM.Devices.SiteCode | string | Site code of the site that created the collection. | 
| MicrosoftECM.Devices.Status | string | Current status | 


#### Command Example
```!ms-ecm-device-list```

#### Context Example
```json
{
    "MicrosoftECM": {
        "Devices": [
            {
                "ClientVersion": "5.00.8790.1007",
                "CurrentLogonUser": null,
                "DeviceAccessState": null,
                "DeviceCategory": null,
                "DeviceOS": "Microsoft Windows NT Advanced Server 10.0",
                "DeviceOSBuild": "10.0.14393.3025",
                "Domain": "DEMISTO",
                "IsActive": "True",
                "LastActiveTime": "2020-26-29T13:09:53Z",
                "LastHardwareScan": "2020-31-27T14:09:34Z",
                "LastInstallationError": null,
                "LastLogonUser": null,
                "LastMPServerName": "EC2AMAZ-PHPTDJV.DEMISTO.LOCAL",
                "MACAddress": "06:0D:64:90:63:4A",
                "Name": "EC2AMAZ-2AKQ815",
                "PrimaryUser": "demisto\\sccmadmin",
                "ResourceID": 16777220,
                "SiteCode": "ISR",
                "Status": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Devices List
>| Name | ClientVersion | CurrentLogonUser | DeviceAccessState | DeviceCategory | DeviceOS | DeviceOSBuild | Domain | IsActive | LastActiveTime | LastHardwareScan | LastInstallationError | LastLogonUser | LastMPServerName | MACAddress | PrimaryUser | ResourceID | SiteCode | Status
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| EC2AMAZ\-2AKQ815 | 5.00.8790.1007 |  |  |  | Microsoft Windows NT Advanced Server 10.0 | 10.0.14393.3025 | DEMISTO | True | 2020\-26\-29T13:09:53Z | 2020\-31\-27T14:09:34Z |  |  | EC2AMAZ\-PHPTDJV.DEMISTO.LOCAL | 06:0D:64:90:63:4A | demisto\\sccmadmin | 16777220 | ISR | 


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocation.OperationID | number | The unique Id of the script operation | 
| MicrosoftECM.ScriptsInvocation.ReturnValue | number | The Return value of the script operation, 0 upon success | 


#### Command Example
```!ms-ecm-script-invoke script_guid=394EDB29-5D89-4B9B-9745-A1F6DC8214E2 collection_name="All Systems"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocation": {
            "OperationID": 16777274,
            "ReturnValue": "0"
        }
    }
}
```

#### Human Readable Output

>### Script Invocation Result
>| OperationID | ReturnValue
>| --- | ---
>| 16777274 | 0


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocation.OperationID | number | The script execution operation ID | 
| MicrosoftECM.ScriptsInvocation.ReturnValue | number | The script execution return value | 


#### Command Example
```!ms-ecm-service-start service_name=dnscache collection_name="All Systems"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocation": {
            "OperationID": 16777276,
            "ReturnValue": "0"
        }
    }
}
```

#### Human Readable Output

>### StartService script Invocation Result
>| OperationID | ReturnValue
>| --- | ---
>| 16777276 | 0


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocation.OperationID | number | The script execution operation ID | 
| MicrosoftECM.ScriptsInvocation.ReturnValue | number | The script execution return value | 


#### Command Example
```!ms-ecm-service-restart service_name=dnscache collection_name="All Systems"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocation": {
            "OperationID": 16777275,
            "ReturnValue": "0"
        }
    }
}
```

#### Human Readable Output

>### RestartService script Invocation Result
>| OperationID | ReturnValue
>| --- | ---
>| 16777275 | 0


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocation.OperationID | number | The script execution operation ID | 
| MicrosoftECM.ScriptsInvocation.ReturnValue | number | The script execution return value | 


#### Command Example
```!ms-ecm-service-stop service_name=dnscache collection_name="All Systems"```

#### Context Example
```json
{
    "MicrosoftECM": {
        "ScriptsInvocation": {
            "OperationID": 16777277,
            "ReturnValue": "0"
        }
    }
}
```

#### Human Readable Output

>### StopService script Invocation Result
>| OperationID | ReturnValue
>| --- | ---
>| 16777277 | 0


### ms-ecm-script-invocation-results
***
Gets a script invocation results


#### Base Command

`ms-ecm-script-invocation-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| operation_id | The script invocation operation ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftECM.ScriptsInvocationResults.ClientOperationId | number | The script invocation operation ID | 
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
            "ClientOperationId": 16777267,
            "CollectionId": "SMS00001",
            "CollectionName": "All Systems",
            "DeviceName": "EC2AMAZ-2AKQ815",
            "LastUpdateTime": "2020-57-29T10:09:15Z",
            "ResourceId": 16777220,
            "ScriptExecutionState": null,
            "ScriptExitCode": "-2147467259",
            "ScriptGuid": "2E0D961D-1C89-477D-B1A7-3FFEDC0AF2FA",
            "ScriptLastModifiedDate": "2020-36-24T14:09:32Z",
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
>| ClientOperationId | CollectionId | CollectionName | DeviceName | ResourceId | LastUpdateTime | ScriptExecutionState | ScriptExitCode | ScriptGuid | ScriptLastModifiedDate | ScriptName | ScriptOutput | ScriptOutputHash | ScriptVersion | TaskID
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
>| 16777267 | SMS00001 | All Systems | EC2AMAZ\-2AKQ815 | 16777220 | 2020\-57\-29T10:09:15Z |  | \-2147467259 | 2E0D961D\-1C89\-477D\-B1A7\-3FFEDC0AF2FA | 2020\-36\-24T14:09:32Z | Fail |  | E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855 | 1 | \{FC58140A\-B688\-4D2E\-8FEE\-F7AED348FABF\}

