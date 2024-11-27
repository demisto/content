McAfee ePolicy Orchestrator
This integration was integrated and tested with version 5.3.2 and 5.10 of McAfee ePO 


## Permissions

McAfee ePO has a highly flexible and powerful permissions system. The permissions required for the user who uses this integration depend on which operations they need to perform. The API user should have the same permissions a regular user would have in order to access the data via the UI. It is possible to view the exact permissions needed for a specific command by running the `!epo-help` command. The `!epo-help` command's output will include help information for the specific command including required permissions. 
More information about McAfee ePO's permissions model is available [here](https://docs.mcafee.com/bundle/epolicy-orchestrator-5.10.0-product-guide/page/GUID-1AEFA219-0726-4090-A8C2-BCAA1CAA7B37.html).

Example `!epo-help` outputs with permission information: 
* `!epo-help command="repository.findPackages"`:
![](../../doc_files/epo-help-find-pkg.png)
* `!epo-help command="repository.deletePackage"`:
![](../../doc_files/epo-help-delete-pkg.png)

## Configure McAfee ePO v2 in Cortex


| **Parameter** | **Description** | **Required** |
| ------------- | --- | --- |
| McAfee ePO Server URI |  | True |
| Username |  | True |
| Password |  | True |
| Trust any certificate (not secure) |   | False |
| Use system proxy settings |   | False |
| HTTP Timeout | The timeout of the HTTP requests sent to McAfee ePO API \(in seconds\). | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### epo-help
***
Displays help (information) for ePO commands. If no command argument is specified, returns all ePO commands.


#### Base Command

`epo-help`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | String to search for in the core.help command output. | Optional | 
| command | The command for which to display help information. | Optional | 
| prefix | Displays help information for commands with the specified prefix. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-help command="core.help"```

#### Human Readable Output

>#### ePO Help - core.help 
> core.help [command] [prefix=<>]
> Lists all registered commands and displays help strings.  Returns the list of
> commands or throws on error.
> Parameters:
>  command (param 1) - If specified, the help string for a specific command is
> displayed. If omitted, a list of all commands is displayed.
>  prefix - if specified, only commands with the given prefix are listed. This is
> useful for showing the commands for a single plug-in. This has no effect if the
> 'command' argument is specified.

### epo-get-latest-dat
***
Checks the latest available DAT file version in the public McAfee repository.


#### Base Command

`epo-get-latest-dat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.latestDAT | number | Latest available McAfee DAT file version. | 


#### Command Example
```!epo-get-latest-dat```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "latestDAT": "10200"
        }
    }
}
```

#### Human Readable Output

>McAfee ePO Latest DAT file version available is: **10200**


### epo-get-current-dat
***
Checks the existing DAT file version in the ePO repository.


#### Base Command

`epo-get-current-dat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.epoDAT | number | Current installed McAfee DAT file in ePO repository | 


#### Command Example
```!epo-get-current-dat```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "epoDAT": "10200"
        }
    }
}
```

#### Human Readable Output

>McAfee ePO Current DAT file version in repository is: **10200**


### epo-command
***
Executes the ePO command. Receives the mandatory 'command' argument, and other optional arguments. Run the 'epo-help' command to get a list of available commands. You can control the response format to be text instead of the default json format using resp_type=text, You can also specify the 'headers' argument to filter table headers. Example/:/ !epo-command command=system.find searchText=10.0.0.1 headers=EPOBranchNode.AutoID,EPOComputerProperties.ComputerName


#### Base Command

`epo-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-command command="system.find" searchText="10.0.0.1" headers="EPOBranchNode.AutoID,EPOComputerProperties.ComputerName"```

#### Human Readable Output

>### ePO command *system.find* results:
>|EPOBranchNode.AutoID|EPOComputerProperties.ComputerName|
>|---|---|
>| 2 | 10.0.0.1 |
>| 2 | 10.0.0.11 |


### epo-update-client-dat
***
Runs a client task to update the DAT file on the given endpoints.


#### Base Command

`epo-update-client-dat`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| systems | A CSV list of IP addresses or system names. | Required | 
| retryAttempts | Number of times the server will attempt to send the task to the client. Default is 1 retry. | Optional | 
| retryIntervalInSeconds | Retry interval in seconds. Default is 30. | Optional | 
| abortAfterMinutes | The threshold (in minutes) after which attempts to send the task to the client are aborted. Default is 5. | Optional | 
| stopAfterMinutes | The threshold (in minutes) that the client task is allowed to run. Default is 20. | Optional | 
| randomizationInterval | Duration (in minutes) over which to randomly spread task execution. Default is 0 (executes on all clients immediately). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-update-client-dat systems="TIE"```

#### Human Readable Output

>ePO client DAT update task started: Succeeded

### epo-update-repository
***
Triggers a server task in specific ePO servers to retrieve the latest signatures from the updated server.


#### Base Command

`epo-update-repository`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-update-repository```

#### Human Readable Output

>ePO repository update started.
>success
>skipped: Current\LMASECORE2000\2.2.0.9309\SpamEngine\0000
>skipped: Current\BOCVSE__1000\657\DAT\0000
>skipped: Current\AMCORDAT1000\1359.1\DAT\0000
>skipped: Current\VIRUSCAN8700\8.7.0\LangPack\0000
>skipped: Current\VIRUSCAN8800\8.8.0\LangPack\0000
>skipped: Current\SUPPMVTCT1000\8.3.0.357\MVTContentUpdate\0000
>skipped: Current\PHCONTENMETA\6006\PHContent\0000
>skipped: Current\MASECORE2000\2.2.0.9309\SpamEngine\0000
>skipped: Current\DBSECDAMMETA\97.3112\DAT\0000
>skipped: Current\MVEDR_R_3000\3.5.2\DAT\0000
>skipped: Current\DBSECDVMMETA\195.2097\DVMCHECKS\0000
>skipped: Current\Findings\1310\FNDContent\0000
>skipped: Current\AUENGINEMETA\1335\BMContent\0000
>skipped: Current\ENDPCNT_1000_LYNX\10.7.0\DAT\0000
>skipped: Current\ENCPTCNT6000\8.0.0.11953\DAT\0000

### epo-get-system-tree-group
***
Returns a system tree group.


#### Base Command

`epo-get-system-tree-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | String to search for in the system tree group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.SystemTreeGroups.groupId | number | System tree group ID. | 
| McAfee.ePO.SystemTreeGroups.groupPath | string | System tree group path. | 


#### Command Example
```!epo-get-system-tree-group search="Lost"```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "SystemTreeGroups": {
                "groupId": 3,
                "groupPath": "My Organization\\Lost&Found"
            }
        }
    }
}
```

#### Human Readable Output

>#### ePO System Tree groups
>Group ID | Group path
>-|-
>3  | My Organization\Lost&Found 


### epo-find-systems
***
Finds computers within a specified group in the McAfee ePO system tree.


#### Base Command

`epo-find-systems`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | System tree group ID. | Required | 
| verbose | Whether to return all system data. Possible values are: true, false. | Optional | 


#### Context Output

| **Path**                              | **Type** | **Description** |
|---------------------------------------| --- | --- |
| Endpoint.ID                           | String | The unique ID within the tool retrieving the endpoint. |
| Endpoint.Domain                       | string | Endpoint domain. | 
| Endpoint.Hostname                     | string | Endpoint hostname. | 
| Endpoint.IPAddress                    | string | Endpoint IP address. | 
| Endpoint.OS                           | string | Endpoint OS. | 
| Endpoint.OSVersion                    | string | Endpoint OS version. | 
| Endpoint.Processor                    | string | Processor model. | 
| Endpoint.Processors                   | number | Number of processors. | 
| Endpoint.Memory                       | number | The amount of memory in the endpoint. | 
| McAfee.ePO.Endpoint.ParentID          | Number | Endpoint parent ID. | 
| McAfee.ePO.Endpoint.ComputerName      | String | Endpoint computer name. | 
| McAfee.ePO.Endpoint.Description       | String | Endpoint description. | 
| McAfee.ePO.Endpoint.SystemDescription | String | Endpoint system description. | 
| McAfee.ePO.Endpoint.TimeZone          | String | Endpoint time zone. | 
| McAfee.ePO.Endpoint.DefaultLangID     | String | Endpoint default language ID. | 
| McAfee.ePO.Endpoint.UserName          | String | Endpoint username. | 
| McAfee.ePO.Endpoint.Domain            | String | Endpoint domain name. | 
| McAfee.ePO.Endpoint.Hostname          | String | Endpoint IP host name | 
| McAfee.ePO.Endpoint.IPV6              | String | Endpoint IPv6 address. | 
| McAfee.ePO.Endpoint.IPAddress         | String | Endpoint IP address. | 
| McAfee.ePO.Endpoint.IPSubnet          | String | Endpoint IP subnet. | 
| McAfee.ePO.Endpoint.IPSubnetMask      | String | Endpoint IP subnet mask | 
| McAfee.ePO.Endpoint.IPV4x             | Number | Endpoint IPV4x address. | 
| McAfee.ePO.Endpoint.IPXAddress        | String | Endpoint IPX address. | 
| McAfee.ePO.Endpoint.SubnetAddress     | String | Endpoint subnet address. | 
| McAfee.ePO.Endpoint.SubnetMask        | String | Endpoint subnet mask. | 
| McAfee.ePO.Endpoint.NetAddress        | String | Endpoint net address. | 
| McAfee.ePO.Endpoint.OSType            | String | Endpoint OS type. | 
| McAfee.ePO.Endpoint.OSVersion         | String | Endpoint OS version. | 
| McAfee.ePO.Endpoint.OSServicePackVer  | String | Endpoint OS service pack version. | 
| McAfee.ePO.Endpoint.OSBuildNum        | Number | Endpoint OS build number. | 
| McAfee.ePO.Endpoint.OSPlatform        | String | Endpoint OS platform. | 
| McAfee.ePO.Endpoint.OSOEMID           | String | Endpoint OS OEM ID. | 
| McAfee.ePO.Endpoint.Processor         | String | Endpoint CPU type. | 
| McAfee.ePO.Endpoint.CPUSpeed          | Number | Endpoint CPU speed. | 
| McAfee.ePO.Endpoint.Processors        | Number | The number of CPUs in the endpoint. | 
| McAfee.ePO.Endpoint.CPUSerialNum      | String | The CPU serial number in the endpoint. | 
| McAfee.ePO.Endpoint.Memory            | Number |The total amount of physical memory in the endpoint. | 
| McAfee.ePO.Endpoint.FreeMemory        | Number | The amount of free memory in the endpoint. | 
| McAfee.ePO.Endpoint.FreeDiskSpace     | Number | The amount of free disk space in the endpoint. | 
| McAfee.ePO.Endpoint.TotalDiskSpace    | Number | The total amount of disk space in the endpoint. | 
| McAfee.ePO.Endpoint.UserProperty1     | String | Endpoint user property 1. | 
| McAfee.ePO.Endpoint.UserProperty2     | String | Endpoint user property 2. | 
| McAfee.ePO.Endpoint.UserProperty3     | String | Endpoint user property 3. | 
| McAfee.ePO.Endpoint.UserProperty4     | String | Endpoint user property 4. | 
| McAfee.ePO.Endpoint.SysvolFreeSpace   | Number | EThe amount of system volume free space in the endpoint. | 
| McAfee.ePO.Endpoint.SysvolTotalSpace  | Number | The amount of system volume total space in the endpoint. | 
| McAfee.ePO.Endpoint.Tags              | String | Endpoint EPO tags. | 
| McAfee.ePO.Endpoint.ExcludedTags      | String | Endpoint EPO excluded tags. | 
| McAfee.ePO.Endpoint.LastUpdate        | Date | The date the endpoint ePO was last updated. | 
| McAfee.ePO.Endpoint.ManagedState      | Number | Endpoint EPO managed state. | 
| McAfee.ePO.Endpoint.AgentGUID         | String | Endpoint EPO agent GUID. | 
| McAfee.ePO.Endpoint.AgentVersion      | String | Endpoint EPO agent version. | 
| McAfee.ePO.Endpoint.AutoID            | Number | Endpoint EPO auto ID. | 


#### Command Example
```!epo-find-systems groupId="2"```

#### Context Example
```json
{
    "Endpoint": [
        {
            "ID": "10.0.0.1"
        },      
        {
            "Domain": "WORKGROUP",
            "ID": "WIN-AQ0LQQOG4Q7",
            "Memory": 8589398016,
            "OS": "Windows Server 2012 R2",
            "OSVersion": "6.3",
            "Processor": "Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz",
            "Processors": 4
        }
    ],
    "McAfee": {
        "ePO": {
            "Endpoint": [
                {
                    "AgentGUID": null,
                    "AgentVersion": null,
                    "AutoID": 2,
                    "CPUSerialNum": "",
                    "CPUSpeed": 0,
                    "CPUType": "",
                    "ComputerName": "10.0.0.1",
                    "DefaultLangID": "",
                    "Description": null,
                    "DomainName": "",
                    "ExcludedTags": "",
                    "FreeDiskSpace": 0,
                    "FreeMemory": 0,
                    "Hostname": "",
                    "IPAddress": "",
                    "IPSubnet": null,
                    "IPSubnetMask": null,
                    "IPV4x": null,
                    "IPV6": null,
                    "IPXAddress": "",
                    "LastUpdate": null,
                    "ManagedState": 0,
                    "NetAddress": "",
                    "NumOfCPU": 0,
                    "OSBuildNum": 0,
                    "OSOEMID": "",
                    "OSPlatform": "",
                    "OSServicePackVer": "",
                    "OSType": "",
                    "OSVersion": "",
                    "ParentID": 7,
                    "SubnetAddress": "",
                    "SubnetMask": "",
                    "SystemDescription": null,
                    "SysvolFreeSpace": 0,
                    "SysvolTotalSpace": 0,
                    "Tags": "Scan Now",
                    "TimeZone": "",
                    "TotalDiskSpace": 0,
                    "TotalPhysicalMemory": 0,
                    "UserName": "",
                    "UserProperty1": null,
                    "UserProperty2": null,
                    "UserProperty3": null,
                    "UserProperty4": null,
                },
                {
                    "AgentGUID": "CA0CE11A-DCE8-11E8-0805-000C2994FF62
                    "AutoID": 2,
                    "CPUSerialNum": "N/A",
                    "CPUSpeed": 2095,
                    "CPUType": "Intel(R) Xeon(R) Silver 4216 CPU @ 2.10GHz",
                    "ComputerName": "WIN-AQ0LQQOG4Q7",
                    "DefaultLangID": "0409",
                    "Description": null,
                    "DomainName": "WORKGROUP",
                    "ExcludedTags": "",
                    "FreeDiskSpace": 145005,
                    "FreeMemory": 1195880448,
                    "Hostname": "",
                    "IPAddress": "",
                    "IPV4x": null,
                    "IPXAddress": "N/A",
                    "LastUpdate": "2021-12-16T14:44:41-08:00",
                    "ManagedState": 1,
                    "NetAddress": "",
                    "NumOfCPU": 4,
                    "OSBuildNum": 9600,
                    "OSOEMID": "00252-00112-50691-AA377",
                    "OSPlatform": "Server",
                    "OSServicePackVer": "",
                    "OSType": "Windows Server 2012 R2",
                    "OSVersion": "6.3",
                    "ParentID": 17,
                    "SubnetAddress": "",
                    "SubnetMask": "",
                    "SystemDescription": "N/A",
                    "SysvolFreeSpace": 145005,
                    "SysvolTotalSpace": 204447,
                    "Tags": "Server",
                    "TimeZone": "Pacific Standard Time",
                    "TotalDiskSpace": 204447,
                    "TotalPhysicalMemory": 8589398016,
                    "UserName": "Administrator",
                    "UserProperty1": null,
                    "UserProperty2": null,
                    "UserProperty3": null,
                    "UserProperty4": null,
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Endpoint information:
>|Memory|Name|Processors|
>|---|---|---|
>| 0 | 10.0.0.1 | 0 |


### epo-find-system
***
Finds systems in the McAfee ePO system tree.


#### Base Command

`epo-find-system`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchText | Hostname to search for. | Required | 
| verbose | Whether to display all system data. Possible values are: true, false. | Optional | 


#### Context Output

| **Path**                              | **Type** | **Description** |
|---------------------------------------| --- | --- |
| Endpoint.ID                           | String | The unique ID within the tool retrieving the endpoint. |
| Endpoint.Domain                       | string | Endpoint domain. | 
| Endpoint.Hostname                     | string | Endpoint hostname. | 
| Endpoint.IPAddress                    | string | Endpoint IP address. | 
| Endpoint.OS                           | string | Endpoint OS. | 
| Endpoint.OSVersion                    | string | Endpoint OS version. | 
| Endpoint.Processor                    | string | Processor model. | 
| Endpoint.Processors                   | number | Number of processors. | 
| Endpoint.Memory                       | number | The amount of memory in the endpoint. | 
| McAfee.ePO.Endpoint.ParentID          | Number | Endpoint Parent ID. | 
| McAfee.ePO.Endpoint.ComputerName      | String | Endpoint computer name. | 
| McAfee.ePO.Endpoint.Description       | String | Endpoint description. | 
| McAfee.ePO.Endpoint.SystemDescription | String | Endpoint system description. | 
| McAfee.ePO.Endpoint.TimeZone          | String | Endpoint time zone. | 
| McAfee.ePO.Endpoint.DefaultLangID     | String | Endpoint default language ID. | 
| McAfee.ePO.Endpoint.UserName          | String | Endpoint username. | 
| McAfee.ePO.Endpoint.Domain            | String | Endpoint domain name. | 
| McAfee.ePO.Endpoint.Hostname          | String |  Endpoint IP host name. | 
| McAfee.ePO.Endpoint.IPV6              | String | Endpoint IPv6 address. | 
| McAfee.ePO.Endpoint.IPAddress         | String | Endpoint IP address. | 
| McAfee.ePO.Endpoint.IPSubnet          | String | Endpoint IP subnet. | 
| McAfee.ePO.Endpoint.IPSubnetMask      | String | Endpoint IP subnet mask. | 
| McAfee.ePO.Endpoint.IPV4x             | Number | Endpoint IPV4x address. | 
| McAfee.ePO.Endpoint.IPXAddress        | String | Endpoint IPX address. | 
| McAfee.ePO.Endpoint.SubnetAddress     | String | Endpoint subnet address. | 
| McAfee.ePO.Endpoint.SubnetMask        | String | Endpoint subnet mask. | 
| McAfee.ePO.Endpoint.NetAddress        | String | Endpoint net address. | 
| McAfee.ePO.Endpoint.OSType            | String | Endpoint OS type. | 
| McAfee.ePO.Endpoint.OSVersion         | String | Endpoint OS version. | 
| McAfee.ePO.Endpoint.OSServicePackVer  | String | Endpoint OS service pack version. | 
| McAfee.ePO.Endpoint.OSBuildNum        | Number | Endpoint OS build number. | 
| McAfee.ePO.Endpoint.OSPlatform        | String | Endpoint OS platform. | 
| McAfee.ePO.Endpoint.OSOEMID           | String | Endpoint OS OEM ID. | 
| McAfee.ePO.Endpoint.Processor         | String | Endpoint CPU type. | 
| McAfee.ePO.Endpoint.CPUSpeed          | Number | Endpoint CPU speed. | 
| McAfee.ePO.Endpoint.Processors        | Number | Number of CPUs in the endpoint. | 
| McAfee.ePO.Endpoint.CPUSerialNum      | String | Endpoint CPU serial number. | 
| McAfee.ePO.Endpoint.Memory            | Number | The total amount of physical memory in the endpoint. | 
| McAfee.ePO.Endpoint.FreeMemory        | Number | The amount of free memory in the endpoint. | 
| McAfee.ePO.Endpoint.FreeDiskSpace     | Number | The amount of free disk space in the endpoint. | 
| McAfee.ePO.Endpoint.TotalDiskSpace    | Number | The total amount of disk space in the endpoint. | 
| McAfee.ePO.Endpoint.UserProperty1     | String | Endpoint user property 1. | 
| McAfee.ePO.Endpoint.UserProperty2     | String | Endpoint user property 2. | 
| McAfee.ePO.Endpoint.UserProperty3     | String | Endpoint user property 3. | 
| McAfee.ePO.Endpoint.UserProperty4     | String | Endpoint user property 4. | 
| McAfee.ePO.Endpoint.SysvolFreeSpace   | Number | The amount of system volume free space in the endpoint. | 
| McAfee.ePO.Endpoint.SysvolTotalSpace  | Number | The total amount of system volume space in the endpoint. | 
| McAfee.ePO.Endpoint.Tags              | String | Endpoint ePO tags. | 
| McAfee.ePO.Endpoint.ExcludedTags      | String | Endpoint EPO excluded tags. | 
| McAfee.ePO.Endpoint.LastUpdate        | Date | Endpoint he date the endpoint was last updated. | 
| McAfee.ePO.Endpoint.ManagedState      | Number | Endpoint managed state. | 
| McAfee.ePO.Endpoint.AgentGUID         | String | Endpoint agent GUID. | 
| McAfee.ePO.Endpoint.AgentVersion      | String | Endpoint agent version. | 
| McAfee.ePO.Endpoint.AutoID            | Number | Endpoint auto ID. | 


#### Command Example
```!epo-find-system searchText="TIE"```

#### Context Example
```json
{
    "Endpoint": {
        "Domain": "(none)",
        "ID": "tie",
        "IPAddress": "192.168.1.102",
        "Memory": 8364199936,
        "OS": "Linux",
        "OSVersion": "4.9",
        "Processor": "Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz",
        "Processors": 8
    },
    "McAfee": {
        "ePO": {
            "Endpoint": {
                "AgentGUID": "E0F52A7C-A841-11E7-0467-000C2936A49A",
                "AutoID": 3,
                "CPUSerialNum": "N/A",
                "CPUSpeed": 2600,
                "CPUType": "Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz",
                "ComputerName": "tie",
                "DefaultLangID": "0409",
                "Description": null,
                "DomainName": "(none)",
                "ExcludedTags": "",
                "FreeDiskSpace": 93781,
                "FreeMemory": 240263168,
                "Hostname": "tie",
                "IPV4x": 1084752230,
                "IPXAddress": "N/A",
                "LastUpdate": "2021-12-16T14:19:25-08:00",
                "ManagedState": 1,
                "NetAddress": "000C29B1EE8E",
                "NumOfCPU": 8,
                "OSBuildNum": 0,
                "OSOEMID": "McAfee TIE Platform Server 3.0.0.480",
                "OSPlatform": "Server",
                "OSServicePackVer": "189-1.mlos2.x86_64",
                "OSType": "Linux",
                "OSVersion": "4.9",
                "ParentID": 2,
                "SubnetAddress": "",
                "SubnetMask": "",
                "SystemDescription": "N/A",
                "SysvolFreeSpace": 0,
                "SysvolTotalSpace": 0,
                "Tags": "DXLBROKER, Server, TIESERVER",
                "TimeZone": "UTC",
                "TotalDiskSpace": 104488,
                "TotalPhysicalMemory": 8364199936,
                "UserName": "root",
                "UserProperty1": null,
                "UserProperty2": null,
                "UserProperty3": null,
                "UserProperty4": null,
            }
        }
    }
}
```

#### Human Readable Output

>#### Systems in the System Tree
>|Name|Domain|Hostname|IPAddress|OS|OSVersion|Processor|Processors|Memory| 
> |-|-|-|-|-|-|-|-|-| 
>|tie |(none) |tie |192.168.1.102 |Linux |4.9 |Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz |8 |8364199936 |


### epo-wakeup-agent
***
Wakes up an agent.


#### Base Command

`epo-wakeup-agent`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| names | A comma-separated list of agent host names. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-wakeup-agent names="TIE"```

#### Human Readable Output

>#### ePO agents was awaken.
>| Completed | Failed | Expired |
>|-|-|-|
>|1|0|0|

### epo-apply-tag
***
Applies a tag to the specified host names.


#### Base Command

`epo-apply-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| names | A comma-separated list of host names on which to apply tags. | Required | 
| tagName | Tag name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-apply-tag names="TIE" tagName="Server"```

#### Human Readable Output

>ePO could not find server or server already assigned to the given tag.


### epo-clear-tag
***
Clears a tag from the specified host names.


#### Base Command

`epo-clear-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| names | A comma-separated list of host names from which to clear tags. | Required | 
| tagName | Tag name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-clear-tag names="TIE" tagName="MARSERVER"```

#### Human Readable Output

>ePO could not find server or server already assigned to the given tag.


### epo-list-tag
***
List tags that contain the searchText. If no searchText is specified, list all tags available in the ePO system.


#### Base Command

`epo-list-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchText | List tags that contains the searchText in their name field. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.Tags.tagId | number | Tag ID.. | 
| McAfee.ePO.Tags.tagName | string | Tag name. | 
| McAfee.ePO.Tags.tagNotes | string | Tag notes. | 


#### Command Example
```!epo-list-tag searchText="server"```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "Tags": [
                {
                    "tagId": 1,
                    "tagName": "Server",
                    "tagNotes": "Default tag for systems identified as a Server"
                },
                {
                    "tagId": 4,
                    "tagName": "TIESERVER",
                    "tagNotes": "Apply Tag to TIEServers"
                },
                {
                    "tagId": 5,
                    "tagName": "MARSERVER",
                    "tagNotes": "Apply Tag to Active Response Server"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ePO Tags
>|tagId|tagName|tagNotes|
>|---|---|---|
>| 1 | Server | Default tag for systems identified as a Server |
>| 4 | TIESERVER | Apply Tag to TIEServers |
>| 5 | MARSERVER | Apply Tag to Active Response Server |


### epo-get-tables
***
Returns the ePO table of the table argument that is specified. If no table argument is specified, returns all ePO tables.


#### Base Command

`epo-get-tables`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table | Name of the table to retrieve. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-get-tables table="Client Events"```

#### Human Readable Output

>### ePO tables:
>|name|target|type|databaseType|description|columns|relatedTables|foreignKeys|
>|---|---|---|---|---|---|---|---|
>| Client Events | EPOProductEvents | target |  | Retrieves information on client events from managed systems. | <br/>    Name          Type           Select? Condition? GroupBy? Order? Number? <br/>    ------------- -------------- ------- ---------- -------- ------ -------<br/>    AutoID        long           False   False      False    True   True   <br/>    AgentGUID     string         True    False      False    True   False  <br/>    NodeID        int            False   False      False    True   True   <br/>    TVDEventID    eventIdInt     True    True       True     True   True   <br/>    TVDSeverity   enum           True    True       True     True   False  <br/>    ReceivedUTC   timestamp      True    True       True     True   False  <br/>    DetectedUTC   timestamp      True    True       True     True   False  <br/>    HostName      string         True    True       True     True   False  <br/>    UserName      string         True    True       True     True   False  <br/>    IPV6          ipv6           True    True       True     True   False  <br/>    ProductCode   string         False   False      False    True   False  <br/>    version       productVersion True    True       True     True   False  <br/>    SPHotFix      string         True    True       True     True   False  <br/>    ExtraDATNames string         True    True       True     True   False  <br/>    Type          string_lookup  True    True       True     True   False  <br/>    Error         enum           True    True       True     True   False  <br/>    Locale        int            True    True       True     True   True   <br/>    SiteName      string         True    True       True     True   False  <br/>    InitiatorID   string         True    True       True     True   False  <br/>    InitiatorType string_lookup  True    True       True     True   False  <br/>    TenantId      int            False   False      False    True   True   <br/> | <br/>    Name<br/>    ------------------<br/>    EPOLeafNode<br/>    EPOSoftwareView<br/>    EPOEventFilterDesc<br/> | <br/>    Source table     Source Columns Destination table Destination columns Allows inverse? One-to-one? Many-to-one? <br/>    ---------------- -------------- ----------------- ------------------- --------------- ----------- ------------<br/>    EPOProductEvents AgentGUID      EPOLeafNode       AgentGUID           False           False       True        <br/>    EPOProductEvents TVDEventID     EPOEventFilterDesc EventId             False           False       True        <br/>    EPOProductEvents ProductCode    EPOSoftwareView   ProductCode         False           False       True        <br/> |


### epo-query-table
***
Queries an ePO table.


#### Base Command

`epo-query-table`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target | Name of the table. | Required | 
| select | The columns to return, in SQUID syntax. Example: "(select EPOEvents.AutoID EPOEvents.DetectedUTC EPOEvents.ReceivedUTC)". | Optional | 
| where | Filter results, in SQUID syntax. Example: "(where ( eq ( OrionTaskLogTask .UserName "ga" )))". | Optional | 
| order | Order in which to return the results, in SQUID syntax. Example: "(order (asc OrionTaskLogTask.StartDate) )"). | Optional | 
| group | Group the results, in SQUID Syntax. Example: "(group EPOBranchNode.NodeName)". | Optional | 
| joinTables | Perform join, in SQUID syntax. | Optional | 
| query_name | Name for the query to appear in the context. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.Query | unknown | Query result. | 


#### Command Example
```!epo-query-table target="FW_Rule" query_name="Test Query"```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "Query": {
                "Test Query": [
                        {
                            "FW_Rule.action": "JUMP",
                            "FW_Rule.direction": "EITHER",
                            "FW_Rule.enabled": 1,
                            "FW_Rule.intrusion": false,
                            "FW_Rule.lastModified": "2014-06-20T11:42:38-07:00",
                            "FW_Rule.lastModifyingUsername": "system",
                            "FW_Rule.localServiceList": "",
                            "FW_Rule.mediaFlags": 7,
                            "FW_Rule.name": "Outlook",
                            "FW_Rule.note": "",
                            "FW_Rule.remoteServiceList": "",
                            "FW_Rule.schedule_end": "0:00",
                            "FW_Rule.schedule_offHours": "NONE",
                            "FW_Rule.schedule_start": "0:00",
                            "FW_Rule.trafficLogged": false,
                            "FW_Rule.transportProtocol": 1024
                        },
                        {
                            "FW_Rule.action": "ALLOW",
                            "FW_Rule.direction": "IN",
                            "FW_Rule.enabled": 1,
                            "FW_Rule.intrusion": false,
                            "FW_Rule.lastModified": "2010-03-29T11:54:22-07:00",
                            "FW_Rule.lastModifyingUsername": "admin",
                            "FW_Rule.localServiceList": "0",
                            "FW_Rule.mediaFlags": 7,
                            "FW_Rule.name": "Allow ICMP Echo Reply Incoming for Services",
                            "FW_Rule.note": "",
                            "FW_Rule.remoteServiceList": "",
                            "FW_Rule.schedule_end": "0:00",
                            "FW_Rule.schedule_offHours": "NONE",
                            "FW_Rule.schedule_start": "0:00",
                            "FW_Rule.trafficLogged": false,
                            "FW_Rule.transportProtocol": 1
                        },
                        {
                            "FW_Rule.action": "BLOCK",
                            "FW_Rule.direction": "IN",
                            "FW_Rule.enabled": 1,
                            "FW_Rule.intrusion": false,
                            "FW_Rule.lastModified": "2009-10-22T17:32:08-07:00",
                            "FW_Rule.lastModifyingUsername": "admin",
                            "FW_Rule.localServiceList": "",
                            "FW_Rule.mediaFlags": 7,
                            "FW_Rule.name": "Block System TCP Incoming",
                            "FW_Rule.note": "",
                            "FW_Rule.remoteServiceList": "",
                            "FW_Rule.schedule_end": "0:00",
                            "FW_Rule.schedule_offHours": "NONE",
                            "FW_Rule.schedule_start": "0:00",
                            "FW_Rule.trafficLogged": false,
                            "FW_Rule.transportProtocol": 6
                        }
                    ]
                }
            }
        }
    }
}
```

#### Human Readable Output

>### ePO Table Query:
>|FW_Rule.localServiceList|FW_Rule.trafficLogged|FW_Rule.lastModifyingUsername|FW_Rule.transportProtocol|FW_Rule.remoteServiceList|FW_Rule.name|FW_Rule.schedule_offHours|FW_Rule.note|FW_Rule.schedule_start|FW_Rule.mediaFlags|FW_Rule.intrusion|FW_Rule.schedule_end|FW_Rule.action|FW_Rule.direction|FW_Rule.lastModified|FW_Rule.enabled|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | false | system | 1024 |  | Outlook | NONE |  | 0:00 | 7 | false | 0:00 | JUMP | EITHER | 2014-06-20T11:42:38-07:00 | 1 |
>| 0 | false | admin | 1 |  | Allow ICMP Echo Reply Incoming for Services | NONE |  | 0:00 | 7 | false | 0:00 | ALLOW | IN | 2010-03-29T11:54:22-07:00 | 1 |
>|  | false | admin | 6 |  | Block System TCP Incoming | NONE |  | 0:00 | 7 | false | 0:00 | BLOCK | IN | 2009-10-22T17:32:08-07:00 | 1 |


### epo-get-version
***
Returns the ePO version.


#### Base Command

`epo-get-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.Version | string | ePO version. | 


#### Command Example
```!epo-get-version```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "Version": "5.3.2"
        }
    }
}
```

#### Human Readable Output

>### ePO version is: 5.3.2

### epo-move-system
***
Moves a system to a different group in the McAfee ePO.


#### Base Command

`epo-move-system`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| names | A comma-separated list of asset names. | Required | 
| parentGroupId | Group ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-move-system names="TIE" parentGroupId="3"```

#### Human Readable Output

>System(s) TIE moved successfully to GroupId 3

### epo-advanced-command
***
Executes the ePO command. Run the 'epo-help' command to get a list of available commands. For example/:/  !epo-advanced-command command=clienttask.find commandArgs=searchText:On-Demand. You can specify the 'headers' argument to filter table headers, for example/:/ !epo-command command=system.find searchText=10.0.0.1 headers=EPOBranchNode.AutoID,EPOComputerProperties.ComputerName.


#### Base Command

`epo-advanced-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command | The command to execute. Run either the core.help command or the !epo-help to get all available commands. | Required | 
| commandArgs | CSV list of key value pairs as additional arguments to pass, for example, "argName1:argValue1,argName2:argValue2". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-advanced-command command="clienttask.find" commandArgs="searchText:On-Demand"```

#### Human Readable Output

>### ePO command *clienttask.find* results:
>|objectName|productId|productName|objectId|typeName|typeId|
>|---|---|---|---|---|---|
>| On-Demand Scan - Full Scan | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 26 | Endpoint Security Threat Prevention: Policy Based On-Demand Scan | 11 |
>| On-Demand Scan - Quick Scan | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 27 | Endpoint Security Threat Prevention: Policy Based On-Demand Scan | 11 |


### epo-find-client-task
***
Finds client tasks.


#### Base Command

`epo-find-client-task`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchText | List client tasks that contains the searchText in their name field. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.ClientTask.objectId | number | Client task object ID. | 
| McAfee.ePO.ClientTask.objectName | string | Client task object name. | 
| McAfee.ePO.ClientTask.productId | string | Client task product ID. | 
| McAfee.ePO.ClientTask.productName | string | Client task product name. | 
| McAfee.ePO.ClientTask.typeId | number | Client task type ID. | 
| McAfee.ePO.ClientTask.typeName | string | Client task type name. | 


#### Command Example
```!epo-find-client-task searchText="On-Demand"```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "ClientTask": [
                {
                    "objectId": 26,
                    "objectName": "On-Demand Scan - Full Scan",
                    "productId": "ENDP_AM_1000",
                    "productName": "Endpoint Security Threat Prevention ",
                    "typeId": 11,
                    "typeName": "Endpoint Security Threat Prevention: Policy Based On-Demand Scan"
                },
                {
                    "objectId": 27,
                    "objectName": "On-Demand Scan - Quick Scan",
                    "productId": "ENDP_AM_1000",
                    "productName": "Endpoint Security Threat Prevention ",
                    "typeId": 11,
                    "typeName": "Endpoint Security Threat Prevention: Policy Based On-Demand Scan"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ePO Client Tasks:
>|productName|objectName|productId|typeId|objectId|typeName|
>|---|---|---|---|---|---|
>| Endpoint Security Threat Prevention  | On-Demand Scan - Full Scan | ENDP_AM_1000 | 11 | 26 | Endpoint Security Threat Prevention: Policy Based On-Demand Scan |
>| Endpoint Security Threat Prevention  | On-Demand Scan - Quick Scan | ENDP_AM_1000 | 11 | 27 | Endpoint Security Threat Prevention: Policy Based On-Demand Scan |


### epo-find-policy
***
Finds policy.


#### Base Command

`epo-find-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| searchText | List policies that contains the searchText in their name field. If no searchText is specified, list all policies in the ePO system. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-find-policy searchText="On-Access"```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "Policy": [
                {
                    "featureId": "ENDP_AM_1000",
                    "featureName": " Policy Category",
                    "objectId": 84,
                    "objectName": "McAfee Default",
                    "objectNotes": "",
                    "productId": "ENDP_AM_1000",
                    "productName": "Endpoint Security Threat Prevention ",
                    "typeId": 40,
                    "typeName": "On-Access Scan"
                },
                {
                    "featureId": "ENDP_AM_1000",
                    "featureName": " Policy Category",
                    "objectId": 86,
                    "objectName": "On-Access Scan for Exchange",
                    "objectNotes": "",
                    "productId": "ENDP_AM_1000",
                    "productName": "Endpoint Security Threat Prevention ",
                    "typeId": 40,
                    "typeName": "On-Access Scan"
                },
                {
                    "featureId": "ENDP_AM_1000",
                    "featureName": " Policy Category",
                    "objectId": 90,
                    "objectName": "My Default",
                    "objectNotes": "",
                    "productId": "ENDP_AM_1000",
                    "productName": "Endpoint Security Threat Prevention ",
                    "typeId": 40,
                    "typeName": "On-Access Scan"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ePO Policies:
>|objectName|featureName|productId|productName|objectId|typeName|featureId|typeId|
>|---|---|---|---|---|---|---|---|
>| McAfee Default |  Policy Category | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 84 | On-Access Scan | ENDP_AM_1000 | 40 |
>| On-Access Scan for Exchange |  Policy Category | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 86 | On-Access Scan | ENDP_AM_1000 | 40 |
>| My Default |  Policy Category | ENDP_AM_1000 | Endpoint Security Threat Prevention  | 90 | On-Access Scan | ENDP_AM_1000 | 40 |


### epo-assign-policy-to-group
***
Assigns a policy to the specified group or resets the group's inheritance for the specified policy.


#### Base Command

`epo-assign-policy-to-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groupId | System tree group ID (as returned by system.findGroups). | Required | 
| productId | Product ID (as returned by policy.find). | Required | 
| objectId | Object ID (as returned by policy.find). | Required | 
| resetInheritance | If true, resets the inheritance for the specified policy on the given group. Default is false. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-assign-policy-to-group groupId="2" productId="ENDP_AM_1000" objectId="86"```

#### Human Readable Output

>Policy productId:ENDP_AM_1000 objectId:86 assigned successfully to GroupId 2

### epo-assign-policy-to-system
***
Assigns a policy to a supplied list of systems or resets the systems' inheritance for the specified policy.


#### Base Command

`epo-assign-policy-to-system`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| names | EEither supply a comma-separated list of names/ip addresses or a comma-separated list of IDs to which the policy is to be assigned. | Required | 
| productId | Product ID (as returned by policy.find). | Required | 
| typeId | Type ID (as returned by policy.find). | Required | 
| objectId | Object ID (as returned by policy.find). | Required | 
| resetInheritance | If true, resets the inheritance for the specified object. Default is false. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-assign-policy-to-system names="TIE" productId="ENDP_AM_1000" typeId="40" objectId="84"```

#### Human Readable Output

>### ePO Policies:
>|status|name|message|id|
>|---|---|---|---|
>| 0 | TIE | Assign policy succeeded | 2 |


### epo-list-issues
***
List the issue for the ID that is specified. If no ID is specified, list all issues in the McAfee ePO system.


#### Base Command

`epo-list-issues`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the issue to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.Issue.activityLog.date | string | Date of the issue activity log. | 
| McAfee.ePO.Issue.activityLog.details | string | Details of the issue activity log. | 
| McAfee.ePO.Issue.activityLog.id | number | The ID of the issue activity log. | 
| McAfee.ePO.Issue.activityLog.issueId | number | The issue ID of the activity log. | 
| McAfee.ePO.Issue.activityLog.title | string | The title of the issue activity log. | 
| McAfee.ePO.Issue.activityLog.username | string | The username of the issue activity log. | 
| McAfee.ePO.Issue.id | number | Issue ID. | 
| McAfee.ePO.Issue.name | string | Issue name. | 
| McAfee.ePO.Issue.type | string | Issue type. | 
| McAfee.ePO.Issue.description | string | Issue description. | 
| McAfee.ePO.Issue.state | string | Issue state. | 
| McAfee.ePO.Issue.priority | string | Issue priority. | 
| McAfee.ePO.Issue.severity | string | Issue severity. | 
| McAfee.ePO.Issue.resolution | string | Issue resolution. | 
| McAfee.ePO.Issue.creatorName | string | Issue creator name. | 
| McAfee.ePO.Issue.assignee | number | Issue assignee ID. | 
| McAfee.ePO.Issue.assigneeName | string | Issue assignee name. | 
| McAfee.ePO.Issue.createdDate | string | Date the issue was created. | 
| McAfee.ePO.Issue.dueDate | string | Date the issue is due. | 
| McAfee.ePO.Issue.ticketId | string | Ticket ID of the issue. | 
| McAfee.ePO.Issue.ticketServerName | string | Issue ticket server name. | 


#### Command Example
```!epo-list-issues```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "Issue": [
                {
                    "activityLog": [
                        {
                            "date": "2021-05-09T03:36:56-07:00",
                            "details": "",
                            "id": 1,
                            "issueId": 1,
                            "title": "Issue Created",
                            "username": "admin"
                        }
                    ],
                    "assignee": null,
                    "assigneeName": "dxl",
                    "createdDate": "2021-05-09T03:36:56-07:00",
                    "creatorName": "admin",
                    "description": "aaaa",
                    "dueDate": null,
                    "id": 1,
                    "name": "aaaa",
                    "priority": "MEDIUM",
                    "resolution": "NONE",
                    "severity": "LOWEST",
                    "state": "NEW",
                    "subtype": null,
                    "ticketId": null,
                    "ticketServerName": null,
                    "type": "issue.type.untyped"
                },
                {
                    "activityLog": [
                        {
                            "date": "2021-11-23T00:46:25-08:00",
                            "details": "",
                            "id": 2,
                            "issueId": 2,
                            "title": "Issue Created",
                            "username": "admin"
                        },
                        {
                            "date": "2021-11-23T23:26:20-08:00",
                            "details": "assignee changed from test_api to admin",
                            "id": 3,
                            "issueId": 2,
                            "title": "Issue Changed",
                            "username": "admin"
                        },
                        {
                            "date": "2021-11-23T23:32:08-08:00",
                            "details": "yakovi",
                            "id": 4,
                            "issueId": 2,
                            "title": "User Comment",
                            "username": "admin"
                        }
                    ],
                    "assignee": null,
                    "assigneeName": "admin",
                    "createdDate": "2021-11-23T00:46:25-08:00",
                    "creatorName": "admin",
                    "description": "test1",
                    "dueDate": null,
                    "id": 2,
                    "name": "Wissam",
                    "priority": "HIGH",
                    "resolution": "NONE",
                    "severity": "MEDIUM",
                    "state": "NEW",
                    "subtype": null,
                    "ticketId": null,
                    "ticketServerName": null,
                    "type": "issue.type.untyped"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ePO Issue List:
>|ticketId|dueDate|createdDate|creatorName|resolution|subtype|assigneeName|description|priority|type|ticketServerName|name|assignee|severity|activityLog|id|state|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | 2021-05-09T03:36:56-07:00 | admin | NONE |  | dxl | aaaa | MEDIUM | issue.type.untyped |  | aaaa |  | LOWEST | {'date': '2021-05-09T03:36:56-07:00', 'details': '', 'id': 1, 'issueId': 1, 'title': 'Issue Created', 'username': 'admin'} | 1 | NEW |
>|  |  | 2021-11-23T00:46:25-08:00 | admin | NONE |  | admin | test1 | HIGH | issue.type.untyped |  | Wissam |  | MEDIUM | {'date': '2021-11-23T00:46:25-08:00', 'details': '', 'id': 2, 'issueId': 2, 'title': 'Issue Created', 'username': 'admin'},<br/>{'date': '2021-11-23T23:26:20-08:00', 'details': 'assignee changed from test_api to admin', 'id': 3, 'issueId': 2, 'title': 'Issue Changed', 'username': 'admin'},<br/>{'date': '2021-11-23T23:32:08-08:00', 'details': 'yakovi', 'id': 4, 'issueId': 2, 'title': 'User Comment', 'username': 'admin'} | 2 | NEW |


### epo-delete-issue
***
Delete an issue.


#### Base Command

`epo-delete-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the issue to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-delete-issue id=8```

#### Human Readable Output

>Issue with id=0 was deleted

### epo-create-issue
***
Create an issue.


#### Base Command

`epo-create-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Issue name. | Required | 
| description | Issue description. | Required | 
| type | Issue type. | Optional | 
| state | Issue state. Possible values are: UNKNOWN, NEW, ASSIGNED, RESOLVED, CLOSED, TICKETED, TICKET_PENDING. | Optional | 
| priority | Issue priority. Possible values are: UNKNOWN, LOWEST, LOW, MEDIUM, HIGH, HIGHEST. | Optional | 
| severity | Issue severity. Possible values are: UNKNOWN, LOWEST, LOW, MEDIUM, HIGH, HIGHEST. | Optional | 
| resolution | Issue resolution. Possible values are: NONE, FIXED, WAIVED, WILLNOTFIX. | Optional | 
| due | Due date of the issue in the format yyyy-mm-dd hh:mm:ss. | Optional | 
| assignee_name | Name of the user assigned to the issue. | Optional | 
| ticketServerName | Ticket server name of the issue. | Optional | 
| ticketId | Ticket ID of the issue. | Optional | 
| properties | Properties of the issue. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfee.ePO.Issue.id | number | Issue ID. | 
| McAfee.ePO.Issue.name | string | Issue name. | 
| McAfee.ePO.Issue.description | string | Issue description. | 


#### Command Example
```!epo-create-issue name="test-epo-integration" description="automatically generated by epo integration" assignee_name="admin"```

#### Context Example
```json
{
    "McAfee": {
        "ePO": {
            "Issue": {
                
                    "description": "automatically generated by epo integration",
                    "id": 35,
                    "name": "test-epo-integration"
            }
        }
    }
}
```

#### Human Readable Output

>Issue with the following ID: 35 was created successfully

### epo-update-issue
***
Update an issue.


#### Base Command

`epo-update-issue`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the issue to update. | Required | 
| name | Name of the issue to update. | Required | 
| description | Description of the issue to update. | Required | 
| state | State of the issue to update. Possible values are: UNKNOWN, NEW, ASSIGNED, RESOLVED, CLOSED, TICKETED, TICKET_PENDING. | Optional | 
| priority | Priority of the issue to update. Possible values are: UNKNOWN, LOWEST, LOW, MEDIUM, HIGH, HIGHEST. | Optional | 
| severity | Severity of the issue to update. Possible values are: UNKNOWN, LOWEST, LOW, MEDIUM, HIGH, HIGHEST. | Optional | 
| resolution | Resolution of the issue to update. Possible values are: NONE, FIXED, WAIVED, WILLNOTFIX. | Optional | 
| due | Due date of the issue to update. | Optional | 
| assignee_name | Name of the user assigned to the issue. | Optional | 
| ticketServerName | Ticket server name of the issue. | Optional | 
| ticketId | Ticket ID of the issue. | Optional | 
| properties | Properties of the issue. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!epo-update-issue id=10 name="test" description="testing epo integration" state="NEW"```

#### Human Readable Output

>Issue with id=10 was updated
