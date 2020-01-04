### cs-falcon-run-command
---
Sends commands to hosts.
##### Base Command

`cs-falcon-run-command`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma separated list of host agent ID’s for which to run commands (can be retrieved by running cs-falcon-search-device command). | Required | 
| command_type | The command type to run. | Required | 
| full_command | The full command to run. | Required | 
| scope | The scope for which to run the command. | Optional | 



##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host for which the command was running. | 
| CrowdStrike.Command.Stdout | string | The standard output of the command. | 
| CrowdStrike.Command.Stderr | string | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | string | The base command. | 
| CrowdStrike.Command.FullCommand | string | The full command. | 


##### Command Example
`cs-falcon-run-command host_ids=284771ee197e422d5176d6634a62b934 command_type=ls full_command="ls C:\\"`

##### Context Example
```
{
    'CrowdStrike': {
        'Command': [{
            'HostID': '284771ee197e422d5176d6634a62b934',
            'Stdout': 'Directory listing for C:\\ -\n\n'
            'Name                                     Type         Size (bytes)    Size (MB)       '
            'Last Modified (UTC-5)     Created (UTC-5)          \n----                             '
            '        ----         ------------    ---------       ---------------------     -------'
            '--------          \n$Recycle.Bin                             <Directory>  --          '
            '    --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     \nITAYDI       '
            '                            <Directory>  --              --              11/19/2018 1:'
            '31:42 PM     11/19/2018 1:31:42 PM    ',
            'Stderr': '',
            'BaseCommand': 'ls',
            'Command': 'ls C:\\'
        }]
}
```

##### Human Readable Output
### Command ls C:\\ results
|BaseCommand|Command|HostID|Stderr|Stdout|
|---|---|---|---|---|
| ls | ls C:\ | 284771ee197e422d5176d6634a62b934 |  | Directory listing for C:\ -<br><br>Name                                     Type         Size (bytes)    Size (MB)       Last Modified (UTC-5)     Created (UTC-5)          <br>----                                     ----         ------------    ---------       ---------------------     ---------------          <br>$Recycle.Bin                             <Directory>  --              --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     <br>ITAYDI                                   <Directory>  --              --              11/19/2018 1:31:42 PM     11/19/2018 1:31:42 PM     |

### cs-falcon-upload-script
---
Uploads a script to Falcon.

##### Base Command
`cs-falcon-upload-script`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The script name to upload. | Required | 
| permission_type | The permission type for the custom script. Can be: "private", which is used only by the user who uploaded it, "group", which is used by all RTR Admins, and "public", which is used by all active-responders and RTR admins. | Optional |
| content | The Contents of the PowerShell script. | Required |  


##### Command Example
`!cs-falcon-upload-script name=greatscript content="Write-Output 'Hello, World!'"`

##### Human Readable Output
The script was uploaded successfully.

### cs-falcon-upload-file
---
Uploads a file to the CrowdStrike cloud (can be used for the RTR `put` command).

##### Base Command
`cs-falcon-upload-file`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The file entry ID to upload. | Required |  

##### Command Example
`!cs-falcon-upload-file entry_id=4@4`

##### Human Readable Output
The file was uploaded successfully.

### cs-falcon-delete-file
---
Deletes a file based on the ID given. Can delete only one file at a time.

##### Base Command
`cs-falcon-delete-file`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | The file ID to delete (can be retrieved by running cs-falcon-list-files command).| Required | 


##### Command Example
`!cs-falcon-delete-file file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

##### Human Readable Output
File le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a was deleted successfully.

### cs-falcon-get-file
---
Returns files based on the IDs given. These are used for the RTR `put` command.

##### Base Command
`cs-falcon-get-file`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_id | A comma separated list of file IDs to get (can be retrieved by running cs-falcon-list-files command). | Required | 



##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.ID | string | The ID of the file. |
| CrowdStrike.File.CreatedBy | string | The email of the user who created the file. |
| CrowdStrike.File.CreatedTime | date | The creation date of the file. |
| CrowdStrike.File.Description | string | The description of the file. |
| CrowdStrike.File.Type | string | The type of the file. For example, script. |
| CrowdStrike.File.ModifiedBy | string | The email of the user who modified the file. |
| CrowdStrike.File.ModifiedTime | date | The modification date of the file. |
| CrowdStrike.File.Name | string | The full file name. |
| CrowdStrike.File.Permission | string | The permission type of the file. Can be: "public", "group" or "private". |
| CrowdStrike.File.SHA256 | string | The SHA-256 hash of the file. |
| File.Type | string | The file type |
| File.Name | string | The full file name. |
| File.SHA256 | string | The SHA-256 hash of the file. |
| File.Size | number | The size of the file in bytes. |

##### Command Example
`!cs-falcon-get-file file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

##### Context Example
```
{
    'CrowdStrike': {
        'File': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'Type': 'script'
            }
        ]
}
```

##### Human Readable Output
### CrowdStrike Falcon file le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|Type|
|---|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc | script |

### cs-falcon-list-files
---
Returns Returns a list of put-file ID's that are available for the user in the `put` command.

##### Base Command
`cs-falcon-list-files`

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.File.ID | string | The ID of the file. |
| CrowdStrike.File.CreatedBy | string | The email of the user who created the file. |
| CrowdStrike.File.CreatedTime | date | The creation date of the file. |
| CrowdStrike.File.Description | string | The description of the file. |
| CrowdStrike.File.Type | string | The type of the file. For example, script. |
| CrowdStrike.File.ModifiedBy | string | The email of the user who modified the file. |
| CrowdStrike.File.ModifiedTime | date | The modification date of the file. |
| CrowdStrike.File.Name | string | The full file name. |
| CrowdStrike.File.Permission | string | The permission type of the file. Can be: "public", "group" or "private". |
| CrowdStrike.File.SHA256 | string | The SHA-256 hash of the file. |
| File.Type | string | The file type |
| File.Name | string | The full file name. |
| File.SHA256 | string | The SHA-256 hash of the file. |
| File.Size | number | The size of the file in bytes. |

##### Command Example
`!cs-falcon-list-files`

##### Context Example
```
{
    'CrowdStrike': {
        'File': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'Type': 'script'
            }
        ]
}
```

##### Human Readable Output
### CrowdStrike Falcon files
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|Type|
|---|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc | script |

### cs-falcon-get-script
---
Return custom scripts based on the ID. Used for the RTR `runscript` command.

##### Base Command
`cs-falcon-get-script`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | A comma separated list of script IDs to get (can be retrieved by running cs-falcon-list-scripts command). | Required | 



##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Script.ID | string | The ID of the script. |
| CrowdStrike.Script.CreatedBy | string | The email of the user who created the script. |
| CrowdStrike.Script.CreatedTime | date | The creation date of the script. |
| CrowdStrike.Script.Description | string | The description of the script. |
| CrowdStrike.Script.ModifiedBy | string | The email of the user who modified the script. |
| CrowdStrike.Script.ModifiedTime | date | The modification date of the script. |
| CrowdStrike.Script.Name | string | The script name. |
| CrowdStrike.Script.Permission | string | The permission type of the script. Can be: "public", "group" or "private". |
| CrowdStrike.Script.SHA256 | string | The SHA-256 hash of the script. |
| CrowdStrike.Script.RunAttemptCount | number | The number of the script run attempts. |
| CrowdStrike.Script.RunSuccessCount | number | List of platforms OS for which the script can run. For example, windows. |
| CrowdStrike.Script.Platform | string | List of platforms OS for which the script can run. For example, windows. |
| CrowdStrike.Script.WriteAccess | boolean | Whether the user has write access to the script. |

##### Command Example
`!cs-falcon-get-script file_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

##### Context Example
```
{
    'CrowdStrike': {
        'Script': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'RunAttemptCount': 0,
                'RunSuccessCount': 0,
                'WriteAccess': True
            }
        ]
}
```

##### Human Readable Output
### CrowdStrike Falcon script le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a
|CreatedBy|CreatedTime|Description|ID|ModifiedBy|ModifiedTime|Name|Permission|SHA256|
|---|---|---|---|---|---|---|---|---|
| spongobob@demisto.com | 2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc |


### cs-falcon-delete-script
---
Deletes a script based on the ID given. Can delete only one script at a time.

##### Base Command
`cs-falcon-delete-script`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_id | The script ID to delete (can be retrieved by running cs-falcon-list-scripts command).| Required | 


##### Command Example
`!cs-falcon-delete-script script_id=le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a`

##### Human Readable Output
Script le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a was deleted successfully.

### cs-falcon-list-scripts
---
Returns a list of custom script IDs that are available for the user in the `runscript` command.

##### Base Command
`cs-falcon-list-scripts`

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Script.ID | string | The ID of the script. |
| CrowdStrike.Script.CreatedBy | string | The email of the user who created the script. |
| CrowdStrike.Script.CreatedTime | date | The creation date of the script. |
| CrowdStrike.Script.Description | string | The description of the script. |
| CrowdStrike.Script.ModifiedBy | string | The email of the user who modified the script. |
| CrowdStrike.Script.ModifiedTime | date | The modification date of the script. |
| CrowdStrike.Script.Name | string | The script name. |
| CrowdStrike.Script.Permission | string | The permission type of the script. Can be: "public", "group" or "private". |
| CrowdStrike.Script.SHA256 | string | The SHA-256 hash of the script. |
| CrowdStrike.Script.RunAttemptCount | number | The number of the script run attempts. |
| CrowdStrike.Script.RunSuccessCount | number | List of platforms OS for which the script can run. For example, windows. |
| CrowdStrike.Script.Platform | string | List of platforms OS for which the script can run. For example, windows. |
| CrowdStrike.Script.WriteAccess | boolean | Whether the user has write access to the script. |

##### Command Example
`!cs-falcon-list-scripts`

##### Context Example
```
{
    'CrowdStrike': {
        'Script': [
            {
                'CreatedBy': 'spongobob@demisto.com',
                'CreatedTime': '2019-10-17T13:41:48.487520845Z',
                'Description': 'Demisto',
                'ID': 'le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a',
                'ModifiedBy': 'spongobob@demisto.com',
                'ModifiedTime': '2019-10-17T13:41:48.487521161Z',
                'Name': 'Demisto',
                'Permission': 'private',
                'SHA256': '5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc',
                'RunAttemptCount': 0,
                'RunSuccessCount': 0,
                'WriteAccess': True
            }
        ]
}
```

##### Human Readable Output
### CrowdStrike Falcon scripts
| CreatedBy | CreatedTime | Description | ID | ModifiedBy | ModifiedTime | Name | Permission| SHA256 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| spongobob@demisto.com |  2019-10-17T13:41:48.487520845Z | Demisto | le10098bf0e311e989190662caec3daa_94cc8c55556741faa1d82bd1faabfb4a | spongobob@demisto.com | 2019-10-17T13:41:48.487521161Z | Demisto | private | 5a4440f2b9ce60b070e98c304370050446a2efa4b3850550a99e4d7b8f447fcc |


### cs-falcon-run-script
---
Runs a script on the agent host.
##### Base Command

`cs-falcon-run-script`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_ids | A comma separated list of host agent ID’s for which to run commands (can be retrieved by running cs-falcon-search-device command). | Required | 
| script_name | The name of the script to run. | Optional | 
| raw | The PowerShell script code to run. | Optional | 

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CrowdStrike.Command.HostID | string | The ID of the host for which the command was running. | 
| CrowdStrike.Command.Stdout | string | The standard output of the command. | 
| CrowdStrike.Command.Stderr | string | The standard error of the command. | 
| CrowdStrike.Command.BaseCommand | string | The base command. | 
| CrowdStrike.Command.FullCommand | string | The full command. | 


##### Command Example
`cs-falcon-run-script host_ids=284771ee197e422d5176d6634a62b934 raw="Write-Output 'Hello, World!"`

##### Context Example
```
{
    'CrowdStrike': {
        'Command': [{
            'HostID': '284771ee197e422d5176d6634a62b934',
                'Stdout': 'Hello, World!',
                'Stderr': '',
                'BaseCommand': 'runscript',
                'Command': "runscript -Raw=Write-Output 'Hello, World!"
        }]
}
```

##### Human Readable Output
### Command runscript -Raw=Write-Output 'Hello, World! results
|BaseCommand|Command|HostID|Stderr|Stdout|
|---|---|---|---|---|
| runscript | runscript -Raw=Write-Output 'Hello, World! | 284771ee197e422d5176d6634a62b934 |  | Hello, World! |                                    Type         Size (bytes)    Size (MB)       Last Modified (UTC-5)     Created (UTC-5)          <br>----                                     ----         ------------    ---------       ---------------------     ---------------          <br>$Recycle.Bin                             <Directory>  --              --              11/27/2018 10:54:44 AM    9/15/2017 3:33:40 AM     <br>ITAYDI                                   <Directory>  --              --              11/19/2018 1:31:42 PM     11/19/2018 1:31:42 PM     |
