VMware Carbon Black Endpoint Standard Live Response is a feature that’s allows security operators to collect information and take action on remote endpoints in real time, These actions include the ability to upload, download, and remove files, retrieve and remove registry entries, dump contents of physical memory, execute and terminate processes.
This integration was integrated and tested with version xx of CarbonBlackLiveResponseCloud
## Configure CarbonBlackLiveResponseCloud on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CarbonBlackLiveResponseCloud.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL | The URL used to access the Carbon Black Cloud | True |
    | Custom Key | The Custom Key to use for connection | True |
    | Custom Id | The Custom Id to use for connection | True |
    | Organization Key | The Organization Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cbd-lr-file-put
***
Create a new file on the remote machine with the specified data


#### Base Command

`cbd-lr-file-put`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| destination_path | File path to create on the remote endpoint. | Required | 
| file_id | The file entry id in the War Room. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-lr-file-put sensor_id="the actually sensor id" destination_path="C:\test\test.txt" file_id=142@5```

#### Human Readable Output

>File: 142@5 is successfully put to the remote destination C:\test\test_file.txt


### cbd-lr-file-get
***
Retrieve contents of the specified file on the remote machine


#### Base Command

`cbd-lr-file-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| source_path | Path of the file to be retrieved. | Required | 
| timeout | Timeout for the operation. | Optional | 
| delay | Delay in seconds to wait before command complete. | Optional | 


#### Context Output
```json
{
    "File": {
        "EntryID": "260@3c9bd2a0-9eac-465b-8799-459df4997b2d",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "db7375b2e67da548049e0a5e500b41eb",
        "Name": "test_file.txt",
        "SHA1": "36017cdf63594765ea755c65765702522ca2031c",
        "SHA256": "9dc4d8e2cf56b9d8ec0a074151eb2a97fff3f2d633ccc166d9f8fa3e489fac8a",
        "SHA512": "6b2390577ca26841d66aa9d9a3faadbb9921fefef49d9eae4f68851014e780578eb17d6443415ea1e592572701e42aac4141e09334a425c8bc6a1f5792a98c4f",
        "SSDeep": "3:H0sKFQO:HKSO",
        "Size": 17,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Command Example
``` !cbd-lr-file-get sensor_id="the actually sensor id" source_path="C:\\test\\test_file.txt" delay=2 timeout=30```

#### Human Readable Output



### cbd-lr-file-delete
***
Delete the specified file name on the remote machine


#### Base Command

`cbd-lr-file-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| source_path | Path of the file to be deleted. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-lr-file-delete sensor_id="the actually sensor id" source_path="C:\test\test_file.txt"```

#### Human Readable Output

>The file: C:\test\test_file.txt was deleted successfully.

### cbd-lr-directory-listing
***
List the contents of a directory on the remote machine


#### Base Command

`cbd-lr-directory-listing`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| directory_path | Directory to list. This parameter should end with the path separator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefenseLR.Directory.content | Data | list of dicts, each one describing a directory entry | 
| CarbonBlackDefenseLR.Directory.sensor_id | String | The sensor \(endpoint\) id | 


#### Command Example
```!cbd-lr-directory-listing sensor_id="the actually sensor id" directory_path="C:\test\"```

#### Context Example
```json
{
    "CarbonBlackDefenseLR": {
        "Directory": {
            "content": [
                {
                    "alternate_name": "",
                    "attributes": [
                        "DIRECTORY"
                    ],
                    "create_time": 1616331959,
                    "filename": ".",
                    "last_access_time": 1619593780,
                    "last_write_time": 1619593761,
                    "size": 0
                },
                {
                    "alternate_name": "",
                    "attributes": [
                        "DIRECTORY"
                    ],
                    "create_time": 1616331959,
                    "filename": "..",
                    "last_access_time": 1619593780,
                    "last_write_time": 1619593761,
                    "size": 0
                },
                {
                    "alternate_name": "A_TEST~1.EXE",
                    "attributes": [
                        "ARCHIVE"
                    ],
                    "create_time": 1619532122,
                    "filename": "a_test_process.exe",
                    "last_access_time": 1619532122,
                    "last_write_time": 1618464943,
                    "size": 839112
                },
                {
                    "alternate_name": "MEMDUM~1",
                    "attributes": [
                        "DIRECTORY"
                    ],
                    "create_time": 1618324107,
                    "filename": "memdump_test",
                    "last_access_time": 1619532952,
                    "last_write_time": 1619532951,
                    "size": 0
                }
            ],
            "sensor_id": "the actually sensor id"
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Live Response Directory content
>|Name|Type|Date Modified|Size|
>|---|---|---|---|
>| . | Directory | 1970-01-19T17:53:20.000Z | 0 |
>| .. | Directory | 1970-01-19T17:53:20.000Z | 0 |
>| a_test_process.exe | File | 1970-01-19T17:34:24.000Z | 839112 |
>| memdump_test | Directory | 1970-01-19T17:52:12.000Z | 0 |


### cbd-lr-reg-sub-keys
***
Enumerate subkeys of the specified registry key on the remote machine


#### Base Command

`cbd-lr-reg-sub-keys`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| reg_path | The registry key to enumerate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefenseLR.RegistrySubKeys.key | String | The parent registry key | 
| CarbonBlackDefenseLR.RegistrySubKeys.sub_keys | Data | The sub keys | 
| CarbonBlackDefenseLR.RegistrySubKeys.sensor_id | String | The sensor \(endpoint\) id | 


#### Command Example
```!cbd-lr-reg-sub-keys reg_path=HKEY_LOCAL_MACHINE\SOFTWARE\TEST sensor_id="the actually sensor id"```

#### Human Readable Output

>The key: HKEY_LOCAL_MACHINE\SOFTWARE\TEST does not contain any sub keys

### cbd-lr-reg-get-values
***
Enumerate all registry values from the specified registry key on the remote machine


#### Base Command

`cbd-lr-reg-get-values`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| reg_path | The registry key to enumerate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefenseLR.RegistryValues.key | String | The registry key | 
| CarbonBlackDefenseLR.RegistryValues.values | Data | The registry values of the given key | 
| CarbonBlackDefenseLR.RegistryValues.sensor_id | String | The sensor \(endpoint\) id | 


#### Command Example
```!cbd-lr-reg-get-values reg_path=HKEY_LOCAL_MACHINE\SOFTWARE\TEST sensor_id="the actually sensor id"```

#### Context Example
```json
{
    "CarbonBlackDefenseLR": {
        "RegistryValues": {
            "key": "HKEY_LOCAL_MACHINE\SOFTWARE\TEST",
            "sensor_id": "the actually sensor id",
            "values": [
                {
                    "value_data": "val_1,val_2",
                    "value_name": "TEST_VAL",
                    "value_type": "pbREG_MULTI_SZ"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Live Response Registry key values
>|Name|Type|Data|
>|---|---|---|
>| TEST_VAL | pbREG_MULTI_SZ | val_1,val_2 |


### cbd-lr-reg-key-create
***
Create a new registry key on the remote machine


#### Base Command

`cbd-lr-reg-key-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| reg_path | The registry key to create. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-lr-reg-key-create sensor_id="the actually sensor id" reg_path=HKEY_LOCAL_MACHINE\SOFTWARE\TEST```

#### Human Readable Output

>Reg key: HKEY_LOCAL_MACHINE\SOFTWARE\TEST, was created successfully.

### cbd-lr-reg-key-delete
***
Delete a registry key on the remote machine, the key must be without any sub keys


#### Base Command

`cbd-lr-reg-key-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| reg_path | The registry key to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-lr-reg-key-delete reg_path=HKEY_LOCAL_MACHINE\SOFTWARE\TEST sensor_id="the actually sensor id"```

#### Human Readable Output

>Registry key: HKEY_LOCAL_MACHINE\SOFTWARE\TEST was deleted successfully.

### cbd-lr-reg-value-delete
***
Delete a registry value on the remote machine


#### Base Command

`cbd-lr-reg-value-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| reg_path | The registry value to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-lr-reg-value-delete sensor_id="the actually sensor id" reg_path=HKEY_LOCAL_MACHINE\SOFTWARE\TEST\TEST_VAL```

#### Human Readable Output

>Registry value: HKEY_LOCAL_MACHINE\SOFTWARE\TEST\TEST_VAL was deleted successfully.

### cbd-lr-reg-value-set
***
Set a registry value on the specified registry key on the remote machine


#### Base Command

`cbd-lr-reg-value-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| reg_path | The path of the key + the path of the value e.g. HKLM\SYSTEM\CurrentControlSet\services\ACPI\testvalue. | Required | 
| value_data | The value data. | Required | 
| value_type | The type of value. Examples: REG_DWORD, REG_MULTI_SZ, REG_SZ. Possible values are: REG_BINARY, REG_DWORD, REG_QWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ, REG_SZ. | Required | 
| overwrite | If True, any existing value will be overwritten. Default is True. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-lr-reg-value-set reg_path=HKEY_LOCAL_MACHINE\SOFTWARE\TEST\TEST_VAL sensor_id="the actually sensor id" value_data=[\"val_1\",\"val_2\"] value_type=REG_MULTI_SZ```

#### Human Readable Output

>Value was set to the reg key: HKEY_LOCAL_MACHINE\SOFTWARE\TEST\TEST_VAL successfully.

### cbd-lr-ps
***
List currently running processes on the remote machine


#### Base Command

`cbd-lr-ps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefenseLR.Processes.processes | String | A list of dicts describing the processes | 
| CarbonBlackDefenseLR.Processes.sensor_id | String | The sensor \(endpoint\) id | 


#### Command Example
```!cbd-lr-ps sensor_id="the actually sensor id"```

#### Context Example
```json
{
    "CarbonBlackDefenseLR": {
        "Processes": {
            "processes": [
                {
                    "command_line": "",
                    "create_time": 132629811990478,
                    "parent": 0,
                    "parent_create_time": 0,
                    "path": "SYSTEM",
                    "pid": 4,
                    "sid": "S-1-5-18",
                    "username": "NT AUTHORITY\SYSTEM"
                },
                {
                    "command_line": "",
                    "create_time": 132629811918118,
                    "parent": 4,
                    "parent_create_time": 132629811990478850,
                    "path": "Registry",
                    "pid": 84,
                    "sid": "S-1-5-18",
                    "username": "NT AUTHORITY\SYSTEM"
                },
                {
                    "command_line": "\SystemRoot\System32\smss.exe",
                    "create_time": 132629811991336,
                    "parent": 4,
                    "parent_create_time": 132629811990478850,
                    "path": "c:\windows\system32\smss.exe",
                    "pid": 308,
                    "sid": "S-1-5-18",
                    "username": "NT AUTHORITY\SYSTEM"
                }
            ],
            "sensor_id": "the actually sensor id"
        }
    }
}
```

#### Human Readable Output

>### Carbon Black Defense Live Response Processes
>|Path|Pid|Command Line|
>|---|---|---|
>| SYSTEM | 4 |  |
>| Registry | 84 |  |
>| c:\windows\system32\smss.exe | 308 | \SystemRoot\System32\smss.exe |
>| c:\windows\system32\wininit.exe | 504 | wininit.exe |


### cbd-lr-kill
***
Terminate a process on the remote machine


#### Base Command

`cbd-lr-kill`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| pid | Process ID to be terminated. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-lr-kill pid=4592 sensor_id="the actually sensor id" ```

#### Human Readable Output

>The process: 4592 was killed successfully.


### cbd-lr-execute
***
Create a new process on the remote machine with the specified command string


#### Base Command

`cbd-lr-execute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| command_string | Command string used for the create process operation. | Required | 
| wait_for_output |  True to block on output from the new process (execute in foreground). This will also set wait_for_completion (below). Default is True. | Optional | 
| working_directory | The working directory of the create process operation. | Optional | 
| remote_output_file_name | The remote output file name used for process output. | Optional | 
| wait_timeout | Timeout used for this command. Default is 30. | Optional | 
| wait_for_completion | True to wait until the process is completed before returning. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CarbonBlackDefenseLR.ExecuteProcess.return_value | String | The output of the process | 
| CarbonBlackDefenseLR.ExecuteProcess.sensor_id | String | The sensor \(endpoint\) id | 


#### Command Example
```!cbd-lr-execute sensor_id="the actually sensor id" command_string="cmd.exe"```

#### Human Readable Output

>### Carbon Black Defense Live Response Process Execution Result
>|Process output|
>|---|
>| actually process output|

### cbd-lr-memdump
***
Perform a memory dump operation on the remote machine


#### Base Command

`cbd-lr-memdump`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sensor_id | The sensor (endpoint) id. | Required | 
| target_path | Path of the file the memory dump will be stored in on the remote machine. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!cbd-lr-memdump sensor_id="the actually sensor id" target_path=C:\test\memdump\dumped_file```

#### Human Readable Output

>Memory was successfully dumped to C:\test\memdump\dumped_file.
