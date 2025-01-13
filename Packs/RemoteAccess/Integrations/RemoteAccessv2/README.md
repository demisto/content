This integration transfers files between Cortex XSOAR and a remote machine and executes commands on the remote machine.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration---remoteaccess-v2).

**Note:** This integration was integrated and tested on a remote machine with Centos-7 operating system. It does not work with Windows operation system.

## Configure RemoteAccess v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Default Hostname or IP Address | If not provided, "host" or "system" should be provided in the command's arguments. | False |
| User | For example, "root". | False |
| Password | The password of the remote machine. | False |
| sshKey | The private RSA key used to authenticate with the remote machine should be configured in the *Credentials* tab under *Settings > Integrations > Credentials*. See [here](https://xsoar.pan.dev/docs/reference/articles/managing-credentials) for more information. | False
| Additional Password | Requires an additional password as an argument to run any command of this module. | False |
| Ciphers | A comma-separated list of ciphers to use. If none of the specified ciphers are agreed to by the server, an error message specifying the supported ciphers is returned. | False |
| Key Algorithms | A comma-separated list of key algorithms to use. If none of the specified key algorithms are agreed to by the server, an error message specifying the supported key algorithms is returned. | False |


## Configure SSH From Remote
For login using root:
1. Edit the /etc/ssh/sshd_config file.
- set `PermitRootLogin` to `yes`
- set `PasswordAuthentication` to `yes`
2. Restart the sshd server: `service sshd restart`

## Configure the instance with SSH certificate
Currently, the only type of certificate that is supported is RSA private keys (.PEM) files.
In case access is required to an instance in the cloud, use the PEM file provided by the cloud provider.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ssh
***
Run the specified command on the remote system with SSH.


#### Base Command

`ssh`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                    | **Required** |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| cmd | Command to run on the remote machine. To combine commands and run them in a single SSH session, concatenate them using semicolons (;) e.g., 'echo 1;echo 2'. | Required | 
| additional_password | Password required to match the Additional Password parameter if it was supplied to run the command.                                                                                                | Optional | 
| timeout | Timeout for command in seconds.                                                                                                                                                                    | Optional | 
| system | System to run the command on.                                                                                                                                                                      | Optional | 
| host | Host name to run the command on.                                                                                                                                                                   | Optional | 
| port | Port to run the command on.                                                                                                                                                                        | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RemoteAccess.Command.output | String | Standard output of the specified command. | 
| RemoteAccess.Command.error | String | Standard error output of the specified command. | 
| RemoteAccess.Command.success | Boolean | Whether the operation was successful. | 
| RemoteAccess.Command.command | String | Command that was run. | 


#### Command Example
```!ssh command="echo test"```

#### Context Example
```json
{
    "RemoteAccess": {
        "Command": [
            {
                "command": "echo test",
                "error": "",
                "output": "test\n",
                "success": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Command echo test Outputs
>|command|output|success|
>|---|---|---|
>| echo test | test<br/> | true |


### copy-to
***
Copies the given file from Cortex XSOAR to the remote machine.



#### Base Command

`copy-to`
#### Input

| **Argument Name**   | **Description**                                                                                                                                                                                                                                   | **Required** |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entry_id            | Entry ID of the file to be copied from Cortex XSOAR to the remote machine.                                                                                                                                                                        | Optional     | 
| destination_path    | Destination of the path of the copied file in the remote machine. Defaults to the `entry_id` file name if not specified.                                                                                                                          | Optional     | 
| additional_password | Password. Required to match the Additional Password parameter if it was supplied in order to run the command.                                                                                                                                     | Optional     | 
| timeout             | Timeout for command in seconds. Default is 10.0 seconds.                                                                                                                                                                                         | Optional     |
| dest-dir            | Destination of the directory to copy the file to in the remote machine. The file name of the `entry_id` will be used as the file name in the destination directory. Creates the destination directory in the remote machine if it does not exist. | Optional     | 
| entry               | This input is deprecated. Please use the `entry_id` input instead.                                                                                                                                                                                | Optional     | 
| system              | System to run the command on. | Optional | 
| host                | Host name to run the command on. | Optional | 
| port                | Port to run the command on. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!copy-to entry_id=104@49493d71-eef6-4bb4-8075-4be38d9bc340 destination_path="test/cortex_copied_file"```

#### Human Readable Output

>### The file corresponding to entry ID: 104@49493d71-eef6-4bb4-8075-4be38d9bc340 was copied to remote host.

### copy-from
***
Copies the given file from the remote machine to Cortex XSOAR.


#### Base Command

`copy-from`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                    | **Required** |
| --- |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| file_path | Path of the file in the remote machine to be copied to Cortex XSOAR.                                                                                                               | Optional     | 
| file_name | Name of the file to be copied to Cortex XSOAR. Defaults to the file name in `file_path` if not specified. For example, if `file_path` is "a/b/c.txt", the file name will be c.txt. | Optional     | 
| additional_password | Password required to match the Additional Password parameter if it was supplied to run the command.                                                                      | Optional     | 
| timeout | Timeout for command, in seconds. Default is 10.0 seconds.                                                                                                                          | Optional     |
| file | This input is deprecated. Please use the `file_path` input instead.                                                                                                                | Optional     | 
| system | System to run the command on. | Optional | 
| host | Host name to run the command on. | Optional | 
| port | Port to run the command on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 


#### Command Example
```!copy-from file_path="test/remote_file.txt" file_name="CopiedRemoteFile"```

#### Context Example
```json
{
    "File": {
        "EntryID": "165@49493d71-eef6-4bb4-8075-4be38d9bc340",
        "Info": "text/plain",
        "MD5": "c5253b90e791d18439a84511c382616b",
        "Name": "CopiedRemoteFile",
        "SHA1": "98c94e6e64b7a52576870fc07a0da5f33243c505",
        "SHA256": "bf98cd7cda320c300218397d9ee1df263415aac7f0f41c8f57dee7944e68fba0",
        "SHA512": "6f2199d786a13c7b8cd6d268166a26f4423d4aa1e4ba59565e9130da01555d83d190870dade6098fe7992425e0d2d9128841b92f419dbf4193a6112c4cf7264f",
        "SSDeep": "3:9bLbEin:6i",
        "Size": 16,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Human Readable Output



## Breaking changes from the previous version of this integration - RemoteAccess v2
- Removed the *Interactive terminal mode* instance parameter.
- Removed the *Terminal Type* instance parameter.

### Commands
### Arguments
#### The following argument names were changed, added, or removed in this version
| Remote Access Command Name | Old Command Argument Name | New Command Name |
| --- | --- | --- |
| copy-to | fileID | **Argument was removed** |
| copy-from | **Argument did not exist** | file_name |

### Outputs
#### The following outputs were removed in this version:
| Remote Access Command Name | Old Command Outputs | Remote Access v2 Command Name | New Command Outputs |
| --- | --- | --- | --- |
| ssh | Command outputs were: <br /> - command<br /> - stdout<br /> -  stderr<br /> - remote machine IP<br /> - success status | ssh | Outputs: <br /> - stdout<br /> - stderr  |