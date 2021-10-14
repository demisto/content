[Enter a comprehensive, yet concise, description of what the integration does, what use cases it is designed for, etc.]
This integration enables Cortex XSOAR to access and run commands on a terminal in a remote location (via SSH).

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-remoteaccessv2).

## Configure RemoteAccessV2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for RemoteAccessV2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Default Hostname Or IP Address |  | True |
    | Ciphers | Comma separated list of ciphers to be used. Will return error with the supported ciphers by server if none of given ciphers were agreed by server. | False |
    | User | For example, "root". | False |
    | Password |  | False |
    | Interactive Terminal Mode | TODO | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### remote-access-ssh
***
Run command on remote system with ssh


#### Base Command

`remote-access-ssh`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| command | Command to run on remote machine. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RemoteAccess.Command.stdout | String | STD output of the given command. | 
| RemoteAccess.Command.std_error | String | STD error output of the given command. | 


#### Command Example
```!remote-access-ssh command=`echo test````

#### Context Example
```json
{
    "RemoteAccess": {
        "Command": [
            {
                "std_error": "",
                "stdout": "test\n"
            }
        ]
    }
}
```

#### Human Readable Output

>### Command echo test Outputs
>|std_error|stdout|
>|---|---|
>|  | test<br/> |


### remote-access-copy-to
***
Run command on remote system with ssh


#### Base Command

`remote-access-copy-to`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file to be copied from Cortex XSOAR to remote machine. | Required | 
| destination_path | Destination of the path of the copied file in the remote machine. Defaults to the `entry_id` file path if not given. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!remote-access-copy-to entry_id=104@49493d71-eef6-4bb4-8075-4be38d9bc340 destination_path="test/cortex_copied_file"```

#### Human Readable Output

>### The file corresponding to entry ID: 104@49493d71-eef6-4bb4-8075-4be38d9bc340 was copied to remote host.

### remote-access-copy-from
***
Run command on remote system with ssh


#### Base Command

`remote-access-copy-from`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | Path of the file in remote machine to be copied to Cortex XSOAR. | Required | 
| file_name | Name of the file to be saved in Cortex XSOAR. Defaults to the file name in `file_path` if not given. E.g, if `file_path` is "a/b/c.txt", the file name will be c.txt. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
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
```!remote-access-copy-from file_path="test/remote_file.txt" file_name="CopiedRemoteFile"```

#### Context Example
```json
{
    "File": {
        "EntryID": "124@49493d71-eef6-4bb4-8075-4be38d9bc340",
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



## Breaking changes from the previous version of this integration - RemoteAccessV2
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
