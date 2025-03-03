Files and Directories management with an SMB server. Supports SMB2 and SMB3 protocols.

## Configure Server Message Block (SMB) v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server IP / Hostname (e.g. 1.2.3.4) |  | False |
| Port |  | False |
| Domain Controller | The domain controller hostname. This is useful for environments with DFS servers as it is used to identify the DFS domain information automatically. | False |
| Username |  | False |
| Client GUID | The client machine name to identify the client to the server on a new connection. | False |
| Force Encryption | Force encryption on the connection, requires SMBv3 or newer on the remote server. Default is "false". | False |
| Secure Dialect Negotiation | Validate the negotiation info when connecting to a share. More information can be found on https://docs.microsoft.com/en-us/archive/blogs/openspecification/smb3-secure-dialect-negotiation | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### smb-download
***
Downloads a file from the server.


#### Base Command

`smb-download`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | The path to the file, starting from the share, for example: Share/Folder/File. This field is case-insensitive. | Required | 
| hostname | Server IP address / hostname.  If empty, the hostname from the instance configuration is used. | Optional | 
| username | The username to use when creating a new SMB session. If empty, the username from the instance configuration is used. | Optional | 
| password | The password to use for authentication. If empty, the password from the instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | number | File size. | 
| File.SHA1 | string | SHA1 hash of the file. | 
| File.SHA256 | string | SHA256 hash of the file. | 
| File.Name | string | File name. | 
| File.SSDeep | string | SSDeep hash of the file. | 
| File.EntryID | string | File entry ID. | 
| File.Info | string | Information about the file. | 
| File.Type | string | File type. | 
| File.MD5 | string | MD5 hash of the file. | 


#### Command Example
```!smb-download file_path=Shared/Tests/Test.txt```

#### Context Example
```json
{
    "File": {
        "EntryID": "2837@51c113de-6213-4aea-8beb-d4b88551f7f8",
        "Extension": "txt",
        "Info": "text/plain; charset=utf-8",
        "MD5": "ce114e4501d2f4e2dcea3e17b546f339",
        "Name": "Test.txt",
        "SHA1": "a54d88e06612d820bc3be72877c74f257b561b19",
        "SHA256": "c7be1ed902fb8dd4d48997c6452f5d7e509fbcdbe2808b16bcf4edce4c07d14e",
        "SHA512": "a028d4f74b602ba45eb0a93c9a4677240dcf281a1a9322f183bd32f0bed82ec72de9c3957b2f4c9a1ccf7ed14f85d73498df38017e703d47ebb9f0b3bf116f69",
        "SSDeep": "3:hMCEpn:hup",
        "Size": 14,
        "Type": "ASCII text, with no line terminators"
    }
}
```

#### Human Readable Output



### smb-upload
***
Uploads a file to the server.


#### Base Command

`smb-upload`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | The path to the file, starting from the share, for example: Share/Folder/File. This field is case-insensitive. | Required | 
| hostname | Server IP address / hostname.  If empty, the hostname from the instance configuration is used. | Optional | 
| username | The username to use when creating a new SMB session. If empty, the username from the instance configuration is used. | Optional | 
| password | The password to use for authentication. If empty, the password from the instance configuration is used. | Optional | 
| entryID | EntryID of the file to send to the share. | Optional | 
| content | File content to send to the share. Ignored if EntryID argument is specified. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!smb-upload file_path=Shared/Tests/Test.txt content="This is a test"```

#### Human Readable Output

>File Test.txt was uploaded successfully

### smb-directory-list
***
Returns a list containing the names of the entries in the directory given by path.


#### Base Command

`smb-directory-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The path to the directory, starting from the share, for example: Share/Folder. This field is case-insensitive. | Required | 
| hostname | Server IP address / hostname.  If empty, the hostname from the instance configuration is used. | Optional | 
| username | The username to use when creating a new SMB session. If empty, the username from the instance configuration is used. | Optional | 
| password | The password to use for authentication. If empty, the password from the instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SMB.Path.SharedFolder | String | The full path of the shared folder. | 
| SMB.Path.Files | Unknown | List of files under the shared folder. | 
| SMB.Path.Directories | Unknown | List of directories under the shared folder. | 


#### Command Example
```!smb-directory-list path=Shared```

#### Context Example
```json
{
    "SMB": {
        "Path": {
            "Directories": [
                "Tests"
            ],
            "Files": [
                "123.txt",
                "test.jpg"
            ],
            "SharedFolder": "127.0.0.1/Shared"
        }
    }
}
```

#### Human Readable Output

>### List Of Entries for 127.0.0.1/Shared
>|Directories|Files|SharedFolder|
>|---|---|---|
>| Tests | 123.txt,<br/>test.jpg | 127.0.0.1/Shared |


### smb-file-remove
***
Removes a file from the server.


#### Base Command

`smb-file-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | The path to the file, starting from the share, for example: Share/Folder/File. This field is case-insensitive. | Required | 
| hostname | Server IP address / hostname. If empty, the hostname from the instance configuration is used. | Optional | 
| username | The username to use when creating a new SMB session. If empty, the username from the instance configuration is used. | Optional | 
| password | The password to use for authentication. If empty, the password from the instance configuration is used. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!smb-file-remove file_path=Shared/Tests/Test.txt```

#### Human Readable Output

>File Test.txt was deleted successfully

### smb-directory-create
***
Creates a new directory under the given path.


#### Base Command

`smb-directory-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The path to the directory, starting from the share, for example: Share/NewFolder. This field is case-insensitive. | Required | 
| hostname | Server IP address / hostname. If empty, the hostname from the instance configuration is used. | Optional | 
| username | The username to use when creating a new SMB session. If empty, the username from the instance configuration is used. | Optional | 
| password | The password to use for authentication. If empty, the password from the instance configuration is used. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!smb-directory-create path=Shared/Tests```

#### Human Readable Output

>Directory: 127.0.0.1/Shared/Tests was created successfully

### smb-directory-remove
***
Removes a directory from the given path.


#### Base Command

`smb-directory-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The path to the directory, starting from the share, for example: Share/NewFolder. This field is case-insensitive. | Required | 
| hostname | Server IP address / hostname. If empty, the hostname from the instance configuration is used. | Optional | 
| username | The username to use when creating a new SMB session. If empty, the username from the instance configuration is used. | Optional | 
| password | The password to use for authentication. If empty, the password from the instance configuration is used. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!smb-directory-remove path=Shared/Tests```

#### Human Readable Output

>Directory: 127.0.0.1/Shared/Tests was removed successfully