PowerShell Remoting is a comprehensive built-in remoting subsystem that is a part of Microsoft's native Windows management framework (WMF) and Windows remote management (WinRM).
This feature allows you to handle most remoting tasks in any configuration you might encounter by creating a remote PowerShell session to Windows hosts and executing commands in the created session.
The integration includes out-of-the-box commands which supports agentless forensics for remote hosts.

For more information about setting up PowerShell Remoting, see the [PowerShell Remoting - Configuration guide](https://xsoar.pan.dev/docs/reference/articles/Powershell_Remoting_-_Configuration).

## Configure PowerShell Remoting in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Domain | Fully Qualified Domain Name suffix to be added to the hostname. For example mydomain.local | False |
| DNS | The IP address of the DNS server the integration will use to resolve your hosts. | False | 
| Username | Username in the target machine. This can be a local or domain user with administrative privileges | True |
| Password |  | True |
| Test Host | Hostname or IP address to use as a test for the integration connectivity. | False |
| Authentication Method |  | True |
| Trust any certificate (not secure) |  | False |
| Use SSL (HTTPS) |  | False |

### Configuration Notes
Please note that in order for the integration to function properly, *Basic Authentication* is required to be enabled for the target host. This is due to the library relying on Basic Auth headers to pass an authentication token even when MFA is enabled.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ps-remote-command
***
Executes remote PowerShell commands on a single host.


#### Base Command

`ps-remote-command`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | A single hostname or IP address on which to run the command. | Required | 
| command | PowerShell commands (can be single or multiple in order of execution) to run on the target machine. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PsRemote.Host | string | The host on which the command was invoked. | 
| PsRemote.FQDN | string | The Fully Qualified Domain Name of the host on which the command was invoked. | 
| PsRemote.CommandResult | list | The result of the command run from the target machine. | 
| PsRemote.CommandName | string | The command sent to the target machine, used as an ID of that query. | 
| PsRemote.UTCTime | string | Time the command finished execution in UTC time. | 


#### Command Example
```!ps-remote-command host=XSOAR-XSOAR command=whoami```

#### Context Example
```json
{
    "PsRemote": {
        "UTCTime": "2021-07-18T15:46:07.2006094+00:00", 
        "FQDN": "XSOAR-XSOAR.winrm.local", 
        "Host": "XSOAR-XSOAR", 
        "CommandName": "whoami", 
        "CommandResult": [
            "winrm\\administrator\n"
        ]
    }
}
```
#### Human Readable Output
> Result for PowerShell Remote Command: whoami
> winrm\administrator


### ps-remote-download-file
***
Downloads a file from the remote endpoint.


#### Base Command

`ps-remote-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | Hostname or the IP address on which to run the command. | Required | 
| path | The path of the file to download. | Required | 
| zip_file | Whether to compress the file. Possible values: "true" and "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 
| check_hash | Whether to compare the value of the original file with the downloaded file and return an error if any differences are found. Possible values: "true" and "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 
| host_prefix | Whether to use the host as a prefix for the name of the downloaded version of the file. Possible values: "true" and "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PsRemoteDownloadedFile.Host | string | The host from which the file was downloaded. | 
| PsRemoteDownloadedFile.FQDN | string | The Fully Qualified Domain Name of the host from which the file was downloaded. | 
| PsRemoteDownloadedFile.FileName | String | File name. | 
| PsRemoteDownloadedFile.FileSize | Number | File size. | 
| PsRemoteDownloadedFile.FileMD5 | String | The MD5 hash of the file. | 
| PsRemoteDownloadedFile.FileSHA1 | String | The SHA1 hash of the file. | 
| PsRemoteDownloadedFile.FileSHA256 | String | The SHA256 hash of the file. | 
| PsRemoteDownloadedFile.FileExtension | String | The extension of the file. | 
| File.Size | Number | The size of the file in bytes. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The full file name. | 
| File.SSDeep | String | The ssdeep hash of the file. | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Info | String | The file information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension, for example: "txt". | 


#### Command Example
```!ps-remote-download-file host="XSOAR-XSOAR" path="c:\\XSOAR-XSOAR.etl" zip_file="true" check_hash="true" host_prefix="true"```


### ps-remote-upload-file
***
Uploads a file to the remote endpoint.


#### Base Command

`ps-remote-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | A single hostname or IP address on which to run the command. | Required | 
| path | The path of the file to upload. | Required | 
| entry_id | The file entry ID to upload. | Required | 
| zip_file | Whether to compress the file before upload. Possible values: "true" and "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 
| check_hash | Whether to compare the values of the original file and uploaded file and return an error if any differences are found. Possible values: "true" and "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PsRemoteUploadedFile.FileName | String | File name. | 
| PsRemoteUploadedFile.FilePath | String | File path in the remote server. | 
| PsRemoteUploadedFile.FileSize | Number | File size. | 
| PsRemoteUploadedFile.FileMD5 | String | The MD5 hash of the file. | 
| PsRemoteUploadedFile.FileSHA1 | String | The SHA1 hash of the file. | 
| PsRemoteUploadedFile.FileSHA256 | String | The SHA256 hash of the file. | 
| PsRemoteUploadedFile.FileExtension | String | The extension of the file. | 
| PsRemoteUploadedFile.Host | string | The host to which the file was uploaded. | 
| PsRemote.FQDN | string | The Fully Qualified Domain Name of the host the file was uploaded to. | 


#### Command Example
```!ps-remote-upload-file entry_id=105@1d0796aa-dde9-4f18-8f04-bbe92434ba81 host="XSOAR-XSOAR" path="c:\\tmpetl.etl"```


#### Human Readable Output
> File 1d0796aa-dde9-4f18-8f04-bbe92434ba81_105@1d0796aa-dde9-4f18-8f04-bbe92434ba81 was uploaded successfully as: c:\tmpetl.etl

### ps-remote-etl-create-start
***
This command starts the recording of an ETL file on a Windows endpoint. An ETL file is just like a PCAP file which is created by the Windows Netsh command.


#### Base Command

`ps-remote-etl-create-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | A single hostname or IP address on which to run the command. | Required | 
| etl_path | The path on the hostname on which to create the ETL file. For example c:\temp\myhost.etl. Default is "C:\Users\&lt;username&gt;\AppData\Local\Temp\NetTraces\NetTrace.etl". | Required | 
| etl_filter | The filter to apply when creating the ETL file. For example IPv4.Address=1.1.1.1 to capture traffic just from the 1.1.1.1 IP address. If no filter is specified all traffic will be recorded. For more examples, see: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj129382(v=ws.11)#using-filters-to-limit-etl-trace-file-details. | Optional | 
| etl_max_size | The maximum file size for the ETL. Once the file has reached this size, the capture will stop. For example 10MB. The default size is 10MB. Default is 10. | Optional | 
| overwrite | Whether to overwrite the file in the path. Possible values: "yes" and "no". Default is "no". Possible values are: yes, no. Default is no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PsRemote.CommandResult | string | The start ETL command results. | 
| PsRemote.EtlFileName | string | The name of the ETL file. | 
| PsRemote.EtlFilePath | unknown | The path and name of the ETL file. | 
| PsRemote.CommandName | string | The name of the command that ran on the host. | 
| PsRemote.FQDN | string | The Full Qualified Domain Name of the host. | 
| PsRemote.Host | string | The name of the host. | 


#### Command Example
```!ps-remote-etl-create-stop host="XSOAR-XSOAR"```

#### Human Readable Output
> Trace configuration: ------------------------------------------------------------------- Status:             Running Trace File:         C:\XSOAR-XSOAR__a.etl Append:             Off Circular:           On Max Size:           10 MB Report:             Off

#### Context Example
```python
{
    "PsRemote": {
        "CommandResult": [
            "Trace configuration:\n", 
            "-------------------------------------------------------------------\n", 
            "Status:             Running\n", 
            "Trace File:         C:\\XSOAR-XSOAR__a.etl\n", 
            "Append:             Off\n", 
            "Circular:           On\n", 
            "Max Size:           10 MB\n", 
            "Report:             Off\n"
        ], 
        "FQDN": "XSOAR-XSOAR.winrm.local", 
        "EtlFilePath": "c:\\XSOAR-XSOAR__a.etl", 
        "UTCTime": "2021-07-18T15:58:08.2528721+00:00", 
        "Host": "XSOAR-XSOAR", 
        "CommandName": "netsh trace start capture=yes traceFile=c:\\XSOAR-XSOAR__a.etl maxsize=10 overwrite=no ", 
        "EtlFileName": "XSOAR-XSOAR__a.etl"
    }
}
```

### ps-remote-etl-create-stop
***
Ends the recording of an ETL file on a Windows endpoint.


#### Base Command

`ps-remote-etl-create-stop`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | A single Hostname or IP address on which to run the command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PsRemote.CommandResult | string | The stop ETL command results. | 
| PsRemote.CommandName | string | The name of the command that ran on the host. | 
| PsRemote.EtlFileName | string | The name of the ETL file. | 
| PsRemote.EtlFilePath | unknown | The path and name of the ETL file. | 
| PsRemote.Host | string | The host the command was invoked on. | 
| PsRemote.FQDN | string | The Fully Qualified Domain Name of the host on which the command was invoked. | 


#### Command Example
```!ps-remote-etl-create-stop host="XSOAR-XSOAR"```

#### Human Readable Output
> Correlating traces … done Merging traces … done Generating data collection … done The trace file and additional troubleshooting information have been compiled as "c:\XSOAR-XSOAR__a.cab". File location = c:\XSOAR-XSOAR__a.etl Tracing session was successfully stopped.

#### Context Example
```python
{
    "PsRemote": {
        "CommandResult": "Correlating traces ... done Merging traces ... done Generating data collection ... done The trace file and additional troubleshooting information have been compiled as \"c:\\XSOAR-XSOAR__a.cab\". File location = c:\\XSOAR-XSOAR__a.etl Tracing session was successfully stopped. ", 
        "FQDN": "XSOAR-XSOAR.winrm.local", 
        "EtlFilePath": "c:\\XSOAR-XSOAR__a.etl", 
        "Host": "XSOAR-XSOAR", 
        "CommandName": "netsh trace stop", 
        "EtlFileName": "XSOAR-XSOAR__a.etl"
    }
}
```

### ps-remote-export-registry
***
Exports the specified registry of hive to a file.


#### Base Command

`ps-remote-export-registry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | A single hostname or IP address on which to run the command. | Required | 
| reg_key_hive | The registry key or hive to export. For example, reg_key_hive=`HKEY_LOCAL_MACHINE`. If the user specifies "all", the entire registry will be exported. Default is "all". Default is all. | Optional | 
| file_path | The path and name on the Windows host where the registry file will be created. For example, file_path=c:\hklm.reg. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PsRemote.CommandResult | string | The command results in the remote host - regedit for all or reg export. | 
| PsRemote.RegistryFilePath | string | The path and name of the registry file. | 
| PsRemote.RegistryFileName | string | The name of the registry file. | 
| PsRemote.Command.Name | string | The name of the command that ran on the host. | 
| PsRemote.Fqdn | string | The Full Qualified Domain Name of the host. | 
| PsRemote.Host | string | The host on which the command was invoked. | 
| PsRemote.FQDN | string | The Fully Qualified Domain Name of the host on which the command was invoked. | 


#### Command Example
```!ps-remote-export-registry host="XSOAR-XSOAR" file_path="c:\\XSOAR-XSOAR__a.reg"```

#### Human Readable Output
>Ran Export Registry.
>Registry file expected path: c:\XSOAR-XSOAR__a.reg

#### Context Example
```python
{
    "PsRemote": {
        "RegistryFileName": "XSOAR-XSOAR__a.reg", 
        "RegistryFilePath": "c:\\XSOAR-XSOAR__a.reg", 
        "FQDN": "XSOAR-XSOAR.winrm.local", 
        "CommandName": "regedit /e c:\\XSOAR-XSOAR__a.reg", 
        "Host": "XSOAR-XSOAR", 
        "CommandResult": null
    }
}
```

### ps-remote-export-mft
***
Extracts the master file table from the volume.


#### Base Command

`ps-remote-export-mft`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host | A single hostname or IP address on which to run the command. | Required | 
| volume | The volume from which to retrieve its master file table. | Optional | 
| output_path | The path in which the MFT file is to be created. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PsRemote.ExportMFT | unknown | The extract master file table command result. | 
| PsRemote.Host | string | The host on which the command was invoked. | 
| PsRemote.FQDN | string | The Fully Qualified Domain Name of the host on which the command was invoked. | 


#### Command Example
```!ps-remote-export-mft host="XSOAR-XSOAR" volume=C```

#### Human Readable Output
>### MFT Export results:
>| ComputerName | MFT File | MFT Size | MFT Volume | NetworkPath | PSComputerName | PSShowComputerName | RunspaceId
>| --- | --- | --- | --- | --- | --- | --- | ---
>| XSOAR\-XSOAR | C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\zzthh5sh.hl2 | 222 MB | C | \\\\XSOAR\-XSOAR\\C$\\Users\\ADMINI~1\\AppData\\Local\\Temp\\zzthh5sh.hl2 | XSOAR\-XSOAR.winrm.local | true | \{"value":"58aa1f39\-f86d\-4f18\-978a\-c9257295df49","Guid":"58aa1f39\-f86d\-4f18\-978a\-c9257295df49"\}


#### Context Example
```python
{
    "PsRemote": {
        "ExportMFT": {
            "ComputerName": "XSOAR-XSOAR", 
            "MFT File": "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\zzthh5sh.hl2", 
            "MFT Size": "222 MB", 
            "PSComputerName": "XSOAR-XSOAR.winrm.local", 
            "NetworkPath": "\\\\XSOAR-XSOAR\\C$\\Users\\ADMINI~1\\AppData\\Local\\Temp\\zzthh5sh.hl2", 
            "MFT Volume": "C", 
            "RunspaceId": "58aa1f39-f86d-4f18-978a-c9257295df49", 
            "PSShowComputerName": true
        }, 
        "Host": "XSOAR-XSOAR", 
        "FQDN": "XSOAR-XSOAR.winrm.local"
    }
}
```