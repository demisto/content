Simple web server with a file uploading console to store small files.
This is helpful to make your environment ready for testing purpose for your playbooks or automations to download files from a web server.
## Configure Web File Repository on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Web File Repository.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Incident type |  | False |
    | Long running instance |  | False |
    | Port mapping (&lt;port&gt; or &lt;host port&gt;:&lt;docker port&gt;) |  | True |
    | User ID for Read/Write |  | False |
    | Password |  | False |
    | User ID for Read-Only |  | False |
    | Password |  | False |
    | Authentication Method | Some of the browsers such as Chrome may not support Digest-sha256. | False |
    | Public Read Access | Authentication is not requiured for read access | False |
    | MIME Types for file extensions | "mime-type  extension \[extension\]\*" for each line, wild-card file extensions are supported. | False |
    | Merge with Default MIME Types | Set true to merge the specified types with the default settings, false to replace them | False |
    | Attachment extensions | List of extensions to set "attachment" to Content-Disposition | False |
    | Storage Protection |  | True |
    | The maximum repository size |  | False |
    | The maximum sandbox repository size |  | False |

4. Click **Test** to validate the URLs, token, and connection.


## How to Access the File Management UI

### Access the File Management UI by URL and Port (HTTP)
In a web browser, go to **`http://<cortex-xsoar-server-address>:<listen_port>`**.

### Access the File Management UI by Instance Name (HTTPS)

To access the File Management UI by instance name, make sure ***Instance execute external*** is enabled. 

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the `instance.execute.external.<instance_name>` key is set to `true`. If this key does not exist, click **+ Add Server Configuration** and add the `instance.execute.external.<instance_name>` and set the value to `true`. See [this documentation](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.
3. In a web browser, go to `https://<cortex-xsoar-address>/instance/execute/<instance_name>/`.

   In Multi Tenant environments, go to `https://<cortex-xsoar-address>/acc_<account name>/instance/execute/<instance_name>/`


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### wfr-status
***
Get the service status


#### Base Command

`wfr-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WebFileRepository.Status.StorageUsage | number | The current storage usage in bytes | 
| WebFileRepository.Status.SandboxUsage | number | The current sandbox usage in bytes | 
| WebFileRepository.Status.StorageProtection | string | The storage protection mode | 
| WebFileRepository.Status.IntercommunicationIP | string | The IP address of the service to which the internal client connects | 
| WebFileRepository.Status.IntercommunicationPort | number | The port number of the service to which the internal client connects | 
| WebFileRepository.Status.ExternaIP | unknown | The external IP address of the service | 
| WebFileRepository.Status.ExternalPort | unknown | The external port number of the service | 
| WebFileRepository.Status.ServerIP | string | The IP address of the service | 
| WebFileRepository.Status.ServerPort | number | The port number of the service | 

### wfr-cleanup
***
Remove all the files from the repository


#### Base Command

`wfr-cleanup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### wfr-upload-file
***
Upload a file to the repository


#### Base Command

`wfr-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry ID list of the file. | Required | 
| file_name | The name of the file. | Optional | 
| extract_archive | Set to true to extract files to archive files, otherwise false. Possible values are: true, false. Default is false. | Optional | 
| upload_directory | The directory path where to upload. Default is /. | Optional | 


#### Context Output

There is no context output for this command.
### wfr-upload-files
***
Upload files to the repository


#### Base Command

`wfr-upload-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_ids | The entry ID list of files. | Required | 
| extract_archive | Set to true to extract files to archive files, otherwise false. Possible values are: true, false. Default is false. | Optional | 
| upload_directory | The directory path where to upload. Default is /. | Optional | 


#### Context Output

There is no context output for this command.
### wfr-list-files
***
List files in the repository


#### Base Command

`wfr-list-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| directory | The directory path where to list files. Default is /. | Optional | 
| recursive | Set to true to list subdirectories recursively, otherwise false. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WebFileRepository.Files.Name | string | The file name | 
| WebFileRepository.Files.Path | string | The file path | 
| WebFileRepository.Files.Size | number | The file size in bytes | 
| WebFileRepository.Files.LastModified | date | The last modified time | 

### wfr-remove-files
***
Remove files from the repository


#### Base Command

`wfr-remove-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| paths | The list of the file paths. | Required | 


#### Context Output

There is no context output for this command.
### wfr-download-file
***
Download a file from the repository


#### Base Command

`wfr-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The file path. | Required | 
| save_as | The name to give the file to save. | Optional | 


#### Context Output

There is no context output for this command.
### wfr-archive-zip
***
Download a file to which all the files are archived


#### Base Command

`wfr-archive-zip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| save_as | The name to give the archive-file to save. | Optional | 


#### Context Output

There is no context output for this command.
### wfr-reset
***
Reset the repository data


#### Base Command

`wfr-reset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.