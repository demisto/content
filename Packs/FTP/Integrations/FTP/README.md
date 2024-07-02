FTP integration to download or upload files to a remote FTP server. Please note that FTP transfer is insecure. Please use it with care.

## Configure FTP on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FTP.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Host | True |
    | Port | False |
    | Username | False |
    | Password | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ftp-ls

***
List all the files under the current folder.

#### Base Command

`ftp-ls`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The path to list. | Optional | 

#### Context Output

There is no context output for this command.
### ftp-put

***
Upload file to FTP server.

#### Base Command

`ftp-put`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The Entry ID of the file to upload. | Required | 
| target | The target FTP server to upload the file to. | Required | 

#### Context Output

There is no context output for this command.
### ftp-get

***
Download file from FTP server.

#### Base Command

`ftp-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | The path to the file to download from the FTP server. | Required | 
| file_name | The file name to download from the FTP server. | Required | 

#### Context Output

There is no context output for this command.
