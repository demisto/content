
### sftp-listdir

***
List Directories SFTP command given directory path. Defaults to current directory upon sftp login.


#### Base Command

`sftp-listdir`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| directory | The directory from which to list the all directories. Default is .. | Optional | 


#### Context Output

There is no context output for this command.

### sftp-copyfrom

***
Copies contents of file specified from the sftp server and prints it to the war room


#### Base Command

`sftp-copyfrom`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | Please provide file path as seen by the sftp user upon login. | Required | 
| return_file | Defaults to False where text based file content will be printed. Please specify as True to download the file in case of non-text based files. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

There is no context output for this command.

### sftp-upload-file

***
Uploads a file from the War Room using it's Entry ID to the SFTP Server at a given path

#### Base Command

`sftp-upload-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Destination path on SFTP Server to upload the file to | Required | 
| file_entry_id | War-room Entry ID for the file to upload | Required | 


#### Context Output

There is no context output for this command.