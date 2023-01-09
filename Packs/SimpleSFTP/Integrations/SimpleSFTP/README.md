
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
| filePath | Please provide file path as seen by the sftp user upon login. | Required | 
| returnFile | Defaults to False where text based file content will be printed. Please specify as True to download the file in case of non-text based files. Possible values are: True, False. Default is False. | Optional | 


#### Context Output

There is no context output for this command.