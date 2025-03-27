Retrieval Augmented Generation (RAG) with LLM and Vector DB that can be local for full data privacy or cloud-based for greater functionality
## Configure AnythingLLM in Cortex


| **Parameter** | **Required** |
| --- | --- |
| AnythingLLM URL (e.g., http://&lt;url to AnythingLLM&gt;:3001) | True |
| AnythingLLM API Key | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### anyllm-document-upload-file

***
Uploads an XSOAR file entry to the custom-documents folder

#### Base Command

`anyllm-document-upload-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileentry | XSOAR file entry to upload - example: 181@24789. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-document-upload-link

***
Uploads a web link to the custom-documents folder

#### Base Command

`anyllm-document-upload-link`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| link | Web link to upload - example:  https://unit42.paloaltonetworks.com/darkgate-malware-uses-excel-files". | Required | 
| title | No description provided. | Required | 
| description | No description provided. | Required | 
| author | No description provided. | Required | 
| source | No description provided. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-document-upload-text

***
Upload text content as a document to the custom-documents folder

#### Base Command

`anyllm-document-upload-text`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Raw text content that is the document. | Required | 
| title | Document title to use when uploading. | Required | 
| description | Description of the document. | Optional | 
| author | Author of the document. | Optional | 
| source | Source of the document. | Optional | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-new

***
Creates a new workspace in AnythingLLM

#### Base Command

`anyllm-workspace-new`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace to create. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-delete

***
Deletes an AnythingLLM workspace

#### Base Command

`anyllm-workspace-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace to delete. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-list

***
List all the workspaces in AnythingLLM

#### Base Command

`anyllm-workspace-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### anyllm-workspace-get

***
Get a specific workspace details

#### Base Command

`anyllm-workspace-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-settings

***
Update workspace settings

#### Base Command

`anyllm-workspace-settings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Required | 
| settings | JSON object for the settings. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-add-embedding

***
Add a document to a workspace and create its vector embedding in the workspace

#### Base Command

`anyllm-workspace-add-embedding`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Required | 
| folder | Folder name containing the document. | Required | 
| document | Document name to add as an embedding. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-delete-embedding

***
Delete a document embedding from the workspace

#### Base Command

`anyllm-workspace-delete-embedding`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Required | 
| folder | Folder the document originated from. | Required | 
| document | Name of the document to have its embedding deleted. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-document-createfolder

***
Create a new document folder

#### Base Command

`anyllm-document-createfolder`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Name of the folder to create. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-document-move

***
Move a document from a source folder to a destination folder

#### Base Command

`anyllm-document-move`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| srcfolder | Name of the source folder. | Required | 
| dstfolder | Name of the destination folder. | Optional | 
| document | Document name to move. | Optional | 

#### Context Output

There is no context output for this command.
### anyllm-document-delete

***
Delete a document

#### Base Command

`anyllm-document-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Name of the folder. | Required | 
| document | Name of the document to delete. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-chat

***
Send a chat message to a workspace (default thread). Query mode is based on embedded documents in chat, whereas chat mode is more general.

#### Base Command

`anyllm-workspace-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Required | 
| message | Message to send. | Required | 
| mode | Mode to chat, query or chat. Possible values are: query, chat. | Required | 
| format | No description provided. Possible values are: markdown, dictionary. Default is dictionary. | Optional | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-stream-chat

***
Send a stream chat message to a workspace (default thread). Query mode is based on embedded documents in chat, whereas chat mode is more general

#### Base Command

`anyllm-workspace-stream-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Required | 
| message | Message to send. | Required | 
| mode | Chat mode, query or chat. Possible values are: query, chat. | Optional | 

#### Context Output

There is no context output for this command.
### anyllm-document-list

***
List all document details

#### Base Command

`anyllm-document-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### anyllm-document-get

***
Get a specific document details

#### Base Command

`anyllm-document-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder | Folder containing the document. | Required | 
| document | Document name. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-pin

***
Set the pinned status of a document embedding

#### Base Command

`anyllm-workspace-pin`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Workspace name. | Required | 
| folder | Folder the document originated from. | Required | 
| document | Document name. | Required | 
| status | Set pin status to true or false. Possible values are: true, false. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-thread-chats

***
Get the conversation for a workspace thread

#### Base Command

`anyllm-workspace-thread-chats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | No description provided. | Required | 
| thread | No description provided. | Optional | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-thread-chat

***
Send a chat a message to a conversation thread

#### Base Command

`anyllm-workspace-thread-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Required | 
| thread | Name of the conversation thread. | Required | 
| message | Message to send. | Required | 
| mode | Mode to chat, query or chat. Possible values are: query, chat. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-thread-new

***
Create a new conversation thread

#### Base Command

`anyllm-workspace-thread-new`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Required | 
| thread | Name of the new conversation thread. | Required | 

#### Context Output

There is no context output for this command.
### anyllm-workspace-thread-delete

***
Delete a thread in a workspace

#### Base Command

`anyllm-workspace-thread-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace | Name of the workspace. | Optional | 
| thread | Name of the thread. | Optional | 

#### Context Output

There is no context output for this command.
