Leverage the Centrify Vault integration to create and manage Secrets.
This integration was integrated and tested with version xx of Centrify Vault
## Configure Centrify Vault on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Centrify Vault.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | tenantUrl | Centrify Tenant URL \(e.g. https://vault.example.local\) | True |
    | clientId | Client ID of the Centrify Vault OAuth App | True |
    | clientSecret | Client Secret of the Centrify Vault OAuth App | True |
    | appId | ID of the Centrify OAuth App | True |
    | scope | Scope of the Centrify OAuth App | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### centrify-retrieve-secrets
***
Retrieves the secret from centrify vault based on folder name, set name or secret name. If folder name is not provided, all the secrets in the parent folder will be fetched recursively. You can filter based on the secret name and folder separately as well as combined. 


#### Base Command

`centrify-retrieve-secrets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| holderType | Type of holder where the secret is located. Values can be Folder or Set. Please make sure to provide value in the "holderName" argument. Possible values are: Folder, Set. | Optional | 
| holderName | Name of the holder (Folder/Set) where the secret is available. Please choose "Folder" or "Set" in the "holderType" argument. Ex: XSOAR, XSOAR/SUB_FOLDER. | Optional | 
| secretName | Secret name which has the secret. Ex: client*, client_secret. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Centrify.Secrets.FolderName | string | Folder name of the secret | 
| Centrify.Secrets.SecretName | string | Secret name of the secret | 
| Centrify.Secrets.SecretText | string | Secret text of the secret | 
| Centrify.Secrets.SecretType | string | Type of the secret | 
| Centrify.Secrets.SecretDescription | string | Description of the secret | 
| Centrify.Secrets.SecretID | string | ID of the Secret retrieved | 


### centrify-retrieve-secret-by-secretid
***
Retrieves the secret from centrify vault based on secret ID.


#### Base Command

`centrify-retrieve-secret-by-secretid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secretId | ID of the secret. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Centrify.Secrets.FolderName | string | Folder name of the secret | 
| Centrify.Secrets.SecretName | string | Secret name of the secret | 
| Centrify.Secrets.SecretText | string | Secret text of the secret | 
| Centrify.Secrets.SecretType | string | Type of the secret | 
| Centrify.Secrets.SecretDescription | string | Description of the secret | 
| Centrify.Secrets.SecretID | string | ID of the Secret retrieved | 


### centrify-create-secretfolder
***
Creates a folder in Centrify Vault


#### Base Command

`centrify-create-secretfolder`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folderName | Name of the folder to be created. This will be subfolder if "parentFolderName" is provided. | Required | 
| parentFolderName | Name of the parent folder. Please note this is case sensitive. . | Optional | 
| folderDescription | Description of the folder to be created. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Centrify.Folder.FolderName | string | Name of the folder created | 
| Centrify.Folder.FolderID | string | ID of the folder created | 
| Centrify.Folder.ParentFolderName | string | Name of the parent folder | 
| Centrify.Folder.FolderDescription | string | Description of the folder created | 


### centrify-create-secret
***
Creates a secret in Centrify Vault.


#### Base Command

`centrify-create-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| holderType | Type of holder where the secret will be created. Values can be Folder or Set. Please make sure to provide value in the "holderName" argument. Possible values are: Folder, Set. | Required | 
| holderName | Name of the holder (Folder/Set) where the secret needs to be created.  Please choose "Folder" or "Set" in the "holderType" argument. Ex: XSOAR, XSOAR/SUB_FOLDER . | Required | 
| secretName | Name of the secret to be created. | Required | 
| secretText | Text of the secret. | Required | 
| secretType | Type of the secret. Possible values are: Text. | Required | 
| secretDescription | Description of the secret. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Centrify.Secrets.holderType | string | Type of the location where secret is created. It can be folder or set. | 
| Centrify.Secrets.SecretName | string | Name of the secret created | 
| Centrify.Secrets.SecretID | string | ID of the secret created | 
| Centrify.Secrets.SecretType | string | Type of the secret created | 
| Centrify.Secrets.FolderName | string | Name of the folder where the secret is created | 
| Centrify.Secrets.FolderID | string | ID of the folder where the secret is created | 
| Centrify.Secrets.SetName | string | Name of the set where the secret is created | 
| Centrify.Secrets.SetID | string | ID of the set where the secret is created | 
| Centrify.Secrets.SecretDescription | string | Description of the created secret | 


### centrify-create-set
***
Creates a set in Centrify Vault


#### Base Command

`centrify-create-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| setName | Name of the Set to be created. | Required | 
| setDescription | Description of the Set to be created. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Centrify.Set.SetName | string | Name of the set created | 
| Centrify.Set.SetID | string | ID of the set created | 
| Centrify.Set.SetDescription | string | Description of the set created | 


### centrify-retrieve-folders
***
Fetch details of all folders in Centrify Vault


#### Base Command

`centrify-retrieve-folders`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Centrify.Folder.FolderName | string | Name of the folder | 
| Centrify.Folder.FolderID | string | ID of the folder | 
| Centrify.Folder.ParentFolder | string | Name of the parent folder | 
| Centrify.Folder.FolderDescription | string | Description of the folder | 
| Centrify.Folder.FolderDirectory | string | Complete directory of the folder | 


### centrify-delete-folder
***
Delete a folder from the Centrify Vault


#### Base Command

`centrify-delete-folder`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folderName | Name of the folder to be deleted. Please provide parent foldername in the argument "parentFolderName" if you are deleting a subfolder. | Required | 
| parentFolderName | Name of the parent folder. | Optional | 


#### Context Output

There is no context output for this command.


### centrify-delete-secret
***
Delete Secret from the Centrify Vault. Please note:  Enabling "recursiveDelete" to "Yes" will delete all secrets if there multiple secrets with same name in subfolders.


#### Base Command

`centrify-delete-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secretName | Name of the secret to be deleted. | Required | 
| folderName | Name of the folder from where the secret should be deleted. If the secret is in subfolder, then provide parent folder followed by "/" and subfolder name. Ex: XSOAR/Demisto. | Optional | 
| recursiveDelete | "Yes" if you want to delete all the secrets having same name in all the subfolders recursively. "No" if you want do not want to delete the secret in the subfolders. Possible values are: Yes, No. | Required | 
| matchPartOfSecret | "Yes" if you want to delete the secret having the provided secretname as a part of the Secret. "No" if you want to delete the secret with the exact name match. Ex: Demisto* will delete all secrets like Demisto_1, Demisto_pwd, Demisto. . Possible values are: Yes, No. | Required | 


#### Context Output

There is no context output for this command.


### centrify-delete-secret-by-secretid
***
Delete Secret from the Centrify Vault based on the Secret ID provided


#### Base Command

`centrify-delete-secret-by-secretid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secretId | ID of the Secret to be deleted. | Required | 


#### Context Output

There is no context output for this command.


### centrify-add-secret-to-set
***
Adds/Moves a secret to a set for the provided secretID. Use "centrify-retrieve-secrets" to fetch secret ID's.


#### Base Command

`centrify-add-secret-to-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| setName | Name of the set where the secret will be added/moved. | Required | 
| secretId | ID of the secret which needs to be moved to the set. | Required | 


#### Context Output

There is no context output for this command.



### centrify-retrieve-sets
***
Fetches the details of all sets in the Centrify Vault


#### Base Command

`centrify-retrieve-sets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Centrify.Set.SetName | string | Name of the set | 
| Centrify.Set.SetID | string | ID of the set | 
| Centrify.Set.SetDescription | string | Description of the set | 


### centrify-delete-set
***
Delete set from the Centrify Vault


#### Base Command

`centrify-delete-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| setName | Name of the set to be deleted. | Required | 


#### Context Output

There is no context output for this command.

## Demo Video
<video controls>
    <source src="https://github.com/demisto/content-assets/raw/58ada3506ba4082dc5aa36044f02bc212af73f96/Assets/CentrifyVault/CentrifyVault_demo.mp4"
            type="video/mp4"/>
    Sorry, your browser doesn't support embedded videos. You can download the video at: https://github.com/demisto/content-assets/blob/58ada3506ba4082dc5aa36044f02bc212af73f96/Assets/CentrifyVault/CentrifyVault_demo.mp4
</video>

