Use the Microsoft Search API in Microsoft Graph to search content stored in OneDrive or SharePoint: files, folders, lists, list items, or sites.
## Configure Microsoft Graph Search in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| ID or Client ID |  | True |
| Token or Tenant ID |  | True |
| Key or Client Secret (can be used instead of Certificate Thumbprint and Private Key) |  | False |
| Certificate Thumbprint (can be used instead of Client Secret) |  | False |
| Private Key |  | False |
| Authorization code |  | True |
| Application redirect URI |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-search-test

***
Tests connectivity.

#### Base Command

`msgraph-search-test`

### msgraph-search-content

***
Use the Microsoft Search API in Microsoft Graph to search content stored in OneDrive or SharePoint: files, folders, lists, list items, or sites.

#### Base Command

`msgraph-search-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_string | Represents a (text string) search query that contains search terms and optional filters. | Required | 
| entity_type | One or more types of resources expected in the response. . Possible values are: list, site, listItem, message, event, drive, driveItem, externalItem. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SearchContent | unknown | OneDrive or SharePoint content returned from the search | 

### msgraph-search-generate-login-url

***
Generate the login url used for Authorization code flow.

#### Base Command

`msgraph-search-generate-login-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.