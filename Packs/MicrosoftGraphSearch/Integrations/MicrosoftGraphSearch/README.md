Use the Microsoft Search API in Microsoft Graph to search content stored in OneDrive or SharePoint: files, folders, lists, list items, or sites.
## Configure Microsoft Graph Search on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph Search.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | ID or Client ID |  | True |
    | Token or Tenant ID |  | True |
    | Key or Client Secret (can be used instead of Certificate Thumbprint and Private Key) |  | False |
    | ID or Client ID - see Detailed Instructions (?) |  | False |
    | Token or Tenant ID - see Detailed Instructions (?) |  | False |
    | Key or Client Secret - see Detailed Instructions (?) |  | False |
    | Certificate Thumbprint (can be used instead of Client Secret) |  | False |
    | Private Key |  | False |
    | Certificate Thumbprint (optional for self-deployed Azure app) | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Authorization code |  | True |
    | Authorization code |  | True |
    | Application redirect URI |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-search-test

***
Tests connectivity.

#### Base Command

`msgraph-search-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
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
| SearchContent | unknown |  | 
