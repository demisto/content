Use the Microsoft Graph API integration to interact with Microsoft APIs that do not have dedicated integrations in Cortex XSOAR, for example, Mail Single-User, etc.
## Configure Microsoft Graph API_Test on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph API_Test.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Azure Cloud | When selecting the Custom option, the Azure AD endpoint parameter must be filled. More information about National clouds can be found here - https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication\#using-national-cloud | False |
    | Application ID |  | False |
    | Application Secret (Required for using Self Deployed Azure app) |  | False |
    | Tenant ID (Required for using Self Deployed Azure app) |  | False |
    | Application redirect URI (for Self Deployed - Authorization Code Flow) |  | False |
    | Authorization code (for Self Deployed - Authorization Code Flow) |  | False |
    | Certificate Thumbprint |  | False |
    | Private Key |  | False |
    | Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp; secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Use a self-deployed Azure Application | Select this checkbox if you are using a self-deployed Azure application. | False |
    | Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
    | Azure AD endpoint | Use this option when required to customize the URL to the Azure Active Directory endpoint. More information can be found here - https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication\#using-national-cloud | False |
    | Scope (Required for using Cortex XSOAR Azure app) | A space-separated list of scopes that you want to consent to. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Application Secret (Deprecated) |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-api-request

***
Run a Microsoft Graph API query.

#### Base Command

`msgraph-api-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The resource in Microsoft Graph to refer. | Required | 
| http_method | The HTTP method used for the request to Microsoft Graph. Possible values are: "GET", "POST", "DELETE", "PUT", or "PATCH". Possible values are: GET, POST, DELETE, PUT, PATCH. Default is GET. | Optional | 
| api_version | The version of the Microsoft Graph API to use. Possible values are: "v1.0" or "beta". Default is "v1.0. Possible values are: v1.0, beta. Default is v1.0. | Optional | 
| request_body | The request body (required for POST queries). | Optional | 
| odata | OData system query options, e.g. $filter=startswith(givenName, 'J'). For more details see https://docs.microsoft.com/en-us/graph/query-parameters. It is recommended to use the $top query option to limit the result. | Optional | 
| populate_context | If "true" will populate the API response to the context data. Possible values are "true" or "false". Default is "true". Possible values are: true, false. Default is true. | Optional | 

#### Context Output

There is no context output for this command.
### msgraph-api-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

#### Base Command

`msgraph-api-auth-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-api-auth-complete

***
Run this command to complete the authorization process. Should be used after running the msgraph-auth-start command.

#### Base Command

`msgraph-api-auth-complete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-api-test

***
Tests connectivity to Microsoft.

#### Base Command

`msgraph-api-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-api-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`msgraph-api-auth-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-api-generate-login-url

***
Generate the login URL used for Authorization code flow.

#### Base Command

`msgraph-api-generate-login-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
