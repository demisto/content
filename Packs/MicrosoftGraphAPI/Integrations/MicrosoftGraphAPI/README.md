Use the Microsoft Graph API integration to interact with Microsoft APIs that do not have dedicated integrations in Cortex XSOAR, for example, Mail Single-User, etc.

---

Note: In this documentation, we will use the [Application resource type](https://docs.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0) as an example.

## Authorization
In order to use the integration, there are 2 application authentication methods available.

Note: Depending on the authentication method that you use, the integration parameters might change.

#### Cortex XSOAR Azure app

In this method, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

To configure the integration:

1. The ***Application ID*** integration parameter should be set to `8922dd2d-7539-4711-b839-374f86083959` (the Cortex XSOAR Azure app ID).

2. The ***Scope*** integration parameter should be set according to the requested OAuth2 permissions types to grant access to in Microsoft identity platform, for more details see the [Microsoft documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent).
For example, if we wish to use the [List applications](https://docs.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http#permissions) API, we need at least the `Application.Read.All` scope.

3. The ***Application Secret*** and the ***Tenant ID*** integration parameters should be left blank.

4. Run the *msgraph-api-auth-start* command - you will be prompted to open the page https://microsoft.com/devicelogin and enter the generated code.

5. Run the *msgraph-api-auth-complete* command

6. Run the *msgraph-api-test* command to ensure connectivity to Microsoft. 
 
#### Self Deployed Azure app

For more information, refer to the following [article](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application). 

## Configure the Azure app
1. [Register the app](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. [Add the requested API permissions](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#request-the-permissions-in-the-app-registration-portal) according to the APIs you wish to use.
    For example, according to the [Create application API documentation](https://docs.microsoft.com/en-us/graph/api/application-post-applications?view=graph-rest-1.0&tabs=http#permissions) in order to create applications we need the *Application.ReadWrite.All* application permission.
3. Grant admin consent for the chosen permissions.

**Note**: The integration stores in cache the API access token based on the permissions it is first run with, so if the permissions are modified, it is recommended to create a new instance of the integration.

## Configure Microsoft Graph API on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph API.
3. Click **Add instance** to create and configure a new integration instance.
4. 
    | **Parameter**                                                          | **Description**                                                                                                                                                                                                                                                                                                                                        | **Required** |
    |------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
    | Azure Cloud                                                            | See option table below.                                                                                                                                                                                                                                                                                                                                | False        |
    | Application ID                                                         |                                                                                                                                                                                                                                                                                                                                                        | False        |
    | Application Secret (Required for using Self Deployed Azure app)        |                                                                                                                                                                                                                                                                                                                                                        | False        |
    | Tenant ID (Required for using Self Deployed Azure app)                 |                                                                                                                                                                                                                                                                                                                                                        | False        |
    | Application redirect URI (for Self Deployed - Authorization Code Flow) |                                                                                                                                                                                                                                                                                                                                                        | False        |
    | Authorization code (for Self Deployed - Authorization Code Flow)       |                                                                                                                                                                                                                                                                                                                                                        | False        |
    | Certificate Thumbprint                                                 |                                                                                                                                                                                                                                                                                                                                                        | False        |
    | Private Key                                                            |                                                                                                                                                                                                                                                                                                                                                        | False        |
    | Certificate Thumbprint                                                 | Used for certificate authentication. As appears in the "Certificates &amp; secrets" page of the app.                                                                                                                                                                                                                                                   | False        |
    | Private Key                                                            | Used for certificate authentication. The private key of the registered certificate.                                                                                                                                                                                                                                                                    | False        |
    | Use a self-deployed Azure Application                                  | Select this checkbox if you are using a self-deployed Azure application.                                                                                                                                                                                                                                                                               | False        |
    | Use Azure Managed Identities                                           | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False        |
    | Azure Managed Identities Client ID                                     | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM.                                                                                                                                                                                                                                         | False        |
    | Azure AD endpoint                                                      | Azure AD endpoint associated with a national cloud. See note below.                                                                                                                                                                                                                                                                                    | False        |
    | Scope (Required for using Cortex XSOAR Azure app)                      | A space-separated list of scopes that you want to consent to.                                                                                                                                                                                                                                                                                          | False        |
    | Trust any certificate (not secure)                                     |                                                                                                                                                                                                                                                                                                                                                        | False        |
    | Use system proxy settings                                              |                                                                                                                                                                                                                                                                                                                                                        | False        |

    Azure cloud options
    
    | Azure Cloud | Description                                                         |
    |-------------|---------------------------------------------------------------------|
    | Worldwide   | The publicly accessible Azure Cloud                                 |
    | US GCC      | Azure cloud for the USA Government Cloud Community (GCC)            |
    | US GCC-High | Azure cloud for the USA Government Cloud Community High (GCC-High)  |
    | DoD         | Azure cloud for the USA Department of Defense (DoD)                 |
    | Germany     | Azure cloud for the German Government                               |
    | China       | Azure cloud for the Chinese Government                              |
    | Custom      | Custom endpoint configuration to the Azure cloud. See note below.   |

   - Note: In most cases, setting Azure cloud is preferred to setting Azure AD endpoint. Only use it in cases where a custom URL is required for accessing a national cloud.

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-api-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.

### msgraph-api-auth-complete
***
Run this command to complete the authorization process.
Should be used after running the ***msgraph-api-auth-start*** command.

### msgraph-api-test
***
Tests connectivity to Microsoft.

### msgraph-api-request

***
Run a Microsoft Graph API query.

#### Base Command

`msgraph-api-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The resource in Microsoft Graph to refer. | Required | 
| http_method | The HTTP method used for the request to Microsoft Graph. Possible values are: GET, POST, DELETE, PUT, PATCH. Default is GET. | Optional | 
| api_version | The version of the Microsoft Graph API to use. Possible values are: v1.0, beta. Default is v1.0. | Optional | 
| request_body | The request body (required for POST queries). | Optional | 
| odata | OData system query options, e.g., $filter=startswith(givenName, 'J'). For more details see https://docs.microsoft.com/en-us/graph/query-parameters. It is recommended to use the $top query option to limit the result. | Optional | 
| populate_context | If "true" will populate the API response to the context data. Possible values are: true, false. Default is true. | Optional | 
| headers | A comma-separated list of headers to send in the GET request, for example: ConsistencyLevel:eventual,User-Agent:MyApp/1.0. | Optional | 

#### Context Output

The context data output depends on the resource executed.
The *populate_context* argument sets whether to output to the context data, under the path **MicrosoftGraph**.
For resources which return a large response, we recommend to narrow the results by using the *odata* argument or outputting to the context data using [Extend Context](https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context).

### msgraph-api-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`msgraph-api-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### msgraph-api-generate-login-url
***
Generate the login URL used for Authorization code flow.

#### Base Command

`msgraph-api-generate-login-url`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```msgraph-api-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.

## Usage
Let's say we want to [list all the applications](https://docs.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http).

We can see that according to the [HTTP request](https://docs.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http#http-request):
 - The HTTP method is ***GET***
 - The resource is ***/applications***
 
So in order to list all the applications using the integration, we would run the command: `!msgraph-api resource=/applications http_method=GET`