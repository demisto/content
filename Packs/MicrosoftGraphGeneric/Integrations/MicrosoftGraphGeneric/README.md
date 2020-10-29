Use the Microsoft Graph Generic integration to interact with Microsoft Graph API. 

The integration should be used for APIs that are not implemented in other specific Microsoft Graph integrations.

The integration supports only Application permission type, and does not support Delegated permission type.

Note: In this documentation, we will use the [Application resource type](https://docs.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0) as an example.

## Configure the Azure app
1. [Register the app](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. [Add the requested API permissions](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#request-the-permissions-in-the-app-registration-portal) according to the APIs you wish to use.
    For example, according to the [Create application API documentation](https://docs.microsoft.com/en-us/graph/api/application-post-applications?view=graph-rest-1.0&tabs=http#permissions) in order to create applications we need the *Application.ReadWrite.All* application permission.
3. Grant admin consent for the chosen permissions.

**Note**: The integration stores in cache the API access token based on the permissions it is first run with, so if the permissions are modified, it is recommended to create a new instance of the integration.

## Configure Microsoft Graph Generic on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph Generic.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| app_id | Application ID | True |
| app_secret | Application Secret | True |
| tenant_id | Tenant ID | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute the command from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### msgraph-generic
***
Run a Microsoft Graph API query.


#### Base Command

`msgraph-generic`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The resource in Microsoft Graph to refer. | Required | 
| http_method | The HTTP method used for the request to Microsoft Graph. Possible values are: "GET", "POST", "DELETE", "PUT", or "PATCH". Default is "GET". | Optional | 
| api_version | The version of the Microsoft Graph API to use. Possible values are: "v1.0" or "beta". Default is "v1.0". | Optional | 
| request_body | The request body (required for POST queries). | Optional | 
| odata | OData system query options, e.g. $filter=startswith(givenName, 'J'). For more details see https://docs.microsoft.com/en-us/graph/query-parameters | Optional | 


#### Context Output

Since the response returned from Graph API can be huge, there is no context output for this command.
Use [Extend Context](https://xsoar.pan.dev/docs/playbooks/playbooks-extend-context) in order to output to the context data.


## Usage
Let's say we want to [list all the applications](https://docs.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http).

We can see that according to the [HTTP request](https://docs.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0&tabs=http#http-request):
 - The HTTP method is ***GET***
 - The resource is ***/applications***
 
So in order to list all the applications using the integration, we would run the command: `!msgraph-generic resource=/applications http_method=GET`
If we would like to store in the context data the first application ID returned, we would run the command: `!msgraph-generic resource=/applications http_method=GET extend-context=MicrosoftGraphGeneric.Application.ID=value.[0].appId`.