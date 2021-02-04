Use the Microsoft Graph Services integration to manage authorized application.
This integration was integrated and tested with version v1.0 of Microsoft Graph Services API
## Configure MicrosoftGraphServices on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MicrosoftGraphServices.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Application ID | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### msgraph-apps-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.

### msgraph-apps-auth-complete
***
Run this command to complete the authorization process. Should be used after running the msgraph-apps-auth-start command.

### msgraph-apps-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.

### msgraph-apps-auth-test
***
Tests connectivity to Microsoft.


### msgraph-apps-service-principal-list
***
Retrieve a list of service principals.


#### Base Command

`msgraph-apps-service-principal-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum results to fetch. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphService.accountEnabled | Boolean | true if the service principal account is enabled; otherwise, false. | 
| MSGraphService.appDescription | String | A brief description of the app. | 
| MSGraphService.appDisplayName | String | The display name exposed by the associated application. | 
| MSGraphService.appId | String | The unique identifier for the associated application \(its appId property\). | 
| MSGraphService.appOwnerOrganizationId | String | Contains the tenant id where the application is registered. This is applicable only to service principals backed by applications. | 
| MSGraphService.appRoleAssignmentRequired | Boolean | Specifies whether users or other service principals need to be granted an app role assignment for this service principal before users can sign in or apps can get tokens. The default value is false. | 
| MSGraphService.applicationTemplateId | String | Unique identifier of the applicationTemplate that the servicePrincipal was created from. Read-only. | 
| MSGraphService.createdDateTime | Date | Time which the application created. | 
| MSGraphService.deletedDateTime | Date | Time which the application deleted. | 
| MSGraphService.description | String | A brief description of the app. | 
| MSGraphService.displayName | String | The display name for the service principal. | 
| MSGraphService.homepage | String | Home page or landing page of the application. | 
| MSGraphService.id | String | The unique identifier for the service principal. | 
| MSGraphService.info.logoUrl | String | CDN URL to the application's logo, | 
| MSGraphService.info.marketingUrl | String | Link to the application's marketing page. | 
| MSGraphService.info.privacyStatementUrl | String | Link to the application's privacy statement. | 
| MSGraphService.info.supportUrl | String | Link to the application's support page. | 
| MSGraphService.info.termsOfServiceUrl | String | Link to the application's terms of service statement. | 
| MSGraphService.loginUrl | String | Specifies the URL where the service provider redirects the user to Azure AD to authenticate. Azure AD uses the URL to launch the application from Microsoft 365 or the Azure AD My Apps | 
| MSGraphService.logoutUrl | String | Specifies the URL that will be used by Microsoft's authorization service to logout an user. | 
| MSGraphService.notes | String | Application's notes. | 
| MSGraphService.oauth2PermissionScopes.adminConsentDescription | String | A description of the delegated permissions, intended to be read by an administrator granting the permission on behalf of all users. This text appears in tenant-wide admin consent experiences. | 
| MSGraphService.oauth2PermissionScopes.adminConsentDisplayName | String | The permission's title, intended to be read by an administrator granting the permission on behalf of all users. | 
| MSGraphService.oauth2PermissionScopes.id | String | Unique delegated permission identifier inside the collection of delegated permissions defined for a resource application. | 
| MSGraphService.oauth2PermissionScopes.isEnabled | Boolean | Is oauth2PermissionScopes enabled or not. | 
| MSGraphService.oauth2PermissionScopes.type | String | Specifies whether this delegated permission should be considered safe for non-admin users to consent to on behalf of themselves, or whether an administrator should be required for consent to the permissions. | 
| MSGraphService.oauth2PermissionScopes.userConsentDescription | String | A description of the delegated permissions, intended to be read by a user granting the permission on their own behalf. This text appears in consent experiences where the user is consenting only on behalf of themselves. | 
| MSGraphService.oauth2PermissionScopes.userConsentDisplayName | String | A title for the permission, | 
| MSGraphService.oauth2PermissionScopes.value | String | Specifies the value to include in the scope claim in access tokens. | 
| MSGraphService.preferredSingleSignOnMode | String | Specifies the single sign-on mode configured for this application. Azure AD uses the preferred single sign-on mode to launch the application from Microsoft 365 or the Azure AD My Apps. The supported values are password, saml, external, and oidc. | 
| MSGraphService.preferredTokenSigningKeyThumbprint | String | Thumbprint of preferred certificate to sign the token | 
| MSGraphService.replyUrls | String | The URLs that user tokens are sent to for sign in with the associated application, or the redirect URIs that OAuth 2.0 authorization codes and access tokens are sent to for the associated application. | 
| MSGraphService.samlSingleSignOnSettings | String | The collection for settings related to saml single sign-on. | 
| MSGraphService.servicePrincipalNames | String | Contains the list of identifiersUris, | 
| MSGraphService.servicePrincipalType | String | Identifies if the service principal represents an application or a managed identity. | 
| MSGraphService.signInAudience | String | The audience that can sign in. | 
| MSGraphService.tokenEncryptionKeyId | String | Specifies the keyId of a public key from the keyCredentials | 
| MSGraphService.verifiedPublisher.addedDateTime | Date | The timestamp when the verified publisher was first added or most recently updated. | 
| MSGraphService.verifiedPublisher.displayName | String | The verified publisher name from the app publisher's Partner Center account. | 
| MSGraphService.verifiedPublisher.verifiedPublisherId | String | The ID of the verified publisher from the app publisher's Partner Center account. | 


#### Command Example
```!msgraph-apps-service-principal-list limit=1```

#### Context Example
```json
{
    "MSGraphService": {
        "accountEnabled": true,
        "addIns": [],
        "alternativeNames": [],
        "appDescription": null,
        "appDisplayName": "Common Data Service",
        "appId": "00000007-0000-0000-c000-000000000000",
        "appOwnerOrganizationId": "<appOwnerOrganizationId>",
        "appRoleAssignmentRequired": false,
        "appRoles": [],
        "applicationTemplateId": null,
        "createdDateTime": "2019-12-11T11:35:03Z",
        "deletedDateTime": null,
        "description": null,
        "displayName": "Common Data Service",
        "homepage": null,
        "id": "<id>>",
        "info": {
            "logoUrl": null,
            "marketingUrl": null,
            "privacyStatementUrl": null,
            "supportUrl": null,
            "termsOfServiceUrl": null
        },
        "keyCredentials": [],
        "loginUrl": null,
        "logoutUrl": null,
        "notes": null,
        "notificationEmailAddresses": [],
        "oauth2PermissionScopes": [
            {
                "adminConsentDescription": "Allows the application to access Common Data Service acting as users in the organization.",
                "adminConsentDisplayName": "Access Common Data Service as organization users",
                "id": "<id>>",
                "isEnabled": true,
                "type": "User",
                "userConsentDescription": "Allows the application to access Common Data Service as you.",
                "userConsentDisplayName": "Access Common Data Service as you",
                "value": "user_impersonation"
            }
        ],
        "passwordCredentials": [],
        "preferredSingleSignOnMode": null,
        "preferredTokenSigningKeyThumbprint": null,
        "replyUrls": [
            "https://admin.example.com/",
            "https://port.example..com/",
            "https://cloudredirector.example.com/"
        ],
        "resourceSpecificApplicationPermissions": [],
        "samlSingleSignOnSettings": null,
        "servicePrincipalNames": [
            "https://admin.example.com/",
            "https://port.example..com/",
            "https://cloudredirector.example.com/"
        ],
        "servicePrincipalType": "Application",
        "signInAudience": "AzureADMultipleOrgs",
        "tags": [],
        "tokenEncryptionKeyId": null,
        "verifiedPublisher": {
            "addedDateTime": "2020-05-19T00:00:00",
            "displayName": "Microsoft",
            "verifiedPublisherId": "000000"
        }
    }
}
```

#### Human Readable Output

>### Available services (applications):
>|id|appId|appDisplayName|accountEnabled|
>|---|---|---|---|
>| 00191e1d-4cbf-49fe-947e-547870a4d33c | 00000007-0000-0000-c000-000000000000 | Common Data Service | true |


### msgraph-apps-service-principal-remove
***
Removes an app from the directory.


#### Base Command

`msgraph-apps-service-principal-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the service to remove. Can be retrieved via msgraph-apps-service-principal-remove command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-apps-service-principal-remove id=4d77f5f1-ec0b-482c-a4ae-1df6a50f19c2```

#### Human Readable Output
>Service 4d77f5f1-ec0b-482c-a4ae-1df6a50f19c2 was deleted.

