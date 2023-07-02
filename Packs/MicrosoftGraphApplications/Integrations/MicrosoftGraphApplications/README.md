Use the Azure Active Directory Applications integration to manage authorized applications.
Use the Azure Active Directory Applications integration to manage authorized application.
This integration was integrated and tested with version v1.0 of Microsoft Graph Services API.
## Configure Azure Active Directory Applications on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Active Directory Applications.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Application ID |  | False |
    | Azure AD endpoint | Azure AD endpoint associated with a national cloud. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Authentication Type | Type of authentication - could be Client Credentials Authorization Flow \(recommended\) or Device Flow | False |
    | Tenant ID (for Client Credentials mode) |  | False |
    | Client Secret (for Client Credentials mode) |  | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |

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
Retrieves a list of applications.


#### Base Command

`msgraph-apps-service-principal-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum results to fetch. A value of 0 fetches all results. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphApplication.keyCredentials.keyId | String | The unique identifier \(GUID\) for the key. | 
| MSGraphApplication.keyCredentials.customKeyIdentifier | String | Custom key identifier. | 
| MSGraphApplication.keyCredentials.displayName | String | Friendly name for the key. Optional. | 
| MSGraphApplication.keyCredentials.type | String | The type of key credential; for example, “Symmetric”. | 
| MSGraphApplication.keyCredentials.key | String | The certificate's raw data in byte array converted to Base64 string. | 
| MSGraphApplication.keyCredentials.usage | String | A string that describes the purpose for which the key can be used; for example, “Verify”. | 
| MSGraphApplication.keyCredentials.startDateTime | Date | The date and time at which the credential expires.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MSGraphApplication.keyCredentials.endDateTime | Date | The date and time at which the credential becomes valid.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' | 
| MSGraphApplication.accountEnabled | Boolean | true if the application account is enabled; otherwise, false. | 
| MSGraphApplication.appDescription | String | A brief description of the application. | 
| MSGraphApplication.appDisplayName | String | The display name exposed by the associated application. | 
| MSGraphApplication.appId | String | The unique identifier for the associated application \(its appId property\). | 
| MSGraphApplication.appOwnerOrganizationId | String | Contains the tenant ID where the application is registered. This is applicable only to service principals backed by applications. | 
| MSGraphApplication.appRoleAssignmentRequired | Boolean | Whether users or other service principals need to be granted an application role assignment for this service principal before users can sign in or apps can get tokens. Default is false. | 
| MSGraphApplication.applicationTemplateId | String | Unique identifier of the application template that the service principal was created from. | 
| MSGraphApplication.createdDateTime | Date | Time the application was created. | 
| MSGraphApplication.deletedDateTime | Date | Time the application was deleted. | 
| MSGraphApplication.description | String | A brief description of the application. | 
| MSGraphApplication.displayName | String | The display name for the application. | 
| MSGraphApplication.homepage | String | Home page or landing page of the application. | 
| MSGraphApplication.id | String | The unique identifier for the application. | 
| MSGraphApplication.info.logoUrl | String | Content delivery network \(CDN\) URL to the application's logo. | 
| MSGraphApplication.info.marketingUrl | String | Link to the application's marketing page. | 
| MSGraphApplication.info.privacyStatementUrl | String | Link to the application's privacy statement. | 
| MSGraphApplication.info.supportUrl | String | Link to the application's support page. | 
| MSGraphApplication.info.termsOfServiceUrl | String | Link to the application's terms of service statement. | 
| MSGraphApplication.loginUrl | String | The URL where the service provider redirects the user to Azure AD to authenticate. Azure AD uses the URL to launch the application from Microsoft 365 or the Azure AD My Apps. | 
| MSGraphApplication.logoutUrl | String | Specifies the URL that will be used by Microsoft's authorization service to log out an user. | 
| MSGraphApplication.notes | String | The application's notes. | 
| MSGraphApplication.oauth2PermissionScopes.adminConsentDescription | String | A description of the delegated permissions, intended to be read by an administrator granting the permission on behalf of all users. This text appears in tenant-wide admin consent experiences. | 
| MSGraphApplication.oauth2PermissionScopes.adminConsentDisplayName | String | The permission's title, intended to be read by an administrator granting the permission on behalf of all users. | 
| MSGraphApplication.oauth2PermissionScopes.id | String | Unique delegated permission identifier inside the collection of delegated permissions defined for a resource application. | 
| MSGraphApplication.oauth2PermissionScopes.isEnabled | Boolean | Whether OAuth 2.0 permission scopes are enabled. | 
| MSGraphApplication.oauth2PermissionScopes.type | String | Whether this delegated permission should be considered safe for non-admin users to consent to on behalf of themselves, or whether an administrator should be required for consent to the permissions. | 
| MSGraphApplication.oauth2PermissionScopes.userConsentDescription | String | A description of the delegated permissions, intended to be read by a user granting the permission on their own behalf. This text appears in consent experiences where the user is consenting only on behalf of themselves. | 
| MSGraphApplication.oauth2PermissionScopes.userConsentDisplayName | String | A title for the permission. | 
| MSGraphApplication.oauth2PermissionScopes.value | String | The value to include in the scope claim in access tokens. | 
| MSGraphApplication.preferredSingleSignOnMode | String | The single sign-on mode configured for this application. Azure AD uses the preferred single sign-on mode to launch the application from Microsoft 365 or the Azure AD My Apps. The supported values are password, SAML, external, and OIDC. | 
| MSGraphApplication.preferredTokenSigningKeyThumbprint | String | Thumbprint of preferred certificate to sign the token. | 
| MSGraphApplication.replyUrls | String | The URLs that user tokens are sent to for signing in with the associated application, or the redirect URIs that OAuth 2.0 authorization codes and access tokens are sent to for the associated application. | 
| MSGraphApplication.samlSingleSignOnSettings | String | The collection for settings related to SAML single sign-on. | 
| MSGraphApplication.servicePrincipalNames | String | The list of identifier URIs. | 
| MSGraphApplication.servicePrincipalType | String | Identifies if the service principal represents an application or a managed identity. | 
| MSGraphApplication.signInAudience | String | The audience that can sign in. | 
| MSGraphApplication.tokenEncryptionKeyId | String | The key ID of a public key from the key credentials. | 
| MSGraphApplication.verifiedPublisher.addedDateTime | Date | The timestamp when the verified publisher was first added or most recently updated. | 
| MSGraphApplication.verifiedPublisher.displayName | String | The verified publisher name from the application publisher's Partner Center account. | 
| MSGraphApplication.verifiedPublisher.verifiedPublisherId | String | The ID of the verified publisher from the application publisher's Partner Center account. | 


#### Command Example
```!msgraph-apps-service-principal-list limit=1```

#### Context Example
```json
{
    "MSGraphApplication": {
        "accountEnabled": true,
        "addIns": [],
        "alternativeNames": [],
        "appDescription": null,
        "appDisplayName": "Common Data Service",
        "appId": "00000007-0000-0000-c000-000000000000",
        "appOwnerOrganizationId": ":app-owner-organization-id:",
        "appRoleAssignmentRequired": false,
        "appRoles": [],
        "applicationTemplateId": null,
        "createdDateTime": "2019-12-11T11:35:03Z",
        "deletedDateTime": null,
        "description": null,
        "displayName": "Common Data Service",
        "homepage": null,
        "id": ":id:",
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
                "id": ":id:",
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
            "https://port.example.com/",
            "https://cloudredirector.example.com/"
        ],
        "servicePrincipalType": "Application",
        "signInAudience": "AzureADMultipleOrgs",
        "tags": [],
        "tokenEncryptionKeyId": null,
        "verifiedPublisher": {
            "addedDateTime": null,
            "displayName": null,
            "verifiedPublisherId": null
        }
    }
}
```

#### Human Readable Output

>### Available services (applications):
>|id|appId|appDisplayName|accountEnabled|
>|---|---|---|---|
>| :id: | 00000007-0000-0000-c000-000000000000 | Common Data Service | true |


### msgraph-apps-service-principal-remove
***
Removes an application from the directory.


#### Base Command

`msgraph-apps-service-principal-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the application to remove. Can be retrieved via the msgraph-apps-service-principal-remove command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-apps-service-principal-remove id=4d77f5f1-ec0b-482c-a4ae-1df6a50f19c2```

#### Human Readable Output
>Service 4d77f5f1-ec0b-482c-a4ae-1df6a50f19c2 was deleted.

