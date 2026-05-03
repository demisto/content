Use the Entra ID Applications integration (formerly Azure Active Directory Applications) to manage authorized applications.
This integration was integrated and tested with version xx of MicrosoftGraphApplications.

## Configure Entra ID Applications in Cortex


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

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-apps-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

#### Base Command

`msgraph-apps-auth-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-apps-auth-complete

***
Run this command to complete the authorization process. Should be used after running the msgraph-apps-auth-start command.

#### Base Command

`msgraph-apps-auth-complete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-apps-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`msgraph-apps-auth-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### msgraph-apps-auth-test

***
Tests connectivity to Microsoft.

#### Base Command

`msgraph-apps-auth-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
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
| MSGraphApplication.keyCredentials.startDateTime | Date | The date and time at which the credential expires.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
| MSGraphApplication.keyCredentials.endDateTime | Date | The date and time at which the credential becomes valid.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
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

### msgraph-apps-service-principal-remove

***
Removes an application from the directory.

#### Base Command

`msgraph-apps-service-principal-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The application id to remove. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 
| app_id | The application client id to remove. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 

#### Context Output

There is no context output for this command.
### msgraph-apps-service-principal-get

***
Retrieve the properties and relationships of a servicePrincipal object.

#### Base Command

`msgraph-apps-service-principal-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The application id to get. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 
| app_id | The application client id to get. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphApplication.keyCredentials.keyId | String | The unique identifier \(GUID\) for the key. | 
| MSGraphApplication.keyCredentials.customKeyIdentifier | String | Custom key identifier. | 
| MSGraphApplication.keyCredentials.displayName | String | Friendly name for the key. Optional. | 
| MSGraphApplication.keyCredentials.type | String | The type of key credential; for example, “Symmetric”. | 
| MSGraphApplication.keyCredentials.key | String | The certificate's raw data in byte array converted to Base64 string. | 
| MSGraphApplication.keyCredentials.usage | String | A string that describes the purpose for which the key can be used; for example, “Verify”. | 
| MSGraphApplication.keyCredentials.startDateTime | Date | The date and time at which the credential expires.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
| MSGraphApplication.keyCredentials.endDateTime | Date | The date and time at which the credential becomes valid.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
| MSGraphApplication.accountEnabled | Boolean | whether the application account is enabled. | 
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

### msgraph-apps-service-principal-update

***
Update the properties of servicePrincipal object.

#### Base Command

`msgraph-apps-service-principal-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The application id to update. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 
| app_id | The application client id to update. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 
| account_enabled | true if the service principal account is enabled; otherwise, false. Possible values are: true, false. | Optional | 
| app_role_assignment_required | Specifies whether an appRoleAssignment to a user or group is required before Microsoft Entra ID will issue a user or access token to the application. Not nullable. Possible values are: true, false. | Optional | 
| display_name | The display name for the service principal. | Optional | 
| preferred_single_sign_on_mode | Specifies the single sign-on mode configured for this application. Microsoft Entra ID uses the preferred single sign-on mode to launch the application from Microsoft 365 or the Microsoft Entra My Apps. The supported values are password, saml, and oidc. Possible values are: password, saml, oidc. | Optional | 
| reply_urls | A comma-separated list of the URLs that user tokens are sent to for sign in with the associated application, or the redirect URIs that OAuth 2.0 authorization codes and access tokens are sent to for the associated application. Not nullable. | Optional | 

#### Context Output

There is no context output for this command.
### msgraph-apps-service-principal-password-add

***
Add a strong password or secret to a service principal. To allow this command, use msgraph-apps-service-principal-unlock-configuration. The password will be expired in 1 hour by default.

#### Base Command

`msgraph-apps-service-principal-password-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The application id to add password. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 
| app_id | The application client id to add password. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 
| display_name | Friendly name for the password. Optional. | Optional | 
| end_date_time | The date and time at which the password expires represented using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Optional. The default value is "startDateTime + 1 hour". | Optional | 
| start_date_time | The date and time at which the password becomes valid. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Optional. The default value is "now". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphApplication.keyCredentials.customKeyIdentifier | String | Custom key identifier. | 
| MSGraphApplication.keyCredentials.endDateTime | Date | The date and time at which the credential becomes valid.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
| MSGraphApplication.keyCredentials.keyId | String | The unique identifier \(GUID\) for the key. | 
| MSGraphApplication.keyCredentials.startDateTime | Date | The date and time at which the credential expires.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
| MSGraphApplication.keyCredentials.displayName | String | Friendly name for the key. Optional. | 
| MSGraphApplication.keyCredentials.secretText | String | The strong passwords generated by Entra ID that are 16-64 characters in length. There is no way to retrieve this password in the future. | 
| MSGraphApplication.keyCredentials.hint | String | The secretText prefix. | 

### msgraph-apps-service-principal-password-remove

***
Remove a password from a service principal. To allow this command, use msgraph-apps-service-principal-unlock-configuration.

#### Base Command

`msgraph-apps-service-principal-password-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The application id to remove password. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 
| app_id | The application client id to remove password. Can be retrieved via the msgraph-apps-service-principal-list command. | Optional | 
| key_id | The unique identifier for the password. | Required | 

#### Context Output

There is no context output for this command.
### msgraph-apps-service-principal-unlock-configuration

***
Unlock configuration of a service principal.

#### Base Command

`msgraph-apps-service-principal-unlock-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The application object id (not the app id). | Required | 

#### Context Output

There is no context output for this command.
### msgraph-apps-service-principal-lock-configuration

***
Lock configuration of a service principal.

#### Base Command

`msgraph-apps-service-principal-lock-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The application object id (not the app id). | Required | 

#### Context Output

There is no context output for this command.
