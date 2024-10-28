# Microsoft Security & Compliance Center - Content Search Integration

This integration allows you to manage and interact with Microsoft Security & Compliance Center's content search capabilities. You can perform comprehensive searches across your organization’s emails, SharePoint sites, OneDrive accounts, and more. Actions like previewing and deleting emails are supported, making it easier to manage potential security threats.

This integration has been developed and tested with the [Security & Compliance Center](https://docs.microsoft.com/en-us/powershell/module/exchange/?view=exchange-ps#policy-and-compliance-content-search).

## Key Features

- **Content Search Management**: Create, modify, retrieve, list, remove, and trigger content searches within the Security & Compliance Center.
- **Search Actions**: Perform actions such as previewing and purging (deleting) emails identified in content searches.

## Playbooks

- **O365 - Security and Compliance - Search and Delete**: Initiates a compliance search and, if configured, deletes or previews identified emails.
- **O365 - Security and Compliance - Search**: Initiates a compliance search to locate emails with attributes matching those of a malicious email.
- **O365 - Security and Compliance - Search Action - Delete**: Deletes emails found by the search.
- **O365 - Security and Compliance - Search Action - Preview**: Provides a preview of emails identified by the search.

## Permissions Setup in the Security & Compliance Center

### Overview

To set up the integration and register the application in Azure, follow these steps:

1. **App Registration**: Register a new application in Azure Active Directory and configure necessary permissions.
2. **Authentication Configuration**: Enable public client flows and create an app secret.
3. **Role Setup**: Assign the required roles in the Security & Compliance Center for the integration to function correctly.

### Step-by-Step Instructions

#### 1. App Registration and Permission Configuration

1. **Navigate to Azure Portal**: Go to the [Azure Portal](https://portal.azure.com/) and sign in with your administrator account.
2. **Access App Registrations**: In the left-hand navigation pane, select **Azure Active Directory** > **App registrations**.
3. **Register a New App**: Click **New registration**, provide a name, and register the app.
4. **Add API Permissions**:
   - Under **Manage**, select **API permissions** > **Add a permission**.
   - Select **APIs my organization uses**.
   - Search for "Office 365 Exchange Online".
   - Select **Delegated permissions** and search for `Exchange.Manage`.
   - Check the box and click **Add permissions**.
   - Ensure the permissions are granted by selecting **Grant admin consent for [Your Organization]**.

#### 2. Enable "Allow Public Client Flows"

1. **Navigate to Authentication Settings**: In your app registration, select **Authentication** under **Manage**.
2. **Enable Public Client Flows**:
   - Scroll to **Advanced settings**.
   - Set **Allow public client flows** to **Yes**.
   - Click **Save** to apply the changes.

#### 3. Add an App Secret

1. **Navigate to Certificates & Secrets**: In your app registration, select **Certificates & secrets** under **Manage**.
2. **Add a Client Secret**:
   - Click **New client secret**.
   - Provide a description and select an expiration period.
   - Click **Add** and immediately copy the secret value for future use.

### Authentication Requirements

To access the Security & Compliance Center, the account used must either have global administrator permissions or the Role Management role, assigned within the Organization Management role group. This role allows users to view, create, and modify role groups. 

**Note:** The account used by the integration does not require Global Administrator permissions.

1. **Login to the [Compliance Center](https://compliance.microsoft.com/)**.
2. **Set Up Roles**:
   - Navigate to **Role & Scopes** > **Permissions** under **Microsoft Purview solutions** > **Roles**.
   - Click **Create role group**.
   - Provide a name and optional description.
   - Click **Choose roles** and select the necessary roles (e.g., Case Management, Compliance Search, Search And Purge).
   - Click **Choose users** to assign users to the role group.
   - Click **Create**.

The username and password for the user you intend to use must be added to the **UPN/Email** and **Delegated Password** fields in the integration instance configuration.

**Important:** Ensure that the connection is secure, as disabling certificate verification is not supported.

### Known Endpoints

| Environment                        | ConnectionUri                                                         | AzureADAuthorizationEndpointUri   |
|------------------------------------|-----------------------------------------------------------------------|-----------------------------------|
| Microsoft 365 or Microsoft 365 GCC | https://ps.compliance.protection.outlook.com/powershell-liveid/       | https://login.microsoftonline.com |
| Microsoft 365 GCC High             | https://ps.compliance.protection.office365.us/powershell-liveid/      | https://login.microsoftonline.us  |
| Microsoft 365 DoD                  | https://l5.ps.compliance.protection.office365.us/powershell-liveid/   | https://login.microsoftonline.us  |
| Office 365 operated by 21Vianet    | https://ps.compliance.protection.partner.outlook.cn/powershell-liveid | https://login.chinacloudapi.cn    |

[More information available here](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps#step-2-connect-and-authenticate).

## Configure SecurityAndComplianceV2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **O365 - Security and Compliance - Content Search**.
3. Authentication / Authorization methods:
   1. Click **Add instance** to create and configure a new integration instance.

      | **Parameter**   | **Description**                                                   | **Required** |
      | --------------- | ----------------------------------------------------------------- | ------------ |
      | url             | Search and Compliance URL.                                         | True         |
      | App Secret      | The client secret created in Azure.                                | True         |
      | App ID          | The application (client) ID from Azure                            | True         |
      | Tenant ID       | The directory (tenant) ID from Azure.                              | True         |
      | Organization    | The organization name for the Security & Compliance Center.        | True         |
      | UPN/Email       | The email address (UPN) of the user account for the integration.   | True         |
      | Insecure        | Trust any certificate (not secure).                                | False        |

   2. Open the War Room in the playground.
   3. Run the `!o365-sc-auth-start` command and follow the instructions.

   **Expected Output:**

   >    ## Security and Compliance - Authorize Instructions
   >
   >    1. To sign in, open [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) in a web browser and enter the code **XXXXXXX** to authenticate.
   >    2. Run the `!o365-sc-auth-complete` command in the War Room.

   4. Test OAuth2.0 authorization by running the `!o365-sc-auth-test` command.


## Troubleshooting and Testing

### Common Issues and Solutions

#### `Response status code does not indicate success: 404 Not Found`

**Scenario:** When running the `!o365-sc-auth-start` command, you may encounter the error message: "Response status code does not indicate success: 404 Not Found."

**Solution:**
**Verify Required Parameters:** Ensure that all required parameters in the integration instance configuration are correctly filled out. This includes:
- **URL**: Ensure the correct URL is provided for the Security & Compliance Center.
- **App Secret**: The client secret created in Azure.
- **App ID**: The application (client) ID from Azure.
- **Tenant ID**: The directory (tenant) ID from Azure.
- **Organization**: The organization name for the Security & Compliance Center.
- **UPN/Email**: The email address (UPN) of the user account for the integration.
  
Missing or incorrect values in these fields can cause a 404 error, as the integration might be attempting to connect to an incorrect or non-existent endpoint.

**Additional Steps:**
- **Check the ConnectionUri**: Verify that the `ConnectionUri` in your configuration matches the environment you are operating in (e.g., Microsoft 365, GCC High, DoD, etc.).
- **Review Endpoint Configuration**: Ensure that the `AzureADAuthorizationEndpointUri` is correctly set according to your environment.

#### `Response status code does not indicate success: 400 Bad Request`

**Scenario:** When running the `!o365-sc-auth-start` command, you may encounter the error message: "Response status code does not indicate success: 400 Bad Request."

**Solution:**
**Check Parameters for Accuracy:** A 400 Bad Request error often indicates that there is a problem with the request sent to the server. Double-check the following:
- **App ID and Tenant ID**: Ensure these are correctly copied from your Azure app registration.
- **App Secret**: Verify that the secret has been correctly entered and has not expired.
- **UPN/Email**: Ensure that the email address is correctly formatted and belongs to a user with the necessary permissions.

**Additional Steps:**
**Test with a Different Account**: If possible, try using a different user account to verify if the issue is related to specific user permissions.

#### Failed OAuth2.0 Authorization

**Scenario:** After running the `!o365-sc-auth-start` command, the authorization process fails, and the integration cannot authenticate with the Security & Compliance Center.

**Solution:**
- **Double-Check App Permissions**: Make sure that the app registration in Azure has the necessary permissions, specifically `Exchange.ManageAsApp`.
- **Grant Admin Consent**: Ensure that admin consent has been granted for the required permissions. Without this, the application cannot function correctly.
- **Review Authentication Setup**: Ensure that "Allow public client flows" is enabled in the Azure app registration settings under **Authentication**.

**Additional Steps:**
- **Use the `!o365-sc-auth-test` Command**: Run this command to verify if the integration can successfully authenticate. If this test fails, revisit the app registration settings and verify all configurations.

### Testing the Integration

1. **Test Basic Connectivity**:
   Use the `!o365-sc-auth-test` command to confirm that the integration can successfully authenticate with the Security & Compliance Center.

2. **Run a Simple Search**:
   Execute the `!o365-sc-search` command with basic parameters to ensure the integration can perform a search operation. This helps verify that the configuration is correct and the integration can communicate with the Security & Compliance Center.

3. **Check Logs and Outputs**:
   After running test commands, review the logs and command outputs in the War Room for any errors or warnings. This can provide additional insights into what might be going wrong.

4. **Review Azure Logs**:
   If issues persist, review the logs in Azure to identify any access issues or authentication errors. This can help diagnose problems related to Azure AD configuration.

### Additional Resources

- **Microsoft 365 Compliance Documentation**:
   [Troubleshoot content search issues](https://docs.microsoft.com/en-us/microsoft-365/compliance/content-search-troubleshoot)

- **Azure AD Troubleshooting**:
  - [Azure AD Sign-in Logs](https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-sign-ins)
  - [OAuth2.0 Authorization Troubleshooting](https://docs.microsoft.com/en-us/azure/active-directory/develop/troubleshoot-oauth2-authorization-code-grant-flow)


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### o365-sc-auth-start
***
OAuth2.0 - Start authorization.


#### Base Command

`o365-sc-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!o365-sc-auth-start```

#### Human Readable Output

>## Security And Compliance - Authorize instructions
>1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin) and enter the code **XXXXXXX** to authenticate.
>2. Run the ***!o365-sc-auth-complete*** command in the War Room.


### o365-sc-auth-complete
***
OAuth2.0 - Complete authorization.


#### Base Command

`o365-sc-auth-complete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!o365-sc-auth-complete```

#### Human Readable Output

>Your account **successfully** authorized!



### o365-sc-auth-test
***
OAuth2.0 - Test authorization.


#### Base Command

`o365-sc-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!o365-sc-auth-test```

#### Human Readable Output

>**Test ok!**


### o365-sc-new-search
***
Create compliance search in the Security & Compliance Center.


#### Base Command

`o365-sc-new-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | The name of the compliance search. If not specified, will have the prefix "XSOAR-" followed by the GUID e.g., XSOAR-d6228fd0-756b-4e4b-8721-76776df91526. | Required |
| case | The name of a Core eDiscovery case to associate with the new compliance search. | Optional |
| kql | Text search string or a query that is formatted using the Keyword Query Language (KQL). [Tips for finding messages to remove using KQL](#tips-for-finding-messages-to-remove)
| Optional |
| description | Description of the compliance search. | Optional |
| allow_not_found_exchange_locations | Whether to include mailboxes other than regular user mailboxes in the compliance search. Default is "false". | Optional |
| exchange_location | Comma-separated list of mailboxes/distribution groups to include, or you can use the value "All" to include all. | Optional |
| exchange_location_exclusion | Comma-separated list of mailboxes/distribution groups to exclude when you use the value "All" for the exchange_location parameter. Deprecated since Microsoft is supporting it only on-premise. | Optional |
| public_folder_location | Comma-separated list of public folders to include, or you can use the value "All" to include all. | Optional |
| share_point_location | Comma-separated list of SharePoint online sites to include. You can identify the sites by their URL value, or you can use the value "All" to include all sites. | Optional |
| share_point_location_exclusion | Comma-separated list of SharePoint online sites to exclude when you use the value "All" for the share_point_location argument. You can identify the sites by their URL value. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.ContentSearch.Search.AllowNotFoundExchangeLocationsEnabled | Boolean | Whether to include mailboxes other than regular user mailboxes in the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.AzureBatchFrameworkEnabled | Boolean | Whether the Azure Batch Framework is enabled for job processing. |
| O365.SecurityAndCompliance.ContentSearch.Search.CaseId | String | Identity of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.CaseName | String | Name of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.ContentMatchQuery | String | Compliance text search string or a query that is formatted using the Keyword Query Language \(KQL\). |
| O365.SecurityAndCompliance.ContentSearch.Search.CreatedBy | String | Security and compliance search creator. |
| O365.SecurityAndCompliance.ContentSearch.Search.CreatedTime | Date | Security and compliance search creation time. |
| O365.SecurityAndCompliance.ContentSearch.Search.Description | String | Security and compliance search description. |
| O365.SecurityAndCompliance.ContentSearch.Search.Errors | String | Security and compliance search errors. |
| O365.SecurityAndCompliance.ContentSearch.Search.ExchangeLocation | String | Security and compliance search exchange locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.Identity | String | Security and compliance search identity. |
| O365.SecurityAndCompliance.ContentSearch.Search.IsValid | Boolean | Whether the security and compliance search is valid. |
| O365.SecurityAndCompliance.ContentSearch.Search.Items | Number | The number of security and compliance search scanned items. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobEndTime | Date | Security and compliance search job end time. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobId | String | Security and compliance search job ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobRunId | String | Security and compliance search job run ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobStartTime | Date | Security and compliance search job run start time. |
| O365.SecurityAndCompliance.ContentSearch.Search.LastModifiedTime | Date | Security and compliance search last modification time. |
| O365.SecurityAndCompliance.ContentSearch.Search.LogLevel | String | Security and compliance search Azure log level. |
| O365.SecurityAndCompliance.ContentSearch.Search.Name | String | Security and compliance search name. |
| O365.SecurityAndCompliance.ContentSearch.Search.OneDriveLocation | String | Security and compliance search OneDrive locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.OneDriveLocationExclusion | String | Security and compliance search OneDrive locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.Search.PublicFolderLocation | String | Security and compliance search public folder locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.PublicFolderLocationExclusion | String | Security and compliance search public folder locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.Search.RunBy | String | Security and compliance search last run by UPN \(Email representation\). |
| O365.SecurityAndCompliance.ContentSearch.Search.RunspaceId | String | Security and compliance search run space ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.SharePointLocation | String | Security and compliance search SharePoint locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.Size | Number | Security and compliance search bytes results size. |
| O365.SecurityAndCompliance.ContentSearch.Search.Status | String | Security and compliance search status. |
| O365.SecurityAndCompliance.ContentSearch.Search.TenantId | String | Security and compliance search Tenant ID. |


#### Command Example
```!o365-sc-new-search search_name="example" exchange_location="user1@demistodev.onmicrosoft.com,user2@demistodev.onmicrosoft.com" allow_not_found_exchange_locations=true kql="Rodrigo"```

#### Context Example
```json
{
    "O365": {
        "SecurityAndCompliance": {
            "ContentSearch": {
                "Search": {
                    "AllowNotFoundExchangeLocationsEnabled": true,
                    "AzureBatchFrameworkEnabled": false,
                    "CaseId": null,
                    "CaseName": "",
                    "ContentMatchQuery": "Rodrigo",
                    "CreatedBy": "XSOAR-user",
                    "CreatedTime": "2020-11-29T07:12:46.5943533Z",
                    "Description": "Short description",
                    "Errors": null,
                    "ExchangeLocation": [
                        "test1@onmicrosoft.com",
                        "test2@onmicrosoft.com"
                    ],
                    "ExchangeLocationExclusion": [],
                    "Identity": "xxxxx",
                    "IsValid": true,
                    "Items": 0,
                    "JobEndTime": null,
                    "JobId": "xxxxx",
                    "JobRunId": null,
                    "JobStartTime": null,
                    "LastModifiedTime": "2020-11-29T07:12:46.5943533Z",
                    "LogLevel": "Suppressed",
                    "Name": "example",
                    "OneDriveLocation": null,
                    "OneDriveLocationExclusion": null,
                    "PublicFolderLocation": null,
                    "PublicFolderLocationExclusion": null,
                    "RunBy": "",
                    "RunspaceId": null,
                    "SharePointLocation": null,
                    "SharePointLocationExclusion": null,
                    "Size": 0,
                    "Status": "NotStarted",
                    "SuccessResults": null,
                    "TenantId": "xxxxx"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Security And Compliance - New search 'example' created
>| ContentMatchQuery | CreatedBy | Description | LastModifiedTime | Name
>| --- | --- | --- | --- | ---
>| Rodrigo | XSOAR-user | Short description | 11/29/2020 7:12:46 AM | example



### o365-sc-set-search

***
Modifies non-running compliance searches in the Security & Compliance Center.


#### Base Command

`o365-sc-set-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | The name of the compliance search. | Required |
| kql | Modify the text search string or a query that is formatted using the Keyword Query Language (KQL). | Optional |
| description | Modify the description for the compliance search. | Optional |
| allow_not_found_exchange_locations | Whether to include mailboxes other than regular user mailboxes in the compliance search. | Optional |
| add_exchange_location | Comma-separated list of added mailboxes/distribution groups to include, or you can use the value "All" to include all mailboxes. | Optional |
| add_exchange_location_exclusion | Comma-separated list of added mailboxes/distribution groups to exclude when you use the value "All" for the exchange_location (used in create new compliance search) or the add_exchange_location argument. | Optional |
| add_public_folder_location | Comma-separated list of added public folders to include, or you can use the value "All" to include all. | Optional |
| add_share_point_location | Comma-separated list of added SharePoint online sites to include. You identify the sites by their URL value, or you can use the value "All" to include all sites. | Optional |
| add_share_point_location_exclusion | Comma-separated list of added SharePoint online sites to exclude when you use the value "All" for the exchange_location (used in create new compliance search) argument or the share_point_location argument. You can identify the sites by their URL value. | Optional |
| remove_exchange_location | Comma-separated list of removed mailboxes/distribution group to include. | Optional |
| remove_exchange_location_exclusion | Comma-separated list of removed mailboxes/distribution group to exclude when you use the value "All" for the exchange_location (Used in create new compliance search) or the add_exchange_location argument. | Optional |
| remove_public_folder_location | Comma-separated list of removed public folders to include. | Optional |
| remove_share_point_location | Comma-separated list of removed SharePoint online sites to include. You can identify the sites by their URL value. | Optional |
| remove_share_point_location_exclusion | Comma-separated list of removed SharePoint online sites to exclude when you use the value "All" for the exchange_location (Used in create new compliance search) argument or the share_point_location argument. You can identify the sites by their URL value. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example
```!o365-sc-set-search search_name="example" remove_exchange_location="test2@demistodev.onmicrosoft.com"```

#### Human Readable Output

>Security And Compliance - Search **example** modified!



### o365-sc-remove-search

***
Remove compliance search by name from the Security & Compliance Center.


#### Base Command

`o365-sc-remove-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | The name of the compliance search. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!o365-sc-remove-search search_name="example"```

#### Human Readable Output

>Security And Compliance - Search **example** removed!



### o365-sc-list-search

***
List compliance searches in the Security & Compliance Center.


#### Base Command

`o365-sc-list-search`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.ContentSearch.Search.AllowNotFoundExchangeLocationsEnabled | Boolean | Whether to include mailboxes other than regular user mailboxes in the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.AzureBatchFrameworkEnabled | Boolean | Whether the Azure Batch Framework is enabled for job processing. |
| O365.SecurityAndCompliance.ContentSearch.Search.CaseId | String | Identity of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.CaseName | String | Name of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.ContentMatchQuery | String | Compliance text search string or a query that is formatted using the Keyword Query Language \(KQL\). |
| O365.SecurityAndCompliance.ContentSearch.Search.CreatedBy | String | Security and compliance search creator. |
| O365.SecurityAndCompliance.ContentSearch.Search.CreatedTime | Date | Security and compliance search creation time. |
| O365.SecurityAndCompliance.ContentSearch.Search.Description | String | Security and compliance search description. |
| O365.SecurityAndCompliance.ContentSearch.Search.Errors | String | Security and compliance search errors. |
| O365.SecurityAndCompliance.ContentSearch.Search.ExchangeLocation | String | Security and compliance search exchange locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.Identity | String | Security and compliance search identity. |
| O365.SecurityAndCompliance.ContentSearch.Search.IsValid | Boolean | Whether the security and compliance search is valid. |
| O365.SecurityAndCompliance.ContentSearch.Search.Items | Number | The number of security and compliance search scanned items. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobEndTime | Date | Security and compliance search job end time. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobId | String | Security and compliance search job ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobRunId | String | Security and compliance search job run ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobStartTime | Date | Security and compliance search job run start time. |
| O365.SecurityAndCompliance.ContentSearch.Search.LastModifiedTime | Date | Security and compliance search last modification time. |
| O365.SecurityAndCompliance.ContentSearch.Search.LogLevel | String | Security and compliance search Azure log level. |
| O365.SecurityAndCompliance.ContentSearch.Search.Name | String | Security and compliance search name. |
| O365.SecurityAndCompliance.ContentSearch.Search.OneDriveLocation | String | Security and compliance search OneDrive locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.OneDriveLocationExclusion | String | Security and compliance search OneDrive locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.Search.PublicFolderLocation | String | Security and compliance search public folder locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.PublicFolderLocationExclusion | String | Security and compliance search public folder locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.Search.RunBy | String | Security and compliance search last run by UPN \(Email representation\). |
| O365.SecurityAndCompliance.ContentSearch.Search.RunspaceId | String | Security and compliance search run space ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.SharePointLocation | String | Security and compliance search SharePoint locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.Size | Number | Security and compliance search bytes results size. |
| O365.SecurityAndCompliance.ContentSearch.Search.Status | String | Security and compliance search status. |
| O365.SecurityAndCompliance.ContentSearch.Search.TenantId | String | Security and compliance search Tenant ID. |


#### Command Example
```!o365-sc-list-search```

#### Context Example
```json
{
    "O365": {
        "SecurityAndCompliance": {
            "ContentSearch": {
                "Search": [
                    {
                        "AllowNotFoundExchangeLocationsEnabled": false,
                        "AzureBatchFrameworkEnabled": false,
                        "CaseId": null,
                        "CaseName": "",
                        "ContentMatchQuery": "subject:test",
                        "CreatedBy": "XSOAR-user1",
                        "CreatedTime": "2019-08-22T06:43:48.747",
                        "Description": "Short description",
                        "Errors": null,
                        "ExchangeLocation": null,
                        "ExchangeLocationExclusion": null,
                        "Identity": "xxxxx",
                        "IsValid": true,
                        "Items": 0,
                        "JobEndTime": "2019-09-05T13:21:11.563",
                        "JobId": "xxxx",
                        "JobRunId": null,
                        "JobStartTime": "2019-09-05T13:20:34.633",
                        "LastModifiedTime": "2019-08-22T06:43:48.747",
                        "LogLevel": "Suppressed",
                        "Name": "example1",
                        "OneDriveLocation": null,
                        "OneDriveLocationExclusion": null,
                        "PublicFolderLocation": null,
                        "PublicFolderLocationExclusion": null,
                        "RunBy": "XSOAR-user1",
                        "RunspaceId": null,
                        "SharePointLocation": null,
                        "SharePointLocationExclusion": null,
                        "Size": 0,
                        "Status": "Completed",
                        "SuccessResults": null,
                        "TenantId": "xxxx"
                    },
                    {
                        "AllowNotFoundExchangeLocationsEnabled": false,
                        "AzureBatchFrameworkEnabled": false,
                        "CaseId": null,
                        "CaseName": "",
                        "ContentMatchQuery": "subject:Incident Summary Report",
                        "CreatedBy": "XSOAR-user2",
                        "CreatedTime": "2020-01-08T00:44:30.94",
                        "Description": "Short description",
                        "Errors": null,
                        "ExchangeLocation": null,
                        "ExchangeLocationExclusion": null,
                        "Identity": "xxxxx",
                        "IsValid": true,
                        "Items": 0,
                        "JobEndTime": "2020-01-08T00:45:13.433",
                        "JobId": "xxxxx",
                        "JobRunId": null,
                        "JobStartTime": "2020-01-08T00:44:33.717",
                        "LastModifiedTime": "2020-01-08T00:44:30.94",
                        "LogLevel": "Suppressed",
                        "Name": "example2",
                        "OneDriveLocation": null,
                        "OneDriveLocationExclusion": null,
                        "PublicFolderLocation": null,
                        "PublicFolderLocationExclusion": null,
                        "RunBy": "XSOAR-user2",
                        "RunspaceId": null,
                        "SharePointLocation": null,
                        "SharePointLocationExclusion": null,
                        "Size": 0,
                        "Status": "Completed",
                        "SuccessResults": null,
                        "TenantId": "xxxxx"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Security And Compliance - Search configurations
>| CreatedBy | Description | LastModifiedTime | Name | RunBy
>| --- | --- | --- | --- | ---
>| XSOAR-user1 | Short description | 8/22/2019 6:43:48 AM | example1 | XSOAR-user1
>| XSOAR-user2 | Short description | 1/8/2020 12:44:30 AM | example2 | XSOAR-user2


### o365-sc-get-search
***
Gets compliance search by name from the Security & Compliance Center.


#### Base Command

`o365-sc-get-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | The name of the compliance search. | Required |
| limit | The maximum number of results to return. If you want to return all requests that match the query, use "-1" for the value of this argument. | Optional |
| all_results | Whether to include mailboxes which have no results in results entry context. | Optional |
| export | Whether to export search results as json file to war-room. | Optional |
| statistics | Show search statistics. Default is "false". | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.ContentSearch.Search.AllowNotFoundExchangeLocationsEnabled | Boolean | Whether to include mailboxes other than regular user mailboxes in the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.AzureBatchFrameworkEnabled | Boolean | Whether the Azure Batch Framework is enabled for job processing. |
| O365.SecurityAndCompliance.ContentSearch.Search.CaseId | String | Identity of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.CaseName | String | Name of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.Search.ContentMatchQuery | String | Compliance text search string or a query that is formatted using the Keyword Query Language \(KQL\). |
| O365.SecurityAndCompliance.ContentSearch.Search.CreatedBy | String | Security and compliance search creator. |
| O365.SecurityAndCompliance.ContentSearch.Search.CreatedTime | Date | Security and compliance search creation time. |
| O365.SecurityAndCompliance.ContentSearch.Search.Description | String | Security and compliance search description. |
| O365.SecurityAndCompliance.ContentSearch.Search.Errors | String | Security and compliance search errors. |
| O365.SecurityAndCompliance.ContentSearch.Search.ExchangeLocation | String | Security and compliance search exchange locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.Identity | String | Security and compliance search identity. |
| O365.SecurityAndCompliance.ContentSearch.Search.IsValid | Boolean | Whether the security and compliance search is valid. |
| O365.SecurityAndCompliance.ContentSearch.Search.Items | Number | Number of security and compliance search scanned items. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobEndTime | Date | Security and compliance search job end time. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobId | String | Security and compliance search job ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobRunId | String | Security and compliance search job run ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.JobStartTime | Date | Security and compliance search job run start time. |
| O365.SecurityAndCompliance.ContentSearch.Search.LastModifiedTime | Date | Security and compliance search last modification time. |
| O365.SecurityAndCompliance.ContentSearch.Search.LogLevel | String | Security and compliance search the Azure log level. |
| O365.SecurityAndCompliance.ContentSearch.Search.Name | String | Security and compliance search name. |
| O365.SecurityAndCompliance.ContentSearch.Search.OneDriveLocation | String | Security and compliance search OneDrive locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.OneDriveLocationExclusion | String | Security and compliance search OneDrive locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.Search.PublicFolderLocation | String | Security and compliance search public folder locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.PublicFolderLocationExclusion | String | Security and compliance search public folder locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.Search.RunBy | String | Security and compliance search last run by UPN \(Email representation\). |
| O365.SecurityAndCompliance.ContentSearch.Search.RunspaceId | String | Security and compliance search run space ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.SharePointLocation | String | Security and compliance search SharePoint locations to include. |
| O365.SecurityAndCompliance.ContentSearch.Search.Size | Number | Security and compliance search bytes results size. |
| O365.SecurityAndCompliance.ContentSearch.Search.Status | String | Security and compliance search status. |
| O365.SecurityAndCompliance.ContentSearch.Search.TenantId | String | Security and compliance search Tenant ID. |
| O365.SecurityAndCompliance.ContentSearch.Search.SuccessResults.Location | String | Security and compliance search result location. |
| O365.SecurityAndCompliance.ContentSearch.Search.SuccessResults.ItemsCount | Number | The number of security and compliance search results in location. |
| O365.SecurityAndCompliance.ContentSearch.Search.SuccessResults.Size | Number | The byte size of the security and compliance search results in location. |


#### Command Example
```!o365-sc-get-search search_name="example"```

#### Context Example
```json
{
    "O365": {
        "SecurityAndCompliance": {
            "ContentSearch": {
                "Search": {
                    "Errors": "", 
                    "AzureBatchFrameworkEnabled": false,
                    "TenantId": "xxxxx", 
                    "SharePointLocationExclusion": null, 
                    "JobStartTime": "2020-11-29T07:20:59.37", 
                    "CreatedTime": "2020-11-29T07:18:04.283", 
                    "OneDriveLocation": null, 
                    "PublicFolderLocation": null, 
                    "Status": "Completed", 
                    "CaseName": "", 
                    "AllowNotFoundExchangeLocationsEnabled": false, 
                    "LogLevel": "Suppressed", 
                    "JobRunId": null, 
                    "CaseId": null, 
                    "JobId": "xxxxx", 
                    "SuccessResults": {
                        "ItemsCount": "122303", 
                        "Location": "user@onmicrosoft.com", 
                        "Size": "12339007379"
                    }, 
                    "LastModifiedTime": "2020-11-29T07:20:43.283", 
                    "Identity": "1d130723-fe0a-4726-6d2a-08d89437520e", 
                    "Name": "example", 
                    "Items": 122303, 
                    "ExchangeLocation": [
                        "user@onmicrosoft.com"
                    ], 
                    "RunBy": "XSOAR-user", 
                    "Description": "Short description", 
                    "ExchangeLocationExclusion": [], 
                    "IsValid": true, 
                    "PublicFolderLocationExclusion": null, 
                    "SharePointLocation": null, 
                    "CreatedBy": "XSOAR-user", 
                    "JobEndTime": "2020-11-29T07:22:01.99", 
                    "RunspaceId": null, 
                    "Size": 12339007379, 
                    "OneDriveLocationExclusion": null, 
                    "ContentMatchQuery": "Rodrigo"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Security And Compliance - 'example' search
>| CreatedBy | Description | LastModifiedTime | Name | RunBy | Status
>| --- | --- | --- | --- | --- | ---
>| XSOAR-user | Short description | 2020-11-29T07:20:43.283 | example | XSOAR-user | NotStarted


### o365-sc-start-search
***
Starts stopped, completed, or not started compliance search in the Security & Compliance Center.


#### Base Command

`o365-sc-start-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | The name of the compliance search. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!o365-sc-start-search search_name="example"```

#### Human Readable Output

>Security And Compliance - search **example** started !

### o365-sc-stop-search
***
Stop running compliance search in the Security & Compliance Center.


#### Base Command

`o365-sc-stop-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | The name of the compliance search. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!o365-sc-stop-search search_name="example"```

#### Human Readable Output

>Security And Compliance - search **example** stopped !


### o365-sc-new-search-action
***
After you create a content search using the ***o365-sc-new-search*** command and run it using the ***o365-sc-start-search*** command, you assign a search action to the search using the ***o365-sc-new-search-action*** command.

Please note that when performing the *Delete* action, items which are deleted will still follow your EWS365 data retention policies. Some data retention policies will move emails to the "Purges" or "Recoverable Items" folder.


#### Base Command

`o365-sc-new-search-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_name | The name of the compliance search. | Required | 
| action | Search action to perform. Possible values are: Preview, Purge, Export. Default is Preview. | Optional | 
| purge_type | Purge type. Possible values are: SoftDelete, HardDelete. Default is SoftDelete. | Optional | 
| share_point_archive_format | Specifies how to export SharePoint and OneDrive search results. Possible values are: IndividualMessage, PerUserZip, SingleZip. IndividualMessage: Export the files uncompressed. This is the default value. PerUserZip: One ZIP file for each user. Each ZIP file contains the exported files for the user. SingleZip: One ZIP file for all users. The ZIP file contains all exported files from all users. This output setting is available only in PowerShell. To specify the format for Exchange search results, use the exchange_archive_format parameter.  | Optional | 
| format | The Format parameter specifies the format of the search results when you use the Export action. Valid values are: FxStream: Export to PST files. This is the only option that's available when you export search results from the Microsoft Purview compliance portal. Mime: Export to .eml message files. This is the default value when you use cmdlets to export the search results. Msg: Export to .msg message files. Possible values are: FxStream, Mime, Msg. | Optional | 
| include_sharepoint_document_versions | Specifies whether to export previous versions of the document when you use the Export action. Possible values are: true, false. | Optional | 
| notify_email | Specifies the email address target for the search results when you use the Export action. | Optional | 
| notify_email_cc | Specifies the cc email address target for the search results when you use the Export action. | Optional | 
| scenario | Specifies the scenario type when you use the Export action. Possible values are: AnalyzeWithZoom, General, GenerateReportsOnly, Inventory, RetentionReports, TriagePreview. | Optional | 
| scope | Specifies the items to include when the action is Export. Possible values are: IndexedItemsOnly, UnindexedItemsOnly, BothIndexedAndUnindexedItems. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Action | String | Security and compliance search action type. Either "Purge" or "Preview". |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.AllowNotFoundExchangeLocationsEnabled | Boolean | Whether to include mailboxes other than regular user mailboxes in the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.AzureBatchFrameworkEnabled | Boolean | Whether the Azure Batch Framework is enabled for job processing. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CaseId | String | Identity of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CaseName | String | Name of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CreatedBy | String | Security and compliance search action creator. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CreatedTime | Date | Security and compliance search action creation time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Description | String | Security and compliance search action description. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Errors | String | Security and compliance search action errors. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.EstimateSearchJobId | String | Security and compliance search action job ID estimation. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.EstimateSearchRunId | String | Security and compliance search action run ID estimation. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.ExchangeLocation | String | Security and compliance search action exchange locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.ExchangeLocationExclusion | String | Security and compliance search action exchange locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Identity | String | Security and compliance search action identity. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.IsValid | Boolean | Whether the security and compliance search action is valid. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobEndTime | Date | Security and compliance search action job end time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobId | String | Security and compliance search action job ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobRunId | String | Security and compliance search action job run ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobStartTime | Date | Security and compliance search action job start time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.LastModifiedTime | Date | Security and compliance search action last modified time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Name | String | Security and compliance search action name. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.PublicFolderLocation | String | Security and compliance search action public folder locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.PublicFolderLocationExclusion | String | Security and compliance search action public folder locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Retry | Boolean | Whether to retry if the search action failed. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.RunBy | String | Security and compliance search action run by UPN \(email address\). |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.RunspaceId | String | Security and compliance search action run space ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SearchName | String | Security and compliance search action search name. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SharePointLocation | String | Security and compliance search action SharePoint locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SharePointLocationExclusion | String | Security and compliance search action SharePoint locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Status | String | Security and compliance search action status. Either "Started" or "Completed". |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.TenantId | String | Security and compliance search action Tenant ID. |


#### Command Example
```!o365-sc-new-search-action search_name="example" action="Preview"```

#### Context Example
```json
{
    "O365": {
        "SecurityAndCompliance": {
            "ContentSearch": {
                "SearchAction": {
                    "Action": "Preview",
                    "AllowNotFoundExchangeLocationsEnabled": false,
                    "AzureBatchFrameworkEnabled": false,
                    "CaseId": null,
                    "CaseName": "",
                    "CreatedBy": "XSOAR-user",
                    "CreatedTime": "2020-11-29T07:23:50.05",
                    "Description": "",
                    "Errors": "",
                    "EstimateSearchJobId": "xxxxx",
                    "EstimateSearchRunId": "xxxxx",
                    "ExchangeLocation": [
                        "user@onmicrosoft.com"
                    ],
                    "ExchangeLocationExclusion": null,
                    "Identity": "xxxxx",
                    "IsValid": true,
                    "JobEndTime": "2020-11-29T07:24:05.76",
                    "JobId": "xxxxx",
                    "JobRunId": "xxxxx",
                    "JobStartTime": "2020-11-29T07:23:50.297",
                    "LastModifiedTime": "2020-11-29T07:23:50.05",
                    "Name": "example_Preview",
                    "PublicFolderLocation": null,
                    "PublicFolderLocationExclusion": null,
                    "Results": null,
                    "Retry": false,
                    "RunBy": "XSOAR-user",
                    "RunspaceId": "xxxxx",
                    "SearchName": "example",
                    "SharePointLocation": null,
                    "SharePointLocationExclusion": null,
                    "Status": "Completed",
                    "TenantId": "xxxxx"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Security And Compliance - search action 'example_Preview' created
>| Action | LastModifiedTime | Name | RunBy | SearchName | Status
>| --- | --- | --- | --- | --- | ---
>| Preview | 11/29/2020 7:23:50 AM | example\_Preview | XSOAR-user | example | Completed


### o365-sc-remove-search-action
***
Removes compliance search action by search the action name from the Security & Compliance Center.


#### Base Command

`o365-sc-remove-search-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_action_name | The name of the compliance search action. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!o365-sc-remove-search-action search_action_name="example_Preview"```

#### Human Readable Output

>Security And Compliance - search action **example_Preview** removed!

### o365-sc-list-search-action
***
Lists compliance search actions from the Security & Compliance Center.


#### Base Command

`o365-sc-list-search-action`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Action | String | Security and compliance search action type. Either "Purge or "Preview". |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.AllowNotFoundExchangeLocationsEnabled | Boolean | Whether to include mailboxes other than regular user mailboxes in the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.AzureBatchFrameworkEnabled | Boolean | Whether the Azure Batch Framework is enabled for job processing. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CaseId | String | Identity of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CaseName | String | Name of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CreatedBy | String | Security and compliance search action creator. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CreatedTime | Date | Security and compliance search action creation time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Description | String | Security and compliance search action description. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Errors | String | Security and compliance search action errors. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.EstimateSearchJobId | String | Security and compliance search action job ID estimation. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.EstimateSearchRunId | String | Security and compliance search action run ID estimation. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.ExchangeLocation | String | Security and compliance search action exchange locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.ExchangeLocationExclusion | String | Security and compliance search action exchange locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Identity | String | Security and compliance search action identity. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.IsValid | Boolean | Whether the security and compliance search action is valid. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobEndTime | Date | Security and compliance search action job end time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobId | String | Security and compliance search action job ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobRunId | String | Security and compliance search action job run ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobStartTime | Date | Security and compliance search action job start time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.LastModifiedTime | Date | Security and compliance search action last modified time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Name | String | Security and compliance search action name. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.PublicFolderLocation | String | Security and compliance search action public folder locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.PublicFolderLocationExclusion | String | Security and compliance search action public folder locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Retry | Boolean | Whether to retry if the search action failed. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.RunBy | String | Security and compliance search action run by UPN \(email address\). |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.RunspaceId | String | Security and compliance search action run space ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SearchName | String | Security and compliance search action search name. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SharePointLocation | String | Security and compliance search action SharePoint locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SharePointLocationExclusion | String | Security and compliance search action SharePoint locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Status | String | Security and compliance search action status \(Started/Completed\). |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.TenantId | String | Security and compliance search action Tenant ID. |


#### Command Example
```!o365-sc-list-search-action```

#### Context Example
```json
{
    "O365": {
        "SecurityAndCompliance": {
            "ContentSearch": {
                "SearchAction": [
                    {
                        "Action": "Preview",
                        "AllowNotFoundExchangeLocationsEnabled": false,
                        "AzureBatchFrameworkEnabled": false,
                        "CaseId": null,
                        "CaseName": "",
                        "CreatedBy": "XSOAR-user",
                        "CreatedTime": "2020-10-14T13:45:44.14",
                        "Description": "",
                        "Errors": "",
                        "EstimateSearchJobId": "xxxxx",
                        "EstimateSearchRunId": "xxxxx",
                        "ExchangeLocation": null,
                        "ExchangeLocationExclusion": null,
                        "Identity": "xxxxx",
                        "IsValid": true,
                        "JobEndTime": "2020-10-14T13:47:00.103",
                        "JobId": "xxxxx",
                        "JobRunId": "xxxxx",
                        "JobStartTime": "2020-10-14T13:45:58.443",
                        "LastModifiedTime": "2020-10-14T13:45:44.14",
                        "Name": "example_Preview",
                        "PublicFolderLocation": null,
                        "PublicFolderLocationExclusion": null,
                        "Results": null,
                        "Retry": false,
                        "RunBy": "XSOAR-user",
                        "RunspaceId": "xxxxx",
                        "SearchName": "example",
                        "SharePointLocation": null,
                        "SharePointLocationExclusion": null,
                        "Status": "Completed",
                        "TenantId": "xxxxx"
                    },
                  	{
                        "Action": "Purge",
                        "AllowNotFoundExchangeLocationsEnabled": false,
                        "AzureBatchFrameworkEnabled": false,
                        "CaseId": null,
                        "CaseName": "",
                        "CreatedBy": "XSOAR-user1",
                        "CreatedTime": "2020-10-14T13:45:44.14",
                        "Description": "",
                        "Errors": "",
                        "EstimateSearchJobId": "xxxxx",
                        "EstimateSearchRunId": "xxxxx",
                        "ExchangeLocation": null,
                        "ExchangeLocationExclusion": null,
                        "Identity": "xxxxx",
                        "IsValid": true,
                        "JobEndTime": "2020-10-14T13:47:00.103",
                        "JobId": "xxxxx",
                        "JobRunId": "xxxxx",
                        "JobStartTime": "2020-10-14T13:45:58.443",
                        "LastModifiedTime": "2020-10-14T13:45:44.14",
                        "Name": "example_Purge",
                        "PublicFolderLocation": null,
                        "PublicFolderLocationExclusion": null,
                        "Results": null,
                        "Retry": false,
                        "RunBy": "XSOAR-user1",
                        "RunspaceId": "xxxxx",
                        "SearchName": "Rodrigo-diffrent",
                        "SharePointLocation": null,
                        "SharePointLocationExclusion": null,
                        "Status": "Completed",
                        "TenantId": "xxxxx"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Security And Compliance - search actions
>| Action | JobEndTime | LastModifiedTime | Name | RunBy | SearchName | Status
>| --- | --- | --- | --- | --- | --- | ---
>| Preview | 10/14/2020 1:47:00 PM | 10/14/2020 1:45:44 PM | example_Preview | XSOAR-user | example | Completed
>| Purge | 11/25/2020 10:51:04 AM | 11/25/2020 10:50:37 AM | example\_Purge | XSOAR-user | example | Completed
>


### o365-sc-get-search-action
***
Gets compliance search action from the Security & Compliance Center.


#### Base Command

`o365-sc-get-search-action`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_action_name | The name of the compliance search action. | Required |
| limit | The maximum number of results to return. If you want to return all requests that match the query, use "-1" for the value of this argument. | Optional |
| export | Whether to export search results as json file to war-room. | Optional |
| results | Whether to print the results in the War Room. Default is "false". | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Action | String | Security and compliance search action type. Either "Purge" or "Preview". |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.AllowNotFoundExchangeLocationsEnabled | Boolean | Whether to include mailboxes other than regular user mailboxes in the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.AzureBatchFrameworkEnabled | Boolean | Whether the Azure Batch Framework is enabled for job processing. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CaseId | String | Identity of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CaseName | String | Name of a Core eDiscovery case which is associated with the compliance search. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CreatedBy | String | Security and compliance search action creator. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.CreatedTime | Date | Security and compliance search action creation time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Description | String | Security and compliance search action description. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Errors | String | Security and compliance search action errors. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.EstimateSearchJobId | String | Security and compliance search action job ID estimation. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.EstimateSearchRunId | String | Security and compliance search action run ID estimation. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.ExchangeLocation | String | Security and compliance search action exchange locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.ExchangeLocationExclusion | String | Security and compliance search action exchange locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Identity | String | Security and compliance search action identity. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.IsValid | Boolean | Whether the security and compliance search action is valid. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobEndTime | Date | Security and compliance search action job end time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobId | String | Security and compliance search action job ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobRunId | String | Security and compliance search action job run ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.JobStartTime | Date | Security and compliance search action job start time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.LastModifiedTime | Date | Security and compliance search action last modified time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Name | String | Security and compliance search action name. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.PublicFolderLocation | String | Security and compliance search action public folder locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.PublicFolderLocationExclusion | String | Security and compliance search action public folder locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.Location | String | Security and compliance search action result location. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.ItemCount | String | Security and compliance search action result item count. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.TotalSize | String | Security and compliance search action result total size. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.FailedCount | String | Security and compliance search action result failed count. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.Sender | String | Security and compliance search action result mail sender. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.Subject | String | Security and compliance search action result subject. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.Type | String | Security and compliance search action result type. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.Size | String | Security and compliance search action result size. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.ReceivedTime | Date | Security and compliance search action result received time. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Results.DataLink | String | Security and compliance search action data link. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Retry | Boolean | Whether to retry if the search action failed. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.RunBy | String | Security and compliance search action run by UPN \(email address\). |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.RunspaceId | String | Security and compliance search action run space ID. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SearchName | String | Security and compliance search action search name. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SharePointLocation | String | Security and compliance search action SharePoint locations to include. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.SharePointLocationExclusion | String | Security and compliance search action SharePoint locations to exclude. |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.Status | String | Security and compliance search action status. Either "Started" or "Completed". |
| O365.SecurityAndCompliance.ContentSearch.SearchAction.TenantId | String | Security and compliance search action Tenant ID. |

#### Command Example
```!o365-sc-get-search-action search_action_name="example_Preview"```

#### Context Example
```json
{
    "O365": {
        "SecurityAndCompliance": {
            "ContentSearch": {
                "SearchAction": {
                    "Action": "Preview",
                    "AllowNotFoundExchangeLocationsEnabled": false,
                    "AzureBatchFrameworkEnabled": false,
                    "CaseId": null,
                    "CaseName": "",
                    "CreatedBy": "XSOAR-user",
                    "CreatedTime": "2020-11-29T07:23:50.05",
                    "Description": "",
                    "Errors": "",
                    "EstimateSearchJobId": "2a967c40-07c3-4903-ed7f-08d89436e9b1",
                    "EstimateSearchRunId": "1d130723-fe0a-4726-6d2a-08d89437520e",
                    "ExchangeLocation": [
                        "user@onmicrosoft.com"
                    ],
                    "ExchangeLocationExclusion": null,
                    "Identity": "xxxxx",
                    "IsValid": true,
                    "JobEndTime": "2020-11-29T07:24:05.76",
                    "JobId": "xxxxx",
                    "JobRunId": "xxxxx",
                    "JobStartTime": "2020-11-29T07:23:50.297",
                    "LastModifiedTime": "2020-11-29T07:23:50.05",
                    "Name": "example_Preview",
                    "PublicFolderLocation": null,
                    "PublicFolderLocationExclusion": null,
                    "Results": [
                        {
                            "DataLink": "data/All/xxxx.eml",
                            "Location": "user@onmicrosoft.com",
                            "ReceivedTime": "11/26/2020 2:59:01 PM",
                            "Sender": "Some user",
                            "Size": "19683",
                            "Subject": "Test1",
                            "Type": "Email"
                        },
                       {
                            "DataLink": "data/All/xxxx.eml",
                            "Location": "user@onmicrosoft.com",
                            "ReceivedTime": "12/26/2020 2:59:01 PM",
                            "Sender": "Some user",
                            "Size": "20225",
                            "Subject": "Test2",
                            "Type": "Email"
                        },
                    ],
                    "Retry": false,
                    "RunBy": "XSOAR-user",
                    "RunspaceId": "xxxxx",
                    "SearchName": "example",
                    "SharePointLocation": null,
                    "SharePointLocationExclusion": null,
                    "Status": "Completed",
                    "TenantId": "xxxxx"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Security And Compliance - search action 'example_Preview'
>| Action | JobEndTime | LastModifiedTime | Name | RunBy | SearchName | Status
>| --- | --- | --- | --- | --- | --- | ---
>| Preview | 11/29/2020 7:24:05 AM | 11/29/2020 7:23:50 AM | example\_Preview | XSOAR-user | example | Completed


## Tips for finding messages to remove
* Keyword Query Language (KQL)
    * If you know the exact text or phrase used in the subject line of the message, use the Subject property in the search query, e.g., `(subject:give me all ur money)`.
    * If you know that exact date (or date range) of the message, include the Received property in the search query, e.g., `(received:6/13/2021..6/16/2021)`.
    * If you know who sent the message, include the From property in the search query, e.g., `(from:user1@demistodev.onmicrosoft.com)`.
    * For all the available search properties see: [Keyword queries and search conditions for eDiscovery.](https://docs.microsoft.com/en-us/microsoft-365/compliance/keyword-queries-and-search-conditions?view=o365-worldwide)
* Preview the search results to verify that the search returned only the message (or messages) that you want to delete.
* Use the search estimate statistics (displayed by using the `o365-sc-get-search` command) to get a count of the total number of emails.

### o365-sc-compliance-case-create

***
Create eDiscovery cases in the Microsoft Purview compliance portal.

#### Base Command

`o365-sc-compliance-case-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_name | Case name create. | Required | 
| case_type | "AdvancedEdiscovery: Used to manage legal or other types of investigations.<br/> ComplianceClassifier: This type of case corresponds to a trainable classifier.<br/> DataInvestigation: Data investigation cases are used to investigate data spillage incidents.<br/> DSR: Data Subject Request (DSR) cases are used to manage General Data Protection Regulation (GDPR) DSR investigations.<br/> eDiscovery: eDiscovery (also called eDiscovery Standard) cases are used to manage legal or other types of investigations.<br/> This is the default value.<br/> InsiderRisk: Insider risk cases are used to manage insider risk management cases.<br/> Typically, insider risk management cases are manually created in the Microsoft Purview<br/> compliance portal to further investigate activity based on a risk alert.<br/> SupervisionPolicy: This type of case corresponds to communication compliance policy."<br/>. Possible values are: AdvancedEdiscovery, ComplianceClassifier, DataInvestigation, DSR, eDiscovery, InsiderRisk, SupervisionPolicy. Default is eDiscovery. | Optional | 
| description | Case description. | Optional | 
| external_id | Case external ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.ComplianceCase.Name | String | Case name. | 
| O365.SecurityAndCompliance.ComplianceCase.Status | String | Case status. | 
| O365.SecurityAndCompliance.ComplianceCase.CreatedDateTime | String | Case created date time. | 

### o365-sc-compliance-case-list

***
List different types of compliance cases in the Microsoft Purview compliance portal.

#### Base Command

`o365-sc-compliance-case-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | List cases by identity. | Optional | 
| case_type | List cases by type. Possible values are: AdvancedEdiscovery, ComplianceClassifier, DataInvestigation, DSR, eDiscovery, InsiderRisk, SupervisionPolicy. | Optional | 
| limit | Limit returned cases list size. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.ComplianceCase.Name | String | Case name. | 
| O365.SecurityAndCompliance.ComplianceCase.Status | String | Case status. | 
| O365.SecurityAndCompliance.ComplianceCase.GUID | UUID | Case GUID. | 
| O365.SecurityAndCompliance.ComplianceCase.CreatedDateTime | String | Case created date time. | 

### o365-sc-compliance-case-delete

***
Removes compliance cases from the Microsoft Purview compliance portal.
#### Base Command

`o365-sc-compliance-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | Delete case by identity. | Required | 

#### Context Output

There is no context output for this command.
### o365-sc-case-hold-policy-create

***
Creates new case hold policies in the Microsoft Purview compliance portal.

#### Base Command

`o365-sc-case-hold-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Name of the policy to create. | Required | 
| case | eDiscovery case, Case Name, Case Identity (GUID value). | Required | 
| comment | Attach a comment to the case. | Optional | 
| exchange_location | Mailbox or distribution group. | Optional | 
| public_folder_location | Comma-separated list of public folders to include, or you can use the value "All" to include all. | Optional | 
| share_point_location | SharePoint Online and OneDrive for Business sites to include. | Optional | 
| enabled | Set hold policy as enabled or not. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.CaseHoldPolicy.Name | String | Case hold policy name. | 
| O365.SecurityAndCompliance.CaseHoldPolicy.Workload | String | Case hold policy workload. | 
| O365.SecurityAndCompliance.CaseHoldPolicy.Enabled | String | Is case hold policy enabled. | 
| O365.SecurityAndCompliance.CaseHoldPolicy.Mode | String | Case hold policy mode. | 

### o365-sc-case-hold-policy-get

***
View existing case hold policies in the Microsoft Purview compliance portal.

#### Base Command

`o365-sc-case-hold-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | Identify of the case hold policy to get. | Optional | 
| case | Case of policy to get. Case name or case GUID. | Optional | 
| distribution_detail | Whether to include distribution details or not. Possible values are: true, false. Default is true. | Optional | 
| include_bindings | Whether to include bindings or not. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.CaseHoldPolicy.Name | String | Case hold policy name. | 
| O365.SecurityAndCompliance.CaseHoldPolicy.GUID | String | Case hold policy GUID. | 
| O365.SecurityAndCompliance.CaseHoldPolicy.Workload | String | Case hold policy workload. | 
| O365.SecurityAndCompliance.CaseHoldPolicy.Status | String | Case hold policy status. | 
| O365.SecurityAndCompliance.CaseHoldPolicy.Mode | String | Case hold policy mode. | 

### o365-sc-case-hold-policy-delete

***
Removes case hold policies from the Microsoft Purview compliance portal.

#### Base Command

`o365-sc-case-hold-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | Identify of the case hold policy to delete. | Required | 
| force_delete | Whether to use force delete or not. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
### o365-sc-case-hold-rule-create

***
Creates new case hold rules in the Microsoft Purview compliance portal.

#### Base Command

`o365-sc-case-hold-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | Create rule with the specified name. | Required | 
| policy_name | Create rule for the specified policy. | Required | 
| query | Query using Keyword Query Language (KQL). | Optional | 
| comment | Attach a comment to the created rule. | Optional | 
| is_disabled | Whether the rule is disabled or not. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.CaseHoldRule.Name | String | Case hold policy name. | 
| O365.SecurityAndCompliance.CaseHoldRule.Status | String | Case hold policy status. | 
| O365.SecurityAndCompliance.CaseHoldRule.Mode | String | Case hold policy mode. | 

### o365-sc-case-hold-rule-list

***
View case hold rules in the Microsoft Purview compliance portal.

#### Base Command

`o365-sc-case-hold-rule-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identify | Get hold rule list by identity. | Optional | 
| policy | Get hold rule list by policy. | Optional | 
| limit | Limit the returned items list size. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| O365.SecurityAndCompliance.CaseHoldRule.Name | String | Case hold policy name. | 
| O365.SecurityAndCompliance.CaseHoldRule.GUID | UUID | Case hold policy GUID. | 
| O365.SecurityAndCompliance.CaseHoldRule.Enabled | String | Whether case hold policy is enabled. | 
| O365.SecurityAndCompliance.CaseHoldRule.Mode | String | Case hold policy mode. | 

### o365-sc-case-hold-rule-delete

***
Removes case hold rules from the Microsoft Purview compliance portal.

#### Base Command

`o365-sc-case-hold-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | Delete rule by identity. | Optional | 
| force_delete | Whether to use force delete or not. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
## Known Limitations

* Security and compliance integrations do not support Security and compliance on-premise.
* Each security and compliance command creates an IPS-Session (PowerShell session). The security and compliance PowerShell limits the number of concurrent sessions to 3. Since this affects the behavior of multiple playbooks running concurrently it we recommend that you retry failed tasks when using the integration commands in playbooks.
* Proxies are not supported due to a Microsoft [limitation](https://github.com/PowerShell/PowerShell/issues/9721).
* Due to a Microsoft limitation, you can perform a search and purge operation on a maximum of 50,000 mailboxes. To work around this limitation, configure multiple instances of the integration each with different permission filtering so that the number of mailboxes in each instance does not exceed 50,000.
* A maximum of 10 items per mailbox can be removed at one time, due to a Microsoft [limitiation](https://docs.microsoft.com/en-us/microsoft-365/compliance/search-for-and-delete-messages-in-your-organization?view=o365-worldwide#before-you-begin).
* For more Microsoft known limitations see [Limits for eDiscovery search](https://docs.microsoft.com/en-us/microsoft-365/compliance/limits-for-content-search?view=o365-worldwide).
### o365-sc-case-hold-policy-set

***
Update inputs for case hold policies.

#### Base Command

`o365-sc-case-hold-policy-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identity | Identity of the policy to update. | Required | 
| add_exchange_locations | Exchange locations to add to the policy. | Optional | 
| add_sharepoint_locations | Sharepoint locations to add to the policy. | Optional | 
| add_public_locations | Public locations to add to the policy. | Optional | 
| remove_exchange_locations | Exchange locations to remove from the policy. | Optional | 
| remove_sharepoint_locations | Sharepoint locations to remove from the policy. | Optional | 
| remove_public_locations | Public locations to remove from the policy. | Optional | 
| comment | Add a comment to existing policy. | Optional | 
| enabled | Enable or disable the policy. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

There is no context output for this command.
