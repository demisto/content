The Microsoft Management Activity API integration enables you to subscribe or unsubscribe to different audits, receive their content, and fetch new content as incidents. Through the integration you can subscribe to new content types or stop your subscription, list the available content of each content type, and most importantly, fetch new content records from content types of your choice as Cortex XSOAR incidents.

This integration was integrated and tested with version 1.0 of Microsoft Management Activity API (O365 Azure Events).

# Authentication

There are two application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application - Authorization Code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authorization-code-flow)

 **Note** - The credentials (created by the Cortex XSOAR application) are valid for a single instance only.

## Self-Deployed Azure App
1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
    - `User.Read ` of type `Delegated`
    - `ActivityFeed.Read` of type `Delegated`
    - `ActivityFeed.Read` of type `Application`
    - `ActivityFeed.ReadDlp` of type `Delegated`
    - `ActivityFeed.ReadDlp` of type `Application`
    - `ServiceHealth.Read` of type `Delegated`
    - `ServiceHealth.Read` of type `Application`

## Configure Microsoft Management Activity API (O365 Azure Events) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | The host URL. | False |
| Application ID or Client ID | The app registration ID. | False |
| Key or Client Secret | The app registration secret. | False |
| Token or Tenant ID | The tenant ID. | False |
| Certificate Thumbprint | Used for certificate authentication as it appears in the "Certificates & secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Use a self-deployed Azure application | Whether to use a selp-deployed application. | False |
| Application redirect URI (for self-deployed mode) | The app registration redirect URI. | False |
| The authentication code you got for the service | For instructions on how to receive it, see the Help tab. | False |
| Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
| Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
| Trust any certificate (not secure) | Whether to trust any certificate. If set to True, is not secure. | False |
| Use system proxy settings | Whether to use system proxy settings. | False |
| First fetch time range | &lt;number&gt; &lt;time unit&gt;, for example 1 hour, 30 minutes. | False |
| Timeout | The default timeout (in seconds) for API calls. Default is 15 seconds. | False |
| Content types to fetch | The content types to fetch. | False |
| Fetch incidents | Whether to fetch incidents. | False |
| Incident type | The incident type to apply. | False |
| Record types to fetch | A comma-separated list of the record types you want to fetch. Content records with a record type that is not specified will not be fetched. If this field is left empty, all record types will be fetched. | False |
| Workloads to fetch | A comma-separated list of the workloads you want to fetch. Content records with a workload that is not specified will not be fetched. If this field is left empty, all workloads will be fetched. | False |
| Operations to fetch | A comma-separated list of the operations you want to fetch. Content records with an operation that is not specified will not be fetched. If this field is left empty, all operations will be fetched. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ms-management-activity-start-subscription
***
Starts a subscription to a given content type.


#### Base Command

`ms-management-activity-start-subscription`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_type | The content type to subscribe to. Possible values are: Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
```!ms-management-activity-start-subscription content_type=Audit.Exchange```

##### Context Example
```
{
    "MicrosoftManagement": {
        "Subscription": {
            "ContentType": "Audit.Exchange",
            "Enabled": true
        }
    }
}
```

##### Human Readable Output
Successfully started subscription to content type: Audit.Exchange

### ms-management-activity-stop-subscription
***
Stops a subscription to a given content type.


#### Base Command

`ms-management-activity-stop-subscription`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_type | The content type to unsubscribe from. Possible values are: Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All. | Required | 


#### Context Output

There is no context output for this command.

##### Command Example
```!ms-management-activity-stop-subscription content_type=Audit.Exchange```

##### Context Example
```
{
    "MicrosoftManagement": {
        "Subscription": {
            "ContentType": "Audit.Exchange",
            "Enabled": false
        }
    }
}
```

##### Human Readable Output
Successfully stopped subscription to content type: Audit.Exchange

### ms-management-activity-list-subscriptions
***
List the content types you are currently subscribed to.


#### Base Command

`ms-management-activity-list-subscriptions`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftManagement.Subscription | string | List of current subscriptions | 


##### Command Example
```!ms-management-activity-list-subscriptions```

##### Context Example
```
{
    "MicrosoftManagement": {
        "Subscription": [
            {
                "ContentType": "Audit.AzureActiveDirectory",
                "Enabled": true
            },
            {
                "ContentType": "Audit.Exchange",
                "Enabled": true
            },
            {
                "ContentType": "Audit.General",
                "Enabled": true
            },
            {
                "ContentType": "Audit.SharePoint",
                "Enabled": true
            }
        ]
    }
}
```

##### Human Readable Output
### Current Subscriptions
|Current Subscriptions|
|---|
| Audit.AzureActiveDirectory |
| Audit.Exchange |
| Audit.General |
| Audit.SharePoint |


### ms-management-activity-list-content
***
Returns all content of a specific content type.


#### Base Command

`ms-management-activity-list-content`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_type | The content type for which to receive content. Possible values are: Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, Audit.General, DLP.All. | Required | 
| start_time | The earliest time to get content from. If start_time is specified, end_time must also be specified. The start_time must be before the end_time, can be at most 7 days ago, and has to be within 24 hours from end_time. Required format: YYYY-MM-DDTHH:MM:SS. If not specified, start time will be 24 hours ago. | Optional | 
| end_time | The latest time to get content from. If end_time is specified, start_time must be also specified. The start_time must be before the end_time and has to be within 24 hours from start_time. Required format: YYYY-MM-DDTHH:MM:SS. If not specified, end_time will be now. | Optional | 
| record_types_filter | A comma-separated list of the record types to fetch. Content records with a record type that isn't specified will not be fetched. If this field is left empty, all record types will be fetched. | Optional | 
| workloads_filter | A comma-separated list of the workloads to fetch. Content records with a workload that isn't specified will not be fetched. If this field is left empty, all workloads will be fetched. | Optional | 
| operations_filter | A comma-separated list of the operations to fetch. Content records with an operation that isn't specified will not be fetched. If this field is left empty, all operations will be fetched. | Optional | 
| timeout | The timeout (in seconds) for the content requesting HTTP call. Default is the value provided as an integration parameter. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftManagement.ContentRecord.ID | number | The ID of the record. | 
| MicrosoftManagement.ContentRecord.CreationTime | date | The creation time of the record. | 
| MicrosoftManagement.ContentRecord.RecordType | string | The type of the record. | 
| MicrosoftManagement.ContentRecord.Operation | string | The operation described in the record. | 
| MicrosoftManagement.ContentRecord.UserType | string | The type of the related user. | 
| MicrosoftManagement.ContentRecord.OrganizationID | number | The ID of the organization relevant to the record. | 
| MicrosoftManagement.ContentRecord.UserKey | string | The key of the related user. | 
| MicrosoftManagement.ContentRecord.ClientIP | string | The IP of the record's client. | 
| MicrosoftManagement.ContentRecord.Scope | string | The scope of the record. | 
| MicrosoftManagement.ContentRecord.Workload | string | The workload of the record. | 
| MicrosoftManagement.ContentRecord.ResultsStatus | string | The results status of the record. | 
| MicrosoftManagement.ContentRecord.ObjectID | string | The ID of the record's object. | 
| MicrosoftManagement.ContentRecord.UserID | string | The ID of the record's user. | 


##### Command Example
```!ms-management-activity-list-content content_type=audit.general```

##### Context Example
```
{
    "MicrosoftManagement": {
        "ContentRecord": [
            {
                "CreationTime": "2020-04-26T10:10:10",
                "ID": "TEST ID",
                "ObjectID": "test-id",
                "Operation": "TeamsSessionStarted",
                "OrganizationID": "test-organization",
                "RecordType": 9,
                "UserID": "test@mail.com",
                "UserKey": "test-key",
                "UserType": 12,
                "Workload": "MicrosoftTeams"
            },
            {
                "CreationTime": "2020-04-26T09:09:09",
                "ID": "TEST ID",
                "Operation": "MemberAdded",
                "OrganizationID": "test-organization",
                "RecordType": 8,
                "UserID": "Application",
                "UserKey": "test-key",
                "UserType": 11,
                "Workload": "MicrosoftTeams"
            }
        ]
    }
}
```

##### Human Readable Output
### Content for content type audit.general
|ID|CreationTime|Workload|Operation|
|---|---|---|---|
| 1111111-aaaa-bbbb | 2020-04-26T10:10:10 | MicrosoftTeams | TeamsSessionStarted |
| 2222222-vvvv-gggg | 2020-04-26T09:09:09 | MicrosoftTeams | MemberAdded |


### ms-management-activity-generate-login-url
***
Generate the login url used for Authorization code flow.

#### Base Command

`ms-management-activity-generate-login-url`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```ms-management-activity-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.


### ms-management-activity-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`ms-management-activity-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.


## Additional Information
- Record types to fetch from should be set with numerical values from the [Microsoft documentation](https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype). For example, in order to fetch events of type **MailSubmission**, the value **29** should be set.
- Note that the API only supports start times up to 7 days in the past when fetching. If the last fetch timestamp exceeds this limit, the integration automatically fetches data from 7 days ago.
-  The credentials are valid for a single instance only.

## Troubleshooting

In case of a **hash verification** error:
1. Use the Oproxy flow to generate a new pair of credentials. This is crucial as it ensures that any issues related to authentication can be mitigated with fresh credentials.
2. Execute the command ***!ms-management-activity-auth-reset***. This command resets the authentication mechanism, allowing for the new credentials to be accepted.
3. Insert the newly created credentials into the original instance where the error occurred. Make sure the credentials are entered correctly to avoid further errors.
4. After updating the credentials, test the integration.