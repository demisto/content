The Microsoft Management Activity API integration enables you to subscribe or unsubscribe to different audits, receive their content, and fetch new content as incidents. Through the integration you can subscribe to new content types or stop your subscription, list the available content of each content type, and most importantly, fetch new content records from content types of your choice as Cortex XSOAR incidents.

This integration was integrated and tested with version 1.0 of Microsoft Management Activity API (O365 Azure Events)

## Grant Cortex XSOAR Authorization in Microsoft Management Activity API
To allow Cortex XSOAR access to the Microsoft Management Activity API you will be required to give authorization to access it.

1. To grant authorization, click [HERE](https://oproxy.demisto.ninja/ms-management-api).
2. After you click the link, click the **Start Authorization Process** button.
3. When prompted, accept the Microsoft authorization request for the required permissions.
You will get an ID, Token, and Key, which you need to enter in the corresponding fields when configuring an integration instance.

## Self-Deployed Configuration
1. Enter the following URL
(**Note**: CLIENT_ID and REDIRECT_URI should be replaced by your own client ID and redirect URI, accordingly):
`https://login.windows.net/common/oauth2/authorize?response_type=code&resource=https://manage.office.com&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI`
1. When prompted, accept the Microsoft authorization request for the required permissions.
2. The URL will change and will have the following structure:
SOME_PREFIX?code=AUTH_CODE&session_state=SESSION_STATE
Take the AUTH_CODE (without the “code=” prefix) and enter it to the instance configuration under the “Authentication” code section.
Moreover, enter your client secret as the “Key” parameter and your client ID as the “ID” parameter. 

## Configure Microsoft Management Activity API (O365 Azure Events) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Management Activity API (O365 Azure Events).
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| base_url | Base URL | False |
| auth_id | ID \(received from the authorization step \- see Detailed Instructions \(?\) section\) | False |
| enc_key | Key \(received from the authorization step \- see Detailed Instructions \(?\) section\) | False |
| refresh_token | Token \(received from the authorization step \- see Detailed Instructions \(?\) section\) | False |
| self_deployed | Use a self\-deployed Azure application | False |
| auth_code | The authentication code you got for the service. For instructions on how to receive it, see Detailed Instructions \(?\) section. | False |
| timeout | The default timeout (in seconds) for API calls. Can be overridden by providing value to the corresponding argument when calling supported commands. Default is 15 seconds. | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| redirect_uri | Application redirect URI (for self-deployed mode) | False |
| first_fetch_delta | First fetch time range \(&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes\) | False |
| content_types_to_fetch | Content types to fetch | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| record_types_filter | Record types to fetch \(Comma\-separated list of the record types you wish to fetch. Content records with a record  type that is not specified will not be fetched. If this field is left empty, all record types will be fetched.\) | False |
| workloads_filter | Workloads to fetch \(Comma\-separated list of the workloads you wish to fetch. Content records with a workload that is not specified will not be fetched. If this field is left empty, all workloads will be fetched.\) | False |
| operations_filter | Operations to \(Comma\-separated list of the operations you wish to fetch. Content records with an operation that is not specified will not be fetched. If this field is left empty, all operations will be fetched.\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ms-management-activity-start-subscription
***
Starts a subscription to a given content type.


##### Base Command

`ms-management-activity-start-subscription`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_type | The content type to subscribe to. Possible values are `Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.SharePoint`, `Audit.General`, `DLP.All` | Required | 


##### Context Output

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


##### Base Command

`ms-management-activity-stop-subscription`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_type | The content type to unsubscribe from. Possible values are `Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.SharePoint`, `Audit.General`, `DLP.All` | Required | 


##### Context Output

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
List the content types you are currently subscribed to


##### Base Command

`ms-management-activity-list-subscriptions`
##### Input

There are no input arguments for this command.

##### Context Output

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


##### Base Command

`ms-management-activity-list-content`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_type | The content type for which to receive content. Possible values are `Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.SharePoint`, `Audit.General`, `DLP.All` | Required | 
| start_time | The earliest time to get content from. If start_time is specified, end_time must also be specified. The start_time must be before the end_time, can be at most 7 days ago, and has to be within 24 hours from end_time. Required format: YYYY-MM-DDTHH:MM:SS. If not specified, start time will be 24 hours ago. | Optional | 
| end_time | The latest time to get content from. If end_time is specified, start_time must be also specified. The start_time must be before the end_time and has to be within 24 hours from start_time. Required format: YYYY-MM-DDTHH:MM:SS. If not specified, end_time will be now. | Optional | 
| record_types_filter | A comma-separated list of the record types to fetch. Content records with a record  type that is not specified will not be fetched. If this field is left empty, all record types will be fetched. | Optional | 
| workloads_filter | A comma-separated list of the workloads to fetch. Content records with a workload that is not specified will not be fetched. If this field is left empty, all workloads will be fetched. | Optional | 
| operations_filter | A comma-separated list of the operations to fetch. Content records with an operation that is not specified will not be fetched. If this field is left empty, all operations will be fetched. | Optional |
| timeout | The timeout for the content requesting http call. The default is configured at the corresponding integration instance parameter. | Optional 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftManagement.ContentRecord.ID | number | The ID of the record. | 
| MicrosoftManagement.ContentRecord.CreationTime | date | The creation time of the record. | 
| MicrosoftManagement.ContentRecord.RecordType | string | The type of the record. | 
| MicrosoftManagement.ContentRecord.Operation | string | The operation described in the record. | 
| MicrosoftManagement.ContentRecord.UserType | string | The type of the related user. | 
| MicrosoftManagement.ContentRecord.OrganizationID | number | The ID of the organization relevant to the record. | 
| MicrosoftManagement.ContentRecord.UserKey | string | The key of the related user. | 
| MicrosoftManagement.ContentRecord.ClientIP | string | The IP of the record&\#x27;s client. | 
| MicrosoftManagement.ContentRecord.Scope | string | The scope of the record. | 
| MicrosoftManagement.ContentRecord.Workload | string | The workload of the record. | 
| MicrosoftManagement.ContentRecord.ResultsStatus | string | The results status of the record. | 
| MicrosoftManagement.ContentRecord.ObjectID | string | The ID of the record&\#x27;s object. | 
| MicrosoftManagement.ContentRecord.UserID | string | The ID of the record&\#x27;s user. | 


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


## Additional Information
Record types to fetch from should be set with numerical values from the [Microsoft documentation](https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#auditlogrecordtype). For example, in order to fetch events of type **MailSubmission**, the value **29** should be set.