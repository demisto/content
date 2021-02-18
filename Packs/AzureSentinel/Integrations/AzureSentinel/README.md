<!-- disable-secrets-detection-start -->
Use the Azure Sentinel integration to get and manage incidents and get related entity information for incidents.
This integration was integrated and tested with API version ***2019-01-01-preview*** of Azure Sentinel.

> <i>Note:</i> The integration is in ***beta*** as it uses a preview version of the Azure Sentniel API. The stable Azure Sentniel API version does not contain all  required endpoints used in some of the integration commands.

## Authorize Cortex XSOAR for Azure Sentinel

You need to grant Cortex XSOAR authorization to access Azure Sentinel.

1. Access the [authorization flow](https://oproxy.demisto.ninja/ms-azure-sentinel). 
2. Click the **Start Authorization Process** button and you will be prompted to grant Cortex XSOAR permissions for your Azure Service Management. 
3. Click the **Accept** button and you will receive your ID, token, and key. You will need to enter these when you configure the Azure Sentinel integration instance in Cortex XSOAR.

## Authorize Cortex XSOAR for Azure Sentinel (self-deployed configuration)

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
   -  API/Permission name `user_impersonation` of type `Delegated`
3. Copy the following URL and replace the ***CLIENT_ID*** and ***REDIRECT_URI*** with your own client ID and redirect URI, accordingly.
```https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&resource=https://management.core.windows.net&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI```
4. Enter the link and you will be prompted to grant Cortex XSOAR permissions for your Azure Service Management. You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
5. Copy the ***AUTH_CODE*** (without the “code=” prefix) and paste it in your instance configuration under the **Authorization code** parameter. 
6. Enter your client ID in the ***ID*** parameter. 
7. Enter your client secret in the ***Key*** parameter.
8. Enter your tenant ID in the ***Token*** parameter.
9. Enter your redirect URI in the ***Redirect URI*** parameter.

## Get the additional instance parameters

To get the ***Subscription ID***, ***Workspace Name*** and ***Resource Group*** parameters, navigate in the Azure Portal to ***Azure Sentinel > YOUR-WORKSPACE > Settings*** and click on ***Workspace Settings*** tab.


## Configure Azure Sentinel on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Sentinel.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| auth_id | ID (received from the authorization step - see Detailed Instructions (?) section) | True |
| refresh_token | Token (received from the authorization step - see Detailed Instructions (?) section) | True |
| enc_key | Key (received from the authorization step - see Detailed Instructions (?) section) | True |
| self_deployed | Use a self-deployed Azure application | False |
| redirect_uri | Application redirect URI (for self-deployed mode) | False |
| auth_code | Authorization code (received from the authorization step - see Detailed Instructions (?) section) | False |
| isFetch | Fetch incidents | False |
| fetch_time | First fetch timestamp ({number} {time unit}, e.g., 12 hours, 7 days) | False |
| min_severity | The minimum severity of incidents to fetch | False |
| incidentType | Incident type | False |
| subscriptionID | Subscription ID | True |
| resourceGroupName | Resource Group Name | True |
| workspaceName | Workspace Name | True |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-sentinel-get-incident-by-id
***
Gets a single incident from Azure Sentinel.


##### Base Command

`azure-sentinel-get-incident-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.Incident.ID | String | The incident ID. | 
| AzureSentinel.Incident.Title | String | The incident title. | 
| AzureSentinel.Incident.Description | String | Description of the incident. | 
| AzureSentinel.Incident.Severity | String | The incident severity. | 
| AzureSentinel.Incident.Status | String | The incident status. | 
| AzureSentinel.Incident.AssigneeName | String | The name of the incident assignee. | 
| AzureSentinel.Incident.AssigneeEmail | String | The email address of the incident assignee. | 
| AzureSentinel.Incident.Label.Name | String | The name of the incident label. | 
| AzureSentinel.Incident.Label.Type | String | The incident label type. | 
| AzureSentinel.Incident.FirstActivityTimeUTC | Date | The date and time of the incident's first activity. | 
| AzureSentinel.Incident.LastActivityTimeUTC | Date | The date and time of the incident's last activity. | 
| AzureSentinel.Incident.LastModifiedTimeUTC | Date | The date and time the incident was last modified. | 
| AzureSentinel.Incident.CreatedTimeUTC | Date | The date and time the incident was created. | 
| AzureSentinel.Incident.IncidentNumber | Number | The incident number. | 
| AzureSentinel.Incident.AlertsCount | Number | The number of the alerts in the incident. | 
| AzureSentinel.Incident.BookmarkCount | Number | The number of bookmarks in the incident. | 
| AzureSentinel.Incident.CommentCount | Number | The number of comments in the incident. | 
| AzureSentinel.Incident.AlertProductNames | String | The alert product names of the incident. | 
| AzureSentinel.Incident.Tactics | String | The incident's tactics. | 
| AzureSentinel.Incident.FirstActivityTimeGenerated | Date | The incident's generated first activity time. | 
| AzureSentinel.Incident.LastActivityTimeGenerated | Date | The incident's generated last activity time. | 
| AzureSentinel.Incident.Etag | String | The Etag of the incident. | 


##### Command Example
```!azure-sentinel-get-incident-by-id incident_id=f1670c58-43dc-4b82-a13a-c732325c41f5```

##### Human Readable Output
### Incident b3de6b49-0945-454e-bb59-98087573cfc2 details
### Incident f1670c58-43dc-4b82-a13a-c732325c41f5 details
|ID|Incident Number|Title|Severity|Status|First Activity Time UTC|Last Activity Time UTC|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|First Activity Time Generated|Last Activity Time Generated|Etag|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| f1670c58-43dc-4b82-a13a-c732325c41f5 | 234 | Test Incident | High | New | 2020-03-28T18:45:59Z | 2020-03-28T23:45:59Z | 2020-03-28T23:51:06Z | 2020-03-28T23:51:06Z | 1 | 0 | 0 | Azure Sentinel | 2020-03-28T23:51:06Z | 2020-03-28T23:51:06Z | "49002835-0000-0100-0000-5e7fe2ea0000" |


### azure-sentinel-list-incidents
***
Gets a list of incidents from Azure Sentinel.


##### Base Command

`azure-sentinel-list-incidents`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of incidents to return. The default and maximum value is 50. | Optional | 
| filter | Filter results using OData syntax. For example: properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For more information see the Azure documentation: https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. This argument overrides all of the other command arguments. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.Incident.ID | String | The incident ID. | 
| AzureSentinel.Incident.Title | String | The incident title. | 
| AzureSentinel.Incident.Description | String | Description of the incident. | 
| AzureSentinel.Incident.Severity | String | The incident severity. | 
| AzureSentinel.Incident.Status | String | The incident status. | 
| AzureSentinel.Incident.AssigneeName | String | The name of the incident assignee. | 
| AzureSentinel.Incident.AssigneeEmail | String | The email address of the incident assignee. | 
| AzureSentinel.Incident.Label.Name | String | The name of the incident label. | 
| AzureSentinel.Incident.Label.Type | String | The incident label type. | 
| AzureSentinel.Incident.FirstActivityTimeUTC | Date | The date and time of the incident's first activity. | 
| AzureSentinel.Incident.LastActivityTimeUTC | Date | The date and time of the incident's last activity. | 
| AzureSentinel.Incident.LastModifiedTimeUTC | Date | The date and time the incident was last modified. | 
| AzureSentinel.Incident.CreatedTimeUTC | Date | The date and time the incident was created. | 
| AzureSentinel.Incident.IncidentNumber | Number | The incident number. | 
| AzureSentinel.Incident.AlertsCount | Number | The number of the alerts in the incident. | 
| AzureSentinel.Incident.BookmarkCount | Number | The number of bookmarks in the incident. | 
| AzureSentinel.Incident.CommentCount | Number | The number of comments in the incident. | 
| AzureSentinel.Incident.AlertProductNames | String | The alert product names of the incident. | 
| AzureSentinel.Incident.Tactics | String | The incident's tactics. | 
| AzureSentinel.Incident.FirstActivityTimeGenerated | Date | The incident's generated first activity time. | 
| AzureSentinel.Incident.LastActivityTimeGenerated | Date | The incident's generated last activity time. | 
| AzureSentinel.NextLink.Description | String | Description of NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns partial results. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 
| AzureSentinel.Incident.Etag | String | The Etag of the incident. | 


##### Command Example
```!azure-sentinel-list-incidents limit=5```

##### Human Readable Output
### Incidents List (5 results)
|ID|Incident Number|Title|Description|Severity|Status|First Activity Time UTC|Last Activity Time UTC|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|First Activity Time Generated|Last Activity Time Generated|Etag|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 35bc3532-494c-44c1-adb8-3d733d966471 | 1 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T07:54:05Z | 2020-01-15T08:54:05Z | 2020-01-15T09:29:12Z | 2020-01-15T09:29:12Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:29:12Z | 2020-01-15T09:29:12Z | "19008ba5-0000-0100-0000-5e1edb680000" |
| 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | 2 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T08:24:05Z | 2020-01-15T09:24:05Z | 2020-01-15T09:29:14Z | 2020-01-15T09:29:14Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:29:14Z | 2020-01-15T09:29:14Z | "190093a5-0000-0100-0000-5e1edb6a0000" |
| e0b06d71-b5a3-43a9-997f-f25b45085cb7 | 4 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T07:59:05Z | 2020-01-15T08:59:05Z | 2020-01-15T09:34:12Z | 2020-01-15T09:34:12Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:34:12Z | 2020-01-15T09:34:12Z | "1900fda9-0000-0100-0000-5e1edc940000" |
| 0c16e64d-3bf5-4f7f-a965-cbab1e5ffcc4 | 5 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T08:34:06Z | 2020-01-15T09:34:06Z | 2020-01-15T09:39:13Z | 2020-01-15T09:39:13Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:39:12Z | 2020-01-15T09:39:12Z | "190094ae-0000-0100-0000-5e1eddc10000" |
| a7977be7-1008-419b-877b-6793b7402a80 | 6 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T08:04:05Z | 2020-01-15T09:04:05Z | 2020-01-15T09:40:09Z | 2020-01-15T09:40:09Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:40:09Z | 2020-01-15T09:40:09Z | "19007eaf-0000-0100-0000-5e1eddf90000" |


### azure-sentinel-update-incident
***
Updates a single incident in Azure Sentinel.


##### Base Command

`azure-sentinel-update-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| title | The incident's title. | Optional | 
| description | Description of the incident. | Optional | 
| severity | The incident severity. | Optional | 
| status | The incident status. | Optional | 
| classification | The reason the incident was closed. Required when updating the status to Closed. Possible values are:  BenignPositive, FalsePositive, TruePositive, Undetermined | Optional | 
| classification_reason | The classification reason the incident was closed with. Required when updating the status to Closed and the classification is determined. Possible values are:  InaccurateData, IncorrectAlertLogic, SuspiciousActivity, SuspiciousButExpected | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.Incident.ID | String | The incident ID. | 
| AzureSentinel.Incident.Title | String | The incident's title. | 
| AzureSentinel.Incident.Description | String | Description of the incident. | 
| AzureSentinel.Incident.Severity | String | The incident severity. | 
| AzureSentinel.Incident.Status | String | The incident status. | 
| AzureSentinel.Incident.AssigneeName | String | The name of the incident assignee. | 
| AzureSentinel.Incident.AssigneeEmail | String | The email address of the incident assignee. | 
| AzureSentinel.Incident.Label.Name | String | The name of the incident label. | 
| AzureSentinel.Incident.Label.Type | String | The incident label type. | 
| AzureSentinel.Incident.FirstActivityTimeUTC | Date | The date and time of the incident's first activity. | 
| AzureSentinel.Incident.LastActivityTimeUTC | Date | The date and time of the incident's last activity. | 
| AzureSentinel.Incident.LastModifiedTimeUTC | Date | The date and time the incident was last modified. | 
| AzureSentinel.Incident.CreatedTimeUTC | Date | The date and time the incident was created. | 
| AzureSentinel.Incident.IncidentNumber | Number | The incident number. | 
| AzureSentinel.Incident.AlertsCount | Number | The number of the alerts in the incident. | 
| AzureSentinel.Incident.BookmarkCount | Number | The number of bookmarks in the incident. | 
| AzureSentinel.Incident.CommentCount | Number | The number of comments in the incident. | 
| AzureSentinel.Incident.AlertProductNames | String | The alert product names of the incident. | 
| AzureSentinel.Incident.Tactics | String | The incident's tactics. | 
| AzureSentinel.Incident.FirstActivityTimeGenerated | Date | The incident's generated first activity time. | 
| AzureSentinel.Incident.LastActivityTimeGenerated | Date | The incident's generated last activity time. | 
| AzureSentinel.Incident.Etag | String | The Etag of the incident. | 


##### Command Example
```!azure-sentinel-update-incident incident_id=f1670c58-43dc-4b82-a13a-c732325c41f5 severity=Medium```

##### Human Readable Output
### Updated incidents b3de6b49-0945-454e-bb59-98087573cfc2 details
|ID|Incident Number|Title|Severity|Status|First Activity Time UTC|Last Activity Time UTC|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|First Activity Time Generated|Last Activity Time Generated|Etag|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| f1670c58-43dc-4b82-a13a-c732325c41f5 | 234 | Test Incident | Medium | New | 2020-03-28T18:45:59Z | 2020-03-28T23:47:10Z | 2020-03-28T23:51:06Z | 2020-03-28T23:51:06Z | 1 | 0 | 0 | Azure Sentinel | 2020-03-28T23:51:06Z | 2020-03-28T23:51:06Z | "49002835-0000-0100-0000-5e7fe2ea0000" |


### azure-sentinel-delete-incident
***
Deletes a single incident in Azure Sentinel.


##### Base Command

`azure-sentinel-delete-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!azure-sentinel-delete-incident incident_id=ca5ffab9-25ff-413d-8000-12d3894b8468```

##### Human Readable Output
Incident ca5ffab9-25ff-413d-8000-12d3894b8468 was deleted successfully.


### azure-sentinel-list-incident-comments
***
Gets the comments of an incident from Azure Sentinel.


##### Base Command

`azure-sentinel-list-incident-comments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| limit | The maximum number of incident comments to return. The default and maximum value is 50. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. Using this argument overrides all of the other command arguments. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentComment.ID | String | The ID of the incident comment. | 
| AzureSentinel.IncidentComment.IncidentID | String | The incident ID. | 
| AzureSentinel.IncidentComment.Message | String | The incident comment. | 
| AzureSentinel.IncidentComment.AuthorName | String | The name of the author of the incident comment. | 
| AzureSentinel.IncidentComment.AuthorEmail | String | The email address of the author of the incident comment. | 
| AzureSentinel.IncidentComment.CreatedTimeUTC | Date | The date and time that the incident comment was created. | 
| AzureSentinel.NextLink.Description | String | Description of NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 


##### Command Example
```!azure-sentinel-list-incident-comments incident_id=b3de6b49-0945-454e-bb59-98087573cfc2```

##### Human Readable Output
### Incident b3de6b49-0945-454e-bb59-98087573cfc2 Comments (4 results)
|ID|Incident ID|Message|Author Email|Created Time UTC|
|---|---|---|---|---|
| 295553115212022172880571041415135580062 | b3de6b49-0945-454e-bb59-98087573cfc2 | This is a message | test@demisto.com | 2020-03-25T14:05:22Z |
| 68963242547946961037852832278311632312 | b3de6b49-0945-454e-bb59-98087573cfc2 | hello 123 | test@demisto.com | 2020-03-25T11:54:44Z |
| 129016399225162631970999636732817548146 | b3de6b49-0945-454e-bb59-98087573cfc2 | Test message | test@demisto.com | 2020-03-05T10:31:05Z |
| 205343125729153100039024461040878407049 | b3de6b49-0945-454e-bb59-98087573cfc2 | This is test | test@demisto.com | 2020-03-05T10:29:42Z |


### azure-sentinel-incident-add-comment
***
Adds a comment to an incident in Azure Sentinel.


##### Base Command

`azure-sentinel-incident-add-comment`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| message | The comment message. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentComment.ID | String | The ID of the incident comment. | 
| AzureSentinel.IncidentComment.IncidentID | String | The incident ID. | 
| AzureSentinel.IncidentComment.Message | String | The incident comment. | 
| AzureSentinel.IncidentComment.AuthorName | String | The name of the author of the incident comment. | 
| AzureSentinel.IncidentComment.AuthorEmail | String | The email address of the author of the incident comment. | 
| AzureSentinel.IncidentComment.CreatedTimeUTC | Date | The date and time that the incident comment was created. | 


##### Command Example
```!azure-sentinel-incident-add-comment incident_id=b3de6b49-0945-454e-bb59-98087573cfc2 message="hello"```

##### Human Readable Output
### Incident b3de6b49-0945-454e-bb59-98087573cfc2 new comment details
|ID|Incident ID|Message|Author Email|Created Time UTC|
|---|---|---|---|---|
| 22830063555802832669755633455570921192 | b3de6b49-0945-454e-bb59-98087573cfc2 | hello | test@demisto.com | 2020-03-26T13:25:20Z |


### azure-sentinel-list-incident-relations
***
Gets a list of an incident's related entities from Azure Sentinel.


##### Base Command

`azure-sentinel-list-incident-relations`

> <i>Note:</i> In this command we use an endpoint which is not available in the stable API version.

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| limit | The maximum number of related entities to return. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. Using this argument overrides all of the other command arguments. | Optional | 
| entity_kinds | A comma-separated list of entity kinds to filter by. By default, the results won't be filtered by kind.<br/>The optional kinds are: Account, Host, File, AzureResource, CloudApplication, DnsResolution, FileHash, Ip, Malware, Process, RegistryKey, RegistryValue, SecurityGroup, Url, IoTDevice, SecurityAlert, Bookmark. | Optional | 
| filter | Filter results using OData syntax. For example: properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For more information see the Azure documentation: https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentRelatedResource.ID | String | The ID of the incident's related resource. | 
| AzureSentinel.IncidentRelatedResource.Kind | String | The kind of the incident's related resource. | 
| AzureSentinel.NextLink.Description | String | The description about NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 
| AzureSentinel.IncidentRelatedResource.IncidentID | String | The incident ID. | 


##### Command Example
```!azure-sentinel-list-incident-relations incident_id=f1670c58-43dc-4b82-a13a-c732325c41f5```

##### Human Readable Output
### Incident f1670c58-43dc-4b82-a13a-c732325c41f5 Relations (1 results)
|ID|Incident ID|Kind|
|---|---|---|
| 7ff48076-37b9-4bb5-83b1-db21618a282a | f1670c58-43dc-4b82-a13a-c732325c41f5 | SecurityAlert |


### azure-sentinel-get-entity-by-id
***
Gets a single entity from Azure Sentinel. Use the azure-sentinel-list-incident-relations command, and get an entity ID to apply this command on. In the current Azure Sentinel API version the retention period for GetEntityByID is 30 days.


##### Base Command

`azure-sentinel-get-entity-by-id`

> <i>Note:</i> In this command we use an endpoint which is not available in the stable API version.

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | The entity ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!azure-sentinel-get-entity-by-id entity_id=7ff48076-37b9-4bb5-83b1-db21618a282a```

##### Human Readable Output
### Entity 7ff48076-37b9-4bb5-83b1-db21618a282a details
|ID|Kind|Additional Data|Alert Display Name|Alert Type|Confidence Level|End Time Utc|Friendly Name|Processing End Time|Product Component Name|Product Name|Provider Alert Id|Severity|Start Time Utc|Status|System Alert Id|Tactics|Time Generated|Vendor Name|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 7ff48076-37b9-4bb5-83b1-db21618a282a | SecurityAlert | Query: SecurityAlert<br/>Query Period: 05:00:00<br/>Query Start Time UTC: 2020-03-28 18:45:59Z<br/>Query End Time UTC: 2020-03-28 23:45:59Z<br/>Trigger Operator: Equal<br/>Trigger Threshold: 0<br/>Query Results Aggregation Kind: SingleAlert<br/>Search Query Results Overall Count: 0 | Test rule | 275b61c7-26ae-4008-a739-1b61b78e7cef_f5b76ab9-a1ff-416e-a706-b3a3e102d68f | Unknown | 2020-03-28T23:45:59.7720057Z | Test rule | 2020-03-28T23:51:06.0937297Z | Scheduled Alerts | Azure Sentinel | e80525d0-1ef0-4f29-92bb-e19bd0894139 | Medium | 2020-03-28T18:45:59.7720057Z | New | 7ff48076-37b9-4bb5-83b1-db21618a282a | InitialAccess,<br/>Persistence,<br/>PrivilegeEscalation,<br/>DefenseEvasion,<br/>CredentialAccess,<br/>Discovery,<br/>LateralMovement,<br/>Execution,<br/>Collection,<br/>Exfiltration,<br/>CommandAndControl,<br/>Impact | 2020-03-28T23:51:06.0937297Z | Microsoft |


### azure-sentinel-list-entity-relations
***
Gets a list of an entity's relations from Azure Sentinel.


##### Base Command

`azure-sentinel-list-entity-relations`

> <i>Note:</i> In this command we use an endpoint which is not available in the stable API version.

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | The entity ID. | Required | 
| limit | The maximum number of relations to return. The default value is 50. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. Using this argument overrides all of the other command arguments. | Optional | 
| entity_kinds | A comma-separated list of entity kinds to filter by. By default, the result won't be filtered by kind.<br/>The optional kinds are: Account, Host, File, AzureResource, CloudApplication, DnsResolution, FileHash, Ip, Malware, Process, RegistryKey, RegistryValue, SecurityGroup, Url, IoTDevice, SecurityAlert, Bookmark. | Optional | 
| filter | Filter results using OData syntax. For example: properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For more information see the Azure documentation: https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.EntityRelatedResource.ID | String | The ID of the entity's related resource. | 
| AzureSentinel.EntityRelatedResource.Kind | String | The kind of the entity's related resource. | 
| AzureSentinel.NextLink.Description | String | Description about NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 
| AzureSentinel.EntityRelatedResource.EntityID | String | The entity ID. | 


##### Command Example
```!azure-sentinel-list-entity-relations entity_id=7ff48076-37b9-4bb5-83b1-db21618a282a```

##### Human Readable Output
### Entity 7ff48076-37b9-4bb5-83b1-db21618a282a Relations (1 results)
|ID|Incident ID|
|---|---|
| f1670c58-43dc-4b82-a13a-c732325c41f5 | 7ff48076-37b9-4bb5-83b1-db21618a282a |


### azure-sentinel-test
***
Tests connectivity to Azure Sentinel.

##### Base Command

`azure-sentinel-test`
##### Input

There are no input arguments for this command.

##### Context Output

There is no context output for this command.

##### Command Example
```!azure-sentinel-test```

##### Human Readable Output
```✅ Success!```
<!-- disable-secrets-detection-end -->
