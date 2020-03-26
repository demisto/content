Azure Sentinel is a cloud-native security information and event manager (SIEM) platform that uses built-in AI to help analyze large volumes of data across an enterprise.
This integration was integrated and tested with version xx of Azure Sentinel
## Configure Azure Sentinel on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Sentinel.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| isFetch | Fetch incidents | False |
| fetch_time | First fetch timestamp (<number> <time unit>, e.g., 12 hours, 7 days) | False |
| min_severity | The minimum severity of incidents to fetch. | False |
| incidentType | Incident type | False |
| url | Server base URL | True |
| tenant_id | Tenant ID | True |
| client_id | Client ID | True |
| client_secret | Client Secret | True |
| auth_code | Authorization Code (Click on the integration tips button on the top of the window ('?') for details) | True |
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
Get a single incident from Azure Sentinel.


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
| AzureSentinel.Incident.Title | String | The incident's title. | 
| AzureSentinel.Incident.Description | String | Description about the incident. | 
| AzureSentinel.Incident.Severity | String | The incident's severity. | 
| AzureSentinel.Incident.Status | String | The status of the incident. | 
| AzureSentinel.Incident.AssigneeName | String | The assignee name of the incident. | 
| AzureSentinel.Incident.AssigneeEmail | String | The assignee email of the incident. | 
| AzureSentinel.Incident.Label.Name | String | The label's name of the incident. | 
| AzureSentinel.Incident.Label.Type | String | The label's type of the incident. | 
| AzureSentinel.Incident.FirstActivityTimeUTC | Date | The incident's first activity time. | 
| AzureSentinel.Incident.LastActivityTimeUTC | Date | The incident's last activity time. | 
| AzureSentinel.Incident.LastModifiedTimeUTC | Date | The incident's last modification time. | 
| AzureSentinel.Incident.CreatedTimeUTC | Date | The incident's creation time. | 
| AzureSentinel.Incident.IncidentNumber | Number | The incident's number. | 
| AzureSentinel.Incident.AlertsCount | Number | Number of the alerts in the incident. | 
| AzureSentinel.Incident.BookmarkCount | Number | Number of bookmarks in the incident. | 
| AzureSentinel.Incident.CommentCount | Number | Number of comments in the incident. | 
| AzureSentinel.Incident.AlertProductNames | String | Alert product names of the incident. | 
| AzureSentinel.Incident.Tactics | String | The incident's tactics. | 
| AzureSentinel.Incident.FirstActivityTimeGenerated | Date | The incident's generated first activity time. | 
| AzureSentinel.Incident.LastActivityTimeGenerated | Date | The incident's generated last activity time. | 
| AzureSentinel.Incident.Etag | String | Etag of the incident. | 


##### Command Example
```!azure-sentinel-get-incident-by-id incident_id=b3de6b49-0945-454e-bb59-98087573cfc2```

##### Human Readable Output


### azure-sentinel-list-incidents
***
Get a list of incidents from Azure Sentinel.


##### Base Command

`azure-sentinel-list-incidents`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of incidents to return. Maximum value is 50. | Optional | 
| filter | Use OData syntax to filter your results (e.g `properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For further information, visit https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter | Optional | 
| next_link | A link that specifies a strating point to use for subsequent calls. Using this argument overrides all of the other command arguments. Note: wrap your input with backticks, as the link might have space characters. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.Incident.ID | String | The incident ID. | 
| AzureSentinel.Incident.Title | String | The incident's title. | 
| AzureSentinel.Incident.Description | String | Description about the incident. | 
| AzureSentinel.Incident.Severity | String | The incident's severity. | 
| AzureSentinel.Incident.Status | String | The status of the incident. | 
| AzureSentinel.Incident.AssigneeName | String | The assignee name of the incident. | 
| AzureSentinel.Incident.AssigneeEmail | String | The assignee email of the incident. | 
| AzureSentinel.Incident.Label.Name | String | The label's name of the incident. | 
| AzureSentinel.Incident.Label.Type | String | The label's type of the incident. | 
| AzureSentinel.Incident.FirstActivityTimeUTC | Date | The incident's first activity time. | 
| AzureSentinel.Incident.LastActivityTimeUTC | Date | The incident's last activity time. | 
| AzureSentinel.Incident.LastModifiedTimeUTC | Date | The incident's last modification time. | 
| AzureSentinel.Incident.CreatedTimeUTC | Date | The incident's creation time. | 
| AzureSentinel.Incident.IncidentNumber | Number | The incident's number. | 
| AzureSentinel.Incident.AlertsCount | Number | Number of the alerts in the incident. | 
| AzureSentinel.Incident.BookmarkCount | Number | Number of bookmarks in the incident. | 
| AzureSentinel.Incident.CommentCount | Number | Number of comments in the incident. | 
| AzureSentinel.Incident.AlertProductNames | String | Alert product names of the incident. | 
| AzureSentinel.Incident.Tactics | String | The incident's tactics. | 
| AzureSentinel.Incident.FirstActivityTimeGenerated | Date | The incident's generated first activity time. | 
| AzureSentinel.Incident.LastActivityTimeGenerated | Date | The incident's generated last activity time. | 
| AzureSentinel.NextLink.Description | String | Description about NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 
| AzureSentinel.Incident.Etag | String | Etag of the incident. | 


##### Command Example
```!azure-sentinel-list-incidents limit=5```

##### Human Readable Output


### azure-sentinel-update-incident
***
Update a single incident in Azure Sentinel.


##### Base Command

`azure-sentinel-update-incident`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| title | The incident title. | Optional | 
| description | The incident's description. | Optional | 
| severity | The incident's severity. | Optional | 
| status | The incident's status. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.Incident.ID | String | The incident ID. | 
| AzureSentinel.Incident.Title | String | The incident's title. | 
| AzureSentinel.Incident.Description | String | Description about the incident. | 
| AzureSentinel.Incident.Severity | String | The incident's severity. | 
| AzureSentinel.Incident.Status | String | The status of the incident. | 
| AzureSentinel.Incident.AssigneeName | String | The assignee name of the incident. | 
| AzureSentinel.Incident.AssigneeEmail | String | The assignee email of the incident. | 
| AzureSentinel.Incident.Label.Name | String | The label's name of the incident. | 
| AzureSentinel.Incident.Label.Type | String | The label's type of the incident. | 
| AzureSentinel.Incident.FirstActivityTimeUTC | Date | The incident's first activity time. | 
| AzureSentinel.Incident.LastActivityTimeUTC | Date | The incident's last activity time. | 
| AzureSentinel.Incident.LastModifiedTimeUTC | Date | The incident's last modification time. | 
| AzureSentinel.Incident.CreatedTimeUTC | Date | The incident's creation time. | 
| AzureSentinel.Incident.IncidentNumber | Number | The incident's number. | 
| AzureSentinel.Incident.AlertsCount | Number | Number of the alerts in the incident. | 
| AzureSentinel.Incident.BookmarkCount | Number | Number of bookmarks in the incident. | 
| AzureSentinel.Incident.CommentCount | Number | Number of comments in the incident. | 
| AzureSentinel.Incident.AlertProductNames | String | Alert product names of the incident. | 
| AzureSentinel.Incident.Tactics | String | The incident's tactics. | 
| AzureSentinel.Incident.FirstActivityTimeGenerated | Date | The incident's generated first activity time. | 
| AzureSentinel.Incident.LastActivityTimeGenerated | Date | The incident's generated last activity time. | 
| AzureSentinel.Incident.Etag | String | Etag of the incident. | 


##### Command Example
```!azure-sentinel-update-incident incident_id=b3de6b49-0945-454e-bb59-98087573cfc2 severity=Medium```

##### Human Readable Output


### azure-sentinel-delete-incident
***
Delete a single incident in Azure Sentinel.


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


### azure-sentinel-list-incident-comments
***
Get an incident comments from Azure Sentinel.


##### Base Command

`azure-sentinel-list-incident-comments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| limit | The maximum number of incident comments to return. Maximum value is 50. | Optional | 
| next_link | A link that specifies a strating point to use for subsequent calls. Using this argument overrides all of the other command arguments. Note: wrap your input with backticks, as the link might have space characters. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentComment.ID | String | Incident comment's ID. | 
| AzureSentinel.IncidentComment.IncidentID | String | Incident ID. | 
| AzureSentinel.IncidentComment.Message | String | The incident comment. | 
| AzureSentinel.IncidentComment.AuthorName | String | Comment's author name. | 
| AzureSentinel.IncidentComment.AuthorEmail | String | Comment's author email. | 
| AzureSentinel.IncidentComment.CreatedTimeUTC | Date | Comment's creation time. | 
| AzureSentinel.NextLink.Description | String | Description about NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 


##### Command Example
```!azure-sentinel-list-incident-comments incident_id=b3de6b49-0945-454e-bb59-98087573cfc2```

##### Human Readable Output


### azure-sentinel-incident-add-comment
***
Add a comment to an incident in Azure Sentinel.


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
| AzureSentinel.IncidentComment.ID | String | Incident comment's ID. | 
| AzureSentinel.IncidentComment.IncidentID | String | Incident ID. | 
| AzureSentinel.IncidentComment.Message | String | The incident comment. | 
| AzureSentinel.IncidentComment.AuthorName | String | Comment's author name. | 
| AzureSentinel.IncidentComment.AuthorEmail | String | Comment's author email. | 
| AzureSentinel.IncidentComment.CreatedTimeUTC | Date | Comment's creation time. | 


##### Command Example
```!azure-sentinel-incident-add-comment incident_id=b3de6b49-0945-454e-bb59-98087573cfc2 message="hello"```

##### Human Readable Output


### azure-sentinel-list-incident-relations
***
Get a list of an incident's related entities from Azure Sentinel.


##### Base Command

`azure-sentinel-list-incident-relations`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| limit | The maximum number of relations to return. | Optional | 
| next_link | A link that specifies a strating point to use for subsequent calls. Using this argument overrides all of the other command arguments. Note: wrap your input with backticks, as the link might have space characters. | Optional | 
| entity_kinds | Comma-separated list of entity kinds to filter by. By default, the result won't be filtered by kind.<br>The optional kinds are: Account, Host, File, AzureResource, CloudApplication, DnsResolution, FileHash, Ip, Malware, Process, RegistryKey, RegistryValue, SecurityGroup, Url, IoTDevice, SecurityAlert, Bookmark. | Optional | 
| filter | Use OData syntax to filter your results (e.g `properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For further information, visit https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentRelatedResource.ID | String | The ID of the incident's related resource. | 
| AzureSentinel.IncidentRelatedResource.Kind | String | The kind of the incident's related resource. | 
| AzureSentinel.NextLink.Description | String | Description about NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 
| AzureSentinel.IncidentRelatedResource.IncidentID | String | The incident ID. | 


##### Command Example
```!azure-sentinel-list-incident-relations incident_id=b3de6b49-0945-454e-bb59-98087573cfc2```

##### Human Readable Output


### azure-sentinel-get-entity-by-id
***
Get a single entity from Azure Sentinel. Use !azure-sentinel-list-incident-relations command, and get an entity ID to apply this command on. Notice that in the current Azure Sentinel API version, the retention period for GetEntityByID is 30 days.


##### Base Command

`azure-sentinel-get-entity-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | The entity ID. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!azure-sentinel-get-entity-by-id entity_id=a7bb8825-64f4-87ba-b0f4-97b7784e28e5```

##### Human Readable Output


### azure-sentinel-list-entity-relations
***
Get a list of an entity's relations from Azure Sentinel.


##### Base Command

`azure-sentinel-list-entity-relations`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | The entity ID. | Required | 
| limit | The maximum number of relations to return. | Optional | 
| next_link | A link that specifies a strating point to use for subsequent calls. Using this argument overrides all of the other command arguments. Note: wrap your input with backticks, as the link might have space characters. | Optional | 
| entity_kinds | Comma-separated list of entity kinds to filter by. By default, the result won't be filtered by kind.<br>The optional kinds are: Account, Host, File, AzureResource, CloudApplication, DnsResolution, FileHash, Ip, Malware, Process, RegistryKey, RegistryValue, SecurityGroup, Url, IoTDevice, SecurityAlert, Bookmark. | Optional | 
| filter | Use OData syntax to filter your results (e.g `properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For further information, visit https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.EntityRelatedResource.ID | String | The ID of the entity's related resource. | 
| AzureSentinel.EntityRelatedResource.Kind | String | The kind of the entity's related resource. | 
| AzureSentinel.NextLink.Description | String | Description about NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 
| AzureSentinel.EntityRelatedResource.EntityID | String | The entity ID. | 


##### Command Example
```!azure-sentinel-list-entity-relations entity_id=sdfdsf```

##### Human Readable Output

