Azure Sentinel is a cloud-native security information and event manager (SIEM) platform that uses built-in AI to help analyze large volumes of data across an enterprise.
This integration was integrated and tested with version xx of Azure Sentinel
## Configure Azure Sentinel on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Sentinel.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| isFetch | Fetch incidents | False |
| fetch_time | First fetch timestamp ({number} {time unit}, e.g., 12 hours, 7 days) | False |
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
### Incident b3de6b49-0945-454e-bb59-98087573cfc2 details
|ID|Incident Number|Title|Description|Severity|Status|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|First Activity Time Generated|Last Activity Time Generated|Etag|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| b3de6b49-0945-454e-bb59-98087573cfc2 | 214 | test_title | test description | Medium | Active | 2020-03-26T12:57:57Z | 2020-02-02T14:10:01Z | 1 | 0 | 14 | Azure Sentinel | 2020-02-02T14:10:01Z | 2020-02-02T14:10:01Z | "7301797c-0000-0100-0000-5e7ca6d50000" |

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
### Incidents List (5 results)
|ID|Incident Number|Title|Description|Severity|Status|First Activity Time UTC|Last Activity Time UTC|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|First Activity Time Generated|Last Activity Time Generated|Etag|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 35bc3532-494c-44c1-adb8-3d733d966471 | 1 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T07:54:05Z | 2020-01-15T08:54:05Z | 2020-01-15T09:29:12Z | 2020-01-15T09:29:12Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:29:12Z | 2020-01-15T09:29:12Z | "19008ba5-0000-0100-0000-5e1edb680000" |
| 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | 2 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T08:24:05Z | 2020-01-15T09:24:05Z | 2020-01-15T09:29:14Z | 2020-01-15T09:29:14Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:29:14Z | 2020-01-15T09:29:14Z | "190093a5-0000-0100-0000-5e1edb6a0000" |
| e0b06d71-b5a3-43a9-997f-f25b45085cb7 | 4 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T07:59:05Z | 2020-01-15T08:59:05Z | 2020-01-15T09:34:12Z | 2020-01-15T09:34:12Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:34:12Z | 2020-01-15T09:34:12Z | "1900fda9-0000-0100-0000-5e1edc940000" |
| 0c16e64d-3bf5-4f7f-a965-cbab1e5ffcc4 | 5 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T08:34:06Z | 2020-01-15T09:34:06Z | 2020-01-15T09:39:13Z | 2020-01-15T09:39:13Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:39:12Z | 2020-01-15T09:39:12Z | "190094ae-0000-0100-0000-5e1eddc10000" |
| a7977be7-1008-419b-877b-6793b7402a80 | 6 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br>exceeds a threshold (default is 100). | Medium | New | 2020-01-15T08:04:05Z | 2020-01-15T09:04:05Z | 2020-01-15T09:40:09Z | 2020-01-15T09:40:09Z | 1 | 0 | 0 | Azure Sentinel | 2020-01-15T09:40:09Z | 2020-01-15T09:40:09Z | "19007eaf-0000-0100-0000-5e1eddf90000" |


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
### Updated incidents b3de6b49-0945-454e-bb59-98087573cfc2 details
|ID|Incident Number|Title|Description|Severity|Status|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|First Activity Time Generated|Last Activity Time Generated|Etag|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| b3de6b49-0945-454e-bb59-98087573cfc2 | 214 | Test Incident | test description | Medium | Active | 2020-03-26T12:53:02Z | 2020-02-02T14:10:01Z | 1 | 0 | 13 | Azure Sentinel | 2020-02-02T14:10:01Z | 2020-02-02T14:10:01Z | "7301806b-0000-0100-0000-5e7ca5ae0000" |


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
Incident ca5ffab9-25ff-413d-8000-12d3894b8468 was deleted successfully.

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
### Incident b3de6b49-0945-454e-bb59-98087573cfc2 Comments (4 results)
|ID|Incident ID|Message|Author Email|Created Time UTC|
|---|---|---|---|---|
| 295553115212022172880571041415135580062 | b3de6b49-0945-454e-bb59-98087573cfc2 | This is a message | test@demisto.com | 2020-03-25T14:05:22Z |
| 68963242547946961037852832278311632312 | b3de6b49-0945-454e-bb59-98087573cfc2 | hello 123 | test@demisto.com | 2020-03-25T11:54:44Z |
| 129016399225162631970999636732817548146 | b3de6b49-0945-454e-bb59-98087573cfc2 | Test message | test@demisto.com | 2020-03-05T10:31:05Z |
| 205343125729153100039024461040878407049 | b3de6b49-0945-454e-bb59-98087573cfc2 | This is test | test@demisto.com | 2020-03-05T10:29:42Z |


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
### Incident b3de6b49-0945-454e-bb59-98087573cfc2 new comment details
|ID|Incident ID|Message|Author Email|Created Time UTC|
|---|---|---|---|---|
| 22830063555802832669755633455570921192 | b3de6b49-0945-454e-bb59-98087573cfc2 | hello | test@demisto.com | 2020-03-26T13:25:20Z |


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
### Incident b3de6b49-0945-454e-bb59-98087573cfc2 Relations (1 results)
|ID|Incident ID|Kind|
|---|---|---|
| f8f7a4c4-b617-4c7f-bdb2-321756dd1d21 | b3de6b49-0945-454e-bb59-98087573cfc2 | SecurityAlert |


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
### Entity a7bb8825-64f4-87ba-b0f4-97b7784e28e5 details
|ID|Kind|Friendly Name|Resource Id|
|---|---|---|---|
| a7bb8825-64f4-87ba-b0f4-97b7784e28e5 | AzureResource | alerts | /subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourcegroups/cloud-shell-storage-eastus/providers/microsoft.compute/virtualmachines/alerts |


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
```!azure-sentinel-list-entity-relations entity_id=a7bb8825-64f4-87ba-b0f4-97b7784e28e5```

##### Human Readable Output
### Entity a7bb8825-64f4-87ba-b0f4-97b7784e28e5 Relations (0 results)
**No entries.**

