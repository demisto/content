Use the Azure Sentinel integration to get and manage incidents and get related entity information for incidents.
This integration was integrated and tested with version xx of Azure Sentinel

## Configure Microsoft Sentinel on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Sentinel.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Tenant ID |  | False |
    | Tenant ID |  | False |
    | Client ID |  | False |
    | Password |  | False |
    | Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
    | Private Key |  | False |
    | Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
    | Azure Managed Identities Client ID | The Managed Identities client id for authentication - relevant only if the integration is running on Azure VM. | False |
    | Subscription ID |  | True |
    | Resource Group Name |  | True |
    | Workspace Name |  | True |
    | Fetch incidents |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | The minimum severity of incidents to fetch |  | False |
    | Incident type |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-sentinel-get-incident-by-id
***
Gets a single incident from Azure Sentinel.


#### Base Command

`azure-sentinel-get-incident-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 


#### Context Output

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
| AzureSentinel.Incident.IncidentUrl | String | The deep-link URL to the incident in the Azure portal. | 

### azure-sentinel-list-incidents
***
Gets a list of incidents from Azure Sentinel.


#### Base Command

`azure-sentinel-list-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of incidents to return. The maximum value is 200. Default is 50. | Optional | 
| filter | Filter results using OData syntax. For example: properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For more information, see the Azure documentation: https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. This argument overrides all of the other command arguments. | Optional | 


#### Context Output

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

### azure-sentinel-list-watchlists
***
Gets a list of watchlists from Azure Sentinel.


#### Base Command

`azure-sentinel-list-watchlists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_alias | Alias of the specific watchlist to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.Watchlist.ID | String | The watchlist ID. | 
| AzureSentinel.Watchlist.Description | String | A description of the watchlist. | 
| AzureSentinel.Watchlist.DisplayName | String | The display name of the watchlist. | 
| AzureSentinel.Watchlist.Provider | String | The provider of the watchlist. | 
| AzureSentinel.Watchlist.Source | String | The source of the watchlist. | 
| AzureSentinel.Watchlist.Created | Date | The time the watchlist was created. | 
| AzureSentinel.Watchlist.Updated | Date | The last time the watchlist was updated. | 
| AzureSentinel.Watchlist.CreatedBy | String | The name of the user who created the watchlist. | 
| AzureSentinel.Watchlist.UpdatedBy | String | The name of the user who updated the watchlist. | 
| AzureSentinel.Watchlist.Alias | String | The alias of the watchlist. | 
| AzureSentinel.Watchlist.Label | unknown | Label that will be used to tag and filter on. | 
| AzureSentinel.Watchlist.ItemsSearchKey | String | The search key is used to optimize query performance when using watchlists for joins with other data. For example, enable a column with IP addresses to be the designated SearchKey field, then use this field as the key field when joining to other event data by IP address. | 
| AzureSentinel.NextLink.Description | String | Description of NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns partial results. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 

### azure-sentinel-delete-watchlist
***
Delete a watchlist from Azure Sentinel.


#### Base Command

`azure-sentinel-delete-watchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_alias | Alias of the watchlist to be deleted. | Required | 


#### Context Output

There is no context output for this command.
### azure-sentinel-watchlist-create-update
***
Create or update a watchlist in Azure Sentinel.


#### Base Command

`azure-sentinel-watchlist-create-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_alias | The alias of the new watchlist or the watchlist to update. | Required | 
| watchlist_display_name | The display name of the watchlist. | Required | 
| description | The description of the watchlist. | Optional | 
| provider | The provider of the watchlist. Default is XSOAR. | Optional | 
| labels | The labels of the watchlist. | Optional | 
| lines_to_skip | The number of lines in the CSV content to skip before the header. Default is 0. | Optional | 
| file_entry_id | A file entry with raw content that represents the watchlist items to create. | Required | 
| items_search_key | The search key is used to optimize query performance when using watchlists for joins with other data. For example, enable a column with IP addresses to be the designated SearchKey field, then use this field as the key field when joining to other event data by IP address. | Required | 
| content_type | The content type of the raw content. For now, only text/csv is valid. Default is Text/Csv. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.Watchlist.Name | String | The name of the watchlist. | 
| AzureSentinel.Watchlist.ID | String | The ID \(GUID\) of the watchlist. | 
| AzureSentinel.Watchlist.Description | String | A description of the watchlist. | 
| AzureSentinel.Watchlist.Provider | String | The provider of the watchlist. | 
| AzureSentinel.Watchlist.Source | String | The source of the watchlist. | 
| AzureSentinel.Watchlist.Created | Date | The time the watchlist was created. | 
| AzureSentinel.Watchlist.Updated | Date | The time the watchlist was updated. | 
| AzureSentinel.Watchlist.CreatedBy | String | The user who created the watchlist. | 
| AzureSentinel.Watchlist.UpdatedBy | String | The user who updated the watchlist. | 
| AzureSentinel.Watchlist.Alias | String | The alias of the watchlist. | 
| AzureSentinel.Watchlist.Label | Unknown | List of labels relevant to this watchlist. | 
| AzureSentinel.Watchlist.ItemsSearchKey | String | The search key is used to optimize query performance when using watchlists for joins with other data. | 

### azure-sentinel-update-incident
***
Updates a single incident in Azure Sentinel.


#### Base Command

`azure-sentinel-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| title | The incident's title. | Optional | 
| description | Description of the incident. | Optional | 
| severity | The incident severity. Possible values are: High, Medium, Low, Informational. | Optional | 
| status | The incident status. Possible values are: New, Active, Closed. | Optional | 
| classification | The reason the incident was closed. Required when updating the status to Closed. Possible values are: BenignPositive, FalsePositive, TruePositive, Undetermined. | Optional | 
| classification_comment | Describes the reason the incident was closed. | Optional | 
| classification_reason | The classification reason the incident was closed with. Required when updating the status to Closed and the classification is determined. Possible values are: InaccurateData, IncorrectAlertLogic, SuspiciousActivity, SuspiciousButExpected. | Optional | 
| assignee_email | The email address of the incident assignee. It is recommended to update *user_principal_name* instead of this field. Note that the updated API field is `owner.email`. | Optional | 
| user_principal_name | The user principal name of the client. Note that the updated API field is `owner.userPrincipalName`. | Optional | 
| labels | Incident labels. Note that all labels will be set as labelType='User'. | Optional | 


#### Context Output

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

### azure-sentinel-delete-incident
***
Deletes a single incident in Azure Sentinel.


#### Base Command

`azure-sentinel-delete-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 


#### Context Output

There is no context output for this command.
### azure-sentinel-list-incident-comments
***
Gets the comments of an incident from Azure Sentinel.


#### Base Command

`azure-sentinel-list-incident-comments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| limit | The maximum number of incident comments to return. The maximum value is 50. Default is 50. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. Using this argument overrides all of the other command arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentComment.ID | String | The ID of the incident comment. | 
| AzureSentinel.IncidentComment.IncidentID | String | The incident ID. | 
| AzureSentinel.IncidentComment.Message | String | The incident comment. | 
| AzureSentinel.IncidentComment.AuthorName | String | The name of the author of the incident's comment. | 
| AzureSentinel.IncidentComment.AuthorEmail | String | The email address of the author of the incident comment. | 
| AzureSentinel.IncidentComment.CreatedTimeUTC | Date | The date and time that the incident comment was created. | 
| AzureSentinel.NextLink.Description | String | Description of NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 

### azure-sentinel-incident-add-comment
***
Adds a comment to an incident in Azure Sentinel.


#### Base Command

`azure-sentinel-incident-add-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| message | The comment message. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentComment.ID | String | The ID of the incident comment. | 
| AzureSentinel.IncidentComment.IncidentID | String | The incident ID. | 
| AzureSentinel.IncidentComment.Message | String | The incident's comment. | 
| AzureSentinel.IncidentComment.AuthorName | String | The name of the author of the incident's comment. | 
| AzureSentinel.IncidentComment.AuthorEmail | String | The email address of the author of the incident comment. | 
| AzureSentinel.IncidentComment.CreatedTimeUTC | Date | The date and time that the incident comment was created. | 

### azure-sentinel-incident-delete-comment
***
Deletes a comment from incident in Azure Sentinel.


#### Base Command

`azure-sentinel-incident-delete-comment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| comment_id | The comment ID. | Required | 


#### Context Output

There is no context output for this command.
### azure-sentinel-list-incident-relations
***
Gets a list of an incident's related entities from Azure Sentinel.


#### Base Command

`azure-sentinel-list-incident-relations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| limit | The maximum number of related entities to return. Default is 50. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. Using this argument overrides all of the other command arguments. | Optional | 
| entity_kinds | A comma-separated list of entity kinds to filter by. By default, the results won't be filtered by kind.<br/>The optional kinds are: Account, Host, File, AzureResource, CloudApplication, DnsResolution, FileHash, Ip, Malware, Process, RegistryKey, RegistryValue, SecurityGroup, Url, IoTDevice, SecurityAlert, Bookmark. Possible values are: . | Optional | 
| filter | Filter results using OData syntax. For example: properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For more information see the Azure documentation: https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentRelatedResource.ID | String | The ID of the incident's related resource. | 
| AzureSentinel.IncidentRelatedResource.Kind | String | The kind of the incident's related resource. | 
| AzureSentinel.NextLink.Description | String | The description about NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 
| AzureSentinel.IncidentRelatedResource.IncidentID | String | The incident ID. | 

### azure-sentinel-list-incident-entities
***
Gets a list of an incident's entities from Azure Sentinel.


#### Base Command

`azure-sentinel-list-incident-entities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentEntity.ID | String | The ID of the entity. | 
| AzureSentinel.IncidentEntity.IncidentId | String | The ID of the incident. | 
| AzureSentinel.IncidentEntity.Kind | String | The kind of the entity. | 
| AzureSentinel.IncidentEntity.Properties | Unknown | The properties of the entity. | 

### azure-sentinel-list-incident-alerts
***
Gets a list of an incident's alerts from Azure Sentinel.


#### Base Command

`azure-sentinel-list-incident-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentAlert.ID | String | The ID of the alert. | 
| AzureSentinel.IncidentAlert.IncidentId | String | The ID of the incident. | 
| AzureSentinel.IncidentAlert.Kind | String | The kind of the alert. | 
| AzureSentinel.IncidentAlert.Tactic | Unknown | The tactics of the alert. | 
| AzureSentinel.IncidentAlert.DisplayName | String | The display name of the alert. | 
| AzureSentinel.IncidentAlert.Description | String | The description of the alert. | 
| AzureSentinel.IncidentAlert.ConfidenceLevel | String | The confidence level of this alert. | 
| AzureSentinel.IncidentAlert.Severity | String | The severity of the alert. | 
| AzureSentinel.IncidentAlert.VendorName | String | The name of the vendor that raised the alert. | 
| AzureSentinel.IncidentAlert.ProductName | String | The name of the product that published this alert. | 
| AzureSentinel.IncidentAlert.ProductComponentName | String | The name of a component inside the product which generated the alert. | 

### azure-sentinel-list-watchlist-items
***
Get a single watchlist item or list of watchlist items.


#### Base Command

`azure-sentinel-list-watchlist-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_alias | The alias of the watchlist. | Required | 
| watchlist_item_id | The ID of the single watchlist item. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.WatchlistItem.WatchlistAlias | String | The alias of the watchlist. | 
| AzureSentinel.WatchlistItem.ID | String | The ID \(GUID\) of the watchlist item. | 
| AzureSentinel.WatchlistItem.Created | Date | The time the watchlist item was created. | 
| AzureSentinel.WatchlistItem.Updated | Date | The last time the watchlist item was updated. | 
| AzureSentinel.WatchlistItem.CreatedBy | String | The name of the user. | 
| AzureSentinel.WatchlistItem.UpdatedBy | String | The user who updated this item. | 
| AzureSentinel.WatchlistItem.ItemsKeyValue | Unknown | Key-value pairs for a watchlist item. | 

### azure-sentinel-delete-watchlist-item
***
Delete a watchlist item.


#### Base Command

`azure-sentinel-delete-watchlist-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_alias | The watchlist alias. | Required | 
| watchlist_item_id | The watchlist item ID to be deleted. | Required | 


#### Context Output

There is no context output for this command.
### azure-sentinel-create-update-watchlist-item
***
Create or update a watchlist item.


#### Base Command

`azure-sentinel-create-update-watchlist-item`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_alias | The watchlist alias. | Required | 
| watchlist_item_id | The watchlist item ID (GUID) to update. | Optional | 
| item_key_value | The JSON for the itemsKeyValue of the item (the key value is different from watchlist to watchlist). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.WatchlistItem.WatchlistAlias | String | The alias of the watchlist. | 
| AzureSentinel.WatchlistItem.ID | String | The ID \(GUID\) of the watchlist item. | 
| AzureSentinel.WatchlistItem.Created | Date | The time the watchlist item was created. | 
| AzureSentinel.WatchlistItem.Updated | Date | The last time the watchlist item was updated. | 
| AzureSentinel.WatchlistItem.CreatedBy | String | The name of the user who created this watchlist item. | 
| AzureSentinel.WatchlistItem.UpdatedBy | String | The user who updated this watchlist item. | 
| AzureSentinel.WatchlistItem.ItemsKeyValue | Unknown | Key-value pairs for a watchlist item. | 

### azure-sentinel-threat-indicator-list
***
Returns a list of threat indicators.


#### Base Command

`azure-sentinel-threat-indicator-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_name | The name of the indicator. | Optional | 
| limit | The maximum number of indicators to return. Default is 50. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls.<br/>This argument overrides all of the other command arguments.<br/>There may be no support for pagination. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.ThreatIndicator.ID | String | The ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Name | String | The name of the indicator. | 
| AzureSentinel.ThreatIndicator.ETag | String | The ETag of the indicator. | 
| AzureSentinel.ThreatIndicator.Type | String | The type of the indicator. | 
| AzureSentinel.ThreatIndicator.Kind | String | The kind of the indicator. | 
| AzureSentinel.ThreatIndicators.Confidence | Number | The confidence of the threat indicator. This is a number between 0-100. | 
| AzureSentinel.ThreatIndicator.Created | Date | When the threat indicator was created. | 
| AzureSentinel.ThreatIndicator.CreatedByRef | String | The creator of the indicator. | 
| AzureSentinel.ThreatIndicator.ExternalID | String | The external ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Revoked | Boolean | Whether the threat indicator was revoked. | 
| AzureSentinel.ThreatIndicator.Source | String | The source of the indicator. | 
| AzureSentinel.ThreatIndicator.ETags | String | The Etags of the indicator. | 
| AzureSentinel.ThreatIndicator.DisplayName | String | The display name of the indicator. | 
| AzureSentinel.ThreatIndicator.Description | String | The description of the indicator. | 
| AzureSentinel.ThreatIndicator.ThreatTypes | Unknown | The threat types of the indicator. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.KillChainName | String | The kill chain's name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeKey | Unknown | The pattern type key of the indicator. | 
| AzureSentinel.ThreatIndicator.Pattern | String | The pattern of the indicator. | 
| AzureSentinel.ThreatIndicator.PatternType | String | The pattern type of the indicator. | 
| AzureSentinel.ThreatIndicator.ValidFrom | Date | The date from which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.ValidUntil | Date | The date until which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.PhaseName | String | The phase name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.Value | String | The value of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.ValueType | String | The value type of the indicator. | 
| AzureSentinel.ThreatIndicator.LastUpdatedTimeUtc | Date | The last updated time of the indicator. | 
| AzureSentinel.ThreatIndicator.Tags | Unknown | The tags of the indicator. | 
| AzureSentinel.ThreatIndicator.Types | Unknown | The threat types of the indicator. | 

### azure-sentinel-threat-indicator-query
***
Returns a list of threat indicators with specific entities.


#### Base Command

`azure-sentinel-threat-indicator-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls.<br/>This argument overrides all of the other command arguments.<br/>There may be no support for pagination. | Optional | 
| min_confidence | The minimum confidence number for a threat indicator. | Optional | 
| max_confidence | The maximum confidence number for a threat indicator. | Optional | 
| min_valid_until | Minimum valid until value of indicators to query. | Optional | 
| max_valid_until | Maximum valid until value of indicators to query. | Optional | 
| include_disabled | If true, the query also returns disabled indicators. Possible values are: true, false. Default is false. | Optional | 
| sources | The sources of the threat indicator. | Optional | 
| indicator_types | The indicator types of the threat indicator. Possible values are: ipv4, ipv6, file, url, domain. | Optional | 
| threat_types | A comma-separated list of threat types of the threat indicator. Possible values are: anomalous-activity, attribution, anonymization, benign, malicious-activity, compromised, unknown. | Optional | 
| keywords | A comma-separated list of keywords. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.ThreatIndicator.ID | String | The ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Name | String | The name of the indicator. | 
| AzureSentinel.ThreatIndicator.ETag | String | The ETag of the indicator. | 
| AzureSentinel.ThreatIndicator.Type | String | The type of the indicator. | 
| AzureSentinel.ThreatIndicator.Kind | String | The kind of the indicator. | 
| AzureSentinel.ThreatIndicators.Confidence | Number | The confidence of the threat indicator. This is a number between 0-100. | 
| AzureSentinel.ThreatIndicator.Created | Date | When the threat indicator was created. | 
| AzureSentinel.ThreatIndicator.CreatedByRef | String | The creator of the indicator. | 
| AzureSentinel.ThreatIndicator.ExternalID | String | The external ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Revoked | Boolean | Whether the threat indicator was revoked. | 
| AzureSentinel.ThreatIndicator.Source | String | The source of the indicator. | 
| AzureSentinel.ThreatIndicator.ETags | String | The Etags of the indicator. | 
| AzureSentinel.ThreatIndicator.DisplayName | String | The display name of the indicator. | 
| AzureSentinel.ThreatIndicator.Description | String | The description of the indicator. | 
| AzureSentinel.ThreatIndicator.ThreatTypes | Unknown | The threat types of the indicator. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.KillChainName | String | The kill chain's name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeKey | Unknown | The pattern type key of the indicator. | 
| AzureSentinel.ThreatIndicator.Pattern | String | The pattern of the indicator. | 
| AzureSentinel.ThreatIndicator.PatternType | String | The pattern type of the indicator. | 
| AzureSentinel.ThreatIndicator.ValidFrom | Date | The date from which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.ValidUntil | Date | The date until which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.PhaseName | String | The phase name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.Value | String | The value of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.ValueType | String | The value type of the indicator. | 
| AzureSentinel.ThreatIndicator.LastUpdatedTimeUtc | Date | The last updated time of the indicator. | 
| AzureSentinel.ThreatIndicator.Tags | Unknown | The tags of the indicator. | 
| AzureSentinel.ThreatIndicator.Types | Unknown | The threat types of the indicator. | 

### azure-sentinel-threat-indicator-create
***
Creates a new threat indicator.


#### Base Command

`azure-sentinel-threat-indicator-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The value of the threat indicator. | Required | 
| display_name | The display name of the new indicator. | Required | 
| description | The description of the new indicator. | Optional | 
| indicator_type | The type of the new indicator. Possible values are: ipv4, ipv6, file, url, domain. | Required | 
| hash_type | The hash type of the new indicator. This argument is mandatory if the indicator type is file. Possible values are: MD5, SHA-1, SHA-256, SHA-512. | Optional | 
| confidence | The confidence of the new threat indicator. Should be a number between 0-100. | Optional | 
| threat_types | A comma-separated list of threat types of the threat indicator. Possible values are: anomalous-activity, attribution, anonymization, benign, malicious-activity, compromised, unknown. | Required | 
| kill_chains | The kill chains phases of the indicator. | Optional | 
| tags | A comma-separated list of tags of the new threat indicator. | Optional | 
| valid_from | The date from which the indicator is valid. | Optional | 
| valid_until | The date until which the indicator is valid. | Optional | 
| created_by | The creator of the new indicator. | Optional | 
| revoked | If true, the indicator is revoked. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.ThreatIndicator.ID | String | The ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Name | String | The name of the indicator. | 
| AzureSentinel.ThreatIndicator.ETag | String | The ETag of the indicator. | 
| AzureSentinel.ThreatIndicator.Type | String | The type of the indicator. | 
| AzureSentinel.ThreatIndicator.Kind | String | The kind of the indicator. | 
| AzureSentinel.ThreatIndicators.Confidence | Number | The confidence of the threat indicator. This is a number between 0-100. | 
| AzureSentinel.ThreatIndicator.Created | Date | When the threat indicator was created. | 
| AzureSentinel.ThreatIndicator.CreatedByRef | String | The creator of the indicator. | 
| AzureSentinel.ThreatIndicator.ExternalID | String | The external ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Revoked | Boolean | Whether the threat indicator was revoked. | 
| AzureSentinel.ThreatIndicator.Source | String | The source of the indicator. | 
| AzureSentinel.ThreatIndicator.ETags | String | The Etags of the indicator. | 
| AzureSentinel.ThreatIndicator.DisplayName | String | The display name of the indicator. | 
| AzureSentinel.ThreatIndicator.Description | String | The description of the indicator. | 
| AzureSentinel.ThreatIndicator.ThreatTypes | Unknown | The threat types of the indicator. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.KillChainName | String | The kill chain's name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeKey | Unknown | The pattern type key of the indicator. | 
| AzureSentinel.ThreatIndicator.Pattern | String | The pattern of the indicator. | 
| AzureSentinel.ThreatIndicator.PatternType | String | The pattern type of the indicator. | 
| AzureSentinel.ThreatIndicator.ValidFrom | Date | The date from which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.ValidUntil | Date | The date until which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.PhaseName | String | The phase name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.Value | String | The value of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.ValueType | String | The value type of the indicator. | 
| AzureSentinel.ThreatIndicator.LastUpdatedTimeUtc | Date | The last updated time of the indicator. | 
| AzureSentinel.ThreatIndicator.Tags | Unknown | The tags of the indicator. | 
| AzureSentinel.ThreatIndicator.Types | Unknown | The threat types of the indicator. | 

### azure-sentinel-threat-indicator-update
***
Updates an existing threat indicator.


#### Base Command

`azure-sentinel-threat-indicator-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_name | The name of the indicator. | Required | 
| value | The value of the indicator. | Required | 
| display_name | The display name of the indicator. | Required | 
| description | The description of the threat indicator. | Optional | 
| indicator_type | The type of the indicator. Possible values are: ipv4, ipv6, file, url, domain. | Required | 
| hash_type | If indicator_type is a file, this entry is mandatory. | Optional | 
| revoked | Whether the indicator is revoked. | Optional | 
| confidence | The confidence of the threat indicator. This is a number between 0-100. | Optional | 
| threat_types | A comma-separated list of threat types of the threat indicator. Possible values are: anomalous-activity, attribution, anonymization, benign, malicious-activity, compromised, unknown. | Optional | 
| kill_chains | A comma-separated list of  kill chains phases of the indicator. | Optional | 
| tags | A comma-separated list of tags of the threat indicator. | Optional | 
| valid_from | The date from which the indicator is valid. | Optional | 
| valid_until | The date until which the indicator is valid. | Optional | 
| created_by | The creator of the indicator. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.ThreatIndicator.ID | String | The ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Name | String | The name of the indicator. | 
| AzureSentinel.ThreatIndicator.ETag | String | The ETag of the indicator. | 
| AzureSentinel.ThreatIndicator.Type | String | The type of the indicator. | 
| AzureSentinel.ThreatIndicator.Kind | String | The kind of the indicator. | 
| AzureSentinel.ThreatIndicators.Confidence | Number | The confidence of the threat indicator. This is a number between 0-100. | 
| AzureSentinel.ThreatIndicator.Created | Date | When the threat indicator was created. | 
| AzureSentinel.ThreatIndicator.CreatedByRef | String | The creator of the indicator. | 
| AzureSentinel.ThreatIndicator.ExternalID | String | The external ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Revoked | Boolean | Was the threat indicator revoked or not. | 
| AzureSentinel.ThreatIndicator.Source | String | The source of the indicator. | 
| AzureSentinel.ThreatIndicator.ETags | String | The Etags of the indicator. | 
| AzureSentinel.ThreatIndicator.DisplayName | String | The display name of the indicator. | 
| AzureSentinel.ThreatIndicator.Description | String | The description of the indicator. | 
| AzureSentinel.ThreatIndicator.ThreatTypes | Unknown | The threat types of the indicator. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.KillChainName | String | The kill chain's name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeKey | Unknown | The pattern type key of the indicator. | 
| AzureSentinel.ThreatIndicator.Pattern | String | The pattern of the indicator. | 
| AzureSentinel.ThreatIndicator.PatternType | String | The pattern type of the indicator. | 
| AzureSentinel.ThreatIndicator.ValidFrom | Date | The date from which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.ValidUntil | Date | The date until which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.PhaseName | String | The phase name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.Value | String | The value of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.ValueType | String | The value type of the indicator. | 
| AzureSentinel.ThreatIndicator.LastUpdatedTimeUtc | Date | The last updated time of the indicator. | 
| AzureSentinel.ThreatIndicator.Tags | Unknown | The tags of the indicator. | 
| AzureSentinel.ThreatIndicator.Types | Unknown | The threat types of the indicator. | 

### azure-sentinel-threat-indicator-delete
***
Deletes an existing threat indicator.


#### Base Command

`azure-sentinel-threat-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_names | A comma-separated list of indicators to delete. | Required | 


#### Context Output

There is no context output for this command.
### azure-sentinel-threat-indicator-tags-append
***
Appends new tags to an existing indicator.


#### Base Command

`azure-sentinel-threat-indicator-tags-append`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_name | The name of the indicator. | Required | 
| tags | A comma-separated list of tags to append. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.ThreatIndicator.ID | String | The ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Name | String | The name of the indicator. | 
| AzureSentinel.ThreatIndicator.ETag | String | The ETag of the indicator. | 
| AzureSentinel.ThreatIndicator.Type | String | The type of the indicator. | 
| AzureSentinel.ThreatIndicator.Kind | String | The kind of the indicator. | 
| AzureSentinel.ThreatIndicators.Confidence | Number | The confidence of the threat indicator. THis is a number between 0-100. | 
| AzureSentinel.ThreatIndicator.Created | Date | When the threat indicator was created. | 
| AzureSentinel.ThreatIndicator.CreatedByRef | String | The creator of the indicator. | 
| AzureSentinel.ThreatIndicator.ExternalID | String | The external ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Revoked | Boolean | Was the threat indicator revoked or not. | 
| AzureSentinel.ThreatIndicator.Source | String | The source of the indicator. | 
| AzureSentinel.ThreatIndicator.ETags | String | The Etags of the indicator. | 
| AzureSentinel.ThreatIndicator.DisplayName | String | The display name of the indicator. | 
| AzureSentinel.ThreatIndicator.Description | String | The description of the indicator. | 
| AzureSentinel.ThreatIndicator.ThreatTypes | Unknown | The threat types of the indicator. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.KillChainName | String | The kill chain's name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeKey | Unknown | The pattern type key of the indicator. | 
| AzureSentinel.ThreatIndicator.Pattern | String | The pattern of the indicator. | 
| AzureSentinel.ThreatIndicator.PatternType | String | The pattern type of the indicator. | 
| AzureSentinel.ThreatIndicator.ValidFrom | Date | The date from which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.ValidUntil | Date | The date until which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.PhaseName | String | The phase name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.Value | String | The value of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.ValueType | String | The value type of the indicator. | 
| AzureSentinel.ThreatIndicator.LastUpdatedTimeUtc | Date | The last updated time of the indicator. | 
| AzureSentinel.ThreatIndicator.Tags | Unknown | The tags of the indicator. | 
| AzureSentinel.ThreatIndicator.Types | Unknown | The threat types of the indicator. | 

### azure-sentinel-threat-indicator-tags-replace
***
Replaces the tags of a given indicator.


#### Base Command

`azure-sentinel-threat-indicator-tags-replace`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_name | The name of the indicator. | Required | 
| tags | A comma-separated list of tags to replace. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.ThreatIndicator.ID | String | The ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Name | String | The name of the indicator. | 
| AzureSentinel.ThreatIndicator.ETag | String | The ETag of the indicator. | 
| AzureSentinel.ThreatIndicator.Type | String | The type of the indicator. | 
| AzureSentinel.ThreatIndicator.Kind | String | The kind of the indicator. | 
| AzureSentinel.ThreatIndicators.Confidence | Number | The confidence of the threat indicator. This is a number between 0-100. | 
| AzureSentinel.ThreatIndicator.Created | Date | When the threat indicator was created. | 
| AzureSentinel.ThreatIndicator.CreatedByRef | String | The creator of the indicator. | 
| AzureSentinel.ThreatIndicator.ExternalID | String | The external ID of the indicator. | 
| AzureSentinel.ThreatIndicator.Revoked | Boolean | Whether the threat indicator was revoked. | 
| AzureSentinel.ThreatIndicator.Source | String | The source of the indicator. | 
| AzureSentinel.ThreatIndicator.ETags | String | The Etags of the indicator. | 
| AzureSentinel.ThreatIndicator.DisplayName | String | The display name of the indicator. | 
| AzureSentinel.ThreatIndicator.Description | String | The description of the indicator. | 
| AzureSentinel.ThreatIndicator.ThreatTypes | Unknown | The threat types of the indicator. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.KillChainName | String | The kill chain's name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeKey | Unknown | The pattern type key of the indicator. | 
| AzureSentinel.ThreatIndicator.Pattern | String | The pattern of the indicator. | 
| AzureSentinel.ThreatIndicator.PatternType | String | The pattern type of the indicator. | 
| AzureSentinel.ThreatIndicator.ValidFrom | Date | The date from which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.ValidUntil | Date | The date until which the indicator is valid. | 
| AzureSentinel.ThreatIndicator.KillChainPhases.PhaseName | String | The phase name of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.Value | String | The value of the indicator. | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.ValueType | String | The value type of the indicator. | 
| AzureSentinel.ThreatIndicator.LastUpdatedTimeUtc | Date | The last updated time of the indicator. | 
| AzureSentinel.ThreatIndicator.Tags | Unknown | The tags of the indicator. | 
| AzureSentinel.ThreatIndicator.Types | Unknown | The threat types of the indicator. | 
