Use the Azure Sentinel integration to get and manage incidents and get related entity information for incidents.
This integration was integrated and tested with version 2021-04-01 of Azure Sentinel.

## Authorize Cortex XSOAR for Azure Sentinel

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the **Register an application** section of the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#register-an-application). (Note: There is no need to create a redirect URI or complete subsequent steps of the article).
2. In your registered app - create a new Client secret.
   1. Navigate in the Azure Portal to **App registrations** > your registered application > **Certificates & secrets** and click **+ New client secret**.
   2. Copy and save the new secret value to use in the add credentials step.
3. Assign a role to the registered app.
   1. In the Azure portal, go to the Subscriptions and select the subscription you are using -> Access control (IAM).
   2. Click **Add** > **Add role assignment**.
   3. Select the *Azure Sentinel Contributor* role > Select your registered app, and click **Save**.
4. In Cortex XSOAR, go to  **Settings** > **Integrations** > **Credentials** and create a new credentials set. 
5. In the *Username* parameter, enter your registered app Application (client) ID.
6. In the *Password* parameter, enter the secret value you created.
7. Copy your tenant ID for the integration configuration usage.

Test of mirroring! 1. 2. 3. 4.

## Configure the server URL

If you have a dedicated server URL, enter it in the *Server Url* parameter. 

## Get the additional instance parameters

To get the *Subscription ID*, *Workspace Name* and *Resource Group* parameters, in the Azure Portal navigate  to **Azure Sentinel** > your workspace > **Settings** and click the **Workspace Settings** tab.

## Configure Azure Sentinel on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Sentinel.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                                                                    | **Required** |
    |----------------------------------------------------------------------------------|--------------|
    | Azure Cloud                                                                      | False        |
    | Tenant ID                                                                        | False        |
    | Client ID                                                                        | False        |
    | Azure Managed Identities Client ID                                               | False        |
    | Subscription ID                                                                  | True         |
    | Resource Group Name                                                              | True         |
    | Workspace Name                                                                   | True         |
    | Fetch incidents                                                                  | False        |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False        |
    | The minimum severity of incidents to fetch                                       | False        |
    | Incident type                                                                    | False        |
    | Trust any certificate (not secure)                                               | False        |
    | Use system proxy settings                                                        | False        |
    | Additional info to fetch                                                         | False        |
    | Mirroring Direction                                                              | False        |
    | Close Mirrored XSOAR Incident                                                    | False        |
    | Close Mirrored Microsoft Sentinel Ticket                                         | False        |
    | Server URL, see note below regarding Azure cloud options.                        | False        |

4. Azure cloud options

    | Azure Cloud | Description                                                              |
    |-------------|--------------------------------------------------------------------------|
    | Worldwide   | The publicly accessible Azure Cloud                                      |
    | US GCC      | Azure cloud for the USA Government Cloud Community (GCC)                 |
    | US GCC-High | Azure cloud for the USA Government Cloud Community High (GCC-High)       |
    | DoD         | Azure cloud for the USA Department of Defense (DoD)                      |
    | Germany     | Azure cloud for the German Government                                    |
    | China       | Azure cloud for the Chinese Government                                   |
    | Custom      | Custom endpoint configuration to the Azure cloud, please see note below. |

   - Note: In most cases setting Azure cloud is preferred to setting Server URL. Only use it in cases where a custom proxy URL is required for accessing a national cloud.

5. Click **Test** to validate the URLs, token, and connection.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Microsoft Sentinel incidents (available from Cortex XSOAR version 6.0.0).

To setup the mirroring follow these instructions:

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for **Microsoft Sentinel** and select your integration instance.
3. Enable **Fetches incidents**.
4. In the **Mirroring Direction** integration parameter, select in which direction the incidents should be mirrored:
   - Incoming - Any changes in *Microsoft Sentinel* incidents will be reflected in Cortex XSOAR incidents.
   - Outgoing - Any changes in Cortex XSOAR incidents will be reflected in *Microsoft Sentinel*.
   - Incoming And Outgoing - Changes in Cortex XSOAR incidents and *Microsoft Sentinel* incidents will be reflected in both directions.
   - None - Turns off incident mirroring.
5. Optional: Check the **Close Mirrored XSOAR Incident** integration parameter to close the Cortex XSOAR incident when the corresponding incident is closed in *Microsoft Sentinel*.
6. Optional: Check the **Close Mirrored Microsoft Sentinel Ticket** integration parameter to close the *Microsoft Sentinel* incident when the corresponding Cortex XSOAR incident is closed.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.  

**Important Notes:**  

- To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and *Microsoft Sentinel*.
- If the **The minimum severity of incidents to fetch** integration parameter is set to a value other than `None`, incidents with a severity lower than the specified value will not be mirrored, even if their severity is changed in *Microsoft Sentinel* to a higher severity.


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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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
| AzureSentinel.Incident.AssigneeObjectID | String | The object ID of the incident assignee. | 
| AzureSentinel.Incident.AssigneeUPN | String | The user principal name of the incident assignee. | 
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


#### Command Example

```!azure-sentinel-get-incident-by-id incident_id=8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742```

#### Context Example

```json
{
    "AzureSentinel": {
        "Incident": {
            "AlertProductNames": [
                "Azure Sentinel"
            ],
            "AlertsCount": 1,
            "AssigneeEmail": "test@test.com",
            "AssigneeName": null,
            "BookmarksCount": 0,
            "CommentsCount": 3,
            "CreatedTimeUTC": "2020-01-15T09:29:14Z",
            "Deleted": false,
            "Description": "Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses\nexceeds a threshold (default is 100).",
            "Etag": "\"2700a244-0000-0100-0000-6123a2930000\"",
            "FirstActivityTimeGenerated": null,
            "FirstActivityTimeUTC": null,
            "ID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
            "IncidentNumber": 2,
            "Label": [
                {
                    "Name": "label_a",
                    "Type": "User"
                },
                {
                    "Name": "label_b",
                    "Type": "User"
                }
            ],
            "LastActivityTimeGenerated": null,
            "LastActivityTimeUTC": null,
            "LastModifiedTimeUTC": "2021-08-23T13:28:51Z",
            "Severity": "Informational",
            "Status": "New",
            "Tactics": null,
            "Title": "SharePointFileOperation via previously unseen IPs"
        }
    }
}
```

#### Human Readable Output

>### Incident 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 details
>
>|ID|Incident Number|Title|Description|Severity|Status|Assignee Email|Label|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|Etag|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | 2 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Informational | New | <test@test.com> | {'Name': 'label_a', 'Type': 'User'},<br/>{'Name': 'label_b', 'Type': 'User'} | 2021-08-23T13:28:51Z | 2020-01-15T09:29:14Z | 1 | 0 | 3 | Azure Sentinel | "2700a244-0000-0100-0000-6123a2930000" |


### azure-sentinel-list-incidents

***
Gets a list of incidents from Azure Sentinel.


#### Base Command

`azure-sentinel-list-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of incidents to return. The maximum value is 200. Default is 50. | Optional | 
| filter | Filter results using OData syntax. For example: properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For more information, see the Azure documentation: <https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter>. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. This argument overrides all of the other command arguments. | Optional | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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


#### Command Example

```!azure-sentinel-list-incidents limit=5```

#### Context Example

```json
{
    "AzureSentinel": {
        "Incident": [
            {
                "AlertProductNames": [
                    "Azure Sentinel"
                ],
                "AlertsCount": 1,
                "AssigneeEmail": "test@test.com",
                "AssigneeName": null,
                "BookmarksCount": 0,
                "CommentsCount": 3,
                "CreatedTimeUTC": "2020-01-15T09:29:14Z",
                "Deleted": false,
                "Description": "Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses\nexceeds a threshold (default is 100).",
                "Etag": "\"2700a244-0000-0100-0000-6123a2930000\"",
                "FirstActivityTimeGenerated": null,
                "FirstActivityTimeUTC": null,
                "ID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
                "IncidentNumber": 2,
                "Label": [
                    {
                        "Name": "label_a",
                        "Type": "User"
                    },
                    {
                        "Name": "label_b",
                        "Type": "User"
                    }
                ],
                "LastActivityTimeGenerated": null,
                "LastActivityTimeUTC": null,
                "LastModifiedTimeUTC": "2021-08-23T13:28:51Z",
                "Severity": "Informational",
                "Status": "New",
                "Tactics": null,
                "Title": "SharePointFileOperation via previously unseen IPs"
            },
            {
                "AlertProductNames": [
                    "Azure Sentinel"
                ],
                "AlertsCount": 1,
                "AssigneeEmail": "test@test.com",
                "AssigneeName": null,
                "BookmarksCount": 0,
                "CommentsCount": 0,
                "CreatedTimeUTC": "2020-01-15T09:34:12Z",
                "Deleted": false,
                "Description": "Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses\nexceeds a threshold (default is 100).",
                "Etag": "\"dc00cb1c-0000-0100-0000-60992bf20000\"",
                "FirstActivityTimeGenerated": null,
                "FirstActivityTimeUTC": null,
                "ID": "e0b06d71-b5a3-43a9-997f-f25b45085cb7",
                "IncidentNumber": 4,
                "Label": [
                    {
                        "Name": "f",
                        "Type": "User"
                    },
                    {
                        "Name": "o",
                        "Type": "User"
                    },
                    {
                        "Name": "o",
                        "Type": "User"
                    },
                    {
                        "Name": "1",
                        "Type": "User"
                    }
                ],
                "LastActivityTimeGenerated": null,
                "LastActivityTimeUTC": null,
                "LastModifiedTimeUTC": "2021-05-10T12:49:54Z",
                "Severity": "Low",
                "Status": "New",
                "Tactics": null,
                "Title": "SharePointFileOperation via previously unseen IPs"
            },
            {
                "AlertProductNames": [
                    "Azure Sentinel"
                ],
                "AlertsCount": 1,
                "AssigneeEmail": null,
                "AssigneeName": null,
                "BookmarksCount": 0,
                "CommentsCount": 0,
                "CreatedTimeUTC": "2020-01-15T09:40:09Z",
                "Deleted": false,
                "Description": "Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses\nexceeds a threshold (default is 100).",
                "Etag": "\"0100c30e-0000-0100-0000-5fb883be0000\"",
                "FirstActivityTimeGenerated": null,
                "FirstActivityTimeUTC": "2020-01-15T08:04:05Z",
                "ID": "a7977be7-1008-419b-877b-6793b7402a80",
                "IncidentNumber": 6,
                "Label": [],
                "LastActivityTimeGenerated": null,
                "LastActivityTimeUTC": "2020-01-15T09:04:05Z",
                "LastModifiedTimeUTC": "2020-01-15T09:40:09Z",
                "Severity": "Medium",
                "Status": "New",
                "Tactics": null,
                "Title": "SharePointFileOperation via previously unseen IPs"
            },
            {
                "AlertProductNames": [
                    "Azure Sentinel"
                ],
                "AlertsCount": 1,
                "AssigneeEmail": null,
                "AssigneeName": null,
                "BookmarksCount": 0,
                "CommentsCount": 1,
                "CreatedTimeUTC": "2020-01-15T09:44:12Z",
                "Deleted": false,
                "Description": "Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses\nexceeds a threshold (default is 100).",
                "Etag": "\"0600a81f-0000-0100-0000-5fdb4e890000\"",
                "FirstActivityTimeGenerated": null,
                "FirstActivityTimeUTC": null,
                "ID": "6440c129-c313-418c-a262-5df608aa9cd2",
                "IncidentNumber": 7,
                "Label": [],
                "LastActivityTimeGenerated": null,
                "LastActivityTimeUTC": null,
                "LastModifiedTimeUTC": "2020-12-17T12:26:49Z",
                "Severity": "Medium",
                "Status": "Active",
                "Tactics": null,
                "Title": "test_title"
            },
            {
                "AlertProductNames": [
                    "Azure Sentinel"
                ],
                "AlertsCount": 1,
                "AssigneeEmail": null,
                "AssigneeName": null,
                "BookmarksCount": 0,
                "CommentsCount": 0,
                "CreatedTimeUTC": "2020-01-15T09:49:12Z",
                "Deleted": false,
                "Description": "Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses\nexceeds a threshold (default is 100).",
                "Etag": "\"0100b70e-0000-0100-0000-5fb883bd0000\"",
                "FirstActivityTimeGenerated": null,
                "FirstActivityTimeUTC": "2020-01-15T08:44:06Z",
                "ID": "413e9d64-c7b4-4e33-ae26-bb39710d2187",
                "IncidentNumber": 9,
                "Label": [],
                "LastActivityTimeGenerated": null,
                "LastActivityTimeUTC": "2020-01-15T09:44:06Z",
                "LastModifiedTimeUTC": "2020-01-15T09:49:12Z",
                "Severity": "Medium",
                "Status": "New",
                "Tactics": null,
                "Title": "SharePointFileOperation via previously unseen IPs"
            }
        ],
        "NextLink": {
            "Description": "NextLink for listing commands",
            "URL": "https://test.com"
        }
    }
}
```

#### Human Readable Output

>### Incidents List (5 results)
>
>|ID|Incident Number|Title|Description|Severity|Status|Assignee Email|Label|First Activity Time UTC|Last Activity Time UTC|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|Etag|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | 2 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Informational | New | <test@test.com> | {'Name': 'label_a', 'Type': 'User'},<br/>{'Name': 'label_b', 'Type': 'User'} |  |  | 2021-08-23T13:28:51Z | 2020-01-15T09:29:14Z | 1 | 0 | 3 | Azure Sentinel | "2700a244-0000-0100-0000-6123a2930000" |
>| e0b06d71-b5a3-43a9-997f-f25b45085cb7 | 4 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Low | New | <test@test.com> | {'Name': 'f', 'Type': 'User'},<br/>{'Name': 'o', 'Type': 'User'},<br/>{'Name': 'o', 'Type': 'User'},<br/>{'Name': '1', 'Type': 'User'} |  |  | 2021-05-10T12:49:54Z | 2020-01-15T09:34:12Z | 1 | 0 | 0 | Azure Sentinel | "dc00cb1c-0000-0100-0000-60992bf20000" |
>| a7977be7-1008-419b-877b-6793b7402a80 | 6 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Medium | New |  |  | 2020-01-15T08:04:05Z | 2020-01-15T09:04:05Z | 2020-01-15T09:40:09Z | 2020-01-15T09:40:09Z | 1 | 0 | 0 | Azure Sentinel | "0100c30e-0000-0100-0000-5fb883be0000" |
>| 6440c129-c313-418c-a262-5df608aa9cd2 | 7 | test_title | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Medium | Active |  |  |  |  | 2020-12-17T12:26:49Z | 2020-01-15T09:44:12Z | 1 | 0 | 1 | Azure Sentinel | "0600a81f-0000-0100-0000-5fdb4e890000" |
>| 413e9d64-c7b4-4e33-ae26-bb39710d2187 | 9 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Medium | New |  |  | 2020-01-15T08:44:06Z | 2020-01-15T09:44:06Z | 2020-01-15T09:49:12Z | 2020-01-15T09:49:12Z | 1 | 0 | 0 | Azure Sentinel | "0100b70e-0000-0100-0000-5fb883bd0000" |


### azure-sentinel-list-watchlists

***
Gets a list of watchlists from Azure Sentinel.


#### Base Command

`azure-sentinel-list-watchlists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_alias | Alias of specific watchlist to get. | Optional | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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
| AzureSentinel.Watchlist.UpdatedBy | String | The name of the user who updated the Watchlist. | 
| AzureSentinel.Watchlist.Alias | String | The alias of the watchlist. | 
| AzureSentinel.Watchlist.Label | unknown | Label that will be used to tag and filter on. | 
| AzureSentinel.Watchlist.ItemsSearchKey | String | The search key is used to optimize query performance when using watchlists for joins with other data. For example, enable a column with IP addresses to be the designated SearchKey field, then use this field as the key field when joining to other event data by IP address. | 
| AzureSentinel.NextLink.Description | String | Description of NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns partial results. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 


#### Command Example

```!azure-sentinel-list-watchlists```

#### Context Example

```json
{
    "AzureSentinel": {
        "Watchlist": [
            {
                "Alias": "booboo",
                "Created": "2021-07-11T08:20:35Z",
                "CreatedBy": "test@test.com",
                "Description": "just for fun",
                "ID": "35bffe30-19f2-40a6-8855-4a858e161fad",
                "ItemsSearchKey": "IP",
                "Label": [
                    "IP"
                ],
                "Name": "booboo",
                "Provider": "xsoar",
                "Source": "Local file",
                "Updated": "2021-07-11T08:20:35Z",
                "UpdatedBy": "test@test.com"
            },
            {
                "Alias": "test_2",
                "Created": "2021-08-16T10:26:56Z",
                "CreatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
                "Description": "test watchlist",
                "ID": "ceae6089-10dd-4f02-89d5-ab32285688dc",
                "ItemsSearchKey": "IP",
                "Label": [],
                "Name": "test_2",
                "Provider": "XSOAR",
                "Source": "Local file",
                "Updated": "2021-08-16T10:26:56Z",
                "UpdatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd"
            },
            {
                "Alias": "test_1",
                "Created": "2021-08-15T14:14:28Z",
                "CreatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
                "Description": "",
                "ID": "92863c74-fee7-4ffe-8288-bc1529d12597",
                "ItemsSearchKey": "IP",
                "Label": [],
                "Name": "test_1",
                "Provider": "XSOAR",
                "Source": "Local file",
                "Updated": "2021-08-15T14:14:28Z",
                "UpdatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd"
            },
            {
                "Alias": "test_4",
                "Created": "2021-08-23T13:30:53Z",
                "CreatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
                "Description": "test watchlist",
                "ID": "84d1fedd-5945-4670-ae34-5e8c94af2660",
                "ItemsSearchKey": "IP",
                "Label": [],
                "Name": "test_4",
                "Provider": "XSOAR",
                "Source": "Local file",
                "Updated": "2021-08-23T13:30:53Z",
                "UpdatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd"
            }
        ]
    }
}
```

#### Human Readable Output

>### Watchlists results
>
>|Name|ID|Description|
>|---|---|---|
>| booboo | 35bffe30-19f2-40a6-8855-4a858e161fad | just for fun |
>| test_2 | ceae6089-10dd-4f02-89d5-ab32285688dc | test watchlist |
>| test_1 | 92863c74-fee7-4ffe-8288-bc1529d12597 |  |
>| test_4 | 84d1fedd-5945-4670-ae34-5e8c94af2660 | test watchlist |


### azure-sentinel-delete-watchlist

***
Delete a watchlists from Azure Sentinel.


#### Base Command

`azure-sentinel-delete-watchlist`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_alias | Alias of the watchlist to be deleted. | Required | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example

```!azure-sentinel-delete-watchlist watchlist_alias=test_4```

#### Human Readable Output

>Watchlist test_4 was deleted successfully.

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
| source | The source of the watchlist. Possible values are: Local file, Remote storage. | Required | 
| labels | The labels of the watchlist. | Optional | 
| lines_to_skip | The number of lines in the CSV content to skip before the header. Default is 0. | Optional | 
| file_entry_id | A file entry with raw content that represents the watchlist items to create. | Required | 
| items_search_key | The search key is used to optimize query performance when using watchlists for joins with other data. For example, enable a column with IP addresses to be the designated SearchKey field, then use this field as the key field when joining to other event data by IP address. | Required | 
| content_type | The content type of the raw content. For now, only text/csv is valid. Default is Text/Csv. | Optional | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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


#### Command Example

```!azure-sentinel-watchlist-create-update items_search_key=IP raw_content=1711@3c9bd2a0-9eac-465b-8799-459df4997b2d source="Local file" watchlist_alias=test_4 watchlist_display_name=test_4 description="test watchlist"```

#### Context Example

```json
{
    "AzureSentinel": {
        "Watchlist": {
            "Alias": "test_4",
            "Created": "2021-08-23T13:30:53Z",
            "CreatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
            "Description": "test watchlist",
            "ID": "84d1fedd-5945-4670-ae34-5e8c94af2660",
            "ItemsSearchKey": "IP",
            "Label": [],
            "Name": "test_4",
            "Provider": "XSOAR",
            "Source": "Local file",
            "Updated": "2021-08-23T13:30:53Z",
            "UpdatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd"
        }
    }
}
```

#### Human Readable Output

>### Create watchlist results
>
>|Name|ID|Description|
>|---|---|---|
>| test_4 | 84d1fedd-5945-4670-ae34-5e8c94af2660 | test watchlist |


### azure-sentinel-update-incident

***
Updates a single incident in Azure Sentinel.


#### Base Command

`azure-sentinel-update-incident`

#### Input

| **Argument Name**      | **Description**                                                                                                                                                                                                                                | **Required** |
|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| incident_id            | The incident ID.                                                                                                                                                                                                                               | Required | 
| title                  | The incident's title.                                                                                                                                                                                                                          | Optional | 
| description            | Description of the incident.                                                                                                                                                                                                                   | Optional | 
| severity               | The incident severity. Possible values are: High, Medium, Low, Informational.                                                                                                                                                                  | Optional | 
| status                 | The incident status. Possible values are: New, Active, Closed.                                                                                                                                                                                 | Optional | 
| classification         | The reason the incident was closed. Required when updating the status to Closed.  Possible values are: BenignPositive, FalsePositive, TruePositive, Undetermined.                                                                              | Optional | 
| classification_comment | Describes the reason the incident was closed.                                                                                                                                                                                                  | Optional | 
| classification_reason  | The classification reason the incident was closed with. Required when updating the status to Closed and the classification is determined. Possible values are: InaccurateData, IncorrectAlertLogic, SuspiciousActivity, SuspiciousButExpected. | Optional | 
| assignee_email         | The email address of the incident assignee. It is recommended to update *user_principal_name* instead of this field. Note that the updated API field is `owner.email`.                                                                         | Optional | 
| user_principal_name    | The user principal name of the client. Note that the updated API field is `owner.userPrincipalName`.                                                                                                                                           | Optional | 
| labels                 | Incident labels. Note that all labels will be set as labelType='User'.                                                                                                                                                                         | Optional | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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
| AzureSentinel.Incident.AssigneeObjectID | String | The object ID of the incident assignee. | 
| AzureSentinel.Incident.AssigneeUPN | String | The user principal name of the incident assignee. | 
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


#### Command Example

```!azure-sentinel-update-incident incident_id=8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 labels=label_a,label_b```

#### Context Example

```json
{
    "AzureSentinel": {
        "Incident": {
            "AlertProductNames": [
                "Azure Sentinel"
            ],
            "AlertsCount": 1,
            "AssigneeEmail": "test@test.com",
            "AssigneeName": null,
            "BookmarksCount": 0,
            "CommentsCount": 4,
            "CreatedTimeUTC": "2020-01-15T09:29:14Z",
            "Deleted": false,
            "Description": "Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses\nexceeds a threshold (default is 100).",
            "Etag": "\"27002845-0000-0100-0000-6123a3090000\"",
            "FirstActivityTimeGenerated": null,
            "FirstActivityTimeUTC": null,
            "ID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
            "IncidentNumber": 2,
            "Label": [
                {
                    "Name": "label_a",
                    "Type": "User"
                },
                {
                    "Name": "label_b",
                    "Type": "User"
                }
            ],
            "LastActivityTimeGenerated": null,
            "LastActivityTimeUTC": null,
            "LastModifiedTimeUTC": "2021-08-23T13:30:49Z",
            "Severity": "Informational",
            "Status": "New",
            "Tactics": null,
            "Title": "SharePointFileOperation via previously unseen IPs"
        }
    }
}
```

#### Human Readable Output

>### Updated incidents 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 details
>
>|ID|Incident Number|Title|Description|Severity|Status|Assignee Email|Label|Last Modified Time UTC|Created Time UTC|Alerts Count|Bookmarks Count|Comments Count|Alert Product Names|Etag|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | 2 | SharePointFileOperation via previously unseen IPs | Identifies when the volume of documents uploaded to or downloaded from Sharepoint by new IP addresses<br/>exceeds a threshold (default is 100). | Informational | New | <test@test.com> | {'Name': 'label_a', 'Type': 'User'},<br/>{'Name': 'label_b', 'Type': 'User'} | 2021-08-23T13:30:49Z | 2020-01-15T09:29:14Z | 1 | 0 | 4 | Azure Sentinel | "27002845-0000-0100-0000-6123a3090000" |


### azure-sentinel-delete-incident

***
Deletes a single incident in Azure Sentinel.


#### Base Command

`azure-sentinel-delete-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example

```!azure-sentinel-delete-incident incident_id=c90cc84d-a95e-47a0-9478-89ebc9ee22fd```

#### Context Example

```json
{
    "AzureSentinel": {
        "Incident": {
            "Deleted": true,
            "ID": "c90cc84d-a95e-47a0-9478-89ebc9ee22fd"
        }
    }
}
```

#### Human Readable Output

>Incident c90cc84d-a95e-47a0-9478-89ebc9ee22fd was deleted successfully.

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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentComment.ID | String | The ID of the incident comment. | 
| AzureSentinel.IncidentComment.IncidentID | String | The incident ID. | 
| AzureSentinel.IncidentComment.Message | String | The incident's comment. | 
| AzureSentinel.IncidentComment.AuthorName | String | The name of the author of the incident's comment. | 
| AzureSentinel.IncidentComment.AuthorEmail | String | The email address of the author of the incident comment. | 
| AzureSentinel.IncidentComment.CreatedTimeUTC | Date | The date and time that the incident comment was created. | 
| AzureSentinel.NextLink.Description | String | Description of NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 


#### Command Example

```!azure-sentinel-list-incident-comments incident_id=8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742```

#### Context Example

```json
{
    "AzureSentinel": {
        "IncidentComment": [
            {
                "AuthorEmail": null,
                "AuthorName": null,
                "CreatedTimeUTC": "2021-08-23T13:30:42Z",
                "ID": "231020399272240422047777436922721687523",
                "IncidentID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
                "Message": "test messages"
            },
            {
                "AuthorEmail": null,
                "AuthorName": null,
                "CreatedTimeUTC": "2021-08-23T13:26:26Z",
                "ID": "251456744761940512356246980948458722890",
                "IncidentID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
                "Message": "test messages"
            },
            {
                "AuthorEmail": null,
                "AuthorName": null,
                "CreatedTimeUTC": "2021-08-12T10:57:44Z",
                "ID": "152909182848719872520422267385960967748",
                "IncidentID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
                "Message": "test messages"
            },
            {
                "AuthorEmail": "test@test.com",
                "AuthorName": null,
                "CreatedTimeUTC": "2020-04-05T12:14:13Z",
                "ID": "307866023137611282164566423986768628663",
                "IncidentID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
                "Message": "hello world"
            }
        ]
    }
}
```

#### Human Readable Output

>### Incident 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 Comments (4 results)
>
>|ID|Incident ID|Message|Author Email|Created Time UTC|
>|---|---|---|---|---|
>| 231020399272240422047777436922721687523 | 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | test messages |  | 2021-08-23T13:30:42Z |
>| 251456744761940512356246980948458722890 | 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | test messages |  | 2021-08-23T13:26:26Z |
>| 152909182848719872520422267385960967748 | 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | test messages |  | 2021-08-12T10:57:44Z |
>| 307866023137611282164566423986768628663 | 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | hello world | <test@test.com> | 2020-04-05T12:14:13Z |


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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentComment.ID | String | The ID of the incident comment. | 
| AzureSentinel.IncidentComment.IncidentID | String | The incident ID. | 
| AzureSentinel.IncidentComment.Message | String | The incident's comment. | 
| AzureSentinel.IncidentComment.AuthorName | String | The name of the author of the incident's comment. | 
| AzureSentinel.IncidentComment.AuthorEmail | String | The email address of the author of the incident comment. | 
| AzureSentinel.IncidentComment.CreatedTimeUTC | Date | The date and time that the incident comment was created. | 


#### Command Example

```!azure-sentinel-incident-add-comment incident_id=8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 message="test messages"```

#### Context Example

```json
{
    "AzureSentinel": {
        "IncidentComment": {
            "AuthorEmail": null,
            "AuthorName": null,
            "CreatedTimeUTC": "2021-08-23T13:30:42Z",
            "ID": "231020399272240422047777436922721687523",
            "IncidentID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
            "Message": "test messages"
        }
    }
}
```

#### Human Readable Output

>### Incident 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 new comment details
>
>|ID|Incident ID|Message|Created Time UTC|
>|---|---|---|---|
>| 231020399272240422047777436922721687523 | 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | test messages | 2021-08-23T13:30:42Z |


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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example

```!azure-sentinel-incident-delete-comment incident_id=8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 comment_id="296745069631925005023508651351426"```

#### Human Readable Output

>Comment 296745069631925005023508651351426 was deleted successfully.


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
| entity_kinds | A comma-separated list of entity kinds to filter by. By default, the results won't be filtered by kind.<br/>The optional kinds are: Account, Host, File, AzureResource, CloudApplication, DnsResolution, FileHash, Ip, Malware, Process, RegistryKey, RegistryValue, SecurityGroup, Url, IoTDevice, SecurityAlert, Bookmark. | Optional | 
| filter | Filter results using OData syntax. For example: properties/createdTimeUtc gt 2020-02-02T14:00:00Z`). For more information see the Azure documentation: <https://docs.microsoft.com/bs-latn-ba/azure/search/search-query-odata-filter>. | Optional | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentRelatedResource.ID | String | The ID of the incident's related resource. | 
| AzureSentinel.IncidentRelatedResource.Kind | String | The kind of the incident's related resource. | 
| AzureSentinel.NextLink.Description | String | The description about NextLink. | 
| AzureSentinel.NextLink.URL | String | Used if an operation returns a partial result. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 
| AzureSentinel.IncidentRelatedResource.IncidentID | String | The incident ID. | 


#### Command Example

```!azure-sentinel-list-incident-relations incident_id=8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742```

#### Context Example

```json
{
    "AzureSentinel": {
        "IncidentRelatedResource": {
            "ID": "bfb02efc-12b7-4147-a8e8-961338b1b834",
            "IncidentID": "8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742",
            "Kind": "SecurityAlert"
        }
    }
}
```

#### Human Readable Output

>### Incident 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 Relations (1 results)
>
>|ID|Incident ID|Kind|
>|---|---|---|
>| bfb02efc-12b7-4147-a8e8-961338b1b834 | 8a44b7bb-c8ae-4941-9fa0-3aecc8ef1742 | SecurityAlert |


### azure-sentinel-list-incident-entities

***
Gets a list of an incident's entities from Azure Sentinel.


#### Base Command

`azure-sentinel-list-incident-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentEntity.ID | String | The ID of the entity. | 
| AzureSentinel.IncidentEntity.IncidentId | String | The ID of the incident. | 
| AzureSentinel.IncidentEntity.Kind | String | The kind of the entity. | 
| AzureSentinel.IncidentEntity.Properties | Unknown | The properties of the entity. | 


#### Command Example

```!azure-sentinel-list-incident-entities incident_id=65d8cbc0-4e4d-4acb-ab7e-8aa19936002c```

#### Context Example

```json
{
    "AzureSentinel": {
        "IncidentEntity": {
            "ID": "176567ab-1ccc-8a53-53bf-97958a78d3b5",
            "IncidentId": "65d8cbc0-4e4d-4acb-ab7e-8aa19936002c",
            "Kind": "Account",
            "Properties": {
                "aadTenantId": "176567ab-1ccc-8a53-53bf-97958a78d3b5",
                "aadUserId": "176567ab-1ccc-8a53-53bf-97958a78d3b5",
                "accountName": "test_user_1",
                "additionalData": {
                    "AdditionalMailAddresses": "[\"test@test.com\"]",
                    "City": "SantaClara",
                    "Country": "United States",
                    "GivenName": "test_name",
                    "IsDeleted": "False",
                    "IsEnabled": "True",
                    "JobTitle": "test",
                    "MailAddress": "test@test.com",
                    "ManagerName": "test_manager",
                    "Sources": "[\"AzureActiveDirectory\"]",
                    "State": "California",
                    "StreetAddress": "test address",
                    "Surname": "test_name",
                    "SyncFromAad": "True",
                    "TransitiveDirectoryRoles": "[\"Global Administrator\"]",
                    "TransitiveGroupsMembership": "[\"kkk\"]",
                    "UpnName": "test",
                    "UserType": "Member"
                },
                "displayName": "Test Name",
                "friendlyName": "Test Name",
                "isDomainJoined": true,
                "upnSuffix": "test.com"
            }
        }
    }
}
```

#### Human Readable Output

>### Incident 65d8cbc0-4e4d-4acb-ab7e-8aa19936002c Entities (1 results)
>
>|ID|Kind|Incident Id|
>|---|---|---|
>| 176567ab-1ccc-8a53-53bf-97958a78d3b5 | Account | 65d8cbc0-4e4d-4acb-ab7e-8aa19936002c |


### azure-sentinel-list-incident-alerts

***
Gets a list of an incident's alerts from Azure Sentinel.


#### Base Command

`azure-sentinel-list-incident-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The incident ID. | Required | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.IncidentAlert.ID | String | The ID of the alert. | 
| AzureSentinel.IncidentAlert.IncidentId | String | The ID of the incident. | 
| AzureSentinel.IncidentAlert.Kind | String | The kind of the alert. | 
| AzureSentinel.IncidentAlert.Tactic | Unknown | The tactics of the alert. | 
| AzureSentinel.IncidentAlert.Techniques | Unknown | The Techniques of the alert. | 
| AzureSentinel.IncidentAlert.DisplayName | String | The display name of the alert. | 
| AzureSentinel.IncidentAlert.Description | String | The description of the alert. | 
| AzureSentinel.IncidentAlert.ConfidenceLevel | String | The confidence level of this alert. | 
| AzureSentinel.IncidentAlert.Severity | String | The severity of the alert. | 
| AzureSentinel.IncidentAlert.VendorName | String | The name of the vendor that raised the alert. | 
| AzureSentinel.IncidentAlert.ProductName | String | The name of the product that published this alert. | 
| AzureSentinel.IncidentAlert.ProductComponentName | String | The name of a component inside the product which generated the alert. | 


#### Command Example

```!azure-sentinel-list-incident-alerts incident_id=25c9ddf4-d951-4b67-9381-172f953feb57```

#### Context Example

```json
{
    "AzureSentinel": {
        "IncidentAlert": {
            "ConfidenceLevel": "Unknown",
            "Description": "",
            "DisplayName": "Test rule",
            "ID": "f3319e38-3f5b-a1eb-9970-69679dcdf916",
            "IncidentId": "25c9ddf4-d951-4b67-9381-172f953feb57",
            "Kind": "SecurityAlert",
            "ProductComponentName": "Scheduled Alerts",
            "ProductName": "Azure Sentinel",
            "Severity": "Medium",
            "Tactic": [
                "InitialAccess",
                "Persistence",
                "PrivilegeEscalation",
                "DefenseEvasion",
                "CredentialAccess",
                "Discovery",
                "LateralMovement",
                "Execution",
                "Collection",
                "Exfiltration",
                "CommandAndControl",
                "Impact"
            ],
            "VendorName": "Microsoft"
        }
    }
}
```

#### Human Readable Output

>### Incident 25c9ddf4-d951-4b67-9381-172f953feb57 Alerts (1 results)
>
>|ID|Kind|Incident Id|
>|---|---|---|
>| f3319e38-3f5b-a1eb-9970-69679dcdf916 | SecurityAlert | 25c9ddf4-d951-4b67-9381-172f953feb57 |


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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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


#### Command Example

```!azure-sentinel-list-watchlist-items watchlist_alias=test_4```

#### Context Example

```json
{
    "AzureSentinel": {
        "WatchlistItem": [
            {
                "Created": "2021-08-23T13:30:53Z",
                "CreatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
                "ID": "28bd8f55-131b-42e6-bd5d-33d30f2d1291",
                "ItemsKeyValue": {
                    "IP": "1.2.3.4",
                    "name": "test1"
                },
                "Name": "28bd8f55-131b-42e6-bd5d-33d30f2d1291",
                "Updated": "2021-08-23T13:30:53Z",
                "UpdatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
                "WatchlistAlias": "test_4"
            },
            {
                "Created": "2021-08-23T13:30:53Z",
                "CreatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
                "ID": "510d8f80-99ad-441d-87f3-88341cc8b439",
                "ItemsKeyValue": {
                    "IP": "1.2.3.5",
                    "name": "test2"
                },
                "Name": "510d8f80-99ad-441d-87f3-88341cc8b439",
                "Updated": "2021-08-23T13:30:53Z",
                "UpdatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
                "WatchlistAlias": "test_4"
            }
        ]
    }
}
```

#### Human Readable Output

>### Watchlist items results
>
>|ID|Items Key Value|
>|---|---|
>| 28bd8f55-131b-42e6-bd5d-33d30f2d1291 | name: test1<br/>IP: 1.2.3.4 |
>| 510d8f80-99ad-441d-87f3-88341cc8b439 | name: test2<br/>IP: 1.2.3.5 |


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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example

```!azure-sentinel-delete-watchlist-item watchlist_alias=test_2 watchlist_item_id=96c326c6-2dea-403c-94bd-6a005921c3c1```

#### Human Readable Output

>Watchlist item 96c326c6-2dea-403c-94bd-6a005921c3c1 was deleted successfully.

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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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


#### Command Example

```!azure-sentinel-create-update-watchlist-item watchlist_alias=test_4 item_key_value=`{"name": "test_4_item", "IP": "4.4.4.4"}````

#### Context Example

```json
{
    "AzureSentinel": {
        "WatchlistItem": {
            "Created": "2021-08-23T13:30:59Z",
            "CreatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
            "ID": "6b21d1ef-18fa-420f-ae4a-a6f94588ebe8",
            "ItemsKeyValue": {
                "IP": "4.4.4.4",
                "name": "test_4_item"
            },
            "Name": "6b21d1ef-18fa-420f-ae4a-a6f94588ebe8",
            "Updated": "2021-08-23T13:30:59Z",
            "UpdatedBy": "78e658fe-3ff0-4785-80e7-ef089a3d6bdd",
            "WatchlistAlias": "test_4"
        }
    }
}
```

#### Human Readable Output

>### Create watchlist item results
>
>|ID|Items Key Value|
>|---|---|
>| 6b21d1ef-18fa-420f-ae4a-a6f94588ebe8 | name: test_4_item<br/>IP: 4.4.4.4 |


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
| next_link | A link that specifies a starting point to use for subsequent calls.<br/>This argument overrides all of the other command arguments. | Optional | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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
| AzureSentinel.ThreatIndicator.KillChainPhases.KillChainName | Unknown | The kill chain's name of the indicator. | 
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


#### Command Example

```!azure-sentinel-threat-indicator-list limit=2```

#### Human Readable Output

### Threat Indicators (2 results)

|Name|Display Name|Values|Types|Source|Tags|
|---|---|---|---|---|---|
| a31f2257-1af5-5eb9-bc82-acb8cc10becd | Name | test.value | malicious-activity | Azure Sentinel | Tag |
| 1286115b-3b65-5537-e831-969045792910 | DisplayName | domain.dot | benign | Azure Sentinel | No Tags |

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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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


#### Command Example

```!azure-sentinel-threat-indicator-query max_confidence=70 ```

#### Human Readable Output

### Threat Indicators (2 results)

|Name|Display Name|Values|Types|Source|Confidence|Tags|
|---|---|---|---|---|---|---|
| a31f2257-1af5-5eb9-bc82-acb8cc10becd | DisplayName | domain.dot | compromised | Azure Sentinel | 50 | newTag |
| 1286115b-3b65-5537-e831-969045792910 | Name | test.dot | compromised | Azure Sentinel | 68 | No Tags |

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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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


#### Command Example

```!azure-sentinel-threat-indicator-create display_name=name indicator_type=domain threat_types=benign value=good.test confidence=77```

#### Human Readable Output

### New threat Indicator was created

|Name|Display Name|Values|Types|Source|Confidence|Tags|
|---|---|---|---|---|---|---|
|a31f2257-1af5-5eb9-bc82-acb8cc10becd| name | good.test | benign | Azure Sentinel | 77 | No Tags |

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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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


#### Command Example

```!azure-sentinel-threat-indicator-update indicator_name=a31f2257-1af5-5eb9-bc82-acb8cc10becd display_name=WeChangedTheDisplayName indicator_type="domain-name" value=verynew.value```

#### Human Readable Output

### Threat Indicator a31f2257-1af5-5eb9-bc82-acb8cc10becd was updated

|Name|Display Name|Values|Types|Source|Tags|
|---|---|---|---|---|---|
| a31f2257-1af5-5eb9-bc82-acb8cc10becd | WeChangedTheDisplayName | verynew.value | malicious-activity | Azure Sentinel | ReplaceTheTag |


### azure-sentinel-threat-indicator-delete

***
Deletes an existing threat indicator.


#### Base Command

`azure-sentinel-threat-indicator-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_names | A comma-separated list of indicators to delete. | Required | 
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example

```!azure-sentinel-threat-indicator-delete indicator_names=1286115b-3b65-5537-e831-969045792910```

#### Human Readable Output

Threat Intelligence Indicators 1286115b-3b65-5537-e831-969045792910 were deleted successfully.


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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


#### Context Output

| **Path** | **Type** | **Description**                                                         |
| --- | --- |-------------------------------------------------------------------------|
| AzureSentinel.ThreatIndicator.ID | String | The ID of the indicator.                                                | 
| AzureSentinel.ThreatIndicator.Name | String | The name of the indicator.                                              | 
| AzureSentinel.ThreatIndicator.ETag | String | The ETag of the indicator.                                              | 
| AzureSentinel.ThreatIndicator.Type | String | The type of the indicator.                                              | 
| AzureSentinel.ThreatIndicator.Kind | String | The kind of the indicator.                                              | 
| AzureSentinel.ThreatIndicators.Confidence | Number | The confidence of the threat indicator. This is a number between 0-100. | 
| AzureSentinel.ThreatIndicator.Created | Date | When the threat indicator was created.                                  | 
| AzureSentinel.ThreatIndicator.CreatedByRef | String | The creator of the indicator.                                           | 
| AzureSentinel.ThreatIndicator.ExternalID | String | The external ID of the indicator.                                       | 
| AzureSentinel.ThreatIndicator.Revoked | Boolean | Was the threat indicator revoked or not.                                | 
| AzureSentinel.ThreatIndicator.Source | String | The source of the indicator.                                            | 
| AzureSentinel.ThreatIndicator.ETags | String | The Etags of the indicator.                                             | 
| AzureSentinel.ThreatIndicator.DisplayName | String | The display name of the indicator.                                      | 
| AzureSentinel.ThreatIndicator.Description | String | The description of the indicator.                                       | 
| AzureSentinel.ThreatIndicator.ThreatTypes | Unknown | The threat types of the indicator.                                      | 
| AzureSentinel.ThreatIndicator.KillChainPhases.KillChainName | String | The kill chain's name of the indicator.                                 | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeKey | Unknown | The pattern type key of the indicator.                                  | 
| AzureSentinel.ThreatIndicator.Pattern | String | The pattern of the indicator.                                           | 
| AzureSentinel.ThreatIndicator.PatternType | String | The pattern type of the indicator.                                      | 
| AzureSentinel.ThreatIndicator.ValidFrom | Date | The date from which the indicator is valid.                             | 
| AzureSentinel.ThreatIndicator.ValidUntil | Date | The date until which the indicator is valid.                            | 
| AzureSentinel.ThreatIndicator.KillChainPhases.PhaseName | String | The phase name of the indicator.                                        | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.Value | String | The value of the indicator.                                             | 
| AzureSentinel.ThreatIndicator.ParsedPattern.PatternTypeValues.ValueType | String | The value type of the indicator.                                        | 
| AzureSentinel.ThreatIndicator.LastUpdatedTimeUtc | Date | The last updated time of the indicator.                                 | 
| AzureSentinel.ThreatIndicator.Tags | Unknown | The tags of the indicator.                                              | 
| AzureSentinel.ThreatIndicator.Types | Unknown | The threat types of the indicator.                                      | 


#### Command Example

```!azure-sentinel-threat-indicator-tags-append indicator_name=1286115b-3b65-5537-e831-969045792910 tags=newtag```

#### Human Readable Output

Tags were appended to 1286115b-3b65-5537-e831-969045792910 Threat Indicator.

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
| subscription_id | The subscription ID. | Optional |
| resource_group_name | The resource group name. | Optional |


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


#### Command Example

```!azure-sentinel-threat-indicator-tags-replace name=1286115b-3b65-5537-e831-969045792910 tags=newtag```

#### Human Readable Output

Tags were replaced to 1286115b-3b65-5537-e831-969045792910 Threat Indicator.

### azure-sentinel-list-alert-rule

***
Gets a list of all alert rules.


#### Base Command

`azure-sentinel-list-alert-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID. If not given, will return all rules. | Optional | 
| limit | The maximum number of rules to return. Default is 50. | Optional | 
| subscription_id | The subscription ID. | Optional | 
| resource_group_name | The resource group name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.AlertRule.id | String | Fully qualified resource ID for the resource. | 
| AzureSentinel.AlertRule.name | String | The name of the resource. | 
| AzureSentinel.AlertRule.type | String | The type of the resource. | 
| AzureSentinel.AlertRule.kind | String | The alert rule kind. | 
| AzureSentinel.AlertRule.etag | String | ETag of the Azure resource. | 
| AzureSentinel.AlertRule.properties.alertRuleTemplateName | Unknown | The name of the alert rule template used to create this rule. | 
| AzureSentinel.AlertRule.properties.displayName | String | The display name for alerts created by this alert rule. | 
| AzureSentinel.AlertRule.properties.description | String | The description of the alert rule. | 
| AzureSentinel.AlertRule.properties.severity | String | The severity for alerts created by this alert rule. | 
| AzureSentinel.AlertRule.properties.enabled | Boolean | Determines whether this alert rule is enabled or disabled. | 
| AzureSentinel.AlertRule.properties.tactics | String | The tactics of the alert rule. | 
| AzureSentinel.AlertRule.properties.query | String | The query that creates alerts for this rule. | 
| AzureSentinel.AlertRule.properties.queryFrequency | String | The frequency \(in ISO 8601 duration format\) for this alert rule to run. | 
| AzureSentinel.AlertRule.properties.queryPeriod | String | The period \(in ISO 8601 duration format\) that this alert rule looks at. | 
| AzureSentinel.AlertRule.properties.triggerOperator | String | The operation against the threshold that triggers the alert rule. | 
| AzureSentinel.AlertRule.properties.triggerThreshold | Number | The threshold that triggers this alert rule. | 
| AzureSentinel.AlertRule.properties.suppressionDuration | String | The suppression \(in ISO 8601 duration format\) to wait since the last time this alert rule was triggered. | 
| AzureSentinel.AlertRule.properties.suppressionEnabled | Boolean | Determines whether the suppression for this alert rule is enabled or disabled. | 
| AzureSentinel.AlertRule.properties.lastModifiedUtc | Date | The last time this alert rule was modified. | 
| AzureSentinel.AlertRule.properties.eventGroupingSettings.aggregationKind | String | The event grouping aggregation kinds. | 
| AzureSentinel.AlertRule.properties.entityMappings.entityType | String | The V3 type of the mapped entity. | 
| AzureSentinel.AlertRule.properties.entityMappings.fieldMappings.identifier | String | The V3 identifier of the entity. | 
| AzureSentinel.AlertRule.properties.entityMappings.fieldMappings.columnName | String | The column name to be mapped to the identifier. | 
| AzureSentinel.AlertRule.properties.alertDetailsOverride.alertDisplayNameFormat | String | The format containing the columns' name\(s\) used to override the alert name. | 
| AzureSentinel.AlertRule.properties.alertDetailsOverride.alertDescriptionFormat | String | The format containing columns' name\(s\) used to override the alert description. | 
| AzureSentinel.AlertRule.properties.alertDetailsOverride.alertTacticsColumnName | Unknown | The column name to take the alert tactics from. | 
| AzureSentinel.AlertRule.properties.alertDetailsOverride.alertSeverityColumnName | Unknown | The column name to take the alert severity from. | 
| AzureSentinel.AlertRule.properties.incidentConfiguration.createIncident | Boolean | Create incidents from alerts triggered by this analytics rule. | 
| AzureSentinel.AlertRule.properties.incidentConfiguration.groupingConfiguration.enabled | Boolean | Whether grouping is enabled. | 
| AzureSentinel.AlertRule.properties.incidentConfiguration.groupingConfiguration.reopenClosedIncident | Boolean | Re-open closed matching incidents. | 
| AzureSentinel.AlertRule.properties.incidentConfiguration.groupingConfiguration.lookbackDuration | String | Limit the group to alerts created within the lookback duration \(in ISO 8601 duration format\). | 
| AzureSentinel.AlertRule.properties.incidentConfiguration.groupingConfiguration.matchingMethod | String | Grouping matching method. When method is Selected at least one of groupByEntities, groupByAlertDetails, groupByCustomDetails must be provided and not empty. | 
| AzureSentinel.AlertRule.properties.incidentConfiguration.groupingConfiguration.groupByEntities | String | A list of entity types to group by \(when matchingMethod is Selected\). Only entities defined in the current alert rule may be used. | 
| AzureSentinel.AlertRule.properties.incidentConfiguration.groupingConfiguration.groupByAlertDetails | String | A list of alert details to group by \(when matchingMethod is Selected\). | 
| AzureSentinel.AlertRule.properties.incidentConfiguration.groupingConfiguration.groupByCustomDetails | String | A list of custom details keys to group by \(when matchingMethod is Selected\). Only keys defined in the current alert rule may be used. | 
| AzureSentinel.AlertRule.properties.productFilter | String | The alerts' productName on which the cases will be generated. | 
| AzureSentinel.AlertRule.properties.severitiesFilter | Unknown | The alerts' severities on which the cases will be generated. | 
| AzureSentinel.AlertRule.properties.displayNamesFilter | Unknown | The alerts' displayNames on which the cases will be generated | 

#### Command example

```!azure-sentinel-list-alert-rule limit=1```

#### Context Example

```json
{
    "AzureSentinel": {
        "AlertRule": {
            "etag": "\"0000-0100-0000\"",
            "id": "/subscriptions/{subscription_id}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules/test-rule-id",
            "kind": "Scheduled",
            "name": "test-rule-id",
            "properties": {
                "alertRuleTemplateName": null,
                "description": null,
                "displayName": "testing displayname",
                "enabled": true,
                "entityMappings": [
                    {
                        "entityType": "Account",
                        "fieldMappings": [
                            {
                                "columnName": "Account",
                                "identifier": "FullName"
                            }
                        ]
                    },
                    {
                        "entityType": "Host",
                        "fieldMappings": [
                            {
                                "columnName": "Computer",
                                "identifier": "FullName"
                            }
                        ]
                    }
                ],
                "eventGroupingSettings": {
                    "aggregationKind": "AlertPerResult"
                },
                "incidentConfiguration": {
                    "createIncident": true,
                    "groupingConfiguration": {
                        "enabled": false,
                        "groupByAlertDetails": null,
                        "groupByCustomDetails": null,
                        "groupByEntities": [],
                        "lookbackDuration": "PT5H",
                        "matchingMethod": "AllEntities",
                        "reopenClosedIncident": false
                    }
                },
                "lastModifiedUtc": "2020-03-28T16:07:49.1905911Z",
                "query": "Heartbeat",
                "queryFrequency": "PT1M",
                "queryPeriod": "P2DT1H30M",
                "severity": "Low",
                "suppressionDuration": "PT1H",
                "suppressionEnabled": false,
                "tactics": [
                    "Persistence"
                ],
                "techniques": [
                    "T11"
                ],
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0
            },
            "type": "Microsoft.SecurityInsights/alertRules"
        }
    }
}
```

#### Human Readable Output

>### Azure Sentinel Alert Rules
>
>|ID|Kind|Severity|Display Name|Description|Enabled|
>|---|---|---|---|---|---|
>| test-rule-id | Scheduled | Low | testing displayname |  | true |

### azure-sentinel-list-alert-rule-template

***
Gets a list of all alert rule templates.


#### Base Command

`azure-sentinel-list-alert-rule-template`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_id | The alert rule template ID. If not given, will return all alert rule templates. | Optional | 
| limit | The maximum number of templates to return. Default is 50. | Optional | 
| subscription_id | The subscription ID. | Optional | 
| resource_group_name | The resource group name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.AlertRuleTemplate.id | String | Fully qualified resource ID for the resource. | 
| AzureSentinel.AlertRuleTemplate.name | String | The name of the resource. | 
| AzureSentinel.AlertRuleTemplate.type | String | The type of the resource. | 
| AzureSentinel.AlertRuleTemplate.kind | String | The alert rule kind. | 
| AzureSentinel.AlertRuleTemplate.properties.severity | String | The severity for alerts created by this alert rule. | 
| AzureSentinel.AlertRuleTemplate.properties.query | String | The query that creates alerts for this rule. | 
| AzureSentinel.AlertRuleTemplate.properties.queryFrequency | String | The frequency \(in ISO 8601 duration format\) for this alert rule to run. | 
| AzureSentinel.AlertRuleTemplate.properties.queryPeriod | String | The period \(in ISO 8601 duration format\) that this alert rule looks at. | 
| AzureSentinel.AlertRuleTemplate.properties.triggerOperator | String | The operation against the threshold that triggers alert rule. | 
| AzureSentinel.AlertRuleTemplate.properties.triggerThreshold | Number | The threshold that triggers this alert rule. | 
| AzureSentinel.AlertRuleTemplate.properties.displayName | String | The display name for the alert rule template. | 
| AzureSentinel.AlertRuleTemplate.properties.description | String | The description of the alert rule template. | 
| AzureSentinel.AlertRuleTemplate.properties.tactics | String | The tactics of the alert rule template. | 
| AzureSentinel.AlertRuleTemplate.properties.lastUpdatedDateUTC | Date | The time this alert rule template was last updated. | 
| AzureSentinel.AlertRuleTemplate.properties.createdDateUTC | Date | The time this alert rule template was added. | 
| AzureSentinel.AlertRuleTemplate.properties.status | String | The alert rule template status. | 
| AzureSentinel.AlertRuleTemplate.properties.version | String | The version of this template in the format &lt;a.b.c&gt;, where all are numbers. For example &lt;1.0.2&gt;. | 
| AzureSentinel.AlertRuleTemplate.properties.requiredDataConnectors.connectorId | String | The connector ID that provides the following data types | 
| AzureSentinel.AlertRuleTemplate.properties.requiredDataConnectors.dataTypes | String | The data types used by the alert rule template. | 
| AzureSentinel.AlertRuleTemplate.properties.alertRulesCreatedByTemplateCount | Number | The number of alert rules that were created by this template. | 
| AzureSentinel.AlertRuleTemplate.properties.productFilter | String | The alerts' productName on which the cases will be generated. | 

#### Command example

```!azure-sentinel-list-alert-rule-template limit=1```

#### Context Example

```json
{
    "AzureSentinel": {
        "AlertRuleTemplate": {
            "id": "/subscriptions/{subscription_id}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/AlertRuleTemplates/test-rule-template-id",
            "kind": "Scheduled",
            "name": "test-rule-template-id",
            "properties": {
                "severity": "Low",
                "query": "let timeframe = 1d;\nAWSCloudTrail\n| where TimeGenerated >= ago(timeframe)\n| where EventName == \"CreateNetworkAclEntry\"\n    or EventName == \"CreateRoute\"\n| project TimeGenerated, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid, UserAgent, UserIdentityUserName, SessionMfaAuthenticated, SourceIpAddress, AWSRegion, EventSource, AdditionalEventData, ResponseElements\n| extend AccountCustomEntity = UserIdentityUserName, IPCustomEntity = SourceIpAddress",
                "queryFrequency": "P1D",
                "queryPeriod": "P1D",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "displayName": "Changes to Amazon VPC settings",
                "description": "This alert monitors changes to Amazon VPC (Virtual Private Cloud) settings such as new ACL entries and routes in route tables.\nMore information: https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255 \nand https://aws.amazon.com/vpc/",
                "tactics": [
                "PrivilegeEscalation",
                "LateralMovement"
                ],
                "lastUpdatedDateUTC": "2021-02-27T10:00:00Z",
                "createdDateUTC": "2019-02-27T00:00:00Z",
                "status": "Available",
                "version": "1.0.1",
                "requiredDataConnectors": [
                {
                    "connectorId": "AWS",
                    "dataTypes": [
                    "AWSCloudTrail"
                    ]
                }
                ],
                "alertRulesCreatedByTemplateCount": 0
            },
            "type": "Microsoft.SecurityInsights/AlertRuleTemplates"
        }
    }
}
```

#### Human Readable Output

>### Azure Sentinel Alert Rule Template
>
>|ID|Kind|Severity|Display Name|Description|Status|Created Date UTC|Last Updated Date UTC|Alert Rules Created By Template Count|
>|---|---|---|---|---|---|---|---|---|
>| test-rule-template-id | Scheduled | Low | Changes to Amazon VPC settings | This alert monitors changes to Amazon VPC (Virtual Private Cloud) settings such as new ACL entries and routes in route tables.<br/>More information: <https://medium.com/@GorillaStack/the-most-important-aws-cloudtrail-security-events-to-track-a5b9873f8255> <br/>and <https://aws.amazon.com/vpc/> | Available | 2019-02-27T00:00:00Z | 2021-02-27T10:00:00Z | 0 |

### azure-sentinel-delete-alert-rule

***
Deletes the specified alert rule.

#### Base Command

`azure-sentinel-delete-alert-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The alert rule ID to delete. | Required | 
| subscription_id | The subscription ID. | Optional | 
| resource_group_name | The resource group name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.AlertRule.ID | String | The alert rule ID. | 
| AzureSentinel.AlertRule.Deleted | Boolean | Whether the alert rule was deleted. | 

#### Command example

```!azure-sentinel-delete-alert-rule rule_id=1234-abcd-5678-efgh```

#### Context Example

```json
{
    "AzureSentinel": {
        "AlertRule": {
            "Deleted": true,
            "ID": "1234-abcd-5678-efgh"
        }
    }
}
```

#### Human Readable Output

>Alert rule 1234-abcd-5678-efgh was deleted successfully.
>
### azure-sentinel-create-alert-rule

***
Creates a new alert rule.

#### Base Command

`azure-sentinel-create-alert-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The alert rule name to create. | Required | 
| kind | The alert rule kind to create. Possible values are: fusion, microsoft_security_incident_creation, scheduled. | Optional | 
| template_name | The name of the alert rule template used to create this rule.<br/>Required for Fusion, optional for Scheduled rules | Optional | 
| enabled | Determines whether this alert rule is enabled or disabled. Possible values are: yes, no. | Optional | 
| etag | ETag of the Azure resource. | Optional | 
| displayName | The display name for alerts created by this alert rule.<br/>Required for MicrosoftSecurityIncidentCreation and scheduled rules | Optional | 
| product_filter | The alerts' productName on which the cases will be generated.<br/>Required for MicrosoftSecurityIncidentCreation rules.<br/>Possible values are: azure_active_directory_identity_protection, azure_advanced_threat_protection, azure_security_center, azure_security_center_for_iot, microsoft_cloud_app_security. | Optional | 
| description | The description of the alert rule.<br/>Relevant for MicrosoftSecurityIncidentCreation and scheduled rules. | Optional | 
| name_exclude_filter | Alerts' displayNames on which the cases will not be generated.<br/>Relevant for MicrosoftSecurityIncidentCreation rules. | Optional | 
| name_include_filter | Alerts' displayNames on which the cases will be generated.<br/>Relevant for MicrosoftSecurityIncidentCreation rules. | Optional | 
| severity_filter | Alerts' severities on which the cases will be generated.<br/>Relevant for MicrosoftSecurityIncidentCreation rules. | Optional | 
| query | The query that creates alerts for this rule.<br/>Required for scheduled rules. | Optional | 
| query_frequency | The frequency (in ISO 8601 duration format: PnYnMnDTnHnMnS or PnW) for this alert rule to run.<br/>Required for scheduled rules. | Optional | 
| query_period | The period (in ISO 8601 duration format: PnYnMnDTnHnMnS or PnW) that this alert rule looks at.<br/>Required for scheduled rules. | Optional | 
| severity | The severity for alerts created by this alert rule.<br/>Required for scheduled rules.<br/>Possible values are: informational, low, medium, high. | Optional | 
| suppression_duration | The suppression (in ISO 8601 duration format: PnYnMnDTnHnMnS or PnW) to wait since the last time this alert rule was triggered.<br/>Required for scheduled rules. | Optional | 
| suppression_enabled | Determines whether the suppression for this alert rule is enabled or disabled.<br/>Required for scheduled rules.<br/>Possible values are: yes, no. | Optional | 
| trigger_operator | The operation against the threshold that triggers the alert rule.<br/>Required for scheduled rules.<br/>Possible values are: equal, greater_than, less_than, not_equal. | Optional | 
| trigger_threshold | The threshold that triggers this alert rule.<br/>Required for scheduled rules. | Optional | 
| tactics | The tactics of the alert rule.<br/>Relevant for scheduled rules. | Optional | 
| techniques | The techniques of the alert rule.<br/>Relevant for scheduled rules. | Optional | 
| rule_json | Option to insert a configured rule JSON instead of using the arguments. | Optional | 
| subscription_id | The subscription ID. | Optional | 
| resource_group_name | The resource group name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description**                                                                                            |
| --- | --- |------------------------------------------------------------------------------------------------------------|
| AzureSentinel.AlertRule.id | String | Fully qualified resource ID for the resource.                                                              | 
| AzureSentinel.AlertRule.name | String | The name of the resource.                                                                                  | 
| AzureSentinel.AlertRule.etag | String | ETag of the Azure resource.                                                                                | 
| AzureSentinel.AlertRule.type | String | The type of the resource, e.g., "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts" | 
| AzureSentinel.AlertRule.kind | String | The alert rule kind.                                                                                       | 
| AzureSentinel.AlertRule.properties.displayName | String | The display name for alerts created by this alert rule.                                                    | 
| AzureSentinel.AlertRule.properties.description | String | The description of the alert rule.                                                                         | 
| AzureSentinel.AlertRule.properties.alertRuleTemplateName | Unknown | The name of the alert rule template used to create this rule.                                              | 
| AzureSentinel.AlertRule.properties.tactics | String | The tactics of the alert rule.                                                                             | 
| AzureSentinel.AlertRule.properties.severity | String | The severity for alerts created by this alert rule.                                                        | 
| AzureSentinel.AlertRule.properties.enabled | Boolean | Determines whether this alert rule is enabled or disabled.                                                 | 
| AzureSentinel.AlertRule.properties.lastModifiedUtc | Date | The last time that this alert was modified.                                                                | 
| AzureSentinel.AlertRule.properties.productFilter | String | The alerts' productName on which the cases will be generated.                                              | 
| AzureSentinel.AlertRule.properties.severitiesFilter | Unknown | The alerts' severities on which the cases will be generated.                                               | 
| AzureSentinel.AlertRule.properties.displayNamesFilter | Unknown | The alerts' displayNames on which the cases will be generated.                                             | 
| AzureSentinel.AlertRule.properties.query | String | The query that creates alerts for this rule.                                                               | 
| AzureSentinel.AlertRule.properties.queryFrequency | String | The frequency \(in ISO 8601 duration format\) for this alert rule to run.                                  | 
| AzureSentinel.AlertRule.properties.queryPeriod | String | The period \(in ISO 8601 duration format\) that this alert rule looks at.                                  | 
| AzureSentinel.AlertRule.properties.triggerOperator | String | The operation against the threshold that triggers the alert rule.                                          | 
| AzureSentinel.AlertRule.properties.triggerThreshold | Number | The threshold that triggers this alert rule.                                                               | 
| AzureSentinel.AlertRule.properties.suppressionDuration | String | The suppression \(in ISO 8601 duration format\) to wait since the last time this alert rule was triggered. | 
| AzureSentinel.AlertRule.properties.suppressionEnabled | Boolean | Determines whether the suppression for this alert rule is enabled or disabled.                             | 
| AzureSentinel.AlertRule.properties.eventGroupingSettings | Unknown | The event grouping settings.                                                                               | 
| AzureSentinel.AlertRule.properties.customDetails | Unknown | Dictionary of string key-value pairs of columns to be attached to the alert.                               | 
| AzureSentinel.AlertRule.properties.entityMappings | Unknown | Array of the entity mappings of the alert rule.                                                            | 
| AzureSentinel.AlertRule.properties.alertDetailsOverride | String | The alert details override settings.                                                                       | 
| AzureSentinel.AlertRule.properties.incidentConfiguration | Unknown | The settings of the incidents that created from alerts triggered by this analytics rule.                   | 

#### Command example

```!azure-sentinel-create-alert-rule enabled=true kind=microsoft_security_incident_creation rule_name=test_name displayName="Testing Display Name" product_filter=microsoft_cloud_app_security```

#### Context Example

```json
{
    "AzureSentinel": {
        "AlertRule": {
            "etag": "\"09009060-0000-5e60000\"",
            "id": "/subscriptions/{subscription_id}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules/test_name",
            "kind": "MicrosoftSecurityIncidentCreation",
            "name": "test_name",
            "properties": {
                "alertRuleTemplateName": null,
                "description": null,
                "displayName": "Testing Display Name",
                "displayNamesExcludeFilter": null,
                "displayNamesFilter": null,
                "enabled": true,
                "lastModifiedUtc": "2023-02-20T10:05:26.5066026Z",
                "productFilter": "Microsoft Cloud App Security",
                "severitiesFilter": null
            },
            "type": "Microsoft.SecurityInsights/alertRules"
        }
    }
}
```

#### Human Readable Output

>### Azure Sentinel Alert Rule successfully created/updated
>
>|ID|Name|Kind|Display Name|Enabled|Etag|
>|---|---|---|---|---|---|---|---|
>| test_name | test_name | MicrosoftSecurityIncidentCreation | Testing Display Name | true | "09009060-0000-5e60000" |

### azure-sentinel-update-alert-rule

***
Updates an alert rule.

#### Base Command

`azure-sentinel-update-alert-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The alert rule name to update. | Required | 
| kind | The alert rule kind to update. Possible values are: fusion, microsoft_security_incident_creation, scheduled. | Optional | 
| template_name | The name of the alert rule template used to update this rule.<br/>Required for Fusion, optional for Scheduled rules. | Optional | 
| enabled | Determines whether this alert rule is enabled or disabled. Possible values are: yes, no. | Optional | 
| etag | ETag of the Azure resource. | Optional | 
| displayName | The display name for alerts created by this alert rule.<br/>Required for MicrosoftSecurityIncidentCreation and scheduled rules. | Optional | 
| product_filter | The alerts' productName on which the cases will be generated.<br/>Required for MicrosoftSecurityIncidentCreation rules.<br/>Possible values are: azure_active_directory_identity_protection, azure_advanced_threat_protection, azure_security_center, azure_security_center_for_iot, microsoft_cloud_app_security. | Optional | 
| description | The description of the alert rule.<br/>Relevant for MicrosoftSecurityIncidentCreation and scheduled rules. | Optional | 
| name_exclude_filter | Alerts' displayNames on which the cases will not be generated.<br/>Relevant for MicrosoftSecurityIncidentCreation rules. | Optional | 
| name_include_filter | Alerts' displayNames on which the cases will be generated.<br/>Relevant for MicrosoftSecurityIncidentCreation rules. | Optional | 
| severity_filter | Alerts' severities on which the cases will be generated.<br/>Relevant for MicrosoftSecurityIncidentCreation rules. | Optional | 
| query | The query that creates alerts for this rule.<br/>Required for scheduled rules. | Optional | 
| query_frequency | The frequency (in ISO 8601 duration format: PnYnMnDTnHnMnS or PnW) for this alert rule to run.<br/>Required for scheduled rules. | Optional | 
| query_period | The period (in ISO 8601 duration format: PnYnMnDTnHnMnS or PnW) that this alert rule looks at.<br/>Required for scheduled rules. | Optional | 
| severity | The severity for alerts created by this alert rule.<br/>Required for scheduled rules.<br/>Possible values are: informational, low, medium, high. | Optional | 
| suppression_duration | The suppression (in ISO 8601 duration format: PnYnMnDTnHnMnS or PnW) to wait since the last time this alert rule was triggered.<br/>Required for scheduled rules. | Optional | 
| suppression_enabled | Determines whether the suppression for this alert rule is enabled or disabled.<br/>Required for scheduled rules.<br/>Possible values are: yes, no. | Optional | 
| trigger_operator | The operation against the threshold that triggers the alert rule.<br/>Required for scheduled rules.<br/>Possible values are: equal, greater_than, less_than, not_equal. | Optional | 
| trigger_threshold | The threshold that triggers this alert rule.<br/>Required for scheduled rules. | Optional | 
| tactics | The tactics of the alert rule.<br/>Relevant for scheduled rules. | Optional | 
| techniques | The techniques of the alert rule.<br/>Relevant for scheduled rules. | Optional | 
| rule_json | Option to insert a configured rule JSON instead of using the arguments. | Optional | 
| subscription_id | The subscription ID. | Optional | 
| resource_group_name | The resource group name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description**                                                                                             |
| --- | --- |-------------------------------------------------------------------------------------------------------------|
| AzureSentinel.AlertRule.id | String | Fully qualified resource ID for the resource.                                                               | 
| AzureSentinel.AlertRule.name | String | The name of the resource.                                                                                   | 
| AzureSentinel.AlertRule.etag | String | ETag of the Azure resource.                                                                                 | 
| AzureSentinel.AlertRule.type | String | The type of the resource, e.g., "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts"  | 
| AzureSentinel.AlertRule.kind | String | The alert rule kind.                                                                                        | 
| AzureSentinel.AlertRule.properties.displayName | String | The display name for alerts created by this alert rule.                                                     | 
| AzureSentinel.AlertRule.properties.description | String | The description of the alert rule.                                                                          | 
| AzureSentinel.AlertRule.properties.alertRuleTemplateName | Unknown | The name of the alert rule template used to update this rule.                                               | 
| AzureSentinel.AlertRule.properties.tactics | String | The tactics of the alert rule.                                                                              | 
| AzureSentinel.AlertRule.properties.severity | String | The severity for alerts created by this alert rule.                                                         | 
| AzureSentinel.AlertRule.properties.enabled | Boolean | Determines whether this alert rule is enabled or disabled.                                                  | 
| AzureSentinel.AlertRule.properties.lastModifiedUtc | Date | The last time this alert was modified.                                                                      | 
| AzureSentinel.AlertRule.properties.productFilter | String | The alerts' productName on which the cases will be generated.                                               | 
| AzureSentinel.AlertRule.properties.severitiesFilter | Unknown | The alerts' severities on which the cases will be generated.                                                | 
| AzureSentinel.AlertRule.properties.displayNamesFilter | Unknown | The alerts' displayNames on which the cases will be generated.                                              | 
| AzureSentinel.AlertRule.properties.query | String | The query that creates alerts for this rule.                                                                | 
| AzureSentinel.AlertRule.properties.queryFrequency | String | The frequency \(in ISO 8601 duration format\) for this alert rule to run.                                   | 
| AzureSentinel.AlertRule.properties.queryPeriod | String | The period \(in ISO 8601 duration format\) that this alert rule looks at.                                   | 
| AzureSentinel.AlertRule.properties.triggerOperator | String | The operation against the threshold that triggers alert rule.                                               | 
| AzureSentinel.AlertRule.properties.triggerThreshold | Number | The threshold triggers this alert rule.                                                                     | 
| AzureSentinel.AlertRule.properties.suppressionDuration | String | The suppression \(in ISO 8601 duration format\) to wait since the last time this alert rule been triggered. | 
| AzureSentinel.AlertRule.properties.suppressionEnabled | Boolean | Determines whether the suppression for this alert rule is enabled or disabled.                              | 
| AzureSentinel.AlertRule.properties.eventGroupingSettings | Unknown | The event grouping settings.                                                                                | 
| AzureSentinel.AlertRule.properties.customDetails | Unknown | Dictionary of string key-value pairs of columns to be attached to the alert                                 | 
| AzureSentinel.AlertRule.properties.entityMappings | Unknown | Array of the entity mappings of the alert rule.                                                             | 
| AzureSentinel.AlertRule.properties.alertDetailsOverride | String | The alert details override settings.                                                                        | 
| AzureSentinel.AlertRule.properties.incidentConfiguration | Unknown | The settings of the incidents that created from alerts triggered by this analytics rule.                    | 

#### Command example

```!azure-sentinel-update-alert-rule enabled=true kind=microsoft_security_incident_creation rule_name=test_name displayName="Testing updating Display Name" product_filter=microsoft_cloud_app_security```

#### Context Example

```json
{
    "AzureSentinel": {
        "AlertRule": {
            "etag": "\"097809060-0000-6hd400\"",
            "id": "/subscriptions/{subscription_id}/resourceGroups/{resourceGroupName}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules/test_name",
            "kind": "MicrosoftSecurityIncidentCreation",
            "name": "test_name",
            "properties": {
                "alertRuleTemplateName": null,
                "description": null,
                "displayName": "Testing updating Display Name",
                "displayNamesExcludeFilter": null,
                "displayNamesFilter": null,
                "enabled": true,
                "lastModifiedUtc": "2023-02-20T11:59:42.2920381Z",
                "productFilter": "Microsoft Cloud App Security",
                "severitiesFilter": null
            },
            "type": "Microsoft.SecurityInsights/alertRules"
        }
    }
}
```

#### Human Readable Output

>### Azure Sentinel Alert Rule successfully created/updated
>
>|ID|Name|Kind|Display Name|Enabled|Etag|
>|---|---|---|---|---|---|---|---|
>| test_name | test_name | MicrosoftSecurityIncidentCreation | Testing updating Display Name | true | "097809060-0000-6hd400" |

### azure-sentinel-subscriptions-list

***
Lists all subscriptions.

#### Base Command

`azure-sentinel-subscriptions-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.SubscriptionId | String | Fully qualified resource ID for the resource. | 
| AzureSentinel.Subscription.displayName | String | The name of the resource. | 
| AzureSentinel.Subscription.authorizationSource | String | The authorization source of the resource. | 
| AzureSentinel.Subscription.managedByTenants | String | The subscriptions that are managed by tenants of the resource. | 
| AzureSentinel.Subscription.tenetId | String | The tenet ID of the resource. | 
| AzureSentinel.Subscription.state | String | The state of the resource. | 
| AzureSentinel.Subscription.subscriptionPolicies | String | The subscription policies of the resource. | 

#### Command example

```!azure-sentinel-subscriptions-list```

#### Context Example

```json
{
    "AzureSentinel": {
        "Subscription": {
            "authorizationSource": "RoleBased",
            "displayName": "Pay-As-You-Go",
            "id": "/subscriptions/0000000000000",
            "managedByTenants": [],
            "state": "Enabled",
            "subscriptionId": "0000000000000",
            "subscriptionPolicies": {
                "locationPlacementId": "Public_2014-09-01",
                "quotaId": "PayAsYouGo_2014-09-01",
                "spendingLimit": "Off"
            },
            "tenantId": "000000000000000"
        }
    }
}
```

#### Human Readable Output

>### Azure Sentinel Subscriptions

>|Subscriptionid|Tenantid|Displayname|State|
>|---|---|---|---|
>| 0000000000000 | 000000000000000 | Pay-As-You-Go | Enabled |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.ResourceGroup.id | String | Fully qualified resource ID for the resource. | 
| AzureSentinel.ResourceGroup.name | String | The name of the resource. | 
| AzureSentinel.ResourceGroup.type | String | The type of the resource. E.g., "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts" | 
| AzureSentinel.ResourceGroup.location | String | The location of the resource group. | 
| AzureSentinel.ResourceGroup.tags | Dictionary | The tags of the resource group. | 
| AzureSentinel.ResourceGroup.properties | dictionary | The properties of the resource group. | 

### azure-sentinel-resource-group-list

***
Lists all resource groups.

#### Base Command

`azure-sentinel-resource-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: The integration default Subscription ID will be used unless this argument is provided. | Optional | 
| tag | The tag name. Input should be `{“Tag Name:Tag Value”}``. Operator is “equals”. | Optional | 
| limit | The maximum number of items to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSentinel.ResourceGroup.id | String | Fully qualified resource ID for the resource. | 
| AzureSentinel.ResourceGroup.name | String | The name of the resource. | 
| AzureSentinel.ResourceGroup.type | String | The type of the resource. E.g., "Microsoft.Compute/virtualMachines" or "Microsoft.Storage/storageAccounts" | 
| AzureSentinel.ResourceGroup.location | String | The location of the resource group. | 
| AzureSentinel.ResourceGroup.tags | Dictionary | The tags of the resource group. | 
| AzureSentinel.ResourceGroup.properties | dictionary | The properties of the resource group. | 

#### Command example

```!azure-sentinel-resource-group-list```

#### Context Example

```json
{
    "AzureSentinel": {
        "ResourceGroup": [
            {
                "id": "/subscriptions/0f907ea4-bc8b-/resourceGroups/cloud-shell",
                "location": "eastus",
                "name": "cloud-shell-storage-eastus",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/0f907ea4/resourceGroups/demi",
                "location": "centralus",
                "name": "demi",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {
                    "Owner": "Demi"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
    ]}
}
```

#### Human Readable Output

>### Azure Sentinel Resource Groups

>|Name|Location|Tags|
>|---|---|---|
>| cloud-shell | eastus |  |
>| demi | centralus | Owner: Demi |


### azure-sentinel-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`azure-sentinel-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
