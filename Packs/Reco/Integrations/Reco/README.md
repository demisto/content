Reco is a Saas data security solution that protects your data from accidental leaks and malicious attacks.
This integration was integrated and tested with version 2023.34.0 of Reco.

## Configure Reco in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://host.reco.ai/api/v1) |  | True |
| JWT app token |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Max fetch |  | False |
| Source | Incidents SaaS Source | False |
| Before | Created At time before which incidents will be fetched | False |
| After | Created At time after which incidents will be fetched | False |
| Risk level | Risk level of the incidents to fetch | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### reco-add-exclusion-filter

***
Add exclusion filter to Reco Classifier

#### Base Command

`reco-add-exclusion-filter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| values_to_add | Values to add to the exclusion filter (split by ','). | Required | 
| key_to_add | key too add to the exclusion filter (e.g. "CASE_SENSITIVE_TERMS", "LOCATION_CASE_INSENSITIVE_TERMS", "OWNERS", "FILE_IDS", "LOCATIONS"). | Required | 

#### Context Output

There is no context output for this command.
### reco-update-incident-timeline

***
Add a comment to an incident in Reco

#### Base Command

`reco-update-incident-timeline`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | Comment to add to the incident. | Required | 
| incident_id | Incident ID to add the comment to. | Required | 

#### Context Output

There is no context output for this command.
### reco-resolve-visibility-event

***
Resolve an event in Reco Finding. Reco Findings contains aggregations of events. This command resolves the event in the Reco Finding.

#### Base Command

`reco-resolve-visibility-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | entity id of the file to resolve. | Required | 
| label_name | label name to resolve (e.g. "Accessible to All Org Users", "Accessible by General Public"). | Required | 

#### Context Output

There is no context output for this command.
### reco-get-risky-users

***
Get Risky Users from Reco

#### Base Command

`reco-get-risky-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.RiskyUsers | unknown | Risky Users | 

### reco-add-risky-user-label

***
Tag a user as risky in Reco

#### Base Command

`reco-add-risky-user-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address of the user to add to the risky users list in Reco. | Required | 

#### Context Output

There is no context output for this command.
### reco-get-assets-user-has-access-to

***
Get all files user has access to from Reco

#### Base Command

`reco-get-assets-user-has-access-to`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address of the user. | Required | 
| only_sensitive | Return only sensitive assets owned by this user. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets | unknown | Assets user has access to | 

### reco-add-leaving-org-user-label

***
Tag a user as leaving org user in Reco

#### Base Command

`reco-add-leaving-org-user-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | Email address of the user to tag as levaing org user. | Required | 

#### Context Output

There is no context output for this command.
### reco-get-sensitive-assets-by-name

***
Get all sensitive assets from Reco by name

#### Base Command

`reco-get-sensitive-assets-by-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_name | Asset name to search for. | Required | 
| regex_search | Return only sensitive assets owned by this user. | Optional | 

#### Context Output

There is no context output for this command.
### reco-get-sensitive-assets-by-id

***
Get all sensitive assets from Reco by id

#### Base Command

`reco-get-sensitive-assets-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset id to search for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.SensitiveAssets.file_name | String | The name of the asset | 
| Reco.SensitiveAssets.file_owner | String | The owner of the asset | 
| Reco.SensitiveAssets.file_url | Unknown | Json string of the asset's url and the name | 
| Reco.SensitiveAssets.currently_permitted_users | String | List of currently permitted users | 
| Reco.SensitiveAssets.visibility | String | Visibility of the asset | 
| Reco.SensitiveAssets.location | String | The path of the asset | 
| Reco.SensitiveAssets.source | String | SaaS tool source of the asset | 
| Reco.SensitiveAssets.sensitivity_level | Number | The sensitivity level of the asset | 

### reco-get-link-to-user-overview-page

***
Generate a magic link for reco UI (overview page)

#### Base Command

`reco-get-link-to-user-overview-page`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity | Entity Type (RM_LINK_TYPE_USER). | Required | 
| param | Entity ID (user email). | Optional | 

#### Context Output

There is no context output for this command.
### reco-get-3rd-parties-accessible-to-data-list

***
Get 3rd parties accessible to sensitive assets

#### Base Command

`reco-get-3rd-parties-accessible-to-data-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_interaction_time_in_days | Last interaction time in days. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Domains.domain | String | The domain of the 3rd party | 
| Reco.Domains.last_activity | String | The last interaction time with the 3rd party | 
| Reco.Domains.files_num | Number | The number of files the 3rd party has access to | 
| Reco.Domains.users_with_access_num | Number | The number of users the 3rd party has access to |

### reco-get-sensitive-assets-with-public-link

***
Get all sensitive assets with public link from Reco

#### Base Command

`reco-get-sensitive-assets-with-public-link`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets.asset_id | String | The asset id | 
| Reco.Assets.asset | Unknown | Json string of the asset's url and the name | 
| Reco.Assets.data_category | String | The data category of the asset | 
| Reco.Assets.data_categories | String | The data categories of the asset | 
| Reco.SensitiveAssets.location | String | The path of the asset | 
| Reco.SensitiveAssets.source | String | SaaS tool source of the asset | 
| Reco.Assets.last_access_date | String | The last access date of the asset | 

### reco-get-files-shared-with-3rd-parties

***
Get files shared with 3rd parties

#### Base Command

`reco-get-files-shared-with-3rd-parties`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_interaction_time_in_days | Last interaction time in days. | Required | 
| domain | Domain to search. | Required | 

#### Context Output

| **Path**                     | **Type** | **Description**                                             |
|------------------------------|----------|-------------------------------------------------------------|
| Reco.Assets.asset_id         | String   | The asset id of the file                                    | 
| Reco.Assets.location         | String   | The location of the file                                    | 
| Reco.Assets.users            | String   | Users the file is shared with                               | 
| Reco.Assets.file_owner       | String   | File Owner                                                  |
| Reco.Assets.asset            | Unknown  | The asset metadata                                          | 
| Reco.Assets.data_category    | String   | The data category of the assets the 3rd party has access to | 
| Reco.Assets.last_access_date | String   | The last access date of the asset                           | 
| Reco.Assets.domain           | String   | The domain of the 3rd party                                 | 

### reco-change-alert-status

***
update alert status in Reco

#### Base Command

`reco-change-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | alert id to get. | Required | 
| status | status to set the alert to (e.g. "ALERT_STATUS_NEW", "ALERT_STATUS_IN_PROGRESS", "ALERT_STATUS_CLOSED"). Possible values are: ALERT_STATUS_NEW, ALERT_STATUS_IN_PROGRESS, ALERT_STATUS_CLOSED. | Required | 

#### Context Output

There is no context output for this command.

### reco-get-user-context-by-email-address

***
Get user context by email address from Reco.

#### Base Command

`reco-get-user-context-by-email-address`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_address | user email address. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.User.email_account | String | The email of the user. | 
| Reco.User.departments | String | User departments. | 
| Reco.User.job_titles | String | Job Title. | 
| Reco.User.category | String | Category. | 
| Reco.User.groups | String | The groups user is member of. | 
| Reco.User.full_name | String | The user full name. | 
| Reco.User.labels | Unknown | User Labels. | 


### reco-get-files-exposed-to-email-address

***
Get files exposed to a specific email address

#### Base Command

`reco-get-files-exposed-to-email-address`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets.asset_id | String | The asset id | 
| Reco.Assets.asset | Unknown | Json string of the asset's url and the name | 
| Reco.Assets.data_category | String | The data category of the asset | 
| Reco.Assets.data_categories | String | The data categories of the asset |
| Reco.Assets.location | String | The path of the asset. |
| Reco.Assets.source | String | SaaS tool source of the asset. |
| Reco.Assets.last_access_date | String | The last access date of the asset |
| Reco.Assets.email_account | String | The last access date of the asset |
| Reco.Assets.file_owner | String | SaaS tool source of the asset | 


### reco-get-assets-shared-externally

***
Get files exposed to a specific email address

#### Base Command

`reco-get-assets-shared-externally`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.Assets.asset_id | String | The asset id | 
| Reco.Assets.asset | Unknown | Json string of the asset's url and the name | 
| Reco.Assets.data_category | String | The data category of the asset | 
| Reco.Assets.data_categories | String | The data categories of the asset | 
| Reco.SensitiveAssets.location | String | The path of the asset | 
| Reco.SensitiveAssets.source | String | SaaS tool source of the asset | 
| Reco.Assets.last_access_date | String | The last access date of the asset |
| Reco.Assets.file_owner | String | SaaS tool source of the asset |


### reco-get-private-email-list-with-access

***
Get private email list with access

#### Base Command

`reco-get-private-email-list-with-access`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description**           |
| --- |----------|---------------------------|
| Reco.privateEmails.email_account | String   | The email account         | 
| Reco.privateEmails.primary_email | String   | The primary email account | 
| Reco.privateEmails.files_num | String   | Number of files           | 
| Reco.privateEmails.user_category | String   | The category of the user  | 



### reco-get-assets-by-id

***
Get all assets from Reco by id

#### Base Command

`reco-get-assets-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset id to search for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Reco.SensitiveAssets.file_name | String | The name of the asset | 
| Reco.SensitiveAssets.file_owner | String | The owner of the asset | 
| Reco.SensitiveAssets.file_url | Unknown | Json string of the asset's url and the name | 
| Reco.SensitiveAssets.currently_permitted_users | String | List of currently permitted users | 
| Reco.SensitiveAssets.visibility | String | Visibility of the asset | 
| Reco.SensitiveAssets.location | String | The path of the asset | 
| Reco.SensitiveAssets.source | String | SaaS tool source of the asset | 
| Reco.SensitiveAssets.sensitivity_level | Number | The sensitivity level of the asset | 