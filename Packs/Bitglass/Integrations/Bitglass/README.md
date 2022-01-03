The app pulls cloudaudit and access Bitglass log data filtered down to the specified DLP patterns. It also provides actions for access to Bitglass REST APIs for group and user manipulation.
This integration was integrated and tested with version xx of Bitglass

## Configure Bitglass on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Bitglass.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Use system proxy |  | False |
    | Allow any cert |  | False |
    | OAuth 2 Authentication Token | The OAuth 2 authentication token for the Bitglass API | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Bitglass API URL | The URL for the Bitglass API to retrieve the log events | True |
    | Proxy settings for Bitglass API | https=https://usr:pswd@1.2.3.4:999 | False |
    | Pull Bitglass Access logs : | Turn on the retrieval of the Access log type events as incidents | False |
    | DLP Pattern for Access | Filter the Access log type events down to the pattern | False |
    | Pull Bitglass CloudAudit logs : | Turn on the retrieval of the CloudAudit log type events as incidents | False |
    | DLP Pattern for CloudAudit | Filter the CloudAudit log type events down to the pattern | False |
    | Incidents Fetch Interval |  | False |
    | Long running instance |  | False |
    | reset tag | Type in a different tag to retrieve anew all incidents starting from 30 days ago up to now | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bitglass-filter-by-dlp-pattern
***
Filter log events by DLP pattern


#### Base Command

`bitglass-filter-by-dlp-pattern`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bg_match_expression | Python regex expression to match the patterns. Default is Malware.*. | Required | 
| bg_log_event | XSOAR Event ID###. Default is artifact:*.id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitglass.user_name | string | Offending user name | 


#### Command Example
``` ```

#### Human Readable Output



### bitglass-create-update-group
***
Create or update a group


#### Base Command

`bitglass-create-update-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bg_group_name | Name of the group to create or update. Default is RiskyUsers. | Required | 
| bg_new_group_name | New name of the group to rename to. Default is RiskyUsers. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### bitglass-delete-group
***
Delete a group


#### Base Command

`bitglass-delete-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bg_group_name | Name of the group to delete. Default is RiskyUsers. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### bitglass-add-user-to-group
***
Add risky user to a group


#### Base Command

`bitglass-add-user-to-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bg_group_name | Name of the group to add the risky user to. Default is RiskyUsers. | Required | 
| bg_user_name | User name to add. Default is ${Bitglass.user_name}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### bitglass-remove-user-from-group
***
Remove risky user from a group


#### Base Command

`bitglass-remove-user-from-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bg_group_name | Name of the group to add the risky user to. Default is RiskyUsers. | Required | 
| bg_user_name | User name to remove. Default is ${Bitglass.user_name}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### bitglass-create-update-user
***
Create or update user


#### Base Command

`bitglass-create-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bg_user_name | Email of the user to create or update. | Required | 
| bg_first_name | First name. | Optional | 
| bg_last_name | Last name. | Optional | 
| bg_secondary_email | Secondary email. | Optional | 
| bg_netbios_domain | NetBIOS domain. | Optional | 
| bg_sam_account_name | SAM account domain. | Optional | 
| bg_user_principal_name | User principal name. | Optional | 
| bg_object_guid | Object GUID. | Optional | 
| bg_country_code | Country code. | Optional | 
| bg_mobile_number | Mobile number. | Optional | 
| bg_admin_role | Admin role. | Optional | 
| bg_group_membership | Place the user under the group. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### bitglass-deactivate-user
***
Deactivate user


#### Base Command

`bitglass-deactivate-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bg_user_name | Email of the user to deactivate. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### bitglass-reactivate-user
***
Reactivate user


#### Base Command

`bitglass-reactivate-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bg_user_name | Email of the user to reactivate. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


