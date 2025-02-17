Use the Code42 integration to identify potential data exfiltration from insider threats while speeding investigation and response by providing fast access to file events and metadata across physical and cloud environments.

## Configure Code42 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Code42 Console URL for your Code42 environment | True |
| API Client ID | True |
| API Client Secret | True |
| Fetch incidents | False |
| Incident type | False |
| Alert severities to fetch when fetching incidents | False |
| First fetch time range (&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes) | False |
| Alerts to fetch per run; note that increasing this value may result in slow performance if too many results are returned at once | False |
| Include the list of files in returned incidents. | False |
| Incidents Fetch Interval | False |
| Use v2 file events | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### code42-file-events-search

***
Search for Code42 Incydr File Events

#### Base Command

`code42-file-events-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| add-to-context | Add results to context at 'Code42.FileEvents'. If 'false', the search will only display results as a markdown table. | Optional | 
| json | Raw JSON file event query to be used for search. | Optional | 
| results | The number of file events to return. Defaults to 50. Default is 50. | Optional | 
| min_risk_score | Filter results by minimum risk score. Default is 1. | Optional | 
| hash | MD5 or SHA256 hash of the file to search for. | Optional | 
| username | Username to search for. | Optional | 
| hostname | Hostname to search for. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.FileEvents.timestamp | date | The timestamp when the event occurred. | 
| Code42.FileEvents.event | unknown | Summary information about the event, including date observed, event type, and event source. | 
| Code42.FileEvents.user | unknown | Details about the user associated with the event \(if any\). | 
| Code42.FileEvents.destination | unknown | Details about the destination target of the event \(if any\). | 
| Code42.FileEvents.process | unknown | Details about the CPU process involved in the event \(if any\). | 
| Code42.FileEvents.risk | unknown | Details overall risk severity for the event and lists all associated risk indicators. | 
| Code42.FileEvents.git | unknown | Details about git repository involved in event \(if any\). | 
| Code42.FileEvents.report | unknown | Details about Salesforce reports involved in the event \(if any\). | 
| Code42.FileEvents.file | unknown | Details about file metadata for file involved in the event \(if any\). | 
| Code42.FileEvents.source | unknown | Info about the origin of a file involved in the event \(if any\). | 

### code42-alert-get

***
Retrieve alert details by alert ID

#### Base Command

`code42-alert-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alert ID to retrieve. Alert IDs are associated with alerts that are fetched via fetch-incidents. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityAlert.Username | string | The username associated with the alert. | 
| Code42.SecurityAlert.Occurred | date | The timestamp when the alert occurred. | 
| Code42.SecurityAlert.Description | string | The description of the alert. | 
| Code42.SecurityAlert.ID | string | The alert ID. | 
| Code42.SecurityAlert.Name | string | The alert rule name that generated the alert. | 
| Code42.SecurityAlert.State | string | The alert state. | 
| Code42.SecurityAlert.Severity | string | The severity of the alert. | 

### code42-alert-update

***
Updates a Code42 Alert Session

#### Base Command

`code42-alert-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alert ID to update. Alert IDs are associated with alerts that are fetched via fetch-incidents. | Required | 
| state | The state to which the session will be updated. Permissible values are OPEN, CLOSED_TP, or CLOSED_FP | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityAlert.ID | string | The alert ID of the resolved alert. | 

### code42-alert-resolve

***
DEPRECATED. Use `code42-alert-update` instead.

#### Base Command

`code42-alert-resolve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The alert ID to resolve. Alert IDs are associated with alerts that are fetched via fetch-incidents. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.SecurityAlert.ID | string | The alert ID of the resolved alert. | 


### code42-user-create

***
Creates a Code42 user.

#### Base Command

`code42-user-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgname | The name of the Code42 organization from which to add the user. | Required | 
| username | The username to give to the user. | Required | 
| email | The email of the user to create. Default is The email to give to the user.. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.Username | String | A username for a Code42 user. | 
| Code42.User.Email | String | An email for a Code42 user. | 
| Code42.User.UserID | String | An ID for a Code42 user. | 

### code42-user-block

***
Blocks a user in Code42.  A blocked user is not allowed to log in or restore files. Backups will continue if the user is still active.

#### Base Command

`code42-user-block`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to block. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | An ID for a Code42 user. | 

### code42-user-deactivate

***
Deactivate a user in Code42; signing them out of their devices. Backups discontinue for a deactivated user, and their archives go to cold storage.

#### Base Command

`code42-user-deactivate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to deactivate. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | The ID of a Code42 User. | 

### code42-user-unblock

***
Removes a block, if one exists, on the user with the given user ID. Unblocked users are allowed to log in and restore.

#### Base Command

`code42-user-unblock`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to unblock. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | An ID for a Code42 user. | 

### code42-user-reactivate

***
Reactivates the user with the given username.

#### Base Command

`code42-user-reactivate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to reactivate. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.User.UserID | String | The ID of a Code42 User. | 

### code42-legalhold-add-user

***
Adds a Code42 user to a legal hold matter.

#### Base Command

`code42-legalhold-add-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to add to the given legal hold matter. | Required | 
| mattername | The name of the legal hold matter to which the user will be added. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.LegalHold.UserID | Unknown | The ID of a Code42 user. | 
| Code42.LegalHold.MatterID | String | The ID of a Code42 legal hold matter. | 
| Code42.LegalHold.Username | String | A username for a Code42 user. | 
| Code42.LegalHold.MatterName | String | A name for a Code42 legal hold matter. | 

### code42-legalhold-remove-user

***
Removes a Code42 user from a legal hold matter.

#### Base Command

`code42-legalhold-remove-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to release from the given legal hold matter. | Required | 
| mattername | The name of the legal hold matter from which the user will be released. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.LegalHold.UserID | Unknown | The ID of a Code42 user. | 
| Code42.LegalHold.MatterID | String | The ID of a Code42 legal hold matter. | 
| Code42.LegalHold.Username | String | A username for a Code42 user. | 
| Code42.LegalHold.MatterName | String | A name for a Code42 legal hold matter. | 

### code42-download-file

***
Downloads a file from Code42.

#### Base Command

`code42-download-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Either the SHA256 or MD5 hash of the file. | Required | 
| filename | The filename to save the file as. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

### code42-watchlists-list

***
List all existing watchlists in your environment.

#### Base Command

`code42-watchlists-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.Watchlists.ListType | string | The Type of Watchlist. | 
| Code42.Watchlists.Id | string | The ID of the Watchlist. | 
| Code42.Watchlists.IncludedUserCount | integer | The count of included users on the Watchlist. | 

### code42-watchlists-add-user

***
Add a user to a watchlist.

#### Base Command

`code42-watchlists-add-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Email id of the user to add to Watchlist. | Required | 
| watchlist | WatchlistID or WatchlistType to add user to. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.UsersAddedToWatchlists.Watchlist | string | The ID/Type of the watchlist user was added to. | 
| Code42.UsersAddedToWatchlists.Username | string | The username added to watchlist. | 
| Code42.UsersAddedToWatchlists.Success | boolean | If the user was added successfully. | 

### code42-watchlists-remove-user

***
Remove a user from a watchlist.

#### Base Command

`code42-watchlists-remove-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Email id of the user to add to Watchlist. | Required | 
| watchlist | WatchlistID or WatchlistType to remove user from. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.UsersRemovedFromWatchlists.Watchlist | string | The ID/Type of the watchlist user was removed from. | 
| Code42.UsersRemovedFromWatchlists.Username | string | The username removed from watchlist. | 
| Code42.UsersRemovedFromWatchlists.Success | boolean | If the user was removed successfully. | 

### code42-watchlists-list-included-users

***
List all users who have been explicitly added to a given watchlist.

#### Base Command

`code42-watchlists-list-included-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist | The WatchlistID or WatchlistType to get a list of included users for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.WatchlistUsers.WatchlistID | string | The ID of the Watchlist. | 
| Code42.WatchlistUsers.Username | string | The username on the watchlist. | 
| Code42.WatchlistUsers.AddedTime | datetime | The datetime the user was added to the watchlist. | 

### code42-get-user-risk-profile

***
Get the risk profile details for a given user.

#### Base Command

`code42-user-get-risk-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The user to get risk profile for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.UserRiskProfiles.Username | string | The username. | 
| Code42.UserRiskProfiles.StartDate | date | The startDate value of the UserRiskProfile. | 
| Code42.UserRiskProfiles.EndDate | date | The startDate value of the UserRiskProfile. | 
| Code42.UserRiskProfiles.Notes | string | The notes value of the UserRiskProfile. | 

### code42-user-update-risk-profile

***
Update a user's risk profile.

#### Base Command

`code42-user-update-risk-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The user to update. | Required | 
| start_date | The user's start date (useful for New Employee Watchlist). | Optional | 
| end_date | The user's end date (useful for Departing Employee Watchlist). | Optional | 
| notes | Risk profile notes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Code42.UpdatedUserRiskProfiles.Username | string | The user that was updated. | 
| Code42.UpdatedUserRiskProfiles.StartDate | date | The startDate value of the UserRiskProfile after the update. | 
| Code42.UpdatedUserRiskProfiles.EndDate | date | The startDate value of the UserRiskProfile after the update. | 
| Code42.UpdatedUserRiskProfiles.Notes | string | The notes value of the UserRiskProfile after the update. | 
| Code42.UpdatedUserRiskProfiles.Success | boolean | If the risk profile update was successful. | 

### code42-file-events-table

***
Render Code42 file events from the context as a markdown table

#### Base Command

`code42-file-events-table`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include | Select which events to include in the table.<br/>- 'incident' only displays the events that originally triggered the Code42 Alert.<br/>- 'searches' only displays events that have been added to the context from 'code42-file-events-search' commands.<br/>- 'all' will include all events in the table.<br/>. Possible values are: all, incident, searches. Default is all. | Optional | 

#### Context Output

There is no context output for this command.