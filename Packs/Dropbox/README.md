Collect events from Dropbox's logs.
This integration was integrated and tested with version 2 of Dropbox API

## Configure Dropbox Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation and Feed Integrations**.
2. Search for Dropbox Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    |---|---|---|
    | Server URL | The endpoint from which to get the logs. | True |
    | App Key | The App key (created in the Dropbox app console). | True |
    | App Secret | The App secret (created in the Dropbox app console).  | True |
    | First fetch in timestamp format | First fetch in timestamp format (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
    | The maximum number of events per fetch |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Run the ***!dropbox-auth-start*** command to test the connection and the authorization process.

## Commands
You can execute these commands from the Cortex XSIAM War Room, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dropbox-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results. This command generates a link. By clicking the link, you get a code for the dropbox-auth-complete command.


#### Base Command

`dropbox-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### dropbox-auth-complete
***
Run this command to complete the authorization process. Should be used after running the dropbox-auth-start command.


#### Base Command

`dropbox-auth-complete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| code | The code that returns from Dropbox. | Required | 


#### Context Output

There is no context output for this command.

### dropbox-auth-test
***
Run this command to test the connectivity to Dropbox. 

***Note: Use this command instead of the Test button in the UI.*** 

#### Base Command

`dropbox-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### dropbox-auth-reset
***
Resets the authentication.


#### Base Command

`dropbox-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### dropbox-get-events
***
Get events.


#### Base Command

`dropbox-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum events to fetch. Default is 500. | Optional | 
| should_push_events | Set this argument to true to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 
| from | Fetch events from this time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 3 days. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!dropbox-get-events should_push_events='false' limit=3```

#### Human Readable Output

>### Dropbox logs
>|Actor|Context|Details|Event _ Category|Event _ Type|Involve _ Non _ Team _ Member|Origin|Timestamp|
>|---|---|---|---|---|---|---|---|
>| .tag: admin<br/>admin: {".tag": "team_member", "account_id": "123456", "display_name": "John Smith", "email": "JohnSmith@example.com", "team_member_id": "111111"} | .tag: team_member<br/>account_id: 123456<br/>display_name: John Smith<br/>email: JohnSmith@example.com<br/>team_member_id: 111111 | .tag: member_change_status_details<br/>previous_value: {".tag": "not_joined"}<br/>new_value: {".tag": "active"}<br/>action: {".tag": "team_join_details", "linked_apps": [], "linked_devices": [], "linked_shared_folders": [], "has_linked_apps": false, "has_linked_devices": true, "has_linked_shared_folders": false} | .tag: members | .tag: member_change_status<br/>description: Changed member status (invited, joined, suspended, etc.) | false | geo_location: {"city": "Tel Aviv", "region": "Tel Aviv", "country": "IL", "ip_address": "1.1.1.1"}<br/>access_method: {".tag": "end_user", "end_user": {".tag": "web", "session_id": "222222"}} | 2022-05-16T11:34:29Z |
>| .tag: admin<br/>admin: {".tag": "team_member", "account_id": "123456", "display_name": "John Smith", "email": "JohnSmith@example.com", "team_member_id": "111111"} | .tag: team_member<br/>account_id: 123456<br/>display_name: John Smith<br/>email: JohnSmith@example.com<br/>team_member_id: 111111 | .tag: member_change_admin_role_details<br/>new_value: {".tag": "team_admin"}<br/>previous_value: {".tag": "member_only"} | .tag: members | .tag: member_change_admin_role<br/>description: Changed team member admin role | false | geo_location: {"city": "Tel Aviv", "region": "Tel Aviv", "country": "IL", "ip_address": "1.1.1.1"}<br/>access_method: {".tag": "end_user", "end_user": {".tag": "web", "session_id": "222222"}} | 2022-05-16T11:34:29Z |
>| .tag: admin<br/>admin: {".tag": "team_member", "account_id": "123456", "display_name": "John Smith", "email": "JohnSmith@example.com", "team_member_id": "111111"} | .tag: team | .tag: member_send_invite_policy_changed_details<br/>new_value: {".tag": "everyone"}<br/>previous_value: {".tag": "specific_members"} | .tag: team_policies | .tag: member_send_invite_policy_changed<br/>description: Changed member send invite policy for team | false | geo_location: {"city": "Tel Aviv", "region": "Tel Aviv", "country": "IL", "ip_address": "1.1.1.1"}<br/>access_method: {".tag": "end_user", "end_user": {".tag": "web", "session_id": "222222"}} | 2022-05-16T11:34:33Z |