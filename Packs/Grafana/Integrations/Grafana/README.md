Grafana alerting service.
This integration was integrated and tested with version 8.0.0 of Grafana

## Configure Grafana in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Username |  | True |
| Password |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Maximum number of incidents to fetch | Maximum is limited to 200. | False |
| Fetch incidents |  | False |
| First fetch time interval |  | False |
| Dashboard IDs to fetch | A comma-separated list of dashboard IDs. Can be found by running the "grafana-dashboards-search" command. | False |
| Panel ID to fetch | See "help". | False |
| Alert name to fetch |  | False |
| States to fetch |  | False |
| Incident type |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### grafana-alerts-list
***
Gets alerts.


#### Base Command

`grafana-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dashboard_id | A comma-separated list of dashboard IDs by which to filter the results. | Optional | 
| panel_id | The ID of the panel by which to filter the results. | Optional | 
| name | Value that is contained in the alert's name by which to filter the results. | Optional | 
| state | A comma-separated list of states by which to filter the results. The options are: all, no_data, paused, alerting, ok, pending, unknown. | Optional | 
| limit | The maximum number of alerts to return. | Optional | 
| folder_id | A comma-separated list of folder IDs by which to filter the results. | Optional | 
| dashboard_name | Value that is contained in the dashboard's name by which to filter the results. | Optional | 
| dashboard_tag | A comma-separated list of dashboard tags by which to filter the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Alert.id | Number | Alert ID. | 
| Grafana.Alert.dashboardId | Number | Alert dashboard ID. | 
| Grafana.Alert.dashboardUid | String | Alert dashboard UID. | 
| Grafana.Alert.dashboardName | String | Alert dashboard name. | 
| Grafana.Alert.panelId | Number | Alert panel ID. | 
| Grafana.Alert.name | String | Alert name. | 
| Grafana.Alert.state | String | Alert state. | 
| Grafana.Alert.newStateDate | Date | The date on which the new alert state appeared. | 
| Grafana.Alert.evalDate | Date | The date the alert was evaluated. | 
| Grafana.Alert.evalData | Unknown | The metric that triggered the alert and made it change to the alerting state. | 
| Grafana.Alert.executionError | String | Alert execution error. | 
| Grafana.Alert.url | String | Alert URL. | 


#### Command Example
```!grafana-alerts-list```

#### Context Example
```json
{
    "Grafana": {
        "Alert": [
            {
                "dashboardId": 2,
                "dashboardName": "streaming2",
                "dashboardUid": "yzDQUOR7z",
                "evalData": {
                    "noData": true
                },
                "evalDate": "0001-01-01T00:00:00Z",
                "executionError": "",
                "id": 2,
                "name": "Adi's Alert",
                "newStateDate": "2021-09-30T15:43:20Z",
                "panelId": 5,
                "state": "unknown",
                "url": "https://base_url/d/yzDQUOR7z/streaming2"
            },
            {
                "dashboardId": 1,
                "dashboardName": "streaming",
                "dashboardUid": "TXSTREZ",
                "evalData": {
                    "noData": true
                },
                "evalDate": "0001-01-01T00:00:00Z",
                "executionError": "",
                "id": 1,
                "name": "Arseny's Alert",
                "newStateDate": "2021-06-09T15:20:01Z",
                "panelId": 4,
                "state": "no_data",
                "url": "https://base_url/d/TXSTREZ/streaming"
            },
            {
                "dashboardId": 2,
                "dashboardName": "streaming2",
                "dashboardUid": "yzDQUOR7z",
                "evalData": {
                    "noData": true
                },
                "evalDate": "0001-01-01T00:00:00Z",
                "executionError": "",
                "id": 3,
                "name": "TryAlert",
                "newStateDate": "2021-08-11T13:30:40Z",
                "panelId": 6,
                "state": "alerting",
                "url": "https://base_url/d/yzDQUOR7z/streaming2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Existing Alerts:
>|Id|Name|State|New State Date|Panel Id|Dashboard Id|Dashboard Uid|Dashboard Name|Url|
>|---|---|---|---|---|---|---|---|---|
>| 2 | Adi's Alert | no_data | 2021-09-30T15:43:20Z | 5 | 2 | yzDQUOR7z | streaming2 | [https://base_url/d/yzDQUOR7z/streaming2](https://base_url/d/yzDQUOR7z/streaming2) |
>| 1 | Arseny's Alert | no_data | 2021-06-09T15:20:01Z | 4 | 1 | TXSTREZ | streaming | [https://base_url/d/TXSTREZ/streaming](https://base_url/d/TXSTREZ/streaming) |
>| 3 | TryAlert | alerting | 2021-08-11T13:30:40Z | 6 | 2 | yzDQUOR7z | streaming2 | [https://base_url/d/yzDQUOR7z/streaming2](https://base_url/d/yzDQUOR7z/streaming2) |


### grafana-alert-pause
***
Pauses an alert by ID.


#### Base Command

`grafana-alert-pause`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | ID of the alert to pause. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Alert.id | Number | The ID of the alert that was paused. | 
| Grafana.Alert.state | String | The new state of the alert. | 


#### Command Example
```!grafana-alert-pause alert_id=2```

#### Context Example
```json
{
    "Grafana": {
        "Alert": {
            "id": 2,
            "message": "Alert paused",
            "state": "paused"
        }
    }
}
```

#### Human Readable Output

>### Paused Alert 2:
>|Id|Message|State|
>|---|---|---|
>| 2 | Alert paused | paused |


### grafana-alert-unpause
***
Unpauses an alert by ID.


#### Base Command

`grafana-alert-unpause`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | ID of the alert to unpause. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Alert.id | Number | The ID of the alert that was unpaused. | 
| Grafana.Alert.state | String | The new state of the alert. | 


#### Command Example
```!grafana-alert-unpause alert_id=2```

#### Context Example
```json
{
    "Grafana": {
        "Alert": {
            "id": 2,
            "message": "Alert un-paused",
            "state": "unknown"
        }
    }
}
```

#### Human Readable Output

>### Un-paused Alert 2:
>|Id|Message|State|
>|---|---|---|
>| 2 | Alert un-paused | unknown |


### grafana-users-search
***
Gets users.


#### Base Command

`grafana-users-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| perpage | Number of results to return per page. | Optional | 
| page | Index of the page of results to retrieve. | Optional | 
| query | The value contained in either the name, login, or email fields by which to filter the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.User.id | Number | User ID. | 
| Grafana.User.name | String | User name. | 
| Grafana.User.login | String | User login. | 
| Grafana.User.email | String | User email. | 
| Grafana.User.avatarUrl | String | User avatar URL. | 
| Grafana.User.isAdmin | Boolean | Is user an admin? | 
| Grafana.User.isDisabled | Boolean | Is user disabled? | 
| Grafana.User.lastSeenAt | Date | The date the user was last seen. | 
| Grafana.User.lastSeenAtAge | String | When the user was last seen in minutes \(m\), years \(Y\), month \(M\), days \(d\), etc. | 
| Grafana.User.authLabels | Unknown | User authentication labels | 


#### Command Example
```!grafana-users-search```

#### Context Example
```json
{
    "Grafana": {
        "User": [
            {
                "authLabels": [],
                "avatarUrl": "https://base_url/avatar/5d9c68c6c50ed3d02a2fcf54f63993b",
                "email": "User@mail",
                "id": 1,
                "isAdmin": true,
                "isDisabled": false,
                "lastSeenAt": "2021-10-04T15:25:40Z",
                "lastSeenAtAge": "4m",
                "login": "admin",
                "name": "admin"
            },
            {
                "authLabels": [],
                "avatarUrl": "https://base_url/avatar/04501192ea3453723d1336c6520ce2c",
                "email": "xadmin",
                "id": 2,
                "isAdmin": false,
                "isDisabled": false,
                "lastSeenAt": "2021-09-29T12:47:23Z",
                "lastSeenAtAge": "5d",
                "login": "xadmin",
                "name": "xadmin"
            }
        ]
    }
}
```

#### Human Readable Output

>### Existing Users:
>|Id|Email|Name|Login|Is Admin|Is Disabled|Avatar Url|Last Seen At|Last Seen At Age|
>|---|---|---|---|---|---|---|---|---|
>| 1 | User@mail | admin | admin | true | false | [https://base_url/avatar/5d9c68c6c50ed3d02a2fcf54f63993b](https://base_url/avatar/5d9c68c6c50ed3d02a2fcf54f63993b) | 2021-10-04T15:25:40Z | 4m |
>| 2 | xadmin | xadmin | xadmin | false | false | [https://base_url/avatar/04501192ea3453723d1336c6520ce2c](https://base_url/avatar/04501192ea3453723d1336c6520ce2c) | 2021-09-29T12:47:23Z | 5d |
>| 3 | test@test | User3 | User | false | false | [https://base_url/avatar/46d229b033af06a191ff2267bca9ae5](https://base_url/avatar/46d229b033af06a191ff2267bca9ae5) | 2011-07-27T15:10:37Z | 10y |


### grafana-user-teams-get
***
Gets the user's teams by user ID.


#### Base Command

`grafana-user-teams-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | ID of user for whom to get teams. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.User.id | Number | User ID. | 
| Grafana.User.teams.id | Number | Team ID. | 
| Grafana.User.teams.orgId | Number | Team organization ID. | 
| Grafana.User.teams.name | String | Team name. | 
| Grafana.User.teams.email | String | Team email. | 
| Grafana.User.teams.avatarUrl | String | Team avatar URL. | 
| Grafana.User.teams.memberCount | Number | Team member count. | 
| Grafana.User.teams.permission | Number | Number of team permissions. | 


#### Command Example
```!grafana-user-teams-get user_id=1```

#### Context Example
```json
{
    "Grafana": {
        "User": {
            "id": "1",
            "teams": [
                {
                    "avatarUrl": "https://base_url/avatar/f1f97cfa3c828a7352da671a",
                    "email": "team@test.com",
                    "id": 15,
                    "memberCount": 1,
                    "name": "Test Team",
                    "orgId": 1,
                    "permission": 0
                },
                {
                    "avatarUrl": "https://base_url/avatar/1d3226029e424011bffde2f",
                    "email": "test2@test.com",
                    "id": 16,
                    "memberCount": 2,
                    "name": "TestTeam2",
                    "orgId": 1,
                    "permission": 0
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Teams For User 1:
>|Id|Org Id|Name|Email|Avatar Url|Member Count|Permission|
>|---|---|---|---|---|---|---|
>| 15 | 1 | Test Team | team@test.com | [https://base_url/avatar/f1f97cfa3c828a7352da671a](https://base_url/avatar/f1f97cfa3c828a7352da671a) | 1 | 0 |
>| 16 | 1 | TestTeam2 | test2@test.com | [https://base_url/avatar/1d3226029e424011bffde2f](https://base_url/avatar/1d3226029e424011bffde2f) | 2 | 0 |


### grafana-user-orgs-get
***
Gets user's organizations by user ID.


#### Base Command

`grafana-user-orgs-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | ID of user for whom to get the organizations. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.User.id | Number | User ID. | 
| Grafana.User.orgs.orgId | Number | Organization ID. | 
| Grafana.User.orgs.name | String | Organization name. | 
| Grafana.User.orgs.role | String | Organization role. | 


#### Command Example
```!grafana-user-orgs-get user_id=1```

#### Context Example
```json
{
    "Grafana": {
        "User": {
            "id": "1",
            "orgs": [
                {
                    "name": "Main Org.",
                    "orgId": 1,
                    "role": "Admin"
                },
                {
                    "name": "New Org.",
                    "orgId": 2,
                    "role": "Admin"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Organizations For User 1:
>|Name|Org Id|Role|
>|---|---|---|
>| Main Org. | 1 | Admin |
>| New Org. | 2 | Admin |


### grafana-user-update
***
Updates a user by user ID. Login or email is mandatory. If you change your own login information, you won't be able to continue querying as your username (login) will change. Login and email should be unique.


#### Base Command

`grafana-user-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | User email. If email is not specified, login must be specified. | Optional | 
| name | User's name. | Optional | 
| login | User login (username). If login is not specified, email must be specified. | Optional | 
| theme | User theme when using Grafana's interface. Possilble values: "light" or "dark". Possible values are: light, dark. | Optional | 
| user_id | User ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-user-update user_id=3 email=TestUser login=TestUser name=TestUser```

#### Human Readable Output

>### Successfully Updated User 3:
>|Message|
>|---|
>| User updated |


### grafana-annotation-create
***
Creates an annotation in the Grafana database. The dashboard_id and panel_id fields are optional. If they are not specified, a global annotation is created and can be queried in any dashboard that adds the Grafana annotations data source. When creating a region annotation include the time_end property.


#### Base Command

`grafana-annotation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dashboard_id | Dashboard ID. | Optional | 
| panel_id | Panel ID. | Optional | 
| time | Start time. | Optional | 
| time_end | End time. | Optional | 
| tags | A comma-separated list of tags by which to filter the dashboards to add the annotation to. | Optional | 
| text | Text of the annotation. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Annotation.id | Number | Annotation ID. | 


#### Command Example
```!grafana-annotation-create text="annotate"```

#### Context Example
```json
{
    "Grafana": {
        "Annotation": {
            "id": 266,
            "message": "Annotation added"
        }
    }
}
```

#### Human Readable Output

>### Successfully Created Annotation 266:
>|Id|Message|
>|---|---|
>| 266 | Annotation added |


### grafana-teams-search
***
Gets teams.


#### Base Command

`grafana-teams-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| perpage | Number of results to return on a page. | Optional | 
| page | Index of the page of results to retrieve. | Optional | 
| query | The value contained in the name of a team. | Optional | 
| name | The exact name of the team. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Team.id | Number | Team ID. | 
| Grafana.Team.orgId | Number | Team organization ID. | 
| Grafana.Team.name | String | Team name. | 
| Grafana.Team.email | String | Team email. | 
| Grafana.Team.avatarUrl | String | Team avatar URL. | 
| Grafana.Team.memberCount | Number | The number of team members. | 
| Grafana.Team.permission | Number | Number of team permissions. | 


#### Command Example
```!grafana-teams-search```

#### Context Example
```json
{
    "Grafana": {
        "Team": [
            {
                "avatarUrl": "https://base_url/avatar/f1f97cfa3c828a7352da671a",
                "email": "team@test.com",
                "id": 15,
                "memberCount": 1,
                "name": "Test Team",
                "orgId": 1,
                "permission": 0
            },
            {
                "avatarUrl": "https://base_url/avatar/1d3226029e424011bffde2f",
                "email": "test2@test.com",
                "id": 16,
                "memberCount": 2,
                "name": "TestTeam2",
                "orgId": 1,
                "permission": 0
            },
            {
                "avatarUrl": "https://base_url/avatar/71cc610bc4841e3444235f09d9c",
                "email": "email@test.com",
                "id": 144,
                "memberCount": 0,
                "name": "Elia",
                "orgId": 1,
                "permission": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Teams Search Results:
>|Id|Org Id|Name|Email|Avatar Url|Member Count|Permission|
>|---|---|---|---|---|---|---|
>| 15 | 1 | Test Team | team@test.com | [https://base_url/avatar/f1f97cfa3c828a7352da671a](https://base_url/avatar/f1f97cfa3c828a7352da671a) | 1 | 0 |
>| 16 | 1 | TestTeam2 | test2@test.com | [https://base_url/avatar/1d3226029e424011bffde2f](https://base_url/avatar/1d3226029e424011bffde2f) | 2 | 0 |
>| 144 | 1 | Elia | email@test.com | [https://base_url/avatar/71cc610bc4841e3444235f09d9c](https://base_url/avatar/71cc610bc4841e3444235f09d9c) | 0 | 0 |


### grafana-team-members-list
***
Gets a list of all team members by team ID.


#### Base Command

`grafana-team-members-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | Team ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Team.id | Number | Team ID. | 
| Grafana.Team.members.orgId | Number | Member organization ID. | 
| Grafana.Team.members.teamId | Number | Member team ID. | 
| Grafana.Team.members.userId | Number | Member user ID. | 
| Grafana.Team.members.auth_module | String | Member authentication module. | 
| Grafana.Team.members.email | String | Member email. | 
| Grafana.Team.members.name | String | Member name. | 
| Grafana.Team.members.login | String | Member login. | 
| Grafana.Team.members.avatarUrl | String | Member avatar URL. | 
| Grafana.Team.members.labels | Unknown | Member labels. | 
| Grafana.Team.members.permission | Number | Member permission. | 


#### Command Example
```!grafana-team-members-list team_id=15```

#### Context Example
```json
{
    "Grafana": {
        "Team": {
            "id": "15",
            "members": [
                {
                    "auth_module": "",
                    "avatarUrl": "https://base_url/avatar/5d9c68c6c50ed3d02a2fcf54f63993b",
                    "email": "User@mail",
                    "labels": [],
                    "login": "admin",
                    "name": "admin",
                    "orgId": 1,
                    "permission": 0,
                    "teamId": 15,
                    "userId": 1
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Team 15 Members:
>|Org Id|Team Id|User Id|Email|Name|Login|Avatar Url|Permission|
>|---|---|---|---|---|---|---|---|
>| 1 | 15 | 1 | User@mail | admin | admin | [https://base_url/avatar/5d9c68c6c50ed3d02a2fcf54f63993b](https://base_url/avatar/5d9c68c6c50ed3d02a2fcf54f63993b) | 0 |


### grafana-user-add-to-team
***
Adds a user to a team.


#### Base Command

`grafana-user-add-to-team`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID. | Required | 
| team_id | Team ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-user-add-to-team team_id=15 user_id=3```

#### Human Readable Output

>### Successfully Added User 3 to Team 15:
>|Message|
>|---|
>| Member added to Team |


### grafana-user-remove-from-team
***
Removes a user from a team.


#### Base Command

`grafana-user-remove-from-team`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | Team ID. | Required | 
| user_id | User ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-user-remove-from-team team_id=15 user_id=3```

#### Human Readable Output

>### Successfully Removed User 3 from Team 15:
>|Message|
>|---|
>| Team Member removed |


### grafana-team-add
***
Creates a new team.


#### Base Command

`grafana-team-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The team name. Must be unique. | Required | 
| email | Email address of the team. | Optional | 
| org_id | Organization ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Team.id | Number | Team ID. | 


#### Command Example
```!grafana-team-add name="TestTeam4"```

#### Context Example
```json
{
    "Grafana": {
        "Team": {
            "id": 153,
            "message": "Team created"
        }
    }
}
```

#### Human Readable Output

>### Successfully Created Team 153:
>|Message|Team Id|
>|---|---|
>| Team created | 153 |


### grafana-team-delete
***
Deletes a team.


#### Base Command

`grafana-team-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | Team ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-team-delete team_id=152```

#### Human Readable Output

>### Successfully Deleted Team 152:
>|Message|
>|---|
>| Team deleted |


### grafana-org-create
***
Creates an organization.


#### Base Command

`grafana-org-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the organization. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Organization.id | Number | Organization ID. | 


#### Command Example
```!grafana-org-create name="Organization"```

#### Context Example
```json
{
    "Grafana": {
        "Organization": {
            "id": 12,
            "message": "Organization created"
        }
    }
}
```

#### Human Readable Output

>### Successfully Created Organization 12:
>|Message|Org Id|
>|---|---|
>| Organization created | 12 |


### grafana-dashboards-search
***
Searches dashboards.


#### Base Command

`grafana-dashboards-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Value is contained in the name of the dashboard. | Optional | 
| tag | A comma-separated list of tags by which to filter the results. | Optional | 
| type | Type of the dashboard. Possible values: "dash-folder" and "dash-db". Possible values are: dash-folder, dash-db. | Optional | 
| dashboard_ids | A comma-separated list of dashboard IDs by which to filter the results. | Optional | 
| folder_ids | A comma-separated list of folder IDs by which to filter the results. | Optional | 
| starred | Whether to only return starred dashboards. Possible values: "true" and "false". Possible values are: true, false. | Optional | 
| limit | The maximum number of dashboards to return. | Optional | 
| page | Page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Dashboard.id | Number | Dashboard ID. | 
| Grafana.Dashboard.uid | String | Dashboard UID. | 
| Grafana.Dashboard.title | String | Dashboard title. | 
| Grafana.Dashboard.uri | String | Dashboard URI. | 
| Grafana.Dashboard.url | String | Dashboard URL | 
| Grafana.Dashboard.slug | String | Dashboard slug. | 
| Grafana.Dashboard.type | String | Dashboard type. | 
| Grafana.Dashboard.tags | Unknown | Dashboard tags. | 
| Grafana.Dashboard.isStarred | Boolean | Is dashboard starred? | 


#### Command Example
```!grafana-dashboards-search```

#### Context Example
```json
{
    "Grafana": {
        "Dashboard": [
            {
                "id": 1,
                "isStarred": true,
                "slug": "",
                "tags": [],
                "title": "Streaming",
                "type": "dash-db",
                "uid": "TXSTREZ",
                "uri": "db/streaming",
                "url": "https://base_url/d/TXSTREZ/streaming"
            },
            {
                "id": 2,
                "isStarred": false,
                "slug": "",
                "tags": [
                    "tag1"
                ],
                "title": "Streaming Simple",
                "type": "dash-db",
                "uid": "yzDQUOR7z",
                "uri": "db/streaming2",
                "url": "https://base_url/d/yzDQUOR7z/streaming2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Existing Dashboards:
>|Id|Uid|Title|Is Starred|Tags|Uri|Url|Type|Sort Meta|
>|---|---|---|---|---|---|---|---|---|
>| 1 | TXSTREZ | Streaming | true |  | db/streaming | [https://base_url/d/TXSTREZ/streaming](https://base_url/d/TXSTREZ/streaming) | dash-db | 0 |
>| 2 | yzDQUOR7z | Streaming Simple | false | tag1 | db/streaming2 | [https://base_url/d/yzDQUOR7z/streaming2](https://base_url/d/yzDQUOR7z/streaming2) | dash-db | 0 |


### grafana-user-get-by-id
***
Gets a user by ID.


#### Base Command

`grafana-user-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.User.id | Number | User ID. | 
| Grafana.User.email | String | User email. | 
| Grafana.User.name | String | User name. | 
| Grafana.User.login | String | User login. | 
| Grafana.User.theme | String | User theme. | 
| Grafana.User.orgId | Number | Organization ID. | 
| Grafana.User.isGrafanaAdmin | Boolean | Is user a Grafana admin? | 
| Grafana.User.isDisabled | Boolean | Is user disabled? | 
| Grafana.User.isExternal | Boolean | Is user external? | 
| Grafana.User.updatedAt | Date | Date when user was updated. | 
| Grafana.User.createdAt | Date | Date when user was created. | 
| Grafana.User.avatarUrl | String | User avatar URL. | 
| Grafana.User.authLabels | Unknown | User authentication labels. | 


#### Command Example
```!grafana-user-get-by-id user_id=1```

#### Context Example
```json
{
    "Grafana": {
        "User": {
            "authLabels": [],
            "avatarUrl": "/avatar/46d229b033af06a191ff2267bca9ae5",
            "createdAt": "2021-06-08T10:57:39Z",
            "email": "User@mail",
            "id": 1,
            "isDisabled": false,
            "isExternal": false,
            "isGrafanaAdmin": true,
            "login": "admin",
            "name": "admin",
            "orgId": 1,
            "theme": "light",
            "updatedAt": "2021-09-30T14:46:22Z"
        }
    }
}
```

#### Human Readable Output

>### User 1 Results:
>|Id|Email|Name|Login|Theme|Org Id|Is Grafana Admin|Is D Is abled|Is External|Updated At|Created At|Avatar Url|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | User@mail | admin | admin | light | 1 | true | false | false | 2021-09-30T14:46:22Z | 2021-06-08T10:57:39Z | [https://base_url/avatar/46d229b033af06a191ff2267bca9ae5](https://base_url/avatar/46d229b033af06a191ff2267bca9ae5) |


### grafana-team-get-by-id
***
Gets a team by ID.


#### Base Command

`grafana-team-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | Team ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Team.id | Number | Team ID. | 
| Grafana.Team.orgId | Number | Team organization ID. | 
| Grafana.Team.name | String | Team name. | 
| Grafana.Team.email | String | Team email. | 
| Grafana.Team.avatarUrl | String | Team avatar URL. | 
| Grafana.Team.memberCount | Number | The number of team members. | 
| Grafana.Team.permission | Number | Number of team permissions. | 


#### Command Example
```!grafana-team-get-by-id team_id=15```

#### Context Example
```json
{
    "Grafana": {
        "Team": {
            "avatarUrl": "https://base_url/avatar/f1f97cfa3c828a7352da671a",
            "email": "team@test.com",
            "id": 15,
            "memberCount": 1,
            "name": "Test Team",
            "orgId": 1,
            "permission": 0
        }
    }
}
```

#### Human Readable Output

>### Team 15 Results:
>|Id|Org Id|Name|Email|Avatar Url|Member Count|Permission|
>|---|---|---|---|---|---|---|
>| 15 | 1 | Test Team | team@test.com | [https://base_url/avatar/f1f97cfa3c828a7352da671a](https://base_url/avatar/f1f97cfa3c828a7352da671a) | 1 | 0 |


### grafana-alert-get-by-id
***
Gets an alert by id.


#### Base Command

`grafana-alert-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Alert.id | Number | Alert ID. | 
| Grafana.Alert.version | Number | Alert version. | 
| Grafana.Alert.orgId | Number | Alert organization ID. | 
| Grafana.Alert.dashboardId | Number | Alert dashboard ID. | 
| Grafana.Alert.panelId | Number | Alert panel ID. | 
| Grafana.Alert.name | String | Alert name. | 
| Grafana.Alert.message | String | Alert message. | 
| Grafana.Alert.severity | String | Alert severity. | 
| Grafana.Alert.state | String | Alert state. | 
| Grafana.Alert.handler | Number | Alert handler. | 
| Grafana.Alert.silenced | Boolean | Whether the alert was silenced. | 
| Grafana.Alert.executionError | String | Alert execution error. | 
| Grafana.Alert.frequency | Number | Alert frequency in seconds. | 
| Grafana.Alert.for | Number | Once the alert rule has been firing for more than this duration in nanoseconds, then the alert changes to "Alerting". Otherwise it goes from "OK" to "Pending". | 
| Grafana.Alert.evalData | Unknown | The metric that triggered the alert and made it change to the "Alerting" state. | 
| Grafana.Alert.newStateDate | Date | The date of the alert's new state. | 
| Grafana.Alert.stateChanges | Number | The number of time the alert state changes. | 
| Grafana.Alert.created | Date | Date the alert was created. | 
| Grafana.Alert.updated | Date | Date the alert was updated. | 
| Grafana.Alert.settings | Unknown | Alert settings. | 


#### Command Example
```!grafana-alert-get-by-id alert_id=1```

#### Context Example
```json
{
    "Grafana": {
        "Alert": {
            "created": "2021-06-09T15:13:45Z",
            "dashboardId": 1,
            "evalData": {
                "noData": true
            },
            "executionError": " ",
            "for": 60000000000,
            "frequency": 600,
            "handler": 1,
            "id": 1,
            "message": "man down!",
            "name": "Arseny's Alert",
            "newStateDate": "2021-06-09T15:20:01Z",
            "orgId": 1,
            "panelId": 4,
            "settings": {
                "alertRuleTags": {
                    "moshe": "2"
                },
                "conditions": [
                    {
                        "evaluator": {
                            "params": [
                                10
                            ],
                            "type": "gt"
                        },
                        "operator": {
                            "type": "and"
                        },
                        "query": {
                            "datasourceId": 1,
                            "model": {
                                "refId": "A",
                                "scenarioId": "streaming_client",
                                "stream": {
                                    "noise": 2.2,
                                    "speed": 100,
                                    "spread": 3.5,
                                    "type": "signal"
                                },
                                "stringInput": ""
                            },
                            "params": [
                                "A",
                                "5m",
                                "now"
                            ]
                        },
                        "reducer": {
                            "params": [],
                            "type": "avg"
                        },
                        "type": "query"
                    }
                ],
                "executionErrorState": "alerting",
                "for": "1m",
                "frequency": "10m",
                "handler": 1,
                "message": "man down!",
                "name": "Arseny's Alert",
                "noDataState": "no_data",
                "notifications": []
            },
            "severity": "",
            "silenced": false,
            "state": "no_data",
            "stateChanges": 1,
            "updated": "2021-06-09T15:14:51Z",
            "version": 0
        }
    }
}
```

#### Human Readable Output

>### Alert 1 Results:
>|Id|Version|Org Id|Dashboard Id|Panel Id|Name|Message|State|New State Date|State Changes|Handler|Silenced|Frequency|For|Created|Updated|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | 0 | 1 | 1 | 4 | Arseny's Alert | man down! | no_data | 2021-06-09T15:20:01Z | 1 | 1 | false | 600 | 60000000000 | 2021-06-09T15:13:45Z | 2021-06-09T15:14:51Z |


### grafana-org-list
***
Gets organizations.


#### Base Command

`grafana-org-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| perpage | Number of results to return on a page. | Optional | 
| page | Index of the page of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Organization.id | Number | Organization ID. | 
| Grafana.Organization.name | String | Organization name. | 


#### Command Example
```!grafana-org-list```

#### Context Example
```json
{
    "Grafana": {
        "Organization": [
            {
                "id": 1,
                "name": "Main Org."
            },
            {
                "id": 2,
                "name": "New Org."
            },
            {
                "id": 12,
                "name": "Organization"
            }
        ]
    }
}
```

#### Human Readable Output

>### Existing Organizations:
>|Id|Name|
>|---|---|
>| 1 | Main Org. |
>| 2 | New Org. |
>| 12 | Organization |


### grafana-org-get-by-name
***
Gets an organization by name.


#### Base Command

`grafana-org-get-by-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The exact name of the organization to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Organization.id | Number | Organization ID. | 
| Grafana.Organization.name | String | Organization name. | 
| Grafana.Organization.address | Unknown | Organization address. | 


#### Command Example
```!grafana-org-get-by-name name="Main Org."```

#### Context Example
```json
{
    "Grafana": {
        "Organization": {
            "address": {
                "address1": "",
                "address2": "",
                "city": "",
                "country": "",
                "state": "",
                "zipCode": ""
            },
            "id": 1,
            "name": "Main Org."
        }
    }
}
```

#### Human Readable Output

>### Organization "Main Org." Results:
>|Name|Id|Address|
>|---|---|---|
>| Main Org. | 1 | address1: <br/>address2: <br/>city: <br/>zipCode: <br/>state: <br/>country:  |


### grafana-org-get-by-id
***
Gets an organization by ID.


#### Base Command

`grafana-org-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Organization.id | Number | Organization ID. | 
| Grafana.Organization.name | String | Organization name. | 
| Grafana.Organization.address | Unknown | Organization address. | 


#### Command Example
```!grafana-org-get-by-id org_id=1```

#### Context Example
```json
{
    "Grafana": {
        "Organization": {
            "address": {
                "address1": "",
                "address2": "",
                "city": "",
                "country": "",
                "state": "",
                "zipCode": ""
            },
            "id": 1,
            "name": "Main Org."
        }
    }
}
```

#### Human Readable Output

>### Organization 1 Results:
>|Id|Name|Address|
>|---|---|---|
>| 1 | Main Org. | address1: <br/>address2: <br/>city: <br/>zipCode: <br/>state: <br/>country:  |
