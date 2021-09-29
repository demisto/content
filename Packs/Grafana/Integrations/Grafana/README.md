Grafana alerting service
This integration was integrated and tested with version 8.0.0 of Grafana

## Configure Grafana on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Grafana.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Username |  | True |
    | Password |  | True |
    | Maximum number of incidents to fetch | maximum is limited to 200 | False |
    | Fetch incidents |  | False |
    | First Fetch Time of Alerts |  | False |
    | Dashboard Id to fetch |  | False |
    | Panel Id to fetch |  | False |
    | Alert name to fetch |  | False |
    | State to fetch |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### grafana-alerts-list
***
Gets alerts.


#### Base Command

`grafana-alerts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dashboard_id | A comma-separated list of dashboard ids by which to filter the results. | Optional | 
| panel_id | Panel id by which to filter the results. | Optional | 
| query | Limit response to alerts having a name like this value. | Optional | 
| state | A comma-separated list of states by which to filter the results. The options are: all, no_data, paused, alerting, ok, pending. | Optional | 
| limit | The maximum number of alerts to return. | Optional | 
| folder_id | A comma-separated list of folder ids by which to filter the results. | Optional | 
| dashboard_query | Dashboard's name by which to filter the results. | Optional | 
| dashboard_tag | A comma-separated list of dashboard tags by which to filter the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Alert.id | Number | Alert id | 
| Grafana.Alert.dashboardId | Number | Alert dashboard id | 
| Grafana.Alert.dashboardUid | String | Alert dashboard uid | 
| Grafana.Alert.dashboardName | String | Alert dashboard name | 
| Grafana.Alert.panelId | Number | Alert panel id | 
| Grafana.Alert.name | String | Alert name | 
| Grafana.Alert.state | String | Alert state | 
| Grafana.Alert.newStateDate | Date | Alert new state date | 
| Grafana.Alert.evalDate | Date | Alert eval date | 
| Grafana.Alert.evalData | Unknown | Alert eval data | 
| Grafana.Alert.executionError | String | Alert execution error | 
| Grafana.Alert.url | String | Alert url | 


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
                "evalDate": "01-01-01T::Z",
                "executionError": "",
                "id": 2,
                "name": "Adi's Alert",
                "newStateDate": "2021-07-27T15:27:33.326964015Z",
                "panelId": 5,
                "state": "unknown",
                "url": "https://www.url/d/yzDQUOR7z/streaming2"
            },
            {
                "dashboardId": 1,
                "dashboardName": "streaming",
                "dashboardUid": "TXSTREZ",
                "evalData": {
                    "noData": true
                },
                "evalDate": "01-01-01T::Z",
                "executionError": "",
                "id": 1,
                "name": "Arseny's Alert",
                "newStateDate": "2021-06-09T15:20:01Z",
                "panelId": 4,
                "state": "no_data",
                "url": "https://www.url/d/TXSTREZ/streaming"
            },
            {
                "dashboardId": 2,
                "dashboardName": "streaming2",
                "dashboardUid": "yzDQUOR7z",
                "evalData": {
                    "noData": true
                },
                "evalDate": "01-01-01T::Z",
                "executionError": "",
                "id": 3,
                "name": "TryAlert",
                "newStateDate": "2021-07-08T12:08:40Z",
                "panelId": 6,
                "state": "alerting",
                "url": "https://www.url/d/yzDQUOR7z/streaming2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Alerts
>|Dashboard Id|Dashboard Slug|Dashboard Uid|Eval Data|Eval Date|Id|Name|New State Date|Panel Id|State|Url|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2 | streaming2 | yzDQUOR7z | noData: true | 01-01-01T::Z | 2 | Adi's Alert | 2021-07-27T15:27:33.326964015Z | 5 | unknown | https://www.url/d/yzDQUOR7z/streaming2 |
>| 1 | streaming | TXSTREZ | noData: true | 01-01-01T::Z | 1 | Arseny's Alert | 2021-06-09T15:20:01Z | 4 | no_data | https://www.url/d/TXSTREZ/streaming |
>| 2 | streaming2 | yzDQUOR7z | noData: true | 01-01-01T::Z | 3 | TryAlert | 2021-07-08T12:08:40Z | 6 | alerting | https://www.url/d/yzDQUOR7z/streaming2 |


### grafana-alert-pause
***
Pauses an alert by id.


#### Base Command

`grafana-alert-pause`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert id to pause. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Alert.id | Number | Alert id paused. | 
| Grafana.Alert.state | String | Alert's new state. | 


#### Command Example
```!grafana-alert-pause alert_id=2```

#### Context Example
```json
{
    "Grafana": {
        "Alert": {
            "id": 2,
            "state": "paused"
        }
    }
}
```

#### Human Readable Output

>### Paused Alert
>|Alert Id|Message|State|
>|---|---|---|
>| 2 | Alert paused | paused |


### grafana-alert-unpause
***
Unpauses an alert by id.


#### Base Command

`grafana-alert-unpause`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert id to unpause. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Alert.id | Number | Alert id paused. | 
| Grafana.Alert.state | String | Alert's new state. | 


#### Command Example
```!grafana-alert-unpause alert_id=2```

#### Context Example
```json
{
    "Grafana": {
        "Alert": {
            "id": 2,
            "state": "unknown"
        }
    }
}
```

#### Human Readable Output

>### Un-paused Alerts
>|Alert Id|Message|State|
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
| perpage | Number of results wanted in one page. | Optional | 
| page | Index of page of results wanted. | Optional | 
| query | Value is contained in one of the name, login or email fields. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.User.id | Number | User id | 
| Grafana.User.name | String | User name | 
| Grafana.User.login | String | User login | 
| Grafana.User.email | String | User email | 
| Grafana.User.avatarUrl | String | User avatar url | 
| Grafana.User.isAdmin | Boolean | Is user admin? | 
| Grafana.User.isDisabled | Boolean | Is user disabled? | 
| Grafana.User.lastSeenAt | Date | User last seen at | 
| Grafana.User.lastSeenAtAge | String | User last seen at age | 


#### Command Example
```!grafana-users-search```

#### Context Example
```json
{
    "Grafana": {
        "User": [
            {
                "authLabels": [],
                "avatarUrl": "/avatar/5d9c68c6c50ed3d02a2fcf54f63993b",
                "email": "User",
                "id": 3,
                "isAdmin": false,
                "isDisabled": false,
                "lastSeenAt": "2011-07-27T15:10:37Z",
                "lastSeenAtAge": "1y",
                "login": "User",
                "name": "User"
            },
            {
                "authLabels": [],
                "avatarUrl": "/avatar/46d229b033af06a191ff2267bca9ae5",
                "email": "admin",
                "id": 1,
                "isAdmin": true,
                "isDisabled": false,
                "lastSeenAt": "2021-07-27T15:27:29Z",
                "lastSeenAtAge": "3m",
                "login": "admin",
                "name": "admin"
            },
            {
                "authLabels": [],
                "avatarUrl": "/avatar/04501192ea3453723d1336c6520ce2c",
                "email": "xadmin",
                "id": 2,
                "isAdmin": false,
                "isDisabled": false,
                "lastSeenAt": "2021-06-27T08:43:02Z",
                "lastSeenAtAge": "30d",
                "login": "xadmin",
                "name": "xadmin"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users
>|Avatar Url|Email|Id|Is Admin|Is Disabled|Last Seen At|Last Seen At Age|Login|Name|
>|---|---|---|---|---|---|---|---|---|
>| /avatar/5d9c68c6c50ed3d02a2fcf54f63993b | User | 3 | false | false | 2011-07-27T15:10:37Z | 1y | User | User |
>| /avatar/46d229b033af06a191ff2267bca9ae5 | admin | 1 | true | false | 2021-07-27T15:27:29Z | 3m | admin | admin |
>| /avatar/04501192ea3453723d1336c6520ce2c | xadmin | 2 | false | false | 2021-06-27T08:43:02Z | 30d | xadmin | xadmin |


### grafana-user-teams-get
***
Gets the user's teams by user id.


#### Base Command

`grafana-user-teams-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User id to get teams for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.User.id | Number | user id | 
| Grafana.User.teams.id | Number | Team id | 
| Grafana.User.teams.orgId | Number | Team organization id | 
| Grafana.User.teams.name | String | Team name | 
| Grafana.User.teams.email | String | Team email | 
| Grafana.User.teams.avatarUrl | String | Team avatar url | 
| Grafana.User.teams.memberCount | Number | Team member count | 
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
                    "avatarUrl": "/avatar/1d3226029ef0424011bf63ffde2f",
                    "email": "",
                    "id": 2,
                    "memberCount": 2,
                    "name": "MyTestTeam2",
                    "orgId": 1,
                    "permission": 0
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Teams For User
>|Avatar Url|Id|Member Count|Name|Org Id|Permission|
>|---|---|---|---|---|---|
>| /avatar/1d3226029ef0424011bf63ffde2f | 2 | 2 | MyTestTeam2 | 1 | 0 |


### grafana-user-orgs-get
***
Gets user's organizations by user id.


#### Base Command

`grafana-user-orgs-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.User.id | Number | User id | 
| Grafana.User.orgs.orgId | Number | Organization id | 
| Grafana.User.orgs.name | String | Organization name | 
| Grafana.User.orgs.role | String | Organization role | 


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
                },
                {
                    "name": "New Org.1",
                    "orgId": 3,
                    "role": "Admin"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Organization For User
>|Name|Org Id|Role|
>|---|---|---|
>| Main Org. | 1 | Admin |
>| New Org. | 2 | Admin |
>| New Org.1 | 3 | Admin |


### grafana-user-update
***
Login or name is mandatory. Pay attantion that if you change your own login information, you won't be able to continue quering.


#### Base Command

`grafana-user-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | User email. | Optional | 
| name | User name. | Optional | 
| login | username. | Optional | 
| theme | User theme. Possible values are: light, dark. | Optional | 
| user_id | User id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-user-update user_id=3 email=User login=User name=User```

#### Human Readable Output

>User updated

### grafana-annotation-create
***
Creates annotation.


#### Base Command

`grafana-annotation-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dashboard_id | Dashboard id. | Optional | 
| panel_id | Panel id. | Optional | 
| time | Time. | Optional | 
| time_end | End time. | Optional | 
| tags | A comma-separated list of tags by which to filter the results. | Optional | 
| text | Text. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-annotation-create text="annotate"```

#### Human Readable Output

>Annotation 33 Added

### grafana-teams-search
***
Gets teams.


#### Base Command

`grafana-teams-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| perpage | Number of results wanted in one page. | Optional | 
| page | Index of page of results wanted. | Optional | 
| query | Contained in the name of a team. | Optional | 
| name | The name of the team. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Team.id | Number | Team id | 
| Grafana.Team.orgId | Number | Team organization id | 
| Grafana.Team.name | String | Team name | 
| Grafana.Team.email | String | Team email | 
| Grafana.Team.avatarUrl | String | Team avatar url | 
| Grafana.Team.memberCount | Number | Team member count | 
| Grafana.Team.permission | Number | Number of team permissions | 


#### Command Example
```!grafana-teams-search```

#### Context Example
```json
{
    "Grafana": {
        "Team": [
            {
                "avatarUrl": "/avatar/f1f97cfa3c828a7352da671a",
                "email": "email@test.com",
                "id": 1,
                "memberCount": 0,
                "name": "MyTestTeam",
                "orgId": 1,
                "permission": 0
            },
            {
                "avatarUrl": "/avatar/1d3226029ef0424011bf63ffde2f",
                "email": "",
                "id": 2,
                "memberCount": 2,
                "name": "MyTestTeam2",
                "orgId": 1,
                "permission": 0
            },
            {
                "avatarUrl": "/avatar/f1f97cfa3c828a7352da671a",
                "email": "email@test.com",
                "id": 5,
                "memberCount": 1,
                "name": "MyTestTeam4",
                "orgId": 1,
                "permission": 0
            },
            {
                "avatarUrl": "/avatar/f1f97cfa3c828a7352da671a",
                "email": "email@test.com",
                "id": 7,
                "memberCount": 0,
                "name": "MyTestTeam6",
                "orgId": 1,
                "permission": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Teams
>|Avatar Url|Email|Id|Member Count|Name|Org Id|Permission|
>|---|---|---|---|---|---|---|
>| /avatar/f1f97cfa3c828a7352da671a | email@test.com | 1 | 0 | MyTestTeam | 1 | 0 |
>| /avatar/1d3226029ef0424011bf63ffde2f |  | 2 | 2 | MyTestTeam2 | 1 | 0 |
>| /avatar/f1f97cfa3c828a7352da671a | email@test.com | 5 | 1 | MyTestTeam4 | 1 | 0 |
>| /avatar/f1f97cfa3c828a7352da671a | email@test.com | 7 | 0 | MyTestTeam6 | 1 | 0 |


### grafana-team-members-list
***
Gets a list of all team members by team id.


#### Base Command

`grafana-team-members-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | Team id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Team.id | Number | Team id | 
| Grafana.Team.members.orgId | Number | Member organization id | 
| Grafana.Team.members.teamId | Number | Member team id | 
| Grafana.Team.members.userId | Number | Member user id | 
| Grafana.Team.members.auth_module | String | Member authentication module | 
| Grafana.Team.members.email | String | Member email | 
| Grafana.Team.members.name | String | Member name | 
| Grafana.Team.members.login | String | Member login | 
| Grafana.Team.members.avatarUrl | String | Member avatar url | 
| Grafana.Team.members.labels | Unknown | Member labels | 
| Grafana.Team.members.permission | Number | Member permission | 


#### Command Example
```!grafana-team-members-list team_id=2```

#### Context Example
```json
{
    "Grafana": {
        "Team": {
            "id": "2",
            "members": [
                {
                    "auth_module": "",
                    "avatarUrl": "/avatar/46d229b033af06a191ff2267bca9ae5",
                    "email": "admin",
                    "labels": [],
                    "login": "admin",
                    "name": "admin",
                    "orgId": 1,
                    "permission": 0,
                    "teamId": 2,
                    "userId": 1
                },
                {
                    "auth_module": "",
                    "avatarUrl": "/avatar/04501192ea3453723d1336c6520ce2c",
                    "email": "xadmin",
                    "labels": [],
                    "login": "xadmin",
                    "name": "xadmin",
                    "orgId": 1,
                    "permission": 0,
                    "teamId": 2,
                    "userId": 2
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Team Members
>|Avatar Url|Email|Login|Name|Org Id|Permission|Team Id|User Id|
>|---|---|---|---|---|---|---|---|
>| /avatar/46d229b033af06a191ff2267bca9ae5 | admin | admin | admin | 1 | 0 | 2 | 1 |
>| /avatar/04501192ea3453723d1336c6520ce2c | xadmin | xadmin | xadmin | 1 | 0 | 2 | 2 |


### grafana-user-add-to-team
***
Adds a user to a team.


#### Base Command

`grafana-user-add-to-team`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User id. | Required | 
| team_id | Team id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-user-add-to-team team_id=1 user_id=1```

#### Human Readable Output

>Member added to Team

### grafana-user-remove-from-team
***
Removes a user from a team.


#### Base Command

`grafana-user-remove-from-team`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | Team id. | Required | 
| user_id | User id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-user-remove-from-team team_id=1 user_id=1```

#### Human Readable Output

>Team Member removed

### grafana-team-add
***
Creates a new team.


#### Base Command

`grafana-team-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name. | Required | 
| email | Email. | Optional | 
| org_id | Organization id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Team.id | Number | Team id | 


#### Command Example
```!grafana-team-add name="TestTeam2"```

#### Context Example
```json
{
    "Grafana": {
        "Team": {
            "id": 10,
            "message": "Team created"
        }
    }
}
```

#### Human Readable Output

>### Added Team
>|Message|Team Id|
>|---|---|
>| Team created | 10 |


### grafana-team-delete
***
Deletes a team.


#### Base Command

`grafana-team-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | Team id. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!grafana-team-delete team_id=7```

#### Human Readable Output

>Team deleted

### grafana-org-create
***
Creats an organization.


#### Base Command

`grafana-org-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Organization.id | Number | Organization id | 


#### Command Example
```!grafana-org-create```

#### Context Example
```json
{
    "Grafana": {
        "Organization": {
            "id": 5,
            "message": "Organization created"
        }
    }
}
```

#### Human Readable Output

>### Added Organization
>|Message|Org Id|
>|---|---|
>| Organization created | 5 |


### grafana-dashboards-search
***
Searchs dashboards.


#### Base Command

`grafana-dashboards-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query. | Optional | 
| tag | A comma-separated list of tags by which to filter the results. | Optional | 
| type | Type. Possible values are: dash-folder, dash-db. | Optional | 
| dashboard_ids | A comma-separated list of dashboard IDs by which to filter the results. | Optional | 
| folder_ids | A comma-separated list of folder IDs by which to filter the results. | Optional | 
| starred | Indices if only starred dashboards should be returned. Possible values are: true, false. | Optional | 
| limit | The maximum number of dashboards to return. | Optional | 
| page | Page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Dashboard.id | Number | Dashboard id | 
| Grafana.Dashboard.uid | String | Dashboard uid | 
| Grafana.Dashboard.title | String | Dashboard title | 
| Grafana.Dashboard.uri | String | Dashboard uri | 
| Grafana.Dashboard.url | String | Dashboard url | 
| Grafana.Dashboard.slug | String | Dashboard slug | 
| Grafana.Dashboard.type | String | Dashboard type | 
| Grafana.Dashboard.tags | Unknown | Dashboard tags | 
| Grafana.Dashboard.isStarred | Boolean | Is dashboard starred? | 
| Grafana.Dashboard.sortMeta | Number | Dashboard sort meta | 


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
                "sortMeta": 0,
                "tags": [],
                "title": "Streaming",
                "type": "dash-db",
                "uid": "TXSTREZ",
                "uri": "db/streaming",
                "url": "https://www.url/d/TXSTREZ/streaming"
            },
            {
                "id": 2,
                "isStarred": false,
                "slug": "",
                "sortMeta": 0,
                "tags": [],
                "title": "Streaming Simple",
                "type": "dash-db",
                "uid": "yzDQUOR7z",
                "uri": "db/streaming2",
                "url": "https://www.url/d/yzDQUOR7z/streaming2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Dashboard
>|Id|Is Starred|Sort Meta|Title|Type|Uid|Uri|Url|
>|---|---|---|---|---|---|---|---|
>| 1 | true | 0 | Streaming | dash-db | TXSTREZ | db/streaming | https://www.url/d/TXSTREZ/streaming |
>| 2 | false | 0 | Streaming Simple | dash-db | yzDQUOR7z | db/streaming2 | https://www.url/d/yzDQUOR7z/streaming2 |


### grafana-user-get-by-id
***
Gets a user by id.


#### Base Command

`grafana-user-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.User.id | Number | User id | 
| Grafana.User.email | String | User email | 
| Grafana.User.name | String | User name | 
| Grafana.User.login | String | User login | 
| Grafana.User.theme | String | User theme | 
| Grafana.User.orgId | Number | Organization id | 
| Grafana.User.isGrafanaAdmin | Boolean | Is user Grafana admin? | 
| Grafana.User.isDisabled | Boolean | Is user disabled? | 
| Grafana.User.isExternal | Boolean | Is user external? | 
| Grafana.User.updatedAt | Date | User updated at | 
| Grafana.User.createdAt | Date | User created at | 
| Grafana.User.avatarUrl | String | User avatar url | 


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
            "email": "admin",
            "id": 1,
            "isDisabled": false,
            "isExternal": false,
            "isGrafanaAdmin": true,
            "login": "admin",
            "name": "admin",
            "orgId": 1,
            "theme": "dark",
            "updatedAt": "2021-07-08T11:13:45Z"
        }
    }
}
```

#### Human Readable Output

>### User
>|Avatar Url|Created At|Email|Id|Is D Is abled|Is External|Is Grafana Admin|Login|Name|Org Id|Theme|Updated At|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| /avatar/46d229b033af06a191ff2267bca9ae5 | 2021-06-08T10:57:39Z | admin | 1 | false | false | true | admin | admin | 1 | dark | 2021-07-08T11:13:45Z |


### grafana-team-get-by-id
***
Gets a team by id.


#### Base Command

`grafana-team-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | Team id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Team.id | Number | Team id | 
| Grafana.Team.orgId | Number | Team organization id | 
| Grafana.Team.name | String | Team name | 
| Grafana.Team.email | String | Team email | 
| Grafana.Team.avatarUrl | String | Team avatar url | 
| Grafana.Team.memberCount | Number | Team member count | 
| Grafana.Team.permission | Number | Number of team permissions | 


#### Command Example
```!grafana-team-get-by-id team_id=1```

#### Context Example
```json
{
    "Grafana": {
        "Team": {
            "avatarUrl": "/avatar/f1f97cfa3c828a7352da671a",
            "email": "email@test.com",
            "id": 1,
            "memberCount": 0,
            "name": "MyTestTeam",
            "orgId": 1,
            "permission": 0
        }
    }
}
```

#### Human Readable Output

>### Team
>|Avatar Url|Email|Id|Member Count|Name|Org Id|Permission|
>|---|---|---|---|---|---|---|
>| /avatar/f1f97cfa3c828a7352da671a | email@test.com | 1 | 0 | MyTestTeam | 1 | 0 |


### grafana-alert-get-by-id
***
Gets an alert by id.


#### Base Command

`grafana-alert-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Alert.id | Number | Alert id | 
| Grafana.Alert.version | Number | Alert version | 
| Grafana.Alert.orgId | Number | Alert organization id | 
| Grafana.Alert.dashboardId | Number | Alert dashboard id | 
| Grafana.Alert.panelId | Number | Alert panel id | 
| Grafana.Alert.name | String | Alert name | 
| Grafana.Alert.message | String | Alert message | 
| Grafana.Alert.severity | String | Alert severity | 
| Grafana.Alert.state | String | Alert state | 
| Grafana.Alert.handler | Number | Alert handler | 
| Grafana.Alert.silenced | Boolean | Alert eval data - silenced | 
| Grafana.Alert.executionError | String | Alert execution error | 
| Grafana.Alert.frequency | Number | Alert frequency | 
| Grafana.Alert.for | Number | Alert for | 
| Grafana.Alert.evalData | Unknown | Alert eval data | 
| Grafana.Alert.newStateDate | Date | Alert new state date | 
| Grafana.Alert.stateChanges | Number | Alert state changes | 
| Grafana.Alert.created | Date | Alert created | 
| Grafana.Alert.updated | Date | Alert updated | 
| Grafana.Alert.settings | Unknown | Alert settings | 


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
            "for": 6,
            "frequency": 6,
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
                                    "speed": 1,
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

>### Alert
>|Created|Dashboard Id|Eval Data|Execution Error|For|Frequency|Handler|Id|Message|Name|New State Date|Org Id|Panel Id|Settings|Silenced|State|State Changes|Updated|Version|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-06-09T15:13:45Z | 1 | noData: true |   | 6 | 6 | 1 | 1 | man down! | Arseny's Alert | 2021-06-09T15:20:01Z | 1 | 4 | alertRuleTags: {"moshe": "2"}<br/>conditions: {'evaluator': {'params': [10], 'type': 'gt'}, 'operator': {'type': 'and'}, 'query': {'datasourceId': 1, 'model': {'refId': 'A', 'scenarioId': 'streaming_client', 'stream': {'noise': 2.2, 'speed': 1, 'spread': 3.5, 'type': 'signal'}, 'stringInput': ''}, 'params': ['A', '5m', 'now']}, 'reducer': {'params': [], 'type': 'avg'}, 'type': 'query'}<br/>executionErrorState: alerting<br/>for: 1m<br/>frequency: 10m<br/>handler: 1<br/>message: man down!<br/>name: Arseny's Alert<br/>noDataState: no_data<br/>notifications:  | false | no_data | 1 | 2021-06-09T15:14:51Z | 0 |


### grafana-org-list
***
Gets organizations.


#### Base Command

`grafana-org-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| perpage | Number of results wanted in one page. | Optional | 
| page | Index of page of results wanted. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Organization.id | Number | Organization id | 
| Grafana.Organization.name | String | Organization name | 


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
                "id": 3,
                "name": "New Org.1"
            },
            {
                "id": 5,
                "name": "None"
            }
        ]
    }
}
```

#### Human Readable Output

>### Organization
>|Id|Name|
>|---|---|
>| 1 | Main Org. |
>| 2 | New Org. |
>| 3 | New Org.1 |
>| 5 | None |


### grafana-org-get-by-name
***
Gets an organization by name.


#### Base Command

`grafana-org-get-by-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Organization.id | Number | Organization id | 
| Grafana.Organization.name | String | Organization name | 
| Grafana.Organization.address | Unknown | Organization address | 


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

>### Organization
>|Address|Id|Name|
>|---|---|---|
>| address1: <br/>address2: <br/>city: <br/>zipCode: <br/>state: <br/>country:  | 1 | Main Org. |


### grafana-org-get-by-id
***
Gets an organization by id.


#### Base Command

`grafana-org-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| org_id | Organization id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Grafana.Organization.id | Number | Organization id | 
| Grafana.Organization.name | String | Organization name | 
| Grafana.Organization.address | Unknown | Organization address | 


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

>### Organization
>|Address|Id|Name|
>|---|---|---|
>| address1: <br/>address2: <br/>city: <br/>zipCode: <br/>state: <br/>country:  | 1 | Main Org. |

