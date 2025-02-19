G Suite Auditor is an integration that receives audit logs from G Suite's different applications - admin, drive, calendar, and more.

## Required Permissions:
In order to use the integration you will need:
* Admin email address.
* Service Account with access to the following scope - https://www.googleapis.com/auth/admin.reports.audit.readonly .

For more information, see the integrations description.

### For more information about the integration arguments:
* [Command arguments documentation](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list?apix_params=%7B%22userKey%22%3A%22all%22%2C%22applicationName%22%3A%22admin%22%2C%22eventName%22%3A%22DELETE_USER%22%2C%22filters%22%3A%22USER_EMAIL%3D%3Dxsoar11%40demistodev.com%22%7D#query-parameters) in Google's API.
* [Application to event names table](https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list#applicationname) by Google's API.

## Google's lag time information
This integration relies on Google's audit logs which are prone to some data delays. Some results may be partial if data had not arrived due to lag times. The lag time changes depending on the used audit log (from near real-time up to 3 days).
For more information - https://support.google.com/a/answer/7061566?hl=en

## Configure G Suite Auditor in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Admin email | True |
| User's Service Account JSON | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gsuite-activity-search
***
Retrieves a list of activities for a specific customer's account and application.


#### Base Command

`gsuite-activity-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_key | Profile ID or the user email for which the data should be filtered. Can be 'all' for all information, or 'userKey' for a user's unique Google Workspace profile ID or their primary email address. | Optional | 
| application_name | Application name for which the events are to be retrieved. Possible values are: access_transparency, admin, calendar, chat, drive, gcp, gplus, groups, groups_enterprise, jamboard, login, meet, mobile, rules, saml, token, user_accounts, context_aware_access, chrome, data_studio, keep. | Required | 
| event_name | The name of the event being queried. For a list of event names for each application, see the integration documentation. | Optional | 
| filters | A comma-separated list of event parameters and relational operators. For example-<br/>'API_CLIENT_NAME==111,API_SCOPES=aaa'.<br/>The relevant 'event name' argument must be supplied to use this argument. | Optional | 
| org_unit_id | ID of the organizational unit to report on. Activity records will be shown only for users who belong to the specified organizational unit. | Optional | 
| group_id | Comma-separated group IDs on which user activities are filtered. <br/>The response will contain activities for only those users who are a part of <br/>at least one of the group IDs mentioned here. For example: "id:abc123,id:xyz456".<br/>To retrieve a group ID, use the 'gsuite-get-group' command in the 'G Suite Admin' pack. | Optional | 
| actor_ip_address | IP address of the host where the event was performed. | Optional | 
| start_time | The beginning of the time range shown in the report. For example - 2010-10-28T10:26:35.000Z. | Optional | 
| end_time | The end of the time range shown in the report. For example - 2010-10-28T10:26:35.000Z. | Optional | 
| max_results | Maximum number of results to return. Default is 50. | Optional | 
| page_token | The token to specify the next page. | Optional | 
| admin_email | Email address of the G Suite domain admin. The request is preformed based on this user's permissions. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GSuite.ActivitySearch.items.id.time | Date | Time the activity occurred. | 
| GSuite.ActivitySearch.items.id.uniqueQualifier | String | Unique qualifier if multiple events have the same time. | 
| GSuite.ActivitySearch.items.id.applicationName | String | Application name to which the event belongs. | 
| GSuite.ActivitySearch.items.id.customerId | String | The unique identifier for a Google Workspace account. | 
| GSuite.ActivitySearch.items.actor.callerType | String | The type of actor. | 
| GSuite.ActivitySearch.items.actor.key | String | Can be the consumer_key of the requestor for OAuth 2LO API requests or an identifier for robot accounts. | 
| GSuite.ActivitySearch.items.events.type | String | Type of event. | 
| GSuite.ActivitySearch.items.events.name | String | Name of the event. | 
| GSuite.ActivitySearch.items.events.parameters.name | String | The name of the parameter. | 
| GSuite.ActivitySearch.items.events.parameters.value | String | String value of the parameter. | 
| GSuite.ActivitySearch.items.actor.email | String | The primary email address of the actor. | 
| GSuite.ActivitySearch.items.actor.profileId | String | The unique Google Workspace profile ID of the actor. | 
| GSuite.ActivitySearch.items.ipAddress | String | IP address of the user performing the action. | 
| GSuite.ActivitySearch.items.events.parameters.boolValue | Boolean | Boolean value of the parameter. | 
| GSuite.ActivitySearch.items.events.parameters.multiValue | String | String values of the parameter. | 
| GSuite.PageToken.ActivitySearch.nextPageToken | String | Token to specify the next page in the list. | 


#### Command Example
```!gsuite-activity-search application_name=admin max_results=2```

#### Context Example
```json
{
    "GSuite": {
        "ActivitySearch": [
            {
                "actor": {
                    "callerType": "KEY",
                    "key": "SYSTEM"
                },
                "events": [
                    {
                        "name": "USER_LICENSE_REVOKE",
                        "parameters": [
                            {
                                "name": "USER_EMAIL",
                                "value": "user@email.com"
                            },
                            {
                                "name": "PRODUCT_NAME",
                                "value": "Google Workspace"
                            },
                            {
                                "name": "OLD_VALUE",
                                "value": "G Suite Business"
                            }
                        ],
                        "type": "LICENSES_SETTINGS"
                    }
                ],
                "id": {
                    "applicationName": "admin",
                    "customerId": "11111",
                    "time": "2021-07-27T02:47:20.894Z",
                    "uniqueQualifier": "-7168880636905757919"
                }
            },
            {
                "actor": {
                    "callerType": "USER",
                    "email": "admin@email.com",
                    "profileId": "103020731686044834269"
                },
                "events": [
                    {
                        "name": "DELETE_USER",
                        "parameters": [
                            {
                                "name": "USER_EMAIL",
                                "value": "user@email.com"
                            }
                        ],
                        "type": "USER_SETTINGS"
                    }
                ],
                "id": {
                    "applicationName": "admin",
                    "customerId": "1111",
                    "time": "2021-07-27T01:47:40.585Z",
                    "uniqueQualifier": "-4797090398870165525"
                },
                "ipAddress": " "
            }
        ],
        "PageToken": {
            "ActivitySearch": {
                "nextPageToken": "A:1627350460585000:-4797090398870165525:207535951991:C02f0zfqw"
            }
        }
    }
}
```

#### Human Readable Output

>### Next Page Token: A:1627350460585000:-4797090398870165525:207535951991:C02f0zfqw
>### Total Retrieved Activities: 2
>|Time|Application Name|Email|ProfileId|IpAddress|Events|
>|---|---|---|---|---|---|
>| 2021-07-27T02:47:20.894Z | admin |  |  |  | {'type': 'LICENSES_SETTINGS', 'name': 'USER_LICENSE_REVOKE', 'parameters': [{'name': 'USER_EMAIL', 'value': 'user@email.com'}, {'name': 'PRODUCT_NAME', 'value': 'Google Workspace'}, {'name': 'OLD_VALUE', 'value': 'G Suite Business'}]} |
>| 2021-07-27T01:47:40.585Z | admin | admin@email.com | 103020731686044834269 | - | {'type': 'USER_SETTINGS', 'name': 'DELETE_USER', 'parameters': [{'name': 'USER_EMAIL', 'value': 'user@email.com'}]} |