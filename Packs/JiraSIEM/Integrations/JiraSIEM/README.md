This integration was integrated and tested with version 3 of JiraSIEM rest API

## Configure Jira SIEM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Jira SIEM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Incident type |  | False |
    | Your server URL |  | True |
    | Method request |  | False |
    | User name | The user name \(admin@example.com\) and password | True |
    | Password |  | True |
    | Fetch incidents |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 1 day, 3 months). default is 3 days. |  | True |
    | The maximum number of incidents per fetch. Default is 100 maximum is 1000. |  | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fetch-events

***

#### Base Command

`fetch-events`

#### Input

| **Argument Name** | **Description**                                                                                          | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------|--------------|
| max_fetch         | The maximum number of incidents per fetch. Default is 100 maximum is 1000.                               | Optional     | 
| first_fetch       | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 1 day, 3 months). default is 3 days. | Optional     | 

#### Context Output

| **Path**             | **Type** | **Description**                                                              |
|----------------------|----------|------------------------------------------------------------------------------|
| Jira.id              | Number   | The ID of the audit record                                                   | 
| Jira.summary         | String   | The summary of the audit record                                              | 
| Jira.remoteAddress   | String   | The URL of the computer where the creation of the audit record was initiated | 
| Jira.authorKey       | String   | The key of the user who created the audit record                             | 
| Jira.created         | String   | The date and time on which the audit record was created                      | 
| Jira.category        | String   | The category of the audit record                                             | 
| Jira.eventSource     | String   | The event the audit record originated from                                   | 
| Jira.description     | String   | The description of the audit record                                          | 
| Jira.objectItem      | Unknown  | Details of an item associated with the changed record                        | 
| Jira.changedValues   | Unknown  | The list of values changed in the record event                               | 
| Jira.associatedItems | Unknown  | The list of items associated with the changed record                         | 

#### Command example

```!fetch-events max_fetch=2```

#### Context Example

```json
{
    "Jira": {
        "Records": [
            {
                "associatedItems": [
                    {
                        "id": "ug:123456-123456-123456",
                        "name": "ug:123456-123456-123456",
                        "parentId": "111",
                        "parentName": "com.atlassian.crowd.directory.example",
                        "typeName": "USER"
                    }
                ],
                "category": "group management",
                "created": "2022-04-24T16:28:53.146+0000",
                "eventSource": "",
                "id": 1111,
                "objectItem": {
                    "name": "jira-servicemanagement-users",
                    "parentId": "111",
                    "parentName": "com.atlassian.crowd.directory.example",
                    "typeName": "GROUP"
                },
                "summary": "User added to group"
            },
            {
                "associatedItems": [
                    {
                        "id": "ug:123456-123456-123457",
                        "name": "ug:123456-123456-123457",
                        "parentId": "111",
                        "parentName": "com.atlassian.crowd.directory.example",
                        "typeName": "USER"
                    }
                ],
                "category": "group management",
                "created": "2022-04-24T16:28:53.098+0000",
                "eventSource": "",
                "id": 1110,
                "objectItem": {
                    "name": "jira-software-users",
                    "parentId": "111",
                    "parentName": "com.atlassian.crowd.directory.example",
                    "typeName": "GROUP"
                },
                "summary": "User added to group"
            }
        ]
    }
}
```

#### Human Readable Output

>### Jira records
>|Associated Items|Category|Created| Id   | Object Item                                                                                                                    |Summary|
>|---|---|------|--------------------------------------------------------------------------------------------------------------------------------|---|---|
>| {'id': 'ug:123456-123456-123456', 'name': 'ug:123456-123456-123456', 'typeName': 'USER', 'parentId': '111', 'parentName': 'com.atlassian.crowd.directory.example'} | group management | 2022-04-24T16:28:53.146+0000 | 1111 | name: jira-servicemanagement-users<br/>typeName: GROUP<br/>parentId: 111<br/>parentName: com.atlassian.crowd.directory.example | User added to group |
>| {'id': 'ug:123456-123456-123457', 'name': 'ug:123456-123456-123457', 'typeName': 'USER', 'parentId': '111', 'parentName': 'com.atlassian.crowd.directory.example'} | group management | 2022-04-24T16:28:53.098+0000 | 1110 | name: jira-software-users<br/>typeName: GROUP<br/>parentId: 111<br/>parentName: com.atlassian.crowd.directory.example          | User added to group |
