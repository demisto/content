This integration was integrated and tested with version 3 of Jira Event Collector rest API.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Jira Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| User name | The user name. For example, `admin@example.com` | True |
| Password |  | True |
| First fetch time |(&lt;number&gt; &lt;time unit&gt;. For example, 12 hours, 1 day, 3 months). Default is 3 days. |  | True |
| The maximum number of incidents per fetch. | Default is 1000. |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the War Room, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### jira-get-events

***

#### Base Command

`jira-get-events`

#### Input

| **Argument Name** | **Description**                                                                                          | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------|--------------|
| max_fetch         | The maximum number of events per fetch. Default is 1000.                                 | Optional     | 
| first_fetch       | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 1 day, 3 months). default is 3 days. | Optional     | 

#### Command example

```!jira-get-events max_fetch=2```

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