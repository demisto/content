This package allows retrieving asset monitoring results from monitoring tasks that can be configured in Resecurity® CTI and Resecurity® DRM platforms.
This integration was integrated and tested with version 1.01 of ResecurityMonitoring

## Configure Resecurity Monitoring in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL |  | True |
| API Key | The API Key to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### resecurity-get-task-monitor-results-data-breaches

***
Retrieve monitoring results from a specific monitor task

#### Base Command

`resecurity-get-task-monitor-results-data-breaches`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| monitor_task_id | Monitor Task ID. | Required | 
| page | Page number. The results will be returned only for specified page if param value is not empty. | Optional | 
| page_size | Page size. Possible range of values: 1 - 50. Default value is 20. | Optional | 
| limit | Limit of the records in dataset. Default value is 1000. | Optional | 
| mode | Affects which results will be included in dataset. Possible values: 1 - only new results, 2 - last results (default value), 3 - all results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Resecurity.DataBreach.id | String | Data breach ID | 
| Resecurity.DataBreach.query | String | The query for which the result was found | 
| Resecurity.DataBreach.detection_date | Number | Data breach detection date | 
| Resecurity.DataBreach.email | String | Data breach email | 
| Resecurity.DataBreach.username | String | Data breach username | 
| Resecurity.DataBreach.password | String | Data breach password | 
| Resecurity.DataBreach.password_hash | String | Data breach password hash | 
| Resecurity.DataBreach.salt | String | Data breach salt | 
| Resecurity.DataBreach.ip | String | Data breach IP address | 
| Resecurity.DataBreach.source_name | String | Data breach source name | 

#### Command example

```!resecurity-get-task-monitor-results-data-breaches monitor_task_id=1 limit=2 mode=2```

#### Context Example

```json
{
    "Resecurity": {
        "DataBreach": [
            {
                "date": "2016-11-04 21:55:00",
                "detection_date": "2023-03-18 13:14:04",
                "email": "email@domain.test",
                "id": 11192938,
                "info": "",
                "ip": "95.112.168.138",
                "password": "",
                "password_hash": "71356c329abee63757ecb3f60b5f90be34ab47caa85d41344cea3f9c92f38eea0313bf60650fe2149e4a2e169d492d9b59a71e97d7331d74caa8b054b448cf04",
                "query": "domain.test",
                "salt": "",
                "source_name": "source1",
                "username": "JMBStarYT"
            },
            {
                "date": "2016-11-30 21:30:00",
                "detection_date": "2023-03-18 13:14:04",
                "email": "email@domain.test",
                "id": 47200407,
                "info": "",
                "ip": "86.178.141.167",
                "password": null,
                "password_hash": "c2f5c61a8ad5dc1ef8c0478617cac76a",
                "query": "domain.test",
                "salt": null,
                "source_name": "source2",
                "username": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Breaches results from task with ID 1
>
>|date|detection_date|email|id|info|ip|password|password_hash|query|salt|source_name|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2016-11-04 21:55:00 | 2023-03-18 13:14:04 | <email@domain.test> | 11192938 |  | 95.112.168.138 |  | 71356c329abee63757ecb3f60b5f90be34ab47caa85d41344cea3f9c92f38eea0313bf60650fe2149e4a2e169d492d9b59a71e97d7331d74caa8b054b448cf04 | domain.test |  | source1 | JMBStarYT |
>| 2016-11-30 21:30:00 | 2023-03-18 13:14:04 | <email@domain.test> | 47200407 |  | 86.178.141.167 |  | c2f5c61a8ad5dc1ef8c0478617cac76a | domain.test |  | source2 |  |


#### Command example

```!resecurity-get-task-monitor-results-data-breaches monitor_task_id=1 page_size=2 page=10 mode=2```

#### Context Example

```json
{
    "Resecurity": {
        "DataBreach": [
            {
                "date": "2016-12-07 15:53:00",
                "detection_date": "2023-03-18 13:14:04",
                "email": "test@test.test",
                "id": 361424177,
                "info": "",
                "ip": "",
                "password": "aaaaaa",
                "password_hash": null,
                "query": "test.test",
                "salt": null,
                "source_name": "source3",
                "username": null
            },
            {
                "date": "2016-12-07 15:53:00",
                "detection_date": "2023-03-18 13:14:04",
                "email": "test@test.test",
                "id": 361832967,
                "info": "",
                "ip": "",
                "password": "pppppp",
                "password_hash": null,
                "query": "test.test",
                "salt": null,
                "source_name": "source3",
                "username": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Breaches results from task with ID 1
>
>|date|detection_date|email|id|info|ip|password|password_hash|query|salt|source_name|username|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2016-12-07 15:53:00 | 2023-03-18 13:14:04 | <test@test.test> | 361424177 |  |  | aaaaaa |  | test.test |  | source3 |  |
>| 2016-12-07 15:53:00 | 2023-03-18 13:14:04 | <test@test.test> | 361832967 |  |  | pppppp |  | test.test |  | source3 |  |
