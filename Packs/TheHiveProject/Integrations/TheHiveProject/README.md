Integration with The Hive Project Security Incident Response Platform.
This integration was integrated and tested with version 4.1.4 of TheHive Project

## Configure TheHive Project in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Host | Ensure to include the port number with the URL \(e.g. http://IP_OF_VM:9000\) | True |
| API Key |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| Incidents Fetch Interval |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| The maximum amount of incidents to fetch at once |  | False |
| Case mirroring | Select whether you would like cases to mirror in, out, in both directions or disabled. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

Test of mirroring! 1. 2. 3. 4.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### thehive-list-cases

***
List cases.


#### Base Command

`thehive-list-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the number of returned results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.customFields | unknown | Any fields that the user of TheHiveProject has added to the platform and filled in as part of a case. | 
| TheHive.Cases.caseId | number | The order of the case. | 
| TheHive.Cases.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.startDate | number | Datetime the case was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.status | string | Status of the case. | 
| TheHive.Cases.owner | string | Owner of the case. | 
| TheHive.Cases.tlp | number | Traffic Light Protocol designation for the case. | 
| TheHive.Cases.title | string | Title of the case. | 
| TheHive.Cases.tags | unknown | Tags added to the case. | 
| TheHive.Cases._type | string | Type of the case. | 
| TheHive.Cases._version | number | The version of TheHive Project. | 
| TheHive.Cases.id | string | The ID of the case. | 
| TheHive.Cases.createdAt | number | Datetime the case was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.description | string | Description of the case. | 
| TheHive.Cases.severity | number | Severity of the case. | 
| TheHive.Cases.pap | number | Permissible Actions Protocol \(PAP\), used to indicate what kind of action is allowed. | 
| TheHive.Cases.createdBy | string | The user who created the case. | 
| TheHive.Cases.tasks._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.tasks.order | number | The order of the task. | 
| TheHive.Cases.tasks.status | string | Status of the task. | 
| TheHive.Cases.tasks.title | string | Title of the task. | 
| TheHive.Cases.tasks._type | string | Type of the task. | 
| TheHive.Cases.tasks._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.id | string | The ID of the task. | 
| TheHive.Cases.tasks.createdAt | number | Datetime the task was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.createdBy | string | The user who created the task. | 
| TheHive.Cases.tasks.group | string | Group of the task. | 
| TheHive.Cases.tasks.logs.message | string | Log message. | 
| TheHive.Cases.tasks.logs._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks.logs._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.logs.startDate | number | Datetime the log was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.status | string | Status of the log. | 
| TheHive.Cases.tasks.logs.owner | string | Owner of the log. | 
| TheHive.Cases.tasks.logs._type | string | Type of the log. | 
| TheHive.Cases.tasks.logs._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.logs.id | string | The ID of the log. | 
| TheHive.Cases.tasks.logs.createdAt | number | Datetime the task log was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.createdBy | string | The user who created the log. | 


#### Command Example

```!thehive-list-cases```

#### Context Example

```json
{
    "TheHive": {
        "Cases": [
            {
                "_id": "~479312",
                "_type": "case",
                "caseId": 1,
                "createdAt": "2021-10-11T17:02:01Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "case with tasks",
                "endDate": null,
                "flag": false,
                "id": "~479312",
                "impactStatus": null,
                "instance": "TheHive Project_instance_1",
                "mirroring": "Both",
                "observables": [],
                "owner": "adrugobitski@paloaltonetworks.com",
                "pap": 2,
                "permissions": [
                    "manageShare",
                    "manageAnalyse",
                    "manageTask",
                    "manageCaseTemplate",
                    "manageCase",
                    "manageUser",
                    "manageProcedure",
                    "managePage",
                    "manageObservable",
                    "manageTag",
                    "manageConfig",
                    "manageAlert",
                    "accessTheHiveFS",
                    "manageAction"
                ],
                "resolutionStatus": null,
                "severity": 2,
                "startDate": 1633971660000,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [
                    {
                        "_createdAt": 1633971721834,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~41500824",
                        "_type": "Task",
                        "extraData": {
                            "shareCount": 0
                        },
                        "flag": false,
                        "group": "default",
                        "logs": [],
                        "order": 0,
                        "status": "Waiting",
                        "title": "task1"
                    },
                    {
                        "_createdAt": 1633971721837,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~438408",
                        "_type": "Task",
                        "extraData": {
                            "shareCount": 0
                        },
                        "flag": false,
                        "group": "default",
                        "logs": [],
                        "order": 0,
                        "status": "Waiting",
                        "title": "task2"
                    },
                    {
                        "_createdAt": 1633971721840,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~442504",
                        "_type": "Task",
                        "extraData": {
                            "shareCount": 0
                        },
                        "flag": false,
                        "group": "default",
                        "logs": [],
                        "order": 0,
                        "status": "Waiting",
                        "title": "task3"
                    }
                ],
                "title": "case with tasks",
                "tlp": 2,
                "updatedAt": 1633971749765,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~487504",
                "_type": "case",
                "caseId": 2,
                "createdAt": "2021-10-11T17:02:34Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "case with no task",
                "endDate": null,
                "flag": false,
                "id": "~487504",
                "impactStatus": null,
                "instance": "TheHive Project_instance_1",
                "mirroring": "Both",
                "observables": [],
                "owner": "adrugobitski@paloaltonetworks.com",
                "pap": 2,
                "permissions": [
                    "manageShare",
                    "manageAnalyse",
                    "manageTask",
                    "manageCaseTemplate",
                    "manageCase",
                    "manageUser",
                    "manageProcedure",
                    "managePage",
                    "manageObservable",
                    "manageTag",
                    "manageConfig",
                    "manageAlert",
                    "accessTheHiveFS",
                    "manageAction"
                ],
                "resolutionStatus": null,
                "severity": 2,
                "startDate": 1633971720000,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "no tasks case",
                "tlp": 2,
                "updatedAt": 1633971809110,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~491600",
                "_type": "case",
                "caseId": 3,
                "createdAt": "2021-10-11T17:02:55Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "case to merge",
                "endDate": null,
                "flag": false,
                "id": "~491600",
                "impactStatus": null,
                "instance": "TheHive Project_instance_1",
                "mirroring": "Both",
                "observables": [],
                "owner": "adrugobitski@paloaltonetworks.com",
                "pap": 2,
                "permissions": [
                    "manageShare",
                    "manageAnalyse",
                    "manageTask",
                    "manageCaseTemplate",
                    "manageCase",
                    "manageUser",
                    "manageProcedure",
                    "managePage",
                    "manageObservable",
                    "manageTag",
                    "manageConfig",
                    "manageAlert",
                    "accessTheHiveFS",
                    "manageAction"
                ],
                "resolutionStatus": null,
                "severity": 2,
                "startDate": 1633971720000,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "merge 1",
                "tlp": 2,
                "updatedAt": 1633971809811,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~524320",
                "_type": "case",
                "caseId": 4,
                "createdAt": "2021-10-11T17:03:12Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "case to merge 2",
                "endDate": null,
                "flag": false,
                "id": "~524320",
                "impactStatus": null,
                "instance": "TheHive Project_instance_1",
                "mirroring": "Both",
                "observables": [],
                "owner": "adrugobitski@paloaltonetworks.com",
                "pap": 2,
                "permissions": [
                    "manageShare",
                    "manageAnalyse",
                    "manageTask",
                    "manageCaseTemplate",
                    "manageCase",
                    "manageUser",
                    "manageProcedure",
                    "managePage",
                    "manageObservable",
                    "manageTag",
                    "manageConfig",
                    "manageAlert",
                    "accessTheHiveFS",
                    "manageAction"
                ],
                "resolutionStatus": null,
                "severity": 2,
                "startDate": 1633971720000,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "merge 2",
                "tlp": 2,
                "updatedAt": 1633971810562,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~561160",
                "_type": "case",
                "caseId": 5,
                "createdAt": "2021-10-11T17:12:06Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "case with observables",
                "endDate": null,
                "flag": false,
                "id": "~561160",
                "impactStatus": null,
                "instance": "TheHive Project_instance_1",
                "mirroring": "Both",
                "observables": [
                    {
                        "_createdAt": 1633972384854,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~41504920",
                        "_type": "Observable",
                        "data": "google",
                        "dataType": "domain",
                        "extraData": {
                            "permissions": [
                                "manageShare",
                                "manageAnalyse",
                                "manageTask",
                                "manageCaseTemplate",
                                "manageCase",
                                "manageUser",
                                "manageProcedure",
                                "managePage",
                                "manageObservable",
                                "manageTag",
                                "manageConfig",
                                "manageAlert",
                                "accessTheHiveFS",
                                "manageAction"
                            ],
                            "seen": {
                                "ioc": false,
                                "seen": 0
                            },
                            "shareCount": 0
                        },
                        "ignoreSimilarity": false,
                        "ioc": false,
                        "message": "observable 2",
                        "reports": {},
                        "sighted": false,
                        "startDate": 1633972384854,
                        "tags": [],
                        "tlp": 1
                    },
                    {
                        "_createdAt": 1633972365905,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~532512",
                        "_type": "Observable",
                        "data": "8.8.8.8",
                        "dataType": "ip",
                        "extraData": {
                            "permissions": [
                                "manageShare",
                                "manageAnalyse",
                                "manageTask",
                                "manageCaseTemplate",
                                "manageCase",
                                "manageUser",
                                "manageProcedure",
                                "managePage",
                                "manageObservable",
                                "manageTag",
                                "manageConfig",
                                "manageAlert",
                                "accessTheHiveFS",
                                "manageAction"
                            ],
                            "seen": {
                                "ioc": false,
                                "seen": 0
                            },
                            "shareCount": 0
                        },
                        "ignoreSimilarity": false,
                        "ioc": false,
                        "message": "observable 1",
                        "reports": {},
                        "sighted": false,
                        "startDate": 1633972365905,
                        "tags": [],
                        "tlp": 2
                    }
                ],
                "owner": "adrugobitski@paloaltonetworks.com",
                "pap": 2,
                "permissions": [
                    "manageShare",
                    "manageAnalyse",
                    "manageTask",
                    "manageCaseTemplate",
                    "manageCase",
                    "manageUser",
                    "manageProcedure",
                    "managePage",
                    "manageObservable",
                    "manageTag",
                    "manageConfig",
                    "manageAlert",
                    "accessTheHiveFS",
                    "manageAction"
                ],
                "resolutionStatus": null,
                "severity": 2,
                "startDate": 1633972260000,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "observables case",
                "tlp": 2,
                "updatedAt": 1633972353588,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~41509016",
                "_type": "case",
                "caseId": 6,
                "createdAt": "2021-10-11T17:16:33Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "case to be removed",
                "endDate": null,
                "flag": false,
                "id": "~41509016",
                "impactStatus": null,
                "instance": "TheHive Project_instance_1",
                "mirroring": "Both",
                "observables": [],
                "owner": "adrugobitski@paloaltonetworks.com",
                "pap": 2,
                "permissions": [
                    "manageShare",
                    "manageAnalyse",
                    "manageTask",
                    "manageCaseTemplate",
                    "manageCase",
                    "manageUser",
                    "manageProcedure",
                    "managePage",
                    "manageObservable",
                    "manageTag",
                    "manageConfig",
                    "manageAlert",
                    "accessTheHiveFS",
                    "manageAction"
                ],
                "resolutionStatus": null,
                "severity": 2,
                "startDate": 1633972560000,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "remove case",
                "tlp": 2,
                "updatedAt": 1633972648939,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### TheHive Cases:

>|id|title|description|createdAt|
>|---|---|---|---|
>| ~479312 | case with tasks | case with tasks | 2021-10-11T17:02:01Z |
>| ~487504 | no tasks case | case with no task | 2021-10-11T17:02:34Z |
>| ~491600 | merge 1 | case to merge | 2021-10-11T17:02:55Z |
>| ~524320 | merge 2 | case to merge 2 | 2021-10-11T17:03:12Z |
>| ~561160 | observables case | case with observables | 2021-10-11T17:12:06Z |
>| ~41509016 | remove case | case to be removed | 2021-10-11T17:16:33Z |


### thehive-get-case

***
Get a case


#### Base Command

`thehive-get-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the case. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.customFields | unknown | Any fields that the user of TheHiveProject has added to the platform and filled in as part of a case. | 
| TheHive.Cases.caseId | number | The order of the case. | 
| TheHive.Cases.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.startDate | number | Datetime the case was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.status | string | Status of the case. | 
| TheHive.Cases.owner | string | Owner of the case. | 
| TheHive.Cases.tlp | number | Traffic Light Protocol designation for the case. | 
| TheHive.Cases.title | string | Title of the case. | 
| TheHive.Cases.tags | unknown | Tags added to the case. | 
| TheHive.Cases._type | string | Type of the case. | 
| TheHive.Cases._version | number | The version of TheHive Project. | 
| TheHive.Cases.id | string | The ID of the case. | 
| TheHive.Cases.createdAt | number | Datetime the case was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.description | string | Description of the case. | 
| TheHive.Cases.severity | number | Severity of the case. | 
| TheHive.Cases.pap | number | Permissible Actions Protocol \(PAP\), used to indicate what kind of action is allowed. | 
| TheHive.Cases.createdBy | string | The user who created the case. | 
| TheHive.Cases.tasks._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.tasks.order | number | The order of the task. | 
| TheHive.Cases.tasks.status | string | Status of the task. | 
| TheHive.Cases.tasks.title | string | Title of the task. | 
| TheHive.Cases.tasks._type | string | Type of the task. | 
| TheHive.Cases.tasks._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.id | string | The ID of the task. | 
| TheHive.Cases.tasks.createdAt | number | Datetime the task was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.createdBy | string | The user who created the task. | 
| TheHive.Cases.tasks.group | string | Group of the task. | 
| TheHive.Cases.tasks.logs.message | string | Log message. | 
| TheHive.Cases.tasks.logs._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks.logs._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.logs.startDate | number | Datetime the log was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.status | string | Status of the log. | 
| TheHive.Cases.tasks.logs.owner | string | Owner of the log. | 
| TheHive.Cases.tasks.logs._type | string | Type of the log. | 
| TheHive.Cases.tasks.logs._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.logs.id | string | The ID of the log. | 
| TheHive.Cases.tasks.logs.createdAt | number | Datetime the task log was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.createdBy | string | The user who created the log. | 


#### Command Example

```!thehive-get-case id="~479312"```

#### Context Example

```json
{
    "TheHive": {
        "Cases": {
            "_id": "~479312",
            "_type": "case",
            "caseId": 1,
            "createdAt": "2021-10-11T17:02:01Z",
            "createdBy": "adrugobitski@paloaltonetworks.com",
            "customFields": {},
            "description": "case with tasks",
            "endDate": null,
            "flag": false,
            "id": "~479312",
            "impactStatus": null,
            "observables": [],
            "owner": "adrugobitski@paloaltonetworks.com",
            "pap": 2,
            "permissions": [
                "manageShare",
                "manageAnalyse",
                "manageTask",
                "manageCaseTemplate",
                "manageCase",
                "manageUser",
                "manageProcedure",
                "managePage",
                "manageObservable",
                "manageTag",
                "manageConfig",
                "manageAlert",
                "accessTheHiveFS",
                "manageAction"
            ],
            "resolutionStatus": null,
            "severity": 2,
            "startDate": 1633971660000,
            "stats": {},
            "status": "Open",
            "summary": null,
            "tags": [],
            "tasks": [
                {
                    "_createdAt": 1633971721834,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~41500824",
                    "_type": "Task",
                    "extraData": {
                        "shareCount": 0
                    },
                    "flag": false,
                    "group": "default",
                    "logs": [],
                    "order": 0,
                    "status": "Waiting",
                    "title": "task1"
                },
                {
                    "_createdAt": 1633971721837,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~438408",
                    "_type": "Task",
                    "extraData": {
                        "shareCount": 0
                    },
                    "flag": false,
                    "group": "default",
                    "logs": [],
                    "order": 0,
                    "status": "Waiting",
                    "title": "task2"
                },
                {
                    "_createdAt": 1633971721840,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~442504",
                    "_type": "Task",
                    "extraData": {
                        "shareCount": 0
                    },
                    "flag": false,
                    "group": "default",
                    "logs": [],
                    "order": 0,
                    "status": "Waiting",
                    "title": "task3"
                }
            ],
            "title": "case with tasks",
            "tlp": 2,
            "updatedAt": 1633971749765,
            "updatedBy": "adrugobitski@paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### TheHive Case ID ~479312:

>|id|title|description|createdAt|
>|---|---|---|---|
>| ~479312 | case with tasks | case with tasks | 2021-10-11T17:02:01Z |


### thehive-update-case

***
Update a case


#### Base Command

`thehive-update-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the case. | Required | 
| title | Title of the case. | Optional | 
| description | Description of the case. | Optional | 
| severity | Severity of the case. Possible values are: 1, 2, 3. | Optional | 
| startDate | Datetime the case was started on, for example, 2018-06-29 08:15:27.243860. | Optional | 
| owner | Owner of the case. | Optional | 
| flag | A boolean flag used for filtering. Possible values are: true, false. | Optional | 
| tlp | Traffic Light Protocol designation for the case. Possible values are: WHITE, GREEN, AMBER, RED. | Optional | 
| tags | Tags added to the case. | Optional | 
| resolutionStatus | Resolution status of the case. Possible values are: Indeterminate, FalsePositive, TruePositive, Other, Duplicated. | Optional | 
| impactStatus | Impact status of the case. Possible values are: NoImpact, WithImpact, NotApplicable. | Optional | 
| summary | Summary of the case. | Optional | 
| endDate | Datetime the case ended, for example, 2018-06-29 08:15:27.243860. | Optional | 
| metrics | Metrics of the case. | Optional | 
| status | Status of the case. Possible values are: Open, Resolved, Deleted. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.customFields | unknown | Any fields that the user of TheHiveProject has added to the platform and filled in as part of a case. | 
| TheHive.Cases.caseId | number | The order of the case. | 
| TheHive.Cases.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.startDate | number | Datetime the case was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.status | string | Status of the case. | 
| TheHive.Cases.owner | string | Owner of the case. | 
| TheHive.Cases.tlp | number | Traffic Light Protocol designation for the case. | 
| TheHive.Cases.title | string | Title of the case. | 
| TheHive.Cases.tags | unknown | Tags added to the case. | 
| TheHive.Cases._type | string | Type of the case. | 
| TheHive.Cases._version | number | The version of TheHive Project. | 
| TheHive.Cases.id | string | The ID of the case. | 
| TheHive.Cases.createdAt | number | Datetime the case was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.description | string | Description of the case. | 
| TheHive.Cases.severity | number | Severity of the case. | 
| TheHive.Cases.pap | number | Permissible Actions Protocol \(PAP\), used to indicate what kind of action is allowed. | 
| TheHive.Cases.createdBy | string | The user who created the case. | 
| TheHive.Cases.tasks._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.tasks.order | number | The order of the task. | 
| TheHive.Cases.tasks.status | string | Status of the task. | 
| TheHive.Cases.tasks.title | string | Title of the task. | 
| TheHive.Cases.tasks._type | string | Type of the task. | 
| TheHive.Cases.tasks._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.id | string | The ID of the task. | 
| TheHive.Cases.tasks.createdAt | number | Datetime the task was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.createdBy | string | The user who created the task. | 
| TheHive.Cases.tasks.group | string | Group of the task. | 
| TheHive.Cases.tasks.logs.message | string | Log message. | 
| TheHive.Cases.tasks.logs._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks.logs._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.logs.startDate | number | Datetime the log was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.status | string | Status of the log. | 
| TheHive.Cases.tasks.logs.owner | string | Owner of the log. | 
| TheHive.Cases.tasks.logs._type | string | Type of the log. | 
| TheHive.Cases.tasks.logs._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.logs.id | string | The ID of the log. | 
| TheHive.Cases.tasks.logs.createdAt | number | Datetime the task log was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.createdBy | string | The user who created the log. | 


#### Command Example

```!thehive-update-case id="~487504" title="updated title for case with no tasks"```

#### Context Example

```json
{
    "TheHive": {
        "Cases": {
            "_id": "~487504",
            "_type": "case",
            "caseId": 2,
            "createdAt": "2021-10-11T17:02:34Z",
            "createdBy": "adrugobitski@paloaltonetworks.com",
            "customFields": {},
            "description": "case with no task",
            "endDate": null,
            "flag": false,
            "id": "~487504",
            "impactStatus": null,
            "owner": "adrugobitski@paloaltonetworks.com",
            "pap": 2,
            "permissions": [
                "manageShare",
                "manageAnalyse",
                "manageTask",
                "manageCaseTemplate",
                "manageCase",
                "manageUser",
                "manageProcedure",
                "managePage",
                "manageObservable",
                "manageTag",
                "manageConfig",
                "manageAlert",
                "accessTheHiveFS",
                "manageAction"
            ],
            "resolutionStatus": null,
            "severity": 2,
            "startDate": 1633971720000,
            "stats": {},
            "status": "Open",
            "summary": null,
            "tags": [],
            "title": "updated title for case with no tasks",
            "tlp": 2,
            "updatedAt": 1633973798560,
            "updatedBy": "adrugobitski@paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### TheHive Update Case ID ~487504:

>|id|title|description|createdAt|
>|---|---|---|---|
>| ~487504 | updated title for case with no tasks | case with no task | 2021-10-11T17:02:34Z |


### thehive-create-case

***
Create a new case


#### Base Command

`thehive-create-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Title of the case. | Required | 
| description | Description of the case. | Required | 
| severity | Severity of the case (default = 2). Possible values are: 1, 2, 3. | Optional | 
| startDate | Datetime the case was started on, for example, 2018-06-29 08:15:27.243860. | Optional | 
| owner | Owner of the case. | Required | 
| flag | A boolean flag used for filtering (default = false). Possible values are: false, true. | Optional | 
| tlp | Traffic Light Protocol designation for the case (default = 2). Possible values are: 0, 1, 2, 3. | Optional | 
| tags | Tags added to the case. | Optional | 
| resolutionStatus | Resolution status of the case. | Optional | 
| impactStatus | Impact status of the case. Possible values are: NoImpact, WithImpact, qNotApplicable. | Optional | 
| summary | Summary of the case. | Optional | 
| endDate | Datetime the case ended, for example, 2018-06-29 08:15:27.243860. | Optional | 
| metrics | Metrics of the case. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.customFields | unknown | Any fields that the user of TheHiveProject has added to the platform and filled in as part of a case. | 
| TheHive.Cases.caseId | number | The order of the case. | 
| TheHive.Cases.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.startDate | number | Datetime the case was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.status | string | Status of the case. | 
| TheHive.Cases.owner | string | Owner of the case. | 
| TheHive.Cases.tlp | number | Traffic Light Protocol designation for the case. | 
| TheHive.Cases.title | string | Title of the case. | 
| TheHive.Cases.tags | unknown | Tags added to the case. | 
| TheHive.Cases._type | string | Type of the case. | 
| TheHive.Cases._version | number | The version of TheHive Project. | 
| TheHive.Cases.id | string | The ID of the case. | 
| TheHive.Cases.createdAt | number | Datetime the case was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.description | string | Description of the case. | 
| TheHive.Cases.severity | number | Severity of the case. | 
| TheHive.Cases.pap | number | Permissible Actions Protocol \(PAP\), used to indicate what kind of action is allowed. | 
| TheHive.Cases.createdBy | string | The user who created the case. | 
| TheHive.Cases.tasks._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.tasks.order | number | The order of the task. | 
| TheHive.Cases.tasks.status | string | Status of the task. | 
| TheHive.Cases.tasks.title | string | Title of the task. | 
| TheHive.Cases.tasks._type | string | Type of the task. | 
| TheHive.Cases.tasks._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.id | string | The ID of the task. | 
| TheHive.Cases.tasks.createdAt | number | Datetime the task was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.createdBy | string | The user who created the task. | 
| TheHive.Cases.tasks.group | string | Group of the task. | 
| TheHive.Cases.tasks.logs.message | string | Log message. | 
| TheHive.Cases.tasks.logs._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks.logs._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.logs.startDate | number | Datetime the log was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.status | string | Status of the log. | 
| TheHive.Cases.tasks.logs.owner | string | Owner of the log. | 
| TheHive.Cases.tasks.logs._type | string | Type of the log. | 
| TheHive.Cases.tasks.logs._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.logs.id | string | The ID of the log. | 
| TheHive.Cases.tasks.logs.createdAt | number | Datetime the task log was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.createdBy | string | The user who created the log. | 


#### Command Example

```!thehive-create-case title="new created case" description="description for new case" owner="owner"```

#### Context Example

```json
{
    "TheHive": {
        "Cases": [
            {
                "_id": "~41492552",
                "_type": "case",
                "caseId": 7,
                "createdAt": "2021-10-11T17:36:40Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~41492552",
                "impactStatus": null,
                "owner": "adrugobitski@paloaltonetworks.com",
                "pap": 2,
                "permissions": [
                    "manageShare",
                    "manageAnalyse",
                    "manageTask",
                    "manageCaseTemplate",
                    "manageCase",
                    "manageUser",
                    "manageProcedure",
                    "managePage",
                    "manageObservable",
                    "manageTag",
                    "manageConfig",
                    "manageAlert",
                    "accessTheHiveFS",
                    "manageAction"
                ],
                "resolutionStatus": null,
                "severity": 2,
                "startDate": 1633973800326,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": null,
                "updatedBy": null
            },
            {
                "_id": "~41496648",
                "_type": "case",
                "caseId": 7,
                "createdAt": "2021-10-11T17:36:40Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~41496648",
                "impactStatus": null,
                "owner": "adrugobitski@paloaltonetworks.com",
                "pap": 2,
                "permissions": [
                    "manageShare",
                    "manageAnalyse",
                    "manageTask",
                    "manageCaseTemplate",
                    "manageCase",
                    "manageUser",
                    "manageProcedure",
                    "managePage",
                    "manageObservable",
                    "manageTag",
                    "manageConfig",
                    "manageAlert",
                    "accessTheHiveFS",
                    "manageAction"
                ],
                "resolutionStatus": null,
                "severity": 2,
                "startDate": 1633973800334,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": null,
                "updatedBy": null
            }
        ]
    }
}
```

#### Human Readable Output

>### TheHive newly Created Case:

>|id|title|description|createdAt|
>|---|---|---|---|
>| ~41492552 | new created case | description for new case | 2021-10-11T17:36:40Z |


### thehive-create-task

***
Create a new task


#### Base Command

`thehive-create-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Case ID. | Required | 
| title | Title of the case. | Required | 
| description | Description. | Optional | 
| startDate | Datetime the task was started on, for example, 2018-06-29 08:15:27.243860. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Tasks.status | string | Status of the task. | 
| TheHive.TasKs.title | string | Title of the task. | 
| TheHive.Tasks.id | string | The ID of the task. | 
| TheHive.Tasks.createdAt | number | Datetime the task was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Tasks._type | string | Type of the task. | 
| TheHive.Tasks.createdBy | string | The user who created the task. | 
| TheHive.Tasks.group | string | Group of the task. | 
| TheHive.Tasks.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Tasks.order | int | The order of the task. | 


#### Command Example

```!thehive-create-task id="~479312" title="newly added task" description="new description"```

#### Context Example

```json
{
    "TheHive": {
        "Tasks": [
            {
                "_id": "~585736",
                "_type": "case_task",
                "createdAt": "2021-10-11T17:36:42Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "description": "new description",
                "flag": false,
                "group": "default",
                "id": "~585736",
                "order": 0,
                "status": "Waiting",
                "title": "newly added task"
            },
            {
                "_id": "~581640",
                "_type": "case_task",
                "createdAt": "2021-10-11T17:36:42Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "description": "new description",
                "flag": false,
                "group": "default",
                "id": "~581640",
                "order": 0,
                "status": "Waiting",
                "title": "newly added task"
            }
        ]
    }
}
```

#### Human Readable Output

>### The newly created task

>|id|title|createdAt|status|
>|---|---|---|---|
>| ~581640 | newly added task | 2021-10-11T17:36:42Z | Waiting |


### thehive-remove-case

***
Removes a case


#### Base Command

`thehive-remove-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Case ID. | Required | 
| permanent | Permanently removes the case (cannot be undone). Possible values are: false, true. Default is false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```thehive-remove-case id='~41496648'```

#### Human Readable Output

```Case ID ~41496648 removed successfully```


### thehive-merge-cases

***
Merges 2 cases


#### Base Command

`thehive-merge-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstCaseID | ID of the first case. | Required | 
| secondCaseID | ID of the second case. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.customFields | unknown | Any fields that the user of TheHiveProject has added to the platform and filled in as part of a case. | 
| TheHive.Cases.caseId | number | The order of the case. | 
| TheHive.Cases.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.startDate | number | Datetime the case was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.status | string | Status of the case. | 
| TheHive.Cases.owner | string | Owner of the case. | 
| TheHive.Cases.tlp | number | Traffic Light Protocol designation for the case. | 
| TheHive.Cases.title | string | Title of the case. | 
| TheHive.Cases.tags | unknown | Tags added to the case. | 
| TheHive.Cases._type | string | Type of the case. | 
| TheHive.Cases._version | number | The version of TheHive Project. | 
| TheHive.Cases.id | string | The ID of the case. | 
| TheHive.Cases.createdAt | number | Datetime the case was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.description | string | Description of the case. | 
| TheHive.Cases.severity | number | Severity of the case. | 
| TheHive.Cases.pap | number | Permissible Actions Protocol \(PAP\), used to indicate what kind of action is allowed. | 
| TheHive.Cases.createdBy | string | The user who created the case. | 
| TheHive.Cases.tasks._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Cases.tasks.order | number | The order of the task. | 
| TheHive.Cases.tasks.status | string | Status of the task. | 
| TheHive.Cases.tasks.title | string | Title of the task. | 
| TheHive.Cases.tasks._type | string | Type of the task. | 
| TheHive.Cases.tasks._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.id | string | The ID of the task. | 
| TheHive.Cases.tasks.createdAt | number | Datetime the task was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.createdBy | string | The user who created the task. | 
| TheHive.Cases.tasks.group | string | Group of the task. | 
| TheHive.Cases.tasks.logs.message | string | Log message. | 
| TheHive.Cases.tasks.logs._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Cases.tasks.logs._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Cases.tasks.logs.startDate | number | Datetime the log was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.status | string | Status of the log. | 
| TheHive.Cases.tasks.logs.owner | string | Owner of the log. | 
| TheHive.Cases.tasks.logs._type | string | Type of the log. | 
| TheHive.Cases.tasks.logs._version | number | The version of TheHive Project. | 
| TheHive.Cases.tasks.logs.id | string | The ID of the log. | 
| TheHive.Cases.tasks.logs.createdAt | number | Datetime the task log was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Cases.tasks.logs.createdBy | string | The user who created the log. | 


#### Command Example

```thehive-merge-cases firstCaseID=12402 secondCaseID=49683```

#### Context Example

```json
{
        "_id": "~41443480",
        "id": "~41443480",
        "createdBy": "adrugobitski@paloaltonetworks.com",
        "updatedBy": null,
        "createdAt": 1633374980441,
        "updatedAt": null,
        "_type": "case",
        "caseId": 27,
        "title": "new created case / new created case",
        "description": "description for new case\n\ndescription for new case",
        "severity": 2,
        "startDate": 1632305365797,
        "endDate": null,
        "impactStatus": null,
        "resolutionStatus": null,
        "tags": [],
        "flag": false,
        "tlp": 2,
        "pap": 2,
        "status": "Open",
        "summary": null,
        "owner": "adrugobitski@paloaltonetworks.com",
        "customFields": {},
        "stats": {},
        "permissions": [
            "manageShare", "manageAnalyse", "manageTask",
            "manageCaseTemplate", "manageCase", "manageUser",
            "manageProcedure", "managePage", "manageObservable",
            "manageTag", "manageConfig", "manageAlert",
            "accessTheHiveFS", "manageAction"
        ]}
```

#### Human Readable Output

>### TheHive Linked Cases of ~413824:

>|id|title|description|createdAt|
>|---|---|---|---|
>| ~41443480 | new created case / new created case | description for new case<br><br>description for new case | 2021-10-04T22:16:20Z |



### thehive-get-case-tasks

***
Get the tasks of a case


#### Base Command

`thehive-get-case-tasks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Case ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

```!thehive-get-case-tasks id="~479312"```

#### Context Example

```json
{
    "TheHive": {
        "Tasks": [
            {
                "_createdAt": "2021-10-11T17:36:42Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~585736",
                "_type": "Task",
                "description": "new description",
                "extraData": {
                    "shareCount": 0
                },
                "flag": false,
                "group": "default",
                "logs": [],
                "order": 0,
                "status": "Waiting",
                "title": "newly added task"
            },
            {
                "_createdAt": "2021-10-11T17:36:42Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~581640",
                "_type": "Task",
                "description": "new description",
                "extraData": {
                    "shareCount": 0
                },
                "flag": false,
                "group": "default",
                "logs": [],
                "order": 0,
                "status": "Waiting",
                "title": "newly added task"
            },
            {
                "_createdAt": "2021-10-11T17:02:01Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41500824",
                "_type": "Task",
                "extraData": {
                    "shareCount": 0
                },
                "flag": false,
                "group": "default",
                "logs": [],
                "order": 0,
                "status": "Waiting",
                "title": "task1"
            },
            {
                "_createdAt": "2021-10-11T17:02:01Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~438408",
                "_type": "Task",
                "extraData": {
                    "shareCount": 0
                },
                "flag": false,
                "group": "default",
                "logs": [],
                "order": 0,
                "status": "Waiting",
                "title": "task2"
            },
            {
                "_createdAt": "2021-10-11T17:02:01Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~442504",
                "_type": "Task",
                "extraData": {
                    "shareCount": 0
                },
                "flag": false,
                "group": "default",
                "logs": [],
                "order": 0,
                "status": "Waiting",
                "title": "task3"
            }
        ]
    }
}
```

#### Human Readable Output

>### TheHive Tasks For Case ~479312:

>|_id|title|_createdAt|_createdBy|status|group|
>|---|---|---|---|---|---|
>| ~585736 | newly added task | 2021-10-11T17:36:42Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~581640 | newly added task | 2021-10-11T17:36:42Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~41500824 | task1 | 2021-10-11T17:02:01Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~438408 | task2 | 2021-10-11T17:02:01Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~442504 | task3 | 2021-10-11T17:02:01Z | adrugobitski@paloaltonetworks.com | Waiting | default |


### thehive-get-task

***
Get a specific task.


#### Base Command

`thehive-get-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Task ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Tasks._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Tasks._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Tasks.flag | boolean | A boolean flag used for filtering. | 
| TheHive.Tasks.order | number | The order of the task. | 
| TheHive.Tasks.status | string | Status of the task. | 
| TheHive.Tasks.title | string | Title of the task. | 
| TheHive.Tasks._type | string | Type of the task. | 
| TheHive.Tasks._version | number | The version of TheHive Project. | 
| TheHive.Tasks.id | string | The ID of the task. | 
| TheHive.Tasks.createdAt | number | Datetime the task was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Tasks.createdBy | string | The user who created the task. | 
| TheHive.Tasks.group | string | Group of the task. | 
| TheHive.Tasks.logs.message | string | Log message. | 
| TheHive.Tasks.logs._routing | string | The root level object which the current object belongs to. For example, a log entry is part of a task, which is part of a case. The _routing in this example would point to the ID of the case. | 
| TheHive.Tasks.logs._parent | string | The direct parent level object which the current object belongs to. | 
| TheHive.Tasks.logs.startDate | number | Datetime the log was started on, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Tasks.logs.status | string | Status of the log. | 
| TheHive.Tasks.logs.owner | string | Owner of the log. | 
| TheHive.Tasks.logs._type | string | Type of the log. | 
| TheHive.Tasks.logs._version | number | The version of TheHive Project. | 
| TheHive.Tasks.logs.id | string | The ID of the log. | 
| TheHive.Tasks.logs.createdAt | number | Datetime the task log was created, for example, 2018-06-29 08:15:27.243860. | 
| TheHive.Tasks.logs.createdBy | string | The user who created the task. | 


#### Command Example

```!thehive-get-task id="~41357336"```

#### Human Readable Output

>No task found with id: ~41357336.

### thehive-update-task

***
Updates a task.


#### Base Command

`thehive-update-task`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Task ID. | Required | 
| title | Title of the task. | Optional | 
| status | Status of the task. Possible values are: Waiting, InProgress, Completed, Cancel. | Optional | 
| flag | A boolean flag used for filtering. Possible values are: false, true. | Optional | 
| owner | Owner of the task. | Optional | 
| startDate | Datetime the task was started on, for example, 2018-06-29 08:15:27.243860. | Optional | 
| endDate | Datetime the case ended, for example, 2018-06-29 08:15:27.243860. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

``` ```

#### Human Readable Output



### thehive-list-users

***
Get a list of users.


#### Base Command

`thehive-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example

```!thehive-list-users```

#### Context Example

```json
{
    "TheHive": {
        "Users": [
            {
                "_id": "~8256",
                "_type": "user",
                "createdAt": "2021-04-21T08:27:32Z",
                "createdBy": "rrapoport@paloaltonetworks.com",
                "hasKey": true,
                "id": "adrugobitski@paloaltonetworks.com",
                "login": "adrugobitski@paloaltonetworks.com",
                "name": "name API",
                "organisation": "name",
                "roles": [
                    "admin",
                    "write",
                    "read",
                    "alert"
                ],
                "status": "Ok"
            },
            {
                "_id": "~8440",
                "_type": "user",
                "createdAt": "2021-04-21T08:13:40Z",
                "createdBy": "admin@thehive.local",
                "hasKey": false,
                "id": "rrapoport@paloaltonetworks.com",
                "login": "rrapoport@paloaltonetworks.com",
                "name": "Roman Rapoport",
                "organisation": "name",
                "roles": [
                    "admin",
                    "write",
                    "read",
                    "alert"
                ],
                "status": "Ok"
            },
            {
                "_id": "~24712",
                "_type": "user",
                "createdAt": "2021-07-15T11:40:29Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "hasKey": false,
                "id": "example@example.com",
                "login": "example@example.com",
                "name": "username",
                "organisation": "name",
                "roles": [
                    "read"
                ],
                "status": "Ok"
            },
            {
                "_id": "~28704",
                "_type": "user",
                "createdAt": "2021-07-15T12:06:57Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "hasKey": false,
                "id": "example@example.com",
                "login": "example@example.com",
                "name": "usernamee",
                "organisation": "name",
                "roles": [
                    "read"
                ],
                "status": "Ok"
            },
            {
                "_id": "~32800",
                "_type": "user",
                "createdAt": "2021-07-15T12:16:53Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "hasKey": false,
                "id": "new_example@example.com",
                "login": "new_example@example.com",
                "name": "user_name",
                "organisation": "name",
                "roles": [
                    "read"
                ],
                "status": "Ok"
            },
            {
                "_id": "~41208",
                "_type": "user",
                "createdAt": "2021-07-15T12:17:35Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "hasKey": false,
                "id": "example_2@example.com",
                "login": "example_2@example.com",
                "name": "user_name_2",
                "organisation": "name",
                "roles": [
                    "read"
                ],
                "status": "Ok"
            },
            {
                "_id": "~422136",
                "_type": "user",
                "createdAt": "2021-09-22T10:27:48Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "hasKey": false,
                "id": "name_login@thehive.local",
                "login": "name_login@thehive.local",
                "name": "dem_test",
                "organisation": "name",
                "roles": [
                    "read"
                ],
                "status": "Ok"
            },
            {
                "_id": "~41033880",
                "_type": "user",
                "createdAt": "2021-07-21T09:21:38Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "hasKey": false,
                "id": "example_2@example.com",
                "login": "example_2@example.com",
                "name": "merit",
                "organisation": "name",
                "roles": [
                    "read"
                ],
                "status": "Ok"
            },
            {
                "_id": "~41402520",
                "_type": "user",
                "createdAt": "2021-09-22T10:32:01Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "hasKey": false,
                "id": "test@example.com",
                "login": "test@example.com",
                "name": "testing",
                "organisation": "name",
                "roles": [
                    "read"
                ],
                "status": "Ok"
            }
        ]
    }
}
```

#### Human Readable Output

>### TheHive Users:

>|id|name|roles|status|
>|---|---|---|---|
>| adrugobitski@paloaltonetworks.com | name API | admin,<br/>write,<br/>read,<br/>alert | Ok |
>| rrapoport@paloaltonetworks.com | Roman Rapoport | admin,<br/>write,<br/>read,<br/>alert | Ok |
>| example@example.com | username | read | Ok |
>| example@example.com | usernamee | read | Ok |
>| new_example@example.com | user_name | read | Ok |
>| test@example.com | user_name_2 | read | Ok |
>| name_login@thehive.local | dem_test | read | Ok |
>| example_2@example.com | merit | read | Ok |
>| test@example.com | testing | read | Ok |


### thehive-get-user

***
Get a single user


#### Base Command

`thehive-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

```!thehive-get-user id="~41402520"```

#### Context Example

```json
{
    "TheHive": {
        "Users": {
            "_id": "~41402520",
            "_type": "user",
            "createdAt": "2021-09-22T10:32:01Z",
            "createdBy": "adrugobitski@paloaltonetworks.com",
            "hasKey": false,
            "id": "test@example.com",
            "login": "test@example.com",
            "name": "testing",
            "organisation": "name",
            "roles": [
                "read"
            ],
            "status": "Ok"
        }
    }
}
```

#### Human Readable Output

>### TheHive User ID ~41402520:

>|_id|name|roles|status|organisation|createdAt|
>|---|---|---|---|---|---|
>| ~41402520 | testing | read | Ok | name | 2021-09-22T10:32:01Z |


### thehive-create-local-user

***
Create a new user


#### Base Command

`thehive-create-local-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| login | Username login. | Required | 
| name | Name of the user. | Required | 
| roles | Roles (CSV: can be read, write, admin). Default is read. | Optional | 
| password | Password. | Required | 
| profile | Profile name (only used with TheHive Project v4 and onwards). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```!thehive-create-local-user login=name name=dem password=1234```

#### Context Example

```json
{
    "TheHive": {
        "Users": [
            {
                "_createdAt": 1633973834658,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~593928",
                "hasKey": false,
                "hasMFA": false,
                "hasPassword": false,
                "locked": false,
                "login": "name@example.local",
                "name": "dem",
                "organisation": "name",
                "organisations": [],
                "permissions": [],
                "profile": "read-only"
            },
            {
                "_createdAt": 1633973834659,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~598024",
                "hasKey": false,
                "hasMFA": false,
                "hasPassword": false,
                "locked": false,
                "login": "name@example.loc",
                "name": "dem",
                "organisation": "name",
                "organisations": [],
                "permissions": [],
                "profile": "read-only"
            }
        ]
    }
}
```

#### Human Readable Output

>### New User ~593928:

>|_id|login|name|profile|
>|---|---|---|---|
>| ~593928 | name@example.local | dem | read-only |


### thehive-block-user

***
Block a user


#### Base Command

`thehive-block-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

```!thehive-block-user id="~41208"```

#### Human Readable Output

>User "~41208" blocked successfully

### thehive-list-observables

***
List observables for a case.


#### Base Command

`thehive-list-observables`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Case ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Observables | string | List of observables for a case. | 


#### Command Example

```!thehive-list-observables id="~561160"```

#### Context Example

```json
{
    "TheHive": {
        "Observables": [
            {
                "_createdAt": 1633972384854,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41504920",
                "_type": "Observable",
                "data": "google",
                "dataType": "domain",
                "extraData": {
                    "permissions": [
                        "manageShare",
                        "manageAnalyse",
                        "manageTask",
                        "manageCaseTemplate",
                        "manageCase",
                        "manageUser",
                        "manageProcedure",
                        "managePage",
                        "manageObservable",
                        "manageTag",
                        "manageConfig",
                        "manageAlert",
                        "accessTheHiveFS",
                        "manageAction"
                    ],
                    "seen": {
                        "ioc": false,
                        "seen": 0
                    },
                    "shareCount": 0
                },
                "ignoreSimilarity": false,
                "ioc": false,
                "message": "observable 2",
                "reports": {},
                "sighted": false,
                "startDate": 1633972384854,
                "tags": [],
                "tlp": 1
            },
            {
                "_createdAt": 1633972365905,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~532512",
                "_type": "Observable",
                "data": "8.8.8.8",
                "dataType": "ip",
                "extraData": {
                    "permissions": [
                        "manageShare",
                        "manageAnalyse",
                        "manageTask",
                        "manageCaseTemplate",
                        "manageCase",
                        "manageUser",
                        "manageProcedure",
                        "managePage",
                        "manageObservable",
                        "manageTag",
                        "manageConfig",
                        "manageAlert",
                        "accessTheHiveFS",
                        "manageAction"
                    ],
                    "seen": {
                        "ioc": false,
                        "seen": 0
                    },
                    "shareCount": 0
                },
                "ignoreSimilarity": false,
                "ioc": false,
                "message": "observable 1",
                "reports": {},
                "sighted": false,
                "startDate": 1633972365905,
                "tags": [],
                "tlp": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Observables for Case ~561160:

>|data|dataType|message|
>|---|---|---|
>| google | domain | observable 2 |
>| 8.8.8.8 | ip | observable 1 |


### thehive-create-observable

***
Creates an observable.


#### Base Command

`thehive-create-observable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Case ID. | Required | 
| data | Data of the observable. | Required | 
| dataType | Data type of the observable. Possible values are: autonomous-system, domain, file, filename, fqdn, hash, ip, mail, mail_subject, other, regexp, registry, uri_path, url, user-agent. Default is other. | Required | 
| message | Observable message. | Required | 
| startDate | Datetime the observable was started on, for example, 2018-06-29 08:15:27.243860. | Optional | 
| tlp | Traffic Light Protocol designation for the observable. Possible values are: WHITE, GREEN, AMBER, RED. | Optional | 
| ioc | Is the observable an IOC?. Possible values are: true, false. | Optional | 
| status | Status of the observable. Possible values are: Ok, Deleted. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

``` ```

#### Human Readable Output



### thehive-update-observable

***
Update an observable.


#### Base Command

`thehive-update-observable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Observable ID. | Required | 
| message | Observable message. | Required | 
| tlp | Traffic Light Protocol designation for the observable. Possible values are: WHITE, GREEN, AMBER, RED. | Optional | 
| ioc | Is the observable an IOC?. Possible values are: true, false. | Optional | 
| status | Status of the observable. Possible values are: Ok, Deleted. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example

```!thehive-update-observable id="~41504920" message="updated message for observable"```

#### Context Example

```json
{
    "TheHive": {
        "Observables": {
            "_id": "~41504920",
            "_type": "case_artifact",
            "createdAt": 1633972384854,
            "createdBy": "adrugobitski@paloaltonetworks.com",
            "data": "google",
            "dataType": "domain",
            "id": "~41504920",
            "ignoreSimilarity": false,
            "ioc": false,
            "message": "updated message for observable",
            "reports": {},
            "sighted": false,
            "startDate": 1633972384854,
            "stats": {},
            "tags": [],
            "tlp": 1,
            "updatedAt": 1633973833004,
            "updatedBy": "adrugobitski@paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### Updated Observable:

>|id|data|dataType|message|
>|---|---|---|---|
>| ~41504920 | google | domain | updated message for observable |


### get-mapping-fields

***
Returns the list of fields.


#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example

``` ```

#### Human Readable Output



### get-remote-data

***
Get remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.


#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ticket ID. | Required | 
| lastUpdate | Retrieve entries that were created after lastUpdate. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

``` ```

#### Human Readable Output



### thehive-get-version

***
Displays the version of TheHive Project.


#### Base Command

`thehive-get-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example

```!thehive-get-version```

#### Human Readable Output

>4.1.4-1

### get-modified-remote-data

***
Gets the list of incidents that were modified since the last update time. Note that this method is here for debugging purposes. The get-modified-remote-data command is used as part of a Mirroring feature, which is available from version 6.1.


#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example

``` ```

#### Human Readable Output

