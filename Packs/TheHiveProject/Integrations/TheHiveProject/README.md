Integration with The Hive Project Security Incident Response Platform.
This integration was integrated and tested with version xx of TheHive Project

## Configure TheHive Project on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TheHive Project.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### thehive-list-cases
***
List cases.


#### Base Command

`thehive-list-cases`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | _routing | 
| TheHive.Cases._parent | string | _parent | 
| TheHive.Cases.customFields | unknown | Custom Fields | 
| TheHive.Cases.caseId | number | Case ID | 
| TheHive.Cases.flag | boolean | Flagged | 
| TheHive.Cases.startDate | number | Start date | 
| TheHive.Cases.status | string | Status | 
| TheHive.Cases.owner | string | Owner | 
| TheHive.Cases.tlp | number | TLP | 
| TheHive.Cases.title | string | Title | 
| TheHive.Cases.tags | unknown | Tags | 
| TheHive.Cases._type | string | _type | 
| TheHive.Cases._version | number | _version | 
| TheHive.Cases._id | string | _id | 
| TheHive.Cases.id | string | ID | 
| TheHive.Cases.createdAt | number | Created at | 
| TheHive.Cases.description | string | Description | 
| TheHive.Cases.severity | number | Severity | 
| TheHive.Cases.pap | number | PAP | 
| TheHive.Cases.createdBy | string | Created by | 
| TheHive.Cases.tasks._routing | string | _routing | 
| TheHive.Cases.tasks._parent | string | _parent | 
| TheHive.Cases.tasks.flag | boolean | Flagged | 
| TheHive.Cases.tasks.order | number | Order | 
| TheHive.Cases.tasks.status | string | Status | 
| TheHive.Cases.tasks.title | string | Title | 
| TheHive.Cases.tasks._type | string | _type | 
| TheHive.Cases.tasks._version | number | _version | 
| TheHive.Cases.tasks._id | string | _id | 
| TheHive.Cases.tasks.id | string | ID | 
| TheHive.Cases.tasks.createdAt | number | Created at | 
| TheHive.Cases.tasks.createdBy | string | Created by | 
| TheHive.Cases.tasks.group | string | Group | 
| TheHive.Cases.tasks.logs.message | string | Message | 
| TheHive.Cases.tasks.logs._routing | string | _routing | 
| TheHive.Cases.tasks.logs._parent | string | _parent | 
| TheHive.Cases.tasks.logs.startDate | number | Start date | 
| TheHive.Cases.tasks.logs.status | string | Status | 
| TheHive.Cases.tasks.logs.owner | string | Owner | 
| TheHive.Cases.tasks.logs._type | string | Type | 
| TheHive.Cases.tasks.logs._version | number | _version | 
| TheHive.Cases.tasks.logs._id | string | _id | 
| TheHive.Cases.tasks.logs.id | string | ID | 
| TheHive.Cases.tasks.logs.createdAt | number | Created at | 
| TheHive.Cases.tasks.logs.createdBy | string | Created by | 


#### Command Example
```!thehive-list-cases```

#### Context Example
```json
{
    "TheHive": {
        "Cases": [
            {
                "_id": "~41324616",
                "_type": "case",
                "caseId": 2,
                "createdAt": "2021-09-19T09:22:28Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~41324616",
                "impactStatus": null,
                "instance": "TheHive Project_instance_1",
                "mirroring": "Both",
                "observables": [
                    {
                        "_createdAt": 1632316225834,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~41418904",
                        "_type": "Observable",
                        "data": "datas for test 2",
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
                        "ioc": false,
                        "message": "messages for test 2",
                        "reports": {},
                        "sighted": false,
                        "startDate": 1632316225834,
                        "tags": [],
                        "tlp": 2
                    },
                    {
                        "_createdAt": 1632316030325,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~41377816",
                        "_type": "Observable",
                        "data": "datas for test",
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
                        "ioc": false,
                        "message": "messages for test",
                        "reports": {},
                        "sighted": false,
                        "startDate": 1632316030325,
                        "tags": [],
                        "tlp": 2
                    },
                    {
                        "_createdAt": 1632307576963,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~446472",
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
                        "ioc": false,
                        "message": "new observable",
                        "reports": {},
                        "sighted": false,
                        "startDate": 1632307576963,
                        "tags": [],
                        "tlp": 2
                    },
                    {
                        "_createdAt": 1632306875578,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~442400",
                        "_type": "Observable",
                        "data": "demisto",
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
                                "seen": 1
                            },
                            "shareCount": 0
                        },
                        "ioc": false,
                        "message": "test observ",
                        "reports": {},
                        "sighted": false,
                        "startDate": 1632306875578,
                        "tags": [],
                        "tlp": 2
                    },
                    {
                        "_createdAt": 1632306875561,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~41345048",
                        "_type": "Observable",
                        "data": "demisto",
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
                        "ioc": false,
                        "message": "test observ",
                        "reports": {},
                        "sighted": false,
                        "startDate": 1632306875561,
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
                "startDate": 1632043348213,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [
                    {
                        "_createdAt": 1632307981876,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~430144",
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
                        "_createdAt": 1632307981851,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~454688",
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
                        "_createdAt": 1632307552125,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~323720",
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
                        "_createdAt": 1632307552231,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~430328",
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
                        "_createdAt": 1632308185938,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~462856",
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
                        "_createdAt": 1632308185978,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~331912",
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
                        "_createdAt": 1632307008722,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~41357336",
                        "_type": "Task",
                        "description": "desc for task 1",
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
                        "_createdAt": 1632307008686,
                        "_createdBy": "adrugobitski@paloaltonetworks.com",
                        "_id": "~41349144",
                        "_type": "Task",
                        "description": "desc for task 1",
                        "extraData": {
                            "shareCount": 0
                        },
                        "flag": false,
                        "group": "default",
                        "logs": [],
                        "order": 0,
                        "status": "Waiting",
                        "title": "task1"
                    }
                ],
                "title": "updated title",
                "tlp": 2,
                "updatedAt": 1632316446722,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~352336",
                "_type": "case",
                "caseId": 4,
                "createdAt": "2021-09-22T10:01:26Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~352336",
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
                "startDate": 1632304886335,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632304906505,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~409848",
                "_type": "case",
                "caseId": 5,
                "createdAt": "2021-09-22T10:01:26Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~409848",
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
                "startDate": 1632304886343,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632304908785,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~413944",
                "_type": "case",
                "caseId": 6,
                "createdAt": "2021-09-22T10:03:12Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~413944",
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
                "startDate": 1632304992384,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632305031043,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~430088",
                "_type": "case",
                "caseId": 7,
                "createdAt": "2021-09-22T10:09:25Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~430088",
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
                "startDate": 1632305365792,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632305391510,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~364624",
                "_type": "case",
                "caseId": 8,
                "createdAt": "2021-09-22T10:09:25Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~364624",
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
                "startDate": 1632305365797,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632305392665,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~418040",
                "_type": "case",
                "caseId": 9,
                "createdAt": "2021-09-22T10:03:12Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~418040",
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
                "startDate": 1632304992392,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632305031833,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~413824",
                "_type": "case",
                "caseId": 12,
                "createdAt": "2021-09-22T10:53:00Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~413824",
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
                "startDate": 1632307980064,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632308031147,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~458760",
                "_type": "case",
                "caseId": 14,
                "createdAt": "2021-09-22T10:56:23Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~458760",
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
                "startDate": 1632308183798,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632308211253,
                "updatedBy": "adrugobitski@paloaltonetworks.com"
            },
            {
                "_id": "~327816",
                "_type": "case",
                "caseId": 15,
                "createdAt": "2021-09-22T10:53:00Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~327816",
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
                "startDate": 1632307980076,
                "stats": {},
                "status": "Open",
                "summary": null,
                "tags": [],
                "tasks": [],
                "title": "new created case",
                "tlp": 2,
                "updatedAt": 1632308031887,
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
>| ~41324616 | updated title | description for new case | 2021-09-19T09:22:28Z |
>| ~352336 | new created case | description for new case | 2021-09-22T10:01:26Z |
>| ~409848 | new created case | description for new case | 2021-09-22T10:01:26Z |
>| ~413944 | new created case | description for new case | 2021-09-22T10:03:12Z |
>| ~430088 | new created case | description for new case | 2021-09-22T10:09:25Z |
>| ~364624 | new created case | description for new case | 2021-09-22T10:09:25Z |
>| ~418040 | new created case | description for new case | 2021-09-22T10:03:12Z |
>| ~413824 | new created case | description for new case | 2021-09-22T10:53:00Z |
>| ~458760 | new created case | description for new case | 2021-09-22T10:56:23Z |
>| ~327816 | new created case | description for new case | 2021-09-22T10:53:00Z |


### thehive-get-case
***
Get a case


#### Base Command

`thehive-get-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | _routing | 
| TheHive.Cases._parent | string | _parent | 
| TheHive.Cases.customFields | unknown | Custom Fields | 
| TheHive.Cases.caseId | number | Case ID | 
| TheHive.Cases.flag | boolean | Flagged | 
| TheHive.Cases.startDate | number | Start date | 
| TheHive.Cases.status | string | Status | 
| TheHive.Cases.owner | string | Owner | 
| TheHive.Cases.tlp | number | TLP | 
| TheHive.Cases.title | string | Title | 
| TheHive.Cases.tags | unknown | Tags | 
| TheHive.Cases._type | string | _type | 
| TheHive.Cases._version | number | _version | 
| TheHive.Cases._id | string | _id | 
| TheHive.Cases.id | string | ID | 
| TheHive.Cases.createdAt | number | Created at | 
| TheHive.Cases.description | string | Description | 
| TheHive.Cases.severity | number | Severity | 
| TheHive.Cases.pap | number | PAP | 
| TheHive.Cases.createdBy | string | Created by | 
| TheHive.Cases.tasks._routing | string | _routing | 
| TheHive.Cases.tasks._parent | string | _parent | 
| TheHive.Cases.tasks.flag | boolean | Flagged | 
| TheHive.Cases.tasks.order | number | Order | 
| TheHive.Cases.tasks.status | string | Status | 
| TheHive.Cases.tasks.title | string | Title | 
| TheHive.Cases.tasks._type | string | _type | 
| TheHive.Cases.tasks._version | number | _version | 
| TheHive.Cases.tasks._id | string | _id | 
| TheHive.Cases.tasks.id | string | ID | 
| TheHive.Cases.tasks.createdAt | number | Created at | 
| TheHive.Cases.tasks.createdBy | string | Created by | 
| TheHive.Cases.tasks.group | string | Group | 
| TheHive.Cases.tasks.logs.message | string | Message | 
| TheHive.Cases.tasks.logs._routing | string | _routing | 
| TheHive.Cases.tasks.logs._parent | string | _parent | 
| TheHive.Cases.tasks.logs.startDate | number | Start date | 
| TheHive.Cases.tasks.logs.status | string | Status | 
| TheHive.Cases.tasks.logs.owner | string | Owner | 
| TheHive.Cases.tasks.logs._type | string | Type | 
| TheHive.Cases.tasks.logs._version | number | _version | 
| TheHive.Cases.tasks.logs._id | string | _id | 
| TheHive.Cases.tasks.logs.id | string | ID | 
| TheHive.Cases.tasks.logs.createdAt | number | Created at | 
| TheHive.Cases.tasks.logs.createdBy | string | Created by | 


#### Command Example
```!thehive-get-case id="~41324616"```

#### Context Example
```json
{
    "TheHive": {
        "Cases": {
            "_id": "~41324616",
            "_type": "case",
            "caseId": 2,
            "createdAt": "2021-09-19T09:22:28Z",
            "createdBy": "adrugobitski@paloaltonetworks.com",
            "customFields": {},
            "description": "description for new case",
            "endDate": null,
            "flag": false,
            "id": "~41324616",
            "impactStatus": null,
            "observables": [
                {
                    "_createdAt": 1632316225834,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~41418904",
                    "_type": "Observable",
                    "data": "datas for test 2",
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
                    "ioc": false,
                    "message": "messages for test 2",
                    "reports": {},
                    "sighted": false,
                    "startDate": 1632316225834,
                    "tags": [],
                    "tlp": 2
                },
                {
                    "_createdAt": 1632316030325,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~41377816",
                    "_type": "Observable",
                    "data": "datas for test",
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
                    "ioc": false,
                    "message": "messages for test",
                    "reports": {},
                    "sighted": false,
                    "startDate": 1632316030325,
                    "tags": [],
                    "tlp": 2
                },
                {
                    "_createdAt": 1632307576963,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~446472",
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
                    "ioc": false,
                    "message": "new observable",
                    "reports": {},
                    "sighted": false,
                    "startDate": 1632307576963,
                    "tags": [],
                    "tlp": 2
                },
                {
                    "_createdAt": 1632306875578,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~442400",
                    "_type": "Observable",
                    "data": "demisto",
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
                            "seen": 1
                        },
                        "shareCount": 0
                    },
                    "ioc": false,
                    "message": "test observ",
                    "reports": {},
                    "sighted": false,
                    "startDate": 1632306875578,
                    "tags": [],
                    "tlp": 2
                },
                {
                    "_createdAt": 1632306875561,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~41345048",
                    "_type": "Observable",
                    "data": "demisto",
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
                    "ioc": false,
                    "message": "test observ",
                    "reports": {},
                    "sighted": false,
                    "startDate": 1632306875561,
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
            "startDate": 1632043348213,
            "stats": {},
            "status": "Open",
            "summary": null,
            "tags": [],
            "tasks": [
                {
                    "_createdAt": 1632307981876,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~430144",
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
                    "_createdAt": 1632307981851,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~454688",
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
                    "_createdAt": 1632307552125,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~323720",
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
                    "_createdAt": 1632307552231,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~430328",
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
                    "_createdAt": 1632308185938,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~462856",
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
                    "_createdAt": 1632308185978,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~331912",
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
                    "_createdAt": 1632307008722,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~41357336",
                    "_type": "Task",
                    "description": "desc for task 1",
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
                    "_createdAt": 1632307008686,
                    "_createdBy": "adrugobitski@paloaltonetworks.com",
                    "_id": "~41349144",
                    "_type": "Task",
                    "description": "desc for task 1",
                    "extraData": {
                        "shareCount": 0
                    },
                    "flag": false,
                    "group": "default",
                    "logs": [],
                    "order": 0,
                    "status": "Waiting",
                    "title": "task1"
                }
            ],
            "title": "updated title",
            "tlp": 2,
            "updatedAt": 1632316446722,
            "updatedBy": "adrugobitski@paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### TheHive Case ID ~41324616:
>|id|title|description|createdAt|
>|---|---|---|---|
>| ~41324616 | updated title | description for new case | 2021-09-19T09:22:28Z |


### thehive-update-case
***
Update a case


#### Base Command

`thehive-update-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID. | Required | 
| title | Title. | Optional | 
| description | Description. | Optional | 
| severity | Severity. Possible values are: 1, 2, 3. | Optional | 
| startDate | Start date. | Optional | 
| owner | Owner. | Optional | 
| flag | Flag. Possible values are: true, false. | Optional | 
| tlp | TLP. Possible values are: WHITE, GREEN, AMBER, RED. | Optional | 
| tags | Tags (can be CSV). | Optional | 
| resolutionStatus | Resolution status. Possible values are: Indeterminate, FalsePositive, TruePositive, Other, Duplicated. | Optional | 
| impactStatus | Impact status. Possible values are: NoImpact, WithImpact, NotApplicable. | Optional | 
| summary | Summary. | Optional | 
| endDate | End date. | Optional | 
| metrics | Metrics. | Optional | 
| status | Status. Possible values are: Open, Resolved, Deleted. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | _routing | 
| TheHive.Cases._parent | string | _parent | 
| TheHive.Cases.customFields | unknown | Custom Fields | 
| TheHive.Cases.caseId | number | Case ID | 
| TheHive.Cases.flag | boolean | Flagged | 
| TheHive.Cases.startDate | number | Start date | 
| TheHive.Cases.status | string | Status | 
| TheHive.Cases.owner | string | Owner | 
| TheHive.Cases.tlp | number | TLP | 
| TheHive.Cases.title | string | Title | 
| TheHive.Cases.tags | unknown | Tags | 
| TheHive.Cases._type | string | _type | 
| TheHive.Cases._version | number | _version | 
| TheHive.Cases._id | string | _id | 
| TheHive.Cases.id | string | ID | 
| TheHive.Cases.createdAt | number | Created at | 
| TheHive.Cases.description | string | Description | 
| TheHive.Cases.severity | number | Severity | 
| TheHive.Cases.pap | number | PAP | 
| TheHive.Cases.createdBy | string | Created by | 
| TheHive.Cases.tasks._routing | string | _routing | 
| TheHive.Cases.tasks._parent | string | _parent | 
| TheHive.Cases.tasks.flag | boolean | Flagged | 
| TheHive.Cases.tasks.order | number | Order | 
| TheHive.Cases.tasks.status | string | Status | 
| TheHive.Cases.tasks.title | string | Title | 
| TheHive.Cases.tasks._type | string | _type | 
| TheHive.Cases.tasks._version | number | _version | 
| TheHive.Cases.tasks._id | string | _id | 
| TheHive.Cases.tasks.id | string | ID | 
| TheHive.Cases.tasks.createdAt | number | Created at | 
| TheHive.Cases.tasks.createdBy | string | Created by | 
| TheHive.Cases.tasks.group | string | Group | 
| TheHive.Cases.tasks.logs.message | string | Message | 
| TheHive.Cases.tasks.logs._routing | string | _routing | 
| TheHive.Cases.tasks.logs._parent | string | _parent | 
| TheHive.Cases.tasks.logs.startDate | number | Start date | 
| TheHive.Cases.tasks.logs.status | string | Status | 
| TheHive.Cases.tasks.logs.owner | string | Owner | 
| TheHive.Cases.tasks.logs._type | string | Type | 
| TheHive.Cases.tasks.logs._version | number | _version | 
| TheHive.Cases.tasks.logs._id | string | _id | 
| TheHive.Cases.tasks.logs.id | string | ID | 
| TheHive.Cases.tasks.logs.createdAt | number | Created at | 
| TheHive.Cases.tasks.logs.createdBy | string | Created by | 


#### Command Example
```!thehive-update-case id="~41324616" title="updated title"```

#### Context Example
```json
{
    "TheHive": {
        "Cases": {
            "_id": "~41324616",
            "_type": "case",
            "caseId": 2,
            "createdAt": "2021-09-19T09:22:28Z",
            "createdBy": "adrugobitski@paloaltonetworks.com",
            "customFields": {},
            "description": "description for new case",
            "endDate": null,
            "flag": false,
            "id": "~41324616",
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
            "startDate": 1632043348213,
            "stats": {},
            "status": "Open",
            "summary": null,
            "tags": [],
            "title": "updated title",
            "tlp": 2,
            "updatedAt": 1632316670768,
            "updatedBy": "adrugobitski@paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### TheHive Update Case ID ~41324616:
>|id|title|description|createdAt|
>|---|---|---|---|
>| ~41324616 | updated title | description for new case | 2021-09-19T09:22:28Z |


### thehive-create-case
***
Create a new case


#### Base Command

`thehive-create-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Title. | Required | 
| description | Description. | Required | 
| severity | Severity 9default = 2). Possible values are: 1, 2, 3. | Optional | 
| startDate | Start date (default = now). | Optional | 
| owner | Owner. | Required | 
| flag | Flag (defaul = false). Possible values are: false, true. | Optional | 
| tlp | TLP (default = 2). Possible values are: 0, 1, 2, 3. | Optional | 
| tags | Tags (can be CSV). | Optional | 
| resolutionStatus | Resolution status. | Optional | 
| impactStatus | Imapct status. Possible values are: NoImpact, WithImpact, qNotApplicable. | Optional | 
| summary | Summary. | Optional | 
| endDate | End date. | Optional | 
| metrics | Metrics. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | _routing | 
| TheHive.Cases._parent | string | _parent | 
| TheHive.Cases.customFields | unknown | Custom Fields | 
| TheHive.Cases.caseId | number | Case ID | 
| TheHive.Cases.flag | boolean | Flagged | 
| TheHive.Cases.startDate | number | Start date | 
| TheHive.Cases.status | string | Status | 
| TheHive.Cases.owner | string | Owner | 
| TheHive.Cases.tlp | number | TLP | 
| TheHive.Cases.title | string | Title | 
| TheHive.Cases.tags | unknown | Tags | 
| TheHive.Cases._type | string | _type | 
| TheHive.Cases._version | number | _version | 
| TheHive.Cases._id | string | _id | 
| TheHive.Cases.id | string | ID | 
| TheHive.Cases.createdAt | number | Created at | 
| TheHive.Cases.description | string | Description | 
| TheHive.Cases.severity | number | Severity | 
| TheHive.Cases.pap | number | PAP | 
| TheHive.Cases.createdBy | string | Created by | 
| TheHive.Cases.tasks._routing | string | _routing | 
| TheHive.Cases.tasks._parent | string | _parent | 
| TheHive.Cases.tasks.flag | boolean | Flagged | 
| TheHive.Cases.tasks.order | number | Order | 
| TheHive.Cases.tasks.status | string | Status | 
| TheHive.Cases.tasks.title | string | Title | 
| TheHive.Cases.tasks._type | string | _type | 
| TheHive.Cases.tasks._version | number | _version | 
| TheHive.Cases.tasks._id | string | _id | 
| TheHive.Cases.tasks.id | string | ID | 
| TheHive.Cases.tasks.createdAt | number | Created at | 
| TheHive.Cases.tasks.createdBy | string | Created by | 
| TheHive.Cases.tasks.group | string | Group | 
| TheHive.Cases.tasks.logs.message | string | Message | 
| TheHive.Cases.tasks.logs._routing | string | _routing | 
| TheHive.Cases.tasks.logs._parent | string | _parent | 
| TheHive.Cases.tasks.logs.startDate | number | Start date | 
| TheHive.Cases.tasks.logs.status | string | Status | 
| TheHive.Cases.tasks.logs.owner | string | Owner | 
| TheHive.Cases.tasks.logs._type | string | Type | 
| TheHive.Cases.tasks.logs._version | number | _version | 
| TheHive.Cases.tasks.logs._id | string | _id | 
| TheHive.Cases.tasks.logs.id | string | ID | 
| TheHive.Cases.tasks.logs.createdAt | number | Created at | 
| TheHive.Cases.tasks.logs.createdBy | string | Created by | 


#### Command Example
```!thehive-create-case title="new created case" description="description for new case" owner="demisto"```

#### Context Example
```json
{
    "TheHive": {
        "Cases": [
            {
                "_id": "~454904",
                "_type": "case",
                "caseId": 16,
                "createdAt": "2021-09-22T13:17:52Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~454904",
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
                "startDate": 1632316672635,
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
                "_id": "~385104",
                "_type": "case",
                "caseId": 17,
                "createdAt": "2021-09-22T13:17:52Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "customFields": {},
                "description": "description for new case",
                "endDate": null,
                "flag": false,
                "id": "~385104",
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
                "startDate": 1632316672673,
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
>| ~454904 | new created case | description for new case | 2021-09-22T13:17:52Z |


### thehive-create-task
***
Create a new task


#### Base Command

`thehive-create-task`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Case Id. | Required | 
| title | Title. | Required | 
| description | Description. | Optional | 
| startDate | Start date (default = now). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Tasks.status | string | Status | 
| TheHive.TasKs.title | string | Title | 
| TheHive.Tasks.id | string | ID | 
| TheHive.Tasks.createdAt | number | Created at | 
| TheHive.Tasks._type | string | Type | 
| TheHive.Tasks.createdBy | string | Created by | 
| TheHive.Tasks.group | string | Group | 
| TheHive.Tasks.flag | boolean | Flag | 
| TheHive.Tasks.order | int | Order | 


#### Command Example
```!thehive-create-task id="~41324616" title="newly added task" description="new description"```

#### Context Example
```json
{
    "TheHive": {
        "Tasks": [
            {
                "_id": "~41381960",
                "_type": "case_task",
                "createdAt": "2021-09-22T13:17:54Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "description": "new description",
                "flag": false,
                "group": "default",
                "id": "~41381960",
                "order": 0,
                "status": "Waiting",
                "title": "newly added task"
            },
            {
                "_id": "~41386056",
                "_type": "case_task",
                "createdAt": "2021-09-22T13:17:54Z",
                "createdBy": "adrugobitski@paloaltonetworks.com",
                "description": "new description",
                "flag": false,
                "group": "default",
                "id": "~41386056",
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
>| ~41381960 | newly added task | 2021-09-22T13:17:54Z | Waiting |


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
``` ```

#### Human Readable Output



### thehive-merge-cases
***
Merges 2 cases


#### Base Command

`thehive-merge-cases`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firstCaseID | First case ID. | Required | 
| secondCaseID | Second case ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TheHive.Cases._routing | string | _routing | 
| TheHive.Cases._parent | string | _parent | 
| TheHive.Cases.customFields | unknown | Custom Fields | 
| TheHive.Cases.caseId | number | Case ID | 
| TheHive.Cases.flag | boolean | Flagged | 
| TheHive.Cases.startDate | number | Start date | 
| TheHive.Cases.status | string | Status | 
| TheHive.Cases.owner | string | Owner | 
| TheHive.Cases.tlp | number | TLP | 
| TheHive.Cases.title | string | Title | 
| TheHive.Cases.tags | unknown | Tags | 
| TheHive.Cases._type | string | _type | 
| TheHive.Cases._version | number | _version | 
| TheHive.Cases._id | string | _id | 
| TheHive.Cases.id | string | ID | 
| TheHive.Cases.createdAt | number | Created at | 
| TheHive.Cases.description | string | Description | 
| TheHive.Cases.severity | number | Severity | 
| TheHive.Cases.pap | number | PAP | 
| TheHive.Cases.createdBy | string | Created by | 
| TheHive.Cases.tasks._routing | string | _routing | 
| TheHive.Cases.tasks._parent | string | _parent | 
| TheHive.Cases.tasks.flag | boolean | Flagged | 
| TheHive.Cases.tasks.order | number | Order | 
| TheHive.Cases.tasks.status | string | Status | 
| TheHive.Cases.tasks.title | string | Title | 
| TheHive.Cases.tasks._type | string | _type | 
| TheHive.Cases.tasks._version | number | _version | 
| TheHive.Cases.tasks._id | string | _id | 
| TheHive.Cases.tasks.id | string | ID | 
| TheHive.Cases.tasks.createdAt | number | Created at | 
| TheHive.Cases.tasks.createdBy | string | Created by | 
| TheHive.Cases.tasks.group | string | Group | 
| TheHive.Cases.tasks.logs.message | string | Message | 
| TheHive.Cases.tasks.logs._routing | string | _routing | 
| TheHive.Cases.tasks.logs._parent | string | _parent | 
| TheHive.Cases.tasks.logs.startDate | number | Start date | 
| TheHive.Cases.tasks.logs.status | string | Status | 
| TheHive.Cases.tasks.logs.owner | string | Owner | 
| TheHive.Cases.tasks.logs._type | string | Type | 
| TheHive.Cases.tasks.logs._version | number | _version | 
| TheHive.Cases.tasks.logs._id | string | _id | 
| TheHive.Cases.tasks.logs.id | string | ID | 
| TheHive.Cases.tasks.logs.createdAt | number | Created at | 
| TheHive.Cases.tasks.logs.createdBy | string | Created by | 


#### Command Example
``` ```

#### Human Readable Output



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
```!thehive-get-case-tasks id="~41324616"```

#### Context Example
```json
{
    "TheHive": {
        "Tasks": [
            {
                "_createdAt": "2021-09-22T10:53:01Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~430144",
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
                "_createdAt": "2021-09-22T10:53:01Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~454688",
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
                "_createdAt": "2021-09-22T10:45:52Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~323720",
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
                "_createdAt": "2021-09-22T10:45:52Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~430328",
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
                "_createdAt": "2021-09-22T10:56:25Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~331912",
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
                "_createdAt": "2021-09-22T10:56:25Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~462856",
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
                "_createdAt": "2021-09-22T13:17:54Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41381960",
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
                "_createdAt": "2021-09-22T13:17:54Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41386056",
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
                "_createdAt": "2021-09-22T10:36:48Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41357336",
                "_type": "Task",
                "description": "desc for task 1",
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
                "_createdAt": "2021-09-22T10:36:48Z",
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41349144",
                "_type": "Task",
                "description": "desc for task 1",
                "extraData": {
                    "shareCount": 0
                },
                "flag": false,
                "group": "default",
                "logs": [],
                "order": 0,
                "status": "Waiting",
                "title": "task1"
            }
        ]
    }
}
```

#### Human Readable Output

>### TheHive Tasks For Case ~41324616:
>|_id|title|_createdAt|_createdBy|status|group|
>|---|---|---|---|---|---|
>| ~430144 | newly added task | 2021-09-22T10:53:01Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~454688 | newly added task | 2021-09-22T10:53:01Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~323720 | newly added task | 2021-09-22T10:45:52Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~430328 | newly added task | 2021-09-22T10:45:52Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~331912 | newly added task | 2021-09-22T10:56:25Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~462856 | newly added task | 2021-09-22T10:56:25Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~41381960 | newly added task | 2021-09-22T13:17:54Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~41386056 | newly added task | 2021-09-22T13:17:54Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~41357336 | task1 | 2021-09-22T10:36:48Z | adrugobitski@paloaltonetworks.com | Waiting | default |
>| ~41349144 | task1 | 2021-09-22T10:36:48Z | adrugobitski@paloaltonetworks.com | Waiting | default |


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
| TheHive.Tasks._routing | string | _routing | 
| TheHive.Tasks._parent | string | _parent | 
| TheHive.Tasks.flag | boolean | Flagged | 
| TheHive.Tasks.order | number | Order | 
| TheHive.Tasks.status | string | Status | 
| TheHive.Tasks.title | string | Title | 
| TheHive.Tasks._type | string | _type | 
| TheHive.Tasks._version | number | _version | 
| TheHive.Tasks._id | string | _id | 
| TheHive.Tasks.id | string | ID | 
| TheHive.Tasks.createdAt | number | Created at | 
| TheHive.Tasks.createdBy | string | Created by | 
| TheHive.Tasks.group | string | Group | 
| TheHive.Tasks.logs.message | string | Message | 
| TheHive.Tasks.logs._routing | string | _routing | 
| TheHive.Tasks.logs._parent | string | _parent | 
| TheHive.Tasks.logs.startDate | number | Start date | 
| TheHive.Tasks.logs.status | string | Status | 
| TheHive.Tasks.logs.owner | string | Owner | 
| TheHive.Tasks.logs._type | string | Type | 
| TheHive.Tasks.logs._version | number | _version | 
| TheHive.Tasks.logs._id | string | _id | 
| TheHive.Tasks.logs.id | string | ID | 
| TheHive.Tasks.logs.createdAt | number | Created at | 
| TheHive.Tasks.logs.createdBy | string | Task ID | 


#### Command Example
``` ```

#### Human Readable Output



### thehive-get-attachment
***
Retrieves an attachment from a log.


#### Base Command

`thehive-get-attachment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Attachmenmt ID. | Required | 
| name | Attachment Name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### thehive-update-task
***
Updates a task.


#### Base Command

`thehive-update-task`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Task ID. | Required | 
| title | Title. | Optional | 
| status | Status. Possible values are: Waiting, InProgress, Completed, Cancel. | Optional | 
| flag | Flag. Possible values are: false, true. | Optional | 
| owner | Owner. | Optional | 
| startDate | Start date. | Optional | 
| endDate | End date. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### thehive-list-users
***
Get a list of users


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
                "name": "Demisto API",
                "organisation": "Demisto",
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
                "organisation": "Demisto",
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
                "id": "user@thehive.local",
                "login": "user@thehive.local",
                "name": "username",
                "organisation": "Demisto",
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
                "id": "userr@thehive.local",
                "login": "userr@thehive.local",
                "name": "usernamee",
                "organisation": "Demisto",
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
                "id": "new_user@thehive.local",
                "login": "new_user@thehive.local",
                "name": "user_name",
                "organisation": "Demisto",
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
                "id": "new_user_2@thehive.local",
                "login": "new_user_2@thehive.local",
                "name": "user_name_2",
                "organisation": "Demisto",
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
                "id": "demisto_login@thehive.local",
                "login": "demisto_login@thehive.local",
                "name": "dem_test",
                "organisation": "Demisto",
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
                "id": "meretmaayta@gmail.com",
                "login": "meretmaayta@gmail.com",
                "name": "merit",
                "organisation": "Demisto",
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
                "id": "test@thehive.local",
                "login": "test@thehive.local",
                "name": "testing",
                "organisation": "Demisto",
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
>| adrugobitski@paloaltonetworks.com | Demisto API | admin,<br/>write,<br/>read,<br/>alert | Ok |
>| rrapoport@paloaltonetworks.com | Roman Rapoport | admin,<br/>write,<br/>read,<br/>alert | Ok |
>| user@thehive.local | username | read | Ok |
>| userr@thehive.local | usernamee | read | Ok |
>| new_user@thehive.local | user_name | read | Ok |
>| new_user_2@thehive.local | user_name_2 | read | Ok |
>| demisto_login@thehive.local | dem_test | read | Ok |
>| meretmaayta@gmail.com | merit | read | Ok |
>| test@thehive.local | testing | read | Ok |


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
``` ```

#### Human Readable Output



### thehive-create-local-user
***
Create a new user


#### Base Command

`thehive-create-local-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| login | Login username. | Required | 
| name | Name. | Required | 
| roles | Roles (CSV: can be read, write, admin). Default is read. | Optional | 
| password | Password. | Required | 
| profile | Profile name (only used with TheHive Project v4 onwards). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
| TheHive.Observables | string | list of observables for a case | 


#### Command Example
```!thehive-list-observables id="~41324616"```

#### Context Example
```json
{
    "TheHive": {
        "Observables": [
            {
                "_createdAt": 1632316225834,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41418904",
                "_type": "Observable",
                "data": "datas for test 2",
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
                "ioc": false,
                "message": "messages for test 2",
                "reports": {},
                "sighted": false,
                "startDate": 1632316225834,
                "tags": [],
                "tlp": 2
            },
            {
                "_createdAt": 1632316030325,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41377816",
                "_type": "Observable",
                "data": "datas for test",
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
                "ioc": false,
                "message": "messages for test",
                "reports": {},
                "sighted": false,
                "startDate": 1632316030325,
                "tags": [],
                "tlp": 2
            },
            {
                "_createdAt": 1632307576963,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~446472",
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
                "ioc": false,
                "message": "new observable",
                "reports": {},
                "sighted": false,
                "startDate": 1632307576963,
                "tags": [],
                "tlp": 2
            },
            {
                "_createdAt": 1632306875578,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~442400",
                "_type": "Observable",
                "data": "demisto",
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
                        "seen": 1
                    },
                    "shareCount": 0
                },
                "ioc": false,
                "message": "test observ",
                "reports": {},
                "sighted": false,
                "startDate": 1632306875578,
                "tags": [],
                "tlp": 2
            },
            {
                "_createdAt": 1632306875561,
                "_createdBy": "adrugobitski@paloaltonetworks.com",
                "_id": "~41345048",
                "_type": "Observable",
                "data": "demisto",
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
                "ioc": false,
                "message": "test observ",
                "reports": {},
                "sighted": false,
                "startDate": 1632306875561,
                "tags": [],
                "tlp": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Observables for Case ~41324616:
>|data|dataType|message|
>|---|---|---|
>| datas for test 2 | domain | messages for test 2 |
>| datas for test | domain | messages for test |
>| google | domain | new observable |
>| demisto | domain | test observ |
>| demisto | domain | test observ |


### thehive-create-observable
***
Creates an observable.


#### Base Command

`thehive-create-observable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Case ID. | Required | 
| data | Data. | Required | 
| dataType | Data type. Possible values are: autonomous-system, domain, file, filename, fqdn, hash, ip, mail, mail_subject, other, regexp, registry, uri_path, url, user-agent. Default is other. | Required | 
| message | Message. | Required | 
| startDate | Start date. | Optional | 
| tlp | TLP. Possible values are: WHITE, GREEN, AMBER, RED. | Optional | 
| ioc | Is IOC?. Possible values are: true, false. | Optional | 
| status | Status. Possible values are: Ok, Deleted. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### thehive-update-observable
***
Update an observable


#### Base Command

`thehive-update-observable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Observable ID. | Required | 
| message | Message. | Required | 
| tlp | TLP. Possible values are: WHITE, GREEN, AMBER, RED. | Optional | 
| ioc | Is IOC?. Possible values are: true, false. | Optional | 
| status | Status. Possible values are: Ok, Deleted. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



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
Displays the version of TheHive Project


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


