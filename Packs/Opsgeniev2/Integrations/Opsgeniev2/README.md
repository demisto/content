Integration with Atlassian OpsGenie V2
This integration was integrated and tested with version 1.0.0 of Opsgeniev2
## Configure Opsgeniev2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://example.net) |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| API Token | Must be created from the Teams API Integration section. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### list-alerts
***
List the current alerts from OpsGenie.


#### Base Command

`list-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum results to return. | Optional | 
| sort | OpsGenie field to sort by. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.Alerts.acknowledged | Boolean | State of Acknoweledgement | 
| OpsGenieV2.Alerts.alias | String | Alert Alias | 
| OpsGenieV2.Alerts.count | Number | Count of Alert occurences | 
| OpsGenieV2.Alerts.createdAt | Date | Time alert created | 
| OpsGenieV2.Alerts.id | String | ID of alert | 
| OpsGenieV2.Alerts.integration.id | String | ID of integration  | 
| OpsGenieV2.Alerts.integration.name | String | Integration name | 
| OpsGenieV2.Alerts.integration.type | String | Type of integration | 
| OpsGenieV2.Alerts.isSeen | Boolean | Whether alert has been seen | 
| OpsGenieV2.Alerts.lastOccurredAt | Date | Time alert last occured | 
| OpsGenieV2.Alerts.message | String | Alert Message | 
| OpsGenieV2.Alerts.owner | String | Owner of Alert | 
| OpsGenieV2.Alerts.ownerTeamId | String | Team ID of Owner | 
| OpsGenieV2.Alerts.priority | String | Alert Priority | 
| OpsGenieV2.Alerts.responders.id | String | ID of responders | 
| OpsGenieV2.Alerts.responders.type | String | Type of Responders | 
| OpsGenieV2.Alerts.seen | Boolean | Seen status of alert | 
| OpsGenieV2.Alerts.snoozed | Boolean | Whether alert has been snoozed | 
| OpsGenieV2.Alerts.source | String | Source of Alert | 
| OpsGenieV2.Alerts.status | String | Status of Alert | 
| OpsGenieV2.Alerts.teams.id | String | ID Of teams associated with Alert | 
| OpsGenieV2.Alerts.tinyId | String | Shorter ID for alert | 
| OpsGenieV2.Alerts.updatedAt | Date | Last Updated time for Alert | 
| OpsGenieV2.Alerts.report.ackTime | Number | Acknoweledgement Time of Alert | 
| OpsGenieV2.Alerts.report.acknowledgedBy | String | User that Acknolwedged the alert | 
| OpsGenieV2.Alerts.report.closeTime | Number | Time Alarm closed | 
| OpsGenieV2.Alerts.report.closedBy | String | Who Closed the alarm | 


#### Command Example
```!list-alerts```

#### Context Example
```json
{
    "OpsGenieV2": {
        "Alerts": [
            {
                "acknowledged": false,
                "alias": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
                "count": 1,
                "createdAt": "2021-02-15T01:49:39.202Z",
                "id": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-15T01:49:39.202Z",
                "message": "New message",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "73",
                "updatedAt": "2021-02-15T01:49:39.355Z"
            },
            {
                "acknowledged": true,
                "alias": "86289902-7b8d-487b-a6fd-dd8677389b5e-1613353749160",
                "count": 1,
                "createdAt": "2021-02-15T01:49:09.16Z",
                "id": "86289902-7b8d-487b-a6fd-dd8677389b5e-1613353749160",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-15T01:49:09.16Z",
                "message": "New message",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 11751,
                    "acknowledgedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "72",
                "updatedAt": "2021-02-15T01:49:20.919Z"
            },
            {
                "acknowledged": true,
                "alias": "44d3f112-deda-4d96-a926-53d8332f98c7-1613353704532",
                "count": 1,
                "createdAt": "2021-02-15T01:48:24.532Z",
                "id": "44d3f112-deda-4d96-a926-53d8332f98c7-1613353704532",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-15T01:48:24.532Z",
                "message": "New message",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 16244,
                    "acknowledgedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "71",
                "updatedAt": "2021-02-15T01:48:40.782Z"
            },
            {
                "acknowledged": false,
                "alias": "adbf2272-0ebc-4145-af9d-c11fe27d47f3-1613352695968",
                "count": 1,
                "createdAt": "2021-02-15T01:31:35.968Z",
                "id": "adbf2272-0ebc-4145-af9d-c11fe27d47f3-1613352695968",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-15T01:31:35.968Z",
                "message": "Example Message",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "69",
                "updatedAt": "2021-02-15T01:41:36.227Z"
            },
            {
                "acknowledged": false,
                "alias": "163332e0-14ed-4821-89b7-aeb36381df0d-1613349877062",
                "count": 1,
                "createdAt": "2021-02-15T00:44:37.062Z",
                "id": "163332e0-14ed-4821-89b7-aeb36381df0d-1613349877062",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-15T00:44:37.062Z",
                "message": "Example Message",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "68",
                "updatedAt": "2021-02-15T00:54:37.274Z"
            },
            {
                "acknowledged": false,
                "alias": "d9d73a3a-66cf-4eb1-9cfd-453a40850cfe-1613349713803",
                "count": 1,
                "createdAt": "2021-02-15T00:41:53.803Z",
                "id": "d9d73a3a-66cf-4eb1-9cfd-453a40850cfe-1613349713803",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-15T00:41:53.803Z",
                "message": "Example Message",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "67",
                "updatedAt": "2021-02-15T00:51:54.093Z"
            },
            {
                "acknowledged": true,
                "alias": "2c1c6f71-0d8c-4594-b844-167b16b40ea8-1613343943249",
                "count": 1,
                "createdAt": "2021-02-14T23:05:43.249Z",
                "id": "2c1c6f71-0d8c-4594-b844-167b16b40ea8-1613343943249",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-14T23:05:43.249Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 4606,
                    "acknowledgedBy": "Alert API",
                    "closeTime": 7991,
                    "closedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "closed",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "65",
                "updatedAt": "2021-02-14T23:05:51.24Z"
            },
            {
                "acknowledged": true,
                "alias": "5304918a-65b8-4b9a-a94e-3fa81fd98c89-1613343620579",
                "count": 1,
                "createdAt": "2021-02-14T23:00:20.579Z",
                "id": "5304918a-65b8-4b9a-a94e-3fa81fd98c89-1613343620579",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-14T23:00:20.579Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 4202,
                    "acknowledgedBy": "Alert API",
                    "closeTime": 7668,
                    "closedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "closed",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "64",
                "updatedAt": "2021-02-14T23:00:28.247Z"
            },
            {
                "acknowledged": true,
                "alias": "6e66c6c6-2345-4c49-8ae6-0dd5b79e65d0-1613343498469",
                "count": 1,
                "createdAt": "2021-02-14T22:58:18.469Z",
                "id": "6e66c6c6-2345-4c49-8ae6-0dd5b79e65d0-1613343498469",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-14T22:58:18.469Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 3877,
                    "acknowledgedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "63",
                "updatedAt": "2021-02-14T23:08:18.747Z"
            },
            {
                "acknowledged": true,
                "alias": "a94d2fdb-1cef-4319-b2a7-fb53454349be-1613206184020",
                "count": 1,
                "createdAt": "2021-02-13T08:49:44.02Z",
                "id": "a94d2fdb-1cef-4319-b2a7-fb53454349be-1613206184020",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-13T08:49:44.02Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 4123,
                    "acknowledgedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "62",
                "updatedAt": "2021-02-13T08:59:44.205Z"
            },
            {
                "acknowledged": true,
                "alias": "d1df5d6b-c377-4620-90b0-f8a417f1178b-1613205322391",
                "count": 1,
                "createdAt": "2021-02-13T08:35:22.391Z",
                "id": "d1df5d6b-c377-4620-90b0-f8a417f1178b-1613205322391",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-13T08:35:22.391Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 4076,
                    "acknowledgedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "61",
                "updatedAt": "2021-02-13T08:45:22.635Z"
            },
            {
                "acknowledged": false,
                "alias": "a1d2ae21-0ffb-4d9e-958f-00033c5539df-1613205203431",
                "count": 1,
                "createdAt": "2021-02-13T08:33:23.431Z",
                "id": "a1d2ae21-0ffb-4d9e-958f-00033c5539df-1613205203431",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-13T08:33:23.431Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "60",
                "updatedAt": "2021-02-13T08:43:23.671Z"
            },
            {
                "acknowledged": true,
                "alias": "068acc9f-da9c-4448-ab3f-47a0df662b99-1613204276847",
                "count": 1,
                "createdAt": "2021-02-13T08:17:56.847Z",
                "id": "068acc9f-da9c-4448-ab3f-47a0df662b99-1613204276847",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-13T08:17:56.847Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 3952,
                    "acknowledgedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "59",
                "updatedAt": "2021-02-13T08:27:57.035Z"
            },
            {
                "acknowledged": true,
                "alias": "cf0856d9-fd36-4248-8e20-101ecf0794c6-1613203908260",
                "count": 1,
                "createdAt": "2021-02-13T08:11:48.26Z",
                "id": "cf0856d9-fd36-4248-8e20-101ecf0794c6-1613203908260",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-13T08:11:48.26Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 3639,
                    "acknowledgedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "58",
                "updatedAt": "2021-02-13T08:21:48.528Z"
            },
            {
                "acknowledged": true,
                "alias": "792fbca4-819f-4b62-9620-2e9450d14930-1613191892008",
                "count": 1,
                "createdAt": "2021-02-13T04:51:32.008Z",
                "id": "792fbca4-819f-4b62-9620-2e9450d14930-1613191892008",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": true,
                "lastOccurredAt": "2021-02-13T04:51:32.008Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "Alert API",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "report": {
                    "ackTime": 3867,
                    "acknowledgedBy": "Alert API"
                },
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": true,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "57",
                "updatedAt": "2021-02-13T05:01:32.181Z"
            },
            {
                "acknowledged": false,
                "alias": "17dbe463-26e8-424f-a258-47562b0226b4-1613191624068",
                "count": 1,
                "createdAt": "2021-02-13T04:47:04.068Z",
                "id": "17dbe463-26e8-424f-a258-47562b0226b4-1613191624068",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-13T04:47:04.068Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "56",
                "updatedAt": "2021-02-13T04:57:04.294Z"
            },
            {
                "acknowledged": false,
                "alias": "0d0b57ae-0e99-4834-81dc-ae1d706714fc-1613191556613",
                "count": 1,
                "createdAt": "2021-02-13T04:45:56.613Z",
                "id": "0d0b57ae-0e99-4834-81dc-ae1d706714fc-1613191556613",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-13T04:45:56.613Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "55",
                "updatedAt": "2021-02-13T04:55:56.819Z"
            },
            {
                "acknowledged": false,
                "alias": "c6d8e0a7-0668-447c-a8f4-90136c26aaea-1613191144692",
                "count": 1,
                "createdAt": "2021-02-13T04:39:04.693Z",
                "id": "c6d8e0a7-0668-447c-a8f4-90136c26aaea-1613191144692",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-13T04:39:04.693Z",
                "message": "This is a message from the test opsgenie playbook.",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "54",
                "updatedAt": "2021-02-13T04:49:04.991Z"
            },
            {
                "acknowledged": false,
                "alias": "8ba1bb77-69bf-4e47-a77c-2548e97e7ded-1613190814551",
                "count": 1,
                "createdAt": "2021-02-13T04:33:34.551Z",
                "id": "8ba1bb77-69bf-4e47-a77c-2548e97e7ded-1613190814551",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-13T04:33:34.551Z",
                "message": "Test Alert From XSOAR",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "53",
                "updatedAt": "2021-02-13T04:43:34.844Z"
            },
            {
                "acknowledged": false,
                "alias": "c39c3863-5da0-45c2-b75a-f16eec9aa10d-1613120280203",
                "count": 1,
                "createdAt": "2021-02-12T08:58:00.203Z",
                "id": "c39c3863-5da0-45c2-b75a-f16eec9aa10d-1613120280203",
                "integration": {
                    "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                    "name": "XSOAR_LAB_API",
                    "type": "API"
                },
                "isSeen": false,
                "lastOccurredAt": "2021-02-12T08:58:00.203Z",
                "message": "This is a test alert!",
                "owner": "",
                "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "priority": "P3",
                "responders": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                        "type": "team"
                    }
                ],
                "seen": false,
                "snoozed": false,
                "source": "2.2.2.3",
                "status": "open",
                "tags": [],
                "teams": [
                    {
                        "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                    }
                ],
                "tinyId": "50",
                "updatedAt": "2021-02-12T09:08:00.481Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### OpsGenie Alerts
>|id|message|createdAt|
>|---|---|---|
>| 37816db1-844e-449f-bf61-b28834cad50f-1613353779202 | New message | 2021-02-15T01:49:39.202Z |
>| 86289902-7b8d-487b-a6fd-dd8677389b5e-1613353749160 | New message | 2021-02-15T01:49:09.16Z |
>| 44d3f112-deda-4d96-a926-53d8332f98c7-1613353704532 | New message | 2021-02-15T01:48:24.532Z |
>| adbf2272-0ebc-4145-af9d-c11fe27d47f3-1613352695968 | Example Message | 2021-02-15T01:31:35.968Z |
>| 163332e0-14ed-4821-89b7-aeb36381df0d-1613349877062 | Example Message | 2021-02-15T00:44:37.062Z |
>| d9d73a3a-66cf-4eb1-9cfd-453a40850cfe-1613349713803 | Example Message | 2021-02-15T00:41:53.803Z |
>| 2c1c6f71-0d8c-4594-b844-167b16b40ea8-1613343943249 | This is a message from the test opsgenie playbook. | 2021-02-14T23:05:43.249Z |
>| 5304918a-65b8-4b9a-a94e-3fa81fd98c89-1613343620579 | This is a message from the test opsgenie playbook. | 2021-02-14T23:00:20.579Z |
>| 6e66c6c6-2345-4c49-8ae6-0dd5b79e65d0-1613343498469 | This is a message from the test opsgenie playbook. | 2021-02-14T22:58:18.469Z |
>| a94d2fdb-1cef-4319-b2a7-fb53454349be-1613206184020 | This is a message from the test opsgenie playbook. | 2021-02-13T08:49:44.02Z |
>| d1df5d6b-c377-4620-90b0-f8a417f1178b-1613205322391 | This is a message from the test opsgenie playbook. | 2021-02-13T08:35:22.391Z |
>| a1d2ae21-0ffb-4d9e-958f-00033c5539df-1613205203431 | This is a message from the test opsgenie playbook. | 2021-02-13T08:33:23.431Z |
>| 068acc9f-da9c-4448-ab3f-47a0df662b99-1613204276847 | This is a message from the test opsgenie playbook. | 2021-02-13T08:17:56.847Z |
>| cf0856d9-fd36-4248-8e20-101ecf0794c6-1613203908260 | This is a message from the test opsgenie playbook. | 2021-02-13T08:11:48.26Z |
>| 792fbca4-819f-4b62-9620-2e9450d14930-1613191892008 | This is a message from the test opsgenie playbook. | 2021-02-13T04:51:32.008Z |
>| 17dbe463-26e8-424f-a258-47562b0226b4-1613191624068 | This is a message from the test opsgenie playbook. | 2021-02-13T04:47:04.068Z |
>| 0d0b57ae-0e99-4834-81dc-ae1d706714fc-1613191556613 | This is a message from the test opsgenie playbook. | 2021-02-13T04:45:56.613Z |
>| c6d8e0a7-0668-447c-a8f4-90136c26aaea-1613191144692 | This is a message from the test opsgenie playbook. | 2021-02-13T04:39:04.693Z |
>| 8ba1bb77-69bf-4e47-a77c-2548e97e7ded-1613190814551 | Test Alert From XSOAR | 2021-02-13T04:33:34.551Z |
>| c39c3863-5da0-45c2-b75a-f16eec9aa10d-1613120280203 | This is a test alert! | 2021-02-12T08:58:00.203Z |


### create-alert
***
 


#### Base Command

`create-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | Alert message. | Required | 
| alias | Client-defined identifier of the alert. | Optional | 
| description | Description field of the alert that is generally used to provide a detailed information about the alert. | Optional | 
| responders | Dictionary of team/user/escalation/schedule for notifications. Dictionary containing type and ID. | Optional | 
| priority | Incident Priority. Possible values are: P1, P2, P3, P4, P5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.CreatedAlert.action | String | Action of this Request | 
| OpsGenieV2.CreatedAlert.alertId | String | ID Of created Alert | 
| OpsGenieV2.CreatedAlert.alias | String | Alais of created Alert | 
| OpsGenieV2.CreatedAlert.integrationId | String | Integration of created Alert | 
| OpsGenieV2.CreatedAlert.isSuccess | Boolean | If the request was successful  | 
| OpsGenieV2.CreatedAlert.processedAt | Date | When the request was processed | 
| OpsGenieV2.CreatedAlert.requestId | String | The ID of the request | 
| OpsGenieV2.CreatedAlert.status | String | The human readable result of the request | 
| OpsGenieV2.CreatedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!create-alert message="Example Message"```

#### Context Example
```json
{
    "OpsGenieV2": {
        "CreatedAlert": {
            "action": "Create",
            "alertId": "b4b23e8b-4003-453d-9200-7735641a272d-1613353863148",
            "alias": "b4b23e8b-4003-453d-9200-7735641a272d-1613353863148",
            "integrationId": "26aaa576-0434-4b17-bc39-602a02fe417c",
            "isSuccess": true,
            "processedAt": "2021-02-15T01:51:03.198Z",
            "requestId": "c660d3a0-7827-49f1-989a-98d358cc4ca2",
            "status": "Created alert",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Created Alert
>|action|alertId|alias|integrationId|isSuccess|processedAt|requestId|status|success|
>|---|---|---|---|---|---|---|---|---|
>| Create | b4b23e8b-4003-453d-9200-7735641a272d-1613353863148 | b4b23e8b-4003-453d-9200-7735641a272d-1613353863148 | 26aaa576-0434-4b17-bc39-602a02fe417c | true | 2021-02-15T01:51:03.198Z | c660d3a0-7827-49f1-989a-98d358cc4ca2 | Created alert | true |


### delete-alert
***
Delete an Alert from OpsGenie


#### Base Command

`delete-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.DeletedAlert.action | String | Action of this Request | 
| OpsGenieV2.DeletedAlert.alertId | String | ID Of Deleted Alert | 
| OpsGenieV2.DeletedAlert.alias | String | Alais of created Alert | 
| OpsGenieV2.DeletedAlert.integrationId | String | Integration of created Alert | 
| OpsGenieV2.DeletedAlert.isSuccess | Boolean | If the request was successful  | 
| OpsGenieV2.DeletedAlert.processedAt | Date | When the request was processed | 
| OpsGenieV2.DeletedAlert.requestId | String | The ID of the request | 
| OpsGenieV2.DeletedAlert.status | String | The human readable result of the request | 
| OpsGenieV2.DeletedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!delete-alert alert-id=37816db1-844e-449f-bf61-b28834cad50f-1613353779202```

#### Context Example
```json
{
    "OpsGenieV2": {
        "DeletedAlert": {
            "action": "Delete",
            "alertId": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
            "alias": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
            "integrationId": "26aaa576-0434-4b17-bc39-602a02fe417c",
            "isSuccess": true,
            "processedAt": "2021-02-15T01:51:22.876Z",
            "requestId": "6c0c5320-0849-4726-adf7-0480cf9fc7c4",
            "status": "Deleted alert",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Deleted Alert
>|action|alertId|alias|integrationId|isSuccess|processedAt|requestId|status|success|
>|---|---|---|---|---|---|---|---|---|
>| Delete | 37816db1-844e-449f-bf61-b28834cad50f-1613353779202 | 37816db1-844e-449f-bf61-b28834cad50f-1613353779202 | 26aaa576-0434-4b17-bc39-602a02fe417c | true | 2021-02-15T01:51:22.876Z | 6c0c5320-0849-4726-adf7-0480cf9fc7c4 | Deleted alert | true |


### get-alert
***
Delete an Alert from OpsGenie


#### Base Command

`get-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.Alert.acknowledged | Boolean | State of Acknoweledgement  | 
| OpsGenieV2.Alert.alias | String | Alert Alias | 
| OpsGenieV2.Alert.count | Number | Count of Alert occurences | 
| OpsGenieV2.Alert.createdAt | Date | Time alert created | 
| OpsGenieV2.Alert.id | String | ID of alert | 
| OpsGenieV2.Alert.integration.id | String | ID of integration  | 
| OpsGenieV2.Alert.integration.name | String | Integration name | 
| OpsGenieV2.Alert.integration.type | String | Type of integration | 
| OpsGenieV2.Alert.isSeen | Boolean | Whether alert has been seen | 
| OpsGenieV2.Alert.lastOccurredAt | Date | Time alert last occured | 
| OpsGenieV2.Alert.message | String | Alert Message | 
| OpsGenieV2.Alert.owner | String | Owner of Alert | 
| OpsGenieV2.Alert.ownerTeamId | String | Team ID of Owner | 
| OpsGenieV2.Alert.priority | String | Alert Priority | 
| OpsGenieV2.Alert.responders.id | String | ID of responders | 
| OpsGenieV2.Alert.responders.type | String | Type of Responders | 
| OpsGenieV2.Alert.seen | Boolean | Seen status of alert | 
| OpsGenieV2.Alert.snoozed | Boolean | Whether alert has been snoozed | 
| OpsGenieV2.Alert.source | String | Source of Alert | 
| OpsGenieV2.Alert.status | String | Status of Alert | 
| OpsGenieV2.Alert.teams.id | String | ID Of teams associated with Alert | 
| OpsGenieV2.Alert.tinyId | String | Shorter ID for alert | 
| OpsGenieV2.Alert.updatedAt | Date | Last Updated time for Alert | 
| OpsGenieV2.Alert.report.ackTime | Number | Acknoweledgement Time of Alert | 
| OpsGenieV2.Alert.report.acknowledgedBy | String | User that Acknolwedged the alert | 
| OpsGenieV2.Alert.report.closeTime | Number | Time Alarm closed | 
| OpsGenieV2.Alert.report.closedBy | String | Who Closed the alarm | 


#### Command Example
```!get-alert alert-id=37816db1-844e-449f-bf61-b28834cad50f-1613353779202```

#### Context Example
```json
{
    "OpsGenieV2": {
        "Alert": {
            "acknowledged": false,
            "actions": [],
            "alias": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
            "count": 1,
            "createdAt": "2021-02-15T01:49:39.202Z",
            "description": "",
            "details": {},
            "entity": "",
            "id": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
            "integration": {
                "id": "26aaa576-0434-4b17-bc39-602a02fe417c",
                "name": "XSOAR_LAB_API",
                "type": "API"
            },
            "isSeen": false,
            "lastOccurredAt": "2021-02-15T01:49:39.202Z",
            "message": "New message",
            "owner": "",
            "ownerTeamId": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
            "priority": "P3",
            "responders": [
                {
                    "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                    "type": "team"
                }
            ],
            "seen": false,
            "snoozed": false,
            "source": "2.2.2.3",
            "status": "open",
            "tags": [],
            "teams": [
                {
                    "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2"
                }
            ],
            "tinyId": "73",
            "updatedAt": "2021-02-15T01:49:39.355Z"
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Alert
>|message|acknowledged|seen|owner|count|
>|---|---|---|---|---|
>| New message | false | false |  | 1 |


### ack-alert
***
Acknowledge an alert in OpsGenie


#### Base Command

`ack-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.AckedAlert.action | String | Action of this Request | 
| OpsGenieV2.AckedAlert.alertId | String | ID Of created Alert | 
| OpsGenieV2.AckedAlert.alias | String | Alais of created Alert | 
| OpsGenieV2.AckedAlert.integrationId | String | Integration of created Alert | 
| OpsGenieV2.AckedAlert.isSuccess | Boolean | If the request was successful  | 
| OpsGenieV2.AckedAlert.processedAt | Date | When the request was processed | 
| OpsGenieV2.AckedAlert.requestId | String | The ID of the request | 
| OpsGenieV2.AckedAlert.status | String | The human readable result of the request | 
| OpsGenieV2.AckedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!ack-alert alert-id=37816db1-844e-449f-bf61-b28834cad50f-1613353779202```

#### Context Example
```json
{
    "OpsGenieV2": {
        "AckedAlert": {
            "action": "Acknowledge",
            "alertId": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
            "alias": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
            "integrationId": "26aaa576-0434-4b17-bc39-602a02fe417c",
            "isSuccess": true,
            "processedAt": "2021-02-15T01:51:11.973Z",
            "requestId": "204f7523-fce4-489a-9d38-083c8269d339",
            "status": "Acknowledged alert",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Ack Alert
>|action|alertId|alias|integrationId|isSuccess|processedAt|requestId|status|success|
>|---|---|---|---|---|---|---|---|---|
>| Acknowledge | 37816db1-844e-449f-bf61-b28834cad50f-1613353779202 | 37816db1-844e-449f-bf61-b28834cad50f-1613353779202 | 26aaa576-0434-4b17-bc39-602a02fe417c | true | 2021-02-15T01:51:11.973Z | 204f7523-fce4-489a-9d38-083c8269d339 | Acknowledged alert | true |


### get-schedule
***
Retrieve the provided Schedule (by ID) from LR


#### Base Command

`get-schedule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule-id | Schedule to retrieve from LR. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.Schedule.description | String | Description of Schedule | 
| OpsGenieV2.Schedule.enabled | Boolean | If this schedule is enabled | 
| OpsGenieV2.Schedule.id | String | ID Of schedule | 
| OpsGenieV2.Schedule.name | String | Name of Schedule | 
| OpsGenieV2.Schedule.ownerTeam.id | String | ID Of the team owning this schedule | 
| OpsGenieV2.Schedule.ownerTeam.name | String | Name of Team owning this Schedule | 
| OpsGenieV2.Schedule.rotations.id | String | ID of rotations on this Schedule | 
| OpsGenieV2.Schedule.rotations.length | Number | Length of Rotations on this Schedule | 
| OpsGenieV2.Schedule.rotations.name | String | Name of Rotation on this Schedule | 
| OpsGenieV2.Schedule.rotations.participants.id | String | ID Of Partipant attached to this schedule | 
| OpsGenieV2.Schedule.rotations.participants.type | String | Type of Participant attached to this Schedule | 
| OpsGenieV2.Schedule.rotations.participants.username | String | Username of Participant Attached to this Schedule | 
| OpsGenieV2.Schedule.rotations.startDate | Date | Start Date of this Schedule | 
| OpsGenieV2.Schedule.rotations.type | String | Type of this Rotation | 
| OpsGenieV2.Schedule.timezone | String | Timezone of this Schedule | 


#### Command Example
```!get-schedule schedule-id=092748e8-c17d-4e53-99da-e84345f06a90```

#### Context Example
```json
{
    "OpsGenieV2": {
        "Schedule": {
            "description": "",
            "enabled": true,
            "id": "092748e8-c17d-4e53-99da-e84345f06a90",
            "name": "Test_schedule",
            "ownerTeam": {
                "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                "name": "Test"
            },
            "rotations": [
                {
                    "id": "05e2a465-24dd-427b-b251-2e2298a9804e",
                    "length": 1,
                    "name": "Rot1",
                    "participants": [
                        {
                            "id": "7f072844-38a7-4de7-b2ff-2a51ffbabe7b",
                            "type": "user",
                            "username": "john@doe.com"
                        }
                    ],
                    "startDate": "2021-01-31T13:00:00Z",
                    "type": "weekly"
                }
            ],
            "timezone": "Australia/Sydney"
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Schedule
>|id|name|timezone|
>|---|---|---|
>| 092748e8-c17d-4e53-99da-e84345f06a90 | Test_schedule | Australia/Sydney |


### list-schedules
***
List Schedules


#### Base Command

`list-schedules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Max number of results to return. | Optional | 
| sort | OpsGenie field to sort on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.Schedules.description | String | Description of Schedule | 
| OpsGenieV2.Schedules.enabled | Boolean | If this schedule is enabled | 
| OpsGenieV2.Schedules.id | String | ID Of schedule | 
| OpsGenieV2.Schedules.name | String | Name of Schedule | 
| OpsGenieV2.Schedules.ownerTeam.id | String | ID Of the team owning this schedule | 
| OpsGenieV2.Schedules.ownerTeam.name | String | Name of Team owning this Schedule | 
| OpsGenieV2.Schedules.rotations.id | String | ID of rotations on this Schedule | 
| OpsGenieV2.Schedules.rotations.length | Number | Length of Rotations on this Schedule | 
| OpsGenieV2.Schedules.rotations.name | String | Name of Rotation on this Schedule | 
| OpsGenieV2.Schedules.rotations.participants.id | String | ID Of Partipant attached to this schedule | 
| OpsGenieV2.Schedules.rotations.participants.type | String | Type of Participant attached to this Schedule | 
| OpsGenieV2.Schedules.rotations.participants.username | String | Username of Participant Attached to this Schedule | 
| OpsGenieV2.Schedules.rotations.startDate | Date | Start Date of this Schedule | 
| OpsGenieV2.Schedules.rotations.type | String | Type of this Rotation | 
| OpsGenieV2.Schedules.timezone | String | Timezone of this Schedule | 


#### Command Example
```!list-schedules```

#### Context Example
```json
{
    "OpsGenieV2": {
        "Schedules": [
            {
                "description": "",
                "enabled": true,
                "id": "092748e8-c17d-4e53-99da-e84345f06a90",
                "name": "Test_schedule",
                "ownerTeam": {
                    "id": "1f8b92b4-37f1-4b50-9380-92250b3f3bc2",
                    "name": "Test"
                },
                "rotations": [],
                "timezone": "Australia/Sydney"
            }
        ]
    }
}
```

#### Human Readable Output

>### OpsGenie Schedules
>|description|id|name|timezone|
>|---|---|---|---|
>|  | 092748e8-c17d-4e53-99da-e84345f06a90 | Test_schedule | Australia/Sydney |


### get-on-call
***
Get the on-call users for the provided schedule


#### Base Command

`get-on-call`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule-id | Schedule from which to return on-call users. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.OnCall._parent.enabled | Boolean | If this OnCall is Enabled | 
| OpsGenieV2.OnCall._parent.id | String | ID Of parent schedule | 
| OpsGenieV2.OnCall._parent.name | String | Name of parent Schedule | 
| OpsGenieV2.OnCall.onCallParticipants.id | String | ID Of oncall participant | 
| OpsGenieV2.OnCall.onCallParticipants.name | String | Name of oncall participant | 
| OpsGenieV2.OnCall.onCallParticipants.type | String | Type of OnCall participant | 


#### Command Example
```!get-on-call schedule-id=092748e8-c17d-4e53-99da-e84345f06a90```

#### Context Example
```json
{
    "OpsGenieV2": {
        "OnCall": {
            "_parent": {
                "enabled": true,
                "id": "092748e8-c17d-4e53-99da-e84345f06a90",
                "name": "Test_schedule"
            },
            "onCallParticipants": [
                {
                    "id": "7f072844-38a7-4de7-b2ff-2a51ffbabe7b",
                    "name": "john@doe.com",
                    "type": "user"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### OpsGenie OnCall Participants
>|id|name|type|
>|---|---|---|
>| 7f072844-38a7-4de7-b2ff-2a51ffbabe7b | john@doe.com | user |


### close-alert
***
Close an OpsGenie Alert


#### Base Command

`close-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | ID Of opsgenie alert. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.CloseAlert.action | String | Action of this Request | 
| OpsGenieV2.CloseAlert.alertId | String | ID Of created Alert | 
| OpsGenieV2.CloseAlert.alias | String | Alais of created Alert | 
| OpsGenieV2.CloseAlert.integrationId | String | Integration of created Alert | 
| OpsGenieV2.CloseAlert.isSuccess | Boolean | If the request was successful  | 
| OpsGenieV2.CloseAlert.processedAt | Date | When the request was processed | 
| OpsGenieV2.CloseAlert.requestId | String | The ID of the request | 
| OpsGenieV2.CloseAlert.status | String | The human readable result of the request | 
| OpsGenieV2.CloseAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!close-alert alert-id=37816db1-844e-449f-bf61-b28834cad50f-1613353779202```

#### Context Example
```json
{
    "OpsGenieV2": {
        "CloseAlert": {
            "action": "Close",
            "alertId": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
            "alias": "37816db1-844e-449f-bf61-b28834cad50f-1613353779202",
            "integrationId": "26aaa576-0434-4b17-bc39-602a02fe417c",
            "isSuccess": true,
            "processedAt": "2021-02-15T01:51:17.434Z",
            "requestId": "73b0d979-9cd1-4159-970a-0aef37eb89bd",
            "status": "Closed alert",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Close Alert
>**No entries.**


### opsgenie-list-alerts

***
List the current alerts from OpsGenie.

#### Base Command

`opsgenie-list-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum results to return. | Optional | 
| sort | OpsGenie field to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.Alerts.acknowledged | Boolean | State of Acknoweledgement | 
| OpsGenieV2.Alerts.alias | String | Alert Alias | 
| OpsGenieV2.Alerts.count | Number | Count of Alert occurences | 
| OpsGenieV2.Alerts.createdAt | Date | Time alert created | 
| OpsGenieV2.Alerts.id | String | ID of alert | 
| OpsGenieV2.Alerts.integration.id | String | ID of integration | 
| OpsGenieV2.Alerts.integration.name | String | Integration name | 
| OpsGenieV2.Alerts.integration.type | String | Type of integration | 
| OpsGenieV2.Alerts.isSeen | Boolean | Whether alert has been seen | 
| OpsGenieV2.Alerts.lastOccurredAt | Date | Time alert last occured | 
| OpsGenieV2.Alerts.message | String | Alert Message | 
| OpsGenieV2.Alerts.owner | String | Owner of Alert | 
| OpsGenieV2.Alerts.ownerTeamId | String | Team ID of Owner | 
| OpsGenieV2.Alerts.priority | String | Alert Priority | 
| OpsGenieV2.Alerts.responders.id | String | ID of responders | 
| OpsGenieV2.Alerts.responders.type | String | Type of Responders | 
| OpsGenieV2.Alerts.seen | Boolean | Seen status of alert | 
| OpsGenieV2.Alerts.snoozed | Boolean | Whether alert has been snoozed | 
| OpsGenieV2.Alerts.source | String | Source of Alert | 
| OpsGenieV2.Alerts.status | String | Status of Alert | 
| OpsGenieV2.Alerts.teams.id | String | ID Of teams associated with Alert | 
| OpsGenieV2.Alerts.tinyId | String | Shorter ID for alert | 
| OpsGenieV2.Alerts.updatedAt | Date | Last Updated time for Alert | 
| OpsGenieV2.Alerts.report.ackTime | Number | Acknoweledgement Time of Alert | 
| OpsGenieV2.Alerts.report.acknowledgedBy | String | User that Acknolwedged the alert | 
| OpsGenieV2.Alerts.report.closeTime | Number | Time Alarm closed | 
| OpsGenieV2.Alerts.report.closedBy | String | Who Closed the alarm | 
### opsgenie-create-alert

***
Create an Alert in opsgenie

#### Base Command

`opsgenie-create-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | Alert message. | Required | 
| alias | Client-defined identifier of the alert. | Optional | 
| description | Description field of the alert that is generally used to provide a detailed information about the alert. | Optional | 
| responders | Dictionary of team/user/escalation/schedule for notifications. Dictionary containing type and ID. | Optional | 
| priority | Incident Priority. Possible values are: P1, P2, P3, P4, P5. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.CreatedAlert.action | String | Action of this Request | 
| OpsGenieV2.CreatedAlert.alertId | String | ID Of created Alert | 
| OpsGenieV2.CreatedAlert.alias | String | Alais of created Alert | 
| OpsGenieV2.CreatedAlert.integrationId | String | Integration of created Alert | 
| OpsGenieV2.CreatedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenieV2.CreatedAlert.processedAt | Date | When the request was processed | 
| OpsGenieV2.CreatedAlert.requestId | String | The ID of the request | 
| OpsGenieV2.CreatedAlert.status | String | The human readable result of the request | 
| OpsGenieV2.CreatedAlert.success | Boolean | Bool, whether the request was a success | 
### opsgenie-delete-alert

***
Delete an Alert from OpsGenie

#### Base Command

`opsgenie-delete-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.DeletedAlert.action | String | Action of this Request | 
| OpsGenieV2.DeletedAlert.alertId | String | ID Of Deleted Alert | 
| OpsGenieV2.DeletedAlert.alias | String | Alais of created Alert | 
| OpsGenieV2.DeletedAlert.integrationId | String | Integration of created Alert | 
| OpsGenieV2.DeletedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenieV2.DeletedAlert.processedAt | Date | When the request was processed | 
| OpsGenieV2.DeletedAlert.requestId | String | The ID of the request | 
| OpsGenieV2.DeletedAlert.status | String | The human readable result of the request | 
| OpsGenieV2.DeletedAlert.success | Boolean | Bool, whether the request was a success | 
### opsgenie-get-alert

***
Delete an Alert from OpsGenie

#### Base Command

`opsgenie-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.Alert.acknowledged | Boolean | State of Acknoweledgement | 
| OpsGenieV2.Alert.alias | String | Alert Alias | 
| OpsGenieV2.Alert.count | Number | Count of Alert occurences | 
| OpsGenieV2.Alert.createdAt | Date | Time alert created | 
| OpsGenieV2.Alert.id | String | ID of alert | 
| OpsGenieV2.Alert.integration.id | String | ID of integration | 
| OpsGenieV2.Alert.integration.name | String | Integration name | 
| OpsGenieV2.Alert.integration.type | String | Type of integration | 
| OpsGenieV2.Alert.isSeen | Boolean | Whether alert has been seen | 
| OpsGenieV2.Alert.lastOccurredAt | Date | Time alert last occured | 
| OpsGenieV2.Alert.message | String | Alert Message | 
| OpsGenieV2.Alert.owner | String | Owner of Alert | 
| OpsGenieV2.Alert.ownerTeamId | String | Team ID of Owner | 
| OpsGenieV2.Alert.priority | String | Alert Priority | 
| OpsGenieV2.Alert.responders.id | String | ID of responders | 
| OpsGenieV2.Alert.responders.type | String | Type of Responders | 
| OpsGenieV2.Alert.seen | Boolean | Seen status of alert | 
| OpsGenieV2.Alert.snoozed | Boolean | Whether alert has been snoozed | 
| OpsGenieV2.Alert.source | String | Source of Alert | 
| OpsGenieV2.Alert.status | String | Status of Alert | 
| OpsGenieV2.Alert.teams.id | String | ID Of teams associated with Alert | 
| OpsGenieV2.Alert.tinyId | String | Shorter ID for alert | 
| OpsGenieV2.Alert.updatedAt | Date | Last Updated time for Alert | 
| OpsGenieV2.Alert.report.ackTime | Number | Acknoweledgement Time of Alert | 
| OpsGenieV2.Alert.report.acknowledgedBy | String | User that Acknolwedged the alert | 
| OpsGenieV2.Alert.report.closeTime | Number | Time Alarm closed | 
| OpsGenieV2.Alert.report.closedBy | String | Who Closed the alarm | 
### opsgenie-ack-alert

***
Acknowledge an alert in OpsGenie

#### Base Command

`opsgenie-ack-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.AckedAlert.action | String | Action of this Request | 
| OpsGenieV2.AckedAlert.alertId | String | ID Of created Alert | 
| OpsGenieV2.AckedAlert.alias | String | Alais of created Alert | 
| OpsGenieV2.AckedAlert.integrationId | String | Integration of created Alert | 
| OpsGenieV2.AckedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenieV2.AckedAlert.processedAt | Date | When the request was processed | 
| OpsGenieV2.AckedAlert.requestId | String | The ID of the request | 
| OpsGenieV2.AckedAlert.status | String | The human readable result of the request | 
| OpsGenieV2.AckedAlert.success | Boolean | Bool, whether the request was a success | 
### opsgenie-get-schedule

***
Retrieve the provided Schedule (by ID) from LR

#### Base Command

`opsgenie-get-schedule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule-id | Schedule to retrieve from LR. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.Schedule.description | String | Description of Schedule | 
| OpsGenieV2.Schedule.enabled | Boolean | If this schedule is enabled | 
| OpsGenieV2.Schedule.id | String | ID Of schedule | 
| OpsGenieV2.Schedule.name | String | Name of Schedule | 
| OpsGenieV2.Schedule.ownerTeam.id | String | ID Of the team owning this schedule | 
| OpsGenieV2.Schedule.ownerTeam.name | String | Name of Team owning this Schedule | 
| OpsGenieV2.Schedule.rotations.id | String | ID of rotations on this Schedule | 
| OpsGenieV2.Schedule.rotations.length | Number | Length of Rotations on this Schedule | 
| OpsGenieV2.Schedule.rotations.name | String | Name of Rotation on this Schedule | 
| OpsGenieV2.Schedule.rotations.participants.id | String | ID Of Partipant attached to this schedule | 
| OpsGenieV2.Schedule.rotations.participants.type | String | Type of Participant attached to this Schedule | 
| OpsGenieV2.Schedule.rotations.participants.username | String | Username of Participant Attached to this Schedule | 
| OpsGenieV2.Schedule.rotations.startDate | Date | Start Date of this Schedule | 
| OpsGenieV2.Schedule.rotations.type | String | Type of this Rotation | 
| OpsGenieV2.Schedule.timezone | String | Timezone of this Schedule | 
### opsgenie-list-schedules

***
List Schedules

#### Base Command

`opsgenie-list-schedules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Max number of results to return. | Optional | 
| sort | OpsGenie field to sort on. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.Schedules.description | String | Description of Schedule | 
| OpsGenieV2.Schedules.enabled | Boolean | If this schedule is enabled | 
| OpsGenieV2.Schedules.id | String | ID Of schedule | 
| OpsGenieV2.Schedules.name | String | Name of Schedule | 
| OpsGenieV2.Schedules.ownerTeam.id | String | ID Of the team owning this schedule | 
| OpsGenieV2.Schedules.ownerTeam.name | String | Name of Team owning this Schedule | 
| OpsGenieV2.Schedules.rotations.id | String | ID of rotations on this Schedule | 
| OpsGenieV2.Schedules.rotations.length | Number | Length of Rotations on this Schedule | 
| OpsGenieV2.Schedules.rotations.name | String | Name of Rotation on this Schedule | 
| OpsGenieV2.Schedules.rotations.participants.id | String | ID Of Partipant attached to this schedule | 
| OpsGenieV2.Schedules.rotations.participants.type | String | Type of Participant attached to this Schedule | 
| OpsGenieV2.Schedules.rotations.participants.username | String | Username of Participant Attached to this Schedule | 
| OpsGenieV2.Schedules.rotations.startDate | Date | Start Date of this Schedule | 
| OpsGenieV2.Schedules.rotations.type | String | Type of this Rotation | 
| OpsGenieV2.Schedules.timezone | String | Timezone of this Schedule | 
### opsgenie-get-on-call

***
Get the on-call users for the provided schedule

#### Base Command

`opsgenie-get-on-call`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule-id | Schedule from which to return on-call users. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.OnCall._parent.enabled | Boolean | If this OnCall is Enabled | 
| OpsGenieV2.OnCall._parent.id | String | ID Of parent schedule | 
| OpsGenieV2.OnCall._parent.name | String | Name of parent Schedule | 
| OpsGenieV2.OnCall.onCallParticipants.id | String | ID Of oncall participant | 
| OpsGenieV2.OnCall.onCallParticipants.name | String | Name of oncall participant | 
| OpsGenieV2.OnCall.onCallParticipants.type | String | Type of OnCall participant | 
### opsgenie-close-alert

***
Close an OpsGenie Alert

#### Base Command

`opsgenie-close-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | ID Of opsgenie alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenieV2.CloseAlert.action | String | Action of this Request | 
| OpsGenieV2.CloseAlert.alertId | String | ID Of created Alert | 
| OpsGenieV2.CloseAlert.alias | String | Alais of created Alert | 
| OpsGenieV2.CloseAlert.integrationId | String | Integration of created Alert | 
| OpsGenieV2.CloseAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenieV2.CloseAlert.processedAt | Date | When the request was processed | 
| OpsGenieV2.CloseAlert.requestId | String | The ID of the request | 
| OpsGenieV2.CloseAlert.status | String | The human readable result of the request | 
| OpsGenieV2.CloseAlert.success | Boolean | Bool, whether the request was a success | 