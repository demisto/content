Integration with Atlassian OpsGenie
This integration was integrated and tested with version xx of OpsGenieV3

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-opsgenie-v3).

## Configure OpsGenie v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpsGenie v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://example.net) |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | API Token | Must be created from the Teams API Integration section. | False |
    | Fetch incidents |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | None |  | False |
    | Event types | Fetch only events with selected event types | True |
    | Status |  | False |
    | Priority |  | False |
    | Tags |  | False |
    | Query |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opsgenie-create-alert
***
Create an Alert in opsgenie


#### Base Command

`opsgenie-create-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| max_results | The number of results to return. Default is 30. | Optional | 
| message | Alert message. | Required | 
| alias | Client-defined identifier of the alert. | Optional | 
| description | Description field of the alert that is generally used to provide a detailed information about the alert. | Optional | 
| responders | Teams/users that the alert is routed to via notifications. List of:responser_type, value_type, value. | Optional | 
| tags | Comma separated list of tags to add. | Optional | 
| priority | Incident Priority. Defaulted to P3 if not provided. Possible values are: P1, P2, P3, P4, P5. Default is P3. | Optional | 
| source | Display name of the request source. Defaulted to IP of the request sender. | Optional | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Alert.action | String | Action of this Request | 
| OpsGenie.Alert.alertId | String | Id of created Alert | 
| OpsGenie.Alert.alias | String | Alais of created Alert | 
| OpsGenie.Alert.integrationId | String | Integration of created Alert | 
| OpsGenie.Alert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Alert.processedAt | Date | When the request was processed | 
| OpsGenie.Alert.requestId | String | The ID of the request | 
| OpsGenie.Alert.status | String | The human readable result of the request | 
| OpsGenie.Alert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-create-alert message="Example Message"```

#### Human Readable Output

>null

### opsgenie-get-alerts
***
List the current alerts from OpsGenie.


#### Base Command

`opsgenie-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Optional | 
| sort | OpsGenie field to sort by. | Optional | 
| limit | Maximum results to return. Default is 20. | Optional | 
| offset | Start index of the result set (to apply pagination). Minimum value (and also default value) is 0. Default is 0. | Optional | 
| status | The ID of the alert from opsgenie. Possible values are: Open, Closed. | Optional | 
| priority | Incident Priority. Defaulted to P3 if not provided. Possible values are: P1, P2, P3, P4, P5. Default is P3. | Optional | 
| tags | Comma separated list of tags to add. | Optional | 
| query | URL Encoded query params. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Alert.acknowledged | Boolean | State of Acknoweledgement | 
| OpsGenie.Alert.alias | String | Alert Alias | 
| OpsGenie.Alert.count | Number | Count of Alert occurences | 
| OpsGenie.Alert.createdAt | Date | Time alert created | 
| OpsGenie.Alert.id | String | ID of alert | 
| OpsGenie.Alert.integration.id | String | ID of integration | 
| OpsGenie.Alert.integration.name | String | Integration name | 
| OpsGenie.Alert.integration.type | String | Type of integration | 
| OpsGenie.Alert.isSeen | Boolean | Whether alert has been seen | 
| OpsGenie.Alert.lastOccurredAt | Date | Time alert last occured | 
| OpsGenie.Alert.message | String | Alert Message | 
| OpsGenie.Alert.owner | String | Owner of Alert | 
| OpsGenie.Alert.ownerTeamId | String | Team ID of Owner | 
| OpsGenie.Alert.priority | String | Alert Priority | 
| OpsGenie.Alert.responders.id | String | ID of responders | 
| OpsGenie.Alert.responders.type | String | Type of Responders | 
| OpsGenie.Alert.seen | Boolean | Seen status of alert | 
| OpsGenie.Alert.snoozed | Boolean | Whether alert has been snoozed | 
| OpsGenie.Alert.source | String | Source of Alert | 
| OpsGenie.Alert.status | String | Status of Alert | 
| OpsGenie.Alert.teams.id | String | Id of teams associated with Alert | 
| OpsGenie.Alert.tinyId | String | Shorter ID for alert | 
| OpsGenie.Alert.updatedAt | Date | Last Updated time for Alert | 
| OpsGenie.Alert.report.ackTime | Number | Acknoweledgement Time of Alert | 
| OpsGenie.Alert.report.acknowledgedBy | String | User that Acknolwedged the alert | 
| OpsGenie.Alert.report.closeTime | Number | Time Alarm closed | 
| OpsGenie.Alert.report.closedBy | String | Who Closed the alarm | 


#### Command Example
```!opsgenie-get-alerts```

#### Human Readable Output

>```
>{
>    "data": [
>        {
>            "acknowledged": false,
>            "alias": "3933647a-f679-49df-9172-7fec810f6dd1-1636985725204",
>            "count": 1,
>            "createdAt": "2021-11-15T14:15:25.204Z",
>            "event_type": "Alerts",
>            "id": "3933647a-f679-49df-9172-7fec810f6dd1-1636985725204",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T14:15:25.204Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "31.154.166.148",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "81",
>            "updatedAt": "2021-11-15T14:15:25.276Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "873b45f3-de87-4fd3-9a2b-cd927ea81c74-1636985621569",
>            "count": 1,
>            "createdAt": "2021-11-15T14:13:41.569Z",
>            "event_type": "Alerts",
>            "id": "873b45f3-de87-4fd3-9a2b-cd927ea81c74-1636985621569",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T14:13:41.569Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "31.154.166.148",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "80",
>            "updatedAt": "2021-11-15T14:13:41.648Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "2640008b-8ee9-49f4-8ecd-89f0292a5f94-1636985221883",
>            "count": 1,
>            "createdAt": "2021-11-15T14:07:01.883Z",
>            "event_type": "Alerts",
>            "id": "2640008b-8ee9-49f4-8ecd-89f0292a5f94-1636985221883",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T14:07:01.883Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "31.154.166.148",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "79",
>            "updatedAt": "2021-11-15T14:07:01.977Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "da591aae-819e-4af8-90db-9f37004b6fc8-1636984673968",
>            "count": 1,
>            "createdAt": "2021-11-15T13:57:53.968Z",
>            "event_type": "Alerts",
>            "id": "da591aae-819e-4af8-90db-9f37004b6fc8-1636984673968",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T13:57:53.968Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "31.154.166.148",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "78",
>            "updatedAt": "2021-11-15T13:57:54.05Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "69b36e77-2533-44e1-b4f2-79a4bc46d191-1636983103612",
>            "count": 1,
>            "createdAt": "2021-11-15T13:31:43.612Z",
>            "event_type": "Alerts",
>            "id": "69b36e77-2533-44e1-b4f2-79a4bc46d191-1636983103612",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T13:31:43.612Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "77",
>            "updatedAt": "2021-11-15T13:31:43.771Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "07c0d8e1-94b7-43eb-803b-af1b21e4989d-1636982442916",
>            "count": 1,
>            "createdAt": "2021-11-15T13:20:42.916Z",
>            "event_type": "Alerts",
>            "id": "07c0d8e1-94b7-43eb-803b-af1b21e4989d-1636982442916",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T13:20:42.916Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "76",
>            "updatedAt": "2021-11-15T13:20:42.993Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "c95bb063-c2da-4667-938f-0a0fe4f28b0e-1636982193238",
>            "count": 1,
>            "createdAt": "2021-11-15T13:16:33.238Z",
>            "event_type": "Alerts",
>            "id": "c95bb063-c2da-4667-938f-0a0fe4f28b0e-1636982193238",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T13:16:33.238Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "75",
>            "updatedAt": "2021-11-15T13:16:33.312Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "078e53ce-6462-40d9-bee3-2813622c2a49-1636976397688",
>            "count": 1,
>            "createdAt": "2021-11-15T11:39:57.688Z",
>            "event_type": "Alerts",
>            "id": "078e53ce-6462-40d9-bee3-2813622c2a49-1636976397688",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T11:39:57.688Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "74",
>            "updatedAt": "2021-11-15T11:39:57.813Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "577424c1-b03c-4d23-9871-da0d395fea17_39197a6e-5dda-4a7f-8bea-5125da7f707a",
>            "count": 1,
>            "createdAt": "2021-11-15T10:55:37.048Z",
>            "event_type": "Alerts",
>            "id": "6a9de381-65d4-4662-9b25-64d87aec23db-1636973737048",
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T10:55:37.048Z",
>            "message": "test",
>            "owner": "",
>            "ownerTeamId": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
>            "priority": "P3",
>            "responders": [
>                {
>                    "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
>                    "type": "team"
>                }
>            ],
>            "seen": false,
>            "snoozed": false,
>            "source": "",
>            "status": "open",
>            "tags": [],
>            "teams": [
>                {
>                    "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b"
>                }
>            ],
>            "tinyId": "73",
>            "updatedAt": "2021-11-15T11:05:37.661Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "3d222bca-b7cf-4fd3-9710-6662450b34b9-1636973392396",
>            "count": 1,
>            "createdAt": "2021-11-15T10:49:52.396Z",
>            "event_type": "Alerts",
>            "id": "3d222bca-b7cf-4fd3-9710-6662450b34b9-1636973392396",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T10:49:52.396Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "72",
>            "updatedAt": "2021-11-15T10:49:52.51Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "a416035a-4fbd-412b-940d-e6364e6eff23-1636973363795",
>            "count": 1,
>            "createdAt": "2021-11-15T10:49:23.795Z",
>            "event_type": "Alerts",
>            "id": "a416035a-4fbd-412b-940d-e6364e6eff23-1636973363795",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T10:49:23.795Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "71",
>            "updatedAt": "2021-11-15T10:49:23.912Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "34db92e6-1c53-4404-aa37-1d3fc5b1140b_935d92fe-819c-43f7-8b0e-d516c7e193d3",
>            "count": 1,
>            "createdAt": "2021-11-15T10:48:54.348Z",
>            "event_type": "Alerts",
>            "id": "617252d7-b2b0-40ab-9195-b330fcf62063-1636973334348",
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T10:48:54.348Z",
>            "message": "this is a teat incident",
>            "owner": "Danil Vilenchik",
>            "ownerTeamId": "",
>            "priority": "P2",
>            "responders": [
>                {
>                    "id": "154d6425-c120-4beb-a3e6-a66c8c44f61d",
>                    "type": "user"
>                }
>            ],
>            "seen": false,
>            "snoozed": false,
>            "source": "",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "70",
>            "updatedAt": "2021-11-15T10:48:54.436Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "5bb46a5d-a21f-42f7-81e0-f04b2258c523-1636972621059",
>            "count": 1,
>            "createdAt": "2021-11-15T10:37:01.059Z",
>            "event_type": "Alerts",
>            "id": "5bb46a5d-a21f-42f7-81e0-f04b2258c523-1636972621059",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T10:37:01.059Z",
>            "message": "Example Message",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "68",
>            "updatedAt": "2021-11-15T10:37:01.135Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "d80add44-6009-4fd2-84cb-a7ffb6824cba-1636970016551",
>            "count": 1,
>            "createdAt": "2021-11-15T09:53:36.551Z",
>            "event_type": "Alerts",
>            "id": "d80add44-6009-4fd2-84cb-a7ffb6824cba-1636970016551",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": true,
>            "lastOccurredAt": "2021-11-15T09:53:36.551Z",
>            "message": "test113",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "report": {
>                "ackTime": 27799,
>                "closeTime": 27799,
>                "closedBy": "Alert API"
>            },
>            "responders": [],
>            "seen": true,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "closed",
>            "tags": [],
>            "teams": [],
>            "tinyId": "67",
>            "updatedAt": "2021-11-15T09:54:04.35Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "6bda0ef6-fb62-403a-bf49-96bbedbada5d-1636969982538",
>            "count": 1,
>            "createdAt": "2021-11-15T09:53:02.538Z",
>            "event_type": "Alerts",
>            "id": "6bda0ef6-fb62-403a-bf49-96bbedbada5d-1636969982538",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-15T09:53:02.538Z",
>            "message": "test113",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "66",
>            "updatedAt": "2021-11-15T09:53:02.61Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "6eb99017-0e6e-4220-8591-9e3d6484257f-1636965757958",
>            "count": 1,
>            "createdAt": "2021-11-15T08:42:37.958Z",
>            "event_type": "Alerts",
>            "id": "6eb99017-0e6e-4220-8591-9e3d6484257f-1636965757958",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": true,
>            "lastOccurredAt": "2021-11-15T08:42:37.958Z",
>            "message": "test113",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "report": {
>                "ackTime": 172363,
>                "closeTime": 172363,
>                "closedBy": "Alert API"
>            },
>            "responders": [],
>            "seen": true,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "closed",
>            "tags": [],
>            "teams": [],
>            "tinyId": "65",
>            "updatedAt": "2021-11-15T08:45:30.321Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "ae3adf0a-84fe-4cc5-8d4e-16ddf4a91de1-1636930853616",
>            "count": 1,
>            "createdAt": "2021-11-14T23:00:53.616Z",
>            "event_type": "Alerts",
>            "id": "ae3adf0a-84fe-4cc5-8d4e-16ddf4a91de1-1636930853616",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-14T23:00:53.616Z",
>            "message": "test113",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "64",
>            "updatedAt": "2021-11-14T23:00:53.707Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "fad372d0-c6c9-4966-a602-9d9be8d7c520-1636893292783",
>            "count": 1,
>            "createdAt": "2021-11-14T12:34:52.783Z",
>            "event_type": "Alerts",
>            "id": "fad372d0-c6c9-4966-a602-9d9be8d7c520-1636893292783",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-14T12:34:52.783Z",
>            "message": "test113",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "147.236.155.109",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "63",
>            "updatedAt": "2021-11-14T12:34:52.861Z"
>        },
>        {
>            "acknowledged": true,
>            "alias": "6ce2a940-2366-4578-908e-2ffd6172cff3-1636632591868",
>            "count": 1,
>            "createdAt": "2021-11-11T12:09:51.868Z",
>            "event_type": "Alerts",
>            "id": "6ce2a940-2366-4578-908e-2ffd6172cff3-1636632591868",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": true,
>            "lastOccurredAt": "2021-11-11T12:09:51.868Z",
>            "message": "test11",
>            "owner": "Alert API",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "report": {
>                "ackTime": 4316459,
>                "acknowledgedBy": "Alert API"
>            },
>            "responders": [],
>            "seen": true,
>            "snoozed": false,
>            "source": "31.154.166.148",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "62",
>            "updatedAt": "2021-11-11T13:21:48.334Z"
>        },
>        {
>            "acknowledged": false,
>            "alias": "3684968b-dd91-42aa-9d76-c6dd4f8f596f-1636560596589",
>            "count": 1,
>            "createdAt": "2021-11-10T16:09:56.589Z",
>            "event_type": "Alerts",
>            "id": "3684968b-dd91-42aa-9d76-c6dd4f8f596f-1636560596589",
>            "integration": {
>                "id": "3cc69931-167f-411c-a331-768997c29d2e",
>                "name": "API",
>                "type": "API"
>            },
>            "isSeen": false,
>            "lastOccurredAt": "2021-11-10T16:09:56.589Z",
>            "message": "testt",
>            "owner": "",
>            "ownerTeamId": "",
>            "priority": "P3",
>            "responders": [],
>            "seen": false,
>            "snoozed": false,
>            "source": "31.154.166.148",
>            "status": "open",
>            "tags": [],
>            "teams": [],
>            "tinyId": "61",
>            "updatedAt": "2021-11-10T16:09:56.662Z"
>        }
>    ],
>    "paging": {
>        "first": "https:<span>//</span>api.opsgenie.com/v2/alerts?limit=20&sort=createdAt&offset=0&order=desc",
>        "last": "https:<span>//</span>api.opsgenie.com/v2/alerts?limit=20&sort=createdAt&offset=60&order=desc",
>        "next": "https:<span>//</span>api.opsgenie.com/v2/alerts?limit=20&sort=createdAt&offset=20&order=desc"
>    },
>    "requestId": "246d320f-3903-4d1a-9ca7-4c6e0537cdac",
>    "took": 0.019
>}
>```

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
| OpsGenie.DeletedAlert.action | String | Action of this Request | 
| OpsGenie.DeletedAlert.alertId | String | Id of deleted Alert | 
| OpsGenie.DeletedAlert.alias | String | Alais of deleted Alert | 
| OpsGenie.DeletedAlert.integrationId | String | Integration of deleted Alert | 
| OpsGenie.DeletedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.DeletedAlert.processedAt | Date | When the request was processed | 
| OpsGenie.DeletedAlert.requestId | String | The ID of the request | 
| OpsGenie.DeletedAlert.status | String | The human readable result of the request | 
| OpsGenie.DeletedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-delete-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286```

#### Human Readable Output

>null

### opsgenie-ack-alert
***
Acknowledge an alert in OpsGenie


#### Base Command

`opsgenie-ack-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AckedAlert.action | String | Action of this Request | 
| OpsGenie.AckedAlert.alertId | String | Id of acked Alert | 
| OpsGenie.AckedAlert.alias | String | Alais of acked Alert | 
| OpsGenie.AckedAlert.integrationId | String | Integration of acked Alert | 
| OpsGenie.AckedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AckedAlert.processedAt | Date | When the request was processed | 
| OpsGenie.AckedAlert.requestId | String | The ID of the request | 
| OpsGenie.AckedAlert.status | String | The human readable result of the request | 
| OpsGenie.AckedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-ack-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286```

#### Human Readable Output

>null

### opsgenie-close-alert
***
Close an alert in OpsGenie


#### Base Command

`opsgenie-close-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert from opsgenie. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.ClosedAlert.action | String | Action of this Request | 
| OpsGenie.ClosedAlert.alertId | String | Id of closed Alert | 
| OpsGenie.ClosedAlert.alias | String | Alais of closed Alert | 
| OpsGenie.ClosedAlert.integrationId | String | Integration of acked Alert | 
| OpsGenie.ClosedAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.ClosedAlert.processedAt | Date | When the request was processed | 
| OpsGenie.ClosedAlert.requestId | String | The ID of the request | 
| OpsGenie.ClosedAlert.status | String | The human readable result of the request | 
| OpsGenie.ClosedAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-close-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286```

#### Context Example
```json
{
    "data": {
        "action": "Add Responder",
        "alertId": "",
        "alias": "",
        "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
        "isSuccess": false,
        "processedAt": "2021-11-15T14:15:33.523Z",
        "status": "Alert does not exist",
        "success": false
    },
    "requestId": "79c3a519-cb8c-42f6-b2b3-39da4367038d",
    "took": 0.002
}
```

#### Human Readable Output

>null

### opsgenie-assign-alert
***
Assign an OpsGenie Alert


#### Base Command

`opsgenie-assign-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| owner_id | Id of User that the alert will be assigned to. Not required if owner_username is present. | Optional | 
| owner_username | Display name of the request owner. Not required if owner_id is present. | Optional | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AssignAlert.action | String | Action of this Request | 
| OpsGenie.AssignAlert.alertId | String | ID of assigned Alert | 
| OpsGenie.AssignAlert.alias | String | Alais of assigned Alert | 
| OpsGenie.AssignAlert.integrationId | String | Integration of assigned Alert | 
| OpsGenie.AssignAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AssignAlert.processedAt | Date | When the request was processed | 
| OpsGenie.AssignAlert.requestId | String | The ID of the request | 
| OpsGenie.AssignAlert.status | String | The human readable result of the request | 
| OpsGenie.AssignAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-assign-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 owner_username=b@g.com```

#### Human Readable Output

>null

### opsgenie-add-responder-alert
***
Add responder to an OpsGenie Alert


#### Base Command

`opsgenie-add-responder-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| identifierType | Type of the identifier. Possible values are: id, tiny, alias. | Optional | 
| responders | Team or user that the alert will be routed to. List of triples (responser_type, value_type, value). | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AddResponderAlert.action | String | Action of this Request | 
| OpsGenie.AddResponderAlert.alertId | String | ID of created Alert | 
| OpsGenie.AddResponderAlert.alias | String | Alais of created Alert | 
| OpsGenie.AddResponderAlert.integrationId | String | Integration of created Alert | 
| OpsGenie.AddResponderAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AddResponderAlert.processedAt | Date | When the request was processed | 
| OpsGenie.AddResponderAlert.requestId | String | The ID of the request | 
| OpsGenie.AddResponderAlert.status | String | The human readable result of the request | 
| OpsGenie.AddResponderAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-add-responder-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 responders=schedule,name,test_schedule```

#### Human Readable Output

>null

### opsgenie-get-escalations
***
Get escalations from OpsGenie


#### Base Command

`opsgenie-get-escalations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| escalation_id | Id of escalation. | Optional | 
| escalation_name | Name of escalation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Escalation.action | String | Action of this Request | 
| OpsGenie.Escalation.Id | String | ID of Escalation | 
| OpsGenie.Escalation.name | String | Name of Escalation | 
| OpsGenie.Escalation.description | String | Description of Escalation | 
| OpsGenie.Escalation.ownerTeam | String | OwnerTeam of Escalation | 
| OpsGenie.Escalation.rules | String | Rules of Escalation | 
| OpsGenie.Escalation.integrationId | String | Integration of escalated Alert | 
| OpsGenie.Escalation.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Escalation.processedAt | Date | When the request was processed | 
| OpsGenie.Escalation.requestId | String | The ID of the request | 
| OpsGenie.Escalation.status | String | The human readable result of the request | 
| OpsGenie.Escalation.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-get-escalations```

#### Human Readable Output

>```
>{
>    "data": [
>        {
>            "description": "",
>            "id": "9a441a8d-2410-43f4-9ef2-f7a265e12b74",
>            "name": "Engineering_escalation",
>            "ownerTeam": {
>                "id": "51d69df8-c40b-439e-9808-e1a78e54f91b",
>                "name": "Engineering"
>            },
>            "rules": [
>                {
>                    "condition": "if-not-acked",
>                    "delay": {
>                        "timeAmount": 0,
>                        "timeUnit": "minutes"
>                    },
>                    "notifyType": "default",
>                    "recipient": {
>                        "id": "7835aa84-7440-41d5-90bf-92e0045714d5",
>                        "name": "Engineering_schedule",
>                        "type": "schedule"
>                    }
>                },
>                {
>                    "condition": "if-not-acked",
>                    "delay": {
>                        "timeAmount": 5,
>                        "timeUnit": "minutes"
>                    },
>                    "notifyType": "next",
>                    "recipient": {
>                        "id": "7835aa84-7440-41d5-90bf-92e0045714d5",
>                        "name": "Engineering_schedule",
>                        "type": "schedule"
>                    }
>                },
>                {
>                    "condition": "if-not-acked",
>                    "delay": {
>                        "timeAmount": 10,
>                        "timeUnit": "minutes"
>                    },
>                    "notifyType": "all",
>                    "recipient": {
>                        "id": "51d69df8-c40b-439e-9808-e1a78e54f91b",
>                        "name": "Engineering",
>                        "type": "team"
>                    }
>                }
>            ]
>        },
>        {
>            "description": "",
>            "id": "c8a0f950-577c-4da5-894b-1fd463d9f51c",
>            "name": "Integration Team_escalation",
>            "ownerTeam": {
>                "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
>                "name": "Integration Team"
>            },
>            "rules": [
>                {
>                    "condition": "if-not-acked",
>                    "delay": {
>                        "timeAmount": 0,
>                        "timeUnit": "minutes"
>                    },
>                    "notifyType": "default",
>                    "recipient": {
>                        "id": "df918339-b999-4878-b69b-3c2c0d508b01",
>                        "name": "Integration Team_schedule",
>                        "type": "schedule"
>                    }
>                },
>                {
>                    "condition": "if-not-acked",
>                    "delay": {
>                        "timeAmount": 1,
>                        "timeUnit": "minutes"
>                    },
>                    "notifyType": "default",
>                    "recipient": {
>                        "id": "154d6425-c120-4beb-a3e6-a66c8c44f61d",
>                        "type": "user",
>                        "username": "dvilenchik@paloaltonetworks.com"
>                    }
>                },
>                {
>                    "condition": "if-not-acked",
>                    "delay": {
>                        "timeAmount": 5,
>                        "timeUnit": "minutes"
>                    },
>                    "notifyType": "next",
>                    "recipient": {
>                        "id": "df918339-b999-4878-b69b-3c2c0d508b01",
>                        "name": "Integration Team_schedule",
>                        "type": "schedule"
>                    }
>                },
>                {
>                    "condition": "if-not-acked",
>                    "delay": {
>                        "timeAmount": 10,
>                        "timeUnit": "minutes"
>                    },
>                    "notifyType": "all",
>                    "recipient": {
>                        "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
>                        "name": "Integration Team",
>                        "type": "team"
>                    }
>                }
>            ]
>        }
>    ],
>    "requestId": "2df90da4-b826-4edb-a699-fc2e406e2bc9",
>    "took": 0.005
>}
>```

### opsgenie-escalate-alert
***
Escalate an OpsGenie Alert


#### Base Command

`opsgenie-escalate-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| escalation_name | Escalation that the alert will be escalated. Either id or name of the escalation should be provided. | Optional | 
| escalation_id | Escalation that the alert will be escalated. Either id or name of the escalation should be provided. | Optional | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.EscalateAlert.action | String | Action of this Request | 
| OpsGenie.EscalateAlert.id | String | ID of escalation | 
| OpsGenie.EscalateAlert.name | String | Name of Escalation | 
| OpsGenie.EscalateAlert.description | String | Description of Escalation | 
| OpsGenie.EscalateAlert.integrationId | String | Integration of escalated Alert | 
| OpsGenie.EscalateAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.EscalateAlert.processedAt | Date | When the request was processed | 
| OpsGenie.EscalateAlert.requestId | String | The ID of the request | 
| OpsGenie.EscalateAlert.status | String | The human readable result of the request | 
| OpsGenie.EscalateAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-escalate-alert alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 escalation_id=9a441a8d-2410-43f4-9ef2-f7a265e12b74```

#### Human Readable Output

>null

### opsgenie-add-alert-tag
***
Add tag into OpsGenie Alert


#### Base Command

`opsgenie-add-alert-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| tags | Comma separated list of tags to add into alert. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AddTagAlert.action | String | Action of this Request | 
| OpsGenie.AddTagAlert.alertId | String | ID of added Alert | 
| OpsGenie.AddTagAlert.alias | String | Alais of added Alert | 
| OpsGenie.AddTagAlert.integrationId | String | Integration of added Alert | 
| OpsGenie.AddTagAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AddTagAlert.processedAt | Date | When the request was processed | 
| OpsGenie.AddTagAlert.requestId | String | The ID of the request | 
| OpsGenie.AddTagAlert.status | String | The human readable result of the request | 
| OpsGenie.AddTagAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-add-alert-tag alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 tags=1,2,3```

#### Human Readable Output

>null

### opsgenie-remove-alert-tag
***
Remove tag from OpsGenie Alert


#### Base Command

`opsgenie-remove-alert-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| tags | Comma separated list of tags to remove from alert. | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.RemoveTagAlert.action | String | Action of this Request | 
| OpsGenie.RemoveTagAlert.alertId | String | ID of removed tag Alert | 
| OpsGenie.RemoveTagAlert.alias | String | Alais of removed tag Alert | 
| OpsGenie.RemoveTagAlert.integrationId | String | Integration of removed tag Alert | 
| OpsGenie.RemoveTagAlert.isSuccess | Boolean | If the request was successful | 
| OpsGenie.RemoveTagAlert.processedAt | Date | When the request was processed | 
| OpsGenie.RemoveTagAlert.requestId | String | The ID of the request | 
| OpsGenie.RemoveTagAlert.status | String | The human readable result of the request | 
| OpsGenie.RemoveTagAlert.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-remove-alert-tag alert-id=69df59c2-41c6-4866-8c03-65c1ecf5417d-1636973048286 tags=1,2,3```

#### Context Example
```json
{
    "data": {
        "action": "Acknowledge",
        "alertId": "",
        "alias": "",
        "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
        "isSuccess": false,
        "processedAt": "2021-11-15T14:15:30.29Z",
        "status": "Alert does not exist",
        "success": false
    },
    "requestId": "7056a2ce-cdd7-41ed-b41b-54a9152c2b71",
    "took": 0.004
}
```

#### Human Readable Output

>null

### opsgenie-get-alert-attachments
***
Get allert attachments


#### Base Command

`opsgenie-get-alert-attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | Id of opsgenie alert. | Required | 
| attachment_id | Identifier of the attachment. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Alert.Attachment.action | String | Action of this Request | 
| OpsGenie.Alert.Attachment.alertId | String | ID of Alert | 
| OpsGenie.Alert.Attachment.alias | String | Alais of Alert | 
| OpsGenie.Alert.Attachment.integrationId | String | Integration of Alert | 
| OpsGenie.Alert.Attachment.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Alert.Attachment.processedAt | Date | When the request was processed | 
| OpsGenie.Alert.Attachment.requestId | String | The ID of the request | 
| OpsGenie.Alert.Attachment.status | String | The human readable result of the request | 
| OpsGenie.Alert.Attachment.success | Boolean | Bool, whether the request was a success | 


#### Command Example
``` ```

#### Human Readable Output



### opsgenie-get-schedules
***
Get dchedules from OpsGenie


#### Base Command

`opsgenie-get-schedules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | Id of schedule. | Optional | 
| schedule_name | Name of schedule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Schedule.description | String | Schedule description | 
| OpsGenie.Schedule.enabled | Boolean | If schedule enabled | 
| OpsGenie.Schedule.id | String | Id of schedule | 
| OpsGenie.Schedule.name | String | Name of schedule | 
| OpsGenie.Schedule.ownerTeam.id | String | Id of schedule owner | 
| OpsGenie.Schedule.ownerTeam.name | String | Name of schedule owner | 
| OpsGenie.Schedule.timezone | String | Schedule timezone | 


#### Command Example
```!opsgenie-get-schedules```

#### Context Example
```json
{
    "OpsGenie": {
        "Schedule": [
            {
                "description": "Schedule when escalation was activated",
                "enabled": true,
                "id": "5892636c-6183-4788-99d6-6d93b9095194",
                "name": "Escalation Schedule",
                "ownerTeam": {
                    "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                    "name": "Integration Team"
                },
                "rotations": [],
                "timezone": "Asia/Jerusalem"
            },
            {
                "description": "",
                "enabled": true,
                "id": "7835aa84-7440-41d5-90bf-92e0045714d5",
                "name": "Engineering_schedule",
                "ownerTeam": {
                    "id": "51d69df8-c40b-439e-9808-e1a78e54f91b",
                    "name": "Engineering"
                },
                "rotations": [],
                "timezone": "Asia/Jerusalem"
            },
            {
                "description": "24/7 Shift",
                "enabled": true,
                "id": "df918339-b999-4878-b69b-3c2c0d508b01",
                "name": "Integration Team_schedule",
                "ownerTeam": {
                    "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                    "name": "Integration Team"
                },
                "rotations": [],
                "timezone": "Asia/Jerusalem"
            }
        ]
    }
}
```

#### Human Readable Output

>### OpsGenie Schedule
>|description|enabled|id|name|ownerTeam|rotations|timezone|
>|---|---|---|---|---|---|---|
>| Schedule when escalation was activated | true | 5892636c-6183-4788-99d6-6d93b9095194 | Escalation Schedule | id: fbbc3f9a-12f4-4794-9938-7e0a85a06f8b<br/>name: Integration Team |  | Asia/Jerusalem |
>|  | true | 7835aa84-7440-41d5-90bf-92e0045714d5 | Engineering_schedule | id: 51d69df8-c40b-439e-9808-e1a78e54f91b<br/>name: Engineering |  | Asia/Jerusalem |
>| 24/7 Shift | true | df918339-b999-4878-b69b-3c2c0d508b01 | Integration Team_schedule | id: fbbc3f9a-12f4-4794-9938-7e0a85a06f8b<br/>name: Integration Team |  | Asia/Jerusalem |


### opsgenie-get-schedule-overrides
***
Get schedule overrides


#### Base Command

`opsgenie-get-schedule-overrides`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | Id of schedule. | Optional | 
| schedule_name | Name of schedule. | Optional | 
| override_alias | Alias of the schedule override. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Schedule.Override.action | String | Action of this Request | 
| OpsGenie.Schedule.Override.alertId | String | ID of Schedule | 
| OpsGenie.Schedule.Override.alias | String | Alais of Schedule | 
| OpsGenie.Schedule.Override.integrationId | String | Integration of Alert | 
| OpsGenie.Schedule.Override.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Schedule.Override.processedAt | Date | When the request was processed | 
| OpsGenie.Schedule.Override.requestId | String | The ID of the request | 
| OpsGenie.Schedule.Override.status | String | The human readable result of the request | 
| OpsGenie.Schedule.Override.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-get-schedule-overrides schedule_id=5892636c-6183-4788-99d6-6d93b9095194```

#### Human Readable Output

>### OpsGenie Schedule
>**No entries.**


### opsgenie-get-on-call
***
Get the on-call users for the provided schedule


#### Base Command

`opsgenie-get-on-call`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| schedule_id | Schedule id from which to return on-call users. | Optional | 
| schedule_name | Schedule name from which to return on-call users. | Optional | 
| starting_date | Starting date of the timeline that will be provided in format as (yyyy-MM-dd'T'HH:mm:ssZ). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Schedule.OnCall._parent.enabled | Boolean | If this OnCall is Enabled | 
| OpsGenie.Schedule.OnCall._parent.id | String | ID Of parent schedule | 
| OpsGenie.Schedule.OnCall._parent.name | String | Name of parent Schedule | 
| OpsGenie.Schedule.OnCall.onCallParticipants.id | String | ID Of oncall participant | 
| OpsGenie.Schedule.OnCall.onCallParticipants.name | String | Name of oncall participant | 
| OpsGenie.Schedule.OnCall.onCallParticipants.type | String | Type of OnCall participant | 


#### Command Example
```!opsgenie-get-on-call schedule_id=5892636c-6183-4788-99d6-6d93b9095194```

#### Context Example
```json
{
    "OpsGenie": {
        "Schedule": {
            "OnCall": {
                "data": {
                    "_parent": {
                        "enabled": true,
                        "id": "5892636c-6183-4788-99d6-6d93b9095194",
                        "name": "Escalation Schedule"
                    },
                    "onCallParticipants": [
                        {
                            "id": "154d6425-c120-4beb-a3e6-a66c8c44f61d",
                            "name": "dvilenchik@paloaltonetworks.com",
                            "type": "user"
                        }
                    ]
                },
                "requestId": "2bc5bd31-3011-4c2f-ac9d-c4d1b66474f4",
                "took": 0.017
            }
        }
    }
}
```

#### Human Readable Output

>### OpsGenie Schedule OnCall
>|_parent|onCallParticipants|
>|---|---|
>| id: 5892636c-6183-4788-99d6-6d93b9095194<br/>name: Escalation Schedule<br/>enabled: true | {'id': '154d6425-c120-4beb-a3e6-a66c8c44f61d', 'name': 'dvilenchik@paloaltonetworks.com', 'type': 'user'} |


### opsgenie-create-incident
***
Create an Incident in opsgenie


#### Base Command

`opsgenie-create-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| message | Incident message. | Required | 
| description | Description field of the incident that is generally used to provide a detailed information about it. | Optional | 
| responders | Teams/users that the incident is routed to via notifications. List of responser_type,value_type,value. | Required | 
| tags | Comma separated list of tags to add. | Optional | 
| priority | Incident Priority. Defaulted to P3 if not provided. Possible values are: P1, P2, P3, P4, P5. Default is P3. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Incident.action | String | Action of this Request | 
| OpsGenie.Incident.Id | String | Id of created Alert | 
| OpsGenie.Incident.alias | String | Alais of created Alert | 
| OpsGenie.Incident.integrationId | String | Integration of created Alert | 
| OpsGenie.Incident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.Incident.processedAt | Date | When the request was processed | 
| OpsGenie.Incident.requestId | String | The ID of the request | 
| OpsGenie.Incident.status | String | The human readable result of the request | 
| OpsGenie.Incident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-create-incident message="test" responders=team,name,test_team,team,name,test_team_1```

#### Context Example
```json
{
    "data": {
        "action": "Close",
        "alertId": "",
        "alias": "",
        "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
        "isSuccess": false,
        "processedAt": "2021-11-15T14:15:44.991Z",
        "status": "Alert does not exist",
        "success": false
    },
    "requestId": "25241db6-7c33-4a7e-abc8-eb34a273a0f1",
    "took": 0.003
}
```

#### Human Readable Output

>null

### opsgenie-delete-incident
***
Delete an incident from OpsGenie


#### Base Command

`opsgenie-delete-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.DeletedIncident.action | String | Action of this Request | 
| OpsGenie.DeletedIncident.alertId | String | Id of deleted incident | 
| OpsGenie.DeletedIncident.alias | String | Alais of deleted incident | 
| OpsGenie.DeletedIncident.integrationId | String | Integration of deleted incident | 
| OpsGenie.DeletedIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.DeletedIncident.processedAt | Date | When the request was processed | 
| OpsGenie.DeletedIncident.requestId | String | The ID of the request | 
| OpsGenie.DeletedIncident.status | String | The human readable result of the request | 
| OpsGenie.DeletedIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-delete-incident incident_id=c59086e0-bf2c-44e2-bdfb-ed7747cc126b```

#### Human Readable Output

>null

### opsgenie-get-polling-result
***
Inside command for polling


#### Base Command

`opsgenie-get-polling-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | Id of request. | Required | 
| request_type_suffix | request_type_suffix. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### opsgenie-get-incidents
***
List the current incidents from OpsGenie.


#### Base Command

`opsgenie-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Optional | 
| limit | Maximum results to return. Default is 20. | Optional | 
| offset | Start index of the result set (to apply pagination). Minimum value (and also default value) is 0. Default is 0. | Optional | 
| status | The ID of the alert from opsgenie. Possible values are: Open, Closed. | Optional | 
| priority | Incident Priority. Defaulted to P3 if not provided. Possible values are: P1, P2, P3, P4, P5. Default is P3. | Optional | 
| tags | Comma separated list of tags to add. | Optional | 
| query | URL Encoded query params. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Incident.acknowledged | Boolean | State of Acknoweledgement | 
| OpsGenie.Incident.alias | String | Alert Alias | 
| OpsGenie.Incident.count | Number | Count of Alert occurences | 
| OpsGenie.Incident.createdAt | Date | Time alert created | 
| OpsGenie.Incident.id | String | ID of alert | 
| OpsGenie.Incident.integration.id | String | ID of integration | 
| OpsGenie.Incident.integration.name | String | Integration name | 
| OpsGenie.Incident.integration.type | String | Type of integration | 
| OpsGenie.Incident.isSeen | Boolean | Whether alert has been seen | 
| OpsGenie.Incident.lastOccurredAt | Date | Time alert last occured | 
| OpsGenie.Incident.message | String | Alert Message | 
| OpsGenie.Incident.owner | String | Owner of Alert | 
| OpsGenie.Incident.ownerTeamId | String | Team ID of Owner | 
| OpsGenie.Incident.priority | String | Alert Priority | 
| OpsGenie.Incident.responders.id | String | ID of responders | 
| OpsGenie.Incident.responders.type | String | Type of Responders | 
| OpsGenie.Incident.seen | Boolean | Seen status of alert | 
| OpsGenie.Incident.snoozed | Boolean | Whether alert has been snoozed | 
| OpsGenie.Incident.source | String | Source of Alert | 
| OpsGenie.Incident.status | String | Status of Alert | 
| OpsGenie.Incident.teams.id | String | Id of teams associated with Alert | 
| OpsGenie.Incident.tinyId | String | Shorter ID for alert | 
| OpsGenie.Incident.updatedAt | Date | Last Updated time for Alert | 
| OpsGenie.Incident.report.ackTime | Number | Acknoweledgement Time of Alert | 
| OpsGenie.Incident.report.acknowledgedBy | String | User that Acknolwedged the alert | 
| OpsGenie.Incident.report.closeTime | Number | Time Alarm closed | 
| OpsGenie.Incident.report.closedBy | String | Who Closed the alarm | 


#### Command Example
```!opsgenie-get-incidents```

#### Human Readable Output

>```
>{
>    "data": [
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T14:15:55.393Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "3ecac888-add8-4fcc-93e7-5414016f4daf",
>            "impactStartDate": "2021-11-15T14:15:55.393Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/3ecac888-add8-4fcc-93e7-5414016f4daf",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/3ecac888-add8-4fcc-93e7-5414016f4daf"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "64",
>            "updatedAt": "2021-11-15T14:15:55.393Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T14:14:12.08Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "641950ef-b108-40cb-b415-10714e077327",
>            "impactStartDate": "2021-11-15T14:14:12.08Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/641950ef-b108-40cb-b415-10714e077327",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/641950ef-b108-40cb-b415-10714e077327"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "63",
>            "updatedAt": "2021-11-15T14:14:12.08Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T14:07:31.52Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "5c99c4a0-0e99-45d5-befe-7db9ba120a8f",
>            "impactStartDate": "2021-11-15T14:07:31.52Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/5c99c4a0-0e99-45d5-befe-7db9ba120a8f",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/5c99c4a0-0e99-45d5-befe-7db9ba120a8f"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "62",
>            "updatedAt": "2021-11-15T14:07:31.52Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T13:58:21.953Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "7cd417c9-e5f9-4622-873e-6c6f236375c6",
>            "impactStartDate": "2021-11-15T13:58:21.953Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/7cd417c9-e5f9-4622-873e-6c6f236375c6",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/7cd417c9-e5f9-4622-873e-6c6f236375c6"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "61",
>            "updatedAt": "2021-11-15T13:58:21.953Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T13:32:14.768Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "94b56f03-bfac-4102-a20c-6636dc20c2e0",
>            "impactStartDate": "2021-11-15T13:32:14.768Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/94b56f03-bfac-4102-a20c-6636dc20c2e0",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/94b56f03-bfac-4102-a20c-6636dc20c2e0"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "60",
>            "updatedAt": "2021-11-15T13:32:14.768Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T13:21:13.489Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "7c9be26c-3279-465b-b829-36d8f21f65d4",
>            "impactStartDate": "2021-11-15T13:21:13.489Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/7c9be26c-3279-465b-b829-36d8f21f65d4",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/7c9be26c-3279-465b-b829-36d8f21f65d4"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "59",
>            "updatedAt": "2021-11-15T13:21:13.489Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T13:17:03.811Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "b1ee9538-60c1-4919-b9a9-d6ad54e25a32",
>            "impactStartDate": "2021-11-15T13:17:03.811Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/b1ee9538-60c1-4919-b9a9-d6ad54e25a32",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/b1ee9538-60c1-4919-b9a9-d6ad54e25a32"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "58",
>            "updatedAt": "2021-11-15T13:17:03.811Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T11:40:27.68Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "26d25ba2-5cbb-456e-bd4f-9875c0b6129c",
>            "impactStartDate": "2021-11-15T11:40:27.68Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/26d25ba2-5cbb-456e-bd4f-9875c0b6129c",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/26d25ba2-5cbb-456e-bd4f-9875c0b6129c"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "57",
>            "updatedAt": "2021-11-15T11:40:27.68Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T10:50:24.124Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "2f14f643-ceb3-498b-a265-41a67e2f668c",
>            "impactStartDate": "2021-11-15T10:50:24.124Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/2f14f643-ceb3-498b-a265-41a67e2f668c",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/2f14f643-ceb3-498b-a265-41a67e2f668c"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "56",
>            "updatedAt": "2021-11-15T10:50:24.124Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T10:44:39.855Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "577424c1-b03c-4d23-9871-da0d395fea17",
>            "impactStartDate": "2021-11-15T10:44:39.855Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/577424c1-b03c-4d23-9871-da0d395fea17",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/577424c1-b03c-4d23-9871-da0d395fea17"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [
>                {
>                    "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
>                    "type": "team"
>                }
>            ],
>            "status": "open",
>            "tags": [],
>            "tinyId": "55",
>            "updatedAt": "2021-11-15T10:55:36.883Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T10:37:34.264Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "6932dc81-7be7-484e-bd99-e631b0272e02",
>            "impactStartDate": "2021-11-15T10:37:34.264Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/6932dc81-7be7-484e-bd99-e631b0272e02",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/6932dc81-7be7-484e-bd99-e631b0272e02"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "54",
>            "updatedAt": "2021-11-15T10:37:34.264Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T10:02:46.289Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "b15c7555-d685-4a96-8798-46320618004e",
>            "impactEndDate": "2021-11-15T10:08:58.793Z",
>            "impactStartDate": "2021-11-15T10:02:46.289Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/b15c7555-d685-4a96-8798-46320618004e",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/b15c7555-d685-4a96-8798-46320618004e"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "resolved",
>            "tags": [
>                "3",
>                "4"
>            ],
>            "tinyId": "53",
>            "updatedAt": "2021-11-15T14:14:26.813Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T09:52:14.456Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "6e5e983a-5bd2-4b5c-ba79-a2a3db26060b",
>            "impactStartDate": "2021-11-15T09:52:14.456Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/6e5e983a-5bd2-4b5c-ba79-a2a3db26060b",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/6e5e983a-5bd2-4b5c-ba79-a2a3db26060b"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "51",
>            "updatedAt": "2021-11-15T09:52:14.456Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-15T08:44:34.219Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "1f3be883-23f4-4728-bb31-e0130633b8b1",
>            "impactStartDate": "2021-11-15T08:44:34.219Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/1f3be883-23f4-4728-bb31-e0130633b8b1",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/1f3be883-23f4-4728-bb31-e0130633b8b1"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "50",
>            "updatedAt": "2021-11-15T08:44:34.219Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-14T22:57:12.454Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "1980bf75-b890-420f-b693-36d557c2bd1a",
>            "impactStartDate": "2021-11-14T22:57:12.454Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/1980bf75-b890-420f-b693-36d557c2bd1a",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/1980bf75-b890-420f-b693-36d557c2bd1a"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "49",
>            "updatedAt": "2021-11-14T22:57:12.454Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-14T22:50:26.497Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "12358be4-23b6-40cf-8bba-f95c7c3fe78b",
>            "impactStartDate": "2021-11-14T22:50:26.497Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/12358be4-23b6-40cf-8bba-f95c7c3fe78b",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/12358be4-23b6-40cf-8bba-f95c7c3fe78b"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "48",
>            "updatedAt": "2021-11-14T22:50:26.497Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-14T22:48:09.794Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "91b9bc7a-226c-45bd-8c9f-41b8e17c21fd",
>            "impactStartDate": "2021-11-14T22:48:09.794Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/91b9bc7a-226c-45bd-8c9f-41b8e17c21fd",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/91b9bc7a-226c-45bd-8c9f-41b8e17c21fd"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "47",
>            "updatedAt": "2021-11-14T22:48:09.794Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-14T22:46:14.557Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "f834ea92-1251-41e2-a08d-cf34500c60ba",
>            "impactStartDate": "2021-11-14T22:46:14.557Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/f834ea92-1251-41e2-a08d-cf34500c60ba",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/f834ea92-1251-41e2-a08d-cf34500c60ba"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "46",
>            "updatedAt": "2021-11-14T22:46:14.557Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-14T22:43:52.388Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "4ab01f6e-a7e6-4440-82d2-26057e8947bd",
>            "impactStartDate": "2021-11-14T22:43:52.388Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/4ab01f6e-a7e6-4440-82d2-26057e8947bd",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/4ab01f6e-a7e6-4440-82d2-26057e8947bd"
>            },
>            "message": "An example incident message",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "45",
>            "updatedAt": "2021-11-14T22:43:52.388Z"
>        },
>        {
>            "actions": [],
>            "createdAt": "2021-11-14T22:39:52.379Z",
>            "description": "",
>            "event_type": "Incidents",
>            "extraProperties": {},
>            "id": "00b1fcdf-e682-4f6a-965d-ab0cb8a13dd9",
>            "impactStartDate": "2021-11-14T22:39:52.379Z",
>            "impactedServices": [],
>            "links": {
>                "api": "https:<span>//</span>api.opsgenie.com/v1/incidents/00b1fcdf-e682-4f6a-965d-ab0cb8a13dd9",
>                "web": "https:<span>//</span>demisto1.app.opsgenie.com/incident/detail/00b1fcdf-e682-4f6a-965d-ab0cb8a13dd9"
>            },
>            "message": "test",
>            "ownerTeam": "",
>            "priority": "P3",
>            "responders": [],
>            "status": "open",
>            "tags": [],
>            "tinyId": "44",
>            "updatedAt": "2021-11-14T22:39:52.379Z"
>        }
>    ],
>    "paging": {
>        "first": "https:<span>//</span>api.opsgenie.com/v1/incidents?limit=20&sort=insertedAt&offset=0&order=desc",
>        "last": "https:<span>//</span>api.opsgenie.com/v1/incidents?limit=20&sort=insertedAt&offset=60&order=desc",
>        "next": "https:<span>//</span>api.opsgenie.com/v1/incidents?limit=20&sort=insertedAt&offset=20&order=desc"
>    },
>    "requestId": "d3300075-682a-4b05-b3f7-eda5ec43aed0",
>    "took": 0.104,
>    "totalCount": 62
>}
>```

### opsgenie-close-incident
***
Close an incident from OpsGenie


#### Base Command

`opsgenie-close-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| note | Additional incident note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.ClosedIncident.action | String | Action of this Request | 
| OpsGenie.ClosedIncident.alertId | String | Id of closed incident | 
| OpsGenie.ClosedIncident.alias | String | Alais of closed incident | 
| OpsGenie.ClosedIncident.integrationId | String | Integration of closed incident | 
| OpsGenie.ClosedIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.ClosedIncident.processedAt | Date | When the request was processed | 
| OpsGenie.ClosedIncident.requestId | String | The ID of the request | 
| OpsGenie.ClosedIncident.status | String | The human readable result of the request | 
| OpsGenie.ClosedIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-close-incident incident_id=c59086e0-bf2c-44e2-bdfb-ed7747cc126b```

#### Context Example
```json
{
    "data": {
        "action": "Delete",
        "alertId": "",
        "alias": "",
        "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
        "isSuccess": false,
        "processedAt": "2021-11-15T14:15:46.687Z",
        "status": "Alert does not exist",
        "success": false
    },
    "requestId": "e76aa645-7d5a-4698-a69b-08cb0a2787ca",
    "took": 0.003
}
```

#### Human Readable Output

>null

### opsgenie-resolve-incident
***
Resolve an incident from OpsGenie


#### Base Command

`opsgenie-resolve-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| note | Additional incident note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.ResolvedIncident.action | String | Action of this Request | 
| OpsGenie.ResolvedIncident.alertId | String | Id of closed incident | 
| OpsGenie.ResolvedIncident.alias | String | Alais of closed incident | 
| OpsGenie.ResolvedIncident.integrationId | String | Integration of closed incident | 
| OpsGenie.ResolvedIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.ResolvedIncident.processedAt | Date | When the request was processed | 
| OpsGenie.ResolvedIncident.requestId | String | The ID of the request | 
| OpsGenie.ResolvedIncident.status | String | The human readable result of the request | 
| OpsGenie.ResolvedIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-resolve-incident incident_id=b15c7555-d685-4a96-8798-46320618004e```

#### Human Readable Output

>null

### opsgenie-add-responder-incident
***
Add responder to an OpsGenie Incident


#### Base Command

`opsgenie-add-responder-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| responders | Team or user that the incident will be routed to. List of triples (responser_type, value_type, value). | Required | 
| note | Additional alert note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AddResponderIncident.action | String | Action of this Request | 
| OpsGenie.AddResponderIncident.alertId | String | ID of created Incident | 
| OpsGenie.AddResponderIncident.alias | String | Alais of created Incident | 
| OpsGenie.AddResponderIncident.integrationId | String | Integration of created Incident | 
| OpsGenie.AddResponderIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AddResponderIncident.processedAt | Date | When the request was processed | 
| OpsGenie.AddResponderIncident.requestId | String | The ID of the request | 
| OpsGenie.AddResponderIncident.status | String | The human readable result of the request | 
| OpsGenie.AddResponderIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-add-responder-incident incident_id=577424c1-b03c-4d23-9871-da0d395fea17 responders="team,name,Integration Team"```

#### Human Readable Output

>null

### opsgenie-add-tag-incident
***
Add tag into OpsGenie Incident


#### Base Command

`opsgenie-add-tag-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| tags | Comma separated list of tags to add into incident. | Required | 
| note | Additional incident note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.AddTagIncident.action | String | Action of this Request | 
| OpsGenie.AddTagIncident.alertId | String | ID of added Incident | 
| OpsGenie.AddTagIncident.alias | String | Alais of added Incident | 
| OpsGenie.AddTagIncident.integrationId | String | Integration of added Incident | 
| OpsGenie.AddTagIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.AddTagIncident.processedAt | Date | When the request was processed | 
| OpsGenie.AddTagIncident.requestId | String | The ID of the request | 
| OpsGenie.AddTagIncident.status | String | The human readable result of the request | 
| OpsGenie.AddTagIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-add-tag-incident incident_id=b15c7555-d685-4a96-8798-46320618004e tags=1,2,3```

#### Context Example
```json
{
    "data": {
        "action": "Create",
        "incidentId": "3ecac888-add8-4fcc-93e7-5414016f4daf",
        "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
        "isSuccess": true,
        "processedAt": "2021-11-15T14:15:55.491Z",
        "status": "Incident created successfully",
        "success": true
    },
    "requestId": "a2504b4a-f47f-40b0-b53c-7eb241c3b0f8",
    "took": 0.03
}
```

#### Human Readable Output

>null

### opsgenie-remove-tag-incident
***
Remove tag from OpsGenie Alert


#### Base Command

`opsgenie-remove-tag-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident from opsgenie. | Required | 
| interval_in_seconds | Interval in seconds between each poll. Default is 5. | Optional | 
| tags | Comma separated list of tags to add into incident. | Required | 
| note | Additional incident note to add. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.RemoveTagIncident.action | String | Action of this Request | 
| OpsGenie.RemoveTagIncident.alertId | String | ID of removed tag Incident | 
| OpsGenie.RemoveTagIncident.alias | String | Alais of removed tag Incident | 
| OpsGenie.RemoveTagIncident.integrationId | String | Integration of removed tag Incident | 
| OpsGenie.RemoveTagIncident.isSuccess | Boolean | If the request was successful | 
| OpsGenie.RemoveTagIncident.processedAt | Date | When the request was processed | 
| OpsGenie.RemoveTagIncident.requestId | String | The ID of the request | 
| OpsGenie.RemoveTagIncident.status | String | The human readable result of the request | 
| OpsGenie.RemoveTagIncident.success | Boolean | Bool, whether the request was a success | 


#### Command Example
```!opsgenie-remove-tag-incident incident_id=b15c7555-d685-4a96-8798-46320618004e tags=1,2```

#### Context Example
```json
{
    "data": {
        "action": "Close",
        "incidentId": "",
        "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
        "isSuccess": false,
        "processedAt": "2021-11-15T14:15:57.429Z",
        "status": "",
        "success": false
    },
    "requestId": "314af988-7189-46d2-a767-30bc16100a1c",
    "took": 0.037
}
```

#### Human Readable Output

>null

### opsgenie-get-teams
***
Get teams


#### Base Command

`opsgenie-get-teams`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | The ID of the team from opsgenie. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpsGenie.Team.description | String | Team description | 
| OpsGenie.Team.id | String | Team id | 
| OpsGenie.Team.links.api | String | Team api links | 
| OpsGenie.Team.links.web | String | Team web links | 
| OpsGenie.Team.name | String | Team name | 


#### Command Example
```!opsgenie-get-teams```

#### Context Example
```json
{
    "OpsGenie": {
        "Schedule": [
            {
                "description": "Engineering",
                "id": "51d69df8-c40b-439e-9808-e1a78e54f91b",
                "links": {
                    "api": "https://api.opsgenie.com/v2/teams/51d69df8-c40b-439e-9808-e1a78e54f91b",
                    "web": "https://demisto1.app.opsgenie.com/teams/dashboard/51d69df8-c40b-439e-9808-e1a78e54f91b/main"
                },
                "name": "Engineering"
            },
            {
                "description": "Integration Team",
                "id": "fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                "links": {
                    "api": "https://api.opsgenie.com/v2/teams/fbbc3f9a-12f4-4794-9938-7e0a85a06f8b",
                    "web": "https://demisto1.app.opsgenie.com/teams/dashboard/fbbc3f9a-12f4-4794-9938-7e0a85a06f8b/main"
                },
                "name": "Integration Team"
            }
        ]
    },
    "data": {
        "action": "Delete",
        "incidentId": "",
        "integrationId": "3cc69931-167f-411c-a331-768997c29d2e",
        "isSuccess": false,
        "processedAt": "2021-11-15T14:15:59.138Z",
        "status": "",
        "success": false
    },
    "requestId": "c890b46e-0a26-4b8c-978f-fc56873fecfa",
    "took": 0.005
}
```

#### Human Readable Output

>### OpsGenie Schedule
>|description|id|links|name|
>|---|---|---|---|
>| Engineering | 51d69df8-c40b-439e-9808-e1a78e54f91b | web: https:<span>//</span>demisto1.app.opsgenie.com/teams/dashboard/51d69df8-c40b-439e-9808-e1a78e54f91b/main<br/>api: https:<span>//</span>api.opsgenie.com/v2/teams/51d69df8-c40b-439e-9808-e1a78e54f91b | Engineering |
>| Integration Team | fbbc3f9a-12f4-4794-9938-7e0a85a06f8b | web: https:<span>//</span>demisto1.app.opsgenie.com/teams/dashboard/fbbc3f9a-12f4-4794-9938-7e0a85a06f8b/main<br/>api: https:<span>//</span>api.opsgenie.com/v2/teams/fbbc3f9a-12f4-4794-9938-7e0a85a06f8b | Integration Team |


## Breaking changes from the previous version of this integration - OpsGenie v3
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *opsgenie-list-alerts* - this command was replaced by XXX.
* *opsgenie-get-alert* - this command was replaced by XXX.
* *opsgenie-get-schedule* - this command was replaced by XXX.
* *opsgenie-list-schedules* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *opsgenie-create-alert* command:
* *priority* - this argument was replaced by XXX.

In the *opsgenie-get-on-call* command:
* *schedule-id* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *opsgenie-create-alert* command:
* *priority* - The default value changed to 'P3'.

### Outputs
#### The following outputs were removed in this version:

In the *opsgenie-create-alert* command:
* *OpsGenieV2.CreatedAlert.action* - this output was replaced by XXX.
* *OpsGenieV2.CreatedAlert.alertId* - this output was replaced by XXX.
* *OpsGenieV2.CreatedAlert.alias* - this output was replaced by XXX.
* *OpsGenieV2.CreatedAlert.integrationId* - this output was replaced by XXX.
* *OpsGenieV2.CreatedAlert.isSuccess* - this output was replaced by XXX.
* *OpsGenieV2.CreatedAlert.processedAt* - this output was replaced by XXX.
* *OpsGenieV2.CreatedAlert.requestId* - this output was replaced by XXX.
* *OpsGenieV2.CreatedAlert.status* - this output was replaced by XXX.
* *OpsGenieV2.CreatedAlert.success* - this output was replaced by XXX.

In the *opsgenie-delete-alert* command:
* *OpsGenieV2.DeletedAlert.action* - this output was replaced by XXX.
* *OpsGenieV2.DeletedAlert.alertId* - this output was replaced by XXX.
* *OpsGenieV2.DeletedAlert.alias* - this output was replaced by XXX.
* *OpsGenieV2.DeletedAlert.integrationId* - this output was replaced by XXX.
* *OpsGenieV2.DeletedAlert.isSuccess* - this output was replaced by XXX.
* *OpsGenieV2.DeletedAlert.processedAt* - this output was replaced by XXX.
* *OpsGenieV2.DeletedAlert.requestId* - this output was replaced by XXX.
* *OpsGenieV2.DeletedAlert.status* - this output was replaced by XXX.
* *OpsGenieV2.DeletedAlert.success* - this output was replaced by XXX.

In the *opsgenie-ack-alert* command:
* *OpsGenieV2.AckedAlert.action* - this output was replaced by XXX.
* *OpsGenieV2.AckedAlert.alertId* - this output was replaced by XXX.
* *OpsGenieV2.AckedAlert.alias* - this output was replaced by XXX.
* *OpsGenieV2.AckedAlert.integrationId* - this output was replaced by XXX.
* *OpsGenieV2.AckedAlert.isSuccess* - this output was replaced by XXX.
* *OpsGenieV2.AckedAlert.processedAt* - this output was replaced by XXX.
* *OpsGenieV2.AckedAlert.requestId* - this output was replaced by XXX.
* *OpsGenieV2.AckedAlert.status* - this output was replaced by XXX.
* *OpsGenieV2.AckedAlert.success* - this output was replaced by XXX.

In the *opsgenie-get-on-call* command:
* *OpsGenieV2.OnCall._parent.enabled* - this output was replaced by XXX.
* *OpsGenieV2.OnCall._parent.id* - this output was replaced by XXX.
* *OpsGenieV2.OnCall._parent.name* - this output was replaced by XXX.
* *OpsGenieV2.OnCall.onCallParticipants.id* - this output was replaced by XXX.
* *OpsGenieV2.OnCall.onCallParticipants.name* - this output was replaced by XXX.
* *OpsGenieV2.OnCall.onCallParticipants.type* - this output was replaced by XXX.

In the *opsgenie-close-alert* command:
* *OpsGenieV2.CloseAlert.action* - this output was replaced by XXX.
* *OpsGenieV2.CloseAlert.alertId* - this output was replaced by XXX.
* *OpsGenieV2.CloseAlert.alias* - this output was replaced by XXX.
* *OpsGenieV2.CloseAlert.integrationId* - this output was replaced by XXX.
* *OpsGenieV2.CloseAlert.isSuccess* - this output was replaced by XXX.
* *OpsGenieV2.CloseAlert.processedAt* - this output was replaced by XXX.
* *OpsGenieV2.CloseAlert.requestId* - this output was replaced by XXX.
* *OpsGenieV2.CloseAlert.status* - this output was replaced by XXX.
* *OpsGenieV2.CloseAlert.success* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
