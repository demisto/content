reflect and manage the Lumu Incidents either from XSOAR Cortex or viceversa using the mirroring integration flow, https://lumu.io/
This integration was integrated and tested with version 20230126 of Lumu

## Configure Lumu on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Lumu.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Maximum number of incidents to fetch every time |  | False |
    | First fetch time interval | The time range to consider for the initial data fetch. \(&amp;lt;number&amp;gt; &amp;lt;unit&amp;gt;, e.g., 2 minutes, 2 hours, 2 days, 2 months, 2 years\). Default is 3 days. | False |
    | Server URL |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | API Key |  | True |
    | Incident Offset |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Incidents Fetch Interval |  | False |
    | Incident Mirroring Direction | Selects which direction you want the incidents mirrored. You can mirror \*\*Incoming\*\* only \(from Lumu to Cortex XSOAR\), \*\*Outgoing\*\* only \(from Cortex XSOAR to Lumu\), or both \*\*Incoming And Outgoing\*\*. | False |
    | Mirror tags | Comment and files that will be marked with this tag will be pushed into Lumu. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lumu-retrieve-labels
***
Get a paginated list of all the labels created for the company and its details such as id, name and business relevance. The items are sorted by the label id in ascending order.


#### Base Command

`lumu-retrieve-labels`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | . | Optional | 
| items | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveLabels.labels.id | Number |  | 
| Lumu.RetrieveLabels.labels.name | String |  | 
| Lumu.RetrieveLabels.labels.relevance | Number |  | 
| Lumu.RetrieveLabels.paginationInfo.page | Number |  | 
| Lumu.RetrieveLabels.paginationInfo.items | Number |  | 
| Lumu.RetrieveLabels.paginationInfo.next | Number |  | 
| Lumu.RetrieveLabels.paginationInfo.prev | Number |  | 

#### Command example
```!lumu-retrieve-labels```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveLabels": {
            "labels": [
                {
                    "id": 51,
                    "name": "Mi Ofi",
                    "relevance": 1
                },
                {
                    "id": 112,
                    "name": "Lab1",
                    "relevance": 1
                },
                {
                    "id": 113,
                    "name": "Lab2",
                    "relevance": 1
                },
                {
                    "id": 134,
                    "name": "cd test",
                    "relevance": 1
                },
                {
                    "id": 147,
                    "name": "cd",
                    "relevance": 1
                },
                {
                    "id": 173,
                    "name": "VA 3.1.2 Test",
                    "relevance": 1
                },
                {
                    "id": 218,
                    "name": "acastaneda",
                    "relevance": 1
                },
                {
                    "id": 227,
                    "name": "VA 1.3.3 Label",
                    "relevance": 1
                },
                {
                    "id": 280,
                    "name": "client test",
                    "relevance": 1
                },
                {
                    "id": 331,
                    "name": "VA 3.1.3",
                    "relevance": 1
                },
                {
                    "id": 375,
                    "name": "Pablo Home",
                    "relevance": 1
                },
                {
                    "id": 384,
                    "name": "jcastellanos",
                    "relevance": 1
                },
                {
                    "id": 548,
                    "name": "QA AgentLabel",
                    "relevance": 1
                },
                {
                    "id": 648,
                    "name": "PaloAltoFw",
                    "relevance": 1
                },
                {
                    "id": 754,
                    "name": "Low",
                    "relevance": 1
                },
                {
                    "id": 805,
                    "name": "felipeg-test1",
                    "relevance": 1
                },
                {
                    "id": 807,
                    "name": "new label",
                    "relevance": 1
                },
                {
                    "id": 822,
                    "name": "DnsPacketsCol",
                    "relevance": 1
                },
                {
                    "id": 825,
                    "name": "Sophos label",
                    "relevance": 1
                },
                {
                    "id": 864,
                    "name": "CTIS_TEST",
                    "relevance": 3
                },
                {
                    "id": 989,
                    "name": "aarguelles",
                    "relevance": 1
                },
                {
                    "id": 994,
                    "name": "QA AgentLabelNetflow",
                    "relevance": 2
                },
                {
                    "id": 1004,
                    "name": "LumuChannel-Test",
                    "relevance": 2
                },
                {
                    "id": 1007,
                    "name": "qwertylabel1",
                    "relevance": 1
                },
                {
                    "id": 1009,
                    "name": "Oscar",
                    "relevance": 1
                },
                {
                    "id": 1010,
                    "name": "nuevo_label",
                    "relevance": 1
                },
                {
                    "id": 1013,
                    "name": "ForcePoint",
                    "relevance": 2
                },
                {
                    "id": 1014,
                    "name": "felipeGPLabel",
                    "relevance": 1
                },
                {
                    "id": 1050,
                    "name": "McafeeLabel",
                    "relevance": 1
                },
                {
                    "id": 1087,
                    "name": "Garf",
                    "relevance": 1
                },
                {
                    "id": 1179,
                    "name": "FGiraldo-VA",
                    "relevance": 2
                },
                {
                    "id": 1189,
                    "name": "BarracudaLB",
                    "relevance": 2
                },
                {
                    "id": 1280,
                    "name": "SonicWallLabel",
                    "relevance": 1
                },
                {
                    "id": 1308,
                    "name": "Karevalo PROD label",
                    "relevance": 2
                },
                {
                    "id": 1340,
                    "name": "Kevin Arevalo test",
                    "relevance": 1
                },
                {
                    "id": 1409,
                    "name": "Demo",
                    "relevance": 3
                },
                {
                    "id": 1426,
                    "name": "newMSPFelipe",
                    "relevance": 2
                },
                {
                    "id": 1580,
                    "name": "Raul Test Label",
                    "relevance": 1
                },
                {
                    "id": 1651,
                    "name": "dcaldas",
                    "relevance": 2
                },
                {
                    "id": 1791,
                    "name": "ChangeKafka",
                    "relevance": 2
                },
                {
                    "id": 1792,
                    "name": "FGP-personalAgent",
                    "relevance": 3
                },
                {
                    "id": 1851,
                    "name": "UmbrellaPull-FGP",
                    "relevance": 2
                },
                {
                    "id": 1876,
                    "name": "CTI MOBILE",
                    "relevance": 3
                },
                {
                    "id": 1885,
                    "name": "Umbrella DC label",
                    "relevance": 3
                },
                {
                    "id": 1988,
                    "name": "UmbrellaPull2",
                    "relevance": 3
                },
                {
                    "id": 2041,
                    "name": "mmeneses",
                    "relevance": 1
                },
                {
                    "id": 2144,
                    "name": "InternalLAN",
                    "relevance": 3
                },
                {
                    "id": 2148,
                    "name": "AWSVpcProd",
                    "relevance": 1
                },
                {
                    "id": 2150,
                    "name": "1.0.2.0 Label",
                    "relevance": 2
                },
                {
                    "id": 2204,
                    "name": "TEST_VT",
                    "relevance": 3
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|labels|paginationInfo|
>|---|---|
>| {'id': 51, 'name': 'Mi Ofi', 'relevance': 1},<br/>{'id': 112, 'name': 'Lab1', 'relevance': 1},<br/>{'id': 113, 'name': 'Lab2', 'relevance': 1},<br/>{'id': 134, 'name': 'cd test', 'relevance': 1},<br/>{'id': 147, 'name': 'cd', 'relevance': 1},<br/>{'id': 173, 'name': 'VA 3.1.2 Test', 'relevance': 1},<br/>{'id': 218, 'name': 'acastaneda', 'relevance': 1},<br/>{'id': 227, 'name': 'VA 1.3.3 Label', 'relevance': 1},<br/>{'id': 280, 'name': 'client test', 'relevance': 1},<br/>{'id': 331, 'name': 'VA 3.1.3', 'relevance': 1},<br/>{'id': 375, 'name': 'Pablo Home', 'relevance': 1},<br/>{'id': 384, 'name': 'jcastellanos', 'relevance': 1},<br/>{'id': 548, 'name': 'QA AgentLabel', 'relevance': 1},<br/>{'id': 648, 'name': 'PaloAltoFw', 'relevance': 1},<br/>{'id': 754, 'name': 'Low', 'relevance': 1},<br/>{'id': 805, 'name': 'felipeg-test1', 'relevance': 1},<br/>{'id': 807, 'name': 'new label', 'relevance': 1},<br/>{'id': 822, 'name': 'DnsPacketsCol', 'relevance': 1},<br/>{'id': 825, 'name': 'Sophos label', 'relevance': 1},<br/>{'id': 864, 'name': 'CTIS_TEST', 'relevance': 3},<br/>{'id': 989, 'name': 'aarguelles', 'relevance': 1},<br/>{'id': 994, 'name': 'QA AgentLabelNetflow', 'relevance': 2},<br/>{'id': 1004, 'name': 'LumuChannel-Test', 'relevance': 2},<br/>{'id': 1007, 'name': 'qwertylabel1', 'relevance': 1},<br/>{'id': 1009, 'name': 'Oscar', 'relevance': 1},<br/>{'id': 1010, 'name': 'nuevo_label', 'relevance': 1},<br/>{'id': 1013, 'name': 'ForcePoint', 'relevance': 2},<br/>{'id': 1014, 'name': 'felipeGPLabel', 'relevance': 1},<br/>{'id': 1050, 'name': 'McafeeLabel', 'relevance': 1},<br/>{'id': 1087, 'name': 'Garf', 'relevance': 1},<br/>{'id': 1179, 'name': 'FGiraldo-VA', 'relevance': 2},<br/>{'id': 1189, 'name': 'BarracudaLB', 'relevance': 2},<br/>{'id': 1280, 'name': 'SonicWallLabel', 'relevance': 1},<br/>{'id': 1308, 'name': 'Karevalo PROD label', 'relevance': 2},<br/>{'id': 1340, 'name': 'Kevin Arevalo test', 'relevance': 1},<br/>{'id': 1409, 'name': 'Demo', 'relevance': 3},<br/>{'id': 1426, 'name': 'newMSPFelipe', 'relevance': 2},<br/>{'id': 1580, 'name': 'Raul Test Label', 'relevance': 1},<br/>{'id': 1651, 'name': 'dcaldas', 'relevance': 2},<br/>{'id': 1791, 'name': 'ChangeKafka', 'relevance': 2},<br/>{'id': 1792, 'name': 'FGP-personalAgent', 'relevance': 3},<br/>{'id': 1851, 'name': 'UmbrellaPull-FGP', 'relevance': 2},<br/>{'id': 1876, 'name': 'CTI MOBILE', 'relevance': 3},<br/>{'id': 1885, 'name': 'Umbrella DC label', 'relevance': 3},<br/>{'id': 1988, 'name': 'UmbrellaPull2', 'relevance': 3},<br/>{'id': 2041, 'name': 'mmeneses', 'relevance': 1},<br/>{'id': 2144, 'name': 'InternalLAN', 'relevance': 3},<br/>{'id': 2148, 'name': 'AWSVpcProd', 'relevance': 1},<br/>{'id': 2150, 'name': '1.0.2.0 Label', 'relevance': 2},<br/>{'id': 2204, 'name': 'TEST_VT', 'relevance': 3} | page: 1<br/>items: 50<br/>next: 2 |


### lumu-retrieve-a-specific-label
***
Get details such as id, name and business relevance from a specific label.

| `{label-id}` | ID of the specific label |
|---|---|


#### Base Command

`lumu-retrieve-a-specific-label`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label_id | . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveASpecificLabel.id | Number |  | 
| Lumu.RetrieveASpecificLabel.name | String |  | 
| Lumu.RetrieveASpecificLabel.relevance | Number |  | 

#### Command example
```!lumu-retrieve-a-specific-label label_id=51```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveASpecificLabel": {
            "id": 51,
            "name": "Mi Ofi",
            "relevance": 1
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|name|relevance|
>|---|---|---|
>| 51 | Mi Ofi | 1 |


### lumu-retrieve-incidents
***
Get a paginated list of incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | . | Optional | 
| items | . | Optional | 
| fromdate | . | Optional | 
| todate | . | Optional | 
| status | . | Optional | 
| adversary-types | . | Optional | 
| labels | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveIncidents.items.id | String |  | 
| Lumu.RetrieveIncidents.items.timestamp | Date |  | 
| Lumu.RetrieveIncidents.items.statusTimestamp | Date |  | 
| Lumu.RetrieveIncidents.items.status | String |  | 
| Lumu.RetrieveIncidents.items.contacts | Number |  | 
| Lumu.RetrieveIncidents.items.adversaries | String |  | 
| Lumu.RetrieveIncidents.items.adversaryTypes | String |  | 
| Lumu.RetrieveIncidents.items.labelDistribution.17 | Number |  | 
| Lumu.RetrieveIncidents.items.totalEndpoints | Number |  | 
| Lumu.RetrieveIncidents.items.lastContact | Date |  | 
| Lumu.RetrieveIncidents.items.unread | Boolean |  | 
| Lumu.RetrieveIncidents.paginationInfo.page | Number |  | 
| Lumu.RetrieveIncidents.paginationInfo.items | Number |  | 

#### Command example
```!lumu-retrieve-incidents```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveIncidents": {
            "items": [
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "muted",
                    "statusTimestamp": "2023-01-26T23:00:36.915Z",
                    "timestamp": "2023-01-26T22:57:47.029Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "78b465c0-9dc5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T22:14:29.778Z",
                    "timestamp": "2023-01-26T22:04:57.756Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "ecc22120-9daa-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T19:08:45.185Z",
                    "timestamp": "2023-01-26T18:54:56.050Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "29dab720-9d1f-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T18:52:06.437Z",
                    "timestamp": "2023-01-26T02:14:29.010Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.sparechange.io"
                    ],
                    "adversaryId": "www.sparechange.io",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-24T14:08:59.469Z",
                    "hasPlaybackContacts": false,
                    "id": "acc03f50-9bf0-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "2254": 3
                    },
                    "lastContact": "2023-01-24T14:23:20.504Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-24T14:09:11.109Z",
                    "timestamp": "2023-01-24T14:09:11.109Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "bonbongame.com"
                    ],
                    "adversaryId": "bonbongame.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-24T12:08:37.234Z",
                    "hasPlaybackContacts": false,
                    "id": "de703020-9bdf-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "2254": 2
                    },
                    "lastContact": "2023-01-24T12:08:37.234Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-24T12:08:53.026Z",
                    "timestamp": "2023-01-24T12:08:53.026Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 98,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 28,
                        "4232": 1,
                        "989": 69
                    },
                    "lastContact": "2023-01-24T21:17:50Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T02:13:33.006Z",
                    "timestamp": "2023-01-24T11:48:56.059Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "f563af00-9bda-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-24T11:45:59.944Z",
                    "timestamp": "2023-01-24T11:33:44.048Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "noment.com"
                    ],
                    "adversaryId": "noment.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 5,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:48:27.684Z",
                    "hasPlaybackContacts": false,
                    "id": "17af99e0-9b70-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 3,
                        "4232": 1
                    },
                    "lastContact": "2023-01-24T20:27:25.049Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-24T11:07:08.277Z",
                    "timestamp": "2023-01-23T22:48:45.438Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "fierdetreroutier.com"
                    ],
                    "adversaryId": "fierdetreroutier.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:30:58.327Z",
                    "hasPlaybackContacts": false,
                    "id": "a5cc17b0-9b6d-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1,
                        "3182": 1
                    },
                    "lastContact": "2023-01-24T20:31:29.489Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:31:15.371Z",
                    "timestamp": "2023-01-23T22:31:15.371Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "aright.de"
                    ],
                    "adversaryId": "aright.de",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:21:31.807Z",
                    "hasPlaybackContacts": false,
                    "id": "520cd7a0-9b6c-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1,
                        "805": 1
                    },
                    "lastContact": "2023-01-24T20:36:26.204Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:21:45.370Z",
                    "timestamp": "2023-01-23T22:21:45.370Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "maximals.ru"
                    ],
                    "adversaryId": "maximals.ru",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:20:54.300Z",
                    "hasPlaybackContacts": false,
                    "id": "3c9a45b0-9b6c-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1,
                        "805": 1
                    },
                    "lastContact": "2023-01-24T20:50:41.786Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:21:09.387Z",
                    "timestamp": "2023-01-23T22:21:09.387Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "lessgeneric.com"
                    ],
                    "adversaryId": "lessgeneric.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:12:38.980Z",
                    "hasPlaybackContacts": false,
                    "id": "158c5e00-9b6b-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T22:12:38.980Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:12:54.368Z",
                    "timestamp": "2023-01-23T22:12:54.368Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "exoticahousing.in"
                    ],
                    "adversaryId": "exoticahousing.in",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:03:27.310Z",
                    "hasPlaybackContacts": false,
                    "id": "ea14b390-9b69-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T22:03:27.310Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:04:31.945Z",
                    "timestamp": "2023-01-23T22:04:31.945Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "andam.vn"
                    ],
                    "adversaryId": "andam.vn",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T21:55:06.459Z",
                    "hasPlaybackContacts": false,
                    "id": "a1f426f0-9b68-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T21:55:06.459Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T21:55:21.439Z",
                    "timestamp": "2023-01-23T21:55:21.439Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "ahmedabadcallgirl.biz"
                    ],
                    "adversaryId": "ahmedabadcallgirl.biz",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T21:54:30.694Z",
                    "hasPlaybackContacts": false,
                    "id": "8e4df090-9b68-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T21:54:30.694Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T21:54:48.473Z",
                    "timestamp": "2023-01-23T21:54:48.473Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "miner.nablabee.com"
                    ],
                    "adversaryId": "miner.nablabee.com",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-23T21:36:19.439Z",
                    "hasPlaybackContacts": false,
                    "id": "01989620-9b66-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T21:36:19.439Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T21:36:33.410Z",
                    "timestamp": "2023-01-23T21:36:33.410Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "skyplanners.com"
                    ],
                    "adversaryId": "skyplanners.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T21:22:35.646Z",
                    "hasPlaybackContacts": false,
                    "id": "15dfb250-9b64-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T21:22:35.646Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T21:22:48.437Z",
                    "timestamp": "2023-01-23T21:22:48.437Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 10,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "2bc88020-9b2c-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 10
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-24T11:33:24.832Z",
                    "timestamp": "2023-01-23T14:42:33.378Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "9b430be0-9b1e-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-23T14:24:09.462Z",
                    "timestamp": "2023-01-23T13:05:27.454Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "249b6b90-9b14-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-23T12:57:59.609Z",
                    "timestamp": "2023-01-23T11:50:33.417Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "cae5a990-99e6-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:58:48.655Z",
                    "timestamp": "2023-01-21T23:53:24.393Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "7db7c400-99e1-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:51:47.406Z",
                    "timestamp": "2023-01-21T23:15:27.424Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "72067f80-99cc-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:13:41.679Z",
                    "timestamp": "2023-01-21T20:44:48.376Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "eaba8420-9932-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T02:27:53.605Z",
                    "timestamp": "2023-01-21T02:25:48.386Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "mykooperativ.ru"
                    ],
                    "adversaryId": "mykooperativ.ru",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-20T23:53:47.814Z",
                    "hasPlaybackContacts": false,
                    "id": "bb540360-991d-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2254": 1
                    },
                    "lastContact": "2023-01-20T23:53:47.814Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-20T23:54:09.430Z",
                    "timestamp": "2023-01-20T23:54:09.430Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "0f055c60-9901-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T02:24:55.326Z",
                    "timestamp": "2023-01-20T20:28:54.438Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "galias.com.co"
                    ],
                    "adversaryId": "galias.com.co",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 3,
                    "description": "Phishing domain",
                    "firstContact": "2023-01-20T13:44:26.511Z",
                    "hasPlaybackContacts": false,
                    "id": "95e1ae70-98c8-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "1179": 1,
                        "147": 1,
                        "4232": 1
                    },
                    "lastContact": "2023-01-24T20:45:31.774Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-20T13:44:39.383Z",
                    "timestamp": "2023-01-20T13:44:39.383Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "museosantiagocarbonell.com"
                    ],
                    "adversaryId": "museosantiagocarbonell.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Ml.B.Wacatac.Script",
                    "firstContact": "2023-01-13T17:11:29.971Z",
                    "hasPlaybackContacts": true,
                    "id": "06883d70-98c3-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "1580": 1
                    },
                    "lastContact": "2023-01-13T17:11:29.971Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-20T13:04:51.399Z",
                    "timestamp": "2023-01-20T13:04:51.399Z",
                    "totalEndpoints": 1,
                    "unread": false
                }
            ],
            "paginationInfo": {
                "items": 50,
                "page": 1
            },
            "timestamp": "2023-01-26T23:17:13.444Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|timestamp|
>|---|---|---|
>| {'id': 'd9bd1450-9dcc-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T22:57:47.029Z', 'statusTimestamp': '2023-01-26T23:00:36.915Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '78b465c0-9dc5-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T22:04:57.756Z', 'statusTimestamp': '2023-01-26T22:14:29.778Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'ecc22120-9daa-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T18:54:56.050Z', 'statusTimestamp': '2023-01-26T19:08:45.185Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '29dab720-9d1f-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T02:14:29.010Z', 'statusTimestamp': '2023-01-26T18:52:06.437Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'acc03f50-9bf0-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T14:09:11.109Z', 'statusTimestamp': '2023-01-24T14:09:11.109Z', 'status': 'open', 'contacts': 3, 'adversaries': ['www.sparechange.io'], 'adversaryId': 'www.sparechange.io', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'2254': 3}, 'totalEndpoints': 2, 'lastContact': '2023-01-24T14:23:20.504Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-24T14:08:59.469Z'},<br/>{'id': 'de703020-9bdf-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T12:08:53.026Z', 'statusTimestamp': '2023-01-24T12:08:53.026Z', 'status': 'open', 'contacts': 2, 'adversaries': ['bonbongame.com'], 'adversaryId': 'bonbongame.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 2}, 'totalEndpoints': 1, 'lastContact': '2023-01-24T12:08:37.234Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-24T12:08:37.234Z'},<br/>{'id': '14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T11:48:56.059Z', 'statusTimestamp': '2023-01-26T02:13:33.006Z', 'status': 'closed', 'contacts': 98, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 28, '989': 69, '4232': 1}, 'totalEndpoints': 4, 'lastContact': '2023-01-24T21:17:50Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'f563af00-9bda-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T11:33:44.048Z', 'statusTimestamp': '2023-01-24T11:45:59.944Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '17af99e0-9b70-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:48:45.438Z', 'statusTimestamp': '2023-01-24T11:07:08.277Z', 'status': 'open', 'contacts': 5, 'adversaries': ['noment.com'], 'adversaryId': 'noment.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 3, '2148': 1, '4232': 1}, 'totalEndpoints': 4, 'lastContact': '2023-01-24T20:27:25.049Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:48:27.684Z'},<br/>{'id': 'a5cc17b0-9b6d-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:31:15.371Z', 'statusTimestamp': '2023-01-23T22:31:15.371Z', 'status': 'open', 'contacts': 3, 'adversaries': ['fierdetreroutier.com'], 'adversaryId': 'fierdetreroutier.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1, '3182': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-24T20:31:29.489Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:30:58.327Z'},<br/>{'id': '520cd7a0-9b6c-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:21:45.370Z', 'statusTimestamp': '2023-01-23T22:21:45.370Z', 'status': 'open', 'contacts': 3, 'adversaries': ['aright.de'], 'adversaryId': 'aright.de', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1, '805': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-24T20:36:26.204Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:21:31.807Z'},<br/>{'id': '3c9a45b0-9b6c-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:21:09.387Z', 'statusTimestamp': '2023-01-23T22:21:09.387Z', 'status': 'open', 'contacts': 3, 'adversaries': ['maximals.ru'], 'adversaryId': 'maximals.ru', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1, '805': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-24T20:50:41.786Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:20:54.300Z'},<br/>{'id': '158c5e00-9b6b-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:12:54.368Z', 'statusTimestamp': '2023-01-23T22:12:54.368Z', 'status': 'open', 'contacts': 2, 'adversaries': ['lessgeneric.com'], 'adversaryId': 'lessgeneric.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T22:12:38.980Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:12:38.980Z'},<br/>{'id': 'ea14b390-9b69-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:04:31.945Z', 'statusTimestamp': '2023-01-23T22:04:31.945Z', 'status': 'open', 'contacts': 2, 'adversaries': ['exoticahousing.in'], 'adversaryId': 'exoticahousing.in', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T22:03:27.310Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:03:27.310Z'},<br/>{'id': 'a1f426f0-9b68-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T21:55:21.439Z', 'statusTimestamp': '2023-01-23T21:55:21.439Z', 'status': 'open', 'contacts': 2, 'adversaries': ['andam.vn'], 'adversaryId': 'andam.vn', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T21:55:06.459Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T21:55:06.459Z'},<br/>{'id': '8e4df090-9b68-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T21:54:48.473Z', 'statusTimestamp': '2023-01-23T21:54:48.473Z', 'status': 'open', 'contacts': 2, 'adversaries': ['ahmedabadcallgirl.biz'], 'adversaryId': 'ahmedabadcallgirl.biz', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T21:54:30.694Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T21:54:30.694Z'},<br/>{'id': '01989620-9b66-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T21:36:33.410Z', 'statusTimestamp': '2023-01-23T21:36:33.410Z', 'status': 'open', 'contacts': 2, 'adversaries': ['miner.nablabee.com'], 'adversaryId': 'miner.nablabee.com', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T21:36:19.439Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T21:36:19.439Z'},<br/>{'id': '15dfb250-9b64-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T21:22:48.437Z', 'statusTimestamp': '2023-01-23T21:22:48.437Z', 'status': 'open', 'contacts': 2, 'adversaries': ['skyplanners.com'], 'adversaryId': 'skyplanners.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T21:22:35.646Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T21:22:35.646Z'},<br/>{'id': '2bc88020-9b2c-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T14:42:33.378Z', 'statusTimestamp': '2023-01-24T11:33:24.832Z', 'status': 'closed', 'contacts': 10, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 10}, 'totalEndpoints': 5, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '9b430be0-9b1e-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T13:05:27.454Z', 'statusTimestamp': '2023-01-23T14:24:09.462Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '249b6b90-9b14-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T11:50:33.417Z', 'statusTimestamp': '2023-01-23T12:57:59.609Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'cae5a990-99e6-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T23:53:24.393Z', 'statusTimestamp': '2023-01-21T23:58:48.655Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '7db7c400-99e1-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T23:15:27.424Z', 'statusTimestamp': '2023-01-21T23:51:47.406Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '72067f80-99cc-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T20:44:48.376Z', 'statusTimestamp': '2023-01-21T23:13:41.679Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 2, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'eaba8420-9932-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T02:25:48.386Z', 'statusTimestamp': '2023-01-21T02:27:53.605Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'bb540360-991d-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T23:54:09.430Z', 'statusTimestamp': '2023-01-20T23:54:09.430Z', 'status': 'open', 'contacts': 1, 'adversaries': ['mykooperativ.ru'], 'adversaryId': 'mykooperativ.ru', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-20T23:53:47.814Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-20T23:53:47.814Z'},<br/>{'id': '0f055c60-9901-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T20:28:54.438Z', 'statusTimestamp': '2023-01-21T02:24:55.326Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '95e1ae70-98c8-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T13:44:39.383Z', 'statusTimestamp': '2023-01-20T13:44:39.383Z', 'status': 'open', 'contacts': 3, 'adversaries': ['galias.com.co'], 'adversaryId': 'galias.com.co', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'147': 1, '1179': 1, '4232': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-24T20:45:31.774Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-20T13:44:26.511Z'},<br/>{'id': '06883d70-98c3-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T13:04:51.399Z', 'statusTimestamp': '2023-01-20T13:04:51.399Z', 'status': 'open', 'contacts': 1, 'adversaries': ['museosantiagocarbonell.com'], 'adversaryId': 'museosantiagocarbonell.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Ml.B.Wacatac.Script', 'labelDistribution': {'1580': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T17:11:29.971Z', 'unread': False, 'hasPlaybackContacts': True, 'firstContact': '2023-01-13T17:11:29.971Z'} | page: 1<br/>items: 50 | 2023-01-26T23:17:13.444Z |


#### Command example
```!lumu-retrieve-incidents page=2 status=open adversary-types=Malware labels=1580```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveIncidents": {
            "items": [],
            "paginationInfo": {
                "items": 50,
                "page": 2,
                "prev": 1
            },
            "timestamp": "2023-01-26T23:17:15.773Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|timestamp|
>|---|---|---|
>|  | page: 2<br/>items: 50<br/>prev: 1 | 2023-01-26T23:17:15.773Z |


### lumu-retrieve-a-specific-incident-details
***
Get details of a specific Incident.

| `{incident-uuid}` | uuid of the specific incident |
|---|---|


#### Base Command

`lumu-retrieve-a-specific-incident-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveASpecificIncidentDetails.id | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.timestamp | Date |  | 
| Lumu.RetrieveASpecificIncidentDetails.isUnread | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.contacts | Number |  | 
| Lumu.RetrieveASpecificIncidentDetails.adversaryId | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.adversaries | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.adversaryTypes | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.description | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.labelDistribution.144 | Number |  | 
| Lumu.RetrieveASpecificIncidentDetails.totalEndpoints | Number |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContact | Date |  | 
| Lumu.RetrieveASpecificIncidentDetails.actions.datetime | Date |  | 
| Lumu.RetrieveASpecificIncidentDetails.actions.userId | Number |  | 
| Lumu.RetrieveASpecificIncidentDetails.actions.action | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.actions.comment | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.status | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.statusTimestamp | Date |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.uuid | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.datetime | Date |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.host | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.types | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.details | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.endpointIp | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.endpointName | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.label | Number |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceType | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceId | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.question.type | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.question.name | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.question.class | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.responseCode | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.authoritative | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_available | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.truncated_response | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.checking_disabled | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_desired | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.authentic_data | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.name | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.type | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.class | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.ttl | Number |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.data | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.opCode | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.isPlayback | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.uuid | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.datetime | Date |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.host | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.types | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.details | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.endpointIp | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.endpointName | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.label | Number |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceType | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceId | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.question.type | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.question.name | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.question.class | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.responseCode | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.authoritative | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_available | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.truncated_response | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.checking_disabled | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_desired | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.authentic_data | Boolean |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.name | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.type | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.class | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.ttl | Number |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.data | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.opCode | String |  | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.isPlayback | Boolean |  | 

#### Command example
```!lumu-retrieve-a-specific-incident-details lumu_incident_id=d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveASpecificIncidentDetails": {
            "actions": [
                {
                    "action": "comment",
                    "comment": "from XSOAR Cortex 20230126_230039 from cortex, palo alto, hmacsha256:8bdedafcfd650db214d9ea052aa0d98e3ce6414157fba9019df9462d1c812922",
                    "datetime": "2023-01-26T23:02:06.706Z",
                    "userId": 0
                },
                {
                    "action": "mute",
                    "comment": "from XSOAR Cortex 20230126_230035 mute from cortex, hmacsha256:61aba842f1db9ed0c23adbcd05f7d019d4c2f525aedf6d5d34e1a5f11489f8dc",
                    "datetime": "2023-01-26T23:00:36.915Z",
                    "userId": 0
                },
                {
                    "action": "read",
                    "comment": "",
                    "datetime": "2023-01-26T22:58:14.963Z",
                    "userId": 6252
                }
            ],
            "adversaries": [
                "activity.lumu.io"
            ],
            "adversaryId": "activity.lumu.io",
            "adversaryTypes": [
                "Spam"
            ],
            "contacts": 1,
            "description": "Activity Test Query",
            "firstContactDetails": {
                "datetime": "2022-12-20T14:37:02.228Z",
                "details": [
                    "Activity Test Query"
                ],
                "endpointIp": "192.168.0.13",
                "endpointName": "Loacal-nesfpdm",
                "host": "activity.lumu.io",
                "isPlayback": false,
                "label": 0,
                "sourceData": {
                    "DNSQueryExtraInfo": {
                        "queryType": "A"
                    }
                },
                "sourceId": "6d942a7a-d287-415e-9c09-3d6632a6a976",
                "sourceType": "custom_collector",
                "types": [
                    "Spam"
                ],
                "uuid": "c45b8540-8073-11ed-b720-73e7235736ec"
            },
            "hasPlaybackContacts": false,
            "id": "d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343",
            "isUnread": false,
            "labelDistribution": {
                "0": 1
            },
            "lastContact": "2022-12-20T14:37:02.228Z",
            "lastContactDetails": {
                "datetime": "2022-12-20T14:37:02.228Z",
                "details": [
                    "Activity Test Query"
                ],
                "endpointIp": "192.168.0.13",
                "endpointName": "Loacal-nesfpdm",
                "host": "activity.lumu.io",
                "isPlayback": false,
                "label": 0,
                "sourceData": {
                    "DNSQueryExtraInfo": {
                        "queryType": "A"
                    }
                },
                "sourceId": "6d942a7a-d287-415e-9c09-3d6632a6a976",
                "sourceType": "custom_collector",
                "types": [
                    "Spam"
                ],
                "uuid": "c45b8540-8073-11ed-b720-73e7235736ec"
            },
            "status": "muted",
            "statusTimestamp": "2023-01-26T23:00:36.915Z",
            "timestamp": "2023-01-26T22:57:47.029Z",
            "totalEndpoints": 1
        }
    }
}
```

#### Human Readable Output

>### Results
>|actions|adversaries|adversaryId|adversaryTypes|contacts|description|firstContactDetails|hasPlaybackContacts|id|isUnread|labelDistribution|lastContact|lastContactDetails|status|statusTimestamp|timestamp|totalEndpoints|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'datetime': '2023-01-26T23:02:06.706Z', 'userId': 0, 'action': 'comment', 'comment': 'from XSOAR Cortex 20230126_230039 from cortex, palo alto, hmacsha256:8bdedafcfd650db214d9ea052aa0d98e3ce6414157fba9019df9462d1c812922'},<br/>{'datetime': '2023-01-26T23:00:36.915Z', 'userId': 0, 'action': 'mute', 'comment': 'from XSOAR Cortex 20230126_230035 mute from cortex, hmacsha256:61aba842f1db9ed0c23adbcd05f7d019d4c2f525aedf6d5d34e1a5f11489f8dc'},<br/>{'datetime': '2023-01-26T22:58:14.963Z', 'userId': 6252, 'action': 'read', 'comment': ''} | activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | uuid: c45b8540-8073-11ed-b720-73e7235736ec<br/>datetime: 2022-12-20T14:37:02.228Z<br/>host: activity.lumu.io<br/>types: Spam<br/>details: Activity Test Query<br/>endpointIp: 192.168.0.13<br/>endpointName: Loacal-nesfpdm<br/>label: 0<br/>sourceType: custom_collector<br/>sourceId: 6d942a7a-d287-415e-9c09-3d6632a6a976<br/>sourceData: {"DNSQueryExtraInfo": {"queryType": "A"}}<br/>isPlayback: false | false | d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343 | false | 0: 1 | 2022-12-20T14:37:02.228Z | uuid: c45b8540-8073-11ed-b720-73e7235736ec<br/>datetime: 2022-12-20T14:37:02.228Z<br/>host: activity.lumu.io<br/>types: Spam<br/>details: Activity Test Query<br/>endpointIp: 192.168.0.13<br/>endpointName: Loacal-nesfpdm<br/>label: 0<br/>sourceType: custom_collector<br/>sourceId: 6d942a7a-d287-415e-9c09-3d6632a6a976<br/>sourceData: {"DNSQueryExtraInfo": {"queryType": "A"}}<br/>isPlayback: false | muted | 2023-01-26T23:00:36.915Z | 2023-01-26T22:57:47.029Z | 1 |


### lumu-retrieve-a-specific-incident-context
***
Get details of a specific Incident.

| `{incident-uuid}` | uuid of the specific incident |
|---|---|


#### Base Command

`lumu-retrieve-a-specific-incident-context`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | . | Optional | 
| hash | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveASpecificIncidentContext.adversary_id | String |  | 
| Lumu.RetrieveASpecificIncidentContext.currently_active | Boolean |  | 
| Lumu.RetrieveASpecificIncidentContext.deactivated_on | Date |  | 
| Lumu.RetrieveASpecificIncidentContext.mitre.details.tactic | String |  | 
| Lumu.RetrieveASpecificIncidentContext.mitre.details.techniques | String |  | 
| Lumu.RetrieveASpecificIncidentContext.mitre.matrix | String |  | 
| Lumu.RetrieveASpecificIncidentContext.mitre.version | String |  | 
| Lumu.RetrieveASpecificIncidentContext.related_files | String |  | 
| Lumu.RetrieveASpecificIncidentContext.threat_details | String |  | 
| Lumu.RetrieveASpecificIncidentContext.threat_triggers | String |  | 
| Lumu.RetrieveASpecificIncidentContext.playbooks | String |  | 
| Lumu.RetrieveASpecificIncidentContext.external_resources | String |  | 
| Lumu.RetrieveASpecificIncidentContext.timestamp | Date |  | 

#### Command example
```!lumu-retrieve-a-specific-incident-context lumu_incident_id=6eddaf40-938c-11ed-b0f8-a7e340234a4e hash=SHA256```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveASpecificIncidentContext": {
            "adversary_id": "jits.ac.in",
            "currently_active": true,
            "external_resources": [
                "https://elis531989.medium.com/funtastic-packers-and-where-to-find-them-41429a7ef9a7",
                "https://research.checkpoint.com/2020/exploring-qbots-latest-attack-methods/",
                "https://malwareandstuff.com/an-old-enemy-diving-into-qbot-part-1/",
                "https://raw.githubusercontent.com/fboldewin/When-ransomware-hits-an-ATM-giant---The-Diebold-Nixdorf-case-dissected/main/When%20ransomware%20hits%20an%20ATM%20giant%20-%20The%20Diebold%20Nixdorf%20case%20dissected%20-%20Group-IB%20CyberCrimeCon2020.pdf",
                "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot",
                "https://unit42.paloaltonetworks.com/wireshark-tutorial-emotet-infection/",
                "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2020-CTI-010.pdf",
                "https://media.scmagazine.com/documents/225/bae_qbot_report_56053.pdf",
                "https://malwareandstuff.com/an-old-enemy-diving-into-qbot-part-3/",
                "https://urlhaus.abuse.ch/host/jits.ac.in/",
                "https://www.hornetsecurity.com/en/security-information/qakbot-malspam-leading-to-prolock/",
                "https://twitter.com/redcanary/status/1334224861628039169",
                "https://blog.morphisec.com/qakbot-qbot-maldoc-two-new-techniques",
                "https://www.vkremez.com/2018/07/lets-learn-in-depth-reversing-of-qakbot.html",
                "https://web.archive.org/web/20201207094648/https://go.group-ib.com/rs/689-LRE-818/images/Group-IB_Egregor_Ransomware.pdf",
                "https://blog.quosec.net/posts/grap_qakbot_navigation/",
                "https://www.virustotal.com/gui/domain/jits.ac.in/relations"
            ],
            "mitre": {
                "details": [
                    {
                        "tactic": "command-and-control",
                        "techniques": [
                            "T1071"
                        ]
                    }
                ],
                "matrix": "enterprise",
                "version": "8.2"
            },
            "playbooks": [
                "https://docs.lumu.io/portal/en/kb/articles/malware-incident-response-playbook"
            ],
            "threat_details": [
                "Akbot",
                "gayfgt",
                "Bashlite",
                "lizkebab",
                "Qbot ",
                "Quakbot",
                "qbot",
                "PinkSlipBot",
                "Qbot",
                "Qakbot",
                "torlus",
                "Pinkslipbot",
                "Gafgyt"
            ],
            "threat_triggers": [
                "https://jits.ac.in/TS.php"
            ],
            "timestamp": "2023-01-26T23:17:20.852Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adversary_id|currently_active|external_resources|mitre|playbooks|threat_details|threat_triggers|timestamp|
>|---|---|---|---|---|---|---|---|
>| jits.ac.in | true | https:<span>//</span>elis531989.medium.com/funtastic-packers-and-where-to-find-them-41429a7ef9a7,<br/>https:<span>//</span>research.checkpoint.com/2020/exploring-qbots-latest-attack-methods/,<br/>https:<span>//</span>malwareandstuff.com/an-old-enemy-diving-into-qbot-part-1/,<br/>https:<span>//</span>raw.githubusercontent.com/fboldewin/When-ransomware-hits-an-ATM-giant---The-Diebold-Nixdorf-case-dissected/main/When%20ransomware%20hits%20an%20ATM%20giant%20-%20The%20Diebold%20Nixdorf%20case%20dissected%20-%20Group-IB%20CyberCrimeCon2020.pdf,<br/>https:<span>//</span>malpedia.caad.fkie.fraunhofer.de/details/win.qakbot,<br/>https:<span>//</span>unit42.paloaltonetworks.com/wireshark-tutorial-emotet-infection/,<br/>https:<span>//</span>www.cert.ssi.gouv.fr/uploads/CERTFR-2020-CTI-010.pdf,<br/>https:<span>//</span>media.scmagazine.com/documents/225/bae_qbot_report_56053.pdf,<br/>https:<span>//</span>malwareandstuff.com/an-old-enemy-diving-into-qbot-part-3/,<br/>https:<span>//</span>urlhaus.abuse.ch/host/jits.ac.in/,<br/>https:<span>//</span>www.hornetsecurity.com/en/security-information/qakbot-malspam-leading-to-prolock/,<br/>https:<span>//</span>twitter.com/redcanary/status/1334224861628039169,<br/>https:<span>//</span>blog.morphisec.com/qakbot-qbot-maldoc-two-new-techniques,<br/>https:<span>//</span>www.vkremez.com/2018/07/lets-learn-in-depth-reversing-of-qakbot.html,<br/>https:<span>//</span>web.archive.org/web/20201207094648/https:<span>//</span>go.group-ib.com/rs/689-LRE-818/images/Group-IB_Egregor_Ransomware.pdf,<br/>https:<span>//</span>blog.quosec.net/posts/grap_qakbot_navigation/,<br/>https:<span>//</span>www.virustotal.com/gui/domain/jits.ac.in/relations | details: {'tactic': 'command-and-control', 'techniques': ['T1071']}<br/>matrix: enterprise<br/>version: 8.2 | https:<span>//</span>docs.lumu.io/portal/en/kb/articles/malware-incident-response-playbook | Akbot,<br/>gayfgt,<br/>Bashlite,<br/>lizkebab,<br/>Qbot ,<br/>Quakbot,<br/>qbot,<br/>PinkSlipBot,<br/>Qbot,<br/>Qakbot,<br/>torlus,<br/>Pinkslipbot,<br/>Gafgyt | https:<span>//</span>jits.ac.in/TS.php | 2023-01-26T23:17:20.852Z |


### lumu-comment-a-specific-incident
***
Get a paginated list of open incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-comment-a-specific-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | . | Optional | 
| comment | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.CommentASpecificIncident.statusCode | number |  | 

#### Command example
```!lumu-comment-a-specific-incident comment="from cortex, palo alto" lumu_incident_id=d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343```
#### Context Example
```json
{
    "Lumu": {
        "CommentASpecificIncident": {
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>### Results
>|statusCode|
>|---|
>| 200 |


### lumu-retrieve-open-incidents
***
Get a paginated list of open incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-open-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | . | Optional | 
| items | . | Optional | 
| adversary-types | . | Optional | 
| labels | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveOpenIncidents.items.id | String |  | 
| Lumu.RetrieveOpenIncidents.items.timestamp | Date |  | 
| Lumu.RetrieveOpenIncidents.items.statusTimestamp | Date |  | 
| Lumu.RetrieveOpenIncidents.items.status | String |  | 
| Lumu.RetrieveOpenIncidents.items.contacts | Number |  | 
| Lumu.RetrieveOpenIncidents.items.adversaries | String |  | 
| Lumu.RetrieveOpenIncidents.items.adversaryId | String |  | 
| Lumu.RetrieveOpenIncidents.items.adversaryTypes | String |  | 
| Lumu.RetrieveOpenIncidents.items.description | String |  | 
| Lumu.RetrieveOpenIncidents.items.labelDistribution.37 | Number |  | 
| Lumu.RetrieveOpenIncidents.items.labelDistribution.39 | Number |  | 
| Lumu.RetrieveOpenIncidents.items.labelDistribution.179 | Number |  | 
| Lumu.RetrieveOpenIncidents.items.totalEndpoints | Number |  | 
| Lumu.RetrieveOpenIncidents.items.lastContact | Date |  | 
| Lumu.RetrieveOpenIncidents.items.unread | Boolean |  | 
| Lumu.RetrieveOpenIncidents.paginationInfo.page | Number |  | 
| Lumu.RetrieveOpenIncidents.paginationInfo.items | Number |  | 

#### Command example
```!lumu-retrieve-open-incidents```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveOpenIncidents": {
            "items": [
                {
                    "adversaries": [
                        "www.sparechange.io"
                    ],
                    "adversaryId": "www.sparechange.io",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-24T14:08:59.469Z",
                    "hasPlaybackContacts": false,
                    "id": "acc03f50-9bf0-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "2254": 3
                    },
                    "lastContact": "2023-01-24T14:23:20.504Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-24T14:09:11.109Z",
                    "timestamp": "2023-01-24T14:09:11.109Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "bonbongame.com"
                    ],
                    "adversaryId": "bonbongame.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-24T12:08:37.234Z",
                    "hasPlaybackContacts": false,
                    "id": "de703020-9bdf-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "2254": 2
                    },
                    "lastContact": "2023-01-24T12:08:37.234Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-24T12:08:53.026Z",
                    "timestamp": "2023-01-24T12:08:53.026Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "noment.com"
                    ],
                    "adversaryId": "noment.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 5,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:48:27.684Z",
                    "hasPlaybackContacts": false,
                    "id": "17af99e0-9b70-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 3,
                        "4232": 1
                    },
                    "lastContact": "2023-01-24T20:27:25.049Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-24T11:07:08.277Z",
                    "timestamp": "2023-01-23T22:48:45.438Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "fierdetreroutier.com"
                    ],
                    "adversaryId": "fierdetreroutier.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:30:58.327Z",
                    "hasPlaybackContacts": false,
                    "id": "a5cc17b0-9b6d-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1,
                        "3182": 1
                    },
                    "lastContact": "2023-01-24T20:31:29.489Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:31:15.371Z",
                    "timestamp": "2023-01-23T22:31:15.371Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "aright.de"
                    ],
                    "adversaryId": "aright.de",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:21:31.807Z",
                    "hasPlaybackContacts": false,
                    "id": "520cd7a0-9b6c-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1,
                        "805": 1
                    },
                    "lastContact": "2023-01-24T20:36:26.204Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:21:45.370Z",
                    "timestamp": "2023-01-23T22:21:45.370Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "maximals.ru"
                    ],
                    "adversaryId": "maximals.ru",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:20:54.300Z",
                    "hasPlaybackContacts": false,
                    "id": "3c9a45b0-9b6c-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1,
                        "805": 1
                    },
                    "lastContact": "2023-01-24T20:50:41.786Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:21:09.387Z",
                    "timestamp": "2023-01-23T22:21:09.387Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "lessgeneric.com"
                    ],
                    "adversaryId": "lessgeneric.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:12:38.980Z",
                    "hasPlaybackContacts": false,
                    "id": "158c5e00-9b6b-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T22:12:38.980Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:12:54.368Z",
                    "timestamp": "2023-01-23T22:12:54.368Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "exoticahousing.in"
                    ],
                    "adversaryId": "exoticahousing.in",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T22:03:27.310Z",
                    "hasPlaybackContacts": false,
                    "id": "ea14b390-9b69-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T22:03:27.310Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T22:04:31.945Z",
                    "timestamp": "2023-01-23T22:04:31.945Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "andam.vn"
                    ],
                    "adversaryId": "andam.vn",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T21:55:06.459Z",
                    "hasPlaybackContacts": false,
                    "id": "a1f426f0-9b68-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T21:55:06.459Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T21:55:21.439Z",
                    "timestamp": "2023-01-23T21:55:21.439Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "ahmedabadcallgirl.biz"
                    ],
                    "adversaryId": "ahmedabadcallgirl.biz",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T21:54:30.694Z",
                    "hasPlaybackContacts": false,
                    "id": "8e4df090-9b68-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T21:54:30.694Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T21:54:48.473Z",
                    "timestamp": "2023-01-23T21:54:48.473Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "miner.nablabee.com"
                    ],
                    "adversaryId": "miner.nablabee.com",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-23T21:36:19.439Z",
                    "hasPlaybackContacts": false,
                    "id": "01989620-9b66-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T21:36:19.439Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T21:36:33.410Z",
                    "timestamp": "2023-01-23T21:36:33.410Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "skyplanners.com"
                    ],
                    "adversaryId": "skyplanners.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-23T21:22:35.646Z",
                    "hasPlaybackContacts": false,
                    "id": "15dfb250-9b64-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 1
                    },
                    "lastContact": "2023-01-23T21:22:35.646Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-23T21:22:48.437Z",
                    "timestamp": "2023-01-23T21:22:48.437Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "mykooperativ.ru"
                    ],
                    "adversaryId": "mykooperativ.ru",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-20T23:53:47.814Z",
                    "hasPlaybackContacts": false,
                    "id": "bb540360-991d-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "2254": 1
                    },
                    "lastContact": "2023-01-20T23:53:47.814Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-20T23:54:09.430Z",
                    "timestamp": "2023-01-20T23:54:09.430Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "galias.com.co"
                    ],
                    "adversaryId": "galias.com.co",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 3,
                    "description": "Phishing domain",
                    "firstContact": "2023-01-20T13:44:26.511Z",
                    "hasPlaybackContacts": false,
                    "id": "95e1ae70-98c8-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "1179": 1,
                        "147": 1,
                        "4232": 1
                    },
                    "lastContact": "2023-01-24T20:45:31.774Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-20T13:44:39.383Z",
                    "timestamp": "2023-01-20T13:44:39.383Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "museosantiagocarbonell.com"
                    ],
                    "adversaryId": "museosantiagocarbonell.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Ml.B.Wacatac.Script",
                    "firstContact": "2023-01-13T17:11:29.971Z",
                    "hasPlaybackContacts": true,
                    "id": "06883d70-98c3-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "1580": 1
                    },
                    "lastContact": "2023-01-13T17:11:29.971Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-20T13:04:51.399Z",
                    "timestamp": "2023-01-20T13:04:51.399Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.midwestgrip.com"
                    ],
                    "adversaryId": "www.midwestgrip.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 6,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-19T00:52:58.373Z",
                    "hasPlaybackContacts": false,
                    "id": "a6cad210-9793-11ed-b6d7-3f0c59c638d9",
                    "labelDistribution": {
                        "2148": 2,
                        "2254": 2,
                        "3182": 2
                    },
                    "lastContact": "2023-01-19T21:11:40.694Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-19T00:53:13.265Z",
                    "timestamp": "2023-01-19T00:53:13.265Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "timekidspreschools.in"
                    ],
                    "adversaryId": "timekidspreschools.in",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 11,
                    "description": "Phishing domain",
                    "firstContact": "2023-01-13T19:15:51.535Z",
                    "hasPlaybackContacts": true,
                    "id": "f8c42af0-953e-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 3,
                        "3182": 2,
                        "4055": 1,
                        "548": 2,
                        "989": 3
                    },
                    "lastContact": "2023-01-19T21:42:51.930Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-18T23:30:31.814Z",
                    "timestamp": "2023-01-16T01:42:01.247Z",
                    "totalEndpoints": 6,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.adrelatemedia.com"
                    ],
                    "adversaryId": "www.adrelatemedia.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 6,
                    "description": "Malware family Trojan.Jqrow.Ursnifdropper.Ad.Tr",
                    "firstContact": "2023-01-18T17:36:54.035Z",
                    "hasPlaybackContacts": false,
                    "id": "baba3320-9756-11ed-b6d7-3f0c59c638d9",
                    "labelDistribution": {
                        "2144": 2,
                        "548": 4
                    },
                    "lastContact": "2023-01-18T22:12:27.349Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-18T17:37:07.410Z",
                    "timestamp": "2023-01-18T17:37:07.410Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "freebitcoinx.com"
                    ],
                    "adversaryId": "freebitcoinx.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 7,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-18T16:57:42.465Z",
                    "hasPlaybackContacts": false,
                    "id": "437d1750-9751-11ed-b6d7-3f0c59c638d9",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 2,
                        "3182": 2,
                        "548": 2
                    },
                    "lastContact": "2023-01-19T22:08:24.488Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-18T16:57:59.877Z",
                    "timestamp": "2023-01-18T16:57:59.877Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "hurricanepub.com"
                    ],
                    "adversaryId": "hurricanepub.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 616,
                    "description": "Malware family UNC4034",
                    "firstContact": "2023-01-18T14:43:54.875Z",
                    "hasPlaybackContacts": false,
                    "id": "90a28550-973e-11ed-b6d7-3f0c59c638d9",
                    "labelDistribution": {
                        "2144": 608,
                        "4055": 4,
                        "548": 4
                    },
                    "lastContact": "2023-01-18T17:48:20.615Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-18T14:44:08.869Z",
                    "timestamp": "2023-01-18T14:44:08.869Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.megapress.click"
                    ],
                    "adversaryId": "www.megapress.click",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 16,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-17T00:56:24.152Z",
                    "hasPlaybackContacts": false,
                    "id": "cf267090-9601-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "0": 1,
                        "1179": 2,
                        "2144": 4,
                        "2148": 2,
                        "2254": 1,
                        "4061": 4,
                        "989": 2
                    },
                    "lastContact": "2023-01-18T16:54:33.124Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-17T00:56:43.289Z",
                    "timestamp": "2023-01-17T00:56:43.289Z",
                    "totalEndpoints": 7,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.app4vn.com"
                    ],
                    "adversaryId": "www.app4vn.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 5,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-17T00:56:23.618Z",
                    "hasPlaybackContacts": false,
                    "id": "cb8b4870-9601-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "2148": 2,
                        "2254": 1,
                        "4061": 2
                    },
                    "lastContact": "2023-01-17T14:39:37.770Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-17T00:56:37.239Z",
                    "timestamp": "2023-01-17T00:56:37.239Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "campusdematematicas.com"
                    ],
                    "adversaryId": "campusdematematicas.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-13T19:08:02.207Z",
                    "hasPlaybackContacts": true,
                    "id": "b7e2a110-9601-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 2
                    },
                    "lastContact": "2023-01-13T19:08:02.207Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-17T00:56:04.257Z",
                    "timestamp": "2023-01-17T00:56:04.257Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "talebooks.com"
                    ],
                    "adversaryId": "talebooks.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 5,
                    "description": "CryptoMining domain",
                    "firstContact": "2023-01-16T13:52:05.057Z",
                    "hasPlaybackContacts": false,
                    "id": "fe57b750-95a4-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "2254": 1,
                        "4061": 3,
                        "548": 1
                    },
                    "lastContact": "2023-01-17T14:41:11.876Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-16T13:52:19.269Z",
                    "timestamp": "2023-01-16T13:52:19.269Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "jits.ac.in"
                    ],
                    "adversaryId": "jits.ac.in",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "QakBot",
                    "firstContact": "2023-01-13T21:51:12.190Z",
                    "hasPlaybackContacts": false,
                    "id": "6eddaf40-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "548": 3
                    },
                    "lastContact": "2023-01-18T16:51:20.270Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-16T12:13:23.292Z",
                    "timestamp": "2023-01-13T21:51:28.308Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "waste4think.eu"
                    ],
                    "adversaryId": "waste4think.eu",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 10,
                    "description": "Phishing domain",
                    "firstContact": "2023-01-13T16:58:06.814Z",
                    "hasPlaybackContacts": true,
                    "id": "a0664d30-94d4-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "4055": 6,
                        "548": 4
                    },
                    "lastContact": "2023-01-18T21:22:09.643Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-15T13:00:46.339Z",
                    "timestamp": "2023-01-15T13:00:46.339Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "msgos.com"
                    ],
                    "adversaryId": "msgos.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:51:10.312Z",
                    "hasPlaybackContacts": false,
                    "id": "6edc4fb0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4055": 1
                    },
                    "lastContact": "2023-01-17T14:56:08.635Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:51:28.299Z",
                    "timestamp": "2023-01-13T21:51:28.299Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "netwonder.net"
                    ],
                    "adversaryId": "netwonder.net",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 8,
                    "description": "Malware family Nivdort",
                    "firstContact": "2023-01-13T21:50:53.247Z",
                    "hasPlaybackContacts": false,
                    "id": "642934c0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 2,
                        "2144": 6
                    },
                    "lastContact": "2023-01-18T16:43:54.810Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:51:10.348Z",
                    "timestamp": "2023-01-13T21:51:10.348Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "subwaybookreview.com"
                    ],
                    "adversaryId": "subwaybookreview.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Exploit.Msoffice.Generic",
                    "firstContact": "2023-01-13T21:50:38.599Z",
                    "hasPlaybackContacts": false,
                    "id": "59641870-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:50:38.599Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:50:52.279Z",
                    "timestamp": "2023-01-13T21:50:52.279Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "michaeleaston.com"
                    ],
                    "adversaryId": "michaeleaston.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family Trojan.Agent.Bg.Script",
                    "firstContact": "2023-01-13T21:49:50.220Z",
                    "hasPlaybackContacts": false,
                    "id": "405525e0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "989": 1
                    },
                    "lastContact": "2023-01-18T16:52:09Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:50:10.238Z",
                    "timestamp": "2023-01-13T21:50:10.238Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "cane.pw"
                    ],
                    "adversaryId": "cane.pw",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:49:28.515Z",
                    "hasPlaybackContacts": false,
                    "id": "304360e0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:49:28.515Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:49:43.278Z",
                    "timestamp": "2023-01-13T21:49:43.278Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "cek.pm"
                    ],
                    "adversaryId": "cek.pm",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:47:46.473Z",
                    "hasPlaybackContacts": false,
                    "id": "f1a7da00-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:47:46.473Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:47:58.240Z",
                    "timestamp": "2023-01-13T21:47:58.240Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "anothercity.ru"
                    ],
                    "adversaryId": "anothercity.ru",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Backdoor.Peg.Php.Generic",
                    "firstContact": "2023-01-13T21:46:26.925Z",
                    "hasPlaybackContacts": false,
                    "id": "c329ff00-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:46:26.925Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:46:40.240Z",
                    "timestamp": "2023-01-13T21:46:40.240Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "tormail.org"
                    ],
                    "adversaryId": "tormail.org",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:46:15.650Z",
                    "hasPlaybackContacts": false,
                    "id": "bc0a4400-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 2
                    },
                    "lastContact": "2023-01-18T18:02:09.546Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:46:28.288Z",
                    "timestamp": "2023-01-13T21:46:28.288Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "businessbackend.com"
                    ],
                    "adversaryId": "businessbackend.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:46:06.886Z",
                    "hasPlaybackContacts": false,
                    "id": "ba390670-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:46:06.886Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:46:25.239Z",
                    "timestamp": "2023-01-13T21:46:25.239Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "asdasd.ru"
                    ],
                    "adversaryId": "asdasd.ru",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:29.477Z",
                    "hasPlaybackContacts": false,
                    "id": "59b2ca20-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:43:29.477Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:43.298Z",
                    "timestamp": "2023-01-13T21:43:43.298Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "hotprice.co"
                    ],
                    "adversaryId": "hotprice.co",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:18.543Z",
                    "hasPlaybackContacts": false,
                    "id": "54504f80-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 2
                    },
                    "lastContact": "2023-01-18T18:17:08.744Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:34.264Z",
                    "timestamp": "2023-01-13T21:43:34.264Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "theshallowtalesreview.com.ng"
                    ],
                    "adversaryId": "theshallowtalesreview.com.ng",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Quakbot",
                    "firstContact": "2023-01-13T21:43:17.535Z",
                    "hasPlaybackContacts": false,
                    "id": "544ca600-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:43:17.535Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:34.240Z",
                    "timestamp": "2023-01-13T21:43:34.240Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "disposable.ml"
                    ],
                    "adversaryId": "disposable.ml",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:13.301Z",
                    "hasPlaybackContacts": false,
                    "id": "50b8f7f0-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:43:13.301Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:28.239Z",
                    "timestamp": "2023-01-13T21:43:28.239Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "founddll.com"
                    ],
                    "adversaryId": "founddll.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family Win32.Diplugem.Browsermodifier",
                    "firstContact": "2023-01-13T21:41:49.494Z",
                    "hasPlaybackContacts": false,
                    "id": "1eb37cd0-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4
                    },
                    "lastContact": "2023-01-13T21:41:49.590Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:42:04.317Z",
                    "timestamp": "2023-01-13T21:42:04.317Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "learnwithportals.com"
                    ],
                    "adversaryId": "learnwithportals.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-13T21:41:48.847Z",
                    "hasPlaybackContacts": false,
                    "id": "1eb0bdb0-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 2
                    },
                    "lastContact": "2023-01-13T21:41:48.945Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:42:04.299Z",
                    "timestamp": "2023-01-13T21:42:04.299Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "realestateexpert.us"
                    ],
                    "adversaryId": "realestateexpert.us",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "QakBot",
                    "firstContact": "2023-01-13T21:41:30.187Z",
                    "hasPlaybackContacts": false,
                    "id": "13ecd9e0-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "2974": 1
                    },
                    "lastContact": "2023-01-13T21:41:30.187Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:41:46.238Z",
                    "timestamp": "2023-01-13T21:41:46.238Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "kloap.com"
                    ],
                    "adversaryId": "kloap.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:40:54.134Z",
                    "hasPlaybackContacts": false,
                    "id": "fcae3a80-938a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 6
                    },
                    "lastContact": "2023-01-18T18:01:53.928Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:41:07.240Z",
                    "timestamp": "2023-01-13T21:41:07.240Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "disconight.com.ar"
                    ],
                    "adversaryId": "disconight.com.ar",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 9,
                    "description": "Phishing domain",
                    "firstContact": "2023-01-13T21:39:29.886Z",
                    "hasPlaybackContacts": false,
                    "id": "cc6cb680-938a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 8
                    },
                    "lastContact": "2023-01-18T20:41:33.286Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:39:46.280Z",
                    "timestamp": "2023-01-13T21:39:46.280Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "adrelatemedia.com"
                    ],
                    "adversaryId": "adrelatemedia.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 17,
                    "description": "Malware family Trojan.Win32.Ml.C.Wacatac",
                    "firstContact": "2023-01-13T21:23:39.826Z",
                    "hasPlaybackContacts": false,
                    "id": "95944170-9388-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "2144": 16,
                        "2974": 1
                    },
                    "lastContact": "2023-01-18T17:36:53.768Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:23:55.271Z",
                    "timestamp": "2023-01-13T21:23:55.271Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "qzmfzfji.ws"
                    ],
                    "adversaryId": "qzmfzfji.ws",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-13T21:16:38.614Z",
                    "hasPlaybackContacts": false,
                    "id": "9b3a7140-9387-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 1
                    },
                    "lastContact": "2023-01-13T21:16:38.614Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:16:55.252Z",
                    "timestamp": "2023-01-13T21:16:55.252Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "poolto.be"
                    ],
                    "adversaryId": "poolto.be",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-13T21:14:23.799Z",
                    "hasPlaybackContacts": false,
                    "id": "4ac8e020-9387-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 2
                    },
                    "lastContact": "2023-01-13T21:14:24.178Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:14:40.290Z",
                    "timestamp": "2023-01-13T21:14:40.290Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "muhaddith.org"
                    ],
                    "adversaryId": "muhaddith.org",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Win32.A.Zpevdo",
                    "firstContact": "2023-01-13T21:11:58.476Z",
                    "hasPlaybackContacts": false,
                    "id": "f328c6f0-9386-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 1
                    },
                    "lastContact": "2023-01-13T21:11:58.476Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:12:13.279Z",
                    "timestamp": "2023-01-13T21:12:13.279Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "sinfiltro.cl"
                    ],
                    "adversaryId": "sinfiltro.cl",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:11:45.836Z",
                    "hasPlaybackContacts": false,
                    "id": "ebfb7760-9386-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 1
                    },
                    "lastContact": "2023-01-13T21:11:45.836Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:12:01.238Z",
                    "timestamp": "2023-01-13T21:12:01.238Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "hempearth.ca"
                    ],
                    "adversaryId": "hempearth.ca",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "QakBot",
                    "firstContact": "2023-01-13T21:11:06.227Z",
                    "hasPlaybackContacts": false,
                    "id": "d2fadcb0-9386-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 1
                    },
                    "lastContact": "2023-01-13T21:11:06.227Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:11:19.291Z",
                    "timestamp": "2023-01-13T21:11:19.291Z",
                    "totalEndpoints": 1,
                    "unread": true
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-01-26T23:17:22.954Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|timestamp|
>|---|---|---|
>| {'id': 'acc03f50-9bf0-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T14:09:11.109Z', 'statusTimestamp': '2023-01-24T14:09:11.109Z', 'status': 'open', 'contacts': 3, 'adversaries': ['www.sparechange.io'], 'adversaryId': 'www.sparechange.io', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'2254': 3}, 'totalEndpoints': 2, 'lastContact': '2023-01-24T14:23:20.504Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-24T14:08:59.469Z'},<br/>{'id': 'de703020-9bdf-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T12:08:53.026Z', 'statusTimestamp': '2023-01-24T12:08:53.026Z', 'status': 'open', 'contacts': 2, 'adversaries': ['bonbongame.com'], 'adversaryId': 'bonbongame.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 2}, 'totalEndpoints': 1, 'lastContact': '2023-01-24T12:08:37.234Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-24T12:08:37.234Z'},<br/>{'id': '17af99e0-9b70-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:48:45.438Z', 'statusTimestamp': '2023-01-24T11:07:08.277Z', 'status': 'open', 'contacts': 5, 'adversaries': ['noment.com'], 'adversaryId': 'noment.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 3, '2148': 1, '4232': 1}, 'totalEndpoints': 4, 'lastContact': '2023-01-24T20:27:25.049Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:48:27.684Z'},<br/>{'id': 'a5cc17b0-9b6d-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:31:15.371Z', 'statusTimestamp': '2023-01-23T22:31:15.371Z', 'status': 'open', 'contacts': 3, 'adversaries': ['fierdetreroutier.com'], 'adversaryId': 'fierdetreroutier.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1, '3182': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-24T20:31:29.489Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:30:58.327Z'},<br/>{'id': '520cd7a0-9b6c-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:21:45.370Z', 'statusTimestamp': '2023-01-23T22:21:45.370Z', 'status': 'open', 'contacts': 3, 'adversaries': ['aright.de'], 'adversaryId': 'aright.de', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1, '805': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-24T20:36:26.204Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:21:31.807Z'},<br/>{'id': '3c9a45b0-9b6c-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:21:09.387Z', 'statusTimestamp': '2023-01-23T22:21:09.387Z', 'status': 'open', 'contacts': 3, 'adversaries': ['maximals.ru'], 'adversaryId': 'maximals.ru', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1, '805': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-24T20:50:41.786Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:20:54.300Z'},<br/>{'id': '158c5e00-9b6b-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:12:54.368Z', 'statusTimestamp': '2023-01-23T22:12:54.368Z', 'status': 'open', 'contacts': 2, 'adversaries': ['lessgeneric.com'], 'adversaryId': 'lessgeneric.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T22:12:38.980Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:12:38.980Z'},<br/>{'id': 'ea14b390-9b69-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T22:04:31.945Z', 'statusTimestamp': '2023-01-23T22:04:31.945Z', 'status': 'open', 'contacts': 2, 'adversaries': ['exoticahousing.in'], 'adversaryId': 'exoticahousing.in', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T22:03:27.310Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T22:03:27.310Z'},<br/>{'id': 'a1f426f0-9b68-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T21:55:21.439Z', 'statusTimestamp': '2023-01-23T21:55:21.439Z', 'status': 'open', 'contacts': 2, 'adversaries': ['andam.vn'], 'adversaryId': 'andam.vn', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T21:55:06.459Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T21:55:06.459Z'},<br/>{'id': '8e4df090-9b68-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T21:54:48.473Z', 'statusTimestamp': '2023-01-23T21:54:48.473Z', 'status': 'open', 'contacts': 2, 'adversaries': ['ahmedabadcallgirl.biz'], 'adversaryId': 'ahmedabadcallgirl.biz', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T21:54:30.694Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T21:54:30.694Z'},<br/>{'id': '01989620-9b66-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T21:36:33.410Z', 'statusTimestamp': '2023-01-23T21:36:33.410Z', 'status': 'open', 'contacts': 2, 'adversaries': ['miner.nablabee.com'], 'adversaryId': 'miner.nablabee.com', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T21:36:19.439Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T21:36:19.439Z'},<br/>{'id': '15dfb250-9b64-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T21:22:48.437Z', 'statusTimestamp': '2023-01-23T21:22:48.437Z', 'status': 'open', 'contacts': 2, 'adversaries': ['skyplanners.com'], 'adversaryId': 'skyplanners.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-23T21:22:35.646Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-23T21:22:35.646Z'},<br/>{'id': 'bb540360-991d-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T23:54:09.430Z', 'statusTimestamp': '2023-01-20T23:54:09.430Z', 'status': 'open', 'contacts': 1, 'adversaries': ['mykooperativ.ru'], 'adversaryId': 'mykooperativ.ru', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-20T23:53:47.814Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-20T23:53:47.814Z'},<br/>{'id': '95e1ae70-98c8-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T13:44:39.383Z', 'statusTimestamp': '2023-01-20T13:44:39.383Z', 'status': 'open', 'contacts': 3, 'adversaries': ['galias.com.co'], 'adversaryId': 'galias.com.co', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'147': 1, '1179': 1, '4232': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-24T20:45:31.774Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-20T13:44:26.511Z'},<br/>{'id': '06883d70-98c3-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T13:04:51.399Z', 'statusTimestamp': '2023-01-20T13:04:51.399Z', 'status': 'open', 'contacts': 1, 'adversaries': ['museosantiagocarbonell.com'], 'adversaryId': 'museosantiagocarbonell.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Ml.B.Wacatac.Script', 'labelDistribution': {'1580': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T17:11:29.971Z', 'unread': False, 'hasPlaybackContacts': True, 'firstContact': '2023-01-13T17:11:29.971Z'},<br/>{'id': 'a6cad210-9793-11ed-b6d7-3f0c59c638d9', 'timestamp': '2023-01-19T00:53:13.265Z', 'statusTimestamp': '2023-01-19T00:53:13.265Z', 'status': 'open', 'contacts': 6, 'adversaries': ['www.midwestgrip.com'], 'adversaryId': 'www.midwestgrip.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 2, '3182': 2, '2148': 2}, 'totalEndpoints': 4, 'lastContact': '2023-01-19T21:11:40.694Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-19T00:52:58.373Z'},<br/>{'id': 'f8c42af0-953e-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-16T01:42:01.247Z', 'statusTimestamp': '2023-01-18T23:30:31.814Z', 'status': 'open', 'contacts': 11, 'adversaries': ['timekidspreschools.in'], 'adversaryId': 'timekidspreschools.in', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'3182': 2, '548': 2, '989': 3, '4055': 1, '1580': 3}, 'totalEndpoints': 6, 'lastContact': '2023-01-19T21:42:51.930Z', 'unread': False, 'hasPlaybackContacts': True, 'firstContact': '2023-01-13T19:15:51.535Z'},<br/>{'id': 'baba3320-9756-11ed-b6d7-3f0c59c638d9', 'timestamp': '2023-01-18T17:37:07.410Z', 'statusTimestamp': '2023-01-18T17:37:07.410Z', 'status': 'open', 'contacts': 6, 'adversaries': ['www.adrelatemedia.com'], 'adversaryId': 'www.adrelatemedia.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Jqrow.Ursnifdropper.Ad.Tr', 'labelDistribution': {'2144': 2, '548': 4}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T22:12:27.349Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-18T17:36:54.035Z'},<br/>{'id': '437d1750-9751-11ed-b6d7-3f0c59c638d9', 'timestamp': '2023-01-18T16:57:59.877Z', 'statusTimestamp': '2023-01-18T16:57:59.877Z', 'status': 'open', 'contacts': 7, 'adversaries': ['freebitcoinx.com'], 'adversaryId': 'freebitcoinx.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 2, '548': 2, '3182': 2, '2148': 1}, 'totalEndpoints': 5, 'lastContact': '2023-01-19T22:08:24.488Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-18T16:57:42.465Z'},<br/>{'id': '90a28550-973e-11ed-b6d7-3f0c59c638d9', 'timestamp': '2023-01-18T14:44:08.869Z', 'statusTimestamp': '2023-01-18T14:44:08.869Z', 'status': 'open', 'contacts': 616, 'adversaries': ['hurricanepub.com'], 'adversaryId': 'hurricanepub.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family UNC4034', 'labelDistribution': {'2144': 608, '4055': 4, '548': 4}, 'totalEndpoints': 3, 'lastContact': '2023-01-18T17:48:20.615Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-18T14:43:54.875Z'},<br/>{'id': 'cf267090-9601-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-17T00:56:43.289Z', 'statusTimestamp': '2023-01-17T00:56:43.289Z', 'status': 'open', 'contacts': 16, 'adversaries': ['www.megapress.click'], 'adversaryId': 'www.megapress.click', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '4061': 4, '2148': 2, '989': 2, '1179': 2, '2144': 4, '0': 1}, 'totalEndpoints': 7, 'lastContact': '2023-01-18T16:54:33.124Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-17T00:56:24.152Z'},<br/>{'id': 'cb8b4870-9601-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-17T00:56:37.239Z', 'statusTimestamp': '2023-01-17T00:56:37.239Z', 'status': 'open', 'contacts': 5, 'adversaries': ['www.app4vn.com'], 'adversaryId': 'www.app4vn.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '2148': 2, '4061': 2}, 'totalEndpoints': 3, 'lastContact': '2023-01-17T14:39:37.770Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-17T00:56:23.618Z'},<br/>{'id': 'b7e2a110-9601-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-17T00:56:04.257Z', 'statusTimestamp': '2023-01-17T00:56:04.257Z', 'status': 'open', 'contacts': 2, 'adversaries': ['campusdematematicas.com'], 'adversaryId': 'campusdematematicas.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'1580': 2}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T19:08:02.207Z', 'unread': False, 'hasPlaybackContacts': True, 'firstContact': '2023-01-13T19:08:02.207Z'},<br/>{'id': 'fe57b750-95a4-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-16T13:52:19.269Z', 'statusTimestamp': '2023-01-16T13:52:19.269Z', 'status': 'open', 'contacts': 5, 'adversaries': ['talebooks.com'], 'adversaryId': 'talebooks.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2254': 1, '4061': 3, '548': 1}, 'totalEndpoints': 4, 'lastContact': '2023-01-17T14:41:11.876Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-16T13:52:05.057Z'},<br/>{'id': '6eddaf40-938c-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:51:28.308Z', 'statusTimestamp': '2023-01-16T12:13:23.292Z', 'status': 'open', 'contacts': 4, 'adversaries': ['jits.ac.in'], 'adversaryId': 'jits.ac.in', 'adversaryTypes': ['Malware'], 'description': 'QakBot', 'labelDistribution': {'1791': 1, '548': 3}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T16:51:20.270Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:51:12.190Z'},<br/>{'id': 'a0664d30-94d4-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-15T13:00:46.339Z', 'statusTimestamp': '2023-01-15T13:00:46.339Z', 'status': 'open', 'contacts': 10, 'adversaries': ['waste4think.eu'], 'adversaryId': 'waste4think.eu', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'4055': 6, '548': 4}, 'totalEndpoints': 3, 'lastContact': '2023-01-18T21:22:09.643Z', 'unread': False, 'hasPlaybackContacts': True, 'firstContact': '2023-01-13T16:58:06.814Z'},<br/>{'id': '6edc4fb0-938c-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:51:28.299Z', 'statusTimestamp': '2023-01-13T21:51:28.299Z', 'status': 'open', 'contacts': 2, 'adversaries': ['msgos.com'], 'adversaryId': 'msgos.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1, '4055': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-17T14:56:08.635Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:51:10.312Z'},<br/>{'id': '642934c0-938c-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:51:10.348Z', 'statusTimestamp': '2023-01-13T21:51:10.348Z', 'status': 'open', 'contacts': 8, 'adversaries': ['netwonder.net'], 'adversaryId': 'netwonder.net', 'adversaryTypes': ['Malware'], 'description': 'Malware family Nivdort', 'labelDistribution': {'1791': 2, '2144': 6}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T16:43:54.810Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:50:53.247Z'},<br/>{'id': '59641870-938c-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:50:52.279Z', 'statusTimestamp': '2023-01-13T21:50:52.279Z', 'status': 'open', 'contacts': 1, 'adversaries': ['subwaybookreview.com'], 'adversaryId': 'subwaybookreview.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Exploit.Msoffice.Generic', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:50:38.599Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:50:38.599Z'},<br/>{'id': '405525e0-938c-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:50:10.238Z', 'statusTimestamp': '2023-01-13T21:50:10.238Z', 'status': 'open', 'contacts': 2, 'adversaries': ['michaeleaston.com'], 'adversaryId': 'michaeleaston.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Agent.Bg.Script', 'labelDistribution': {'1791': 1, '989': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T16:52:09Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:49:50.220Z'},<br/>{'id': '304360e0-938c-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:49:43.278Z', 'statusTimestamp': '2023-01-13T21:49:43.278Z', 'status': 'open', 'contacts': 1, 'adversaries': ['cane.pw'], 'adversaryId': 'cane.pw', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:49:28.515Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:49:28.515Z'},<br/>{'id': 'f1a7da00-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:47:58.240Z', 'statusTimestamp': '2023-01-13T21:47:58.240Z', 'status': 'open', 'contacts': 1, 'adversaries': ['cek.pm'], 'adversaryId': 'cek.pm', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:47:46.473Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:47:46.473Z'},<br/>{'id': 'c329ff00-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:46:40.240Z', 'statusTimestamp': '2023-01-13T21:46:40.240Z', 'status': 'open', 'contacts': 1, 'adversaries': ['anothercity.ru'], 'adversaryId': 'anothercity.ru', 'adversaryTypes': ['Malware'], 'description': 'Malware family Backdoor.Peg.Php.Generic', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:46:26.925Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:46:26.925Z'},<br/>{'id': 'bc0a4400-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:46:28.288Z', 'statusTimestamp': '2023-01-13T21:46:28.288Z', 'status': 'open', 'contacts': 3, 'adversaries': ['tormail.org'], 'adversaryId': 'tormail.org', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1, '2144': 2}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T18:02:09.546Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:46:15.650Z'},<br/>{'id': 'ba390670-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:46:25.239Z', 'statusTimestamp': '2023-01-13T21:46:25.239Z', 'status': 'open', 'contacts': 1, 'adversaries': ['businessbackend.com'], 'adversaryId': 'businessbackend.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:46:06.886Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:46:06.886Z'},<br/>{'id': '59b2ca20-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:43:43.298Z', 'statusTimestamp': '2023-01-13T21:43:43.298Z', 'status': 'open', 'contacts': 1, 'adversaries': ['asdasd.ru'], 'adversaryId': 'asdasd.ru', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:43:29.477Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:43:29.477Z'},<br/>{'id': '54504f80-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:43:34.264Z', 'statusTimestamp': '2023-01-13T21:43:34.264Z', 'status': 'open', 'contacts': 3, 'adversaries': ['hotprice.co'], 'adversaryId': 'hotprice.co', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1, '2144': 2}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T18:17:08.744Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:43:18.543Z'},<br/>{'id': '544ca600-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:43:34.240Z', 'statusTimestamp': '2023-01-13T21:43:34.240Z', 'status': 'open', 'contacts': 1, 'adversaries': ['theshallowtalesreview.com.ng'], 'adversaryId': 'theshallowtalesreview.com.ng', 'adversaryTypes': ['Malware'], 'description': 'Quakbot', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:43:17.535Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:43:17.535Z'},<br/>{'id': '50b8f7f0-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:43:28.239Z', 'statusTimestamp': '2023-01-13T21:43:28.239Z', 'status': 'open', 'contacts': 1, 'adversaries': ['disposable.ml'], 'adversaryId': 'disposable.ml', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:43:13.301Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:43:13.301Z'},<br/>{'id': '1eb37cd0-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:42:04.317Z', 'statusTimestamp': '2023-01-13T21:42:04.317Z', 'status': 'open', 'contacts': 4, 'adversaries': ['founddll.com'], 'adversaryId': 'founddll.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Win32.Diplugem.Browsermodifier', 'labelDistribution': {'1791': 4}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:41:49.590Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:41:49.494Z'},<br/>{'id': '1eb0bdb0-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:42:04.299Z', 'statusTimestamp': '2023-01-13T21:42:04.299Z', 'status': 'open', 'contacts': 2, 'adversaries': ['learnwithportals.com'], 'adversaryId': 'learnwithportals.com', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'1791': 2}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:41:48.945Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:41:48.847Z'},<br/>{'id': '13ecd9e0-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:41:46.238Z', 'statusTimestamp': '2023-01-13T21:41:46.238Z', 'status': 'open', 'contacts': 1, 'adversaries': ['realestateexpert.us'], 'adversaryId': 'realestateexpert.us', 'adversaryTypes': ['Malware'], 'description': 'QakBot', 'labelDistribution': {'2974': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:41:30.187Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:41:30.187Z'},<br/>{'id': 'fcae3a80-938a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:41:07.240Z', 'statusTimestamp': '2023-01-13T21:41:07.240Z', 'status': 'open', 'contacts': 7, 'adversaries': ['kloap.com'], 'adversaryId': 'kloap.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1, '2144': 6}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T18:01:53.928Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:40:54.134Z'},<br/>{'id': 'cc6cb680-938a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:39:46.280Z', 'statusTimestamp': '2023-01-13T21:39:46.280Z', 'status': 'open', 'contacts': 9, 'adversaries': ['disconight.com.ar'], 'adversaryId': 'disconight.com.ar', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'1791': 1, '2144': 8}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T20:41:33.286Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:39:29.886Z'},<br/>{'id': '95944170-9388-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:23:55.271Z', 'statusTimestamp': '2023-01-13T21:23:55.271Z', 'status': 'open', 'contacts': 17, 'adversaries': ['adrelatemedia.com'], 'adversaryId': 'adrelatemedia.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Win32.Ml.C.Wacatac', 'labelDistribution': {'2974': 1, '2144': 16}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T17:36:53.768Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:23:39.826Z'},<br/>{'id': '9b3a7140-9387-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:16:55.252Z', 'statusTimestamp': '2023-01-13T21:16:55.252Z', 'status': 'open', 'contacts': 1, 'adversaries': ['qzmfzfji.ws'], 'adversaryId': 'qzmfzfji.ws', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'1580': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:16:38.614Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:16:38.614Z'},<br/>{'id': '4ac8e020-9387-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:14:40.290Z', 'statusTimestamp': '2023-01-13T21:14:40.290Z', 'status': 'open', 'contacts': 2, 'adversaries': ['poolto.be'], 'adversaryId': 'poolto.be', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'1580': 2}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:14:24.178Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:14:23.799Z'},<br/>{'id': 'f328c6f0-9386-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:12:13.279Z', 'statusTimestamp': '2023-01-13T21:12:13.279Z', 'status': 'open', 'contacts': 1, 'adversaries': ['muhaddith.org'], 'adversaryId': 'muhaddith.org', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Win32.A.Zpevdo', 'labelDistribution': {'1580': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:11:58.476Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:11:58.476Z'},<br/>{'id': 'ebfb7760-9386-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:12:01.238Z', 'statusTimestamp': '2023-01-13T21:12:01.238Z', 'status': 'open', 'contacts': 1, 'adversaries': ['sinfiltro.cl'], 'adversaryId': 'sinfiltro.cl', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1580': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:11:45.836Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:11:45.836Z'},<br/>{'id': 'd2fadcb0-9386-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:11:19.291Z', 'statusTimestamp': '2023-01-13T21:11:19.291Z', 'status': 'open', 'contacts': 1, 'adversaries': ['hempearth.ca'], 'adversaryId': 'hempearth.ca', 'adversaryTypes': ['Malware'], 'description': 'QakBot', 'labelDistribution': {'1580': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:11:06.227Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:11:06.227Z'} | page: 1<br/>items: 50<br/>next: 2 | 2023-01-26T23:17:22.954Z |


#### Command example
```!lumu-retrieve-open-incidents adversary-types=Spam labels=1791```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveOpenIncidents": {
            "items": [
                {
                    "adversaries": [
                        "msgos.com"
                    ],
                    "adversaryId": "msgos.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:51:10.312Z",
                    "hasPlaybackContacts": false,
                    "id": "6edc4fb0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4055": 1
                    },
                    "lastContact": "2023-01-17T14:56:08.635Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:51:28.299Z",
                    "timestamp": "2023-01-13T21:51:28.299Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "cane.pw"
                    ],
                    "adversaryId": "cane.pw",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:49:28.515Z",
                    "hasPlaybackContacts": false,
                    "id": "304360e0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:49:28.515Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:49:43.278Z",
                    "timestamp": "2023-01-13T21:49:43.278Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "cek.pm"
                    ],
                    "adversaryId": "cek.pm",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:47:46.473Z",
                    "hasPlaybackContacts": false,
                    "id": "f1a7da00-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:47:46.473Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:47:58.240Z",
                    "timestamp": "2023-01-13T21:47:58.240Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "tormail.org"
                    ],
                    "adversaryId": "tormail.org",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:46:15.650Z",
                    "hasPlaybackContacts": false,
                    "id": "bc0a4400-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 2
                    },
                    "lastContact": "2023-01-18T18:02:09.546Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:46:28.288Z",
                    "timestamp": "2023-01-13T21:46:28.288Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "businessbackend.com"
                    ],
                    "adversaryId": "businessbackend.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:46:06.886Z",
                    "hasPlaybackContacts": false,
                    "id": "ba390670-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:46:06.886Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:46:25.239Z",
                    "timestamp": "2023-01-13T21:46:25.239Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "asdasd.ru"
                    ],
                    "adversaryId": "asdasd.ru",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:29.477Z",
                    "hasPlaybackContacts": false,
                    "id": "59b2ca20-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:43:29.477Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:43.298Z",
                    "timestamp": "2023-01-13T21:43:43.298Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "hotprice.co"
                    ],
                    "adversaryId": "hotprice.co",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:18.543Z",
                    "hasPlaybackContacts": false,
                    "id": "54504f80-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 2
                    },
                    "lastContact": "2023-01-18T18:17:08.744Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:34.264Z",
                    "timestamp": "2023-01-13T21:43:34.264Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "disposable.ml"
                    ],
                    "adversaryId": "disposable.ml",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:13.301Z",
                    "hasPlaybackContacts": false,
                    "id": "50b8f7f0-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1
                    },
                    "lastContact": "2023-01-13T21:43:13.301Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:28.239Z",
                    "timestamp": "2023-01-13T21:43:28.239Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "kloap.com"
                    ],
                    "adversaryId": "kloap.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:40:54.134Z",
                    "hasPlaybackContacts": false,
                    "id": "fcae3a80-938a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 6
                    },
                    "lastContact": "2023-01-18T18:01:53.928Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:41:07.240Z",
                    "timestamp": "2023-01-13T21:41:07.240Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "jdz.ro"
                    ],
                    "adversaryId": "jdz.ro",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T20:44:27.671Z",
                    "hasPlaybackContacts": false,
                    "id": "1baa0700-9383-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:36:01.944Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:44:43.248Z",
                    "timestamp": "2023-01-13T20:44:43.248Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "veryday.info"
                    ],
                    "adversaryId": "veryday.info",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T20:44:22.181Z",
                    "hasPlaybackContacts": false,
                    "id": "1816a710-9383-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 2
                    },
                    "lastContact": "2023-01-13T21:35:57.035Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:44:37.249Z",
                    "timestamp": "2023-01-13T20:44:37.249Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "niwl.net"
                    ],
                    "adversaryId": "niwl.net",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T20:42:47.278Z",
                    "hasPlaybackContacts": false,
                    "id": "dee785e0-9382-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4
                    },
                    "lastContact": "2023-01-13T21:34:12.902Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:43:01.310Z",
                    "timestamp": "2023-01-13T20:43:01.310Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "shipfromto.com"
                    ],
                    "adversaryId": "shipfromto.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:48:45.035Z",
                    "hasPlaybackContacts": false,
                    "id": "8e61bd60-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:30:35.022Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:48:58.294Z",
                    "timestamp": "2023-01-13T17:48:58.294Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "nut.cc"
                    ],
                    "adversaryId": "nut.cc",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:46:45.978Z",
                    "hasPlaybackContacts": false,
                    "id": "489c6960-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:29:05.534Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:47:01.238Z",
                    "timestamp": "2023-01-13T17:47:01.238Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "5july.org"
                    ],
                    "adversaryId": "5july.org",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:46:31.250Z",
                    "hasPlaybackContacts": false,
                    "id": "41755b60-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:27:37.997Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:46:49.238Z",
                    "timestamp": "2023-01-13T17:46:49.238Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "nowmymail.com"
                    ],
                    "adversaryId": "nowmymail.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:46:03.300Z",
                    "hasPlaybackContacts": false,
                    "id": "2f9b5980-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:29:04.201Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:46:19.288Z",
                    "timestamp": "2023-01-13T17:46:19.288Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "humaility.com"
                    ],
                    "adversaryId": "humaility.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:38:41.782Z",
                    "hasPlaybackContacts": false,
                    "id": "27048450-9369-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:24:14.176Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:38:55.381Z",
                    "timestamp": "2023-01-13T17:38:55.381Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "bobmurchison.com"
                    ],
                    "adversaryId": "bobmurchison.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:35:52.041Z",
                    "hasPlaybackContacts": false,
                    "id": "c2d0f770-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:21:01.223Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:36:07.271Z",
                    "timestamp": "2023-01-13T17:36:07.271Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "zoemail.com"
                    ],
                    "adversaryId": "zoemail.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:33:54.255Z",
                    "hasPlaybackContacts": false,
                    "id": "7b48bdc0-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:19:49.590Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:34:07.260Z",
                    "timestamp": "2023-01-13T17:34:07.260Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "whiffles.org"
                    ],
                    "adversaryId": "whiffles.org",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:32:23.990Z",
                    "hasPlaybackContacts": false,
                    "id": "45c6ed20-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:20:12.982Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:32:37.490Z",
                    "timestamp": "2023-01-13T17:32:37.490Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "cdpa.cc"
                    ],
                    "adversaryId": "cdpa.cc",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:32:14.141Z",
                    "hasPlaybackContacts": false,
                    "id": "405a1240-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:18:50.608Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:32:28.388Z",
                    "timestamp": "2023-01-13T17:32:28.388Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "maboard.com"
                    ],
                    "adversaryId": "maboard.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:26:24.964Z",
                    "hasPlaybackContacts": false,
                    "id": "70d86da0-9367-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:17:01.288Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:26:40.250Z",
                    "timestamp": "2023-01-13T17:26:40.250Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "trashmail.me"
                    ],
                    "adversaryId": "trashmail.me",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 6,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:25:20.022Z",
                    "hasPlaybackContacts": false,
                    "id": "49817990-9367-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 6
                    },
                    "lastContact": "2023-01-13T21:16:04.210Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:25:34.249Z",
                    "timestamp": "2023-01-13T17:25:34.249Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "ige.es"
                    ],
                    "adversaryId": "ige.es",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:17:09.658Z",
                    "hasPlaybackContacts": false,
                    "id": "260cbe30-9366-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3
                    },
                    "lastContact": "2023-01-13T21:10:03.443Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:17:25.267Z",
                    "timestamp": "2023-01-13T17:17:25.267Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "recipeforfailure.com"
                    ],
                    "adversaryId": "recipeforfailure.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 5,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:14:43.996Z",
                    "hasPlaybackContacts": false,
                    "id": "ce6a0cf0-9365-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 5
                    },
                    "lastContact": "2023-01-13T21:09:28.184Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:14:58.239Z",
                    "timestamp": "2023-01-13T17:14:58.239Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "ht.cx"
                    ],
                    "adversaryId": "ht.cx",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:08:41.074Z",
                    "hasPlaybackContacts": false,
                    "id": "f6118770-9364-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4
                    },
                    "lastContact": "2023-01-13T21:06:01.810Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:08:55.271Z",
                    "timestamp": "2023-01-13T17:08:55.271Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "emailz.ga"
                    ],
                    "adversaryId": "emailz.ga",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:04:07.777Z",
                    "hasPlaybackContacts": false,
                    "id": "7c9b7950-9364-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4
                    },
                    "lastContact": "2023-01-13T21:02:29.769Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:05:31.493Z",
                    "timestamp": "2023-01-13T17:05:31.493Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "throam.com"
                    ],
                    "adversaryId": "throam.com",
                    "adversaryTypes": [
                        "Malware",
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "CoinMiner",
                    "firstContact": "2023-01-13T17:02:53.430Z",
                    "hasPlaybackContacts": false,
                    "id": "5bcda590-9364-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4
                    },
                    "lastContact": "2023-01-13T21:01:34.951Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:04:36.457Z",
                    "timestamp": "2023-01-13T17:04:36.457Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "guerillamail.de"
                    ],
                    "adversaryId": "guerillamail.de",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T15:51:31.019Z",
                    "hasPlaybackContacts": false,
                    "id": "36215fd0-935a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "2974": 1
                    },
                    "lastContact": "2023-01-13T21:30:52.668Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T15:51:58.285Z",
                    "timestamp": "2023-01-13T15:51:58.285Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "shiftmail.com"
                    ],
                    "adversaryId": "shiftmail.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T15:51:02.843Z",
                    "hasPlaybackContacts": false,
                    "id": "2273d670-935a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "2974": 1
                    },
                    "lastContact": "2023-01-13T21:30:28.698Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T15:51:25.271Z",
                    "timestamp": "2023-01-13T15:51:25.271Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "landmail.co"
                    ],
                    "adversaryId": "landmail.co",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T15:49:27.939Z",
                    "hasPlaybackContacts": false,
                    "id": "e5a32480-9359-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "2974": 1
                    },
                    "lastContact": "2023-01-13T21:29:08.665Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T15:49:43.240Z",
                    "timestamp": "2023-01-13T15:49:43.240Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "morriesworld.ml"
                    ],
                    "adversaryId": "morriesworld.ml",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T15:47:32.413Z",
                    "hasPlaybackContacts": false,
                    "id": "a1bc2d70-9359-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "2974": 1
                    },
                    "lastContact": "2023-01-13T21:27:48.886Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T15:47:49.319Z",
                    "timestamp": "2023-01-13T15:47:49.319Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "mailguard.me"
                    ],
                    "adversaryId": "mailguard.me",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T15:46:03.633Z",
                    "hasPlaybackContacts": false,
                    "id": "6fa26700-9359-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "2974": 1
                    },
                    "lastContact": "2023-01-13T21:26:50.263Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T15:46:25.264Z",
                    "timestamp": "2023-01-13T15:46:25.264Z",
                    "totalEndpoints": 3,
                    "unread": true
                }
            ],
            "paginationInfo": {
                "items": 50,
                "page": 1
            },
            "timestamp": "2023-01-26T23:17:25.305Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|timestamp|
>|---|---|---|
>| {'id': '6edc4fb0-938c-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:51:28.299Z', 'statusTimestamp': '2023-01-13T21:51:28.299Z', 'status': 'open', 'contacts': 2, 'adversaries': ['msgos.com'], 'adversaryId': 'msgos.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1, '4055': 1}, 'totalEndpoints': 2, 'lastContact': '2023-01-17T14:56:08.635Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:51:10.312Z'},<br/>{'id': '304360e0-938c-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:49:43.278Z', 'statusTimestamp': '2023-01-13T21:49:43.278Z', 'status': 'open', 'contacts': 1, 'adversaries': ['cane.pw'], 'adversaryId': 'cane.pw', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:49:28.515Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:49:28.515Z'},<br/>{'id': 'f1a7da00-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:47:58.240Z', 'statusTimestamp': '2023-01-13T21:47:58.240Z', 'status': 'open', 'contacts': 1, 'adversaries': ['cek.pm'], 'adversaryId': 'cek.pm', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:47:46.473Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:47:46.473Z'},<br/>{'id': 'bc0a4400-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:46:28.288Z', 'statusTimestamp': '2023-01-13T21:46:28.288Z', 'status': 'open', 'contacts': 3, 'adversaries': ['tormail.org'], 'adversaryId': 'tormail.org', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1, '2144': 2}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T18:02:09.546Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:46:15.650Z'},<br/>{'id': 'ba390670-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:46:25.239Z', 'statusTimestamp': '2023-01-13T21:46:25.239Z', 'status': 'open', 'contacts': 1, 'adversaries': ['businessbackend.com'], 'adversaryId': 'businessbackend.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:46:06.886Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:46:06.886Z'},<br/>{'id': '59b2ca20-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:43:43.298Z', 'statusTimestamp': '2023-01-13T21:43:43.298Z', 'status': 'open', 'contacts': 1, 'adversaries': ['asdasd.ru'], 'adversaryId': 'asdasd.ru', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:43:29.477Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:43:29.477Z'},<br/>{'id': '54504f80-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:43:34.264Z', 'statusTimestamp': '2023-01-13T21:43:34.264Z', 'status': 'open', 'contacts': 3, 'adversaries': ['hotprice.co'], 'adversaryId': 'hotprice.co', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1, '2144': 2}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T18:17:08.744Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:43:18.543Z'},<br/>{'id': '50b8f7f0-938b-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:43:28.239Z', 'statusTimestamp': '2023-01-13T21:43:28.239Z', 'status': 'open', 'contacts': 1, 'adversaries': ['disposable.ml'], 'adversaryId': 'disposable.ml', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:43:13.301Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:43:13.301Z'},<br/>{'id': 'fcae3a80-938a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T21:41:07.240Z', 'statusTimestamp': '2023-01-13T21:41:07.240Z', 'status': 'open', 'contacts': 7, 'adversaries': ['kloap.com'], 'adversaryId': 'kloap.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 1, '2144': 6}, 'totalEndpoints': 2, 'lastContact': '2023-01-18T18:01:53.928Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T21:40:54.134Z'},<br/>{'id': '1baa0700-9383-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T20:44:43.248Z', 'statusTimestamp': '2023-01-13T20:44:43.248Z', 'status': 'open', 'contacts': 3, 'adversaries': ['jdz.ro'], 'adversaryId': 'jdz.ro', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:36:01.944Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T20:44:27.671Z'},<br/>{'id': '1816a710-9383-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T20:44:37.249Z', 'statusTimestamp': '2023-01-13T20:44:37.249Z', 'status': 'open', 'contacts': 2, 'adversaries': ['veryday.info'], 'adversaryId': 'veryday.info', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 2}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:35:57.035Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T20:44:22.181Z'},<br/>{'id': 'dee785e0-9382-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T20:43:01.310Z', 'statusTimestamp': '2023-01-13T20:43:01.310Z', 'status': 'open', 'contacts': 4, 'adversaries': ['niwl.net'], 'adversaryId': 'niwl.net', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 4}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T21:34:12.902Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T20:42:47.278Z'},<br/>{'id': '8e61bd60-936a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:48:58.294Z', 'statusTimestamp': '2023-01-13T17:48:58.294Z', 'status': 'open', 'contacts': 3, 'adversaries': ['shipfromto.com'], 'adversaryId': 'shipfromto.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 2, 'lastContact': '2023-01-13T21:30:35.022Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:48:45.035Z'},<br/>{'id': '489c6960-936a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:47:01.238Z', 'statusTimestamp': '2023-01-13T17:47:01.238Z', 'status': 'open', 'contacts': 3, 'adversaries': ['nut.cc'], 'adversaryId': 'nut.cc', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 2, 'lastContact': '2023-01-13T21:29:05.534Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:46:45.978Z'},<br/>{'id': '41755b60-936a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:46:49.238Z', 'statusTimestamp': '2023-01-13T17:46:49.238Z', 'status': 'open', 'contacts': 3, 'adversaries': ['5july.org'], 'adversaryId': '5july.org', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 2, 'lastContact': '2023-01-13T21:27:37.997Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:46:31.250Z'},<br/>{'id': '2f9b5980-936a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:46:19.288Z', 'statusTimestamp': '2023-01-13T17:46:19.288Z', 'status': 'open', 'contacts': 3, 'adversaries': ['nowmymail.com'], 'adversaryId': 'nowmymail.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 2, 'lastContact': '2023-01-13T21:29:04.201Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:46:03.300Z'},<br/>{'id': '27048450-9369-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:38:55.381Z', 'statusTimestamp': '2023-01-13T17:38:55.381Z', 'status': 'open', 'contacts': 3, 'adversaries': ['humaility.com'], 'adversaryId': 'humaility.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:24:14.176Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:38:41.782Z'},<br/>{'id': 'c2d0f770-9368-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:36:07.271Z', 'statusTimestamp': '2023-01-13T17:36:07.271Z', 'status': 'open', 'contacts': 3, 'adversaries': ['bobmurchison.com'], 'adversaryId': 'bobmurchison.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:21:01.223Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:35:52.041Z'},<br/>{'id': '7b48bdc0-9368-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:34:07.260Z', 'statusTimestamp': '2023-01-13T17:34:07.260Z', 'status': 'open', 'contacts': 3, 'adversaries': ['zoemail.com'], 'adversaryId': 'zoemail.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:19:49.590Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:33:54.255Z'},<br/>{'id': '45c6ed20-9368-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:32:37.490Z', 'statusTimestamp': '2023-01-13T17:32:37.490Z', 'status': 'open', 'contacts': 3, 'adversaries': ['whiffles.org'], 'adversaryId': 'whiffles.org', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:20:12.982Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:32:23.990Z'},<br/>{'id': '405a1240-9368-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:32:28.388Z', 'statusTimestamp': '2023-01-13T17:32:28.388Z', 'status': 'open', 'contacts': 3, 'adversaries': ['cdpa.cc'], 'adversaryId': 'cdpa.cc', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:18:50.608Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:32:14.141Z'},<br/>{'id': '70d86da0-9367-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:26:40.250Z', 'statusTimestamp': '2023-01-13T17:26:40.250Z', 'status': 'open', 'contacts': 3, 'adversaries': ['maboard.com'], 'adversaryId': 'maboard.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:17:01.288Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:26:24.964Z'},<br/>{'id': '49817990-9367-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:25:34.249Z', 'statusTimestamp': '2023-01-13T17:25:34.249Z', 'status': 'open', 'contacts': 6, 'adversaries': ['trashmail.me'], 'adversaryId': 'trashmail.me', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 6}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:16:04.210Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:25:20.022Z'},<br/>{'id': '260cbe30-9366-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:17:25.267Z', 'statusTimestamp': '2023-01-13T17:17:25.267Z', 'status': 'open', 'contacts': 3, 'adversaries': ['ige.es'], 'adversaryId': 'ige.es', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:10:03.443Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:17:09.658Z'},<br/>{'id': 'ce6a0cf0-9365-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:14:58.239Z', 'statusTimestamp': '2023-01-13T17:14:58.239Z', 'status': 'open', 'contacts': 5, 'adversaries': ['recipeforfailure.com'], 'adversaryId': 'recipeforfailure.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 5}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:09:28.184Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:14:43.996Z'},<br/>{'id': 'f6118770-9364-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:08:55.271Z', 'statusTimestamp': '2023-01-13T17:08:55.271Z', 'status': 'open', 'contacts': 4, 'adversaries': ['ht.cx'], 'adversaryId': 'ht.cx', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 4}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:06:01.810Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:08:41.074Z'},<br/>{'id': '7c9b7950-9364-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:05:31.493Z', 'statusTimestamp': '2023-01-13T17:05:31.493Z', 'status': 'open', 'contacts': 4, 'adversaries': ['emailz.ga'], 'adversaryId': 'emailz.ga', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'1791': 4}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:02:29.769Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:04:07.777Z'},<br/>{'id': '5bcda590-9364-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T17:04:36.457Z', 'statusTimestamp': '2023-01-13T17:04:36.457Z', 'status': 'open', 'contacts': 4, 'adversaries': ['throam.com'], 'adversaryId': 'throam.com', 'adversaryTypes': ['Malware', 'Spam'], 'description': 'CoinMiner', 'labelDistribution': {'1791': 4}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:01:34.951Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T17:02:53.430Z'},<br/>{'id': '36215fd0-935a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T15:51:58.285Z', 'statusTimestamp': '2023-01-13T15:51:58.285Z', 'status': 'open', 'contacts': 4, 'adversaries': ['guerillamail.de'], 'adversaryId': 'guerillamail.de', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2974': 1, '1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:30:52.668Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T15:51:31.019Z'},<br/>{'id': '2273d670-935a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T15:51:25.271Z', 'statusTimestamp': '2023-01-13T15:51:25.271Z', 'status': 'open', 'contacts': 4, 'adversaries': ['shiftmail.com'], 'adversaryId': 'shiftmail.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2974': 1, '1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:30:28.698Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T15:51:02.843Z'},<br/>{'id': 'e5a32480-9359-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T15:49:43.240Z', 'statusTimestamp': '2023-01-13T15:49:43.240Z', 'status': 'open', 'contacts': 4, 'adversaries': ['landmail.co'], 'adversaryId': 'landmail.co', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2974': 1, '1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:29:08.665Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T15:49:27.939Z'},<br/>{'id': 'a1bc2d70-9359-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T15:47:49.319Z', 'statusTimestamp': '2023-01-13T15:47:49.319Z', 'status': 'open', 'contacts': 4, 'adversaries': ['morriesworld.ml'], 'adversaryId': 'morriesworld.ml', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2974': 1, '1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:27:48.886Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T15:47:32.413Z'},<br/>{'id': '6fa26700-9359-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T15:46:25.264Z', 'statusTimestamp': '2023-01-13T15:46:25.264Z', 'status': 'open', 'contacts': 4, 'adversaries': ['mailguard.me'], 'adversaryId': 'mailguard.me', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2974': 1, '1791': 3}, 'totalEndpoints': 3, 'lastContact': '2023-01-13T21:26:50.263Z', 'unread': True, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T15:46:03.633Z'} | page: 1<br/>items: 50 | 2023-01-26T23:17:25.305Z |


### lumu-retrieve-muted-incidents
***
Get a paginated list of muted incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-muted-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | . | Optional | 
| items | . | Optional | 
| adversary-types | . | Optional | 
| labels | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveMutedIncidents.items.id | String |  | 
| Lumu.RetrieveMutedIncidents.items.timestamp | Date |  | 
| Lumu.RetrieveMutedIncidents.items.statusTimestamp | Date |  | 
| Lumu.RetrieveMutedIncidents.items.status | String |  | 
| Lumu.RetrieveMutedIncidents.items.contacts | Number |  | 
| Lumu.RetrieveMutedIncidents.items.adversaries | String |  | 
| Lumu.RetrieveMutedIncidents.items.adversaryId | String |  | 
| Lumu.RetrieveMutedIncidents.items.adversaryTypes | String |  | 
| Lumu.RetrieveMutedIncidents.items.description | String |  | 
| Lumu.RetrieveMutedIncidents.items.labelDistribution.179 | Number |  | 
| Lumu.RetrieveMutedIncidents.items.labelDistribution.39 | Number |  | 
| Lumu.RetrieveMutedIncidents.items.totalEndpoints | Number |  | 
| Lumu.RetrieveMutedIncidents.items.lastContact | Date |  | 
| Lumu.RetrieveMutedIncidents.items.unread | Boolean |  | 
| Lumu.RetrieveMutedIncidents.paginationInfo.page | Number |  | 
| Lumu.RetrieveMutedIncidents.paginationInfo.items | Number |  | 

#### Command example
```!lumu-retrieve-muted-incidents```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveMutedIncidents": {
            "items": [
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "muted",
                    "statusTimestamp": "2023-01-26T23:00:36.915Z",
                    "timestamp": "2023-01-26T22:57:47.029Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "mediaworld.pro"
                    ],
                    "adversaryId": "mediaworld.pro",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Spam.Pdf",
                    "firstContact": "2023-01-13T19:43:16.549Z",
                    "hasPlaybackContacts": false,
                    "id": "945eb000-937a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 1
                    },
                    "lastContact": "2023-01-13T19:43:16.549Z",
                    "status": "muted",
                    "statusTimestamp": "2023-01-26T22:55:53.366Z",
                    "timestamp": "2023-01-13T19:43:40.288Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "12finance.com"
                    ],
                    "adversaryId": "12finance.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 11,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-12-23T14:46:54Z",
                    "hasPlaybackContacts": false,
                    "id": "721ed640-82d2-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "2148": 1,
                        "2254": 10
                    },
                    "lastContact": "2022-12-23T22:30:10.448Z",
                    "status": "muted",
                    "statusTimestamp": "2022-12-27T02:39:14.360Z",
                    "timestamp": "2022-12-23T14:59:48.772Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.digeus.com"
                    ],
                    "adversaryId": "www.digeus.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family Application.Deceptor.ANL",
                    "firstContact": "2022-12-12T23:20:56.706Z",
                    "hasPlaybackContacts": false,
                    "id": "ab056a80-7a73-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "147": 1,
                        "218": 1
                    },
                    "lastContact": "2022-12-22T20:37:02.228Z",
                    "status": "muted",
                    "statusTimestamp": "2022-12-15T20:59:51.796Z",
                    "timestamp": "2022-12-12T23:21:12.744Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "jameshallybone.co.uk"
                    ],
                    "adversaryId": "jameshallybone.co.uk",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 8,
                    "description": "Malicious domain",
                    "firstContact": "2022-11-21T21:46:01.425Z",
                    "hasPlaybackContacts": false,
                    "id": "f06a50c0-69e5-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "1651": 1,
                        "3811": 1,
                        "989": 6
                    },
                    "lastContact": "2022-12-05T16:03:05.322Z",
                    "status": "muted",
                    "statusTimestamp": "2022-12-13T20:48:09.825Z",
                    "timestamp": "2022-11-21T21:46:22.028Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "3.223.53.1"
                    ],
                    "adversaryId": "3.223.53.1",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-12T17:09:20.331Z",
                    "hasPlaybackContacts": false,
                    "id": "8b6f8c70-7a71-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "218": 1
                    },
                    "lastContact": "2022-12-12T17:09:20.331Z",
                    "status": "muted",
                    "statusTimestamp": "2022-12-12T23:21:43.833Z",
                    "timestamp": "2022-12-12T23:06:00.759Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "coovigomez.com"
                    ],
                    "adversaryId": "coovigomez.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-11-12T23:31:33Z",
                    "hasPlaybackContacts": false,
                    "id": "149207b0-6471-11ed-b373-192ba321fedf",
                    "labelDistribution": {
                        "2148": 1
                    },
                    "lastContact": "2022-11-12T23:31:33Z",
                    "status": "muted",
                    "statusTimestamp": "2022-11-17T18:56:09.751Z",
                    "timestamp": "2022-11-14T23:07:15.755Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "barbombon.com."
                    ],
                    "adversaryId": "barbombon.com.",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family Trojan.Script.Generic",
                    "firstContact": "2022-10-28T19:39:13.452Z",
                    "hasPlaybackContacts": false,
                    "id": "47bbc6c0-56f8-11ed-987a-cd6f8ff058b8",
                    "labelDistribution": {
                        "1651": 2
                    },
                    "lastContact": "2022-10-28T19:44:10.172Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-31T21:51:02.594Z",
                    "timestamp": "2022-10-28T19:39:47.372Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "coasttickets.com"
                    ],
                    "adversaryId": "coasttickets.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Downloader.Psdownload.MSIL.Generic",
                    "firstContact": "2022-09-22T15:19:42.152Z",
                    "hasPlaybackContacts": true,
                    "id": "11c5a410-41fd-11ed-8751-63984e51f242",
                    "labelDistribution": {
                        "548": 1
                    },
                    "lastContact": "2022-09-22T15:19:42.152Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-28T17:06:32.994Z",
                    "timestamp": "2022-10-02T02:51:09.905Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "dark-utilities.pw"
                    ],
                    "adversaryId": "dark-utilities.pw",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-10-27T16:47:40Z",
                    "hasPlaybackContacts": false,
                    "id": "8da63fc0-5618-11ed-987a-cd6f8ff058b8",
                    "labelDistribution": {
                        "2148": 1,
                        "2267": 1
                    },
                    "lastContact": "2022-10-27T17:12:45.099Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-27T17:57:57.931Z",
                    "timestamp": "2022-10-27T16:58:17.404Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.com-about.com"
                    ],
                    "adversaryId": "www.com-about.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Downloader.Riskware.A.Atoz",
                    "firstContact": "2022-10-25T20:45:41.154Z",
                    "hasPlaybackContacts": false,
                    "id": "046a19c0-54a6-11ed-9df2-6538d9561738",
                    "labelDistribution": {
                        "3635": 1
                    },
                    "lastContact": "2022-10-25T20:45:41.154Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-25T21:17:21.376Z",
                    "timestamp": "2022-10-25T20:45:53.372Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "nexttime.ovh"
                    ],
                    "adversaryId": "nexttime.ovh",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 5,
                    "description": "Malicious domain",
                    "firstContact": "2022-10-25T21:13:43.551Z",
                    "hasPlaybackContacts": false,
                    "id": "ef8ee900-54a9-11ed-9df2-6538d9561738",
                    "labelDistribution": {
                        "3635": 5
                    },
                    "lastContact": "2022-10-26T22:45:31.230Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-25T21:16:15.909Z",
                    "timestamp": "2022-10-25T21:13:56.368Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "pinkexcel.com"
                    ],
                    "adversaryId": "pinkexcel.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Sodinokibi",
                    "firstContact": "2022-09-15T14:33:58.544Z",
                    "hasPlaybackContacts": false,
                    "id": "ef8ef190-3503-11ed-9b90-a51546bb08b5",
                    "labelDistribution": {
                        "548": 1
                    },
                    "lastContact": "2022-09-15T14:33:58.544Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-25T20:38:58.664Z",
                    "timestamp": "2022-09-15T14:37:33.865Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ezstat.ru"
                    ],
                    "adversaryId": "ezstat.ru",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family Tr.Af.Fakealert.Html",
                    "firstContact": "2022-10-19T16:23:50.322Z",
                    "hasPlaybackContacts": false,
                    "id": "71f54180-4fca-11ed-9df2-6538d9561738",
                    "labelDistribution": {
                        "3077": 4
                    },
                    "lastContact": "2022-10-21T15:53:49.585Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-20T12:24:17.272Z",
                    "timestamp": "2022-10-19T16:24:03.224Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "fbbrrnheqexb.online",
                        "fulimvwfyjol.com",
                        "gklmwtupmnwx.com",
                        "grccwbqgltxo.com",
                        "mrsvxqjipgbq.biz"
                    ],
                    "adversaryId": "Malware family Tinba",
                    "adversaryTypes": [
                        "DGA"
                    ],
                    "contacts": 5,
                    "description": "Malware family Tinba",
                    "firstContact": "2022-10-18T15:10:08.512Z",
                    "hasPlaybackContacts": false,
                    "id": "784d16b0-4f1c-11ed-9df2-6538d9561738",
                    "labelDistribution": {
                        "1791": 5
                    },
                    "lastContact": "2022-10-18T15:10:08.512Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-18T20:15:42.917Z",
                    "timestamp": "2022-10-18T19:38:41.435Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "chitraprakashan.com"
                    ],
                    "adversaryId": "chitraprakashan.com",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 1,
                    "description": "Phishing domain",
                    "firstContact": "2022-09-16T20:24:54.669Z",
                    "hasPlaybackContacts": false,
                    "id": "b7585190-35fd-11ed-9b90-a51546bb08b5",
                    "labelDistribution": {
                        "548": 1
                    },
                    "lastContact": "2022-09-16T20:24:54.669Z",
                    "status": "muted",
                    "statusTimestamp": "2022-09-21T23:37:35.972Z",
                    "timestamp": "2022-09-16T20:25:33.737Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "23.227.202.142"
                    ],
                    "adversaryId": "23.227.202.142",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 2,
                    "description": "Malware family Agentemis",
                    "firstContact": "2022-09-07T15:22:02.529Z",
                    "hasPlaybackContacts": false,
                    "id": "f2084460-2ec0-11ed-9b90-a51546bb08b5",
                    "labelDistribution": {
                        "2280": 2
                    },
                    "lastContact": "2022-09-07T15:22:03.289Z",
                    "status": "muted",
                    "statusTimestamp": "2022-09-09T19:20:07.516Z",
                    "timestamp": "2022-09-07T15:22:54.758Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "video4you.com.hostinghood.com"
                    ],
                    "adversaryId": "video4you.com.hostinghood.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family VertexNet",
                    "firstContact": "2022-07-14T16:39:33.444Z",
                    "hasPlaybackContacts": false,
                    "id": "90e07b60-0393-11ed-80a5-f16f41289f2f",
                    "labelDistribution": {
                        "0": 1,
                        "1791": 1
                    },
                    "lastContact": "2022-07-15T19:14:27Z",
                    "status": "muted",
                    "statusTimestamp": "2022-08-08T15:50:00.228Z",
                    "timestamp": "2022-07-14T16:39:44.406Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "secure.runescape.com-oc.ru"
                    ],
                    "adversaryId": "secure.runescape.com-oc.ru",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 47,
                    "description": "Malicious domain",
                    "firstContact": "2022-07-07T06:47:29.452Z",
                    "hasPlaybackContacts": false,
                    "id": "dc758440-fdc0-11ec-80a5-f16f41289f2f",
                    "labelDistribution": {
                        "1651": 4,
                        "989": 43
                    },
                    "lastContact": "2022-12-05T16:03:05.328Z",
                    "status": "muted",
                    "statusTimestamp": "2022-07-07T20:15:16.997Z",
                    "timestamp": "2022-07-07T06:48:51.588Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.registrywizard.com"
                    ],
                    "adversaryId": "www.registrywizard.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Win32.Wc.Adwareadposhel",
                    "firstContact": "2022-07-04T15:27:43.917Z",
                    "hasPlaybackContacts": false,
                    "id": "ec3c46d0-fbad-11ec-bf30-1b7883f212a4",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-07-04T15:27:43.917Z",
                    "status": "muted",
                    "statusTimestamp": "2022-07-05T15:48:52.651Z",
                    "timestamp": "2022-07-04T15:28:15.293Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "cc-cc.usa.cc"
                    ],
                    "adversaryId": "cc-cc.usa.cc",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 5,
                    "description": "Disposable email host",
                    "firstContact": "2022-06-30T16:18:42.635Z",
                    "hasPlaybackContacts": false,
                    "id": "57ca5660-f890-11ec-bf30-1b7883f212a4",
                    "labelDistribution": {
                        "2267": 5
                    },
                    "lastContact": "2022-06-30T16:30:15.536Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-30T16:28:06.892Z",
                    "timestamp": "2022-06-30T16:18:57.350Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "email.cbes.net"
                    ],
                    "adversaryId": "email.cbes.net",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2022-06-28T22:49:59.229Z",
                    "hasPlaybackContacts": false,
                    "id": "b8fe8210-f734-11ec-ad9e-6f96a7a32f4d",
                    "labelDistribution": {
                        "2267": 2
                    },
                    "lastContact": "2022-06-30T16:18:44.373Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-30T09:08:24.362Z",
                    "timestamp": "2022-06-28T22:50:35.569Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "dma.in-ulm.de"
                    ],
                    "adversaryId": "dma.in-ulm.de",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2022-06-28T22:50:47.762Z",
                    "hasPlaybackContacts": false,
                    "id": "e04c7570-f734-11ec-ad9e-6f96a7a32f4d",
                    "labelDistribution": {
                        "2267": 2
                    },
                    "lastContact": "2022-06-30T16:18:43.901Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-29T21:18:22.197Z",
                    "timestamp": "2022-06-28T22:51:41.511Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "grupoexclusiva.cl"
                    ],
                    "adversaryId": "grupoexclusiva.cl",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 18,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-06-24T13:54:57Z",
                    "hasPlaybackContacts": false,
                    "id": "236ddf00-f3c6-11ec-ad9e-6f96a7a32f4d",
                    "labelDistribution": {
                        "2148": 1,
                        "989": 17
                    },
                    "lastContact": "2022-06-30T01:15:58.167Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-24T21:58:39.281Z",
                    "timestamp": "2022-06-24T14:01:26.512Z",
                    "totalEndpoints": 6,
                    "unread": false
                },
                {
                    "adversaries": [
                        "dnd5spells.rpgist.net"
                    ],
                    "adversaryId": "dnd5spells.rpgist.net",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 2,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-06-24T00:07:34.283Z",
                    "hasPlaybackContacts": false,
                    "id": "ac3e7e40-f351-11ec-ad9e-6f96a7a32f4d",
                    "labelDistribution": {
                        "989": 2
                    },
                    "lastContact": "2022-06-24T00:07:55.505Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-24T15:12:28.661Z",
                    "timestamp": "2022-06-24T00:07:44.932Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "smetafor.ru"
                    ],
                    "adversaryId": "smetafor.ru",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 6,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-06-22T22:12:46.158Z",
                    "hasPlaybackContacts": false,
                    "id": "785a8bc0-f278-11ec-bb85-650a89d8b1da",
                    "labelDistribution": {
                        "989": 6
                    },
                    "lastContact": "2022-06-22T22:20:59.876Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-23T09:53:14.529Z",
                    "timestamp": "2022-06-22T22:12:57.084Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "subw.ru"
                    ],
                    "adversaryId": "subw.ru",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-06-21T18:33:25Z",
                    "hasPlaybackContacts": false,
                    "id": "c080a110-f191-11ec-bb85-650a89d8b1da",
                    "labelDistribution": {
                        "2148": 1
                    },
                    "lastContact": "2022-06-21T18:33:25Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-22T22:55:51.151Z",
                    "timestamp": "2022-06-21T18:41:24.385Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.globalpatron.com"
                    ],
                    "adversaryId": "www.globalpatron.com",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 21,
                    "description": "Phishing domain",
                    "firstContact": "2022-06-15T21:06:21Z",
                    "hasPlaybackContacts": false,
                    "id": "31cfbec0-ecef-11ec-bb85-650a89d8b1da",
                    "labelDistribution": {
                        "1189": 3,
                        "1580": 2,
                        "989": 16
                    },
                    "lastContact": "2022-08-01T19:13:09Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-16T19:38:45.965Z",
                    "timestamp": "2022-06-15T21:07:41.868Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "minergate.com"
                    ],
                    "adversaryId": "minergate.com",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 8,
                    "description": "Malware related",
                    "firstContact": "2022-06-08T21:42:24Z",
                    "hasPlaybackContacts": false,
                    "id": "eaed0560-e773-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "1681": 8
                    },
                    "lastContact": "2022-06-08T21:43:18Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-08T23:05:21.185Z",
                    "timestamp": "2022-06-08T21:42:39.030Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ru.minergate.com"
                    ],
                    "adversaryId": "ru.minergate.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malicious domain",
                    "firstContact": "2022-06-08T21:45:52Z",
                    "hasPlaybackContacts": false,
                    "id": "67e92d00-e774-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "1681": 4
                    },
                    "lastContact": "2022-06-08T21:45:52Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-08T22:45:30.098Z",
                    "timestamp": "2022-06-08T21:46:08.720Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.wersage.bugs3.com"
                    ],
                    "adversaryId": "www.wersage.bugs3.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family Stealer",
                    "firstContact": "2022-06-08T17:57:32Z",
                    "hasPlaybackContacts": false,
                    "id": "780bb680-e756-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "1885": 2
                    },
                    "lastContact": "2022-06-08T17:57:32Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-08T21:13:03.626Z",
                    "timestamp": "2022-06-08T18:11:50.888Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "fundacionalianzas.com"
                    ],
                    "adversaryId": "fundacionalianzas.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-06-08T12:52:40Z",
                    "hasPlaybackContacts": false,
                    "id": "1dc013e0-e72b-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "2148": 1
                    },
                    "lastContact": "2022-06-08T12:52:40Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-08T15:08:27.370Z",
                    "timestamp": "2022-06-08T13:01:31.038Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "dominj.ru"
                    ],
                    "adversaryId": "dominj.ru",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-06-07T01:19:27Z",
                    "hasPlaybackContacts": false,
                    "id": "b614aec0-e600-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "2148": 1
                    },
                    "lastContact": "2022-06-07T01:19:27Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-08T09:13:02.725Z",
                    "timestamp": "2022-06-07T01:25:27.084Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.13stamps.com"
                    ],
                    "adversaryId": "www.13stamps.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-06-04T20:47:36Z",
                    "hasPlaybackContacts": false,
                    "id": "bec14c40-e448-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "2148": 1
                    },
                    "lastContact": "2022-06-04T20:47:36Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-06T20:39:00.854Z",
                    "timestamp": "2022-06-04T20:56:03.076Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "trk.klclick3.com"
                    ],
                    "adversaryId": "trk.klclick3.com",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 6,
                    "description": "Phishing domain",
                    "firstContact": "2022-06-03T21:02:12.317Z",
                    "hasPlaybackContacts": false,
                    "id": "777e07b0-e380-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "147": 1,
                        "2144": 3,
                        "989": 2
                    },
                    "lastContact": "2022-06-09T15:05:59.984Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-03T22:30:12.767Z",
                    "timestamp": "2022-06-03T21:02:24.171Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "privedmidved.net"
                    ],
                    "adversaryId": "privedmidved.net",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family WebInject",
                    "firstContact": "2022-06-03T21:01:47Z",
                    "hasPlaybackContacts": false,
                    "id": "5c068eb0-e382-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "1885": 1
                    },
                    "lastContact": "2022-06-03T21:01:47Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-03T22:00:37.147Z",
                    "timestamp": "2022-06-03T21:15:57.083Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.zhong-ix.com"
                    ],
                    "adversaryId": "www.zhong-ix.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family P2PZeuS",
                    "firstContact": "2022-06-03T21:00:56.760Z",
                    "hasPlaybackContacts": false,
                    "id": "793fdbf0-e380-11ec-b7a5-9ded001a2220",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-06-03T21:00:56.760Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-03T21:58:48.985Z",
                    "timestamp": "2022-06-03T21:02:27.119Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "icce.cl"
                    ],
                    "adversaryId": "icce.cl",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family Backdoor",
                    "firstContact": "2022-05-23T13:45:10.784Z",
                    "hasPlaybackContacts": false,
                    "id": "9867a520-da9e-11ec-af21-1383d6a11730",
                    "labelDistribution": {
                        "147": 1,
                        "218": 1
                    },
                    "lastContact": "2022-05-25T16:19:45.246Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-02T22:54:39.424Z",
                    "timestamp": "2022-05-23T13:45:23.826Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "herp.in"
                    ],
                    "adversaryId": "herp.in",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 8,
                    "description": "Disposable email host",
                    "firstContact": "2022-05-24T15:16:38.125Z",
                    "hasPlaybackContacts": false,
                    "id": "9cfe17f0-db74-11ec-af21-1383d6a11730",
                    "labelDistribution": {
                        "218": 1,
                        "2267": 5,
                        "2692": 2
                    },
                    "lastContact": "2022-12-19T22:38:10.956Z",
                    "status": "muted",
                    "statusTimestamp": "2022-06-01T23:55:09.793Z",
                    "timestamp": "2022-05-24T15:17:23.823Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "backgrounds.pk"
                    ],
                    "adversaryId": "backgrounds.pk",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 20,
                    "description": "RaccoonStealer",
                    "hasPlaybackContacts": false,
                    "id": "ca4ebe00-aa26-11ec-af58-8da2705ed08a",
                    "labelDistribution": {
                        "0": 2,
                        "864": 18
                    },
                    "lastContact": "2022-10-19T15:07:40.899Z",
                    "status": "muted",
                    "statusTimestamp": "2022-03-22T21:28:05.171Z",
                    "timestamp": "2022-03-22T21:26:52.128Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "0x21.in"
                    ],
                    "adversaryId": "0x21.in",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 14,
                    "description": "QuasarRAT",
                    "hasPlaybackContacts": false,
                    "id": "983d5c00-aa26-11ec-af58-8da2705ed08a",
                    "labelDistribution": {
                        "864": 14
                    },
                    "lastContact": "2022-03-22T21:27:49.692Z",
                    "status": "muted",
                    "statusTimestamp": "2022-03-22T21:27:38.469Z",
                    "timestamp": "2022-03-22T21:25:28.128Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "mimbc.net"
                    ],
                    "adversaryId": "mimbc.net",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 28,
                    "description": "Malware family P2PZeuS",
                    "firstContact": "2022-07-04T04:06:02.042Z",
                    "hasPlaybackContacts": false,
                    "id": "7ab62700-a4b0-11ec-af58-8da2705ed08a",
                    "labelDistribution": {
                        "1885": 2,
                        "2254": 24,
                        "864": 1,
                        "989": 1
                    },
                    "lastContact": "2023-01-03T23:31:45.292Z",
                    "status": "muted",
                    "statusTimestamp": "2022-03-15T22:54:40.924Z",
                    "timestamp": "2022-03-15T22:37:22.160Z",
                    "totalEndpoints": 7,
                    "unread": false
                },
                {
                    "adversaries": [
                        "asapcallcenter.net"
                    ],
                    "adversaryId": "asapcallcenter.net",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 5,
                    "description": "Malware family KINS",
                    "hasPlaybackContacts": false,
                    "id": "2720e2a0-a0c9-11ec-af58-8da2705ed08a",
                    "labelDistribution": {
                        "1651": 3,
                        "548": 1,
                        "864": 1
                    },
                    "lastContact": "2022-07-09T15:53:55.423Z",
                    "status": "muted",
                    "statusTimestamp": "2022-03-10T23:59:14.933Z",
                    "timestamp": "2022-03-10T23:23:54.698Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "queenshippartners.com"
                    ],
                    "adversaryId": "queenshippartners.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family P2PZeuS",
                    "hasPlaybackContacts": false,
                    "id": "17220c70-9fe4-11ec-b69e-2d8391d9c9ca",
                    "labelDistribution": {
                        "1885": 1
                    },
                    "lastContact": "2022-03-09T19:52:48Z",
                    "status": "muted",
                    "statusTimestamp": "2022-03-10T05:28:53.416Z",
                    "timestamp": "2022-03-09T20:04:13.111Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "freelancergyn.com.br"
                    ],
                    "adversaryId": "freelancergyn.com.br",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 1,
                    "description": "Malware family P2PZeuS",
                    "hasPlaybackContacts": false,
                    "id": "e78a1410-9fd1-11ec-b69e-2d8391d9c9ca",
                    "labelDistribution": {
                        "1885": 1
                    },
                    "lastContact": "2022-03-09T17:39:06Z",
                    "status": "muted",
                    "statusTimestamp": "2022-03-09T19:00:15.293Z",
                    "timestamp": "2022-03-09T17:54:02.321Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "saecargomaritime.com"
                    ],
                    "adversaryId": "saecargomaritime.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Fareit",
                    "hasPlaybackContacts": false,
                    "id": "582f8cf0-9ea0-11ec-b69e-2d8391d9c9ca",
                    "labelDistribution": {
                        "218": 1
                    },
                    "lastContact": "2022-03-07T14:37:02.228Z",
                    "status": "muted",
                    "statusTimestamp": "2022-03-08T20:29:54.248Z",
                    "timestamp": "2022-03-08T05:26:45.311Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "domain2222.com"
                    ],
                    "adversaryId": "domain2222.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 36,
                    "description": "Malware family TaurusStealer",
                    "hasPlaybackContacts": false,
                    "id": "d39f4230-7a43-11ec-843d-dd7e2ea288b6",
                    "labelDistribution": {
                        "0": 2,
                        "1851": 13,
                        "1885": 20,
                        "280": 1
                    },
                    "lastContact": "2022-01-27T16:10:09Z",
                    "status": "muted",
                    "statusTimestamp": "2022-02-08T20:40:31.481Z",
                    "timestamp": "2022-01-20T22:53:47.347Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.credi-familialtda.com"
                    ],
                    "adversaryId": "www.credi-familialtda.com",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 1,
                    "description": "Phishing domain",
                    "hasPlaybackContacts": false,
                    "id": "64ea9a30-796f-11ec-843d-dd7e2ea288b6",
                    "labelDistribution": {
                        "864": 1
                    },
                    "lastContact": "2022-01-19T21:32:55.282Z",
                    "status": "muted",
                    "statusTimestamp": "2022-01-24T14:21:11.017Z",
                    "timestamp": "2022-01-19T21:33:08.307Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "saner.com.au"
                    ],
                    "adversaryId": "saner.com.au",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 7,
                    "description": "Malware family P2PZeuS",
                    "hasPlaybackContacts": false,
                    "id": "e37738d0-7b0f-11ec-b95a-431da32564f1",
                    "labelDistribution": {
                        "1851": 1,
                        "1885": 1,
                        "1988": 1,
                        "218": 4
                    },
                    "lastContact": "2022-03-07T21:21:01Z",
                    "status": "muted",
                    "statusTimestamp": "2022-01-21T23:18:45.525Z",
                    "timestamp": "2022-01-21T23:14:31.261Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "tempmail.co"
                    ],
                    "adversaryId": "tempmail.co",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1953,
                    "description": "Disposable email host",
                    "firstContact": "2022-01-05T22:58:12.900Z",
                    "hasPlaybackContacts": false,
                    "id": "e727df00-6e7d-11ec-a2fc-7f6e039c5267",
                    "labelDistribution": {
                        "864": 1,
                        "989": 1952
                    },
                    "lastContact": "2022-06-24T14:17:43.651Z",
                    "status": "muted",
                    "statusTimestamp": "2022-01-06T15:13:22.379Z",
                    "timestamp": "2022-01-05T23:19:16.976Z",
                    "totalEndpoints": 2,
                    "unread": false
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-01-26T23:17:27.349Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|timestamp|
>|---|---|---|
>| {'id': 'd9bd1450-9dcc-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T22:57:47.029Z', 'statusTimestamp': '2023-01-26T23:00:36.915Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '945eb000-937a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-13T19:43:40.288Z', 'statusTimestamp': '2023-01-26T22:55:53.366Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['mediaworld.pro'], 'adversaryId': 'mediaworld.pro', 'adversaryTypes': ['Malware'], 'description': 'Malware family Spam.Pdf', 'labelDistribution': {'1580': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-13T19:43:16.549Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-13T19:43:16.549Z'},<br/>{'id': '721ed640-82d2-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-23T14:59:48.772Z', 'statusTimestamp': '2022-12-27T02:39:14.360Z', 'status': 'muted', 'contacts': 11, 'adversaries': ['12finance.com'], 'adversaryId': '12finance.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1, '2254': 10}, 'totalEndpoints': 4, 'lastContact': '2022-12-23T22:30:10.448Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-23T14:46:54Z'},<br/>{'id': 'ab056a80-7a73-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T23:21:12.744Z', 'statusTimestamp': '2022-12-15T20:59:51.796Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['www.digeus.com'], 'adversaryId': 'www.digeus.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Application.Deceptor.ANL', 'labelDistribution': {'147': 1, '218': 1}, 'totalEndpoints': 2, 'lastContact': '2022-12-22T20:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-12T23:20:56.706Z'},<br/>{'id': 'f06a50c0-69e5-11ed-89c2-6136df938368', 'timestamp': '2022-11-21T21:46:22.028Z', 'statusTimestamp': '2022-12-13T20:48:09.825Z', 'status': 'muted', 'contacts': 8, 'adversaries': ['jameshallybone.co.uk'], 'adversaryId': 'jameshallybone.co.uk', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'989': 6, '1651': 1, '3811': 1}, 'totalEndpoints': 3, 'lastContact': '2022-12-05T16:03:05.322Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-11-21T21:46:01.425Z'},<br/>{'id': '8b6f8c70-7a71-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T23:06:00.759Z', 'statusTimestamp': '2022-12-12T23:21:43.833Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['3.223.53.1'], 'adversaryId': '3.223.53.1', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'218': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-12T17:09:20.331Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-12T17:09:20.331Z'},<br/>{'id': '149207b0-6471-11ed-b373-192ba321fedf', 'timestamp': '2022-11-14T23:07:15.755Z', 'statusTimestamp': '2022-11-17T18:56:09.751Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['coovigomez.com'], 'adversaryId': 'coovigomez.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1}, 'totalEndpoints': 1, 'lastContact': '2022-11-12T23:31:33Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-11-12T23:31:33Z'},<br/>{'id': '47bbc6c0-56f8-11ed-987a-cd6f8ff058b8', 'timestamp': '2022-10-28T19:39:47.372Z', 'statusTimestamp': '2022-10-31T21:51:02.594Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['barbombon.com.'], 'adversaryId': 'barbombon.com.', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Script.Generic', 'labelDistribution': {'1651': 2}, 'totalEndpoints': 1, 'lastContact': '2022-10-28T19:44:10.172Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-28T19:39:13.452Z'},<br/>{'id': '11c5a410-41fd-11ed-8751-63984e51f242', 'timestamp': '2022-10-02T02:51:09.905Z', 'statusTimestamp': '2022-10-28T17:06:32.994Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['coasttickets.com'], 'adversaryId': 'coasttickets.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Downloader.Psdownload.MSIL.Generic', 'labelDistribution': {'548': 1}, 'totalEndpoints': 1, 'lastContact': '2022-09-22T15:19:42.152Z', 'unread': False, 'hasPlaybackContacts': True, 'firstContact': '2022-09-22T15:19:42.152Z'},<br/>{'id': '8da63fc0-5618-11ed-987a-cd6f8ff058b8', 'timestamp': '2022-10-27T16:58:17.404Z', 'statusTimestamp': '2022-10-27T17:57:57.931Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['dark-utilities.pw'], 'adversaryId': 'dark-utilities.pw', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1, '2267': 1}, 'totalEndpoints': 2, 'lastContact': '2022-10-27T17:12:45.099Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-27T16:47:40Z'},<br/>{'id': '046a19c0-54a6-11ed-9df2-6538d9561738', 'timestamp': '2022-10-25T20:45:53.372Z', 'statusTimestamp': '2022-10-25T21:17:21.376Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['www.com-about.com'], 'adversaryId': 'www.com-about.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Downloader.Riskware.A.Atoz', 'labelDistribution': {'3635': 1}, 'totalEndpoints': 1, 'lastContact': '2022-10-25T20:45:41.154Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-25T20:45:41.154Z'},<br/>{'id': 'ef8ee900-54a9-11ed-9df2-6538d9561738', 'timestamp': '2022-10-25T21:13:56.368Z', 'statusTimestamp': '2022-10-25T21:16:15.909Z', 'status': 'muted', 'contacts': 5, 'adversaries': ['nexttime.ovh'], 'adversaryId': 'nexttime.ovh', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'3635': 5}, 'totalEndpoints': 1, 'lastContact': '2022-10-26T22:45:31.230Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-25T21:13:43.551Z'},<br/>{'id': 'ef8ef190-3503-11ed-9b90-a51546bb08b5', 'timestamp': '2022-09-15T14:37:33.865Z', 'statusTimestamp': '2022-10-25T20:38:58.664Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['pinkexcel.com'], 'adversaryId': 'pinkexcel.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family Sodinokibi', 'labelDistribution': {'548': 1}, 'totalEndpoints': 1, 'lastContact': '2022-09-15T14:33:58.544Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-09-15T14:33:58.544Z'},<br/>{'id': '71f54180-4fca-11ed-9df2-6538d9561738', 'timestamp': '2022-10-19T16:24:03.224Z', 'statusTimestamp': '2022-10-20T12:24:17.272Z', 'status': 'muted', 'contacts': 4, 'adversaries': ['ezstat.ru'], 'adversaryId': 'ezstat.ru', 'adversaryTypes': ['Malware'], 'description': 'Malware family Tr.Af.Fakealert.Html', 'labelDistribution': {'3077': 4}, 'totalEndpoints': 1, 'lastContact': '2022-10-21T15:53:49.585Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-19T16:23:50.322Z'},<br/>{'id': '784d16b0-4f1c-11ed-9df2-6538d9561738', 'timestamp': '2022-10-18T19:38:41.435Z', 'statusTimestamp': '2022-10-18T20:15:42.917Z', 'status': 'muted', 'contacts': 5, 'adversaries': ['fbbrrnheqexb.online', 'fulimvwfyjol.com', 'gklmwtupmnwx.com', 'grccwbqgltxo.com', 'mrsvxqjipgbq.biz'], 'adversaryId': 'Malware family Tinba', 'adversaryTypes': ['DGA'], 'description': 'Malware family Tinba', 'labelDistribution': {'1791': 5}, 'totalEndpoints': 1, 'lastContact': '2022-10-18T15:10:08.512Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-18T15:10:08.512Z'},<br/>{'id': 'b7585190-35fd-11ed-9b90-a51546bb08b5', 'timestamp': '2022-09-16T20:25:33.737Z', 'statusTimestamp': '2022-09-21T23:37:35.972Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['chitraprakashan.com'], 'adversaryId': 'chitraprakashan.com', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'548': 1}, 'totalEndpoints': 1, 'lastContact': '2022-09-16T20:24:54.669Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-09-16T20:24:54.669Z'},<br/>{'id': 'f2084460-2ec0-11ed-9b90-a51546bb08b5', 'timestamp': '2022-09-07T15:22:54.758Z', 'statusTimestamp': '2022-09-09T19:20:07.516Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['23.227.202.142'], 'adversaryId': '23.227.202.142', 'adversaryTypes': ['C2C'], 'description': 'Malware family Agentemis', 'labelDistribution': {'2280': 2}, 'totalEndpoints': 1, 'lastContact': '2022-09-07T15:22:03.289Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-09-07T15:22:02.529Z'},<br/>{'id': '90e07b60-0393-11ed-80a5-f16f41289f2f', 'timestamp': '2022-07-14T16:39:44.406Z', 'statusTimestamp': '2022-08-08T15:50:00.228Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['video4you.com.hostinghood.com'], 'adversaryId': 'video4you.com.hostinghood.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family VertexNet', 'labelDistribution': {'1791': 1, '0': 1}, 'totalEndpoints': 2, 'lastContact': '2022-07-15T19:14:27Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-07-14T16:39:33.444Z'},<br/>{'id': 'dc758440-fdc0-11ec-80a5-f16f41289f2f', 'timestamp': '2022-07-07T06:48:51.588Z', 'statusTimestamp': '2022-07-07T20:15:16.997Z', 'status': 'muted', 'contacts': 47, 'adversaries': ['secure.runescape.com-oc.ru'], 'adversaryId': 'secure.runescape.com-oc.ru', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'1651': 4, '989': 43}, 'totalEndpoints': 2, 'lastContact': '2022-12-05T16:03:05.328Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-07-07T06:47:29.452Z'},<br/>{'id': 'ec3c46d0-fbad-11ec-bf30-1b7883f212a4', 'timestamp': '2022-07-04T15:28:15.293Z', 'statusTimestamp': '2022-07-05T15:48:52.651Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['www.registrywizard.com'], 'adversaryId': 'www.registrywizard.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Win32.Wc.Adwareadposhel', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-07-04T15:27:43.917Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-07-04T15:27:43.917Z'},<br/>{'id': '57ca5660-f890-11ec-bf30-1b7883f212a4', 'timestamp': '2022-06-30T16:18:57.350Z', 'statusTimestamp': '2022-06-30T16:28:06.892Z', 'status': 'muted', 'contacts': 5, 'adversaries': ['cc-cc.usa.cc'], 'adversaryId': 'cc-cc.usa.cc', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2267': 5}, 'totalEndpoints': 1, 'lastContact': '2022-06-30T16:30:15.536Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-30T16:18:42.635Z'},<br/>{'id': 'b8fe8210-f734-11ec-ad9e-6f96a7a32f4d', 'timestamp': '2022-06-28T22:50:35.569Z', 'statusTimestamp': '2022-06-30T09:08:24.362Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['email.cbes.net'], 'adversaryId': 'email.cbes.net', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2267': 2}, 'totalEndpoints': 1, 'lastContact': '2022-06-30T16:18:44.373Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-28T22:49:59.229Z'},<br/>{'id': 'e04c7570-f734-11ec-ad9e-6f96a7a32f4d', 'timestamp': '2022-06-28T22:51:41.511Z', 'statusTimestamp': '2022-06-29T21:18:22.197Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['dma.in-ulm.de'], 'adversaryId': 'dma.in-ulm.de', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2267': 2}, 'totalEndpoints': 1, 'lastContact': '2022-06-30T16:18:43.901Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-28T22:50:47.762Z'},<br/>{'id': '236ddf00-f3c6-11ec-ad9e-6f96a7a32f4d', 'timestamp': '2022-06-24T14:01:26.512Z', 'statusTimestamp': '2022-06-24T21:58:39.281Z', 'status': 'muted', 'contacts': 18, 'adversaries': ['grupoexclusiva.cl'], 'adversaryId': 'grupoexclusiva.cl', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1, '989': 17}, 'totalEndpoints': 6, 'lastContact': '2022-06-30T01:15:58.167Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-24T13:54:57Z'},<br/>{'id': 'ac3e7e40-f351-11ec-ad9e-6f96a7a32f4d', 'timestamp': '2022-06-24T00:07:44.932Z', 'statusTimestamp': '2022-06-24T15:12:28.661Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['dnd5spells.rpgist.net'], 'adversaryId': 'dnd5spells.rpgist.net', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'989': 2}, 'totalEndpoints': 1, 'lastContact': '2022-06-24T00:07:55.505Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-24T00:07:34.283Z'},<br/>{'id': '785a8bc0-f278-11ec-bb85-650a89d8b1da', 'timestamp': '2022-06-22T22:12:57.084Z', 'statusTimestamp': '2022-06-23T09:53:14.529Z', 'status': 'muted', 'contacts': 6, 'adversaries': ['smetafor.ru'], 'adversaryId': 'smetafor.ru', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'989': 6}, 'totalEndpoints': 1, 'lastContact': '2022-06-22T22:20:59.876Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-22T22:12:46.158Z'},<br/>{'id': 'c080a110-f191-11ec-bb85-650a89d8b1da', 'timestamp': '2022-06-21T18:41:24.385Z', 'statusTimestamp': '2022-06-22T22:55:51.151Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['subw.ru'], 'adversaryId': 'subw.ru', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1}, 'totalEndpoints': 1, 'lastContact': '2022-06-21T18:33:25Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-21T18:33:25Z'},<br/>{'id': '31cfbec0-ecef-11ec-bb85-650a89d8b1da', 'timestamp': '2022-06-15T21:07:41.868Z', 'statusTimestamp': '2022-06-16T19:38:45.965Z', 'status': 'muted', 'contacts': 21, 'adversaries': ['www.globalpatron.com'], 'adversaryId': 'www.globalpatron.com', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'1189': 3, '1580': 2, '989': 16}, 'totalEndpoints': 5, 'lastContact': '2022-08-01T19:13:09Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-15T21:06:21Z'},<br/>{'id': 'eaed0560-e773-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-08T21:42:39.030Z', 'statusTimestamp': '2022-06-08T23:05:21.185Z', 'status': 'muted', 'contacts': 8, 'adversaries': ['minergate.com'], 'adversaryId': 'minergate.com', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malware related', 'labelDistribution': {'1681': 8}, 'totalEndpoints': 1, 'lastContact': '2022-06-08T21:43:18Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-08T21:42:24Z'},<br/>{'id': '67e92d00-e774-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-08T21:46:08.720Z', 'statusTimestamp': '2022-06-08T22:45:30.098Z', 'status': 'muted', 'contacts': 4, 'adversaries': ['ru.minergate.com'], 'adversaryId': 'ru.minergate.com', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'1681': 4}, 'totalEndpoints': 1, 'lastContact': '2022-06-08T21:45:52Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-08T21:45:52Z'},<br/>{'id': '780bb680-e756-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-08T18:11:50.888Z', 'statusTimestamp': '2022-06-08T21:13:03.626Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['www.wersage.bugs3.com'], 'adversaryId': 'www.wersage.bugs3.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family Stealer', 'labelDistribution': {'1885': 2}, 'totalEndpoints': 1, 'lastContact': '2022-06-08T17:57:32Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-08T17:57:32Z'},<br/>{'id': '1dc013e0-e72b-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-08T13:01:31.038Z', 'statusTimestamp': '2022-06-08T15:08:27.370Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['fundacionalianzas.com'], 'adversaryId': 'fundacionalianzas.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1}, 'totalEndpoints': 1, 'lastContact': '2022-06-08T12:52:40Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-08T12:52:40Z'},<br/>{'id': 'b614aec0-e600-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-07T01:25:27.084Z', 'statusTimestamp': '2022-06-08T09:13:02.725Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['dominj.ru'], 'adversaryId': 'dominj.ru', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1}, 'totalEndpoints': 1, 'lastContact': '2022-06-07T01:19:27Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-07T01:19:27Z'},<br/>{'id': 'bec14c40-e448-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-04T20:56:03.076Z', 'statusTimestamp': '2022-06-06T20:39:00.854Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['www.13stamps.com'], 'adversaryId': 'www.13stamps.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1}, 'totalEndpoints': 1, 'lastContact': '2022-06-04T20:47:36Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-04T20:47:36Z'},<br/>{'id': '777e07b0-e380-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-03T21:02:24.171Z', 'statusTimestamp': '2022-06-03T22:30:12.767Z', 'status': 'muted', 'contacts': 6, 'adversaries': ['trk.klclick3.com'], 'adversaryId': 'trk.klclick3.com', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'989': 2, '2144': 3, '147': 1}, 'totalEndpoints': 4, 'lastContact': '2022-06-09T15:05:59.984Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-03T21:02:12.317Z'},<br/>{'id': '5c068eb0-e382-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-03T21:15:57.083Z', 'statusTimestamp': '2022-06-03T22:00:37.147Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['privedmidved.net'], 'adversaryId': 'privedmidved.net', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family WebInject', 'labelDistribution': {'1885': 1}, 'totalEndpoints': 1, 'lastContact': '2022-06-03T21:01:47Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-03T21:01:47Z'},<br/>{'id': '793fdbf0-e380-11ec-b7a5-9ded001a2220', 'timestamp': '2022-06-03T21:02:27.119Z', 'statusTimestamp': '2022-06-03T21:58:48.985Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['www.zhong-ix.com'], 'adversaryId': 'www.zhong-ix.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-06-03T21:00:56.760Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-06-03T21:00:56.760Z'},<br/>{'id': '9867a520-da9e-11ec-af21-1383d6a11730', 'timestamp': '2022-05-23T13:45:23.826Z', 'statusTimestamp': '2022-06-02T22:54:39.424Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['icce.cl'], 'adversaryId': 'icce.cl', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family Backdoor', 'labelDistribution': {'147': 1, '218': 1}, 'totalEndpoints': 2, 'lastContact': '2022-05-25T16:19:45.246Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-05-23T13:45:10.784Z'},<br/>{'id': '9cfe17f0-db74-11ec-af21-1383d6a11730', 'timestamp': '2022-05-24T15:17:23.823Z', 'statusTimestamp': '2022-06-01T23:55:09.793Z', 'status': 'muted', 'contacts': 8, 'adversaries': ['herp.in'], 'adversaryId': 'herp.in', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'2267': 5, '218': 1, '2692': 2}, 'totalEndpoints': 5, 'lastContact': '2022-12-19T22:38:10.956Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-05-24T15:16:38.125Z'},<br/>{'id': 'ca4ebe00-aa26-11ec-af58-8da2705ed08a', 'timestamp': '2022-03-22T21:26:52.128Z', 'statusTimestamp': '2022-03-22T21:28:05.171Z', 'status': 'muted', 'contacts': 20, 'adversaries': ['backgrounds.pk'], 'adversaryId': 'backgrounds.pk', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'RaccoonStealer', 'labelDistribution': {'864': 18, '0': 2}, 'totalEndpoints': 2, 'lastContact': '2022-10-19T15:07:40.899Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': '983d5c00-aa26-11ec-af58-8da2705ed08a', 'timestamp': '2022-03-22T21:25:28.128Z', 'statusTimestamp': '2022-03-22T21:27:38.469Z', 'status': 'muted', 'contacts': 14, 'adversaries': ['0x21.in'], 'adversaryId': '0x21.in', 'adversaryTypes': ['C2C'], 'description': 'QuasarRAT', 'labelDistribution': {'864': 14}, 'totalEndpoints': 1, 'lastContact': '2022-03-22T21:27:49.692Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': '7ab62700-a4b0-11ec-af58-8da2705ed08a', 'timestamp': '2022-03-15T22:37:22.160Z', 'statusTimestamp': '2022-03-15T22:54:40.924Z', 'status': 'muted', 'contacts': 28, 'adversaries': ['mimbc.net'], 'adversaryId': 'mimbc.net', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'864': 1, '1885': 2, '2254': 24, '989': 1}, 'totalEndpoints': 7, 'lastContact': '2023-01-03T23:31:45.292Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-07-04T04:06:02.042Z'},<br/>{'id': '2720e2a0-a0c9-11ec-af58-8da2705ed08a', 'timestamp': '2022-03-10T23:23:54.698Z', 'statusTimestamp': '2022-03-10T23:59:14.933Z', 'status': 'muted', 'contacts': 5, 'adversaries': ['asapcallcenter.net'], 'adversaryId': 'asapcallcenter.net', 'adversaryTypes': ['C2C'], 'description': 'Malware family KINS', 'labelDistribution': {'864': 1, '1651': 3, '548': 1}, 'totalEndpoints': 3, 'lastContact': '2022-07-09T15:53:55.423Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': '17220c70-9fe4-11ec-b69e-2d8391d9c9ca', 'timestamp': '2022-03-09T20:04:13.111Z', 'statusTimestamp': '2022-03-10T05:28:53.416Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['queenshippartners.com'], 'adversaryId': 'queenshippartners.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'1885': 1}, 'totalEndpoints': 1, 'lastContact': '2022-03-09T19:52:48Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': 'e78a1410-9fd1-11ec-b69e-2d8391d9c9ca', 'timestamp': '2022-03-09T17:54:02.321Z', 'statusTimestamp': '2022-03-09T19:00:15.293Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['freelancergyn.com.br'], 'adversaryId': 'freelancergyn.com.br', 'adversaryTypes': ['C2C'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'1885': 1}, 'totalEndpoints': 1, 'lastContact': '2022-03-09T17:39:06Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': '582f8cf0-9ea0-11ec-b69e-2d8391d9c9ca', 'timestamp': '2022-03-08T05:26:45.311Z', 'statusTimestamp': '2022-03-08T20:29:54.248Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['saecargomaritime.com'], 'adversaryId': 'saecargomaritime.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family Fareit', 'labelDistribution': {'218': 1}, 'totalEndpoints': 1, 'lastContact': '2022-03-07T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': 'd39f4230-7a43-11ec-843d-dd7e2ea288b6', 'timestamp': '2022-01-20T22:53:47.347Z', 'statusTimestamp': '2022-02-08T20:40:31.481Z', 'status': 'muted', 'contacts': 36, 'adversaries': ['domain2222.com'], 'adversaryId': 'domain2222.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family TaurusStealer', 'labelDistribution': {'280': 1, '0': 2, '1885': 20, '1851': 13}, 'totalEndpoints': 3, 'lastContact': '2022-01-27T16:10:09Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': '64ea9a30-796f-11ec-843d-dd7e2ea288b6', 'timestamp': '2022-01-19T21:33:08.307Z', 'statusTimestamp': '2022-01-24T14:21:11.017Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['www.credi-familialtda.com'], 'adversaryId': 'www.credi-familialtda.com', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'864': 1}, 'totalEndpoints': 1, 'lastContact': '2022-01-19T21:32:55.282Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': 'e37738d0-7b0f-11ec-b95a-431da32564f1', 'timestamp': '2022-01-21T23:14:31.261Z', 'statusTimestamp': '2022-01-21T23:18:45.525Z', 'status': 'muted', 'contacts': 7, 'adversaries': ['saner.com.au'], 'adversaryId': 'saner.com.au', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'218': 4, '1885': 1, '1988': 1, '1851': 1}, 'totalEndpoints': 2, 'lastContact': '2022-03-07T21:21:01Z', 'unread': False, 'hasPlaybackContacts': False},<br/>{'id': 'e727df00-6e7d-11ec-a2fc-7f6e039c5267', 'timestamp': '2022-01-05T23:19:16.976Z', 'statusTimestamp': '2022-01-06T15:13:22.379Z', 'status': 'muted', 'contacts': 1953, 'adversaries': ['tempmail.co'], 'adversaryId': 'tempmail.co', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'989': 1952, '864': 1}, 'totalEndpoints': 2, 'lastContact': '2022-06-24T14:17:43.651Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-01-05T22:58:12.900Z'} | page: 1<br/>items: 50<br/>next: 2 | 2023-01-26T23:17:27.349Z |


#### Command example
```!lumu-retrieve-muted-incidents labels=1651 adversary-types=Malware```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveMutedIncidents": {
            "items": [
                {
                    "adversaries": [
                        "jameshallybone.co.uk"
                    ],
                    "adversaryId": "jameshallybone.co.uk",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 8,
                    "description": "Malicious domain",
                    "firstContact": "2022-11-21T21:46:01.425Z",
                    "hasPlaybackContacts": false,
                    "id": "f06a50c0-69e5-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "1651": 1,
                        "3811": 1,
                        "989": 6
                    },
                    "lastContact": "2022-12-05T16:03:05.322Z",
                    "status": "muted",
                    "statusTimestamp": "2022-12-13T20:48:09.825Z",
                    "timestamp": "2022-11-21T21:46:22.028Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "barbombon.com."
                    ],
                    "adversaryId": "barbombon.com.",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family Trojan.Script.Generic",
                    "firstContact": "2022-10-28T19:39:13.452Z",
                    "hasPlaybackContacts": false,
                    "id": "47bbc6c0-56f8-11ed-987a-cd6f8ff058b8",
                    "labelDistribution": {
                        "1651": 2
                    },
                    "lastContact": "2022-10-28T19:44:10.172Z",
                    "status": "muted",
                    "statusTimestamp": "2022-10-31T21:51:02.594Z",
                    "timestamp": "2022-10-28T19:39:47.372Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "secure.runescape.com-oc.ru"
                    ],
                    "adversaryId": "secure.runescape.com-oc.ru",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 47,
                    "description": "Malicious domain",
                    "firstContact": "2022-07-07T06:47:29.452Z",
                    "hasPlaybackContacts": false,
                    "id": "dc758440-fdc0-11ec-80a5-f16f41289f2f",
                    "labelDistribution": {
                        "1651": 4,
                        "989": 43
                    },
                    "lastContact": "2022-12-05T16:03:05.328Z",
                    "status": "muted",
                    "statusTimestamp": "2022-07-07T20:15:16.997Z",
                    "timestamp": "2022-07-07T06:48:51.588Z",
                    "totalEndpoints": 2,
                    "unread": false
                }
            ],
            "paginationInfo": {
                "items": 50,
                "page": 1
            },
            "timestamp": "2023-01-26T23:17:29.801Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|timestamp|
>|---|---|---|
>| {'id': 'f06a50c0-69e5-11ed-89c2-6136df938368', 'timestamp': '2022-11-21T21:46:22.028Z', 'statusTimestamp': '2022-12-13T20:48:09.825Z', 'status': 'muted', 'contacts': 8, 'adversaries': ['jameshallybone.co.uk'], 'adversaryId': 'jameshallybone.co.uk', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'989': 6, '1651': 1, '3811': 1}, 'totalEndpoints': 3, 'lastContact': '2022-12-05T16:03:05.322Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-11-21T21:46:01.425Z'},<br/>{'id': '47bbc6c0-56f8-11ed-987a-cd6f8ff058b8', 'timestamp': '2022-10-28T19:39:47.372Z', 'statusTimestamp': '2022-10-31T21:51:02.594Z', 'status': 'muted', 'contacts': 2, 'adversaries': ['barbombon.com.'], 'adversaryId': 'barbombon.com.', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Script.Generic', 'labelDistribution': {'1651': 2}, 'totalEndpoints': 1, 'lastContact': '2022-10-28T19:44:10.172Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-28T19:39:13.452Z'},<br/>{'id': 'dc758440-fdc0-11ec-80a5-f16f41289f2f', 'timestamp': '2022-07-07T06:48:51.588Z', 'statusTimestamp': '2022-07-07T20:15:16.997Z', 'status': 'muted', 'contacts': 47, 'adversaries': ['secure.runescape.com-oc.ru'], 'adversaryId': 'secure.runescape.com-oc.ru', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'1651': 4, '989': 43}, 'totalEndpoints': 2, 'lastContact': '2022-12-05T16:03:05.328Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-07-07T06:47:29.452Z'} | page: 1<br/>items: 50 | 2023-01-26T23:17:29.801Z |


### lumu-retrieve-closed-incidents
***
Get a paginated list of closed incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-closed-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | . | Optional | 
| items | . | Optional | 
| adversary-types | . | Optional | 
| labels | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveClosedIncidents.items.id | String |  | 
| Lumu.RetrieveClosedIncidents.items.timestamp | Date |  | 
| Lumu.RetrieveClosedIncidents.items.statusTimestamp | Date |  | 
| Lumu.RetrieveClosedIncidents.items.status | String |  | 
| Lumu.RetrieveClosedIncidents.items.contacts | Number |  | 
| Lumu.RetrieveClosedIncidents.items.adversaries | String |  | 
| Lumu.RetrieveClosedIncidents.items.adversaryId | String |  | 
| Lumu.RetrieveClosedIncidents.items.adversaryTypes | String |  | 
| Lumu.RetrieveClosedIncidents.items.description | String |  | 
| Lumu.RetrieveClosedIncidents.items.labelDistribution.37 | Number |  | 
| Lumu.RetrieveClosedIncidents.items.totalEndpoints | Number |  | 
| Lumu.RetrieveClosedIncidents.items.lastContact | Date |  | 
| Lumu.RetrieveClosedIncidents.items.unread | Boolean |  | 
| Lumu.RetrieveClosedIncidents.paginationInfo.page | Number |  | 
| Lumu.RetrieveClosedIncidents.paginationInfo.items | Number |  | 
| Lumu.RetrieveClosedIncidents.paginationInfo.next | Number |  | 

#### Command example
```!lumu-retrieve-closed-incidents```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveClosedIncidents": {
            "items": [
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "78b465c0-9dc5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T22:14:29.778Z",
                    "timestamp": "2023-01-26T22:04:57.756Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "ecc22120-9daa-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T19:08:45.185Z",
                    "timestamp": "2023-01-26T18:54:56.050Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "29dab720-9d1f-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T18:52:06.437Z",
                    "timestamp": "2023-01-26T02:14:29.010Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 98,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 28,
                        "4232": 1,
                        "989": 69
                    },
                    "lastContact": "2023-01-24T21:17:50Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T02:13:33.006Z",
                    "timestamp": "2023-01-24T11:48:56.059Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "f563af00-9bda-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-24T11:45:59.944Z",
                    "timestamp": "2023-01-24T11:33:44.048Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 10,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "2bc88020-9b2c-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 10
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-24T11:33:24.832Z",
                    "timestamp": "2023-01-23T14:42:33.378Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "9b430be0-9b1e-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-23T14:24:09.462Z",
                    "timestamp": "2023-01-23T13:05:27.454Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "249b6b90-9b14-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-23T12:57:59.609Z",
                    "timestamp": "2023-01-23T11:50:33.417Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "cae5a990-99e6-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:58:48.655Z",
                    "timestamp": "2023-01-21T23:53:24.393Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "7db7c400-99e1-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:51:47.406Z",
                    "timestamp": "2023-01-21T23:15:27.424Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "72067f80-99cc-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:13:41.679Z",
                    "timestamp": "2023-01-21T20:44:48.376Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "eaba8420-9932-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T02:27:53.605Z",
                    "timestamp": "2023-01-21T02:25:48.386Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "0f055c60-9901-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T02:24:55.326Z",
                    "timestamp": "2023-01-20T20:28:54.438Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 134,
                    "description": "Activity Test Query",
                    "firstContact": "2023-01-18T15:32:25.126Z",
                    "hasPlaybackContacts": false,
                    "id": "3b43f070-982a-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 108,
                        "4055": 1,
                        "989": 25
                    },
                    "lastContact": "2023-01-18T17:02:46Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-20T15:54:56.324Z",
                    "timestamp": "2023-01-19T18:51:06.871Z",
                    "totalEndpoints": 10,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 36,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "aedb44c0-978a-11ed-b6d7-3f0c59c638d9",
                    "labelDistribution": {
                        "0": 36
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-19T16:42:19.541Z",
                    "timestamp": "2023-01-18T23:49:01.324Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 26,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "8b02a730-9778-11ed-b6d7-3f0c59c638d9",
                    "labelDistribution": {
                        "0": 26
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-18T23:44:37.049Z",
                    "timestamp": "2023-01-18T21:39:10.243Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 131,
                    "description": "Activity Test Query",
                    "firstContact": "2023-01-16T17:00:18.868Z",
                    "hasPlaybackContacts": false,
                    "id": "5c99aa20-95bf-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "0": 130,
                        "4055": 1
                    },
                    "lastContact": "2023-01-18T15:32:25.126Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-18T21:38:33.960Z",
                    "timestamp": "2023-01-16T17:01:04.322Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "hurricanepub.com"
                    ],
                    "adversaryId": "hurricanepub.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family UNC4034",
                    "firstContact": "2023-01-17T17:05:28.225Z",
                    "hasPlaybackContacts": false,
                    "id": "2d49ca50-9689-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "147": 2
                    },
                    "lastContact": "2023-01-17T18:40:55.695Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-18T14:43:31.970Z",
                    "timestamp": "2023-01-17T17:05:43.285Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1053,
                    "description": "Activity Test Query",
                    "firstContact": "2023-01-04T20:00:06.375Z",
                    "hasPlaybackContacts": false,
                    "id": "7094dee0-8c6a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "0": 1045,
                        "1580": 1,
                        "4055": 4,
                        "4061": 3
                    },
                    "lastContact": "2023-01-16T16:01:28.124Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-16T16:54:32.918Z",
                    "timestamp": "2023-01-04T20:00:30.158Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ibu.com.uy"
                    ],
                    "adversaryId": "ibu.com.uy",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 8,
                    "description": "Phishing domain",
                    "firstContact": "2022-12-21T16:39:39.451Z",
                    "hasPlaybackContacts": false,
                    "id": "19294280-814e-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "2254": 8
                    },
                    "lastContact": "2022-12-22T20:11:10.974Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-06T19:12:19.050Z",
                    "timestamp": "2022-12-21T16:39:54.792Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 24,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-29T13:57:01.548Z",
                    "hasPlaybackContacts": false,
                    "id": "b27b1d90-8780-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 22,
                        "4053": 1,
                        "989": 1
                    },
                    "lastContact": "2023-01-04T19:00:52.902Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-04T19:11:56.620Z",
                    "timestamp": "2022-12-29T13:57:13.833Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-29T00:21:38.089Z",
                    "hasPlaybackContacts": false,
                    "id": "c97f79e0-870e-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-12-29T13:50:21.218Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-29T13:54:35.413Z",
                    "timestamp": "2022-12-29T00:21:49.822Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-29T00:18:57.237Z",
                    "hasPlaybackContacts": false,
                    "id": "6abbae10-870e-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-29T00:18:57.237Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-29T00:20:51.490Z",
                    "timestamp": "2022-12-29T00:19:10.833Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-29T00:10:39.969Z",
                    "hasPlaybackContacts": false,
                    "id": "41ed0390-870d-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-29T00:15:37.061Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-29T00:18:37.071Z",
                    "timestamp": "2022-12-29T00:10:52.873Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "nightking43.art"
                    ],
                    "adversaryId": "nightking43.art",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-12-14T22:40:32Z",
                    "hasPlaybackContacts": false,
                    "id": "e62442a0-7c74-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "2148": 1
                    },
                    "lastContact": "2022-12-14T22:40:32Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:58:13.010Z",
                    "timestamp": "2022-12-15T12:35:03.754Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "javxr.com"
                    ],
                    "adversaryId": "javxr.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 11,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-12-06T22:40:14.671Z",
                    "hasPlaybackContacts": false,
                    "id": "fb392f80-75b6-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 10,
                        "2267": 1
                    },
                    "lastContact": "2022-12-22T18:29:18.846Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:50:06.608Z",
                    "timestamp": "2022-12-06T22:40:27.768Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "anx.com.np"
                    ],
                    "adversaryId": "anx.com.np",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-12-09T19:48:27Z",
                    "hasPlaybackContacts": false,
                    "id": "f70cc990-7948-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "2148": 1
                    },
                    "lastContact": "2022-12-09T19:48:27Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:48:38.328Z",
                    "timestamp": "2022-12-11T11:43:00.777Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "go.ly"
                    ],
                    "adversaryId": "go.ly",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 1,
                    "description": "Phishing domain",
                    "firstContact": "2022-12-11T20:00:30Z",
                    "hasPlaybackContacts": false,
                    "id": "8f3d9c90-798e-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "3938": 1
                    },
                    "lastContact": "2022-12-11T20:00:30Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:37:53.303Z",
                    "timestamp": "2022-12-11T20:01:11.385Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "api.netflare.info"
                    ],
                    "adversaryId": "api.netflare.info",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "Malicious domain",
                    "firstContact": "2022-12-09T22:37:16Z",
                    "hasPlaybackContacts": false,
                    "id": "99890290-796e-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "2148": 1
                    },
                    "lastContact": "2022-12-09T22:37:16Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:23:34.778Z",
                    "timestamp": "2022-12-11T16:12:24.761Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.ascentive.com"
                    ],
                    "adversaryId": "www.ascentive.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Win32.Generic",
                    "firstContact": "2022-12-12T22:11:46.180Z",
                    "hasPlaybackContacts": false,
                    "id": "003eef80-7a6a-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "147": 1
                    },
                    "lastContact": "2022-12-12T22:11:46.180Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:20:35.551Z",
                    "timestamp": "2022-12-12T22:12:00.760Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "fastpool.xyz"
                    ],
                    "adversaryId": "fastpool.xyz",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 3,
                    "description": "Malicious domain",
                    "firstContact": "2022-12-16T14:46:54.264Z",
                    "hasPlaybackContacts": false,
                    "id": "84d264f0-7d50-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "147": 1,
                        "2254": 2
                    },
                    "lastContact": "2022-12-16T19:49:02.864Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:17:35.713Z",
                    "timestamp": "2022-12-16T14:47:09.759Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "lps.peacerental.com"
                    ],
                    "adversaryId": "lps.peacerental.com",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 3,
                    "description": "Phishing domain",
                    "firstContact": "2022-12-12T17:19:31.374Z",
                    "hasPlaybackContacts": false,
                    "id": "2c924600-7a41-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "147": 2,
                        "1885": 1
                    },
                    "lastContact": "2022-12-12T23:43:34Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:13:49.481Z",
                    "timestamp": "2022-12-12T17:19:45.760Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "cnt.statistic.date"
                    ],
                    "adversaryId": "cnt.statistic.date",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "Malicious domain",
                    "firstContact": "2022-12-12T16:09:46.405Z",
                    "hasPlaybackContacts": false,
                    "id": "6c5393c0-7a37-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-12T16:09:46.405Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:05:23.814Z",
                    "timestamp": "2022-12-12T16:09:57.756Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 6,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-27T20:05:47Z",
                    "hasPlaybackContacts": false,
                    "id": "37eb2760-8635-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "2148": 6
                    },
                    "lastContact": "2022-12-27T20:51:54Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T22:47:44.343Z",
                    "timestamp": "2022-12-27T22:24:24.790Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-22T18:29:08.846Z",
                    "hasPlaybackContacts": false,
                    "id": "9326b8f0-8226-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 1,
                        "2254": 6
                    },
                    "lastContact": "2022-12-23T22:34:34.191Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-27T20:39:23.918Z",
                    "timestamp": "2022-12-22T18:29:30.751Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-21T16:39:34.419Z",
                    "hasPlaybackContacts": false,
                    "id": "159b60d0-814e-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "2254": 4
                    },
                    "lastContact": "2022-12-21T16:39:34.696Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-22T18:28:39.879Z",
                    "timestamp": "2022-12-21T16:39:48.829Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ibu.com.uy"
                    ],
                    "adversaryId": "ibu.com.uy",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 1,
                    "description": "Phishing domain",
                    "firstContact": "2022-12-20T23:20:59.367Z",
                    "hasPlaybackContacts": false,
                    "id": "fe5c9240-80bc-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "147": 1
                    },
                    "lastContact": "2022-12-20T23:20:59.367Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-21T16:26:11.582Z",
                    "timestamp": "2022-12-20T23:21:12.804Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "6d178850-7d5e-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 1,
                        "2254": 1
                    },
                    "lastContact": "2022-12-16T19:20:59.642Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-21T16:23:38.937Z",
                    "timestamp": "2022-12-16T16:26:42.901Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "upch.mx"
                    ],
                    "adversaryId": "upch.mx",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 32,
                    "description": "Malware family Agent.Tr.5e6f.Wm",
                    "firstContact": "2022-12-20T23:36:42.101Z",
                    "hasPlaybackContacts": false,
                    "id": "3197e360-80bf-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "3077": 32
                    },
                    "lastContact": "2022-12-21T00:16:08.153Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-21T00:16:44.129Z",
                    "timestamp": "2022-12-20T23:36:57.750Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "upch.mx"
                    ],
                    "adversaryId": "upch.mx",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Agent.Tr.5e6f.Wm",
                    "firstContact": "2022-12-20T23:32:36.743Z",
                    "hasPlaybackContacts": false,
                    "id": "9ef6cf30-80be-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "3077": 1
                    },
                    "lastContact": "2022-12-20T23:32:36.743Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-20T23:35:41.292Z",
                    "timestamp": "2022-12-20T23:32:51.747Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "86515610-7d4b-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-16T14:13:21.021Z",
                    "timestamp": "2022-12-16T14:11:24.785Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 18,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "2082d5a0-7960-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 17,
                        "3938": 1
                    },
                    "lastContact": "2022-12-12T19:29:12.308Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-16T14:09:27.416Z",
                    "timestamp": "2022-12-11T14:28:48.762Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "curlhph.tk"
                    ],
                    "adversaryId": "curlhph.tk",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 6,
                    "description": "Disposable email host",
                    "firstContact": "2022-11-21T21:45:50.011Z",
                    "hasPlaybackContacts": false,
                    "id": "f0580140-69e5-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "989": 6
                    },
                    "lastContact": "2022-12-05T16:03:05.316Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-14T01:33:23.102Z",
                    "timestamp": "2022-11-21T21:46:21.908Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "horsecatdog.com.au"
                    ],
                    "adversaryId": "horsecatdog.com.au",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family P2PZeuS",
                    "firstContact": "2022-12-12T16:36:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "b0fc2f80-7a6b-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "2267": 2
                    },
                    "lastContact": "2022-12-12T16:36:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-12T23:02:51.010Z",
                    "timestamp": "2022-12-12T22:24:06.776Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "mastergamenameper.club"
                    ],
                    "adversaryId": "mastergamenameper.club",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 2,
                    "description": "Malware family Adrozek",
                    "firstContact": "2022-12-12T17:19:56.518Z",
                    "hasPlaybackContacts": false,
                    "id": "3cab0fe0-7a41-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "147": 2
                    },
                    "lastContact": "2022-12-12T17:19:56.518Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-12T22:59:11.953Z",
                    "timestamp": "2022-12-12T17:20:12.766Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "paulstoreyphotography.com"
                    ],
                    "adversaryId": "paulstoreyphotography.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family P2PZeuS",
                    "firstContact": "2021-03-30T09:36:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "80b0e780-7a6b-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "2267": 1
                    },
                    "lastContact": "2021-03-30T09:36:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-12T22:26:29.775Z",
                    "timestamp": "2022-12-12T22:22:45.752Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "siamjaguar.com"
                    ],
                    "adversaryId": "siamjaguar.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 9,
                    "description": "Malware family P2PZeuS",
                    "firstContact": "2022-09-23T16:05:10.363Z",
                    "hasPlaybackContacts": false,
                    "id": "68186cc0-3b5a-11ed-a970-0deeb09d4f42",
                    "labelDistribution": {
                        "3077": 8,
                        "989": 1
                    },
                    "lastContact": "2022-10-25T12:50:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-12T22:25:01.052Z",
                    "timestamp": "2022-09-23T16:11:39.788Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "just-a-downloader.su"
                    ],
                    "adversaryId": "just-a-downloader.su",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family P2PZeuS",
                    "firstContact": "2021-03-30T09:36:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "a0dfbc20-7a6b-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "2267": 1
                    },
                    "lastContact": "2021-03-30T09:36:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-12T22:24:27.419Z",
                    "timestamp": "2022-12-12T22:23:39.746Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "horsecatdog.com.au"
                    ],
                    "adversaryId": "horsecatdog.com.au",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family P2PZeuS",
                    "firstContact": "2022-10-25T20:39:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "46deb190-54a5-11ed-9df2-6538d9561738",
                    "labelDistribution": {
                        "989": 1
                    },
                    "lastContact": "2022-10-25T20:39:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-12T22:23:41.743Z",
                    "timestamp": "2022-10-25T20:40:35.369Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "rea.co.ke"
                    ],
                    "adversaryId": "rea.co.ke",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family P2PZeuS",
                    "firstContact": "2022-10-26T22:53:13.548Z",
                    "hasPlaybackContacts": false,
                    "id": "0082fd00-5581-11ed-987a-cd6f8ff058b8",
                    "labelDistribution": {
                        "3635": 1
                    },
                    "lastContact": "2022-10-26T22:53:13.548Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-12T22:21:58.919Z",
                    "timestamp": "2022-10-26T22:53:26.608Z",
                    "totalEndpoints": 1,
                    "unread": false
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-01-26T23:17:31.850Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|timestamp|
>|---|---|---|
>| {'id': '78b465c0-9dc5-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T22:04:57.756Z', 'statusTimestamp': '2023-01-26T22:14:29.778Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'ecc22120-9daa-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T18:54:56.050Z', 'statusTimestamp': '2023-01-26T19:08:45.185Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '29dab720-9d1f-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T02:14:29.010Z', 'statusTimestamp': '2023-01-26T18:52:06.437Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T11:48:56.059Z', 'statusTimestamp': '2023-01-26T02:13:33.006Z', 'status': 'closed', 'contacts': 98, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 28, '989': 69, '4232': 1}, 'totalEndpoints': 4, 'lastContact': '2023-01-24T21:17:50Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'f563af00-9bda-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T11:33:44.048Z', 'statusTimestamp': '2023-01-24T11:45:59.944Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '2bc88020-9b2c-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T14:42:33.378Z', 'statusTimestamp': '2023-01-24T11:33:24.832Z', 'status': 'closed', 'contacts': 10, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 10}, 'totalEndpoints': 5, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '9b430be0-9b1e-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T13:05:27.454Z', 'statusTimestamp': '2023-01-23T14:24:09.462Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '249b6b90-9b14-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T11:50:33.417Z', 'statusTimestamp': '2023-01-23T12:57:59.609Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'cae5a990-99e6-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T23:53:24.393Z', 'statusTimestamp': '2023-01-21T23:58:48.655Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '7db7c400-99e1-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T23:15:27.424Z', 'statusTimestamp': '2023-01-21T23:51:47.406Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '72067f80-99cc-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T20:44:48.376Z', 'statusTimestamp': '2023-01-21T23:13:41.679Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 2, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'eaba8420-9932-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T02:25:48.386Z', 'statusTimestamp': '2023-01-21T02:27:53.605Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '0f055c60-9901-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T20:28:54.438Z', 'statusTimestamp': '2023-01-21T02:24:55.326Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '3b43f070-982a-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-19T18:51:06.871Z', 'statusTimestamp': '2023-01-20T15:54:56.324Z', 'status': 'closed', 'contacts': 134, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'4055': 1, '0': 108, '989': 25}, 'totalEndpoints': 10, 'lastContact': '2023-01-18T17:02:46Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-18T15:32:25.126Z'},<br/>{'id': 'aedb44c0-978a-11ed-b6d7-3f0c59c638d9', 'timestamp': '2023-01-18T23:49:01.324Z', 'statusTimestamp': '2023-01-19T16:42:19.541Z', 'status': 'closed', 'contacts': 36, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 36}, 'totalEndpoints': 2, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '8b02a730-9778-11ed-b6d7-3f0c59c638d9', 'timestamp': '2023-01-18T21:39:10.243Z', 'statusTimestamp': '2023-01-18T23:44:37.049Z', 'status': 'closed', 'contacts': 26, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 26}, 'totalEndpoints': 2, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '5c99aa20-95bf-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-16T17:01:04.322Z', 'statusTimestamp': '2023-01-18T21:38:33.960Z', 'status': 'closed', 'contacts': 131, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 130, '4055': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-18T15:32:25.126Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-16T17:00:18.868Z'},<br/>{'id': '2d49ca50-9689-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-17T17:05:43.285Z', 'statusTimestamp': '2023-01-18T14:43:31.970Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['hurricanepub.com'], 'adversaryId': 'hurricanepub.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family UNC4034', 'labelDistribution': {'147': 2}, 'totalEndpoints': 1, 'lastContact': '2023-01-17T18:40:55.695Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-17T17:05:28.225Z'},<br/>{'id': '7094dee0-8c6a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-04T20:00:30.158Z', 'statusTimestamp': '2023-01-16T16:54:32.918Z', 'status': 'closed', 'contacts': 1053, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1045, '4055': 4, '4061': 3, '1580': 1}, 'totalEndpoints': 5, 'lastContact': '2023-01-16T16:01:28.124Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-04T20:00:06.375Z'},<br/>{'id': '19294280-814e-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-21T16:39:54.792Z', 'statusTimestamp': '2023-01-06T19:12:19.050Z', 'status': 'closed', 'contacts': 8, 'adversaries': ['ibu.com.uy'], 'adversaryId': 'ibu.com.uy', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'2254': 8}, 'totalEndpoints': 2, 'lastContact': '2022-12-22T20:11:10.974Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-21T16:39:39.451Z'},<br/>{'id': 'b27b1d90-8780-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-29T13:57:13.833Z', 'statusTimestamp': '2023-01-04T19:11:56.620Z', 'status': 'closed', 'contacts': 24, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 22, '989': 1, '4053': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-04T19:00:52.902Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-29T13:57:01.548Z'},<br/>{'id': 'c97f79e0-870e-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-29T00:21:49.822Z', 'statusTimestamp': '2022-12-29T13:54:35.413Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 1, 'lastContact': '2022-12-29T13:50:21.218Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-29T00:21:38.089Z'},<br/>{'id': '6abbae10-870e-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-29T00:19:10.833Z', 'statusTimestamp': '2022-12-29T00:20:51.490Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-29T00:18:57.237Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-29T00:18:57.237Z'},<br/>{'id': '41ed0390-870d-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-29T00:10:52.873Z', 'statusTimestamp': '2022-12-29T00:18:37.071Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-12-29T00:15:37.061Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-29T00:10:39.969Z'},<br/>{'id': 'e62442a0-7c74-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-15T12:35:03.754Z', 'statusTimestamp': '2022-12-28T23:58:13.010Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['nightking43.art'], 'adversaryId': 'nightking43.art', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-14T22:40:32Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-14T22:40:32Z'},<br/>{'id': 'fb392f80-75b6-11ed-89c2-6136df938368', 'timestamp': '2022-12-06T22:40:27.768Z', 'statusTimestamp': '2022-12-28T23:50:06.608Z', 'status': 'closed', 'contacts': 11, 'adversaries': ['javxr.com'], 'adversaryId': 'javxr.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'0': 10, '2267': 1}, 'totalEndpoints': 2, 'lastContact': '2022-12-22T18:29:18.846Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-06T22:40:14.671Z'},<br/>{'id': 'f70cc990-7948-11ed-89c2-6136df938368', 'timestamp': '2022-12-11T11:43:00.777Z', 'statusTimestamp': '2022-12-28T23:48:38.328Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['anx.com.np'], 'adversaryId': 'anx.com.np', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'2148': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-09T19:48:27Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-09T19:48:27Z'},<br/>{'id': '8f3d9c90-798e-11ed-89c2-6136df938368', 'timestamp': '2022-12-11T20:01:11.385Z', 'statusTimestamp': '2022-12-28T23:37:53.303Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['go.ly'], 'adversaryId': 'go.ly', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'3938': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-11T20:00:30Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-11T20:00:30Z'},<br/>{'id': '99890290-796e-11ed-89c2-6136df938368', 'timestamp': '2022-12-11T16:12:24.761Z', 'statusTimestamp': '2022-12-28T23:23:34.778Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['api.netflare.info'], 'adversaryId': 'api.netflare.info', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'2148': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-09T22:37:16Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-09T22:37:16Z'},<br/>{'id': '003eef80-7a6a-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T22:12:00.760Z', 'statusTimestamp': '2022-12-28T23:20:35.551Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['www.ascentive.com'], 'adversaryId': 'www.ascentive.com', 'adversaryTypes': ['Malware'], 'description': 'Malware family Trojan.Win32.Generic', 'labelDistribution': {'147': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-12T22:11:46.180Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-12T22:11:46.180Z'},<br/>{'id': '84d264f0-7d50-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-16T14:47:09.759Z', 'statusTimestamp': '2022-12-28T23:17:35.713Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['fastpool.xyz'], 'adversaryId': 'fastpool.xyz', 'adversaryTypes': ['Malware'], 'description': 'Malicious domain', 'labelDistribution': {'147': 1, '2254': 2}, 'totalEndpoints': 2, 'lastContact': '2022-12-16T19:49:02.864Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-16T14:46:54.264Z'},<br/>{'id': '2c924600-7a41-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T17:19:45.760Z', 'statusTimestamp': '2022-12-28T23:13:49.481Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['lps.peacerental.com'], 'adversaryId': 'lps.peacerental.com', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'147': 2, '1885': 1}, 'totalEndpoints': 2, 'lastContact': '2022-12-12T23:43:34Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-12T17:19:31.374Z'},<br/>{'id': '6c5393c0-7a37-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T16:09:57.756Z', 'statusTimestamp': '2022-12-28T23:05:23.814Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['cnt.statistic.date'], 'adversaryId': 'cnt.statistic.date', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-12T16:09:46.405Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-12T16:09:46.405Z'},<br/>{'id': '37eb2760-8635-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-27T22:24:24.790Z', 'statusTimestamp': '2022-12-28T22:47:44.343Z', 'status': 'closed', 'contacts': 6, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'2148': 6}, 'totalEndpoints': 1, 'lastContact': '2022-12-27T20:51:54Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-27T20:05:47Z'},<br/>{'id': '9326b8f0-8226-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-22T18:29:30.751Z', 'statusTimestamp': '2022-12-27T20:39:23.918Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1, '2254': 6}, 'totalEndpoints': 4, 'lastContact': '2022-12-23T22:34:34.191Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-22T18:29:08.846Z'},<br/>{'id': '159b60d0-814e-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-21T16:39:48.829Z', 'statusTimestamp': '2022-12-22T18:28:39.879Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'2254': 4}, 'totalEndpoints': 1, 'lastContact': '2022-12-21T16:39:34.696Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-21T16:39:34.419Z'},<br/>{'id': 'fe5c9240-80bc-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-20T23:21:12.804Z', 'statusTimestamp': '2022-12-21T16:26:11.582Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['ibu.com.uy'], 'adversaryId': 'ibu.com.uy', 'adversaryTypes': ['Phishing'], 'description': 'Phishing domain', 'labelDistribution': {'147': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T23:20:59.367Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T23:20:59.367Z'},<br/>{'id': '6d178850-7d5e-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-16T16:26:42.901Z', 'statusTimestamp': '2022-12-21T16:23:38.937Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1, '2254': 1}, 'totalEndpoints': 2, 'lastContact': '2022-12-16T19:20:59.642Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '3197e360-80bf-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-20T23:36:57.750Z', 'statusTimestamp': '2022-12-21T00:16:44.129Z', 'status': 'closed', 'contacts': 32, 'adversaries': ['upch.mx'], 'adversaryId': 'upch.mx', 'adversaryTypes': ['Malware'], 'description': 'Malware family Agent.Tr.5e6f.Wm', 'labelDistribution': {'3077': 32}, 'totalEndpoints': 2, 'lastContact': '2022-12-21T00:16:08.153Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T23:36:42.101Z'},<br/>{'id': '9ef6cf30-80be-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-20T23:32:51.747Z', 'statusTimestamp': '2022-12-20T23:35:41.292Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['upch.mx'], 'adversaryId': 'upch.mx', 'adversaryTypes': ['Malware'], 'description': 'Malware family Agent.Tr.5e6f.Wm', 'labelDistribution': {'3077': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T23:32:36.743Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T23:32:36.743Z'},<br/>{'id': '86515610-7d4b-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-16T14:11:24.785Z', 'statusTimestamp': '2022-12-16T14:13:21.021Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '2082d5a0-7960-11ed-89c2-6136df938368', 'timestamp': '2022-12-11T14:28:48.762Z', 'statusTimestamp': '2022-12-16T14:09:27.416Z', 'status': 'closed', 'contacts': 18, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 17, '3938': 1}, 'totalEndpoints': 3, 'lastContact': '2022-12-12T19:29:12.308Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'f0580140-69e5-11ed-89c2-6136df938368', 'timestamp': '2022-11-21T21:46:21.908Z', 'statusTimestamp': '2022-12-14T01:33:23.102Z', 'status': 'closed', 'contacts': 6, 'adversaries': ['curlhph.tk'], 'adversaryId': 'curlhph.tk', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'989': 6}, 'totalEndpoints': 1, 'lastContact': '2022-12-05T16:03:05.316Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-11-21T21:45:50.011Z'},<br/>{'id': 'b0fc2f80-7a6b-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T22:24:06.776Z', 'statusTimestamp': '2022-12-12T23:02:51.010Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['horsecatdog.com.au'], 'adversaryId': 'horsecatdog.com.au', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'2267': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-12T16:36:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-12T16:36:02.228Z'},<br/>{'id': '3cab0fe0-7a41-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T17:20:12.766Z', 'statusTimestamp': '2022-12-12T22:59:11.953Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['mastergamenameper.club'], 'adversaryId': 'mastergamenameper.club', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family Adrozek', 'labelDistribution': {'147': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-12T17:19:56.518Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-12T17:19:56.518Z'},<br/>{'id': '80b0e780-7a6b-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T22:22:45.752Z', 'statusTimestamp': '2022-12-12T22:26:29.775Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['paulstoreyphotography.com'], 'adversaryId': 'paulstoreyphotography.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'2267': 1}, 'totalEndpoints': 1, 'lastContact': '2021-03-30T09:36:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2021-03-30T09:36:02.228Z'},<br/>{'id': '68186cc0-3b5a-11ed-a970-0deeb09d4f42', 'timestamp': '2022-09-23T16:11:39.788Z', 'statusTimestamp': '2022-12-12T22:25:01.052Z', 'status': 'closed', 'contacts': 9, 'adversaries': ['siamjaguar.com'], 'adversaryId': 'siamjaguar.com', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'3077': 8, '989': 1}, 'totalEndpoints': 2, 'lastContact': '2022-10-25T12:50:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-09-23T16:05:10.363Z'},<br/>{'id': 'a0dfbc20-7a6b-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T22:23:39.746Z', 'statusTimestamp': '2022-12-12T22:24:27.419Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['just-a-downloader.su'], 'adversaryId': 'just-a-downloader.su', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'2267': 1}, 'totalEndpoints': 1, 'lastContact': '2021-03-30T09:36:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2021-03-30T09:36:02.228Z'},<br/>{'id': '46deb190-54a5-11ed-9df2-6538d9561738', 'timestamp': '2022-10-25T20:40:35.369Z', 'statusTimestamp': '2022-12-12T22:23:41.743Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['horsecatdog.com.au'], 'adversaryId': 'horsecatdog.com.au', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'989': 1}, 'totalEndpoints': 1, 'lastContact': '2022-10-25T20:39:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-25T20:39:02.228Z'},<br/>{'id': '0082fd00-5581-11ed-987a-cd6f8ff058b8', 'timestamp': '2022-10-26T22:53:26.608Z', 'statusTimestamp': '2022-12-12T22:21:58.919Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['rea.co.ke'], 'adversaryId': 'rea.co.ke', 'adversaryTypes': ['C2C', 'Malware'], 'description': 'Malware family P2PZeuS', 'labelDistribution': {'3635': 1}, 'totalEndpoints': 1, 'lastContact': '2022-10-26T22:53:13.548Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-26T22:53:13.548Z'} | page: 1<br/>items: 50<br/>next: 2 | 2023-01-26T23:17:31.850Z |


#### Command example
```!lumu-retrieve-closed-incidents labels=0 adversary-types=Mining,Spam```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveClosedIncidents": {
            "items": [
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "78b465c0-9dc5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T22:14:29.778Z",
                    "timestamp": "2023-01-26T22:04:57.756Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "ecc22120-9daa-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T19:08:45.185Z",
                    "timestamp": "2023-01-26T18:54:56.050Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "29dab720-9d1f-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T18:52:06.437Z",
                    "timestamp": "2023-01-26T02:14:29.010Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 98,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 28,
                        "4232": 1,
                        "989": 69
                    },
                    "lastContact": "2023-01-24T21:17:50Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T02:13:33.006Z",
                    "timestamp": "2023-01-24T11:48:56.059Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "f563af00-9bda-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-24T11:45:59.944Z",
                    "timestamp": "2023-01-24T11:33:44.048Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 10,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "2bc88020-9b2c-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 10
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-24T11:33:24.832Z",
                    "timestamp": "2023-01-23T14:42:33.378Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "9b430be0-9b1e-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-23T14:24:09.462Z",
                    "timestamp": "2023-01-23T13:05:27.454Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "249b6b90-9b14-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-23T12:57:59.609Z",
                    "timestamp": "2023-01-23T11:50:33.417Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "cae5a990-99e6-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:58:48.655Z",
                    "timestamp": "2023-01-21T23:53:24.393Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "7db7c400-99e1-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 7
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:51:47.406Z",
                    "timestamp": "2023-01-21T23:15:27.424Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "72067f80-99cc-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T23:13:41.679Z",
                    "timestamp": "2023-01-21T20:44:48.376Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "eaba8420-9932-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T02:27:53.605Z",
                    "timestamp": "2023-01-21T02:25:48.386Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "0f055c60-9901-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-21T02:24:55.326Z",
                    "timestamp": "2023-01-20T20:28:54.438Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 134,
                    "description": "Activity Test Query",
                    "firstContact": "2023-01-18T15:32:25.126Z",
                    "hasPlaybackContacts": false,
                    "id": "3b43f070-982a-11ed-980e-915fb2011ca7",
                    "labelDistribution": {
                        "0": 108,
                        "4055": 1,
                        "989": 25
                    },
                    "lastContact": "2023-01-18T17:02:46Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-20T15:54:56.324Z",
                    "timestamp": "2023-01-19T18:51:06.871Z",
                    "totalEndpoints": 10,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 36,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "aedb44c0-978a-11ed-b6d7-3f0c59c638d9",
                    "labelDistribution": {
                        "0": 36
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-19T16:42:19.541Z",
                    "timestamp": "2023-01-18T23:49:01.324Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 26,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "8b02a730-9778-11ed-b6d7-3f0c59c638d9",
                    "labelDistribution": {
                        "0": 26
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-18T23:44:37.049Z",
                    "timestamp": "2023-01-18T21:39:10.243Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 131,
                    "description": "Activity Test Query",
                    "firstContact": "2023-01-16T17:00:18.868Z",
                    "hasPlaybackContacts": false,
                    "id": "5c99aa20-95bf-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "0": 130,
                        "4055": 1
                    },
                    "lastContact": "2023-01-18T15:32:25.126Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-18T21:38:33.960Z",
                    "timestamp": "2023-01-16T17:01:04.322Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1053,
                    "description": "Activity Test Query",
                    "firstContact": "2023-01-04T20:00:06.375Z",
                    "hasPlaybackContacts": false,
                    "id": "7094dee0-8c6a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "0": 1045,
                        "1580": 1,
                        "4055": 4,
                        "4061": 3
                    },
                    "lastContact": "2023-01-16T16:01:28.124Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-16T16:54:32.918Z",
                    "timestamp": "2023-01-04T20:00:30.158Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 24,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-29T13:57:01.548Z",
                    "hasPlaybackContacts": false,
                    "id": "b27b1d90-8780-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 22,
                        "4053": 1,
                        "989": 1
                    },
                    "lastContact": "2023-01-04T19:00:52.902Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-04T19:11:56.620Z",
                    "timestamp": "2022-12-29T13:57:13.833Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-29T00:21:38.089Z",
                    "hasPlaybackContacts": false,
                    "id": "c97f79e0-870e-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-12-29T13:50:21.218Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-29T13:54:35.413Z",
                    "timestamp": "2022-12-29T00:21:49.822Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-29T00:18:57.237Z",
                    "hasPlaybackContacts": false,
                    "id": "6abbae10-870e-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-29T00:18:57.237Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-29T00:20:51.490Z",
                    "timestamp": "2022-12-29T00:19:10.833Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-29T00:10:39.969Z",
                    "hasPlaybackContacts": false,
                    "id": "41ed0390-870d-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-29T00:15:37.061Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-29T00:18:37.071Z",
                    "timestamp": "2022-12-29T00:10:52.873Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "javxr.com"
                    ],
                    "adversaryId": "javxr.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 11,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-12-06T22:40:14.671Z",
                    "hasPlaybackContacts": false,
                    "id": "fb392f80-75b6-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 10,
                        "2267": 1
                    },
                    "lastContact": "2022-12-22T18:29:18.846Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:50:06.608Z",
                    "timestamp": "2022-12-06T22:40:27.768Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "cnt.statistic.date"
                    ],
                    "adversaryId": "cnt.statistic.date",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 1,
                    "description": "Malicious domain",
                    "firstContact": "2022-12-12T16:09:46.405Z",
                    "hasPlaybackContacts": false,
                    "id": "6c5393c0-7a37-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-12T16:09:46.405Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-28T23:05:23.814Z",
                    "timestamp": "2022-12-12T16:09:57.756Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 7,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-22T18:29:08.846Z",
                    "hasPlaybackContacts": false,
                    "id": "9326b8f0-8226-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 1,
                        "2254": 6
                    },
                    "lastContact": "2022-12-23T22:34:34.191Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-27T20:39:23.918Z",
                    "timestamp": "2022-12-22T18:29:30.751Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "6d178850-7d5e-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 1,
                        "2254": 1
                    },
                    "lastContact": "2022-12-16T19:20:59.642Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-21T16:23:38.937Z",
                    "timestamp": "2022-12-16T16:26:42.901Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "86515610-7d4b-11ed-a600-d53ba4d2bb70",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-16T14:13:21.021Z",
                    "timestamp": "2022-12-16T14:11:24.785Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 18,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "2082d5a0-7960-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 17,
                        "3938": 1
                    },
                    "lastContact": "2022-12-12T19:29:12.308Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-16T14:09:27.416Z",
                    "timestamp": "2022-12-11T14:28:48.762Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "4657b300-795f-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-11T14:23:29.691Z",
                    "timestamp": "2022-12-11T14:22:42.736Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 12,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "b62ddba0-78f6-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 12
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-11T14:20:58.708Z",
                    "timestamp": "2022-12-11T01:54:13.210Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "cdb76f10-78e8-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-11T00:23:20.854Z",
                    "timestamp": "2022-12-11T00:14:39.745Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "b20661c0-78e5-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-11T00:13:46.832Z",
                    "timestamp": "2022-12-10T23:52:24.796Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "fd6ba400-78e4-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T23:50:17.331Z",
                    "timestamp": "2022-12-10T23:47:21.792Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "fdba55b0-78e3-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T23:45:42.579Z",
                    "timestamp": "2022-12-10T23:40:12.811Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "cnt.statistic.date"
                    ],
                    "adversaryId": "cnt.statistic.date",
                    "adversaryTypes": [
                        "Malware",
                        "Mining"
                    ],
                    "contacts": 4,
                    "description": "Malicious domain",
                    "firstContact": "2022-12-08T14:14:05Z",
                    "hasPlaybackContacts": false,
                    "id": "55131840-77c9-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 3,
                        "2148": 1
                    },
                    "lastContact": "2022-12-09T22:35:48.305Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T23:29:17.060Z",
                    "timestamp": "2022-12-09T13:56:51.780Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "6ea05420-78dd-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T23:29:16.415Z",
                    "timestamp": "2022-12-10T22:53:15.746Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 19,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "b49fdaf0-782d-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 19
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T22:18:40.298Z",
                    "timestamp": "2022-12-10T01:55:21.759Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "f7153610-782c-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T01:54:57.549Z",
                    "timestamp": "2022-12-10T01:50:03.761Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "a8666390-782c-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T01:49:38.902Z",
                    "timestamp": "2022-12-10T01:47:51.753Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "faf4afa0-782b-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T01:46:24.981Z",
                    "timestamp": "2022-12-10T01:43:00.762Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 18,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "9d9d4710-7815-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 18
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-10T01:42:33.470Z",
                    "timestamp": "2022-12-09T23:02:55.233Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "a003ee30-7812-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 4
                    },
                    "lastContact": "2022-10-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-09T23:01:39.625Z",
                    "timestamp": "2022-12-09T22:41:30.771Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 46,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-09T17:58:14.664Z",
                    "hasPlaybackContacts": false,
                    "id": "1ab96150-77eb-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 46
                    },
                    "lastContact": "2022-12-09T22:35:38.305Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-09T22:40:19.890Z",
                    "timestamp": "2022-12-09T17:58:36.773Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-09T17:53:25.070Z",
                    "hasPlaybackContacts": false,
                    "id": "6d490cf0-77ea-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-09T17:53:30.786Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-09T17:55:55.295Z",
                    "timestamp": "2022-12-09T17:53:45.791Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 13,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-07T20:47:07.573Z",
                    "hasPlaybackContacts": false,
                    "id": "5c75c470-7670-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 2,
                        "2254": 1,
                        "989": 10
                    },
                    "lastContact": "2022-12-09T17:14:35.344Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-09T17:52:49.935Z",
                    "timestamp": "2022-12-07T20:47:27.799Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 16,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-06T20:27:21.461Z",
                    "hasPlaybackContacts": false,
                    "id": "6fb9fe60-75a4-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 12,
                        "989": 4
                    },
                    "lastContact": "2022-12-06T22:40:04.671Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-07T20:46:55.216Z",
                    "timestamp": "2022-12-06T20:27:42.790Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "javxr.com"
                    ],
                    "adversaryId": "javxr.com",
                    "adversaryTypes": [
                        "Mining"
                    ],
                    "contacts": 3,
                    "description": "CryptoMining domain",
                    "firstContact": "2022-12-06T22:00:16.389Z",
                    "hasPlaybackContacts": false,
                    "id": "65540620-75b1-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 1,
                        "989": 2
                    },
                    "lastContact": "2022-12-06T22:11:15.294Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-06T22:40:06.511Z",
                    "timestamp": "2022-12-06T22:00:28.802Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-06T20:23:37.896Z",
                    "hasPlaybackContacts": false,
                    "id": "eb797cc0-75a3-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-06T20:23:37.896Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-06T20:26:23.878Z",
                    "timestamp": "2022-12-06T20:24:00.908Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 53,
                    "description": "Activity Test Query",
                    "firstContact": "2022-10-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "e3542c10-70d6-11ed-89c2-6136df938368",
                    "labelDistribution": {
                        "0": 3,
                        "147": 1,
                        "989": 49
                    },
                    "lastContact": "2022-12-06T20:20:25.089Z",
                    "status": "closed",
                    "statusTimestamp": "2022-12-06T20:22:40.754Z",
                    "timestamp": "2022-11-30T17:46:15.761Z",
                    "totalEndpoints": 6,
                    "unread": false
                },
                {
                    "adversaries": [
                        "activity.lumu.io"
                    ],
                    "adversaryId": "activity.lumu.io",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 22,
                    "description": "Activity Test Query",
                    "firstContact": "2022-09-06T17:20:21.958Z",
                    "hasPlaybackContacts": false,
                    "id": "439be660-2e08-11ed-9b90-a51546bb08b5",
                    "labelDistribution": {
                        "0": 2,
                        "134": 10,
                        "989": 10
                    },
                    "lastContact": "2022-09-14T17:43:59.781Z",
                    "status": "closed",
                    "statusTimestamp": "2022-09-14T18:00:37.215Z",
                    "timestamp": "2022-09-06T17:20:54.726Z",
                    "totalEndpoints": 4,
                    "unread": false
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-01-26T23:17:34.303Z"
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|timestamp|
>|---|---|---|
>| {'id': '78b465c0-9dc5-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T22:04:57.756Z', 'statusTimestamp': '2023-01-26T22:14:29.778Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'ecc22120-9daa-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T18:54:56.050Z', 'statusTimestamp': '2023-01-26T19:08:45.185Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '29dab720-9d1f-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-26T02:14:29.010Z', 'statusTimestamp': '2023-01-26T18:52:06.437Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T11:48:56.059Z', 'statusTimestamp': '2023-01-26T02:13:33.006Z', 'status': 'closed', 'contacts': 98, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 28, '989': 69, '4232': 1}, 'totalEndpoints': 4, 'lastContact': '2023-01-24T21:17:50Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'f563af00-9bda-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-24T11:33:44.048Z', 'statusTimestamp': '2023-01-24T11:45:59.944Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '2bc88020-9b2c-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T14:42:33.378Z', 'statusTimestamp': '2023-01-24T11:33:24.832Z', 'status': 'closed', 'contacts': 10, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 10}, 'totalEndpoints': 5, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '9b430be0-9b1e-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T13:05:27.454Z', 'statusTimestamp': '2023-01-23T14:24:09.462Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '249b6b90-9b14-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-23T11:50:33.417Z', 'statusTimestamp': '2023-01-23T12:57:59.609Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'cae5a990-99e6-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T23:53:24.393Z', 'statusTimestamp': '2023-01-21T23:58:48.655Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '7db7c400-99e1-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T23:15:27.424Z', 'statusTimestamp': '2023-01-21T23:51:47.406Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 7}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '72067f80-99cc-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T20:44:48.376Z', 'statusTimestamp': '2023-01-21T23:13:41.679Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 2, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': 'eaba8420-9932-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-21T02:25:48.386Z', 'statusTimestamp': '2023-01-21T02:27:53.605Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '0f055c60-9901-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-20T20:28:54.438Z', 'statusTimestamp': '2023-01-21T02:24:55.326Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-20T14:37:02.228Z'},<br/>{'id': '3b43f070-982a-11ed-980e-915fb2011ca7', 'timestamp': '2023-01-19T18:51:06.871Z', 'statusTimestamp': '2023-01-20T15:54:56.324Z', 'status': 'closed', 'contacts': 134, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'4055': 1, '0': 108, '989': 25}, 'totalEndpoints': 10, 'lastContact': '2023-01-18T17:02:46Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-18T15:32:25.126Z'},<br/>{'id': 'aedb44c0-978a-11ed-b6d7-3f0c59c638d9', 'timestamp': '2023-01-18T23:49:01.324Z', 'statusTimestamp': '2023-01-19T16:42:19.541Z', 'status': 'closed', 'contacts': 36, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 36}, 'totalEndpoints': 2, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '8b02a730-9778-11ed-b6d7-3f0c59c638d9', 'timestamp': '2023-01-18T21:39:10.243Z', 'statusTimestamp': '2023-01-18T23:44:37.049Z', 'status': 'closed', 'contacts': 26, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 26}, 'totalEndpoints': 2, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '5c99aa20-95bf-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-16T17:01:04.322Z', 'statusTimestamp': '2023-01-18T21:38:33.960Z', 'status': 'closed', 'contacts': 131, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 130, '4055': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-18T15:32:25.126Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-16T17:00:18.868Z'},<br/>{'id': '7094dee0-8c6a-11ed-b0f8-a7e340234a4e', 'timestamp': '2023-01-04T20:00:30.158Z', 'statusTimestamp': '2023-01-16T16:54:32.918Z', 'status': 'closed', 'contacts': 1053, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1045, '4055': 4, '4061': 3, '1580': 1}, 'totalEndpoints': 5, 'lastContact': '2023-01-16T16:01:28.124Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-04T20:00:06.375Z'},<br/>{'id': 'b27b1d90-8780-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-29T13:57:13.833Z', 'statusTimestamp': '2023-01-04T19:11:56.620Z', 'status': 'closed', 'contacts': 24, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 22, '989': 1, '4053': 1}, 'totalEndpoints': 3, 'lastContact': '2023-01-04T19:00:52.902Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-29T13:57:01.548Z'},<br/>{'id': 'c97f79e0-870e-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-29T00:21:49.822Z', 'statusTimestamp': '2022-12-29T13:54:35.413Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 1, 'lastContact': '2022-12-29T13:50:21.218Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-29T00:21:38.089Z'},<br/>{'id': '6abbae10-870e-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-29T00:19:10.833Z', 'statusTimestamp': '2022-12-29T00:20:51.490Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-29T00:18:57.237Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-29T00:18:57.237Z'},<br/>{'id': '41ed0390-870d-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-29T00:10:52.873Z', 'statusTimestamp': '2022-12-29T00:18:37.071Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-12-29T00:15:37.061Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-29T00:10:39.969Z'},<br/>{'id': 'fb392f80-75b6-11ed-89c2-6136df938368', 'timestamp': '2022-12-06T22:40:27.768Z', 'statusTimestamp': '2022-12-28T23:50:06.608Z', 'status': 'closed', 'contacts': 11, 'adversaries': ['javxr.com'], 'adversaryId': 'javxr.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'0': 10, '2267': 1}, 'totalEndpoints': 2, 'lastContact': '2022-12-22T18:29:18.846Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-06T22:40:14.671Z'},<br/>{'id': '6c5393c0-7a37-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-12T16:09:57.756Z', 'statusTimestamp': '2022-12-28T23:05:23.814Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['cnt.statistic.date'], 'adversaryId': 'cnt.statistic.date', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-12T16:09:46.405Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-12T16:09:46.405Z'},<br/>{'id': '9326b8f0-8226-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-22T18:29:30.751Z', 'statusTimestamp': '2022-12-27T20:39:23.918Z', 'status': 'closed', 'contacts': 7, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1, '2254': 6}, 'totalEndpoints': 4, 'lastContact': '2022-12-23T22:34:34.191Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-22T18:29:08.846Z'},<br/>{'id': '6d178850-7d5e-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-16T16:26:42.901Z', 'statusTimestamp': '2022-12-21T16:23:38.937Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1, '2254': 1}, 'totalEndpoints': 2, 'lastContact': '2022-12-16T19:20:59.642Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '86515610-7d4b-11ed-a600-d53ba4d2bb70', 'timestamp': '2022-12-16T14:11:24.785Z', 'statusTimestamp': '2022-12-16T14:13:21.021Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '2082d5a0-7960-11ed-89c2-6136df938368', 'timestamp': '2022-12-11T14:28:48.762Z', 'statusTimestamp': '2022-12-16T14:09:27.416Z', 'status': 'closed', 'contacts': 18, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 17, '3938': 1}, 'totalEndpoints': 3, 'lastContact': '2022-12-12T19:29:12.308Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '4657b300-795f-11ed-89c2-6136df938368', 'timestamp': '2022-12-11T14:22:42.736Z', 'statusTimestamp': '2022-12-11T14:23:29.691Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'b62ddba0-78f6-11ed-89c2-6136df938368', 'timestamp': '2022-12-11T01:54:13.210Z', 'statusTimestamp': '2022-12-11T14:20:58.708Z', 'status': 'closed', 'contacts': 12, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 12}, 'totalEndpoints': 2, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'cdb76f10-78e8-11ed-89c2-6136df938368', 'timestamp': '2022-12-11T00:14:39.745Z', 'statusTimestamp': '2022-12-11T00:23:20.854Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 3}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'b20661c0-78e5-11ed-89c2-6136df938368', 'timestamp': '2022-12-10T23:52:24.796Z', 'statusTimestamp': '2022-12-11T00:13:46.832Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'fd6ba400-78e4-11ed-89c2-6136df938368', 'timestamp': '2022-12-10T23:47:21.792Z', 'statusTimestamp': '2022-12-10T23:50:17.331Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'fdba55b0-78e3-11ed-89c2-6136df938368', 'timestamp': '2022-12-10T23:40:12.811Z', 'statusTimestamp': '2022-12-10T23:45:42.579Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '55131840-77c9-11ed-89c2-6136df938368', 'timestamp': '2022-12-09T13:56:51.780Z', 'statusTimestamp': '2022-12-10T23:29:17.060Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['cnt.statistic.date'], 'adversaryId': 'cnt.statistic.date', 'adversaryTypes': ['Malware', 'Mining'], 'description': 'Malicious domain', 'labelDistribution': {'2148': 1, '0': 3}, 'totalEndpoints': 2, 'lastContact': '2022-12-09T22:35:48.305Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-08T14:14:05Z'},<br/>{'id': '6ea05420-78dd-11ed-89c2-6136df938368', 'timestamp': '2022-12-10T22:53:15.746Z', 'statusTimestamp': '2022-12-10T23:29:16.415Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'b49fdaf0-782d-11ed-89c2-6136df938368', 'timestamp': '2022-12-10T01:55:21.759Z', 'statusTimestamp': '2022-12-10T22:18:40.298Z', 'status': 'closed', 'contacts': 19, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 19}, 'totalEndpoints': 3, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'f7153610-782c-11ed-89c2-6136df938368', 'timestamp': '2022-12-10T01:50:03.761Z', 'statusTimestamp': '2022-12-10T01:54:57.549Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'a8666390-782c-11ed-89c2-6136df938368', 'timestamp': '2022-12-10T01:47:51.753Z', 'statusTimestamp': '2022-12-10T01:49:38.902Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'faf4afa0-782b-11ed-89c2-6136df938368', 'timestamp': '2022-12-10T01:43:00.762Z', 'statusTimestamp': '2022-12-10T01:46:24.981Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '9d9d4710-7815-11ed-89c2-6136df938368', 'timestamp': '2022-12-09T23:02:55.233Z', 'statusTimestamp': '2022-12-10T01:42:33.470Z', 'status': 'closed', 'contacts': 18, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 18}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': 'a003ee30-7812-11ed-89c2-6136df938368', 'timestamp': '2022-12-09T22:41:30.771Z', 'statusTimestamp': '2022-12-09T23:01:39.625Z', 'status': 'closed', 'contacts': 4, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 4}, 'totalEndpoints': 1, 'lastContact': '2022-10-20T14:37:02.228Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '1ab96150-77eb-11ed-89c2-6136df938368', 'timestamp': '2022-12-09T17:58:36.773Z', 'statusTimestamp': '2022-12-09T22:40:19.890Z', 'status': 'closed', 'contacts': 46, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 46}, 'totalEndpoints': 2, 'lastContact': '2022-12-09T22:35:38.305Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-09T17:58:14.664Z'},<br/>{'id': '6d490cf0-77ea-11ed-89c2-6136df938368', 'timestamp': '2022-12-09T17:53:45.791Z', 'statusTimestamp': '2022-12-09T17:55:55.295Z', 'status': 'closed', 'contacts': 2, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2}, 'totalEndpoints': 1, 'lastContact': '2022-12-09T17:53:30.786Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-09T17:53:25.070Z'},<br/>{'id': '5c75c470-7670-11ed-89c2-6136df938368', 'timestamp': '2022-12-07T20:47:27.799Z', 'statusTimestamp': '2022-12-09T17:52:49.935Z', 'status': 'closed', 'contacts': 13, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 2, '2254': 1, '989': 10}, 'totalEndpoints': 3, 'lastContact': '2022-12-09T17:14:35.344Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-07T20:47:07.573Z'},<br/>{'id': '6fb9fe60-75a4-11ed-89c2-6136df938368', 'timestamp': '2022-12-06T20:27:42.790Z', 'statusTimestamp': '2022-12-07T20:46:55.216Z', 'status': 'closed', 'contacts': 16, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 12, '989': 4}, 'totalEndpoints': 1, 'lastContact': '2022-12-06T22:40:04.671Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-06T20:27:21.461Z'},<br/>{'id': '65540620-75b1-11ed-89c2-6136df938368', 'timestamp': '2022-12-06T22:00:28.802Z', 'statusTimestamp': '2022-12-06T22:40:06.511Z', 'status': 'closed', 'contacts': 3, 'adversaries': ['javxr.com'], 'adversaryId': 'javxr.com', 'adversaryTypes': ['Mining'], 'description': 'CryptoMining domain', 'labelDistribution': {'989': 2, '0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-06T22:11:15.294Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-06T22:00:16.389Z'},<br/>{'id': 'eb797cc0-75a3-11ed-89c2-6136df938368', 'timestamp': '2022-12-06T20:24:00.908Z', 'statusTimestamp': '2022-12-06T20:26:23.878Z', 'status': 'closed', 'contacts': 1, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'0': 1}, 'totalEndpoints': 1, 'lastContact': '2022-12-06T20:23:37.896Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-12-06T20:23:37.896Z'},<br/>{'id': 'e3542c10-70d6-11ed-89c2-6136df938368', 'timestamp': '2022-11-30T17:46:15.761Z', 'statusTimestamp': '2022-12-06T20:22:40.754Z', 'status': 'closed', 'contacts': 53, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'989': 49, '147': 1, '0': 3}, 'totalEndpoints': 6, 'lastContact': '2022-12-06T20:20:25.089Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-10-20T14:37:02.228Z'},<br/>{'id': '439be660-2e08-11ed-9b90-a51546bb08b5', 'timestamp': '2022-09-06T17:20:54.726Z', 'statusTimestamp': '2022-09-14T18:00:37.215Z', 'status': 'closed', 'contacts': 22, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'989': 10, '134': 10, '0': 2}, 'totalEndpoints': 4, 'lastContact': '2022-09-14T17:43:59.781Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2022-09-06T17:20:21.958Z'} | page: 1<br/>items: 50<br/>next: 2 | 2023-01-26T23:17:34.303Z |


### lumu-retrieve-endpoints-by-incident
***
Get a paginated summary of the endpoints affected by a specified incident.

| `{incident-uuid}` | uuid of the specific incident |
|---|---|


#### Base Command

`lumu-retrieve-endpoints-by-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | . | Optional | 
| page | . | Optional | 
| items | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveEndpointsByIncident.items.label | Number |  | 
| Lumu.RetrieveEndpointsByIncident.items.endpoint | String |  | 
| Lumu.RetrieveEndpointsByIncident.items.total | Number |  | 
| Lumu.RetrieveEndpointsByIncident.items.first | Date |  | 
| Lumu.RetrieveEndpointsByIncident.items.last | Date |  | 
| Lumu.RetrieveEndpointsByIncident.paginationInfo.page | Number |  | 
| Lumu.RetrieveEndpointsByIncident.paginationInfo.items | Number |  | 

#### Command example
```!lumu-retrieve-endpoints-by-incident lumu_incident_id=d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveEndpointsByIncident": {
            "items": [
                {
                    "endpoint": "Loacal-nesfpdm",
                    "first": "2022-12-20T14:37:02.228Z",
                    "label": 0,
                    "last": "2022-12-20T14:37:02.228Z",
                    "lastSourceId": "6d942a7a-d287-415e-9c09-3d6632a6a976",
                    "lastSourceType": "custom_collector",
                    "total": 1
                }
            ],
            "paginationInfo": {
                "items": 50,
                "page": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|items|paginationInfo|
>|---|---|
>| {'label': 0, 'endpoint': 'Loacal-nesfpdm', 'total': 1, 'first': '2022-12-20T14:37:02.228Z', 'last': '2022-12-20T14:37:02.228Z', 'lastSourceType': 'custom_collector', 'lastSourceId': '6d942a7a-d287-415e-9c09-3d6632a6a976'} | page: 1<br/>items: 50 |


### lumu-mark-incident-as-read
***
This transaction does not require any additional body parameters.

| `{incident-uuid}` | uuid of the specific incident |
|---|---|

>To associate a specific user to this transaction, include the header `Lumu-User-Id` with the user id as a value. [Read more](#user-identification-considerations).


#### Base Command

`lumu-mark-incident-as-read`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.MarkIncidentAsRead.statusCode | unknown |  | 

#### Command example
```!lumu-mark-incident-as-read lumu_incident_id=d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343 ```
#### Context Example
```json
{
    "Lumu": {
        "MarkIncidentAsRead": {
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>### Results
>|statusCode|
>|---|
>| 200 |


### lumu-mute-incident
***
| `{incident-uuid}` | uuid of the specific incident |
|---|---|

>To associate a specific user to this transaction, include the header `Lumu-User-Id` with the user id as a value. [Read more](#user-identification-considerations).


#### Base Command

`lumu-mute-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | . | Optional | 
| comment | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.MuteIncident.statusCode | unknown |  | 

#### Command example
```!lumu-mute-incident lumu_incident_id=d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343 comment="mute from cortex"```
#### Context Example
```json
{
    "Lumu": {
        "MuteIncident": {
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>### Results
>|statusCode|
>|---|
>| 200 |


### lumu-unmute-incident
***
| `{incident-uuid}` | uuid of the specific incident |
|---|---|

>To associate a specific user to this transaction, include the header `Lumu-User-Id` with the user id as a value. [Read more](#user-identification-considerations).


#### Base Command

`lumu-unmute-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | . | Optional | 
| comment | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.UnmuteIncident.statusCode | unknown |  | 

#### Command example
```!lumu-unmute-incident lumu_incident_id=d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343 comment="unmute from cortex"```
#### Context Example
```json
{
    "Lumu": {
        "UnmuteIncident": {
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>### Results
>|statusCode|
>|---|
>| 200 |


### lumu-consult-incidents-updates-through-rest
***
Lumu provides an endpoint to consult real-time updates on incident operations through REST when Websocket is not available.

Note: the date format in the updates received from the endpoint is in the UTC time zone and follows standards published in RFC 3339 and ISO 8601

| `{company-key}` | Your company's unique API key available at the [Lumu Portal](#access-and-authentication) |
| --- | --- |


#### Base Command

`lumu-consult-incidents-updates-through-rest`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | . | Optional | 
| items | . | Optional | 
| time | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.companyId | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.id | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.timestamp | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.statusTimestamp | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.status | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.contacts | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.adversaries | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.adversaryId | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.adversaryTypes | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.description | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.labelDistribution.0 | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.totalEndpoints | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.lastContact | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.unread | Boolean |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.hasPlaybackContacts | Boolean |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.firstContact | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.comment | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.companyId | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.openIncidents | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.totalContacts | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.DGA | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.C2C | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Network Scan | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Mining | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Phishing | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Spam | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Malware | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.totalEndpoints | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.companyId | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.id | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.timestamp | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.statusTimestamp | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.status | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.contacts | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.adversaries | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.adversaryId | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.adversaryTypes | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.description | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.labelDistribution.2148 | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.totalEndpoints | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.lastContact | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.unread | Boolean |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.hasPlaybackContacts | Boolean |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.firstContact | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.comment | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.companyId | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.id | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.timestamp | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.statusTimestamp | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.status | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.contacts | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.adversaries | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.adversaryId | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.adversaryTypes | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.description | String |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.labelDistribution.218 | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.totalEndpoints | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.lastContact | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.unread | Boolean |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.hasPlaybackContacts | Boolean |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.firstContact | Date |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.openIncidents | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.totalContacts | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.DGA | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.C2C | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Network Scan | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Mining | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Phishing | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Spam | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Malware | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.totalEndpoints | Number |  | 
| Lumu.ConsultIncidentsUpdatesThroughRest.offset | Number |  | 

#### Command example
```!lumu-consult-incidents-updates-through-rest items=50 offset=1085692 time=2```
#### Context Example
```json
{
    "Lumu": {
        "ConsultIncidentsUpdatesThroughRest": {
            "offset": 1085692,
            "updates": []
        }
    }
}
```

#### Human Readable Output

>### Results
>|offset|updates|
>|---|---|
>| 1085692 |  |


### lumu-close-incident
***
| `{incident-uuid}` | uuid of the specific incident |
|---|---|

>To associate a specific user to this transaction, include the header `Lumu-User-Id` with the user id as a value. [Read more](#user-identification-considerations).


#### Base Command

`lumu-close-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | . | Optional | 
| comment | . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.CloseIncident.statusCode | unknown |  | 

#### Command example
```!lumu-close-incident lumu_incident_id=d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343 comment="closed from Cortex"```
#### Context Example
```json
{
    "Lumu": {
        "CloseIncident": {
            "statusCode": 200
        }
    }
}
```

#### Human Readable Output

>### Results
>|statusCode|
>|---|
>| 200 |


### get-modified-remote-data
***



#### Base Command

`get-modified-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | . | Optional | 


#### Context Output

There is no context output for this command.
### get-remote-data
***



#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | . | Required | 
| id | . | Required | 


#### Context Output

There is no context output for this command.
### get-mapping-fields
***



#### Base Command

`get-mapping-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### lumu-clear-cache
***



#### Base Command

`lumu-clear-cache`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
#### Command example
```!lumu-clear-cache```
#### Human Readable Output

>cache cleared get_integration_context()={'cache': [], 'lumu_incidentsId': []}

### update-remote-system
***



#### Base Command

`update-remote-system`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | . | Required | 
| entries | . | Optional | 
| incident_changed | . | Optional | 
| remote_incident_id | . | Optional | 


#### Context Output

There is no context output for this command.
### lumu-get-cache
***



#### Base Command

`lumu-get-cache`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.GetCache.cache | string |  | 
| Lumu.GetCache.lumu_incidentsId | string |  | 

#### Command example
```!lumu-get-cache```
#### Context Example
```json
{
    "Lumu": {
        "GetCache": {
            "cache": [],
            "lumu_incidentsId": [
                "3c9a45b0-9b6c-11ed-980e-915fb2011ca7",
                "de703020-9bdf-11ed-a0c7-dd6f8e69d343",
                "a5cc17b0-9b6d-11ed-980e-915fb2011ca7",
                "f563af00-9bda-11ed-a0c7-dd6f8e69d343",
                "ecc22120-9daa-11ed-a0c7-dd6f8e69d343",
                "2bc88020-9b2c-11ed-980e-915fb2011ca7",
                "14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343",
                "acc03f50-9bf0-11ed-a0c7-dd6f8e69d343",
                "29dab720-9d1f-11ed-a0c7-dd6f8e69d343",
                "95e1ae70-98c8-11ed-980e-915fb2011ca7",
                "17af99e0-9b70-11ed-980e-915fb2011ca7",
                "3545a2d0-937b-11ed-b0f8-a7e340234a4e",
                "78b465c0-9dc5-11ed-a0c7-dd6f8e69d343",
                "d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343",
                "ee862770-69e5-11ed-89c2-6136df938368",
                "520cd7a0-9b6c-11ed-980e-915fb2011ca7"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|cache|lumu_incidentsId|
>|---|---|
>|  | 3c9a45b0-9b6c-11ed-980e-915fb2011ca7,<br/>de703020-9bdf-11ed-a0c7-dd6f8e69d343,<br/>a5cc17b0-9b6d-11ed-980e-915fb2011ca7,<br/>f563af00-9bda-11ed-a0c7-dd6f8e69d343,<br/>ecc22120-9daa-11ed-a0c7-dd6f8e69d343,<br/>2bc88020-9b2c-11ed-980e-915fb2011ca7,<br/>14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343,<br/>acc03f50-9bf0-11ed-a0c7-dd6f8e69d343,<br/>29dab720-9d1f-11ed-a0c7-dd6f8e69d343,<br/>95e1ae70-98c8-11ed-980e-915fb2011ca7,<br/>17af99e0-9b70-11ed-980e-915fb2011ca7,<br/>3545a2d0-937b-11ed-b0f8-a7e340234a4e,<br/>78b465c0-9dc5-11ed-a0c7-dd6f8e69d343,<br/>d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343,<br/>ee862770-69e5-11ed-89c2-6136df938368,<br/>520cd7a0-9b6c-11ed-980e-915fb2011ca7 |


## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Lumu corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Lumu events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Lumu events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and Lumu events will be reflected in both directions. |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Lumu.
