SecOps operations - Reflect and manage the Lumu Incidents either from XSOAR Cortex or viceversa using the mirroring integration flow, https://lumu.io/
This integration was integrated and tested with version 20230207 of Lumu

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
    | Total Incident per fecthing using lumu endpoint |  | False |
    | Max time in seconds per fecthing using lumu endpoint |  | False |
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
| page | page requested. | Optional | 
| items | items requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveLabels.labels.id | Number | label id | 
| Lumu.RetrieveLabels.labels.name | String | label name | 
| Lumu.RetrieveLabels.labels.relevance | Number | label relevance | 
| Lumu.RetrieveLabels.paginationInfo.page | Number | current page | 
| Lumu.RetrieveLabels.paginationInfo.items | Number | current items | 
| Lumu.RetrieveLabels.paginationInfo.next | Number | next page | 
| Lumu.RetrieveLabels.paginationInfo.prev | Number | previous page | 

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

>### Labels
>|Id|Name|Relevance|
>|---|---|---|
>| 51 | Mi Ofi | 1 |
>| 112 | Lab1 | 1 |
>| 113 | Lab2 | 1 |
>| 134 | cd test | 1 |
>| 147 | cd | 1 |
>| 173 | VA 3.1.2 Test | 1 |
>| 218 | acastaneda | 1 |
>| 227 | VA 1.3.3 Label | 1 |
>| 280 | client test | 1 |
>| 331 | VA 3.1.3 | 1 |
>| 375 | Pablo Home | 1 |
>| 384 | jcastellanos | 1 |
>| 548 | QA AgentLabel | 1 |
>| 648 | PaloAltoFw | 1 |
>| 754 | Low | 1 |
>| 805 | felipeg-test1 | 1 |
>| 807 | new label | 1 |
>| 822 | DnsPacketsCol | 1 |
>| 825 | Sophos label | 1 |
>| 864 | CTIS_TEST | 3 |
>| 989 | aarguelles | 1 |
>| 994 | QA AgentLabelNetflow | 2 |
>| 1004 | LumuChannel-Test | 2 |
>| 1007 | qwertylabel1 | 1 |
>| 1009 | Oscar | 1 |
>| 1010 | nuevo_label | 1 |
>| 1013 | ForcePoint | 2 |
>| 1014 | felipeGPLabel | 1 |
>| 1050 | McafeeLabel | 1 |
>| 1087 | Garf | 1 |
>| 1179 | FGiraldo-VA | 2 |
>| 1189 | BarracudaLB | 2 |
>| 1280 | SonicWallLabel | 1 |
>| 1308 | Karevalo PROD label | 2 |
>| 1340 | Kevin Arevalo test | 1 |
>| 1409 | Demo | 3 |
>| 1426 | newMSPFelipe | 2 |
>| 1580 | Raul Test Label | 1 |
>| 1651 | dcaldas | 2 |
>| 1791 | ChangeKafka | 2 |
>| 1792 | FGP-personalAgent | 3 |
>| 1851 | UmbrellaPull-FGP | 2 |
>| 1876 | CTI MOBILE | 3 |
>| 1885 | Umbrella DC label | 3 |
>| 1988 | UmbrellaPull2 | 3 |
>| 2041 | mmeneses | 1 |
>| 2144 | InternalLAN | 3 |
>| 2148 | AWSVpcProd | 1 |
>| 2150 | 1.0.2.0 Label | 2 |
>| 2204 | TEST_VT | 3 |


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
| label_id | label id requested. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveASpecificLabel.id | Number | label id | 
| Lumu.RetrieveASpecificLabel.name | String | label name | 
| Lumu.RetrieveASpecificLabel.relevance | Number | label relevance | 

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

>### Label
>|Id|Name|Relevance|
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
| page | page requested. | Optional | 
| items | items requested. | Optional | 
| fromdate | from date in ISO string format. | Optional | 
| todate | to date in ISO string format. | Optional | 
| status | choose status: open,muted,closed. | Optional | 
| adversary_types | choose types: c2c,malware,dga,mining,spam,phishing. | Optional | 
| labels | choose labels. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveIncidents.items.id | String | Lumu incident id | 
| Lumu.RetrieveIncidents.items.timestamp | Date | Lumu timestamp | 
| Lumu.RetrieveIncidents.items.statusTimestamp | Date | Lumu statusTimestamp | 
| Lumu.RetrieveIncidents.items.status | String | Lumu status | 
| Lumu.RetrieveIncidents.items.contacts | Number | Lumu contacts | 
| Lumu.RetrieveIncidents.items.adversaries | String | umu adversaries | 
| Lumu.RetrieveIncidents.items.adversaryTypes | String | Lumu adversaryTypes | 
| Lumu.RetrieveIncidents.items.labelDistribution | Number | Lumu incident labels  | 
| Lumu.RetrieveIncidents.items.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.RetrieveIncidents.items.lastContact | Date | Lumu lastContact | 
| Lumu.RetrieveIncidents.items.unread | Boolean | Lumu unread | 
| Lumu.RetrieveIncidents.paginationInfo.page | Number | current page | 
| Lumu.RetrieveIncidents.paginationInfo.items | Number | current items | 

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
                    "contacts": 2,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "9e9238e0-a73d-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-07T23:17:41.358Z",
                    "timestamp": "2023-02-07T23:17:41.358Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "104.156.63.145"
                    ],
                    "adversaryId": "104.156.63.145",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 5,
                    "description": "Malware family Agentemis",
                    "firstContact": "2023-02-08T03:10:49Z",
                    "hasPlaybackContacts": false,
                    "id": "eef6afd0-a72b-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "2144": 5
                    },
                    "lastContact": "2023-02-08T03:10:51Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-07T21:11:05.293Z",
                    "timestamp": "2023-02-07T21:11:05.293Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "104.156.63.145"
                    ],
                    "adversaryId": "104.156.63.145",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 5,
                    "description": "Malware family Agentemis",
                    "firstContact": "2023-02-08T03:09:07Z",
                    "hasPlaybackContacts": false,
                    "id": "b22ba330-a72b-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "2144": 5
                    },
                    "lastContact": "2023-02-08T03:09:09Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-07T21:10:17.404Z",
                    "timestamp": "2023-02-07T21:09:23.299Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "104.156.63.145"
                    ],
                    "adversaryId": "104.156.63.145",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 10,
                    "description": "Malware family Agentemis",
                    "firstContact": "2023-02-08T00:50:58Z",
                    "hasPlaybackContacts": false,
                    "id": "65a131f0-a718-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "2144": 10
                    },
                    "lastContact": "2023-02-08T00:52:12Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-07T21:07:38.628Z",
                    "timestamp": "2023-02-07T18:51:14.447Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.spotifyvault.com"
                    ],
                    "adversaryId": "www.spotifyvault.com",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 4,
                    "description": "Phishing domain",
                    "firstContact": "2023-02-07T17:02:29Z",
                    "hasPlaybackContacts": false,
                    "id": "6d06a650-a709-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "147": 2,
                        "2144": 2
                    },
                    "lastContact": "2023-02-07T23:10:10.721Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-07T17:04:04.405Z",
                    "timestamp": "2023-02-07T17:04:04.405Z",
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
                    "contacts": 12,
                    "description": "Activity Test Query",
                    "firstContact": "2023-02-07T15:51:15.463Z",
                    "hasPlaybackContacts": false,
                    "id": "826dd220-a6ff-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "0": 11,
                        "989": 1
                    },
                    "lastContact": "2023-02-07T15:51:15.463Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-07T23:08:53.658Z",
                    "timestamp": "2023-02-07T15:53:05.346Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ics-nett.com"
                    ],
                    "adversaryId": "ics-nett.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 3,
                    "description": "Malicious Content",
                    "firstContact": "2023-01-27T19:00:23.897Z",
                    "hasPlaybackContacts": true,
                    "id": "080189f0-a64b-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "2144": 2,
                        "4301": 1
                    },
                    "lastContact": "2023-02-07T23:10:30.115Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-06T18:21:10.543Z",
                    "timestamp": "2023-02-06T18:21:10.543Z",
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
                    "id": "eb611160-a638-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-06T16:19:52.211Z",
                    "timestamp": "2023-02-06T16:11:31.574Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.chg.com.br"
                    ],
                    "adversaryId": "www.chg.com.br",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 5,
                    "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                    "firstContact": "2023-02-03T19:01:00Z",
                    "hasPlaybackContacts": false,
                    "id": "d0ce2800-a3f5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 2,
                        "989": 3
                    },
                    "lastContact": "2023-02-03T19:22:57.892Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-03T19:06:08.384Z",
                    "timestamp": "2023-02-03T19:06:08.384Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.chg.com.br"
                    ],
                    "adversaryId": "www.chg.com.br",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 3,
                    "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                    "firstContact": "2023-02-03T19:01:00Z",
                    "hasPlaybackContacts": false,
                    "id": "608c0ee0-a3f5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "989": 3
                    },
                    "lastContact": "2023-02-03T19:01:30Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-03T19:05:06.851Z",
                    "timestamp": "2023-02-03T19:03:00.046Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.chg.com.br"
                    ],
                    "adversaryId": "www.chg.com.br",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 6,
                    "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                    "firstContact": "2023-02-26T18:57:00Z",
                    "hasPlaybackContacts": false,
                    "id": "6afd9ee0-a3f3-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "989": 6
                    },
                    "lastContact": "2023-02-26T18:57:30Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-03T19:01:12.035Z",
                    "timestamp": "2023-02-03T18:48:58.574Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "try2hack.nl"
                    ],
                    "adversaryId": "try2hack.nl",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Win32.Cl.B.Tilken",
                    "firstContact": "2023-02-03T18:17:59.597Z",
                    "hasPlaybackContacts": false,
                    "id": "22dccb80-a3ef-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "147": 1
                    },
                    "lastContact": "2023-02-03T18:17:59.597Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-03T18:18:19.576Z",
                    "timestamp": "2023-02-03T18:18:19.576Z",
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
                    "contacts": 2,
                    "description": "Malware family Trojan.Win32.Generic",
                    "firstContact": "2023-02-02T23:51:26.644Z",
                    "hasPlaybackContacts": false,
                    "id": "967c43e0-a354-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "989": 2
                    },
                    "lastContact": "2023-02-02T23:51:26.645Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-03T15:22:35.368Z",
                    "timestamp": "2023-02-02T23:52:01.566Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "musicaitaliana.com"
                    ],
                    "adversaryId": "musicaitaliana.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "QakBot",
                    "firstContact": "2023-01-28T04:46:11.531Z",
                    "hasPlaybackContacts": true,
                    "id": "cffb7650-a353-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:46:11.531Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-02T23:46:28.533Z",
                    "timestamp": "2023-02-02T23:46:28.533Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "soardigital.net"
                    ],
                    "adversaryId": "soardigital.net",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "QakBot",
                    "firstContact": "2023-01-13T17:37:32.767Z",
                    "hasPlaybackContacts": true,
                    "id": "17d791d0-a353-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4055": 1,
                        "51": 3
                    },
                    "lastContact": "2023-02-07T08:10:51.125Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-02T23:41:19.597Z",
                    "timestamp": "2023-02-02T23:41:19.597Z",
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
                    "contacts": 22,
                    "description": "Activity Test Query",
                    "firstContact": "2023-02-01T15:13:41.904Z",
                    "hasPlaybackContacts": false,
                    "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 9,
                        "1792": 1,
                        "989": 12
                    },
                    "lastContact": "2023-02-03T16:44:00.395Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-06T16:04:22.570Z",
                    "timestamp": "2023-02-01T15:14:17.061Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "smartvizx.com"
                    ],
                    "adversaryId": "smartvizx.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "QakBot",
                    "firstContact": "2023-01-28T03:04:15.908Z",
                    "hasPlaybackContacts": true,
                    "id": "0a017730-a1ee-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T03:04:15.908Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-02T17:08:28.378Z",
                    "timestamp": "2023-02-01T05:05:26.051Z",
                    "totalEndpoints": 1,
                    "unread": false
                }
            ],
            "paginationInfo": {
                "items": 50,
                "page": 1
            },
            "timestamp": "2023-02-07T23:20:07.544Z"
        }
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 9e9238e0-a73d-11ed-9fd0-e5fb50c818f6 | 0: 2 | 2022-12-20T14:37:02.228Z | open | 2023-02-07T23:17:41.358Z | 2023-02-07T23:17:41.358Z | 1 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 5 | Malware family Agentemis | 2023-02-08T03:10:49Z | false | eef6afd0-a72b-11ed-9fd0-e5fb50c818f6 | 2144: 5 | 2023-02-08T03:10:51Z | open | 2023-02-07T21:11:05.293Z | 2023-02-07T21:11:05.293Z | 1 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 5 | Malware family Agentemis | 2023-02-08T03:09:07Z | false | b22ba330-a72b-11ed-9fd0-e5fb50c818f6 | 2144: 5 | 2023-02-08T03:09:09Z | closed | 2023-02-07T21:10:17.404Z | 2023-02-07T21:09:23.299Z | 1 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 10 | Malware family Agentemis | 2023-02-08T00:50:58Z | false | 65a131f0-a718-11ed-9fd0-e5fb50c818f6 | 2144: 10 | 2023-02-08T00:52:12Z | closed | 2023-02-07T21:07:38.628Z | 2023-02-07T18:51:14.447Z | 1 | false |
>| www.spotifyvault.com | www.spotifyvault.com | Phishing | 4 | Phishing domain | 2023-02-07T17:02:29Z | false | 6d06a650-a709-11ed-9fd0-e5fb50c818f6 | 147: 2<br/>2144: 2 | 2023-02-07T23:10:10.721Z | open | 2023-02-07T17:04:04.405Z | 2023-02-07T17:04:04.405Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 12 | Activity Test Query | 2023-02-07T15:51:15.463Z | false | 826dd220-a6ff-11ed-9fd0-e5fb50c818f6 | 989: 1<br/>0: 11 | 2023-02-07T15:51:15.463Z | closed | 2023-02-07T23:08:53.658Z | 2023-02-07T15:53:05.346Z | 3 | false |
>| ics-nett.com | ics-nett.com | Malware | 3 | Malicious Content | 2023-01-27T19:00:23.897Z | true | 080189f0-a64b-11ed-a0c7-dd6f8e69d343 | 4301: 1<br/>2144: 2 | 2023-02-07T23:10:30.115Z | open | 2023-02-06T18:21:10.543Z | 2023-02-06T18:21:10.543Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | eb611160-a638-11ed-a0c7-dd6f8e69d343 | 0: 3 | 2022-12-20T14:37:02.228Z | closed | 2023-02-06T16:19:52.211Z | 2023-02-06T16:11:31.574Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 5 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-03T19:01:00Z | false | d0ce2800-a3f5-11ed-a0c7-dd6f8e69d343 | 989: 3<br/>0: 2 | 2023-02-03T19:22:57.892Z | open | 2023-02-03T19:06:08.384Z | 2023-02-03T19:06:08.384Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 3 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-03T19:01:00Z | false | 608c0ee0-a3f5-11ed-a0c7-dd6f8e69d343 | 989: 3 | 2023-02-03T19:01:30Z | closed | 2023-02-03T19:05:06.851Z | 2023-02-03T19:03:00.046Z | 2 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 6 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-26T18:57:00Z | false | 6afd9ee0-a3f3-11ed-a0c7-dd6f8e69d343 | 989: 6 | 2023-02-26T18:57:30Z | closed | 2023-02-03T19:01:12.035Z | 2023-02-03T18:48:58.574Z | 2 | false |
>| try2hack.nl | try2hack.nl | Malware | 1 | Malware family Trojan.Win32.Cl.B.Tilken | 2023-02-03T18:17:59.597Z | false | 22dccb80-a3ef-11ed-a0c7-dd6f8e69d343 | 147: 1 | 2023-02-03T18:17:59.597Z | open | 2023-02-03T18:18:19.576Z | 2023-02-03T18:18:19.576Z | 1 | false |
>| www.ascentive.com | www.ascentive.com | Malware | 2 | Malware family Trojan.Win32.Generic | 2023-02-02T23:51:26.644Z | false | 967c43e0-a354-11ed-a0c7-dd6f8e69d343 | 989: 2 | 2023-02-02T23:51:26.645Z | open | 2023-02-03T15:22:35.368Z | 2023-02-02T23:52:01.566Z | 1 | false |
>| musicaitaliana.com | musicaitaliana.com | Malware | 1 | QakBot | 2023-01-28T04:46:11.531Z | true | cffb7650-a353-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:46:11.531Z | open | 2023-02-02T23:46:28.533Z | 2023-02-02T23:46:28.533Z | 1 | false |
>| soardigital.net | soardigital.net | Malware | 4 | QakBot | 2023-01-13T17:37:32.767Z | true | 17d791d0-a353-11ed-a0c7-dd6f8e69d343 | 4055: 1<br/>51: 3 | 2023-02-07T08:10:51.125Z | open | 2023-02-02T23:41:19.597Z | 2023-02-02T23:41:19.597Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 22 | Activity Test Query | 2023-02-01T15:13:41.904Z | false | 182f3950-a243-11ed-a0c7-dd6f8e69d343 | 1792: 1<br/>989: 12<br/>0: 9 | 2023-02-03T16:44:00.395Z | closed | 2023-02-06T16:04:22.570Z | 2023-02-01T15:14:17.061Z | 5 | false |
>| smartvizx.com | smartvizx.com | Malware | 1 | QakBot | 2023-01-28T03:04:15.908Z | true | 0a017730-a1ee-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T03:04:15.908Z | closed | 2023-02-02T17:08:28.378Z | 2023-02-01T05:05:26.051Z | 1 | false |


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
            "timestamp": "2023-02-07T23:20:10.242Z"
        }
    }
}
```

#### Human Readable Output

>### Incidents
>**No entries.**


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
| lumu_incident_id | Lumu id requested. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveASpecificIncidentDetails.id | String | Lumu id | 
| Lumu.RetrieveASpecificIncidentDetails.timestamp | Date | Lumu timestamp | 
| Lumu.RetrieveASpecificIncidentDetails.isUnread | Boolean | Lumu isUnread | 
| Lumu.RetrieveASpecificIncidentDetails.contacts | Number | Lumu contacts | 
| Lumu.RetrieveASpecificIncidentDetails.adversaryId | String | Lumu adversaryId | 
| Lumu.RetrieveASpecificIncidentDetails.adversaries | String | Lumu adversaries | 
| Lumu.RetrieveASpecificIncidentDetails.adversaryTypes | String | Lumu adversaryTypes | 
| Lumu.RetrieveASpecificIncidentDetails.description | String | Lumu description | 
| Lumu.RetrieveASpecificIncidentDetails.labelDistribution | Number | Lumu incident label | 
| Lumu.RetrieveASpecificIncidentDetails.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.RetrieveASpecificIncidentDetails.lastContact | Date | Lumu lastContact | 
| Lumu.RetrieveASpecificIncidentDetails.actions.datetime | Date | Lumu actions.datetime | 
| Lumu.RetrieveASpecificIncidentDetails.actions.userId | Number | Lumu actions.userId | 
| Lumu.RetrieveASpecificIncidentDetails.actions.action | String | Lumu actions.action | 
| Lumu.RetrieveASpecificIncidentDetails.actions.comment | String | Lumu comment | 
| Lumu.RetrieveASpecificIncidentDetails.status | String | Lumu status | 
| Lumu.RetrieveASpecificIncidentDetails.statusTimestamp | Date | Lumu statusTimestamp | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.uuid | String | Lumu firstContactDetails.uuid | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.datetime | Date | Lumu firstContactDetails.datetime | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.host | String | Lumu firstContactDetails.host | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.types | String | Lumu firstContactDetails.types | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.details | String | Lumu firstContactDetails.details | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.endpointIp | String | Lumu firstContactDetails.endpointIp | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.endpointName | String | Lumu firstContactDetails.endpointName | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.label | Number | Lumu firstContactDetails.label | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceType | String | Lumu firstContactDetails.sourceType | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceId | String | Lumu firstContactDetails.sourceId | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.question.type | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.question.type | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.question.name | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.question.name | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.question.class | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.question.class | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.responseCode | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.responseCode | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.authoritative | Boolean | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.flags.authoritative | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_available | Boolean | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_available | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.truncated_response | Boolean | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.flags.truncated_response | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.checking_disabled | Boolean | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.flags.checking_disabled | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_desired | Boolean | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_desired | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.flags.authentic_data | Boolean | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.flags.authentic_data | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.name | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.answers.name | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.type | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.answers.type | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.class | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.answers.class | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.ttl | Number | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.answers.ttl | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.answers.data | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.answers.data | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.sourceData.DNSPacketExtraInfo.opCode | String | Lumu firstContactDetails.sourceData.DNSPacketExtraInfo.opCode | 
| Lumu.RetrieveASpecificIncidentDetails.firstContactDetails.isPlayback | Boolean | Lumu firstContactDetails.isPlayback | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.uuid | String | Lumu lastContactDetails.uuid | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.datetime | Date | Lumu lastContactDetails.datetime | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.host | String | Lumu lastContactDetails.host | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.types | String | Lumu lastContactDetails.types | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.details | String | Lumu lastContactDetails.details | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.endpointIp | String | Lumu lastContactDetails.endpointIp | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.endpointName | String | Lumu lastContactDetails.endpointName | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.label | Number | Lumu lastContactDetails.label | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceType | String | Lumu lastContactDetails.sourceType | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceId | String | Lumu lastContactDetails.sourceId | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.question.type | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.question.type | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.question.name | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.question.name | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.question.class | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.question.class | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.responseCode | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.responseCode | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.authoritative | Boolean | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.flags.authoritative | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_available | Boolean | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_available | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.truncated_response | Boolean | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.flags.truncated_response | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.checking_disabled | Boolean | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.flags.checking_disabled | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_desired | Boolean | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.flags.recursion_desired | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.flags.authentic_data | Boolean | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.flags.authentic_data | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.name | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.answers.name | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.type | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.answers.type | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.class | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.answers.class | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.ttl | Number | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.answers.ttl | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.answers.data | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.answers.data | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.sourceData.DNSPacketExtraInfo.opCode | String | Lumu lastContactDetails.sourceData.DNSPacketExtraInfo.opCode | 
| Lumu.RetrieveASpecificIncidentDetails.lastContactDetails.isPlayback | Boolean | Lumu lastContactDetails.isPlayback | 

#### Command example
```!lumu-retrieve-a-specific-incident-details lumu_incident_id=9e9238e0-a73d-11ed-9fd0-e5fb50c818f6```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveASpecificIncidentDetails": {
            "actions": [
                {
                    "action": "close",
                    "comment": "from XSOAR Cortex 20230207_232042 closed from Cortex, hmacsha256:03e3787c1bd05e2d0712ab524633e8ca3f0caffd683b5ef3c84ace7a241936ba",
                    "datetime": "2023-02-07T23:20:42.817Z",
                    "userId": 0
                },
                {
                    "action": "comment",
                    "comment": "from XSOAR Cortex 20230207_232040 from cortex, palo alto, hmacsha256:0c7a0308aeb33cf36b52fb0d1efa18f9eb71ecd6b5b6987c53cbc460b6d19a99",
                    "datetime": "2023-02-07T23:20:40.912Z",
                    "userId": 0
                },
                {
                    "action": "unmute",
                    "comment": "from XSOAR Cortex 20230207_232038 unmute from cortex, hmacsha256:170cdef0d2caa8297e585f438c084c31713fd910941117465a1db7a2af323c06",
                    "datetime": "2023-02-07T23:20:38.919Z",
                    "userId": 0
                },
                {
                    "action": "mute",
                    "comment": "from XSOAR Cortex 20230207_232036 mute from cortex, hmacsha256:7faef97643c44288b9bcaa2017f8ba31c12fa5b9380e29b0e7458521438bfd2b",
                    "datetime": "2023-02-07T23:20:37.018Z",
                    "userId": 0
                },
                {
                    "action": "read",
                    "comment": "",
                    "datetime": "2023-02-07T23:18:50.305Z",
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
            "contacts": 2,
            "description": "Activity Test Query",
            "firstContactDetails": {
                "datetime": "2022-12-20T14:37:02.228Z",
                "details": [
                    "Activity Test Query"
                ],
                "endpointIp": "192.168.110.113",
                "endpointName": "Loacal-nesfapdm",
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
                "uuid": "c45b8540-8073-11ed-9a2f-0f9b6b993ffe"
            },
            "hasPlaybackContacts": false,
            "id": "9e9238e0-a73d-11ed-9fd0-e5fb50c818f6",
            "isUnread": false,
            "labelDistribution": {
                "0": 2
            },
            "lastContact": "2022-12-20T14:37:02.228Z",
            "lastContactDetails": {
                "datetime": "2022-12-20T14:37:02.228Z",
                "details": [
                    "Activity Test Query"
                ],
                "endpointIp": "192.168.110.113",
                "endpointName": "Loacal-nesfapdm",
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
                "uuid": "c45b8540-8073-11ed-9a2f-0f9b6b993ffe"
            },
            "status": "closed",
            "statusTimestamp": "2023-02-07T23:20:42.817Z",
            "timestamp": "2023-02-07T23:17:41.358Z",
            "totalEndpoints": 1
        }
    }
}
```

#### Human Readable Output

>### Incident
>|Actions|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact Details|Has Playback Contacts|Id|Is Unread|Label Distribution|Last Contact|Last Contact Details|Status|Status Timestamp|Timestamp|Total Endpoints|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| {'datetime': '2023-02-07T23:20:42.817Z', 'userId': 0, 'action': 'close', 'comment': 'from XSOAR Cortex 20230207_232042 closed from Cortex, hmacsha256:03e3787c1bd05e2d0712ab524633e8ca3f0caffd683b5ef3c84ace7a241936ba'},<br/>{'datetime': '2023-02-07T23:20:40.912Z', 'userId': 0, 'action': 'comment', 'comment': 'from XSOAR Cortex 20230207_232040 from cortex, palo alto, hmacsha256:0c7a0308aeb33cf36b52fb0d1efa18f9eb71ecd6b5b6987c53cbc460b6d19a99'},<br/>{'datetime': '2023-02-07T23:20:38.919Z', 'userId': 0, 'action': 'unmute', 'comment': 'from XSOAR Cortex 20230207_232038 unmute from cortex, hmacsha256:170cdef0d2caa8297e585f438c084c31713fd910941117465a1db7a2af323c06'},<br/>{'datetime': '2023-02-07T23:20:37.018Z', 'userId': 0, 'action': 'mute', 'comment': 'from XSOAR Cortex 20230207_232036 mute from cortex, hmacsha256:7faef97643c44288b9bcaa2017f8ba31c12fa5b9380e29b0e7458521438bfd2b'},<br/>{'datetime': '2023-02-07T23:18:50.305Z', 'userId': 6252, 'action': 'read', 'comment': ''} | activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | uuid: c45b8540-8073-11ed-9a2f-0f9b6b993ffe<br/>datetime: 2022-12-20T14:37:02.228Z<br/>host: activity.lumu.io<br/>types: Spam<br/>details: Activity Test Query<br/>endpointIp: 192.168.110.113<br/>endpointName: Loacal-nesfapdm<br/>label: 0<br/>sourceType: custom_collector<br/>sourceId: 6d942a7a-d287-415e-9c09-3d6632a6a976<br/>sourceData: {"DNSQueryExtraInfo": {"queryType": "A"}}<br/>isPlayback: false | false | 9e9238e0-a73d-11ed-9fd0-e5fb50c818f6 | false | 0: 2 | 2022-12-20T14:37:02.228Z | uuid: c45b8540-8073-11ed-9a2f-0f9b6b993ffe<br/>datetime: 2022-12-20T14:37:02.228Z<br/>host: activity.lumu.io<br/>types: Spam<br/>details: Activity Test Query<br/>endpointIp: 192.168.110.113<br/>endpointName: Loacal-nesfapdm<br/>label: 0<br/>sourceType: custom_collector<br/>sourceId: 6d942a7a-d287-415e-9c09-3d6632a6a976<br/>sourceData: {"DNSQueryExtraInfo": {"queryType": "A"}}<br/>isPlayback: false | closed | 2023-02-07T23:20:42.817Z | 2023-02-07T23:17:41.358Z | 1 |


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
| lumu_incident_id | Lumu id requested. | Required | 
| hash | Lumu hash type. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveASpecificIncidentContext.adversary_id | String | Lumu adversary_id | 
| Lumu.RetrieveASpecificIncidentContext.currently_active | Boolean | Lumu currently_active | 
| Lumu.RetrieveASpecificIncidentContext.deactivated_on | Date | Lumu deactivated_on | 
| Lumu.RetrieveASpecificIncidentContext.mitre.details.tactic | String | Lumu mitre.details.tactic | 
| Lumu.RetrieveASpecificIncidentContext.mitre.details.techniques | String | Lumu mitre.details.techniques | 
| Lumu.RetrieveASpecificIncidentContext.mitre.matrix | String | Lumu mitre.matrix | 
| Lumu.RetrieveASpecificIncidentContext.mitre.version | String | Lumu mitre.version | 
| Lumu.RetrieveASpecificIncidentContext.related_files | String | Lumu related_files | 
| Lumu.RetrieveASpecificIncidentContext.threat_details | String | Lumu threat_details | 
| Lumu.RetrieveASpecificIncidentContext.threat_triggers | String | Lumu threat_triggers | 
| Lumu.RetrieveASpecificIncidentContext.playbooks | String | Lumu playbooks | 
| Lumu.RetrieveASpecificIncidentContext.external_resources | String | Lumu external_resources | 
| Lumu.RetrieveASpecificIncidentContext.timestamp | Date | Lumu timestamp | 

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
                "https://blog.morphisec.com/qakbot-qbot-maldoc-two-new-techniques",
                "https://media.scmagazine.com/documents/225/bae_qbot_report_56053.pdf",
                "https://web.archive.org/web/20201207094648/https://go.group-ib.com/rs/689-LRE-818/images/Group-IB_Egregor_Ransomware.pdf",
                "https://urlhaus.abuse.ch/host/jits.ac.in/",
                "https://malwareandstuff.com/an-old-enemy-diving-into-qbot-part-3/",
                "https://malwareandstuff.com/an-old-enemy-diving-into-qbot-part-1/",
                "https://twitter.com/redcanary/status/1334224861628039169",
                "https://www.vkremez.com/2018/07/lets-learn-in-depth-reversing-of-qakbot.html",
                "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot",
                "https://unit42.paloaltonetworks.com/wireshark-tutorial-emotet-infection/",
                "https://elis531989.medium.com/funtastic-packers-and-where-to-find-them-41429a7ef9a7",
                "https://research.checkpoint.com/2020/exploring-qbots-latest-attack-methods/",
                "https://www.hornetsecurity.com/en/security-information/qakbot-malspam-leading-to-prolock/",
                "https://raw.githubusercontent.com/fboldewin/When-ransomware-hits-an-ATM-giant---The-Diebold-Nixdorf-case-dissected/main/When%20ransomware%20hits%20an%20ATM%20giant%20-%20The%20Diebold%20Nixdorf%20case%20dissected%20-%20Group-IB%20CyberCrimeCon2020.pdf",
                "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2020-CTI-010.pdf",
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
                "qbot",
                "Pinkslipbot",
                "gayfgt",
                "Gafgyt",
                "Qbot",
                "Bashlite",
                "PinkSlipBot",
                "Qakbot",
                "lizkebab",
                "Quakbot",
                "Akbot",
                "torlus",
                "Qbot "
            ],
            "threat_triggers": [
                "https://jits.ac.in/TS.php"
            ],
            "timestamp": "2023-02-07T23:46:09.442Z"
        }
    }
}
```

#### Human Readable Output

>### Incident
>|Adversary _ Id|Currently _ Active|External _ Resources|Mitre|Playbooks|Threat _ Details|Threat _ Triggers|Timestamp|
>|---|---|---|---|---|---|---|---|
>| jits.ac.in | true | https:<span>//</span>blog.morphisec.com/qakbot-qbot-maldoc-two-new-techniques,<br/>https:<span>//</span>media.scmagazine.com/documents/225/bae_qbot_report_56053.pdf,<br/>https:<span>//</span>web.archive.org/web/20201207094648/https:<span>//</span>go.group-ib.com/rs/689-LRE-818/images/Group-IB_Egregor_Ransomware.pdf,<br/>https:<span>//</span>urlhaus.abuse.ch/host/jits.ac.in/,<br/>https:<span>//</span>malwareandstuff.com/an-old-enemy-diving-into-qbot-part-3/,<br/>https:<span>//</span>malwareandstuff.com/an-old-enemy-diving-into-qbot-part-1/,<br/>https:<span>//</span>twitter.com/redcanary/status/1334224861628039169,<br/>https:<span>//</span>www.vkremez.com/2018/07/lets-learn-in-depth-reversing-of-qakbot.html,<br/>https:<span>//</span>malpedia.caad.fkie.fraunhofer.de/details/win.qakbot,<br/>https:<span>//</span>unit42.paloaltonetworks.com/wireshark-tutorial-emotet-infection/,<br/>https:<span>//</span>elis531989.medium.com/funtastic-packers-and-where-to-find-them-41429a7ef9a7,<br/>https:<span>//</span>research.checkpoint.com/2020/exploring-qbots-latest-attack-methods/,<br/>https:<span>//</span>www.hornetsecurity.com/en/security-information/qakbot-malspam-leading-to-prolock/,<br/>https:<span>//</span>raw.githubusercontent.com/fboldewin/When-ransomware-hits-an-ATM-giant---The-Diebold-Nixdorf-case-dissected/main/When%20ransomware%20hits%20an%20ATM%20giant%20-%20The%20Diebold%20Nixdorf%20case%20dissected%20-%20Group-IB%20CyberCrimeCon2020.pdf,<br/>https:<span>//</span>www.cert.ssi.gouv.fr/uploads/CERTFR-2020-CTI-010.pdf,<br/>https:<span>//</span>blog.quosec.net/posts/grap_qakbot_navigation/,<br/>https:<span>//</span>www.virustotal.com/gui/domain/jits.ac.in/relations | details: {'tactic': 'command-and-control', 'techniques': ['T1071']}<br/>matrix: enterprise<br/>version: 8.2 | https:<span>//</span>docs.lumu.io/portal/en/kb/articles/malware-incident-response-playbook | qbot,<br/>Pinkslipbot,<br/>gayfgt,<br/>Gafgyt,<br/>Qbot,<br/>Bashlite,<br/>PinkSlipBot,<br/>Qakbot,<br/>lizkebab,<br/>Quakbot,<br/>Akbot,<br/>torlus,<br/>Qbot  | https:<span>//</span>jits.ac.in/TS.php | 2023-02-07T23:46:09.442Z |


### lumu-comment-a-specific-incident
***
Get a paginated list of open incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-comment-a-specific-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lumu_incident_id | Lumu incident id requested. | Required | 
| comment | Lumu comment requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.CommentASpecificIncident.statusCode | number | Lumu statusCode | 

#### Command example
```!lumu-comment-a-specific-incident comment="from cortex, palo alto" lumu_incident_id=9e9238e0-a73d-11ed-9fd0-e5fb50c818f6```
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

>Comment added to the incident successfully.

### lumu-retrieve-open-incidents
***
Get a paginated list of open incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-open-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page requested . | Optional | 
| items | item requested . | Optional | 
| adversary_types | Lumu adversary-types requested. | Optional | 
| labels | Lumu labels requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveOpenIncidents.items.id | String | Lumu incident id | 
| Lumu.RetrieveOpenIncidents.items.timestamp | Date | Lumu timestamp | 
| Lumu.RetrieveOpenIncidents.items.statusTimestamp | Date | Lumu statusTimestamp | 
| Lumu.RetrieveOpenIncidents.items.status | String | Lumu status | 
| Lumu.RetrieveOpenIncidents.items.contacts | Number | Lumu contacts | 
| Lumu.RetrieveOpenIncidents.items.adversaries | String | Lumu adversaries | 
| Lumu.RetrieveOpenIncidents.items.adversaryId | String | Lumu adversaryId | 
| Lumu.RetrieveOpenIncidents.items.adversaryTypes | String | Lumu adversaryTypes | 
| Lumu.RetrieveOpenIncidents.items.description | String | Lumu description | 
| Lumu.RetrieveOpenIncidents.items.labelDistribution | Number | Lumu labelDistribution | 
| Lumu.RetrieveOpenIncidents.items.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.RetrieveOpenIncidents.items.lastContact | Date | Lumu lastContact | 
| Lumu.RetrieveOpenIncidents.items.unread | Boolean | Lumu unread | 
| Lumu.RetrieveOpenIncidents.paginationInfo.page | Number | current page  | 
| Lumu.RetrieveOpenIncidents.paginationInfo.items | Number | current items  | 

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
                    "id": "9e9238e0-a73d-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "0": 2
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-07T23:17:41.358Z",
                    "timestamp": "2023-02-07T23:17:41.358Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "104.156.63.145"
                    ],
                    "adversaryId": "104.156.63.145",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 5,
                    "description": "Malware family Agentemis",
                    "firstContact": "2023-02-08T03:10:49Z",
                    "hasPlaybackContacts": false,
                    "id": "eef6afd0-a72b-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "2144": 5
                    },
                    "lastContact": "2023-02-08T03:10:51Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-07T21:11:05.293Z",
                    "timestamp": "2023-02-07T21:11:05.293Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.spotifyvault.com"
                    ],
                    "adversaryId": "www.spotifyvault.com",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 4,
                    "description": "Phishing domain",
                    "firstContact": "2023-02-07T17:02:29Z",
                    "hasPlaybackContacts": false,
                    "id": "6d06a650-a709-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "147": 2,
                        "2144": 2
                    },
                    "lastContact": "2023-02-07T23:10:10.721Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-07T17:04:04.405Z",
                    "timestamp": "2023-02-07T17:04:04.405Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ics-nett.com"
                    ],
                    "adversaryId": "ics-nett.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 3,
                    "description": "Malicious Content",
                    "firstContact": "2023-01-27T19:00:23.897Z",
                    "hasPlaybackContacts": true,
                    "id": "080189f0-a64b-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "2144": 2,
                        "4301": 1
                    },
                    "lastContact": "2023-02-07T23:10:30.115Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-06T18:21:10.543Z",
                    "timestamp": "2023-02-06T18:21:10.543Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "obobbo.com"
                    ],
                    "adversaryId": "obobbo.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:29:57.692Z",
                    "hasPlaybackContacts": false,
                    "id": "790f0700-9ec4-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:29:57.692Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-06T15:03:06.017Z",
                    "timestamp": "2023-01-28T04:30:20.016Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.chg.com.br"
                    ],
                    "adversaryId": "www.chg.com.br",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 5,
                    "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                    "firstContact": "2023-02-03T19:01:00Z",
                    "hasPlaybackContacts": false,
                    "id": "d0ce2800-a3f5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 2,
                        "989": 3
                    },
                    "lastContact": "2023-02-03T19:22:57.892Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-03T19:06:08.384Z",
                    "timestamp": "2023-02-03T19:06:08.384Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "try2hack.nl"
                    ],
                    "adversaryId": "try2hack.nl",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Win32.Cl.B.Tilken",
                    "firstContact": "2023-02-03T18:17:59.597Z",
                    "hasPlaybackContacts": false,
                    "id": "22dccb80-a3ef-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "147": 1
                    },
                    "lastContact": "2023-02-03T18:17:59.597Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-03T18:18:19.576Z",
                    "timestamp": "2023-02-03T18:18:19.576Z",
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
                    "contacts": 2,
                    "description": "Malware family Trojan.Win32.Generic",
                    "firstContact": "2023-02-02T23:51:26.644Z",
                    "hasPlaybackContacts": false,
                    "id": "967c43e0-a354-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "989": 2
                    },
                    "lastContact": "2023-02-02T23:51:26.645Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-03T15:22:35.368Z",
                    "timestamp": "2023-02-02T23:52:01.566Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "musicaitaliana.com"
                    ],
                    "adversaryId": "musicaitaliana.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "QakBot",
                    "firstContact": "2023-01-28T04:46:11.531Z",
                    "hasPlaybackContacts": true,
                    "id": "cffb7650-a353-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:46:11.531Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-02T23:46:28.533Z",
                    "timestamp": "2023-02-02T23:46:28.533Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "soardigital.net"
                    ],
                    "adversaryId": "soardigital.net",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "QakBot",
                    "firstContact": "2023-01-13T17:37:32.767Z",
                    "hasPlaybackContacts": true,
                    "id": "17d791d0-a353-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4055": 1,
                        "51": 3
                    },
                    "lastContact": "2023-02-07T08:10:51.125Z",
                    "status": "open",
                    "statusTimestamp": "2023-02-02T23:41:19.597Z",
                    "timestamp": "2023-02-02T23:41:19.597Z",
                    "totalEndpoints": 2,
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
                    "status": "open",
                    "statusTimestamp": "2023-02-02T14:08:55.775Z",
                    "timestamp": "2023-01-13T19:43:40.288Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ibf.tw"
                    ],
                    "adversaryId": "ibf.tw",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Vidar",
                    "firstContact": "2023-01-28T05:31:53.849Z",
                    "hasPlaybackContacts": true,
                    "id": "2a00ca40-a194-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:31:53.849Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-31T18:22:05.028Z",
                    "timestamp": "2023-01-31T18:22:05.028Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ep.com.pl"
                    ],
                    "adversaryId": "ep.com.pl",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 15,
                    "description": "Malware family Trojan.Downloader.Win32.Sjt.Codecpack",
                    "firstContact": "2023-01-28T05:37:04.281Z",
                    "hasPlaybackContacts": false,
                    "id": "bda17930-a099-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1,
                        "989": 14
                    },
                    "lastContact": "2023-02-02T22:33:46.643Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-30T12:29:29.027Z",
                    "timestamp": "2023-01-30T12:29:29.027Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ny.hideip.co"
                    ],
                    "adversaryId": "ny.hideip.co",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 1,
                    "description": "Phishing domain",
                    "firstContact": "2022-03-08T03:45:12Z",
                    "hasPlaybackContacts": true,
                    "id": "593c12e0-a015-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "1651": 1
                    },
                    "lastContact": "2022-03-08T03:45:12Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-29T20:41:47.022Z",
                    "timestamp": "2023-01-29T20:41:47.022Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "wetraq.ca"
                    ],
                    "adversaryId": "wetraq.ca",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 1,
                    "description": "Phishing domain",
                    "firstContact": "2023-01-13T17:18:02.525Z",
                    "hasPlaybackContacts": true,
                    "id": "44f29180-9f6e-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4055": 1
                    },
                    "lastContact": "2023-01-13T17:18:02.525Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-29T00:45:47.032Z",
                    "timestamp": "2023-01-29T00:45:47.032Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "berm.co.nz"
                    ],
                    "adversaryId": "berm.co.nz",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Win32.B.Bitrep",
                    "firstContact": "2023-01-28T05:36:23.885Z",
                    "hasPlaybackContacts": false,
                    "id": "ca731f60-9ecd-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:36:23.885Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:37:02.038Z",
                    "timestamp": "2023-01-28T05:37:02.038Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "politerm.com"
                    ],
                    "adversaryId": "politerm.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.TR/Crypt.XPACK.Gen3",
                    "firstContact": "2023-01-28T05:35:05.622Z",
                    "hasPlaybackContacts": false,
                    "id": "96949e80-9ecd-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:35:05.622Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:35:35.016Z",
                    "timestamp": "2023-01-28T05:35:35.016Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "abyssmail.com"
                    ],
                    "adversaryId": "abyssmail.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:34:25.436Z",
                    "hasPlaybackContacts": false,
                    "id": "76672970-9ecd-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:34:25.436Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:34:41.031Z",
                    "timestamp": "2023-01-28T05:34:41.031Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "mainsite.org"
                    ],
                    "adversaryId": "mainsite.org",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 1,
                    "description": "Malware family Kwampirs",
                    "firstContact": "2023-01-28T05:31:08.541Z",
                    "hasPlaybackContacts": false,
                    "id": "02355f90-9ecd-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:31:08.541Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:31:26.089Z",
                    "timestamp": "2023-01-28T05:31:26.089Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "zainmax.net"
                    ],
                    "adversaryId": "zainmax.net",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:29:30.313Z",
                    "hasPlaybackContacts": false,
                    "id": "ce58b370-9ecc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:29:30.313Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:29:59.079Z",
                    "timestamp": "2023-01-28T05:29:59.079Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ac20mail.in"
                    ],
                    "adversaryId": "ac20mail.in",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:29:26.009Z",
                    "hasPlaybackContacts": false,
                    "id": "ce5753e0-9ecc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:29:26.009Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:29:59.070Z",
                    "timestamp": "2023-01-28T05:29:59.070Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "wronghead.com"
                    ],
                    "adversaryId": "wronghead.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:25:59.209Z",
                    "hasPlaybackContacts": false,
                    "id": "54b776a0-9ecc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:25:59.209Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:26:35.018Z",
                    "timestamp": "2023-01-28T05:26:35.018Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "diamondgroupweb.com"
                    ],
                    "adversaryId": "diamondgroupweb.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "QakBot",
                    "firstContact": "2023-01-28T05:25:37.238Z",
                    "hasPlaybackContacts": false,
                    "id": "46693390-9ecc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:25:37.238Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:26:11.017Z",
                    "timestamp": "2023-01-28T05:26:11.017Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "cmail.net"
                    ],
                    "adversaryId": "cmail.net",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:24:07.606Z",
                    "hasPlaybackContacts": false,
                    "id": "0d344600-9ecc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:24:07.606Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:24:35.040Z",
                    "timestamp": "2023-01-28T05:24:35.040Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "voxelcore.com"
                    ],
                    "adversaryId": "voxelcore.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:23:45.015Z",
                    "hasPlaybackContacts": false,
                    "id": "fee28080-9ecb-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:23:45.015Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:24:11.016Z",
                    "timestamp": "2023-01-28T05:24:11.016Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "notepad.it"
                    ],
                    "adversaryId": "notepad.it",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Generickd",
                    "firstContact": "2023-01-28T05:23:23.535Z",
                    "hasPlaybackContacts": false,
                    "id": "f09e0170-9ecb-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:23:23.535Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:23:47.079Z",
                    "timestamp": "2023-01-28T05:23:47.079Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "redbrickoffices.com"
                    ],
                    "adversaryId": "redbrickoffices.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Downloader.Agent.Oms.Js",
                    "firstContact": "2023-01-28T05:21:37.865Z",
                    "hasPlaybackContacts": false,
                    "id": "b76a7370-9ecb-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:21:37.865Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:22:11.111Z",
                    "timestamp": "2023-01-28T05:22:11.111Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "crackedfine.co"
                    ],
                    "adversaryId": "crackedfine.co",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malicious Content",
                    "firstContact": "2023-01-28T05:18:50.449Z",
                    "hasPlaybackContacts": false,
                    "id": "550c90f0-9ecb-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:18:50.449Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:19:26.079Z",
                    "timestamp": "2023-01-28T05:19:26.079Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "sega-dc.de"
                    ],
                    "adversaryId": "sega-dc.de",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family W32/Bredolab.AR_b.gen!Eldorado",
                    "firstContact": "2023-01-28T05:18:07.943Z",
                    "hasPlaybackContacts": false,
                    "id": "3bfadf40-9ecb-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:18:07.943Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:18:44.020Z",
                    "timestamp": "2023-01-28T05:18:44.020Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "visal168.ga"
                    ],
                    "adversaryId": "visal168.ga",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:17:19.613Z",
                    "hasPlaybackContacts": false,
                    "id": "1d97c9f0-9ecb-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:17:19.613Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:17:53.039Z",
                    "timestamp": "2023-01-28T05:17:53.039Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "midlertidig.net"
                    ],
                    "adversaryId": "midlertidig.net",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:17:08.529Z",
                    "hasPlaybackContacts": false,
                    "id": "0f49adf0-9ecb-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:17:08.529Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:17:29.039Z",
                    "timestamp": "2023-01-28T05:17:29.039Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "penoto.tk"
                    ],
                    "adversaryId": "penoto.tk",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:15:19.487Z",
                    "hasPlaybackContacts": false,
                    "id": "d4446d30-9eca-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:15:19.487Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:15:50.019Z",
                    "timestamp": "2023-01-28T05:15:50.019Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "yabai-oppai.tk"
                    ],
                    "adversaryId": "yabai-oppai.tk",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:13:04.876Z",
                    "hasPlaybackContacts": false,
                    "id": "82098dc0-9eca-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:13:04.876Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:13:32.060Z",
                    "timestamp": "2023-01-28T05:13:32.060Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "bst-72.com"
                    ],
                    "adversaryId": "bst-72.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T05:07:51.959Z",
                    "hasPlaybackContacts": false,
                    "id": "cb9fb550-9ec9-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:07:51.959Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:08:26.021Z",
                    "timestamp": "2023-01-28T05:08:26.021Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "wsp.pl"
                    ],
                    "adversaryId": "wsp.pl",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Cl.A.Woreflint.Script",
                    "firstContact": "2023-01-28T05:02:17.429Z",
                    "hasPlaybackContacts": false,
                    "id": "035a5460-9ec9-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T05:02:17.429Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:02:50.022Z",
                    "timestamp": "2023-01-28T05:02:50.022Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "ama-trade.de"
                    ],
                    "adversaryId": "ama-trade.de",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:59:59.967Z",
                    "hasPlaybackContacts": false,
                    "id": "a82e5550-9ec8-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:59:59.967Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T05:00:17.061Z",
                    "timestamp": "2023-01-28T05:00:17.061Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "imstations.com"
                    ],
                    "adversaryId": "imstations.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:57:55.135Z",
                    "hasPlaybackContacts": false,
                    "id": "643b7760-9ec8-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:57:55.135Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:58:23.062Z",
                    "timestamp": "2023-01-28T04:58:23.062Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "tmail.com"
                    ],
                    "adversaryId": "tmail.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:54:57.796Z",
                    "hasPlaybackContacts": false,
                    "id": "0019c4d0-9ec8-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:54:57.796Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:55:35.069Z",
                    "timestamp": "2023-01-28T04:55:35.069Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "richacontentwriter.com"
                    ],
                    "adversaryId": "richacontentwriter.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Agensla.MSIL.PSW.Generic",
                    "firstContact": "2023-01-28T04:52:30.732Z",
                    "hasPlaybackContacts": false,
                    "id": "9bed8af0-9ec7-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:52:30.732Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:52:47.007Z",
                    "timestamp": "2023-01-28T04:52:47.007Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "themojjo.com"
                    ],
                    "adversaryId": "themojjo.com",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 2,
                    "description": "Phishing domain",
                    "firstContact": "2023-01-28T04:52:01Z",
                    "hasPlaybackContacts": false,
                    "id": "8d9f6ef0-9ec7-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "1792": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-02-01T15:05:13.323Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:52:23.007Z",
                    "timestamp": "2023-01-28T04:52:23.007Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "mfsa.info"
                    ],
                    "adversaryId": "mfsa.info",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:50:47.547Z",
                    "hasPlaybackContacts": false,
                    "id": "6650b840-9ec7-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:50:47.547Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:51:17.060Z",
                    "timestamp": "2023-01-28T04:51:17.060Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "0v.ro"
                    ],
                    "adversaryId": "0v.ro",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:50:09.906Z",
                    "hasPlaybackContacts": false,
                    "id": "56338190-9ec7-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:50:09.906Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:50:50.025Z",
                    "timestamp": "2023-01-28T04:50:50.025Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "delmadang.com"
                    ],
                    "adversaryId": "delmadang.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.Cl.A.Woreflint.Script",
                    "firstContact": "2023-01-28T04:36:57.579Z",
                    "hasPlaybackContacts": false,
                    "id": "73661810-9ec5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:36:57.579Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:37:20.017Z",
                    "timestamp": "2023-01-28T04:37:20.017Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "rabie3-alfirdws-ala3la.net"
                    ],
                    "adversaryId": "rabie3-alfirdws-ala3la.net",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Trojan.A.Phishing.Php",
                    "firstContact": "2023-01-28T04:36:31.756Z",
                    "hasPlaybackContacts": false,
                    "id": "6522d180-9ec5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:36:31.756Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:36:56.088Z",
                    "timestamp": "2023-01-28T04:36:56.088Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "cfo2go.ro"
                    ],
                    "adversaryId": "cfo2go.ro",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:36:18.991Z",
                    "hasPlaybackContacts": false,
                    "id": "65219900-9ec5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:36:18.991Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:36:56.080Z",
                    "timestamp": "2023-01-28T04:36:56.080Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "spammotel.com"
                    ],
                    "adversaryId": "spammotel.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:33:25.847Z",
                    "hasPlaybackContacts": false,
                    "id": "f2a5bc80-9ec4-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:33:25.847Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:33:44.008Z",
                    "timestamp": "2023-01-28T04:33:44.008Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "hammerofgod.com"
                    ],
                    "adversaryId": "hammerofgod.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "Malware family Hacktool.Win32.A.Tsgrinder",
                    "firstContact": "2023-01-28T04:31:04.578Z",
                    "hasPlaybackContacts": false,
                    "id": "a2395b80-9ec4-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:31:04.578Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:31:29.080Z",
                    "timestamp": "2023-01-28T04:31:29.080Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "myemailboxy.com"
                    ],
                    "adversaryId": "myemailboxy.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:28:15.191Z",
                    "hasPlaybackContacts": false,
                    "id": "41a870d0-9ec4-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:28:15.191Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:28:47.069Z",
                    "timestamp": "2023-01-28T04:28:47.069Z",
                    "totalEndpoints": 1,
                    "unread": true
                },
                {
                    "adversaries": [
                        "pecinan.com"
                    ],
                    "adversaryId": "pecinan.com",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:27:21.290Z",
                    "hasPlaybackContacts": false,
                    "id": "18837380-9ec4-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:27:21.290Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:27:38.040Z",
                    "timestamp": "2023-01-28T04:27:38.040Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "nospamfor.us"
                    ],
                    "adversaryId": "nospamfor.us",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 1,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-28T04:27:06.840Z",
                    "hasPlaybackContacts": false,
                    "id": "1881ece0-9ec4-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T04:27:06.840Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-28T04:27:38.030Z",
                    "timestamp": "2023-01-28T04:27:38.030Z",
                    "totalEndpoints": 1,
                    "unread": false
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-02-07T23:20:17.696Z"
        }
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 9e9238e0-a73d-11ed-9fd0-e5fb50c818f6 | 0: 2 | 2022-12-20T14:37:02.228Z | open | 2023-02-07T23:17:41.358Z | 2023-02-07T23:17:41.358Z | 1 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 5 | Malware family Agentemis | 2023-02-08T03:10:49Z | false | eef6afd0-a72b-11ed-9fd0-e5fb50c818f6 | 2144: 5 | 2023-02-08T03:10:51Z | open | 2023-02-07T21:11:05.293Z | 2023-02-07T21:11:05.293Z | 1 | false |
>| www.spotifyvault.com | www.spotifyvault.com | Phishing | 4 | Phishing domain | 2023-02-07T17:02:29Z | false | 6d06a650-a709-11ed-9fd0-e5fb50c818f6 | 147: 2<br/>2144: 2 | 2023-02-07T23:10:10.721Z | open | 2023-02-07T17:04:04.405Z | 2023-02-07T17:04:04.405Z | 2 | false |
>| ics-nett.com | ics-nett.com | Malware | 3 | Malicious Content | 2023-01-27T19:00:23.897Z | true | 080189f0-a64b-11ed-a0c7-dd6f8e69d343 | 4301: 1<br/>2144: 2 | 2023-02-07T23:10:30.115Z | open | 2023-02-06T18:21:10.543Z | 2023-02-06T18:21:10.543Z | 2 | false |
>| obobbo.com | obobbo.com | Spam | 1 | Disposable email host | 2023-01-28T04:29:57.692Z | false | 790f0700-9ec4-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:29:57.692Z | open | 2023-02-06T15:03:06.017Z | 2023-01-28T04:30:20.016Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 5 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-03T19:01:00Z | false | d0ce2800-a3f5-11ed-a0c7-dd6f8e69d343 | 989: 3<br/>0: 2 | 2023-02-03T19:22:57.892Z | open | 2023-02-03T19:06:08.384Z | 2023-02-03T19:06:08.384Z | 1 | false |
>| try2hack.nl | try2hack.nl | Malware | 1 | Malware family Trojan.Win32.Cl.B.Tilken | 2023-02-03T18:17:59.597Z | false | 22dccb80-a3ef-11ed-a0c7-dd6f8e69d343 | 147: 1 | 2023-02-03T18:17:59.597Z | open | 2023-02-03T18:18:19.576Z | 2023-02-03T18:18:19.576Z | 1 | false |
>| www.ascentive.com | www.ascentive.com | Malware | 2 | Malware family Trojan.Win32.Generic | 2023-02-02T23:51:26.644Z | false | 967c43e0-a354-11ed-a0c7-dd6f8e69d343 | 989: 2 | 2023-02-02T23:51:26.645Z | open | 2023-02-03T15:22:35.368Z | 2023-02-02T23:52:01.566Z | 1 | false |
>| musicaitaliana.com | musicaitaliana.com | Malware | 1 | QakBot | 2023-01-28T04:46:11.531Z | true | cffb7650-a353-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:46:11.531Z | open | 2023-02-02T23:46:28.533Z | 2023-02-02T23:46:28.533Z | 1 | false |
>| soardigital.net | soardigital.net | Malware | 4 | QakBot | 2023-01-13T17:37:32.767Z | true | 17d791d0-a353-11ed-a0c7-dd6f8e69d343 | 4055: 1<br/>51: 3 | 2023-02-07T08:10:51.125Z | open | 2023-02-02T23:41:19.597Z | 2023-02-02T23:41:19.597Z | 2 | false |
>| mediaworld.pro | mediaworld.pro | Malware | 1 | Malware family Spam.Pdf | 2023-01-13T19:43:16.549Z | false | 945eb000-937a-11ed-b0f8-a7e340234a4e | 1580: 1 | 2023-01-13T19:43:16.549Z | open | 2023-02-02T14:08:55.775Z | 2023-01-13T19:43:40.288Z | 1 | false |
>| ibf.tw | ibf.tw | Malware | 1 | Malware family Vidar | 2023-01-28T05:31:53.849Z | true | 2a00ca40-a194-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:31:53.849Z | open | 2023-01-31T18:22:05.028Z | 2023-01-31T18:22:05.028Z | 1 | false |
>| ep.com.pl | ep.com.pl | Malware | 15 | Malware family Trojan.Downloader.Win32.Sjt.Codecpack | 2023-01-28T05:37:04.281Z | false | bda17930-a099-11ed-a0c7-dd6f8e69d343 | 4301: 1<br/>989: 14 | 2023-02-02T22:33:46.643Z | open | 2023-01-30T12:29:29.027Z | 2023-01-30T12:29:29.027Z | 2 | false |
>| ny.hideip.co | ny.hideip.co | Phishing | 1 | Phishing domain | 2022-03-08T03:45:12Z | true | 593c12e0-a015-11ed-a0c7-dd6f8e69d343 | 1651: 1 | 2022-03-08T03:45:12Z | open | 2023-01-29T20:41:47.022Z | 2023-01-29T20:41:47.022Z | 1 | false |
>| wetraq.ca | wetraq.ca | Phishing | 1 | Phishing domain | 2023-01-13T17:18:02.525Z | true | 44f29180-9f6e-11ed-a0c7-dd6f8e69d343 | 4055: 1 | 2023-01-13T17:18:02.525Z | open | 2023-01-29T00:45:47.032Z | 2023-01-29T00:45:47.032Z | 1 | true |
>| berm.co.nz | berm.co.nz | Malware | 1 | Malware family Trojan.Win32.B.Bitrep | 2023-01-28T05:36:23.885Z | false | ca731f60-9ecd-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:36:23.885Z | open | 2023-01-28T05:37:02.038Z | 2023-01-28T05:37:02.038Z | 1 | false |
>| politerm.com | politerm.com | Malware | 1 | Malware family Trojan.TR/Crypt.XPACK.Gen3 | 2023-01-28T05:35:05.622Z | false | 96949e80-9ecd-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:35:05.622Z | open | 2023-01-28T05:35:35.016Z | 2023-01-28T05:35:35.016Z | 1 | false |
>| abyssmail.com | abyssmail.com | Spam | 1 | Disposable email host | 2023-01-28T05:34:25.436Z | false | 76672970-9ecd-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:34:25.436Z | open | 2023-01-28T05:34:41.031Z | 2023-01-28T05:34:41.031Z | 1 | false |
>| mainsite.org | mainsite.org | C2C | 1 | Malware family Kwampirs | 2023-01-28T05:31:08.541Z | false | 02355f90-9ecd-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:31:08.541Z | open | 2023-01-28T05:31:26.089Z | 2023-01-28T05:31:26.089Z | 1 | false |
>| zainmax.net | zainmax.net | Spam | 1 | Disposable email host | 2023-01-28T05:29:30.313Z | false | ce58b370-9ecc-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:29:30.313Z | open | 2023-01-28T05:29:59.079Z | 2023-01-28T05:29:59.079Z | 1 | false |
>| ac20mail.in | ac20mail.in | Spam | 1 | Disposable email host | 2023-01-28T05:29:26.009Z | false | ce5753e0-9ecc-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:29:26.009Z | open | 2023-01-28T05:29:59.070Z | 2023-01-28T05:29:59.070Z | 1 | true |
>| wronghead.com | wronghead.com | Spam | 1 | Disposable email host | 2023-01-28T05:25:59.209Z | false | 54b776a0-9ecc-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:25:59.209Z | open | 2023-01-28T05:26:35.018Z | 2023-01-28T05:26:35.018Z | 1 | true |
>| diamondgroupweb.com | diamondgroupweb.com | Malware | 1 | QakBot | 2023-01-28T05:25:37.238Z | false | 46693390-9ecc-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:25:37.238Z | open | 2023-01-28T05:26:11.017Z | 2023-01-28T05:26:11.017Z | 1 | true |
>| cmail.net | cmail.net | Spam | 1 | Disposable email host | 2023-01-28T05:24:07.606Z | false | 0d344600-9ecc-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:24:07.606Z | open | 2023-01-28T05:24:35.040Z | 2023-01-28T05:24:35.040Z | 1 | true |
>| voxelcore.com | voxelcore.com | Spam | 1 | Disposable email host | 2023-01-28T05:23:45.015Z | false | fee28080-9ecb-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:23:45.015Z | open | 2023-01-28T05:24:11.016Z | 2023-01-28T05:24:11.016Z | 1 | true |
>| notepad.it | notepad.it | Malware | 1 | Malware family Trojan.Generickd | 2023-01-28T05:23:23.535Z | false | f09e0170-9ecb-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:23:23.535Z | open | 2023-01-28T05:23:47.079Z | 2023-01-28T05:23:47.079Z | 1 | true |
>| redbrickoffices.com | redbrickoffices.com | Malware | 1 | Malware family Trojan.Downloader.Agent.Oms.Js | 2023-01-28T05:21:37.865Z | false | b76a7370-9ecb-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:21:37.865Z | open | 2023-01-28T05:22:11.111Z | 2023-01-28T05:22:11.111Z | 1 | true |
>| crackedfine.co | crackedfine.co | Malware | 1 | Malicious Content | 2023-01-28T05:18:50.449Z | false | 550c90f0-9ecb-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:18:50.449Z | open | 2023-01-28T05:19:26.079Z | 2023-01-28T05:19:26.079Z | 1 | true |
>| sega-dc.de | sega-dc.de | Malware | 1 | Malware family W32/Bredolab.AR_b.gen!Eldorado | 2023-01-28T05:18:07.943Z | false | 3bfadf40-9ecb-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:18:07.943Z | open | 2023-01-28T05:18:44.020Z | 2023-01-28T05:18:44.020Z | 1 | true |
>| visal168.ga | visal168.ga | Spam | 1 | Disposable email host | 2023-01-28T05:17:19.613Z | false | 1d97c9f0-9ecb-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:17:19.613Z | open | 2023-01-28T05:17:53.039Z | 2023-01-28T05:17:53.039Z | 1 | true |
>| midlertidig.net | midlertidig.net | Spam | 1 | Disposable email host | 2023-01-28T05:17:08.529Z | false | 0f49adf0-9ecb-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:17:08.529Z | open | 2023-01-28T05:17:29.039Z | 2023-01-28T05:17:29.039Z | 1 | true |
>| penoto.tk | penoto.tk | Spam | 1 | Disposable email host | 2023-01-28T05:15:19.487Z | false | d4446d30-9eca-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:15:19.487Z | open | 2023-01-28T05:15:50.019Z | 2023-01-28T05:15:50.019Z | 1 | true |
>| yabai-oppai.tk | yabai-oppai.tk | Spam | 1 | Disposable email host | 2023-01-28T05:13:04.876Z | false | 82098dc0-9eca-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:13:04.876Z | open | 2023-01-28T05:13:32.060Z | 2023-01-28T05:13:32.060Z | 1 | true |
>| bst-72.com | bst-72.com | Spam | 1 | Disposable email host | 2023-01-28T05:07:51.959Z | false | cb9fb550-9ec9-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:07:51.959Z | open | 2023-01-28T05:08:26.021Z | 2023-01-28T05:08:26.021Z | 1 | true |
>| wsp.pl | wsp.pl | Malware | 1 | Malware family Trojan.Cl.A.Woreflint.Script | 2023-01-28T05:02:17.429Z | false | 035a5460-9ec9-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:02:17.429Z | open | 2023-01-28T05:02:50.022Z | 2023-01-28T05:02:50.022Z | 1 | true |
>| ama-trade.de | ama-trade.de | Spam | 1 | Disposable email host | 2023-01-28T04:59:59.967Z | false | a82e5550-9ec8-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:59:59.967Z | open | 2023-01-28T05:00:17.061Z | 2023-01-28T05:00:17.061Z | 1 | true |
>| imstations.com | imstations.com | Spam | 1 | Disposable email host | 2023-01-28T04:57:55.135Z | false | 643b7760-9ec8-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:57:55.135Z | open | 2023-01-28T04:58:23.062Z | 2023-01-28T04:58:23.062Z | 1 | true |
>| tmail.com | tmail.com | Spam | 1 | Disposable email host | 2023-01-28T04:54:57.796Z | false | 0019c4d0-9ec8-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:54:57.796Z | open | 2023-01-28T04:55:35.069Z | 2023-01-28T04:55:35.069Z | 1 | true |
>| richacontentwriter.com | richacontentwriter.com | Malware | 1 | Malware family Trojan.Agensla.MSIL.PSW.Generic | 2023-01-28T04:52:30.732Z | false | 9bed8af0-9ec7-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:52:30.732Z | open | 2023-01-28T04:52:47.007Z | 2023-01-28T04:52:47.007Z | 1 | true |
>| themojjo.com | themojjo.com | Phishing | 2 | Phishing domain | 2023-01-28T04:52:01Z | false | 8d9f6ef0-9ec7-11ed-a0c7-dd6f8e69d343 | 4301: 1<br/>1792: 1 | 2023-02-01T15:05:13.323Z | open | 2023-01-28T04:52:23.007Z | 2023-01-28T04:52:23.007Z | 2 | true |
>| mfsa.info | mfsa.info | Spam | 1 | Disposable email host | 2023-01-28T04:50:47.547Z | false | 6650b840-9ec7-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:50:47.547Z | open | 2023-01-28T04:51:17.060Z | 2023-01-28T04:51:17.060Z | 1 | true |
>| 0v.ro | 0v.ro | Spam | 1 | Disposable email host | 2023-01-28T04:50:09.906Z | false | 56338190-9ec7-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:50:09.906Z | open | 2023-01-28T04:50:50.025Z | 2023-01-28T04:50:50.025Z | 1 | true |
>| delmadang.com | delmadang.com | Malware | 1 | Malware family Trojan.Cl.A.Woreflint.Script | 2023-01-28T04:36:57.579Z | false | 73661810-9ec5-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:36:57.579Z | open | 2023-01-28T04:37:20.017Z | 2023-01-28T04:37:20.017Z | 1 | true |
>| rabie3-alfirdws-ala3la.net | rabie3-alfirdws-ala3la.net | Malware | 1 | Malware family Trojan.A.Phishing.Php | 2023-01-28T04:36:31.756Z | false | 6522d180-9ec5-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:36:31.756Z | open | 2023-01-28T04:36:56.088Z | 2023-01-28T04:36:56.088Z | 1 | true |
>| cfo2go.ro | cfo2go.ro | Spam | 1 | Disposable email host | 2023-01-28T04:36:18.991Z | false | 65219900-9ec5-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:36:18.991Z | open | 2023-01-28T04:36:56.080Z | 2023-01-28T04:36:56.080Z | 1 | true |
>| spammotel.com | spammotel.com | Spam | 1 | Disposable email host | 2023-01-28T04:33:25.847Z | false | f2a5bc80-9ec4-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:33:25.847Z | open | 2023-01-28T04:33:44.008Z | 2023-01-28T04:33:44.008Z | 1 | true |
>| hammerofgod.com | hammerofgod.com | Malware | 1 | Malware family Hacktool.Win32.A.Tsgrinder | 2023-01-28T04:31:04.578Z | false | a2395b80-9ec4-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:31:04.578Z | open | 2023-01-28T04:31:29.080Z | 2023-01-28T04:31:29.080Z | 1 | true |
>| myemailboxy.com | myemailboxy.com | Spam | 1 | Disposable email host | 2023-01-28T04:28:15.191Z | false | 41a870d0-9ec4-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:28:15.191Z | open | 2023-01-28T04:28:47.069Z | 2023-01-28T04:28:47.069Z | 1 | true |
>| pecinan.com | pecinan.com | Spam | 1 | Disposable email host | 2023-01-28T04:27:21.290Z | false | 18837380-9ec4-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:27:21.290Z | open | 2023-01-28T04:27:38.040Z | 2023-01-28T04:27:38.040Z | 1 | false |
>| nospamfor.us | nospamfor.us | Spam | 1 | Disposable email host | 2023-01-28T04:27:06.840Z | false | 1881ece0-9ec4-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T04:27:06.840Z | open | 2023-01-28T04:27:38.030Z | 2023-01-28T04:27:38.030Z | 1 | false |


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
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:51:10.312Z",
                    "hasPlaybackContacts": false,
                    "id": "6edc4fb0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4055": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:16:25.261Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:51:28.299Z",
                    "timestamp": "2023-01-13T21:51:28.299Z",
                    "totalEndpoints": 3,
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
                    "contacts": 9,
                    "description": "Malware family Nivdort",
                    "firstContact": "2023-01-13T21:50:53.247Z",
                    "hasPlaybackContacts": false,
                    "id": "642934c0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 2,
                        "2144": 6,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:21:19.861Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:51:10.348Z",
                    "timestamp": "2023-01-13T21:51:10.348Z",
                    "totalEndpoints": 3,
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
                    "contacts": 2,
                    "description": "Malware family Exploit.Msoffice.Generic",
                    "firstContact": "2023-01-13T21:50:38.599Z",
                    "hasPlaybackContacts": false,
                    "id": "59641870-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:33:59.964Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:50:52.279Z",
                    "timestamp": "2023-01-13T21:50:52.279Z",
                    "totalEndpoints": 2,
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
                    "contacts": 3,
                    "description": "Malware family Trojan.Agent.Bg.Script",
                    "firstContact": "2023-01-13T21:49:50.220Z",
                    "hasPlaybackContacts": false,
                    "id": "405525e0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1,
                        "989": 1
                    },
                    "lastContact": "2023-01-27T21:16:25.995Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:50:10.238Z",
                    "timestamp": "2023-01-13T21:50:10.238Z",
                    "totalEndpoints": 3,
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
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:49:28.515Z",
                    "hasPlaybackContacts": false,
                    "id": "304360e0-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:16:25.956Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:49:43.278Z",
                    "timestamp": "2023-01-13T21:49:43.278Z",
                    "totalEndpoints": 2,
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
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:47:46.473Z",
                    "hasPlaybackContacts": false,
                    "id": "f1a7da00-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:16:25.744Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:47:58.240Z",
                    "timestamp": "2023-01-13T21:47:58.240Z",
                    "totalEndpoints": 2,
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
                    "contacts": 2,
                    "description": "Malware family Backdoor.Peg.Php.Generic",
                    "firstContact": "2023-01-13T21:46:26.925Z",
                    "hasPlaybackContacts": false,
                    "id": "c329ff00-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:16:25.912Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:46:40.240Z",
                    "timestamp": "2023-01-13T21:46:40.240Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "tormail.org"
                    ],
                    "adversaryId": "tormail.org",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:46:15.650Z",
                    "hasPlaybackContacts": false,
                    "id": "bc0a4400-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 2,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:03:07.761Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:46:28.288Z",
                    "timestamp": "2023-01-13T21:46:28.288Z",
                    "totalEndpoints": 3,
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
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:46:06.886Z",
                    "hasPlaybackContacts": false,
                    "id": "ba390670-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:03:35.699Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:46:25.239Z",
                    "timestamp": "2023-01-13T21:46:25.239Z",
                    "totalEndpoints": 2,
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
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:29.477Z",
                    "hasPlaybackContacts": false,
                    "id": "59b2ca20-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:04:16.129Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:43.298Z",
                    "timestamp": "2023-01-13T21:43:43.298Z",
                    "totalEndpoints": 2,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:18.543Z",
                    "hasPlaybackContacts": false,
                    "id": "54504f80-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 2,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:55:01.444Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:34.264Z",
                    "timestamp": "2023-01-13T21:43:34.264Z",
                    "totalEndpoints": 3,
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
                    "contacts": 2,
                    "description": "Quakbot",
                    "firstContact": "2023-01-13T21:43:17.535Z",
                    "hasPlaybackContacts": false,
                    "id": "544ca600-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:54:58.611Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:34.240Z",
                    "timestamp": "2023-01-13T21:43:34.240Z",
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
                    "contacts": 2,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:43:13.301Z",
                    "hasPlaybackContacts": false,
                    "id": "50b8f7f0-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:16:25.335Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:43:28.239Z",
                    "timestamp": "2023-01-13T21:43:28.239Z",
                    "totalEndpoints": 2,
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
                    "contacts": 5,
                    "description": "Malware family Win32.Diplugem.Browsermodifier",
                    "firstContact": "2023-01-13T21:41:49.494Z",
                    "hasPlaybackContacts": false,
                    "id": "1eb37cd0-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:59:32.047Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:42:04.317Z",
                    "timestamp": "2023-01-13T21:42:04.317Z",
                    "totalEndpoints": 2,
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
                    "contacts": 3,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-13T21:41:48.847Z",
                    "hasPlaybackContacts": false,
                    "id": "1eb0bdb0-938b-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 2,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:40:55.364Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:42:04.299Z",
                    "timestamp": "2023-01-13T21:42:04.299Z",
                    "totalEndpoints": 2,
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
                    "contacts": 8,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T21:40:54.134Z",
                    "hasPlaybackContacts": false,
                    "id": "fcae3a80-938a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "2144": 6,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T21:13:37.991Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T21:41:07.240Z",
                    "timestamp": "2023-01-13T21:41:07.240Z",
                    "totalEndpoints": 3,
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
                        "jdz.ro"
                    ],
                    "adversaryId": "jdz.ro",
                    "adversaryTypes": [
                        "Spam"
                    ],
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T20:44:27.671Z",
                    "hasPlaybackContacts": false,
                    "id": "1baa0700-9383-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:25:55.829Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:44:43.248Z",
                    "timestamp": "2023-01-13T20:44:43.248Z",
                    "totalEndpoints": 2,
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
                    "contacts": 3,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T20:44:22.181Z",
                    "hasPlaybackContacts": false,
                    "id": "1816a710-9383-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 2,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:25:24.459Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:44:37.249Z",
                    "timestamp": "2023-01-13T20:44:37.249Z",
                    "totalEndpoints": 2,
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
                    "contacts": 5,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T20:42:47.278Z",
                    "hasPlaybackContacts": false,
                    "id": "dee785e0-9382-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:17:24.328Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:43:01.310Z",
                    "timestamp": "2023-01-13T20:43:01.310Z",
                    "totalEndpoints": 2,
                    "unread": true
                },
                {
                    "adversaries": [
                        "vbox.me"
                    ],
                    "adversaryId": "vbox.me",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 5,
                    "description": "Malware family Win32.Tr.F340fc85.Ge",
                    "firstContact": "2023-01-13T20:41:55.053Z",
                    "hasPlaybackContacts": false,
                    "id": "c07b21c0-9382-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 2,
                        "2144": 2,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:30:56.298Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:42:10.268Z",
                    "timestamp": "2023-01-13T20:42:10.268Z",
                    "totalEndpoints": 4,
                    "unread": false
                },
                {
                    "adversaries": [
                        "unikaas.com"
                    ],
                    "adversaryId": "unikaas.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 5,
                    "description": "QakBot",
                    "firstContact": "2023-01-13T20:41:50.618Z",
                    "hasPlaybackContacts": false,
                    "id": "bce94870-9382-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:29:58.403Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:42:04.279Z",
                    "timestamp": "2023-01-13T20:42:04.279Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "lipitorbuy.com"
                    ],
                    "adversaryId": "lipitorbuy.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 7,
                    "description": "Malicious Content",
                    "firstContact": "2023-01-13T20:41:09.425Z",
                    "hasPlaybackContacts": false,
                    "id": "a3e21e10-9382-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 6,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:16:27.181Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T20:41:22.289Z",
                    "timestamp": "2023-01-13T20:41:22.289Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "faucet.works"
                    ],
                    "adversaryId": "faucet.works",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 5,
                    "description": "Malicious domain",
                    "firstContact": "2023-01-13T17:51:17.631Z",
                    "hasPlaybackContacts": false,
                    "id": "e98cd210-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:33:44.453Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:51:31.249Z",
                    "timestamp": "2023-01-13T17:51:31.249Z",
                    "totalEndpoints": 4,
                    "unread": true
                },
                {
                    "adversaries": [
                        "altawon-water-leakage-discovery.com"
                    ],
                    "adversaryId": "altawon-water-leakage-discovery.com",
                    "adversaryTypes": [
                        "Malware",
                        "Phishing"
                    ],
                    "contacts": 4,
                    "description": "QakBot",
                    "firstContact": "2023-01-13T17:50:49.858Z",
                    "hasPlaybackContacts": false,
                    "id": "d977ffd0-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:30:39.588Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:51:04.269Z",
                    "timestamp": "2023-01-13T17:51:04.269Z",
                    "totalEndpoints": 4,
                    "unread": true
                },
                {
                    "adversaries": [
                        "lajosmizse.hu"
                    ],
                    "adversaryId": "lajosmizse.hu",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family Riskware.Ammyy",
                    "firstContact": "2023-01-13T17:48:46.784Z",
                    "hasPlaybackContacts": false,
                    "id": "90276230-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:24:16.012Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:49:01.267Z",
                    "timestamp": "2023-01-13T17:49:01.267Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "goldenagecollectables.com"
                    ],
                    "adversaryId": "goldenagecollectables.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family Trojan.Downloader.Rfn.Emotet.O97m",
                    "firstContact": "2023-01-13T17:48:45.579Z",
                    "hasPlaybackContacts": false,
                    "id": "902602a0-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:17:13.200Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:49:01.258Z",
                    "timestamp": "2023-01-13T17:49:01.258Z",
                    "totalEndpoints": 3,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:48:45.035Z",
                    "hasPlaybackContacts": false,
                    "id": "8e61bd60-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:24:13.936Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:48:58.294Z",
                    "timestamp": "2023-01-13T17:48:58.294Z",
                    "totalEndpoints": 3,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:46:45.978Z",
                    "hasPlaybackContacts": false,
                    "id": "489c6960-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:13:42.181Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:47:01.238Z",
                    "timestamp": "2023-01-13T17:47:01.238Z",
                    "totalEndpoints": 3,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:46:31.250Z",
                    "hasPlaybackContacts": false,
                    "id": "41755b60-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:56:05.885Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:46:49.238Z",
                    "timestamp": "2023-01-13T17:46:49.238Z",
                    "totalEndpoints": 3,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:46:03.300Z",
                    "hasPlaybackContacts": false,
                    "id": "2f9b5980-936a-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:56:48.668Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:46:19.288Z",
                    "timestamp": "2023-01-13T17:46:19.288Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "parafia.zlotoria.eu"
                    ],
                    "adversaryId": "parafia.zlotoria.eu",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family TrojanDownloader:JS/FakejQuery.AR!MTB",
                    "firstContact": "2023-01-13T17:44:16.981Z",
                    "hasPlaybackContacts": false,
                    "id": "ef3bdb80-9369-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:13:59.851Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:44:31.288Z",
                    "timestamp": "2023-01-13T17:44:31.288Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "melodypods.com"
                    ],
                    "adversaryId": "melodypods.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family Tr.A.Phishing.Pdf",
                    "firstContact": "2023-01-13T17:43:11.255Z",
                    "hasPlaybackContacts": false,
                    "id": "c7e6bc30-9369-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T20:12:27.003Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:43:25.299Z",
                    "timestamp": "2023-01-13T17:43:25.299Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "prettypower.net",
                        "leadmine.net",
                        "cloudstep.net",
                        "southscene.net",
                        "heavyobject.net"
                    ],
                    "adversaryId": "Malware family Suppobox",
                    "adversaryTypes": [
                        "DGA"
                    ],
                    "contacts": 9,
                    "description": "Malware family Suppobox",
                    "firstContact": "2023-01-13T17:39:51.654Z",
                    "hasPlaybackContacts": false,
                    "id": "50358f90-9369-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1580": 2,
                        "1791": 3,
                        "4055": 1,
                        "4301": 3
                    },
                    "lastContact": "2023-01-28T01:10:52.251Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:40:04.489Z",
                    "timestamp": "2023-01-13T17:40:04.489Z",
                    "totalEndpoints": 6,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:38:41.782Z",
                    "hasPlaybackContacts": false,
                    "id": "27048450-9369-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:51:58.932Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:38:55.381Z",
                    "timestamp": "2023-01-13T17:38:55.381Z",
                    "totalEndpoints": 4,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:35:52.041Z",
                    "hasPlaybackContacts": false,
                    "id": "c2d0f770-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:22:33.293Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:36:07.271Z",
                    "timestamp": "2023-01-13T17:36:07.271Z",
                    "totalEndpoints": 4,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:33:54.255Z",
                    "hasPlaybackContacts": false,
                    "id": "7b48bdc0-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:20:06.321Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:34:07.260Z",
                    "timestamp": "2023-01-13T17:34:07.260Z",
                    "totalEndpoints": 4,
                    "unread": true
                },
                {
                    "adversaries": [
                        "curadincubator.org"
                    ],
                    "adversaryId": "curadincubator.org",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware related",
                    "firstContact": "2023-01-13T17:33:29.705Z",
                    "hasPlaybackContacts": false,
                    "id": "6ec85ce0-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:43:38.550Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:33:46.286Z",
                    "timestamp": "2023-01-13T17:33:46.286Z",
                    "totalEndpoints": 4,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:32:23.990Z",
                    "hasPlaybackContacts": false,
                    "id": "45c6ed20-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:41:00.772Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:32:37.490Z",
                    "timestamp": "2023-01-13T17:32:37.490Z",
                    "totalEndpoints": 4,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:32:14.141Z",
                    "hasPlaybackContacts": false,
                    "id": "405a1240-9368-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:15:21.427Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:32:28.388Z",
                    "timestamp": "2023-01-13T17:32:28.388Z",
                    "totalEndpoints": 4,
                    "unread": true
                },
                {
                    "adversaries": [
                        "kidsdown.com"
                    ],
                    "adversaryId": "kidsdown.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 5,
                    "description": "Malware family Trojan.Win32.Generic",
                    "firstContact": "2023-01-13T17:30:03.908Z",
                    "hasPlaybackContacts": false,
                    "id": "f3781080-9367-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:24:20.940Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:30:19.400Z",
                    "timestamp": "2023-01-13T17:30:19.400Z",
                    "totalEndpoints": 4,
                    "unread": true
                },
                {
                    "adversaries": [
                        "splushka.com"
                    ],
                    "adversaryId": "splushka.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family Trojan.Win32.Ml.B.Fl.Sabsik",
                    "firstContact": "2023-01-13T17:26:27.909Z",
                    "hasPlaybackContacts": false,
                    "id": "72a20a10-9367-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:00:23.687Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:26:43.249Z",
                    "timestamp": "2023-01-13T17:26:43.249Z",
                    "totalEndpoints": 4,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:26:24.964Z",
                    "hasPlaybackContacts": false,
                    "id": "70d86da0-9367-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:18:43.461Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:26:40.250Z",
                    "timestamp": "2023-01-13T17:26:40.250Z",
                    "totalEndpoints": 4,
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
                    "contacts": 7,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:25:20.022Z",
                    "hasPlaybackContacts": false,
                    "id": "49817990-9367-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 6,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:00:23.582Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:25:34.249Z",
                    "timestamp": "2023-01-13T17:25:34.249Z",
                    "totalEndpoints": 4,
                    "unread": true
                },
                {
                    "adversaries": [
                        "garhoogin.com"
                    ],
                    "adversaryId": "garhoogin.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family Trojan.Win32.Plock.Tiggre",
                    "firstContact": "2023-01-13T17:23:20.257Z",
                    "hasPlaybackContacts": false,
                    "id": "02028eb0-9367-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:00:23.365Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:23:34.299Z",
                    "timestamp": "2023-01-13T17:23:34.299Z",
                    "totalEndpoints": 3,
                    "unread": true
                },
                {
                    "adversaries": [
                        "rksbusiness.com"
                    ],
                    "adversaryId": "rksbusiness.com",
                    "adversaryTypes": [
                        "C2C",
                        "Malware"
                    ],
                    "contacts": 4,
                    "description": "Malware family Sodinokibi",
                    "firstContact": "2023-01-13T17:21:12.216Z",
                    "hasPlaybackContacts": false,
                    "id": "b8b21820-9366-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:00:15.678Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:21:31.298Z",
                    "timestamp": "2023-01-13T17:21:31.298Z",
                    "totalEndpoints": 4,
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
                    "contacts": 4,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:17:09.658Z",
                    "hasPlaybackContacts": false,
                    "id": "260cbe30-9366-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 3,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:00:15.153Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:17:25.267Z",
                    "timestamp": "2023-01-13T17:17:25.267Z",
                    "totalEndpoints": 4,
                    "unread": true
                },
                {
                    "adversaries": [
                        "shorturl.ac"
                    ],
                    "adversaryId": "shorturl.ac",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 9,
                    "description": "Phishing domain",
                    "firstContact": "2023-01-13T17:14:44.779Z",
                    "hasPlaybackContacts": false,
                    "id": "ce6c7df0-9365-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 8,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:00:14.931Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:14:58.255Z",
                    "timestamp": "2023-01-13T17:14:58.255Z",
                    "totalEndpoints": 4,
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
                    "contacts": 7,
                    "description": "Disposable email host",
                    "firstContact": "2023-01-13T17:14:43.996Z",
                    "hasPlaybackContacts": false,
                    "id": "ce6a0cf0-9365-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 5,
                        "4301": 2
                    },
                    "lastContact": "2023-01-27T19:00:23.405Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:14:58.239Z",
                    "timestamp": "2023-01-13T17:14:58.239Z",
                    "totalEndpoints": 4,
                    "unread": true
                },
                {
                    "adversaries": [
                        "slimcleaner.com"
                    ],
                    "adversaryId": "slimcleaner.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 5,
                    "description": "Malware family M.Slimware.Potentialrisk.PUA",
                    "firstContact": "2023-01-13T17:14:23.518Z",
                    "hasPlaybackContacts": false,
                    "id": "c3b0d780-9365-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 4,
                        "4301": 1
                    },
                    "lastContact": "2023-01-27T19:00:11.457Z",
                    "status": "open",
                    "statusTimestamp": "2023-01-13T17:14:40.248Z",
                    "timestamp": "2023-01-13T17:14:40.248Z",
                    "totalEndpoints": 4,
                    "unread": true
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-02-07T23:20:19.924Z"
        }
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| msgos.com | msgos.com | Spam | 3 | Disposable email host | 2023-01-13T21:51:10.312Z | false | 6edc4fb0-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4055: 1<br/>4301: 1 | 2023-01-27T21:16:25.261Z | open | 2023-01-13T21:51:28.299Z | 2023-01-13T21:51:28.299Z | 3 | false |
>| netwonder.net | netwonder.net | Malware | 9 | Malware family Nivdort | 2023-01-13T21:50:53.247Z | false | 642934c0-938c-11ed-b0f8-a7e340234a4e | 1791: 2<br/>2144: 6<br/>4301: 1 | 2023-01-27T21:21:19.861Z | open | 2023-01-13T21:51:10.348Z | 2023-01-13T21:51:10.348Z | 3 | false |
>| subwaybookreview.com | subwaybookreview.com | Malware | 2 | Malware family Exploit.Msoffice.Generic | 2023-01-13T21:50:38.599Z | false | 59641870-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:33:59.964Z | open | 2023-01-13T21:50:52.279Z | 2023-01-13T21:50:52.279Z | 2 | true |
>| michaeleaston.com | michaeleaston.com | Malware | 3 | Malware family Trojan.Agent.Bg.Script | 2023-01-13T21:49:50.220Z | false | 405525e0-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>989: 1<br/>4301: 1 | 2023-01-27T21:16:25.995Z | open | 2023-01-13T21:50:10.238Z | 2023-01-13T21:50:10.238Z | 3 | false |
>| cane.pw | cane.pw | Spam | 2 | Disposable email host | 2023-01-13T21:49:28.515Z | false | 304360e0-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:16:25.956Z | open | 2023-01-13T21:49:43.278Z | 2023-01-13T21:49:43.278Z | 2 | true |
>| cek.pm | cek.pm | Spam | 2 | Disposable email host | 2023-01-13T21:47:46.473Z | false | f1a7da00-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:16:25.744Z | open | 2023-01-13T21:47:58.240Z | 2023-01-13T21:47:58.240Z | 2 | true |
>| anothercity.ru | anothercity.ru | Malware | 2 | Malware family Backdoor.Peg.Php.Generic | 2023-01-13T21:46:26.925Z | false | c329ff00-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:16:25.912Z | open | 2023-01-13T21:46:40.240Z | 2023-01-13T21:46:40.240Z | 2 | false |
>| tormail.org | tormail.org | Spam | 4 | Disposable email host | 2023-01-13T21:46:15.650Z | false | bc0a4400-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>2144: 2<br/>4301: 1 | 2023-01-27T21:03:07.761Z | open | 2023-01-13T21:46:28.288Z | 2023-01-13T21:46:28.288Z | 3 | true |
>| businessbackend.com | businessbackend.com | Spam | 2 | Disposable email host | 2023-01-13T21:46:06.886Z | false | ba390670-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:03:35.699Z | open | 2023-01-13T21:46:25.239Z | 2023-01-13T21:46:25.239Z | 2 | true |
>| asdasd.ru | asdasd.ru | Spam | 2 | Disposable email host | 2023-01-13T21:43:29.477Z | false | 59b2ca20-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:04:16.129Z | open | 2023-01-13T21:43:43.298Z | 2023-01-13T21:43:43.298Z | 2 | false |
>| hotprice.co | hotprice.co | Spam | 4 | Disposable email host | 2023-01-13T21:43:18.543Z | false | 54504f80-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>2144: 2<br/>4301: 1 | 2023-01-27T20:55:01.444Z | open | 2023-01-13T21:43:34.264Z | 2023-01-13T21:43:34.264Z | 3 | true |
>| theshallowtalesreview.com.ng | theshallowtalesreview.com.ng | Malware | 2 | Quakbot | 2023-01-13T21:43:17.535Z | false | 544ca600-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T20:54:58.611Z | open | 2023-01-13T21:43:34.240Z | 2023-01-13T21:43:34.240Z | 2 | true |
>| disposable.ml | disposable.ml | Spam | 2 | Disposable email host | 2023-01-13T21:43:13.301Z | false | 50b8f7f0-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:16:25.335Z | open | 2023-01-13T21:43:28.239Z | 2023-01-13T21:43:28.239Z | 2 | true |
>| founddll.com | founddll.com | Malware | 5 | Malware family Win32.Diplugem.Browsermodifier | 2023-01-13T21:41:49.494Z | false | 1eb37cd0-938b-11ed-b0f8-a7e340234a4e | 1791: 4<br/>4301: 1 | 2023-01-27T20:59:32.047Z | open | 2023-01-13T21:42:04.317Z | 2023-01-13T21:42:04.317Z | 2 | true |
>| learnwithportals.com | learnwithportals.com | Malware | 3 | Malicious domain | 2023-01-13T21:41:48.847Z | false | 1eb0bdb0-938b-11ed-b0f8-a7e340234a4e | 1791: 2<br/>4301: 1 | 2023-01-27T20:40:55.364Z | open | 2023-01-13T21:42:04.299Z | 2023-01-13T21:42:04.299Z | 2 | true |
>| kloap.com | kloap.com | Spam | 8 | Disposable email host | 2023-01-13T21:40:54.134Z | false | fcae3a80-938a-11ed-b0f8-a7e340234a4e | 1791: 1<br/>2144: 6<br/>4301: 1 | 2023-01-27T21:13:37.991Z | open | 2023-01-13T21:41:07.240Z | 2023-01-13T21:41:07.240Z | 3 | true |
>| disconight.com.ar | disconight.com.ar | Phishing | 9 | Phishing domain | 2023-01-13T21:39:29.886Z | false | cc6cb680-938a-11ed-b0f8-a7e340234a4e | 1791: 1<br/>2144: 8 | 2023-01-18T20:41:33.286Z | open | 2023-01-13T21:39:46.280Z | 2023-01-13T21:39:46.280Z | 2 | false |
>| jdz.ro | jdz.ro | Spam | 4 | Disposable email host | 2023-01-13T20:44:27.671Z | false | 1baa0700-9383-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T20:25:55.829Z | open | 2023-01-13T20:44:43.248Z | 2023-01-13T20:44:43.248Z | 2 | true |
>| veryday.info | veryday.info | Spam | 3 | Disposable email host | 2023-01-13T20:44:22.181Z | false | 1816a710-9383-11ed-b0f8-a7e340234a4e | 1791: 2<br/>4301: 1 | 2023-01-27T20:25:24.459Z | open | 2023-01-13T20:44:37.249Z | 2023-01-13T20:44:37.249Z | 2 | true |
>| niwl.net | niwl.net | Spam | 5 | Disposable email host | 2023-01-13T20:42:47.278Z | false | dee785e0-9382-11ed-b0f8-a7e340234a4e | 1791: 4<br/>4301: 1 | 2023-01-27T20:17:24.328Z | open | 2023-01-13T20:43:01.310Z | 2023-01-13T20:43:01.310Z | 2 | true |
>| vbox.me | vbox.me | Malware | 5 | Malware family Win32.Tr.F340fc85.Ge | 2023-01-13T20:41:55.053Z | false | c07b21c0-9382-11ed-b0f8-a7e340234a4e | 1791: 2<br/>2144: 2<br/>4301: 1 | 2023-01-27T20:30:56.298Z | open | 2023-01-13T20:42:10.268Z | 2023-01-13T20:42:10.268Z | 4 | false |
>| unikaas.com | unikaas.com | Malware | 5 | QakBot | 2023-01-13T20:41:50.618Z | false | bce94870-9382-11ed-b0f8-a7e340234a4e | 1791: 4<br/>4301: 1 | 2023-01-27T20:29:58.403Z | open | 2023-01-13T20:42:04.279Z | 2023-01-13T20:42:04.279Z | 3 | false |
>| lipitorbuy.com | lipitorbuy.com | Malware | 7 | Malicious Content | 2023-01-13T20:41:09.425Z | false | a3e21e10-9382-11ed-b0f8-a7e340234a4e | 1791: 6<br/>4301: 1 | 2023-01-27T20:16:27.181Z | open | 2023-01-13T20:41:22.289Z | 2023-01-13T20:41:22.289Z | 3 | false |
>| faucet.works | faucet.works | Malware | 5 | Malicious domain | 2023-01-13T17:51:17.631Z | false | e98cd210-936a-11ed-b0f8-a7e340234a4e | 1791: 4<br/>4301: 1 | 2023-01-27T20:33:44.453Z | open | 2023-01-13T17:51:31.249Z | 2023-01-13T17:51:31.249Z | 4 | true |
>| altawon-water-leakage-discovery.com | altawon-water-leakage-discovery.com | Malware,<br/>Phishing | 4 | QakBot | 2023-01-13T17:50:49.858Z | false | d977ffd0-936a-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T20:30:39.588Z | open | 2023-01-13T17:51:04.269Z | 2023-01-13T17:51:04.269Z | 4 | true |
>| lajosmizse.hu | lajosmizse.hu | Malware | 4 | Malware family Riskware.Ammyy | 2023-01-13T17:48:46.784Z | false | 90276230-936a-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T20:24:16.012Z | open | 2023-01-13T17:49:01.267Z | 2023-01-13T17:49:01.267Z | 3 | true |
>| goldenagecollectables.com | goldenagecollectables.com | Malware | 4 | Malware family Trojan.Downloader.Rfn.Emotet.O97m | 2023-01-13T17:48:45.579Z | false | 902602a0-936a-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T20:17:13.200Z | open | 2023-01-13T17:49:01.258Z | 2023-01-13T17:49:01.258Z | 3 | true |
>| shipfromto.com | shipfromto.com | Spam | 4 | Disposable email host | 2023-01-13T17:48:45.035Z | false | 8e61bd60-936a-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T20:24:13.936Z | open | 2023-01-13T17:48:58.294Z | 2023-01-13T17:48:58.294Z | 3 | true |
>| nut.cc | nut.cc | Spam | 4 | Disposable email host | 2023-01-13T17:46:45.978Z | false | 489c6960-936a-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T20:13:42.181Z | open | 2023-01-13T17:47:01.238Z | 2023-01-13T17:47:01.238Z | 3 | true |
>| 5july.org | 5july.org | Spam | 4 | Disposable email host | 2023-01-13T17:46:31.250Z | false | 41755b60-936a-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:56:05.885Z | open | 2023-01-13T17:46:49.238Z | 2023-01-13T17:46:49.238Z | 3 | true |
>| nowmymail.com | nowmymail.com | Spam | 4 | Disposable email host | 2023-01-13T17:46:03.300Z | false | 2f9b5980-936a-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:56:48.668Z | open | 2023-01-13T17:46:19.288Z | 2023-01-13T17:46:19.288Z | 3 | true |
>| parafia.zlotoria.eu | parafia.zlotoria.eu | Malware | 4 | Malware family TrojanDownloader:JS/FakejQuery.AR!MTB | 2023-01-13T17:44:16.981Z | false | ef3bdb80-9369-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T20:13:59.851Z | open | 2023-01-13T17:44:31.288Z | 2023-01-13T17:44:31.288Z | 3 | true |
>| melodypods.com | melodypods.com | Malware | 4 | Malware family Tr.A.Phishing.Pdf | 2023-01-13T17:43:11.255Z | false | c7e6bc30-9369-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T20:12:27.003Z | open | 2023-01-13T17:43:25.299Z | 2023-01-13T17:43:25.299Z | 3 | true |
>| prettypower.net,<br/>leadmine.net,<br/>cloudstep.net,<br/>southscene.net,<br/>heavyobject.net | Malware family Suppobox | DGA | 9 | Malware family Suppobox | 2023-01-13T17:39:51.654Z | false | 50358f90-9369-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4055: 1<br/>1580: 2<br/>4301: 3 | 2023-01-28T01:10:52.251Z | open | 2023-01-13T17:40:04.489Z | 2023-01-13T17:40:04.489Z | 6 | true |
>| humaility.com | humaility.com | Spam | 4 | Disposable email host | 2023-01-13T17:38:41.782Z | false | 27048450-9369-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:51:58.932Z | open | 2023-01-13T17:38:55.381Z | 2023-01-13T17:38:55.381Z | 4 | true |
>| bobmurchison.com | bobmurchison.com | Spam | 4 | Disposable email host | 2023-01-13T17:35:52.041Z | false | c2d0f770-9368-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:22:33.293Z | open | 2023-01-13T17:36:07.271Z | 2023-01-13T17:36:07.271Z | 4 | true |
>| zoemail.com | zoemail.com | Spam | 4 | Disposable email host | 2023-01-13T17:33:54.255Z | false | 7b48bdc0-9368-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:20:06.321Z | open | 2023-01-13T17:34:07.260Z | 2023-01-13T17:34:07.260Z | 4 | true |
>| curadincubator.org | curadincubator.org | Malware | 4 | Malware related | 2023-01-13T17:33:29.705Z | false | 6ec85ce0-9368-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:43:38.550Z | open | 2023-01-13T17:33:46.286Z | 2023-01-13T17:33:46.286Z | 4 | true |
>| whiffles.org | whiffles.org | Spam | 4 | Disposable email host | 2023-01-13T17:32:23.990Z | false | 45c6ed20-9368-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:41:00.772Z | open | 2023-01-13T17:32:37.490Z | 2023-01-13T17:32:37.490Z | 4 | true |
>| cdpa.cc | cdpa.cc | Spam | 4 | Disposable email host | 2023-01-13T17:32:14.141Z | false | 405a1240-9368-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:15:21.427Z | open | 2023-01-13T17:32:28.388Z | 2023-01-13T17:32:28.388Z | 4 | true |
>| kidsdown.com | kidsdown.com | Malware | 5 | Malware family Trojan.Win32.Generic | 2023-01-13T17:30:03.908Z | false | f3781080-9367-11ed-b0f8-a7e340234a4e | 1791: 4<br/>4301: 1 | 2023-01-27T19:24:20.940Z | open | 2023-01-13T17:30:19.400Z | 2023-01-13T17:30:19.400Z | 4 | true |
>| splushka.com | splushka.com | Malware | 4 | Malware family Trojan.Win32.Ml.B.Fl.Sabsik | 2023-01-13T17:26:27.909Z | false | 72a20a10-9367-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:00:23.687Z | open | 2023-01-13T17:26:43.249Z | 2023-01-13T17:26:43.249Z | 4 | true |
>| maboard.com | maboard.com | Spam | 4 | Disposable email host | 2023-01-13T17:26:24.964Z | false | 70d86da0-9367-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:18:43.461Z | open | 2023-01-13T17:26:40.250Z | 2023-01-13T17:26:40.250Z | 4 | true |
>| trashmail.me | trashmail.me | Spam | 7 | Disposable email host | 2023-01-13T17:25:20.022Z | false | 49817990-9367-11ed-b0f8-a7e340234a4e | 1791: 6<br/>4301: 1 | 2023-01-27T19:00:23.582Z | open | 2023-01-13T17:25:34.249Z | 2023-01-13T17:25:34.249Z | 4 | true |
>| garhoogin.com | garhoogin.com | Malware | 4 | Malware family Trojan.Win32.Plock.Tiggre | 2023-01-13T17:23:20.257Z | false | 02028eb0-9367-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:00:23.365Z | open | 2023-01-13T17:23:34.299Z | 2023-01-13T17:23:34.299Z | 3 | true |
>| rksbusiness.com | rksbusiness.com | C2C,<br/>Malware | 4 | Malware family Sodinokibi | 2023-01-13T17:21:12.216Z | false | b8b21820-9366-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:00:15.678Z | open | 2023-01-13T17:21:31.298Z | 2023-01-13T17:21:31.298Z | 4 | true |
>| ige.es | ige.es | Spam | 4 | Disposable email host | 2023-01-13T17:17:09.658Z | false | 260cbe30-9366-11ed-b0f8-a7e340234a4e | 1791: 3<br/>4301: 1 | 2023-01-27T19:00:15.153Z | open | 2023-01-13T17:17:25.267Z | 2023-01-13T17:17:25.267Z | 4 | true |
>| shorturl.ac | shorturl.ac | Phishing | 9 | Phishing domain | 2023-01-13T17:14:44.779Z | false | ce6c7df0-9365-11ed-b0f8-a7e340234a4e | 1791: 8<br/>4301: 1 | 2023-01-27T19:00:14.931Z | open | 2023-01-13T17:14:58.255Z | 2023-01-13T17:14:58.255Z | 4 | true |
>| recipeforfailure.com | recipeforfailure.com | Spam | 7 | Disposable email host | 2023-01-13T17:14:43.996Z | false | ce6a0cf0-9365-11ed-b0f8-a7e340234a4e | 1791: 5<br/>4301: 2 | 2023-01-27T19:00:23.405Z | open | 2023-01-13T17:14:58.239Z | 2023-01-13T17:14:58.239Z | 4 | true |
>| slimcleaner.com | slimcleaner.com | Malware | 5 | Malware family M.Slimware.Potentialrisk.PUA | 2023-01-13T17:14:23.518Z | false | c3b0d780-9365-11ed-b0f8-a7e340234a4e | 1791: 4<br/>4301: 1 | 2023-01-27T19:00:11.457Z | open | 2023-01-13T17:14:40.248Z | 2023-01-13T17:14:40.248Z | 4 | true |


### lumu-retrieve-muted-incidents
***
Get a paginated list of muted incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-muted-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page requested . | Optional | 
| items | items requested . | Optional | 
| adversary_types | Lumu adversary-types requested . | Optional | 
| labels | Lumu labels requested . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveMutedIncidents.items.id | String | Lumu incident id | 
| Lumu.RetrieveMutedIncidents.items.timestamp | Date | Lumu timestamp | 
| Lumu.RetrieveMutedIncidents.items.statusTimestamp | Date | Lumu statusTimestamp | 
| Lumu.RetrieveMutedIncidents.items.status | String | Lumu status | 
| Lumu.RetrieveMutedIncidents.items.contacts | Number | Lumu contacts | 
| Lumu.RetrieveMutedIncidents.items.adversaries | String | Lumu adversaries | 
| Lumu.RetrieveMutedIncidents.items.adversaryId | String | Lumu adversaryId | 
| Lumu.RetrieveMutedIncidents.items.adversaryTypes | String | Lumu adversaryTypes | 
| Lumu.RetrieveMutedIncidents.items.description | String | Lumu description | 
| Lumu.RetrieveMutedIncidents.items.labelDistribution | Number | Lumu labelDistribution | 
| Lumu.RetrieveMutedIncidents.items.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.RetrieveMutedIncidents.items.lastContact | Date | Lumu lastContact | 
| Lumu.RetrieveMutedIncidents.items.unread | Boolean | Lumu unread | 
| Lumu.RetrieveMutedIncidents.paginationInfo.page | Number | current page  | 
| Lumu.RetrieveMutedIncidents.paginationInfo.items | Number | current items  | 

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
                        "jits.ac.in"
                    ],
                    "adversaryId": "jits.ac.in",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 5,
                    "description": "QakBot",
                    "firstContact": "2023-01-13T21:51:12.190Z",
                    "hasPlaybackContacts": false,
                    "id": "6eddaf40-938c-11ed-b0f8-a7e340234a4e",
                    "labelDistribution": {
                        "1791": 1,
                        "4301": 1,
                        "548": 3
                    },
                    "lastContact": "2023-01-27T21:23:34.329Z",
                    "status": "muted",
                    "statusTimestamp": "2023-02-06T16:58:11.034Z",
                    "timestamp": "2023-01-13T21:51:28.308Z",
                    "totalEndpoints": 3,
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
                    "firstContact": "2022-03-07T14:37:02.228Z",
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
                },
                {
                    "adversaries": [
                        "vcdb.org"
                    ],
                    "adversaryId": "vcdb.org",
                    "adversaryTypes": [
                        "Phishing"
                    ],
                    "contacts": 5,
                    "description": "Phishing domain",
                    "firstContact": "2021-06-01T22:51:14Z",
                    "hasPlaybackContacts": false,
                    "id": "ee7dec20-c03d-11eb-b377-eba5fa4be63d",
                    "labelDistribution": {
                        "864": 1,
                        "989": 4
                    },
                    "lastContact": "2021-06-02T23:05:33Z",
                    "status": "closed",
                    "statusTimestamp": "2022-01-05T23:07:53.632Z",
                    "timestamp": "2021-05-29T05:22:59.170Z",
                    "totalEndpoints": 2,
                    "unread": false
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-02-07T23:20:22.014Z"
        }
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| jits.ac.in | jits.ac.in | Malware | 5 | QakBot | 2023-01-13T21:51:12.190Z | false | 6eddaf40-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>548: 3<br/>4301: 1 | 2023-01-27T21:23:34.329Z | muted | 2023-02-06T16:58:11.034Z | 2023-01-13T21:51:28.308Z | 3 | false |
>| 12finance.com | 12finance.com | Mining | 11 | CryptoMining domain | 2022-12-23T14:46:54Z | false | 721ed640-82d2-11ed-a600-d53ba4d2bb70 | 2148: 1<br/>2254: 10 | 2022-12-23T22:30:10.448Z | muted | 2022-12-27T02:39:14.360Z | 2022-12-23T14:59:48.772Z | 4 | false |
>| www.digeus.com | www.digeus.com | Malware | 2 | Malware family Application.Deceptor.ANL | 2022-12-12T23:20:56.706Z | false | ab056a80-7a73-11ed-a600-d53ba4d2bb70 | 147: 1<br/>218: 1 | 2022-12-22T20:37:02.228Z | muted | 2022-12-15T20:59:51.796Z | 2022-12-12T23:21:12.744Z | 2 | false |
>| jameshallybone.co.uk | jameshallybone.co.uk | Malware | 8 | Malicious domain | 2022-11-21T21:46:01.425Z | false | f06a50c0-69e5-11ed-89c2-6136df938368 | 989: 6<br/>1651: 1<br/>3811: 1 | 2022-12-05T16:03:05.322Z | muted | 2022-12-13T20:48:09.825Z | 2022-11-21T21:46:22.028Z | 3 | false |
>| 3.223.53.1 | 3.223.53.1 | Spam | 1 | Activity Test Query | 2022-12-12T17:09:20.331Z | false | 8b6f8c70-7a71-11ed-a600-d53ba4d2bb70 | 218: 1 | 2022-12-12T17:09:20.331Z | muted | 2022-12-12T23:21:43.833Z | 2022-12-12T23:06:00.759Z | 1 | false |
>| coovigomez.com | coovigomez.com | Mining | 1 | CryptoMining domain | 2022-11-12T23:31:33Z | false | 149207b0-6471-11ed-b373-192ba321fedf | 2148: 1 | 2022-11-12T23:31:33Z | muted | 2022-11-17T18:56:09.751Z | 2022-11-14T23:07:15.755Z | 1 | false |
>| barbombon.com. | barbombon.com. | Malware | 2 | Malware family Trojan.Script.Generic | 2022-10-28T19:39:13.452Z | false | 47bbc6c0-56f8-11ed-987a-cd6f8ff058b8 | 1651: 2 | 2022-10-28T19:44:10.172Z | muted | 2022-10-31T21:51:02.594Z | 2022-10-28T19:39:47.372Z | 1 | false |
>| coasttickets.com | coasttickets.com | Malware | 1 | Malware family Trojan.Downloader.Psdownload.MSIL.Generic | 2022-09-22T15:19:42.152Z | true | 11c5a410-41fd-11ed-8751-63984e51f242 | 548: 1 | 2022-09-22T15:19:42.152Z | muted | 2022-10-28T17:06:32.994Z | 2022-10-02T02:51:09.905Z | 1 | false |
>| dark-utilities.pw | dark-utilities.pw | Mining | 2 | CryptoMining domain | 2022-10-27T16:47:40Z | false | 8da63fc0-5618-11ed-987a-cd6f8ff058b8 | 2148: 1<br/>2267: 1 | 2022-10-27T17:12:45.099Z | muted | 2022-10-27T17:57:57.931Z | 2022-10-27T16:58:17.404Z | 2 | false |
>| www.com-about.com | www.com-about.com | Malware | 1 | Malware family Downloader.Riskware.A.Atoz | 2022-10-25T20:45:41.154Z | false | 046a19c0-54a6-11ed-9df2-6538d9561738 | 3635: 1 | 2022-10-25T20:45:41.154Z | muted | 2022-10-25T21:17:21.376Z | 2022-10-25T20:45:53.372Z | 1 | false |
>| nexttime.ovh | nexttime.ovh | Malware,<br/>Mining | 5 | Malicious domain | 2022-10-25T21:13:43.551Z | false | ef8ee900-54a9-11ed-9df2-6538d9561738 | 3635: 5 | 2022-10-26T22:45:31.230Z | muted | 2022-10-25T21:16:15.909Z | 2022-10-25T21:13:56.368Z | 1 | false |
>| pinkexcel.com | pinkexcel.com | C2C,<br/>Malware | 1 | Malware family Sodinokibi | 2022-09-15T14:33:58.544Z | false | ef8ef190-3503-11ed-9b90-a51546bb08b5 | 548: 1 | 2022-09-15T14:33:58.544Z | muted | 2022-10-25T20:38:58.664Z | 2022-09-15T14:37:33.865Z | 1 | false |
>| ezstat.ru | ezstat.ru | Malware | 4 | Malware family Tr.Af.Fakealert.Html | 2022-10-19T16:23:50.322Z | false | 71f54180-4fca-11ed-9df2-6538d9561738 | 3077: 4 | 2022-10-21T15:53:49.585Z | muted | 2022-10-20T12:24:17.272Z | 2022-10-19T16:24:03.224Z | 1 | false |
>| fbbrrnheqexb.online,<br/>fulimvwfyjol.com,<br/>gklmwtupmnwx.com,<br/>grccwbqgltxo.com,<br/>mrsvxqjipgbq.biz | Malware family Tinba | DGA | 5 | Malware family Tinba | 2022-10-18T15:10:08.512Z | false | 784d16b0-4f1c-11ed-9df2-6538d9561738 | 1791: 5 | 2022-10-18T15:10:08.512Z | muted | 2022-10-18T20:15:42.917Z | 2022-10-18T19:38:41.435Z | 1 | false |
>| chitraprakashan.com | chitraprakashan.com | Phishing | 1 | Phishing domain | 2022-09-16T20:24:54.669Z | false | b7585190-35fd-11ed-9b90-a51546bb08b5 | 548: 1 | 2022-09-16T20:24:54.669Z | muted | 2022-09-21T23:37:35.972Z | 2022-09-16T20:25:33.737Z | 1 | false |
>| 23.227.202.142 | 23.227.202.142 | C2C | 2 | Malware family Agentemis | 2022-09-07T15:22:02.529Z | false | f2084460-2ec0-11ed-9b90-a51546bb08b5 | 2280: 2 | 2022-09-07T15:22:03.289Z | muted | 2022-09-09T19:20:07.516Z | 2022-09-07T15:22:54.758Z | 1 | false |
>| video4you.com.hostinghood.com | video4you.com.hostinghood.com | C2C,<br/>Malware | 2 | Malware family VertexNet | 2022-07-14T16:39:33.444Z | false | 90e07b60-0393-11ed-80a5-f16f41289f2f | 1791: 1<br/>0: 1 | 2022-07-15T19:14:27Z | muted | 2022-08-08T15:50:00.228Z | 2022-07-14T16:39:44.406Z | 2 | false |
>| secure.runescape.com-oc.ru | secure.runescape.com-oc.ru | Malware | 47 | Malicious domain | 2022-07-07T06:47:29.452Z | false | dc758440-fdc0-11ec-80a5-f16f41289f2f | 1651: 4<br/>989: 43 | 2022-12-05T16:03:05.328Z | muted | 2022-07-07T20:15:16.997Z | 2022-07-07T06:48:51.588Z | 2 | false |
>| www.registrywizard.com | www.registrywizard.com | Malware | 1 | Malware family Win32.Wc.Adwareadposhel | 2022-07-04T15:27:43.917Z | false | ec3c46d0-fbad-11ec-bf30-1b7883f212a4 | 0: 1 | 2022-07-04T15:27:43.917Z | muted | 2022-07-05T15:48:52.651Z | 2022-07-04T15:28:15.293Z | 1 | false |
>| cc-cc.usa.cc | cc-cc.usa.cc | Spam | 5 | Disposable email host | 2022-06-30T16:18:42.635Z | false | 57ca5660-f890-11ec-bf30-1b7883f212a4 | 2267: 5 | 2022-06-30T16:30:15.536Z | muted | 2022-06-30T16:28:06.892Z | 2022-06-30T16:18:57.350Z | 1 | false |
>| email.cbes.net | email.cbes.net | Spam | 2 | Disposable email host | 2022-06-28T22:49:59.229Z | false | b8fe8210-f734-11ec-ad9e-6f96a7a32f4d | 2267: 2 | 2022-06-30T16:18:44.373Z | muted | 2022-06-30T09:08:24.362Z | 2022-06-28T22:50:35.569Z | 1 | false |
>| dma.in-ulm.de | dma.in-ulm.de | Spam | 2 | Disposable email host | 2022-06-28T22:50:47.762Z | false | e04c7570-f734-11ec-ad9e-6f96a7a32f4d | 2267: 2 | 2022-06-30T16:18:43.901Z | muted | 2022-06-29T21:18:22.197Z | 2022-06-28T22:51:41.511Z | 1 | false |
>| grupoexclusiva.cl | grupoexclusiva.cl | Mining | 18 | CryptoMining domain | 2022-06-24T13:54:57Z | false | 236ddf00-f3c6-11ec-ad9e-6f96a7a32f4d | 2148: 1<br/>989: 17 | 2022-06-30T01:15:58.167Z | muted | 2022-06-24T21:58:39.281Z | 2022-06-24T14:01:26.512Z | 6 | false |
>| dnd5spells.rpgist.net | dnd5spells.rpgist.net | Mining | 2 | CryptoMining domain | 2022-06-24T00:07:34.283Z | false | ac3e7e40-f351-11ec-ad9e-6f96a7a32f4d | 989: 2 | 2022-06-24T00:07:55.505Z | muted | 2022-06-24T15:12:28.661Z | 2022-06-24T00:07:44.932Z | 1 | false |
>| smetafor.ru | smetafor.ru | Mining | 6 | CryptoMining domain | 2022-06-22T22:12:46.158Z | false | 785a8bc0-f278-11ec-bb85-650a89d8b1da | 989: 6 | 2022-06-22T22:20:59.876Z | muted | 2022-06-23T09:53:14.529Z | 2022-06-22T22:12:57.084Z | 1 | false |
>| subw.ru | subw.ru | Mining | 1 | CryptoMining domain | 2022-06-21T18:33:25Z | false | c080a110-f191-11ec-bb85-650a89d8b1da | 2148: 1 | 2022-06-21T18:33:25Z | muted | 2022-06-22T22:55:51.151Z | 2022-06-21T18:41:24.385Z | 1 | false |
>| www.globalpatron.com | www.globalpatron.com | Phishing | 21 | Phishing domain | 2022-06-15T21:06:21Z | false | 31cfbec0-ecef-11ec-bb85-650a89d8b1da | 1189: 3<br/>1580: 2<br/>989: 16 | 2022-08-01T19:13:09Z | muted | 2022-06-16T19:38:45.965Z | 2022-06-15T21:07:41.868Z | 5 | false |
>| minergate.com | minergate.com | Malware,<br/>Mining | 8 | Malware related | 2022-06-08T21:42:24Z | false | eaed0560-e773-11ec-b7a5-9ded001a2220 | 1681: 8 | 2022-06-08T21:43:18Z | muted | 2022-06-08T23:05:21.185Z | 2022-06-08T21:42:39.030Z | 1 | false |
>| ru.minergate.com | ru.minergate.com | Malware | 4 | Malicious domain | 2022-06-08T21:45:52Z | false | 67e92d00-e774-11ec-b7a5-9ded001a2220 | 1681: 4 | 2022-06-08T21:45:52Z | muted | 2022-06-08T22:45:30.098Z | 2022-06-08T21:46:08.720Z | 1 | false |
>| www.wersage.bugs3.com | www.wersage.bugs3.com | C2C,<br/>Malware | 2 | Malware family Stealer | 2022-06-08T17:57:32Z | false | 780bb680-e756-11ec-b7a5-9ded001a2220 | 1885: 2 | 2022-06-08T17:57:32Z | muted | 2022-06-08T21:13:03.626Z | 2022-06-08T18:11:50.888Z | 1 | false |
>| fundacionalianzas.com | fundacionalianzas.com | Mining | 1 | CryptoMining domain | 2022-06-08T12:52:40Z | false | 1dc013e0-e72b-11ec-b7a5-9ded001a2220 | 2148: 1 | 2022-06-08T12:52:40Z | muted | 2022-06-08T15:08:27.370Z | 2022-06-08T13:01:31.038Z | 1 | false |
>| dominj.ru | dominj.ru | Mining | 1 | CryptoMining domain | 2022-06-07T01:19:27Z | false | b614aec0-e600-11ec-b7a5-9ded001a2220 | 2148: 1 | 2022-06-07T01:19:27Z | muted | 2022-06-08T09:13:02.725Z | 2022-06-07T01:25:27.084Z | 1 | false |
>| www.13stamps.com | www.13stamps.com | Mining | 1 | CryptoMining domain | 2022-06-04T20:47:36Z | false | bec14c40-e448-11ec-b7a5-9ded001a2220 | 2148: 1 | 2022-06-04T20:47:36Z | muted | 2022-06-06T20:39:00.854Z | 2022-06-04T20:56:03.076Z | 1 | false |
>| trk.klclick3.com | trk.klclick3.com | Phishing | 6 | Phishing domain | 2022-06-03T21:02:12.317Z | false | 777e07b0-e380-11ec-b7a5-9ded001a2220 | 989: 2<br/>2144: 3<br/>147: 1 | 2022-06-09T15:05:59.984Z | muted | 2022-06-03T22:30:12.767Z | 2022-06-03T21:02:24.171Z | 4 | false |
>| privedmidved.net | privedmidved.net | C2C,<br/>Malware | 1 | Malware family WebInject | 2022-06-03T21:01:47Z | false | 5c068eb0-e382-11ec-b7a5-9ded001a2220 | 1885: 1 | 2022-06-03T21:01:47Z | muted | 2022-06-03T22:00:37.147Z | 2022-06-03T21:15:57.083Z | 1 | false |
>| www.zhong-ix.com | www.zhong-ix.com | C2C,<br/>Malware | 1 | Malware family P2PZeuS | 2022-06-03T21:00:56.760Z | false | 793fdbf0-e380-11ec-b7a5-9ded001a2220 | 0: 1 | 2022-06-03T21:00:56.760Z | muted | 2022-06-03T21:58:48.985Z | 2022-06-03T21:02:27.119Z | 1 | false |
>| icce.cl | icce.cl | C2C,<br/>Malware | 2 | Malware family Backdoor | 2022-05-23T13:45:10.784Z | false | 9867a520-da9e-11ec-af21-1383d6a11730 | 147: 1<br/>218: 1 | 2022-05-25T16:19:45.246Z | muted | 2022-06-02T22:54:39.424Z | 2022-05-23T13:45:23.826Z | 2 | false |
>| herp.in | herp.in | Spam | 8 | Disposable email host | 2022-05-24T15:16:38.125Z | false | 9cfe17f0-db74-11ec-af21-1383d6a11730 | 2267: 5<br/>218: 1<br/>2692: 2 | 2022-12-19T22:38:10.956Z | muted | 2022-06-01T23:55:09.793Z | 2022-05-24T15:17:23.823Z | 5 | false |
>| backgrounds.pk | backgrounds.pk | C2C,<br/>Malware | 20 | RaccoonStealer |  | false | ca4ebe00-aa26-11ec-af58-8da2705ed08a | 864: 18<br/>0: 2 | 2022-10-19T15:07:40.899Z | muted | 2022-03-22T21:28:05.171Z | 2022-03-22T21:26:52.128Z | 2 | false |
>| 0x21.in | 0x21.in | C2C | 14 | QuasarRAT |  | false | 983d5c00-aa26-11ec-af58-8da2705ed08a | 864: 14 | 2022-03-22T21:27:49.692Z | muted | 2022-03-22T21:27:38.469Z | 2022-03-22T21:25:28.128Z | 1 | false |
>| mimbc.net | mimbc.net | C2C,<br/>Malware | 28 | Malware family P2PZeuS | 2022-07-04T04:06:02.042Z | false | 7ab62700-a4b0-11ec-af58-8da2705ed08a | 864: 1<br/>1885: 2<br/>2254: 24<br/>989: 1 | 2023-01-03T23:31:45.292Z | muted | 2022-03-15T22:54:40.924Z | 2022-03-15T22:37:22.160Z | 7 | false |
>| asapcallcenter.net | asapcallcenter.net | C2C | 5 | Malware family KINS |  | false | 2720e2a0-a0c9-11ec-af58-8da2705ed08a | 864: 1<br/>1651: 3<br/>548: 1 | 2022-07-09T15:53:55.423Z | muted | 2022-03-10T23:59:14.933Z | 2022-03-10T23:23:54.698Z | 3 | false |
>| queenshippartners.com | queenshippartners.com | C2C,<br/>Malware | 1 | Malware family P2PZeuS |  | false | 17220c70-9fe4-11ec-b69e-2d8391d9c9ca | 1885: 1 | 2022-03-09T19:52:48Z | muted | 2022-03-10T05:28:53.416Z | 2022-03-09T20:04:13.111Z | 1 | false |
>| freelancergyn.com.br | freelancergyn.com.br | C2C | 1 | Malware family P2PZeuS |  | false | e78a1410-9fd1-11ec-b69e-2d8391d9c9ca | 1885: 1 | 2022-03-09T17:39:06Z | muted | 2022-03-09T19:00:15.293Z | 2022-03-09T17:54:02.321Z | 1 | false |
>| saecargomaritime.com | saecargomaritime.com | C2C,<br/>Malware | 1 | Malware family Fareit | 2022-03-07T14:37:02.228Z | false | 582f8cf0-9ea0-11ec-b69e-2d8391d9c9ca | 218: 1 | 2022-03-07T14:37:02.228Z | muted | 2022-03-08T20:29:54.248Z | 2022-03-08T05:26:45.311Z | 1 | false |
>| domain2222.com | domain2222.com | C2C,<br/>Malware | 36 | Malware family TaurusStealer |  | false | d39f4230-7a43-11ec-843d-dd7e2ea288b6 | 280: 1<br/>0: 2<br/>1885: 20<br/>1851: 13 | 2022-01-27T16:10:09Z | muted | 2022-02-08T20:40:31.481Z | 2022-01-20T22:53:47.347Z | 3 | false |
>| www.credi-familialtda.com | www.credi-familialtda.com | Phishing | 1 | Phishing domain |  | false | 64ea9a30-796f-11ec-843d-dd7e2ea288b6 | 864: 1 | 2022-01-19T21:32:55.282Z | muted | 2022-01-24T14:21:11.017Z | 2022-01-19T21:33:08.307Z | 1 | false |
>| saner.com.au | saner.com.au | C2C,<br/>Malware | 7 | Malware family P2PZeuS |  | false | e37738d0-7b0f-11ec-b95a-431da32564f1 | 218: 4<br/>1885: 1<br/>1988: 1<br/>1851: 1 | 2022-03-07T21:21:01Z | muted | 2022-01-21T23:18:45.525Z | 2022-01-21T23:14:31.261Z | 2 | false |
>| tempmail.co | tempmail.co | Spam | 1953 | Disposable email host | 2022-01-05T22:58:12.900Z | false | e727df00-6e7d-11ec-a2fc-7f6e039c5267 | 989: 1952<br/>864: 1 | 2022-06-24T14:17:43.651Z | muted | 2022-01-06T15:13:22.379Z | 2022-01-05T23:19:16.976Z | 2 | false |
>| vcdb.org | vcdb.org | Phishing | 5 | Phishing domain | 2021-06-01T22:51:14Z | false | ee7dec20-c03d-11eb-b377-eba5fa4be63d | 864: 1<br/>989: 4 | 2021-06-02T23:05:33Z | closed | 2022-01-05T23:07:53.632Z | 2021-05-29T05:22:59.170Z | 2 | false |


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
                }
            ],
            "paginationInfo": {
                "items": 50,
                "page": 1
            },
            "timestamp": "2023-02-07T23:20:24.161Z"
        }
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| jameshallybone.co.uk | jameshallybone.co.uk | Malware | 8 | Malicious domain | 2022-11-21T21:46:01.425Z | false | f06a50c0-69e5-11ed-89c2-6136df938368 | 989: 6<br/>1651: 1<br/>3811: 1 | 2022-12-05T16:03:05.322Z | muted | 2022-12-13T20:48:09.825Z | 2022-11-21T21:46:22.028Z | 3 | false |
>| barbombon.com. | barbombon.com. | Malware | 2 | Malware family Trojan.Script.Generic | 2022-10-28T19:39:13.452Z | false | 47bbc6c0-56f8-11ed-987a-cd6f8ff058b8 | 1651: 2 | 2022-10-28T19:44:10.172Z | muted | 2022-10-31T21:51:02.594Z | 2022-10-28T19:39:47.372Z | 1 | false |
>| secure.runescape.com-oc.ru | secure.runescape.com-oc.ru | Malware | 47 | Malicious domain | 2022-07-07T06:47:29.452Z | false | dc758440-fdc0-11ec-80a5-f16f41289f2f | 1651: 4<br/>989: 43 | 2022-12-05T16:03:05.328Z | muted | 2022-07-07T20:15:16.997Z | 2022-07-07T06:48:51.588Z | 2 | false |
>| asapcallcenter.net | asapcallcenter.net | C2C | 5 | Malware family KINS |  | false | 2720e2a0-a0c9-11ec-af58-8da2705ed08a | 864: 1<br/>1651: 3<br/>548: 1 | 2022-07-09T15:53:55.423Z | muted | 2022-03-10T23:59:14.933Z | 2022-03-10T23:23:54.698Z | 3 | false |


### lumu-retrieve-closed-incidents
***
Get a paginated list of closed incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-closed-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page requested . | Optional | 
| items | items requested . | Optional | 
| adversary_types | Lumu adversary-types requested. | Optional | 
| labels | Lumu labels requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveClosedIncidents.items.id | String | Lumu incident id | 
| Lumu.RetrieveClosedIncidents.items.timestamp | Date | Lumu timestamp | 
| Lumu.RetrieveClosedIncidents.items.statusTimestamp | Date | Lumu statusTimestamp | 
| Lumu.RetrieveClosedIncidents.items.status | String | Lumu status | 
| Lumu.RetrieveClosedIncidents.items.contacts | Number | Lumu contacts | 
| Lumu.RetrieveClosedIncidents.items.adversaries | String | Lumu adversaries | 
| Lumu.RetrieveClosedIncidents.items.adversaryId | String | Lumu adversaryId | 
| Lumu.RetrieveClosedIncidents.items.adversaryTypes | String | Lumu adversaryTypes | 
| Lumu.RetrieveClosedIncidents.items.description | String | Lumu description | 
| Lumu.RetrieveClosedIncidents.items.labelDistribution | Number | Lumu labelDistribution | 
| Lumu.RetrieveClosedIncidents.items.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.RetrieveClosedIncidents.items.lastContact | Date | Lumu lastContact | 
| Lumu.RetrieveClosedIncidents.items.unread | Boolean | Lumu unread | 
| Lumu.RetrieveClosedIncidents.paginationInfo.page | Number | current page  | 
| Lumu.RetrieveClosedIncidents.paginationInfo.items | Number | current items  | 
| Lumu.RetrieveClosedIncidents.paginationInfo.next | Number | next page  | 

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
                    "contacts": 12,
                    "description": "Activity Test Query",
                    "firstContact": "2023-02-07T15:51:15.463Z",
                    "hasPlaybackContacts": false,
                    "id": "826dd220-a6ff-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "0": 11,
                        "989": 1
                    },
                    "lastContact": "2023-02-07T15:51:15.463Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-07T23:08:53.658Z",
                    "timestamp": "2023-02-07T15:53:05.346Z",
                    "totalEndpoints": 3,
                    "unread": false
                },
                {
                    "adversaries": [
                        "104.156.63.145"
                    ],
                    "adversaryId": "104.156.63.145",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 5,
                    "description": "Malware family Agentemis",
                    "firstContact": "2023-02-08T03:09:07Z",
                    "hasPlaybackContacts": false,
                    "id": "b22ba330-a72b-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "2144": 5
                    },
                    "lastContact": "2023-02-08T03:09:09Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-07T21:10:17.404Z",
                    "timestamp": "2023-02-07T21:09:23.299Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "104.156.63.145"
                    ],
                    "adversaryId": "104.156.63.145",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 10,
                    "description": "Malware family Agentemis",
                    "firstContact": "2023-02-08T00:50:58Z",
                    "hasPlaybackContacts": false,
                    "id": "65a131f0-a718-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "2144": 10
                    },
                    "lastContact": "2023-02-08T00:52:12Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-07T21:07:38.628Z",
                    "timestamp": "2023-02-07T18:51:14.447Z",
                    "totalEndpoints": 1,
                    "unread": false
                },
                {
                    "adversaries": [
                        "104.156.63.145"
                    ],
                    "adversaryId": "104.156.63.145",
                    "adversaryTypes": [
                        "C2C"
                    ],
                    "contacts": 19,
                    "description": "Malware family Agentemis",
                    "firstContact": "2022-09-07T14:51:00.858Z",
                    "hasPlaybackContacts": false,
                    "id": "9b992df0-2ebc-11ed-9b90-a51546bb08b5",
                    "labelDistribution": {
                        "2144": 17,
                        "2280": 2
                    },
                    "lastContact": "2023-02-08T00:49:59Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-07T18:50:39.534Z",
                    "timestamp": "2022-09-07T14:51:51.759Z",
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
                    "id": "eb611160-a638-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-06T16:19:52.211Z",
                    "timestamp": "2023-02-06T16:11:31.574Z",
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
                    "contacts": 22,
                    "description": "Activity Test Query",
                    "firstContact": "2023-02-01T15:13:41.904Z",
                    "hasPlaybackContacts": false,
                    "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 9,
                        "1792": 1,
                        "989": 12
                    },
                    "lastContact": "2023-02-03T16:44:00.395Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-06T16:04:22.570Z",
                    "timestamp": "2023-02-01T15:14:17.061Z",
                    "totalEndpoints": 5,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.chg.com.br"
                    ],
                    "adversaryId": "www.chg.com.br",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 3,
                    "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                    "firstContact": "2023-02-03T19:01:00Z",
                    "hasPlaybackContacts": false,
                    "id": "608c0ee0-a3f5-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "989": 3
                    },
                    "lastContact": "2023-02-03T19:01:30Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-03T19:05:06.851Z",
                    "timestamp": "2023-02-03T19:03:00.046Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "www.chg.com.br"
                    ],
                    "adversaryId": "www.chg.com.br",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 6,
                    "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                    "firstContact": "2023-02-26T18:57:00Z",
                    "hasPlaybackContacts": false,
                    "id": "6afd9ee0-a3f3-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "989": 6
                    },
                    "lastContact": "2023-02-26T18:57:30Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-03T19:01:12.035Z",
                    "timestamp": "2023-02-03T18:48:58.574Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "ascentive.com"
                    ],
                    "adversaryId": "ascentive.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 3,
                    "description": "Malware family HEUR:Trojan.Win32.Generic",
                    "firstContact": "2023-01-28T02:26:51.842Z",
                    "hasPlaybackContacts": false,
                    "id": "44df68a0-9eb3-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1,
                        "989": 2
                    },
                    "lastContact": "2023-02-02T23:51:26.327Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-02T23:54:08.075Z",
                    "timestamp": "2023-01-28T02:27:11.018Z",
                    "totalEndpoints": 2,
                    "unread": false
                },
                {
                    "adversaries": [
                        "smartvizx.com"
                    ],
                    "adversaryId": "smartvizx.com",
                    "adversaryTypes": [
                        "Malware"
                    ],
                    "contacts": 1,
                    "description": "QakBot",
                    "firstContact": "2023-01-28T03:04:15.908Z",
                    "hasPlaybackContacts": true,
                    "id": "0a017730-a1ee-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "4301": 1
                    },
                    "lastContact": "2023-01-28T03:04:15.908Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-02T17:08:28.378Z",
                    "timestamp": "2023-02-01T05:05:26.051Z",
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
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "f55f27b0-9e36-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-27T11:56:03.516Z",
                    "timestamp": "2023-01-27T11:37:20.043Z",
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
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T23:17:50.720Z",
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
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-02-07T23:20:26.085Z"
        }
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| activity.lumu.io | activity.lumu.io | Spam | 12 | Activity Test Query | 2023-02-07T15:51:15.463Z | false | 826dd220-a6ff-11ed-9fd0-e5fb50c818f6 | 989: 1<br/>0: 11 | 2023-02-07T15:51:15.463Z | closed | 2023-02-07T23:08:53.658Z | 2023-02-07T15:53:05.346Z | 3 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 5 | Malware family Agentemis | 2023-02-08T03:09:07Z | false | b22ba330-a72b-11ed-9fd0-e5fb50c818f6 | 2144: 5 | 2023-02-08T03:09:09Z | closed | 2023-02-07T21:10:17.404Z | 2023-02-07T21:09:23.299Z | 1 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 10 | Malware family Agentemis | 2023-02-08T00:50:58Z | false | 65a131f0-a718-11ed-9fd0-e5fb50c818f6 | 2144: 10 | 2023-02-08T00:52:12Z | closed | 2023-02-07T21:07:38.628Z | 2023-02-07T18:51:14.447Z | 1 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 19 | Malware family Agentemis | 2022-09-07T14:51:00.858Z | false | 9b992df0-2ebc-11ed-9b90-a51546bb08b5 | 2280: 2<br/>2144: 17 | 2023-02-08T00:49:59Z | closed | 2023-02-07T18:50:39.534Z | 2022-09-07T14:51:51.759Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | eb611160-a638-11ed-a0c7-dd6f8e69d343 | 0: 3 | 2022-12-20T14:37:02.228Z | closed | 2023-02-06T16:19:52.211Z | 2023-02-06T16:11:31.574Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 22 | Activity Test Query | 2023-02-01T15:13:41.904Z | false | 182f3950-a243-11ed-a0c7-dd6f8e69d343 | 1792: 1<br/>989: 12<br/>0: 9 | 2023-02-03T16:44:00.395Z | closed | 2023-02-06T16:04:22.570Z | 2023-02-01T15:14:17.061Z | 5 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 3 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-03T19:01:00Z | false | 608c0ee0-a3f5-11ed-a0c7-dd6f8e69d343 | 989: 3 | 2023-02-03T19:01:30Z | closed | 2023-02-03T19:05:06.851Z | 2023-02-03T19:03:00.046Z | 2 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 6 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-26T18:57:00Z | false | 6afd9ee0-a3f3-11ed-a0c7-dd6f8e69d343 | 989: 6 | 2023-02-26T18:57:30Z | closed | 2023-02-03T19:01:12.035Z | 2023-02-03T18:48:58.574Z | 2 | false |
>| ascentive.com | ascentive.com | Malware | 3 | Malware family HEUR:Trojan.Win32.Generic | 2023-01-28T02:26:51.842Z | false | 44df68a0-9eb3-11ed-a0c7-dd6f8e69d343 | 4301: 1<br/>989: 2 | 2023-02-02T23:51:26.327Z | closed | 2023-02-02T23:54:08.075Z | 2023-01-28T02:27:11.018Z | 2 | false |
>| smartvizx.com | smartvizx.com | Malware | 1 | QakBot | 2023-01-28T03:04:15.908Z | true | 0a017730-a1ee-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T03:04:15.908Z | closed | 2023-02-02T17:08:28.378Z | 2023-02-01T05:05:26.051Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | f55f27b0-9e36-11ed-a0c7-dd6f8e69d343 | 0: 1 | 2022-12-20T14:37:02.228Z | closed | 2023-01-27T11:56:03.516Z | 2023-01-27T11:37:20.043Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343 | 0: 1 | 2022-12-20T14:37:02.228Z | closed | 2023-01-26T23:17:50.720Z | 2023-01-26T22:57:47.029Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 78b465c0-9dc5-11ed-a0c7-dd6f8e69d343 | 0: 3 | 2022-12-20T14:37:02.228Z | closed | 2023-01-26T22:14:29.778Z | 2023-01-26T22:04:57.756Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | ecc22120-9daa-11ed-a0c7-dd6f8e69d343 | 0: 2 | 2022-12-20T14:37:02.228Z | closed | 2023-01-26T19:08:45.185Z | 2023-01-26T18:54:56.050Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 7 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 29dab720-9d1f-11ed-a0c7-dd6f8e69d343 | 0: 7 | 2022-12-20T14:37:02.228Z | closed | 2023-01-26T18:52:06.437Z | 2023-01-26T02:14:29.010Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 98 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343 | 0: 28<br/>989: 69<br/>4232: 1 | 2023-01-24T21:17:50Z | closed | 2023-01-26T02:13:33.006Z | 2023-01-24T11:48:56.059Z | 4 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | f563af00-9bda-11ed-a0c7-dd6f8e69d343 | 0: 1 | 2022-12-20T14:37:02.228Z | closed | 2023-01-24T11:45:59.944Z | 2023-01-24T11:33:44.048Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 10 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 2bc88020-9b2c-11ed-980e-915fb2011ca7 | 0: 10 | 2022-12-20T14:37:02.228Z | closed | 2023-01-24T11:33:24.832Z | 2023-01-23T14:42:33.378Z | 5 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 7 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 9b430be0-9b1e-11ed-980e-915fb2011ca7 | 0: 7 | 2022-12-20T14:37:02.228Z | closed | 2023-01-23T14:24:09.462Z | 2023-01-23T13:05:27.454Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 249b6b90-9b14-11ed-980e-915fb2011ca7 | 0: 2 | 2022-12-20T14:37:02.228Z | closed | 2023-01-23T12:57:59.609Z | 2023-01-23T11:50:33.417Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 4 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | cae5a990-99e6-11ed-980e-915fb2011ca7 | 0: 4 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T23:58:48.655Z | 2023-01-21T23:53:24.393Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 7 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 7db7c400-99e1-11ed-980e-915fb2011ca7 | 0: 7 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T23:51:47.406Z | 2023-01-21T23:15:27.424Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 4 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 72067f80-99cc-11ed-980e-915fb2011ca7 | 0: 4 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T23:13:41.679Z | 2023-01-21T20:44:48.376Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | eaba8420-9932-11ed-980e-915fb2011ca7 | 0: 3 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T02:27:53.605Z | 2023-01-21T02:25:48.386Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 0f055c60-9901-11ed-980e-915fb2011ca7 | 0: 2 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T02:24:55.326Z | 2023-01-20T20:28:54.438Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 134 | Activity Test Query | 2023-01-18T15:32:25.126Z | false | 3b43f070-982a-11ed-980e-915fb2011ca7 | 4055: 1<br/>0: 108<br/>989: 25 | 2023-01-18T17:02:46Z | closed | 2023-01-20T15:54:56.324Z | 2023-01-19T18:51:06.871Z | 10 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 36 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | aedb44c0-978a-11ed-b6d7-3f0c59c638d9 | 0: 36 | 2022-10-20T14:37:02.228Z | closed | 2023-01-19T16:42:19.541Z | 2023-01-18T23:49:01.324Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 26 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 8b02a730-9778-11ed-b6d7-3f0c59c638d9 | 0: 26 | 2022-10-20T14:37:02.228Z | closed | 2023-01-18T23:44:37.049Z | 2023-01-18T21:39:10.243Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 131 | Activity Test Query | 2023-01-16T17:00:18.868Z | false | 5c99aa20-95bf-11ed-b0f8-a7e340234a4e | 0: 130<br/>4055: 1 | 2023-01-18T15:32:25.126Z | closed | 2023-01-18T21:38:33.960Z | 2023-01-16T17:01:04.322Z | 3 | false |
>| hurricanepub.com | hurricanepub.com | C2C,<br/>Malware | 2 | Malware family UNC4034 | 2023-01-17T17:05:28.225Z | false | 2d49ca50-9689-11ed-b0f8-a7e340234a4e | 147: 2 | 2023-01-17T18:40:55.695Z | closed | 2023-01-18T14:43:31.970Z | 2023-01-17T17:05:43.285Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1053 | Activity Test Query | 2023-01-04T20:00:06.375Z | false | 7094dee0-8c6a-11ed-b0f8-a7e340234a4e | 0: 1045<br/>4055: 4<br/>4061: 3<br/>1580: 1 | 2023-01-16T16:01:28.124Z | closed | 2023-01-16T16:54:32.918Z | 2023-01-04T20:00:30.158Z | 5 | false |
>| ibu.com.uy | ibu.com.uy | Phishing | 8 | Phishing domain | 2022-12-21T16:39:39.451Z | false | 19294280-814e-11ed-a600-d53ba4d2bb70 | 2254: 8 | 2022-12-22T20:11:10.974Z | closed | 2023-01-06T19:12:19.050Z | 2022-12-21T16:39:54.792Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 24 | Activity Test Query | 2022-12-29T13:57:01.548Z | false | b27b1d90-8780-11ed-a600-d53ba4d2bb70 | 0: 22<br/>989: 1<br/>4053: 1 | 2023-01-04T19:00:52.902Z | closed | 2023-01-04T19:11:56.620Z | 2022-12-29T13:57:13.833Z | 3 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 4 | Activity Test Query | 2022-12-29T00:21:38.089Z | false | c97f79e0-870e-11ed-a600-d53ba4d2bb70 | 0: 4 | 2022-12-29T13:50:21.218Z | closed | 2022-12-29T13:54:35.413Z | 2022-12-29T00:21:49.822Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-12-29T00:18:57.237Z | false | 6abbae10-870e-11ed-a600-d53ba4d2bb70 | 0: 1 | 2022-12-29T00:18:57.237Z | closed | 2022-12-29T00:20:51.490Z | 2022-12-29T00:19:10.833Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-29T00:10:39.969Z | false | 41ed0390-870d-11ed-a600-d53ba4d2bb70 | 0: 3 | 2022-12-29T00:15:37.061Z | closed | 2022-12-29T00:18:37.071Z | 2022-12-29T00:10:52.873Z | 1 | false |
>| nightking43.art | nightking43.art | Mining | 1 | CryptoMining domain | 2022-12-14T22:40:32Z | false | e62442a0-7c74-11ed-a600-d53ba4d2bb70 | 2148: 1 | 2022-12-14T22:40:32Z | closed | 2022-12-28T23:58:13.010Z | 2022-12-15T12:35:03.754Z | 1 | false |
>| javxr.com | javxr.com | Mining | 11 | CryptoMining domain | 2022-12-06T22:40:14.671Z | false | fb392f80-75b6-11ed-89c2-6136df938368 | 0: 10<br/>2267: 1 | 2022-12-22T18:29:18.846Z | closed | 2022-12-28T23:50:06.608Z | 2022-12-06T22:40:27.768Z | 2 | false |
>| anx.com.np | anx.com.np | Mining | 1 | CryptoMining domain | 2022-12-09T19:48:27Z | false | f70cc990-7948-11ed-89c2-6136df938368 | 2148: 1 | 2022-12-09T19:48:27Z | closed | 2022-12-28T23:48:38.328Z | 2022-12-11T11:43:00.777Z | 1 | false |
>| go.ly | go.ly | Phishing | 1 | Phishing domain | 2022-12-11T20:00:30Z | false | 8f3d9c90-798e-11ed-89c2-6136df938368 | 3938: 1 | 2022-12-11T20:00:30Z | closed | 2022-12-28T23:37:53.303Z | 2022-12-11T20:01:11.385Z | 1 | false |
>| api.netflare.info | api.netflare.info | Malware,<br/>Mining | 1 | Malicious domain | 2022-12-09T22:37:16Z | false | 99890290-796e-11ed-89c2-6136df938368 | 2148: 1 | 2022-12-09T22:37:16Z | closed | 2022-12-28T23:23:34.778Z | 2022-12-11T16:12:24.761Z | 1 | false |
>| www.ascentive.com | www.ascentive.com | Malware | 1 | Malware family Trojan.Win32.Generic | 2022-12-12T22:11:46.180Z | false | 003eef80-7a6a-11ed-a600-d53ba4d2bb70 | 147: 1 | 2022-12-12T22:11:46.180Z | closed | 2022-12-28T23:20:35.551Z | 2022-12-12T22:12:00.760Z | 1 | false |
>| fastpool.xyz | fastpool.xyz | Malware | 3 | Malicious domain | 2022-12-16T14:46:54.264Z | false | 84d264f0-7d50-11ed-a600-d53ba4d2bb70 | 147: 1<br/>2254: 2 | 2022-12-16T19:49:02.864Z | closed | 2022-12-28T23:17:35.713Z | 2022-12-16T14:47:09.759Z | 2 | false |
>| lps.peacerental.com | lps.peacerental.com | Phishing | 3 | Phishing domain | 2022-12-12T17:19:31.374Z | false | 2c924600-7a41-11ed-a600-d53ba4d2bb70 | 147: 2<br/>1885: 1 | 2022-12-12T23:43:34Z | closed | 2022-12-28T23:13:49.481Z | 2022-12-12T17:19:45.760Z | 2 | false |
>| cnt.statistic.date | cnt.statistic.date | Malware,<br/>Mining | 1 | Malicious domain | 2022-12-12T16:09:46.405Z | false | 6c5393c0-7a37-11ed-a600-d53ba4d2bb70 | 0: 1 | 2022-12-12T16:09:46.405Z | closed | 2022-12-28T23:05:23.814Z | 2022-12-12T16:09:57.756Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 6 | Activity Test Query | 2022-12-27T20:05:47Z | false | 37eb2760-8635-11ed-a600-d53ba4d2bb70 | 2148: 6 | 2022-12-27T20:51:54Z | closed | 2022-12-28T22:47:44.343Z | 2022-12-27T22:24:24.790Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 7 | Activity Test Query | 2022-12-22T18:29:08.846Z | false | 9326b8f0-8226-11ed-a600-d53ba4d2bb70 | 0: 1<br/>2254: 6 | 2022-12-23T22:34:34.191Z | closed | 2022-12-27T20:39:23.918Z | 2022-12-22T18:29:30.751Z | 4 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 4 | Activity Test Query | 2022-12-21T16:39:34.419Z | false | 159b60d0-814e-11ed-a600-d53ba4d2bb70 | 2254: 4 | 2022-12-21T16:39:34.696Z | closed | 2022-12-22T18:28:39.879Z | 2022-12-21T16:39:48.829Z | 1 | false |
>| ibu.com.uy | ibu.com.uy | Phishing | 1 | Phishing domain | 2022-12-20T23:20:59.367Z | false | fe5c9240-80bc-11ed-a600-d53ba4d2bb70 | 147: 1 | 2022-12-20T23:20:59.367Z | closed | 2022-12-21T16:26:11.582Z | 2022-12-20T23:21:12.804Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 6d178850-7d5e-11ed-a600-d53ba4d2bb70 | 0: 1<br/>2254: 1 | 2022-12-16T19:20:59.642Z | closed | 2022-12-21T16:23:38.937Z | 2022-12-16T16:26:42.901Z | 2 | false |


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
                    "contacts": 12,
                    "description": "Activity Test Query",
                    "firstContact": "2023-02-07T15:51:15.463Z",
                    "hasPlaybackContacts": false,
                    "id": "826dd220-a6ff-11ed-9fd0-e5fb50c818f6",
                    "labelDistribution": {
                        "0": 11,
                        "989": 1
                    },
                    "lastContact": "2023-02-07T15:51:15.463Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-07T23:08:53.658Z",
                    "timestamp": "2023-02-07T15:53:05.346Z",
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
                    "contacts": 3,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "eb611160-a638-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 3
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-06T16:19:52.211Z",
                    "timestamp": "2023-02-06T16:11:31.574Z",
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
                    "contacts": 22,
                    "description": "Activity Test Query",
                    "firstContact": "2023-02-01T15:13:41.904Z",
                    "hasPlaybackContacts": false,
                    "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 9,
                        "1792": 1,
                        "989": 12
                    },
                    "lastContact": "2023-02-03T16:44:00.395Z",
                    "status": "closed",
                    "statusTimestamp": "2023-02-06T16:04:22.570Z",
                    "timestamp": "2023-02-01T15:14:17.061Z",
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
                    "contacts": 1,
                    "description": "Activity Test Query",
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "f55f27b0-9e36-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-27T11:56:03.516Z",
                    "timestamp": "2023-01-27T11:37:20.043Z",
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
                    "firstContact": "2022-12-20T14:37:02.228Z",
                    "hasPlaybackContacts": false,
                    "id": "d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343",
                    "labelDistribution": {
                        "0": 1
                    },
                    "lastContact": "2022-12-20T14:37:02.228Z",
                    "status": "closed",
                    "statusTimestamp": "2023-01-26T23:17:50.720Z",
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
                }
            ],
            "paginationInfo": {
                "items": 50,
                "next": 2,
                "page": 1
            },
            "timestamp": "2023-02-07T23:20:28.283Z"
        }
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| activity.lumu.io | activity.lumu.io | Spam | 12 | Activity Test Query | 2023-02-07T15:51:15.463Z | false | 826dd220-a6ff-11ed-9fd0-e5fb50c818f6 | 989: 1<br/>0: 11 | 2023-02-07T15:51:15.463Z | closed | 2023-02-07T23:08:53.658Z | 2023-02-07T15:53:05.346Z | 3 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | eb611160-a638-11ed-a0c7-dd6f8e69d343 | 0: 3 | 2022-12-20T14:37:02.228Z | closed | 2023-02-06T16:19:52.211Z | 2023-02-06T16:11:31.574Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 22 | Activity Test Query | 2023-02-01T15:13:41.904Z | false | 182f3950-a243-11ed-a0c7-dd6f8e69d343 | 1792: 1<br/>989: 12<br/>0: 9 | 2023-02-03T16:44:00.395Z | closed | 2023-02-06T16:04:22.570Z | 2023-02-01T15:14:17.061Z | 5 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | f55f27b0-9e36-11ed-a0c7-dd6f8e69d343 | 0: 1 | 2022-12-20T14:37:02.228Z | closed | 2023-01-27T11:56:03.516Z | 2023-01-27T11:37:20.043Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | d9bd1450-9dcc-11ed-a0c7-dd6f8e69d343 | 0: 1 | 2022-12-20T14:37:02.228Z | closed | 2023-01-26T23:17:50.720Z | 2023-01-26T22:57:47.029Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 78b465c0-9dc5-11ed-a0c7-dd6f8e69d343 | 0: 3 | 2022-12-20T14:37:02.228Z | closed | 2023-01-26T22:14:29.778Z | 2023-01-26T22:04:57.756Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | ecc22120-9daa-11ed-a0c7-dd6f8e69d343 | 0: 2 | 2022-12-20T14:37:02.228Z | closed | 2023-01-26T19:08:45.185Z | 2023-01-26T18:54:56.050Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 7 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 29dab720-9d1f-11ed-a0c7-dd6f8e69d343 | 0: 7 | 2022-12-20T14:37:02.228Z | closed | 2023-01-26T18:52:06.437Z | 2023-01-26T02:14:29.010Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 98 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 14fd84b0-9bdd-11ed-a0c7-dd6f8e69d343 | 0: 28<br/>989: 69<br/>4232: 1 | 2023-01-24T21:17:50Z | closed | 2023-01-26T02:13:33.006Z | 2023-01-24T11:48:56.059Z | 4 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | f563af00-9bda-11ed-a0c7-dd6f8e69d343 | 0: 1 | 2022-12-20T14:37:02.228Z | closed | 2023-01-24T11:45:59.944Z | 2023-01-24T11:33:44.048Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 10 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 2bc88020-9b2c-11ed-980e-915fb2011ca7 | 0: 10 | 2022-12-20T14:37:02.228Z | closed | 2023-01-24T11:33:24.832Z | 2023-01-23T14:42:33.378Z | 5 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 7 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 9b430be0-9b1e-11ed-980e-915fb2011ca7 | 0: 7 | 2022-12-20T14:37:02.228Z | closed | 2023-01-23T14:24:09.462Z | 2023-01-23T13:05:27.454Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 249b6b90-9b14-11ed-980e-915fb2011ca7 | 0: 2 | 2022-12-20T14:37:02.228Z | closed | 2023-01-23T12:57:59.609Z | 2023-01-23T11:50:33.417Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 4 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | cae5a990-99e6-11ed-980e-915fb2011ca7 | 0: 4 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T23:58:48.655Z | 2023-01-21T23:53:24.393Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 7 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 7db7c400-99e1-11ed-980e-915fb2011ca7 | 0: 7 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T23:51:47.406Z | 2023-01-21T23:15:27.424Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 4 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 72067f80-99cc-11ed-980e-915fb2011ca7 | 0: 4 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T23:13:41.679Z | 2023-01-21T20:44:48.376Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | eaba8420-9932-11ed-980e-915fb2011ca7 | 0: 3 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T02:27:53.605Z | 2023-01-21T02:25:48.386Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 0f055c60-9901-11ed-980e-915fb2011ca7 | 0: 2 | 2022-12-20T14:37:02.228Z | closed | 2023-01-21T02:24:55.326Z | 2023-01-20T20:28:54.438Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 134 | Activity Test Query | 2023-01-18T15:32:25.126Z | false | 3b43f070-982a-11ed-980e-915fb2011ca7 | 4055: 1<br/>0: 108<br/>989: 25 | 2023-01-18T17:02:46Z | closed | 2023-01-20T15:54:56.324Z | 2023-01-19T18:51:06.871Z | 10 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 36 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | aedb44c0-978a-11ed-b6d7-3f0c59c638d9 | 0: 36 | 2022-10-20T14:37:02.228Z | closed | 2023-01-19T16:42:19.541Z | 2023-01-18T23:49:01.324Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 26 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 8b02a730-9778-11ed-b6d7-3f0c59c638d9 | 0: 26 | 2022-10-20T14:37:02.228Z | closed | 2023-01-18T23:44:37.049Z | 2023-01-18T21:39:10.243Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 131 | Activity Test Query | 2023-01-16T17:00:18.868Z | false | 5c99aa20-95bf-11ed-b0f8-a7e340234a4e | 0: 130<br/>4055: 1 | 2023-01-18T15:32:25.126Z | closed | 2023-01-18T21:38:33.960Z | 2023-01-16T17:01:04.322Z | 3 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1053 | Activity Test Query | 2023-01-04T20:00:06.375Z | false | 7094dee0-8c6a-11ed-b0f8-a7e340234a4e | 0: 1045<br/>4055: 4<br/>4061: 3<br/>1580: 1 | 2023-01-16T16:01:28.124Z | closed | 2023-01-16T16:54:32.918Z | 2023-01-04T20:00:30.158Z | 5 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 24 | Activity Test Query | 2022-12-29T13:57:01.548Z | false | b27b1d90-8780-11ed-a600-d53ba4d2bb70 | 0: 22<br/>989: 1<br/>4053: 1 | 2023-01-04T19:00:52.902Z | closed | 2023-01-04T19:11:56.620Z | 2022-12-29T13:57:13.833Z | 3 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 4 | Activity Test Query | 2022-12-29T00:21:38.089Z | false | c97f79e0-870e-11ed-a600-d53ba4d2bb70 | 0: 4 | 2022-12-29T13:50:21.218Z | closed | 2022-12-29T13:54:35.413Z | 2022-12-29T00:21:49.822Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-12-29T00:18:57.237Z | false | 6abbae10-870e-11ed-a600-d53ba4d2bb70 | 0: 1 | 2022-12-29T00:18:57.237Z | closed | 2022-12-29T00:20:51.490Z | 2022-12-29T00:19:10.833Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-29T00:10:39.969Z | false | 41ed0390-870d-11ed-a600-d53ba4d2bb70 | 0: 3 | 2022-12-29T00:15:37.061Z | closed | 2022-12-29T00:18:37.071Z | 2022-12-29T00:10:52.873Z | 1 | false |
>| javxr.com | javxr.com | Mining | 11 | CryptoMining domain | 2022-12-06T22:40:14.671Z | false | fb392f80-75b6-11ed-89c2-6136df938368 | 0: 10<br/>2267: 1 | 2022-12-22T18:29:18.846Z | closed | 2022-12-28T23:50:06.608Z | 2022-12-06T22:40:27.768Z | 2 | false |
>| cnt.statistic.date | cnt.statistic.date | Malware,<br/>Mining | 1 | Malicious domain | 2022-12-12T16:09:46.405Z | false | 6c5393c0-7a37-11ed-a600-d53ba4d2bb70 | 0: 1 | 2022-12-12T16:09:46.405Z | closed | 2022-12-28T23:05:23.814Z | 2022-12-12T16:09:57.756Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 7 | Activity Test Query | 2022-12-22T18:29:08.846Z | false | 9326b8f0-8226-11ed-a600-d53ba4d2bb70 | 0: 1<br/>2254: 6 | 2022-12-23T22:34:34.191Z | closed | 2022-12-27T20:39:23.918Z | 2022-12-22T18:29:30.751Z | 4 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 6d178850-7d5e-11ed-a600-d53ba4d2bb70 | 0: 1<br/>2254: 1 | 2022-12-16T19:20:59.642Z | closed | 2022-12-21T16:23:38.937Z | 2022-12-16T16:26:42.901Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 86515610-7d4b-11ed-a600-d53ba4d2bb70 | 0: 2 | 2022-10-20T14:37:02.228Z | closed | 2022-12-16T14:13:21.021Z | 2022-12-16T14:11:24.785Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 18 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 2082d5a0-7960-11ed-89c2-6136df938368 | 0: 17<br/>3938: 1 | 2022-12-12T19:29:12.308Z | closed | 2022-12-16T14:09:27.416Z | 2022-12-11T14:28:48.762Z | 3 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 4657b300-795f-11ed-89c2-6136df938368 | 0: 1 | 2022-10-20T14:37:02.228Z | closed | 2022-12-11T14:23:29.691Z | 2022-12-11T14:22:42.736Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 12 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | b62ddba0-78f6-11ed-89c2-6136df938368 | 0: 12 | 2022-10-20T14:37:02.228Z | closed | 2022-12-11T14:20:58.708Z | 2022-12-11T01:54:13.210Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | cdb76f10-78e8-11ed-89c2-6136df938368 | 0: 3 | 2022-10-20T14:37:02.228Z | closed | 2022-12-11T00:23:20.854Z | 2022-12-11T00:14:39.745Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | b20661c0-78e5-11ed-89c2-6136df938368 | 0: 1 | 2022-10-20T14:37:02.228Z | closed | 2022-12-11T00:13:46.832Z | 2022-12-10T23:52:24.796Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | fd6ba400-78e4-11ed-89c2-6136df938368 | 0: 1 | 2022-10-20T14:37:02.228Z | closed | 2022-12-10T23:50:17.331Z | 2022-12-10T23:47:21.792Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | fdba55b0-78e3-11ed-89c2-6136df938368 | 0: 2 | 2022-10-20T14:37:02.228Z | closed | 2022-12-10T23:45:42.579Z | 2022-12-10T23:40:12.811Z | 1 | false |
>| cnt.statistic.date | cnt.statistic.date | Malware,<br/>Mining | 4 | Malicious domain | 2022-12-08T14:14:05Z | false | 55131840-77c9-11ed-89c2-6136df938368 | 2148: 1<br/>0: 3 | 2022-12-09T22:35:48.305Z | closed | 2022-12-10T23:29:17.060Z | 2022-12-09T13:56:51.780Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 1 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 6ea05420-78dd-11ed-89c2-6136df938368 | 0: 1 | 2022-10-20T14:37:02.228Z | closed | 2022-12-10T23:29:16.415Z | 2022-12-10T22:53:15.746Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 19 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | b49fdaf0-782d-11ed-89c2-6136df938368 | 0: 19 | 2022-10-20T14:37:02.228Z | closed | 2022-12-10T22:18:40.298Z | 2022-12-10T01:55:21.759Z | 3 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | f7153610-782c-11ed-89c2-6136df938368 | 0: 2 | 2022-10-20T14:37:02.228Z | closed | 2022-12-10T01:54:57.549Z | 2022-12-10T01:50:03.761Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | a8666390-782c-11ed-89c2-6136df938368 | 0: 2 | 2022-10-20T14:37:02.228Z | closed | 2022-12-10T01:49:38.902Z | 2022-12-10T01:47:51.753Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | faf4afa0-782b-11ed-89c2-6136df938368 | 0: 2 | 2022-10-20T14:37:02.228Z | closed | 2022-12-10T01:46:24.981Z | 2022-12-10T01:43:00.762Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 18 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | 9d9d4710-7815-11ed-89c2-6136df938368 | 0: 18 | 2022-10-20T14:37:02.228Z | closed | 2022-12-10T01:42:33.470Z | 2022-12-09T23:02:55.233Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 4 | Activity Test Query | 2022-10-20T14:37:02.228Z | false | a003ee30-7812-11ed-89c2-6136df938368 | 0: 4 | 2022-10-20T14:37:02.228Z | closed | 2022-12-09T23:01:39.625Z | 2022-12-09T22:41:30.771Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 46 | Activity Test Query | 2022-12-09T17:58:14.664Z | false | 1ab96150-77eb-11ed-89c2-6136df938368 | 0: 46 | 2022-12-09T22:35:38.305Z | closed | 2022-12-09T22:40:19.890Z | 2022-12-09T17:58:36.773Z | 2 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-09T17:53:25.070Z | false | 6d490cf0-77ea-11ed-89c2-6136df938368 | 0: 2 | 2022-12-09T17:53:30.786Z | closed | 2022-12-09T17:55:55.295Z | 2022-12-09T17:53:45.791Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 13 | Activity Test Query | 2022-12-07T20:47:07.573Z | false | 5c75c470-7670-11ed-89c2-6136df938368 | 0: 2<br/>2254: 1<br/>989: 10 | 2022-12-09T17:14:35.344Z | closed | 2022-12-09T17:52:49.935Z | 2022-12-07T20:47:27.799Z | 3 | false |


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
| lumu_incident_id | Lumu incident id requested. | Required | 
| page | page requested . | Optional | 
| items | items requested . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.RetrieveEndpointsByIncident.items.label | Number | Lumu label | 
| Lumu.RetrieveEndpointsByIncident.items.endpoint | String | Lumu endpoint | 
| Lumu.RetrieveEndpointsByIncident.items.total | Number | Lumu total | 
| Lumu.RetrieveEndpointsByIncident.items.first | Date | Lumu first | 
| Lumu.RetrieveEndpointsByIncident.items.last | Date | Lumu last | 
| Lumu.RetrieveEndpointsByIncident.paginationInfo.page | Number | current page  | 
| Lumu.RetrieveEndpointsByIncident.paginationInfo.items | Number | current items  | 

#### Command example
```!lumu-retrieve-endpoints-by-incident lumu_incident_id=9e9238e0-a73d-11ed-9fd0-e5fb50c818f6```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveEndpointsByIncident": {
            "items": [
                {
                    "endpoint": "Loacal-nesfapdm",
                    "first": "2022-12-20T14:37:02.228Z",
                    "label": 0,
                    "last": "2022-12-20T14:37:02.228Z",
                    "lastSourceId": "6d942a7a-d287-415e-9c09-3d6632a6a976",
                    "lastSourceType": "custom_collector",
                    "total": 2
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

>### Incident endpoints
>|Endpoint|First|Label|Last|Last Source Id|Last Source Type|Total|
>|---|---|---|---|---|---|---|
>| Loacal-nesfapdm | 2022-12-20T14:37:02.228Z | 0 | 2022-12-20T14:37:02.228Z | 6d942a7a-d287-415e-9c09-3d6632a6a976 | custom_collector | 2 |


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
| lumu_incident_id | Lumu incident id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.MarkIncidentAsRead.statusCode | unknown | Lumu statusCode | 

#### Command example
```!lumu-mark-incident-as-read lumu_incident_id=9e9238e0-a73d-11ed-9fd0-e5fb50c818f6 ```
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

>Marked as read the incident successfully.

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
| lumu_incident_id | Lumu incident id requested. | Required | 
| comment | Lumu comment requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.MuteIncident.statusCode | unknown | Lumu statusCode | 

#### Command example
```!lumu-mute-incident lumu_incident_id=9e9238e0-a73d-11ed-9fd0-e5fb50c818f6 comment="mute from cortex"```
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

>Muted the incident successfully.

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
| lumu_incident_id | Lumu incident id requested. | Required | 
| comment | Lumu comment requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.UnmuteIncident.statusCode | unknown | Lumu statusCode | 

#### Command example
```!lumu-unmute-incident lumu_incident_id=9e9238e0-a73d-11ed-9fd0-e5fb50c818f6 comment="unmute from cortex"```
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

>Unmute the incident successfully.

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
| offset | Lumu offset requested. | Optional | 
| items | items requested . | Optional | 
| time | time requested . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.companyId | String | Lumu companyId | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.id | String | Lumu incident id | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.timestamp | Date | Lumu timestamp | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.statusTimestamp | Date | Lumu statusTimestamp | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.status | String | Lumu status | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.contacts | Number | Lumu contacts | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.adversaries | String | Lumu adversaries | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.adversaryId | String | Lumu adversaryId | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.adversaryTypes | String | Lumu adversaryTypes | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.description | String | Lumu description | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.labelDistribution | Number | Lumu labelDistribution | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.lastContact | Date | Lumu lastContact | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.unread | Boolean | Lumu unread | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.hasPlaybackContacts | Boolean | Lumu hasPlaybackContacts | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.incident.firstContact | Date | Lumu firstContact | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentClosed.comment | String | Lumu comment | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.companyId | String | Lumu companyId | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.openIncidents | Number | Lumu openIncidents | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.totalContacts | Number | Lumu totalContacts | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.DGA | Number | Lumu DGA | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.C2C | Number | Lumu C2C | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Network Scan | Number | Lumu Network Scan | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Mining | Number | Lumu Mining | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Phishing | Number | Lumu Phishing | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Spam | Number | Lumu Spam | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.typeDistribution.Malware | Number | Lumu Malware | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.OpenIncidentsStatusUpdated.openIncidentsStatus.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.companyId | String | Lumu companyId | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.id | String | Lumu id | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.timestamp | Date | Lumu timestamp | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.statusTimestamp | Date | Lumu statusTimestamp | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.status | String | Lumu status | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.contacts | Number | Lumu contacts | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.adversaries | String | Lumu adversaries | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.adversaryId | String | Lumu adversaryId | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.adversaryTypes | String | Lumu adversaryTypes | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.description | String | Lumu description | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.labelDistribution | Number | Lumu labelDistribution | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.lastContact | Date | Lumu lastContact | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.unread | Boolean | Lumu unread | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.hasPlaybackContacts | Boolean | Lumu hasPlaybackContacts | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.incident.firstContact | Date | Lumu firstContact | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.IncidentUnmuted.comment | String | Lumu comment | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.companyId | String | Lumu companyId | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.id | String | Lumu id | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.timestamp | Date | Lumu timestamp | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.statusTimestamp | Date | Lumu statusTimestamp | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.status | String | Lumu status | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.contacts | Number | Lumu contacts | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.adversaries | String | Lumu adversaries | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.adversaryId | String | Lumu adversaryId | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.adversaryTypes | String | Lumu adversaryTypes | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.description | String | Lumu description | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.labelDistribution | Number | Lumu labelDistribution | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.lastContact | Date | Lumu lastContact | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.unread | Boolean | Lumu unread | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.hasPlaybackContacts | Boolean | Lumu hasPlaybackContacts | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.incident.firstContact | Date | Lumu firstContact | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.openIncidents | Number | Lumu openIncidents | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.totalContacts | Number | Lumu totalContacts | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.DGA | Number | Lumu DGA | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.C2C | Number | Lumu C2C | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Network Scan | Number | Lumu Network Scan | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Mining | Number | Lumu Mining | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Phishing | Number | Lumu Phishing | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Spam | Number | Lumu Spam | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.typeDistribution.Malware | Number | Lumu Malware | 
| Lumu.ConsultIncidentsUpdatesThroughRest.updates.NewIncidentCreated.openIncidentsStats.totalEndpoints | Number | Lumu totalEndpoints | 
| Lumu.ConsultIncidentsUpdatesThroughRest.offset | Number | Lumu next offset | 

#### Command example
```!lumu-consult-incidents-updates-through-rest items=4 offset=1096305 time=4```
#### Context Example
```json
{
    "Lumu": {
        "ConsultIncidentsUpdatesThroughRest": {
            "offset": 1096566,
            "updates": [
                {
                    "IncidentUpdated": {
                        "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                        "contactSummary": {
                            "adversaryHost": "activity.lumu.io",
                            "endpointIp": "192.168.0.13",
                            "endpointName": "Loacal-nesfpdm",
                            "fromPlayback": false,
                            "timestamp": "2022-12-20T14:37:02.228Z",
                            "uuid": "c45b8540-8073-11ed-b5ad-23f20297b7bb"
                        },
                        "incident": {
                            "adversaries": [
                                "activity.lumu.io"
                            ],
                            "adversaryId": "activity.lumu.io",
                            "adversaryTypes": [
                                "Spam"
                            ],
                            "contacts": 15,
                            "description": "Activity Test Query",
                            "firstContact": "2023-02-01T15:13:41.904Z",
                            "hasPlaybackContacts": false,
                            "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                            "labelDistribution": {
                                "0": 2,
                                "1792": 1,
                                "989": 12
                            },
                            "lastContact": "2023-02-03T16:44:00.395Z",
                            "status": "open",
                            "statusTimestamp": "2023-02-01T15:14:17.061Z",
                            "timestamp": "2023-02-01T15:14:17.061Z",
                            "totalEndpoints": 5,
                            "unread": false
                        },
                        "openIncidentsStats": {
                            "labelDistribution": {
                                "0": 35,
                                "1179": 2,
                                "147": 27,
                                "1580": 147,
                                "1651": 14,
                                "1791": 81,
                                "1792": 2,
                                "1885": 3,
                                "2144": 29,
                                "2148": 247,
                                "218": 4,
                                "2254": 89,
                                "2267": 11,
                                "2280": 28,
                                "2692": 1,
                                "2821": 1,
                                "2974": 20,
                                "3005": 1,
                                "3077": 30,
                                "3179": 1,
                                "3182": 4,
                                "3628": 1,
                                "3635": 2,
                                "3771": 1,
                                "3774": 1,
                                "3811": 7,
                                "4055": 134,
                                "4061": 10,
                                "4232": 2,
                                "4301": 393,
                                "548": 25,
                                "805": 9,
                                "864": 3,
                                "989": 72
                            },
                            "openIncidents": 1124,
                            "totalContacts": 10311,
                            "totalEndpoints": 209,
                            "typeDistribution": {
                                "C2C": 106,
                                "DGA": 10,
                                "Inappropriate content": 1,
                                "Malware": 666,
                                "Mining": 274,
                                "Network Scan": 6,
                                "Phishing": 31,
                                "Spam": 265
                            }
                        }
                    }
                },
                {
                    "IncidentUpdated": {
                        "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                        "contactSummary": {
                            "adversaryHost": "activity.lumu.io",
                            "endpointIp": "192.168.0.13",
                            "endpointName": "Loacal-nesfpdm",
                            "fromPlayback": false,
                            "timestamp": "2022-12-20T14:37:02.228Z",
                            "uuid": "c45b8540-8073-11ed-ab18-23f2022bdf77"
                        },
                        "incident": {
                            "adversaries": [
                                "activity.lumu.io"
                            ],
                            "adversaryId": "activity.lumu.io",
                            "adversaryTypes": [
                                "Spam"
                            ],
                            "contacts": 16,
                            "description": "Activity Test Query",
                            "firstContact": "2023-02-01T15:13:41.904Z",
                            "hasPlaybackContacts": false,
                            "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                            "labelDistribution": {
                                "0": 3,
                                "1792": 1,
                                "989": 12
                            },
                            "lastContact": "2023-02-03T16:44:00.395Z",
                            "status": "open",
                            "statusTimestamp": "2023-02-01T15:14:17.061Z",
                            "timestamp": "2023-02-01T15:14:17.061Z",
                            "totalEndpoints": 5,
                            "unread": false
                        },
                        "openIncidentsStats": {
                            "labelDistribution": {
                                "0": 35,
                                "1179": 2,
                                "147": 27,
                                "1580": 147,
                                "1651": 14,
                                "1791": 81,
                                "1792": 2,
                                "1885": 3,
                                "2144": 29,
                                "2148": 247,
                                "218": 4,
                                "2254": 89,
                                "2267": 11,
                                "2280": 28,
                                "2692": 1,
                                "2821": 1,
                                "2974": 20,
                                "3005": 1,
                                "3077": 30,
                                "3179": 1,
                                "3182": 4,
                                "3628": 1,
                                "3635": 2,
                                "3771": 1,
                                "3774": 1,
                                "3811": 7,
                                "4055": 134,
                                "4061": 10,
                                "4232": 2,
                                "4301": 393,
                                "548": 25,
                                "805": 9,
                                "864": 3,
                                "989": 72
                            },
                            "openIncidents": 1124,
                            "totalContacts": 10312,
                            "totalEndpoints": 209,
                            "typeDistribution": {
                                "C2C": 106,
                                "DGA": 10,
                                "Inappropriate content": 1,
                                "Malware": 666,
                                "Mining": 274,
                                "Network Scan": 6,
                                "Phishing": 31,
                                "Spam": 265
                            }
                        }
                    }
                },
                {
                    "IncidentUpdated": {
                        "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                        "contactSummary": {
                            "adversaryHost": "activity.lumu.io",
                            "endpointIp": "192.168.0.13",
                            "endpointName": "Loacal-nesfpdm",
                            "fromPlayback": false,
                            "timestamp": "2022-12-20T14:37:02.228Z",
                            "uuid": "c45b8540-8073-11ed-a675-23f2020a8d4c"
                        },
                        "incident": {
                            "adversaries": [
                                "activity.lumu.io"
                            ],
                            "adversaryId": "activity.lumu.io",
                            "adversaryTypes": [
                                "Spam"
                            ],
                            "contacts": 17,
                            "description": "Activity Test Query",
                            "firstContact": "2023-02-01T15:13:41.904Z",
                            "hasPlaybackContacts": false,
                            "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                            "labelDistribution": {
                                "0": 4,
                                "1792": 1,
                                "989": 12
                            },
                            "lastContact": "2023-02-03T16:44:00.395Z",
                            "status": "open",
                            "statusTimestamp": "2023-02-01T15:14:17.061Z",
                            "timestamp": "2023-02-01T15:14:17.061Z",
                            "totalEndpoints": 5,
                            "unread": false
                        },
                        "openIncidentsStats": {
                            "labelDistribution": {
                                "0": 35,
                                "1179": 2,
                                "147": 27,
                                "1580": 147,
                                "1651": 14,
                                "1791": 81,
                                "1792": 2,
                                "1885": 3,
                                "2144": 29,
                                "2148": 247,
                                "218": 4,
                                "2254": 89,
                                "2267": 11,
                                "2280": 28,
                                "2692": 1,
                                "2821": 1,
                                "2974": 20,
                                "3005": 1,
                                "3077": 30,
                                "3179": 1,
                                "3182": 4,
                                "3628": 1,
                                "3635": 2,
                                "3771": 1,
                                "3774": 1,
                                "3811": 7,
                                "4055": 134,
                                "4061": 10,
                                "4232": 2,
                                "4301": 393,
                                "548": 25,
                                "805": 9,
                                "864": 3,
                                "989": 72
                            },
                            "openIncidents": 1124,
                            "totalContacts": 10313,
                            "totalEndpoints": 209,
                            "typeDistribution": {
                                "C2C": 106,
                                "DGA": 10,
                                "Inappropriate content": 1,
                                "Malware": 666,
                                "Mining": 274,
                                "Network Scan": 6,
                                "Phishing": 31,
                                "Spam": 265
                            }
                        }
                    }
                },
                {
                    "IncidentUpdated": {
                        "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                        "contactSummary": {
                            "adversaryHost": "activity.lumu.io",
                            "endpointIp": "192.168.0.13",
                            "endpointName": "Loacal-nesfpdm",
                            "fromPlayback": false,
                            "timestamp": "2022-12-20T14:37:02.228Z",
                            "uuid": "c45b8540-8073-11ed-ba29-23f202e1cb1a"
                        },
                        "incident": {
                            "adversaries": [
                                "activity.lumu.io"
                            ],
                            "adversaryId": "activity.lumu.io",
                            "adversaryTypes": [
                                "Spam"
                            ],
                            "contacts": 18,
                            "description": "Activity Test Query",
                            "firstContact": "2023-02-01T15:13:41.904Z",
                            "hasPlaybackContacts": false,
                            "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                            "labelDistribution": {
                                "0": 5,
                                "1792": 1,
                                "989": 12
                            },
                            "lastContact": "2023-02-03T16:44:00.395Z",
                            "status": "open",
                            "statusTimestamp": "2023-02-01T15:14:17.061Z",
                            "timestamp": "2023-02-01T15:14:17.061Z",
                            "totalEndpoints": 5,
                            "unread": false
                        },
                        "openIncidentsStats": {
                            "labelDistribution": {
                                "0": 35,
                                "1179": 2,
                                "147": 27,
                                "1580": 147,
                                "1651": 14,
                                "1791": 81,
                                "1792": 2,
                                "1885": 3,
                                "2144": 29,
                                "2148": 247,
                                "218": 4,
                                "2254": 89,
                                "2267": 11,
                                "2280": 28,
                                "2692": 1,
                                "2821": 1,
                                "2974": 20,
                                "3005": 1,
                                "3077": 30,
                                "3179": 1,
                                "3182": 4,
                                "3628": 1,
                                "3635": 2,
                                "3771": 1,
                                "3774": 1,
                                "3811": 7,
                                "4055": 134,
                                "4061": 10,
                                "4232": 2,
                                "4301": 393,
                                "548": 25,
                                "805": 9,
                                "864": 3,
                                "989": 72
                            },
                            "openIncidents": 1124,
                            "totalContacts": 10314,
                            "totalEndpoints": 209,
                            "typeDistribution": {
                                "C2C": 106,
                                "DGA": 10,
                                "Inappropriate content": 1,
                                "Malware": 666,
                                "Mining": 274,
                                "Network Scan": 6,
                                "Phishing": 31,
                                "Spam": 265
                            }
                        }
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|offset|updates|
>|---|---|
>| 1096566 | {'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 15, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 2}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10311, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-b5ad-23f20297b7bb', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 16, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 3}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10312, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-ab18-23f2022bdf77', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 17, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 4}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10313, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-a675-23f2020a8d4c', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 18, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 5}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10314, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-ba29-23f202e1cb1a', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}} |


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
| lumu_incident_id | Lumu incident id. | Required | 
| comment | Lumu comment requested. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.CloseIncident.statusCode | unknown | Lumu statusCode | 

#### Command example
```!lumu-close-incident lumu_incident_id=9e9238e0-a73d-11ed-9fd0-e5fb50c818f6 comment="closed from Cortex"```
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

>Closed the incident successfully.

### get-modified-remote-data
***
mirror process 


#### Base Command

`get-modified-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | lastUpdate . | Optional | 


#### Context Output

There is no context output for this command.
### get-remote-data
***
mirror process 


#### Base Command

`get-remote-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | lastUpdate . | Required | 
| id | id . | Required | 


#### Context Output

There is no context output for this command.
### get-mapping-fields
***
mirror process 


#### Base Command

`get-mapping-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### lumu-clear-cache
***
Lumu clear cache, only trigger if it mandatory 


#### Base Command

`lumu-clear-cache`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.ClearCache | string | Lumu clear cache | 

#### Command example
```!lumu-clear-cache```
#### Context Example
```json
{
    "Lumu": {
        "ClearCache": "cache cleared get_integration_context()={'cache': [], 'lumu_incidentsId': []}"
    }
}
```

#### Human Readable Output

>cache cleared get_integration_context()={'cache': [], 'lumu_incidentsId': []}

### update-remote-system
***
mirror process 


#### Base Command

`update-remote-system`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | data . | Required | 
| entries | entries . | Optional | 
| incident_changed | incident_changed . | Optional | 
| remote_incident_id | remote_incident_id . | Optional | 


#### Context Output

There is no context output for this command.
### lumu-get-cache
***
Lumu get cache


#### Base Command

`lumu-get-cache`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lumu.GetCache.cache | string | Lumu cache | 
| Lumu.GetCache.lumu_incidentsId | string | Lumu incident ids processed | 

#### Command example
```!lumu-get-cache```
#### Context Example
```json
{
    "Lumu": {
        "GetCache": {
            "cache": [],
            "lumu_incidentsId": [
                "460dd2d0-a740-11ed-9fd0-e5fb50c818f6"
            ]
        }
    }
}
```

#### Human Readable Output

>### Cache
>|Lumu _ Incidents Id|
>|---|
>| 460dd2d0-a740-11ed-9fd0-e5fb50c818f6 |


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
