SecOps operations - Reflect and manage the Lumu Incidents either from XSOAR Cortex or viceversa using the mirroring integration flow, https://lumu.io/
This integration was integrated and tested with version 20230215 of Lumu

## Configure Lumu in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Maximum number of incidents to fetch every time |  | False |
| First fetch time interval | The time range to consider for the initial data fetch. \(&amp;lt;number&amp;gt; &amp;lt;unit&amp;gt;, e.g., 2 minutes, 2 hours, 2 days, 2 months, 2 years\). Default is 3 days. | False |
| Server URL |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| API Key |  | True |
| Incident Offset |  | False |
| Total Incident per fetching using lumu endpoint |  | False |
| Max time in seconds per fetching using lumu endpoint |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Incidents Fetch Interval |  | False |
| Incident Mirroring Direction | Selects which direction you want the incidents mirrored. You can mirror \*\*Incoming\*\* only \(from Lumu to Cortex XSOAR\), \*\*Outgoing\*\* only \(from Cortex XSOAR to Lumu\), or both \*\*Incoming And Outgoing\*\*. | False |
| Mirror tags | Comment and files that will be marked with this tag will be pushed into Lumu. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| limit | items limit requested. Default is 10. | Optional | 


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
                }
            ],
            "paginationInfo": {
                "items": 10,
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
>
>### paginationInfo
>|Items|Next|Page|
>|---|---|---|
>| 10 | 2 | 1 |


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
| limit | items limit requested. Default is 10. | Optional | 
| fromdate | from date in ISO string format <br/> e.g. 2023 january 1st, 14:40:14 - 2023-01-01T14:40:14.000Z <br/> e.g. 2023 july 4th, 05:10 - 2023-07-04T05:10:00.000Z. | Optional | 
| todate | from date in ISO string format <br/> e.g. 2023 january 1st, 14:40:14 - 2023-01-01T14:40:14.000Z <br/> e.g. 2023 july 4th, 05:10 - 2023-07-04T05:10:00.000Z. | Optional | 
| status | choose status: open,muted,closed. Possible values are: open, muted, closed. | Optional | 
| adversary_types | choose types: C2C,Malware,DGA,Mining,Spam,Phishing. Possible values are: C2C, Malware, DGA, Mining, Spam, Phishing. | Optional | 
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
        "RetrieveIncidents": [
            {
                "adversaries": [
                    "www.chg.com.br"
                ],
                "adversaryId": "www.chg.com.br",
                "adversaryTypes": [
                    "Malware"
                ],
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-15T13:28:25.537Z",
                "hasPlaybackContacts": false,
                "id": "ad2b63c0-ad34-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-15T13:28:25.537Z",
                "status": "closed",
                "statusTimestamp": "2023-02-15T21:53:41.468Z",
                "timestamp": "2023-02-15T13:28:47.356Z",
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
                "firstContact": "2023-02-15T02:21:59Z",
                "hasPlaybackContacts": false,
                "id": "8c5efc90-aca5-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "2144": 10
                },
                "lastContact": "2023-02-15T05:35:40Z",
                "status": "open",
                "statusTimestamp": "2023-02-14T20:24:14.297Z",
                "timestamp": "2023-02-14T20:24:14.297Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "161.97.110.203"
                ],
                "adversaryId": "161.97.110.203",
                "adversaryTypes": [
                    "C2C"
                ],
                "contacts": 1,
                "description": "Malware family Katana",
                "firstContact": "2023-02-15T02:18:17Z",
                "hasPlaybackContacts": false,
                "id": "853e3020-aca5-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "2144": 1
                },
                "lastContact": "2023-02-15T02:18:17Z",
                "status": "open",
                "statusTimestamp": "2023-02-14T20:24:02.338Z",
                "timestamp": "2023-02-14T20:24:02.338Z",
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
                "firstContact": "2023-02-14T17:27:26.791Z",
                "hasPlaybackContacts": false,
                "id": "e0b39da0-ac8c-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "989": 1
                },
                "lastContact": "2023-02-14T17:27:26.791Z",
                "status": "closed",
                "statusTimestamp": "2023-02-14T18:33:38.315Z",
                "timestamp": "2023-02-14T17:27:38.362Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "www.puertoballesta.com"
                ],
                "adversaryId": "www.puertoballesta.com",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 1,
                "description": "Phishing domain",
                "firstContact": "2023-02-14T17:08:11.751Z",
                "hasPlaybackContacts": false,
                "id": "91aaaf20-ac8a-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "989": 1
                },
                "lastContact": "2023-02-14T17:08:11.751Z",
                "status": "open",
                "statusTimestamp": "2023-02-14T17:24:41.268Z",
                "timestamp": "2023-02-14T17:11:06.770Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "bitmovil.mx"
                ],
                "adversaryId": "bitmovil.mx",
                "adversaryTypes": [
                    "Malware"
                ],
                "contacts": 2,
                "description": "Heodo",
                "firstContact": "2023-02-14T17:05:37.987Z",
                "hasPlaybackContacts": false,
                "id": "0d207a50-ac8a-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "989": 2
                },
                "lastContact": "2023-02-14T17:05:37.987Z",
                "status": "closed",
                "statusTimestamp": "2023-02-14T18:44:09.946Z",
                "timestamp": "2023-02-14T17:07:24.405Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "msk.turbolider.ru"
                ],
                "adversaryId": "msk.turbolider.ru",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 2,
                "description": "Phishing domain",
                "firstContact": "2023-02-14T16:28:11.169Z",
                "hasPlaybackContacts": false,
                "id": "99b7bf10-ac84-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "147": 2
                },
                "lastContact": "2023-02-14T16:28:11.169Z",
                "status": "open",
                "statusTimestamp": "2023-02-14T16:28:23.297Z",
                "timestamp": "2023-02-14T16:28:23.297Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "rspg-spectrum.eu"
                ],
                "adversaryId": "rspg-spectrum.eu",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 7,
                "description": "Phishing domain",
                "firstContact": "2023-01-13T18:15:24.305Z",
                "hasPlaybackContacts": true,
                "id": "903c5580-abef-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "2041": 5,
                    "4055": 2
                },
                "lastContact": "2023-02-14T16:01:27.715Z",
                "status": "open",
                "statusTimestamp": "2023-02-13T22:41:32.376Z",
                "timestamp": "2023-02-13T22:41:32.376Z",
                "totalEndpoints": 3,
                "unread": false
            },
            {
                "adversaries": [
                    "scalarchives.com"
                ],
                "adversaryId": "scalarchives.com",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 4,
                "description": "Phishing domain",
                "firstContact": "2023-01-13T21:44:39.025Z",
                "hasPlaybackContacts": true,
                "id": "f2571f00-aa43-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "4055": 4
                },
                "lastContact": "2023-01-13T21:44:39.035Z",
                "status": "open",
                "statusTimestamp": "2023-02-11T19:40:32.368Z",
                "timestamp": "2023-02-11T19:40:32.368Z",
                "totalEndpoints": 2,
                "unread": false
            },
            {
                "adversaries": [
                    "portaconexao8.top"
                ],
                "adversaryId": "portaconexao8.top",
                "adversaryTypes": [
                    "Malware"
                ],
                "contacts": 2,
                "description": "Malware hash: 55e57c52cd5e1dcfad4e9bcf0eb2f3a5",
                "firstContact": "2023-02-11T18:40:09.087Z",
                "hasPlaybackContacts": false,
                "id": "89658e80-aa3b-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "147": 2
                },
                "lastContact": "2023-02-11T18:40:09.087Z",
                "status": "closed",
                "statusTimestamp": "2023-02-15T13:26:02.357Z",
                "timestamp": "2023-02-11T18:40:20.328Z",
                "totalEndpoints": 1,
                "unread": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-15T13:28:25.537Z | false | ad2b63c0-ad34-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-15T13:28:25.537Z | closed | 2023-02-15T21:53:41.468Z | 2023-02-15T13:28:47.356Z | 1 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 10 | Malware family Agentemis | 2023-02-15T02:21:59Z | false | 8c5efc90-aca5-11ed-9fd0-e5fb50c818f6 | 2144: 10 | 2023-02-15T05:35:40Z | open | 2023-02-14T20:24:14.297Z | 2023-02-14T20:24:14.297Z | 1 | false |
>| 161.97.110.203 | 161.97.110.203 | C2C | 1 | Malware family Katana | 2023-02-15T02:18:17Z | false | 853e3020-aca5-11ed-9fd0-e5fb50c818f6 | 2144: 1 | 2023-02-15T02:18:17Z | open | 2023-02-14T20:24:02.338Z | 2023-02-14T20:24:02.338Z | 1 | false |
>| rea.co.ke | rea.co.ke | C2C,<br/>Malware | 1 | Malware family P2PZeuS | 2023-02-14T17:27:26.791Z | false | e0b39da0-ac8c-11ed-9fd0-e5fb50c818f6 | 989: 1 | 2023-02-14T17:27:26.791Z | closed | 2023-02-14T18:33:38.315Z | 2023-02-14T17:27:38.362Z | 1 | false |
>| www.puertoballesta.com | www.puertoballesta.com | Phishing | 1 | Phishing domain | 2023-02-14T17:08:11.751Z | false | 91aaaf20-ac8a-11ed-9fd0-e5fb50c818f6 | 989: 1 | 2023-02-14T17:08:11.751Z | open | 2023-02-14T17:24:41.268Z | 2023-02-14T17:11:06.770Z | 1 | false |
>| bitmovil.mx | bitmovil.mx | Malware | 2 | Heodo | 2023-02-14T17:05:37.987Z | false | 0d207a50-ac8a-11ed-9fd0-e5fb50c818f6 | 989: 2 | 2023-02-14T17:05:37.987Z | closed | 2023-02-14T18:44:09.946Z | 2023-02-14T17:07:24.405Z | 1 | false |
>| msk.turbolider.ru | msk.turbolider.ru | Phishing | 2 | Phishing domain | 2023-02-14T16:28:11.169Z | false | 99b7bf10-ac84-11ed-9fd0-e5fb50c818f6 | 147: 2 | 2023-02-14T16:28:11.169Z | open | 2023-02-14T16:28:23.297Z | 2023-02-14T16:28:23.297Z | 1 | false |
>| rspg-spectrum.eu | rspg-spectrum.eu | Phishing | 7 | Phishing domain | 2023-01-13T18:15:24.305Z | true | 903c5580-abef-11ed-9fd0-e5fb50c818f6 | 4055: 2<br/>2041: 5 | 2023-02-14T16:01:27.715Z | open | 2023-02-13T22:41:32.376Z | 2023-02-13T22:41:32.376Z | 3 | false |
>| scalarchives.com | scalarchives.com | Phishing | 4 | Phishing domain | 2023-01-13T21:44:39.025Z | true | f2571f00-aa43-11ed-9fd0-e5fb50c818f6 | 4055: 4 | 2023-01-13T21:44:39.035Z | open | 2023-02-11T19:40:32.368Z | 2023-02-11T19:40:32.368Z | 2 | false |
>| portaconexao8.top | portaconexao8.top | Malware | 2 | Malware hash: 55e57c52cd5e1dcfad4e9bcf0eb2f3a5 | 2023-02-11T18:40:09.087Z | false | 89658e80-aa3b-11ed-9fd0-e5fb50c818f6 | 147: 2 | 2023-02-11T18:40:09.087Z | closed | 2023-02-15T13:26:02.357Z | 2023-02-11T18:40:20.328Z | 1 | false |
>
>### paginationInfo
>|Items|Next|Page|
>|---|---|---|
>| 10 | 2 | 1 |


#### Command example
```!lumu-retrieve-incidents page=2 status=open adversary-types=Malware labels=1580```
#### Human Readable Output

>### Incidents
>**No entries.**
>
>### paginationInfo
>|Items|Page|Prev|
>|---|---|---|
>| 10 | 2 | 1 |


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
```!lumu-retrieve-a-specific-incident-details lumu_incident_id=7c40be00-a7cf-11ed-9fd0-e5fb50c818f6```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveASpecificIncidentDetails": {
            "actions": [
                {
                    "action": "comment",
                    "comment": "test comment",
                    "datetime": "2023-02-15T12:18:53.523Z",
                    "userId": 6252
                },
                {
                    "action": "comment",
                    "comment": "from XSOAR Cortex 20230215_121052 jusa a comment 710, hmacsha256:4a72fe5ec25900e165988e155a1f629ceb2b3e0b92127b8b7df04ab8576b86e8",
                    "datetime": "2023-02-15T12:10:54.152Z",
                    "userId": 0
                },
                {
                    "action": "unmute",
                    "comment": "from XSOAR Cortex 20230215_120059 , hmacsha256:7e909a46d09f7e2fe9f81b8dbb4e56f39f1ed760744ff9b6ca0d17ca31c5a4c4",
                    "datetime": "2023-02-15T12:01:03.667Z",
                    "userId": 0
                },
                {
                    "action": "mute",
                    "comment": "from XSOAR Cortex 20230209_165814 at 1158, hmacsha256:ad2f2ce9951184230647f2feed5856d41fa75500ded13aed5bf78176d825e40b",
                    "datetime": "2023-02-09T16:58:14.536Z",
                    "userId": 0
                }
            ],
            "adversaries": [
                "activity.lumu.io"
            ],
            "adversaryId": "activity.lumu.io",
            "adversaryTypes": [
                "Spam"
            ],
            "contacts": 8,
            "description": "Activity Test Query",
            "firstContactDetails": {
                "datetime": "2023-02-08T16:41:35.613Z",
                "details": [
                    "Activity Test Query"
                ],
                "endpointIp": "186.29.109.138",
                "endpointName": "cd-ho",
                "host": "activity.lumu.io",
                "isPlayback": false,
                "label": 147,
                "sourceData": null,
                "sourceId": "587ec9d348053ca03a58aeddeccb1b93",
                "sourceType": "PublicResolver",
                "types": [
                    "Spam"
                ],
                "uuid": "737f12d0-a7cf-11ed-972b-0f9b6b3c6ffd"
            },
            "hasPlaybackContacts": false,
            "id": "7c40be00-a7cf-11ed-9fd0-e5fb50c818f6",
            "isUnread": false,
            "labelDistribution": {
                "0": 2,
                "147": 1,
                "1885": 2,
                "2254": 1,
                "989": 2
            },
            "lastContact": "2023-02-15T16:59:47.142Z",
            "lastContactDetails": {
                "datetime": "2023-02-15T16:59:47.142Z",
                "details": [
                    "Activity Test Query"
                ],
                "endpointIp": "192.168.1.100",
                "endpointName": "LUMU-100",
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
                "uuid": "26fd6e60-ad52-11ed-8d57-0f9b6b8d54f0"
            },
            "status": "open",
            "statusTimestamp": "2023-02-15T12:01:03.667Z",
            "timestamp": "2023-02-08T16:41:50.304Z",
            "totalEndpoints": 6
        }
    }
}
```

#### Human Readable Output

>### Incident
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact Details|Has Playback Contacts|Id|Is Unread|Label Distribution|Last Contact|Last Contact Details|Status|Status Timestamp|Timestamp|Total Endpoints|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| activity.lumu.io | activity.lumu.io | Spam | 8 | Activity Test Query | uuid: 737f12d0-a7cf-11ed-972b-0f9b6b3c6ffd<br/>datetime: 2023-02-08T16:41:35.613Z<br/>host: activity.lumu.io<br/>types: Spam<br/>details: Activity Test Query<br/>endpointIp: 186.29.109.138<br/>endpointName: cd-ho<br/>label: 147<br/>sourceType: PublicResolver<br/>sourceId: 587ec9d348053ca03a58aeddeccb1b93<br/>sourceData: null<br/>isPlayback: false | false | 7c40be00-a7cf-11ed-9fd0-e5fb50c818f6 | false | 147: 1<br/>2254: 1<br/>1885: 2<br/>989: 2<br/>0: 2 | 2023-02-15T16:59:47.142Z | uuid: 26fd6e60-ad52-11ed-8d57-0f9b6b8d54f0<br/>datetime: 2023-02-15T16:59:47.142Z<br/>host: activity.lumu.io<br/>types: Spam<br/>details: Activity Test Query<br/>endpointIp: 192.168.1.100<br/>endpointName: LUMU-100<br/>label: 0<br/>sourceType: custom_collector<br/>sourceId: 6d942a7a-d287-415e-9c09-3d6632a6a976<br/>sourceData: {"DNSQueryExtraInfo": {"queryType": "A"}}<br/>isPlayback: false | open | 2023-02-15T12:01:03.667Z | 2023-02-08T16:41:50.304Z | 6 |
>
>### Actions
>|Action|Comment|Datetime|User Id|
>|---|---|---|---|
>| comment | test comment | 2023-02-15T12:18:53.523Z | 6252 |
>| comment | from XSOAR Cortex 20230215_121052 jusa a comment 710, hmacsha256:4a72fe5ec25900e165988e155a1f629ceb2b3e0b92127b8b7df04ab8576b86e8 | 2023-02-15T12:10:54.152Z | 0 |
>| unmute | from XSOAR Cortex 20230215_120059 , hmacsha256:7e909a46d09f7e2fe9f81b8dbb4e56f39f1ed760744ff9b6ca0d17ca31c5a4c4 | 2023-02-15T12:01:03.667Z | 0 |
>| mute | from XSOAR Cortex 20230209_165814 at 1158, hmacsha256:ad2f2ce9951184230647f2feed5856d41fa75500ded13aed5bf78176d825e40b | 2023-02-09T16:58:14.536Z | 0 |


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
                "https://blog.quosec.net/posts/grap_qakbot_navigation/",
                "https://unit42.paloaltonetworks.com/wireshark-tutorial-emotet-infection/",
                "https://malwareandstuff.com/an-old-enemy-diving-into-qbot-part-1/",
                "https://raw.githubusercontent.com/fboldewin/When-ransomware-hits-an-ATM-giant---The-Diebold-Nixdorf-case-dissected/main/When%20ransomware%20hits%20an%20ATM%20giant%20-%20The%20Diebold%20Nixdorf%20case%20dissected%20-%20Group-IB%20CyberCrimeCon2020.pdf",
                "https://malpedia.caad.fkie.fraunhofer.de/details/win.qakbot",
                "https://media.scmagazine.com/documents/225/bae_qbot_report_56053.pdf",
                "https://malwareandstuff.com/an-old-enemy-diving-into-qbot-part-3/",
                "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2020-CTI-010.pdf",
                "https://urlhaus.abuse.ch/host/jits.ac.in/",
                "https://elis531989.medium.com/funtastic-packers-and-where-to-find-them-41429a7ef9a7",
                "https://research.checkpoint.com/2020/exploring-qbots-latest-attack-methods/",
                "https://www.vkremez.com/2018/07/lets-learn-in-depth-reversing-of-qakbot.html",
                "https://twitter.com/redcanary/status/1334224861628039169",
                "https://web.archive.org/web/20201207094648/https://go.group-ib.com/rs/689-LRE-818/images/Group-IB_Egregor_Ransomware.pdf",
                "https://www.hornetsecurity.com/en/security-information/qakbot-malspam-leading-to-prolock/",
                "https://blog.morphisec.com/qakbot-qbot-maldoc-two-new-techniques",
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
                "Gafgyt",
                "Qakbot",
                "Quakbot",
                "Qbot",
                "lizkebab",
                "torlus",
                "PinkSlipBot",
                "Bashlite",
                "Akbot",
                "Pinkslipbot",
                "Qbot ",
                "gayfgt"
            ],
            "threat_triggers": [
                "https://jits.ac.in/TS.php"
            ],
            "timestamp": "2023-02-15T21:59:16.261Z"
        }
    }
}
```

#### Human Readable Output

>### Incident
>|Adversary _ Id|Currently _ Active|External _ Resources|Mitre|Playbooks|Threat _ Details|Threat _ Triggers|Timestamp|
>|---|---|---|---|---|---|---|---|
>| jits.ac.in | true | https:<span>//</span>blog.quosec.net/posts/grap_qakbot_navigation/,<br/>https:<span>//</span>unit42.paloaltonetworks.com/wireshark-tutorial-emotet-infection/,<br/>https:<span>//</span>malwareandstuff.com/an-old-enemy-diving-into-qbot-part-1/,<br/>https:<span>//</span>raw.githubusercontent.com/fboldewin/When-ransomware-hits-an-ATM-giant---The-Diebold-Nixdorf-case-dissected/main/When%20ransomware%20hits%20an%20ATM%20giant%20-%20The%20Diebold%20Nixdorf%20case%20dissected%20-%20Group-IB%20CyberCrimeCon2020.pdf,<br/>https:<span>//</span>malpedia.caad.fkie.fraunhofer.de/details/win.qakbot,<br/>https:<span>//</span>media.scmagazine.com/documents/225/bae_qbot_report_56053.pdf,<br/>https:<span>//</span>malwareandstuff.com/an-old-enemy-diving-into-qbot-part-3/,<br/>https:<span>//</span>www.cert.ssi.gouv.fr/uploads/CERTFR-2020-CTI-010.pdf,<br/>https:<span>//</span>urlhaus.abuse.ch/host/jits.ac.in/,<br/>https:<span>//</span>elis531989.medium.com/funtastic-packers-and-where-to-find-them-41429a7ef9a7,<br/>https:<span>//</span>research.checkpoint.com/2020/exploring-qbots-latest-attack-methods/,<br/>https:<span>//</span>www.vkremez.com/2018/07/lets-learn-in-depth-reversing-of-qakbot.html,<br/>https:<span>//</span>twitter.com/redcanary/status/1334224861628039169,<br/>https:<span>//</span>web.archive.org/web/20201207094648/https:<span>//</span>go.group-ib.com/rs/689-LRE-818/images/Group-IB_Egregor_Ransomware.pdf,<br/>https:<span>//</span>www.hornetsecurity.com/en/security-information/qakbot-malspam-leading-to-prolock/,<br/>https:<span>//</span>blog.morphisec.com/qakbot-qbot-maldoc-two-new-techniques,<br/>https:<span>//</span>www.virustotal.com/gui/domain/jits.ac.in/relations | details: {'tactic': 'command-and-control', 'techniques': ['T1071']}<br/>matrix: enterprise<br/>version: 8.2 | https:<span>//</span>docs.lumu.io/portal/en/kb/articles/malware-incident-response-playbook | qbot,<br/>Gafgyt,<br/>Qakbot,<br/>Quakbot,<br/>Qbot,<br/>lizkebab,<br/>torlus,<br/>PinkSlipBot,<br/>Bashlite,<br/>Akbot,<br/>Pinkslipbot,<br/>Qbot ,<br/>gayfgt | https:<span>//</span>jits.ac.in/TS.php | 2023-02-15T21:59:16.261Z |


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
```!lumu-comment-a-specific-incident comment="from cortex, palo alto" lumu_incident_id=7c40be00-a7cf-11ed-9fd0-e5fb50c818f6```
#### Context Example
```json
{
    "Lumu": {
        "CommentASpecificIncident": {
            "response": "",
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
| limit | item limit requested . Default is 10. | Optional | 
| adversary_types | choose types: C2C,Malware,DGA,Mining,Spam,Phishing. Possible values are: C2C, Malware, DGA, Mining, Spam, Phishing. | Optional | 
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
        "RetrieveOpenIncidents": [
            {
                "adversaries": [
                    "activity.lumu.io"
                ],
                "adversaryId": "activity.lumu.io",
                "adversaryTypes": [
                    "Spam"
                ],
                "contacts": 8,
                "description": "Activity Test Query",
                "firstContact": "2023-02-08T16:41:35.613Z",
                "hasPlaybackContacts": false,
                "id": "7c40be00-a7cf-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 2,
                    "147": 1,
                    "1885": 2,
                    "2254": 1,
                    "989": 2
                },
                "lastContact": "2023-02-15T16:59:47.142Z",
                "status": "open",
                "statusTimestamp": "2023-02-15T12:01:03.667Z",
                "timestamp": "2023-02-08T16:41:50.304Z",
                "totalEndpoints": 6,
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
                "firstContact": "2023-02-15T02:21:59Z",
                "hasPlaybackContacts": false,
                "id": "8c5efc90-aca5-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "2144": 10
                },
                "lastContact": "2023-02-15T05:35:40Z",
                "status": "open",
                "statusTimestamp": "2023-02-14T20:24:14.297Z",
                "timestamp": "2023-02-14T20:24:14.297Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "161.97.110.203"
                ],
                "adversaryId": "161.97.110.203",
                "adversaryTypes": [
                    "C2C"
                ],
                "contacts": 1,
                "description": "Malware family Katana",
                "firstContact": "2023-02-15T02:18:17Z",
                "hasPlaybackContacts": false,
                "id": "853e3020-aca5-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "2144": 1
                },
                "lastContact": "2023-02-15T02:18:17Z",
                "status": "open",
                "statusTimestamp": "2023-02-14T20:24:02.338Z",
                "timestamp": "2023-02-14T20:24:02.338Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "www.puertoballesta.com"
                ],
                "adversaryId": "www.puertoballesta.com",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 1,
                "description": "Phishing domain",
                "firstContact": "2023-02-14T17:08:11.751Z",
                "hasPlaybackContacts": false,
                "id": "91aaaf20-ac8a-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "989": 1
                },
                "lastContact": "2023-02-14T17:08:11.751Z",
                "status": "open",
                "statusTimestamp": "2023-02-14T17:24:41.268Z",
                "timestamp": "2023-02-14T17:11:06.770Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "msk.turbolider.ru"
                ],
                "adversaryId": "msk.turbolider.ru",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 2,
                "description": "Phishing domain",
                "firstContact": "2023-02-14T16:28:11.169Z",
                "hasPlaybackContacts": false,
                "id": "99b7bf10-ac84-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "147": 2
                },
                "lastContact": "2023-02-14T16:28:11.169Z",
                "status": "open",
                "statusTimestamp": "2023-02-14T16:28:23.297Z",
                "timestamp": "2023-02-14T16:28:23.297Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "rspg-spectrum.eu"
                ],
                "adversaryId": "rspg-spectrum.eu",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 7,
                "description": "Phishing domain",
                "firstContact": "2023-01-13T18:15:24.305Z",
                "hasPlaybackContacts": true,
                "id": "903c5580-abef-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "2041": 5,
                    "4055": 2
                },
                "lastContact": "2023-02-14T16:01:27.715Z",
                "status": "open",
                "statusTimestamp": "2023-02-13T22:41:32.376Z",
                "timestamp": "2023-02-13T22:41:32.376Z",
                "totalEndpoints": 3,
                "unread": false
            },
            {
                "adversaries": [
                    "scalarchives.com"
                ],
                "adversaryId": "scalarchives.com",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 4,
                "description": "Phishing domain",
                "firstContact": "2023-01-13T21:44:39.025Z",
                "hasPlaybackContacts": true,
                "id": "f2571f00-aa43-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "4055": 4
                },
                "lastContact": "2023-01-13T21:44:39.035Z",
                "status": "open",
                "statusTimestamp": "2023-02-11T19:40:32.368Z",
                "timestamp": "2023-02-11T19:40:32.368Z",
                "totalEndpoints": 2,
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
                "contacts": 9,
                "description": "Malware family Trojan.Win32.Generic",
                "firstContact": "2023-02-09T16:04:59.540Z",
                "hasPlaybackContacts": false,
                "id": "e6a0cc30-a893-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "1885": 1,
                    "2144": 7,
                    "989": 1
                },
                "lastContact": "2023-02-14T23:34:09.414Z",
                "status": "open",
                "statusTimestamp": "2023-02-09T16:07:50.131Z",
                "timestamp": "2023-02-09T16:07:50.131Z",
                "totalEndpoints": 3,
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
                "statusTimestamp": "2023-02-09T15:55:27.960Z",
                "timestamp": "2023-01-28T05:29:59.070Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "dimar.cl"
                ],
                "adversaryId": "dimar.cl",
                "adversaryTypes": [
                    "Malware"
                ],
                "contacts": 2,
                "description": "Malicious domain",
                "firstContact": "2023-02-07T08:10:51.125Z",
                "hasPlaybackContacts": false,
                "id": "cf26cf90-a7e5-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "51": 2
                },
                "lastContact": "2023-02-07T08:10:51.125Z",
                "status": "open",
                "statusTimestamp": "2023-02-08T19:21:38.313Z",
                "timestamp": "2023-02-08T19:21:38.313Z",
                "totalEndpoints": 1,
                "unread": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| activity.lumu.io | activity.lumu.io | Spam | 8 | Activity Test Query | 2023-02-08T16:41:35.613Z | false | 7c40be00-a7cf-11ed-9fd0-e5fb50c818f6 | 147: 1<br/>2254: 1<br/>1885: 2<br/>989: 2<br/>0: 2 | 2023-02-15T16:59:47.142Z | open | 2023-02-15T12:01:03.667Z | 2023-02-08T16:41:50.304Z | 6 | false |
>| 104.156.63.145 | 104.156.63.145 | C2C | 10 | Malware family Agentemis | 2023-02-15T02:21:59Z | false | 8c5efc90-aca5-11ed-9fd0-e5fb50c818f6 | 2144: 10 | 2023-02-15T05:35:40Z | open | 2023-02-14T20:24:14.297Z | 2023-02-14T20:24:14.297Z | 1 | false |
>| 161.97.110.203 | 161.97.110.203 | C2C | 1 | Malware family Katana | 2023-02-15T02:18:17Z | false | 853e3020-aca5-11ed-9fd0-e5fb50c818f6 | 2144: 1 | 2023-02-15T02:18:17Z | open | 2023-02-14T20:24:02.338Z | 2023-02-14T20:24:02.338Z | 1 | false |
>| www.puertoballesta.com | www.puertoballesta.com | Phishing | 1 | Phishing domain | 2023-02-14T17:08:11.751Z | false | 91aaaf20-ac8a-11ed-9fd0-e5fb50c818f6 | 989: 1 | 2023-02-14T17:08:11.751Z | open | 2023-02-14T17:24:41.268Z | 2023-02-14T17:11:06.770Z | 1 | false |
>| msk.turbolider.ru | msk.turbolider.ru | Phishing | 2 | Phishing domain | 2023-02-14T16:28:11.169Z | false | 99b7bf10-ac84-11ed-9fd0-e5fb50c818f6 | 147: 2 | 2023-02-14T16:28:11.169Z | open | 2023-02-14T16:28:23.297Z | 2023-02-14T16:28:23.297Z | 1 | false |
>| rspg-spectrum.eu | rspg-spectrum.eu | Phishing | 7 | Phishing domain | 2023-01-13T18:15:24.305Z | true | 903c5580-abef-11ed-9fd0-e5fb50c818f6 | 4055: 2<br/>2041: 5 | 2023-02-14T16:01:27.715Z | open | 2023-02-13T22:41:32.376Z | 2023-02-13T22:41:32.376Z | 3 | false |
>| scalarchives.com | scalarchives.com | Phishing | 4 | Phishing domain | 2023-01-13T21:44:39.025Z | true | f2571f00-aa43-11ed-9fd0-e5fb50c818f6 | 4055: 4 | 2023-01-13T21:44:39.035Z | open | 2023-02-11T19:40:32.368Z | 2023-02-11T19:40:32.368Z | 2 | false |
>| www.ascentive.com | www.ascentive.com | Malware | 9 | Malware family Trojan.Win32.Generic | 2023-02-09T16:04:59.540Z | false | e6a0cc30-a893-11ed-9fd0-e5fb50c818f6 | 989: 1<br/>2144: 7<br/>1885: 1 | 2023-02-14T23:34:09.414Z | open | 2023-02-09T16:07:50.131Z | 2023-02-09T16:07:50.131Z | 3 | false |
>| ac20mail.in | ac20mail.in | Spam | 1 | Disposable email host | 2023-01-28T05:29:26.009Z | false | ce5753e0-9ecc-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T05:29:26.009Z | open | 2023-02-09T15:55:27.960Z | 2023-01-28T05:29:59.070Z | 1 | false |
>| dimar.cl | dimar.cl | Malware | 2 | Malicious domain | 2023-02-07T08:10:51.125Z | false | cf26cf90-a7e5-11ed-9fd0-e5fb50c818f6 | 51: 2 | 2023-02-07T08:10:51.125Z | open | 2023-02-08T19:21:38.313Z | 2023-02-08T19:21:38.313Z | 1 | false |
>
>### paginationInfo
>|Items|Next|Page|
>|---|---|---|
>| 10 | 2 | 1 |


#### Command example
```!lumu-retrieve-open-incidents adversary-types=Spam labels=1791```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveOpenIncidents": [
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
                "status": "open",
                "statusTimestamp": "2023-02-08T00:29:50.824Z",
                "timestamp": "2023-01-13T21:51:28.308Z",
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
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| jits.ac.in | jits.ac.in | Malware | 5 | QakBot | 2023-01-13T21:51:12.190Z | false | 6eddaf40-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>548: 3<br/>4301: 1 | 2023-01-27T21:23:34.329Z | open | 2023-02-08T00:29:50.824Z | 2023-01-13T21:51:28.308Z | 3 | false |
>| msgos.com | msgos.com | Spam | 3 | Disposable email host | 2023-01-13T21:51:10.312Z | false | 6edc4fb0-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4055: 1<br/>4301: 1 | 2023-01-27T21:16:25.261Z | open | 2023-01-13T21:51:28.299Z | 2023-01-13T21:51:28.299Z | 3 | false |
>| netwonder.net | netwonder.net | Malware | 9 | Malware family Nivdort | 2023-01-13T21:50:53.247Z | false | 642934c0-938c-11ed-b0f8-a7e340234a4e | 1791: 2<br/>2144: 6<br/>4301: 1 | 2023-01-27T21:21:19.861Z | open | 2023-01-13T21:51:10.348Z | 2023-01-13T21:51:10.348Z | 3 | false |
>| subwaybookreview.com | subwaybookreview.com | Malware | 2 | Malware family Exploit.Msoffice.Generic | 2023-01-13T21:50:38.599Z | false | 59641870-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:33:59.964Z | open | 2023-01-13T21:50:52.279Z | 2023-01-13T21:50:52.279Z | 2 | true |
>| michaeleaston.com | michaeleaston.com | Malware | 3 | Malware family Trojan.Agent.Bg.Script | 2023-01-13T21:49:50.220Z | false | 405525e0-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>989: 1<br/>4301: 1 | 2023-01-27T21:16:25.995Z | open | 2023-01-13T21:50:10.238Z | 2023-01-13T21:50:10.238Z | 3 | false |
>| cane.pw | cane.pw | Spam | 2 | Disposable email host | 2023-01-13T21:49:28.515Z | false | 304360e0-938c-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:16:25.956Z | open | 2023-01-13T21:49:43.278Z | 2023-01-13T21:49:43.278Z | 2 | true |
>| cek.pm | cek.pm | Spam | 2 | Disposable email host | 2023-01-13T21:47:46.473Z | false | f1a7da00-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:16:25.744Z | open | 2023-01-13T21:47:58.240Z | 2023-01-13T21:47:58.240Z | 2 | true |
>| anothercity.ru | anothercity.ru | Malware | 2 | Malware family Backdoor.Peg.Php.Generic | 2023-01-13T21:46:26.925Z | false | c329ff00-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:16:25.912Z | open | 2023-01-13T21:46:40.240Z | 2023-01-13T21:46:40.240Z | 2 | false |
>| tormail.org | tormail.org | Spam | 4 | Disposable email host | 2023-01-13T21:46:15.650Z | false | bc0a4400-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>2144: 2<br/>4301: 1 | 2023-01-27T21:03:07.761Z | open | 2023-01-13T21:46:28.288Z | 2023-01-13T21:46:28.288Z | 3 | true |
>| businessbackend.com | businessbackend.com | Spam | 2 | Disposable email host | 2023-01-13T21:46:06.886Z | false | ba390670-938b-11ed-b0f8-a7e340234a4e | 1791: 1<br/>4301: 1 | 2023-01-27T21:03:35.699Z | open | 2023-01-13T21:46:25.239Z | 2023-01-13T21:46:25.239Z | 2 | true |
>
>### paginationInfo
>|Items|Next|Page|
>|---|---|---|
>| 10 | 2 | 1 |


### lumu-retrieve-muted-incidents
***
Get a paginated list of muted incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-muted-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page requested . | Optional | 
| limit | items limit requested . Default is 10. | Optional | 
| adversary_types | choose types: C2C,Malware,DGA,Mining,Spam,Phishing. Possible values are: C2C, Malware, DGA, Mining, Spam, Phishing. | Optional | 
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
        "RetrieveMutedIncidents": [
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
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
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
>
>### paginationInfo
>|Items|Next|Page|
>|---|---|---|
>| 10 | 2 | 1 |


#### Command example
```!lumu-retrieve-muted-incidents labels=1651 adversary-types=Malware```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveMutedIncidents": [
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
        ]
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
>
>### paginationInfo
>|Items|Page|
>|---|---|
>| 10 | 1 |


### lumu-retrieve-closed-incidents
***
Get a paginated list of closed incidents for the company. The items are listed by the most recent.


#### Base Command

`lumu-retrieve-closed-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page requested . | Optional | 
| limit | items limit requested . Default is 10. | Optional | 
| adversary_types | choose types: C2C,Malware,DGA,Mining,Spam,Phishing. Possible values are: C2C, Malware, DGA, Mining, Spam, Phishing. | Optional | 
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
        "RetrieveClosedIncidents": [
            {
                "adversaries": [
                    "www.chg.com.br"
                ],
                "adversaryId": "www.chg.com.br",
                "adversaryTypes": [
                    "Malware"
                ],
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-15T13:28:25.537Z",
                "hasPlaybackContacts": false,
                "id": "ad2b63c0-ad34-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-15T13:28:25.537Z",
                "status": "closed",
                "statusTimestamp": "2023-02-15T21:53:41.468Z",
                "timestamp": "2023-02-15T13:28:47.356Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "italive.it"
                ],
                "adversaryId": "italive.it",
                "adversaryTypes": [
                    "Phishing"
                ],
                "contacts": 1,
                "description": "Phishing domain",
                "firstContact": "2023-01-28T03:37:56.088Z",
                "hasPlaybackContacts": false,
                "id": "3e5f6480-9ebd-11ed-a0c7-dd6f8e69d343",
                "labelDistribution": {
                    "4301": 1
                },
                "lastContact": "2023-01-28T03:37:56.088Z",
                "status": "closed",
                "statusTimestamp": "2023-02-15T13:28:32.355Z",
                "timestamp": "2023-01-28T03:38:35.080Z",
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
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-10T23:58:44.455Z",
                "hasPlaybackContacts": false,
                "id": "e65b3f60-a99e-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-10T23:58:44.455Z",
                "status": "closed",
                "statusTimestamp": "2023-02-15T13:28:07.991Z",
                "timestamp": "2023-02-10T23:59:05.302Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "portaconexao8.top"
                ],
                "adversaryId": "portaconexao8.top",
                "adversaryTypes": [
                    "Malware"
                ],
                "contacts": 2,
                "description": "Malware hash: 55e57c52cd5e1dcfad4e9bcf0eb2f3a5",
                "firstContact": "2023-02-11T18:40:09.087Z",
                "hasPlaybackContacts": false,
                "id": "89658e80-aa3b-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "147": 2
                },
                "lastContact": "2023-02-11T18:40:09.087Z",
                "status": "closed",
                "statusTimestamp": "2023-02-15T13:26:02.357Z",
                "timestamp": "2023-02-11T18:40:20.328Z",
                "totalEndpoints": 1,
                "unread": false
            },
            {
                "adversaries": [
                    "bitmovil.mx"
                ],
                "adversaryId": "bitmovil.mx",
                "adversaryTypes": [
                    "Malware"
                ],
                "contacts": 2,
                "description": "Heodo",
                "firstContact": "2023-02-14T17:05:37.987Z",
                "hasPlaybackContacts": false,
                "id": "0d207a50-ac8a-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "989": 2
                },
                "lastContact": "2023-02-14T17:05:37.987Z",
                "status": "closed",
                "statusTimestamp": "2023-02-14T18:44:09.946Z",
                "timestamp": "2023-02-14T17:07:24.405Z",
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
                "firstContact": "2023-02-14T17:27:26.791Z",
                "hasPlaybackContacts": false,
                "id": "e0b39da0-ac8c-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "989": 1
                },
                "lastContact": "2023-02-14T17:27:26.791Z",
                "status": "closed",
                "statusTimestamp": "2023-02-14T18:33:38.315Z",
                "timestamp": "2023-02-14T17:27:38.362Z",
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
                "contacts": 21,
                "description": "Malware family P2PZeuS",
                "firstContact": "2022-12-12T16:36:02.228Z",
                "hasPlaybackContacts": false,
                "id": "726849c0-7a6b-11ed-a600-d53ba4d2bb70",
                "labelDistribution": {
                    "1885": 1,
                    "2254": 19,
                    "2267": 1
                },
                "lastContact": "2023-01-03T23:31:50.938Z",
                "status": "closed",
                "statusTimestamp": "2023-02-14T17:26:47.897Z",
                "timestamp": "2022-12-12T22:22:21.788Z",
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
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-10T22:39:28.912Z",
                "hasPlaybackContacts": false,
                "id": "d42c40b0-a993-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-10T22:39:28.912Z",
                "status": "closed",
                "statusTimestamp": "2023-02-10T22:41:07.512Z",
                "timestamp": "2023-02-10T22:39:50.331Z",
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
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-10T21:56:41.360Z",
                "hasPlaybackContacts": false,
                "id": "d98a0f20-a98d-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-10T21:56:41.360Z",
                "status": "closed",
                "statusTimestamp": "2023-02-10T22:37:37.379Z",
                "timestamp": "2023-02-10T21:57:02.354Z",
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
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-10T21:41:27.961Z",
                "hasPlaybackContacts": false,
                "id": "b9e93490-a98b-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-10T21:41:27.961Z",
                "status": "closed",
                "statusTimestamp": "2023-02-10T21:56:37.507Z",
                "timestamp": "2023-02-10T21:41:50.297Z",
                "totalEndpoints": 1,
                "unread": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-15T13:28:25.537Z | false | ad2b63c0-ad34-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-15T13:28:25.537Z | closed | 2023-02-15T21:53:41.468Z | 2023-02-15T13:28:47.356Z | 1 | false |
>| italive.it | italive.it | Phishing | 1 | Phishing domain | 2023-01-28T03:37:56.088Z | false | 3e5f6480-9ebd-11ed-a0c7-dd6f8e69d343 | 4301: 1 | 2023-01-28T03:37:56.088Z | closed | 2023-02-15T13:28:32.355Z | 2023-01-28T03:38:35.080Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-10T23:58:44.455Z | false | e65b3f60-a99e-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-10T23:58:44.455Z | closed | 2023-02-15T13:28:07.991Z | 2023-02-10T23:59:05.302Z | 1 | false |
>| portaconexao8.top | portaconexao8.top | Malware | 2 | Malware hash: 55e57c52cd5e1dcfad4e9bcf0eb2f3a5 | 2023-02-11T18:40:09.087Z | false | 89658e80-aa3b-11ed-9fd0-e5fb50c818f6 | 147: 2 | 2023-02-11T18:40:09.087Z | closed | 2023-02-15T13:26:02.357Z | 2023-02-11T18:40:20.328Z | 1 | false |
>| bitmovil.mx | bitmovil.mx | Malware | 2 | Heodo | 2023-02-14T17:05:37.987Z | false | 0d207a50-ac8a-11ed-9fd0-e5fb50c818f6 | 989: 2 | 2023-02-14T17:05:37.987Z | closed | 2023-02-14T18:44:09.946Z | 2023-02-14T17:07:24.405Z | 1 | false |
>| rea.co.ke | rea.co.ke | C2C,<br/>Malware | 1 | Malware family P2PZeuS | 2023-02-14T17:27:26.791Z | false | e0b39da0-ac8c-11ed-9fd0-e5fb50c818f6 | 989: 1 | 2023-02-14T17:27:26.791Z | closed | 2023-02-14T18:33:38.315Z | 2023-02-14T17:27:38.362Z | 1 | false |
>| rea.co.ke | rea.co.ke | C2C,<br/>Malware | 21 | Malware family P2PZeuS | 2022-12-12T16:36:02.228Z | false | 726849c0-7a6b-11ed-a600-d53ba4d2bb70 | 2267: 1<br/>1885: 1<br/>2254: 19 | 2023-01-03T23:31:50.938Z | closed | 2023-02-14T17:26:47.897Z | 2022-12-12T22:22:21.788Z | 5 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-10T22:39:28.912Z | false | d42c40b0-a993-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-10T22:39:28.912Z | closed | 2023-02-10T22:41:07.512Z | 2023-02-10T22:39:50.331Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-10T21:56:41.360Z | false | d98a0f20-a98d-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-10T21:56:41.360Z | closed | 2023-02-10T22:37:37.379Z | 2023-02-10T21:57:02.354Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-10T21:41:27.961Z | false | b9e93490-a98b-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-10T21:41:27.961Z | closed | 2023-02-10T21:56:37.507Z | 2023-02-10T21:41:50.297Z | 1 | false |
>
>### paginationInfo
>|Items|Next|Page|
>|---|---|---|
>| 10 | 2 | 1 |


#### Command example
```!lumu-retrieve-closed-incidents labels=0 adversary-types=Mining,Spam```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveClosedIncidents": [
            {
                "adversaries": [
                    "www.chg.com.br"
                ],
                "adversaryId": "www.chg.com.br",
                "adversaryTypes": [
                    "Malware"
                ],
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-15T13:28:25.537Z",
                "hasPlaybackContacts": false,
                "id": "ad2b63c0-ad34-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-15T13:28:25.537Z",
                "status": "closed",
                "statusTimestamp": "2023-02-15T21:53:41.468Z",
                "timestamp": "2023-02-15T13:28:47.356Z",
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
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-10T23:58:44.455Z",
                "hasPlaybackContacts": false,
                "id": "e65b3f60-a99e-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-10T23:58:44.455Z",
                "status": "closed",
                "statusTimestamp": "2023-02-15T13:28:07.991Z",
                "timestamp": "2023-02-10T23:59:05.302Z",
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
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-10T22:39:28.912Z",
                "hasPlaybackContacts": false,
                "id": "d42c40b0-a993-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-10T22:39:28.912Z",
                "status": "closed",
                "statusTimestamp": "2023-02-10T22:41:07.512Z",
                "timestamp": "2023-02-10T22:39:50.331Z",
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
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-10T21:56:41.360Z",
                "hasPlaybackContacts": false,
                "id": "d98a0f20-a98d-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-10T21:56:41.360Z",
                "status": "closed",
                "statusTimestamp": "2023-02-10T22:37:37.379Z",
                "timestamp": "2023-02-10T21:57:02.354Z",
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
                "contacts": 1,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-10T21:41:27.961Z",
                "hasPlaybackContacts": false,
                "id": "b9e93490-a98b-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 1
                },
                "lastContact": "2023-02-10T21:41:27.961Z",
                "status": "closed",
                "statusTimestamp": "2023-02-10T21:56:37.507Z",
                "timestamp": "2023-02-10T21:41:50.297Z",
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
                "contacts": 10,
                "description": "Malware family Win32.Remoteadmin.C.Winvnc.Based",
                "firstContact": "2023-02-03T19:01:00Z",
                "hasPlaybackContacts": false,
                "id": "d0ce2800-a3f5-11ed-a0c7-dd6f8e69d343",
                "labelDistribution": {
                    "0": 7,
                    "989": 3
                },
                "lastContact": "2023-02-10T21:40:12.762Z",
                "status": "closed",
                "statusTimestamp": "2023-02-10T21:41:34.408Z",
                "timestamp": "2023-02-03T19:06:08.384Z",
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
                "contacts": 5,
                "description": "Activity Test Query",
                "firstContact": "2022-12-20T14:37:02.228Z",
                "hasPlaybackContacts": false,
                "id": "460dd2d0-a740-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 5
                },
                "lastContact": "2022-12-20T14:37:02.228Z",
                "status": "closed",
                "statusTimestamp": "2023-02-08T00:57:03.424Z",
                "timestamp": "2023-02-07T23:36:41.341Z",
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
                "id": "9e9238e0-a73d-11ed-9fd0-e5fb50c818f6",
                "labelDistribution": {
                    "0": 2
                },
                "lastContact": "2022-12-20T14:37:02.228Z",
                "status": "closed",
                "statusTimestamp": "2023-02-07T23:20:42.817Z",
                "timestamp": "2023-02-07T23:17:41.358Z",
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
            }
        ]
    }
}
```

#### Human Readable Output

>### Incidents
>|Adversaries|Adversary Id|Adversary Types|Contacts|Description|First Contact|Has Playback Contacts|Id|Label Distribution|Last Contact|Status|Status Timestamp|Timestamp|Total Endpoints|Unread|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-15T13:28:25.537Z | false | ad2b63c0-ad34-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-15T13:28:25.537Z | closed | 2023-02-15T21:53:41.468Z | 2023-02-15T13:28:47.356Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-10T23:58:44.455Z | false | e65b3f60-a99e-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-10T23:58:44.455Z | closed | 2023-02-15T13:28:07.991Z | 2023-02-10T23:59:05.302Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-10T22:39:28.912Z | false | d42c40b0-a993-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-10T22:39:28.912Z | closed | 2023-02-10T22:41:07.512Z | 2023-02-10T22:39:50.331Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-10T21:56:41.360Z | false | d98a0f20-a98d-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-10T21:56:41.360Z | closed | 2023-02-10T22:37:37.379Z | 2023-02-10T21:57:02.354Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 1 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-10T21:41:27.961Z | false | b9e93490-a98b-11ed-9fd0-e5fb50c818f6 | 0: 1 | 2023-02-10T21:41:27.961Z | closed | 2023-02-10T21:56:37.507Z | 2023-02-10T21:41:50.297Z | 1 | false |
>| www.chg.com.br | www.chg.com.br | Malware | 10 | Malware family Win32.Remoteadmin.C.Winvnc.Based | 2023-02-03T19:01:00Z | false | d0ce2800-a3f5-11ed-a0c7-dd6f8e69d343 | 989: 3<br/>0: 7 | 2023-02-10T21:40:12.762Z | closed | 2023-02-10T21:41:34.408Z | 2023-02-03T19:06:08.384Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 5 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 460dd2d0-a740-11ed-9fd0-e5fb50c818f6 | 0: 5 | 2022-12-20T14:37:02.228Z | closed | 2023-02-08T00:57:03.424Z | 2023-02-07T23:36:41.341Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 2 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | 9e9238e0-a73d-11ed-9fd0-e5fb50c818f6 | 0: 2 | 2022-12-20T14:37:02.228Z | closed | 2023-02-07T23:20:42.817Z | 2023-02-07T23:17:41.358Z | 1 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 12 | Activity Test Query | 2023-02-07T15:51:15.463Z | false | 826dd220-a6ff-11ed-9fd0-e5fb50c818f6 | 989: 1<br/>0: 11 | 2023-02-07T15:51:15.463Z | closed | 2023-02-07T23:08:53.658Z | 2023-02-07T15:53:05.346Z | 3 | false |
>| activity.lumu.io | activity.lumu.io | Spam | 3 | Activity Test Query | 2022-12-20T14:37:02.228Z | false | eb611160-a638-11ed-a0c7-dd6f8e69d343 | 0: 3 | 2022-12-20T14:37:02.228Z | closed | 2023-02-06T16:19:52.211Z | 2023-02-06T16:11:31.574Z | 1 | false |
>
>### paginationInfo
>|Items|Next|Page|
>|---|---|---|
>| 10 | 2 | 1 |


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
| limit | items limit requested . Default is 10. | Optional | 


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
```!lumu-retrieve-endpoints-by-incident lumu_incident_id=7c40be00-a7cf-11ed-9fd0-e5fb50c818f6```
#### Context Example
```json
{
    "Lumu": {
        "RetrieveEndpointsByIncident": [
            {
                "endpoint": "LUMU-100",
                "first": "2023-02-15T16:59:47.142Z",
                "label": 0,
                "last": "2023-02-15T16:59:47.142Z",
                "lastSourceId": "6d942a7a-d287-415e-9c09-3d6632a6a976",
                "lastSourceType": "custom_collector",
                "total": 1
            },
            {
                "endpoint": "Loacal-nesfapdm",
                "first": "2022-12-20T14:37:02.228Z",
                "label": 0,
                "last": "2022-12-20T14:37:02.228Z",
                "lastSourceId": "6d942a7a-d287-415e-9c09-3d6632a6a976",
                "lastSourceType": "custom_collector",
                "total": 1
            },
            {
                "endpoint": "cd-ho",
                "first": "2023-02-08T16:41:35.613Z",
                "label": 147,
                "last": "2023-02-08T16:41:35.613Z",
                "lastSourceId": "587ec9d348053ca03a58aeddeccb1b93",
                "lastSourceType": "PublicResolver",
                "total": 1
            },
            {
                "endpoint": "fgiraldo",
                "first": "2023-02-10T14:23:45Z",
                "label": 1885,
                "last": "2023-02-10T15:15:16Z",
                "lastSourceId": "c91a9a48-274f-430e-989e-cc237b594621",
                "lastSourceType": "integration",
                "total": 2
            },
            {
                "endpoint": "63620343863.instance-1",
                "first": "2023-02-13T17:01:43.204Z",
                "label": 2254,
                "last": "2023-02-13T17:01:43.204Z",
                "lastSourceId": "4358d167-3af0-4821-9f7b-ee58824ff87b",
                "lastSourceType": "integration",
                "total": 1
            },
            {
                "endpoint": "DESKTOP-LUMU",
                "first": "2023-02-09T15:22:01.450Z",
                "label": 989,
                "last": "2023-02-09T15:22:30.732Z",
                "lastSourceId": "c5ae44a0-8c53-11ed-8008-11cbedd55f0c",
                "lastSourceType": "windows_agent",
                "total": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Incident endpoints
>|Endpoint|First|Label|Last|Last Source Id|Last Source Type|Total|
>|---|---|---|---|---|---|---|
>| LUMU-100 | 2023-02-15T16:59:47.142Z | 0 | 2023-02-15T16:59:47.142Z | 6d942a7a-d287-415e-9c09-3d6632a6a976 | custom_collector | 1 |
>| Loacal-nesfapdm | 2022-12-20T14:37:02.228Z | 0 | 2022-12-20T14:37:02.228Z | 6d942a7a-d287-415e-9c09-3d6632a6a976 | custom_collector | 1 |
>| cd-ho | 2023-02-08T16:41:35.613Z | 147 | 2023-02-08T16:41:35.613Z | 587ec9d348053ca03a58aeddeccb1b93 | PublicResolver | 1 |
>| fgiraldo | 2023-02-10T14:23:45Z | 1885 | 2023-02-10T15:15:16Z | c91a9a48-274f-430e-989e-cc237b594621 | integration | 2 |
>| 63620343863.instance-1 | 2023-02-13T17:01:43.204Z | 2254 | 2023-02-13T17:01:43.204Z | 4358d167-3af0-4821-9f7b-ee58824ff87b | integration | 1 |
>| DESKTOP-LUMU | 2023-02-09T15:22:01.450Z | 989 | 2023-02-09T15:22:30.732Z | c5ae44a0-8c53-11ed-8008-11cbedd55f0c | windows_agent | 2 |
>
>### paginationInfo
>|Items|Page|
>|---|---|
>| 10 | 1 |


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
```!lumu-mark-incident-as-read lumu_incident_id=7c40be00-a7cf-11ed-9fd0-e5fb50c818f6 ```
#### Context Example
```json
{
    "Lumu": {
        "MarkIncidentAsRead": ""
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
```!lumu-mute-incident lumu_incident_id=7c40be00-a7cf-11ed-9fd0-e5fb50c818f6 comment="mute from cortex"```
#### Context Example
```json
{
    "Lumu": {
        "MuteIncident": {
            "response": "",
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
```!lumu-unmute-incident lumu_incident_id=7c40be00-a7cf-11ed-9fd0-e5fb50c818f6 comment="unmute from cortex"```
#### Context Example
```json
{
    "Lumu": {
        "UnmuteIncident": {
            "response": "",
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
| limit | items limit requested . Default is 10. | Optional | 
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
            "offset": 1096578,
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
                            "uuid": "c45b8540-8073-11ed-8392-23f20218d429"
                        },
                        "incident": {
                            "adversaries": [
                                "activity.lumu.io"
                            ],
                            "adversaryId": "activity.lumu.io",
                            "adversaryTypes": [
                                "Spam"
                            ],
                            "contacts": 19,
                            "description": "Activity Test Query",
                            "firstContact": "2023-02-01T15:13:41.904Z",
                            "hasPlaybackContacts": false,
                            "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                            "labelDistribution": {
                                "0": 6,
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
                            "totalContacts": 10315,
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
                            "uuid": "c45b8540-8073-11ed-abb1-23f202b7a63d"
                        },
                        "incident": {
                            "adversaries": [
                                "activity.lumu.io"
                            ],
                            "adversaryId": "activity.lumu.io",
                            "adversaryTypes": [
                                "Spam"
                            ],
                            "contacts": 20,
                            "description": "Activity Test Query",
                            "firstContact": "2023-02-01T15:13:41.904Z",
                            "hasPlaybackContacts": false,
                            "id": "182f3950-a243-11ed-a0c7-dd6f8e69d343",
                            "labelDistribution": {
                                "0": 7,
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
                            "totalContacts": 10316,
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
                    "IncidentCommentAdded": {
                        "comment": "from XSOAR Cortex 20230206_135000 test comment, hmacsha256:efa407ced8d7cdedef4ed94e3730e3242996bd7ebf394c1e694d0b9a3f1087c6",
                        "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                        "incidentId": "182f3950-a243-11ed-a0c7-dd6f8e69d343"
                    }
                },
                {
                    "IncidentCommentAdded": {
                        "comment": "comment 854",
                        "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                        "incidentId": "182f3950-a243-11ed-a0c7-dd6f8e69d343"
                    }
                },
                {
                    "IncidentMarkedAsRead": {
                        "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                        "incidentId": "790f0700-9ec4-11ed-a0c7-dd6f8e69d343"
                    }
                },
                {
                    "IncidentMuted": {
                        "comment": "test",
                        "companyId": "10228d9c-ff18-4251-ac19-514185e00f17",
                        "incident": {
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
                            "status": "muted",
                            "statusTimestamp": "2023-02-06T15:01:54.199Z",
                            "timestamp": "2023-01-28T04:30:20.016Z",
                            "totalEndpoints": 1,
                            "unread": false
                        },
                        "reason": "irrelevant"
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
>| 1096578 | {'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 15, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 2}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10311, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-b5ad-23f20297b7bb', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 16, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 3}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10312, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-ab18-23f2022bdf77', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 17, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 4}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10313, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-a675-23f2020a8d4c', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 18, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 5}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10314, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-ba29-23f202e1cb1a', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 19, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 6}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10315, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-8392-23f20218d429', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentUpdated': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-02-01T15:14:17.061Z', 'statusTimestamp': '2023-02-01T15:14:17.061Z', 'status': 'open', 'contacts': 20, 'adversaries': ['activity.lumu.io'], 'adversaryId': 'activity.lumu.io', 'adversaryTypes': ['Spam'], 'description': 'Activity Test Query', 'labelDistribution': {'1792': 1, '989': 12, '0': 7}, 'totalEndpoints': 5, 'lastContact': '2023-02-03T16:44:00.395Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-02-01T15:13:41.904Z'}, 'openIncidentsStats': {'openIncidents': 1124, 'totalContacts': 10316, 'typeDistribution': {'DGA': 10, 'C2C': 106, 'Network Scan': 6, 'Mining': 274, 'Inappropriate content': 1, 'Phishing': 31, 'Spam': 265, 'Malware': 666}, 'labelDistribution': {'1792': 2, '147': 27, '3771': 1, '2254': 89, '4061': 10, '3774': 1, '3077': 30, '2280': 28, '3182': 4, '1885': 3, '2267': 11, '805': 9, '1791': 81, '2148': 247, '548': 25, '3635': 2, '989': 72, '3179': 1, '3005': 1, '4055': 134, '4301': 393, '1179': 2, '864': 3, '2144': 29, '1580': 147, '3811': 7, '4232': 2, '0': 35, '2974': 20, '3628': 1, '218': 4, '2692': 1, '1651': 14, '2821': 1}, 'totalEndpoints': 209}, 'contactSummary': {'uuid': 'c45b8540-8073-11ed-abb1-23f202b7a63d', 'timestamp': '2022-12-20T14:37:02.228Z', 'adversaryHost': 'activity.lumu.io', 'endpointIp': '192.168.0.13', 'endpointName': 'Loacal-nesfpdm', 'fromPlayback': False}}},<br/>{'IncidentCommentAdded': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incidentId': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'comment': 'from XSOAR Cortex 20230206_135000 test comment, hmacsha256:efa407ced8d7cdedef4ed94e3730e3242996bd7ebf394c1e694d0b9a3f1087c6'}},<br/>{'IncidentCommentAdded': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incidentId': '182f3950-a243-11ed-a0c7-dd6f8e69d343', 'comment': 'comment 854'}},<br/>{'IncidentMarkedAsRead': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incidentId': '790f0700-9ec4-11ed-a0c7-dd6f8e69d343'}},<br/>{'IncidentMuted': {'companyId': '10228d9c-ff18-4251-ac19-514185e00f17', 'incident': {'id': '790f0700-9ec4-11ed-a0c7-dd6f8e69d343', 'timestamp': '2023-01-28T04:30:20.016Z', 'statusTimestamp': '2023-02-06T15:01:54.199Z', 'status': 'muted', 'contacts': 1, 'adversaries': ['obobbo.com'], 'adversaryId': 'obobbo.com', 'adversaryTypes': ['Spam'], 'description': 'Disposable email host', 'labelDistribution': {'4301': 1}, 'totalEndpoints': 1, 'lastContact': '2023-01-28T04:29:57.692Z', 'unread': False, 'hasPlaybackContacts': False, 'firstContact': '2023-01-28T04:29:57.692Z'}, 'comment': 'test', 'reason': 'irrelevant'}} |


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
```!lumu-close-incident lumu_incident_id=7c40be00-a7cf-11ed-9fd0-e5fb50c818f6 comment="closed from Cortex"```
#### Context Example
```json
{
    "Lumu": {
        "CloseIncident": {
            "response": "",
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
                "e65b3f60-a99e-11ed-9fd0-e5fb50c818f6",
                "8c5efc90-aca5-11ed-9fd0-e5fb50c818f6",
                "903c5580-abef-11ed-9fd0-e5fb50c818f6",
                "ad2b63c0-ad34-11ed-9fd0-e5fb50c818f6",
                "229d4030-9eba-11ed-a0c7-dd6f8e69d343",
                "50240240-9ec0-11ed-a0c7-dd6f8e69d343",
                "02355f90-9ecd-11ed-a0c7-dd6f8e69d343",
                "099a9e80-2ec0-11ed-9b90-a51546bb08b5",
                "0fe32870-9ec3-11ed-a0c7-dd6f8e69d343",
                "73661810-9ec5-11ed-a0c7-dd6f8e69d343",
                "3e5f6480-9ebd-11ed-a0c7-dd6f8e69d343",
                "89658e80-aa3b-11ed-9fd0-e5fb50c818f6",
                "f2571f00-aa43-11ed-9fd0-e5fb50c818f6",
                "853e3020-aca5-11ed-9fd0-e5fb50c818f6",
                "6522d180-9ec5-11ed-a0c7-dd6f8e69d343",
                "fd6788c0-561b-11ed-987a-cd6f8ff058b8",
                "e6a0cc30-a893-11ed-9fd0-e5fb50c818f6",
                "38183850-8bbb-11ed-b0f8-a7e340234a4e",
                "a82e5550-9ec8-11ed-a0c7-dd6f8e69d343",
                "0d207a50-ac8a-11ed-9fd0-e5fb50c818f6",
                "7c40be00-a7cf-11ed-9fd0-e5fb50c818f6",
                "99b7bf10-ac84-11ed-9fd0-e5fb50c818f6",
                "91aaaf20-ac8a-11ed-9fd0-e5fb50c818f6",
                "726849c0-7a6b-11ed-a600-d53ba4d2bb70",
                "e0b39da0-ac8c-11ed-9fd0-e5fb50c818f6",
                "ec869190-85aa-11ed-a600-d53ba4d2bb70",
                "672a8c90-9ebe-11ed-a0c7-dd6f8e69d343"
            ]
        }
    }
}
```

#### Human Readable Output

>### Cache
>|Lumu _ Incidents Id|
>|---|
>| e65b3f60-a99e-11ed-9fd0-e5fb50c818f6,<br/>8c5efc90-aca5-11ed-9fd0-e5fb50c818f6,<br/>903c5580-abef-11ed-9fd0-e5fb50c818f6,<br/>ad2b63c0-ad34-11ed-9fd0-e5fb50c818f6,<br/>229d4030-9eba-11ed-a0c7-dd6f8e69d343,<br/>50240240-9ec0-11ed-a0c7-dd6f8e69d343,<br/>02355f90-9ecd-11ed-a0c7-dd6f8e69d343,<br/>099a9e80-2ec0-11ed-9b90-a51546bb08b5,<br/>0fe32870-9ec3-11ed-a0c7-dd6f8e69d343,<br/>73661810-9ec5-11ed-a0c7-dd6f8e69d343,<br/>3e5f6480-9ebd-11ed-a0c7-dd6f8e69d343,<br/>89658e80-aa3b-11ed-9fd0-e5fb50c818f6,<br/>f2571f00-aa43-11ed-9fd0-e5fb50c818f6,<br/>853e3020-aca5-11ed-9fd0-e5fb50c818f6,<br/>6522d180-9ec5-11ed-a0c7-dd6f8e69d343,<br/>fd6788c0-561b-11ed-987a-cd6f8ff058b8,<br/>e6a0cc30-a893-11ed-9fd0-e5fb50c818f6,<br/>38183850-8bbb-11ed-b0f8-a7e340234a4e,<br/>a82e5550-9ec8-11ed-a0c7-dd6f8e69d343,<br/>0d207a50-ac8a-11ed-9fd0-e5fb50c818f6,<br/>7c40be00-a7cf-11ed-9fd0-e5fb50c818f6,<br/>99b7bf10-ac84-11ed-9fd0-e5fb50c818f6,<br/>91aaaf20-ac8a-11ed-9fd0-e5fb50c818f6,<br/>726849c0-7a6b-11ed-a600-d53ba4d2bb70,<br/>e0b39da0-ac8c-11ed-9fd0-e5fb50c818f6,<br/>ec869190-85aa-11ed-a600-d53ba4d2bb70,<br/>672a8c90-9ebe-11ed-a0c7-dd6f8e69d343 |


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