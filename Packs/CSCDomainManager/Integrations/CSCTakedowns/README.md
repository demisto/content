This is a CSCTakedowns api for organizations.
This integration was integrated and tested with version xx of CSCTakedowns.

## Configure CSCTakedowns in Cortex

| **Parameter**                      | **Description** | **Required** |
|------------------------------------| --- | --- |
| Server URL                         | The endpoint URL | True |
| API Key                            | The API Key to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings          |  | False |

## Access and Data Security

You request access through the CSC service team at: phishing-response@cscglobal.com. The team will gather account details and access authorization to any accounts that will be used to access the API; and the API key will be generated and returned along with login credentials to access the API.

There is no token refresh or API expiration, all that is needed is to place the API key at the end of this URL:
`https://apis.cscglobal.com/dbs/fraud-protection/v1/fraud-protection-api/swagger/external/docs?APIKey={YOUR API KEY HERE}` and signing in with the provided credentials on said page.

CSC generates the API key and authorizes access to accounts within the organization. These authorizations are checked and verified before any information is returned to ensure data security.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### csctakedowns-fetchthephishkitdatawithticketid

***
Fetch the phishkit data with ticketId

#### Base Command

`csctakedowns-fetchthephishkitdatawithticketid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | Ticket Id to fetch phishkit. | Required |

#### Context Output

There is no context output for this command.


#### Context Example

```json
{
    "CSCTakeDowns": {
    "data": {
        "phishkit": [
            {
                "kit": "blob",
                "timeStamp": "2024-06-25T13:12:32"
            }
        ],
        "ticketId": 35607910
    },
    "message": "Data Fetched Successfully",
    "status": "success"
    }
}
```

### csctakedowns-fetchthescreenshotdatawithticketid

***
Fetch the screenshot data with ticketId

#### Base Command

`csctakedowns-fetchthescreenshotdatawithticketid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | Ticket Id to fetch screenshot. | Required |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCTakeDowns": {
        "data": {
            "screenshot": "blob",
            "screenshotTimeStamp": "2024-06-25 13:12:21.553812",
            "ticketId": "123456"
        },
        "message": "Data Fetched Successfully",
        "status": "success"
    }
}
```
### csctakedowns-gethtmlsourcecodeforaticket

***
Get HTML Source Code for a Ticket

#### Base Command

`csctakedowns-gethtmlsourcecodeforaticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | Ticket ID to fetch HTML source. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCTakedowns.message | String |  |
| CSCTakedowns.status | String |  |

#### Context Example

```json
{
    "CSCTakeDowns": {

    "code": "Ref00-14816",
    "message": "Event is not found in the application for ticketId: 1234",
    "status": "error"
}
}
```

### csctakedowns-listofworklogsforticketid

***
List of work logs for ticket id

#### Base Command

`csctakedowns-listofworklogsforticketid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | Ticket ID to fetch work log details. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCTakedowns.message | String |  |
| CSCTakedowns.status | String |  |


#### Context Example

```json
{
    "CSCTakeDowns": {
        "status": "success",
        "message": "Data Fetched Successfully",
        "data": [
            {
                "timeStamp": "2026-06-26 17:56:01",
                "title": "Event status changed from Monitoring to Inprogress by External API User",
                "type": "Internal Communication",
                "toAddress": null
            }
        ]
    }
}
```

### csctakedowns-listtakedownevents

***
List Takedown Events

#### Base Command

`csctakedowns-listtakedownevents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Start date in YYYY-MM-DD format. | Required |
| toDate | End date in YYYY--MM--DD format. | Required |
| page | page size. | Optional |
| limit | Limit between 100 and 500, default = 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCTakedowns.message | String |  |
| CSCTakedowns.status | String |  |

#### Context Example

```json
{
    "CSCTakeDowns": {
    "status": "success",
    "message": "Data Fetched Successfully",
    "data": [],
    "meta": {
        "currentPage": 1,
        "pageSize": 101,
        "total": 0,
        "hasPrevious": true,
        "pages": 0,
        "hasNext": false,
        "previousPage": 0,
        "nextPage": null
    }
}
}
```

### csctakedowns-listtakedowneventswithfilters

***
List Takedown events with filters

#### Base Command

`csctakedowns-listtakedowneventswithfilters`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- | --- |
| fromDate          | Start date in YYYY-MM-DD format. | Required |
| toDate            | End date in YYYY--MM--DD format. | Required |
| brandId           | Filter by Brand Id. | Optional |
| fraudType         | Type of the Fraud. | Optional |
| ticketStatus      | Ticket Status. | Optional |
| DetectionDate     | Filter by Detection date. | Optional |
| AuthorizationDate | Filter by Authorization date. | Optional |
| CompletedDate     | Filter by Closed date. | Optional |
| page              | page size. | Optional |
| limit             | Limit between 100 and 500, default = 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCTakedowns.message | String |  |
| CSCTakedowns.status | String |  |


#### Context Example

```json
{
    "CSCTakeDowns": {
    "status": "success",
    "message": "Data Fetched Successfully",
    "data": [],
    "meta": {
        "currentPage": 1,
        "pageSize": 101,
        "total": 0,
        "hasPrevious": true,
        "pages": 0,
        "hasNext": false,
        "previousPage": 0,
        "nextPage": null
    }
}
}
```

### csctakedowns-updatetheactionwithticketid

***
Update the action with ticketId

#### Base Command

`csctakedowns-updatetheactionwithticketid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Ticket action. | Required |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCTakeDowns": {
    "status": "200",
    "message": "Updated Successfully",
    "data": {
        "ticketId": 62406,
        "action": "OPEN"
    }
}
}
```