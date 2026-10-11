This is an anti fraud external api for organizations.
This integration was integrated and tested with version xx of Anti Fraud API.

## Configure Anti Fraud API in Cortex

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

### csc-controldetectionflowbyeventidandaction

***
Control detection flow by event ID and action

#### Base Command

`csc-controldetectionflowbyeventidandaction`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Update the action with eventID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCFraudProtection.message | String |  |
| CSCFraudProtection.status | String |  |

#### Context Example

```json
{
    "CSCFraudProtection": {
    "code": "Ref00-14818",
    "message": "The requested event was not found",
    "status": "error"
    }
}
```

### csc-fetchthephishkitdatawithticketid

***
Fetch the phishkit data with ticketId

#### Base Command

`csc-fetchthephishkitdatawithticketid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | Ticket Id to fetch phishkit. | Required |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCFraudProtection": {
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

### csc-fetchthescreenshotdatawithticketid

***
Fetch the screenshot data with ticketId

#### Base Command

`csc-fetchthescreenshotdatawithticketid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | Ticket Id to fetch screenshot. | Required |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCFraudProtection": {
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

### csc-gethtmlsourcecodeforaticket

***
Get HTML Source Code for a Ticket

#### Base Command

`csc-gethtmlsourcecodeforaticket`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | Ticket ID to fetch HTML source. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCFraudProtection.message | String |  |
| CSCFraudProtection.status | String |  |


#### Context Example

```json
{
    "CSCFraudProtection": {

    "code": "Ref00-14816",
    "message": "Event is not found in the application for ticketId: 1234",
    "status": "error"
}
}
```

### csc-getlistofbrands

***
Get list of Brands

#### Base Command

`csc-getlistofbrands`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCFraudProtection.brandId | Number |  |
| CSCFraudProtection.brandName | String |  |
| CSCFraudProtection.isActive | Boolean |  |

#### Context Example

```json
{
    "CSCFraudProtection": {
    "status": "success",
    "message": "fetched successfully",
    "data": [
        {
            "brandId": 4843,
            "brandName": "CSC Demo",
            "isActive": true
        }]
    }
}
```

### csc-getlistoffraudtypes

***
Get list of fraud types

#### Base Command

`csc-getlistoffraudtypes`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCFraudProtection.fraudTypeId | Number |  |
| CSCFraudProtection.fraudTypeName | String |  |

#### Context Example

```json
{
    "CSCFraudProtection": {
        "status": "success",
        "message": "fetched successfully",
        "data": [
            {
                "fraudTypeId": 1,
                "fraudTypeName": "Advanced Fee Fraud"
            },
            {
                "fraudTypeId": 2,
                "fraudTypeName": "BEC Scam"
            }
        ]
    }
}
```

### csc-listofworklogsforticketid

***
List of work logs for ticket id

#### Base Command

`csc-listofworklogsforticketid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ticketId | Ticket ID to fetch work log details. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCFraudProtection.message | String |  |
| CSCFraudProtection.status | String |  |

#### Context Example

```json
{
    "CSCFraudProtection": {
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

### csc-listtakedownevents

***
List Takedown Events

#### Base Command

`csc-listtakedownevents`

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
| CSCFraudProtection.message | String |  |
| CSCFraudProtection.status | String |  |

#### Context Example

```json
{
    "CSCFraudProtection": {
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

### csc-listtakedowneventswithfilters

***
List Takedown events with filters

#### Base Command

`csc-listtakedowneventswithfilters`

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
| CSCFraudProtection.message | String |  |
| CSCFraudProtection.status | String |  |

#### Context Example

```json
{
    "CSCFraudProtection": {
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

### csc-performanactiononasingletarget

***
Perform an action on a single target

#### Base Command

`csc-performanactiononasingletarget`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| targetType | Type of the target (URL, PHONE, EMAIL). | Optional |
| action | Ticket action. | Required |
| fraudType | Type of the Fraud. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCFraudProtection.message | String |  |
| CSCFraudProtection.status | String |  |

#### Context Example

```json
{
    "CSCFraudProtection": {
    "data": {
        "action": "monitor",
        "eventId": 275023938,
        "responseCode": 201
    },
    "status": 201
}
}
```

### csc-retrieveeventscreenshotwitheventid

***
Retrieve event screenshot with eventId

#### Base Command

`csc-retrieveeventscreenshotwitheventid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId | Event Id to fetch screenshot details. | Required |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCFraudProtection": {
        "status": "success",
        "message": "Data Fetched Successfully",
        "data": {
            "eventId": 187605483,
            "screenshot": "iVBORw0KGgoAAAANSUhEUgAAAlUAAAFNCAYAAAApa5rZAAAAAXNSR0IArs4c6QAAAARnQU1"
        }
    }
}
```

### csc-retrievefilteredlistofmonitoringresultswithinspecifiedtimeframe

***
Retrieve filtered list of monitoring results within specified timeframe

#### Base Command

`csc-retrievefilteredlistofmonitoringresultswithinspecifiedtimeframe`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- | --- |
| startDate         | Filter by from date. Expected format: YYYY-MM-DD. | Required |
| endDate           | Filter by end date. Expected format: YYYY-MM-DD. | Required |
| brandId           | Filter by Brand Id. | Optional |
| fraudType         | Type of the Fraud. | Optional |
| monitoringStatus  | Monitoring Status. | Optional |
| page              | page size. | Optional |
| limit             | Limit between 100 and 500, default is 100. | Optional |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCFraudProtection": {
    "status": "success",
    "message": "Data Fetched Successfully",
    "data": [],
    "meta": {
        "currentPage": 0,
        "pageSize": 100,
        "total": 0,
        "hasPrevious": false,
        "pages": 0,
        "hasNext": false,
        "previousPage": null,
        "nextPage": null
    }
}
}
```

### csc-retrievelistofdetectionswithinspecifiedtimeframe

***
Retrieve list of detections within specified timeframe

#### Base Command

`csc-retrievelistofdetectionswithinspecifiedtimeframe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fromDate | Filter by from date. Expected format: YYYY-MM-DD. | Required |
| toDate | Filter by to date. Expected format: YYYY-MM-DD. | Required |
| scoreMin | Filter by score. | Optional |
| ip | Filter by ip. | Optional |
| isp | Filter by isp. | Optional |
| registrar | Filter by registrar. | Optional |
| monitoring | Filter by monitoring. | Optional |
| page | page size. | Optional |
| limit | Limit between 100 and 500, default is 100. | Optional |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCFraudProtection": {
    "status": "success",
    "message": "Data Fetched Successfully",
    "data": [],
    "meta": {
        "currentPage": 0,
        "pageSize": 100,
        "total": 0,
        "hasPrevious": false,
        "pages": 0,
        "hasNext": false,
        "previousPage": null,
        "nextPage": null
    }
}
}
```
### csc-retrievelistofmonitoringresultswithinspecifiedtimeframe

***
Retrieve list of monitoring results within specified timeframe

#### Base Command

`csc-retrievelistofmonitoringresultswithinspecifiedtimeframe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| startDate | Filter by from date. Expected format: YYYY-MM-DD. | Required |
| endDate | Filter by end date. Expected format: YYYY-MM-DD. | Required |
| page | page size. | Optional |
| limit | Limit between 100 and 500, default is 100. | Optional |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCFraudProtection": {
        "data": [
            {
                "data": {
                    "ip": "34.205.231.173",
                    "isp": "Amazon AES",
                    "records": [
                        {
                            "recVersion": 2,
                            "recordType": "A",
                            "recordValue": "0.0.0.0"
                        }
                    ]
                }
            }
        ]
    }
}
```

### csc-retrievephishkitwitheventid

***
Retrieve phishkit with eventId

#### Base Command

`csc-retrievephishkitwitheventid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId | Event Id to fetch phishkit details. | Required |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCFraudProtection": {
    "code": "Ref00-14855",
    "message": "The requested phishkit was not found",
    "status": "error"
}
}
```

### csc-startorstopmonitoringforaspecificevent

***
Start or stop monitoring for a specific event

#### Base Command

`csc-startorstopmonitoringforaspecificevent`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Monitoring action to perform. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CSCFraudProtection.message | String |  |
| CSCFraudProtection.status | String |  |

#### Context Example

```json
{
    "CSCFraudProtection": {
    "code": "Ref00-14857",
    "message": "Event is not found in the application",
    "status": "error"
}
}
```

### csc-updatetheactionwithticketid

***
Update the action with ticketId

#### Base Command

`csc-updatetheactionwithticketid`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | Ticket action. | Required |

#### Context Output

There is no context output for this command.

#### Context Example

```json
{
    "CSCFraudProtection": {
    "status": "200",
    "message": "Updated Successfully",
    "data": {
        "ticketId": 62406,
        "action": "OPEN"
    }
}
}
```