This is an anti fraud external api for organizations.
This integration was integrated and tested with version xx of Anti Fraud API.

## Configure Anti Fraud API in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Access and Data Security

You request access through the CSC service team at: phishing-response@cscglobal.com. The team will gather account details and access authorization to any accounts that will be used to access the API; and the API key will be generated and returned along with login credentials to access the API.

There is no token refresh or API expiration, all that is needed is to place the API key at the end of this URL:
https://apis.cscglobal.com/dbs/fraud-protection/v1/fraud-protection-api/swagger/external/docs?APIKey={YOUR API KEY HERE} and signing in with the provided credentials on said page.

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
