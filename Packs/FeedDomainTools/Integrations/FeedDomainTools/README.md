DomainTools NOD/NAD Feed integration.
This integration was integrated and tested with version xx of FeedDomainTools.

## Configure FeedDomainTools in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Username |  | True |
| API Key |  | True |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dtfeeds-get-indicators

***
Gets indicators from the feed.

#### Base Command

`dtfeeds-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 10. | Optional | 
| feed_type | The DomainTools integration feed type to fetch. Default is nod. | Optional | 
| session_id | The session id. | Optional | 
| domain | The top level domain to query (e.g. `*.com`). | Optional | 
| after | The timestamp filter. | Optional | 
| top | The top items to return from the API. | Optional | 

#### Context Output

There is no context output for this command.
