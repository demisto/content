# ServiceNowGenericFeed

ServiceNowGenericFeed is a feed integration that pulls records from a ServiceNow CMDB API endpoint and ingests them as indicators into Threat Intelligence Management (TIM).

## Configure ServiceNowGenericFeed in Cortex XSOAR

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| integrationReliability | Reliability of the source providing the intelligence data. | False |
| url | Server URL (e.g., https://api.xsoar-example.com). Default: https://company.service-now.com/ | True |
| credentials | API Key (username/password). | True |
| feedTags | Tags applied to fetched indicators. | False |
| query_url | The API route of the requested information in ServiceNow. | False |
| indicator_field | Field used to build indicator values. | False |

## Commands

This integration is a feed and does not expose custom commands.

## Fetch Indicators

When the integration runs **fetch-indicators**, it:

1. Calls the ServiceNow CMDB API using **query_url**
2. Extracts records from the `result` field
3. Builds indicator objects using **indicator_field**
4. Adds indicators to TIM with **feedTags**

## Notes

- If **query_url** is not configured, the integration returns an error.
- If no records are returned from ServiceNow, the integration returns an error.
