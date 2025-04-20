Use this integration to fetch email security incidents from FireEye ETP as XSIAM events.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure FireEye ETP Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://etp.us.fireeye.com) |  | True |
| API Secret Key | The API Key allows you to integrate with the FireEye ETP. | True |
| Maximum number of Alerts to fetch. | The maximum number of Alert events to fetch from FireEye ETP. |  |
| Maximum number of Email Trace to fetch. | The maximum number of Email Trace events to fetch from FireEye ETP. |  |
| Maximum number of Activity Log fetch. | The maximum number of Activity Log events to fetch from FireEye ETP. |  |
| Trust any certificate (not secure) |  |  |
| Use system proxy settings |  |  |
| Fetch outbound traffic | Outbound traffic will be fetched in addition to inbound traffic. |  |
| Hide sensitive details from email | Hide subject and attachments details from emails. |  |


## Access control
All the API requests follow the domain and domain group restrictions of the user. For example, if a user has access to only a few domains in their organization, the response to the APIs will be based on only those domains and domain groups.

## REST API Limitation
Email Security — Cloud REST APIs have a rate limit of 60 requests per minute per API route (/trace, /alert, and /quarantine) for every customer.
This means, in 1 minute, a customer can make:

60 requests to Trace APIs (parallel or sequential)
60 requests to Alert APIs (parallel or sequential)
60 requests to Quarantine APIs (parallel or sequential)

Within the minute, the 61st request to any of these APIs would throw a rate limit exceeded error.

The rate limit applies to the customer as a whole. This means that if the customer has multiple admin users who have generated API Keys, the rate limit is applicable at the customer level and not per API key. 

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fireeye-etp-get-events
***
Gets events from FireEye ETP.


#### Base Command

`fireeye-etp-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return. Default is 10. | Optional | 
| since_time | The start time by which to filter events. Date format will be the same as in the first_fetch parameter. Default is 3 days. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 


#### Context Output

There is no context output for this command.