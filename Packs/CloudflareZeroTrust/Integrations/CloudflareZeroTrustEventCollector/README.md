Cloudflare provides network and security products for consumers and businesses, utilizing reverse proxies for web traffic, edge computing, and since 2010, a content distribution network to provide content across its network of servers.
This integration was integrated and tested with version 1 of Cloudflare Zero Trust.

## Configure Cloudflare Zero Trust in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Maximum number of account audit logs per fetch | False |
| Maximum number of user audit logs per fetch | False |
| Maximum number of access authentication logs per fetch | False |
| API email | True |
| Global API key | True |
| Account ID | True |
| Event types to fetch | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cloudflare-zero-trust-get-events

***
Gets events from Cloudflare Zero Trust.

#### Base Command

`cloudflare-zero-trust-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return per type. Default is 10. | Optional | 
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Optional | 
| start_date | The start date from which to filter events. | Optional | 
| event_types_to_fetch | Event types to fetch. You can choose more than one, separated by commas, possible values are `Account Audit Logs`, `User Audit Logs`, and `Access Authentication Logs`. Possible values are: Account Audit Logs, User Audit Logs, Access Authentication Logs. Default is Account Audit Logs,User Audit Logs. | Optional | 

#### Context Output

There is no context output for this command.
