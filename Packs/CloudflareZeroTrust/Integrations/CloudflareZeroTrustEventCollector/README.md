Cloudflare provides network and security products for consumers and businesses, utilizing reverse proxies for web traffic, edge computing, and a content distribution network to provide content across its network of servers.
This integration was integrated and tested with version 1 of Cloudflare Zero Trust.

## Authorization

Two authorization types are supported:

- **API Token** - Requires generating an account or a user API token.
- **Global API Key (Legacy)** - Requires retrieving the global API key and finding the associated Email address.

Refer to the integration help section for detailed instructions on how to attain the required credentials.

## Token Permissions

The **API Token** authorization method requires an access token with the following permissions:

- **Account** - **Account Settings** - **Read**
- **Account** - **Access: Audit Logs** - **Read**

**Note**: It is recommended to use an **account token** (instead of a user token) to set up this integration.

## Configure Cloudflare Zero Trust in Cortex

| **Parameter** | **Required** | **Additional Info** |
| --- | --- | --- |
| Server URL | True | The base URL for the Cloudflare API (e.g., https://api.cloudflare.com). |
| Account ID | True | Obtain from the [Account Overview page](https://dash.cloudflare.com/). |
| Trust any certificate (not secure) | False | |
| Use system proxy settings | False | |
| Authorization Type | True | Possible values are: API Token, Global API Key (Legacy). Default value is Global API Key (Legacy). |
| API Token | False | Obtain from the [Cloudflare API Tokens page](https://dash.cloudflare.com/profile/api-tokens). |
| API Email | False | Obtain from the [Cloudflare Profile page](https://dash.cloudflare.com/profile). |
| Global API Key | False | Obtain from the [Cloudflare API Tokens page](https://dash.cloudflare.com/profile/api-tokens). |
| Event types to fetch | True | Specify the types of events to fetch. Possible values are: Account Audit Logs, User Audit Logs, and Access Authentication Logs. |
| Maximum number of account audit logs per fetch | False | |
| Maximum number of user audit logs per fetch | False | |
| Maximum number of access authentication logs per fetch | False | |

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
| event_types_to_fetch | Comma-separated list of event types to fetch. Possible values are: Account Audit Logs, User Audit Logs, Access Authentication Logs. Default is Account Audit Logs,User Audit Logs. | Optional |

#### Context Output

There is no context output for this command.
