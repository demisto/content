# 1Password Event Collector

Fetch events about actions performed by 1Password users within a specific account, access and modifications to items in shared vaults, and user sign-in attempts.

This integration was integrated and tested with V2 endpoints of the 1Password Events API.

## Configure 1Password Event Collector in Cortex

The integration can be configured to fetch three types of events from 1Password:

- **Audit events** - Information about actions performed by team members within a 1Password account. Events include when an action was performed and by whom, along with details about the type and object of the action and any other information about the activity.

- **Item usage actions** - Information about items in shared vaults that have been modified, accessed, or used. Events include the name and IP address of the user who accessed the item, when the item was accessed, and the vault where the item is stored.
  
- **Sign in attempts** - Information about sign-in attempts. Events include the name and IP address of the user who attempted to sign in to the account, when the attempt was made, and, for failed attempts, the cause of the failure.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The API server URL depends on the domain where the account is hosted. Refer to the integration Help section for more details. | True |
| API Token | The bearer token used to authenticate with the 1Password Events API. This must include the required features (scopes) that correspond to the event types to be fetched. Refer to the integration Help section for more details. | True |
| Trust any certificate (not secure) | Allow connections without verifying the SSL certificate of the server. | False |
| Use system proxy settings |  | False |
| Fetch Events | Whether to fetch events from 1Password. | False |
| Types of events to fetch | Types of events to fetch from 1Password. Possible values are: Audit events, Item usage actions, Sign in attempts. | True |
| Maximum number of audit events per fetch |  | True |
| Maximum number of item usage actions per fetch |  | True |
| Maximum number of sign in attempts per fetch |  | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### 1password-get-events

***
Fetch events from 1Password.

#### Base Command

`1password-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of events to fetch for the given event type. | Optional |
| should_push_events | Set this argument to True in order to push events to XSIAM, otherwise the command will only display them. Possible values are: true, false. Default is False. | Required |
| event_type | 1Password event type. If not specified, all event types will be fetched. Possible values are: Audit events, Item usage actions, Sign in attempts. | Optional |
| from_date | The date from which to get events. If not specified, events from the last 7 days will be fetched. | Optional |

#### Context Output

There is no context output for this command.
