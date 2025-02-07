# 1Password

Fetch events about actions performed by 1Password users within a specific account, access and modifications to items in shared vaults, and user sign-in attempts.

This integration was integrated and tested with V2 endpoints of the 1Password Events API.

## Configure 1Password in Cortex

The integration can be configured to fetch three types of events from 1Password:

- **Audit events** - Information about actions performed by team members within a 1Password account. Events include details on a preformed action such as execution time and executing user, action type and any additional information about the activity.
- **Item usage actions** - Information about items in shared vaults that have been modified, accessed, or used. Events include the accessing user's name and IP address, time of access, and the vault where the item is stored.
- **Sign-in attempts** - Information about sign-in attempts. Events include the name and IP address of the user who attempted to sign in to the account, when the attempt was made, and, for failed attempts, the cause of the failure.

All event timestamps, along with date and time configuration parameters and command arguments, are in the Coordinated Universal Time (UTC) timezone.

Every call to the 1Password Events API must be authorized with a bearer token. To issue a new bearer token:

1. Sign in to your 1Password account and click **Integrations** in the sidebar.
2. Under the **Directory** tab, choose **(•••) Other** and enter a descriptive name for the integration, such as 'Cortex XSIAM'.
3. Enter a name for the bearer token and choose when it will expire.
4. Ensure the token has access to the event types listed above.
5. Click **Issue Token** to generate a new bearer token.
6. Save the token in a secure location and use it in configuring this integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The API server URL depends on the domain where the account is hosted. Refer to the integration Help section for more details. | True |
| API Token | The bearer token used to authenticate with the 1Password Events API. This must include the required features (scopes) that correspond to the event types to be fetched. Refer to the integration Help section for more details. | True |
| Trust any certificate (not secure) | Allow connections without verifying the SSL certificate of the server. | False |
| Use system proxy settings |  | False |
| Fetch Events | Whether to fetch events from 1Password. | False |
| Types of events to fetch | Types of events to fetch from 1Password. Possible values are: Audit events, Item usage actions, Sign in attempts. Default value is Audit events, Item usage actions, Sign in attempts. | True |
| Maximum number of audit events per fetch | If not specified, API default (100) will be used. | False |
| Maximum number of item usage actions per fetch | If not specified, API default (100) will be used. | False |
| Maximum number of sign-in attempts per fetch | If not specified, API default (100) will be used. | False |

## Limitations

It is recommended to configure the integration instance so that the maximum number of fetched events does not exceed **100,000 per minute per event type**. Otherwise, the 1Password Events API may raise rate limit errors (HTTP 429).

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### one-password-get-events

***
Fetch events from 1Password. This command is intended for development and debugging purposes and should be used with caution as it may create duplicate events.

#### Base Command

`one-password-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_type | 1Password event type. Possible values are: Audit events, Item usage actions, Sign in attempts. | Required |
| limit | The maximum number of events to fetch for the given event type. Default is 1000. | Optional |
| from_date | The date from which to get events. If not specified, events from the last minute will be fetched. | Optional |
| should_push_events | Set this argument to True in order to push events to Cortex XSIAM, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required |

#### Command Example

```!one-password-get-events event_type="Sign in attempts" limit=2 from_date="2024-12-12T12:00:00.000Z" should_push_events=False```

#### Context Output

There is no context output for this command.

#### Human Readable Output

>### Sign in attempts
>
>| account_uuid | category | client | country | location | session_uuid | target_user | timestamp | type | uuid |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>| H9T8ZQ6P4F3JY1VK7D2N5L7XQ2W | success | app_name: 1Password Browser Extension<br>app_version: 81055002<br>... | UK | country: UK<br>region: Scotland<br>city: Glasgow<br>... | YB7RPKX9V6N2DAG3T0ZQ8YHWY4C | uuid: LJ5T8WK9U8FQGZ2D1Q4V9RLP3S<br>name: Jenny Bee<br>email: userB@example.com<br>type: user | 2024-12-13T19:52:14.658476952Z | credentials_ok | NAFGMYS3LZBCZLX2MVRSWNXIHI |
>| B7N3W5E9Y6JHQ2V1KZ8M4P0QX5T | success | app_name: 1Password for Web<br>app_version: 1895<br>... | IL | country: IL<br>region: Gush Dan<br>city: Tel Aviv<br>... | C4XUJWF8N2Y1K9V3WZ7M5E6T0H | uuid: MNY8UJ6PZG5BVW9QH3A1K2X3CK<br>name: John Doe<br>email: userA@example.com<br>type: user | 2024-12-16T13:27:33.375466135Z | credentials_ok | QXZTBRJULQX5ZJWKRFG8YTP8EX |
