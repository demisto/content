Okta Advanced Server Access integration for Cortex XSIAM.

## Configure Okta ASA in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://app.scaleft.com) |  | True |
| API Key ID | The API Key ID to use for connection. | True |
| API Key Secret | The API Key Secret to use for connection. | True |
| Team Name | A named group of users who can authenticate with Okta. | True |
| The maximum number of audit events per fetch. |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### okta-asa-get-events

***
Gets events from Okta ASA.

#### Base Command

`okta-asa-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required |
| limit | Maximum results to return. Default is 50. | Optional |

#### Context Output

There is no context output for this command.
