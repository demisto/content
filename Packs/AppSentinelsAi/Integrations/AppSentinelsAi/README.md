Appsentinels.ai offers a platform for collecting, analyzing, and managing security events to provide comprehensive application protection.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure AppSentinels.ai in Cortex

| **Parameter** | **Description**                                                   | **Required** |
| --- |-------------------------------------------------------------------| --- |
| Your server URL |                                                                   | True |
| User Key | The Client User key for connection with AppSentinels.ai.          | True |
| API Key | The Client API key for connection with AppSentinels.ai.           | True |
| Organization name | The organization name.                                            | True |
| Trust any certificate (not secure) |                                                                   | False |
| Use system proxy settings |                                                                   | False |
| Fetch events |                                                                   | False |
| Maximum number of audit logs per fetch | Maximum number of Audit Log entries to retrieve per fetch cycle. default value is 5000. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### appsentinels-get-events

***
Retrieves a list of events from the AppSentinels.ai instance.

#### Base Command

`appsentinels-get-events`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                      | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| should_push_events | Set this argument to true to create events, otherwise it only displays them. Possible values are: true, false. Default is false.                                                     | Required |
| limit | Returns no more than the specified number of events.                                                                                                                                 | Optional |
| first_fetch | The UTC date or relative timestamp from when to start fetching events. Supported formats: N minutes, N hours, N days, N weeks, N months, N years, yyyy-mm-dd, yyyy-mm-ddTHH:MM. | Optional |

#### Context Output

There is no context output for this command.
