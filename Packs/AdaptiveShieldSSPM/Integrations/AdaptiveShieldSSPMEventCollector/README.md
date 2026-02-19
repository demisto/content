Adaptive Shield SSPM fetches security check events from Adaptive Shield and sends them to Cortex XSIAM.

## Configure Adaptive Shield SSPM in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Account ID | The Adaptive Shield account ID. Can be retrieved from the List Accounts endpoint or from your user settings in the Adaptive Shield dashboard \(API tab\). | True |
| API Key |  | True |
| Fetch events |  | False |
| The maximum number of Security Checks per fetch | The maximum number of Security Checks per fetch. The default is 5000. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Configuration steps

A valid API key is required to send any request.

**Generate API Key**

An API key is required for every request sent to Adaptive Shield's API.

1. In your Adaptive Shield dashboard navigate to your user profile
2. Click the API tab
3. Click "Generate a new key"
4. Set a key name, and click "Create"

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### adaptive-shield-sspm-get-events

***
Fetches security check events from Adaptive Shield. Use with caution during development or debugging; this command may trigger event duplication or exceed API request limits.

#### Base Command

`adaptive-shield-sspm-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set to True to create events; otherwise, the command only displays the events. Possible values are: true, false. Default is false. | Required |
| limit | The maximum number of security checks to return. Default is 10. | Optional |

#### Context Output

There is no context output for this command.
