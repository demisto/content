IBM Security Verify provides a secure and scalable solution for collecting and managing security events from IBM Security Verify, offering advanced threat detection and response capabilities for protecting identities, applications, and data.
This integration was integrated and tested with version xx of IBMSecurityVerifyEventCollector.

## Configure IBM Security Verify Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IBM Security Verify Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | For example: https://tenant.verify.ibm.com | True |
    | Client ID |  | True |
    | Client Secret |  | True |
    | The maximum number of events per fetch | The maximum is 50,000. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ibm-security-verify-get-events

***
Retrieves events from IBM Security Verify.

#### Base Command

`ibm-security-verify-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If set to 'True', the command will create events; otherwise, it will only display them. Possible values are: True, False. Default is False. | Optional | 
| limit | Maximum number of results to return. Default is 1000. | Optional | 
| last_id | The ID of the last event retrieved. Use together with `last_time` for pagination to get events after this ID. Example: 1234abcd-5678-90ef-1234-567890abcdef. | Optional | 
| last_time | The timestamp of the last event retrieved. Use together with `last_id` for pagination to get events after this time. Example: 1672531200000. | Optional | 
| sort_order | Order to sort events by: 'Desc' or 'Asc'. Possible values are: Desc, Asc. Default is Desc. | Optional | 

#### Context Output

There is no context output for this command.
