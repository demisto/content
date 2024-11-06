IBM Security Verify provides a secure and scalable solution for collecting and managing security events from IBM Security Verify, offering advanced threat detection and response capabilities for protecting identities, applications, and data.


## Set up the Third Party System
To obtain the **Client ID** and **Client Secret**, follow these steps:

1. Log in to the IBM Security Verify UI.  
2. Click the profile icon located at the top right corner of the interface.
3. Select **Switch to admin** to access administrative settings.
4. Navigate to **Security** > **API Access**.  
5. Click **Add API Client** to generate the necessary credentials.
6. After clicking **Add API Client**, make sure to assign the following permissions to the API client:
   - **Manage reports**
   - **Read reports**

- ![Creating an API Client](https://github.com/demisto/content-assets/raw/master/Assets/IBMSecurityVerify/Creating_an_API_Client.gif)

## Configure IBM Security Verify on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**.
2. Search for IBM Security Verify.
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

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
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
