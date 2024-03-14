Security Center is the foundation of our unified security portfolio. It lets you connect your security at your own pace, starting with a single core system. Even if you're only interested in upgrading your video surveillance or access control, taking the next step is easy.

## Configure Armis Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Genetec Security Center Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Username | Username &amp;amp; Password. | True |
    | Password |  | True |
    | Application ID |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Maximum number of events per fetch | Alerts and activity events. |  |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands Alert War Room in the CLI in XSIAM.
### genetec-security-center-get-events
***
Manual command to fetch events and display them.


#### Base Command

`genetec-security-center-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum amount of events to retrieve. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. | Required | 


#### Context Output

There is no context output for this command.