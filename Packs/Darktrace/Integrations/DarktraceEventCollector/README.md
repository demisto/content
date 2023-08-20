Use this integration to fetch a list of model breaches, filtered by the specified parameters. This is important for organizations that wish to integrate Darktrace programmatically into their SOC environment.
The integration was integrated and tested with version v5.2 API of Darktrace.
## Configure Darktrace Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automations & Feed Integrations**. 
2. Search for Darktrace Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. <https://example.cloud.darktrace.com>) | REST API Endpoint of Darktrace server. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Public API Token | Public token obtained by creating an API token pair on the /config configuration page. | True |
    | Private API Token | Private token obtained by creating an API token pair on the /config configuration page. | True |
    | Max events per fetch | Maximum number of Darktrace model breaches to fetch at a time. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | Time to start fetching the first incidents. Limited to 1 Year.| False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### darktrace-get-events

***
Gets events from Darktrace Event Collector.

#### Base Command

`darktrace-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of events to return. Default is 10. | Optional | 
| start_time | The start time by which to filter events. Date format will be the same as in the first_fetch parameter. | Optional | 
| end_time | The end time by which to filter events. | Optional | 
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 

#### Context Output

There is no context output for this command.
