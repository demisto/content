
This integration was integrated and tested with version xx of Mimecast Event Collector

## Configure Mimecast Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Mimecast Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Base URL | True |
    | App Id | True |
    | Application key | True |
    | Access Key | True |
    | Secret Key | True |
    | The product name corresponding to the integration that originated the events | False |
    | The vendor name corresponding to the integration that originated the events | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, for example, 12 hours, 7 days, 3 months, 1 year) | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## General information 
This integration is collecting events from 2 end points. 
* ### audit events
    All events are fetched at once when activating the integration from **first fetch timestamp** until now.
    after that the fetch mechanism will call every 1 minute to update the audit events from mimecast
* ### siem logs 
    The logs will **always be fetched from 7 days ago**. Once the integration is activated the logs will 
    stream in batches of 350 logs per fetch.
    when all logs available are retrieved the fetch mechanism will call every 1 minute to update the siem logs from mimecast.  

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mimecast-get-events
***
Manual command to fetch events and display them.


#### Base Command

`mimecast-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required | 


#### Context Output

There is no context output for this command.