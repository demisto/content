CyberArk Identity logs event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 22.4 of CyberArk Identity Event Collector.

## Configure CyberArk Identity Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for CyberArk Identity Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description**                                                                 | **Required** |
    |---------------------------------------------------------------------------------| --- | --- |
    | Server URL | CyberArk Identity URL (https://{{tenant}}.my.idaptive.app).                     | True |
    | App ID | The application ID from where to fetch the logs.                                | True |
    | User name | The user name (e.g.`admin@example.com`).                                        | True |
    | Password | The password.                                                                   | True |
    | The product corresponding to the integration that originated the events | The name of the product to name the dataset after.                              | False        |
    | The vendor corresponding to the integration that originated the events | The name of the vendor to name the dataset after.                               | False        |
    | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 1 day, 3 months). Default is 3 days. | The period (in days) to retrieve events from, if no time is saved in the system | True |
    | The maximum number of events per fetch. Default is 100. | The amount of items to retrieve from CyberArk's API per request.                | True |
    | Trust any certificate (not secure) | When selected, certificates are not checked.                                    | False |
    | proxy | Use system proxy settings.                                                      | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSIAM Alerts War Room, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cyberarkidentity-get-events
***
Returns a list of events


#### Base Command

`cyberarkidentity-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in orfer to create events, otherwise the command will only display them. Possible values are: True, False. Default is False. | Required |
| limit | The maximum number of incidents per fetch. Default is 100. | Optional | 
| from | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 1 day, 3 months). Default is 3 days. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
`!cyberarkidentity-get-events should_push_events=false limit=10 from="3 days"`
#### Human Readable Output

>### CyberArkIdentity RedRock records
>|Auth Method|Directory Service Uuid|From IP Address|ID|Level|Normalized User|Request Device OS|Request Host Name|Request Is Mobile Device|Tenant|User Guid|When Logged|When Occurred|_ Table Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdef | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376432605)/ | /Date(1652376432605)/ | events |
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdeg | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376492682)/ | /Date(1652376492682)/ | events |
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdeh | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376552546)/ | /Date(1652376552546)/ | events |
