CyberArk logs event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 22.4 of CyberArk Event Collector.

## Configure CyberArk Event Collector on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for CyberArk Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | App ID |  | True |
    | User name | The user name (e.g.`admin@example.com`). | True |
    | Password |  | True |
    | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 1 day, 3 months). Default is 3 days. |  | True |
    | The maximum number of events per fetch. Default is 100. |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSIAM Alerts War Room, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### CyberArk-get-events
***
Returns a list of events


#### Base Command

`CyberArk-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of incidents per fetch. Default is 100. | Optional | 
| from | First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 1 day, 3 months). Default is 3 days. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
`!CyberArk-get-events limit=10 from="3 days"`
#### Human Readable Output

>### CyberArkIdentity RedRock records
>|Auth Method|Directory Service Uuid|From IP Address|ID|Level|Normalized User|Request Device OS|Request Host Name|Request Is Mobile Device|Tenant|User Guid|When Logged|When Occurred|_ Table Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdef | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376432605)/ | /Date(1652376432605)/ | events |
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdeg | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376492682)/ | /Date(1652376492682)/ | events |
>| None | 123456abcdef.123456.abcdef | 1.1.1.1 | 123456abcdef.123456.abcdeh | Info | admin@example.com.11 | Unknown | 1.1.1.1 | false | AAM4730 | 123456abcdef.123456.abcdef | /Date(1652376552546)/ | /Date(1652376552546)/ | events |
