Amazon Web Services Guard Duty Service (gd) event collector integration for XSIAM.
This integration was integrated and tested with version xx of AWS - GuardDuty Event Collector

## Configure AWS - GuardDuty Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - GuardDuty Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | AWS Default Region |  | True |
    | Role Arn |  | False |
    | Role Session Name |  | False |
    | Role Session Duration |  | False |
    | Access Key |  | False |
    | Secret Key |  | False |
    | Password |  | False |
    | Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
    | Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | First fetch time interval |  | False |
    | Number of events to fetch per fetch. |  | False |
    | Guard Duty Severity level | The minimum severity of the events to fetch. \(inclusive\). | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | The product name corresponding to the integration that originated the events |  | False |
    | The vendor name corresponding to the integration that originated the events |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-gd-get-events
***
Manual command to fetch events and display them.


#### Base Command

`aws-gd-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in orfer to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 
| severity | The minimum severity of the events to fetch. (inclusive). Possible values are: Low, Medium, High. Default is Low. | Required | 
| collect_from | The date to start collecting the events from. | Optional | 
| limit | The maximum amount of events to return. | Optional | 


#### Context Output

There is no context output for this command.