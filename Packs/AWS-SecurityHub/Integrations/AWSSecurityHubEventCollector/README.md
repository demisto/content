An XSIAM event collector for AWS Security Hub.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure AWS Security Hub Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| AWS Default Region |  | True |
| Role Arn |  | False |
| Access Key |  | False |
| Secret Key |  | False |
| First fetch time (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
| Role Session Name |  | False |
| Role Session Duration |  | False |
| Max events per fetch | The maximum number of events to retrieve for each event type \(up to 10000 events\). For more information about event types, see the help section. | False |
| Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

### aws-securityhub-get-events

***
Fetch events from AWS Security Hub.

#### Base Command

`aws-securityhub-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. | Optional | 