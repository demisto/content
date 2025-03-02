Apigee is Google Cloud's native API management platform that can be used to build, manage, and secure APIs — for any use case, environment, or scale. Apigee offers high performance API proxies to create a consistent, reliable interface for your backend services. The proxy layer gives you granular control over security, rate limiting, quotas, analytics, and more for all of your services. Apigee supports REST, gRPC, SOAP, and GraphQL, providing the flexibility to implement any API architectural style.
This integration was integrated and tested with version xx of Google Apigee Event Collector.

## Configure Google Apigee in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Client ID | True |
| Password | True |
| Organization Name | True |
| Zone | False |
| The maximum number of Audit Logs per fetch | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### google-apigee-get-events

***
Gets logs from Google Apigee.

#### Base Command

`google-apigee-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | The number of events to return. | Optional | 
| from_date | Date from which to get events. | Optional | 

#### Context Output

There is no context output for this command.
