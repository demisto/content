This is a feed integration for extracting indicators from ServiceNow.

## Configure ServiceNow Generic Feed in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The format should be https://company.service-now.com/ | True |
| Use OAuth Login | Select this checkbox if to use OAuth 2.0 authentication. See \(?\) for more information. | False |
| Use JWT Authentication | Select this checkbox to use JWT authentication. See \(?\) for more information. | False |
| Username / Client ID |  | True |
| Password / Client Secret |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | True |
| Indicator Verdict | Indicators from this integration instance will be marked with this verdict | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Feed Expiration Policy |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | The tag applied to the indicator when being forwarded into the TIM. | False |
| Query URL | The API route of the requested information in ServiceNow | True |
| Indicator Field | The field needed from the ServiceNow response which contains the indicator value | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### snow-get-indicators

***
Retrieve indicators from ServiceNow.

#### Base Command

`snow-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of indicators that can be returned. Default is 1. | Optional |

#### Context Output

There is no context output for this command.
