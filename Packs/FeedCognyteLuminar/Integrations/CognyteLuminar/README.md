Cognyte is a global leader in security analytics software that empowers governments and enterprises with Actionable
Intelligence for a safer world. Our open software fuses, analyzes and visualizes disparate data sets at scale to help
security organizations find the needles in the haystacks. Over 1,000 government and enterprise customers in more than
100 countries rely on Cognyte’s solutions to accelerate security investigations and connect the dots to successfully
identify, neutralize, and prevent threats to national security, business continuity and cyber security.

Luminar is an asset-based cybersecurity intelligence platform that empowers enterprise organizations to build and
maintain a proactive threat intelligence operation that enables to anticipate and mitigate cyber threats, reduce risk
and enhance security resilience. Luminar enables security teams to define a customized, dynamic monitoring plan to
uncover malicious activity in its earliest stages on all layers of the Web.

This connector allows integration of intelligence-based IOC data and customer-related leaked records identified by Luminar.

## Configure Luminar IOCs & leaked credentials in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Luminar Base URL | Luminar Base URL | True |
| Luminar API Account ID | Luminar API Account ID | True |
| Luminar API Client ID | Luminar API Client ID | True |
| Luminar API Client Secret | Luminar API Secret | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\) | False |
| Use system proxy settings | Use system proxy settings | False |
| Fetch indicators | Fetch indicators | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Feed Expiration Policy | Feed Expiration Policy | False |
| Feed Fetch Interval | Feed Fetch Interval | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### luminar-get-indicators

***
Gets Luminar Indicators

#### Base Command

`luminar-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 50. | Optional |
| fetch_date | Start date/time (UTC) to begin fetching records. Handles various formats including relative time expressions like '3 days ago', '1 hour ago', and standard date/time formats. | Optional |

#### Context Output

There is no context output for this command.

### luminar-get-leaked-records

***
Gets Luminar Leaked Records

#### Base Command

`luminar-get-leaked-records`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of leaked records to return. Default is 50. | Optional |
| fetch_date | Start date/time (UTC) to begin fetching records. Handles various formats including relative time expressions like '3 days ago', '1 hour ago', and standard date/time formats. | Optional |

#### Context Output

There is no context output for this command.

#### Command example

```!luminar-get-leaked-records limit="3"```

#### Context Example

```json
{
    "Luminar": {
        "Leaked_Credentials": [
            {
                "Credentials": "######",
                "Indicator Type": "Account",
                "Indicator Value": "a@a.com",
                "rawJSON": {
                    "account_login": "a@a.com",
                    "credential": "######",
                    "display_name": "a@a.com",
                    "id": "user-account--e4af982e-4673-4795-94d6-17b5ef96f8ae",
                    "spec_version": "2.1",
                    "type": "user-account"
                }
            },
            {
                "Credentials": "######",
                "Indicator Type": "Account",
                "Indicator Value": "b@b.com",
                "rawJSON": {
                    "account_login": "b@b.com",
                    "credential": "######",
                    "display_name": "b@b.com",
                    "id": "user-account--b8fc71bf-3542-4fcb-a0c7-70dc5e7366e8",
                    "spec_version": "2.1",
                    "type": "user-account"
                }
            },
            {
                "Credentials": "######",
                "Indicator Type": "Account",
                "Indicator Value": "c@c.com",
                "rawJSON": {
                    "account_login": "c@c.com",
                    "credential": "######",
                    "display_name": "c@c.com",
                    "id": "user-account--885ee892-320c-4e62-8161-a999d2df086a",
                    "spec_version": "2.1",
                    "type": "user-account"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Leaked Credentials from Luminar
>
>|Indicator Type| Indicator Value |Credentials|
>|-----------------|---|---|
>| Account | a@a.com         | ###### |
>| Account | b@b.com         | ###### |
>| Account | c@c.com         | ###### |

### luminar-reset-fetch-indicators

### luminar-get-leaked-records

***
Gets Luminar Leaked Records

#### Base Command

`luminar-get-leaked-records`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of leaked records to return. Default is 50. | Optional |
| fetch_date | Start date/time (UTC) to begin fetching records. Handles various formats including relative time expressions like '3 days ago', '1 hour ago', and standard date/time formats. | Optional |

#### Context Output

There is no context output for this command.
