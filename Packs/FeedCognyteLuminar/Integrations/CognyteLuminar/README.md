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


#### Context Output

There is no context output for this command.
#### Command example
```!luminar-get-indicators limit="3"```
#### Context Example
```json
{
    "Luminar": {
        "Indicators": [
            {
                "Indicator Type": "File",
                "Indicator Value": "a35866ff36a7ec0a226b8f814f3642185742020e",
                "Malware Family": "SlayerRAT v0.4",
                "rawJSON": {
                    "created": "2016-02-15T00:00:00.000Z",
                    "created_by_ref": "identity--cd3843c0-8119-4ac0-9409-cec757123a6a",
                    "id": "indicator--88369314-3515-4c5c-a3e3-dba75e4ae964",
                    "indicator_types": [
                        "malicious-activity"
                    ],
                    "modified": "2016-02-15T00:00:00.000Z",
                    "name": "SlayerRAT v0.4",
                    "pattern": "[file:hashes.'SHA-1' = 'a35866ff36a7ec0a226b8f814f3642185742020e']",
                    "pattern_type": "stix",
                    "spec_version": "2.1",
                    "type": "indicator",
                    "valid_from": "2016-02-15T00:00:00.000Z"
                }
            },
            {
                "Indicator Type": "Domain",
                "Indicator Value": "xbodyyellow.top",
                "Malware Family": "Locky",
                "rawJSON": {
                    "created": "2016-02-22T00:00:00.000Z",
                    "created_by_ref": "identity--cd3843c0-8119-4ac0-9409-cec757123a6a",
                    "id": "indicator--0240fda0-1b77-4bde-86d8-eeb27203e4d7",
                    "indicator_types": [
                        "malicious-activity"
                    ],
                    "modified": "2016-02-22T00:00:00.000Z",
                    "name": "Locky",
                    "pattern": "[domain-name:value = 'xbodyyellow.top']",
                    "pattern_type": "stix",
                    "spec_version": "2.1",
                    "type": "indicator",
                    "valid_from": "2016-02-22T00:00:00.000Z"
                }
            },
            {
                "Indicator Type": "Email",
                "Indicator Value": "javamaker@inbox.ru",
                "Malware Family": "OilRig",
                "rawJSON": {
                    "created": "2016-10-10T00:00:00.000Z",
                    "created_by_ref": "identity--cd3843c0-8119-4ac0-9409-cec757123a6a",
                    "id": "indicator--a1ee47e7-fe49-4fae-8c20-7a14452c5da7",
                    "indicator_types": [
                        "malicious-activity"
                    ],
                    "modified": "2016-10-10T00:00:00.000Z",
                    "name": "OilRig",
                    "pattern": "[email-addr:value = 'javamaker@inbox.ru']",
                    "pattern_type": "stix",
                    "spec_version": "2.1",
                    "type": "indicator",
                    "valid_from": "2016-10-10T00:00:00.000Z"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators from Luminar
>|Indicator Type|Indicator Value|Malware Family|
>|---|---|---|
>| File | a35866ff36a7ec0a226b8f814f3642185742020e | SlayerRAT v0.4 |
>| Domain | xbodyyellow.top | Locky |
>| Email | javamaker@inbox.ru | OilRig |


### luminar-get-leaked-records
***
Gets Luminar Leaked Records


#### Base Command

`luminar-get-leaked-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of leaked records to return. Default is 50. | Optional | 


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
>|Indicator Type| Indicator Value |Credentials|
>|-----------------|---|---|
>| Account | a@a.com         | ###### |
>| Account | b@b.com         | ###### |
>| Account | c@c.com         | ###### |


### luminar-reset-fetch-indicators
***
WARNING: This command will reset your fetch history.


#### Base Command

`luminar-reset-fetch-indicators`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!luminar-reset-fetch-indicators```
#### Human Readable Output

>Fetch history deleted successfully