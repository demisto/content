Alexa provides website ranking information that can be used to help determine if a domain has a strong web presence.
This integration was integrated and tested with Alexa Rank Indicator V2.

##### New: Alexa Rank Indicator v2
- Use of the Alexa API rank.
- Domains that are not in the Alexa database, are considered "Unknown" instead of "Suspicious".
- If the domain doesn't exist, there is an error.
- Default values changed: 1000 for *Top Domain Threshold* and unspecified for *Suspicous Domain Threshold*.

## Configure Alexa Rank Indicator V2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Rank threshold for suspicious domain | If the domain's Alexa rank is over this threshold, the domain is marked as suspicious. If the rank is between the threshold for suspicious domains and top domains, the domain is marked as *unknown*. | True |
| Base API URL |  | True |
| Rank threshold for top domains | If the domain's Alexa rank is under this threshold, the domain is considered trusted and marked as good. If the rank is between the threshold for suspicious domains and top domains, the domain is marked as *unknown*. | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| API Key |  | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### domain
***
Provides the Alexa ranking of a domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain(s) to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain being checked. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Alexa.Domain.Indicator | String | The domain being checked. | 
| Alexa.Domain.Name | String | The domain being checked. | 
| Alexa.Domain.Rank | String | Alexa rank as determined by Amazon. | 


#### Command Example
```!domain domain="google.com,xsoar.com"

#### Context Example
```json
{
    "Alexa": {
        "Domain": [
            {
                "Indicator": "google.com",
                "Name": "google.com",
                "Rank": "1"
            },
            {
                "Indicator": "xsoar.com",
                "Name": "xsoar.com",
                "Rank": "Unknown"
            }
        ]
    },
    "DBotScore": [
        {
            "Indicator": "google.com",
            "Reliability": "A - Completely reliable",
            "Score": 0,
            "Type": "domain",
            "Vendor": "Alexa Rank Indicator V2"
        },
        {
            "Indicator": "xsoar.com",
            "Reliability": "A - Completely reliable",
            "Score": 2,
            "Type": "domain",
            "Vendor": "Alexa Rank Indicator V2"
        }
    ],
    "Domain": [
        {
            "Name": "google.com"
        },
        {
            "Name": "xsoar.com"
        }
    ]
}
```

#### Human Readable Output

>### Alexa Rank for xsoar.com
>|Domain|Alexa Rank|Reputation|
>|---|---|---|
>| xsoar.com |  | Suspicous |