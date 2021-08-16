Alexa provides website ranking information that can be useful in determining if the domain in question has a strong web presence. V2
This integration was integrated and tested with Alexa Rank Indicator V2

## Configure Alexa Rank Indicator V2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Alexa Rank Indicator V2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Rank threshold for suspicious domain | For Alexa rank over this threshold, the domain will be marked as suspicious. | True |
    | Base API URL |  | True |
    | Rank threshold for top domains | For Alexa rank less than this threshold, the domain will be considered trusted and marked as good. | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Api Key |  | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### domain
***
Provides an Alexa ranking of the Domain in question.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain(s) to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The Domain being checked | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Alexa.Domain.Indicator | String | The Domain being checked | 
| Alexa.Domain.Name | String | The Domain being checked | 
| Alexa.Domain.Rank | String | Alexa rank as determined by Amazon | 


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

