Palo Alto Networks Enterprise DLP discovers and protects company data across every data channel and repository. Integrated Enterprise DLP enables data protection and compliance everywhere without complexity.
This integration was integrated and tested with Palo Alto Networks Enterprise DLP
## Configure Palo Alto Networks Enterprise DLP on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks Enterprise DLP.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| access_token | Access Token | True |
| refresh_token | Refresh Token | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pan-dlp-get-report
***
Fetches a DLP report associated with the passed report ID.


#### Base Command

`pan-dlp-get-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | DLP report ID. | Required | 
| fetch_snippets | If "true" will include snippets with the reports. Default is "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DLP.Report.DataProfile | unknown | Data profile name. | 
| DLP.Report.DataPatternMatches.DataPatternName | unknown | DLP data pattern name. | 
| DLP.Report.DataPatternMatches.Detections | unknown | Snippets of DLP detections. | 
| DLP.Report.DataPatternMatches.HighConfidenceFrequency | unknown | Number of occurrences at High confidence. | 
| DLP.Report.DataPatternMatches.MediumConfidenceFrequency | unknown | Number of occurrences at Low confidence. | 
| DLP.Report.DataPatternMatches.LowConfidenceFrequency | unknown | Number of occurrences at Medium confidence. | 


#### Command Example
```!pan-dlp-get-report report_id=3165792284```

#### Context Example
```json
{
    "DLP": {
        "Reports": {
            "DataPatternMatches": [
                {
                    "DataPatternName": "Credit Card Number",
                    "Detections": null,
                    "HighConfidenceFrequency": 0,
                    "LowConfidenceFrequency": 1,
                    "MediumConfidenceFrequency": 1
                },
                {
                    "DataPatternName": "National Id - US Social Security Number - SSN",
                    "Detections": null,
                    "HighConfidenceFrequency": 11,
                    "LowConfidenceFrequency": 15,
                    "MediumConfidenceFrequency": 0
                },
                {
                    "DataPatternName": "Passport - US",
                    "Detections": null,
                    "HighConfidenceFrequency": 4,
                    "LowConfidenceFrequency": 6,
                    "MediumConfidenceFrequency": 0
                },
                {
                    "DataPatternName": "Secret Key - AWS Access Key ID",
                    "Detections": null,
                    "HighConfidenceFrequency": 2,
                    "LowConfidenceFrequency": 2,
                    "MediumConfidenceFrequency": 0
                },
                {
                    "DataPatternName": "Tax Id - US - TIN",
                    "Detections": null,
                    "HighConfidenceFrequency": 0,
                    "LowConfidenceFrequency": 15,
                    "MediumConfidenceFrequency": 0
                }
            ],
            "DataProfile": "Sensitive-File-Upload"
        }
    }
}
```

#### Human Readable Output

>### DLP Report for profile: Sensitive-File-Upload
>|DataPatternName|ConfidenceFrequency|
>|---|---|
>| Credit Card Number | Low: 1<br/>Medium: 1<br/>High: 0 |
>| National Id - US Social Security Number - SSN | Low: 15<br/>Medium: 0<br/>High: 11 |
>| Passport - US | Low: 6<br/>Medium: 0<br/>High: 4 |
>| Secret Key - AWS Access Key ID | Low: 2<br/>Medium: 0<br/>High: 2 |
>| Tax Id - US - TIN | Low: 15<br/>Medium: 0<br/>High: 0 |

