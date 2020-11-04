Palo Alto Networks Enterprise DLP discovers and protect company data across every data channel and repository. Integrated Enterprise DLP enables data protection and compliance everywhere without complexity.
This integration was integrated and tested with version xx of Palo Alto Networks Enterprise DLP
## Configure Palo Alto Networks Enterprise DLP on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks Enterprise DLP.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| access_token | Access Token | True |
| refresh_token | Refresh Token | True |
| longRunning | Long running instance | False |
| incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-dlp-report
***
 


#### Base Command

`get-dlp-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | DLP Report ID | Required | 
| fetch_snippets | Provide snippets in the reports | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DLP.Report.DataProfile | unknown | Data Profile Name | 
| DLP.Report.DataPatternMatches | unknown | Data Pattern Matches in DLP Report | 


#### Command Example
```!get-dlp-report report_id=3165792284```

#### Context Example
```json
{
    "DLP": {
        "Reports": {
            "DataPatternMatches": [
                {
                    "Data Pattern Name": "Credit Card Number",
                    "Detections": null,
                    "High Confidence Frequency": 0,
                    "Low Confidence Frequency": 1,
                    "Medium Confidence Frequency": 1
                },
                {
                    "Data Pattern Name": "National Id - US Social Security Number - SSN",
                    "Detections": null,
                    "High Confidence Frequency": 11,
                    "Low Confidence Frequency": 15,
                    "Medium Confidence Frequency": 0
                },
                {
                    "Data Pattern Name": "Passport - US",
                    "Detections": null,
                    "High Confidence Frequency": 4,
                    "Low Confidence Frequency": 6,
                    "Medium Confidence Frequency": 0
                },
                {
                    "Data Pattern Name": "Secret Key - AWS Access Key ID",
                    "Detections": null,
                    "High Confidence Frequency": 2,
                    "Low Confidence Frequency": 2,
                    "Medium Confidence Frequency": 0
                },
                {
                    "Data Pattern Name": "Tax Id - US - TIN",
                    "Detections": null,
                    "High Confidence Frequency": 0,
                    "Low Confidence Frequency": 15,
                    "Medium Confidence Frequency": 0
                }
            ],
            "Data_Profile": "Sensitive-File-Upload"
        }
    }
}
```

#### Human Readable Output

>### DLP Report for profile: Sensitive-File-Upload
>|Data Pattern Name|Confidence Frequency|
>|---|---|
>| Credit Card Number | Low: 1<br/>Medium: 1<br/>High: 0 |
>| National Id - US Social Security Number - SSN | Low: 15<br/>Medium: 0<br/>High: 11 |
>| Passport - US | Low: 6<br/>Medium: 0<br/>High: 4 |
>| Secret Key - AWS Access Key ID | Low: 2<br/>Medium: 0<br/>High: 2 |
>| Tax Id - US - TIN | Low: 15<br/>Medium: 0<br/>High: 0 |


### test-module
***
For testing connectivity


#### Base Command

`test-module`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


