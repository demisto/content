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

### pan-dlp-update-incident
***
Updates a DLP incident with user feedback
#### Base Command

`pan-dlp-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | DLP Incident ID. | Required | 
| user_id | The user whose upload triggered the DLP incident | Required |
| feedback | User's feedback to the incident | Required |
| region | The region in which the DLP incident was generated | Required | 
| report_id | The DLP report id for the incident | Optional |
| dlp_channel | The DLP channel in which the incident originated from | Optional |
#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
|  DLP.IncidentUpdate.success | bool | Whether or not the update is successful. | 
|  DLP.IncidentUpdate.exemption_duration | bool | The effective duration for the exemption in hours |

### pan-dlp-exemption-eligible
*** 
Check if a violation from a DLP data profile can be exempted
#### Base Command

`pan-dlp-exemption-eligible`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data_profile_name | DLP data profile name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
|  DLP.exemption.eligible | bool | Whether or not violations can be exempted for this data profile. | 

### pan-dlp-slack-message
***
Retrieve the customized Slack bot message from the DLP integration instance
#### Base Command

`pan-dlp-slack-message`

#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | the user's name used for greeting in the message | Required |
| app_name | the name of the Cloud app that the user tried to upload the file to | Required |
| file_name | The file that triggered the incident. | Required | 
| data_profile_name | DLP data profile name. | Required |
| snippets | The violation snippets. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
|  DLP.slack_message | string | The slack message  |


### pan-dlp-reset-last-run
***
Resets the fetch incidents last run value, which resets the fetch to its initial fetch state. 
**Please Note**: It is recommended to *disable* and then *enable* the DLP instance for the reset to take effect immediately.

#### Base Command

`pan-dlp-reset-last-run`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!pan-dlp-reset-last-run```

#### Human Readable Output

>fetch-incidents was reset successfully.



