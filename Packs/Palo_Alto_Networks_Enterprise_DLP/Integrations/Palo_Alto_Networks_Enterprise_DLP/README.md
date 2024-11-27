Palo Alto Networks Enterprise DLP discovers and protects company data across every data channel and repository. Integrated Enterprise DLP enables data protection and compliance everywhere without complexity.
This integration was integrated and tested with version 2.0 of Palo Alto Networks Enterprise DLP

### Setup
Go to the `Settings` tab on the DLP web interface. 
Choose `Alerts` on the left menu. Follow all the steps under `Setup Instructions`.
Make sure the toggle at the bottom is switched on.

## Configure Palo Alto Networks Enterprise DLP in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Access Token | Access token generated in the Enterprise DLP UI | True |
| Refresh Token | Refresh token generated in the Enterprise DLP UI | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Long running instance |  | False |
| DLP Regions |  | False |
| Data profiles to allow exemption | A comma-separated list of data profile names to request an exemption. Use "\*" to allow everything. | False |
| Bot Message | The message to send to the user to ask for feedback. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pan-dlp-get-report
***
Fetches DLP reports associated with a report ID.


#### Base Command

`pan-dlp-get-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | DLP report ID. | Required | 
| fetch_snippets | If True, includes snippets with the reports. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DLP.Report.DataProfile | unknown | The data profile name. | 
| DLP.Report.DataPatternMatches.DataPatternName | unknown | The DLP data pattern name. | 
| DLP.Report.DataPatternMatches.Detections | unknown | The DLP detection snippets. | 
| DLP.Report.DataPatternMatches.HighConfidenceFrequency | unknown | The number of high confidence occurrences. | 
| DLP.Report.DataPatternMatches.MediumConfidenceFrequency | unknown | The number of medium confidence occurrences. | 
| DLP.Report.DataPatternMatches.LowConfidenceFrequency | unknown | The number of low confidence occurrences. | 

### pan-dlp-update-incident
***
Updates a DLP incident with user feedback.


#### Base Command

`pan-dlp-update-incident`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                           | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| incident_id | The ID of the incident to update.                                                                                                                                                                                         | Required | 
| feedback | The user feedback. Possible values are: PENDING_RESPONSE, CONFIRMED_SENSITIVE, CONFIRMED_FALSE_POSITIVE, EXCEPTION_REQUESTED, EXCEPTION_GRANTED, EXCEPTION_NOT_REQUESTED, OPERATIONAL_ERROR, SEND_NOTIFICATION_FAILURE, EXCEPTION_DENIED. | Required | 
| user_id | The ID of the user the feedback is collected from.                                                                                                                                                                        | Required | 
| region | The region where the incident originated.                                                                                                                                                                                 | Optional | 
| report_id | The DLP report ID, needed only for granting exemptions.                                                                                                                                                                   | Optional | 
| dlp_channel | The DLP channel, needed only for granting exemptions.                                                                                                                                                                     | Optional | 
| error_details | Error details if status is SEND_NOTIFICATION_FAILURE.                                                                                                                                                                     | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DLP.IncidentUpdate.success | boolean | Whether the update was successful. | 
| DLP.IncidentUpdate.exemption_duration | number | The exemption duration, only available for "EXCEPTION_GRANTED". | 

### pan-dlp-exemption-eligible
***
Determines whether exemption can be granted on incidents from a certain data profile.


#### Base Command

`pan-dlp-exemption-eligible`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data_profile | The name of the data profile. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DLP.exemption.eligible | boolean | Whether the data profile is eligible for exemption. | 

### pan-dlp-slack-message
***
Gets the Slack bot message to send to the user for gathering feedback.


#### Base Command

`pan-dlp-slack-message`
#### Input

| **Argument Name** | **Description**                                          | **Required** |
| --- |----------------------------------------------------------| --- |
| user | The name of the user that receives this message.         | Required | 
| file_name | The name of the file that triggered the incident.        | Required | 
| data_profile_name | The data profile name associated with the incident.      | Required | 
| snippets | The snippets of the violation.                           | Optional | 
| app_name | The name of the application that performed the activity. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DLP.slack_message | string | The Slack bot message. | 

### pan-dlp-reset-last-run
***
Resets the fetch incidents last run value, which resets the fetch to its initial fetch state.


#### Base Command

`pan-dlp-reset-last-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.