Palo Alto Networks Enterprise DLP discovers and protects company data across every data channel and repository. Integrated Enterprise DLP enables data protection and compliance everywhere without complexity.
This integration was integrated and tested with version 2.0 of Palo Alto Networks Enterprise DLP.

**Note**:  
This integration currently supports fetching DLP incidents from "NGFW" and "Prisma Access" channels only.

### Setup

Go to the `Settings` tab on the DLP web interface.
Choose `Alerts` on the left menu. Follow all the steps under `Setup Instructions`.
Make sure the toggle at the bottom is switched on.

## Configure Palo Alto Networks Enterprise DLP in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Default value is https://api.dlp.paloaltonetworks.com/v1/ | False |
| Authentication URL | Default value is https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token | False |
| Access Token | Access token generated in the Enterprise DLP UI | True |
| Refresh Token | Refresh token generated in the Enterprise DLP UI | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Maximum number of incidents per fetch | Default value is 50. | False |
| First fetch timestamp | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default value is 60 minutes. | False |
| DLP Regions | Possible values: `US` (United States), `EU` (European Union), `AP` (Asia-Pacific), `UK` (United Kingdom), `CA` (Canada), `AU` (Australia), `IN` (India), `JP` (Japan), `BR` (Brazil), `PAR` (Paris), `SUI` (Switzerland). | False |
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
| DLP.Report.DataPatternMatches.MatchedConfidenceLevel | String | The matched confidence level of the data pattern \(e.g., "high", "medium", "low"\). Only present for patterns that matched. |
| DLP.Report.DataProfiles.Name | String | The name of the data profile. |
| DLP.Report.DataProfiles.Id | Number | The ID of the data profile. |
| DLP.Report.DataProfiles.Version | Number | The version of the data profile. |
| DLP.Report.DataProfiles.IsTriggered | Boolean | Whether the data profile was triggered. |
| DLP.Report.DataProfiles.DataPatterns.Id | String | The data pattern ID within the profile. |
| DLP.Report.DataProfiles.DataPatterns.IsMatched | Boolean | Whether the data pattern matched. |
| DLP.Report.DataProfiles.DataPatterns.ConfidenceLevel | String | The confidence level configured for the pattern. |
| DLP.Report.DataProfiles.DataPatterns.OccurrenceCount | Number | The number of occurrences detected. |
| DLP.Report.DataProfiles.DataPatterns.OccurrenceOperatorType | String | The occurrence operator type \(e.g., "more_than_equal_to", "between"\). |
| DLP.Report.DataProfiles.DataPatterns.OccurrenceLow | Number | The low bound for "between" operator type. |
| DLP.Report.DataProfiles.DataPatterns.OccurrenceHigh | Number | The high bound for "between" operator type. |

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
Deprecated.  Reset the "last run" timestamp via the integration instance configuration window.

#### Base Command

`pan-dlp-reset-last-run`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

## Troubleshooting

In case specific DLP incidents are not appearing on the Cortex tenant, verify the following:

1. **DLP Regions Configuration**
   - Check the Strata Cloud Manager to confirm which regions generated the incidents.
   - **Note**: The *DLP Regions* dropdown menu shows all currently-supported regions.
   - Ensure all regions where incidents originated are selected from the dropdown menu.

2. **Strata Cloud Manager (SCM) Channel Support**
   - Verify the channel in SCM console under the incident details.
   - **Note**: Only incidents from the "NGFW" and "Prisma Access" SCM channels are supported.
   - Incidents from other channels, such as Endpoint DLP, will not be fetched by this integration.
