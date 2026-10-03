Palo Alto Networks Enterprise DLP discovers and protects company data across every data channel and repository. Integrated Enterprise DLP enables data protection and compliance everywhere without complexity.
This integration was integrated and tested with version 2.0 of Palo Alto Networks Enterprise DLP.

**Note**:
Incidents are fetched from every control point the tenant can see. Use the *DLP Channels* parameter to narrow the fetch to specific control points.

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
| Fetch Lookback Window (minutes) | The number of minutes to look back during each fetch to capture late-indexed incidents. Default value is 0. | False |
| DLP Regions | The regions to fetch incidents from. When empty, incidents are fetched from every region the tenant can see. Possible values: `US` (United States), `EU` (European Union), `SG` (Singapore), `UK` (United Kingdom), `CA` (Canada), `AU` (Australia), `IN` (India), `JP` (Japan), `BR` (Brazil), `FR` (France), `CH` (Switzerland), `SA` (Saudi Arabia). | False |
| DLP Channels | The control points to fetch incidents from. Possible values: `NGFW`, `PRISMA_ACCESS`, `PRISMA_ACCESS_BROWSER`, `ENDPOINT_DLP`, `SAAS_API`, `EMAIL_DLP`. When empty, incidents are fetched from every channel. | False |
| DLP Severities | The severities to fetch. Possible values: `Critical`, `High`, `Medium`, `Low`, `Informational`. The severity is stored as a number, so the selected value is translated before the query is sent - `Critical` becomes `5` and `Informational` becomes `1`. When empty, incidents of every severity are fetched. | False |
| DLP Incident Statuses | The incident statuses to fetch. Possible values: `New`, `open`, `under_investigation`, `closed`. When empty, incidents of every status are fetched. | False |
| DLP Priorities | The priorities to fetch. Possible values: `P1`, `P2`, `P3`, `P4`, `P5`. When empty, incidents of every priority are fetched. | False |
| DLP Data Profile IDs | A comma-separated list of data profile IDs to fetch incidents for. These are numeric IDs, not profile names - a profile name matches nothing. When empty, incidents for every data profile are fetched. | False |
| DLP Data Pattern IDs | A comma-separated list of data pattern IDs to fetch incidents for. These are numeric IDs, not pattern names - a pattern name matches nothing. When empty, incidents for every data pattern are fetched. | False |
| DLP Incident Tags | A comma-separated list of incident tags to fetch. When empty, incidents are fetched regardless of their tags. | False |
| DLP Report IDs | A comma-separated list of report IDs to fetch incidents for. When empty, incidents are fetched regardless of their report ID. | False |
| DLP URL Domains | A comma-separated list of URL domains to fetch incidents for, for example "drive.google.com". When empty, incidents are fetched regardless of their URL. | False |
| DLP Assets | A comma-separated list of asset names to fetch incidents for, for example a file name. When empty, incidents are fetched regardless of their asset name. | False |
| DLP Actions | The actions taken on the incident to fetch. Possible values: `alert`, `block`, `allow`. When empty, incidents are fetched regardless of the action taken. | False |
| DLP Policy Types | The policy types to fetch. Possible values: `Data in Motion`, `Data at Rest`, `Peripheral Control`. When empty, incidents of every policy type are fetched. | False |
| DLP Sub Policy Types | A comma-separated list of sub policy types to fetch. When empty, incidents are fetched regardless of their sub policy type. | False |
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
| service_name | The DLP service that the report belongs to. Determines which backend the report is retrieved from. When empty, the request does not specify a service and the server retrieves the report from Prisma Access. Possible values are: ngfw, prisma-access, prisma-saas, prisma-access-browser, endpoint-dlp. | Optional |

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

#### Command example

```!pan-dlp-get-report report_id=3165792284 service_name=prisma-saas```

#### Human Readable Output

>### DLP Report for profile: Sample-Data-Profile
>
>|DataPatternName|ConfidenceFrequency|MatchedConfidenceLevel|
>|---|---|---|
>| National Id - US Social Security Number - SSN | Low: 30<br>Medium: 0<br>High: 30 | high |
>| Credit Card Number | Low: 30<br>Medium: 30<br>High: 30 | high |

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

1. **Incident Filter Configuration**
   - Every configured *DLP* filter parameter narrows the fetch, and the filters are combined with AND. An incident is fetched only if it matches all of them.
   - Leave a filter empty to stop it narrowing the fetch. Clearing every filter fetches all incidents the tenant can see.
   - Check the Strata Cloud Manager incident details to confirm the values the incidents actually carry, and make sure each configured filter includes them.
   - The free-text filters are matched exactly and are case-sensitive. *DLP Data Profile IDs* and *DLP Data Pattern IDs* take numeric IDs - a profile or pattern name matches nothing.

2. **DLP Regions Configuration**
   - Check the Strata Cloud Manager to confirm which regions generated the incidents.
   - **Note**: The *DLP Regions* dropdown menu shows all currently-supported regions.
   - Ensure all regions where incidents originated are selected from the dropdown menu.
