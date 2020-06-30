TruSTAR is an Intelligence Management Platform that helps you operationalize data across tools and teams, helping you prioritize investigations and accelerate incident response.
This integration was integrated and tested with version xx of TruSTAR v2
## Configure TruSTAR v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for TruSTAR v2.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g. https://api.trustar.co\) | True |
| station | Station URL \(e.g. https://station.trustar.co\) |  |
| key | TruSTAR API Key | True |
| secret | TruSTAR API Secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### trustar-search-indicators
***
Searches for all indicators that contain the given search term.


#### Base Command

`trustar-search-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | The term to search for (e.g. covid-19) | Optional | 
| enclave_ids | Comma-separated list of enclave ids; only indicators found in reports from these enclaves will be returned (defaults to all of user’s enclaves). Defaults is all enclaves the user has READ access to. | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Indicators.indicatorType | string | Indicator type | 
| TruSTAR.Indicators.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-get-enclaves
***
Returns the list of all enclaves that the user has access to, as well as whether they can read, create, and update reports in that enclave.


#### Base Command

`trustar-get-enclaves`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Enclaves.id | string | Enclave type | 
| TruSTAR.Enclaves.name | string | Enclave name | 
| TruSTAR.Enclaves.type | string | Enclave type | 
| TruSTAR.Enclaves.create | Bool | True if I have create permissions on enclave | 
| TruSTAR.Enclaves.update | Bool | True if I have update permissions on enclave | 
| TruSTAR.Enclaves.read | Bool | True if I have read permissions on enclave | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-related-indicators
***
Finds all reports that contain any of the given indicators and returns correlated indicators from those reports.


#### Base Command

`trustar-related-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc. | Required | 
| enclave_ids | Comma-separated list of enclave IDs; only indicators found in reports from these enclaves will be returned (defaults to all of user’s enclaves). Defaults is all enclaves the user has READ access to. | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Indicators.indicatorType | string | Indicator type | 
| TruSTAR.Indicators.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-trending-indicators
***
Find indicators that are trending in the community.


#### Base Command

`trustar-trending-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | The types of indicators to be returned. If other, then all indicator types except for CVE and MALWARE will be returned. | Optional | 
| days_back | The number of days back to count correlations for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Indicators.correlationCount | Number | Indicator correlation count | 
| TruSTAR.Indicators.indicatorType | string | Indicator type | 
| TruSTAR.Indicators.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-indicators-metadata
***
Provide metadata associated with a list of indicators, including value, indicatorType, noteCount, sightings, lastSeen, enclaveIds, and tags. The metadata is determined based on the enclaves the user making the request has READ access to.


#### Base Command

`trustar-indicators-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc. | Required | 
| enclave_ids | a list of enclave IDs to restrict to. By default, uses all of the user’s enclaves. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.IndicatorsMetadata.notes | string | Indicator notes | 
| TruSTAR.IndicatorsMetadata.indicatorType | string | Indicator type | 
| TruSTAR.IndicatorsMetadata.firstSeen | Date | Indicator first seen value | 
| TruSTAR.IndicatorsMetadata.correlationCount | Number | Indicator correlation count | 
| TruSTAR.IndicatorsMetadata.value | string | Indicator value | 
| TruSTAR.IndicatorsMetadata.lastSeen | Date | Indicator last seen value | 
| TruSTAR.IndicatorsMetadata.tags | string | Indicator tags | 
| TruSTAR.IndicatorsMetadata.enclaveIds | string | Enclave IDs where indicator is present | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-indicator-summaries
***
Provides structured summaries about indicators, which are derived from intelligence sources on the TruSTAR Marketplace.


#### Base Command

`trustar-indicator-summaries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| values | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc. | Required | 
| enclave_ids | The enclaves to search for indicator summaries in. These should be enclaves containing data from sources on the TruSTAR Marketplace. | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.IndicatorSummaries.severityLevel | string | Indicator severity level | 
| TruSTAR.IndicatorSummaries.reportId | string | Indicator report ID | 
| TruSTAR.IndicatorSummaries.value | string | Indicator value | 
| TruSTAR.IndicatorSummaries.score.name | string | Indicator score name | 
| TruSTAR.IndicatorSummaries.score.value | string | Indicator score value | 
| TruSTAR.IndicatorSummaries.attributes | String | Indicator attributes | 
| TruSTAR.IndicatorSummaries.enclaveId | string | Indicator enclave ID | 
| TruSTAR.IndicatorSummaries.type | string | Indicator type | 
| TruSTAR.IndicatorSummaries.source.key | string | Indicator source key | 
| TruSTAR.IndicatorSummaries.source.name | string | Indicator source name | 
| TruSTAR.IndicatorSummaries.updated | string | Indicator last update value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-get-whitelisted-indicators
***
Gets a list of indicators that the user’s company has whitelisted.


#### Base Command

`trustar-get-whitelisted-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.WhitelistedIndicators.indicatorType | string | File MD5 | 
| TruSTAR.WhitelistedIndicators.value | string | File SHA1 | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-get-reports
***
Returns incident reports matching the specified filters. All parameters are optional: if nothing is specified, the latest 25 reports accessible by the user will be returned (matching the view the user would have by logging into Station).


#### Base Command

`trustar-get-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_time | Start of time window (format is YY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00). Based on updated time, and not created time. Default is 1 day ago. | Optional | 
| to_time | End of time window (format is YY-MM-DD HH:MM:SS, i.e. 2018-01-01 10:30:00). Based on updated time, and not created time. Default is current time. | Optional | 
| distribution_type | Whether to search for reports in the community, or only in enclaves | Optional | 
| enclave_ids | Comma separated list of enclave ids to search for reports in. Even if distributionType is COMMUNITY, these enclaves will still be searched as well. Default is All enclaves the user has READ access to. | Optional | 
| tags | a list of names of tags to filter by; only reports containing ALL of these tags will be returned | Optional | 
| excluded_tags | reports containing ANY of these tags will be excluded from the results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.title | string | Title of the report | 
| TruSTAR.Report.reportBody | string | Body of the report | 
| TruSTAR.Report.id | string | ID of the report | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-get-indicators-for-report
***
Return a list of indicators extracted from a report.


#### Base Command

`trustar-get-indicators-for-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | the ID of the report to get the indicators from | Required | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Indicators.type | string | Indicator type | 
| TruSTAR.Indicators.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-move-report
***
Move a report from one enclave to another.


#### Base Command

`trustar-move-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | the ID of the report you want to move | Required | 
| dest-enclave-id | the ID of the destination enclave | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-copy-report
***
Copies a report from one enclave to another.


#### Base Command

`trustar-copy-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | the ID of the report you want to move | Required | 
| dest_enclave_id | the ID of the destination enclave | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-submit-report
***
Submit a new incident report, and receive the ID it has been assigned in TruSTAR’s system.


#### Base Command

`trustar-submit-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Title of the report | Required | 
| report_body | Text content of report | Required | 
| enclave_ids | CSV of TruSTAR-generated enclave ids. Use the enclave ID, NOT the enclave name. Mandatory if the distribution type is ENCLAVE. | Optional | 
| distribution_type | Distribution type of the report | Optional | 
| external_url | URL for the external report that this originated from, if one exists. Limit 500 alphanumeric characters. Must be unique across all reports for a given company. | Optional | 
| time_began | ISO-8601 formatted incident time with timezone, e.g. 2016-09-22T11:38:35+00:00. Default is current time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.title | string | Title of the report | 
| TruSTAR.Report.reportBody | string | Body of the report | 
| TruSTAR.Report.id | string | ID of the report | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-delete-report
***
Deletes a report as specified by given id (id can be TruSTAR report id or external id).


#### Base Command

`trustar-delete-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Finds a report by its internal or external id. | Required | 
| id_type | Type of report ID | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-correlated-reports
***
Returns a list of all reports that contain any of the provided indicator values.


#### Base Command

`trustar-correlated-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc. | Required | 
| enclave-ids | Comma-separated list of enclave ids; only indicators found in reports from these enclaves will be returned (defaults to all of user’s enclaves). Defaults is all enclaves the user has READ access to. | Optional | 
| limit | Limit of results to return. Max value possible is 1000. | Optional | 
| distribution_type | Distribution type of the report | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-report-details
***
Finds a report by its ID and returns the report details.


#### Base Command

`trustar-report-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Finds a report by its internal or external id. | Required | 
| id_type | Type of report ID | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.title | string | Title of the report | 
| TruSTAR.Report.reportBody | string | Body of the report | 
| TruSTAR.Report.id | string | ID of the report | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-update-report
***
Update the report with the specified ID. Either the internal TruSTAR report ID or an external tracking ID can be used. Only the fields passed will be updated. All others will be left unchanged.


#### Base Command

`trustar-update-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | TruSTAR report id or external tracking id. | Required | 
| title | Title of the report | Optional | 
| report-body | Text content of report | Optional | 
| enclave_ids | CSV of TruSTAR-generated enclave ids. Use the enclave ID, NOT the enclave name. Mandatory if the distribution type is ENCLAVE. | Optional | 
| external_url | URL for the external report that this originated from, if one exists. Limit 500 alphanumeric characters. Must be unique across all reports for a given company. | Optional | 
| distribution_type | Distribution type of the report | Optional | 
| time_began | ISO-8601 formatted incident time with timezone, e.g. 2016-09-22T11:38:35+00:00. Default is current time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.title | string | Title of the report | 
| TruSTAR.Report.reportBody | string | Body of the report | 
| TruSTAR.Report.id | string | ID of the report | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-search-reports
***
Searches for all reports that contain the given search term.


#### Base Command

`trustar-search-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_term | The term to search for (e.g. covid-19) If empty, no search term will be applied. Otherwise, must be at least 3 characters. | Optional | 
| enclave_ids | Comma-separated list of enclave ids; only indicators found in reports from these enclaves will be returned (defaults to all of user’s enclaves) | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.Report.id | string | ID of the report | 
| TruSTAR.Report.title | string | Report Title | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-add-to-whitelist
***
Whitelist a list of indicator values for the user’s company.


#### Base Command

`trustar-add-to-whitelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicators | CSV of indicators to whitelist, i.e. evil.com,101.43.52.224 | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-remove-from-whitelist
***
Delete an indicator from the user’s company whitelist.


#### Base Command

`trustar-remove-from-whitelist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | The value of the indicator to delete. | Required | 
| indicator_type | The type of the indicator to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-get-phishing-submissions
***
Fetches all phishing submissions that fit the given criteria


#### Base Command

`trustar-get-phishing-submissions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| priority_event_score | List of email submissions scores to restrict the query. Possible values are -1, 0, 1, 2, 3. | Optional | 
| from_time | Start of time window (defaults to 24 hours ago) (YYYY-MM-DD HH:MM:SS) | Optional | 
| to_time | End of time window (defaults to current time) (YYYY-MM-DD HH:MM:SS) | Optional | 
| status | A list of triage statuses for submissions (UNRESOLVED,CONFIRMED,IGNORED); only email submissions marked with at least one of these statuses will be returned | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.PhishingSubmission.submissionId | string | The submission ID | 
| TruSTAR.PhishingSubmission.title | string | Submission title | 
| TruSTAR.PhishingSubmission.normalizedTriageScore | number | Submission triage score | 
| TruSTAR.PhishingSubmission.context.indicatorType | string | Indicator type | 
| TruSTAR.PhishingSubmission.context.sourceKey | string | Indicator source | 
| TruSTAR.PhishingSubmission.context.normalizedSourceScore | number | Indicator score | 
| TruSTAR.PhishingSubmission.context.originalIndicatorScore.name | string | Original Indicator score name | 
| TruSTAR.PhishingSubmission.context.originalIndicatorScore.value | string | Original Indicator score value | 


#### Command Example
``` ```

#### Human Readable Output



### trustar-set-triage-status
***
Marks a phishing email submission with one of the phishing namespace tags


#### Base Command

`trustar-set-triage-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| submission_id | ID of the email submission | Required | 
| status | Submission status | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-get-phishing-indicators
***
Get phishing indicators that match the given criteria.


#### Base Command

`trustar-get-phishing-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| normalized_indicator_score | List of Intel scores to restrict the query. Possible values are -1, 0, 1, 2, 3. | Optional | 
| priority_event_score | List of email submissions scores to restrict the query. Possible values are -1, 0, 1, 2, 3. | Optional | 
| from_time | Start of time window (defaults to 24 hours ago) (YYYY-MM-DD HH:MM:SS) | Optional | 
| to_time | End of time window (defaults to current time) (YYYY-MM-DD HH:MM:SS) | Optional | 
| status | A list of triage statuses for submissions; only email submissions marked with at least one of these statuses will be returned. Options are 'UNRESOLVED', 'CONFIRMED', 'IGNORED' | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TruSTAR.PhishingIndicator.indicatorType | string | Indicator Type | 
| TruSTAR.PhishingIndicator.normalizedIndicatorScore | number | Indicator normalized score | 
| TruSTAR.PhishingIndicator.originalIndicatorScore.name | string | Indicator original score name | 
| TruSTAR.PhishingIndicator.originalIndicatorScore.value | string | Indicator original score value | 
| TruSTAR.PhishingIndicator.sourceKey | string | Indicator source key | 
| TruSTAR.PhishingIndicator.value | string | Indicator value | 
| File.Name | String | The full file name \(including file extension\). | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA1 hash of the file. | 
| IP.Address | String | IP address | 
| URL.Data | String | The URL | 
| CVE.ID | String | The ID of the CVE, for example: CVE\-2015\-1653 | 
| Account.Email.Address | String | The email address of the account. | 
| RegistryKey.Path | String | The path to the registry key | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | string | The indicator we tested | 
| DBotScore.Type | string | The type of the indicator | 
| DBotScore.Vendor | string | Vendor used to calculate the score | 
| DBotScore.Score | number | The actual score | 


#### Command Example
``` ```

#### Human Readable Output


