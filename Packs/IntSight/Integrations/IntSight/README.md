Use IntSights to manage and mitigate threats.
This integration was tested with Intsights API version 3.

## Configure IntSights in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. <https://192.168.0.1>) | True |
| Credentials | True |
| Password | True |
| Alert type to fetch as incidents, allowed: "AttackIndication", "DataLeakage", "Phishing", "BrandSecurity", "ExploitableData", "VIP" | False |
| Minimum Alert severity level to fetch incidents incidents from, allowed values are: 'All', 'Low', 'Medium','High'(Setting to All will fetch all incidents) | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Fetch incidents | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
| Max fetch | False |
| Incident type | False |
| Sub Account ID (MSSP accounts only) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### intsights-get-alert-image

***
Returns an image of an alert by ID.

#### Base Command

`intsights-get-alert-image`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| image-id | The ID of the image to return. | Required | 

#### Context Output

There is no context output for this command.

### intsights-get-alert-activities

***
Returns alert activities.

#### Base Command

`intsights-get-alert-activities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Activities.Type | string | The type of the activity. | 
| IntSights.Alerts.Activities.Initiator | string | The initiator of the alert. | 
| IntSights.Alerts.Activities.CreatedDate | date | The date the alert was created. | 
| IntSights.Alerts.Activities.UpdateDate | date | The date the alert was updated. | 
| IntSights.Alerts.Activities.RemediationBlocklistUpdate | string | The remediation blocked list update. | 
| IntSights.Alerts.Activities.AskTheAnalyst.Replies | string | The replies to questions of the analyst. | 
| IntSights.Alerts.Activities.Mail.Replies | string | The replies to an email. | 
| IntSights.Alerts.Activities.ReadBy | string | The alert that was read by. | 

### intsights-assign-alert

***
Assigns an alert.

#### Base Command

`intsights-assign-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The unique ID of the Alert. | Required | 
| assignee-email | The user email of the assignee. | Required | 
| is-mssp-optional | Whether the assigned user is an MSSP user. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Assignees.AssigneeID | string | The ID of the assignee. | 

### intsights-unassign-alert

***
Unassigns an alert from a user.

#### Base Command

`intsights-unassign-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The unique ID of the alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 

### intsights-send-mail

***
Sends an email containing a question and details of the alert.

#### Base Command

`intsights-send-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The unique ID of the alert. | Required | 
| emails | The destination email addresses array (comma-separated). | Required | 
| content | The content added to the alert details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the Alert. | 
| IntSights.Alerts.Mail.EmailID | string | The ID of the email. | 
| IntSights.Alerts.Question | string | Details of the question. | 

### intsights-ask-the-analyst

***
Sends a question to the IntSights analyst about the requested alert.

#### Base Command

`intsights-ask-the-analyst`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The unique ID of the alert. | Required | 
| question | Question to ask the Intsights analyst about the requested alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the Alert. | 
| IntSights.Alerts.Question | string | Details of the question. | 

### intsights-add-tag-to-alert

***
Adds a tag to the alert.

#### Base Command

`intsights-add-tag-to-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the unique alert. | Required | 
| tag-name | The new tag string. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Tags.TagName | string | The name of the tag. | 
| IntSights.Alerts.Tags.ID | string | The ID of the Tag. | 

### intsights-remove-tag-from-alert

***
Removes a tag from the specified alert.

#### Base Command

`intsights-remove-tag-from-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The unique ID of the alert. | Required | 
| tag-id | The unique ID of the tag to remove. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Tags.ID | string | The ID of the tag. | 

### intsights-add-comment-to-alert

***
Adds a comment to a specified alert.

#### Base Command

`intsights-add-comment-to-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The unique ID of the alert. | Required | 
| comment | The comment to add to the alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Comment | string | The comment in the alert. | 

### intsights-update-alert-severity

***
Changes the severity of a specified alert.

#### Base Command

`intsights-update-alert-severity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The unique ID of the alert. | Required | 
| severity | The severity of the alert. Can be: "High", "Medium", or "Low". Possible values are: High, Medium, Low. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Severity | string | The severity of the alert. | 

### intsights-get-alert-by-id

***
Returns the alert object by alert ID.

#### Base Command

`intsights-get-alert-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The unique ID of the alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Severity | string | The severity of the alert. | 
| IntSights.Alerts.Type | string | The type of the alert. | 
| IntSights.Alerts.FoundDate | date | The date that the alert was found. | 
| IntSights.Alerts.SourceType | string | The source type of the alert. | 
| IntSights.Alerts.SourceURL | string | The source URL of the alert. | 
| IntSights.Alerts.SourceEmail | string | The source email of the alert. | 
| IntSights.Alerts.SourceNetworkType | string | The network type of the alert. | 
| IntSights.Alerts.IsClosed | boolean | Whether or not the alert is closed. | 
| IntSights.Alerts.IsFlagged | boolean | Whether or not the alert is flagged. | 
| IntSights.Alerts.Tags.CreatedBy | string | Name of the service for which the tag was created. | 
| IntSights.Alerts.Tag.Name | string | Name of the tag. | 
| IntSights.Alerts.Tag.ID | string | The ID of the tag. | 
| IntSights.Alerts.Images | string | The ID of the images. | 
| IntSights.Alerts.Description | string | The description of the alert. | 
| IntSights.Alerts.Title | string | The title of the alert. | 
| IntSights.Alerts.TakedownStatus | string | The TakedownStatus of the alert. | 
| IntSights.Alerts.SubType | string | The sub type of the alert. | 

### intsights-get-ioc-by-value

***
Searches for an exact IOC value.

#### Base Command

`intsights-get-ioc-by-value`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The IOC value for which to search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Iocs.Value | string | The value of the IOC. | 
| IntSights.Iocs.Type | string | The type of the IOC. | 
| IntSights.Iocs.FirstSeen | date | The date the IOC was first seen. | 
| IntSights.Iocs.LastSeen | date | The date the IOC was last seen. | 
| IntSights.Iocs.LastUpdatedDate | date | The date the IOC was last updated. | 
| IntSights.Iocs.SourceID | string | The source ID of the IOC. | 
| IntSights.Iocs.SourceName | string | The source name of the IOC. | 
| IntSights.Iocs.SourceConfidenceLevel | string | The confidence level of the IOC source. | 
| IntSights.Iocs.Severity | string | The severity of the IOC. | 
| IntSights.Iocs.Status | string | The status of the IOC. | 
| IntSights.Iocs.Sources.name | string | The source name of the IOC. | 
| IntSights.Iocs.Sources.confidenceLevel | string | The confidence level of the IOC source. | 
| IntSights.Iocs.Sources.id | string | The source id of the IOC. | 
| IntSights.Iocs.tags | Array | The tags of the IOC. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The type of the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| File.Name | String | The full file name \(including file extension\). | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Address | String | IP address. | 
| Domain.Name | String | The domain name. For example, "google.com". | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 

### intsights-get-iocs

***
Returns count totals of the available IOCs.

#### Base Command

`intsights-get-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of the IOC. Can be: "Urls", "Hashes", "IpAddresses", or "domains". Possible values are: Urls, Hashes, IpAddresses, Domains. | Optional | 
| limit | The maximum number of results from 1-1000. Default is 1000. | Optional | 
| severity | The severity level of the IOC. Can be: "High", "Medium", or "Low". Possible values are: High, Medium, Low. | Optional | 
| source-ID | The source of the IOC. | Optional | 
| first-seen-from | Beginning of the date range when the IOC was first seen (MM/DD/YYYY). Default is 0. | Optional | 
| first-seen-to | End of the date range when the IOC was first seen (MM/DD/YYYY). Default is 0. | Optional | 
| last-seen-from | Beginning of the date range when the IOC was last seen (MM/DD/YYYY). Default is 0. | Optional | 
| last-updated-from | Beginning of the date range when the IOC was last updated (YYYY-MM-DD). | Optional | 
| last-seen-to | End of the date range when the IOC was last seen (MM/DD/YYYY). Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Iocs.Value | string | The value of the IOC. | 
| IntSights.Iocs.Type | string | The type of the IOC. | 
| IntSights.Iocs.FirstSeen | date | The date the IOC was first seen. | 
| IntSights.Iocs.LastSeen | date | The date the IOC was last seen. | 
| IntSights.Iocs.LastUpdatedDate | date | The date the IOC was last updated. | 
| IntSights.Iocs.SourceID | string | The source ID of the IOC. | 
| IntSights.Iocs.SourceName | string | The source name of the IOC. | 
| IntSights.Iocs.SourceConfidenceLevel | string | The confidence level of the IOC source. | 
| IntSights.Iocs.Severity | string | The severity of the IOC. | 
| IntSights.Iocs.Status | string | The status of the IOC. | 
| IntSights.Iocs.Sources.name | string | The source name of the IOC. | 
| IntSights.Iocs.Sources.confidenceLevel | string | The confidence level of the IOC source. | 
| IntSights.Iocs.Sources.id | string | The source id of the IOC. | 
| IntSights.Iocs.tags | Array | The tags of the IOC. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The type of the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| File.Name | String | The full file name \(including file extension\). | 
| File.Malicious.Vendor | String | The vendor that reported the file as malicious. | 
| File.Malicious.Description | String | A description explaining why the file was determined to be malicious. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| URL.Data | String | The URL. | 
| URL.Malicious.Vendor | String | The vendor reporting the URL as malicious. | 
| URL.Malicious.Description | String | A description of the malicious URL. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.Address | String | IP address. | 
| Domain.Name | String | The domain name. For example, "google.com". | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 

### intsights-get-alerts

***
Returns alerts.

#### Base Command

`intsights-get-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-type | The type of the alert. Can be: "AttackIndication", "DataLeakage", "Phishing", "BrandSecurity", "ExploitableData", "VIP". Possible values are: AttackIndication, DataLeakage, Phishing, BrandSecurity, ExploitableData, VIP. | Optional | 
| severity | The severity of the alert. Can be: "High", "Medium", or "Low". Possible values are: High, Medium, Low. | Optional | 
| source-type | The source type of the alert. Can be: "ApplicationStores", "BlackMarkets", "HackingForums", "SocialMedia", "PasteSites", or "Others". Possible values are: ApplicationStores, BlackMarkets, HackingForums, SocialMedia, PasteSites, Others. | Optional | 
| network-type | The network type of the alert. Can be: "ClearWeb", or "DarkWeb". Possible values are: ClearWeb, DarkWeb. | Optional | 
| source-date-from | The start date for which to fetch in Millisecond Timestamp in UNIX. | Optional | 
| source-date-to | The end date for which to fetch in Millisecond Timestamp in UNIX. | Optional | 
| found-date-from | The start date for which fetch in Millisecond Timestamp in UNIX. | Optional | 
| found-date-to | The end date for which fetch in Millisecond Timestamp in UNIX. | Optional | 
| assigned | Whether to show assigned or unassigned alerts. | Optional | 
| is-flagged | Whether to show flagged or unflagged alerts. | Optional | 
| is-closed | Whether to show closed/open alerts. | Optional | 
| time-delta | Shows alerts within a specified time delta, given in days. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Severity | string | The severity of the alert. | 
| IntSights.Alerts.Type | string | The type of the alert. | 
| IntSights.Alerts.FoundDate | date | The date that the alert was found. | 
| IntSights.Alerts.SourceType | string | The source type of the alert. | 
| IntSights.Alerts.SourceURL | string | The source URL of the alert. | 
| IntSights.Alerts.SourceEmail | string | The source email of the alert. | 
| IntSights.Alerts.SourceNetworkType | string | The network type of the alert. | 
| IntSights.Alerts.IsClosed | boolean | Whether or not the alert is closed. | 
| IntSights.Alerts.IsFlagged | boolean | Whether or not the alert is flagged. | 
| IntSights.Alerts.Tags.CreatedBy | string | Name of the service that the tag was created. | 
| IntSights.Alerts.Tag.Name | string | Name of the tag. | 
| IntSights.Alerts.Tag.ID | string | The ID of the tag. | 
| IntSights.Alerts.Images | string | The ID of each image. | 
| IntSights.Alerts.Description | string | The description of the alert. | 
| IntSights.Alerts.Title | string | The title of the alert. | 
| IntSights.Alerts.TakedownStatus | string | The TakedownStatus of the alert. | 
| IntSights.Alerts.SubType | string | The sub type of the alert. | 

### intsights-alert-takedown-request

***
Requests an alert takedown.

#### Base Command

`intsights-alert-takedown-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 

### intsights-get-alert-takedown-status

***
Returns the alert takedown status.

#### Base Command

`intsights-get-alert-takedown-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.TakedownStatus | string | The status of the takedown. | 

### intsights-update-ioc-blocklist-status

***
Updates the IOC block list status.

#### Base Command

`intsights-update-ioc-blocklist-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert. | Required | 
| type | A comma separated list of each type of IOC. Options: Domains, IPs, URLs. | Required | 
| value | A comma separated list of the value of the IOCs. | Required | 
| blocklist-status | A comma separated list of the IOCs block list status. Options: Sent, NotSent. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Status | string | The status of the block list. | 

### intsights-get-ioc-blocklist-status

***
Returns the status of the IOC block list.

#### Base Command

`intsights-get-ioc-blocklist-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Status | string | The status of the block list. | 

### intsights-close-alert

***
Closes an alert

#### Base Command

`intsights-close-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert-id | The ID of the alert. | Required | 
| reason | The reason to close the alert. Can be: "ProblemSolved", "InformationalOnly", "ProblemWeAreAlreadyAwareOf", "CompanyOwnedDomain", "LegitimateApplication/Profile", "NotRelatedToMyCompany", "FalsePositive", or "Other". Possible values are: ProblemSolved, InformationalOnly, ProblemWeAreAlreadyAwareOf, CompanyOwnedDomain, LegitimateApplication/Profile, NotRelatedToMyCompany, FalsePositive, Other. | Required | 
| free-text | The comments in the alert. | Optional | 
| is-hidden | The hidden status of the alert. Deletes an alert from the account instance - only when reason is a FalsePositive). Possible values are: True, False. Default is False. | Optional | 
| rate | The rate of the alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.Alerts.ID | string | The ID of the alert. | 
| IntSights.Alerts.Closed.Reason | string | The closed reason of the alert. | 

### intsights-mssp-get-sub-accounts

***
Returns all Managed Security Service Provider's (MSSP) sub accounts.

#### Base Command

`intsights-mssp-get-sub-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IntSights.MsspAccount.ID | String | The ID of IntSights MSSP sub account. | 
| IntSights.MsspAccount.Status | String | The enabled status of IntSights MSSP sub account | 
| IntSights.MsspAccount.AssetsCount | Number | The assets count of IntSights MSSP sub account. | 
| IntSights.MsspAccount.AssetLimit | Number | The asset limit of IntSights MSSP sub account. | 
| IntSights.MsspAccount.CompanyName | String | The company name of IntSights MSSP sub account. | 

### intsights-request-ioc-enrichment

***
Request and receive enrichment of an IOC.

#### Base Command

`intsights-request-ioc-enrichment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The IOC value for which to enrich. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | domain name | 
| Domain.DNS | String | domain dns | 
| Domain.Resolutions | String | domain resolutions | 
| Domain.Subdomains | String | domain subdomains | 
| Domain.WHOIS/History | String | domain whois | 
| Domain.Malicious | String | domain malicious | 
| IP.Address | String | ip address | 
| IP.IpDetails | String | ip details | 
| IP.RelatedHashes | String | ip related hashes | 
| IP.WHOIS | String | ip whois | 
| IP.Malicious | String | ip malicious | 
| URL.Data | String | URL Data | 
| URL.AntivirusDetectedEngines | String | URL Antivirus Detected Engines | 
| URL.AntivirusDetectionRatio | String | URL Antivirus Detection Ratio | 
| URL.AntivirusDetections | String | URL Antivirus Detections | 
| URL.AntivirusScanDate | String | URL Antivirus Scan Date | 
| URL.RelatedHashes | String | URL Related Hashes | 
| URL.Malicious | String | URL Malicious | 
| File.Name | String | File Name | 
| File.AntivirusDetectedEngines | String | File Antivirus Detected Engines | 
| File.AntivirusDetectionRatio | String | File Antivirus Detection Ratio | 
| File.AntivirusDetections | String | File Antivirus Detections | 
| File.AntivirusScanDate | String | File Antivirus Scan Date | 
| File.Malicious | String | File Malicious | 
| IntSights.Iocs.Type | String | IntSights Iocs Type | 
| IntSights.Iocs.Value | String | IntSights Iocs Value | 
| IntSights.Iocs.FirstSeen | String | IntSights Iocs First Seen | 
| IntSights.Iocs.LastSeen | String | IntSights Iocs Last Seen | 
| IntSights.Iocs.Status | String | IntSights Iocs Status | 
| IntSights.Iocs.Severity | String | IntSights Iocs Severity | 
| IntSights.Iocs.RelatedMalwares | String | IntSights Iocs Related Malwares | 
| IntSights.Iocs.Sources | String | IntSights Iocs Sources | 
| IntSights.Iocs.IsKnownIoc | String | IntSights Iocs Is Known Ioc | 
| IntSightsIocs.RelatedThreatActors | String | IntSights Iocs Related Threat Actors | 
| IntSights.Iocs.SystemTags | String | IntSights Iocs SystemTags | 
| IntSights.Iocs.Tags | String | IntSights Iocs Tags | 
| IntSights.Iocs.Whitelisted | String | IntSights Iocs Whitelisted | 
| IntSights.Iocs.OriginalValue | String | IntSights Iocs Original Value | 
| Domain.WHOIS | String | Domain WHOIS | 