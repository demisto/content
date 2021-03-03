BitSight for Security Performance Management (SPM) enables CISOs to use an external view of security performance to measure, monitor, manage, and report on their cybersecurity program performance over time, and to facilitate a universal understanding of cyber risk across their organization. This improved understanding enables security leaders to make more informed decisions about their cybersecurity program, including where to focus their limited resources in order to achieve the greatest impact, where to spend money, and how to manage their cyber risk more effectively. 
The data-driven metrics within BitSight indicate if the cybersecurity program is performing up to the expectations set by internal goals and objectives, industry best practices, regulators, customers, and other internal or external stakeholders. The BitSight Security Rating, the industry’s original cybersecurity rating score, provides a trusted metric that reflects the organization’s cybersecurity program performance over time. By combining the insights gained from BitSight SPM with the BitSight Security Rating, security leaders provide a more complete view of their cybersecurity program performance over time and help to bring about a universal understanding of cyber risk to the Board of Directors and other stakeholders. 
Bring BitSight findings event information into your security program and leverage Cortex XSOAR's incident management workflows for automation of managing security incidents. This visibility enables you to pinpoint and control the sources of infections in your company infrastructure, seamlessly going from awareness to rapid remediation. The findings information reveals associated IP addresses, destination ports, and more, to assist your company in connecting the security and IT teams to respond faster and more effectively to threats. 
This integration was integrated and tested with version 01 of BitSight for Security Performance Management
## Configure BitSight for Security Performance Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BitSight for Security Performance Management.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://api.bitsighttech.com) |  | True |
    | API Key |  | True |
    | Company's GUID |  | False |
    | First fetch time | Enter the  number in days  | False |
    | Incident Daily Fetch time | Please provide Incident fetch time in day in 24 hours format \('HH:MM'\) | False |
    | Minimum Severity for Findings |  | False |
    | Findings minimum asset category | By default value will be empty, records will be fetched without asset category filter | False |
    | Findings Grade |  | False |
    | Risk Vector (All has been selected by default) |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bitsight-get-company-details
***
BitSight command - to get comany details based on guid.


#### Base Command

`bitsight-get-company-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guid | GUID of the company to fetch its details. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| errorCode | string | Error code number when API fails | 
| errorMessage | string | Error Message when API fails | 
| guid | string | guid | 
| customId | string | customId | 
| name | string | name | 
| description | string | description | 
| ipv4Count | string | ipv4Count | 
| peopleCount | string | peopleCount | 
| shortName | string | shortName | 
| industry | string | industry | 
| industrySlug | string | industrySlug | 
| subIndustry | string | subIndustry | 
| subIndustrySlug | string | subIndustrySlug | 
| homePage | string | homePage | 
| primaryDomain | string | primaryDomain | 
| type | string | type | 
| displayURL | string | displayURL | 
| ratingDetails | string | ratingDetails | 
| ratings | string | ratings | 
| searchCount | string | searchCount | 
| subscriptionType | string | subscriptionType | 
| sparkline | string | sparkline | 
| subscriptionTypeKey | string | subscriptionTypeKey | 
| subscriptionEndDate | string | subscriptionEndDate | 
| bulkEmailSenderStatus | string | bulkEmailSenderStatus | 
| serviceProvider | string | serviceProvider | 
| customerMonitoringCount | string | customerMonitoringCount | 
| availableUpgradeTypes | string | availableUpgradeTypes | 
| hasCompanyTree | string | hasCompanyTree | 
| hasPreferredContact | string | hasPreferredContact | 
| isBundle | string | isBundle | 
| ratingIndustryMedian | string | ratingIndustryMedian | 
| primaryCompany | string | primaryCompany | 
| permissions | string | permissions | 
| isPrimary | string | isPrimary | 
| securityGrade | string | securityGrade | 
| inSpmPortfolio | string | inSpmPortfolio | 
| isMycompMysubsBundle | string | isMycompMysubsBundle | 
| companyFeatures | string | companyFeatures | 


#### Command Example
``` ```

#### Human Readable Output



### bitsight-get-company-findings
***
BitSight command to get company findings


#### Base Command

`bitsight-get-company-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guid | Guid of the company. | Required | 
| first_seen | First seen date of the findings, Date format is YYYY-MM-DD. | Required | 
| last_seen | Last seen date of the findings, Date format is YYYY-MM-DD. | Required | 
| severity | Minimum Severity of the findings. | Optional | 
| grade | Minimum Grade of the findings. | Optional | 
| asset_category | Asset Category of the findings. | Optional | 
| risk_vector_label | Risk category of the findings. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| errorCode | string | Error code number when API fails | 
| errorMessage | String | Error Message when API fails | 
| temporaryId | string | temporary Id | 
| affectsRating | string | Whther rating is affected | 
| assets | unknown | Information about assets | 
| details | string | Details about findings | 
| evidenceKey | string | evidence key | 
| firstSeen | date | first seen date of the findings | 
| lastSeen | date | last seen date of the findings | 
| relatedFindings | string | related findings | 
| riskCategory | string | risk category | 
| riskVector | string | risk vector | 
| riskVectorLabel | string | risk vector label | 
| rolledupObservationId | string | rolledup observation id | 
| severity | string | severity | 
| severityCategory | string | severity category | 
| tags | string | tags | 
| duration | string | duration | 
| comments | unknown | comments | 
| remainingDecay | string | remaining decay | 


#### Command Example
``` ```

#### Human Readable Output



### bitsight-get-companies-guid
***
BitSight command to get list of companies and GUID


#### Base Command

`bitsight-get-companies-guid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BitSight.Guid.companyName | String | Name of the company | 
| BitSight.Guid.shortName | Date | short name of the company | 
| BitSight.Guid.guid | String | GUID of the company | 
| BitSight.Guid.errorCode | String | Error code in case API fails | 
| BitSight.Guid.errorMessage | String | Error Message in case API fails | 


#### Command Example
``` ```

#### Human Readable Output


