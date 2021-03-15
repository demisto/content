BitSight Integration to get company guid, details, findings and to create Incidents. 
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
    | First fetch Days | Enter the  number in days. When the fetch incident run for first time, incident will be fetched for given number of days  | False |
    | Incident Daily Fetch time | Please provide Incident fetch time in day in 24 hours format \('HH:MM'\). Fetch incident will run once in day if  execution time grater than given time here. | False |
    | Max Fetch | Maximum Number of records to fetch | False |
    | Minimum Severity for Findings |  | False |
    | Findings minimum asset category | Filter by the asset category \(critical, high, medium, low\) | False |
    | Findings Grade | Filter the result by the value of grade. | False |
    | Risk Vector ('All' has been selected by default) | This parameter comma separated list of values. By default 'All' will be selected, if you need only particular values you can unselect 'All' and select the required values. List of values are Web Application Headers, Botnet Infections, Breaches, Desktop Software, DKIM, DNSSEC, File Sharing, Insecure Systems, Malware Servers, Mobile App Publications, Mobile Application Security, Mobile Software, Open Ports, Patching Cadence, Potentially Exploited, Server Software, Spam Propagation, SPF, SSL Certificates, SSL Configurations, Unsolicited Communications. | False |
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
| BitSight.Company.errorCode | string | Error code number when API fails | 
| BitSight.Company.errorMessage | string | Error Message when API fails | 
| BitSight.Company.guid | string | guid | 
| BitSight.Company.customId | string | customId | 
| BitSight.Company.name | string | name | 
| BitSight.Company.description | string | description | 
| BitSight.Company.ipv4Count | string | ipv4Count | 
| BitSight.Company.peopleCount | string | peopleCount | 
| BitSight.Company.shortName | string | shortName | 
| BitSight.Company.industry | string | industry | 
| BitSight.Company.industrySlug | string | industrySlug | 
| BitSight.Company.subIndustry | string | subIndustry | 
| BitSight.Company.subIndustrySlug | string | subIndustrySlug | 
| BitSight.Company.homePage | string | homePage | 
| BitSight.Company.primaryDomain | string | primaryDomain | 
| BitSight.Company.type | string | type | 
| BitSight.Company.displayURL | string | displayURL | 
| BitSight.Company.ratingDetails | string | ratingDetails | 
| BitSight.Company.ratings | string | ratings | 
| BitSight.Company.searchCount | string | searchCount | 
| BitSight.Company.subscriptionType | string | subscriptionType | 
| BitSight.Company.sparkline | string | sparkline | 
| BitSight.Company.subscriptionTypeKey | string | subscriptionTypeKey | 
| BitSight.Company.subscriptionEndDate | string | subscriptionEndDate | 
| BitSight.Company.bulkEmailSenderStatus | string | bulkEmailSenderStatus | 
| BitSight.Company.serviceProvider | string | serviceProvider | 
| BitSight.Company.customerMonitoringCount | string | customerMonitoringCount | 
| BitSight.Company.availableUpgradeTypes | string | availableUpgradeTypes | 
| BitSight.Company.hasCompanyTree | string | hasCompanyTree | 
| BitSight.Company.hasPreferredContact | string | hasPreferredContact | 
| BitSight.Company.isBundle | string | isBundle | 
| BitSight.Company.ratingIndustryMedian | string | ratingIndustryMedian | 
| BitSight.Company.primaryCompany | string | primaryCompany | 
| BitSight.Company.permissions | string | permissions | 
| BitSight.Company.isPrimary | string | isPrimary | 
| BitSight.Company.securityGrade | string | securityGrade | 
| BitSight.Company.inSpmPortfolio | string | inSpmPortfolio | 
| BitSight.Company.isMycompMysubsBundle | string | isMycompMysubsBundle | 
| BitSight.Company.companyFeatures | string | companyFeatures | 


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
| first_seen | First seen date of the findings, Date format is YYYY-MM-DD, Example: 2021-01-01. | Required | 
| last_seen | Last seen date of the findings, Date format is YYYY-MM-DD, Example: 2021-01-01. | Required | 
| severity | Minimum Severity of the findings. Possible values are: minor, moderate, material, severe. | Optional | 
| grade | Grade of the findings. Possible values are: good, fair, warn, bad, neutral. | Optional | 
| asset_category | Asset Category of the findings. Possible values are: low, medium, high, critical. | Optional | 
| risk_vector_label | Risk category of the findings. Possible values are: Web Application Headers, Botnet Infections, Breaches, Desktop Software, DKIM, DNSSEC, File Sharing, Insecure Systems, Malware Servers, Mobile App Publications, Mobile Application Security, Mobile Software, Open Ports, Patching Cadence, Potentially Exploited, Server Software, Spam Propagation, SPF, SSL Certificates, SSL Configurations, Unsolicited Communications. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BitSight.Finding.errorCode | string | Error code number when API fails | 
| BitSight.Finding.errorMessage | String | Error Message when API fails | 
| BitSight.Finding.temporaryId | string | temporary Id | 
| BitSight.Finding.affectsRating | string | Whther rating is affected | 
| BitSight.Finding.assets | unknown | Information about assets | 
| BitSight.Finding.details | string | Details about findings | 
| BitSight.Finding.evidenceKey | string | evidence key | 
| BitSight.Finding.firstSeen | date | first seen date of the findings | 
| BitSight.Finding.lastSeen | date | last seen date of the findings | 
| BitSight.Finding.relatedFindings | string | related findings | 
| BitSight.Finding.riskCategory | string | risk category | 
| BitSight.Finding.riskVector | string | risk vector | 
| BitSight.Finding.riskVectorLabel | string | risk vector label | 
| BitSight.Finding.rolledupObservationId | string | rolledup observation id | 
| BitSight.Finding.severity | string | severity | 
| BitSight.Finding.severityCategory | string | severity category | 
| BitSight.Finding.tags | string | tags | 
| BitSight.Finding.duration | string | duration | 
| BitSight.Finding.comments | unknown | comments | 
| BitSight.Finding.remainingDecay | string | remaining decay | 


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


