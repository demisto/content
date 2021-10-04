BitSight Integration to get company guid, details, findings and to create Incidents. 
This integration was integrated and tested with version 01 of BitSight for Security Performance Management
## Configure BitSight for Security Performance Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for BitSight for Security Performance Management.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://test.com) |  | True |
    | API Key |  | True |
    | Company's GUID |  | False |
    | First fetch time in days | Enter the  number in days. When the fetch incident run for first time, incident will be fetched for given number of days  | False |
    | Incident Daily Fetch time | Please provide Incident fetch time in day in 24 hours format \('HH:MM'\). Fetch incident will run once a day if execution time greater than the given time here. | False |
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
```!bitsight-get-company-details guid=a940bb61-33c4-42c9-9231-c8194c305db3```

#### Context Example
```json
{
    "BitSight": {
        "Company": {
            "availableUpgradeTypes": [],
            "bulkEmailSenderStatus": "NONE",
            "companyFeatures": [],
            "customId": null,
            "customerMonitoringCount": 217,
            "description": "Saperix Technologies LLC develops risk analysis software solutions.",
            "displayURL": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/overview/",
            "guid": "a940bb61-33c4-42c9-9231-c8194c305db3",
            "hasCompanyTree": true,
            "hasPreferredContact": true,
            "homePage": "http://www.test.com",
            "inSpmPortfolio": true,
            "industry": "Technology",
            "industrySlug": "technology",
            "ipv4Count": 5273,
            "isBundle": false,
            "isMycompMysubsBundle": false,
            "isPrimary": false,
            "name": "Saperix, Inc.",
            "peopleCount": 13000,
            "permissions": {
                "can_annotate": true,
                "can_download_company_report": true,
                "can_view_company_reports": true,
                "can_view_forensics": true,
                "can_view_infrastructure": true,
                "can_view_ip_attributions": true,
                "can_view_service_providers": true,
                "has_control": true
            },
            "primaryCompany": {
                "guid": "eed24cfa-c3ea-4467-aefa-89648881e277",
                "name": "Saperix Corporate"
            },
            "primaryDomain": "saperix.com",
            "ratingDetails": {
                "application_security": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=http_headers",
                    "grade": "C",
                    "grade_color": "#ecb870",
                    "name": "Web Application Headers",
                    "order": 11,
                    "percentile": 40,
                    "rating": 660
                },
                "botnet_infections": {
                    "beta": false,
                    "category": "Compromised Systems",
                    "category_order": 0,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Botnet%20Infections",
                    "grade": "F",
                    "grade_color": "#b24053",
                    "name": "Botnet Infections",
                    "order": 0,
                    "percentile": 12,
                    "rating": 560
                },
                "data_breaches": {
                    "beta": false,
                    "category": "Public Disclosures",
                    "category_order": 3,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/rating-details/?vector=news",
                    "grade": "A",
                    "grade_color": "#2c4d7f",
                    "name": "Security Incidents",
                    "order": 19,
                    "percentile": 100,
                    "rating": 820
                },
                "desktop_software": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=endpoint_pc",
                    "grade": "F",
                    "grade_color": "#b24053",
                    "name": "Desktop Software",
                    "order": 17,
                    "percentile": 1,
                    "rating": 390
                },
                "dkim": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=dkim",
                    "grade": "C",
                    "grade_color": "#ecb870",
                    "name": "DKIM",
                    "order": 6,
                    "percentile": 60,
                    "rating": 720
                },
                "dnssec": {
                    "beta": true,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=dnssec",
                    "grade": "F",
                    "grade_color": "#b24053",
                    "name": "DNSSEC",
                    "order": 10,
                    "percentile": 0,
                    "rating": 300
                },
                "file_sharing": {
                    "beta": false,
                    "category": "User Behavior",
                    "category_order": 2,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/user-behavior",
                    "grade": "C",
                    "grade_color": "#ecb870",
                    "name": "File Sharing",
                    "order": 13,
                    "percentile": 40,
                    "rating": 650
                },
                "insecure_systems": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=insecure_sys",
                    "grade": "D",
                    "grade_color": "#c77481",
                    "name": "Insecure Systems",
                    "order": 15,
                    "percentile": 28,
                    "rating": 590
                },
                "malware_servers": {
                    "beta": false,
                    "category": "Compromised Systems",
                    "category_order": 0,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Malware%20Servers",
                    "grade": "A",
                    "grade_color": "#2c4d7f",
                    "name": "Malware Servers",
                    "order": 2,
                    "percentile": 100,
                    "rating": 820
                },
                "mobile_application_security": {
                    "beta": true,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=mobile_appsec",
                    "grade": "N/A",
                    "grade_color": "#495057",
                    "name": "Mobile Application Security",
                    "order": 20,
                    "percentile": "N/A",
                    "rating": "N/A"
                },
                "mobile_software": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=endpoint_mobile",
                    "grade": "F",
                    "grade_color": "#b24053",
                    "name": "Mobile Software",
                    "order": 18,
                    "percentile": 3,
                    "rating": 430
                },
                "open_ports": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=open_port",
                    "grade": "A",
                    "grade_color": "#2c4d7f",
                    "name": "Open Ports",
                    "order": 9,
                    "percentile": 91,
                    "rating": 790
                },
                "patching_cadence": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=pc",
                    "grade": "B",
                    "grade_color": "#526d96",
                    "name": "Patching Cadence",
                    "order": 12,
                    "percentile": 86,
                    "rating": 780
                },
                "potentially_exploited": {
                    "beta": false,
                    "category": "Compromised Systems",
                    "category_order": 0,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Potentially%20Exploited",
                    "grade": "F",
                    "grade_color": "#b24053",
                    "name": "Potentially Exploited",
                    "order": 4,
                    "percentile": 16,
                    "rating": 580
                },
                "server_software": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=server_software",
                    "grade": "A",
                    "grade_color": "#2c4d7f",
                    "name": "Server Software",
                    "order": 16,
                    "percentile": 99,
                    "rating": 810
                },
                "spam_propagation": {
                    "beta": false,
                    "category": "Compromised Systems",
                    "category_order": 0,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Spam%20Propagation",
                    "grade": "A",
                    "grade_color": "#2c4d7f",
                    "name": "Spam Propagation",
                    "order": 1,
                    "percentile": 100,
                    "rating": 820
                },
                "spf": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=spf",
                    "grade": "B",
                    "grade_color": "#526d96",
                    "name": "SPF",
                    "order": 5,
                    "percentile": 89,
                    "rating": 790
                },
                "ssl_certificates": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=certificate",
                    "grade": "A",
                    "grade_color": "#2c4d7f",
                    "name": "SSL Certificates",
                    "order": 7,
                    "percentile": 93,
                    "rating": 800
                },
                "ssl_configurations": {
                    "beta": false,
                    "category": "Diligence",
                    "category_order": 1,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=ssl",
                    "grade": "C",
                    "grade_color": "#ecb870",
                    "name": "SSL Configurations",
                    "order": 8,
                    "percentile": 49,
                    "rating": 680
                },
                "unsolicited_comm": {
                    "beta": false,
                    "category": "Compromised Systems",
                    "category_order": 0,
                    "display_url": "https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Unsolicited%20Communications",
                    "grade": "A",
                    "grade_color": "#2c4d7f",
                    "name": "Unsolicited Communications",
                    "order": 3,
                    "percentile": 100,
                    "rating": 820
                }
            },
            "ratingIndustryMedian": "below",
            "ratings": [
                {
                    "range": "Basic",
                    "rating": 470,
                    "rating_color": "#b24053",
                    "rating_date": "2021-03-10"
                },
                {
                    "range": "Basic",
                    "rating": 470,
                    "rating_color": "#b24053",
                    "rating_date": "2021-03-09"
                }
            ],
            "searchCount": 6352,
            "securityGrade": null,
            "serviceProvider": false,
            "shortName": "Saperix",
            "sparkline": "https://api.bitsighttech.com/ratings/v1/companies/a940bb61-33c4-42c9-9231-c8194c305db3/sparkline?size=small",
            "subIndustry": "Computer & Network Security",
            "subIndustrySlug": "computer_network_security",
            "subscriptionEndDate": null,
            "subscriptionType": "Total Risk Monitoring",
            "subscriptionTypeKey": "continuous_monitoring",
            "type": "CURATED"
        }
    }
}
```

#### Human Readable Output

>### Get Company Details:
>|Company Info|Ratings|Rating Details|
>|---|---|---|
>| guid: a940bb61-33c4-42c9-9231-c8194c305db3<br/>customId: null<br/>name: Saperix, Inc.<br/>description: Saperix Technologies LLC develops risk analysis software solutions.<br/>ipv4Count: 5273<br/>peopleCount: 13000<br/>shortName: Saperix<br/>industry: Technology<br/>industrySlug: technology<br/>subIndustry: Computer & Network Security<br/>subIndustrySlug: computer_network_security<br/>homePage: http://www.saperix.com<br/>primaryDomain: saperix.com<br/>type: CURATED<br/>displayURL: https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/overview/ | {'rating': 470, 'rating_date': '2021-03-10', 'range': 'Basic'},<br/>{'rating': 470, 'rating_date': '2021-03-09', 'range': 'Basic'},<br/> | {'name': 'Botnet Infections', 'rating': 560, 'percentile': 12, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Botnet%20Infections'},<br/>{'name': 'Spam Propagation', 'rating': 820, 'percentile': 100, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Spam%20Propagation'},<br/>{'name': 'Malware Servers', 'rating': 820, 'percentile': 100, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Malware%20Servers'},<br/>{'name': 'Unsolicited Communications', 'rating': 820, 'percentile': 100, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Unsolicited%20Communications'},<br/>{'name': 'Potentially Exploited', 'rating': 580, 'percentile': 16, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/compromised-systems/?filter=Potentially%20Exploited'},<br/>{'name': 'SPF', 'rating': 790, 'percentile': 89, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=spf'},<br/>{'name': 'DKIM', 'rating': 720, 'percentile': 60, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=dkim'},<br/>{'name': 'SSL Certificates', 'rating': 800, 'percentile': 93, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=certificate'},<br/>{'name': 'SSL Configurations', 'rating': 680, 'percentile': 49, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=ssl'},<br/>{'name': 'Open Ports', 'rating': 790, 'percentile': 91, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=open_port'},<br/>{'name': 'DNSSEC', 'rating': 300, 'percentile': 0, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=dnssec'},<br/>{'name': 'Web Application Headers', 'rating': 660, 'percentile': 40, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=http_headers'},<br/>{'name': 'Patching Cadence', 'rating': 780, 'percentile': 86, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=pc'},<br/>{'name': 'File Sharing', 'rating': 650, 'percentile': 40, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/user-behavior'},<br/>{'name': 'Insecure Systems', 'rating': 590, 'percentile': 28, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=insecure_sys'},<br/>{'name': 'Server Software', 'rating': 810, 'percentile': 99, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=server_software'},<br/>{'name': 'Desktop Software', 'rating': 390, 'percentile': 1, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=endpoint_pc'},<br/>{'name': 'Mobile Software', 'rating': 430, 'percentile': 3, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=endpoint_mobile'},<br/>{'name': 'Security Incidents', 'rating': 820, 'percentile': 100, 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/rating-details/?vector=news'},<br/>{'name': 'Mobile Application Security', 'rating': 'N/A', 'percentile': 'N/A', 'display_url': 'https://service.bitsighttech.com/app/company/a940bb61-33c4-42c9-9231-c8194c305db3/diligence-details/?filter=mobile_appsec'} |


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
| grade | Grade of the findings. This can be a comma-separated list. Select the values from list of pre defined values good,fair,warn,bad,neutral. Possible values are: good, fair, warn, bad, neutral. | Optional | 
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
```!bitsight-get-company-findings guid=a940bb61-33c4-42c9-9231-c8194c305db3 first_seen=2021-01-01 last_seen=2021-02-01```

#### Context Example
```json
{
    "BitSight": {
        "Finding": {
            "affectsRating": true,
            "assets": [],
            "comments": null,
            "details": {
                "diligence_annotations": {
                    "count_ips": 1,
                    "operating_system_rule": {
                        "eol": "2019-11-05",
                        "is": "match",
                        "launch": "2019-10-07",
                        "version": "10.15"
                    },
                    "sample_ips": [
                        "0.0.0.0"
                    ],
                    "sample_user_agent_strings": [
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:84.0) Gecko/20100101 Firefox/84.0"
                    ],
                    "user_agent_rule": {
                        "eol": "2021-02-02",
                        "is": "match",
                        "launch": "2020-12-15",
                        "version": "84"
                    }
                },
                "estimation_of_users": "1",
                "geo_ip_location": "US",
                "grade": "GOOD",
                "operating_system_family": "Mac OS X",
                "operating_system_grade": "UNKNOWN",
                "operating_system_name": "macOS",
                "operating_system_support_status": "UNKNOWN",
                "operating_system_version": "10.15",
                "remediations": [
                    {
                        "help_text": "The operating system details could not be recognized and the browser is supported.",
                        "message": "Unknown Operating System and Supported Browser",
                        "remediation_tip": "If obfuscation of the operating system version is intentional, for which there is no penalty, ensure an operating system update strategy is in place."
                    }
                ],
                "rollup_end_date": "2021-01-15",
                "rollup_start_date": "2021-01-15",
                "user_agent_family": "Firefox",
                "user_agent_grade": "GOOD",
                "user_agent_support_status": "SUPPORTED",
                "user_agent_version": "84.0",
                "vulnerabilities": []
            },
            "duration": null,
            "evidenceKey": "Mac OS X 10.15 / Firefox 84.0",
            "firstSeen": "2021-01-15",
            "lastSeen": "2021-01-15",
            "relatedFindings": [],
            "remainingDecay": 10,
            "riskCategory": "Diligence",
            "riskVector": "desktop_software",
            "riskVectorLabel": "Desktop Software",
            "rolledupObservationId": "HnimbqIzjRlVBUNrQaYPIQ==",
            "severity": 1,
            "severityCategory": "minor",
            "tags": [],
            "temporaryId": "A9Jq47BBje22bbe943896099be3f3b0566e3df0283"
        }
    }
}
```

#### Human Readable Output

>### Get Company findings:
>|Evidence Key|Risk Vector Label|First Seen|Last Seen|ID|Risk Category|Severity|
>|---|---|---|---|---|---|---|
>| Chrome OS 12607.58.0 / Chrome 79.0.3945 | Desktop Software | 2021-01-15 | 2021-01-15 | A9Jq47BBje9faec367e8947c1e6e57994c16433813 | Diligence | moderate |
>| Chrome OS 12607.82.0 / Chrome 79.0.3945 | Desktop Software | 2021-01-15 | 2021-01-15 | A9Jq47BBje450a9e48c74bdd1911387b40f4f0de29 | Diligence | moderate |
>| Mac OS X 10.15 / Firefox 84.0 | Desktop Software | 2021-01-15 | 2021-01-15 | A9Jq47BBje22bbe943896099be3f3b0566e3df0283 | Diligence | minor |


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
```!bitsight-get-companies-guid```

#### Context Example
```json
{
    "BitSight": {
        "GUID": {
            "companyName": "Black Hills Technologies",
            "guid": "a5e23bf0-38d4-4cea-aa50-19ee75da481d",
            "shortName": "Black Hills Technologies"
        }
    }
}
```

#### Human Readable Output

>### Get Companies GUID:
>|companyName|shortName|guid|
>|---|---|---|
>| my_company | my_company | a940bb61-33c4-42c9-9231-c8194c305db3 |
>| Saperix, Inc. | Saperix | a940bb61-33c4-42c9-9231-c8194c305db3 |
>| Actors Films | Actors Films | 1b3d260c-9e23-4e19-b3a5-a0bcf67d74d9 |
>| Frontstore, Inc. | Frontstore | 9ecd7b7e-42b4-4d32-99e8-1b65e59b0774 |
>| Kati Communications, Inc. | Kati Communications, Inc. | 331d73bd-11cc-4eca-a92e-87beacec50ff |
>| Parallel Signals | Parallel Signals | b0cf77ea-cd4f-43b7-9f00-6be657b2a192 |
>| Goliath Investments LLC | Goliath Investments | 1263b9c6-af38-4497-84ee-e15efdb065e9 |
>| Blue Seas International | Blue Seas International | feeccea4-e062-4cf5-9a3d-7034addb12d1 |
>| PanAmerican Trust Group | PanAmerican Trust | d3f98ffc-184c-4298-b259-35ce09d39704 |
>| Cyprus Hotels, Inc. | Cyprus Hotels | 71466c18-a27d-46f1-898b-a1f95dbe0447 |
>| Pollinate, Inc. | Pollinate | 19d16bf5-11a6-467b-b7b1-f5563daece69 |
>| Black Hills Technologies | Black Hills Technologies | a5e23bf0-38d4-4cea-aa50-19ee75da481d |

