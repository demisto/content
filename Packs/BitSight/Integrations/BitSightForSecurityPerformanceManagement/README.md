Use the "Bitsight for Security Performance Management" Integration to get company guid, details, and findings. This integration also allows to fetch the findings by using the fetch incidents capability.
This integration was integrated and tested with version 01 of Bitsight for Security Performance Management

## Configure Bitsight for Security Performance Management in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key |  | True |
| Company's GUID | Use "bitsight-companies-guid-get" command to retrieve the company's GUID. | False |
| First fetch time in days | Enter the number in days. When the fetch incident runs for first time, incidents will be fetched for a given number of days. | False |
| Max Fetch | Maximum number of incidents to fetch. The maximum value is 200. | False |
| Findings Minimum Severity | Minimum severity of the findings to fetch. | False |
| Findings Minimum Asset Category | Filter by the asset category \(critical, high, medium, low\). | False |
| Findings Grade | Filter the result by the value of grade. | False |
| Risk Vector ('All' has been selected by default) | This parameter supports comma separated list of values. By default 'All' will be selected, if you need only particular values you can unselect 'All' and select the required values. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bitsight-company-details-get
***
Bitsight command to get company details based on the provided GUID. The details include rating details, rating history, and grades for individual risk vectors.


#### Base Command

`bitsight-company-details-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guid | GUID of the company to fetch its details.<br/><br/>Note: Users can get the list of the GUID by executing the "bitsight-companies-guid-get" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BitSight.Company.guid | string | The unique identifier of this company. | 
| BitSight.Company.customId | string | The customizable ID assigned to this company. | 
| BitSight.Company.name | string | The name of this company. | 
| BitSight.Company.description | string | Details about this company, which typically includes its industry and location. | 
| BitSight.Company.ipv4Count | number | The number of IP addresses attributed to this company. | 
| BitSight.Company.peopleCount | number | The number of employees in this company. | 
| BitSight.Company.shortname | string | The abbreviated name of this company. | 
| BitSight.Company.industry | string | The industry of this company. | 
| BitSight.Company.industrySlug | string | The industry slug name of this company. | 
| BitSight.Company.subIndustry | string | The sub-industry of this company. | 
| BitSight.Company.subIndustrySlug | string | The sub-industry slug name of this company. | 
| BitSight.Company.homePage | string | The URL of this company's primary external website. | 
| BitSight.Company.primaryDomain | string | The name of this company's primary domain. | 
| BitSight.Company.type | string | The type of rating. | 
| BitSight.Company.displayURL | string | The URL to this company's overview page in the Bitsight platform. | 
| BitSight.Company.ratingDetails.name | string | The name of this risk vector. | 
| BitSight.Company.ratingDetails.rating | number | Internal rating of this risk vector. | 
| BitSight.Company.ratingDetails.grade | string | The letter grade of this risk vector. | 
| BitSight.Company.ratingDetails.percentile | number | This company's performance on this risk vector against their peers. | 
| BitSight.Company.ratingDetails.gradeColor | string | The hex code to display letter grade colors in HTML applications. | 
| BitSight.Company.ratingDetails.category | string | The risk category of this risk vector. | 
| BitSight.Company.ratingDetails.categoryOrder | number | Used to visually sort this risk category in the Bitsight platform. | 
| BitSight.Company.ratingDetails.beta | boolean | A true value indicates this risk vector is in beta and does not affect this company's security rating. | 
| BitSight.Company.ratingDetails.order | number | Used to visually sort this risk vector in the Bitsight platform. | 
| BitSight.Company.ratingDetails.displayUrl | string | The URL in the Bitsight platform that contains the details of this risk vector. | 
| BitSight.Company.ratings.ratingDate | date | The date when this Bitsight Security Rating Report was generated. | 
| BitSight.Company.ratings.rating | number | The Bitsight Security Rating of this company on this day. | 
| BitSight.Company.ratings.range | string | The rating category of this company on this day. | 
| BitSight.Company.ratings.ratingColor | string | The hex code to display rating category colors in HTML applications. | 
| BitSight.Company.searchCount | number | The number of times this company has been listed in search results. | 
| BitSight.Company.subscriptionType | string | The type of subscription used to monitor this company. | 
| BitSight.Company.sparkline | string | The URL path to the security rating trend line of this company during the past one year. | 
| BitSight.Company.subscriptionTypeKey | string | The slug name of the subscription used to monitor this company. | 
| BitSight.Company.subscriptionEndDate | date | The date when the subscription to this company expires. | 
| BitSight.Company.bulkEmailSenderStatus | string | A FULL value indicates this company provides bulk email sending services, which excludes this company from the Spam Propagation risk vector. | 
| BitSight.Company.serviceProvider | boolean | A true value indicates this company is a service provider. | 
| BitSight.Company.customerMonitoringCount | number | The number of companies that are monitoring this company. | 
| BitSight.Company.availableUpgradeTypes | string | For internal Bitsight use. | 
| BitSight.Company.hasCompanyTree | boolean | A true value indicates this company has a Ratings Tree. | 
| BitSight.Company.hasPreferredContact | boolean | For internal Bitsight use. | 
| BitSight.Company.isBundle | boolean | A true value indicates this company is part of a ratings bundle. | 
| BitSight.Company.ratingIndustryMedian | string | Indicates this company's position in the peer group distribution chart. | 
| BitSight.Company.primaryCompany.guid | string | The unique identifier of this organization's primary company. | 
| BitSight.Company.primaryCompany.name | string | The name of this organization's primary company. | 
| BitSight.Company.permissions.canDownloadCompanyReport | boolean | A true value indicates you can view and download Bitsight Security Rating Reports \(PDF\). | 
| BitSight.Company.permissions.canViewForensics | boolean | A true value indicates you have the Event Forensics add-on package. | 
| BitSight.Company.permissions.canViewServiceProviders | boolean | A true value indicates you can access Bitsight for Fourth Party Risk Management. | 
| BitSight.Company.permissions.canRequestSelfPublishedEntity | boolean | A true value indicates you can request the creation of a self-published rating. | 
| BitSight.Company.permissions.canViewInfrastructure | boolean | A true value indicates you can view your infrastructure attribution. | 
| BitSight.Company.permissions.canAnnotate | boolean | A true value indicates you can identify assets and segment your network with infrastructure tags. | 
| BitSight.Company.permissions.canViewCompanyReports | boolean | A true value indicates you can view Bitsight Security Rating Reports. | 
| BitSight.Company.permissions.canManagePrimaryCompany | boolean | A true value indicates you can highlight a primary for your organization. | 
| BitSight.Company.permissions.hasControl | boolean | For internal Bitsight use. | 
| BitSight.Company.permissions.canEnableVendorAccess | boolean | A true value indicates you can modify vendor access. | 
| BitSight.Company.isPrimary | boolean | A true value indicates your company is the primary for your organization. | 
| BitSight.Company.securityGrade | string | For internal Bitsight use. | 
| BitSight.Company.inSpmPortfolio | boolean | A true value indicates this company is in your Security Performance Management portfolio \(My Company, SPM Subsidiary, etc.\). | 
| BitSight.Company.isMycompMysubsBundle | string | For internal Bitsight use. | 
| BitSight.Company.companyFeatures | string | For internal Bitsight use. | 

#### Command example
```!bitsight-company-details-get guid=00000000-0000-0000-0000-000000000001```
#### Context Example
```json
{
    "BitSight": {
        "Company": {
            "bulkEmailSenderStatus": "NONE",
            "customerMonitoringCount": 228,
            "description": "Saperix Technologies LLC develops risk analysis software solutions.",
            "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/overview/",
            "guid": "00000000-0000-0000-0000-000000000001",
            "hasCompanyTree": true,
            "hasPreferredContact": true,
            "homepage": "http://www.saperix.com",
            "inSpmPortfolio": true,
            "industry": "Technology",
            "industrySlug": "technology",
            "ipv4Count": 4169,
            "isBundle": false,
            "isMycompMysubsBundle": false,
            "isPrimary": false,
            "name": "Saperix, Inc.",
            "peopleCount": 400,
            "permissions": {
                "canAnnotate": true,
                "canDownloadCompanyReport": true,
                "canManagePrimaryCompany": true,
                "canRequestSelfPublishedEntity": true,
                "canViewCompanyReports": true,
                "canViewForensics": true,
                "canViewInfrastructure": true,
                "canViewIpAttributions": true,
                "canViewServiceProviders": true,
                "hasControl": true
            },
            "primaryCompany": {
                "guid": "00000000-0000-0000-0000-000000000002",
                "name": "Saperix Corporate"
            },
            "primaryDomain": "saperix.com",
            "ratingDetails": [
                {
                    "beta": false,
                    "category": "Compromised Systems",
                    "categoryOrder": 0,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Botnet%20Infections",
                    "grade": "A",
                    "gradeColor": "#2c4d7f",
                    "name": "Botnet Infections",
                    "order": 0,
                    "percentile": 100,
                    "rating": 820
                },
                {
                    "beta": false,
                    "category": "Compromised Systems",
                    "categoryOrder": 0,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Spam%20Propagation",
                    "grade": "A",
                    "gradeColor": "#2c4d7f",
                    "name": "Spam Propagation",
                    "order": 1,
                    "percentile": 100,
                    "rating": 820
                },
                {
                    "beta": false,
                    "category": "Compromised Systems",
                    "categoryOrder": 0,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Malware%20Servers",
                    "grade": "A",
                    "gradeColor": "#2c4d7f",
                    "name": "Malware Servers",
                    "order": 2,
                    "percentile": 100,
                    "rating": 820
                },
                {
                    "beta": false,
                    "category": "Compromised Systems",
                    "categoryOrder": 0,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Unsolicited%20Communications",
                    "grade": "A",
                    "gradeColor": "#2c4d7f",
                    "name": "Unsolicited Communications",
                    "order": 3,
                    "percentile": 100,
                    "rating": 820
                },
                {
                    "beta": false,
                    "category": "Compromised Systems",
                    "categoryOrder": 0,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Potentially%20Exploited",
                    "grade": "B",
                    "gradeColor": "#526d96",
                    "name": "Potentially Exploited",
                    "order": 4,
                    "percentile": 77,
                    "rating": 760
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=spf",
                    "grade": "B",
                    "gradeColor": "#526d96",
                    "name": "SPF",
                    "order": 5,
                    "percentile": 87,
                    "rating": 780
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=dkim",
                    "grade": "C",
                    "gradeColor": "#ecb870",
                    "name": "DKIM",
                    "order": 6,
                    "percentile": 54,
                    "rating": 700
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=certificate",
                    "grade": "B",
                    "gradeColor": "#526d96",
                    "name": "SSL Certificates",
                    "order": 7,
                    "percentile": 86,
                    "rating": 780
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=ssl",
                    "grade": "C",
                    "gradeColor": "#ecb870",
                    "name": "SSL Configurations",
                    "order": 8,
                    "percentile": 55,
                    "rating": 700
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=open_port",
                    "grade": "A",
                    "gradeColor": "#2c4d7f",
                    "name": "Open Ports",
                    "order": 9,
                    "percentile": 90,
                    "rating": 790
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=http_headers",
                    "grade": "F",
                    "gradeColor": "#b24053",
                    "name": "Web Application Headers",
                    "order": 10,
                    "percentile": 8,
                    "rating": 490
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=pc",
                    "grade": "C",
                    "gradeColor": "#ecb870",
                    "name": "Patching Cadence",
                    "order": 11,
                    "percentile": 62,
                    "rating": 720
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=insecure_sys",
                    "grade": "C",
                    "gradeColor": "#ecb870",
                    "name": "Insecure Systems",
                    "order": 12,
                    "percentile": 61,
                    "rating": 700
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=server_software",
                    "grade": "A",
                    "gradeColor": "#2c4d7f",
                    "name": "Server Software",
                    "order": 13,
                    "percentile": 99,
                    "rating": 810
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=endpoint_pc",
                    "grade": "F",
                    "gradeColor": "#b24053",
                    "name": "Desktop Software",
                    "order": 14,
                    "percentile": 1,
                    "rating": 400
                },
                {
                    "beta": false,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=endpoint_mobile",
                    "grade": "F",
                    "gradeColor": "#b24053",
                    "name": "Mobile Software",
                    "order": 15,
                    "percentile": 9,
                    "rating": 500
                },
                {
                    "beta": true,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=dnssec",
                    "grade": "F",
                    "gradeColor": "#b24053",
                    "name": "DNSSEC",
                    "order": 16,
                    "percentile": 0,
                    "rating": 300
                },
                {
                    "beta": true,
                    "category": "Diligence",
                    "categoryOrder": 1,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=mobile_appsec",
                    "grade": "N/A",
                    "gradeColor": "#495057",
                    "name": "Mobile Application Security",
                    "order": 17,
                    "percentile": "N/A",
                    "rating": "N/A"
                },
                {
                    "beta": false,
                    "category": "User Behavior",
                    "categoryOrder": 2,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/user-behavior",
                    "grade": "B",
                    "gradeColor": "#526d96",
                    "name": "File Sharing",
                    "order": 18,
                    "percentile": 79,
                    "rating": 750
                },
                {
                    "beta": false,
                    "category": "Public Disclosures",
                    "categoryOrder": 3,
                    "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/rating-details/?vector=news",
                    "grade": "C",
                    "gradeColor": "#ecb870",
                    "name": "Security Incidents",
                    "order": 19,
                    "percentile": 47,
                    "rating": 790
                }
            ],
            "ratingIndustryMedian": "below",
            "ratings": [
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-10"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-09"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-08"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-07"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-06"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-05"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-04"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-03"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-02"
                },
                {
                    "range": "Basic",
                    "rating": 600,
                    "ratingColor": "#b24053",
                    "ratingDate": "2021-03-01"
                }
            ],
            "searchCount": 8956,
            "serviceProvider": false,
            "shortname": "Saperix",
            "sparkline": "https://api.bitsighttech.com/ratings/v1/companies/00000000-0000-0000-0000-000000000001/sparkline?size=small",
            "subIndustry": "Computer & Network Security",
            "subIndustrySlug": "computer_network_security",
            "subscriptionType": "Total Risk Monitoring",
            "subscriptionTypeKey": "continuous_monitoring",
            "type": "CURATED"
        }
    }
}
```

#### Human Readable Output

>### Company Details:
>|Company Info|Ratings|Rating Details|
>|---|---|---|
>| guid: 00000000-0000-0000-0000-000000000001<br/>customId: null<br/>name: Saperix, Inc.<br/>description: Saperix Technologies LLC develops risk analysis software solutions.<br/>ipv4Count: 4169<br/>peopleCount: 400<br/>shortName: Saperix<br/>industry: Technology<br/>industrySlug: technology<br/>subIndustry: Computer & Network Security<br/>subIndustrySlug: computer_network_security<br/>homePage: http:<span>//</span>www.saperix.com<br/>primaryDomain: saperix.com<br/>type: CURATED<br/>displayURL: https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/overview/ | {'rating': 600, 'rating_date': '2021-03-10', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-09', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-08', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-07', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-06', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-05', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-04', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-03', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-02', 'range': 'Basic'},<br/>{'rating': 600, 'rating_date': '2021-03-01', 'range': 'Basic'} | {'name': 'Botnet Infections', 'rating': 820, 'percentile': 100, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Botnet%20Infections'},<br/>{'name': 'Spam Propagation', 'rating': 820, 'percentile': 100, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Spam%20Propagation'},<br/>{'name': 'Malware Servers', 'rating': 820, 'percentile': 100, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Malware%20Servers'},<br/>{'name': 'Unsolicited Communications', 'rating': 820, 'percentile': 100, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Unsolicited%20Communications'},<br/>{'name': 'Potentially Exploited', 'rating': 760, 'percentile': 77, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/compromised-systems/?filter=Potentially%20Exploited'},<br/>{'name': 'SPF', 'rating': 780, 'percentile': 87, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=spf'},<br/>{'name': 'DKIM', 'rating': 700, 'percentile': 54, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=dkim'},<br/>{'name': 'SSL Certificates', 'rating': 780, 'percentile': 86, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=certificate'},<br/>{'name': 'SSL Configurations', 'rating': 700, 'percentile': 55, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=ssl'},<br/>{'name': 'Open Ports', 'rating': 790, 'percentile': 90, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=open_port'},<br/>{'name': 'Web Application Headers', 'rating': 490, 'percentile': 8, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=http_headers'},<br/>{'name': 'Patching Cadence', 'rating': 720, 'percentile': 62, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=pc'},<br/>{'name': 'Insecure Systems', 'rating': 700, 'percentile': 61, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=insecure_sys'},<br/>{'name': 'Server Software', 'rating': 810, 'percentile': 99, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=server_software'},<br/>{'name': 'Desktop Software', 'rating': 400, 'percentile': 1, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=endpoint_pc'},<br/>{'name': 'Mobile Software', 'rating': 500, 'percentile': 9, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=endpoint_mobile'},<br/>{'name': 'DNSSEC', 'rating': 300, 'percentile': 0, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=dnssec'},<br/>{'name': 'Mobile Application Security', 'rating': 'N/A', 'percentile': 'N/A', 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/diligence-details/?filter=mobile_appsec'},<br/>{'name': 'File Sharing', 'rating': 750, 'percentile': 79, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/user-behavior'},<br/>{'name': 'Security Incidents', 'rating': 790, 'percentile': 47, 'display_url': 'https:<span>//</span>service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/rating-details/?vector=news'} |


### bitsight-company-findings-get

***
Bitsight command to get company findings.

#### Base Command

`bitsight-company-findings-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| guid | GUID of the company.<br/><br/>Note: Users can get the list of the GUID by executing the "bitsight-companies-guid-get" command. | Required | 
| first_seen | Filter the findings that were seen on and after this date. Format accepted: YYYY-MM-DD, Example: 2021-01-01. | Required | 
| last_seen | Filter the findings that were seen on and prior to this date. Format accepted: YYYY-MM-DD, Example: 2021-01-01. | Required | 
| severity | Minimum Severity of the findings. Possible values are: minor, moderate, material, severe. | Optional | 
| grade | Filter by the grade of the findings. Supports comma separated values. Select the values from the list of predefined values: good, fair, warn, bad and, neutral. | Optional | 
| asset_category | Minimum Asset Category of the findings.<br/><br/>Example: If low is selected from the options then low, medium, high, and critical will be considered in retrieving results. Possible values are: low, medium, high, critical. | Optional | 
| risk_vector_label | Risk category of the findings. Supports comma separated values. Select the values from the list of predefined values: Web Application Headers, Botnet Infections, Breaches, Desktop Software, DKIM, DNSSEC, File Sharing, Insecure Systems, Malware Servers, Mobile App Publications, Mobile Application Security, Mobile Software, Open Ports, Patching Cadence, Potentially Exploited, Server Software, Spam Propagation, SPF, SSL Certificates, SSL Configurations, Unsolicited Communications, Web Application Security, DMARC. | Optional | 
| limit | Set the maximum number of results to be retrieved. The maximum value is 1000.<br/><br/>Note: If a negative value is provided then the default value of 100 will be used. Default is 100. | Optional | 
| offset | Set the starting point of the results to be returned. A 0 (zero) value starts the results from the first record in the result set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BitSight.Company.guid | string | The unique identifier of this company. | 
| BitSight.Company.CompanyFinding.temporaryId | string | A temporary identifier for this finding. | 
| BitSight.Company.CompanyFinding.affectsRating | boolean | Indicates if this finding has an impact on the letter grade. | 
| BitSight.Company.CompanyFinding.assets.asset | string | The asset \(IP address or domain\) associated with this finding. | 
| BitSight.Company.CompanyFinding.assets.identifier | string | Identifier associated with the asset. | 
| BitSight.Company.CompanyFinding.assets.category | string | The Bitsight-calculated asset importance. | 
| BitSight.Company.CompanyFinding.assets.importance | number | For internal Bitsight use. | 
| BitSight.Company.CompanyFinding.assets.isIp | boolean | A true value indicates this asset is an IP address. | 
| BitSight.Company.CompanyFinding.details | string | Details of this finding. The included keys vary, depending on the following risk types Compromised Systems, Diligence, File Sharing. | 
| BitSight.Company.CompanyFinding.evidenceKey | string | The company's asset \(domain or IP address\) that's attributed to the finding. | 
| BitSight.Company.CompanyFinding.firstSeen | date | The date of the first observation. | 
| BitSight.Company.CompanyFinding.lastSeen | date | The date of the most recent observation. | 
| BitSight.Company.CompanyFinding.relatedFindings | string | Details of related findings. | 
| BitSight.Company.CompanyFinding.riskCategory | string | The risk category associated with this finding. | 
| BitSight.Company.CompanyFinding.riskVector | string | The slug name of the risk vector associated with this finding. | 
| BitSight.Company.CompanyFinding.riskVectorLabel | string | The name of the risk vector associated with this finding. | 
| BitSight.Company.CompanyFinding.rolledupObservationId | string | A unique identifier for this observation. | 
| BitSight.Company.CompanyFinding.severity | number | The severity of the finding, which is the measured risk that this finding introduces. | 
| BitSight.Company.CompanyFinding.severityCategory | string | The slug name of the finding severity. | 
| BitSight.Company.CompanyFinding.tags | string | Infrastructure tags that help identify this asset. | 
| BitSight.Company.CompanyFinding.duration | string | For internal Bitsight use. | 
| BitSight.Company.CompanyFinding.comments | string | A thread of finding comments. | 
| BitSight.Company.CompanyFinding.remainingDecay | number | For internal Bitsight use. | 
| BitSight.Company.CompanyFinding.remediationHistory.lastRequestedRefreshDate | date | The date when a record refresh that included this finding was last requested. | 
| BitSight.Company.CompanyFinding.remediationHistory.lastRefreshStatusDate | date | The date when a refresh of the remediation status of this finding was last requested. | 
| BitSight.Company.CompanyFinding.remediationHistory.lastRefreshStatusLabel | string | The current record refresh status of this finding. | 
| BitSight.Company.CompanyFinding.remediationHistory.lastRefreshReasonCode | string | The reason code of the last refresh of this finding. | 
| BitSight.Company.CompanyFinding.remediationHistory.lastRemediationStatusLabel | string | The current remediation status of this finding. | 
| BitSight.Company.CompanyFinding.remediationHistory.lastRemediationStatusDate | date | The date when the remediation status of this finding was last changed. | 
| BitSight.Company.CompanyFinding.remediationHistory.remediationAssignments | unknown | The users who are assigned to remediate this finding. | 
| BitSight.Company.CompanyFinding.remediationHistory.lastRemediationStatusUpdatedBy | string | The name of the user who updated the remediation status of this finding. | 
| BitSight.Company.CompanyFinding.assetOverrides.asset | string | The domain or IP address of the overridden asset. | 
| BitSight.Company.CompanyFinding.assetOverrides.importance | string | The user-assigned asset importance. | 
| BitSight.Company.CompanyFinding.assetOverrides.overrideImportance | unknown | For internal Bitsight use. | 
| BitSight.Company.CompanyFinding.attributedCompanies.guid | string | The unique identifier of the company attributed to the finding. | 
| BitSight.Company.CompanyFinding.attributedCompanies.name | string | The name of the company that is attributed to the finding. | 
| BitSight.Page.name | String | Name of the command. | 
| BitSight.Page.next | String | The URL to navigate to the next page of results. | 
| BitSight.Page.previous | String | The URL to navigate to the previous page of results. | 
| BitSight.Page.count | Number | The number of findings. | 

#### Command example
```!bitsight-company-findings-get guid=00000000-0000-0000-0000-000000000001 first_seen=2021-01-01 last_seen=2022-03-01 limit=2```
#### Context Example
```json
{
    "BitSight": {
        "Company": {
            "CompanyFinding": [
                {
                    "affectsRating": false,
                    "assets": [
                        {
                            "asset": "X.X.X.1",
                            "category": "low",
                            "importance": 0,
                            "isIp": true
                        }
                    ],
                    "attributedCompanies": [
                        {
                            "guid": "00000000-0000-0000-0000-000000000001",
                            "name": "Saperix, Inc."
                        }
                    ],
                    "details": {
                        "checkPass": "",
                        "country": "United States",
                        "destPort": 22,
                        "diligenceAnnotations": {
                            "cPE": [
                                "a:openbsd:openssh:8.0"
                            ],
                            "close-seen": "2022-03-11 16:22:22",
                            "message": "Detected service: SSH {{(OpenSSH_8.0)}}",
                            "product": "OpenSSH",
                            "transport": "tcp",
                            "version": "8.0"
                        },
                        "geoIpLocation": "US",
                        "grade": "GOOD",
                        "remediations": [
                            {
                                "helpText": "This port was observed running SSH, which is used for sending and receiving secure communication.",
                                "message": "Detected service: SSH (OpenSSH_8.0)",
                                "remediationTip": ""
                            }
                        ],
                        "rollupEndDate": "2022-01-28",
                        "rollupStartDate": "2022-01-28",
                        "searchableDetails": "Detected service: SSH {{(OpenSSH_8.0)}},tcp,OpenSSH"
                    },
                    "evidenceKey": "X.X.X.1:22",
                    "firstSeen": "2022-01-28",
                    "lastSeen": "2022-01-28",
                    "riskCategory": "Diligence",
                    "riskVector": "open_ports",
                    "riskVectorLabel": "Open Ports",
                    "rolledupObservationId": "11A3==",
                    "severity": 1,
                    "severityCategory": "minor",
                    "temporaryId": "A9yq"
                },
                {
                    "affectsRating": true,
                    "assetOverrides": [
                        {
                            "asset": "X.X.X.2",
                            "importance": "high",
                            "overrideImportance": "high"
                        }
                    ],
                    "assets": [
                        {
                            "asset": "X.X.X.2",
                            "category": "critical",
                            "importance": 0.49,
                            "isIp": true
                        }
                    ],
                    "attributedCompanies": [
                        {
                            "guid": "00000000-0000-0000-0000-000000000002",
                            "name": "Saperix Lab"
                        },
                        {
                            "guid": "00000000-0000-0000-0000-000000000001",
                            "name": "Saperix, Inc."
                        }
                    ],
                    "details": {
                        "checkPass": "",
                        "country": "United States",
                        "destPort": 143,
                        "geoIpLocation": "US",
                        "grade": "GOOD",
                        "observedIps": [
                            "X.X.X.2:143"
                        ],
                        "rollupEndDate": "2022-03-01",
                        "rollupStartDate": "2021-01-04"
                    },
                    "evidenceKey": "X.X.X.2:143",
                    "firstSeen": "2021-01-04",
                    "lastSeen": "2022-03-01",
                    "remainingDecay": 32,
                    "riskCategory": "Diligence",
                    "riskVector": "ssl_configurations",
                    "riskVectorLabel": "SSL Configurations",
                    "rolledupObservationId": "10A==",
                    "severity": 1,
                    "severityCategory": "minor",
                    "temporaryId": "A9yq"
                }
            ],
            "guid": "00000000-0000-0000-0000-000000000001"
        },
        "Page": {
            "count": 2441,
            "name": "bitsight-company-findings-get",
            "next": "https://api.bitsighttech.com/v1/companies/00000000-0000-0000-0000-000000000001/findings?expand=attributed_companies&first_seen_gte=2021-01-01&last_seen_lte=2022-03-01&limit=2&offset=2&unsampled=true",
            "previous": null
        }
    }
}
```

#### Human Readable Output

>### Company findings:
>Total Findings: 2441
>|Evidence Key|Risk Vector Label|First Seen|Last Seen|ID|Risk Category|Severity|Asset Category|Finding Grade|
>|---|---|---|---|---|---|---|---|---|
>| X.X.X.1:22 | Open Ports | 2022-01-28 | 2022-01-28 | A9Jq | Diligence | minor | X.X.X.1: Low | Good |
>| X.X.X.2:143 | SSL Configurations | 2021-01-04 | 2022-03-01 | A9yq | Diligence | minor | X.X.X.2: Critical | Good |


### bitsight-companies-guid-get
***
Bitsight command to get list of companies and GUID.


#### Base Command

`bitsight-companies-guid-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BitSight.Company.name | String | Name of this company. | 
| BitSight.Company.shortname | String | The abbreviated name of this company. | 
| BitSight.Company.guid | String | The unique identifier of this company. | 
| BitSight.Company.customId | String | The customizable ID assigned to this company. | 
| BitSight.Company.networkSizeV4 | Number | The number of IPv4 addresses attributed to this company. | 
| BitSight.Company.rating | Number | The most recent security rating of this company. | 
| BitSight.Company.ratingDate | Date | The date when the rating report for this company was generated. | 
| BitSight.Company.dateAdded | Date | The date when this company was added to your portfolio. | 
| BitSight.Company.industry | String | The industry of this company. | 
| BitSight.Company.industrySlug | String | The slug name of this company's industry. | 
| BitSight.Company.subIndustry | String | The sub-industry of this company. | 
| BitSight.Company.subIndustrySlug | String | The slug name of this company's sub-industry. | 
| BitSight.Company.type | String | The rating type. | 
| BitSight.Company.logo | String | The URL in the Bitsight platform to this company's logo image. | 
| BitSight.Company.sparkline | String | The URL in the Bitsight platform to this company's historical ratings trend line. | 
| BitSight.Company.externalId | Number | The external ID assigned to this company. | 
| BitSight.Company.subscriptionType | String | The subscription type used to monitor this company. | 
| BitSight.Company.subscriptionTypeKey | String | The slug name of the subscription type used to monitor this company. | 
| BitSight.Company.primaryDomain | String | The primary domain of this company. | 
| BitSight.Company.securityGrade | String | For internal Bitsight use. | 
| BitSight.Company.gradeDate | Date | For internal Bitsight use. | 
| BitSight.Company.displayURL | String | The URL in the Bitsight platform to this company's overview page. | 
| BitSight.Company.href | String | The URL in the Bitsight platform to this company's page. | 
| BitSight.MyCompany.guid | String | The unique identifier of my company. | 

#### Command example
```!bitsight-companies-guid-get```
#### Context Example
```json
{
    "BitSight": {
        "Company": [
            {
                "dateAdded": "2020-09-03",
                "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000001/overview/",
                "externalId": 14885770,
                "guid": "00000000-0000-0000-0000-000000000001",
                "href": "https://api.bitsighttech.com/v1/companies/00000000-0000-0000-0000-000000000001",
                "industry": "Technology",
                "industrySlug": "technology",
                "logo": "https://api.bitsighttech.com/ratings/v1/companies/00000000-0000-0000-0000-000000000001/logo-image",
                "name": "Saperix, Inc.",
                "networkSizeV4": 4169,
                "primaryDomain": "saperix.com",
                "rating": 640,
                "ratingDate": "2022-03-29",
                "shortname": "Saperix",
                "sparkline": "https://api.bitsighttech.com/ratings/v1/companies/00000000-0000-0000-0000-000000000001/sparkline?size=small",
                "subIndustry": "Computer & Network Security",
                "subIndustrySlug": "computer_network_security",
                "subscriptionType": "Total Risk Monitoring",
                "subscriptionTypeKey": "continuous_monitoring",
                "type": "CURATED"
            },
            {
                "dateAdded": "2021-11-23",
                "displayUrl": "https://service.bitsighttech.com/app/company/00000000-0000-0000-0000-000000000002/overview/",
                "externalId": 51818179,
                "guid": "00000000-0000-0000-0000-000000000002",
                "href": "https://api.bitsighttech.com/v1/companies/00000000-0000-0000-0000-000000000002",
                "industry": "Technology",
                "industrySlug": "technology",
                "logo": "https://api.bitsighttech.com/ratings/v1/companies/00000000-0000-0000-0000-000000000002/logo-image",
                "name": "Saperix Corporate",
                "networkSizeV4": 4032,
                "primaryDomain": "saperix.com",
                "rating": 730,
                "ratingDate": "2022-03-29",
                "shortname": "Saperix Corporate",
                "sparkline": "https://api.bitsighttech.com/ratings/v1/companies/00000000-0000-0000-0000-000000000002/sparkline?size=small",
                "subIndustry": "Computer & Network Security",
                "subIndustrySlug": "computer_network_security",
                "subscriptionType": "MySubsidiary",
                "subscriptionTypeKey": "my_subsidiary",
                "type": "CURATED,SELF-PUBLISHED"
            }
        ],
        "MyCompany": {
            "guid": "00000000-0000-0000-0000-000000000001"
        }
    }
}
```

#### Human Readable Output

>### Companies:
>My Company: 00000000-0000-0000-0000-000000000001
> 
> 
>|Company Name|Company Short Name|GUID|Rating|
>|---|---|---|---|
>| Saperix, Inc. | Saperix | 00000000-0000-0000-0000-000000000001 | 640 |
>| Saperix Corporate | Saperix Corporate | 00000000-0000-0000-0000-000000000002 | 730 |
