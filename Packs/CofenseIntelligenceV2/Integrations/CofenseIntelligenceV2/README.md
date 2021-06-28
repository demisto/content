Use the Cofense Intelligence integration to check the reputation of URLs, IP addresses, file hashes, and email addresses.
This integration was integrated and tested with version 2 of Cofense Intelligence

Some changes have been made that might affect your existing content. For more information, see [Breaking Changes](#Breaking-changes-from-previous-versions-of-this-integration).

Search for threats associated with an indicator.
The verdict (Unknown, Benign, Suspicious, Malicious) of each threat is determined by the impact (None, Minor, Moderate, Major) of its associated web locations as detected in cofense,  along with a threshold value that is being set by the user (when configuring the instance):

for each Threat, if the searched indicator is found in the report - we will use its impact as the verdict, else will use the maximal impact in the report. 

Example: 
Threshold = Major (Default value)

| **Threat ID** | **Impact** | **Dbot score** | **Adjusted Verdict** |
| --- | --- | --- | --- |
| 1 | Minor | Suspicious | Suspicious |
| 2 | Moderate | Suspicious | Suspicious |
| 3  | Major | Bad | Malicious |
## Configure CofenseIntelligenceV2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CofenseIntelligenceV2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The Api endpoint (https://www.threathq.com) | True |
    | Token Name | Cofense API Token name | True |
    | Password | Cofense API password | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | IP Threshold | Threshold for IP related threats' severity. | False |
    | File Threshold | Threshold for file related threats' severity. | False |
    | URL Threshold | Threshold for URL related threats' severity. | False |
    | Email Threshold | Threshold for email related threats' severity. | False |
    | Time limit for collecting data | The maximum number of days from which to start returning data. 90 days is recomended by Cofense. |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Checks the reputation of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 
| days_back | The maximum number of days from which to start returning data. 90 days is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.ASN | unknown | The autonomous system name for the IP address. | 
| IP.GEO.Location | unknown | The geolocation where the IP address is located, in the format of latitude: longitude. | 
| IP.GEO.Country | unknown | The country in which the IP address is located. | 
| IP.Address | unknown | IP address. | 
| IP.MalwareFamily | unknown | The malware family associated with the IP address. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.IP.Data | String | The IP address. | 
| CofenseIntelligence.IP.Threats.id | Number | Threat ID. | 
| CofenseIntelligence.IP.Threats.feeds.id | Number | Integer identifier for this feed. | 
| CofenseIntelligence.IP.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed. | 
| CofenseIntelligence.IP.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed. | 
| CofenseIntelligence.IP.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed. | 
| CofenseIntelligence.IP.Threats.feeds.displayName | String | Human readable name for this feed. | 
| CofenseIntelligence.IP.Threats.blockSet.malwareFamily.familyName | String | The name of the malware family. | 
| CofenseIntelligence.IP.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works. | 
| CofenseIntelligence.IP.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0. | 
| CofenseIntelligence.IP.Threats.blockSet.confidence | Number | The level of confidence in the threats block. | 
| CofenseIntelligence.IP.Threats.blockSet.blockType | String | Data type of the watchlist item. | 
| CofenseIntelligence.IP.Threats.blockSet.roleDescription | String | Description of infrastructure type. | 
| CofenseIntelligence.IP.Threats.blockSet.role | String | Infrastructure type. | 
| CofenseIntelligence.IP.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of the infrastructure type being used. | 
| CofenseIntelligence.IP.Threats.blockSet.data | String | Domain name or an IP address. | 
| CofenseIntelligence.IP.Threats.blockSet.data_1 | String | Either a domain name or an IP address. | 
| CofenseIntelligence.IP.Threats.campaignBrandSet.totalCount | Number | Total number of individual messages associated with this brand. | 
| CofenseIntelligence.IP.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.IP.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.IP.Threats.domainSet.totalCount | Number | Total number of the instances of each item named. | 
| CofenseIntelligence.IP.Threats.domainSet.domain | String | Sender domain name. | 
| CofenseIntelligence.IP.Threats.senderEmailSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.IP.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.IP.Threats.executableSet.malwareFamily.familyName | String | Family name of the malware. | 
| CofenseIntelligence.IP.Threats.executableSet.malwareFamily.description | String | The name of the malware family. | 
| CofenseIntelligence.IP.Threats.executableSet.vendorDetections.detected | Boolean | Whether an executable was detected. | 
| CofenseIntelligence.IP.Threats.executableSet.vendorDetections.threatVendorName | String | Name of the antivirus vendor. | 
| CofenseIntelligence.IP.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection. | 
| CofenseIntelligence.IP.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection. | 
| CofenseIntelligence.IP.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery. | 
| CofenseIntelligence.IP.Threats.executableSet.severityLevel | String | The malware infection severity level. | 
| CofenseIntelligence.IP.Threats.executableSet.fileNameExtension | String | The file extension. | 
| CofenseIntelligence.IP.Threats.executableSet.md5Hex | String | The MD5 hash of the file. | 
| CofenseIntelligence.IP.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file. | 
| CofenseIntelligence.IP.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file. | 
| CofenseIntelligence.IP.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file. | 
| CofenseIntelligence.IP.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file. | 
| CofenseIntelligence.IP.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file. | 
| CofenseIntelligence.IP.Threats.executableSet.executableSubtype.description | String | The description of the executable file. | 
| CofenseIntelligence.IP.Threats.senderIpSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.IP.Threats.senderIpSet.ip | String | One of possibly many IP addresses used in the delivery of the email. | 
| CofenseIntelligence.IP.Threats.senderNameSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.IP.Threats.senderNameSet.name | String | The friendly name of the sender of the email. | 
| CofenseIntelligence.IP.Threats.subjectSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.IP.Threats.subjectSet.subject | String | Email subject line. | 
| CofenseIntelligence.IP.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated. | 
| CofenseIntelligence.IP.Threats.firstPublished | Date | Timestamp of when this campaign was initially published. | 
| CofenseIntelligence.IP.Threats.label | String | Human readable name for this campaign. | 
| CofenseIntelligence.IP.Threats.executiveSummary | String | Analyst written summary of the campaign. | 
| CofenseIntelligence.IP.Threats.hasReport | Boolean | Whether this campaign has a written report associated with it. | 
| CofenseIntelligence.IP.Threats.reportURL | String | Direct URL to the human readable report for this campaign. | 
| CofenseIntelligence.IP.Threats.apiReportURL | String | URL to the human readable report for this campaign. | 
| CofenseIntelligence.IP.Threats.threatDetailURL | String | T3 report URL. | 
| CofenseIntelligence.IP.Threats.malwareFamilySet.familyName | String | Family name of the malware. | 
| CofenseIntelligence.IP.Threats.malwareFamilySet.description | String | Description of the malware family set. | 
| CofenseIntelligence.IP.Threats.threatType | String | If malware, will have value ‘malware’, otherwise it is empty. | 



#### Command Example
```!ip ip=8.8.8.8 using=CofenseIntelligenceV2_instance```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "IP": {
            "Data": "8.8.8.8",
            "Threats": [
                {
                    "apiReportURL": "https://www.threathq.com/apiv1/t3/malware/125002/html",
                    "blockSet": [
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "8.8.8.8",
                            "data_1": "8.8.8.8",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 23456,
                                "continentCode": "AS",
                                "continentName": "Asia",
                                "countryIsoCode": "IN",
                                "countryName": "India",
                                "ip": "8.8.8.8",
                                "isp": "Seema Infotech",
                                "latitude": 20,
                                "longitude": 77,
                                "lookupOn": 1616428612903,
                                "organization": "Seema Infotech",
                                "timeZone": "Asia/Kolkata"
                            }
                    ],
                    "campaignBrandSet": [
                        {
                            "brand": {
                                "id": 2051,
                                "text": "None"
                            },
                            "totalCount": 1
                        }
                    ],
                    "campaignLanguageSet": [
                        {
                            "languageDefinition": {
                                "family": "Indo-European",
                                "isoCode": "en",
                                "name": "English",
                                "nativeName": "English"
                            }
                        }
                    ],
                    "deliveryMechanisms": [],
                    "domainSet": [],
                    "executableSet": [
                    ],
                    "executiveSummary": "summary",
                    "extractedStringSet": [],
                    "feeds": [
                    ],
                    "firstPublished": 1616428569154,
                    "hasReport": true,
                    "id": 125002,
                    "label": "Finance - FormGrabber",
                    "lastPublished": 1616428570962,
                    "malwareFamilySet": [
                        {
                            "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                            "familyName": "FormGrabber"
                        }
                    ],
                    "naicsCodes": [],
                    "relatedSearchTags": [],
                    "reportURL": "link",
                    "senderEmailSet": [],
                    "senderIpSet": [],
                    "senderNameSet": [],
                    "spamUrlSet": [],
                    "subjectSet": [
                        {
                            "subject": "subject",
                            "totalCount": 1
                        }
                    ],
                    "threatDetailURL": "",
                    "threatType": "MALWARE"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "ip",
        "Vendor": "CofenseIntelligenceV2"
    },
    "IP": {
        "ASN": 23456,
        "Address": "8.8.8.8",
        "Geo": {
            "Country": "IN",
            "Location": "20.0:77.0"
        },
        "MalwareFamily": "FormGrabber"
    }
}
```

#### Human Readable Output

>### Cofense IP Reputation for IP 8.8.8.8
>|Threat ID|Threat Types|Verdict|Executive Summary|Campaign|Last Published|ASN|Country|Threat Report|
>|---|---|---|---|---|---|---|---|---|
>| 125002 | type | Suspicious | summary |  Campaign | 2021-03-22 15:56:10 | ASN |country | link


### cofense-search
***
Searches for extracted strings identified within malware campaigns.


#### Base Command

`cofense-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| str | String to search. | Required | 
| limit | Maximum number of strings to search. Default is 10. | Optional | 
| days_back | Limit the number of days from which we should start returning data. 90 days limit is recommended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CofenseIntelligence.Threats.id | Number | Threat ID. | 
| CofenseIntelligence.Threats.feeds.id | Number | Integer identifier for this feed. | 
| CofenseIntelligence.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed. | 
| CofenseIntelligence.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed. | 
| CofenseIntelligence.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed. | 
| CofenseIntelligence.Threats.feeds.displayName | String | Human readable name for this feed. | 
| CofenseIntelligence.Threats.blockSet.malwareFamily.familyName | String | The name of the malware family. | 
| CofenseIntelligence.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works. | 
| CofenseIntelligence.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0. | 
| CofenseIntelligence.Threats.blockSet.confidence | Number | The level of confidence in the threats block. | 
| CofenseIntelligence.Threats.blockSet.blockType | String | Data type of the watchlist item. | 
| CofenseIntelligence.Threats.blockSet.roleDescription | String | Description of infrastructure type. | 
| CofenseIntelligence.Threats.blockSet.role | String | Infrastructure type. | 
| CofenseIntelligence.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of the infrastructure type being used. | 
| CofenseIntelligence.Threats.blockSet.data | String | Domain name or an IP address. | 
| CofenseIntelligence.Threats.blockSet.data_1 | String | Either a domain name or an IP address. | 
| CofenseIntelligence.Threats.campaignBrandSet.totalCount | Number | Total number of individual messages associated with this brand. | 
| CofenseIntelligence.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.Threats.domainSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Threats.domainSet.domain | String | Sender domain name. | 
| CofenseIntelligence.Threats.senderEmailSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Threats.executableSet.malwareFamily.familyName | String | Family name of malware. | 
| CofenseIntelligence.Threats.executableSet.malwareFamily.description | String | The name of the malware family. | 
| CofenseIntelligence.Threats.executableSet.vendorDetections.detected | Boolean | Whether an executable was detected. | 
| CofenseIntelligence.Threats.executableSet.vendorDetections.threatVendorName | String | Name of the antivirus vendor. | 
| CofenseIntelligence.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection. | 
| CofenseIntelligence.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection. | 
| CofenseIntelligence.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery. | 
| CofenseIntelligence.Threats.executableSet.severityLevel | String | The malware infection severity level. | 
| CofenseIntelligence.Threats.executableSet.fileNameExtension | String | The file extension. | 
| CofenseIntelligence.Threats.executableSet.md5Hex | String | The MD5 hash of the file. | 
| CofenseIntelligence.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file. | 
| CofenseIntelligence.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file. | 
| CofenseIntelligence.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file. | 
| CofenseIntelligence.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file. | 
| CofenseIntelligence.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file. | 
| CofenseIntelligence.Threats.executableSet.executableSubtype.description | String | The description of the executable file. | 
| CofenseIntelligence.Threats.senderIpSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Threats.senderNameSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Threats.senderNameSet.name | String | The friendly name of the sender of the email. | 
| CofenseIntelligence.Threats.subjectSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Threats.subjectSet.subject | String | Email subject line. | 
| CofenseIntelligence.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated. | 
| CofenseIntelligence.Threats.firstPublished | Date | Timestamp of when this campaign was initially published. | 
| CofenseIntelligence.Threats.label | String | Human readable name for this campaign. | 
| CofenseIntelligence.Threats.executiveSummary | String | .Analyst written summary of the campaign. | 
| CofenseIntelligence.Threats.hasReport | Boolean | Whether this campaign has a written report associated with it. | 
| CofenseIntelligence.Threats.reportURL | String | Direct URL to human readable report for this campaign. | 
| CofenseIntelligence.Threats.apiReportURL | String | URL to human readable report for this campaign. | 
| CofenseIntelligence.Threats.threatDetailURL | String | T3 report URL. | 
| CofenseIntelligence.Threats.malwareFamilySet.familyName | String | Family name of malware. | 
| CofenseIntelligence.Threats.malwareFamilySet.description | String | Description of the malware family set. | 
| CofenseIntelligence.Threats.threatType | String | If malware, will have value ‘malware’, otherwise it is empty. | 



#### Command Example
```!cofense-search str=border using=CofenseIntelligenceV2_instance```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "Threats": {
            "apiReportURL": "url",
            "blockSet": [
            ],
            "campaignBrandSet": [
            ],
            "campaignLanguageSet": [
                {
                    "languageDefinition": {
                        "family": "Indo-European",
                        "isoCode": "en",
                        "name": "English",
                        "nativeName": "English"
                    }
                }
            ],
            "deliveryMechanisms": [],
            "domainSet": [
                {
                    "domain": "szmc.goldentec.com",
                    "totalCount": 3
                }
            ],
            "executableSet": [],
            "executiveSummary": "summary",
            "extractedStringSet": [
                {
                    "data": "border",
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    }
                }
            ],
            "feeds": [
                {
                    "displayName": "Cofense",
                    "id": 23,
                    "permissions": {
                        "OWNER": false,
                        "READ": true,
                        "WRITE": false
                    }
                }
            ],
            "firstPublished": 1618498390036,
            "hasReport": true,
            "id": 178991,
            "label": "Refund - Credential Phishing",
            "lastPublished": 1618498391774,
            "malwareFamilySet": [
                {
                    "description": "An instance of credential phishing",
                    "familyName": "Credential Phishing"
                }
            ],
            "naicsCodes": [],
            "relatedSearchTags": [],
            "reportURL": "link",
            "senderEmailSet": [
            ],
            "senderIpSet": [],
            "senderNameSet": [
            ],
            "threatDetailURL": "link",
            "threatType": "MALWARE"
        }
    }
}
```

#### Human Readable Output

>### There are 1 threats regarding your string search
>
>|Threat ID|Threat Types|Executive Summary|Campaign|Last Published|Threat Report|
>|---|---|---|---|---|---|
>| 178991 | summary | Refund - Credential Phishing | 2021-04-15 14:53:11 | Link |


### file
***
Checks the reputation of a file hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The MD5 hash of the file to check. | Required | 
| days_back | The maximum number of days from which to start returning data. 90 days is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Extension | unknown | The file extension. | 
| File.MD5 | unknown | The MD5 hash of the file. | 
| File.Malicious.Description | unknown | A description explaining why the file was determined to be malicious. | 
| File.Malicious.Vendor | unknown | The vendor who reported the file as malicious. | 
| File.MalwareFamily | unknown | The malware family associated with the file. | 
| File.Name | unknown | The full file name. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.File.Data | String | The file hash. | 
| CofenseIntelligence.File.Threats.id | Number | Threat ID. | 
| CofenseIntelligence.File.Threats.feeds.id | Number | Integer identifier for this feed. | 
| CofenseIntelligence.File.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed. | 
| CofenseIntelligence.File.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed. | 
| CofenseIntelligence.File.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed. | 
| CofenseIntelligence.File.Threats.feeds.displayName | String | Human readable name for this feed. | 
| CofenseIntelligence.File.Threats.blockSet.malwareFamily.familyName | String | The name of the malware family. | 
| CofenseIntelligence.File.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works. | 
| CofenseIntelligence.File.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0. | 
| CofenseIntelligence.File.Threats.blockSet.confidence | Number | The level of confidence in the threats block. | 
| CofenseIntelligence.File.Threats.blockSet.blockType | String | Data type of the watchlist item. | 
| CofenseIntelligence.File.Threats.blockSet.roleDescription | String | Description of the infrastructure type. | 
| CofenseIntelligence.File.Threats.blockSet.role | String | Infrastructure type. | 
| CofenseIntelligence.File.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of the infrastructure type being used. | 
| CofenseIntelligence.File.Threats.blockSet.data | String | Domain name or an IP address. | 
| CofenseIntelligence.File.Threats.blockSet.data_1 | String | Either a domain name or an IP address. | 
| CofenseIntelligence.File.Threats.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand. | 
| CofenseIntelligence.File.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.File.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.File.Threats.domainSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.File.Threats.domainSet.domain | String | Sender domain name. | 
| CofenseIntelligence.File.Threats.senderEmailSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.File.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.File.Threats.executableSet.malwareFamily.familyName | String | Family name of malware. | 
| CofenseIntelligence.File.Threats.executableSet.malwareFamily.description | String | The name of the malware family. | 
| CofenseIntelligence.File.Threats.executableSet.vendorDetections.detected | Boolean | Whether an executable was detected. | 
| CofenseIntelligence.File.Threats.executableSet.vendorDetections.threatVendorName | String | Name of the antivirus vendor. | 
| CofenseIntelligence.File.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection. | 
| CofenseIntelligence.File.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection. | 
| CofenseIntelligence.File.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery. | 
| CofenseIntelligence.File.Threats.executableSet.severityLevel | String | The malware infection severity level. | 
| CofenseIntelligence.File.Threats.executableSet.fileNameExtension | String | The file extension. | 
| CofenseIntelligence.File.Threats.executableSet.md5Hex | String | The MD5 hash of the file. | 
| CofenseIntelligence.File.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file. | 
| CofenseIntelligence.File.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file. | 
| CofenseIntelligence.File.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file. | 
| CofenseIntelligence.File.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file. | 
| CofenseIntelligence.File.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file. | 
| CofenseIntelligence.File.Threats.executableSet.executableSubtype.description | String | The description of the executable file. | 
| CofenseIntelligence.File.Threats.senderIpSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.File.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.File.Threats.senderNameSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.File.Threats.senderNameSet.name | String | The friendly name of the sender of the email. | 
| CofenseIntelligence.File.Threats.subjectSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.File.Threats.subjectSet.subject | String | Email subject line. | 
| CofenseIntelligence.File.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated. | 
| CofenseIntelligence.File.Threats.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.File.Threats.label | String | Human readable name for this campaign. | 
| CofenseIntelligence.File.Threats.executiveSummary | String | Analyst written summary of the campaign. | 
| CofenseIntelligence.File.Threats.hasReport | Boolean | Whether this campaign has a written report associated with it. | 
| CofenseIntelligence.File.Threats.reportURL | String | Direct URL to human readable report for this campaign. | 
| CofenseIntelligence.File.Threats.apiReportURL | String | URL to human readable report for this campaign. | 
| CofenseIntelligence.File.Threats.threatDetailURL | String | T3 report URL. | 
| CofenseIntelligence.File.Threats.malwareFamilySet.familyName | String | Family name of the malware. | 
| CofenseIntelligence.File.Threats.malwareFamilySet.description | String | Description of the malware family set. | 
| CofenseIntelligence.File.Threats.threatType | String | If malware, will have value ‘malware’, otherwise it is empty. | 

#### Command Example
```!file file=9798ba6199168e6d2cf205760ea683d1 using=CofenseIntelligenceV2_instance```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "File": {
            "Data": "9798ba6199168e6d2cf205760ea683d1",
            "Threats": [
                {
                    "apiReportURL": "https://www.threathq.com/apiv1/t3/malware/158959/html",
                    "blockSet": [
                        {
                            "blockType": "Email",
                            "confidence": 0,
                            "data": "email@email.com",
                            "data_1": "email@email.com",
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                                "familyName": "Agent Tesla"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },

                    ],
                    "campaignBrandSet": [
                        {
                            "brand": {
                                "id": 2051,
                                "text": "None"
                            },
                            "totalCount": 1
                        }
                    ],
                    "campaignLanguageSet": [
                        {
                            "languageDefinition": {
                                "family": "Indo-European",
                                "isoCode": "en",
                                "name": "English",
                                "nativeName": "English"
                            }
                        }
                    ],
                    "deliveryMechanisms": [
                        {
                            "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                            "mechanismName": "CVE-2017-11882"
                        }
                    ],
                    "domainSet": [],
                    "executableSet":[ 
                    ],
                    "executiveSummary": "summary",
                    "extractedStringSet": [],
                    "feeds": [
                        {
                            "displayName": "Cofense",
                            "id": 23,
                            "permissions": {
                                "OWNER": false,
                                "READ": true,
                                "WRITE": false
                            }
                        }
                    ],
                    "firstPublished": 1616096866503,
                    "hasReport": true,
                    "id": 158959,
                    "label": "Order - CVE-2017-11882, Agent Tesla Keylogger",
                    "lastPublished": 1616096868262,
                    "malwareFamilySet": [
                        {
                            "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                            "familyName": "Agent Tesla"
                        }
                    ],
                    "naicsCodes": [],
                    "relatedSearchTags": [],
                    "reportURL": "link",
                    "senderEmailSet": [],
                    "senderIpSet": [],
                    "senderNameSet": [],
                    "spamUrlSet": [],
                    "subjectSet": [
                        {
                            "subject": "RFQ ",
                            "totalCount": 1
                        }
                    ],
                    "threatDetailURL": "url",
                    "threatType": "MALWARE"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "9798ba6199168e6d2cf205760ea683d1",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "CofenseIntelligenceV2"
    },
    "File": {
        "Extension": "exe",
        "MD5": "9798ba6199168e6d2cf205760ea683d1",
        "Malicious": {
            "Description": null,
            "Vendor": "CofenseIntelligenceV2"
        },
        "MalwareFamily": "Agent Tesla",
        "Name": "bobbyx.exe"
    }
}
```

#### Human Readable Output

>### Cofense file Reputation for file 9798ba6199168e6d2cf205760ea683d1
>|Threat ID|Threat Types|Verdict|Executive Summary|Campaign|Last Published|Threat Report|
>|---|---|---|---|---|---|---|
>| 158959 |type | Malicious |  summary | campaign name | 2021-03-18 19:47:48 | Link |


### email
***
Checks the reputation of an email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Sender email address to check. | Required | 
| days_back | The maximum number of days from which to start returning data. 90 days is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.Email.Data | String | The email address. | 
| CofenseIntelligence.Email.Threats.id | Number | Threat ID. | 
| CofenseIntelligence.Email.Threats.feeds.id | Number | Integer identifier for this feed. | 
| CofenseIntelligence.Email.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed. | 
| CofenseIntelligence.Email.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed. | 
| CofenseIntelligence.Email.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed. | 
| CofenseIntelligence.Email.Threats.feeds.displayName | String | Human readable name for this feed. | 
| CofenseIntelligence.Email.Threats.blockSet.malwareFamily.familyName | String | Names and describes the malware families. | 
| CofenseIntelligence.Email.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works. | 
| CofenseIntelligence.Email.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0. | 
| CofenseIntelligence.Email.Threats.blockSet.confidence | Number | The level of confidence in the threats block. | 
| CofenseIntelligence.Email.Threats.blockSet.blockType | String | Data type of the watchlist item. | 
| CofenseIntelligence.Email.Threats.blockSet.roleDescription | String | Description of the infrastructure type. | 
| CofenseIntelligence.Email.Threats.blockSet.role | String | Infrastructure type. | 
| CofenseIntelligence.Email.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of the infrastructure type being used. | 
| CofenseIntelligence.Email.Threats.blockSet.data | String | Domain name or an IP address. | 
| CofenseIntelligence.Email.Threats.blockSet.data_1 | String | Either a domain name or an IP address. | 
| CofenseIntelligence.Email.Threats.campaignBrandSet.totalCount | Number | Total number of individual messages associated with this brand. | 
| CofenseIntelligence.Email.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.Email.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.Email.Threats.domainSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Email.Threats.domainSet.domain | String | Sender domain name. | 
| CofenseIntelligence.Email.Threats.senderEmailSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Email.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Email.Threats.executableSet.malwareFamily.familyName | String | Family name of the malware. | 
| CofenseIntelligence.Email.Threats.executableSet.malwareFamily.description | String | The name of the malware family. | 
| CofenseIntelligence.Email.Threats.executableSet.vendorDetections.detected | Boolean | Whether an executable was detected. | 
| CofenseIntelligence.Email.Threats.executableSet.vendorDetections.threatVendorName | String | Name of the antivirus vendor. | 
| CofenseIntelligence.Email.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection. | 
| CofenseIntelligence.Email.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection. | 
| CofenseIntelligence.Email.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery. | 
| CofenseIntelligence.Email.Threats.executableSet.severityLevel | String | The malware infection severity level. | 
| CofenseIntelligence.Email.Threats.executableSet.fileNameExtension | String | The file extension. | 
| CofenseIntelligence.Email.Threats.executableSet.md5Hex | String | The MD5 hash of the file. | 
| CofenseIntelligence.Email.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file. | 
| CofenseIntelligence.Email.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file. | 
| CofenseIntelligence.Email.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file. | 
| CofenseIntelligence.Email.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file. | 
| CofenseIntelligence.Email.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file. | 
| CofenseIntelligence.Email.Threats.executableSet.executableSubtype.description | String | The description of the executable file. | 
| CofenseIntelligence.Email.Threats.senderIpSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Email.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Email.Threats.senderNameSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Email.Threats.senderNameSet.name | String | The friendly name of the sender of the email. | 
| CofenseIntelligence.Email.Threats.subjectSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Email.Threats.subjectSet.subject | String | Email subject line. | 
| CofenseIntelligence.Email.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated. | 
| CofenseIntelligence.Email.Threats.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.Email.Threats.label | String | Human readable name for this campaign. | 
| CofenseIntelligence.Email.Threats.executiveSummary | String | Analyst written summary of the campaign. | 
| CofenseIntelligence.Email.Threats.hasReport | Boolean | Whether this campaign has a written report associated with it. | 
| CofenseIntelligence.Email.Threats.reportURL | String | Direct URL to human readable report for this campaign. | 
| CofenseIntelligence.Email.Threats.apiReportURL | String | URL to human readable report for this campaign. | 
| CofenseIntelligence.Email.Threats.threatDetailURL | String | T3 report URL. | 
| CofenseIntelligence.Email.Threats.malwareFamilySet.familyName | String | Family name of the malware. | 
| CofenseIntelligence.Email.Threats.malwareFamilySet.description | String | Description of the malware family set. | 
| CofenseIntelligence.Email.Threats.threatType | String | If malware, will have value ‘malware’, otherwise it is empty. | 

#### Command Example
```!email email=email@email.com using=CofenseIntelligenceV2_instance_1_copy```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "Email": {
            "Data": "email@email.com",
            "Threats": [
                {
                    "apiReportURL": "report",
                    "blockSet": [
                        {
                            "blockType": "Email",
                            "confidence": 0,
                            "data": "email@email.com",
                            "data_1": "email@email.com",
                            "impact": "Major",
                            "malwareFamily": {
                                "familyName": "Agent Tesla"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        }
                    ],
                    "campaignBrandSet": [
                        {
                            "brand": {
                                "id": 2051,
                                "text": "None"
                            },
                            "totalCount": 1
                        }
                    ],
                    "campaignLanguageSet": [
                        {
                            "languageDefinition": {
                                "family": "Indo-European",
                                "isoCode": "en",
                                "name": "English",
                                "nativeName": "English"
                            }
                        }
                    ],
                    "domainSet": [],
                    "executableSet": [],
                        
                    "executiveSummary": "summary",
                    "extractedStringSet": [],
 
                    "firstPublished": 1616096866503,
                    "hasReport": true,
                    "id": 158959,
                    "label": "Order - CVE-2017-11882, Agent Tesla Keylogger",
                    "lastPublished": 1616096868262,
                    "malwareFamilySet": [
                        {
                            "familyName": "Agent Tesla"
                        }
                    ],
                    "naicsCodes": [],
                    "relatedSearchTags": [],
                    "reportURL": "report",
                    "senderEmailSet": [],
                    "senderIpSet": [],
                    "senderNameSet": [],
                    "spamUrlSet": [],
                    "subjectSet": [
                        {
                            "subject": "RFQ ",
                            "totalCount": 1
                        }
                    ],
                    "threatDetailURL": "url",
                    "threatType": "MALWARE"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "email@email.com",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "email",
        "Vendor": "CofenseIntelligenceV2"
    },
    "Email": {
        "Address": "email@email.com",
        "Domain": "sankapatrol.com"
    }
}
```

#### Human Readable Output

>### Cofense email Reputation for email email@email.com
>|Threat ID|Threat Types|Verdict|Executive Summary|Campaign|Last Published|Threat Report|
>|---|---|---|---|---|---|---|
>| 158959 | Type | Malicious | Summary | Campaign name | 2021-03-18 19:47:48 | link |


### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 
| days_back | The maximum number of days from which to start returning data. 90 days is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| URL.Data | string | The URL | 
| URL.Malicious.Description | string | A description of the malicious URL. | 
| URL.Malicious.Vendor | string | The vendor who reported the URL as malicious. | 
| CofenseIntelligence.URL.Data | String | The URL. | 
| CofenseIntelligence.URL.Threats.id | Number | Threat ID. | 
| CofenseIntelligence.URL.Threats.feeds.id | Number | Integer identifier for this feed. | 
| CofenseIntelligence.URL.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed. | 
| CofenseIntelligence.URL.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed. | 
| CofenseIntelligence.URL.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed. | 
| CofenseIntelligence.URL.Threats.feeds.displayName | String | Human readable name for this feed. | 
| CofenseIntelligence.URL.Threats.blockSet.malwareFamily.familyName | String | The name of the malware family. | 
| CofenseIntelligence.URL.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works. | 
| CofenseIntelligence.URL.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0. | 
| CofenseIntelligence.URL.Threats.blockSet.confidence | Number | The level of confidence in the threats block. | 
| CofenseIntelligence.URL.Threats.blockSet.blockType | String | Data type of the watchlist item. | 
| CofenseIntelligence.URL.Threats.blockSet.roleDescription | String | Description of the infrastructure type. | 
| CofenseIntelligence.URL.Threats.blockSet.role | String | Infrastructure type. | 
| CofenseIntelligence.URL.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of the infrastructure type being used. | 
| CofenseIntelligence.URL.Threats.blockSet.data | String | Domain name or an IP address. | 
| CofenseIntelligence.URL.Threats.blockSet.data_1 | String | Either a domain name or an IP address. | 
| CofenseIntelligence.URL.Threats.campaignBrandSet.totalCount | Number | Total number of individual messages associated with this brand. | 
| CofenseIntelligence.URL.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.URL.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.URL.Threats.domainSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.URL.Threats.domainSet.domain | String | Sender domain name. | 
| CofenseIntelligence.URL.Threats.senderEmailSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.URL.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.URL.Threats.executableSet.malwareFamily.familyName | String | Family name of the malware. | 
| CofenseIntelligence.URL.Threats.executableSet.malwareFamily.description | String | The name of the malware family. | 
| CofenseIntelligence.URL.Threats.executableSet.vendorDetections.detected | Boolean | Whether an executable was detected. | 
| CofenseIntelligence.URL.Threats.executableSet.vendorDetections.threatVendorName | String | Name of the antivirus vendor. | 
| CofenseIntelligence.URL.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection. | 
| CofenseIntelligence.URL.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection. | 
| CofenseIntelligence.URL.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery. | 
| CofenseIntelligence.URL.Threats.executableSet.severityLevel | String | The malware infection severity level. | 
| CofenseIntelligence.URL.Threats.executableSet.fileNameExtension | String | The file extension. | 
| CofenseIntelligence.URL.Threats.executableSet.md5Hex | String | The MD5 hash of the file. | 
| CofenseIntelligence.URL.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file. | 
| CofenseIntelligence.URL.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file. | 
| CofenseIntelligence.URL.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file. | 
| CofenseIntelligence.URL.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file. | 
| CofenseIntelligence.URL.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file. | 
| CofenseIntelligence.URL.Threats.executableSet.executableSubtype.description | String | The description of the executable file. | 
| CofenseIntelligence.URL.Threats.senderIpSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.URL.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.URL.Threats.senderNameSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.URL.Threats.senderNameSet.name | String | The friendly name of the sender of the email. | 
| CofenseIntelligence.URL.Threats.subjectSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.URL.Threats.subjectSet.subject | String | Email subject line. | 
| CofenseIntelligence.URL.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated. | 
| CofenseIntelligence.URL.Threats.firstPublished | Date | Timestamp of when this campaign was initially published. | 
| CofenseIntelligence.URL.Threats.label | String | Human readable name for this campaign. | 
| CofenseIntelligence.URL.Threats.executiveSummary | String | Analyst written summary of the campaign. | 
| CofenseIntelligence.URL.Threats.hasReport | Boolean | Whether this campaign has a written report associated with it. | 
| CofenseIntelligence.URL.Threats.reportURL | String | Direct URL to human readable report for this campaign. | 
| CofenseIntelligence.URL.Threats.apiReportURL | String | URL to human readable report for this campaign. | 
| CofenseIntelligence.URL.Threats.threatDetailURL | String | T3 report URL. | 
| CofenseIntelligence.URL.Threats.malwareFamilySet.familyName | String | Family name of the malware. | 
| CofenseIntelligence.URL.Threats.malwareFamilySet.description | String | Description of the malware family set. | 
| CofenseIntelligence.URL.Threats.threatType | String | If malware, will have value ‘malware’, otherwise it is empty. | 


#### Command Example
```!url url=url using=CofenseIntelligenceV2_instance```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "URL": {
            "Data": "url",
            "Threats": [
                {
                    "apiReportURL": "report",
                    "blockSet": [
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "url",
                            "data_1": "url",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "description",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.itool.group/cp5/",
                            "impact": "Major",
                            "malwareFamily": {
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                    ],
                    "campaignBrandSet": [
                        {
                            "brand": {
                                "id": 2051,
                                "text": "None"
                            },
                            "totalCount": 1
                        }
                    ],
                    "campaignLanguageSet": [
                        {
                            "languageDefinition": {
                                "family": "Indo-European",
                                "isoCode": "en",
                                "name": "English",
                                "nativeName": "English"
                            }
                        }
                    ],
                    "deliveryMechanisms": [],
                    "domainSet": [],
                    "executableSet": [
                        
                    ],
                    "executiveSummary": "Finance-themed campaign delivers FormGrabber.",
                    "extractedStringSet": [],
                    "hasReport": true,
                    "id": 125002,
                    "label": "Finance - FormGrabber",
                    "lastPublished": 1616428570962,
                    "malwareFamilySet": [
                        {
                            "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                            "familyName": "FormGrabber"
                        }
                    ],
                    "naicsCodes": [],
                    "relatedSearchTags": [],
                    "reportURL": "url",
                    "senderEmailSet": [],
                    "senderIpSet": [],
                    "senderNameSet": [],
                    "spamUrlSet": [],
                    "threatDetailURL": "url",
                    "threatType": "MALWARE"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "url",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "CofenseIntelligenceV2"
    },
    "URL": {
        "Data": "url",
        "Malicious": {
            "Description": null,
            "Vendor": "CofenseIntelligenceV2"
        }
    }
}
```

#### Human Readable Output

>### Cofense URL Reputation for url url
>|Threat ID|Threat Types|Verdict|Executive Summary|Campaign|Last Published|Threat Report|
>|---|---|---|---|---|---|---|
>| 125002 | threat type | Malicious | summary | 2021-03-22 15:56:10 |Link |

## Breaking changes from previous versions of this integration
The following sections list the changes in this version.
### Outputs
The following outputs were removed in this version:

In the *url* command:
* *Cofense.URL.Data* - this output was replaced by *CofenseIntelligence.URL.Data*.
* *Cofense.URL.Malicious.Vendor* - this output was replaced by *CofenseIntelligence.URL.Malicious.Vendor*.
* *Cofense.URL.Malicious.Description* - this output was replaced by *CofenseIntelligence.URL.Malicious.Description*.
* *Cofense.URL.Cofense.ThreatIDs* - this output was replaced by *CofenseIntelligence.URL.Cofense.ThreatIDs*.

In the *file* command:
* *Cofense.File.MD5* - this output was replaced by *CofenseIntelligence.File.MD5*.
* *Cofense.File.Malicious.Vendor* - this output was replaced by *CofenseIntelligence.File.Malicious.Vendor*.
* *Cofense.File.Malicious.Description* - this output was replaced by *CofenseIntelligence.File.Malicious.Description*.
* *Cofense.File.ThreatIDs* - this output was replaced by *CofenseIntelligence.File.ThreatIDs*.

In the *ip* command:
* *Cofense.IP.Data* - this output was replaced by *CofenseIntelligence.IP.Data*.
* *Cofense.IP.Malicious.Vendor* - this output was replaced by *CofenseIntelligence.IP.Malicious.Vendor*.
* *Cofense.IP.Malicious.Description* - this output was replaced by *CofenseIntelligence.IP.Malicious.Description*.
* *Cofense.IP.Cofense.ThreatIDs* - this output was replaced by *CofenseIntelligence.IP.Cofense.ThreatIDs*.

In the *email* command:
* *Account.Email.Malicious.Vendor* - this output was replaced by *CofenseIntelligence.Email.Malicious.Vendor*.
* *Account.Email.Malicious.Description* - this output was replaced by *CofenseIntelligence.Email.Malicious.Description*.
* *Cofense.Email.Data* - this output was replaced by *CofenseIntelligence.Email.Data*.
* *Cofense.Email.Malicious.Vendor* - this output was replaced by *CofenseIntelligence.Email.Malicious.Vendor*.
* *Cofense.Email.Malicious.Description* - this output was replaced by *CofenseIntelligence.Email.Malicious.Description*.
* *Cofense.Email.Cofense.ThreatIDs* - this output was replaced by *CofenseIntelligence.Email.Cofense.ThreatIDs*.

In the *cofense-search* command:
* *Cofense.NumOfThreats* - this output was replaced by *CofenseIntelligence.NumOfThreats*.
* *Cofense.String* - this output was replaced by *CofenseIntelligence.String*.

## Additional Considerations for this Version
* Added an option to Limit the number of days from which we should start returning data. 90 days limit is recommended by Cofense.