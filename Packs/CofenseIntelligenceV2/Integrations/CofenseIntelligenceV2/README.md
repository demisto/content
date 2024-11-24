Use the Cofense Intelligence integration to check the reputation of domains, URLs, IP addresses, file hashes, and email addresses.
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
## Configure CofenseIntelligenceV2 in Cortex


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
| Domain Threshold | Threshold for domain related threats' severity. | False |
| Time limit for collecting data | The maximum number of days from which to start returning data. 90 days is recomended by Cofense. |
| Create relationships | Create relationships between indicators as part of Enrichment. | False |
| Score Mapping | Mapping of Cofense Intelligence indicator rating to XSOAR DBOT Score standard rating.<br/>For Example-: None:0, Minor:1, Moderate:2, Major:3<br/><br/>Note: Cofense Indicator ratings are Major, Minor, Moderate, None. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| days_back | The maximum number of days from which to start returning data. 90 days is recommended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.ASN | unknown | The autonomous system name for the IP address. | 
| IP.GEO.Location | unknown | The geolocation where the IP address is located, in the format of latitude: longitude. | 
| IP.GEO.Country | unknown | The country in which the IP address is located. | 
| IP.Address | unknown | IP address. | 
| IP.MalwareFamily | unknown | The malware family associated with the IP address. | 
| IP.Relationships.EntityA | String | The source of the relationship. | 
| IP.Relationships.EntityB | String | The destination of the relationship. | 
| IP.Relationships.Relationship | String | The name of the relationship. | 
| IP.Relationships.EntityAType | String | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | String | The type of the destination of the relationship. | 
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
>|Threat ID|Threat Type|Verdict|Executive Summary|Campaign|Malware Family Description|Last Published|ASN|Country|Threat Report|
>|---|---|---|---|---|---|---|---|---|---|
>| 125002 | type | Suspicious | summary |  Campaign | Family Description | 2021-03-22 15:56:10 | ASN |country | link


### cofense-search
***
Retrieves a specific threat or a list of threats based on the filter values provided in the command arguments.


#### Base Command

`cofense-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| str | String to search. | Optional | 
| limit | Maximum number of strings to search. Default is 10. | Optional | 
| days_back | Limit the number of days from which we should start returning data. 90 days limit is recommended by Cofense. | Optional | 
| malware_family | The malware family associated with a malware campaign. | Optional | 
| malware_file | The filename associated with a phishing or malware campaign. | Optional | 
| malware_subject | Search the message subject associated with malware campaigns. | Optional | 
| url | A specific url to search for.<br/><br/>Note: This supports exact and partial matching of urls. | Optional | 

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
>|Threat ID|Threat Type|Executive Summary|Campaign|Malware Family|Malware File|Malware Subject|Malware Family Description|Last Published|Threat Report|
>|---|---|---|---|---|---|---|---|---|---|
>| 178991 | type | summary | Refund - Credential Phishing | Family | File | Subject | Family Description | 2021-04-15 14:53:11 | Link |


### file
***
Checks the reputation of a file hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The hash of the file to check. | Required | 
| days_back | The maximum number of days from which to start returning data. 90 days is recommended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Extension | Unknown | The file extension. | 
| File.MD5 | Unknown | The MD5 hash of the file. | 
| File.sha1 | String | The SHA-1 hash of the file. | 
| File.sha256 | String | The SHA-256 hash of the file. | 
| File.sha512 | String | The SHA-512 hash of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.Type | String | The file type. | 
| File.Hashes.type | String | The hash type. | 
| File.Hashes.value | String | The hash value. | 
| File.Malicious.Description | Unknown | A description explaining why the file was determined to be malicious. | 
| File.Malicious.Vendor | Unknown | The vendor who reported the file as malicious. | 
| File.MalwareFamily | Unknown | The malware family associated with the file. | 
| File.Name | Unknown | The full file name. | 
| File.Relationships.EntityA | String | The source of the relationship. | 
| File.Relationships.EntityB | String | The destination of the relationship. | 
| File.Relationships.Relationship | String | The name of the relationship. | 
| File.Relationships.EntityAType | String | The type of the source of the relationship. | 
| File.Relationships.EntityBType | String | The type of the destination of the relationship. | 
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
| CofenseIntelligence.File.Threats.executableSet.ssdeep | String | The ssdeep hash of the file. | 
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
| CofenseIntelligence.File.Threats.threatType | String | If malware, will have value 'malware', otherwise it is empty. | 

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
                    "deliveryMechanisms": [
                        {
                            "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                            "mechanismName": "CVE-2017-11882"
                        }
                    ],
                    "domainSet": [],
                    "executableSet":[
                        {
                            "dateEntered": 1598576136841,
                            "deliveryMechanism": {
                                "description": "Microsoft Office documents with macro scripting for malware delivery",
                                "mechanismName": "OfficeMacro"
                            },
                            "fileName": "bobbyx.exe",
                            "fileNameExtension": "exe",
                            "md5Hex": "9798ba6199168e6d2cf205760ea683d1",
                            "severityLevel": "Major",
                            "sha1Hex": "dcfad03686e029646d6118a5edd18a3b56a2c358",
                            "sha224Hex": "78c4f0f7f8c90d137fcb633b6c2c24e2a9f6b9c6054e5de1157d1bed",
                            "sha256Hex": "5eb93964840290b1a5e35577b2e7ed1c0f212ef275113d5ecdb4a85c127ae57a",
                            "sha384Hex": "9bd5ab8d458cf2bd64e6942dd586b5456f4a37d73ae788e4acbef666332c7ed00672fa4bc714d1f5b1b826f8e32ca6fe",
                            "sha512Hex": "4be7710c5d25b94861ace0a7ad83459163c6e294a511c41876e0d29a69d715a805bc859ad3f06a100141e245975893719a089c98cdffb60b3432119b66586f03",
                            "ssdeep": "3072:2vYy0u8YGgjv+ZvchmkHcI/o1/Vb6//////////////////////////////////p:S0uXnWFchmmcI/o1/3Jwnp",
                            "type": "Attachment",
                            "vendorDetections": []
                        }
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
        "sha1": "dcfad03686e029646d6118a5edd18a3b56a2c358",
        "sha256": "5eb93964840290b1a5e35577b2e7ed1c0f212ef275113d5ecdb4a85c127ae57a",
        "sha512": "4be7710c5d25b94861ace0a7ad83459163c6e294a511c41876e0d29a69d715a805bc859ad3f06a100141e245975893719a089c98cdffb60b3432119b66586f03",
        "SSDeep": "3072:2vYy0u8YGgjv+ZvchmkHcI/o1/Vb6//////////////////////////////////p:S0uXnWFchmmcI/o1/3Jwnp",
        "Type": "Attachment",
        "Malicious": {
            "Description": null,
            "Vendor": "CofenseIntelligenceV2"
        },
        "Hashes": [
          {
            "type": "MD5",
            "value": "9798ba6199168e6d2cf205760ea683d1"
          },
          {
            "type": "sha1",
            "value": "dcfad03686e029646d6118a5edd18a3b56a2c358"
          },
          {
            "type": "sha256",
            "value": "5eb93964840290b1a5e35577b2e7ed1c0f212ef275113d5ecdb4a85c127ae57a"
          },
          {
            "type": "sha512",
            "value": "4be7710c5d25b94861ace0a7ad83459163c6e294a511c41876e0d29a69d715a805bc859ad3f06a100141e245975893719a089c98cdffb60b3432119b66586f03"
          },
          {
            "type": "SSDeep",
            "value": "3072:2vYy0u8YGgjv+ZvchmkHcI/o1/Vb6//////////////////////////////////p:S0uXnWFchmmcI/o1/3Jwnp"
          }
        ],
        "MalwareFamily": "Agent Tesla",
        "Name": "bobbyx.exe"
    }
}
```

#### Human Readable Output

>### Cofense file Reputation for file 9798ba6199168e6d2cf205760ea683d1
>|Threat ID|Threat Type|Verdict|Executive Summary|Campaign|Malware Family Description|Last Published|Threat Report|
>|---|---|---|---|---|---|---|---|
>| 158959 |type | Malicious |  summary | campaign name | Family Description | 2021-03-18 19:47:48 | Link |


### email
***
Checks the reputation of an email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Sender email address to check. | Required | 
| days_back | The maximum number of days from which to start returning data. 90 days is recommended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| Email.Relationships.EntityA | String | The source of the relationship. | 
| Email.Relationships.EntityB | String | The destination of the relationship. | 
| Email.Relationships.Relationship | String | The name of the relationship. | 
| Email.Relationships.EntityAType | String | The type of the source of the relationship. | 
| Email.Relationships.EntityBType | String | The type of the destination of the relationship. | 
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
>|Threat ID|Threat Type|Verdict|Executive Summary|Campaign|Malware Family Description|Last Published|Threat Report|
>|---|---|---|---|---|---|---|---|
>| 158959 | Type | Malicious | Summary | Campaign name | Family Description | 2021-03-18 19:47:48 | link |


### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 
| days_back | The maximum number of days from which to start returning data. 90 days is recommended by Cofense. | Optional | 


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
| URL.Relationships.EntityA | String | The source of the relationship. | 
| URL.Relationships.EntityB | String | The destination of the relationship. | 
| URL.Relationships.Relationship | String | The name of the relationship. | 
| URL.Relationships.EntityAType | String | The type of the source of the relationship. | 
| URL.Relationships.EntityBType | String | The type of the destination of the relationship. | 
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
>|Threat ID|Threat Type|Verdict|Executive Summary|Campaign|Malware Family Description|Last Published|Threat Report|
>|---|---|---|---|---|---|---|---|
>| 125002 | threat type | Malicious | summary | Campaign name | Family Description | 2021-03-22 15:56:10 | Link |

### domain
***
Checks the reputation of the domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to check. | Required | 
| days_back | The maximum number of days from which to start returning data. 90 days is recommended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | The actual score. | 
| Domain.Name | String | The Domain. | 
| Domain.Malicious.Description | String | A description of the malicious URL. | 
| Domain.Malicious.Vendor | String | The vendor who reported the Domain as malicious. | 
| Domain.Relationships.EntityA | String | The source of the relationship. | 
| Domain.Relationships.EntityB | String | The destination of the relationship. | 
| Domain.Relationships.Relationship | String | The name of the relationship. | 
| Domain.Relationships.EntityAType | String | The type of the source of the relationship. | 
| Domain.Relationships.EntityBType | String | The type of the destination of the relationship. | 
| CofenseIntelligence.Domain.Data | String | The Domain. | 
| CofenseIntelligence.Domain.Threats.id | Number | Threat ID. | 
| CofenseIntelligence.Domain.Threats.feeds.id | Number | Integer identifier for this feed. | 
| CofenseIntelligence.Domain.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed. | 
| CofenseIntelligence.Domain.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed. | 
| CofenseIntelligence.Domain.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed. | 
| CofenseIntelligence.Domain.Threats.feeds.displayName | String | Human readable name for this feed. | 
| CofenseIntelligence.Domain.Threats.blockSet.malwareFamily.familyName | String | The name of the malware family. | 
| CofenseIntelligence.Domain.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works. | 
| CofenseIntelligence.Domain.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0. | 
| CofenseIntelligence.Domain.Threats.blockSet.confidence | Number | The level of confidence in the threats block. | 
| CofenseIntelligence.Domain.Threats.blockSet.blockType | String | Data type of the watchlist item. | 
| CofenseIntelligence.Domain.Threats.blockSet.roleDescription | String | Description of the infrastructure type. | 
| CofenseIntelligence.Domain.Threats.blockSet.role | String | Infrastructure type. | 
| CofenseIntelligence.Domain.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of the infrastructure type being used. | 
| CofenseIntelligence.Domain.Threats.blockSet.data | String | Domain name or an IP address. | 
| CofenseIntelligence.Domain.Threats.blockSet.data_1 | String | Either a domain name or an IP address. | 
| CofenseIntelligence.Domain.Threats.campaignBrandSet.totalCount | Number | Total number of individual messages associated with this brand. | 
| CofenseIntelligence.Domain.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.Domain.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand. | 
| CofenseIntelligence.Domain.Threats.domainSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Domain.Threats.domainSet.domain | String | Sender domain name. | 
| CofenseIntelligence.Domain.Threats.senderEmailSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Domain.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Domain.Threats.executableSet.malwareFamily.familyName | String | Family name of the malware. | 
| CofenseIntelligence.Domain.Threats.executableSet.malwareFamily.description | String | The name of the malware family. | 
| CofenseIntelligence.Domain.Threats.executableSet.vendorDetections.detected | Boolean | Whether an executable was detected. | 
| CofenseIntelligence.Domain.Threats.executableSet.vendorDetections.threatVendorName | String | Name of the antivirus vendor. | 
| CofenseIntelligence.Domain.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection. | 
| CofenseIntelligence.Domain.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection. | 
| CofenseIntelligence.Domain.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery. | 
| CofenseIntelligence.Domain.Threats.executableSet.severityLevel | String | The malware infection severity level. | 
| CofenseIntelligence.Domain.Threats.executableSet.fileNameExtension | String | The file extension. | 
| CofenseIntelligence.Domain.Threats.executableSet.md5Hex | String | The MD5 hash of the file. | 
| CofenseIntelligence.Domain.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file. | 
| CofenseIntelligence.Domain.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file. | 
| CofenseIntelligence.Domain.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file. | 
| CofenseIntelligence.Domain.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file. | 
| CofenseIntelligence.Domain.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file. | 
| CofenseIntelligence.Domain.Threats.executableSet.executableSubtype.description | String | The description of the executable file. | 
| CofenseIntelligence.Domain.Threats.senderIpSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Domain.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Domain.Threats.senderNameSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Domain.Threats.senderNameSet.name | String | The friendly name of the sender of the email. | 
| CofenseIntelligence.Domain.Threats.subjectSet.totalCount | Number | Total number of instances of each item named. | 
| CofenseIntelligence.Domain.Threats.subjectSet.subject | String | Email subject line. | 
| CofenseIntelligence.Domain.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated. | 
| CofenseIntelligence.Domain.Threats.firstPublished | Date | Timestamp of when this campaign was initially published. | 
| CofenseIntelligence.Domain.Threats.label | String | Human readable name for this campaign. | 
| CofenseIntelligence.Domain.Threats.executiveSummary | String | Analyst written summary of the campaign. | 
| CofenseIntelligence.Domain.Threats.hasReport | Boolean | Whether this campaign has a written report associated with it. | 
| CofenseIntelligence.Domain.Threats.reportDomain | String | Direct URL to human readable report for this campaign. | 
| CofenseIntelligence.Domain.Threats.apiReportURL | String | URL to human readable report for this campaign. | 
| CofenseIntelligence.Domain.Threats.threatDetailURL | String | T3 report URL. | 
| CofenseIntelligence.Domain.Threats.malwareFamilySet.familyName | String | Family name of the malware. | 
| CofenseIntelligence.Domain.Threats.malwareFamilySet.description | String | Description of the malware family set. | 
| CofenseIntelligence.Domain.Threats.threatType | String | If malware, will have value 'malware', otherwise it is empty. | 


#### Command Example
```!domain domain=www.sutomoresmestaj.net days_back=20000 using=CofenseIntelligenceV2_instance```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "Domain": {
            "Data": "www.sutomoresmestaj.net",
            "Threats": [
                {
                    "apiReportURL": "https://www.threathq.com/apiv1/t3/malware/55110/html",
                    "blockSet": [
                        {
                            "blockType": "URL",
                            "confidence": 100,
                            "data": "http://tamymakeup.com/myclassapp/Rt/",
                            "data_1": {
                                "domain": "tamymakeup.com",
                                "host": "tamymakeup.com",
                                "path": "/myclassapp/Rt/",
                                "protocol": "http",
                                "url": "http://tamymakeup.com/myclassapp/Rt/"
                            },
                            "deliveryMechanism": {
                                "description": "Microsoft Office documents with macro scripting for malware delivery",
                                "mechanismName": "OfficeMacro"
                            },
                            "impact": "Major",
                            "role": "Payload",
                            "roleDescription": "Location from which a payload is obtained"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 100,
                            "data": "www.sutomoresmestaj.net",
                            "data_1": "www.sutomoresmestaj.net",
                            "deliveryMechanism": {
                                "description": "Microsoft Office documents with macro scripting for malware delivery",
                                "mechanismName": "OfficeMacro"
                            },
                            "impact": "Moderate",
                            "role": "Payload",
                            "roleDescription": "Location from which a payload is obtained"
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
                    "campaignScreenshotSet": [],
                    "deliveryMechanisms": [
                        {
                            "description": "Microsoft Office documents with macro scripting for malware delivery",
                            "mechanismName": "OfficeMacro"
                        }
                    ],
                    "domainSet": [],
                    "executableSet": [
                        {
                            "dateEntered": 1598576136841,
                            "deliveryMechanism": {
                                "description": "Microsoft Office documents with macro scripting for malware delivery",
                                "mechanismName": "OfficeMacro"
                            },
                            "fileName": "000685.doc",
                            "fileNameExtension": "doc",
                            "md5Hex": "28c311de9ab487265c0846487e528423",
                            "severityLevel": "Major",
                            "sha1Hex": "dcfad03686e029646d6118a5edd18a3b56a2c358",
                            "sha224Hex": "78c4f0f7f8c90d137fcb633b6c2c24e2a9f6b9c6054e5de1157d1bed",
                            "sha256Hex": "5eb93964840290b1a5e35577b2e7ed1c0f212ef275113d5ecdb4a85c127ae57a",
                            "sha384Hex": "9bd5ab8d458cf2bd64e6942dd586b5456f4a37d73ae788e4acbef666332c7ed00672fa4bc714d1f5b1b826f8e32ca6fe",
                            "sha512Hex": "4be7710c5d25b94861ace0a7ad83459163c6e294a511c41876e0d29a69d715a805bc859ad3f06a100141e245975893719a089c98cdffb60b3432119b66586f03",
                            "ssdeep": "3072:2vYy0u8YGgjv+ZvchmkHcI/o1/Vb6//////////////////////////////////p:S0uXnWFchmmcI/o1/3Jwnp",
                            "type": "Attachment",
                            "vendorDetections": []
                        }
                    ],
                    "executiveSummary": "This report is part of our Emotet/Geodo series. Emotet is a malware family that was initially formed as a banking trojan but today often downloads additional malware payloads. We process very large Emotet campaigns containing thousands of stage one documents and we often find there are a small number of unique URLs and stage two payloads in each campaign. As such, you may notice these lists contain mostly document-specific IOCs, compared with fewer unique URLs and unique stage two payloads.",
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
                    "firstPublished": 1598622645803,
                    "hasReport": true,
                    "id": 55110,
                    "label": "Finance or Response Themed - OfficeMacro, Emotet/Geodo",
                    "lastPublished": 1598622745988,
                    "malwareFamilySet": [
                        {
                            "description": "Adaptable financial crimes botnet trojan with email worm and malware delivery capabilities, also known as Emotet",
                            "familyName": "Emotet/Geodo"
                        }
                    ],
                    "naicsCodes": [],
                    "relatedSearchTags": [],
                    "reportURL": "https://www.threathq.com/api/l/activethreatreport/55110/html",
                    "senderEmailSet": [],
                    "senderIpSet": [],
                    "senderNameSet": [],
                    "spamUrlSet": [],
                    "subjectSet": [
                        {
                            "subject": "Invoice",
                            "totalCount": 1
                        },
                        {
                            "subject": "Notice",
                            "totalCount": 1
                        },
                        {
                            "subject": "Purchase Order",
                            "totalCount": 1
                        },
                        {
                            "subject": "Report",
                            "totalCount": 1
                        },
                        {
                            "subject": "Response",
                            "totalCount": 1
                        },
                        {
                            "subject": "Scanned Document",
                            "totalCount": 1
                        }
                    ],
                    "threatDetailURL": "https://www.threathq.com/p42/search/default?m=55110",
                    "threatType": "MALWARE"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "www.sutomoresmestaj.net",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "CofenseIntelligenceV2"
    },
    "Domain": {
        "Name": "www.sutomoresmestaj.net",
        "Relationships": [
            {
                "EntityA": "www.sutomoresmestaj.net",
                "EntityAType": "Domain",
                "EntityB": "http://tamymakeup.com/myclassapp/Rt/",
                "EntityBType": "URL",
                "Relationship": "related-to"
            },
            {
                "EntityA": "www.sutomoresmestaj.net",
                "EntityAType": "Domain",
                "EntityB": "www.sutomoresmestaj.net",
                "EntityBType": "Domain Name",
                "Relationship": "related-to"
            }
        ]
    }
}
```

#### Human Readable Output

>### Cofense Domain Reputation for domain www.sutomoresmestaj.net
>|Threat ID|Threat Type|Verdict|Executive Summary|Campaign|Malware Family Description|Last Published|Threat Report|
>|---|---|---|---|---|---|---|---|
>| 55110 | MALWARE | Suspicious | This report is part of our Emotet/Geodo series. Emotet is a malware family that was initially formed as a banking trojan but today often downloads additional malware payloads. We process very large Emotet campaigns containing thousands of stage one documents and we often find there are a small number of unique URLs and stage two payloads in each campaign. As such, you may notice these lists contain mostly document-specific IOCs, compared with fewer unique URLs and unique stage two payloads. | Finance or Response Themed - OfficeMacro, Emotet/Geodo | Adaptable financial crimes botnet trojan with email worm and malware delivery capabilities, also known as Emotet | 2020-08-28 13:52:25 | [https://www.threathq.com/api/l/activethreatreport/55110/html](https://www.threathq.com/api/l/activethreatreport/55110/html) |

### cofense-threat-report-get
***
Downloads threat report provided by cofense intelligence of an indicator for the given unique report id.


#### Base Command

`cofense-threat-report-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Unique id to download the specified threat report. | Required | 
| report_format | Report format to download.<br/>Allowed types are html and pdf. Possible values are: html, pdf. Default is html. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | The entry ID of the file. | 
| File.Info | String | File information. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The file extension. | 

#### Command example
```!cofense-threat-report-get report_id=290367```
#### Context Example
```json
{
    "File": {
        "EntryID": "17353@2f1342cd-06b5-4b3f-8c20-fe27a087f3a8",
        "Extension": "html",
        "Info": "text/html; charset=utf-8",
        "MD5": "e61fc1a2b206650a3eb48f7856126291",
        "Name": "290367.html",
        "SHA1": "bb419100bd5319a43f4f5640075f22a7716ed5f8",
        "SHA256": "d5da427907395fc8cf0e2942465990486e9bdb016ff820c89511599a0ec0b86a",
        "SHA512": "aad5ffa7e291bb1f1528f2ed805307a8dfe9bdfae13b766e4fdbd7b9605008a2bc7eb9b177b3306de9fc113eda7c5c632f27446956394f601713cdeeaa075a43",
        "SSDeep": "1536:TVsXVrOaM0uEcFrlsd21G33VRxQFsUKRFdLeo0sw/x7W:4OapOlOXLisUybLeoO/4",
        "Size": 79669,
        "Type": "HTML document, ASCII text, with very long lines, with CRLF line terminators"
    }
}
```

#### Human Readable Output

Uploaded file: 290367.html [Download](https://1.1.1.1/entry/download/17)

>|EntryID|Info|MD5|Name|SHA1|SHA256|SHA512|SSDeep|Size|Type|
>|---|---|---|---|---|---|---|---|---|---|
>| 17353@2f1342cd-06b5-4b3f-8c20-fe27a087f3a8 | text/html; charset=utf-8 | e61fc1a2b206650a3eb48f7856126291 | 290367.html | bb419100bd5319a43f4f5640075f22a7716ed5f8 | d5da427907395fc8cf0e2942465990486e9bdb016ff820c89511599a0ec0b86a | aad5ffa7e291bb1f1528f2ed805307a8dfe9bdfae13b766e4fdbd7b9605008a2bc7eb9b177b3306de9fc113eda7c5c632f27446956394f601713cdeeaa075a43 | 1536:TVsXVrOaM0uEcFrlsd21G33VRxQFsUKRFdLeo0sw/x7W:4OapOlOXLisUybLeoO/4 | 79669 | HTML document, ASCII text, with very long lines, with CRLF line terminators |

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