Use the Cofense Intelligence integration to check the reputation of URLs, IP addresses, file hashes, and email addresses.
This integration was integrated and tested with version 2 of Cofense Intelligence

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
    | Time limit for collecting data | Limit the number of days from which we should start returning data. 90 days limit is recomended by Cofense. |  |
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
| days_back | Limit the number of days from wich we should start returning data. 90 days limit is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.IP.Data | String | The IP address | 
| CofenseIntelligence.IP.Threats.id | Number | Threat ID | 
| CofenseIntelligence.IP.Threats.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.IP.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.IP.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.IP.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.IP.Threats.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.IP.Threats.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.IP.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.IP.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.IP.Threats.blockSet.confidence | Number | The level of confidence in the threats block | 
| CofenseIntelligence.IP.Threats.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.IP.Threats.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.IP.Threats.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.IP.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.IP.Threats.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.IP.Threats.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.IP.Threats.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.IP.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.IP.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.IP.Threats.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.IP.Threats.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.IP.Threats.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.IP.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.IP.Threats.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.IP.Threats.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.IP.Threats.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.IP.Threats.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.IP.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.IP.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.IP.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.IP.Threats.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.IP.Threats.executableSet.fileNameExtension | String | The extension of the file | 
| CofenseIntelligence.IP.Threats.executableSet.md5Hex | String | The MD5 hash of the file | 
| CofenseIntelligence.IP.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.IP.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.IP.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.IP.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.IP.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.IP.Threats.executableSet.executableSubtype.description | String | The description of the executable file | 
| CofenseIntelligence.IP.Threats.senderIpSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.IP.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email | 
| CofenseIntelligence.IP.Threats.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.IP.Threats.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.IP.Threats.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.IP.Threats.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.IP.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.IP.Threats.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.IP.Threats.label | String | Human readable name for this campaign | 
| CofenseIntelligence.IP.Threats.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.IP.Threats.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.IP.Threats.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.IP.Threats.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.IP.Threats.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.IP.Threats.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.IP.Threats.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.IP.Threats.threatType | String | This will only have one value for malware | 


#### Command Example
```!ip ip=45.116.166.177 using=CofenseIntelligenceV2_instance```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "IP": {
            "Data": "45.116.166.177",
            "Threats": [
                {
                    "apiReportURL": "https://www.threathq.com/apiv1/t3/malware/125002/html",
                    "blockSet": [
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "45.116.166.177",
                            "data_1": "45.116.166.177",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 23456,
                                "continentCode": "AS",
                                "continentName": "Asia",
                                "countryIsoCode": "IN",
                                "countryName": "India",
                                "ip": "45.116.166.177",
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
                    "executiveSummary": "Finance-themed campaign delivers FormGrabber.",
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
                    "reportURL": "https://www.threathq.com/api/l/activethreatreport/125002/html",
                    "senderEmailSet": [],
                    "senderIpSet": [],
                    "senderNameSet": [],
                    "spamUrlSet": [],
                    "subjectSet": [
                        {
                            "subject": "RE: price request: 3131-50SG0BK00T1",
                            "totalCount": 1
                        }
                    ],
                    "threatDetailURL": "https://www.threathq.com/p42/search/default?m=125002",
                    "threatType": "MALWARE"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "45.116.166.177",
        "Reliability": "B - Usually reliable",
        "Score": 2,
        "Type": "ip",
        "Vendor": "CofenseIntelligenceV2"
    },
    "IP": {
        "ASN": 23456,
        "Address": "45.116.166.177",
        "Geo": {
            "Country": "IN",
            "Location": "20.0:77.0"
        },
        "MalwareFamily": "FormGrabber"
    }
}
```

#### Human Readable Output

>### Cofense IP Reputation for IP 45.116.166.177
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
| days_back | Limit the number of days from wich we should start returning data. 90 days limit is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CofenseIntelligence.Threats.id | Number | Threat ID | 
| CofenseIntelligence.Threats.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.Threats.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.Threats.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.Threats.blockSet.confidence | Number | The level of confidence in the threats block | 
| CofenseIntelligence.Threats.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.Threats.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.Threats.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.Threats.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.Threats.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.Threats.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threats.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threats.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.Threats.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Threats.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.Threats.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.Threats.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.Threats.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.Threats.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.Threats.executableSet.fileNameExtension | String | The extension of the file | 
| CofenseIntelligence.Threats.executableSet.md5Hex | String | The MD5 hash of the file | 
| CofenseIntelligence.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.Threats.executableSet.executableSubtype.description | String | The description of the executable file | 
| CofenseIntelligence.Threats.senderIpSet.totalCount | Number | Count of the instances of each item named. | 
| CofenseIntelligence.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Threats.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threats.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.Threats.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threats.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.Threats.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.Threats.label | String | Human readable name for this campaign | 
| CofenseIntelligence.Threats.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.Threats.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.Threats.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.Threats.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.Threats.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.Threats.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.Threats.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.Threats.threatType | String | This will only have one value for malware | 


#### Command Example
```!cofense-search str=border using=CofenseIntelligenceV2_instance_1_copy```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "Threats": {
            "apiReportURL": "https://www.threathq.com/apiv1/t3/malware/178991/html",
            "blockSet": [
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "https://infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com/dh/ref/in/gov/",
                    "data_1": {
                        "domain": "easywp.com",
                        "host": "infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com",
                        "path": "/dh/ref/in/gov/",
                        "protocol": "https",
                        "url": "https://infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com/dh/ref/in/gov/"
                    },
                    "impact": "Major",
                    "infrastructureTypeSubclass": {
                        "description": "Additional phishing URLs not found in the original email"
                    },
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "https://infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com/dh/ref/in/gov/a696f8bfc1c1110/submit.php",
                    "data_1": {
                        "domain": "easywp.com",
                        "host": "infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com",
                        "path": "/dh/ref/in/gov/a696f8bfc1c1110/submit.php",
                        "protocol": "https",
                        "url": "https://infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com/dh/ref/in/gov/a696f8bfc1c1110/submit.php"
                    },
                    "impact": "Major",
                    "infrastructureTypeSubclass": {
                        "description": "Threat Actor controlled host or email address to which harvested credentials are exfiltrated."
                    },
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "Domain Name",
                    "confidence": 0,
                    "data": "wp1.inform-kuwaitost.pw72n.spectrum.myjino.ru",
                    "data_1": "wp1.inform-kuwaitost.pw72n.spectrum.myjino.ru",
                    "impact": "Major",
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "http://wp1.inform-kuwaitost.pw72n.spectrum.myjino.ru/desk/naghoz/asd/",
                    "data_1": {
                        "domain": "inform-kuwaitost.pw72n.spectrum.myjino.ru",
                        "host": "wp1.inform-kuwaitost.pw72n.spectrum.myjino.ru",
                        "path": "/desk/naghoz/asd/",
                        "protocol": "http",
                        "url": "http://wp1.inform-kuwaitost.pw72n.spectrum.myjino.ru/desk/naghoz/asd/"
                    },
                    "impact": "Major",
                    "infrastructureTypeSubclass": {
                        "description": "Additional phishing URLs not found in the original email"
                    },
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "https://cdfs-info-kw.blogspot.com/",
                    "data_1": {
                        "domain": "cdfs-info-kw.blogspot.com",
                        "host": "cdfs-info-kw.blogspot.com",
                        "path": "/",
                        "protocol": "https",
                        "url": "https://cdfs-info-kw.blogspot.com/"
                    },
                    "impact": "Major",
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "Domain Name",
                    "confidence": 0,
                    "data": "infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com",
                    "data_1": "infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com",
                    "impact": "Major",
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "https://bom.to/1UaQKCOLHTnAl",
                    "data_1": {
                        "domain": "bom.to",
                        "host": "bom.to",
                        "path": "/1UaQKCOLHTnAl",
                        "protocol": "https",
                        "url": "https://bom.to/1UaQKCOLHTnAl"
                    },
                    "impact": "Major",
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "https://dgahaeb.r.af.d.sendibt2.com/tr/cl/",
                    "data_1": {
                        "domain": "sendibt2.com",
                        "host": "dgahaeb.r.af.d.sendibt2.com",
                        "path": "/tr/cl/",
                        "protocol": "https",
                        "url": "https://dgahaeb.r.af.d.sendibt2.com/tr/cl/"
                    },
                    "impact": "Major",
                    "infrastructureTypeSubclass": {
                        "description": "URL embedded in the email or attached file."
                    },
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "https://infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com/dh/ref/in/gov/a696f8bfc1c1110/details.php",
                    "data_1": {
                        "domain": "easywp.com",
                        "host": "infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com",
                        "path": "/dh/ref/in/gov/a696f8bfc1c1110/details.php",
                        "protocol": "https",
                        "url": "https://infornegative-dh-gov-hk-8358a9.ingress-baronn.easywp.com/dh/ref/in/gov/a696f8bfc1c1110/details.php"
                    },
                    "impact": "Major",
                    "infrastructureTypeSubclass": {
                        "description": "Threat Actor controlled host or email address to which harvested credentials are exfiltrated."
                    },
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "https://tinyurl.com/2msy6au5",
                    "data_1": {
                        "domain": "tinyurl.com",
                        "host": "tinyurl.com",
                        "path": "/2msy6au5",
                        "protocol": "https",
                        "url": "https://tinyurl.com/2msy6au5"
                    },
                    "impact": "Major",
                    "infrastructureTypeSubclass": {
                        "description": "URL embedded in the email or attached file."
                    },
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "http://wp1.inform-kuwaitost.pw72n.spectrum.myjino.ru/desk/naghoz/asd/send1.php",
                    "data_1": {
                        "domain": "inform-kuwaitost.pw72n.spectrum.myjino.ru",
                        "host": "wp1.inform-kuwaitost.pw72n.spectrum.myjino.ru",
                        "path": "/desk/naghoz/asd/send1.php",
                        "protocol": "http",
                        "url": "http://wp1.inform-kuwaitost.pw72n.spectrum.myjino.ru/desk/naghoz/asd/send1.php"
                    },
                    "impact": "Major",
                    "infrastructureTypeSubclass": {
                        "description": "Threat Actor controlled host or email address to which harvested credentials are exfiltrated."
                    },
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                },
                {
                    "blockType": "Domain Name",
                    "confidence": 0,
                    "data": "cdfs-info-kw.blogspot.com",
                    "data_1": "cdfs-info-kw.blogspot.com",
                    "impact": "Major",
                    "malwareFamily": {
                        "description": "An instance of credential phishing",
                        "familyName": "Credential Phishing"
                    },
                    "role": "Credential Phishing",
                    "roleDescription": "Credential Phishing"
                }
            ],
            "campaignBrandSet": [
                {
                    "brand": {
                        "id": 12968,
                        "text": "Hong Kong Department of Health"
                    },
                    "totalCount": 3
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
            "domainSet": [
                {
                    "domain": "szmc.goldentec.com",
                    "totalCount": 3
                }
            ],
            "executableSet": [],
            "executiveSummary": "Hong Kong Department of Health-spoofing emails deliver Credential Phishing via embedded links.",
            "extractedStringSet": [
                {
                    "data": "<tbody style=\"-webkit-font-smoothing: antialiased\">\r\n<tr style=\"-webkit-font-smoothing: antialiased\">\r\n<td style=\"BORDER-TOP: medium none; BORDER-RIGHT: medium none; BORDER-COLLAPSE: collapse; BORDER-BOTTOM: medium none; COLOR: rgb(255,255,255); PADDING-BOTTOM: 10px; PADDING-TOP: 10px; PADDING-LEFT: 25px; BORDER-LEFT: medium none; PADDING-RIGHT: 25px; border-radius: 3px; -webkit-font-smoothing: antialiased\" bgcolor=\"#004d3a\" valign=\"middle\" align=\"center\">\r\n\t<a title=\"https://cfspart.impots.gouv.fr\" \r\n\t\tstyle=\"BORDER-TOP: 0px; FONT-FAMILY: Arial, sans-serif; BORDER-RIGHT: 0px; VERTICAL-ALIGN: baseline; BORDER-BOTTOM: 0px; COLOR: rgb(255,255,255); PADDING-BOTTOM: 0px; PADDING-TOP: 0px; PADDING-LEFT: 0px; BORDER-LEFT: 0px; MARGIN: 0px; LINE-HEIGHT: 16px; PADDING-RIGHT: 0px; -webkit-font-smoothing: antialiased; font-stretch: inherit; text-decoration-line: none; background-clip: initial; background-size: initial; background-origin: initial\" \r\n\t\thref=\"https://dgahaeb.r.af.d.sendibt2.com/tr/cl/\" \r\n\t\trel=\"noreferrer noopener\" \r\n\t\ttarget=\"_blank\" \r\n\t\tdata-cke-saved-href=\"https://tinyurl.com/2msy6au5\" \r\n\t\tdata-linkindex=\"0\" \r\n\t\tdata-auth=\"NotApplicable\">\r\n\t<strong style=\"-webkit-font-smoothing: antialiased\">\r\n\t<font style=\"-webkit-font-smoothing: antialiased\" size=\"3\">My personal space</font>\r\n</strong>\r\n</a>\r\n</td>\r\n</tr>\r\n</tbody>",
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
            "reportURL": "https://www.threathq.com/api/l/activethreatreport/178991/html",
            "senderEmailSet": [
                {
                    "senderEmail": "dzfp@szmc.goldentec.com",
                    "totalCount": 3
                }
            ],
            "senderIpSet": [],
            "senderNameSet": [
                {
                    "name": "dh.gov.hk",
                    "totalCount": 3
                }
            ],
            "spamUrlSet": [],
            "subjectSet": [
                {
                    "subject": "Electronic Refund Form",
                    "totalCount": 3
                }
            ],
            "threatDetailURL": "https://www.threathq.com/p42/search/default?m=178991",
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
>| 178991 | An instance of credential phishing | Hong Kong Department of Health-spoofing emails deliver Credential Phishing via embedded links. | Refund - Credential Phishing | 2021-04-15 14:53:11 | [https://www.threathq.com/api/l/activethreatreport/178991/html](https://www.threathq.com/api/l/activethreatreport/178991/html) |


### file
***
Checks the reputation of a file hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A file MD5 hash to check. | Required | 
| days_back | Limit the number of days from wich we should start returning data. 90 days limit is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.File.Data | String | The file hash | 
| CofenseIntelligence.File.Threats.id | Number | Threat ID | 
| CofenseIntelligence.File.Threats.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.File.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.File.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.File.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.File.Threats.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.File.Threats.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.File.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.File.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.File.Threats.blockSet.confidence | Number | The level of confidence in the threats block | 
| CofenseIntelligence.File.Threats.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.File.Threats.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.File.Threats.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.File.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.File.Threats.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.File.Threats.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.File.Threats.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.File.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.File.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.File.Threats.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.File.Threats.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.File.Threats.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.File.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.File.Threats.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.File.Threats.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.File.Threats.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.File.Threats.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.File.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.File.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.File.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.File.Threats.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.File.Threats.executableSet.fileNameExtension | String | The extension of the file | 
| CofenseIntelligence.File.Threats.executableSet.md5Hex | String | The MD5 hash of the file | 
| CofenseIntelligence.File.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.File.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.File.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.File.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.File.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.File.Threats.executableSet.executableSubtype.description | String | The description of the executable file | 
| CofenseIntelligence.File.Threats.senderIpSet.totalCount | Number | Count of the instances of each item named. | 
| CofenseIntelligence.File.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.File.Threats.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.File.Threats.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.File.Threats.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.File.Threats.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.File.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.File.Threats.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.File.Threats.label | String | Human readable name for this campaign | 
| CofenseIntelligence.File.Threats.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.File.Threats.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.File.Threats.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.File.Threats.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.File.Threats.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.File.Threats.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.File.Threats.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.File.Threats.threatType | String | This will only have one value for malware | 


#### Command Example
```!file file=9798ba6199168e6d2cf205760ea683d1 using=CofenseIntelligenceV2_instance_1_copy```

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
                            "data": "info@sankapatrol.com",
                            "data_1": "info@sankapatrol.com",
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                                "familyName": "Agent Tesla"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://zytrox.tk/modex/bobbyx.exe",
                            "data_1": {
                                "domain": "zytrox.tk",
                                "host": "zytrox.tk",
                                "path": "/modex/bobbyx.exe",
                                "protocol": "http",
                                "url": "http://zytrox.tk/modex/bobbyx.exe"
                            },
                            "deliveryMechanism": {
                                "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                                "mechanismName": "CVE-2017-11882"
                            },
                            "impact": "Major",
                            "role": "Payload",
                            "roleDescription": "Location from which a payload is obtained"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "45.84.196.197",
                            "data_1": "45.84.196.197",
                            "deliveryMechanism": {
                                "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                                "mechanismName": "CVE-2017-11882"
                            },
                            "impact": "Minor",
                            "role": "Payload",
                            "roleDescription": "Location from which a payload is obtained"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "zytrox.tk",
                            "data_1": "zytrox.tk",
                            "deliveryMechanism": {
                                "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                                "mechanismName": "CVE-2017-11882"
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
                    "deliveryMechanisms": [
                        {
                            "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                            "mechanismName": "CVE-2017-11882"
                        }
                    ],
                    "domainSet": [],
                    "executableSet": [
                        {
                            "dateEntered": 1616096828270,
                            "fileName": "bobbyx.exe",
                            "fileNameExtension": "exe",
                            "malwareFamily": {
                                "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                                "familyName": "Agent Tesla"
                            },
                            "md5Hex": "9798ba6199168e6d2cf205760ea683d1",
                            "severityLevel": "Major",
                            "type": "Download",
                            "vendorDetections": []
                        },
                        {
                            "dateEntered": 1615989305686,
                            "deliveryMechanism": {
                                "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                                "mechanismName": "CVE-2017-11882"
                            },
                            "fileName": "Purchase order.doc",
                            "fileNameExtension": "doc",
                            "md5Hex": "eb8dd4479c7e56f370965efd1f5bfe42",
                            "severityLevel": "Major",
                            "sha1Hex": "80c64b74ec6491f1bacd7ce452af9a981708516d",
                            "sha224Hex": "3c61eeb7eadb596c7f329e119cd7ad3b6f1c9ecfa7325469cd11b43b",
                            "sha256Hex": "958b88da50d90cea5d54285d31cde79ef7841df6604aa8cfd0a52c87e714aa93",
                            "sha384Hex": "56e2a7b7141078ebf97c75ab0929dda4de8e816edc8a5f3e9ccfaf8d30375b89898dcf729a65c6c838b4ed8e4606a248",
                            "sha512Hex": "310719a3af341572024e2fcf387708337da51e6e9c3164e0c42a84abec0f3c518ee8ccc15563fc838323a29cd122bb938b574224d797fe7136ebaa5ffb577f7a",
                            "ssdeep": "3072:zkV0AvFTnx1//kUWwyJi7eLbkrMrN6EetrKYWZ6gq6AVKlG5hEBYRPek02e:zkmKFvkeeLbyA6EeNXvgGVKlchEBgPKP",
                            "type": "Attachment",
                            "vendorDetections": []
                        }
                    ],
                    "executiveSummary": "Order-themed email delivering Agent Tesla keylogger via CVE-2017-11882.",
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
                    "reportURL": "https://www.threathq.com/api/l/activethreatreport/158959/html",
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
                    "threatDetailURL": "https://www.threathq.com/p42/search/default?m=158959",
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
>| 158959 | Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes. | Malicious | Order-themed email delivering Agent Tesla keylogger via CVE-2017-11882. | Order - CVE-2017-11882, Agent Tesla Keylogger | 2021-03-18 19:47:48 | [https://www.threathq.com/api/l/activethreatreport/158959/html](https://www.threathq.com/api/l/activethreatreport/158959/html) |


### email
***
Checks the reputation of an email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Sender email address to check. | Required | 
| days_back | Limit the number of days from wich we should start returning data. 90 days limit is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.Email.Data | String | The Email address | 
| CofenseIntelligence.Email.Threats.id | Number | Threat ID | 
| CofenseIntelligence.Email.Threats.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.Email.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.Email.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.Email.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.Email.Threats.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.Email.Threats.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.Email.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.Email.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.Email.Threats.blockSet.confidence | Number | The level of confidence in the threats block | 
| CofenseIntelligence.Email.Threats.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.Email.Threats.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.Email.Threats.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.Email.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.Email.Threats.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.Email.Threats.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.Email.Threats.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.Email.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Email.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Email.Threats.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Email.Threats.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.Email.Threats.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Email.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Email.Threats.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.Email.Threats.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.Email.Threats.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.Email.Threats.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.Email.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.Email.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.Email.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.Email.Threats.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.Email.Threats.executableSet.fileNameExtension | String | The extension of the file | 
| CofenseIntelligence.Email.Threats.executableSet.md5Hex | String | The MD5 hash of the file | 
| CofenseIntelligence.Email.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.Email.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.Email.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.Email.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.Email.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.Email.Threats.executableSet.executableSubtype.description | String | The description of the executable file | 
| CofenseIntelligence.Email.Threats.senderIpSet.totalCount | Number | Count of the instances of each item named. | 
| CofenseIntelligence.Email.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Email.Threats.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Email.Threats.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.Email.Threats.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Email.Threats.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.Email.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.Email.Threats.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.Email.Threats.label | String | Human readable name for this campaign | 
| CofenseIntelligence.Email.Threats.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.Email.Threats.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.Email.Threats.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.Email.Threats.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.Email.Threats.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.Email.Threats.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.Email.Threats.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.Email.Threats.threatType | String | This will only have one value for malware | 


#### Command Example
```!email email=info@sankapatrol.com using=CofenseIntelligenceV2_instance_1_copy```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "Email": {
            "Data": "info@sankapatrol.com",
            "Threats": [
                {
                    "apiReportURL": "https://www.threathq.com/apiv1/t3/malware/158959/html",
                    "blockSet": [
                        {
                            "blockType": "Email",
                            "confidence": 0,
                            "data": "info@sankapatrol.com",
                            "data_1": "info@sankapatrol.com",
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                                "familyName": "Agent Tesla"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://zytrox.tk/modex/bobbyx.exe",
                            "data_1": {
                                "domain": "zytrox.tk",
                                "host": "zytrox.tk",
                                "path": "/modex/bobbyx.exe",
                                "protocol": "http",
                                "url": "http://zytrox.tk/modex/bobbyx.exe"
                            },
                            "deliveryMechanism": {
                                "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                                "mechanismName": "CVE-2017-11882"
                            },
                            "impact": "Major",
                            "role": "Payload",
                            "roleDescription": "Location from which a payload is obtained"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "45.84.196.197",
                            "data_1": "45.84.196.197",
                            "deliveryMechanism": {
                                "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                                "mechanismName": "CVE-2017-11882"
                            },
                            "impact": "Minor",
                            "role": "Payload",
                            "roleDescription": "Location from which a payload is obtained"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "zytrox.tk",
                            "data_1": "zytrox.tk",
                            "deliveryMechanism": {
                                "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                                "mechanismName": "CVE-2017-11882"
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
                    "deliveryMechanisms": [
                        {
                            "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                            "mechanismName": "CVE-2017-11882"
                        }
                    ],
                    "domainSet": [],
                    "executableSet": [
                        {
                            "dateEntered": 1616096828270,
                            "fileName": "bobbyx.exe",
                            "fileNameExtension": "exe",
                            "malwareFamily": {
                                "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                                "familyName": "Agent Tesla"
                            },
                            "md5Hex": "9798ba6199168e6d2cf205760ea683d1",
                            "severityLevel": "Major",
                            "type": "Download",
                            "vendorDetections": []
                        },
                        {
                            "dateEntered": 1615989305686,
                            "deliveryMechanism": {
                                "description": "Microsoft Office exploit taking advantage of flaw in Microsoft Equation Editor allowing for arbitrary code execution",
                                "mechanismName": "CVE-2017-11882"
                            },
                            "fileName": "Purchase order.doc",
                            "fileNameExtension": "doc",
                            "md5Hex": "eb8dd4479c7e56f370965efd1f5bfe42",
                            "severityLevel": "Major",
                            "sha1Hex": "80c64b74ec6491f1bacd7ce452af9a981708516d",
                            "sha224Hex": "3c61eeb7eadb596c7f329e119cd7ad3b6f1c9ecfa7325469cd11b43b",
                            "sha256Hex": "958b88da50d90cea5d54285d31cde79ef7841df6604aa8cfd0a52c87e714aa93",
                            "sha384Hex": "56e2a7b7141078ebf97c75ab0929dda4de8e816edc8a5f3e9ccfaf8d30375b89898dcf729a65c6c838b4ed8e4606a248",
                            "sha512Hex": "310719a3af341572024e2fcf387708337da51e6e9c3164e0c42a84abec0f3c518ee8ccc15563fc838323a29cd122bb938b574224d797fe7136ebaa5ffb577f7a",
                            "ssdeep": "3072:zkV0AvFTnx1//kUWwyJi7eLbkrMrN6EetrKYWZ6gq6AVKlG5hEBYRPek02e:zkmKFvkeeLbyA6EeNXvgGVKlchEBgPKP",
                            "type": "Attachment",
                            "vendorDetections": []
                        }
                    ],
                    "executiveSummary": "Order-themed email delivering Agent Tesla keylogger via CVE-2017-11882.",
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
                    "reportURL": "https://www.threathq.com/api/l/activethreatreport/158959/html",
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
                    "threatDetailURL": "https://www.threathq.com/p42/search/default?m=158959",
                    "threatType": "MALWARE"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "info@sankapatrol.com",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "email",
        "Vendor": "CofenseIntelligenceV2"
    },
    "Email": {
        "Address": "info@sankapatrol.com",
        "Domain": "sankapatrol.com"
    }
}
```

#### Human Readable Output

>### Cofense email Reputation for email info@sankapatrol.com
>|Threat ID|Threat Types|Verdict|Executive Summary|Campaign|Last Published|Threat Report|
>|---|---|---|---|---|---|---|
>| 158959 | Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes. | Malicious | Order-themed email delivering Agent Tesla keylogger via CVE-2017-11882. | Order - CVE-2017-11882, Agent Tesla Keylogger | 2021-03-18 19:47:48 | [https://www.threathq.com/api/l/activethreatreport/158959/html](https://www.threathq.com/api/l/activethreatreport/158959/html) |


### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 
| days_back | Limit the number of days from wich we should start returning data. 90 days limit is recomended by Cofense. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.URL.Data | String | The URL | 
| CofenseIntelligence.URL.Threats.id | Number | Threat ID | 
| CofenseIntelligence.URL.Threats.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.URL.Threats.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.URL.Threats.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.URL.Threats.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.URL.Threats.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.URL.Threats.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.URL.Threats.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.URL.Threats.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.URL.Threats.blockSet.confidence | Number | The level of confidence in the threats block | 
| CofenseIntelligence.URL.Threats.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.URL.Threats.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.URL.Threats.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.URL.Threats.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.URL.Threats.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.URL.Threats.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.URL.Threats.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.URL.Threats.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.URL.Threats.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.URL.Threats.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.URL.Threats.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.URL.Threats.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.URL.Threats.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.URL.Threats.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.URL.Threats.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.URL.Threats.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.URL.Threats.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.URL.Threats.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.URL.Threats.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.URL.Threats.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.URL.Threats.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.URL.Threats.executableSet.fileNameExtension | String | The extension of the file | 
| CofenseIntelligence.URL.Threats.executableSet.md5Hex | String | The MD5 hash of the file | 
| CofenseIntelligence.URL.Threats.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.URL.Threats.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.URL.Threats.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.URL.Threats.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.URL.Threats.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.URL.Threats.executableSet.executableSubtype.description | String | The description of the executable file | 
| CofenseIntelligence.URL.Threats.senderIpSet.totalCount | Number | Count of the instances of each item named. | 
| CofenseIntelligence.URL.Threats.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.URL.Threats.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.URL.Threats.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.URL.Threats.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.URL.Threats.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.URL.Threats.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.URL.Threats.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.URL.Threats.label | String | Human readable name for this campaign | 
| CofenseIntelligence.URL.Threats.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.URL.Threats.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.URL.Threats.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.URL.Threats.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.URL.Threats.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.URL.Threats.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.URL.Threats.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.URL.Threats.threatType | String | This will only have one value for malware | 


#### Command Example
```!url url=http://www.radissonhotelsusa.com/cp5/ using=CofenseIntelligenceV2_instance_1_copy```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "URL": {
            "Data": "http://www.radissonhotelsusa.com/cp5/",
            "Threats": [
                {
                    "apiReportURL": "https://www.threathq.com/apiv1/t3/malware/125002/html",
                    "blockSet": [
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.glcpunix.com",
                            "data_1": "www.glcpunix.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.itool.group/cp5/",
                            "data_1": {
                                "domain": "itool.group",
                                "host": "www.itool.group",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.itool.group/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "184.28.50.50",
                            "data_1": "184.28.50.50",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 20940,
                                "asnOrganization": "Akamai International B.V.",
                                "continentCode": "NA",
                                "continentName": "North America",
                                "countryIsoCode": "US",
                                "countryName": "United States",
                                "ip": "184.28.50.50",
                                "isp": "Akamai Technologies",
                                "latitude": 41.396,
                                "longitude": -71.6631,
                                "lookupOn": 1616428612889,
                                "metroCode": 521,
                                "organization": "Akamai Technologies",
                                "postalCode": "02813",
                                "subdivisionIsoCode": "RI",
                                "subdivisionName": "Rhode Island",
                                "timeZone": "America/New_York"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.mwakossolutions.com",
                            "data_1": "www.mwakossolutions.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "184.28.50.40",
                            "data_1": "184.28.50.40",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 20940,
                                "asnOrganization": "Akamai International B.V.",
                                "continentCode": "NA",
                                "continentName": "North America",
                                "countryIsoCode": "US",
                                "countryName": "United States",
                                "ip": "184.28.50.40",
                                "isp": "Akamai Technologies",
                                "latitude": 41.396,
                                "longitude": -71.6631,
                                "lookupOn": 1616428611405,
                                "metroCode": 521,
                                "organization": "Akamai Technologies",
                                "postalCode": "02813",
                                "subdivisionIsoCode": "RI",
                                "subdivisionName": "Rhode Island",
                                "timeZone": "America/New_York"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.radissonhotelsusa.com/cp5/",
                            "data_1": {
                                "domain": "radissonhotelsusa.com",
                                "host": "www.radissonhotelsusa.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.radissonhotelsusa.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.lzbnwy.com",
                            "data_1": "www.lzbnwy.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "45.116.166.177",
                            "data_1": "45.116.166.177",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 23456,
                                "continentCode": "AS",
                                "continentName": "Asia",
                                "countryIsoCode": "IN",
                                "countryName": "India",
                                "ip": "45.116.166.177",
                                "isp": "Seema Infotech",
                                "latitude": 20,
                                "longitude": 77,
                                "lookupOn": 1616428612903,
                                "organization": "Seema Infotech",
                                "timeZone": "Asia/Kolkata"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.wateryourlandscape.com",
                            "data_1": "www.wateryourlandscape.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.wateryourlandscape.com/cp5/",
                            "data_1": {
                                "domain": "wateryourlandscape.com",
                                "host": "www.wateryourlandscape.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.wateryourlandscape.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.bifa510.com",
                            "data_1": "www.bifa510.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 37,
                            "data": "37.97.254.27",
                            "data_1": "37.97.254.27",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 20857,
                                "asnOrganization": "Transip B.V.",
                                "continentCode": "EU",
                                "continentName": "Europe",
                                "countryIsoCode": "NL",
                                "countryName": "Netherlands",
                                "ip": "37.97.254.27",
                                "isp": "Transip B.V.",
                                "latitude": 52.3824,
                                "longitude": 4.8995,
                                "lookupOn": 1616428612334,
                                "organization": "Transip B.V.",
                                "timeZone": "Europe/Amsterdam"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "154.214.155.96",
                            "data_1": "154.214.155.96",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 35916,
                                "asnOrganization": "MULTACOM CORPORATION",
                                "continentCode": "NA",
                                "continentName": "North America",
                                "countryIsoCode": "US",
                                "countryName": "United States",
                                "ip": "154.214.155.96",
                                "isp": "Multacom Corporation",
                                "latitude": 34.0544,
                                "longitude": -118.244,
                                "lookupOn": 1616428610664,
                                "metroCode": 803,
                                "organization": "Multacom Corporation",
                                "postalCode": "90009",
                                "subdivisionIsoCode": "CA",
                                "subdivisionName": "California",
                                "timeZone": "America/Los_Angeles"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.osrs-remastered.com",
                            "data_1": "www.osrs-remastered.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.best20hookups.com",
                            "data_1": "www.best20hookups.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.carscompetition.com",
                            "data_1": "www.carscompetition.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.dopeneeds.com",
                            "data_1": "www.dopeneeds.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.bifa510.com/cp5/",
                            "data_1": {
                                "domain": "bifa510.com",
                                "host": "www.bifa510.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.bifa510.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "156.252.78.39",
                            "data_1": "156.252.78.39",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 37353,
                                "asnOrganization": "MacroLAN",
                                "continentCode": "AF",
                                "continentName": "Africa",
                                "countryIsoCode": "ZA",
                                "countryName": "South Africa",
                                "ip": "156.252.78.39",
                                "isp": "MacroLAN",
                                "latitude": -26.2309,
                                "longitude": 28.0583,
                                "lookupOn": 1616428610272,
                                "organization": "MacroLAN",
                                "postalCode": "2000",
                                "subdivisionIsoCode": "GT",
                                "subdivisionName": "Gauteng",
                                "timeZone": "Africa/Johannesburg"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.gdhymc.com/cp5/",
                            "data_1": {
                                "domain": "gdhymc.com",
                                "host": "www.gdhymc.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.gdhymc.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.dopeneeds.com/cp5/",
                            "data_1": {
                                "domain": "dopeneeds.com",
                                "host": "www.dopeneeds.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.dopeneeds.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.radissonhotelsusa.com",
                            "data_1": "www.radissonhotelsusa.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.itool.group",
                            "data_1": "www.itool.group",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.lzbnwy.com/cp5/",
                            "data_1": {
                                "domain": "lzbnwy.com",
                                "host": "www.lzbnwy.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.lzbnwy.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "111.230.19.237",
                            "data_1": "111.230.19.237",
                            "impact": "Minor",
                            "ipDetail": {
                                "continentCode": "AS",
                                "continentName": "Asia",
                                "countryIsoCode": "CN",
                                "countryName": "China",
                                "ip": "111.230.19.237",
                                "isp": "Beijing Faster Internet Technology Co.,Ltd",
                                "latitude": 39.9289,
                                "longitude": 116.3883,
                                "lookupOn": 1616428610295,
                                "organization": "Tencent cloud computing",
                                "subdivisionIsoCode": "11",
                                "subdivisionName": "Beijing",
                                "timeZone": "Asia/Shanghai"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "50.62.144.5",
                            "data_1": "50.62.144.5",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 26496,
                                "asnOrganization": "GoDaddy.com, LLC",
                                "continentCode": "NA",
                                "continentName": "North America",
                                "countryIsoCode": "US",
                                "countryName": "United States",
                                "ip": "50.62.144.5",
                                "isp": "GoDaddy.com, LLC",
                                "latitude": 33.6119,
                                "longitude": -111.8906,
                                "lookupOn": 1616428612877,
                                "metroCode": 753,
                                "organization": "GoDaddy.com, LLC",
                                "postalCode": "85260",
                                "subdivisionIsoCode": "AZ",
                                "subdivisionName": "Arizona",
                                "timeZone": "America/Phoenix"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.theautocareshop.com",
                            "data_1": "www.theautocareshop.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.gdhymc.com",
                            "data_1": "www.gdhymc.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.carscompetition.com/cp5/",
                            "data_1": {
                                "domain": "carscompetition.com",
                                "host": "www.carscompetition.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.carscompetition.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.sensualblogs.com",
                            "data_1": "www.sensualblogs.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.sensualblogs.com/cp5/",
                            "data_1": {
                                "domain": "sensualblogs.com",
                                "host": "www.sensualblogs.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.sensualblogs.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "107.160.176.77",
                            "data_1": "107.160.176.77",
                            "impact": "Minor",
                            "ipDetail": {
                                "asn": 40676,
                                "asnOrganization": "Psychz Networks",
                                "continentCode": "NA",
                                "continentName": "North America",
                                "countryIsoCode": "US",
                                "countryName": "United States",
                                "ip": "107.160.176.77",
                                "isp": "Psychz Networks",
                                "latitude": 34.0584,
                                "longitude": -118.278,
                                "lookupOn": 1616428610396,
                                "metroCode": 803,
                                "organization": "Psychz Networks",
                                "postalCode": "90017",
                                "subdivisionIsoCode": "CA",
                                "subdivisionName": "California",
                                "timeZone": "America/Los_Angeles"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "Domain Name",
                            "confidence": 0,
                            "data": "www.sailacc.com",
                            "data_1": "www.sailacc.com",
                            "impact": "Moderate",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "IPv4 Address",
                            "confidence": 0,
                            "data": "168.206.166.225",
                            "data_1": "168.206.166.225",
                            "impact": "Minor",
                            "ipDetail": {
                                "continentCode": "AF",
                                "continentName": "Africa",
                                "countryIsoCode": "ZA",
                                "countryName": "South Africa",
                                "ip": "168.206.166.225",
                                "isp": "The Atomic Energy Board",
                                "latitude": -25.7069,
                                "longitude": 28.2294,
                                "lookupOn": 1616428612318,
                                "organization": "The Atomic Energy Board",
                                "postalCode": "0002",
                                "subdivisionIsoCode": "GT",
                                "subdivisionName": "Gauteng",
                                "timeZone": "Africa/Johannesburg"
                            },
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "role": "C2",
                            "roleDescription": "Command and control location used by malware"
                        },
                        {
                            "blockType": "URL",
                            "confidence": 0,
                            "data": "http://www.mwakossolutions.com/cp5/",
                            "data_1": {
                                "domain": "mwakossolutions.com",
                                "host": "www.mwakossolutions.com",
                                "path": "/cp5/",
                                "protocol": "http",
                                "url": "http://www.mwakossolutions.com/cp5/"
                            },
                            "impact": "Major",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
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
                    "deliveryMechanisms": [],
                    "domainSet": [],
                    "executableSet": [
                        {
                            "dateEntered": 1611039423839,
                            "fileName": "3131_50SG0BK00T1,pdf.exe",
                            "fileNameExtension": "exe",
                            "malwareFamily": {
                                "description": "FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications.",
                                "familyName": "FormGrabber"
                            },
                            "md5Hex": "2b71bd4f414944163720bffe66296f21",
                            "severityLevel": "Major",
                            "sha1Hex": "7c86106022e7b4150d0ba2709f4df368c4b8bc15",
                            "sha224Hex": "e2223dc35e93aaf29dc37299670b00e2af13fb0398e687528870810e",
                            "sha256Hex": "9bf3bb9e44490d5836c31036a78c59c92a51d8f6bfb33363d8c617d27967ff3f",
                            "sha384Hex": "9fd54ac13cc39942eb7529f60d9fef1eddbe2a39943327ecc1fadbdfd12eb694f550908c3bea6e37bd341b701b6f1e70",
                            "sha512Hex": "8eeb0bbcefd0109a82c806d7740a8fe4b6f811a352d20772362302ba2ed615351a0bb3df18f1cd8d5ae28cc1ff7e3bd19333d546b4e4e0faf194ee068b905a7b",
                            "ssdeep": "24576:053q3J/CelpgYUGw58+JgG3Sr2BqPMl7rnJ4wYbS:Ia30eTgYUnCk3G2rJ4wYbS",
                            "type": "Attachment",
                            "vendorDetections": []
                        }
                    ],
                    "executiveSummary": "Finance-themed campaign delivers FormGrabber.",
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
                    "reportURL": "https://www.threathq.com/api/l/activethreatreport/125002/html",
                    "senderEmailSet": [],
                    "senderIpSet": [],
                    "senderNameSet": [],
                    "spamUrlSet": [],
                    "subjectSet": [
                        {
                            "subject": "RE: price request: 3131-50SG0BK00T1",
                            "totalCount": 1
                        }
                    ],
                    "threatDetailURL": "https://www.threathq.com/p42/search/default?m=125002",
                    "threatType": "MALWARE"
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "http://www.radissonhotelsusa.com/cp5/",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "CofenseIntelligenceV2"
    },
    "URL": {
        "Data": "http://www.radissonhotelsusa.com/cp5/",
        "Malicious": {
            "Description": null,
            "Vendor": "CofenseIntelligenceV2"
        }
    }
}
```

#### Human Readable Output

>### Cofense URL Reputation for url http://www.radissonhotelsusa.com/cp5/
>|Threat ID|Threat Types|Verdict|Executive Summary|Campaign|Last Published|Threat Report|
>|---|---|---|---|---|---|---|
>| 125002 | FormGrabber is a browser focused keylogger coded in ASM/C. It can record keystrokes, form input, clipboard contents, take screenshots, and recover stored credentials from many different applications. | Malicious | Finance-themed campaign delivers FormGrabber. | Finance - FormGrabber | 2021-03-22 15:56:10 | [https://www.threathq.com/api/l/activethreatreport/125002/html](https://www.threathq.com/api/l/activethreatreport/125002/html) |

