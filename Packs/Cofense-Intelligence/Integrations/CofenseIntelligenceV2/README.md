Use the Cofense Intelligence integration to check the reputation of URLs, IP addresses, file hashes, and email addresses.
This integration was integrated and tested with version 02 of CofenseIntelligenceV2
## Configure CofenseIntelligenceV2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CofenseIntelligenceV2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g., https://www.threathq.com/apiv1) | Cofense Intelligence base API url | True |
    | User name | API token user name | True |
    | Password  | API token password | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |
    | IP Threshold | threshold for IP related threat's severity  | False |
    | File Threshold | threshold for file related threat's severity | False |
    | URL Threshold | threshold for url related threat's severity | False |
    | Email Threshold | threshold for email related threat's severity | False |
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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.Threat.id | Number | Threat ID | 
| CofenseIntelligence.Threat.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.Threat.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.Threat.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.Threat.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.Threat.blockSet.confidence | Number | level of confidence in the threats block | 
| CofenseIntelligence.Threat.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.Threat.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.Threat.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.Threat.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.Threat.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.Threat.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.Threat.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.Threat.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.Threat.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.Threat.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.Threat.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.Threat.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.Threat.executableSet.fileNameExtension | String | extension of the file | 
| CofenseIntelligence.Threat.executableSet.md5Hex | String | The md5 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.Threat.executableSet.executableSubtype.description | String | description of the executable file | 
| CofenseIntelligence.Threat.senderIpSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email | 
| CofenseIntelligence.Threat.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.Threat.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.Threat.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.Threat.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.Threat.label | String | Human readable name for this campaign | 
| CofenseIntelligence.Threat.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.Threat.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.Threat.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.Threat.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.Threat.threatType | String | This will only have one value for malware | 


#### Command Example
```!ip ip=8.8.8.8 using=CofenseIntelligenceV2_instance_1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "ip",
        "Vendor": "CofenseIntelligenceV2"
    },
    "IP": {
        "Address": "8.8.8.8"
    }
}
```

#### Human Readable Output

>### Cofense IP Reputation for IP 8.8.8.8
>**No entries.**


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


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.Threat.id | Number | Threat ID | 
| CofenseIntelligence.Threat.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.Threat.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.Threat.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.Threat.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.Threat.blockSet.confidence | Number | level of confidence in the threats block | 
| CofenseIntelligence.Threat.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.Threat.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.Threat.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.Threat.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.Threat.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.Threat.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.Threat.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.Threat.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.Threat.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.Threat.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.Threat.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.Threat.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.Threat.executableSet.fileNameExtension | String | extension of the file | 
| CofenseIntelligence.Threat.executableSet.md5Hex | String | The md5 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.Threat.executableSet.executableSubtype.description | String | description of the executable file | 
| CofenseIntelligence.Threat.senderIpSet.totalCount | Number | Count of the instances of each item named. | 
| CofenseIntelligence.Threat.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Threat.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.Threat.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.Threat.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.Threat.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.Threat.label | String | Human readable name for this campaign | 
| CofenseIntelligence.Threat.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.Threat.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.Threat.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.Threat.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.Threat.threatType | String | This will only have one value for malware | 


#### Command Example
```!cofense-search str=string using=CofenseIntelligenceV2_instance_1```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "Threat": {
            "CofenseIntelligence": {
                "NumOfThreats": 10,
                "String": "string"
            }
        }
    }
}
```

#### Human Readable Output

>### There are 10 threats regarding your string search
>
>|Threat ID|Threat Types|Executive Summary|Campaign|Last Published|
>|---|---|---|---|---|
>| 11907 | Advanced derivative of the Zeus financial crimes and botnet trojan | These emails claim to deliver information pertaining to an order and request that recipients view the attached file. The attachment is an .xls Microsoft Excel spreadsheet containing a malicious Office macro tasked with downloading and executing a sample of the Zeus Panda banking trojan. At runtime, this malware application performs extensive checks to determine if it is running in a virtualized or analysis environment before making contact with its command and control host. Once contact has been established, this host will provide additional instructions, updated executables, and configuration data used to guide the financial crimes and botnet trojan's activity on infected machines. In this case the configuration data contained a list of targeted websites including PayPal, Poste Italiane, and the banking websites for Intesa san Paolo and Monte dei Paschi di Siena. | Order - OfficeMacro, Zeus Panda | 2018-06-07 20:16:38 |
>| 11979 | Malware capable of collecting victim keystrokes for exfiltration | These emails impersonate the agricultural export company Orchid Exim, and claim to have an attached purchase order. The attachment is a Microsoft Office Word document that abuses an object relationship to download and open an RTF file. This RTF file exploits a form of CVE-2017-8570 to launch embedded Macro-Enabled Worksheet Objects automatically once the file is opened. These objects then prompt for user permission to run an embedded Office macro. There are a total of 5 Macro-Enabled Worksheet Objects, if the victim is perceptive enough to not allow macros to execute they will be repeatedly prompted 5 times. If the victim does allow macros to run an executable sample of the Hawkeye keylogger malware will be dropped to disk and run. A PowerShell process will then delete antivirus definitions and dynamic signatures for Windows Defender before closing all Office windows and turning off script execution warnings and prevention mechanics for Microsoft Office. The Hawkeye keylogger malware is tasked with stealing valuable information such as keystrokes, email passwords, instant messenger credentials, and other sensitive data. | New Order - Object Relationship Abuse, CVE-2017-8570, OfficeMacro, Hawkeye Keylogger | 2018-06-14 13:40:18 |
>| 12126 | Remote access trojan | These messages claim to have attached payment information in an attempt to entice users into interacting with the attached document. The attached .docx document is booby-trapped, designed to exploit CVE-2017-0199. Should this exploit be successfully triggered, it will retrieve and open an RTF file from a remote server. This RTF file attempts to exploit CVE-2017-11882. Should the exploit be successful, a sample of the WebMonitor Remote Access Trojan is downloaded and run. WebMonitor has many different capabilities including the ability to view Bluetooth information, steal credentials, control webcams, log keystrokes, take screenshots, and to provide the threat actors with remote access to the victim's machine. | Your Payment - CVE-2017-0199, CVE-2017-11882, WebMonitor RAT | 2018-07-02 13:41:53 |
>| 12244 |  | This campaign attempts to entice recipients into interacting with the attached files by claiming to have important information from Coast Capital Savings. The attachment is a .zip archive containing an obfuscated .vbs Visual Basic script. Once run, this script extracts several components that it uses to gather information about the victims' machine which it then exfiltrates to the threat actor. The malware then continues connecting to its command and control location to wait for additional commands. | Coast Capital Savings Credit Union - Malicious Visual Basic Script | 2018-07-10 17:49:38 |
>| 12887 | Encryption Ransomware which frequently changes its C2 communication methods | These messages claim to be job applications and have the relevant resume attached. The attachment is a zip archive containing 2 executable samples of the GandCrab ransomware. Recent versions of GandCrab encrypt the victim's files and present them with a ransom note explaining where to go and how to render the required payment. GandCrab then exfiltrates information to a large number of hard coded command and control locations. This GandCrab sample claims to be version 4, it no longer uses .bit and .coin command and control locations and can encrypt victims offline. At the time of this analysis the requested ransom was $1200 USD. | Application - GandCrab v4 Ransomware | 2019-01-16 15:49:34 |
>| 12898 | Botnet malware | These emails impersonate BBVA Compass, claiming to deliver payment information and make the request to view the attached file. The attachment is a Microsoft Office Word document containing a malicious Office macro tasked with downloading and executing a sample of the Ursnif malware. Ursnif is a data stealer, exfiltrating keystroke logs, browsing history, and other potentially sensitive information via its command and control location. | Paid/Closed Heloc Letter - OfficeMacro, Ursnif | 2018-08-28 14:46:23 |
>| 13962 | DDoS Capable multi-functional RAT | These messages claim to contain a quotation request in the attached file. The file is a .zip archive containing a Windows shortcut .lnk file. Interacting with the shortcut downloads and executes a PowerShell script. When run, the PowerShell script downloads and displays a decoy image before decoding and running an embedded executable. The executable is a sample of the DarkComet Remote Access Trojan. This malware is tasked with providing the threat actors with remote access to the victim's machine, as well as the capability to exfiltrate sensitive data via its command and control location. Additional .lnk payload locations were found during the course of this analysis. | Quotation Request - LNK Downloader, Malicious Powershell Script, Dark Comet RAT | 2018-10-12 12:28:46 |
>| 14078 | Malware capable of collecting victim keystrokes for exfiltration | These messages claim to have information about a shipment from DHL available to recipients via a link embedded i the message body. Clicking the link downloads a Microsoft Office document containing a hostile macro script used to decode and run an embedded executable sample of the Limitless Keylogger. This keylogger has a number of capabilities that make it a robust espionage tool. In addition to being able to dump stored and session credentials, this malware is capable of taking screenshots of user activity and collecting keystrokes from the Windows environment. It is also capable of spreading via many different methods including removable USB devices and instant messaging. This malware exfiltrates this information to the threat actors' command and control location via email. | Package Notification - OfficeMacro, Limitless Keylogger | 2018-10-16 17:46:45 |
>| 14794 | Adaptable financial crimes botnet trojan with email worm and malware delivery capabilities, also known as Emotet<br/>Advanced banking trojan utilizing both webinjects and browser redirection | Multilingual invoice themed messages deliver Microsoft Word documents containing Office macros which download Geodo malware. Geodo then downloads and runs the banking trojan IcedID. | Invoices - OfficeMacro, Geodo, IcedID | 2018-11-08 20:13:04 |
>| 14943 | Information stealer designed to steal stored credentials and cryptocurrency wallets | Receipt themed emails deliver AZORult malware. | CTM Receipt - AZORult | 2018-11-13 15:55:51 |


### file
***
Checks the reputation of a file hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | A CSV list of file hashes to check (MD5, SHA1, or SHA256). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.Threat.id | Number | Threat ID | 
| CofenseIntelligence.Threat.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.Threat.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.Threat.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.Threat.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.Threat.blockSet.confidence | Number | level of confidence in the threats block | 
| CofenseIntelligence.Threat.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.Threat.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.Threat.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.Threat.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.Threat.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.Threat.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.Threat.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.Threat.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.Threat.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.Threat.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.Threat.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.Threat.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.Threat.executableSet.fileNameExtension | String | extension of the file | 
| CofenseIntelligence.Threat.executableSet.md5Hex | String | The md5 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.Threat.executableSet.executableSubtype.description | String | description of the executable file | 
| CofenseIntelligence.Threat.senderIpSet.totalCount | Number | Count of the instances of each item named. | 
| CofenseIntelligence.Threat.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Threat.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.Threat.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.Threat.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.Threat.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.Threat.label | String | Human readable name for this campaign | 
| CofenseIntelligence.Threat.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.Threat.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.Threat.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.Threat.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.Threat.threatType | String | This will only have one value for malware | 


#### Command Example
```!file file=md5 using=CofenseIntelligenceV2_instance_1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "md5",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "file",
        "Vendor": "CofenseIntelligenceV2"
    },
    "File": {
        "MD5": "md5"
    }
}
```

#### Human Readable Output

>### Cofense file Reputation for file md5
>**No entries.**


### email
***
Checks the reputation of an email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Sender email address to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.Threat.id | Number | Threat ID | 
| CofenseIntelligence.Threat.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.Threat.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.Threat.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.Threat.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.Threat.blockSet.confidence | Number | level of confidence in the threats block | 
| CofenseIntelligence.Threat.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.Threat.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.Threat.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.Threat.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.Threat.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.Threat.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.Threat.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.Threat.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.Threat.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.Threat.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.Threat.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.Threat.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.Threat.executableSet.fileNameExtension | String | extension of the file | 
| CofenseIntelligence.Threat.executableSet.md5Hex | String | The md5 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.Threat.executableSet.executableSubtype.description | String | description of the executable file | 
| CofenseIntelligence.Threat.senderIpSet.totalCount | Number | Count of the instances of each item named. | 
| CofenseIntelligence.Threat.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Threat.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.Threat.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.Threat.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.Threat.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.Threat.label | String | Human readable name for this campaign | 
| CofenseIntelligence.Threat.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.Threat.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.Threat.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.Threat.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.Threat.threatType | String | This will only have one value for malware | 


#### Command Example
```!email email=email@email.com using=CofenseIntelligenceV2_instance_1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "email@email.com",
        "Reliability": "B - Usually reliable",
        "Score": 0,
        "Type": "email",
        "Vendor": "CofenseIntelligenceV2"
    },
    "EMAIL": {
        "Address": "email@email.com",
        "Domain": "email.com"
    }
}
```

#### Human Readable Output

>### Cofense email Reputation for email email@email.com
>**No entries.**


### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Reliability | string | The actual score. | 
| CofenseIntelligence.Threat.id | Number | Threat ID | 
| CofenseIntelligence.Threat.feeds.id | Number | Integer identifier for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.WRITE | Boolean | True if you are allowed to submit data to this feed | 
| CofenseIntelligence.Threat.feeds.permissions.OWNER | Boolean | True if you are the original provider of the source data for this feed | 
| CofenseIntelligence.Threat.feeds.permissions.READ | Boolean | True if you are allowed to view data for this feed | 
| CofenseIntelligence.Threat.feeds.displayName | String | Human readable name for this feed | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.familyName | String | Names and describes malware families | 
| CofenseIntelligence.Threat.blockSet.malwareFamily.description | String | Brief description of the malware family, what it does, or how it works | 
| CofenseIntelligence.Threat.blockSet.impact | String | Values borrowed from stixVocabs:ImpactRatingVocab-1.0 | 
| CofenseIntelligence.Threat.blockSet.confidence | Number | level of confidence in the threats block | 
| CofenseIntelligence.Threat.blockSet.blockType | String | Data type of the watchlist item | 
| CofenseIntelligence.Threat.blockSet.roleDescription | String | Description of infrastructure type | 
| CofenseIntelligence.Threat.blockSet.role | String | Infrastructure Type | 
| CofenseIntelligence.Threat.blockSet.infrastructureTypeSubclass.description | String | Brief description of infrastructure type being used | 
| CofenseIntelligence.Threat.blockSet.data | String | Domain name or an IP address | 
| CofenseIntelligence.Threat.blockSet.data_1 | String | Either a domain name or an IP address | 
| CofenseIntelligence.Threat.campaignBrandSet.totalCount | Number | Number of individual messages associated with this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.id | Number | Numeric identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.campaignBrandSet.brand.text | String | String identifier used by Malcovery to track this brand | 
| CofenseIntelligence.Threat.domainSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.domainSet.domain | String | Sender domain name | 
| CofenseIntelligence.Threat.senderEmailSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderEmailSet.senderEmail | String | The possibly spoofed email address used in the delivery of the email. | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.executableSet.malwareFamily.description | String | Names and describes malware families. | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.detected | Boolean | Was executable detected? | 
| CofenseIntelligence.Threat.executableSet.vendorDetections.threatVendorName | String | Name of antivirus vendor | 
| CofenseIntelligence.Threat.executableSet.fileName | String | The file name of any file discovered during a malware infection | 
| CofenseIntelligence.Threat.executableSet.type | String | Description of the purpose this file serves within the malware infection | 
| CofenseIntelligence.Threat.executableSet.dateEntered | Date | Date when this file was analyzed by Malcovery | 
| CofenseIntelligence.Threat.executableSet.severityLevel | String | The malware infection severity level | 
| CofenseIntelligence.Threat.executableSet.fileNameExtension | String | extension of the file | 
| CofenseIntelligence.Threat.executableSet.md5Hex | String | The md5 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha384Hex | String | The SHA-384 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha512Hex | String | The SHA-512 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha1Hex | String | The SHA-1 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha224Hex | String | The SHA-224 hash of the file | 
| CofenseIntelligence.Threat.executableSet.sha256Hex | String | The SHA-256 hash of the file | 
| CofenseIntelligence.Threat.executableSet.executableSubtype.description | String | description of the executable file | 
| CofenseIntelligence.Threat.senderIpSet.totalCount | Number | Count of the instances of each item named. | 
| CofenseIntelligence.Threat.senderIpSet.ip | String | One of possibly many IPs used in the delivery of the email. | 
| CofenseIntelligence.Threat.senderNameSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.senderNameSet.name | String | This is the friendly name of the sender of the email | 
| CofenseIntelligence.Threat.subjectSet.totalCount | Number | Count of the instances of each item named | 
| CofenseIntelligence.Threat.subjectSet.subject | String | Email subject line | 
| CofenseIntelligence.Threat.lastPublished | Date | Timestamp of when this campaign was most recently updated | 
| CofenseIntelligence.Threat.firstPublished | Date | Timestamp of when this campaign was initially published | 
| CofenseIntelligence.Threat.label | String | Human readable name for this campaign | 
| CofenseIntelligence.Threat.executiveSummary | String | Analyst written summary of the campaign | 
| CofenseIntelligence.Threat.hasReport | Boolean | Flag to show whether this campaign has a written report associated with it | 
| CofenseIntelligence.Threat.reportURL | String | Direct URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.apiReportURL | String | URL to human readable report for this campaign | 
| CofenseIntelligence.Threat.threatDetailURL | String | T3 Report URL | 
| CofenseIntelligence.Threat.malwareFamilySet.familyName | String | Family name of malware | 
| CofenseIntelligence.Threat.malwareFamilySet.description | String | Set of malware family | 
| CofenseIntelligence.Threat.threatType | String | This will only have one value for malware | 


#### Command Example
```!url url=http://prosciuttuamo.it/tmp/ifeanyi.exe using=CofenseIntelligenceV2_instance_1```

#### Context Example
```json
{
    "CofenseIntelligence": {
        "Threat": {
            "apiReportURL": "https://www.threathq.com/apiv1/t3/malware/10882/html",
            "blockSet": [
                {
                    "blockType": "URL",
                    "confidence": 0,
                    "data": "http://prosciuttuamo.it/tmp/ifeanyi.exe",
                    "data_1": {
                        "domain": "prosciuttuamo.it",
                        "host": "prosciuttuamo.it",
                        "path": "/tmp/ifeanyi.exe",
                        "protocol": "http",
                        "url": "http://prosciuttuamo.it/tmp/ifeanyi.exe"
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
                    "confidence": 0,
                    "data": "prosciuttuamo.it",
                    "data_1": "prosciuttuamo.it",
                    "deliveryMechanism": {
                        "description": "Microsoft Office documents with macro scripting for malware delivery",
                        "mechanismName": "OfficeMacro"
                    },
                    "impact": "Major",
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
                    "description": "Microsoft Office documents with macro scripting for malware delivery",
                    "mechanismName": "OfficeMacro"
                }
            ],
            "domainSet": [],
            "executableSet": [
                {
                    "dateEntered": 1519398005902,
                    "executableSubtype": {
                        "description": "Persistence module or file"
                    },
                    "fileName": "brightness.exe",
                    "fileNameExtension": "exe",
                    "malwareFamily": {
                        "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                        "familyName": "Agent Tesla"
                    },
                    "md5Hex": "f35fde4c89835f7572097ff81f276ba0",
                    "severityLevel": "Major",
                    "sha1Hex": "77745c2f07b784b8b141ab02891d3edd6cefef66",
                    "sha224Hex": "2cfe240cca8d529c9d4644a96bbf974ef67235212cef348006e54126",
                    "sha256Hex": "9d7c877bd2f32f0167df79a7ab790bb51601168106ea4046b80b4c849f09d007",
                    "sha384Hex": "9de1ac275fa190628e050c90d9fb332cb11a6706c06e758a599893b60b5297e06f8c0b01f9e0da49f51202372c90f79f",
                    "sha512Hex": "041f5b6e9cab20fdb3035346868e26c0b37f4091941e49e79ea1206bb0a6aca4bfa71521be53bf7999b1658622aa9cc84e617b87de6775e2ef42fb24a1055186",
                    "ssdeep": "6144:R/6LbrXfRdYdEqmEeVpWDaFIJ9tRRV4pOJfaAR:BOtKEXHVWoOJP",
                    "type": "Drop",
                    "vendorDetections": [
                        {
                            "detected": true,
                            "threatVendorName": "Invincea"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "AhnLab-V3"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Cyren"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Emsisoft"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "ZoneAlarm"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "nProtect"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "AVG"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "AegisLab"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Comodo"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "MAX"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "VBA32"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Fortinet"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "SentinelOne"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Baidu"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "F-Prot"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Symantec"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Jiangmin"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Antiy-AVL"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Microsoft"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "GData"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ALYac"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Kaspersky"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "AVware"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "CMC"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "TrendMicro"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Zoner"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Bkav"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Malwarebytes"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Yandex"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ClamAV"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "CAT-QuickHeal"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "CrowdStrike"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "TheHacker"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "ESET-NOD32"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "McAfee-GW-Edition"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Tencent"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "K7GW"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Qihoo-360"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Arcabit"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Cylance"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "WhiteArmor"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Webroot"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "TrendMicro-HouseCall"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "K7AntiVirus"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "McAfee"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "VIPRE"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "MicroWorld-eScan"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "eGambit"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Avast"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Panda"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Sophos"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "DrWeb"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "NANO-Antivirus"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Rising"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Avira"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "BitDefender"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "SUPERAntiSpyware"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Endgame"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "F-Secure"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Ikarus"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Paloalto"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Cybereason"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Ad-Aware"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Avast-Mobile"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Zillya"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ViRobot"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Kingsoft"
                        }
                    ]
                },
                {
                    "dateEntered": 1519396864251,
                    "deliveryMechanism": {
                        "description": "Microsoft Office documents with macro scripting for malware delivery",
                        "mechanismName": "OfficeMacro"
                    },
                    "fileName": "confirm bank details.doc",
                    "fileNameExtension": "doc",
                    "md5Hex": "f75336ad0aacf070c73af87c5c27c661",
                    "severityLevel": "Major",
                    "sha1Hex": "142acabb7c22198b8421e48535a05114c773a7c4",
                    "sha224Hex": "87e98c9cb085688c0ea293b9d861a34f5f6436303eec97e884e290ee",
                    "sha256Hex": "4da99d163ad6997bb77e7ec055d87858bff2fa538807f0d26437eabc5ba64cd6",
                    "sha384Hex": "b037b5ae0fffecea46aaad2109b4786b1f69b76f332aa6e76f52ef60d11527c047373e8e463479f0b7cc213d826b30f2",
                    "sha512Hex": "5c7b13151cf4850aa26fdfcd46d616f77e05956c1ec38a88dbbc642904caede76a6f38d43cd00c356cb7f6b390a6ad085cfb7270114b4394450431f1587e098d",
                    "ssdeep": "12288:6dkdY2/yIrvUGhokV+/eQGUacHsjYwhY7Y+TmO7ogKd9iJ+6kQjAEt:6dkpfTFhJV+svp+qOLKLSiEt",
                    "type": "Attachment",
                    "vendorDetections": [
                        {
                            "detected": true,
                            "threatVendorName": "MAX"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Avira"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "McAfee"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "F-Secure"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "K7GW"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Jiangmin"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "TheHacker"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "AhnLab-V3"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "F-Prot"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Bkav"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Zillya"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "WhiteArmor"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "GData"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "ESET-NOD32"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Comodo"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Avast-Mobile"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "NANO-Antivirus"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "TrendMicro-HouseCall"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Ad-Aware"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ALYac"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "SUPERAntiSpyware"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "VBA32"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "VIPRE"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "McAfee-GW-Edition"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "DrWeb"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Emsisoft"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Panda"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "AVG"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Zoner"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Arcabit"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Qihoo-360"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "MicroWorld-eScan"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Fortinet"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Malwarebytes"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Antiy-AVL"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "CMC"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "BitDefender"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Alibaba"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "AVware"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Kingsoft"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Ikarus"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "K7AntiVirus"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "TrendMicro"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Rising"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "ZoneAlarm"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Tencent"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Kaspersky"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Cyren"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Sophos"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Webroot"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ViRobot"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ClamAV"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Baidu"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "CAT-QuickHeal"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Yandex"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Symantec"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Microsoft"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "nProtect"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Avast"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "AegisLab"
                        }
                    ]
                },
                {
                    "dateEntered": 1519398005917,
                    "fileName": "ifeanyi.exe",
                    "fileNameExtension": "exe",
                    "malwareFamily": {
                        "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                        "familyName": "Agent Tesla"
                    },
                    "md5Hex": "f35fde4c89835f7572097ff81f276ba0",
                    "severityLevel": "Major",
                    "sha1Hex": "77745c2f07b784b8b141ab02891d3edd6cefef66",
                    "sha224Hex": "2cfe240cca8d529c9d4644a96bbf974ef67235212cef348006e54126",
                    "sha256Hex": "9d7c877bd2f32f0167df79a7ab790bb51601168106ea4046b80b4c849f09d007",
                    "sha384Hex": "9de1ac275fa190628e050c90d9fb332cb11a6706c06e758a599893b60b5297e06f8c0b01f9e0da49f51202372c90f79f",
                    "sha512Hex": "041f5b6e9cab20fdb3035346868e26c0b37f4091941e49e79ea1206bb0a6aca4bfa71521be53bf7999b1658622aa9cc84e617b87de6775e2ef42fb24a1055186",
                    "ssdeep": "6144:R/6LbrXfRdYdEqmEeVpWDaFIJ9tRRV4pOJfaAR:BOtKEXHVWoOJP",
                    "type": "Download",
                    "vendorDetections": [
                        {
                            "detected": false,
                            "threatVendorName": "Avast-Mobile"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "CMC"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Zillya"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "K7GW"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "K7AntiVirus"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Tencent"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Cyren"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "WhiteArmor"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Symantec"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Zoner"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ViRobot"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Comodo"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ALYac"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "McAfee-GW-Edition"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Kingsoft"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Webroot"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "eGambit"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Sophos"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Ikarus"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "AegisLab"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "GData"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "MAX"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "AVG"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Baidu"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Cybereason"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Qihoo-360"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "AhnLab-V3"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Bkav"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Ad-Aware"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Jiangmin"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "TheHacker"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "AVware"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "F-Prot"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Fortinet"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "CrowdStrike"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Endgame"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "MicroWorld-eScan"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "ClamAV"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Avast"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Emsisoft"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "VBA32"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Cylance"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Microsoft"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Rising"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "NANO-Antivirus"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Malwarebytes"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "DrWeb"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Paloalto"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Avira"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "SentinelOne"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Panda"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "McAfee"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Invincea"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "ESET-NOD32"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "TrendMicro-HouseCall"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Antiy-AVL"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "nProtect"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "VIPRE"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "SUPERAntiSpyware"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "TrendMicro"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Arcabit"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "BitDefender"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "Kaspersky"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "CAT-QuickHeal"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "F-Secure"
                        },
                        {
                            "detected": true,
                            "threatVendorName": "ZoneAlarm"
                        },
                        {
                            "detected": false,
                            "threatVendorName": "Yandex"
                        }
                    ]
                }
            ],
            "executiveSummary": "These emails claim to be a request to confirm banking details within the attached Word document. In reality, the campaign delivers a weaponised .doc file which contains obfuscated macros, written to download and execute a payload from a remote server. In this instance, the retrieved executable is a sample of the Agent Tesla keylogger. Upon execution, Agent Tesla starts collecting sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
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
            "firstPublished": 1519416942654,
            "hasReport": true,
            "id": 10882,
            "label": "Banking Details - OfficeMacro, Agent Tesla Keylogger",
            "lastPublished": 1536338435096,
            "malwareFamilySet": [
                {
                    "description": "Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes.",
                    "familyName": "Agent Tesla"
                }
            ],
            "naicsCodes": [],
            "relatedSearchTags": [],
            "reportURL": "https://www.threathq.com/api/l/activethreatreport/10882/html",
            "senderEmailSet": [],
            "senderIpSet": [],
            "senderNameSet": [],
            "spamUrlSet": [],
            "subjectSet": [
                {
                    "subject": "Re-confirm your banking details",
                    "totalCount": 1
                }
            ],
            "threatDetailURL": "https://www.threathq.com/p42/search/default?m=10882",
            "threatType": "MALWARE"
        }
    },
    "DBotScore": {
        "Indicator": "http://prosciuttuamo.it/tmp/ifeanyi.exe",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "CofenseIntelligenceV2"
    },
    "URL": {
        "Data": "http://prosciuttuamo.it/tmp/ifeanyi.exe",
        "Malicious": {
            "Description": null,
            "Vendor": "CofenseIntelligenceV2"
        }
    }
}
```

#### Human Readable Output

>### Cofense URL Reputation for url http://prosciuttuamo.it/tmp/ifeanyi.exe
>|Threat ID|Threat Types|Verdict|Executive Summary|Campaign|Last Published|
>|---|---|---|---|---|---|
>| 10882 | Agent Tesla collects sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes. | Bad | These emails claim to be a request to confirm banking details within the attached Word document. In reality, the campaign delivers a weaponised .doc file which contains obfuscated macros, written to download and execute a payload from a remote server. In this instance, the retrieved executable is a sample of the Agent Tesla keylogger. Upon execution, Agent Tesla starts collecting sensitive information, such as saved credentials for web, ftp, email, and instant messaging clients. Additionally, Tesla gathers data about the victim's PC and captures keystrokes. | Banking Details - OfficeMacro, Agent Tesla Keylogger | 2018-09-07 16:40:35 |

