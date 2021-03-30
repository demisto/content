Analyzes suspicious hashes, URLs, domains, and IP addresses.
This integration was integrated and tested with version v3 API of VirusTotal (API v3)
## Configure VirusTotal (API v3) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for VirusTotal (API v3).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | See *Acquiring your API key* | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data |  |
    | Premium Subscription | Whether to use premium subscription (for advanced reputation analyze. See *Premium analysis: Relationship Files Threshold*) | False |
    | File Threshold. Minimum number of positive results from VT scanners to consider the file malicious. | See *Indicator Thresholds* section. | False |
    | IP Threshold. Minimum number of positive results from VT scanners to consider the IP malicious. | See *Indicator Thresholds* section. | False |
    | URL Threshold. Minimum number of positive results from VT scanners to consider the URL malicious. | See *Indicator Thresholds* section. | False |
    | Domain Threshold. Minimum number of positive results from VT scanners to consider the domain malicious. | See *Indicator Thresholds* section. | False |
    | Preferred Vendors List. CSV list of vendors who are considered more trustworthy. | See *Indicator Thresholds* section.  | False |
    | Preferred Vendor Threshold. The minimum number of highly trusted vendors required to consider a domain, IP address, URL, or file as malicious.  | See *Indicator Thresholds* section | False |
    | Enable score analyzing by Crowdsourced Yara Rules, Sigma, and IDS | See *Rules threshold* | False |
    | Crowdsourced Yara Rules Threshold | See *Rules threshold* | False |
    | Sigma and Intrusion Detection Rules Threshold | See *Rules threshold* | False |
    | Domain Popularity Ranking Threshold | See *Rules threshold* | False |
    | Premium Subscription Only: Relationship Files Threshold | See *Premium analysis: Relationship Files Threshold* | False |

4. Click **Test** to validate the URLs, token, and connection.

### Acquiring your API key:
Your API key can be found in your VirusTotal account user menu:  
![](https://files.readme.io/ddeb298-Screen_Shot_2019-10-17_at_3.17.04_PM.png)  
Your API key carries all your privileges, so keep it secure and don't share it with anyone.

## DBot Score / Reputation scores

The following information describes DBot Score which is new for this version.

### Indicator Thresholds
Configure the default threshold for each indicator type in the instance settings.
You can also specify the threshold as an argument when running relevant commands.
Indicators with positive results from preferred vendors equal to or higher than threshold will be considered malicious.
Indicators with positive results equal to or higher than the threshold will be considered malicious.
Indicators with positive results equal to or higher than half of the threshold value, and lower than the threshold, will be considered suspicious.

### Rules threshold
If the YARA rules analysis threshold is enabled:
Indicators with positive results, the number of found YARA rules results, Sigma analysis, or IDS equal to or higher than the threshold, will be considered suspicious.
If both the the basic analysis and the rules analysis is suspicious, the indicator will be considered as malicious.
If the indicator was found to be suspicious only by the rules thresholds, the indicator will be considered suspicious.


### Premium analysis: Relationship Files Threshold
If the organization is using the premium subscription of VirusTotal, you can use the premium API analysis.
The premium API analysis will check 3 file relationships of each indicator (domain, url, and ip).
If the relationship is found to be malicious, the indicator will be considered malicious.
If the relationship is found to be suspicious and the basic score is suspicious, the indicator will be considered malicious.
If the relationship is found to be suspicious, the indicator will be considered suspicious.

The premium API analysis can call up to 4 API calls per indicator. If you want to decrease the use of the API quota, you can disable it.


## Changes by Commands
The following lists the changes in this version according to commands from VirusTotal integration.

### Reputation commands (ip, url, domain, and file)
- Will only get information from VirusTotal. Will not analyze the indicator if it does
not exist.
- Added output paths: For each command, outputs will appear under *VirusTotal.IP*, *VirusTotal.Domain*, *VirusTotal.File* and *VirusTotal.URL*.
- Removed output paths: Due to changes in VirusTotal API, *IP.VirusTotal*, *Domain.VirusTotal*, *URL.VirusTotal*, *File.VirusTotal* will no longer supported.
instead, you can use *VirusTotal.Domain* and *VirusTotal.IP* which returns concrete indicator's reputation.
- The *file* and *url* commands will no longer analyse the file/url sent to it, but will get the information stored in VirusTotal.  
  If you wish to analyze (detonate) the indicator, you can use the *Detonate File - VirusTotal V3* and *Detonate URL - VirusTotal V3* playbooks.
- Each reputation command will use at least 1 API call. For advanced reputation commands, use the *Premium API* flag.

### Comments
In VirusTotal v3 you can now add comments to all indicator types (IP, Domain, File and URL) so each command now has the *resource_type* argument.
If supplied, the command will use the resource type to add a comment. If not, the command will determine if the given input is a hash or a URL.
This arguments is available in the **vt-comments-get** and **vt-comments-add** commands.

### vt-comments-get:
- Added the *resource_type* argument. If not supplied, will try to determine if the *resource* argument is a hash or a URL.
- Added the *limit* argument: Gets the latest comments within the given limit.
- New output path: *VirusTotal.Comments*.

### Detonation (scan) commands
The *vtLink* output removed from all commands as it does not longer returns from the API.
To easily use the scan commands we suggest to use the **Detonate File - VirusTotal V3** and **Detonate URL - VirusTotal V3** playbooks.
The command to get the report from the scans is **vt-analysis-get**.

### file-rescan:
- New output path: *VirusTotal.Submission*
- Preserved output: *vtScanID*
- Removed output path: *vtLink* - The V3 API does not returns a link to the GUI anymore.


### file-scan
- New output path: *VirusTotal.Submission*
- Preserved output: *vtScanID*
- Removed output path: *vtLink* - The V3 API does not returns a link to the GUI anymore.


### url-scan 
- New output path: *VirusTotal.Submission*
- Preserved output: *vtScanID*
- Removed output path: *vtLink* - The V3 API does not returns a link to the GUI anymore.

### vt-file-scan-upload-url: 
- New output path: *VirusTotal.FileUploadURL*
- Preserved output: *vtUploadURL*

## New Commands
- ***vt-search***
- ***vt-ip-passive-dns-data***
- ***vt-file-sandbox-report***
- ***vt-comments-get-by-id***
- ***vt-analysis-get***

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### file
***
Checks the file reputation of the specified hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports MD5, SHA1, and SHA256. | Required | 
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | unknown | Bad MD5 hash. | 
| File.SHA1 | unknown | Bad SHA1 hash. | 
| File.SHA256 | unknown | Bad SHA256 hash. | 
| File.Malicious.Vendor | unknown | For malicious files, the vendor that made the decision. | 
| File.Malicious.Detections | unknown | For malicious files, the total number of detections. | 
| File.Malicious.TotalEngines | unknown | For malicious files, the total number of engines that checked the file hash. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the DBot score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| VirusTotal.File.attributes.type_description | String | Description of the type of the file. | 
| VirusTotal.File.attributes.tlsh | String | The locality-sensitive hashing. | 
| VirusTotal.File.attributes.exiftool.MIMEType | String | MIME type of the file. | 
| VirusTotal.File.attributes.names | String | Names of the file. | 
| VirusTotal.File.attributes.javascript_info.tags | String | Tags of the JavaScript. | 
| VirusTotal.File.attributes.exiftool.FileType | String | The file type. | 
| VirusTotal.File.attributes.exiftool.WordCount | String | Total number of words in the file. | 
| VirusTotal.File.attributes.exiftool.LineCount | String | Total number of lines in file. | 
| VirusTotal.File.attributes.crowdsourced_ids_stats.info | Number | Number of IDS that marked the file as "info". | 
| VirusTotal.File.attributes.crowdsourced_ids_stats.high | Number | Number of IDS that marked the file as "high". | 
| VirusTotal.File.attributes.crowdsourced_ids_stats.medium | Number | Number of IDS that marked the file as "medium". | 
| VirusTotal.File.attributes.crowdsourced_ids_stats.low | Number | Number of IDS that marked the file as "low". | 
| VirusTotal.File.attributes.sigma_analysis_stats.critical | Number | Number of Sigma analysis that marked the file as "critical". | 
| VirusTotal.File.attributes.sigma_analysis_stats.high | Number | Number of Sigma analysis that marked the file as "high". | 
| VirusTotal.File.attributes.sigma_analysis_stats.medium | Number | Number of Sigma analysis that marked the file as "medium". | 
| VirusTotal.File.attributes.sigma_analysis_stats.low | Number | Number of Sigma analysis that marked the file as "low". | 
| VirusTotal.File.attributes.exiftool.MIMEEncoding | String | The MIME encoding. | 
| VirusTotal.File.attributes.exiftool.FileTypeExtension | String | The file type extension. | 
| VirusTotal.File.attributes.exiftool.Newlines | String | Number of newlines signs. | 
| VirusTotal.File.attributes.trid.file_type | String | The TrID file type. | 
| VirusTotal.File.attributes.trid.probability | Number | The TrID probability. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.description | String | Description of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.source | String | Source of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.author | String | Author of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.ruleset_name | String | Rule set name of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.rule_name | String | Name of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.ruleset_id | String | ID of the YARA rule. | 
| VirusTotal.File.attributes.names | String | Name of the file. | 
| VirusTotal.File.attributes.last_modification_date | Number | The last modification date in epoch format. | 
| VirusTotal.File.attributes.type_tag | String | Tag of the type. | 
| VirusTotal.File.attributes.total_votes.harmless | Number | Total number of harmless votes. | 
| VirusTotal.File.attributes.total_votes.malicious | Number | Total number of malicious votes. | 
| VirusTotal.File.attributes.size | Number | Size of the file. | 
| VirusTotal.File.attributes.popular_threat_classification.suggested_threat_label | String | Suggested thread label. | 
| VirusTotal.File.attributes.popular_threat_classification.popular_threat_name | Number | The popular thread name. | 
| VirusTotal.File.attributes.times_submitted | Number | Number of times the file was submitted. | 
| VirusTotal.File.attributes.last_submission_date | Number | Last submission date in epoch format. | 
| VirusTotal.File.attributes.downloadable | Boolean | Whether the file is downloadable. | 
| VirusTotal.File.attributes.sha256 | String | SHA-256 hash of the file. | 
| VirusTotal.File.attributes.type_extension | String | Extension of the type. | 
| VirusTotal.File.attributes.tags | String | File tags. | 
| VirusTotal.File.attributes.last_analysis_date | Number | Last analysis date in epoch format. | 
| VirusTotal.File.attributes.unique_sources | Number | Unique sources. | 
| VirusTotal.File.attributes.first_submission_date | Number | First submission date in epoch format. | 
| VirusTotal.File.attributes.ssdeep | String | SSDeep hash of the file. | 
| VirusTotal.File.attributes.md5 | String | MD5 hash of the file. | 
| VirusTotal.File.attributes.sha1 | String | SHA-1 hash of the file. | 
| VirusTotal.File.attributes.magic | String | Identification of file by the magic number. | 
| VirusTotal.File.attributes.last_analysis_stats.harmless | Number | The number of engines that found the indicator to be harmless. | 
| VirusTotal.File.attributes.last_analysis_stats.type-unsupported | Number | The number of engines that found the indicator to be of type unsupported. | 
| VirusTotal.File.attributes.last_analysis_stats.suspicious | Number | The number of engines that found the indicator to be suspicious. | 
| VirusTotal.File.attributes.last_analysis_stats.confirmed-timeout | Number | The number of engines that confirmed the timeout of the indicator. | 
| VirusTotal.File.attributes.last_analysis_stats.timeout | Number | The number of engines that timed out for the indicator. | 
| VirusTotal.File.attributes.last_analysis_stats.failure | Number | The number of failed analysis engines. | 
| VirusTotal.File.attributes.last_analysis_stats.malicious | Number | The number of engines that found the indicator to be malicious. | 
| VirusTotal.File.attributes.last_analysis_stats.undetected | Number | The number of engines that could not detect the indicator. | 
| VirusTotal.File.attributes.meaningful_name | String | Meaningful name of the file. | 
| VirusTotal.File.attributes.reputation | Number | The reputation of the file. | 
| VirusTotal.File.type | String | Type of the indicator \(file\). | 
| VirusTotal.File.id | String | Type ID of the indicator. | 
| VirusTotal.File.links.self | String | Link to the response. | 


#### Command Example
```!file file=17bb7bda507abc602bdf1b160d7f51edaccac39fd34f8dab1e793c3612cfc8c2```

#### Human Readable Output

>Could not process file: "17bb7bda507abc602bdf1b160d7f51edaccac39fd34f8dab1e793c3612cfc8c2"
> Error in API call [404] - Not Found
>{"error": {"message": "File \"17bb7bda507abc602bdf1b160d7f51edaccac39fd34f8dab1e793c3612cfc8c2\" not found", "code": "NotFoundError"}}

### ip
***
Checks the reputation of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | unknown | Bad IP address. | 
| IP.ASN | unknown | Bad IP ASN. | 
| IP.Geo.Country | unknown | Bad IP country. | 
| IP.Malicious.Vendor | unknown | For malicious IPs, the vendor that made the decision. | 
| IP.Malicious.Description | unknown | For malicious IPs, the reason that the vendor made the decision. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the DBot score. | 
| DBotScore.Score | unknown | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| VirusTotal.IP.attributes.regional_internet_registry | String | Regional internet registry \(RIR\). | 
| VirusTotal.IP.attributes.jarm | String | JARM data. | 
| VirusTotal.IP.attributes.network | String | Network data. | 
| VirusTotal.IP.attributes.country | String | The country where the IP is located. | 
| VirusTotal.IP.attributes.as_owner | String | IP owner. | 
| VirusTotal.IP.attributes.last_analysis_stats.harmless | Number | The number of engines that found the domain to be harmless. | 
| VirusTotal.IP.attributes.last_analysis_stats.malicious | Number | The number of engines that found the indicator to be malicious. | 
| VirusTotal.IP.attributes.last_analysis_stats.suspicious | Number | The number of engines that found the indicator to be suspicious. | 
| VirusTotal.IP.attributes.last_analysis_stats.undetected | Number | The number of engines that could not detect the indicator. | 
| VirusTotal.IP.attributes.last_analysis_stats.timeout | Number | The number of engines that timed out for the indicator. | 
| VirusTotal.IP.attributes.asn | Number | ASN data. | 
| VirusTotal.IP.attributes.whois_date | Number | Date of the last update of the whois record. | 
| VirusTotal.IP.attributes.reputation | Number | IP reputation. | 
| VirusTotal.IP.attributes.last_modification_date | Number | Last modification date in epoch format. | 
| VirusTotal.IP.attributes.total_votes.harmless | Number | Total number of harmless votes. | 
| VirusTotal.IP.attributes.total_votes.malicious | Number | Total number of malicious votes. | 
| VirusTotal.IP.attributes.continent | String | The continent where the IP is located. | 
| VirusTotal.IP.attributes.whois | String | whois data. | 
| VirusTotal.IP.type | String | Indicator IP type. | 
| VirusTotal.IP.id | String | ID of the IP. | 


#### Command Example
```!ip ip=1.1.1.1```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Reliability": "A - Completely reliable",
        "Score": 1,
        "Type": "ip",
        "Vendor": "VirusTotal"
    },
    "IP": {
        "ASN": 13335,
        "Address": "1.1.1.1",
        "DetectionEngines": 82,
        "Geo": {
            "Country": "AU"
        },
        "PositiveDetections": 1
    },
    "VirusTotal": {
        "IP": {
            "attributes": {
                "as_owner": "CLOUDFLARENET",
                "asn": 13335,
                "continent": "OC",
                "country": "AU",
                "jarm": "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",
                "last_analysis_stats": {
                    "harmless": 73,
                    "malicious": 1,
                    "suspicious": 1,
                    "timeout": 0,
                    "undetected": 7
                },
                "last_https_certificate": {
                    "cert_signature": {
                        "signature": "3064023024c2cf6cbdf6aed1c9d51f4a742e3c3dd1c03edcd71bd394715bfea5861626820122d30a6efc98b5d2e2b9e5076977960230457b6f82a67db662c33185d5b5355d4f4c8488ac1a003d0c8440dcb0a7ca1c1327151e37f946c3aed9fdf9b9238b7f2a",
                        "signature_algorithm": "1.2.840.10045.4.3.3"
                    },
                    "extensions": {
                        "1.3.6.1.4.1.11129.2.4.2": "0481f200f00076002979bef09e393921f056739f63a577e5be577d9c600af8f9",
                        "CA": true,
                        "authority_key_identifier": {
                            "keyid": "0abc0829178ca5396d7a0ece33c72eb3edfbc37a"
                        },
                        "ca_information_access": {
                            "CA Issuers": "http://cacerts.digicert.com/DigiCertTLSHybridECCSHA3842020CA1.crt",
                            "OCSP": "http://ocsp.digicert.com"
                        },
                        "certificate_policies": [
                            "2.16.840.1.114412.1.1",
                            "2.23.140.1.2.2"
                        ],
                        "crl_distribution_points": [
                            "http://crl3.digicert.com/DigiCertTLSHybridECCSHA3842020CA1.crl",
                            "http://crl4.digicert.com/DigiCertTLSHybridECCSHA3842020CA1.crl"
                        ],
                        "extended_key_usage": [
                            "serverAuth",
                            "clientAuth"
                        ],
                        "key_usage": [
                            "ff"
                        ],
                        "subject_alternative_name": [
                            "cloudflare-dns.com",
                            "*.cloudflare-dns.com",
                            "one.one.one.one",
                            "\u0001\u0001\u0001\u0001",
                            "\u0001\u0001",
                            "\\xa2\\x9f$\\x01",
                            "\\xa2\\x9f.\\x01",
                            "&\u0006GG\u0011\u0011",
                            "&\u0006GG\u0010\u0001",
                            "GGd",
                            "GGd"
                        ],
                        "subject_key_identifier": "e1b6fc06f9b98b05f4c1e2489b02b90bc1b53d79",
                        "tags": []
                    },
                    "issuer": {
                        "C": "US",
                        "CN": "DigiCert TLS Hybrid ECC SHA384 2020 CA1",
                        "O": "DigiCert Inc"
                    },
                    "public_key": {
                        "algorithm": "EC",
                        "ec": {
                            "oid": "secp256r1",
                            "pub": "0417ad1fe835af70d38d9c9e64fd471e5b970c0ad110a826321136664d1299c3e131bbf5216373dda5c1c1a0f06da4c45ee1c2dbdaf90d34801af7b9e03af2d574"
                        }
                    },
                    "serial_number": "5076f66d11b692256ccacd546ffec53",
                    "signature_algorithm": "1.2.840.10045.4.3.3",
                    "size": 1418,
                    "subject": {
                        "C": "US",
                        "CN": "cloudflare-dns.com",
                        "L": "San Francisco",
                        "O": "Cloudflare, Inc.",
                        "ST": "California"
                    },
                    "tags": [],
                    "thumbprint": "f1b38143b992645497cf452f8c1ac84249794282",
                    "thumbprint_sha256": "fb444eb8e68437bae06232b9f5091bccff62a768ca09e92eb5c9c2cf9d17c426",
                    "validity": {
                        "not_after": "2022-01-18 23:59:59",
                        "not_before": "2021-01-11 00:00:00"
                    },
                    "version": "V3"
                },
                "last_https_certificate_date": 1617041198,
                "last_modification_date": 1617083545,
                "network": "1.1.1.0/24",
                "regional_internet_registry": "APNIC",
                "reputation": 33,
                "tags": [],
                "total_votes": {
                    "harmless": 22,
                    "malicious": 6
                },
                "whois": "Domain Name: one.one\r\nRegistry Domain ID: DB8D9612E99A84235AF9133FBE4EB27D5-ARI\r\nRegistrar WHOIS Server:\r\nRegistrar URL:\r\nUpdated Date: 2020-07-04T12:15:48Z\r\nCreation Date: 2015-05-20T12:15:44Z\r\nRegistry Expiry Date: 2021-05-20T12:15:44Z\r\nRegistrar: One.com A/S - ONE\r\nRegistrar IANA ID: 9998\r\nRegistrar Abuse Contact Email:\r\nRegistrar Abuse Contact Phone:\r\nDomain Status: ok https://icann.org/epp#ok\r\nRegistry Registrant ID: REDACTED FOR PRIVACY\r\nRegistrant Name: REDACTED FOR PRIVACY\r\nRegistrant Organization: One.com A/S\r\nRegistrant Street: REDACTED FOR PRIVACY\r\nRegistrant Street: REDACTED FOR PRIVACY\r\nRegistrant Street: REDACTED FOR PRIVACY\r\nRegistrant City: REDACTED FOR PRIVACY\r\nRegistrant State/Province:\r\nRegistrant Postal Code: REDACTED FOR PRIVACY\r\nRegistrant Country: dk\r\nRegistrant Phone: REDACTED FOR PRIVACY\r\nRegistrant Phone Ext: REDACTED FOR PRIVACY\r\nRegistrant Fax: REDACTED FOR PRIVACY\r\nRegistrant Fax Ext: REDACTED FOR PRIVACY\r\nRegistrant Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.\r\nRegistry Admin ID: REDACTED FOR PRIVACY\r\nAdmin Name: REDACTED FOR PRIVACY\r\nAdmin Organization: REDACTED FOR PRIVACY\r\nAdmin Street: REDACTED FOR PRIVACY\r\nAdmin Street: REDACTED FOR PRIVACY\r\nAdmin Street: REDACTED FOR PRIVACY\r\nAdmin City: REDACTED FOR PRIVACY\r\nAdmin State/Province: REDACTED FOR PRIVACY\r\nAdmin Postal Code: REDACTED FOR PRIVACY\r\nAdmin Country: REDACTED FOR PRIVACY\r\nAdmin Phone: REDACTED FOR PRIVACY\r\nAdmin Phone Ext: REDACTED FOR PRIVACY\r\nAdmin Fax: REDACTED FOR PRIVACY\r\nAdmin Fax Ext: REDACTED FOR PRIVACY\r\nAdmin Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.\r\nRegistry Tech ID: REDACTED FOR PRIVACY\r\nTech Name: REDACTED FOR PRIVACY\r\nTech Organization: REDACTED FOR PRIVACY\r\nTech Street: REDACTED FOR PRIVACY\r\nTech Street: REDACTED FOR PRIVACY\r\nTech Street: REDACTED FOR PRIVACY\r\nTech City: REDACTED FOR PRIVACY\r\nTech State/Province: REDACTED FOR PRIVACY\r\nTech Postal Code: REDACTED FOR PRIVACY\r\nTech Country: REDACTED FOR PRIVACY\r\nTech Phone: REDACTED FOR PRIVACY\r\nTech Phone Ext: REDACTED FOR PRIVACY\r\nTech Fax: REDACTED FOR PRIVACY\r\nTech Fax Ext: REDACTED FOR PRIVACY\r\nTech Email: Please query the RDDS service of the Registrar of Record identified in this output for information on how to contact the Registrant, Admin, or Tech contact of the queried domain name.\r\nName Server: a.b-one-dns.net\r\nName Server: b.b-one-dns.net\r\nDNSSEC: signedDelegation\r\nURL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\r\n>>> Last update of WHOIS database: 2021-03-15T01:25:26Z <<<\r\n\r\nFor more information on Whois status codes, please visit https://icann.org/epp\r\n\r\nThe above WHOIS results have been redacted to remove potential personal data. The full WHOIS output may be available to individuals and organisations with a legitimate interest in accessing this data not outweighed by the fundamental privacy rights of the data subject. To find out more, or to make a request for access, please visit: RDDSrequest.nic.one.\r\n\r\nData provided as WHOIS information on this page is intended to provide you with relevant contact information for a domain name registrant and associated administrative and technical contact.\r\n\r\nThe data in this record is provided by One Registry for information purposes only, and One Registry does not guarantee the accuracy of the information provided. One Registry is authoritative for WHOIS information in TLDs operated by One Registry under contract with the Internet Corporation for Assigned Names and Numbers (ICANN). \r\n\r\nThis WHOIS service is intended only for query-based access. By using this service, you agree that you will use any data presented only for lawful purposes and that, under no circumstances will you\r\n (a) use the data to allow, enable, or otherwise support any marketing activities, regardless of the medium used. Such media include but are not limited to e-mail, telephone, facsimile, postal mail and SMS; or\r\n (b) use the data to enable high volume, automated, electronic processes that send queries or data to the systems of any Registry Operator or ICANN-Accredited registrar, except as reasonably necessary to register domain names or modify existing registrations; or\r\n (c) sell or redistribute the data except insofar as it has been incorporated into a value-added product or service that does not permit the extraction of a substantial portion of the bulk data from the value-added product or service for use by other parties.\r\n\r\n One Registry reserves the right to modify these terms at any time. By submitting this query and using the WHOIS service provided by One Registry, you agree to these terms of use.\r\n",
                "whois_date": 1615771527
            },
            "id": "1.1.1.1",
            "links": {
                "self": "https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1"
            },
            "type": "ip_address"
        }
    }
}
```

#### Human Readable Output

>### IP reputation of 1.1.1.1:
>|Id|Network|Country|LastModified|Reputation|Positives|
>|---|---|---|---|---|---|
>| 1.1.1.1 | 1.1.1.0/24 | AU | 2021-03-30 05:52:25Z | 33 | 1/82 |


### url
***
Checks the reputation of a URL.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | Bad URLs found. | 
| URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | unknown | For malicious URLs, the reason that the vendor made the decision. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the DBot score. | 
| DBotScore.Score | unknown | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| VirusTotal.URL.attributes.favicon.raw_md5 | String | The MD5 hash of the URL. | 
| VirusTotal.URL.attributes.favicon.dhash | String | Difference hash. | 
| VirusTotal.URL.attributes.last_modification_date | Number | Last modification date in epoch format. | 
| VirusTotal.URL.attributes.times_submitted | Number | The number of times the url has been submitted. | 
| VirusTotal.URL.attributes.total_votes.harmless | Number | Total number of harmless votes. | 
| VirusTotal.URL.attributes.total_votes.malicious | Number | Total number of malicious votes. | 
| VirusTotal.URL.attributes.threat_names | String | Name of the threats found. | 
| VirusTotal.URL.attributes.last_submission_date | Number | The last submission date in epoch format. | 
| VirusTotal.URL.attributes.last_http_response_content_length | Number | The last HTTPS response length. | 
| VirusTotal.URL.attributes.last_http_response_headers.date | Date | The last response header date. | 
| VirusTotal.URL.attributes.last_http_response_headers.x-sinkhole | String | DNS sinkhole from last response. | 
| VirusTotal.URL.attributes.last_http_response_headers.content-length | String | The content length of the last response. | 
| VirusTotal.URL.attributes.last_http_response_headers.content-type | String | The content type of the last response. | 
| VirusTotal.URL.attributes.reputation | Number | Reputation of the indicator. | 
| VirusTotal.URL.attributes.last_analysis_date | Number | The date of the last analysis in epoch format. | 
| VirusTotal.URL.attributes.has_content | Boolean | Whether the url has content in it. | 
| VirusTotal.URL.attributes.first_submission_date | Number | The first submission date in epoch format. | 
| VirusTotal.URL.attributes.last_http_response_content_sha256 | String | The SHA-256 hash of the content of the last response. | 
| VirusTotal.URL.attributes.last_http_response_code | Number | Last response status code. | 
| VirusTotal.URL.attributes.last_final_url | String | Last final URL. | 
| VirusTotal.URL.attributes.url | String | The URL itself. | 
| VirusTotal.URL.attributes.title | String | Title of the page. | 
| VirusTotal.URL.attributes.last_analysis_stats.harmless | Number | The number of engines that found the domain to be harmless. | 
| VirusTotal.URL.attributes.last_analysis_stats.malicious | Number | The number of engines that found the indicator to be malicious. | 
| VirusTotal.URL.attributes.last_analysis_stats.suspicious | Number | The number of engines that found the indicator to be suspicious. | 
| VirusTotal.URL.attributes.last_analysis_stats.undetected | Number | The number of engines that could not detect the indicator. | 
| VirusTotal.URL.attributes.last_analysis_stats.timeout | Number | The number of engines that timed out for the indicator. | 
| VirusTotal.URL.attributes.outgoing_links | String | Outgoing links of the URL page. | 
| VirusTotal.URL.type | String | Type of the indicator \(url\). | 
| VirusTotal.URL.id | String | ID of the indicator. | 
| VirusTotal.URL.links.self | String | Link to the response. | 


#### Command Example
```!url url=https://down.mykings.pw```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://down.mykings.pw",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "url",
        "Vendor": "VirusTotal"
    },
    "URL": {
        "Category": {
            "Dr.Web": "known infection source",
            "Forcepoint ThreatSeeker": "information technology",
            "alphaMountain.ai": "Malicious",
            "sophos": "malware callhome, command and control"
        },
        "Data": "https://down.mykings.pw",
        "DetectionEngines": 86,
        "PositiveDetections": 8
    },
    "VirusTotal": {
        "URL": {
            "attributes": {
                "categories": {
                    "Dr.Web": "known infection source",
                    "Forcepoint ThreatSeeker": "information technology",
                    "alphaMountain.ai": "Malicious",
                    "sophos": "malware callhome, command and control"
                },
                "first_submission_date": 1554509044,
                "has_content": false,
                "html_meta": {},
                "last_analysis_date": 1615900309,
                "last_analysis_stats": {
                    "harmless": 71,
                    "malicious": 8,
                    "suspicious": 0,
                    "timeout": 0,
                    "undetected": 7
                },
                "last_final_url": "https://down.mykings.pw/dashboard/",
                "last_http_response_code": 200,
                "last_http_response_content_length": 1671,
                "last_http_response_content_sha256": "f2ddbc5b5468c2cd9c28ae820420d32c4f53d088e4a1cc31f661230e4893104a",
                "last_http_response_headers": {
                    "content-length": "1671",
                    "content-type": "text/html; charset=utf-8",
                    "date": "Tue, 16 Mar 2021 13:16:50 GMT",
                    "x-sinkhole": "Malware"
                },
                "last_modification_date": 1615900620,
                "last_submission_date": 1615900309,
                "outgoing_links": [
                    "http://www.kaspersky.com",
                    "http://www.securelist.com"
                ],
                "reputation": 0,
                "tags": [],
                "targeted_brand": {},
                "threat_names": [
                    "C2/Generic-A"
                ],
                "times_submitted": 5,
                "title": "Welcome page",
                "total_votes": {
                    "harmless": 0,
                    "malicious": 0
                },
                "trackers": {},
                "url": "https://down.mykings.pw/"
            },
            "id": "84eb1485254266e093683024b3bd172abde615fc6a37498707ca912964a108a9",
            "links": {
                "self": "https://www.virustotal.com/api/v3/urls/84eb1485254266e093683024b3bd172abde615fc6a37498707ca912964a108a9"
            },
            "type": "url"
        }
    }
}
```

#### Human Readable Output

>### URL data of "https://down.mykings.pw"
>|Url|Title|LastModified|HasContent|LastHttpResponseContentSha256|Positives|Reputation|
>|---|---|---|---|---|---|---|
>| https://down.mykings.pw | Welcome page | 2021-03-16 13:17:00Z | false | f2ddbc5b5468c2cd9c28ae820420d32c4f53d088e4a1cc31f661230e4893104a | 8/86 | 0 |


### domain
***
Checks the reputation of a domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to check. | Required | 
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Bad domain found. | 
| Domain.Malicious.Vendor | unknown | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | unknown | For malicious domains, the reason that the vendor made the decision. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
| DBotScore.Score | unknown | The actual DBot score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| VirusTotal.Domain.attributes.last_dns_records.type | String | The type of the last DNS records. | 
| VirusTotal.Domain.attributes.last_dns_records.value | String | The value of the last DNS records. | 
| VirusTotal.Domain.attributes.last_dns_records.ttl | Number | The time To live \(ttl\) of the last DNS records. | 
| VirusTotal.Domain.attributes.jarm | String | JARM data. | 
| VirusTotal.Domain.attributes.whois | String | whois data. | 
| VirusTotal.Domain.attributes.last_dns_records_date | Number | The last DNS records date in epoch format. | 
| VirusTotal.Domain.attributes.last_analysis_stats.harmless | Number | The number of engines that found the domain to be harmless. | 
| VirusTotal.Domain.attributes.last_analysis_stats.malicious | Number | The number of engines that found the indicator to be malicious. | 
| VirusTotal.Domain.attributes.last_analysis_stats.suspicious | Number | The number of engines that found the indicator to be suspicious. | 
| VirusTotal.Domain.attributes.last_analysis_stats.undetected | Number | The number of engines that could not detect the indicator. | 
| VirusTotal.Domain.attributes.last_analysis_stats.timeout | Number | The number of engines that timed out for the indicator. | 
| VirusTotal.Domain.attributes.favicon.raw_md5 | String | MD5 hash of the domain. | 
| VirusTotal.Domain.attributes.favicon.dhash | String | Difference hash. | 
| VirusTotal.Domain.attributes.reputation | Number | Reputation of the indicator. | 
| VirusTotal.Domain.attributes.registrar | String | Registrar information. | 
| VirusTotal.Domain.attributes.last_update_date | Number | Last updated date in epoch format. | 
| VirusTotal.Domain.attributes.last_modification_date | Number | Last modification date in epoch format. | 
| VirusTotal.Domain.attributes.creation_date | Number | Creation date in epoch format. | 
| VirusTotal.Domain.attributes.total_votes.harmless | Number | Total number of harmless votes. | 
| VirusTotal.Domain.attributes.total_votes.malicious | Number | Total number of malicious votes. | 
| VirusTotal.Domain.type | String | Type of indicator \(domain\). | 
| VirusTotal.Domain.id | String | ID of the domain. | 
| VirusTotal.Domain.links.self | String | Link to the domain investigation. | 


#### Command Example
```!domain domain=down.mykings.pw```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "down.mykings.pw",
        "Reliability": "A - Completely reliable",
        "Score": 2,
        "Type": "domain",
        "Vendor": "VirusTotal"
    },
    "Domain": {
        "Admin": {
            "Country": " PA",
            "Email": " [REDACTED]@whoisguard.com",
            "Name": " WhoisGuard, Inc.",
            "Phone": null
        },
        "CreationDate": [
            " 2017-01-21T16:26:19.0Z",
            " 2017-01-21T16:26:19.00Z"
        ],
        "ExpirationDate": " 2018-01-21T23:59:59.0Z",
        "Name": "down.mykings.pw",
        "NameServers": [
            " PDNS1.REGISTRAR-SERVERS.COM",
            " PDNS2.REGISTRAR-SERVERS.COM",
            " pdns1.registrar-servers.com",
            " pdns2.registrar-servers.com"
        ],
        "Registrant": {
            "Country": " PA",
            "Email": " [REDACTED]@whoisguard.com",
            "Name": null,
            "Phone": null
        },
        "Registrar": {
            "AbuseEmail": " abuse@namecheap.com",
            "AbusePhone": " +1.6613102107",
            "Name": [
                " Namecheap",
                " NAMECHEAP INC"
            ]
        },
        "UpdatedDate": [
            " 2017-03-06T21:52:39.0Z",
            " 2017-01-21T16:26:23.00Z"
        ],
        "WHOIS": {
            "Admin": {
                "Country": " PA",
                "Email": " [REDACTED]@whoisguard.com",
                "Name": " WhoisGuard, Inc.",
                "Phone": null
            },
            "CreationDate": [
                " 2017-01-21T16:26:19.0Z",
                " 2017-01-21T16:26:19.00Z"
            ],
            "ExpirationDate": " 2018-01-21T23:59:59.0Z",
            "NameServers": [
                " PDNS1.REGISTRAR-SERVERS.COM",
                " PDNS2.REGISTRAR-SERVERS.COM",
                " pdns1.registrar-servers.com",
                " pdns2.registrar-servers.com"
            ],
            "Registrant": {
                "Country": " PA",
                "Email": " [REDACTED]@whoisguard.com",
                "Name": null,
                "Phone": null
            },
            "Registrar": {
                "AbuseEmail": " abuse@namecheap.com",
                "AbusePhone": " +1.6613102107",
                "Name": [
                    " Namecheap",
                    " NAMECHEAP INC"
                ]
            },
            "UpdatedDate": [
                " 2017-03-06T21:52:39.0Z",
                " 2017-01-21T16:26:23.00Z"
            ]
        }
    },
    "VirusTotal": {
        "Domain": {
            "attributes": {
                "categories": {
                    "Dr.Web": "known infection source",
                    "Forcepoint ThreatSeeker": "information technology",
                    "alphaMountain.ai": "Malicious",
                    "sophos": "malware callhome, command and control"
                },
                "creation_date": 1485015979,
                "favicon": {
                    "dhash": "f4cca89496a0ccb2",
                    "raw_md5": "6eb4a43cb64c97f76562af703893c8fd"
                },
                "jarm": "29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38",
                "last_analysis_stats": {
                    "harmless": 66,
                    "malicious": 8,
                    "suspicious": 0,
                    "timeout": 0,
                    "undetected": 8
                },
                "last_dns_records": [
                    {
                        "ttl": 3599,
                        "type": "A",
                        "value": "134.209.227.14"
                    }
                ],
                "last_dns_records_date": 1615900633,
                "last_modification_date": 1615900633,
                "last_update_date": 1488837159,
                "popularity_ranks": {},
                "registrar": "Namecheap",
                "reputation": 0,
                "tags": [],
                "total_votes": {
                    "harmless": 0,
                    "malicious": 0
                },
                "whois": "Domain Name: MYKINGS.PW\nRegistry Domain ID: D42904076-CNIC\nRegistrar WHOIS Server: whois.namecheap.com\nUpdated Date: 2017-03-06T21:52:39.0Z\nCreation Date: 2017-01-21T16:26:19.0Z\nRegistry Expiry Date: 2018-01-21T23:59:59.0Z\nRegistrar: Namecheap\nRegistrar IANA ID: 1068\nDomain Status: serverHold https://icann.org/epp#serverHold\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nRegistry Registrant ID: C113380656-CNIC\nRegistrant Country: PA\nRegistrant Email: [REDACTED]@whoisguard.com\nRegistry Admin ID: C113380651-CNIC\nAdmin Organization: WhoisGuard, Inc.\nAdmin City: Panama\nAdmin State/Province: Panama\nAdmin Country: PA\nAdmin Email: [REDACTED]@whoisguard.com\nRegistry Tech ID: C113380657-CNIC\nTech Organization: WhoisGuard, Inc.\nTech City: Panama\nTech State/Province: Panama\nTech Country: PA\nTech Email: [REDACTED]@whoisguard.com\nName Server: PDNS1.REGISTRAR-SERVERS.COM\nName Server: PDNS2.REGISTRAR-SERVERS.COM\nDNSSEC: unsigned\nRegistry Billing ID: C113380652-CNIC\nBilling Organization: WhoisGuard, Inc.\nBilling City: Panama\nBilling State/Province: Panama\nBilling Country: PA\nBilling Email: [REDACTED]@whoisguard.com\nRegistrar Abuse Contact Email: abuse@namecheap.com\nRegistrar Abuse Contact Phone: +1.6613102107\nDomain name: mykings.pw\nRegistrar URL: http://www.namecheap.com\nUpdated Date: 2017-01-21T16:26:23.00Z\nCreation Date: 2017-01-21T16:26:19.00Z\nRegistrar Registration Expiration Date: 2018-01-21T23:59:59.00Z\nRegistrar: NAMECHEAP INC\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: addPeriod https://icann.org/epp#addPeriod\nRegistry Registrant ID: h0vgttny0epf16dd\nRegistry Admin ID: 7wb6xoq1zsnorcv3\nRegistry Tech ID: bn39juqyqwo74klf\nName Server: pdns1.registrar-servers.com\nName Server: pdns2.registrar-servers.com"
            },
            "id": "down.mykings.pw",
            "links": {
                "self": "https://www.virustotal.com/api/v3/domains/down.mykings.pw"
            },
            "type": "domain"
        }
    }
}
```

#### Human Readable Output

>### Domain data of down.mykings.pw
>|Id|Registrant Country|LastModified|LastAnalysisStats|
>|---|---|---|---|
>| down.mykings.pw |  PA | 2021-03-16 13:17:13Z | harmless: 66<br/>malicious: 8<br/>suspicious: 0<br/>undetected: 8<br/>timeout: 0 |


### file-scan
***
Submits a file for scanning. Use the vt-analysis-get command to get the scan results.


#### Base Command

`file-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | The file entry ID to submit. | Required | 
| uploadURL | Premium API extension. Special upload URL for files larger than 32 MB. Can be acquired from the vt-file-scan-upload-url command. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Submission.is_valid_scan_id | boolean | Is the scan ID is valid. If not, run rescan-file. | 
| VirusTotal.Submission.type | String | The submission type. | 
| VirusTotal.Submission.id | String | The ID of the submission. | 
| VirusTotal.Submission.EntryID | String | The entry ID of the file detonated. | 
| VirusTotal.Submission.Extension | String | File extension. | 
| VirusTotal.Submission.Info | String | File info. | 
| VirusTotal.Submission.MD5 | String | MD5 hash of the file. | 
| VirusTotal.Submission.Name | String | Name of the file. | 
| VirusTotal.Submission.SHA1 | String | SHA-1 hash of the file | 
| VirusTotal.Submission.SHA256 | String | SHA-256 of the file. | 
| VirusTotal.Submission.SHA512 | String | SHA-512 of the file. | 
| VirusTotal.Submission.SSDeep | String | SSDeep of the file. | 
| VirusTotal.Submission.Size | Number | Size of the file. | 
| VirusTotal.Submission.Type | String | The type of the submission \(analysis\). | 


#### Command Example
```!file-scan entryID=VyoASWK4aRCWLS8T3Jc7EL@2c18b8c3-8f96-458e-8849-39fc741e78fa```

#### Human Readable Output

>Could not process entry_id='VyoASWK4aRCWLS8T3Jc7EL@2c18b8c3-8f96-458e-8849-39fc741e78fa'.

### file-rescan
***
Rescans an already submitted file. This avoids having to upload the file again. Use the vt-analysis-get command to get the scan results.


#### Base Command

`file-rescan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to rescan. Supports MD5, SHA1, and SHA256. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Submission.Type | String | The type of the submission \(analysis\). | 
| VirusTotal.Submission.id | String | The ID of the submission | 
| VirusTotal.Submission.hash | String | The indicator sent to rescan. | 


#### Command Example
```!file-rescan file=6bcae8ceb7f8b3a503c321085d59d7441c2ae87220f7e7170fec91098d99bb7e```

#### Context Example
```json
{
    "VirusTotal": {
        "Submission": {
            "hash": "6bcae8ceb7f8b3a503c321085d59d7441c2ae87220f7e7170fec91098d99bb7e",
            "id": "YmVhNjVlZmNjMDAxNjlkZWM0ZjdlMmVkNjEyZTA0MWY6MTYxNzA4ODg5Mw==",
            "type": "analysis"
        }
    },
    "vtScanID": "YmVhNjVlZmNjMDAxNjlkZWM0ZjdlMmVkNjEyZTA0MWY6MTYxNzA4ODg5Mw=="
}
```

#### Human Readable Output

>### File "6bcae8ceb7f8b3a503c321085d59d7441c2ae87220f7e7170fec91098d99bb7e" resubmitted.
>|Hash|Id|Type|
>|---|---|---|
>| 6bcae8ceb7f8b3a503c321085d59d7441c2ae87220f7e7170fec91098d99bb7e | YmVhNjVlZmNjMDAxNjlkZWM0ZjdlMmVkNjEyZTA0MWY6MTYxNzA4ODg5Mw== | analysis |


### url-scan
***
Scans a specified URL. Use the vt-analysis-get command to get the scan results.


#### Base Command

`url-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL to scan. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Submission.Type | String | The type of the submission \(analysis\). | 
| VirusTotal.Submission.id | String | The ID of the submission. | 
| VirusTotal.Submission.hash | String | The indicator sent to rescan. | 


#### Command Example
```!url-scan url=https://example.com```

#### Context Example
```json
{
    "VirusTotal": {
        "Submission": {
            "id": "u-0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1617088890",
            "type": "analysis",
            "url": "https://example.com"
        }
    },
    "vtScanID": "u-0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1617088890"
}
```

#### Human Readable Output

>### New url submission:
>|id|url|
>|---|---|
>| u-0f115db062b7c0dd030b16878c99dea5c354b49dc37b38eb8846179c7783e9d7-1617088890 | https://example.com |


### vt-comments-add
***
Adds comments to files and URLs.


#### Base Command

`vt-comments-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The file hash (MD5, SHA1, orSHA256), Domain, URL or IP on which you're commenting on. If not supplied, will try to determine if it's a hash or a url. | Required | 
| resource_type | The type of the resource on which you're commenting. Possible values are: ip, url, domain, hash. | Optional | 
| comment | The actual review that you can tag by using the "#" twitter-like syntax, for example, #disinfection #zbot, and reference users using the "@" syntax, for example, @VirusTotalTeam. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Comments.comments.attributes.date | Number | The date of the comment in epoch format. | 
| VirusTotal.Comments.comments.attributes.text | String | The text of the comment. | 
| VirusTotal.Comments.comments.attributes.votes.positive | Number | Number of positive votes. | 
| VirusTotal.Comments.comments.attributes.votes.abuse | Number | Number of abuse votes. | 
| VirusTotal.Comments.comments.attributes.votes.negative | Number | Number of negative votes. | 
| VirusTotal.Comments.comments.attributes.html | String | The HTML content. | 
| VirusTotal.Comments.comments.type | String | The type of the comment. | 
| VirusTotal.Comments.comments.id | String | ID of the comment. | 
| VirusTotal.Comments.comments.links.self | String | Link to the request. | 


#### Command Example
```!vt-comments-add resource=paloaltonetworks.com resource_type=domain comment="this is a comment"```

#### Context Example
```json
{
    "VirusTotal": {
        "Comments": {
            "comments": {
                "attributes": {
                    "date": 1617088894,
                    "html": "this is a comment",
                    "tags": [],
                    "text": "this is a comment",
                    "votes": {
                        "abuse": 0,
                        "negative": 0,
                        "positive": 0
                    }
                },
                "id": "d-paloaltonetworks.com-e757b16b",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/comments/d-paloaltonetworks.com-e757b16b"
                },
                "type": "comment"
            }
        }
    }
}
```

#### Human Readable Output

>### Comment has been added!
>|Date|Text|Positive Votes|Abuse Votes|Negative Votes|
>|---|---|---|---|---|
>| 2021-03-30 07:21:34Z | this is a comment | 0 | 0 | 0 |


### vt-file-scan-upload-url
***
Premium API. Get a special URL for files larger than 32 MB.


#### Base Command

`vt-file-scan-upload-url`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.FileUploadURL | unknown | The special upload URL for large files. | 


#### Command Example
```!vt-file-scan-upload-url```

#### Context Example
```json
{
    "VirusTotal": {
        "FileUploadURL": "https://www.virustotal.com/_ah/upload/AMmfu6ZDt_t1X9y-O6BDDco3BzQM0u4LOTdib_B49i9MI7ykV6mdrQMbA4HETkMCGizBzmzUaitIbRrzPjls4hrNhR-IUxvNxIt3VoR1OiqAaDqkDvNOAjjZ5BEBt0otSxzkH2stfChRSCqVosoGsVQ2qztWqeVmLxqBrCUM0sRaQo713Q3WfgpJc5wuwAPhwif71bsgJU4KKIadzH67y6xYqiZem9OVpHEjvRFwdjUByntJtTJS0aMJ-DmgXVUeTQ_WjDm1U21Y9wDaU24j1CUnwiYCBhMw42YcZ0ppVuQ56qfeShflThXTtjCFHMMhEZ4YbzQXgbToLgzfPRy6T4fAozwKE1IR9XdzZzmoJmiV5Bc3f4DT6QSf6hLbVjmnY0WPTfjsZwchX7yT4zWZ2HzSXR6DkqGuL1FAKCMCz_t5bx4la9XBbrboitsMbufmfxtD_4VtRYpWya5TcS9eQuuRAfvAsZS85Dqdd_BtmT9itbYvr64W2FJIKZW4j1fwrxMbrap0_6J_qWSxOgqWFWPZp_xloSUJA9Qepi5pj8QD_MZ1yhuTvLN5u2nxcE6-szdXHL3mgAJmPTDy0FcFMvk-vnHrv3GAojhP9IURHHBm_qkRpesEGGlEIcAe7dYRv2mocjeyRI4PCCRuY-dLHj41SfSZosqhgrgHu8WEh9x9z3L-DDoeiRi3lDkKrPjXdAhx4uVKxtuOJT44y3Md32c3iFV-xjr8ZPJHMUz7j1h6r4IVbek5t--q1fBwmoFIiUodVPupXLj21GtQPneiWiCXvevHf9zMxU2Av9aqvAlISqhJoiId2Yza1AvOLWQh6PhNPwXAY5Qo18zV0RGm33kNZn4J-n4svIE--y1b_9j4IApdtf65Mue1lFJ0B6RlEIjRbeaSB5P6U7LUFCbzmhiagw2x9xf_5EmsQn66-EtAH42E7Rurcu1G4QflDL0vMky54ukk8Nx8d-bQgfqmkSVhqELH_Ht-taO1doAqNiatdzDpbAxAOUo2Uf1VAaDpBJnLq1Yfh2qn7EqQniBBedR8YY4A4-ApYW_ZgrclceyrWJ_zLOsDU9NlNVeuuSQ98q2Qbn0x5pN6/ALBNUaYAAAAAYGLUFoVWv3ZAaGqdk9AzEGlZ9eUZoyHd/"
    },
    "vtUploadURL": "https://www.virustotal.com/_ah/upload/AMmfu6ZDt_t1X9y-O6BDDco3BzQM0u4LOTdib_B49i9MI7ykV6mdrQMbA4HETkMCGizBzmzUaitIbRrzPjls4hrNhR-IUxvNxIt3VoR1OiqAaDqkDvNOAjjZ5BEBt0otSxzkH2stfChRSCqVosoGsVQ2qztWqeVmLxqBrCUM0sRaQo713Q3WfgpJc5wuwAPhwif71bsgJU4KKIadzH67y6xYqiZem9OVpHEjvRFwdjUByntJtTJS0aMJ-DmgXVUeTQ_WjDm1U21Y9wDaU24j1CUnwiYCBhMw42YcZ0ppVuQ56qfeShflThXTtjCFHMMhEZ4YbzQXgbToLgzfPRy6T4fAozwKE1IR9XdzZzmoJmiV5Bc3f4DT6QSf6hLbVjmnY0WPTfjsZwchX7yT4zWZ2HzSXR6DkqGuL1FAKCMCz_t5bx4la9XBbrboitsMbufmfxtD_4VtRYpWya5TcS9eQuuRAfvAsZS85Dqdd_BtmT9itbYvr64W2FJIKZW4j1fwrxMbrap0_6J_qWSxOgqWFWPZp_xloSUJA9Qepi5pj8QD_MZ1yhuTvLN5u2nxcE6-szdXHL3mgAJmPTDy0FcFMvk-vnHrv3GAojhP9IURHHBm_qkRpesEGGlEIcAe7dYRv2mocjeyRI4PCCRuY-dLHj41SfSZosqhgrgHu8WEh9x9z3L-DDoeiRi3lDkKrPjXdAhx4uVKxtuOJT44y3Md32c3iFV-xjr8ZPJHMUz7j1h6r4IVbek5t--q1fBwmoFIiUodVPupXLj21GtQPneiWiCXvevHf9zMxU2Av9aqvAlISqhJoiId2Yza1AvOLWQh6PhNPwXAY5Qo18zV0RGm33kNZn4J-n4svIE--y1b_9j4IApdtf65Mue1lFJ0B6RlEIjRbeaSB5P6U7LUFCbzmhiagw2x9xf_5EmsQn66-EtAH42E7Rurcu1G4QflDL0vMky54ukk8Nx8d-bQgfqmkSVhqELH_Ht-taO1doAqNiatdzDpbAxAOUo2Uf1VAaDpBJnLq1Yfh2qn7EqQniBBedR8YY4A4-ApYW_ZgrclceyrWJ_zLOsDU9NlNVeuuSQ98q2Qbn0x5pN6/ALBNUaYAAAAAYGLUFoVWv3ZAaGqdk9AzEGlZ9eUZoyHd/"
}
```

#### Human Readable Output

>### New upload url acquired!
>|Upload url|
>|---|
>| https://www.virustotal.com/_ah/upload/AMmfu6ZDt_t1X9y-O6BDDco3BzQM0u4LOTdib_B49i9MI7ykV6mdrQMbA4HETkMCGizBzmzUaitIbRrzPjls4hrNhR-IUxvNxIt3VoR1OiqAaDqkDvNOAjjZ5BEBt0otSxzkH2stfChRSCqVosoGsVQ2qztWqeVmLxqBrCUM0sRaQo713Q3WfgpJc5wuwAPhwif71bsgJU4KKIadzH67y6xYqiZem9OVpHEjvRFwdjUByntJtTJS0aMJ-DmgXVUeTQ_WjDm1U21Y9wDaU24j1CUnwiYCBhMw42YcZ0ppVuQ56qfeShflThXTtjCFHMMhEZ4YbzQXgbToLgzfPRy6T4fAozwKE1IR9XdzZzmoJmiV5Bc3f4DT6QSf6hLbVjmnY0WPTfjsZwchX7yT4zWZ2HzSXR6DkqGuL1FAKCMCz_t5bx4la9XBbrboitsMbufmfxtD_4VtRYpWya5TcS9eQuuRAfvAsZS85Dqdd_BtmT9itbYvr64W2FJIKZW4j1fwrxMbrap0_6J_qWSxOgqWFWPZp_xloSUJA9Qepi5pj8QD_MZ1yhuTvLN5u2nxcE6-szdXHL3mgAJmPTDy0FcFMvk-vnHrv3GAojhP9IURHHBm_qkRpesEGGlEIcAe7dYRv2mocjeyRI4PCCRuY-dLHj41SfSZosqhgrgHu8WEh9x9z3L-DDoeiRi3lDkKrPjXdAhx4uVKxtuOJT44y3Md32c3iFV-xjr8ZPJHMUz7j1h6r4IVbek5t--q1fBwmoFIiUodVPupXLj21GtQPneiWiCXvevHf9zMxU2Av9aqvAlISqhJoiId2Yza1AvOLWQh6PhNPwXAY5Qo18zV0RGm33kNZn4J-n4svIE--y1b_9j4IApdtf65Mue1lFJ0B6RlEIjRbeaSB5P6U7LUFCbzmhiagw2x9xf_5EmsQn66-EtAH42E7Rurcu1G4QflDL0vMky54ukk8Nx8d-bQgfqmkSVhqELH_Ht-taO1doAqNiatdzDpbAxAOUo2Uf1VAaDpBJnLq1Yfh2qn7EqQniBBedR8YY4A4-ApYW_ZgrclceyrWJ_zLOsDU9NlNVeuuSQ98q2Qbn0x5pN6/ALBNUaYAAAAAYGLUFoVWv3ZAaGqdk9AzEGlZ9eUZoyHd/ |


### vt-comments-delete
***
Delete a comment.


#### Base Command

`vt-comments-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Comment ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### vt-comments-get
***
Retrieves comments for a given resource.


#### Base Command

`vt-comments-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The file hash (MD5, SHA1, orSHA256), Domain, URL or IP on which you're commenting on. If not supplied, will try to determine if it's a hash or a url. | Required | 
| resource_type | The type of the resource on which you're commenting. If not supplied, will determine if it's a url or a file. Possible values are: ip, url, domain, file. | Optional | 
| limit | Maximum comments to fetch. Default is 10. | Optional | 
| before | Fetch only comments before the given time. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Comments.id | String | ID that contains the comment \(the given hash, domain, url, or ip\). | 
| VirusTotal.Comments.comments.attributes.date | Number | The date of the comment in epoch format. | 
| VirusTotal.Comments.comments.attributes.text | String | The text of the comment. | 
| VirusTotal.Comments.comments.attributes.votes.positive | Number | Number of positive votes. | 
| VirusTotal.Comments.comments.attributes.votes.abuse | Number | Number of abuse votes. | 
| VirusTotal.Comments.comments.attributes.votes.negative | Number | Number of negative votes. | 
| VirusTotal.Comments.comments.attributes.html | String | The HTML content. | 
| VirusTotal.Comments.comments.type | String | The type of the comment. | 
| VirusTotal.Comments.comments.id | String | ID of the commented. | 
| VirusTotal.Comments.comments.links.self | String | Link to the request | 


#### Command Example
```!vt-comments-get resource=https://paloaltonetworks.com```

#### Context Example
```json
{
    "VirusTotal": {
        "Comments": {
            "comments": [
                {
                    "attributes": {
                        "date": 1616325673,
                        "html": "another comment",
                        "tags": [],
                        "text": "another comment",
                        "votes": {
                            "abuse": 0,
                            "negative": 0,
                            "positive": 0
                        }
                    },
                    "id": "u-c5fad1f7084153e328563fbacdb07a9ad6428dc3f0a88e756266efb7c0553d9d-fe2d6a9e",
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/comments/u-c5fad1f7084153e328563fbacdb07a9ad6428dc3f0a88e756266efb7c0553d9d-fe2d6a9e"
                    },
                    "type": "comment"
                },
                {
                    "attributes": {
                        "date": 1616325673,
                        "html": "another comment",
                        "tags": [],
                        "text": "another comment",
                        "votes": {
                            "abuse": 0,
                            "negative": 0,
                            "positive": 0
                        }
                    },
                    "id": "u-c5fad1f7084153e328563fbacdb07a9ad6428dc3f0a88e756266efb7c0553d9d-d63782a9",
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/comments/u-c5fad1f7084153e328563fbacdb07a9ad6428dc3f0a88e756266efb7c0553d9d-d63782a9"
                    },
                    "type": "comment"
                },
                {
                    "attributes": {
                        "date": 1616313101,
                        "html": "a new comment",
                        "tags": [],
                        "text": "a new comment",
                        "votes": {
                            "abuse": 0,
                            "negative": 0,
                            "positive": 0
                        }
                    },
                    "id": "u-c5fad1f7084153e328563fbacdb07a9ad6428dc3f0a88e756266efb7c0553d9d-97a331a3",
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/comments/u-c5fad1f7084153e328563fbacdb07a9ad6428dc3f0a88e756266efb7c0553d9d-97a331a3"
                    },
                    "type": "comment"
                },
                {
                    "attributes": {
                        "date": 1616313067,
                        "html": "a comment",
                        "tags": [],
                        "text": "a comment",
                        "votes": {
                            "abuse": 0,
                            "negative": 0,
                            "positive": 0
                        }
                    },
                    "id": "u-c5fad1f7084153e328563fbacdb07a9ad6428dc3f0a88e756266efb7c0553d9d-ae0de9fc",
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/comments/u-c5fad1f7084153e328563fbacdb07a9ad6428dc3f0a88e756266efb7c0553d9d-ae0de9fc"
                    },
                    "type": "comment"
                }
            ],
            "indicator": "https://paloaltonetworks.com"
        }
    }
}
```

#### Human Readable Output

>### Virus Total comments of url: "https://paloaltonetworks.com"
>|Date|Text|Positive Votes|Abuse Votes|Negative Votes|
>|---|---|---|---|---|
>| 2021-03-21 11:21:13Z | another comment | 0 | 0 | 0 |
>| 2021-03-21 11:21:13Z | another comment | 0 | 0 | 0 |
>| 2021-03-21 07:51:41Z | a new comment | 0 | 0 | 0 |
>| 2021-03-21 07:51:07Z | a comment | 0 | 0 | 0 |


### vt-comments-get-by-id
***
Retrieves a comment by comment ID.


#### Base Command

`vt-comments-get-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The comment's ID. Can be retrieved using the vt-comments-get command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Comments.comments.id | String | ID of the comment. | 
| VirusTotal.Comments.comments.attributes.date | Number | The date of the comment in epoch format. | 
| VirusTotal.Comments.comments.attributes.text | String | The text of the comment. | 
| VirusTotal.Comments.comments.attributes.votes.positive | Number | Number of positive votes. | 
| VirusTotal.Comments.comments.attributes.votes.abuse | Number | Number of abuse votes. | 
| VirusTotal.Comments.comments.attributes.votes.negative | Number | Number of negative votes. | 
| VirusTotal.Comments.comments.attributes.html | String | The HTML content. | 
| VirusTotal.Comments.comments.type | String | The type of the comment. | 
| VirusTotal.Comments.comments.links.self | String | Link to the request. | 


#### Command Example
```!vt-comments-get-by-id id=d-paloaltonetworks.com-64591897```

#### Context Example
```json
{
    "VirusTotal": {
        "Comments": {
            "comments": {
                "attributes": {
                    "date": 1615195751,
                    "html": "a new comment!",
                    "tags": [],
                    "text": "a new comment!",
                    "votes": {
                        "abuse": 0,
                        "negative": 0,
                        "positive": 0
                    }
                },
                "id": "d-paloaltonetworks.com-64591897",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/comments/d-paloaltonetworks.com-64591897"
                },
                "type": "comment"
            }
        }
    }
}
```

#### Human Readable Output

>### Comment of ID d-paloaltonetworks.com-64591897
>|Date|Text|Positive Votes|Abuse Votes|Negative Votes|
>|---|---|---|---|---|
>| 2021-03-08 09:29:11Z | a new comment! | 0 | 0 | 0 |


### vt-search
***
Search for an indicator in Virus Total.


#### Base Command

`vt-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | This endpoint searches any of the following: A file hash, URL, domain, IP address, tag comments. | Required | 
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 
| limit | Maximum number of results to fetch. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.SearchResults.attributes.last_analysis_stats.harmless | Number | Number of engines that found the indicator to be harmless. | 
| VirusTotal.SearchResults.attributes.last_analysis_stats.malicious | Number | Number of engines that found the indicator to be malicious. | 
| VirusTotal.SearchResults.attributes.last_analysis_stats.suspicious | Number | Number of engines that found the indicator to be suspicious. | 
| VirusTotal.SearchResults.attributes.last_analysis_stats.undetected | Number | Number of engines that could not detect the indicator. | 
| VirusTotal.SearchResults.attributes.last_analysis_stats.timeout | Number | Number of engines that timed out. | 
| VirusTotal.SearchResults.attributes.reputation | Number | The indicator's reputation | 
| VirusTotal.SearchResults.attributes.last_modification_date | Number | The last modification date in epoch format. | 
| VirusTotal.SearchResults.attributes.total_votes.harmless | Number | Total number of harmless votes. | 
| VirusTotal.SearchResults.attributes.total_votes.malicious | Number | Total number of malicious votes. | 
| VirusTotal.SearchResults.type | String | The type of the indicator \(ip, domain, url, file\). | 
| VirusTotal.SearchResults.id | String | ID of the indicator. | 
| VirusTotal.SearchResults.links.self | String | Link to the response. | 


#### Command Example
```!vt-search query=paloaltonetworks.com```

#### Context Example
```json
{
    "VirusTotal": {
        "SearchResults": {
            "attributes": {
                "categories": {
                    "BitDefender": "marketing",
                    "Forcepoint ThreatSeeker": "information technology",
                    "alphaMountain.ai": "Business/Economy, Information Technology",
                    "sophos": "information technology"
                },
                "creation_date": 1108953730,
                "favicon": {
                    "dhash": "02e9ecb69ac869a8",
                    "raw_md5": "920c3c89139c32d356fa4b8b61616f37"
                },
                "jarm": "29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae",
                "last_analysis_stats": {
                    "harmless": 75,
                    "malicious": 0,
                    "suspicious": 0,
                    "timeout": 0,
                    "undetected": 7
                },
                "last_dns_records": [
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "atlassian-domain-verification=WeW32v7AwYQEviMzlNjYyXNMUngcnmIMtNZKJ69TuQUoda5T6DFFV/A6rRvOzwvs"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "35g550m1f2732uuklt7om3fr0k"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "amazonses:wD8q9vBgr/tA/9V4Lh4CPADIMQs4LIW/EpqeYxrS5e8="
                    },
                    {
                        "ttl": 21599,
                        "type": "NS",
                        "value": "ns7.dnsmadeeasy.com"
                    },
                    {
                        "expire": 604800,
                        "minimum": 3600,
                        "refresh": 3600,
                        "retry": 600,
                        "rname": "domains.paloaltonetworks.com",
                        "serial": 1616778508,
                        "ttl": 14399,
                        "type": "SOA",
                        "value": "ns1.p23.dynect.net"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "e6dj6aj6redkv98nojsphl0bp6"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "mongodb-site-verification=iAfodgMVqXWglWqKv3qb4xzIjtZkfBwk"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "wcfF7BYKYfRSc96jwmhQfabmMPUMLVmBu1Pauas9oU0="
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "docusign=7979590c-2e52-4018-b599-54a429f449d1"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "b1kisgsns70occu4j4jpl552a9"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "status-page-domain-verification=gxhgqp5msy2m"
                    },
                    {
                        "ttl": 23,
                        "type": "A",
                        "value": "34.107.151.202"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "74H6MX8NRYBAQ3D8H2MJC3Y8P5AGSNB8"
                    },
                    {
                        "priority": 10,
                        "ttl": 14399,
                        "type": "MX",
                        "value": "mxa-00169c01.gslb.pphosted.com"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "CGJAZFH9QTYUPE2A6XJE8VEBUSSB47B5"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "3fln6bvgju1p5c0aa455mjl61n"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "lrlteq11f2vuhlvmkerhqnpua7"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "c2e1bv49egsn6v6ohlra47namp"
                    },
                    {
                        "ttl": 21599,
                        "type": "NS",
                        "value": "ns6.dnsmadeeasy.com"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "logmein-verification-code=ccb897d5-1bed-410a-9c45-a6dd6be9b1c"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "p5cIVMfOtO93Vdzz9extJY700HwcOXxbhBcB+dyK028="
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "omi6ve5p04je278gjtiegkblh1"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "atlassian-domain-verification=OLe058dAXDG6kcCutEa7uSYy2iKLT7CvYNxGz2iROYa4NJ8FazXAkt/Elc8OzblS"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "okansnmkk1j60die0or78624gh"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "9j6u125ve5mvsd634h0gkovq27"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "amazonses:Do93Z/wjV5nZDDaT6n/geaLn2dcmC4LKxWJr6kW09J4="
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "o9c2hro57o4ahin6q2jj64lft8"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "5q1hlpu2u9j6lgrp3rp2ucv48p"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "gbe3h5tqf05k12gdkh1ch15c7r"
                    },
                    {
                        "priority": 10,
                        "ttl": 14399,
                        "type": "MX",
                        "value": "mxb-00169c01.gslb.pphosted.com"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "google-site-verification=8zcmNvhRzBOYw-GN3l86mhO5MTfJjEd8ocEyjdsSLak"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "vm77066l7cp2i2hr66uvsforij"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "hi8pl0b5i96m35pf2741v1hqth"
                    },
                    {
                        "ttl": 21599,
                        "type": "NS",
                        "value": "ns5.dnsmadeeasy.com"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "h7vhs2ouk1vftgjoqqlmjcthbj"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "css6v61730u8halh3dec5lgreo"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "eks3p/qXVt97oL7X1IGBQdP05ev8rOuFOK8LAzqJ8iMkRDfXrKKGEFy3zHyGEAG8IkwimKG83eTQtoWgLClb2A=="
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "7is4vpdq4k8dcioag2dhd5dtot"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "jkt1bch6hqi27c4jisrstg5mke"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "atlassian-domain-verification=2eHeLgLQ13HybaqKxXx+k/uq1dD51Vcs0GAhz1rsbpWTAP3pagbUpE1SuY3dTIyi"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "rmrophudqgsjmkfu3fur0da1dh"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "lspo05pafcr60k2utns50jephr"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "o1l85onfiau3ujepq88nscnsbp"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "9n1sitvm4qt002dkp0riccqu3b"
                    },
                    {
                        "ttl": 21599,
                        "type": "NS",
                        "value": "ns2.p23.dynect.net"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "nm70udiiaufkln1coolgar432q"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "ca2mn12n6lmqe0l187um71u78f"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "R4WKB79BFYVKQ8DVZPR2JCS5CS2CTXMY"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "uZ5++1a8ndinwH931iYZakLQiALyIpSMchkwXnu+cd4="
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "c552n5ffvckbvajtvlbq87h6e4"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "fu93k0bu02qfg8mhfiedij43fo"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "2342193"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "kel7gtj8ljaveug9l29u3eaeqf"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "hkitftvrblcmp35ccr2rfgmg0p"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "36fvpcfneha0psdkcongoslqhi"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "adobe-sign-verification=3f81eef2cae0ba508fad3d31356494b4"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "14cdviopi83qfqsr00edmeb02u"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "v4s6p80shob7d34obcvgthap5i"
                    },
                    {
                        "ttl": 21599,
                        "type": "NS",
                        "value": "ns1.p23.dynect.net"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "adobe-idp-site-verification=9b01a9ad-47a1-4d79-a207-25b12d1958a7"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "p2avt2pnrn006tf2iht0ktphsp"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "v=spf1 include:spf-a.paloaltonetworks.com include:spf-b.paloaltonetworks.com include:spf-c.paloaltonetworks.com ~all"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "CGTGPGXPT3YNYUMKWS4RXNGXQHN5QEY3"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "logmein-verification-code=1379d49d-5d99-4141-9baa-0b30f7c69214"
                    },
                    {
                        "ttl": 21599,
                        "type": "NS",
                        "value": "ns3.p23.dynect.net"
                    },
                    {
                        "ttl": 21599,
                        "type": "NS",
                        "value": "ns4.p23.dynect.net"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "EHJSPTQUZK5WEHK7JD5XWWQAUGW3XMJT"
                    },
                    {
                        "ttl": 14399,
                        "type": "TXT",
                        "value": "nncr5kvkcogrqimf5m5vtussp6"
                    }
                ],
                "last_dns_records_date": 1616986415,
                "last_https_certificate": {
                    "cert_signature": {
                        "signature": "b1f0bbeaa5a3b22b63b7d1601c633eb028fb5a77c73226d578cda06d55406c89eb55cf65f69f55b7ed015456b86063adc87ad288d7ee4d922a315cab02da9c5cd12751010b248ca73de4d1596bab4611d72758f3a2244e0f0ebf2f6a969d83180ed930b901c43bb1756ce6d2a1248da4be9cd47c4e2012e5f8d510c7c5249bbc97839e639733d5dc22697159aec439bf37f5c73ecaff7f72db1de1e652850f7ee29b9b9c17026c411f73020b99f1006e9dbe732e7d8f4a060e380bda9e05f56b3c3bd78b16dd3447a1a96382cc80e86f3627163a41879e58041ceff9697ec11f5c566a091c9c3921e29623194bbecac9e278d9da84816dbd32ab6838cedef881",
                        "signature_algorithm": "sha256RSA"
                    },
                    "extensions": {
                        "1.3.6.1.4.1.11129.2.4.2": "0482016a0168007600a4b90990b418581487bb13a2cc67700a3c359804f91bdf",
                        "CA": true,
                        "authority_key_identifier": {
                            "keyid": "40c2bd278ecc348330a233d7fb6cb3f0b42c80ce"
                        },
                        "ca_information_access": {
                            "CA Issuers": "http://certificates.godaddy.com/repository/gdig2.crt",
                            "OCSP": "http://ocsp.godaddy.com/"
                        },
                        "certificate_policies": [
                            "2.16.840.1.114413.1.7.23.1",
                            "2.23.140.1.2.1"
                        ],
                        "crl_distribution_points": [
                            "http://crl.godaddy.com/gdig2s1-1677.crl"
                        ],
                        "extended_key_usage": [
                            "serverAuth",
                            "clientAuth"
                        ],
                        "key_usage": [
                            "ff"
                        ],
                        "subject_alternative_name": [
                            "www.paloaltonetworks.com",
                            "paloaltonetworks.com",
                            "aws.paloaltonetworks.com",
                            "events.paloaltonetworks.com",
                            "azure.paloaltonetworks.com",
                            "get.info.paloaltonetworks.com",
                            "compete.paloaltonetworks.com",
                            "marketing.paloaltonetworks.com",
                            "googlecloud.paloaltonetworks.com"
                        ],
                        "subject_key_identifier": "ed89d4b918aab2968bd1dfde421a179c51445be0",
                        "tags": []
                    },
                    "issuer": {
                        "C": "US",
                        "CN": "Go Daddy Secure Certificate Authority - G2",
                        "L": "Scottsdale",
                        "O": "GoDaddy.com, Inc.",
                        "OU": "http://certs.godaddy.com/repository/",
                        "ST": "Arizona"
                    },
                    "public_key": {
                        "algorithm": "RSA",
                        "rsa": {
                            "exponent": "010001",
                            "key_size": 2048,
                            "modulus": "00badd2ce557c9c83883e418d6710ef2c286a8cd701bf7adbed530b4909fb147d3c879e7863b6c00ae2a79e7a11131a04da94b23b97d9ecb93a3fc39bc24b186b3eeba9c1e1d7315a580c58a7dc94e2e8a6cca45a2c25513f5c28f4582e08b04adc1a0269f636eba4624e8baef3b3bc40c4cb2bf9bedd14092e619b424e5d863e491da1c9c5b88516eab6794ced195cf212ac4c8bd1f3403269b85dbae0b948672b0f526d4c725035fbaa64f5d4e521790ce88810fcda36b94737f7af0b6347e912101d8718814c153c7f3771de172de490cd971a99fa7b41d746839a0a7e6981f9b6074a6260a6ee6009edb62f90161ebd652f1ddf6122412ba946e33706ac0f1"
                        }
                    },
                    "serial_number": "f5fa379466d9884a",
                    "signature_algorithm": "sha256RSA",
                    "size": 1963,
                    "subject": {
                        "CN": "www.paloaltonetworks.com",
                        "OU": "Domain Control Validated"
                    },
                    "tags": [],
                    "thumbprint": "0296c20e3a4a607b8d9e2af86155cde04594535e",
                    "thumbprint_sha256": "17bb7bda507abc602bdf1b160d7f51edaccac39fd34f8dab1e793c3612cfc8c2",
                    "validity": {
                        "not_after": "2022-01-27 16:52:24",
                        "not_before": "2020-01-27 16:52:24"
                    },
                    "version": "V3"
                },
                "last_https_certificate_date": 1616986415,
                "last_modification_date": 1617084294,
                "last_update_date": 1594825871,
                "popularity_ranks": {
                    "Alexa": {
                        "rank": 32577,
                        "timestamp": 1617032161
                    },
                    "Cisco Umbrella": {
                        "rank": 6605,
                        "timestamp": 1616686562
                    },
                    "Majestic": {
                        "rank": 4886,
                        "timestamp": 1617032162
                    },
                    "Quantcast": {
                        "rank": 20361,
                        "timestamp": 1585582565
                    },
                    "Statvoo": {
                        "rank": 32577,
                        "timestamp": 1617032187
                    }
                },
                "registrar": "MarkMonitor Inc.",
                "reputation": 0,
                "tags": [],
                "total_votes": {
                    "harmless": 0,
                    "malicious": 0
                },
                "whois": "Creation Date: 2005-02-21T02:42:10Z\nDNSSEC: signedDelegation\nDomain Name: PALOALTONETWORKS.COM\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nName Server: NS1.P23.DYNECT.NET\nName Server: NS2.P23.DYNECT.NET\nName Server: NS3.P23.DYNECT.NET\nName Server: NS4.P23.DYNECT.NET\nName Server: NS5.DNSMADEEASY.COM\nName Server: NS6.DNSMADEEASY.COM\nName Server: NS7.DNSMADEEASY.COM\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nRegistrar IANA ID: 292\nRegistrar URL: http://www.markmonitor.com\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar: MarkMonitor Inc.\nRegistry Domain ID: 143300555_DOMAIN_COM-VRSN\nRegistry Expiry Date: 2024-02-21T02:42:10Z\nUpdated Date: 2020-07-15T15:11:11Z",
                "whois_date": 1615321176
            },
            "id": "paloaltonetworks.com",
            "links": {
                "self": "https://www.virustotal.com/api/v3/domains/paloaltonetworks.com"
            },
            "type": "domain"
        }
    }
}
```

#### Human Readable Output

>### Search result of query paloaltonetworks.com
>|Categories|CreationDate|Favicon|Jarm|LastAnalysisStats|LastDnsRecords|LastDnsRecordsDate|LastHttpsCertificate|LastHttpsCertificateDate|LastModificationDate|LastUpdateDate|PopularityRanks|Registrar|Reputation|TotalVotes|Whois|WhoisDate|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Forcepoint ThreatSeeker: information technology<br/>sophos: information technology<br/>BitDefender: marketing<br/>alphaMountain.ai: Business/Economy, Information Technology | 1108953730 | raw_md5: 920c3c89139c32d356fa4b8b61616f37<br/>dhash: 02e9ecb69ac869a8 | 29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae | harmless: 75<br/>malicious: 0<br/>suspicious: 0<br/>undetected: 7<br/>timeout: 0 | {'type': 'TXT', 'value': 'atlassian-domain-verification=WeW32v7AwYQEviMzlNjYyXNMUngcnmIMtNZKJ69TuQUoda5T6DFFV/A6rRvOzwvs', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '35g550m1f2732uuklt7om3fr0k', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'amazonses:wD8q9vBgr/tA/9V4Lh4CPADIMQs4LIW/EpqeYxrS5e8=', 'ttl': 14399},<br/>{'type': 'NS', 'value': 'ns7.dnsmadeeasy.com', 'ttl': 21599},<br/>{'rname': 'domains.paloaltonetworks.com', 'retry': 600, 'value': 'ns1.p23.dynect.net', 'minimum': 3600, 'refresh': 3600, 'expire': 604800, 'ttl': 14399, 'serial': 1616778508, 'type': 'SOA'},<br/>{'type': 'TXT', 'value': 'e6dj6aj6redkv98nojsphl0bp6', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'mongodb-site-verification=iAfodgMVqXWglWqKv3qb4xzIjtZkfBwk', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'wcfF7BYKYfRSc96jwmhQfabmMPUMLVmBu1Pauas9oU0=', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'docusign=7979590c-2e52-4018-b599-54a429f449d1', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'b1kisgsns70occu4j4jpl552a9', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'status-page-domain-verification=gxhgqp5msy2m', 'ttl': 14399},<br/>{'type': 'A', 'value': '34.107.151.202', 'ttl': 23},<br/>{'type': 'TXT', 'value': '74H6MX8NRYBAQ3D8H2MJC3Y8P5AGSNB8', 'ttl': 14399},<br/>{'priority': 10, 'type': 'MX', 'value': 'mxa-00169c01.gslb.pphosted.com', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'CGJAZFH9QTYUPE2A6XJE8VEBUSSB47B5', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '3fln6bvgju1p5c0aa455mjl61n', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'lrlteq11f2vuhlvmkerhqnpua7', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'c2e1bv49egsn6v6ohlra47namp', 'ttl': 14399},<br/>{'type': 'NS', 'value': 'ns6.dnsmadeeasy.com', 'ttl': 21599},<br/>{'type': 'TXT', 'value': 'logmein-verification-code=ccb897d5-1bed-410a-9c45-a6dd6be9b1c', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'p5cIVMfOtO93Vdzz9extJY700HwcOXxbhBcB+dyK028=', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'omi6ve5p04je278gjtiegkblh1', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'atlassian-domain-verification=OLe058dAXDG6kcCutEa7uSYy2iKLT7CvYNxGz2iROYa4NJ8FazXAkt/Elc8OzblS', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'okansnmkk1j60die0or78624gh', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '9j6u125ve5mvsd634h0gkovq27', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'amazonses:Do93Z/wjV5nZDDaT6n/geaLn2dcmC4LKxWJr6kW09J4=', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'o9c2hro57o4ahin6q2jj64lft8', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '5q1hlpu2u9j6lgrp3rp2ucv48p', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'gbe3h5tqf05k12gdkh1ch15c7r', 'ttl': 14399},<br/>{'priority': 10, 'type': 'MX', 'value': 'mxb-00169c01.gslb.pphosted.com', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'google-site-verification=8zcmNvhRzBOYw-GN3l86mhO5MTfJjEd8ocEyjdsSLak', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'vm77066l7cp2i2hr66uvsforij', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'hi8pl0b5i96m35pf2741v1hqth', 'ttl': 14399},<br/>{'type': 'NS', 'value': 'ns5.dnsmadeeasy.com', 'ttl': 21599},<br/>{'type': 'TXT', 'value': 'h7vhs2ouk1vftgjoqqlmjcthbj', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'css6v61730u8halh3dec5lgreo', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'eks3p/qXVt97oL7X1IGBQdP05ev8rOuFOK8LAzqJ8iMkRDfXrKKGEFy3zHyGEAG8IkwimKG83eTQtoWgLClb2A==', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '7is4vpdq4k8dcioag2dhd5dtot', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'jkt1bch6hqi27c4jisrstg5mke', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'atlassian-domain-verification=2eHeLgLQ13HybaqKxXx+k/uq1dD51Vcs0GAhz1rsbpWTAP3pagbUpE1SuY3dTIyi', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'rmrophudqgsjmkfu3fur0da1dh', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'lspo05pafcr60k2utns50jephr', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'o1l85onfiau3ujepq88nscnsbp', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '9n1sitvm4qt002dkp0riccqu3b', 'ttl': 14399},<br/>{'type': 'NS', 'value': 'ns2.p23.dynect.net', 'ttl': 21599},<br/>{'type': 'TXT', 'value': 'nm70udiiaufkln1coolgar432q', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'ca2mn12n6lmqe0l187um71u78f', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'R4WKB79BFYVKQ8DVZPR2JCS5CS2CTXMY', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'uZ5++1a8ndinwH931iYZakLQiALyIpSMchkwXnu+cd4=', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'c552n5ffvckbvajtvlbq87h6e4', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'fu93k0bu02qfg8mhfiedij43fo', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '2342193', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'kel7gtj8ljaveug9l29u3eaeqf', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'hkitftvrblcmp35ccr2rfgmg0p', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '36fvpcfneha0psdkcongoslqhi', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'adobe-sign-verification=3f81eef2cae0ba508fad3d31356494b4', 'ttl': 14399},<br/>{'type': 'TXT', 'value': '14cdviopi83qfqsr00edmeb02u', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'v4s6p80shob7d34obcvgthap5i', 'ttl': 14399},<br/>{'type': 'NS', 'value': 'ns1.p23.dynect.net', 'ttl': 21599},<br/>{'type': 'TXT', 'value': 'adobe-idp-site-verification=9b01a9ad-47a1-4d79-a207-25b12d1958a7', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'p2avt2pnrn006tf2iht0ktphsp', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'v=spf1 include:spf-a.paloaltonetworks.com include:spf-b.paloaltonetworks.com include:spf-c.paloaltonetworks.com ~all', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'CGTGPGXPT3YNYUMKWS4RXNGXQHN5QEY3', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'logmein-verification-code=1379d49d-5d99-4141-9baa-0b30f7c69214', 'ttl': 14399},<br/>{'type': 'NS', 'value': 'ns3.p23.dynect.net', 'ttl': 21599},<br/>{'type': 'NS', 'value': 'ns4.p23.dynect.net', 'ttl': 21599},<br/>{'type': 'TXT', 'value': 'EHJSPTQUZK5WEHK7JD5XWWQAUGW3XMJT', 'ttl': 14399},<br/>{'type': 'TXT', 'value': 'nncr5kvkcogrqimf5m5vtussp6', 'ttl': 14399} | 1616986415 | size: 1963<br/>public_key: {"rsa": {"key_size": 2048, "modulus": "00badd2ce557c9c83883e418d6710ef2c286a8cd701bf7adbed530b4909fb147d3c879e7863b6c00ae2a79e7a11131a04da94b23b97d9ecb93a3fc39bc24b186b3eeba9c1e1d7315a580c58a7dc94e2e8a6cca45a2c25513f5c28f4582e08b04adc1a0269f636eba4624e8baef3b3bc40c4cb2bf9bedd14092e619b424e5d863e491da1c9c5b88516eab6794ced195cf212ac4c8bd1f3403269b85dbae0b948672b0f526d4c725035fbaa64f5d4e521790ce88810fcda36b94737f7af0b6347e912101d8718814c153c7f3771de172de490cd971a99fa7b41d746839a0a7e6981f9b6074a6260a6ee6009edb62f90161ebd652f1ddf6122412ba946e33706ac0f1", "exponent": "010001"}, "algorithm": "RSA"}<br/>thumbprint_sha256: 17bb7bda507abc602bdf1b160d7f51edaccac39fd34f8dab1e793c3612cfc8c2<br/>tags: <br/>cert_signature: {"signature": "b1f0bbeaa5a3b22b63b7d1601c633eb028fb5a77c73226d578cda06d55406c89eb55cf65f69f55b7ed015456b86063adc87ad288d7ee4d922a315cab02da9c5cd12751010b248ca73de4d1596bab4611d72758f3a2244e0f0ebf2f6a969d83180ed930b901c43bb1756ce6d2a1248da4be9cd47c4e2012e5f8d510c7c5249bbc97839e639733d5dc22697159aec439bf37f5c73ecaff7f72db1de1e652850f7ee29b9b9c17026c411f73020b99f1006e9dbe732e7d8f4a060e380bda9e05f56b3c3bd78b16dd3447a1a96382cc80e86f3627163a41879e58041ceff9697ec11f5c566a091c9c3921e29623194bbecac9e278d9da84816dbd32ab6838cedef881", "signature_algorithm": "sha256RSA"}<br/>validity: {"not_after": "2022-01-27 16:52:24", "not_before": "2020-01-27 16:52:24"}<br/>version: V3<br/>extensions: {"certificate_policies": ["2.16.840.1.114413.1.7.23.1", "2.23.140.1.2.1"], "extended_key_usage": ["serverAuth", "clientAuth"], "authority_key_identifier": {"keyid": "40c2bd278ecc348330a233d7fb6cb3f0b42c80ce"}, "subject_alternative_name": ["www.paloaltonetworks.com", "paloaltonetworks.com", "aws.paloaltonetworks.com", "events.paloaltonetworks.com", "azure.paloaltonetworks.com", "get.info.paloaltonetworks.com", "compete.paloaltonetworks.com", "marketing.paloaltonetworks.com", "googlecloud.paloaltonetworks.com"], "tags": [], "subject_key_identifier": "ed89d4b918aab2968bd1dfde421a179c51445be0", "crl_distribution_points": ["http://crl.godaddy.com/gdig2s1-1677.crl"], "key_usage": ["ff"], "1.3.6.1.4.1.11129.2.4.2": "0482016a0168007600a4b90990b418581487bb13a2cc67700a3c359804f91bdf", "CA": true, "ca_information_access": {"CA Issuers": "http://certificates.godaddy.com/repository/gdig2.crt", "OCSP": "http://ocsp.godaddy.com/"}}<br/>signature_algorithm: sha256RSA<br/>serial_number: f5fa379466d9884a<br/>thumbprint: 0296c20e3a4a607b8d9e2af86155cde04594535e<br/>issuer: {"C": "US", "CN": "Go Daddy Secure Certificate Authority - G2", "L": "Scottsdale", "O": "GoDaddy.com, Inc.", "ST": "Arizona", "OU": "http://certs.godaddy.com/repository/"}<br/>subject: {"OU": "Domain Control Validated", "CN": "www.paloaltonetworks.com"} | 1616986415 | 1617084294 | 1594825871 | Majestic: {"timestamp": 1617032162, "rank": 4886}<br/>Statvoo: {"timestamp": 1617032187, "rank": 32577}<br/>Alexa: {"timestamp": 1617032161, "rank": 32577}<br/>Cisco Umbrella: {"timestamp": 1616686562, "rank": 6605}<br/>Quantcast: {"timestamp": 1585582565, "rank": 20361} | MarkMonitor Inc. | 0 | harmless: 0<br/>malicious: 0 | Creation Date: 2005-02-21T02:42:10Z<br/>DNSSEC: signedDelegation<br/>Domain Name: PALOALTONETWORKS.COM<br/>Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited<br/>Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited<br/>Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited<br/>Name Server: NS1.P23.DYNECT.NET<br/>Name Server: NS2.P23.DYNECT.NET<br/>Name Server: NS3.P23.DYNECT.NET<br/>Name Server: NS4.P23.DYNECT.NET<br/>Name Server: NS5.DNSMADEEASY.COM<br/>Name Server: NS6.DNSMADEEASY.COM<br/>Name Server: NS7.DNSMADEEASY.COM<br/>Registrar Abuse Contact Email: abusecomplaints@markmonitor.com<br/>Registrar Abuse Contact Phone: +1.2083895740<br/>Registrar IANA ID: 292<br/>Registrar URL: http://www.markmonitor.com<br/>Registrar WHOIS Server: whois.markmonitor.com<br/>Registrar: MarkMonitor Inc.<br/>Registry Domain ID: 143300555_DOMAIN_COM-VRSN<br/>Registry Expiry Date: 2024-02-21T02:42:10Z<br/>Updated Date: 2020-07-15T15:11:11Z | 1615321176 |


### vt-file-sandbox-report
***
Retrieves a behavioral relationship of the given file hash.


#### Base Command

`vt-file-sandbox-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports MD5, SHA1, and SHA256. | Required | 
| limit | Maximum number of results to fetch. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SandboxReport.attributes.analysis_date | Number | The date of the analysis in epoch format. | 
| SandboxReport.attributes.behash | String | Behash of the attribute. | 
| SandboxReport.attributes.command_executions | String | Which command were executed. | 
| SandboxReport.attributes.dns_lookups.hostname | String | Host names found in the lookup. | 
| SandboxReport.attributes.dns_lookups.resolved_ips | String | The IPs that were resolved. | 
| SandboxReport.attributes.files_attribute_changed | String | The file attributes that were changed. | 
| SandboxReport.attributes.has_html_report | Boolean | Whether there is an HTML report. | 
| SandboxReport.attributes.has_pcap | Boolean | Whether the IP has a PCAP file. | 
| SandboxReport.attributes.http_conversations.request_method | String | The request method of the HTTP conversation. | 
| SandboxReport.attributes.http_conversations.response_headers.Cache-Control | String | The cache-control method of the response header. | 
| SandboxReport.attributes.http_conversations.response_headers.Connection | String | The connection of the response header. | 
| SandboxReport.attributes.http_conversations.response_headers.Content-Length | String | THe Content-Length of the response header. | 
| SandboxReport.attributes.http_conversations.response_headers.Content-Type | String | The Content-Type of the response header. | 
| SandboxReport.attributes.http_conversations.response_headers.Pragma | String | The pragma of the  response header. | 
| SandboxReport.attributes.http_conversations.response_headers.Server | String | The server of the response header. | 
| SandboxReport.attributes.http_conversations.response_headers.Status-Line | String | The Status-Line of the response header. | 
| SandboxReport.attributes.http_conversations.response_status_code | Number | The response status code. | 
| SandboxReport.attributes.http_conversations.url | String | The conversation URL. | 
| SandboxReport.attributes.last_modification_date | Number | Last modified data in epoch format. | 
| SandboxReport.attributes.modules_loaded | String | Loaded modules. | 
| SandboxReport.attributes.mutexes_created | String | The mutexes that were created. | 
| SandboxReport.attributes.mutexes_opened | String | The mutexes that were opened. | 
| SandboxReport.attributes.processes_created | String | The processes that were created. | 
| SandboxReport.attributes.processes_tree.name | String | The name of the process tree. | 
| SandboxReport.attributes.processes_tree.process_id | String | The ID of the process. | 
| SandboxReport.attributes.registry_keys_deleted | String | Deleted registry keys. | 
| SandboxReport.attributes.registry_keys_set.key | String | Key of the registry key. | 
| SandboxReport.attributes.registry_keys_set.value | String | Value of the registry key. | 
| SandboxReport.attributes.sandbox_name | String | The name of the sandbox. | 
| SandboxReport.attributes.services_started | String | The services that were started. | 
| SandboxReport.attributes.verdicts | String | The verdicts. | 
| SandboxReport.id | String | The IP analyzed. | 
| SandboxReport.links.self | String | Link to the response. | 
| SandboxReport.attributes.files_dropped.path | String | Path of the file dropped. | 
| SandboxReport.attributes.files_dropped.sha256 | String | SHA-256 hash of the dropped files. | 
| SandboxReport.attributes.files_opened | String | The files that were opened. | 
| SandboxReport.attributes.files_written | String | The files that were written. | 
| SandboxReport.attributes.ip_traffic.destination_ip | String | Destination IP in the traffic. | 
| SandboxReport.attributes.ip_traffic.destination_port | Number | Destination port in the traffic. | 
| SandboxReport.attributes.ip_traffic.transport_layer_protocol | String | Transport layer protocol in the traffic. | 
| SandboxReport.attributes.registry_keys_opened | String | The registry keys that were opened. | 
| SandboxReport.attributes.tags | String | The tags of the DNS data. | 
| SandboxReport.attributes.files_copied.destination | String | Destination of the files copied. | 
| SandboxReport.attributes.files_copied.source | String | Source of the files copied. | 
| SandboxReport.attributes.permissions_requested | String | The permissions that where requested. | 
| SandboxReport.attributes.processes_injected | String | The processes that were injected. | 
| SandboxReport.attributes.processes_terminated | String | The processes that were terminated. | 
| SandboxReport.attributes.processes_tree.children.name | String | The name of the children of the process. | 
| SandboxReport.attributes.processes_tree.children.process_id | String | The ID of the children of the process. | 
| SandboxReport.attributes.services_opened | String | The services that were opened. | 
| SandboxReport.attributes.text_highlighted | String | The text that was highlighted. | 
| SandboxReport.attributes.calls_highlighted | String | The calls that were highlighted. | 
| SandboxReport.attributes.processes_tree.children.time_offset | Number | The time offset of the children in the process. | 
| SandboxReport.links.self | String | The link to the response. | 
| SandboxReport.meta.count | Number | The number of objects that were found in the attributes. | 


#### Command Example
```!vt-file-sandbox-report file=2b294b3499d1cce794badffc959b7618```

#### Context Example
```json
{
    "VirusTotal": {
        "SandboxReport": [
            {
                "attributes": {
                    "analysis_date": 1558429832,
                    "behash": "079386becc949a2aafdcd2c6042cf0a9",
                    "command_executions": [
                        "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\Win32.AgentTesla.exe",
                        "Shutdown -r -t 5",
                        "C:\\Users\\Lucas\\AppData\\Local\\Temp\\Win32.AgentTesla.exe",
                        "C:\\Windows\\SysWow64\\WindowsPowerShell\\v1.0\\powershell.exe Start-Process -FilePath C:\\Users\\Lucas\\AppData\\Local\\Temp\\Win32.AgentTesla.exe -wait"
                    ],
                    "dns_lookups": [
                        {
                            "hostname": "checkip.dyndns.org",
                            "resolved_ips": [
                                "131.186.113.70",
                                "216.146.43.70",
                                "162.88.193.70",
                                "216.146.43.71"
                            ]
                        },
                        {
                            "hostname": "checkip.dyndns.org",
                            "resolved_ips": [
                                "131.186.113.70",
                                "131.186.161.70",
                                "216.146.43.70",
                                "162.88.193.70",
                                "216.146.43.71"
                            ]
                        }
                    ],
                    "files_attribute_changed": [
                        "C:\\Documents and Settings\\Miller\\Local Settings\\Temp\\xws\\xws.exe",
                        "C:\\Documents and Settings\\Miller\\Local Settings\\Temp\\xws\\xws.exe\\:Zone.Identifier:$DATA",
                        "C:\\Users\\Lucas\\AppData\\Local\\Temp\\xws\\xws.exe",
                        "C:\\Users\\Lucas\\AppData\\Local\\Temp\\xws\\xws.exe\\:Zone.Identifier:$DATA"
                    ],
                    "has_html_report": false,
                    "has_pcap": false,
                    "http_conversations": [
                        {
                            "request_method": "GET",
                            "response_headers": {
                                "Cache-Control": "no-cache",
                                "Connection": "close",
                                "Content-Length": "107",
                                "Content-Type": "text/html",
                                "Pragma": "no-cache",
                                "Server": "DynDNS-CheckIP/1.0.1",
                                "Status-Line": "HTTP/1.1 200"
                            },
                            "response_status_code": 200,
                            "url": "http://checkip.dyndns.org/"
                        },
                        {
                            "request_method": "GET",
                            "response_headers": {
                                "Cache-Control": "no-cache",
                                "Connection": "close",
                                "Content-Length": "105",
                                "Content-Type": "text/html",
                                "Pragma": "no-cache",
                                "Server": "DynDNS-CheckIP/1.0.1",
                                "Status-Line": "HTTP/1.1 200"
                            },
                            "response_status_code": 200,
                            "url": "http://checkip.dyndns.org/"
                        }
                    ],
                    "last_modification_date": 1588377117,
                    "modules_loaded": [
                        "c:\\windows\\system32\\imm32.dll",
                        "c:\\windows\\system32\\msctf.dll",
                        "c:\\windows\\microsoft.net\\framework\\v4.0.30319\\nlssorting.dll",
                        "c:\\windows\\microsoft.net\\framework\\v4.0.30319\\clr.dll",
                        "c:\\windows\\system32\\msvcr100_clr0400.dll",
                        "c:\\windows\\system32\\ole32.dll",
                        "c:\\windows\\system32\\xpsp2res.dll",
                        "c:\\windows\\system32\\uxtheme.dll",
                        "c:\\windows\\system32\\apphelp.dll",
                        "c:\\windows\\system32\\mscoree.dll",
                        "c:\\windows\\system32\\secur32.dll",
                        "c:\\windows\\system32\\msvcrt.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system\\964da027ebca3b263a05cadb8eaa20a3\\system.ni.dll",
                        "c:\\windows\\system32\\msctfime.ime",
                        "c:\\windows\\microsoft.net\\framework\\v4.0.30319\\culture.dll",
                        "c:\\windows\\system32\\shlwapi.dll",
                        "c:\\windows\\microsoft.net\\framework\\v4.0.30319\\mscoreei.dll",
                        "c:\\windows\\system32\\gdi32.dll",
                        "c:\\windows\\system32\\version.dll",
                        "c:\\windows\\system32\\kernel32.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.core\\713647b987b140a17e3c4ffe4c721f85\\system.core.ni.dll",
                        "c:\\windows\\system32\\rpcrt4.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.drawing\\dd57bc19f5807c6dbe8f88d4a23277f6\\system.drawing.ni.dll",
                        "c:\\windows\\system32\\user32.dll",
                        "c:\\windows\\system32\\ntdll.dll",
                        "c:\\windows\\system32\\psapi.dll",
                        "c:\\windows\\microsoft.net\\framework\\v4.0.30319\\clrjit.dll",
                        "c:\\windows\\system32\\advapi32.dll",
                        "c:\\windows\\winsxs\\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.0.2600.5512_x-ww_dfb54e0c\\gdiplus.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\microsoft.visualbas#\\e8ab3b63bade82c3522613f2b1240c0d\\microsoft.visualbasic.ni.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\mscorlib\\246f1a5abb686b9dcdf22d3505b08cea\\mscorlib.ni.dll",
                        "c:\\windows\\system32\\clbcatq.dll",
                        "c:\\windows\\system32\\rtutils.dll",
                        "c:\\windows\\system32\\winmm.dll",
                        "c:\\windows\\system32\\msvcp60.dll",
                        "c:\\windows\\system32\\wbem\\wbemprox.dll",
                        "c:\\windows\\system32\\urlmon.dll",
                        "c:\\windows\\system32\\setupapi.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.configuration\\ac18c2dcd06bd2a0589bac94ccae5716\\system.configuration.ni.dll",
                        "c:\\windows\\system32\\ws2help.dll",
                        "c:\\windows\\system32\\rsaenh.dll",
                        "c:\\windows\\system32\\wbem\\wbemcomn.dll",
                        "c:\\windows\\system32\\wbem\\wbemdisp.dll",
                        "c:\\windows\\system32\\wbem\\wbemsvc.dll",
                        "c:\\windows\\system32\\rasadhlp.dll",
                        "c:\\windows\\system32\\tapi32.dll",
                        "c:\\windows\\microsoft.net\\assembly\\gac_32\\custommarshalers\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\custommarshalers.dll",
                        "c:\\windows\\system32\\rasapi32.dll",
                        "c:\\windows\\system32\\netapi32.dll",
                        "c:\\windows\\system32\\comctl32.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.management\\6a6f4be744ed5bc5273cbcf0fcf303e3\\system.management.ni.dll",
                        "c:\\windows\\system32\\wbem\\wmiutils.dll",
                        "c:\\windows\\system32\\wldap32.dll",
                        "c:\\windows\\system32\\ntdsapi.dll",
                        "c:\\windows\\system32\\comres.dll",
                        "c:\\windows\\system32\\hnetcfg.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\custommarshalers\\d2574c8ae333ff959be2e0d83121ad10\\custommarshalers.ni.dll",
                        "c:\\windows\\system32\\shfolder.dll",
                        "c:\\windows\\system32\\wshtcpip.dll",
                        "c:\\windows\\microsoft.net\\framework\\v4.0.30319\\wminet_utils.dll",
                        "c:\\windows\\system32\\msv1_0.dll",
                        "c:\\windows\\system32\\oleaut32.dll",
                        "c:\\windows\\system32\\shell32.dll",
                        "c:\\windows\\system32\\iphlpapi.dll",
                        "c:\\windows\\system32\\sxs.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.xml\\e997d0200c25f7db6bd32313d50b729d\\system.xml.ni.dll",
                        "c:\\windows\\system32\\ws2_32.dll",
                        "c:\\windows\\system32\\wbem\\fastprox.dll",
                        "c:\\windows\\system32\\dnsapi.dll",
                        "c:\\windows\\system32\\mswsock.dll",
                        "c:\\windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\\comctl32.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.windows.forms\\17e020ae92d7fab33bcc1c98b25019d0\\system.windows.forms.ni.dll",
                        "c:\\windows\\system32\\rasman.dll",
                        "c:\\windows\\system32\\winrnr.dll",
                        "c:\\windows\\system32\\iertutil.dll",
                        "c:\\windows\\system32\\msacm32.dll",
                        "c:\\windows\\apppatch\\acgenral.dll",
                        "c:\\windows\\system32\\shimeng.dll",
                        "c:\\windows\\system32\\userenv.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\mscorlib\\51e2934144ba15628ba5a31be2dae7dc\\mscorlib.ni.dll",
                        "c:\\windows\\syswow64\\usp10.dll",
                        "c:\\windows\\system32\\rpcrtremote.dll",
                        "c:\\windows\\syswow64\\sechost.dll",
                        "c:\\windows\\system32\\windowscodecs.dll",
                        "c:\\windows\\system32\\msvcr110_clr0400.dll",
                        "c:\\windows\\syswow64\\gdi32.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.drawing\\72269ea7cc6281139e4d155e7c57dc67\\system.drawing.ni.dll",
                        "c:\\windows\\syswow64\\rpcrt4.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system\\e40da7a49f8c3f0108e7c835b342f382\\system.ni.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.core\\b9f7adbc90a2bcbe8eb9e6e8d2bb975b\\system.core.ni.dll",
                        "c:\\windows\\system32\\wow64.dll",
                        "c:\\windows\\winsxs\\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.17514_none_72d18a4386696c80\\gdiplus.dll",
                        "c:\\windows\\syswow64\\kernelbase.dll",
                        "c:\\windows\\system32\\cryptsp.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\microsoft.v9921e851#\\536f3c2e6e4137a628f2f64e0dfd407e\\microsoft.visualbasic.ni.dll",
                        "c:\\windows\\syswow64\\user32.dll",
                        "c:\\windows\\syswow64\\msctf.dll",
                        "c:\\windows\\syswow64\\advapi32.dll",
                        "c:\\windows\\system32\\wow64win.dll",
                        "c:\\windows\\syswow64\\sspicli.dll",
                        "c:\\windows\\syswow64\\kernel32.dll",
                        "c:\\windows\\syswow64\\msvcrt.dll",
                        "c:\\windows\\syswow64\\shlwapi.dll",
                        "c:\\windows\\syswow64\\ntdll.dll",
                        "c:\\windows\\system32\\wow64cpu.dll",
                        "c:\\windows\\syswow64\\cryptbase.dll",
                        "c:\\windows\\syswow64\\ole32.dll",
                        "c:\\windows\\syswow64\\psapi.dll",
                        "c:\\windows\\syswow64\\lpk.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.configuration\\28586400bcaf94c13a9fd0dff4a1e090\\system.configuration.ni.dll",
                        "c:\\windows\\syswow64\\urlmon.dll",
                        "c:\\windows\\system32\\dhcpcsvc6.dll",
                        "c:\\windows\\system32\\dwmapi.dll",
                        "c:\\windows\\syswow64\\wininet.dll",
                        "c:\\windows\\syswow64\\api-ms-win-downlevel-shell32-l1-1-0.dll",
                        "c:\\windows\\syswow64\\profapi.dll",
                        "c:\\windows\\syswow64\\clbcatq.dll",
                        "c:\\windows\\system32\\wship6.dll",
                        "c:\\windows\\syswow64\\ieframe.dll",
                        "c:\\windows\\syswow64\\iertutil.dll",
                        "c:\\windows\\system32\\mpr.dll",
                        "c:\\windows\\syswow64\\api-ms-win-downlevel-advapi32-l1-1-0.dll",
                        "c:\\windows\\system32\\dhcpcsvc.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\custommarshalers\\8a37b97ce8d5b322c455be3dd440e5f2\\custommarshalers.ni.dll",
                        "c:\\windows\\system32\\bcrypt.dll",
                        "c:\\windows\\system32\\wbemcomn.dll",
                        "c:\\windows\\syswow64\\api-ms-win-downlevel-normaliz-l1-1-0.dll",
                        "c:\\windows\\syswow64\\api-ms-win-downlevel-shlwapi-l1-1-0.dll",
                        "c:\\windows\\winsxs\\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.17514_none_41e6975e2bd6f2b2\\comctl32.dll",
                        "c:\\windows\\system32\\fwpuclnt.dll",
                        "c:\\windows\\syswow64\\oleaut32.dll",
                        "c:\\windows\\system32\\winnsi.dll",
                        "c:\\windows\\system32\\webio.dll",
                        "c:\\windows\\syswow64\\setupapi.dll",
                        "c:\\windows\\system32\\winhttp.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.windows.forms\\22ae167d586450ad3a9b9a9ee43ebc86\\system.windows.forms.ni.dll",
                        "c:\\windows\\syswow64\\api-ms-win-downlevel-version-l1-1-0.dll",
                        "c:\\windows\\syswow64\\api-ms-win-downlevel-user32-l1-1-0.dll",
                        "c:\\windows\\system32\\credssp.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.management\\95623e12dc6a64d28bad5b85f4c730ae\\system.management.ni.dll",
                        "c:\\windows\\syswow64\\ws2_32.dll",
                        "c:\\windows\\syswow64\\userenv.dll",
                        "c:\\windows\\system32\\propsys.dll",
                        "c:\\windows\\syswow64\\normaliz.dll",
                        "c:\\windows\\syswow64\\cfgmgr32.dll",
                        "c:\\windows\\syswow64\\api-ms-win-downlevel-ole32-l1-1-0.dll",
                        "c:\\windows\\assembly\\nativeimages_v4.0.30319_32\\system.xml\\9ba07396ae369d010c5c3927a82ef426\\system.xml.ni.dll",
                        "c:\\windows\\syswow64\\devobj.dll",
                        "c:\\windows\\syswow64\\nsi.dll",
                        "c:\\windows\\syswow64\\shell32.dll",
                        "c:\\windows\\system32\\ntshrui.dll",
                        "c:\\windows\\assembly\\nativeimages_v2.0.50727_32\\mscorlib\\62a0b3e4b40ec0e8c5cfaa0c8848e64a\\mscorlib.ni.dll",
                        "c:\\windows\\system32\\srvcli.dll",
                        "c:\\windows\\system32\\slc.dll",
                        "c:\\windows\\assembly\\nativeimages_v2.0.50727_32\\system.management.a#\\4436815b432c313255af322f4ec3560d\\system.management.automation.ni.dll",
                        "c:\\windows\\microsoft.net\\framework\\v2.0.50727\\mscorwks.dll",
                        "c:\\windows\\assembly\\nativeimages_v2.0.50727_32\\microsoft.powershel#\\b1c511d8fad78ad3c5213b2b4fb02b8b\\microsoft.powershell.consolehost.ni.dll",
                        "c:\\windows\\assembly\\nativeimages_v2.0.50727_32\\system\\9e0a3b9b9f457233a335d7fba8f95419\\system.ni.dll",
                        "c:\\windows\\system32\\cscapi.dll",
                        "c:\\windows\\system32\\shdocvw.dll",
                        "c:\\windows\\winsxs\\x86_microsoft.vc80.crt_1fc8b3b9a1e18e3b_8.0.50727.4940_none_d08cc06a442b34fc\\msvcr80.dll",
                        "c:\\windows\\system32\\linkinfo.dll",
                        "c:\\windows\\system32\\atl.dll"
                    ],
                    "mutexes_created": [
                        "CTF.Compart.MutexDefaultS-1-5-21-1229272821-1563985344-1801674531-1003",
                        "CTF.LBES.MutexDefaultS-1-5-21-1229272821-1563985344-1801674531-1003",
                        "CTF.Layouts.MutexDefaultS-1-5-21-1229272821-1563985344-1801674531-1003",
                        "CTF.Asm.MutexDefaultS-1-5-21-1229272821-1563985344-1801674531-1003",
                        "CTF.TimListCache.FMPDefaultS-1-5-21-1229272821-1563985344-1801674531-1003MUTEX.DefaultS-1-5-21-1229272821-1563985344-1801674531-1003",
                        "CTF.TMD.MutexDefaultS-1-5-21-1229272821-1563985344-1801674531-1003",
                        "Local\\ZonesCounterMutex",
                        "Local\\ZonesLockedCacheCounterMutex",
                        "RasPbFile",
                        "MSCTF.Shared.MUTEX.IDD",
                        "Local\\ZoneAttributeCacheCounterMutex",
                        "Local\\ZonesCacheCounterMutex",
                        "SHIMLIB_LOG_MUTEX",
                        "Global\\CLR_PerfMon_WrapMutex",
                        "_SHuassist.mtx"
                    ],
                    "mutexes_opened": [
                        "ShimCacheMutex",
                        "Local\\!IETld!Mutex",
                        "RasPbFile",
                        "Local\\MSCTF.Asm.MutexDefault1",
                        "Global\\CLR_CASOFF_MUTEX"
                    ],
                    "processes_created": [
                        "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\Win32.AgentTesla.exe",
                        "C:\\WINDOWS\\system32\\Shutdown.exe",
                        "C:\\Users\\Lucas\\AppData\\Local\\Temp\\Win32.AgentTesla.exe",
                        "C:\\Windows\\SysWow64\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "C:\\Windows\\SysWOW64\\Shutdown.exe"
                    ],
                    "processes_tree": [
                        {
                            "name": "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\Win32.AgentTesla.exe",
                            "process_id": "272"
                        },
                        {
                            "name": "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\Win32.AgentTesla.exe",
                            "process_id": "476"
                        },
                        {
                            "name": "C:\\WINDOWS\\system32\\Shutdown.exe",
                            "process_id": "284"
                        }
                    ],
                    "registry_keys_deleted": [
                        "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\CLASSES\\MSCFILE\\SHELL\\OPEN\\COMMAND",
                        "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\CLASSES\\MSCFILE",
                        "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\CLASSES\\MSCFILE\\SHELL",
                        "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\CLASSES\\MSCFILE\\SHELL\\OPEN"
                    ],
                    "registry_keys_set": [
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN",
                            "value": "xws"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
                            "value": "Cookies"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP",
                            "value": "UNCAsIntranet"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP",
                            "value": "AutoDetect"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
                            "value": "Local AppData"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
                            "value": "Desktop"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\MOUNTPOINTS2\\{A7A58122-718B-11E3-95AC-806D6172696F}",
                            "value": "BaseClass"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
                            "value": "Common Documents"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
                            "value": "Cache"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
                            "value": "Common Desktop"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP",
                            "value": "IntranetName"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\MOUNTPOINTS2\\{4D7134C0-AF74-11E5-A617-806D6172696F}",
                            "value": "BaseClass"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP",
                            "value": "ProxyBypass"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\MOUNTPOINTS2\\{A7A58125-718B-11E3-95AC-806D6172696F}",
                            "value": "BaseClass"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
                            "value": "AppData"
                        },
                        {
                            "key": "HKU\\S-1-5-21-1229272821-1563985344-1801674531-1003\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
                            "value": "Personal"
                        },
                        {
                            "key": "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN",
                            "value": "xws"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASMANCS",
                            "value": "FileDirectory"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASAPI32",
                            "value": "MaxFileSize"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASAPI32",
                            "value": "FileDirectory"
                        },
                        {
                            "key": "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP",
                            "value": "IntranetName"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASMANCS",
                            "value": "FileTracingMask"
                        },
                        {
                            "key": "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP",
                            "value": "ProxyBypass"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASMANCS",
                            "value": "EnableConsoleTracing"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASAPI32",
                            "value": "FileTracingMask"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASAPI32",
                            "value": "ConsoleTracingMask"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASMANCS",
                            "value": "ConsoleTracingMask"
                        },
                        {
                            "key": "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP",
                            "value": "AutoDetect"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASMANCS",
                            "value": "EnableFileTracing"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASAPI32",
                            "value": "EnableConsoleTracing"
                        },
                        {
                            "key": "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\INTERNET SETTINGS\\ZONEMAP",
                            "value": "UNCAsIntranet"
                        },
                        {
                            "key": "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\CLASSES\\MSCFILE\\SHELL\\OPEN\\COMMAND",
                            "value": ""
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASMANCS",
                            "value": "MaxFileSize"
                        },
                        {
                            "key": "HKLM\\SOFTWARE\\MICROSOFT\\TRACING\\WIN32_RASAPI32",
                            "value": "EnableFileTracing"
                        },
                        {
                            "key": "HKU\\S-1-5-21-3712457824-2419000099-45725732-1005\\SOFTWARE\\CLASSES\\LOCAL SETTINGS\\MUICACHE\\E6\\52C64B7E",
                            "value": "LanguageList"
                        }
                    ],
                    "sandbox_name": "Lastline",
                    "services_started": [
                        "RASMAN",
                        "WinHttpAutoProxySvc"
                    ],
                    "verdicts": [
                        "MALWARE",
                        "TROJAN"
                    ]
                },
                "id": "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_Lastline",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/file_behaviours/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_Lastline"
                },
                "type": "file_behaviour"
            },
            {
                "attributes": {
                    "analysis_date": 1561405459,
                    "files_dropped": [
                        {
                            "path": "\\Users\\Petra\\AppData\\Local\\Temp\\xws\\xws.exe",
                            "sha256": "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3"
                        }
                    ],
                    "files_opened": [
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\config\\machine.config",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Drawing\\3c20a6b0ca532bcc6271bf4b7ad0b4d9\\System.Drawing.ni.dll.aux",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\mscorlib\\77f338d420d067a26b2d34f47445fc51\\mscorlib.ni.dll.aux",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\Microsoft.V9921e851#\\1c459c609c9edf4427ae91b4293b0d0a\\Microsoft.VisualBasic.ni.dll.aux",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System\\0b2f69b43a576b9edcc807a30872bd91\\System.ni.dll.aux",
                        "C:\\Users\\<USER>\\AppData\\Local\\Temp\\1526312897-2b294b349.pe32",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Core\\7aa0dcace3b5d10b626540709537d280\\System.Core.ni.dll.aux"
                    ],
                    "files_written": [
                        "C:\\Users\\<USER>\\AppData\\Local\\Temp\\xws\\xws.exe"
                    ],
                    "has_html_report": false,
                    "has_pcap": false,
                    "ip_traffic": [
                        {
                            "destination_ip": "13.107.4.50",
                            "destination_port": 80,
                            "transport_layer_protocol": "TCP"
                        }
                    ],
                    "last_modification_date": 1563272815,
                    "processes_tree": [
                        {
                            "name": "1526312897-2b294b349.pe32",
                            "process_id": "2624"
                        },
                        {
                            "name": "1526312897-2b294b349.pe32",
                            "process_id": "2724"
                        },
                        {
                            "name": "1526312897-2b294b349.pe32",
                            "process_id": "2780"
                        }
                    ],
                    "registry_keys_opened": [
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\OLE",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Fusion",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\ExtendedLocale",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CustomLocale",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\System",
                        "\\REGISTRY\\USER\\S-1-5-21-1119815420-2032815650-2779196966-1000\\Control Panel\\Desktop",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Fusion",
                        "\\REGISTRY\\USER\\S-1-5-21-1119815420-2032815650-2779196966-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\SKUs\\default",
                        "\\REGISTRY\\USER\\S-1-5-21-1119815420-2032815650-2779196966-1000_Classes",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\.NETFramework\\Policy\\",
                        "\\REGISTRY\\USER\\S-1-5-21-1119815420-2032815650-2779196966-1000\\Control Panel\\Desktop\\LanguageConfiguration",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Sorting\\Versions",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                        "\\REGISTRY\\USER\\S-1-5-21-1119815420-2032815650-2779196966-1000",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\.NETFramework",
                        "\\REGISTRY\\USER\\S-1-5-21-1119815420-2032815650-2779196966-1000\\Control Panel\\Desktop\\MuiCached",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Language Groups",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider Types\\Type 001",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Rpc",
                        "\\Registry\\Machine\\Software\\Classes\\CLSID\\{FAE3D380-FEA4-4623-8C75-C6B61110B681}\\Instance",
                        "\\Registry\\Machine\\Software\\Microsoft\\SQMClient\\Windows",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\GRE_Initialize",
                        "\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\Session Manager",
                        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Cryptography",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\.NETFramework\\NGen\\Policy\\v4.0",
                        "\\REGISTRY\\MACHINE",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Locale",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\Installer\\Assemblies\\Global",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\Policy\\v4.0",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\.NETFramework\\v4.0.30319\\SKUs\\",
                        "\\Registry\\Machine\\System\\Setup",
                        "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Locale\\Alternate Sorts",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\Policy\\Standards",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Cryptography",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\Policy\\Servicing",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows\\Windows Error Reporting\\WMR"
                    ],
                    "registry_keys_set": [
                        {
                            "key": "\\REGISTRY\\USER\\S-1-5-21-1119815420-2032815650-2779196966-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "value": "xws"
                        }
                    ],
                    "sandbox_name": "SNDBOX",
                    "tags": [
                        "PERSISTENCE"
                    ]
                },
                "id": "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_SNDBOX",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/file_behaviours/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_SNDBOX"
                },
                "type": "file_behaviour"
            },
            {
                "attributes": {
                    "analysis_date": 1601545446,
                    "behash": "7617055bb3994dea99c19877fd7ec55a",
                    "command_executions": [
                        "\"C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\EB93A6\\996E.exe\"",
                        "Shutdown -r -t 5"
                    ],
                    "dns_lookups": [
                        {
                            "hostname": "checkip.dyndns.org"
                        }
                    ],
                    "files_copied": [
                        {
                            "destination": "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\xws\\xws.exe ",
                            "source": "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\EB93A6\\996E.exe "
                        }
                    ],
                    "files_opened": [
                        "C:\\WINDOWS\\system32\\winime32.dll",
                        "C:\\WINDOWS\\system32\\ws2_32.dll",
                        "C:\\WINDOWS\\system32\\ws2help.dll",
                        "C:\\WINDOWS\\system32\\psapi.dll",
                        "C:\\WINDOWS\\system32\\mscoree.dll",
                        "C:\\WINDOWS\\system32\\imm32.dll",
                        "C:\\WINDOWS\\system32\\lpk.dll",
                        "C:\\WINDOWS\\system32\\usp10.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\mscoreei.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v2.0.50727\\mscorwks.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\clr.dll",
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\EB93A6\\996E.exe",
                        "C:\\WINDOWS\\system32\\MSVCR100_CLR0400.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\Config\\machine.config",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\index18.dat",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\mscorlib\\cece9d0256e18427b64587ba690605d4\\mscorlib.ni.dll",
                        "C:\\WINDOWS\\system32\\rpcss.dll",
                        "C:\\WINDOWS\\system32\\MSCTF.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\Culture.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\locale.nlp",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\nlssorting.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\SortDefault.nlp",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\clrjit.dll",
                        "C:\\WINDOWS\\assembly\\pubpol1.dat",
                        "C:\\WINDOWS\\Microsoft.NET\\assembly\\GAC_MSIL\\Microsoft.VisualBasic\\v4.0_10.0.0.0__b03f5f7f11d50a3a\\Microsoft.VisualBasic.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System\\7169c473071af03077b1cd2a9c1dbcbe\\System.ni.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Core\\4a9f25bff4bb74c9b6a21091923307d2\\System.Core.ni.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\mscorrc.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Drawing\\cad0df97be252ddb80a846b61f26a4dd\\System.Drawing.ni.dll",
                        "C:\\WINDOWS\\WinSxS\\x86_Microsoft.Windows.GdiPlus_6595b64144ccf1df_1.0.6002.22509_x-ww_c7dad023\\GdiPlus.dll",
                        "C:\\WINDOWS\\system32\\MSCTFIME.IME",
                        "C:\\WINDOWS\\system32\\rsaenh.dll",
                        "C:\\WINDOWS\\system32\\crypt32.dll",
                        "C:\\WINDOWS\\system32\\winlogon.exe",
                        "C:\\WINDOWS\\system32\\xpsp2res.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Windows.Forms\\039d68cb3f0e971d7d44a92dc6a259bf\\System.Windows.Forms.ni.dll",
                        "C:\\WINDOWS\\system32\\shell32.dll",
                        "C:\\WINDOWS\\WinSxS\\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\\comctl32.dll",
                        "C:\\WINDOWS\\WindowsShell.Manifest",
                        "C:\\WINDOWS\\system32\\comctl32.dll",
                        "C:\\WINDOWS\\system32\\clbcatq.dll",
                        "C:\\WINDOWS\\system32\\comres.dll",
                        "C:\\WINDOWS\\Registration\\R000000000007.clb",
                        "C:\\WINDOWS\\system32\\wbem\\wbemdisp.dll",
                        "C:\\WINDOWS\\system32\\msvcp60.dll",
                        "C:\\WINDOWS\\system32\\wbem\\wbemprox.dll",
                        "C:\\WINDOWS\\system32\\wbem\\wbemcomn.dll",
                        "C:\\WINDOWS\\system32\\wbem\\wmiutils.dll",
                        "C:\\WINDOWS\\system32\\wbem\\wbemsvc.dll",
                        "C:\\WINDOWS\\system32\\wbem\\fastprox.dll",
                        "C:\\WINDOWS\\system32\\ntdsapi.dll",
                        "C:\\WINDOWS\\system32\\dnsapi.dll",
                        "C:\\WINDOWS\\system32\\sxs.dll",
                        "C:\\WINDOWS\\system32\\wbem\\wbemdisp.tlb",
                        "C:\\WINDOWS\\Microsoft.NET\\assembly\\GAC_32\\CustomMarshalers\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\CustomMarshalers.dll",
                        "C:\\WINDOWS\\system32\\stdole2.tlb",
                        "C:\\WINDOWS\\Microsoft.NET\\assembly\\GAC_MSIL\\System.Management\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\System.Management.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\wminet_utils.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Configuration\\ce74542c47679fb707831ba40f03c151\\System.Configuration.ni.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Xml\\282e409391657633e44fd8c290240446\\System.Xml.ni.dll",
                        "C:\\WINDOWS\\system32\\rasapi32.dll",
                        "C:\\WINDOWS\\system32\\rasman.dll",
                        "C:\\WINDOWS\\system32\\tapi32.dll",
                        "C:\\WINDOWS\\system32\\rtutils.dll",
                        "C:\\WINDOWS\\system32\\winmm.dll",
                        "C:\\WINDOWS\\system32\\mswsock.dll",
                        "C:\\WINDOWS\\system32\\hnetcfg.dll",
                        "C:\\WINDOWS\\system32\\wshtcpip.dll",
                        "C:\\WINDOWS\\system32\\msv1_0.dll",
                        "C:\\WINDOWS\\system32\\iphlpapi.dll",
                        "C:\\WINDOWS\\system32\\shutdown.exe",
                        "C:\\WINDOWS\\system32\\apphelp.dll",
                        "C:\\WINDOWS\\AppPatch\\sysmain.sdb",
                        "C:\\WINDOWS\\system32\\MSIMTF.dll",
                        "C:\\WINDOWS\\system32\\setupapi.dll",
                        "C:\\DiskD",
                        "C:\\Documents and Settings\\Administrator\\My Documents\\desktop.ini",
                        "C:\\Documents and Settings\\All Users\\Documents\\desktop.ini",
                        "C:\\WINDOWS\\system32\\shfolder.dll",
                        "C:\\WINDOWS\\system32\\urlmon.dll",
                        "C:\\WINDOWS\\system32\\shdocvw.dll",
                        "C:\\WINDOWS\\system32\\wininet.dll",
                        "C:\\WINDOWS\\system32\\riched20.dll",
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temporary Internet Files",
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\History",
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temporary Internet Files\\Content.IE5",
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temporary Internet Files\\Content.IE5\\index.dat",
                        "C:\\Documents and Settings\\Administrator\\Cookies",
                        "C:\\Documents and Settings\\Administrator\\Cookies\\index.dat",
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\History\\History.IE5",
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\History\\History.IE5\\index.dat",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Security\\60cc74b4bd29de9724a3414e8e854b1f\\System.Security.ni.dll"
                    ],
                    "files_written": [
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\xws\\xws.exe",
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\Ktx.exe"
                    ],
                    "has_html_report": true,
                    "has_pcap": false,
                    "last_modification_date": 1601545448,
                    "modules_loaded": [
                        "ADVAPI32.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\mscoreei.dll",
                        "SHLWAPI.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\clr.dll",
                        "mscoree.dll",
                        "ntdll",
                        "rpcrt4.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\mscorlib\\cece9d0256e18427b64587ba690605d4\\mscorlib.ni.dll",
                        "AdvApi32.dll",
                        "ole32.dll",
                        "C:\\WINDOWS\\system32\\MSCTF.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\culture.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\nlssorting.dll",
                        "kernel32.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\clrjit.dll",
                        "NTDLL.DLL",
                        "C:\\WINDOWS\\Microsoft.Net\\assembly\\GAC_MSIL\\Microsoft.VisualBasic\\v4.0_10.0.0.0__b03f5f7f11d50a3a\\Microsoft.VisualBasic.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System\\7169c473071af03077b1cd2a9c1dbcbe\\System.ni.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Core\\4a9f25bff4bb74c9b6a21091923307d2\\System.Core.ni.dll",
                        "advapi32.dll",
                        "C:\\WINDOWS\\Microsoft.NET\\Framework\\v4.0.30319\\mscorrc.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Drawing\\cad0df97be252ddb80a846b61f26a4dd\\System.Drawing.ni.dll",
                        "gdiplus.dll",
                        "C:\\WINDOWS\\system32\\msctfime.ime",
                        "C:\\WINDOWS\\system32\\ole32.dll",
                        "ntdll.dll",
                        "user32.dll",
                        "crypt32.dll",
                        "C:\\WINDOWS\\system32\\rsaenh.dll",
                        "psapi.dll",
                        "kernel32",
                        "xpsp2res.dll",
                        "OLE32",
                        "C:\\WINDOWS\\system32\\Msctf.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Windows.Forms\\039d68cb3f0e971d7d44a92dc6a259bf\\System.Windows.Forms.ni.dll",
                        "comctl32.dll",
                        "imm32.dll",
                        "shell32.dll",
                        "OLE32.DLL",
                        "KERNEL32.DLL",
                        "C:\\WINDOWS\\system32\\wbem\\wbemdisp.dll",
                        "C:\\WINDOWS\\system32\\advapi32.dll",
                        "oleaut32.dll",
                        "C:\\WINDOWS\\system32\\wbem\\wbemprox.dll",
                        "C:\\WINDOWS\\system32\\wbem\\wmiutils.dll",
                        "C:\\WINDOWS\\system32\\wbem\\wbemsvc.dll",
                        "C:\\WINDOWS\\system32\\wbem\\fastprox.dll",
                        "SXS.DLL",
                        "sxs.dll",
                        "OLEAUT32.dll",
                        "C:\\WINDOWS\\Microsoft.Net\\assembly\\GAC_32\\CustomMarshalers\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\CustomMarshalers.dll",
                        "KERNEL32.dll",
                        "USER32.dll",
                        "Secur32.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Configuration\\ce74542c47679fb707831ba40f03c151\\System.Configuration.ni.dll",
                        "C:\\WINDOWS\\assembly\\NativeImages_v4.0.30319_32\\System.Xml\\282e409391657633e44fd8c290240446\\System.Xml.ni.dll",
                        "RASAPI32.DLL",
                        "rasapi32.dll",
                        "RTUTILS.DLL",
                        "ws2_32.dll",
                        "WS2HELP.dll",
                        "hnetcfg.dll",
                        "C:\\WINDOWS\\System32\\wshtcpip.dll",
                        "RASMAN.DLL",
                        "secur32.dll",
                        "C:\\WINDOWS\\system32\\msv1_0.dll",
                        "iphlpapi.dll",
                        "gdi32.dll",
                        "User32.dll",
                        "C:\\WINDOWS\\system32\\shutdown.exe",
                        "user32",
                        "RPCRT4.dll",
                        "C:\\WINDOWS\\system32\\SHELL32.dll",
                        "shfolder.dll",
                        "Comctl32.dll",
                        "C:\\WINDOWS\\system32\\shdocvw.dll",
                        "C:\\WINDOWS\\system32\\urlmon.dll"
                    ],
                    "mutexes_created": [
                        "CTF.LBES.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
                        "CTF.Compart.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
                        "CTF.Asm.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
                        "CTF.Layouts.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
                        "CTF.TMD.MutexDefaultS-1-5-21-1482476501-1645522239-1417001333-500",
                        "CTF.TimListCache.FMPDefaultS-1-5-21-1482476501-1645522239-1417001333-500MUTEX.DefaultS-1-5-21-1482476501-1645522239-1417001333-500",
                        "RasPbFile",
                        "MSCTF.Shared.MUTEX.EBH",
                        "MSCTF.Shared.MUTEX.IIB",
                        "ZonesCounterMutex",
                        "ZonesCacheCounterMutex",
                        "ZonesLockedCacheCounterMutex"
                    ],
                    "mutexes_opened": [
                        "ShimCacheMutex",
                        "RasPbFile",
                        "_!MSFTHISTORY!_",
                        "c:!documents and settings!administrator!local settings!temporary internet files!content.ie5!",
                        "c:!documents and settings!administrator!cookies!",
                        "c:!documents and settings!administrator!local settings!history!history.ie5!"
                    ],
                    "permissions_requested": [
                        "SE_DEBUG_PRIVILEGE",
                        "SE_SHUTDOWN_PRIVILEGE",
                        "SE_REMOTE_SHUTDOWN_PRIVILEGE",
                        "SE_LOAD_DRIVER_PRIVILEGE"
                    ],
                    "processes_created": [
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\EB93A6\\996E.exe",
                        "C:\\WINDOWS\\system32\\shutdown.exe"
                    ],
                    "processes_injected": [
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\EB93A6\\996E.exe"
                    ],
                    "processes_terminated": [
                        "C:\\Documents and Settings\\Administrator\\Local Settings\\Temp\\EB93A6\\996E.exe",
                        "C:\\WINDOWS\\system32\\shutdown.exe"
                    ],
                    "processes_tree": [
                        {
                            "children": [
                                {
                                    "children": [
                                        {
                                            "name": "shutdown.exe",
                                            "process_id": "2336"
                                        }
                                    ],
                                    "name": "****.exe",
                                    "process_id": "1024"
                                }
                            ],
                            "name": "****.exe",
                            "process_id": "628"
                        }
                    ],
                    "registry_keys_opened": [
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\996E.exe",
                        "\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\SafeBoot\\Option",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\TransparentEnabled",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mscoreei.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ntdll.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\KERNEL32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\GDI32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\USER32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Secur32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\RPCRT4.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ADVAPI32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msvcrt.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WS2HELP.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WS2_32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SHLWAPI.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\PSAPI.DLL",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\ole32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\OLEAUT32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\winime32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mscoree.dll",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mscoree.dll\\CheckAppHelp",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\IMM32.DLL",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\USP10.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LPK.DLL",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MSVCR100_CLR0400.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\clr.dll",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\996E.exe\\RpcThreadPoolThrottle",
                        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MSCTF.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mscorlib.ni.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\culture.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\nlssorting.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\clrjit.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\VERSION.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\gdiplus.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\System.ni.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\System.Core.ni.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\System.Drawing.ni.dll",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\IMM\\Ime File",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msctfime.ime",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\xws",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rsaenh.dll",
                        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Cryptography",
                        "\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\AuthenticodeEnabled",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\LevelObjects",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\Levels",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths\\{dda3f824-d8cb-441b-834d-be2efd2c1a33}",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths\\{dda3f824-d8cb-441b-834d-be2efd2c1a33}\\ItemData",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths\\{dda3f824-d8cb-441b-834d-be2efd2c1a33}\\SaferFlags",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{349d35ab-37b5-462f-9b89-edd5fbde1328}",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{349d35ab-37b5-462f-9b89-edd5fbde1328}\\ItemData",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{349d35ab-37b5-462f-9b89-edd5fbde1328}\\HashAlg",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{349d35ab-37b5-462f-9b89-edd5fbde1328}\\ItemSize",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{349d35ab-37b5-462f-9b89-edd5fbde1328}\\SaferFlags",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{7fb9cd2e-3076-4df9-a57b-b813f72dbb91}",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{7fb9cd2e-3076-4df9-a57b-b813f72dbb91}\\ItemData",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{7fb9cd2e-3076-4df9-a57b-b813f72dbb91}\\HashAlg",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{7fb9cd2e-3076-4df9-a57b-b813f72dbb91}\\ItemSize",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{7fb9cd2e-3076-4df9-a57b-b813f72dbb91}\\SaferFlags",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{81d1fe15-dd9d-4762-b16d-7c29ddecae3f}",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{81d1fe15-dd9d-4762-b16d-7c29ddecae3f}\\ItemData",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{81d1fe15-dd9d-4762-b16d-7c29ddecae3f}\\HashAlg",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{81d1fe15-dd9d-4762-b16d-7c29ddecae3f}\\ItemSize",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{81d1fe15-dd9d-4762-b16d-7c29ddecae3f}\\SaferFlags",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{94e3e076-8f53-42a5-8411-085bcc18a68d}",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{94e3e076-8f53-42a5-8411-085bcc18a68d}\\ItemData",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{94e3e076-8f53-42a5-8411-085bcc18a68d}\\HashAlg",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{94e3e076-8f53-42a5-8411-085bcc18a68d}\\ItemSize",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{94e3e076-8f53-42a5-8411-085bcc18a68d}\\SaferFlags",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{dc971ee5-44eb-4fe4-ae2e-b91490411bfc}",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{dc971ee5-44eb-4fe4-ae2e-b91490411bfc}\\ItemData",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{dc971ee5-44eb-4fe4-ae2e-b91490411bfc}\\HashAlg",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{dc971ee5-44eb-4fe4-ae2e-b91490411bfc}\\ItemSize",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes\\{dc971ee5-44eb-4fe4-ae2e-b91490411bfc}\\SaferFlags",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\UrlZones",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\4096\\Paths",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\4096\\Hashes",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\4096\\UrlZones",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\65536\\Paths",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\65536\\Hashes",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\65536\\UrlZones",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\131072\\Paths",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\131072\\Hashes",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\131072\\UrlZones",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\262144\\Paths",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\262144\\Hashes",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\262144\\UrlZones",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Paths",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\Hashes",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\0\\UrlZones",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\4096\\Paths",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\4096\\Hashes",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\4096\\UrlZones",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\65536\\Paths",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\65536\\Hashes",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\65536\\UrlZones",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\131072\\Paths",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\131072\\Hashes",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\131072\\UrlZones",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\262144\\Paths",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\262144\\Hashes",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\262144\\UrlZones",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\DefaultLevel",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\PolicyScope",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Cache",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\LogFileName",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\System.Windows.Forms.ni.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\shell32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\comctl32.dll",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\AppData",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\COMRes.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\CLBCATQ.DLL",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\xpsp2res.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\MSVCP60.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wbemdisp.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wbemcomn.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wbemprox.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wmiutils.dll",
                        "\\Registry\\Machine\\Software\\Policies\\Microsoft\\System\\DNSclient",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wbemsvc.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DNSAPI.dll",
                        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\DnsClient",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\NETAPI32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WLDAP32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\NTDSAPI.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\fastprox.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SXS.DLL",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\CustomMarshalers.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wminet_utils.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rasman.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rtutils.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\WINMM.dll",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave1",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave2",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave3",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave4",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave5",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave6",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave7",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave8",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\wave9",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi1",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi2",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi3",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi4",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi5",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi6",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi7",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi8",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\midi9",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux1",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux2",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux3",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux4",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux5",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux6",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux7",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux8",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\aux9",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer1",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer2",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer3",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer4",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer5",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer6",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer7",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer8",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32\\mixer9",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\TAPI32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\rasapi32.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\System.Configuration.ni.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\System.Xml.ni.dll",
                        "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Services\\WinSock2\\Parameters",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\WinSock_Registry_Version",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Serial_Access_Num",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\00000007",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Next_Catalog_Entry_ID",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Num_Catalog_Entries",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000001",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000001\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000002",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000002\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000003",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000003\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000004",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000004\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000005",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000005\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000006",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000006\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000007",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000007\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000008",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000008\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000009",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000009\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000010",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000010\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000011",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000011\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000012",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000012\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000013",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000013\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000014",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000014\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000015",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries\\000000000015\\PackedCatalogItem",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Serial_Access_Num",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\00000004",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Num_Catalog_Entries",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001\\LibraryPath",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001\\DisplayString",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001\\ProviderId",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001\\AddressFamily",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001\\SupportedNameSpace",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001\\Enabled",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001\\Version",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000001\\StoresServiceClassInfo",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002\\LibraryPath",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002\\DisplayString",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002\\ProviderId",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002\\AddressFamily",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002\\SupportedNameSpace",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002\\Enabled",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002\\Version",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000002\\StoresServiceClassInfo",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003\\LibraryPath",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003\\DisplayString",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003\\ProviderId",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003\\AddressFamily",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003\\SupportedNameSpace",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003\\Enabled",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003\\Version",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries\\000000000003\\StoresServiceClassInfo",
                        "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Services\\Winsock2\\Parameters",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Ws2_32NumHandleBuckets",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\WinSock2\\Parameters\\Ws2_32SpinCount",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mswsock.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\hnetcfg.dll",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Rpc\\SecurityService\\DefaultAuthLevel",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\Winsock\\Parameters\\Transports",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\Tcpip\\Parameters\\Winsock\\HelperDllName",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wshtcpip.dll",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Rpc\\SecurityService\\10",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Control\\SecurityProviders\\SecurityProviders",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\iphlpapi.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msv1_0.dll",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxySettingsPerUser",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\Tcpip\\Parameters\\Interfaces\\{8C6B73CA-C00B-4864-99FA-12B90E0F122A}\\DhcpServer",
                        "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Services\\Tcpip\\Parameters\\Interfaces\\{8C6B73CA-C00B-4864-99FA-12B90E0F122A}\\NameServer",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Apphelp.dll",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Shutdown.exe",
                        "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Shutdown.exe\\RpcThreadPoolThrottle",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Control Panel\\International\\Calendars\\TwoDigitYearMax",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\NoInternetIcon",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoInternetIcon",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\NoControlPanel",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoControlPanel",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\NoSetFolders",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoSetFolders",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500_CLASSES\\.exe",
                        "\\Registry\\Machine\\Software\\Classes\\.exe",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500_Classes\\.exe",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Hidden",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Personal",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SETUPAPI.dll",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Documents",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Desktop",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Common Desktop",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\shfolder.dll",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders\\Local AppData",
                        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\urlmon.dll",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\",
                        "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Security_HKLM_only",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\",
                        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\",
                        "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges\\",
                        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges\\",
                        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
                    ],
                    "registry_keys_set": [
                        {
                            "key": "\\REGISTRY\\USER\\S-1-5-21-1482476501-1645522239-1417001333-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\xws",
                            "value": "C:\\DOCUME~1\\ADMINI~1\\LOCALS~1\\Temp\\xws\\xws.exe\u0000"
                        }
                    ],
                    "sandbox_name": "Tencent HABO",
                    "services_opened": [
                        "RASMAN"
                    ],
                    "services_started": [
                        "LocalSystem"
                    ],
                    "tags": [
                        "DETECT_DEBUG_ENVIRONMENT"
                    ],
                    "text_highlighted": [
                        "\u786e\u5b9a",
                        "This application requires one of the following versions of the .NET Framework: v4.5",
                        "This application could not be started"
                    ]
                },
                "id": "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_Tencent HABO",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/file_behaviours/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_Tencent HABO"
                },
                "type": "file_behaviour"
            },
            {
                "attributes": {
                    "analysis_date": 1592373137,
                    "behash": "7a12f7e0e2969bd955f19b530f28f1ca",
                    "calls_highlighted": [
                        "GetTickCount",
                        "IsDebuggerPresent"
                    ],
                    "files_copied": [
                        {
                            "destination": "C:\\Users\\<USER>\\AppData\\Local\\Temp\\xws\\xws.exe",
                            "source": "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe"
                        }
                    ],
                    "files_opened": [
                        "C:\\Windows\\SYSTEM32\\MSCOREE.DLL.local",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\mscoreei.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v1.0.3705\\clr.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v1.0.3705\\clr.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v1.0.3705\\mscorwks.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v1.0.3705\\mscorwks.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v1.1.4322\\clr.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v1.1.4322\\clr.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v1.1.4322\\mscorwks.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v1.1.4322\\mscorwks.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\clr.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\clr.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\mscorwks.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\mscorwks.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\clr.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\clr.dll",
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe.config",
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "C:\\Windows\\system32\\VERSION.dll",
                        "C:\\Windows\\system32\\VCRUNTIME140_CLR0400.dll",
                        "C:\\Windows\\system32\\ucrtbase_clr0400.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\config\\machine.config",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\fusion.localgac",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_32\\mscorlib\\v4.0_4.0.0.0__b77a5c561934e089\\mscorlib.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\mscorlib\\",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\mscorlib\\36eaccfde177c2e7b93b8dbdde4e012a\\mscorlib.ni.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\mscorlib\\36eaccfde177c2e7b93b8dbdde4e012a\\mscorlib.ni.dll.aux",
                        "C:\\Users\\",
                        "C:\\Users\\<USER>\\",
                        "C:\\Users\\<USER>\\Downloads\\",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\Po160118\\",
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.INI",
                        "C:\\Windows\\system32\\api-ms-win-core-xstate-l2-1-0.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\clrjit.dll",
                        "C:\\Windows\\assembly\\pubpol24.dat",
                        "C:\\Windows\\assembly\\GAC\\PublisherPolicy.tme",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_32\\Microsoft.VisualBasic\\v4.0_10.0.0.0__b03f5f7f11d50a3a\\Microsoft.VisualBasic.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\Microsoft.VisualBasic\\v4.0_10.0.0.0__b03f5f7f11d50a3a\\Microsoft.VisualBasic.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\Microsoft.V9921e851#\\",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\Microsoft.V9921e851#\\a891970b44db9e340c3ef3efa95b793c\\Microsoft.VisualBasic.ni.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\Microsoft.V9921e851#\\a891970b44db9e340c3ef3efa95b793c\\Microsoft.VisualBasic.ni.dll.aux",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_32\\System\\v4.0_4.0.0.0__b77a5c561934e089\\System.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System\\v4.0_4.0.0.0__b77a5c561934e089\\System.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System\\",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System\\2c3c912ea8f058f9d04c4650128feb3f\\System.ni.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System\\2c3c912ea8f058f9d04c4650128feb3f\\System.ni.dll.aux",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Configuration\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\System.Configuration.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Xml\\v4.0_4.0.0.0__b77a5c561934e089\\System.Xml.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_32\\System.Core\\v4.0_4.0.0.0__b77a5c561934e089\\System.Core.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Core\\v4.0_4.0.0.0__b77a5c561934e089\\System.Core.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Core\\",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Core\\31fae3290fad30c31c98651462d22724\\System.Core.ni.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Core\\31fae3290fad30c31c98651462d22724\\System.Core.ni.dll.aux",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Numerics\\v4.0_4.0.0.0__b77a5c561934e089\\System.Numerics.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Security\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\System.Security.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Windows.Forms\\v4.0_4.0.0.0__b77a5c561934e089\\System.Windows.Forms.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Drawing\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\System.Drawing.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Deployment\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\System.Deployment.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Management\\v4.0_4.0.0.0__b03f5f7f11d50a3a\\System.Management.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Xml.Linq\\v4.0_4.0.0.0__b77a5c561934e089\\System.Xml.Linq.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System.Runtime.Remoting\\v4.0_4.0.0.0__b77a5c561934e089\\System.Runtime.Remoting.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\nlssorting.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\SortDefault.nlp",
                        "C:\\Windows\\system32\\CRYPTSP.dll",
                        "C:\\Windows\\system32\\rsaenh.dll",
                        "C:\\Users\\<USER>\\Downloads\\en-US\\Po160118.resources.dll",
                        "C:\\Users\\<USER>\\Downloads\\en-US\\Po160118.resources\\Po160118.resources.dll",
                        "C:\\Users\\<USER>\\Downloads\\en-US\\Po160118.resources.exe",
                        "C:\\Users\\<USER>\\Downloads\\en-US\\Po160118.resources\\Po160118.resources.exe",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\mscorrc.dll",
                        "C:\\Users\\<USER>\\Downloads\\en\\Po160118.resources.dll",
                        "C:\\Users\\<USER>\\Downloads\\en\\Po160118.resources\\Po160118.resources.dll",
                        "C:\\Users\\<USER>\\Downloads\\en\\Po160118.resources.exe",
                        "C:\\Users\\<USER>\\Downloads\\en\\Po160118.resources\\Po160118.resources.exe",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Drawing\\",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Drawing\\f7568d7f1b9d356f64779b4c0927cfb3\\System.Drawing.ni.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Drawing\\f7568d7f1b9d356f64779b4c0927cfb3\\System.Drawing.ni.dll.aux",
                        "C:\\Windows\\WinSxS\\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.23894_none_5c0be957a009922e",
                        "C:\\Windows\\WinSxS\\x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.23894_none_5c0be957a009922e\\gdiplus.dll",
                        "C:\\Windows\\system32\\WindowsCodecs.dll",
                        "C:\\Users\\<USER>\\AppData\\Local\\Temp\\xws",
                        "C:\\Users\\<USER>\\AppData\\Local\\Temp",
                        "C:\\Users\\<USER>\\AppData\\Local\\Temp\\xws\\xws.exe",
                        "C:\\Windows\\system32\\apphelp.dll",
                        "C:\\Windows\\system32\\RpcRtRemote.dll"
                    ],
                    "has_html_report": true,
                    "has_pcap": true,
                    "last_modification_date": 1592373137,
                    "modules_loaded": [
                        "api-ms-win-core-synch-l1-2-0",
                        "api-ms-win-core-fibers-l1-1-1",
                        "kernel32",
                        "api-ms-win-core-localization-l1-2-1",
                        "ADVAPI32.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\mscoreei.dll",
                        "SHLWAPI.dll",
                        "api-ms-win-appmodel-runtime-l1-1-2.dll",
                        "api-ms-win-appmodel-runtime-l1-1-0.dll",
                        "VERSION.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\clr.dll",
                        "USER32.dll",
                        "api-ms-win-core-quirks-l1-1-0.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\mscoree.dll",
                        "mscoree.dll",
                        "C:\\Windows\\system32\\combase.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\mscorlib\\36eaccfde177c2e7b93b8dbdde4e012a\\mscorlib.ni.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\ole32.dll",
                        "ole32.dll",
                        "api-ms-win-core-xstate-l2-1-0.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\clrjit.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System\\2c3c912ea8f058f9d04c4650128feb3f\\System.ni.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Core\\31fae3290fad30c31c98651462d22724\\System.Core.ni.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\Microsoft.V9921e851#\\a891970b44db9e340c3ef3efa95b793c\\Microsoft.VisualBasic.ni.dll",
                        "kernel32.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\nlssorting.dll",
                        "CRYPTSP.dll",
                        "CRYPTBASE.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\en-US\\mscorrc.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\en\\mscorrc.dll",
                        "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\mscorrc.dll",
                        "C:\\Windows\\assembly\\NativeImages_v4.0.30319_32\\System.Drawing\\f7568d7f1b9d356f64779b4c0927cfb3\\System.Drawing.ni.dll",
                        "gdiplus.dll",
                        "amsi.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System\\v4.0_4.0.0.0__b77a5c561934e089\\ntdll.dll",
                        "ntdll.dll",
                        "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\System\\v4.0_4.0.0.0__b77a5c561934e089\\psapi.dll",
                        "psapi.dll",
                        "API-MS-Win-Security-LSALookup-L1-1-0.dll"
                    ],
                    "processes_created": [
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe"
                    ],
                    "processes_terminated": [
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe"
                    ],
                    "processes_tree": [
                        {
                            "children": [
                                {
                                    "name": "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                                    "process_id": "2840",
                                    "time_offset": 22
                                },
                                {
                                    "name": "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                                    "process_id": "2288",
                                    "time_offset": 20
                                },
                                {
                                    "name": "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                                    "process_id": "2656",
                                    "time_offset": 18
                                },
                                {
                                    "name": "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                                    "process_id": "1472",
                                    "time_offset": 17
                                },
                                {
                                    "name": "C:\\Users\\<USER>\\Downloads\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                                    "process_id": "456",
                                    "time_offset": 16
                                }
                            ],
                            "name": "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                            "process_id": "1992"
                        }
                    ],
                    "registry_keys_opened": [
                        "HKLM\\Software\\Microsoft\\.NETFramework\\Policy",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\Policy\\v4.0",
                        "HKLM\\Software\\Microsoft\\.NETFramework",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\InstallRoot",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\CLRLoadLogDir",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\UseLegacyV2RuntimeActivationPolicyDefaultValue",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\OnlyUseLatestCLR",
                        "HKCU\\Software\\Microsoft\\.NETFramework\\Policy\\Standards",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\Policy\\Standards\\v4.0.30319",
                        "HKLM\\SOFTWARE\\Microsoft\\Fusion",
                        "HKLM\\SOFTWARE\\Microsoft\\Fusion\\NoClientChecks",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\v4.0.30319\\SKUs",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\v4.0.30319\\SKUs\\default",
                        "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full",
                        "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\Release",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\DisableConfigCache",
                        "HKLM\\Software\\Microsoft\\Fusion",
                        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "HKLM\\Software\\Microsoft\\Fusion\\CacheLocation",
                        "HKLM\\Software\\Microsoft\\Fusion\\DownloadCacheQuotaInKB",
                        "HKLM\\Software\\Microsoft\\Fusion\\EnableLog",
                        "HKLM\\Software\\Microsoft\\Fusion\\LoggingLevel",
                        "HKLM\\Software\\Microsoft\\Fusion\\ForceLog",
                        "HKLM\\Software\\Microsoft\\Fusion\\LogFailures",
                        "HKLM\\Software\\Microsoft\\Fusion\\LogResourceBinds",
                        "HKLM\\Software\\Microsoft\\Fusion\\FileInUseRetryAttempts",
                        "HKLM\\Software\\Microsoft\\Fusion\\FileInUseMillisecondsBetweenRetries",
                        "HKLM\\Software\\Microsoft\\Fusion\\UseLegacyIdentityFormat",
                        "HKLM\\Software\\Microsoft\\Fusion\\DisableMSIPeek",
                        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
                        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DevOverrideEnable",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\NGen\\Policy\\v4.0",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\NGen\\Policy\\v4.0\\OptimizeUsedBinaries",
                        "HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\Policy\\Servicing",
                        "HKLM\\Software\\Microsoft\\StrongName",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\FeatureSIMD",
                        "HKLM\\Software\\Microsoft\\.NETFramework\\AltJit",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\Latest",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\index24",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\LegacyPolicyTimeStamp",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.10.0.Microsoft.VisualBasic__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.10.0.Microsoft.VisualBasic__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Configuration__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Configuration__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Xml__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Xml__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Core__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Core__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Numerics__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Numerics__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Security__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Security__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Windows.Forms__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Windows.Forms__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Drawing__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Drawing__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Deployment__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Deployment__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Management__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Management__b03f5f7f11d50a3a",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Xml.Linq__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Xml.Linq__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\v4.0_policy.4.0.System.Runtime.Remoting__b77a5c561934e089",
                        "HKLM\\Software\\Microsoft\\Fusion\\PublisherPolicy\\Default\\policy.4.0.System.Runtime.Remoting__b77a5c561934e089",
                        "HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\Policy\\APTCA",
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Managed\\S-1-5-21-3711686801-687107597-1149503783-1001\\Installer\\Assemblies\\C:|Users|admin|Downloads|699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "HKCU\\Software\\Microsoft\\Installer\\Assemblies\\C:|Users|admin|Downloads|699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "HKLM\\SOFTWARE\\Classes\\Installer\\Assemblies\\C:|Users|admin|Downloads|699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3.exe",
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Managed\\S-1-5-21-3711686801-687107597-1149503783-1001\\Installer\\Assemblies\\Global",
                        "HKCU\\Software\\Microsoft\\Installer\\Assemblies\\Global",
                        "HKLM\\SOFTWARE\\Classes\\Installer\\Assemblies\\Global",
                        "HKLM\\SOFTWARE\\Microsoft\\.NETFramework\\AppContext",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\xws",
                        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
                    ],
                    "registry_keys_set": [
                        {
                            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\xws",
                            "value": "C:\\Users\\<USER>\\AppData\\Local\\Temp\\xws\\xws.exe"
                        }
                    ],
                    "sandbox_name": "VirusTotal Jujubox",
                    "tags": [
                        "DIRECT_CPU_CLOCK_ACCESS",
                        "DETECT_DEBUG_ENVIRONMENT",
                        "RUNTIME_MODULES",
                        "PERSISTENCE"
                    ],
                    "text_highlighted": [
                        "C:\\Windows\\system32\\cmd.exe"
                    ]
                },
                "id": "699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_VirusTotal Jujubox",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/file_behaviours/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_VirusTotal Jujubox"
                },
                "type": "file_behaviour"
            }
        ]
    }
}
```

#### Human Readable Output

>### Sandbox Reports for file hash: 2b294b3499d1cce794badffc959b7618
>|AnalysisDate|LastModificationDate|SandboxName|Link|
>|---|---|---|---|
>| 1558429832 | 1588377117 | Lastline | https://www.virustotal.com/api/v3/file_behaviours/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_Lastline |
>| 1561405459 | 1563272815 | SNDBOX | https://www.virustotal.com/api/v3/file_behaviours/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_SNDBOX |
>| 1601545446 | 1601545448 | Tencent HABO | https://www.virustotal.com/api/v3/file_behaviours/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_Tencent HABO |
>| 1592373137 | 1592373137 | VirusTotal Jujubox | https://www.virustotal.com/api/v3/file_behaviours/699ec052ecc898bdbdafea0027c4ab44c3d01ae011c17745dd2b7fbddaa077f3_VirusTotal Jujubox |


### vt-passive-dns-data
***
Returns passive DNS records by indicator.


#### Base Command

`vt-passive-dns-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP for which to get its DNS data. | Required | 
| limit | Maximum number of results to fetch. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.PassiveDNS.attributes.date | Number | Date of the DNS analysis in epoch format. | 
| VirusTotal.PassiveDNS.attributes.host_name | String | The DNS host name. | 
| VirusTotal.PassiveDNS.attributes.ip_address | String | The DNS IP address. | 
| VirusTotal.PassiveDNS.attributes.resolver | String | The name of the resolver. | 
| VirusTotal.PassiveDNS.id | String | The ID of the resolution. | 
| VirusTotal.PassiveDNS.links.self | String | The link to the resolution. | 
| VirusTotal.PassiveDNS.type | String | The type of the resolution. | 


#### Command Example
```!vt-passive-dns-data ip=1.1.1.1```

#### Context Example
```json
{
    "VirusTotal": {
        "PassiveDNS": [
            {
                "attributes": {
                    "date": 1617085962,
                    "host_name": "muhaha.xyz",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1muhaha.xyz",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1muhaha.xyz"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617085950,
                    "host_name": "video.sldlcdn.com",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1video.sldlcdn.com",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1video.sldlcdn.com"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617085674,
                    "host_name": "star.rqbao.com",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1star.rqbao.com",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1star.rqbao.com"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617084497,
                    "host_name": "latitude.financial",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1latitude.financial",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1latitude.financial"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617083613,
                    "host_name": "jy.saas.sainandianqi01.cn",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1jy.saas.sainandianqi01.cn",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1jy.saas.sainandianqi01.cn"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617083586,
                    "host_name": "itech.men",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1itech.men",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1itech.men"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617073360,
                    "host_name": "stephanievignery.com",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1stephanievignery.com",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1stephanievignery.com"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617073314,
                    "host_name": "gandicellular.blogspot.com.mythem.es",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1gandicellular.blogspot.com.mythem.es",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1gandicellular.blogspot.com.mythem.es"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617069938,
                    "host_name": "cuuiallvf18.com",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1cuuiallvf18.com",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1cuuiallvf18.com"
                },
                "type": "resolution"
            },
            {
                "attributes": {
                    "date": 1617068286,
                    "host_name": "cpanel.salonmanager.hu",
                    "ip_address": "1.1.1.1",
                    "resolver": "VirusTotal"
                },
                "id": "1.1.1.1cpanel.salonmanager.hu",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/resolutions/1.1.1.1cpanel.salonmanager.hu"
                },
                "type": "resolution"
            }
        ]
    }
}
```

#### Human Readable Output

>### Passive DNS data for IP 1.1.1.1
>|Id|Date|HostName|IpAddress|Resolver|
>|---|---|---|---|---|
>| 1.1.1.1muhaha.xyz | 1617085962 | muhaha.xyz | 1.1.1.1 | VirusTotal |
>| 1.1.1.1video.sldlcdn.com | 1617085950 | video.sldlcdn.com | 1.1.1.1 | VirusTotal |
>| 1.1.1.1star.rqbao.com | 1617085674 | star.rqbao.com | 1.1.1.1 | VirusTotal |
>| 1.1.1.1latitude.financial | 1617084497 | latitude.financial | 1.1.1.1 | VirusTotal |
>| 1.1.1.1jy.saas.sainandianqi01.cn | 1617083613 | jy.saas.sainandianqi01.cn | 1.1.1.1 | VirusTotal |
>| 1.1.1.1itech.men | 1617083586 | itech.men | 1.1.1.1 | VirusTotal |
>| 1.1.1.1stephanievignery.com | 1617073360 | stephanievignery.com | 1.1.1.1 | VirusTotal |
>| 1.1.1.1gandicellular.blogspot.com.mythem.es | 1617073314 | gandicellular.blogspot.com.mythem.es | 1.1.1.1 | VirusTotal |
>| 1.1.1.1cuuiallvf18.com | 1617069938 | cuuiallvf18.com | 1.1.1.1 | VirusTotal |
>| 1.1.1.1cpanel.salonmanager.hu | 1617068286 | cpanel.salonmanager.hu | 1.1.1.1 | VirusTotal |


### vt-analysis-get
***
Retrieves resolutions of the given IP.


#### Base Command

`vt-analysis-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the analysis (from file-scan, file-rescan, or url-scan). | Required | 
| extended_data | Whether to return extended data (last_analysis_results). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Analysis.data.attributes.date | Number | Date of the analysis in epoch format. | 
| VirusTotal.Analysis.data.attributes.stats.harmless | Number | Number of engines that found the indicator to be harmless. | 
| VirusTotal.Analysis.data.attributes.stats.malicious | Number | Number of engines that found the indicator to be malicious. | 
| VirusTotal.Analysis.data.attributes.stats.suspicious | Number | Number of engines that found the indicator to be suspicious. | 
| VirusTotal.Analysis.data.attributes.stats.timeout | Number | he number of engines that timed out for the indicator. | 
| VirusTotal.Analysis.data.attributes.stats.undetected | Number | Number of engines the found the indicator to be undetected. | 
| VirusTotal.Analysis.data.attributes.status | String | Status of the analysis. | 
| VirusTotal.Analysis.data.id | String | ID of the analysis. | 
| VirusTotal.Analysis.data.type | String | Type of object \(analysis\). | 
| VirusTotal.Analysis.meta.file_info.sha256 | String | SHA-256 hash of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.file_info.sha1 | String | SHA-1 hash of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.file_info.md5 | String | MD5 hash of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.file_info.name | unknown | Name of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.file_info.size | String | Size of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.url_info.id | String | ID of the url \(if it is a URL\). | 
| VirusTotal.Analysis.meta.url_info.url | String | The URL \(if it is a URL\). | 
| VirusTotal.Analysis.id | String | The analysis ID. | 


#### Command Example
```!vt-analysis-get id=u-20694f234fbac92b1dcc16f424aa1c85e9dd7af75b360745df6484dcae410853-1613980758```

#### Context Example
```json
{
    "VirusTotal": {
        "Analysis": {
            "data": {
                "attributes": {
                    "date": 1613980758,
                    "results": {
                        "ADMINUSLabs": {
                            "category": "harmless",
                            "engine_name": "ADMINUSLabs",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "AICC (MONITORAPP)": {
                            "category": "harmless",
                            "engine_name": "AICC (MONITORAPP)",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "AegisLab WebGuard": {
                            "category": "harmless",
                            "engine_name": "AegisLab WebGuard",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "AlienVault": {
                            "category": "harmless",
                            "engine_name": "AlienVault",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Antiy-AVL": {
                            "category": "malicious",
                            "engine_name": "Antiy-AVL",
                            "method": "blacklist",
                            "result": "malicious"
                        },
                        "Armis": {
                            "category": "harmless",
                            "engine_name": "Armis",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Artists Against 419": {
                            "category": "harmless",
                            "engine_name": "Artists Against 419",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "AutoShun": {
                            "category": "malicious",
                            "engine_name": "AutoShun",
                            "method": "blacklist",
                            "result": "malicious"
                        },
                        "Avira": {
                            "category": "harmless",
                            "engine_name": "Avira",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "BADWARE.INFO": {
                            "category": "harmless",
                            "engine_name": "BADWARE.INFO",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Baidu-International": {
                            "category": "harmless",
                            "engine_name": "Baidu-International",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "BitDefender": {
                            "category": "harmless",
                            "engine_name": "BitDefender",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "BlockList": {
                            "category": "harmless",
                            "engine_name": "BlockList",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Blueliv": {
                            "category": "harmless",
                            "engine_name": "Blueliv",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "CINS Army": {
                            "category": "harmless",
                            "engine_name": "CINS Army",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "CLEAN MX": {
                            "category": "harmless",
                            "engine_name": "CLEAN MX",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "CMC Threat Intelligence": {
                            "category": "harmless",
                            "engine_name": "CMC Threat Intelligence",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "CRDF": {
                            "category": "malicious",
                            "engine_name": "CRDF",
                            "method": "blacklist",
                            "result": "malicious"
                        },
                        "Certego": {
                            "category": "harmless",
                            "engine_name": "Certego",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Comodo Valkyrie Verdict": {
                            "category": "undetected",
                            "engine_name": "Comodo Valkyrie Verdict",
                            "method": "blacklist",
                            "result": "unrated"
                        },
                        "CyRadar": {
                            "category": "harmless",
                            "engine_name": "CyRadar",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Cyan": {
                            "category": "undetected",
                            "engine_name": "Cyan",
                            "method": "blacklist",
                            "result": "unrated"
                        },
                        "CyberCrime": {
                            "category": "harmless",
                            "engine_name": "CyberCrime",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Cyren": {
                            "category": "harmless",
                            "engine_name": "Cyren",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "DNS8": {
                            "category": "harmless",
                            "engine_name": "DNS8",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Dr.Web": {
                            "category": "malicious",
                            "engine_name": "Dr.Web",
                            "method": "blacklist",
                            "result": "malicious"
                        },
                        "ESET": {
                            "category": "harmless",
                            "engine_name": "ESET",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "EmergingThreats": {
                            "category": "harmless",
                            "engine_name": "EmergingThreats",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Emsisoft": {
                            "category": "harmless",
                            "engine_name": "Emsisoft",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "EonScope": {
                            "category": "harmless",
                            "engine_name": "EonScope",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Feodo Tracker": {
                            "category": "harmless",
                            "engine_name": "Feodo Tracker",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Forcepoint ThreatSeeker": {
                            "category": "harmless",
                            "engine_name": "Forcepoint ThreatSeeker",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Fortinet": {
                            "category": "malicious",
                            "engine_name": "Fortinet",
                            "method": "blacklist",
                            "result": "malware"
                        },
                        "FraudScore": {
                            "category": "harmless",
                            "engine_name": "FraudScore",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "G-Data": {
                            "category": "harmless",
                            "engine_name": "G-Data",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Google Safebrowsing": {
                            "category": "harmless",
                            "engine_name": "Google Safebrowsing",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "GreenSnow": {
                            "category": "harmless",
                            "engine_name": "GreenSnow",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Hoplite Industries": {
                            "category": "harmless",
                            "engine_name": "Hoplite Industries",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "IPsum": {
                            "category": "harmless",
                            "engine_name": "IPsum",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "K7AntiVirus": {
                            "category": "harmless",
                            "engine_name": "K7AntiVirus",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Kaspersky": {
                            "category": "malicious",
                            "engine_name": "Kaspersky",
                            "method": "blacklist",
                            "result": "malware"
                        },
                        "Lumu": {
                            "category": "undetected",
                            "engine_name": "Lumu",
                            "method": "blacklist",
                            "result": "unrated"
                        },
                        "MalBeacon": {
                            "category": "harmless",
                            "engine_name": "MalBeacon",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "MalSilo": {
                            "category": "harmless",
                            "engine_name": "MalSilo",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Malware Domain Blocklist": {
                            "category": "harmless",
                            "engine_name": "Malware Domain Blocklist",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "MalwareDomainList": {
                            "category": "harmless",
                            "engine_name": "MalwareDomainList",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "MalwarePatrol": {
                            "category": "harmless",
                            "engine_name": "MalwarePatrol",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Malwared": {
                            "category": "harmless",
                            "engine_name": "Malwared",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Netcraft": {
                            "category": "undetected",
                            "engine_name": "Netcraft",
                            "method": "blacklist",
                            "result": "unrated"
                        },
                        "NotMining": {
                            "category": "undetected",
                            "engine_name": "NotMining",
                            "method": "blacklist",
                            "result": "unrated"
                        },
                        "Nucleon": {
                            "category": "harmless",
                            "engine_name": "Nucleon",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "OpenPhish": {
                            "category": "harmless",
                            "engine_name": "OpenPhish",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "PREBYTES": {
                            "category": "harmless",
                            "engine_name": "PREBYTES",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "PhishLabs": {
                            "category": "undetected",
                            "engine_name": "PhishLabs",
                            "method": "blacklist",
                            "result": "unrated"
                        },
                        "Phishing Database": {
                            "category": "harmless",
                            "engine_name": "Phishing Database",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Phishtank": {
                            "category": "harmless",
                            "engine_name": "Phishtank",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Quick Heal": {
                            "category": "harmless",
                            "engine_name": "Quick Heal",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Quttera": {
                            "category": "harmless",
                            "engine_name": "Quttera",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Rising": {
                            "category": "harmless",
                            "engine_name": "Rising",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "SCUMWARE.org": {
                            "category": "harmless",
                            "engine_name": "SCUMWARE.org",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Sangfor": {
                            "category": "harmless",
                            "engine_name": "Sangfor",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "SecureBrain": {
                            "category": "harmless",
                            "engine_name": "SecureBrain",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Snort IP sample list": {
                            "category": "harmless",
                            "engine_name": "Snort IP sample list",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Sophos": {
                            "category": "malicious",
                            "engine_name": "Sophos",
                            "method": "blacklist",
                            "result": "malicious"
                        },
                        "Spam404": {
                            "category": "harmless",
                            "engine_name": "Spam404",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Spamhaus": {
                            "category": "harmless",
                            "engine_name": "Spamhaus",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "StopBadware": {
                            "category": "undetected",
                            "engine_name": "StopBadware",
                            "method": "blacklist",
                            "result": "unrated"
                        },
                        "StopForumSpam": {
                            "category": "harmless",
                            "engine_name": "StopForumSpam",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Sucuri SiteCheck": {
                            "category": "harmless",
                            "engine_name": "Sucuri SiteCheck",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Tencent": {
                            "category": "harmless",
                            "engine_name": "Tencent",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "ThreatHive": {
                            "category": "harmless",
                            "engine_name": "ThreatHive",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Threatsourcing": {
                            "category": "harmless",
                            "engine_name": "Threatsourcing",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Trustwave": {
                            "category": "harmless",
                            "engine_name": "Trustwave",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "URLhaus": {
                            "category": "harmless",
                            "engine_name": "URLhaus",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "VX Vault": {
                            "category": "harmless",
                            "engine_name": "VX Vault",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Virusdie External Site Scan": {
                            "category": "harmless",
                            "engine_name": "Virusdie External Site Scan",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Web Security Guard": {
                            "category": "harmless",
                            "engine_name": "Web Security Guard",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "Yandex Safebrowsing": {
                            "category": "harmless",
                            "engine_name": "Yandex Safebrowsing",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "ZeroCERT": {
                            "category": "harmless",
                            "engine_name": "ZeroCERT",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "desenmascara.me": {
                            "category": "harmless",
                            "engine_name": "desenmascara.me",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "malwares.com URL checker": {
                            "category": "harmless",
                            "engine_name": "malwares.com URL checker",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "securolytics": {
                            "category": "harmless",
                            "engine_name": "securolytics",
                            "method": "blacklist",
                            "result": "clean"
                        },
                        "zvelo": {
                            "category": "harmless",
                            "engine_name": "zvelo",
                            "method": "blacklist",
                            "result": "clean"
                        }
                    },
                    "stats": {
                        "harmless": 69,
                        "malicious": 7,
                        "suspicious": 0,
                        "timeout": 0,
                        "undetected": 7
                    },
                    "status": "completed"
                },
                "id": "u-20694f234fbac92b1dcc16f424aa1c85e9dd7af75b360745df6484dcae410853-1613980758",
                "links": {
                    "self": "https://www.virustotal.com/api/v3/analyses/u-20694f234fbac92b1dcc16f424aa1c85e9dd7af75b360745df6484dcae410853-1613980758"
                },
                "type": "analysis"
            },
            "id": "u-20694f234fbac92b1dcc16f424aa1c85e9dd7af75b360745df6484dcae410853-1613980758",
            "meta": {
                "url_info": {
                    "id": "20694f234fbac92b1dcc16f424aa1c85e9dd7af75b360745df6484dcae410853"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Analysis results:
>|Id|Stats|Status|
>|---|---|---|
>| u-20694f234fbac92b1dcc16f424aa1c85e9dd7af75b360745df6484dcae410853-1613980758 | harmless: 69<br/>malicious: 7<br/>suspicious: 0<br/>undetected: 7<br/>timeout: 0 | completed |

