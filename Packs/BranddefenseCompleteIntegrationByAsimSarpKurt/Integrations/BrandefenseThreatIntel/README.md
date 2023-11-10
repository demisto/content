Analyzes suspicious hashes, URLs, domains, and IP addresses.
## Configure Brandefense Threat Intel on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Brandefense Threat Intel.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key (leave empty. Fill in the API key in the password field.) |  | True |
    | API Key |  | True |
    | Brandefense API Server URL | Brandefense API Server URL | True |
    | Company Website URL | Company Website URL | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.

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
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | unknown | Bad MD5 hash. | 
| File.SHA1 | unknown | Bad SHA1 hash. | 
| File.SHA256 | unknown | Bad SHA256 hash. | 
| File.Relationships.EntityA | string | The source of the relationship. | 
| File.Relationships.EntityB | string | The destination of the relationship. | 
| File.Relationships.Relationship | string | The name of the relationship. | 
| File.Relationships.EntityAType | string | The type of the source of the relationship. | 
| File.Relationships.EntityBType | string | The type of the destination of the relationship. | 
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

### ip

***
Checks the reputation of an IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required | 
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | unknown | Bad IP address. | 
| IP.ASN | unknown | Bad IP ASN. | 
| IP.Geo.Country | unknown | Bad IP country. | 
| IP.Relationships.EntityA | string | The source of the relationship. | 
| IP.Relationships.EntityB | string | The destination of the relationship. | 
| IP.Relationships.Relationship | string | The name of the relationship. | 
| IP.Relationships.EntityAType | string | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. | 
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

### url

***
Checks the reputation of a URL.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL to check. | Required | 
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | unknown | Bad URLs found. | 
| URL.Malicious.Vendor | unknown | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | unknown | For malicious URLs, the reason that the vendor made the decision. | 
| URL.Relationships.EntityA | string | The source of the relationship. | 
| URL.Relationships.EntityB | string | The destination of the relationship. | 
| URL.Relationships.Relationship | string | The name of the relationship. | 
| URL.Relationships.EntityAType | string | The type of the source of the relationship. | 
| URL.Relationships.EntityBType | string | The type of the destination of the relationship. | 
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

### domain

***
Checks the reputation of a domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name to check. | Required | 
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Bad domain found. | 
| Domain.Malicious.Vendor | unknown | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | unknown | For malicious domains, the reason that the vendor made the decision. | 
| Domain.Relationships.EntityA | string | The source of the relationship. | 
| Domain.Relationships.EntityB | string | The destination of the relationship. | 
| Domain.Relationships.Relationship | string | The name of the relationship. | 
| Domain.Relationships.EntityAType | string | The type of the source of the relationship. | 
| Domain.Relationships.EntityBType | string | The type of the destination of the relationship. | 
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
