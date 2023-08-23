Analyzes suspicious hashes, URLs, domains, and IP addresses.
This integration was integrated and tested with version v3 of VirusTotal (API v3)

## Configure VirusTotal (API v3) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for VirusTotal (API v3).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key (leave empty. Fill in the API key in the password field.) |  | True |
    | API Key |  | True |
    | Source Reliability | Reliability of the source providing the intelligence data | False |
    | Premium Subscription |  | False |
    | File Threshold. Minimum number of positive results from VT scanners to consider the file malicious. |  | False |
    | IP Threshold. Minimum number of positive results from VT scanners to consider the IP malicious. |  | False |
    | Disable reputation lookups for private IP addresses | To reduce the number of lookups made to the VT API, this option can be selected to gracefully skip enrichment of any private IP addresses as defined in RFC1918. | False |
    | URL Threshold. Minimum number of positive results from VT scanners to consider the URL malicious. |  | False |
    | Domain Threshold. Minimum number of positive results from VT scanners to consider the domain malicious. |  | False |
    | Preferred Vendors List. CSV list of vendors who are considered more trustworthy. |  | False |
    | Preferred Vendor Threshold. The minimum number of highly trusted vendors required to consider a domain, IP address, URL, or file as malicious.  |  | False |
    | Enable score analyzing by Crowdsourced Yara Rules, Sigma, and IDS |  | False |
    | Crowdsourced Yara Rules Threshold |  | False |
    | Sigma and Intrusion Detection Rules Threshold |  | False |
    | Domain Popularity Ranking Threshold |  | False |
    | Premium Subscription Only: Relationship Files Threshold |  | False |
    | IP Relationships | Select the list of relationships to retrieve from the API. Note that relationships that are signed with \* key are available only for the VirusTotal premium API key. | False |
    | Domain Relationships | Select the list of relationships to retrieve from the API. Note that relationships that are signed with \* key are available only for the VirusTotal premium API key. | False |
    | URL Relationships | Select the list of relationships to retrieve from the API. Note that relationships that are signed with \* key are available only for the VirusTotal premium API key. | False |
    | File Relationships | Select the list of relationships to retrieve from the API. Note that relationships that are signed with \* key are available only for the VirusTotal premium API key. | False |
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
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 

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
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
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
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 
| override_private_lookup | When set to "true", enrichment of private IP address will be conducted even if it has been disabled at the integration level. Possible values are: true, false. | Optional | 

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
| IP.ASOwner | String | The autonomous system owner of the IP. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
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
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 

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
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 
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
| extended_data | Whether to return extended data (last_analysis_results). Possible values are: true, false. | Optional | 

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
| VirusTotal.Submission.Size | String | Size of the file. | 
| VirusTotal.Submission.Type | String | The type of the submission \(analysis\). | 

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
### vt-comments-get

***
Retrieves comments for a given resource.

#### Base Command

`vt-comments-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The file hash (MD5, SHA1, orSHA256), Domain, URL or IP on which you're commenting on. If not supplied, will try to determine if it's a hash or a url. | Required | 
| resource_type | The type of the resource on which you're commenting. If not supplied, will determine if it's a url or a file. Possible values are: ip, url, domain, file, hash. | Optional | 
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

### vt-passive-dns-data

***
Returns passive DNS records by indicator.

#### Base Command

`vt-passive-dns-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | IP or domain for which to get its DNS data. | Optional | 
| ip | IP for which to get its DNS data. | Optional | 
| domain | Domain for which to get its DNS data. | Optional | 
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

### vt-analysis-get

***
Get analysis of a file submitted to VirusTotal.

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
| VirusTotal.Analysis.meta.file_info.size | Number | Size of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.url_info.id | String | ID of the url \(if it is a URL\). | 
| VirusTotal.Analysis.meta.url_info.url | String | The URL \(if it is a URL\). | 
| VirusTotal.Analysis.id | String | The analysis ID. | 

### vt-file-sigma-analysis

***
Result of the last Sigma analysis in markdown format.

#### Base Command

`vt-file-sigma-analysis`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash (md5, sha1, sha256). | Required | 
| only_stats | Print only Sigma analysis summary stats. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.SigmaAnalysis.data.attributes.last_modification_date | Number | Date of the last update in epoch format. | 
| VirusTotal.SigmaAnalysis.data.attributes.analysis_date | Number | Date of the last update in epoch format. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.rule_matches.match_context | String | Matched strings from the log file. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.rule_matches.rule_author | String | Rule authors separated by commas. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.rule_matches.rule_description | String | Brief summary about what the rule detects. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.rule_matches.rule_id | String | Rule ID in VirusTotal's database. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.rule_matches.rule_level | String | Rule severity. Can be "low", "medium", "high" or "critical". | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.rule_matches.rule_source | String | Ruleset where the rule belongs. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.rule_matches.rule_title | String | Rule title. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.severity_stats.critical | Number | Number of matched rules having a "critical" severity. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.severity_stats.high | Number | Number of matched rules having a "high" severity. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.severity_stats.low | Number | Number of matched rules having a "low" severity. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.severity_stats.medium | Number | Number of matched rules having a "medium" severity. | 
| VirusTotal.SigmaAnalysis.data.attributes.stats.source_severity_stats | unknown | Same as severity_stats but grouping stats by ruleset. Keys are ruleset names as string and values are stats in a dictionary. | 
| VirusTotal.SigmaAnalysis.data.id | String | ID of the analysis. | 

### vt-privatescanning-file

***
Checks the file reputation of the specified private hash.

#### Base Command

`vt-privatescanning-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports MD5, SHA1, and SHA256. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.File.attributes.type_description | String | Description of the type of the file. | 
| VirusTotal.File.attributes.tlsh | String | The locality-sensitive hashing. | 
| VirusTotal.File.attributes.exiftool.MIMEType | String | MIME type of the file. | 
| VirusTotal.File.attributes.names | String | Names of the file. | 
| VirusTotal.File.attributes.javascript_info.tags | String | Tags of the JavaScript. | 
| VirusTotal.File.attributes.exiftool.FileType | String | The file type. | 
| VirusTotal.File.attributes.exiftool.WordCount | Number | Total number of words in the file. | 
| VirusTotal.File.attributes.exiftool.LineCount | Number | Total number of lines in file. | 
| VirusTotal.File.attributes.exiftool.MIMEEncoding | String | The MIME encoding. | 
| VirusTotal.File.attributes.exiftool.FileTypeExtension | String | The file type extension. | 
| VirusTotal.File.attributes.exiftool.Newlines | Number | Number of newlines signs. | 
| VirusTotal.File.attributes.crowdsourced_ids_stats.info | Number | Number of IDS that marked the file as "info". | 
| VirusTotal.File.attributes.crowdsourced_ids_stats.high | Number | Number of IDS that marked the file as "high". | 
| VirusTotal.File.attributes.crowdsourced_ids_stats.medium | Number | Number of IDS that marked the file as "medium". | 
| VirusTotal.File.attributes.crowdsourced_ids_stats.low | Number | Number of IDS that marked the file as "low". | 
| VirusTotal.File.attributes.trid.file_type | String | The TrID file type. | 
| VirusTotal.File.attributes.trid.probability | Number | The TrID probability. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.description | String | Description of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.source | String | Source of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.author | String | Author of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.ruleset_name | String | Rule set name of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.rule_name | String | Name of the YARA rule. | 
| VirusTotal.File.attributes.crowdsourced_yara_results.ruleset_id | String | ID of the YARA rule. | 
| VirusTotal.File.attributes.names | String | Name of the file. | 
| VirusTotal.File.attributes.type_tag | String | Tag of the type. | 
| VirusTotal.File.attributes.size | Number | Size of the file. | 
| VirusTotal.File.attributes.sha256 | String | SHA-256 hash of the file. | 
| VirusTotal.File.attributes.type_extension | String | Extension of the type. | 
| VirusTotal.File.attributes.tags | String | File tags. | 
| VirusTotal.File.attributes.last_analysis_date | Number | Last analysis date in epoch format. | 
| VirusTotal.File.attributes.ssdeep | String | SSDeep hash of the file. | 
| VirusTotal.File.attributes.md5 | String | MD5 hash of the file. | 
| VirusTotal.File.attributes.sha1 | String | SHA-1 hash of the file. | 
| VirusTotal.File.attributes.magic | String | Identification of file by the magic number. | 
| VirusTotal.File.attributes.meaningful_name | String | Meaningful name of the file. | 
| VirusTotal.File.attributes.threat_severity.threat_severity_level | String | Threat severity level of the file. | 
| VirusTotal.File.attributes.threat_severity.threat_severity_data.popular_threat_category | String | Popular threat category of the file. | 
| VirusTotal.File.attributes.threat_verdict | String | Threat verdict of the file. | 
| VirusTotal.File.type | String | Type of the file. | 
| VirusTotal.File.id | String | ID of the file. | 
| VirusTotal.File.links.self | String | Link to the response. | 

### vt-privatescanning-file-scan

***
Submits a file for private scanning. Use the vt-privatescanning-analysis-get command to get the scan results.

#### Base Command

`vt-privatescanning-file-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | The file entry ID to submit. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Submission.type | String | The type of the submission \(analysis\). | 
| VirusTotal.Submission.id | String | The ID of the submission. | 
| VirusTotal.Submission.EntryID | String | The entry ID of the file detonated. | 
| VirusTotal.Submission.Extension | String | File extension. | 
| VirusTotal.Submission.Info | String | File info. | 
| VirusTotal.Submission.MD5 | String | MD5 hash of the file. | 
| VirusTotal.Submission.Name | String | Name of the file. | 
| VirusTotal.Submission.SHA1 | String | SHA-1 of the file. | 
| VirusTotal.Submission.SHA256 | String | SHA-256 of the file. | 
| VirusTotal.Submission.SHA512 | String | SHA-512 of the file. | 
| VirusTotal.Submission.SSDeep | String | SSDeep of the file. | 
| VirusTotal.Submission.Size | String | Size of the file. | 
| VirusTotal.Submission.Type | String | Type of the file. | 

### vt-privatescanning-analysis-get

***
Get analysis of a private file submitted to VirusTotal.

#### Base Command

`vt-privatescanning-analysis-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the analysis. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VirusTotal.Analysis.data.attributes.date | Number | Date of the analysis in epoch format. | 
| VirusTotal.Analysis.data.attributes.status | String | Status of the analysis. | 
| VirusTotal.Analysis.data.attributes.threat_severity_level | String | Threat severity level of the private file. | 
| VirusTotal.Analysis.data.attributes.popular_threat_category | String | Popular threat category of the private file. | 
| VirusTotal.Analysis.data.attributes.threat_verdict | String | Threat verdict of the private file. | 
| VirusTotal.Analysis.data.id | String | ID of the analysis. | 
| VirusTotal.Analysis.data.type | String | Type of object \(analysis\). | 
| VirusTotal.Analysis.meta.file_info.sha256 | String | SHA-256 hash of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.file_info.sha1 | String | SHA-1 hash of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.file_info.md5 | String | MD5 hash of the file \(if it is a file\). | 
| VirusTotal.Analysis.meta.file_info.size | Number | Size of the file \(if it is a file\). | 
| VirusTotal.Analysis.id | String | The analysis ID. | 
