Enrich a file using one or more integrations.

- Provide threat information
- Determine file reputation using the !file command

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* File Enrichment - Virus Total (API v3)

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

* file
* cylance-protect-get-threat

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| MD5 | File MD5 hash to enrich. | File.MD5 | Optional |
| SHA256 | The file SHA256 hash to enrich. | File.SHA256 | Optional |
| SHA1 | The file SHA1 hash to enrich. | File.SHA1 | Optional |
| UseReputationCommand | Define if you would like to use the \!file command.<br/>Note: This input should be used whenever there is no auto-extract enabled in the investigation flow.<br/>Possible values: True / False. | False | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator that was tested. | string |
| DBotScore.Type | The indicator type. | string |
| File.SHA1 | SHA1 hash of the file. | string |
| File.SHA256 | SHA256 hash of the file. | string |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision. | string |
| File.MD5 | MD5 hash of the file. | string |
| DBotScore | The DBotScore object. | unknown |
| File | The file object | unknown |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| File.Malicious.Description | The reason the vendor decided the file was malicious. | string |
| File.Name | The name of the threat. | string |
| File.MalwareFamily | The file family classification. | string |
| File.AutoRun | Indicates if the file is set to automatically run on system startup. | string |
| File.AvIndustry | The score provided by the Anti-Virus industry. | string |
| File.CertIssuer | The ID for the certificate issuer. | string |
| File.CertPublisher | The ID for the certificate publisher. | string |
| File.CertTimestamp | The date and time \(in UTC\) when the file was signed using the certificate. | string |
| File.Classification | The threat classification for the threat. | string |
| File.CylanceScore | The Cylance Score assigned to the threat. | string |
| File.DetectedBy | The name of the Cylance module that detected the threat. | string |
| File.FileSize | The size of the file. | string |
| File.GlobalQuarantine | Identifies if the threat is on the Global Quarantine list. | string |
| File.Running | Identifies if the threat is executing, or another executable loaded or called it. | string |
| File.Safelisted | Identifies if the threat is on the Safe List. | string |
| File.Signed | Identifies the file as signed or not signed. | string |
| File.SubClassification | The threat sub-classification for the threat. | string |
| File.UniqueToCylance | Whether the threat was identified by Cylance, and not by other anti-virus sources. | string |
| File.Relationships.EntityA | The source of the relationship. | String |
| File.Relationships.EntityB | The destination of the relationship. | String |
| File.Relationships.Relationship | The name of the relationship. | String |
| File.Relationships.EntityAtype | The type of the source of the relationship. | String |
| File.Relationships.EntityBtype | The type of the destination of the relationship. | String |
| File.Malicious.TotalEngines | For malicious files, the total number of engines that checked the file hash. | Unknown |
| DBotScore.Reliability | Reliability of the source providing the intelligence data. | String |
| VirusTotal.File.attributes.type_description | description of the type of the file. | String |
| VirusTotal.File.attributes.tlsh | The locality-sensitive hashing. | String |
| VirusTotal.File.attributes.names | Names of the file. | String |
| VirusTotal.File.attributes.last_modification_date | The last modification date in epoch format. | Number |
| VirusTotal.File.attributes.type_tag | Tag of the type. | String |
| VirusTotal.File.attributes.size | Size of the file. | Number |
| VirusTotal.File.attributes.times_submitted | Number of times the file was submitted. | Number |
| VirusTotal.File.attributes.last_submission_date | Last submission date in epoch format. | Number |
| VirusTotal.File.attributes.downloadable | Whether the file is downloadable. | Boolean |
| VirusTotal.File.attributes.sha256 | SHA-256 hash of the file. | String |
| VirusTotal.File.attributes.type_extension | Extension of the type. | String |
| VirusTotal.File.attributes.tags | File tags. | String |
| VirusTotal.File.attributes.last_analysis_date | Last analysis date in epoch format. | Number |
| VirusTotal.File.attributes.unique_sources | Unique sources. | Number |
| VirusTotal.File.attributes.first_submission_date | First submission date in epoch format. | Number |
| VirusTotal.File.attributes.ssdeep | SSDeep hash of the file. | String |
| VirusTotal.File.attributes.md5 | MD5 hash of the file. | String |
| VirusTotal.File.attributes.sha1 | SHA-1 hash of the file. | String |
| VirusTotal.File.attributes.magic | Identification of file by the magic number. | String |
| VirusTotal.File.attributes.meaningful_name | Meaningful name of the file. | String |
| VirusTotal.File.attributes.reputation | The reputation of the file. | Number |
| VirusTotal.File.attributes.exiftool.MIMEtype | MIME type of the file. | String |
| VirusTotal.File.attributes.exiftool.Filetype | The file type. | String |
| VirusTotal.File.attributes.exiftool.WordCount | Total number of words in the file. | String |
| VirusTotal.File.attributes.exiftool.LineCount | Total number of lines in file. | String |
| VirusTotal.File.attributes.exiftool.MIMEEncoding | The MIME encoding. | String |
| VirusTotal.File.attributes.exiftool.FiletypeExtension | The file type extension. | String |
| VirusTotal.File.attributes.exiftool.Newlines | Number of newlines signs. | String |
| VirusTotal.File.attributes.javascript_info.tags | Tags of the JavaScript. | String |
| VirusTotal.File.attributes.crowdsourced_ids_stats.info | Number of IDS that marked the file as "info". | Number |
| VirusTotal.File.attributes.crowdsourced_ids_stats.high | Number of IDS that marked the file as "high". | Number |
| VirusTotal.File.attributes.crowdsourced_ids_stats.medium | Number of IDS that marked the file as "medium". | Number |
| VirusTotal.File.attributes.crowdsourced_ids_stats.low | Number of IDS that marked the file as "low". | Number |
| VirusTotal.File.attributes.sigma_analysis_stats.critical | Number of Sigma analysis that marked the file as "critical". | Number |
| VirusTotal.File.attributes.sigma_analysis_stats.high | Number of Sigma analysis that marked the file as "high". | Number |
| VirusTotal.File.attributes.sigma_analysis_stats.medium | Number of Sigma analysis that marked the file as "medium". | Number |
| VirusTotal.File.attributes.sigma_analysis_stats.low | Number of Sigma analysis that marked the file as "low". | Number |
| VirusTotal.File.attributes.trid.file_type | The TrID file type. | String |
| VirusTotal.File.attributes.trid.probability | The TrID probability. | Number |
| VirusTotal.File.attributes.crowdsourced_yara_results.description | description of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.source | Source of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.author | Author of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.ruleset_name | Rule set name of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.rule_name | Name of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.ruleset_id | ID of the YARA rule. | String |
| VirusTotal.File.attributes.total_votes.harmless | Total number of harmless votes. | Number |
| VirusTotal.File.attributes.total_votes.malicious | Total number of malicious votes. | Number |
| VirusTotal.File.attributes.popular_threat_classification.suggested_threat_label | Suggested thread label. | String |
| VirusTotal.File.attributes.popular_threat_classification.popular_threat_name | The popular thread name. | Number |
| VirusTotal.File.attributes.last_analysis_stats.harmless | The number of engines that found the indicator to be harmless. | Number |
| VirusTotal.File.attributes.last_analysis_stats.type-unsupported | The number of engines that found the indicator to be of type unsupported. | Number |
| VirusTotal.File.attributes.last_analysis_stats.suspicious | The number of engines that found the indicator to be suspicious. | Number |
| VirusTotal.File.attributes.last_analysis_stats.confirmed-timeout | The number of engines that confirmed the timeout of the indicator. | Number |
| VirusTotal.File.attributes.last_analysis_stats.timeout | The number of engines that timed out for the indicator. | Number |
| VirusTotal.File.attributes.last_analysis_stats.failure | The number of failed analysis engines. | Number |
| VirusTotal.File.attributes.last_analysis_stats.malicious | The number of engines that found the indicator to be malicious. | Number |
| VirusTotal.File.attributes.last_analysis_stats.undetected | The number of engines that could not detect the indicator. | Number |
| VirusTotal.File.type | type of the indicator \(file\). | String |
| VirusTotal.File.id | type ID of the indicator. | String |
| VirusTotal.File.links.self | Link to the response. | Unknown |

## Playbook Image

---

![File Enrichment - Generic v2](../doc_files/File_Enrichment_-_Generic_v2.png)
