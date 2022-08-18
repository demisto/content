Get file information using the Virus Total API integration.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
* VirusTotal (API v3)

### Scripts
This playbook does not use any scripts.

### Commands
* vt-file-sandbox-report
* file

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileHash | File Hash to enrich | File.SHA256 | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.MD5 | Bad MD5 hash. | Unknown |
| File.SHA1 | Bad SHA1 hash. | Unknown |
| File.SHA256 | Bad SHA256 hash. | Unknown |
| File.Relationships.EntityA | The source of the relationship. | String |
| File.Relationships.EntityB | The destination of the relationship. | String |
| File.Relationships.Relationship | The name of the relationship. | String |
| File.Relationships.EntityAtype | The type of the source of the relationship. | String |
| File.Relationships.EntityBtype | The type of the destination of the relationship. | String |
| File.Malicious.Vendor | For malicious files, the vendor that made the decision. | Unknown |
| File.Malicious.Detections | For malicious files, the total number of detections. | Unknown |
| File.Malicious.TotalEngines | For malicious files, the total number of engines that checked the file hash. | Unknown |
| DBotScore.Indicator | The indicator that was tested. | Unknown |
| DBotScore.type | The indicator type. | Unknown |
| DBotScore.Vendor | The vendor used to calculate the DBot score. | Unknown |
| DBotScore.Score | The actual score. | Number |
| DBotScore.Reliability | Reliability of the source providing the intelligence data. | String |
| VirusTotal.File.attributes.type_description | description of the type of the file. | String |
| VirusTotal.File.attributes.tlsh | The locality-sensitive hashing. | String |
| VirusTotal.File.attributes.exiftool.MIMEtype | MIME type of the file. | String |
| VirusTotal.File.attributes.names | Names of the file. | String |
| VirusTotal.File.attributes.javascript_info.tags | Tags of the JavaScript. | String |
| VirusTotal.File.attributes.exiftool.Filetype | The file type. | String |
| VirusTotal.File.attributes.exiftool.WordCount | Total number of words in the file. | String |
| VirusTotal.File.attributes.exiftool.LineCount | Total number of lines in file. | String |
| VirusTotal.File.attributes.crowdsourced_ids_stats.info | Number of IDS that marked the file as "info". | Number |
| VirusTotal.File.attributes.crowdsourced_ids_stats.high | Number of IDS that marked the file as "high". | Number |
| VirusTotal.File.attributes.crowdsourced_ids_stats.medium | Number of IDS that marked the file as "medium". | Number |
| VirusTotal.File.attributes.crowdsourced_ids_stats.low | Number of IDS that marked the file as "low". | Number |
| VirusTotal.File.attributes.sigma_analysis_stats.critical | Number of Sigma analysis that marked the file as "critical". | Number |
| VirusTotal.File.attributes.sigma_analysis_stats.high | Number of Sigma analysis that marked the file as "high". | Number |
| VirusTotal.File.attributes.sigma_analysis_stats.medium | Number of Sigma analysis that marked the file as "medium". | Number |
| VirusTotal.File.attributes.sigma_analysis_stats.low | Number of Sigma analysis that marked the file as "low". | Number |
| VirusTotal.File.attributes.exiftool.MIMEEncoding | The MIME encoding. | String |
| VirusTotal.File.attributes.exiftool.FiletypeExtension | The file type extension. | String |
| VirusTotal.File.attributes.exiftool.Newlines | Number of newlines signs. | String |
| VirusTotal.File.attributes.trid.file_type | The TrID file type. | String |
| VirusTotal.File.attributes.trid.probability | The TrID probability. | Number |
| VirusTotal.File.attributes.crowdsourced_yara_results.description | description of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.source | Source of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.author | Author of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.ruleset_name | Rule set name of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.rule_name | Name of the YARA rule. | String |
| VirusTotal.File.attributes.crowdsourced_yara_results.ruleset_id | ID of the YARA rule. | String |
| VirusTotal.File.attributes.names | Name of the file. | String |
| VirusTotal.File.attributes.last_modification_date | The last modification date in epoch format. | Number |
| VirusTotal.File.attributes.type_tag | Tag of the type. | String |
| VirusTotal.File.attributes.total_votes.harmless | Total number of harmless votes. | Number |
| VirusTotal.File.attributes.total_votes.malicious | Total number of malicious votes. | Number |
| VirusTotal.File.attributes.size | Size of the file. | Number |
| VirusTotal.File.attributes.popular_threat_classification.suggested_threat_label | Suggested thread label. | String |
| VirusTotal.File.attributes.popular_threat_classification.popular_threat_name | The popular thread name. | Number |
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
| VirusTotal.File.attributes.last_analysis_stats.harmless | The number of engines that found the indicator to be harmless. | Number |
| VirusTotal.File.attributes.last_analysis_stats.type-unsupported | The number of engines that found the indicator to be of type unsupported. | Number |
| VirusTotal.File.attributes.last_analysis_stats.suspicious | The number of engines that found the indicator to be suspicious. | Number |
| VirusTotal.File.attributes.last_analysis_stats.confirmed-timeout | The number of engines that confirmed the timeout of the indicator. | Number |
| VirusTotal.File.attributes.last_analysis_stats.timeout | The number of engines that timed out for the indicator. | Number |
| VirusTotal.File.attributes.last_analysis_stats.failure | The number of failed analysis engines. | Number |
| VirusTotal.File.attributes.last_analysis_stats.malicious | The number of engines that found the indicator to be malicious. | Number |
| VirusTotal.File.attributes.last_analysis_stats.undetected | The number of engines that could not detect the indicator. | Number |
| VirusTotal.File.attributes.meaningful_name | Meaningful name of the file. | String |
| VirusTotal.File.attributes.reputation | The reputation of the file. | Number |
| VirusTotal.File.type | type of the indicator \(file\). | String |
| VirusTotal.File.id | type ID of the indicator. | String |
| VirusTotal.File.links.self | Link to the response. | Unknown |

## Playbook Image
---
![File Enrichment - Virus Total (API v3)](../doc_files/File_Enrichment_-_Virus_Total_API_v3.png)