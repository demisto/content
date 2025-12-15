This script gathers for reputation data from multiple integrations and returns a "FileEnrichment" object with consolidated information in the context output. The script runs core-get-hash-analytics-prevalence on SHA256 values only.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.10.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* FileEnrichment - Test

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| file_hash | A comma-separated list of File hashes to enrich. Supported types are: MD5, SHA1, SHA256, and SHA512. |
| external_enrichment | "Whether to call external integrations for enrichment:<br/>- 'true': enrich using all enabled integrations \(e.g., VirusTotal \(API v3\), AlienVault OTX v2\).<br/>- 'false': Will enrich using only WildFire-v2 if available; skip external integrations.<br/>If the 'brands' argument is provided, this flag is ignored and enrichment is run only on the brands provided."<br/> |
| verbose | Retrieve a human-readable entry for each command; if false, only the final result is summarized. |
| brands | A list of integration brands to run enrichment against.  <br/>Example: \`"AlienVault OTX v2", "WildFire-v2"\`.  <br/>- If provided, only the selected brands are used. <br/>- If left empty, the script runs enrichment on all enabled integrations,<br/>  depending on the \`external_enrichment\` flag.<br/>- In order to run core-get-hash-analytics-prevalence, add Cortex Core - IR to the brands list \(will run only on SHA256 values\).<br/>To see the available brands for the \`file\` command, run: \`\!ProvidesCommand command=file\`.<br/> |
| additional_fields | When set to true, the output includes an \`AdditionalFields\` object<br/>for each of the indicator results.  <br/>\`AdditionalFields\` contains all fields returned by TIM or the integrations<br/>that are not part of the standard output keys: \`MD5\`, \`SHA1\`, \`SHA256\`, \`SHA512\`, \`CRC32\`, \`CTPH\`, \`SSDeep\`, \`ImpHash\`, <br/>\`SourceTimeStamp\`, \`Modified\`, \`Path\`, \`Size\`, \`FileExtension\`, \`AssociatedFileNames\`, \`Brand\`, \`Score\`.<br/>When set to false, only the standard keys are returned.<br/> |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| FileEnrichment.Value | The File hash from the input Value. | String |
| FileEnrichment.Hashes.MD5 | The file MD5 hash if exists. | String |
| FileEnrichment.Hashes.SHA1 | The file SHA1 hash if exists. | String |
| FileEnrichment.Hashes.SHA256 | The file SHA256 hash if exists. | String |
| FileEnrichment.Hashes.SHA512 | The file SHA512 hash if exists. | String |
| FileEnrichment.Hashes.CRC32 | The file CRC32 hash if exists. | String |
| FileEnrichment.Hashes.CTPH | The file CTPH hash if exists. | String |
| FileEnrichment.Hashes.SSDeep | The file SSDeep hash if exists. | String |
| FileEnrichment.Hashes.ImpHash | The file ImpHash hash if exists. | String |
| FileEnrichment.MaxScore | The max score of all the indicators found. | Number |
| FileEnrichment.MaxVerdict | The max verdict of all the indicators found. | String |
| FileEnrichment.Results | List of all indicators found for the URL. | Array |
| FileEnrichment.TIMScore | The TIM score of the URL. | Number |
| FileEnrichment.Status | The status of the indicator: "Manual" if the score was changed manually, "Fresh" if modified within the last week, "Stale" if modified more than a week ago, and "None" if never modified. | String |
| FileEnrichment.ModifiedTime | The time the indicator was last modified. | Date |
| FileEnrichment.Results.Brand | The brand of the indicator. | String |
| FileEnrichment.Results.Score | The score of the indicator. | Number |
| FileEnrichment.Results.Verdict | The verdict of the indicator. | String |
| FileEnrichment.Results.DetectionEngines | The detection engines of the indicator. | Number |
| FileEnrichment.Results.PositiveDetections | The positive detections of the indicator. | Number |
| FileEnrichment.Results.MD5 | The file MD5 hash if exists. | String |
| FileEnrichment.Results.SHA1 | The file SHA1 hash if exists. | String |
| FileEnrichment.Results.SHA256 | The file SHA256 hash if exists. | String |
| FileEnrichment.Results.SHA512 | The file SHA512 hash if exists. | String |
| FileEnrichment.Results.CRC32 | The file CRC32 hash if exists. | String |
| FileEnrichment.Results.CTPH | The file CTPH hash if exists. | String |
| FileEnrichment.Results.SSDeep | The file SSDeep hash if exists. | String |
| FileEnrichment.Results.ImpHash | The file ImpHash hash if exists. | String |
| FileEnrichment.Results.Reliability | The reliability of the Brand. | String |
| FileEnrichment.Results.AdditionalFields.Name | The name of the file including its extension. | String |
| FileEnrichment.Results.AdditionalFields.EntryID | The identifier used to locate the file in the Incident War Room. | String |
| FileEnrichment.Results.AdditionalFields.Actor | The threat actor associated with the file, if applicable. | String |
| FileEnrichment.Results.AdditionalFields.behavior.details | A brief description of the behavior exhibited by the file. | String |
| FileEnrichment.Results.AdditionalFields.behavior.title | A brief description of the behavior exhibited by the file. | String |
| FileEnrichment.Results.AdditionalFields.Campaign | The identified campaign associated with the file, if applicable. | String |
| FileEnrichment.Results.AdditionalFields.CommunityNotes.note | Community-contributed notes regarding observations or findings related to the file. | String |
| FileEnrichment.Results.AdditionalFields.CommunityNotes.timestamp | The timestamp when the community note was added. | Date |
| FileEnrichment.Results.AdditionalFields.Company | The name of the company that released a binary. | String |
| FileEnrichment.Results.AdditionalFields.DigitalSignature.Publisher | The entity that issued the digital signature of the file. | String |
| FileEnrichment.Results.AdditionalFields.Extension | The file extension, indicating the type of file format, for example, 'exe'. | String |
| FileEnrichment.Results.AdditionalFields.FeedRelatedIndicators.value | Shows other indicators associated with the file. | String |
| FileEnrichment.Results.AdditionalFields.FeedRelatedIndicators.type | Identifies the types of associated indicators. | String |
| FileEnrichment.Results.AdditionalFields.FeedRelatedIndicators.description | Describes the associated indicators providing context or relevance. | String |
| FileEnrichment.Results.AdditionalFields.FirstSeenBySource | The first time seen by the source brand. | Date |
| FileEnrichment.Results.AdditionalFields.GlobalPrevalence | The global prevalence of the file hash. | Number |
| FileEnrichment.Results.AdditionalFields.Hostname | The hostname of the device where the file was found. | String |
| FileEnrichment.Results.AdditionalFields.LastSeenBySource | The last time seed by the source brand. | Date |
| FileEnrichment.Results.AdditionalFields.Malicious.Vendor | Specifies the vendor that identified the file as malicious. | String |
| FileEnrichment.Results.AdditionalFields.Malicious.Description | For malicious files, the reason that the vendor made the decision. | Unknown |
| FileEnrichment.Results.AdditionalFields.Malicious.Detections | For malicious files, the total number of detections. | Unknown |
| FileEnrichment.Results.AdditionalFields.Malicious.TotalEngines | For malicious files, the total number of engines that checked the file hash. | Unknown |
| FileEnrichment.Results.AdditionalFields.VTVendors.EngineDetections | Number of VT vendors that flagged the file as malicious. | Unknown |
| FileEnrichment.Results.AdditionalFields.VTVendors.EngineVendors | VT vendors who flagged the file as malicious. | Unknown |
| FileEnrichment.Results.AdditionalFields.VTVendors.EngineDetectionNames | VT detection names that flagged the file as malicious. | Unknown |
| FileEnrichment.Results.AdditionalFields.MalwareFamily | Names the malware family associated with the file, if known. | String |
| FileEnrichment.Results.AdditionalFields.Organization | The organization to which the file is attributed. | String |
| FileEnrichment.Results.AdditionalFields.OrganizationFirstSeen | The date and time when the indicator was first seen in the organization. | Date |
| FileEnrichment.Results.AdditionalFields.OrganizationLastSeen | The date and time when the indicator was last seen in the organization. | Date |
| FileEnrichment.Results.AdditionalFields.OrganizationPrevalence | The number of times the indicator is detected in the organization. | Number |
| FileEnrichment.Results.AdditionalFields.ProductName | The file product name. | String |
| FileEnrichment.Results.AdditionalFields.Publications.source | Identifies the publishing source of an article relating to the file. | String |
| FileEnrichment.Results.AdditionalFields.Publications.title | Identifies the publishing source of an article relating to the file. | String |
| FileEnrichment.Results.AdditionalFields.Publications.link | Provides a hyperlink to the full article or publication for detailed information. | String |
| FileEnrichment.Results.AdditionalFields.Publications.timestamp | Publications.timestamp | Date |
| FileEnrichment.Results.AdditionalFields.Quarantined | Indicates whether the file has been quarantined to prevent potential harm. | Bool |
| FileEnrichment.Results.AdditionalFields.Relationships.EntityA | The initiating entity in a relationship involving the file. | String |
| FileEnrichment.Results.AdditionalFields.Relationships.EntityB | The recipient or target entity in a relationship involving the file. | String |
| FileEnrichment.Results.AdditionalFields.Relationships.Relationship | Defines the type or nature of the relationship between entities. | String |
| FileEnrichment.Results.AdditionalFields.Relationships.EntityAType | The type or classification of the initiating entity. | String |
| FileEnrichment.Results.AdditionalFields.Relationships.EntityBType | The type or classification of the recipient entity. | String |
| FileEnrichment.Results.AdditionalFields.Signature.Authentihash | The Authentihash, a cryptographic hash, used for verifying the file's authenticity. | String |
| FileEnrichment.Results.AdditionalFields.Signature.Description | Describes the file signature data relevant to identification. | String |
| FileEnrichment.Results.AdditionalFields.Signature.FileVersion | Indicates the version number of the file. | String |
| FileEnrichment.Results.AdditionalFields.Signature.InternalName | The internal name of the file as designated by the creators. | String |
| FileEnrichment.Results.AdditionalFields.Signature.OriginalName | The original name of the file before any changes or renames. | String |
| FileEnrichment.Results.AdditionalFields.Tags | Tags assigned to the file for categorization or identification. | Array |
| FileEnrichment.Results.AdditionalFields.ThreatTypes | Threat types associated with the file. | Unknown |
| FileEnrichment.Results.AdditionalFields.TrafficLightProtocol | Specifies the TLP color designation suitable for handling the file. | String |
| FileEnrichment.Results.AdditionalFields.Type | The file type determined by libmagic. | String |
| Core.AnalyticsPrevalence.Hash.value | Whether the hash is prevalent or not. | Boolean |
| Core.AnalyticsPrevalence.Hash.data.global_prevalence.value | The global prevalence of the hash. | Number |
| Core.AnalyticsPrevalence.Hash.data.local_prevalence.value | The local prevalence of the hash. | Number |
| Core.AnalyticsPrevalence.Hash.data.prevalence.value | The prevalence of the hash. | Number |
