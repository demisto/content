This script gathers file reputation data from multiple integrations and returns a "FileEnrichment" object with consolidated information to the context output.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                                                       |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| file_hash | Hash of the file. Supported types are: MD5, SHA1, SHA256, and SHA512. For multiple values, provide a comma-separated list of file hashes.                                                                                                                                                                                                                                             |
| brands | Integrations brands to use for running external enrichment. If not provided, the command will run for all available integrations that implement the file reputation command.<br/>For multiple values, provide a comma-separated list of integration IDs. For example: "VirusTotal \(API v3\),WildFire-v2, Cortex Core - IR". Specifying brands will force enable external_enrichment. |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result and suppress error entries from commands. Default is false.                                                                                                                                                                                      |
| external_enrichment | Whether to run additional external indicator enrichment commands. Set to true to enrich with information from the specified source brands. If set to false, only existing indicators in the Threat Intelligence Module \(TIM\) will be retrieved. Default is false.                                                                                                                   |
| additional_fields | Whether to return unmapped \(secondary\) fields to the context output under the "FileEnrichment.AdditionalFields" path. Default is false.                                                                                                                                                                                                                                             |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The value of the file indicator. | String |
| DBotScore.Score | The risk score associated with the file. | Number |
| DBotScore.Reliability | The reliability level of the score, for example, "C - Fairly Reliable". | String |
| DBotScore.Type | The type of the indicator. | String |
| DBotScore.Vendor | The vendor \(source brand\) that provided the score. | String |
| FileEnrichment.Brand | The enrichment vendor \(source brand\). | String |
| FileEnrichment.Score | The risk score associated with the file. | Number |
| FileEnrichment.Name | The name of the file including its extension. | String |
| FileEnrichment.EntryID | The identifier used to locate the file in the Incident War Room. | String |
| FileEnrichment.Size | The file size measured in bytes. | Number |
| FileEnrichment.MD5 | The MD5 hash of the file. | String |
| FileEnrichment.SHA1 | The SHA1 hash of the file. | String |
| FileEnrichment.SHA256 | The SHA256 hash of the file. | String |
| FileEnrichment.SHA512 | The SHA512 hash of the file. | String |
| FileEnrichment.SSDeep | The ssdeep hash of the file, used to track versions or alterations. | String |
| FileEnrichment.Extension | The file extension, indicating the type of file format, for example, 'exe'. | String |
| FileEnrichment.Type | The file type determined by libmagic. | String |
| FileEnrichment.Hostname | The hostname of the device where the file was found. | String |
| FileEnrichment.Path | The directory path where the file is located. | String |
| FileEnrichment.Company | The name of the company that released a binary. | String |
| FileEnrichment.ProductName | The product title to which the file belongs. | String |
| FileEnrichment.DigitalSignature.Publisher | The entity that issued the digital signature of the file. | String |
| FileEnrichment.Actor | The threat actor associated with the file, if applicable. | String |
| FileEnrichment.Tags | Tags assigned to the file for categorization or identification. | Array |
| FileEnrichment.FeedRelatedIndicators.value | Shows other indicators associated with the file. | String |
| FileEnrichment.FeedRelatedIndicators.type | Identifies the types of associated indicators. | String |
| FileEnrichment.FeedRelatedIndicators.description | Describes the associated indicators providing context or relevance. | String |
| FileEnrichment.MalwareFamily | Names the malware family associated with the file, if known. | String |
| FileEnrichment.Signature.Authentihash | The Authentihash, a cryptographic hash, used for verifying the file's authenticity. | String |
| FileEnrichment.Signature.Description | Describes the file signature data relevant to identification. | String |
| FileEnrichment.Signature.FileVersion | Indicates the version number of the file. | String |
| FileEnrichment.Signature.InternalName | The internal name of the file as designated by the creators. | String |
| FileEnrichment.Signature.OriginalName | The original name of the file before any changes or renames. | String |
| FileEnrichment.Malicious.Vendor | Specifies the vendor that identified the file as malicious. | String |
| FileEnrichment.Malicious.Description | Provides details on why the file was deemed malicious. | String |
| FileEnrichment.Relationships.EntityA | The initiating entity in a relationship involving the file. | String |
| FileEnrichment.Relationships.EntityB | The recipient or target entity in a relationship involving the file. | String |
| FileEnrichment.Relationships.Relationship | Defines the type or nature of the relationship between entities. | String |
| FileEnrichment.Relationships.EntityAType | The type or classification of the initiating entity. | String |
| FileEnrichment.Relationships.EntityBType | The type or classification of the recipient entity. | String |
| FileEnrichment.Campaign | The identified campaign associated with the file, if applicable. | String |
| FileEnrichment.TrafficLightProtocol | Specifies the TLP color designation suitable for handling the file. | String |
| FileEnrichment.CommunityNotes.note | Community-contributed notes regarding observations or findings related to the file. | String |
| FileEnrichment.CommunityNotes.timestamp | The timestamp when the community note was added. | Date |
| FileEnrichment.Publications.source | Identifies the publishing source of an article relating to the file. | String |
| FileEnrichment.Publications.title | The title of the publication discussing aspects of the file. | String |
| FileEnrichment.Publications.link | Provides a hyperlink to the full article or publication for detailed information. | String |
| FileEnrichment.Publications.timestamp | The publication date and time of the related article. | Date |
| FileEnrichment.Behavior.details | Detailed technical information describing the file's behavior. | String |
| FileEnrichment.Behavior.title | A brief description of the behavior exhibited by the file. | String |
| FileEnrichment.Imphash | The import hash \(imphash\) of the file, specific to the imports used within an executable. | String |
| FileEnrichment.Quarantined | Indicates whether the file has been quarantined to prevent potential harm. | Bool |
| FileEnrichment.Organization | The organization to which the file is attributed. | String |
| FileEnrichment.AssociatedFileNames | The names of other files associated with this file. | Array |
| FileEnrichment.GlobalPrevalence | The global prevalence of the file hash. | Number |
| FileEnrichment.LocalPrevalence | The local prevalence of the file hash. | Number |
| FileEnrichment.AdditionalFields | Unmapped \(secondary\) fields. Only available if the additional_fields argument is set to true. | Object |
