This script gathers file reputation data from multiple integrations and returns a File entity with consolidated information to the context output.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| file_hash | Hash of the file. Supported types are: MD5, SHA1, SHA256, and SHA512. |
| brands | Which integrations brands to run the command for. If not provided, the command will run for all available integrations.<br/>For multi-select, provide a comma-separated list. For example: "VirusTotal \(API v3\),Cortex Core - IR". |
| verbose | Whether to retrieve human readable entry for every command or only the final result. Set to true to get a human-readable entry for every command. Set to false to get a human-readable summary of the final result. |
| external_enrichment | Whether to run additional external indicator enrichment commands. Set to true to enrich with information from the specified source brands. Set to false to only query for existing indicators in the Threat Intelligence Module \(TIM\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The value of the file indicator. | String |
| DBotScore.Score | The risk score associated with the file. | Number |
| DBotScore.Reliability | The reliability level of the score, for example, "C - Fairly Reliable". | String |
| DBotScore.Type | The type of the indicator. | String |
| DBotScore.Vendor | The vendor \(source brand\) that provided the score. | String |
| File.Name | The name of the file including its extension. | String |
| File.EntryID | The identifier used to locate the file in the Incident War Room. | String |
| File.Size | The file size measured in bytes. | Number |
| File.MD5 | The MD5 hash of the file. | String |
| File.SHA1 | The SHA1 hash of the file. | String |
| File.SHA256 | The SHA256 hash of the file. | String |
| File.SHA512 | The SHA512 hash of the file. | String |
| File.SSDeep | The ssdeep hash of the file, used to track versions or alterations. | String |
| File.Extension | The file extension, indicating the type of file format, for example, 'exe'. | String |
| File.Type | The file type determined by libmagic. | String |
| File.Hostname | The hostname of the device where the file was found. | String |
| File.Path | The directory path where the file is located. | String |
| File.Company | The name of the company that released a binary. | String |
| File.ProductName | The product title to which the file belongs. | String |
| File.DigitalSignature.Publisher | The entity that issued the digital signature of the file. | String |
| File.Actor | The threat actor associated with the file, if applicable. | String |
| File.Tags | Tags assigned to the file for categorization or identification. | Array |
| File.FeedRelatedIndicators.value | Shows other indicators associated with the file. | String |
| File.FeedRelatedIndicators.type | Identifies the types of associated indicators. | String |
| File.FeedRelatedIndicators.description | Describes the associated indicators providing context or relevance. | String |
| File.MalwareFamily | Names the malware family associated with the file, if known. | String |
| File.Signature.Authentihash | The Authentihash, a cryptographic hash, used for verifying the file's authenticity. | String |
| File.Signature.Description | Describes the file signature data relevant to identification. | String |
| File.Signature.FileVersion | Indicates the version number of the file. | String |
| File.Signature.InternalName | The internal name of the file as designated by the creators. | String |
| File.Signature.OriginalName | The original name of the file before any changes or renames. | String |
| File.Malicious.Vendor | Specifies the vendor that identified the file as malicious. | String |
| File.Malicious.Description | Provides details on why the file was deemed malicious. | String |
| File.Relationships.EntityA | The initiating entity in a relationship involving the file. | string |
| File.Relationships.EntityB | The recipient or target entity in a relationship involving the file. | string |
| File.Relationships.Relationship | Defines the type or nature of the relationship between entities. | string |
| File.Relationships.EntityAType | The type or classification of the initiating entity. | string |
| File.Relationships.EntityBType | The type or classification of the recipient entity. | string |
| File.Campaign | The identified campaign associated with the file, if applicable. | String |
| File.TrafficLightProtocol | Specifies the TLP color designation suitable for handling the file. | String |
| File.CommunityNotes.note | Community-contributed notes regarding observations or findings related to the file. | String |
| File.CommunityNotes.timestamp | The timestamp when the community note was added. | Date |
| File.Publications.source | Identifies the publishing source of an article relating to the file. | String |
| File.Publications.title | The title of the publication discussing aspects of the file. | String |
| File.Publications.link | Provides a hyperlink to the full article or publication for detailed information. | String |
| File.Publications.timestamp | The publication date and time of the related article. | Date |
| File.Behavior.details | Detailed technical information describing the file's behavior. | String |
| File.Behavior.title | A brief description of the behavior exhibited by the file. | String |
| File.Imphash | The import hash \(imphash\) of the file, specific to the imports used within an executable. | String |
| File.Quarantined | Indicates whether the file has been quarantined to prevent potential harm. | Bool |
| File.Organization | The organization to which the file is attributed. | String |
| File.AssociatedFileNames | Lists other file names associated with this file. | Array |
