This script gathers file reputation data from multiple integrations and returns a "File" object with consolidated information to the context output.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| file_hash | Hash of the file. Supported types are: MD5, SHA1, SHA256, and SHA512. |
| enrichment_brands | Integrations brands to use for running the file reputation command. If not provided, the command will run for all available integrations that contain the file reputation command.<br/>For multi-select, provide a comma-separated list. For example: "VirusTotal \(API v3\),WildFire-v2". |
| verbose | Whether to retrieve a human-readable entry for every command or only the final result. Set to true to retrieve a human-readable entry for every command. Set to retrieve a human-readable summary of the final result. |
| external_enrichment | Whether to run additional external indicator enrichment commands. Set to true to enrich with information from the specified source brands. Set to false to query only for existing indicators in Threat Intelligence \(TIM\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator.Value | The value of the file indicator. | String |
| DBotScore.Indicator.Source | The vendor from which the file indicator value was retrieved. | String |
| DBotScore.Score.Value | The risk score associated with the file. | Number |
| DBotScore.Score.Source | The vendor from which the risk score was retrieved. | String |
| DBotScore.Reliability.Value | The reliability level of the score, for example, "C - Fairly Reliable". | String |
| DBotScore.Reliability.Source | The vendor from which the reliability level was retrieved. | String |
| DBotScore.Type.Value | The type of the indicator. | String |
| DBotScore.Type.Source | The vendor from which the indicator type was retrieved. | String |
| DBotScore.Vendor.Value | The vendor \(source brand\) that provided the score. | String |
| DBotScore.Vendor.Source | The vendor from which the vendor information was retrieved. | String |
| File.Name.Value | The name of the file including its extension. | String |
| File.Name.Source | The vendor from which the file name was retrieved. | String |
| File.EntryID.Value | The identifier used to locate the file in the Incident War Room. | String |
| File.EntryID.Source | The vendor from which the identifier was retrieved. | String |
| File.Size.Value | The file size measured in bytes. | Number |
| File.Size.Source | The vendor from which the file size was retrieved. | String |
| File.MD5.Value | The MD5 hash of the file. | String |
| File.MD5.Source | The vendor from which the MD5 hash was retrieved. | String |
| File.SHA1.Value | The SHA1 hash of the file. | String |
| File.SHA1.Source | The vendor from which the SHA1 hash was retrieved. | String |
| File.SHA256.Value | The SHA256 hash of the file. | String |
| File.SHA256.Source | The vendor from which the SHA256 hash was retrieved. | String |
| File.SHA512.Value | The SHA512 hash of the file. | String |
| File.SHA512.Source | The vendor from which the SHA512 hash was retrieved. | String |
| File.SSDeep.Value | The ssdeep hash of the file, used to track versions or alterations. | String |
| File.SSDeep.Source | The vendor from which the ssdeep hash was retrieved. | String |
| File.Extension.Value | The file extension, indicating the type of file format, for example, 'exe'. | String |
| File.Extension.Source | The vendor from which the file extension was retrieved. | String |
| File.Type.Value | The file type determined by libmagic. | String |
| File.Type.Source | The vendor from which the file type was retrieved. | String |
| File.Hostname.Value | The hostname of the device where the file was found. | String |
| File.Hostname.Source | The vendor from which the hostname was retrieved. | String |
| File.Path.Value | The directory path where the file is located. | String |
| File.Path.Source | The vendor from which the directory path was retrieved. | String |
| File.Company.Value | The name of the company that released a binary. | String |
| File.Company.Source | The vendor from which the company name was retrieved. | String |
| File.ProductName.Value | The product title to which the file belongs. | String |
| File.ProductName.Source | The vendor from which the product title was retrieved. | String |
| File.DigitalSignature.Publisher.Value | The entity that issued the digital signature of the file. | String |
| File.DigitalSignature.Publisher.Source | The vendor from which the digital signature was retrieved. | String |
| File.Actor.Value | The threat actor associated with the file, if applicable. | String |
| File.Actor.Source | The vendor from which the threat actor information was retrieved. | String |
| File.Tags.Value | Tags assigned to the file for categorization or identification. | Array |
| File.Tags.Source | The vendor from which the tags were retrieved. | String |
| File.FeedRelatedIndicators.Value.Value | Shows other indicators associated with the file. | String |
| File.FeedRelatedIndicators.Value.Source | The vendor from which the related indicators were retrieved. | String |
| File.FeedRelatedIndicators.type.Value | Identifies the types of associated indicators. | String |
| File.FeedRelatedIndicators.type.Source | The vendor from which the types of associated indicators were retrieved. | String |
| File.FeedRelatedIndicators.description.Value | Describes the associated indicators providing context or relevance. | String |
| File.FeedRelatedIndicators.description.Source | The vendor from which the description of the associated indicators was retrieved. | String |
| File.MalwareFamily.Value | Names the malware family associated with the file, if known. | String |
| File.MalwareFamily.Source | The vendor from which the malware family name was retrieved. | String |
| File.Signature.Authentihash.Value | The Authentihash, a cryptographic hash, used for verifying the file's authenticity. | String |
| File.Signature.Authentihash.Source | The vendor from which the Authentihash was retrieved. | String |
| File.Signature.Description.Value | Describes the file signature data relevant to identification. | String |
| File.Signature.Description.Source | The vendor from which the signature description was retrieved. | String |
| File.Signature.FileVersion.Value | Indicates the version number of the file. | String |
| File.Signature.FileVersion.Source | The vendor from which the file version was retrieved. | String |
| File.Signature.InternalName.Value | The internal name of the file as designated by the creators. | String |
| File.Signature.InternalName.Source | The vendor from which the internal name was retrieved. | String |
| File.Signature.OriginalName.Value | The original name of the file before any changes or renames. | String |
| File.Signature.OriginalName.Source | The vendor from which the original name was retrieved. | String |
| File.Malicious.Vendor.Value | Specifies the vendor that identified the file as malicious. | String |
| File.Malicious.Vendor.Source | The vendor from which the information identifying the file as malicious was retrieved. | String |
| File.Malicious.Description.Value | Provides details on why the file was deemed malicious. | String |
| File.Malicious.Description.Source | The vendor from which the malicious description was retrieved. | String |
| File.Relationships.EntityA.Value | The initiating entity in a relationship involving the file. | String |
| File.Relationships.EntityA.Source | The vendor from which the initiating entity information was retrieved. | String |
| File.Relationships.EntityB.Value | The recipient or target entity in a relationship involving the file. | String |
| File.Relationships.EntityB.Source | The vendor from which the recipient or target entity information was retrieved. | String |
| File.Relationships.Relationship.Value | Defines the type or nature of the relationship between entities. | String |
| File.Relationships.Relationship.Source | The vendor from which the relationship type was retrieved. | String |
| File.Relationships.EntityAType.Value | The type or classification of the initiating entity. | String |
| File.Relationships.EntityAType.Source | The vendor from which the initiating entity type was retrieved. | String |
| File.Relationships.EntityBType.Value | The type or classification of the recipient entity. | String |
| File.Relationships.EntityBType.Source | The vendor from which the recipient entity type was retrieved. | String |
| File.Campaign.Value | The identified campaign associated with the file, if applicable. | String |
| File.Campaign.Source | The vendor from which the campaign information was retrieved. | String |
| File.TrafficLightProtocol.Value | Specifies the TLP color designation suitable for handling the file. | String |
| File.TrafficLightProtocol.Source | The vendor from which the TLP color designation was retrieved. | String |
| File.CommunityNotes.note.Value | Community-contributed notes regarding observations or findings related to the file. | String |
| File.CommunityNotes.note.Source | The vendor from which the community-contributed notes were retrieved. | String |
| File.CommunityNotes.timestamp.Value | The timestamp when the community note was added. | Date |
| File.CommunityNotes.timestamp.Source | The vendor from which the timestamp of the community note was retrieved. | String |
| File.Publications.source.Value | Identifies the publishing source of an article relating to the file. | String |
| File.Publications.source.Source | The vendor from which the publishing source information was retrieved. | String |
| File.Publications.title.Value | The title of the publication discussing aspects of the file. | String |
| File.Publications.title.Source | The vendor from which the publication title was retrieved. | String |
| File.Publications.link.Value | Provides a hyperlink to the full article or publication for detailed information. | String |
| File.Publications.link.Source | The vendor from which the publication link was retrieved. | String |
| File.Publications.timestamp.Value | The publication date and time of the related article. | Date |
| File.Publications.timestamp.Source | The vendor from which the publication date and time was retrieved. | String |
| File.Behavior.details.Value | Detailed technical information describing the file's behavior. | String |
| File.Behavior.details.Source | The vendor from which the detailed technical information was retrieved. | String |
| File.Behavior.title.Value | A brief description of the behavior exhibited by the file. | String |
| File.Behavior.title.Source | The vendor from which the behavior title was retrieved. | String |
| File.Imphash.Value | The import hash \(imphash\) of the file, specific to the imports used within an executable. | String |
| File.Imphash.Source | The vendor from which the imphash was retrieved. | String |
| File.Quarantined.Value | Indicates whether the file has been quarantined to prevent potential harm. | Bool |
| File.Quarantined.Source | The vendor from which the quarantine status was retrieved. | String |
| File.Organization.Value | The organization to which the file is attributed. | String |
| File.Organization.Source | The vendor from which the organization information was retrieved. | String |
| File.AssociatedFileNames.Value | The names of other files associated with this file. | Array |
| File.AssociatedFileNames.Source | The vendor from which the associated file names were retrieved. | String |
