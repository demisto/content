This script gathers URL reputation data from multiple integrations and returns a "URLEnrichment" object with consolidated information in the context output.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| url_list | Accepts a list of URLs to enrich.<br/>- From CLI: Provide a comma-separated list.  <br/>  If a URL contains a comma, wrap the URLs in a JSON array.  <br/>  Example: "\[\\"https://example.com/search?tags=red,yellow,green\\", \\"https://example2.com\\"\]".<br/>- From Context: Pass JSON arrays directly, without modification.<br/> |
| external_enrichment | Whether to call external integrations for enrichment: - 'true': enrich using enabled external integrations \(e.g., VirusTotal \(API v3\), AlienVault OTX v2\). - 'false': use only existing TIM data; skip external integrations. If the 'brands' argument is provided, this flag is ignored and enrichment is run only on the brands provided. |
| verbose | Retrieve a human-readable entry for each command; if false, only the final result is summarized and errors are suppressed. |
| brands | A list of integration brands to run enrichment against.  <br/>Example: \`"VirusTotal \(API v3\), AlienVault OTX v2"\`.  <br/>- If provided, only the selected brands are used. <br/>- If left empty, the script runs enrichment on all enabled integrations,<br/>  depending on the \`external_enrichment\` flag.<br/>To see the available brands for the \`url\` command, run: \`\!ProvidesCommand command=url\`.<br/> |
| additional_fields | When set to true, the output includes an \`AdditionalFields\` object<br/>for each of the indicator result.  <br/>\`AdditionalFields\` contains all fields returned by TIM or the integrations<br/>that are not part of the standard output keys: \`Data\`, \`DetectionEngines\`, <br/>\`PositiveDetections\`, \`Score\`, and \`Brand\`.  <br/>When set to false, only the standard keys are returned.<br/> |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URLEnrichment.Value | The URL. | string |
| URLEnrichment.MaxScore | The max score of all the indicators found. | number |
| URLEnrichment.MaxVerdict | The max verdict of all the indicators found. | string |
| URLEnrichment.Results | List of all indicators found for the URL. | array |
| URLEnrichment.TIMScore | The TIM score of the URL. | number |
| URLEnrichment.Status | The status of the indicator: "Manual" if the score was changed manually, "Fresh" if modified within the last week, "Stale" if modified more than a week ago, and "None" if never modified. | string |
| URLEnrichment.ModifiedTime | The time the indicator was last modified. | Date |
| URLEnrichment.Results.Brand | The brand of the indicator. | string |
| URLEnrichment.Results.Score | The score of the indicator. | number |
| URLEnrichment.Results.Verdict | The verdict of the indicator. | string |
| URLEnrichment.Results.DetectionEngines | The detection engines of the indicator. | number |
| URLEnrichment.Results.PositiveDetections | The positive detections of the indicator. | number |
| URLEnrichment.Results.Data | The URL it self. | string |
| URLEnrichment.Results.AdditionalFields | All fields extracted from the indicator other then the main keys \("Brand", "Score", "Verdict", "DetectionEngines", "PositiveDetections", "Data"\). | Object |
| URLEnrichment.Results.AdditionalFields.Relationships.EntityA | The source of the relationship. | string |
| URLEnrichment.Results.AdditionalFields.Relationships.EntityB | The destination of the relationship. | string |
| URLEnrichment.Results.AdditionalFields.Relationships.Relationship | The name of the relationship. | string |
| URLEnrichment.Results.AdditionalFields.Relationships.EntityAType | The type of the source of the relationship. | string |
| URLEnrichment.Results.AdditionalFields.Relationships.EntityBType | The type of the destination of the relationship. | string |
| URLEnrichment.Results.AdditionalFields.Category | The category associated with the indicator. | String |
| URLEnrichment.Results.AdditionalFields.Malicious.Vendor | The vendor reporting the URL as malicious. | String |
| URLEnrichment.Results.AdditionalFields.Malicious.Description | A description of the malicious URL. | String |
| URLEnrichment.Results.AdditionalFields.Tags | \(List\) Tags of the URL. | Unknown |
| URLEnrichment.Results.AdditionalFields.FeedRelatedIndicators.value | Indicators that are associated with the URL. | String |
| URLEnrichment.Results.AdditionalFields.FeedRelatedIndicators.type | The type of the indicators that are associated with the URL. | String |
| URLEnrichment.Results.AdditionalFields.FeedRelatedIndicators.description | The description of the indicators that are associated with the URL. | String |
| URLEnrichment.Results.AdditionalFields.MalwareFamily | The malware family associated with the URL. | String |
| URLEnrichment.Results.AdditionalFields.Port | Ports that are associated with the URL. | String |
| URLEnrichment.Results.AdditionalFields.Internal | Whether or not the URL is internal or external. | Bool |
| URLEnrichment.Results.AdditionalFields.Campaign | The campaign associated with the URL. | String |
| URLEnrichment.Results.AdditionalFields.TrafficLightProtocol | The Traffic Light Protocol \(TLP\) color that is suitable for the URL. | String |
| URLEnrichment.Results.AdditionalFields.ThreatTypes.threatcategory | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. | String |
| URLEnrichment.Results.AdditionalFields.ThreatTypes.threatcategoryconfidence | Threat Category Confidence is the confidence level provided by the vendor for the threat type category For example a confidence of 90 for threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. | String |
| URLEnrichment.Results.AdditionalFields.ASN | The autonomous system name for the URL, for example: 'AS8948'. | String |
| URLEnrichment.Results.AdditionalFields.ASOwner | The autonomous system owner of the URL. | String |
| URLEnrichment.Results.AdditionalFields.GeoCountry | The country in which the URL is located. | String |
| URLEnrichment.Results.AdditionalFields.Organization | The organization of the URL. | String |
| URLEnrichment.Results.AdditionalFields.CommunityNotes.note | Notes on the URL that were given by the community. | String |
| URLEnrichment.Results.AdditionalFields.CommunityNotes.timestamp | The time in which the note was published. | Date |
| URLEnrichment.Results.AdditionalFields.Publications.source | The source in which the article was published. | String |
| URLEnrichment.Results.AdditionalFields.Publications.title | The name of the article. | String |
| URLEnrichment.Results.AdditionalFields.Publications.link | A link to the original article. | String |
| URLEnrichment.Results.AdditionalFields.Publications.timestamp | The time in which the article was published. | Date |
