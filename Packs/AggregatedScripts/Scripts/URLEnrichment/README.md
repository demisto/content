This script gathers url reputation data from multiple integrations and returns a "URLEnrichment" object with consolidated information to the context output.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.1.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| url_list | A comma-separated list of URLs to enrich. |
| external_enrichment | When set to 'true', the script runs reputation commands using all available external integrations. This is ignored if the 'brands' argument is used, as 'brands' provides an explicit list of integrations to run. |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result and suppress error entries from commands. |
| brands | A comma-separated list of specific integration brands to use for enrichment, e.g., "VirusTotal,CrowdStrike". If left empty, the script runs on all enabled integrations according to the 'external_enrichment' flag. <br/>Run \!ProvidesCommand command=url to see available integrations.<br/>Add WildfFire-v2 in order to run wildfire-get-verdict. |
| additional_fields | Whether to return secondary fields to the context output under "AdditionalFields". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URLEnrichment.Value | the url it self. | string |
| URLEnrichment.MaxScore | the max score of all the indicators found. | number |
| URLEnrichment.MaxVerdict | the max verdict of all the indicators found. | string |
| URLEnrichment.Results | list of all indicators found for the url. | array |
| URLEnrichment.Results.Brand | the brand of the indicator. | string |
| URLEnrichment.Results.Score | the score of the indicator. | number |
| URLEnrichment.Results.DetectionEngines | the detection engines of the indicator. | number |
| URLEnrichment.Results.PositiveDetections | the positive detections of the indicator. | number |
| URLEnrichment.Results.AdditionalFields | Secondary fields. Only available if the additional_fields argument is set to true. | Object |
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
| WildFire.Verdicts.VerdictDescription | Description of the verdict. | string |
| WildFire.Verdicts.AnalysisTime | Verdict analysis time. | Date |
| WildFire.Verdicts.URL | The URL of the web page. | String |
| WildFire.Verdicts.Valid | Is the URL valid. | String |
| WildFire.Verdicts.Verdict | Verdict of the URL. | Number |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Reliability | The reliability of the score. | string |
