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
| external_enrichment | Set to true to run reputation commands from external sources. If false (default), the script only queries internal sources as TIM and wildfire-get-verdict. Note, providing a value for the brands argument overrides this option. |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result and suppress error entries from commands. |
| brands | A comma-separated list of specific integration brands to use for enrichment, e.g., "VirusTotal,CrowdStrike". If empty, runs against all enabled integrations according to the 'external_enrichment' flag. Run !ProvidesCommand command=url to see available integrations. Add WildfFire-v2 in order to run wildfire-get-verdict. |
| additional_fields | Whether to return unmapped \(secondary\) fields to the context output under the "URLEnrichment.results.AdditionalFields" path. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URLEnrichment.Data | the url it self | string |
| URLEnrichment.max_score | the max score of all the indicators found | number |
| URLEnrichment.max_verdict | the max verdict of all the indicators found | string |
| URLEnrichment.results | list of all indicators found for the url | array |
| URLEnrichment.results.Brand | the brand of the indicator | string |
| URLEnrichment.results.score | the score of the indicator | number |
| URLEnrichment.results.detection_engines | the detection engines of the indicator | number |
| URLEnrichment.results.positive_detections | the positive detections of the indicator | number |
| URLEnrichment.results.additional_fields | Unmapped \(secondary\) fields. Only available if the additional_fields argument is set to true. | Object |
| WildFire.Verdicts.MD5 | MD5 hash of the file. | string |
| WildFire.Verdicts.SHA256 | SHA256 hash of the file. | string |
| WildFire.Verdicts.VerdictDescription | Description of the file verdict. | string |
| WildFire.Verdicts.AnalysisTime | Verdict analysis time. | Date |
| WildFire.Verdicts.URL | The URL of the web page. | String |
| WildFire.Verdicts.Valid | Is the URL valid. | String |
| WildFire.Verdicts.Verdict | Verdict of the file. | Number |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Reliability | The reliability of the score. | string |
