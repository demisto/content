This script gathers domain reputation data from multiple integrations and returns a "DomainEnrichment" object with consolidated information to the context output.

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
| domain_list | A comma-separated list of domains to enrich. |
| external_enrichment | Set to true to run reputation commands from external sources. If false (default), the script only queries internal sources as TIM and core-get-domain-analytics-prevalence. Note, providing a value for the brands argument overrides this option. |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result and suppress error entries from commands. |
| brands | A comma-separated list of specific integration brands to use for enrichment, e.g., "VirusTotal,CrowdStrike". If empty, runs against all internal integrations and if external_enrichment is true will run on all external integrations. |
| additional_fields | Whether to return unmapped \(secondary\) fields to the context output under the "DomainEnrichment.results.AdditionalFields" path. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DomainEnrichment.Data | the domain it self | string |
| DomainEnrichment.max_score | the max score of all the indicators found | number |
| DomainEnrichment.max_verdict | the max verdict of all the indicators found | string |
| DomainEnrichment.results | list of all indicators found for the domain | array |
| DomainEnrichment.results.Brand | the brand of the indicator | string |
| DomainEnrichment.results.score | the score of the indicator | number |
| DomainEnrichment.results.detection_engines | the detection engines of the indicator | number |
| DomainEnrichment.results.positive_detections | the positive detections of the indicator | number |
| DomainEnrichment.results.additional_fields | Unmapped \(secondary\) fields. Only available if the additional_fields argument is set to true. | Object |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Reliability | The reliability of the score. | string |
| Core.AnalyticsPrevalence.Domain.value | Whether the domain is prevalent or not. | Boolean |
| Core.AnalyticsPrevalence.Domain.data.global_prevalence.value | The global prevalence of the domain. | Number |
| Core.AnalyticsPrevalence.Domain.data.local_prevalence.value | The local prevalence of the domain. | Number |
| Core.AnalyticsPrevalence.Domain.data.prevalence.value | The prevalence of the domain. | Number |
