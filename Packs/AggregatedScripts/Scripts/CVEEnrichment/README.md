This script gathers CVE reputation data from multiple integrations and returns a "CVEEnrichment" object with consolidated information to the context output.

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
| cve_list | A comma-separated list of CVEs to enrich. |
| external_enrichment | Set to true to run reputation commands from external sources. If false \\\(default\\\), the script only queries internal sources as TIM. Note, providing a value for the brands argument overrides this option. |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result and suppress error entries from commands. |
| brands | A comma-separated list of specific integration brands to use for enrichment, e.g., "VirusTotal,CrowdStrike". If empty, and external_enrichment is true will run on all external integrations. |
| additional_fields | Whether to return unmapped \(secondary\) fields to the context output under the "CVE.AdditionalFields" path. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CveEnrichment.ID | the cve it self | string |
| CveEnrichment.Results | list of all indicators found for the cve | array |
| CveEnrichment.Results.Brand | the brand of the indicator | string |
| CveEnrichment.Results.CVSS | the CVSS of the indicator | number |
| CveEnrichment.Results.Description | the description of the indicator | string |
| CveEnrichment.Results.Published | the published date of the indicator | string |
| CveEnrichment.Results.additional_fields | Unmapped \(secondary\) fields. Only available if the additional_fields argument is set to true. | Object |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Reliability | The reliability of the score. | string |
