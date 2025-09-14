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
| external_enrichment | When set to 'true', the script runs reputation commands using all available external integrations. This is ignored if the 'brands' argument is used, as 'brands' provides an explicit list of integrations to run. |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result and suppress error entries from commands. |
| brands | A comma-separated list of specific integration brands to use for enrichment, e.g., "VirusTotal,CrowdStrike". If left empty, the script runs on all enabled integrations according to the 'external_enrichment' flag. <br/>Run \!ProvidesCommand command=cve to see available integrations. |
| additional_fields | Whether to return secondary fields to the context output under "AdditionalFields". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CVEEnrichment.Value | the cve it self. | string |
| CVEEnrichment.Results | list of all indicators found for the cve. | array |
| CVEEnrichment.Results.Brand | the brand of the indicator. | string |
| CVEEnrichment.Results.CVSS | the CVSS of the indicator. | number |
| CVEEnrichment.Results.Description | the description of the indicator. | string |
| CVEEnrichment.Results.Published | the published date of the indicator. | string |
| CVEEnrichment.Results.additionalFields | Unmapped \(secondary\) fields. Only available if the additional_fields argument is set to true. | Object |
| CVEEnrichment.Results.additionalFields.Relationships.EntityA | The source of the relationship. | string |
| CVEEnrichment.Results.additionalFields.Relationships.EntityB | The destination of the relationship. | string |
| CVEEnrichment.Results.additionalFields.Relationships.Relationship | The name of the relationship. | string |
| CVEEnrichment.Results.additionalFields.Relationships.EntityAType | The type of the source of the relationship. | string |
| CVEEnrichment.Results.additionalFields.Relationships.EntityBType | The type of the destination of the relationship. | string |
| CVEEnrichment.Results.additionalFields.Modified | The timestamp of when the CVE was last modified. | Date |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Reliability | The reliability of the score. | string |
