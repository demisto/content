This script gathers CVE reputation data from multiple integrations and returns a "CVEEnrichment" object with consolidated information to the context output.

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

* CVEEnrichment-Test

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| cve_list | A comma-separated list of CVEs to enrich. |
| external_enrichment | Whether to call external integrations for enrichment.<br/>- 'true': enrich using enabled external integrations \(e.g., CIRCL CVE Search, CVE Search v2\).<br/>- 'false': use only existing TIM data; skip external integrations.<br/>If the 'brands' argument is provided, this flag is ignored and enrichment is run only on the brands provided.<br/> |
| verbose | Whether to retrieve a human-readable entry for every command; if false, only the final result is summarized and error entries are suppressed. |
| brands | A list of integration brands to run enrichment against.  <br/>Example: \`"CIRCL CVE Search, CVE Search v2"\`.  <br/>- If provided, only the selected brands are used. <br/>- If left empty, the script runs enrichment on all enabled integrations,<br/>  depending on the \`external_enrichment\` flag.<br/>To see the available brands for the \`cve\` command, run: \`\!ProvidesCommand command=cve\`.<br/> |
| additional_fields | When set to true, the output will also include an \`AdditionalFields\` object<br/>for each of the indicator result.  <br/>\`AdditionalFields\` contains all fields returned by TIM or the integrations<br/>that are not part of the standard output keys: \`ID\`, \`Brand\`, \`CVSS\`, <br/>\`Description\`, \`Published\`, \`CVSS\`.  <br/>When set to false, only the standard keys are returned.<br/> |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CVEEnrichment.Value | The CVE. | string |
| CVEEnrichment.MaxCVSS | The max CVSS of the indicator. | number |
| CVEEnrichment.MaxCVSSRating | The max CVSS rating of the indicator. | string |
| CVEEnrichment.Results | List of all indicators found for the CVE. | array |
| CVEEnrichment.Status | The status of the indicator. | string |
| CVEEnrichment.Results.Brand | The brand of the indicator. | string |
| CVEEnrichment.Results.CVSS | The CVSS of the indicator. | number |
| CVEEnrichment.Results.Description | The description of the indicator. | string |
| CVEEnrichment.Results.Published | The published date of the indicator. | string |
| CVEEnrichment.Results.Status | The status of the indicator: "Manual" if the score was changed manually, "Fresh" if modified within the last week, "Stale" if modified more than a week ago, and "None" if never modified. | string |
| CVEEnrichment.Results.ModifiedTime | The time the indicator was last modified. | Date |
| CVEEnrichment.Results.AdditionalFields | All fields extracted from the indicator other then the main keys \("ID", "Brand", "CVSS", "Description", "Published", "CVSS"\). | Object |
| CVEEnrichment.Results.AdditionalFields.Relationships.EntityA | The source of the relationship. | string |
| CVEEnrichment.Results.AdditionalFields.Relationships.EntityB | The destination of the relationship. | string |
| CVEEnrichment.Results.AdditionalFields.Relationships.Relationship | The name of the relationship. | string |
| CVEEnrichment.Results.AdditionalFields.Relationships.EntityAType | The type of the source of the relationship. | string |
| CVEEnrichment.Results.AdditionalFields.Relationships.EntityBType | The type of the destination of the relationship. | string |
| CVEEnrichment.Results.AdditionalFields.Modified | The timestamp of when the CVE was last modified. | Date |
