This script enriches Domains data with information from multiple integrations and returns a "DomainEnrichment" object with consolidated information in the context output.

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
| domain_list | Accepts a list of domains to enrich.<br/>- From CLI: Provide a comma-separated list.  <br/>  If a Domain contains a comma, wrap the domains in a JSON array.  <br/>  Example: "\[\\"example.com/search:yellow,red\\", \\"example2.com\\"\]".<br/>- From Context: Pass JSON arrays directly, without modification.<br/> |
| external_enrichment | Whether to call external integrations for enrichment: - 'true': enrich using enabled external integrations \(e.g., VirusTotal \(API v3\), AlienVault OTX v2\) and run internal commands. - 'false': use only existing TIM data and run internal commands; skip external integrations. If the 'brands' argument is provided, this flag is ignored and enrichment/internal commands will run only on the brands provided. |
| verbose | Retrieve a human-readable entry for each command; if false, only the final result is summarized and errors are suppressed. |
| brands | A list of integration brands to run enrichment against.  <br/>Example: \`"VirusTotal \(API v3\), AlienVault OTX v2"\`.<br/>- If provided, only the selected brands are used.<br/>- If left empty, the script runs enrichment on all enabled integrations,<br/>  depending on the \`external_enrichment\` flag.<br/>- In order to run core-get-IP-analytics-prevalence, add Cortex Core - IR to the brands list.<br/>To see the available brands for the \`domain\` command, run: \`\!ProvidesCommand command=domain\`.<br/> |
| additional_fields | When set to true, the output includes an \`AdditionalFields\` object  <br/>for each of the indicator result.  <br/>\`AdditionalFields\` contains all fields returned by TIM or the integrations<br/>that are not part of the standard output keys: \`Name\`, \`Brand\`, \`Score\`, \`Verdict\`, \`DetectionEngines\`, <br/>\`PositiveDetections\`.  <br/>When set to false, only the standard keys are returned.<br/> |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DomainEnrichment.Value | The Domain. | string |
| DomainEnrichment.MaxScore | The max score of all the indicators found. | number |
| DomainEnrichment.MaxVerdict | The max verdict of all the indicators found. | string |
| DomainEnrichment.Results | List of all indicators found for the domain. | array |
| DomainEnrichment.TIMScore | The TIM score of the domain. | number |
| DomainEnrichment.Status | The status of the indicator: "Manual" if the score was changed manually, "Fresh" if modified within the last week, "Stale" if modified more than a week ago, and "None" if never modified. | string |
| DomainEnrichment.ModifiedTime | The time the indicator was last modified. | Date |
| DomainEnrichment.Results.Brand | The brand of the indicator. | string |
| DomainEnrichment.Results.Score | The score of the indicator. | number |
| DomainEnrichment.Results.Verdict | The verdict of the indicator. | string |
| DomainEnrichment.Results.DetectionEngines | The detection engines of the indicator. | number |
| DomainEnrichment.Results.PositiveDetections | The positive detections of the indicator. | number |
| DomainEnrichment.Results.Name | The Domain. | string |
| DomainEnrichment.Results.AdditionalFields | All fields extracted from the indicator other then the main keys \("Brand", "Score", "Verdict", "DetectionEngines", "PositiveDetections", "Name"\). | Object |
| DomainEnrichment.Results.AdditionalFields.Relationships.EntityA | The source of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.Relationships.EntityB | The destination of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.Relationships.Relationship | The name of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.Relationships.EntityAType | The type of the source of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.Relationships.EntityBType | The type of the destination of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.DNS | A list of IP objects resolved by DNS. | String |
| DomainEnrichment.Results.AdditionalFields.CreationDate | The date when the domain was created. | Date |
| DomainEnrichment.Results.AdditionalFields.UpdatedDate | The date when the domain was last updated. | String |
| DomainEnrichment.Results.AdditionalFields.ExpirationDate | The expiration date of the domain. | Date |
| DomainEnrichment.Results.AdditionalFields.DomainStatus | The status of the domain. | Datte |
| DomainEnrichment.Results.AdditionalFields.NameServers | \(List&lt;String&gt;\) Name servers of the domain. | Unknown |
| DomainEnrichment.Results.AdditionalFields.Organization | The organization of the domain. | String |
| DomainEnrichment.Results.AdditionalFields.Subdomains | \(List&lt;String&gt;\) Subdomains of the domain. | Unknown |
| DomainEnrichment.Results.AdditionalFields.Admin.Country | The country of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.Admin.Email | The email address of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.Admin.Name | The name of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.Admin.Phone | The phone number of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.Registrant.Country | The country of the registrant. | String |
| DomainEnrichment.Results.AdditionalFields.Registrant.Email | The email address of the registrant. | String |
| DomainEnrichment.Results.AdditionalFields.Registrant.Name | The name of the registrant. | String |
| DomainEnrichment.Results.AdditionalFields.Registrant.Phone | The phone number to receive abuse reports. | String |
| DomainEnrichment.Results.AdditionalFields.Tags | \(List\) Tags of the domain. | Unknown |
| DomainEnrichment.Results.AdditionalFields.FeedRelatedIndicators.value | Indicators that are associated with the domain. | String |
| DomainEnrichment.Results.AdditionalFields.FeedRelatedIndicators.type | The type of the indicators that are associated with the domain. | String |
| DomainEnrichment.Results.AdditionalFields.FeedRelatedIndicators.description | The description of the indicators that are associated with the domain. | String |
| DomainEnrichment.Results.AdditionalFields.MalwareFamily | The malware family associated with the domain. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.DomainStatus | The status of the domain. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.NameServers | \(List&lt;String&gt;\) Name servers of the domain. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.CreationDate | The date that the domain was created. | Date |
| DomainEnrichment.Results.AdditionalFields.WHOIS.UpdatedDate | The date that the domain was last updated. | Date |
| DomainEnrichment.Results.AdditionalFields.WHOIS.ExpirationDate | The expiration date of the domain. | Date |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrant.Name | The name of the registrant. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrant.Email | The email address of the registrant. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrant.Phone | The phone number of the registrant. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrar.Name | The name of the registrar, for example, GoDaddy. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrar.AbuseEmail | The email address of the contact to report abuse. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrar.AbusePhone | The phone number of the contact to report abuse. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Admin.Name | The name of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Admin.Email | The email address of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Admin.Phone | The phone number of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.History | List of Whois objects. | String |
| DomainEnrichment.Results.AdditionalFields.Malicious.Vendor | The vendor reporting the domain as malicious. | String |
| DomainEnrichment.Results.AdditionalFields.Malicious.Description | Reason the domain was reported as malicious. | String |
| DomainEnrichment.Results.AdditionalFields.DomainIDNName | The internationalized domain name \(IDN\) of the domain. | String |
| DomainEnrichment.Results.AdditionalFields.Port | Ports associated with the domain. | String |
| DomainEnrichment.Results.AdditionalFields.Internal | Whether the domain is internal or external. | Bool |
| DomainEnrichment.Results.AdditionalFields.Category | The category associated with the indicator. | String |
| DomainEnrichment.Results.AdditionalFields.Campaign | The campaign associated with the domain. | String |
| DomainEnrichment.Results.AdditionalFields.TrafficLightProtocol | The Traffic Light Protocol \(TLP\) color that is suitable for the domain. | String |
| DomainEnrichment.Results.AdditionalFields.ThreatTypes.threatcategory | The threat category associated to this indicator by the source vendor, for example, Phishing, Control, TOR, etc. | String |
| DomainEnrichment.Results.AdditionalFields.ThreatTypes.threatcategoryconfidence | Threat Category Confidence is the confidence level provided by the vendor for the threat type category. For example, a confidence of 90 for the threat type category 'malware' means the vendor estimates a 90% likelihood that it is malware. | String |
| DomainEnrichment.Results.AdditionalFields.Geo.Location | The geolocation where the domain address is located, in the format: latitude:longitude. | String |
| DomainEnrichment.Results.AdditionalFields.Geo.Country | The country in which the domain address is located. | String |
| DomainEnrichment.Results.AdditionalFields.Geo.Description | Additional information about the location. | String |
| DomainEnrichment.Results.AdditionalFields.Tech.Country | The country of the domain technical contact. | String |
| DomainEnrichment.Results.AdditionalFields.Tech.Name | The name of the domain technical contact. | String |
| DomainEnrichment.Results.AdditionalFields.Tech.Organization | The organization of the domain technical contact. | String |
| DomainEnrichment.Results.AdditionalFields.Tech.Email | The email address of the domain technical contact. | String |
| DomainEnrichment.Results.AdditionalFields.CommunityNotes.note | Notes on the domain that were given by the community. | String |
| DomainEnrichment.Results.AdditionalFields.CommunityNotes.timestamp | Time the note was published. | Date |
| DomainEnrichment.Results.AdditionalFields.Publications.source | The source where the article was published. | String |
| DomainEnrichment.Results.AdditionalFields.Publications.title | The name of the article. | String |
| DomainEnrichment.Results.AdditionalFields.Publications.link | A link to the original article. | String |
| DomainEnrichment.Results.AdditionalFields.Publications.timestamp | Time the article was published. | Date |
| DomainEnrichment.Results.AdditionalFields.Billing | Billing address of the domain. | String |
| Core.AnalyticsPrevalence.Domain.value | Whether the domain is prevalent or not. | Boolean |
| Core.AnalyticsPrevalence.Domain.data.global_prevalence.value | The global prevalence of the domain. | Number |
| Core.AnalyticsPrevalence.Domain.data.local_prevalence.value | The local prevalence of the domain. | Number |
| Core.AnalyticsPrevalence.Domain.data.prevalence.value | The prevalence of the domain. | Number |
