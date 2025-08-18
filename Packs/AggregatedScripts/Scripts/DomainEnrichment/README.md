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
| external_enrichment | When set to 'true', the script runs reputation commands using all available external integrations. This is ignored if the 'brands' argument is used, as 'brands' provides an explicit list of integrations to run. |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result and suppress error entries from commands. |
| brands | A comma-separated list of specific integration brands to use for enrichment, e.g., "VirusTotal,CrowdStrike". If left empty, the script runs on all enabled integrations according to the 'external_enrichment' flag.<br/>Run \!ProvidesCommand command=domain to see available integrations.<br/>Add Cortex Core - IR to run core-get-domain-analytics-prevalence. |
| additional_fields | Whether to return secondary fields to the context output under "AdditionalFields". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DomainEnrichment.Value | the domain it self. | string |
| DomainEnrichment.MaxScore | the max score of all the indicators found. | number |
| DomainEnrichment.MaxVerdict | the max verdict of all the indicators found. | string |
| DomainEnrichment.Results | list of all indicators found for the domain. | array |
| DomainEnrichment.Results.Brand | the brand of the indicator. | string |
| DomainEnrichment.Results.Score | the score of the indicator. | number |
| DomainEnrichment.Results.DetectionEngines | the detection engines of the indicator. | number |
| DomainEnrichment.Results.PositiveDetections | the positive detections of the indicator. | number |
| DomainEnrichment.Results.AdditionalFields | Unmapped \(secondary\) fields. Only available if the additional_fields argument is set to true. | Object |
| DomainEnrichment.Results.AdditionalFields.Relationships.EntityA | The source of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.Relationships.EntityB | The destination of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.Relationships.Relationship | The name of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.Relationships.EntityAType | The type of the source of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.Relationships.EntityBType | The type of the destination of the relationship. | string |
| DomainEnrichment.Results.AdditionalFields.DNS | A list of IP objects resolved by DNS. | String |
| DomainEnrichment.Results.AdditionalFields.CreationDate | The date that the domain was created. | Date |
| DomainEnrichment.Results.AdditionalFields.UpdatedDate | The date that the domain was last updated. | String |
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
| DomainEnrichment.Results.AdditionalFields.Registrant.Phone | The phone number for receiving abuse reports. | String |
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
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrar.Name | The name of the registrar, for example GoDaddy. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrar.AbuseEmail | The email address of the contact for reporting abuse. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Registrar.AbusePhone | The phone number of contact for reporting abuse. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Admin.Name | The name of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Admin.Email | The email address of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.Admin.Phone | The phone number of the domain administrator. | String |
| DomainEnrichment.Results.AdditionalFields.WHOIS.History | List of Whois object. | String |
| DomainEnrichment.Results.AdditionalFields.Malicious.Vendor | The vendor reporting the domain as malicious. | String |
| DomainEnrichment.Results.AdditionalFields.Malicious.Description | A description explaining why the domain was reported as malicious. | String |
| DomainEnrichment.Results.AdditionalFields.DomainIDNName | The internationalized domain name \(IDN\) of the domain. | String |
| DomainEnrichment.Results.AdditionalFields.Port | Ports that are associated with the domain. | String |
| DomainEnrichment.Results.AdditionalFields.Internal | Whether or not the domain is internal or external. | Bool |
| DomainEnrichment.Results.AdditionalFields.Category | The category associated with the indicator. | String |
| DomainEnrichment.Results.AdditionalFields.Campaign | The campaign associated with the domain. | String |
| DomainEnrichment.Results.AdditionalFields.TrafficLightProtocol | The Traffic Light Protocol \(TLP\) color that is suitable for the domain. | String |
| DomainEnrichment.Results.AdditionalFields.ThreatTypes.threatcategory | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. | String |
| DomainEnrichment.Results.AdditionalFields.ThreatTypes.threatcategoryconfidence | Threat Category Confidence is the confidence level provided by the vendor for the threat type category For example a confidence of 90 for threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. | String |
| DomainEnrichment.Results.AdditionalFields.Geo.Location | The geolocation where the domain address is located, in the format: latitude:longitude. | String |
| DomainEnrichment.Results.AdditionalFields.Geo.Country | The country in which the domain address is located. | String |
| DomainEnrichment.Results.AdditionalFields.Geo.Description | Additional information about the location. | String |
| DomainEnrichment.Results.AdditionalFields.Tech.Country | The country of the domain technical contact. | String |
| DomainEnrichment.Results.AdditionalFields.Tech.Name | The name of the domain technical contact. | String |
| DomainEnrichment.Results.AdditionalFields.Tech.Organization | The organization of the domain technical contact. | String |
| DomainEnrichment.Results.AdditionalFields.Tech.Email | The email address of the domain technical contact. | String |
| DomainEnrichment.Results.AdditionalFields.CommunityNotes.note | Notes on the domain that were given by the community. | String |
| DomainEnrichment.Results.AdditionalFields.CommunityNotes.timestamp | The time in which the note was published. | Date |
| DomainEnrichment.Results.AdditionalFields.Publications.source | The source in which the article was published. | String |
| DomainEnrichment.Results.AdditionalFields.Publications.title | The name of the article. | String |
| DomainEnrichment.Results.AdditionalFields.Publications.link | A link to the original article. | String |
| DomainEnrichment.Results.AdditionalFields.Publications.timestamp | The time in which the article was published. | Date |
| DomainEnrichment.Results.AdditionalFields.Billing | The billing address of the domain. | String |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Reliability | The reliability of the score. | string |
| Core.AnalyticsPrevalence.Domain.value | Whether the domain is prevalent or not. | Boolean |
| Core.AnalyticsPrevalence.Domain.data.global_prevalence.value | The global prevalence of the domain. | Number |
| Core.AnalyticsPrevalence.Domain.data.local_prevalence.value | The local prevalence of the domain. | Number |
| Core.AnalyticsPrevalence.Domain.data.prevalence.value | The prevalence of the domain. | Number |
