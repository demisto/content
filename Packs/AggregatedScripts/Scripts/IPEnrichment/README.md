This script gathers ip reputation data from multiple integrations and returns an ip entity with consolidated information to the context.

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
| ip_list | A comma-separated list of IPs to enrich. |
| external_enrichment | When set to 'true', the script runs reputation commands using all available external integrations. This is ignored if the 'brands' argument is used, as 'brands' provides an explicit list of integrations to run. |
| verbose | Whether to retrieve a human-readable entry for every command. When set to false, human-readable will only summarize the final result and suppress error entries from commands. |
| brands | A comma-separated list of specific integration brands to use for enrichment, e.g., "VirusTotal,CrowdStrike". If left empty, the script runs on all enabled integrations according to the 'external_enrichment' flag.<br/>Run \!ProvidesCommand command=ip to see available integrations.<br/>Add Cortex Core - IR to run core-get-IP-analytics-prevalence or Script to run get-endpoint-data. |
| additional_fields | Whether to return secondary fields to the context output under "AdditionalFields". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IPEnrichment.Value | the ip address . | string |
| IPEnrichment.MaxScore | the max score of all the indicators found. | number |
| IPEnrichment.MaxVerdict | the max verdict of all the indicators found. | string |
| IPEnrichment.Results | list of all indicators found for the ip. | array |
| IPEnrichment.Results.Source | the source of the indicator. | string |
| IPEnrichment.Results.Brand | the brand of the indicator. | string |
| IPEnrichment.Results.DetectionEngines | the detection engines of the indicator. | number |
| IPEnrichment.Results.PositiveDetections | the positive detections of the indicator. | number |
| IPEnrichment.Results.ASOwner | the AS owner of the indicator. | string |
| IPEnrichment.Results.Score | the score of the indicator. | number |
| IPEnrichment.Results.Verdict | the verdict of the indicator. | string |
| IPEnrichment.Results.additionalFields | Unmapped \(secondary\) fields. Only available if the additional_fields argument is set to true. | list |
| IPEnrichment.Results.additionalFields.Relationships.EntityA | The source of the relationship. | string |
| IPEnrichment.Results.additionalFields.Relationships.EntityB | The destination of the relationship. | string |
| IPEnrichment.Results.additionalFields.Relationships.Relationship | The name of the relationship. | string |
| IPEnrichment.Results.additionalFields.Relationships.EntityAType | The type of the source of the relationship. | string |
| IPEnrichment.Results.additionalFields.Relationships.EntityBType | The type of the destination of the relationship. | string |
| IPEnrichment.Results.additionalFields.ASN | The autonomous system name for the IP address, for example: "AS8948". | String |
| IPEnrichment.Results.additionalFields.Hostname | The hostname that is mapped to this IP address. | String |
| IPEnrichment.Results.additionalFields.Geo.Location | The geolocation where the IP address is located, in the format: latitude:longitude. | String |
| IPEnrichment.Results.additionalFields.Geo.Country | The country in which the IP address is located. | String |
| IPEnrichment.Results.additionalFields.Geo.Description | Additional information about the location. | String |
| IPEnrichment.Results.additionalFields.Malicious.Vendor | The vendor reporting the IP address as malicious. | String |
| IPEnrichment.Results.additionalFields.Malicious.Description | A description explaining why the IP address was reported as malicious. | String |
| IPEnrichment.Results.additionalFields.Tags | \(List\) Tags of the IP. | Unknown |
| IPEnrichment.Results.additionalFields.FeedRelatedIndicators.value | Indicators that are associated with the IP. | String |
| IPEnrichment.Results.additionalFields.FeedRelatedIndicators.type | The type of the indicators that are associated with the IP. | String |
| IPEnrichment.Results.additionalFields.FeedRelatedIndicators.description | The description of the indicators that are associated with the IP. | String |
| IPEnrichment.Results.additionalFields.MalwareFamily | The malware family associated with the IP. | String |
| IPEnrichment.Results.additionalFields.Organization.Name | The organization of the IP. | String |
| IPEnrichment.Results.additionalFields.Organization.Type | The organization type of the IP. | String |
| IPEnrichment.Results.additionalFields.Region | The region in which the IP is located. | String |
| IPEnrichment.Results.additionalFields.Port | Ports that are associated with the IP. | String |
| IPEnrichment.Results.additionalFields.Internal | Whether or not the IP is internal or external. | Bool |
| IPEnrichment.Results.additionalFields.UpdatedDate | The date that the IP was last updated. | Date |
| IPEnrichment.Results.additionalFields.Registrar.Abuse.Name | The name of the contact for reporting abuse. | String |
| IPEnrichment.Results.additionalFields.Registrar.Abuse.Address | The address of the contact for reporting abuse. | String |
| IPEnrichment.Results.additionalFields.Registrar.Abuse.Country | The country of the contact for reporting abuse. | String |
| IPEnrichment.Results.additionalFields.Registrar.Abuse.Network | The network of the contact for reporting abuse. | String |
| IPEnrichment.Results.additionalFields.Registrar.Abuse.Phone | The phone number of the contact for reporting abuse. | String |
| IPEnrichment.Results.additionalFields.Registrar.Abuse.Email | The email address of the contact for reporting abuse. | String |
| IPEnrichment.Results.additionalFields.Campaign | The campaign associated with the IP. | String |
| IPEnrichment.Results.additionalFields.TrafficLightProtocol | The Traffic Light Protocol \(TLP\) color that is suitable for the IP. | String |
| IPEnrichment.Results.additionalFields.CommunityNotes.note | Notes on the IP that were given by the community. | String |
| IPEnrichment.Results.additionalFields.CommunityNotes.timestamp | The time in which the note was published. | Date |
| IPEnrichment.Results.additionalFields.Publications.source | The source in which the article was published. | String |
| IPEnrichment.Results.additionalFields.Publications.title | The name of the article. | String |
| IPEnrichment.Results.additionalFields.Publications.link | A link to the original article. | String |
| IPEnrichment.Results.additionalFields.Publications.timestamp | The time in which the article was published. | Date |
| IPEnrichment.Results.additionalFields.ThreatTypes.threatcategory | The threat category associated to this indicator by the source vendor. For example, Phishing, Control, TOR, etc. | String |
| IPEnrichment.Results.additionalFields.ThreatTypes.threatcategoryconfidence | Threat Category Confidence is the confidence level provided by the vendor for the threat type category For example a confidence of 90 for threat type category 'malware' means that the vendor rates that this is 90% confidence of being a malware. | String |
| Core.AnalyticsPrevalence.Ip.value | Whether the IP address is prevalent or not. | Boolean |
| Core.AnalyticsPrevalence.Ip.data.global_prevalence.value | The global prevalence of the IP. | Number |
| Core.AnalyticsPrevalence.Ip.data.local_prevalence.value | The local prevalence of the IP. | Number |
| Core.AnalyticsPrevalence.Ip.data.prevalence.value | The prevalence of the IP. | Number |
| Endpoint.Hostname.value | The endpoint's hostname. | String |
| Endpoint.Hostname.source | The vendor from which the hostname of this endpoint was retrieved. | String |
| Endpoint.EntityA.value | The source of the relationship. | String |
| Endpoint.EntityA.source | The vendor from which EntityA of this endpoint was retrieved. | String |
| Endpoint.EntityB.value | The destination of the relationship. | String |
| Endpoint.EntityB.source | The vendor from which EntityB of this endpoint was retrieved. | String |
| Endpoint.Relationship.value | The name of the relationship. | String |
| Endpoint.Relationship.source | The vendor from which the relationship of this endpoint was retrieved. | String |
| Endpoint.EntityAType.value | The type of the source of the relationship. | String |
| Endpoint.EntityAType.source | The vendor from which the type of the source of the relationship of this endpoint was retrieved. | String |
| Endpoint.EntityBType.value | The type of the destination of the relationship. | String |
| Endpoint.EntityBType.source | The vendor from which the type of the destination of the relationship of this endpoint was retrieved. | String |
| Endpoint.ID.value | The endpoint's ID. | String |
| Endpoint.ID.source | The vendor from which the ID of this endpoint was retrieved. | String |
| Endpoint.IPAddress.value | The endpoint's IP address. | String |
| Endpoint.IPAddress.source | The vendor from which the IP address of this endpoint was retrieved. | String |
| Endpoint.Domain.value | The endpoint's domain. | String |
| Endpoint.Domain.source | The vendor from which the domain of this endpoint was retrieved. | String |
| Endpoint.MACAddress.value | The endpoint's MAC address. | String |
| Endpoint.MACAddress.source | The vendor from which the MAC address of this endpoint was retrieved. | String |
| Endpoint.DHCPServer.value | The DHCP server of the endpoint. | String |
| Endpoint.DHCPServer.source | The vendor from which the DHCP server of this endpoint was retrieved. | String |
| Endpoint.OS.value | The endpoint's operating system. | String |
| Endpoint.OS.source | The vendor from which the operating system of this endpoint was retrieved. | String |
| Endpoint.OSVersion.value | The endpoint's operating system version. | String |
| Endpoint.OSVersion.source | The vendor from which the operating system version of this endpoint was retrieved. | String |
| Endpoint.BIOSVersion.value | The endpoint's BIOS version. | String |
| Endpoint.BIOSVersion.source | The vendor from which the BIOS version of this endpoint was retrieved. | String |
| Endpoint.Model.value | The model of the machine or device. | String |
| Endpoint.Model.source | The vendor from which the model of this endpoint was retrieved. | String |
| Endpoint.Memory.value | Amount of memory on this endpoint. | Integer |
| Endpoint.Memory.source | The vendor from which the amount of memory of this endpoint was retrieved. | String |
| Endpoint.Processors.value | The number of processors. | Integer |
| Endpoint.Processors.source | The vendor from which the processors of this endpoint was retrieved. | String |
| Endpoint.Processor.value | The model of the processor. | String |
| Endpoint.Processor.source | The vendor from which the processor of this endpoint was retrieved. | String |
| Endpoint.IsIsolated.value | The endpoint's isolation status. | String |
| Endpoint.IsIsolated.source | The vendor from which the isolation of this endpoint was retrieved. | String |
| Endpoint.Status.value | The endpoint's status. | String |
| Endpoint.Status.source | The vendor from which the status of this endpoint was retrieved. | String |
| Endpoint.Vendor.value | The integration name of the endpoint vendor. | String |
| Endpoint.Vendor.source | The vendor from which the Vendor of this endpoint was retrieved. | String |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | Vendor used to calculate the score. | string |
| DBotScore.Score | The actual score. | number |
| DBotScore.Reliability | The reliability of the score. | string |
