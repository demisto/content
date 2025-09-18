This script gathers IP reputation data from multiple integrations and returns an IP entity with consolidated information in the context.

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
| ip_list | A comma-separated list of IPs to enrich. |
| external_enrichment | Whether to call external integrations for enrichment: - 'true': enrich using enabled external integrations \(e.g., VirusTotal \(API v3\), AlienVault OTX v2\) and run internal commands. - 'false': use only existing TIM data and run internal commands; skip external integrations. If the 'brands' argument is provided, this flag is ignored and enrichment/internal commands will run only on the brands provided. |
| verbose | Retrieve a human-readable entry for each command; if false, only the final result is summarized and errors are suppressed. |
| brands | A list of integration brands to run enrichment against.  <br/>Example: \`"VirusTotal \(API v3\), AlienVault OTX v2"\`.<br/>- If provided, only the selected brands are used.<br/>- If left empty, the script runs enrichment on all enabled integrations,<br/>  depending on the \`external_enrichment\` flag.<br/>- In order to run get-endpoint-data add Core to the brands list.<br/>- In order to run core-get-IP-analytics-prevalence, add Cortex Core - IR to the brands list.<br/>To see the available brands for the \`ip\` command, run: \`\!ProvidesCommand command=ip\`.<br/> |
| additional_fields | When set to true, the output includes an \`AdditionalFields\` object<br/>for each of the indicator result.  <br/>\`AdditionalFields\` contains all fields returned by TIM or the integrations<br/>that are not part of the standard output keys: \`Address\`, \`DetectionEngines\`, <br/>\`PositiveDetections\`, \`Score\`, and \`Brand\`.  <br/>When set to false, only the standard keys are returned.<br/> |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IPEnrichment.Value | The IP address. | string |
| IPEnrichment.MaxScore | The max score of all the indicators found. | number |
| IPEnrichment.MaxVerdict | The max verdict of all the indicators found. | string |
| IPEnrichment.TIMScore | The TIM score of the IP address. | number |
| IPEnrichment.Results | A list of all indicators found for the IP address. | array |
| IPEnrichment.Status | The status of the indicator: "Manual" if the score was changed manually, "Fresh" if modified within the last week, "Stale" if modified more than a week ago, and "None" if never modified. | string |
| IPEnrichment.ModifiedTime | The time the indicator was last modified. | Date |
| IPEnrichment.Results.Source | The source of the indicator. | string |
| IPEnrichment.Results.Brand | The brand of the indicator. | string |
| IPEnrichment.Results.DetectionEngines | The detection engines of the indicator. | number |
| IPEnrichment.Results.PositiveDetections | The positive detections of the indicator. | number |
| IPEnrichment.Results.ASOwner | Registered owner of the Autonomous System announcing the IP prefix. | string |
| IPEnrichment.Results.Score | The score of the indicator. | number |
| IPEnrichment.Results.Verdict | The verdict of the indicator. | string |
| IPEnrichment.Results.Address | The IP address of the indicator. | string |
| IPEnrichment.Results.AdditionalFields | All fields extracted from the indicator other then the main keys \("Brand", "Score", "Verdict", "DetectionEngines", "PositiveDetections", "Address"\). | list |
| IPEnrichment.Results.AdditionalFields.Relationships.EntityA | The source of the relationship. | string |
| IPEnrichment.Results.AdditionalFields.Relationships.EntityB | The destination of the relationship. | string |
| IPEnrichment.Results.AdditionalFields.Relationships.Relationship | The name of the relationship. | string |
| IPEnrichment.Results.AdditionalFields.Relationships.EntityAType | The type of the source of the relationship. | string |
| IPEnrichment.Results.AdditionalFields.Relationships.EntityBType | The type of the destination of the relationship. | string |
| IPEnrichment.Results.AdditionalFields.ASN | The autonomous system name for the IP address, for example: "AS8948". | String |
| IPEnrichment.Results.AdditionalFields.Hostname | The hostname that is mapped to this IP address. | String |
| IPEnrichment.Results.AdditionalFields.Geo.Location | The geolocation where the IP address is located, in the format: latitude:longitude. | String |
| IPEnrichment.Results.AdditionalFields.Geo.Country | The country in which the IP address is located. | String |
| IPEnrichment.Results.AdditionalFields.Geo.Description | Additional information about the location. | String |
| IPEnrichment.Results.AdditionalFields.Malicious.Vendor | The vendor reporting the IP address as malicious. | String |
| IPEnrichment.Results.AdditionalFields.Malicious.Description | A description explaining why the IP address was reported as malicious. | String |
| IPEnrichment.Results.AdditionalFields.Tags | \(List\) Tags of the IP. | Unknown |
| IPEnrichment.Results.AdditionalFields.FeedRelatedIndicators.value | Indicators that are associated with the IP. | String |
| IPEnrichment.Results.AdditionalFields.FeedRelatedIndicators.type | The type of the indicators that are associated with the IP. | String |
| IPEnrichment.Results.AdditionalFields.FeedRelatedIndicators.description | The description of the indicators that are associated with the IP. | String |
| IPEnrichment.Results.AdditionalFields.MalwareFamily | The malware family associated with the IP. | String |
| IPEnrichment.Results.AdditionalFields.Organization.Name | The organization of the IP. | String |
| IPEnrichment.Results.AdditionalFields.Organization.Type | The organization type of the IP. | String |
| IPEnrichment.Results.AdditionalFields.Region | The region in which the IP is located. | String |
| IPEnrichment.Results.AdditionalFields.Port | Ports that are associated with the IP. | String |
| IPEnrichment.Results.AdditionalFields.Internal | Whether or not the IP is internal or external. | Bool |
| IPEnrichment.Results.AdditionalFields.UpdatedDate | The date that the IP was last updated. | Date |
| IPEnrichment.Results.AdditionalFields.Registrar.Abuse.Name | The name of the contact for reporting abuse. | String |
| IPEnrichment.Results.AdditionalFields.Registrar.Abuse.Address | The address of the contact for reporting abuse. | String |
| IPEnrichment.Results.AdditionalFields.Registrar.Abuse.Country | The country of the contact for reporting abuse. | String |
| IPEnrichment.Results.AdditionalFields.Registrar.Abuse.Network | The network of the contact for reporting abuse. | String |
| IPEnrichment.Results.AdditionalFields.Registrar.Abuse.Phone | The phone number of the contact for reporting abuse. | String |
| IPEnrichment.Results.AdditionalFields.Registrar.Abuse.Email | The email address of the contact for reporting abuse. | String |
| IPEnrichment.Results.AdditionalFields.Campaign | The campaign associated with the IP. | String |
| IPEnrichment.Results.AdditionalFields.TrafficLightProtocol | The Traffic Light Protocol \(TLP\) color that is suitable for the IP. | String |
| IPEnrichment.Results.AdditionalFields.CommunityNotes.note | Notes on the IP that were given by the community. | String |
| IPEnrichment.Results.AdditionalFields.CommunityNotes.timestamp | The time in which the note was published. | Date |
| IPEnrichment.Results.AdditionalFields.Publications.source | The source in which the article was published. | String |
| IPEnrichment.Results.AdditionalFields.Publications.title | The name of the article. | String |
| IPEnrichment.Results.AdditionalFields.Publications.link | A link to the original article. | String |
| IPEnrichment.Results.AdditionalFields.Publications.timestamp | The time in which the article was published. | Date |
| IPEnrichment.Results.AdditionalFields.ThreatTypes.threatcategory | The threat category associated to this indicator by the source vendor, for example, Phishing, Control, TOR, etc. | String |
| IPEnrichment.Results.AdditionalFields.ThreatTypes.threatcategoryconfidence | Threat Category Confidence is the confidence level provided by the vendor for the threat type category. For example, a confidence level of 90 for the 'malware' threat type category means that the vendor is confident that its 90% malware. | String |
| Core.AnalyticsPrevalence.Ip.value | Whether the IP address is prevalent or not. | Boolean |
| Core.AnalyticsPrevalence.Ip.data.global_prevalence.value | The global prevalence of the IP. | Number |
| Core.AnalyticsPrevalence.Ip.data.local_prevalence.value | The local prevalence of the IP. | Number |
| Core.AnalyticsPrevalence.Ip.data.prevalence.value | The prevalence of the IP. | Number |
| EndpointData.Hostname.value | The endpoint's hostname. | String |
| EndpointData.Hostname.source | The vendor from which the hostname of this endpoint was retrieved. | String |
| EndpointData.EntityA.value | The source of the relationship. | String |
| EndpointData.EntityA.source | The vendor from which EntityA of this endpoint was retrieved. | String |
| EndpointData.EntityB.value | The destination of the relationship. | String |
| EndpointData.EntityB.source | The vendor from which EntityB of this endpoint was retrieved. | String |
| EndpointData.Relationship.value | The name of the relationship. | String |
| EndpointData.Relationship.source | The vendor from which the relationship of this endpoint was retrieved. | String |
| EndpointData.EntityAType.value | The type of the source of the relationship. | String |
| EndpointData.EntityAType.source | The vendor from which the type of the source of the relationship of this endpoint was retrieved. | String |
| EndpointData.EntityBType.value | The type of the destination of the relationship. | String |
| EndpointData.EntityBType.source | The vendor from which the type of the destination of the relationship of this endpoint was retrieved. | String |
| EndpointData.ID.value | The endpoint's ID. | String |
| EndpointData.ID.source | The vendor from which the ID of this endpoint was retrieved. | String |
| EndpointData.IPAddress | The endpoint's IP address. | String |
| EndpointData.Domain.value | The endpoint's domain. | String |
| EndpointData.Domain.source | The vendor from which the domain of this endpoint was retrieved. | String |
| EndpointData.MACAddress.value | The endpoint's MAC address. | String |
| EndpointData.MACAddress.source | The vendor from which the MAC address of this endpoint was retrieved. | String |
| EndpointData.DHCPServer.value | The DHCP server of the endpoint. | String |
| EndpointData.DHCPServer.source | The vendor from which the DHCP server of this endpoint was retrieved. | String |
| EndpointData.OS.value | The endpoint's operating system. | String |
| EndpointData.OS.source | The vendor from which the operating system of this endpoint was retrieved. | String |
| EndpointData.OSVersion.value | The endpoint's operating system version. | String |
| EndpointData.OSVersion.source | The vendor from which the operating system version of this endpoint was retrieved. | String |
| EndpointData.BIOSVersion.value | The endpoint's BIOS version. | String |
| EndpointData.BIOSVersion.source | The vendor from which the BIOS version of this endpoint was retrieved. | String |
| EndpointData.Model.value | The model of the machine or device. | String |
| EndpointData.Model.source | The vendor from which the model of this endpoint was retrieved. | String |
| EndpointData.Memory.value | Amount of memory on this endpoint. | Integer |
| EndpointData.Memory.source | The vendor from which the amount of memory of this endpoint was retrieved. | String |
| EndpointData.Processors.value | The number of processors. | Integer |
| EndpointData.Processors.source | The vendor from which the processors of this endpoint was retrieved. | String |
| EndpointData.Processor.value | The model of the processor. | String |
| EndpointData.Processor.source | The vendor from which the processor of this endpoint was retrieved. | String |
| EndpointData.IsIsolated.value | The endpoint's isolation status. | String |
| EndpointData.IsIsolated.source | The vendor from which the isolation of this endpoint was retrieved. | String |
| EndpointData.Status.value | The endpoint's status. | String |
| EndpointData.Status.source | The vendor from which the status of this endpoint was retrieved. | String |
| EndpointData.Vendor.value | The integration name of the endpoint vendor. | String |
| EndpointData.Vendor.source | The vendor from which the Vendor of this endpoint was retrieved. | String |
