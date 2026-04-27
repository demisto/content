Enriches indicators from a provided list or a block of free text. This script detects the indicator type and runs the correct underlying enrichment script. Currently supports: IP, URL, Domain, CVE, and File.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript, enrichment |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_list | Accepts a list of indicators to enrich.<br/>- From CLI: Provide a comma-separated list.  <br/>  If an indicator contains a comma, wrap the indicators in a JSON array.  <br/>  Example: "\[\\"https://example.com/search?tags=red,yellow,green\\", \\"https://example2.com\\"\]".<br/>- From Context: Pass JSON arrays directly, without modification.<br/> |
| text | Free text to be parsed for indicators. The script will run \!extractIndicators to retrieve the underlying indicators within the text. |
| external_enrichment | Whether to call external integrations for enrichment: - 'true': enrich using enabled external integrations \(e.g., VirusTotal \(API v3\), AlienVault OTX v2\) and run internal commands. - 'false': use only existing TIM data and run internal commands; skip external integrations. If the 'brands' argument is provided, this flag is ignored and enrichment/internal commands will run only on the brands provided. |
| brands | A comma separated list of integration brands to run enrichment against.  <br/>Example: \`"VirusTotal \(API v3\), AlienVault OTX v2"\`.<br/>- If provided, only the selected brands are used. Specifying brands will force enable external_enrichment.<br/>- If left empty, the script runs enrichment on all enabled integrations.<br/> |
| additional_fields | When set to true, the output for each enrichment command  includes an \`AdditionalFields\` object for each of the indicator results.  <br/>\`AdditionalFields\` contains all fields returned by TIM or the integrations<br/>that are not part of the standard output keys: \`Address\`, \`DetectionEngines\`, <br/>\`PositiveDetections\`, \`Score\`, and \`Brand\`.  <br/>When set to false, only the standard keys are returned.<br/> |
| raw_context | If true, will also append the underlying enrichment command outputs to the context. \(For backwards compatibility\). |
| ignore_indicator_limit | By default, the script enforces a 100 indicator limit to maintain performance. If more than 100 unique indicators are found, the script will stop and return an error. Set this argument to true to bypass this limit and process all found indicators. Note: Bypassing the limit is not recommended as it may impact performance. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IndicatorEnrichment.Status | The overall status of the script execution. "Success", "Failed". | String |
| IndicatorEnrichment.Message | A success message if the command runs successfully, otherwise a message that contains the error. | String |
| IndicatorEnrichment.Results | A list of all indicators found. | Array |
| IndicatorEnrichment.Results.Type | The detected indicator type \(e.g., "IP", "URL"\) that triggered this enrichment. | String |
| IndicatorEnrichment.Results.Value | The indicator value. \(e.g, IP, URL\). | string |
| IndicatorEnrichment.Results.MaxScore | The max score of all the indicators found. | number |
| IndicatorEnrichment.Results.MaxVerdict | The max verdict of all the indicators found. | string |
| IndicatorEnrichment.Results.TIMScore | The TIM score of the indicator. | number |
| IndicatorEnrichment.TIMCVSS | The max CVSS of the indicator. | number |
| IndicatorEnrichment.Results.Status | The status of the indicator: "Manual" if the score was changed manually, "Fresh" if modified within the last week, "Stale" if modified more than a week ago, and "None" if never modified. | string |
| IndicatorEnrichment.Results.ModifiedTime | The time the indicator was last modified. | Date |
| IndicatorEnrichment.Results.Results | A list of all the underlying script results for the valid indicators. | array |
| IndicatorEnrichment.Results.Results.Source | The source of the indicator. | string |
| IndicatorEnrichment.Results.Results.Brand | The brand of the indicator. | string |
| IndicatorEnrichment.Results.Results.DetectionEngines | The detection engines of the indicator. | number |
| IndicatorEnrichment.Results.Results.PositiveDetections | The positive detections of the indicator. | number |
| IndicatorEnrichment.Results.Results.ASOwner | Registered owner of the Autonomous System announcing the IP prefix. | string |
| IndicatorEnrichment.Results.Results.Score | The score of the indicator. | number |
| IndicatorEnrichment.Results.Results.Verdict | The verdict of the indicator. | string |
| IndicatorEnrichment.Results.Results.Address | The IP address of the indicator. | string |
| IndicatorEnrichment.Results.Data | The URL of the indicator. | string |
| IndicatorEnrichment.Results.Name | The Domain of the indicator. | string |
| IndicatorEnrichment.Results.Results.Reliability | The reliability of the Brand. | string |
| IndicatorEnrichment.Results.Results.AdditionalFields | All fields extracted from the indicator other then the main keys \("Brand", "Score", "Verdict", "DetectionEngines", "PositiveDetections", "Address"\). | list |
| IndicatorEnrichment.Results.Results.AdditionalFields.Relationships.EntityA | The source of the relationship. | string |
| IndicatorEnrichment.Results.Results.AdditionalFields.Relationships.EntityB | The destination of the relationship. | string |
| IndicatorEnrichment.Results.Results.AdditionalFields.Relationships.Relationship | The name of the relationship. | string |
| IndicatorEnrichment.Results.Results.AdditionalFields.Relationships.EntityAType | The type of the source of the relationship. | string |
| IndicatorEnrichment.Results.Results.AdditionalFields.Relationships.EntityBType | The type of the destination of the relationship. | string |
| IndicatorEnrichment.Results.Results.AdditionalFields.Category | The category associated with the indicator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.ASN | The autonomous system name for the IP address, for example: "AS8948". | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Hostname | The hostname that is mapped to this IP address. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.DNS | A list of IP objects resolved by DNS. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Geo.Location | The geolocation where the IP address or Domain is located, in the format: latitude:longitude. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Geo.Country | The country in which the IP address is located. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Geo.Description | Additional information about the location. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Malicious.Vendor | The vendor reporting the IP address as malicious. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Malicious.Description | A description explaining why the IP address was reported as malicious. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Tags | \(List\) Tags of the Indicator. | Unknown |
| IndicatorEnrichment.Results.Results.AdditionalFields.FeedRelatedIndicators.value | Indicators that are associated with the given indicator value. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.FeedRelatedIndicators.type | The type of the indicators that are associated with the given indicator value. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.FeedRelatedIndicators.description | The description of the indicators that are associated with the given indicator value. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.MalwareFamily | The malware family associated with the given indicator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Organization.Name | The organization of the IP. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Organization.Type | The organization type of the IP. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Region | The region in which the IP is located. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Port | Ports that are associated with the Indicator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Internal | Whether or not the indicator is internal or external. | Bool |
| IndicatorEnrichment.Results.Results.AdditionalFields.UpdatedDate | The date that the indicator was last updated. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.Billing | Billing address of the domain. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Tech.Country | The country of the domain technical contact. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Tech.Name | The name of the domain technical contact. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Tech.Organization | The organization of the domain technical contact. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Tech.Email | The email address of the domain technical contact. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.DomainIDNName | The internationalized domain name \(IDN\) of the domain. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.ExpirationDate | The expiration date of the domain. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.DomainStatus | The status of the domain. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.NameServers | \(List&lt;String&gt;\) Name servers of the domain. | Unknown |
| IndicatorEnrichment.Results.Results.AdditionalFields.Organization | The organization of the domain. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Subdomains | \(List&lt;String&gt;\) Subdomains of the domain. | Unknown |
| IndicatorEnrichment.Results.Results.AdditionalFields.Admin.Country | The country of the domain administrator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Admin.Email | The email address of the domain administrator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Admin.Name | The name of the domain administrator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Admin.Phone | The phone number of the domain administrator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrant.Country | The country of the registrant. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrant.Email | The email address of the registrant. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrant.Name | The name of the registrant. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrant.Phone | The phone number to receive abuse reports. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.NameServers | \(List&lt;String&gt;\) Name servers of the domain. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.CreationDate | The date that the domain was created. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.UpdatedDate | The date that the domain was last updated. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.ExpirationDate | The expiration date of the domain. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Registrant.Name | The name of the registrant. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Registrant.Email | The email address of the registrant. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Registrant.Phone | The phone number of the registrant. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Registrar.Name | The name of the registrar, for example, GoDaddy. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Registrar.AbuseEmail | The email address of the contact to report abuse. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Registrar.AbusePhone | The phone number of the contact to report abuse. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Admin.Name | The name of the domain administrator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Admin.Email | The email address of the domain administrator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.Admin.Phone | The phone number of the domain administrator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.WHOIS.History | List of Whois objects. | String |
| IndicatorEnrichment.Results.Results.CVSS | The CVSS of the indicator. | number |
| IndicatorEnrichment.Results.Results.Description | The description of the indicator. | string |
| IndicatorEnrichment.Results.Results.Published | The published date of the indicator. | string |
| IndicatorEnrichment.Results.Results.AdditionalFields.CreationDate | The date when the domain was created. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.ExpirationDate | The expiration date of the domain. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrar.Abuse.Name | The name of the contact for reporting abuse. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrar.Abuse.Address | The address of the contact for reporting abuse. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrar.Abuse.Country | The country of the contact for reporting abuse. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrar.Abuse.Network | The network of the contact for reporting abuse. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrar.Abuse.Phone | The phone number of the contact for reporting abuse. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Registrar.Abuse.Email | The email address of the contact for reporting abuse. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Campaign | The campaign associated with the Indicator. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.TrafficLightProtocol | The Traffic Light Protocol \(TLP\) color that is suitable for the IP/Domain. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.CommunityNotes.note | Notes on the IP that were given by the community. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.CommunityNotes.timestamp | The time in which the note was published. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.Publications.source | The source in which the article was published. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Publications.title | The name of the article. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Publications.link | A link to the original article. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.Publications.timestamp | The time in which the article was published. | Date |
| IndicatorEnrichment.Results.Results.AdditionalFields.ThreatTypes.threatcategory | The threat category associated to this indicator by the source vendor, for example, Phishing, Control, TOR, etc. | String |
| IndicatorEnrichment.Results.Results.AdditionalFields.ThreatTypes.threatcategoryconfidence | Threat Category Confidence is the confidence level provided by the vendor for the threat type category. For example, a confidence level of 90 for the 'malware' threat type category means that the vendor is confident that its 90% malware. | String |
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
| IndicatorEnrichment.Failed | Audit log of all the inputs/indicators that were not successfully sent to an enrichment script. Weather the type is unsupported, unknown or some internal fatal error. | Array |
| IndicatorEnrichment.Failed.Value | The indicator value that failed. | String |
| IndicatorEnrichment.Failed.Type | The detected type of the indicator that failed. | String |
| IndicatorEnrichment.Failed.Error | The reason for the failure \(e.g., "Unsupported indicator type"\). | String |
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
| IPEnrichment.Results.Reliability | The reliability of the Brand. | string |
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
| DomainEnrichment.Results.Reliability | The reliability of the Brand. | string |
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
| DomainEnrichment.Results.AdditionalFields.DomainStatus | The status of the domain. | Date |
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
| URLEnrichment.Value | The URL. | string |
| URLEnrichment.MaxScore | The max score of all the indicators found. | number |
| URLEnrichment.MaxVerdict | The max verdict of all the indicators found. | string |
| URLEnrichment.Results | List of all indicators found for the URL. | array |
| URLEnrichment.TIMScore | The TIM score of the URL. | number |
| URLEnrichment.Status | The status of the indicator: "Manual" if the score was changed manually, "Fresh" if modified within the last week, "Stale" if modified more than a week ago, and "None" if never modified. | string |
| URLEnrichment.ModifiedTime | The time the indicator was last modified. | Date |
| URLEnrichment.Results.Brand | The brand of the indicator. | string |
| URLEnrichment.Results.Score | The score of the indicator. | number |
| URLEnrichment.Results.Verdict | The verdict of the indicator. | string |
| URLEnrichment.Results.DetectionEngines | The detection engines of the indicator. | number |
| URLEnrichment.Results.PositiveDetections | The positive detections of the indicator. | number |
| URLEnrichment.Results.Data | The URL it self. | string |
| URLEnrichment.Results.Reliability | The reliability of the Brand. | string |
| URLEnrichment.Results.AdditionalFields | All fields extracted from the indicator other then the main keys \("Brand", "Score", "Verdict", "DetectionEngines", "PositiveDetections", "Data"\). | Object |
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
| CVEEnrichment.Value | The CVE. | string |
| CVEEnrichment.TIMCVSS | The max CVSS of the indicator. | number |
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
