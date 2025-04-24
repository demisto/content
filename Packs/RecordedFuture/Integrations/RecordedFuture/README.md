Unique threat intel technology that automatically serves up relevant insights in real time.
This integration was integrated and tested with version 2.4.3 of Recorded Future v2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previo-us-version-of-this-integration-recorded-future-v2).

## Configure Recorded Future v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://api.recordedfuture.com/gw/xsoar/) |  | True |
| API Token |  | True |
| File Threshold | Minimum risk score from Recorded Future to consider the file malicious. | False |
| CVE Threshold | Minimum risk score from Recorded Future to consider the CVE malicious. | False |
| IP Threshold | Minimum risk score from RF to consider the IP malicious. | False |
| Domain Threshold | Minimum risk score from Recorded Future to consider the domain malicious. | False |
| URL Threshold | Minimum risk score from Recorded Future to consider the URL malicious. | False |
| Vulnerability Threshold | Minimum risk score from Recorded Future to consider the vulnerability critical. | False |
| Collective Insights | The Recorded Future Intelligence Cloud aggregates data related to indicators, driving collective insights to better identify threats. Anonymized data is collected for analytical purposes to identify trends and insights with the Intelligence Cloud. Go to the Recorded Future support site to learn more about Collective Insights. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Rule names to fetch alerts by | Rule names to fetch alerts by, separated by semicolon. If empty, all alerts will be fetched. | False |
| Alert Statuses to include in the fetch | Comma-separated alert statuses \(e.g. "unassigned,assigned,pending,actionable,no-action,tuning"\). If empty, the default value of "no-action" will be used. | False |
| Update alert status on fetch. | If selected, alerts with a status of 'no-action' will be updated to 'pending' once fetched by the integration. | False |
| First fetch time | Format: &amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., "12 hours", "7 days", "3 months", "1 year". | False |
| Incident type |  | False |
| Maximum number of incidents per fetch |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
|  |  | False |
| Incidents Fetch Interval |  | False |
| Incidents Fetch Interval |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### domain

***
Gets a quick indicator of the risk associated with a domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain for which to get the reputation. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious Domains, the reason that the vendor made the decision. | 
| Domain.Name | string | Domain name. | 
| RecordedFuture.Domain.riskScore | number | Recorded Future domain risk score. | 
| RecordedFuture.Domain.riskLevel | string | Recorded Future domain risk level. | 
| RecordedFuture.Domain.Evidence.rule | string | Recorded Future risk rule name. | 
| RecordedFuture.Domain.Evidence.mitigation | string | Recorded Future risk rule mitigation. | 
| RecordedFuture.Domain.Evidence.description | string | Recorded Future risk rule description. | 
| RecordedFuture.Domain.Evidence.timestamp | date | Recorded Future risk rule timestamp. | 
| RecordedFuture.Domain.Evidence.level | number | Recorded Future risk rule level. | 
| RecordedFuture.Domain.Evidence.ruleid | string | Recorded Future risk rule ID. | 
| RecordedFuture.Domain.name | string | Domain name. | 
| RecordedFuture.Domain.maxRules | number | Maximum number of Recorded Future domain risk rules. | 
| RecordedFuture.Domain.rules | string | All the rules concatenated by comma. | 
| RecordedFuture.Domain.ruleCount | number | Number of triggered Recorded Future domain risk rules. | 

### ip

***
Gets a quick indicator of the risk associated with an IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address for which to get the reputation. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the reason that the vendor made the decision. | 
| IP.Address | string | IP address. | 
| RecordedFuture.IP.riskScore | number | Recorded Future IP risk score. | 
| RecordedFuture.IP.riskLevel | string | Recorded Future IP risk level. | 
| RecordedFuture.IP.Evidence.rule | string | Recorded Future risk rule name. | 
| RecordedFuture.IP.Evidence.mitigation | string | Recorded Future risk rule mitigation. | 
| RecordedFuture.IP.Evidence.description | string | Recorded Future risk rule description. | 
| RecordedFuture.IP.Evidence.timestamp | date | Recorded Future risk rule timestamp. | 
| RecordedFuture.IP.Evidence.level | number | Recorded Future risk rule level. | 
| RecordedFuture.IP.Evidence.ruleid | string | Recorded Future risk rule ID. | 
| RecordedFuture.IP.name | string | IP address. | 
| RecordedFuture.IP.maxRules | number | Maximum number of Recorded Future IP risk rules. | 
| RecordedFuture.IP.rules | string | All the rules concatenated by comma. | 
| RecordedFuture.IP.ruleCount | number | Number of triggered Recorded Future IP risk rules. | 

### file

***
Gets a quick indicator of the risk associated with a file.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | File hash for which to check the reputation. Can be an MD5, SHA1, SHA256, SHA512, CRC32 or CTPH. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| File.SHA256 | string | SHA-256 hash of the file. | 
| File.SHA512 | string | SHA-512 hash of the file. | 
| File.SHA1 | string | SHA-1 hash of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.CRC32 | string | CRC32 hash of the file. | 
| File.CTPH | string | CTPH hash of the file. | 
| File.Malicious.Vendor | string | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | string | For malicious files, the reason that the vendor made the decision. | 
| RecordedFuture.File.riskScore | number | Recorded Future hash risk score. | 
| RecordedFuture.File.riskLevel | string | Recorded Future hash risk level. | 
| RecordedFuture.File.Evidence.rule | string | Recorded Future risk rule name. | 
| RecordedFuture.File.Evidence.mitigation | string | Recorded Future risk rule mitigation. | 
| RecordedFuture.File.Evidence.description | string | Recorded Future risk rule description. | 
| RecordedFuture.File.Evidence.timestamp | date | Recorded Future risk rule timestamp. | 
| RecordedFuture.File.Evidence.level | number | Recorded Future risk rule level. | 
| RecordedFuture.File.Evidence.ruleid | string | Recorded Future risk rule ID. | 
| RecordedFuture.File.name | string | File name. | 
| RecordedFuture.File.maxRules | number | Maximum number of Recorded Future hash risk rules. | 
| RecordedFuture.File.rules | string | All the rules concatenated by comma. | 
| RecordedFuture.File.ruleCount | number | Number of triggered Recorded Future hash risk rules. | 

### cve

***
Gets a quick indicator of the risk associated with a CVE.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | CVE for which to get the reputation. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| CVE.ID | string | Vulnerability name. | 
| RecordedFuture.CVE.riskScore | number | Recorded Future vulnerability risk score. | 
| RecordedFuture.CVE.riskLevel | string | Recorded Future vulnerability risk level. | 
| RecordedFuture.CVE.Evidence.rule | string | Recorded Future risk rule name. | 
| RecordedFuture.CVE.Evidence.mitigation | string | Recorded Future risk rule mitigation. | 
| RecordedFuture.CVE.Evidence.description | string | Recorded Future risk rule description. | 
| RecordedFuture.CVE.Evidence.timestamp | date | Recorded Future risk rule timestamp. | 
| RecordedFuture.CVE.Evidence.level | number | Recorded Future risk rule level. | 
| RecordedFuture.CVE.Evidence.ruleid | string | Recorded Future risk rule ID. | 
| RecordedFuture.CVE.name | string | CVE name. | 
| RecordedFuture.CVE.maxRules | number | Maximum number of Recorded Future vulnerability risk rules. | 
| RecordedFuture.CVE.rules | string | All the rules concatenated by comma. | 
| RecordedFuture.CVE.ruleCount | number | Number of triggered Recorded Future vulnerability risk rules. | 

### url

***
Gets a quick indicator of the risk associated with a URL.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL for which to get the reputation. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the reason that the vendor made the decision. | 
| URL.Data | string | URL name. | 
| RecordedFuture.URL.riskScore | number | Recorded Future URL risk score. | 
| RecordedFuture.URL.riskLevel | string | Recorded Future URL risk level. | 
| RecordedFuture.URL.Evidence.rule | string | Recorded Risk rule name. | 
| RecordedFuture.URL.Evidence.mitigation | string | Recorded Risk rule mitigation. | 
| RecordedFuture.URL.Evidence.description | string | Recorded Risk rule description. | 
| RecordedFuture.URL.Evidence.timestamp | date | Recorded Risk rule timestamp. | 
| RecordedFuture.URL.Evidence.level | number | Recorded Risk rule level. | 
| RecordedFuture.URL.Evidence.ruleid | string | Recorded Risk rule ID. | 
| RecordedFuture.URL.name | string | URL name. | 
| RecordedFuture.URL.maxRules | number | Maximum number of Recorded Future URL risk rules. | 
| RecordedFuture.URL.rules | string | All the rules concatenated by comma. | 
| RecordedFuture.URL.ruleCount | number | Number of triggered Recorded Future URL risk rules. | 

### recordedfuture-threat-assessment

***
Get an indicator of the risk based on context.

#### Base Command

`recordedfuture-threat-assessment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context | Context to use for the assessment. This is used by Recorded Future to calculate the relevant score and verdict. Can be "c2", "malware", or "phishing". Possible values are: c2, malware, phishing. | Required | 
| ip | IP addresses to check if they are related to the selected context. | Optional | 
| domain | Domains to check if they are related to the selected context. | Optional | 
| file | File hashes to check if they are related to the selected context. | Optional | 
| url | URLs to check if they are related to the selected context. | Optional | 
| cve | CVEs to check if they are related to the selected context. | Optional | 
| filter | Will filter out entities that have zero as score. Possible values are: yes, no. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | Indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| File.SHA256 | string | SHA-256 hash of the file. | 
| File.SHA512 | string | SHA-512 hash of the file. | 
| File.SHA1 | string | SHA-1 hash of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.CRC32 | string | CRC32 hash of the file. | 
| File.CTPH | string | CTPH hash of the file. | 
| IP.Address | string | IP address. | 
| IP.ASN | string | ASN. | 
| IP.Geo.Country | string | IP address geolocation country. | 
| Domain.Name | string | Domain name. | 
| URL.Data | string | URL name. | 
| CVE.ID | string | Vulnerability name. | 
| RecordedFuture.verdict | boolean | Recorded Future verdict. | 
| RecordedFuture.context | string | Threat assessment context. | 
| RecordedFuture.riskScore | number | Recorded Future maximum risk score. | 
| RecordedFuture.Entities.id | string | Recorded Future entity ID. | 
| RecordedFuture.Entities.name | string | Recorded Future entity name. | 
| RecordedFuture.Entities.type | string | Recorded Future entity type. | 
| RecordedFuture.Entities.score | string | Recorded Future entity score. | 
| RecordedFuture.Entities.context | string | Contains the current context if there is evidence. | 
| RecordedFuture.Entities.Evidence.ruleid | string | Recorded Future risk rule ID. | 
| RecordedFuture.Entities.Evidence.timestamp | date | Recorded Future evidence timestamp. | 
| RecordedFuture.Entities.Evidence.mitigation | string | Recorded Future evidence mitigation. | 
| RecordedFuture.Entities.Evidence.description | string | Recorded Future evidence description. | 
| RecordedFuture.Entities.Evidence.rule | string | Recorded Future risk rule. | 
| RecordedFuture.Entities.Evidence.level | number | Recorded Future risk rule level. | 

### recordedfuture-intelligence

***
Get threat intelligence for an IP, Domain, CVE, URL, File or Malware.

#### Base Command

`recordedfuture-intelligence`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile | Depending on what profile you choose you will get different related entities matching the given profile. Possible values are: All, Threat Hunter, SecOp Analyst, TI Analyst, Vulnerability Analyst. Default is All. | Optional | 
| entity_type | The type of entity for which to fetch context. Should be provided with its value in entityValue argument. Can be "domain", "ip", "file", "url", "cve", or "malware". Possible values are: domain, ip, file, url, cve, malware. | Required | 
| entity | The value of the entity for which to fetch context. Should be provided with its type in entity_type argument. Supported hash types: MD5, SHA1, SHA256, SHA512, CRC32, and CTPH. Vulnerability supports CVEs. | Required | 
| fetch_related_entities | Whether to fetch related entity data. Can be "yes" or "no". Possible values are: yes, no. | Optional | 
| fetch_analyst_notes | Whether to fetch analyst notes. Can be "yes" or "no". Possible values are: yes, no. Default is no. | Optional | 
| fetch_riskyCIDRips | Whether risk scores for other IP addresses within the same CIDR should be fetched (only for IP intelligence). Can be "yes" or "no". Possible values are: no, yes. Default is no. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | Indicator type. | 
| DBotScore.Vendor | string | Vendor used to calculate the score. | 
| DBotScore.Score | number | The actual score. | 
| File.SHA256 | string | SHA-256 hash of the file. | 
| File.SHA512 | string | SHA-512 hash of the file. | 
| File.SHA1 | string | SHA-1 hash of the file. | 
| File.MD5 | string | MD5 hash of the file. | 
| File.CRC32 | string | CRC32 hash of the file. | 
| File.CTPH | string | CTPH hash of the file. | 
| IP.Address | string | IP address. | 
| IP.ASN | string | ASN. | 
| IP.Geo.Country | string | IP address geolocation country. | 
| Domain.Name | string | Domain name. | 
| URL.Data | string | URL name. | 
| CVE.ID | string | Vulnerability name. | 
| RecordedFuture.IP.criticality | number | Risk criticality. | 
| RecordedFuture.IP.criticalityLabel | string | Risk criticality label. | 
| RecordedFuture.IP.riskString | string | Risk string. | 
| RecordedFuture.IP.riskSummary | string | Risk summary. | 
| RecordedFuture.IP.rules | string | Risk rules. | 
| RecordedFuture.Ip.concatRules | string | All risk rules concatenated by comma. | 
| RecordedFuture.IP.score | number | Risk score. | 
| RecordedFuture.IP.firstSeen | date | Evidence first seen date. | 
| RecordedFuture.IP.lastSeen | date | Evidence last seen date. | 
| RecordedFuture.IP.intelCard | string | Recorded Future intelligence card URL. | 
| RecordedFuture.IP.type | string | Recorded Future entity type. | 
| RecordedFuture.IP.name | string | Recorded Future entity name. | 
| RecordedFuture.IP.id | string | Recorded Future entity ID. | 
| RecordedFuture.IP.location.asn | string | ASN number. | 
| RecordedFuture.IP.location.cidr.id | string | Recorded Future CIDR ID. | 
| RecordedFuture.IP.location.cidr.name | string | CIDR name. | 
| RecordedFuture.IP.location.cidr.type | string | CIDR type. | 
| RecordedFuture.IP.location.location.city | string | IP address geolocation city. | 
| RecordedFuture.IP.location.location.continent | string | IP address geolocation continent. | 
| RecordedFuture.IP.location.location.country | string | IP address geolocation country. | 
| RecordedFuture.IP.location.organization | string | IP address geolocation organization. | 
| RecordedFuture.IP.metrics.type | string | Recorded Future metrics type. | 
| RecordedFuture.IP.metrics.value | number | Recorded Future metrics value. | 
| RecordedFuture.IP.threatLists.description | string | Recorded Future threat list description. | 
| RecordedFuture.IP.threatLists.id | string | Recorded Future threat list ID. | 
| RecordedFuture.IP.threatLists.name | string | Recorded Future threat list name. | 
| RecordedFuture.IP.threatLists.type | string | Recorded Future threat list type. | 
| RecordedFuture.IP.relatedEntities.RelatedAttacker.count | number | Recorded Future related attacker count. | 
| RecordedFuture.IP.relatedEntities.RelatedAttacker.id | string | Recorded Future related attacker ID. | 
| RecordedFuture.IP.relatedEntities.RelatedAttacker.name | string | Recorded Future related attacker name. | 
| RecordedFuture.IP.relatedEntities.RelatedAttacker.type | string | Recorded Future related attacker type. | 
| RecordedFuture.IP.relatedEntities.RelatedTarget.count | number | Recorded Future related target count. | 
| RecordedFuture.IP.relatedEntities.RelatedTarget.id | string | Recorded Future related target ID. | 
| RecordedFuture.IP.relatedEntities.RelatedTarget.name | string | Recorded Future related target name. | 
| RecordedFuture.IP.relatedEntities.RelatedTarget.type | string | Recorded Future related target type. | 
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.count | number | Recorded Future related threat actor count. | 
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.id | string | Recorded Future related threat actor ID. | 
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.name | string | Recorded Future related threat actor name. | 
| RecordedFuture.IP.relatedEntities.RelatedThreatActor.type | string | Recorded Future related threat actor type. | 
| RecordedFuture.IP.relatedEntities.RelatedMalware.count | number | Recorded Future related malware count. | 
| RecordedFuture.IP.relatedEntities.RelatedMalware.id | string | Recorded Future related malware ID. | 
| RecordedFuture.IP.relatedEntities.RelatedMalware.name | string | Recorded Future related malware name. | 
| RecordedFuture.IP.relatedEntities.RelatedMalware.type | string | Recorded Future related malware type. | 
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.count | number | Recorded Future related vulnerability count. | 
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.id | string | Recorded Future related vulnerability ID. | 
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.name | string | Recorded Future related vulnerability name. | 
| RecordedFuture.IP.relatedEntities.RelatedCyberVulnerability.type | string | Recorded Future related vulnerability type. | 
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.count | number | Recorded Future related IP address count. | 
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.id | string | Recorded Future related IP address ID. | 
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.name | string | Recorded Future related IP address name. | 
| RecordedFuture.IP.relatedEntities.RelatedIpAddress.type | string | Recorded Future related IP address type. | 
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.count | number | Recorded Future related domain name count. | 
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.id | string | Recorded Future related domain name ID. | 
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.name | string | Recorded Future related domain name name. | 
| RecordedFuture.IP.relatedEntities.RelatedInternetDomainName.type | string | Recorded Future related domain name type. | 
| RecordedFuture.IP.relatedEntities.RelatedProduct.count | number | Recorded Future related product count. | 
| RecordedFuture.IP.relatedEntities.RelatedProduct.id | string | Recorded Future related product ID. | 
| RecordedFuture.IP.relatedEntities.RelatedProduct.name | string | Recorded Future related product name. | 
| RecordedFuture.IP.relatedEntities.RelatedProduct.type | string | Recorded Future related product type. | 
| RecordedFuture.IP.relatedEntities.RelatedCountries.count | number | Recorded Future related countries count. | 
| RecordedFuture.IP.relatedEntities.RelatedCountries.id | string | Recorded Future related countries ID. | 
| RecordedFuture.IP.relatedEntities.RelatedCountries.name | string | Recorded Future related countries name. | 
| RecordedFuture.IP.relatedEntities.RelatedCountries.type | string | Recorded Future related countries type. | 
| RecordedFuture.IP.relatedEntities.RelatedHash.count | number | Recorded Future related hash count. | 
| RecordedFuture.IP.relatedEntities.RelatedHash.id | string | Recorded Future related hash ID. | 
| RecordedFuture.IP.relatedEntities.RelatedHash.name | string | Recorded Future related hash name. | 
| RecordedFuture.IP.relatedEntities.RelatedHash.type | string | Recorded Future related hash type. | 
| RecordedFuture.IP.relatedEntities.RelatedTechnology.count | number | Recorded Future related technology count. | 
| RecordedFuture.IP.relatedEntities.RelatedTechnology.id | string | Recorded Future related technology ID. | 
| RecordedFuture.IP.relatedEntities.RelatedTechnology.name | string | Recorded Future related technology name. | 
| RecordedFuture.IP.relatedEntities.RelatedTechnology.type | string | Recorded Future related technology type. | 
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.count | number | Recorded Future related email address count. | 
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.id | string | Recorded Future related email address ID. | 
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.name | string | Recorded Future related email address name. | 
| RecordedFuture.IP.relatedEntities.RelatedEmailAddress.type | string | Recorded Future related email address type. | 
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.count | number | Recorded Future related attack vector count. | 
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.id | string | Recorded Future related attack vector ID. | 
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.name | string | Recorded Future related attack vector name. | 
| RecordedFuture.IP.relatedEntities.RelatedAttackVector.type | string | Recorded Future related attack vector type. | 
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.count | number | Recorded Future related malware category count. | 
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.id | string | Recorded Future related malware category ID. | 
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.name | string | Recorded Future related malware category name. | 
| RecordedFuture.IP.relatedEntities.RelatedMalwareCategory.type | string | Recorded Future related malware category type. | 
| RecordedFuture.IP.relatedEntities.RelatedOperations.count | number | Recorded Future related operations count. | 
| RecordedFuture.IP.relatedEntities.RelatedOperations.id | string | Recorded Future related operations ID. | 
| RecordedFuture.IP.relatedEntities.RelatedOperations.name | string | Recorded Future related operations name. | 
| RecordedFuture.IP.relatedEntities.RelatedOperations.type | string | Recorded Future related operations type. | 
| RecordedFuture.IP.relatedEntities.RelatedCompany.count | number | Recorded Future related company count. | 
| RecordedFuture.IP.relatedEntities.RelatedCompany.id | string | Recorded Future related company ID. | 
| RecordedFuture.IP.relatedEntities.RelatedCompany.name | string | Recorded Future related company name. | 
| RecordedFuture.IP.relatedEntities.RelatedCompany.type | string | Recorded Future related company type. | 
| RecordedFuture.IP.analystNotes.attributes.context_entities.id | string | Recorded Future analyst note context entity ID. | 
| RecordedFuture.IP.analystNotes.attributes.context_entities.name | string | Recorded Future analyst note context entity name. | 
| RecordedFuture.IP.analystNotes.attributes.context_entities.type | string | Recorded Future analyst note context entity type. | 
| RecordedFuture.IP.analystNotes.attributes.note_entities.id | string | Recorded Future analyst note entity ID. | 
| RecordedFuture.IP.analystNotes.attributes.note_entities.name | string | Recorded Future analyst note entity name. | 
| RecordedFuture.IP.analystNotes.attributes.note_entities.type | string | Recorded Future analyst note entity type. | 
| RecordedFuture.IP.analystNotes.attributes.published | date | Recorded Future analyst note publishing time. | 
| RecordedFuture.IP.analystNotes.attributes.validated_on | date | Recorded Future analyst note validation time. | 
| RecordedFuture.IP.analystNotes.attributes.text | string | Recorded Future analyst note content. | 
| RecordedFuture.IP.analystNotes.attributes.title | string | Recorded Future analyst note title. | 
| RecordedFuture.IP.analystNotes.attributes.topic.description | string | Recorded Future analyst note topic description. | 
| RecordedFuture.IP.analystNotes.attributes.topic.id | string | Recorded Future analyst note topic ID. | 
| RecordedFuture.IP.analystNotes.attributes.topic.name | string | Recorded Future analyst note topic name. | 
| RecordedFuture.IP.analystNotes.attributes.topic.type | string | Recorded Future analyst note topic type. | 
| RecordedFuture.IP.analystNotes.attributes.validation_urls.id | string | Recorded Future analyst note validation URL ID. | 
| RecordedFuture.IP.analystNotes.attributes.validation_urls.name | string | Recorded Future analyst note validation URL. | 
| RecordedFuture.IP.analystNotes.attributes.validation_urls.type | string | Recorded Future analyst note validation URL entity type. | 
| RecordedFuture.IP.analystNotes.id | string | Recorded Future analyst note ID. | 
| RecordedFuture.IP.analystNotes.source.id | string | Recorded Future analyst note source ID. | 
| RecordedFuture.IP.analystNotes.source.name | string | Recorded Future analyst note source name. | 
| RecordedFuture.IP.analystNotes.source.type | string | Recorded Future analyst note source type. | 
| RecordedFuture.Domain.criticality | number | Risk criticality. | 
| RecordedFuture.Domain.criticalityLabel | string | Risk criticality label. | 
| RecordedFuture.Domain.riskString | string | Risk string. | 
| RecordedFuture.Domain.riskSummary | string | Risk summary. | 
| RecordedFuture.Domain.rules | string | Risk rules. | 
| RecordedFuture.Domain.concatRules | string | All risk rules concatenated by comma. | 
| RecordedFuture.Domain.score | number | Risk score. | 
| RecordedFuture.Domain.firstSeen | date | Evidence first seen date. | 
| RecordedFuture.Domain.lastSeen | date | Evidence last seen. | 
| RecordedFuture.Domain.intelCard | string | Recorded Future intelligence card URL. | 
| RecordedFuture.Domain.type | string | Recorded Future entity type. | 
| RecordedFuture.Domain.name | string | Recorded Future entity name. | 
| RecordedFuture.Domain.id | string | Recorded Future entity ID. | 
| RecordedFuture.Domain.metrics.type | string | Recorded Future metrics type. | 
| RecordedFuture.Domain.metrics.value | number | Recorded Future metrics value. | 
| RecordedFuture.Domain.threatLists.description | string | Recorded Future threat list description. | 
| RecordedFuture.Domain.threatLists.id | string | Recorded Future threat list ID. | 
| RecordedFuture.Domain.threatLists.name | string | Recorded Future threat list name. | 
| RecordedFuture.Domain.threatLists.type | string | Recorded Future threat list type. | 
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.count | number | Recorded Future related attacker count. | 
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.id | string | Recorded Future related attacker ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.name | string | Recorded Future related attacker name. | 
| RecordedFuture.Domain.relatedEntities.RelatedAttacker.type | string | Recorded Future related attacker type. | 
| RecordedFuture.Domain.relatedEntities.RelatedTarget.count | number | Recorded Future related target count. | 
| RecordedFuture.Domain.relatedEntities.RelatedTarget.id | string | Recorded Future related target ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedTarget.name | string | Recorded Future related target name. | 
| RecordedFuture.Domain.relatedEntities.RelatedTarget.type | string | Recorded Future related target type. | 
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.count | number | Recorded Future related threat actor count. | 
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.id | string | Recorded Future related threat actor ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.name | string | Recorded Future related threat actor name. | 
| RecordedFuture.Domain.relatedEntities.RelatedThreatActor.type | string | Recorded Future related threat actor type. | 
| RecordedFuture.Domain.relatedEntities.RelatedMalware.count | number | Recorded Future related malware count. | 
| RecordedFuture.Domain.relatedEntities.RelatedMalware.id | string | Recorded Future related malware ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedMalware.name | string | Recorded Future related malware name. | 
| RecordedFuture.Domain.relatedEntities.RelatedMalware.type | string | Recorded Future related malware type. | 
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.count | number | Recorded Future related vulnerability count. | 
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.id | string | Recorded Future related vulnerability ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.name | string | Recorded Future related vulnerability name. | 
| RecordedFuture.Domain.relatedEntities.RelatedCyberVulnerability.type | string | Recorded Future related vulnerability type. | 
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.count | number | Recorded Future related IP address count. | 
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.id | string | Recorded Future related IP address ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.name | string | Recorded Future related IP address name. | 
| RecordedFuture.Domain.relatedEntities.RelatedIpAddress.type | string | Recorded Future related IP address type. | 
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.count | number | Recorded Future related domain name count. | 
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.id | string | Recorded Future related domain name ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.name | string | Recorded Future related domain name name. | 
| RecordedFuture.Domain.relatedEntities.RelatedInternetDomainName.type | string | Recorded Future related domain name type. | 
| RecordedFuture.Domain.relatedEntities.RelatedProduct.count | number | Recorded Future related product count. | 
| RecordedFuture.Domain.relatedEntities.RelatedProduct.id | string | Recorded Future related product ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedProduct.name | string | Recorded Future related product name. | 
| RecordedFuture.Domain.relatedEntities.RelatedProduct.type | string | Recorded Future related product type. | 
| RecordedFuture.Domain.relatedEntities.RelatedCountries.count | number | Recorded Future related countries count. | 
| RecordedFuture.Domain.relatedEntities.RelatedCountries.id | string | Recorded Future related countries ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedCountries.name | string | Recorded Future related countries name. | 
| RecordedFuture.Domain.relatedEntities.RelatedCountries.type | string | Recorded Future related countries type. | 
| RecordedFuture.Domain.relatedEntities.RelatedHash.count | number | Recorded Future related hash count. | 
| RecordedFuture.Domain.relatedEntities.RelatedHash.id | string | Recorded Future related hash ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedHash.name | string | Recorded Future related hash name. | 
| RecordedFuture.Domain.relatedEntities.RelatedHash.type | string | Recorded Future related hash type. | 
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.count | number | Recorded Future related technology count. | 
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.id | string | Recorded Future related technology ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.name | string | Recorded Future related technology name. | 
| RecordedFuture.Domain.relatedEntities.RelatedTechnology.type | string | Recorded Future related technology type. | 
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.count | number | Recorded Future related email address count. | 
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.id | string | Recorded Future related email address ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.name | string | Recorded Future related email address name. | 
| RecordedFuture.Domain.relatedEntities.RelatedEmailAddress.type | string | Recorded Future related email address type. | 
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.count | number | Recorded Future related attack vector count. | 
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.id | string | Recorded Future related attack vector ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.name | string | Recorded Future related attack vector name. | 
| RecordedFuture.Domain.relatedEntities.RelatedAttackVector.type | string | Recorded Future related attack vector type. | 
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.count | number | Recorded Future related malware category count. | 
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.id | string | Recorded Future related malware category ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.name | string | Recorded Future related malware category name. | 
| RecordedFuture.Domain.relatedEntities.RelatedMalwareCategory.type | string | Recorded Future related malware category type. | 
| RecordedFuture.Domain.relatedEntities.RelatedOperations.count | number | Recorded Future related operations count. | 
| RecordedFuture.Domain.relatedEntities.RelatedOperations.id | string | Recorded Future related operations ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedOperations.name | string | Recorded Future related operations name. | 
| RecordedFuture.Domain.relatedEntities.RelatedOperations.type | string | Recorded Future related operations type. | 
| RecordedFuture.Domain.relatedEntities.RelatedCompany.count | number | Recorded Future related company count. | 
| RecordedFuture.Domain.relatedEntities.RelatedCompany.id | string | Recorded Future related company ID. | 
| RecordedFuture.Domain.relatedEntities.RelatedCompany.name | string | Recorded Future related company name. | 
| RecordedFuture.Domain.relatedEntities.RelatedCompany.type | string | Recorded Future related company type. | 
| RecordedFuture.Domain.analystNotes.attributes.context_entities.id | string | Recorded Future analyst note context entity ID. | 
| RecordedFuture.Domain.analystNotes.attributes.context_entities.name | string | Recorded Future analyst note context entity name. | 
| RecordedFuture.Domain.analystNotes.attributes.context_entities.type | string | Recorded Future analyst note context entity type. | 
| RecordedFuture.Domain.analystNotes.attributes.note_entities.id | string | Recorded Future analyst note entity ID. | 
| RecordedFuture.Domain.analystNotes.attributes.note_entities.name | string | Recorded Future analyst note entity name. | 
| RecordedFuture.Domain.analystNotes.attributes.note_entities.type | string | Recorded Future analyst note entity type. | 
| RecordedFuture.Domain.analystNotes.attributes.published | date | Recorded Future analyst note publishing time. | 
| RecordedFuture.Domain.analystNotes.attributes.validated_on | date | Recorded Future analyst note validation time. | 
| RecordedFuture.Domain.analystNotes.attributes.text | string | Recorded Future analyst note content. | 
| RecordedFuture.Domain.analystNotes.attributes.title | string | Recorded Future analyst note title. | 
| RecordedFuture.Domain.analystNotes.attributes.topic.description | string | Recorded Future analyst note topic description. | 
| RecordedFuture.Domain.analystNotes.attributes.topic.id | string | Recorded Future analyst note topic ID. | 
| RecordedFuture.Domain.analystNotes.attributes.topic.name | string | Recorded Future analyst note topic name. | 
| RecordedFuture.Domain.analystNotes.attributes.topic.type | string | Recorded Future analyst note topic type. | 
| RecordedFuture.Domain.analystNotes.attributes.validation_urls.id | string | Recorded Future analyst note validation URL ID. | 
| RecordedFuture.Domain.analystNotes.attributes.validation_urls.name | string | Recorded Future analyst note validation URL. | 
| RecordedFuture.Domain.analystNotes.attributes.validation_urls.type | string | Recorded Future analyst note validation URL entity type. | 
| RecordedFuture.Domain.analystNotes.id | string | Recorded Future analyst note ID. | 
| RecordedFuture.Domain.analystNotes.source.id | string | Recorded Future analyst note source ID. | 
| RecordedFuture.Domain.analystNotes.source.name | string | Recorded Future analyst note source name. | 
| RecordedFuture.Domain.analystNotes.source.type | string | Recorded Future analyst note source type. | 
| RecordedFuture.CVE.criticality | number | Risk criticality. | 
| RecordedFuture.CVE.criticalityLabel | string | Risk criticality label. | 
| RecordedFuture.CVE.riskString | string | Risk string. | 
| RecordedFuture.CVE.riskSummary | string | Risk summary. | 
| RecordedFuture.CVE.rules | string | Risk rules. | 
| RecordedFuture.CVE.concatRules | string | All risk rules concatenated by comma. | 
| RecordedFuture.CVE.score | number | Risk score. | 
| RecordedFuture.CVE.firstSeen | date | Evidence first seen. | 
| RecordedFuture.CVE.lastSeen | date | Evidence last seen. | 
| RecordedFuture.CVE.intelCard | string | Recorded Future intelligence card URL. | 
| RecordedFuture.CVE.hashAlgorithm | string | Hash algorithm. | 
| RecordedFuture.CVE.type | string | Recorded Future entity type. | 
| RecordedFuture.CVE.name | string | Recorded Future entity name. | 
| RecordedFuture.CVE.id | string | Recorded Future entity ID. | 
| RecordedFuture.CVE.metrics.type | string | Recorded Future metrics type. | 
| RecordedFuture.CVE.metrics.value | number | Recorded Future metrics value. | 
| RecordedFuture.CVE.threatLists.description | string | Recorded Future threat list description. | 
| RecordedFuture.CVE.threatLists.id | string | Recorded Future threat list ID. | 
| RecordedFuture.CVE.threatLists.name | string | Recorded Future threat list name. | 
| RecordedFuture.CVE.threatLists.type | string | Recorded Future threat list type. | 
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.count | number | Recorded Future related attacker count. | 
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.id | string | Recorded Future related attacker ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.name | string | Recorded Future related attacker name. | 
| RecordedFuture.CVE.relatedEntities.RelatedAttacker.type | string | Recorded Future related attacker type. | 
| RecordedFuture.CVE.relatedEntities.RelatedTarget.count | number | Recorded Future related target count. | 
| RecordedFuture.CVE.relatedEntities.RelatedTarget.id | string | Recorded Future related target ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedTarget.name | string | Recorded Future related target name. | 
| RecordedFuture.CVE.relatedEntities.RelatedTarget.type | string | Recorded Future related target type. | 
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.count | number | Recorded Future related threat actor count. | 
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.id | string | Recorded Future related threat actor ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.name | string | Recorded Future related threat actor name. | 
| RecordedFuture.CVE.relatedEntities.RelatedThreatActor.type | string | Recorded Future related threat actor type. | 
| RecordedFuture.CVE.relatedEntities.RelatedMalware.count | number | Recorded Future related malware count. | 
| RecordedFuture.CVE.relatedEntities.RelatedMalware.id | string | Recorded Future related malware ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedMalware.name | string | Recorded Future related malware name. | 
| RecordedFuture.CVE.relatedEntities.RelatedMalware.type | string | Recorded Future related malware type. | 
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.count | number | Recorded Future related vulnerability count. | 
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.id | string | Recorded Future related vulnerability ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.name | string | Recorded Future related vulnerability name. | 
| RecordedFuture.CVE.relatedEntities.RelatedCyberVulnerability.type | string | Recorded Future related vulnerability type. | 
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.count | number | Recorded Future related IP address count. | 
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.id | string | Recorded Future related IP address ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.name | string | Recorded Future related IP address name. | 
| RecordedFuture.CVE.relatedEntities.RelatedIpAddress.type | string | Recorded Future related IP address type. | 
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.count | number | Recorded Future related domain name count. | 
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.id | string | Recorded Future related domain name ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.name | string | Recorded Future related domain name name. | 
| RecordedFuture.CVE.relatedEntities.RelatedInternetDomainName.type | string | Recorded Future related domain name type. | 
| RecordedFuture.CVE.relatedEntities.RelatedProduct.count | number | Recorded Future related product count. | 
| RecordedFuture.CVE.relatedEntities.RelatedProduct.id | string | Recorded Future related product ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedProduct.name | string | Recorded Future related product name. | 
| RecordedFuture.CVE.relatedEntities.RelatedProduct.type | string | Recorded Future related product type. | 
| RecordedFuture.CVE.relatedEntities.RelatedCountries.count | number | Recorded Future related countries count. | 
| RecordedFuture.CVE.relatedEntities.RelatedCountries.id | string | Recorded Future related countries ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedCountries.name | string | Recorded Future related countries name. | 
| RecordedFuture.CVE.relatedEntities.RelatedCountries.type | string | Recorded Future related countries type. | 
| RecordedFuture.CVE.relatedEntities.RelatedHash.count | number | Recorded Future related hash count. | 
| RecordedFuture.CVE.relatedEntities.RelatedHash.id | string | Recorded Future related hash ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedHash.name | string | Recorded Future related hash name. | 
| RecordedFuture.CVE.relatedEntities.RelatedHash.type | string | Recorded Future related hash type. | 
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.count | number | Recorded Future related technology count. | 
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.id | string | Recorded Future related technology ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.name | string | Recorded Future related technology name. | 
| RecordedFuture.CVE.relatedEntities.RelatedTechnology.type | string | Recorded Future related technology type. | 
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.count | number | Recorded Future related email address count. | 
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.id | string | Recorded Future related email address ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.name | string | Recorded Future related email address name. | 
| RecordedFuture.CVE.relatedEntities.RelatedEmailAddress.type | string | Recorded Future related email address type. | 
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.count | number | Recorded Future related attack vector count. | 
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.id | string | Recorded Future related attack vector ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.name | string | Recorded Future related attack vector name. | 
| RecordedFuture.CVE.relatedEntities.RelatedAttackVector.type | string | Recorded Future related attack vector type. | 
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.count | number | Recorded Future related malware category count. | 
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.id | string | Recorded Future related malware category ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.name | string | Recorded Future related malware category name. | 
| RecordedFuture.CVE.relatedEntities.RelatedMalwareCategory.type | string | Recorded Future related malware category type. | 
| RecordedFuture.CVE.relatedEntities.RelatedOperations.count | number | Recorded Future related operations count. | 
| RecordedFuture.CVE.relatedEntities.RelatedOperations.id | string | Recorded Future related operations ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedOperations.name | string | Recorded Future related operations name. | 
| RecordedFuture.CVE.relatedEntities.RelatedOperations.type | string | Recorded Future related operations type. | 
| RecordedFuture.CVE.relatedEntities.RelatedCompany.count | number | Recorded Future related company count. | 
| RecordedFuture.CVE.relatedEntities.RelatedCompany.id | string | Recorded Future related company ID. | 
| RecordedFuture.CVE.relatedEntities.RelatedCompany.name | string | Recorded Future related company name. | 
| RecordedFuture.CVE.relatedEntities.RelatedCompany.type | string | Recorded Future related company type. | 
| RecordedFuture.CVE.relatedLinks | string | Recorded Future CVE related links. | 
| RecordedFuture.CVE.analystNotes.attributes.context_entities.id | string | Recorded Future analyst note context entity ID. | 
| RecordedFuture.CVE.analystNotes.attributes.context_entities.name | string | Recorded Future analyst note context entity name. | 
| RecordedFuture.CVE.analystNotes.attributes.context_entities.type | string | Recorded Future analyst note context entity type. | 
| RecordedFuture.CVE.analystNotes.attributes.note_entities.id | string | Recorded Future analyst note entity ID. | 
| RecordedFuture.CVE.analystNotes.attributes.note_entities.name | string | Recorded Future analyst note entity name. | 
| RecordedFuture.CVE.analystNotes.attributes.note_entities.type | string | Recorded Future analyst note entity type. | 
| RecordedFuture.CVE.analystNotes.attributes.published | date | Recorded Future analyst note publishing time. | 
| RecordedFuture.CVE.analystNotes.attributes.validated_on | date | Recorded Future analyst note validation time. | 
| RecordedFuture.CVE.analystNotes.attributes.text | string | Recorded Future analyst note content. | 
| RecordedFuture.CVE.analystNotes.attributes.title | string | Recorded Future analyst note title. | 
| RecordedFuture.CVE.analystNotes.attributes.topic.description | string | Recorded Future analyst note topic description. | 
| RecordedFuture.CVE.analystNotes.attributes.topic.id | string | Recorded Future analyst note topic ID. | 
| RecordedFuture.CVE.analystNotes.attributes.topic.name | string | Recorded Future analyst note topic name. | 
| RecordedFuture.CVE.analystNotes.attributes.topic.type | string | Recorded Future analyst note topic type. | 
| RecordedFuture.CVE.analystNotes.attributes.validation_urls.id | string | Recorded Future analyst note validation URL ID. | 
| RecordedFuture.CVE.analystNotes.attributes.validation_urls.name | string | Recorded Future analyst note validation URL. | 
| RecordedFuture.CVE.analystNotes.attributes.validation_urls.type | string | Recorded Future analyst note validation URL entity type. | 
| RecordedFuture.CVE.analystNotes.id | string | Recorded Future analyst note ID. | 
| RecordedFuture.CVE.analystNotes.source.id | string | Recorded Future analyst note source ID. | 
| RecordedFuture.CVE.analystNotes.source.name | string | Recorded Future analyst note source name. | 
| RecordedFuture.CVE.analystNotes.source.type | string | Recorded Future analyst note source type. | 
| RecordedFuture.CVE.cpe | string | Recorded Future CPE information. | 
| RecordedFuture.File.criticality | number | Risk criticality. | 
| RecordedFuture.File.criticalityLabel | string | Risk criticality label. | 
| RecordedFuture.File.riskString | string | Risk string. | 
| RecordedFuture.File.riskSummary | string | Risk summary. | 
| RecordedFuture.File.rules | string | Risk rules. | 
| RecordedFuture.File.concatRules | string | All risk rules concatenated by comma. | 
| RecordedFuture.File.score | number | Risk score. | 
| RecordedFuture.File.firstSeen | date | Evidence first seen. | 
| RecordedFuture.File.lastSeen | date | Evidence last seen. | 
| RecordedFuture.File.intelCard | string | Recorded Future intelligence card URL. | 
| RecordedFuture.File.hashAlgorithm | string | Hash algorithm. | 
| RecordedFuture.File.type | string | Recorded Future entity type. | 
| RecordedFuture.File.name | string | Recorded Future entity name. | 
| RecordedFuture.File.id | string | Recorded Future entity ID. | 
| RecordedFuture.File.metrics.type | string | Recorded Future metrics type. | 
| RecordedFuture.File.metrics.value | number | Recorded Future metrics value. | 
| RecordedFuture.File.threatLists.description | string | Recorded Future threat list description. | 
| RecordedFuture.File.threatLists.id | string | Recorded Future threat list ID. | 
| RecordedFuture.File.threatLists.name | string | Recorded Future threat list name. | 
| RecordedFuture.File.threatLists.type | string | Recorded Future threat list type. | 
| RecordedFuture.File.relatedEntities.RelatedAttacker.count | number | Recorded Future related attacker count. | 
| RecordedFuture.File.relatedEntities.RelatedAttacker.id | string | Recorded Future related attacker ID. | 
| RecordedFuture.File.relatedEntities.RelatedAttacker.name | string | Recorded Future related attacker name. | 
| RecordedFuture.File.relatedEntities.RelatedAttacker.type | string | Recorded Future related attacker type. | 
| RecordedFuture.File.relatedEntities.RelatedTarget.count | number | Recorded Future related target count. | 
| RecordedFuture.File.relatedEntities.RelatedTarget.id | string | Recorded Future related target ID. | 
| RecordedFuture.File.relatedEntities.RelatedTarget.name | string | Recorded Future related target name. | 
| RecordedFuture.File.relatedEntities.RelatedTarget.type | string | Recorded Future related target type. | 
| RecordedFuture.File.relatedEntities.RelatedThreatActor.count | number | Recorded Future related threat actor count. | 
| RecordedFuture.File.relatedEntities.RelatedThreatActor.id | string | Recorded Future related threat actor ID. | 
| RecordedFuture.File.relatedEntities.RelatedThreatActor.name | string | Recorded Future related threat actor name. | 
| RecordedFuture.File.relatedEntities.RelatedThreatActor.type | string | Recorded Future related threat actor type. | 
| RecordedFuture.File.relatedEntities.RelatedMalware.count | number | Recorded Future related malware count. | 
| RecordedFuture.File.relatedEntities.RelatedMalware.id | string | Recorded Future related malware ID. | 
| RecordedFuture.File.relatedEntities.RelatedMalware.name | string | Recorded Future related malware name. | 
| RecordedFuture.File.relatedEntities.RelatedMalware.type | string | Recorded Future related malware type. | 
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.count | number | Recorded Future related vulnerability count. | 
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.id | string | Recorded Future related vulnerability ID. | 
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.name | string | Recorded Future related vulnerability name. | 
| RecordedFuture.File.relatedEntities.RelatedCyberVulnerability.type | string | Recorded Future related vulnerability type. | 
| RecordedFuture.File.relatedEntities.RelatedIpAddress.count | number | Recorded Future related IP address count. | 
| RecordedFuture.File.relatedEntities.RelatedIpAddress.id | string | Recorded Future related IP address ID. | 
| RecordedFuture.File.relatedEntities.RelatedIpAddress.name | string | Recorded Future related IP address name. | 
| RecordedFuture.File.relatedEntities.RelatedIpAddress.type | string | Recorded Future related IP address type. | 
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.count | number | Recorded Future related domain name count. | 
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.id | string | Recorded Future related domain name ID. | 
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.name | string | Recorded Future related domain name name. | 
| RecordedFuture.File.relatedEntities.RelatedInternetDomainName.type | string | Recorded Future related domain name type. | 
| RecordedFuture.File.relatedEntities.RelatedProduct.count | number | Recorded Future related product count. | 
| RecordedFuture.File.relatedEntities.RelatedProduct.id | string | Recorded Future related product ID. | 
| RecordedFuture.File.relatedEntities.RelatedProduct.name | string | Recorded Future related product name. | 
| RecordedFuture.File.relatedEntities.RelatedProduct.type | string | Recorded Future related product type. | 
| RecordedFuture.File.relatedEntities.RelatedCountries.count | number | Recorded Future related countries count. | 
| RecordedFuture.File.relatedEntities.RelatedCountries.id | string | Recorded Future related countries ID. | 
| RecordedFuture.File.relatedEntities.RelatedCountries.name | string | Recorded Future related countries name. | 
| RecordedFuture.File.relatedEntities.RelatedCountries.type | string | Recorded Future related countries type. | 
| RecordedFuture.File.relatedEntities.RelatedHash.count | number | Recorded Future related hash count. | 
| RecordedFuture.File.relatedEntities.RelatedHash.id | string | Recorded Future related hash ID. | 
| RecordedFuture.File.relatedEntities.RelatedHash.name | string | Recorded Future related hash name. | 
| RecordedFuture.File.relatedEntities.RelatedHash.type | string | Recorded Future related hash type. | 
| RecordedFuture.File.relatedEntities.RelatedTechnology.count | number | Recorded Future related technology count. | 
| RecordedFuture.File.relatedEntities.RelatedTechnology.id | string | Recorded Future related technology ID. | 
| RecordedFuture.File.relatedEntities.RelatedTechnology.name | string | Recorded Future related technology name. | 
| RecordedFuture.File.relatedEntities.RelatedTechnology.type | string | Recorded Future related technology type. | 
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.count | number | Recorded Future related email address count. | 
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.id | string | Recorded Future related email address ID. | 
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.name | string | Recorded Future related email address name. | 
| RecordedFuture.File.relatedEntities.RelatedEmailAddress.type | string | Recorded Future related email address type. | 
| RecordedFuture.File.relatedEntities.RelatedAttackVector.count | number | Recorded Future related attack vector count. | 
| RecordedFuture.File.relatedEntities.RelatedAttackVector.id | string | Recorded Future related attack vector ID. | 
| RecordedFuture.File.relatedEntities.RelatedAttackVector.name | string | Recorded Future related attack vector name. | 
| RecordedFuture.File.relatedEntities.RelatedAttackVector.type | string | Recorded Future related attack vector type. | 
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.count | number | Recorded Future related malware category count. | 
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.id | string | Recorded Future related malware category ID. | 
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.name | string | Recorded Future related malware category name. | 
| RecordedFuture.File.relatedEntities.RelatedMalwareCategory.type | string | Recorded Future related malware category type. | 
| RecordedFuture.File.relatedEntities.RelatedOperations.count | number | Recorded Future related operations count. | 
| RecordedFuture.File.relatedEntities.RelatedOperations.id | string | Recorded Future related operations ID. | 
| RecordedFuture.File.relatedEntities.RelatedOperations.name | string | Recorded Future related operations name. | 
| RecordedFuture.File.relatedEntities.RelatedOperations.type | string | Recorded Future related operations type. | 
| RecordedFuture.File.relatedEntities.RelatedCompany.count | number | Recorded Future related company count. | 
| RecordedFuture.File.relatedEntities.RelatedCompany.id | string | Recorded Future related company ID. | 
| RecordedFuture.File.relatedEntities.RelatedCompany.name | string | Recorded Future related company name. | 
| RecordedFuture.File.relatedEntities.RelatedCompany.type | string | Recorded Future related company type. | 
| RecordedFuture.File.analystNotes.attributes.context_entities.id | string | Recorded Future analyst note context entity ID. | 
| RecordedFuture.File.analystNotes.attributes.context_entities.name | string | Recorded Future analyst note context entity name. | 
| RecordedFuture.File.analystNotes.attributes.context_entities.type | string | Recorded Future analyst note context entity type. | 
| RecordedFuture.File.analystNotes.attributes.note_entities.id | string | Recorded Future analyst note entity ID. | 
| RecordedFuture.File.analystNotes.attributes.note_entities.name | string | Recorded Future analyst note entity name. | 
| RecordedFuture.File.analystNotes.attributes.note_entities.type | string | Recorded Future analyst note entity type. | 
| RecordedFuture.File.analystNotes.attributes.published | date | Recorded Future analyst note publishing time. | 
| RecordedFuture.File.analystNotes.attributes.validated_on | date | Recorded Future analyst note validation time. | 
| RecordedFuture.File.analystNotes.attributes.text | string | Recorded Future analyst note content. | 
| RecordedFuture.File.analystNotes.attributes.title | string | Recorded Future analyst note title. | 
| RecordedFuture.File.analystNotes.attributes.topic.description | string | Recorded Future analyst note topic description. | 
| RecordedFuture.File.analystNotes.attributes.topic.id | string | Recorded Future analyst note topic ID. | 
| RecordedFuture.File.analystNotes.attributes.topic.name | string | Recorded Future analyst note topic name. | 
| RecordedFuture.File.analystNotes.attributes.topic.type | string | Recorded Future analyst note topic type. | 
| RecordedFuture.File.analystNotes.attributes.validation_urls.id | string | Recorded Future analyst note validation URL ID. | 
| RecordedFuture.File.analystNotes.attributes.validation_urls.name | string | Recorded Future analyst note validation URL. | 
| RecordedFuture.File.analystNotes.attributes.validation_urls.type | string | Recorded Future analyst note validation URL entity type. | 
| RecordedFuture.File.analystNotes.id | string | Recorded Future analyst note ID. | 
| RecordedFuture.File.analystNotes.source.id | string | Recorded Future analyst note source ID. | 
| RecordedFuture.File.analystNotes.source.name | string | Recorded Future analyst note source name. | 
| RecordedFuture.File.analystNotes.source.type | string | Recorded Future analyst note source type. | 
| RecordedFuture.URL.criticality | number | Risk criticality. | 
| RecordedFuture.URL.criticalityLabel | string | Risk criticality label. | 
| RecordedFuture.URL.riskString | string | Risk string. | 
| RecordedFuture.URL.riskSummary | string | Risk summary. | 
| RecordedFuture.URL.rules | string | Risk rules. | 
| RecordedFuture.URL.concatRules | string | All risk rules concatenated by comma. | 
| RecordedFuture.URL.score | number | Risk score. | 
| RecordedFuture.URL.firstSeen | date | Evidence first seen. | 
| RecordedFuture.URL.lastSeen | date | Evidence last seen. | 
| RecordedFuture.URL.intelCard | string | Recorded Future intelligence card URL. | 
| RecordedFuture.URL.type | string | Recorded Future entity type. | 
| RecordedFuture.URL.name | string | Recorded Future entity name. | 
| RecordedFuture.URL.id | string | Recorded Future entity ID. | 
| RecordedFuture.URL.metrics.type | string | Recorded Future metrics type. | 
| RecordedFuture.URL.metrics.value | number | Recorded Future metrics value. | 
| RecordedFuture.URL.threatLists.description | string | Recorded Future threat list description. | 
| RecordedFuture.URL.threatLists.id | string | Recorded Future threat list ID. | 
| RecordedFuture.URL.threatLists.name | string | Recorded Future threat list name. | 
| RecordedFuture.URL.threatLists.type | string | Recorded Future threat list type. | 
| RecordedFuture.URL.relatedEntities.RelatedAttacker.count | number | Recorded Future related attacker count. | 
| RecordedFuture.URL.relatedEntities.RelatedAttacker.id | string | Recorded Future related attacker ID. | 
| RecordedFuture.URL.relatedEntities.RelatedAttacker.name | string | Recorded Future related attacker name. | 
| RecordedFuture.URL.relatedEntities.RelatedAttacker.type | string | Recorded Future related attacker type. | 
| RecordedFuture.URL.relatedEntities.RelatedTarget.count | number | Recorded Future related target count. | 
| RecordedFuture.URL.relatedEntities.RelatedTarget.id | string | Recorded Future related target ID. | 
| RecordedFuture.URL.relatedEntities.RelatedTarget.name | string | Recorded Future related target name. | 
| RecordedFuture.URL.relatedEntities.RelatedTarget.type | string | Recorded Future related target type. | 
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.count | number | Recorded Future related threat actor count. | 
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.id | string | Recorded Future related threat actor ID. | 
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.name | string | Recorded Future related threat actor name. | 
| RecordedFuture.URL.relatedEntities.RelatedThreatActor.type | string | Recorded Future related threat actor type. | 
| RecordedFuture.URL.relatedEntities.RelatedMalware.count | number | Recorded Future related malware count. | 
| RecordedFuture.URL.relatedEntities.RelatedMalware.id | string | Recorded Future related malware ID. | 
| RecordedFuture.URL.relatedEntities.RelatedMalware.name | string | Recorded Future related malware name. | 
| RecordedFuture.URL.relatedEntities.RelatedMalware.type | string | Recorded Future related malware type. | 
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.count | number | Recorded Future related vulnerability count. | 
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.id | string | Recorded Future related vulnerability ID. | 
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.name | string | Recorded Future related vulnerability name. | 
| RecordedFuture.URL.relatedEntities.RelatedCyberVulnerability.type | string | Recorded Future related vulnerability type. | 
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.count | number | Recorded Future related IP address count. | 
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.id | string | Recorded Future related IP address ID. | 
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.name | string | Recorded Future related IP address name. | 
| RecordedFuture.URL.relatedEntities.RelatedIpAddress.type | string | Recorded Future related IP address type. | 
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.count | number | Recorded Future related domain name count. | 
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.id | string | Recorded Future related domain name ID. | 
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.name | string | Recorded Future related domain name name. | 
| RecordedFuture.URL.relatedEntities.RelatedInternetDomainName.type | string | Recorded Future related domain name type. | 
| RecordedFuture.URL.relatedEntities.RelatedProduct.count | number | Recorded Future related product count. | 
| RecordedFuture.URL.relatedEntities.RelatedProduct.id | string | Recorded Future related product ID. | 
| RecordedFuture.URL.relatedEntities.RelatedProduct.name | string | Recorded Future related product name. | 
| RecordedFuture.URL.relatedEntities.RelatedProduct.type | string | Recorded Future related product type. | 
| RecordedFuture.URL.relatedEntities.RelatedCountries.count | number | Recorded Future related countries count. | 
| RecordedFuture.URL.relatedEntities.RelatedCountries.id | string | Recorded Future related countries ID. | 
| RecordedFuture.URL.relatedEntities.RelatedCountries.name | string | Recorded Future related countries name. | 
| RecordedFuture.URL.relatedEntities.RelatedCountries.type | string | Recorded Future related countries type. | 
| RecordedFuture.URL.relatedEntities.RelatedHash.count | number | Recorded Future related hash count. | 
| RecordedFuture.URL.relatedEntities.RelatedHash.id | string | Recorded Future related hash ID. | 
| RecordedFuture.URL.relatedEntities.RelatedHash.name | string | Recorded Future related hash name. | 
| RecordedFuture.URL.relatedEntities.RelatedHash.type | string | Recorded Future related hash type. | 
| RecordedFuture.URL.relatedEntities.RelatedTechnology.count | number | Recorded Future related technology count. | 
| RecordedFuture.URL.relatedEntities.RelatedTechnology.id | string | Recorded Future related technology ID. | 
| RecordedFuture.URL.relatedEntities.RelatedTechnology.name | string | Recorded Future related technology name. | 
| RecordedFuture.URL.relatedEntities.RelatedTechnology.type | string | Recorded Future related technology type. | 
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.count | number | Recorded Future related email address count. | 
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.id | string | Recorded Future related email address ID. | 
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.name | string | Recorded Future related email address name. | 
| RecordedFuture.URL.relatedEntities.RelatedEmailAddress.type | string | Recorded Future related email address type. | 
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.count | number | Recorded Future related attack vector count. | 
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.id | string | Recorded Future related attack vector ID. | 
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.name | string | Recorded Future related attack vector name. | 
| RecordedFuture.URL.relatedEntities.RelatedAttackVector.type | string | Recorded Future related attack vector type. | 
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.count | number | Recorded Future related malware category count. | 
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.id | string | Recorded Future related malware category ID. | 
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.name | string | Recorded Future related malware category name. | 
| RecordedFuture.URL.relatedEntities.RelatedMalwareCategory.type | string | Recorded Future related malware category type. | 
| RecordedFuture.URL.relatedEntities.RelatedOperations.count | number | Recorded Future related operations count. | 
| RecordedFuture.URL.relatedEntities.RelatedOperations.id | string | Recorded Future related operations ID. | 
| RecordedFuture.URL.relatedEntities.RelatedOperations.name | string | Recorded Future related operations name. | 
| RecordedFuture.URL.relatedEntities.RelatedOperations.type | string | Recorded Future related operations type. | 
| RecordedFuture.URL.relatedEntities.RelatedCompany.count | number | Recorded Future related company count. | 
| RecordedFuture.URL.relatedEntities.RelatedCompany.id | string | Recorded Future related company ID. | 
| RecordedFuture.URL.relatedEntities.RelatedCompany.name | string | Recorded Future related company name. | 
| RecordedFuture.URL.relatedEntities.RelatedCompany.type | string | Recorded Future related company type. | 
| RecordedFuture.URL.analystNotes.attributes.context_entities.id | string | Recorded Future analyst note context entity ID. | 
| RecordedFuture.URL.analystNotes.attributes.context_entities.name | string | Recorded Future analyst note context entity name. | 
| RecordedFuture.URL.analystNotes.attributes.context_entities.type | string | Recorded Future analyst note context entity type. | 
| RecordedFuture.URL.analystNotes.attributes.note_entities.id | string | Recorded Future analyst note entity ID. | 
| RecordedFuture.URL.analystNotes.attributes.note_entities.name | string | Recorded Future analyst note entity name. | 
| RecordedFuture.URL.analystNotes.attributes.note_entities.type | string | Recorded Future analyst note entity type. | 
| RecordedFuture.URL.analystNotes.attributes.published | date | Recorded Future analyst note publishing time. | 
| RecordedFuture.URL.analystNotes.attributes.validated_on | date | Recorded Future analyst note validation time. | 
| RecordedFuture.URL.analystNotes.attributes.text | string | Recorded Future analyst note content. | 
| RecordedFuture.URL.analystNotes.attributes.title | string | Recorded Future analyst note title. | 
| RecordedFuture.URL.analystNotes.attributes.topic.description | string | Recorded Future analyst note topic description. | 
| RecordedFuture.URL.analystNotes.attributes.topic.id | string | Recorded Future analyst note topic ID. | 
| RecordedFuture.URL.analystNotes.attributes.topic.name | string | Recorded Future analyst note topic name. | 
| RecordedFuture.URL.analystNotes.attributes.topic.type | string | Recorded Future analyst note topic type. | 
| RecordedFuture.URL.analystNotes.attributes.validation_urls.id | string | Recorded Future analyst note validation URL ID. | 
| RecordedFuture.URL.analystNotes.attributes.validation_urls.name | string | Recorded Future analyst note validation URL. | 
| RecordedFuture.URL.analystNotes.attributes.validation_urls.type | string | Recorded Future analyst note validation URL entity type. | 
| RecordedFuture.URL.analystNotes.id | string | Recorded Future analyst note ID. | 
| RecordedFuture.URL.analystNotes.source.id | string | Recorded Future analyst note source ID. | 
| RecordedFuture.URL.analystNotes.source.name | string | Recorded Future analyst note source name. | 
| RecordedFuture.URL.analystNotes.source.type | string | Recorded Future analyst note source type. | 
| RecordedFuture.Malware.metrics.type | string | Recorded Future metrics type. | 
| RecordedFuture.Malware.metrics.value | number | Recorded Future metrics value. | 
| RecordedFuture.Malware.intelCard | date | Recorded Future intelligence card URL. | 
| RecordedFuture.Malware.firstSeen | date | Evidence first seen. | 
| RecordedFuture.Malware.lastSeen | date | Evidence last seen. | 
| RecordedFuture.Malware.name | date | Recorded Future entity name. | 
| RecordedFuture.Malware.type | string | Recorded Future entity type \(always = "Malware"\). | 
| RecordedFuture.Malware.id | string | Recorded Future malware ID. | 
| RecordedFuture.Malware.categories.id | string | Recorded Future malware category ID. | 
| RecordedFuture.Malware.categories.name | string | Recorded Future malware category name. | 
| RecordedFuture.Malware.categories.type | string | Recorded Future malware category type \(always = "MalwareCategory"\). | 
| RecordedFuture.Malware.relatedEntities.RelatedAttacker.count | number | Recorded Future related attacker count. | 
| RecordedFuture.Malware.relatedEntities.RelatedAttacker.id | string | Recorded Future related attacker ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedAttacker.name | string | Recorded Future related attacker name. | 
| RecordedFuture.Malware.relatedEntities.RelatedAttacker.type | string | Recorded Future related attacker type. | 
| RecordedFuture.Malware.relatedEntities.RelatedTarget.count | number | Recorded Future related target count. | 
| RecordedFuture.Malware.relatedEntities.RelatedTarget.id | string | Recorded Future related target ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedTarget.name | string | Recorded Future related target name. | 
| RecordedFuture.Malware.relatedEntities.RelatedTarget.type | string | Recorded Future related target type. | 
| RecordedFuture.Malware.relatedEntities.RelatedThreatActor.count | number | Recorded Future related threat actor count. | 
| RecordedFuture.Malware.relatedEntities.RelatedThreatActor.id | string | Recorded Future related threat actor ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedThreatActor.name | string | Recorded Future related threat actor name. | 
| RecordedFuture.Malware.relatedEntities.RelatedThreatActor.type | string | Recorded Future related threat actor type. | 
| RecordedFuture.Malware.relatedEntities.RelatedMalware.count | number | Recorded Future related malware count. | 
| RecordedFuture.Malware.relatedEntities.RelatedMalware.id | string | Recorded Future related malware ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedMalware.name | string | Recorded Future related malware name. | 
| RecordedFuture.Malware.relatedEntities.RelatedMalware.type | string | Recorded Future related malware type. | 
| RecordedFuture.Malware.relatedEntities.RelatedCyberVulnerability.count | number | Recorded Future related vulnerability count. | 
| RecordedFuture.Malware.relatedEntities.RelatedCyberVulnerability.id | string | Recorded Future related vulnerability ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedCyberVulnerability.name | string | Recorded Future related vulnerability name. | 
| RecordedFuture.Malware.relatedEntities.RelatedCyberVulnerability.type | string | Recorded Future related vulnerability type. | 
| RecordedFuture.Malware.relatedEntities.RelatedIpAddress.count | number | Recorded Future related IP address count. | 
| RecordedFuture.Malware.relatedEntities.RelatedIpAddress.id | string | Recorded Future related IP address ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedIpAddress.name | string | Recorded Future related IP address name. | 
| RecordedFuture.Malware.relatedEntities.RelatedIpAddress.type | string | Recorded Future related IP address type. | 
| RecordedFuture.Malware.relatedEntities.RelatedInternetDomainName.count | number | Recorded Future related domain name count. | 
| RecordedFuture.Malware.relatedEntities.RelatedInternetDomainName.id | string | Recorded Future related domain name ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedInternetDomainName.name | string | Recorded Future related domain name name. | 
| RecordedFuture.Malware.relatedEntities.RelatedInternetDomainName.type | string | Recorded Future related domain name type. | 
| RecordedFuture.Malware.relatedEntities.RelatedProduct.count | number | Recorded Future related product count. | 
| RecordedFuture.Malware.relatedEntities.RelatedProduct.id | string | Recorded Future related product ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedProduct.name | string | Recorded Future related product name. | 
| RecordedFuture.Malware.relatedEntities.RelatedProduct.type | string | Recorded Future related product type. | 
| RecordedFuture.Malware.relatedEntities.RelatedCountries.count | number | Recorded Future related countries count. | 
| RecordedFuture.Malware.relatedEntities.RelatedCountries.id | string | Recorded Future related countries ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedCountries.name | string | Recorded Future related countries name. | 
| RecordedFuture.Malware.relatedEntities.RelatedCountries.type | string | Recorded Future related countries type. | 
| RecordedFuture.Malware.relatedEntities.RelatedHash.count | number | Recorded Future related hash count. | 
| RecordedFuture.Malware.relatedEntities.RelatedHash.id | string | Recorded Future related hash ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedHash.name | string | Recorded Future related hash name. | 
| RecordedFuture.Malware.relatedEntities.RelatedHash.type | string | Recorded Future related hash type. | 
| RecordedFuture.Malware.relatedEntities.RelatedTechnology.count | number | Recorded Future related technology count. | 
| RecordedFuture.Malware.relatedEntities.RelatedTechnology.id | string | Recorded Future related technology ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedTechnology.name | string | Recorded Future related technology name. | 
| RecordedFuture.Malware.relatedEntities.RelatedTechnology.type | string | Recorded Future related technology type. | 
| RecordedFuture.Malware.relatedEntities.RelatedEmailAddress.count | number | Recorded Future related email address count. | 
| RecordedFuture.Malware.relatedEntities.RelatedEmailAddress.id | string | Recorded Future related email address ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedEmailAddress.name | string | Recorded Future related email address name. | 
| RecordedFuture.Malware.relatedEntities.RelatedEmailAddress.type | string | Recorded Future related email address type. | 
| RecordedFuture.Malware.relatedEntities.RelatedAttackVector.count | number | Recorded Future related attack vector count. | 
| RecordedFuture.Malware.relatedEntities.RelatedAttackVector.id | string | Recorded Future related attack vector ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedAttackVector.name | string | Recorded Future related attack vector name. | 
| RecordedFuture.Malware.relatedEntities.RelatedAttackVector.type | string | Recorded Future related attack vector type. | 
| RecordedFuture.Malware.relatedEntities.RelatedMalwareCategory.count | number | Recorded Future related malware category count. | 
| RecordedFuture.Malware.relatedEntities.RelatedMalwareCategory.id | string | Recorded Future related malware category ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedMalwareCategory.name | string | Recorded Future related malware category name. | 
| RecordedFuture.Malware.relatedEntities.RelatedMalwareCategory.type | string | Recorded Future related malware category type. | 
| RecordedFuture.Malware.relatedEntities.RelatedOperations.count | number | Recorded Future related operations count. | 
| RecordedFuture.Malware.relatedEntities.RelatedOperations.id | string | Recorded Future related operations ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedOperations.name | string | Recorded Future related operations name. | 
| RecordedFuture.Malware.relatedEntities.RelatedOperations.type | string | Recorded Future related operations type. | 
| RecordedFuture.Malware.relatedEntities.RelatedCompany.count | number | Recorded Future related company count. | 
| RecordedFuture.Malware.relatedEntities.RelatedCompany.id | string | Recorded Future related company ID. | 
| RecordedFuture.Malware.relatedEntities.RelatedCompany.name | string | Recorded Future related company name. | 
| RecordedFuture.Malware.relatedEntities.RelatedCompany.type | string | Recorded Future related company type. | 
| RecordedFuture.Malware.analystNotes.attributes.context_entities.id | string | Recorded Future analyst note context entity ID. | 
| RecordedFuture.Malware.analystNotes.attributes.context_entities.name | string | Recorded Future analyst note context entity name. | 
| RecordedFuture.Malware.analystNotes.attributes.context_entities.type | string | Recorded Future analyst note context entity type. | 
| RecordedFuture.Malware.analystNotes.attributes.note_entities.id | string | Recorded Future analyst note entity ID. | 
| RecordedFuture.Malware.analystNotes.attributes.note_entities.name | string | Recorded Future analyst note entity name. | 
| RecordedFuture.Malware.analystNotes.attributes.note_entities.type | string | Recorded Future analyst note entity type. | 
| RecordedFuture.Malware.analystNotes.attributes.published | date | Recorded Future analyst note publishing time. | 
| RecordedFuture.Malware.analystNotes.attributes.validated_on | date | Recorded Future analyst note validation time. | 
| RecordedFuture.Malware.analystNotes.attributes.text | string | Recorded Future analyst note content. | 
| RecordedFuture.Malware.analystNotes.attributes.title | string | Recorded Future analyst note title. | 
| RecordedFuture.Malware.analystNotes.attributes.topic.description | string | Recorded Future analyst note topic description. | 
| RecordedFuture.Malware.analystNotes.attributes.topic.id | string | Recorded Future analyst note topic ID. | 
| RecordedFuture.Malware.analystNotes.attributes.topic.name | string | Recorded Future analyst note topic name. | 
| RecordedFuture.Malware.analystNotes.attributes.topic.type | string | Recorded Future analyst note topic type. | 
| RecordedFuture.Malware.analystNotes.attributes.validation_urls.id | string | Recorded Future analyst note validation URL ID. | 
| RecordedFuture.Malware.analystNotes.attributes.validation_urls.name | string | Recorded Future analyst note validation URL. | 
| RecordedFuture.Malware.analystNotes.attributes.validation_urls.type | string | Recorded Future analyst note validation URL entity type. | 
| RecordedFuture.Malware.analystNotes.id | string | Recorded Future analyst note ID. | 
| RecordedFuture.Malware.analystNotes.source.id | string | Recorded Future analyst note source ID. | 
| RecordedFuture.Malware.analystNotes.source.name | string | Recorded Future analyst note source name. | 
| RecordedFuture.Malware.analystNotes.source.type | string | Recorded Future analyst note source type. | 

### recordedfuture-links

***
Get Insikt Group Research Links for an IP, Domain, CVE, URL, File, or Malware.

#### Base Command

`recordedfuture-links`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_type | The type of entity for which to fetch context. Should be provided with its value in entityValue argument. Can be "domain", "ip", "file", "url", "cve", or "malware". Possible values are: domain, ip, file, url, cve, malware. | Required | 
| entity | The value of the entity for which to fetch context. Should be provided with its type in entity_type argument. Supported hash types: MD5, SHA1, SHA256, SHA512, CRC32, and CTPH. Vulnerability supports CVEs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Links.category | String | Recorded Future links category. | 
| RecordedFuture.Links.type | String | Recorded Future links type. | 
| RecordedFuture.Links.lists.entity_type | String | Recorded Future links entity list type. | 
| RecordedFuture.Links.lists.entities.type | String | Recorded Future link entity type. | 
| RecordedFuture.Links.lists.entities.name | String | Recorded Future link entity name. | 
| RecordedFuture.Links.lists.entities.score | Number | Recorded Future link entity risk score. | 

### recordedfuture-single-alert

***
Get detailed information from vulnerability, typosquat and credential alerts.

#### Base Command

`recordedfuture-single-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Alert ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.SingleAlert.id | string | Recorded Future alert ID. | 
| RecordedFuture.SingleAlert.flat_entities.fragment | string | Recorded Future fragment of the entity. | 
| RecordedFuture.SingleAlert.flat_entities.name | string | Recorded Future name of the entity. | 
| RecordedFuture.SingleAlert.flat_entities.type | string | Recorded Future type of the entity. | 
| RecordedFuture.SingleAlert.flat_entities.id | string | Recorded Future ID of the entity. | 

### recordedfuture-alerts

***
Gets details on alerts configured and generated by Recorded Future by alert rule ID and/or time range.

#### Base Command

`recordedfuture-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Alert rule ID. | Optional | 
| limit | Maximum number of alerts to return. Default is 10. Default is 10. | Optional | 
| triggered_time | Alert triggered time, e.g., "1 hour" or "2 days". | Optional | 
| assignee | Alert assignee's email address. | Optional | 
| status | Alert review status. Can be "unassigned", "assigned", "pending", "actionable", "no-action", or "tuning". Possible values are: unassigned, assigned, pending, actionable, no-action, tuning. | Optional | 
| freetext | Free text search. | Optional | 
| offset | Alerts from offset. | Optional | 
| orderby | Alerts sort order. Possible values are: triggered. | Optional | 
| direction | The direction by which to sort alerts. Can be "asc" or "desc". Possible values are: asc, desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Alert.id | string | Alert ID. | 
| RecordedFuture.Alert.name | string | Alert name. | 
| RecordedFuture.Alert.type | string | Alert type. | 
| RecordedFuture.Alert.triggered | date | Alert triggered time. | 
| RecordedFuture.Alert.status | string | Alert status. | 
| RecordedFuture.Alert.assignee | string | Alert assignee. | 
| RecordedFuture.Alert.rule | string | Alert rule name. | 

### recordedfuture-alert-rules

***
Search for alert rule IDs.

#### Base Command

`recordedfuture-alert-rules`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | Rule name to search. Can be a partial name. | Optional | 
| limit | Maximum number of rules to return. Default is 10. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.AlertRule.id | string | Alert rule ID. | 
| RecordedFuture.AlertRule.name | string | Alert rule name. | 

### recordedfuture-alert-set-status

***
Set alert into predefined status.

#### Base Command

`recordedfuture-alert-set-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert id. | Required | 
| status | The status we want to set for the alert in Recorded Future. Possible values are: unassigned, assigned, pending, dismiss, no-action, actionable, tuning. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Alerts.id | String | Recorded Future alert ID. | 
| RecordedFuture.Alerts.status | String | Recorded Future alert status. | 
| RecordedFuture.Alerts.note.text | String | Recorded Future alert note text. | 
| RecordedFuture.Alerts.note.author | String | Recorded Future alert note author. | 
| RecordedFuture.Alerts.note.date | date | Recorded Future alert note date. | 
| RecordedFuture.Alerts.reviewDate | date | Recorded Future alert get date. | 

### recordedfuture-alert-set-note

***
Set a note for the alert in Recorded Future.

#### Base Command

`recordedfuture-alert-set-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 
| note | The note of the ID we want to set. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Alerts.id | String | Recorded Future alert ID. | 
| RecordedFuture.Alerts.status | String | Recorded Future alert status. | 
| RecordedFuture.Alerts.note.text | String | Recorded Future alert note text. | 
| RecordedFuture.Alerts.note.author | String | Recorded Future alert note author. | 
| RecordedFuture.Alerts.note.date | date | Recorded Future alert note date. | 
| RecordedFuture.Alerts.reviewDate | date | Recorded Future alert get date. | 

### recordedfuture-malware-search

***
Search for a malware by specified filters.

#### Base Command

`recordedfuture-malware-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| freetext | Part of malware name or ID to search for. | Optional | 
| limit | How many records to retrieve (default = 10). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| RecordedFuture.Malware.id | string | Recorded Future malware ID. | 
| RecordedFuture.Malware.name | string | Recorded Future entity name. | 
| RecordedFuture.Malware.type | string | Recorded Future entity type \(always = "Malware"\). | 
| RecordedFuture.Malware.intelCard | date | Recorded Future intelligence card URL. | 


#### Base Command

`recordedfuture-threat-map`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actors_ids | Actors IDs for which to get the threat map | Optional | 
| actor_name | Actors name for which to get the threat map | Optional | 
| include_links | Fetch links to threat actor or not | Optional | 

#### Context Output

| **Path**                             | **Type** | **Description**                           |
|--------------------------------------|----------|-------------------------------------------|
| RecordedFuture.ThreatMap.id          | string   | Recorded Future threat actor ID.          | 
| RecordedFuture.ThreatMap.name        | string   | Recorded Future entity name.              | 
| RecordedFuture.ThreatMap.alias       | array    | Recorded Future threat actor alias.       | 
| RecordedFuture.ThreatMap.intent      | number   | Recorded Future threat actor intent.      | 
| RecordedFuture.ThreatMap.id          | string   | Recorded Future threat actor ID.          | 
| RecordedFuture.ThreatMap.opportunity | number   | Recorded Future threat actor opportunity. | 
| RecordedFuture.ThreatMap.log_entries | array    | Recorded Future threat actor log entries. | 
| RecordedFuture.ThreatMap.links       | array    | Recorded Future threat actor links.       |


#### Base Command

`recordedfuture-threat-links`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                         | **Required** |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entity_type       | Type of the entity to fetch links for. E.g. "domain", "ip", "file", "url", "cve", "malware", "organization, "person". Should be provided along with the entity in entity_name argument. | Optional     | 
| entity_name       | Name of the entity to fetch links for                                                                                                                                                   | Optional     | 
| entity_id         | ID of entity to fetch links for                                                                                                                                                         | Optional     | 
| source_type       | Source of the links to be fetched. Can be "insikt" or "technical"                                                                                                                       | Optional     | 
| timeframe         | Time range of the links to be fetched. Eg. "-1d" for last 1 day                                                                                                                         | Optional     | 
| technical_type    | Type of technical source to fetch links from. Can be "type:MalwareAnalysis", "type:InfrastructureAnalysis", "type:NetworkTrafficAnalysis" or "type:TTPAnalysis"                         | Optional     | 

#### Context Output

| **Path**                              | **Type** | **Description**                  |
|---------------------------------------|----------|----------------------------------|
| RecordedFuture.Links.entity.id        | string   | Recorded Future Entity id.       | 
| RecordedFuture.Links.entity.type      | string   | Recorded Future Entity type      | 
| RecordedFuture.Links.links.type       | string   | Recorded Future link type.       | 
| RecordedFuture.Links.links.id         | string   | Recorded Future link id.         | 
| RecordedFuture.Links.links.name       | string   | Recorded Future link name.       | 
| RecordedFuture.Links.links.source     | string   | Recorded Future link source.     | 
| RecordedFuture.Links.links.section    | string   | Recorded Future link section.    | 
| RecordedFuture.Links.links.attributes | string   | Recorded Future link attributes. |


#### Base Command

`recordedfuture-detection-rules`

#### Input

| **Argument Name** | **Description**                            | **Required** |
|-------------------|--------------------------------------------|--------------|
| entity_type       | Type of the entity to fetch links for      | Optional     | 
| entity_name       | Name of the entity to fetch links for      | Optional     | 
| entity_id         | ID of entity to fetch links for            | Optional     | 
| rule_types        | Rule type. Can be "yara", "sigma", "snort" | Optional     | 
| title             | Rule title                                 | Optional     | 

#### Context Output

| **Path**                                          | **Type** | **Description**                             |
|---------------------------------------------------|----------|---------------------------------------------|
| RecordedFuture.DetectionRules.id                  | string   | Recorded Future Detection rule id.          | 
| RecordedFuture.DetectionRules.type                | string   | Recorded Future Detection rule type.        | 
| RecordedFuture.DetectionRules.title               | string   | Recorded Future Detection rule title.       | 
| RecordedFuture.DetectionRules.description         | string   | Recorded Future Detection rule description. | 
| RecordedFuture.DetectionRules.created             | string   | Recorded Future link name.                  | 
| RecordedFuture.DetectionRules.updated             | string   | Recorded Future link source.                | 
| RecordedFuture.DetectionRules.rules               | array    | Recorded Future link section.               | 
| RecordedFuture.DetectionRules.rules.entities      | array    | Recorded Future link attributes.            |
| RecordedFuture.DetectionRules.rules.entities.id   | string   | Recorded Future link attributes.            |
| RecordedFuture.DetectionRules.rules.entities.type | string   | Recorded Future link attributes.            |
| RecordedFuture.DetectionRules.rules.entities.name | string   | Recorded Future link attributes.            |
| RecordedFuture.DetectionRules.rules.content       | string   | Recorded Future link attributes.            |
| RecordedFuture.DetectionRules.rules.file_name     | string   | Recorded Future link attributes.            |


#### Base Command

`recordedfuture-collective-insight`

#### Input
#### Input

| **Argument Name**  | **Description**                                                                                     | **Required** |
|--------------------|-----------------------------------------------------------------------------------------------------|--------------|
| entity_type        | Value that can contain one of the enumerated list of values (ip, hash, domain, vulnerability, url). | Required     | 
| entity_name        | Value of the IOC itself                                                                             | Required     | 
| entity_source_type | Used to describe what log source the IOC came from                                                  | Optional     | 
| incident_name      | Title of the incident related to the IOC                                                            | Optional     | 
| incident_id        | ID of the incident related to the IOC                                                               | Optional     | 
| incident_type      | Attack vector associated with the incident (C2, Phishing.. etc)                                     | Optional     | 
| mitre_codes        | List contains one or more MITRE codes associated with the IOC                                       | Optional     | 
| malware            | List contains all known malware associated with the IOCs                                            | Optional     | 

#### Context Output

| **Path**                                | **Type** | **Description** |
|-----------------------------------------|----------|-----------------|
| RecordedFuture.CollectiveInsight.status | string   | Request status  | 

## Breaking changes from the previous version of this integration - Recorded Future v2

Renamed the integration setting "Incident Sharing" to "Collective Insights", resetting any previous configuration to this setting. 