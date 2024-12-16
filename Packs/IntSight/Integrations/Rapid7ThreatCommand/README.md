Rapid7 Insight - Threat Command allows managing alerts, CVEs, IOCs, and assets by accounts and MSSP accounts.
This integration was integrated and tested with version 3.1.4 of rapid7_threat_command

## Configure Rapid7 - Threat Command (IntSights) in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | URL of the Rapid7 platform. | True |
| Account ID |  | True |
| API key |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Fetch incidents |  | False |
| First fetch timestamp. | Timestamp in ISO format or &lt;number&gt; &lt;time unit&gt;, e.g., 2023-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | False |
| Maximum incidents per fetch | The maximum number of alerts to fetch each time. The default is 50. If the value is greater than 200, it will be considered as 200. | True |
| Alert types to fetch as incidents | Alert types to fetch as incidents. | False |
| Network types to fetch as incidents | Network types to fetch as incidents. | False |
| Minimum Alert Severity Level | Alerts with the minimum level of severity to fetch. | False |
| Source types to filter alerts by | Source types to filter alerts by. | False |
| Fetch closed alerts | Fetch closed alerts from Rapid7 platform. | False |
| Include CSV files of alerts |  | False |
| Include attachments of alerts | MSSP accounts must provide a sub-account ID to perform this action. | False |
| Sub-account ID (for MSSP accounts). |  | False |
| Incident type |  | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### threat-command-cyber-term-list

***
List cyber terms by filter.

#### Base Command

`threat-command-cyber-term-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Filter by free text, which can be the cyber term name or ID. | Optional | 
| types | A comma-separated list of cyber term types by which to filter the results. For example: ThreatActor,Campaign. Possible values are: Threat Actor, Malware, Campaign. | Optional | 
| severities | A comma-separated list of cyber term severities by which to filter the results. For example: High,Low. Possible values are: High, Medium, Low. | Optional | 
| sectors | A comma-separated list of targeted sectors by which to filter the results. For example: Education,Government. | Optional | 
| countries | A comma-separated list of targeted countries by which to filter the results. For example: Albania,Algeria. | Optional | 
| origins | A comma-separated list of nationalities by which to filter the results. For example: Egypt,Iraq. | Optional | 
| ttps | A comma-separated list of TTPs by which to filter the results. For example: Malware,Backdoor. | Optional | 
| last_update_from | Filter for results whose last update date is greater than the given value (in ISO 8601 format). For example:  2022-12-25T08:38:06Z. Default value: Last year. | Optional | 
| last_update_to | Filter for results whose last update date is less than the given value (in ISO 8601 format). For example:  2022-12-25T08:38:06Z. | Optional | 
| page | The page number of the results to retrieve (1-based). Default is 1. | Optional | 
| page_size | The number of objects per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.CyberTerm.id | String | The ID of the cyber term. | 
| ThreatCommand.CyberTerm.type | String | The type of the cyber term. | 
| ThreatCommand.CyberTerm.name | String | Name of the cyber term. | 
| ThreatCommand.CyberTerm.severity | String | The severity of the cyber term. | 
| ThreatCommand.CyberTerm.aliases | String | Aliases of the cyber term. | 
| ThreatCommand.CyberTerm.target_countries | String | List of targeted countries. | 
| ThreatCommand.CyberTerm.sectors | String | List of targeted sectors. | 
| ThreatCommand.CyberTerm.origins | String | List of origin nationalities. | 
| ThreatCommand.CyberTerm.created_date | Date | The date the cyber term was first reported. | 
| ThreatCommand.CyberTerm.updated_date | Date | The date the cyber term was last updated. | 
| ThreatCommand.CyberTerm.ttp | String | List of TTPs. | 
| ThreatCommand.CyberTerm.overview | String | Overview of the cyber term. | 
| ThreatCommand.CyberTerm.additional_information | String | Additional information about the cyber term. | 
| ThreatCommand.CyberTerm.related_malware | String | Related malware names. | 
| ThreatCommand.CyberTerm.related_threat_actor | String | Related threat actor names. | 
| ThreatCommand.CyberTerm.related_campaigns | String | Related campaign names. | 
| ThreatCommand.CyberTerm.MitreAttack.tactic | String | MITRE ATT&amp;CK tactic name related to the cyber term. | 
| ThreatCommand.CyberTerm.MitreAttack.Techniques.name | String | MITRE ATT&amp;CK technique names. | 
| ThreatCommand.CyberTerm.MitreAttack.Techniques.url | String | MITRE ATT&amp;CK technique URLs. | 

#### Command example

```!threat-command-cyber-term-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "CyberTerm": {
            "MitreAttack": [],
            "additional_information": "N/A",
            "aliases": [],
            "created_date": "2022-05-09T08:57:28.920Z",
            "id": "6278d77884709631217f2ead",
            "name": "Curious Gorge",
            "origins": [
                "China"
            ],
            "overview": "The Curious Gorge threat group was first reported by Google's Threat Analysis Group (TAG) in March 2022, amidst the Russo-Ukrainian War. The APT group, attributed to China’s Liberation Army Strategic Support Force (PLA SSF), targets government, military, logistics, and manufacturing organizations in Ukraine, Russia, and Central Asia. There is little information about Curious Gorge’s TTPs. \n\nIn March 2022, Curious Gorge was observed targeting government and military organizations in Ukraine, Russia, Kazakhstan, and Mongolia. \n\nIn May 2022, Google reported that Curious Gorge attacked multiple government organizations in Russia, including the Ministry of Foreign Affairs as well as Russian defense contractors, manufacturers, and a logistics company. \n\nThe attacks of a Chinese state-sponsored group against Russian entities are interesting, as the two countries are allies. It may reflect a possible shift in China's intelligence collection objectives amidst the Russo-Ukrainian War.",
            "related_campaigns": [
                "The 2022 Russia-Ukraine Cyberwarfare"
            ],
            "related_malware": [],
            "related_threat_actor": [],
            "sectors": [
                "Aerospace/Defense",
                "Government",
                "Manufacturing"
            ],
            "severity": "Medium",
            "target_countries": [
                "Kazakhstan",
                "Mongolia",
                "Russian Federation",
                "Ukraine"
            ],
            "ttp": [],
            "type": "ThreatActor",
            "updated_date": "2022-05-09T09:04:11.589Z"
        }
    }
}
```

#### Human Readable Output

>### Cyber terms

>|Id|Name|Severity|Overview|Target Countries|Sectors|Related Campaigns|
>|---|---|---|---|---|---|---|
>| 6278d77884709631217f2ead | Curious Gorge | Medium | The Curious Gorge threat group was first reported by Google's Threat Analysis Group (TAG) in March 2022, amidst the Russo-Ukrainian War. The APT group, attributed to China’s Liberation Army Strategic Support Force (PLA SSF), targets government, military, logistics, and manufacturing organizations in Ukraine, Russia, and Central Asia. There is little information about Curious Gorge’s TTPs. <br/><br/>In March 2022, Curious Gorge was observed targeting government and military organizations in Ukraine, Russia, Kazakhstan, and Mongolia. <br/><br/>In May 2022, Google reported that Curious Gorge attacked multiple government organizations in Russia, including the Ministry of Foreign Affairs as well as Russian defense contractors, manufacturers, and a logistics company. <br/><br/>The attacks of a Chinese state-sponsored group against Russian entities are interesting, as the two countries are allies. It may reflect a possible shift in China's intelligence collection objectives amidst the Russo-Ukrainian War. | Kazakhstan,<br/>Mongolia,<br/>Russian Federation,<br/>Ukraine | Aerospace/Defense,<br/>Government,<br/>Manufacturing | The 2022 Russia-Ukraine Cyberwarfare |


### threat-command-cyber-term-cve-list

***
List cyber term CVEs by cyber term ID.

#### Base Command

`threat-command-cyber-term-cve-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cyber_term_id | Cyber term unique ID (dependencies - use threat-command-cyber-term-list command to get all the cyber term IDs). | Required | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_results | Show all results if True. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.CVE.id | String | CVE ID. | 
| ThreatCommand.CVE.publish_date | String | CVE publish date. | 
| ThreatCommand.CVE.vendor_product | Number | CVE vendor product. | 

#### Command example

```!threat-command-cyber-term-cve-list cyber_term_id=1234 limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "CVE": {
            "id": "CVE-2015-8562",
            "publish_date": "2015-12-16T21:59:00.000Z",
            "vendor_product": [
                "Joomla Joomla\\!"
            ]
        }
    }
}
```

#### Human Readable Output

>### Related CVEs to Cyber term 628223a9b8a7a90f3aca3d7d

>|Id|Publish Date|Vendor Product|
>|---|---|---|
>| CVE-2015-8562 | 2015-12-16T21:59:00.000Z | Joomla Joomla\! |


### threat-command-cyber-term-ioc-list

***
List cyber term IOCs by cyber term ID.

#### Base Command

`threat-command-cyber-term-ioc-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cyber_term_id | Cyber term unique ID (dependencies - use threat-command-cyber-term-list command to get all the cyber term IDs). | Required | 
| ioc_type | IOC types to include. Possible values are: Ip Addresses, Urls, Domains, Hashes, Emails. | Optional | 
| page | The page number of the results to retrieve (1-based). Default is 1. | Optional | 
| page_size | The number of objects per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.IOC.value | String | The value of the IOC. | 
| ThreatCommand.IOC.type | String | The type of the IOC. | 
| ThreatCommand.IOC.updated_date | String | The date the IOC was last updated. | 
| ThreatCommand.IOC.status | String | The status of the IOC. | 
| ThreatCommand.IOC.is_whitelisted | String | Whether the IOC is whitelisted. | 
| ThreatCommand.IOC.severity | String | The severity of the IOC. | 
| ThreatCommand.IOC.reporting_feeds | String | List of reporting feeds in which the value appears. | 

#### Command example

```!threat-command-cyber-term-ioc-list cyber_term_id=1234 limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "IOC": {
            "is_whitelisted": false,
            "reporting_feeds": [
                "Threat Library",
                "AlienVault OTX"
            ],
            "severity": "Medium",
            "status": "Active",
            "type": "Hashes",
            "updated_date": "2022-11-17T11:13:28.000Z",
            "value": "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5"
        }
    }
}
```

#### Human Readable Output

>### Related IOCs to Cyber term 628223a9b8a7a90f3aca3d7d

>|Value|Type|Is Whitelisted|Updated Date|
>|---|---|---|---|
>| 11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5 | Hashes | false | 2022-11-17T11:13:28.000Z |


### threat-command-source-list

***
Gets lists of IOC document sources.

#### Base Command

`threat-command-source-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_results | Show all results if True. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Source.id | String | Source ID. | 
| ThreatCommand.Source.name | String | Source name. | 
| ThreatCommand.Source.confidence_level | Number | Source confidence level. | 
| ThreatCommand.Source.is_enable | Boolean | Whether the source is enabled. | 
| ThreatCommand.Source.type | String | Source type. | 

#### Command example

```!threat-command-source-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "Source": {
            "confidence_level": 3,
            "id": "5b68306cf84f7c8696047fda",
            "is_enabled": true,
            "name": "AlienVault OTX",
            "type": "IntelligenceFeed"
        }
    }
}
```

#### Human Readable Output

>### IOC sources

>|Id|Name|Confidence Level|Type|
>|---|---|---|---|
>| 5b68306cf84f7c8696047fda | AlienVault OTX | 3 | IntelligenceFeed |


### threat-command-source-document-create

***
Adds a new IOC source document. At least one IOC is required.

#### Base Command

`threat-command-source-document-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Source name. | Required | 
| description | Source description. | Required | 
| confidence_level | Source confidence level. Possible values are: 1, 2, 3. | Required | 
| share | Whether to share this source with all tenants (available for MSSP users only). Possible values are: true, false. | Optional | 
| severity | Source severity level. Possible values are: High, Medium, Low. | Optional | 
| tags | Comma-separated list of user tags for the document. | Optional | 
| domains | Comma-separated list of domain IOC values to add. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to add. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of IP IOC values to add. For example: 8.8.8.8,1.2.3.4. | Optional | 
| hashes | Comma-separated list of hash IOC values to add. For example: 8100f3d2668f0f61e6c7ea0dfda59458111238dfeeb9bf47d9fa7543abfb6fb7. | Optional | 
| emails | Comma-separated list of email IOC values to add. For example: test@test.com. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Source.Files.id | String | Document source ID. | 
| ThreatCommand.Source.Files.name | String | Document source name. | 

#### Command example

```!threat-command-source-document-create name=2023test description=test confidence_level=1 domains=test.com```

#### Context Example

```json
{
    "ThreatCommand": {
        "Source": {
            "Files": {
                "id": "64538007a44a2f2d6740f6be",
                "name": "2023test"
            }
        }
    }
}
```

#### Human Readable Output

>### Source document successfully created.

>|Id|Name|
>|---|---|
>| 64538007a44a2f2d6740f6be | 2023test |


### threat-command-source-document-delete

***
Deletes an existing IOC source document.

#### Base Command

`threat-command-source-document-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_id | The ID of the source document (dependencies - use threat-command-source-ioc-get command with  source_type="Files" to get all the document source IDs). | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-source-document-delete source_id=6400a3289083fa5eab401cdd```

#### Human Readable Output

>Source document "6400a3289083fa5eab401cdd" successfully deleted.

### threat-command-source-document-ioc-create

***
Create new IOCs to existing IOC source documents. At least one IOC is required.

#### Base Command

`threat-command-source-document-ioc-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_id | The ID of the source document (dependencies - use threat-command-source-ioc-get command with  source_type="Files" to get all the document source IDs). | Required | 
| domains | Comma-separated list of domain IOC values to create. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to create. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of IP IOC values to create. For example: 8.8.8.8,1.2.3.4. | Optional | 
| hashes | Comma-separated list of hash IOC values to create. For example: 8100f3d2668f0f61e6c7ea0dfda59458111238dfeeb9bf47d9fa7543abfb6fb7. | Optional | 
| emails | Comma-separated list of email IOC values to create. For example: test@test.com. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-source-document-ioc-create source_id=6400a3289083fa5eab401cdd domains=test.com```

#### Human Readable Output

>IOC "['test.com']" successfully added to "6400a3289083fa5eab401cdd" document source.

### threat-command-ioc-search

***
Gets IOC details by value or IOC's full enrichment data. While using the enrichment flag, the command is scheduled and allows us to get full enrichment data. Note that enrichment has a quota. You can get the quota by using threat-command-quotas-usage-get.

#### Base Command

`threat-command-ioc-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_value | IOC value. Required when last_updated_from is not selected. Not supported for email addresses. While using this argument, all the other filtering arguments are not relevant. . | Optional | 
| page | The page number of the results to retrieve (1-based). Default is 1. | Optional | 
| page_size | The number of objects per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| enrichment | Enrichment flag. Use True to enrich the data about the IOC. Supported IOC types are: Domains, URLs, IP addresses and file hashes. While using this argument, all the other filtering arguments are not relevant (except ioc_value). . Possible values are: true, false. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Relevant while enrichment=true. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Relevant while enrichment=true. Default is 600. | Optional | 
| last_updated_from | Filter by last update date (IOC update date is greater than). For example:  2022-12-25T08:38:06Z. Required when ioc_value is not selected. | Optional | 
| last_updated_to | Filter by last update date (IOC update date is less than). For example:  2022-12-25T08:38:06Z. | Optional | 
| last_seen_from | Filter by last seen date (IOC last seen date is greater than). For example:  2022-12-25T08:38:06Z. | Optional | 
| last_seen_to | Filter by last seen date (IOC last seen date is less than). For example:  2022-12-25T08:38:06Z. | Optional | 
| first_seen_from | Filter by first seen date (IOC first seen date is greater than). For example:  2022-12-25T08:38:06Z. | Optional | 
| first_seen_to | Filter by first seen date (IOC first seen date is less than). For example:  2022-12-25T08:38:06Z. | Optional | 
| status | Filter by IOC status. Possible values are: Active, Retired. | Optional | 
| type_list | Comma-separated list of IOC types to filter. For example: Urls,Domains. Possible values are: Ip Addresses, Urls, Domains, Hashes, Emails. | Optional | 
| severity_list | Comma-separated list of IOC severities to filter. For example: Low,Medium. Possible values are: High, Medium, Low. | Optional | 
| whitelisted | Filter by whitelist status. Possible values are: true, false. | Optional | 
| source_ids | Comma-separated list of source IDs (dependencies - use threat-command-source-document-ioc-get command to get all the document source IDs). | Optional | 
| kill_chain_phases | Comma-separated list of the phase of the Lockheed-Martin kills chain. For example: Delivery,Exploitation. Possible values are: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control, Actions on Objective. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.IOC.value | String | IOC value. | 
| ThreatCommand.IOC.type | String | IOC type. | 
| ThreatCommand.IOC.Source.name | String | IOC source name \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.Source.confindece_level | String | IOC source confidence level\(Relevant to enrichment only\). | 
| ThreatCommand.IOC.system_tags | String | IOC system tags \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.tags | String | IOC tags. | 
| ThreatCommand.IOC.status | String | IOC status is determined based on how recently the IOC was last seen. \(Active/Retired\).The domain is active for 3 months, the Email address for 2 months, the File hash for 1 year, the IP address for 2 weeks, and the URL for 2 months. | 
| ThreatCommand.IOC.is_known_ioc | Boolean | Whether the IOC is known \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.related_malware | String | Malware related to the IOC \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.RelatedThreatActors.value | String | Threat actors related to the IOC \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.related_campaign | String | Related campaign \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.first_seen | Date | IOC first seen date. | 
| ThreatCommand.IOC.last_seen | Date | IOC last seen date. | 
| ThreatCommand.IOC.update_seen | Date | IOC updated seen date \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.is_whitelisted | Boolean | Whether the IOC is whitelisted. | 
| ThreatCommand.IOC.Severity.value | String | IOC severity value. | 
| ThreatCommand.IOC.Severity.score | Number | IOC severity score. | 
| ThreatCommand.IOC.Severity.origin | String | IOC severity origin \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.DnsRecord.value | String | IOC DNS recorded value \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.DnsRecord.type | String | IOC DNS recorded type \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.DnsRecord.first_resolved | Date | IOC DNS recorded first resolved \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.DnsRecord.last_resolved | Date | IOC DNS recorded last resolved \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.DnsRecord.count | String | IOC DNS record count \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.subdomains | String | IOC subdomain \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.History.status | String | History statuses \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.History.name_servers | String | History name servers \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.Current.status | String | Current statuses \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.Current.name_servers | String | Current name servers \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.Resolution.resolved_ip_address | String | Resolved IP address \(Relevant to domain IOC\) \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.Resolution.resolved_domain | String | Resolved domain \(Relevant to IP IOC\) \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.Resolution.reporting_sources | String | Reporting sources \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.RelatedHash.downloaded | String | Download hashes \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.RelatedHash.communicating | String | Communicating hashes \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.RelatedHashes.referencing | String | Referencing hashes \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.antivirus_scan_date | Date | Antivirus scan date \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.file_name | String | File name \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.file_type | String | File type \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.file_author | String | File author \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.file_description | String | File description \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.file_size | Number | File size \(the file size is shown in bytes\) \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.antivirus_detection_ratio | String | Antivirus detection ratio \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.antivirus_detected_engines | String | Antivirus-detected engines \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.AntivirusDetection.name | String | Detection name \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.AntivirusDetection.version | String | Detection version \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.AntivirusDetection.detected | Boolean | Whether the IOC is detected \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.AntivirusDetection.result | String | Detection result \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.RelatedHash.type | String | Hash type \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.RelatedHash.value | String | Hash value \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.ip_range | String | IOC IP range \(Relevant to enrichment only\). | 
| ThreatCommand.IOC.last_update_date | Date | IOC last update date \(Relevant to search mode only\). | 
| ThreatCommand.IOC.geo_location | String | Geo location code \(Relevant to search mode only\). | 
| ThreatCommand.IOC.reportedFeeds.id | String | IOC reported feed ID \(Relevant to search mode only\). | 
| ThreatCommand.IOC.reportedFeeds.name | String | IOC reported feed name \(Relevant to search mode only\). | 
| ThreatCommand.IOC.reportedFeeds.confidence_level | Number | IOC reported feed confidence level \(Relevant to search mode only\). | 

#### Command example

```!threat-command-ioc-search ioc_value=test.com```

#### Context Example

```json
{
    "ThreatCommand": {
        "IOC": {
            "ReportedFeeds": [
                {
                    "confidence_level": 1,
                    "id": "64538007a44a2f2d6740f6be",
                    "name": "2023test"
                },
                {
                    "confidence_level": 1,
                    "id": "64537fa66a2fbddfeb0835f6",
                    "name": "test2023test"
                },
                {
                    "confidence_level": 1,
                    "id": "64537f2a31c0638f03a0e6d7",
                    "name": "test"
                }
            ],
            "first_seen": "2023-05-04T09:47:22.783Z",
            "is_whitelisted": true,
            "last_seen": "2023-05-04T09:51:03.300Z",
            "last_update_date": "2023-05-04T09:58:10.957Z",
            "related_campaigns": [],
            "related_malware": [],
            "related_threat_actors": [],
            "score": 85,
            "severity": "High",
            "status": "Active",
            "tags": [
                "test"
            ],
            "type": "Domains",
            "value": "test.com"
        }
    }
}
```

#### Human Readable Output

>### IOC "test.com"

>|Value|Type|Status|Is Whitelisted|Score|Severity|Last Update Date|
>|---|---|---|---|---|---|---|
>| test.com | Domains | Active | true | 85 | High | 2023-05-04T09:58:10.957Z |


### threat-command-ioc-tags-add

***
Adds user tags to IOCs. This enables you to classify IOCs and later search for all IOCs with a specific tag. There is no indication of success or failure for this command. The user has to choose a correct and existing IOC.

#### Base Command

`threat-command-ioc-tags-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_value | The IOC value. | Required | 
| tag_values | Comma-separated list of tags to add (Tag can be any word). For example: "Example Tag","Regional Alert". | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-ioc-tags-add ioc_value=test.com tag_values=test```

#### Human Readable Output

>The tags "['test']" successfully added to "test.com" IOC.

### threat-command-account-whitelist-update

***
You can add an IOC to your user whitelist (even if it is already on the system whitelist). If you change your mind, you can then revert that decision to rely again on the system designation using the threat-command-account-whitelist-remove command. When an IOC is whitelisted, it will not be sent to integrated security to block. When an IOC is not whitelisted, it will be sent to integrated security devices to block. There is no indication of success or failure for this command. The user has to choose a correct and existing IOC. At least one IOC is required. 

#### Base Command

`threat-command-account-whitelist-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| is_whitelisted | The whitelist status for the IOCs. Add to the user whitelist - The IOCs will not be passed to integrated devices. Do not whitelist - The IOCs will be passed to integrated devices, even if the IOCs are on the system whitelist. . Possible values are: Add to the user whitelist, Do not whitelist. | Required | 
| domains | Comma-separated list of domain IOC values to apply is_whitelisted to. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to apply is_whitelisted to. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of IP IOC values to apply is_whitelisted to. For example: 8.8.8.8,1.2.3.4. | Optional | 
| hashes | Comma-separated list of hash IOC values to apply is_whitelisted to. For example: 8100f3d2668f0f61e6c7ea0dfda59458111238dfeeb9bf47d9fa7543abfb6fb7. | Optional | 
| emails | Comma-separated list of email IOC values to apply is_whitelisted to. For example: test@test.com. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-account-whitelist-update is_whitelisted="Add to the user whitelist" domains=test.com```

#### Human Readable Output

>The status "Add to the user whitelist" successfully updated to "['test.com']" IOCs in the account whitelist.

### threat-command-account-whitelist-remove

***
Reverts IOC values to the system-default whitelist status. The ETP Suite automatically whitelists certain IOCs, such as company assets. You can override this designation or ensure that certain IOCs will not be system whitelisted using the threat-command-account-whitelist-update command. There is no indication of success or failure for this command. The user has to choose a correct and existing IOC. At least one IOC is required.

#### Base Command

`threat-command-account-whitelist-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | Comma-separated list of domain IOC values to be reverted back to the system whitelist default. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to be reverted back to the system whitelist default. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of domain IOC values to be reverted back to the system whitelist default. For example: 8.8.8.8,1.2.3.4. | Optional | 
| hashes | Comma-separated list of domain IOC values to be reverted back to the system whitelist default. For example: 8100f3d2668f0f61e6c7ea0dfda59458111238dfeeb9bf47d9fa7543abfb6fb7. | Optional | 
| emails | Comma-separated list of domain IOC values to be reverted back to the system whitelist default. For example: test@test.com. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-account-whitelist-remove domains=test.com```

#### Human Readable Output

>The IOCs "['test.com']" successfully removed from the account whitelist.

### threat-command-ioc-blocklist-add

***
Adds an IOC to an internal Remediation Blocklist. By sending the blocklist to security devices, you can block the IOCs. At least one IOC is required.

#### Base Command

`threat-command-ioc-blocklist-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | Comma-separated list of domain IOC values to add to the Remediation blocklist. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to add to the Remediation blocklist. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of IP IOC valuesto add to the Remediation blocklist. For example: 8.8.8.8,1.2.3.4. | Optional | 
| hashes | Comma-separated list of hash IOC values to add to the Remediation blocklist. For example: 8100f3d2668f0f61e6c7ea0dfda59458111238dfeeb9bf47d9fa7543abfb6fb7. | Optional | 
| emails | Comma-separated list of email IOC values to add to the Remediation blocklist. For example: test@test.com. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-ioc-blocklist-add domains=test.com```

#### Human Readable Output

>The IOCs "['test.com']" successfully added to the remediation blocklist.

### threat-command-ioc-blocklist-remove

***
Removes IOC values from the Remediation blocklist. There is no indication of success or failure for this command. The user has to choose a correct and existing IOC. At least one IOC is required.

#### Base Command

`threat-command-ioc-blocklist-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domains | Comma-separated list of domain IOC values to remove from the Remediation blocklist. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to remove from the Remediation blocklist. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of IP IOC values to remove from the Remediation blocklist. For example: 8.8.8.8,1.2.3.4. | Optional | 
| hashes | Comma-separated list of hash IOC values to remove from the Remediation blocklist. For example: 8100f3d2668f0f61e6c7ea0dfda59458111238dfeeb9bf47d9fa7543abfb6fb7. | Optional | 
| emails | Comma-separated list of email IOC values to remove from the Remediation blocklist. For example: test@test.com. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-ioc-blocklist-remove domains=test.com```

#### Human Readable Output

>The IOCs "['test.com']" successfully removed from the remediation blocklist.

### threat-command-ioc-severity-update

***
Changes the severity of existing IOCs for the requester account (overrides the system severity). At least one IOC is required.

#### Base Command

`threat-command-ioc-severity-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | The severity of the IOCs. Possible values are: High, Medium, Low. | Required | 
| domains | Comma-separated list of domain IOC values to update the severity. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to update the severity. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of IP IOC values to update the severity. For example: 8.8.8.8,1.2.3.4. | Optional | 
| hashes | Comma-separated list of hash IOC values to update the severity. For example: 8100f3d2668f0f61e6c7ea0dfda59458111238dfeeb9bf47d9fa7543abfb6fb7. | Optional | 
| emails | Comma-separated list of email IOC values to update the severity. For example: test@test.com. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-ioc-severity-update severity=High domains=test.com```

#### Human Readable Output

>The severity "High" successfully updated to "['test.com']" IOCs.

### threat-command-ioc-comment-add

***
Adds comments to IOCs. At least one IOC is required.

#### Base Command

`threat-command-ioc-comment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | The comment to add. | Required | 
| domains | Comma-separated list of domain IOC values to add the comment to. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to add the comment to. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of IP IOC values to add the comment to. For example: 8.8.8.8,1.2.3.4. | Optional | 
| hashes | Comma-separated list of hash IOC values to add the comment to. For example: 8100f3d2668f0f61e6c7ea0dfda59458111238dfeeb9bf47d9fa7543abfb6fb7. | Optional | 
| emails | Comma-separated list of email IOC values to add the comment to. For example: test@test.com. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-ioc-comment-add comment=test domains=test.com```

#### Human Readable Output

>The comment "test" successfully updated to "['test.com']" IOCs.

### threat-command-enrichment-quota-usage

***
Gets the current API enrichment credits ("quota") usage for the requester account.

#### Base Command

`threat-command-enrichment-quota-usage`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-enrichment-quota-usage```

#### Context Example

```json
{
    "ThreatCommand": {
        "IOCsQuota": {
            "remaining": 43,
            "time_period": "2023-05-04",
            "total": 50
        }
    }
}
```

#### Human Readable Output

>### Current API enrichment credits (quota).

>|Time Period|Total|Remaining|
>|---|---|---|
>| 2023-05-04 | 50 | 43 |


### threat-command-alert-list

***
Get a list of alerts with all details.

#### Base Command

`threat-command-alert-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Optional | 
| page | The page number of the results to retrieve (1-based). Default is 1. | Optional | 
| page_size | The number of objects per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| retrieve_ids_only | Retrieve alert IDs only. Set to False in order to get the alerts with complete data details, and set to True in order to get a list of alerts. Possible values are: true, false. | Optional | 
| last_updated_from | Start date to fetch from. For example:  2022-12-25T08:38:06Z. Default is 1970-01-01T00:00:00.000Z. | Optional | 
| alert_type | Alert's type. Possible values are: Attack Indication, Data Leakage, Phishing, Brand Security, Exploitable Data, vip. | Optional | 
| severity | Comma-separated list of alert severities. For example:High,Medium. Possible values are: High, Medium, Low. | Optional | 
| source_type | Comma-separated list of alert source types. For example:Others,Markets. Possible values are: Application Stores, Black Markets, Hacking Forums, Social Media, Paste Sites, Others. | Optional | 
| network_type | Comma-separated list of alert network types. For example:Clear Web,Dark Web. Possible values are: Clear Web, Dark Web. | Optional | 
| matched_asset_value | Comma-separated list of alert matched assets. | Optional | 
| last_updated_to | End date to fetch to. For example:  2022-12-25T08:38:06Z. | Optional | 
| source_date_from | Start date to fetch from. For example:  2022-12-25T08:38:06Z. | Optional | 
| source_date_to | End date to fetch to. For example:  2022-12-25T08:38:06Z. | Optional | 
| found_date_from | Start date to fetch from. For example:  2022-12-25T08:38:06Z. | Optional | 
| found_date_to | End date to fetch to. For example:  2022-12-25T08:38:06Z. | Optional | 
| assigned | Show assigned/unassigned alerts. Possible values are: true, false. | Optional | 
| is_flagged | Show flagged/unflagged alerts. Possible values are: true, false. | Optional | 
| is_closed | Show closed/open alerts. Possible values are: true, false. | Optional | 
| has_ioc | Show alerts with IOC results. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.id | String | Alert ID. | 
| ThreatCommand.Alert.assets.type | Date | Asset type. | 
| ThreatCommand.Alert.assets.value | String | Asset value. | 
| ThreatCommand.Alert.assignees | String | Assignees list. | 
| ThreatCommand.Alert.type | String | Alert type list. | 
| ThreatCommand.Alert.sub_type | String | Alert sub type. | 
| ThreatCommand.Alert.title | String | Alert title. | 
| ThreatCommand.Alert.description | String | Alert description. | 
| ThreatCommand.Alert.severity | String | Alert severity. | 
| ThreatCommand.Alert.images | String | Alert images list. | 
| ThreatCommand.Alert.source_type | String | Alert type. | 
| ThreatCommand.Alert.source_url | String | Alert URL source. | 
| ThreatCommand.Alert.source_email | String | Alert email source. | 
| ThreatCommand.Alert.source_network_type | String | Alert network type. | 
| ThreatCommand.Alert.source_date | Date | Alert date. | 
| ThreatCommand.Alert.Tags.created_by | String | Alert tag creator. | 
| ThreatCommand.Alert.Tags.name | String | Alert tag name. | 
| ThreatCommand.Alert.Tags.id | String | Alert tag ID. | 
| ThreatCommand.Alert.related_iocs | String | Alert related IOC list. | 
| ThreatCommand.Alert.found_date | String | Alert found date. | 
| ThreatCommand.Alert.update_date | String | Alert update date. | 
| ThreatCommand.Alert.takedown_status | String | Alert remediation status. | 
| ThreatCommand.Alert.is_closed | Boolean | Whether the alert is closed. | 
| ThreatCommand.Alert.is_flagged | Boolean | Whether the alert is flagged. | 
| ThreatCommand.Alert.related_threat_ids | String | Alert-related threat IDs. | 

#### Command example

```!threat-command-alert-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "Tags": [],
            "assets": [],
            "assignees": [],
            "description": "Asfsdfiption",
            "found_date": "2018-01-01T00:00:00.000Z",
            "id": "641b19b45d60c905560fc484",
            "images": [],
            "is_closed": false,
            "is_flagged": false,
            "related_iocs": [
                "https://test.com/cghostinfo"
            ],
            "related_threat_ids": [],
            "severity": "Low",
            "source_date": "None",
            "source_email": "",
            "source_network_type": "DarkWeb",
            "source_type": "Credit Card Black Market",
            "source_url": "https://test.com/cghostinfo",
            "sub_type": "VulnerabilityInTechnologyInUse",
            "takedown_status": "NotSent",
            "title": "sdfsdf",
            "type": "AttackIndication",
            "update_date": "2018-01-01T00:00:00.000Z"
        }
    }
}
```

#### Human Readable Output

>### Alert list

>|Id|Type|Sub Type|Title|Description|Severity|Found Date|Is Closed|
>|---|---|---|---|---|---|---|---|
>| 641b19b45d60c905560fc484 | AttackIndication | VulnerabilityInTechnologyInUse | sdfsdf | Asfsdfiption | Low | 2018-01-01T00:00:00.000Z | false |


### threat-command-alert-takedown-request

***
Send a takedown request for the selected alert (Request that Threat Command will contact the host to request a takedown of a malicious domain, website, or mobile application).

#### Base Command

`threat-command-alert-takedown-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| target | Takedown target. Available for phishing scenarios only. If you have evidence of malicious activity associated with this domain, select Domain. Possible values are: Domain, Website. Default is Domain. | Optional | 
| close_alert_after_success | Whether to close the alert after successful remediation. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.

### threat-command-alert-takedown-request-status-get

***
Get the alert's takedown status.

#### Base Command

`threat-command-alert-takedown-request-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.takedown_status | String | Alert's takedown status. | 

#### Command example

```!threat-command-alert-takedown-request-status-get alert_id=1234```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "id": "1234",
            "takedown_status": "\"NotSent\""
        }
    }
}
```

#### Human Readable Output

>### Takedown status for alert "1234".

>|Takedown Status|
>|---|
>| "NotSent" |


### threat-command-alert-create

***
Create a new alert. You have to insert scenario or type and sub_type.

#### Base Command

`threat-command-alert-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| found_date | Alert's found date. For example:  2022-12-25T08:38:06Z. The defaut value is the current time. | Optional | 
| title | Alert's title. | Required | 
| description | Alert's description. | Required | 
| type | Alert's type (dependencies - use threat-command-alert-type-list command to get all the alert types). Required while scenario not inserted. Possible values are: Attack Indication, Data Leakage, Phishing, Brand Security, Exploitable Data, vip. | Optional | 
| sub_type | Alert subtype (dependencies - use threat-command-alert-type-list command to get all the alert subtypes). Required while scenario not inserted. | Optional | 
| severity | Alert's severity. Possible values are: High, Medium, Low. | Required | 
| source_type | Alert source type (dependencies - use threat-command-alert-source-type-list command to get all the alert source types). | Required | 
| source_network_type | Source network type. Possible values are: Clear Web, Dark Web. | Required | 
| source_url | The source URL of the alert. . | Optional | 
| source_date | Alert's source date. For example:  2022-12-25T08:38:06Z. | Optional | 
| image_entry_ids | Comma-separated list of image entry IDs to attach to the alert. Allowed image types: gif,jpeg. | Optional | 
| scenario | If provided, the related values will override any type and sub_type parameters (dependencies - use the threat-command-alert-scenario-list command to get all the alert scenarios). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.id | String | Alert ID. | 

#### Command example

```!threat-command-alert-create title="test" description="test" severity="Low" source_type="Application Store" source_network_type="Clear Web" source_url="test.com" scenario="ACompanyEmailAddressReportedAsMalicious"```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "id": "64538b71ba5d3f7a8fb27ddc"
        }
    }
}
```

#### Human Readable Output

>### Alert successfully created

>|Id|
>|---|
>| 64538b71ba5d3f7a8fb27ddc |


### threat-command-alert-close

***
Close alert.

#### Base Command

`threat-command-alert-close`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| reason | Alert's closed reason. Possible values are: Problem Solved, Informational Only, Problem We Are Already Aware Of, Company Owned Domain, Legitimate Application/Profile, Not Related To My Company, False Positive, Other. | Required | 
| comment | Alert's comments. | Optional | 
| is_hidden | Alerts' hidden status (Delete alert from the account instance only when reason is FalsePositive). Possible values are: true, false. | Optional | 
| rate | Alert's rate. Rate range: 0-5 (The range not officaly documented). Possible values are: 0, 1, 2, 3, 4, 5. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.id | String | Alert ID. | 
| ThreatCommand.Alert.is_closed | String | Whether the alert is closed. | 

#### Command example

```!threat-command-alert-close alert_id=1234 reason=Other```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "id": "1234",
            "is_closed": true
        }
    }
}
```

#### Human Readable Output

>### Alert "1234" successfully closed

>|Id|Is Closed|
>|---|---|
>| 1234 | true |


### threat-command-alert-severity-update

***
Change the alert's severity. Changing the severity level of alerts can help to prioritize alert management.

#### Base Command

`threat-command-alert-severity-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| severity | The desired severity. Possible values are: High, Medium, Low. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.id | String | Alert ID. | 
| ThreatCommand.Alert.severity | String | Alert severity. | 

#### Command example

```!threat-command-alert-severity-update alert_id=1234 severity=Medium```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "id": "1234",
            "severity": "Medium"
        }
    }
}
```

#### Human Readable Output

>### Alert "1234" severity successfully updated to "Medium".

>|Id|Severity|
>|---|---|
>| 1234 | Medium |


### threat-command-alert-blocklist-get

***
Get alert's blocklist status.

#### Base Command

`threat-command-alert-blocklist-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.id | String | Alert ID. | 
| ThreatCommand.Alert.BlockList.value | String | Alert blocklist value. | 
| ThreatCommand.Alert.BlockList.status | String | Alert blocklist status. | 

#### Command example

```!threat-command-alert-blocklist-get alert_id=1234```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "BlockList": [],
            "id": "1234"
        }
    }
}
```

#### Human Readable Output

>### Blocklist for alert "1234".

>**No entries.**


### threat-command-alert-blocklist-update

***
Change selected IOCs blocklist status.

#### Base Command

`threat-command-alert-blocklist-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| domains | Comma-separated list of domain IOC values to add. For example: securitywap.com,test.com. | Optional | 
| urls | Comma-separated list of URL IOC values to add. For example: "http://securitywap.com/path". | Optional | 
| ips | Comma-separated list of IP IOC values to add. For example: 8.8.8.8,1.2.3.4. | Optional | 
| emails | Comma-separated list of email IOC values to add. For example: test@test.com. | Optional | 
| blocklist_status | Blocklist status. Possible values are: Sent, Not Sent. | Required | 

#### Context Output

There is no context output for this command.

### threat-command-alert-ioc-report

***
Report IOCs to external sources (Report the URLs and domains that are included in an alert to external sources. This can warn others of the potential danger of those IOCs).

#### Base Command

`threat-command-alert-ioc-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| external_sources | Comma-separated list of the desired source names (dependencies - use threat-command-source-ioc-get to get all the source names). For example:GoogleWebRisk,PhishTank.Since there are variety of sources that accept different types of IOCs, select only sources that accept the alert IOCs. | Required | 

#### Context Output

There is no context output for this command.

### threat-command-alert-assign

***
Assign an alert to other ETP Suite users. When an alert is assigned, the assignee will receive a notification. Mainly used to assign alerts.

#### Base Command

`threat-command-alert-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| user_id | Assigned user ID (dependencies - use threat-command-mssp-user-list or threat-command-account-user-list to get user IDs). | Required | 
| is_mssp | If the assigned user is an MSSP user or not. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.id | String | Alert ID. | 
| ThreatCommand.Alert.assignees | String | Assignees list. | 

#### Command example

```!threat-command-alert-assign alert_id=1234 user_id=1234```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "assignees": [
                "1234"
            ],
            "id": "1234"
        }
    }
}
```

#### Human Readable Output

>### Alert "1234" successfully assign to user "631ef479b675f72ec9309785".

>|Id|Assignees|
>|---|---|
>| 1234 | 1234 |


### threat-command-alert-unassign

***
Unassign an alert from all users.

#### Base Command

`threat-command-alert-unassign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.id | String | Alert ID. | 
| ThreatCommand.Alert.assignees | String | Assignees list. | 

#### Command example

```!threat-command-alert-unassign alert_id=1234```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "assignees": null,
            "id": "1234"
        }
    }
}
```

#### Human Readable Output

>### Alert '1234' successfully unassigned from any user.

>|Id|
>|---|
>| 1234 |


### threat-command-alert-reopen

***
Reopen alert.

#### Base Command

`threat-command-alert-reopen`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-alert-reopen alert_id=1234```

#### Human Readable Output

>Alert "1234" successfully re-opened.

### threat-command-alert-tag-add

***
Adds a tag to an alert. This enables you to classify alerts and later search for all alerts with a specific tag.

#### Base Command

`threat-command-alert-tag-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| tag_name | The new tag string. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-alert-tag-add alert_id=1234 tag_name=test```

#### Human Readable Output

>The tag "test" successfully added to "1234" Alert.

### threat-command-alert-tag-remove

***
Removes a tag from the alert.

#### Base Command

`threat-command-alert-tag-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| tag_id | Tag's unique ID to remove (dependencies - use threat-command-alert-list command to get all the tag IDs). | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-alert-tag-remove alert_id=6432e3aa6ff61aae819dc46b tag_id=1234```

#### Human Readable Output

>The tag "6453871c0d771fdc938f18d5" successfully removed from "6432e3aa6ff61aae819dc46b" Alert.

### threat-command-alert-send-mail

***
Send mail with the alert details and a question.

#### Base Command

`threat-command-alert-send-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| email_addresses | Comma-separated list of destinaions email addresses. | Required | 
| content | Content added to the alert details. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-alert-send-mail alert_id=6432e3aa6ff61aae819dc46b email_addresses=test@test.com content=test```

#### Human Readable Output

>The alert "6432e3aa6ff61aae819dc46b" successfully send to "['test@test.com']".

### threat-command-alert-analyst-ask

***
Send a question to an analyst about the requested alert. Questions can revolve around an alert explanation, a request for more context, recommended remediation steps, or requests for threat actor engagement. In order to get the conversation with the analyst, use the threat-command-alert-analyst-conversation-list command.

#### Base Command

`threat-command-alert-analyst-ask`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| question | Question added to the alert details. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-alert-analyst-ask alert_id=1234 question=test```

#### Human Readable Output

>The alert "1234" successfully sent to the analyst.

### threat-command-alert-analyst-conversation-list

***
Get alert's analyst response

#### Base Command

`threat-command-alert-analyst-conversation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.id | String | Alert ID. | 
| ThreatCommand.Alert.Message.date | String | Response date. | 
| ThreatCommand.Alert.Message.initiator | String | Response initiator. | 
| ThreatCommand.Alert.Message.message | String | Response message. | 

#### Command example

```!threat-command-alert-analyst-conversation-list alert_id=1234```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "Message": [
                {
                    "date": "2023-04-03T15:02:34.641Z",
                    "initiator": "test@test.com",
                    "message": "Hello"
                },
                {
                    "date": "2023-04-03T15:40:56.195Z",
                    "initiator": "Intsights",
                    "message": "Hi"
                },
                {
                    "date": "2023-04-03T18:29:41.169Z",
                    "initiator": "test@test.com",
                    "message": "thank you"
                },
            ],
            "id": "1234"
        }
    }
}
```

#### Human Readable Output

>### Alert conversation with analyst:

>|Initiator|Message|Date|
>|---|---|---|
>| test@test.com | Hello| 2023-04-03T15:02:34.641Z |
>| Intsights | Hi| 2023-04-03T15:40:56.195Z |
>| test@test.com | thank you| 2023-04-03T18:29:41.169Z |


### threat-command-alert-activity-log-get

***
Get alert activity log.

#### Base Command

`threat-command-alert-activity-log-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Alert.ActivityLog.rate | Number | Alert rate. | 
| ThreatCommand.Alert.ActivityLog.type | String | Alert type. | 
| ThreatCommand.Alert.ActivityLog.sub_types | String | Alert subtypes. | 
| ThreatCommand.Alert.ActivityLog.initiator | String | Alert initiator. | 
| ThreatCommand.Alert.ActivityLog.created_date | Date | Alert created date. | 
| ThreatCommand.Alert.ActivityLog.update_date | Date | Alert update date. | 
| ThreatCommand.Alert.ActivityLog.read_by | String | Alert read by. | 
| ThreatCommand.Alert.ActivityLog.id | String | Alert created ID. | 
| ThreatCommand.Alert.ActivityLog.tag_names | String | Alert tag names. | 
| ThreatCommand.Alert.ActivityLog.tag_ids | String | Alert tag IDs. | 
| ThreatCommand.Alert.ActivityLog.Mail.note_id | String | Alert note ID. | 
| ThreatCommand.Alert.ActivityLog.Mail.question | String | Alert mail question. | 
| ThreatCommand.Alert.ActivityLog.Mail.Replies.email | String | Alert mail reply email. | 
| ThreatCommand.Alert.ActivityLog.Mail.Replies.token | String | Alert mail reply token. | 
| ThreatCommand.Alert.ActivityLog.Mail.Replies.date | Date | Alert mail reply date. | 
| ThreatCommand.Alert.ActivityLog.Mail.Replies.read_by | String | Alert mail read by. | 
| ThreatCommand.Alert.ActivityLog.Mail.Replies.is_token_valid | Boolean | Alert mail reply is token valid. | 
| ThreatCommand.Alert.ActivityLog.Messages.initiator_id | String | Alert message ID. | 
| ThreatCommand.Alert.ActivityLog.Messages.initiator_is_support | Boolean | Whether asking the analyst is supported. | 
| ThreatCommand.Alert.ActivityLog.Messages.date | Date | Alert message date. | 
| ThreatCommand.Alert.ActivityLog.Messages.content | String | Alert message content. | 

#### Command example

```!threat-command-alert-activity-log-get alert_id=1234```

#### Context Example

```json
{
    "ThreatCommand": {
        "Alert": {
            "ActivityLog": [
                {
                    "created_date": "2023-03-23T20:54:11.730Z",
                    "id": "641cbc73bade6cc1ed3a1a25",
                    "initiator": "59490cd818a3b902664b4ed7",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "64214c014c75609d09ebb767",
                        "64214bc94c75609d09ebb56a",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "sub_types": [
                        "PolicyClose",
                        "PolicyTag"
                    ],
                    "type": "PolicyRule",
                    "update_date": "2023-03-23T20:54:11.730Z"
                },
                {
                    "created_date": "2023-03-26T14:21:10.178Z",
                    "id": "642054d68d62709fc5a6ae9b",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "64214c014c75609d09ebb767",
                        "64214bc94c75609d09ebb56a",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AlertRead",
                    "update_date": "2023-03-26T14:21:10.178Z"
                },
                {
                    "created_date": "2023-03-27T07:13:31.321Z",
                    "id": "6421421b21f4e115ecc8c931",
                    "initiator": "631ef479b675f72ec9309785",
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "64214c014c75609d09ebb767",
                        "64214bc94c75609d09ebb56a",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AlertReopened",
                    "update_date": "2023-03-27T07:13:31.321Z"
                },
                {
                    "created_date": "2023-03-27T08:00:49.244Z",
                    "id": "64214d318d62709fc5a99219",
                    "initiator": "64214c014c75609d09ebb767",
                    "rate": 0,
                    "read_by": [
                        "64214c014c75609d09ebb767",
                        "631ef479b675f72ec9309785",
                        "64214bc94c75609d09ebb56a",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AlertRead",
                    "update_date": "2023-03-27T08:00:49.244Z"
                },
                {
                    "created_date": "2023-03-27T13:20:02.865Z",
                    "id": "6421980221f4e115ecca9660",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "64214bc94c75609d09ebb56a",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "tag_ids": [
                        "641cbc74bade6cc1ed3a1a2a"
                    ],
                    "tag_names": [
                        "Historical Alert"
                    ],
                    "type": "RemoveTag",
                    "update_date": "2023-03-27T13:20:02.865Z"
                },
                {
                    "created_date": "2023-03-28T11:04:59.497Z",
                    "id": "6422c9db1b2080e62a5f60a0",
                    "initiator": "64214bc94c75609d09ebb56a",
                    "rate": 0,
                    "read_by": [
                        "64214bc94c75609d09ebb56a",
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AlertRead",
                    "update_date": "2023-03-28T11:04:59.497Z"
                },
                {
                    "created_date": "2023-03-28T11:05:02.300Z",
                    "id": "6422c9de071e6ceab7106a04",
                    "initiator": "64214bc94c75609d09ebb56a",
                    "rate": 0,
                    "read_by": [
                        "64214bc94c75609d09ebb56a",
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "tag_ids": [
                        "6422c9de071e6ceab7106a05"
                    ],
                    "tag_names": [
                        "test2"
                    ],
                    "type": "AddTag",
                    "update_date": "2023-03-28T11:05:02.300Z"
                },
                {
                    "created_date": "2023-03-28T11:47:43.170Z",
                    "id": "6422d3df28c6b34a7004b43d",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "tag_ids": [
                        "6422d3df28c6b34a7004b43e"
                    ],
                    "tag_names": [
                        "123"
                    ],
                    "type": "AddTag",
                    "update_date": "2023-03-28T11:47:43.170Z"
                },
                {
                    "created_date": "2023-03-30T16:53:26.193Z",
                    "id": "6425be860112b8035eedef2b",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "ChangedSeverity",
                    "update_date": "2023-03-30T16:53:26.193Z"
                },
                {
                    "created_date": "2023-04-03T14:10:35.277Z",
                    "id": "642ade5b841e1c963048d9fe",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "Assign",
                    "update_date": "2023-04-03T14:10:35.277Z"
                },
                {
                    "created_date": "2023-04-03T14:11:46.331Z",
                    "id": "642adea264ed2f6ce85abf13",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "Assign",
                    "update_date": "2023-04-03T14:11:46.331Z"
                },
                {
                    "created_date": "2023-04-03T14:11:50.358Z",
                    "id": "642adea664ed2f6ce85abf8c",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "Assign",
                    "update_date": "2023-04-03T14:11:50.358Z"
                },
                {
                    "created_date": "2023-04-03T14:11:55.831Z",
                    "id": "642adeab841e1c963048dba1",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "Assign",
                    "update_date": "2023-04-03T14:11:55.831Z"
                },
                {
                    "Messages": [
                        {
                            "content": "Hello",
                            "date": "2023-04-03T15:02:34.793Z",
                            "initiator_id": "631ef479b675f72ec9309785",
                            "initiator_is_support": false
                        },
                        {
                            "content": "Hi",
                            "date": "2023-04-03T15:40:56.197Z",
                            "initiator_is_support": true
                        },
                    ],
                    "created_date": "2023-04-03T15:02:34.793Z",
                    "id": "642aea8ababb12ffd004d60e",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AskTheAnalystRequest",
                    "update_date": "2023-05-04T10:11:58.270Z"
                },
                {
                    "created_date": "2023-04-03T15:02:34.795Z",
                    "id": "642aea8ababb12ffd004d610",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AskTheAnalystQuestion",
                    "update_date": "2023-04-03T15:02:34.795Z"
                },
                {
                    "created_date": "2023-04-03T15:40:56.199Z",
                    "id": "642af388ffcc326df6ba58da",
                    "initiator": "System",
                    "rate": 0,
                    "read_by": [
                        "63a1cc800d782c827d29e73d",
                        "631ef479b675f72ec9309785"
                    ],
                    "type": "AskTheAnalystAnswer",
                    "update_date": "2023-04-03T15:40:56.199Z"
                },
                {
                    "created_date": "2023-04-03T18:29:41.326Z",
                    "id": "642b1b1549600a740c70b1c7",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AskTheAnalystQuestion",
                    "update_date": "2023-04-03T18:29:41.326Z"
                },
                {
                    "created_date": "2023-04-03T19:06:43.557Z",
                    "id": "642b23c3128075fc8c55ad23",
                    "initiator": "System",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AskTheAnalystAnswer",
                    "update_date": "2023-04-03T19:06:43.557Z"
                },
                {
                    "created_date": "2023-04-04T10:30:26.005Z",
                    "id": "642bfc42841e1c96304dd178",
                    "initiator": "631ef479b675f72ec9309785",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785",
                        "63a1cc800d782c827d29e73d"
                    ],
                    "type": "AskTheAnalystQuestion",
                    "update_date": "2023-04-04T10:30:26.005Z"
                },
                {
                    "created_date": "2023-04-04T13:59:48.026Z",
                    "id": "642c2d54128075fc8c564fdb",
                    "initiator": "System",
                    "rate": 0,
                    "read_by": [
                        "631ef479b675f72ec9309785"
                    ],
                    "type": "AskTheAnalystAnswer",
                    "update_date": "2023-04-04T13:59:48.026Z"
                },
                {
                    "created_date": "2023-05-04T10:10:24.478Z",
                    "id": "645384909b3179c05ca2ad41",
                    "initiator": "API",
                    "type": "AlertClosed",
                    "update_date": "2023-05-04T10:10:24.478Z"
                },
                {
                    "created_date": "2023-05-04T10:10:33.304Z",
                    "id": "645384999b3179c05ca2adf6",
                    "initiator": "API",
                    "rate": 0,
                    "type": "ChangedSeverity",
                    "update_date": "2023-05-04T10:10:33.304Z"
                },
                {
                    "created_date": "2023-05-04T10:11:07.781Z",
                    "id": "645384bbd3e54df9a593372b",
                    "initiator": "API",
                    "rate": 0,
                    "type": "Assign",
                    "update_date": "2023-05-04T10:11:07.781Z"
                },
                {
                    "created_date": "2023-05-04T10:11:16.487Z",
                    "id": "645384c4d3e54df9a59338b4",
                    "initiator": "API",
                    "rate": 0,
                    "type": "Unassign",
                    "update_date": "2023-05-04T10:11:16.487Z"
                },
                {
                    "created_date": "2023-05-04T10:11:25.161Z",
                    "id": "645384cd08e4bc1e2948ec09",
                    "initiator": "API",
                    "type": "AlertReopened",
                    "update_date": "2023-05-04T10:11:25.161Z"
                },
                {
                    "created_date": "2023-05-04T10:11:33.638Z",
                    "id": "645384d511ba24a35d0ab861",
                    "initiator": "API",
                    "rate": 0,
                    "tag_ids": [
                        "645384d511ba24a35d0ab862"
                    ],
                    "tag_names": [
                        "test"
                    ],
                    "type": "AddTag",
                    "update_date": "2023-05-04T10:11:33.638Z"
                },
                {
                    "created_date": "2023-05-04T10:11:58.271Z",
                    "id": "645384ee6a6f7be836b95c00",
                    "initiator": "API",
                    "rate": 0,
                    "type": "AskTheAnalystQuestion",
                    "update_date": "2023-05-04T10:11:58.271Z"
                }
            ],
            "id": "1234"
        }
    }
}
```

#### Human Readable Output

>### Alert "1234" activity log

>|Id|Type|Update Date|Sub Types|Initiator|
>|---|---|---|---|---|
>| 641cbc73bade6cc1ed3a1a25 | PolicyRule | 2023-03-23T20:54:11.730Z | PolicyClose,<br/>PolicyTag | 59490cd818a3b902664b4ed7 |
>| 642054d68d62709fc5a6ae9b | AlertRead | 2023-03-26T14:21:10.178Z |  | 631ef479b675f72ec9309785 |
>| 6421421b21f4e115ecc8c931 | AlertReopened | 2023-03-27T07:13:31.321Z |  | 631ef479b675f72ec9309785 |
>| 64214d318d62709fc5a99219 | AlertRead | 2023-03-27T08:00:49.244Z |  | 64214c014c75609d09ebb767 |
>| 6421980221f4e115ecca9660 | RemoveTag | 2023-03-27T13:20:02.865Z |  | 631ef479b675f72ec9309785 |
>| 6422c9db1b2080e62a5f60a0 | AlertRead | 2023-03-28T11:04:59.497Z |  | 64214bc94c75609d09ebb56a |
>| 6422c9de071e6ceab7106a04 | AddTag | 2023-03-28T11:05:02.300Z |  | 64214bc94c75609d09ebb56a |
>| 6422d3df28c6b34a7004b43d | AddTag | 2023-03-28T11:47:43.170Z |  | 631ef479b675f72ec9309785 |
>| 6425be860112b8035eedef2b | ChangedSeverity | 2023-03-30T16:53:26.193Z |  | 631ef479b675f72ec9309785 |
>| 642ade5b841e1c963048d9fe | Assign | 2023-04-03T14:10:35.277Z |  | 631ef479b675f72ec9309785 |
>| 642adea264ed2f6ce85abf13 | Assign | 2023-04-03T14:11:46.331Z |  | 631ef479b675f72ec9309785 |
>| 642adea664ed2f6ce85abf8c | Assign | 2023-04-03T14:11:50.358Z |  | 631ef479b675f72ec9309785 |
>| 642adeab841e1c963048dba1 | Assign | 2023-04-03T14:11:55.831Z |  | 631ef479b675f72ec9309785 |
>| 642aea8ababb12ffd004d60e | AskTheAnalystRequest | 2023-05-04T10:11:58.270Z |  | 631ef479b675f72ec9309785 |
>| 642aea8ababb12ffd004d610 | AskTheAnalystQuestion | 2023-04-03T15:02:34.795Z |  | 631ef479b675f72ec9309785 |
>| 642af388ffcc326df6ba58da | AskTheAnalystAnswer | 2023-04-03T15:40:56.199Z |  | System |
>| 642b1b1549600a740c70b1c7 | AskTheAnalystQuestion | 2023-04-03T18:29:41.326Z |  | 631ef479b675f72ec9309785 |
>| 642b23c3128075fc8c55ad23 | AskTheAnalystAnswer | 2023-04-03T19:06:43.557Z |  | System |
>| 642bfc42841e1c96304dd178 | AskTheAnalystQuestion | 2023-04-04T10:30:26.005Z |  | 631ef479b675f72ec9309785 |
>| 642c2d54128075fc8c564fdb | AskTheAnalystAnswer | 2023-04-04T13:59:48.026Z |  | System |
>| 645384909b3179c05ca2ad41 | AlertClosed | 2023-05-04T10:10:24.478Z |  | API |
>| 645384999b3179c05ca2adf6 | ChangedSeverity | 2023-05-04T10:10:33.304Z |  | API |
>| 645384bbd3e54df9a593372b | Assign | 2023-05-04T10:11:07.781Z |  | API |
>| 645384c4d3e54df9a59338b4 | Unassign | 2023-05-04T10:11:16.487Z |  | API |
>| 645384cd08e4bc1e2948ec09 | AlertReopened | 2023-05-04T10:11:25.161Z |  | API |
>| 645384d511ba24a35d0ab861 | AddTag | 2023-05-04T10:11:33.638Z |  | API |
>| 645384ee6a6f7be836b95c00 | AskTheAnalystQuestion | 2023-05-04T10:11:58.271Z |  | API |


### threat-command-alert-csv-get

***
Get alert's CSV file in case of credentials leakage or leaked credit cards alerts.

#### Base Command

`threat-command-alert-csv-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.CSV.alert_id | String | Alert ID. | 
| ThreatCommand.CSV.content | Unknown | Content of CSV file. | 
| InfoFile.EntryID | string | The EntryID of the CSV file. | 
| InfoFile.Extension | string | The extension of the CSV file. | 
| InfoFile.Name | string | The name of the CSV file. | 
| InfoFile.Info | string | The info of the CSV file. | 
| InfoFile.Size | number | The size of the CSV file. | 
| InfoFile.Type | string | The type of the CSV file. | 

#### Command example

```!threat-command-alert-csv-get alert_id=1234```

#### Context Example

```json
{
    "ThreatCommand": {
      "CSV": {
        "alert_id": "1234",
        "content": [
          {
            "email": "someone@my.com",
            "password": "password",
            "raw_line": "someone@my.com|password"
          }
        ]
      }
    },
    "InfoFile": {
        "EntryID": "35323@b5fa0da4-31d6-4517-8d5c-484d4bb598ac",
        "Extension": "csv",
        "Info": "text/csv; charset=utf-8",
        "Name": "1234.csv",
        "Size": 150,
        "Type": "ASCII text, with CRLF line terminators"
    }
}
```

#### Human Readable Output

>Alert "1234" CSV file.

### threat-command-alert-note-add

***
Add a note to the alert. You can add notes, as text or uploaded files, to an alert that can be seen by internal users. Each note is accompanied by the name of the note creator. Other users can reply to notes. Alert notes remain with the alert, even after it is closed or otherwise remediated.

#### Base Command

`threat-command-alert-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 
| note | Desired note. | Required | 
| entry_ids | Comma-separated list of file entry IDs. Allowed types: pdf,csv,doc,docx,png,txt,jpeg,jpg. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-alert-note-add alert_id=1234 note=test```

#### Human Readable Output

>Note successfully add to alert "1234".

### threat-command-alert-image-list

***
List alert images by ID.

#### Base Command

`threat-command-alert-image-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert's unique ID (dependencies - use threat-command-alert-list command to get all the alert IDs). | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-alert-image-list alert_id=1234```

#### Human Readable Output

>Alert "1234" does not contain images.

### threat-command-cve-list

***
Get CVE's list from account.

#### Base Command

`threat-command-cve-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| offset | This field is used for pagination. Each request is limited to 1000 results. To get the next page, send the returned "nextOffset" parameter back to the sever as "offset". | Optional | 
| publish_date_from | CVE's publish date minimum value. For example:  2022-12-25T08:38:06Z. | Optional | 
| publish_date_to | CVE's publish date maximum value. For example:  2022-12-25T08:38:06Z. | Optional | 
| update_date_from | CVE's update date minimum value. For example:  2022-12-25T08:38:06Z. | Optional | 
| update_date_to | CVE's update date maximum value. For example:  2022-12-25T08:38:06Z. | Optional | 
| severity_list | Comma-separated list of CVE severities. Possible values are: Critical, High, Medium, Low. | Optional | 
| cpe_list | Comma-separated list of CPEs. | Optional | 
| cve_ids | Comma-separated list of specific CVE IDs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.CVE.id | String | CVE ID. | 
| ThreatCommand.CVE.Cpe.value | String | CVE CPE value. | 
| ThreatCommand.CVE.Cpe.title | String | CVE CPE title. | 
| ThreatCommand.CVE.Cpe.vendor_product | String | CVE CPE vendor. | 
| ThreatCommand.CVE.published_date | Date | CVE CP publish date. | 
| ThreatCommand.CVE.update_date | Date | CVE update date. | 
| ThreatCommand.CVE.severity | String | CVE severity. | 
| ThreatCommand.CVE.intsights_score | Number | CVE insight score. | 
| ThreatCommand.CVE.cvss_score | Number | CVE CVSS score. | 
| ThreatCommand.CVE.mentions_amount | Number | CVE mentions amount. | 
| ThreatCommand.CVE.paste_site_mentions | Number | CVE paste site mentions. | 
| ThreatCommand.CVE.hacking_forum_mentions | Number | CVE hacking forum mentions. | 
| ThreatCommand.CVE.instant_message_mentions | Number | CVE instant message mentions. | 
| ThreatCommand.CVE.dark_web_mentions | Number | CVE dark web mentions. | 
| ThreatCommand.CVE.clear_web_cyber_blogs_mentions | Number | CVE clear web cyber blogs mentions. | 
| ThreatCommand.CVE.code_repositories_mentions | Number | CVE code repositories mentions. | 
| ThreatCommand.CVE.exploit_mentions | Number | CVE exploit mentions. | 
| ThreatCommand.CVE.social_media_mentions | Number | CVE social media mentions. | 
| ThreatCommand.CVE.first_mention_date | Date | CVE first mention date. | 
| ThreatCommand.CVE.last_mention_date | Date | CVE last mention date. | 
| ThreatCommand.CVE.exploit_availability | Boolean | CVE exploit availability. | 
| ThreatCommand.CVE.vulnerability_origin | String | CVE last vulnerability origin. | 
| ThreatCommand.CVE.related_threat_actors | String | Related threat actors. | 
| ThreatCommand.CVE.related_malware | String | Related malware. | 
| ThreatCommand.CVE.related_campaigns | String | Related campaigns. | 

#### Command example

```!threat-command-cve-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "CVE": {
            "clear_web_cyber_blogs_mentions": 1,
            "code_repositories_mentions": 0,
            "cpe": [
                {
                    "title": "Familyconnect Project 1.5.0 Android",
                    "value": "cpe:2.3:a:familyconnect_project:familyconnect:1.5.0:*:*:*:*:android:*:*",
                    "vendor_product": "Familyconnect Project Familyconnect"
                }
            ],
            "cvss_score": 5.4,
            "dark_web_mentions": 0,
            "exploit_availability": false,
            "exploit_mentions": 0,
            "first_mention_date": "2021-11-03T19:39:00.000Z",
            "hacking_forum_mentions": 0,
            "id": "CVE-2014-5600",
            "instant_message_mentions": 0,
            "intsights_score": 17,
            "last_mention_date": "2021-11-03T19:39:00.000Z",
            "paste_site_mentions": 1,
            "poc_mentions": 0,
            "published_date": "2014-09-09T01:55:00.000Z",
            "related_campaigns": [],
            "related_malware": [],
            "related_threat_actors": [],
            "severity": "Low",
            "social_media_mentions": 0,
            "update_date": "2023-04-30T22:00:37.673Z",
            "vulnerability_origin": [
                "Technologies in use asset"
            ]
        }
    }
}
```

#### Human Readable Output

>### CVE list.

>|Id|Published Date|Update Date|Severity|Intsights Score|Cvss Score|
>|---|---|---|---|---|---|
>| CVE-2014-5600 | 2014-09-09T01:55:00.000Z | 2023-04-30T22:00:37.673Z | Low | 17 | 5.4 |


### threat-command-cve-add

***
Add CVEs to account.

#### Base Command

`threat-command-cve-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_ids | Comma-separated list of CVEs unique IDs. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-cve-add cve_ids=CVE-1999-0002```

#### Human Readable Output

>The "CVE-1999-0002" CVEs successfully added.

### threat-command-cve-delete

***
Delete CVEs from account.

#### Base Command

`threat-command-cve-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_ids | Comma-separated list of CVEs unique IDs (dependencies - use threat-command-cve-listto get all the CVE IDs). | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-cve-delete cve_ids=CVE-1999-0002```

#### Human Readable Output

>The "CVE-1999-0002" CVEs successfully deleted.

### threat-command-asset-add

***
Add assets by type and value. Assets include any company resource that could lead to a potential security threat.

#### Base Command

`threat-command-asset-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | The type of asset to add value. For example: asset_type="Domains" asset_value="example.com". (You can get the asset types with threat-command-asset-type-list command). | Required | 
| asset_value | Asset value. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Asset.type | String | The type of the asset. | 
| ThreatCommand.Asset.value | String | The value of the asset type. | 

#### Command example

```!threat-command-asset-add asset_type=CompanyNames asset_value=test```

#### Context Example

```json
{
    "ThreatCommand": {
        "Asset": {
            "type": "CompanyNames",
            "value": "test"
        }
    }
}
```

#### Human Readable Output

>### Asset "test" successfully added to "CompanyNames" asset list.

>|Type|Value|
>|---|---|
>| CompanyNames | test |


### threat-command-asset-list

***
Get account assets grouped by asset type.

#### Base Command

`threat-command-asset-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_results | Show all results if True. Possible values are: true, false. | Optional | 
| asset_types | Comma-separated list of alert source types (dependencies - use threat-command-asset-type-list command to get all the asset types). For example:Domains,CompanyNames. . | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Asset.type | String | The type of the asset. | 
| ThreatCommand.Asset.value | String | The value of the asset type. | 

#### Command example

```!threat-command-asset-list limit=4```

#### Context Example

```json
{
    "ThreatCommand": {
        "Asset": [
            {
                "type": "Domains",
                "value": "com.com"
            },
            {
                "type": "Domains",
                "value": "google.com"
            },
            {
                "type": "Domains",
                "value": "moh.gov.il"
            },
            {
                "type": "Domains",
                "value": "qmasters.co"
            }
        ]
    }
}
```

#### Human Readable Output

>### Asset list.

>|Type|Value|
>|---|---|
>| Domains | com.com |
>| Domains | google.com |
>| Domains | moh.gov.il |
>| Domains | qmasters.co |


### threat-command-asset-type-list

***
Get all asset types. Mainly used to add or delete assets.

#### Base Command

`threat-command-asset-type-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_results | Show all results if True. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.AssetType | String | Asset type. | 

### threat-command-asset-delete

***
Delete asset by type and value.

#### Base Command

`threat-command-asset-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | The type of asset to add value. For example: asset_type="Domains" asset_value="example.com". (You can get the asset types with threat-command-asset-type-list command). | Required | 
| asset_value | Asset value. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!threat-command-asset-delete asset_type=CompanyNames asset_value=test```

#### Human Readable Output

>Asset "test" successfully deleted from "CompanyNames" asset list.

### threat-command-account-system-modules-list

***
List the system modules of your account.

#### Base Command

`threat-command-account-system-modules-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.SystemModule.module_name | String | Module name. | 
| ThreatCommand.SystemModule.status | String | Whether the module module is enabled. | 

#### Command example

```!threat-command-account-system-modules-list```

#### Context Example

```json
{
    "ThreatCommand": {
        "SystemModule": [
            {
                "module_name": "discovery",
                "status": true
            },
            {
                "module_name": "remediation",
                "status": true
            },
            {
                "module_name": "ioc",
                "status": true
            },
            {
                "module_name": "virtualappliance",
                "status": true
            },
            {
                "module_name": "investigationpage",
                "status": true
            },
            {
                "module_name": "threatlibrary",
                "status": false
            },
            {
                "module_name": "intellifind",
                "status": true
            },
            {
                "module_name": "cve",
                "status": true
            }
        ]
    }
}
```

#### Human Readable Output

>### System modules

>|Module Name|Status|
>|---|---|
>| discovery | true |
>| remediation | true |
>| ioc | true |
>| virtualappliance | true |
>| investigationpage | true |
>| threatlibrary | false |
>| intellifind | true |
>| cve | true |


### threat-command-mention-search

***
Search for strings in the scrapes database.

#### Base Command

`threat-command-mention-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Search using simple keywords (you can choose the search keywords by the outputs keywords), basic operators, search operators, and by document type. Basic operators: Use AND, OR, NOT, and (). For example: Searching for "bin_number: 1234 AND email_user_name: john_smith" returns all results that contain this BIN number and that username as the email user name, Searching for "comment_number: 17 AND author: gyber" returns all results with 17 comments and the author is Gyber. . | Required | 
| report_date | Supply time-frame. For example:  2022-12-25T08:38:06Z. | Optional | 
| page_number | Zero-based page number. 15 results per page. Default is 0. | Optional | 
| source_types | A comma-separated list of source types to filter. Possible values are: Social Media, Paste Site, Hacking Forum, Instant Message, Black Market, Cyber Security Blog, Web Page. | Optional | 
| only_dark_web | Show only mentions from the dark web or not. Possible values are: true, false. | Optional | 
| highlight_tags | Show highlight tags (&lt;em&gt;) in the content or not. Possible values are: true, false. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Mentions.author | String | Mention author. | 
| ThreatCommand.Mentions.comment_number | Number | Mentions comments number. | 
| ThreatCommand.Mentions.original_url | String | Mentions original URL. | 
| ThreatCommand.Mentions.source_date | Date | Mentions source date. | 
| ThreatCommand.Mentions.url | String | Mention URL. | 
| ThreatCommand.Mentions.insertion_date | Date | Mention insertion date. | 
| ThreatCommand.Mentions.type | String | Mention type. | 
| ThreatCommand.Mentions.Tags.is_product_for_sale | Boolean | Whether the product for sale. | 
| ThreatCommand.Mentions.Tags.credit_cards | Boolean | Whether the mention includes credit cards. | 
| ThreatCommand.Mentions.Tags.domains | Boolean | Whether the mention includes domains. | 
| ThreatCommand.Mentions.Tags.emails | Boolean | Whether the mention includes emails. | 
| ThreatCommand.Mentions.Tags.ips | Boolean | Whether the mention includes IPs. | 
| ThreatCommand.Mentions.Tags.ssns | Boolean | Whether the mention includes SSNs \(Switched Service Networks\). | 
| ThreatCommand.Mentions.Tags.urls | Boolean | Whether the mention includes URLs. | 
| ThreatCommand.Mentions.id | String | Mention ID. | 
| ThreatCommand.Mentions.short_content | String | Mention short content. | 
| ThreatCommand.Mentions.title | String | Mention title. | 
| ThreatCommand.Mentions.date | Date | Mention date. | 

#### Command example

```!threat-command-mention-search search=test.com```

#### Context Example

```json
{
    "ThreatCommand": {
        "Mentions": [
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "jamedoefo",
                "comment_number": 321,
                "date": "2023-05-04T10:20:02",
                "id": "1234",
                "insertion_date": "2023-05-04T09:55:46.794664",
                "original_url": "https://cybercarders.com/threads/onlyfans-lana-rhoades-3gb-update.222455/unread",
                "short_content": "i was here",
                "source_date": "2023-05-04T10:20:02",
                "title": "",
                "type": "comment",
                "url": "https://cybercarders.com/threads/onlyfans-lana-rhoades-3gb-update.222455/page-33"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": true,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": true
                },
                "author": "anon",
                "comment_number": 48,
                "date": "2023-05-04T10:17:00",
                "id": "f15c68c9c4d8a4ccc7efc21373f228a7f9d7826a",
                "insertion_date": "2023-05-04T10:09:30.652547",
                "original_url": "https://www.wilderssecurity.com/threads/brave-browser-discussion-update-thread.388288/unread",
                "short_content": "brave v1.51.110 (may 3, 2023) \nhttps://brave.com/latest/\n\nspoiler: release notes v1.51.110 (may 3, 2023)\nrelease notes v1.51.110 (may 3, 2023)\nweb3\n\nadded the ability to set brave wallet permission duration when connecting to dapps. (#28841)\n[security] prevent blind cross chain signing as reported o",
                "source_date": "2023-05-04T10:17:00",
                "title": "",
                "type": "comment",
                "url": "https://www.wilderssecurity.com/threads/brave-browser-discussion-update-thread.388288/page-36"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": false,
                    "is_product_for_sale": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "aleksandermachulin",
                "date": "2023-05-04T10:16:18",
                "id": "1234",
                "insertion_date": "2023-05-04T10:21:44.790150",
                "short_content": "test",
                "source_date": "2023-05-04T10:16:18",
                "title": "test",
                "type": "paste",
                "url": "https://test.com/z2sZCecJ"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "no_author",
                "date": "2023-05-04T10:16:08",
                "id": "01b2a09ab8abab28f48c44aef1d3cce141cc1131",
                "insertion_date": "2023-05-04T10:21:45.660025",
                "short_content": "#include <iostream>\r\n\r\nusing namespace std;\r\n\r\nstruct nod{\r\n    int info;\r\n    nod * urm;\r\n};\r\n\r\nint cmmdc(int a , int b)\r\n{\r\n    int r;\r\n    if(b == 0) return a;\r\n    return cmmdc(b , a % b);\r\n}\r\n\r\nint numarare(nod *p)\r\n{\r\n    int perechi = 0;\r\n    for(nod *q  = p ; q -> urm ; q = q -> urm)\r\n      ",
                "source_date": "2023-05-04T10:16:08",
                "title": "untitled",
                "type": "paste",
                "url": "https://test.com/tQ4pR7pi"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "no_author",
                "date": "2023-05-04T10:16:05",
                "id": "0b847ec3750cf77211057d978a50226a4a6aba8b",
                "insertion_date": "2023-05-04T10:21:46.495238",
                "short_content": "To navigate from a SwiftUI view wrapped in a `UIHostingController` to another `UIViewController`, you can use a custom `UIViewControllerRepresentable`. This approach allows you to create a bridge between SwiftUI and UIKit components. Here's a step-by-step process to achieve this:\r\n\r\n1. First, create",
                "source_date": "2023-05-04T10:16:05",
                "title": "untitled",
                "type": "paste",
                "url": "https://test.com/bQcx0nuj"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "juanliraz",
                "comment_number": 28,
                "date": "2023-05-04T10:16:01",
                "id": "c61a9a37a18baef534d0cece9cd1e28207e75b5a",
                "insertion_date": "2023-05-04T10:09:12.482796",
                "original_url": "https://cybercarders.com/threads/heart-sender-3-0-33-full-clean-all-other-sources-are-fake-contains-malware.233594/unread",
                "short_content": "checking",
                "source_date": "2023-05-04T10:16:01",
                "title": "",
                "type": "comment",
                "url": "https://cybercarders.com/threads/heart-sender-3-0-33-full-clean-all-other-sources-are-fake-contains-malware.233594/page-3"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": true,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": true
                },
                "author": "no_author",
                "date": "2023-05-04T10:15:56",
                "id": "6a6c18dba343a6446070f47a07c68135f0005ee1",
                "insertion_date": "2023-05-04T10:21:47.505657",
                "short_content": "/*************************************************** \r\n  This is an example for the Adafruit VS1053 Codec Breakout\r\n\r\n  Designed specifically to work with the Adafruit VS1053 Codec Breakout \r\n  ----> https://www.adafruit.com/products/1381\r\n\r\n  Adafruit invests time and resources providing this open ",
                "source_date": "2023-05-04T10:15:56",
                "title": "basicplayeronesp32",
                "type": "paste",
                "url": "https://test.com/qwcJVs8E"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": true,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": true
                },
                "author": "no_author",
                "date": "2023-05-04T10:15:49",
                "id": "d0a330840ac6908ce40fe7692b6151011a2334e7",
                "insertion_date": "2023-05-04T10:21:48.530660",
                "short_content": "const axios = require('axios');\r\n\r\nmodule.exports = {\r\n config: {\r\n name: \"binary\",\r\n aliases: [\"bin\"],\r\n version: \"1.0\",\r\n author: \"shinpei\",\r\n countDown: 0,\r\n role: 0,\r\n shortDescription: {\r\n en: \"Converts text to binary.\"\r\n },\r\n longDescription: {\r\n en: \"Converts text to binary using an API.\"\r\n }",
                "source_date": "2023-05-04T10:15:49",
                "title": "untitled",
                "type": "paste",
                "url": "https://test.com/6Gm6jjGG"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": true,
                    "emails": false,
                    "ips": true,
                    "ssns": false,
                    "urls": false
                },
                "author": "no_author",
                "date": "2023-05-04T10:15:42",
                "id": "f0e20e7cf875b7d0d6cc042014ec1a3dcff6e3e6",
                "insertion_date": "2023-05-04T10:21:49.433871",
                "short_content": "##\r\n# Host Database\r\n#\r\n# localhost is used to configure the loopback interface\r\n# when the system is booting.  Do not change this entry.\r\n##\r\n127.0.0.1    localhost\r\n255.255.255.255    broadcasthost\r\n::1             localhost\r\n# Added by Docker Desktop\r\n# To allow the same kube context to work on t",
                "source_date": "2023-05-04T10:15:42",
                "title": "untitled",
                "type": "paste",
                "url": "https://test.com/0Te6vfhK"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": true,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "no_author",
                "date": "2023-05-04T10:15:32",
                "id": "f908cce77843dd1f974281d5e5ea67d43114c016",
                "insertion_date": "2023-05-04T10:21:50.308696",
                "short_content": "[12:08:46 ERROR]: test v10.0.33\r\njava.lang.NoSuchMethodError: org.bukkit.World.getGameTime()J\r\n        at me.libraryaddict.disguise.utilities.DisguiseUtilities.setPlayerVelocity(DisguiseUtilities.java:556) ~[?:?]\r\n        at me.libraryaddict.disgu",
                "source_date": "2023-05-04T10:15:32",
                "title": "untitled",
                "type": "paste",
                "url": "https://test.com/GHNnERD4"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": true,
                    "ssns": false,
                    "urls": false
                },
                "author": "no_author",
                "date": "2023-05-04T10:15:18",
                "id": "60e0bdce36800a3539b03ef010345d943d5669c4",
                "insertion_date": "2023-05-04T10:21:51.176037",
                "short_content": "test",
                "source_date": "2023-05-04T10:15:18",
                "title": "untitled",
                "type": "paste",
                "url": "https://test.com/uL32rurg"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "no_author",
                "date": "2023-05-04T10:15:11",
                "id": "3fc8bf2c1c67a61c8f35b0dd188ec555a629c6fa",
                "insertion_date": "2023-05-04T10:21:52.029357",
                "short_content": "Yeet",
                "source_date": "2023-05-04T10:15:11",
                "title": "password",
                "type": "paste",
                "url": "https://test.com/ypvSpgA8"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": true,
                    "ssns": false,
                    "urls": false
                },
                "author": "no_author",
                "date": "2023-05-04T10:15:06",
                "id": "f51f0fb266db888d946f8206ac82057e38dde44a",
                "insertion_date": "2023-05-04T10:21:52.895423",
                "short_content": "absl-py==1.4.0\r\naiofiles==23.1.0\r\naiohttp==3.8.4\r\naiosignal==1.3.1\r\naltair==4.2.2\r\nanyio @ file:///home/conda/feedstock_root/build_artifacts/anyio_1666191106763/work/dist\r\nappdirs==1.4.4\r\nargon2-cffi @ file:///home/conda/feedstock_root/build_artifacts/argon2-cffi_1640817743617/work\r\nargon2-cffi-bind",
                "source_date": "2023-05-04T10:15:06",
                "title": "untitled",
                "type": "paste",
                "url": "https://test.com/dp4wF6MR"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": true,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "no_author",
                "date": "2023-05-04T10:15:02",
                "id": "f55651764e3c6c05376f7e38cf6555f64fc23158",
                "insertion_date": "2023-05-04T10:21:53.834800",
                "short_content": "[10:13:58 WARN]: [org.javacord.core.util.gateway.DiscordWebSocketAdapter] Websocket error!\r\ncom.neovisionaries.ws.client.WebSocketException: Flushing frames to the server failed: Connection or outbound has closed\r\n        at com.neovisionaries.ws.client.WritingThread.doFlush(WritingThread.java:434) ",
                "source_date": "2023-05-04T10:15:02",
                "title": "untitled",
                "type": "paste",
                "url": "https://test.com/pK0YYRsa"
            },
            {
                "Tags": {
                    "credit_cards": false,
                    "domains": false,
                    "emails": false,
                    "ips": false,
                    "ssns": false,
                    "urls": false
                },
                "author": "bellgamin",
                "comment_number": 33,
                "date": "2023-05-04T10:15:00",
                "id": "a6f37b218dad85e7472d11b3332546ad985cd46c",
                "insertion_date": "2023-05-04T09:23:49.643335",
                "original_url": "https://www.wilderssecurity.com/threads/laptop-battery-question.451238/unread",
                "short_content": "thanks for the comments bill. live long & prosper.\n\nas to \"...when you might want to turn off smart charging\" -- i quoted that part of the ms article in the comment where i linked to the ms article. ms is stating a few exceptions to ms's implicit rule, and that implicit rule is: \"turn on smart charg",
                "source_date": "2023-05-04T10:15:00",
                "title": "",
                "type": "comment",
                "url": "https://www.wilderssecurity.com/threads/laptop-battery-question.451238/page-2"
            }
        ]
    }
}
```

#### Human Readable Output

>### Mentions for "test.com" (page number 0).

>|Author|Original Url|Url|Type|Id|Short Content|Title|Date|
>|---|---|---|---|---|---|---|---|
>| jamedoefo | https:<span>//</span>cybercarders.com/threads/onlyfans-lana-rhoades-3gb-update.222455/unread | https:<span>//</span>cybercarders.com/threads/onlyfans-lana-rhoades-3gb-update.222455/page-33 | comment | 1234 | i was here |  | 2023-05-04T10:20:02 |
>| anon | https:<span>//</span>www.wilderssecurity.com/threads/brave-browser-discussion-update-thread.388288/unread | https:<span>//</span>www.wilderssecurity.com/threads/brave-browser-discussion-update-thread.388288/page-36 | comment | f15c68c9c4d8a4ccc7efc21373f228a7f9d7826a | brave v1.51.110 (may 3, 2023) <br/>https:<span>//</span>brave.com/latest/<br/><br/>spoiler: release notes v1.51.110 (may 3, 2023)<br/>release notes v1.51.110 (may 3, 2023)<br/>web3<br/><br/>added the ability to set brave wallet permission duration when connecting to dapps. (#28841)<br/>[security] prevent blind cross chain signing as reported o |  | 2023-05-04T10:17:00 |


### threat-command-mssp-customer-list

***
Get all Managed Security Service Provider's (MSSP) sub-accounts.

#### Base Command

`threat-command-mssp-customer-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_result | Show all results if True. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.MsspCustomer.id | String | Customer ID. | 
| ThreatCommand.MsspCustomer.company_name | String | Customer company name. | 
| ThreatCommand.MsspCustomer.status | String | Customer status. | 
| ThreatCommand.MsspCustomer.note | String | Customer note. | 

#### Command example

```!threat-command-mssp-customer-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "MsspCustomer": {
            "company_name": "Demo - Qmasters",
            "id": "59490ca49b655c027458d115",
            "note": "test",
            "status": "Enabled"
        }
    }
}
```

#### Human Readable Output

>### MSSP customer list

>|Id|Company Name|Status|Note|
>|---|---|---|---|
>| 59490ca49b655c027458d115 | Demo - Qmasters | Enabled | test |


### threat-command-mssp-user-list

***
Get the details of the MSSPs users (In case you are an MSSP account).

#### Base Command

`threat-command-mssp-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_result | Show all results if True. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.MsspUser.id | String | User ID. | 
| ThreatCommand.MsspUser.email | String | User email. | 
| ThreatCommand.MsspUser.role | String | User role. | 
| ThreatCommand.MsspUser.is_deleted | String | Whether the user was deleted. | 

#### Command example

```!threat-command-mssp-user-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "MsspUser": {
            "email": "test@test.com",
            "id": "64214bc94c75609d09ebb56a",
            "is_deleted": false,
            "role": "Admin"
        }
    }
}
```

#### Human Readable Output

>### MSSP user list

>|Id|Email|Role|Is Deleted|
>|---|---|---|---|
>| 64214bc94c75609d09ebb56a | test@test.com | Admin | false |


### threat-command-account-user-list

***
List the users in your account. Mainly used to assign alerts.

#### Base Command

`threat-command-account-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_type | Type of the user. Possible values are: Admin, Analyst. | Optional | 
| user_email | Email of the user. | Optional | 
| user_id | The ID of the user. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_result | Show all results if True. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.AccountUser.id | String | User ID. | 
| ThreatCommand.AccountUser.email | String | User email. | 
| ThreatCommand.AccountUser.first_name | String | User first name. | 
| ThreatCommand.AccountUser.last_name | String | User last name. | 
| ThreatCommand.AccountUser.role | String | User role. | 
| ThreatCommand.AccountUser.is_deleted | String | Whether the user was deleted. | 

#### Command example

```!threat-command-account-user-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "AccountUser": {
            "email": "test@test.com",
            "first_name": "test",
            "id": "59490cd818a3b902664b4ed7",
            "is_deleted": false,
            "last_name": "test",
            "permissions": {
                "Automation": {
                    "Extend": true,
                    "Integrations": true,
                    "Policy": true,
                    "Profiler": true
                },
                "Configurations": {
                    "PhishingWatchManager": true
                },
                "Data": {
                    "Actions": {
                        "AskTheAnalyst": true,
                        "Assignment": true,
                        "ChangeSeverity": true,
                        "ChangeStatus": true,
                        "Remediation": {
                            "Report": true,
                            "Takedown": true
                        },
                        "Share": true
                    },
                    "AlertTypes": {
                        "AttackIndication": true,
                        "BrandSecurity": true,
                        "DataLeakage": true,
                        "ExploitableData": true,
                        "Phishing": true,
                        "vip": true
                    },
                    "Assets": {
                        "Edit": true,
                        "View": true
                    },
                    "Reports": {
                        "View": true
                    },
                    "StrategicInsights": {
                        "Edit": true,
                        "View": true
                    }
                },
                "TIP": {
                    "EditSources": true,
                    "IntelliFind": true,
                    "InvestigationPage": true,
                    "ThreatLibrary": true,
                    "View": true
                },
                "ThreatThirdParty": {
                    "RiskAssessment": {
                        "Assess": true,
                        "View": true
                    },
                    "TailoredRisk": {
                        "Assess": true,
                        "View": true
                    }
                },
                "Vulnerabilities": {
                    "View": true
                }
            },
            "role": "Admin"
        }
    }
}
```

#### Human Readable Output

>### Account user list

>|Id|Email|First Name|Last Name|Role|Is Deleted|
>|---|---|---|---|---|---|
>| 59490cd818a3b902664b4ed7 | test@test.com | test | test | Admin | false |


### threat-command-alert-type-list

***
List alert types and sub-types. They are mainly used to add manual alerts.

#### Base Command

`threat-command-alert-type-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_result | Show all results if True. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.AlertType.type | String | Type. | 
| ThreatCommand.AlertType.sub_type | String | Sub-type of the type. | 

#### Command example

```!threat-command-alert-type-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "AlertType": {
            "sub_type": "VulnerabilityInTechnologyInUse",
            "type": "ExploitableData"
        }
    }
}
```

#### Human Readable Output

>### Alert types

>|Type|Sub Type|
>|---|---|
>| ExploitableData | VulnerabilityInTechnologyInUse |


### threat-command-alert-source-type-list

***
List alert source types. They are mainly used to add manual alerts.

#### Base Command

`threat-command-alert-source-type-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_result | Show all results if True. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.AlertSourceType | String | List of source types. | 

#### Command example

```!threat-command-alert-source-type-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "AlertSourceType": [
            "Application Store"
        ]
    }
}
```

#### Human Readable Output

>### Alert source types

>|Source Type|
>|---|
>| Application Store |


### threat-command-alert-scenario-list

***
List alert scenarios. They are mainly used to add manual alerts.

#### Base Command

`threat-command-alert-scenario-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 
| all_result | Show all results if True. Possible values are: true, false. | Optional | 
| type | Alert type (dependencies - use threat-command-alert-type-list command to get all the alert types). Possible values are: Attack Indication, Data Leakage, Phishing, Brand Security, Exploitable Data, vip. | Optional | 
| sub_type | Alert's sub-type (dependencies - use threat-command-alert-type-list command to get all the alert subtypes). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ThreatCommand.Scenario.type | String | Alert type. | 
| ThreatCommand.Scenario.subtype | String | Alert sub-type. | 
| ThreatCommand.Scenario.scenario | String | Name of the scenario. | 
| ThreatCommand.Scenario.description | String | Short description of the scenario. | 

#### Command example

```!threat-command-alert-scenario-list limit=1```

#### Context Example

```json
{
    "ThreatCommand": {
        "Scenario": {
            "description": "A company email address reported as spamming",
            "scenario": "ACompanyEmailAddressReportedAsMalicious",
            "subtype": "AssetReportedAsMalicious",
            "type": "AttackIndication"
        }
    }
}
```

#### Human Readable Output

>### Alert scenario list

>|Scenario|Description|Type|Subtype|
>|---|---|---|---|
>| ACompanyEmailAddressReportedAsMalicious | A company email address reported as spamming | AttackIndication | AssetReportedAsMalicious |


### file

***
Runs reputation on files.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unfinished_enriches | Unfinished IOCs number. Default is -1. | Required | 
| file | Hash of the file to query. Supports MD5, SHA1, and SHA256. | Required | 
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.sha512 | String | The SHA512 hash of the file. | 
| File.name | String | The full file name \(including file extension\). | 
| File.description | String | The description of the file. | 
| File.size | String | The size of the file. | 
| File.file_type | String | The type of the file. | 
| File.tags | String | The tags of the file. | 
| File.actor | String | Related threat actors to the file. | 
| File.campaign | String | Related threat campaigns to the file. | 
| File.associated_file_names | String | Assosiated file names to the file. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 

### ip

***
Checks the reputation of an IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unfinished_enriches | Unfinished IOCs number. Default is -1. | Required | 
| ip | IP address to check. | Required | 
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.ASN | String | IP ASN. | 
| IP.Address | String | IP address. | 
| IP.Region | String | IP region. | 
| IP.UpdatedDate | String | IP updated date. | 
| ThreatCommand.IP.asn | String | IP ASN. | 
| ThreatCommand.IP.ip | String | IP address. | 
| ThreatCommand.IP.region | String | IP region. | 
| ThreatCommand.IP.updated_date | String | IP updated date. | 

### url

***
Checks the reputation of a URL.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unfinished_enriches | Unfinished IOCs number. Default is -1. | Required | 
| url | A comma-separated list of URLs to check. This command will not work properly on URLs containing commas. | Required | 
| sampleSize | The number of samples from each type (resolutions, detections, etc.) to display for long format. Default is 10. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Data | String | The URL value. | 
| URL.DetectionEngines | String | URL detection engines. | 
| URL.PositiveDetections | Number | Number of positive engines. | 
| URL.Tags | Number | URL tags. | 
| ThreatCommand.URL.detection_engines | String | URL detection engines. | 
| ThreatCommand.URL.positive_detections | String | URL positive detection engines. | 
| ThreatCommand.URL.tags | String | URL tags. | 
| ThreatCommand.URL.url | Number | The URL value. | 

### domain

***
Checks the reputation of a domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unfinished_enriches | Unfinished IOCs number. Default is -1. | Required | 
| domain | Domain name to check. | Required | 
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.domain | String | Domain found. | 
| Domain.Name | String | The name of the domain that was checked. |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.DNSRecords | String | DNS records of the domain. | 
| ThreatCommand.Domain.domain | String | The domain value. | 
| ThreatCommand.Domain.sub_domains | Date | Sub domains of the domain. | 
| ThreatCommand.Domain.tags | String | Tags of the domain. | 
| ThreatCommand.Domain.updated_date | String | Domain updated date. | 