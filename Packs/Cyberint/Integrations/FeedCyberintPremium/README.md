Use the Cyberint Premium Feed integration to get IOC indicators from the premium feed.
This integration was integrated and tested with version xx of Cyberint Premium Feed.

## Configure Check Point EM Premium Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Cyberint API URL | Cyberint API URL on which the services run \(i.e https://your-company.cyberint.io\) | True |
| Company Name | Company \(client\) name associated with Cyberint instance. | True |
| API access token |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Indicator Type | Which indicator types to fetch | True |
| Activity | Filter by activity classification | False |
| Confidence Min | Minimum confidence score \(0-100\) to fetch indicators from. | False |
| Confidence Max | Maximum confidence score \(0-100\) to fetch indicators from. | False |
| Severity Min | Minimum severity level \(1-5\) to fetch indicators from. | False |
| Severity Max | Maximum severity level \(1-5\) to fetch indicators from. | False |
| Malicious | Filter by malicious classification. | False |
| First Fetch Time | How far back to fetch indicators on the first run. Subsequent runs fetch only new indicators since the last successful fetch. Supports relative expressions like "3 days", "7 days", "24 hours". | False |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cyberint-premium-get-indicators

***
Gets indicators from the premium feed.

#### Base Command

`cyberint-premium-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 50. Default is 50. | Optional | 
| offset | Specifies the starting position from which data retrieval should begin. Default is 0. | Optional | 
| indicator_type | Filter by indicator type. Supports comma-separated values. Possible values are: ipv4, domain, url, sha256, sha1, md5. | Optional | 
| activity | Filter by activity classification. Supports comma-separated values. | Optional | 
| confidence_min | Minimum confidence score (0-100). | Optional | 
| severity_min | Minimum severity level (1-5). | Optional | 
| malicious | Filter by malicious classification. Possible values are: yes, no, inconclusive. | Optional | 
| added_to_feed_after | Filter indicators added to the feed after this date-time (ISO 8601). | Optional | 
| added_to_feed_before | Filter indicators added to the feed before this date-time (ISO 8601). | Optional | 
| sort_field | Field to sort by. Possible values are: confidence, severity, first_seen, last_seen, added_to_feed. Default is last_seen. | Optional | 
| sort_direction | Sort direction. Possible values are: asc, desc. Default is desc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberintPremium.Indicator.indicator_type | String | The indicator type. | 
| CyberintPremium.Indicator.indicator_value | String | The indicator value. | 
| CyberintPremium.Indicator.activity | String | Activity classification. | 
| CyberintPremium.Indicator.confidence | Number | Confidence score \(0-100\). | 
| CyberintPremium.Indicator.severity | Number | Severity level \(1-5\). | 
| CyberintPremium.Indicator.malicious | String | Malicious classification \(yes/no/inconclusive\). | 
| CyberintPremium.Indicator.kill_chain_stage | String | Kill chain stage. | 
| CyberintPremium.Indicator.first_seen | Date | First seen date-time. ISO8601 format: 2020-01-01T00:11:22Z. | 
| CyberintPremium.Indicator.last_seen | Date | Last seen date-time. ISO8601 format: 2020-01-01T00:11:22Z. | 
| CyberintPremium.Indicator.added_to_feed | Date | Date-time when added to the feed. ISO8601 format: 2020-01-01T00:11:22Z. | 
| CyberintPremium.Indicator.valid_until | Date | Valid until date-time. ISO8601 format: 2020-01-01T00:11:22Z. | 
| CyberintPremium.Indicator.is_blocking | Boolean | Whether the indicator is blocking. | 
| CyberintPremium.Indicator.is_unique | Boolean | Whether the indicator is unique. | 
| CyberintPremium.Indicator.malware_types | Unknown | List of malware types. | 
| CyberintPremium.Indicator.has_cve | Boolean | Whether the indicator has associated CVEs. | 
| CyberintPremium.Indicator.has_campaign | Boolean | Whether the indicator has an associated campaign. | 

### cyberint-premium-enrich

***
Enriches a single IOC indicator with reputation, threat intelligence, and type-specific enrichment data.

#### Base Command

`cyberint-premium-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The IOC type. Possible values are: ipv4, domain, url, sha256, sha1, md5. | Required | 
| value | The indicator value (e.g. IP address, domain name, URL, or file hash). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyberintPremium.Enrichment.indicator_type | String | The indicator type. | 
| CyberintPremium.Enrichment.indicator_value | String | The indicator value. | 
| CyberintPremium.Enrichment.activity | String | Activity classification. | 
| CyberintPremium.Enrichment.confidence | Number | Confidence score \(0-100\). | 
| CyberintPremium.Enrichment.severity | Number | Severity level \(0-5\). | 
| CyberintPremium.Enrichment.malicious | String | Malicious classification \(yes/no/inconclusive\). | 
| CyberintPremium.Enrichment.kill_chain_stage | String | Kill chain stage. | 
| CyberintPremium.Enrichment.first_seen | Date | First seen date-time. ISO8601 format: 2020-01-01T00:11:22Z. | 
| CyberintPremium.Enrichment.last_seen | Date | Last seen date-time. ISO8601 format: 2020-01-01T00:11:22Z. | 
| CyberintPremium.Enrichment.valid_until | Date | Valid until date-time. ISO8601 format: 2020-01-01T00:11:22Z. | 
| CyberintPremium.Enrichment.malware_types | Unknown | List of malware types. | 
| CyberintPremium.Enrichment.malware_family | String | Malware family name. | 
| CyberintPremium.Enrichment.origin_countries | Unknown | Origin countries. | 
| CyberintPremium.Enrichment.targeted_countries | Unknown | Targeted countries. | 
| CyberintPremium.Enrichment.targeted_sectors | Unknown | Targeted sectors. | 
| CyberintPremium.Enrichment.targeted_brands | Unknown | Targeted brands. | 
| CyberintPremium.Enrichment.threat_actors | Unknown | Associated threat actors. | 
| CyberintPremium.Enrichment.campaigns | Unknown | Associated campaigns. | 
| CyberintPremium.Enrichment.cves | Unknown | Associated CVEs. | 
| CyberintPremium.Enrichment.ttps | Unknown | Associated TTPs with MITRE IDs. | 
| CyberintPremium.Enrichment.tags | Unknown | Tags. | 
| CyberintPremium.Enrichment.enrichment | Unknown | Type-specific enrichment data \(geo, whois, file info, etc.\). | 
