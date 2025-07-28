GreyNoise is a cybersecurity platform that collects and analyzes Internet-wide scan and attack traffic. With this integration, users can contextualize existing alerts, filter false-positives, identify compromised devices, and track emerging threats.
This integration was integrated and tested with version 3.0.0 of the GreyNoise SDK.
Supported Cortex XSOAR versions: 6.0.0 and later.

## Configure GreyNoise in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| apikey | API Key | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Runs reputation on IPs.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of IPs. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Reliability | String | The reliability of the data. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| GreyNoise.IP.address | string | The IP address of the scanning device IP. |
| GreyNoise.IP.actor | string | The overt actor the device has been associated with. |
| GreyNoise.IP.bot | Boolean | Whether the IP is associated with known bot activity or not. Common examples include credential stuffing, content scraping, or brute force attacks. |
| GreyNoise.IP.classification | string | Whether the device has been categorized as unknown, benign, or malicious. |
| GreyNoise.IP.cve | array | CVEs associated with IP. |
| GreyNoise.IP.first_seen | date | The date the device was first observed by GreyNoise. Format is ISO8601. |
| GreyNoise.IP.found | boolean | Whether the IP was found in GreyNoise records. |
| GreyNoise.IP.last_seen | date | The date the device was last observed by GreyNoise. Format is ISO8601. |
| GreyNoise.IP.last_seen_timestamp | string | The timestamp when the device was last observed by GreyNoise. |
| GreyNoise.IP.metadata.asn | string | The autonomous system identification number. |
| GreyNoise.IP.metadata.carrier | string | The carrier information for the IP address. |
| GreyNoise.IP.metadata.category | string | Whether the device belongs to a business, isp, hosting, education, or mobile network. |
| GreyNoise.IP.metadata.city | string | The city the device is geographically located in. |
| GreyNoise.IP.metadata.country | string | The full name of the country. |
| GreyNoise.IP.metadata.country_code | string | The two-character country code of the country. |
| GreyNoise.IP.metadata.datacenter | string | The datacenter information for the IP address. |
| GreyNoise.IP.metadata.destination_asns | array | The list of ASNs targeted by scanning. |
| GreyNoise.IP.metadata.destination_cities | array | The list of cities targeted by scanning. |
| GreyNoise.IP.metadata.destination_countries | array | The list of countries targeted by scanning. |
| GreyNoise.IP.metadata.destination_country_codes | array | The list of country codes targeted by scanning. |
| GreyNoise.IP.metadata.domain | string | The domain associated with the IP address. |
| GreyNoise.IP.metadata.latitude | number | The latitude coordinate of the IP address location. |
| GreyNoise.IP.metadata.longitude | number | The longitude coordinate of the IP address location. |
| GreyNoise.IP.metadata.mobile | boolean | Whether the device is on a mobile network. |
| GreyNoise.IP.metadata.organization | string | The organization that owns the network that the IP address belongs to. |
| GreyNoise.IP.metadata.os | string | The name of the operating system of the device. |
| GreyNoise.IP.metadata.rdns | string | Reverse DNS lookup of the IP address. |
| GreyNoise.IP.metadata.rdns_parent | string | The parent domain of the reverse DNS lookup. |
| GreyNoise.IP.metadata.rdns_validated | boolean | Whether the reverse DNS lookup has been validated. |
| GreyNoise.IP.metadata.region | string | The full name of the region the device is geographically located in. |
| GreyNoise.IP.metadata.sensor_count | number | The number of sensors that observed activity from this IP. |
| GreyNoise.IP.metadata.sensor_hits | number | The number of sensors events recorded from this IP. |
| GreyNoise.IP.metadata.single_destination | boolean | Whether the IP targets a single destination. |
| GreyNoise.IP.metadata.source_city | string | The city where the IP is geographically located. |
| GreyNoise.IP.metadata.source_country | string | The full name of the IP source country. |
| GreyNoise.IP.metadata.source_country_code | string | The country code of the IP source country. |
| GreyNoise.IP.metadata.tor | boolean | Whether the device is a known Tor exit node. |
| GreyNoise.IP.tor | boolean | Whether the device is a known Tor exit node. |
| GreyNoise.IP.raw_data.hassh.fingerprint | string | HASSH hash fingerprint string. |
| GreyNoise.IP.raw_data.hassh.port | number | TCP port connection where the HASSH hash was identified. |
| GreyNoise.IP.raw_data.http.md5 | array | MD5 hashes of HTTP requests made by the device. |
| GreyNoise.IP.raw_data.http.method | array | HTTP methods used by the device. |
| GreyNoise.IP.raw_data.http.path | array | HTTP paths the device has been observed accessing. |
| GreyNoise.IP.raw_data.http.request_header | array | HTTP request headers used by the device. |
| GreyNoise.IP.raw_data.http.useragent | array | HTTP user-agents the device has been observed using. |
| GreyNoise.IP.raw_data.ja3.fingerprint | string | The JA3 TLS/SSL fingerprint. |
| GreyNoise.IP.raw_data.ja3.port | number | The corresponding TCP port for the given JA3 fingerprint. |
| GreyNoise.IP.raw_data.tls.ja4 | array | JA4 TLS/SSL fingerprints. |
| GreyNoise.IP.raw_data.scan.port | number | The port number\(s\) the devices has been observed scanning. |
| GreyNoise.IP.raw_data.scan.protocol | string | The protocol of the port the device has been observed scanning. |
| GreyNoise.IP.raw_data.source.bytes | number | The number of bytes sent by the source. |
| GreyNoise.IP.raw_data.tls.cipher | array | TLS cipher suites used by the device. |
| GreyNoise.IP.raw_data.web.paths | array | Any HTTP paths the device has been observed crawling the Internet for. |
| GreyNoise.IP.raw_data.web.useragents | array | Any HTTP user-agents the device has been observed using while crawling the Internet. |
| GreyNoise.IP.seen | boolean | Whether the IP is in record with GreyNoise. |
| GreyNoise.IP.spoofable | boolean | Whether the ip is spoofable. |
| GreyNoise.IP.tags.category | string | The category of the given tag. |
| GreyNoise.IP.tags.created | date | The date the tag was added to the GreyNoise system. |
| GreyNoise.IP.tags.description | string | A description of what the tag identifies. |
| GreyNoise.IP.tags.id | string | The unique id of the tag. |
| GreyNoise.IP.tags.intention | string | The intention of the associated activity the tag identifies. |
| GreyNoise.IP.tags.name | string | The name of the tag. |
| GreyNoise.IP.tags.recommend_block | boolean | Indicates if IPs associated with this tag should be blocked. |
| GreyNoise.IP.tags.references | string | A list of references used to create the tag. |
| GreyNoise.IP.tags.slug | string | The unique slug of the tag. |
| GreyNoise.IP.tags.updated_at | date | The date the tag was last updated. |
| GreyNoise.IP.vpn | boolean | Whether the device is a VPN endpoint or not. |
| GreyNoise.IP.vpn_service | string | The name of the VPN service provider of the device. |
| GreyNoise.IP.category | string | The category of the business service. |
| GreyNoise.IP.description | string | Description of the business service. |
| GreyNoise.IP.explanation | string | Explanation of why the IP is considered a business service. |
| GreyNoise.IP.riot | boolean | Whether the IP is a common business service. |
| GreyNoise.IP.last_updated | date | When was the last time the business service information was updated. |
| GreyNoise.IP.name | string | The name of the business service. |
| GreyNoise.IP.reference | string | Reference link for the business service. |
| GreyNoise.IP.trust_level | string | If the IP is a business service, how trustworthy is the IP. |
| IP.Address | string | IP address. |
| IP.ASN | string | The autonomous system name for the IP address. |
| IP.Geo.Country | string | The country in which the IP address is located. |
| IP.Geo.Description | string | Additional information about the location such as city and region. |
| IP.Hostname | string | The hostname that is mapped to IP address. |
| IP.Malicious.Description | string | A description explaining why the IP address was reported as malicious. |
| IP.Malicious.Vendor | string | The vendor reporting the IP address as malicious. |

#### Command Example

``` !ip ip="64.39.108.148" ```

### IP: 64.39.108.148 found with Reputation: Good

### GreyNoise Internet Scanner Intelligence Lookup

|IP|Internet Scanner|Classification|Actor|Tags|Spoofable|VPN|BOT|Tor|First Seen|Last Seen Timestamp|
|---|---|---|---|---|---|---|---|---|---|---|
| [64.39.108.148](https://viz.greynoise.io/ip/64.39.108.148) | true | benign | Qualys | Qualys (benign - actor) | true | false | false | false | 2025-05-25 | 2025-05-25 09:28:51 |

### IP: 64.39.108.148 found with Reputation: Good

#### Belongs to Common Business Service: Qualys

### GreyNoise Business Service Intelligence Lookup

|IP|Business Service|Category|Name|Trust Level|Description|Last Updated|
|---|---|---|---|---|---|---|
| [64.39.108.148](https://viz.greynoise.io/ip/64.39.108.148) | true | vulnerability_management | Qualys | 1 - Reasonably Ignore | Qualys Inc (Qualys) is a provider of cloud-based platform information security and compliance cloud solutions. The company's cloud platform offers private cloud platforms, private cloud platform appliances, public cloud integrations, and cloud agents. | 2025-06-26T13:10:55Z |

### greynoise-ip-quick-check

***
Check whether a given IP address is "Internet background noise", or has been observed scanning or attacking devices across the Internet. Note: It checks against the last 60 days of Internet scanner data.

#### Base Command

`greynoise-ip-quick-check`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List IP addresses to retrieve quick check about. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreyNoise.IP.address | string | The IP address of the scanning device IP. |
| GreyNoise.IP.internet_scanner_intelligence.found | boolean | Whether the IP has been observed scanning the internet. |
| GreyNoise.IP.business_service_intelligence.found | boolean | Whether the IP is a common business service. |
| GreyNoise.IP.internet_scanner_intelligence.classification  | string | If the IP has been observed, what is the GreyNoise classification. |
| GreyNoise.IP.business_service_intelligence.trust_level| string | If the IP is a business service, how trustworthy is the IP. |

#### Command Example

``` !greynoise-ip-quick-check ip="45.83.65.120,45.83.66.18" ```

#### Human Readable Output

### GreyNoise Quick IP Lookup Details

|IP|Internet Scanner|Classification|Business Service|Trust Level|
|---|---|---|---|---|
| [64.39.108.148](https://viz.greynoise.io/ip/64.39.108.148) | true | benign | true | 1 |

### greynoise-query

***
Get the information of IP based on the providence filters.

#### Base Command

`greynoise-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_seen | The date the device was most recently observed by GreyNoise. Example: 1d, 2d, 12h, or 1m. | Optional |
| organization | The organization that owns the network the IP address belongs to. | Optional |
| classification | Classification of the device. Possible values: unknown, benign, malicious. Possible values are: unknown, benign, malicious. | Optional |
| spoofable | Whether the IP is spoofable or not. Possible values are: true, false. Default is false. | Optional |
| actor | The actor the device has been associated with. | Optional |
| cve | A CVE to get scanning data about, example CVE-2021-12345. | Optional |
| size | Maximum amount of results to grab. Default is 10. | Optional |
| advanced_query | GNQL query to filter records.<br/> Note: It merges other arguments and takes higher precedence over the same argument if supplied.<br/> Example:<br/> malicious,<br/> spoofable:false SSH Scanner,<br/> spoofable:false classification:benign tags:POP3 Scanner cve:CVE-2010-0103. | Optional |
| next_token | Scroll token to paginate through results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GreyNoise.IP.address | string | The IP address of the scanning device IP. |
| GreyNoise.IP.business_service_intelligence.category | string | The category of the business service. |
| GreyNoise.IP.business_service_intelligence.description | string | Description of the business service. |
| GreyNoise.IP.business_service_intelligence.explanation | string | Explanation of why the IP is considered a business service. |
| GreyNoise.IP.business_service_intelligence.found | boolean | Whether the IP is a common business service. |
| GreyNoise.IP.business_service_intelligence.last_updated | date | When was the last time the business service information was updated. |
| GreyNoise.IP.business_service_intelligence.name | string | The name of the business service. |
| GreyNoise.IP.business_service_intelligence.reference | string | Reference link for the business service. |
| GreyNoise.IP.business_service_intelligence.trust_level | string | If the IP is a business service, how trustworthy is the IP. |
| GreyNoise.IP.internet_scanner_intelligence.actor | string | The overt actor the device has been associated with. |
| GreyNoise.IP.internet_scanner_intelligence.bot | Boolean | Whether the IP is associated with known bot activity or not. Common examples include credential stuffing, content scraping, or brute force attacks. |
| GreyNoise.IP.internet_scanner_intelligence.classification | string | Whether the device has been categorized as unknown, benign, or malicious. |
| GreyNoise.IP.internet_scanner_intelligence.cve | array | CVEs associated with IP. |
| GreyNoise.IP.internet_scanner_intelligence.first_seen | date | The date the device was first observed by GreyNoise. Format is ISO8601. |
| GreyNoise.IP.internet_scanner_intelligence.found | boolean | Whether the IP was found in GreyNoise records. |
| GreyNoise.IP.internet_scanner_intelligence.last_seen | date | The date the device was last observed by GreyNoise. Format is ISO8601. |
| GreyNoise.IP.internet_scanner_intelligence.last_seen_timestamp | string | The timestamp when the device was last observed by GreyNoise. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.asn | string | The autonomous system identification number. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.carrier | string | The carrier information for the IP address. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.category | string | Whether the device belongs to a business, isp, hosting, education, or mobile network. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.city | string | The city the device is geographically located in. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.country | string | The full name of the country. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.country_code | string | The two-character country code of the country. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.datacenter | string | The datacenter information for the IP address. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.destination_asns | array | The list of ASNs targeted by scanning. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.destination_cities | array | The list of cities targeted by scanning. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.destination_countries | array | The list of countries targeted by scanning. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.destination_country_codes | array | The list of country codes targeted by scanning. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.domain | string | The domain associated with the IP address. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.latitude | number | The latitude coordinate of the IP address location. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.longitude | number | The longitude coordinate of the IP address location. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.mobile | boolean | Whether the device is on a mobile network. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.organization | string | The organization that owns the network that the IP address belongs to. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.os | string | The name of the operating system of the device. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.rdns | string | Reverse DNS lookup of the IP address. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.rdns_parent | string | The parent domain of the reverse DNS lookup. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.rdns_validated | boolean | Whether the reverse DNS lookup has been validated. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.region | string | The full name of the region the device is geographically located in. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.sensor_count | number | The number of sensors that observed activity from this IP. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.sensor_hits | number | The number of sensor events recorded from this IP. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.single_destination | boolean | Whether the IP targets a single destination. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.source_city | string | The city where the IP is geographically located. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.source_country | string | The full name of the IP source country. |
| GreyNoise.IP.internet_scanner_intelligence.metadata.source_country_code | string | The country code of the IP source country. |
| GreyNoise.IP.internet_scanner_intelligence.tor | boolean | Whether the device is a known Tor exit node. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.hassh.fingerprint | string | HASSH hash fingerprint string. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.hassh.port | number | TCP port connection where the HASSH hash was identified. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.http.md5 | array | MD5 hashes of HTTP requests made by the device. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.http.method | array | HTTP methods used by the device. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.http.path | array | HTTP paths the device has been observed accessing. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.http.request_header | array | HTTP request headers used by the device. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.http.useragent | array | HTTP user-agents the device has been observed using. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.ja3.fingerprint | string | The JA3 TLS/SSL fingerprint. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.ja3.port | number | The corresponding TCP port for the given JA3 fingerprint. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.scan.port | number | The port number\(s\) the device has been observed scanning. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.scan.protocol | string | The protocol of the port the device has been observed scanning. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.source.bytes | number | The number of bytes sent by the source. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.tls.cipher | array | TLS cipher suites used by the device. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.tls.ja4 | array | JA4 TLS/SSL fingerprints. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.web.paths | array | Any HTTP paths the device has been observed crawling the Internet for. |
| GreyNoise.IP.internet_scanner_intelligence.raw_data.web.useragents | array | Any HTTP user-agents the device has been observed using while crawling the Internet. |
| GreyNoise.IP.internet_scanner_intelligence.seen | boolean | Whether the IP is in record with GreyNoise. |
| GreyNoise.IP.internet_scanner_intelligence.spoofable | boolean | Whether the ip is spoofable. |
| GreyNoise.IP.internet_scanner_intelligence.tags.category | string | The category of the given tag. |
| GreyNoise.IP.internet_scanner_intelligence.tags.created | date | The date the tag was added to the GreyNoise system. |
| GreyNoise.IP.internet_scanner_intelligence.tags.description | string | A description of what the tag identifies. |
| GreyNoise.IP.internet_scanner_intelligence.tags.id | string | The unique id of the tag. |
| GreyNoise.IP.internet_scanner_intelligence.tags.intention | string | The intention of the associated activity the tag identifies. |
| GreyNoise.IP.internet_scanner_intelligence.tags.name | string | The name of the tag. |
| GreyNoise.IP.internet_scanner_intelligence.tags.recommend_block | boolean | Indicates if IPs associated with this tag should be blocked. |
| GreyNoise.IP.internet_scanner_intelligence.tags.references | string | A list of references used to create the tag. |
| GreyNoise.IP.internet_scanner_intelligence.tags.slug | string | The unique slug of the tag. |
| GreyNoise.IP.internet_scanner_intelligence.tags.updated_at | date | The date the tag was last updated. |
| GreyNoise.IP.internet_scanner_intelligence.vpn | boolean | Whether the device is a VPN endpoint or not. |
| GreyNoise.IP.internet_scanner_intelligence.vpn_service | string | The name of the VPN service provider of the device. |
| GreyNoise.Query.complete | boolean | Whether all results have been fetched or not. |
| GreyNoise.Query.count | number | Count of the total matching records. |
| GreyNoise.Query.message | string | Message from the API response. |
| GreyNoise.Query.query | string | Query which was used to filter the records. |
| GreyNoise.Query.scroll | string | Scroll token to paginate through results. |

#### Command Example

`!greynoise-query advanced_query=ip:64.39.108.148 spoofable=true`

#### Human Readable Output

### GreyNoise Internet Scanner Intelligence

#### Total findings: 1

#### Query: (ip:64.39.108.148 spoofable:true) last_seen:90d

### GreyNoise Internet Scanner Intelligence

|IP|Internet Scanner|Classification|Actor|Tags|Spoofable|VPN|BOT|Tor|First Seen|Last Seen Timestamp|
|---|---|---|---|---|---|---|---|---|---|---|
| [64.39.108.148](https://viz.greynoise.io/ip/64.39.108.148) | true | benign | Qualys | Qualys (benign - actor) | true | false | false | false | 2025-05-25 | 2025-05-25 09:28:51 |

*To view the detailed query result please click [here](https://viz.greynoise.io/query/?gnql=(ip:64.39.108.148+spoofable:true)+last_seen:90d).*

### greynoise-stats

***
Get aggregate statistics for the top organizations, actors, tags, ASNs, countries, classifications, and operating systems of all the results of a given GNQL query.

#### Base Command

`greynoise-stats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| classification | Classification of the device like unknown, benign, malicious. Possible values are: unknown, benign, malicious. | Optional |
| spoofable | Whether the IP is spoofable or not. Possible values are: true, false. | Optional |
| actor | The benign actor the device has been associated with. | Optional |
| size | Maximum amount of results to grab. Default is 10. | Optional |
| advanced_query | GNQL query to filter records. Note: It merges other arguments and takes higher precedence over the same argument if supplied. Example: malicious, spoofable:false SSH Scanner, spoofable:false classification:benign tags:POP3 Scanner cve:CVE-2010-0103. | Optional |
| last_seen | The date the device was most recently observed by GreyNoise. Example: 1d, 2d, 12h, or 1m. | Optional |
| organization | The organization that owns the network that the IP address belongs to. | Optional |

#### Context Output

| **Path**                                                 | **Type** | **Description** |
|----------------------------------------------------------| --- | --- |
| GreyNoise.Stats.adjusted_query                           | string | Provides the adjusted query, if the submitted one could not be executed as-is. |
| GreyNoise.Stats.query                                    | string | The query which was used to filter the records. |
| GreyNoise.Stats.count                                    | number | Count of total aggregated records. |
| GreyNoise.Stats.stats.classifications.classification     | string | Classification name. |
| GreyNoise.Stats.stats.classifications.count              | number | Classification count. |
| GreyNoise.Stats.stats.spoofable.spoofable                | boolean | Whether records are spoofable or not. |
| GreyNoise.Stats.stats.spoofable.count                    | number | Spoofable count. |
| GreyNoise.Stats.stats.organizations.organization         | string | Organization name. |
| GreyNoise.Stats.stats.organizations.count                | number | Organization count. |
| GreyNoise.Stats.stats.actors.actor                       | string | Actor name. |
| GreyNoise.Stats.stats.actors.count                       | number | Actor count. |
| GreyNoise.Stats.stats.countries.country                  | string | Country name. |
| GreyNoise.Stats.stats.countries.count                    | number | Country count. |
| GreyNoise.Stats.stats.source_countries.country           | string | Country name. |
| GreyNoise.Stats.stats.source_countries.count             | number | Country count. |
| GreyNoise.Stats.stats.destination_countries.country      | string | Country name. |
| GreyNoise.Stats.stats.destination_countries.count        | number | Country count. |
| GreyNoise.Stats.stats.tags.tag                           | string | Tag name. |
| GreyNoise.Stats.stats.tags.id                           | string | Tag ID. |
| GreyNoise.Stats.stats.tags.count                         | number | Tag count. |
| GreyNoise.Stats.stats.operating_systems.operating_system | string | Operating system name. |
| GreyNoise.Stats.stats.operating_systems.count            | number | Operating system count. |
| GreyNoise.Stats.stats.categories.category                | string | Category name. |
| GreyNoise.Stats.stats.categories.count                   | number | Category count. |
| GreyNoise.Stats.stats.asns.asn                           | string | Asn name. |
| GreyNoise.Stats.stats.asns.count                         | number | Asn count. |

#### Command Example

``` !greynoise-stats spoofable=true size=2 advanced_query="spoofable:false ```

#### Human Readable Output

### GreyNoise Internet Scanner Intelligence

#### Stats Query

#### Total IP Count: 489889

### Classifications

|Classification|Count|
|---|---|
| unknown | 248634 |
| malicious | 127595 |
| suspicious | 103741 |
| benign | 9919 |

### Spoofable

|Spoofable|Count|
|---|---|
| False | 489889 |

### Organizations

|Organization|Count|
|---|---|
| Mobile Communication Company of Iran PLC | 58005 |
| National Internet Backbone | 30561 |
| CHINA UNICOM China169 Backbone | 26144 |
| CHINANET-BACKBONE | 19036 |
| Iran Telecommunication Company PJS | 17789 |
| Iran Cell Service and Communication Company | 17343 |
| Cloudflare, Inc. | 13137 |
| DigitalOcean, LLC | 8490 |
| Telecom International Myanmar Co., Ltd | 5160 |

### Actors

|Actor|Count|
|---|---|
| Stretchoid | 2008 |
| Cortex Xpanse | 1983 |
| GoogleBot | 1142 |
| Alpha Strike Labs | 1018 |
| ShadowServer.org | 983 |
| Bytespider | 896 |
| BinaryEdge.io | 756 |
| Driftnet | 609 |
| ONYPHE | 576 |

### Source Countries

|Country|Count|
|---|---|
| Iran | 106580 |
| China | 58763 |
| India | 48230 |
| United States | 32369 |
| Russia | 14796 |
| Myanmar | 12047 |
| Germany | 11446 |
| Singapore | 7643 |
| Brazil | 6892 |

### Destination Countries

|Country|Count|
|---|---|
| United States | 407724 |
| India | 271246 |
| Singapore | 241697 |
| United Kingdom | 162690 |
| Germany | 133679 |
| Japan | 124237 |
| Spain | 121176 |
| Canada | 108688 |
| Mexico | 104668 |
| France | 103558 |

### Tags

|Tag|Count|
|---|---|
| Web Crawler | 177741 |
| TLS/SSL Crawler | 157135 |
| Telnet Login Attempt | 63236 |
| SSH Connection Attempt | 62197 |
| SMBv1 Crawler | 62062 |
| Telnet Bruteforcer | 58469 |
| Go HTTP Client | 53544 |
| Generic IoT Default Password Attempt | 40313 |
| Mirai | 33110 |
| Mirai TCP Scanner | 30260 |

### Categories

|Category|Count|
|---|---|
| isp | 307235 |
| hosting | 86812 |
| business | 6373 |
| education | 952 |
| government | 421 |

### ASNs

|ASN|Count|
|---|---|
| AS197207 | 58005 |
| AS9829 | 30561 |
| AS4837 | 26144 |
| AS4134 | 19036 |
| AS58224 | 17789 |
| AS44244 | 17343 |
| AS13335 | 13100 |
| AS14061 | 8490 |
| AS136255 | 5160 |

### greynoise-riot

***
Identifies IPs from known benign services and organizations that commonly cause false positives in network security and threat intelligence products. The collection of IPs in RIOT is continually curated and verified to provide accurate results. These IPs are extremely unlikely to pose a threat to your network.

#### Base Command

`greynoise-riot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to be checked if it is potentially harmful or not. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Reliability | String | The reliability of the data. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| GreyNoise.IP.category | String | The category of the IP if riot is "True". |
| GreyNoise.IP.classification | String | The classification of the IP if riot is "True". |
| GreyNoise.IP.description | String | The description of the IP if riot is "True". |
| GreyNoise.IP.explanation | String | The explanation of the IP if riot is "True". |
| GreyNoise.IP.found | String | Indicates if the IP is business service. |
| GreyNoise.IP.last_updated | Date | When was the last time the business service information was updated. |
| GreyNoise.IP.ip | String | The IP to query. |
| GreyNoise.IP.name | String | The name of the IP if the riot is "True". |
| GreyNoise.IP.reference | String | The reference of the IP if riot is "True". |
| GreyNoise.IP.riot | String | Indicates if the IP is business service. |
| GreyNoise.IP.trust_level | String | The trust level of the IP if riot is "True". |

#### Example Command

``` !greynoise-riot ip="64.39.108.148" ```

#### Human Readable Output

### IP: 64.39.108.148 found with Reputation: Good

#### Belongs to Common Business Service: Qualys

### GreyNoise Business Service Intelligence Lookup

|IP|Business Service|Category|Name|Trust Level|Description|Last Updated|
|---|---|---|---|---|---|---|
| [64.39.108.148](https://viz.greynoise.io/ip/64.39.108.148) | true | vulnerability_management | Qualys | 1 - Reasonably Ignore | Qualys Inc (Qualys) is a provider of cloud-based platform information security and compliance cloud solutions. The company's cloud platform offers private cloud platforms, private cloud platform appliances, public cloud integrations, and cloud agents. | 2025-06-26T13:10:55Z |

### greynoise-context

***
Identifies IPs that have been observed mass-scanning the internet.

#### Base Command

`greynoise-context`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to query in GreyNoise Context Command. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Reliability | String | The reliability of the data. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| GreyNoise.IP.address | string | The IP address of the scanning device IP. |
| GreyNoise.IP.actor | string | The overt actor the device has been associated with. |
| GreyNoise.IP.bot | Boolean | Whether the IP is associated with known bot activity or not. Common examples include credential stuffing, content scraping, or brute force attacks. |
| GreyNoise.IP.classification | string | Whether the device has been categorized as unknown, benign, or malicious. |
| GreyNoise.IP.cve | array | CVEs associated with IP. |
| GreyNoise.IP.first_seen | date | The date the device was first observed by GreyNoise. Format is ISO8601. |
| GreyNoise.IP.found | boolean | Whether the IP was found in GreyNoise records. |
| GreyNoise.IP.last_seen | date | The date the device was last observed by GreyNoise. Format is ISO8601. |
| GreyNoise.IP.last_seen_timestamp | string | The timestamp when the device was last observed by GreyNoise. |
| GreyNoise.IP.metadata.asn | string | The autonomous system identification number. |
| GreyNoise.IP.metadata.carrier | string | The carrier information for the IP address. |
| GreyNoise.IP.metadata.category | string | Whether the device belongs to a business, isp, hosting, education, or mobile network. |
| GreyNoise.IP.metadata.city | string | The city the device is geographically located in. |
| GreyNoise.IP.metadata.country | string | The full name of the country. |
| GreyNoise.IP.metadata.country_code | string | The two-character country code of the country. |
| GreyNoise.IP.metadata.datacenter | string | The datacenter information for the IP address. |
| GreyNoise.IP.metadata.destination_asns | array | The list of ASNs targeted by scanning. |
| GreyNoise.IP.metadata.destination_cities | array | The list of cities targeted by scanning. |
| GreyNoise.IP.metadata.destination_countries | array | The list of countries targeted by scanning. |
| GreyNoise.IP.metadata.destination_country_codes | array | The list of country codes targeted by scanning. |
| GreyNoise.IP.metadata.domain | string | The domain associated with the IP address. |
| GreyNoise.IP.metadata.latitude | number | The latitude coordinate of the IP address location. |
| GreyNoise.IP.metadata.longitude | number | The longitude coordinate of the IP address location. |
| GreyNoise.IP.metadata.mobile | boolean | Whether the device is on a mobile network. |
| GreyNoise.IP.metadata.organization | string | The organization that owns the network that the IP address belongs to. |
| GreyNoise.IP.metadata.os | string | The name of the operating system of the device. |
| GreyNoise.IP.metadata.rdns | string | Reverse DNS lookup of the IP address. |
| GreyNoise.IP.metadata.rdns_parent | string | The parent domain of the reverse DNS lookup. |
| GreyNoise.IP.metadata.rdns_validated | boolean | Whether the reverse DNS lookup has been validated. |
| GreyNoise.IP.metadata.region | string | The full name of the region the device is geographically located in. |
| GreyNoise.IP.metadata.sensor_count | number | The number of sensors that observed activity from this IP. |
| GreyNoise.IP.metadata.sensor_hits | number | The number of sensor events recorded from this IP. |
| GreyNoise.IP.metadata.single_destination | boolean | Whether the IP targets a single destination. |
| GreyNoise.IP.metadata.source_city | string | The city where the IP is geographically located. |
| GreyNoise.IP.metadata.source_country | string | The full name of the IP source country. |
| GreyNoise.IP.metadata.source_country_code | string | The country code of the IP source country. |
| GreyNoise.IP.metadata.tor | boolean | Whether the device is a known Tor exit node. |
| GreyNoise.IP.tor | boolean | Whether the device is a known Tor exit node. |
| GreyNoise.IP.raw_data.hassh.fingerprint | string | HASSH hash fingerprint string. |
| GreyNoise.IP.raw_data.hassh.port | number | TCP port connection where the HASSH hash was identified. |
| GreyNoise.IP.raw_data.http.md5 | array | MD5 hashes of HTTP requests made by the device. |
| GreyNoise.IP.raw_data.http.method | array | HTTP methods used by the device. |
| GreyNoise.IP.raw_data.http.path | array | HTTP paths the device has been observed accessing. |
| GreyNoise.IP.raw_data.http.request_header | array | HTTP request headers used by the device. |
| GreyNoise.IP.raw_data.http.useragent | array | HTTP user-agents the device has been observed using. |
| GreyNoise.IP.raw_data.ja3.fingerprint | string | The JA3 TLS/SSL fingerprint. |
| GreyNoise.IP.raw_data.ja3.port | number | The corresponding TCP port for the given JA3 fingerprint. |
| GreyNoise.IP.raw_data.tls.ja4 | array | JA4 TLS/SSL fingerprints. |
| GreyNoise.IP.raw_data.scan.port | number | The port number\(s\) the device has been observed scanning. |
| GreyNoise.IP.raw_data.scan.protocol | string | The protocol of the port the device has been observed scanning. |
| GreyNoise.IP.raw_data.source.bytes | number | The number of bytes sent by the source. |
| GreyNoise.IP.raw_data.tls.cipher | array | TLS cipher suites used by the device. |
| GreyNoise.IP.raw_data.tls.ja4 | array | JA4 TLS/SSL fingerprints. |
| GreyNoise.IP.raw_data.web.paths | array | Any HTTP paths the device has been observed crawling the Internet for. |
| GreyNoise.IP.raw_data.web.useragents | array | Any HTTP user-agents the device has been observed using while crawling the Internet. |
| GreyNoise.IP.seen | boolean | Whether the IP is in record with GreyNoise. |
| GreyNoise.IP.spoofable | boolean | Whether the ip is spoofable. |
| GreyNoise.IP.tags.category | string | The category of the given tag. |
| GreyNoise.IP.tags.created | date | The date the tag was added to the GreyNoise system. |
| GreyNoise.IP.tags.description | string | A description of what the tag identifies. |
| GreyNoise.IP.tags.id | string | The unique id of the tag. |
| GreyNoise.IP.tags.intention | string | The intention of the associated activity the tag identifies. |
| GreyNoise.IP.tags.name | string | The name of the tag. |
| GreyNoise.IP.tags.recommend_block | boolean | Indicates if IPs associated with this tag should be blocked. |
| GreyNoise.IP.tags.references | string | A list of references used to create the tag. |
| GreyNoise.IP.tags.slug | string | The unique slug of the tag. |
| GreyNoise.IP.tags.updated_at | date | The date the tag was last updated. |
| GreyNoise.IP.vpn | boolean | Whether the device is a VPN endpoint or not. |
| GreyNoise.IP.vpn_service | string | The name of the VPN service provider of the device. |

#### Example Command

``` !greynoise-context ip="114.119.130.178" ```

#### Human Readable Output

### IP: 64.39.108.148 found with Reputation: Good

### GreyNoise Internet Scanner Intelligence Lookup

|IP|Internet Scanner|Classification|Actor|Tags|Spoofable|VPN|BOT|Tor|First Seen|Last Seen Timestamp|
|---|---|---|---|---|---|---|---|---|---|---|
| [64.39.108.148](https://viz.greynoise.io/ip/64.39.108.148) | true | benign | Qualys | Qualys (benign - actor) | true | false | false | false | 2025-05-25 | 2025-05-25 09:28:51 |

### greynoise-similarity

***
Identify IPs with a similar internet scanning profile.

#### Base Command

`greynoise-similarity`

#### Input

| **Argument Name** | **Description**                        | **Required** |
| --- |----------------------------------------| --- |
| ip | The IP address to find similar IPs for | Required |
| minimum_score | The similar score to return results above.  Valid from 85 to 100. Default is 90. | Optional |
| maximum_results | The maximum number of similar results to return.  Default is 50. | Optional |

#### Context Output

| **Path**                           | **Type** | **Description** |
|------------------------------------| --- | --- |
| GreyNoise.Similar.ip               | string | The IP address of the scanning device IP. |
| GreyNoise.Similar.first_seen       | date | The date the device was first observed by GreyNoise. Format is ISO8601. |
| GreyNoise.Similar.last_seen        | date | The date the device was last observed by GreyNoise. Format is ISO8601. |
| GreyNoise.Similar.actor            | string | The overt actor the device has been associated with. |
| GreyNoise.Similar.classification        | string | Whether the device has been categorized as unknown, benign, or malicious. |
| GreyNoise.Similar.asn           | string | The autonomous system identification number. |
| GreyNoise.Similar.city          | string | The city the device is geographically located in. |
| GreyNoise.Similar.country       | string | The full name of the country. |
| GreyNoise.Similar.country_code  | string | The two-character country code of the country. |
| GreyNoise.Similar.organization  | string | The organization that owns the network that the IP address belongs to. |
| GreyNoise.Similar.similar_ips    | array | Details of similar IPs |

#### Command Example

```!greynoise-similarity   ip="1.2.3.4" minimum_score="90" maximum_results="50"```

#### Human Readable Output - Results

IP: 59.88.225.2 - Similar Internet Scanners found in GreyNoise
Total Similar IPs with Score above 90%: 100
Displaying 50 results below.  To see all results, visit the GreyNoise Visualizer.
GreyNoise Similar IPs

| IP      | Score | Classification | Actor   | Organization | Last Seen  | Similarity Features   |
|---------|-------|----------------|---------|--------------|------------|-----------------------|
| 1.2.3.4 | 100   | malicious      | unknown | GoogleBot    | 2023-04-05 | ports,spoofable_bool  |

``` !greynoise-similarity  ip="114.119.130.178" ```

#### Human Readable Output - No Results

GreyNoise Similarity Lookup returned No Results.

### greynoise-timeline

***
Get timeline activity for an IP address.

#### Base Command

`greynoise-timeline`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to get timeline activity for | Required |
| days | The number of days from today to get activity.  Valid from 1 to 90. Default is 30. | Optional |
| maximum_results | The maximum number of similar results to return.  Default is 50. | Optional |

#### Context Output

| **Path**                                | **Type** | **Description**                           |
|-----------------------------------------|----------|-------------------------------------------|
| GreyNoise.Timeline.ip                   | string   | The IP address of the scanning device IP. |
| GreyNoise.Timeline.metadata.start_time  | date     | The start time of the activity period     |
| GreyNoise.Timeline.metadata.end_time    | date     | The end time of the activity period       |
| GreyNoise.Timeline.metadata.limit       | string   | Limit of activity events returned         |
| GreyNoise.Timeline.metadata.next_cursor | string   | Cursor value to pull next page of results |
| GreyNoise.Timeline.activity             | array    | Daily activity summaries                  |

#### Command Example

```!greynoise-timeline ip="1.1.2.2" days="30" maximum_results="30"```

#### Human Readable Output - Results

IP: 45.164.214.212 - GreyNoise IP Timeline
Internet Scanner Timeline Details - Daily Activity Summary

| Date    | Classification | Tags        | rDNS        | Organization | ASN     | Ports                | Web Paths  | User Agents     |
|---------|----------------|-------------|-------------|--------------|---------|----------------------|------------|-----------------|
| 1.2.3.4 | malicious      | BruteForcer | me.acme.lcl | Acme, Inc    | AS12345 | ports,spoofable_bool | /root/home | MozillaFirefox  |

#### Human Readable Output - No Results

GreyNoise IP Timeline Returned No Results.

### cve

***
Queries GreyNoise for CVE Vuln Intelligence.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | A comma-separated list of CVE IDs. | Required |

#### Context Output

| **Path**                                                                          | **Type** | **Description**                                                                                                                        |
|-----------------------------------------------------------------------------------| --- |----------------------------------------------------------------------------------------------------------------------------------------|
| CVE.ID                                                                            | string | CVE ID.                                                                                                                                |
| GreyNoise.CVE.details.vulnerability_name                                          | String | The vulnerability name.                                                                                                                |
| GreyNoise.CVE.details.vulnerability_description                                   | String | A description of the vulnerability.                                                                                                    |
| GreyNoise.CVE.details.cve_cvss_score                                              | Number | The CVSS score.                                                                                                                        |
| GreyNoise.CVE.details.product                                                     | String | The vulnerable product.                                                                                                                |
| GreyNoise.CVE.details.vendor                                                      | String | The vendor that produces the vulnerable product.                                                                                       |
| GreyNoise.CVE.details.published_to_nist_nvd                                       | Boolean | Is this CVE published to NIST NVD?                                                                                                     |
| GreyNoise.CVE.timeline.cve_published_date                                         | Date | When was the CVE published.                                                                                                            |
| GreyNoise.CVE.timeline.cve_last_updated_date                                      | Date | When was the CVE information last updated.                                                                                             |
| GreyNoise.CVE.timeline.first_known_published_date                                 | Date | When first exploit associated with CVE was published.                                                                                  |
| GreyNoise.CVE.timeline.cisa_kev_date_added                                        | Date | When the CVE was added to KEV.                                                                                                         |
| GreyNoise.CVE.exploitation_details.attack_vector                                  | String | The attack vector category.                                                                                                            |
| GreyNoise.CVE.exploitation_details.exploit_found                                  | Boolean | Whether any known exploits are available.                                                                                              |
| GreyNoise.CVE.exploitation_details.exploitation_registered_in_kev                 | Boolean | Whether exploitation has been registered in KEV database.                                                                              |
| GreyNoise.CVE.exploitation_details.epss_score                                     | Number | EPSS score associated with this exploitation \(Exploit Prediction Scoring System\).                                                    |
| GreyNoise.CVE.exploitation_stats.number_of_available_exploits                     | Number | The total number of exploits available \(public \+ commercial\).                                                                       |
| GreyNoise.CVE.exploitation_stats.number_of_threat_actors_exploiting_vulnerability | Number | The total number of known threat actors.                                                                                               |
| GreyNoise.CVE.exploitation_stats.number_of_botnets_exploiting_vulnerability       | Number | The total number of botnets.                                                                                                           |
| GreyNoise.CVE.exploitation_activity.activity_seen                                 | Boolean | Whether GreyNoise has seen activity.                                                                                                   |
| GreyNoise.CVE.exploitation_activity.benign_ip_count_1d                            | Number | The total number of benign IP addresses GreyNoise has seen exercising (Scanning or Exploiting) this vulnerability in the last day.     |
| GreyNoise.CVE.exploitation_activity.benign_ip_count_10d                           | Number | The total number of benign IP addresses GreyNoise has seen exercising (Scanning or Exploiting) this vulnerability in the last 10 days. |
| GreyNoise.CVE.exploitation_activity.benign_ip_count_30d                           | Number | The total number of benign IP addresses GreyNoise has seen exercising (Scanning or Exploiting) this vulnerability in the last 30 days. |
| GreyNoise.CVE.exploitation_activity.threat_ip_count_1d                            | Number | The total number of threat IP addresses GreyNoise has seen exercising (Scanning or Exploiting) this vulnerability in the last day.     |
| GreyNoise.CVE.exploitation_activity.threat_ip_count_10d                           | Number | The total number of threat IP addresses GreyNoise has seen exercising (Scanning or Exploiting) this vulnerability in the last 10 days. |
| GreyNoise.CVE.exploitation_activity.threat_ip_count_30d                           | Number | The total number of threat IP addresses GreyNoise has seen exercising (Scanning or Exploiting) this vulnerability in the last 30 days. |
| DBotScore.Indicator                                                               | String | The indicator that was tested.                                                                                                         |
| DBotScore.Type                                                                    | String | The indicator type.                                                                                                                    |
| DBotScore.Vendor                                                                  | String | The vendor used to calculate the score.                                                                                                |
| DBotScore.Score                                                                   | Number | The actual score.                                                                                                                      |

#### Example Command

```!cve cve="CVE-2021-26086"```

#### Human Readable Output

### CVE: CVE-2021-26086 is found

### GreyNoise CVE Lookup

|CVE ID|CVSS|Vendor|Product|Published to NVD|
|---|---|---|---|---|
| CVE-2021-26086 | 5.3 | Atlassian | Jira Server and Data Center | true |

### Timeline Details

|Added to Kev|Last Updated|CVE Published|First Published|
|---|---|---|---|
| 2024-11-12 | 2025-02-09 | 2021-08-16 | 2023-11-18 |

### Exploitation Details

|Attack Vector|EPSS Base Score|Exploit Found|Exploit Registered in KEV|
|---|---|---|---|
| NETWORK | 0.94247 | true | true |

### Exploitation Stats

|# of Available Exploits|# of Botnets Exploiting|# of Threat Actors Exploiting|
|---|---|---|
| 4 | 1 | 1 |

### Exploitation Activity - GreyNoise Insights

|GreyNoise Observed Activity|# of Benign IPs - Last Day|# of Benign IPs - Last 10 Days|# of Benign IPs - Last 30 Days|# of Threat IPs - Last Day|# of Threat IPs - Last 10 Days|# of Threat IPs - Last 30 Days|
|---|---|---|---|---|---|---|
| true | 14 | 15 | 15 | 126 | 164 | 261 |
