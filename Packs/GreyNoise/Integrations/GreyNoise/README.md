GreyNoise is a cybersecurity platform that collects and analyzes Internet-wide scan and attack traffic. With this integration, users can contextualize existing alerts, filter false-positives, identify compromised devices, and track emerging threats.
This integration was integrated and tested with version 2.0.1 of the GreyNoise SDK.
Supported Cortex XSOAR versions: 5.5.0 and later.

## Configure GreyNoise on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GreyNoise.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | apikey | API Key | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Runs reputation on IPs.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 


#### Context Output

| **Path**                                        | **Type** | **Description**                                                                       |
|-------------------------------------------------|----------|---------------------------------------------------------------------------------------|
| DBotScore.Indicator                             | String   | The indicator that was tested.                                                        | 
| DBotScore.Score                                 | Number   | The actual score.                                                                     | 
| DBotScore.Type                                  | String   | The indicator type.                                                                   | 
| DBotScore.Vendor                                | String   | The vendor used to calculate the score.                                               | 
| IP.Address                                      | string   | IP address.                                                                           | 
| IP.ASN                                          | string   | The autonomous system name for the IP address.                                        | 
| IP.Hostname                                     | string   | The hostname that is mapped to IP address.                                            | 
| IP.Geo.Country                                  | string   | The country in which the IP address is located.                                       | 
| IP.Geo.Description                              | string   | Additional information about the location such as city and region.                    | 
| IP.Malicious.Vendor                             | string   | The vendor reporting the IP address as malicious.                                     | 
| IP.Malicious.Description                        | string   | A description explaining why the IP address was reported as malicious.                | 
| GreyNoise.IP.address                            | string   | The IP address of the scanning device IP.                                             | 
| GreyNoise.IP.first_seen                         | date     | The date the device was first observed by GreyNoise. Format is ISO8601.               | 
| GreyNoise.IP.last_seen                          | date     | The date the device was last observed by GreyNoise. Format is ISO8601.                | 
| GreyNoise.IP.seen                               | boolean  | IP is in record with GreyNoise.                                                       | 
| GreyNoise.IP.tags                               | array    | A list of the tags the device has been assigned over the past 90 days.                | 
| GreyNoise.IP.actor                              | string   | The overt actor the device has been associated with.                                  | 
| GreyNoise.IP.spoofable                          | boolean  | Boolean indicates if IP is spoofable.                                                 | 
| GreyNoise.IP.classification                     | string   | Whether the device has been categorized as unknown, benign, or malicious.             | 
| GreyNoise.IP.cve                                | array    | CVEs associated with IP.                                                              | 
| GreyNoise.IP.vpn                                | boolean  | Whether the device is VPN endpoint or not.                                            | 
| GreyNoise.IP.vpn_service                        | string   | The name of the VPN service provider of the device.                                   | 
| GreyNoise.IP.metadata.asn                       | string   | The autonomous system identification number.                                          | 
| GreyNoise.IP.metadata.city                      | string   | The city the device is geographically located in.                                     | 
| GreyNoise.IP.metadata.region                    | string   | The full name of the region the device is geographically located in.                  | 
| GreyNoise.IP.metadata.country                   | string   | The full name of the country.                                                         | 
| GreyNoise.IP.metadata.country_code              | string   | The two-character country code of the country.                                        | 
| GreyNoise.IP.metadata.source_country            | string   | The full name of the country.                                                         | 
| GreyNoise.IP.metadata.source_country_code       | string   | The two-character country code of the country.                                        | 
| GreyNoise.IP.metadata.destination_countries     | string   | The list of countries with observed scanning, by country name.                        | 
| GreyNoise.IP.metadata.destination_country_codes | string   | The list of countries with observed scanning, by two-character country code.          | 
| GreyNoise.IP.metadata.organization              | string   | The organization that owns the network that the IP address belongs to.                | 
| GreyNoise.IP.metadata.category                  | string   | Whether the device belongs to a business, isp, hosting, education, or mobile network. | 
| GreyNoise.IP.metadata.tor                       | boolean  | Whether or not the device is a known Tor exit node.                                   | 
| GreyNoise.IP.metadata.rdns                      | string   | Reverse DNS lookup of the IP address.                                                 | 
| GreyNoise.IP.metadata.os                        | string   | The name of the operating system of the device.                                       | 
| GreyNoise.IP.metadata.sensor_hits               | string   | The number of GreyNoise sensors that observed scanning.                               | 
| GreyNoise.IP.metadata.sensor_count              | string   | The number of scanning events observed.                                               | 
| GreyNoise.IP.raw_data.scan.port                 | number   | The port number\(s\) the devices has been observed scanning.                          | 
| GreyNoise.IP.raw_data.scan.protocol             | string   | The protocol of the port the device has been observed scanning.                       | 
| GreyNoise.IP.raw_data.web.paths                 | array    | Any HTTP paths the device has been observed crawling the Internet for.                | 
| GreyNoise.IP.raw_data.web.useragents            | array    | Any HTTP user-agents the device has been observed using while crawling the Internet.  | 
| GreyNoise.IP.raw_data.ja3.fingerprint           | string   | The JA3 TLS/SSL fingerprint.                                                          | 
| GreyNoise.IP.raw_data.ja3.port                  | number   | The corresponding TCP port for the given JA3 fingerprint.                             | 
| GreyNoise.IP.raw_data.hassh.fingerprint         | string   | HASSH hash fingerprint string.                                                        | 
| GreyNoise.IP.raw_data.hassh.port                | number   | TCP port connection where the HASSH hash was identified.                              | 


#### Command Example

``` !ip "66.249.68.82" ```

#### Human Readable Output

### IP: 66.249.68.82 found with Noise Reputation: Good

### GreyNoise Context IP Lookup

|IP|Classification|Actor|Tags|Spoofable|VPN|BOT|Tor|First Seen|Last Seen|
|---|---|---|---|---|---|---|---|---|---|
| 66.249.68.82| benign | GoogleBot | TLS/SSL Crawler, Web Crawler | false | false | false | false | 2021-05-30 | 2021-09-16 |

### IP: 66.249.68.82 found with RIOT Reputation: Good

### Belongs to Common Business Service: Google

### GreyNoise RIOT IP Lookup

|IP|Category|Name|Trust Level|Description|Last Updated|
|---|---|---|---|---|---|
| 66.249.68.82 | software | Google | 	1 - Reasonably Ignore | 	Google LLC is an American multinational technology company that specializes in Internet-related services and products, which include online advertising technologies, a search engine, cloud computing, software, and hardware. | 2021-09-16T17:53:00Z|


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
| GreyNoise.IP.noise | boolean | Whether the IP is internet background noise or attacking. | 
| GreyNoise.IP.riot | string | Whether the IP is a common business service. | 
| GreyNoise.IP.code | string | Code which correlates to why GreyNoise labeled the IP as noise. |
| GreyNoise.IP.code_value | string | Message which correlates to why GreyNoise labeled the IP as noise. | 


#### Command Example

``` !greynoise-ip-quick-check ip="45.83.65.120,45.83.66.18" ```

#### Human Readable Output

### IP Quick Check Details

|IP|Noise|Code|Code Description|
|---|---|---|---|
| 45.83.66.18 | true | 0x01 | IP has been observed by the GreyNoise sensor network |
| 45.83.65.120| true | 0x01 | IP has been observed by the GreyNoise sensor network |

### greynoise-query

***
Get the information of IP based on the providence filters.


#### Base Command

`greynoise-query`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                           | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| classification | Classification of the device like unknown, benign, malicious. Possible values are: unknown, benign, malicious.                                                                                                                                            | Optional | 
| spoofable | Whether the IP is spoofable or not. Possible values are: true, false.                                                                                                                                                                                     | Optional | 
| actor | The benign actor the device has been associated with.                                                                                                                                                                                                     | Optional | 
| size | Maximum amount of results to grab. Default is 10.                                                                                                                                                                                                         | Optional | 
| advanced_query | GNQL query to filter records. Note: It merges other arguments and takes higher precedence over the same argument if supplied. Example: malicious, spoofable:false SSH Scanner, spoofable:false classification:benign tags:POP3 Scanner cve:CVE-2010-0103. | Optional | 
| next_token | Scroll token to paginate through results.                                                                                                                                                                                                                 | Optional | 
| last_seen | The date the device was most recently observed by GreyNoise. Example: 1d, 2d, 12h, or 1m.                                                                                                                                                                 | Optional | 
| organization | The organization that owns the network that the IP address belongs to.                                                                                                                                                                                    | Optional | 

#### Advance Query

GNQL (GreyNoise Query Language) is a domain-specific query language that uses Lucene deep under the hood.  
For more information on the syntax to write GNQL of argument `advanced_query`, visit <https://docs.greynoise.io/reference/>.

#### Context Output

| **Path**                                        | **Type** | **Description**                                                                                                                                     |
|-------------------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| GreyNoise.IP.address                            | string   | The IP address of the scanning device IP.                                                                                                           | 
| GreyNoise.IP.first_seen                         | date     | The date the device was first observed by GreyNoise. Format is ISO8601.                                                                             | 
| GreyNoise.IP.last_seen                          | date     | The date the device was last observed by GreyNoise. Format is ISO8601.                                                                              | 
| GreyNoise.IP.seen                               | boolean  | IP is in record with GreyNoise.                                                                                                                     | 
| GreyNoise.IP.tags                               | array    | A list of the tags the device has been assigned over the past 90 days.                                                                              | 
| GreyNoise.IP.actor                              | string   | The overt actor the device has been associated with.                                                                                                | 
| GreyNoise.IP.spoofable                          | boolean  | Boolean indicates if IP is spoofable.                                                                                                               | 
| GreyNoise.IP.classification                     | string   | Whether the device has been categorized as unknown, benign, or malicious.                                                                           | 
| GreyNoise.IP.cve                                | array    | CVEs associated with IP.                                                                                                                            | 
| GreyNoise.IP.vpn                                | boolean  | Whether the device is VPN endpoint or not.                                                                                                          | 
| GreyNoise.IP.vpn_service                        | string   | The name of the VPN service provider of the device.                                                                                                 | 
| GreyNoise.IP.metadata.asn                       | string   | The autonomous system identification number.                                                                                                        | 
| GreyNoise.IP.metadata.city                      | string   | The city the device is geographically located in.                                                                                                   | 
| GreyNoise.IP.metadata.region                    | string   | The full name of the region the device is geographically located in.                                                                                | 
| GreyNoise.IP.metadata.country                   | string   | The full name of the country.                                                                                                                       | 
| GreyNoise.IP.metadata.country_code              | string   | The two-character country code of the country.                                                                                                      | 
| GreyNoise.IP.metadata.source_country            | string   | The full name of the country.                                                                                                                       | 
| GreyNoise.IP.metadata.source_country_code       | string   | The two-character country code of the country.                                                                                                      | 
| GreyNoise.IP.metadata.destination_countries     | string   | The list of countries with observed scanning, by country name.                                                                                      | 
| GreyNoise.IP.metadata.destination_country_codes | string   | The list of countries with observed scanning, by two-character country code.                                                                        | 
| GreyNoise.IP.metadata.organization              | string   | The organization that owns the network that the IP address belongs to.                                                                              | 
| GreyNoise.IP.metadata.category                  | string   | Whether the device belongs to a business, isp, hosting, education, or mobile network.                                                               | 
| GreyNoise.IP.metadata.tor                       | boolean  | Whether or not the device is a known Tor exit node.                                                                                                 | 
| GreyNoise.IP.metadata.rdns                      | string   | Reverse DNS lookup of the IP address.                                                                                                               | 
| GreyNoise.IP.metadata.os                        | string   | The name of the operating system of the device.                                                                                                     | 
| GreyNoise.IP.metadata.sensor_hits               | string   | The number of GreyNoise sensors that observed scanning.                                                                                             | 
| GreyNoise.IP.metadata.sensor_count              | string   | The number of scanning events observed.                                                                                                             | 
| GreyNoise.IP.raw_data.scan.port                 | number   | The port number\(s\) the devices has been observed scanning.                                                                                        | 
| GreyNoise.IP.raw_data.scan.protocol             | string   | The protocol of the port the device has been observed scanning.                                                                                     | 
| GreyNoise.IP.raw_data.web.paths                 | array    | Any HTTP paths the device has been observed crawling the Internet for.                                                                              | 
| GreyNoise.IP.raw_data.web.useragents            | array    | Any HTTP user-agents the device has been observed using while crawling the Internet.                                                                | 
| GreyNoise.IP.raw_data.ja3.fingerprint           | string   | The JA3 TLS/SSL fingerprint.                                                                                                                        | 
| GreyNoise.IP.raw_data.ja3.port                  | number   | The corresponding TCP port for the given JA3 fingerprint.                                                                                           | 
| GreyNoise.IP.raw_data.hassh.fingerprint         | string   | HASSH hash fingerprint string.                                                                                                                      | 
| GreyNoise.IP.raw_data.hassh.port                | number   | TCP port connection where the HASSH hash was identified.                                                                                            | 
| GreyNoise.Query.complete                        | boolean  | Whether all results have been fetched or not.                                                                                                       | 
| GreyNoise.Query.count                           | number   | Count of the total matching records.                                                                                                                | 
| GreyNoise.Query.message                         | string   | Message from the API response.                                                                                                                      | 
| GreyNoise.Query.query                           | string   | Query which was used to filter the records.                                                                                                         | 
| GreyNoise.Query.scroll                          | string   | Scroll token to paginate through results.                                                                                                           | 
| GreyNoise.IP.bot                                | boolean  | Whether the IP is associated with known bot activity or not. Common examples include credential stuffing, content scraping, or brute force attacks. |

#### Command Example

``` !greynoise-query spoofable=true size=1 advanced_query="spoofable:false" ```

#### Human Readable Output

### Total findings: 2846548

### IP Context

| IP            |Classification|Actor| CVE                                         |Spoofable|VPN|First Seen|Last Seen|
|---------------|---|---|---------------------------------------------|---|---|---|---|
| 71.6.135.131  | benign | Shodan.io | CVE-1999-0526 ,CVE-2013-6117, CVE-2019-0708 | false | false | 2017-09-20 | 2021-02-03 |

### Next Page Token: 

DnF1ZXJ5VGhlbkZldGNoBQAAAAAcV1_HFkFKSExEdUc4VEtta2

*To view the detailed query result please click here.*

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

### Stats

### Query: spoofable:false Count: 2846548

### Classifications

|Classification|Count|
|---|---|
| unknown | 1838719 |
| malicious | 998758 |

### Spoofable

|Spoofable|Count|
|---|---|
| False | 2846548 |

### Organizations

|Organization|Count|
|---|---|
| CHINA UNICOM China169 Backbone | 252542 |
| CHINANET-BACKBONE | 244599 |

### Actors

|Actor|Count|
|---|---|
| GoogleBot | 2202 |

### Source Countries

|Country|Count|
|---|---|
| China | 562209 |
| Iran | 376353 |

### Destination Countries

|Country|Count|
|---|---|
| China | 562209 |
| Iran | 376353 |

### Tags

|Tag|Count|
|---|---|
| SMB Scanner | 592090 |
| Web Scanner | 578058 |

### Operating Systems

|Operating System|Count|
|---|---|
| Linux 2.2-3.x | 1202422 |
| Windows 7/8 | 727215 |

### Categories

|Category|Count|
|---|---|
| isp | 2263259 |
| mobile | 348306 |

### ASNs

|ASN|Count|
|---|---|
| AS4837 | 252542 |
| AS4134 | 244603 |



### greynoise-riot

***
Identify IPs from known benign services and organizations that commonly cause false positives in network security and threat intelligence products. The collection of IPs in RIOT is continually curated and verified to provide accurate results. These IPs are extremely unlikely to pose a threat to your network.

#### Base Command

`greynoise-riot`

#### Input

| **Argument Name** | **Description**                                                   | **Required** |
|-------------------|-------------------------------------------------------------------|--------------|
| ip                | The IP address to be checked if it is potentially harmful or not. | Required     | 


#### Context Output

| **Path**                    | **Type** | **Description**                                        |
|-----------------------------|----------|--------------------------------------------------------|
| GreyNoise.Riot.ip           | string   | The IP given to check riot information about.          | 
| GreyNoise.Riot.riot         | string   | The riot of the IP. "True" or "False"                  | 
| GreyNoise.Riot.category     | string   | The category of the IP if riot is "True".              | 
| GreyNoise.Riot.name         | string   | The name of the IP if the riot is "True".              | 
| GreyNoise.Riot.description  | string   | The description of the IP if riot is "True".           | 
| GreyNoise.Riot.explanation  | date     | The explanation of the IP if riot is "True".           | 
| GreyNoise.Riot.last_updated | string   | The last updated time of the IP if the riot is "True". | 
| GreyNoise.Riot.reference    | string   | The reference of the IP if riot is "True".             | 
| GreyNoise.Riot.trust_level  | string   | The trust_level of the IP if riot is "True".           | 

#### Command Example

``` !greynoise-riot ip="8.8.8.8" ```

#### Human Readable Output

### GreyNoise: IP Belongs to Common Business Service

|IP|Category|Name|Trust Level|Description|Last Updated|
|---|---|---|---|---|---|
| 8.8.8.8  | public_dns | Google Public DNS | 	1 - Reasonably Ignore | Google's global domain name system (DNS) resolution service.|2021-04-12T05:55:35Z|

``` !greynoise-riot ip="114.119.130.178" ```

#### Human Readable Output

### GreyNoise: IP Not Found in RIOT

|IP|RIOT|
|---|---|
| 114.119.130.178| false |


### greynoise-context

***
Identify IPs that are mass-scanning the internet and identify what they are scanning for. 

#### Base Command

`greynoise-context`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to be checked if it is mass-scanning the internet | Required | 


#### Context Output

| **Path**                                        | **Type** | **Description**                                                                       |
|-------------------------------------------------|----------|---------------------------------------------------------------------------------------|
| GreyNoise.IP.address                            | string   | The IP address of the scanning device IP.                                             | 
| GreyNoise.IP.first_seen                         | date     | The date the device was first observed by GreyNoise. Format is ISO8601.               | 
| GreyNoise.IP.last_seen                          | date     | The date the device was last observed by GreyNoise. Format is ISO8601.                | 
| GreyNoise.IP.seen                               | boolean  | IP is in record with GreyNoise.                                                       | 
| GreyNoise.IP.tags                               | array    | A list of the tags the device has been assigned over the past 90 days.                | 
| GreyNoise.IP.actor                              | string   | The overt actor the device has been associated with.                                  | 
| GreyNoise.IP.spoofable                          | boolean  | Boolean indicates if IP is spoofable.                                                 | 
| GreyNoise.IP.classification                     | string   | Whether the device has been categorized as unknown, benign, or malicious.             | 
| GreyNoise.IP.cve                                | array    | CVEs associated with IP.                                                              | 
| GreyNoise.IP.vpn                                | boolean  | Whether the device is VPN endpoint or not.                                            | 
| GreyNoise.IP.vpn_service                        | string   | The name of the VPN service provider of the device.                                   | 
| GreyNoise.IP.bot                                | boolean  | Whether belongs to common bot activity.                                               | 
| GreyNoise.IP.metadata.asn                       | string   | The autonomous system identification number.                                          | 
| GreyNoise.IP.metadata.city                      | string   | The city the device is geographically located in.                                     | 
| GreyNoise.IP.metadata.region                    | string   | The full name of the region the device is geographically located in.                  | 
| GreyNoise.IP.metadata.country                   | string   | The full name of the country.                                                         | 
| GreyNoise.IP.metadata.country_code              | string   | The two-character country code of the country.                                        | 
| GreyNoise.IP.metadata.source_country            | string   | The full name of the country.                                                         | 
| GreyNoise.IP.metadata.source_country_code       | string   | The two-character country code of the country.                                        | 
| GreyNoise.IP.metadata.destination_countries     | string   | The list of countries with observed scanning, by country name.                        | 
| GreyNoise.IP.metadata.destination_country_codes | string   | The list of countries with observed scanning, by two-character country code.          | 
| GreyNoise.IP.metadata.organization              | string   | The organization that owns the network that the IP address belongs to.                | 
| GreyNoise.IP.metadata.category                  | string   | Whether the device belongs to a business, isp, hosting, education, or mobile network. | 
| GreyNoise.IP.metadata.tor                       | boolean  | Whether or not the device is a known Tor exit node.                                   | 
| GreyNoise.IP.metadata.rdns                      | string   | Reverse DNS lookup of the IP address.                                                 | 
| GreyNoise.IP.metadata.os                        | string   | The name of the operating system of the device.                                       | 
| GreyNoise.IP.metadata.sensor_hits               | string   | The number of GreyNoise sensors that observed scanning.                               | 
| GreyNoise.IP.metadata.sensor_count              | string   | The number of scanning events observed.                                               | 
| GreyNoise.IP.raw_data.scan.port                 | number   | The port number\(s\) the devices has been observed scanning.                          | 
| GreyNoise.IP.raw_data.scan.protocol             | string   | The protocol of the port the device has been observed scanning.                       | 
| GreyNoise.IP.raw_data.web.paths                 | array    | Any HTTP paths the device has been observed crawling the Internet for.                | 
| GreyNoise.IP.raw_data.web.useragents            | array    | Any HTTP user-agents the device has been observed using while crawling the Internet.  | 
| GreyNoise.IP.raw_data.ja3.fingerprint           | string   | The JA3 TLS/SSL fingerprint.                                                          | 
| GreyNoise.IP.raw_data.ja3.port                  | number   | The corresponding TCP port for the given JA3 fingerprint.                             | 
| GreyNoise.IP.raw_data.hassh.fingerprint         | string   | HASSH hash fingerprint string.                                                        | 
| GreyNoise.IP.raw_data.hassh.port                | number   | TCP port connection where the HASSH hash was identified.                              | 

#### Command Example

``` !greynoise-context ip="66.249.68.82" ```

#### Human Readable Output

### Benign IP

IP: 66.249.68.82 found with Noise Reputation: Good

|IP|Classification|Actor|Tags|Spoofable|VPN|BOT|Tor|First Seen|Last Seen|
|---|---|---|---|---|---|---|---|---|---|
| 66.249.68.82 | 66.249.68.82 | GoogleBot | TLS/SSL Crawler, Web Crawler | false | false | false | false | 2021-05-30 | 2021-09-16 |

``` !greynoise-context ip="114.119.130.178" ```

#### Human Readable Output

### Unidentified IP

IP: 103.21.244.0 No Mass-Internet Scanning Noise Found

|IP|Seen|
|---|---|
| 103.21.244.0 | false |


### greynoise-similarity 

***
Identify IPs with a similar internet scanning profile. 

#### Base Command

`greynoise-similarity `

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

``` !greynoise-similarity   ip="1.2.3.4" minimum_score="90" maximum_results="50"```

#### Human Readable Output

IP: 59.88.225.2 - Similar Internet Scanners found in GreyNoise
Total Similar IPs with Score above 90%: 100
Displaying 50 results below.  To see all results, visit the GreyNoise Visualizer.
GreyNoise Similar IPs

| IP      | Score | Classification | Actor   | Organization | Last Seen  | Similarity Features   |
|---------|-------|----------------|---------|--------------|------------|-----------------------|
| 1.2.3.4 | 100   | malicious      | unknown | GoogleBot    | 2023-04-05 | ports,spoofable_bool  |

``` !greynoise-similarity  ip="114.119.130.178" ```

#### Human Readable Output

GreyNoise Similarity Lookup returned No Results.

### greynoise-similarity 

***
Identify IPs with a similar internet scanning profile. 

#### Base Command

`greynoise-similarity `

#### Input

| **Argument Name** | **Description**                                                                    | **Required** |
|-------------------|------------------------------------------------------------------------------------|--------------|
| ip                | The IP address to find similar IPs for                                             | Required     |
| days              | The number of days from today to get activity.  Valid from 1 to 90. Default is 30. | Optional     |
| maximum_results   | The maximum number of similar results to return.  Default is 50.                   | Optional     |



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

``` !greynoise-timeline ip="1.1.2.2" days="30" maximum_results="30"```

#### Human Readable Output

IP: 45.164.214.212 - GreyNoise IP Timeline
Internet Scanner Timeline Details - Daily Activity Summary

| Date    | Classification | Tags        | rDNS        | Organization | ASN     | Ports                | Web Paths  | User Agents     |
|---------|----------------|-------------|-------------|--------------|---------|----------------------|------------|-----------------|
| 1.2.3.4 | malicious      | BruteForcer | me.acme.lcl | Acme, Inc    | AS12345 | ports,spoofable_bool | /root/home | MozillaFirefox  |

``` !greynoise-timeline ip="1.1.2.2" days="30" maximum_results="30" ```

#### Human Readable Output

GreyNoise IP Timeline Returned No Results.
