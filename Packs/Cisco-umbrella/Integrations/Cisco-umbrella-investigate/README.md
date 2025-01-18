Cisco Umbrella Investigate enable you to research domains, IPs, and URLs observed by the Umbrella resolvers.
This integration was integrated and tested with version 2.0.0 of Cisco Umbrella Investigate.

## Configure Cisco Umbrella Investigate in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | API key and Secret | True |
| API Secret |  | True |
| Source Reliability |  | True |
| Trust any certificate (not secure) |  |  |
| Use system proxy settings |  |  |
| Base URL | Cisco Umbrella Investigate base URL. | True |
| DBot Score Suspicious Threshold (-100 to 100) | Make sure the suspicious threshold is greater than the Malicious threshold. | True |
| Score Malicious Threshold (-100 to 100) | Make sure the Malicious threshold is less than the suspicious threshold. | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### umbrella-domain-categorization

***
Get the status, security, and content categories for the domain.

#### Base Command

`umbrella-domain-categorization`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The name of the domain. For example: cnn.com. | Required |
| show_label | Whether to display the security and content category labels in the response. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.SecurityCategories | Unknown | The Umbrella security categories that match this domain. |
| Domain.ContentCategories | Unknown | The Umbrella content categories that match this domain. |
| DBotScore.Indicator | String | The name of the domain. |
| DBotScore.Vendor | String | The vendor reporting the score of the indicator. |
| DBotScore.Type | String | The type of the indicator. |
| DBotScore.Score | Number | The domain score. |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |

#### Command example
```!umbrella-domain-categorization domain=cisco.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "cisco.com",
        "Reliability": "A+ - 3rd party enrichment",
        "Score": 1,
        "Type": "domain",
        "Vendor": "Cisco Umbrella Investigate"
    },
    "Domain": {
        "ContentCategories": [
            "Business Services",
            "Computers and Internet",
            "Software/Technology"
        ],
        "Name": "cisco.com",
        "SecurityCategories": [],
        "status": 1
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-domain-search

***
Search for newly seen domains that match a regular expression pattern.

#### Base Command

`umbrella-domain-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| regex | A standard regular expression pattern search. For example: exa[a-z]ple.com. | Required |
| start | Filter for data that appears after this time (within the last 30 days). You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. Default is 1 week ago. | Optional |
| stop | Filter for data that appears before this time (within the last 30 days). You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. Default is now. | Optional |
| include_category | Whether to retrieve security categories in the response. Possible values are: true, false. | Optional |
| type | Filter with the search database node type. Possible values are: URL, IP, HOST. | Optional |
| page | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0. Default is 0. | Optional |
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the query. |
| Domain.FirstSeen | String | The first time Umbrella related the domain for the resource record, specified in Unix epoch time. |
| Domain.FirstSeenISO | String | The first time Umbrella related the domain for the resource record, specified in ISO date and time format. |
| Domain.SecurityCategories | Unknown | The list of Umbrella security categories that match the domain. |

#### Command example
```!umbrella-domain-search regex=exa[a-z]ple.com limit=1```
#### Human Readable Output

>Metrics reported successfully.

### umbrella-domain-co-occurrences

***
List the co-occurences for the specified domain. A co-occurrence is when two or more domains are accessed by the same users within a small window of time. Co-occurring domains are not necessarily problematic; legitimate sites co-occur with each other as a part of normal web activity. However, unusual or suspicious co-occurences can provide additional information regarding attacks. To determine co-occurrences for a domain, a small time window of traffic across all of our datacenters is taken. Umbrella Investigate checks the sites that end users visited before and after the domain was requested in the API call.

#### Base Command

`umbrella-domain-co-occurrences`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name. For example: cnn.com. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.CoOccurrences.Name | String |  The name of the co-occurrence domain. |
| Domain.CoOccurrences.Score | Number | The score of the co-occurrence domain. |

#### Command example
```!umbrella-domain-co-occurrences domain=cisco.com```
#### Context Example
```json
{
    "Domain": {
        "CoOccurrences": [
            {
                "Name": "bankofamerica.com",
                "Score": 0.9605992656904034
            },
            {
                "Name": "www.bankofamerica.com",
                "Score": 0.019189025631362176
            }
        ],
        "Name": "cisco.com"
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-domain-related

***
List domain names that are frequently requested around the same time (up to 60 seconds before or after) as the given domain name, but that are not frequently associated with other domain names.

#### Base Command

`umbrella-domain-related`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name. For example: cnn.com. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.Related.Name | String | A related domain name. |
| Domain.Related.Score | Number | The number of client IP requests to the site around the same time that the site is looked up. |

#### Command example
```!umbrella-domain-related domain=cisco.com```
#### Context Example
```json
{
    "Domain": {
        "Name": "cisco.com",
        "Related": [
            {
                "Name": "www.google.com.",
                "Score": 74
            }
        ]
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-domain-security

***
Get multiple scores or security features for a domain. You can use the scores or security features to determine relevant data points and build insights on the reputation or security risk posed by the site.

#### Base Command

`umbrella-domain-security`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name. For example: cnn.com. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.Security.DGA | Number | A domain generation algorithm \(DGA\) is used by malware to generate large lists of domain names. This score is created based on the likeliness of the domain name being generated by an algorithm rather than a human. This algorithm is designed to identify domains that have been created using an automated randomization strategy, which is a common evasion technique in malware kits or botnets. This score ranges from -100 \(suspicious\) to 0 \(benign\). |
| Domain.Security.Perplexity | Number | A second score on the likeliness of the name to be algorithmically generated, on a scale from 0 to 100. This score is used in conjunction with DGA. |
| Domain.Security.Entropy | Number | The number of bits required to encode the domain name as a score. This score is used in conjunction with DGA and Perplexity. |
| Domain.Security.SecureRank | Number | The suspicious rank for a domain that reviews are based on the lookup behavior of client IP for the domain. Secure rank is designed to identify hostnames requested by known infected clients but never requested by clean clients, assuming these domains are more likely to be bad. Scores returned range from -100 \(suspicious\) to 100 \(benign\). |
| Domain.Security.PageRank | Number | A popularity score according to Google's PageRank algorithm. |
| Domain.Security.ASNScore | Number | The ASN reputation score ranges from -100 to 0 where -100 is very suspicious. |
| Domain.Security.PrefixScore | Number | The prefix ranks domains given their IP prefixes \(an IP prefix is the first three octets in an IP address\) and the reputation score of these prefixes. The scores range from -100 to 0 where -100 is very suspicious. |
| Domain.Security.RipScore | Number | The RIP ranks domains given their IP addresses and the reputation score of these IP addresses. The scores ranges from -100 to 0 where -100 is very suspicious. |
| Domain.Security.Popularity | Number | The number of unique client IPs visiting this site, relative to all requests to all sites. A score of how many different client or unique IPs requested to this domain compared to others. |
| Domain.Security.GeoScore | Number | A score that represents how far the different physical locations serving this name are from each other. |
| Domain.Security.KolmoorovSmirnov | Number | A number that represents the Kolmogorov-Smirnov test on geo diversity. Zero indicates that the client traffic matches what is expected for this top-level domain. |
| Domain.Security.AttackName | String | The name of any known attacks associated with this domain. |
| Domain.Security.ThreatType | String | The type of the known attack, such as botnet or APT. |
| Domain.tld_geodiversity | Unknown | The list of scores that represent the top-level domain country code geo diversity as a percentage of clients visiting the domain. |
| Domain.GeodiversityNormalized.score | Number | Score that represents the amount of queries for clients visiting the domain \(by country\) |
| Domain.GeodiversityNormalized.country_code | String | Country code for the score. |
| Domain.Geodiversity.score | Number | Score that represents the amount of queries for clients visiting the domain \(by country\) |
| Domain.Geodiversity.country_code | String | Country code for the score. |

#### Command example
```!umbrella-domain-security domain=cisco.com```
#### Context Example
```json
{
    "Domain": {
        "Geodiversity": [
            {
                "country_code": "BM",
                "score": 0.15136951091031767
            }
        ],
        "Name": "cisco.com",
        "Security": {
            "ASNScore": 0,
            "AttackName": "",
            "DGA": 0,
            "Entropy": 1.9219280948873625,
            "GeoScore": 0,
            "KolmoorovSmirnov": 0,
            "PageRank": 0,
            "Perplexity": 0.11194989638754399,
            "Popularity": 100,
            "PrefixScore": 0,
            "RipScore": 0,
            "SecureRank": 0,
            "ThreatType": ""
        },
        "tld_geodiversity": []
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-domain-risk-score

***
Get the domain risk score. The Umbrella Investigate Risk Score is based on an analysis of the lexical characteristics of the domain name, patterns in queries and requests to the domain. The risk score is scaled from 0 to 100 where 100 is the highest risk and 0 represents no risk at all.

#### Base Command

`umbrella-get-domain-risk-score`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name. For example: cnn.com. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Umbrella.Domain.name | String | The name of the domain. |
| Umbrella.Domain.risk_score | Number | The indicator risk score. |
| Umbrella.Domain.Indicator.score | Number | The raw outcome score from the statistical algorithms. |
| Umbrella.Domain.Indicator.normalized_score | Number | Normalized risk score. The risk score is scaled from 0 to 100 where 100 is the highest risk and 0 represents no risk at all. |
| Umbrella.Domain.Indicator.indicator_id | String | The indicator ID. Each  is a behavioral or lexical feature that contributes to the calculation of the risk score. |
| Umbrella.Domain.Indicator.indicator | String | The name of the indicator. |
| DBotScore.Indicator | String | The name of the domain. |
| DBotScore.Vendor | String | The vendor reporting the score of the indicator. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Score | Number | The domain score. |
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. |

#### Command example
```!umbrella-get-domain-risk-score domain=cisco.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "cisco.com",
        "Reliability": "A+ - 3rd party enrichment",
        "Score": 1,
        "Type": "domain",
        "Vendor": "Cisco Umbrella Investigate"
    },
    "Domain": {
        "Name": "cisco.com"
    },
    "Umbrella": {
        "Domain": {
            "Indicator": [
                {
                    "indicator": "Geo Popularity Score",
                    "indicator_id": "Geo Popularity Score",
                    "normalized_score": 2,
                    "score": -3.610878170000001
                }
            ],
            "name": "cisco.com",
            "risk_score": 5
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-list-resource-record

***
List the Resource Record (RR) data for DNS responses, and categorization data, where the answer (or rdata) is the inserted value or list historical data from the Umbrella resolvers for domains, IPs, and other resource records (by using the type name).

#### Base Command

`umbrella-list-resource-record`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of the inserted value. Possible values are: IP, Domain, Raw, Name. | Required |
| value | The text representation of the data. For example, when type is raw - %22abc%22. When type is IP - 8.8.8.8. When type is Domain - cisco.com. When type is Name - test . . | Required |
| sort_order | Sort records by ascending (asc) or descending (desc) order. Possible values are: asc, desc. Default is desc. | Optional |
| sort_by | Sort records by one of the following fields. Possible values are: Min Ttl, Max Ttl, First Seen, Last Seen. | Optional |
| record_type | Comma-separated list of types of records. For example: A,Cname. Possible values are: A, Cname, Ns, Mx. | Optional |
| include_features | Whether to add the feature sections to the response. If set to true, the response will contain additional information about the IP address, such as record counts and diversity metrics. Possible values are: true, false. | Optional |
| min_first_seen | Select records that are first seen after the inserted value. You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. | Optional |
| max_first_seen | Select records that are first seen before the inserted value. You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. | Optional |
| min_last_seen | Select records that were last seen after the inserted value. You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. | Optional |
| max_last_seen | Select records that were last seen before the inserted value. You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. | Optional |
| sort_categories | Comma-separated list of security categories to sort the results. For example, Mobile Threats,Malware. Possible values are: All, Drive-by Downloads/Exploits, Mobile Threats, Dynamic DNS, High Risk Sites and Locations, Command and Control, Malware, Phishing, Newly Seen Domains, Potentially Harmful, DNS Tunneling VPN, Cryptomining. | Optional |
| required_categories | Comma-separated list of security categories to filter for records that are assigned the specified categories. For example, Malware,Phishing. Possible values are: Drive-by Downloads/Exploits, Mobile Threats, Dynamic DNS, High Risk Sites and Locations, Command and Control, Malware, Phishing, Newly Seen Domains, Potentially Harmful, DNS Tunneling VPN, Cryptomining. . | Optional |
| page | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0. Default is 0. | Optional |
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.ResourceRecord.value | String | The text representation of the data. |
| Umbrella.ResourceRecord.last_seen_iso | Date | The last time Umbrella related the domain for the resource record, specified in ISO date and time format. |
| Umbrella.ResourceRecord.first_seen_iso | Date | The first time Umbrella related the domain for the resource record, specified in ISO date and time format. |
| Umbrella.ResourceRecord.content_categories | Unknown | The Umbrella content categories. |
| Umbrella.ResourceRecord.security_categories | Unknown | The Umbrella security categories. |
| Umbrella.ResourceRecord.type | String | The DNS record type. |
| Umbrella.ResourceRecord.name | String | The name of the query. |
| Umbrella.ResourceRecord.rr | String | The Resource Records, if any that match the domain. |
| Umbrella.ResourceRecord.last_seen | Number | The last time Umbrella related the domain for the resource record, specified in Unix epoch time. |
| Umbrella.ResourceRecord.first_seen | Number | The first time Umbrella related the domain for the resource record, specified in Unix epoch time. |
| Umbrella.ResourceRecord.max_ttl | Number | The maximum TTL for the record in seconds. |
| Umbrella.ResourceRecord.min_ttl | Number | The minimum TTL for the record in seconds. |

#### Command example
```!umbrella-list-resource-record value=cisco.com type=Name limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "ResourceRecord": {
            "content_categories": [
                "Business Services",
                "Computers and Internet",
                "Software/Technology"
            ],
            "first_seen": 1408040040,
            "first_seen_iso": "2014-08-14T18:14Z",
            "last_seen": 1722850932,
            "last_seen_iso": "2024-08-05T09:42Z",
            "max_ttl": 86400,
            "min_ttl": 1,
            "name": "cisco.com",
            "rr": "ns1.cisco.com.",
            "security_categories": [],
            "type": "NS",
            "value": "cisco.com"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-list-domain-subdomain

***
List sub-domains of a given domain.

#### Base Command

`umbrella-list-domain-subdomain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name. For example: cnn.com. | Required |
| offset_name | Specify the subdomain to filter the collection. For example api.cisco.com when domain is cisco.com. The default value is the target domain. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.Domain.name | String | The name of the domain. |
| Umbrella.Domain.SubDomain.name | String | The name of the sub-domain. |
| Umbrella.Domain.SubDomain.first_seen | String | The first time Umbrella related the domain for the resource record, specified in Unix epoch time. |
| Umbrella.Domain.SubDomain.security_categories | Unknown | The list of security categories that are tagged on this sub-domain. |

#### Command example
```!umbrella-list-domain-subdomain domain=cisco.com limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "Domain": {
            "SubDomain": [
                {
                    "first_seen": "1463632560",
                    "name": "00-0f-44-00-9e-3b-lobby-dmp.cisco.com",
                    "security_categories": []
                }
            ],
            "name": "cisco.com"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-ip-bgp

***
Get data about ASN and IP relationships, showing how IP addresses are related to each other and to the regional registries. You can find out more about the IP space associated with an AS and correlate BGP routing information between AS.

#### Base Command

`umbrella-get-ip-bgp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IPv4 IP address where to obtain the AS information. For example: 1.2.3.4. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.BGPInformation.ip | String | The IP address. |
| Umbrella.BGPInformation.creation_date | String | The date when the AS was first created. |
| Umbrella.BGPInformation.ir | Number | The IR number corresponds to one of the 5 Regional Internet Registries \(RIR\). 1 - AfriNIC: Africa2 - APNIC: Asia, Australia, New Zealand, and neighboring countries.3 - ARIN: United States, Canada, several parts of the Caribbean region, and Antarctica.4 - LACNIC: Latin America and parts of the Caribbean region.5 - RIPE NCC: Europe, Russia, the Middle East, and Central Asia.0 - Unknown / Not Available. |
| Umbrella.BGPInformation.description | String | Network owner description as provided by the network owner. |
| Umbrella.BGPInformation.asn | String | The autonomous system number \(ASN\) associated with the IP address. |
| Umbrella.BGPInformation.cidr | String | The IP CIDR for the ASN. |

#### Command example
```!umbrella-get-ip-bgp ip=8.8.8.8```
#### Context Example
```json
{
    "Umbrella": {
        "BGPInformation": [
            {
                "asn": 3356,
                "cidr": "8.8.8.8/12",
                "creation_date": "2000-03-10",
                "description": "LEVEL3, US 86400",
                "ip": "8.8.8.8",
                "ir": 3
            }
        ]
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-asn-bgp

***
Get BGP Route Information for ASN. Each hash reference contains two keys: `geo` and `cidr`. Geo is a hash reference with the country name and country code (the code corresponds to the country code list for ISO-3166-1 alpha-2). CIDR contains the IP prefix for this ASN.

#### Base Command

`umbrella-get-asn-bgp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asn | Autonomous System Number (ASN) for the AS. For example: 4134. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.BGPInformation.asn | String | The ASN. |
| Umbrella.BGPInformation.cidr | String | A list of the CIDR range of IP addresses associated with this AS.The CIDR contains the IP prefix for the ASN. |
| Umbrella.BGPInformation.Geo.country_name | Number | The country name of the geolocation. |
| Umbrella.BGPInformation.Geo.country_code | String | The country code of the geolocation. |

#### Command example
```!umbrella-get-asn-bgp asn=3356```
#### Context Example
```json
{
    "Umbrella": {
        "BGPInformation": [
            {
                "Geo": {
                    "country_code": "US",
                    "country_name": "United States"
                },
                "asn": "3356",
                "cidr": "8.8.8.8/9"
            }
        ]
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### domain

***
Get the WHOIS information for the specified domains.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name. For example: cnn.com. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. |
| Domain.Umbrella.RiskScore | String | Suspicious rank for a domain that has reviews based on the lookup behavior of client IP for the domain. Securerank is designed to identify hostnames requested by known infected clients but never requested by clean clients, assuming these domains are more likely to be bad. Scores returned range from -100 \(suspicious\) to 100 \(benign\). |
| Domain.Umbrella.SecureRank | String | Suspicious rank for a domain that has reviews based on the lookup behavior of client IP for the domain. Securerank is designed to identify hostnames requested by known infected clients but never requested by clean clients, assuming these domains are more likely to be bad. Scores returned range from -100 \(suspicious\) to 100 \(benign\). |
| Domain.Umbrella.FirstQueriedTime | String | The time when the attribution for this domain was made. |
| DBotScore.Indicator | String | The Indicator name. |
| DBotScore.Score | String | The DBot score. |
| DBotScore.Type | String | The domain type. |
| DBotScore.Vendor | String | The DBot score vendor. |
| Domain.Umbrella.ContentCategories | String | The Umbrella content category or categories that match this domain. If none of them match, the return will be blank. |
| Domain.Umbrella.MalwareCategories | String | string |
| Domain.Malicious.Vendor | String | string |
| Domain.Malicious.Description | String | string |
| Domain.Admin.Country | String | string |
| Domain.Admin.Email | String | string |
| Domain.Admin.Name | String | string |
| Domain.Admin.Phone | String | string |
| Domain.Registrant.Country | String | string |
| Domain.Registrant.Email | String | string |
| Domain.Registrant.Name | String | string |
| Domain.Registrant.Phone | String | string |
| Domain.CreationDate | String | date |
| Domain.DomainStatus | String | string |
| Domain.UpdatedDate | String | date |
| Domain.ExpirationDate | String | date |
| Domain.Registrar.Name | String | string |

#### Command example
```!domain domain=cisco.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "cisco.com",
        "Reliability": "A+ - 3rd party enrichment",
        "Score": 0,
        "Type": "domain",
        "Vendor": "Cisco Umbrella Investigate"
    },
    "Domain": {
        "Admin": {
            "Country": "UNITED STATES",
            "Email": "infosec@cisco.com",
            "Name": "Domain Administrator",
            "Phone": "14085273842"
        },
        "CreationDate": "1987-05-14",
        "DomainStatus": [
            "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited"
        ],
        "ExpirationDate": "2025-05-15",
        "Name": "cisco.com",
        "Registrant": {
            "Country": "UNITED STATES",
            "Email": "infosec@cisco.com",
            "Name": "Domain Administrator",
            "Phone": "14085273842"
        },
        "Registrar": {
            "Name": "MarkMonitor, Inc."
        },
        "Umbrella": {
            "ContentCategories": [
                "32",
                "167",
                "25"
            ],
            "FirstQueriedTime": "1987-05-14",
            "MalwareCategories": [],
            "RiskScore": 5,
            "SecureRank": 0
        },
        "UpdatedDate": "2024-04-13"
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-whois-for-domain

***
Get the WHOIS information for the specified domains. You can search by multiple email addresses or multiple nameservers.

#### Base Command

`umbrella-get-whois-for-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name. For example: cnn.com. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.WHOIS.name | String | The domain name. |
| Umbrella.WHOIS.Domain | String | The domain name. |
| Umbrella.WHOIS.Data.RegistrarName | String | The domain registrar name. |
| Umbrella.WHOIS.Data.LastRetrieved | String | Domain last retrieved date |
| Umbrella.WHOIS.Data.Created | String | The domain created date. |
| Umbrella.WHOIS.Data.Updated | String | The domain updated date. |
| Umbrella.WHOIS.Data.Expires | String | The domain expiry date. |
| Umbrella.WHOIS.Data.IANAID | String | The registrar IANA ID. |
| Umbrella.WHOIS.Data.LastObserved | String | The domain last observed time. |
| Umbrella.WHOIS.Data.Nameservers.Name | String | The domain’s name servers. |
| Umbrella.WHOIS.Data.Emails.Name | String | The domain’s email. |
| Domain.Admin.Country | String | The country of the domain administrator. |
| Domain.name | String | The domain name. |
| Domain.CreationDate | String | The date on which the domain was created. |
| Domain.UpdatedDate | String | The date on which the domain was last updated. |
| Domain.ExpirationDate | String | The expiration date of the domain. |
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. |
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. |
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. |
| Domain.WHOIS.Registrant.Country | String | The country of the registrant. |
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. |
| Domain.WHOIS.Registrant.Name | String | The phone number of the registrant. |
| Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant. |
| Domain.WHOIS.DomainStatus | String | The status of the domain. |
| Domain.WHOIS.Registrar.Name | String | The name of the registrar. |
| Domain.Admin.Email | String | The email address of the domain administrator. |
| Domain.Admin.Name | String | The name of the domain administrator. |
| Domain.Admin.Phone | String | The phone number of the domain administrator. |
| Domain.Registrant.Country | String | The country of the registrant. |
| Domain.Registrant.Email | String | The email address of the registrant. |
| Domain.Registrant.Name | String | The phone number of the registrant. |
| Domain.Registrant.Phone | String | The phone number of the registrant. |
| Domain.DomainStatus | String | The status of the domain. |
| Domain.Registrar.Name | String | The name of the registrar. |

#### Command example
```!umbrella-get-whois-for-domain domain=cisco.com limit=1```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "cisco.com",
        "Reliability": "A+ - 3rd party enrichment",
        "Score": 0,
        "Type": "domain",
        "Vendor": "Cisco Umbrella Investigate"
    },
    "Domain": {
        "Admin": {
            "Country": "UNITED STATES",
            "Email": "infosec@cisco.com",
            "Name": "Domain Administrator",
            "Phone": "14085273842"
        },
        "CreationDate": "1987-05-14",
        "DomainStatus": [
            "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited"
        ],
        "ExpirationDate": "2025-05-15",
        "Name": "cisco.com",
        "Registrant": {
            "Country": "UNITED STATES",
            "Email": "infosec@cisco.com",
            "Name": "Domain Administrator",
            "Phone": "14085273842"
        },
        "Registrar": {
            "AbuseEmail": null,
            "AbusePhone": null,
            "Name": "MarkMonitor, Inc."
        },
        "UpdatedDate": "2024-04-13",
        "WHOIS": {
            "Admin": {
                "Country": "UNITED STATES",
                "Email": "infosec@cisco.com",
                "Name": "Domain Administrator",
                "Phone": "14085273842"
            },
            "CreationDate": "1987-05-14",
            "DomainStatus": [
                "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited"
            ],
            "ExpirationDate": "2025-05-15",
            "Registrant": {
                "Country": "UNITED STATES",
                "Email": "infosec@cisco.com",
                "Name": "Domain Administrator",
                "Phone": "14085273842"
            },
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "MarkMonitor, Inc."
            },
            "UpdatedDate": "2024-04-13"
        }
    },
    "Umbrella": {
        "WHOIS": {
            "Data": {
                "Created": "1987-05-14",
                "Emails": [
                    {
                        "Name": "infosec@cisco.com"
                    }
                ],
                "Expires": "2025-05-15",
                "IANAID": "292",
                "LastObserved": "2024-06-19 23:56:41 UTC",
                "LastRetrieved": 1718896344930,
                "Nameservers": [
                    {
                        "Name": "ns1.cisco.com"
                    },
                    {
                        "Name": "ns2.cisco.com"
                    },
                    {
                        "Name": "ns3.cisco.com"
                    }
                ],
                "RegistrarName": "Domain Administrator",
                "Updated": "2024-04-13"
            },
            "Domain": "cisco.com",
            "name": "cisco.com"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-domain-whois-history

***
Get a WHOIS response record for a single domain with available historical WHOIS data returned in an object. The information displayed varies by registrant.

#### Base Command

`umbrella-get-domain-whois-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name. For example: cnn.com. | Required |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.WHOIS.name | String | The name of the domain. |
| Umbrella.WHOIS.DomainHistory.addresses | String | Addresses related to the domain. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_city | String | City of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_country | String | Country of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_email | String | Email of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_fax | String | Fax number of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_fax_ext | String | Fax extension of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_name | String | Name of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_organization | String | Organization of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_postal_code | String | Postal code of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_state | String | State of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_street | String | Street address of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_telephone | String | Telephone number of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.administrative_contact_telephone_ext | String | Telephone extension of the administrative contact. |
| Umbrella.WHOIS.DomainHistory.audit_updated_date | String | Audit update date. |
| Umbrella.WHOIS.DomainHistory.billing_contact_city | String | City of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_country | String | Country of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_email | String | Email of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_fax | String | Fax number of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_fax_ext | String | Fax extension of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_name | String | Name of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_organization | String | Organization of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_postal_code | String | Postal code of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_state | String | State of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_street | String | Street address of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_telephone | String | Telephone number of the billing contact. |
| Umbrella.WHOIS.DomainHistory.billing_contact_telephone_ext | String | Telephone extension of the billing contact. |
| Umbrella.WHOIS.DomainHistory.created | String | The domain created date. |
| Umbrella.WHOIS.DomainHistory.domain_name | String | The domain name. |
| Umbrella.WHOIS.DomainHistory.emails | String | Emails associated with the domain. |
| Umbrella.WHOIS.DomainHistory.expires | String | The domain expiry date. |
| Umbrella.WHOIS.DomainHistory.has_raw_text | String | Indicates if there is raw text. |
| Umbrella.WHOIS.DomainHistory.name_servers | String | The domain’s name servers. |
| Umbrella.WHOIS.DomainHistory.record_expired | String | Record expired status. |
| Umbrella.WHOIS.DomainHistory.registrant_city | String | City of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_country | String | Country of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_email | String | Email of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_fax | String | Fax number of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_fax_ext | String | Fax extension of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_name | String | Name of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_organization | String | Organization of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_postal_code | String | Postal code of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_state | String | State of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_street | String | Street address of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_telephone | String | Telephone number of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrant_telephone_ext | String | Telephone extension of the registrant. |
| Umbrella.WHOIS.DomainHistory.registrar_ianad | String | Registrar IANA ID. |
| Umbrella.WHOIS.DomainHistory.registrar_name | String | Name of the registrar. |
| Umbrella.WHOIS.DomainHistory.status | String | Domain status. |
| Umbrella.WHOIS.DomainHistory.technical_contact_city | String | City of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_country | String | Country of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_email | String | Email of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_fax | String | Fax number of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_fax_ext | String | Fax extension of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_name | String | Name of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_organization | String | Organization of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_postal_code | String | Postal code of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_state | String | State of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_street | String | Street address of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_telephone | String | Telephone number of the technical contact. |
| Umbrella.WHOIS.DomainHistory.technical_contact_telephone_ext | String | Telephone extension of the technical contact. |
| Umbrella.WHOIS.DomainHistory.time_of_latest_realtime_check | String | Time of the latest realtime check. |
| Umbrella.WHOIS.DomainHistory.timestamp | String | Timestamp of the record. |
| Umbrella.WHOIS.DomainHistory.updated | String | The domain updated date. |
| Umbrella.WHOIS.DomainHistory.whois_servers | String | WHOIS servers associated with the domain. |
| Umbrella.WHOIS.DomainHistory.zone_contact_city | String | City of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_country | String | Country of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_email | String | Email of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_fax | String | Fax number of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_fax_ext | String | Fax extension of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_name | String | Name of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_organization | String | Organization of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_postal_code | String | Postal code of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_state | String | State of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_street | String | Street address of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_telephone | String | Telephone number of the zone contact. |
| Umbrella.WHOIS.DomainHistory.zone_contact_telephone_ext | String | Telephone extension of the zone contact. |

#### Command example
```!umbrella-get-domain-whois-history domain=cisco.com limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "WHOIS": {
            "DomainHistory": [
                {
                    "addresses": [
                        "170 w. tasman dr."
                    ],
                    "administrative_contact_city": "San Jose",
                    "administrative_contact_country": "UNITED STATES",
                    "administrative_contact_email": "infosec@cisco.com",
                    "administrative_contact_fax": null,
                    "administrative_contact_fax_ext": null,
                    "administrative_contact_name": "Domain Administrator",
                    "administrative_contact_organization": "Cisco Technology Inc.",
                    "administrative_contact_postal_code": "95134",
                    "administrative_contact_state": "CA",
                    "administrative_contact_street": [
                        "170 w. tasman dr."
                    ],
                    "administrative_contact_telephone": "14085273842",
                    "administrative_contact_telephone_ext": null,
                    "audit_updated_date": "2024-06-19 23:56:41 UTC",
                    "billing_contact_city": null,
                    "billing_contact_country": null,
                    "billing_contact_email": null,
                    "billing_contact_fax": null,
                    "billing_contact_fax_ext": null,
                    "billing_contact_name": null,
                    "billing_contact_organization": null,
                    "billing_contact_postal_code": null,
                    "billing_contact_state": null,
                    "billing_contact_street": [],
                    "billing_contact_telephone": null,
                    "billing_contact_telephone_ext": null,
                    "created": "1987-05-14",
                    "domain_name": "cisco.com",
                    "emails": [
                        "infosec@cisco.com"
                    ],
                    "expires": "2025-05-15",
                    "has_raw_text": true,
                    "name_servers": [
                        "ns1.cisco.com",
                        "ns2.cisco.com",
                        "ns3.cisco.com"
                    ],
                    "record_expired": false,
                    "registrant_city": "San Jose",
                    "registrant_country": "UNITED STATES",
                    "registrant_email": "infosec@cisco.com",
                    "registrant_fax": "14085264575",
                    "registrant_fax_ext": null,
                    "registrant_name": "Domain Administrator",
                    "registrant_organization": "Cisco Technology Inc.",
                    "registrant_postal_code": "95134",
                    "registrant_state": "CA",
                    "registrant_street": [
                        "170 w. tasman dr."
                    ],
                    "registrant_telephone": "14085273842",
                    "registrant_telephone_ext": null,
                    "registrar_ianaid": "292",
                    "registrar_name": "MarkMonitor, Inc.",
                    "status": [
                        "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited"
                    ],
                    "technical_contact_city": "San Jose",
                    "technical_contact_country": "UNITED STATES",
                    "technical_contact_email": "infosec@cisco.com",
                    "technical_contact_fax": "14085264575",
                    "technical_contact_fax_ext": null,
                    "technical_contact_name": "Domain Administrator",
                    "technical_contact_organization": "Cisco Technology Inc.",
                    "technical_contact_postal_code": "95134",
                    "technical_contact_state": "CA",
                    "technical_contact_street": [
                        "170 w. tasman dr."
                    ],
                    "technical_contact_telephone": "14085273842",
                    "technical_contact_telephone_ext": null,
                    "time_of_latest_realtime_check": 1718896344930,
                    "timestamp": null,
                    "updated": "2024-04-13",
                    "whois_servers": "whois.markmonitor.com",
                    "zone_contact_city": null,
                    "zone_contact_country": null,
                    "zone_contact_email": null,
                    "zone_contact_fax": null,
                    "zone_contact_fax_ext": null,
                    "zone_contact_name": null,
                    "zone_contact_organization": null,
                    "zone_contact_postal_code": null,
                    "zone_contact_state": null,
                    "zone_contact_street": [],
                    "zone_contact_telephone": null,
                    "zone_contact_telephone_ext": null
                }
            ],
            "name": "cisco.com"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-nameserver-whois

***
Get WHOIS information for the nameserver. A nameserver can potentially register hundreds or thousands of domains.

#### Base Command

`umbrella-get-nameserver-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nameserver | The nameserver's domain name or comma-separated list of nameservers. For example ns1.google.com or ns1.google.com,ns2.google.com. | Required |
| sort | Sort the results by. Possible values are: Created, Updated, Expires, Domain name. | Optional |
| page | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0. | Optional |
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.WHOIS.Nameserver.name | String | The nameserver's domain name. |
| Umbrella.WHOIS.Nameserver.Domain.current | Boolean | Whether the domain name is current. |
| Umbrella.WHOIS.Nameserver.Domain.domain | String | The domain name. |

#### Command example
```!umbrella-get-nameserver-whois nameserver=nameserver1.com limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "WHOIS": {
            "Nameserver": {
                "Domain": [
                    {
                        "current": false,
                        "domain": "choicehotels.link"
                    }
                ],
                "name": "nameserver1.com"
            }
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-email-whois

***
Get WHOIS information for the email address. Returns the email address or addresses of the registrar for the domain or domains. The results include the total number of results for domains registered by this email address and a list of the first 500 domains associated with this email.

#### Base Command

`umbrella-get-email-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | An email address that follows the RFC5322 conventions. For example, test@test.com. | Required |
| sort | Sort the results by. Possible values are: Created, Updated, Expires, Domain name. | Optional |
| page | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0. Default is 0. | Optional |
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.WHOIS.Email.name | String | The email name. |
| Umbrella.WHOIS.Email.Domain.current | Boolean | Whether the domain name is current. |
| Umbrella.WHOIS.Email.Domain.domain | String | The domain name. |

#### Command example
```!umbrella-get-email-whois email=test@test.com limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "WHOIS": {
            "Email": {
                "Domain": [
                    {
                        "current": false,
                        "domain": "hswv.org"
                    }
                ],
                "name": "test@test.com"
            }
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-regex-whois

***
Performs a regular expression (RegEx) search on the WHOIS data (domain, nameserver, and email fields) that was updated or created in the specified time range. Returns a list of ten WHOIS records that match the specified RegEx expression.

#### Base Command

`umbrella-get-regex-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| regex | A standard regular expression pattern search. For example, exa[a-z]ple.com. | Required |
| search_field | Specifies the field name to use in the RegEx search. Possible values are: Domain, Nameserver, Email. | Required |
| start | Filter for data that appears after this time (within the last 30 days). You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. Default is 1 week ago. | Optional |
| stop | Filter for data that appears before this time (within the last 30 days). You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. Default is now. | Optional |
| sort | Sort the results by. Possible values are: Created, Updated, Expires, Domain name. Default is Updated. | Optional |
| page | The optional 0 based index of the page to retrieve. Must be an integer greater than or equal to 0. Default is 0. | Optional |
| page_size | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.WHOIS.Regex.domain_name | String | The domain name. |
| Umbrella.WHOIS.Regex.registrant_name | String | The domain registrar name. |
| Umbrella.WHOIS.Regex.created | String | The domain created date. |
| Umbrella.WHOIS.Regex.updated | String | The domain updated date. |
| Umbrella.WHOIS.Regex.expires | String | The domain expiry date. |
| Umbrella.WHOIS.Regex.registrar_ianad | String | Registrar IANA ID. |
| Umbrella.WHOIS.Regex.name_servers | String | The domain’s name servers. |
| Umbrella.WHOIS.Regex.emails | String | The domain’s email. |
| Umbrella.WHOIS.Regex.administrative_contact_fax | String | Administrative contact fax number. |
| Umbrella.WHOIS.Regex.whois_servers | String | WHOIS servers associated with the domain. |
| Umbrella.WHOIS.Regex.addresses | String | Addresses related to the domain. |
| Umbrella.WHOIS.Regex.administrative_contact_name | String | Name of the administrative contact. |
| Umbrella.WHOIS.Regex.zone_contact_email | String | Zone contact email. |
| Umbrella.WHOIS.Regex.billing_contact_fax | String | Billing contact fax number. |
| Umbrella.WHOIS.Regex.administrative_contact_telephone_ext | String | Administrative contact telephone extension. |
| Umbrella.WHOIS.Regex.administrative_contact_email | String | Administrative contact email. |
| Umbrella.WHOIS.Regex.technical_contact_email | String | Technical contact email. |
| Umbrella.WHOIS.Regex.technical_contact_fax | String | Technical contact fax number. |
| Umbrella.WHOIS.Regex.zone_contact_name | String | Name of the zone contact. |
| Umbrella.WHOIS.Regex.billing_contact_postal_code | String | Billing contact postal code. |
| Umbrella.WHOIS.Regex.zone_contact_fax | String | Zone contact fax number. |
| Umbrella.WHOIS.Regex.registrant_telephone_ext | String | Registrant telephone extension. |
| Umbrella.WHOIS.Regex.zone_contact_fax_ext | String | Zone contact fax extension. |
| Umbrella.WHOIS.Regex.technical_contact_telephone_ext | String | Technical contact telephone extension. |
| Umbrella.WHOIS.Regex.billing_contact_city | String | Billing contact city. |
| Umbrella.WHOIS.Regex.zone_contact_street | String | Street address of the zone contact. |
| Umbrella.WHOIS.Regex.administrative_contact_city | String | City of the administrative contact. |
| Umbrella.WHOIS.Regex.zone_contact_city | String | City of the zone contact. |
| Umbrella.WHOIS.Regex.zone_contact_postal_code | String | Postal code of the zone contact. |
| Umbrella.WHOIS.Regex.administrative_contact_fax_ext | String | Administrative contact fax extension. |
| Umbrella.WHOIS.Regex.technical_contact_country | String | Country of the technical contact. |
| Umbrella.WHOIS.Regex.administrative_contact_street | String | Street address of the administrative contact. |
| Umbrella.WHOIS.Regex.status | String | Domain status. |
| Umbrella.WHOIS.Regex.registrant_city | String | City of the registrant. |
| Umbrella.WHOIS.Regex.billing_contact_country | String | Country of the billing contact. |
| Umbrella.WHOIS.Regex.technical_contact_street | String | Street address of the technical contact. |
| Umbrella.WHOIS.Regex.registrant_organization | String | Organization of the registrant. |
| Umbrella.WHOIS.Regex.billing_contact_street | String | Street address of the billing contact. |
| Umbrella.WHOIS.Regex.registrar_name | String | Name of the registrar. |
| Umbrella.WHOIS.Regex.registrant_postal_code | String | Postal code of the registrant. |
| Umbrella.WHOIS.Regex.zone_contact_telephone | String | Telephone number of the zone contact. |
| Umbrella.WHOIS.Regex.registrant_email | String | Email of the registrant. |
| Umbrella.WHOIS.Regex.technical_contact_fax_ext | String | Technical contact fax extension. |
| Umbrella.WHOIS.Regex.technical_contact_organization | String | Organization of the technical contact. |
| Umbrella.WHOIS.Regex.registrant_street | String | Street address of the registrant. |
| Umbrella.WHOIS.Regex.technical_contact_telephone | String | Telephone number of the technical contact. |
| Umbrella.WHOIS.Regex.technical_contact_state | String | State of the technical contact. |
| Umbrella.WHOIS.Regex.technical_contact_city | String | City of the technical contact. |
| Umbrella.WHOIS.Regex.registrant_fax | String | Fax number of the registrant. |
| Umbrella.WHOIS.Regex.registrant_country | String | Country of the registrant. |
| Umbrella.WHOIS.Regex.billing_contact_fax_ext | String | Billing contact fax extension. |
| Umbrella.WHOIS.Regex.timestamp | String | Timestamp of the record. |
| Umbrella.WHOIS.Regex.zone_contact_organization | String | Organization of the zone contact. |
| Umbrella.WHOIS.Regex.administrative_contact_country | String | Country of the administrative contact. |
| Umbrella.WHOIS.Regex.billing_contact_name | String | Name of the billing contact. |
| Umbrella.WHOIS.Regex.registrant_state | String | State of the registrant. |
| Umbrella.WHOIS.Regex.registrant_telephone | String | Telephone number of the registrant. |
| Umbrella.WHOIS.Regex.administrative_contact_state | String | State of the administrative contact. |
| Umbrella.WHOIS.Regex.registrant_fax_ext | String | Fax extension of the registrant. |
| Umbrella.WHOIS.Regex.technical_contact_postal_code | String | Postal code of the technical contact. |
| Umbrella.WHOIS.Regex.zone_contact_telephone_ext | String | Telephone extension of the zone contact. |
| Umbrella.WHOIS.Regex.administrative_contact_organization | String | Organization of the administrative contact. |
| Umbrella.WHOIS.Regex.billing_contact_telephone | String | Telephone number of the billing contact. |
| Umbrella.WHOIS.Regex.billing_contact_telephone_ext | String | Telephone extension of the billing contact. |
| Umbrella.WHOIS.Regex.zone_contact_state | String | State of the zone contact. |
| Umbrella.WHOIS.Regex.administrative_contact_telephone | String | Telephone number of the administrative contact. |
| Umbrella.WHOIS.Regex.billing_contact_organization | String | Organization of the billing contact. |
| Umbrella.WHOIS.Regex.technical_contact_name | String | Name of the technical contact. |
| Umbrella.WHOIS.Regex.administrative_contact_postal_code | String | Postal code of the administrative contact. |
| Umbrella.WHOIS.Regex.zone_contact_country | String | Country of the zone contact. |
| Umbrella.WHOIS.Regex.billing_contact_state | String | State of the billing contact. |
| Umbrella.WHOIS.Regex.audit_updated_date | String | Audit update date. |
| Umbrella.WHOIS.Regex.record_expired | String | Record expired status. |
| Umbrella.WHOIS.Regex.time_of_latest_realtime_check | String | Time of the latest realtime check. |
| Umbrella.WHOIS.Regex.has_raw_text | String | Indicates if there is raw text. |

#### Command example
```!umbrella-get-regex-whois search_field=Email regex=t[a-z]@test.com start="20 days ago"```
#### Context Example
```json
{
    "Umbrella": {
        "WHOIS": {
            "Regex": [
                {
                    "addresses": [
                        "105 adelaide street west, suite 700",
                        "5335 gate parkway",
                        "105 adelaide st. west"
                    ],
                    "administrative_contact_city": "Toronto",
                    "administrative_contact_country": "CANADA",
                    "administrative_contact_email": "test@test.com",
                    "administrative_contact_fax": null,
                    "administrative_contact_fax_ext": "",
                    "administrative_contact_name": "Manish Handa",
                    "administrative_contact_organization": "Northbridge Financial Corporation",
                    "administrative_contact_postal_code": "M5H1P9",
                    "administrative_contact_state": "ON",
                    "administrative_contact_street": [
                        "105 adelaide street west, suite 700"
                    ],
                    "administrative_contact_telephone": "14167861659",
                    "administrative_contact_telephone_ext": "",
                    "audit_updated_date": "2024-07-28 05:58:15 UTC",
                    "billing_contact_city": "Jacksonville",
                    "billing_contact_country": "UNITED STATES",
                    "billing_contact_email": "test@test.com",
                    "billing_contact_fax": "",
                    "billing_contact_fax_ext": "",
                    "billing_contact_name": "Default Contact",
                    "billing_contact_organization": "Network Solutions, LLC",
                    "billing_contact_postal_code": "32256",
                    "billing_contact_state": "FL",
                    "billing_contact_street": [
                        "5335 gate parkway"
                    ],
                    "billing_contact_telephone": "15707088780",
                    "billing_contact_telephone_ext": "",
                    "created": "2024-05-24",
                    "domain_name": "weclaimdifferently.ca",
                    "emails": [
                        "test@test.com",
                        "test@test.com",
                        "test@test.com"
                    ],
                    "expires": "2027-05-24",
                    "has_raw_text": false,
                    "name_servers": [
                        "elias.ns.cloudflare.com",
                        "keira.ns.cloudflare.com"
                    ],
                    "record_expired": false,
                    "registrant_city": "Toronto",
                    "registrant_country": "CANADA",
                    "registrant_email": "test@test.com",
                    "registrant_fax": "18886429675",
                    "registrant_fax_ext": "",
                    "registrant_name": "Northbridge Financial Corporation",
                    "registrant_organization": "Northbridge Financial Corporation",
                    "registrant_postal_code": "M5H1P9",
                    "registrant_state": "ON",
                    "registrant_street": [
                        "105 adelaide st. west"
                    ],
                    "registrant_telephone": "14163504001",
                    "registrant_telephone_ext": "",
                    "registrar_ianaid": "not applicable",
                    "registrar_name": "Network Solutions Canada ULC",
                    "status": [
                        "clientTransferProhibited"
                    ],
                    "technical_contact_city": "Toronto",
                    "technical_contact_country": "CANADA",
                    "technical_contact_email": "test@test.com",
                    "technical_contact_fax": "18886429675",
                    "technical_contact_fax_ext": "",
                    "technical_contact_name": "Manish Handa",
                    "technical_contact_organization": "Northbridge Financial Corporation",
                    "technical_contact_postal_code": "M5H1P9",
                    "technical_contact_state": "ON",
                    "technical_contact_street": [
                        "105 adelaide street west, suite 700"
                    ],
                    "technical_contact_telephone": "14167861659",
                    "technical_contact_telephone_ext": "",
                    "time_of_latest_realtime_check": null,
                    "timestamp": null,
                    "updated": "2024-07-25",
                    "whois_servers": null,
                    "zone_contact_city": "",
                    "zone_contact_country": "",
                    "zone_contact_email": "",
                    "zone_contact_fax": "",
                    "zone_contact_fax_ext": "",
                    "zone_contact_name": "",
                    "zone_contact_organization": "",
                    "zone_contact_postal_code": "",
                    "zone_contact_state": "",
                    "zone_contact_street": [],
                    "zone_contact_telephone": "",
                    "zone_contact_telephone_ext": ""
                },
                {
                    "addresses": [
                        "4431 80th st",
                        "5335 gate parkway",
                        "4431 80th street"
                    ],
                    "administrative_contact_city": "Delta",
                    "administrative_contact_country": "CANADA",
                    "administrative_contact_email": "network@puresunfarms.com",
                    "administrative_contact_fax": null,
                    "administrative_contact_fax_ext": "",
                    "administrative_contact_name": "Marcelo Campos",
                    "administrative_contact_organization": "Pure Sunfarms Corp.",
                    "administrative_contact_postal_code": "V4K3N3",
                    "administrative_contact_state": "BC",
                    "administrative_contact_street": [
                        "4431 80th street"
                    ],
                    "administrative_contact_telephone": "17787148702",
                    "administrative_contact_telephone_ext": "",
                    "audit_updated_date": "2024-07-23 05:03:03 UTC",
                    "billing_contact_city": "Jacksonville",
                    "billing_contact_country": "UNITED STATES",
                    "billing_contact_email": "test@test.com",
                    "billing_contact_fax": "",
                    "billing_contact_fax_ext": "",
                    "billing_contact_name": "Default Contact",
                    "billing_contact_organization": "Network Solutions, LLC",
                    "billing_contact_postal_code": "32256",
                    "billing_contact_state": "FL",
                    "billing_contact_street": [
                        "5335 gate parkway"
                    ],
                    "billing_contact_telephone": "15707088780",
                    "billing_contact_telephone_ext": "",
                    "created": "2024-07-18",
                    "domain_name": "teamhiatus.ca",
                    "emails": [
                        "network@puresunfarms.com",
                        "test@test.com"
                    ],
                    "expires": "2025-07-18",
                    "has_raw_text": false,
                    "name_servers": [
                        "ns49.worldnic.com",
                        "ns50.worldnic.com"
                    ],
                    "record_expired": false,
                    "registrant_city": "Delta",
                    "registrant_country": "CANADA",
                    "registrant_email": "network@puresunfarms.com",
                    "registrant_fax": "18886429675",
                    "registrant_fax_ext": "",
                    "registrant_name": "Michael Stenner",
                    "registrant_organization": "Pure SunFarms Corp.",
                    "registrant_postal_code": "V4K3N3",
                    "registrant_state": "BC",
                    "registrant_street": [
                        "4431 80th st"
                    ],
                    "registrant_telephone": "17787143650",
                    "registrant_telephone_ext": "",
                    "registrar_ianaid": "not applicable",
                    "registrar_name": "Network Solutions Canada ULC",
                    "status": [
                        "addPeriod clientTransferProhibited serverTransferProhibited"
                    ],
                    "technical_contact_city": "Delta",
                    "technical_contact_country": "CANADA",
                    "technical_contact_email": "network@puresunfarms.com",
                    "technical_contact_fax": "18886429675",
                    "technical_contact_fax_ext": "",
                    "technical_contact_name": "Marcelo Campos",
                    "technical_contact_organization": "Pure Sunfarms Corp.",
                    "technical_contact_postal_code": "V4K3N3",
                    "technical_contact_state": "BC",
                    "technical_contact_street": [
                        "4431 80th street"
                    ],
                    "technical_contact_telephone": "17787148702",
                    "technical_contact_telephone_ext": "",
                    "time_of_latest_realtime_check": null,
                    "timestamp": null,
                    "updated": "2024-07-18",
                    "whois_servers": null,
                    "zone_contact_city": "",
                    "zone_contact_country": "",
                    "zone_contact_email": "",
                    "zone_contact_fax": "",
                    "zone_contact_fax_ext": "",
                    "zone_contact_name": "",
                    "zone_contact_organization": "",
                    "zone_contact_postal_code": "",
                    "zone_contact_state": "",
                    "zone_contact_street": [],
                    "zone_contact_telephone": "",
                    "zone_contact_telephone_ext": ""
                },
                {
                    "addresses": [
                        "for sale at domaincollection.com"
                    ],
                    "administrative_contact_city": "",
                    "administrative_contact_country": "",
                    "administrative_contact_email": "",
                    "administrative_contact_fax": null,
                    "administrative_contact_fax_ext": "",
                    "administrative_contact_name": "",
                    "administrative_contact_organization": "",
                    "administrative_contact_postal_code": "",
                    "administrative_contact_state": "",
                    "administrative_contact_street": [],
                    "administrative_contact_telephone": "",
                    "administrative_contact_telephone_ext": "",
                    "audit_updated_date": "2024-07-17 20:10:18 UTC",
                    "billing_contact_city": "",
                    "billing_contact_country": "",
                    "billing_contact_email": "",
                    "billing_contact_fax": "",
                    "billing_contact_fax_ext": "",
                    "billing_contact_name": "",
                    "billing_contact_organization": "",
                    "billing_contact_postal_code": "",
                    "billing_contact_state": "",
                    "billing_contact_street": [],
                    "billing_contact_telephone": "",
                    "billing_contact_telephone_ext": "",
                    "created": "2024-07-16",
                    "domain_name": "imaxen.com",
                    "emails": [
                        "test@test.com"
                    ],
                    "expires": "2025-07-16",
                    "has_raw_text": true,
                    "name_servers": [
                        "a.share-dns.com",
                        "b.share-dns.net"
                    ],
                    "record_expired": false,
                    "registrant_city": "CORAL GABLES",
                    "registrant_country": "UNITED STATES",
                    "registrant_email": "test@test.com",
                    "registrant_fax": "",
                    "registrant_fax_ext": "",
                    "registrant_name": "CAMBRIDGE CAPITAL INVESTMENT LTD.",
                    "registrant_organization": "CAMBRIDGE CAPITAL INVESTMENT LTD.",
                    "registrant_postal_code": "33146",
                    "registrant_state": "FL",
                    "registrant_street": [
                        "for sale at domaincollection.com"
                    ],
                    "registrant_telephone": "13054639709",
                    "registrant_telephone_ext": "",
                    "registrar_ianaid": "3807",
                    "registrar_name": "Alboran Domains LLC",
                    "status": [
                        "ok"
                    ],
                    "technical_contact_city": "",
                    "technical_contact_country": "",
                    "technical_contact_email": "",
                    "technical_contact_fax": "",
                    "technical_contact_fax_ext": "",
                    "technical_contact_name": "",
                    "technical_contact_organization": "",
                    "technical_contact_postal_code": "",
                    "technical_contact_state": "",
                    "technical_contact_street": [],
                    "technical_contact_telephone": "",
                    "technical_contact_telephone_ext": "",
                    "time_of_latest_realtime_check": null,
                    "timestamp": null,
                    "updated": "2024-07-17",
                    "whois_servers": null,
                    "zone_contact_city": "",
                    "zone_contact_country": "",
                    "zone_contact_email": "",
                    "zone_contact_fax": "",
                    "zone_contact_fax_ext": "",
                    "zone_contact_name": "",
                    "zone_contact_organization": "",
                    "zone_contact_postal_code": "",
                    "zone_contact_state": "",
                    "zone_contact_street": [],
                    "zone_contact_telephone": "",
                    "zone_contact_telephone_ext": ""
                }
            ]
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-top-most-seen-domain

***
List the most seen domains in Umbrella. The popularity list contains Cisco Umbrella most queried domains based on passive DNS usage across Umbrella global network. The metric does not only consist of browser-based http requests from users but also takes into account the number of unique client IPs invoking this domain relative to the sum of all requests to all domains. The ranking reflects the domain's relative internet activity agnostic to the invocation protocols and applications where as site ranking models (such as Alexa) focus on the web activity over port 80 (primarily from browsers). In addition, the Umbrella popularity algorithm also applies data normalization techniques to smooth potential biases that may occur due to sampling of DNS usage data.

#### Base Command

`umbrella-get-top-most-seen-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.MostSeenDomain.domain | str | A domain name. |

#### Command example
```!umbrella-get-top-most-seen-domain limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "MostSeenDomain": {
            "domain": "google.com"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-domain-queryvolume

***
List the query volume for a domain over the last 30 days. If there is no information about the domain, Umbrella Investigate returns an empty array. As the query takes time to generate, the last two hours may be blank.

#### Base Command

`umbrella-get-domain-queryvolume`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name. | Required |
| start | Filter for data that appears after this time (within the last 30 days). You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. Default is 1 week ago. | Optional |
| stop | Filter for data that appears before this time (within the last 30 days). You can specify a verbal time or time in ISO 8061 format. For example, 2024-03-26T11:03:18Z or 1 day ago. Default is now. | Optional |
| match | The type of the query volume for the domain. Possible values are: exact, component, all. Default is all. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.QueryVolume.name | Umbrella.QueryVolume.Domain | String |
| Umbrella.QueryVolume.Domain | String | String |
| Umbrella.QueryVolume.Data.StartDate | String | String |
| Umbrella.QueryVolume.Data.StopDate | String | String |
| Umbrella.QueryVolume.QueriesInfo.QueryHour | Umbrella.QueryVolume.Data.QueriesInfo.QueryHour | String |
| Umbrella.QueryVolume.QueriesInfo.Queries | Umbrella.QueryVolume.Data.QueriesInfo.Queries | String |

#### Command example
```!umbrella-get-domain-queryvolume domain=cisco.com```
#### Context Example
```json
{
    "Umbrella": {
        "QueryVolume": {
            "Data": {
                "StartDate": "1 week ago",
                "StopDate": "now"
            },
            "Domain": "cisco.com",
            "QueriesInfo": [
                {
                    "Queries": 25222268,
                    "QueryHour": 1722247200000
                }
            ],
            "name": "cisco.com"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-domain-timeline

***
List the historical tagging timeline for a given domain. Each timeline item includes lists of security category, attack, or threat type associated with the destination. Use the Tagging Timeline endpoint to verify when Umbrella assigned or removed a security category, attack, or threat type. If the current timeline item contains the security category, type of attack, or threat type not found in the previous timeline item, Umbrella updated the current timeline item. If the current timeline item does not contain the security category, attack, or threat type found in the previous timeline item, Umbrella removed the security category, type of attack, or threat type.

#### Base Command

`umbrella-get-domain-timeline`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain. For example, cisco.com. | Required |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.Timeline.Domain | String | An IP, a domain, or a URL. |
| Umbrella.Timeline.Data.MalwareCategories | Unknown | The list of security categories assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.Attacks | Unknown | The list of threats assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.ThreatTypes | Unknown | The list of threat types assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.Timestamp | Number | The date and time of the tagging of the domain, IP, or URL. |

#### Command example
```!umbrella-get-domain-timeline name=maliciouswebsitetest.com limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "Timeline": {
            "Data": [
                {
                    "Attacks": [],
                    "MalwareCategories": [],
                    "ThreatTypes": [],
                    "Timestamp": 1722693276390
                }
            ],
            "Domain": "maliciouswebsitetest.com"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-url-timeline

***
List the historical tagging timeline for RL. Each timeline item includes lists of security category, attack, or threat type associated with the destination. Use the Tagging Timeline endpoint to verify when Umbrella assigned or removed a security category, attack, or threat type. If the current timeline item contains the security category, type of attack, or threat type not found in the previous timeline item, Umbrella updated the current timeline item. If the current timeline item does not contain the security category, attack, or threat type found in the previous timeline item, Umbrella removed the security category, type of attack, or threat type.

#### Base Command

`umbrella-get-url-timeline`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | An URL. For example www.cisco.com. | Required |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.Timeline.URL | String | An URL.  |
| Umbrella.Timeline.Data.MalwareCategories | Unknown | The list of security categories assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.Attacks | Unknown | The list of threats assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.ThreatTypes | Unknown | The list of threat types assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.Timestamp | Number | The date and time of the tagging of the domain, IP, or URL. |

#### Command example
```!umbrella-get-domain-timeline name=www.maliciouswebsitetest.com limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "Timeline": {
            "Data": [
                {
                    "Attacks": [],
                    "MalwareCategories": [],
                    "ThreatTypes": [],
                    "Timestamp": 1722693276390
                }
            ],
            "URL": "www.maliciouswebsitetest.com"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.

### umbrella-get-ip-timeline

***
List the historical tagging timeline for a given IP address. Each timeline item includes lists of security category, attack, or threat type associated with the destination. Use the Tagging Timeline endpoint to verify when Umbrella assigned or removed a security category, attack, or threat type. If the current timeline item contains the security category, type of attack, or threat type not found in the previous timeline item, Umbrella updated the current timeline item. If the current timeline item does not contain the security category, attack, or threat type found in the previous timeline item, Umbrella removed the security category, type of attack, or threat type.

#### Base Command

`umbrella-get-domain-timeline`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | An IP address. For example, 8.8.8.8. | Required |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.Timeline.IP | String | An IP address. For example, 8.8.8.8. |
| Umbrella.Timeline.Data.MalwareCategories | Unknown | The list of security categories assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.Attacks | Unknown | The list of threats assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.ThreatTypes | Unknown | The list of threat types assigned at this date and time on the domain, IP, or URL. |
| Umbrella.Timeline.Data.Timestamp | Number | The date and time of the tagging of the domain, IP, or URL. |

#### Command example
```!umbrella-get-ip-timeline name=8.8.8.8 limit=1```
#### Context Example
```json
{
    "Umbrella": {
        "Timeline": {
            "Data": [
                {
                    "Attacks": [],
                    "MalwareCategories": [],
                    "ThreatTypes": [],
                    "Timestamp": 1722693276390
                }
            ],
            "IP": "8.8.8.8"
        }
    }
}
```

#### Human Readable Output

>Metrics reported successfully.