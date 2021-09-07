# HYAS Insight
HYAS Insight is a threat investigation and attribution solution that uses exclusive data sources and non-traditional mechanisms to improve visibility and productivity for analysts, researchers, and investigators while increasing the accuracy of findings. HYAS Insight connects attack instances and campaigns to billions of indicators of compromise to deliver insights and visibility. With an easy-to-use user interface, transforms, and API access, HYAS Insight combines rich threat data into a powerful research and attribution solution. HYAS Insight is complemented by the HYAS Intelligence team that helps organizations to better understand the nature of the threats they face on a daily basis.

Use the HYAS Insight integration to interactively lookup PassiveDNS, DynamicDNS, WHOIS, Malware Information – either as playbook tasks or through API calls in the War Room.
This integration was integrated and tested with version 1.0.0 of HYAS Insight
## Configure HYAS Insight on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HYAS Insight.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | HYAS Insight Api Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hyas-get-passive-dns-records-by-indicator
***
Returns PassiveDNS records for the provided indicator value.


#### Base Command

`hyas-get-passive-dns-records-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: ipv4, domain. | Required | 
| indicator_value | Indicator value to query. | Required | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.PassiveDNS.count | Number | The passive dns count | 
| HYAS.PassiveDNS.domain | String | The domain of the passive dns information requested | 
| HYAS.PassiveDNS.first_seen | Date | The first time this domain was seen | 
| HYAS.PassiveDNS.ip.geo.city_name | String | City of the ip organization | 
| HYAS.PassiveDNS.ip.geo.country_iso_code | String | Country ISO code of the ip organization | 
| HYAS.PassiveDNS.ip.geo.country_name | String | Country name of the ip organization | 
| HYAS.PassiveDNS.ip.geo.location_latitude | Number | The latitude of the ip organization | 
| HYAS.PassiveDNS.ip.geo.location_longitude | Number | The longitude of the ip organization | 
| HYAS.PassiveDNS.ip.geo.postal_code | String | The longitude of the ip organization | 
| HYAS.PassiveDNS.ip.ip | String | IP of the organization | 
| HYAS.PassiveDNS.ip.isp.autonomous_system_number | String | The ASN of the ip | 
| HYAS.PassiveDNS.ip.isp.autonomous_system_organization | String | The ASO of the ip | 
| HYAS.PassiveDNS.ip.isp.ip_address | String | The IP | 
| HYAS.PassiveDNS.ip.isp.isp | String | The Internet Service Provider | 
| HYAS.PassiveDNS.ip.isp.organization | String | The ISP organization | 
| HYAS.PassiveDNS.ipv4 | String | The ipv4 address of the passive dns record | 
| HYAS.PassiveDNS.last_seen | Date | The last time this domain was seen | 
| HYAS.PassiveDNS.sources | Unknown | A list of pDNS providers which the data came from | 


#### Command Example
```!hyas-get-passive-dns-records-by-indicator indicator_type="domain" indicator_value="domain.org" limit="3"```

#### Context Example
```json
{
    "HYAS": {
        "PassiveDNS": [
            {
                "count": "10571",
                "domain": "domain.org",
                "first_seen": "2019-03-14T23:36:40Z",
                "ip": {
                    "geo": {
                        "city_name": "Cutlerville",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "42.8409",
                        "location_longitude": "-85.6636",
                        "postal_code": "12345"
                    },
                    "ip": "",
                    "isp": {
                        "autonomous_system_number": "AS12345",
                        "autonomous_system_organization": "System LLX",
                        "ip_address": "",
                        "isp": "System LLX",
                        "organization": "System LLX"
                    }
                },
                "ipv4": "",
                "last_seen": "2021-07-16T15:29:13.033000Z",
                "sources": [
                    "hyas",
                    "farsight"
                ]
            },
            {
                "count": "151",
                "domain": "domain.org",
                "first_seen": "2011-08-02T12:15:17Z",
                "ip": {
                    "geo": {
                        "city_name": "Chicago",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "41.8500",
                        "location_longitude": "-87.6500",
                        "postal_code": "60666"
                    },
                    "ip": "",
                    "isp": {
                        "autonomous_system_number": "AS12345",
                        "autonomous_system_organization": "System LLX",
                        "ip_address": "",
                        "isp": "System LLX",
                        "organization": "System LLX"
                    }
                },
                "ipv4": "",
                "last_seen": "2012-06-18T08:36:11Z",
                "sources": [
                    "farsight"
                ]
            },
            {
                "count": "7439",
                "domain": "domain.org",
                "first_seen": "2014-04-08T03:30:41Z",
                "ip": {
                    "geo": {
                        "city_name": "Denver",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "39.7392",
                        "location_longitude": "-104.9847",
                        "postal_code": "80208"
                    },
                    "ip": "",
                    "isp": {
                        "autonomous_system_number": "AS46606",
                        "autonomous_system_organization": "Unified Layer",
                        "ip_address": "",
                        "isp": "Unified Layer",
                        "organization": "Unified Layer"
                    }
                },
                "ipv4": "",
                "last_seen": "2018-11-25T08:06:47Z",
                "sources": [
                    "farsight"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS PassiveDNS records for domain : domain.org
>|Count|Domain|First seen|City Name|Country Code|Country Name|Latitude|Longitude|Postal Code|IP|ISP ASN|ISP ASN Organization|ISP IP Address|ISP|ISP Organization|IPV4|Last Seen|Sources|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 10571 | domain.org | 2019-03-14T23:36:40Z | Cutlerville | US | United States | 42.8409 | -85.6636 | 12345 |  | AS12345 | System LLX |  | System LLX | System LLX |  | 2021-07-16T15:29:13.033000Z | hyas,<br/>farsight |
>| 151 | domain.org | 2011-08-02T12:15:17Z | Chicago | US | United States | 41.8500 | -87.6500 | 60666 |  | AS12345 | System LLX |  | System LLX | System LLX |  | 2012-06-18T08:36:11Z | farsight |
>| 7439 | domain.org | 2014-04-08T03:30:41Z | Denver | US | United States | 39.7392 | -104.9847 | 80208 |  | AS46606 | Unified Layer |  | Unified Layer | Unified Layer |  | 2018-11-25T08:06:47Z | farsight |


### hyas-get-dynamic-dns-records-by-indicator
***
Returns DynamicDNS records for the provided indicator value.


#### Base Command

`hyas-get-dynamic-dns-records-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: ip, domain, email. | Required | 
| indicator_value | Indicator value to query. | Required | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.DynamicDNS.a_record | String | The A record for the domain | 
| HYAS.DynamicDNS.account | String | The account holder name | 
| HYAS.DynamicDNS.created | Date | The date which the domain was created | 
| HYAS.DynamicDNS.created_ip | String | The ip address of the account holder | 
| HYAS.DynamicDNS.domain | String | The domain associated with the dynamic dns information | 
| HYAS.DynamicDNS.domain_creator_ip | String | The ip address of the domain creator | 
| HYAS.DynamicDNS.email | String | The email address connected to the domain | 


#### Command Example
```!hyas-get-dynamic-dns-records-by-indicator indicator_type="ip" indicator_value="4.4.4.4" limit="3"```

#### Context Example
```json
{
    "HYAS": {
        "DynamicDNS": [
            {
                "a_record": "4.4.4.4",
                "account": "free",
                "created": "2019-03-30T14:39:49Z",
                "created_ip": "",
                "domain": "domain.org",
                "domain_creator_ip": "",
                "email": ""
            },
            {
                "a_record": "4.4.4.4",
                "account": "free",
                "created": "2020-05-09T03:39:28Z",
                "created_ip": "",
                "domain": "domain.org",
                "domain_creator_ip": "",
                "email": ""
            },
            {
                "a_record": "4.4.4.4",
                "account": "free",
                "created": "2020-05-09T03:39:24Z",
                "created_ip": "",
                "domain": "bensonwonghk.duckdns.org",
                "domain_creator_ip": "",
                "email": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS DynamicDNS records for ip : 4.4.4.4
>|A Record|Account|Created Date|Account Holder IP Address|Domain|Domain Creator IP Address|Email Address|
>|---|---|---|---|---|---|---|
>| 4.4.4.4 | free | 2019-03-30T14:39:49Z |  | domain.org |  |  |
>| 4.4.4.4 | free | 2020-05-09T03:39:28Z |  | domain.org |  |  |
>| 4.4.4.4 | free | 2020-05-09T03:39:24Z |  | bensonwonghk.duckdns.org | |  |


### hyas-get-whois-records-by-indicator
***
Returns WHOIS records for the provided indicator value.


#### Base Command

`hyas-get-whois-records-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: domain, email, phone. | Required | 
| indicator_value | Indicator value to query. | Required | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.WHOIS.address | Unknown | address | 
| HYAS.WHOIS.city | Unknown | city | 
| HYAS.WHOIS.country | Unknown | country | 
| HYAS.WHOIS.domain | String | The domain of the registrant | 
| HYAS.WHOIS.domain_2tld | String | The second-level domain of the registrant | 
| HYAS.WHOIS.domain_created_datetime | Date | The date and time when the whois record was created | 
| HYAS.WHOIS.domain_expires_datetime | Date | The date and time when the whois record expires | 
| HYAS.WHOIS.domain_updated_datetime | Date | The date and time when the whois record was last updated | 
| HYAS.WHOIS.email | Unknown | email | 
| HYAS.WHOIS.idn_name | String | The international domain name | 
| HYAS.WHOIS.nameserver | Unknown | nameserver | 
| HYAS.WHOIS.phone.phone | String | The phone number registrant contact in e164 format | 
| HYAS.WHOIS.phone.phone_info.carrier | String | Phone number carrier | 
| HYAS.WHOIS.phone.phone_info.country | String | Phone number country | 
| HYAS.WHOIS.phone.phone_info.geo | String | Phone number geo. Can be city, province, region or country | 
| HYAS.WHOIS.privacy_punch | Boolean | True if this record has additional information bypassing privacy protect | 
| HYAS.WHOIS.registrar | String | The domain registrar | 


#### Command Example
```!hyas-get-whois-records-by-indicator indicator_type="domain" indicator_value="domain.net" limit="3"```

#### Context Example
```json
{
    "HYAS": {
        "WHOIS": [
            {
                "address": [],
                "city": [
                    "ha noi"
                ],
                "country": [],
                "domain": "domain.net",
                "domain_2tld": "None",
                "domain_created_datetime": "2015-05-22T00:00:00Z",
                "domain_expires_datetime": "2016-05-22T00:00:00Z",
                "domain_updated_datetime": "2017-06-14T19:06:36.577650Z",
                "email": [
                    "ngoc.mycomputer@gmail.com"
                ],
                "idn_name": "None",
                "nameserver": [
                    "ns2.inet.vn",
                    "ns1.inet.vn"
                ],
                "phone": [
                    {
                        "phone": "+123456789123",
                        "phone_info": {
                            "carrier": "Viettel",
                            "country": "Vietnam",
                            "geo": "Vietnam"
                        }
                    }
                ],
                "privacy_punch": false,
                "registrar": "onlinenic, inc."
            },
            {
                "address": [],
                "city": [
                    "hcm"
                ],
                "country": [
                    "VN"
                ],
                "domain": "domain.net",
                "domain_2tld": "None",
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": "2019-10-31T01:09:53.933724Z",
                "email": [
                    "",
                    "abuse-contact@publicdomainregistry.com"
                ],
                "idn_name": "None",
                "nameserver": [
                    "viendong.mars.orderbox-dns.com",
                    "viendong.venus.orderbox-dns.com",
                    "viendong.earth.orderbox-dns.com",
                    "viendong.mercury.orderbox-dns.com"
                ],
                "phone": [
                    {
                        "phone": "+84909095309",
                        "phone_info": {
                            "carrier": "MobiFone",
                            "country": "Vietnam",
                            "geo": "Vietnam"
                        }
                    }
                ],
                "privacy_punch": false,
                "registrar": "pdr ltd. d/b/a publicdomainregistry.comvien dong co., ltd."
            },
            {
                "address": [
                    "32 duong 885 kp 5 tt ba tri",
                    "vn"
                ],
                "city": [
                    "hcm"
                ],
                "country": [
                    "VN"
                ],
                "domain": "domain.net",
                "domain_2tld": "domain.net",
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": "None",
                "email": [
                    "",
                    "dns@cloudflare.com"
                ],
                "idn_name": "None",
                "nameserver": [],
                "phone": [
                    {
                        "phone": "+84909095309",
                        "phone_info": {
                            "carrier": "MobiFone",
                            "country": "Vietnam",
                            "geo": "Vietnam"
                        }
                    }
                ],
                "privacy_punch": true,
                "registrar": "pdr ltd. d/b/a publicdomainregistry.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS WHOIS records for domain : domain.net
>|Address|City|Country|Domain|Domain_2tld|Domain Created Time|Domain Expires Time|Domain Updated Time|Email Address|IDN Name|Nameserver|Phone Info|Privacy_punch|Registrar|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | ha noi |  | domain.net | None | 2015-05-22T00:00:00Z | 2016-05-22T00:00:00Z | 2017-06-14T19:06:36.577650Z | ngoc.mycomputer@gmail.com | None | ns2.inet.vn,<br/>ns1.inet.vn | {'phone': '+123456789123', 'phone_info': {'carrier': 'Viettel', 'country': 'Vietnam', 'geo': 'Vietnam'}} | false | onlinenic, inc. |
>|  | hcm | VN | domain.net | None | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | 2019-10-31T01:09:53.933724Z | "",<br/>abuse-contact@publicdomainregistry.com | None | viendong.mars.orderbox-dns.com,<br/>viendong.venus.orderbox-dns.com,<br/>viendong.earth.orderbox-dns.com,<br/>viendong.mercury.orderbox-dns.com | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | false | pdr ltd. d/b/a publicdomainregistry.comvien dong co., ltd. |
>| 32 duong 885 kp 5 tt ba tri,<br/>vn | hcm | VN | domain.net | domain.net | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | None | "",<br/>dns@cloudflare.com | None |  | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | true | pdr ltd. d/b/a publicdomainregistry.com |


### hyas-get-whois-current-records-by-domain
***
Returns WHOIS Current records for the provided indicator value.


#### Base Command

`hyas-get-whois-current-records-by-domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.WHOISCurrent.abuse_emails | Unknown | abuse emails | 
| HYAS.WHOISCurrent.address | Unknown | address | 
| HYAS.WHOISCurrent.city | Unknown | city | 
| HYAS.WHOISCurrent.country | Unknown | country | 
| HYAS.WHOISCurrent.domain | String | The domain of the registrant | 
| HYAS.WHOISCurrent.domain_2tld | String | The second-level domain of the registrant | 
| HYAS.WHOISCurrent.domain_created_datetime | Date | The date and time when the whois record was created | 
| HYAS.WHOISCurrent.domain_expires_datetime | Date | The date and time when the whois record expires | 
| HYAS.WHOISCurrent.domain_updated_datetime | Date | The date and time when the whois record was last updated | 
| HYAS.WHOISCurrent.email | Unknown | email | 
| HYAS.WHOISCurrent.idn_name | String | The international domain name | 
| HYAS.WHOISCurrent.nameserver | Unknown | nameserver | 
| HYAS.WHOISCurrent.organization | Unknown | organization | 
| HYAS.WHOISCurrent.phone | Unknown | The phone number | 
| HYAS.WHOISCurrent.registrar | String | The domain registrar | 
| HYAS.WHOISCurrent.state | Unknown | The state | 


#### Command Example
```!hyas-get-whois-current-records-by-domain domain="www.hyas.com"```

#### Context Example
```json
{
    "HYAS": {
        "WHOISCurrent": {
            "abuse_emails": [
                ""
            ],
            "address": [],
            "city": [],
            "country": [
                "Canada"
            ],
            "domain": "hyas.com",
            "domain_2tld": "hyas.com",
            "domain_created_datetime": "2001-05-01T23:42:14",
            "domain_expires_datetime": "2026-05-01T23:42:14",
            "domain_updated_datetime": "2020-06-30T15:43:39",
            "email": [],
            "idn_name": "None",
            "nameserver": [
                "n1.domaincontrol.com",
                "n2.domaincontrol.com"
            ],
            "organization": [
                "HYAS Infosec Inc."
            ],
            "phone": [],
            "registrar": "GoDaddy.com, LLC",
            "state": [
                "British Columbia"
            ]
        }
    }
}
```

#### Human Readable Output

>### HYAS WHOISCurrent records for domain : www.hyas.com
>|Abuse Emails|Address|City|Country|Domain|Domain_2tld|Domain Created Time|Domain Expires Time|Domain Updated Time|Email Address|IDN Name|Nameserver|Organization|Phone Info|Registrar|State|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  | Canada | hyas.com | hyas.com | 2001-05-01T23:42:14 | 2026-05-01T23:42:14 | 2020-06-30T15:43:39 |  | None | n1.domaincontrol.com,<br/>n2.domaincontrol.com | HYAS Infosec Inc. |  | GoDaddy.com, LLC | British Columbia |


### hyas-get-malware-samples-records-by-indicator
***
Returns Malware Sample records for the provided indicator value.


#### Base Command

`hyas-get-malware-samples-records-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: domain, ipv4, md5. | Required | 
| indicator_value | Indicator value to query. | Required | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.MalwareSamples.datetime | Date | The date which the sample was processed | 
| HYAS.MalwareSamples.domain | String | The domain of the sample | 
| HYAS.MalwareSamples.ipv4 | String | The ipv4 of the sample | 
| HYAS.MalwareSamples.ipv6 | String | The ipv6 of the sample | 
| HYAS.MalwareSamples.md5 | String | The md5 of the sample | 
| HYAS.MalwareSamples.sha1 | String | The sha1  of the sample | 
| HYAS.MalwareSamples.sha256 | String | The sha256 of the sample | 


#### Command Example
```!hyas-get-malware-samples-records-by-indicator indicator_type="domain" indicator_value="butterfly.bigmoney.biz" limit="3"```

#### Context Example
```json
{
    "HYAS": {
        "MalwareSamples": [
            {
                "datetime": "2021-06-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "",
                "ipv6": null,
                "md5": "f8e537c178999f4ab1609576c6f5751e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2021-05-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "",
                "ipv6": null,
                "md5": "5fb3ee62c7bd0d801d76e272f51fe137",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2021-05-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "",
                "ipv6": null,
                "md5": "a20473e3a24c52ac3d89d7489b500189",
                "sha1": null,
                "sha256": null
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS MalwareSamples records for domain : butterfly.bigmoney.biz
>|Datetime|Domain|IPV4 Address|IPV6 Address|MD5 Value|SHA1 Value|SHA256 Value|
>|---|---|---|---|---|---|---|
>| 2021-06-03 | butterfly.bigmoney.biz |  | None | f8e537c178999f4ab1609576c6f5751e | None | None |
>| 2021-05-18 | butterfly.bigmoney.biz |  | None | 5fb3ee62c7bd0d801d76e272f51fe137 | None | None |
>| 2021-05-18 | butterfly.bigmoney.biz |  | None | a20473e3a24c52ac3d89d7489b500189 | None | None |


### hyas-get-associated-ips-by-hash
***
Returns associated IP's for the provided hash value.


#### Base Command

`hyas-get-associated-ips-by-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | The md5 value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.HASH-IP.md5 | String | The provided MD5 value | 
| HYAS.HASH-IP.ips | String | Associated IPS  for the provided MD5 value | 


#### Command Example
```!hyas-get-associated-ips-by-hash md5="1d0a97c41afe5540edd0a8c1fb9a0f2d"```

#### Context Example
```json
{
    "HYAS": {
        "HASH-IP": {
            "ips": [
                "106.187.43.98"
            ],
            "md5": "1d0a97c41afe5540edd0a8c1fb9a0f2d"
        }
    }
}
```

#### Human Readable Output

>### HYAS HASH-IP records for md5 : 1d0a97c41afe5540edd0a8c1fb9a0f2d
>|Associated IPs|
>|---|
>| 106.187.43.98 |


### hyas-get-associated-domains-by-hash
***
Returns associated Domain's for the provided hash value.


#### Base Command

`hyas-get-associated-domains-by-hash`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| md5 | The md5 value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.HASH-DOMAIN.domains | String | Associated Domains for the provided MD5 value | 
| HYAS.HASH-DOMAIN.md5 | String | The provided MD5 value | 


#### Command Example
```!hyas-get-associated-domains-by-hash md5="1d0a97c41afe5540edd0a8c1fb9a0f2d"```

#### Context Example
```json
{
    "HYAS": {
        "HASH-DOMAIN": {
            "domains": [
                "domain.es",
                "qwertasdfg.sinip.es",
                "butterfly.bigmoney.biz"
            ],
            "md5": "1d0a97c41afe5540edd0a8c1fb9a0f2d"
        }
    }
}
```

#### Human Readable Output

>### HYAS HASH-DOMAIN records for md5 : 1d0a97c41afe5540edd0a8c1fb9a0f2d
>|Associated Domains|
>|---|
>| domain.es |
>| qwertasdfg.sinip.es |
>| butterfly.bigmoney.biz |

