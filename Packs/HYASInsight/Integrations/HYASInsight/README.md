# HYAS Insight
HYAS Insight is a threat investigation and attribution solution that uses exclusive data sources and non-traditional mechanisms to improve visibility and productivity for analysts, researchers, and investigators while increasing the accuracy of findings. HYAS Insight connects attack instances and campaigns to billions of indicators of compromise to deliver insights and visibility. With an easy-to-use user interface, transforms, and API access, HYAS Insight combines rich threat data into a powerful research and attribution solution. HYAS Insight is complemented by the HYAS Intelligence team that helps organizations to better understand the nature of the threats they face on a daily basis.

Use the HYAS Insight integration to interactively lookup PassiveDNS, DynamicDNS, WHOIS, Malware and C2 Attribution Information.

## How to get a HYAS API Key
In order to obtain a HYAS Insight API key to use with Cortex XSOAR, please contact your HYAS Insight Admin. If you are unsure who your Admin is, you can also contact HYAS Support via email at support@hyas.com, by visiting the HYAS website https://www.hyas.com/contact, or by using the HYAS Insight web UI by clicking the ‘help’ icon at the top right of the screen, to request a key.

## Partner Contributed Integration
### Integration Author: HYAS
Support and maintenance for this integration are provided by the author. Please use the following contact details:
    **Email:** support@hyas.com
    **URL:** https://www.hyas.com/contact

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
                "count": "273983",
                "domain": "domain.org",
                "first_seen": "2015-06-08T19:16:18Z",
                "ip": {
                    "geo": {
                        "city_name": "Boston",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "42.3584",
                        "location_longitude": "-71.0598",
                        "postal_code": "02108"
                    },
                    "ip": "65.254.244.180",
                    "isp": {
                        "autonomous_system_number": "AS29873",
                        "autonomous_system_organization": "Newfold Digital, Inc.",
                        "ip_address": "65.254.244.180",
                        "isp": "Newfold Digital, Inc.",
                        "organization": "Newfold Digital, Inc."
                    }
                },
                "ipv4": "65.254.244.180",
                "last_seen": "2021-11-08T22:39:59Z",
                "sources": [
                    "farsight"
                ]
            },
            {
                "count": "62645",
                "domain": "domain.org",
                "first_seen": "2010-07-13T17:29:58Z",
                "ip": {
                    "geo": {
                        "city_name": "Tukwila",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "47.4740",
                        "location_longitude": "-122.2610",
                        "postal_code": "98178"
                    },
                    "ip": "216.34.94.184",
                    "isp": {
                        "autonomous_system_number": "AS3561",
                        "autonomous_system_organization": "CenturyLink Communications, LLC",
                        "ip_address": "216.34.94.184",
                        "isp": "Dotster, Inc.",
                        "organization": "Dotster, Inc."
                    }
                },
                "ipv4": "216.34.94.184",
                "last_seen": "2015-06-08T17:50:06Z",
                "sources": [
                    "farsight"
                ]
            },
            {
                "count": "1",
                "domain": "biszhu.com.domain.org",
                "first_seen": "2017-09-05T00:00:00Z",
                "ip": {
                    "geo": {
                        "city_name": "Boston",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "42.3584",
                        "location_longitude": "-71.0598",
                        "postal_code": "02108"
                    },
                    "ip": "65.254.244.180",
                    "isp": {
                        "autonomous_system_number": "AS29873",
                        "autonomous_system_organization": "Newfold Digital, Inc.",
                        "ip_address": "65.254.244.180",
                        "isp": "Newfold Digital, Inc.",
                        "organization": "Newfold Digital, Inc."
                    }
                },
                "ipv4": "65.254.244.180",
                "last_seen": "2017-09-05T00:00:00Z",
                "sources": [
                    "zetalytics"
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
>| 273983 | domain.org | 2015-06-08T19:16:18Z | Boston | US | United States | 42.3584 | -71.0598 | 02108 | 65.254.244.180 | AS29873 | Newfold Digital, Inc. | 65.254.244.180 | Newfold Digital, Inc. | Newfold Digital, Inc. | 65.254.244.180 | 2021-11-08T22:39:59Z | farsight |
>| 62645 | domain.org | 2010-07-13T17:29:58Z | Tukwila | US | United States | 47.4740 | -122.2610 | 98178 | 216.34.94.184 | AS3561 | CenturyLink Communications, LLC | 216.34.94.184 | Dotster, Inc. | Dotster, Inc. | 216.34.94.184 | 2015-06-08T17:50:06Z | farsight |
>| 1 | biszhu.com.domain.org | 2017-09-05T00:00:00Z | Boston | US | United States | 42.3584 | -71.0598 | 02108 | 65.254.244.180 | AS29873 | Newfold Digital, Inc. | 65.254.244.180 | Newfold Digital, Inc. | Newfold Digital, Inc. | 65.254.244.180 | 2017-09-05T00:00:00Z | zetalytics |


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
                "created_ip": "78.191.27.210",
                "domain": "seyir.duckdns.org",
                "domain_creator_ip": "78.191.25.0",
                "email": "halbayrak75@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "account": "free",
                "created": "2020-05-09T03:39:28Z",
                "created_ip": "42.3.24.108",
                "domain": "tempoary.duckdns.org",
                "domain_creator_ip": "42.3.24.36",
                "email": "benson877204@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "account": "free",
                "created": "2020-05-09T03:39:24Z",
                "created_ip": "42.3.24.108",
                "domain": "bensonwonghk.duckdns.org",
                "domain_creator_ip": "42.3.24.108",
                "email": "benson877204@gmail.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS DynamicDNS records for ip : 4.4.4.4
>|A Record|Account|Created Date|Account Holder IP Address|Domain|Domain Creator IP Address|Email Address|
>|---|---|---|---|---|---|---|
>| 4.4.4.4 | free | 2019-03-30T14:39:49Z | 78.191.27.210 | seyir.duckdns.org | 78.191.25.0 | halbayrak75@gmail.com |
>| 4.4.4.4 | free | 2020-05-09T03:39:28Z | 42.3.24.108 | tempoary.duckdns.org | 42.3.24.36 | benson877204@gmail.com |
>| 4.4.4.4 | free | 2020-05-09T03:39:24Z | 42.3.24.108 | bensonwonghk.duckdns.org | 42.3.24.108 | benson877204@gmail.com |


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
```!hyas-get-whois-records-by-indicator indicator_type="domain" indicator_value="dulieuonline.net" limit="3"```

#### Context Example
```json
{
    "HYAS": {
        "WHOIS": [
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
                "domain": "dulieuonline.net",
                "domain_2tld": "dulieuonline.net",
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": "None",
                "email": [
                    "viendongonline@gmail.com",
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
            },
            {
                "address": [],
                "city": [
                    "hcm"
                ],
                "country": [
                    "VN"
                ],
                "domain": "dulieuonline.net",
                "domain_2tld": "None",
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": "2019-10-30T06:23:09.543083Z",
                "email": [
                    "viendongonline@gmail.com",
                    "hostmaster@dulieuonline.net"
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
                "registrar": "pdrltd.d/b/apublicdomainregistry.com"
            },
            {
                "address": [],
                "city": [
                    "hcm"
                ],
                "country": [
                    "VN"
                ],
                "domain": "dulieuonline.net",
                "domain_2tld": "None",
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": "2019-10-31T09:04:17.873274Z",
                "email": [
                    "viendongonline@gmail.com"
                ],
                "idn_name": "None",
                "nameserver": [
                    "viendong.mars.orderbox-dns.com",
                    "viendong.venus.orderbox-dns.com",
                    "viendong.mercury.orderbox-dns.com",
                    "viendong.earth.orderbox-dns.com"
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
                "registrar": "pdr ltd. d/b/a publicdomainregistry.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS WHOIS records for domain : dulieuonline.net
>|Address|City|Country|Domain|Domain_2tld|Domain Created Time|Domain Expires Time|Domain Updated Time|Email Address|IDN Name|Nameserver|Phone Info|Privacy_punch|Registrar|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 32 duong 885 kp 5 tt ba tri,<br/>vn | hcm | VN | dulieuonline.net | dulieuonline.net | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | None | viendongonline@gmail.com,<br/>dns@cloudflare.com | None |  | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | true | pdr ltd. d/b/a publicdomainregistry.com |
>|  | hcm | VN | dulieuonline.net | None | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | 2019-10-30T06:23:09.543083Z | viendongonline@gmail.com,<br/>hostmaster@dulieuonline.net | None |  | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | true | pdrltd.d/b/apublicdomainregistry.com |
>|  | hcm | VN | dulieuonline.net | None | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | 2019-10-31T09:04:17.873274Z | viendongonline@gmail.com | None | viendong.mars.orderbox-dns.com,<br/>viendong.venus.orderbox-dns.com,<br/>viendong.mercury.orderbox-dns.com,<br/>viendong.earth.orderbox-dns.com | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | false | pdr ltd. d/b/a publicdomainregistry.com |


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
                "abuse@godaddy.com"
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
            "domain_updated_datetime": "2020-06-30T22:43:34",
            "email": [],
            "idn_name": "146",
            "nameserver": [
                "ns09.domaincontrol.com",
                "ns10.domaincontrol.com"
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
>|Abuse Emails|Country|Domain|Domain_2tld|Domain Created Time|Domain Expires Time|Domain Updated Time|IDN Name|Nameserver|Organization|Registrar|State|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| abuse@godaddy.com | Canada | hyas.com | hyas.com | 2001-05-01T23:42:14 | 2026-05-01T23:42:14 | 2020-06-30T22:43:34 | 146 | ns09.domaincontrol.com,<br/>ns10.domaincontrol.com | HYAS Infosec Inc. | GoDaddy.com, LLC | British Columbia |


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
                "datetime": "2021-11-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": "None",
                "md5": "d3a107934774f288481a66d6a4c6b3f3",
                "sha1": "None",
                "sha256": "None"
            },
            {
                "datetime": "2021-11-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": "None",
                "md5": "af73babf3276037b2d662fda0e3e40b3",
                "sha1": "None",
                "sha256": "None"
            },
            {
                "datetime": "2021-11-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": "None",
                "md5": "70d72fcb14219b3c4649b9b7cc14afa0",
                "sha1": "None",
                "sha256": "None"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS MalwareSamples records for domain : butterfly.bigmoney.biz
>|Datetime|Domain|IPV4 Address|IPV6 Address|MD5 Value|SHA1 Value|SHA256 Value|
>|---|---|---|---|---|---|---|
>| 2021-11-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | d3a107934774f288481a66d6a4c6b3f3 | None | None |
>| 2021-11-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | af73babf3276037b2d662fda0e3e40b3 | None | None |
>| 2021-11-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | 70d72fcb14219b3c4649b9b7cc14afa0 | None | None |


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
| HYAS.HASH-IP.ips | Unknown | Associated IPS for the provided MD5 value | 


#### Command Example
```!hyas-get-associated-ips-by-hash md5="1d0a97c41afe5540edd0a8c1fb9a0f1c"```

#### Context Example
```json
{
    "HYAS": {
        "HASH-IP": {
            "ips": [
                "106.187.43.98"
            ],
            "md5": "1d0a97c41afe5540edd0a8c1fb9a0f1c"
        }
    }
}
```

#### Human Readable Output

>### HYAS HASH-IP records for md5 : 1d0a97c41afe5540edd0a8c1fb9a0f1c
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
| HYAS.HASH-DOMAIN.domains | Unknown | Associated Domains for the provided MD5 value | 
| HYAS.HASH-DOMAIN.md5 | String | The provided MD5 value | 


#### Command Example
```!hyas-get-associated-domains-by-hash md5="1d0a97c41afe5540edd0a8c1fb9a0f1c"```

#### Context Example
```json
{
    "HYAS": {
        "HASH-DOMAIN": {
            "domains": [
                "butterfly.sinip.es",
                "qwertasdfg.sinip.es",
                "butterfly.bigmoney.biz"
            ],
            "md5": "1d0a97c41afe5540edd0a8c1fb9a0f1c"
        }
    }
}
```

#### Human Readable Output

>### HYAS HASH-DOMAIN records for md5 : 1d0a97c41afe5540edd0a8c1fb9a0f1c
>|Associated Domains|
>|---|
>| butterfly.sinip.es |
>| qwertasdfg.sinip.es |
>| butterfly.bigmoney.biz |


### hyas-get-c2attribution-records-by-indicator
***
Return C2 Attribution records for the provided indicator value.


#### Base Command

`hyas-get-c2attribution-records-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: ip, domain, sha256, email. | Required | 
| indicator_value | Indicator Value. | Required | 
| limit | The maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.C2_Attribution.actor_ipv4 | String | The actor ipv4 | 
| HYAS.C2_Attribution.c2_domain | String | The c2 domain | 
| HYAS.C2_Attribution.c2_ip | String | The c2 ip | 
| HYAS.C2_Attribution.c2_url | String | The C2 panel url | 
| HYAS.C2_Attribution.datetime | String | C2 Attribution datetime | 
| HYAS.C2_Attribution.email | String | The actor email | 
| HYAS.C2_Attribution.email_domain | String | The email domain | 
| HYAS.C2_Attribution.referrer_domain | String | The referrer domain | 
| HYAS.C2_Attribution.referrer_ipv4 | String | The referrer ipv4 | 
| HYAS.C2_Attribution.referrer_url | String | The referrer url | 
| HYAS.C2_Attribution.sha256 | String | The sha256 malware hash | 


#### Command Example
```!hyas-get-c2attribution-records-by-indicator indicator_type=domain indicator_value=himionsa.com limit=3```

#### Context Example
```json
{
    "HYAS": {
        "C2_Attribution": [
            {
                "actor_ipv4": "197.210.53.224",
                "c2_domain": "himionsa.com",
                "c2_ip": "89.208.229.55",
                "c2_url": "http://himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report",
                "datetime": "2020-02-21T10:16:06Z",
                "email": "None",
                "email_domain": "None",
                "referrer_domain": "None",
                "referrer_ipv4": "None",
                "referrer_url": "None",
                "sha256": "None"
            },
            {
                "actor_ipv4": "197.210.84.26",
                "c2_domain": "himionsa.com",
                "c2_ip": "89.208.229.55",
                "c2_url": "http://himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report",
                "datetime": "2020-02-20T13:08:36Z",
                "email": "None",
                "email_domain": "None",
                "referrer_domain": "None",
                "referrer_ipv4": "None",
                "referrer_url": "None",
                "sha256": "None"
            },
            {
                "actor_ipv4": "197.210.53.79",
                "c2_domain": "himionsa.com",
                "c2_ip": "89.208.229.55",
                "c2_url": "http://himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report",
                "datetime": "2020-02-21T09:03:46Z",
                "email": "None",
                "email_domain": "None",
                "referrer_domain": "None",
                "referrer_ipv4": "None",
                "referrer_url": "None",
                "sha256": "None"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS C2_Attribution records for domain : himionsa.com
>|Actor IPv4|C2 Domain|C2 IP|C2 URL|Datetime|Email|Email Domain|Referrer Domain|Referrer IPv4|Referrer URL|SHA256|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 197.210.53.224 | himionsa.com | 89.208.229.55 | http:<span>//</span>himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report | 2020-02-21T10:16:06Z | None | None | None | None | None | None |
>| 197.210.84.26 | himionsa.com | 89.208.229.55 | http:<span>//</span>himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report | 2020-02-20T13:08:36Z | None | None | None | None | None | None |
>| 197.210.53.79 | himionsa.com | 89.208.229.55 | http:<span>//</span>himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report | 2020-02-21T09:03:46Z | None | None | None | None | None | None |

