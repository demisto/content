# HYAS Insight

HYAS Insight is a threat investigation and attribution solution that uses exclusive data sources and non-traditional mechanisms to improve visibility and productivity for analysts, researchers, and investigators while increasing the accuracy of findings. HYAS Insight connects attack instances and campaigns to billions of indicators of compromise to deliver insights and visibility. With an easy-to-use user interface, transforms, and API access, HYAS Insight combines rich threat data into a powerful research and attribution solution. HYAS Insight is complemented by the HYAS Intelligence team that helps organizations to better understand the nature of the threats they face on a daily basis.

Use the HYAS Insight integration to interactively lookup  PassiveDNS, DynamicDNS, WHOIS, Sample Malware Records, C2 Attribution, Passive Hash, SSL Certificate, Open Source Indicators, Device Geo, Sinkhole, Malware Sample Information.

## How to get a HYAS API Key
In order to obtain a HYAS Insight API key to use with Cortex XSOAR, please contact your HYAS Insight Admin. If you are unsure who your Admin is, you can also contact HYAS Support via email at support@hyas.com, by visiting the HYAS website https://www.hyas.com/contact, or by using the HYAS Insight web UI by clicking the ‘help’ icon at the top right of the screen, to request a key.

## Partner Contributed Integration
### Integration Author: HYAS
Support and maintenance for this integration are provided by the author. Please use the following contact details:
    **Email:** support@hyas.com
    **URL:** https://support.hyas.com
## Configure HYASInsight in Cortex


| **Parameter** | **Required** |
| --- | --- |
| HYAS Insight Api Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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

#### Command example
```!hyas-get-passive-dns-records-by-indicator indicator_type="domain" indicator_value="domain.org" limit="3"```
#### Context Example
```json
{
    "HYAS": {
        "PassiveDNS": [
            {
                "count": 310833,
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
                "last_seen": "2023-06-30T02:05:29Z",
                "sources": [
                    "hyas",
                    "farsight"
                ]
            },
            {
                "count": 62645,
                "domain": "domain.org",
                "first_seen": "2010-07-13T17:29:58Z",
                "ip": {
                    "geo": {
                        "city_name": "Seattle",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "47.6062",
                        "location_longitude": "-122.3321",
                        "postal_code": "98101"
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
                "count": 1,
                "domain": "'.domain.org",
                "first_seen": "2011-02-17T11:17:10Z",
                "ip": {
                    "geo": {
                        "city_name": "Seattle",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "47.6062",
                        "location_longitude": "-122.3321",
                        "postal_code": "98101"
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
                "last_seen": "2011-02-17T11:17:10Z",
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
>| 310833 | domain.org | 2015-06-08T19:16:18Z | Boston | US | United States | 42.3584 | -71.0598 | 02108 | 65.254.244.180 | AS29873 | Newfold Digital, Inc. | 65.254.244.180 | Newfold Digital, Inc. | Newfold Digital, Inc. | 65.254.244.180 | 2023-06-30T02:05:29Z | hyas,<br/>farsight |
>| 62645 | domain.org | 2010-07-13T17:29:58Z | Seattle | US | United States | 47.6062 | -122.3321 | 98101 | 216.34.94.184 | AS3561 | CenturyLink Communications, LLC | 216.34.94.184 | Dotster, Inc. | Dotster, Inc. | 216.34.94.184 | 2015-06-08T17:50:06Z | farsight |
>| 1 | '.domain.org | 2011-02-17T11:17:10Z | Seattle | US | United States | 47.6062 | -122.3321 | 98101 | 216.34.94.184 | AS3561 | CenturyLink Communications, LLC | 216.34.94.184 | Dotster, Inc. | Dotster, Inc. | 216.34.94.184 | 2011-02-17T11:17:10Z | farsight |


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

#### Command example
```!hyas-get-dynamic-dns-records-by-indicator indicator_type="ip" indicator_value="4.4.4.4" limit="3"```
#### Context Example
```json
{
    "HYAS": {
        "DynamicDNS": [
            {
                "a_record": "4.4.4.4",
                "a_record_geo": {
                    "geo": {
                        "city_name": "Paris",
                        "country_iso_code": "FR",
                        "country_name": "France",
                        "location_latitude": "48.8534",
                        "location_longitude": "2.3488",
                        "postal_code": "75000"
                    },
                    "isp": {
                        "autonomous_system_number": "AS3356",
                        "autonomous_system_organization": "Level 3 Parent, LLC",
                        "ip_address": "4.4.4.4",
                        "isp": "Level 3 Communications, Inc.",
                        "organization": "Level 3 Communications, Inc."
                    }
                },
                "account": "free",
                "created": "2022-03-14T11:05:14Z",
                "created_geo": {
                    "geo": {
                        "city_name": "Adelaide",
                        "country_iso_code": "AU",
                        "country_name": "Australia",
                        "location_latitude": "-34.8595",
                        "location_longitude": "138.6192",
                        "postal_code": "5085"
                    },
                    "isp": {
                        "autonomous_system_number": "AS1221",
                        "autonomous_system_organization": "Telstra Corporation Ltd",
                        "ip_address": "4.4.4.4",
                        "isp": "Telstra",
                        "organization": "Telstra"
                    }
                },
                "created_ip": "4.4.4.4",
                "domain": "block-make.duckdns.org",
                "domain_creator_geo": {
                    "geo": {
                        "city_name": "Adelaide",
                        "country_iso_code": "AU",
                        "country_name": "Australia",
                        "location_latitude": "-34.8666",
                        "location_longitude": "138.6768",
                        "postal_code": "5075"
                    },
                    "isp": {
                        "autonomous_system_number": "AS1221",
                        "autonomous_system_organization": "Telstra Corporation Ltd",
                        "ip_address": "4.4.4.4",
                        "isp": "Telstra",
                        "organization": "Telstra"
                    }
                },
                "domain_creator_ip": "4.4.4.4",
                "email": "DarkMagicSource@github"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": {
                    "geo": {
                        "city_name": "Paris",
                        "country_iso_code": "FR",
                        "country_name": "France",
                        "location_latitude": "48.8534",
                        "location_longitude": "2.3488",
                        "postal_code": "75000"
                    },
                    "isp": {
                        "autonomous_system_number": "AS3356",
                        "autonomous_system_organization": "Level 3 Parent, LLC",
                        "ip_address": "4.4.4.4",
                        "isp": "Level 3 Communications, Inc.",
                        "organization": "Level 3 Communications, Inc."
                    }
                },
                "account": "free",
                "created": "2023-02-27T10:00:12Z",
                "created_geo": {
                    "geo": {
                        "city_name": "Adelaide",
                        "country_iso_code": "AU",
                        "country_name": "Australia",
                        "location_latitude": "-34.8595",
                        "location_longitude": "138.6192",
                        "postal_code": "5085"
                    },
                    "isp": {
                        "autonomous_system_number": "AS1221",
                        "autonomous_system_organization": "Telstra Corporation Ltd",
                        "ip_address": "4.4.4.4",
                        "isp": "Telstra",
                        "organization": "Telstra"
                    }
                },
                "created_ip": "4.4.4.4",
                "domain": "flindersmc.duckdns.org",
                "domain_creator_geo": {
                    "geo": {
                        "city_name": "Adelaide",
                        "country_iso_code": "AU",
                        "country_name": "Australia",
                        "location_latitude": "-35.0075",
                        "location_longitude": "138.5437",
                        "postal_code": "5046"
                    },
                    "isp": {
                        "autonomous_system_number": "AS1221",
                        "autonomous_system_organization": "Telstra Corporation Ltd",
                        "ip_address": "4.4.4.4",
                        "isp": "Telstra",
                        "organization": "Telstra"
                    }
                },
                "domain_creator_ip": "4.4.4.4",
                "email": "DarkMagicSource@github"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": {
                    "geo": {
                        "city_name": "Paris",
                        "country_iso_code": "FR",
                        "country_name": "France",
                        "location_latitude": "48.8534",
                        "location_longitude": "2.3488",
                        "postal_code": "75000"
                    },
                    "isp": {
                        "autonomous_system_number": "AS3356",
                        "autonomous_system_organization": "Level 3 Parent, LLC",
                        "ip_address": "4.4.4.4",
                        "isp": "Level 3 Communications, Inc.",
                        "organization": "Level 3 Communications, Inc."
                    }
                },
                "account": "free",
                "created": "2020-04-11T17:01:15Z",
                "created_geo": {
                    "geo": {
                        "city_name": "Toronto",
                        "country_iso_code": "CA",
                        "country_name": "Canada",
                        "location_latitude": "43.7001",
                        "location_longitude": "-79.4163",
                        "postal_code": "M5A"
                    },
                    "isp": {
                        "autonomous_system_number": "AS174",
                        "autonomous_system_organization": "Cogent Communications",
                        "ip_address": "4.4.4.4",
                        "isp": "Amanah Tech Inc.",
                        "organization": "Amanah Tech Inc."
                    }
                },
                "created_ip": "4.4.4.4",
                "domain": "mysql.duckdns.org",
                "email": "xyz"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS DynamicDNS records for ip : 4.4.4.4
>|A Record|Account|Created Date|Account Holder IP Address|Domain|Domain Creator IP Address| Email Address |
>|---|---|---|---|---|---|--------------|
>| 4.4.4.4 | free | 2022-03-14T11:05:14Z | 4.4.4.4 | block-make.duckdns.org | 4.4.4.4 | DarkMagicSource@github |
>| 4.4.4.4 | free | 2023-02-27T10:00:12Z | 4.4.4.4 | flindersmc.duckdns.org | 4.4.4.4 | DarkMagicSource@github |
>| 4.4.4.4 | free | 2020-04-11T17:01:15Z | 4.4.4.4 | mysql.duckdns.org |  | xyz |


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

#### Command example
```!hyas-get-whois-records-by-indicator indicator_type="domain" indicator_value="edubolivia.org" limit="3"```
#### Context Example
```json
{
    "HYAS": {
        "WHOIS": [
            {
                "abuse_emails": [],
                "address": [],
                "city": [],
                "country": [
                    "BO"
                ],
                "datetime": "2021-07-15T08:00:25.296Z",
                "domain": "edubolivia.org",
                "domain_2tld": "edubolivia.org",
                "domain_created_datetime": "2010-04-08T13:24:40Z",
                "domain_expires_datetime": "2022-04-08T13:24:40Z",
                "domain_updated_datetime": "2021-03-26T13:55:53Z",
                "email": [
                    "xyz"
                ],
                "idn_name": null,
                "name": [
                    "pablo maldonado"
                ],
                "nameserver": [
                    "ns1.solucionesrmc.com",
                    "ns2.solucionesrmc.com"
                ],
                "organization": [],
                "phone": [],
                "privacy_punch": false,
                "registrar": "pdr ltd. d/b/a publicdomainregistry.com",
                "state": [],
                "whois_nameserver": [],
                "whois_pii": []
            },
            {
                "abuse_emails": [],
                "address": [],
                "city": [],
                "country": [],
                "datetime": "2023-06-30T09:01:13.703Z",
                "domain": "edubolivia.org",
                "domain_2tld": "edubolivia.org",
                "domain_created_datetime": "2010-04-08T13:24:40Z",
                "domain_expires_datetime": "2024-04-08T13:24:40Z",
                "domain_updated_datetime": "2023-03-26T12:56:44Z",
                "email": [],
                "idn_name": null,
                "name": [],
                "nameserver": [
                    "ns1.dns-parking.com",
                    "ns2.dns-parking.com"
                ],
                "organization": [],
                "phone": [],
                "privacy_punch": false,
                "registrar": "pdr ltd. d/b/a publicdomainregistry.com",
                "state": [],
                "whois_nameserver": [],
                "whois_pii": []
            },
            {
                "abuse_emails": [],
                "address": [],
                "city": [],
                "country": [],
                "datetime": "2023-06-30T09:01:13.703Z",
                "domain": "edubolivia.org",
                "domain_2tld": "edubolivia.org",
                "domain_created_datetime": "2010-04-08T13:24:40Z",
                "domain_expires_datetime": "2023-04-08T13:24:40Z",
                "domain_updated_datetime": "2022-12-14T07:28:16Z",
                "email": [],
                "idn_name": null,
                "name": [],
                "nameserver": [
                    "ns3.server-us.com",
                    "ns4.server-us.com"
                ],
                "organization": [],
                "phone": [],
                "privacy_punch": false,
                "registrar": "pdr ltd. d/b/a publicdomainregistry.com",
                "state": [],
                "whois_nameserver": [],
                "whois_pii": []
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS WHOIS records for domain : edubolivia.org
>|Country|Domain|Domain_2tld|Domain Created Time|Domain Expires Time|Domain Updated Time|Email Address|IDN Name|Nameserver|Privacy_punch|Registrar|
>|---|---|---|---|---|---|---|---|---|---|---|
>| BO | edubolivia.org | edubolivia.org | 2010-04-08T13:24:40Z | 2022-04-08T13:24:40Z | 2021-03-26T13:55:53Z | xyz | None | ns1.solucionesrmc.com,<br/>ns2.solucionesrmc.com | false | pdr ltd. d/b/a publicdomainregistry.com |
>|  | edubolivia.org | edubolivia.org | 2010-04-08T13:24:40Z | 2024-04-08T13:24:40Z | 2023-03-26T12:56:44Z |  | None | ns1.dns-parking.com,<br/>ns2.dns-parking.com | false | pdr ltd. d/b/a publicdomainregistry.com |
>|  | edubolivia.org | edubolivia.org | 2010-04-08T13:24:40Z | 2023-04-08T13:24:40Z | 2022-12-14T07:28:16Z |  | None | ns3.server-us.com,<br/>ns4.server-us.com | false | pdr ltd. d/b/a publicdomainregistry.com |


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

#### Command example
```!hyas-get-whois-current-records-by-domain domain="edubolivia.org"```
#### Context Example
```json
{
    "HYAS": {
        "WHOISCurrent": {
            "items": [
                {
                    "abuse_emails": [
                        "abuse@publicdomainregistry.com"
                    ],
                    "address": [],
                    "city": [],
                    "country": [
                        "Bolivia"
                    ],
                    "datetime": null,
                    "domain": "edubolivia.org",
                    "domain_2tld": "edubolivia.org",
                    "domain_created_datetime": "2010-04-08T13:24:40Z",
                    "domain_expires_datetime": "2024-04-08T13:24:40Z",
                    "domain_updated_datetime": "2023-03-26T12:56:44Z",
                    "email": [
                        "please query the rdds service of the registrar of record identified in this output for information on how to contact the registrant, admin, or tech contact of the queried domain name."
                    ],
                    "idn_name": null,
                    "name": [
                        "Redacted For Privacy\nPablo Maldonado"
                    ],
                    "nameserver": [
                        "ns1.dns-parking.com",
                        "ns2.dns-parking.com"
                    ],
                    "organization": [],
                    "phone": [
                        {
                            "phone": "REDACTED FOR PRIVACY ext. REDACTED FOR PRIVACY"
                        }
                    ],
                    "privacy_punch": false,
                    "registrar": "pdr ltd. d/b/a publicdomainregistry.com",
                    "state": [
                        "la Paz"
                    ],
                    "whois_nameserver": [
                        {
                            "domain": "ns1.dns-parking.com"
                        },
                        {
                            "domain": "ns2.dns-parking.com"
                        }
                    ],
                    "whois_pii": [
                        {
                            "email": "please query the rdds service of the registrar of record identified in this output for information on how to contact the registrant, admin, or tech contact of the queried domain name.",
                            "phone_e164": "REDACTED FOR PRIVACY ext. REDACTED FOR PRIVACY"
                        },
                        {
                            "email": "please query the rdds service of the registrar of record identified in this output for information on how to contact the registrant, admin, or tech contact of the queried domain name.",
                            "geo_country_alpha_2": "Bolivia",
                            "name": "Redacted For Privacy\nPablo Maldonado",
                            "phone_e164": "REDACTED FOR PRIVACY ext. REDACTED FOR PRIVACY",
                            "state": "la Paz"
                        }
                    ]
                }
            ],
            "source": "whois",
            "total_count": 1
        }
    }
}
```

#### Human Readable Output

>### HYAS WHOISCurrent records for domain : edubolivia.org
>|Abuse Emails|Country|Domain|Domain_2tld|Domain Created Time|Domain Expires Time|Domain Updated Time|Email Address|IDN Name|Nameserver|Phone Info|Registrar|State|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| abuse@publicdomainregistry.com | Bolivia | edubolivia.org | edubolivia.org | 2010-04-08T13:24:40Z | 2024-04-08T13:24:40Z | 2023-03-26T12:56:44Z | please query the rdds service of the registrar of record identified in this output for information on how to contact the registrant, admin, or tech contact of the queried domain name. | None | ns1.dns-parking.com,<br/>ns2.dns-parking.com | {'phone': 'REDACTED FOR PRIVACY ext. REDACTED FOR PRIVACY'} | pdr ltd. d/b/a publicdomainregistry.com | la Paz |


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

#### Command example
```!hyas-get-malware-samples-records-by-indicator indicator_type="domain" indicator_value="chennaigastrosurgeon.com" limit="3"```
#### Context Example
```json
{
    "HYAS": {
        "MalwareSamples": [
            {
                "datetime": "2022-09-28T00:00:00Z",
                "domain": "chennaigastrosurgeon.com",
                "ipv4": "4.4.4.4",
                "md5": "0268fb20d9143c429138034969e06833"
            },
            {
                "datetime": "2022-09-27T00:00:00Z",
                "domain": "chennaigastrosurgeon.com",
                "ipv4": "4.4.4.4",
                "md5": "21a77bca1417deb64a2ab7df77786ded"
            },
            {
                "datetime": "2022-09-24T00:00:00Z",
                "domain": "chennaigastrosurgeon.com",
                "ipv4": "4.4.4.4",
                "md5": "953951ede4e9f706e6842fa4eb4e2e65"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS MalwareSamples records for domain : chennaigastrosurgeon.com
>|Datetime|Domain|IPV4 Address|MD5 Value|
>|---|---|---|---|
>| 2022-09-28T00:00:00Z | chennaigastrosurgeon.com | 4.4.4.4 | 0268fb20d9143c429138034969e06833 |
>| 2022-09-27T00:00:00Z | chennaigastrosurgeon.com | 4.4.4.4 | 21a77bca1417deb64a2ab7df77786ded |
>| 2022-09-24T00:00:00Z | chennaigastrosurgeon.com | 4.4.4.4 | 953951ede4e9f706e6842fa4eb4e2e65 |


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

#### Command example
```!hyas-get-c2attribution-records-by-indicator indicator_type=domain indicator_value=himionsa.com limit=3```
#### Context Example
```json
{
    "HYAS": {
        "C2_Attribution": {
            "actor_ipv4": "4.4.4.4",
            "c2_domain": "himionsa.com",
            "c2_ip": "89.208.229.55",
            "c2_url": "http://himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report",
            "datetime": "2020-02-25T16:39:43Z"
        }
    }
}
```

#### Human Readable Output

>### HYAS C2_Attribution records for domain : himionsa.com
>|Actor IPv4|C2 Domain|C2 IP|C2 URL|Datetime|
>|--|---|---|---|---|
>| 4.4.4.4 | himionsa.com | 89.208.229.55 | http:<span>//</span>himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report | 2020-02-25T21:49:27Z |
>| 4.4.4.4 | himionsa.com | 89.208.229.55 | http:<span>//</span>himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report | 2020-02-25T16:39:48Z |
>| 4.4.4.4 | himionsa.com | 89.208.229.55 | http:<span>//</span>himionsa.com/rich/panel/pvqdq929bsx_a_d_m1n_a.php?mazm=report | 2020-02-25T16:39:43Z |


### hyas-get-passive-hash-records-by-indicator

***
Return passive hash records for the provided indicator value.

#### Base Command

`hyas-get-passive-hash-records-by-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: ipv4, domain. | Required | 
| indicator_value | Indicator Value. | Required | 
| limit | The maximum number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.Passive_Hash.domain | String | The domain of the passive hash information requested | 
| HYAS.Passive_Hash.md5_count | String | The passive dns count | 

#### Command example
```!hyas-get-passive-hash-records-by-indicator indicator_type="domain" indicator_value="edubolivia.org" limit="3"```
#### Context Example
```json
{
    "HYAS": {
        "Passive_Hash": [
            {
                "domain": "edubolivia.org",
                "md5_count": 457
            },
            {
                "domain": "juliusdobos.com",
                "md5_count": 457
            },
            {
                "domain": "ogsrealestate.com",
                "md5_count": 457
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS Passive_Hash records for domain : edubolivia.org
>|Domain|MD5 Count|
>|---|---|
>| edubolivia.org | 457 |
>| juliusdobos.com | 457 |
>| ogsrealestate.com | 457 |


### hyas-get-ssl-certificate-records-by-indicator

***
Return SSL certificate records for the provided indicator value.

#### Base Command

`hyas-get-ssl-certificate-records-by-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: ip, domain, hash. | Required | 
| indicator_value | Indicator Value. | Required | 
| limit | The maximum number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.SSL_Certificate.ssl_certs.ip | String | The ip address associated with certificate | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.cert_key | String | The certificate key \(sha1\) | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.expire_date | String | The expiry date of the certificate | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.issue_date | String | The issue date of the certificate | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.issuer_commonName | String | The common name that the certificate was issued from | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.issuer_countryName | String | The country ISO the certificate was issued from | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.issuer_localityName | String | The city where the issuer company is legally located | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.issuer_organizationName | String | The organization name that issued the certificate | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.issuer_organizationalUnitName | String | The organization unit name that issued the certificate | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.issuer_stateOrProvinceName | String | The issuer state or province | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.md5 | String | The certificate MD5 | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.serial_number | String | The certificate serial number | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.sha1 | String | The certificate sha1 | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.sha_256 | String | The certificate sha256 | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.sig_algo | String | The certificate signature algorithm | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.signature | String | The certificate signature. Signature split into multiple lines | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.ssl_version | String | The SSL version | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.subject_commonName | String | The subject name that the certificate was issued to | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.subject_countryName | String | The country the certificate was issued to | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.subject_localityName | String | The city where the subject company is legally located | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.subject_organizationName | String | The organization name that recieved the certificate | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.subject_organizationalUnitName | String | The organization unit name that recieved the certificate | 
| HYAS.SSL_Certificate.ssl_certs.ssl_cert.timestamp | String | The certificate date and time | 

### hyas-get-opensource-indicator-records-by-indicator

***
Return Open Source intel records for the provided indicator value.

#### Base Command

`hyas-get-opensource-indicator-records-by-indicator`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: ipv4, ipv6, domain, sha1, sha256, md5. | Required | 
| indicator_value | Indicator Value. | Required | 
| limit | The maximum number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.OS_Indicators.context | String | Additional information about source. | 
| HYAS.OS_Indicators.data | Unknown | A json blob with raw data. | 
| HYAS.OS_Indicators.datetime | String | A date-time string in RFC 3339 format. | 
| HYAS.OS_Indicators.domain | String | A domain. | 
| HYAS.OS_Indicators.domain_2tld | String | A domain_2tld. | 
| HYAS.OS_Indicators.first_seen | String | A date-time string in RFC 3339 format. | 
| HYAS.OS_Indicators.ipv4 | String | The ipv4 address. Can be a cidr. | 
| HYAS.OS_Indicators.ipv6 | String | The ipv6 address. Can be a cidr. | 
| HYAS.OS_Indicators.last_seen | String | A date-time string in RFC 3339 format. | 
| HYAS.OS_Indicators.md5 | String | The md5 value. | 
| HYAS.OS_Indicators.sha1 | String | The sha1 value. | 
| HYAS.OS_Indicators.sha256 | String | The sha256 value. | 
| HYAS.OS_Indicators.source_name | String | The source name | 
| HYAS.OS_Indicators.source_url | String | The source url | 
| HYAS.OS_Indicators.uri | String | The source uri value. | 

#### Command example
```!hyas-get-opensource-indicator-records-by-indicator indicator_type=domain indicator_value=kidd16.blinn.edu limit="3"```
#### Human Readable Output

>### HYAS OS_Indicators records for domain : kidd16.blinn.edu
>**No entries.**


### hyas-get-device-geo-records-by-ip-address

***
Returns a list of mobile geolocation information

#### Base Command

`hyas-get-device-geo-records-by-ip-address`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: ipv4, ipv6. | Required | 
| indicator_value | Indicator Value. | Required | 
| limit | The maximum number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.Device_Geo.datetime | String | A date-time string in RFC 3339 format. | 
| HYAS.Device_Geo.device_user_agent | String | The user agent string for the device. | 
| HYAS.Device_Geo.geo_country_alpha_2 | String | The ISO 3316 alpha-2 code for the country associated with the lat/long reported. | 
| HYAS.Device_Geo.geo_horizontal_accuracy | String | The GPS horizontal accuracy. | 
| HYAS.Device_Geo.ipv4 | String | The ipv4 address assigned to the device. A device may have either or ipv4 and ipv6. | 
| HYAS.Device_Geo.ipv6 | String | The ipv6 address assigned to the device. A device may have either or ipv4 and ipv6. | 
| HYAS.Device_Geo.latitude | Number | Units are degrees on the WGS 84 spheroid. | 
| HYAS.Device_Geo.longitude | Number | Units are degrees on the WGS 84 spheroid. | 
| HYAS.Device_Geo.wifi_bssid | String | The BSSID \(MAC address\) of the wifi router that the device communicated through. | 

#### Command example
```!hyas-get-device-geo-records-by-ip-address indicator_type=ipv4 indicator_value=4.4.4.4 limit="3"```
#### Context Example
```json
{
    "HYAS": {
        "Device_Geo": [
            {
                "datetime": "2022-03-01T16:07:07Z",
                "device_geo_id": "9120a69e-cc23-451a-a55d-4223e0cec88b",
                "device_user_agent": "15.3.1",
                "geo_country_alpha_2": "AU",
                "geo_horizontal_accuracy": 20,
                "ipv4": "4.4.4.4",
                "latitude": -33.805888,
                "longitude": 150.781879
            },
            {
                "datetime": "2022-03-01T15:46:10Z",
                "device_geo_id": "c6d36363-c966-4c94-9163-cff050fc2257",
                "device_user_agent": "15.3.1",
                "geo_country_alpha_2": "AU",
                "geo_horizontal_accuracy": 15.6,
                "ipv4": "4.4.4.4",
                "latitude": -33.805855,
                "longitude": 150.781918
            },
            {
                "datetime": "2022-03-01T15:07:46Z",
                "device_geo_id": "44442ff1-3b71-406a-963c-3ece950e11f5",
                "device_user_agent": "15.3.1",
                "geo_country_alpha_2": "AU",
                "geo_horizontal_accuracy": 15.6,
                "ipv4": "4.4.4.4",
                "latitude": -33.805855,
                "longitude": 150.781918
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS Device_Geo records for ipv4 : 4.4.4.4
>|Date Time|Device User Agent|Geo Country Alpha 2|Geo Horizontal Accuracy|IPV4|Latitude|Longitude|
>|---|---|---|---|---|---|---|
>| 2022-03-01T16:07:07Z | 15.3.1 | AU | 20.0 | 4.4.4.4 | -33 | 150 |
>| 2022-03-01T15:46:10Z | 15.3.1 | AU | 15.6 | 4.4.4.4 | -33 | 150 |
>| 2022-03-01T15:07:46Z | 15.3.1 | AU | 15.6 | 4.4.4.4 | -33 | 150 |


### hyas-get-sinkhole-records-by-ipv4-address

***
Returns sinkhole information.

#### Base Command

`hyas-get-sinkhole-records-by-ipv4-address`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ipv4 | The ipv4 address value to query. | Required | 
| limit | The maximum number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.Sinkhole.count | String | The sinkhole count | 
| HYAS.Sinkhole.country_name | String | The country of the ip | 
| HYAS.Sinkhole.data_port | String | The data port | 
| HYAS.Sinkhole.datetime | String | The first seen date of the sinkhole | 
| HYAS.Sinkhole.ipv4 | String | The ipv4 of the sinkhole | 
| HYAS.Sinkhole.last_seen | String | The last seen date of the sinkhole | 
| HYAS.Sinkhole.organization_name | String | The isp organization for the ip | 
| HYAS.Sinkhole.sink_source | String | The ipv4 of the sink source | 

#### Command example
```!hyas-get-sinkhole-records-by-ipv4-address ipv4=4.4.4.4 limit="3"```
#### Context Example
```json
{
    "HYAS": {
        "Sinkhole": [
            {
                "count": 18,
                "country_code": "GB",
                "country_name": "United Kingdom",
                "data_port": 5552,
                "datetime": "2020-12-23T14:06:56Z",
                "ipv4": "4.4.4.4",
                "last_seen": "2020-12-23T14:06:56Z",
                "organization_name": "Shahkar Towse'e Tejarat Mana PJSC",
                "sink_source": "4.4.4.4"
            },
            {
                "count": 157,
                "country_code": "GB",
                "country_name": "United Kingdom",
                "data_port": 5552,
                "datetime": "2020-12-23T13:59:28Z",
                "ipv4": "4.4.4.4",
                "last_seen": "2020-12-23T13:59:28Z",
                "organization_name": "Shahkar Towse'e Tejarat Mana PJSC",
                "sink_source": "4.4.4.4"
            },
            {
                "count": 160,
                "country_code": "GB",
                "country_name": "United Kingdom",
                "data_port": 5552,
                "datetime": "2020-12-23T12:59:44Z",
                "ipv4": "4.4.4.4",
                "last_seen": "2020-12-23T12:59:44Z",
                "organization_name": "Shahkar Towse'e Tejarat Mana PJSC",
                "sink_source": "4.4.4.4"
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS Sinkhole records for ipv4 : 4.4.4.4
>|Count|Country Name|Data Port|Date Time|IPV4|Last Seen|Organization Name|Sink Source|
>|---|---|---|---|---|---|---|---|
>| 18 | United Kingdom | 5552 | 2020-12-23T14:06:56Z | 4.4.4.4 | 2020-12-23T14:06:56Z | Shahkar Towse'e Tejarat Mana PJSC | 4.4.4.4 |
>| 157 | United Kingdom | 5552 | 2020-12-23T13:59:28Z | 4.4.4.4 | 2020-12-23T13:59:28Z | Shahkar Towse'e Tejarat Mana PJSC | 4.4.4.4 |
>| 160 | United Kingdom | 5552 | 2020-12-23T12:59:44Z | 4.4.4.4 | 2020-12-23T12:59:44Z | Shahkar Towse'e Tejarat Mana PJSC | 4.4.4.4 |


### hyas-get-malware-sample-information-by-hash

***
Returns malware information.

#### Base Command

`hyas-get-malware-sample-information-by-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | The hash value to query. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.Malware_Information.avscan_score | String | AV scan score | 
| HYAS.Malware_Information.md5 | String | MD5 Hash | 
| HYAS.Malware_Information.scan_results.av_name | String | The AV Name | 
| HYAS.Malware_Information.scan_results.def_time | String | The AV datetime | 
| HYAS.Malware_Information.scan_results.threat_found | String | The source | 
| HYAS.Malware_Information.scan_time | String | The datetime of the scan | 
| HYAS.Malware_Information.sha1 | String | The sha1 hash | 
| HYAS.Malware_Information.sha256 | String | The sha256 hash | 
| HYAS.Malware_Information.sha512 | String | The sha512 hash | 

#### Command example
```!hyas-get-malware-sample-information-by-hash hash=1d0a97c41afe5540edd0a8c1fb9a0f1c limit="3"```
#### Context Example
```json
{
    "HYAS": {
        "Malware_Information": {
            "avscan_score": "1/9",
            "md5": "1d0a97c41afe5540edd0a8c1fb9a0f1c",
            "scan_results": [
                {
                    "av_name": "Cyren",
                    "def_time": "2023-02-13T09:49:00Z",
                    "threat_found": "abc"
                }
            ],
            "scan_time": "2023-02-21T07:36:35Z",
            "sha1": "9f3ae27d3d071b1cd0a220ec2d5944cde44af91a",
            "sha256": "3e3f900e6ab9e03f93fee334d357336f8ae67633420a462d0662fd51bc5004ab",
            "sha512": "956ab65f8119e9060cc955db31284bc99e6bf82bcd1b0dfcf29457cdf61acacf884209191692f8173970c6b28128e3c79d3126fd9f50df8c71612ee9b47710f9"
        }
    }
}
```

#### Human Readable Output

>### HYAS Malware_Information records for hash : 1d0a97c41afe5540edd0a8c1fb9a0f1c
>|AV Scan Score|MD5|AV Name|AV DateTime| Source    |Scan Time|SHA1|SHA256|SHA512|
>|---|---|---|---|-----------|---|---|---|---|
>| 1/9 | 1d0a97c41afe5540edd0a8c1fb9a0f1c | Cyren | 2023-02-13T09:49:00Z | abc | 2023-02-21T07:36:35Z | 9f3ae27d3d071b1cd0a220ec2d5944cde44af91a | 3e3f900e6ab9e03f93fee334d357336f8ae67633420a462d0662fd51bc5004ab | 956ab65f8119e9060cc955db31284bc99e6bf82bcd1b0dfcf29457cdf61acacf884209191692f8173970c6b28128e3c79d3126fd9f50df8c71612ee9b47710f9 |


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
| HYAS.HASH-IP.ips | Unknown | Associated IPS  for the provided MD5 value | 

#### Command example
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

#### Command example
```!hyas-get-associated-domains-by-hash md5="1d0a97c41afe5540edd0a8c1fb9a0f1c"```
#### Context Example
```json
{
    "HYAS": {
        "HASH-DOMAIN": {
            "domains": [
                "qwertasdfg.sinip.es",
                "butterfly.bigmoney.biz",
                "butterfly.sinip.es"
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
>| qwertasdfg.sinip.es |
>| butterfly.bigmoney.biz |
>| butterfly.sinip.es |
