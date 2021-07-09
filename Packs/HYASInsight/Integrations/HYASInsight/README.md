# HYAS Insight
HYAS Insight is a threat investigation and attribution solution that uses exclusive data sources and non-traditional mechanisms to improve visibility and productivity for analysts, researchers, and investigators while increasing the accuracy of findings. HYAS Insight connects attack instances and campaigns to billions of indicators of compromise to deliver insights and visibility. With an easy-to-use user interface, transforms, and API access, HYAS Insight combines rich threat data into a powerful research and attribution solution. HYAS Insight is complemented by the HYAS Intelligence team that helps organizations to better understand the nature of the threats they face on a daily basis.

Use the HYAS Insight integration to interactively lookup PassiveDNS, DynamicDNS, WHOIS, Malware Information – either as playbook tasks or through API calls in the War Room.
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
| indicator_type | Indicator Type. Possible values are: IPv4, Domain. Possible values are: ipv4, domain. | Required | 
| indicator_value | Indicator value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.PassiveDNS.cert_name | String | The certificate provider name | 
| HYAS.PassiveDNS.count | String | The passive dns count | 
| HYAS.PassiveDNS.domain | String | The domain of the passive dns information requested | 
| HYAS.PassiveDNS.first_seen | String | The first time this domain was seen | 
| HYAS.PassiveDNS.ip.geo.city_name | String | City of the ip organization | 
| HYAS.PassiveDNS.ip.geo.country_iso_code | String | Country ISO code of the ip organization | 
| HYAS.PassiveDNS.ip.geo.country_name | String | Country name of the ip organization | 
| HYAS.PassiveDNS.ip.geo.location_latitude | String | The latitude of the ip organization | 
| HYAS.PassiveDNS.ip.geo.location_longitude | String | The longitude of the ip organization | 
| HYAS.PassiveDNS.ip.geo.postal_code | String | The longitude of the ip organization | 
| HYAS.PassiveDNS.ip | String | IP of the organization | 
| HYAS.PassiveDNS.isp.autonomous_system_number | String | The ASN of the ip | 
| HYAS.PassiveDNS.isp.autonomous_system_organization | String | The ASO of the ip | 
| HYAS.PassiveDNS.isp.ip_address | String | The IP | 
| HYAS.PassiveDNS.isp.isp | String | The Internet Service Provider | 
| HYAS.PassiveDNS.isp.organization | String | The ISP organization | 
| HYAS.PassiveDNS.ipv4 | String | The ipv4 address of the passive dns record | 
| HYAS.PassiveDNS.ipv6 | String | The ipv6 address of the passive dns record | 
| HYAS.PassiveDNS.last_seen | String | The last time this domain was seen | 
| HYAS.PassiveDNS.sources | Unknown | A list of pDNS providers which the data came from | 


#### Command Example
```!hyas-get-passive-dns-records-by-indicator indicator_type="domain" indicator_value="edubolivia.org"```

#### Context Example
```json
{
    "HYAS": {
        "PassiveDNS": [
            {
                "count": 10570,
                "domain": "edubolivia.org",
                "first_seen": "2019-03-14T23:36:40Z",
                "ip": {
                    "geo": {
                        "city_name": "Cutlerville",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "42.8409",
                        "location_longitude": "-85.6636",
                        "postal_code": "49548"
                    },
                    "ip": "99.198.121.82",
                    "isp": {
                        "autonomous_system_number": "AS32475",
                        "autonomous_system_organization": "SingleHop LLC",
                        "ip_address": "99.198.121.82",
                        "isp": "SingleHop LLC",
                        "organization": "SingleHop LLC"
                    }
                },
                "ipv4": "99.198.121.82",
                "last_seen": "2021-07-06T03:37:14Z",
                "sources": [
                    "hyas",
                    "farsight"
                ]
            },
            {
                "count": 151,
                "domain": "edubolivia.org",
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
                    "ip": "69.175.25.234",
                    "isp": {
                        "autonomous_system_number": "AS32475",
                        "autonomous_system_organization": "SingleHop LLC",
                        "ip_address": "69.175.25.234",
                        "isp": "SingleHop LLC",
                        "organization": "SingleHop LLC"
                    }
                },
                "ipv4": "69.175.25.234",
                "last_seen": "2012-06-18T08:36:11Z",
                "sources": [
                    "farsight"
                ]
            },
            {
                "count": 7439,
                "domain": "edubolivia.org",
                "first_seen": "2014-04-08T03:30:41Z",
                "ip": {
                    "geo": {
                        "city_name": "Scottsdale",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "33.5092",
                        "location_longitude": "-111.8990",
                        "postal_code": "85261"
                    },
                    "ip": "70.40.220.103",
                    "isp": {
                        "autonomous_system_number": "AS46606",
                        "autonomous_system_organization": "Unified Layer",
                        "ip_address": "70.40.220.103",
                        "isp": "Unified Layer",
                        "organization": "Unified Layer"
                    }
                },
                "ipv4": "70.40.220.103",
                "last_seen": "2018-11-25T08:06:47Z",
                "sources": [
                    "farsight"
                ]
            },
            {
                "count": 93,
                "domain": "edubolivia.org",
                "first_seen": "2014-04-06T03:14:02Z",
                "ip": {
                    "geo": {
                        "city_name": "Scottsdale",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "33.5092",
                        "location_longitude": "-111.8990",
                        "postal_code": "85261"
                    },
                    "ip": "74.220.199.6",
                    "isp": {
                        "autonomous_system_number": "AS46606",
                        "autonomous_system_organization": "Unified Layer",
                        "ip_address": "74.220.199.6",
                        "isp": "Unified Layer",
                        "organization": "Unified Layer"
                    }
                },
                "ipv4": "74.220.199.6",
                "last_seen": "2019-03-08T23:27:49Z",
                "sources": [
                    "farsight"
                ]
            },
            {
                "count": 1,
                "domain": "edubolivia.org",
                "first_seen": "2011-07-29T14:59:51Z",
                "ip": {
                    "geo": {
                        "city_name": "Chicago",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "41.8500",
                        "location_longitude": "-87.6500",
                        "postal_code": "60666"
                    },
                    "ip": "173.236.37.194",
                    "isp": {
                        "autonomous_system_number": "AS32475",
                        "autonomous_system_organization": "SingleHop LLC",
                        "ip_address": "173.236.37.194",
                        "isp": "Vorex",
                        "organization": "Vorex"
                    }
                },
                "ipv4": "173.236.37.194",
                "last_seen": "2011-07-29T14:59:51Z",
                "sources": [
                    "farsight"
                ]
            },
            {
                "count": 1,
                "domain": "edubolivia.org",
                "first_seen": "2018-04-08T00:00:00Z",
                "ip": {
                    "geo": {
                        "city_name": "Houston",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "29.7633",
                        "location_longitude": "-95.3633",
                        "postal_code": "77052"
                    },
                    "ip": "209.99.40.221",
                    "isp": {
                        "autonomous_system_number": "AS40034",
                        "autonomous_system_organization": "Confluence Networks Inc",
                        "ip_address": "209.99.40.221",
                        "isp": "Confluence Networks Inc.",
                        "organization": "Confluence Networks Inc."
                    }
                },
                "ipv4": "209.99.40.221",
                "last_seen": "2018-04-16T00:00:00Z",
                "sources": [
                    "zetalytics"
                ]
            },
            {
                "count": 1,
                "domain": "www.edubolivia.org",
                "first_seen": "2019-03-16T00:00:00Z",
                "ip": {
                    "geo": {
                        "city_name": "Cutlerville",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "42.8409",
                        "location_longitude": "-85.6636",
                        "postal_code": "49548"
                    },
                    "ip": "99.198.121.82",
                    "isp": {
                        "autonomous_system_number": "AS32475",
                        "autonomous_system_organization": "SingleHop LLC",
                        "ip_address": "99.198.121.82",
                        "isp": "SingleHop LLC",
                        "organization": "SingleHop LLC"
                    }
                },
                "ipv4": "99.198.121.82",
                "last_seen": "2021-07-07T00:00:00Z",
                "sources": [
                    "zetalytics"
                ]
            },
            {
                "count": 1,
                "domain": "edubolivia.org",
                "first_seen": "2019-07-08T00:00:00Z",
                "ip": {
                    "geo": {
                        "city_name": "Ashburn",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "39.0437",
                        "location_longitude": "-77.4875",
                        "postal_code": "20149"
                    },
                    "ip": "146.112.239.193",
                    "isp": {
                        "autonomous_system_number": "AS36692",
                        "autonomous_system_organization": "Cisco OpenDNS, LLC",
                        "ip_address": "146.112.239.193",
                        "isp": "CISCO CIE QUADRA ASH1",
                        "organization": "CISCO CIE QUADRA ASH1"
                    }
                },
                "ipv4": "146.112.239.193",
                "last_seen": "2019-07-08T00:00:00Z",
                "sources": [
                    "zetalytics"
                ]
            },
            {
                "count": 1,
                "domain": "webmail.edubolivia.org",
                "first_seen": "2019-06-01T00:00:00Z",
                "ip": {
                    "geo": {
                        "city_name": "Cutlerville",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "42.8409",
                        "location_longitude": "-85.6636",
                        "postal_code": "49548"
                    },
                    "ip": "99.198.121.82",
                    "isp": {
                        "autonomous_system_number": "AS32475",
                        "autonomous_system_organization": "SingleHop LLC",
                        "ip_address": "99.198.121.82",
                        "isp": "SingleHop LLC",
                        "organization": "SingleHop LLC"
                    }
                },
                "ipv4": "99.198.121.82",
                "last_seen": "2021-07-01T00:00:00Z",
                "sources": [
                    "zetalytics"
                ]
            },
            {
                "count": 1,
                "domain": "cpcalendars.edubolivia.org",
                "first_seen": "2021-01-15T00:00:00Z",
                "ip": {
                    "geo": {
                        "city_name": "Cutlerville",
                        "country_iso_code": "US",
                        "country_name": "United States",
                        "location_latitude": "42.8409",
                        "location_longitude": "-85.6636",
                        "postal_code": "49548"
                    },
                    "ip": "99.198.121.82",
                    "isp": {
                        "autonomous_system_number": "AS32475",
                        "autonomous_system_organization": "SingleHop LLC",
                        "ip_address": "99.198.121.82",
                        "isp": "SingleHop LLC",
                        "organization": "SingleHop LLC"
                    }
                },
                "ipv4": "99.198.121.82",
                "last_seen": "2021-07-08T00:00:00Z",
                "sources": [
                    "zetalytics"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS PassiveDNS records for domain : edubolivia.org
>|Cert Name|Count|Domain|First seen|City Name|Country Code|Country Name|Latitude|Longitude|Postal Code|IP|ISP ASN|ISP ASN Organization|ISP IP Address|ISP|ISP Organization|IPV4|IPV6|Last Seen|SHA1|Sources|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | 10570 | edubolivia.org | 2019-03-14T23:36:40Z | Cutlerville | US | United States | 42.8409 | -85.6636 | 49548 | 99.198.121.82 | AS32475 | SingleHop LLC | 99.198.121.82 | SingleHop LLC | SingleHop LLC | 99.198.121.82 |  | 2021-07-06T03:37:14Z |  | hyas,<br/>farsight |
>|  | 151 | edubolivia.org | 2011-08-02T12:15:17Z | Chicago | US | United States | 41.8500 | -87.6500 | 60666 | 69.175.25.234 | AS32475 | SingleHop LLC | 69.175.25.234 | SingleHop LLC | SingleHop LLC | 69.175.25.234 |  | 2012-06-18T08:36:11Z |  | farsight |
>|  | 7439 | edubolivia.org | 2014-04-08T03:30:41Z | Scottsdale | US | United States | 33.5092 | -111.8990 | 85261 | 70.40.220.103 | AS46606 | Unified Layer | 70.40.220.103 | Unified Layer | Unified Layer | 70.40.220.103 |  | 2018-11-25T08:06:47Z |  | farsight |
>|  | 93 | edubolivia.org | 2014-04-06T03:14:02Z | Scottsdale | US | United States | 33.5092 | -111.8990 | 85261 | 74.220.199.6 | AS46606 | Unified Layer | 74.220.199.6 | Unified Layer | Unified Layer | 74.220.199.6 |  | 2019-03-08T23:27:49Z |  | farsight |
>|  | 1 | edubolivia.org | 2011-07-29T14:59:51Z | Chicago | US | United States | 41.8500 | -87.6500 | 60666 | 173.236.37.194 | AS32475 | SingleHop LLC | 173.236.37.194 | Vorex | Vorex | 173.236.37.194 |  | 2011-07-29T14:59:51Z |  | farsight |
>|  | 1 | edubolivia.org | 2018-04-08T00:00:00Z | Houston | US | United States | 29.7633 | -95.3633 | 77052 | 209.99.40.221 | AS40034 | Confluence Networks Inc | 209.99.40.221 | Confluence Networks Inc. | Confluence Networks Inc. | 209.99.40.221 |  | 2018-04-16T00:00:00Z |  | zetalytics |
>|  | 1 | www.edubolivia.org | 2019-03-16T00:00:00Z | Cutlerville | US | United States | 42.8409 | -85.6636 | 49548 | 99.198.121.82 | AS32475 | SingleHop LLC | 99.198.121.82 | SingleHop LLC | SingleHop LLC | 99.198.121.82 |  | 2021-07-07T00:00:00Z |  | zetalytics |
>|  | 1 | edubolivia.org | 2019-07-08T00:00:00Z | Ashburn | US | United States | 39.0437 | -77.4875 | 20149 | 146.112.239.193 | AS36692 | Cisco OpenDNS, LLC | 146.112.239.193 | CISCO CIE QUADRA ASH1 | CISCO CIE QUADRA ASH1 | 146.112.239.193 |  | 2019-07-08T00:00:00Z |  | zetalytics |
>|  | 1 | webmail.edubolivia.org | 2019-06-01T00:00:00Z | Cutlerville | US | United States | 42.8409 | -85.6636 | 49548 | 99.198.121.82 | AS32475 | SingleHop LLC | 99.198.121.82 | SingleHop LLC | SingleHop LLC | 99.198.121.82 |  | 2021-07-01T00:00:00Z |  | zetalytics |
>|  | 1 | cpcalendars.edubolivia.org | 2021-01-15T00:00:00Z | Cutlerville | US | United States | 42.8409 | -85.6636 | 49548 | 99.198.121.82 | AS32475 | SingleHop LLC | 99.198.121.82 | SingleHop LLC | SingleHop LLC | 99.198.121.82 |  | 2021-07-08T00:00:00Z |  | zetalytics |


### hyas-get-dynamic-dns-records-by-indicator
***
Returns DynamicDNS records for the provided indicator value.


#### Base Command

`hyas-get-dynamic-dns-records-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: IP, Domain, Email. Possible values are: ip, domain, email. | Required | 
| indicator_value | Indicator value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.DynamicDNS.a_record | String | The A record for the domain | 
| HYAS.DynamicDNS.account | String | The account holder name | 
| HYAS.DynamicDNS.created | String | The date which the domain was created | 
| HYAS.DynamicDNS.created_ip | String | The ip address of the account holder | 
| HYAS.DynamicDNS.domain | String | The domain associated with the dynamic dns information | 
| HYAS.DynamicDNS.domain_creator_ip | String | The ip address of the domain creator | 
| HYAS.DynamicDNS.email | String | The email address connected to the domain | 


#### Command Example
```!hyas-get-dynamic-dns-records-by-indicator indicator_type="ip" indicator_value="4.4.4.4" ```

#### Context Example
```json
{
    "HYAS": {
        "DynamicDNS": [
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2019-03-30T14:39:49Z",
                "created_geo": null,
                "created_ip": "78.191.27.210",
                "domain": "seyir.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "78.191.25.0",
                "email": "halbayrak75@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2020-05-09T03:39:28Z",
                "created_geo": null,
                "created_ip": "42.3.24.108",
                "domain": "tempoary.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "42.3.24.36",
                "email": "benson877204@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2020-05-09T03:39:24Z",
                "created_geo": null,
                "created_ip": "42.3.24.108",
                "domain": "bensonwonghk.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "42.3.24.108",
                "email": "benson877204@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2020-02-28T22:32:59Z",
                "created_geo": null,
                "created_ip": "8.47.64.2",
                "domain": "benhuabenhua.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "8.47.64.2",
                "email": "bhua@paloaltonetworks.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2021-04-13T01:25:56Z",
                "created_geo": null,
                "created_ip": "177.156.128.127",
                "domain": "netvirtua-test.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "179.162.29.32",
                "email": "jeison.hinckel@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2020-04-11T17:01:31Z",
                "created_geo": null,
                "created_ip": "38.113.188.72",
                "domain": "sftp.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "",
                "email": "hezarkhani@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2020-04-11T17:01:15Z",
                "created_geo": null,
                "created_ip": "38.113.188.72",
                "domain": "mysql.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "",
                "email": "hezarkhani@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2020-04-11T17:01:08Z",
                "created_geo": null,
                "created_ip": "38.113.188.72",
                "domain": "btcex.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "",
                "email": "hezarkhani@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2019-02-26T19:04:08Z",
                "created_geo": null,
                "created_ip": "72.12.197.242",
                "domain": "hackme1.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "72.12.197.242",
                "email": "michaelaharrison@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2016-02-24T10:45:19Z",
                "created_geo": null,
                "created_ip": "",
                "domain": "fbport.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "",
                "email": "luizfbi01@gmail.com#persona"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2019-05-16T02:13:52Z",
                "created_geo": null,
                "created_ip": "24.193.56.4",
                "domain": "mobilelab.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "24.193.56.4",
                "email": "hsinewyork@gmail.com"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2017-01-26T15:37:27Z",
                "created_geo": null,
                "created_ip": "188.83.48.112",
                "domain": "mmmestanza.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "188.83.48.112",
                "email": "rurik1944@sapo.pt#facebook"
            },
            {
                "a_record": "4.4.4.4",
                "a_record_geo": null,
                "account": "free",
                "created": "2020-09-05T15:08:53Z",
                "created_geo": null,
                "created_ip": "65.48.218.90",
                "domain": "tbsdp.duckdns.org",
                "domain_creator_geo": null,
                "domain_creator_ip": "209.59.90.208",
                "email": "chadlettsome@gmail.com"
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
>| 4.4.4.4 | free | 2020-02-28T22:32:59Z | 8.47.64.2 | benhuabenhua.duckdns.org | 8.47.64.2 | bhua@paloaltonetworks.com |
>| 4.4.4.4 | free | 2021-04-13T01:25:56Z | 177.156.128.127 | netvirtua-test.duckdns.org | 179.162.29.32 | jeison.hinckel@gmail.com |
>| 4.4.4.4 | free | 2020-04-11T17:01:31Z | 38.113.188.72 | sftp.duckdns.org |  | hezarkhani@gmail.com |
>| 4.4.4.4 | free | 2020-04-11T17:01:15Z | 38.113.188.72 | mysql.duckdns.org |  | hezarkhani@gmail.com |
>| 4.4.4.4 | free | 2020-04-11T17:01:08Z | 38.113.188.72 | btcex.duckdns.org |  | hezarkhani@gmail.com |
>| 4.4.4.4 | free | 2019-02-26T19:04:08Z | 72.12.197.242 | hackme1.duckdns.org | 72.12.197.242 | michaelaharrison@gmail.com |
>| 4.4.4.4 | free | 2016-02-24T10:45:19Z |  | fbport.duckdns.org |  | luizfbi01@gmail.com#persona |
>| 4.4.4.4 | free | 2019-05-16T02:13:52Z | 24.193.56.4 | mobilelab.duckdns.org | 24.193.56.4 | hsinewyork@gmail.com |
>| 4.4.4.4 | free | 2017-01-26T15:37:27Z | 188.83.48.112 | mmmestanza.duckdns.org | 188.83.48.112 | rurik1944@sapo.pt#facebook |
>| 4.4.4.4 | free | 2020-09-05T15:08:53Z | 65.48.218.90 | tbsdp.duckdns.org | 209.59.90.208 | chadlettsome@gmail.com |


### hyas-get-whois-records-by-indicator
***
Returns WHOIS records for the provided indicator value.


#### Base Command

`hyas-get-whois-records-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: Domain, Email, Phone. Possible values are: domain, email, phone. | Required | 
| indicator_value | Indicator value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.WHOIS.address | Unknown | address | 
| HYAS.WHOIS.city | Unknown | city | 
| HYAS.WHOIS.country | Unknown | country | 
| HYAS.WHOIS.domain | String | The domain of the registrant | 
| HYAS.WHOIS.domain_2tld | String | The second-level domain of the registrant | 
| HYAS.WHOIS.domain_created_datetime | String | The date and time when the whois record was created | 
| HYAS.WHOIS.domain_expires_datetime | String | The date and time when the whois record expires | 
| HYAS.WHOIS.domain_updated_datetime | String | The date and time when the whois record was last updated | 
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
```!hyas-get-whois-records-by-indicator indicator_type="domain" indicator_value="dulieuonline.net"```

#### Context Example
```json
{
    "HYAS": {
        "WHOIS": [
            {
                "address": [],
                "city": [
                    "hcm"
                ],
                "country": [
                    "VN"
                ],
                "data": null,
                "datetime": "2019-10-31T09:04:17.870095Z",
                "domain": "dulieuonline.net",
                "domain_2tld": null,
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": "2019-10-31T09:04:17.873274Z",
                "email": [
                    "viendongonline@gmail.com"
                ],
                "idn_name": null,
                "meta_data": {
                    "data": {
                        "city": [
                            "hcm"
                        ],
                        "collected_date": "2019-10-30T07:00:00+00:00",
                        "country": [
                            {
                                "alpha_2": "VN",
                                "alpha_3": "VNM",
                                "name": "Viet Nam",
                                "numeric": "704"
                            },
                            {
                                "alpha_2": "VN",
                                "alpha_3": "VNM",
                                "name": "Viet Nam",
                                "numeric": "704"
                            },
                            {
                                "alpha_2": "VN",
                                "alpha_3": "VNM",
                                "name": "Viet Nam",
                                "numeric": "704"
                            }
                        ],
                        "create_date": "2019-10-29T09:48:04+00:00",
                        "email": [
                            "viendongonline@gmail.com"
                        ],
                        "expire_date": "2020-10-29T09:48:04+00:00",
                        "name": [
                            "hieu"
                        ],
                        "nameservers": [
                            "viendong.earth.orderbox-dns.com",
                            "viendong.mars.orderbox-dns.com",
                            "viendong.mercury.orderbox-dns.com",
                            "viendong.venus.orderbox-dns.com"
                        ],
                        "phone": [
                            "+84909095309"
                        ],
                        "postal_code": [
                            "700000"
                        ],
                        "registrar_name": "pdr ltd. d/b/a publicdomainregistry.com",
                        "state": [
                            "other"
                        ],
                        "update_date": "2019-10-29T09:48:04+00:00"
                    },
                    "updated": "2019-10-31T09:04:17.873274",
                    "version": "1.03"
                },
                "name": [
                    "hieu"
                ],
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
                "registrar": "pdr ltd. d/b/a publicdomainregistry.com",
                "whois_hash": null,
                "whois_id": null
            },
            {
                "address": [],
                "city": [
                    "hcm"
                ],
                "country": [
                    "VN"
                ],
                "data": null,
                "datetime": "2019-10-30T06:23:09.540756Z",
                "domain": "dulieuonline.net",
                "domain_2tld": null,
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": "2019-10-30T06:23:09.543083Z",
                "email": [
                    "viendongonline@gmail.com",
                    "hostmaster@dulieuonline.net"
                ],
                "idn_name": null,
                "meta_data": {
                    "data": {
                        "city": [
                            "hcm"
                        ],
                        "country": [
                            {
                                "alpha_2": "VN",
                                "alpha_3": "VNM",
                                "name": "Viet Nam",
                                "numeric": "704"
                            },
                            {
                                "alpha_2": "VN",
                                "alpha_3": "VNM",
                                "name": "Viet Nam",
                                "numeric": "704"
                            }
                        ],
                        "create_date": "2019-10-29T09:48:04+00:00",
                        "email": [
                            "viendongonline@gmail.com",
                            "hostmaster@dulieuonline.net"
                        ],
                        "expire_date": "2020-10-29T09:48:04+00:00",
                        "name": [
                            "hieu"
                        ],
                        "phone": [
                            "+84909095309"
                        ],
                        "postal_code": [
                            "700000",
                            "70000"
                        ],
                        "registrar_name": "pdrltd.d/b/apublicdomainregistry.com",
                        "state": [
                            "other",
                            "bentre"
                        ]
                    },
                    "updated": "2019-10-30T06:23:09.543083",
                    "version": "1.03"
                },
                "name": [
                    "hieu"
                ],
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
                "registrar": "pdrltd.d/b/apublicdomainregistry.com",
                "whois_hash": null,
                "whois_id": null
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
                "data": null,
                "datetime": "2019-10-29T00:00:00Z",
                "domain": "dulieuonline.net",
                "domain_2tld": "dulieuonline.net",
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": null,
                "email": [
                    "viendongonline@gmail.com",
                    "dns@cloudflare.com"
                ],
                "idn_name": null,
                "meta_data": {
                    "state_list": null,
                    "state_raw": null
                },
                "name": [
                    "hieu"
                ],
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
                "registrar": "pdr ltd. d/b/a publicdomainregistry.com",
                "whois_hash": null,
                "whois_id": null
            },
            {
                "address": [],
                "city": [
                    "hcm"
                ],
                "country": [
                    "VN"
                ],
                "data": null,
                "datetime": "2019-10-31T01:09:53.931763Z",
                "domain": "dulieuonline.net",
                "domain_2tld": null,
                "domain_created_datetime": "2019-10-29T09:48:04Z",
                "domain_expires_datetime": "2020-10-29T09:48:04Z",
                "domain_updated_datetime": "2019-10-31T01:09:53.933724Z",
                "email": [
                    "viendongonline@gmail.com",
                    "abuse-contact@publicdomainregistry.com"
                ],
                "idn_name": null,
                "meta_data": {
                    "data": {
                        "city": [
                            "hcm"
                        ],
                        "collected_date": "2019-10-30T20:13:27+00:00",
                        "country": [
                            {
                                "alpha_2": "VN",
                                "alpha_3": "VNM",
                                "name": "Viet Nam",
                                "numeric": "704"
                            },
                            {
                                "alpha_2": "VN",
                                "alpha_3": "VNM",
                                "name": "Viet Nam",
                                "numeric": "704"
                            },
                            {
                                "alpha_2": "VN",
                                "alpha_3": "VNM",
                                "name": "Viet Nam",
                                "numeric": "704"
                            }
                        ],
                        "create_date": "2019-10-29T09:48:04+00:00",
                        "email": [
                            "viendongonline@gmail.com",
                            "abuse-contact@publicdomainregistry.com"
                        ],
                        "expire_date": "2020-10-29T09:48:04+00:00",
                        "name": [
                            "hieu"
                        ],
                        "nameservers": [
                            "viendong.earth.orderbox-dns.com",
                            "viendong.mars.orderbox-dns.com",
                            "viendong.mercury.orderbox-dns.com",
                            "viendong.venus.orderbox-dns.com"
                        ],
                        "phone": [
                            "+84909095309"
                        ],
                        "postal_code": [
                            "700000"
                        ],
                        "registrar_name": "pdr ltd. d/b/a publicdomainregistry.comvien dong co., ltd.",
                        "state": [
                            "other"
                        ],
                        "update_date": "2019-10-30T20:13:27+00:00"
                    },
                    "updated": "2019-10-31T01:09:53.933724",
                    "version": "1.03"
                },
                "name": [
                    "hieu"
                ],
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
                "registrar": "pdr ltd. d/b/a publicdomainregistry.comvien dong co., ltd.",
                "whois_hash": null,
                "whois_id": null
            },
            {
                "address": [],
                "city": [
                    "ha noi"
                ],
                "country": [],
                "data": null,
                "datetime": "2016-12-07T06:05:05.230927Z",
                "domain": "dulieuonline.net",
                "domain_2tld": null,
                "domain_created_datetime": "2015-05-22T00:00:00Z",
                "domain_expires_datetime": "2016-05-22T00:00:00Z",
                "domain_updated_datetime": "2017-06-14T19:06:36.577650Z",
                "email": [
                    "ngoc.mycomputer@gmail.com"
                ],
                "idn_name": null,
                "meta_data": {
                    "data": {
                        "city": [
                            "ha noi"
                        ],
                        "collected_date": "2015-05-23T00:00:00+00:00",
                        "country": [
                            {
                                "alpha_2": "VIETNAM",
                                "alpha_3": "VIETNAM",
                                "name": "VIETNAM",
                                "numeric": -1
                            },
                            {
                                "alpha_2": "VIETNAM",
                                "alpha_3": "VIETNAM",
                                "name": "VIETNAM",
                                "numeric": -1
                            },
                            {
                                "alpha_2": "VIETNAM",
                                "alpha_3": "VIETNAM",
                                "name": "VIETNAM",
                                "numeric": -1
                            }
                        ],
                        "create_date": "2015-05-22T00:00:00+00:00",
                        "email": [
                            "ngoc.mycomputer@gmail.com"
                        ],
                        "expire_date": "2016-05-22T00:00:00+00:00",
                        "name": [
                            "ong phan van ngoc"
                        ],
                        "nameservers": [
                            "ns1.inet.vn",
                            "ns2.inet.vn"
                        ],
                        "phone": [
                            "+84986386242"
                        ],
                        "postal_code": [
                            "10000"
                        ],
                        "registrar_name": "onlinenic, inc.",
                        "state": [
                            "hni"
                        ],
                        "update_date": "2015-05-22T00:00:00+00:00"
                    },
                    "updated": "2017-06-14T19:06:36.577650",
                    "version": "1.03"
                },
                "name": [
                    "ong phan van ngoc"
                ],
                "nameserver": [
                    "ns2.inet.vn",
                    "ns1.inet.vn"
                ],
                "phone": [
                    {
                        "phone": "+84986386242",
                        "phone_info": {
                            "carrier": "Viettel",
                            "country": "Vietnam",
                            "geo": "Vietnam"
                        }
                    }
                ],
                "privacy_punch": false,
                "registrar": "onlinenic, inc.",
                "whois_hash": null,
                "whois_id": null
            }
        ]
    }
}
```

#### Human Readable Output

>### HYAS WHOIS records for domain : dulieuonline.net
>|Address|City|Country|Domain|Domain_2tld|Domain Created Time|Domain Expires Time|Domain Updated Time|Email Address|IDN Name|Nameserver|Phone Info|Privacy_punch|Registrar|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | hcm | VN | dulieuonline.net | None | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | 2019-10-31T09:04:17.873274Z | viendongonline@gmail.com | None | viendong.mars.orderbox-dns.com,<br/>viendong.venus.orderbox-dns.com,<br/>viendong.mercury.orderbox-dns.com,<br/>viendong.earth.orderbox-dns.com | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | false | pdr ltd. d/b/a publicdomainregistry.com |
>|  | hcm | VN | dulieuonline.net | None | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | 2019-10-30T06:23:09.543083Z | viendongonline@gmail.com,<br/>hostmaster@dulieuonline.net | None |  | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | true | pdrltd.d/b/apublicdomainregistry.com |
>| 32 duong 885 kp 5 tt ba tri,<br/>vn | hcm | VN | dulieuonline.net | dulieuonline.net | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | None | viendongonline@gmail.com,<br/>dns@cloudflare.com | None |  | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | true | pdr ltd. d/b/a publicdomainregistry.com |
>|  | hcm | VN | dulieuonline.net | None | 2019-10-29T09:48:04Z | 2020-10-29T09:48:04Z | 2019-10-31T01:09:53.933724Z | viendongonline@gmail.com,<br/>abuse-contact@publicdomainregistry.com | None | viendong.mars.orderbox-dns.com,<br/>viendong.venus.orderbox-dns.com,<br/>viendong.earth.orderbox-dns.com,<br/>viendong.mercury.orderbox-dns.com | {'phone': '+84909095309', 'phone_info': {'carrier': 'MobiFone', 'country': 'Vietnam', 'geo': 'Vietnam'}} | false | pdr ltd. d/b/a publicdomainregistry.comvien dong co., ltd. |
>|  | ha noi |  | dulieuonline.net | None | 2015-05-22T00:00:00Z | 2016-05-22T00:00:00Z | 2017-06-14T19:06:36.577650Z | ngoc.mycomputer@gmail.com | None | ns2.inet.vn,<br/>ns1.inet.vn | {'phone': '+84986386242', 'phone_info': {'carrier': 'Viettel', 'country': 'Vietnam', 'geo': 'Vietnam'}} | false | onlinenic, inc. |


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
| HYAS.WHOISCurrent.items.abuse_emails | Unknown | abuse emails | 
| HYAS.WHOISCurrent.items.address | Unknown | address | 
| HYAS.WHOISCurrent.items.city | Unknown | city | 
| HYAS.WHOISCurrent.items.country | Unknown | country | 
| HYAS.WHOISCurrent.items.data | String | country | 
| HYAS.WHOISCurrent.items.datetime | String | datetime | 
| HYAS.WHOISCurrent.items.domain | String | The domain of the registrant | 
| HYAS.WHOISCurrent.items.domain_2tld | String | The second-level domain of the registrant | 
| HYAS.WHOISCurrent.items.domain_created_datetime | String | The date and time when the whois record was created | 
| HYAS.WHOISCurrent.items.domain_expires_datetime | String | The date and time when the whois record expires | 
| HYAS.WHOISCurrent.items.domain_updated_datetime | String | The date and time when the whois record was last updated | 
| HYAS.WHOISCurrent.items.email | Unknown | email | 
| HYAS.WHOISCurrent.items.idn_name | String | The international domain name | 
| HYAS.WHOISCurrent.items.meta_data | String | Meta Data | 
| HYAS.WHOISCurrent.items.name | Unknown | name | 
| HYAS.WHOISCurrent.items.nameserver | Unknown | nameserver | 
| HYAS.WHOISCurrent.items.organization | Unknown | organization | 
| HYAS.WHOISCurrent.items.phone | String | The phone number | 
| HYAS.WHOISCurrent.items.registrar | String | The domain registrar | 
| HYAS.WHOISCurrent.items.state | Unknown | The state | 
| HYAS.WHOISCurrent.items.whois_hash | String | The whois hash | 
| HYAS.WHOISCurrent.items.whois_id | String | The whois id | 
| HYAS.WHOISCurrent.items.whois_nameserver | Unknown | The whois nameserver details | 
| HYAS.WHOISCurrent.items.whois_pii | Unknown | The whois pii details | 


#### Command Example
```!hyas-get-whois-current-records-by-domain domain="www.hyas.com"```

#### Context Example
```json
{
    "HYAS": {
        "WHOISCurrent": {
            "items": [
                {
                    "abuse_emails": [
                        "abuse@godaddy.com"
                    ],
                    "address": [],
                    "city": [],
                    "country": [
                        "Canada"
                    ],
                    "data": null,
                    "datetime": "2021-07-09T11:17:03.611218Z",
                    "domain": "hyas.com",
                    "domain_2tld": "hyas.com",
                    "domain_created_datetime": "2001-05-01T23:42:14",
                    "domain_expires_datetime": "2026-05-01T23:42:14",
                    "domain_updated_datetime": "2020-06-30T15:43:39",
                    "email": [],
                    "idn_name": null,
                    "meta_data": null,
                    "name": [],
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
                    ],
                    "whois_hash": null,
                    "whois_id": "70195358_DOMAIN_COM-VRSN",
                    "whois_nameserver": [
                        {
                            "domain": "ns09.domaincontrol.com",
                            "domain_2tld": "ns09.domaincontrol.com",
                            "whois_related_nameserver_id": null
                        },
                        {
                            "domain": "ns10.domaincontrol.com",
                            "domain_2tld": "ns10.domaincontrol.com",
                            "whois_related_nameserver_id": null
                        }
                    ],
                    "whois_pii": [
                        {
                            "address": null,
                            "city": null,
                            "data": null,
                            "email": null,
                            "geo_country_alpha_2": "Canada",
                            "name": null,
                            "organization": "HYAS Infosec Inc.",
                            "phone_e164": null,
                            "state": "British Columbia",
                            "whois_related_pii_id": null,
                            "whois_related_type": null
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

>### HYAS WHOISCurrent records for domain : www.hyas.com
>|Abuse Emails|Address|City|Country|Data|Datetime|Domain|Domain_2tld|Domain Created Time|Domain Expires Time|Domain Updated Time|Email Address|IDN Name|Meta Data|Name|Nameserver|Organization|Phone Number|Registrar|State|Whois Hash|Whois ID|Whois Nameserver|Whois PII|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| abuse@godaddy.com |  |  | Canada | None | 2021-07-09T11:17:03.611218Z | hyas.com | hyas.com | 2001-05-01T23:42:14 | 2026-05-01T23:42:14 | 2020-06-30T15:43:39 |  | None | None |  | ns09.domaincontrol.com,<br/>ns10.domaincontrol.com | HYAS Infosec Inc. |  | GoDaddy.com, LLC | British Columbia | None | 70195358_DOMAIN_COM-VRSN | {'domain': 'ns09.domaincontrol.com', 'domain_2tld': 'ns09.domaincontrol.com', 'whois_related_nameserver_id': None},<br/>{'domain': 'ns10.domaincontrol.com', 'domain_2tld': 'ns10.domaincontrol.com', 'whois_related_nameserver_id': None} | {'address': None, 'city': None, 'data': None, 'email': None, 'geo_country_alpha_2': 'Canada', 'name': None, 'organization': 'HYAS Infosec Inc.', 'phone_e164': None, 'state': 'British Columbia', 'whois_related_pii_id': None, 'whois_related_type': None} |


### hyas-get-malware-samples-records-by-indicator
***
Returns Malware Sample records for the provided indicator value.


#### Base Command

`hyas-get-malware-samples-records-by-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_type | Indicator Type. Possible values are: Domain, IPV4, HASH. Possible values are: domain, ipv4, md5. | Required | 
| indicator_value | Indicator value to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HYAS.MALWARESAMPLES.datetime | String | The date which the sample was processed | 
| HYAS.MALWARESAMPLES.domain | String | The domain of the sample | 
| HYAS.MALWARESAMPLES.ipv4 | String | The ipv4 of the sample | 
| HYAS.MALWARESAMPLES.ipv6 | String | The ipv6 of the sample | 
| HYAS.MALWARESAMPLES.md5 | String | The md5 of the sample | 
| HYAS.MALWARESAMPLES.sha1 | String | The sha1  of the sample | 
| HYAS.MALWARESAMPLES.sha256 | String | The sha256 of the sample | 


#### Command Example
```!hyas-get-malware-samples-records-by-indicator indicator_type="domain" indicator_value="butterfly.bigmoney.biz"```

#### Context Example
```json
{
    "HYAS": {
        "MalwareSamples": [
            {
                "datetime": "2021-06-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f8e537c178999f4ab1609576c6f5751e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2021-05-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a20473e3a24c52ac3d89d7489b500189",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2021-05-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5fb3ee62c7bd0d801d76e272f51fe137",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2021-03-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "088a7aaf18ae930086a62767a106b3a3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2021-02-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "20a4fff1d0d7b5636713574f1eff4f75",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2021-01-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "45465c3259f3b14cda195a1fd618057b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-12-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1ace32d465cd5e70217a7fd51b48cb19",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-12-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "50dc274203443ee6c7c550aa81e60336",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-12-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a58ae7ca91959f940a34ee11788687c8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-11-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "afb386c2061a09d8495070209bd7cc14",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-11-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8245e4c82e6cfcc6e31f5c17cfba23e4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-11-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7750f8b7ecfe2274fd4a9cf187e58510",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-10-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "509e6331efe3d3d76908362308ee6018",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-10-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5cb50bca257e7c7b1370ab095a792ac4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-10-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c59b7375f416bbef2fab67f4610c1171",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-10-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a95f3db489d526484862f54c1e3aa1a9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-10-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e01aec8b2f39497868c238be793dd52d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-10-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d0f7a8c5050cfdb9bf562988582b9731",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-10-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e4d33c1c7647c37e77c63164d71607d5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-10-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4f8832b52d61cbfc944bb3b879d3b69e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "550219bd15f015b8a0a14ca57ae8a414",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1035bb8c9a20f3fe464901a301517ded",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "65f710a80b7f11f5da725d9876057aac",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "68248be052f137cbb4bdf02ead7a0603",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f290a1a7282b617de4ab6c9fa5345be0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a02aab50a7d4bcceaebb542957d11787",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0df9553cd1663c61dbdbb0f2b5d5dfe3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "af13a97ca7e6544fb02858b3662da902",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3a6e2b19a7d4a5344f47aac0e0a0f9a6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "489703a4d98abd26d8e71df7ee423498",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "542ed16d3908c857f91e1030b6c1b2e1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7d6abb1d56d071da2b1e774b2c05f402",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2fb8f759df4671392e019f3aab54dad1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2400bac8df12b358058112d2df20043f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "20c78cd790c321150dfa9f0d14e0a8a3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cd207249556b2b1d4f9e430d93d03150",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "95de7ab20ecaeb6b62b3748aa58ece5b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1e74bfb1fbfbc416bb7d8a81d10e1568",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1a35b2cec676bc8ae085f710e8de01b4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "63a60aceedbea3323b9218137b3c7a4c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "32e9bf29be5fff790d75128885b5d033",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1c86f2b825f6c0a85df49c39baca8774",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3022cf136a0370bf89fd380f8c6c50c7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4c2f858cda5025a5c5d0581905066066",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "00dfbb6e2b1ea9f9e64a6a4c52013ea5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "34f1c341a9d6ad122adf2b23ff47b9d2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "48539b7cae582281e7f0345a513b649d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5102776a209876ceb830b7d37d0cd3ab",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1dc5ad0b772fae562bd2b12d8fb5636f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "50080ae048f880b3c020c7ae3b046de8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6de2aead9cdbb25000ba4df2fd65e06b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0c05fef8f63cc66c465cf35ff1bfcbc9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "51c02cf617dfe1de7737b078d89ad2e7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b51a8c2eb58205f8886178cb49bad82f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "de5eda96416f3396b81606628b31db26",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1d0a97c41afe5540edd0a8c1fb9a0f1c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "be63b545e4db052b4b9d883c8cf1aca8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-06-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5a7fe21d3602d744cc9c1b6b87905d6b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bfce9b599be4d19a41db83c1d246c115",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "29490ad77e83711d74718b47956c4fbd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-06-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a7cc1fc0c3a17947614c5219707992de",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-06-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "205ece692dc220d2b9c24c3df0cf151f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "18cc9481f19970c83ab851714e869e45",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-05-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "65138219d7010e09955b705175cc562c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-05-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2d80bd8cf692ab3e50d0ec7d7389d170",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-05-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "15c4d604cb588648aeafbee7701ecd17",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-04-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4e2820e2296dab73f5d6cadcab5e7f93",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-04-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c84e05322eea41a6bc8555095adaaf2a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-04-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4167f3dc806534677c846b6a2e120d61",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-03-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "39f191a005bf5684b0b9dec3865687c3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-03-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ed1b61424bb01692de170c9f489cf7bc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-03-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1c91986ae2fc3d06eb81c8546b111126",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-03-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2fd19fefb30ff49c86e038ba686a88d7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-03-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8718990dde34f090f748f9c9d1e8743a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-03-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "21135ba76c934db12c335587510fec42",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-03-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "9b3d10d767154028421588937f7aca17",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-03-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "752332b2db68a755dd27c7afad6fd66b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "dad6552a69d3a01c503fae664dc6868a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6f7b66962b86dcf37e207fb492357991",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c7340a198d26ff6ebbdcc94a49f623ef",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4cfbacd51c21395acfddc2ee43d6448b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f3a25aa11faf9c026da3baecb5821b14",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1ba7b062e267f98a05116249c0334218",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e17bd40796f9c84dbd04c900f3b4e656",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3cf37009b23568a5fb3752525ed1317e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fe15e25de57af4710842efde333ac82c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2704ba3c6ab5555f6504877945cf0d4d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8ee451cc477b992b004dc01609c73d19",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "09aa29adf5d64179b52e216234b434ec",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "dd853de2ddbe20fda219dee0ec147a64",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-02-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e3f6464d2358c56ff32962cffd6a4ffc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "53c10f35639cbcfc622d201f1577e7c0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "50d01f60138e9b390ded98ad1d9f766e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ee974d7aad24003b935bdaa798d28e27",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "02a051666b6b7ecc4796f60baab3904f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5dcea2477d72c6dde4f7a3039e5082c9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "267e30a164d416b0031e3d279538fecc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "740dcef7434cb496b535afe434fae775",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4e071af48a5e606fc840af4e736267d9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c8b9de94f9d10323bcaa51452cbb4e9d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "abea51528b73699844f1853ba9ad4d34",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6a28cb71aca3daafe4c3b375534e43ab",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2020-01-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "93435132e539efd77b604cc139ab41c1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-12-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "34f89e2205a147541cdd9f58cf554a88",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-12-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d9f921508a08e7549860f50a2e1c24bb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-11-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a5cea197f5d57c2fb28c511d41e82f49",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-10-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d6823f3aeaadd832d6ee9ce9b9e134d0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-10-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "02f81c9588f9f1efed70673969441d82",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-08-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c12df87d5d103dfcd29ee23bb6a8a7bf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-08-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6b6890d6e19234a3098be48d51441b4c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-08-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c3881adcf0b183030d6079bd176414cc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-07-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a14e96604a5d3c5295a42db6baf10f43",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-06-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "efb41846ece49dfce5433dcb4a554c5e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-06-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "07aca646403e8be0cdff358f1edf3a6a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-06-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f05eae423c40bc3c03654119e37d7d40",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-06-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0046ef697908c3c0524bab0f40d8e42f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-06-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8364456720732f56a28b4f10035794f7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-05-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "127427fc8e88d824cb625a239d8e4ad6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-05-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "59393f4dccfbbde9d5383f0fc197ad88",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-05-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5e2be0e19473445ab8ca8c62c0495057",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-05-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d9b010f538570244a30c2dbfe9e64678",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-05-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a45c18df4eafb085f63f275b79a281e6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-05-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "68ec0f4e366e51848b9c85fea2109a70",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-05-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "403679d99a62b43e43dfb3e7e3375d1a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "587c8a7b70ad63f6df5497ca7544152d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7f1695a5bf1ca9cf5d9a60db7c6721ac",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2e5c4a4935e10ada2f529d528e03d8f6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "59c33695fd8288145e25b2a9fce7585a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "24abaf4057d094c03807894bc26a9aa0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "adfc35525ced1e756a7112498ff406bc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b597f68fd89c0a3e8c3e3c1f7b55506b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d656e140b240926d04f4b3e407f52be5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a505c83fc3480e14c7ab98f731ec0efb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6bb7849d807d562246c6b211a17e8d80",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "9e7639bb083044e0586592fa263dcfd9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-04-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e32fa5622382775f7bb2cf5d23032696",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "022b3de9660194646d00923266c1ffb6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fe03f062f69df8c20b66d2599368c721",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8dd28280f8c0404c6675a5e66c6a44a4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1d89c4d3c3b1a645d4bfb30f9fba0b38",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "69bb6244cef66ccbb565385384fea4b7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ae7d1004da36086a2d3b34622472b626",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1de10fa0b8e75aefe67f49c74627852c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "839c052c0cc428ebbbaafd760204befc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-03-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "13798086aa328f09c1cd4e7bf77eac3a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-02-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7fa12f4ccdbeff8fd188029bc82d092c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-02-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "15f2f2871688c79e374a93635cf26c54",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-02-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5865d58d3a00af2a1597d5318b0f89cb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-02-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c53b49632d3048350fb40987248fadd8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-01-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d795f691900c531fb67f32a8753e31f5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2019-01-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "962dbbeb98a86c5475b75de4de610a6b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-12-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "398b59f0ba3d5c0e114a4956874ae25e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-12-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c09c2dfc0ae4655a6a4f8ee127167371",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-12-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a6801d64a12be7e65aad0bc4da94c85a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "be6d9355d76f84c9a06ecc972405f105",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "17069c1976ed3d8a6b08f3f916acdbf5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2c458b498c5562d49108918cdee8bcbf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "12ef71913c457a492c9c2f8bb8c8bc7d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3c73cf83b7f02b4d85f538edbcc935cf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "32c962a70f2beeca9987a494738e0269",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0a6869e67385ba4d6051323b6a77a3bb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "70671648159e30aeaf3abfcc5f434bb9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5a54de78f98cfcb519d380dbc165d65d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f2e6ba76ddf07173649c7a7f6b535534",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fc6a4a9148e6125eb7d0f8b1003c8b60",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "087a809879776cb4a2372d94e8ad2fbd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3727b40724b34c46b1cba03525473150",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-11-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "39fcf693544a795cd6d8cfe0c9c0aaa8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-10-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cc022eaa16c9171fb4a4d23d922ddd4a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-10-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bb2b916bd245b5fbafdd79665f7cf907",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-10-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "22329efb5602e1a501c95b8141b92b10",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "82f94e6efc767c0eace2e8fc85908581",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4027052359e30beda00f9fb5d696b2d3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6c0199606383fc92196bd940b79807a5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3de07f477ed09eabe963f89c12bf4d07",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "67c9d73422a41ada8a9a1a4f5068d1e0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8100f112798fee572118b47bdebf3b11",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6e56ca76f632880e596ae035fa785294",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5bd177e297325335617bb567cb3e84a1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-09-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c908bba2c49f233226ed3ba93ac0d697",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e0e75c4e4a76a2470108bea360a54b2c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-08-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "074001aee583f23483e8a41213270043",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-08-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "eb3f7bd20300e18f10b335b2a4bae961",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "9574154618eb372801bd99938e89cbb1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8943467e8a12d9b7d9b45a58c24884da",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-06-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "90c7c65c3ed14e4fea250a17d954596a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-06-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6cd6600fe6d05d2fab5b9a51ea4aa04f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-05-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fd37c332aa180ccb8ae90846f892a3e9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-05-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1ab79ff726cdfc5e7ace3e780301d8b0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-05-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "72920ed8816a9be5877c3ff7d4652eff",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-05-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c30ceca86ff4eaa98741b9caf26d980f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-05-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b8f1e3fdac633c842f1035fb25bc38ac",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-04-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6b8fc24ef1fb40919f41e0032f86171d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-04-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7bef86fdce599e031223a8b3f831135c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-04-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6fc53f8dbb27f627b9e170926a30d7d6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-04-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6b6a3ff264c7e71413380ff1b8251d4e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-03-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ddfdc1ec66159e404b902b6bd424a7e6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-03-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f47f17911057752eb335d96f3750b470",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-03-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f43b0c4feafbfe7779d0362ccbb2af1d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-03-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f662d80ee56853d309396bd2b56bc976",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-03-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f270731d9c5e47b9a6e74de40451a324",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-03-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f23e6e0e33b4187f9e7d633ff3c1a4c3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-03-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f0e3035df321267145e5cdb92eb46d71",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-03-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a4b794c660e150dc86a7607f23d40d87",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d95d81917ce3d6e9d30b6ccd0a659128",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d5c4f413ff93ce1a0e90c958ee17a2c9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d6e832f543fd7829ff20ccd73f247819",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d5107b76a328347f832acfd8fa966463",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d315aae6b60373c0915dace4684b3735",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d35524360a10a305db4c56cdb9bd08e2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d0c4c81b0e8f6d625aafcef84151e29b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cdceccb62c60b5556a27f3f41afabc32",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cb4029f5790ee26a773c3d6253cfc92a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cd2aa1429cd660741bcdbbc47521a066",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "12796670015a6fab9a567dc0e89b5f19",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e28a432fbc47c718de43a035cee596c1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ad1fbd9331eb0929532ded9abb8c4e57",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "aa0feb408929291f2cd9097253aac2ec",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a9ffad79d2397949fbe45a095c9cc44a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "da0e80f1fde52e0e9026a802d220d3e4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a39f1a531878bc834845978cdf49d802",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a7b48b1e26eeb265079f40645b134074",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a04939fcb508694fd3812300b5e80b17",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a25cfbb36aab214e22695e68b153cc7a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c72a0d27db64d08cc338d617cbce0e56",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ae326116a9dc4fb56f285d628145c603",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c3fdff018cd5110e3793c5bb164e7416",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bad4387323c39fd87524d5330ffbed0b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b8c42d022dd8f5d5798c854c1d92539c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bbeb677560353fabcf18f72e7098745f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b428f736386b32119bcc54f46055a636",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bc95fcc7a9f46c3b8ee359b636f83ee2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c3ab9c2a49cd2e331fd4800966a1d13b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bbac214eee51ba7057cf6efdafdd9254",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b9d5bd92257af80bcba42b836180ed62",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c617818c61aaef32a187b76b38816cd3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ae973d71cee0905fc2212648f5ce78d6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fee40580b42cc4a61839b88de4127e18",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fc68cb343580e6cdfd460434f47babbf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e254dc541514227e5e363eddca3a09d3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fafd7c7910c250caabcb49f37f0ac519",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e3c06358e84700f45d2e502c7bc9a6e8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f9cb7703a8a586c3be073c968c4e3df8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e85305916773e2dcfa7d0af6d701b86b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e6fe695a8e4dbd31f25899fd9f6dbed6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e03a3c0b168dfb285a25069ec7eb223b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ea820e8b3d38d0b1a0106b43c704b558",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-02-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e410d4314013bf7b40ebc7d34436ae79",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-01-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c083ddad629f73d847f976d111fb43a0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-01-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c4b787c7a88c14c578e300dffbe4a091",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2018-01-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "472d1fa0afa49caf633896890bf29dc5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-12-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "feb530f220ced765b78c4c0552657026",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-12-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6bf7ba8be55afb4abcc2e43f33abd373",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-12-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "27ec7502570a75593a1a3df35932c927",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-11-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8587c1a5eaf79a23f771cb0ae4acd536",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-11-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b8367a577869b20823f5a839f2ee5d2c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-10-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cb076b086f55fecc96631215ff90bf02",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c4aae791fb0b4afffb43b95be70df884",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ce68b3013979f010e2a8141e56dcc5e7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cf60186676c5551189202330a9673719",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "53d90edf6d35aad6879eb7b4e3894a98",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4a98d287db4674b941e7269bd2c2f91d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5de21421f215561fe9f33ed4adc92342",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "99c692763df76c6efffb5fd133194107",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "47a6b7b5766f44f56fbc88c4968e51e4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "136f1470771073c82bc44c5c717083a3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "12af58fa908ab0502bf3f9060262ce5f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "86e66b63ad2e9c0b3068193af3874b09",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d480c294a1b3594ef8183c0e08cd79ea",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5f57d6e77351b426628e97d3a052ac51",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-08-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ddfe22513e1f7fa2e158590e378c7e33",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-08-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "47d861bc6c00fbaf9cc05604480404df",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-08-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "708addbf38925110ea069fd6a46414a6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-06-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d60ab3d651898cde4bd09c8d22b332cd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-06-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "98e72458318cb94bb77a6c8184037e3c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0eee89ba99fcfebda48908e487ce5697",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c75f8e77f94ae662d95e248494d28a5e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-05-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e8e78159af4baa13ba1c7e5586f36041",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-05-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c110e12899bdc843f87cb87557867b63",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-05-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "91fa8bd953394108e3bc60ecc5ee6e4f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-05-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "11171f31a38951625e53deaa3867249b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-05-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "60070f8de9dce0acb642fcfe091b7e00",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-05-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5da5e62407229be674d0a2514ead99d9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-05-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3aa6ff6771a7f75a1e10ba4bbd826dbf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "491d0b723d2b43975f7c8d14d1e65fca",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b01c62a6febec86b9ae61cf06fb61d49",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "05889cc95d500398ac000d476d01b99c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "41dbad4043b69c8146d841bca8c83275",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3d699af1ddfb2c4b4c6043bb28f7e52f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8b98d189c121a19cc298ff66adfc8aa1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "22f03e7068a996664cbe49cba04d6736",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "18b229394afc06e01a6084ba6cdb5c1e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a7403dafb7ce5451cc71cf0dc7f607a5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-04-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "674cf3ac1d76b7f7dcd27a9eeb94f98d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-03-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ff90f1b439078ff49bd7a15fea878ce9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-03-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "abe1654ac0bc69c13c5e75f9a9c6c79a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-03-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d37bc88dd138f97fc8e7c9c5118bc2dd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-03-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "81174343e6c75366b838c78ecba3ce89",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-03-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7843709e1ce2b04f96ec84f8e5a33ec3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-03-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "be4f6f23d8fa10b65f4280ecd11fb0e0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-03-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "733beca7a60553082c4d15e8465e9000",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-02-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "81f4bfc51f485bc97c8be988e2ca32e3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-02-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "029473b78803c042c13799f2e3af1811",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-02-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "87837e855367fa67859fe0f450675b89",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-02-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e132fe5d106dd80c0336178bf01bb4bc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-02-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b5a450273de1d155bcc9c73fe959f75f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-02-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "50672ecb7551d4ec195442fd2ca1e5ab",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-02-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8b60f4fe520a696f6773d80a2e1a90f3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-01-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c527570daf3272e464bf347eb573d2c4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-01-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a654be686ff309966d30c8548be25cb1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2017-01-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b3fc71fa2bee4710a269a698f8f5312b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-12-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c990caec1785ab090727d0f421ba38e1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-12-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0d525e6f4540360b5680ab6bbaa974f1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-12-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b57a2e824a97d321de2faa391fc35157",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-12-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ea3f70c763b583601f4624e7ccb6d1a5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-12-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d2b43b2bf60cbf7a73b5944182e39373",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-12-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d9a13b27bbb00bd646f34f1cb8aa0cd1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-12-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": null,
                "ipv6": null,
                "md5": "c220d5ed213a056f6a5b0f417f6132bf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1b5f0e624b0268b3bedf99ce6af20a6e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a4fd456112fa16abae6dd0fe9f9948f1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5e4a76862caf152bd3d8337888651f3e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f5a47548230899be201781ea1543fbf6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cbc5686ef21927ff2cc3cebc04a7e103",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6455195cfa93c2e79f80b07736c430ed",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "68ae24ec22f6b7982799929bda4c48dc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e44b4c34e91b685e6c696c462f505b47",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c7ca91bd5b0d1af2a429af3875c0d752",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "488da89b86658c0438f481a390ebb4cd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c196113422bbc63cf45c252f930e7fee",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bf173495ab1751ce6d20d6f6e15d5cb1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ac0ff3ed33335d94ecadb5a367a75ccc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-11-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c89ad956251ced912b88932c62c99cc6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-10-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a9c080105dcad52126836d73cb8ffb70",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-10-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d9957548d5274ca296b8e616e4d686b9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-10-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3c220dce06d20cafde032fec38056200",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-10-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "25cd0c5c8cea691a59589b0a23ebf9e1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-10-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a1c9dc3e92b53b35c9336433a031033c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-10-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d26a5920493674116b6a2a18a9dc5e8d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d671735f0c4f4ffb163349e9564b73c9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cbedcac4d2c4aef525d5af1859e0726c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c33bf8206cde830fbcdcf56b918474f8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5e840cc5e027e6061fb2be714d3a9b68",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bd24ed7c8cd59f81d710ff2c89104aaa",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "816d5d6a3cbf4102a56d035b46f9f3fa",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a2424908ad9dbd60021d03c8a859e69d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a358c0843956f23e92cdfeb3776895e5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a7160a88a37335f2fbc279023f2abefe",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c42548e979aadaa98f5cd2f12b75cc7b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cf7c3c5cd01ff04a5fc121742e58a943",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a829a79ace799e7af732a1c6d2c133e1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ae1da3f81d564b4f1a2e3d3102b3a0e1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a48fd800ef828720c3e5e81bd25ee278",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ee7b34a77184da8f39ce7c4f03485f81",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "88a56a2df5089e942d63e652bc34a3fb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c60e83a3ef83c7718269e2f06fe65b39",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-09-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d33a75f6a139be81856fc55c219205b5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c2cadb6ce6ee1412fdb64ef1b5d02e4c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c8e7263035308dba8e3fcebcf4e74e80",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cd94f03082af14ce62b624dfd92ac09e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bcdd838c8d76af56272f2c2182db50a9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bef893402f938b34438b7fb52f28d58e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bd0cac288e410edf471d8da6c02cdeec",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ae6f05399cdf9727b20e613386a5184e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a84312536bf7e4ce07cb4d26e54b1900",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b7095dcdbcdcb78fad0bbd77eeb7c2fa",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "24ef011c7fdefdd34fe1865768ca745f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c94f1430521353a8b26ac2f720fe17a9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d205b8048e52cfbc3e3b97d6f538ef19",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b862814e1e45fa9ea29c7648ba6b3a16",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cf7c06514fdd3ff4dde0b2c249ecbc4a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bb0d0f27545ddb329c645942b5f1ba51",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bb5e518c9afcc4559937cd005060a64e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a6784d652f7937d3eede14731da5d939",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cc9e65fe92eceee550f73b90d8cf9ddd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "acafead9ef2ec8229f57bca816a68fa5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a114ab4d161aae417c66a27a0e1bd421",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b07d6f1e50f5f171d8a5b932bce09f59",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b41fe97243d346b3d50e43bf93979e2b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b125c163dcf9c5fb06ed0f88b436785d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b0c7f02020e54efcb2b739350c69c4af",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d203386806446f3e088ebe658bd3c4d1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ad9702f162ace2c6a63c394025647e6f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c31e24f97b9ccdc63c0451a8c7aef54d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bf86a8efef7982ddf3eec57cafeebf78",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bb4b33aa02a76642d29862405513b1de",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e3413e0b793b36e20485af45ef6dcf4d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e5ad5940a0d468a5528d26afa70894ea",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ceaac86874e4ba69a68dc647f3cf3b89",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bf5422f8345a2640356b9426a0948e2b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a65d9975ff6b43a09e3e23abaeb76a88",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a0dea1bce7f63d6d02661899929858a8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b870c4cdc5dca4e64525c7efd20086fa",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "aff352bde44ad640b77055d222b66530",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bbae3e4a922ef76e090e756e00b37d3d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cd49e88317be1906073e3b181286795a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a001384213e5904ee7bd68936d045549",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bb27ec38d9a5020d3bccbe0e9ce21652",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b40434607f4cb74a99ecbf8ddd3d2e5f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "dc079f942301cfe245474ced94456745",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b2e9c250581e47058c95fd38869ea1bf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a482349f3ded51822349192ed4ce8735",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ab1d84ebfa94ce712764b924592215cd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a0df92ed3b0832710ad2516415bda1a6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ab0fc214999f3616a00f9b2640acd106",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b52a405a082a25cd1497171e7deab63c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bfe8b427270b750324a4820b03a32c81",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b9b809748dcbdbc12ca6056bc31eb632",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ba538256af0bf6bd00367231d8b2a5a7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a6718af52bc5e139629c6c950734f78a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a018629eeb74fa8c6ba4c3df6615d2df",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a0ace8d23b5279bfb0de871d85f58ca6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c73dd6905e609fbc75171cbc236c2844",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c9cb2c7e431afd7ef23728c4aebfbef2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c82543e3c21e983d61dc3a702032edb7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "adf27978bd472c64cc8bcdb1a083f445",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bf2fb0a28df5829f397326eb4eb0c9d2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a3d820c665d65de5071ca87596dc4e4b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ca11b35f0c570860cda05a3c1a7b6ca6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bae3dc6b99c02dcd89b6f7ed8c1c797a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a7c0d0f235223ceb9a43fb9e68b2b0c6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "afcb7d8fea5442a4acf814088b4609da",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b583efa7cea4ecc67840bf1a605e0407",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a340d164e3eb3c21c9e620d77069f7e6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b04d3f6934b16295fa3dcd241ed94cd6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a8834d92bc82228936d72b9c3abc4e8e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b941c23710ac0fad5370a1763ae18d2d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "afaca331ff4373be8d7391731df47179",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bea6727a4a02732054a7bb6c607ccdeb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b7d7ca9fcfa72e7937099f99223ea878",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a2222d1c8ad09231147887c6be0e410c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a2ec8c31c18e524e0f9bcabcdd40805e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a58d01891bd33131069fa033caee1631",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ba8c5ce64f55381ff1212f0b383e4adc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ba4bdd29a7ee23fde17ce6afde4f9f5f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b669811aa416cd941defdf1229f3e794",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3bacfb88f322636922033e7efb152641",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b325c0d33f8b33ded1010d77caf6fce4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2016-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bc8352bc329724ecc096fecaafc7bfe9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-10-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4e3f4d259f13e5739d73b8494cbff808",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-10-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "04b71f5226f004e37c38cd780f5b571c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-10-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b0c37b18c76532a166d8ddf051744061",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-10-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1a11d68ff2e14600c7805feb946eb450",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "863d101664ad53163a6c474ae0814084",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8f8fd02c04db01ab30357cc3484010fd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8fd64ed8236981d82c19bd7a442a8537",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "308339d18e7f6bc521bcf78e260f546e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "657a510af7716efa3cec3460808cd9ee",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "106966ea73725a5eb0f0af25641bc3a4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1b3c2732a4139ee8d9462a8d3581b347",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f3deea76078bb70046b03b5796f43a34",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c64683804fea07baccccb50a47b6a675",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c6ce40b60db6f60e5765ab4f61132275",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e33b13066dbcebca0b39276f05a8fba1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0a1112ddd47831f4267e263aec336b3d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d8061326f8edd567b3540a9a7c7c7c41",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ab286de67a1d1edeff22520db303a721",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cad3b457ca2e5493f3c4b9cd6c36a7ce",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7afbdefaec9ebebff4e583b2ac6a99a6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b55b0ee9ff9b05b6785581741cabb98c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4c451afe7a7360287b548c20250d1cd9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "9f6b90029c7214193b7d16686b25917d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cb37c6c144bac63ead5abf58f6b0163c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bbfa0f4c8c6586628b7120fc07446ceb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c9f641849fff25c4643cda4723a60ad7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "33afc90b914d8d065d783d12ffbaf3a0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "266cfe4e377e2c515368912374203405",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3149aa3741543c0c3817f7acd7e06a09",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a2e5eeba19d4a8a404cce7e19fb8715b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "de80e0d158e954dedd19d7acdc531a7f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "37442afc905237cd6dc1e89b9bdb0b36",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "ebe083f30bba285d69da0085f283b10b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "fe2071dfcd3cd67276a29f4abb450820",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f30ac63c6059def8e268af4838f59019",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b92f99d535533e5facfd7eb545c2af65",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f03b444364b5472dc3109235a5bd870d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "f0232f8e3dafb034bd44568ed86899af",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "df639ecf9557231ade58aceb347e13cb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "dc3ed39e0fe39fdc4a458ddb893be7ea",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f99b5858cd73019f7d457af71fda0c36",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f0bbd6b9f87c99d32e61e232725d1798",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "fdffa611bd4b6658c32b38e7e184cae6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "127.0.0.2",
                "ipv6": null,
                "md5": "de7d53372a11440842ffd81efa445f24",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f48d465efcfc47ea12a4253bc095e9f9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "f551e82e2f92d95311d4f311a695db0c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7d4d5f08af7e549d8af252b9219fa1d1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "f1b98edc7f024ae5bb92460688432bba",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "463a7442b82a84f565dcecfdcb206ffc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "fff3df0197353b5c511a2b0cef724aaa",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f42a398d1f7f4ee22771c34e2c31b2bb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "d876e9d559ba2e4b278a02378200855b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f3048b6abe287f86889786b781d28563",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "dcbfdaf47919623d36a232312428a5bd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f5012ad9c13ba7f2b17001db9b46718c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "fc3c5d6fc8d891069fc9877ce49bd07f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "f70b7487c3813c0c4ed755cd7db7bcd4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "de7efee30b18b74c18ee7d974f2e166b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "fb872369a66611bdcc700f0ae386ca0b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f00e96e864703fe24ed85b3cfe5c6880",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "400742867b63d433c834b35b79deb92d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "ee6bef5712e8f76870ecac5dfdc1d3bb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "038fb610f48ebcc352e732c99fd1e622",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fdbec06d524b231eb2b2d8eab7fa4a94",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "f85f1130af653117b4f5be3d12245481",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "faa7ec3d679b4711a447b6a9189b5cbe",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "22ec47f2c536e2c5ee3080e5f9d68d28",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "f3b4c84f2e5db34d528a2faaef97cb85",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "f9ecbf532bb6f6c017fa0b72f7dcfa7d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "77f34e89e17de8b9b16a008d63e80007",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bd766e5ee7d7c0a22d8565c792000dd3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cb056fe4fe93984cd2420933ffd4761a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "f73967c2d0a4c4c635118b2710fd3068",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e77079d040d7bd48aeac8f0769959ebd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "f69b67799bd99fb404279a7a0b9ccac3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d8208c98574f1b5c13c6641113b4e99b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f302c8d18bcde7a6d4a5c092f58aea4a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6b340f0c7510f348b00d6231f23bd50d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "db2408b84f0901b62faf7e2a1aef6809",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d0e271a3a441bc7e04803f3156df5168",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-09-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d92a3dc83f7f4161908586aa306ad7a3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "15310164fbceba3c6fbd6257bb496a6f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "dc9a7ae4424cbb8e2b767ab71d5bcf30",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2c513da65bcb9a09e3bb78637af843dc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0b0eaefd8f4d1c98e2eda9d1e2928885",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2f67c32071b419bb94e8dddde9b21407",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "ddbb837f93d837308d8f289d413da0e5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ebc3d159f1fbea4b8dc5b0762bd31cdf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "d9d7d8534e893cd8b275f969066d61f0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "d723fe70ec0ba7b66f9d778ba1057447",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "d9ec8e5e45413e4b313638feea467820",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "46c4e2c8d586697e6fc6ed4ebcac5889",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "d419c716724b06ef74a8cb8a4a2639dd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "d28c314a8267a9a61f4534a4b30bd08f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "d3a2bd3bde6e98a3f219239cf8c64165",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "d216d117b7150cbaf07fc4efba38064e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "ca1ab5d7e0dfae4e11c1f44a2adcecc6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "390f42dc637c60f527583891ca46238d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "c5b0d8235a1d82699717a56c4cadb0f0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "beaf110af6f86783909d016ea00c3907",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bec6877cd8615753aad2c39953df6b88",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0535fe8608ca3716a01303e5cedd13d6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e140756abee7be1b07e6ddf00c94d8f4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d0aaaa7859b3184ce0f8bde5dbd8e0c6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4ff927a131a05c2310e686de2ab0afdc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "59df76c1bbf9281d11439f020990f8f7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3dd049b3122b766606f65630ab9dc066",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "65db1f061b5b21394a1364b2d4ec9d2e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4a7355c3cd94782808d89ea58f040fae",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "443f77ab64e00e55a70063769a084eed",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "bcb363dd3d58582b73d467945e3a9229",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "15e7ab91313ae174ea9dc7894dad8609",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bda6c0f23d400c5d55ef491487b4a7db",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "dbb6ccd948406c65c878823f77eca2a1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "bd46e08061bec10cb3c7be5ca6754af4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "b94b10bc1731e3364e86f89bbcec0ce4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1d04a84b08ff75a897e654fc795dad22",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "34ba602087d5abae00c42a288b1ac04e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1c425114941bd653c9682b922abdcc49",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "b906b6545fb62b472c52573fb7456e16",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c5cfbbe0b9937105135f7c886ae26f09",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "518a26c697ecda7723247b292ab6fa33",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2d32f9678a9af570ef8ae326581644f2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2489d943b2561fc0bce06d90a7e4a6cc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2de0326ff5165ebd4d2abc882d2c3476",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "30665caf4a010bfd9ba9727c94885bec",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4143a9f42c16c1d54d4c1102c1f3a954",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b08c413496fb617eb3310f4ed8b13697",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a99b54e5babbc105ea7a40f1eba9a9f5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6f7e9f9c39a16aaf9ffb149483a0131e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "651ba39923114fc894ae41783e73449e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ead794a64a18b04e01648418d0882a57",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4f47e7f832f2aa1762f451cbbe786896",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "b7410c693756acaee26dee55bcb03fca",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a0714af77d6f6ac099242a343eb4741a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a309afd50272ecfc87fb7600c2d77fa6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "62fb79036a196745362515692f0a4a83",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b155bf00edb39180285384f9ade5b982",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "af83e8ffde26561d05cb383f62b7b761",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "45488e080f41adaa566ee3b00f02237c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ac9f56bb9a73c27a0e085be100467d76",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "bb31d32910ab3dd542050490e9d9242f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a1066b9708203d9a92e2b3fa4bcb882e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "ba10c3260173c476706db0c189dda635",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "a7579cf6586c34d365ccc2638f2b8c55",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "b6da5f7231cd50bb867218e00d19fa29",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "b8d00f68a653d0a80809e101542bf949",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a9baefc3ca2daa790a8de1cd1baf02bd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "01164a6cad79acd32ecf8da6b8168b8e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "b63eb3c9ad19137117cc1298d63d474f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "b62e952e457f416d4430ca126af39f2f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d4acb9eca0e8dc1749238a827f785bac",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "b1f232b5f5d19e59ccc3af2478b14327",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3a4b5bd8f6c2b76c80025f639ea5e80a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "b61d78842ccf46b8d89e04bdded179d8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-08-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "a2cfcc8fd5231bee4f849b984982a2d1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "a369146bc1a36aa5b5788cdeea3958ee",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f3a5c57c2b85c74b34fa7bc525aec5e0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "a05439071ff3d34deed8c96b66755313",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-31",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ea3a88da8025040e1fb70f4899b76f45",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "7d3710980a3a0d88dcb8b38d297627fb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "9bad4cb7f71cd9a45ea84f5a1df366e6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "9c112c80700dc8feca3ef9e90245a07c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "a473c2f676cc7807c60636e6218644e2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "70132aaf560b57e0a07b193e8a8e49e1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "9933e958ae795a8e75dee811971066ef",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f64c7f9ad2b37ee375b5e3b568fe1cdc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "96df3af41d896d23e641f0954b4c86a6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "a11e65006ca50dba4aadef784534bac6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0d12b2cc160a51738dcda34665a5fa28",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "90fae2a55379d31a15701877184c2d97",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "41960c7566c16edf4d4b25e3cfee524b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "8d863e7b619a9a61b72e2b50bb38e3a7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8346dc6d874b3287496d40d8374e8aec",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "99cb24bc6f951d950cc0335a5eb64f6b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "87e51957f14dd4eca8b284b6332fcd0b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.80.169",
                "ipv6": null,
                "md5": "891e758b2de0d59da531bcef231b643e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "9abb14277a366b863e07fd56154f86f3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8747863884c21494b2bb85533475c1a9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7004985bb72c947a3f3da3c286560e51",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.80.169",
                "ipv6": null,
                "md5": "819cd25eadfff55779357df7bea1b7b7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "8232e034cb29b1006bb69fed5fa06ab8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "97c351c96afcbbead6571ee99a09335d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "917863a51b078ca22ead42c0844ae4db",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "96eb7cc85592f67010a3b0e9840c0fe1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "94e4bf0b765c35f7bb1fe060e00ad969",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "91a2a24955067d757a85634ed222993f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "7ee46ac5fc4f5fbf9ad38ac05db18821",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "7819e30c8b31550de8ac6a00c7535018",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "93f323c5cd8b7102e8c1121dc99b5189",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "929de4f9cbc97d152225edf6cda5224a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "7538b10ffd7d30d8217c4aef7ef30924",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "733d41e157e8426cdbe07a27df695e73",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "099e9697241302ec756e3108f8b93763",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "6a656784ee4fe8237e080c7e0ebf84ab",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "417d798023983cc39adcb8ff192a7349",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "6bb151d7ecbc95ae1715fe2faa8279be",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "6b6bc5a1a8626ca99f9de1e2e1699066",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "6d12a48db6dbf584355eb9c79a31d98e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "6942f6c33932ff29a1743f7064b0c578",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "685376f8315271467015e9b2c5e0d228",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "6a034c3da9ad4962c5e2be9b6f1bcb3b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "699cabc2647d42ff86092078e292b7d9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "690a77827cc9d2cad8f81d8149dee38b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "6a9ed4db4ff3651550a009f35a9daa04",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "6a8d773e5d1c371165db50b7fab9c213",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d608c0ba5bd31a1846aa3246d547d174",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.80.169",
                "ipv6": null,
                "md5": "68e197d6e83f9cfd60a4bcd64887afa5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "69804ae9503211ac2c865e3f746effac",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "6a562bc41fb4d5d4da8ece17901aa5fe",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "69fc2fe1910f772e3b2b41a9b1d6fbb1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "67e1d40b54f5e47af665df8c2bc6c958",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "67a5ddebf65772069fb12260f0b74613",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "68284ea7f8d127f3d247c967d6754ed1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "67cfa204e1c448a84a87b0a550b42a46",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2c5a2d8b9cbe89545b51cc7b1f64164d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "995e50c7f1eeba613d10696c7d733a98",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "6842d071638461d7865528cdf7084127",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "6547d762e8dd1d6ab452ddc7254712ba",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "62820a79d265376f1250d609e59fad50",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "197c633df03bb6bb123f6fbd2276fe0f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "64a5aca8f8646d0821e6fd86d4a42dde",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "60f2cecb9ce42028685a471f4fcd84f4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "60b751ef26f940c6d1d05a0918b14ca8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "6117b36b64fd3f88a44308276ccdd83e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "61d150a8700ec43904c562f082e7e02b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7244df9d5356e5636d71fafa03dd9398",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5dea7447a17172ffc15e074a12fc532c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5f044290ae5c2f8992477c1d38d004ea",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.67.195",
                "ipv6": null,
                "md5": "5cc7660694654db4863caf77bb41e1d7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "58ed850bf3907a889dcdbc3b2af63726",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "558591a5cbc6c0cdee0e9835ad888199",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ef41b65e7b420fa0ca38a15d9c17fa7e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "55e02756713ea93b3f496f471809cbb7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5666bbfc3f5873fdd69b51b3d4887eeb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "537fdcd053b588e99cc78fa41dcc8e4d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "46777804ffb93692d79adbec565a1d74",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "542260af52e968413bcae6eb740b0f97",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.73.18",
                "ipv6": null,
                "md5": "53ae90fdfd5601fd42be7a267c21a4c6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "e4127f0221f0460ae2af35c409f5d0a1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4e04caa47c8d2530212973adbf155a61",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4dd68e09d17c8281d26eb33ed1eb4fe5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4e46b1650717086ca1cdee0eaafee624",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "503c35c6c6beaf173fbdc0b43e8e09a7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "5021cb452a2c8f6f0de3bec2d62f08fa",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "5075cf55b1700a85dcefaed3314856eb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "7c569fc12c7384c3cd83e172f59faded",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4dd6aabec5c7e0eba945f2ecfecb5d2d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4e07fd251688aa85bf05d3afb009a202",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "518ca900d2463587624573093dbdb1fd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f46bad1d0db1a19f7536b85ebcbc24c9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4ea11243194860a08083367b34e59d19",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "49e91830bb6d35df41c053fbbb24e194",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4d379449889da4a8088818b4c285bfce",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "4cc2f2e9ee94aef3f11b60f1e438a2ff",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c46101f576aa964ec806404788c6fd57",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4bb8e3d0844a4b797ed74859cbdc3615",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4b353d918afa74652acbe8be68de1798",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4db4b4355dd791d590f9e416a515650e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "dbd0ccf4f779ce9b447f806a29e8c0ff",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "77d31669b517fd4867504015d8548d9a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "39601d7a778132b4075b5a69a139859a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "49d6b46c941f263ead2e635d5d16ff49",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "482062b560a32f51de2fbf6191a17e60",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "4a972f73a5e888014d11e79e2d433ee0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "46be70f8fdedf330bd813ca96a38b44d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "36c38b0d2f01cd311e126cd0542005ec",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "473338795b6e8667668dc06fd21499bc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "75ee6cccca2fbbbb674e51dc2839993f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "451730eeb1409d3d8bbb1adad06800fd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cdb7c1a435955e1bbbb5bb527843249f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3257f90ceac5e897fdc1a7670b6fb079",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "74868092c868e7183829cdae8375032a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "418f2c9e73f46b623ce90eee30c03940",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "40c671da982c48f1224dff5116025219",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "74dbd77d9b29a28bbc46923e85835d86",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "42e88c8f664bcdf24b69eff4ddd248c6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d14e8b3826b458f95c83a22d755ff10d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3fce42a03fd3086c3e5cbf4899fd470a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "406363d4db3aae850064de45a4907f68",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "3fd9b998d568b83c1dddbec2f4006b4c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3d5d0cb5c088626a0f57cefce0fdb2f6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3f478b1de8cf566cfe3b857eb9b32aae",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "3f0c93f04b3b08918227f75eabb3bc15",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "711de5490271e0e5c705eb48cff3ff71",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "3b79c0e6e4135b11d08fcfe32520a9f3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3bdef55e39165030dd67840f58b08cad",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "3ba14fae43400ceff572bf99ab3a4685",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3b3f180ecf9d746baa125577623d4a16",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.79.202",
                "ipv6": null,
                "md5": "3d2b168643a0d32492ee75f0155657ef",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3ba3cedfefcb22d5755af7029dc28221",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3bbf7e7bee9622fa4cf2cb454458180e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "3b94d100f9d0e2244c0e48a53b610a64",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "3b9a2f850ffc98c78b72b1f30ec2f2de",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "9a69f8a033c86d1e6d97982456b3d38e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "3b8b30e789535f683879a25c9ccee13b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "7037d9b549803726fd0b26ead2c10f24",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "383a367265a2aa685018c6c074c32011",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3991c4d13c873e2c899494f7e9752c58",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3ad3a9ef0672f1e983d92aa6cfb5a3af",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3adb7c5922bf3d1fa0145a8ac39071d6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-04",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "39b4f1890c6fc22ffbf9ac6e41c47478",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "38aea1b4dfc4cb156c82c098a259874b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "396145b5c6fad1adf2d519fde64166a5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "373c5bf736f17f2ce6173dab74f02163",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1d0a40eeb2b35dd1fd5456e433318150",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "fb65683f10ae174f631848f297c6ee49",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "380edba4752b1358f4ee955425551c41",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "387191c902a826c8dc550c0841422681",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "6ce3d6eeeca6776f6699edd855601288",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-03",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "39c62271fbfec69d6d9acb2bc74518e7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "33a9b7dc5d2daaafed5be1ee164261b9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3410afac4c6ccd17dbe0d8169d818f3e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "36275c665c4a760c4ca61ddb9451b8bc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "33be4502c630b2d9bf6e788a78a8c6bb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "349411f7a9020ba79a723f81d7c81072",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "35645a31ebdc84b0839c463bbf176e99",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3618625ac68e0b099bf5272446735492",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "354c67e782120e226760b84ca79baa9e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "35089bb5279f53f6b9693842cfb1a370",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "365b856b69ef247e325e12ab2ac53725",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "365a0a08f21a63b578597ad3768302c6",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-02",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "345bbc63067db437d38defb4cab8ecb8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3365a35ac6d5156b1b79b4d760362bfe",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "21be290dc52e92d744d41a901b0e3f76",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-07-01",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3229dff5ab4d56ef185d8d5d7615e569",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f299125fb61f9fbce49409488d7d9e51",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "67edfd8fdd76e25e8768a0213fc7c595",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-30",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f039d7ca570161205577c51a4a17cecb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "30abd2b763c72dddc6ea711110c1930c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2f05840682f2a7c45407feee7a2c2efd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.80.169",
                "ipv6": null,
                "md5": "2f983284680a5d0c965887fe84fcf171",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "305ac55a9d29f940319e57c8b695e5c2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "30774972433e6a3c0b093912d51df382",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0a4af632053aa39c6cdf89a4b2568efe",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-29",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2f0ceeb1c78950bc5132c471572be412",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2e97d3516f28223770bbbce5aa535ba0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-28",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2e71ed5214d8fc8693a8efeaf3da8650",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.80.169",
                "ipv6": null,
                "md5": "2c9ad1005b9e5d038580e0226173240a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2caebab75140002bd908e723b05ca6fb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "5add2afe1b9af6d17bfe17913b128a24",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "019b2b93e4ab030da87a30d7c7dce131",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2cdd71e59f235f7ded759340756becbe",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-27",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2b8b1ce2b39cbdb3387e7d5bad5b871b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "63358e405a565f12bc0b809cdc08bbdc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "2a476df7d3c7028cfbe35652b0d56cc1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "2b644c5ed201ea461e7f620b512ca620",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2a672deadff5b2d06cb838cd5a4fef9d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-26",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ff31abb495750fbdc39f99dd3a7a6004",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "290e3e3ca66a8b63fba8005f11e2c16e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2972e423f3a5f20257da3fa1933445cf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "60e68bec0111e70ea7adebb750f4649a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "251b2a4e4ca0db6f2f368daa3802e206",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "28ef735ea7e6f23b7e8251fc9b5620ef",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "290e913a82e65e80dca2c202f0b8cda5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "297fe18c0944b07336bb5f1939dd593d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "f628e3a498321fefa23375a96b73d132",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "289aed5efeee9b3c4f3afea4afe4e6f2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-25",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "28a35360a56a522783fca21afcafa601",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5ee6b4604ede99ce8c3ed229de3f4018",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5ed1438288f5f43c2b77bda577d66085",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-24",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2845fc3341b87222ba06679b27b4c806",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2752791de8c67bbeadc1fb62e7a48997",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5d0fe2dd9b72a052ade432c26d202e3f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5dbe45edd60bfaa77020ef81144680f8",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "ec8e39a4e4b829e01952c0d093cbc45e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "ea20a8485ec84d8f49b5ff088672ec6d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "26c83fa1c99608c6bea19b33ba578db5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-23",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5c3b7fb32fa6997276b33861854d8682",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5ab0d4d072336418a6029d537c419d7a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "def9d97dc8ae8f66bab1979b36db0f0f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-22",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "268575bee897ffb3f961a1dc3b69a87b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "57d1e001d676dc7769eb51a96969c0f3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "25ed65cfc64d0ef6e39fa11421eb18ab",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.80.169",
                "ipv6": null,
                "md5": "259fd3c2cfaac42727522ef34a5fb695",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "db15b941dd8beeb23b67599aa10d1494",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "dbc9f64ecb5cf050ce1b979ac4106dad",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-21",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "25b8dfab085f44e023ec6f543bf00298",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "d1cf4870653e04e9f39efe53ee0de31c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "24f32bfe8935d07a8d15414e11c300e9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d1afa3b84e9d96b2bc9a88e8cc739ec3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-20",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "55ef3ff8c8859db8da1065bec62b9942",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "24c1f0209232cbcc6994298ee5800f8b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "cc44236d9b0cd1fd7b25bc44e1a5739e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "2454a5e2517927055c8054947d6fe41b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ce1239290263a915205cfc5a3655d4e9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "54b349a7dd3b2ca44d88d926e3ab80ac",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-19",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "24303feb1a7ea27b9e64adeba00790cb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "23e7ef6869608d40f5e6e4ef6cb364da",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "50b75a1b0654daf5294e62a8ae658595",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "5153b2b1772d001b4b5a163a07f52651",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-18",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c64e4db2c8b4f87d37defb071d050b29",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "bd46cb71ee51f2d9c79cbf7791bf320c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "a4e130ca56cfdd423f658ea57c93be0f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "4ea266739476e7db0f5bf849047f431b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4f203ae30061654ef4920f0be8f19101",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "c1ff850617553a56b173d65da2cc6c39",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "4f286cfeffe27a180dcd3661d0f887ed",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "c027e358ee144c40a6fb44f4657e267c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-17",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "231a0c4e70d488dc31be9964a01f7045",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "22d617bdc92ac729d8f876836fa4f7ce",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "f66cb0f2f9fbb8ef48e885a381ed3b7f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b9e3c8a8697218de1400531e7f612e39",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "4ad5603dfc6247e3b2195c4675e53478",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-16",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "4b508ab8ed46489187fc5c1ebbc0ee9b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ee2b28eff7a9615e73ca99b0f689b1c3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-15",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "48e964c18ee86cdc645dcb0f39890158",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "217f7390de363344ce2d3173f2f1c7b9",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "0f3b701195124e78bb07823b588ab9dd",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-14",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "217c5f9d3e74ed29a1c4b9d7e06379e5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "d89e51c0c740ec803c0ea7ec7079af4f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "20f8c0e3ea2868491b016d39c1dedfac",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "20a3418aead0fe919961c23a3c419811",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "ddfc4a11a762b750571b9e28afdf400c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "211ecc9f3c570d57636cb7910ab87a76",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-13",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "45151b2bb751cbf7743a1460cf0ad161",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "42c2e2bd76cf4d9672fe975b48e7321b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "2607ae3f87b42ce7890b0ac4fcb00758",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "42b59990a2096e0aedf9be572c46ada3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "206e3237ca05dc4d2c36eea21b7a7bd2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "20082687daaf4c7ea0e768eb77634ec5",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d385e67bde52cd19e3ce0d30f8ae4605",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-12",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "d675e916847b705d498f20b95e1a7a19",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "9f56f09f4f119e9bfbe45ac57d37821d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "977e7944f12e403f95c8bc9d3f515bcc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cafc119f5d6f2d95eb4d261d6a14003c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "40843829a57dd8bc3546ada1ef59eb00",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "cffe4f47189cefacce06ff2d4855f41e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1fe5aae5e3bc7244fb136bbe5d9a38bf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1f85505ee8654c8a9ab7446f09102404",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "41dfb1271d9ff48a893cea4c6d63c160",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1f9167efd8b14076c6e553f69dbcd0a2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "d5c15705061af2b37f6eb8b39283901f",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-11",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "425cf124dba598118e95013a5880de04",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "c53439cdba04d0357223923faed3c1cf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-10",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "9bc9005a0c523b70c3ad2f11eb5b8065",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3e3634d2f8352c40e2cca7c486433ea0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "1e7a50caed70ee5cbc815ce2ee9d1173",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3d7238546d51c10159c07cef62a60e1d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1e92132798c9e47555e390bbb684cf02",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "1e78f240ed4a560f76a82bad90dd51d0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-09",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3efbcb335bf09c739fbc528219efa46d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "89aa9ec1a9a99b44e40c53a360cfb4f0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1dfd49149f3cd29ca7f7327625ba17c7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1e210ea39dfcb291c8db00dcda0a7845",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1dec9df5dc13fe0ad799b0f159ea7c29",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1dc530def1c1f642eafded30ce5f6836",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "b7ab036fd9547a565996af46b7b09801",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3b01a5ff23963c470b3fe7b2beba055a",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "3b4b992959eb061fff230159547f822d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8f6597a8982002498502ed6983445449",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1e47facfbbdcc3e41f0299ca39b0591e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1e40597ee11cc5e09b4b58c6fa015822",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1dc104d1ef1e49f5ac67c4b4f18a9445",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "8b65babba3fb7ad613ce2c379c698edf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "85d4026393c1ff172d2c0fe666e2d0f4",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1daf16064d6f1527f86cf9d1d3736f0c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-08",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1e1ab6810af24f9ca82e4c1d0644f85e",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "1d922f8351517199bc3beb2dc2e4e56d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1d917913a05450d1b0b83135d0bda8fc",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "7fd13ebd4ced5707d09f72408a75a152",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "b187564bc79fbe7bdad943a18f73828c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "39d3c3640593f65d980625194cff61db",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "827a1be453bcbb343d03e6f5e733a86b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1d1bd05389d7232bd3e5e651d3aabc68",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-07",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "1d724399f2b490e156e59404929de608",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "1a29ac724cc9f7b4c46605817d36c847",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3750f0c43c1f0a1fa09934cd31c8993b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1beb9e57e1347214ef1a25b880788240",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "3783bba78e348aef87d2b36b9786290c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "415753553165e2ab89fdb1351d0d87fb",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "1cbbb1fac365ead4d5808048410b981c",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "760e1db51c82ffaa070ff181f1ff95d7",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1ca3924286b5382295644b44a6b613e2",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "106.187.43.98",
                "ipv6": null,
                "md5": "75f5f8d73546bbcf079ffa244513dbaf",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1acd7efec0fbbfc9093779a70fd020d1",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1b299a8eb269e9d4a9d5c297bb7d6b5d",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1b5b9c00dea1e88ee01c770dd97d346b",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1c889de81ad6bbaef9458bb566a30d22",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "1a503e3e8db966626ba2deba89ecdf54",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "76.74.255.138",
                "ipv6": null,
                "md5": "1c39225d9bc8c23ed4032f49ae8675c3",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1b4d6cd10464702f1a47e04189476761",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "173.255.212.165",
                "ipv6": null,
                "md5": "1c6d8616edd73dce96397a1e0617bf02",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-06",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "67.210.170.170",
                "ipv6": null,
                "md5": "1c003210ec935729da61caaba45411b0",
                "sha1": null,
                "sha256": null
            },
            {
                "datetime": "2015-06-05",
                "domain": "butterfly.bigmoney.biz",
                "ipv4": "10.92.80.169",
                "ipv6": null,
                "md5": "18d3611384cf442ba6ca0184b76283f4",
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
>| 2021-06-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | f8e537c178999f4ab1609576c6f5751e | None | None |
>| 2021-05-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | a20473e3a24c52ac3d89d7489b500189 | None | None |
>| 2021-05-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5fb3ee62c7bd0d801d76e272f51fe137 | None | None |
>| 2021-03-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | 088a7aaf18ae930086a62767a106b3a3 | None | None |
>| 2021-02-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | 20a4fff1d0d7b5636713574f1eff4f75 | None | None |
>| 2021-01-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 45465c3259f3b14cda195a1fd618057b | None | None |
>| 2020-12-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1ace32d465cd5e70217a7fd51b48cb19 | None | None |
>| 2020-12-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 50dc274203443ee6c7c550aa81e60336 | None | None |
>| 2020-12-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | a58ae7ca91959f940a34ee11788687c8 | None | None |
>| 2020-11-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | afb386c2061a09d8495070209bd7cc14 | None | None |
>| 2020-11-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8245e4c82e6cfcc6e31f5c17cfba23e4 | None | None |
>| 2020-11-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7750f8b7ecfe2274fd4a9cf187e58510 | None | None |
>| 2020-10-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 509e6331efe3d3d76908362308ee6018 | None | None |
>| 2020-10-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5cb50bca257e7c7b1370ab095a792ac4 | None | None |
>| 2020-10-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | c59b7375f416bbef2fab67f4610c1171 | None | None |
>| 2020-10-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | a95f3db489d526484862f54c1e3aa1a9 | None | None |
>| 2020-10-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | e01aec8b2f39497868c238be793dd52d | None | None |
>| 2020-10-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | d0f7a8c5050cfdb9bf562988582b9731 | None | None |
>| 2020-10-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | e4d33c1c7647c37e77c63164d71607d5 | None | None |
>| 2020-10-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4f8832b52d61cbfc944bb3b879d3b69e | None | None |
>| 2020-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 550219bd15f015b8a0a14ca57ae8a414 | None | None |
>| 2020-08-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1035bb8c9a20f3fe464901a301517ded | None | None |
>| 2020-08-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 65f710a80b7f11f5da725d9876057aac | None | None |
>| 2020-08-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | 68248be052f137cbb4bdf02ead7a0603 | None | None |
>| 2020-08-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | f290a1a7282b617de4ab6c9fa5345be0 | None | None |
>| 2020-08-13 | butterfly.bigmoney.biz | 106.187.43.98 | None | a02aab50a7d4bcceaebb542957d11787 | None | None |
>| 2020-08-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0df9553cd1663c61dbdbb0f2b5d5dfe3 | None | None |
>| 2020-08-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | af13a97ca7e6544fb02858b3662da902 | None | None |
>| 2020-08-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3a6e2b19a7d4a5344f47aac0e0a0f9a6 | None | None |
>| 2020-08-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 489703a4d98abd26d8e71df7ee423498 | None | None |
>| 2020-08-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 542ed16d3908c857f91e1030b6c1b2e1 | None | None |
>| 2020-08-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7d6abb1d56d071da2b1e774b2c05f402 | None | None |
>| 2020-08-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2fb8f759df4671392e019f3aab54dad1 | None | None |
>| 2020-08-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2400bac8df12b358058112d2df20043f | None | None |
>| 2020-08-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 20c78cd790c321150dfa9f0d14e0a8a3 | None | None |
>| 2020-08-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | cd207249556b2b1d4f9e430d93d03150 | None | None |
>| 2020-08-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 95de7ab20ecaeb6b62b3748aa58ece5b | None | None |
>| 2020-08-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1e74bfb1fbfbc416bb7d8a81d10e1568 | None | None |
>| 2020-08-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1a35b2cec676bc8ae085f710e8de01b4 | None | None |
>| 2020-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 63a60aceedbea3323b9218137b3c7a4c | None | None |
>| 2020-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 32e9bf29be5fff790d75128885b5d033 | None | None |
>| 2020-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1c86f2b825f6c0a85df49c39baca8774 | None | None |
>| 2020-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3022cf136a0370bf89fd380f8c6c50c7 | None | None |
>| 2020-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4c2f858cda5025a5c5d0581905066066 | None | None |
>| 2020-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 00dfbb6e2b1ea9f9e64a6a4c52013ea5 | None | None |
>| 2020-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 34f1c341a9d6ad122adf2b23ff47b9d2 | None | None |
>| 2020-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 48539b7cae582281e7f0345a513b649d | None | None |
>| 2020-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5102776a209876ceb830b7d37d0cd3ab | None | None |
>| 2020-07-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1dc5ad0b772fae562bd2b12d8fb5636f | None | None |
>| 2020-07-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 50080ae048f880b3c020c7ae3b046de8 | None | None |
>| 2020-07-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6de2aead9cdbb25000ba4df2fd65e06b | None | None |
>| 2020-07-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0c05fef8f63cc66c465cf35ff1bfcbc9 | None | None |
>| 2020-07-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 51c02cf617dfe1de7737b078d89ad2e7 | None | None |
>| 2020-07-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | b51a8c2eb58205f8886178cb49bad82f | None | None |
>| 2020-07-13 | butterfly.bigmoney.biz | 106.187.43.98 | None | de5eda96416f3396b81606628b31db26 | None | None |
>| 2020-07-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1d0a97c41afe5540edd0a8c1fb9a0f1c | None | None |
>| 2020-07-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | be63b545e4db052b4b9d883c8cf1aca8 | None | None |
>| 2020-06-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5a7fe21d3602d744cc9c1b6b87905d6b | None | None |
>| 2020-06-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | bfce9b599be4d19a41db83c1d246c115 | None | None |
>| 2020-06-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 29490ad77e83711d74718b47956c4fbd | None | None |
>| 2020-06-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | a7cc1fc0c3a17947614c5219707992de | None | None |
>| 2020-06-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | 205ece692dc220d2b9c24c3df0cf151f | None | None |
>| 2020-06-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 18cc9481f19970c83ab851714e869e45 | None | None |
>| 2020-05-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | 65138219d7010e09955b705175cc562c | None | None |
>| 2020-05-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2d80bd8cf692ab3e50d0ec7d7389d170 | None | None |
>| 2020-05-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | 15c4d604cb588648aeafbee7701ecd17 | None | None |
>| 2020-04-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4e2820e2296dab73f5d6cadcab5e7f93 | None | None |
>| 2020-04-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | c84e05322eea41a6bc8555095adaaf2a | None | None |
>| 2020-04-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4167f3dc806534677c846b6a2e120d61 | None | None |
>| 2020-03-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | 39f191a005bf5684b0b9dec3865687c3 | None | None |
>| 2020-03-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | ed1b61424bb01692de170c9f489cf7bc | None | None |
>| 2020-03-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1c91986ae2fc3d06eb81c8546b111126 | None | None |
>| 2020-03-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2fd19fefb30ff49c86e038ba686a88d7 | None | None |
>| 2020-03-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8718990dde34f090f748f9c9d1e8743a | None | None |
>| 2020-03-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | 21135ba76c934db12c335587510fec42 | None | None |
>| 2020-03-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | 9b3d10d767154028421588937f7aca17 | None | None |
>| 2020-03-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | 752332b2db68a755dd27c7afad6fd66b | None | None |
>| 2020-02-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | dad6552a69d3a01c503fae664dc6868a | None | None |
>| 2020-02-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6f7b66962b86dcf37e207fb492357991 | None | None |
>| 2020-02-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | c7340a198d26ff6ebbdcc94a49f623ef | None | None |
>| 2020-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4cfbacd51c21395acfddc2ee43d6448b | None | None |
>| 2020-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | f3a25aa11faf9c026da3baecb5821b14 | None | None |
>| 2020-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1ba7b062e267f98a05116249c0334218 | None | None |
>| 2020-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | e17bd40796f9c84dbd04c900f3b4e656 | None | None |
>| 2020-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3cf37009b23568a5fb3752525ed1317e | None | None |
>| 2020-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | fe15e25de57af4710842efde333ac82c | None | None |
>| 2020-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2704ba3c6ab5555f6504877945cf0d4d | None | None |
>| 2020-02-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8ee451cc477b992b004dc01609c73d19 | None | None |
>| 2020-02-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 09aa29adf5d64179b52e216234b434ec | None | None |
>| 2020-02-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | dd853de2ddbe20fda219dee0ec147a64 | None | None |
>| 2020-02-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | e3f6464d2358c56ff32962cffd6a4ffc | None | None |
>| 2020-01-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | 53c10f35639cbcfc622d201f1577e7c0 | None | None |
>| 2020-01-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | 50d01f60138e9b390ded98ad1d9f766e | None | None |
>| 2020-01-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | ee974d7aad24003b935bdaa798d28e27 | None | None |
>| 2020-01-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 02a051666b6b7ecc4796f60baab3904f | None | None |
>| 2020-01-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5dcea2477d72c6dde4f7a3039e5082c9 | None | None |
>| 2020-01-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 267e30a164d416b0031e3d279538fecc | None | None |
>| 2020-01-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 740dcef7434cb496b535afe434fae775 | None | None |
>| 2020-01-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4e071af48a5e606fc840af4e736267d9 | None | None |
>| 2020-01-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | c8b9de94f9d10323bcaa51452cbb4e9d | None | None |
>| 2020-01-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | abea51528b73699844f1853ba9ad4d34 | None | None |
>| 2020-01-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6a28cb71aca3daafe4c3b375534e43ab | None | None |
>| 2020-01-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 93435132e539efd77b604cc139ab41c1 | None | None |
>| 2019-12-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 34f89e2205a147541cdd9f58cf554a88 | None | None |
>| 2019-12-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | d9f921508a08e7549860f50a2e1c24bb | None | None |
>| 2019-11-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | a5cea197f5d57c2fb28c511d41e82f49 | None | None |
>| 2019-10-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | d6823f3aeaadd832d6ee9ce9b9e134d0 | None | None |
>| 2019-10-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | 02f81c9588f9f1efed70673969441d82 | None | None |
>| 2019-08-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | c12df87d5d103dfcd29ee23bb6a8a7bf | None | None |
>| 2019-08-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6b6890d6e19234a3098be48d51441b4c | None | None |
>| 2019-08-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | c3881adcf0b183030d6079bd176414cc | None | None |
>| 2019-07-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | a14e96604a5d3c5295a42db6baf10f43 | None | None |
>| 2019-06-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | efb41846ece49dfce5433dcb4a554c5e | None | None |
>| 2019-06-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 07aca646403e8be0cdff358f1edf3a6a | None | None |
>| 2019-06-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | f05eae423c40bc3c03654119e37d7d40 | None | None |
>| 2019-06-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0046ef697908c3c0524bab0f40d8e42f | None | None |
>| 2019-06-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8364456720732f56a28b4f10035794f7 | None | None |
>| 2019-05-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | 127427fc8e88d824cb625a239d8e4ad6 | None | None |
>| 2019-05-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 59393f4dccfbbde9d5383f0fc197ad88 | None | None |
>| 2019-05-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5e2be0e19473445ab8ca8c62c0495057 | None | None |
>| 2019-05-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | d9b010f538570244a30c2dbfe9e64678 | None | None |
>| 2019-05-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | a45c18df4eafb085f63f275b79a281e6 | None | None |
>| 2019-05-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | 68ec0f4e366e51848b9c85fea2109a70 | None | None |
>| 2019-05-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 403679d99a62b43e43dfb3e7e3375d1a | None | None |
>| 2019-04-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 587c8a7b70ad63f6df5497ca7544152d | None | None |
>| 2019-04-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7f1695a5bf1ca9cf5d9a60db7c6721ac | None | None |
>| 2019-04-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2e5c4a4935e10ada2f529d528e03d8f6 | None | None |
>| 2019-04-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 59c33695fd8288145e25b2a9fce7585a | None | None |
>| 2019-04-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 24abaf4057d094c03807894bc26a9aa0 | None | None |
>| 2019-04-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | adfc35525ced1e756a7112498ff406bc | None | None |
>| 2019-04-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | b597f68fd89c0a3e8c3e3c1f7b55506b | None | None |
>| 2019-04-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | d656e140b240926d04f4b3e407f52be5 | None | None |
>| 2019-04-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | a505c83fc3480e14c7ab98f731ec0efb | None | None |
>| 2019-04-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6bb7849d807d562246c6b211a17e8d80 | None | None |
>| 2019-04-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | 9e7639bb083044e0586592fa263dcfd9 | None | None |
>| 2019-04-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | e32fa5622382775f7bb2cf5d23032696 | None | None |
>| 2019-03-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | 022b3de9660194646d00923266c1ffb6 | None | None |
>| 2019-03-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | fe03f062f69df8c20b66d2599368c721 | None | None |
>| 2019-03-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8dd28280f8c0404c6675a5e66c6a44a4 | None | None |
>| 2019-03-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1d89c4d3c3b1a645d4bfb30f9fba0b38 | None | None |
>| 2019-03-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | 69bb6244cef66ccbb565385384fea4b7 | None | None |
>| 2019-03-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | ae7d1004da36086a2d3b34622472b626 | None | None |
>| 2019-03-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1de10fa0b8e75aefe67f49c74627852c | None | None |
>| 2019-03-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 839c052c0cc428ebbbaafd760204befc | None | None |
>| 2019-03-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | 13798086aa328f09c1cd4e7bf77eac3a | None | None |
>| 2019-02-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7fa12f4ccdbeff8fd188029bc82d092c | None | None |
>| 2019-02-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 15f2f2871688c79e374a93635cf26c54 | None | None |
>| 2019-02-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5865d58d3a00af2a1597d5318b0f89cb | None | None |
>| 2019-02-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | c53b49632d3048350fb40987248fadd8 | None | None |
>| 2019-01-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | d795f691900c531fb67f32a8753e31f5 | None | None |
>| 2019-01-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 962dbbeb98a86c5475b75de4de610a6b | None | None |
>| 2018-12-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 398b59f0ba3d5c0e114a4956874ae25e | None | None |
>| 2018-12-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | c09c2dfc0ae4655a6a4f8ee127167371 | None | None |
>| 2018-12-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | a6801d64a12be7e65aad0bc4da94c85a | None | None |
>| 2018-11-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | be6d9355d76f84c9a06ecc972405f105 | None | None |
>| 2018-11-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 17069c1976ed3d8a6b08f3f916acdbf5 | None | None |
>| 2018-11-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2c458b498c5562d49108918cdee8bcbf | None | None |
>| 2018-11-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 12ef71913c457a492c9c2f8bb8c8bc7d | None | None |
>| 2018-11-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3c73cf83b7f02b4d85f538edbcc935cf | None | None |
>| 2018-11-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 32c962a70f2beeca9987a494738e0269 | None | None |
>| 2018-11-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0a6869e67385ba4d6051323b6a77a3bb | None | None |
>| 2018-11-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 70671648159e30aeaf3abfcc5f434bb9 | None | None |
>| 2018-11-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5a54de78f98cfcb519d380dbc165d65d | None | None |
>| 2018-11-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | f2e6ba76ddf07173649c7a7f6b535534 | None | None |
>| 2018-11-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | fc6a4a9148e6125eb7d0f8b1003c8b60 | None | None |
>| 2018-11-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | 087a809879776cb4a2372d94e8ad2fbd | None | None |
>| 2018-11-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3727b40724b34c46b1cba03525473150 | None | None |
>| 2018-11-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | 39fcf693544a795cd6d8cfe0c9c0aaa8 | None | None |
>| 2018-10-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | cc022eaa16c9171fb4a4d23d922ddd4a | None | None |
>| 2018-10-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | bb2b916bd245b5fbafdd79665f7cf907 | None | None |
>| 2018-10-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 22329efb5602e1a501c95b8141b92b10 | None | None |
>| 2018-09-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | 82f94e6efc767c0eace2e8fc85908581 | None | None |
>| 2018-09-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4027052359e30beda00f9fb5d696b2d3 | None | None |
>| 2018-09-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6c0199606383fc92196bd940b79807a5 | None | None |
>| 2018-09-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3de07f477ed09eabe963f89c12bf4d07 | None | None |
>| 2018-09-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | 67c9d73422a41ada8a9a1a4f5068d1e0 | None | None |
>| 2018-09-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8100f112798fee572118b47bdebf3b11 | None | None |
>| 2018-09-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6e56ca76f632880e596ae035fa785294 | None | None |
>| 2018-09-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5bd177e297325335617bb567cb3e84a1 | None | None |
>| 2018-09-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | c908bba2c49f233226ed3ba93ac0d697 | None | None |
>| 2018-08-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | e0e75c4e4a76a2470108bea360a54b2c | None | None |
>| 2018-08-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 074001aee583f23483e8a41213270043 | None | None |
>| 2018-08-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | eb3f7bd20300e18f10b335b2a4bae961 | None | None |
>| 2018-07-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 9574154618eb372801bd99938e89cbb1 | None | None |
>| 2018-07-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8943467e8a12d9b7d9b45a58c24884da | None | None |
>| 2018-06-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 90c7c65c3ed14e4fea250a17d954596a | None | None |
>| 2018-06-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6cd6600fe6d05d2fab5b9a51ea4aa04f | None | None |
>| 2018-05-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | fd37c332aa180ccb8ae90846f892a3e9 | None | None |
>| 2018-05-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1ab79ff726cdfc5e7ace3e780301d8b0 | None | None |
>| 2018-05-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 72920ed8816a9be5877c3ff7d4652eff | None | None |
>| 2018-05-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | c30ceca86ff4eaa98741b9caf26d980f | None | None |
>| 2018-05-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | b8f1e3fdac633c842f1035fb25bc38ac | None | None |
>| 2018-04-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6b8fc24ef1fb40919f41e0032f86171d | None | None |
>| 2018-04-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7bef86fdce599e031223a8b3f831135c | None | None |
>| 2018-04-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6fc53f8dbb27f627b9e170926a30d7d6 | None | None |
>| 2018-04-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6b6a3ff264c7e71413380ff1b8251d4e | None | None |
>| 2018-03-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | ddfdc1ec66159e404b902b6bd424a7e6 | None | None |
>| 2018-03-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | f47f17911057752eb335d96f3750b470 | None | None |
>| 2018-03-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | f43b0c4feafbfe7779d0362ccbb2af1d | None | None |
>| 2018-03-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | f662d80ee56853d309396bd2b56bc976 | None | None |
>| 2018-03-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | f270731d9c5e47b9a6e74de40451a324 | None | None |
>| 2018-03-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | f23e6e0e33b4187f9e7d633ff3c1a4c3 | None | None |
>| 2018-03-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | f0e3035df321267145e5cdb92eb46d71 | None | None |
>| 2018-03-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | a4b794c660e150dc86a7607f23d40d87 | None | None |
>| 2018-02-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | d95d81917ce3d6e9d30b6ccd0a659128 | None | None |
>| 2018-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | d5c4f413ff93ce1a0e90c958ee17a2c9 | None | None |
>| 2018-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | d6e832f543fd7829ff20ccd73f247819 | None | None |
>| 2018-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | d5107b76a328347f832acfd8fa966463 | None | None |
>| 2018-02-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | d315aae6b60373c0915dace4684b3735 | None | None |
>| 2018-02-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | d35524360a10a305db4c56cdb9bd08e2 | None | None |
>| 2018-02-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | d0c4c81b0e8f6d625aafcef84151e29b | None | None |
>| 2018-02-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | cdceccb62c60b5556a27f3f41afabc32 | None | None |
>| 2018-02-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | cb4029f5790ee26a773c3d6253cfc92a | None | None |
>| 2018-02-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | cd2aa1429cd660741bcdbbc47521a066 | None | None |
>| 2018-02-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 12796670015a6fab9a567dc0e89b5f19 | None | None |
>| 2018-02-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | e28a432fbc47c718de43a035cee596c1 | None | None |
>| 2018-02-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | ad1fbd9331eb0929532ded9abb8c4e57 | None | None |
>| 2018-02-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | aa0feb408929291f2cd9097253aac2ec | None | None |
>| 2018-02-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | a9ffad79d2397949fbe45a095c9cc44a | None | None |
>| 2018-02-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | da0e80f1fde52e0e9026a802d220d3e4 | None | None |
>| 2018-02-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | a39f1a531878bc834845978cdf49d802 | None | None |
>| 2018-02-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | a7b48b1e26eeb265079f40645b134074 | None | None |
>| 2018-02-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | a04939fcb508694fd3812300b5e80b17 | None | None |
>| 2018-02-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | a25cfbb36aab214e22695e68b153cc7a | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | c72a0d27db64d08cc338d617cbce0e56 | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | ae326116a9dc4fb56f285d628145c603 | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | c3fdff018cd5110e3793c5bb164e7416 | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | bad4387323c39fd87524d5330ffbed0b | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | b8c42d022dd8f5d5798c854c1d92539c | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | bbeb677560353fabcf18f72e7098745f | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | b428f736386b32119bcc54f46055a636 | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | bc95fcc7a9f46c3b8ee359b636f83ee2 | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | c3ab9c2a49cd2e331fd4800966a1d13b | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | bbac214eee51ba7057cf6efdafdd9254 | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | b9d5bd92257af80bcba42b836180ed62 | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | c617818c61aaef32a187b76b38816cd3 | None | None |
>| 2018-02-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | ae973d71cee0905fc2212648f5ce78d6 | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | fee40580b42cc4a61839b88de4127e18 | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | fc68cb343580e6cdfd460434f47babbf | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | e254dc541514227e5e363eddca3a09d3 | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | fafd7c7910c250caabcb49f37f0ac519 | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | e3c06358e84700f45d2e502c7bc9a6e8 | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | f9cb7703a8a586c3be073c968c4e3df8 | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | e85305916773e2dcfa7d0af6d701b86b | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | e6fe695a8e4dbd31f25899fd9f6dbed6 | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | e03a3c0b168dfb285a25069ec7eb223b | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | ea820e8b3d38d0b1a0106b43c704b558 | None | None |
>| 2018-02-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | e410d4314013bf7b40ebc7d34436ae79 | None | None |
>| 2018-01-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | c083ddad629f73d847f976d111fb43a0 | None | None |
>| 2018-01-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | c4b787c7a88c14c578e300dffbe4a091 | None | None |
>| 2018-01-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 472d1fa0afa49caf633896890bf29dc5 | None | None |
>| 2017-12-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | feb530f220ced765b78c4c0552657026 | None | None |
>| 2017-12-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6bf7ba8be55afb4abcc2e43f33abd373 | None | None |
>| 2017-12-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | 27ec7502570a75593a1a3df35932c927 | None | None |
>| 2017-11-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8587c1a5eaf79a23f771cb0ae4acd536 | None | None |
>| 2017-11-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | b8367a577869b20823f5a839f2ee5d2c | None | None |
>| 2017-10-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | cb076b086f55fecc96631215ff90bf02 | None | None |
>| 2017-09-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | c4aae791fb0b4afffb43b95be70df884 | None | None |
>| 2017-09-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | ce68b3013979f010e2a8141e56dcc5e7 | None | None |
>| 2017-09-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | cf60186676c5551189202330a9673719 | None | None |
>| 2017-09-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 53d90edf6d35aad6879eb7b4e3894a98 | None | None |
>| 2017-09-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4a98d287db4674b941e7269bd2c2f91d | None | None |
>| 2017-09-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5de21421f215561fe9f33ed4adc92342 | None | None |
>| 2017-09-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 99c692763df76c6efffb5fd133194107 | None | None |
>| 2017-09-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 47a6b7b5766f44f56fbc88c4968e51e4 | None | None |
>| 2017-09-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 136f1470771073c82bc44c5c717083a3 | None | None |
>| 2017-09-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 12af58fa908ab0502bf3f9060262ce5f | None | None |
>| 2017-09-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 86e66b63ad2e9c0b3068193af3874b09 | None | None |
>| 2017-09-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | d480c294a1b3594ef8183c0e08cd79ea | None | None |
>| 2017-09-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5f57d6e77351b426628e97d3a052ac51 | None | None |
>| 2017-08-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | ddfe22513e1f7fa2e158590e378c7e33 | None | None |
>| 2017-08-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | 47d861bc6c00fbaf9cc05604480404df | None | None |
>| 2017-08-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | 708addbf38925110ea069fd6a46414a6 | None | None |
>| 2017-06-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | d60ab3d651898cde4bd09c8d22b332cd | None | None |
>| 2017-06-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 98e72458318cb94bb77a6c8184037e3c | None | None |
>| 2017-06-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0eee89ba99fcfebda48908e487ce5697 | None | None |
>| 2017-06-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | c75f8e77f94ae662d95e248494d28a5e | None | None |
>| 2017-05-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | e8e78159af4baa13ba1c7e5586f36041 | None | None |
>| 2017-05-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | c110e12899bdc843f87cb87557867b63 | None | None |
>| 2017-05-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 91fa8bd953394108e3bc60ecc5ee6e4f | None | None |
>| 2017-05-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 11171f31a38951625e53deaa3867249b | None | None |
>| 2017-05-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | 60070f8de9dce0acb642fcfe091b7e00 | None | None |
>| 2017-05-13 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5da5e62407229be674d0a2514ead99d9 | None | None |
>| 2017-05-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3aa6ff6771a7f75a1e10ba4bbd826dbf | None | None |
>| 2017-04-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | 491d0b723d2b43975f7c8d14d1e65fca | None | None |
>| 2017-04-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | b01c62a6febec86b9ae61cf06fb61d49 | None | None |
>| 2017-04-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 05889cc95d500398ac000d476d01b99c | None | None |
>| 2017-04-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 41dbad4043b69c8146d841bca8c83275 | None | None |
>| 2017-04-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3d699af1ddfb2c4b4c6043bb28f7e52f | None | None |
>| 2017-04-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8b98d189c121a19cc298ff66adfc8aa1 | None | None |
>| 2017-04-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 22f03e7068a996664cbe49cba04d6736 | None | None |
>| 2017-04-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 18b229394afc06e01a6084ba6cdb5c1e | None | None |
>| 2017-04-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | a7403dafb7ce5451cc71cf0dc7f607a5 | None | None |
>| 2017-04-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | 674cf3ac1d76b7f7dcd27a9eeb94f98d | None | None |
>| 2017-03-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | ff90f1b439078ff49bd7a15fea878ce9 | None | None |
>| 2017-03-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | abe1654ac0bc69c13c5e75f9a9c6c79a | None | None |
>| 2017-03-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | d37bc88dd138f97fc8e7c9c5118bc2dd | None | None |
>| 2017-03-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | 81174343e6c75366b838c78ecba3ce89 | None | None |
>| 2017-03-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7843709e1ce2b04f96ec84f8e5a33ec3 | None | None |
>| 2017-03-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | be4f6f23d8fa10b65f4280ecd11fb0e0 | None | None |
>| 2017-03-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 733beca7a60553082c4d15e8465e9000 | None | None |
>| 2017-02-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | 81f4bfc51f485bc97c8be988e2ca32e3 | None | None |
>| 2017-02-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 029473b78803c042c13799f2e3af1811 | None | None |
>| 2017-02-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | 87837e855367fa67859fe0f450675b89 | None | None |
>| 2017-02-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | e132fe5d106dd80c0336178bf01bb4bc | None | None |
>| 2017-02-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | b5a450273de1d155bcc9c73fe959f75f | None | None |
>| 2017-02-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 50672ecb7551d4ec195442fd2ca1e5ab | None | None |
>| 2017-02-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8b60f4fe520a696f6773d80a2e1a90f3 | None | None |
>| 2017-01-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | c527570daf3272e464bf347eb573d2c4 | None | None |
>| 2017-01-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | a654be686ff309966d30c8548be25cb1 | None | None |
>| 2017-01-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | b3fc71fa2bee4710a269a698f8f5312b | None | None |
>| 2016-12-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | c990caec1785ab090727d0f421ba38e1 | None | None |
>| 2016-12-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0d525e6f4540360b5680ab6bbaa974f1 | None | None |
>| 2016-12-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | b57a2e824a97d321de2faa391fc35157 | None | None |
>| 2016-12-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | ea3f70c763b583601f4624e7ccb6d1a5 | None | None |
>| 2016-12-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | d2b43b2bf60cbf7a73b5944182e39373 | None | None |
>| 2016-12-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | d9a13b27bbb00bd646f34f1cb8aa0cd1 | None | None |
>| 2016-12-13 | butterfly.bigmoney.biz | None | None | c220d5ed213a056f6a5b0f417f6132bf | None | None |
>| 2016-11-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1b5f0e624b0268b3bedf99ce6af20a6e | None | None |
>| 2016-11-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | a4fd456112fa16abae6dd0fe9f9948f1 | None | None |
>| 2016-11-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5e4a76862caf152bd3d8337888651f3e | None | None |
>| 2016-11-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | f5a47548230899be201781ea1543fbf6 | None | None |
>| 2016-11-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | cbc5686ef21927ff2cc3cebc04a7e103 | None | None |
>| 2016-11-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6455195cfa93c2e79f80b07736c430ed | None | None |
>| 2016-11-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | 68ae24ec22f6b7982799929bda4c48dc | None | None |
>| 2016-11-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | e44b4c34e91b685e6c696c462f505b47 | None | None |
>| 2016-11-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | c7ca91bd5b0d1af2a429af3875c0d752 | None | None |
>| 2016-11-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 488da89b86658c0438f481a390ebb4cd | None | None |
>| 2016-11-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | c196113422bbc63cf45c252f930e7fee | None | None |
>| 2016-11-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | bf173495ab1751ce6d20d6f6e15d5cb1 | None | None |
>| 2016-11-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | ac0ff3ed33335d94ecadb5a367a75ccc | None | None |
>| 2016-11-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | c89ad956251ced912b88932c62c99cc6 | None | None |
>| 2016-10-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | a9c080105dcad52126836d73cb8ffb70 | None | None |
>| 2016-10-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | d9957548d5274ca296b8e616e4d686b9 | None | None |
>| 2016-10-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3c220dce06d20cafde032fec38056200 | None | None |
>| 2016-10-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | 25cd0c5c8cea691a59589b0a23ebf9e1 | None | None |
>| 2016-10-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | a1c9dc3e92b53b35c9336433a031033c | None | None |
>| 2016-10-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | d26a5920493674116b6a2a18a9dc5e8d | None | None |
>| 2016-09-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | d671735f0c4f4ffb163349e9564b73c9 | None | None |
>| 2016-09-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | cbedcac4d2c4aef525d5af1859e0726c | None | None |
>| 2016-09-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | c33bf8206cde830fbcdcf56b918474f8 | None | None |
>| 2016-09-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5e840cc5e027e6061fb2be714d3a9b68 | None | None |
>| 2016-09-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | bd24ed7c8cd59f81d710ff2c89104aaa | None | None |
>| 2016-09-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 816d5d6a3cbf4102a56d035b46f9f3fa | None | None |
>| 2016-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | a2424908ad9dbd60021d03c8a859e69d | None | None |
>| 2016-09-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | a358c0843956f23e92cdfeb3776895e5 | None | None |
>| 2016-09-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | a7160a88a37335f2fbc279023f2abefe | None | None |
>| 2016-09-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | c42548e979aadaa98f5cd2f12b75cc7b | None | None |
>| 2016-09-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | cf7c3c5cd01ff04a5fc121742e58a943 | None | None |
>| 2016-09-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | a829a79ace799e7af732a1c6d2c133e1 | None | None |
>| 2016-09-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | ae1da3f81d564b4f1a2e3d3102b3a0e1 | None | None |
>| 2016-09-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | a48fd800ef828720c3e5e81bd25ee278 | None | None |
>| 2016-09-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | ee7b34a77184da8f39ce7c4f03485f81 | None | None |
>| 2016-09-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | 88a56a2df5089e942d63e652bc34a3fb | None | None |
>| 2016-09-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | c60e83a3ef83c7718269e2f06fe65b39 | None | None |
>| 2016-09-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | d33a75f6a139be81856fc55c219205b5 | None | None |
>| 2016-08-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | c2cadb6ce6ee1412fdb64ef1b5d02e4c | None | None |
>| 2016-08-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | c8e7263035308dba8e3fcebcf4e74e80 | None | None |
>| 2016-08-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | cd94f03082af14ce62b624dfd92ac09e | None | None |
>| 2016-08-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | bcdd838c8d76af56272f2c2182db50a9 | None | None |
>| 2016-08-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | bef893402f938b34438b7fb52f28d58e | None | None |
>| 2016-08-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | bd0cac288e410edf471d8da6c02cdeec | None | None |
>| 2016-08-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | ae6f05399cdf9727b20e613386a5184e | None | None |
>| 2016-08-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | a84312536bf7e4ce07cb4d26e54b1900 | None | None |
>| 2016-08-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | b7095dcdbcdcb78fad0bbd77eeb7c2fa | None | None |
>| 2016-08-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 24ef011c7fdefdd34fe1865768ca745f | None | None |
>| 2016-08-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | c94f1430521353a8b26ac2f720fe17a9 | None | None |
>| 2016-08-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | d205b8048e52cfbc3e3b97d6f538ef19 | None | None |
>| 2016-08-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | b862814e1e45fa9ea29c7648ba6b3a16 | None | None |
>| 2016-08-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | cf7c06514fdd3ff4dde0b2c249ecbc4a | None | None |
>| 2016-08-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | bb0d0f27545ddb329c645942b5f1ba51 | None | None |
>| 2016-08-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | bb5e518c9afcc4559937cd005060a64e | None | None |
>| 2016-08-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | a6784d652f7937d3eede14731da5d939 | None | None |
>| 2016-08-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | cc9e65fe92eceee550f73b90d8cf9ddd | None | None |
>| 2016-08-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | acafead9ef2ec8229f57bca816a68fa5 | None | None |
>| 2016-08-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | a114ab4d161aae417c66a27a0e1bd421 | None | None |
>| 2016-08-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | b07d6f1e50f5f171d8a5b932bce09f59 | None | None |
>| 2016-08-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | b41fe97243d346b3d50e43bf93979e2b | None | None |
>| 2016-08-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | b125c163dcf9c5fb06ed0f88b436785d | None | None |
>| 2016-08-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | b0c7f02020e54efcb2b739350c69c4af | None | None |
>| 2016-08-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | d203386806446f3e088ebe658bd3c4d1 | None | None |
>| 2016-08-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | ad9702f162ace2c6a63c394025647e6f | None | None |
>| 2016-08-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | c31e24f97b9ccdc63c0451a8c7aef54d | None | None |
>| 2016-08-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | bf86a8efef7982ddf3eec57cafeebf78 | None | None |
>| 2016-08-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | bb4b33aa02a76642d29862405513b1de | None | None |
>| 2016-08-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | e3413e0b793b36e20485af45ef6dcf4d | None | None |
>| 2016-08-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | e5ad5940a0d468a5528d26afa70894ea | None | None |
>| 2016-08-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | ceaac86874e4ba69a68dc647f3cf3b89 | None | None |
>| 2016-08-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | bf5422f8345a2640356b9426a0948e2b | None | None |
>| 2016-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | a65d9975ff6b43a09e3e23abaeb76a88 | None | None |
>| 2016-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | a0dea1bce7f63d6d02661899929858a8 | None | None |
>| 2016-08-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | b870c4cdc5dca4e64525c7efd20086fa | None | None |
>| 2016-08-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | aff352bde44ad640b77055d222b66530 | None | None |
>| 2016-08-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | bbae3e4a922ef76e090e756e00b37d3d | None | None |
>| 2016-08-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | cd49e88317be1906073e3b181286795a | None | None |
>| 2016-08-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | a001384213e5904ee7bd68936d045549 | None | None |
>| 2016-08-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | bb27ec38d9a5020d3bccbe0e9ce21652 | None | None |
>| 2016-08-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | b40434607f4cb74a99ecbf8ddd3d2e5f | None | None |
>| 2016-08-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | dc079f942301cfe245474ced94456745 | None | None |
>| 2016-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | b2e9c250581e47058c95fd38869ea1bf | None | None |
>| 2016-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | a482349f3ded51822349192ed4ce8735 | None | None |
>| 2016-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | ab1d84ebfa94ce712764b924592215cd | None | None |
>| 2016-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | a0df92ed3b0832710ad2516415bda1a6 | None | None |
>| 2016-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | ab0fc214999f3616a00f9b2640acd106 | None | None |
>| 2016-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | b52a405a082a25cd1497171e7deab63c | None | None |
>| 2016-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | bfe8b427270b750324a4820b03a32c81 | None | None |
>| 2016-07-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | b9b809748dcbdbc12ca6056bc31eb632 | None | None |
>| 2016-07-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | ba538256af0bf6bd00367231d8b2a5a7 | None | None |
>| 2016-07-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | a6718af52bc5e139629c6c950734f78a | None | None |
>| 2016-07-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | a018629eeb74fa8c6ba4c3df6615d2df | None | None |
>| 2016-07-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | a0ace8d23b5279bfb0de871d85f58ca6 | None | None |
>| 2016-07-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | c73dd6905e609fbc75171cbc236c2844 | None | None |
>| 2016-07-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | c9cb2c7e431afd7ef23728c4aebfbef2 | None | None |
>| 2016-07-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | c82543e3c21e983d61dc3a702032edb7 | None | None |
>| 2016-07-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | adf27978bd472c64cc8bcdb1a083f445 | None | None |
>| 2016-07-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | bf2fb0a28df5829f397326eb4eb0c9d2 | None | None |
>| 2016-07-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | a3d820c665d65de5071ca87596dc4e4b | None | None |
>| 2016-07-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | ca11b35f0c570860cda05a3c1a7b6ca6 | None | None |
>| 2016-07-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | bae3dc6b99c02dcd89b6f7ed8c1c797a | None | None |
>| 2016-07-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | a7c0d0f235223ceb9a43fb9e68b2b0c6 | None | None |
>| 2016-07-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | afcb7d8fea5442a4acf814088b4609da | None | None |
>| 2016-07-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | b583efa7cea4ecc67840bf1a605e0407 | None | None |
>| 2016-07-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | a340d164e3eb3c21c9e620d77069f7e6 | None | None |
>| 2016-07-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | b04d3f6934b16295fa3dcd241ed94cd6 | None | None |
>| 2016-07-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | a8834d92bc82228936d72b9c3abc4e8e | None | None |
>| 2016-07-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | b941c23710ac0fad5370a1763ae18d2d | None | None |
>| 2016-07-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | afaca331ff4373be8d7391731df47179 | None | None |
>| 2016-07-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | bea6727a4a02732054a7bb6c607ccdeb | None | None |
>| 2016-07-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | b7d7ca9fcfa72e7937099f99223ea878 | None | None |
>| 2016-07-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | a2222d1c8ad09231147887c6be0e410c | None | None |
>| 2016-07-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | a2ec8c31c18e524e0f9bcabcdd40805e | None | None |
>| 2016-07-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | a58d01891bd33131069fa033caee1631 | None | None |
>| 2016-07-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | ba8c5ce64f55381ff1212f0b383e4adc | None | None |
>| 2016-07-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | ba4bdd29a7ee23fde17ce6afde4f9f5f | None | None |
>| 2016-07-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | b669811aa416cd941defdf1229f3e794 | None | None |
>| 2016-07-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3bacfb88f322636922033e7efb152641 | None | None |
>| 2016-07-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | b325c0d33f8b33ded1010d77caf6fce4 | None | None |
>| 2016-07-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | bc8352bc329724ecc096fecaafc7bfe9 | None | None |
>| 2015-10-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4e3f4d259f13e5739d73b8494cbff808 | None | None |
>| 2015-10-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | 04b71f5226f004e37c38cd780f5b571c | None | None |
>| 2015-10-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | b0c37b18c76532a166d8ddf051744061 | None | None |
>| 2015-10-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1a11d68ff2e14600c7805feb946eb450 | None | None |
>| 2015-09-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | 863d101664ad53163a6c474ae0814084 | None | None |
>| 2015-09-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8f8fd02c04db01ab30357cc3484010fd | None | None |
>| 2015-09-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8fd64ed8236981d82c19bd7a442a8537 | None | None |
>| 2015-09-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 308339d18e7f6bc521bcf78e260f546e | None | None |
>| 2015-09-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 657a510af7716efa3cec3460808cd9ee | None | None |
>| 2015-09-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 106966ea73725a5eb0f0af25641bc3a4 | None | None |
>| 2015-09-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1b3c2732a4139ee8d9462a8d3581b347 | None | None |
>| 2015-09-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | f3deea76078bb70046b03b5796f43a34 | None | None |
>| 2015-09-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | c64683804fea07baccccb50a47b6a675 | None | None |
>| 2015-09-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | c6ce40b60db6f60e5765ab4f61132275 | None | None |
>| 2015-09-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | e33b13066dbcebca0b39276f05a8fba1 | None | None |
>| 2015-09-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0a1112ddd47831f4267e263aec336b3d | None | None |
>| 2015-09-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | d8061326f8edd567b3540a9a7c7c7c41 | None | None |
>| 2015-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | ab286de67a1d1edeff22520db303a721 | None | None |
>| 2015-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | cad3b457ca2e5493f3c4b9cd6c36a7ce | None | None |
>| 2015-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7afbdefaec9ebebff4e583b2ac6a99a6 | None | None |
>| 2015-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | b55b0ee9ff9b05b6785581741cabb98c | None | None |
>| 2015-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4c451afe7a7360287b548c20250d1cd9 | None | None |
>| 2015-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 9f6b90029c7214193b7d16686b25917d | None | None |
>| 2015-09-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | cb37c6c144bac63ead5abf58f6b0163c | None | None |
>| 2015-09-13 | butterfly.bigmoney.biz | 106.187.43.98 | None | bbfa0f4c8c6586628b7120fc07446ceb | None | None |
>| 2015-09-13 | butterfly.bigmoney.biz | 106.187.43.98 | None | c9f641849fff25c4643cda4723a60ad7 | None | None |
>| 2015-09-13 | butterfly.bigmoney.biz | 106.187.43.98 | None | 33afc90b914d8d065d783d12ffbaf3a0 | None | None |
>| 2015-09-13 | butterfly.bigmoney.biz | 106.187.43.98 | None | 266cfe4e377e2c515368912374203405 | None | None |
>| 2015-09-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3149aa3741543c0c3817f7acd7e06a09 | None | None |
>| 2015-09-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | a2e5eeba19d4a8a404cce7e19fb8715b | None | None |
>| 2015-09-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | de80e0d158e954dedd19d7acdc531a7f | None | None |
>| 2015-09-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 37442afc905237cd6dc1e89b9bdb0b36 | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | ebe083f30bba285d69da0085f283b10b | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | fe2071dfcd3cd67276a29f4abb450820 | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 76.74.255.138 | None | f30ac63c6059def8e268af4838f59019 | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | b92f99d535533e5facfd7eb545c2af65 | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | f03b444364b5472dc3109235a5bd870d | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | f0232f8e3dafb034bd44568ed86899af | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 67.210.170.170 | None | df639ecf9557231ade58aceb347e13cb | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 76.74.255.138 | None | dc3ed39e0fe39fdc4a458ddb893be7ea | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 76.74.255.138 | None | f99b5858cd73019f7d457af71fda0c36 | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 76.74.255.138 | None | f0bbd6b9f87c99d32e61e232725d1798 | None | None |
>| 2015-09-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | fdffa611bd4b6658c32b38e7e184cae6 | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 127.0.0.2 | None | de7d53372a11440842ffd81efa445f24 | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 76.74.255.138 | None | f48d465efcfc47ea12a4253bc095e9f9 | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | f551e82e2f92d95311d4f311a695db0c | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7d4d5f08af7e549d8af252b9219fa1d1 | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 67.210.170.170 | None | f1b98edc7f024ae5bb92460688432bba | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 463a7442b82a84f565dcecfdcb206ffc | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | fff3df0197353b5c511a2b0cef724aaa | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 76.74.255.138 | None | f42a398d1f7f4ee22771c34e2c31b2bb | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 67.210.170.170 | None | d876e9d559ba2e4b278a02378200855b | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 76.74.255.138 | None | f3048b6abe287f86889786b781d28563 | None | None |
>| 2015-09-08 | butterfly.bigmoney.biz | 67.210.170.170 | None | dcbfdaf47919623d36a232312428a5bd | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 76.74.255.138 | None | f5012ad9c13ba7f2b17001db9b46718c | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | fc3c5d6fc8d891069fc9877ce49bd07f | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | f70b7487c3813c0c4ed755cd7db7bcd4 | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | de7efee30b18b74c18ee7d974f2e166b | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | fb872369a66611bdcc700f0ae386ca0b | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 76.74.255.138 | None | f00e96e864703fe24ed85b3cfe5c6880 | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 400742867b63d433c834b35b79deb92d | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | ee6bef5712e8f76870ecac5dfdc1d3bb | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 038fb610f48ebcc352e732c99fd1e622 | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | fdbec06d524b231eb2b2d8eab7fa4a94 | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 67.210.170.170 | None | f85f1130af653117b4f5be3d12245481 | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | faa7ec3d679b4711a447b6a9189b5cbe | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 22ec47f2c536e2c5ee3080e5f9d68d28 | None | None |
>| 2015-09-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | f3b4c84f2e5db34d528a2faaef97cb85 | None | None |
>| 2015-09-06 | butterfly.bigmoney.biz | 76.74.255.138 | None | f9ecbf532bb6f6c017fa0b72f7dcfa7d | None | None |
>| 2015-09-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | 77f34e89e17de8b9b16a008d63e80007 | None | None |
>| 2015-09-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | bd766e5ee7d7c0a22d8565c792000dd3 | None | None |
>| 2015-09-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | cb056fe4fe93984cd2420933ffd4761a | None | None |
>| 2015-09-05 | butterfly.bigmoney.biz | 67.210.170.170 | None | f73967c2d0a4c4c635118b2710fd3068 | None | None |
>| 2015-09-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | e77079d040d7bd48aeac8f0769959ebd | None | None |
>| 2015-09-05 | butterfly.bigmoney.biz | 67.210.170.170 | None | f69b67799bd99fb404279a7a0b9ccac3 | None | None |
>| 2015-09-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | d8208c98574f1b5c13c6641113b4e99b | None | None |
>| 2015-09-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | f302c8d18bcde7a6d4a5c092f58aea4a | None | None |
>| 2015-09-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6b340f0c7510f348b00d6231f23bd50d | None | None |
>| 2015-09-03 | butterfly.bigmoney.biz | 76.74.255.138 | None | db2408b84f0901b62faf7e2a1aef6809 | None | None |
>| 2015-09-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | d0e271a3a441bc7e04803f3156df5168 | None | None |
>| 2015-09-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | d92a3dc83f7f4161908586aa306ad7a3 | None | None |
>| 2015-08-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | 15310164fbceba3c6fbd6257bb496a6f | None | None |
>| 2015-08-31 | butterfly.bigmoney.biz | 67.210.170.170 | None | dc9a7ae4424cbb8e2b767ab71d5bcf30 | None | None |
>| 2015-08-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2c513da65bcb9a09e3bb78637af843dc | None | None |
>| 2015-08-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0b0eaefd8f4d1c98e2eda9d1e2928885 | None | None |
>| 2015-08-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2f67c32071b419bb94e8dddde9b21407 | None | None |
>| 2015-08-30 | butterfly.bigmoney.biz | 67.210.170.170 | None | ddbb837f93d837308d8f289d413da0e5 | None | None |
>| 2015-08-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | ebc3d159f1fbea4b8dc5b0762bd31cdf | None | None |
>| 2015-08-28 | butterfly.bigmoney.biz | 76.74.255.138 | None | d9d7d8534e893cd8b275f969066d61f0 | None | None |
>| 2015-08-28 | butterfly.bigmoney.biz | 67.210.170.170 | None | d723fe70ec0ba7b66f9d778ba1057447 | None | None |
>| 2015-08-28 | butterfly.bigmoney.biz | 67.210.170.170 | None | d9ec8e5e45413e4b313638feea467820 | None | None |
>| 2015-08-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | 46c4e2c8d586697e6fc6ed4ebcac5889 | None | None |
>| 2015-08-27 | butterfly.bigmoney.biz | 67.210.170.170 | None | d419c716724b06ef74a8cb8a4a2639dd | None | None |
>| 2015-08-26 | butterfly.bigmoney.biz | 67.210.170.170 | None | d28c314a8267a9a61f4534a4b30bd08f | None | None |
>| 2015-08-26 | butterfly.bigmoney.biz | 76.74.255.138 | None | d3a2bd3bde6e98a3f219239cf8c64165 | None | None |
>| 2015-08-26 | butterfly.bigmoney.biz | 76.74.255.138 | None | d216d117b7150cbaf07fc4efba38064e | None | None |
>| 2015-08-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | ca1ab5d7e0dfae4e11c1f44a2adcecc6 | None | None |
>| 2015-08-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 390f42dc637c60f527583891ca46238d | None | None |
>| 2015-08-24 | butterfly.bigmoney.biz | 173.255.212.165 | None | c5b0d8235a1d82699717a56c4cadb0f0 | None | None |
>| 2015-08-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | beaf110af6f86783909d016ea00c3907 | None | None |
>| 2015-08-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | bec6877cd8615753aad2c39953df6b88 | None | None |
>| 2015-08-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0535fe8608ca3716a01303e5cedd13d6 | None | None |
>| 2015-08-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | e140756abee7be1b07e6ddf00c94d8f4 | None | None |
>| 2015-08-23 | butterfly.bigmoney.biz | 106.187.43.98 | None | d0aaaa7859b3184ce0f8bde5dbd8e0c6 | None | None |
>| 2015-08-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4ff927a131a05c2310e686de2ab0afdc | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | 59df76c1bbf9281d11439f020990f8f7 | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3dd049b3122b766606f65630ab9dc066 | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 65db1f061b5b21394a1364b2d4ec9d2e | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4a7355c3cd94782808d89ea58f040fae | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 443f77ab64e00e55a70063769a084eed | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | bcb363dd3d58582b73d467945e3a9229 | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | 15e7ab91313ae174ea9dc7894dad8609 | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | bda6c0f23d400c5d55ef491487b4a7db | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | dbb6ccd948406c65c878823f77eca2a1 | None | None |
>| 2015-08-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | bd46e08061bec10cb3c7be5ca6754af4 | None | None |
>| 2015-08-21 | butterfly.bigmoney.biz | 173.255.212.165 | None | b94b10bc1731e3364e86f89bbcec0ce4 | None | None |
>| 2015-08-21 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1d04a84b08ff75a897e654fc795dad22 | None | None |
>| 2015-08-21 | butterfly.bigmoney.biz | 173.255.212.165 | None | 34ba602087d5abae00c42a288b1ac04e | None | None |
>| 2015-08-21 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1c425114941bd653c9682b922abdcc49 | None | None |
>| 2015-08-20 | butterfly.bigmoney.biz | 173.255.212.165 | None | b906b6545fb62b472c52573fb7456e16 | None | None |
>| 2015-08-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | c5cfbbe0b9937105135f7c886ae26f09 | None | None |
>| 2015-08-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 518a26c697ecda7723247b292ab6fa33 | None | None |
>| 2015-08-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2d32f9678a9af570ef8ae326581644f2 | None | None |
>| 2015-08-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2489d943b2561fc0bce06d90a7e4a6cc | None | None |
>| 2015-08-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2de0326ff5165ebd4d2abc882d2c3476 | None | None |
>| 2015-08-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | 30665caf4a010bfd9ba9727c94885bec | None | None |
>| 2015-08-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4143a9f42c16c1d54d4c1102c1f3a954 | None | None |
>| 2015-08-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | b08c413496fb617eb3310f4ed8b13697 | None | None |
>| 2015-08-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | a99b54e5babbc105ea7a40f1eba9a9f5 | None | None |
>| 2015-08-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6f7e9f9c39a16aaf9ffb149483a0131e | None | None |
>| 2015-08-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | 651ba39923114fc894ae41783e73449e | None | None |
>| 2015-08-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | ead794a64a18b04e01648418d0882a57 | None | None |
>| 2015-08-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4f47e7f832f2aa1762f451cbbe786896 | None | None |
>| 2015-08-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | b7410c693756acaee26dee55bcb03fca | None | None |
>| 2015-08-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | a0714af77d6f6ac099242a343eb4741a | None | None |
>| 2015-08-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | a309afd50272ecfc87fb7600c2d77fa6 | None | None |
>| 2015-08-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | 62fb79036a196745362515692f0a4a83 | None | None |
>| 2015-08-05 | butterfly.bigmoney.biz | 106.187.43.98 | None | b155bf00edb39180285384f9ade5b982 | None | None |
>| 2015-08-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | af83e8ffde26561d05cb383f62b7b761 | None | None |
>| 2015-08-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 45488e080f41adaa566ee3b00f02237c | None | None |
>| 2015-08-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | ac9f56bb9a73c27a0e085be100467d76 | None | None |
>| 2015-08-03 | butterfly.bigmoney.biz | 76.74.255.138 | None | bb31d32910ab3dd542050490e9d9242f | None | None |
>| 2015-08-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | a1066b9708203d9a92e2b3fa4bcb882e | None | None |
>| 2015-08-02 | butterfly.bigmoney.biz | 67.210.170.170 | None | ba10c3260173c476706db0c189dda635 | None | None |
>| 2015-08-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | a7579cf6586c34d365ccc2638f2b8c55 | None | None |
>| 2015-08-02 | butterfly.bigmoney.biz | 67.210.170.170 | None | b6da5f7231cd50bb867218e00d19fa29 | None | None |
>| 2015-08-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | b8d00f68a653d0a80809e101542bf949 | None | None |
>| 2015-08-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | a9baefc3ca2daa790a8de1cd1baf02bd | None | None |
>| 2015-08-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | 01164a6cad79acd32ecf8da6b8168b8e | None | None |
>| 2015-08-01 | butterfly.bigmoney.biz | 173.255.212.165 | None | b63eb3c9ad19137117cc1298d63d474f | None | None |
>| 2015-08-01 | butterfly.bigmoney.biz | 173.255.212.165 | None | b62e952e457f416d4430ca126af39f2f | None | None |
>| 2015-08-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | d4acb9eca0e8dc1749238a827f785bac | None | None |
>| 2015-08-01 | butterfly.bigmoney.biz | 76.74.255.138 | None | b1f232b5f5d19e59ccc3af2478b14327 | None | None |
>| 2015-08-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3a4b5bd8f6c2b76c80025f639ea5e80a | None | None |
>| 2015-08-01 | butterfly.bigmoney.biz | 173.255.212.165 | None | b61d78842ccf46b8d89e04bdded179d8 | None | None |
>| 2015-08-01 | butterfly.bigmoney.biz | 173.255.212.165 | None | a2cfcc8fd5231bee4f849b984982a2d1 | None | None |
>| 2015-07-31 | butterfly.bigmoney.biz | 76.74.255.138 | None | a369146bc1a36aa5b5788cdeea3958ee | None | None |
>| 2015-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | f3a5c57c2b85c74b34fa7bc525aec5e0 | None | None |
>| 2015-07-31 | butterfly.bigmoney.biz | 173.255.212.165 | None | a05439071ff3d34deed8c96b66755313 | None | None |
>| 2015-07-31 | butterfly.bigmoney.biz | 106.187.43.98 | None | ea3a88da8025040e1fb70f4899b76f45 | None | None |
>| 2015-07-30 | butterfly.bigmoney.biz | 173.255.212.165 | None | 7d3710980a3a0d88dcb8b38d297627fb | None | None |
>| 2015-07-30 | butterfly.bigmoney.biz | 173.255.212.165 | None | 9bad4cb7f71cd9a45ea84f5a1df366e6 | None | None |
>| 2015-07-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | 9c112c80700dc8feca3ef9e90245a07c | None | None |
>| 2015-07-29 | butterfly.bigmoney.biz | 173.255.212.165 | None | a473c2f676cc7807c60636e6218644e2 | None | None |
>| 2015-07-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | 70132aaf560b57e0a07b193e8a8e49e1 | None | None |
>| 2015-07-29 | butterfly.bigmoney.biz | 173.255.212.165 | None | 9933e958ae795a8e75dee811971066ef | None | None |
>| 2015-07-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | f64c7f9ad2b37ee375b5e3b568fe1cdc | None | None |
>| 2015-07-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | 96df3af41d896d23e641f0954b4c86a6 | None | None |
>| 2015-07-28 | butterfly.bigmoney.biz | 173.255.212.165 | None | a11e65006ca50dba4aadef784534bac6 | None | None |
>| 2015-07-28 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0d12b2cc160a51738dcda34665a5fa28 | None | None |
>| 2015-07-28 | butterfly.bigmoney.biz | 173.255.212.165 | None | 90fae2a55379d31a15701877184c2d97 | None | None |
>| 2015-07-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | 41960c7566c16edf4d4b25e3cfee524b | None | None |
>| 2015-07-27 | butterfly.bigmoney.biz | 173.255.212.165 | None | 8d863e7b619a9a61b72e2b50bb38e3a7 | None | None |
>| 2015-07-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8346dc6d874b3287496d40d8374e8aec | None | None |
>| 2015-07-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 99cb24bc6f951d950cc0335a5eb64f6b | None | None |
>| 2015-07-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 87e51957f14dd4eca8b284b6332fcd0b | None | None |
>| 2015-07-26 | butterfly.bigmoney.biz | 10.92.80.169 | None | 891e758b2de0d59da531bcef231b643e | None | None |
>| 2015-07-26 | butterfly.bigmoney.biz | 173.255.212.165 | None | 9abb14277a366b863e07fd56154f86f3 | None | None |
>| 2015-07-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8747863884c21494b2bb85533475c1a9 | None | None |
>| 2015-07-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7004985bb72c947a3f3da3c286560e51 | None | None |
>| 2015-07-25 | butterfly.bigmoney.biz | 10.92.80.169 | None | 819cd25eadfff55779357df7bea1b7b7 | None | None |
>| 2015-07-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | 8232e034cb29b1006bb69fed5fa06ab8 | None | None |
>| 2015-07-24 | butterfly.bigmoney.biz | 106.187.43.98 | None | 97c351c96afcbbead6571ee99a09335d | None | None |
>| 2015-07-24 | butterfly.bigmoney.biz | 173.255.212.165 | None | 917863a51b078ca22ead42c0844ae4db | None | None |
>| 2015-07-24 | butterfly.bigmoney.biz | 67.210.170.170 | None | 96eb7cc85592f67010a3b0e9840c0fe1 | None | None |
>| 2015-07-24 | butterfly.bigmoney.biz | 67.210.170.170 | None | 94e4bf0b765c35f7bb1fe060e00ad969 | None | None |
>| 2015-07-24 | butterfly.bigmoney.biz | 173.255.212.165 | None | 91a2a24955067d757a85634ed222993f | None | None |
>| 2015-07-24 | butterfly.bigmoney.biz | 173.255.212.165 | None | 7ee46ac5fc4f5fbf9ad38ac05db18821 | None | None |
>| 2015-07-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | 7819e30c8b31550de8ac6a00c7535018 | None | None |
>| 2015-07-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | 93f323c5cd8b7102e8c1121dc99b5189 | None | None |
>| 2015-07-23 | butterfly.bigmoney.biz | 67.210.170.170 | None | 929de4f9cbc97d152225edf6cda5224a | None | None |
>| 2015-07-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | 7538b10ffd7d30d8217c4aef7ef30924 | None | None |
>| 2015-07-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | 733d41e157e8426cdbe07a27df695e73 | None | None |
>| 2015-07-22 | butterfly.bigmoney.biz | 106.187.43.98 | None | 099e9697241302ec756e3108f8b93763 | None | None |
>| 2015-07-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 6a656784ee4fe8237e080c7e0ebf84ab | None | None |
>| 2015-07-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | 417d798023983cc39adcb8ff192a7349 | None | None |
>| 2015-07-20 | butterfly.bigmoney.biz | 173.255.212.165 | None | 6bb151d7ecbc95ae1715fe2faa8279be | None | None |
>| 2015-07-20 | butterfly.bigmoney.biz | 67.210.170.170 | None | 6b6bc5a1a8626ca99f9de1e2e1699066 | None | None |
>| 2015-07-20 | butterfly.bigmoney.biz | 76.74.255.138 | None | 6d12a48db6dbf584355eb9c79a31d98e | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 76.74.255.138 | None | 6942f6c33932ff29a1743f7064b0c578 | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | 685376f8315271467015e9b2c5e0d228 | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 76.74.255.138 | None | 6a034c3da9ad4962c5e2be9b6f1bcb3b | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 173.255.212.165 | None | 699cabc2647d42ff86092078e292b7d9 | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 173.255.212.165 | None | 690a77827cc9d2cad8f81d8149dee38b | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 173.255.212.165 | None | 6a9ed4db4ff3651550a009f35a9daa04 | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 173.255.212.165 | None | 6a8d773e5d1c371165db50b7fab9c213 | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | d608c0ba5bd31a1846aa3246d547d174 | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 10.92.80.169 | None | 68e197d6e83f9cfd60a4bcd64887afa5 | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 76.74.255.138 | None | 69804ae9503211ac2c865e3f746effac | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 76.74.255.138 | None | 6a562bc41fb4d5d4da8ece17901aa5fe | None | None |
>| 2015-07-19 | butterfly.bigmoney.biz | 76.74.255.138 | None | 69fc2fe1910f772e3b2b41a9b1d6fbb1 | None | None |
>| 2015-07-18 | butterfly.bigmoney.biz | 173.255.212.165 | None | 67e1d40b54f5e47af665df8c2bc6c958 | None | None |
>| 2015-07-18 | butterfly.bigmoney.biz | 67.210.170.170 | None | 67a5ddebf65772069fb12260f0b74613 | None | None |
>| 2015-07-18 | butterfly.bigmoney.biz | 67.210.170.170 | None | 68284ea7f8d127f3d247c967d6754ed1 | None | None |
>| 2015-07-18 | butterfly.bigmoney.biz | 173.255.212.165 | None | 67cfa204e1c448a84a87b0a550b42a46 | None | None |
>| 2015-07-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2c5a2d8b9cbe89545b51cc7b1f64164d | None | None |
>| 2015-07-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | 995e50c7f1eeba613d10696c7d733a98 | None | None |
>| 2015-07-18 | butterfly.bigmoney.biz | 76.74.255.138 | None | 6842d071638461d7865528cdf7084127 | None | None |
>| 2015-07-17 | butterfly.bigmoney.biz | 76.74.255.138 | None | 6547d762e8dd1d6ab452ddc7254712ba | None | None |
>| 2015-07-17 | butterfly.bigmoney.biz | 173.255.212.165 | None | 62820a79d265376f1250d609e59fad50 | None | None |
>| 2015-07-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | 197c633df03bb6bb123f6fbd2276fe0f | None | None |
>| 2015-07-17 | butterfly.bigmoney.biz | 67.210.170.170 | None | 64a5aca8f8646d0821e6fd86d4a42dde | None | None |
>| 2015-07-16 | butterfly.bigmoney.biz | 67.210.170.170 | None | 60f2cecb9ce42028685a471f4fcd84f4 | None | None |
>| 2015-07-16 | butterfly.bigmoney.biz | 67.210.170.170 | None | 60b751ef26f940c6d1d05a0918b14ca8 | None | None |
>| 2015-07-16 | butterfly.bigmoney.biz | 76.74.255.138 | None | 6117b36b64fd3f88a44308276ccdd83e | None | None |
>| 2015-07-16 | butterfly.bigmoney.biz | 173.255.212.165 | None | 61d150a8700ec43904c562f082e7e02b | None | None |
>| 2015-07-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7244df9d5356e5636d71fafa03dd9398 | None | None |
>| 2015-07-15 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5dea7447a17172ffc15e074a12fc532c | None | None |
>| 2015-07-15 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5f044290ae5c2f8992477c1d38d004ea | None | None |
>| 2015-07-15 | butterfly.bigmoney.biz | 10.92.67.195 | None | 5cc7660694654db4863caf77bb41e1d7 | None | None |
>| 2015-07-14 | butterfly.bigmoney.biz | 173.255.212.165 | None | 58ed850bf3907a889dcdbc3b2af63726 | None | None |
>| 2015-07-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 558591a5cbc6c0cdee0e9835ad888199 | None | None |
>| 2015-07-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | ef41b65e7b420fa0ca38a15d9c17fa7e | None | None |
>| 2015-07-13 | butterfly.bigmoney.biz | 173.255.212.165 | None | 55e02756713ea93b3f496f471809cbb7 | None | None |
>| 2015-07-13 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5666bbfc3f5873fdd69b51b3d4887eeb | None | None |
>| 2015-07-12 | butterfly.bigmoney.biz | 173.255.212.165 | None | 537fdcd053b588e99cc78fa41dcc8e4d | None | None |
>| 2015-07-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | 46777804ffb93692d79adbec565a1d74 | None | None |
>| 2015-07-12 | butterfly.bigmoney.biz | 76.74.255.138 | None | 542260af52e968413bcae6eb740b0f97 | None | None |
>| 2015-07-12 | butterfly.bigmoney.biz | 10.92.73.18 | None | 53ae90fdfd5601fd42be7a267c21a4c6 | None | None |
>| 2015-07-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | e4127f0221f0460ae2af35c409f5d0a1 | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4e04caa47c8d2530212973adbf155a61 | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4dd68e09d17c8281d26eb33ed1eb4fe5 | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4e46b1650717086ca1cdee0eaafee624 | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 76.74.255.138 | None | 503c35c6c6beaf173fbdc0b43e8e09a7 | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 67.210.170.170 | None | 5021cb452a2c8f6f0de3bec2d62f08fa | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 67.210.170.170 | None | 5075cf55b1700a85dcefaed3314856eb | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 76.74.255.138 | None | 7c569fc12c7384c3cd83e172f59faded | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4dd6aabec5c7e0eba945f2ecfecb5d2d | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4e07fd251688aa85bf05d3afb009a202 | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 76.74.255.138 | None | 518ca900d2463587624573093dbdb1fd | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | f46bad1d0db1a19f7536b85ebcbc24c9 | None | None |
>| 2015-07-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4ea11243194860a08083367b34e59d19 | None | None |
>| 2015-07-10 | butterfly.bigmoney.biz | 173.255.212.165 | None | 49e91830bb6d35df41c053fbbb24e194 | None | None |
>| 2015-07-10 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4d379449889da4a8088818b4c285bfce | None | None |
>| 2015-07-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 4cc2f2e9ee94aef3f11b60f1e438a2ff | None | None |
>| 2015-07-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | c46101f576aa964ec806404788c6fd57 | None | None |
>| 2015-07-10 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4bb8e3d0844a4b797ed74859cbdc3615 | None | None |
>| 2015-07-10 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4b353d918afa74652acbe8be68de1798 | None | None |
>| 2015-07-10 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4db4b4355dd791d590f9e416a515650e | None | None |
>| 2015-07-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | dbd0ccf4f779ce9b447f806a29e8c0ff | None | None |
>| 2015-07-09 | butterfly.bigmoney.biz | 76.74.255.138 | None | 77d31669b517fd4867504015d8548d9a | None | None |
>| 2015-07-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 39601d7a778132b4075b5a69a139859a | None | None |
>| 2015-07-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | 49d6b46c941f263ead2e635d5d16ff49 | None | None |
>| 2015-07-09 | butterfly.bigmoney.biz | 76.74.255.138 | None | 482062b560a32f51de2fbf6191a17e60 | None | None |
>| 2015-07-09 | butterfly.bigmoney.biz | 76.74.255.138 | None | 4a972f73a5e888014d11e79e2d433ee0 | None | None |
>| 2015-07-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 46be70f8fdedf330bd813ca96a38b44d | None | None |
>| 2015-07-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 36c38b0d2f01cd311e126cd0542005ec | None | None |
>| 2015-07-08 | butterfly.bigmoney.biz | 67.210.170.170 | None | 473338795b6e8667668dc06fd21499bc | None | None |
>| 2015-07-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 75ee6cccca2fbbbb674e51dc2839993f | None | None |
>| 2015-07-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 451730eeb1409d3d8bbb1adad06800fd | None | None |
>| 2015-07-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | cdb7c1a435955e1bbbb5bb527843249f | None | None |
>| 2015-07-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3257f90ceac5e897fdc1a7670b6fb079 | None | None |
>| 2015-07-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | 74868092c868e7183829cdae8375032a | None | None |
>| 2015-07-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | 418f2c9e73f46b623ce90eee30c03940 | None | None |
>| 2015-07-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | 40c671da982c48f1224dff5116025219 | None | None |
>| 2015-07-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | 74dbd77d9b29a28bbc46923e85835d86 | None | None |
>| 2015-07-07 | butterfly.bigmoney.biz | 76.74.255.138 | None | 42e88c8f664bcdf24b69eff4ddd248c6 | None | None |
>| 2015-07-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | d14e8b3826b458f95c83a22d755ff10d | None | None |
>| 2015-07-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3fce42a03fd3086c3e5cbf4899fd470a | None | None |
>| 2015-07-06 | butterfly.bigmoney.biz | 67.210.170.170 | None | 406363d4db3aae850064de45a4907f68 | None | None |
>| 2015-07-06 | butterfly.bigmoney.biz | 76.74.255.138 | None | 3fd9b998d568b83c1dddbec2f4006b4c | None | None |
>| 2015-07-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3d5d0cb5c088626a0f57cefce0fdb2f6 | None | None |
>| 2015-07-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3f478b1de8cf566cfe3b857eb9b32aae | None | None |
>| 2015-07-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | 3f0c93f04b3b08918227f75eabb3bc15 | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 173.255.212.165 | None | 711de5490271e0e5c705eb48cff3ff71 | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 76.74.255.138 | None | 3b79c0e6e4135b11d08fcfe32520a9f3 | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3bdef55e39165030dd67840f58b08cad | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 76.74.255.138 | None | 3ba14fae43400ceff572bf99ab3a4685 | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3b3f180ecf9d746baa125577623d4a16 | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 10.92.79.202 | None | 3d2b168643a0d32492ee75f0155657ef | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3ba3cedfefcb22d5755af7029dc28221 | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3bbf7e7bee9622fa4cf2cb454458180e | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 76.74.255.138 | None | 3b94d100f9d0e2244c0e48a53b610a64 | None | None |
>| 2015-07-05 | butterfly.bigmoney.biz | 67.210.170.170 | None | 3b9a2f850ffc98c78b72b1f30ec2f2de | None | None |
>| 2015-07-04 | butterfly.bigmoney.biz | 106.187.43.98 | None | 9a69f8a033c86d1e6d97982456b3d38e | None | None |
>| 2015-07-04 | butterfly.bigmoney.biz | 76.74.255.138 | None | 3b8b30e789535f683879a25c9ccee13b | None | None |
>| 2015-07-04 | butterfly.bigmoney.biz | 173.255.212.165 | None | 7037d9b549803726fd0b26ead2c10f24 | None | None |
>| 2015-07-04 | butterfly.bigmoney.biz | 173.255.212.165 | None | 383a367265a2aa685018c6c074c32011 | None | None |
>| 2015-07-04 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3991c4d13c873e2c899494f7e9752c58 | None | None |
>| 2015-07-04 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3ad3a9ef0672f1e983d92aa6cfb5a3af | None | None |
>| 2015-07-04 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3adb7c5922bf3d1fa0145a8ac39071d6 | None | None |
>| 2015-07-04 | butterfly.bigmoney.biz | 76.74.255.138 | None | 39b4f1890c6fc22ffbf9ac6e41c47478 | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 76.74.255.138 | None | 38aea1b4dfc4cb156c82c098a259874b | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 173.255.212.165 | None | 396145b5c6fad1adf2d519fde64166a5 | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 173.255.212.165 | None | 373c5bf736f17f2ce6173dab74f02163 | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1d0a40eeb2b35dd1fd5456e433318150 | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 106.187.43.98 | None | fb65683f10ae174f631848f297c6ee49 | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 173.255.212.165 | None | 380edba4752b1358f4ee955425551c41 | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 76.74.255.138 | None | 387191c902a826c8dc550c0841422681 | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 173.255.212.165 | None | 6ce3d6eeeca6776f6699edd855601288 | None | None |
>| 2015-07-03 | butterfly.bigmoney.biz | 173.255.212.165 | None | 39c62271fbfec69d6d9acb2bc74518e7 | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | 33a9b7dc5d2daaafed5be1ee164261b9 | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3410afac4c6ccd17dbe0d8169d818f3e | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | 36275c665c4a760c4ca61ddb9451b8bc | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 76.74.255.138 | None | 33be4502c630b2d9bf6e788a78a8c6bb | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | 349411f7a9020ba79a723f81d7c81072 | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 76.74.255.138 | None | 35645a31ebdc84b0839c463bbf176e99 | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3618625ac68e0b099bf5272446735492 | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 106.187.43.98 | None | 354c67e782120e226760b84ca79baa9e | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | 35089bb5279f53f6b9693842cfb1a370 | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 76.74.255.138 | None | 365b856b69ef247e325e12ab2ac53725 | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 173.255.212.165 | None | 365a0a08f21a63b578597ad3768302c6 | None | None |
>| 2015-07-02 | butterfly.bigmoney.biz | 76.74.255.138 | None | 345bbc63067db437d38defb4cab8ecb8 | None | None |
>| 2015-07-01 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3365a35ac6d5156b1b79b4d760362bfe | None | None |
>| 2015-07-01 | butterfly.bigmoney.biz | 106.187.43.98 | None | 21be290dc52e92d744d41a901b0e3f76 | None | None |
>| 2015-07-01 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3229dff5ab4d56ef185d8d5d7615e569 | None | None |
>| 2015-06-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | f299125fb61f9fbce49409488d7d9e51 | None | None |
>| 2015-06-30 | butterfly.bigmoney.biz | 173.255.212.165 | None | 67edfd8fdd76e25e8768a0213fc7c595 | None | None |
>| 2015-06-30 | butterfly.bigmoney.biz | 106.187.43.98 | None | f039d7ca570161205577c51a4a17cecb | None | None |
>| 2015-06-29 | butterfly.bigmoney.biz | 76.74.255.138 | None | 30abd2b763c72dddc6ea711110c1930c | None | None |
>| 2015-06-29 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2f05840682f2a7c45407feee7a2c2efd | None | None |
>| 2015-06-29 | butterfly.bigmoney.biz | 10.92.80.169 | None | 2f983284680a5d0c965887fe84fcf171 | None | None |
>| 2015-06-29 | butterfly.bigmoney.biz | 173.255.212.165 | None | 305ac55a9d29f940319e57c8b695e5c2 | None | None |
>| 2015-06-29 | butterfly.bigmoney.biz | 173.255.212.165 | None | 30774972433e6a3c0b093912d51df382 | None | None |
>| 2015-06-29 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0a4af632053aa39c6cdf89a4b2568efe | None | None |
>| 2015-06-29 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2f0ceeb1c78950bc5132c471572be412 | None | None |
>| 2015-06-28 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2e97d3516f28223770bbbce5aa535ba0 | None | None |
>| 2015-06-28 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2e71ed5214d8fc8693a8efeaf3da8650 | None | None |
>| 2015-06-27 | butterfly.bigmoney.biz | 10.92.80.169 | None | 2c9ad1005b9e5d038580e0226173240a | None | None |
>| 2015-06-27 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2caebab75140002bd908e723b05ca6fb | None | None |
>| 2015-06-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | 5add2afe1b9af6d17bfe17913b128a24 | None | None |
>| 2015-06-27 | butterfly.bigmoney.biz | 106.187.43.98 | None | 019b2b93e4ab030da87a30d7c7dce131 | None | None |
>| 2015-06-27 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2cdd71e59f235f7ded759340756becbe | None | None |
>| 2015-06-27 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2b8b1ce2b39cbdb3387e7d5bad5b871b | None | None |
>| 2015-06-26 | butterfly.bigmoney.biz | 173.255.212.165 | None | 63358e405a565f12bc0b809cdc08bbdc | None | None |
>| 2015-06-26 | butterfly.bigmoney.biz | 76.74.255.138 | None | 2a476df7d3c7028cfbe35652b0d56cc1 | None | None |
>| 2015-06-26 | butterfly.bigmoney.biz | 76.74.255.138 | None | 2b644c5ed201ea461e7f620b512ca620 | None | None |
>| 2015-06-26 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2a672deadff5b2d06cb838cd5a4fef9d | None | None |
>| 2015-06-26 | butterfly.bigmoney.biz | 106.187.43.98 | None | ff31abb495750fbdc39f99dd3a7a6004 | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | 290e3e3ca66a8b63fba8005f11e2c16e | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2972e423f3a5f20257da3fa1933445cf | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | 60e68bec0111e70ea7adebb750f4649a | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | 251b2a4e4ca0db6f2f368daa3802e206 | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | 28ef735ea7e6f23b7e8251fc9b5620ef | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | 290e913a82e65e80dca2c202f0b8cda5 | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 67.210.170.170 | None | 297fe18c0944b07336bb5f1939dd593d | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 106.187.43.98 | None | f628e3a498321fefa23375a96b73d132 | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | 289aed5efeee9b3c4f3afea4afe4e6f2 | None | None |
>| 2015-06-25 | butterfly.bigmoney.biz | 173.255.212.165 | None | 28a35360a56a522783fca21afcafa601 | None | None |
>| 2015-06-24 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5ee6b4604ede99ce8c3ed229de3f4018 | None | None |
>| 2015-06-24 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5ed1438288f5f43c2b77bda577d66085 | None | None |
>| 2015-06-24 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2845fc3341b87222ba06679b27b4c806 | None | None |
>| 2015-06-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2752791de8c67bbeadc1fb62e7a48997 | None | None |
>| 2015-06-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5d0fe2dd9b72a052ade432c26d202e3f | None | None |
>| 2015-06-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5dbe45edd60bfaa77020ef81144680f8 | None | None |
>| 2015-06-23 | butterfly.bigmoney.biz | 76.74.255.138 | None | ec8e39a4e4b829e01952c0d093cbc45e | None | None |
>| 2015-06-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | ea20a8485ec84d8f49b5ff088672ec6d | None | None |
>| 2015-06-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | 26c83fa1c99608c6bea19b33ba578db5 | None | None |
>| 2015-06-23 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5c3b7fb32fa6997276b33861854d8682 | None | None |
>| 2015-06-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5ab0d4d072336418a6029d537c419d7a | None | None |
>| 2015-06-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | def9d97dc8ae8f66bab1979b36db0f0f | None | None |
>| 2015-06-22 | butterfly.bigmoney.biz | 173.255.212.165 | None | 268575bee897ffb3f961a1dc3b69a87b | None | None |
>| 2015-06-21 | butterfly.bigmoney.biz | 173.255.212.165 | None | 57d1e001d676dc7769eb51a96969c0f3 | None | None |
>| 2015-06-21 | butterfly.bigmoney.biz | 173.255.212.165 | None | 25ed65cfc64d0ef6e39fa11421eb18ab | None | None |
>| 2015-06-21 | butterfly.bigmoney.biz | 10.92.80.169 | None | 259fd3c2cfaac42727522ef34a5fb695 | None | None |
>| 2015-06-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | db15b941dd8beeb23b67599aa10d1494 | None | None |
>| 2015-06-21 | butterfly.bigmoney.biz | 106.187.43.98 | None | dbc9f64ecb5cf050ce1b979ac4106dad | None | None |
>| 2015-06-21 | butterfly.bigmoney.biz | 173.255.212.165 | None | 25b8dfab085f44e023ec6f543bf00298 | None | None |
>| 2015-06-20 | butterfly.bigmoney.biz | 76.74.255.138 | None | d1cf4870653e04e9f39efe53ee0de31c | None | None |
>| 2015-06-20 | butterfly.bigmoney.biz | 173.255.212.165 | None | 24f32bfe8935d07a8d15414e11c300e9 | None | None |
>| 2015-06-20 | butterfly.bigmoney.biz | 106.187.43.98 | None | d1afa3b84e9d96b2bc9a88e8cc739ec3 | None | None |
>| 2015-06-20 | butterfly.bigmoney.biz | 173.255.212.165 | None | 55ef3ff8c8859db8da1065bec62b9942 | None | None |
>| 2015-06-19 | butterfly.bigmoney.biz | 173.255.212.165 | None | 24c1f0209232cbcc6994298ee5800f8b | None | None |
>| 2015-06-19 | butterfly.bigmoney.biz | 173.255.212.165 | None | cc44236d9b0cd1fd7b25bc44e1a5739e | None | None |
>| 2015-06-19 | butterfly.bigmoney.biz | 173.255.212.165 | None | 2454a5e2517927055c8054947d6fe41b | None | None |
>| 2015-06-19 | butterfly.bigmoney.biz | 106.187.43.98 | None | ce1239290263a915205cfc5a3655d4e9 | None | None |
>| 2015-06-19 | butterfly.bigmoney.biz | 173.255.212.165 | None | 54b349a7dd3b2ca44d88d926e3ab80ac | None | None |
>| 2015-06-19 | butterfly.bigmoney.biz | 76.74.255.138 | None | 24303feb1a7ea27b9e64adeba00790cb | None | None |
>| 2015-06-18 | butterfly.bigmoney.biz | 173.255.212.165 | None | 23e7ef6869608d40f5e6e4ef6cb364da | None | None |
>| 2015-06-18 | butterfly.bigmoney.biz | 173.255.212.165 | None | 50b75a1b0654daf5294e62a8ae658595 | None | None |
>| 2015-06-18 | butterfly.bigmoney.biz | 173.255.212.165 | None | 5153b2b1772d001b4b5a163a07f52651 | None | None |
>| 2015-06-18 | butterfly.bigmoney.biz | 106.187.43.98 | None | c64e4db2c8b4f87d37defb071d050b29 | None | None |
>| 2015-06-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | bd46cb71ee51f2d9c79cbf7791bf320c | None | None |
>| 2015-06-17 | butterfly.bigmoney.biz | 106.187.43.98 | None | a4e130ca56cfdd423f658ea57c93be0f | None | None |
>| 2015-06-17 | butterfly.bigmoney.biz | 76.74.255.138 | None | 4ea266739476e7db0f5bf849047f431b | None | None |
>| 2015-06-17 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4f203ae30061654ef4920f0be8f19101 | None | None |
>| 2015-06-17 | butterfly.bigmoney.biz | 173.255.212.165 | None | c1ff850617553a56b173d65da2cc6c39 | None | None |
>| 2015-06-17 | butterfly.bigmoney.biz | 76.74.255.138 | None | 4f286cfeffe27a180dcd3661d0f887ed | None | None |
>| 2015-06-17 | butterfly.bigmoney.biz | 173.255.212.165 | None | c027e358ee144c40a6fb44f4657e267c | None | None |
>| 2015-06-17 | butterfly.bigmoney.biz | 173.255.212.165 | None | 231a0c4e70d488dc31be9964a01f7045 | None | None |
>| 2015-06-16 | butterfly.bigmoney.biz | 173.255.212.165 | None | 22d617bdc92ac729d8f876836fa4f7ce | None | None |
>| 2015-06-16 | butterfly.bigmoney.biz | 173.255.212.165 | None | f66cb0f2f9fbb8ef48e885a381ed3b7f | None | None |
>| 2015-06-16 | butterfly.bigmoney.biz | 106.187.43.98 | None | b9e3c8a8697218de1400531e7f612e39 | None | None |
>| 2015-06-16 | butterfly.bigmoney.biz | 173.255.212.165 | None | 4ad5603dfc6247e3b2195c4675e53478 | None | None |
>| 2015-06-16 | butterfly.bigmoney.biz | 76.74.255.138 | None | 4b508ab8ed46489187fc5c1ebbc0ee9b | None | None |
>| 2015-06-15 | butterfly.bigmoney.biz | 106.187.43.98 | None | ee2b28eff7a9615e73ca99b0f689b1c3 | None | None |
>| 2015-06-15 | butterfly.bigmoney.biz | 173.255.212.165 | None | 48e964c18ee86cdc645dcb0f39890158 | None | None |
>| 2015-06-14 | butterfly.bigmoney.biz | 173.255.212.165 | None | 217f7390de363344ce2d3173f2f1c7b9 | None | None |
>| 2015-06-14 | butterfly.bigmoney.biz | 106.187.43.98 | None | 0f3b701195124e78bb07823b588ab9dd | None | None |
>| 2015-06-14 | butterfly.bigmoney.biz | 76.74.255.138 | None | 217c5f9d3e74ed29a1c4b9d7e06379e5 | None | None |
>| 2015-06-13 | butterfly.bigmoney.biz | 173.255.212.165 | None | d89e51c0c740ec803c0ea7ec7079af4f | None | None |
>| 2015-06-13 | butterfly.bigmoney.biz | 173.255.212.165 | None | 20f8c0e3ea2868491b016d39c1dedfac | None | None |
>| 2015-06-13 | butterfly.bigmoney.biz | 173.255.212.165 | None | 20a3418aead0fe919961c23a3c419811 | None | None |
>| 2015-06-13 | butterfly.bigmoney.biz | 106.187.43.98 | None | ddfc4a11a762b750571b9e28afdf400c | None | None |
>| 2015-06-13 | butterfly.bigmoney.biz | 76.74.255.138 | None | 211ecc9f3c570d57636cb7910ab87a76 | None | None |
>| 2015-06-13 | butterfly.bigmoney.biz | 173.255.212.165 | None | 45151b2bb751cbf7743a1460cf0ad161 | None | None |
>| 2015-06-12 | butterfly.bigmoney.biz | 173.255.212.165 | None | 42c2e2bd76cf4d9672fe975b48e7321b | None | None |
>| 2015-06-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | 2607ae3f87b42ce7890b0ac4fcb00758 | None | None |
>| 2015-06-12 | butterfly.bigmoney.biz | 173.255.212.165 | None | 42b59990a2096e0aedf9be572c46ada3 | None | None |
>| 2015-06-12 | butterfly.bigmoney.biz | 173.255.212.165 | None | 206e3237ca05dc4d2c36eea21b7a7bd2 | None | None |
>| 2015-06-12 | butterfly.bigmoney.biz | 173.255.212.165 | None | 20082687daaf4c7ea0e768eb77634ec5 | None | None |
>| 2015-06-12 | butterfly.bigmoney.biz | 106.187.43.98 | None | d385e67bde52cd19e3ce0d30f8ae4605 | None | None |
>| 2015-06-12 | butterfly.bigmoney.biz | 173.255.212.165 | None | d675e916847b705d498f20b95e1a7a19 | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | 9f56f09f4f119e9bfbe45ac57d37821d | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | 977e7944f12e403f95c8bc9d3f515bcc | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | cafc119f5d6f2d95eb4d261d6a14003c | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 40843829a57dd8bc3546ada1ef59eb00 | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | cffe4f47189cefacce06ff2d4855f41e | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1fe5aae5e3bc7244fb136bbe5d9a38bf | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1f85505ee8654c8a9ab7446f09102404 | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 41dfb1271d9ff48a893cea4c6d63c160 | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1f9167efd8b14076c6e553f69dbcd0a2 | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 106.187.43.98 | None | d5c15705061af2b37f6eb8b39283901f | None | None |
>| 2015-06-11 | butterfly.bigmoney.biz | 173.255.212.165 | None | 425cf124dba598118e95013a5880de04 | None | None |
>| 2015-06-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | c53439cdba04d0357223923faed3c1cf | None | None |
>| 2015-06-10 | butterfly.bigmoney.biz | 106.187.43.98 | None | 9bc9005a0c523b70c3ad2f11eb5b8065 | None | None |
>| 2015-06-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3e3634d2f8352c40e2cca7c486433ea0 | None | None |
>| 2015-06-09 | butterfly.bigmoney.biz | 106.187.43.98 | None | 1e7a50caed70ee5cbc815ce2ee9d1173 | None | None |
>| 2015-06-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3d7238546d51c10159c07cef62a60e1d | None | None |
>| 2015-06-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1e92132798c9e47555e390bbb684cf02 | None | None |
>| 2015-06-09 | butterfly.bigmoney.biz | 76.74.255.138 | None | 1e78f240ed4a560f76a82bad90dd51d0 | None | None |
>| 2015-06-09 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3efbcb335bf09c739fbc528219efa46d | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 89aa9ec1a9a99b44e40c53a360cfb4f0 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1dfd49149f3cd29ca7f7327625ba17c7 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1e210ea39dfcb291c8db00dcda0a7845 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1dec9df5dc13fe0ad799b0f159ea7c29 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1dc530def1c1f642eafded30ce5f6836 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | b7ab036fd9547a565996af46b7b09801 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3b01a5ff23963c470b3fe7b2beba055a | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 76.74.255.138 | None | 3b4b992959eb061fff230159547f822d | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8f6597a8982002498502ed6983445449 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1e47facfbbdcc3e41f0299ca39b0591e | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1e40597ee11cc5e09b4b58c6fa015822 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1dc104d1ef1e49f5ac67c4b4f18a9445 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 8b65babba3fb7ad613ce2c379c698edf | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 106.187.43.98 | None | 85d4026393c1ff172d2c0fe666e2d0f4 | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1daf16064d6f1527f86cf9d1d3736f0c | None | None |
>| 2015-06-08 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1e1ab6810af24f9ca82e4c1d0644f85e | None | None |
>| 2015-06-07 | butterfly.bigmoney.biz | 76.74.255.138 | None | 1d922f8351517199bc3beb2dc2e4e56d | None | None |
>| 2015-06-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1d917913a05450d1b0b83135d0bda8fc | None | None |
>| 2015-06-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 7fd13ebd4ced5707d09f72408a75a152 | None | None |
>| 2015-06-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | b187564bc79fbe7bdad943a18f73828c | None | None |
>| 2015-06-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | 39d3c3640593f65d980625194cff61db | None | None |
>| 2015-06-07 | butterfly.bigmoney.biz | 106.187.43.98 | None | 827a1be453bcbb343d03e6f5e733a86b | None | None |
>| 2015-06-07 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1d1bd05389d7232bd3e5e651d3aabc68 | None | None |
>| 2015-06-07 | butterfly.bigmoney.biz | 76.74.255.138 | None | 1d724399f2b490e156e59404929de608 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 76.74.255.138 | None | 1a29ac724cc9f7b4c46605817d36c847 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3750f0c43c1f0a1fa09934cd31c8993b | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1beb9e57e1347214ef1a25b880788240 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 3783bba78e348aef87d2b36b9786290c | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | 415753553165e2ab89fdb1351d0d87fb | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 67.210.170.170 | None | 1cbbb1fac365ead4d5808048410b981c | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | 760e1db51c82ffaa070ff181f1ff95d7 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1ca3924286b5382295644b44a6b613e2 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 106.187.43.98 | None | 75f5f8d73546bbcf079ffa244513dbaf | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1acd7efec0fbbfc9093779a70fd020d1 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1b299a8eb269e9d4a9d5c297bb7d6b5d | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1b5b9c00dea1e88ee01c770dd97d346b | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1c889de81ad6bbaef9458bb566a30d22 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 76.74.255.138 | None | 1a503e3e8db966626ba2deba89ecdf54 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 76.74.255.138 | None | 1c39225d9bc8c23ed4032f49ae8675c3 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1b4d6cd10464702f1a47e04189476761 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 173.255.212.165 | None | 1c6d8616edd73dce96397a1e0617bf02 | None | None |
>| 2015-06-06 | butterfly.bigmoney.biz | 67.210.170.170 | None | 1c003210ec935729da61caaba45411b0 | None | None |
>| 2015-06-05 | butterfly.bigmoney.biz | 10.92.80.169 | None | 18d3611384cf442ba6ca0184b76283f4 | None | None |


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
| HYAS.HASH-IP.ip | String | Associated IP's for the provided MD5 value | 


#### Command Example
```!hyas-get-associated-ips-by-hash md5="1d0a97c41afe5540edd0a8c1fb9a0f1c"```

#### Context Example
```json
{
    "HYAS": {
        "HASH-IP": [
            {
                "ip": "106.187.43.98"
            }
        ]
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
| HYAS.HASH-DOMAIN.domain | String | Associated Domains for the provided MD5 value | 


#### Command Example
```!hyas-get-associated-domains-by-hash md5="1d0a97c41afe5540edd0a8c1fb9a0f1c"```

#### Context Example
```json
{
    "HYAS": {
        "HASH-DOMAIN": [
            {
                "domain": "butterfly.sinip.es"
            },
            {
                "domain": "qwertasdfg.sinip.es"
            },
            {
                "domain": "butterfly.bigmoney.biz"
            }
        ]
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

