Enrich indicators by obtaining enhanced information and reputation via ThreatFusion of SOCRadar.
This integration was integrated and tested with v21.11 of SOCRadar.

## Configure SOCRadarThreatFusion on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SOCRadarThreatFusion.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | The API Key to use for connection to SOCRadar ThreatFusion API. | True |
    | insecure | Trust any certificate (not secure). |  False |
    | proxy | Whether to use XSOAR’s system proxy settings to connect to the API. | False |

4. Click **Test** to validate API key and connection to SOCRadar ThreatFusion API.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### How to obtain SOCRadar ThreatFusion API key?

To obtain your SOCRadar ThreatFusion API key please contact with the SOCRadar operation team via **operation@socradar.io** 

After obtaining the SOCRadar ThreatFusion API key insert it into **API Key** field and start using the SOCRadar ThreatFusion integration by creating the instance.


### ip

***
Scores provided IP entities' reputation in SOCRadar ThreatFusion.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP entities to score. (IPv4 or IPv6). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarThreatFusion.Reputation.IP.Risk Score | Number | Reputation score of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Score Details | JSON | Risk score details of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Total Encounters | Number | Number of times that SOCRadar has encountered with the queried IP address in its threat sources. | 
| SOCRadarThreatFusion.Reputation.IP.IP | String | Queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn | String | ASN field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_cidr | String | ASN CIDR field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_country_code | String | ASN country code field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_date | Date | ASN date field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_description | String | ASN description field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_registry | String | ASN registry field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.address | String | Nets&gt;address field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.cidr | String | Nets&gt;CIDR field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.city | String | Nets&gt;city field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.country | String | Nets&gt;country field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.created | String | Nets&gt;created field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.description | String | Nets&gt;description field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.emails | String | Nets&gt;emails field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.handle | String | Nets&gt;handle field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.name | String | Nets&gt;name field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.postal_code | Number | Nets&gt;postal code field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.range | String | Nets&gt;range field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.state | String | Nets&gt;state field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.updated | Date | Nets&gt;updated field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nir | String | NIR field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.query | String | Query field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.raw_referral | String | Raw referral field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.referral | String | Referral field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.DNS Details | JSON | DNS information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.ASN | Number | ASN field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.AsnCode | Number | ASN code field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.AsnName | String | ASN name field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.Cidr | String | CIDR field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.CityName | String | City name field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.CountryCode | String | Country code field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.CountryName | String | Country name field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.Latitude | Number | Latitude field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.Longitude | Number | Longitude field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.RegionName | String | Region name field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.Timezone | String | Timezone field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.ZipCode | String | Zip code field Geographical location information of queried IP address. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | String | IP address | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 


#### Command Example

```!ip ip="1.1.1.1"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Score": 1,
        "Type": "ip",
        "Vendor": "SOCRadar ThreatFusion"
    },
    "IP": {
        "ASN": "[13335] CLOUDFLARENET, US",
        "Address": "1.1.1.1",
        "Geo": {
            "Country": "US",
            "Location": "0.0:0.0"
        },
        "Region": "California"
    },
    "SOCRadarThreatFusion": {
        "Reputation": {
            "IP": {
                "DNS Details": {
                    "PTR": [
                        "one.one.one.one"
                    ]
                },
                "Geo Location": {
                    "ASN": "[13335] CLOUDFLARENET, US",
                    "AsnCode": 13335,
                    "AsnName": "CloudFlare Inc",
                    "Cidr": "1.1.1.0/24",
                    "CityName": "Los Angeles",
                    "CountryCode": "US",
                    "CountryName": "United States of America",
                    "Latitude": 0.0,
                    "Longitude": 0.0,
                    "RegionName": "California",
                    "Timezone": "-07:00",
                    "ZipCode": "90001"
                },
                "IP": "1.1.1.1",
                "Risk Score (Out of 1000)": 0,
                "Score Details": {},
                "Total Encounters": 0,
                "Whois Details": {
                    "asn": "13335",
                    "asn_cidr": "1.1.1.0/24",
                    "asn_country_code": "AU",
                    "asn_date": "2011-08-11",
                    "asn_description": "CLOUDFLARENET, US",
                    "asn_registry": "apnic",
                    "nets": [
                        {
                            "address": "PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia",
                            "cidr": "1.1.1.0/24",
                            "city": null,
                            "country": "AU",
                            "created": null,
                            "description": "APNIC and Cloudflare DNS Resolver project\nRouted globally by AS13335/Cloudflare\nResearch prefix for APNIC Labs",
                            "emails": [
                                "resolver-abuse@cloudflare.com"
                            ],
                            "handle": "AA1412-AP",
                            "name": "APNIC-LABS",
                            "postal_code": null,
                            "range": "1.1.1.0 - 1.1.1.255",
                            "state": null,
                            "updated": null
                        },
                        {
                            "address": null,
                            "cidr": "1.1.1.0/24",
                            "city": null,
                            "country": null,
                            "created": null,
                            "description": "APNIC Research and Development\n                6 Cordelia St",
                            "emails": null,
                            "handle": null,
                            "name": null,
                            "postal_code": null,
                            "range": "1.1.1.0 - 1.1.1.255",
                            "state": null,
                            "updated": null
                        }
                    ],
                    "nir": null,
                    "query": "1.1.1.1",
                    "raw_referral": null,
                    "referral": null
                }
            }
        }
    }
}
```

#### Human Readable Output

>### SOCRadar - Analysis results for IP: 1.1.1.1

>|DNS Details|Geo Location|IP|Risk Score (Out of 1000)|Score Details|Total Encounters|Whois Details|
>|---|---|---|---|---|---|---|
>| PTR: one.one.one.one | Cidr: 1.1.1.0/24<br/>AsnCode: 13335<br/>AsnName: CloudFlare Inc<br/>ZipCode: 90001<br/>CityName: Los Angeles<br/>Latitude: 0.0<br/>Timezone: -07:00<br/>Longitude: 0.0<br/>RegionName: California<br/>CountryCode: US<br/>CountryName: United States of America<br/>ASN: [13335] CLOUDFLARENET, US | 1.1.1.1 | 0 |  | 0 | asn: 13335<br/>nir: null<br/>nets: {'cidr': '1.1.1.0/24', 'city': None, 'name': 'APNIC-LABS', 'range': '1.1.1.0 - 1.1.1.255', 'state': None, 'emails': ['resolver-abuse@cloudflare.com'], 'handle': 'AA1412-AP', 'address': 'PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia', 'country': 'AU', 'created': None, 'updated': None, 'description': 'APNIC and Cloudflare DNS Resolver project\nRouted globally by AS13335/Cloudflare\nResearch prefix for APNIC Labs', 'postal_code': None},<br/>{'cidr': '1.1.1.0/24', 'city': None, 'name': None, 'range': '1.1.1.0 - 1.1.1.255', 'state': None, 'emails': None, 'handle': None, 'address': None, 'country': None, 'created': None, 'updated': None, 'description': 'APNIC Research and Development\n                6 Cordelia St', 'postal_code': None}<br/>query: 1.1.1.1<br/>asn_cidr: 1.1.1.0/24<br/>asn_date: 2011-08-11<br/>referral: null<br/>asn_registry: apnic<br/>raw_referral: null<br/>asn_description: CLOUDFLARENET, US<br/>asn_country_code: AU |


### domain

***
Scores provided domain entities' reputation in SOCRadar ThreatFusion.


#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain entities to score. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarThreatFusion.Reputation.Domain.Risk Score | Number | Reputation score of queried domain. | 
| SOCRadarThreatFusion.Reputation.IP.Score Details | JSON | Risk score details of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Total Encounters | Number | Number of times that SOCRadar has encountered with the queried domain in its threat sources. | 
| SOCRadarThreatFusion.Reputation.Domain.Domain | String | Queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.org | String | Org field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.city | String | City field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.name | String | Name field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.state | String | State field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.dnssec | String | Dnssec field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.emails | String | Emails field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.status | String | Status field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.address | String | Address field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.country | String | Country field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.zipcode | Number | Zip code field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.registrar | String | Registrar field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.domain_name | String | Domain name field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.name_servers | String | Name servers field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.referral_url | String | Referral URL field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.updated_date | Date | Updated date field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.whois_server | String | Whois server field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.creation_date | Date | Creation date field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.expiration_date | Date | Expiration date field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.DNS Details | String | DNS information of queried domain. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The domain name, for example: "google.com". | 
| Domain.DNS | String | A list of IP objects resolved by DNS. | 
| Domain.CreationDate | Date | The date that the domain was created. | 
| Domain.UpdatedDate | String | The date that the domain was last updated. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.NameServers | Unknown | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.NameServers | String | \(List&lt;String&gt;\) Name servers of the domain. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy" | 
| Domain.Geo.Country | String | The country in which the domain address is located. | 
| Domain.Subdomains | Unknown | \(List&lt;String&gt;\) Subdomains of the domain. | 
| Domain.Registrant.Country | String | The country of the registrant. | 


#### Command Example

```!domain domain="paloaltonetworks.com"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "paloaltonetworks.com",
        "Score": 1,
        "Type": "domain",
        "Vendor": "SOCRadar ThreatFusion"
    },
    "Domain": {
        "CreationDate": "Mon, 21 Feb 2005 02:42:10 GMT",
        "DNS": "1.1.1.1",
        "ExpirationDate": "Wed, 21 Feb 2024 02:42:10 GMT",
        "Geo": {
            "Country": "US"
        },
        "Name": "paloaltonetworks.com",
        "NameServers": [
            "ns record"
        ],
        "Organization": "Palo Alto Networks, Inc.",
        "Registrar": {
            "AbuseEmail": null,
            "AbusePhone": null,
            "Name": "MarkMonitor Inc."
        },
        "UpdatedDate": "Thu, 01 Jul 2021 00:32:38 GMT",
        "WHOIS": {
            "CreationDate": "Mon, 21 Feb 2005 02:42:10 GMT",
            "ExpirationDate": "Wed, 21 Feb 2024 02:42:10 GMT",
            "NameServers": [
                "ns record"
            ],
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "MarkMonitor Inc."
            },
            "UpdatedDate": "Thu, 01 Jul 2021 00:32:38 GMT"
        }
    },
    "SOCRadarThreatFusion": {
        "Reputation": {
            "Domain": {
                "DNS Details": {
                    "A": [
                        "1.1.1.1"
                    ],
                    "MX": [
                        "mx record"
                    ],
                    "NS": [
                        "ns record"
                    ],
                    "SOA": [
                        "domains.paloaltonetworks.com. 1627343953 3600 600 604800 3600"
                    ],
                    "TXT": [
                        "txt record"
                    ]
                },
                "Domain": "paloaltonetworks.com",
                "Risk Score (Out of 1000)": 0,
                "Score Details": {},
                "Subdomains": [],
                "Total Encounters": 0,
                "Whois Details": {
                    "address": null,
                    "city": null,
                    "country": "US",
                    "creation_date": "Mon, 21 Feb 2005 02:42:10 GMT",
                    "dnssec": "signedDelegation",
                    "domain_name": "PALOALTONETWORKS.COM",
                    "emails": [
                        "abusecomplaints@markmonitor.com",
                        "whoisrequest@markmonitor.com"
                    ],
                    "expiration_date": "Wed, 21 Feb 2024 02:42:10 GMT",
                    "name": null,
                    "name_servers": [
                        "ns record"
                    ],
                    "org": "Palo Alto Networks, Inc.",
                    "referral_url": null,
                    "registrar": "MarkMonitor Inc.",
                    "state": "CA",
                    "status": [
                        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
                        "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                        "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                        "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
                        "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
                        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited"
                    ],
                    "updated_date": "Thu, 01 Jul 2021 00:32:38 GMT",
                    "whois_server": "whois.markmonitor.com",
                    "zipcode": null
                }
            }
        }
    }
}
```

#### Human Readable Output

>### SOCRadar - Analysis results for domain: paloaltonetworks.com

>|DNS Details|Domain|Risk Score (Out of 1000)|Score Details|Subdomains|Total Encounters|Whois Details|
>|---|---|---|---|---|---|---|
>| A: 1.1.1.1<br/>MX: mx record<br/>NS: ns record<br/>SOA: domains.paloaltonetworks.com. 1627343953 3600 600 604800 3600<br/>TXT: txt record | paloaltonetworks.com | 0 |  |  | 0 | org: Palo Alto Networks, Inc.<br/>city: null<br/>name: null<br/>state: CA<br/>dnssec: signedDelegation<br/>emails: abusecomplaints@markmonitor.com,<br/>whoisrequest@markmonitor.com<br/>status: clientUpdateProhibited https:<span>//</span>icann.org/epp#clientUpdateProhibited,<br/>clientTransferProhibited https:<span>//</span>icann.org/epp#clientTransferProhibited,<br/>clientDeleteProhibited https:<span>//</span>icann.org/epp#clientDeleteProhibited,<br/>clientTransferProhibited (https:<span>//</span>www.icann.org/epp#clientTransferProhibited),<br/>clientUpdateProhibited (https:<span>//</span>www.icann.org/epp#clientUpdateProhibited),<br/>clientDeleteProhibited (https:<span>//</span>www.icann.org/epp#clientDeleteProhibited)<br/>address: null<br/>country: US<br/>zipcode: null<br/>registrar: MarkMonitor Inc.<br/>domain_name: PALOALTONETWORKS.COM<br/>name_servers: ns record<br/>referral_url: null<br/>updated_date: Thu, 01 Jul 2021 00:32:38 GMT<br/>whois_server: whois.markmonitor.com<br/>creation_date: Mon, 21 Feb 2005 02:42:10 GMT<br/>expiration_date: Wed, 21 Feb 2024 02:42:10 GMT |


### file

***
Scores provided hash entities' reputation in SOCRadar ThreatFusion.


#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash entities to score. (MD5 or SHA1). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarThreatFusion.Reputation.Hash.Risk Score | Number | Reputation score of queried hash. | 
| SOCRadarThreatFusion.Reputation.Hash.Score Details | JSON | Risk score details of queried hash. | 
| SOCRadarThreatFusion.Reputation.Hash.Total Encounters | Number | Number of times that SOCRadar has encountered with the queried hash in its threat sources. | 
| SOCRadarThreatFusion.Reputation.Hash.File | String | Queried hash. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 


#### Command Example

```!file file="3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792"```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792",
        "Score": 1,
        "Type": "file",
        "Vendor": "SOCRadar ThreatFusion"
    },
    "File": {
        "MD5": "3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792"
    },
    "SOCRadarThreatFusion": {
        "Reputation": {
            "Hash": {
                "File": "3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792",
                "Risk Score (Out of 1000)": 360,
                "Score Details": {
                    "Maldatabase": 360
                },
                "Total Encounters": 1
            }
        }
    }
}
```

#### Human Readable Output

>### SOCRadar - Analysis results for hash: 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792

>|File|Risk Score (Out of 1000)|Score Details|Total Encounters|
>|---|---|---|---|
>| 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792 | 360.0 | Maldatabase: 360.0 | 1 |


### socradar-score-ip

***
Scores provided IP entity's reputation in SOCRadar ThreatFusion.


#### Base Command

`socradar-score-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP entity to score. (IPv4 or IPv6). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarThreatFusion.Reputation.IP.Risk Score | Number | Reputation score of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Score Details | JSON | Risk score details of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Total Encounters | Number | Number of times that SOCRadar has encountered with the queried IP address in its threat sources. | 
| SOCRadarThreatFusion.Reputation.IP.IP | String | Queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn | String | ASN field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_cidr | String | ASN CIDR field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_country_code | String | ASN country code field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_date | Date | ASN date field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_description | String | ASN description field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.asn_registry | String | ASN registry field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.address | String | Nets&gt;address field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.cidr | String | Nets&gt;CIDR field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.city | String | Nets&gt;city field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.country | String | Nets&gt;country field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.created | String | Nets&gt;created field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.description | String | Nets&gt;description field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.emails | String | Nets&gt;emails field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.handle | String | Nets&gt;handle field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.name | String | Nets&gt;name field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.postal_code | Number | Nets&gt;postal code field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.range | String | Nets&gt;range field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.state | String | Nets&gt;state field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nets.updated | Date | Nets&gt;updated field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.nir | String | NIR field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.query | String | Query field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.raw_referral | String | Raw referral field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Whois Details.referral | String | Referral field Whois information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.DNS Details | JSON | DNS information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.ASN | Number | ASN field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.AsnCode | Number | ASN code field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.AsnName | String | ASN name field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.Cidr | String | CIDR field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.CityName | String | City name field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.CountryCode | String | Country code field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.CountryName | String | Country name field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.Latitude | Number | Latitude field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.Longitude | Number | Longitude field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.RegionName | String | Region name field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.Timezone | String | Timezone field Geographical location information of queried IP address. | 
| SOCRadarThreatFusion.Reputation.IP.Geo Location.ZipCode | String | Zip code field Geographical location information of queried IP address. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the indicator score. | 


#### Command Example

```!socradar-score-ip ip="1.1.1.1"```

#### Context Example

```json
{
    "SOCRadarThreatFusion": {
        "Reputation": {
            "IP": {
                "DBotScore": {
                    "Indicator": "1.1.1.1",
                    "Score": 1,
                    "Type": "ip",
                    "Vendor": "SOCRadar ThreatFusion"
                },
                "DNS Details": {
                    "PTR": [
                        "one.one.one.one"
                    ]
                },
                "Geo Location": {
                    "ASN": "[13335] CLOUDFLARENET, US",
                    "AsnCode": 13335,
                    "AsnName": "CloudFlare Inc",
                    "Cidr": "1.1.1.0/24",
                    "CityName": "Los Angeles",
                    "CountryCode": "US",
                    "CountryName": "United States of America",
                    "Latitude": 0.0,
                    "Longitude": 0.0,
                    "RegionName": "California",
                    "Timezone": "-07:00",
                    "ZipCode": "90001"
                },
                "IP": "1.1.1.1",
                "Risk Score (Out of 1000)": 0,
                "Score Details": {},
                "Total Encounters": 0,
                "Whois Details": {
                    "asn": "13335",
                    "asn_cidr": "1.1.1.0/24",
                    "asn_country_code": "AU",
                    "asn_date": "2011-08-11",
                    "asn_description": "CLOUDFLARENET, US",
                    "asn_registry": "apnic",
                    "nets": [
                        {
                            "address": "PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia",
                            "cidr": "1.1.1.0/24",
                            "city": null,
                            "country": "AU",
                            "created": null,
                            "description": "APNIC and Cloudflare DNS Resolver project\nRouted globally by AS13335/Cloudflare\nResearch prefix for APNIC Labs",
                            "emails": [
                                "resolver-abuse@cloudflare.com"
                            ],
                            "handle": "AA1412-AP",
                            "name": "APNIC-LABS",
                            "postal_code": null,
                            "range": "1.1.1.0 - 1.1.1.255",
                            "state": null,
                            "updated": null
                        },
                        {
                            "address": null,
                            "cidr": "1.1.1.0/24",
                            "city": null,
                            "country": null,
                            "created": null,
                            "description": "APNIC Research and Development\n                6 Cordelia St",
                            "emails": null,
                            "handle": null,
                            "name": null,
                            "postal_code": null,
                            "range": "1.1.1.0 - 1.1.1.255",
                            "state": null,
                            "updated": null
                        }
                    ],
                    "nir": null,
                    "query": "1.1.1.1",
                    "raw_referral": null,
                    "referral": null
                }
            }
        }
    }
}
```

#### Human Readable Output

>### SOCRadar - Analysis results for IP: 1.1.1.1

>|DNS Details|Geo Location|IP|Risk Score (Out of 1000)|Score Details|Total Encounters|Whois Details|
>|---|---|---|---|---|---|---|
>| PTR: one.one.one.one | AsnCode: 13335<br/>AsnName: CloudFlare Inc<br/>Cidr: 1.1.1.0/24<br/>CityName: Los Angeles<br/>CountryCode: US<br/>CountryName: United States of America<br/>ASN: [13335] CLOUDFLARENET, US<br />Latitude: 0.0<br/>Longitude: 0.0<br/>RegionName: California<br/>Timezone: -07:00<br/>ZipCode: 90001 | 1.1.1.1 | 0 |  | 0 | asn: 13335<br/>asn_cidr: 1.1.1.0/24<br/>asn_country_code: AU<br/>asn_date: 2011-08-11<br/>asn_description: CLOUDFLARENET, US<br/>asn_registry: apnic<br/>nets: {'address': 'PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia', 'cidr': '1.1.1.0/24', 'city': None, 'country': 'AU', 'created': None, 'description': 'APNIC and Cloudflare DNS Resolver project\nRouted globally by AS13335/Cloudflare\nResearch prefix for APNIC Labs', 'emails': ['resolver-abuse@cloudflare.com'], 'handle': 'AA1412-AP', 'name': 'APNIC-LABS', 'postal_code': None, 'range': '1.1.1.0 - 1.1.1.255', 'state': None, 'updated': None},<br/>{'address': None, 'cidr': '1.1.1.0/24', 'city': None, 'country': None, 'created': None, 'description': 'APNIC Research and Development\n                6 Cordelia St', 'emails': None, 'handle': None, 'name': None, 'postal_code': None, 'range': '1.1.1.0 - 1.1.1.255', 'state': None, 'updated': None}<br/>nir: null<br/>query: 1.1.1.1<br/>raw_referral: null<br/>referral: null |


### socradar-score-domain

***
Scores provided domain entity's reputation in SOCRadar ThreatFusion.


#### Base Command

`socradar-score-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain entity to score. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarThreatFusion.Reputation.Domain.Risk Score | Number | Reputation score of queried domain. | 
| SOCRadarThreatFusion.Reputation.IP.Score Details | JSON | Risk score details of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Total Encounters | Number | Number of times that SOCRadar has encountered with the queried domain in its threat sources. | 
| SOCRadarThreatFusion.Reputation.Domain.Domain | String | Queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.org | String | Org field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.city | String | City field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.name | String | Name field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.state | String | State field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.dnssec | String | Dnssec field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.emails | String | Emails field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.status | String | Status field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.address | String | Address field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.country | String | Country field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.zipcode | Number | Zip code field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.registrar | String | Registrar field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.domain_name | String | Domain name field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.name_servers | String | Name servers field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.referral_url | String | Referral URL field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.updated_date | Date | Updated date field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.whois_server | String | Whois server field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.creation_date | Date | Creation date field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.Whois Details.expiration_date | Date | Expiration date field Whois information of queried domain. | 
| SOCRadarThreatFusion.Reputation.Domain.DNS Details | String | DNS information of queried domain. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the indicator score. | 


#### Command Example

```!socradar-score-domain domain="paloaltonetworks.com"```

#### Context Example

```json
{
    "SOCRadarThreatFusion": {
        "Reputation": {
            "Domain": {
                "DBotScore": {
                    "Indicator": "paloaltonetworks.com",
                    "Score": 1,
                    "Type": "domain",
                    "Vendor": "SOCRadar ThreatFusion"
                },
                "DNS Details": {
                    "A": [
                        "1.1.1.1"
                    ],
                    "MX": [
                        "mx record"
                    ],
                    "NS": [
                        "ns record"
                    ],
                    "SOA": [
                        "domains.paloaltonetworks.com. 1627343953 3600 600 604800 3600"
                    ],
                    "TXT": [
                        "txt record"
                    ]
                },
                "Domain": "paloaltonetworks.com",
                "Risk Score (Out of 1000)": 0,
                "Score Details": {},
                "Subdomains": [],
                "Total Encounters": 0,
                "Whois Details": {
                    "address": null,
                    "city": null,
                    "country": "US",
                    "creation_date": "Mon, 21 Feb 2005 02:42:10 GMT",
                    "dnssec": "signedDelegation",
                    "domain_name": "PALOALTONETWORKS.COM",
                    "emails": [
                        "abusecomplaints@markmonitor.com",
                        "whoisrequest@markmonitor.com"
                    ],
                    "expiration_date": "Wed, 21 Feb 2024 02:42:10 GMT",
                    "name": null,
                    "name_servers": [
                        "ns record"
                    ],
                    "org": "Palo Alto Networks, Inc.",
                    "referral_url": null,
                    "registrar": "MarkMonitor Inc.",
                    "state": "CA",
                    "status": [
                        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
                        "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
                        "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
                        "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
                        "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
                        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited"
                    ],
                    "updated_date": "Thu, 01 Jul 2021 00:32:38 GMT",
                    "whois_server": "whois.markmonitor.com",
                    "zipcode": null
                }
            }
        }
    }
}
```

#### Human Readable Output

>### SOCRadar - Analysis results for domain: paloaltonetworks.com

>|DNS Details|Domain|Risk Score (Out of 1000)|Score Details|Subdomains|Total Encounters|Whois Details|
>|---|---|---|---|---|---|---|
>| A: 1.1.1.1<br/>MX: mx record<br/>NS: ns record<br/>SOA: domains.paloaltonetworks.com. 1627343953 3600 600 604800 3600<br/>TXT: txt record | paloaltonetworks.com | 0 |  |  | 0 | org: Palo Alto Networks, Inc.<br/>city: null<br/>name: null<br/>state: CA<br/>dnssec: signedDelegation<br/>emails: abusecomplaints@markmonitor.com,<br/>whoisrequest@markmonitor.com<br/>status: clientUpdateProhibited https:<span>//</span>icann.org/epp#clientUpdateProhibited,<br/>clientTransferProhibited https:<span>//</span>icann.org/epp#clientTransferProhibited,<br/>clientDeleteProhibited https:<span>//</span>icann.org/epp#clientDeleteProhibited,<br/>clientTransferProhibited (https:<span>//</span>www.icann.org/epp#clientTransferProhibited),<br/>clientUpdateProhibited (https:<span>//</span>www.icann.org/epp#clientUpdateProhibited),<br/>clientDeleteProhibited (https:<span>//</span>www.icann.org/epp#clientDeleteProhibited)<br/>address: null<br/>country: US<br/>zipcode: null<br/>registrar: MarkMonitor Inc.<br/>domain_name: PALOALTONETWORKS.COM<br/>name_servers: ns record<br/>referral_url: null<br/>updated_date: Thu, 01 Jul 2021 00:32:38 GMT<br/>whois_server: whois.markmonitor.com<br/>creation_date: Mon, 21 Feb 2005 02:42:10 GMT<br/>expiration_date: Wed, 21 Feb 2024 02:42:10 GMT |


### socradar-score-hash

***
Scores provided hash entity's reputation in SOCRadar ThreatFusion.


#### Base Command

`socradar-score-hash`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hash | Hash entity to score. (MD5 or SHA1). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SOCRadarThreatFusion.Reputation.Hash.Risk Score | Number | Reputation score of queried hash. | 
| SOCRadarThreatFusion.Reputation.Hash.Score Details | JSON | Risk score details of queried hash. | 
| SOCRadarThreatFusion.Reputation.Hash.Total Encounters | Number | Number of times that SOCRadar has encountered with the queried hash in its threat sources. | 
| SOCRadarThreatFusion.Reputation.Hash.File | String | Queried hash. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the indicator score. | 


#### Command Example

```!socradar-score-hash hash="3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792"```

#### Context Example

```json
{
    "SOCRadarThreatFusion": {
        "Reputation": {
            "Hash": {
                "DBotScore": {
                    "Indicator": "3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792",
                    "Score": 1,
                    "Type": "file",
                    "Vendor": "SOCRadar ThreatFusion"
                },
                "File": "3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792",
                "Risk Score (Out of 1000)": 360,
                "Score Details": {
                    "Maldatabase": 360
                },
                "Total Encounters": 1
            }
        }
    }
}
```

#### Human Readable Output

>### SOCRadar - Analysis results for hash: 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792

>|File|Risk Score (Out of 1000)|Score Details|Total Encounters|
>|---|---|---|---|
>| 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792 | 360.0 | Maldatabase: 360.0 | 1 |

