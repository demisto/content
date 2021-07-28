Enrich indicators by obtaining enhanced information and reputation via SOCRadar.
This integration was integrated and tested with version 1.0 of SOCRadarThreatFusion.

## Configure SOCRadarThreatFusion on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SOCRadarThreatFusion.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | The API Key to use for connection to SOCRadar Threat Analysis API. | True |
    | insecure | Trust any certificate (not secure). |  False |
    | proxy | Whether to use XSOAR’s system proxy settings to connect to the API. | False |

4. Click **Test** to validate API key and connection to SOCRadar Threat Analysis API.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### How to obtain SOCRadar Threat API key?


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
| SOCRadarThreatFusion.Reputation.IP.Total Encounters | Number | Number of times that SOCRadar has encountered the queried IP address in its threat sources. | 
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

#### Command Example
```!socradar-score-ip ip="1.1.1.1" ```

#### Context Example
```
{
    "is_success": true,
    "message": "Requested entity: 1.1.1.1 has been successfully processed.",
    "response_code": 200,
    "data": {
        "score": 0,
        "value": "1.1.1.1",
        "whois": {
             "asn": "398101",
            "nir": null,
            "raw": "TOO LONG TO DISPLAY",
            "nets": [{
                "cidr": "Mock CIDR",
                "city": "Scottsdale",
                "name": "GO-DADDY-COM-LLC",
                "range": "Range-Range",
                "state": "AZ",
                "emails": [
                    "Email 1",
                    "Email 2"
                ],
                "handle": "NET-132-148-0-0-1",
                "address": "Address",
                "country": "US",
                "created": "2015-10-21",
                "updated": "2015-10-26",
                "description": "Description",
                "postal_code": "85260"
            }],
        "query": "1.1.1.1",
        "asn_cidr": "Mock CIDR",
        "asn_date": "2015-10-21",
        "referral": null,
        "asn_registry": "arin",
        "raw_referral": null,
        "asn_description": "GO-DADDY-COM-LLC, US",
        "asn_country_code": "US"
    },
    "dns_info": {
        "PTR": [
            "Mock PTR Record"
        ]
    },
    "findings": [],
    "geo_location": [{
        "Ip": "1.1.1.1",
        "Cidr": "CIDR",
        "AsnCode": 398101,
        "AsnName": "ASN name",
        "ZipCode": "85260",
        "CityName": "Scottsdale",
        "Latitude": 0.0,
        "Timezone": "-07:00",
        "Longitude": -0.0,
        "RegionName": "Arizona",
        "CountryCode": "US",
        "CountryName": "United States of America"
    }],
    "score_details": {},
    "classification": "ipv4",
    "is_whitelisted": false,
    "remaining_credit": 3650000,
    "whitelist_sources": [],
    "is_advance_investigation": false
    }
}

```

#### Human Readable Output

##### SOCRadar - Analysis results for IP: 1.1.1.1

|  |  |
| ------ | ------
| DNS Details | PTR: Mock PTR Record  |
| Geo Location | AsnCode: 398101 <br/> AsnName: ASN name <br/> Cidr: CIDR <br/> CityName: Scottsdale <br/> CountryCode: US <br/> CountryName: United States of America <br/> Latitude: 0.0 <br/> Longitude: -0.0 <br/> RegionName: Arizona <br/> Timezone: -07:00 <br/> ZipCode: 85260  |
| IP | 1.1.1.1   |
| Risk Score (Out of 1000) | 0   |
| Score Details |  |
| Total Encounters | 0 |
| Whois Details |  asn: 398101 <br/> asn_cidr: Mock CIDR <br/> asn_country_code: US <br/> asn_date: 2015-10-21 <br/> asn_description: GO-DADDY-COM-LLC, US <br/> asn_registry: arin <br/> nets: {'address': 'Address', 'cidr': 'Mock CIDR', 'city': 'Scottsdale', 'country': 'US', 'created': '2015-10-21', 'description': 'Description', 'emails': ['Email 1', 'Email 2'], 'handle': 'NET-132-148-0-0-1', 'name': 'GO-DADDY-COM-LLC', 'postal_code': '85260', 'range': 'Range-Range', 'state': 'AZ', 'updated': '2015-10-26'} <br/> nir: null <br/> query: 1.1.1.1 <br/> raw_referral: null <br/> referral: null  |


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
| SOCRadarThreatFusion.Reputation.Domain.Total Encounters | Number | Number of times that SOCRadar has encountered the queried domain in its threat sources. | 
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

#### Command Example
```!socradar-score-domain domain="paloaltonetworks.com" ```

#### Context Example
```
{
    "is_success": true,
    "message": "Requested entity: paloaltonetworks.com has been successfully processed.",
    "response_code": 200,
    "data": {
        "score": 0,
        "value": "paloaltonetworks.com",
        "whois": {
        "org": "Palo Alto Networks, Inc.",
        "city": null,
        "name": null,
        "state": "CA",
        "dnssec": "signedDelegation",
        "emails": [
            "whoisrequest@markmonitor.com",
            "abusecomplaints@markmonitor.com"
        ],
        "status": [
            "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
            "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
            "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
            "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
            "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"
        ],
        "address": null,
        "country": "US",
        "zipcode": null,
        "registrar": [
            "MarkMonitor, Inc.",
            "MarkMonitor Inc."
        ],
        "domain_name": "PALOALTONETWORKS.COM",
        "name_servers": [
            "ns4.p23.dynect.net",
            "ns1.p23.dynect.net",
            "ns3.p23.dynect.net",
            "ns5.dnsmadeeasy.com",
            "ns2.p23.dynect.net",
            "ns6.dnsmadeeasy.com",
            "ns7.dnsmadeeasy.com"
        ],
        "referral_url": null,
        "updated_date": [
            "Thu, 01 Jul 2021 00:32:38 GMT",
            "Thu, 01 Jul 2021 00:32:38 GMT"
        ],
        "whois_server": "whois.markmonitor.com",
        "creation_date": [
            "Mon, 21 Feb 2005 02:42:10 GMT",
            "Mon, 21 Feb 2005 02:42:10 GMT"
        ],
        "expiration_date": [
            "Wed, 21 Feb 2024 02:42:10 GMT",
            "Wed, 21 Feb 2024 02:42:10 GMT"
        ]
    },
    "dns_info": {
        "A": [
            "A Record"
        ],
        "MX": [
            "MX Record 1",
            "MX Record 2"
        ],
        "NS": [
            "NS Record"
        ],
        "SOA": [
            "SOA Record"
        ],
        "TXT": [
            TOO LONG TO DISPLAY
        ]
    },
    "findings": [],
    "subdomains": [],
    "score_details": {},
    "classification": "hostname",
    "is_whitelisted": true,
    "remaining_credit": 3650000,
    "whitelist_sources": [
        "Cisco Top 1m Domain",
        "Top 500k Domain",
        "Majestic Top 1m Domain",
        "Alexa Top 1m Domain"
    ],
    "is_advance_investigation": false
    }
}

```

#### Human Readable Output

##### SOCRadar - Analysis results for domain: paloaltonetworks.com

|  |  |
| ------ | ------
| DNS Details | A: A record <br/> MX: MX Record 1, <br/> MX Record 2 <br/> NS: NS Record <br/> TXT: TOO LONG TO DISPLAY
| Domain | paloaltonetworks.com  |
| Risk Score (Out of 1000) | 0 |
| Score Details |  |
| Total Encounters | 0 |
| Whois Details |  address: null <br/> city: null <br/> country: US ...abusecomplaints@markmonitor.com, <br/> whoisrequest@markmonitor.com <br/> expiration_date: Wed, 21 Feb 2024 02:42:10 GMT, <br/> Wed, 21 Feb 2024 02:42:10 GMT <br/> name: null <br/> name_servers: Name Server <br/> org: Palo Alto Networks, Inc. <br/> referral_url: null <br/> registrar: MarkMonitor, Inc., <br/> MarkMonitor Inc. <br/> state: CA <br/> status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited), <br/> clientTransferProhibited https://icann.org/epp#clientTransferProhibited, <br/> clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited), <br/> clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited, <br/> clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited, <br/> clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited) <br/> updated_date: Thu, 01 Jul 2021 00:32:38 GMT, <br/> Thu, 01 Jul 2021 00:32:38 GMT <br/> whois_server: whois.markmonitor.com <br/> zipcode: null  |
| Subdomains |  |



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
| SOCRadarThreatFusion.Reputation.Hash.Total Encounters | Number | Number of times that SOCRadar has encountered the queried hash in its threat sources. | 
| SOCRadarThreatFusion.Reputation.Hash.File | String | Queried hash. | 

#### Command Example
```!socradar-score-hash hash="3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792" ```

#### Context Example
```
{
    "is_success": true,
    "message": "Requested entity: 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792 has been     successfully processed.",
    "response_code": 200,
    "data": {
        "score": 360,
        "value": "3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792",
        "findings": [],
        "score_details": {
            "Maldatabase": 360
        },
        "classification": "hash",
        "is_whitelisted": false,
        "remaining_credit": 3650000,
        "whitelist_sources": [],
        "is_advance_investigation": false
    }
}

```

#### Human Readable Output

##### SOCRadar - Analysis results for hash: 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792

|  |  |
| ------ | ------
| File | 3b7b359ea17ac76341957573e332a2d6bcac363401ac71c8df94dac93df6d792  |
| Risk Score (Out of 1000) | 360.0 |
| Score Details | Maldatabase: 360.0 |
| Total Encounters | 1 |

