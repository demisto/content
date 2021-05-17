## Overview
---

The Expanse App for Demisto leverages the Expander API to retrieve network exposures and create incidents in Demisto.  This application also allows for IP, Domain, Certificate, and Behavior enrichment, retrieving assets and exposures information drawn from Expanse’s unparalleled view of the Internet.
This integration was integrated and tested with Expanse Events API v1, Assets API v2, and Behavior API v1.

## Configure Expanse on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Expanse.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __API Key__
    * __Fetch incidents__
    * __Include Behavior data in incidents__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __How many events to pull from Expander per run__
    * __How many days to pull past events on first run__
    * __Minimum severity of Expanse Exposure to create an incident for__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---
```
{
    'eventType': 'ON_PREM_EXPOSURE_APPEARANCE',
    'eventTime': '2020-02-05T00:00:00Z',
    'businessUnit': {
        'id': 'a1f0f39b-f358-3c8c-947b-926887871b88',
        'name': 'VanDelay Import-Export'
    },
    'payload': {
        '_type': 'ExposurePayload',
        'id': 'b0acfbc5-4d55-3fdb-9155-4927eab91218',
        'exposureType': 'NTP_SERVER',
        'ip': '203.215.173.113',
        'port': 123,
        'portProtocol': 'UDP',
        'exposureId': '6bedf636-5b6a-3b47-82a5-92b511c0649b',
        'domainName': None,
        'scanned': '2020-02-05T00:00:00Z',
        'geolocation': {
            'latitude': 33.7,
            'longitude': 73.17,
            'city': 'ISLAMABAD',
            'regionCode': '',
            'countryCode':
                'PK'
        },
        'configuration': {
            '_type': 'NtpServerConfiguration',
            'response': {
                'ntp': {
                    'leapIndicator': 0,
                    'mode': 4,
                    'poll': 4,
                    'precision': -19,
                    'stratum': 5,
                    'delay': 0,
                    'dispersion': 22,
                    'version': 4,
                    'originateTime': '2004-11-24T15:12:11.444Z',
                    'receiveTime': '2020-02-05T14:25:08.963Z',
                    'updateTime': '2020-02-05T14:25:01.597Z',
                    'transmitTime': '2020-02-05T14:25:08.963Z',
                    'reference': {
                        'ref_ip': {
                            'reference': {
                                'ipv4': '127.127.1.1'
                            }
                        }
                    },
                    'extentionData': None,
                    'keyIdentifier': None,
                    'messageDigest': None
                }
            }
        },
        'severity': 'ROUTINE',
        'tags': {
            'ipRange': ['untagged']
        },
        'providers': ['InternallyHosted'],
        'certificatePem': None,
        'remediationStatuses': []
    },
    'id': 'b4a1e2e6-165a-31a5-9e6a-af286adc3dcd'
}
```
## Fetched Behavior Incident Data
---
```
{
    "id": "c9704240-5021-321e-a82b-32865e07d541",
    "tenantBusinessUnitId": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5",
    "businessUnit": {
        "id": "6b73ef6c-b230-3797-b321-c4a340169eb7",
        "name": "Acme Latex Supply"
    },
    "riskRule": {
        "id": "02b6c647-65f4-4b69-b4b0-64af34fd1b29",
        "name": "Connections to and from Blacklisted Countries",
        "description": "Connections to and from Blacklisted Countries (Belarus, Côte d'Ivoire, Cuba, Democratic Republic of the Congo, Iran, Iraq, Liberia, North Korea, South Sudan, Sudan, Syria, Zimbabwe)",
        "additionalDataFields": "[]"
    },
    "internalAddress": "184.174.38.51",
    "internalPort": 35125,
    "externalAddress": "217.218.108.188",
    "externalPort": 443,
    "flowDirection": "OUTBOUND",
    "acked": true,
    "protocol": "TCP",
    "externalCountryCodes": [
        "IR"
    ],
    "internalCountryCodes": [
        "US"
    ],
    "externalCountryCode": "IR",
    "internalCountryCode": "US",
    "internalExposureTypes": [],
    "internalDomains": [],
    "internalTags": {
        "ipRange": []
    },
    "observationTimestamp": "2020-03-23T14:59:04.211Z",
    "created": "2020-03-24T02:45:28.450131Z"
}
```

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. ip
2. domain
3. expanse-get-certificate
4. expanse-get-behavior
5. expanse-get-exposures
6. expanse-get-domains-for-certificate

### 1. ip
---
ip command
##### Required Permissions
**none**
##### Base Command

`ip`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | ip address | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | Internet Protocol Address | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location | 
| Expanse.IP.Address | String | Internet Protocol Address | 
| Expanse.IP.Version | String | Internet Protocol Address Version | 
| Expanse.IP.BusinessUnits | String | Expanse Business Units this IP belongs to | 
| Expanse.IP.IPRange.StartAdress | String | First IP address in IP Network this IP address belongs to | 
| Expanse.IP.IPRange.EndAddress | String | Last IP address in IP Network this IP address belongs to | 
| Expanse.IP.IPRange.RangeSize | Number | Number of IP addresses in IP Network this IP address belongs to | 
| Expanse.IP.IPRange.ResponsiveIPCount | Number | Number of responsive IP addresses in IP Network this IP address belongs to | 
| Expanse.IP.IPRange.RangeIntroduced | Date | Date the IP network this IP address belongs to was introduced to Expanse | 
| Expanse.IP.IPRange.AttributionReasons | String | The reason why this IP belongs to the IP Range | 
| Expanse.IP.Geo.Latitude | String | Geo coordinates: Latitude of IP address | 
| Expanse.IP.Geo.Longitude | String | Geo coordinates: Longitude of IP address | 
| Expanse.IP.Geo.City | String | Geo coordinates city for this IP address | 
| Expanse.IP.Geo.RegionCode | String | Geo coordinates Region Code for this IP address | 
| Expanse.IP.Geo.CountryCode | String | Geo coordinates Country Code for this IP address | 
| Expanse.IP.Annotations.Tags | String | Customer defined Tags from Expanse related to this IP Range | 
| Expanse.IP.Annotations.AdditionalNotes | String | Customer defined Notes from Expanse related to this IP Range | 
| Expanse.IP.Annotations.PointsOfContact | String | Customer defined Points of Contact from Expanse related to this IP Range | 
| Expanse.IP.SeverityCounts.CRITICAL | Number | Count of CRITICAL Events for this IP address | 
| Expanse.IP.SeverityCounts.ROUTINE | Number | Count of ROUTINE Events for this IP address | 
| Expanse.IP.SeverityCounts.WARNING | Number | Count of WARNING Events for this IP address | 
| Expanse.IP.Geo.Description | String | Additional information about the location | 
| Expanse.IP.Geo.Country | String | The country in which the IP address is located. | 


##### Command Example
```!ip ip=74.142.119.130```

##### Context Example
```
{
    "IP": {
        "Geo": {
            "Country": "US", 
            "Description": "AKRON", 
            "Location": "41.0433:-81.5239"
        }, 
        "Address": "74.142.119.130"
    }, 
    "DBotScore": {
        "Vendor": "Expanse", 
        "Indicator": "74.142.119.130", 
        "Score": 0, 
        "Type": "ip"
    }, 
    "Expanse.IP": {
        "Version": "4", 
        "Annotations": {
            "AdditionalNotes": "", 
            "Tags": [], 
            "PointsOfContact": []
        }, 
        "BusinessUnits": [
            "Acme Latex Supply"
        ], 
        "SeverityCounts": {
            "CRITICAL": 2, 
            "WARNING": 4, 
            "ROUTINE": 2
        }, 
        "Address": "74.142.119.130", 
        "Geo": {
            "City": "AKRON", 
            "Description": "AKRON", 
            "CountryCode": "US", 
            "Longitude": -81.5239, 
            "RegionCode": "OH", 
            "Location": "41.0433:-81.5239", 
            "Latitude": 41.0433
        }, 
        "IPRange": {
            "AttributionReasons": [
                "This parent range is attributed via IP network registration records for 74.142.119.128\u201374.142.119.135"
            ], 
            "ResponsiveIPCount": 1, 
            "EndAddress": "74.142.119.135", 
            "RangeIntroduced": "2019-08-02", 
            "StartAddress": "74.142.119.128", 
            "RangeSize": 8
        }
    }
}
```

##### Human Readable Output
### IP information for: 74.142.119.130
|Address|Annotations|BusinessUnits|Geo|IPRange|SeverityCounts|Version|
|---|---|---|---|---|---|---|
| 74.142.119.130 | AdditionalNotes: null<br />PointsOfContact: null<br />Tags: null| Acme Latex Supply | Description: AKRON<br />Latitude: 41.0433<br />Longitude: -81.5239<br />City: AKRON<br />RegionCode: OH<br />CountryCode: US<br />Location: 41.0433:-81.5239 | StartAddress: 74.142.119.128<br />EndAddress: 74.142.119.135<br />RangeSize: 8<br />ResponsiveIPCount: 2<br />RangeIntroduced: 2019-08-02<br />AttributionReasons: This parent range is attributed via IP network registration records for 74.142.119.128–74.142.119.135 | CRITICAL: 1<br />ROUTINE: 4<br />WARNING: 2 | 4 |


### 2. domain
---
domain command
##### Required Permissions
**none**
##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | domain to search | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: "google.com | 
| Domain.DNS | String | A list of IP objects resolved by DNS | 
| Domain.CreationDate | Date | The date that the domain was created | 
| Domain.DomainStatus | String | The status of the domain | 
| Domain.ExpirationDate | Date | The expiration date of the domain | 
| Domain.NameServers | String | Name servers of the domain | 
| Domain.Organization | String | The organization of the domain | 
| Domain.Admin.Country | String | The country of the domain administrator | 
| Domain.Admin.Email | String | The email of the domain administrator | 
| Domain.Admin.Name | String | The name of the domain administrator | 
| Domain.Admin.Phone | String | The phone of the domain administrator | 
| Domain.Registrant.Country | String | The country of the registrant | 
| Domain.Registrant.Email | String | The email of the registrant | 
| Domain.Registrant.Name | String | The name of the registrant | 
| Domain.Registrant.Phone | String | The phone of the registrant | 
| Domain.WHOIS.DomainStatus | String | The status of the domain | 
| Domain.WHOIS.NameServers | String | A list of name servers, for example: "ns1.bla.com, ns2.bla.com" | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated | 
| Domain.WHOIS.ExpirationDate | Date | The date that the domain expires | 
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant | 
| Domain.WHOIS.Registrant.Phone | String | The phone of the registrant | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy" | 
| Domain.WHOIS.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse | 
| Domain.WHOIS.Registrar.AbusePhone | Unknown | The phone number of contact for reporting abuse | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator | 
| Domain.WHOIS.Admin.Phone | Unknown | The phone number of the domain administrator | 
| Expanse.Domain.Name | String | The domain name, for example: "google.com | 
| Expanse.Domain.DateAdded | Date | Date the domain was added to Expanse | 
| Expanse.Domain.FirstObserved | Date | Date Expanse first observed the domain | 
| Expanse.Domain.LastObserved | Date | Date Expanse last observed the domain | 
| Expanse.Domain.HasLinkedCloudResources | Boolean | Does this domain have linked cloud resources ? | 
| Expanse.Domain.SourceDomain | String | Top level domain | 
| Expanse.Domain.Tenant | String | Customer defined Tenant from Expanse | 
| Expanse.Domain.BusinessUnits | String | Customer defined Business Units from Expanse | 
| Expanse.Domain.DNSSEC | String | DNSSEC info | 
| Expanse.Domain.RecentIPs | String | Any recent IP addresses Expanse has seen for this domain | 
| Expanse.Domain.CloudResources | String | Any Cloud Resources Expanse has seen for this domain | 
| Expanse.Domain.LastSubdomainMetadata | String | Any recent subdomain metadata Expanse has seen for this domain | 
| Expanse.Domain.ServiceStatus | String | Service Status Expanse sees for this domain | 
| Expanse.Domain.LastSampledIP | String | Last seen IP address for this domain | 
| Expanse.Domain.DNS | String | A list of IP objects resolved by DNS | 
| Expanse.Domain.CreationDate | Date | The date that the domain was created | 
| Expanse.Domain.DomainStatus | String | The status of the domain | 
| Expanse.Domain.ExpirationDate | Date | The expiration date of the domain | 
| Expanse.Domain.NameServers | String | Name servers of the domain | 
| Expanse.Domain.Organization | String | The organization of the domain | 
| Expanse.Domain.Admin.Country | String | The country of the domain administrator | 
| Expanse.Domain.Admin.Email | String | The email address of the domain administrator | 
| Expanse.Domain.Admin.Name | String | The name of the domain administrator | 
| Expanse.Domain.Admin.Phone | String | The phone number of the domain administrator | 
| Expanse.Domain.Registrant.Country | String | The country of the registrant | 
| Expanse.Domain.Registrant.Email | String | The email address of the registrant | 
| Expanse.Domain.Registrant.Name | String | The name of the registrant | 
| Expanse.Domain.Registrant.Phone | String | The phone number for receiving abuse reports | 
| Expanse.Domain.WHOIS.DomainStatus | String | The status of the domain | 
| Expanse.Domain.WHOIS.NameServers | String | A list of name servers, for example: "ns1.bla.com, ns2.bla.com" | 
| Expanse.Domain.WHOIS.CreationDate | Date | The date that the domain was created | 
| Expanse.Domain.WHOIS.UpdatedDate | String | The date that the domain was last updated | 
| Expanse.Domain.WHOIS.ExpirationDate | String | The date that the domain expires | 
| Expanse.Domain.WHOIS.Registrant.Email | String | The email address of the registrant | 
| Expanse.Domain.WHOIS.Registrant.Name | String | The name of the registrant | 
| Expanse.Domain.WHOIS.Registrant.Phone | String | The phone number of the registrant | 
| Expanse.Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: "GoDaddy" | 
| Expanse.Domain.WHOIS.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse | 
| Expanse.Domain.WHOIS.Registrar.AbusePhone | String | The phone number of contact for reporting abuse | 
| Expanse.Domain.WHOIS.Admin.Name | String | The name of the domain administrator | 
| Expanse.Domain.WHOIS.Admin.Email | String | The email address of the domain administrator | 
| Expanse.Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator | 


##### Command Example
```!domain domain=atlas.enron.com```

##### Context Example
```
{
    "Domain": {
        "Name": "atlas.enron.com", 
        "Admin": {
            "Phone": "14806242599", 
            "Country": "UNITED STATES", 
            "Email": "ENRON.COM@domainsbyproxy.com", 
            "Name": "Registration Private"
        }, 
        "DomainStatus": [
            "HAS_DNS_RESOLUTION"
        ], 
        "NameServers": [
            "NS73.DOMAINCONTROL.COM", 
            "NS74.DOMAINCONTROL.COM"
        ], 
        "ExpirationDate": "2019-10-10T04:00:00Z", 
        "DNS": [], 
        "Organization": "Domains By Proxy, LLC", 
        "CreationDate": "1995-10-10T04:00:00Z", 
        "Registrant": {
            "Phone": "14806242599", 
            "Country": "UNITED STATES", 
            "Email": "ENRON.COM@domainsbyproxy.com", 
            "Name": "Registration Private"
        }, 
        "WHOIS": {
            "Admin": {
                "Phone": "14806242599",
                "Email": "ENRON.COM@domainsbyproxy.com",
                "Name": "Registration Private"
            }, 
            "DomainStatus": [
                "clientDeleteProhibited clientRenewProhibited clientTransferProhibited clientUpdateProhibited"
            ], 
            "NameServers": [
                "NS73.DOMAINCONTROL.COM", 
                "NS74.DOMAINCONTROL.COM"
            ], 
            "UpdatedDate": "2015-07-29T16:20:56Z", 
            "Registrar": {
                "AbuseEmail": null, 
                "AbusePhone": null, 
                "Name": "GoDaddy.com, LLC"
            }, 
            "ExpirationDate": "2019-10-10T04:00:00Z", 
            "CreationDate": "1995-10-10T04:00:00Z", 
            "Registrant": {
                "Phone": "14806242599", 
                "Email": "ENRON.COM@domainsbyproxy.com", 
                "Name": "Registration Private"
            }
        }
    }, 
    "Expanse.Domain": {
        "LastSubdomainMetadata": null, 
        "WHOIS": {
            "Admin": {
                "Phone": "14806242599", 
                "Email": "ENRON.COM@domainsbyproxy.com", 
                "Name": "Registration Private"
            }, 
            "DomainStatus": [
                "clientDeleteProhibited clientRenewProhibited clientTransferProhibited clientUpdateProhibited"
            ], 
            "NameServers": [
                "NS73.DOMAINCONTROL.COM", 
                "NS74.DOMAINCONTROL.COM"
            ], 
            "UpdatedDate": "2015-07-29T16:20:56Z", 
            "Registrar": {
                "AbuseEmail": null, 
                "AbusePhone": null, 
                "Name": "GoDaddy.com, LLC"
            }, 
            "ExpirationDate": "2019-10-10T04:00:00Z", 
            "CreationDate": "1995-10-10T04:00:00Z", 
            "Registrant": {
                "Phone": "14806242599", 
                "Email": "ENRON.COM@domainsbyproxy.com", 
                "Name": "Registration Private"
            }
        }, 
        "DNSSEC": null, 
        "DomainStatus": [
            "HAS_DNS_RESOLUTION"
        ], 
        "HasLinkedCloudResources": false, 
        "SourceDomain": "enron.com", 
        "LastObserved": "2020-01-02T09:30:00.374Z", 
        "ExpirationDate": "2019-10-10T04:00:00Z", 
        "CloudResources": [], 
        "Tenant": "VanDelay Industries", 
        "Name": "atlas.enron.com", 
        "Admin": {
            "Phone": "14806242599", 
            "Country": "UNITED STATES", 
            "Email": "ENRON.COM@domainsbyproxy.com", 
            "Name": "Registration Private"
        }, 
        "LastSampledIP": "192.64.147.150", 
        "BusinessUnits": [
            "VanDelay Industries"
        ], 
        "DNS": [], 
        "RecentIPs": [], 
        "Organization": "Domains By Proxy, LLC", 
        "DateAdded": "2020-01-04T04:57:48.580Z", 
        "NameServers": [
            "NS73.DOMAINCONTROL.COM", 
            "NS74.DOMAINCONTROL.COM"
        ], 
        "FirstObserved": "2020-01-02T09:30:00.374Z", 
        "ServiceStatus": [
            "NO_ACTIVE_SERVICE", 
            "NO_ACTIVE_CLOUD_SERVICE", 
            "NO_ACTIVE_ON_PREM_SERVICE"
        ], 
        "CreationDate": "1995-10-10T04:00:00Z", 
        "Registrant": {
            "Phone": "14806242599", 
            "Country": "UNITED STATES", 
            "Email": "ENRON.COM@domainsbyproxy.com", 
            "Name": "Registration Private"
        }
    }, 
    "DBotScore": {
        "Vendor": "Expanse", 
        "Indicator": "atlas.enron.com", 
        "Score": 0, 
        "Type": "url"
    }
}
```

##### Human Readable Output
### Domain information for: atlas.enron.com
|Admin|BusinessUnits|CloudResources|CreationDate|DNS|DNSSEC|DateAdded|DomainStatus|ExpirationDate|FirstObserved|HasLinkedCloudResources|LastObserved|LastSampledIP|LastSubdomainMetadata|Name|NameServers|Organization|RecentIPs|Registrant|ServiceStatus|SourceDomain|Tenant|WHOIS|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Country: UNITED STATES<br />Email: ENRON.COM@domainsbyproxy.com<br />Name: Registration Private<br />Phone: 14806242599 | VanDelay Industries |  | 1995-10-10T04:00:00Z |  |  | 2020-01-04T04:57:48.580Z | HAS_DNS_RESOLUTION | 2019-10-10T04:00:00Z | 2020-01-02T09:30:00.374Z | false | 2020-01-02T09:30:00.374Z | 192.64.147.150 |  | atlas.enron.com | NS73.DOMAINCONTROL.COM,<br />NS74.DOMAINCONTROL.COM | Domains By Proxy, LLC |  | Country: UNITED STATES<br />Email: ENRON.COM@domainsbyproxy.com<br />Name: Registration Private<br />Phone: 14806242599 | NO_ACTIVE_SERVICE,<br />NO_ACTIVE_CLOUD_SERVICE,<br />NO_ACTIVE_ON_PREM_SERVICE | enron.com | VanDelay Industries | DomainStatus: clientDeleteProhibited clientRenewProhibited clientTransferProhibited clientUpdateProhibited<br />NameServers: NS73.DOMAINCONTROL.COM,<br />NS74.DOMAINCONTROL.COM<br />CreationDate: 1995-10-10T04:00:00Z<br />UpdatedDate: 2015-07-29T16:20:56Z<br />ExpirationDate: 2019-10-10T04:00:00Z<br />Registrant: {"Email": "ENRON.COM@domainsbyproxy.com", "Name": "Registration Private", "Phone": "14806242599"}<br />Registrar: {"Name": "GoDaddy.com, LLC", "AbuseEmail": null, "AbusePhone": null}<br />Admin: {"Name": "Registration Private", "Email": "ENRON.COM@domainsbyproxy.com", "Phone": "14806242599"} |

### 3. expanse-get-certificate
---
expanse-get-certificate command
##### Required Permissions
**none**
##### Base Command

`expanse-get-certificate`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| common_name | domain to search | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Certificate.SearchTerm | string | The common name searched for |
| Expanse.Certificate.CommonName | string | The certificate common name |
| Expanse.Certificate.FirstObserved | date | Certificate first observation date |
| Expanse.Certificate.LastObserved | date | Certificate last observation date |
| Expanse.Certificate.DateAdded | date | Date certificate was added to Expanse |
| Expanse.Certificate.Provider | string | The certificate provider |
| Expanse.Certificate.NotValidBefore | date | Certificate not-valid-before date |
| Expanse.Certificate.NotValidAfter | date | Certificate not-valid-after date |
| Expanse.Certificate.Properties | string | Certificate properties |
| Expanse.Certificate.MD5Hash | string | Certificate MD5 Hash |
| Expanse.Certificate.PublicKeyAlgorithm | string | Certificate public key algorithm used |
| Expanse.Certificate.PublicKeyBits | number | Public key size |
| Expanse.Certificate.BusinessUnits | string | Business Unit for certificate |
| Expanse.Certificate.CertificateAdvertisementStatus | string | Is Certificate advertised |
| Expanse.Certificate.ServiceStatus | string | Any detected services for the certificate |
| Expanse.Certificate.RecentIPs | string | Any recent IPs the certificate was detected on |
| Expanse.Certificate.CloudResources | string | Any cloud resources returning the certificate |
| Expanse.Certificate.PemSha1 | string | SHA1 hash of the certificate PEM |
| Expanse.Certificate.PemSha256 | string | SHA256 hash of the certificate PEM |
| Expanse.Certificate.Issuer.Name | string | Certificate Issuer name |
| Expanse.Certificate.Issuer.Email | string | Certificate Issuer email |
| Expanse.Certificate.Issuer.Country | string | Certificate Issuer country |
| Expanse.Certificate.Issuer.Org | string | Certificate Issuer Org |
| Expanse.Certificate.Issuer.Unit | string | Certificate Issuer Unit |
| Expanse.Certificate.Issuer.AltNames | string | Certificate Issuer alternative names |
| Expanse.Certificate.Issuer.Raw | string | Certificate Issuer raw details |
| Expanse.Certificate.Subject.Name | string | Certificate Subject name |
| Expanse.Certificate.Subject.Email | string | Certificate Subject email |
| Expanse.Certificate.Subject.Country | string | Certificate Subject country |
| Expanse.Certificate.Subject.Org | string | Certificate Subject Org |
| Expanse.Certificate.Subject.Unit | string | Certificate Subject Unit |
| Expanse.Certificate.Subject.AltNames | string | Certificate Subject alternative names | 
| Expanse.Certificate.Subject.Raw | string | Certificate Subject raw details |

##### Command Example
```!expanse-get-certificate common_name=atlas.enron.com```

##### Context Example
```
{
    "Expanse.Certificate": {
        "BusinessUnits": "VanDelay Industries",
        "CertificateAdvertisementStatus": "NO_CERTIFICATE_ADVERTISEMENT",
        "CloudResources": "",
        "CommonName": "atlas.enron.com",
        "DateAdded": "2019-11-21T09:14:27.308679Z",
        "FirstObserved": "2019-11-21T09:14:27.308679Z",
        "Issuer": {
            "AltNames": "",
            "Country": "US",
            "Email": null,
            "Name": "Let's Encrypt Authority X3",
            "Org": "Let's Encrypt",
            "Raw": "C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3",
            "Unit": null
        },
        "LastObserved": ""2019-12-19T09:13:47.208679Z",
        "MD5Hash": "VEwAbJfmIFAVcZ_x4lm42g==",
        "NotValidAfter": "2019-03-31T00:27:46Z",
        "NotValidBefore": "2018-12-31T00:27:46Z",
        "PemSha1": "3LAYlmV3xtn4ONJ3C9JN_ogz0u8=",
        "PemSha256": "kyERnydF-dzOuCCpG4jDnkGr4fI2a--lBZQz2hyhb30=",
        "Properties": "EXPIRED",
        "Provider": "None",
        "PublicKeyAlgorithm": "RSA",
        "PublicKeyBits": 2048,
        "RecentIPs": "",
        "SearchTerm": "atlas.enron.com",
        "ServiceStatus": "NO_ACTIVE_SERVICE,NO_ACTIVE_ON_PREM_SERVICE,NO_ACTIVE_CLOUD_SERVICE",
        "Subject": {
            "AltNames": "atlas.enron.com",
            "Country": "US",
            "Email": "ENRON.COM@domainsbyproxy.com",
            "Name": "atlas.enron.com",
            "Org": "ENRON",
            "Raw": "CN=api-dev.radioshack.com",
            "Unit": null
        }
    }
}
```

##### Human Readable Output
### Certificate information for: atlas.enron.com
|BusinessUnits|CertificateAdvertisementStatus|CloudResources|CommonName|DateAdded|FirstObserved|Issuer|LastObserved|MD5Hash|NotValidAfter|NotValidBefore|PemSha1|PemSha256|Properties|Provider|PublicKeyAlgorithm|PublicKeyBits|RecentIPs|SearchTerm|ServiceStatus|Subject|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| VanDelay Industries | NO_CERTIFICATE_ADVERTISEMENT |  | atlas.enron.com | 2019-11-21T09:14:27.308679Z |  | Name: Let's Encrypt Authority X3<br />Email: null<br />Country: US<br />Org: Let's Encrypt<br />Unit: null<br />AltNames: <br />Raw: C=US,O=Let's Encrypt,CN=Let's Encrypt Authority X3 |  | VEwAbJfmIFAVcZ_x4lm42g== | 2019-03-31T00:27:46Z | 2018-12-31T00:27:46Z | 3LAYlmV3xtn4ONJ3C9JN_ogz0u8= | kyERnydF-dzOuCCpG4jDnkGr4fI2a--lBZQz2hyhb30= | EXPIRED | None | RSA | 2048 |  | atlas.enron.com | NO_ACTIVE_SERVICE,NO_ACTIVE_ON_PREM_SERVICE,NO_ACTIVE_CLOUD_SERVICE | Name: atlas.enron.com<br />Email: ENRON.COM@domainsbyproxy.com<br />Country: US<br />Org: null<br />Unit: null<br />AltNames: atlas.enron.com<br />Raw: CN=atlas.enron.com |


### 4. expanse-get-behavior
---
expanse-get-behavior command
##### Required Permissions
**none**
##### Base Command

`expanse-get-behavior`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | ip to search| Required |
| start_time | ISO-8601 UTC timestamp denoting the earliest behavior data to fetch| Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Behavior.SearchTerm | string | IP used to search |
| Expanse.Behavior.InternalAddress| string | IP internal to Organization |
| Expanse.Behavior.InternalCountryCode | string | Internal IP Country Geolocation country |
| Expanse.Behavior.BusinessUnit | string | Buisness unit of IP |
| Expanse.Behavior.InternalDomains | string | Known domains associated with IP |
| Expanse.Behavior.InternalIPRanges | string | Known Internal IP ranges containing IP |
| Expanse.Behavior.InternalExposureTypes | string | Known Exposures for IP |
| Expanse.Behavior.ExternalAddresses | string | External IP addresses with known communication to IP |
| Expanse.Behavior.FlowSummaries | string | Summaries of most recents risky flows for IP |
| Expanse.Behavior.Flows | string | Array of Flow Objects |
| Expanse.Behavior.Flows.InternalAddress | string | Internal IP address for flow |
| Expanse.Behavior.Flows.InternalPort | number | Internal Port for flow |
| Expanse.Behavior.Flows.InternalCountryCode | string | Internal country code for flow |
| Expanse.Behavior.Flows.ExternalAddress | string | External IP address for flow |
| Expanse.Behavior.Flows.ExternalPort | number | External Port for flow |
| Expanse.Behavior.Flows.ExternalCountryCode | string | External country code for flow |
| Expanse.Behavior.Flows.Timestamp | date | Timestamp of flow |
| Expanse.Behavior.Flows.Protocol | string | Protocol of flow (UDP, TCP) |
| Expanse.Behavior.Flows.Direction | string | Direction of flow |
| Expanse.Behavior.Flows.RiskRule | string | Risk rule violated by flow | 

##### Command Example
```!expanse-get-behavior ip=74.142.119.130 start_time=7```

##### Context Example
```
{
    "BusinessUnit": "VanDelay Industries",
    "ExternalAddresses": "66.110.49.36,66.110.49.72",
    "FlowSummaries": "74.142.119.130:57475 (US) -\u003e 66.110.49.72:443 (CA) TCP violates Outbound Flows from Servers at 2020-04-05T21:18:56.889Z\n74.142.119.130:61694 (US) -\u003e 66.110.49.36:443 (CA) TCP violates Outbound Flows from Servers at 2020-04-05T21:03:50.867Z\n",
    "Flows": [
        {
            "Direction": "OUTBOUND",
            "ExternalAddress": "66.110.49.72",
            "ExternalCountryCode": "CA",
            "ExternalPort": 443,
            "InternalAddress": "74.142.119.130",
            "InternalCountryCode": "US",
            "InternalPort": 57475,
            "Protocol": "TCP",
            "RiskRule": "Outbound Flows from Servers",
            "Timestamp": "2020-04-05T21:18:56.889Z"
        },
        {
            "Direction": "OUTBOUND",
            "ExternalAddress": "66.110.49.36",
            "ExternalCountryCode": "CA",
            "ExternalPort": 443,
            "InternalAddress": "74.142.119.130",
            "InternalCountryCode": "US",
            "InternalPort": 61694,
            "Protocol": "TCP",
            "RiskRule": "Outbound Flows from Servers",
            "Timestamp": "2020-04-05T21:03:50.867Z"
        }
    ],
    "InternalAddress": "74.142.119.130",
    "InternalCountryCode": "US",
    "InternalDomains": "",
    "InternalExposureTypes": "HttpServer",
    "InternalIPRanges": "",
    "SearchTerm": "74.142.119.130"
}
```

##### Human Readable Output
### Expanse Behavior information for: 74.142.119.130
|BusinessUnit|ExternalAddresses|FlowSummaries|InternalAddress|InternalCountryCode|InternalDomains|InternalExposureTypes|InternalIPRanges|SearchTerm|
|---|---|---|---|---|---|---|---|---|
| VanDelay Industries | 66.110.49.36,66.110.49.72 | 74.142.119.130:57475 (US) -> 66.110.49.72:443 (CA) TCP violates Outbound Flows from Servers at 2020-04-05T21:18:56.889Z<br />74.142.119.130:61694 (US) -> 66.110.49.36:443 (CA) TCP violates Outbound Flows from Servers at 2020-04-05T21:03:50.867Z | 74.142.119.130 | US |  | HttpServer |  | 74.142.119.130 |


### 4. expanse-get-exposures
---
expanse-get-exposures command
##### Required Permissions
**none**
##### Base Command

`expanse-get-exposures`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | ip to search| Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Exposures.SearchTerm | string | IP used to search |
| Expanse.Exposures.TotalExposureCount | number | The total count of exposures for the IP |
| Expanse.Exposures.CriticalExposureCount | number | The total count of CRITICAL exposures for the IP |
| Expanse.Exposures.WarningExposureCount | number | The total count of WARNING exposures for the IP |
| Expanse.Exposures.RoutineExposureCount | number | The total count of ROUTINE exposures for the IP |
| Expanse.Exposures.UnknownExposureCount | number | The total count of UNKNOWN exposures for the IP |
| Expanse.Exposures.ExposureSummaries | string | Summaries of exposures for the IP address |
| Expanse.Exposures.Exposures | unknown | Array of Exposures for the IP address |
| Expanse.Exposures.Exposures.ExposureType | string | Exposure type of the Exposure |
| Expanse.Exposures.Exposures.BusinessUnit | string | Business Unit of the Exposure |
| Expanse.Exposures.Exposures.Ip | string | IP Address the Exposure was found on |
| Expanse.Exposures.Exposures.Port | string | Port the Exposure was found on |
| Expanse.Exposures.Exposures.Severity | string | Severity of the Exposure |
| Expanse.Exposures.Exposures.Certificate | unknown | Certificate details associated with Exposure |
| Expanse.Exposures.Exposures.FirstObservsation | unknown | First Observation of the Exposure |
| Expanse.Exposures.Exposures.LastObservsation | unknown | Last Observation of the Exposure |
| Expanse.Exposures.Exposures.Status | unknown | Status details of the Exposure |
| Expanse.Exposures.Exposures.Provider | unknown | Provider details of the Exposure |


##### Command Example
```!expanse-get-exposures ip=33.2.243.123```

##### Context Example
```
{
    "CriticalExposureCount": 0,
    "ExposureSummaries": "NTP_SERVER exposure on 33.2.243.123:UDP123",
    "Exposures": [
        {
            "BusinessUnit": "VanDelay Industries",
            "Certificate": null,
            "ExposureType": "NTP_SERVER",
            "FirstObservsation": {
                "configuration": {
                    "certificate": null,
                    "response": {
                        "ntp": {
                            "delay": 0,
                            "dispersion": 65537,
                            "extentionData": null,
                            "keyIdentifier": null,
                            "leapIndicator": 3,
                            "messageDigest": null,
                            "mode": 4,
                            "originateTime": "2004-11-24T15:12:11.444Z",
                            "poll": 4,
                            "precision": -18,
                            "receiveTime": "2019-02-01T00:32:17.693Z",
                            "reference": {
                                "ref_str": {
                                    "reference": ""
                                }
                            },
                            "stratum": 0,
                            "transmitTime": "2019-02-01T00:32:17.693Z",
                            "updateTime": "2036-02-07T06:28:16Z",
                            "version": 4
                        }
                    }
                },
                "geolocation": {
                    "city": "VICTOR",
                    "countryCode": "US",
                    "latitude": 42.982,
                    "longitude": -77.4245,
                    "regionCode": "NY"
                },
                "hostname": null,
                "id": "2d349139-1111-3c92-a168-557d34729bf8",
                "ip": "33.2.243.123",
                "portNumber": 123,
                "portProtocol": "UDP",
                "qrispTaskId": 21716146,
                "scanned": "2019-02-01T00:19:16Z"
            },
            "Ip": "33.2.243.123",
            "LastObservsation": {
                "configuration": {
                    "certificate": null,
                    "response": {
                        "ntp": {
                            "delay": 0,
                            "dispersion": 65537,
                            "extentionData": null,
                            "keyIdentifier": null,
                            "leapIndicator": 3,
                            "messageDigest": null,
                            "mode": 4,
                            "originateTime": "2004-11-24T15:12:11.444Z",
                            "poll": 4,
                            "precision": -18,
                            "receiveTime": "2020-05-05T16:05:36.606Z",
                            "reference": {
                                "ref_str": {
                                    "reference": ""
                                }
                            },
                            "stratum": 0,
                            "transmitTime": "2020-05-05T16:05:36.606Z",
                            "updateTime": "2036-02-07T06:28:16Z",
                            "version": 4
                        }
                    }
                },
                "geolocation": {
                    "city": "VICTOR",
                    "countryCode": "US",
                    "latitude": 42.982,
                    "longitude": -77.4245,
                    "regionCode": "NY"
                },
                "hostname": null,
                "id": "69a0159b-facc-3c55-b71d-3e6b8ae9252b",
                "ip": "33.2.243.123",
                "portNumber": 123,
                "portProtocol": "UDP",
                "qrispTaskId": 41755001,
                "scanned": "2020-05-05T16:03:30Z"
            },
            "Port": "UDP123",
            "Provider": null,
            "Severity": "ROUTINE",
            "Status": {
                "remediation": [],
                "snooze": []
            }
        }
    ],
    "RoutineExposureCount": 1,
    "SearchTerm": "33.2.243.123",
    "TotalExposureCount": 1,
    "UnknownExposureCount": 0,
    "WarningExposureCount": 0
}
```

##### Human Readable Output
### Expanse Exposure information for: 33.2.243.123
|CriticalExposureCount|ExposureSummaries|RoutineExposureCount|SearchTerm|TotalExposureCount|UnknownExposureCount|WarningExposureCount|
|---|---|---|---|---|---|---|
| 0 | NTP_SERVER exposure on 33.2.243.123:UDP123 | 1 | 33.2.243.123 | 1 | 0 | 0 |


### 4. expanse-get-domains-for-certificate
---
expanse-get-domains-for-certificate command
##### Required Permissions
**none**
##### Base Command

`expanse-get-domains-for-certificate`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| common_name | The certificate common name | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.IPDomains.SearchTerm | string | The common name that was searched |
| Expanse.IPDomains.TotalDomainCount | number | The number of domains found matching the specified certificate |
| Expanse.IPDomains.FlatDomainList | number | An array of all domain names found. This is truncated at 50 |
| Expanse.IPDomains.DomainList | number | An array of domain objects. This is truncated at 50 |

##### Command Example
```!expanse-get-domains-for-certificate common_name="*.us.expanse.co"```

##### Context Example
<!-- disable-secrets-detection-start -->
```
{
    "SearchTerm": "*.us.expanse.co",
    "TotalDomainCount": 2,
    "FlatDomainList": ["california.us.expanse.co", "dc.us.expanse.co"]
    "DomainList": [
        {
            "ip": "33.2.243.123",
            "domain": "california.us.expanse.co",
            "type": "DOMAIN_RESOLUTION",
            "assetType": "DOMAIN",
            "assetKey": "california.us.expanse.co",
            "provider": {
                "id": "AWS",
                "name": "Amazon Web Services"
            },
            "lastObserved": "2020-06-22T05:20:32.883Z",
            "tenant": {
                "id": "4b7efca7-c595-408e-b4d1-634080e48367",
                "name": "Palo Alto Networks",
                "tenantId": "4b7efca7-c595-408e-b4d1-634080e48367"
            },
            "businessUnits": [
                {
                    "id": "a1f0f39b-f358-3c8c-947b-926887871b88",
                    "name": "VanDelay Import-Export"
                    "tenantId": "a1f0f39b-f358-3c8c-947b-926887871b88"
                }
            ],
            "commonName": null
        },
        {
            "ip": "33.2.243.123",
            "domain": "dc.us.expanse.co",
            "type": "DOMAIN_RESOLUTION",
            "assetType": "DOMAIN",
            "assetKey": "dc.us.expanse.co",
            "provider": {
                "id": "AWS",
                "name": "Amazon Web Services"
            },
            "lastObserved": "2020-06-21T07:20:32.883Z",
            "tenant": {
                "id": "4b7efca7-c595-408e-b4d1-634080e48367",
                "name": "Palo Alto Networks",
                "tenantId": "4b7efca7-c595-408e-b4d1-634080e48367"
            },
            "businessUnits": [
                {
                    "id": "a1f0f39b-f358-3c8c-947b-926887871b88",
                    "name": "VanDelay Import-Export"
                    "tenantId": "a1f0f39b-f358-3c8c-947b-926887871b88"
                }
            ],
            "commonName": null
        }
    ]
}
```
<!-- disable-secrets-detection-start -->

##### Human Readable Output
### Expanse Domains matching Certificate Common Name: *.us.expanse.co
| FlatDomainList | SearchTerm | TotalDomainCount |
|---|---|---|
| california.us.expanse.co, dc.us.expanse.co | *.us.expanse.co | 2 |


## Contact Details
---
For Product Support, please contact your Technical Account Manager or email help@expanseinc.com
