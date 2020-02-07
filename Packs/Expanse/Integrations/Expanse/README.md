## Overview
---

The Expanse App for Demisto leverages the Expander API to retrieve network exposures and create incidents in Demisto.  This application also allows for IP and Domain enrichment, retrieving assets and exposures information drawn from Expanse’s unparalleled view of the Internet.
This integration was integrated and tested with version xx of Expanse
## Expanse Playbook
---

## Use Cases
---

## Configure Expanse on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Expanse.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __API Key__
    * __Fetch incidents__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
    * __How many events to pull from Expander per run__
    * __How many days to pull past events on first run__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. ip
2. domain
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
| Expanse.IP.Geo.CountryCode | String | Geo coordinates Contry Code for this IP address | 
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
| 74.142.119.130 | Tags: <br>AdditionalNotes: <br>PointsOfContact:  | Acme Latex Supply | Location: 41.0433:-81.5239<br>Description: AKRON<br>Latitude: 41.0433<br>Longitude: -81.5239<br>City: AKRON<br>RegionCode: OH<br>CountryCode: US | StartAddress: 74.142.119.128<br>EndAddress: 74.142.119.135<br>RangeSize: 8<br>ResponsiveIPCount: 1<br>RangeIntroduced: 2019-08-02<br>AttributionReasons: This parent range is attributed via IP network registration records for 74.142.119.128–74.142.119.135 | CRITICAL: 2<br>ROUTINE: 2<br>WARNING: 4 | 4 |


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
| domain | domain to searh | Required | 


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
| Expanse.Domain.Tenant | String | Customer defined Tenant from Exapnse | 
| Expanse.Domain.BusinessUnits | String | Customer defined Busines Units from Exapnse | 
| Expanse.Domain.DNSSEC | String | DNSSEC info | 
| Expanse.Domain.RecentIPs | String | Any recent IP addresses Expanse has seen for this domain | 
| Expanse.Domain.CloudResources | String | Any Cloud Resources Expanse has seen for this domain | 
| Expanse.Domain.LastSubdomainMetadata | String | Any recent subdomain metadata Expanse has seen for this domain | 
| Expanse.Domain.ServiceStatus | String | Service Status Expanse sees for this domain | 
| Expanse.Domain.LastSampledIP | String | Last seen IP address fdor this domain | 
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
| Country: UNITED STATES<br>Email: ENRON.COM@domainsbyproxy.com<br>Name: Registration Private<br>Phone: 14806242599 | VanDelay Industries |  | 1995-10-10T04:00:00Z |  |  | 2020-01-04T04:57:48.580Z | HAS_DNS_RESOLUTION | 2019-10-10T04:00:00Z | 2020-01-02T09:30:00.374Z | false | 2020-01-02T09:30:00.374Z | 192.64.147.150 |  | atlas.enron.com | NS73.DOMAINCONTROL.COM,<br>NS74.DOMAINCONTROL.COM | Domains By Proxy, LLC |  | Country: UNITED STATES<br>Email: ENRON.COM@domainsbyproxy.com<br>Name: Registration Private<br>Phone: 14806242599 | NO_ACTIVE_SERVICE,<br>NO_ACTIVE_CLOUD_SERVICE,<br>NO_ACTIVE_ON_PREM_SERVICE | enron.com | VanDelay Industries | DomainStatus: clientDeleteProhibited clientRenewProhibited clientTransferProhibited clientUpdateProhibited<br>NameServers: NS73.DOMAINCONTROL.COM,<br>NS74.DOMAINCONTROL.COM<br>CreationDate: 1995-10-10T04:00:00Z<br>UpdatedDate: 2015-07-29T16:20:56Z<br>ExpirationDate: 2019-10-10T04:00:00Z<br>Registrant: {"Email": "ENRON.COM@domainsbyproxy.com", "Name": "Registration Private", "Phone": "14806242599"}<br>Registrar: {"Name": "GoDaddy.com, LLC", "AbuseEmail": null, "AbusePhone": null}<br>Admin: {"Name": "Registration Private", "Email": "ENRON.COM@domainsbyproxy.com", "Phone": "14806242599"} |


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
