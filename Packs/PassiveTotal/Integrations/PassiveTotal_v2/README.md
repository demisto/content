Analyze and understand threat infrastructure from a variety of sources-passive DNS, active DNS, WHOIS, SSL certificates and more-without devoting resources to time-intensive manual threat research and analysis.
This integration was integrated and tested with enterprise version of PassiveTotal v2.

## Configure PassiveTotal v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | API URL | True |
| username | Username | True |
| secret | API Secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| request_timeout | HTTP\(S\) Request Timeout \(in seconds\) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### pt-whois-search

***
Gets WHOIS information records based on field matching queries.


#### Base Command

`pt-whois-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query value to use in your request. | Required | 
| field | WHOIS field to execute the search on: domain, email, name, organization, address, phone, nameserver. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: 'google.com'. | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.NameServers | String | Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.WHOIS.Admin.Country | String | The country of the domain administrator. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: 'GoDaddy'. | 
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.WHOIS.Registrant.Country | String | The country of the registrant. | 
| PassiveTotal.WHOIS.domain | String | The domain name, for example: 'google.com'. | 
| PassiveTotal.WHOIS.registrar | String | The name of the registrar of the domain | 
| PassiveTotal.WHOIS.whoisServer | String | WHOIS server name where the details of domain registrations belong | 
| PassiveTotal.WHOIS.registered | Date | The date that the domain was registered. | 
| PassiveTotal.WHOIS.expiresAt | Date | The expiration date of the domain. | 
| PassiveTotal.WHOIS.registryUpdatedAt | Date | The date when registry was last updated. | 
| PassiveTotal.WHOIS.lastLoadedAt | Date | Last loaded date of WHOIS database. | 
| PassiveTotal.WHOIS.nameServers | String | Name servers of the domain. | 
| PassiveTotal.WHOIS.organization | String | The organization of the domain. | 
| PassiveTotal.WHOIS.name | String | Name of the domain. | 
| PassiveTotal.WHOIS.telephone | String | Telephone number fetched from whois details of the domain. | 
| PassiveTotal.WHOIS.contactEmail | String | Contact Email address of the domain owner | 
| PassiveTotal.WHOIS.registrantEmail | String | The name of the domain registrant. | 
| PassiveTotal.WHOIS.registrantFax | String | The fax number of the domain registrant. | 
| PassiveTotal.WHOIS.registrantName | String | The name of the domain registrant. | 
| PassiveTotal.WHOIS.registrantOrganization | String | The organizations of the domain registrant. | 
| PassiveTotal.WHOIS.registrantStreet | String | The street of the domain registrant. | 
| PassiveTotal.WHOIS.registrantCity | String | The city of the domain registrant. | 
| PassiveTotal.WHOIS.registrantState | String | The state of the domain registrant. | 
| PassiveTotal.WHOIS.registrantPostalCode | String | The postal code of the domain registrant. | 
| PassiveTotal.WHOIS.registrantCountry | String | The country of the domain registrant. | 
| PassiveTotal.WHOIS.registrantTelephone | String | The telephone number of the domain registrant. | 
| PassiveTotal.WHOIS.adminEmail | String | The email address of the domain administrator. | 
| PassiveTotal.WHOIS.adminFax | String | The fax number of the domain administrator. | 
| PassiveTotal.WHOIS.adminName | String | The name of the domain administrator. | 
| PassiveTotal.WHOIS.adminOrganization | String | The organizations of the domain administrator. | 
| PassiveTotal.WHOIS.adminStreet | String | The street of the domain administrator. | 
| PassiveTotal.WHOIS.adminCity | String | The city of the domain administrator. | 
| PassiveTotal.WHOIS.adminState | String | The state of the domain administrator. | 
| PassiveTotal.WHOIS.adminPostalCode | String | The postal code of the domain administrator. | 
| PassiveTotal.WHOIS.adminCountry | String | The country of the domain administrator. | 
| PassiveTotal.WHOIS.adminTelephone | String | The telephone number of the domain administrator. | 
| PassiveTotal.WHOIS.billingEmail | String | The email address of the domain billing. | 
| PassiveTotal.WHOIS.billingFax | String | The fax number of the domain billing. | 
| PassiveTotal.WHOIS.billingName | String | The name of the domain billing. | 
| PassiveTotal.WHOIS.billingOrganization | String | The organizations of the domain billing. | 
| PassiveTotal.WHOIS.billingStreet | String | The street of the domain billing. | 
| PassiveTotal.WHOIS.billingCity | String | The city of the domain billing. | 
| PassiveTotal.WHOIS.billingState | String | The state of the domain billing. | 
| PassiveTotal.WHOIS.billingPostalCode | String | The postal code of the domain billing. | 
| PassiveTotal.WHOIS.billingCountry | String | The country of the domain billing. | 
| PassiveTotal.WHOIS.billingTelephone | String | The telephone number of the domain billing. | 
| PassiveTotal.WHOIS.techEmail | String | The email address of the domain tech. | 
| PassiveTotal.WHOIS.techFax | String | The fax number of the domain tech. | 
| PassiveTotal.WHOIS.techName | String | The name of the domain tech. | 
| PassiveTotal.WHOIS.techOrganization | String | The organizations of domain tech. | 
| PassiveTotal.WHOIS.techStreet | String | The street of the domain tech. | 
| PassiveTotal.WHOIS.techCity | String | The city of the domain tech. | 
| PassiveTotal.WHOIS.techState | String | The state of the domain tech. | 
| PassiveTotal.WHOIS.techPostalCode | String | The postal code of the domain tech. | 
| PassiveTotal.WHOIS.techCountry | String | The country of the domain tech. | 
| PassiveTotal.WHOIS.techTelephone | String | The telephone number of the domain tech. | 


#### Command Example

```!pt-whois-search field=domain query=riskiq.com```

#### Context Example

```
{
    "DBotScore": [
        {
            "Indicator": "riskiq.com",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        }
    ],
    "Domain": [
        {
            "Admin": {
                "Country": "us",
                "Email": "domains@riskiq.com",
                "Name": "Risk IQ",
                "Phone": "18884154447"
            },
            "CreationDate": "2006-01-11T16:00:00.000-0800",
            "ExpirationDate": "2017-01-11T16:00:00.000-0800",
            "Name": "riskiq.com",
            "NameServers": [
                "luke.ns.cloudflare.com",
                "serena.ns.cloudflare.com"
            ],
            "Organization": "RiskIQ, Inc.",
            "Registrant": {
                "Country": "us",
                "Email": "domains@riskiq.com",
                "Name": "Risk IQ",
                "Phone": "18884154447"
            },
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "GODADDY.COM, LLC"
            },
            "UpdatedDate": "2014-12-08T16:00:00.000-0800",
            "WHOIS": {
                "Admin": {
                    "Country": "us",
                    "Email": "domains@riskiq.com",
                    "Name": "Risk IQ",
                    "Phone": "18884154447"
                },
                "CreationDate": "2006-01-11T16:00:00.000-0800",
                "ExpirationDate": "2017-01-11T16:00:00.000-0800",
                "NameServers": [
                    "luke.ns.cloudflare.com",
                    "serena.ns.cloudflare.com"
                ],
                "Registrant": {
                    "Country": "us",
                    "Email": "domains@riskiq.com",
                    "Name": "Risk IQ",
                    "Phone": "18884154447"
                },
                "Registrar": {
                    "AbuseEmail": null,
                    "AbusePhone": null,
                    "Name": "GODADDY.COM, LLC"
                },
                "UpdatedDate": "2014-12-08T16:00:00.000-0800"
            }
        }
    ],
    "PassiveTotal": {
        "WHOIS": {
            "adminCity": "san francisco",
            "adminCountry": "us",
            "adminEmail": "domains@riskiq.com",
            "adminName": "Risk IQ",
            "adminOrganization": "RiskIQ, Inc.",
            "adminPostalCode": "94111",
            "adminState": "california",
            "adminStreet": "22 Battery Street\n10th Floor",
            "adminTelephone": "18884154447",
            "contactEmail": "domains@riskiq.com",
            "domain": "riskiq.com",
            "expiresAt": "2017-01-11T16:00:00.000-0800",
            "lastLoadedAt": "2016-09-27T09:40:31.180-0700",
            "name": "Risk IQ",
            "nameServers": [
                "luke.ns.cloudflare.com",
                "serena.ns.cloudflare.com"
            ],
            "organization": "RiskIQ, Inc.",
            "registered": "2006-01-11T16:00:00.000-0800",
            "registrantCity": "san francisco",
            "registrantCountry": "us",
            "registrantEmail": "domains@riskiq.com",
            "registrantName": "Risk IQ",
            "registrantOrganization": "RiskIQ, Inc.",
            "registrantPostalCode": "94111",
            "registrantState": "california",
            "registrantStreet": "22 Battery Street\n10th Floor",
            "registrantTelephone": "18884154447",
            "registrar": "GODADDY.COM, LLC",
            "registryUpdatedAt": "2014-12-08T16:00:00.000-0800",
            "techCity": "san francisco",
            "techCountry": "us",
            "techEmail": "domains@riskiq.com",
            "techName": "Risk IQ",
            "techOrganization": "RiskIQ, Inc.",
            "techPostalCode": "94111",
            "techState": "california",
            "techStreet": "22 Battery Street\n10th Floor",
            "techTelephone": "18884154447",
            "telephone": "18884154447",
            "whoisServer": "whois.godaddy.com"
        }
    }
}
```

#### Human Readable Output

>### Total Retrieved Record(s): 2

>### Associated Domains

>|Domain|WHOIS Server|Registrar|Contact Email|Name Servers|Registrant|Admin|Tech|Creation Date (GMT)|Expire Date (GMT)|Updated Date (GMT)|Last Scanned (GMT)|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| riskiq.com | whois.godaddy.com | GODADDY.COM, LLC | domains@riskiq.com | luke.ns.cloudflare.com, serena.ns.cloudflare.com | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | 2006-01-11T16:00:00.000-0800 | 2017-01-11T16:00:00.000-0800 | 2014-12-08T16:00:00.000-0800 | 2016-09-27T09:40:31.180-0700 |


### pt-get-components

***
Retrieves the host attribute components for a domain or IP address. Maximum 2000 records are fetched.


#### Base Command

`pt-get-components`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Domain or IP address you want to search components for. | Required | 
| start | Filter for records whose last seen is after this datetime. It accepts "yyyy-mm-dd hh:mm:ss" or "yyyy-mm-dd" format. | Optional | 
| end | Filter for records whose first seen is before this datetime. It accepts "yyyy-mm-dd hh:mm:ss" or "yyyy-mm-dd" format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| IP.Address | String | The IP Address of the component. | 
| PassiveTotal.Component.firstSeen | Date | The date and time when the component was first observed. | 
| PassiveTotal.Component.lastSeen | Date | The date and time when the component was most recently observed. | 
| PassiveTotal.Component.version | String | The current version of component. | 
| PassiveTotal.Component.category | String | The category under which the component falls. | 
| PassiveTotal.Component.label | String | The value of the component. | 
| PassiveTotal.Component.hostname | String | The hostname of the component. | 
| PassiveTotal.Component.address | String | The IP address of the component. | 


#### Command Example

```!pt-get-components query=www.furth.com.ar```

#### Context Example

```
{
    "DBotScore": {
        "Indicator": "www.furth.com.ar",
        "Score": 0,
        "Type": "domain",
        "Vendor": "PassiveTotal"
    },
    "Domain": {
        "Name": "www.furth.com.ar"
    },
    "PassiveTotal": {
        "Component": [
            {
                "category": "Framework",
                "firstSeen": "2020-05-29 10:57:44",
                "hostname": "www.furth.com.ar",
                "label": "PHP",
                "lastSeen": "2020-05-29 10:57:44"
            },
            {
                "category": "Server",
                "firstSeen": "2020-05-29 10:57:44",
                "hostname": "www.furth.com.ar",
                "label": "Apache",
                "lastSeen": "2020-05-29 10:57:44"
            },
            {
                "category": "Server Module",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "mod_bwlimited",
                "lastSeen": "2017-10-24 15:53:52",
                "version": "1.4"
            },
            {
                "category": "Server Module",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "OpenSSL",
                "lastSeen": "2017-10-24 15:53:52",
                "version": "1.0.1e-fips"
            },
            {
                "category": "Server",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "Apache",
                "lastSeen": "2017-10-24 15:53:52",
                "version": "2.2.29"
            },
            {
                "category": "Operating System",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "Unix",
                "lastSeen": "2017-10-24 15:53:52"
            },
            {
                "category": "Server Module",
                "firstSeen": "2016-01-11 23:45:15",
                "hostname": "www.furth.com.ar",
                "label": "mod_ssl",
                "lastSeen": "2017-10-24 15:53:52",
                "version": "2.2.29"
            }
        ]
    }
}
```

#### Human Readable Output

>### Total Retrieved Record(s): 7

>### COMPONENTS

>|Hostname|First (GMT)|Last (GMT)|Category|Value|Version|
>|---|---|---|---|---|---|
>| www.furth.com.ar | 2020-05-29 10:57:44 | 2020-05-29 10:57:44 | Framework | PHP |  |
>| www.furth.com.ar | 2020-05-29 10:57:44 | 2020-05-29 10:57:44 | Server | Apache |  |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Server Module | mod_bwlimited | 1.4 |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Server Module | OpenSSL | 1.0.1e-fips |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Server | Apache | 2.2.29 |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Operating System | Unix |  |
>| www.furth.com.ar | 2016-01-11 23:45:15 | 2017-10-24 15:53:52 | Server Module | mod_ssl | 2.2.29 |


### pt-get-trackers

***
Retrieves the host attribute trackers for a domain or IP address. Maximum 2000 records are fetched.


#### Base Command

`pt-get-trackers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Domain or IP address you want to search trackers for. | Required | 
| start | Filter for records whose last seen is after this datetime. It accepts "yyyy-mm-dd hh:mm:ss" or "yyyy-mm-dd" format. | Optional | 
| end | Filter for records whose first seen is before this datetime. It accepts "yyyy-mm-dd hh:mm:ss" or "yyyy-mm-dd" format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: "google.com". | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| IP.Address | String | The IP Address of the component. | 
| PassiveTotal.Tracker.firstSeen | Date | The date and time when the tracker was first observed. | 
| PassiveTotal.Tracker.lastSeen | Date | The date and time when the tracker was most recently observed. | 
| PassiveTotal.Tracker.attributeValue | String | The value of the tracker. | 
| PassiveTotal.Tracker.attributeType | String | The type under which the tracker falls. | 
| PassiveTotal.Tracker.hostname | String | The hostname of the tracker. | 
| PassiveTotal.Tracker.address | String | The IP address of the tracker. | 


#### Command Example

```!pt-get-trackers query=filmesonlinegratis.net```

#### Context Example

```
{
    "DBotScore": [
        {
            "Indicator": "filmesonlinegratis.net",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        },
        {
            "Indicator": "www.filmesonlinegratis.net",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        }
    ],
    "Domain": [
        {
            "Name": "filmesonlinegratis.net"
        },
        {
            "Name": "www.filmesonlinegratis.net"
        }
    ],
    "PassiveTotal": {
        "Tracker": [
            {
                "attributeType": "GoogleAnalyticsTrackingId",
                "attributeValue": "ua-70630818-3",
                "firstSeen": "2016-10-14 10:16:38",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2020-06-14 19:43:28"
            },
            {
                "attributeType": "GoogleAnalyticsAccountNumber",
                "attributeValue": "ua-70630818",
                "firstSeen": "2016-10-14 10:16:38",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2020-06-14 19:43:28"
            },
            {
                "attributeType": "GoogleAnalyticsAccountNumber",
                "attributeValue": "ua-11598035",
                "firstSeen": "2012-03-07 05:53:50",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2016-10-13 15:38:35"
            },
            {
                "attributeType": "GoogleAnalyticsTrackingId",
                "attributeValue": "ua-11598035-1",
                "firstSeen": "2012-03-07 05:53:50",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2016-10-13 15:38:35"
            },
            {
                "attributeType": "GoogleAnalyticsTrackingId",
                "attributeValue": "ua-11598035-1",
                "firstSeen": "2014-02-11 01:30:40",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2016-09-13 03:54:34"
            },
            {
                "attributeType": "GoogleAnalyticsAccountNumber",
                "attributeValue": "ua-11598035",
                "firstSeen": "2014-02-11 01:30:40",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2016-09-13 03:54:34"
            },
            {
                "attributeType": "TumblrId",
                "attributeValue": "25.media",
                "firstSeen": "2016-07-02 00:46:33",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2016-09-02 11:09:30"
            },
            {
                "attributeType": "FacebookId",
                "attributeValue": "filmesog",
                "firstSeen": "2012-11-27 06:06:44",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2015-09-26 05:52:23"
            },
            {
                "attributeType": "FacebookId",
                "attributeValue": "filmesog",
                "firstSeen": "2014-02-11 01:30:40",
                "hostname": "filmesonlinegratis.net",
                "lastSeen": "2015-09-24 05:12:39"
            },
            {
                "attributeType": "WhosAmungUsId",
                "attributeValue": "6cdg",
                "firstSeen": "2012-03-07 05:53:50",
                "hostname": "www.filmesonlinegratis.net",
                "lastSeen": "2012-03-07 16:00:45"
            }
        ]
    }
}
```

#### Human Readable Output

>### Total Retrieved Record(s): 10

>### TRACKERS

>|Hostname|First (GMT)|Last (GMT)|Type|Value|
>|---|---|---|---|---|
>| filmesonlinegratis.net | 2016-10-14 10:16:38 | 2020-06-14 19:43:28 | GoogleAnalyticsTrackingId | ua-70630818-3 |
>| filmesonlinegratis.net | 2016-10-14 10:16:38 | 2020-06-14 19:43:28 | GoogleAnalyticsAccountNumber | ua-70630818 |
>| www.filmesonlinegratis.net | 2012-03-07 05:53:50 | 2016-10-13 15:38:35 | GoogleAnalyticsAccountNumber | ua-11598035 |
>| www.filmesonlinegratis.net | 2012-03-07 05:53:50 | 2016-10-13 15:38:35 | GoogleAnalyticsTrackingId | ua-11598035-1 |
>| filmesonlinegratis.net | 2014-02-11 01:30:40 | 2016-09-13 03:54:34 | GoogleAnalyticsTrackingId | ua-11598035-1 |
>| filmesonlinegratis.net | 2014-02-11 01:30:40 | 2016-09-13 03:54:34 | GoogleAnalyticsAccountNumber | ua-11598035 |
>| www.filmesonlinegratis.net | 2016-07-02 00:46:33 | 2016-09-02 11:09:30 | TumblrId | 25.media |
>| www.filmesonlinegratis.net | 2012-11-27 06:06:44 | 2015-09-26 05:52:23 | FacebookId | filmesog |
>| filmesonlinegratis.net | 2014-02-11 01:30:40 | 2015-09-24 05:12:39 | FacebookId | filmesog |
>| www.filmesonlinegratis.net | 2012-03-07 05:53:50 | 2012-03-07 16:00:45 | WhosAmungUsId | 6cdg |


### pt-get-pdns-details

***
Retrieves the passive DNS results from active account sources.


#### Base Command

`pt-get-pdns-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The domain or IP being queried. | Required | 
| start | Filter for records whose last seen is after this datetime. It accepts "yyyy-mm-dd hh:mm:ss" or "yyyy-mm-dd" format. | Optional | 
| end | Filter for records whose first seen is before this datetime. It accepts "yyyy-mm-dd hh:mm:ss" or "yyyy-mm-dd" format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.PDNS.resolve | String | The host or ip address that indicates resolve in Passive DNS record. | 
| PassiveTotal.PDNS.resolveType | String | The type of the resolve. I.e domain, ip, host, etc. | 
| PassiveTotal.PDNS.value | String | The value of the Passive DNS record. | 
| PassiveTotal.PDNS.source | String | Source of the passive DNS records. | 
| PassiveTotal.PDNS.firstSeen | String | First seen timestamp of the passive DNS record. | 
| PassiveTotal.PDNS.lastSeen | String | Last seen timestamp of the passive DNS record. | 
| PassiveTotal.PDNS.collected | String | The date when a passive DNS record is collected. | 
| PassiveTotal.PDNS.recordType | String | The type of the passive DNS record. I.e CNAME, SOA, A, etc | 
| PassiveTotal.PDNS.recordHash | String | The hash value of the passive DNS record. | 
| Domain.Name | String | The domain name, for example: 'google.com'. | 
| IP.Address | String | The IP Address of the component. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 


#### Command Example

```!pt-get-pdns-details query=www.furth.com.ar```

#### Context Example

```
{
    "DBotScore": [
        {
            "Indicator": "furth.com.ar",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        },
        {
            "Indicator": "77.81.241.5",
            "Score": 0,
            "Type": "ip",
            "Vendor": "PassiveTotal"
        },
        {
            "Indicator": "184.75.255.33",
            "Score": 0,
            "Type": "ip",
            "Vendor": "PassiveTotal"
        }
    ],
    "Domain": {
        "Name": "furth.com.ar"
    },
    "IP": [
        {
            "Address": "77.81.241.5"
        },
        {
            "Address": "184.75.255.33"
        }
    ],
    "PassiveTotal": {
        "PDNS": [
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2010-12-15 09:10:10",
                "lastSeen": "2020-06-17 05:26:33",
                "recordHash": "abf781b2484ea79d521cffb0745b71319d4db1158f71bb019b41077f8e55b035",
                "recordType": "CNAME",
                "resolve": "furth.com.ar",
                "resolveType": "domain",
                "source": [
                    "riskiq",
                    "pingly"
                ],
                "value": "www.furth.com.ar"
            },
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2020-05-29 03:57:44",
                "lastSeen": "2020-06-17 05:26:33",
                "recordHash": "d7183564ca617e173fc26aeff66a38bb5c1b9089e56819851183860b9a37ccca",
                "recordType": "A",
                "resolve": "77.81.241.5",
                "resolveType": "ip",
                "source": [
                    "riskiq",
                    "pingly"
                ],
                "value": "www.furth.com.ar"
            },
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2016-01-11 15:45:15",
                "lastSeen": "2017-10-24 08:53:52",
                "recordHash": "345780dcde96f0c28e3b93ec53bd33067f26075f30c2d4e49fafe0d2396194ca",
                "recordType": "A",
                "resolve": "184.75.255.33",
                "resolveType": "ip",
                "source": [
                    "riskiq"
                ],
                "value": "www.furth.com.ar"
            },
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2020-06-17 05:26:33",
                "lastSeen": "2020-06-17 05:26:33",
                "recordHash": "63deb7c38cbea98f631777fd3ba89de0c270178bd37eb6a270ee7e37b3cd92e5",
                "recordType": "SOA",
                "resolve": "webmaster@furth.com.ar",
                "resolveType": "email",
                "source": [
                    "pingly"
                ],
                "value": "www.furth.com.ar"
            },
            {
                "collected": "2020-06-17 12:26:33",
                "firstSeen": "2020-06-17 05:26:33",
                "lastSeen": "2020-06-17 05:26:33",
                "recordHash": "24fa99da36eecc22b8970a33f8adf0f150598391319df4fc02128d677999e886",
                "recordType": "MX",
                "resolve": "furth.com.ar",
                "resolveType": "domain",
                "source": [
                    "pingly"
                ],
                "value": "www.furth.com.ar"
            }
        ]
    }
}
```

#### Human Readable Output

>### Total Retrieved Record(s): 5

>### PDNS detail(s)

>|Resolve|Resolve Type|Record Type|Collected (GMT)|First (GMT)|Last (GMT)|Source|Record Hash|
>|---|---|---|---|---|---|---|---|
>| furth.com.ar | domain | CNAME | 2020-06-17 12:26:33 | 2010-12-15 09:10:10 | 2020-06-17 05:26:33 | riskiq, pingly | abf781b2484ea79d521cffb0745b71319d4db1158f71bb019b41077f8e55b035 |
>| 77.81.241.5 | ip | A | 2020-06-17 12:26:33 | 2020-05-29 03:57:44 | 2020-06-17 05:26:33 | riskiq, pingly | d7183564ca617e173fc26aeff66a38bb5c1b9089e56819851183860b9a37ccca |
>| 184.75.255.33 | ip | A | 2020-06-17 12:26:33 | 2016-01-11 15:45:15 | 2017-10-24 08:53:52 | riskiq | 345780dcde96f0c28e3b93ec53bd33067f26075f30c2d4e49fafe0d2396194ca |
>| webmaster@furth.com.ar | email | SOA | 2020-06-17 12:26:33 | 2020-06-17 05:26:33 | 2020-06-17 05:26:33 | pingly | 63deb7c38cbea98f631777fd3ba89de0c270178bd37eb6a270ee7e37b3cd92e5 |
>| furth.com.ar | domain | MX | 2020-06-17 12:26:33 | 2020-06-17 05:26:33 | 2020-06-17 05:26:33 | pingly | 24fa99da36eecc22b8970a33f8adf0f150598391319df4fc02128d677999e886 |


### pt-ssl-cert-search

***
Retrieves SSL certificates for a given field value.


#### Base Command

`pt-ssl-cert-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | Field by which to search. <br/><br/>Allowed values: issuerSurname, subjectOrganizationName, issuerCountry, issuerOrganizationUnitName, fingerprint, subjectOrganizationUnitName, serialNumber, subjectEmailAddress, subjectCountry, issuerGivenName, subjectCommonName, issuerCommonName, issuerStateOrProvinceName, issuerProvince, subjectStateOrProvinceName, sha1, subjectStreetAddress, subjectSerialNumber, issuerOrganizationName, subjectSurname, subjectLocalityName, issuerStreetAddress, issuerLocalityName, subjectGivenName, subjectProvince, issuerSerialNumber, issuerEmailAddress | Required | 
| query | Field value for which to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.SSL.firstSeen | Number | Epoch timestamp when SSL certificate identified by the system. | 
| PassiveTotal.SSL.lastSeen | Number | The last seen epoch timestamp of the SSL certificates. | 
| PassiveTotal.SSL.fingerprint | String | A fingerprint detail from the SSL certificates.  | 
| PassiveTotal.SSL.sslVersion | Number | A version of the certificate. | 
| PassiveTotal.SSL.expirationDate | String | The expiry date of the certificate. | 
| PassiveTotal.SSL.issueDate | String | Issue date of the certificate. | 
| PassiveTotal.SSL.sha1 | String | Sha1 of the certificate. | 
| PassiveTotal.SSL.serialNumber | String | A serial number of the certificate. | 
| PassiveTotal.SSL.issuerCountry | String | The country name of the certificate issuer. | 
| PassiveTotal.SSL.issuerStateOrProvinceName | String | The state or province name of the certificate issuer. | 
| PassiveTotal.SSL.issuerCommonName | String | The common name of the issuer. | 
| PassiveTotal.SSL.issuerEmailAddress | String | A contact email address of the certificate issuer. | 
| PassiveTotal.SSL.issuerProvince | String | A province of the certificate issuer. | 
| PassiveTotal.SSL.issuerOrganizationUnitName | String | An organization unit name of the certificate issuer. | 
| PassiveTotal.SSL.issuerSurname | String | The surname of the certificate issuer. | 
| PassiveTotal.SSL.issuerStreetAddress | String | Street address of the certificate issuer. | 
| PassiveTotal.SSL.issuerLocalityName | String | The locality of the certificate issuer. | 
| PassiveTotal.SSL.issuerSerialNumber | String | The serial number of the certificate issuer. | 
| PassiveTotal.SSL.issuerOrganizationName | String | An organization name of the certificate issuer. | 
| PassiveTotal.SSL.issuerGivenName | String | A given name of the certificate issuer. | 
| PassiveTotal.SSL.subjectCommonName | String | The common name of the subject. | 
| PassiveTotal.SSL.subjectOrganizationName | String | An organization name of the subject of the certificate. | 
| PassiveTotal.SSL.subjectOrganizationUnitName | String | An organization unit name of the subject of the certificate. | 
| PassiveTotal.SSL.subjectGivenName | String | The given name of the subject of the certificate. | 
| PassiveTotal.SSL.subjectSurname | String | The surname of the subject of the certificate. | 
| PassiveTotal.SSL.subjectLocalityName | String | The locality of the subject. | 
| PassiveTotal.SSL.subjectEmailAddress | String | A contact email address of the subject. | 
| PassiveTotal.SSL.subjectProvince | String | The province of the subject. | 
| PassiveTotal.SSL.subjectStateOrProvinceName | String | The state or province name of the subject. | 
| PassiveTotal.SSL.subjectSerialNumber | String | A serial number of the subject. | 
| PassiveTotal.SSL.subjectStreetAddress | String | The street address of the subject. | 
| PassiveTotal.SSL.subjectCountry | String | The country name of the subject from the certificate. | 
| PassiveTotal.SSL.subjectAlternativeNames | String | Alternative names of the subject from the certificate details. | 


#### Command Example

```!pt-ssl-cert-search field=serialNumber query=61135c80f8ed28d2```

#### Context Example

```
{
    "PassiveTotal": {
        "SSL": [
            {
                "expirationDate": "Apr 09 13:15:00 2019 GMT",
                "fingerprint": "88:48:e8:68:b1:90:d0:fd:cb:6f:39:c3:7b:53:82:c8:7e:09:76:b0",
                "firstSeen": 1547559631314,
                "issueDate": "Jan 15 13:15:00 2019 GMT",
                "issuerCommonName": "Google Internet Authority G3",
                "issuerCountry": "US",
                "issuerOrganizationName": "Google Trust Services",
                "lastSeen": 1547607634446,
                "serialNumber": "6995036355238373586",
                "sha1": "8848e868b190d0fdcb6f39c37b5382c87e0976b0",
                "sslVersion": "3",
                "subjectAlternativeNames": [
                    "www.google.com"
                ],
                "subjectCommonName": "www.google.com",
                "subjectCountry": "US",
                "subjectLocalityName": "Mountain View",
                "subjectOrganizationName": "Google LLC",
                "subjectProvince": "California",
                "subjectStateOrProvinceName": "California"
            },
            {
                "expirationDate": "Apr 09 13:15:00 2019 GMT",
                "fingerprint": "99:5b:00:5f:44:be:53:bf:3e:59:21:90:1d:79:a9:8e:54:af:d3:29",
                "firstSeen": 1548455641692,
                "issueDate": "Jan 15 13:15:00 2019 GMT",
                "issuerCommonName": "Google Internet Authority G3",
                "issuerCountry": "US",
                "issuerOrganizationName": "Google Trust Services",
                "lastSeen": 1549571983939,
                "serialNumber": "6995036355238373586",
                "sha1": "995b005f44be53bf3e5921901d79a98e54afd329",
                "sslVersion": "3",
                "subjectAlternativeNames": [
                    "www.google.com"
                ],
                "subjectCommonName": "www.google.com",
                "subjectCountry": "US",
                "subjectLocalityName": "Mountain View",
                "subjectOrganizationName": "Google LLC",
                "subjectProvince": "California",
                "subjectStateOrProvinceName": "California"
            }
        ]
    }
}
```

#### Human Readable Output

>### Total Retrieved Record(s): 2

>### SSL certificate(s)

>|Sha1|Serial Number|Issued (GMT)|Expires (GMT)|SSL Version|First (GMT)|Last (GMT)|Issuer Common Name|Subject Common Name|Subject Alternative Names|Issuer Organization Name|Subject Organization Name|Subject Locality Name|Subject State/Province Name|Issuer Country|Subject Country|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8848e868b190d0fdcb6f39c37b5382c87e0976b0 | 6995036355238373586 | Jan 15 13:15:00 2019 GMT | Apr 09 13:15:00 2019 GMT | 3 | 2019-01-15 13:40:31 | 2019-01-16 03:00:34 | Google Internet Authority G3 | www.google.com | www.google.com | Google Trust Services | Google LLC | Mountain View | California | US | US |
>| 995b005f44be53bf3e5921901d79a98e54afd329 | 6995036355238373586 | Jan 15 13:15:00 2019 GMT | Apr 09 13:15:00 2019 GMT | 3 | 2019-01-25 22:34:01 | 2019-02-07 20:39:43 | Google Internet Authority G3 | www.google.com | www.google.com | Google Trust Services | Google LLC | Mountain View | California | US | US |


### pt-get-host-pairs

***
Retrieves the host attribute pairs related to a domain or IP address. Maximum 2000 records are fetched.


#### Base Command

`pt-get-host-pairs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Domain or IP address you want to search host-pairs for. | Required | 
| direction | The direction of searching pair records for a given domain. Valid values: children, parents. | Required | 
| start | Filter for records whose last seen is after this datetime. It accepts "yyyy-mm-dd hh:mm:ss" or "yyyy-mm-dd" format. | Optional | 
| end | Filter for records whose first seen is before this datetime. It accepts "yyyy-mm-dd hh:mm:ss" or "yyyy-mm-dd" format. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.HostPair.firstSeen | Date | The date and time when the host pair was first observed. | 
| PassiveTotal.HostPair.lastSeen | Date | The date and time when the host pair was most recently observed. | 
| PassiveTotal.HostPair.cause | String | The cause of relation between parent and child. | 
| PassiveTotal.HostPair.parent | String | The hostname of the parent of the host pair. | 
| PassiveTotal.HostPair.child | String | The hostname of the child of the host pair. | 


#### Command Example

```!pt-get-host-pairs direction=children query=ns1.furth.com.ar```

#### Context Example

```
{
    "PassiveTotal": {
        "HostPair": [
            {
                "cause": "redirect",
                "child": "furth.com.ar",
                "firstSeen": "2020-05-29 07:05:22",
                "lastSeen": "2020-06-10 11:53:23",
                "parent": "ns1.furth.com.ar"
            },
            {
                "cause": "parentPage",
                "child": "ns1.furth.com.ar",
                "firstSeen": "2020-05-02 06:47:23",
                "lastSeen": "2020-06-08 03:08:38",
                "parent": "ns1.furth.com.ar"
            }
        ]
    }
}
```

#### Human Readable Output

>### Total Retrieved Record(s): 2

>### HOST PAIRS

>|Parent Hostname|Child Hostname|First (GMT)|Last (GMT)|Cause|
>|---|---|---|---|---|
>| ns1.furth.com.ar | furth.com.ar | 2020-05-29 07:05:22 | 2020-06-10 11:53:23 | redirect |
>| ns1.furth.com.ar | ns1.furth.com.ar | 2020-05-02 06:47:23 | 2020-06-08 03:08:38 | parentPage |


### domain

***
Provides data enrichment for domains.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to enrich. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name, for example: 'google.com'. | 
| Domain.WHOIS.CreationDate | Date | The date that the domain was created. | 
| Domain.WHOIS.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.NameServers | String | Name servers of the domain. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Registrant.Email | String | The email address of the registrant. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.WHOIS.Admin.Email | String | The email address of the domain administrator. | 
| Domain.WHOIS.Admin.Name | String | The name of the domain administrator. | 
| Domain.WHOIS.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.WHOIS.Admin.Country | String | The country of the domain administrator. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example: 'GoDaddy'. | 
| Domain.WHOIS.Registrant.Email | String | The email address of the registrant. | 
| Domain.WHOIS.Registrant.Name | String | The name of the registrant. | 
| Domain.WHOIS.Registrant.Phone | String | The phone number for receiving abuse reports. | 
| Domain.WHOIS.Registrant.Country | String | The country of the registrant. | 
| PassiveTotal.Domain.domain | String | The domain name, for example: 'google.com'. | 
| PassiveTotal.Domain.registrar | String | The name of the registrar of the domain | 
| PassiveTotal.Domain.whoisServer | String | WHOIS server name where the details of domain registrations belong | 
| PassiveTotal.Domain.registered | Date | The date that the domain was registered. | 
| PassiveTotal.Domain.expiresAt | Date | The expiration date of the domain. | 
| PassiveTotal.Domain.registryUpdatedAt | Date | The date when registry was last updated. | 
| PassiveTotal.Domain.lastLoadedAt | Date | Last loaded date of WHOIS database. | 
| PassiveTotal.Domain.nameServers | String | Name servers of the domain. | 
| PassiveTotal.Domain.organization | String | The organization of the domain. | 
| PassiveTotal.Domain.name | String | Name of the domain. | 
| PassiveTotal.Domain.telephone | String | Telephone number fetched from whois details of the domain. | 
| PassiveTotal.Domain.contactEmail | String | Contact Email address of the domain owner | 
| PassiveTotal.Domain.registrantEmail | String | The name of the domain registrant. | 
| PassiveTotal.Domain.registrantFax | String | The fax number of the domain registrant. | 
| PassiveTotal.Domain.registrantName | String | The name of the domain registrant. | 
| PassiveTotal.Domain.registrantOrganization | String | The organizations of the domain registrant. | 
| PassiveTotal.Domain.registrantStreet | String | The street of the domain registrant. | 
| PassiveTotal.Domain.registrantCity | String | The city of the domain registrant. | 
| PassiveTotal.Domain.registrantState | String | The state of the domain registrant. | 
| PassiveTotal.Domain.registrantPostalCode | String | The postal code of the domain registrant. | 
| PassiveTotal.Domain.registrantCountry | String | The country of the domain registrant. | 
| PassiveTotal.Domain.registrantTelephone | String | The telephone number of the domain registrant. | 
| PassiveTotal.Domain.adminEmail | String | The email address of the domain administrator. | 
| PassiveTotal.Domain.adminFax | String | The fax number of the domain administrator. | 
| PassiveTotal.Domain.adminName | String | The name of the domain administrator. | 
| PassiveTotal.Domain.adminOrganization | String | The organizations of the domain administrator. | 
| PassiveTotal.Domain.adminStreet | String | The street of the domain administrator. | 
| PassiveTotal.Domain.adminCity | String | The city of the domain administrator. | 
| PassiveTotal.Domain.adminState | String | The state of the domain administrator. | 
| PassiveTotal.Domain.adminPostalCode | String | The postal code of the domain administrator. | 
| PassiveTotal.Domain.adminCountry | String | The country of the domain administrator. | 
| PassiveTotal.Domain.adminTelephone | String | The telephone number of the domain administrator. | 
| PassiveTotal.Domain.billingEmail | String | The email address of the domain billing. | 
| PassiveTotal.Domain.billingFax | String | The fax number of the domain billing. | 
| PassiveTotal.Domain.billingName | String | The name of the domain billing. | 
| PassiveTotal.Domain.billingOrganization | String | The organizations of the domain billing. | 
| PassiveTotal.Domain.billingStreet | String | The street of the domain billing. | 
| PassiveTotal.Domain.billingCity | String | The city of the domain billing. | 
| PassiveTotal.Domain.billingState | String | The state of the domain billing. | 
| PassiveTotal.Domain.billingPostalCode | String | The postal code of the domain billing. | 
| PassiveTotal.Domain.billingCountry | String | The country of the domain billing. | 
| PassiveTotal.Domain.billingTelephone | String | The telephone number of the domain billing. | 
| PassiveTotal.Domain.techEmail | String | The email address of the domain tech. | 
| PassiveTotal.Domain.techFax | String | The fax number of the domain tech. | 
| PassiveTotal.Domain.techName | String | The name of the domain tech. | 
| PassiveTotal.Domain.techOrganization | String | The organizations of domain tech. | 
| PassiveTotal.Domain.techStreet | String | The street of the domain tech. | 
| PassiveTotal.Domain.techCity | String | The city of the domain tech. | 
| PassiveTotal.Domain.techState | String | The state of the domain tech. | 
| PassiveTotal.Domain.techPostalCode | String | The postal code of the domain tech. | 
| PassiveTotal.Domain.techCountry | String | The country of the domain tech. | 
| PassiveTotal.Domain.techTelephone | String | The telephone number of the domain tech. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual DBot score. |
| PassiveTotal.Domain.score | Number | Reputation score of the indicator. |
| PassiveTotal.Domain.classification | String | Reputation classification of the indicator. (Can be GOOD, SUSPICIOUS, MALICIOUS, or UNKNOWN) |
| PassiveTotal.Domain.rules.name | String | Name of the rule that informed the reputation score of the indicator. |
| PassiveTotal.Domain.rules.description | String | Description of the rule. |
| PassiveTotal.Domain.rules.severity | Number | Severity of the rule. |
| PassiveTotal.Domain.rules.link | String | Link to the rule. |


#### Command Example

```!domain domain=riskiq.com```

#### Context Example

```
{
    "DBotScore": [
        {
            "Indicator": "riskiq.com",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        }
    ],
    "Domain": [
        {
            "Admin": {
                "Country": "us",
                "Email": "domains@riskiq.com",
                "Name": "Risk IQ",
                "Phone": "18884154447"
            },
            "CreationDate": "2006-01-11T16:00:00.000-0800",
            "ExpirationDate": "2017-01-11T16:00:00.000-0800",
            "Name": "riskiq.com",
            "NameServers": [
                "luke.ns.cloudflare.com",
                "serena.ns.cloudflare.com"
            ],
            "Organization": "RiskIQ, Inc.",
            "Registrant": {
                "Country": "us",
                "Email": "domains@riskiq.com",
                "Name": "Risk IQ",
                "Phone": "18884154447"
            },
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "GODADDY.COM, LLC"
            },
            "UpdatedDate": "2014-12-08T16:00:00.000-0800",
            "WHOIS": {
                "Admin": {
                    "Country": "us",
                    "Email": "domains@riskiq.com",
                    "Name": "Risk IQ",
                    "Phone": "18884154447"
                },
                "CreationDate": "2006-01-11T16:00:00.000-0800",
                "ExpirationDate": "2017-01-11T16:00:00.000-0800",
                "NameServers": [
                    "luke.ns.cloudflare.com",
                    "serena.ns.cloudflare.com"
                ],
                "Registrant": {
                    "Country": "us",
                    "Email": "domains@riskiq.com",
                    "Name": "Risk IQ",
                    "Phone": "18884154447"
                },
                "Registrar": {
                    "AbuseEmail": null,
                    "AbusePhone": null,
                    "Name": "GODADDY.COM, LLC"
                },
                "UpdatedDate": "2014-12-08T16:00:00.000-0800"
            }
        }
    ],
    "PassiveTotal": {
        "Domain": {
            "adminCity": "san francisco",
            "adminCountry": "us",
            "adminEmail": "domains@riskiq.com",
            "adminName": "Risk IQ",
            "adminOrganization": "RiskIQ, Inc.",
            "adminPostalCode": "94111",
            "adminState": "california",
            "adminStreet": "22 Battery Street\n10th Floor",
            "adminTelephone": "18884154447",
            "contactEmail": "domains@riskiq.com",
            "domain": "riskiq.com",
            "expiresAt": "2017-01-11T16:00:00.000-0800",
            "lastLoadedAt": "2016-09-27T09:40:31.180-0700",
            "name": "Risk IQ",
            "nameServers": [
                "luke.ns.cloudflare.com",
                "serena.ns.cloudflare.com"
            ],
            "organization": "RiskIQ, Inc.",
            "registered": "2006-01-11T16:00:00.000-0800",
            "registrantCity": "san francisco",
            "registrantCountry": "us",
            "registrantEmail": "domains@riskiq.com",
            "registrantName": "Risk IQ",
            "registrantOrganization": "RiskIQ, Inc.",
            "registrantPostalCode": "94111",
            "registrantState": "california",
            "registrantStreet": "22 Battery Street\n10th Floor",
            "registrantTelephone": "18884154447",
            "registrar": "GODADDY.COM, LLC",
            "registryUpdatedAt": "2014-12-08T16:00:00.000-0800",
            "techCity": "san francisco",
            "techCountry": "us",
            "techEmail": "domains@riskiq.com",
            "techName": "Risk IQ",
            "techOrganization": "RiskIQ, Inc.",
            "techPostalCode": "94111",
            "techState": "california",
            "techStreet": "22 Battery Street\n10th Floor",
            "techTelephone": "18884154447",
            "telephone": "18884154447",
            "whoisServer": "whois.godaddy.com",
            "score": 3,
            "classification": "UNKNOWN",
              "rules": [
                {
                  "name": "Open ports observed",
                  "description": "The number of open ports may indicate maliciousness",
                  "severity": 3
                }
              ]
        }
    }
}
```

#### Human Readable Output

>### Domain(s)

>|Domain|WHOIS Server|Registrar|Contact Email|Name Servers|Registrant|Admin|Tech|Creation Date (GMT)|Expire Date (GMT)|Updated Date (GMT)|Last Scanned (GMT)|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| riskiq.com | whois.godaddy.com | GODADDY.COM, LLC | domains@riskiq.com | luke.ns.cloudflare.com, serena.ns.cloudflare.com | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | 2006-01-11T16:00:00.000-0800 | 2017-01-11T16:00:00.000-0800 | 2014-12-08T16:00:00.000-0800 | 2016-09-27T09:40:31.180-0700 |
>The reputation score for 'riskiq.com' is 3 and is classified as 'UNKNOWN'.

>### Reputation Rules

>|Name|Description|Severity|
>|---|---|---|
>| Open ports observed | The number of open ports may indicate maliciousness | 3 |

### pt-get-services

***
Retrieves exposed services on the recently open ports for an IP address.

#### Base Command

`pt-get-services`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address for which the user wants to search services for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Service.ip | String | IP address of the service. | 
| PassiveTotal.Service.portNumber | Number | Port number on which recent services were running or current services are running. | 
| PassiveTotal.Service.firstSeen | Date | The date and time when the service was started for the first time on the port. | 
| PassiveTotal.Service.lastSeen | Date | The date and time when the service was most recently used on the port. | 
| PassiveTotal.Service.lastScan | Date | The date and time when the system performed the last scan to check whether any service is running on the port or not. | 
| PassiveTotal.Service.count | Number | The total number of times service was used on the port. | 
| PassiveTotal.Service.status | String | The status of the service. | 
| PassiveTotal.Service.protocol | String | The protocol used by the service. | 
| PassiveTotal.Service.banners.banner | String | The description of the banner generated as a result of scanning. Can be in HTML format. | 
| PassiveTotal.Service.banners.scanType | String | The type of scan when the banner was generated. | 
| PassiveTotal.Service.banners.firstSeen | Date | The date and time when the scan started. | 
| PassiveTotal.Service.banners.lastSeen | Date | The date and time when the scan ended. | 
| PassiveTotal.Service.banners.count | Number | The total number of times the same label was generated while scanning. | 
| PassiveTotal.Service.currentServices.firstSeen | Date | The date and time when the current service started. | 
| PassiveTotal.Service.currentServices.lastSeen | Date | The date and time when the current service was most recently used. | 
| PassiveTotal.Service.currentServices.version | String | The version of the current service. | 
| PassiveTotal.Service.currentServices.category | String | The category of the current service. | 
| PassiveTotal.Service.currentServices.label | String | The label of the current service. | 
| PassiveTotal.Service.recentServices.firstSeen | Date | The date and time when the recent service started. | 
| PassiveTotal.Service.recentServices.lastSeen | Date | The date and time when the recent service was most recently used. | 
| PassiveTotal.Service.recentServices.version | String | The version of the recent service. | 
| PassiveTotal.Service.recentServices.category | String | The category of the recent service. | 
| PassiveTotal.Service.recentServices.label | String | The label of the recent service. | 
| PassiveTotal.Service.mostRecentSslCert.firstSeen | Date | The timestamp in epoch when the most recent SSL certificate was identified by the system. | 
| PassiveTotal.Service.mostRecentSslCert.lastSeen | Date | The timestamp in epoch when the most recent SSL certificate was last used. | 
| PassiveTotal.Service.mostRecentSslCert.fingerprint | String | A fingerprint detail from the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.sslVersion | String | The version of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.expirationDate | Date | The expiry date and time  of the most recent SSL certificate in GMT. | 
| PassiveTotal.Service.mostRecentSslCert.issueDate | Date | The date and time in GMT when the most recent SSL certificate was issued. | 
| PassiveTotal.Service.mostRecentSslCert.sha1 | String | Sha1 of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.serialNumber | String | The serial Number of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectCountry | String | The name of the Country of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerCommonName | String | The common name of the issuer of most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerProvince | String | The province of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectStateOrProvinceName | String | The state or province name of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectStreetAddress | String | The street address of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerStateOrProvinceName | String | The state or province name of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectSurname | String | The surname of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerCountry | String | The country of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectLocalityName | String | The subject locality name of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectAlternativeNames | String | List of alternative names of the subject of the most recent SSL certificate. |
| PassiveTotal.Service.mostRecentSslCert.issuerOrganizationUnitName | String | The name organization unit of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerOrganizationName | String | The  organization name of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectEmailAddress | String | Email Address of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectOrganizationName | String | The organization name of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerLocalityName | String | The name of the locality of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectCommonName | String | Common name of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectProvince | String | The province of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerGivenName | String | The given name of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectOrganizationUnitName | String | Subject organization unit name of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerEmailAddress | String | The email address of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectGivenName | String | Given name of the subject of the the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.subjectSerialNumber | String | The serial number of the subject of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerStreetAddress | String | The street Address of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerSerialNumber | String | The serial number of the issuer of the most recent SSL certificate. | 
| PassiveTotal.Service.mostRecentSslCert.issuerSurname | String | The surname of the issuer of the most recent SSL certificate. | 

#### Command Example

```!pt-get-services ip=1.1.1.1```

#### Context Example

```json
{
  "PassiveTotal": {
    "Service": [
      {
        "count": 42335,
        "currentServices": [
          {
            "label": "Other Service"
          }
        ],
        "firstSeen": "2018-03-28 12:04:21",
        "ip": "1.1.1.1",
        "lastScan": "2021-03-06 02:28:14",
        "lastSeen": "2021-03-04 05:11:29",
        "portNumber": 53,
        "protocol": "UDP",
        "status": "filtered"
      },
      {
        "banners": [
          {
            "banner": "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>cloudflare</center>\r\n</body>\r\n</html>\r\n",
            "count": 3,
            "firstSeen": "2021-03-05 13:56:20",
            "lastSeen": "2021-03-06 00:20:32",
            "scanType": "http"
          }
        ],
        "count": 1386,
        "currentServices": [
          {
            "category": "Server",
            "firstSeen": "2019-06-18 13:45:42",
            "label": "CloudFlare",
            "lastSeen": "2021-03-10 07:58:44"
          },
          {
            "category": "Server",
            "firstSeen": "2020-07-09 16:19:47",
            "label": "cloudflare",
            "lastSeen": "2021-03-10 05:59:33"
          },
          {
            "category": "Server",
            "firstSeen": "2018-07-02 11:46:37",
            "label": "yunjiasu-nginx",
            "lastSeen": "2021-03-09 02:26:20"
          }
        ],
        "firstSeen": "2018-04-01 00:38:56",
        "ip": "1.1.1.1",
        "lastScan": "2021-03-06 13:27:15",
        "lastSeen": "2021-03-06 00:20:32",
        "portNumber": 80,
        "protocol": "TCP",
        "recentServices": [
          {
            "category": "Server",
            "firstSeen": "2020-03-18 20:37:06",
            "label": "BigIP",
            "lastSeen": "2021-03-05 21:31:27"
          },
          {
            "category": "Server",
            "firstSeen": "2020-06-11 11:50:49",
            "label": "F5 BIG-IP load balancer httpd",
            "lastSeen": "2021-03-05 21:31:27"
          },
          {
            "category": "Server",
            "firstSeen": "2020-10-27 12:39:22",
            "label": "OpenResty web app server",
            "lastSeen": "2021-02-27 19:59:14"
          },
          {
            "category": "Server",
            "firstSeen": "2019-02-09 11:59:43",
            "label": "openresty",
            "lastSeen": "2021-02-27 19:59:14"
          },
          {
            "category": "Server",
            "firstSeen": "2018-08-05 00:56:16",
            "label": "Apache",
            "lastSeen": "2020-11-09 07:02:20"
          }
        ],
        "status": "open"
      },
      {
        "count": 41,
        "currentServices": [
          {
            "label": "Other Service"
          }
        ],
        "firstSeen": "2020-02-29 04:02:09",
        "ip": "1.1.1.1",
        "lastScan": "2021-03-06 06:51:11",
        "lastSeen": "2021-02-27 16:00:28",
        "portNumber": 111,
        "protocol": "UDP",
        "status": "closed"
      }
    ]
  }
}
```

#### Human Readable Output

> ### Total Retrieved Record(s) 13

> ### Services

>|Port Number|Protocol|Status|Current Service Labels|First Seen Date (GMT)|Last Seen Date (GMT)|Last Scanned Date (GMT)|
>|---|---|---|---|---|---|---|
>| 53 | UDP | filtered | Other Service | 2018-03-28 12:04:21 | 2021-03-04 05:11:29 | 2021-03-06 02:28:14 |
>| 80 | TCP | open | CloudFlare, cloudflare, yunjiasu-nginx | 2018-04-01 00:38:56 | 2021-03-06 00:20:32 | 2021-03-06 13:27:15 |
>| 111 | UDP | closed | Other Service | 2020-02-29 04:02:09 | 2021-02-27 16:00:28 | 2021-03-06 06:51:11 |

### pt-get-whois

***
Gets WHOIS information records based on queries.


#### Base Command

`pt-get-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query value to use in the request. For example: riskiq.com, 1.1.1.1 | Required | 
| history | Whether to return historical results. Valid values: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.WHOIS.domain | String | The domain name. For example: 'google.com'. | 
| PassiveTotal.WHOIS.registrar | String | The name of the registrar of the domain. | 
| PassiveTotal.WHOIS.whoisServer | String | WHOIS server name where the details of domain registrations belong. | 
| PassiveTotal.WHOIS.registered | Date | The date that the domain was registered. | 
| PassiveTotal.WHOIS.expiresAt | Date | The expiration date of the domain. | 
| PassiveTotal.WHOIS.registryUpdatedAt | Date | The date when the registry was last updated. | 
| PassiveTotal.WHOIS.lastLoadedAt | Date | Last loaded date of WHOIS database. | 
| PassiveTotal.WHOIS.nameServers | String | Name servers of the domain. | 
| PassiveTotal.WHOIS.organization | String | The organization of the domain. | 
| PassiveTotal.WHOIS.name | String | Name of the domain. | 
| PassiveTotal.WHOIS.telephone | String | Telephone number fetched from whois details of the domain. | 
| PassiveTotal.WHOIS.contactEmail | String | Contact Email address of the domain owner. | 
| PassiveTotal.WHOIS.registrantEmail | String | The name of the domain registrant. | 
| PassiveTotal.WHOIS.registrantFax | String | The fax number of the domain registrant. | 
| PassiveTotal.WHOIS.registrantName | String | The name of the domain registrant. | 
| PassiveTotal.WHOIS.registrantOrganization | String | The organizations of the domain registrant. | 
| PassiveTotal.WHOIS.registrantStreet | String | The street of the domain registrant. | 
| PassiveTotal.WHOIS.registrantCity | String | The city of the domain registrant. | 
| PassiveTotal.WHOIS.registrantState | String | The state of the domain registrant. | 
| PassiveTotal.WHOIS.registrantPostalCode | String | The postal code of the domain registrant. | 
| PassiveTotal.WHOIS.registrantCountry | String | The country of the domain registrant. | 
| PassiveTotal.WHOIS.registrantTelephone | String | The telephone number of the domain registrant. | 
| PassiveTotal.WHOIS.adminEmail | String | The email address of the domain administrator. | 
| PassiveTotal.WHOIS.adminFax | String | The fax number of the domain administrator. | 
| PassiveTotal.WHOIS.adminName | String | The name of the domain administrator. | 
| PassiveTotal.WHOIS.adminOrganization | String | The organizations of the domain administrator. | 
| PassiveTotal.WHOIS.adminStreet | String | The street of the domain administrator. | 
| PassiveTotal.WHOIS.adminCity | String | The city of the domain administrator. | 
| PassiveTotal.WHOIS.adminState | String | The state of the domain administrator. | 
| PassiveTotal.WHOIS.adminPostalCode | String | The postal code of the domain administrator. | 
| PassiveTotal.WHOIS.adminCountry | String | The country of the domain administrator. | 
| PassiveTotal.WHOIS.adminTelephone | String | The telephone number of the domain administrator. | 
| PassiveTotal.WHOIS.billingEmail | String | The email address of the domain billing. | 
| PassiveTotal.WHOIS.billingFax | String | The fax number of the domain billing. | 
| PassiveTotal.WHOIS.billingName | String | The name of the domain billing. | 
| PassiveTotal.WHOIS.billingOrganization | String | The organizations of the domain billing. | 
| PassiveTotal.WHOIS.billingStreet | String | The street of the domain billing. | 
| PassiveTotal.WHOIS.billingCity | String | The city of the domain billing. | 
| PassiveTotal.WHOIS.billingState | String | The state of the domain billing. | 
| PassiveTotal.WHOIS.billingPostalCode | String | The postal code of the domain billing. | 
| PassiveTotal.WHOIS.billingCountry | String | The country of the domain billing. | 
| PassiveTotal.WHOIS.billingTelephone | String | The telephone number of the domain billing. | 
| PassiveTotal.WHOIS.techEmail | String | The email address of the domain tech. | 
| PassiveTotal.WHOIS.techFax | String | The fax number of the domain tech. | 
| PassiveTotal.WHOIS.techName | String | The name of the domain tech. | 
| PassiveTotal.WHOIS.techOrganization | String | The organizations of domain tech. | 
| PassiveTotal.WHOIS.techStreet | String | The street of the domain tech. | 
| PassiveTotal.WHOIS.techCity | String | The city of the domain tech. | 
| PassiveTotal.WHOIS.techState | String | The state of the domain tech. | 
| PassiveTotal.WHOIS.techPostalCode | String | The postal code of the domain tech. | 
| PassiveTotal.WHOIS.techCountry | String | The country of the domain tech. | 
| PassiveTotal.WHOIS.techTelephone | String | The telephone number of the domain tech. | 


#### Command Example

```!pt-get-whois query=riskiq.com```

#### Context Example

```
{
    "PassiveTotal": {
        "WHOIS": {
            "adminCity": "san francisco",
            "adminCountry": "us",
            "adminEmail": "domains@riskiq.com",
            "adminName": "Risk IQ",
            "adminOrganization": "RiskIQ, Inc.",
            "adminPostalCode": "94111",
            "adminState": "california",
            "adminStreet": "22 Battery Street\n10th Floor",
            "adminTelephone": "18884154447",
            "contactEmail": "domains@riskiq.com",
            "domain": "riskiq.com",
            "expiresAt": "2017-01-11T16:00:00.000-0800",
            "lastLoadedAt": "2016-09-27T09:40:31.180-0700",
            "name": "Risk IQ",
            "nameServers": [
                "luke.ns.cloudflare.com",
                "serena.ns.cloudflare.com"
            ],
            "organization": "RiskIQ, Inc.",
            "registered": "2006-01-11T16:00:00.000-0800",
            "registrantCity": "san francisco",
            "registrantCountry": "us",
            "registrantEmail": "domains@riskiq.com",
            "registrantName": "Risk IQ",
            "registrantOrganization": "RiskIQ, Inc.",
            "registrantPostalCode": "94111",
            "registrantState": "california",
            "registrantStreet": "22 Battery Street\n10th Floor",
            "registrantTelephone": "18884154447",
            "registrar": "GODADDY.COM, LLC",
            "registryUpdatedAt": "2014-12-08T16:00:00.000-0800",
            "techCity": "san francisco",
            "techCountry": "us",
            "techEmail": "domains@riskiq.com",
            "techName": "Risk IQ",
            "techOrganization": "RiskIQ, Inc.",
            "techPostalCode": "94111",
            "techState": "california",
            "techStreet": "22 Battery Street\n10th Floor",
            "techTelephone": "18884154447",
            "telephone": "18884154447",
            "whoisServer": "whois.godaddy.com"
        }
    }
}
```

#### Human Readable Output

>### Total Retrieved Record(s): 1

>### Associated Domains

>|Domain|WHOIS Server|Registrar|Contact Email|Name Servers|Registrant|Admin|Tech|Creation Date (GMT)|Expire Date (GMT)|Updated Date (GMT)|Last Scanned (GMT)|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| riskiq.com | whois.godaddy.com | GODADDY.COM, LLC | domains@riskiq.com | luke.ns.cloudflare.com, serena.ns.cloudflare.com | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | 2006-01-11T16:00:00.000-0800 | 2017-01-11T16:00:00.000-0800 | 2014-12-08T16:00:00.000-0800 | 2016-09-27T09:40:31.180-0700 |


### pt-get-cookies

***
Retrieves cookies addresses or hostname information based on cookie name or domain.


#### Base Command

`pt-get-cookies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_by | Search cookies information by name or domain. Valid values: 1. get addresses by cookie domain, 2. get addresses by cookie name, 3. get hosts by cookie domain, 4. get hosts by cookie name. | Required | 
| query | Name or domain of cookie the user wants to search for. | Required | 
| page | Page number for paging through results. Each page contains 2000 values. Default is 0. | Optional | 
| sort | Field to sort the results on. Valid values: last seen, first seen. Default is last seen. | Optional | 
| order | Order to return the results in. Valid values: asc, desc. Default is desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Cookie.hostname | String | The hostname/IP of the machine on which the cookie was found. | 
| PassiveTotal.Cookie.cookieName | String | The name of the cookie that was found on the host. | 
| PassiveTotal.Cookie.cookieDomain | String | The domain from which the cookie originated from. | 
| PassiveTotal.Cookie.firstSeen | Date | The date and time when the cookie was first observed. | 
| PassiveTotal.Cookie.lastSeen | Date | The date and time when the cookie was most recently observed. | 


#### Command Example

```!pt-get-cookies search_by="get hosts by cookie name" query=dummyCookie```

#### Context Example

```json
{
    "PassiveTotal": {
        "Cookie": [
            {
                "cookieDomain": "dummy.domain",
                "cookieName": "dummyCookie",
                "firstSeen": "2016-11-22 03:36:07",
                "hostname": "dummy.domain",
                "lastSeen": "2017-07-27 21:05:10"
            }
        ]
    }
}
```

#### Human Readable Output

>### Total Record(s): 1

>### Total Retrieved Record(s): 1

>### Cookies

>|Hostname|Cookie Name|Cookie Domain|First Seen Date (GMT)|Last Seen Date (GMT)|
>|---|---|---|---|---|
>| dummy.domain | dummyCookie | dummy.domain | 2019-04-02 01:53:50 | 2021-01-22 07:15:13 |


### pt-get-articles

***
Retrieves information related to articles for a specific indicator.


#### Base Command

`pt-get-articles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Indicator value to search for in articles. For example: riskiq.com, 1.1.1.1 | Required | 
| type | Type of the indicator. For example: domain, ip, url | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Article.guid | String | The global unique ID of the article. | 
| PassiveTotal.Article.title | String | The title of the article. | 
| PassiveTotal.Article.summary | String | The summary of the article. | 
| PassiveTotal.Article.type | String | The type of an article. | 
| PassiveTotal.Article.publishedDate | Date | The date and time on which the article was published. | 
| PassiveTotal.Article.link | String | The link of the article for getting more details. | 
| PassiveTotal.Article.categories | Unknown | An array of categories of the article. | 
| PassiveTotal.Article.tags | Unknown | An array of tags for the article. | 
| PassiveTotal.Article.indicators.type | String | The type of the indicator. | 
| PassiveTotal.Article.indicators.count | Number | Total number of indicators of a particular type. | 
| PassiveTotal.Article.indicators.values | Unknown | An array of values related to indicators. | 
| PassiveTotal.Article.indicators.source | String | The source of the indicator. | 


#### Command Example

```!pt-get-articles query=dummy.com```

#### Context Example

```json
{
    "PassiveTotal": {
        "Article": {
            "categories": [
                "Categories 1",
                "Categories 2"
            ],
            "guid": "12e123b1",
            "indicators": [
                {
                    "count": 1,
                    "source": "public",
                    "type": "domain",
                    "values": [
                        "dummy.com"
                    ]
                }
            ],
            "link": "https://community.riskiq.com/article/12e123b1",
            "publishedDate": "Mon Aug 29 20:00:00 VET 2016",
            "summary": "Did you know that you can get all kinds of free stuff, just by giving out your personal information? The internet is full of these fake reward scams which RiskIQ's sytems surface every hour of the day.",
            "tags": [
                "fake rewards",
                "playstation",
                "scam"
            ],
            "title": "Free PlayStations on the Internet are Probably an Online Scam",
            "type": "public"
        }
    }
}
```

#### Human Readable Output

>### Total Retrieved Record(s): 1

>### Article(s)

>|GUID|Title|Summary|Type|Tags|Categories|Article Link|Published Date (GMT)|
>|---|---|---|---|---|---|---|---|
>| 12e123b1 | Free PlayStations on the Internet are Probably an Online Scam | Did you know that you can get all kinds of free stuff, just by giving out your personal information? The internet is full of these fake reward scams which RiskIQ's sytems surface every hour of the day. | public | fake rewards, playstation, scam | Categories 1, Categories 2 | <https://community.riskiq.com/article/12e123b1> | Mon Aug 29 20:00:00 VET 2016 |


### pt-get-data-card

***
Retrieves a summary data card associated with the given query.


#### Base Command

`pt-get-data-card`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The domain, host or IP address to be queried. For example: riskiq.com, 1.1.1.1. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.DataCard.type | String | Type of the indicator. | 
| PassiveTotal.DataCard.name | String | Name of the indicator. | 
| PassiveTotal.DataCard.link | String | Link to the indicator. | 
| PassiveTotal.DataCard.netblock | String | Netblock associated with the indicator. | 
| PassiveTotal.DataCard.os | String | Operating system associated with the indicator. | 
| PassiveTotal.DataCard.organization | String | The organization of the indicator. | 
| PassiveTotal.DataCard.asn | String | Autonomous system number assigned to the indicator. | 
| PassiveTotal.DataCard.hosting_provider | String | Host provider of the indicator. | 
| PassiveTotal.DataCard.data_summary.resolutions.count | Number | Number of resolutions attached to the indicator. | 
| PassiveTotal.DataCard.data_summary.resolutions.link | String | Link of the resolutions attached to the indicator. | 
| PassiveTotal.DataCard.data_summary.services.count | Number | Number of service records for the indicator. | 
| PassiveTotal.DataCard.data_summary.services.link | String | Link to the service records of the indicator. | 
| PassiveTotal.DataCard.data_summary.certificates.count | Number | Number of certificates for the given indicator. | 
| PassiveTotal.DataCard.data_summary.certificates.link | String | Link to the certificates associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.hashes.count | Number | Number of hashes associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.hashes.link | String | Link to the hashes associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.projects.count | Number | Number of projects containing the indicator. | 
| PassiveTotal.DataCard.data_summary.projects.link | String | Number of projects containing the indicator. | 
| PassiveTotal.DataCard.data_summary.articles.count | Number | Number of articles referencing the indicator. | 
| PassiveTotal.DataCard.data_summary.articles.link | String | Link to the articles referencing the indicator. | 
| PassiveTotal.DataCard.data_summary.trackers.count | Number | Number of trackers associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.trackers.link | String | Link to the trackers associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.components.count | Number | Number of components associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.components.link | String | Link to the components associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.host_pairs.count | Number | Number of host pairs associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.host_pairs.link | String | Link to the host pairs associated with the indicator. | 
| PassiveTotal.DataCard.data_summary.reverse_dns.count | Number | Number of DNS records for the indicator. | 
| PassiveTotal.DataCard.data_summary.reverse_dns.link | String | Link to the DNS records of the indicator. | 
| PassiveTotal.DataCard.data_summary.cookies.count | Number | Number of available cookie records for the indicator. | 
| PassiveTotal.DataCard.data_summary.cookies.link | String | Link to the cookie records for the indicator. | 


#### Command Example

```!pt-get-data-card query="1.1.1.1"```

#### Context Example

```json
{
    "PassiveTotal": {
        "DataCard": {
            "asn": "AS13335 - CLOUDFLARENET",
            "data_summary": {
                "articles": {
                    "count": 0,
                    "link": "https://community.pt.com/research/1.1.1.1"
                },
                "certificates": {
                    "count": 3742,
                    "link": "https://community.pt.com/search/1.1.1.1/domaincertificates"
                },
                "components": {
                    "count": 914,
                    "link": "https://community.pt.com/search/1.1.1.1/components"
                },
                "cookies": {
                    "count": 23346,
                    "link": "https://community.pt.com/search/1.1.1.1/cookies"
                },
                "hashes": {
                    "count": 1000,
                    "link": "https://community.pt.com/search/1.1.1.1/hashes"
                },
                "host_pairs": {
                    "count": 6987,
                    "link": "https://community.pt.com/search/1.1.1.1/hostpairs"
                },
                "projects": {
                    "count": 4,
                    "link": "https://community.pt.com/search/1.1.1.1/projects"
                },
                "resolutions": {
                    "count": 1997,
                    "link": "https://community.pt.com/search/1.1.1.1/resolutions"
                },
                "reverse_dns": {
                    "count": 5,
                    "link": "https://community.pt.com/search/1.1.1.1/dns"
                },
                "services": {
                    "count": 3,
                    "link": "https://community.pt.com/search/1.1.1.1/services"
                },
                "trackers": {
                    "count": 3983,
                    "link": "https://community.pt.com/search/1.1.1.1/trackers"
                }
            },
            "hosting_provider": "Cloudflare",
            "link": "https://community.pt.com/search/1.1.1.1",
            "name": "1.1.1.1",
            "netblock": "1.1.1.0/24",
            "organization": "Cloudflare, Inc.",
            "os": "CentOS",
            "type": "IP Address"
        }
    }
}
```

#### Human Readable Output

>### Data Card Summary

>|Name|Type|Netblock|Autonomous System Number|Host Provider|Operating System|Data Card Summary|
>|---|---|---|---|---|---|---|
>| 1.1.1.1 | IP Address | 1.1.1.0/24 | AS13335 - CLOUDFLARENET | Cloudflare | CentOS | Resolutions: [1997](https://community.pt.com/search/1.1.1.1/resolutions), Services: [3](https://community.pt.com/search/1.1.1.1/services), Certificates: [3742](https://community.pt.com/search/1.1.1.1/domaincertificates), Hashes: [1000](https://community.pt.com/search/1.1.1.1/hashes), Projects: [4](https://community.pt.com/search/1.1.1.1/projects), Articles: 0, Trackers: [3983](https://community.pt.com/search/1.1.1.1/trackers), Components: [914](https://community.pt.com/search/1.1.1.1/components), Host Pairs: [6987](https://community.pt.com/search/1.1.1.1/hostpairs), Reverse Dns: [5](https://community.pt.com/search/1.1.1.1/dns), Cookies: [23346](https://community.pt.com/search/1.1.1.1/cookies) |


### pt-get-reputation

***
Gets reputation for a given domain, host or IP.


#### Base Command

`pt-get-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The domain, host or IP address to be queried. For example: riskiq.com, 1.1.1.1. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Reputation.query | String | The value of the indicator. | 
| PassiveTotal.Reputation.score | Number | Reputation score of the indicator. | 
| PassiveTotal.Reputation.classification | String | Reputation classification of the indicator. \(Can be GOOD, SUSPICIOUS, MALICIOUS, or UNKNOWN\) | 
| PassiveTotal.Reputation.rules.name | String | Name of the rule that informed the reputation score of the indicator. | 
| PassiveTotal.Reputation.rules.description | String | Description of the rule. | 
| PassiveTotal.Reputation.rules.severity | Number | Severity of the rule. | 
| PassiveTotal.Reputation.rules.link | String | Link to the rule. | 


#### Command Example

```!pt-get-reputation query="amazon.hksupd.com"```

#### Context Example

```json
{
    "PassiveTotal": {
        "Reputation": {
            "classification": "MALICIOUS",
            "query": "amazon.hksupd.com",
            "rules": [
                {
                    "description": "Vermilion Strike: Linux and Windows Re-implementation of Cobalt Strike",
                    "link": "https://community.pt.com/article/d0bf5d18",
                    "name": "RiskIQ Intel Article",
                    "severity": 5
                }
            ],
            "score": 100
        }
    }
}
```

#### Human Readable Output

>The reputation score for 'amazon.hksupd.com' is 100 and is classified as 'MALICIOUS'.

>### Reputation Rules

>|Name|Description|Severity|
>|---|---|---|
>| [RiskIQ Intel Article](https://community.pt.com/article/d0bf5d18) | Vermilion Strike: Linux and Windows Re-implementation of Cobalt Strike | 5 |


### ip

***
Checks the reputation of an IP address.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address to check. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.IP.query | String | The value of the indicator. | 
| PassiveTotal.IP.score | Number | Reputation score of the indicator. | 
| PassiveTotal.IP.classification | String | Reputation classification of the indicator. \(Can be GOOD, SUSPICIOUS, MALICIOUS, or UNKNOWN\) | 
| PassiveTotal.IP.rules.name | String | Name of the rule that informed the reputation score of the indicator. | 
| PassiveTotal.IP.rules.description | String | Description of the rule. | 
| PassiveTotal.IP.rules.severity | Number | Severity of the rule. | 
| PassiveTotal.IP.rules.link | String | Link to the rule. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | String | The IP Address. | 


#### Command Example

```!ip ip=8.8.8.8```

#### Context Example

```json
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip",
        "Vendor": "PassiveTotal v2"
    },
    "IP": {
        "Address": "8.8.8.8"
    },
    "PassiveTotal": {
        "IP": {
            "classification": "UNKNOWN",
            "query": "8.8.8.8",
            "rules": [
                {
                    "description": "The number of open ports may indicate maliciousness",
                    "name": "Open ports observed",
                    "severity": 3
                }
            ],
            "score": 3
        }
    }
}
```

#### Human Readable Output

>The reputation score for '8.8.8.8' is 3 and is classified as 'UNKNOWN'.

>### Reputation Rules

>|Name|Description|Severity|
>|---|---|---|
>| Open ports observed | The number of open ports may indicate maliciousness | 3 |


### pt-list-intel-profiles

***
Retrieves the list of all profiles.


#### Base Command

`pt-list-intel-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the ID of the profile to retrieve the specific profile.<br/><br/>Note: If 'id' argument is provided, all other arguments will be neglected. | Optional | 
| query | Filter the result based on title or aliases. . | Optional | 
| type | Filter the results based on the profile type. <br/><br/>Possible values: actor, tool, backdoor. | Optional | 
| indicator_value | Specify the indicator value to retrieve the profiles containing the given indicator.<br/><br/>Note: To retrieve the list of indicators, execute the "pt-list-intel-profile-indicators" command.<br/>When both indicator_value and query are provided, higher priority will be given to indicator_value. | Optional | 
| source | Filter the result based on the indicator source. <br/><br/>Possible values: osint, riskiq.<br/><br/>Note: Requires 'indicator_value' argument. | Optional | 
| category | Filter the result based on the indicator category. <br/><br/>Possible values: host, network.<br/><br/>Note: Requires 'indicator_value' argument. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is 1000. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.IntelProfile.id | String | ID of the intel profile. | 
| PassiveTotal.IntelProfile.title | String | Title of the intel profile. | 
| PassiveTotal.IntelProfile.link | String | Link to the intel profile. | 
| PassiveTotal.IntelProfile.osintIndicatorsCount | Number | Count of the open source intelligence indicators referencing the intel profile. | 
| PassiveTotal.IntelProfile.riskIqIndicatorsCount | Number | Count of the riskiq indicators referencing the intel profile. | 
| PassiveTotal.IntelProfile.indicators | String | Link to the indicators referencing the intel profile. | 
| PassiveTotal.IntelProfile.aliases | String | Aliases of the intel profile. | 
| PassiveTotal.IntelProfile.tags.label | String | Labels associated with the intel profile. | 
| PassiveTotal.IntelProfile.tags.countryCode | String | Country code of the tags associated with the intel profile. | 


#### Command Example

```!pt-list-intel-profiles id="apt33"```

#### Context Example

```json
{
    "PassiveTotal": {
        "IntelProfile": {
            "aliases": [
                "Elfin",
                "Magnallium",
                "Refined Kitten",
                "Holmium",
                "Cobalt Trinity"
            ],
            "id": "apt33",
            "indicators": "https://api.pt.net/pt/v2/intel-profiles/apt33/indicators",
            "link": "https://community.pt.com/intel-profiles/apt33",
            "osintIndicatorsCount": 410,
            "riskIqIndicatorsCount": 122,
            "tags": [
                {
                    "label": "Espionage"
                },
                {
                    "label": "Sabotage"
                },
                {
                    "label": "Windows"
                },
                {
                    "label": "Aviation"
                },
                {
                    "label": "Defense"
                },
                {
                    "label": "Oil & Gas"
                },
                {
                    "countryCode": "ir",
                    "label": "State Sponsored: Iran"
                },
                {
                    "countryCode": "sa",
                    "label": "Target: Saudi Arabia"
                },
                {
                    "countryCode": "us",
                    "label": "Target: USA"
                },
                {
                    "countryCode": "kr",
                    "label": "Target: South Korea"
                },
                {
                    "countryCode": "il",
                    "label": "Target: Israel"
                }
            ],
            "title": "APT33"
        }
    }
}
```

#### Human Readable Output

>### Profile(s)

>|ID|Title|Aliases|Public Indicators|RiskIQ Indicators|
>|---|---|---|---|---|
>| apt33 | APT33 | Elfin, Magnallium, Refined Kitten, Holmium, Cobalt Trinity  | 410 | 122 |


### pt-list-intel-profile-indicators

***
Retrieves the indicators for the given profile.


#### Base Command

`pt-list-intel-profile-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the ID of the profile to retrieve indicators for the specific profile.<br/><br/>Note: To retrieve the list of profile IDs, execute the "pt-list-intel-profile" command.| Required | 
| type | Filter the results based on the indicator type. <br/><br/>Possible values: certificate_sha1, domain, email, hash_md5, hash_sha256, ip, pdb_path, soa_email, url, whois_email. | Optional | 
| indicator_value | Specify the indicator value to retrieve the specific indicator. | Optional | 
| source | Filter the result based on the indicator source. <br/><br/>Possible values: osint, riskiq. | Optional | 
| category | Filter the result based on the indicator category. <br/><br/>Possible values: host, network. | Optional | 
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.IntelProfile.id | String | Profile ID containing the indicator. | 
| PassiveTotal.IntelProfile.indicator.id | String | ID of the indicator. | 
| PassiveTotal.IntelProfile.indicator.type | String | Type of the indicator. | 
| PassiveTotal.IntelProfile.indicator.value | String | Value of the indicator. | 
| PassiveTotal.IntelProfile.indicator.category | String | Category of the indicator. | 
| PassiveTotal.IntelProfile.indicator.firstSeen | String | Date &amp; time the record was first seen. | 
| PassiveTotal.IntelProfile.indicator.lastSeen | String | Date &amp; time the record was most recently observed. | 
| PassiveTotal.IntelProfile.indicator.osint | String | Whether the indicator was published in open source intelligence articles. | 
| PassiveTotal.IntelProfile.indicator.osintUrl | String | Link to the osint source of the indicator. | 
| PassiveTotal.IntelProfile.indicator.articleGuids | String | List of RiskIQ OSINT article GUIDs associated with the indicator. | 


#### Command Example

```!pt-list-intel-profile-indicators id="apt33" page_size=1```

#### Context Example

```json
{
    "PassiveTotal": {
        "IntelProfile": {
            "id": "apt33",
            "indicator": [
                {
                    "articleGuids": [
                        "633605c6"
                    ],
                    "category": "host",
                    "firstSeen": "2017-03-06T00:00:00.000+00:00",
                    "id": "apt33:00c417425a73db5a315d23fac8cb353f",
                    "osint": true,
                    "type": "hash_md5",
                    "value": "00c417425a73db5a315d23fac8cb353f",
                    "lastSeen": "2017-03-06T00:00:00.000+00:00"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Total Retrieved Indicator(s) 532

>### Indicator(s)

>|ID|Artifact Value|Type|First Seen (GMT)|Last Seen (GMT)|Source|
>|---|---|---|---|---|---|
>| apt33:00c417425a73db5a315d23fac8cb353f | 00c417425a73db5a315d23fac8cb353f | hash_md5 | 2017-03-06T00:00:00.000+00:00 | 2017-03-06T00:00:00.000+00:00 | OSINT |


### pt-list-my-attack-surface-insights

***
Retrieves the attack surface insight  information of the individual's account.


#### Base Command

`pt-list-my-attack-surface-insights`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| priority | Filter the results based on the priority level specified.<br/><br/>Possible values: high, medium, low. | Required | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is 1000. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Summary.Insight.name | String | The command name. | 
| PassiveTotal.Summary.Insight.activeInsightCount | Number | Total number of active insights. | 
| PassiveTotal.Summary.Insight.totalInsightCount | Number | Total number of insights. | 
| PassiveTotal.Summary.Insight.totalObservations | Number | Total number of observations. | 
| PassiveTotal.Insight.priorityLevel | String | Priority level of insights. | 
| PassiveTotal.Insight.insight.name | String | Name of the insight. | 
| PassiveTotal.Insight.insight.description | String | Description of the insight. | 
| PassiveTotal.Insight.insight.observationCount | Number | Number of observations for the given insight. | 
| PassiveTotal.Insight.insight.link | String | Link to the insight. | 
| PassiveTotal.Insight.insight.insightId | String | ID of the third party insight. | 
| PassiveTotal.Insight.insight.segmentBy | String | Segment by of the insight. | 


#### Command Example

```!pt-list-my-attack-surface-insights priority="low"```

#### Context Example

```json
{
    "PassiveTotal": {
        "Insight": {
            "insight": [
                {
                    "description": "##### Description \nThe following SSL certificates are SHA-1 certificates and are no longer recognized by web browsers due to possible hash collision.\n\n##### Remediation\nOrganizations should replace these certificates with new SSL certificate that use SHA-256.",
                    "insightId": "40466",
                    "link": "https://api.pt.net/pt/v2/attack-surface/insight/40466?page=0&size=25&groupBy=RISK_CATEGORY&segmentBy=savedfilter_metric_29630",
                    "name": "ASI: SHA-1 Certificates",
                    "observationCount": 0,
                    "segmentBy": "savedfilter_metric_29630"
                },
                {
                    "description": "##### Description \nDeprecated versions of Nginx web server that are no longer supported.  Running end of life or deprecated hardware or software can open organizations up to potential risks and vulnerabilities as these systems are no longer supported via regular updates and security patches\n\n##### Remediation\nOrganizations should consider upgrading to supported versions of Nginx to ensure security patches are available.\n",
                    "insightId": "40466",
                    "link": "https://api.pt.net/pt/v2/attack-surface/insight/40466?page=0&size=25&groupBy=RISK_CATEGORY&segmentBy=savedfilter_metric_29643",
                    "name": "ASI:  Deprecated Tech - Nginx",
                    "observationCount": 146,
                    "segmentBy": "savedfilter_metric_29643"
                }
            ],
            "priorityLevel": "low"
        },
        "Summary": {
            "Insight": {
                "activeInsightCount": 6,
                "name": "pt-list-my-attack-surface-insights",
                "totalInsightCount": 11,
                "totalObservations": 165
            }
        }
    }
}
```

#### Human Readable Output

>### Low Severity Insights

>6 Active of 11 Insights - 165 Observations
>
>|Name|Description|Observations|Insight ID|Segment By|
>|---|---|---|---|---|
>| ASI:  Deprecated Tech - Nginx | ##### Description <br/>Deprecated versions of Nginx web server that are no longer supported.  Running end of life or deprecated hardware or software can open organizations up to potential risks and vulnerabilities as these systems are no longer supported via regular updates and security patches<br/><br/>##### Remediation<br/>Organizations should consider upgrading to supported versions of Nginx to ensure security patches are available.<br/> | 146 | 40466 | savedfilter_metric_29643 |
>| ASI: SSL Certificates Expiring in 30 Days | ##### Description <br/>The following SSL Certificates expire within the next 30 days.  Expired certificates can lead to critical business functions being unavailable to customers or employees.   Expired certificates could prevent customers from accessing your website and negatively impact an organization’s brand.<br/><br/><br/>##### Remediation<br/>Organizations should review these certificates and ensure appropriate policies and procedures are in place to keep SSL certificates up to date. | 13 | 40466 | savedfilter_metric_29632 |


### pt-list-my-attack-surfaces

***
Retrieves the attack surface information of the individual's account.


#### Base Command

`pt-list-my-attack-surfaces`

#### Input


| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is 1000. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.AttackSurface.id | Number | ID of the attack surface. | 
| PassiveTotal.AttackSurface.name | String | Name of the attack surface. | 
| PassiveTotal.AttackSurface.priority.high.observationCount | Number | Total observations of high priority attack surface. | 
| PassiveTotal.AttackSurface.priority.high.link | String | Link to the high priority attack surface. | 
| PassiveTotal.AttackSurface.priority.medium.observationCount | Number | Total observations of medium priority attack surface. | 
| PassiveTotal.AttackSurface.priority.medium.link | String | Link to the medium priority attack surface. | 
| PassiveTotal.AttackSurface.priority.low.observationCount | Number | Total observations of low priority attack surface. | 
| PassiveTotal.AttackSurface.priority.low.link | String | Link to the low priority attack surface. | 


#### Command Example

```!pt-list-my-attack-surfaces```

#### Context Example

```json
{
    "PassiveTotal": {
        "AttackSurface": {
            "id": 88256,
            "name": "RiskIQ, Inc.",
            "priority": {
                "high": {
                    "link": "https://api.pt.net/pt/v2/attack-surface/priority/high",
                    "observationCount": 13
                },
                "low": {
                    "link": "https://api.pt.net/pt/v2/attack-surface/priority/low",
                    "observationCount": 165
                },
                "medium": {
                    "link": "https://api.pt.net/pt/v2/attack-surface/priority/medium",
                    "observationCount": 4
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Attack Surface(s)

>|ID|Name|High Severity|Medium Severity|Low Severity|
>|---|---|---|---|---|
>| 88256 | [RiskIQ, Inc.](https://community.pt.com/attack-surfaces/88256) | 13 observations | 4 observations | 165 observations |


### pt-list-third-party-attack-surface

***
Retrieves the attack surface observations by severity level for the given third-party account.


#### Base Command

`pt-list-third-party-attack-surface`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the vendor ID to retrieve the attack surface third party information. | Optional | 
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.ThirdParty.id | Number | ID of the vendor. | 
| PassiveTotal.ThirdParty.name | String | Name of the vendor. | 
| PassiveTotal.ThirdParty.priority.high.observationCount | Number | Total observations of high priority attack surface. | 
| PassiveTotal.ThirdParty.priority.high.link | String | Link to the high priority attack surface. | 
| PassiveTotal.ThirdParty.priority.medium.observationCount | Number | Total observations of medium priority attack surface. | 
| PassiveTotal.ThirdParty.priority.medium.link | String | Link to the medium priority attack surface. | 
| PassiveTotal.ThirdParty.priority.low.observationCount | Number | Total observations of low priority attack surface. | 
| PassiveTotal.ThirdParty.priority.low.link | String | Link to the low priority attack surface. | 
| PassiveTotal.Summary.ThirdPartyASI.name | String | The command name. | 
| PassiveTotal.Summary.ThirdPartyASI.totalCount | Number | Total number of attack surfaces. | 
| PassiveTotal.Summary.ThirdPartyASI.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.ThirdPartyASI.nextPage | String | Link to the next page. | 


#### Command Example

```!pt-list-third-party-attack-surface```

#### Context Example

```json
{
    "PassiveTotal": {
        "Summary": {
            "ThirdPartyASI": {
                "name": "pt-list-third-party-attack-surface",
                "totalCount": 2,
                "totalPages": 1
            }
        },
        "ThirdParty": [
            {
                "id": 45998,
                "name": "Mitsubishi Corporation",
                "priority": {
                    "high": {
                        "link": "https://api.pt.net/pt/v2/attack-surface/third-party/45998/priority/high",
                        "observationCount": 3
                    },
                    "low": {
                        "link": "https://api.pt.net/pt/v2/attack-surface/third-party/45998/priority/low",
                        "observationCount": 92
                    },
                    "medium": {
                        "link": "https://api.pt.net/pt/v2/attack-surface/third-party/45998/priority/medium",
                        "observationCount": 35
                    }
                }
            },
            {
                "id": 371662,
                "name": "Aeroflot-Russian Airlines",
                "priority": {
                    "high": {
                        "link": "https://api.pt.net/pt/v2/attack-surface/third-party/371662/priority/high",
                        "observationCount": 7
                    },
                    "low": {
                        "link": "https://api.pt.net/pt/v2/attack-surface/third-party/371662/priority/low",
                        "observationCount": 16
                    },
                    "medium": {
                        "link": "https://api.pt.net/pt/v2/attack-surface/third-party/371662/priority/medium",
                        "observationCount": 8
                    }
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Attack Surface(s)

>|ID|Name|High Severity|Medium Severity|Low Severity|
>|---|---|---|---|---|
>| 45998 | [Mitsubishi Corporation](https://community.pt.com/attack-surfaces/45998) | 3 observations | 35 observations | 92 observations |
>| 371662 | [Aeroflot-Russian Airlines](https://community.pt.com/attack-surfaces/371662) | 7 observations | 8 observations | 16 observations |


### pt-list-third-party-attack-surface-insights

***
Retrieves the attack surface insight information of the given third-party account.


#### Base Command

`pt-list-third-party-attack-surface-insights`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the vendor ID to retrieve the third-party insights information.<br/><br/>Note: To retrieve the list of vendor IDs, execute the "pt-list-third-party-attack-surface" command. | Required | 
| priority | Filter the results based on the priority level specified.<br/><br/>Possible values: high, medium, low. | Required | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is 1000. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Summary.ThirdPartyInsight.activeInsightCount | Number | Total number of active third party insights. | 
| PassiveTotal.Summary.ThirdPartyInsight.totalInsightCount | Number | Total number of third party insights. | 
| PassiveTotal.Summary.ThirdPartyInsight.totalObservations | Number | Total number of third party observations. | 
| PassiveTotal.ThirdParty.id | Number | Vendor ID associated with the third party insights. | 
| PassiveTotal.ThirdParty.priorityLevel | String | Priority level of third party insights. | 
| PassiveTotal.ThirdParty.Insight.insight.name | String | Name of the third party insight. | 
| PassiveTotal.ThirdParty.Insight.insight.description | String | Description of the third party insight. | 
| PassiveTotal.ThirdParty.Insight.insight.observationCount | Number | Number of observations for the given third party insight. | 
| PassiveTotal.ThirdParty.Insight.insight.link | String | Link to the third party insight. | 
| PassiveTotal.ThirdParty.Insight.insight.insightId | String | ID of the third party insight. | 
| PassiveTotal.ThirdParty.Insight.insight.segmentBy | String | Segment by of the third party insight. | 
| PassiveTotal.Summary.ThirdPartyInsight.name | String | The command name. | 


#### Command Example

```!pt-list-third-party-attack-surface-insights id="45998" priority="low"```

#### Context Example

```json
{
    "PassiveTotal": {
        "Summary": {
            "ThirdPartyInsight": {
                "activeInsightCount": 9,
                "name": "pt-list-third-party-attack-surface-insights",
                "totalInsightCount": 11,
                "totalObservations": 92
            }
        },
        "ThirdParty": {
            "Insight": {
                "insight": [
                    {
                        "description": "Root page assets with any CVSS/CVSS v3 score. ",
                        "insightId": "40466",
                        "link": "https://api.pt.net/pt/v2/attack-surface/third-party/45998/insight/40466?page=0&size=25&groupBy=RISK_CATEGORY&segmentBy=savedfilter_metric_15881",
                        "name": "Affected CVSS Page",
                        "observationCount": 0,
                        "segmentBy": "savedfilter_metric_15881"
                    },
                    {
                        "description": "##### Description \nDeprecated versions of Apache server that are no longer supported.  Running end of life or deprecated software can open organizations up to potential risks and vulnerabilities as these systems are no longer supported via regular updates and security patches.\n\n##### Remediation\nOrganizations should consider upgrading to supported versions of Apache to ensure security patches are available.",
                        "insightId": "40466",
                        "link": "https://api.pt.net/pt/v2/attack-surface/third-party/45998/insight/40466?page=0&size=25&groupBy=RISK_CATEGORY&segmentBy=savedfilter_metric_29644",
                        "name": "ASI: Deprecated Tech - Apache",
                        "observationCount": 2,
                        "segmentBy": "savedfilter_metric_29644"
                    }
                ]
            },
            "id": 45998,
            "priorityLevel": "low"
        }
    }
}
```

#### Human Readable Output

>### Low Severity Insights

>9 Active of 11 Insights - 92 Observations
>
>|Name|Description|Observations|Insight ID|Segment By|
>|---|---|---|---|---|
>| ASI: Deprecated Tech - Apache | ##### Description <br/>Deprecated versions of Apache server that are no longer supported.  Running end of life or deprecated software can open organizations up to potential risks and vulnerabilities as these systems are no longer supported via regular updates and security patches.<br/><br/>##### Remediation<br/>Organizations should consider upgrading to supported versions of Apache to ensure security patches are available. | 2 | 40466 | savedfilter_metric_29644 |
>| Affected CVSS Page | Root page assets with any CVSS/CVSS v3 score.  | 0 | 40466 | savedfilter_metric_15881 |

### pt-list-my-attack-surface-assets

***
Retrieves the attack surface asset information of the individual's account.


#### Base Command

`pt-list-my-attack-surface-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the insight ID to retrieve the assets.<br/><br/>Note: To retrieve the list of insight IDs, execute the "pt-list-my-attack-surface-insights" command. | Required | 
| segment_by | Specify the segment_by to retrieve the assets.<br/><br/>Note: To retrieve the list of segment by, execute the "pt-list-my-attack-surface-insights" command. | Required | 
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Summary.Asset.totalCount | Number | Total number of available assets. | 
| PassiveTotal.Summary.Asset.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.Asset.nextPage | String | Link to the next page. | 
| PassiveTotal.Asset.insightId | String | Insight ID for which assets are retrieved. | 
| PassiveTotal.Asset.segmentBy | String | Segment by for which assets are retrieved. | 
| PassiveTotal.Asset.asset.type | String | Type of the asset. | 
| PassiveTotal.Asset.asset.name | String | Name of the asset. | 
| PassiveTotal.Asset.asset.firstSeen | Date | Date &amp; time the record was first seen. | 
| PassiveTotal.Asset.asset.lastSeen | Date | Date &amp; time the record was most recently observed. | 
| PassiveTotal.Summary.Asset.name | String | The command name. | 


#### Command Example

```!pt-list-my-attack-surface-assets id="40466" segment_by="savedfilter_metric_29634"```

#### Context Example

```json
{
    "PassiveTotal": {
        "Asset": {
            "asset": [
                {
                    "firstSeen": "2016-05-25 20:07:40",
                    "lastSeen": "2021-09-19 09:50:32",
                    "name": "financialtradie.com",
                    "type": "DOMAIN"
                }
            ],
            "insightId": "40466",
            "segmentBy": "savedfilter_metric_29634"
        },
        "Summary": {
            "Asset": {
                "name": "pt-list-my-attack-surface-assets",
                "totalCount": 1,
                "totalPages": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Asset(s)

>|Name|Type|First Seen (GMT)|Last Seen (GMT)|
>|---|---|---|---|
>| financialtradie.com | DOMAIN | 2016-05-25 20:07:40 | 2021-09-19 09:50:32 |


### pt-list-my-attack-surface-vulnerable-components

***
Retrieves the attack surface vulnerable component information of the individual's account.


#### Base Command

`pt-list-my-attack-surface-vulnerable-components`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Summary.VulnerableComponent.name | String | The command name. | 
| PassiveTotal.Summary.VulnerableComponent.totalCount | Number | Total number of available vulnerable components. | 
| PassiveTotal.Summary.VulnerableComponent.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.VulnerableComponent.nextPage | String | Link to the next page. | 
| PassiveTotal.VulnerableComponent.name | String | Name of the vulnerable component. | 
| PassiveTotal.VulnerableComponent.type | String | Type of the vulnerable component. | 
| PassiveTotal.VulnerableComponent.severity | String | Severity of the vulnerable component. | 
| PassiveTotal.VulnerableComponent.count | Number | Number of assets affected. | 


#### Command Example

```!pt-list-my-attack-surface-vulnerable-components page_size=2```

#### Context Example

```json
{
    "PassiveTotal": {
        "Summary": {
            "VulnerableComponent": {
                "name": "pt-list-my-attack-surface-vulnerable-components",
                "nextPage": "https://api.pt.net/pt/v2/attack-surface/vuln-intel/components?page=1&size=2",
                "totalCount": 24,
                "totalPages": 12
            }
        },
        "VulnerableComponent": [
            {
                "count": 129,
                "name": "nginx 1.14.0",
                "severity": "HIGH",
                "type": "Server"
            },
            {
                "count": 13,
                "name": "nginx 1.16.1",
                "severity": "HIGH",
                "type": "Server"
            }
        ]
    }
}
```

#### Human Readable Output

>### Vulnerable Component(s)

>|Name|Type|Severity|Asset Count|
>|---|---|---|---|
>| nginx 1.14.0 | Server | HIGH | 129 |
>| nginx 1.16.1 | Server | HIGH | 13 |


### pt-list-my-attack-surface-vulnerabilities

***
Retrieves the attack surface vulnerability information of the individual's account.


#### Base Command

`pt-list-my-attack-surface-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Vulnerability.cveId | String | ID of the CVE. | 
| PassiveTotal.Vulnerability.cwes.cweId | String | CWE ID associated with the CVE. | 
| PassiveTotal.Vulnerability.priorityScore | Number | Priority score of the CVE. | 
| PassiveTotal.Vulnerability.observationCount | Number | Number of observations of CVE. | 
| PassiveTotal.Vulnerability.cveLink | String | Link to the CVE. | 
| PassiveTotal.Summary.Vulnerability.name | String | The command name. | 
| PassiveTotal.Summary.Vulnerability.totalCount | Number | Total number of vulnerabilities. | 
| PassiveTotal.Summary.Vulnerability.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.Vulnerability.nextPage | String | Link to the next page. | 


#### Command Example

```!pt-list-my-attack-surface-vulnerabilities page_size=2```

#### Context Example

```json
{
    "PassiveTotal": {
        "Summary": {
            "Vulnerability": {
                "name": "pt-list-my-attack-surface-vulnerabilities",
                "nextPage": "https://api.pt.net/pt/v2/attack-surface/vuln-intel/cves?page=1&size=2",
                "totalCount": 413,
                "totalPages": 207
            }
        },
        "Vulnerability": [
            {
                "cveId": "CVE-2021-23017",
                "cveLink": "https://api.pt.net/pt/v2/vuln-intel/CVE-2021-23017",
                "cwes": [
                    {
                        "cweId": "CWE-193"
                    }
                ],
                "observationCount": 149,
                "priorityScore": 98
            },
            {
                "cveId": "CVE-2019-20372",
                "cveLink": "https://api.pt.net/pt/v2/vuln-intel/CVE-2019-20372",
                "cwes": [
                    {
                        "cweId": "CWE-444"
                    }
                ],
                "observationCount": 145,
                "priorityScore": 53
            }
        ]
    }
}
```

#### Human Readable Output

>### Vulnerabilities

>|CVE ID|CWE ID|RiskIQ Priority Score|Asset Count|
>|---|---|---|---|
>| CVE-2021-23017 | CWE-193  | 98.0 | 149 |
>| CVE-2019-20372 | CWE-444  | 53.0 | 145 |


### pt-list-my-attack-surface-observations

***
Retrieves the attack surface vulnerability observation information of the individual's account.


#### Base Command

`pt-list-my-attack-surface-observations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | Specify the CVE ID to retrieve observations of that CVE.<br/><br/>Note: To retrieve the list of CVE IDs, execute the "pt-list-my-attack-surface-vulnerabilities" command. | Required | 
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.Observation.asset.type | String | Type of the asset. | 
| PassiveTotal.Observation.asset.name | String | Name of the asset. | 
| PassiveTotal.Observation.asset.firstSeen | Date | Date &amp; time the record was first seen. | 
| PassiveTotal.Observation.asset.lastSeen | Date | Date &amp; time the record was most recently observed. | 
| PassiveTotal.Observation.cveId | String | ID of the CVE. | 
| PassiveTotal.Observation.cwe.cweId | String | CWE ID associated with the CVE. | 
| PassiveTotal.Summary.Observation.name | String | The command name. | 
| PassiveTotal.Summary.Observation.totalCount | Number | Total number of vulnerabilities. | 
| PassiveTotal.Summary.Observation.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.Observation.nextPage | String | Link to the next page. | 


#### Command Example

```!pt-list-my-attack-surface-observations cve_id="CVE-2021-23017" page_size=2```

#### Context Example

```json
{
    "PassiveTotal": {
        "Observation": {
            "asset": [
                {
                    "firstSeen": "2018-05-11 20:40:17",
                    "lastSeen": "2021-09-19 14:46:48",
                    "name": "riskiq.app",
                    "type": "HOST"
                },
                {
                    "firstSeen": "2018-06-30 00:03:32",
                    "lastSeen": "2021-09-15 19:36:38",
                    "name": "www.riskiq.app",
                    "type": "HOST"
                }
            ],
            "cveId": "CVE-2021-23017",
            "cwe": [
                {
                    "cweId": "CWE-193"
                }
            ]
        },
        "Summary": {
            "Observation": {
                "name": "pt-list-my-attack-surface-observations",
                "nextPage": "https://api.pt.net/pt/v2/attack-surface/vuln-intel/cves/CVE-2021-23017/observations?page=1&size=2",
                "totalCount": 149,
                "totalPages": 75
            }
        }
    }
}
```

#### Human Readable Output

>### Observation(s)

>|Name|Type|First Seen (GMT)|Last Seen (GMT)|
>|---|---|---|---|
>| riskiq.app | HOST | 2018-05-11 20:40:17 | 2021-09-19 14:46:48 |
>| www.riskiq.app | HOST | 2018-06-30 00:03:32 | 2021-09-15 19:36:38 |


### pt-list-third-party-attack-surface-assets

***
Retrieves the attack surface asset information of the given third-party account.


#### Base Command

`pt-list-third-party-attack-surface-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the insight ID to retrieve the assets.<br/><br/>Note: To retrieve the list of insight IDs, execute the "pt-list-third-party-attack-surface-insights" command. | Required | 
| vendor_id | Specify the vendor ID to retrieve the assets of a specific vendor.<br/><br/>Note: To retrieve the list of vendor IDs, execute the "pt-list-third-party-attack-surface" command. | Required | 
| segment_by | Specify the segment_by to retrieve the assets.<br/><br/>Note: To retrieve the list of segment by, execute the "pt-list-third-party-attack-surface-insights" command. | Required | 
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.ThirdParty.id | Number | ID of the vendor. | 
| PassiveTotal.Summary.ThirdPartyInsightAsset.name | String | The command name. | 
| PassiveTotal.Summary.ThirdPartyInsightAsset.totalCount | Number | Total number of available assets. | 
| PassiveTotal.Summary.ThirdPartyInsightAsset.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.ThirdPartyInsightAsset.nextPage | String | Link to the next page. | 
| PassiveTotal.ThirdParty.InsightAsset.insightId | Number | Insight ID for which assets are retrieved. | 
| PassiveTotal.ThirdParty.InsightAsset.segmentBy | String | Segment by for which assets are retrieved. | 
| PassiveTotal.ThirdParty.InsightAsset.asset.type | String | Type of the asset. | 
| PassiveTotal.ThirdParty.InsightAsset.asset.name | String | Name of the asset. | 
| PassiveTotal.ThirdParty.InsightAsset.asset.firstSeen | Date | Date &amp; time the record was first seen. | 
| PassiveTotal.ThirdParty.InsightAsset.asset.lastSeen | Date | Date &amp; time the record was most recently observed. | 


#### Command Example

```!pt-list-third-party-attack-surface-assets id="40464" vendor_id="45998" segment_by="savedfilter_metric_29644"```

#### Context Example

```json
{
    "PassiveTotal": {
        "Summary": {
            "ThirdPartyInsightAsset": {
                "name": "pt-list-third-party-attack-surface-assets",
                "totalCount": 2,
                "totalPages": 1
            }
        },
        "ThirdParty": {
            "InsightAsset": {
                "asset": [
                    {
                        "firstSeen": "2010-06-24 07:49:19",
                        "lastSeen": "2021-09-21 23:02:08",
                        "name": "160.189.11.4",
                        "type": "IP_ADDRESS"
                    },
                    {
                        "firstSeen": "2017-12-01 09:22:21",
                        "lastSeen": "2021-09-21 18:23:10",
                        "name": "ec.soup-stock-tokyo.com",
                        "type": "HOST"
                    }
                ],
                "insightId": "40464",
                "segmentBy": "savedfilter_metric_29644"
            },
            "id": 45998
        }
    }
}
```

#### Human Readable Output

>### Asset(s)

>|Name|Type|First Seen (GMT)|Last Seen (GMT)|
>|---|---|---|---|
>| 160.189.11.4 | IP_ADDRESS | 2010-06-24 07:49:19 | 2021-09-21 23:02:08 |
>| ec.soup-stock-tokyo.com | HOST | 2017-12-01 09:22:21 | 2021-09-21 18:23:10 |


### pt-list-third-party-attack-surface-vulnerable-components

***
Retrieves the attack surface vulnerable component information of the given third-party account.


#### Base Command

`pt-list-third-party-attack-surface-vulnerable-components`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the vendor ID to retrieve the vulnerable components for a particular vendor.<br/><br/>Note: To retrieve the list of vendor IDs, execute the "pt-list-third-party-attack-surface" command. | Required | 
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.ThirdParty.id | String | ID of the vendor. | 
| PassiveTotal.Summary.ThirdPartyVulnerableComponent.name | String | The command name. | 
| PassiveTotal.Summary.ThirdPartyVulnerableComponent.totalCount | Number | Total number of available vulnerable components. | 
| PassiveTotal.Summary.ThirdPartyVulnerableComponent.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.ThirdPartyVulnerableComponent.nextPage | String | Link to the next page. | 
| PassiveTotal.ThirdParty.VulnerableComponent.name | String | Name of the vulnerable component. | 
| PassiveTotal.ThirdParty.VulnerableComponent.type | String | Type of the vulnerable component. | 
| PassiveTotal.ThirdParty.VulnerableComponent.severity | String | Severity of the vulnerable component. | 
| PassiveTotal.ThirdParty.VulnerableComponent.count | Number | Number of assets affected. | 


#### Command Example

```!pt-list-third-party-attack-surface-vulnerable-components id="45998" page_size=2```

#### Context Example

```json
{
    "PassiveTotal": {
        "Summary": {
            "ThirdPartyVulnerableComponent": {
                "name": "pt-list-third-party-attack-surface-vulnerable-components",
                "nextPage": "https://api.pt.net/pt/v2/attack-surface/vuln-intel/third-party/45998/components?page=1&size=2",
                "totalCount": 45,
                "totalPages": 23
            }
        },
        "ThirdParty": {
            "VulnerableComponent": [
                {
                    "count": 14,
                    "name": "Microsoft-IIS 8.5",
                    "severity": "MEDIUM",
                    "type": "Server"
                },
                {
                    "count": 5,
                    "name": "OpenSSL 1.0.2k",
                    "severity": "HIGH",
                    "type": "Server Module"
                }
            ],
            "id": 45998
        }
    }
}
```

#### Human Readable Output

>### Vulnerable Component(s)

>|Name|Type|Severity|Asset Count|
>|---|---|---|---|
>| Microsoft-IIS 8.5 | Server | MEDIUM | 14 |
>| OpenSSL 1.0.2k | Server Module | HIGH | 5 |


### pt-list-third-party-attack-surface-vulnerabilities

***
Retrieves the attack surface vulnerability information of the given third-party account.


#### Base Command

`pt-list-third-party-attack-surface-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the vendor ID to retrieve the vulnerabilities for a particular vendor.<br/><br/>Note: To retrieve the list of vendor IDs, execute the "pt-list-third-party-attack-surface" command. | Required | 
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.ThirdParty.id | Number | ID of the vendor. | 
| PassiveTotal.ThirdParty.Vulnerability.cveId | String | ID of the CVE. | 
| PassiveTotal.ThirdParty.Vulnerability.cwes.cweId | String | CWE ID associated with the CVE. | 
| PassiveTotal.ThirdParty.Vulnerability.priorityScore | Number | Priority score of the CVE. | 
| PassiveTotal.ThirdParty.Vulnerability.observationCount | Number | Number of observations of CVE. | 
| PassiveTotal.ThirdParty.Vulnerability.cveLink | String | Link to the CVE. | 
| PassiveTotal.Summary.ThirdPartyVulnerability.name | String | The command name. | 
| PassiveTotal.Summary.ThirdPartyVulnerability.totalCount | Number | Total number of vulnerabilities. | 
| PassiveTotal.Summary.ThirdPartyVulnerability.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.ThirdPartyVulnerability.nextPage | String | Link to the next page. | 


#### Command Example

```!pt-list-third-party-attack-surface-vulnerabilities id="45998" page_size=2```

#### Context Example

```json
{
    "PassiveTotal": {
        "Summary": {
            "ThirdPartyVulnerability": {
                "name": "pt-list-third-party-attack-surface-vulnerabilities",
                "nextPage": "https://api.pt.net/pt/v2/attack-surface/vuln-intel/third-party/45998/cves?page=1&size=2",
                "totalCount": 548,
                "totalPages": 274
            }
        },
        "ThirdParty": {
            "Vulnerability": [
                {
                    "cveId": "CVE-2020-11022",
                    "cveLink": "https://api.pt.net/pt/v2/vuln-intel/CVE-2020-11022",
                    "cwes": [
                        {
                            "cweId": "CWE-79"
                        }
                    ],
                    "observationCount": 19,
                    "priorityScore": 61
                },
                {
                    "cveId": "CVE-2020-11023",
                    "cveLink": "https://api.pt.net/pt/v2/vuln-intel/CVE-2020-11023",
                    "cwes": [
                        {
                            "cweId": "CWE-79"
                        }
                    ],
                    "observationCount": 19,
                    "priorityScore": 61
                }
            ],
            "id": 45998
        }
    }
}
```

#### Human Readable Output

>### Vulnerabilities

>|CVE ID|CWE ID|RiskIQ Priority Score|Asset Count|
>|---|---|---|---|
>| CVE-2020-11022 | CWE-79  | 61.0 | 19 |
>| CVE-2020-11023 | CWE-79  | 61.0 | 19 |


### pt-list-third-party-attack-surface-observations

***
Retrieves the attack surface vulnerability observation information of the given third-party account.


#### Base Command

`pt-list-third-party-attack-surface-observations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the vendor ID to retrieve the vulnerability observations for a particular vendor.<br/><br/>Note: To retrieve the list of vendor IDs, execute the "pt-list-third-party-attack-surface" command. | Required | 
| cve_id | Specify the CVE ID to retrieve observations of the CVE.<br/><br/>Note: To retrieve the list of CVE IDs, execute the "pt-list-third-party-attack-surface-vulnerabilities" command. | Required | 
| page_number | Page number for paging through results.<br/><br/>Note: The minimum value supported is 0 and maximum value supported is int32. Default is 0. | Optional | 
| page_size | Maximum number of results to return per page.<br/><br/>Note: The minimum value supported is 1 and maximum value supported is int32. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PassiveTotal.ThirdParty.id | Number | ID of the vendor. | 
| PassiveTotal.ThirdParty.Observation.asset.type | String | Type of the asset. | 
| PassiveTotal.ThirdParty.Observation.asset.name | String | Name of the asset. | 
| PassiveTotal.ThirdParty.Observation.asset.firstSeen | Date | Date &amp; time the record was first seen. | 
| PassiveTotal.ThirdParty.Observation.asset.lastSeen | Date | Date &amp; time the record was most recently observed. | 
| PassiveTotal.ThirdParty.Observation.cveId | String | ID of the CVE. | 
| PassiveTotal.ThirdParty.Observation.cwe.cweId | String | CWE ID associated with the CVE. | 
| PassiveTotal.Summary.ThirdPartyObservation.name | String | The command name. | 
| PassiveTotal.Summary.ThirdPartyObservation.totalCount | Number | Total number of observations. | 
| PassiveTotal.Summary.ThirdPartyObservation.totalPages | Number | Number of pages. | 
| PassiveTotal.Summary.ThirdPartyObservation.nextPage | String | Link to the next page. | 


#### Command Example

```!pt-list-third-party-attack-surface-observations id="45998" cve_id="CVE-2020-11022" page_size=2```

#### Context Example

```json
{
    "PassiveTotal": {
        "Summary": {
            "ThirdPartyObservation": {
                "name": "pt-list-third-party-attack-surface-observations",
                "nextPage": "https://api.pt.net/pt/v2/attack-surface/vuln-intel/third-party/45998/cves/CVE-2020-11022/observations?page=1&size=2",
                "totalCount": 19,
                "totalPages": 10
            }
        },
        "ThirdParty": {
            "Observation": {
                "asset": [
                    {
                        "firstSeen": "2015-05-12 14:58:34",
                        "lastSeen": "2021-09-21 06:14:39",
                        "name": "blog.accesstage.com.br",
                        "type": "HOST"
                    },
                    {
                        "firstSeen": "2010-09-22 14:57:20",
                        "lastSeen": "2021-09-22 00:21:45",
                        "name": "www.accesstage.com.br",
                        "type": "HOST"
                    }
                ],
                "cveId": "CVE-2020-11022",
                "cwe": [
                    {
                        "cweId": "CWE-79"
                    }
                ]
            },
            "id": 45998
        }
    }
}
```

#### Human Readable Output

>### Observation(s)

>|Name|Type|First Seen (GMT)|Last Seen (GMT)|
>|---|---|---|---|
>| blog.accesstage.com.br | HOST | 2015-05-12 14:58:34 | 2021-09-21 06:14:39 |
>| www.accesstage.com.br | HOST | 2010-09-22 14:57:20 | 2021-09-22 00:21:45 |