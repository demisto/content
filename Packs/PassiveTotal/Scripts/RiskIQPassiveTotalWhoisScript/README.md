Enhancement script to enrich whois information for Domain and Email type of indicators.
It can be set by following these steps:
 - Settings > ADVANCED > Indicator Type
 - Edit Domain and Email Indicator one by one 
 - Add this script into Enhancement Scripts
 
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | enhancement |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* pt-whois-search

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| indicator_value | domain or email indicator value that need to enrich |

## Outputs
---
There are no outputs for this script.


## Script Example
```!RiskIQPassiveTotalWhoisScript indicator_value=domains@riskiq.com```

## Context Example
```
{
    "DBotScore": [
        {
            "Indicator": "someone@riskiq.com",
            "Score": 0,
            "Type": "domain",
            "Vendor": "PassiveTotal"
        },
        {
            "Indicator": "domains@riskiq.com",
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
            "Name": "someone@riskiq.com",
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
        },
        {
            "Admin": {
                "Country": "us",
                "Email": "domains@riskiq.com",
                "Name": "Risk IQ",
                "Phone": "18884154447"
            },
            "CreationDate": "2006-01-11T16:00:00.000-0800",
            "ExpirationDate": "2017-01-11T16:00:00.000-0800",
            "Name": "domains@riskiq.com",
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
            "domain": "domains@riskiq.com",
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

## Human Readable Output

>### Total Retrieved Record(s): 2
>### Associated Domains
>|Domain|WHOIS Server|Registrar|Contact Email|Name Servers|Registrant|Admin|Tech|Creation Date (GMT)|Expire Date (GMT)|Updated Date (GMT)|Last Scanned (GMT)|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| someone@riskiq.com | whois.godaddy.com | GODADDY.COM, LLC | domains@riskiq.com | luke.ns.cloudflare.com, serena.ns.cloudflare.com | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | 2006-01-11T16:00:00.000-0800 | 2017-01-11T16:00:00.000-0800 | 2014-12-08T16:00:00.000-0800 | 2016-09-27T09:40:31.102-0700 |
>| domains@riskiq.com | whois.godaddy.com | GODADDY.COM, LLC | domains@riskiq.com | luke.ns.cloudflare.com, serena.ns.cloudflare.com | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | **City:** san francisco,<br/>**Country:** us,<br/>**Email:** domains@riskiq.com,<br/>**Name:** Risk IQ,<br/>**Organization:** RiskIQ, Inc.,<br/>**PostalCode:** 94111,<br/>**State:** california,<br/>**Street:** 22 Battery Street<br/>10th Floor,<br/>**Telephone:** 18884154447 | 2006-01-11T16:00:00.000-0800 | 2017-01-11T16:00:00.000-0800 | 2014-12-08T16:00:00.000-0800 | 2016-09-27T09:40:31.180-0700 |
