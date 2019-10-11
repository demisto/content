## Overview
---

This integration was integrated and tested with version xx of DomainTools Iris
## DomainTools Iris Playbook
---

## Use Cases
---

## Configure DomainTools Iris on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for DomainTools Iris.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __API Username__
    * __API Key__
    * __High-Risk Threshold__
    * __Open authentication (less secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. domain
2. domaintoolsiris-analytics
3. domaintoolsiris-threat-profile
4. domaintoolsiris-pivot
### 1. domain
---
Get a complete profile of the domain provided.
##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | Domain Name | 
| Domain.DNS | String | Domain DNS | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.Vendor | String | Domain Vendor | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.RiskScore | Number | Domain RiskScore | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | String | Domain NameServers | 
| Domain.Registrant | Unknown | Domain Registrant | 
| Domain.Malicious | Unknown | Is the Domain Malicious | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | Unknown | Description of why domain was found to be malicious | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics | Unknown | Analytics Data about the Domain from DomainTools | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore | Unknown | DomainTools Threat Profile Info | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | Unknown | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | Unknown | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Unknown | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Unknown | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | Unknown | DomainTools Tags | 
| DomainTools.Domains.Identity | Unknown | DomainTools Identity Info about the Domain | 
| DomainTools.Domains.Identity.RegistrantName | Unknown | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | Unknown | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact | Unknown | Registrant Contact Info | 
| DomainTools.Domains.Identity.RegistrantContact.Country | Unknown | Registrant Contact Country | 
| DomainTools.Domains.Identity.RegistrantContact.Email | Unknown | Registrant Contact Email | 
| DomainTools.Domains.Identity.RegistrantContact.Name | Unknown | Registrant Contact Name | 
| DomainTools.Domains.Identity.RegistrantContact.Phone | Unknown | Registrant Contact Phone | 
| DomainTools.Domains.Identity.SOAEmail | Unknown | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | Unknown | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact | Unknown | Admin Contact Info | 
| DomainTools.Domains.Identity.AdminContact.Country | Unknown | Admin Contact Country | 
| DomainTools.Domains.Identity.AdminContact.Email | Unknown | Admin Contact Email | 
| DomainTools.Domains.Identity.AdminContact.Name | Unknown | Admin Contact Name | 
| DomainTools.Domains.Identity.AdminContact.Phone | Unknown | Admin Contact Phone | 
| DomainTools.Domains.Identity.TechnicalContact | Unknown | Technical Contact Info | 
| DomainTools.Domains.Identity.TechnicalContact.Country | Unknown | Technical Contact Country | 
| DomainTools.Domains.Identity.TechnicalContact.Email | Unknown | Technical Contact Email | 
| DomainTools.Domains.Identity.TechnicalContact.Name | Unknown | Technical Contact Name | 
| DomainTools.Domains.Identity.TechnicalContact.Phone | Unknown | Technical Contact Phone | 
| DomainTools.Domains.Identity.BillingContact | Unknown | Billing Contact Info | 
| DomainTools.Domains.Identity.BillingContact.Country | Unknown | Billing Contact Country | 
| DomainTools.Domains.Identity.BillingContact.Email | Unknown | Billing Contact Email | 
| DomainTools.Domains.Identity.BillingContact.Name | Unknown | Billing Contact Name | 
| DomainTools.Domains.Identity.BillingContact.Phone | Unknown | Billing Contact Phone | 
| DomainTools.Domains.Identity.EmailDomains | Unknown | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails | Unknown | Additional Whois Emails | 
| DomainTools.Domains.Registration | Unknown | DomainTools Registration Info about the Domain | 
| DomainTools.Domains.Registration.DomainRegistrant | Unknown | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | Unknown | Reistrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting | Unknown | DomainTools Hosting Info about the Domain | 
| DomainTools.Domains.Hosting.IPAddresses | Unknown | IP Addresses Info | 
| DomainTools.Domains.Hosting.IPCountryCode | Unknown | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers | Unknown | Mail Servers Info | 
| DomainTools.Domains.Hosting.SPFRecord | Unknown | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers | Unknown | Name Servers Info | 
| DomainTools.Domains.Hosting.SSLCertificate | Unknown | SSL Certificate Info | 
| DomainTools.Domains.Hosting.RedirectsTo | Unknown | Domains it Redirects To | 
| DomainTools.Domains.Hosting.GoogleAdsenseTrackingCode | Unknown | Google Adsense Tracking Code | 
| DomainTools.Domains.Hosting.GoogleAnalyticTrackingCode | Unknown | Google Analytics Tracking Code | 


##### Command Example
`!domain domain=demisto.com`

##### Context Example
```
{
        "Domain": {
            "CreationDate": "2015-01-16",
            "DNS": "104.196.188.170",
            "DomainStatus": true,
            "DomainTools": {
                "Analytics": {
                    "Alexa Rank": 218532,
                    "OverallRiskScore": 38,
                    "ProximityRiskScore": 38,
                    "Tags": null,
                    "ThreatProfileRiskScore": {
                        "Evidence": null,
                        "RiskScore": 0,
                        "Threats": null
                    },
                    "WebsiteResponseCode": 500
                },
                "Hosting": {
                    "GoogleAdsenseTrackingCode": null,
                    "GoogleAnalyticTrackingCode": null,
                    "IPAddresses": [
                        {
                            "address": {
                                "count": 121,
                                "value": "104.196.188.170"
                            },
                            "asn": [
                                {
                                    "count": 13785569,
                                    "value": 15169
                                }
                            ],
                            "country_code": {
                                "count": 292797151,
                                "value": "us"
                            },
                            "isp": {
                                "count": 2095931,
                                "value": "Google Inc."
                            }
                        }
                    ],
                    "IPCountryCode": {
                        "address": {
                            "count": 121,
                            "value": "104.196.188.170"
                        },
                        "asn": [
                            {
                                "count": 13785569,
                                "value": 15169
                            }
                        ],
                        "country_code": {
                            "count": 292797151,
                            "value": "us"
                        },
                        "isp": {
                            "count": 2095931,
                            "value": "Google Inc."
                        }
                    },
                    "MailServers": [
                        {
                            "domain": {
                                "count": 89169,
                                "value": "pphosted.com"
                            },
                            "host": {
                                "count": 13,
                                "value": "mxa-00169c01.gslb.pphosted.com"
                            },
                            "ip": [
                                {
                                    "count": 11,
                                    "value": "67.231.156.123"
                                }
                            ],
                            "priority": 10
                        },
                        {
                            "domain": {
                                "count": 89169,
                                "value": "pphosted.com"
                            },
                            "host": {
                                "count": 12,
                                "value": "mxb-00169c01.gslb.pphosted.com"
                            },
                            "ip": [
                                {
                                    "count": 11,
                                    "value": "67.231.148.124"
                                }
                            ],
                            "priority": 10
                        }
                    ],
                    "NameServers": [
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9963,
                                "value": "pns31.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 14297,
                                    "value": "185.136.96.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9520,
                                "value": "pns32.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 13824,
                                    "value": "185.136.97.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9084,
                                "value": "pns33.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 11922,
                                    "value": "185.136.98.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9043,
                                "value": "pns34.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 11657,
                                    "value": "185.136.99.66"
                                }
                            ]
                        }
                    ],
                    "RedirectsTo": {
                        "count": 0,
                        "value": null
                    },
                    "SPFRecord": "v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all",
                    "SSLCertificate": [
                        {
                            "email": null,
                            "hash": {
                                "count": 1,
                                "value": "655e7afb5bd1a5fe4b887ae1d0b3477e859d6bac"
                            },
                            "organization": {
                                "count": 0,
                                "value": null
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=demisto.com"
                            }
                        },
                        {
                            "email": null,
                            "hash": {
                                "count": 1,
                                "value": "7fed20410a1eb258c540f9c08ac7d361a9abd505"
                            },
                            "organization": {
                                "count": 0,
                                "value": null
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=www.demisto.com"
                            }
                        }
                    ]
                },
                "Identity": {
                    "AdditionalWhoisEmails": [
                        {
                            "count": 18112317,
                            "value": "abuse@namecheap.com"
                        }
                    ],
                    "AdminContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    },
                    "BillingContact": {
                        "Country": {
                            "count": 0,
                            "value": null
                        },
                        "Email": null,
                        "Name": {
                            "count": 0,
                            "value": null
                        },
                        "Phone": {
                            "count": 0,
                            "value": null
                        }
                    },
                    "EmailDomains": [
                        "cloudns.net",
                        "namecheap.com",
                        "whoisguard.com"
                    ],
                    "RegistrantContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    },
                    "RegistrantName": "WhoisGuard Protected",
                    "RegistrantOrg": "WhoisGuard, Inc",
                    "SOAEmail": [
                        "support@cloudns.net"
                    ],
                    "SSLCertificateEmail": null,
                    "TechnicalContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    }
                },
                "LastEnriched": "2019-09-18",
                "Name": "demisto.com",
                "Registration": {
                    "CreateDate": "2015-01-16",
                    "DomainRegistrant": "NAMECHEAP INC,NAMECHEAP, INC",
                    "DomainStatus": true,
                    "ExpirationDate": "2026-01-16",
                    "RegistrarStatus": [
                        "clientTransferProhibited"
                    ]
                }
            },
            "ExpirationDate": "2026-01-16",
            "Name": "demisto.com",
            "NameServers": "pns31.cloudns.net, pns32.cloudns.net, pns33.cloudns.net, pns34.cloudns.net",
            "Registrant": {
                "Country": "pa",
                "Email": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com",
                "Name": "WhoisGuard Protected",
                "Phone": "5078365503"
            },
            "RiskScore": 38,
            "Vendor": "DomainTools"
        }
    
```

##### Human Readable Output
##### DomainTools Domain Profile for demisto.com.\n|Name|Last Enriched|Overall Risk Score|Proximity Risk Score|Threat Profile Risk Score|Threat Profile Threats|Threat Profile Evidence|Website Response Code|Alexa Rank|Tags|Registrant Name|Registrant Org|Registrant Contact|SOA Email|SSL Certificate Email|Admin Contact|Technical Contact|Billing Contact|Email Domains|Additional Whois Emails|Domain Registrant|Registrar Status|Domain Status|Create Date|Expiration Date|IP Addresses|IP Country Code|Mail Servers|SPF Record|Name Servers|SSL Certificate|Redirects To|Google Adsense Tracking Code|Google Analytic Tracking Code|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n|demisto.com|2019-10-10|33|33|0|||500|326569||WhoisGuard Protected|WhoisGuard, Inc|Country: {\"value\": \"pa\", \"count\": 19786098}<br>Email: {'value': '5be9245893ff486d98c3640879bb2657.protect@whoisguard.com', 'count': 1}<br>Name: {\"value\": \"WhoisGuard Protected\", \"count\": 8625643}<br>Phone: {\"value\": \"5078365503\", \"count\": 10343154}|support@cloudns.net||Country: {\"value\": \"pa\", \"count\": 19786098}<br>Email: {'value': '5be9245893ff486d98c3640879bb2657.protect@whoisguard.com', 'count': 1}<br>Name: {\"value\": \"WhoisGuard Protected\", \"count\": 8625643}<br>Phone: {\"value\": \"5078365503\", \"count\": 10343154}|Country: {\"value\": \"pa\", \"count\": 19786098}<br>Email: {'value': '5be9245893ff486d98c3640879bb2657.protect@whoisguard.com', 'count': 1}<br>Name: {\"value\": \"WhoisGuard Protected\", \"count\": 8625643}<br>Phone: {\"value\": \"5078365503\", \"count\": 10343154}|Country: {\"value\": null, \"count\": 0}<br>Email: null<br>Name: {\"value\": null, \"count\": 0}<br>Phone: {\"value\": null, \"count\": 0}|cloudns.net,<br>namecheap.com,<br>whoisguard.com|{'value': 'abuse@namecheap.com', 'count': 18388844}|NAMECHEAP INC,NAMECHEAP, INC|clientTransferProhibited|true|2015-01-16|2026-01-16|{'address': {'value': '104.196.188.170', 'count': 121}, 'asn': [{'value': 15169, 'count': 13931803}], 'country_code': {'value': 'us', 'count': 295509125}, 'isp': {'value': 'Google Inc.', 'count': 2092359}}|address: {\"value\": \"104.196.188.170\", \"count\": 121}<br>asn: {'value': 15169, 'count': 13931803}<br>country_code: {\"value\": \"us\", \"count\": 295509125}<br>isp: {\"value\": \"Google Inc.\", \"count\": 2092359}|{'host': {'value': 'mxa-00169c01.gslb.pphosted.com', 'count': 13}, 'domain': {'value': 'pphosted.com', 'count': 90310}, 'ip': [{'value': '67.231.148.124', 'count': 10}], 'priority': 10},<br>{'host': {'value': 'mxb-00169c01.gslb.pphosted.com', 'count': 12}, 'domain': {'value': 'pphosted.com', 'count': 90310}, 'ip': [{'value': '67.231.156.123', 'count': 12}], 'priority': 10}|v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all|{'host': {'value': 'pns31.cloudns.net', 'count': 10798}, 'domain': {'value': 'cloudns.net', 'count': 227179}, 'ip': [{'value': '185.136.96.66', 'count': 15398}]},<br>{'host': {'value': 'pns32.cloudns.net', 'count': 10323}, 'domain': {'value': 'cloudns.net', 'count': 227179}, 'ip': [{'value': '185.136.97.66', 'count': 14881}]},<br>{'host': {'value': 'pns33.cloudns.net', 'count': 9776}, 'domain': {'value': 'cloudns.net', 'count': 227179}, 'ip': [{'value': '185.136.98.66', 'count': 12689}]},<br>{'host': {'value': 'pns34.cloudns.net', 'count': 9736}, 'domain': {'value': 'cloudns.net', 'count': 227179}, 'ip': [{'value': '185.136.99.66', 'count': 12410}]}|{'hash': {'value': '7fed20410a1eb258c540f9c08ac7d361a9abd505', 'count': 1}, 'subject': {'value': 'CN=www.demisto.com', 'count': 1}, 'organization': {'value': None, 'count': 0}, 'email': None},<br>{'hash': {'value': '36cbf4ec8b46e8baadaf4a9895d7dec7af7f138e', 'count': 1}, 'subject': {'value': 'CN=demisto.com', 'count': 1}, 'organization': {'value': None, 'count': 0}, 'email': None}|value: null<br>count: 0|||\n

### 2. domaintoolsiris-analytics
---
 
##### Base Command

`domaintoolsiris-analytics`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | Domain Name | 
| Domain.DNS | String | Domain DNS | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.Vendor | String | Domain Vendor | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.RiskScore | Number | Domain RiskScore | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | String | Domain NameServers | 
| Domain.Registrant | Unknown | Domain Registrant | 
| Domain.Malicious | Unknown | Is the Domain Malicious | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | Unknown | Description of why domain was found to be malicious | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics | Unknown | Analytics Data about the Domain from DomainTools | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore | Unknown | DomainTools Threat Profile Info | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | Unknown | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | Unknown | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Unknown | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Unknown | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | Unknown | DomainTools Tags | 
| DomainTools.Domains.Identity | Unknown | DomainTools Identity Info about the Domain | 
| DomainTools.Domains.Identity.RegistrantName | Unknown | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | Unknown | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact | Unknown | Registrant Contact Info | 
| DomainTools.Domains.Identity.RegistrantContact.Country | Unknown | Registrant Contact Country | 
| DomainTools.Domains.Identity.RegistrantContact.Email | Unknown | Registrant Contact Email | 
| DomainTools.Domains.Identity.RegistrantContact.Name | Unknown | Registrant Contact Name | 
| DomainTools.Domains.Identity.RegistrantContact.Phone | Unknown | Registrant Contact Phone | 
| DomainTools.Domains.Identity.SOAEmail | Unknown | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | Unknown | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact | Unknown | Admin Contact Info | 
| DomainTools.Domains.Identity.AdminContact.Country | Unknown | Admin Contact Country | 
| DomainTools.Domains.Identity.AdminContact.Email | Unknown | Admin Contact Email | 
| DomainTools.Domains.Identity.AdminContact.Name | Unknown | Admin Contact Name | 
| DomainTools.Domains.Identity.AdminContact.Phone | Unknown | Admin Contact Phone | 
| DomainTools.Domains.Identity.TechnicalContact | Unknown | Technical Contact Info | 
| DomainTools.Domains.Identity.TechnicalContact.Country | Unknown | Technical Contact Country | 
| DomainTools.Domains.Identity.TechnicalContact.Email | Unknown | Technical Contact Email | 
| DomainTools.Domains.Identity.TechnicalContact.Name | Unknown | Technical Contact Name | 
| DomainTools.Domains.Identity.TechnicalContact.Phone | Unknown | Technical Contact Phone | 
| DomainTools.Domains.Identity.BillingContact | Unknown | Billing Contact Info | 
| DomainTools.Domains.Identity.BillingContact.Country | Unknown | Billing Contact Country | 
| DomainTools.Domains.Identity.BillingContact.Email | Unknown | Billing Contact Email | 
| DomainTools.Domains.Identity.BillingContact.Name | Unknown | Billing Contact Name | 
| DomainTools.Domains.Identity.BillingContact.Phone | Unknown | Billing Contact Phone | 
| DomainTools.Domains.Identity.EmailDomains | Unknown | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails | Unknown | Additional Whois Emails | 
| DomainTools.Domains.Registration | Unknown | DomainTools Registration Info about the Domain | 
| DomainTools.Domains.Registration.DomainRegistrant | Unknown | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | Unknown | Reistrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting | Unknown | DomainTools Hosting Info about the Domain | 
| DomainTools.Domains.Hosting.IPAddresses | Unknown | IP Addresses Info | 
| DomainTools.Domains.Hosting.IPCountryCode | Unknown | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers | Unknown | Mail Servers Info | 
| DomainTools.Domains.Hosting.SPFRecord | Unknown | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers | Unknown | Name Servers Info | 
| DomainTools.Domains.Hosting.SSLCertificate | Unknown | SSL Certificate Info | 
| DomainTools.Domains.Hosting.RedirectsTo | Unknown | Domains it Redirects To | 
| DomainTools.Domains.Hosting.GoogleAdsenseTrackingCode | Unknown | Google Adsense Tracking Code | 
| DomainTools.Domains.Hosting.GoogleAnalyticTrackingCode | Unknown | Google Analytics Tracking Code | 


##### Command Example
`!domain-analytics domain=demisto.com`

##### Context Example
```
{
        "Domain": {
            "CreationDate": "2015-01-16",
            "DNS": "104.196.188.170",
            "DomainStatus": true,
            "DomainTools": {
                "Analytics": {
                    "Alexa Rank": 218532,
                    "OverallRiskScore": 38,
                    "ProximityRiskScore": 38,
                    "Tags": null,
                    "ThreatProfileRiskScore": {
                        "Evidence": null,
                        "RiskScore": 0,
                        "Threats": null
                    },
                    "WebsiteResponseCode": 500
                },
                "Hosting": {
                    "GoogleAdsenseTrackingCode": null,
                    "GoogleAnalyticTrackingCode": null,
                    "IPAddresses": [
                        {
                            "address": {
                                "count": 121,
                                "value": "104.196.188.170"
                            },
                            "asn": [
                                {
                                    "count": 13785569,
                                    "value": 15169
                                }
                            ],
                            "country_code": {
                                "count": 292797151,
                                "value": "us"
                            },
                            "isp": {
                                "count": 2095931,
                                "value": "Google Inc."
                            }
                        }
                    ],
                    "IPCountryCode": {
                        "address": {
                            "count": 121,
                            "value": "104.196.188.170"
                        },
                        "asn": [
                            {
                                "count": 13785569,
                                "value": 15169
                            }
                        ],
                        "country_code": {
                            "count": 292797151,
                            "value": "us"
                        },
                        "isp": {
                            "count": 2095931,
                            "value": "Google Inc."
                        }
                    },
                    "MailServers": [
                        {
                            "domain": {
                                "count": 89169,
                                "value": "pphosted.com"
                            },
                            "host": {
                                "count": 13,
                                "value": "mxa-00169c01.gslb.pphosted.com"
                            },
                            "ip": [
                                {
                                    "count": 11,
                                    "value": "67.231.156.123"
                                }
                            ],
                            "priority": 10
                        },
                        {
                            "domain": {
                                "count": 89169,
                                "value": "pphosted.com"
                            },
                            "host": {
                                "count": 12,
                                "value": "mxb-00169c01.gslb.pphosted.com"
                            },
                            "ip": [
                                {
                                    "count": 11,
                                    "value": "67.231.148.124"
                                }
                            ],
                            "priority": 10
                        }
                    ],
                    "NameServers": [
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9963,
                                "value": "pns31.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 14297,
                                    "value": "185.136.96.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9520,
                                "value": "pns32.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 13824,
                                    "value": "185.136.97.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9084,
                                "value": "pns33.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 11922,
                                    "value": "185.136.98.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9043,
                                "value": "pns34.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 11657,
                                    "value": "185.136.99.66"
                                }
                            ]
                        }
                    ],
                    "RedirectsTo": {
                        "count": 0,
                        "value": null
                    },
                    "SPFRecord": "v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all",
                    "SSLCertificate": [
                        {
                            "email": null,
                            "hash": {
                                "count": 1,
                                "value": "655e7afb5bd1a5fe4b887ae1d0b3477e859d6bac"
                            },
                            "organization": {
                                "count": 0,
                                "value": null
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=demisto.com"
                            }
                        },
                        {
                            "email": null,
                            "hash": {
                                "count": 1,
                                "value": "7fed20410a1eb258c540f9c08ac7d361a9abd505"
                            },
                            "organization": {
                                "count": 0,
                                "value": null
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=www.demisto.com"
                            }
                        }
                    ]
                },
                "Identity": {
                    "AdditionalWhoisEmails": [
                        {
                            "count": 18112317,
                            "value": "abuse@namecheap.com"
                        }
                    ],
                    "AdminContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    },
                    "BillingContact": {
                        "Country": {
                            "count": 0,
                            "value": null
                        },
                        "Email": null,
                        "Name": {
                            "count": 0,
                            "value": null
                        },
                        "Phone": {
                            "count": 0,
                            "value": null
                        }
                    },
                    "EmailDomains": [
                        "cloudns.net",
                        "namecheap.com",
                        "whoisguard.com"
                    ],
                    "RegistrantContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    },
                    "RegistrantName": "WhoisGuard Protected",
                    "RegistrantOrg": "WhoisGuard, Inc",
                    "SOAEmail": [
                        "support@cloudns.net"
                    ],
                    "SSLCertificateEmail": null,
                    "TechnicalContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    }
                },
                "LastEnriched": "2019-09-18",
                "Name": "demisto.com",
                "Registration": {
                    "CreateDate": "2015-01-16",
                    "DomainRegistrant": "NAMECHEAP INC,NAMECHEAP, INC",
                    "DomainStatus": true,
                    "ExpirationDate": "2026-01-16",
                    "RegistrarStatus": [
                        "clientTransferProhibited"
                    ]
                }
            },
            "ExpirationDate": "2026-01-16",
            "Name": "demisto.com",
            "NameServers": "pns31.cloudns.net, pns32.cloudns.net, pns33.cloudns.net, pns34.cloudns.net",
            "Registrant": {
                "Country": "pa",
                "Email": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com",
                "Name": "WhoisGuard Protected",
                "Phone": "5078365503"
            },
            "RiskScore": 38,
            "Vendor": "DomainTools"
        }
```

##### Human Readable Output
##### DomainTools Domain Analytics for demisto.com.\n|Overall Risk Score|Proximity Risk Score|Domain Age (in days)|Website Response|Google Adsense|Google Analytics|Alexa Rank|Tags|\n|---|---|---|---|---|---|---|---|\n|38|38|1706|500|||218532||\n

### 3. threat-profile
---
 
##### Base Command

`domaintoolsiris-threat-profile`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | Domain Name | 
| Domain.DNS | String | Domain DNS | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.Vendor | String | Domain Vendor | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.RiskScore | Number | Domain RiskScore | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | String | Domain NameServers | 
| Domain.Registrant | Unknown | Domain Registrant | 
| Domain.Malicious | Unknown | Is the Domain Malicious | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | Unknown | Description of why domain was found to be malicious | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics | Unknown | Analytics Data about the Domain from DomainTools | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore | Unknown | DomainTools Threat Profile Info | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | Unknown | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | Unknown | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Unknown | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Unknown | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | Unknown | DomainTools Tags | 
| DomainTools.Domains.Identity | Unknown | DomainTools Identity Info about the Domain | 
| DomainTools.Domains.Identity.RegistrantName | Unknown | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | Unknown | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact | Unknown | Registrant Contact Info | 
| DomainTools.Domains.Identity.RegistrantContact.Country | Unknown | Registrant Contact Country | 
| DomainTools.Domains.Identity.RegistrantContact.Email | Unknown | Registrant Contact Email | 
| DomainTools.Domains.Identity.RegistrantContact.Name | Unknown | Registrant Contact Name | 
| DomainTools.Domains.Identity.RegistrantContact.Phone | Unknown | Registrant Contact Phone | 
| DomainTools.Domains.Identity.SOAEmail | Unknown | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | Unknown | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact | Unknown | Admin Contact Info | 
| DomainTools.Domains.Identity.AdminContact.Country | Unknown | Admin Contact Country | 
| DomainTools.Domains.Identity.AdminContact.Email | Unknown | Admin Contact Email | 
| DomainTools.Domains.Identity.AdminContact.Name | Unknown | Admin Contact Name | 
| DomainTools.Domains.Identity.AdminContact.Phone | Unknown | Admin Contact Phone | 
| DomainTools.Domains.Identity.TechnicalContact | Unknown | Technical Contact Info | 
| DomainTools.Domains.Identity.TechnicalContact.Country | Unknown | Technical Contact Country | 
| DomainTools.Domains.Identity.TechnicalContact.Email | Unknown | Technical Contact Email | 
| DomainTools.Domains.Identity.TechnicalContact.Name | Unknown | Technical Contact Name | 
| DomainTools.Domains.Identity.TechnicalContact.Phone | Unknown | Technical Contact Phone | 
| DomainTools.Domains.Identity.BillingContact | Unknown | Billing Contact Info | 
| DomainTools.Domains.Identity.BillingContact.Country | Unknown | Billing Contact Country | 
| DomainTools.Domains.Identity.BillingContact.Email | Unknown | Billing Contact Email | 
| DomainTools.Domains.Identity.BillingContact.Name | Unknown | Billing Contact Name | 
| DomainTools.Domains.Identity.BillingContact.Phone | Unknown | Billing Contact Phone | 
| DomainTools.Domains.Identity.EmailDomains | Unknown | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails | Unknown | Additional Whois Emails | 
| DomainTools.Domains.Registration | Unknown | DomainTools Registration Info about the Domain | 
| DomainTools.Domains.Registration.DomainRegistrant | Unknown | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | Unknown | Reistrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting | Unknown | DomainTools Hosting Info about the Domain | 
| DomainTools.Domains.Hosting.IPAddresses | Unknown | IP Addresses Info | 
| DomainTools.Domains.Hosting.IPCountryCode | Unknown | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers | Unknown | Mail Servers Info | 
| DomainTools.Domains.Hosting.SPFRecord | Unknown | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers | Unknown | Name Servers Info | 
| DomainTools.Domains.Hosting.SSLCertificate | Unknown | SSL Certificate Info | 
| DomainTools.Domains.Hosting.RedirectsTo | Unknown | Domains it Redirects To | 
| DomainTools.Domains.Hosting.GoogleAdsenseTrackingCode | Unknown | Google Adsense Tracking Code | 
| DomainTools.Domains.Hosting.GoogleAnalyticTrackingCode | Unknown | Google Analytics Tracking Code | 


##### Command Example
`!domaintoolsiris-threat-profile domain=demisto.com`

##### Context Example
```
{
        "Domain": {
            "CreationDate": "2015-01-16",
            "DNS": "104.196.188.170",
            "DomainStatus": true,
            "DomainTools": {
                "Analytics": {
                    "Alexa Rank": 218532,
                    "OverallRiskScore": 38,
                    "ProximityRiskScore": 38,
                    "Tags": null,
                    "ThreatProfileRiskScore": {
                        "Evidence": null,
                        "RiskScore": 0,
                        "Threats": null
                    },
                    "WebsiteResponseCode": 500
                },
                "Hosting": {
                    "GoogleAdsenseTrackingCode": null,
                    "GoogleAnalyticTrackingCode": null,
                    "IPAddresses": [
                        {
                            "address": {
                                "count": 121,
                                "value": "104.196.188.170"
                            },
                            "asn": [
                                {
                                    "count": 13785569,
                                    "value": 15169
                                }
                            ],
                            "country_code": {
                                "count": 292797151,
                                "value": "us"
                            },
                            "isp": {
                                "count": 2095931,
                                "value": "Google Inc."
                            }
                        }
                    ],
                    "IPCountryCode": {
                        "address": {
                            "count": 121,
                            "value": "104.196.188.170"
                        },
                        "asn": [
                            {
                                "count": 13785569,
                                "value": 15169
                            }
                        ],
                        "country_code": {
                            "count": 292797151,
                            "value": "us"
                        },
                        "isp": {
                            "count": 2095931,
                            "value": "Google Inc."
                        }
                    },
                    "MailServers": [
                        {
                            "domain": {
                                "count": 89169,
                                "value": "pphosted.com"
                            },
                            "host": {
                                "count": 13,
                                "value": "mxa-00169c01.gslb.pphosted.com"
                            },
                            "ip": [
                                {
                                    "count": 11,
                                    "value": "67.231.156.123"
                                }
                            ],
                            "priority": 10
                        },
                        {
                            "domain": {
                                "count": 89169,
                                "value": "pphosted.com"
                            },
                            "host": {
                                "count": 12,
                                "value": "mxb-00169c01.gslb.pphosted.com"
                            },
                            "ip": [
                                {
                                    "count": 11,
                                    "value": "67.231.148.124"
                                }
                            ],
                            "priority": 10
                        }
                    ],
                    "NameServers": [
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9963,
                                "value": "pns31.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 14297,
                                    "value": "185.136.96.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9520,
                                "value": "pns32.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 13824,
                                    "value": "185.136.97.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9084,
                                "value": "pns33.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 11922,
                                    "value": "185.136.98.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9043,
                                "value": "pns34.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 11657,
                                    "value": "185.136.99.66"
                                }
                            ]
                        }
                    ],
                    "RedirectsTo": {
                        "count": 0,
                        "value": null
                    },
                    "SPFRecord": "v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all",
                    "SSLCertificate": [
                        {
                            "email": null,
                            "hash": {
                                "count": 1,
                                "value": "655e7afb5bd1a5fe4b887ae1d0b3477e859d6bac"
                            },
                            "organization": {
                                "count": 0,
                                "value": null
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=demisto.com"
                            }
                        },
                        {
                            "email": null,
                            "hash": {
                                "count": 1,
                                "value": "7fed20410a1eb258c540f9c08ac7d361a9abd505"
                            },
                            "organization": {
                                "count": 0,
                                "value": null
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=www.demisto.com"
                            }
                        }
                    ]
                },
                "Identity": {
                    "AdditionalWhoisEmails": [
                        {
                            "count": 18112317,
                            "value": "abuse@namecheap.com"
                        }
                    ],
                    "AdminContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    },
                    "BillingContact": {
                        "Country": {
                            "count": 0,
                            "value": null
                        },
                        "Email": null,
                        "Name": {
                            "count": 0,
                            "value": null
                        },
                        "Phone": {
                            "count": 0,
                            "value": null
                        }
                    },
                    "EmailDomains": [
                        "cloudns.net",
                        "namecheap.com",
                        "whoisguard.com"
                    ],
                    "RegistrantContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    },
                    "RegistrantName": "WhoisGuard Protected",
                    "RegistrantOrg": "WhoisGuard, Inc",
                    "SOAEmail": [
                        "support@cloudns.net"
                    ],
                    "SSLCertificateEmail": null,
                    "TechnicalContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    }
                },
                "LastEnriched": "2019-09-18",
                "Name": "demisto.com",
                "Registration": {
                    "CreateDate": "2015-01-16",
                    "DomainRegistrant": "NAMECHEAP INC,NAMECHEAP, INC",
                    "DomainStatus": true,
                    "ExpirationDate": "2026-01-16",
                    "RegistrarStatus": [
                        "clientTransferProhibited"
                    ]
                }
            },
            "ExpirationDate": "2026-01-16",
            "Name": "demisto.com",
            "NameServers": "pns31.cloudns.net, pns32.cloudns.net, pns33.cloudns.net, pns34.cloudns.net",
            "Registrant": {
                "Country": "pa",
                "Email": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com",
                "Name": "WhoisGuard Protected",
                "Phone": "5078365503"
            },
            "RiskScore": 38,
            "Vendor": "DomainTools"
        }
```

##### Human Readable Output
##### DomainTools Threat Profile for demisto.com.\n|Overall Risk Score|Proximity Risk Score|Threat Profile Risk ScoreThreat Profile Threats|Threat Profile Evidence|Threat Profile Malware Risk Score|Threat Profile Phishing Risk Score|Threat Profile Spam Risk Score|\n|---|---|---|---|---|---|---|\n|33|33|||0|0|0|\n

### 4. domain-pivot
---
 
##### Base Command

`domain-pivot`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP Address | Optional | 
| email | E-mail Address | Optional | 
| nameserver_ip | Name Server IP Address | Optional | 
| ssl_hash | SSL Hash | Optional | 
| nameserver_host | Fully-qualified host name of the name server (ns1.domaintools.net) | Optional | 
| mailserver_host | Fully-qualified host name of the mail server (mx.domaintools.net) | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainTools.PivotedDomains.Name | String | DomainTools Domain Name | 
| DomainTools.PivotedDomains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.PivotedDomains.Analytics | Unknown | Analytics Data about the Domain from DomainTools | 
| DomainTools.PivotedDomains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.PivotedDomains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore | Unknown | DomainTools Threat Profile Info | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.Threats | Unknown | DomainTools Threat Profile Threats | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.Evidence | Unknown | DomainTools Threat Profile Evidence | 
| DomainTools.PivotedDomains.Analytics.WebsiteResponseCode | Unknown | Website Response Code | 
| DomainTools.PivotedDomains.Analytics.AlexaRank | Unknown | Alexa Rank | 
| DomainTools.PivotedDomains.Analytics.Tags | Unknown | DomainTools Tags | 
| DomainTools.PivotedDomains.Identity | Unknown | DomainTools Identity Info about the Domain | 
| DomainTools.PivotedDomains.Identity.RegistrantName | Unknown | Registrant Name | 
| DomainTools.PivotedDomains.Identity.RegistrantOrg | Unknown | Registrant Org | 
| DomainTools.PivotedDomains.Identity.RegistrantContact | Unknown | Registrant Contact Info | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Country | Unknown | Registrant Contact Country | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Email | Unknown | Registrant Contact Email | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Name | Unknown | Registrant Contact Name | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Phone | Unknown | Registrant Contact Phone | 
| DomainTools.PivotedDomains.Identity.SOAEmail | Unknown | SOA Record Email | 
| DomainTools.PivotedDomains.Identity.SSLCertificateEmail | Unknown | SSL Certificate Email | 
| DomainTools.PivotedDomains.Identity.AdminContact | Unknown | Admin Contact Info | 
| DomainTools.PivotedDomains.Identity.AdminContact.Country | Unknown | Admin Contact Country | 
| DomainTools.PivotedDomains.Identity.AdminContact.Email | Unknown | Admin Contact Email | 
| DomainTools.PivotedDomains.Identity.AdminContact.Name | Unknown | Admin Contact Name | 
| DomainTools.PivotedDomains.Identity.AdminContact.Phone | Unknown | Admin Contact Phone | 
| DomainTools.PivotedDomains.Identity.TechnicalContact | Unknown | Technical Contact Info | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Country | Unknown | Technical Contact Country | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Email | Unknown | Technical Contact Email | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Name | Unknown | Technical Contact Name | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Phone | Unknown | Technical Contact Phone | 
| DomainTools.PivotedDomains.Identity.BillingContact | Unknown | Billing Contact Info | 
| DomainTools.PivotedDomains.Identity.BillingContact.Country | Unknown | Billing Contact Country | 
| DomainTools.PivotedDomains.Identity.BillingContact.Email | Unknown | Billing Contact Email | 
| DomainTools.PivotedDomains.Identity.BillingContact.Name | Unknown | Billing Contact Name | 
| DomainTools.PivotedDomains.Identity.BillingContact.Phone | Unknown | Billing Contact Phone | 
| DomainTools.PivotedDomains.Identity.EmailDomains | Unknown | Email Domains | 
| DomainTools.PivotedDomains.Identity.AdditionalWhoisEmails | Unknown | Additional Whois Emails | 
| DomainTools.PivotedDomains.Registration | Unknown | DomainTools Registration Info about the Domain | 
| DomainTools.PivotedDomains.Registration.DomainRegistrant | Unknown | Domain Registrant | 
| DomainTools.PivotedDomains.Registration.RegistrarStatus | Unknown | Reistrar Status | 
| DomainTools.PivotedDomains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.PivotedDomains.Registration.CreateDate | Date | Create Date | 
| DomainTools.PivotedDomains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.PivotedDomains.Hosting | Unknown | DomainTools Hosting Info about the Domain | 
| DomainTools.PivotedDomains.Hosting.IPAddresses | Unknown | IP Addresses Info | 
| DomainTools.PivotedDomains.Hosting.IPCountryCode | Unknown | IP Country Code | 
| DomainTools.PivotedDomains.Hosting.MailServers | Unknown | Mail Servers Info | 
| DomainTools.PivotedDomains.Hosting.SPFRecord | Unknown | SPF Record Info | 
| DomainTools.PivotedDomains.Hosting.NameServers | Unknown | Name Servers Info | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate | Unknown | SSL Certificate Info | 
| DomainTools.PivotedDomains.Hosting.RedirectsTo | Unknown | Domains it Redirects To | 
| DomainTools.PivotedDomains.Hosting.GoogleAdsenseTrackingCode | Unknown | Google Adsense Tracking Code | 
| DomainTools.PivotedDomains.Hosting.GoogleAnalyticTrackingCode | Unknown | Google Analytics Tracking Code | 

##### Command Example
`!domaintoolsiris-pivot ip=104.196.188.170`

##### Context Example
```
        {
        "PivotedDomains": {
            "CreationDate": "2015-01-16",
            "DNS": "104.196.188.170",
            "DomainStatus": true,
            "DomainTools": {
                "Analytics": {
                    "Alexa Rank": 218532,
                    "OverallRiskScore": 38,
                    "ProximityRiskScore": 38,
                    "Tags": null,
                    "ThreatProfileRiskScore": {
                        "Evidence": null,
                        "RiskScore": 0,
                        "Threats": null
                    },
                    "WebsiteResponseCode": 500
                },
                "Hosting": {
                    "GoogleAdsenseTrackingCode": null,
                    "GoogleAnalyticTrackingCode": null,
                    "IPAddresses": [
                        {
                            "address": {
                                "count": 121,
                                "value": "104.196.188.170"
                            },
                            "asn": [
                                {
                                    "count": 13785569,
                                    "value": 15169
                                }
                            ],
                            "country_code": {
                                "count": 292797151,
                                "value": "us"
                            },
                            "isp": {
                                "count": 2095931,
                                "value": "Google Inc."
                            }
                        }
                    ],
                    "IPCountryCode": {
                        "address": {
                            "count": 121,
                            "value": "104.196.188.170"
                        },
                        "asn": [
                            {
                                "count": 13785569,
                                "value": 15169
                            }
                        ],
                        "country_code": {
                            "count": 292797151,
                            "value": "us"
                        },
                        "isp": {
                            "count": 2095931,
                            "value": "Google Inc."
                        }
                    },
                    "MailServers": [
                        {
                            "domain": {
                                "count": 89169,
                                "value": "pphosted.com"
                            },
                            "host": {
                                "count": 13,
                                "value": "mxa-00169c01.gslb.pphosted.com"
                            },
                            "ip": [
                                {
                                    "count": 11,
                                    "value": "67.231.156.123"
                                }
                            ],
                            "priority": 10
                        },
                        {
                            "domain": {
                                "count": 89169,
                                "value": "pphosted.com"
                            },
                            "host": {
                                "count": 12,
                                "value": "mxb-00169c01.gslb.pphosted.com"
                            },
                            "ip": [
                                {
                                    "count": 11,
                                    "value": "67.231.148.124"
                                }
                            ],
                            "priority": 10
                        }
                    ],
                    "NameServers": [
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9963,
                                "value": "pns31.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 14297,
                                    "value": "185.136.96.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9520,
                                "value": "pns32.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 13824,
                                    "value": "185.136.97.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9084,
                                "value": "pns33.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 11922,
                                    "value": "185.136.98.66"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 225034,
                                "value": "cloudns.net"
                            },
                            "host": {
                                "count": 9043,
                                "value": "pns34.cloudns.net"
                            },
                            "ip": [
                                {
                                    "count": 11657,
                                    "value": "185.136.99.66"
                                }
                            ]
                        }
                    ],
                    "RedirectsTo": {
                        "count": 0,
                        "value": null
                    },
                    "SPFRecord": "v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all",
                    "SSLCertificate": [
                        {
                            "email": null,
                            "hash": {
                                "count": 1,
                                "value": "655e7afb5bd1a5fe4b887ae1d0b3477e859d6bac"
                            },
                            "organization": {
                                "count": 0,
                                "value": null
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=demisto.com"
                            }
                        },
                        {
                            "email": null,
                            "hash": {
                                "count": 1,
                                "value": "7fed20410a1eb258c540f9c08ac7d361a9abd505"
                            },
                            "organization": {
                                "count": 0,
                                "value": null
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=www.demisto.com"
                            }
                        }
                    ]
                },
                "Identity": {
                    "AdditionalWhoisEmails": [
                        {
                            "count": 18112317,
                            "value": "abuse@namecheap.com"
                        }
                    ],
                    "AdminContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    },
                    "BillingContact": {
                        "Country": {
                            "count": 0,
                            "value": null
                        },
                        "Email": null,
                        "Name": {
                            "count": 0,
                            "value": null
                        },
                        "Phone": {
                            "count": 0,
                            "value": null
                        }
                    },
                    "EmailDomains": [
                        "cloudns.net",
                        "namecheap.com",
                        "whoisguard.com"
                    ],
                    "RegistrantContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    },
                    "RegistrantName": "WhoisGuard Protected",
                    "RegistrantOrg": "WhoisGuard, Inc",
                    "SOAEmail": [
                        "support@cloudns.net"
                    ],
                    "SSLCertificateEmail": null,
                    "TechnicalContact": {
                        "Country": {
                            "count": 19564746,
                            "value": "pa"
                        },
                        "Email": [
                            {
                                "count": 1,
                                "value": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
                            }
                        ],
                        "Name": {
                            "count": 8518184,
                            "value": "WhoisGuard Protected"
                        },
                        "Phone": {
                            "count": 10240321,
                            "value": "5078365503"
                        }
                    }
                },
                "LastEnriched": "2019-09-18",
                "Name": "demisto.com",
                "Registration": {
                    "CreateDate": "2015-01-16",
                    "DomainRegistrant": "NAMECHEAP INC,NAMECHEAP, INC",
                    "DomainStatus": true,
                    "ExpirationDate": "2026-01-16",
                    "RegistrarStatus": [
                        "clientTransferProhibited"
                    ]
                }
            },
            "ExpirationDate": "2026-01-16",
            "Name": "demisto.com",
            "NameServers": "pns31.cloudns.net, pns32.cloudns.net, pns33.cloudns.net, pns34.cloudns.net",
            "Registrant": {
                "Country": "pa",
                "Email": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com",
                "Name": "WhoisGuard Protected",
                "Phone": "5078365503"
            },
            "RiskScore": 38,
            "Vendor": "DomainTools"
        }
```

##### Human Readable Output
##### Domains for IP: 104.196.188.170.\n|Domains|\n|---|\n|8lock.co|\n|8lock.io|\n|9thcircuitcriminalcases.com|\n|abclawcenters.com|\n|abogadoayudany.com|\n|abqnorthstorage.com|\n|aclassmegastorage.com|\n|actua.pe|\n|adfconverter.com|\n|agmednet.com|\n|alabamatortlaw.com|\n|alliioop.com|\n|americanaddictionfoundation.com|\n|americanrotors.com|\n|apmlawyers.com|\n|archstonelaw.com|\n|arthurbayrvpark.com|\n|auraexperiences.com|\n|babcocklegal.com|\n|balancednutritionwny.com|\n|batchesmke.com|\n|bigroomstudios.com|\n|bila.ca|\n|bilac.ca|\n|birthinjuryexperts.com|\n|brr-law.com|\n|capandkudler.com|\n|carlaleader.com|\n|carsonfootwear.com|\n|charlotteinsurance.com|\n|cincinnatieducationlaw.com|\n|cooperagemke.com|\n|crownasset.com|\n|crucialpointllc.com|\n|ctovision.com|\n|customhroservices.com|\n|dandanmke.com|\n|decaleco.com|\n|demisto.com|\n|demysto.com|\n|dewshilaw.ca|\n|directfuel.net|\n|diversifiedauto.com|\n|donaldsonlaw.com|\n|dovermiller.com|\n|dstlintelligence.com|\n|eleanoramagazine.com|\n|esterev.com|\n|evergreenredbarn.com|\n|federalforfeitureguide.com|\n|finlayllc.com|\n|forecite.com|\n|happydragonthriftshop.org|\n|hempcocanada.com|\n|jameseducationcenter.com|\n|jamespublishing.com|\n|jamestoolbox.com|\n|joinappa.com|\n|kaelfoods.com|\n|kissmetricshq.com|\n|kristaliney.com|\n|kycriminaldefense.com|\n|lloydjonescapital.com|\n|lloydjonesinvest.com|\n|lloydjonesinvestments.com|\n|lloydjonesllc.com|\n|lutco.com|\n|makeithome.net|\n|marcellaallison.com|\n|marylandfamiliesengage.org|\n|mccormickkennedy.com|\n|motherson-ossia.com|\n|mothersonossia.com|\n|nanadecals.com|\n|nikolanews.com|\n|noizchain.com|\n|ocpmgmt.com|\n|oheleanora.com|\n|omnisole.com|\n|orthopediccarepartners.com|\n|pacificmedicallaw.ca|\n|parentalguidance.com|\n|portsideautorepair.com|\n|portsidetruckrepair.com|\n|precisionmedicalbilling.com|\n|proautotran.com|\n|productengagementstack.com|\n|proficientautotransport.com|\n|proficientautotransport.net|\n|pspp.org|\n|rdairways.com|\n|rengalaxy.com|\n|rivetinc.org|\n|segalaslawfirm.com|\n|sentencingcases.com|\n|shariaportfolio.ca|\n|shariaportfolio.com|\n|shikistitches.com|\n|simonbrosroofing.com|\n|skihouseswap.com|\n|spacepencil.com|\n|stuffmadein.com|\n|stuffmadeinct.com|\n|stuffmadeinma.com|\n|stuffmadeinme.com|\n|stuffmadeinnh.com|\n|theargyle.org|\n|therawragency.com|\n|thingscyber.com|\n|threatbrief.com|\n|tinrx.com|\n|toi-health.com|\n|unicornthrift.com|\n|unicornthriftshop.com|\n|upconstructionllc.com|\n|upliftfs.org|\n|vroom.training|\n|washingtondcsouth.com|\n|weddingrings.com.ph|\n|welleryou.com|\n|youngamericatrading.com|\n

## Additional Information
---

## Known Limitations
---

## Troubleshooting
---
