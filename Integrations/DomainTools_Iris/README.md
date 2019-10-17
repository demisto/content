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
| Domain.DNS | Unknown | Domain DNS | 
| Domain.DNS.address | Unknown | Domain DNS address | 
| Domain.DNS.address.value | String | Domain DNS address value | 
| Domain.DNS.address.count | Number | Domain DNS address count | 
| Domain.DNS.asn | Unknown | Domain DNS asn | 
| Domain.DNS.asn.value | String | Domain DNS asn value | 
| Domain.DNS.asn.count | Number | Domain DNS asn count | 
| Domain.DNS.country_code | Unknown | Domain DNS country_code | 
| Domain.DNS.country_code.value | String | Domain DNS country_code value | 
| Domain.DNS.country_code.count | Number | Domain DNS country_code count | 
| Domain.DNS.isp | Unknown | Domain DNS isp | 
| Domain.DNS.isp.value | String | Domain DNS isp value | 
| Domain.DNS.isp.count | Number | Domain DNS isp count | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | Unknown | Domain NameServers | 
| Domain.NameServers.domain | Unknown | Domain NameServers domain | 
| Domain.NameServers.domain.value | String | Domain NameServers domain value | 
| Domain.NameServers.domain.count | Number | Domain NameServers domain count | 
| Domain.NameServers.host | Unknown | Domain NameServers host | 
| Domain.NameServers.host.value | String | Domain NameServers host value | 
| Domain.NameServers.host.count | Number | Domain NameServers host count | 
| Domain.NameServers.ip | Unknown | Domain NameServers ip | 
| Domain.NameServers.ip.value | String | Domain NameServers ip value | 
| Domain.NameServers.ip.count | Number | Domain NameServers ip count | 
| Domain.Registrant | Unknown | Domain Registrant | 
| Domain.Registrant.Country | Unknown | Domain Registrant Country | 
| Domain.Registrant.Country.value | String | Domain Registrant Country value | 
| Domain.Registrant.Country.count | Number | Domain Registrant Country count | 
| Domain.Registrant.Email | Unknown | Domain Registrant Email | 
| Domain.Registrant.Email.value | String | Domain Registrant Email value | 
| Domain.Registrant.Email.count | Number | Domain Registrant Email count | 
| Domain.Registrant.Name | Unknown | Domain Registrant Name | 
| Domain.Registrant.Name.value | String | Domain Registrant Name value | 
| Domain.Registrant.Name.count | Number | Domain Registrant Name count | 
| Domain.Registrant.Phone | Unknown | Domain Registrant Phone | 
| Domain.Registrant.Phone.value | String | Domain Registrant Phone value | 
| Domain.Registrant.Phone.count | Number | Domain Registrant Phone count | 
| Domain.Malicious | Unknown | Is the Domain Malicious | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | Unknown | Description of why domain was found to be malicious | 
| DomainTools.Domains | Unknown | DomainTools Domains | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics | Unknown | Analytics Data about the Domain from DomainTools | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore | Unknown | DomainTools Threat Profile Info | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | Unknown | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | Unknown | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Number | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | Unknown | DomainTools Tags | 
| DomainTools.Domains.Identity | Unknown | DomainTools Identity Info about the Domain | 
| DomainTools.Domains.Identity.RegistrantName | String | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | String | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact | Unknown | Registrant Contact Info | 
| DomainTools.Domains.Identity.RegistrantContact.Country | Unknown | Registrant Contact Country | 
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | Registrant Contact Country value | 
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Count | Registrant Contact Country count | 
| DomainTools.Domains.Identity.RegistrantContact.Email | Unknown | Registrant Contact Email | 
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | Registrant Contact Email value | 
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | Registrant Contact Email count | 
| DomainTools.Domains.Identity.RegistrantContact.Name | Unknown | Registrant Contact Name | 
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | Registrant Contact Name value | 
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | Registrant Contact Name count | 
| DomainTools.Domains.Identity.RegistrantContact.Phone | Unknown | Registrant Contact Phone | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | Registrant Contact Phone value | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | Registrant Contact Phone count | 
| DomainTools.Domains.Identity.SOAEmail | Unknown | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | Unknown | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact | Unknown | Admin Contact Info | 
| DomainTools.Domains.Identity.AdminContact.Country | Unknown | Admin Contact Country | 
| DomainTools.Domains.Identity.AdminContact.Country.value | String | Admin Contact Country value | 
| DomainTools.Domains.Identity.AdminContact.Country.count | Number | Admin Contact Country count | 
| DomainTools.Domains.Identity.AdminContact.Email | Unknown | Admin Contact Email | 
| DomainTools.Domains.Identity.AdminContact.Email.value | String | Admin Contact Email value | 
| DomainTools.Domains.Identity.AdminContact.Email.count | Number | Admin Contact Email count | 
| DomainTools.Domains.Identity.AdminContact.Name | Unknown | Admin Contact Name | 
| DomainTools.Domains.Identity.AdminContact.Name.value | String | Admin Contact Name value | 
| DomainTools.Domains.Identity.AdminContact.Name.count | Number | Admin Contact Name count | 
| DomainTools.Domains.Identity.AdminContact.Phone | Unknown | Admin Contact Phone | 
| DomainTools.Domains.Identity.AdminContact.Phone.value | String | Admin Contact Phone value | 
| DomainTools.Domains.Identity.AdminContact.Phone.count | Number | Admin Contact Phone count | 
| DomainTools.Domains.Identity.TechnicalContact | Unknown | Technical Contact Info | 
| DomainTools.Domains.Identity.TechnicalContact.Country | Unknown | Technical Contact Country | 
| DomainTools.Domains.Identity.TechnicalContact.Country.value | String | Technical Contact Country value | 
| DomainTools.Domains.Identity.TechnicalContact.Country.count | Number | Technical Contact Country count | 
| DomainTools.Domains.Identity.TechnicalContact.Email | Unknown | Technical Contact Email | 
| DomainTools.Domains.Identity.TechnicalContact.Email.value | String | Technical Contact Email value | 
| DomainTools.Domains.Identity.TechnicalContact.Email.count | Number | Technical Contact Email count | 
| DomainTools.Domains.Identity.TechnicalContact.Name | Unknown | Technical Contact Name | 
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | Technical Contact Name value | 
| DomainTools.Domains.Identity.TechnicalContact.Name.count | Number | Technical Contact Name count | 
| DomainTools.Domains.Identity.TechnicalContact.Phone | Unknown | Technical Contact Phone | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | String | Technical Contact Phone value | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | Number | Technical Contact Phone count | 
| DomainTools.Domains.Identity.BillingContact | Unknown | Billing Contact Info | 
| DomainTools.Domains.Identity.BillingContact.Country | Unknown | Billing Contact Country | 
| DomainTools.Domains.Identity.BillingContact.Country.value | String | Billing Contact Country value | 
| DomainTools.Domains.Identity.BillingContact.Country.count | Number | Billing Contact Country count | 
| DomainTools.Domains.Identity.BillingContact.Email | Unknown | Billing Contact Email | 
| DomainTools.Domains.Identity.BillingContact.Email.value | String | Billing Contact Email value | 
| DomainTools.Domains.Identity.BillingContact.Email.count | Number | Billing Contact Email count | 
| DomainTools.Domains.Identity.BillingContact.Name | Unknown | Billing Contact Name | 
| DomainTools.Domains.Identity.BillingContact.Name.value | String | Billing Contact Name value | 
| DomainTools.Domains.Identity.BillingContact.Name.count | Number | Billing Contact Name count | 
| DomainTools.Domains.Identity.BillingContact.Phone | Unknown | Billing Contact Phone | 
| DomainTools.Domains.Identity.BillingContact.Phone.value | String | Billing Contact Phone value | 
| DomainTools.Domains.Identity.BillingContact.Phone.count | Number | Billing Contact Phone count | 
| DomainTools.Domains.Identity.EmailDomains | Unknown | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails | Unknown | Additional Whois Emails | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | Additional Whois Emails value | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | Additional Whois Emails count | 
| DomainTools.Domains.Registration | Unknown | DomainTools Registration Info about the Domain | 
| DomainTools.Domains.Registration.DomainRegistrant | Unknown | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | Unknown | Reistrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting | Unknown | DomainTools Hosting Info about the Domain | 
| DomainTools.Domains.Hosting.IPAddresses | Unknown | IP Addresses Info | 
| DomainTools.Domains.Hosting.IPAddresses.address | Unknown | IP Addresses Info address | 
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | IP Addresses Info address value | 
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | IP Addresses Info address count | 
| DomainTools.Domains.Hosting.IPAddresses.asn | Unknown | IP Addresses Info asn | 
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | IP Addresses Info asn value | 
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | IP Addresses Info asn count | 
| DomainTools.Domains.Hosting.IPAddresses.country_code | Unknown | IP Addresses Info country_code | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | IP Addresses Info country_code value | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | IP Addresses Info country_code count | 
| DomainTools.Domains.Hosting.IPAddresses.isp | Unknown | IP Addresses Info isp | 
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.Domains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers | Unknown | Mail Servers Info | 
| DomainTools.Domains.Hosting.MailServers.domain | Unknown | Mail Servers Info domain | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.Domains.Hosting.MailServers.host | Unknown | Mail Servers Info host | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.Domains.Hosting.MailServers.ip | Unknown | Mail Servers Info ip | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
| DomainTools.Domains.Hosting.SPFRecord | Unknown | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers | Unknown | Name Servers Info | 
| DomainTools.Domains.NameServers.domain | Unknown | DomainTools Domains NameServers domain | 
| DomainTools.Domains.NameServers.domain.value | String | DomainTools Domains NameServers domain value | 
| DomainTools.Domains.NameServers.domain.count | Number | DomainTools Domains NameServers domain count | 
| DomainTools.Domains.NameServers.host | Unknown | DomainTools Domains NameServers host | 
| DomainTools.Domains.NameServers.host.value | String | DomainTools Domains NameServers host value | 
| DomainTools.Domains.NameServers.host.count | Number | DomainTools Domains NameServers host count | 
| DomainTools.Domains.NameServers.ip | Unknown | DomainTools Domains NameServers ip | 
| DomainTools.Domains.NameServers.ip.value | String | DomainTools Domains NameServers ip value | 
| DomainTools.Domains.NameServers.ip.count | Number | DomainTools Domains NameServers ip count | 
| DomainTools.Domains.Hosting.SSLCertificate | Unknown | SSL Certificate Info | 
| DomainTools.Domains.Hosting.SSLCertificate.hash | Unknown | SSL Certificate Info hash | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | SSL Certificate Info hash value | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | SSL Certificate Info hash count | 
| DomainTools.Domains.Hosting.SSLCertificate.organization | Unknown | SSL Certificate Info organization | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | SSL Certificate Info organization value | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | SSL Certificate Info organization count | 
| DomainTools.Domains.Hosting.SSLCertificate.subject | Unknown | SSL Certificate Info subject | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | SSL Certificate Info subject value | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | SSL Certificate Info subject count | 
| DomainTools.Domains.Hosting.RedirectsTo | Unknown | Domains it Redirects To | 
| DomainTools.Domains.Hosting.RedirectsTo.value | String | Domains it Redirects To value | 
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | Domains it Redirects To count | 
| DomainTools.Domains.Hosting.GoogleAdsenseTrackingCode | Unknown | Google Adsense Tracking Code | 
| DomainTools.Domains.Hosting.GoogleAnalyticTrackingCode | Unknown | Google Analytics Tracking Code | 
| DBotScore | Unknown | DBot Score | 
| DBotScore.Indicator | String | DBotScore Indicator | 
| DBotScore.Type | String | DBotScore Indicator Type | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
`!domain domain=demisto.com`

##### Context Example
```
        "DBotScore": {
            "Indicator": "demisto.com",
            "Score": 1,
            "Type": "domain",
            "Vendor": "DomainTools"
        },
        "Domain(val.Name && val.Name == obj.Name)": {
            "CreationDate": "2015-01-16",
            "DNS": [
                {
                    "address": {
                        "count": 122,
                        "value": "104.196.188.170"
                    },
                    "asn": [
                        {
                            "count": 13952015,
                            "value": 15169
                        }
                    ],
                    "country_code": {
                        "count": 305300756,
                        "value": "us"
                    },
                    "isp": {
                        "count": 12313137,
                        "value": "Google LLC"
                    }
                }
            ],
            "DomainStatus": true,
            "ExpirationDate": "2026-01-16",
            "Name": "demisto.com",
            "NameServers": [
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 11071,
                        "value": "pns31.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 15798,
                            "value": "a136.96.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10594,
                        "value": "pns32.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 15276,
                            "value": "a136.97.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10037,
                        "value": "pns33.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 12976,
                            "value": "a136.98.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10008,
                        "value": "pns34.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 12705,
                            "value": "a136.99.66"
                        }
                    ]
                }
            ],
            "Registrant": {
                "Country": {
                    "count": 19853629,
                    "value": "pa"
                },
                "Email": [
                    {
                        "count": 1,
                        "value": "whoisguard.com"
                    }
                ],
                "Name": {
                    "count": 8660262,
                    "value": "WhoisGuard Protected"
                },
                "Phone": {
                    "count": 10376394,
                    "value": "5078365503"
                }
            }
        },
        "DomainTools.Domains(val.Name && val.Name == obj.Name)": {
            "Analytics": {
                "OverallRiskScore": 33,
                "ProximityRiskScore": 33,
                "ThreatProfileRiskScore": {
                    "RiskScore": 0
                },
                "WebsiteResponseCode": 500
            },
            "Hosting": {
                "IPAddresses": [
                    {
                        "address": {
                            "count": 122,
                            "value": "104.196.188.170"
                        },
                        "asn": [
                            {
                                "count": 13952015,
                                "value": 15169
                            }
                        ],
                        "country_code": {
                            "count": 305300756,
                            "value": "us"
                        },
                        "isp": {
                            "count": 12313137,
                            "value": "Google LLC"
                        }
                    }
                ],
                "IPCountryCode": "us",
                "MailServers": [
                    {
                        "domain": {
                            "count": 90571,
                            "value": "pphosted.com"
                        },
                        "host": {
                            "count": 13,
                            "value": "ma"
                        },
                        "ip": [
                            {
                                "count": 10,
                                "value": "67.231.148.124"
                            }
                        ],
                        "priority": 10
                    },
                    {
                        "domain": {
                            "count": 90571,
                            "value": "pphosted.com"
                        },
                        "host": {
                            "count": 12,
                            "value": "mb"
                        },
                        "ip": [
                            {
                                "count": 9,
                                "value": "67.231.156.123"
                            }
                        ],
                        "priority": 10
                    }
                ],
                "NameServers": [
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 11071,
                            "value": "pns31.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 15798,
                                "value": "a136.96.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10594,
                            "value": "pns32.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 15276,
                                "value": "a136.97.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10037,
                            "value": "pns33.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 12976,
                                "value": "a136.98.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10008,
                            "value": "pns34.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 12705,
                                "value": "a136.99.66"
                            }
                        ]
                    }
                ],
                "SPFRecord": "v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all",
                "SSLCertificate": [
                    {
                        "hash": {
                            "count": 1,
                            "value": "7fed20410a1eb258c540f9c08ac7d361a9abd505"
                        },
                        "subject": {
                            "count": 1,
                            "value": "CN=www.demisto.com"
                        }
                    },
                    {
                        "hash": {
                            "count": 1,
                            "value": "36cbf4ec8b46e8baadaf4a9895d7dec7af7f138e"
                        },
                        "subject": {
                            "count": 1,
                            "value": "CN=demisto.com"
                        }
                    }
                ]
            },
            "Identity": {
                "AdditionalWhoisEmails": [
                    {
                        "count": 18465843,
                        "value": "namecheap.com"
                    }
                ],
                "AdminContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                },
                "EmailDomains": [
                    "cloudns.net",
                    "namecheap.com",
                    "whoisguard.com"
                ],
                "RegistrantContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                },
                "RegistrantName": "WhoisGuard Protected",
                "RegistrantOrg": "WhoisGuard, Inc",
                "SOAEmail": [
                    "support_cloudns.net"
                ],
                "TechnicalContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                }
            },
            "LastEnriched": "2019-10-17",
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
        }
    }
    
```

##### Human Readable Output
##### DomainTools Domain Profile for demisto.com.\n|Name|Last Enriched|Overall Risk Score|Proximity Risk Score|Threat Profile Risk Score|Threat Profile Threats|Threat Profile Evidence|Website Response Code|Alexa Rank|Tags|Registrant Name|Registrant Org|Registrant Contact|SOA Email|SSL Certificate Email|Admin Contact|Technical Contact|Billing Contact|Email Domains|Additional Whois Emails|Domain Registrant|Registrar Status|Domain Status|Create Date|Expiration Date|IP Addresses|IP Country Code|Mail Servers|SPF Record|Name Servers|SSL Certificate|Redirects To|Google Adsense Tracking Code|Google Analytic Tracking Code|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n|demisto.com|2019-10-10|33|33|0|||500|326569||WhoisGuard Protected|WhoisGuard, Inc|Country: {\"value\": \"pa\", \"count\": 19786098}<br>Email: {'value': '5be9245893ff486d98c3640879bb2657.protect_whoisguard.com', 'count': 1}<br>Name: {\"value\": \"WhoisGuard Protected\", \"count\": 8625643}<br>Phone: {\"value\": \"5078365503\", \"count\": 10343154}|support_cloudns.net||Country: {\"value\": \"pa\", \"count\": 19786098}<br>Email: {'value': '5be9245893ff486d98c3640879bb2657.protect_whoisguard.com', 'count': 1}<br>Name: {\"value\": \"WhoisGuard Protected\", \"count\": 8625643}<br>Phone: {\"value\": \"5078365503\", \"count\": 10343154}|Country: {\"value\": \"pa\", \"count\": 19786098}<br>Email: {'value': '5be9245893ff486d98c3640879bb2657.protect_whoisguard.com', 'count': 1}<br>Name: {\"value\": \"WhoisGuard Protected\", \"count\": 8625643}<br>Phone: {\"value\": \"5078365503\", \"count\": 10343154}|Country: {\"value\": null, \"count\": 0}<br>Email: null<br>Name: {\"value\": null, \"count\": 0}<br>Phone: {\"value\": null, \"count\": 0}|cloudns.net,<br>namecheap.com,<br>whoisguard.com|{'value': 'abuse_namecheap.com', 'count': 18388844}|NAMECHEAP INC,NAMECHEAP, INC|clientTransferProhibited|true|2015-01-16|2026-01-16|{'address': {'value': '104.196.188.170', 'count': 121}, 'asn': [{'value': 15169, 'count': 13931803}], 'country_code': {'value': 'us', 'count': 295509125}, 'isp': {'value': 'Google Inc.', 'count': 2092359}}|address: {\"value\": \"104.196.188.170\", \"count\": 121}<br>asn: {'value': 15169, 'count': 13931803}<br>country_code: {\"value\": \"us\", \"count\": 295509125}<br>isp: {\"value\": \"Google Inc.\", \"count\": 2092359}|{'host': {'value': 'ma', 'count': 13}, 'domain': {'value': 'pphosted.com', 'count': 90310}, 'ip': [{'value': '67.231.148.124', 'count': 10}], 'priority': 10},<br>{'host': {'value': 'mb', 'count': 12}, 'domain': {'value': 'pphosted.com', 'count': 90310}, 'ip': [{'value': '67.231.156.123', 'count': 12}], 'priority': 10}|v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all|{'host': {'value': 'pns31.cloudns.net', 'count': 10798}, 'domain': {'value': 'cloudns.net', 'count': 227179}, 'ip': [{'value': 'a136.96.66', 'count': 15398}]},<br>{'host': {'value': 'pns32.cloudns.net', 'count': 10323}, 'domain': {'value': 'cloudns.net', 'count': 227179}, 'ip': [{'value': 'a136.97.66', 'count': 14881}]},<br>{'host': {'value': 'pns33.cloudns.net', 'count': 9776}, 'domain': {'value': 'cloudns.net', 'count': 227179}, 'ip': [{'value': 'a136.98.66', 'count': 12689}]},<br>{'host': {'value': 'pns34.cloudns.net', 'count': 9736}, 'domain': {'value': 'cloudns.net', 'count': 227179}, 'ip': [{'value': 'a136.99.66', 'count': 12410}]}|{'hash': {'value': '7fed20410a1eb258c540f9c08ac7d361a9abd505', 'count': 1}, 'subject': {'value': 'CN=www.demisto.com', 'count': 1}, 'organization': {'value': None, 'count': 0}, 'email': None},<br>{'hash': {'value': '36cbf4ec8b46e8baadaf4a9895d7dec7af7f138e', 'count': 1}, 'subject': {'value': 'CN=demisto.com', 'count': 1}, 'organization': {'value': None, 'count': 0}, 'email': None}|value: null<br>count: 0|||\n

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
| Domain.DNS | Unknown | Domain DNS | 
| Domain.DNS.address | Unknown | Domain DNS address | 
| Domain.DNS.address.value | String | Domain DNS address value | 
| Domain.DNS.address.count | Number | Domain DNS address count | 
| Domain.DNS.asn | Unknown | Domain DNS asn | 
| Domain.DNS.asn.value | String | Domain DNS asn value | 
| Domain.DNS.asn.count | Number | Domain DNS asn count | 
| Domain.DNS.country_code | Unknown | Domain DNS country_code | 
| Domain.DNS.country_code.value | String | Domain DNS country_code value | 
| Domain.DNS.country_code.count | Number | Domain DNS country_code count | 
| Domain.DNS.isp | Unknown | Domain DNS isp | 
| Domain.DNS.isp.value | String | Domain DNS isp value | 
| Domain.DNS.isp.count | Number | Domain DNS isp count | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | Unknown | Domain NameServers | 
| Domain.NameServers.domain | Unknown | Domain NameServers domain | 
| Domain.NameServers.domain.value | String | Domain NameServers domain value | 
| Domain.NameServers.domain.count | Number | Domain NameServers domain count | 
| Domain.NameServers.host | Unknown | Domain NameServers host | 
| Domain.NameServers.host.value | String | Domain NameServers host value | 
| Domain.NameServers.host.count | Number | Domain NameServers host count | 
| Domain.NameServers.ip | Unknown | Domain NameServers ip | 
| Domain.NameServers.ip.value | String | Domain NameServers ip value | 
| Domain.NameServers.ip.count | Number | Domain NameServers ip count | 
| Domain.Registrant | Unknown | Domain Registrant | 
| Domain.Registrant.Country | Unknown | Domain Registrant Country | 
| Domain.Registrant.Country.value | String | Domain Registrant Country value | 
| Domain.Registrant.Country.count | Number | Domain Registrant Country count | 
| Domain.Registrant.Email | Unknown | Domain Registrant Email | 
| Domain.Registrant.Email.value | String | Domain Registrant Email value | 
| Domain.Registrant.Email.count | Number | Domain Registrant Email count | 
| Domain.Registrant.Name | Unknown | Domain Registrant Name | 
| Domain.Registrant.Name.value | String | Domain Registrant Name value | 
| Domain.Registrant.Name.count | Number | Domain Registrant Name count | 
| Domain.Registrant.Phone | Unknown | Domain Registrant Phone | 
| Domain.Registrant.Phone.value | String | Domain Registrant Phone value | 
| Domain.Registrant.Phone.count | Number | Domain Registrant Phone count | 
| Domain.Malicious | Unknown | Is the Domain Malicious | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | Unknown | Description of why domain was found to be malicious | 
| DomainTools.Domains | Unknown | DomainTools Domains | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics | Unknown | Analytics Data about the Domain from DomainTools | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore | Unknown | DomainTools Threat Profile Info | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | Unknown | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | Unknown | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Number | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | Unknown | DomainTools Tags | 
| DomainTools.Domains.Identity | Unknown | DomainTools Identity Info about the Domain | 
| DomainTools.Domains.Identity.RegistrantName | String | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | String | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact | Unknown | Registrant Contact Info | 
| DomainTools.Domains.Identity.RegistrantContact.Country | Unknown | Registrant Contact Country | 
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | Registrant Contact Country value | 
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Count | Registrant Contact Country count | 
| DomainTools.Domains.Identity.RegistrantContact.Email | Unknown | Registrant Contact Email | 
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | Registrant Contact Email value | 
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | Registrant Contact Email count | 
| DomainTools.Domains.Identity.RegistrantContact.Name | Unknown | Registrant Contact Name | 
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | Registrant Contact Name value | 
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | Registrant Contact Name count | 
| DomainTools.Domains.Identity.RegistrantContact.Phone | Unknown | Registrant Contact Phone | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | Registrant Contact Phone value | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | Registrant Contact Phone count | 
| DomainTools.Domains.Identity.SOAEmail | Unknown | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | Unknown | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact | Unknown | Admin Contact Info | 
| DomainTools.Domains.Identity.AdminContact.Country | Unknown | Admin Contact Country | 
| DomainTools.Domains.Identity.AdminContact.Country.value | String | Admin Contact Country value | 
| DomainTools.Domains.Identity.AdminContact.Country.count | Number | Admin Contact Country count | 
| DomainTools.Domains.Identity.AdminContact.Email | Unknown | Admin Contact Email | 
| DomainTools.Domains.Identity.AdminContact.Email.value | String | Admin Contact Email value | 
| DomainTools.Domains.Identity.AdminContact.Email.count | Number | Admin Contact Email count | 
| DomainTools.Domains.Identity.AdminContact.Name | Unknown | Admin Contact Name | 
| DomainTools.Domains.Identity.AdminContact.Name.value | String | Admin Contact Name value | 
| DomainTools.Domains.Identity.AdminContact.Name.count | Number | Admin Contact Name count | 
| DomainTools.Domains.Identity.AdminContact.Phone | Unknown | Admin Contact Phone | 
| DomainTools.Domains.Identity.AdminContact.Phone.value | String | Admin Contact Phone value | 
| DomainTools.Domains.Identity.AdminContact.Phone.count | Number | Admin Contact Phone count | 
| DomainTools.Domains.Identity.TechnicalContact | Unknown | Technical Contact Info | 
| DomainTools.Domains.Identity.TechnicalContact.Country | Unknown | Technical Contact Country | 
| DomainTools.Domains.Identity.TechnicalContact.Country.value | String | Technical Contact Country value | 
| DomainTools.Domains.Identity.TechnicalContact.Country.count | Number | Technical Contact Country count | 
| DomainTools.Domains.Identity.TechnicalContact.Email | Unknown | Technical Contact Email | 
| DomainTools.Domains.Identity.TechnicalContact.Email.value | String | Technical Contact Email value | 
| DomainTools.Domains.Identity.TechnicalContact.Email.count | Number | Technical Contact Email count | 
| DomainTools.Domains.Identity.TechnicalContact.Name | Unknown | Technical Contact Name | 
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | Technical Contact Name value | 
| DomainTools.Domains.Identity.TechnicalContact.Name.count | Number | Technical Contact Name count | 
| DomainTools.Domains.Identity.TechnicalContact.Phone | Unknown | Technical Contact Phone | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | String | Technical Contact Phone value | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | Number | Technical Contact Phone count | 
| DomainTools.Domains.Identity.BillingContact | Unknown | Billing Contact Info | 
| DomainTools.Domains.Identity.BillingContact.Country | Unknown | Billing Contact Country | 
| DomainTools.Domains.Identity.BillingContact.Country.value | String | Billing Contact Country value | 
| DomainTools.Domains.Identity.BillingContact.Country.count | Number | Billing Contact Country count | 
| DomainTools.Domains.Identity.BillingContact.Email | Unknown | Billing Contact Email | 
| DomainTools.Domains.Identity.BillingContact.Email.value | String | Billing Contact Email value | 
| DomainTools.Domains.Identity.BillingContact.Email.count | Number | Billing Contact Email count | 
| DomainTools.Domains.Identity.BillingContact.Name | Unknown | Billing Contact Name | 
| DomainTools.Domains.Identity.BillingContact.Name.value | String | Billing Contact Name value | 
| DomainTools.Domains.Identity.BillingContact.Name.count | Number | Billing Contact Name count | 
| DomainTools.Domains.Identity.BillingContact.Phone | Unknown | Billing Contact Phone | 
| DomainTools.Domains.Identity.BillingContact.Phone.value | String | Billing Contact Phone value | 
| DomainTools.Domains.Identity.BillingContact.Phone.count | Number | Billing Contact Phone count | 
| DomainTools.Domains.Identity.EmailDomains | Unknown | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails | Unknown | Additional Whois Emails | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | Additional Whois Emails value | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | Additional Whois Emails count | 
| DomainTools.Domains.Registration | Unknown | DomainTools Registration Info about the Domain | 
| DomainTools.Domains.Registration.DomainRegistrant | Unknown | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | Unknown | Reistrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting | Unknown | DomainTools Hosting Info about the Domain | 
| DomainTools.Domains.Hosting.IPAddresses | Unknown | IP Addresses Info | 
| DomainTools.Domains.Hosting.IPAddresses.address | Unknown | IP Addresses Info address | 
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | IP Addresses Info address value | 
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | IP Addresses Info address count | 
| DomainTools.Domains.Hosting.IPAddresses.asn | Unknown | IP Addresses Info asn | 
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | IP Addresses Info asn value | 
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | IP Addresses Info asn count | 
| DomainTools.Domains.Hosting.IPAddresses.country_code | Unknown | IP Addresses Info country_code | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | IP Addresses Info country_code value | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | IP Addresses Info country_code count | 
| DomainTools.Domains.Hosting.IPAddresses.isp | Unknown | IP Addresses Info isp | 
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.Domains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers | Unknown | Mail Servers Info | 
| DomainTools.Domains.Hosting.MailServers.domain | Unknown | Mail Servers Info domain | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.Domains.Hosting.MailServers.host | Unknown | Mail Servers Info host | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.Domains.Hosting.MailServers.ip | Unknown | Mail Servers Info ip | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
| DomainTools.Domains.Hosting.SPFRecord | Unknown | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers | Unknown | Name Servers Info | 
| DomainTools.Domains.NameServers.domain | Unknown | DomainTools Domains NameServers domain | 
| DomainTools.Domains.NameServers.domain.value | String | DomainTools Domains NameServers domain value | 
| DomainTools.Domains.NameServers.domain.count | Number | DomainTools Domains NameServers domain count | 
| DomainTools.Domains.NameServers.host | Unknown | DomainTools Domains NameServers host | 
| DomainTools.Domains.NameServers.host.value | String | DomainTools Domains NameServers host value | 
| DomainTools.Domains.NameServers.host.count | Number | DomainTools Domains NameServers host count | 
| DomainTools.Domains.NameServers.ip | Unknown | DomainTools Domains NameServers ip | 
| DomainTools.Domains.NameServers.ip.value | String | DomainTools Domains NameServers ip value | 
| DomainTools.Domains.NameServers.ip.count | Number | DomainTools Domains NameServers ip count | 
| DomainTools.Domains.Hosting.SSLCertificate | Unknown | SSL Certificate Info | 
| DomainTools.Domains.Hosting.SSLCertificate.hash | Unknown | SSL Certificate Info hash | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | SSL Certificate Info hash value | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | SSL Certificate Info hash count | 
| DomainTools.Domains.Hosting.SSLCertificate.organization | Unknown | SSL Certificate Info organization | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | SSL Certificate Info organization value | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | SSL Certificate Info organization count | 
| DomainTools.Domains.Hosting.SSLCertificate.subject | Unknown | SSL Certificate Info subject | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | SSL Certificate Info subject value | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | SSL Certificate Info subject count | 
| DomainTools.Domains.Hosting.RedirectsTo | Unknown | Domains it Redirects To | 
| DomainTools.Domains.Hosting.RedirectsTo.value | String | Domains it Redirects To value | 
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | Domains it Redirects To count | 
| DomainTools.Domains.Hosting.GoogleAdsenseTrackingCode | Unknown | Google Adsense Tracking Code | 
| DomainTools.Domains.Hosting.GoogleAnalyticTrackingCode | Unknown | Google Analytics Tracking Code | 
| DBotScore | Unknown | DBot Score | 
| DBotScore.Indicator | String | DBotScore Indicator | 
| DBotScore.Type | String | DBotScore Indicator Type | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
`!domain-analytics domain=demisto.com`

##### Context Example
```
        "DBotScore": {
            "Indicator": "demisto.com",
            "Score": 1,
            "Type": "domain",
            "Vendor": "DomainTools"
        },
        "Domain(val.Name && val.Name == obj.Name)": {
            "CreationDate": "2015-01-16",
            "DNS": [
                {
                    "address": {
                        "count": 122,
                        "value": "104.196.188.170"
                    },
                    "asn": [
                        {
                            "count": 13952015,
                            "value": 15169
                        }
                    ],
                    "country_code": {
                        "count": 305300756,
                        "value": "us"
                    },
                    "isp": {
                        "count": 12313137,
                        "value": "Google LLC"
                    }
                }
            ],
            "DomainStatus": true,
            "ExpirationDate": "2026-01-16",
            "Name": "demisto.com",
            "NameServers": [
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 11071,
                        "value": "pns31.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 15798,
                            "value": "a136.96.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10594,
                        "value": "pns32.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 15276,
                            "value": "a136.97.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10037,
                        "value": "pns33.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 12976,
                            "value": "a136.98.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10008,
                        "value": "pns34.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 12705,
                            "value": "a136.99.66"
                        }
                    ]
                }
            ],
            "Registrant": {
                "Country": {
                    "count": 19853629,
                    "value": "pa"
                },
                "Email": [
                    {
                        "count": 1,
                        "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                    }
                ],
                "Name": {
                    "count": 8660262,
                    "value": "WhoisGuard Protected"
                },
                "Phone": {
                    "count": 10376394,
                    "value": "5078365503"
                }
            }
        },
        "DomainTools.Domains(val.Name && val.Name == obj.Name)": {
            "Analytics": {
                "OverallRiskScore": 33,
                "ProximityRiskScore": 33,
                "ThreatProfileRiskScore": {
                    "RiskScore": 0
                },
                "WebsiteResponseCode": 500
            },
            "Hosting": {
                "IPAddresses": [
                    {
                        "address": {
                            "count": 122,
                            "value": "104.196.188.170"
                        },
                        "asn": [
                            {
                                "count": 13952015,
                                "value": 15169
                            }
                        ],
                        "country_code": {
                            "count": 305300756,
                            "value": "us"
                        },
                        "isp": {
                            "count": 12313137,
                            "value": "Google LLC"
                        }
                    }
                ],
                "IPCountryCode": "us",
                "MailServers": [
                    {
                        "domain": {
                            "count": 90571,
                            "value": "pphosted.com"
                        },
                        "host": {
                            "count": 13,
                            "value": "ma"
                        },
                        "ip": [
                            {
                                "count": 10,
                                "value": "67.231.148.124"
                            }
                        ],
                        "priority": 10
                    },
                    {
                        "domain": {
                            "count": 90571,
                            "value": "pphosted.com"
                        },
                        "host": {
                            "count": 12,
                            "value": "mb"
                        },
                        "ip": [
                            {
                                "count": 9,
                                "value": "67.231.156.123"
                            }
                        ],
                        "priority": 10
                    }
                ],
                "NameServers": [
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 11071,
                            "value": "pns31.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 15798,
                                "value": "a136.96.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10594,
                            "value": "pns32.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 15276,
                                "value": "a136.97.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10037,
                            "value": "pns33.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 12976,
                                "value": "a136.98.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10008,
                            "value": "pns34.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 12705,
                                "value": "a136.99.66"
                            }
                        ]
                    }
                ],
                "SPFRecord": "v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all",
                "SSLCertificate": [
                    {
                        "hash": {
                            "count": 1,
                            "value": "7fed20410a1eb258c540f9c08ac7d361a9abd505"
                        },
                        "subject": {
                            "count": 1,
                            "value": "CN=www.demisto.com"
                        }
                    },
                    {
                        "hash": {
                            "count": 1,
                            "value": "36cbf4ec8b46e8baadaf4a9895d7dec7af7f138e"
                        },
                        "subject": {
                            "count": 1,
                            "value": "CN=demisto.com"
                        }
                    }
                ]
            },
            "Identity": {
                "AdditionalWhoisEmails": [
                    {
                        "count": 18465843,
                        "value": "abuse_namecheap.com"
                    }
                ],
                "AdminContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                },
                "EmailDomains": [
                    "cloudns.net",
                    "namecheap.com",
                    "whoisguard.com"
                ],
                "RegistrantContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                },
                "RegistrantName": "WhoisGuard Protected",
                "RegistrantOrg": "WhoisGuard, Inc",
                "SOAEmail": [
                    "support_cloudns.net"
                ],
                "TechnicalContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                }
            },
            "LastEnriched": "2019-10-17",
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
        }
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
| Domain.DNS | Unknown | Domain DNS | 
| Domain.DNS.address | Unknown | Domain DNS address | 
| Domain.DNS.address.value | String | Domain DNS address value | 
| Domain.DNS.address.count | Number | Domain DNS address count | 
| Domain.DNS.asn | Unknown | Domain DNS asn | 
| Domain.DNS.asn.value | String | Domain DNS asn value | 
| Domain.DNS.asn.count | Number | Domain DNS asn count | 
| Domain.DNS.country_code | Unknown | Domain DNS country_code | 
| Domain.DNS.country_code.value | String | Domain DNS country_code value | 
| Domain.DNS.country_code.count | Number | Domain DNS country_code count | 
| Domain.DNS.isp | Unknown | Domain DNS isp | 
| Domain.DNS.isp.value | String | Domain DNS isp value | 
| Domain.DNS.isp.count | Number | Domain DNS isp count | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | Unknown | Domain NameServers | 
| Domain.NameServers.domain | Unknown | Domain NameServers domain | 
| Domain.NameServers.domain.value | String | Domain NameServers domain value | 
| Domain.NameServers.domain.count | Number | Domain NameServers domain count | 
| Domain.NameServers.host | Unknown | Domain NameServers host | 
| Domain.NameServers.host.value | String | Domain NameServers host value | 
| Domain.NameServers.host.count | Number | Domain NameServers host count | 
| Domain.NameServers.ip | Unknown | Domain NameServers ip | 
| Domain.NameServers.ip.value | String | Domain NameServers ip value | 
| Domain.NameServers.ip.count | Number | Domain NameServers ip count | 
| Domain.Registrant | Unknown | Domain Registrant | 
| Domain.Registrant.Country | Unknown | Domain Registrant Country | 
| Domain.Registrant.Country.value | String | Domain Registrant Country value | 
| Domain.Registrant.Country.count | Number | Domain Registrant Country count | 
| Domain.Registrant.Email | Unknown | Domain Registrant Email | 
| Domain.Registrant.Email.value | String | Domain Registrant Email value | 
| Domain.Registrant.Email.count | Number | Domain Registrant Email count | 
| Domain.Registrant.Name | Unknown | Domain Registrant Name | 
| Domain.Registrant.Name.value | String | Domain Registrant Name value | 
| Domain.Registrant.Name.count | Number | Domain Registrant Name count | 
| Domain.Registrant.Phone | Unknown | Domain Registrant Phone | 
| Domain.Registrant.Phone.value | String | Domain Registrant Phone value | 
| Domain.Registrant.Phone.count | Number | Domain Registrant Phone count | 
| Domain.Malicious | Unknown | Is the Domain Malicious | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | Unknown | Description of why domain was found to be malicious | 
| DomainTools.Domains | Unknown | DomainTools Domains | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics | Unknown | Analytics Data about the Domain from DomainTools | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore | Unknown | DomainTools Threat Profile Info | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | Unknown | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | Unknown | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Number | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | Unknown | DomainTools Tags | 
| DomainTools.Domains.Identity | Unknown | DomainTools Identity Info about the Domain | 
| DomainTools.Domains.Identity.RegistrantName | String | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | String | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact | Unknown | Registrant Contact Info | 
| DomainTools.Domains.Identity.RegistrantContact.Country | Unknown | Registrant Contact Country | 
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | Registrant Contact Country value | 
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Count | Registrant Contact Country count | 
| DomainTools.Domains.Identity.RegistrantContact.Email | Unknown | Registrant Contact Email | 
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | Registrant Contact Email value | 
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | Registrant Contact Email count | 
| DomainTools.Domains.Identity.RegistrantContact.Name | Unknown | Registrant Contact Name | 
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | Registrant Contact Name value | 
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | Registrant Contact Name count | 
| DomainTools.Domains.Identity.RegistrantContact.Phone | Unknown | Registrant Contact Phone | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | Registrant Contact Phone value | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | Registrant Contact Phone count | 
| DomainTools.Domains.Identity.SOAEmail | Unknown | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | Unknown | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact | Unknown | Admin Contact Info | 
| DomainTools.Domains.Identity.AdminContact.Country | Unknown | Admin Contact Country | 
| DomainTools.Domains.Identity.AdminContact.Country.value | String | Admin Contact Country value | 
| DomainTools.Domains.Identity.AdminContact.Country.count | Number | Admin Contact Country count | 
| DomainTools.Domains.Identity.AdminContact.Email | Unknown | Admin Contact Email | 
| DomainTools.Domains.Identity.AdminContact.Email.value | String | Admin Contact Email value | 
| DomainTools.Domains.Identity.AdminContact.Email.count | Number | Admin Contact Email count | 
| DomainTools.Domains.Identity.AdminContact.Name | Unknown | Admin Contact Name | 
| DomainTools.Domains.Identity.AdminContact.Name.value | String | Admin Contact Name value | 
| DomainTools.Domains.Identity.AdminContact.Name.count | Number | Admin Contact Name count | 
| DomainTools.Domains.Identity.AdminContact.Phone | Unknown | Admin Contact Phone | 
| DomainTools.Domains.Identity.AdminContact.Phone.value | String | Admin Contact Phone value | 
| DomainTools.Domains.Identity.AdminContact.Phone.count | Number | Admin Contact Phone count | 
| DomainTools.Domains.Identity.TechnicalContact | Unknown | Technical Contact Info | 
| DomainTools.Domains.Identity.TechnicalContact.Country | Unknown | Technical Contact Country | 
| DomainTools.Domains.Identity.TechnicalContact.Country.value | String | Technical Contact Country value | 
| DomainTools.Domains.Identity.TechnicalContact.Country.count | Number | Technical Contact Country count | 
| DomainTools.Domains.Identity.TechnicalContact.Email | Unknown | Technical Contact Email | 
| DomainTools.Domains.Identity.TechnicalContact.Email.value | String | Technical Contact Email value | 
| DomainTools.Domains.Identity.TechnicalContact.Email.count | Number | Technical Contact Email count | 
| DomainTools.Domains.Identity.TechnicalContact.Name | Unknown | Technical Contact Name | 
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | Technical Contact Name value | 
| DomainTools.Domains.Identity.TechnicalContact.Name.count | Number | Technical Contact Name count | 
| DomainTools.Domains.Identity.TechnicalContact.Phone | Unknown | Technical Contact Phone | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | String | Technical Contact Phone value | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | Number | Technical Contact Phone count | 
| DomainTools.Domains.Identity.BillingContact | Unknown | Billing Contact Info | 
| DomainTools.Domains.Identity.BillingContact.Country | Unknown | Billing Contact Country | 
| DomainTools.Domains.Identity.BillingContact.Country.value | String | Billing Contact Country value | 
| DomainTools.Domains.Identity.BillingContact.Country.count | Number | Billing Contact Country count | 
| DomainTools.Domains.Identity.BillingContact.Email | Unknown | Billing Contact Email | 
| DomainTools.Domains.Identity.BillingContact.Email.value | String | Billing Contact Email value | 
| DomainTools.Domains.Identity.BillingContact.Email.count | Number | Billing Contact Email count | 
| DomainTools.Domains.Identity.BillingContact.Name | Unknown | Billing Contact Name | 
| DomainTools.Domains.Identity.BillingContact.Name.value | String | Billing Contact Name value | 
| DomainTools.Domains.Identity.BillingContact.Name.count | Number | Billing Contact Name count | 
| DomainTools.Domains.Identity.BillingContact.Phone | Unknown | Billing Contact Phone | 
| DomainTools.Domains.Identity.BillingContact.Phone.value | String | Billing Contact Phone value | 
| DomainTools.Domains.Identity.BillingContact.Phone.count | Number | Billing Contact Phone count | 
| DomainTools.Domains.Identity.EmailDomains | Unknown | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails | Unknown | Additional Whois Emails | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | Additional Whois Emails value | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | Additional Whois Emails count | 
| DomainTools.Domains.Registration | Unknown | DomainTools Registration Info about the Domain | 
| DomainTools.Domains.Registration.DomainRegistrant | Unknown | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | Unknown | Reistrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting | Unknown | DomainTools Hosting Info about the Domain | 
| DomainTools.Domains.Hosting.IPAddresses | Unknown | IP Addresses Info | 
| DomainTools.Domains.Hosting.IPAddresses.address | Unknown | IP Addresses Info address | 
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | IP Addresses Info address value | 
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | IP Addresses Info address count | 
| DomainTools.Domains.Hosting.IPAddresses.asn | Unknown | IP Addresses Info asn | 
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | IP Addresses Info asn value | 
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | IP Addresses Info asn count | 
| DomainTools.Domains.Hosting.IPAddresses.country_code | Unknown | IP Addresses Info country_code | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | IP Addresses Info country_code value | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | IP Addresses Info country_code count | 
| DomainTools.Domains.Hosting.IPAddresses.isp | Unknown | IP Addresses Info isp | 
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.Domains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers | Unknown | Mail Servers Info | 
| DomainTools.Domains.Hosting.MailServers.domain | Unknown | Mail Servers Info domain | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.Domains.Hosting.MailServers.host | Unknown | Mail Servers Info host | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.Domains.Hosting.MailServers.ip | Unknown | Mail Servers Info ip | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
| DomainTools.Domains.Hosting.SPFRecord | Unknown | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers | Unknown | Name Servers Info | 
| DomainTools.Domains.NameServers.domain | Unknown | DomainTools Domains NameServers domain | 
| DomainTools.Domains.NameServers.domain.value | String | DomainTools Domains NameServers domain value | 
| DomainTools.Domains.NameServers.domain.count | Number | DomainTools Domains NameServers domain count | 
| DomainTools.Domains.NameServers.host | Unknown | DomainTools Domains NameServers host | 
| DomainTools.Domains.NameServers.host.value | String | DomainTools Domains NameServers host value | 
| DomainTools.Domains.NameServers.host.count | Number | DomainTools Domains NameServers host count | 
| DomainTools.Domains.NameServers.ip | Unknown | DomainTools Domains NameServers ip | 
| DomainTools.Domains.NameServers.ip.value | String | DomainTools Domains NameServers ip value | 
| DomainTools.Domains.NameServers.ip.count | Number | DomainTools Domains NameServers ip count | 
| DomainTools.Domains.Hosting.SSLCertificate | Unknown | SSL Certificate Info | 
| DomainTools.Domains.Hosting.SSLCertificate.hash | Unknown | SSL Certificate Info hash | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | SSL Certificate Info hash value | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | SSL Certificate Info hash count | 
| DomainTools.Domains.Hosting.SSLCertificate.organization | Unknown | SSL Certificate Info organization | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | SSL Certificate Info organization value | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | SSL Certificate Info organization count | 
| DomainTools.Domains.Hosting.SSLCertificate.subject | Unknown | SSL Certificate Info subject | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | SSL Certificate Info subject value | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | SSL Certificate Info subject count | 
| DomainTools.Domains.Hosting.RedirectsTo | Unknown | Domains it Redirects To | 
| DomainTools.Domains.Hosting.RedirectsTo.value | String | Domains it Redirects To value | 
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | Domains it Redirects To count | 
| DomainTools.Domains.Hosting.GoogleAdsenseTrackingCode | Unknown | Google Adsense Tracking Code | 
| DomainTools.Domains.Hosting.GoogleAnalyticTrackingCode | Unknown | Google Analytics Tracking Code | 
| DBotScore | Unknown | DBot Score | 
| DBotScore.Indicator | String | DBotScore Indicator | 
| DBotScore.Type | String | DBotScore Indicator Type | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
`!domaintoolsiris-threat-profile domain=demisto.com`

##### Context Example
```
        "DBotScore": {
            "Indicator": "demisto.com",
            "Score": 1,
            "Type": "domain",
            "Vendor": "DomainTools"
        },
        "Domain(val.Name && val.Name == obj.Name)": {
            "CreationDate": "2015-01-16",
            "DNS": [
                {
                    "address": {
                        "count": 122,
                        "value": "104.196.188.170"
                    },
                    "asn": [
                        {
                            "count": 13952015,
                            "value": 15169
                        }
                    ],
                    "country_code": {
                        "count": 305300756,
                        "value": "us"
                    },
                    "isp": {
                        "count": 12313137,
                        "value": "Google LLC"
                    }
                }
            ],
            "DomainStatus": true,
            "ExpirationDate": "2026-01-16",
            "Name": "demisto.com",
            "NameServers": [
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 11071,
                        "value": "pns31.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 15798,
                            "value": "a136.96.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10594,
                        "value": "pns32.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 15276,
                            "value": "a136.97.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10037,
                        "value": "pns33.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 12976,
                            "value": "a136.98.66"
                        }
                    ]
                },
                {
                    "domain": {
                        "count": 227290,
                        "value": "cloudns.net"
                    },
                    "host": {
                        "count": 10008,
                        "value": "pns34.cloudns.net"
                    },
                    "ip": [
                        {
                            "count": 12705,
                            "value": "a136.99.66"
                        }
                    ]
                }
            ],
            "Registrant": {
                "Country": {
                    "count": 19853629,
                    "value": "pa"
                },
                "Email": [
                    {
                        "count": 1,
                        "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                    }
                ],
                "Name": {
                    "count": 8660262,
                    "value": "WhoisGuard Protected"
                },
                "Phone": {
                    "count": 10376394,
                    "value": "5078365503"
                }
            }
        },
        "DomainTools.Domains(val.Name && val.Name == obj.Name)": {
            "Analytics": {
                "OverallRiskScore": 33,
                "ProximityRiskScore": 33,
                "ThreatProfileRiskScore": {
                    "RiskScore": 0
                },
                "WebsiteResponseCode": 500
            },
            "Hosting": {
                "IPAddresses": [
                    {
                        "address": {
                            "count": 122,
                            "value": "104.196.188.170"
                        },
                        "asn": [
                            {
                                "count": 13952015,
                                "value": 15169
                            }
                        ],
                        "country_code": {
                            "count": 305300756,
                            "value": "us"
                        },
                        "isp": {
                            "count": 12313137,
                            "value": "Google LLC"
                        }
                    }
                ],
                "IPCountryCode": "us",
                "MailServers": [
                    {
                        "domain": {
                            "count": 90571,
                            "value": "pphosted.com"
                        },
                        "host": {
                            "count": 13,
                            "value": "ma"
                        },
                        "ip": [
                            {
                                "count": 10,
                                "value": "67.231.148.124"
                            }
                        ],
                        "priority": 10
                    },
                    {
                        "domain": {
                            "count": 90571,
                            "value": "pphosted.com"
                        },
                        "host": {
                            "count": 12,
                            "value": "mb"
                        },
                        "ip": [
                            {
                                "count": 9,
                                "value": "67.231.156.123"
                            }
                        ],
                        "priority": 10
                    }
                ],
                "NameServers": [
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 11071,
                            "value": "pns31.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 15798,
                                "value": "a136.96.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10594,
                            "value": "pns32.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 15276,
                                "value": "a136.97.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10037,
                            "value": "pns33.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 12976,
                                "value": "a136.98.66"
                            }
                        ]
                    },
                    {
                        "domain": {
                            "count": 227290,
                            "value": "cloudns.net"
                        },
                        "host": {
                            "count": 10008,
                            "value": "pns34.cloudns.net"
                        },
                        "ip": [
                            {
                                "count": 12705,
                                "value": "a136.99.66"
                            }
                        ]
                    }
                ],
                "SPFRecord": "v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com include:sendgrid.net -all",
                "SSLCertificate": [
                    {
                        "hash": {
                            "count": 1,
                            "value": "7fed20410a1eb258c540f9c08ac7d361a9abd505"
                        },
                        "subject": {
                            "count": 1,
                            "value": "CN=www.demisto.com"
                        }
                    },
                    {
                        "hash": {
                            "count": 1,
                            "value": "36cbf4ec8b46e8baadaf4a9895d7dec7af7f138e"
                        },
                        "subject": {
                            "count": 1,
                            "value": "CN=demisto.com"
                        }
                    }
                ]
            },
            "Identity": {
                "AdditionalWhoisEmails": [
                    {
                        "count": 18465843,
                        "value": "abuse_namecheap.com"
                    }
                ],
                "AdminContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                },
                "EmailDomains": [
                    "cloudns.net",
                    "namecheap.com",
                    "whoisguard.com"
                ],
                "RegistrantContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                },
                "RegistrantName": "WhoisGuard Protected",
                "RegistrantOrg": "WhoisGuard, Inc",
                "SOAEmail": [
                    "support_cloudns.net"
                ],
                "TechnicalContact": {
                    "Country": {
                        "count": 19853629,
                        "value": "pa"
                    },
                    "Email": [
                        {
                            "count": 1,
                            "value": "5be9245893ff486d98c3640879bb2657.protect_whoisguard.com"
                        }
                    ],
                    "Name": {
                        "count": 8660262,
                        "value": "WhoisGuard Protected"
                    },
                    "Phone": {
                        "count": 10376394,
                        "value": "5078365503"
                    }
                }
            },
            "LastEnriched": "2019-10-17",
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
        }
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
| DomainTools.PivotedDomains | Unknown | DomainTools PivotedDomains | 
| DomainTools.PivotedDomains.Name | String | DomainTools Domain Name | 
| DomainTools.PivotedDomains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.PivotedDomains.Analytics | Unknown | Analytics Data about the Domain from DomainTools | 
| DomainTools.PivotedDomains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.PivotedDomains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore | Unknown | DomainTools Threat Profile Info | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.Threats | Unknown | DomainTools Threat Profile Threats | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.Evidence | Unknown | DomainTools Threat Profile Evidence | 
| DomainTools.PivotedDomains.Analytics.WebsiteResponseCode | Number | Website Response Code | 
| DomainTools.PivotedDomains.Analytics.AlexaRank | Number | Alexa Rank | 
| DomainTools.PivotedDomains.Analytics.Tags | Unknown | DomainTools Tags | 
| DomainTools.PivotedDomains.Identity | Unknown | DomainTools Identity Info about the Domain | 
| DomainTools.PivotedDomains.Identity.RegistrantName | String | Registrant Name | 
| DomainTools.PivotedDomains.Identity.RegistrantOrg | String | Registrant Org | 
| DomainTools.PivotedDomains.Identity.RegistrantContact | Unknown | Registrant Contact Info | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Country | Unknown | Registrant Contact Country | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Country.value | String | Registrant Contact Country value | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Country.count | Count | Registrant Contact Country count | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Email | Unknown | Registrant Contact Email | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Email.value | String | Registrant Contact Email value | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Email.count | Number | Registrant Contact Email count | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Name | Unknown | Registrant Contact Name | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Name.value | String | Registrant Contact Name value | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Name.count | Number | Registrant Contact Name count | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Phone | Unknown | Registrant Contact Phone | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Phone.value | String | Registrant Contact Phone value | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Phone.count | Number | Registrant Contact Phone count | 
| DomainTools.PivotedDomains.Identity.SOAEmail | Unknown | SOA Record Email | 
| DomainTools.PivotedDomains.Identity.SSLCertificateEmail | Unknown | SSL Certificate Email | 
| DomainTools.PivotedDomains.Identity.AdminContact | Unknown | Admin Contact Info | 
| DomainTools.PivotedDomains.Identity.AdminContact.Country | Unknown | Admin Contact Country | 
| DomainTools.PivotedDomains.Identity.AdminContact.Country.value | String | Admin Contact Country value | 
| DomainTools.PivotedDomains.Identity.AdminContact.Country.count | Number | Admin Contact Country count | 
| DomainTools.PivotedDomains.Identity.AdminContact.Email | Unknown | Admin Contact Email | 
| DomainTools.PivotedDomains.Identity.AdminContact.Email.value | String | Admin Contact Email value | 
| DomainTools.PivotedDomains.Identity.AdminContact.Email.count | Number | Admin Contact Email count | 
| DomainTools.PivotedDomains.Identity.AdminContact.Name | Unknown | Admin Contact Name | 
| DomainTools.PivotedDomains.Identity.AdminContact.Name.value | String | Admin Contact Name value | 
| DomainTools.PivotedDomains.Identity.AdminContact.Name.count | Number | Admin Contact Name count | 
| DomainTools.PivotedDomains.Identity.AdminContact.Phone | Unknown | Admin Contact Phone | 
| DomainTools.PivotedDomains.Identity.AdminContact.Phone.value | String | Admin Contact Phone value | 
| DomainTools.PivotedDomains.Identity.AdminContact.Phone.count | Number | Admin Contact Phone count | 
| DomainTools.PivotedDomains.Identity.TechnicalContact | Unknown | Technical Contact Info | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Country | Unknown | Technical Contact Country | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Country.value | String | Technical Contact Country value | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Country.count | Number | Technical Contact Country count | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Email | Unknown | Technical Contact Email | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Email.value | String | Technical Contact Email value | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Email.count | Number | Technical Contact Email count | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Name | Unknown | Technical Contact Name | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Name.value | String | Technical Contact Name value | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Name.count | Number | Technical Contact Name count | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Phone | Unknown | Technical Contact Phone | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Phone.value | String | Technical Contact Phone value | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Phone.count | Number | Technical Contact Phone count | 
| DomainTools.PivotedDomains.Identity.BillingContact | Unknown | Billing Contact Info | 
| DomainTools.PivotedDomains.Identity.BillingContact.Country | Unknown | Billing Contact Country | 
| DomainTools.PivotedDomains.Identity.BillingContact.Country.value | String | Billing Contact Country value | 
| DomainTools.PivotedDomains.Identity.BillingContact.Country.count | Number | Billing Contact Country count | 
| DomainTools.PivotedDomains.Identity.BillingContact.Email | Unknown | Billing Contact Email | 
| DomainTools.PivotedDomains.Identity.BillingContact.Email.value | String | Billing Contact Email value | 
| DomainTools.PivotedDomains.Identity.BillingContact.Email.count | Number | Billing Contact Email count | 
| DomainTools.PivotedDomains.Identity.BillingContact.Name | Unknown | Billing Contact Name | 
| DomainTools.PivotedDomains.Identity.BillingContact.Name.value | String | Billing Contact Name value | 
| DomainTools.PivotedDomains.Identity.BillingContact.Name.count | Number | Billing Contact Name count | 
| DomainTools.PivotedDomains.Identity.BillingContact.Phone | Unknown | Billing Contact Phone | 
| DomainTools.PivotedDomains.Identity.BillingContact.Phone.value | String | Billing Contact Phone value | 
| DomainTools.PivotedDomains.Identity.BillingContact.Phone.count | Number | Billing Contact Phone count | 
| DomainTools.PivotedDomains.Identity.EmailDomains | Unknown | Email Domains | 
| DomainTools.PivotedDomains.Identity.AdditionalWhoisEmails | Unknown | Additional Whois Emails | 
| DomainTools.PivotedDomains.Identity.AdditionalWhoisEmails.value | String | Additional Whois Emails value | 
| DomainTools.PivotedDomains.Identity.AdditionalWhoisEmails.count | Number | Additional Whois Emails count | 
| DomainTools.PivotedDomains.Registration | Unknown | DomainTools Registration Info about the Domain | 
| DomainTools.PivotedDomains.Registration.DomainRegistrant | Unknown | Domain Registrant | 
| DomainTools.PivotedDomains.Registration.RegistrarStatus | Unknown | Reistrar Status | 
| DomainTools.PivotedDomains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.PivotedDomains.Registration.CreateDate | Date | Create Date | 
| DomainTools.PivotedDomains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.PivotedDomains.Hosting | Unknown | DomainTools Hosting Info about the Domain | 
| DomainTools.PivotedDomains.Hosting.IPAddresses | Unknown | IP Addresses Info | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.address | Unknown | IP Addresses Info address | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.address.value | String | IP Addresses Info address value | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.address.count | Number | IP Addresses Info address count | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.asn | Unknown | IP Addresses Info asn | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.asn.value | String | IP Addresses Info asn value | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.asn.count | Number | IP Addresses Info asn count | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.country_code | Unknown | IP Addresses Info country_code | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.country_code.value | String | IP Addresses Info country_code value | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.country_code.count | Number | IP Addresses Info country_code count | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.isp | Unknown | IP Addresses Info isp | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.PivotedDomains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.PivotedDomains.Hosting.MailServers | Unknown | Mail Servers Info | 
| DomainTools.PivotedDomains.Hosting.MailServers.domain | Unknown | Mail Servers Info domain | 
| DomainTools.PivotedDomains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.PivotedDomains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.PivotedDomains.Hosting.MailServers.host | Unknown | Mail Servers Info host | 
| DomainTools.PivotedDomains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.PivotedDomains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.PivotedDomains.Hosting.MailServers.ip | Unknown | Mail Servers Info ip | 
| DomainTools.PivotedDomains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.PivotedDomains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
| DomainTools.PivotedDomains.Hosting.SPFRecord | Unknown | SPF Record Info | 
| DomainTools.PivotedDomains.Hosting.NameServers | Unknown | Name Servers Info | 
| DomainTools.PivotedDomains.NameServers.domain | Unknown | DomainTools Domains NameServers domain | 
| DomainTools.PivotedDomains.NameServers.domain.value | String | DomainTools Domains NameServers domain value | 
| DomainTools.PivotedDomains.NameServers.domain.count | Number | DomainTools Domains NameServers domain count | 
| DomainTools.PivotedDomains.NameServers.host | Unknown | DomainTools Domains NameServers host | 
| DomainTools.PivotedDomains.NameServers.host.value | String | DomainTools Domains NameServers host value | 
| DomainTools.PivotedDomains.NameServers.host.count | Number | DomainTools Domains NameServers host count | 
| DomainTools.PivotedDomains.NameServers.ip | Unknown | DomainTools Domains NameServers ip | 
| DomainTools.PivotedDomains.NameServers.ip.value | String | DomainTools Domains NameServers ip value | 
| DomainTools.PivotedDomains.NameServers.ip.count | Number | DomainTools Domains NameServers ip count | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate | Unknown | SSL Certificate Info | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.hash | Unknown | SSL Certificate Info hash | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.hash.value | String | SSL Certificate Info hash value | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.hash.count | Number | SSL Certificate Info hash count | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.organization | Unknown | SSL Certificate Info organization | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.organization.value | String | SSL Certificate Info organization value | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.organization.count | Number | SSL Certificate Info organization count | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.subject | Unknown | SSL Certificate Info subject | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.subject.value | String | SSL Certificate Info subject value | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.subject.count | Number | SSL Certificate Info subject count | 
| DomainTools.PivotedDomains.Hosting.RedirectsTo | Unknown | Domains it Redirects To | 
| DomainTools.PivotedDomains.Hosting.RedirectsTo.value | String | Domains it Redirects To value | 
| DomainTools.PivotedDomains.Hosting.RedirectsTo.count | Number | Domains it Redirects To count | 
| DomainTools.PivotedDomains.Hosting.GoogleAdsenseTrackingCode | Unknown | Google Adsense Tracking Code | 
| DomainTools.PivotedDomains.Hosting.GoogleAnalyticTrackingCode | Unknown | Google Analytics Tracking Code | 
##### Command Example
`!domaintoolsiris-pivot nameserver_host=demisto.com`

##### Context Example
```
        {
        "PivotedDomains":             {
                "Analytics": {
                    "OverallRiskScore": 4,
                    "ProximityRiskScore": 4,
                    "ThreatProfileRiskScore": {
                        "RiskScore": 0
                    },
                    "WebsiteResponseCode": 404
                },
                "Hosting": {
                    "IPAddresses": [
                        {
                            "address": {
                                "count": 122,
                                "value": "a196.188.170"
                            },
                            "asn": [
                                {
                                    "count": 13952015,
                                    "value": 15169
                                }
                            ],
                            "country_code": {
                                "count": 305300756,
                                "value": "us"
                            },
                            "isp": {
                                "count": 12313137,
                                "value": "Google LLC"
                            }
                        },
                        {
                            "address": {
                                "count": 99,
                                "value": "a56.85.186"
                            },
                            "asn": [
                                {
                                    "count": 1663270,
                                    "value": 32475
                                }
                            ],
                            "country_code": {
                                "count": 305300756,
                                "value": "us"
                            },
                            "isp": {
                                "count": 1101367,
                                "value": "SiteGround Hosting EOOD"
                            }
                        }
                    ],
                    "IPCountryCode": "us",
                    "MailServers": [
                        {
                            "domain": {
                                "count": 1210020,
                                "value": "zoho.com"
                            },
                            "host": {
                                "count": 1172860,
                                "value": "mx.zoho.com"
                            },
                            "ip": [
                                {
                                    "count": 862144,
                                    "value": "a141.42.121"
                                }
                            ],
                            "priority": 10
                        },
                        {
                            "domain": {
                                "count": 1210020,
                                "value": "zoho.com"
                            },
                            "host": {
                                "count": 1128807,
                                "value": "mx2.zoho.com"
                            },
                            "ip": [
                                {
                                    "count": 755176,
                                    "value": "a141.32.121"
                                }
                            ],
                            "priority": 20
                        },
                        {
                            "domain": {
                                "count": 1210020,
                                "value": "zoho.com"
                            },
                            "host": {
                                "count": 553267,
                                "value": "mx3.zoho.com"
                            },
                            "ip": [
                                {
                                    "count": 424379,
                                    "value": "a141.42.52"
                                }
                            ],
                            "priority": 50
                        }
                    ],
                    "NameServers": [
                        {
                            "domain": {
                                "count": 10251135,
                                "value": "ui-dns.biz"
                            },
                            "host": {
                                "count": 91064,
                                "value": "ns1075.ui-dns.biz"
                            },
                            "ip": [
                                {
                                    "count": 91063,
                                    "value": "a160.81.75"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 10659447,
                                "value": "ui-dns.com"
                            },
                            "host": {
                                "count": 91224,
                                "value": "ns1075.ui-dns.com"
                            },
                            "ip": [
                                {
                                    "count": 91207,
                                    "value": "a160.82.75"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 10251540,
                                "value": "ui-dns.de"
                            },
                            "host": {
                                "count": 91494,
                                "value": "ns1075.ui-dns.de"
                            },
                            "ip": [
                                {
                                    "count": 91493,
                                    "value": "a160.80.75"
                                }
                            ]
                        },
                        {
                            "domain": {
                                "count": 10252244,
                                "value": "ui-dns.org"
                            },
                            "host": {
                                "count": 90920,
                                "value": "ns1075.ui-dns.org"
                            },
                            "ip": [
                                {
                                    "count": 90920,
                                    "value": "a160.83.75"
                                }
                            ]
                        }
                    ],
                    "SPFRecord": "v=spf1 include:zoho.com ~all",
                    "SSLCertificate": [
                        {
                            "hash": {
                                "count": 131307,
                                "value": "c6a00220562bb921d359e1cb2f74e579da6eddd0"
                            },
                            "subject": {
                                "count": 220507,
                                "value": "CN=*.wpengine.com"
                            }
                        },
                        {
                            "hash": {
                                "count": 1,
                                "value": "1defc9b00bb727ecd893fa5755fdcb9d59e9e5f2"
                            },
                            "subject": {
                                "count": 1,
                                "value": "CN=youngamericatrading.com"
                            }
                        }
                    ]
                },
                "Identity": {
                    "AdditionalWhoisEmails": [
                        {
                            "count": 4947783,
                            "value": "abuse_ionos.com"
                        }
                    ],
                    "AdminContact": {
                        "Country": {
                            "count": 33514168,
                            "value": "REDACTED FOR PRIVACY"
                        },
                        "Email": [
                            {
                                "count": 1226106,
                                "value": "privacy_1and1.com"
                            }
                        ],
                        "Name": {
                            "count": 38695388,
                            "value": "REDACTED FOR PRIVACY"
                        }
                    },
                    "EmailDomains": [
                        "1and1.com",
                        "ionos.com"
                    ],
                    "RegistrantContact": {
                        "Country": {
                            "count": 179490298,
                            "value": "us"
                        },
                        "Email": [
                            {
                                "count": 1226084,
                                "value": "1and1.com"
                            }
                        ],
                        "Name": {
                            "count": 1368062,
                            "value": "Oneandone Private Registration"
                        },
                        "Phone": {
                            "count": 1357542,
                            "value": "18772064254"
                        }
                    },
                    "RegistrantName": "Oneandone Private Registration",
                    "RegistrantOrg": "1&1 Internet Inc",
                    "SOAEmail": [
                        "1and1.com"
                    ],
                    "TechnicalContact": {
                        "Country": {
                            "count": 33514168,
                            "value": "REDACTED FOR PRIVACY"
                        },
                        "Email": [
                            {
                                "count": 1226096,
                                "value": "1and1.com"
                            }
                        ],
                        "Name": {
                            "count": 38695388,
                            "value": "REDACTED FOR PRIVACY"
                        }
                    }
                },
                "LastEnriched": "2019-10-17",
                "Name": "youngamericatrading.com",
                "Registration": {
                    "CreateDate": "2014-02-18",
                    "DomainRegistrant": "1&1 IONOS SE",
                    "DomainStatus": true,
                    "ExpirationDate": "2020-02-18",
                    "RegistrarStatus": [
                        "clientTransferProhibited"
                    ]
                }
            }
        ]
    }
```

##### Human Readable Output
##### Domains for NameServer Host Name: demisto.com.\n|Domains|\n|---|\n|8lock.co|\n|8lock.io|\n|9thcircuitcriminalcases.com|\n|abclawcenters.com|\n|abogadoayudany.com|\n|abqnorthstorage.com|\n|aclassmegastorage.com|\n|actua.pe|\n|adfconverter.com|\n|agmednet.com|\n|alabamatortlaw.com|\n|alliioop.com|\n|americanaddictionfoundation.com|\n|americanrotors.com|\n|apmlawyers.com|\n|archstonelaw.com|\n|arthurbayrvpark.com|\n|auraexperiences.com|\n|babcocklegal.com|\n|balancednutritionwny.com|\n|batchesmke.com|\n|bigroomstudios.com|\n|bila.ca|\n|bilac.ca|\n|birthinjuryexperts.com|\n|brr-law.com|\n|capandkudler.com|\n|carlaleader.com|\n|carsonfootwear.com|\n|charlotteinsurance.com|\n|cincinnatieducationlaw.com|\n|cooperagemke.com|\n|crownasset.com|\n|crucialpointllc.com|\n|ctovision.com|\n|customhroservices.com|\n|dandanmke.com|\n|decaleco.com|\n|demisto.com|\n|demysto.com|\n|dewshilaw.ca|\n|directfuel.net|\n|diversifiedauto.com|\n|donaldsonlaw.com|\n|dovermiller.com|\n|dstlintelligence.com|\n|eleanoramagazine.com|\n|esterev.com|\n|evergreenredbarn.com|\n|federalforfeitureguide.com|\n|finlayllc.com|\n|forecite.com|\n|happydragonthriftshop.org|\n|hempcocanada.com|\n|jameseducationcenter.com|\n|jamespublishing.com|\n|jamestoolbox.com|\n|joinappa.com|\n|kaelfoods.com|\n|kissmetricshq.com|\n|kristaliney.com|\n|kycriminaldefense.com|\n|lloydjonescapital.com|\n|lloydjonesinvest.com|\n|lloydjonesinvestments.com|\n|lloydjonesllc.com|\n|lutco.com|\n|makeithome.net|\n|marcellaallison.com|\n|marylandfamiliesengage.org|\n|mccormickkennedy.com|\n|motherson-ossia.com|\n|mothersonossia.com|\n|nanadecals.com|\n|nikolanews.com|\n|noizchain.com|\n|ocpmgmt.com|\n|oheleanora.com|\n|omnisole.com|\n|orthopediccarepartners.com|\n|pacificmedicallaw.ca|\n|parentalguidance.com|\n|portsideautorepair.com|\n|portsidetruckrepair.com|\n|precisionmedicalbilling.com|\n|proautotran.com|\n|productengagementstack.com|\n|proficientautotransport.com|\n|proficientautotransport.net|\n|pspp.org|\n|rdairways.com|\n|rengalaxy.com|\n|rivetinc.org|\n|segalaslawfirm.com|\n|sentencingcases.com|\n|shariaportfolio.ca|\n|shariaportfolio.com|\n|shikistitches.com|\n|simonbrosroofing.com|\n|skihouseswap.com|\n|spacepencil.com|\n|stuffmadein.com|\n|stuffmadeinct.com|\n|stuffmadeinma.com|\n|stuffmadeinme.com|\n|stuffmadeinnh.com|\n|theargyle.org|\n|therawragency.com|\n|thingscyber.com|\n|threatbrief.com|\n|tinrx.com|\n|toi-health.com|\n|unicornthrift.com|\n|unicornthriftshop.com|\n|upconstructionllc.com|\n|upliftfs.org|\n|vroom.training|\n|washingtondcsouth.com|\n|weddingrings.com.ph|\n|welleryou.com|\n|youngamericatrading.com|\n

## Additional Information
---

## Known Limitations
---

## Troubleshooting
---
