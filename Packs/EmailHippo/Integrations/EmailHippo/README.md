This is the Email Hippo integration used to verify email sources as fake emails that were used as part of phishing attacks.
.
This integration was integrated and tested with version 2.0.1551 of Email Hippo.

## Configure Email Hippo in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| MORE Server URL (e.g., https://api.hippoapi.com) |  | True |
| Email Hippo WHOIS Server URL (e.g., https://api.whoishippo.com) |  | True |
| MORE API Key |  | True |
| WHOIS API Key |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Create relationships | Create relationships between indicators as part of enrichment. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### email-hippo-email-quota-get

***
Get the email quota from the API.

#### Base Command

`email-hippo-email-quota-get`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EmailHippo.Quota.quotaUsed | String | Total quota used. | 
| EmailHippo.Quota.quotaRemaining | String | The remaining quota. | 

#### Command example
```!email-hippo-email-quota-get```
#### Context Example
```json
{
    "EmailHippo": {
        "Quota": {
            "accountId": 7031,
            "errorSummary": "Valid",
            "nextQuotaResetDate": "2023-12-28T00:00:00",
            "quotaRemaining": 99,
            "quotaUsed": 1,
            "reportedDate": "2023-11-28T12:49:16.0260781Z"
        }
    }
}
```

#### Human Readable Output

>### Email quota
>|Email Quota remaining|Email Quota used|
>|---|---|
>| 99 | 1 |


### email

***
Return email information and reputation.

#### Base Command

`email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | A comma-separated list of email addresses to validate. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Email.Address | String | The email address of the indicator. | 
| Email.Domain | string | The email domain. | 
| EmailHippo.Email.Address | String | The email address of the indicator. | 

#### Command example
```!email email=test@example.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "test@example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 1,
        "Type": "email",
        "Vendor": "Email Hippo"
    },
    "Email": {
        "Address": "test@example.com",
        "Domain": "example.com"
    },
    "EmailHippo": {
        "Email": {
            "Address": "test@example.com",
            "diagnostic": {
                "key": "e4ddf797-f25b-410b-a753-58234759a67a"
            },
            "disposition": {
                "isFreeMail": false,
                "isRole": true
            },
            "domain": null,
            "emailVerification": {
                "dnsVerification": {
                    "isDomainHasDnsRecord": true,
                    "isDomainHasMxRecords": true,
                    "mxRecords": [
                        {
                            "exchange": ".",
                            "ipAddresses": null,
                            "preference": 0
                        }
                    ],
                    "recordRoot": {
                        "ipAddresses": [
                            "93.184.216.34"
                        ]
                    },
                    "recordWww": {
                        "ipAddresses": [
                            "93.184.216.34"
                        ]
                    },
                    "txtRecords": [
                        "\"wgyf8z8cgvm2qmxpnbnldrcltvk4xqfn\"",
                        "\"v=spf1 -all\""
                    ]
                },
                "mailboxVerification": {
                    "reason": "DomainIsWellKnownDea",
                    "result": "Unverifiable"
                },
                "syntaxVerification": {
                    "isSyntaxValid": true,
                    "reason": "Success"
                }
            },
            "hippoTrust": {
                "level": "Low",
                "score": 0
            },
            "infrastructure": {
                "mail": {
                    "mailServerLocation": null,
                    "serviceTypeId": "Other",
                    "smtpBanner": null
                },
                "web": {
                    "hasAliveWebServer": true
                }
            },
            "meta": {
                "domain": "example.com",
                "email": "test@example.com",
                "emailHashMd5": "55502f40dc8b7c769880b10874abc9d0",
                "emailHashSha1": "567159d622ffbb50b11b0efd307be358624a26ee",
                "emailHashSha256": "973dfe463ec85785f5f95af5ba3906eedb2d931c24e69824a89ea65dba4e813b",
                "expires": "Sat, 24 Feb 2024 23:31:57 GMT",
                "lastModified": "Mon, 28 Aug 2023 23:31:57 GMT",
                "subDomain": null,
                "tld": "com",
                "user": "test"
            },
            "performance": {
                "dnsLookup": 740,
                "mailboxVerification": 0,
                "other": 0,
                "overallExecutionTime": 818,
                "spamAssessment": 0,
                "syntaxCheck": 0,
                "webInfrastructurePing": 78
            },
            "sendAssess": {
                "inboxQualityScore": 0.1,
                "sendRecommendation": "DoNotSend"
            },
            "social": {
                "gravatar": {
                    "imageUrl": "//www.gravatar.com/avatar/55502f40dc8b7c769880b10874abc9d0",
                    "profileUrl": "//www.gravatar.com/55502f40dc8b7c769880b10874abc9d0"
                }
            },
            "spamAssess": {
                "actionRecomendation": "Block",
                "blockLists": [
                    {
                        "blockListName": "spamhaus",
                        "isListed": false,
                        "listedMoreInfo": null,
                        "listedReason": null
                    }
                ],
                "domainRiskScore": 10,
                "formatRiskScore": 0,
                "isDarkWebEmailAddress": false,
                "isDisposableEmailAddress": true,
                "isGibberishDomain": false,
                "isGibberishUser": false,
                "overallRiskScore": 10,
                "profanityRiskScore": 0
            },
            "spamTrapAssess": {
                "isSpamTrap": false,
                "spamTrapDescriptor": null
            },
            "version": {
                "doc": "https://api-docs.emailhippo.com/en/latest/",
                "v": "More-(1.2.1091)"
            }
        }
    }
}
```

#### Human Readable Output

>### Email test@example.com
>|Hippo Trust Score|Inbox quality score|Result|Spam risk score|
>|---|---|---|---|
>| Low | DoNotSend | result: Unverifiable<br/>reason: DomainIsWellKnownDea | Block |


### domain

***
Returns domain information and reputation.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to query (CSV). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Reliability | String | The reliability score of the vendor. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The name of the domain that was checked. | 
| Domain.NameServers | String | Name of the servers of the domain. | 
| Domain.UpdatedDate | Date | The date that the domain was last updated. | 
| Domain.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e.,'2020-04-30T10:35:00.000Z'\). | 
| Domain.Registrar.Name | String | The name of the registrar. | 
| Domain.Registrar.AbuseEmail | String | The email address of the contact for reporting abuse. | 
| Domain.Registrar.AbusePhone | String | The phone number of the contact for reporting abuse. | 
| Domain.Admin.Country | String | The country of the domain administrator. | 
| Domain.Admin.Email | String | The email address of the domain administrator. | 
| Domain.Admin.Name | String | The name of the domain administrator. | 
| Domain.Admin.Phone | String | The phone number of the domain administrator. | 
| Domain.Tech.Country | String | The country of tech administrator. | 
| Domain.Tech.Name | String | The name of the tech administrator. | 
| Domain.Tech.Email | String | The email of the tech administrator. | 
| Domain.Tech.Organization | String | The organization of the tech administrator. | 
| Domain.WHOIS.NameServers | String | A CSV string of name servers, for example 'ns1.bla.com, ns2.bla.com'. | 
| Domain.WHOIS.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e., '2020-04-30T10:35:00.000Z'\). | 
| Domain.WHOIS.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e., '2020-04-30T10:35:00.000Z'\). | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 

#### Command example
```!domain domain=example.com```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example.com",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "domain",
        "Vendor": "Email Hippo"
    },
    "Domain": {
        "CreationDate": "2018-08-21T14:02:43.000Z",
        "Name": "example.com",
        "NameServers": [
            {
                "Address": "A.example.NET"
            },
            {
                "Address": "B.example.NET"
            }
        ],
        "UpdatedDate": "2018-08-21T14:02:43.000Z",
        "WHOIS": {
            "CreationDate": "2018-08-21T14:02:43.000Z",
            "NameServers": [
                {
                    "Address": "A.example.NET"
                },
                {
                    "Address": "B.example.NET"
                }
            ],
            "UpdatedDate": "2018-08-21T14:02:43.000Z"
        }
    },
    "EmailHippo": {
        "Domain": {
            "creation_date": "2018-08-21T14:02:43.000Z",
            "domain": "example.com",
            "meta": {
                "domain": "example.com",
                "domainAge": "0 year(s), 0 month(s), 0 week(s), 0 day(s)",
                "domainAgeIso8601": "P0D",
                "domainAgeSeconds": 0,
                "executionTime": 2092,
                "parseCode": "Success",
                "recordAge": "5 year(s), 3 months, 0 week(s), 6 day(s), 22 hour(s), 46 minute(s)",
                "recordAgeIso8601": "P5Y3M6DT22H46M23.4811208S",
                "recordCreatedDate": "2018-08-21T14:02:43Z",
                "recordUpdatedDate": "2018-08-21T14:02:43Z",
                "timeToExpiry": "0 year(s), 0 months, 0 week(s), 0 day(s)",
                "timeToExpiryIso8601": "P0D",
                "timeToExpirySeconds": 0,
                "tld": "com"
            },
            "updated_date": "2018-08-21T14:02:43.000Z",
            "version": {
                "doc": "https://emailhippo.github.io/whois-developers",
                "v": "1.0.511"
            },
            "whoisServerRecord": {
                "adminContact": {
                    "city": "",
                    "country": "",
                    "email": "",
                    "faxNumber": "",
                    "faxNumberExt": "",
                    "name": "",
                    "organization": "",
                    "phoneNumber": "",
                    "phoneNumberExt": "",
                    "postalCode": "",
                    "state": "",
                    "street1": "",
                    "street2": null,
                    "street3": null,
                    "street4": null,
                    "userId": ""
                },
                "billingContact": {
                    "city": null,
                    "country": null,
                    "email": null,
                    "faxNumber": null,
                    "faxNumberExt": null,
                    "name": null,
                    "organization": null,
                    "phoneNumber": null,
                    "phoneNumberExt": null,
                    "postalCode": null,
                    "state": null,
                    "street1": null,
                    "street2": null,
                    "street3": null,
                    "street4": null,
                    "userId": null
                },
                "changed": null,
                "created": null,
                "customFields": null,
                "dnsSec": "",
                "domainHandle": "",
                "domainName": "example.com",
                "domainOwnerContact": {
                    "city": "",
                    "country": "",
                    "email": "",
                    "faxNumber": "",
                    "faxNumberExt": "",
                    "name": "",
                    "organization": "",
                    "phoneNumber": "",
                    "phoneNumberExt": "",
                    "postalCode": "",
                    "state": "",
                    "street1": "",
                    "street2": null,
                    "street3": null,
                    "street4": null,
                    "userId": ""
                },
                "domainStati": null,
                "expiry": null,
                "nameServers": [
                    {
                        "Address": "A.example.NET"
                    },
                    {
                        "Address": "B.example.NET"
                    }
                ],
                "recordFound": true,
                "registrar": {
                    "abuseEmail": "",
                    "abusePhone": "",
                    "name": "",
                    "registrarId": "",
                    "url": "",
                    "whois": "--UNSPECIFIED--"
                },
                "registrarContact": {
                    "city": null,
                    "country": null,
                    "email": null,
                    "faxNumber": null,
                    "faxNumberExt": null,
                    "name": null,
                    "organization": null,
                    "phoneNumber": null,
                    "phoneNumberExt": null,
                    "postalCode": null,
                    "state": null,
                    "street1": null,
                    "street2": null,
                    "street3": null,
                    "street4": null,
                    "userId": null
                },
                "remarks": null,
                "reseller": "",
                "techContact": {
                    "city": "",
                    "country": "",
                    "email": "",
                    "faxNumber": "",
                    "faxNumberExt": "",
                    "name": "",
                    "organization": "",
                    "phoneNumber": "",
                    "phoneNumberExt": "",
                    "postalCode": "",
                    "state": "",
                    "street1": "",
                    "street2": null,
                    "street3": null,
                    "street4": null,
                    "userId": ""
                },
                "tld": "com",
                "zoneContact": {
                    "city": null,
                    "country": null,
                    "email": null,
                    "faxNumber": null,
                    "faxNumberExt": null,
                    "name": null,
                    "organization": null,
                    "phoneNumber": null,
                    "phoneNumberExt": null,
                    "postalCode": null,
                    "state": null,
                    "street1": null,
                    "street2": null,
                    "street3": null,
                    "street4": null,
                    "userId": null
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Domain example.com
>|Domain Age|Expires On|Name servers|Registered On|Registrar|Status|Time To Expiry|Updated On|
>|---|---|---|---|---|---|---|---|
>| 0 year(s), 0 month(s), 0 week(s), 0 day(s) |  | {'Address': 'A.example.NET'},<br/>{'Address': 'B.example.NET'} |  |  |  | 0 year(s), 0 months, 0 week(s), 0 day(s) |  |
